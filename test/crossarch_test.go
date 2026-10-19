package test

// Cross-architecture differential test.
//
// For each target on PATH that has both a GNU cross objcopy and a cross gcc,
// this test compiles the same hello.c into a PIE executable, a non-PIE
// executable and a relocatable object, then runs one objcopy operation at a
// time through the GNU cross objcopy and through gobjcopy.  Results are
// compared semantically with internal/elfdump.Default: section layout and file
// offsets are ignored (GNU reorders them freely), while sections, symbols,
// relocations and section contents must agree.  -O binary output is compared
// byte for byte.
//
// Compression options are deliberately absent.  GNU uses C zlib and gobjcopy
// uses Go's compress/flate; both produce valid streams, but the bytes differ
// (see "为什么 compress.exp 里有 4 个 zlib 用例过不了" in README.md).
//
// The test needs, per target:
//
//	<triple>-objcopy                     GNU reference
//	<triple>-gcc, or <triple>-gcc-N      compiler (e.g. gcc-13 on Debian)
//
// and a gobjcopy binary, discovered exactly like TestDifferential (GOBJCOPY or
// ./gobjcopy).  Missing tools skip the corresponding target instead of failing,
// so hosts without cross toolchains keep `go test ./...` green.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/internal/elfdump"
)

const crossHelloSource = `#include <stdio.h>
int g=42; static int s=7;
static int h(int x){return x*3+s;}
int main(void){printf("%d\n",h(g));return 0;}
`

var crossTargets = []string{"aarch64-linux-gnu", "loongarch64-linux-gnu"}

type crossToolchain struct {
	triple  string
	gcc     string
	objcopy string
}

type crossInput struct {
	name string
	path string
}

type crossOp struct {
	name string
	args []string
	// binary compares the output byte for byte instead of as ELF.
	binary bool
	// skipObject explains why this operation is not compared on the
	// relocatable object, or is empty when it is.
	skipObject string
}

var crossOps = []crossOp{
	{name: "copy"},
	{name: "strip-all", args: []string{"-S"}},
	{name: "strip-debug", args: []string{"-g"}},
	{name: "only-keep-debug", args: []string{"--only-keep-debug"}},
	{name: "keep-symbol", args: []string{"-K", "main"}},
	{name: "strip-unneeded", args: []string{"--strip-unneeded"}},
	{
		name: "keep-text",
		args: []string{"-j", ".text"},
		// GNU objcopy 2.44 aborts with "no symbols" on a relocatable input
		// filtered down to one section; gobjcopy drops the now-stale
		// relocations and produces a usable object.  This is documented as a
		// known difference in README.md, so only executables are compared.
		skipObject: "GNU objcopy 2.44 fails on -j for a relocatable object (known difference, see README)",
	},
	{name: "remove-comment", args: []string{"-R", ".comment"}},
	{name: "add-symbol", args: []string{"--add-symbol", "NEW=0x1234"}},
	{name: "change-section-address", args: []string{"--change-section-address", ".text+0x10"}},
	{name: "strip-section-headers", args: []string{"--strip-section-headers"}},
	{name: "binary", args: []string{"-O", "binary"}, binary: true},
}

func TestCrossArchSemantics(t *testing.T) {
	subj := findSubject(t)

	available := 0
	for _, triple := range crossTargets {
		tc, ok := findCrossToolchain(t, triple)
		if !ok {
			continue
		}
		available++
		t.Run(triple, func(t *testing.T) {
			t.Logf("GNU objcopy: %s", tc.objcopy)
			t.Logf("gcc:         %s", tc.gcc)
			t.Logf("gobjcopy:    %s", subj)

			inputs := buildCrossInputs(t, tc, t.TempDir())
			for _, in := range inputs {
				for _, op := range crossOps {
					in, op := in, op
					t.Run(in.name+"/"+op.name, func(t *testing.T) {
						if op.skipObject != "" && in.name == "object" {
							t.Skip(op.skipObject)
						}
						runCrossOp(t, tc, subj, in, op)
					})
				}
			}
		})
	}
	if available == 0 {
		t.Skip("no cross toolchain found: need <triple>-objcopy and <triple>-gcc (or a versioned <triple>-gcc-N)")
	}
}

// findCrossToolchain resolves the GNU tools for one target.  A versioned gcc
// name is accepted because distributions commonly ship only that name (Debian's
// loongarch64 toolchain is loongarch64-linux-gnu-gcc-13).
func findCrossToolchain(t *testing.T, triple string) (crossToolchain, bool) {
	t.Helper()
	objcopyPath, err := exec.LookPath(triple + "-objcopy")
	if err != nil {
		t.Logf("skipping %s: %v", triple, err)
		return crossToolchain{}, false
	}
	gccPath := findCrossGCC(triple)
	if gccPath == "" {
		t.Logf("skipping %s: neither %s-gcc nor %s-gcc-N found on PATH", triple, triple, triple)
		return crossToolchain{}, false
	}
	return crossToolchain{triple: triple, gcc: gccPath, objcopy: objcopyPath}, true
}

// findCrossGCC returns the unversioned cross compiler when present, otherwise
// the highest-numbered <triple>-gcc-N found on PATH.
func findCrossGCC(triple string) string {
	if p, err := exec.LookPath(triple + "-gcc"); err == nil {
		return p
	}
	var candidates []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		matches, err := filepath.Glob(filepath.Join(dir, triple+"-gcc-*"))
		if err != nil {
			continue
		}
		for _, m := range matches {
			if crossGCCVersion(triple, m) < 0 {
				continue
			}
			st, err := os.Stat(m)
			if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
				continue
			}
			candidates = append(candidates, m)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		return crossGCCVersion(triple, candidates[i]) < crossGCCVersion(triple, candidates[j])
	})
	return candidates[len(candidates)-1]
}

// crossGCCVersion extracts N from a <triple>-gcc-N basename, or -1 when the
// basename is not exactly that pattern (so e.g. -gcc-ranlib-13 is ignored).
func crossGCCVersion(triple, path string) int {
	base := filepath.Base(path)
	prefix := triple + "-gcc-"
	if !strings.HasPrefix(base, prefix) {
		return -1
	}
	rest := base[len(prefix):]
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return -1
	}
	v, err := strconv.Atoi(rest[:digits])
	if err != nil {
		return -1
	}
	return v
}

// buildCrossInputs compiles hello.c in the three shapes the CLI cares about.
func buildCrossInputs(t *testing.T, tc crossToolchain, dir string) []crossInput {
	t.Helper()
	src := filepath.Join(dir, "hello.c")
	if err := os.WriteFile(src, []byte(crossHelloSource), 0o644); err != nil {
		t.Fatalf("write %s: %v", src, err)
	}

	variants := []struct {
		name  string
		flags []string
	}{
		{"pie", []string{"-g", "-O0", "-fPIE", "-pie"}},
		{"nopie", []string{"-g", "-O0", "-fno-pie", "-no-pie"}},
		{"object", []string{"-g", "-O0", "-c"}},
	}
	var inputs []crossInput
	for _, v := range variants {
		out := filepath.Join(dir, v.name+".elf")
		args := append(append([]string{}, v.flags...), "-o", out, src)
		cmd := exec.Command(tc.gcc, args...)
		cmd.Dir = dir
		cmd.Env = cleanEnv()
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: cannot build %s fixture: %v\n%s", tc.triple, v.name, err, output)
		}
		inputs = append(inputs, crossInput{name: v.name, path: out})
	}
	return inputs
}

// runCrossOp executes one operation on one input for both implementations and
// compares the results.
func runCrossOp(t *testing.T, tc crossToolchain, subj string, in crossInput, op crossOp) {
	t.Helper()

	root := t.TempDir()
	refDir := filepath.Join(root, "gnu")
	subjDir := filepath.Join(root, "gobjcopy")
	for _, dir := range []string{refDir, subjDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	base := filepath.Base(in.path)
	copyFile(t, in.path, filepath.Join(refDir, base))
	copyFile(t, in.path, filepath.Join(subjDir, base))

	tokens := makeTokens(base)
	argv := append(append([]string{}, op.args...), "@in@", "@out@")

	refRes, err := runCommand(tc.objcopy, refDir, argv, tokens)
	if err != nil {
		t.Fatalf("running GNU objcopy: %v", err)
	}
	subjRes, err := runCommand(subj, subjDir, argv, tokens)
	if err != nil {
		t.Fatalf("running gobjcopy: %v", err)
	}

	if refRes.exit != subjRes.exit {
		t.Fatalf("exit status differs: GNU=%d gobjcopy=%d\nGNU stderr:\n%s\ngobjcopy stderr:\n%s",
			refRes.exit, subjRes.exit, strings.TrimSpace(refRes.stderr), strings.TrimSpace(subjRes.stderr))
	}
	if refRes.exit != 0 {
		t.Fatalf("both implementations failed (exit %d)\nGNU stderr:\n%s\ngobjcopy stderr:\n%s",
			refRes.exit, strings.TrimSpace(refRes.stderr), strings.TrimSpace(subjRes.stderr))
	}

	compareCrossOutput(t, op, filepath.Join(refDir, base+".out"), filepath.Join(subjDir, base+".out"))
}

// compareCrossOutput compares the GNU and gobjcopy results.
func compareCrossOutput(t *testing.T, op crossOp, refPath, subjPath string) {
	t.Helper()

	if op.binary {
		ref, err := os.ReadFile(refPath)
		if err != nil {
			t.Fatalf("read GNU output: %v", err)
		}
		subj, err := os.ReadFile(subjPath)
		if err != nil {
			t.Fatalf("read gobjcopy output: %v", err)
		}
		if !bytes.Equal(ref, subj) {
			t.Errorf("binary output differs:\n%s", binaryDiff(ref, subj))
		}
		return
	}

	refDump, err := elfdump.DumpFile(refPath, elfdump.Default)
	if err != nil {
		t.Fatalf("cannot parse GNU output %s: %v", refPath, err)
	}
	subjDump, err := elfdump.DumpFile(subjPath, elfdump.Default)
	if err != nil {
		t.Fatalf("cannot parse gobjcopy output %s: %v", subjPath, err)
	}
	if diff := elfdump.FirstDiff(refDump, subjDump); diff != "" {
		t.Errorf("semantic difference (GNU first, gobjcopy second):\n%s", diff)
	}
}
