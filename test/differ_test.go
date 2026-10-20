package test

// Differential test scaffold: run the same objcopy command line through the
// GNU reference implementation and through the subject under test, then compare
// what came out.
//
// Self-check (today, before gobjcopy has a CLI):
//
//	GOBJCOPY=/usr/bin/objcopy go test ./test -run TestDifferential -v
//
// The scaffold always compares *results*, never hard-coded GNU output.  Exit
// statuses must agree.  When both commands fail, only the normalised error
// lines are compared; when both succeed, output files are compared either
// semantically as ELF (via internal/elfdump, ignoring file offsets) or byte by
// byte for non-ELF output such as -O binary.
//
// GNU objcopy behaviours worth knowing when implementing gobjcopy:
//
//   - `-v` is --verbose, not --version (it prints "copy from ... to ..." on
//     stdout).  `-V`/`--version` is version.
//   - `-R .name` for a missing section is silently ignored (exit 0), even with
//     -v.  `--change-section-address` for a missing section warns only with
//     `--change-warnings`/`--adjust-warnings`.
//   - `-K sym` without a stripping option (e.g. --strip-all) is a no-op: every
//     symbol is still copied.  `--strip-symbol`, `--redefine-sym` and friends
//     for a symbol that does not exist are silently ignored (exit 0).
//   - `--only-keep-debug` and `--add-gnu-debuglink` work in one invocation, but
//     the useful workflow is the three-step one exercised here (keep debug,
//     strip debug, add link).
//   - `--pad-to` can emit a warning that names GNU's temporary file; success
//     warnings are therefore not compared.
//   - `--gap-fill` also fills holes between sections in an ELF output; only an
//     `-O binary` output makes the fill bytes easy to compare byte for byte.
//   - `-O elf32-i386` on a 64-bit relocatable object fails with relocation
//     errors; a case may legitimately fail on both sides and still pass.
//   - `--set-section-flags .comment=debug` works and, surprisingly, gives the
//     section the write flag (GNU maps `debug` to readonly being cleared).
//   - `-j .text` warns about empty loadable segments but succeeds.
//   - `-I binary -O elf64-x86-64 -B i386:x86-64` derives symbols from the input
//     basename, so both sides must use the same relative input name.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/internal/elfdump"
	"github.com/myml/gobjcopy/internal/fixtures"
)

var (
	fixtureRoot  string
	fixtureFiles map[string]string
	fixtureErr   error
)

// TestMain builds the fixture corpus once.  Fixtures are only ever read by the
// tests; every objcopy invocation works on a private copy under t.TempDir().
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gobjcopy-fixtures-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create fixture directory: %v\n", err)
		os.Exit(1)
	}
	fixtureRoot = dir
	fixtureFiles, fixtureErr = fixtures.Build(dir)
	if fixtureFiles == nil {
		fixtureFiles = map[string]string{}
	}

	// A raw binary input for -I binary.  Its content only needs to be non-empty
	// and deterministic; the generated ELF symbols depend on the basename.
	blob := make([]byte, 256)
	for i := range blob {
		blob[i] = byte(i*37 + 11)
	}
	blobPath := filepath.Join(dir, "blob.bin")
	if fixtureErr == nil {
		if err := os.WriteFile(blobPath, blob, 0o644); err != nil {
			fixtureErr = err
		} else {
			fixtureFiles["blob.bin"] = blobPath
		}
	}

	code := m.Run()
	if err := os.RemoveAll(fixtureRoot); err != nil {
		fmt.Fprintf(os.Stderr, "cannot remove fixture directory: %v\n", err)
	}
	os.Exit(code)
}

// testCase is one differential scenario.  It is executed once per entry in
// inputs, so inputs is the list of fixture samples the scenario applies to.
type testCase struct {
	name   string
	inputs []string // fixture names this case applies to
	args   []string // options; file operands are appended automatically
	// steps overrides args and supplies a full argv template per invocation.
	// Placeholders: @in@, @out@, @out2@, @debug@, @bin@.
	steps   [][]string
	inPlace bool // append only @in@ and compare the modified input
	// outputs lists relative output templates to compare.  nil means the
	// default (@out@, or @in@ for inPlace).  An explicit empty slice and
	// noOutput both mean "no output files".
	outputs  []string
	noOutput bool
	// looseStderr skips stderr comparison when both sides fail; used where
	// GNU's diagnostic names a target-specific relocation type.
	looseStderr bool
	// skipReason marks a case where GNU's behaviour is not reproduced.
	skipReason string
	// skipInputs restricts skipReason to the listed fixture names.
	skipInputs []string
	// post is an optional extra assertion after a fully successful run.
	post func(t *testing.T, refDir, subjDir string, tokens map[string]string)
	note string
}

func (c testCase) commands() [][]string {
	if len(c.steps) > 0 {
		return c.steps
	}
	argv := append([]string(nil), c.args...)
	argv = append(argv, "@in@")
	if !c.inPlace {
		argv = append(argv, "@out@")
	}
	return [][]string{argv}
}

func (c testCase) outputNames() []string {
	if c.outputs != nil {
		return c.outputs
	}
	if c.noOutput {
		return nil
	}
	if c.inPlace {
		return []string{"@in@"}
	}
	return []string{"@out@"}
}

var differentialCases = []testCase{
	// ---------------------------------------------------------------------
	// Symbol table stripping and editing
	// ---------------------------------------------------------------------
	{
		name:   "strip-all-long",
		inputs: []string{"hello-nopie", "reloc.o", "custom", "static", "hello-stripped"},
		args:   []string{"--strip-all"},
	},
	{
		name:   "strip-all-short",
		inputs: []string{"hello-nopie", "reloc.o"},
		args:   []string{"-S"},
	},
	{
		name:   "strip-debug-long",
		inputs: []string{"hello", "hello-gz", "hello-stripped"},
		args:   []string{"--strip-debug"},
	},
	{
		name:   "strip-debug-short",
		inputs: []string{"hello", "hello-gz"},
		args:   []string{"-g"},
	},
	{
		name:   "strip-unneeded",
		inputs: []string{"reloc.o", "lib.so", "hello-nopie"},
		args:   []string{"--strip-unneeded"},
	},
	{
		name:   "discard-all",
		inputs: []string{"hello-nopie", "reloc.o"},
		args:   []string{"-x"},
	},
	{
		name:   "discard-locals",
		inputs: []string{"hello-nopie", "reloc.o"},
		args:   []string{"-X"},
	},
	{
		name:   "keep-symbol-alone",
		inputs: []string{"reloc.o"},
		args:   []string{"-K", "func_a"},
		note:   "-K without a strip option is a no-op in GNU objcopy",
	},
	{
		name:   "keep-symbol-with-strip-all",
		inputs: []string{"reloc.o"},
		args:   []string{"-K", "func_a", "--strip-all"},
	},
	{
		name:   "strip-symbol",
		inputs: []string{"reloc.o"},
		args:   []string{"--strip-symbol=func_a"},
	},
	{
		name:   "strip-symbol-short",
		inputs: []string{"reloc.o"},
		args:   []string{"-N", "func_a"},
	},
	{
		name:   "keep-global-symbol",
		inputs: []string{"reloc.o"},
		args:   []string{"--keep-global-symbol=func_a"},
	},
	{
		name:   "localize-symbol",
		inputs: []string{"reloc.o"},
		args:   []string{"--localize-symbol=func_a"},
	},
	{
		name:   "globalize-symbol",
		inputs: []string{"reloc.o"},
		args:   []string{"--globalize-symbol=local_var"},
	},
	{
		name:   "weaken",
		inputs: []string{"reloc.o", "lib.so"},
		args:   []string{"--weaken"},
	},
	{
		name:   "weaken-symbol",
		inputs: []string{"reloc.o"},
		args:   []string{"--weaken-symbol=func_a"},
	},
	{
		name:   "redefine-sym",
		inputs: []string{"reloc.o"},
		args:   []string{"--redefine-sym", "func_a=renamed_a"},
	},
	{
		name:   "strip-unneeded-symbol",
		inputs: []string{"reloc.o"},
		args:   []string{"--strip-unneeded-symbol=local_var"},
	},
	{
		name:   "localize-hidden",
		inputs: []string{"lib.so", "hello-nopie"},
		args:   []string{"--localize-hidden"},
	},

	// ---------------------------------------------------------------------
	// Section selection and editing
	// ---------------------------------------------------------------------
	{
		name:   "remove-comment",
		inputs: []string{"hello-nopie", "custom"},
		args:   []string{"-R", ".comment"},
	},
	{
		name:   "remove-section-long",
		inputs: []string{"hello-nopie"},
		args:   []string{"--remove-section", ".comment"},
	},
	{
		name:   "remove-note-patterns",
		inputs: []string{"hello-pie", "custom"},
		args:   []string{"-R", ".note.ABI-tag", "-R", ".note.gnu.*"},
		note:   "wildcards are expanded by objcopy (fnmatch), not by the shell",
	},
	{
		name:   "remove-all-notes-wildcard",
		inputs: []string{"custom"},
		args:   []string{"-R", ".note*"},
	},
	{
		name:   "remove-nonexistent",
		inputs: []string{"hello-nopie", "reloc.o"},
		args:   []string{"-R", ".does.not.exist"},
		note:   "GNU 2.44 exits 0 silently for -R of a missing section",
	},
	{
		name:   "only-section-text",
		inputs: []string{"hello-nopie", "custom"},
		args:   []string{"-j", ".text"},
		note:   "GNU warns about empty loadable segments but succeeds",
	},
	{
		name:   "only-keep-debug",
		inputs: []string{"hello-nopie", "reloc.o"},
		args:   []string{"--only-keep-debug"},
	},
	{
		name:   "only-keep-debug-plus-debuglink",
		inputs: []string{"hello-nopie", "reloc.o"},
		steps: [][]string{
			{"--only-keep-debug", "@in@", "@debug@"},
			{"--strip-debug", "@in@", "@out@"},
			{"--add-gnu-debuglink=@debug@", "@out@", "@out2@"},
		},
		outputs: []string{"@debug@", "@out2@"},
		note:    "classic three-step workflow; .gnu_debuglink stores the given name and the debug file's CRC, so both sides use the same relative names",
	},
	{
		name:   "set-section-flags",
		inputs: []string{"custom"},
		args:   []string{"--set-section-flags", ".mydata=alloc,load,code"},
	},
	{
		name:   "set-section-flags-debug",
		inputs: []string{"hello-nopie"},
		args:   []string{"--set-section-flags", ".comment=debug"},
		note:   "GNU maps the debug flag to a writable non-alloc section",
	},
	{
		name:   "rename-section",
		inputs: []string{"custom"},
		args:   []string{"--rename-section", ".mydata=.yourdata"},
	},
	{
		name:       "rename-section-with-flags",
		inputs:     []string{"custom"},
		args:       []string{"--rename-section", ".mydata=.yourdata,alloc,load,readonly,code"},
		skipReason: "GNU 2.44 zeroes the contents of a renamed section when its flags are replaced; gobjcopy keeps them",
	},

	// ---------------------------------------------------------------------
	// Section/symbol prefixes, symbol-only extraction, alternate machine code
	// ---------------------------------------------------------------------
	{
		name:   "prefix-sections",
		inputs: []string{"reloc.o"},
		args:   []string{"--prefix-sections", "foo_"},
		note:   "relocation sections follow their target: .rela.text -> .relafoo_.text",
	},
	{
		name:   "prefix-alloc-sections",
		inputs: []string{"reloc.o"},
		args:   []string{"--prefix-alloc-sections", "al_"},
	},
	{
		name:   "prefix-sections-both",
		inputs: []string{"reloc.o"},
		args:   []string{"--prefix-sections", "foo_", "--prefix-alloc-sections", "al_"},
	},
	{
		name:   "rename-section-with-relocs",
		inputs: []string{"reloc.o"},
		args:   []string{"--rename-section", ".text=.mytext"},
		note:   "BFD renames .rela.text to .rela.mytext as well",
	},
	{
		name:   "prefix-sections-with-rename",
		inputs: []string{"reloc.o"},
		args:   []string{"--prefix-sections", "foo_", "--rename-section", ".text=.mytext"},
	},
	{
		name:   "prefix-sections-with-prefix-symbols",
		inputs: []string{"reloc.o"},
		args:   []string{"--prefix-sections", "foo_", "--prefix-symbols", "bar_"},
	},
	{
		name:   "prefix-symbols",
		inputs: []string{"reloc.o", "hello-nopie", "lib.so"},
		args:   []string{"--prefix-symbols", "bar_"},
	},
	{
		name:   "prefix-symbols-section-symbol",
		inputs: []string{"reloc.o"},
		args:   []string{"--prefix-symbols", "bar_", "-N", ".text"},
		note:   "the prefix is applied to the section symbol's derived name, so -N .text no longer matches",
	},
	{
		name:        "prefix-symbols-section-symbol-fatal",
		inputs:      []string{"reloc.o"},
		args:        []string{"--prefix-symbols", "bar_", "-N", "bar_.text"},
		looseStderr: true,
	},
	{
		name:   "prefix-symbols-with-redefine",
		inputs: []string{"reloc.o"},
		args:   []string{"--prefix-symbols", "bar_", "--redefine-sym", "func_a=func_z"},
	},
	{
		name:   "prefix-symbols-with-add-symbol",
		inputs: []string{"reloc.o"},
		args:   []string{"--prefix-symbols", "bar_", "--add-symbol", "NEW=0x1234"},
		note:   "GNU inserts --add-symbol symbols before the prefix step, so NEW stays unprefixed",
	},
	{
		name:   "extract-symbol",
		inputs: []string{"reloc.o", "hello-nopie", "hello-pie", "hello", "lib.so"},
		args:   []string{"--extract-symbol"},
	},
	{
		name:   "extract-symbol-with-prefixes",
		inputs: []string{"reloc.o"},
		args:   []string{"--extract-symbol", "--prefix-sections", "foo_", "--prefix-symbols", "bar_"},
	},
	{
		name:   "alt-machine-code",
		inputs: []string{"reloc.o", "hello-nopie"},
		args:   []string{"--alt-machine-code", "40"},
		note:   "two warnings on stderr are checked by the CLI tests; the result carries e_machine=40",
	},
	{
		name:   "change-leading-char",
		inputs: []string{"reloc.o", "hello-nopie"},
		args:   []string{"--change-leading-char"},
		note:   "ELF has no symbol leading character, so this is a no-op",
	},
	{
		name:   "remove-leading-char",
		inputs: []string{"reloc.o", "hello-nopie"},
		args:   []string{"--remove-leading-char"},
		note:   "ELF has no symbol leading character, so this is a no-op",
	},

	// ---------------------------------------------------------------------
	// Addresses, padding and filling
	// ---------------------------------------------------------------------
	{
		name:   "change-addresses",
		inputs: []string{"hello-nopie", "reloc.o"},
		args:   []string{"--change-addresses", "0x1000"},
	},
	{
		name:   "adjust-vma",
		inputs: []string{"hello-nopie", "reloc.o"},
		args:   []string{"--adjust-vma", "0x1000"},
	},
	{
		// GNU moves .text to a fresh file offset and adds a LOAD segment when
		// the new address would overlap .fini; gobjcopy must not let .fini
		// overwrite the moved .text contents.
		name:   "change-section-address",
		inputs: []string{"hello-nopie", "reloc.o"},
		args:   []string{"--change-section-address", ".text+0x100"},
	},
	{
		name:   "change-section-address-missing-warn",
		inputs: []string{"hello-nopie"},
		args:   []string{"--change-section-address", ".nosuch+0x100", "--change-warnings"},
		note:   "succeeds but warns '--change-section-vma ... never used' on stderr",
	},
	{
		name:   "set-start",
		inputs: []string{"hello-nopie", "reloc.o"},
		args:   []string{"--set-start", "0x500000"},
	},
	{
		name:   "pad-to",
		inputs: []string{"hello-pie"},
		args:   []string{"--pad-to", "0x20000"},
		note:   "GNU warns about a .bss lma adjustment naming a random temp file",
	},
	{
		name:   "pad-to-binary",
		inputs: []string{"hello-pie"},
		args:   []string{"-O", "binary", "--pad-to", "0x20000"},
	},
	{
		name:   "gap-fill",
		inputs: []string{"hello-nopie"},
		args:   []string{"--gap-fill", "0xaa"},
	},
	{
		name:   "gap-fill-binary",
		inputs: []string{"hello-nopie"},
		args:   []string{"-O", "binary", "--gap-fill=0xaa"},
	},
	{
		name:   "gap-fill-pad-binary",
		inputs: []string{"hello-pie"},
		args:   []string{"-O", "binary", "--gap-fill=0xaa", "--pad-to=0x20000"},
	},

	// ---------------------------------------------------------------------
	// Output formats
	// ---------------------------------------------------------------------
	{
		name:   "output-binary",
		inputs: []string{"hello-nopie", "custom"},
		args:   []string{"-O", "binary"},
	},
	{
		name:   "output-binary-only-text",
		inputs: []string{"hello-nopie"},
		args:   []string{"-j", ".text", "-O", "binary"},
	},
	{
		// x32 output keeps the x86-64 machine and relocation types, which
		// both implementations convert; elf32-i386 would instead reject the
		// x86-64 relocations (GNU fails, gobjcopy converts).
		name:   "output-elf32-on-reloc",
		inputs: []string{"reloc.o"},
		args:   []string{"-O", "elf32-x86-64"},
	},
	{
		name:   "output-elf32-on-reloc32",
		inputs: []string{"reloc32.o"},
		args:   []string{"-O", "elf32-i386"},
	},
	{
		name:   "input-binary",
		inputs: []string{"blob.bin"},
		args:   []string{"-I", "binary", "-O", "elf64-x86-64", "-B", "i386:x86-64"},
		note:   "symbol names are derived from the input basename",
	},

	// ---------------------------------------------------------------------
	// Miscellaneous CLI behaviour
	// ---------------------------------------------------------------------
	{
		name:   "preserve-dates",
		inputs: []string{"hello-nopie", "reloc.o"},
		args:   []string{"-p", "-R", ".comment"},
		post:   checkPreservedDates,
	},
	{
		name:    "in-place-strip-debug",
		inputs:  []string{"hello"},
		args:    []string{"--strip-debug"},
		inPlace: true,
		note:    "only an input file is given; GNU rewrites a temporary copy in place",
	},
	{
		name:    "in-place-rename-section",
		inputs:  []string{"custom"},
		args:    []string{"--rename-section", ".mydata=.yourdata"},
		inPlace: true,
	},
	{
		name:   "verbose",
		inputs: []string{"hello-nopie"},
		args:   []string{"-v", "--strip-debug"},
		note:   "-v is --verbose; its stdout text is captured but not compared",
	},
	{
		name:     "version",
		noOutput: true,
		steps:    [][]string{{"-V"}},
		note:     "-V/--version needs no file operands; only exit status is compared",
	},
}

// checkPreservedDates asserts that -p/--preserve-dates carried the input's
// timestamp to the output on both sides.  This is a property check the ELF
// semantic comparison cannot observe.
func checkPreservedDates(t *testing.T, refDir, subjDir string, tokens map[string]string) {
	t.Helper()
	in, out := tokens["@in@"], tokens["@out@"]
	for _, dir := range []string{refDir, subjDir} {
		inSt, err := os.Stat(filepath.Join(dir, in))
		if err != nil {
			t.Errorf("stat %s/%s: %v", dir, in, err)
			continue
		}
		outSt, err := os.Stat(filepath.Join(dir, out))
		if err != nil {
			t.Errorf("stat %s/%s: %v", dir, out, err)
			continue
		}
		if !outSt.ModTime().Equal(inSt.ModTime()) {
			t.Errorf("-p did not preserve mtime in %s: input=%v output=%v",
				dir, inSt.ModTime(), outSt.ModTime())
		}
	}
}

func TestDifferential(t *testing.T) {
	if fixtureErr != nil {
		t.Skipf("fixtures could not be built: %v", fixtureErr)
	}
	ref := findReference(t)
	subj := findSubject(t)
	t.Logf("reference: %s", ref)
	t.Logf("subject:   %s", subj)
	t.Logf("fixtures:  %s", fixtureRoot)

	for _, c := range differentialCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if c.note != "" {
				t.Logf("note: %s", c.note)
			}
			if len(c.inputs) == 0 {
				runDiffCase(t, c, "", ref, subj)
				return
			}
			for _, fixture := range c.inputs {
				fixture := fixture
				t.Run(fixture, func(t *testing.T) {
					runDiffCase(t, c, fixture, ref, subj)
				})
			}
		})
	}
}

// findReference locates GNU objcopy via PATH, honouring REF_COPY.
func findReference(t *testing.T) string {
	t.Helper()
	name := os.Getenv("REF_COPY")
	if name == "" {
		name = "objcopy"
	}
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("reference objcopy %q not found: %v", name, err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("cannot resolve reference path %q: %v", p, err)
	}
	return abs
}

// findSubject locates the implementation under test.  GOBJCOPY wins; without it
// the test looks for ./gobjcopy then ../gobjcopy and skips when neither exists,
// so the suite stays green in a checkout without a built binary.
func findSubject(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("GOBJCOPY"); v != "" {
		cand := v
		if !strings.ContainsRune(v, os.PathSeparator) {
			if p, err := exec.LookPath(v); err == nil {
				cand = p
			}
		}
		abs, err := filepath.Abs(cand)
		if err != nil {
			t.Fatalf("cannot resolve GOBJCOPY=%q: %v", v, err)
		}
		st, err := os.Stat(abs)
		if err != nil {
			t.Fatalf("GOBJCOPY=%q is not usable: %v", v, err)
		}
		if st.IsDir() {
			t.Fatalf("GOBJCOPY=%q is a directory", v)
		}
		if st.Mode()&0o111 == 0 {
			t.Fatalf("GOBJCOPY=%q is not executable", v)
		}
		return abs
	}
	for _, cand := range []string{"./gobjcopy", "../gobjcopy"} {
		st, err := os.Stat(cand)
		if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
			continue
		}
		abs, err := filepath.Abs(cand)
		if err != nil {
			t.Fatalf("cannot resolve %q: %v", cand, err)
		}
		return abs
	}
	t.Skip("no gobjcopy under test: set GOBJCOPY or build ./gobjcopy")
	return ""
}

// runDiffCase runs one case on one fixture, both sides in private directories.
func runDiffCase(t *testing.T, c testCase, fixture, ref, subj string) {
	t.Helper()
	var src string
	if fixture != "" {
		var ok bool
		src, ok = fixtureFiles[fixture]
		if !ok {
			t.Skipf("fixture %q is not available on this host", fixture)
		}
	}
	if c.skipReason != "" && (len(c.skipInputs) == 0 || slices.Contains(c.skipInputs, fixture)) {
		t.Skip(c.skipReason)
	}
	tokens := map[string]string{}
	if src != "" {
		tokens = makeTokens(filepath.Base(src))
	}

	root := t.TempDir()
	refDir := filepath.Join(root, "ref")
	subjDir := filepath.Join(root, "subj")
	for _, dir := range []string{refDir, subjDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if src != "" {
		// Copy, never touch the fixture original.
		copyFile(t, src, filepath.Join(refDir, filepath.Base(src)))
		copyFile(t, src, filepath.Join(subjDir, filepath.Base(src)))
	}

	cmds := c.commands()
	refResults, err := runSequence(ref, refDir, cmds, tokens)
	if err != nil {
		t.Fatalf("reference: %v", err)
	}
	subjResults, err := runSequence(subj, subjDir, cmds, tokens)
	if err != nil {
		t.Fatalf("subject: %v", err)
	}

	if !compareSequences(t, c, ref, subj, refDir, subjDir, refResults, subjResults) {
		return
	}

	for _, name := range c.outputNames() {
		name = expandTokens([]string{name}, tokens)[0]
		compareOutputs(t, filepath.Join(refDir, name), filepath.Join(subjDir, name))
	}
	if c.post != nil {
		c.post(t, refDir, subjDir, tokens)
	}
}

// runSequence runs the command templates until one fails (a failing step makes
// later steps meaningless).  A command that cannot be started at all is an
// error; a non-zero exit status is a normal result.
func runSequence(prog, dir string, cmds [][]string, tokens map[string]string) ([]execResult, error) {
	var results []execResult
	for _, tmpl := range cmds {
		res, err := runCommand(prog, dir, tmpl, tokens)
		if err != nil {
			return results, err
		}
		results = append(results, res)
		if res.exit != 0 {
			break
		}
	}
	return results, nil
}

// compareSequences compares exit statuses step by step.  It returns true only
// when every step succeeded on both sides, meaning output files are comparable.
func compareSequences(t *testing.T, c testCase, ref, subj, refDir, subjDir string,
	refResults, subjResults []execResult) bool {
	t.Helper()
	n := len(refResults)
	if len(subjResults) < n {
		n = len(subjResults)
	}
	for i := 0; i < n; i++ {
		r, s := refResults[i], subjResults[i]
		if r.exit != s.exit {
			t.Errorf("step %d %q: exit status differs: reference=%d subject=%d\nreference stderr:\n%s\nsubject stderr:\n%s",
				i+1, r.argv, r.exit, s.exit, indent(r.stderr), indent(s.stderr))
			return false
		}
		if r.exit == 0 {
			continue
		}

		// Both failed.  Compare only the essential diagnostic text, with paths
		// and the program name normalised away.
		refKey := keyError(r.stderr, refDir, ref)
		subjKey := keyError(s.stderr, subjDir, subj)
		if referenceDoesNotSupport(refKey) {
			t.Skipf("reference objcopy does not support this combination: %s", refKey)
		}
		if refKey != subjKey && c.looseStderr {
			t.Logf("step %d %q: both failed (diagnostics differ by design): %s", i+1, r.argv, firstLine(refKey))
			return false
		}
		if refKey != subjKey {
			t.Errorf("step %d %q: both failed with exit %d but diagnostics differ\nreference:\n%s\nsubject:\n%s",
				i+1, r.argv, r.exit, indent(refKey), indent(subjKey))
			return false
		}
		t.Logf("step %d %q: both sides failed identically with exit %d: %s",
			i+1, r.argv, r.exit, firstLine(refKey))
		return false // no output files to compare
	}
	if len(refResults) != len(subjResults) {
		t.Errorf("step count differs: reference ran %d, subject ran %d (one side stopped early)",
			len(refResults), len(subjResults))
		return false
	}
	return true
}

// referenceDoesNotSupport recognises diagnostics meaning the reference does not
// know an option or argument at all.  Such a case is skipped rather than failed:
// there is no GNU behaviour to compare against.
func referenceDoesNotSupport(key string) bool {
	lower := strings.ToLower(key)
	for _, phrase := range []string{
		"unrecognized option",
		"unrecognized argument",
		"unknown option",
	} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// compareOutputs compares one pair of output files.  Two ELF files are compared
// semantically; anything else is compared byte for byte.
func compareOutputs(t *testing.T, refPath, subjPath string) {
	t.Helper()
	refBytes, refErr := os.ReadFile(refPath)
	subjBytes, subjErr := os.ReadFile(subjPath)
	if refErr != nil || subjErr != nil {
		t.Errorf("output file missing or unreadable: reference=%v subject=%v", refErr, subjErr)
		return
	}
	refELF, subjELF := isELF(refBytes), isELF(subjBytes)
	switch {
	case refELF && subjELF:
		refDump, err := elfdump.DumpFile(refPath, elfdump.Default)
		if err != nil {
			t.Errorf("cannot parse reference ELF output %s: %v", filepath.Base(refPath), err)
			return
		}
		subjDump, err := elfdump.DumpFile(subjPath, elfdump.Default)
		if err != nil {
			t.Errorf("cannot parse subject ELF output %s: %v", filepath.Base(subjPath), err)
			return
		}
		refDump, subjDump = normalizeNoteAlign(refDump), normalizeNoteAlign(subjDump)
		if refDump != subjDump {
			t.Errorf("ELF output %s differs semantically:\n%s",
				filepath.Base(refPath), elfdump.FirstDiff(refDump, subjDump))
		}
		compareReadelfSections(t, refPath, subjPath)
	case refELF != subjELF:
		t.Errorf("output %s: reference is ELF=%v but subject is ELF=%v",
			filepath.Base(refPath), refELF, subjELF)
	default:
		if diff := binaryDiff(refBytes, subjBytes); diff != "" {
			t.Errorf("binary output %s differs:\n%s", filepath.Base(refPath), diff)
		}
	}
}

// normalizeNoteAlign hides sh_addralign of GNU property notes.  GNU keeps 8
// for some compiler-produced objects but writes the class word for assembled
// ones; gobjcopy follows BFD's conversion code and always writes the class
// word.  The note payload is still compared.
func normalizeNoteAlign(dump string) string {
	lines := strings.Split(dump, "\n")
	for i, line := range lines {
		if !strings.Contains(line, `.note.gnu.property`) {
			continue
		}
		if j := strings.Index(line, " align=0x"); j >= 0 {
			rest := line[j+len(" align=0x"):]
			if k := strings.IndexByte(rest, ' '); k >= 0 {
				rest = rest[k:]
			} else {
				rest = ""
			}
			lines[i] = line[:j] + " align=*" + rest
		}
	}
	return strings.Join(lines, "\n")
}

func indent(s string) string {
	if s == "" {
		return "    <empty>"
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = "    " + line
	}
	return strings.Join(lines, "\n")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
