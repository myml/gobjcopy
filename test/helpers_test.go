package test

// Helpers shared by the differential test scaffold.
//
// The scaffold runs the same objcopy-style command line against two
// executables (the GNU reference and the subject under test), each in its own
// scratch directory, then compares exit status and the resulting files.  This
// file contains the process plumbing, text normalisation, and an independent
// readelf based section cross-check.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// execResult is the captured outcome of one command invocation.
type execResult struct {
	argv   []string
	exit   int
	stdout string
	stderr string
}

// cleanEnv returns the process environment with the locale forced to C so
// diagnostics from GNU tools are stable, and without duplicate or user
// supplied locale overrides.
func cleanEnv() []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LC_ALL=") || strings.HasPrefix(kv, "LANG=") ||
			strings.HasPrefix(kv, "LC_MESSAGES=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "LC_ALL=C", "LANG=C")
}

// runCommand executes prog with argv in dir and captures its exit status,
// stdout and stderr.  A non-zero exit status is not an error; a failure to
// even start the program is.
func runCommand(prog, dir string, argv []string, tokens map[string]string) (execResult, error) {
	argv = expandTokens(argv, tokens)
	cmd := exec.Command(prog, argv...)
	cmd.Dir = dir
	cmd.Env = cleanEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	res := execResult{argv: argv}
	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.exit = exitErr.ExitCode()
			res.stdout = stdout.String()
			res.stderr = stderr.String()
			return res, nil
		}
		return res, fmt.Errorf("cannot run %s: %w", prog, err)
	}
	res.stdout = stdout.String()
	res.stderr = stderr.String()
	return res, nil
}

// expandTokens substitutes @in@, @out@, ... placeholders in a command line.
// The command is always executed directly (no shell), so quoting is preserved
// as ordinary argument text.
func expandTokens(args []string, tokens map[string]string) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		for token, value := range tokens {
			arg = strings.ReplaceAll(arg, token, value)
		}
		out[i] = arg
	}
	return out
}

// makeTokens builds the placeholder map for one input file name.  All paths
// are relative to the per-side scratch directory, which keeps output bytes
// such as .gnu_debuglink contents identical between the two runs.
func makeTokens(input string) map[string]string {
	if input == "" {
		return map[string]string{}
	}
	return map[string]string{
		"@in@":    input,
		"@out@":   input + ".out",
		"@out2@":  input + ".out2",
		"@debug@": input + ".debug",
		"@bin@":   input + ".bin",
	}
}

// copyFile copies src to dst preserving permission bits and timestamps.
// Preserving timestamps makes -p/--preserve-dates deterministic for both
// sides; the fixture originals are only ever read.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	st, err := os.Stat(src)
	if err != nil {
		t.Fatalf("stat fixture %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, st.Mode().Perm()); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
	if err := os.Chmod(dst, st.Mode().Perm()); err != nil {
		t.Fatalf("chmod %s: %v", dst, err)
	}
	if err := os.Chtimes(dst, st.ModTime(), st.ModTime()); err != nil {
		t.Fatalf("chtimes %s: %v", dst, err)
	}
}

// keyError reduces stderr to the "interesting" lines so two implementations
// can be compared without requiring byte-identical diagnostics:
//
//   - the scratch directory and program path are replaced by placeholders,
//   - warning lines are dropped (GNU often warns and then succeeds),
//   - lines are sorted, because ordering is not semantically interesting.
//
// When no error-looking line exists (for instance a failure that only prints a
// warning), all non-empty lines are kept.
func keyError(stderr, workdir, prog string) string {
	s := stderr
	s = strings.ReplaceAll(s, workdir, "<work>")
	s = strings.ReplaceAll(s, filepath.Clean(workdir), "<work>")
	s = strings.ReplaceAll(s, prog, "<prog>")
	s = strings.ReplaceAll(s, filepath.Base(prog), "<prog>")

	var all, key []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		all = append(all, line)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "warning:") {
			continue
		}
		key = append(key, line)
	}
	if len(key) == 0 {
		key = all
	}
	sort.Strings(key)
	return strings.Join(key, "\n")
}

// binaryDiff reports the first differing byte together with a hex context
// window, or "" if a and b are identical.
func binaryDiff(a, b []byte) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return fmt.Sprintf("first difference at offset %#x (lengths %d and %d)\n  a: %s\n  b: %s",
				i, len(a), len(b), hexContext(a, i), hexContext(b, i))
		}
	}
	if len(a) != len(b) {
		return fmt.Sprintf("common prefix of %d bytes, lengths differ: %d and %d", n, len(a), len(b))
	}
	return ""
}

// hexContext returns up to 16 bytes around off as hex, with the byte at off
// marked by brackets.
func hexContext(b []byte, off int) string {
	const window = 8
	start := off - window
	if start < 0 {
		start = 0
	}
	end := off + window + 1
	if end > len(b) {
		end = len(b)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "[0x%x] ", start)
	for i := start; i < end; i++ {
		if i == off {
			fmt.Fprintf(&sb, "[%02x] ", b[i])
		} else {
			fmt.Fprintf(&sb, "%02x ", b[i])
		}
	}
	return strings.TrimSpace(sb.String())
}

func isELF(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
}

// readelfSections parses `readelf -SW` into a sorted set of section records
// covering name, type, address, size, flags and alignment.  It deliberately
// ignores section and file offsets, like the elfdump comparison does.
func readelfSections(path string) ([]string, error) {
	prog, err := exec.LookPath("readelf")
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(prog, "-SW", path)
	cmd.Env = cleanEnv()
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("readelf -SW %s: %v: %s", path, err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("readelf -SW %s: %w", path, err)
	}

	var records []string
	for _, line := range strings.Split(string(out), "\n") {
		close := strings.Index(line, "]")
		if close < 0 {
			continue
		}
		f := strings.Fields(line[close+1:])
		// Name Type Address Off Size ES [Flg] Lk Inf Al
		if len(f) < 9 {
			continue
		}
		var flags, align string
		if len(f) >= 10 {
			flags, align = f[6], f[9]
		} else {
			align = f[8]
		}
		size := normHex(f[4])
		// String tables reachable only from symbol tables may legitimately
		// differ in layout between implementations.
		switch f[0] {
		case ".strtab", ".dynstr", ".shstrtab":
			size = "0x0"
		}
		records = append(records, strings.Join([]string{
			f[0],
			f[1],
			normHex(f[2]),
			size,
			flags,
			align,
		}, "|"))
	}
	sort.Strings(records)
	return records, nil
}

func normHex(s string) string {
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return s
	}
	return fmt.Sprintf("%#x", v)
}

// compareReadelfSections is an independent corroboration of the elfdump
// comparison.  It is skipped when readelf is unavailable or when the reference
// output cannot be parsed (which means there is nothing to cross-check).
func compareReadelfSections(t *testing.T, refPath, subjPath string) {
	t.Helper()
	ref, err := readelfSections(refPath)
	if errors.Is(err, exec.ErrNotFound) {
		t.Logf("readelf not found; skipping readelf cross-check")
		return
	}
	if err != nil {
		t.Logf("readelf could not parse reference output (%v); skipping cross-check", err)
		return
	}
	subj, err := readelfSections(subjPath)
	if err != nil {
		t.Errorf("readelf could not parse subject output: %v", err)
		return
	}
	if diff := firstDifference(ref, subj); diff != "" {
		t.Errorf("readelf section cross-check disagrees:\n%s", diff)
	}
}

// firstDifference compares two string slices and describes the first
// mismatch, including a few neighbouring entries.
func firstDifference(a, b []string) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			lo := i - 2
			if lo < 0 {
				lo = 0
			}
			hiA, hiB := i+3, i+3
			if hiA > len(a) {
				hiA = len(a)
			}
			if hiB > len(b) {
				hiB = len(b)
			}
			return fmt.Sprintf("at index %d:\n  ref:  %s\n  subj: %s\n  ref  context: %s\n  subj context: %s",
				i, a[i], b[i], a[lo:hiA], b[lo:hiB])
		}
	}
	if len(a) != len(b) {
		return fmt.Sprintf("different number of section records: ref=%d subj=%d", len(a), len(b))
	}
	return ""
}
