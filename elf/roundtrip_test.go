package elf_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

// TestRoundTrip exercises Parse -> Bytes -> Parse for every fixture, compares
// the results semantically, validates them with readelf and runs rewritten
// executables.
func TestRoundTrip(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	names := fixtureNames(t)
	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := fixture(t, name)
			f, err := elf.Open(path)
			if err != nil {
				t.Fatalf("%s: Open: %v", name, err)
			}

			runnable := isRunnable(f)
			wantExit, wantOut := 0, ""
			if runnable {
				wantExit, wantOut = runBinary(t, path)
			}

			dst := writeELF(t, f, 0o755, name)
			if fi, err := os.Stat(dst); err != nil {
				t.Fatalf("%s: stat rewritten file: %v", name, err)
			} else if fi.Mode().Perm()&0o111 == 0 {
				t.Errorf("%s: rewritten file is not executable: %v", name, fi.Mode())
			}

			assertReadelfParses(t, dst)
			g, err := elf.Open(dst)
			if err != nil {
				t.Fatalf("%s: reparse %s: %v", name, dst, err)
			}
			assertDumpsEqual(t, name, f, g)
			assertSemanticEqual(t, name, f, g)
			assertReadelfMatchesModel(t, dst, g)

			// Serialising the reparsed image must be stable.
			first, err := g.Bytes()
			if err != nil {
				t.Fatalf("%s: second Bytes: %v", name, err)
			}
			again, err := elf.Parse(first)
			if err != nil {
				t.Fatalf("%s: Parse of second serialisation: %v", name, err)
			}
			second, err := again.Bytes()
			if err != nil {
				t.Fatalf("%s: third Bytes: %v", name, err)
			}
			if !bytes.Equal(first, second) {
				t.Errorf("%s: serialisation is not idempotent (%d vs %d bytes)", name, len(first), len(second))
			}

			if !runnable {
				return
			}
			gotExit, gotOut := runBinary(t, dst)
			if gotExit != wantExit || gotOut != wantOut {
				t.Errorf("%s: rewritten executable behaves differently: exit %d/%q, original exit %d/%q",
					name, gotExit, gotOut, wantExit, wantOut)
			}
			// Every runnable fixture except "custom" exits 0 by construction.
			// custom's main returns my_blob[0]+my_ro[0] == 'B'+1 == 67.
			if name != "custom" && gotExit != 0 {
				t.Errorf("%s: rewritten executable exited %d, want 0 (output %q)", name, gotExit, gotOut)
			}
			if name == "custom" && gotExit != 67 {
				t.Errorf("%s: rewritten executable exited %d, want fixture's 67", name, gotExit)
			}
		})
	}
}

// TestRoundTripSystemBinaries additionally covers binaries that were not
// produced by gcc, such as the host's /bin/true.
func TestRoundTripSystemBinaries(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	for _, p := range []string{"/bin/true", "/bin/ls"} {
		p := p
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			if _, err := os.Stat(p); err != nil {
				t.Skipf("%s not available: %v", p, err)
			}
			f, err := elf.Open(p)
			if err != nil {
				t.Fatalf("%s: Open: %v", p, err)
			}
			dst := writeELF(t, f, 0o755, "rewritten")
			assertReadelfParses(t, dst)
			g, err := elf.Open(dst)
			if err != nil {
				t.Fatalf("%s: reparse: %v", p, err)
			}
			assertDumpsEqual(t, p, f, g)
			assertSemanticEqual(t, p, f, g)
			assertReadelfMatchesModel(t, dst, g)
			wantExit, wantOut := runBinary(t, p)
			gotExit, gotOut := runBinary(t, dst)
			if gotExit != wantExit || gotOut != wantOut {
				t.Errorf("%s: rewritten binary behaves differently: exit %d/%q, original %d/%q",
					p, gotExit, gotOut, wantExit, wantOut)
			}
		})
	}
}
