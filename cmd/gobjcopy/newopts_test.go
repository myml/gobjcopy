package main

// CLI-level tests for --prefix-sections, --prefix-alloc-sections,
// --prefix-symbols, --extract-symbol, --alt-machine-code and the two ELF
// no-op leading-character options.

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/fixtures"
	"github.com/myml/gobjcopy/objcopy"
)

func TestParseCULong(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
	}{
		{"40", 40},
		{"0x28", 40},
		{"0X28", 40},
		{"040", 32},
		{"0409", 32}, // base 8 stops at '9'
		{"0", 0},
		{"0x0", 0},
		{"0x", 0},
		{"abc", 0},
		{"", 0},
		{"40xyz", 40},
		{"  \t+40", 40},
		{"-1", math.MaxUint64},
		{"18446744073709551616", math.MaxUint64},
		{"0b10", 0}, // strtoul base 0 also stops at 'b'
	}
	for _, tc := range tests {
		if got := parseCULong(tc.in); got != tc.want {
			t.Errorf("parseCULong(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseArgsNewOptions(t *testing.T) {
	cfg, operands, err := parseArgs([]string{
		"--prefix-sections=foo_",
		"--prefix-alloc-sections=al_",
		"--prefix-symbols=bar_",
		"--extract-symbol",
		"--alt-machine-code=0x28",
		"in", "out",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(operands, []string{"in", "out"}) {
		t.Errorf("operands = %v", operands)
	}
	if cfg.PrefixSections != "foo_" || cfg.PrefixAllocSections != "al_" || cfg.PrefixSymbols != "bar_" {
		t.Errorf("prefixes = %q/%q/%q", cfg.PrefixSections, cfg.PrefixAllocSections, cfg.PrefixSymbols)
	}
	if !cfg.ExtractSymbol {
		t.Error("ExtractSymbol not set")
	}
	if cfg.AltMachineCode != 40 {
		t.Errorf("AltMachineCode = %d, want 40", cfg.AltMachineCode)
	}

	// --change-leading-char and --remove-leading-char are accepted but must
	// not modify the configuration: ELF has no leading character.
	for _, opt := range []string{"--change-leading-char", "--remove-leading-char"} {
		got, _, err := parseArgs([]string{opt, "in", "out"})
		if err != nil {
			t.Fatalf("%s: %v", opt, err)
		}
		if !reflect.DeepEqual(got, objcopy.Default()) {
			t.Errorf("%s changed the configuration: %+v", opt, got)
		}
	}
}

func buildNewOptsFixture(t *testing.T, name string) string {
	t.Helper()
	p, err := fixtures.BuildOne(t.TempDir(), name)
	if err != nil {
		t.Skipf("fixture %s unavailable: %v", name, err)
	}
	return p
}

func TestRunAltMachineCode(t *testing.T) {
	in := buildNewOptsFixture(t, "reloc.o")
	out := filepath.Join(t.TempDir(), "out.o")
	code, _, stderr := runCLI(t, "--alt-machine-code=40", in, out)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	want := "gobjcopy: this target does not support 40 alternative machine codes\n" +
		"gobjcopy: treating that number as an absolute e_machine value instead\n"
	if stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	f, err := elf.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	if f.Machine != 40 {
		t.Errorf("e_machine = %d, want 40", f.Machine)
	}
}

func TestRunAltMachineCodeFatal(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.o")
	for _, arg := range []string{"--alt-machine-code=0", "--alt-machine-code=abc", "--alt-machine-code=0x0"} {
		code, _, stderr := runCLI(t, arg, "in", out)
		if code != 1 {
			t.Errorf("%s: exit = %d, want 1", arg, code)
		}
		if stderr != "gobjcopy: unable to parse alternative machine code\n" {
			t.Errorf("%s: stderr = %q", arg, stderr)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("%s: output file was created", arg)
		}
	}
}

func readFileOrFail(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRunLeadingCharIsNoOp(t *testing.T) {
	for _, fixture := range []string{"reloc.o", "hello-nopie"} {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			in := buildNewOptsFixture(t, fixture)
			dir := t.TempDir()
			base := filepath.Join(dir, "base")
			if code, _, stderr := runCLI(t, in, base); code != 0 {
				t.Fatalf("plain copy failed: %s", stderr)
			}
			want := readFileOrFail(t, base)
			for _, opt := range []string{"--change-leading-char", "--remove-leading-char"} {
				out := filepath.Join(dir, strings.TrimPrefix(opt, "--"))
				code, _, stderr := runCLI(t, opt, in, out)
				if code != 0 {
					t.Fatalf("%s: exit = %d, stderr = %s", opt, code, stderr)
				}
				if got := readFileOrFail(t, out); !bytes.Equal(got, want) {
					t.Errorf("%s changed the output (%d vs %d bytes)", opt, len(got), len(want))
				}
			}
		})
	}
}

func TestRunSectionAndSymbolPrefixes(t *testing.T) {
	in := buildNewOptsFixture(t, "reloc.o")
	out := filepath.Join(t.TempDir(), "out.o")
	code, _, stderr := runCLI(t,
		"--prefix-sections=foo_",
		"--prefix-alloc-sections=al_",
		"--prefix-symbols=bar_",
		in, out)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	f, err := elf.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	// .text is allocatable, .debug_info is not.
	for _, name := range []string{"al_.text", "foo_.debug_info", ".relaal_.text"} {
		if f.Section(name) == nil {
			var have []string
			for _, s := range f.Sections {
				have = append(have, s.Name)
			}
			t.Fatalf("missing section %q; have %v", name, have)
		}
	}
	st, err := f.ReadSymtab(f.SectionByType(elf.SHT_SYMTAB))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, sym := range st.Entries {
		if sym.Name != "" {
			names = append(names, sym.Name)
			if !strings.HasPrefix(sym.Name, "bar_") {
				t.Errorf("symbol %q was not prefixed", sym.Name)
			}
		}
	}
	for _, want := range []string{"bar_func_a", "bar_func_b", "bar_ext_var", "bar_reloc.c"} {
		found := false
		for _, name := range names {
			if name == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing symbol %q; have %v", want, names)
		}
	}
}

func TestRunExtractSymbol(t *testing.T) {
	for _, fixture := range []string{"reloc.o", "hello-nopie", "hello-pie"} {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			in := buildNewOptsFixture(t, fixture)
			src, err := elf.Open(in)
			if err != nil {
				t.Fatal(err)
			}
			srcSyms := 0
			if st := src.Symtab(); st != nil {
				srcSyms = len(st.Entries)
			}
			if srcSyms == 0 {
				t.Skip("fixture has no static symbol table")
			}
			out := filepath.Join(t.TempDir(), "out")
			code, _, stderr := runCLI(t, "--extract-symbol", in, out)
			if code != 0 {
				t.Fatalf("exit = %d, stderr = %s", code, stderr)
			}
			f, err := elf.Open(out)
			if err != nil {
				t.Fatal(err)
			}
			if f.Entry != 0 {
				t.Errorf("entry = %#x, want 0", f.Entry)
			}
			if f.Type != src.Type {
				t.Errorf("e_type = %d, want %d", f.Type, src.Type)
			}
			for _, s := range f.Sections {
				switch s.Name {
				case "", ".symtab", ".strtab", ".shstrtab":
					continue
				}
				if s.Size != 0 {
					t.Errorf("section %s size = %#x, want 0", s.Name, s.Size)
				}
			}
			st := f.Symtab()
			if st == nil {
				t.Fatal("symbol table was stripped")
			}
			if len(st.Entries) != srcSyms {
				t.Errorf("symbol count = %d, want %d (unchanged)", len(st.Entries), srcSyms)
			}
		})
	}
}
