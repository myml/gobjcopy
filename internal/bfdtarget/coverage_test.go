package bfdtarget

// Coverage tests: every advertised target must parse back to itself, the
// canonical-name helpers must agree with Parse, and every error path must
// produce a message that quotes the offending input.

import (
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

func TestAllTargetsRoundTrip(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("All() is empty")
	}
	seen := map[string]bool{}
	for _, want := range all {
		if want == nil || want.Name == "" {
			t.Fatalf("invalid target in All(): %+v", want)
		}
		if seen[want.Name] {
			t.Errorf("duplicate target %q", want.Name)
		}
		seen[want.Name] = true
		if got := want.String(); got != want.Name {
			t.Errorf("String() = %q, want %q", got, want.Name)
		}
		got, err := Parse(want.Name)
		if err != nil {
			t.Errorf("Parse(%q) failed: %v", want.Name, err)
			continue
		}
		if got.Class != want.Class || got.Data != want.Data ||
			got.Machine != want.Machine || got.IsELF != want.IsELF ||
			got.IsBinary != want.IsBinary || got.IsIHex != want.IsIHex ||
			got.IsSREC != want.IsSREC || got.IsVerilog != want.IsVerilog {
			t.Errorf("Parse(%q) = %+v, want %+v", want.Name, got, want)
		}
		if !strings.Contains(Info(), want.Name) {
			t.Errorf("Info() does not mention %q", want.Name)
		}
	}
}

func TestDefaultTarget(t *testing.T) {
	d := Default()
	if d == nil || !d.IsELF {
		t.Fatalf("Default() = %+v", d)
	}
	back, err := Parse(d.Name)
	if err != nil {
		t.Fatalf("Parse(Default().Name): %v", err)
	}
	if back.Class != d.Class || back.Data != d.Data || back.Machine != d.Machine {
		t.Errorf("Default() round trip = %+v, want %+v", back, d)
	}
}

func TestParseVariants(t *testing.T) {
	cases := []struct {
		in      string
		class   elf.Class
		data    elf.Data
		machine uint16
		elf     bool
		binary  bool
		ihex    bool
		srec    bool
	}{
		{"elf64-x86-64", elf.Class64, elf.DataLSB, elf.EM_X86_64, true, false, false, false},
		{"ELF32-I386", elf.Class32, elf.DataLSB, elf.EM_386, true, false, false, false},
		{"  elf64-little  ", elf.Class64, elf.DataLSB, elf.EM_NONE, true, false, false, false},
		{"elf32-big", elf.Class32, elf.DataMSB, elf.EM_NONE, true, false, false, false},
		{"elf64-bigaarch64", elf.Class64, elf.DataMSB, elf.EM_AARCH64, true, false, false, false},
		{"elf32-littlearm", elf.Class32, elf.DataLSB, elf.EM_ARM, true, false, false, false},
		{"elf32-x86-64", elf.Class32, elf.DataLSB, elf.EM_X86_64, true, false, false, false},
		{"binary", 0, 0, 0, false, true, false, false},
		{"ihex", 0, 0, 0, false, false, true, false},
		{"srec", 0, 0, 0, false, false, false, true},
		{"verilog", 0, 0, 0, false, false, false, false},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if got.Class != c.class || got.Data != c.data || got.Machine != c.machine ||
			got.IsELF != c.elf || got.IsBinary != c.binary || got.IsIHex != c.ihex || got.IsSREC != c.srec {
			t.Errorf("Parse(%q) = %+v", c.in, got)
		}
	}
}

func TestParseErrorMessages(t *testing.T) {
	for _, in := range []string{"", "   ", "elf64", "elf32-", "elf64-bogusarch", "macho", "binary-x", "elf16-little"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", in)
		} else if !strings.Contains(err.Error(), strings.TrimSpace(in)) {
			t.Errorf("error for %q does not quote the input: %v", in, err)
		}
	}
}

func TestParseArchMore(t *testing.T) {
	cases := []struct {
		in      string
		class   elf.Class
		machine uint16
	}{
		{"i386:x86-64", elf.Class64, elf.EM_X86_64},
		{"x86-64", elf.Class64, elf.EM_X86_64},
		{"i386", elf.Class32, elf.EM_386},
		{"arm", elf.Class32, elf.EM_ARM},
		{"aarch64", elf.Class64, elf.EM_AARCH64},
		{"riscv:rv64", elf.Class64, elf.EM_RISCV},
		{"riscv:rv32", elf.Class32, elf.EM_RISCV},
		{"powerpc:common64", elf.Class64, elf.EM_PPC64},
		{"s390:64", elf.Class64, elf.EM_S390},
		{"loongarch64", elf.Class64, elf.EM_LOONGARCH},
	}
	for _, c := range cases {
		class, machine, ok := ParseArch(c.in)
		if !ok {
			t.Errorf("ParseArch(%q) failed", c.in)
			continue
		}
		if class != c.class || machine != c.machine {
			t.Errorf("ParseArch(%q) = (%d, %d), want (%d, %d)", c.in, class, machine, c.class, c.machine)
		}
	}
	for _, in := range []string{"", "bogus", ":rv64"} {
		if _, _, ok := ParseArch(in); ok {
			t.Errorf("ParseArch(%q) unexpectedly succeeded", in)
		}
	}
}

func TestCanonicalName(t *testing.T) {
	cases := []struct {
		class   elf.Class
		data    elf.Data
		machine uint16
		want    string
	}{
		{elf.Class64, elf.DataLSB, elf.EM_X86_64, "elf64-x86-64"},
		{elf.Class32, elf.DataLSB, elf.EM_386, "elf32-i386"},
		{elf.Class64, elf.DataLSB, elf.EM_NONE, "elf64-little"},
		{elf.Class32, elf.DataMSB, elf.EM_NONE, "elf32-big"},
		{elf.Class64, elf.DataMSB, elf.EM_AARCH64, "elf64-bigaarch64"},
		{elf.Class64, elf.DataLSB, elf.EM_PPC64, "elf64-littlepowerpc64"},
		{elf.Class32, elf.DataLSB, 0x1234, "elf32-little"},
	}
	for _, c := range cases {
		if got := canonicalName(c.class, c.data, c.machine); got != c.want {
			t.Errorf("canonicalName(%d,%d,%d) = %q, want %q", c.class, c.data, c.machine, got, c.want)
		}
		if got := String(c.class, c.data, c.machine); got != c.want {
			t.Errorf("String(...) = %q, want %q", got, c.want)
		}
	}
	if machineData(elf.EM_PPC) != elf.DataMSB || machineData(elf.EM_X86_64) != elf.DataLSB {
		t.Error("machineData returned the wrong natural byte order")
	}
}

func TestGenericAndMustParse(t *testing.T) {
	g := generic(elf.Class64, elf.DataLSB, elf.EM_X86_64, "i386")
	if g == nil || !g.IsELF || g.Class != elf.Class64 || g.Machine != elf.EM_X86_64 {
		t.Fatalf("generic() = %+v", g)
	}
	if got := mustParse("elf32-i386"); got.Class != elf.Class32 {
		t.Errorf("mustParse(elf32-i386) = %+v", got)
	}
	if got := mustParse("  binary "); !got.IsBinary {
		t.Errorf("mustParse(binary) = %+v", got)
	}
}
