package bfdtarget

import (
	"runtime"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in      string
		name    string
		class   elf.Class
		data    elf.Data
		machine uint16
		isELF   bool
	}{
		{"elf64-x86-64", "elf64-x86-64", elf.Class64, elf.DataLSB, elf.EM_X86_64, true},
		{"ELF64-X86-64", "elf64-x86-64", elf.Class64, elf.DataLSB, elf.EM_X86_64, true},
		{"  Elf32-I386 ", "elf32-i386", elf.Class32, elf.DataLSB, elf.EM_386, true},
		{"elf32-iamcu", "elf32-iamcu", elf.Class32, elf.DataLSB, elf.EM_IAMCU, true},
		{"elf32-x86-64", "elf32-x86-64", elf.Class32, elf.DataLSB, elf.EM_X86_64, true},
		{"elf64-aarch64", "elf64-aarch64", elf.Class64, elf.DataLSB, elf.EM_AARCH64, true},
		{"elf64-littleaarch64", "elf64-aarch64", elf.Class64, elf.DataLSB, elf.EM_AARCH64, true},
		{"elf32-bigarm", "elf32-bigarm", elf.Class32, elf.DataMSB, elf.EM_ARM, true},
		{"elf64-riscv", "elf64-riscv", elf.Class64, elf.DataLSB, elf.EM_RISCV, true},
		{"elf32-riscv", "elf32-riscv", elf.Class32, elf.DataLSB, elf.EM_RISCV, true},
		{"elf64-mips", "elf64-mips", elf.Class64, elf.DataMSB, elf.EM_MIPS, true},
		{"elf32-mips", "elf32-mips", elf.Class32, elf.DataMSB, elf.EM_MIPS, true},
		{"elf32-tradlittlemips", "elf32-littlemips", elf.Class32, elf.DataLSB, elf.EM_MIPS, true},
		{"elf64-powerpc64", "elf64-powerpc64", elf.Class64, elf.DataMSB, elf.EM_PPC64, true},
		{"elf64-ppc64le", "elf64-littlepowerpc64", elf.Class64, elf.DataLSB, elf.EM_PPC64, true},
		{"elf64-s390", "elf64-s390", elf.Class64, elf.DataMSB, elf.EM_S390, true},
		{"elf64-loongarch", "elf64-loongarch", elf.Class64, elf.DataLSB, elf.EM_LOONGARCH, true},
		{"elf64-bpf", "elf64-bpf", elf.Class64, elf.DataLSB, elf.EM_BPF, true},
		{"elf64-little", "elf64-little", elf.Class64, elf.DataLSB, elf.EM_NONE, true},
		{"elf32-BIG", "elf32-big", elf.Class32, elf.DataMSB, elf.EM_NONE, true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q) returned error: %v", tt.in, err)
			}
			if got.Name != tt.name {
				t.Errorf("Name = %q, want %q", got.Name, tt.name)
			}
			if got.Class != tt.class {
				t.Errorf("Class = %v, want %v", got.Class, tt.class)
			}
			if got.Data != tt.data {
				t.Errorf("Data = %v, want %v", got.Data, tt.data)
			}
			if got.Machine != tt.machine {
				t.Errorf("Machine = %d, want %d", got.Machine, tt.machine)
			}
			if got.IsELF != tt.isELF {
				t.Errorf("IsELF = %v, want %v", got.IsELF, tt.isELF)
			}
		})
	}
}

func TestParseNonELF(t *testing.T) {
	tests := []struct {
		in  string
		chk func(*Target) bool
	}{
		{"binary", func(t *Target) bool { return t.IsBinary }},
		{"IHEX", func(t *Target) bool { return t.IsIHex }},
		{"srec", func(t *Target) bool { return t.IsSREC }},
		{"symbolsrec", func(t *Target) bool { return t.IsSymbolsRec }},
		{"verilog", func(t *Target) bool { return t.IsVerilog }},
		{"tekhex", func(t *Target) bool { return t.IsTekHex }},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q) returned error: %v", tt.in, err)
			}
			if got.IsELF {
				t.Errorf("Parse(%q).IsELF = true, want false", tt.in)
			}
			if !tt.chk(got) {
				t.Errorf("Parse(%q) has wrong format flag: %+v", tt.in, got)
			}
			if got.Machine != elf.EM_NONE {
				t.Errorf("Parse(%q).Machine = %d, want EM_NONE", tt.in, got.Machine)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"elf64-bogus", "bogus", "", "elf32-", "elf64-x86-64-extra"} {
		t.Run(in, func(t *testing.T) {
			_, err := Parse(in)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, want error", in)
			}
			if !strings.Contains(err.Error(), in) {
				t.Errorf("error %q does not mention original name %q", err, in)
			}
		})
	}
}

func TestParseArch(t *testing.T) {
	tests := []struct {
		in      string
		class   elf.Class
		machine uint16
	}{
		{"i386", elf.Class32, elf.EM_386},
		{"I386", elf.Class32, elf.EM_386},
		{"i386:x86-64", elf.Class64, elf.EM_X86_64},
		{"x86-64", elf.Class64, elf.EM_X86_64},
		{"aarch64", elf.Class64, elf.EM_AARCH64},
		{"arm", elf.Class32, elf.EM_ARM},
		{"riscv", elf.Class64, elf.EM_RISCV},
		{"riscv:rv32", elf.Class32, elf.EM_RISCV},
		{"riscv:rv64", elf.Class64, elf.EM_RISCV},
		{"powerpc:common", elf.Class32, elf.EM_PPC},
		{"powerpc:common64", elf.Class64, elf.EM_PPC64},
		{"mips", elf.Class32, elf.EM_MIPS},
		{"mips:64", elf.Class64, elf.EM_MIPS},
		{"s390x", elf.Class64, elf.EM_S390},
		{"loongarch", elf.Class64, elf.EM_LOONGARCH},
		{"sh", elf.Class32, elf.EM_SH},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			class, machine, ok := ParseArch(tt.in)
			if !ok {
				t.Fatalf("ParseArch(%q) = false, want true", tt.in)
			}
			if class != tt.class || machine != tt.machine {
				t.Errorf("ParseArch(%q) = (%v, %d), want (%v, %d)",
					tt.in, class, machine, tt.class, tt.machine)
			}
		})
	}
}

func TestParseArchUnknown(t *testing.T) {
	for _, in := range []string{"", "bogus", "not-an-arch", "x86-64-bogus"} {
		if class, machine, ok := ParseArch(in); ok {
			t.Errorf("ParseArch(%q) = (%v, %d, true), want false", in, class, machine)
		}
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		class   elf.Class
		data    elf.Data
		machine uint16
		want    string
	}{
		{elf.Class64, elf.DataLSB, elf.EM_X86_64, "elf64-x86-64"},
		{elf.Class32, elf.DataLSB, elf.EM_386, "elf32-i386"},
		{elf.Class64, elf.DataLSB, elf.EM_AARCH64, "elf64-aarch64"},
		{elf.Class32, elf.DataLSB, elf.EM_ARM, "elf32-arm"},
		{elf.Class64, elf.DataLSB, elf.EM_RISCV, "elf64-riscv"},
		{elf.Class64, elf.DataMSB, elf.EM_PPC64, "elf64-powerpc64"},
		{elf.Class64, elf.DataLSB, elf.EM_PPC64, "elf64-littlepowerpc64"},
		{elf.Class64, elf.DataLSB, elf.EM_NONE, "elf64-little"},
		{elf.Class32, elf.DataMSB, elf.EM_NONE, "elf32-big"},
		{elf.Class64, elf.DataLSB, 0x1234, "elf64-little"},
	}
	for _, tt := range tests {
		if got := String(tt.class, tt.data, tt.machine); got != tt.want {
			t.Errorf("String(%v, %v, %d) = %q, want %q",
				tt.class, tt.data, tt.machine, got, tt.want)
		}
	}
}

func TestStringRoundTrip(t *testing.T) {
	for _, machine := range []uint16{
		elf.EM_386, elf.EM_X86_64, elf.EM_ARM, elf.EM_AARCH64, elf.EM_RISCV,
		elf.EM_MIPS, elf.EM_PPC, elf.EM_PPC64, elf.EM_S390, elf.EM_LOONGARCH,
		elf.EM_BPF, elf.EM_SH, elf.EM_AVR, elf.EM_MSP430,
	} {
		for _, class := range []elf.Class{elf.Class32, elf.Class64} {
			for _, data := range []elf.Data{elf.DataLSB, elf.DataMSB} {
				name := String(class, data, machine)
				got, err := Parse(name)
				if err != nil {
					t.Errorf("Parse(String(%v, %v, %d)) = %q: %v",
						class, data, machine, name, err)
					continue
				}
				if got.Machine != machine {
					t.Errorf("round trip of %q: Machine = %d, want %d", name, got.Machine, machine)
				}
				if got.Class != class {
					t.Errorf("round trip of %q: Class = %v, want %v", name, got.Class, class)
				}
				if got.Data != data {
					t.Errorf("round trip of %q: Data = %v, want %v", name, got.Data, data)
				}
			}
		}
	}
}

func TestDefault(t *testing.T) {
	got := Default()
	if got == nil {
		t.Fatal("Default() = nil")
	}
	if !got.IsELF {
		t.Errorf("Default().IsELF = false, want true")
	}
	if got.Class != elf.Class32 && got.Class != elf.Class64 {
		t.Errorf("Default().Class = %v, want 32 or 64", got.Class)
	}
	if got.Data != elf.DataLSB && got.Data != elf.DataMSB {
		t.Errorf("Default().Data = %v, want LSB or MSB", got.Data)
	}
	if got.Name == "" {
		t.Error("Default().Name is empty")
	}
	if _, err := Parse(got.Name); err != nil {
		t.Errorf("Default().Name %q does not parse: %v", got.Name, err)
	}

	if runtime.GOARCH == "amd64" {
		if got.Name != "elf64-x86-64" {
			t.Errorf("Default().Name = %q, want elf64-x86-64", got.Name)
		}
		if got.Class != elf.Class64 || got.Data != elf.DataLSB || got.Machine != elf.EM_X86_64 {
			t.Errorf("Default() = %+v, want class64/little/x86-64", got)
		}
	}
	if runtime.GOARCH == "arm64" {
		if got.Name != "elf64-little" || got.Machine != elf.EM_AARCH64 {
			t.Errorf("Default() = %+v, want elf64-little/aarch64", got)
		}
	}
}

func TestAll(t *testing.T) {
	all := All()
	if len(all) < 25 {
		t.Fatalf("All() returned %d targets, want at least 25", len(all))
	}
	seen := make(map[string]bool)
	required := map[string]bool{
		"elf64-x86-64": false,
		"elf32-i386":   false,
		"elf64-little": false,
		"elf32-big":    false,
		"binary":       false,
		"ihex":         false,
		"srec":         false,
		"verilog":      false,
	}
	for _, target := range all {
		if target.Name == "" {
			t.Errorf("All() contains a target with an empty name")
			continue
		}
		if seen[target.Name] {
			t.Errorf("All() contains duplicate target %q", target.Name)
		}
		seen[target.Name] = true
		if _, ok := required[target.Name]; ok {
			required[target.Name] = true
		}
		parsed, err := Parse(target.Name)
		if err != nil {
			t.Errorf("All() target %q does not parse: %v", target.Name, err)
			continue
		}
		if parsed.Name != target.Name {
			t.Errorf("All() target %q parses as %q", target.Name, parsed.Name)
		}
	}
	for name, found := range required {
		if !found {
			t.Errorf("All() is missing target %q", name)
		}
	}

	// Mutating the returned slice must not affect later calls.
	all[0].Name = "mutated"
	if All()[0].Name == "mutated" {
		t.Error("All() returns shared mutable targets")
	}
}

func TestInfo(t *testing.T) {
	info := Info()
	lines := strings.Split(info, "\n")
	if len(lines) == 0 || lines[0] != "BFD header file version (gobjcopy)" {
		t.Fatalf("Info() first line = %q, want version banner", lines[0])
	}
	for _, want := range []string{
		"elf64-x86-64\n",
		"elf32-i386\n",
		"elf64-little\n",
		"binary\n",
		"ihex\n",
		" (header little endian, data little endian)\n",
		" (header big endian, data big endian)\n",
		" (header endianness unknown, data endianness unknown)\n",
		"  i386\n",
		"  aarch64\n",
	} {
		if !strings.Contains(info, want) {
			t.Errorf("Info() does not contain %q", want)
		}
	}
}

func TestTargetString(t *testing.T) {
	target, err := Parse("elf64-x86-64")
	if err != nil {
		t.Fatal(err)
	}
	if target.String() != target.Name {
		t.Errorf("Target.String() = %q, want %q", target.String(), target.Name)
	}
}
