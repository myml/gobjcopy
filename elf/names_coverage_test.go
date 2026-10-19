package elf

import (
	"fmt"
	"strings"
	"testing"
)

// TestMachineTablesExhaustive walks both machine tables in both directions.
// The maps are the single source of truth, so every entry added to names.go is
// checked automatically by MachineName and MachineFromName.
func TestMachineTablesExhaustive(t *testing.T) {
	for machine, name := range machineNames {
		if got := MachineName(machine); got != name {
			t.Errorf("MachineName(%d) = %q, want %q", machine, got, name)
		}
		if got, ok := MachineFromName(name); !ok || got != machine {
			t.Errorf("MachineFromName(%q) = (%d, %v), want (%d, true)", name, got, ok, machine)
		}
		if got, ok := MachineFromName("  " + strings.ToUpper(name) + " "); !ok || got != machine {
			t.Errorf("MachineFromName(upper %q) = (%d, %v), want (%d, true)", name, got, ok, machine)
		}
	}

	for alias, machine := range machineAliases {
		if got, ok := MachineFromName(alias); !ok || got != machine {
			t.Errorf("MachineFromName(%q) = (%d, %v), want (%d, true)", alias, got, ok, machine)
		}
		if got, ok := MachineFromName(" " + strings.ToUpper(alias) + "\t"); !ok || got != machine {
			t.Errorf("MachineFromName(upper %q) = (%d, %v), want (%d, true)", alias, got, ok, machine)
		}
	}

	for _, machine := range []uint16{0x0100, 0x1234, 0xabcd, 0xffff} {
		if _, ok := machineNames[machine]; ok {
			continue
		}
		want := fmt.Sprintf("0x%x", machine)
		if got := MachineName(machine); got != want {
			t.Errorf("MachineName(unknown %#x) = %q, want %q", machine, got, want)
		}
	}

	for _, name := range []string{"", " ", "\t\n", "bogus", "not-an-elf-machine", "0x3e"} {
		if machine, ok := MachineFromName(name); ok {
			t.Errorf("MachineFromName(%q) = (%d, true), want false", name, machine)
		}
	}
}

func TestTypeNameCoverage(t *testing.T) {
	tests := []struct {
		in   uint16
		want string
	}{
		{ET_NONE, "NONE"},
		{ET_REL, "REL"},
		{ET_EXEC, "EXEC"},
		{ET_DYN, "DYN"},
		{ET_CORE, "CORE"},
		{ET_LOOS, "0xfe00"},
		{0x1234, "0x1234"},
		{0xffff, "0xffff"},
	}
	for _, tt := range tests {
		if got := TypeName(tt.in); got != tt.want {
			t.Errorf("TypeName(%#x) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSectionTypeNameCoverage(t *testing.T) {
	tests := []struct {
		in   uint32
		want string
	}{
		{SHT_NULL, "NULL"},
		{SHT_PROGBITS, "PROGBITS"},
		{SHT_SYMTAB, "SYMTAB"},
		{SHT_STRTAB, "STRTAB"},
		{SHT_RELA, "RELA"},
		{SHT_HASH, "HASH"},
		{SHT_DYNAMIC, "DYNAMIC"},
		{SHT_NOTE, "NOTE"},
		{SHT_NOBITS, "NOBITS"},
		{SHT_REL, "REL"},
		{SHT_SHLIB, "SHLIB"},
		{SHT_DYNSYM, "DYNSYM"},
		{SHT_INIT_ARRAY, "INIT_ARRAY"},
		{SHT_FINI_ARRAY, "FINI_ARRAY"},
		{SHT_PREINIT_ARRAY, "PREINIT_ARRAY"},
		{SHT_GROUP, "GROUP"},
		{SHT_SYMTAB_SHNDX, "SYMTAB SECTION INDICES"},
		{SHT_RELR, "RELR"},
		{SHT_GNU_ATTRIBUTES, "GNU_ATTRIBUTES"},
		{SHT_GNU_HASH, "GNU_HASH"},
		{SHT_GNU_LIBLIST, "GNU_LIBLIST"},
		{SHT_CHECKSUM, "CHECKSUM"},
		{SHT_GNU_verdef, "VERDEF"},
		{SHT_GNU_verneed, "VERNEED"},
		{SHT_GNU_versym, "VERSYM"},
		{0x1234, "0x1234"},
		{0xffffffff, "0xffffffff"},
	}
	for _, tt := range tests {
		if got := SectionTypeName(tt.in); got != tt.want {
			t.Errorf("SectionTypeName(%#x) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSectionFlagNameCoverage(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{0, ""},
		{SHF_WRITE, "W"},
		{SHF_ALLOC, "A"},
		{SHF_EXECINSTR, "X"},
		{SHF_MERGE, "M"},
		{SHF_STRINGS, "S"},
		{SHF_INFO_LINK, "I"},
		{SHF_LINK_ORDER, "L"},
		{SHF_OS_NONCONFORMING, "O"},
		{SHF_GROUP, "G"},
		{SHF_TLS, "T"},
		{SHF_COMPRESSED, "C"},
		{SHF_GNU_RETAIN, "R"},
		{SHF_EXCLUDE, "E"},
		{SHF_WRITE | SHF_ALLOC, "WA"},
		{SHF_ALLOC | SHF_EXECINSTR, "AX"},
		{SHF_MERGE | SHF_STRINGS, "MS"},
		{SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR | SHF_MERGE | SHF_STRINGS | SHF_INFO_LINK | SHF_LINK_ORDER | SHF_OS_NONCONFORMING | SHF_GROUP | SHF_TLS | SHF_COMPRESSED | SHF_GNU_RETAIN | SHF_EXCLUDE, "WAXMSILOGTCR" + "E"},
		{0x1000, "0x1000"},
		{SHF_WRITE | 0x1000, "W|0x1000"},
		{SHF_GNU_MBIND, "0x1000000"},
		{SHF_X86_64_LARGE, "0x10000000"},
		{SHF_MASKPROC, "E|0x70000000"},
	}
	for _, tt := range tests {
		if got := SectionFlagName(tt.in); got != tt.want {
			t.Errorf("SectionFlagName(%#x) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSymbolBindNameCoverage(t *testing.T) {
	tests := []struct {
		in   byte
		want string
	}{
		{STB_LOCAL, "LOCAL"},
		{STB_GLOBAL, "GLOBAL"},
		{STB_WEAK, "WEAK"},
		{STB_GNU_UNIQUE, "UNIQUE"},
		{0x0f, "0xf"},
		{0xff, "0xff"},
	}
	for _, tt := range tests {
		if got := SymbolBindName(tt.in); got != tt.want {
			t.Errorf("SymbolBindName(%#x) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSymbolTypeNameCoverage(t *testing.T) {
	tests := []struct {
		in   byte
		want string
	}{
		{STT_NOTYPE, "NOTYPE"},
		{STT_OBJECT, "OBJECT"},
		{STT_FUNC, "FUNC"},
		{STT_SECTION, "SECTION"},
		{STT_FILE, "FILE"},
		{STT_COMMON, "COMMON"},
		{STT_TLS, "TLS"},
		{STT_GNU_IFUNC, "IFUNC"},
		{0x0f, "0xf"},
		{0xff, "0xff"},
	}
	for _, tt := range tests {
		if got := SymbolTypeName(tt.in); got != tt.want {
			t.Errorf("SymbolTypeName(%#x) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSymbolVisNameCoverage(t *testing.T) {
	tests := []struct {
		in   byte
		want string
	}{
		{STV_DEFAULT, "DEFAULT"},
		{STV_INTERNAL, "INTERNAL"},
		{STV_HIDDEN, "HIDDEN"},
		{STV_PROTECTED, "PROTECTED"},
		{0x04, "0x4"},
		{0xff, "0xff"},
	}
	for _, tt := range tests {
		if got := SymbolVisName(tt.in); got != tt.want {
			t.Errorf("SymbolVisName(%#x) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestProgramTypeNameCoverage(t *testing.T) {
	tests := []struct {
		in   uint32
		want string
	}{
		{PT_NULL, "NULL"},
		{PT_LOAD, "LOAD"},
		{PT_DYNAMIC, "DYNAMIC"},
		{PT_INTERP, "INTERP"},
		{PT_NOTE, "NOTE"},
		{PT_SHLIB, "SHLIB"},
		{PT_PHDR, "PHDR"},
		{PT_TLS, "TLS"},
		{PT_GNU_EH_FRAME, "GNU_EH_FRAME"},
		{PT_GNU_STACK, "GNU_STACK"},
		{PT_GNU_RELRO, "GNU_RELRO"},
		{PT_GNU_PROPERTY, "GNU_PROPERTY"},
		{PT_LOOS, "0x60000000"},
		{0x1234, "0x1234"},
		{0xffffffff, "0xffffffff"},
	}
	for _, tt := range tests {
		if got := ProgramTypeName(tt.in); got != tt.want {
			t.Errorf("ProgramTypeName(%#x) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestOSABINameCoverage(t *testing.T) {
	tests := []struct {
		in   byte
		want string
	}{
		{ELFOSABI_NONE, "System V"},
		{ELFOSABI_HPUX, "HP-UX"},
		{ELFOSABI_NETBSD, "NetBSD"},
		{ELFOSABI_GNU, "GNU"},
		{ELFOSABI_SOLARIS, "Solaris"},
		{ELFOSABI_AIX, "AIX"},
		{ELFOSABI_IRIX, "IRIX"},
		{ELFOSABI_FREEBSD, "FreeBSD"},
		{ELFOSABI_TRU64, "TRU64"},
		{ELFOSABI_MODESTO, "Modesto"},
		{ELFOSABI_OPENBSD, "OpenBSD"},
		{ELFOSABI_OPENVMS, "OpenVMS"},
		{ELFOSABI_NSK, "NonStop Kernel"},
		{ELFOSABI_AROS, "AROS"},
		{ELFOSABI_FENIXOS, "FenixOS"},
		{ELFOSABI_CLOUDABI, "CloudABI"},
		{ELFOSABI_OPENVOS, "OpenVOS"},
		{ELFOSABI_ARM_AEABI, "ARM EABI"},
		{ELFOSABI_ARM, "ARM"},
		{ELFOSABI_STANDALONE, "Standalone"},
		{0x04, "0x4"},
		{0xab, "0xab"},
	}
	for _, tt := range tests {
		if got := OSABIName(tt.in); got != tt.want {
			t.Errorf("OSABIName(%#x) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestClassDataString covers the String methods in types.go, including
// out-of-range values that fall back to the default spelling.
func TestClassDataString(t *testing.T) {
	classTests := []struct {
		in   Class
		want string
	}{
		{Class32, "ELF32"},
		{Class64, "ELF64"},
		{0, "ELF32"},
		{3, "ELF32"},
	}
	for _, tt := range classTests {
		if got := tt.in.String(); got != tt.want {
			t.Errorf("Class(%d).String() = %q, want %q", tt.in, got, tt.want)
		}
	}

	dataTests := []struct {
		in   Data
		want string
	}{
		{DataLSB, "little endian"},
		{DataMSB, "big endian"},
		{0, "little endian"},
		{3, "little endian"},
	}
	for _, tt := range dataTests {
		if got := tt.in.String(); got != tt.want {
			t.Errorf("Data(%d).String() = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSectionPredicatesCoverage(t *testing.T) {
	for _, tt := range []struct {
		name      string
		flags     uint64
		typ       uint32
		wantAlloc bool
		wantNoBit bool
	}{
		{"alloc", SHF_ALLOC, SHT_PROGBITS, true, false},
		{"plain", 0, SHT_PROGBITS, false, false},
		{"nobits", 0, SHT_NOBITS, false, true},
		{"alloc-nobits", SHF_ALLOC, SHT_NOBITS, true, true},
	} {
		s := &Section{SectionHeader: SectionHeader{Flags: tt.flags, Type: tt.typ}}
		if got := s.IsAlloc(); got != tt.wantAlloc {
			t.Errorf("%s: IsAlloc() = %v, want %v", tt.name, got, tt.wantAlloc)
		}
		if got := s.IsNoBits(); got != tt.wantNoBit {
			t.Errorf("%s: IsNoBits() = %v, want %v", tt.name, got, tt.wantNoBit)
		}
	}
}
