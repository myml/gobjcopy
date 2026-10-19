// Package bfdtarget parses and generates binutils BFD target names, as used by
// objcopy's -I/-O/-F options and by --info.
//
// The recognized names are the common ELF targets (for example
// "elf64-x86-64", "elf32-i386", "elf64-little") plus the non-ELF formats that
// objcopy supports ("binary", "ihex", "srec", "verilog", ...). Parsing is
// case-insensitive, matching binutils' behaviour of lower-casing target names.
package bfdtarget

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/myml/gobjcopy/elf"
)

// Target describes one BFD target: its canonical name, the ELF class and byte
// order it produces, and the architecture it defaults to.
type Target struct {
	// Name is the canonical, lower-case BFD target name, e.g. "elf64-x86-64".
	Name string
	// Class and Data are the ELF class and byte order. They are zero for
	// non-ELF formats, which have neither.
	Class elf.Class
	Data  elf.Data
	// Machine is the default ELF machine type, or elf.EM_NONE for targets
	// that do not imply an architecture (e.g. "elf64-little", "binary").
	Machine uint16

	// IsELF reports whether the target produces an ELF object.
	IsELF bool
	// IsBinary reports whether the target is raw binary.
	IsBinary bool
	// The remaining flags identify the other non-ELF formats.
	IsIHex       bool
	IsSREC       bool
	IsSymbolsRec bool
	IsVerilog    bool
	IsTekHex     bool

	// Arch is the BFD architecture name shown by --info, e.g. "i386" or
	// "aarch64". It is empty when the target is architecture-independent.
	Arch string
}

// String returns the canonical BFD target name.
func (t *Target) String() string { return t.Name }

// archSpec is the internal description of a BFD architecture name.
type archSpec struct {
	machine uint16
	class   elf.Class
	data    elf.Data
	arch    string // label used by --info
}

func spec(machine uint16, class elf.Class, data elf.Data, arch string) archSpec {
	return archSpec{machine: machine, class: class, data: data, arch: arch}
}

// archTable maps BFD architecture spellings accepted by -B to their default
// class, byte order and machine type.
var archTable = map[string]archSpec{
	// x86
	"i386":        spec(elf.EM_386, elf.Class32, elf.DataLSB, "i386"),
	"i486":        spec(elf.EM_386, elf.Class32, elf.DataLSB, "i386"),
	"i586":        spec(elf.EM_386, elf.Class32, elf.DataLSB, "i386"),
	"i686":        spec(elf.EM_386, elf.Class32, elf.DataLSB, "i386"),
	"iamcu":       spec(elf.EM_IAMCU, elf.Class32, elf.DataLSB, "iamcu"),
	"x86-64":      spec(elf.EM_X86_64, elf.Class64, elf.DataLSB, "i386"),
	"x86_64":      spec(elf.EM_X86_64, elf.Class64, elf.DataLSB, "i386"),
	"i386:x86-64": spec(elf.EM_X86_64, elf.Class64, elf.DataLSB, "i386"),
	"i386:x86_64": spec(elf.EM_X86_64, elf.Class64, elf.DataLSB, "i386"),
	"amd64":       spec(elf.EM_X86_64, elf.Class64, elf.DataLSB, "i386"),
	"x64":         spec(elf.EM_X86_64, elf.Class64, elf.DataLSB, "i386"),

	// ARM
	"arm":           spec(elf.EM_ARM, elf.Class32, elf.DataLSB, "arm"),
	"armeb":         spec(elf.EM_ARM, elf.Class32, elf.DataMSB, "arm"),
	"aarch64":       spec(elf.EM_AARCH64, elf.Class64, elf.DataLSB, "aarch64"),
	"aarch64_be":    spec(elf.EM_AARCH64, elf.Class64, elf.DataMSB, "aarch64"),
	"aarch64:ilp32": spec(elf.EM_AARCH64, elf.Class32, elf.DataLSB, "aarch64"),
	"arm64":         spec(elf.EM_AARCH64, elf.Class64, elf.DataLSB, "aarch64"),

	// RISC-V
	"riscv":       spec(elf.EM_RISCV, elf.Class64, elf.DataLSB, "riscv"),
	"riscv32":     spec(elf.EM_RISCV, elf.Class32, elf.DataLSB, "riscv"),
	"riscv64":     spec(elf.EM_RISCV, elf.Class64, elf.DataLSB, "riscv"),
	"riscv:rv32":  spec(elf.EM_RISCV, elf.Class32, elf.DataLSB, "riscv"),
	"riscv:rv64":  spec(elf.EM_RISCV, elf.Class64, elf.DataLSB, "riscv"),
	"riscv:rv128": spec(elf.EM_RISCV, elf.Class64, elf.DataLSB, "riscv"),

	// MIPS
	"mips":             spec(elf.EM_MIPS, elf.Class32, elf.DataMSB, "mips"),
	"mips:32":          spec(elf.EM_MIPS, elf.Class32, elf.DataMSB, "mips"),
	"mips:64":          spec(elf.EM_MIPS, elf.Class64, elf.DataMSB, "mips"),
	"mips32":           spec(elf.EM_MIPS, elf.Class32, elf.DataMSB, "mips"),
	"mips64":           spec(elf.EM_MIPS, elf.Class64, elf.DataMSB, "mips"),
	"mipsel":           spec(elf.EM_MIPS, elf.Class32, elf.DataLSB, "mips"),
	"mips64el":         spec(elf.EM_MIPS, elf.Class64, elf.DataLSB, "mips"),
	"tradbigmips":      spec(elf.EM_MIPS, elf.Class32, elf.DataMSB, "mips"),
	"tradlittlemips":   spec(elf.EM_MIPS, elf.Class32, elf.DataLSB, "mips"),
	"tradbigmips64":    spec(elf.EM_MIPS, elf.Class64, elf.DataMSB, "mips"),
	"tradlittlemips64": spec(elf.EM_MIPS, elf.Class64, elf.DataLSB, "mips"),

	// PowerPC
	"powerpc":          spec(elf.EM_PPC, elf.Class32, elf.DataMSB, "powerpc:common"),
	"powerpc:common":   spec(elf.EM_PPC, elf.Class32, elf.DataMSB, "powerpc:common"),
	"powerpc:common64": spec(elf.EM_PPC64, elf.Class64, elf.DataMSB, "powerpc:common64"),
	"powerpcle":        spec(elf.EM_PPC, elf.Class32, elf.DataLSB, "powerpc:common"),
	"powerpc64":        spec(elf.EM_PPC64, elf.Class64, elf.DataMSB, "powerpc:common64"),
	"powerpc64le":      spec(elf.EM_PPC64, elf.Class64, elf.DataLSB, "powerpc:common64"),
	"ppc":              spec(elf.EM_PPC, elf.Class32, elf.DataMSB, "powerpc:common"),
	"ppc64":            spec(elf.EM_PPC64, elf.Class64, elf.DataMSB, "powerpc:common64"),
	"ppc64le":          spec(elf.EM_PPC64, elf.Class64, elf.DataLSB, "powerpc:common64"),

	// SystemZ
	"s390":    spec(elf.EM_S390, elf.Class32, elf.DataMSB, "s390"),
	"s390:32": spec(elf.EM_S390, elf.Class32, elf.DataMSB, "s390"),
	"s390:64": spec(elf.EM_S390, elf.Class64, elf.DataMSB, "s390"),
	"s390x":   spec(elf.EM_S390, elf.Class64, elf.DataMSB, "s390"),

	// SPARC
	"sparc":    spec(elf.EM_SPARC, elf.Class32, elf.DataMSB, "sparc"),
	"sparc32":  spec(elf.EM_SPARC, elf.Class32, elf.DataMSB, "sparc"),
	"sparcv8":  spec(elf.EM_SPARC, elf.Class32, elf.DataMSB, "sparc"),
	"sparc:32": spec(elf.EM_SPARC, elf.Class32, elf.DataMSB, "sparc"),
	"sparc64":  spec(elf.EM_SPARCV9, elf.Class64, elf.DataMSB, "sparc64"),
	"sparcv9":  spec(elf.EM_SPARCV9, elf.Class64, elf.DataMSB, "sparc64"),
	"sparc:64": spec(elf.EM_SPARCV9, elf.Class64, elf.DataMSB, "sparc64"),

	// HP PA-RISC
	"hppa":   spec(elf.EM_PARISC, elf.Class32, elf.DataMSB, "hppa"),
	"parisc": spec(elf.EM_PARISC, elf.Class32, elf.DataMSB, "hppa"),
	"hppa64": spec(elf.EM_PARISC, elf.Class64, elf.DataMSB, "hppa"),

	// Itanium
	"ia64": spec(elf.EM_IA_64, elf.Class64, elf.DataLSB, "ia64"),

	// LoongArch
	"loongarch":   spec(elf.EM_LOONGARCH, elf.Class64, elf.DataLSB, "loongarch"),
	"loongarch64": spec(elf.EM_LOONGARCH, elf.Class64, elf.DataLSB, "loongarch"),
	"loongarch32": spec(elf.EM_LOONGARCH, elf.Class32, elf.DataLSB, "loongarch"),

	// BPF
	"bpf":   spec(elf.EM_BPF, elf.Class64, elf.DataLSB, "bpf"),
	"bpfel": spec(elf.EM_BPF, elf.Class64, elf.DataLSB, "bpf"),
	"bpfeb": spec(elf.EM_BPF, elf.Class64, elf.DataMSB, "bpf"),

	// Everything below is useful mainly for -B and for round-tripping names.
	"csky":         spec(elf.EM_CSKY, elf.Class32, elf.DataLSB, "csky"),
	"sh":           spec(elf.EM_SH, elf.Class32, elf.DataLSB, "sh"),
	"sh64":         spec(elf.EM_SH, elf.Class64, elf.DataLSB, "sh"),
	"sheb":         spec(elf.EM_SH, elf.Class32, elf.DataMSB, "sh"),
	"avr":          spec(elf.EM_AVR, elf.Class32, elf.DataLSB, "avr"),
	"avr32":        spec(elf.EM_AVR32, elf.Class32, elf.DataMSB, "avr32"),
	"msp430":       spec(elf.EM_MSP430, elf.Class32, elf.DataLSB, "msp430"),
	"m32r":         spec(elf.EM_M32R, elf.Class32, elf.DataMSB, "m32r"),
	"m32c":         spec(elf.EM_M32C, elf.Class32, elf.DataLSB, "m32c"),
	"mn10300":      spec(elf.EM_MN10300, elf.Class32, elf.DataLSB, "mn10300"),
	"mn10200":      spec(elf.EM_MN10200, elf.Class32, elf.DataLSB, "mn10200"),
	"or1k":         spec(elf.EM_OPENRISC, elf.Class32, elf.DataMSB, "or1k"),
	"openrisc":     spec(elf.EM_OPENRISC, elf.Class32, elf.DataMSB, "or1k"),
	"xtensa":       spec(elf.EM_XTENSA, elf.Class32, elf.DataLSB, "xtensa"),
	"microblaze":   spec(elf.EM_MICROBLAZE, elf.Class32, elf.DataMSB, "microblaze"),
	"microblazeel": spec(elf.EM_MICROBLAZE, elf.Class32, elf.DataLSB, "microblaze"),
	"nios2":        spec(elf.EM_ALTERA_NIOS2, elf.Class32, elf.DataLSB, "nios2"),
	"rx":           spec(elf.EM_RX, elf.Class32, elf.DataLSB, "rx"),
	"metag":        spec(elf.EM_METAG, elf.Class32, elf.DataLSB, "metag"),
	"m68k":         spec(elf.EM_68K, elf.Class32, elf.DataMSB, "m68k"),
	"m88k":         spec(elf.EM_88K, elf.Class32, elf.DataMSB, "m88k"),
	"i860":         spec(elf.EM_860, elf.Class32, elf.DataLSB, "i860"),
	"i960":         spec(elf.EM_960, elf.Class32, elf.DataLSB, "i960"),
	"vax":          spec(elf.EM_VAX, elf.Class32, elf.DataLSB, "vax"),
	"cris":         spec(elf.EM_CRIS, elf.Class32, elf.DataLSB, "cris"),
	"frv":          spec(elf.EM_FRV, elf.Class32, elf.DataMSB, "frv"),
	"v850":         spec(elf.EM_V850, elf.Class32, elf.DataLSB, "v850"),
	"d10v":         spec(elf.EM_D10V, elf.Class32, elf.DataLSB, "d10v"),
	"d30v":         spec(elf.EM_D30V, elf.Class32, elf.DataLSB, "d30v"),
	"ip2k":         spec(elf.EM_IP2K, elf.Class32, elf.DataLSB, "ip2k"),
	"z80":          spec(elf.EM_Z80, elf.Class32, elf.DataLSB, "z80"),
	"moxie":        spec(elf.EM_MOXIE, elf.Class32, elf.DataMSB, "moxie"),
	"amdgpu":       spec(elf.EM_AMDGPU, elf.Class64, elf.DataLSB, "amdgpu"),
	"cuda":         spec(elf.EM_CUDA, elf.Class64, elf.DataLSB, "cuda"),
	"nvptx":        spec(elf.EM_CUDA, elf.Class64, elf.DataLSB, "cuda"),
	"nds32":        spec(elf.EM_NDS32, elf.Class32, elf.DataLSB, "nds32"),
	"arc":          spec(elf.EM_ARC_COMPACT, elf.Class32, elf.DataLSB, "arc"),
	"arcompact":    spec(elf.EM_ARC_COMPACT, elf.Class32, elf.DataLSB, "arc"),
	"arcv2":        spec(elf.EM_ARCV2, elf.Class32, elf.DataLSB, "arc"),
	"tile64":       spec(elf.EM_TILE64, elf.Class64, elf.DataLSB, "tile64"),
	"tilepro":      spec(elf.EM_TILEPRO, elf.Class32, elf.DataLSB, "tilepro"),
	"tilegx":       spec(elf.EM_TILEGX, elf.Class64, elf.DataLSB, "tilegx"),
	"tic6x":        spec(elf.EM_TI_C6000, elf.Class32, elf.DataLSB, "tic6x"),
	"c6x":          spec(elf.EM_TI_C6000, elf.Class32, elf.DataLSB, "tic6x"),
	"pru":          spec(elf.EM_TI_PRU, elf.Class32, elf.DataLSB, "pru"),
	"visium":       spec(elf.EM_VISIUM, elf.Class32, elf.DataLSB, "visium"),
	"ft32":         spec(elf.EM_FT32, elf.Class32, elf.DataLSB, "ft32"),
	"rl78":         spec(elf.EM_RL78, elf.Class32, elf.DataLSB, "rl78"),
	"cr16":         spec(elf.EM_CR16, elf.Class32, elf.DataLSB, "cr16"),
	"h8300":        spec(elf.EM_H8_300, elf.Class32, elf.DataMSB, "h8300"),
	"h8300h":       spec(elf.EM_H8_300H, elf.Class32, elf.DataMSB, "h8300h"),
	"h8300s":       spec(elf.EM_H8S, elf.Class32, elf.DataMSB, "h8300s"),
	"h8500":        spec(elf.EM_H8_500, elf.Class32, elf.DataMSB, "h8500"),
	"m32":          spec(elf.EM_M32, elf.Class32, elf.DataMSB, "m32"),
	"s370":         spec(elf.EM_S370, elf.Class32, elf.DataMSB, "s370"),
	"spu":          spec(elf.EM_SPU, elf.Class32, elf.DataMSB, "spu"),
	"tricore":      spec(elf.EM_TRICORE, elf.Class32, elf.DataLSB, "tricore"),
	"alpha":        spec(elf.EM_ALPHA, elf.Class64, elf.DataLSB, "alpha"),
}

// nonELFTargets lists the non-ELF formats objcopy understands, in the order
// they appear in --info output.
var nonELFTargets = []*Target{
	{Name: "binary", IsBinary: true},
	{Name: "ihex", IsIHex: true},
	{Name: "srec", IsSREC: true},
	{Name: "symbolsrec", IsSymbolsRec: true},
	{Name: "verilog", IsVerilog: true},
	{Name: "tekhex", IsTekHex: true},
}

// allNames is the canonical list of targets reported by All and --info.
var allNames = []string{
	"elf64-x86-64",
	"elf32-i386",
	"elf32-iamcu",
	"elf32-x86-64",
	"elf64-aarch64",
	"elf32-arm",
	"elf64-riscv",
	"elf32-riscv",
	"elf64-mips",
	"elf32-mips",
	"elf64-powerpc64",
	"elf32-powerpc",
	"elf64-s390",
	"elf32-s390",
	"elf64-sparc64",
	"elf64-ia64",
	"elf64-loongarch",
	"elf64-bpf",
	"elf32-sh",
	"elf32-avr",
	"elf32-msp430",
	"elf32-microblaze",
	"elf64-alpha",
	"elf32-or1k",
	"elf64-little",
	"elf64-big",
	"elf32-little",
	"elf32-big",
	"binary",
	"ihex",
	"srec",
	"symbolsrec",
	"verilog",
	"tekhex",
}

// Parse parses a BFD target name such as "elf64-x86-64", "elf32-i386",
// "elf64-little", "binary", "ihex", "srec" or "verilog". Matching is
// case-insensitive. An unknown name yields an error that quotes the original
// input.
func Parse(name string) (*Target, error) {
	original := name
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return nil, fmt.Errorf("bfd target %q: empty target name", original)
	}

	for _, t := range nonELFTargets {
		if t.Name == key {
			clone := *t
			return &clone, nil
		}
	}

	var class elf.Class
	switch {
	case strings.HasPrefix(key, "elf32-"):
		class = elf.Class32
		key = key[len("elf32-"):]
	case strings.HasPrefix(key, "elf64-"):
		class = elf.Class64
		key = key[len("elf64-"):]
	default:
		return nil, fmt.Errorf("bfd target %q: unknown target", original)
	}
	if key == "" {
		return nil, fmt.Errorf("bfd target %q: unknown target", original)
	}

	data := elf.Data(0)
	archName := key
	switch {
	case key == "little":
		data = elf.DataLSB
		archName = ""
	case key == "big":
		data = elf.DataMSB
		archName = ""
	case strings.HasPrefix(key, "little"):
		data = elf.DataLSB
		archName = key[len("little"):]
	case strings.HasPrefix(key, "big"):
		data = elf.DataMSB
		archName = key[len("big"):]
	}

	if archName == "" {
		return &Target{
			Name:    canonicalName(class, data, elf.EM_NONE),
			Class:   class,
			Data:    data,
			Machine: elf.EM_NONE,
			IsELF:   true,
		}, nil
	}

	spec, ok := lookupArch(archName)
	if !ok {
		return nil, fmt.Errorf("bfd target %q: unknown target", original)
	}
	if data == 0 {
		data = spec.data
	}
	return &Target{
		Name:    canonicalName(class, data, spec.machine),
		Class:   class,
		Data:    data,
		Machine: spec.machine,
		IsELF:   true,
		Arch:    spec.arch,
	}, nil
}

// lookupArch resolves an architecture name (already lower-cased) including
// BFD's "base:qualifier" spelling.
func lookupArch(name string) (archSpec, bool) {
	if s, ok := archTable[name]; ok {
		return s, true
	}
	if i := strings.LastIndexByte(name, ':'); i > 0 {
		if s, ok := archTable[name[:i]]; ok {
			return s, true
		}
	}
	return archSpec{}, false
}

// ParseArch parses a -B/--binary-architecture argument such as "i386",
// "i386:x86-64", "aarch64", "arm", "riscv:rv64" or "powerpc:common64". It
// returns the default ELF class, the machine value, and whether the name was
// recognized.
func ParseArch(name string) (elf.Class, uint16, bool) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return 0, 0, false
	}
	s, ok := lookupArch(key)
	if !ok {
		return 0, 0, false
	}
	class := s.class
	if i := strings.LastIndexByte(key, ':'); i > 0 {
		switch key[i+1:] {
		case "32", "rv32", "ilp32":
			class = elf.Class32
		case "64", "rv64", "rv128", "common64", "x86-64":
			class = elf.Class64
		}
	}
	return class, s.machine, true
}

// String generates the canonical BFD target name for an ELF class, byte order
// and machine, for example "elf64-x86-64". When the machine has no conventional
// BFD name, a generic name such as "elf64-little" or "elf32-big" is returned.
func String(class elf.Class, data elf.Data, machine uint16) string {
	return canonicalName(class, data, machine)
}

func canonicalName(class elf.Class, data elf.Data, machine uint16) string {
	prefix := "elf64"
	if class == elf.Class32 {
		prefix = "elf32"
	}
	endian := "little"
	if data == elf.DataMSB {
		endian = "big"
	}
	if machine == elf.EM_NONE {
		return prefix + "-" + endian
	}
	name := elf.MachineName(machine)
	if strings.HasPrefix(name, "0x") {
		return prefix + "-" + endian
	}
	if data == machineData(machine) {
		return prefix + "-" + name
	}
	// Explicit endianness lets us name architectures whose natural byte
	// order differs from the requested one, e.g. elf64-littlepowerpc64.
	return prefix + "-" + endian + name
}

// machineData returns the natural byte order for an ELF machine. Most targets
// are little-endian; only the historically big-endian families are listed.
func machineData(machine uint16) elf.Data {
	switch machine {
	case elf.EM_M32, elf.EM_SPARC, elf.EM_68K, elf.EM_88K, elf.EM_S370,
		elf.EM_PARISC, elf.EM_SPARC32PLUS, elf.EM_PPC, elf.EM_PPC64,
		elf.EM_S390, elf.EM_SPU, elf.EM_SPARCV9, elf.EM_MIPS,
		elf.EM_M32R, elf.EM_OPENRISC, elf.EM_H8_300, elf.EM_H8_300H,
		elf.EM_H8S, elf.EM_H8_500, elf.EM_M32C, elf.EM_MICROBLAZE,
		elf.EM_AVR32, elf.EM_MOXIE, elf.EM_FRV:
		return elf.DataMSB
	}
	return elf.DataLSB
}

// Default returns the BFD target for the current host architecture.
func Default() *Target {
	switch runtime.GOARCH {
	case "amd64":
		return mustParse("elf64-x86-64")
	case "386":
		return mustParse("elf32-i386")
	case "arm64":
		return generic(elf.Class64, elf.DataLSB, elf.EM_AARCH64, "aarch64")
	case "arm":
		return generic(elf.Class32, elf.DataLSB, elf.EM_ARM, "arm")
	case "riscv64":
		return generic(elf.Class64, elf.DataLSB, elf.EM_RISCV, "riscv")
	case "loong64":
		return generic(elf.Class64, elf.DataLSB, elf.EM_LOONGARCH, "loongarch")
	case "ppc64":
		return generic(elf.Class64, elf.DataMSB, elf.EM_PPC64, "powerpc:common64")
	case "ppc64le":
		return generic(elf.Class64, elf.DataLSB, elf.EM_PPC64, "powerpc:common64")
	case "s390x":
		return generic(elf.Class64, elf.DataMSB, elf.EM_S390, "s390")
	case "mips":
		return generic(elf.Class32, elf.DataMSB, elf.EM_MIPS, "mips")
	case "mipsle":
		return generic(elf.Class32, elf.DataLSB, elf.EM_MIPS, "mips")
	case "mips64":
		return generic(elf.Class64, elf.DataMSB, elf.EM_MIPS, "mips")
	case "mips64le":
		return generic(elf.Class64, elf.DataLSB, elf.EM_MIPS, "mips")
	case "sparc64":
		return generic(elf.Class64, elf.DataMSB, elf.EM_SPARCV9, "sparc64")
	case "wasm":
		return generic(elf.Class32, elf.DataLSB, elf.EM_NONE, "")
	default:
		class := elf.Class32
		if strconv.IntSize == 64 {
			class = elf.Class64
		}
		return generic(class, elf.DataLSB, elf.EM_NONE, "")
	}
}

func generic(class elf.Class, data elf.Data, machine uint16, arch string) *Target {
	return &Target{
		Name:    canonicalName(class, data, machine),
		Class:   class,
		Data:    data,
		Machine: machine,
		IsELF:   true,
		Arch:    arch,
	}
}

func mustParse(name string) *Target {
	t, err := Parse(name)
	if err != nil {
		panic(err)
	}
	return t
}

// All returns the supported targets, in the order used by --info. Callers may
// modify the returned targets; a fresh slice is allocated on every call.
func All() []*Target {
	targets := make([]*Target, 0, len(allNames))
	for _, name := range allNames {
		t, err := Parse(name)
		if err != nil {
			continue // keep All total even if the table is edited badly
		}
		targets = append(targets, t)
	}
	return targets
}

// Info returns text in the style of "objcopy --info": a version banner, then
// one block per target with its name, its endianness, and the architecture it
// supports.
func Info() string {
	var b strings.Builder
	b.WriteString("BFD header file version (gobjcopy)\n")
	for _, t := range All() {
		b.WriteString(t.Name)
		b.WriteByte('\n')
		if t.IsELF {
			fmt.Fprintf(&b, " (header %s, data %s)\n", t.Data, t.Data)
		} else {
			b.WriteString(" (header endianness unknown, data endianness unknown)\n")
		}
		if t.Arch != "" {
			fmt.Fprintf(&b, "  %s\n", t.Arch)
		} else if arch := hostArchName(); arch != "" {
			// Generic ELF targets and non-ELF formats have no architecture
			// of their own; BFD lists the host's architecture instead.
			fmt.Fprintf(&b, "  %s\n", arch)
		}
	}
	return b.String()
}

// hostArchName returns the BFD architecture label corresponding to the host
// GOARCH, used by Info for architecture-independent targets.
func hostArchName() string {
	switch runtime.GOARCH {
	case "amd64", "386":
		return "i386"
	case "arm64":
		return "aarch64"
	case "arm":
		return "arm"
	case "riscv64":
		return "riscv"
	case "loong64":
		return "loongarch"
	case "ppc64", "ppc64le":
		return "powerpc:common64"
	case "s390x":
		return "s390"
	case "mips", "mipsle", "mips64", "mips64le":
		return "mips"
	case "sparc64":
		return "sparc64"
	}
	return ""
}
