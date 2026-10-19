package elf

import (
	"fmt"
	"strings"
)

// ELF machine (architecture) values. These mirror the EM_* constants from the
// ELF gABI and binutils' elf/common.h.
const (
	EM_NONE          = 0
	EM_M32           = 1
	EM_SPARC         = 2
	EM_386           = 3
	EM_68K           = 4
	EM_88K           = 5
	EM_IAMCU         = 6
	EM_860           = 7
	EM_MIPS          = 8
	EM_S370          = 9
	EM_MIPS_RS3_LE   = 10
	EM_PARISC        = 15
	EM_VPP500        = 17
	EM_SPARC32PLUS   = 18
	EM_960           = 19
	EM_PPC           = 20
	EM_PPC64         = 21
	EM_S390          = 22
	EM_SPU           = 23
	EM_V800          = 36
	EM_FR20          = 37
	EM_RH32          = 38
	EM_RCE           = 39
	EM_ARM           = 40
	EM_SH            = 42
	EM_SPARCV9       = 43
	EM_TRICORE       = 44
	EM_ARC           = 45
	EM_H8_300        = 46
	EM_H8_300H       = 47
	EM_H8S           = 48
	EM_H8_500        = 49
	EM_IA_64         = 50
	EM_MIPS_X        = 51
	EM_68HC12        = 53
	EM_MMA           = 54
	EM_PCP           = 55
	EM_NCPU          = 56
	EM_NDR1          = 57
	EM_STARCORE      = 58
	EM_ME16          = 59
	EM_ST100         = 60
	EM_TINYJ         = 61
	EM_X86_64        = 62
	EM_PDSP          = 63
	EM_FX66          = 66
	EM_ST9PLUS       = 67
	EM_ST7           = 68
	EM_68HC16        = 69
	EM_68HC11        = 70
	EM_68HC08        = 71
	EM_68HC05        = 72
	EM_SVX           = 73
	EM_ST19          = 74
	EM_VAX           = 75
	EM_CRIS          = 76
	EM_JAVELIN       = 77
	EM_FIREPATH      = 78
	EM_ZSP           = 79
	EM_MMIX          = 80
	EM_HUANY         = 81
	EM_PRISM         = 82
	EM_AVR           = 83
	EM_FR30          = 84
	EM_D10V          = 85
	EM_D30V          = 86
	EM_V850          = 87
	EM_M32R          = 88
	EM_MN10300       = 89
	EM_MN10200       = 90
	EM_PJ            = 91
	EM_OPENRISC      = 92
	EM_ARC_COMPACT   = 93
	EM_XTENSA        = 94
	EM_VIDEOCORE     = 95
	EM_TMM_GPP       = 96
	EM_NS32K         = 97
	EM_TPC           = 98
	EM_SNP1K         = 99
	EM_ST200         = 100
	EM_IP2K          = 101
	EM_MAX           = 102
	EM_CR            = 103
	EM_F2MC16        = 104
	EM_MSP430        = 105
	EM_BLACKFIN      = 106
	EM_SE_C33        = 107
	EM_SEP           = 108
	EM_ARCA          = 109
	EM_UNICORE       = 110
	EM_EXCESS        = 111
	EM_DXP           = 112
	EM_ALTERA_NIOS2  = 113
	EM_CRX           = 114
	EM_XGATE         = 115
	EM_C166          = 116
	EM_M16C          = 117
	EM_DSPIC30F      = 118
	EM_CE            = 119
	EM_M32C          = 120
	EM_TSK3000       = 131
	EM_RS08          = 132
	EM_SHARC         = 133
	EM_ECOG2         = 134
	EM_SCORE7        = 135
	EM_DSP24         = 136
	EM_VIDEOCORE3    = 137
	EM_LATTICEMICO32 = 138
	EM_SE_C17        = 139
	EM_TI_C6000      = 140
	EM_TI_C2000      = 141
	EM_TI_C5500      = 142
	EM_TI_ARP32      = 143
	EM_TI_PRU        = 144
	EM_MMDSP_PLUS    = 160
	EM_CYPRESS_M8C   = 161
	EM_R32C          = 162
	EM_TRIMEDIA      = 163
	EM_QDSP6         = 164
	EM_8051          = 165
	EM_STXP7X        = 166
	EM_NDS32         = 167
	EM_ECOG1X        = 168
	EM_MAXQ30        = 169
	EM_XIMO16        = 170
	EM_MANIK         = 171
	EM_CRAYNV2       = 172
	EM_RX            = 173
	EM_METAG         = 174
	EM_MCST_ELBRUS   = 175
	EM_ECOG16        = 176
	EM_CR16          = 177
	EM_ETPU          = 178
	EM_SLE9X         = 179
	EM_L10M          = 180
	EM_K10M          = 181
	EM_AARCH64       = 183
	EM_AVR32         = 185
	EM_STM8          = 186
	EM_TILE64        = 187
	EM_TILEPRO       = 188
	EM_MICROBLAZE    = 189
	EM_CUDA          = 190
	EM_TILEGX        = 191
	EM_CLOUDSHIELD   = 192
	EM_COREA_1ST     = 193
	EM_COREA_2ND     = 194
	EM_ARCV2         = 195 // also known as EM_ARC_COMPACT2
	EM_OPEN8         = 196
	EM_RL78          = 197
	EM_VIDEOCORE5    = 198
	EM_78KOR         = 199
	EM_56800EX       = 200
	EM_BA1           = 201
	EM_BA2           = 202
	EM_XCORE         = 203
	EM_MCHP_PIC      = 204
	EM_KM32          = 210
	EM_KMX32         = 211
	EM_KMX16         = 212
	EM_KMX8          = 213
	EM_KVARC         = 214
	EM_CDP           = 215
	EM_COGE          = 216
	EM_COOL          = 217
	EM_NORC          = 218
	EM_CSR_KALIMBA   = 219
	EM_Z80           = 220
	EM_VISIUM        = 221
	EM_FT32          = 222
	EM_MOXIE         = 223
	EM_AMDGPU        = 224
	EM_RISCV         = 243
	EM_BPF           = 247
	EM_CSKY          = 252
	EM_LOONGARCH     = 258

	// EM_ALPHA and EM_FRV have non-contiguous historical values.
	EM_ALPHA = 0x9026
	EM_FRV   = 0x5441

	// Historical aliases.
	EM_ARC_COMPACT2 = EM_ARCV2
	EM_ARC_A5       = EM_ARC_COMPACT
)

// machineNames maps machine values to their canonical short names. The names
// follow binutils' BFD architecture names where those are short and commonly
// used (e.g. "x86-64" rather than "i386:x86-64").
var machineNames = map[uint16]string{
	EM_NONE:         "none",
	EM_M32:          "m32",
	EM_SPARC:        "sparc",
	EM_386:          "i386",
	EM_68K:          "m68k",
	EM_88K:          "m88k",
	EM_IAMCU:        "iamcu",
	EM_860:          "i860",
	EM_MIPS:         "mips",
	EM_S370:         "s370",
	EM_MIPS_RS3_LE:  "mips:rs3-le",
	EM_PARISC:       "hppa",
	EM_VPP500:       "vpp500",
	EM_SPARC32PLUS:  "sparc32plus",
	EM_960:          "i960",
	EM_PPC:          "powerpc",
	EM_PPC64:        "powerpc64",
	EM_S390:         "s390",
	EM_SPU:          "spu",
	EM_V800:         "v800",
	EM_FR20:         "fr20",
	EM_RH32:         "rh32",
	EM_RCE:          "rce",
	EM_ARM:          "arm",
	EM_SH:           "sh",
	EM_SPARCV9:      "sparc64",
	EM_TRICORE:      "tricore",
	EM_ARC:          "arc",
	EM_H8_300:       "h8300",
	EM_H8_300H:      "h8300h",
	EM_H8S:          "h8300s",
	EM_H8_500:       "h8500",
	EM_IA_64:        "ia64",
	EM_MIPS_X:       "mips-x",
	EM_X86_64:       "x86-64",
	EM_VAX:          "vax",
	EM_CRIS:         "cris",
	EM_AVR:          "avr",
	EM_D10V:         "d10v",
	EM_D30V:         "d30v",
	EM_V850:         "v850",
	EM_M32R:         "m32r",
	EM_MN10300:      "mn10300",
	EM_MN10200:      "mn10200",
	EM_OPENRISC:     "or1k",
	EM_ARC_COMPACT:  "arcompact",
	EM_XTENSA:       "xtensa",
	EM_IP2K:         "ip2k",
	EM_MSP430:       "msp430",
	EM_BLACKFIN:     "blackfin",
	EM_SE_C33:       "s1c33",
	EM_ALTERA_NIOS2: "nios2",
	EM_XGATE:        "xgate",
	EM_M32C:         "m32c",
	EM_TI_C6000:     "tic6x",
	EM_TI_PRU:       "pru",
	EM_NDS32:        "nds32",
	EM_RX:           "rx",
	EM_METAG:        "metag",
	EM_CR16:         "cr16",
	EM_AARCH64:      "aarch64",
	EM_AVR32:        "avr32",
	EM_TILE64:       "tile64",
	EM_TILEPRO:      "tilepro",
	EM_MICROBLAZE:   "microblaze",
	EM_CUDA:         "cuda",
	EM_TILEGX:       "tilegx",
	EM_ARCV2:        "arcv2",
	EM_RL78:         "rl78",
	EM_Z80:          "z80",
	EM_VISIUM:       "visium",
	EM_FT32:         "ft32",
	EM_MOXIE:        "moxie",
	EM_AMDGPU:       "amdgpu",
	EM_RISCV:        "riscv",
	EM_BPF:          "bpf",
	EM_CSKY:         "csky",
	EM_LOONGARCH:    "loongarch",
	EM_ALPHA:        "alpha",
	EM_FRV:          "frv",
}

// machineAliases contains alternative spellings accepted by MachineFromName.
// The canonical short names from machineNames are accepted as well.
var machineAliases = map[string]uint16{
	// x86
	"x86":         EM_386,
	"i486":        EM_386,
	"i586":        EM_386,
	"i686":        EM_386,
	"x86-64":      EM_X86_64,
	"x86_64":      EM_X86_64,
	"amd64":       EM_X86_64,
	"i386:x86-64": EM_X86_64,
	"x64":         EM_X86_64,
	"iamcu":       EM_IAMCU,

	// ARM
	"arm64":         EM_AARCH64,
	"aarch64:ilp32": EM_AARCH64,
	"aarch64_be":    EM_AARCH64,
	"armeb":         EM_ARM,

	// RISC-V
	"riscv32":    EM_RISCV,
	"riscv64":    EM_RISCV,
	"riscv:rv32": EM_RISCV,
	"riscv:rv64": EM_RISCV,

	// MIPS
	"mips32":   EM_MIPS,
	"mips64":   EM_MIPS,
	"mipsel":   EM_MIPS,
	"mips64el": EM_MIPS,
	"mips:32":  EM_MIPS,
	"mips:64":  EM_MIPS,

	// PowerPC
	"ppc":              EM_PPC,
	"ppc64":            EM_PPC64,
	"ppc64le":          EM_PPC64,
	"powerpc:common":   EM_PPC,
	"powerpcle":        EM_PPC,
	"powerpc64le":      EM_PPC64,
	"powerpc:common64": EM_PPC64,

	// SPARC
	"sparc32":  EM_SPARC,
	"sparcv8":  EM_SPARC,
	"sparcv9":  EM_SPARCV9,
	"sparc:64": EM_SPARCV9,

	// HP PA-RISC
	"parisc": EM_PARISC,
	"hppa64": EM_PARISC,

	// IBM
	"s390x":   EM_S390,
	"s390:64": EM_S390,
	"power":   EM_PPC,
	"power64": EM_PPC64,

	// Others whose common BFD spellings differ from the short name.
	"or1k":         EM_OPENRISC,
	"openrisc":     EM_OPENRISC,
	"nios2":        EM_ALTERA_NIOS2,
	"c6x":          EM_TI_C6000,
	"tic6x":        EM_TI_C6000,
	"microblazeel": EM_MICROBLAZE,
	"sh64":         EM_SH,
	"sheb":         EM_SH,
	"bpfel":        EM_BPF,
	"bpfeb":        EM_BPF,
	"loongarch64":  EM_LOONGARCH,
	"loongarch32":  EM_LOONGARCH,
	"nvptx":        EM_CUDA,
	"cuda":         EM_CUDA,
	"moxiebox":     EM_MOXIE,
	"crisv32":      EM_CRIS,
	"h8":           EM_H8_300,
	"h8s":          EM_H8S,
	"v850e":        EM_V850,
}

// MachineName returns the canonical short architecture name for an ELF
// machine value, for example "x86-64" for EM_X86_64. Unknown values are
// rendered in hexadecimal rather than causing a panic.
func MachineName(m uint16) string {
	if name, ok := machineNames[m]; ok {
		return name
	}
	return fmt.Sprintf("0x%x", m)
}

// MachineFromName resolves an architecture name (case-insensitively) to an ELF
// machine value. Both canonical short names and common BFD/objcopy spellings
// such as "i386:x86-64" or "powerpc:common64" are accepted.
func MachineFromName(s string) (uint16, bool) {
	key := strings.ToLower(strings.TrimSpace(s))
	if m, ok := machineAliases[key]; ok {
		return m, true
	}
	for m, name := range machineNames {
		if name == key {
			return m, true
		}
	}
	return 0, false
}

// TypeName returns the conventional name of an ELF file (e_type) value.
func TypeName(t uint16) string {
	switch t {
	case ET_NONE:
		return "NONE"
	case ET_REL:
		return "REL"
	case ET_EXEC:
		return "EXEC"
	case ET_DYN:
		return "DYN"
	case ET_CORE:
		return "CORE"
	}
	return fmt.Sprintf("0x%x", t)
}

// SectionTypeName returns the readelf-style name of a section type (sh_type).
func SectionTypeName(t uint32) string {
	switch t {
	case SHT_NULL:
		return "NULL"
	case SHT_PROGBITS:
		return "PROGBITS"
	case SHT_SYMTAB:
		return "SYMTAB"
	case SHT_STRTAB:
		return "STRTAB"
	case SHT_RELA:
		return "RELA"
	case SHT_HASH:
		return "HASH"
	case SHT_DYNAMIC:
		return "DYNAMIC"
	case SHT_NOTE:
		return "NOTE"
	case SHT_NOBITS:
		return "NOBITS"
	case SHT_REL:
		return "REL"
	case SHT_SHLIB:
		return "SHLIB"
	case SHT_DYNSYM:
		return "DYNSYM"
	case SHT_INIT_ARRAY:
		return "INIT_ARRAY"
	case SHT_FINI_ARRAY:
		return "FINI_ARRAY"
	case SHT_PREINIT_ARRAY:
		return "PREINIT_ARRAY"
	case SHT_GROUP:
		return "GROUP"
	case SHT_SYMTAB_SHNDX:
		return "SYMTAB SECTION INDICES"
	case SHT_RELR:
		return "RELR"
	case SHT_GNU_ATTRIBUTES:
		return "GNU_ATTRIBUTES"
	case SHT_GNU_HASH:
		return "GNU_HASH"
	case SHT_GNU_LIBLIST:
		return "GNU_LIBLIST"
	case SHT_CHECKSUM:
		return "CHECKSUM"
	case SHT_GNU_verdef:
		return "VERDEF"
	case SHT_GNU_verneed:
		return "VERNEED"
	case SHT_GNU_versym:
		return "VERSYM"
	}
	return fmt.Sprintf("0x%x", t)
}

// SectionFlagName renders section flags in readelf style, for example "WA" for
// a writable, allocated section or "AX" for executable code. Unknown bits are
// appended in hexadecimal form.
func SectionFlagName(f uint64) string {
	var b strings.Builder
	for _, flag := range []struct {
		bit  uint64
		char byte
	}{
		{SHF_WRITE, 'W'},
		{SHF_ALLOC, 'A'},
		{SHF_EXECINSTR, 'X'},
		{SHF_MERGE, 'M'},
		{SHF_STRINGS, 'S'},
		{SHF_INFO_LINK, 'I'},
		{SHF_LINK_ORDER, 'L'},
		{SHF_OS_NONCONFORMING, 'O'},
		{SHF_GROUP, 'G'},
		{SHF_TLS, 'T'},
		{SHF_COMPRESSED, 'C'},
		{SHF_GNU_RETAIN, 'R'},
		{0x80000000, 'E'}, // SHF_EXCLUDE
	} {
		if f&flag.bit != 0 {
			b.WriteByte(flag.char)
			f &^= flag.bit
		}
	}
	if f != 0 {
		if b.Len() != 0 {
			b.WriteByte('|')
		}
		fmt.Fprintf(&b, "0x%x", f)
	}
	return b.String()
}

// SymbolBindName returns the name of a symbol binding (ST_BIND).
func SymbolBindName(b byte) string {
	switch b {
	case STB_LOCAL:
		return "LOCAL"
	case STB_GLOBAL:
		return "GLOBAL"
	case STB_WEAK:
		return "WEAK"
	case STB_GNU_UNIQUE:
		return "UNIQUE"
	}
	return fmt.Sprintf("0x%x", b)
}

// SymbolTypeName returns the name of a symbol type (ST_TYPE).
func SymbolTypeName(t byte) string {
	switch t {
	case STT_NOTYPE:
		return "NOTYPE"
	case STT_OBJECT:
		return "OBJECT"
	case STT_FUNC:
		return "FUNC"
	case STT_SECTION:
		return "SECTION"
	case STT_FILE:
		return "FILE"
	case STT_COMMON:
		return "COMMON"
	case STT_TLS:
		return "TLS"
	case STT_GNU_IFUNC:
		return "IFUNC"
	}
	return fmt.Sprintf("0x%x", t)
}

// SymbolVisName returns the name of a symbol visibility (ST_VISIBILITY).
func SymbolVisName(v byte) string {
	switch v {
	case STV_DEFAULT:
		return "DEFAULT"
	case STV_INTERNAL:
		return "INTERNAL"
	case STV_HIDDEN:
		return "HIDDEN"
	case STV_PROTECTED:
		return "PROTECTED"
	}
	return fmt.Sprintf("0x%x", v)
}

// ProgramTypeName returns the readelf-style name of a program header type
// (p_type).
func ProgramTypeName(t uint32) string {
	switch t {
	case PT_NULL:
		return "NULL"
	case PT_LOAD:
		return "LOAD"
	case PT_DYNAMIC:
		return "DYNAMIC"
	case PT_INTERP:
		return "INTERP"
	case PT_NOTE:
		return "NOTE"
	case PT_SHLIB:
		return "SHLIB"
	case PT_PHDR:
		return "PHDR"
	case PT_TLS:
		return "TLS"
	case PT_GNU_EH_FRAME:
		return "GNU_EH_FRAME"
	case PT_GNU_STACK:
		return "GNU_STACK"
	case PT_GNU_RELRO:
		return "GNU_RELRO"
	case PT_GNU_PROPERTY:
		return "GNU_PROPERTY"
	}
	return fmt.Sprintf("0x%x", t)
}

// OSABIName returns a short human-readable name for an ELF OS/ABI value.
func OSABIName(b byte) string {
	switch b {
	case ELFOSABI_NONE:
		return "System V"
	case ELFOSABI_HPUX:
		return "HP-UX"
	case ELFOSABI_NETBSD:
		return "NetBSD"
	case ELFOSABI_GNU:
		return "GNU"
	case ELFOSABI_SOLARIS:
		return "Solaris"
	case ELFOSABI_AIX:
		return "AIX"
	case ELFOSABI_IRIX:
		return "IRIX"
	case ELFOSABI_FREEBSD:
		return "FreeBSD"
	case ELFOSABI_TRU64:
		return "TRU64"
	case ELFOSABI_MODESTO:
		return "Modesto"
	case ELFOSABI_OPENBSD:
		return "OpenBSD"
	case ELFOSABI_OPENVMS:
		return "OpenVMS"
	case ELFOSABI_NSK:
		return "NonStop Kernel"
	case ELFOSABI_AROS:
		return "AROS"
	case ELFOSABI_FENIXOS:
		return "FenixOS"
	case ELFOSABI_CLOUDABI:
		return "CloudABI"
	case ELFOSABI_OPENVOS:
		return "OpenVOS"
	case ELFOSABI_ARM_AEABI:
		return "ARM EABI"
	case ELFOSABI_ARM:
		return "ARM"
	case ELFOSABI_STANDALONE:
		return "Standalone"
	}
	return fmt.Sprintf("0x%x", b)
}
