// Package elf implements reading and writing of ELF object files in pure Go.
//
// Unlike the standard library's debug/elf package it is not read-only: the
// parsed representation can be modified and serialised back to a valid ELF
// file, including section/program header layout and relocation fixups.
package elf

// Class is the ELF class (32 or 64 bit).
type Class uint8

const (
	Class32 Class = 1
	Class64 Class = 2
)

func (c Class) String() string {
	if c == Class64 {
		return "ELF64"
	}
	return "ELF32"
}

// Data is the ELF byte order.
type Data uint8

const (
	DataLSB Data = 1
	DataMSB Data = 2
)

func (d Data) String() string {
	if d == DataMSB {
		return "big endian"
	}
	return "little endian"
}

// ELF file types.
const (
	ET_NONE   = 0
	ET_REL    = 1
	ET_EXEC   = 2
	ET_DYN    = 3
	ET_CORE   = 4
	ET_LOOS   = 0xfe00
	ET_HIOS   = 0xfeff
	ET_LOPROC = 0xff00
	ET_HIPROC = 0xffff
)

// ELF versions.
const (
	EV_NONE    = 0
	EV_CURRENT = 1
)

// OS ABI values.
const (
	ELFOSABI_NONE       = 0
	ELFOSABI_SYSV       = 0
	ELFOSABI_HPUX       = 1
	ELFOSABI_NETBSD     = 2
	ELFOSABI_GNU        = 3
	ELFOSABI_LINUX      = 3
	ELFOSABI_SOLARIS    = 6
	ELFOSABI_AIX        = 7
	ELFOSABI_IRIX       = 8
	ELFOSABI_FREEBSD    = 9
	ELFOSABI_TRU64      = 10
	ELFOSABI_MODESTO    = 11
	ELFOSABI_OPENBSD    = 12
	ELFOSABI_OPENVMS    = 13
	ELFOSABI_NSK        = 14
	ELFOSABI_AROS       = 15
	ELFOSABI_FENIXOS    = 16
	ELFOSABI_CLOUDABI   = 17
	ELFOSABI_OPENVOS    = 18
	ELFOSABI_ARM_AEABI  = 64
	ELFOSABI_ARM        = 97
	ELFOSABI_STANDALONE = 255
)

// Special section indices.
const (
	SHN_UNDEF     = 0
	SHN_LORESERVE = 0xff00
	SHN_LOPROC    = 0xff00
	SHN_HIPROC    = 0xff1f
	SHN_LOOS      = 0xff20
	SHN_HIOS      = 0xff3f
	SHN_ABS       = 0xfff1
	SHN_COMMON    = 0xfff2
	SHN_XINDEX    = 0xffff
	SHN_HIRESERVE = 0xffff
)

// Section types.
const (
	SHT_NULL           = 0
	SHT_PROGBITS       = 1
	SHT_SYMTAB         = 2
	SHT_STRTAB         = 3
	SHT_RELA           = 4
	SHT_HASH           = 5
	SHT_DYNAMIC        = 6
	SHT_NOTE           = 7
	SHT_NOBITS         = 8
	SHT_REL            = 9
	SHT_SHLIB          = 10
	SHT_DYNSYM         = 11
	SHT_INIT_ARRAY     = 14
	SHT_FINI_ARRAY     = 15
	SHT_PREINIT_ARRAY  = 16
	SHT_GROUP          = 17
	SHT_SYMTAB_SHNDX   = 18
	SHT_RELR           = 19
	SHT_GNU_ATTRIBUTES = 0x6ffffff5
	SHT_GNU_HASH       = 0x6ffffff6
	SHT_GNU_LIBLIST    = 0x6ffffff7
	SHT_CHECKSUM       = 0x6ffffff8
	SHT_GNU_verdef     = 0x6ffffffd
	SHT_GNU_verneed    = 0x6ffffffe
	SHT_GNU_versym     = 0x6fffffff
	SHT_LOPROC         = 0x70000000
	SHT_HIPROC         = 0x7fffffff
	SHT_LOUSER         = 0x80000000
	SHT_HIUSER         = 0xffffffff
)

// Section flags.
const (
	SHF_WRITE            = 0x1
	SHF_ALLOC            = 0x2
	SHF_EXECINSTR        = 0x4
	SHF_MERGE            = 0x10
	SHF_STRINGS          = 0x20
	SHF_INFO_LINK        = 0x40
	SHF_LINK_ORDER       = 0x80
	SHF_OS_NONCONFORMING = 0x100
	SHF_GROUP            = 0x200
	SHF_TLS              = 0x400
	SHF_COMPRESSED       = 0x800
	SHF_GNU_RETAIN       = 0x200000
	SHF_GNU_MBIND        = 0x01000000
	SHF_X86_64_LARGE     = 0x10000000
	SHF_EXCLUDE          = 0x80000000
	SHF_MASKOS           = 0x0ff00000
	SHF_MASKPROC         = 0xf0000000
)

// Symbol binding.
const (
	STB_LOCAL      = 0
	STB_GLOBAL     = 1
	STB_WEAK       = 2
	STB_GNU_UNIQUE = 10
	STB_LOOS       = 10
	STB_HIOS       = 12
	STB_LOPROC     = 13
	STB_HIPROC     = 15
)

// Symbol types.
const (
	STT_NOTYPE    = 0
	STT_OBJECT    = 1
	STT_FUNC      = 2
	STT_SECTION   = 3
	STT_FILE      = 4
	STT_COMMON    = 5
	STT_TLS       = 6
	STT_GNU_IFUNC = 10
	STT_LOOS      = 10
	STT_HIOS      = 12
	STT_LOPROC    = 13
	STT_HIPROC    = 15
)

// Symbol visibility.
const (
	STV_DEFAULT   = 0
	STV_INTERNAL  = 1
	STV_HIDDEN    = 2
	STV_PROTECTED = 3
)

// Program header types.
const (
	PT_NULL         = 0
	PT_LOAD         = 1
	PT_DYNAMIC      = 2
	PT_INTERP       = 3
	PT_NOTE         = 4
	PT_SHLIB        = 5
	PT_PHDR         = 6
	PT_TLS          = 7
	PT_LOOS         = 0x60000000
	PT_GNU_EH_FRAME = 0x6474e550
	PT_GNU_STACK    = 0x6474e551
	PT_GNU_RELRO    = 0x6474e552
	PT_GNU_PROPERTY = 0x6474e553
	PT_HIOS         = 0x6fffffff
	PT_LOPROC       = 0x70000000
	PT_HIPROC       = 0x7fffffff
)

// Program header flags.
const (
	PF_X        = 0x1
	PF_W        = 0x2
	PF_R        = 0x4
	PF_MASKOS   = 0x0ff00000
	PF_MASKPROC = 0xf0000000
)

// Header describes a file header's mutable fields.
type Header struct {
	Class      Class
	Data       Data
	OSABI      byte
	ABIVersion byte
	Type       uint16
	Machine    uint16
	Version    uint32
	Entry      uint64
	Flags      uint32
}

// SectionHeader mirrors the on-disk Elf{32,64}_Shdr structure. Link and Info
// are section indices into a File's Sections slice (the writer renumbers them).
type SectionHeader struct {
	Name      string
	Type      uint32
	Flags     uint64
	Addr      uint64
	Offset    uint64 // file offset, set on read; recomputed on write
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

// Section is a section header plus its contents. Data is nil for SHT_NOBITS.
type Section struct {
	SectionHeader
	Data []byte
	// LMA overrides the load address used when writing raw binary output.
	// ELF itself stores no per-section LMA; it is derived from PT_LOAD
	// segments. nil means "derive from segments".
	LMA *uint64
}

// IsAlloc reports whether the section occupies memory at run time.
func (s *Section) IsAlloc() bool { return s.Flags&SHF_ALLOC != 0 }

// IsNoBits reports whether the section occupies no file space.
func (s *Section) IsNoBits() bool { return s.Type == SHT_NOBITS }

// ProgramHeader mirrors the on-disk Elf{32,64}_Phdr structure.
type ProgramHeader struct {
	Type   uint32
	Flags  uint32
	Offset uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

// File is a parsed ELF file. Sections and Segments are the mutable model; the
// string table used for section names is always looked up from Sections.
type File struct {
	Header
	Sections []*Section
	Segments []*ProgramHeader

	// Path is the file name the image was read from, if any.
	Path string

	// Shstrndx is the section index of the section name string table.
	Shstrndx int
	// NoSectionHeaders suppresses the section header table on output
	// (objcopy --strip-section-headers).
	NoSectionHeaders bool

	raw []byte

	// SectionHeadersPresent records whether the input had a section header
	// table. Striped-at-the-source executables may not.
	SectionHeadersPresent bool
}
