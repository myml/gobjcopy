package elf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

// ErrNotELF is returned when the input does not start with the ELF magic.
var ErrNotELF = errors.New("elf: not an ELF file")

// Error describes a malformed ELF file.
type Error struct{ Msg string }

func (e *Error) Error() string { return "elf: " + e.Msg }

func errf(format string, args ...any) error {
	return &Error{Msg: fmt.Sprintf(format, args...)}
}

// Order returns the byte order implied by d.
func (d Data) Order() binary.ByteOrder {
	if d == DataMSB {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// Parse parses an in-memory ELF image.
func Parse(b []byte) (*File, error) {
	if len(b) < 16 || b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F' {
		return nil, ErrNotELF
	}
	class := Class(b[4])
	if class != Class32 && class != Class64 {
		return nil, errf("invalid ELF class %d", b[4])
	}
	data := Data(b[5])
	if data != DataLSB && data != DataMSB {
		return nil, errf("invalid ELF data encoding %d", b[5])
	}
	hdrSize := 52
	shdrSize, phdrSize := 40, 32
	if class == Class64 {
		hdrSize, shdrSize, phdrSize = 64, 64, 56
	}
	if len(b) < hdrSize {
		return nil, errf("truncated ELF header")
	}
	order := data.Order()
	f := &File{SectionHeadersPresent: false, raw: b}
	f.Class = class
	f.Data = data
	f.OSABI = b[7]
	f.ABIVersion = b[8]
	f.Type = order.Uint16(b[16:])
	f.Machine = order.Uint16(b[18:])
	f.Version = order.Uint32(b[20:])

	var phoff, shoff uint64
	var ehsize, phentsize, phnum, shentsize, shnum, shstrndx uint16
	if class == Class64 {
		f.Entry = order.Uint64(b[24:])
		phoff = order.Uint64(b[32:])
		shoff = order.Uint64(b[40:])
		f.Flags = order.Uint32(b[48:])
		ehsize = order.Uint16(b[52:])
		phentsize = order.Uint16(b[54:])
		phnum = order.Uint16(b[56:])
		shentsize = order.Uint16(b[58:])
		shnum = order.Uint16(b[60:])
		shstrndx = order.Uint16(b[62:])
	} else {
		f.Entry = uint64(order.Uint32(b[24:]))
		phoff = uint64(order.Uint32(b[28:]))
		shoff = uint64(order.Uint32(b[32:]))
		f.Flags = order.Uint32(b[36:])
		ehsize = order.Uint16(b[40:])
		phentsize = order.Uint16(b[42:])
		phnum = order.Uint16(b[44:])
		shentsize = order.Uint16(b[46:])
		shnum = order.Uint16(b[48:])
		shstrndx = order.Uint16(b[50:])
	}
	_ = ehsize
	if shentsize != 0 && int(shentsize) < shdrSize {
		return nil, errf("invalid section header entry size %d", shentsize)
	}
	if phentsize != 0 && int(phentsize) < phdrSize {
		return nil, errf("invalid program header entry size %d", phentsize)
	}

	// Section headers may use the extended numbering scheme.
	if shoff != 0 {
		if shoff > uint64(len(b)) || uint64(shdrSize) > uint64(len(b))-shoff {
			return nil, errf("section header table offset 0x%x out of bounds", shoff)
		}
		sh0, _ := parseShdr(b, shoff, class, order)
		if shnum == 0 {
			shnum = uint16(sh0.Size)
		}
		if shstrndx == SHN_XINDEX {
			shstrndx = uint16(sh0.Link)
		}
	}
	if shnum > 0 && shoff != 0 {
		end := shoff + uint64(shnum)*uint64(shdrSize)
		if end > uint64(len(b)) || end < shoff {
			return nil, errf("section header table (%d entries) out of bounds", shnum)
		}
		f.Sections = make([]*Section, 0, shnum)
		nameOffs := make([]uint32, 0, shnum)
		for i := 0; i < int(shnum); i++ {
			off := shoff + uint64(i)*uint64(shdrSize)
			sh, nameOff := parseShdr(b, off, class, order)
			sec := &Section{SectionHeader: *sh}
			if sec.Type != SHT_NOBITS && sec.Type != SHT_NULL && sec.Size > 0 {
				if sec.Offset > uint64(len(b)) || sec.Size > uint64(len(b))-sec.Offset {
					return nil, errf("section %d content out of bounds", i)
				}
				sec.Data = append([]byte(nil), b[sec.Offset:sec.Offset+sec.Size]...)
			}
			f.Sections = append(f.Sections, sec)
			nameOffs = append(nameOffs, nameOff)
		}
		if int(shstrndx) < len(f.Sections) {
			if strtab := f.Sections[shstrndx]; strtab != nil && strtab.Type == SHT_STRTAB {
				for i, sec := range f.Sections {
					sec.Name = cstring(strtab.Data, uint64(nameOffs[i]))
				}
			}
		}
		f.SectionHeadersPresent = true
		f.Shstrndx = int(shstrndx)
	}

	// Program headers.
	if phnum > 0 && phoff != 0 {
		end := phoff + uint64(phnum)*uint64(phdrSize)
		if end > uint64(len(b)) || end < phoff {
			return nil, errf("program header table out of bounds")
		}
		f.Segments = make([]*ProgramHeader, 0, phnum)
		for i := 0; i < int(phnum); i++ {
			off := phoff + uint64(i)*uint64(phdrSize)
			f.Segments = append(f.Segments, parsePhdr(b[off:], class, order))
		}
	}
	return f, nil
}

// Open reads and parses the named file.
func Open(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := Parse(b)
	if err != nil {
		return nil, err
	}
	f.Path = path
	return f, nil
}

func parseShdr(b []byte, off uint64, class Class, order binary.ByteOrder) (*SectionHeader, uint32) {
	s := &SectionHeader{}
	nameOff := order.Uint32(b[off:])
	s.Type = order.Uint32(b[off+4:])
	if class == Class64 {
		s.Flags = order.Uint64(b[off+8:])
		s.Addr = order.Uint64(b[off+16:])
		s.Offset = order.Uint64(b[off+24:])
		s.Size = order.Uint64(b[off+32:])
		s.Link = order.Uint32(b[off+40:])
		s.Info = order.Uint32(b[off+44:])
		s.Addralign = order.Uint64(b[off+48:])
		s.Entsize = order.Uint64(b[off+56:])
	} else {
		s.Flags = uint64(order.Uint32(b[off+8:]))
		s.Addr = uint64(order.Uint32(b[off+12:]))
		s.Offset = uint64(order.Uint32(b[off+16:]))
		s.Size = uint64(order.Uint32(b[off+20:]))
		s.Link = order.Uint32(b[off+24:])
		s.Info = order.Uint32(b[off+28:])
		s.Addralign = uint64(order.Uint32(b[off+32:]))
		s.Entsize = uint64(order.Uint32(b[off+36:]))
	}
	return s, nameOff
}

func parsePhdr(b []byte, class Class, order binary.ByteOrder) *ProgramHeader {
	if class == Class64 {
		return &ProgramHeader{
			Type:   order.Uint32(b[0:]),
			Flags:  order.Uint32(b[4:]),
			Offset: order.Uint64(b[8:]),
			Vaddr:  order.Uint64(b[16:]),
			Paddr:  order.Uint64(b[24:]),
			Filesz: order.Uint64(b[32:]),
			Memsz:  order.Uint64(b[40:]),
			Align:  order.Uint64(b[48:]),
		}
	}
	return &ProgramHeader{
		Type:   order.Uint32(b[0:]),
		Offset: uint64(order.Uint32(b[4:])),
		Vaddr:  uint64(order.Uint32(b[8:])),
		Paddr:  uint64(order.Uint32(b[12:])),
		Filesz: uint64(order.Uint32(b[16:])),
		Memsz:  uint64(order.Uint32(b[20:])),
		Flags:  order.Uint32(b[24:]),
		Align:  uint64(order.Uint32(b[28:])),
	}
}

func cstring(b []byte, off uint64) string {
	if off >= uint64(len(b)) {
		return ""
	}
	b = b[off:]
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
