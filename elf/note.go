package elf

import (
	"encoding/binary"
	"math"
)

// Note constants from the ELF gABI and from GNU's <elf/common.h>. Only the
// values that this package and its callers need are defined here.
const (
	// SHT_NOTE entry types used by GNU.
	NT_GNU_ABI_TAG         = 1 // NT_GNU_ABI_TAG
	NT_GNU_HWCAP           = 2
	NT_GNU_BUILD_ID        = 3
	NT_GNU_GOLD_VERSION    = 4
	NT_GNU_PROPERTY_TYPE_0 = 5

	// GNU build attribute note types (the n_type field).
	NT_GNU_BUILD_ATTRIBUTE_OPEN = 0x100
	NT_GNU_BUILD_ATTRIBUTE_FUNC = 0x101

	// GNU build attribute value kinds, encoded in the first byte of the
	// note name (after the optional "GA" owner prefix).
	GNU_BUILD_ATTRIBUTE_TYPE_NUMERIC    = '*'
	GNU_BUILD_ATTRIBUTE_TYPE_STRING     = '$'
	GNU_BUILD_ATTRIBUTE_TYPE_BOOL_TRUE  = '+'
	GNU_BUILD_ATTRIBUTE_TYPE_BOOL_FALSE = '!'

	// GNU build attribute identifiers, encoded in the byte after the value
	// kind and a NUL terminator for string/boolean attributes.
	GNU_BUILD_ATTRIBUTE_VERSION    = 1
	GNU_BUILD_ATTRIBUTE_STACK_PROT = 2
	GNU_BUILD_ATTRIBUTE_RELRO      = 3
	GNU_BUILD_ATTRIBUTE_STACK_SIZE = 4
	GNU_BUILD_ATTRIBUTE_TOOL       = 5
	GNU_BUILD_ATTRIBUTE_ABI        = 6
	GNU_BUILD_ATTRIBUTE_PIC        = 7
	GNU_BUILD_ATTRIBUTE_SHORT_ENUM = 8

	// GNU_BUILD_ATTRS_SECTION_NAME is the section that GNU objcopy merges
	// with --merge-notes. BFD matches it as a prefix, not exactly.
	GNU_BUILD_ATTRS_SECTION_NAME = ".gnu.build.attributes"

	// DefaultNoteAlign is the note entry alignment used when a section does
	// not request 8-byte alignment.
	DefaultNoteAlign = 4
)

// Note is one entry of an SHT_NOTE section:
//
//	uint32 namesz, uint32 descsz, uint32 type, name[namesz], desc[descsz]
//
// Name and Desc hold the exact on-disk bytes, without the alignment padding
// that follows each of them: Name therefore normally ends with a NUL byte.
// MarshalNotes regenerates the padding as zero bytes, so a parse/serialise
// round trip normalises non-zero padding.
type Note struct {
	Name []byte
	Desc []byte
	Type uint32
}

// NameString returns Name as a string with the trailing NUL removed. It is a
// convenience for diagnostics and for ASCII note owners such as "GNU".
func (n Note) NameString() string {
	s := string(n.Name)
	if len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return s
}

// NoteAlign converts an SHT_NOTE section's sh_addralign into the entry
// alignment used on disk. The gABI uses 4-byte alignment for ELF32 notes and
// 8-byte alignment for ELF64 notes; like BFD, any value below 4 is treated as
// 4 and any other value is rejected.
func NoteAlign(addralign uint64) (int, error) {
	if addralign <= DefaultNoteAlign {
		return DefaultNoteAlign, nil
	}
	if addralign == 8 {
		return 8, nil
	}
	return 0, errf("note section alignment %d is not 4 or 8", addralign)
}

// ParseNotes decodes the contents of an SHT_NOTE section. order is the file
// byte order and align the entry alignment returned by NoteAlign; values below
// 4 are treated as 4.
func ParseNotes(order binary.ByteOrder, align int, data []byte) ([]Note, error) {
	if align < DefaultNoteAlign {
		align = DefaultNoteAlign
	}
	if align != 4 && align != 8 {
		return nil, errf("note alignment %d is not 4 or 8", align)
	}
	var notes []Note
	for off := 0; off < len(data); {
		if len(data)-off < 12 {
			return nil, errf("truncated note header at offset %d", off)
		}
		namesz := order.Uint32(data[off:])
		descsz := order.Uint32(data[off+4:])
		typ := order.Uint32(data[off+8:])

		nameOff := off + 12
		if uint64(namesz) > uint64(len(data)-nameOff) {
			return nil, errf("note name at offset %d is out of bounds", off)
		}
		nameEnd := nameOff + int(namesz)
		descOff := alignUpInt(nameEnd, align)
		if descOff > len(data) {
			return nil, errf("note descriptor at offset %d is out of bounds", off)
		}
		if uint64(descsz) > uint64(len(data)-descOff) {
			return nil, errf("note descriptor at offset %d is out of bounds", off)
		}
		descEnd := descOff + int(descsz)

		notes = append(notes, Note{
			Name: data[nameOff:nameEnd],
			Desc: data[descOff:descEnd],
			Type: typ,
		})

		next := alignUpInt(descEnd, align)
		if next > len(data) {
			// A note at the end of the section may omit its trailing
			// padding; tolerate that, as long as the descriptor itself fit.
			next = len(data)
		}
		if next <= off {
			return nil, errf("note at offset %d does not advance", off)
		}
		off = next
	}
	return notes, nil
}

// MarshalNotes encodes notes as the contents of an SHT_NOTE section, using
// the same byte order and alignment as ParseNotes. Padding bytes are zero.
func MarshalNotes(order binary.ByteOrder, align int, notes []Note) ([]byte, error) {
	if align < DefaultNoteAlign {
		align = DefaultNoteAlign
	}
	if align != 4 && align != 8 {
		return nil, errf("note alignment %d is not 4 or 8", align)
	}
	size := 0
	for i, n := range notes {
		if uint64(len(n.Name)) > math.MaxUint32 {
			return nil, errf("note %d name is too long", i)
		}
		if uint64(len(n.Desc)) > math.MaxUint32 {
			return nil, errf("note %d descriptor is too long", i)
		}
		// The descriptor starts at an aligned offset counted from the start
		// of the note header, not from the start of the name; with 8-byte
		// alignment the 12-byte header itself consumes one alignment unit.
		size += 12
		size = alignUpInt(size+len(n.Name), align)
		size = alignUpInt(size+len(n.Desc), align)
	}
	out := make([]byte, 0, size)
	for _, n := range notes {
		var hdr [12]byte
		order.PutUint32(hdr[0:], uint32(len(n.Name)))
		order.PutUint32(hdr[4:], uint32(len(n.Desc)))
		order.PutUint32(hdr[8:], n.Type)
		out = append(out, hdr[:]...)
		out = append(out, n.Name...)
		appendZeros(&out, alignUpInt(len(out), align)-len(out))
		out = append(out, n.Desc...)
		appendZeros(&out, alignUpInt(len(out), align)-len(out))
	}
	return out, nil
}

// Notes parses sec as an SHT_NOTE section of f.
func (f *File) Notes(sec *Section) ([]Note, error) {
	if sec == nil {
		return nil, errf("nil note section")
	}
	if sec.Type != SHT_NOTE {
		return nil, errf("section %q is not a note section", sec.Name)
	}
	align, err := NoteAlign(sec.Addralign)
	if err != nil {
		return nil, err
	}
	return ParseNotes(f.Data.Order(), align, sec.Data)
}

// SetNotes serialises notes into sec and updates its size. It does not change
// the section type or its flags.
func (f *File) SetNotes(sec *Section, notes []Note) error {
	if sec == nil {
		return errf("nil note section")
	}
	align, err := NoteAlign(sec.Addralign)
	if err != nil {
		return err
	}
	data, err := MarshalNotes(f.Data.Order(), align, notes)
	if err != nil {
		return err
	}
	sec.Data = data
	sec.Size = uint64(len(data))
	return nil
}

func alignUpInt(v, a int) int {
	if a <= 1 {
		return v
	}
	return (v + a - 1) &^ (a - 1)
}

func appendZeros(b *[]byte, n int) {
	for i := 0; i < n; i++ {
		*b = append(*b, 0)
	}
}
