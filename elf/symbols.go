package elf

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Symbol is a decoded symbol table entry. Shndx is a section index into
// File.Sections (or a SHN_* special value).
type Symbol struct {
	Name  string
	Info  byte
	Other byte
	Shndx uint16
	Value uint64
	Size  uint64
}

// Bind returns the symbol binding (STB_*).
func (s Symbol) Bind() byte { return s.Info >> 4 }

// Type returns the symbol type (STT_*).
func (s Symbol) Type() byte { return s.Info & 0xf }

// Visibility returns the symbol visibility (STV_*).
func (s Symbol) Visibility() byte { return s.Other & 0x3 }

// SetBind sets the binding nibble.
func (s *Symbol) SetBind(b byte) { s.Info = s.Info&0x0f | b<<4 }

// SetType sets the type nibble.
func (s *Symbol) SetType(t byte) { s.Info = s.Info&0xf0 | t&0x0f }

// SetVisibility sets the visibility bits.
func (s *Symbol) SetVisibility(v byte) { s.Other = s.Other&^0x3 | v&0x3 }

// Symtab is a decoded symbol table together with the section holding it.
type Symtab struct {
	Section *Section
	Entries []Symbol
}

// Section returns the section with the given name, or nil.
func (f *File) Section(name string) *Section {
	for _, s := range f.Sections {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// SectionIndex returns the index of sec in f.Sections, or -1.
func (f *File) SectionIndex(sec *Section) int {
	for i, s := range f.Sections {
		if s == sec {
			return i
		}
	}
	return -1
}

// SectionByType returns the first live section of the given type.
func (f *File) SectionByType(t uint32) *Section {
	for _, s := range f.Sections {
		if s.Type == t {
			return s
		}
	}
	return nil
}

// Symtab returns the primary (static) symbol table, or nil if absent.
func (f *File) Symtab() *Symtab {
	sec := f.SectionByType(SHT_SYMTAB)
	if sec == nil {
		return nil
	}
	st, err := f.ReadSymtab(sec)
	if err != nil {
		return nil
	}
	return st
}

// Dynsym returns the dynamic symbol table, or nil if absent.
func (f *File) Dynsym() *Symtab {
	sec := f.SectionByType(SHT_DYNSYM)
	if sec == nil {
		return nil
	}
	st, err := f.ReadSymtab(sec)
	if err != nil {
		return nil
	}
	return st
}

// SymSize returns the on-disk size of a symbol entry.
func (f *File) SymSize() int {
	if f.Class == Class64 {
		return 24
	}
	return 16
}

// ReadSymtab decodes the symbol table stored in sec.
func (f *File) ReadSymtab(sec *Section) (*Symtab, error) {
	if sec.Type != SHT_SYMTAB && sec.Type != SHT_DYNSYM {
		return nil, fmt.Errorf("elf: section %q is not a symbol table", sec.Name)
	}
	ent := f.SymSize()
	if len(sec.Data)%ent != 0 {
		return nil, fmt.Errorf("elf: symbol table %q has bad size %d", sec.Name, len(sec.Data))
	}
	var strtab []byte
	if int(sec.Link) < len(f.Sections) {
		strtab = f.Sections[sec.Link].Data
	}
	var xindex []byte
	// SHT_SYMTAB_SHNDX companion, if any, holds extended section indices.
	for _, s := range f.Sections {
		if s.Type == SHT_SYMTAB_SHNDX && int(s.Link) == f.SectionIndex(sec) {
			xindex = s.Data
		}
	}
	order := f.Data.Order()
	n := len(sec.Data) / ent
	out := &Symtab{Section: sec, Entries: make([]Symbol, 0, n)}
	for i := 0; i < n; i++ {
		b := sec.Data[i*ent:]
		sym := Symbol{}
		nameOff := order.Uint32(b[0:])
		sym.Name = cstring(strtab, uint64(nameOff))
		if f.Class == Class64 {
			sym.Info = b[4]
			sym.Other = b[5]
			sym.Shndx = order.Uint16(b[6:])
			sym.Value = order.Uint64(b[8:])
			sym.Size = order.Uint64(b[16:])
		} else {
			sym.Value = uint64(order.Uint32(b[4:]))
			sym.Size = uint64(order.Uint32(b[8:]))
			sym.Info = b[12]
			sym.Other = b[13]
			sym.Shndx = order.Uint16(b[14:])
		}
		if sym.Shndx == SHN_XINDEX && len(xindex) >= 4*(i+1) {
			sym.Shndx = uint16(order.Uint32(xindex[4*i:]))
		}
		out.Entries = append(out.Entries, sym)
	}
	return out, nil
}

// writeSymtab encodes entries and rewrites the linked string table. Section
// indices in Shndx refer to f.Sections.
func (f *File) writeSymtab(sec *Section, entries []Symbol) error {
	order := f.Data.Order()
	names := make([]string, len(entries))
	for i := range entries {
		names[i] = entries[i].Name
	}
	linked := int(sec.Link) < len(f.Sections)
	var strtab []byte
	var offs []uint32
	if sec.Type == SHT_DYNSYM && linked && f.Sections[sec.Link].Type == SHT_STRTAB {
		// .dynstr is also referenced by .gnu.version* and .dynamic, so keep
		// the existing strings and offsets and only append new names.
		strtab, offs = appendStrtab(f.Sections[sec.Link].Data, names)
	} else {
		strtab, offs = buildStrtab(names)
	}
	ent := f.SymSize()
	buf := make([]byte, len(entries)*ent)
	for i, sym := range entries {
		b := buf[i*ent:]
		order.PutUint32(b[0:], offs[i])
		if f.Class == Class64 {
			b[4] = sym.Info
			b[5] = sym.Other
			order.PutUint16(b[6:], sym.Shndx)
			order.PutUint64(b[8:], sym.Value)
			order.PutUint64(b[16:], sym.Size)
		} else {
			order.PutUint32(b[4:], uint32(sym.Value))
			order.PutUint32(b[8:], uint32(sym.Size))
			b[12] = sym.Info
			b[13] = sym.Other
			order.PutUint16(b[14:], sym.Shndx)
		}
	}
	if sec.Link == 0 || int(sec.Link) >= len(f.Sections) || f.Sections[sec.Link].Type != SHT_STRTAB {
		return errf("symbol table %q has no string table", sec.Name)
	}
	sec.Data = buf
	sec.Size = uint64(len(buf))
	if sec.Type != SHT_DYNSYM {
		sec.Type = SHT_SYMTAB
	}
	sec.Entsize = uint64(ent)
	if sec.Addralign == 0 {
		sec.Addralign = 8
	}
	if linked {
		st := f.Sections[sec.Link]
		st.Data = strtab
		st.Size = uint64(len(strtab))
		st.Type = SHT_STRTAB
	}
	// sh_info is the index of the first non-local symbol.
	first := len(entries)
	for i, s := range entries {
		if s.Bind() != STB_LOCAL {
			first = i
			break
		}
	}
	sec.Info = uint32(first)
	return nil
}

// SetSymtab encodes st back into its section (and its string table).
func (f *File) SetSymtab(st *Symtab) error {
	return f.writeSymtab(st.Section, st.Entries)
}

// appendStrtab returns seed with any names not already present appended, along
// with each name's offset. Offsets of existing strings are preserved so that
// references into the table from other sections stay valid. seed must start
// with a NUL byte; otherwise a fresh table is built.
func appendStrtab(seed []byte, names []string) ([]byte, []uint32) {
	if len(seed) == 0 || seed[0] != 0 {
		return buildStrtab(names)
	}
	buf := append([]byte(nil), seed...)
	seen := map[string]uint32{"": 0}
	for off := 0; off < len(buf); {
		end := bytes.IndexByte(buf[off:], 0)
		if end < 0 {
			end = len(buf) - off
		}
		name := string(buf[off : off+end])
		if _, ok := seen[name]; !ok {
			seen[name] = uint32(off)
		}
		off += end + 1
	}
	if buf[len(buf)-1] != 0 {
		buf = append(buf, 0)
	}
	offs := make([]uint32, len(names))
	for i, name := range names {
		if off, ok := seen[name]; ok {
			offs[i] = off
			continue
		}
		off := uint32(len(buf))
		buf = append(buf, name...)
		buf = append(buf, 0)
		seen[name] = off
		offs[i] = off
	}
	return buf, offs
}

// buildStrtab builds a string table from the symbol names, sharing suffixes
// the way BFD's ELF string table does. Offset 0 is the empty string.
func buildStrtab(names []string) ([]byte, []uint32) {
	buf := make([]byte, 1)
	offs := make([]uint32, len(names))
	for i, name := range names {
		if name == "" {
			continue
		}
		needle := append([]byte(name), 0)
		if j := bytes.Index(buf, needle); j >= 0 {
			offs[i] = uint32(j)
			continue
		}
		offs[i] = uint32(len(buf))
		buf = append(buf, needle...)
	}
	return buf, offs
}

// Reloc is a decoded relocation entry.
type Reloc struct {
	Offset uint64
	Sym    uint32
	Type   uint32
	Addend int64
	// HasAddend is true for SHT_RELA sections.
	HasAddend bool
}

// RelSize returns the on-disk size of one relocation entry for sec.
func (f *File) RelSize(sec *Section) int {
	rel := 8
	if f.Class == Class64 {
		rel = 16
	}
	if sec.Type == SHT_RELA {
		rel += 4
		if f.Class == Class64 {
			rel += 4
		}
	}
	return rel
}

// ReadRelocs decodes a SHT_REL or SHT_RELA section.
func (f *File) ReadRelocs(sec *Section) ([]Reloc, error) {
	if sec.Type != SHT_REL && sec.Type != SHT_RELA {
		return nil, fmt.Errorf("elf: section %q is not a relocation section", sec.Name)
	}
	order := f.Data.Order()
	ent := f.RelSize(sec)
	if ent == 0 || len(sec.Data)%ent != 0 {
		return nil, fmt.Errorf("elf: reloc section %q has bad size %d", sec.Name, len(sec.Data))
	}
	n := len(sec.Data) / ent
	out := make([]Reloc, 0, n)
	for i := 0; i < n; i++ {
		b := sec.Data[i*ent:]
		r := Reloc{HasAddend: sec.Type == SHT_RELA}
		var info uint64
		if f.Class == Class64 {
			r.Offset = order.Uint64(b[0:])
			info = order.Uint64(b[8:])
			r.Sym = uint32(info >> 32)
			r.Type = uint32(info)
			if r.HasAddend {
				r.Addend = int64(order.Uint64(b[16:]))
			}
		} else {
			r.Offset = uint64(order.Uint32(b[0:]))
			info = uint64(order.Uint32(b[4:]))
			r.Sym = uint32(info >> 8)
			r.Type = uint32(info & 0xff)
			if r.HasAddend {
				r.Addend = int64(int32(order.Uint32(b[8:])))
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// SetRelocs encodes relocations back into sec.
func (f *File) SetRelocs(sec *Section, relocs []Reloc) error {
	order := f.Data.Order()
	ent := f.RelSize(sec)
	buf := make([]byte, len(relocs)*ent)
	for i, r := range relocs {
		b := buf[i*ent:]
		var info uint64
		if f.Class == Class64 {
			info = uint64(r.Sym)<<32 | uint64(r.Type)
			order.PutUint64(b[0:], r.Offset)
			order.PutUint64(b[8:], info)
			if sec.Type == SHT_RELA {
				order.PutUint64(b[16:], uint64(r.Addend))
			}
		} else {
			info = uint64(r.Sym)<<8 | uint64(r.Type&0xff)
			order.PutUint32(b[0:], uint32(r.Offset))
			order.PutUint32(b[4:], uint32(info))
			if sec.Type == SHT_RELA {
				order.PutUint32(b[8:], uint32(r.Addend))
			}
		}
	}
	sec.Data = buf
	sec.Size = uint64(len(buf))
	sec.Entsize = uint64(ent)
	if sec.Addralign == 0 {
		sec.Addralign = 4
	}
	return nil
}

// StringTable returns the contents of the SHT_STRTAB section at index i, or
// nil.
func (f *File) StringTable(i uint32) []byte {
	if int(i) >= len(f.Sections) {
		return nil
	}
	return f.Sections[i].Data
}

var _ = binary.LittleEndian
