package elf

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"sort"
)

// EhdrSize returns the size of the ELF header for the file's class.
func (f *File) EhdrSize() int {
	if f.Class == Class64 {
		return 64
	}
	return 52
}

// PhdrSize returns the size of one program header entry.
func (f *File) PhdrSize() int {
	if f.Class == Class64 {
		return 56
	}
	return 32
}

// ShdrSize returns the size of one section header entry.
func (f *File) ShdrSize() int {
	if f.Class == Class64 {
		return 64
	}
	return 40
}

// Bytes serialises the file, recomputing the section and segment layout.
func (f *File) Bytes() ([]byte, error) {
	if !f.SectionHeadersPresent {
		if len(f.raw) > 0 {
			return append([]byte(nil), f.raw...), nil
		}
		return nil, errf("input has no section headers; cannot rewrite")
	}
	if len(f.Sections) == 0 {
		return nil, errf("file has no sections")
	}
	if f.Sections[0].Type != SHT_NULL {
		return nil, errf("section 0 is not SHT_NULL")
	}
	if f.Class == Class32 {
		if f.Entry > math.MaxUint32 {
			return nil, errf("entry point 0x%x does not fit in ELF32", f.Entry)
		}
	}

	shstr := -1
	var nameData []byte
	var nameOffs []uint32
	if !f.NoSectionHeaders {
		shstr = f.ensureShstrtab()
		nameData, nameOffs = buildShstrtab(f.Sections, shstr)
		shstrSec := f.Sections[shstr]
		if shstrSec.Type != SHT_STRTAB {
			return nil, errf("section %d is not a string table", shstr)
		}
		shstrSec.Data = nameData
		shstrSec.Size = uint64(len(nameData))
		shstrSec.Addralign = 1
	}

	ehsize := uint64(f.EhdrSize())
	phsize := uint64(f.PhdrSize())
	phnum := len(f.Segments)
	phoff := uint64(0)
	if phnum > 0 {
		phoff = ehsize
	}
	headerEnd := ehsize + uint64(phnum)*phsize

	cursor := headerEnd
	placed := make([]bool, len(f.Sections))
	placed[0] = true
	f.Sections[0].Offset = 0

	// Lay out PT_LOAD contents first: those segments determine offsets of all
	// allocated, file-backed sections.
	loads := make([]*ProgramHeader, 0, len(f.Segments))
	for _, ph := range f.Segments {
		if ph.Type == PT_LOAD {
			loads = append(loads, ph)
		}
	}
	sort.SliceStable(loads, func(i, j int) bool { return loads[i].Vaddr < loads[j].Vaddr })

	for _, ph := range loads {
		if ph.Memsz == 0 {
			continue
		}
		idx := f.segmentSections(ph, placed)
		if len(idx) == 0 {
			if ph.Offset == 0 && headerEnd > ph.Vaddr {
				ph.Filesz = headerEnd - ph.Vaddr
				ph.Memsz = ph.Filesz
			} else {
				ph.Filesz = 0
				ph.Memsz = 0
			}
			continue
		}
		if ph.Offset == 0 {
			// The segment containing the ELF header keeps offset 0 so that
			// PT_PHDR and AT_PHDR remain valid; contents stay at their
			// original virtual-address deltas.
			end := headerEnd
			for _, i := range idx {
				sec := f.Sections[i]
				if sec.Addr < ph.Vaddr {
					continue
				}
				off := sec.Addr - ph.Vaddr
				if off < end {
					// Would overlap the ELF header, program headers or a
					// previously placed section; move it past them.
					align := sec.Addralign
					if align < 1 {
						align = 1
					}
					off = alignUp(end, align)
				}
				sec.Offset = off
				placed[i] = true
				if !sec.IsNoBits() {
					if e := off + sec.Size; e > end {
						end = e
					}
				}
			}
			ph.Offset = 0
			ph.Filesz = end
			if end > cursor {
				cursor = end
			}
			continue
		}
		align := ph.Align
		if align < 1 {
			align = 1
		}
		// Smallest offset at or after cursor that is congruent to the
		// segment's virtual address modulo its alignment.
		base := cursor
		if d := (ph.Vaddr - base) % align; d != 0 {
			base += d
		}
		end := base
		for _, i := range idx {
			sec := f.Sections[i]
			if sec.Addr < ph.Vaddr {
				continue
			}
			off := base + (sec.Addr - ph.Vaddr)
			if off < end {
				align := sec.Addralign
				if align < 1 {
					align = 1
				}
				off = alignUp(end, align)
			}
			sec.Offset = off
			placed[i] = true
			if !sec.IsNoBits() {
				if e := off + sec.Size; e > end {
					end = e
				}
			}
		}
		ph.Offset = base
		ph.Filesz = end - base
		cursor = end
	}

	// Everything else (non-allocated sections, and allocated sections that no
	// program header covers) follows.
	for i := 1; i < len(f.Sections); i++ {
		if placed[i] {
			continue
		}
		sec := f.Sections[i]
		align := sec.Addralign
		if align < 1 {
			align = 1
		}
		cursor = alignUp(cursor, align)
		sec.Offset = cursor
		placed[i] = true
		if !sec.IsNoBits() {
			cursor += sec.Size
		}
	}

	var shoff uint64
	shnum := len(f.Sections)
	total := cursor
	if !f.NoSectionHeaders {
		shoff = alignUp(cursor, uint64(f.align()))
		total = shoff + uint64(shnum)*uint64(f.ShdrSize())
	}

	f.updateSegments(phoff, headerEnd, phnum, phsize)

	if f.Class == Class32 {
		for _, sec := range f.Sections {
			if sec.Offset > math.MaxUint32 || sec.Size > math.MaxUint32 || sec.Addr > math.MaxUint32 {
				return nil, errf("section %q does not fit in ELF32", sec.Name)
			}
		}
		if total > math.MaxUint32 {
			return nil, errf("output too large for ELF32")
		}
	}
	// Refuse absurd layouts up front instead of trying to allocate them
	// (malformed input can make a single section offset astronomically large).
	const maxOutputSize = 1 << 32
	if total > maxOutputSize {
		return nil, errf("output too large (%d bytes)", total)
	}
	for _, sec := range f.Sections {
		if sec.Offset > maxOutputSize || sec.Size > maxOutputSize {
			return nil, errf("section %q has an out-of-range offset", sec.Name)
		}
	}

	buf := make([]byte, total)
	if f.NoSectionHeaders {
		f.writeHeader(buf, phoff, 0, uint16(phnum), 0, 0)
	} else {
		f.writeHeader(buf, phoff, shoff, uint16(phnum), shnum, shstr)
	}
	for i, ph := range f.Segments {
		f.writePhdr(buf[phoff+uint64(i)*phsize:], ph)
	}
	for i := 1; i < len(f.Sections); i++ {
		sec := f.Sections[i]
		if sec.IsNoBits() || len(sec.Data) == 0 {
			continue
		}
		copy(buf[sec.Offset:], sec.Data)
	}
	if !f.NoSectionHeaders {
		shdrBase := buf[shoff:]
		for i, sec := range f.Sections {
			f.writeShdr(shdrBase[uint64(i)*uint64(f.ShdrSize()):], sec, nameOffs[i], i, shnum, shstr)
		}
	}
	return buf, nil
}

func (f *File) align() int {
	if f.Class == Class64 {
		return 8
	}
	return 4
}

// segmentSections returns the indices of not-yet-placed allocated sections that
// belong to ph, ordered by virtual address.
func (f *File) segmentSections(ph *ProgramHeader, placed []bool) []int {
	var idx []int
	for i := 1; i < len(f.Sections); i++ {
		if placed[i] {
			continue
		}
		sec := f.Sections[i]
		if !sec.IsAlloc() {
			continue
		}
		if sec.Addr < ph.Vaddr {
			continue
		}
		if ph.Memsz != 0 && sec.Addr >= ph.Vaddr+ph.Memsz {
			continue
		}
		idx = append(idx, i)
	}
	sort.SliceStable(idx, func(a, b int) bool {
		sa, sb := f.Sections[idx[a]], f.Sections[idx[b]]
		if sa.Addr != sb.Addr {
			return sa.Addr < sb.Addr
		}
		return idx[a] < idx[b]
	})
	return idx
}

func (f *File) updateSegments(phoff, headerEnd uint64, phnum int, phsize uint64) {
	for _, ph := range f.Segments {
		switch ph.Type {
		case PT_LOAD:
			if ph.Memsz == 0 && ph.Filesz == 0 {
				// A degenerate program header that maps nothing; leave it
				// alone rather than growing it over the whole address space.
				continue
			}
			// Shrink the memory image to the sections that remain.
			origMemsz := ph.Memsz
			end := ph.Vaddr + ph.Filesz
			if ph.Offset == 0 && headerEnd > end {
				end = headerEnd
			}
			for _, sec := range f.Sections {
				if !sec.IsAlloc() || sec.Addr < ph.Vaddr {
					continue
				}
				if origMemsz != 0 && sec.Addr >= ph.Vaddr+origMemsz {
					continue
				}
				if e := sec.Addr + sec.Size; e > end {
					end = e
				}
			}
			if end > ph.Vaddr {
				ph.Memsz = end - ph.Vaddr
			}
		case PT_PHDR:
			ph.Offset = phoff
			ph.Filesz = uint64(phnum) * phsize
			ph.Memsz = ph.Filesz
		default:
			if off, ok := f.vaddrToOffset(ph.Vaddr); ok {
				ph.Offset = off
			}
		}
	}
}

func (f *File) vaddrToOffset(v uint64) (uint64, bool) {
	for _, sec := range f.Sections {
		if !sec.IsAlloc() || sec.IsNoBits() || sec.Size == 0 {
			continue
		}
		if v >= sec.Addr && v < sec.Addr+sec.Size {
			return sec.Offset + (v - sec.Addr), true
		}
	}
	for _, ph := range f.Segments {
		if ph.Type != PT_LOAD || ph.Filesz == 0 {
			continue
		}
		if v >= ph.Vaddr && v < ph.Vaddr+ph.Filesz {
			return ph.Offset + (v - ph.Vaddr), true
		}
	}
	return 0, false
}

func (f *File) ensureShstrtab() int {
	if f.Shstrndx > 0 && f.Shstrndx < len(f.Sections) && f.Sections[f.Shstrndx].Type == SHT_STRTAB {
		return f.Shstrndx
	}
	for i, s := range f.Sections {
		if s.Name == ".shstrtab" && s.Type == SHT_STRTAB {
			f.Shstrndx = i
			return i
		}
	}
	sec := &Section{SectionHeader: SectionHeader{
		Name:      ".shstrtab",
		Type:      SHT_STRTAB,
		Addralign: 1,
	}}
	f.Sections = append(f.Sections, sec)
	f.Shstrndx = len(f.Sections) - 1
	return f.Shstrndx
}

func (f *File) writeHeader(buf []byte, phoff, shoff uint64, phnum uint16, shnum, shstr int) {
	order := f.Data.Order()
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = byte(f.Class)
	buf[5] = byte(f.Data)
	buf[6] = byte(EV_CURRENT)
	buf[7] = f.OSABI
	buf[8] = f.ABIVersion
	for i := 9; i < 16; i++ {
		buf[i] = 0
	}
	order.PutUint16(buf[16:], f.Type)
	order.PutUint16(buf[18:], f.Machine)
	order.PutUint32(buf[20:], f.Version)
	shnumField := uint16(shnum)
	shstrField := uint16(shstr)
	if shnum >= SHN_LORESERVE {
		shnumField = 0
		f.Sections[0].Size = uint64(shnum)
	} else {
		// sh_size of the initial entry only carries the section count when
		// extended numbering is in use; clear any stale value from the input.
		f.Sections[0].Size = 0
	}
	if shstr >= SHN_LORESERVE {
		shstrField = SHN_XINDEX
		f.Sections[0].Link = uint32(shstr)
	} else {
		f.Sections[0].Link = 0
	}
	if f.Class == Class64 {
		order.PutUint64(buf[24:], f.Entry)
		order.PutUint64(buf[32:], phoff)
		order.PutUint64(buf[40:], shoff)
		order.PutUint32(buf[48:], f.Flags)
		order.PutUint16(buf[52:], uint16(f.EhdrSize()))
		phentsize := uint16(f.PhdrSize())
		if phnum == 0 {
			phentsize = 0
		}
		order.PutUint16(buf[54:], phentsize)
		order.PutUint16(buf[56:], phnum)
		shentsize := uint16(f.ShdrSize())
		if f.NoSectionHeaders {
			shentsize = 0
		}
		order.PutUint16(buf[58:], shentsize)
		order.PutUint16(buf[60:], shnumField)
		order.PutUint16(buf[62:], shstrField)
	} else {
		order.PutUint32(buf[24:], uint32(f.Entry))
		order.PutUint32(buf[28:], uint32(phoff))
		order.PutUint32(buf[32:], uint32(shoff))
		order.PutUint32(buf[36:], f.Flags)
		order.PutUint16(buf[40:], uint16(f.EhdrSize()))
		phentsize := uint16(f.PhdrSize())
		if phnum == 0 {
			phentsize = 0
		}
		order.PutUint16(buf[42:], phentsize)
		order.PutUint16(buf[44:], phnum)
		shentsize := uint16(f.ShdrSize())
		if f.NoSectionHeaders {
			shentsize = 0
		}
		order.PutUint16(buf[46:], shentsize)
		order.PutUint16(buf[48:], shnumField)
		order.PutUint16(buf[50:], shstrField)
	}
}

func (f *File) writePhdr(b []byte, ph *ProgramHeader) {
	order := f.Data.Order()
	if f.Class == Class64 {
		order.PutUint32(b[0:], ph.Type)
		order.PutUint32(b[4:], ph.Flags)
		order.PutUint64(b[8:], ph.Offset)
		order.PutUint64(b[16:], ph.Vaddr)
		order.PutUint64(b[24:], ph.Paddr)
		order.PutUint64(b[32:], ph.Filesz)
		order.PutUint64(b[40:], ph.Memsz)
		order.PutUint64(b[48:], ph.Align)
		return
	}
	order.PutUint32(b[0:], ph.Type)
	order.PutUint32(b[4:], uint32(ph.Offset))
	order.PutUint32(b[8:], uint32(ph.Vaddr))
	order.PutUint32(b[12:], uint32(ph.Paddr))
	order.PutUint32(b[16:], uint32(ph.Filesz))
	order.PutUint32(b[20:], uint32(ph.Memsz))
	order.PutUint32(b[24:], ph.Flags)
	order.PutUint32(b[28:], uint32(ph.Align))
}

func (f *File) writeShdr(b []byte, sec *Section, nameOff uint32, idx, shnum, shstr int) {
	order := f.Data.Order()
	order.PutUint32(b[0:], nameOff)
	order.PutUint32(b[4:], sec.Type)
	if f.Class == Class64 {
		order.PutUint64(b[8:], sec.Flags)
		order.PutUint64(b[16:], sec.Addr)
		order.PutUint64(b[24:], sec.Offset)
		order.PutUint64(b[32:], sec.Size)
		order.PutUint32(b[40:], sec.Link)
		order.PutUint32(b[44:], sec.Info)
		order.PutUint64(b[48:], sec.Addralign)
		order.PutUint64(b[56:], sec.Entsize)
	} else {
		order.PutUint32(b[8:], uint32(sec.Flags))
		order.PutUint32(b[12:], uint32(sec.Addr))
		order.PutUint32(b[16:], uint32(sec.Offset))
		order.PutUint32(b[20:], uint32(sec.Size))
		order.PutUint32(b[24:], sec.Link)
		order.PutUint32(b[28:], sec.Info)
		order.PutUint32(b[32:], uint32(sec.Addralign))
		order.PutUint32(b[36:], uint32(sec.Entsize))
	}
}

// WriteFile serialises f to path with the given permissions.
func (f *File) WriteFile(path string, perm os.FileMode) error {
	b, err := f.Bytes()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, perm)
}

func buildShstrtab(secs []*Section, shstr int) ([]byte, []uint32) {
	// BFD's ELF string table shares suffixes: a name that already occurs in
	// the table (ending at a NUL) is referenced in place. The .shstrtab name
	// itself is inserted first, matching BFD.
	buf := make([]byte, 1)
	offs := make([]uint32, len(secs))
	add := func(name string) uint32 {
		if name == "" {
			return 0
		}
		needle := append([]byte(name), 0)
		if i := bytes.Index(buf, needle); i >= 0 {
			return uint32(i)
		}
		off := uint32(len(buf))
		buf = append(buf, needle...)
		return off
	}
	if shstr >= 0 && shstr < len(secs) {
		add(secs[shstr].Name)
	}
	for i, s := range secs {
		offs[i] = add(s.Name)
	}
	return buf, offs
}

func alignUp(v, a uint64) uint64 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) / a * a
}

var _ = binary.LittleEndian
