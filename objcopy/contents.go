package objcopy

import (
	"fmt"

	"github.com/myml/gobjcopy/elf"
)

// applySectionContents implements --reverse-bytes and the --interleave family.
// GNU applies both in copy_section, i.e. to every section whose contents are
// copied, before --gap-fill/--pad-to enlarge the sections. applySectionStrip
// calls it at that point of the pipeline.
func (c *Config) applySectionContents(f *elf.File) error {
	if c.ReverseBytes == 0 && c.Interleave <= 0 {
		return nil
	}
	for _, s := range f.Sections {
		if !hasCopiedContents(s) {
			continue
		}
		if c.ReverseBytes > 0 {
			if len(s.Data)%c.ReverseBytes != 0 {
				return &FatalError{Msg: fmt.Sprintf(
					"cannot reverse bytes: length of section %s must be evenly divisible by %d",
					s.Name, c.ReverseBytes)}
			}
			reverseChunks(s.Data, c.ReverseBytes)
		}
		if c.Interleave > 0 && c.Byte >= 0 {
			c.interleaveSection(f, s)
		}
	}
	return nil
}

// hasCopiedContents reports whether GNU objcopy would copy this section's
// contents. Symbol and string tables are written by the ELF backend itself,
// and group sections are handled specially, so they are not transformed.
func hasCopiedContents(s *elf.Section) bool {
	switch s.Type {
	case elf.SHT_NULL, elf.SHT_SYMTAB, elf.SHT_DYNSYM, elf.SHT_STRTAB,
		elf.SHT_SYMTAB_SHNDX, elf.SHT_GROUP:
		return false
	}
	if s.IsNoBits() || len(s.Data) == 0 {
		return false
	}
	return true
}

// reverseChunks reverses the byte order of every size-byte chunk of data in
// place, which is how --reverse-bytes turns little endian data into big
// endian data.
func reverseChunks(data []byte, size int) {
	for i := 0; i+size <= len(data); i += size {
		for lo, hi := i, i+size-1; lo < hi; lo, hi = lo+1, hi-1 {
			data[lo], data[hi] = data[hi], data[lo]
		}
	}
}

// interleaveSection keeps --interleave-width bytes out of every
// --interleave bytes of the section, starting at --byte, exactly like the
// interleave branch of GNU's copy_section. The section shrinks and its load
// address is scaled by the interleave factor.
func (c *Config) interleaveSection(f *elf.File, s *elf.Section) {
	size := len(s.Data)
	// If the section address is not exactly divisible by the interleave, bias
	// the start: skip forward one block and bump the final load address.
	lma := sectionLMA(f, s)
	extra := int(lma % uint64(c.Interleave))
	from := c.Byte - extra
	if c.Byte < extra {
		from += c.Interleave
	}

	out := make([]byte, 0, size)
	for ; from < size; from += c.Interleave {
		for i := 0; i < c.InterleaveWidth; i++ {
			if from+i >= size {
				break
			}
			out = append(out, s.Data[from+i])
		}
	}

	newSize := (size + c.Interleave - 1 - c.Byte) / c.Interleave * c.InterleaveWidth
	if newSize < 0 {
		newSize = 0
	}
	// BFD writes newSize bytes out of the compacted buffer; anything past the
	// bytes actually produced keeps its old value.
	data := make([]byte, newSize)
	copy(data, out)
	for i := len(out); i < newSize && i < size; i++ {
		data[i] = s.Data[i]
	}
	s.Data = data
	s.Size = uint64(len(data))

	newLMA := lma / uint64(c.Interleave)
	if c.Byte < extra {
		newLMA++
	}
	s.LMA = &newLMA
}
