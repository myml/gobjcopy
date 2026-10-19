package objcopy

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/bfdtarget"
)

// binarySymbolBase turns a file name into the GNU _binary_<name> form.
func binarySymbolBase(path string) string {
	base := filepath.Base(path)
	out := make([]byte, 0, len(base))
	for i := 0; i < len(base); i++ {
		c := base[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// binaryToELF builds the synthetic ELF object GNU objcopy produces for
// "-I binary".
func binaryToELF(data []byte, path string, cfg *Config, t *bfdtarget.Target) (*elf.File, error) {
	f := &elf.File{
		Header: elf.Header{
			Class:   t.Class,
			Data:    t.Data,
			Type:    elf.ET_REL,
			Machine: t.Machine,
			Version: elf.EV_CURRENT,
		},
		SectionHeadersPresent: true,
	}
	null := &elf.Section{}
	dataSec := &elf.Section{
		SectionHeader: elf.SectionHeader{
			Name:      ".data",
			Type:      elf.SHT_PROGBITS,
			Flags:     elf.SHF_ALLOC | elf.SHF_WRITE,
			Addralign: 1,
		},
		Data: data,
	}
	dataSec.Size = uint64(len(data))
	symSec := &elf.Section{SectionHeader: elf.SectionHeader{
		Name:      ".symtab",
		Type:      elf.SHT_SYMTAB,
		Addralign: 8,
		Entsize:   uint64(f.SymSize()),
		Link:      3,
		Info:      1,
	}}
	strSec := &elf.Section{SectionHeader: elf.SectionHeader{Name: ".strtab", Type: elf.SHT_STRTAB, Addralign: 1}}
	shstrSec := &elf.Section{SectionHeader: elf.SectionHeader{Name: ".shstrtab", Type: elf.SHT_STRTAB, Addralign: 1}}
	f.Sections = []*elf.Section{null, dataSec, symSec, strSec, shstrSec}
	f.Shstrndx = 4

	base := binarySymbolBase(path)
	const global = elf.STB_GLOBAL << 4
	syms := []elf.Symbol{
		{},
		{Name: "_binary_" + base + "_start", Info: global | elf.STT_NOTYPE, Shndx: 1},
		{Name: "_binary_" + base + "_end", Info: global | elf.STT_NOTYPE, Shndx: 1, Value: uint64(len(data))},
		{Name: "_binary_" + base + "_size", Info: global | elf.STT_NOTYPE, Shndx: elf.SHN_ABS, Value: uint64(len(data))},
	}
	if err := f.SetSymtab(&elf.Symtab{Section: symSec, Entries: syms}); err != nil {
		return nil, err
	}
	return f, nil
}

// sectionLMA returns the load address BFD would use for s.
func sectionLMA(f *elf.File, s *elf.Section) uint64 {
	if s.LMA != nil {
		return *s.LMA
	}
	for _, ph := range f.Segments {
		if ph.Type != elf.PT_LOAD || ph.Memsz == 0 {
			continue
		}
		if s.Addr >= ph.Vaddr && s.Addr < ph.Vaddr+ph.Memsz {
			return ph.Paddr + (s.Addr - ph.Vaddr)
		}
	}
	return s.Addr
}

func grow(buf []byte, n int, fill byte) []byte {
	if n <= len(buf) {
		return buf
	}
	if fill == 0 {
		return append(buf, make([]byte, n-len(buf))...)
	}
	return append(buf, bytes.Repeat([]byte{fill}, n-len(buf))...)
}

// ToBinary renders the file as a flat binary image, matching BFD's "binary"
// target: allocated sections with contents, laid out by LMA.
func ToBinary(f *elf.File, cfg *Config) ([]byte, error) {
	type item struct {
		sec *elf.Section
		lma uint64
	}
	var items []item
	var low uint64
	for _, s := range f.Sections {
		if !s.IsAlloc() || s.IsNoBits() || s.Size == 0 || len(s.Data) == 0 {
			continue
		}
		lma := sectionLMA(f, s)
		if len(items) == 0 || lma < low {
			low = lma
		}
		items = append(items, item{sec: s, lma: lma})
	}
	if len(items) == 0 {
		return nil, nil
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].lma < items[j].lma })

	var fill byte
	if cfg != nil && cfg.GapFill != nil {
		fill = byte(*cfg.GapFill)
	}
	var out []byte
	for _, it := range items {
		off := it.lma - low
		end := off + uint64(len(it.sec.Data))
		out = grow(out, int(end), fill)
		copy(out[off:], it.sec.Data)
	}
	if cfg != nil && cfg.PadTo != nil {
		if *cfg.PadTo > low {
			out = grow(out, int(*cfg.PadTo-low), fill)
		}
	}
	return out, nil
}

var _ = fmt.Sprintf
