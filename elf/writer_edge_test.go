package elf_test

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

// edgeBaseFile returns a minimal valid file with a section 0, .text and
// .shstrtab. The segment list is left to the caller.
func edgeBaseFile(class elf.Class) *elf.File {
	addr := uint64(0x1000)
	if class == elf.Class64 {
		addr = 0x401000
	}
	return &elf.File{
		Header: elf.Header{
			Class: class, Data: elf.DataLSB, Type: elf.ET_EXEC,
			Machine: elf.EM_X86_64, Version: elf.EV_CURRENT, Entry: addr,
		},
		SectionHeadersPresent: true,
		Shstrndx:              2,
		Sections: []*elf.Section{
			{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}},
			{
				SectionHeader: elf.SectionHeader{
					Name: ".text", Type: elf.SHT_PROGBITS,
					Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, Addr: addr,
					Addralign: 1,
				},
				Data: []byte{0x90, 0x90, 0x90, 0x90},
			},
			{SectionHeader: elf.SectionHeader{Name: ".shstrtab", Type: elf.SHT_STRTAB, Addralign: 1}},
		},
	}
}

func edgeBytes(t *testing.T, f *elf.File, context string) []byte {
	t.Helper()
	b, err := f.Bytes()
	if err != nil {
		t.Fatalf("%s: Bytes: %v", context, err)
	}
	return b
}

func edgeU16(t *testing.T, order binary.ByteOrder, b []byte, off int) uint16 {
	t.Helper()
	if len(b) < off+2 {
		t.Fatalf("output has %d bytes, cannot read uint16 at %d", len(b), off)
	}
	return order.Uint16(b[off:])
}

func edgeU32(t *testing.T, order binary.ByteOrder, b []byte, off int) uint32 {
	t.Helper()
	if len(b) < off+4 {
		t.Fatalf("output has %d bytes, cannot read uint32 at %d", len(b), off)
	}
	return order.Uint32(b[off:])
}

func edgeU64(t *testing.T, order binary.ByteOrder, b []byte, off int) uint64 {
	t.Helper()
	if len(b) < off+8 {
		t.Fatalf("output has %d bytes, cannot read uint64 at %d", len(b), off)
	}
	return order.Uint64(b[off:])
}

// TestWriterAlignmentAndEmptySegments covers the writer paths for zero
// alignment, overlapping virtual addresses, allocated sections outside every
// segment, and a LOAD segment that maps no section at all.
func TestWriterAlignmentAndEmptySegments(t *testing.T) {
	f := edgeBaseFile(elf.Class64)
	// Replace the base sections with the specific addresses this test needs.
	f.Sections = []*elf.Section{
		{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}}, // 0
		{
			SectionHeader: elf.SectionHeader{
				Name: ".text", Type: elf.SHT_PROGBITS,
				Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, Addr: 0x400000,
				Addralign: 0,
			},
			Data: []byte{1, 2, 3, 4},
		},
		{
			SectionHeader: elf.SectionHeader{
				Name: ".data", Type: elf.SHT_PROGBITS,
				Flags: elf.SHF_ALLOC | elf.SHF_WRITE, Addr: 0x400010,
				Addralign: 0,
			},
			Data: []byte{5, 6, 7, 8},
		},
		{
			SectionHeader: elf.SectionHeader{
				Name: ".overlap1", Type: elf.SHT_PROGBITS,
				Flags: elf.SHF_ALLOC, Addr: 0x700000, Size: 0x100,
				Addralign: 0,
			},
			Data: make([]byte, 0x100),
		},
		{
			SectionHeader: elf.SectionHeader{
				Name: ".overlap2", Type: elf.SHT_PROGBITS,
				Flags: elf.SHF_ALLOC, Addr: 0x700010, Size: 0x10,
				Addralign: 0,
			},
			Data: make([]byte, 0x10),
		},
		{
			SectionHeader: elf.SectionHeader{
				Name: ".low", Type: elf.SHT_PROGBITS,
				Flags: elf.SHF_ALLOC, Addr: 0x1000, Addralign: 0,
			},
			Data: []byte{9},
		},
		{
			SectionHeader: elf.SectionHeader{
				Name: ".plain", Type: elf.SHT_PROGBITS, Addralign: 0,
			},
			Data: []byte{10},
		},
		{SectionHeader: elf.SectionHeader{Name: ".shstrtab", Type: elf.SHT_STRTAB, Addralign: 1}},
	}
	f.Shstrndx = 7
	f.Segments = []*elf.ProgramHeader{
		{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Offset: 0, Vaddr: 0x400000, Memsz: 0x1000, Align: 0x1000},
		{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W, Offset: 0x200, Vaddr: 0x700000, Memsz: 0x1000, Align: 0},
		{Type: elf.PT_LOAD, Flags: elf.PF_R, Offset: 0x500, Vaddr: 0x800000, Memsz: 0x100, Align: 8},
		// Filesz without Memsz: Bytes skips it during layout, and
		// updateSegments must grow it from the header when Offset is zero.
		{Type: elf.PT_LOAD, Flags: elf.PF_R, Offset: 0, Vaddr: 0, Filesz: 0x10, Align: 4},
		{Type: elf.PT_PHDR, Flags: elf.PF_R, Vaddr: 0x34, Align: 8},
	}

	out := edgeBytes(t, f, "alignment")
	order := f.Data.Order()
	g, err := elf.Parse(out)
	if err != nil {
		t.Fatalf("Parse of serialised edge layout: %v", err)
	}
	if len(g.Segments) != len(f.Segments) {
		t.Fatalf("reparsed %d segments, want %d", len(g.Segments), len(f.Segments))
	}
	var foundEmpty bool
	for _, ph := range g.Segments {
		if ph.Type != elf.PT_LOAD || ph.Vaddr != 0x800000 {
			continue
		}
		foundEmpty = true
		if ph.Filesz != 0 || ph.Memsz != 0 {
			t.Errorf("empty LOAD at 0x800000 has filesz=%#x memsz=%#x, want 0/0", ph.Filesz, ph.Memsz)
		}
	}
	if !foundEmpty {
		t.Error("empty LOAD segment at 0x800000 was not preserved")
	}
	// The degenerate LOAD must have been normalised to a non-empty range.
	for _, ph := range g.Segments {
		if ph.Type == elf.PT_LOAD && ph.Vaddr == 0 {
			if ph.Filesz == 0 || ph.Memsz == 0 {
				t.Errorf("degenerate LOAD was not grown: filesz=%#x memsz=%#x", ph.Filesz, ph.Memsz)
			}
		}
	}
	// The file must remain parseable and its section headers reachable.
	if !g.SectionHeadersPresent {
		t.Error("reparsed output has no section headers")
	}
	if out[0] != 0x7f || string(out[1:4]) != "ELF" {
		t.Errorf("output does not start with ELF magic: % x", out[:4])
	}
	if got := edgeU16(t, order, out, 54); got != uint16(f.PhdrSize()) {
		t.Errorf("e_phentsize = %d, want %d", got, f.PhdrSize())
	}
}

// TestWriterExtendedSectionNumbering forces the extended shnum/shstrndx
// encoding in the writer. With 0xff01 sections both fields overflow their
// regular 16-bit representation.
func TestWriterExtendedSectionNumbering(t *testing.T) {
	const count = elf.SHN_LORESERVE + 1 // 0xff01 sections
	f := &elf.File{
		Header: elf.Header{
			Class: elf.Class64, Data: elf.DataLSB, Type: elf.ET_REL,
			Machine: elf.EM_X86_64, Version: elf.EV_CURRENT,
		},
		SectionHeadersPresent: true,
	}
	f.Sections = make([]*elf.Section, 0, count)
	f.Sections = append(f.Sections, &elf.Section{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}})
	for i := 1; i < count-1; i++ {
		f.Sections = append(f.Sections, &elf.Section{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}})
	}
	shstr := count - 1
	f.Sections = append(f.Sections, &elf.Section{SectionHeader: elf.SectionHeader{
		Name: ".shstrtab", Type: elf.SHT_STRTAB, Addralign: 1,
	}})
	f.Shstrndx = shstr

	out := edgeBytes(t, f, "extended numbering")
	order := f.Data.Order()
	shoff := edgeU64(t, order, out, 40)
	if got := edgeU16(t, order, out, 58); got != uint16(f.ShdrSize()) {
		t.Errorf("e_shentsize = %d, want %d", got, f.ShdrSize())
	}
	if got := edgeU16(t, order, out, 60); got != 0 {
		t.Errorf("e_shnum = %d, want 0 for extended numbering", got)
	}
	if got := edgeU16(t, order, out, 62); got != elf.SHN_XINDEX {
		t.Errorf("e_shstrndx = %#x, want SHN_XINDEX", got)
	}
	if got := edgeU64(t, order, out, int(shoff)+32); got != uint64(count) {
		t.Errorf("section 0 sh_size = %d, want %d", got, count)
	}
	if got := edgeU32(t, order, out, int(shoff)+40); got != uint32(shstr) {
		t.Errorf("section 0 sh_link = %d, want %d", got, shstr)
	}

	g, err := elf.Parse(out)
	if err != nil {
		t.Fatalf("Parse of extended-numbering output: %v", err)
	}
	if len(g.Sections) != count {
		t.Fatalf("reparsed %d sections, want %d", len(g.Sections), count)
	}
	if g.Shstrndx != shstr {
		t.Errorf("reparsed Shstrndx = %d, want %d", g.Shstrndx, shstr)
	}
	if len(g.Sections) > shstr && g.Sections[shstr].Name != ".shstrtab" {
		t.Errorf("reparsed shstrtab name = %q", g.Sections[shstr].Name)
	}
}

// TestWriterELF32HeaderAndProgramHeaders exercises the 32-bit e_phdr encoder
// and both 32-bit and 64-bit variants of parsePhdr.
func TestWriterELF32HeaderAndProgramHeaders(t *testing.T) {
	f := edgeBaseFile(elf.Class32)
	f.Segments = []*elf.ProgramHeader{{
		Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X,
		Offset: 0, Vaddr: 0x1000, Paddr: 0x1000,
		Filesz: 4, Memsz: 0x100, Align: 0x1000,
	}}

	out := edgeBytes(t, f, "elf32")
	order := f.Data.Order()
	if got := edgeU32(t, order, out, 28); got != 52 {
		t.Errorf("ELF32 e_phoff = %d, want 52", got)
	}
	if got := edgeU16(t, order, out, 42); got != 32 {
		t.Errorf("ELF32 e_phentsize = %d, want 32", got)
	}
	if got := edgeU16(t, order, out, 44); got != 1 {
		t.Errorf("ELF32 e_phnum = %d, want 1", got)
	}
	if got := edgeU16(t, order, out, 46); got != 40 {
		t.Errorf("ELF32 e_shentsize = %d, want 40", got)
	}
	g, err := elf.Parse(out)
	if err != nil {
		t.Fatalf("Parse of ELF32 output: %v", err)
	}
	if g.Class != elf.Class32 {
		t.Fatalf("reparsed class = %v, want ELF32", g.Class)
	}
	if len(g.Segments) != 1 {
		t.Fatalf("reparsed %d segments, want 1", len(g.Segments))
	}
	ph := g.Segments[0]
	if ph.Type != elf.PT_LOAD || ph.Flags != elf.PF_R|elf.PF_X {
		t.Errorf("ELF32 program header type/flags = %d/%#x", ph.Type, ph.Flags)
	}
	if ph.Vaddr != 0x1000 || ph.Align != 0x1000 || ph.Filesz == 0 || ph.Memsz == 0 {
		t.Errorf("ELF32 program header = %+v", ph)
	}

	// The same file without section headers hits the 32-bit shentsize=0
	// branch in writeHeader.
	f.NoSectionHeaders = true
	out = edgeBytes(t, f, "elf32-no-sections")
	if got := edgeU32(t, order, out, 28); got != 52 {
		t.Errorf("header-less ELF32 e_phoff = %d, want 52", got)
	}
	if got := edgeU16(t, order, out, 46); got != 0 {
		t.Errorf("header-less ELF32 e_shentsize = %d, want 0", got)
	}
	if got := edgeU16(t, order, out, 48); got != 0 {
		t.Errorf("header-less ELF32 e_shnum = %d, want 0", got)
	}
	if got := edgeU16(t, order, out, 50); got != 0 {
		t.Errorf("header-less ELF32 e_shstrndx = %d, want 0", got)
	}
	if _, err := elf.Parse(out); err != nil {
		t.Fatalf("Parse of header-less ELF32 output: %v", err)
	}
}

// TestWriterErrorBoundaries covers the remaining size/offset guards.
func TestWriterErrorBoundaries(t *testing.T) {
	t.Run("elf32-section-size", func(t *testing.T) {
		f := edgeBaseFile(elf.Class32)
		f.Sections = append(f.Sections, &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".huge", Type: elf.SHT_NOBITS, Size: 1 << 32, Addralign: 1,
		}})
		if _, err := f.Bytes(); err == nil {
			t.Error("Bytes accepted an ELF32 section larger than uint32")
		}
	})

	t.Run("elf32-total", func(t *testing.T) {
		f := edgeBaseFile(elf.Class32)
		f.Sections = append(f.Sections, &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".huge", Type: elf.SHT_NOBITS, Size: math.MaxUint32, Addralign: 1,
		}})
		// NOBITS contributes no bytes, so use a file-backed section just
		// below the uint32 per-section limit to overflow the total.
		f.Sections[len(f.Sections)-1].Type = elf.SHT_PROGBITS
		if _, err := f.Bytes(); err == nil {
			t.Error("Bytes accepted an ELF32 output larger than uint32")
		}
	})

	t.Run("out-of-range-section", func(t *testing.T) {
		f := edgeBaseFile(elf.Class64)
		f.NoSectionHeaders = true
		f.Sections = append(f.Sections, &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".huge", Type: elf.SHT_NOBITS, Size: 1<<32 + 1, Addralign: 1,
		}})
		if _, err := f.Bytes(); err == nil {
			t.Error("Bytes accepted a section with an out-of-range size")
		}
	})

	t.Run("ensure-shstrtab-existing", func(t *testing.T) {
		f := edgeBaseFile(elf.Class64)
		f.Shstrndx = 0 // invalid; ensureShstrtab must find .shstrtab by name
		if _, err := f.Bytes(); err != nil {
			t.Fatalf("Bytes: %v", err)
		}
		if f.Shstrndx != 2 {
			t.Errorf("ensureShstrtab found index %d, want 2", f.Shstrndx)
		}
	})

	t.Run("open-non-elf", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "not-elf")
		if err := os.WriteFile(p, []byte("not an elf file"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := elf.Open(p); err == nil {
			t.Error("Open accepted a non-ELF file")
		}
	})
}

func TestWriteFile(t *testing.T) {
	f := edgeBaseFile(elf.Class64)
	path := filepath.Join(t.TempDir(), "out.o")
	if err := f.WriteFile(path, 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() == 0 {
		t.Error("WriteFile produced a file with no permission bits")
	}
	g, err := elf.Open(path)
	if err != nil {
		t.Fatalf("Open of WriteFile output: %v", err)
	}
	if len(g.Sections) == 0 {
		t.Error("WriteFile output has no sections")
	}

	var bad elf.File
	if err := bad.WriteFile(filepath.Join(t.TempDir(), "bad.o"), 0o644); err == nil {
		t.Error("WriteFile on an invalid file succeeded, want error")
	}
}
