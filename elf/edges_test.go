package elf_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

func TestParseNonELF(t *testing.T) {
	t.Parallel()
	cases := map[string][]byte{
		"empty":          nil,
		"short":          []byte("ELF"),
		"text":           []byte("this is definitely not an ELF file"),
		"bad-magic":      append([]byte{0x7f, 'X', 'L', 'F'}, make([]byte, 60)...),
		"partial-magic":  []byte{0x7f, 'E', 'L'},
		"nul":            make([]byte, 64),
		"elf-but-short":  []byte{0x7f, 'E', 'L', 'F', 2, 1},
		"empty-with-bom": []byte("\xef\xbb\xbfnot an elf"),
	}
	for name, data := range cases {
		data := data
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := elf.Parse(data); !errors.Is(err, elf.ErrNotELF) {
				t.Errorf("Parse(%s) error = %v, want ErrNotELF", name, err)
			}
		})
	}
}

func TestParseInvalidIdent(t *testing.T) {
	t.Parallel()
	base := make([]byte, 64)
	copy(base, []byte{0x7f, 'E', 'L', 'F'})
	for _, tc := range []struct {
		name  string
		class byte
		data  byte
	}{
		{"bad-class", 0x99, 1},
		{"bad-data", 2, 0x99},
		{"class-zero", 0, 1},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := append([]byte(nil), base...)
			b[4] = tc.class
			b[5] = tc.data
			_, err := elf.Parse(b)
			if err == nil {
				t.Fatalf("Parse succeeded for %s", tc.name)
			}
			if errors.Is(err, elf.ErrNotELF) {
				t.Errorf("Parse error = ErrNotELF, want a malformed-ELF error")
			}
		})
	}
}

// TestParseTruncated feeds every prefix of an object file and a selection of
// executable prefixes to Parse. None may panic; all proper prefixes must fail.
func TestParseTruncated(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(fixture(t, "reloc.o"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	for n := 0; n < len(raw); n++ {
		if _, err := elf.Parse(raw[:n]); err == nil {
			t.Errorf("Parse of %d-byte prefix succeeded, want error", n)
		}
	}

	hello, err := os.ReadFile(fixture(t, "hello"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	f, err := elf.Parse(hello)
	if err != nil {
		t.Fatalf("parse hello: %v", err)
	}
	order := f.Data.Order()
	shoff := readHeaderU64(order, hello, 40)
	_, _, shnumOff, _ := elfHeaderOffsets(f)
	shnum := int(readHeaderU16(order, hello, shnumOff))
	points := []int{0, 1, 4, 15, 16, 63, 64, 65, int(shoff) - 1, int(shoff), int(shoff) + f.ShdrSize()*shnum/2, int(shoff) + f.ShdrSize()*shnum - 1, len(hello) - 1}
	for _, n := range points {
		if n < 0 || n >= len(hello) {
			continue
		}
		if _, err := elf.Parse(hello[:n]); err == nil {
			t.Errorf("Parse of %d-byte hello prefix succeeded, want error", n)
		}
	}
	if _, err := elf.Parse(hello); err != nil {
		t.Errorf("Parse of full hello failed: %v", err)
	}
}

// elfHeaderOffsets returns the byte offsets of e_shoff, e_shentsize, e_shnum
// and e_shstrndx for the file's class.
func elfHeaderOffsets(f *elf.File) (shoff, shentsize, shnum, shstr int) {
	if f.Class == elf.Class64 {
		return 40, 58, 60, 62
	}
	return 32, 46, 48, 50
}

func putHeader(t *testing.T, order binary.ByteOrder, b []byte, off int, v uint64, size int) {
	t.Helper()
	switch size {
	case 2:
		order.PutUint16(b[off:], uint16(v))
	case 4:
		order.PutUint32(b[off:], uint32(v))
	case 8:
		order.PutUint64(b[off:], v)
	default:
		t.Fatalf("bad putHeader size %d", size)
	}
}

// TestParseCorruptHeaders patches header fields to out-of-bounds or malformed
// values and requires a clean error, never a panic.
func TestParseCorruptHeaders(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(fixture(t, "hello"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	f, err := elf.Parse(raw)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	order := f.Data.Order()
	shoffOff, shentsizeOff, shnumOff, shstrOff := elfHeaderOffsets(f)
	shoff := readELFHeaderShoff(f.Class, order, raw)
	shsize := 8
	if f.Class == elf.Class32 {
		shsize = 4
	}
	shnum := readHeaderU16(order, raw, shnumOff)
	if int(shnum) >= len(f.Sections) {
		shnum = uint16(len(f.Sections))
	}

	put := func(b []byte, off int, v uint64, size int) {
		putHeader(t, order, b, off, v, size)
	}
	// Locate a PROGBITS section header to corrupt its file range.
	shdr := int(shoff)
	for i := 0; i < int(shnum); i++ {
		off := shdr + i*f.ShdrSize()
		if sectionField(f.Class, order, raw, off, "type") == elf.SHT_PROGBITS &&
			sectionField(f.Class, order, raw, off, "size") > 0 {
			shdr = off
			break
		}
	}

	cases := []struct {
		name   string
		mutate func(b []byte)
	}{
		{"shoff-past-eof", func(b []byte) { put(b, shoffOff, uint64(len(raw))+0x1000, shsize) }},
		{"shnum-huge", func(b []byte) { put(b, shnumOff, math.MaxUint16, 2) }},
		{"shentsize-too-small", func(b []byte) { put(b, shentsizeOff, 1, 2) }},
		{"phoff-past-eof", func(b []byte) {
			off := 32
			if f.Class == elf.Class32 {
				off = 28
			}
			put(b, off, uint64(len(raw))+1, shsize)
		}},
		{"phentsize-too-small", func(b []byte) {
			off := 54
			if f.Class == elf.Class32 {
				off = 42
			}
			put(b, off, 1, 2)
		}},
		{"section-content-out-of-bounds", func(b []byte) {
			if f.Class == elf.Class32 {
				put(b, shdr+16, uint64(len(raw)), 4) // sh_offset
			} else {
				put(b, shdr+24, uint64(len(raw)), 8) // sh_offset
			}
		}},
		{"section-index-out-of-range", func(b []byte) { put(b, shstrOff, 0x7fff, 2) }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := append([]byte(nil), raw...)
			tc.mutate(b)
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Parse panicked for %s: %v", tc.name, r)
					}
				}()
				_, err := elf.Parse(b)
				if tc.name == "section-index-out-of-range" {
					// An out-of-range e_shstrndx is tolerated; names are
					// simply unavailable.
					if err != nil {
						t.Errorf("Parse with out-of-range e_shstrndx failed: %v", err)
					}
					return
				}
				if err == nil {
					t.Errorf("Parse succeeded for corrupt input %s", tc.name)
				}
			}()
		})
	}
}

// TestExtendedSectionNumbering builds files with e_shnum == 0 (count in
// sh_size of section 0) and e_shstrndx == SHN_XINDEX.
func TestExtendedSectionNumbering(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	for _, fixtureName := range []string{"hello", "reloc32.o"} {
		fixtureName := fixtureName
		t.Run(fixtureName, func(t *testing.T) {
			t.Parallel()
			path := fixture(t, fixtureName)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			f, err := elf.Parse(raw)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			order := f.Data.Order()
			_, _, shnumOff, shstrOff := elfHeaderOffsets(f)
			shoff := readELFHeaderShoff(f.Class, order, raw)
			count := len(f.Sections)
			shstr := f.Shstrndx
			shsize := 8
			if f.Class == elf.Class32 {
				shsize = 4
			}
			sh0 := int(shoff)
			sizeField, linkField := sh0+32, sh0+40 // ELF64
			if f.Class == elf.Class32 {
				sizeField, linkField = sh0+20, sh0+24
			}

			t.Run("count-in-sh0", func(t *testing.T) {
				b := append([]byte(nil), raw...)
				putHeader(t, order, b, shnumOff, 0, 2)
				putHeader(t, order, b, sizeField, uint64(count), shsize)
				g, err := elf.Parse(b)
				if err != nil {
					t.Fatalf("Parse of e_shnum=0 file: %v", err)
				}
				if len(g.Sections) != count {
					t.Fatalf("extended numbering: %d sections, want %d", len(g.Sections), count)
				}
				if g.Shstrndx != shstr {
					t.Errorf("Shstrndx %d, want %d", g.Shstrndx, shstr)
				}
				for i, sec := range f.Sections {
					if g.Sections[i].Name != sec.Name {
						t.Errorf("section %d name %q, want %q", i, g.Sections[i].Name, sec.Name)
					}
				}
				outPath := writeELF(t, g, 0o644, "extended")
				assertReadelfParses(t, outPath)
				out, err := os.ReadFile(outPath)
				if err != nil {
					t.Fatal(err)
				}
				if got := readHeaderU16(order, out, shnumOff); got != uint16(count) {
					t.Errorf("output e_shnum = %d, want %d (writer should use normal numbering)", got, count)
				}
				if got := readHeaderU16(order, out, shstrOff); got != uint16(shstr) {
					t.Errorf("output e_shstrndx = %d, want %d", got, shstr)
				}
				outShoff := int(readELFHeaderShoff(g.Class, order, out))
				if got := sectionField(g.Class, order, out, outShoff, "size"); got != 0 {
					t.Errorf("output section 0 sh_size = %d, want 0 when e_shnum is literal", got)
				}
				h, err := elf.Parse(out)
				if err != nil {
					t.Fatalf("reparse output: %v", err)
				}
				if h.Sections[0].Size != 0 || h.Sections[0].Link != 0 {
					t.Errorf("section 0 extended fields not cleared: size=%d link=%d", h.Sections[0].Size, h.Sections[0].Link)
				}
				if len(h.Sections) != count {
					t.Errorf("reparsed section count %d, want %d", len(h.Sections), count)
				}
			})

			t.Run("shstrndx-xindex", func(t *testing.T) {
				b := append([]byte(nil), raw...)
				putHeader(t, order, b, shnumOff, 0, 2)
				putHeader(t, order, b, shstrOff, elf.SHN_XINDEX, 2)
				putHeader(t, order, b, sizeField, uint64(count), shsize)
				putHeader(t, order, b, linkField, uint64(shstr), shsize)
				g, err := elf.Parse(b)
				if err != nil {
					t.Fatalf("Parse of SHN_XINDEX file: %v", err)
				}
				if g.Shstrndx != shstr {
					t.Fatalf("Shstrndx %d, want %d", g.Shstrndx, shstr)
				}
				if len(g.Sections) != count {
					t.Fatalf("%d sections, want %d", len(g.Sections), count)
				}
				if name := g.Sections[1].Name; name == "" {
					t.Errorf("section 1 lost its name with SHN_XINDEX")
				}
				outPath := writeELF(t, g, 0o644, "extended-xindex")
				assertReadelfParses(t, outPath)
				out, err := os.ReadFile(outPath)
				if err != nil {
					t.Fatal(err)
				}
				h, err := elf.Parse(out)
				if err != nil {
					t.Fatalf("reparse output: %v", err)
				}
				if h.Shstrndx != shstr {
					t.Errorf("reparsed Shstrndx %d, want %d", h.Shstrndx, shstr)
				}
				if h.Sections[0].Link != 0 {
					t.Errorf("output section 0 sh_link = %d, want 0 when e_shstrndx is literal", h.Sections[0].Link)
				}
			})

			t.Run("count-too-large", func(t *testing.T) {
				b := append([]byte(nil), raw...)
				putHeader(t, order, b, shnumOff, 0, 2)
				putHeader(t, order, b, sizeField, uint64(len(raw))+1000, shsize)
				if _, err := elf.Parse(b); err == nil {
					t.Error("Parse succeeded with an out-of-bounds extended section count")
				}
			})
		})
	}
}

// TestNoSectionHeaders covers images without a section header table. Bytes
// must fall back to the original bytes.
func TestNoSectionHeaders(t *testing.T) {
	t.Parallel()
	name := "hello"
	path := fixture(t, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	check := func(t *testing.T, data []byte, label string) {
		t.Helper()
		f, err := elf.Parse(data)
		if err != nil {
			t.Fatalf("%s: Parse: %v", label, err)
		}
		if f.SectionHeadersPresent {
			t.Errorf("%s: SectionHeadersPresent = true, want false", label)
		}
		if len(f.Sections) != 0 {
			t.Errorf("%s: %d sections, want none", label, len(f.Sections))
		}
		out, err := f.Bytes()
		if err != nil {
			t.Fatalf("%s: Bytes on section-header-less file: %v", label, err)
		}
		if !bytes.Equal(out, data) {
			t.Errorf("%s: Bytes did not return the original image (%d vs %d bytes)", label, len(out), len(data))
		}
		dst := writeBytes(t, out, 0o755, "stripped")
		g, err := elf.Parse(out)
		if err != nil {
			t.Fatalf("%s: reparse: %v", label, err)
		}
		if g.SectionHeadersPresent {
			t.Errorf("%s: reparsed file claims section headers", label)
		}
		gotExit, gotOut := runBinary(t, dst)
		if gotExit != 0 {
			t.Errorf("%s: header-less executable exited %d, want 0 (output %q)", label, gotExit, gotOut)
		}
	}

	// Build a header-less image manually.
	manually := append([]byte(nil), raw...)
	f, err := elf.Parse(raw)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	order := f.Data.Order()
	shoffOff, shentsizeOff, shnumOff, shstrOff := elfHeaderOffsets(f)
	putHeader(t, order, manually, shoffOff, 0, 8)
	putHeader(t, order, manually, shentsizeOff, 0, 2)
	putHeader(t, order, manually, shnumOff, 0, 2)
	putHeader(t, order, manually, shstrOff, 0, 2)
	t.Run("manual", func(t *testing.T) {
		t.Parallel()
		check(t, manually, "manual header patch")
	})

	// Prefer the real "objcopy --strip-section-headers" output when the host
	// binutils support it.
	if objcopy, err := lookPath("objcopy"); err == nil {
		dst := writeBytes(t, raw, 0o755, "input")
		out := dst + ".nosections"
		if _, err := runTool(t, objcopy, "--strip-section-headers", dst, out); err == nil {
			b, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("read objcopy output: %v", err)
			}
			// The rewritten file may differ in the header only; compare what
			// Parse gives us and require the raw fallback to match exactly.
			t.Run("objcopy-strip-section-headers", func(t *testing.T) {
				t.Parallel()
				check(t, b, "objcopy --strip-section-headers")
			})
		}
	}
}

// TestBytesErrors covers serialisation of incomplete or inconsistent models.
func TestBytesErrors(t *testing.T) {
	t.Parallel()
	if _, err := (&elf.File{}).Bytes(); err == nil {
		t.Error("Bytes on zero File succeeded, want error")
	}
	if _, err := (&elf.File{SectionHeadersPresent: true}).Bytes(); err == nil {
		t.Error("Bytes on File without sections succeeded, want error")
	}
	f := openFixture(t, "reloc.o")
	f.Sections[0].Type = elf.SHT_PROGBITS
	if _, err := f.Bytes(); err == nil {
		t.Error("Bytes with non-SHT_NULL section 0 succeeded, want error")
	}

	f = openFixture(t, "reloc32.o")
	f.Entry = 1 << 32
	if _, err := f.Bytes(); err == nil {
		t.Error("Bytes with ELF32 entry point > uint32 succeeded, want error")
	}

	// An absurd section alignment must be rejected instead of triggering a
	// gigantic allocation (this is what the fuzzer found).
	f = &elf.File{
		Header:                elf.Header{Class: elf.Class64, Data: elf.DataLSB},
		SectionHeadersPresent: true,
		Shstrndx:              1,
		Sections: []*elf.Section{
			{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}},
			{SectionHeader: elf.SectionHeader{Name: ".shstrtab", Type: elf.SHT_STRTAB}},
			{
				SectionHeader: elf.SectionHeader{Name: ".huge", Type: elf.SHT_PROGBITS, Addralign: 1 << 40},
				Data:          []byte{1},
			},
		},
	}
	if _, err := f.Bytes(); err == nil {
		t.Error("Bytes with an astronomically aligned section succeeded, want error")
	}
}

func TestOpenMissingFile(t *testing.T) {
	t.Parallel()
	if _, err := elf.Open("/nonexistent/gobjcopy/no-such-file"); err == nil {
		t.Error("Open of a missing file succeeded, want error")
	}
}

// TestNoSectionHeadersOutput covers the writer's NoSectionHeaders mode: the
// output has no section header table, still runs, and reparses through the
// raw-image fallback.
func TestNoSectionHeadersOutput(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	name := "hello"
	path := fixture(t, name)
	wantExit, wantOut := runBinary(t, path)
	f := openFixture(t, name)
	f.NoSectionHeaders = true
	out := mustBytes(t, f)

	order := f.Data.Order()
	_, shentsizeOff, shnumOff, shstrOff := elfHeaderOffsets(f)
	if got := readELFHeaderShoff(f.Class, order, out); got != 0 {
		t.Errorf("%s: NoSectionHeaders output e_shoff = %#x, want 0", name, got)
	}
	if got := readHeaderU16(order, out, shentsizeOff); got != 0 {
		t.Errorf("%s: NoSectionHeaders output e_shentsize = %d, want 0", name, got)
	}
	if got := readHeaderU16(order, out, shnumOff); got != 0 {
		t.Errorf("%s: NoSectionHeaders output e_shnum = %d, want 0", name, got)
	}
	if got := readHeaderU16(order, out, shstrOff); got != 0 {
		t.Errorf("%s: NoSectionHeaders output e_shstrndx = %d, want 0", name, got)
	}

	dst := writeBytes(t, out, 0o755, name)
	assertReadelfParses(t, dst)
	g, err := elf.Parse(out)
	if err != nil {
		t.Fatalf("%s: Parse of header-less output: %v", name, err)
	}
	if g.SectionHeadersPresent {
		t.Errorf("%s: reparsed output claims to have section headers", name)
	}
	if len(g.Sections) != 0 {
		t.Errorf("%s: reparsed output has %d sections, want none", name, len(g.Sections))
	}
	again, err := g.Bytes()
	if err != nil {
		t.Fatalf("%s: Bytes on header-less output: %v", name, err)
	}
	if !bytes.Equal(again, out) {
		t.Errorf("%s: header-less Bytes fallback changed the image (%d vs %d bytes)", name, len(again), len(out))
	}
	gotExit, gotOut := runBinary(t, dst)
	if gotExit != wantExit || gotOut != wantOut {
		t.Errorf("%s: header-less executable: exit %d/%q, want %d/%q", name, gotExit, gotOut, wantExit, wantOut)
	}
}

// TestEmptyLoadAndNoBits exercises an added empty PT_LOAD and a SHT_NOBITS
// section. Neither may be encoded with assumptions about offsets or memsz.
// degenerateLoad reports whether f contains a zero-sized PT_LOAD.
func degenerateLoad(f *elf.File) bool {
	for _, ph := range f.Segments {
		if ph.Type == elf.PT_LOAD && ph.Memsz == 0 && ph.Filesz == 0 {
			return true
		}
	}
	return false
}

func TestEmptyLoadAndNoBits(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	name := "hello"
	orig := openFixture(t, name)

	f := openFixture(t, name)
	f.Segments = append(f.Segments, &elf.ProgramHeader{Type: elf.PT_LOAD})
	nobits := &elf.Section{SectionHeader: elf.SectionHeader{
		Name:      ".test_nobits",
		Type:      elf.SHT_NOBITS,
		Size:      0x100,
		Addralign: 1,
	}}
	if err := f.AddSection(nobits); err != nil {
		t.Fatalf("%s: AddSection(NOBITS): %v", name, err)
	}
	out := mustBytes(t, f)
	dst := writeBytes(t, out, 0o755, name)
	assertReadelfParses(t, dst)
	g, err := elf.Open(dst)
	if err != nil {
		t.Fatalf("%s: reparse: %v", name, err)
	}
	if got, want := len(g.Segments), len(orig.Segments)+1; got != want {
		t.Fatalf("%s: %d segments after adding an empty PT_LOAD, want %d", name, got, want)
	}
	last := g.Segments[len(g.Segments)-1]
	if last.Type != elf.PT_LOAD {
		t.Errorf("%s: last segment type %d, want PT_LOAD", name, last.Type)
	}
	if last.Filesz > 0 && last.Offset+last.Filesz > uint64(len(out)) {
		t.Errorf("%s: empty PT_LOAD became out of bounds: offset %#x filesz %#x, file %d bytes",
			name, last.Offset, last.Filesz, len(out))
	}
	nb := g.Section(".test_nobits")
	if nb == nil {
		t.Fatalf("%s: .test_nobits missing", name)
	}
	if nb.Type != elf.SHT_NOBITS || !nb.IsNoBits() || nb.Size != 0x100 || len(nb.Data) != 0 {
		t.Errorf("%s: .test_nobits header %+v, want SHT_NOBITS size 0x100 without data", name, nb.SectionHeader)
	}
	for _, sec := range orig.Sections {
		if sec.IsNoBits() || sec.Name == ".shstrtab" {
			// .shstrtab changes when a section is added.
			continue
		}
		got := g.Section(sec.Name)
		if got == nil {
			t.Errorf("%s: original section %q lost", name, sec.Name)
			continue
		}
		if !bytes.Equal(got.Data, sec.Data) {
			t.Errorf("%s: original section %q contents changed", name, sec.Name)
		}
	}
	// The synthetic zero-sized PT_LOAD at vaddr 0 cannot be described by a
	// consistent vaddr->offset mapping, so readelf's cross-section checks
	// (which resolve DT_* addresses through the program headers) cannot be
	// used here.  Section contents are compared above instead.
	if degenerateLoad(g) {
		t.Logf("%s: skipping readelf model cross-check for a file with a zero-sized PT_LOAD", name)
	} else {
		assertReadelfMatchesModel(t, dst, g)
	}
}
