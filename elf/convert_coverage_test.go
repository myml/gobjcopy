package elf

// Coverage-focused tests for convert.go.  These live in package elf so that
// the individual decoders and the bounds checker can be exercised directly,
// including their malformed-input branches.  Real fixtures cover the ordinary
// round-trip path.

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/myml/gobjcopy/internal/fixtures"
)

// ---- fixture plumbing ----------------------------------------------------

var (
	cvFixtureOnce sync.Once
	cvFixtureMap  map[string]string
	cvFixtureErr  error
)

func cvFixturePath(t *testing.T, name string) string {
	t.Helper()
	cvFixtureOnce.Do(func() {
		dir, err := os.MkdirTemp("", "elf-conv-coverage-")
		if err != nil {
			cvFixtureErr = err
			return
		}
		cvFixtureMap, cvFixtureErr = fixtures.Build(dir)
	})
	if cvFixtureErr != nil {
		t.Skipf("fixtures unavailable: %v", cvFixtureErr)
	}
	p, ok := cvFixtureMap[name]
	if !ok {
		t.Skipf("fixture %q was not built on this host", name)
	}
	return p
}

func cvOpenFixture(t *testing.T, name string) *File {
	t.Helper()
	f, err := Open(cvFixturePath(t, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

// ---- synthetic model helpers --------------------------------------------

func cvNewFile(class Class, typ uint16) *File {
	return &File{
		Header: Header{
			Class: class, Data: DataLSB, Type: typ,
			Machine: EM_X86_64, Version: EV_CURRENT,
		},
		SectionHeadersPresent: true,
		Sections:              []*Section{{SectionHeader: SectionHeader{Type: SHT_NULL}}},
	}
}

func cvAdd(f *File, name string, typ uint32, data []byte) *Section {
	s := &Section{
		SectionHeader: SectionHeader{Name: name, Type: typ, Addralign: 1},
		Data:          data,
	}
	if data != nil {
		s.Size = uint64(len(data))
	}
	f.Sections = append(f.Sections, s)
	return s
}

// cvPropEntry returns a 4-byte property entry padded to align bytes.
func cvPropEntry(order binary.ByteOrder, align int, typ, val uint32) []byte {
	b := make([]byte, alignInt(8+4, align))
	order.PutUint32(b[0:], typ)
	order.PutUint32(b[4:], 4)
	order.PutUint32(b[8:], val)
	return b
}

// cvNote builds one NT_GNU_PROPERTY_TYPE_0 note from pre-encoded entries.
func cvNote(order binary.ByteOrder, align int, entries ...[]byte) []byte {
	var desc []byte
	for _, e := range entries {
		desc = append(desc, e...)
	}
	b := make([]byte, 16)
	order.PutUint32(b[0:], 4)
	order.PutUint32(b[4:], uint32(len(desc)))
	order.PutUint32(b[8:], gnuPropertyType0)
	copy(b[12:16], "GNU\x00")
	return append(b, desc...)
}

// cvParseProps decodes the single note produced by encodePropertyNote.
func cvParseProps(t *testing.T, data []byte, align int, order binary.ByteOrder) []gnuProperty {
	t.Helper()
	if len(data) < 16 {
		t.Fatalf("note too short: %d", len(data))
	}
	descsz := int(order.Uint32(data[4:]))
	if descsz > len(data)-16 {
		t.Fatalf("descsz %d > %d", descsz, len(data)-16)
	}
	props, ok := parsePropertyList(data[16:16+descsz], align, order)
	if !ok {
		t.Fatalf("parsePropertyList failed for %x", data)
	}
	return props
}

func cvPropValues(props []gnuProperty, order binary.ByteOrder) map[uint32]uint64 {
	out := map[uint32]uint64{}
	for _, p := range props {
		switch len(p.data) {
		case 4:
			out[p.typ] = uint64(order.Uint32(p.data))
		case 8:
			out[p.typ] = order.Uint64(p.data)
		default:
			out[p.typ] = 0
		}
	}
	return out
}

// ---- guards --------------------------------------------------------------

func TestConvertCoverageGuards(t *testing.T) {
	if err := ConvertClass(nil, Class32); err == nil {
		t.Fatal("ConvertClass(nil) = nil error")
	}
	f := cvNewFile(Class64, ET_REL)
	if err := ConvertClass(f, Class(9)); err == nil {
		t.Fatal("invalid class accepted")
	}
	if err := f.ConvertClass(Class64); err != nil {
		t.Fatalf("same-class conversion: %v", err)
	}
	noSections := cvNewFile(Class64, ET_REL)
	noSections.SectionHeadersPresent = false
	if err := noSections.ConvertClass(Class32); err == nil {
		t.Fatal("conversion without section headers accepted")
	}
	exec := cvNewFile(Class64, ET_EXEC)
	if err := exec.ConvertClass(Class32); err == nil {
		t.Fatal("ET_EXEC conversion accepted")
	}
	large := cvNewFile(Class64, ET_REL)
	cvAdd(large, ".data", SHT_PROGBITS, []byte{1}).Flags |= SHF_X86_64_LARGE
	err := large.ConvertClass(Class32)
	if err == nil || !strings.Contains(err.Error(), "'large' flag is ELF x86-64 specific") {
		t.Fatalf("large flag error = %v", err)
	}
	if err := large.ConvertClass(Class64); err != nil {
		t.Fatalf("same-class large conversion: %v", err)
	}

	// Minimal file: no tables at all, both directions.
	minimal := cvNewFile(Class64, ET_REL)
	if err := minimal.ConvertClass(Class32); err != nil {
		t.Fatalf("minimal 64->32: %v", err)
	}
	if err := minimal.ConvertClass(Class64); err != nil {
		t.Fatalf("minimal 32->64: %v", err)
	}
}

// ---- real fixtures -------------------------------------------------------

func cvReadTables(t *testing.T, f *File) (map[string][]Symbol, map[string][]Reloc) {
	t.Helper()
	syms := map[string][]Symbol{}
	for _, s := range f.Sections {
		if s.Type != SHT_SYMTAB && s.Type != SHT_DYNSYM {
			continue
		}
		st, err := f.ReadSymtab(s)
		if err != nil {
			t.Fatalf("read %s: %v", s.Name, err)
		}
		syms[s.Name] = st.Entries
	}
	rels := map[string][]Reloc{}
	for _, s := range f.Sections {
		if s.Type != SHT_REL && s.Type != SHT_RELA {
			continue
		}
		rs, err := f.ReadRelocs(s)
		if err != nil {
			t.Fatalf("read %s: %v", s.Name, err)
		}
		rels[s.Name] = rs
	}
	return syms, rels
}

func cvRequireTables(t *testing.T, f *File, wantSyms map[string][]Symbol, wantRels map[string][]Reloc) {
	t.Helper()
	gotSyms, gotRels := cvReadTables(t, f)
	if !reflect.DeepEqual(gotSyms, wantSyms) {
		t.Errorf("symbol tables changed:\n got %+v\nwant %+v", gotSyms, wantSyms)
	}
	if !reflect.DeepEqual(gotRels, wantRels) {
		t.Errorf("relocation tables changed:\n got %+v\nwant %+v", gotRels, wantRels)
	}
}

func TestConvertCoverageFixtureRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		to   Class
	}{
		{"reloc.o", Class32},
		{"reloc32.o", Class64},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := cvOpenFixture(t, tc.name)
			wantSyms, wantRels := cvReadTables(t, f)
			origClass := f.Class
			if err := f.ConvertClass(tc.to); err != nil {
				t.Fatalf("convert to %v: %v", tc.to, err)
			}
			if f.Class != tc.to {
				t.Fatalf("class = %v, want %v", f.Class, tc.to)
			}
			cvRequireTables(t, f, wantSyms, wantRels)
			if err := f.ConvertClass(origClass); err != nil {
				t.Fatalf("convert back to %v: %v", origClass, err)
			}
			cvRequireTables(t, f, wantSyms, wantRels)
			// The model must still serialise and reparse.
			b, err := f.Bytes()
			if err != nil {
				t.Fatalf("Bytes: %v", err)
			}
			if _, err := Parse(b); err != nil {
				t.Fatalf("Parse: %v", err)
			}
		})
	}
}

func TestConvertCoverageFixtureTables(t *testing.T) {
	// reloc.o has a symbol table and RELA sections; exercise switching the
	// static table to a dynamic one as well.
	f := cvOpenFixture(t, "reloc.o")
	for _, s := range f.Sections {
		if s.Type == SHT_SYMTAB {
			s.Type = SHT_DYNSYM
		}
	}
	wantSyms, wantRels := cvReadTables(t, f)
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("convert dynsym to ELF32: %v", err)
	}
	cvRequireTables(t, f, wantSyms, wantRels)
	if err := f.ConvertClass(Class64); err != nil {
		t.Fatalf("convert dynsym back: %v", err)
	}
	cvRequireTables(t, f, wantSyms, wantRels)
}

// ---- malformed symtab/reloc tables --------------------------------------

func TestConvertCoverageTableErrors(t *testing.T) {
	// A symbol table whose size is not a multiple of the entry size.
	f := cvNewFile(Class64, ET_REL)
	cvAdd(f, ".symtab", SHT_SYMTAB, make([]byte, 5))
	if err := f.ConvertClass(Class32); err == nil {
		t.Fatal("bad symtab accepted")
	}

	// A well formed symbol table without a string table: decoding works,
	// re-encoding fails after the class has changed.
	f = cvNewFile(Class64, ET_REL)
	sym := cvAdd(f, ".symtab", SHT_SYMTAB, make([]byte, 24))
	sym.Link = 0
	if err := f.ConvertClass(Class32); err == nil {
		t.Fatal("symtab without strtab accepted")
	}

	// Empty symbol table with a valid string table.
	f = cvNewFile(Class64, ET_REL)
	str := cvAdd(f, ".strtab", SHT_STRTAB, []byte{0})
	sym = cvAdd(f, ".symtab", SHT_SYMTAB, nil)
	sym.Link = uint32(f.SectionIndex(str))
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("empty symtab: %v", err)
	}
	if len(sym.Data) != 0 || sym.Entsize != 16 {
		t.Fatalf("empty symtab after convert: len=%d entsize=%d", len(sym.Data), sym.Entsize)
	}

	// Relocation section with a bad size.
	f = cvNewFile(Class64, ET_REL)
	rel := cvAdd(f, ".rela.text", SHT_RELA, make([]byte, 10))
	rel.Link = 0
	if err := f.ConvertClass(Class32); err == nil {
		t.Fatal("bad rela size accepted")
	}
	f = cvNewFile(Class64, ET_REL)
	rel = cvAdd(f, ".rel.text", SHT_REL, make([]byte, 9))
	rel.Link = 0
	if err := f.ConvertClass(Class32); err == nil {
		t.Fatal("bad rel size accepted")
	}

	// Empty relocation section.
	f = cvNewFile(Class64, ET_REL)
	rel = cvAdd(f, ".rela.text", SHT_RELA, nil)
	rel.Link = 0
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("empty rela: %v", err)
	}
	if rel.Entsize != 12 {
		t.Fatalf("empty rela entsize = %d", rel.Entsize)
	}
}

// ---- SHF_COMPRESSED ------------------------------------------------------

func cvCompressedSection(t *testing.T, f *File, class Class, name string, payload []byte, size, align uint64) *Section {
	t.Helper()
	order := f.Data.Order()
	hdr := 12
	if class == Class64 {
		hdr = 24
	}
	data := make([]byte, hdr+len(payload))
	order.PutUint32(data[0:], 1) // ELFCOMPRESS_ZLIB
	if class == Class64 {
		order.PutUint64(data[8:], size)
		order.PutUint64(data[16:], align)
	} else {
		order.PutUint32(data[4:], uint32(size))
		order.PutUint32(data[8:], uint32(align))
	}
	copy(data[hdr:], payload)
	sec := cvAdd(f, name, SHT_PROGBITS, data)
	sec.Flags |= SHF_COMPRESSED
	return sec
}

func TestConvertCoverageCompressed(t *testing.T) {
	payload := []byte{0x78, 0x9c, 1, 2, 3, 4}
	order := DataLSB.Order()

	f := cvNewFile(Class64, ET_REL)
	sec := cvCompressedSection(t, f, Class64, ".debug_info", payload, 1234, 8)
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("64->32 compressed: %v", err)
	}
	if len(sec.Data) != 12+len(payload) || sec.Size != uint64(12+len(payload)) {
		t.Fatalf("32-bit compressed size = %d/%d", len(sec.Data), sec.Size)
	}
	if got := order.Uint32(sec.Data[0:]); got != 1 {
		t.Errorf("ch_type = %#x", got)
	}
	if got := order.Uint32(sec.Data[4:]); got != 1234 {
		t.Errorf("ch_size = %d", got)
	}
	if got := order.Uint32(sec.Data[8:]); got != 8 {
		t.Errorf("ch_addralign = %d", got)
	}
	if !bytes.Equal(sec.Data[12:], payload) {
		t.Errorf("payload changed: %x", sec.Data[12:])
	}
	if err := f.ConvertClass(Class64); err != nil {
		t.Fatalf("32->64 compressed: %v", err)
	}
	if len(sec.Data) != 24+len(payload) {
		t.Fatalf("64-bit compressed size = %d", len(sec.Data))
	}
	if got := order.Uint64(sec.Data[8:]); got != 1234 {
		t.Errorf("ch_size = %d", got)
	}

	// A compressed section that is empty is left alone.
	f = cvNewFile(Class64, ET_REL)
	empty := cvAdd(f, ".debug_empty", SHT_PROGBITS, nil)
	empty.Flags |= SHF_COMPRESSED
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("empty compressed section: %v", err)
	}
	if len(empty.Data) != 0 || empty.Flags&SHF_COMPRESSED == 0 {
		t.Errorf("empty compressed section modified: %+v", empty.SectionHeader)
	}

	// A compressed NOBITS section is left alone too.
	f = cvNewFile(Class64, ET_REL)
	nobits := cvAdd(f, ".debug_nobits", SHT_NOBITS, []byte{1, 2, 3})
	nobits.Flags |= SHF_COMPRESSED
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("compressed NOBITS: %v", err)
	}

	// A truncated header reaching ConvertClass (not just decodeCompressed).
	for _, class := range []Class{Class64, Class32} {
		to := Class32
		if class == Class32 {
			to = Class64
		}
		f = cvNewFile(class, ET_REL)
		bad := cvAdd(f, ".debug_bad", SHT_PROGBITS, make([]byte, 8))
		bad.Flags |= SHF_COMPRESSED
		if err := f.ConvertClass(to); err == nil {
			t.Errorf("%v->%v accepted a truncated compressed header", class, to)
		}
	}

	// Truncated headers for both classes.
	if _, err := decodeCompressed(&Section{SectionHeader: SectionHeader{Name: ".x"}}, Class64, order); err == nil {
		t.Error("truncated 64-bit chdr accepted")
	}
	if _, err := decodeCompressed(&Section{SectionHeader: SectionHeader{Name: ".x"}}, Class32, order); err == nil {
		t.Error("truncated 32-bit chdr accepted")
	}

	// Fields that do not fit in ELF32.
	f = cvNewFile(Class64, ET_REL)
	cvCompressedSection(t, f, Class64, ".debug_big", payload, 1<<32, 8)
	if err := f.ConvertClass(Class32); err == nil {
		t.Error("large ch_size accepted")
	}
	f = cvNewFile(Class64, ET_REL)
	cvCompressedSection(t, f, Class64, ".debug_align", payload, 16, 1<<32)
	if err := f.ConvertClass(Class32); err == nil {
		t.Error("large ch_addralign accepted")
	}
}

// ---- SHT_DYNAMIC and SHT_DYNSYM -----------------------------------------

func cvDynamicSection(t *testing.T, f *File, class Class, entries []dynamicEntry) *Section {
	t.Helper()
	order := f.Data.Order()
	sec := cvAdd(f, ".dynamic", SHT_DYNAMIC, nil)
	encodeDynamic(sec, entries, class, order)
	return sec
}

func cvDynsymSection(t *testing.T, f *File, class Class, str *Section) *Section {
	t.Helper()
	order := f.Data.Order()
	ent := 16
	if class == Class64 {
		ent = 24
	}
	data := make([]byte, 2*ent)
	// Entry 1: name offset 1 ("foo"), global function at section 1.
	if class == Class64 {
		order.PutUint32(data[ent:], 1)
		data[ent+4] = STB_GLOBAL<<4 | STT_FUNC
		data[ent+5] = 0
		order.PutUint16(data[ent+6:], 1)
		order.PutUint64(data[ent+8:], 0x100)
		order.PutUint64(data[ent+16:], 0x20)
	} else {
		order.PutUint32(data[ent:], 1)
		order.PutUint32(data[ent+4:], 0x100)
		order.PutUint32(data[ent+8:], 0x20)
		data[ent+12] = STB_GLOBAL<<4 | STT_FUNC
		data[ent+13] = 0
		order.PutUint16(data[ent+14:], 1)
	}
	sec := cvAdd(f, ".dynsym", SHT_DYNSYM, data)
	sec.Link = uint32(f.SectionIndex(str))
	sec.Addralign = 8
	return sec
}

func TestConvertCoverageDynamic(t *testing.T) {
	order := DataLSB.Order()
	strData := []byte("\x00foo\x00bar\x00")
	entries := []dynamicEntry{{tag: 1, val: 0x10}, {tag: 0, val: 0}}

	f := cvNewFile(Class64, ET_REL)
	cvAdd(f, ".text", SHT_PROGBITS, []byte{0x90})
	str := cvAdd(f, ".dynstr", SHT_STRTAB, append([]byte(nil), strData...))
	dynsym := cvDynsymSection(t, f, Class64, str)
	dyn := cvDynamicSection(t, f, Class64, entries)

	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(dyn.Data) != 2*8 || dyn.Entsize != 8 {
		t.Errorf("32-bit dynamic: len=%d entsize=%d", len(dyn.Data), dyn.Entsize)
	}
	got, err := decodeDynamic(dyn, Class32, order)
	if err != nil || !reflect.DeepEqual(got, entries) {
		t.Errorf("decoded dynamic = %+v, %v", got, err)
	}
	if len(dynsym.Data) != 2*16 || dynsym.Entsize != 16 {
		t.Errorf("32-bit dynsym: len=%d entsize=%d", len(dynsym.Data), dynsym.Entsize)
	}
	st, err := f.ReadSymtab(dynsym)
	if err != nil {
		t.Fatalf("read converted dynsym: %v", err)
	}
	if len(st.Entries) != 2 || st.Entries[1].Name != "foo" ||
		st.Entries[1].Value != 0x100 || st.Entries[1].Size != 0x20 ||
		st.Entries[1].Bind() != STB_GLOBAL || st.Entries[1].Type() != STT_FUNC {
		t.Errorf("converted dynsym entries: %+v", st.Entries)
	}

	if err := f.ConvertClass(Class64); err != nil {
		t.Fatalf("convert back: %v", err)
	}
	if len(dyn.Data) != 2*16 || dyn.Entsize != 16 {
		t.Errorf("64-bit dynamic: len=%d entsize=%d", len(dyn.Data), dyn.Entsize)
	}
	got, err = decodeDynamic(dyn, Class64, order)
	if err != nil || !reflect.DeepEqual(got, entries) {
		t.Errorf("decoded 64-bit dynamic = %+v, %v", got, err)
	}

	// Empty dynamic section.
	f = cvNewFile(Class64, ET_REL)
	dyn = cvAdd(f, ".dynamic", SHT_DYNAMIC, nil)
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("empty dynamic: %v", err)
	}
	if len(dyn.Data) != 0 || dyn.Entsize != 8 {
		t.Errorf("empty dynamic: len=%d entsize=%d", len(dyn.Data), dyn.Entsize)
	}

	// Malformed sizes.
	for _, class := range []Class{Class64, Class32} {
		sec := &Section{SectionHeader: SectionHeader{Name: ".dynamic"}, Data: make([]byte, 10)}
		if _, err := decodeDynamic(sec, class, order); err == nil {
			t.Errorf("bad dynamic size accepted for %v", class)
		}
	}
	f = cvNewFile(Class64, ET_REL)
	cvAdd(f, ".dynamic", SHT_DYNAMIC, make([]byte, 10))
	if err := f.ConvertClass(Class32); err == nil {
		t.Error("ConvertClass accepted bad dynamic size")
	}

	// Oversized values/tags rejected on 64->32.
	f = cvNewFile(Class64, ET_REL)
	cvDynamicSection(t, f, Class64, []dynamicEntry{{tag: 1, val: 1 << 32}})
	if err := f.ConvertClass(Class32); err == nil {
		t.Error("large dynamic value accepted")
	}
	f = cvNewFile(Class64, ET_REL)
	cvDynamicSection(t, f, Class64, []dynamicEntry{{tag: math.MaxInt32 + 1, val: 0}})
	if err := f.ConvertClass(Class32); err == nil {
		t.Error("large dynamic tag accepted")
	}
	f = cvNewFile(Class64, ET_REL)
	cvDynamicSection(t, f, Class64, []dynamicEntry{{tag: math.MinInt32 - 1, val: 0}})
	if err := f.ConvertClass(Class32); err == nil {
		t.Error("small dynamic tag accepted")
	}

	// Empty dynsym table with a string table (writeSymtab path).
	f = cvNewFile(Class64, ET_REL)
	str = cvAdd(f, ".dynstr", SHT_STRTAB, []byte{0})
	dynsym = cvAdd(f, ".dynsym", SHT_DYNSYM, nil)
	dynsym.Link = uint32(f.SectionIndex(str))
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("empty dynsym: %v", err)
	}
	if dynsym.Entsize != 16 {
		t.Errorf("empty dynsym entsize = %d", dynsym.Entsize)
	}
}

// ---- SHT_RELR ------------------------------------------------------------

func TestConvertCoverageRelr(t *testing.T) {
	order := DataLSB.Order()
	entries := []uint64{0x1000, 0x2004}

	f := cvNewFile(Class64, ET_REL)
	sec := cvAdd(f, ".relr.dyn", SHT_RELR, nil)
	encodeRelr(sec, entries, Class64, order)
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(sec.Data) != 2*4 || sec.Entsize != 4 {
		t.Fatalf("32-bit relr: len=%d entsize=%d", len(sec.Data), sec.Entsize)
	}
	got, err := decodeRelr(sec, Class32, order)
	if err != nil || !reflect.DeepEqual(got, entries) {
		t.Errorf("decoded relr = %+v, %v", got, err)
	}
	if err := f.ConvertClass(Class64); err != nil {
		t.Fatalf("convert back: %v", err)
	}
	if len(sec.Data) != 2*8 || sec.Entsize != 8 {
		t.Fatalf("64-bit relr: len=%d entsize=%d", len(sec.Data), sec.Entsize)
	}
	got, err = decodeRelr(sec, Class64, order)
	if err != nil || !reflect.DeepEqual(got, entries) {
		t.Errorf("decoded 64-bit relr = %+v, %v", got, err)
	}

	// Empty section.
	f = cvNewFile(Class64, ET_REL)
	sec = cvAdd(f, ".relr.dyn", SHT_RELR, nil)
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("empty relr: %v", err)
	}
	if len(sec.Data) != 0 || sec.Entsize != 4 {
		t.Errorf("empty relr: len=%d entsize=%d", len(sec.Data), sec.Entsize)
	}

	// Malformed sizes for both classes.
	for _, class := range []Class{Class64, Class32} {
		bad := &Section{SectionHeader: SectionHeader{Name: ".relr"}, Data: make([]byte, 6)}
		if _, err := decodeRelr(bad, class, order); err == nil {
			t.Errorf("bad relr size accepted for %v", class)
		}
	}
	f = cvNewFile(Class64, ET_REL)
	cvAdd(f, ".relr.dyn", SHT_RELR, make([]byte, 6))
	if err := f.ConvertClass(Class32); err == nil {
		t.Error("ConvertClass accepted bad relr size")
	}

	// Offset that does not fit in ELF32.
	f = cvNewFile(Class64, ET_REL)
	sec = cvAdd(f, ".relr.dyn", SHT_RELR, nil)
	encodeRelr(sec, []uint64{1 << 32}, Class64, order)
	if err := f.ConvertClass(Class32); err == nil {
		t.Error("large relr offset accepted")
	}
}

// ---- SHT_GNU_HASH --------------------------------------------------------

func cvGNUHashData(order binary.ByteOrder, class Class, bloom []uint64, rest []byte) []byte {
	word := 4
	if class == Class64 {
		word = 8
	}
	b := make([]byte, 16+len(bloom)*word+len(rest))
	order.PutUint32(b[0:], 1) // nbuckets
	order.PutUint32(b[4:], 1) // symoffset
	order.PutUint32(b[8:], uint32(len(bloom)))
	order.PutUint32(b[12:], 2) // bloom_shift
	for i, w := range bloom {
		if class == Class64 {
			order.PutUint64(b[16+i*8:], w)
		} else {
			order.PutUint32(b[16+i*4:], uint32(w))
		}
	}
	copy(b[16+len(bloom)*word:], rest)
	return b
}

func TestConvertCoverageGNUHash(t *testing.T) {
	order := DataLSB.Order()
	bloom := []uint64{0x1122334455667788, 0x99aabbccddeeff00}
	rest := []byte{0xde, 0xad, 0xbe, 0xef}

	f := cvNewFile(Class64, ET_REL)
	sec := cvAdd(f, ".gnu.hash", SHT_GNU_HASH, cvGNUHashData(order, Class64, bloom, rest))
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("convert: %v", err)
	}
	if got := order.Uint32(sec.Data[8:]); got != 4 {
		t.Errorf("32-bit bloom_size = %d, want 4", got)
	}
	if len(sec.Data) != 16+4*4+len(rest) {
		t.Errorf("32-bit gnu.hash size = %d", len(sec.Data))
	}
	wantBloom := []uint64{
		0x55667788, 0x11223344,
		0xddeeff00, 0x99aabbcc,
	}
	for i, want := range wantBloom {
		if got := uint64(order.Uint32(sec.Data[16+i*4:])); got != want {
			t.Errorf("32-bit bloom[%d] = %#x, want %#x", i, got, want)
		}
	}
	if !bytes.Equal(sec.Data[16+4*4:], rest) {
		t.Errorf("32-bit gnu.hash rest = %x", sec.Data[16+4*4:])
	}

	if err := f.ConvertClass(Class64); err != nil {
		t.Fatalf("convert back: %v", err)
	}
	if got := order.Uint32(sec.Data[8:]); got != 2 {
		t.Errorf("64-bit bloom_size = %d, want 2", got)
	}
	for i, want := range bloom {
		if got := order.Uint64(sec.Data[16+i*8:]); got != want {
			t.Errorf("64-bit bloom[%d] = %#x, want %#x", i, got, want)
		}
	}
	if !bytes.Equal(sec.Data[16+2*8:], rest) {
		t.Errorf("64-bit gnu.hash rest = %x", sec.Data[16+2*8:])
	}

	// 32->64 with an even Bloom filter.
	f = cvNewFile(Class32, ET_REL)
	bloom32 := []uint64{0x55667788, 0x11223344, 0xddeeff00, 0x99aabbcc}
	sec = cvAdd(f, ".gnu.hash", SHT_GNU_HASH, cvGNUHashData(order, Class32, bloom32, rest))
	if err := f.ConvertClass(Class64); err != nil {
		t.Fatalf("32->64 gnu.hash: %v", err)
	}
	if got := order.Uint32(sec.Data[8:]); got != 2 {
		t.Errorf("merged bloom_size = %d, want 2", got)
	}
	want64 := []uint64{0x1122334455667788, 0x99aabbccddeeff00}
	for i, want := range want64 {
		if got := order.Uint64(sec.Data[16+i*8:]); got != want {
			t.Errorf("merged bloom[%d] = %#x, want %#x", i, got, want)
		}
	}

	// Odd Bloom filter cannot be paired for ELF64.
	f = cvNewFile(Class32, ET_REL)
	cvAdd(f, ".gnu.hash", SHT_GNU_HASH, cvGNUHashData(order, Class32, []uint64{1}, rest))
	if err := f.ConvertClass(Class64); err == nil {
		t.Error("odd bloom_size accepted for ELF64")
	}

	// encodeGNUHash's defensive early return for an odd size.
	h := savedGNUHash{sec: &Section{}, header: [16]byte{}, bloom: []uint64{1}, rest: nil, bloomSize: 1}
	encodeGNUHash(h, Class64, order)

	// Truncated / inconsistent input.
	if _, err := decodeGNUHash(&Section{SectionHeader: SectionHeader{Name: ".h"}, Data: make([]byte, 12)}, Class64, order); err == nil {
		t.Error("short gnu.hash accepted")
	}
	bad := cvGNUHashData(order, Class64, bloom, rest)
	order.PutUint32(bad[8:], 100)
	if _, err := decodeGNUHash(&Section{SectionHeader: SectionHeader{Name: ".h"}, Data: bad}, Class64, order); err == nil {
		t.Error("oversized bloom filter accepted")
	}
	f = cvNewFile(Class64, ET_REL)
	cvAdd(f, ".gnu.hash", SHT_GNU_HASH, make([]byte, 12))
	if err := f.ConvertClass(Class32); err == nil {
		t.Error("ConvertClass accepted short gnu.hash")
	}
}

// ---- GNU property notes --------------------------------------------------

func TestConvertCoveragePropertyRoundTrip(t *testing.T) {
	order := DataLSB.Order()
	f := cvNewFile(Class64, ET_REL)
	data := cvNote(order, 8,
		cvPropEntry(order, 8, 0xc0010002, 0xa),
		cvPropEntry(order, 8, 0xc0008002, 0xa0),
		cvPropEntry(order, 8, 0xc0010002, 0xa0),
	)
	sec := cvAdd(f, ".note.gnu.property", SHT_NOTE, data)
	sec.Flags |= SHF_ALLOC
	sec.Addralign = 8
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("convert: %v", err)
	}
	props := cvParseProps(t, sec.Data, 4, order)
	got := cvPropValues(props, order)
	if got[0xc0010002] != 0xaa || got[0xc0008002] != 0xa0 {
		t.Errorf("merged properties = %#x", got)
	}
	if got := order.Uint32(sec.Data[4:]); got != 2*12 {
		t.Errorf("ELF32 descsz = %d, want 24", got)
	}
	// BFD preserves the input section alignment; only the descriptor layout
	// follows the class word.
	if sec.Addralign != 8 {
		t.Errorf("ELF32 alignment = %d, want 8", sec.Addralign)
	}
	if err := f.ConvertClass(Class64); err != nil {
		t.Fatalf("convert back: %v", err)
	}
	if got := order.Uint32(sec.Data[4:]); got != 2*16 {
		t.Errorf("ELF64 descsz = %d, want 32", got)
	}
	if sec.Addralign != 8 {
		t.Errorf("ELF64 alignment = %d", sec.Addralign)
	}

	// Multiple notes: stack size, ISA_NEEDED and FEATURE_2_USED are merged
	// into one note and sorted by type.
	f = cvNewFile(Class64, ET_REL)
	stack := make([]byte, 16)
	order.PutUint32(stack[0:], gnuPropertyStackSz)
	order.PutUint32(stack[4:], 8)
	order.PutUint64(stack[8:], 0xffffffff)
	data = append(data, cvNote(order, 8, stack)...)
	data = append(data, cvNote(order, 8, cvPropEntry(order, 8, 0xc0010001, 1))...)
	sec = cvAdd(f, ".note.gnu.property", SHT_NOTE, data)
	sec.Flags |= SHF_ALLOC
	sec.Addralign = 8
	if err := f.ConvertClass(Class32); err != nil {
		t.Fatalf("convert multi-note: %v", err)
	}
	props = cvParseProps(t, sec.Data, 4, order)
	got = cvPropValues(props, order)
	if got[0xc0010002] != 0xaa || got[0xc0008002] != 0xa0 || got[0xc0010001] != 1 {
		t.Errorf("multi-note merge = %#x", got)
	}
	// Stack size is written with the target class's width.
	if got := order.Uint32(sec.Data[16+4:]); got != 4 {
		t.Errorf("stack size datasz = %d", got)
	}
	for i := 1; i < len(props); i++ {
		if props[i-1].typ > props[i].typ {
			t.Errorf("properties not sorted: %#x > %#x", props[i-1].typ, props[i].typ)
		}
	}
}

func TestConvertCoveragePropertyMalformed(t *testing.T) {
	order := DataLSB.Order()

	// Too short for a note header.
	if _, ok := decodePropertyNotes(&Section{SectionHeader: SectionHeader{Name: ".note.gnu.property"}, Data: make([]byte, 11)}, Class64, order); ok {
		t.Error("short note accepted")
	}
	// namesz larger than the data.
	b := cvNote(order, 8, cvPropEntry(order, 8, 0xc0010002, 1))
	order.PutUint32(b[0:], 0xffff)
	if _, ok := decodePropertyNotes(&Section{SectionHeader: SectionHeader{Name: ".n"}, Data: b}, Class64, order); ok {
		t.Error("oversized namesz accepted")
	}
	// descsz larger than the data.
	b = cvNote(order, 8, cvPropEntry(order, 8, 0xc0010002, 1))
	order.PutUint32(b[4:], 0xffff)
	if _, ok := decodePropertyNotes(&Section{SectionHeader: SectionHeader{Name: ".n"}, Data: b}, Class64, order); ok {
		t.Error("oversized descsz accepted")
	}
	// Non-property note.
	b = make([]byte, 16)
	order.PutUint32(b[0:], 4)
	order.PutUint32(b[4:], 0)
	order.PutUint32(b[8:], 1) // NT_GNU_ABI_TAG
	copy(b[12:], "GNU\x00")
	if _, ok := decodePropertyNotes(&Section{SectionHeader: SectionHeader{Name: ".n"}, Data: b}, Class64, order); ok {
		t.Error("non-property note accepted")
	}
	// A non-GNU note followed by a valid property note; the first is skipped.
	other := make([]byte, 16)
	order.PutUint32(other[0:], 4)
	order.PutUint32(other[4:], 0)
	order.PutUint32(other[8:], 5)
	copy(other[12:], "XYZ\x00")
	b = append(other, cvNote(order, 8, cvPropEntry(order, 8, 0xc0010002, 7))...)
	props, ok := decodePropertyNotes(&Section{SectionHeader: SectionHeader{Name: ".n"}, Data: b}, Class64, order)
	if !ok || len(props) != 1 || cvPropValues(props, order)[0xc0010002] != 7 {
		t.Errorf("non-GNU note handling: %+v ok=%v", props, ok)
	}
	// Malformed property descriptor (datasz beyond the descriptor).
	n := make([]byte, 16+8)
	order.PutUint32(n[0:], 4)
	order.PutUint32(n[4:], 8)
	order.PutUint32(n[8:], gnuPropertyType0)
	copy(n[12:], "GNU\x00")
	order.PutUint32(n[16:], 0xc0010002)
	order.PutUint32(n[20:], 100)
	if _, ok := decodePropertyNotes(&Section{SectionHeader: SectionHeader{Name: ".n"}, Data: n}, Class64, order); ok {
		t.Error("malformed property accepted")
	}
	// Trailing bytes that are not a complete note.
	b = cvNote(order, 8, cvPropEntry(order, 8, 0xc0010002, 1))
	b = append(b, 1, 2, 3)
	if _, ok := decodePropertyNotes(&Section{SectionHeader: SectionHeader{Name: ".n"}, Data: b}, Class64, order); ok {
		t.Error("trailing partial note accepted")
	}
	// Unknown section alignment falls back to the class default.
	b = cvNote(order, 8, cvPropEntry(order, 8, 0xc0010002, 2))
	sec := &Section{SectionHeader: SectionHeader{Name: ".n", Addralign: 3}, Data: b}
	if _, ok := decodePropertyNotes(sec, Class64, order); !ok {
		t.Error("class-default alignment rejected")
	}
	b4 := cvNote(order, 4, cvPropEntry(order, 4, 0xc0010002, 2))
	sec = &Section{SectionHeader: SectionHeader{Name: ".n", Addralign: 0}, Data: b4}
	if _, ok := decodePropertyNotes(sec, Class32, order); !ok {
		t.Error("class-default alignment rejected (32)")
	}
}

func TestConvertCoveragePropertyHelpers(t *testing.T) {
	order := DataLSB.Order()

	// parsePropertyList error branches.
	if _, ok := parsePropertyList([]byte{1, 2, 3}, 4, order); ok {
		t.Error("short property list accepted")
	}
	bad := make([]byte, 8)
	order.PutUint32(bad[0:], 0xc0010002)
	order.PutUint32(bad[4:], 100)
	if _, ok := parsePropertyList(bad, 4, order); ok {
		t.Error("oversized datasz accepted")
	}
	// align 1 exercises alignInt's trivial branch.
	if _, ok := parsePropertyList(bad[:4], 1, order); ok {
		t.Error("short property list accepted with align 1")
	}
	if got := alignInt(7, 1); got != 7 {
		t.Errorf("alignInt(7,1) = %d", got)
	}
	if got := alignInt(7, 0); got != 7 {
		t.Errorf("alignInt(7,0) = %d", got)
	}
	if got := alignInt(7, 4); got != 8 {
		t.Errorf("alignInt(7,4) = %d", got)
	}

	// mergeProperties: new entry, 4-byte OR, 8-byte OR, stack replacement and
	// mismatched sizes.
	p4 := func(typ, val uint32) gnuProperty {
		b := make([]byte, 4)
		order.PutUint32(b, val)
		return gnuProperty{typ: typ, data: b}
	}
	p8 := func(typ uint32, val uint64) gnuProperty {
		b := make([]byte, 8)
		order.PutUint64(b, val)
		return gnuProperty{typ: typ, data: b}
	}
	props := mergeProperties(nil, []gnuProperty{p4(0xc0010002, 1)}, order)
	props = mergeProperties(props, []gnuProperty{p4(0xc0010002, 2)}, order)
	if cvPropValues(props, order)[0xc0010002] != 3 {
		t.Errorf("4-byte OR failed: %+v", props)
	}
	props = mergeProperties(props, []gnuProperty{p8(4, 1)}, order)
	props = mergeProperties(props, []gnuProperty{p8(4, 2)}, order)
	if cvPropValues(props, order)[4] != 3 {
		t.Errorf("8-byte OR failed: %+v", props)
	}
	props = mergeProperties(props, []gnuProperty{p4(gnuPropertyStackSz, 5)}, order)
	props = mergeProperties(props, []gnuProperty{p4(gnuPropertyStackSz, 9)}, order)
	if cvPropValues(props, order)[gnuPropertyStackSz] != 9 {
		t.Errorf("stack size replacement failed: %+v", props)
	}
	props = mergeProperties(props, []gnuProperty{p8(0xc0010002, 8)}, order)
	if len(props[len(props)-1].data) != 8 {
		// The mismatched duplicate keeps the first value.
		for _, p := range props {
			if p.typ == 0xc0010002 && len(p.data) != 4 {
				t.Errorf("mismatched merge changed data: %+v", p)
			}
		}
	}
	// Duplicate with a zero-length property.
	z := gnuProperty{typ: 7, data: nil}
	props = mergeProperties(props, []gnuProperty{z}, order)
	props = mergeProperties(props, []gnuProperty{z}, order)
	if cvPropValues(props, order)[7] != 0 {
		t.Errorf("zero-length merge: %+v", props)
	}

	// encodePropertyNote: stack size with an 8-byte value into ELF32 and a
	// 4-byte value into ELF64; a plain 8-byte property is preserved.
	stack8 := p8(gnuPropertyStackSz, 0xffffffff)
	plain8 := p8(0xc0008002, 0x1234)
	sec := &Section{}
	encodePropertyNote(sec, []gnuProperty{stack8, plain8}, Class32, order)
	props = cvParseProps(t, sec.Data, 4, order)
	got := cvPropValues(props, order)
	if got[gnuPropertyStackSz] != 0xffffffff {
		t.Errorf("stack size 64->32 = %#x", got[gnuPropertyStackSz])
	}
	if got[0xc0008002] != 0x1234 {
		t.Errorf("8-byte property 64->32 = %#x", got[0xc0008002])
	}
	stack4 := p4(gnuPropertyStackSz, 0xffffffff)
	sec = &Section{}
	encodePropertyNote(sec, []gnuProperty{stack4, p4(0xc0010001, 3)}, Class64, order)
	props = cvParseProps(t, sec.Data, 8, order)
	got = cvPropValues(props, order)
	if got[gnuPropertyStackSz] != 0xffffffff || got[0xc0010001] != 3 {
		t.Errorf("stack size 32->64 = %#x / %#x", got[gnuPropertyStackSz], got[0xc0010001])
	}
}

// ---- bounds checking -----------------------------------------------------

func TestConvertCoverageFitChecks(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*File, *[]savedSymtab, *[]savedRelocs, *[]savedDynamic, *[]savedRelr, *[]savedCompressed)
	}{
		{"entry", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			f.Entry = 1 << 32
		}},
		{"section-address", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			cvAdd(f, ".s", SHT_PROGBITS, nil).Addr = 1 << 32
		}},
		{"section-size", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			cvAdd(f, ".s", SHT_PROGBITS, nil).Size = 1 << 32
		}},
		{"section-offset", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			cvAdd(f, ".s", SHT_PROGBITS, nil).Offset = 1 << 32
		}},
		{"section-align", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			cvAdd(f, ".s", SHT_PROGBITS, nil).Addralign = 1 << 32
		}},
		{"section-entsize", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			cvAdd(f, ".s", SHT_PROGBITS, nil).Entsize = 1 << 32
		}},
		{"section-flags", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			cvAdd(f, ".s", SHT_PROGBITS, nil).Flags = 1 << 32
		}},
		{"segment-offset", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			f.Segments = []*ProgramHeader{{Offset: 1 << 32}}
		}},
		{"segment-vaddr", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			f.Segments = []*ProgramHeader{{Vaddr: 1 << 32}}
		}},
		{"segment-paddr", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			f.Segments = []*ProgramHeader{{Paddr: 1 << 32}}
		}},
		{"segment-filesz", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			f.Segments = []*ProgramHeader{{Filesz: 1 << 32}}
		}},
		{"segment-memsz", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			f.Segments = []*ProgramHeader{{Memsz: 1 << 32}}
		}},
		{"segment-align", func(f *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			f.Segments = []*ProgramHeader{{Align: 1 << 32}}
		}},
		{"symbol-value", func(_ *File, tabs *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			*tabs = append(*tabs, savedSymtab{entries: []Symbol{{Name: "sym", Value: 1 << 32}}})
		}},
		{"symbol-size", func(_ *File, tabs *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			*tabs = append(*tabs, savedSymtab{entries: []Symbol{{Name: "sym", Size: 1 << 32}}})
		}},
		{"reloc-offset", func(_ *File, _ *[]savedSymtab, rels *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			*rels = append(*rels, savedRelocs{sec: &Section{SectionHeader: SectionHeader{Name: ".rel"}},
				relocs: []Reloc{{Offset: 1 << 32}}})
		}},
		{"reloc-type", func(_ *File, _ *[]savedSymtab, rels *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			*rels = append(*rels, savedRelocs{sec: &Section{SectionHeader: SectionHeader{Name: ".rel"}},
				relocs: []Reloc{{Type: 0x100}}})
		}},
		{"reloc-addend-high", func(_ *File, _ *[]savedSymtab, rels *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			*rels = append(*rels, savedRelocs{sec: &Section{SectionHeader: SectionHeader{Name: ".rel"}},
				relocs: []Reloc{{HasAddend: true, Addend: math.MaxInt64}}})
		}},
		{"reloc-addend-low", func(_ *File, _ *[]savedSymtab, rels *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			*rels = append(*rels, savedRelocs{sec: &Section{SectionHeader: SectionHeader{Name: ".rel"}},
				relocs: []Reloc{{HasAddend: true, Addend: math.MinInt64}}})
		}},
		{"dynamic-tag-high", func(_ *File, _ *[]savedSymtab, _ *[]savedRelocs, dyn *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			*dyn = append(*dyn, savedDynamic{sec: &Section{}, entries: []dynamicEntry{{tag: math.MaxInt64}}})
		}},
		{"dynamic-tag-low", func(_ *File, _ *[]savedSymtab, _ *[]savedRelocs, dyn *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			*dyn = append(*dyn, savedDynamic{sec: &Section{}, entries: []dynamicEntry{{tag: math.MinInt64}}})
		}},
		{"dynamic-value", func(_ *File, _ *[]savedSymtab, _ *[]savedRelocs, dyn *[]savedDynamic, _ *[]savedRelr, _ *[]savedCompressed) {
			*dyn = append(*dyn, savedDynamic{sec: &Section{}, entries: []dynamicEntry{{val: 1 << 32}}})
		}},
		{"relr-offset", func(_ *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, relr *[]savedRelr, _ *[]savedCompressed) {
			*relr = append(*relr, savedRelr{sec: &Section{}, entries: []uint64{1 << 32}})
		}},
		{"compressed-size", func(_ *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, comp *[]savedCompressed) {
			*comp = append(*comp, savedCompressed{sec: &Section{SectionHeader: SectionHeader{Name: ".c"}}, size: 1 << 32})
		}},
		{"compressed-align", func(_ *File, _ *[]savedSymtab, _ *[]savedRelocs, _ *[]savedDynamic, _ *[]savedRelr, comp *[]savedCompressed) {
			*comp = append(*comp, savedCompressed{sec: &Section{SectionHeader: SectionHeader{Name: ".c"}}, align: 1 << 32})
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := cvNewFile(Class64, ET_REL)
			var syms []savedSymtab
			var rels []savedRelocs
			var dyns []savedDynamic
			var relrs []savedRelr
			var comps []savedCompressed
			tc.setup(f, &syms, &rels, &dyns, &relrs, &comps)
			if err := checkClassFits(f, syms, rels, dyns, relrs, comps); err == nil {
				t.Fatalf("%s: checkClassFits accepted an overflowing value", tc.name)
			}
		})
	}

	// A fully populated but in-range file passes.
	f := cvNewFile(Class64, ET_REL)
	f.Entry = math.MaxUint32
	sec := cvAdd(f, ".s", SHT_PROGBITS, nil)
	sec.Addr, sec.Size, sec.Offset = math.MaxUint32, math.MaxUint32, math.MaxUint32
	sec.Addralign, sec.Entsize, sec.Flags = math.MaxUint32, math.MaxUint32, math.MaxUint32
	f.Segments = []*ProgramHeader{{
		Offset: math.MaxUint32, Vaddr: math.MaxUint32, Paddr: math.MaxUint32,
		Filesz: math.MaxUint32, Memsz: math.MaxUint32, Align: math.MaxUint32,
	}}
	syms := []savedSymtab{{entries: []Symbol{{Name: "s", Value: math.MaxUint32, Size: math.MaxUint32}}}}
	rels := []savedRelocs{{sec: sec, relocs: []Reloc{
		{Offset: math.MaxUint32, Type: 0xff, HasAddend: true, Addend: math.MaxInt32},
		{Offset: 0, HasAddend: false, Addend: math.MinInt64},
	}}}
	dyns := []savedDynamic{{sec: sec, entries: []dynamicEntry{
		{tag: math.MaxInt32, val: math.MaxUint32},
		{tag: math.MinInt32, val: 0},
	}}}
	relrs := []savedRelr{{sec: sec, entries: []uint64{math.MaxUint32}}}
	comps := []savedCompressed{{sec: sec, size: math.MaxUint32, align: math.MaxUint32}}
	if err := checkClassFits(f, syms, rels, dyns, relrs, comps); err != nil {
		t.Fatalf("in-range file rejected: %v", err)
	}

	// checkU32 itself.
	if err := checkU32("x", math.MaxUint32); err != nil {
		t.Errorf("checkU32(max) = %v", err)
	}
	if err := checkU32("x", math.MaxUint32+1); err == nil {
		t.Error("checkU32(overflow) = nil")
	}
}

// ---- interaction between class-dependent sections ------------------------

func TestConvertCoverageKitchenSink(t *testing.T) {
	// One file containing every class-dependent section, converted in both
	// directions.  Values are small so the ELF32 bounds checks pass.
	order := DataLSB.Order()
	build := func(class Class) *File {
		f := cvNewFile(class, ET_REL)
		cvAdd(f, ".text", SHT_PROGBITS, []byte{0x90, 0x90})
		str := cvAdd(f, ".dynstr", SHT_STRTAB, []byte("\x00foo\x00"))
		cvDynsymSection(t, f, class, str)
		cvDynamicSection(t, f, class, []dynamicEntry{{tag: 0, val: 0}})
		relr := cvAdd(f, ".relr.dyn", SHT_RELR, nil)
		encodeRelr(relr, []uint64{0x1000}, class, order)
		bloom := []uint64{1, 2}
		if class == Class32 {
			bloom = []uint64{1, 2, 3, 4}
		}
		cvAdd(f, ".gnu.hash", SHT_GNU_HASH, cvGNUHashData(order, class, bloom, []byte{7, 8}))
		note := cvNote(order, 4, cvPropEntry(order, 4, 0xc0010002, 5))
		if class == Class64 {
			note = cvNote(order, 8, cvPropEntry(order, 8, 0xc0010002, 5))
		}
		ns := cvAdd(f, ".note.gnu.property", SHT_NOTE, note)
		ns.Addralign = 4
		if class == Class64 {
			ns.Addralign = 8
		}
		comp := cvCompressedSection(t, f, class, ".debug_info", []byte{1, 2}, 2, 1)
		_ = comp
		return f
	}

	for _, from := range []Class{Class64, Class32} {
		to := Class32
		if from == Class32 {
			to = Class64
		}
		f := build(from)
		if err := f.ConvertClass(to); err != nil {
			t.Fatalf("%v->%v: %v", from, to, err)
		}
		if f.Class != to {
			t.Fatalf("%v->%v: class = %v", from, to, f.Class)
		}
		if err := f.ConvertClass(from); err != nil {
			t.Fatalf("%v back: %v", to, err)
		}
	}
}
