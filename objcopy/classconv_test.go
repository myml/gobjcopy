package objcopy_test

// Tests for ELF32 <-> ELF64 class conversion (x86-64 <-> x32).  The model is
// checked directly through elf.ConvertClass and end to end through
// objcopy.Run, and every converted file is cross-checked with readelf.

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/fixtures"
	"github.com/myml/gobjcopy/objcopy"
)

func classConvFixtures(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	fx, err := fixtures.Build(dir)
	if err != nil {
		t.Fatalf("build fixtures: %v", err)
	}
	if len(fx) == 0 {
		t.Skip("fixtures unavailable (gcc not installed?)")
	}
	return fx
}

func classConvFixture(t *testing.T, fx map[string]string, name string) string {
	t.Helper()
	p, ok := fx[name]
	if !ok {
		t.Skipf("fixture %q was not built on this host", name)
	}
	return p
}

// ---- semantic snapshot ---------------------------------------------------

type convSection struct {
	Name      string
	Type      uint32
	Flags     uint64
	Addr      uint64
	Size      uint64
	Addralign uint64
	Entsize   uint64
	Link      uint32
	Info      uint32
	Data      string // empty for symbol/relocation/string tables
}

type convSymbol struct {
	Name  string
	Info  byte
	Other byte
	Shndx uint16
	Value uint64
	Size  uint64
}

type convReloc struct {
	Offset    uint64
	Sym       uint32
	Type      uint32
	Addend    int64
	HasAddend bool
}

type convSymtab struct {
	Section string
	Info    uint32
	Symbols []convSymbol
}

type convRelocs struct {
	Section string
	Info    uint32
	Relocs  []convReloc
}

type convSnapshot struct {
	Type     uint16
	Machine  uint16
	Flags    uint32
	Entry    uint64
	Sections []convSection
	Symtabs  []convSymtab
	Relocs   []convRelocs
}

func takeSnapshot(t *testing.T, f *elf.File) convSnapshot {
	t.Helper()
	s := convSnapshot{Type: f.Type, Machine: f.Machine, Flags: f.Flags, Entry: f.Entry}
	for _, sec := range f.Sections {
		cs := convSection{
			Name:      sec.Name,
			Type:      sec.Type,
			Flags:     sec.Flags,
			Addr:      sec.Addr,
			Size:      sec.Size,
			Addralign: sec.Addralign,
			Entsize:   sec.Entsize,
			Link:      sec.Link,
			Info:      sec.Info,
		}
		if !sec.IsNoBits() && !classConvTableData(sec) {
			sum := sha256.Sum256(sec.Data)
			cs.Data = fmt.Sprintf("%x", sum)
		}
		// Symbol/relocation tables and the string tables they use are
		// compared through their decoded entries; their byte layout (and
		// therefore sh_size) legitimately differs between implementations.
		if classConvStrTab(sec) {
			cs.Size = 0
		}
		s.Sections = append(s.Sections, cs)
	}
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_SYMTAB && sec.Type != elf.SHT_DYNSYM {
			continue
		}
		st, err := f.ReadSymtab(sec)
		if err != nil {
			t.Fatalf("read %s: %v", sec.Name, err)
		}
		tab := convSymtab{Section: sec.Name, Info: sec.Info}
		for _, sym := range st.Entries {
			tab.Symbols = append(tab.Symbols, convSymbol{
				Name: sym.Name, Info: sym.Info, Other: sym.Other,
				Shndx: sym.Shndx, Value: sym.Value, Size: sym.Size,
			})
		}
		s.Symtabs = append(s.Symtabs, tab)
	}
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_REL && sec.Type != elf.SHT_RELA {
			continue
		}
		rs, err := f.ReadRelocs(sec)
		if err != nil {
			t.Fatalf("read %s: %v", sec.Name, err)
		}
		tab := convRelocs{Section: sec.Name, Info: sec.Info}
		for _, r := range rs {
			tab.Relocs = append(tab.Relocs, convReloc{
				Offset: r.Offset, Sym: r.Sym, Type: r.Type,
				Addend: r.Addend, HasAddend: r.HasAddend,
			})
		}
		s.Relocs = append(s.Relocs, tab)
	}
	return s
}

// classConvTableData reports whether a section's bytes are covered by the
// decoded symbol/relocation snapshots, or are a string table whose layout may
// legitimately change when it is re-encoded.
func classConvTableData(sec *elf.Section) bool {
	switch sec.Type {
	case elf.SHT_SYMTAB, elf.SHT_DYNSYM, elf.SHT_REL, elf.SHT_RELA:
		return true
	case elf.SHT_STRTAB:
		return true
	}
	return false
}

// classConvStrTab reports whether sec is one of the symbol string tables whose
// layout is an implementation detail.
func classConvStrTab(sec *elf.Section) bool {
	if sec.Type != elf.SHT_STRTAB {
		return false
	}
	switch sec.Name {
	case ".strtab", ".dynstr", ".shstrtab":
		return true
	}
	return false
}

// ignoreClassWidths clears fields whose width legitimately follows the class,
// so that a converted file can be compared with its input.
func ignoreClassWidths(s *convSnapshot) {
	for i := range s.Sections {
		sec := &s.Sections[i]
		switch sec.Type {
		case elf.SHT_SYMTAB, elf.SHT_DYNSYM, elf.SHT_REL, elf.SHT_RELA:
			sec.Size = 0
			sec.Entsize = 0
			sec.Addralign = 0
			sec.Data = ""
		case elf.SHT_STRTAB:
			sec.Size = 0
			sec.Data = ""
		}
	}
}

// ignoreNoteAlign drops the sh_addralign of GNU property notes.  GNU is
// inconsistent here (compiler-produced objects keep 8, assembled ones get the
// class word), so only the note payload is compared.
func ignoreNoteAlign(s *convSnapshot) {
	for i := range s.Sections {
		sec := &s.Sections[i]
		if sec.Type == elf.SHT_NOTE && sec.Name == ".note.gnu.property" {
			sec.Addralign = 0
		}
	}
}

// ignoreNoteLayouts drops the layout of GNU property notes.  Their size and
// internal alignment legitimately follow the class word (x32 packs the
// descriptors on 4-byte boundaries), and whether the host compiler emits one
// at all depends on its default -fcf-protection setting.
func ignoreNoteLayouts(s *convSnapshot) {
	for i := range s.Sections {
		sec := &s.Sections[i]
		if sec.Type == elf.SHT_NOTE && sec.Name == ".note.gnu.property" {
			sec.Size = 0
			sec.Addralign = 0
			sec.Data = ""
		}
	}
}

func compareSnapshots(t *testing.T, want, got convSnapshot) {
	t.Helper()
	if want.Type != got.Type || want.Machine != got.Machine || want.Flags != got.Flags || want.Entry != got.Entry {
		t.Errorf("header differs: want type=%d machine=%d flags=%#x entry=%#x, got type=%d machine=%d flags=%#x entry=%#x",
			want.Type, want.Machine, want.Flags, want.Entry,
			got.Type, got.Machine, got.Flags, got.Entry)
	}
	if len(want.Sections) != len(got.Sections) {
		t.Fatalf("section count %d != %d", len(got.Sections), len(want.Sections))
	}
	for i := range want.Sections {
		if want.Sections[i] != got.Sections[i] {
			t.Errorf("section %d differs:\n want %+v\n got  %+v", i, want.Sections[i], got.Sections[i])
		}
	}
	if !reflect.DeepEqual(want.Symtabs, got.Symtabs) {
		t.Errorf("symbol tables differ:\n want %+v\n got  %+v", want.Symtabs, got.Symtabs)
	}
	if !reflect.DeepEqual(want.Relocs, got.Relocs) {
		t.Errorf("relocations differ:\n want %+v\n got  %+v", want.Relocs, got.Relocs)
	}
}

// roundTrip converts f to class and back, returning the reparsed result and
// the intermediate serialised bytes.
func classConvRoundTrip(t *testing.T, path string, class elf.Class) (*elf.File, []byte) {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	back := f.Class
	if err := f.ConvertClass(class); err != nil {
		t.Fatalf("convert %s to class %d: %v", path, class, err)
	}
	if f.Class != class {
		t.Fatalf("class = %d, want %d", f.Class, class)
	}
	mid, err := f.Bytes()
	if err != nil {
		t.Fatalf("serialise %s class %d: %v", path, class, err)
	}
	g, err := elf.Parse(mid)
	if err != nil {
		t.Fatalf("reparse converted %s: %v", path, err)
	}
	if err := g.ConvertClass(back); err != nil {
		t.Fatalf("convert %s back to class %d: %v", path, back, err)
	}
	out, err := g.Bytes()
	if err != nil {
		t.Fatalf("serialise back %s: %v", path, err)
	}
	h, err := elf.Parse(out)
	if err != nil {
		t.Fatalf("reparse round-tripped %s: %v", path, err)
	}
	return h, mid
}

func TestClassConvertRoundTrip(t *testing.T) {
	fx := classConvFixtures(t)
	readelf := classConvTool(t, "readelf")
	cases := []struct {
		name  string
		class elf.Class
	}{
		{"reloc.o", elf.Class32},
		{"reloc32.o", elf.Class64},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := classConvFixture(t, fx, tc.name)
			orig, err := elf.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			want := takeSnapshot(t, orig)

			got, mid := classConvRoundTrip(t, path, tc.class)
			back := takeSnapshot(t, got)
			compareSnapshots(t, want, back)

			// The intermediate image must keep symbol and relocation
			// semantics even though entry widths change.
			midFile, err := elf.Parse(mid)
			if err != nil {
				t.Fatal(err)
			}
			if midFile.Class != tc.class {
				t.Fatalf("intermediate class = %d, want %d", midFile.Class, tc.class)
			}
			midSnap := takeSnapshot(t, midFile)
			ignoreClassWidths(&midSnap)
			ignoreNoteLayouts(&midSnap)
			interWant := want
			ignoreClassWidths(&interWant)
			ignoreNoteLayouts(&interWant)
			// Section sizes of debug data are unchanged, but the symbol
			// table and relocation table sizes shrink or grow with the
			// class; ignoreClassWidths already zeroed those.
			compareSnapshots(t, interWant, midSnap)

			p := classConvWrite(t, mid, tc.name)
			classConvReadelfParses(t, readelf, p, tc.class)
		})
	}
}

// TestClassConvertRun exercises the objcopy pipeline and the -O targets used by
// binutils' "Convert x32 object to x86-64" tests.
func TestClassConvertRun(t *testing.T) {
	fx := classConvFixtures(t)
	readelf := classConvTool(t, "readelf")
	path := classConvFixture(t, fx, "reloc.o")

	orig, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	want := takeSnapshot(t, orig)
	ignoreClassWidths(&want)
	ignoreNoteLayouts(&want)

	for _, tc := range []struct {
		target string
		class  elf.Class
	}{
		{"elf32-x86-64", elf.Class32},
		{"elf64-x86-64", elf.Class64},
	} {
		tc := tc
		t.Run(tc.target, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			out := filepath.Join(dir, "out.o")
			cfg := objcopy.Default()
			cfg.OutputTarget = tc.target
			if err := objcopy.Run(cfg, path, out); err != nil {
				t.Fatalf("-O %s: %v", tc.target, err)
			}
			f, err := elf.Open(out)
			if err != nil {
				t.Fatalf("-O %s: %v", tc.target, err)
			}
			if f.Class != tc.class {
				t.Fatalf("class = %d, want %d", f.Class, tc.class)
			}
			snap := takeSnapshot(t, f)
			ignoreClassWidths(&snap)
			ignoreNoteLayouts(&snap)
			compareSnapshots(t, want, snap)

			classConvReadelfParses(t, readelf, out, tc.class)
		})
	}
}

// TestClassConvertGNUParity compares a 64->32 conversion with GNU objcopy,
// which uses the same class translation rules (see bfd/elf.c).  Only the
// x86-64 -> x32 direction is compared: GNU also changes e_machine when it
// converts an i386 object to elf64-x86-64, while this implementation leaves
// the machine alone (objcopy's class hook only receives the target class).
func TestClassConvertGNUParity(t *testing.T) {
	gnu := classConvTool(t, "objcopy")
	fx := classConvFixtures(t)
	path := classConvFixture(t, fx, "reloc.o")
	dir := t.TempDir()

	ours := filepath.Join(dir, "ours.o")
	cfg := objcopy.Default()
	cfg.OutputTarget = "elf32-x86-64"
	if err := objcopy.Run(cfg, path, ours); err != nil {
		t.Fatalf("ours: %v", err)
	}
	ref := filepath.Join(dir, "ref.o")
	cmd := exec.Command(gnu, "-O", "elf32-x86-64", path, ref)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("GNU objcopy: %v\n%s", err, out)
	}

	refFile, err := elf.Open(ref)
	if err != nil {
		t.Fatal(err)
	}
	ourFile, err := elf.Open(ours)
	if err != nil {
		t.Fatal(err)
	}
	want := takeSnapshot(t, refFile)
	got := takeSnapshot(t, ourFile)
	ignoreClassWidths(&want)
	ignoreClassWidths(&got)
	ignoreNoteAlign(&want)
	ignoreNoteAlign(&got)
	compareSnapshots(t, want, got)
}

// TestClassConvertCompressed checks that class conversion preserves the debug
// payload when the input carries SHF_COMPRESSED (zlib-gabi) or .zdebug
// (zlib-gnu) sections, including a switch between the two compression
// variants in the same invocation.
func TestClassConvertCompressed(t *testing.T) {
	fx := classConvFixtures(t)
	path := classConvFixture(t, fx, "reloc.o")
	orig, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	want := classConvDebugContents(t, orig)
	if len(want) == 0 {
		t.Skip("fixture has no debug sections")
	}

	for _, tc := range []struct {
		name   string
		first  string // compression of the intermediate file
		second string // compression requested during conversion
		target string
		class  elf.Class
		gnuOut bool
	}{
		{"gabi-to-x32", "zlib-gabi", "", "elf32-x86-64", elf.Class32, false},
		{"gnu-to-x32", "zlib-gnu", "", "elf32-x86-64", elf.Class32, true},
		{"gabi-to-gnu-x32", "zlib-gabi", "zlib-gnu", "elf32-x86-64", elf.Class32, true},
		{"gnu-to-gabi-x32", "zlib-gnu", "zlib-gabi", "elf32-x86-64", elf.Class32, false},
		{"gnu-to-gabi-x64", "zlib-gnu", "zlib-gabi", "elf64-x86-64", elf.Class64, false},
		{"gabi-to-gnu-x64", "zlib-gabi", "zlib-gnu", "elf64-x86-64", elf.Class64, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			first := filepath.Join(dir, "first.o")
			cfg := objcopy.Default()
			cfg.CompressDebug = tc.first
			if err := objcopy.Run(cfg, path, first); err != nil {
				t.Fatalf("compress %s: %v", tc.first, err)
			}
			out := filepath.Join(dir, "out.o")
			cfg = objcopy.Default()
			cfg.OutputTarget = tc.target
			cfg.CompressDebug = tc.second
			if err := objcopy.Run(cfg, first, out); err != nil {
				t.Fatalf("-O %s compress %q: %v", tc.target, tc.second, err)
			}
			f, err := elf.Open(out)
			if err != nil {
				t.Fatalf("reparse: %v", err)
			}
			if f.Class != tc.class {
				t.Fatalf("class = %d, want %d", f.Class, tc.class)
			}
			for _, sec := range f.Sections {
				if !strings.HasPrefix(sec.Name, ".debug") && !strings.HasPrefix(sec.Name, ".zdebug") {
					continue
				}
				isZdebug := strings.HasPrefix(sec.Name, ".zdebug")
				if tc.gnuOut {
					// A section whose compression would not make it smaller
					// is left uncompressed under its .debug name.
					if isZdebug {
						if sec.Flags&elf.SHF_COMPRESSED != 0 {
							t.Errorf("%s: GNU compression must not set SHF_COMPRESSED", sec.Name)
						}
					} else if sec.Flags&elf.SHF_COMPRESSED != 0 || bytes.HasPrefix(sec.Data, []byte("ZLIB")) {
						t.Errorf("%s: still compressed, want GNU .zdebug form", sec.Name)
					}
				} else if isZdebug {
					t.Errorf("%s: still uses the GNU .zdebug name", sec.Name)
				}
				if tc.second == "" {
					continue
				}
				if !tc.gnuOut && sec.Flags&elf.SHF_COMPRESSED == 0 && sec.Size > 0 {
					t.Logf("%s: emitted uncompressed", sec.Name)
				}
			}
			got := classConvDebugContents(t, f)
			if len(got) != len(want) {
				t.Fatalf("debug section count %d != %d", len(got), len(want))
			}
			for name, data := range want {
				if !bytes.Equal(got[name], data) {
					t.Errorf("debug section %s: contents changed (%d vs %d bytes)", name, len(got[name]), len(data))
				}
			}

			// The converted output must parse with readelf too.
			classConvReadelfClass(t, classConvTool(t, "readelf"), out, tc.class)
		})
	}
}

// classConvDebugContents expands every debug section so that a converted file
// can be compared with its input regardless of the compression wrapper.
func classConvDebugContents(t *testing.T, f *elf.File) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	order := f.Data.Order()
	for _, sec := range f.Sections {
		name := sec.Name
		var raw []byte
		switch {
		case sec.Flags&elf.SHF_COMPRESSED != 0:
			hdr := 12
			if f.Class == elf.Class64 {
				hdr = 24
			}
			if len(sec.Data) < hdr {
				t.Fatalf("%s: truncated compression header", sec.Name)
			}
			if order.Uint32(sec.Data[0:]) != 1 {
				t.Fatalf("%s: unsupported compression type", sec.Name)
			}
			// Align/name handling is checked elsewhere; only contents matter.
			raw = classConvUnzlib(t, sec.Name, sec.Data[hdr:])
			name = ".debug" + strings.TrimPrefix(name, ".debug")
		case strings.HasPrefix(name, ".zdebug"):
			if len(sec.Data) < 12 || string(sec.Data[:4]) != "ZLIB" {
				t.Fatalf("%s: bad ZLIB header", sec.Name)
			}
			raw = classConvUnzlib(t, sec.Name, sec.Data[12:])
			name = ".debug" + strings.TrimPrefix(name, ".zdebug")
		case strings.HasPrefix(name, ".debug"):
			raw = sec.Data
		default:
			continue
		}
		out[name] = raw
	}
	return out
}

func classConvUnzlib(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	raw, err := classConvZlibReader(data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return raw
}

// ---- small helpers -------------------------------------------------------

func classConvZlibReader(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func classConvTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("required tool %q not found", name)
	}
	return p
}

func classConvRun(t *testing.T, binary string, args ...string) string {
	t.Helper()
	out, err := exec.Command(binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", binary, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func classConvReadelfClass(t *testing.T, readelf, path string, class elf.Class) {
	t.Helper()
	out := classConvRun(t, readelf, "-h", path)
	want := "ELF64"
	if class == elf.Class32 {
		want = "ELF32"
	}
	if !strings.Contains(out, "Class:                             "+want) {
		t.Errorf("%s: readelf does not report %s:\n%s", path, want, out)
	}
}

// classConvReadelfParses requires readelf to decode the converted file's
// headers, sections, symbols and relocations without errors.  Raw readelf
// output is not compared across classes: its column widths follow the class.
func classConvReadelfParses(t *testing.T, readelf, path string, class elf.Class) {
	t.Helper()
	classConvReadelfClass(t, readelf, path, class)
	for _, args := range [][]string{
		{"-h", "--wide"},
		{"-S", "--wide"},
		{"-s", "--wide"},
		{"-r", "--wide"},
	} {
		classConvRun(t, readelf, append(append([]string(nil), args...), path)...)
	}
}

func classConvWrite(t *testing.T, data []byte, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestClassConvertGNUPropertyNote checks the class-sized .note.gnu.property
// layout: ELF64 aligns each property to 8 bytes, ELF32 to 4, and the property
// list is emitted sorted by type (as BFD does).
func TestClassConvertGNUPropertyNote(t *testing.T) {
	note := func(descsz uint32) []byte {
		b := make([]byte, 16+descsz)
		binary.LittleEndian.PutUint32(b[0:], 4)
		binary.LittleEndian.PutUint32(b[4:], descsz)
		binary.LittleEndian.PutUint32(b[8:], 5) // NT_GNU_PROPERTY_TYPE_0
		copy(b[12:16], "GNU\x00")
		return b
	}
	// Two x86 properties in reverse type order: 0xc0000002 (FEATURE_1_AND)
	// then 0xc0000001 (ISA_1_USED), each 4 bytes, padded to 8.
	prop64 := note(32)
	binary.LittleEndian.PutUint32(prop64[16:], 0xc0000002)
	binary.LittleEndian.PutUint32(prop64[20:], 4)
	binary.LittleEndian.PutUint32(prop64[24:], 4)
	binary.LittleEndian.PutUint32(prop64[32:], 0xc0000001)
	binary.LittleEndian.PutUint32(prop64[36:], 4)
	binary.LittleEndian.PutUint32(prop64[40:], 1)

	f := &elf.File{
		Header: elf.Header{
			Class: elf.Class64, Data: elf.DataLSB, Type: elf.ET_REL,
			Machine: elf.EM_X86_64, Version: elf.EV_CURRENT,
		},
		Shstrndx: 2,
		Sections: []*elf.Section{
			{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}},
			{SectionHeader: elf.SectionHeader{
				Name: ".note.gnu.property", Type: elf.SHT_NOTE,
				Flags: elf.SHF_ALLOC, Addralign: 8,
			}, Data: prop64},
			{SectionHeader: elf.SectionHeader{
				Name: ".shstrtab", Type: elf.SHT_STRTAB, Addralign: 1,
			}},
		},
		SectionHeadersPresent: true,
	}

	if err := f.ConvertClass(elf.Class32); err != nil {
		t.Fatalf("convert to ELF32: %v", err)
	}
	sec := f.Sections[1]
	// _bfd_elf_convert_gnu_properties sets the alignment to the x32 class
	// word.
	if sec.Addralign != 4 {
		t.Errorf("ELF32 property note alignment = %d, want 4", sec.Addralign)
	}
	if got, want := parseGNUProps(t, sec.Data, 4), []gnuProp{
		{0xc0000001, 1}, {0xc0000002, 4},
	}; !reflect.DeepEqual(got, want) {
		t.Errorf("ELF32 properties = %+v, want %+v", got, want)
	}
	if sec.Size != uint64(len(sec.Data)) {
		t.Errorf("size = %d, data = %d", sec.Size, len(sec.Data))
	}
	// ELF64 aligns each property to 8 bytes and sorts by type.
	if err := f.ConvertClass(elf.Class64); err != nil {
		t.Fatalf("convert back to ELF64: %v", err)
	}
	sec = f.Sections[1]
	if sec.Addralign != 8 {
		t.Errorf("ELF64 property note alignment = %d, want 8", sec.Addralign)
	}
	if got, want := parseGNUProps(t, sec.Data, 8), []gnuProp{
		{0xc0000001, 1}, {0xc0000002, 4},
	}; !reflect.DeepEqual(got, want) {
		t.Errorf("ELF64 properties = %+v, want %+v", got, want)
	}
}

type gnuProp struct {
	typ uint32
	val uint32
}

func parseGNUProps(t *testing.T, b []byte, align int) []gnuProp {
	t.Helper()
	if len(b) < 16 {
		t.Fatalf("note too short: %d", len(b))
	}
	order := binary.LittleEndian
	namesz := order.Uint32(b[0:])
	descsz := order.Uint32(b[4:])
	typ := order.Uint32(b[8:])
	if namesz != 4 || typ != 5 || string(b[12:16]) != "GNU\x00" {
		t.Fatalf("bad note header: namesz=%d type=%d name=%q", namesz, typ, b[12:16])
	}
	if uint64(descsz) > uint64(len(b)-16) {
		t.Fatalf("descsz %d exceeds note size %d", descsz, len(b))
	}
	desc := b[16 : 16+descsz]
	var out []gnuProp
	for off := 0; off+8 <= len(desc); {
		pt := order.Uint32(desc[off:])
		ds := int(order.Uint32(desc[off+4:]))
		off += 8
		if ds != 4 || off+ds > len(desc) {
			t.Fatalf("bad property type=%#x datasz=%d", pt, ds)
		}
		out = append(out, gnuProp{typ: pt, val: order.Uint32(desc[off:])})
		off = (off + ds + align - 1) / align * align
	}
	return out
}

// TestClassConvertGNUPropertyMerge mirrors binutils-all/x86-64/pr23494: an
// object can hold several NT_GNU_PROPERTY_TYPE_0 notes whose properties BFD
// merges into one note on class conversion, sorting by type and ORing
// duplicate x86 properties.
func TestClassConvertGNUPropertyMerge(t *testing.T) {
	order := binary.LittleEndian
	// One property entry: type, datasz, value, padded to 8 bytes.
	entry := func(typ, val uint32) []byte {
		b := make([]byte, 16)
		order.PutUint32(b[0:], typ)
		order.PutUint32(b[4:], 4)
		order.PutUint32(b[8:], val)
		return b
	}
	note := func(entries ...[]byte) []byte {
		var desc []byte
		for _, e := range entries {
			desc = append(desc, e...)
		}
		b := make([]byte, 16+len(desc))
		order.PutUint32(b[0:], 4)
		order.PutUint32(b[4:], uint32(len(desc)))
		order.PutUint32(b[8:], 5) // NT_GNU_PROPERTY_TYPE_0
		copy(b[12:16], "GNU\x00")
		copy(b[16:], desc)
		return b
	}
	var data []byte
	data = append(data, note(entry(0xc0010002, 0xa))...)                     // ISA_USED
	data = append(data, note(entry(0xc0008002, 0xa0))...)                    // ISA_NEEDED
	data = append(data, note(entry(0xc0010002, 0xa0))...)                    // ISA_USED
	data = append(data, note(entry(0xc0010002, 0), entry(0xc0010001, 1))...) // + FEATURE_2_USED

	f := &elf.File{
		Header: elf.Header{
			Class: elf.Class64, Data: elf.DataLSB, Type: elf.ET_REL,
			Machine: elf.EM_X86_64, Version: elf.EV_CURRENT,
		},
		Shstrndx: 2,
		Sections: []*elf.Section{
			{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}},
			{SectionHeader: elf.SectionHeader{
				Name: ".note.gnu.property", Type: elf.SHT_NOTE,
				Flags: elf.SHF_ALLOC, Addralign: 8,
			}, Data: data},
			{SectionHeader: elf.SectionHeader{
				Name: ".shstrtab", Type: elf.SHT_STRTAB, Addralign: 1,
			}},
		},
		SectionHeadersPresent: true,
	}
	want := []gnuProp{
		{0xc0008002, 0xa0},
		{0xc0010001, 1},
		{0xc0010002, 0xaa},
	}
	if err := f.ConvertClass(elf.Class32); err != nil {
		t.Fatalf("convert to ELF32: %v", err)
	}
	sec := f.Sections[1]
	if got := parseGNUProps(t, sec.Data, 4); !reflect.DeepEqual(got, want) {
		t.Errorf("ELF32 properties = %+v, want %+v", got, want)
	}
	if sec.Addralign != 4 {
		t.Errorf("ELF32 alignment = %d, want 4", sec.Addralign)
	}
	if wantSize := uint64(16 + 3*12); sec.Size != wantSize {
		t.Errorf("ELF32 note size = %d, want %d", sec.Size, wantSize)
	}
	if err := f.ConvertClass(elf.Class64); err != nil {
		t.Fatalf("convert back to ELF64: %v", err)
	}
	sec = f.Sections[1]
	if got := parseGNUProps(t, sec.Data, 8); !reflect.DeepEqual(got, want) {
		t.Errorf("ELF64 properties = %+v, want %+v", got, want)
	}
	if sec.Addralign != 8 {
		t.Errorf("ELF64 alignment = %d, want 8", sec.Addralign)
	}
	if wantSize := uint64(16 + 3*16); sec.Size != wantSize {
		t.Errorf("ELF64 note size = %d, want %d", sec.Size, wantSize)
	}
}

// ---- failure cases -------------------------------------------------------

func TestClassConvertRejectsOverflow(t *testing.T) {
	fx := classConvFixtures(t)
	path := classConvFixture(t, fx, "reloc.o")
	cases := []struct {
		name   string
		mutate func(*elf.File)
	}{
		{"entry", func(f *elf.File) { f.Entry = 1 << 33 }},
		{"section-addr", func(f *elf.File) { f.Sections[1].Addr = 1 << 32 }},
		{"section-size", func(f *elf.File) { f.Sections[1].Size = 1 << 32 }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f, err := elf.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(f)
			if err := f.ConvertClass(elf.Class32); err == nil {
				t.Fatalf("ConvertClass succeeded, want overflow error")
			}
		})
	}
}

func TestClassConvertRejectsLargeFlag(t *testing.T) {
	fx := classConvFixtures(t)
	path := classConvFixture(t, fx, "reloc.o")
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Sections[1].Flags |= elf.SHF_X86_64_LARGE
	err = f.ConvertClass(elf.Class32)
	if err == nil {
		t.Fatal("ConvertClass succeeded, want large-flag error")
	}
	if !strings.Contains(err.Error(), "'large' flag is ELF x86-64 specific") {
		t.Fatalf("error = %q", err)
	}
}

func TestClassConvertRejectsNonRelocatable(t *testing.T) {
	fx := classConvFixtures(t)
	path := classConvFixture(t, fx, "reloc.o")
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Type = elf.ET_DYN
	if err := f.ConvertClass(elf.Class32); err == nil {
		t.Fatal("ConvertClass succeeded on ET_DYN input")
	}
}

// findNote returns the .note.gnu.property section, or nil.
func findNote(t *testing.T, f *elf.File) *elf.Section {
	t.Helper()
	for _, sec := range f.Sections {
		if sec.Name == ".note.gnu.property" && sec.Type == elf.SHT_NOTE {
			return sec
		}
	}
	return nil
}

// TestClassConvertPropertyNote pins the exact layout BFD uses when converting
// an object that carries a GNU property note: the x32 form packs the
// descriptor on 4-byte boundaries but keeps sh_addralign 8, and converting
// back restores the original 64-bit encoding.
func TestClassConvertPropertyNote(t *testing.T) {
	fx := classConvFixtures(t)
	path := classConvFixture(t, fx, "reloc-cfp.o")

	orig, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	origNote := findNote(t, orig)
	if origNote == nil {
		t.Skip("host compiler did not emit .note.gnu.property")
	}
	if origNote.Size != 32 || origNote.Addralign != 8 {
		t.Fatalf("unexpected input note: size=%d align=%d", origNote.Size, origNote.Addralign)
	}
	origData := []byte(origNote.Data)

	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.ConvertClass(elf.Class32); err != nil {
		t.Fatalf("convert to 32: %v", err)
	}
	midNote := findNote(t, f)
	if midNote == nil {
		t.Fatal("property note disappeared")
	}
	wantX32 := []byte{
		0x04, 0, 0, 0, 0x0c, 0, 0, 0, 0x05, 0, 0, 0,
		'G', 'N', 'U', 0,
		0x02, 0, 0, 0xc0, 0x04, 0, 0, 0, 0x03, 0, 0, 0,
	}
	if midNote.Size != 28 {
		t.Errorf("x32 note size = %d, want 28", midNote.Size)
	}
	if midNote.Addralign != 4 {
		t.Errorf("x32 note alignment = %d, want 4", midNote.Addralign)
	}
	if got := []byte(midNote.Data); !bytes.Equal(got, wantX32) {
		t.Errorf("x32 note data = %x, want %x", got, wantX32)
	}

	mid, err := f.Bytes()
	if err != nil {
		t.Fatalf("serialise x32: %v", err)
	}
	g, err := elf.Parse(mid)
	if err != nil {
		t.Fatalf("reparse x32: %v", err)
	}
	if err := g.ConvertClass(elf.Class64); err != nil {
		t.Fatalf("convert back: %v", err)
	}
	backNote := findNote(t, g)
	if backNote == nil {
		t.Fatal("property note disappeared on the way back")
	}
	if backNote.Size != 32 || backNote.Addralign != 8 {
		t.Errorf("round-tripped note size/align = %d/%d, want 32/8", backNote.Size, backNote.Addralign)
	}
	if got := []byte(backNote.Data); !bytes.Equal(got, origData) {
		t.Errorf("round-tripped note data = %x, want %x", got, origData)
	}

	// Compare the x32 form with GNU objcopy when it is available.
	gnu, err := exec.LookPath("objcopy")
	if err != nil {
		t.Log("objcopy not found; skipping GNU parity check")
		return
	}
	out := filepath.Join(t.TempDir(), "gnu32.o")
	cmd := exec.Command(gnu, "-O", "elf32-x86-64", path, out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("GNU objcopy cannot convert this object: %v\n%s", err, b)
	}
	ref, err := elf.Open(out)
	if err != nil {
		t.Fatalf("parse GNU output: %v", err)
	}
	refNote := findNote(t, ref)
	if refNote == nil {
		t.Fatal("GNU output lost the property note")
	}
	// GNU is inconsistent about sh_addralign here (8 for compiler-produced
	// objects, 4 for assembled ones), so only size and payload are compared.
	if refNote.Size != midNote.Size ||
		!bytes.Equal([]byte(refNote.Data), []byte(midNote.Data)) {
		t.Errorf("x32 note differs from GNU: GNU size/align/data %d/%d/%x, ours %d/%d/%x",
			refNote.Size, refNote.Addralign, []byte(refNote.Data),
			midNote.Size, midNote.Addralign, []byte(midNote.Data))
	}
}
