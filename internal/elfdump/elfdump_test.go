package elfdump_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/elfdump"
)

// sample builds an in-memory ELF model with enough variety to exercise every
// branch of Dump: sections with and without names for link/info, hashable and
// unhashable contents, two symbol tables, good and malformed relocations, and
// a mix of segment types.
func sample(t *testing.T) *elf.File {
	t.Helper()

	strtab := func(name string, data []byte) *elf.Section {
		return &elf.Section{SectionHeader: elf.SectionHeader{
			Name: name, Type: elf.SHT_STRTAB, Addralign: 1,
		}, Data: data}
	}
	progbits := func(name string, flags uint64, addr uint64, data []byte) *elf.Section {
		return &elf.Section{SectionHeader: elf.SectionHeader{
			Name: name, Type: elf.SHT_PROGBITS, Flags: flags, Addr: addr,
			Addralign: 8,
		}, Data: data}
	}
	rel := func(name string, typ uint32, link, info uint32) *elf.Section {
		return &elf.Section{SectionHeader: elf.SectionHeader{
			Name: name, Type: typ, Link: link, Info: info, Addralign: 8,
		}}
	}

	secs := []*elf.Section{
		{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}}, // 0
		strtab(".shstrtab", []byte{0}),                         // 1
		strtab(".strtab", nil),                                 // 2
		{SectionHeader: elf.SectionHeader{ // 3
			Name: ".symtab", Type: elf.SHT_SYMTAB, Link: 2, Addralign: 8,
		}},
		strtab(".dynstr", []byte{0}), // 4
		{SectionHeader: elf.SectionHeader{ // 5
			Name: ".dynsym", Type: elf.SHT_DYNSYM, Link: 4, Addralign: 8,
		}},
		progbits(".text", elf.SHF_ALLOC|elf.SHF_EXECINSTR, 0x401000, []byte("code")), // 6
		progbits(".data", elf.SHF_ALLOC|elf.SHF_WRITE, 0x402000, []byte("data")),     // 7
		rel(".rela.text", elf.SHT_RELA, 3, 6),                                        // 8
		rel(".rel.text", elf.SHT_REL, 3, 6),                                          // 9
		rel(".rela.badlink", elf.SHT_RELA, 999, 999),                                 // 10
		progbits(".gnu_debuglink", 0, 0, []byte("debug\x00\x01\x02\x03")),            // 11
		progbits(".gnu_debugaltlink", 0, 0, []byte("alt\x00")),                       // 12
		progbits(".compressed", elf.SHF_COMPRESSED, 0, []byte("compressed")),         // 13
		strtab(".otherstr", []byte{0, 'x', 0}),                                       // 14
		{SectionHeader: elf.SectionHeader{ // 15
			Name: ".group", Type: elf.SHT_GROUP, Info: 6,
		}},
		{SectionHeader: elf.SectionHeader{ // 16
			Name: ".bad.symtab", Type: elf.SHT_SYMTAB, Link: 2,
		}, Data: []byte{1, 2, 3}},
		rel(".rela.bad", elf.SHT_RELA, 3, 6), // 17
		{SectionHeader: elf.SectionHeader{ // 18
			Name: ".nobits", Type: elf.SHT_NOBITS, Flags: elf.SHF_ALLOC,
			Addr: 0x403000, Size: 16,
		}},
		{SectionHeader: elf.SectionHeader{ // 19
			Name: ".info_link", Type: elf.SHT_PROGBITS,
			Flags: elf.SHF_INFO_LINK, Info: 6,
		}, Data: []byte("info")},
		rel(".rela.noinfo", elf.SHT_RELA, 3, 999),    // 20
		rel(".rela.badsymlink", elf.SHT_RELA, 16, 6), // 21
	}

	f := &elf.File{
		Header: elf.Header{
			Class:   elf.Class64,
			Data:    elf.DataLSB,
			OSABI:   elf.ELFOSABI_GNU,
			Type:    elf.ET_DYN,
			Machine: elf.EM_X86_64,
			Version: elf.EV_CURRENT,
			Entry:   0x401000,
			Flags:   0x5,
		},
		Sections: secs,
		Segments: []*elf.ProgramHeader{
			{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Offset: 0, Vaddr: 0x400000, Filesz: 0x3000, Memsz: 0x3000, Align: 0x1000},
			{Type: elf.PT_DYNAMIC, Flags: elf.PF_R | elf.PF_W, Offset: 0x2000, Vaddr: 0x402000, Filesz: 0x100, Memsz: 0x100, Align: 8},
			{Type: elf.PT_GNU_RELRO, Flags: elf.PF_R, Offset: 0x2000, Vaddr: 0x402000, Filesz: 0x100, Memsz: 0x100, Align: 8},
			{Type: elf.PT_NOTE, Flags: elf.PF_R, Offset: 0x3000, Vaddr: 0x404000, Filesz: 0x20, Memsz: 0x20, Align: 4},
		},
	}

	mksym := func(name string, bind, typ byte, shndx uint16, value, size uint64, vis byte) elf.Symbol {
		s := elf.Symbol{Name: name, Shndx: shndx, Value: value, Size: size}
		s.SetBind(bind)
		s.SetType(typ)
		s.SetVisibility(vis)
		return s
	}
	syms := []elf.Symbol{
		mksym("", elf.STB_LOCAL, elf.STT_NOTYPE, elf.SHN_UNDEF, 0, 0, elf.STV_DEFAULT),
		mksym("foo", elf.STB_GLOBAL, elf.STT_FUNC, 6, 0x401000, 4, elf.STV_DEFAULT),
		mksym("bar", elf.STB_LOCAL, elf.STT_OBJECT, elf.SHN_ABS, 0x10, 8, elf.STV_DEFAULT),
		mksym("baz", elf.STB_WEAK, elf.STT_TLS, elf.SHN_COMMON, 0x20, 16, elf.STV_DEFAULT),
		mksym("qux", elf.STB_GLOBAL, elf.STT_NOTYPE, elf.SHN_UNDEF, 0, 0, elf.STV_DEFAULT),
		mksym("loc", elf.STB_LOCAL, elf.STT_SECTION, elf.SHN_LORESERVE, 0, 0, elf.STV_DEFAULT),
		mksym("out", elf.STB_GLOBAL, elf.STT_OBJECT, 200, 0, 0, elf.STV_DEFAULT),
		mksym("hid", elf.STB_LOCAL, elf.STT_FILE, 6, 0, 0, elf.STV_HIDDEN),
		mksym("prot", elf.STB_GLOBAL, elf.STT_FUNC, 6, 0x401002, 2, elf.STV_PROTECTED),
	}
	if err := f.SetSymtab(&elf.Symtab{Section: secs[3], Entries: syms}); err != nil {
		t.Fatalf("SetSymtab: %v", err)
	}
	dynsyms := []elf.Symbol{
		mksym("", elf.STB_LOCAL, elf.STT_NOTYPE, elf.SHN_UNDEF, 0, 0, elf.STV_DEFAULT),
		mksym("dyn", elf.STB_GLOBAL, elf.STT_FUNC, 6, 0x401000, 4, elf.STV_DEFAULT),
	}
	if err := f.SetSymtab(&elf.Symtab{Section: secs[5], Entries: dynsyms}); err != nil {
		t.Fatalf("SetSymtab(dynsym): %v", err)
	}

	relocSets := []struct {
		sec    *elf.Section
		relocs []elf.Reloc
	}{
		{secs[8], []elf.Reloc{
			{Offset: 0x10, Sym: 1, Type: 1, Addend: 4, HasAddend: true},
			{Offset: 0x20, Sym: 999, Type: 2, Addend: -1, HasAddend: true},
		}},
		{secs[9], []elf.Reloc{{Offset: 8, Sym: 2, Type: 3}}},
		{secs[10], []elf.Reloc{{Offset: 0x30, Sym: 0, Type: 4}}},
		{secs[20], []elf.Reloc{{Offset: 0x40, Sym: 1, Type: 5, Addend: 1, HasAddend: true}}},
		{secs[21], []elf.Reloc{{Offset: 0x50, Sym: 1, Type: 6, Addend: 2, HasAddend: true}}},
	}
	for _, rs := range relocSets {
		if err := f.SetRelocs(rs.sec, rs.relocs); err != nil {
			t.Fatalf("SetRelocs(%s): %v", rs.sec.Name, err)
		}
	}
	// Intentionally leave secs[17].Data malformed so ReadRelocs reports an
	// error instead of decoding it.
	secs[17].Data = []byte{1, 2, 3}
	return f
}

func TestDumpCoversAllFeatures(t *testing.T) {
	f := sample(t)
	opt := elfdump.Options{Offsets: true, Contents: true, IgnoreRelro: false, IgnoreSegments: false}
	got := elfdump.Dump(f, opt)

	for _, want := range []string{
		"header class=2 data=1 osabi=3 abi=0 type=3 machine=62 version=1 entry=0x401000 flags=0x5",
		`section 2: type=3 name=".strtab"`,
		` link=".strtab"`,
		` link=999`,
		` info=".text"`,
		` info=999`,
		`name=".gnu_debuglink"`,
		`name=".gnu_debugaltlink"`,
		`name=".compressed"`,
		`name=".otherstr"`,
		`name=".nobits"`,
		"segment 0: type=1 flags=0x5 vaddr=0x400000 memsz=0x3000 align=0x1000 off=0x0 filesz=0x3000",
		"segment 1: type=2",
		"segment 2: type=1685382482",
		"segment 3: type=4",
		`symtab ".symtab": count=9 info=1`,
		`symtab ".dynsym": count=2`,
		`symtab ".bad.symtab": error`,
		`relocs ".rela.text": target=".text" link=".symtab" count=2`,
		` rel 0: off=0x10 sym="foo" symidx=1 type=1 addend=4`,
		` rel 1: off=0x20 sym="" symidx=999 type=2 addend=-1`,
		`relocs ".rel.text": target=".text" link=".symtab" count=1`,
		`relocs ".rela.badlink": target="" link="999" count=1`,
		`relocs ".rela.noinfo": target="" link=".symtab" count=1`,
		`relocs ".rela.badsymlink": target=".text" link=".bad.symtab" count=1`,
		`relocs ".rela.bad": error`,
		"shndx=UNDEF",
		"shndx=ABS",
		"shndx=COMMON",
		"shndx=0xff00",
		"shndx=6(.text)",
		"shndx=200",
		"sha=",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Dump output does not contain %q\n--- output ---\n%s", want, got)
		}
	}

	// Hash skipping rules.
	if lineFor(got, `name=".gnu_debuglink"`, "sha=") {
		t.Error("Dump hashed .gnu_debuglink")
	}
	if lineFor(got, `name=".gnu_debugaltlink"`, "sha=") {
		t.Error("Dump hashed .gnu_debugaltlink")
	}
	if lineFor(got, `name=".compressed"`, "sha=") {
		t.Error("Dump hashed a SHF_COMPRESSED section")
	}
	if !lineFor(got, `name=".text"`, "sha=") {
		t.Error("Dump did not hash .text")
	}
	if lineFor(got, `name=".nobits"`, "sha=") {
		t.Error("Dump hashed SHT_NOBITS")
	}
	// .strtab/.dynstr/.shstrtab sizes are normalised away.
	if !lineFor(got, `name=".strtab"`, "size=0x0 ") {
		t.Error("Dump did not normalise .strtab size")
	}
	if !lineFor(got, `name=".dynstr"`, "size=0x0 ") {
		t.Error("Dump did not normalise .dynstr size")
	}
}

// lineFor reports whether the line containing marker also contains want.
func lineFor(dump, marker, want string) bool {
	for _, line := range strings.Split(dump, "\n") {
		if strings.Contains(line, marker) {
			return strings.Contains(line, want)
		}
	}
	return false
}

func TestDumpOptionMatrix(t *testing.T) {
	f := sample(t)
	for mask := 0; mask < 16; mask++ {
		opt := elfdump.Options{
			Offsets:        mask&1 != 0,
			Contents:       mask&2 != 0,
			IgnoreRelro:    mask&4 != 0,
			IgnoreSegments: mask&8 != 0,
		}
		name := fmt.Sprintf("mask=%d", mask)
		got := elfdump.Dump(f, opt)
		if !strings.Contains(got, "header class=2") {
			t.Errorf("%s: missing header line", name)
		}
		if strings.Contains(got, "sha=") != opt.Contents {
			t.Errorf("%s: Contents=%v but sha presence=%v", name, opt.Contents, strings.Contains(got, "sha="))
		}
		// Relocation lines always contain "off=", so look at a field only
		// section and segment lines emit when Offsets is enabled.
		sectionOff := strings.Contains(got, " off=0x0 link=")
		if sectionOff != opt.Offsets {
			t.Errorf("%s: Offsets=%v but section off presence=%v", name, opt.Offsets, sectionOff)
		}

		hasSegments := strings.Contains(got, "segment 0:")
		if hasSegments == opt.IgnoreSegments {
			t.Errorf("%s: IgnoreSegments=%v but segment presence=%v", name, opt.IgnoreSegments, hasSegments)
		}
		if !opt.IgnoreSegments {
			hasDynamic := strings.Contains(got, "segment 1: type=2")
			if opt.IgnoreRelro && hasDynamic {
				t.Errorf("%s: IgnoreRelro skipped only LOAD segments, found DYNAMIC", name)
			}
			if !opt.IgnoreRelro && !hasDynamic {
				t.Errorf("%s: IgnoreRelro=false but DYNAMIC segment missing", name)
			}
		}
		hasSymtab := strings.Contains(got, "\nsymtab \"")
		hasRelocs := strings.Contains(got, "\nrelocs \"")
		if opt.IgnoreSegments {
			if hasSymtab || hasRelocs {
				t.Errorf("%s: early return still emitted symtab/relocs", name)
			}
		} else if !hasSymtab || !hasRelocs {
			t.Errorf("%s: missing symtab/reloc output (symtab=%v relocs=%v)", name, hasSymtab, hasRelocs)
		}
	}
}

func TestDefaultOptions(t *testing.T) {
	want := elfdump.Options{Contents: true, IgnoreRelro: true, IgnoreSegments: true}
	if elfdump.Default != want {
		t.Errorf("Default = %+v, want %+v", elfdump.Default, want)
	}
}

func TestFirstDiff(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want string
	}{
		{"equal", "a\nb\nc", "a\nb\nc", ""},
		{"empty", "", "", ""},
		{"first", "a\nb", "x\nb", "line 1:\n  a: a\n  b: x"},
		{"second", "a\nb", "a\nc", "line 2:\n  a: b\n  b: c"},
		{"b-longer", "a", "a\nb", "line 2:\n  a: \n  b: b"},
		{"a-longer", "a\nb", "a", "line 2:\n  a: b\n  b: "},
		{"empty-vs-line", "", "x", "line 1:\n  a: \n  b: x"},
		{"trailing-newline", "a\n", "a\n\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := elfdump.FirstDiff(tt.a, tt.b); got != tt.want {
				t.Errorf("FirstDiff(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// dumpableFile returns the bytes of a small, valid ELF image that DumpFile can
// parse from disk.
func dumpableFile(t *testing.T) []byte {
	t.Helper()
	f := &elf.File{
		Header: elf.Header{
			Class: elf.Class64, Data: elf.DataLSB, Type: elf.ET_REL,
			Machine: elf.EM_X86_64, Version: elf.EV_CURRENT,
		},
		SectionHeadersPresent: true,
		Sections: []*elf.Section{
			{SectionHeader: elf.SectionHeader{Type: elf.SHT_NULL}},
			{
				SectionHeader: elf.SectionHeader{
					Name: ".text", Type: elf.SHT_PROGBITS,
					Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, Addr: 0x1000,
					Addralign: 1,
				},
				Data: []byte("code"),
			},
		},
	}
	b, err := f.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	return b
}

func TestDumpFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.o")
	if err := os.WriteFile(path, dumpableFile(t), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := elfdump.DumpFile(path, elfdump.Default)
	if err != nil {
		t.Fatalf("DumpFile: %v", err)
	}
	if !strings.Contains(got, "header class=2 data=1") {
		t.Errorf("DumpFile output missing header: %q", got)
	}
	if !strings.Contains(got, `name=".text"`) {
		t.Errorf("DumpFile output missing .text: %q", got)
	}

	if _, err := elfdump.DumpFile(filepath.Join(dir, "missing"), elfdump.Default); err == nil {
		t.Error("DumpFile of missing file succeeded, want error")
	}

	bad := filepath.Join(dir, "not-elf")
	if err := os.WriteFile(bad, []byte("not an elf"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := elfdump.DumpFile(bad, elfdump.Default); err == nil {
		t.Error("DumpFile of non-ELF data succeeded, want error")
	}
}
