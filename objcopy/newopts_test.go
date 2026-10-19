package objcopy

// Tests for the last pure-ELF GNU objcopy options: section/symbol prefixes,
// --extract-symbol and --alt-machine-code. The expected values were taken from
// binutils 2.44 (see docs/gnu-objcopy-behavior.md).

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

// newOptsELF builds a relocatable image with .text, .rela.text, .data and a
// symbol table, which is enough to observe every naming rule.
func newOptsELF(t *testing.T) *elf.File {
	t.Helper()
	f := covELF(
		covData(".text", 0x1000, []byte{1, 2, 3, 4}),
		&elf.Section{
			SectionHeader: elf.SectionHeader{
				Name:      ".rela.text",
				Type:      elf.SHT_RELA,
				Flags:     elf.SHF_INFO_LINK,
				Addralign: 8,
				Entsize:   24,
				Info:      1,
				Link:      4,
			},
		},
		&elf.Section{
			SectionHeader: elf.SectionHeader{
				Name:      ".data",
				Type:      elf.SHT_PROGBITS,
				Flags:     elf.SHF_WRITE,
				Addr:      0x2000,
				Addralign: 1,
				Size:      2,
			},
			Data: []byte{0xaa, 0xbb},
		},
	)
	symtab := covSymtab(f, []elf.Symbol{
		{},
		{Name: "src.c", Info: elf.STT_FILE | elf.STB_LOCAL<<4, Shndx: elf.SHN_ABS},
		{Name: "loc", Info: elf.STT_FUNC | elf.STB_LOCAL<<4, Shndx: 1, Value: 0x1000},
		{Name: "glob", Info: elf.STT_OBJECT | elf.STB_GLOBAL<<4, Shndx: 3, Value: 0x2000},
		{Name: "undef", Info: elf.STT_NOTYPE | elf.STB_GLOBAL<<4, Shndx: elf.SHN_UNDEF},
		{Info: elf.STT_SECTION | elf.STB_LOCAL<<4, Shndx: 1},
	})
	// The relocation section was created before the symbol table; re-point its
	// sh_link at it now that the index is known.
	rel := f.Section(".rela.text")
	rel.Link = uint32(f.SectionIndex(symtab))
	// A real (non-empty) relocation keeps applySymbols from dropping the
	// empty relocation section during its "no relocations left" cleanup.
	if err := f.SetRelocs(rel, []elf.Reloc{{Offset: 0, Sym: 3, Type: 1}}); err != nil {
		t.Fatalf("SetRelocs: %v", err)
	}
	return f
}

func sectionNames(f *elf.File) map[string]string {
	out := map[string]string{}
	for _, s := range f.Sections {
		if s.Name != "" {
			out[s.Name] = s.Name
		}
	}
	return out
}

func TestPrefixSectionsGNU(t *testing.T) {
	f := newOptsELF(t)
	c := Default()
	c.PrefixSections = "foo_"
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"foo_.text", "foo_.data"} {
		if f.Section(want) == nil {
			t.Errorf("missing prefixed section %q; have %v", want, sectionNames(f))
		}
	}
	// BFD rebuilds the relocation name from the target's output name, so
	// there is no dot between ".rela" and "foo_".
	if f.Section(".relafoo_.text") == nil {
		t.Errorf("relocation section is not .relafoo_.text; have %v", sectionNames(f))
	}
	if f.Section(".rela.text") != nil || f.Section("foo_.rela.text") != nil {
		t.Errorf("unexpected relocation section name; have %v", sectionNames(f))
	}
	// BFD-created bookkeeping tables are never prefixed.
	for _, name := range []string{".symtab", ".strtab"} {
		if f.Section(name) == nil {
			t.Errorf("bookkeeping section %s was renamed; have %v", name, sectionNames(f))
		}
	}
	// A section symbol has no name of its own and displays the prefixed
	// section name through its shndx.
	st, err := f.ReadSymtab(f.SectionByType(elf.SHT_SYMTAB))
	if err != nil {
		t.Fatal(err)
	}
	for _, sym := range st.Entries {
		if sym.Type() == elf.STT_SECTION {
			if sym.Name != "" {
				t.Errorf("section symbol name = %q, want empty", sym.Name)
			}
			if got := f.Sections[sym.Shndx].Name; got != "foo_.text" {
				t.Errorf("section symbol points at %q, want foo_.text", got)
			}
			return
		}
	}
	t.Error("no section symbol found")
}

func TestPrefixAllocSectionsGNU(t *testing.T) {
	f := newOptsELF(t)
	c := Default()
	c.PrefixAllocSections = "al_"
	c.PrefixSections = "gen_"
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	// .text is SHF_ALLOC in the input; .data is only SHF_WRITE.
	if f.Section("al_.text") == nil || f.Section("gen_.data") == nil {
		t.Errorf("alloc prefix selection wrong; have %v", sectionNames(f))
	}
	if f.Section(".relaal_.text") == nil {
		t.Errorf("relocation did not follow the alloc prefix; have %v", sectionNames(f))
	}
}

func TestPrefixAllocUsesInputFlags(t *testing.T) {
	f := newOptsELF(t)
	// --set-section-flags clears SHF_ALLOC, but GNU chooses the prefix from
	// the input section's flags before this list is applied.
	c := Default()
	c.PrefixAllocSections = "al_"
	c.PrefixSections = "gen_"
	c.SetSectionFlags = []SectionFlags{
		{Name: ".text", Flags: "alloc,code"},
		{Name: ".data", Flags: "alloc,data"},
	}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if f.Section("al_.text") == nil {
		t.Errorf(".text lost its alloc prefix after --set-section-flags; have %v", sectionNames(f))
	}
	if f.Section("gen_.data") == nil || f.Section("al_.data") != nil {
		t.Errorf(".data should use the generic prefix because its input flag was clear; have %v", sectionNames(f))
	}
}

func TestPrefixSectionsAfterRename(t *testing.T) {
	f := newOptsELF(t)
	c := Default()
	c.Renames = []Rename{{Old: ".text", New: ".mytext"}}
	c.PrefixSections = "foo_"
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if f.Section("foo_.mytext") == nil || f.Section(".relafoo_.mytext") == nil {
		t.Errorf("prefix must apply to the renamed name; have %v", sectionNames(f))
	}
}

func TestPrefixSectionsMatchingUsesInputNames(t *testing.T) {
	f := newOptsELF(t)
	c := Default()
	c.PrefixSections = "foo_"
	c.RemoveSections = []string{".text"}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if f.Section("foo_.text") != nil {
		t.Errorf("-R .text matched after prefixing; have %v", sectionNames(f))
	}
}

func TestPrefixSectionsSkipsSynthetic(t *testing.T) {
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload")
	if err := os.WriteFile(payload, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := newOptsELF(t)
	c := Default()
	c.PrefixSections = "foo_"
	c.AddSections = []AddSection{{Name: ".added", File: payload}}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	// GNU creates --add-section after section naming.
	if f.Section(".added") == nil || f.Section("foo_.added") != nil {
		t.Errorf("--add-section section was prefixed; have %v", sectionNames(f))
	}
}

func TestPrefixSymbolsGNU(t *testing.T) {
	f := newOptsELF(t)
	c := Default()
	c.PrefixSymbols = "bar_"
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	st, err := f.ReadSymtab(f.SectionByType(elf.SHT_SYMTAB))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"bar_src.c": true, // STT_FILE
		"bar_loc":   true, // local
		"bar_glob":  true, // global
		"bar_undef": true, // undefined
	}
	got := map[string]bool{}
	for _, sym := range st.Entries {
		if sym.Name != "" {
			got[sym.Name] = true
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("missing prefixed symbol %q; have %v", name, got)
		}
	}
	if got["src.c"] || got["loc"] || got["glob"] || got["undef"] {
		t.Errorf("unprefixed symbol survived: %v", got)
	}
}

func TestPrefixSymbolsAndSectionsIndependent(t *testing.T) {
	f := newOptsELF(t)
	c := Default()
	c.PrefixSections = "foo_"
	c.PrefixSymbols = "bar_"
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if f.Section("foo_.text") == nil {
		t.Errorf("section prefix missing; sections=%v", sectionNames(f))
	}
	st, err := f.ReadSymtab(f.SectionByType(elf.SHT_SYMTAB))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sym := range st.Entries {
		if sym.Name == "bar_glob" {
			found = true
		}
	}
	if !found {
		t.Error("symbol prefix missing while section prefix is active")
	}
}

func TestPrefixSymbolsAfterRedefine(t *testing.T) {
	f := newOptsELF(t)
	c := Default()
	c.Redefines = []Redefine{{Old: "loc", New: "renamed"}}
	c.PrefixSymbols = "bar_"
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	st, err := f.ReadSymtab(f.SectionByType(elf.SHT_SYMTAB))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sym := range st.Entries {
		if sym.Name == "bar_renamed" {
			found = true
		}
		if sym.Name == "bar_loc" || sym.Name == "renamed" {
			t.Errorf("unexpected symbol name %q", sym.Name)
		}
	}
	if !found {
		t.Error("--prefix-symbols did not apply after --redefine-sym")
	}
}

func TestPrefixSymbolsSkipsAddedSymbols(t *testing.T) {
	f := newOptsELF(t)
	c := Default()
	c.PrefixSymbols = "bar_"
	c.AddSymbols = []AddSymbol{{Name: "NEW", Value: 0x1234}}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	st, err := f.ReadSymtab(f.SectionByType(elf.SHT_SYMTAB))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sym := range st.Entries {
		if sym.Name == "NEW" {
			found = true
		}
		if sym.Name == "bar_NEW" {
			t.Error("--add-symbol symbol was prefixed")
		}
	}
	if !found {
		t.Error("--add-symbol symbol disappeared")
	}
}

func TestExtractSymbolGNU(t *testing.T) {
	f := newOptsELF(t)
	f.Entry = 0x1234
	before := len(f.Sections)
	c := Default()
	c.ExtractSymbol = true
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if f.Entry != 0 {
		t.Errorf("entry = %#x, want 0", f.Entry)
	}
	if len(f.Sections) != before {
		t.Errorf("section count changed: %d -> %d", before, len(f.Sections))
	}
	for _, s := range f.Sections {
		switch s.Name {
		case "", ".symtab", ".strtab":
			continue
		}
		if s.Size != 0 || len(s.Data) != 0 {
			t.Errorf("section %s not emptied: size=%d data=%d", s.Name, s.Size, len(s.Data))
		}
	}
	// Type, flags and address survive; the symbol table keeps every entry.
	if s := f.Section(".text"); s.Type != elf.SHT_PROGBITS || s.Flags&elf.SHF_ALLOC == 0 || s.Addr != 0x1000 {
		t.Errorf(".text metadata changed: %+v", s.SectionHeader)
	}
	st, err := f.ReadSymtab(f.SectionByType(elf.SHT_SYMTAB))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Entries) != 6 {
		t.Errorf("symbol entries = %d, want 6 (symbols must be preserved)", len(st.Entries))
	}
}

func TestExtractSymbolKeepsAddedSections(t *testing.T) {
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload")
	if err := os.WriteFile(payload, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := newOptsELF(t)
	c := Default()
	c.ExtractSymbol = true
	c.AddSections = []AddSection{{Name: ".added", File: payload}}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	sec := f.Section(".added")
	if sec == nil {
		t.Fatal("added section disappeared")
	}
	// GNU creates added sections after the copy, so --extract-symbol leaves
	// their contents alone.
	if sec.Size != 5 || string(sec.Data) != "hello" {
		t.Errorf("added section was emptied: size=%d data=%q", sec.Size, sec.Data)
	}
}

func TestExtractSymbolKeepsSymbolReferences(t *testing.T) {
	f := newOptsELF(t)
	c := Default()
	c.ExtractSymbol = true
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	st, err := f.ReadSymtab(f.SectionByType(elf.SHT_SYMTAB))
	if err != nil {
		t.Fatal(err)
	}
	for _, sym := range st.Entries {
		if sym.Shndx == elf.SHN_UNDEF || sym.Shndx >= elf.SHN_LORESERVE {
			continue
		}
		if int(sym.Shndx) >= len(f.Sections) {
			t.Errorf("symbol %q has stale shndx %d", sym.Name, sym.Shndx)
		}
	}
}

func TestAltMachineCodeWarnings(t *testing.T) {
	f := newOptsELF(t)
	var warnings []string
	c := Default()
	c.AltMachineCode = 40
	c.Warnf = func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if f.Machine != 40 {
		t.Errorf("machine = %d, want 40", f.Machine)
	}
	want := []string{
		"this target does not support 40 alternative machine codes",
		"treating that number as an absolute e_machine value instead",
	}
	if len(warnings) != len(want) {
		t.Fatalf("warnings = %#v, want %#v", warnings, want)
	}
	for i := range want {
		if warnings[i] != want[i] {
			t.Errorf("warning %d = %q, want %q", i, warnings[i], want[i])
		}
	}
}

func TestAltMachineCodeTruncates(t *testing.T) {
	f := newOptsELF(t)
	c := Default()
	c.AltMachineCode = 70000
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	// e_machine is a 16-bit field; GNU assigns the unsigned long directly and
	// the compiler truncates it.
	want := uint16(70000 % 65536)
	if f.Machine != want {
		t.Errorf("machine = %#x, want %#x", f.Machine, want)
	}
}

func TestAltMachineCodeZeroIsUnset(t *testing.T) {
	f := newOptsELF(t)
	f.Machine = 62
	var warnings int
	c := Default()
	c.Warnf = func(string, ...any) { warnings++ }
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if f.Machine != 62 || warnings != 0 {
		t.Errorf("zero AltMachineCode changed machine=%d warnings=%d", f.Machine, warnings)
	}
}

func TestRenameSectionUpdatesRelocation(t *testing.T) {
	f := newOptsELF(t)
	c := Default()
	c.Renames = []Rename{{Old: ".text", New: ".mytext"}}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if f.Section(".rela.mytext") == nil {
		t.Errorf("relocation section did not follow the rename; have %v", sectionNames(f))
	}
}
