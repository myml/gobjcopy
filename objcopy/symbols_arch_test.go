package objcopy

// Regression tests for GNU objcopy's section-symbol rules, which are
// architecture dependent:
//
//   - input STT_SECTION symbols are marked BSF_SECTION_SYM_USED, but that does
//     not mean they are kept: filter_symbols only keeps them when a surviving
//     relocation names them (BSF_KEEP) or when no debug stripping was asked
//     for;
//   - non-relocatable outputs get freshly generated section symbols for every
//     output section when the target's keep_unused_section_symbols flag is
//     true (aarch64/loongarch/most targets) or --keep-section-symbols was
//     given, and none otherwise (x86);
//   - a symbol table is only written when GNU's filter_symbols kept at least
//     one symbol, or when a relocatable output still has relocations. With -j
//     that explains both the "null + one section symbol" table and the
//     completely dropped table.
//
// The fixtures are host gcc output, so the tests derive the architecture
// dependent expectations from the same helpers the implementation uses.

import (
	"testing"

	"github.com/myml/gobjcopy/elf"
)

// addTestSection appends a simple PROGBITS section and returns its index.
func addTestSection(t *testing.T, f *elf.File, name string, flags uint64, data []byte) int {
	t.Helper()
	sec := &elf.Section{
		SectionHeader: elf.SectionHeader{
			Name:      name,
			Type:      elf.SHT_PROGBITS,
			Flags:     flags,
			Addralign: 1,
			Size:      uint64(len(data)),
		},
		Data: data,
	}
	if err := f.InsertSection(len(f.Sections), sec); err != nil {
		t.Fatalf("insert section %s: %v", name, err)
	}
	return f.SectionIndex(sec)
}

// addTestSectionSymbol appends a local STT_SECTION symbol for section secIdx
// and returns its symbol table index.
func addTestSectionSymbol(t *testing.T, f *elf.File, secIdx int) int {
	t.Helper()
	symSec := f.SectionByType(elf.SHT_SYMTAB)
	if symSec == nil {
		t.Fatal("fixture has no static symbol table")
	}
	st, err := f.ReadSymtab(symSec)
	if err != nil {
		t.Fatalf("read symtab: %v", err)
	}
	idx := len(st.Entries)
	st.Entries = append(st.Entries, elf.Symbol{
		Info:  elf.STT_SECTION | elf.STB_LOCAL<<4,
		Shndx: uint16(secIdx),
	})
	if err := f.SetSymtab(st); err != nil {
		t.Fatalf("set symtab: %v", err)
	}
	return idx
}

// addTestReloc creates a reloc section for targetSec that names symIdx.
func addTestReloc(t *testing.T, f *elf.File, targetSec, symIdx int) {
	t.Helper()
	symSec := f.SectionByType(elf.SHT_SYMTAB)
	if symSec == nil {
		t.Fatal("fixture has no static symbol table")
	}
	rel := &elf.Section{
		SectionHeader: elf.SectionHeader{
			Name:      ".rela" + f.Sections[targetSec].Name,
			Type:      elf.SHT_RELA,
			Addralign: 8,
			Link:      uint32(f.SectionIndex(symSec)),
			Info:      uint32(targetSec),
		},
	}
	if err := f.InsertSection(len(f.Sections), rel); err != nil {
		t.Fatalf("insert relocation section: %v", err)
	}
	rel.Entsize = uint64(f.RelSize(rel))
	if err := f.SetRelocs(rel, []elf.Reloc{{Sym: uint32(symIdx), Type: 0, HasAddend: true}}); err != nil {
		t.Fatalf("set relocations: %v", err)
	}
}

// staticSectionSymbols returns the static table's STT_SECTION entries.
func staticSectionSymbols(t *testing.T, f *elf.File) []elf.Symbol {
	t.Helper()
	sec := f.SectionByType(elf.SHT_SYMTAB)
	if sec == nil {
		return nil
	}
	st, err := f.ReadSymtab(sec)
	if err != nil {
		t.Fatalf("read symtab: %v", err)
	}
	var out []elf.Symbol
	for _, sym := range st.Entries[1:] {
		if sym.Type() == elf.STT_SECTION {
			out = append(out, sym)
		}
	}
	return out
}

// transformFixture applies prep to a fresh fixture, then runs Transform.
func transformFixture(t *testing.T, name string, prep func(*elf.File), mutate func(*Config)) *elf.File {
	t.Helper()
	f := openFixtureFile(t, name)
	if prep != nil {
		prep(f)
	}
	c := Default()
	if mutate != nil {
		mutate(c)
	}
	if err := Transform(f, c); err != nil {
		t.Fatalf("Transform: %v", err)
	}
	return f
}

// setupSectionSymbolPair gives reloc.o two extra non-debug sections: one whose
// section symbol is named by a relocation, and one whose section symbol is
// not referenced at all.
func setupSectionSymbolPair(t *testing.T, f *elf.File) {
	t.Helper()
	holder := addTestSection(t, f, ".symtest.holder", elf.SHF_ALLOC, make([]byte, 8))
	unused := addTestSection(t, f, ".symtest.unused", elf.SHF_ALLOC, make([]byte, 8))
	keptSym := addTestSectionSymbol(t, f, holder)
	addTestSectionSymbol(t, f, unused)
	addTestReloc(t, f, holder, keptSym)
}

func hasSectionSymbolNamed(f *elf.File, syms []elf.Symbol, name string) bool {
	for _, sym := range syms {
		if int(sym.Shndx) < len(f.Sections) && f.Sections[sym.Shndx].Name == name {
			return true
		}
	}
	return false
}

func TestSectionSymbolsReferencedKeptUnreferencedTrimmed(t *testing.T) {
	f := transformFixture(t, "reloc.o", func(f *elf.File) {
		setupSectionSymbolPair(t, f)
	}, func(c *Config) { c.StripDebug = true })

	syms := staticSectionSymbols(t, f)
	if !hasSectionSymbolNamed(f, syms, ".symtest.holder") {
		t.Errorf("section symbol referenced by a surviving relocation was dropped")
	}
	if hasSectionSymbolNamed(f, syms, ".symtest.unused") {
		t.Errorf("unreferenced section symbol survived -g")
	}
	// The synthetic relocation section survives too: -g only removes debug
	// sections and their relocations.
	if f.Section(".rela.symtest.holder") == nil {
		t.Error("relocation section for a live section was removed")
	}
}

func TestSectionSymbolsStripUnneededKeepsReferenced(t *testing.T) {
	f := transformFixture(t, "reloc.o", func(f *elf.File) {
		setupSectionSymbolPair(t, f)
	}, func(c *Config) { c.StripUnneeded = true })

	syms := staticSectionSymbols(t, f)
	if !hasSectionSymbolNamed(f, syms, ".symtest.holder") {
		t.Errorf("--strip-unneeded dropped a section symbol that is named in a relocation")
	}
	if hasSectionSymbolNamed(f, syms, ".symtest.unused") {
		t.Errorf("--strip-unneeded kept an unreferenced section symbol")
	}
}

func TestSectionSymbolsAllKeptWithoutStripping(t *testing.T) {
	// BFD leaves section symbols alone as long as no debug stripping is in
	// effect, even with -x/-X, because they carry BSF_DEBUGGING.
	for _, mutate := range []func(*Config){
		nil,
		func(c *Config) { c.DiscardAll = true },
		func(c *Config) { c.DiscardLocals = true },
	} {
		f := transformFixture(t, "reloc.o", func(f *elf.File) {
			unused := addTestSection(t, f, ".symtest.unused", elf.SHF_ALLOC, make([]byte, 8))
			addTestSectionSymbol(t, f, unused)
		}, mutate)
		if !hasSectionSymbolNamed(f, staticSectionSymbols(t, f), ".symtest.unused") {
			t.Errorf("unreferenced section symbol dropped without symbol stripping")
		}
	}
}

func TestSectionSymbolsStripAllDropsThem(t *testing.T) {
	f := transformFixture(t, "reloc.o", nil, func(c *Config) { c.StripAll = true })
	if f.SectionByType(elf.SHT_SYMTAB) != nil {
		t.Fatal("--strip-all must drop the static symbol table")
	}
}

func TestKeepSectionSymbolsNonRelocatable(t *testing.T) {
	// --keep-section-symbols only does anything for non-relocatable outputs:
	// it makes BFD mark every output section symbol used, which then get
	// generated by elf_map_symbols.
	f := transformFixture(t, "hello", nil, func(c *Config) {
		c.StripDebug = true
		c.KeepSectionSymbols = true
	})
	syms := staticSectionSymbols(t, f)
	if len(syms) == 0 {
		t.Fatal("--keep-section-symbols did not keep section symbols")
	}
	// One generated section symbol for every real output section.
	symSec := f.SectionByType(elf.SHT_SYMTAB)
	want := 0
	for idx := range f.Sections {
		if sectionSymbolTarget(f, symSec, idx) {
			want++
		}
	}
	if len(syms) != want {
		t.Errorf("--keep-section-symbols kept %d section symbols, want %d", len(syms), want)
	}
	for _, sym := range syms {
		if int(sym.Shndx) >= len(f.Sections) {
			t.Errorf("section symbol with bad shndx %d", sym.Shndx)
			continue
		}
		if got, want := sym.Value, f.Sections[sym.Shndx].Addr; got != want {
			t.Errorf("section symbol %s value = %#x, want %#x", f.Sections[sym.Shndx].Name, got, want)
		}
	}

	// x86 targets have keep_unused_section_symbols = false, so without the
	// option -g must not emit any section symbols at all. Other targets keep
	// them in both cases.
	plain := transformFixture(t, "hello", nil, func(c *Config) { c.StripDebug = true })
	if keepUnusedSectionSymbols(f.Machine) {
		if got, want := len(staticSectionSymbols(t, plain)), want; got != want {
			t.Errorf("target keeps section symbols: got %d, want %d", got, want)
		}
	} else if got := len(staticSectionSymbols(t, plain)); got != 0 {
		t.Errorf("x86 target dropped %d section symbols without --keep-section-symbols", got)
	}
}

func TestKeepSectionSymbolsRelocatableIsIgnored(t *testing.T) {
	// GNU 2.44 does not use keep_section_symbols for relocatable outputs:
	// filter_symbols still drops section symbols under -g and BFD never
	// regenerates them there.
	f := transformFixture(t, "reloc.o", nil, func(c *Config) {
		c.StripDebug = true
		c.KeepSectionSymbols = true
	})
	syms := staticSectionSymbols(t, f)
	for _, sym := range syms {
		if int(sym.Shndx) >= len(f.Sections) {
			t.Errorf("section symbol with bad shndx %d", sym.Shndx)
			continue
		}
		if f.Sections[sym.Shndx].Name == ".symtest.unused" {
			t.Error("--keep-section-symbols resurrected an unreferenced section symbol")
		}
	}
	// The only section symbols that may survive are the ones GNU's filter
	// keeps because a surviving relocation names them; every one of them must
	// be referenced.
	used := make(map[uint32]bool)
	for _, s := range f.Sections {
		if s.Type != elf.SHT_REL && s.Type != elf.SHT_RELA {
			continue
		}
		relocs, err := f.ReadRelocs(s)
		if err != nil {
			t.Fatalf("read relocations: %v", err)
		}
		for _, r := range relocs {
			used[r.Sym] = true
		}
	}
	st, err := f.ReadSymtab(f.SectionByType(elf.SHT_SYMTAB))
	if err != nil {
		t.Fatalf("read symtab: %v", err)
	}
	for i, sym := range st.Entries {
		if sym.Type() != elf.STT_SECTION {
			continue
		}
		if !used[uint32(i)] {
			t.Errorf("unreferenced section symbol %s survived -g", f.Sections[sym.Shndx].Name)
		}
	}
}

func TestOnlySectionsEmptySymtabRules(t *testing.T) {
	// -j keeps the null symbol plus a section symbol that survives filtering:
	// GNU writes a two entry table in that case.
	t.Run("section-symbol-survives", func(t *testing.T) {
		var sec int
		f := transformFixture(t, "reloc.o", func(f *elf.File) {
			sec = addTestSection(t, f, ".symtest.only", elf.SHF_ALLOC, make([]byte, 4))
			addTestSectionSymbol(t, f, sec)
		}, func(c *Config) { c.OnlySections = []string{".symtest.only"} })

		symSec := f.SectionByType(elf.SHT_SYMTAB)
		if symSec == nil {
			t.Fatal("-j dropped the symbol table although a section symbol survived")
		}
		st, err := f.ReadSymtab(symSec)
		if err != nil {
			t.Fatalf("read symtab: %v", err)
		}
		if len(st.Entries) != 2 {
			t.Fatalf("symbol table has %d entries, want 2 (null + section)", len(st.Entries))
		}
		if got := st.Entries[1].Type(); got != elf.STT_SECTION {
			t.Errorf("second symbol type = %d, want STT_SECTION", got)
		}
		if name := f.Sections[st.Entries[1].Shndx].Name; name != ".symtest.only" {
			t.Errorf("section symbol points at %q, want .symtest.only", name)
		}
	})

	// Without any surviving symbol and without relocations GNU writes no
	// symbol table at all, so .symtab and its string table disappear.
	t.Run("empty-table-dropped", func(t *testing.T) {
		f := transformFixture(t, "reloc.o", func(f *elf.File) {
			addTestSection(t, f, ".symtest.only", elf.SHF_ALLOC, make([]byte, 4))
		}, func(c *Config) { c.OnlySections = []string{".symtest.only"} })

		if f.Section(".symtest.only") == nil {
			t.Fatal("-j dropped the only selected section")
		}
		if f.SectionByType(elf.SHT_SYMTAB) != nil {
			t.Error("-j kept a symbol table with no symbols and no relocations")
		}
		if f.Section(".strtab") != nil {
			t.Error("-j kept the string table of a dropped symbol table")
		}
	})
}

func TestMappingSymbolsSurviveStripUnneeded(t *testing.T) {
	// AArch64/ARM mapping symbols are marked BSF_KEEP for relocatable inputs,
	// so --strip-unneeded keeps them even though they are local NOTYPE
	// symbols.
	f := openFixtureFile(t, "reloc.o")
	f.Machine = elf.EM_AARCH64
	symSec := f.SectionByType(elf.SHT_SYMTAB)
	st, err := f.ReadSymtab(symSec)
	if err != nil {
		t.Fatalf("read symtab: %v", err)
	}
	text := f.Section(".text")
	if text == nil {
		t.Skip("fixture has no .text section")
	}
	textIdx := uint16(f.SectionIndex(text))
	st.Entries = append(st.Entries,
		elf.Symbol{Name: "$x", Info: elf.STT_NOTYPE | elf.STB_LOCAL<<4, Shndx: textIdx},
		elf.Symbol{Name: "$d.1", Info: elf.STT_NOTYPE | elf.STB_LOCAL<<4, Shndx: textIdx},
		elf.Symbol{Name: "local_not_mapping", Info: elf.STT_NOTYPE | elf.STB_LOCAL<<4, Shndx: textIdx},
	)
	if err := f.SetSymtab(st); err != nil {
		t.Fatalf("set symtab: %v", err)
	}
	c := Default()
	c.StripUnneeded = true
	if err := Transform(f, c); err != nil {
		t.Fatalf("Transform: %v", err)
	}
	names := map[string]bool{}
	st, err = f.ReadSymtab(f.SectionByType(elf.SHT_SYMTAB))
	if err != nil {
		t.Fatalf("read symtab: %v", err)
	}
	for _, sym := range st.Entries {
		names[sym.Name] = true
	}
	for _, want := range []string{"$x", "$d.1"} {
		if !names[want] {
			t.Errorf("mapping symbol %s was stripped by --strip-unneeded", want)
		}
	}
	if names["local_not_mapping"] {
		t.Error("ordinary local symbol survived --strip-unneeded")
	}
}

func TestNonRelocOnlySectionSymbolsKeepsNullTable(t *testing.T) {
	// GNU keeps a symbol table alive based on the filter_symbols result, even
	// when every surviving symbol is a section symbol that BFD later refuses
	// to emit for a non-relocatable output. It then writes a table with just
	// the null symbol (verified against binutils 2.44).
	f := openFixtureFile(t, "hello")
	symSec := f.SectionByType(elf.SHT_SYMTAB)
	if symSec == nil {
		t.Skip("fixture has no static symbol table")
	}
	st, err := f.ReadSymtab(symSec)
	if err != nil {
		t.Fatalf("read symtab: %v", err)
	}
	entries := []elf.Symbol{{}}
	added := 0
	for idx := range f.Sections {
		if !sectionSymbolTarget(f, symSec, idx) {
			continue
		}
		entries = append(entries, elf.Symbol{
			Info:  elf.STT_SECTION | elf.STB_LOCAL<<4,
			Shndx: uint16(idx),
			Value: f.Sections[idx].Addr,
		})
		added++
	}
	st.Entries = entries
	if err := f.SetSymtab(st); err != nil {
		t.Fatalf("set symtab: %v", err)
	}
	if err := Transform(f, Default()); err != nil {
		t.Fatalf("Transform: %v", err)
	}
	got := f.SectionByType(elf.SHT_SYMTAB)
	if got == nil {
		t.Fatal("symbol table was dropped although filter_symbols kept symbols")
	}
	st, err = f.ReadSymtab(got)
	if err != nil {
		t.Fatalf("read symtab: %v", err)
	}
	if keepUnusedSectionSymbols(f.Machine) {
		if len(st.Entries) != added+1 {
			t.Errorf("kept %d symbols, want %d (null + one per section)", len(st.Entries), added+1)
		}
		return
	}
	// x86: BFD ignores the section symbols but still wrote the table.
	if len(st.Entries) != 1 {
		t.Errorf("symbol table has %d entries, want just the null symbol", len(st.Entries))
	}
}
