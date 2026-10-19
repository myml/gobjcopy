package elf_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

func sectionName(f *elf.File, idx uint32) string {
	if int(idx) < len(f.Sections) {
		return f.Sections[idx].Name
	}
	return fmt.Sprintf("<%d>", idx)
}

// expectedSymbolsAfterRemoval models the library's symbol rewrites: static
// (SHT_SYMTAB) entries defined in the removed section are dropped, dynamic
// entries become SHN_UNDEF, and later section indices move down by one.
func expectedSymbolsAfterRemoval(t *testing.T, name string, before *elf.File, table *elf.Section, removedIdx int) []elf.Symbol {
	t.Helper()
	st, err := before.ReadSymtab(table)
	if err != nil {
		t.Fatalf("%s: ReadSymtab(%s): %v", name, table.Name, err)
	}
	drop := table.Type == elf.SHT_SYMTAB
	out := make([]elf.Symbol, 0, len(st.Entries))
	for i, sym := range st.Entries {
		if i == 0 {
			out = append(out, sym)
			continue
		}
		switch {
		case int(sym.Shndx) == removedIdx && drop:
			continue
		case int(sym.Shndx) == removedIdx:
			sym.Shndx = elf.SHN_UNDEF
		case int(sym.Shndx) > removedIdx && sym.Shndx < elf.SHN_LORESERVE:
			sym.Shndx--
		}
		out = append(out, sym)
	}
	return out
}

// assertSymbolSectionsRemapped verifies symbol dropping, st_shndx renumbering
// and that every surviving symbol still designates the same section name.
func assertSymbolSectionsRemapped(t *testing.T, name string, before, after *elf.File, removedIdx int) {
	t.Helper()
	for _, table := range []string{".symtab", ".dynsym"} {
		bs, as := before.Section(table), after.Section(table)
		if bs == nil || as == nil {
			continue
		}
		want := expectedSymbolsAfterRemoval(t, name, before, bs, removedIdx)
		ast, err := after.ReadSymtab(as)
		if err != nil {
			t.Fatalf("%s: ReadSymtab(%s) after removal: %v", name, table, err)
		}
		if len(want) != len(ast.Entries) {
			t.Errorf("%s: %s has %d entries after removal, want %d",
				name, table, len(ast.Entries), len(want))
		}
		for i := 0; i < len(want) && i < len(ast.Entries); i++ {
			if want[i] != ast.Entries[i] {
				t.Errorf("%s: %s entry %d after removal: got %+v, want %+v",
					name, table, i, ast.Entries[i], want[i])
				continue
			}
			if want[i].Shndx < elf.SHN_LORESERVE {
				wantName := after.Sections[want[i].Shndx].Name
				gotName := after.Sections[ast.Entries[i].Shndx].Name
				if wantName != gotName {
					t.Errorf("%s: %s entry %d (%q) points at %q, want %q",
						name, table, i, want[i].Name, gotName, wantName)
				}
			}
		}
	}
}

// assertSymbolSectionsInserted verifies that st_shndx values were shifted for
// a section inserted at pos.
func assertSymbolSectionsInserted(t *testing.T, name string, before, after *elf.File, pos int) {
	t.Helper()
	for _, table := range []string{".symtab", ".dynsym"} {
		bs, as := before.Section(table), after.Section(table)
		if bs == nil || as == nil {
			continue
		}
		bst, err := before.ReadSymtab(bs)
		if err != nil {
			t.Fatalf("%s: ReadSymtab(%s): %v", name, table, err)
		}
		ast, err := after.ReadSymtab(as)
		if err != nil {
			t.Fatalf("%s: ReadSymtab(%s) after insertion: %v", name, table, err)
		}
		if len(bst.Entries) != len(ast.Entries) {
			t.Fatalf("%s: %s entry count changed after insertion: %d != %d",
				name, table, len(bst.Entries), len(ast.Entries))
		}
		for i := range bst.Entries {
			b, a := bst.Entries[i], ast.Entries[i]
			want := b.Shndx
			if b.Shndx >= elf.SHN_LORESERVE {
				// Special indices are never renumbered.
			} else if int(b.Shndx) >= pos {
				want = b.Shndx + 1
			}
			if a.Shndx != want {
				t.Errorf("%s: %s symbol %d (%q): st_shndx %d after insertion at %d, want %d",
					name, table, i, b.Name, a.Shndx, pos, want)
			}
			if b.Shndx < elf.SHN_LORESERVE && int(a.Shndx) < len(after.Sections) {
				wantName := before.Sections[b.Shndx].Name
				gotName := after.Sections[a.Shndx].Name
				if gotName != wantName {
					t.Errorf("%s: %s symbol %d (%q): section %q after insertion, want %q",
						name, table, i, b.Name, gotName, wantName)
				}
			}
		}
	}
}

// sectionInfoIsIndex mirrors the library's rule for sh_info holding a
// section index instead of a symbol count.
func sectionInfoIsIndex(sec *elf.Section) bool {
	switch sec.Type {
	case elf.SHT_REL, elf.SHT_RELA, elf.SHT_GROUP:
		return true
	}
	return sec.Flags&elf.SHF_INFO_LINK != 0
}

// assertSectionLinksRemapped checks that every surviving section's sh_link and
// (where it is an index) sh_info still resolve to the same section name.
func assertSectionLinksRemapped(t *testing.T, name string, before, after *elf.File, removedName string) {
	t.Helper()
	for _, bs := range before.Sections {
		if removedName != "" && bs.Name == removedName {
			continue
		}
		as := after.Section(bs.Name)
		if as == nil {
			t.Errorf("%s: section %q disappeared", name, bs.Name)
			continue
		}
		check := func(field string, wantIdx, gotIdx uint32) {
			want := sectionName(before, wantIdx)
			got := sectionName(after, gotIdx)
			if removedName != "" && want == removedName {
				want = ""
			}
			if got != want {
				t.Errorf("%s: section %q %s resolves to %q, want %q",
					name, bs.Name, field, got, want)
			}
		}
		check("sh_link", bs.Link, as.Link)
		if sectionInfoIsIndex(bs) {
			check("sh_info", bs.Info, as.Info)
		}
	}
}

// expectedRelocsAfterRemoval models relocation dropping/remapping for a
// removed section. Relocations linked to a static symbol table are remapped
// (and dropped when their symbol is dropped); dynamic links are untouched.
func expectedRelocsAfterRemoval(t *testing.T, name string, before *elf.File, relocSec *elf.Section, removedIdx int) []elf.Reloc {
	t.Helper()
	rels, err := before.ReadRelocs(relocSec)
	if err != nil {
		t.Fatalf("%s: ReadRelocs(%s): %v", name, relocSec.Name, err)
	}
	if int(relocSec.Link) >= len(before.Sections) {
		return rels
	}
	symtab := before.Sections[relocSec.Link]
	if symtab.Type != elf.SHT_SYMTAB || int(relocSec.Link) == removedIdx {
		return rels
	}
	st, err := before.ReadSymtab(symtab)
	if err != nil {
		t.Fatalf("%s: ReadSymtab(%s): %v", name, symtab.Name, err)
	}
	remap := make([]int, len(st.Entries))
	if len(remap) > 0 {
		remap[0] = 0
	}
	next := 1
	for i := 1; i < len(st.Entries); i++ {
		if int(st.Entries[i].Shndx) == removedIdx {
			remap[i] = -1
			continue
		}
		remap[i] = next
		next++
	}
	kept := make([]elf.Reloc, 0, len(rels))
	for _, r := range rels {
		if int(r.Sym) < len(remap) {
			if remap[r.Sym] < 0 {
				continue
			}
			r.Sym = uint32(remap[r.Sym])
		}
		kept = append(kept, r)
	}
	return kept
}

// assertRelocsRemapped verifies relocation section sh_link/sh_info references
// and relocation entries across a section edit. Pass removedIdx < 0 for an
// insertion.
func assertRelocsRemapped(t *testing.T, name string, before, after *elf.File, removedIdx int, removedName string) {
	t.Helper()
	for _, bs := range before.Sections {
		if bs.Type != elf.SHT_REL && bs.Type != elf.SHT_RELA {
			continue
		}
		if removedName != "" && bs.Name == removedName {
			if after.Section(bs.Name) != nil {
				t.Errorf("%s: relocation section %q was not removed", name, bs.Name)
			}
			continue
		}
		as := after.Section(bs.Name)
		if as == nil {
			t.Errorf("%s: relocation section %q disappeared", name, bs.Name)
			continue
		}
		wantTarget := sectionName(before, bs.Info)
		gotTarget := sectionName(after, as.Info)
		if removedName != "" && wantTarget == removedName {
			wantTarget = ""
		}
		if gotTarget != wantTarget {
			t.Errorf("%s: %s sh_info resolves to %q, want %q", name, bs.Name, gotTarget, wantTarget)
		}
		wantLink := sectionName(before, bs.Link)
		gotLink := sectionName(after, as.Link)
		if removedName != "" && wantLink == removedName {
			wantLink = ""
		}
		if gotLink != wantLink {
			t.Errorf("%s: %s sh_link resolves to %q, want %q", name, bs.Name, gotLink, wantLink)
		}
		want, err := before.ReadRelocs(bs)
		if err != nil {
			t.Fatalf("%s: ReadRelocs(%s): %v", name, bs.Name, err)
		}
		if removedIdx >= 0 {
			want = expectedRelocsAfterRemoval(t, name, before, bs, removedIdx)
		}
		got, err := after.ReadRelocs(as)
		if err != nil {
			t.Fatalf("%s: ReadRelocs(%s) after edit: %v", name, bs.Name, err)
		}
		if len(got) != len(want) {
			t.Errorf("%s: %s reloc count %d after edit, want %d", name, bs.Name, len(got), len(want))
		}
		for i := 0; i < len(got) && i < len(want); i++ {
			if got[i] != want[i] {
				t.Errorf("%s: %s reloc %d after edit: got %+v, want %+v",
					name, bs.Name, i, got[i], want[i])
			}
		}
	}
}

func indexOfSection(f *elf.File, name string) int {
	for i, s := range f.Sections {
		if s.Name == name {
			return i
		}
	}
	return -1
}

// removeAndCheck removes target from the fixture and returns the reparsed
// result after validating readelf.
func removeAndCheck(t *testing.T, fixtureName, target string) (*elf.File, *elf.File, int, string) {
	t.Helper()
	orig := openFixture(t, fixtureName)
	idx := indexOfSection(orig, target)
	if idx < 0 {
		t.Skipf("%s has no %s section", fixtureName, target)
	}
	f := openFixture(t, fixtureName)
	ok, err := f.RemoveSectionByName(target)
	if err != nil {
		t.Fatalf("%s: RemoveSectionByName(%q): %v", fixtureName, target, err)
	}
	if !ok {
		t.Fatalf("%s: RemoveSectionByName(%q) reported false", fixtureName, target)
	}
	if f.Section(target) != nil {
		t.Fatalf("%s: section %q is still present after removal", fixtureName, target)
	}
	if len(f.Sections) != len(orig.Sections)-1 {
		t.Fatalf("%s: %d sections after removing %q, want %d",
			fixtureName, len(f.Sections), target, len(orig.Sections)-1)
	}
	dst := writeELF(t, f, 0o755, fixtureName)
	assertReadelfParses(t, dst)
	g, err := elf.Open(dst)
	if err != nil {
		t.Fatalf("%s: reparse after removing %q: %v", fixtureName, target, err)
	}
	assertReadelfMatchesModel(t, dst, g)
	assertSymbolSectionsRemapped(t, fixtureName, orig, g, idx)
	assertRelocsRemapped(t, fixtureName, orig, g, idx, target)
	assertSectionLinksRemapped(t, fixtureName, orig, g, target)
	return orig, g, idx, dst
}

// TestRemoveSectionKeepsExecutableRunnable deletes sections that a running
// program does not need and checks that the result still runs identically.
func TestRemoveSectionKeepsExecutableRunnable(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	for _, name := range fixtureNames(t) {
		name := name
		f := openFixture(t, name)
		if !isRunnable(f) {
			continue
		}
		path := fixture(t, name)
		wantExit, wantOut := runBinary(t, path)
		for _, target := range []string{".comment", ".note.gnu.build-id", ".note.gnu.property"} {
			target := target
			if f.Section(target) == nil {
				continue
			}
			t.Run(name+"/"+target, func(t *testing.T) {
				t.Parallel()
				_, _, _, dst := removeAndCheck(t, name, target)
				gotExit, gotOut := runBinary(t, dst)
				if gotExit != wantExit || gotOut != wantOut {
					t.Errorf("%s: executable after removing %q: exit %d/%q, want %d/%q",
						name, target, gotExit, gotOut, wantExit, wantOut)
				}
			})
		}
	}
}

// TestRemoveSectionRenumbersObject removes a section in the middle of a
// relocatable object, forcing sh_link/sh_info and st_shndx renumbering.
func TestRemoveSectionRenumbersObject(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	for _, name := range []string{"reloc.o", "reloc32.o"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			orig := openFixture(t, name)
			target := ""
			for _, candidate := range []string{".data", ".rodata", ".bss", ".text"} {
				if idx := indexOfSection(orig, candidate); idx > 0 && idx < len(orig.Sections)-3 {
					target = candidate
					break
				}
			}
			if target == "" {
				t.Skipf("%s has no suitable middle section", name)
			}
			idx := indexOfSection(orig, target)
			// Make sure the removal actually exercises symbol renumbering.
			st := orig.Symtab()
			if st == nil {
				t.Skipf("%s has no .symtab", name)
			}
			renumbered := 0
			for _, sym := range st.Entries {
				if int(sym.Shndx) > idx && sym.Shndx < elf.SHN_LORESERVE {
					renumbered++
				}
			}
			if renumbered == 0 {
				t.Skipf("%s has no symbols after %q to renumber", name, target)
			}
			_, g, _, dst := removeAndCheck(t, name, target)
			if g.Symtab() == nil {
				t.Fatalf("%s: .symtab disappeared", name)
			}
			// readelf -s specifically must agree with the renumbered model.
			assertReadelfMatchesModel(t, dst, g)
			if g.Section(".shstrtab") == nil {
				t.Errorf("%s: .shstrtab missing after removal", name)
			}
		})
	}
}

// TestRemoveSectionRelocationTarget removes the section that relocations point
// at; sh_info must fall back to zero and the file must stay parseable.
func TestRemoveSectionRelocationTarget(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	name := "reloc.o"
	orig := openFixture(t, name)
	target := ".text"
	idx := indexOfSection(orig, target)
	if idx < 0 {
		t.Skipf("%s has no %s", name, target)
	}
	_, g, _, dst := removeAndCheck(t, name, target)
	for _, sec := range orig.Sections {
		if sec.Type != elf.SHT_REL && sec.Type != elf.SHT_RELA {
			continue
		}
		if int(sec.Info) != idx {
			continue
		}
		nsec := g.Section(sec.Name)
		if nsec == nil {
			t.Fatalf("%s: relocation section %q disappeared", name, sec.Name)
		}
		if nsec.Info != 0 {
			t.Errorf("%s: %s sh_info %d after its target was removed, want 0", name, sec.Name, nsec.Info)
		}
	}
	// Symbols defined in the removed section become undefined.
	st := g.Symtab()
	if st == nil {
		t.Fatalf("%s: .symtab disappeared", name)
	}
	for _, sym := range st.Entries {
		if sym.Shndx == elf.SHN_UNDEF {
			continue
		}
		if int(sym.Shndx) < len(g.Sections) && g.Sections[sym.Shndx].Name == target {
			t.Errorf("%s: symbol %q still refers to removed section %q", name, sym.Name, target)
		}
	}
	assertReadelfMatchesModel(t, dst, g)
}

// TestRemoveSectionSymtab removes the static symbol table; relocations lose
// their sh_link but the file must remain parseable.
func TestRemoveSectionSymtab(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	name := "reloc.o"
	orig := openFixture(t, name)
	if orig.Section(".symtab") == nil {
		t.Skipf("%s has no .symtab", name)
	}
	_, g, _, _ := removeAndCheck(t, name, ".symtab")
	if g.Section(".symtab") != nil {
		t.Fatalf("%s: .symtab still present", name)
	}
	for _, sec := range g.Sections {
		if sec.Type != elf.SHT_REL && sec.Type != elf.SHT_RELA {
			continue
		}
		if sec.Link != 0 {
			t.Errorf("%s: %s sh_link %d after .symtab removal, want 0", name, sec.Name, sec.Link)
		}
		if _, err := g.ReadRelocs(sec); err != nil {
			t.Errorf("%s: ReadRelocs(%s): %v", name, sec.Name, err)
		}
	}
	ok, err := g.RemoveSectionByName(".symtab")
	if err != nil || ok {
		t.Errorf("%s: RemoveSectionByName on a missing section = %v, %v; want false, nil", name, ok, err)
	}
}

// TestRemoveSectionShstrtab removes the section name string table; the writer
// must recreate one and keep every section name intact.
func TestRemoveSectionShstrtab(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	name := "reloc.o"
	orig := openFixture(t, name)
	if orig.Section(".shstrtab") == nil {
		t.Skipf("%s has no .shstrtab", name)
	}
	_, g, _, dst := removeAndCheck(t, name, ".shstrtab")
	if g.Section(".shstrtab") == nil {
		t.Fatalf("%s: writer did not recreate .shstrtab", name)
	}
	for i, sec := range orig.Sections {
		if sec.Name == ".shstrtab" {
			continue
		}
		if g.Section(sec.Name) == nil {
			t.Errorf("%s: section %q (index %d) lost its name", name, sec.Name, i)
		}
	}
	assertReadelfMatchesModel(t, dst, g)
}

// TestRemoveSectionErrors covers invalid indices.
func TestRemoveSectionErrors(t *testing.T) {
	t.Parallel()
	f := openFixture(t, "reloc.o")
	before := len(f.Sections)
	for _, idx := range []int{-1, 0, len(f.Sections), len(f.Sections) + 10} {
		if err := f.RemoveSection(idx); err == nil {
			t.Errorf("RemoveSection(%d) succeeded, want error", idx)
		}
	}
	if len(f.Sections) != before {
		t.Errorf("failed RemoveSection calls changed the section count: %d != %d", len(f.Sections), before)
	}
}

// insertAndCheck inserts sec at pos and validates the result with readelf.
func insertAndCheck(t *testing.T, fixtureName string, pos int, sec *elf.Section) (*elf.File, *elf.File, string) {
	t.Helper()
	orig := openFixture(t, fixtureName)
	f := openFixture(t, fixtureName)
	if err := f.InsertSection(pos, sec); err != nil {
		t.Fatalf("%s: InsertSection(%d): %v", fixtureName, pos, err)
	}
	if len(f.Sections) != len(orig.Sections)+1 {
		t.Fatalf("%s: %d sections after insertion, want %d", fixtureName, len(f.Sections), len(orig.Sections)+1)
	}
	if f.Sections[pos] != sec {
		t.Fatalf("%s: InsertSection did not place the section at index %d", fixtureName, pos)
	}
	dst := writeELF(t, f, 0o755, fixtureName)
	assertReadelfParses(t, dst)
	g, err := elf.Open(dst)
	if err != nil {
		t.Fatalf("%s: reparse after insertion: %v", fixtureName, err)
	}
	assertReadelfMatchesModel(t, dst, g)
	assertSymbolSectionsInserted(t, fixtureName, orig, g, pos)
	assertSectionLinksRemapped(t, fixtureName, orig, g, "")
	return orig, g, dst
}

// TestInsertSection inserts a new section before the symbol table and verifies
// renumbering of sh_link, sh_info and st_shndx.
func TestInsertSection(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	for _, name := range []string{"reloc.o", "reloc32.o"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			orig := openFixture(t, name)
			pos := indexOfSection(orig, ".symtab")
			if pos <= 0 {
				t.Skipf("%s has no .symtab to insert before", name)
			}
			data := []byte("inserted section data")
			sec := &elf.Section{
				SectionHeader: elf.SectionHeader{Name: ".test_added", Type: elf.SHT_PROGBITS, Addralign: 4},
				Data:          data,
			}
			_, g, dst := insertAndCheck(t, name, pos, sec)
			if sec.Size != uint64(len(data)) {
				t.Errorf("%s: InsertSection left Size=%d for %d bytes of data", name, sec.Size, len(data))
			}
			added := g.Section(".test_added")
			if added == nil {
				t.Fatalf("%s: .test_added missing after round-trip", name)
			}
			if !bytes.Equal(added.Data, data) {
				t.Errorf("%s: .test_added data %q != %q", name, added.Data, data)
			}
			if added.Type != elf.SHT_PROGBITS || added.Link != 0 || added.Info != 0 {
				t.Errorf("%s: .test_added header %+v, want PROGBITS with Link/Info 0", name, added.SectionHeader)
			}
			// Inserting before .symtab must move its sh_link to the string table.
			symtab := g.Section(".symtab")
			if symtab == nil {
				t.Fatalf("%s: .symtab missing", name)
			}
			if got := sectionName(g, symtab.Link); got != ".strtab" {
				t.Errorf("%s: .symtab sh_link points at %q, want .strtab", name, got)
			}
			if st, err := g.ReadSymtab(symtab); err != nil || st == nil {
				t.Errorf("%s: ReadSymtab after insertion: %v", name, err)
			}
			assertRelocsRemapped(t, name, orig, g, -1, "")
			_ = dst
		})
	}
}

// TestInsertSectionSharedLibrary triggers a .dynsym rewrite and checks that it
// stays a dynamic symbol table.
func TestInsertSectionSharedLibrary(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	name := "lib.so"
	orig := openFixture(t, name)
	if orig.Dynsym() == nil {
		t.Skipf("%s has no .dynsym", name)
	}
	pos := 2 // before the dynsym, forcing every defined dynsym entry to shift
	sec := &elf.Section{
		SectionHeader: elf.SectionHeader{Name: ".test_added", Type: elf.SHT_PROGBITS, Addralign: 1},
		Data:          []byte{0xaa, 0xbb},
	}
	_, g, dst := insertAndCheck(t, name, pos, sec)
	dyn := g.Section(".dynsym")
	if dyn == nil {
		t.Fatalf("%s: .dynsym disappeared", name)
	}
	if dyn.Type != elf.SHT_DYNSYM {
		t.Errorf("%s: .dynsym type %d after insertion, want SHT_DYNSYM (%d)", name, dyn.Type, elf.SHT_DYNSYM)
	}
	mustReadelf(t, dst, "--dyn-syms", "-W")
}

// TestAddSection covers AddSection's placement before the symbol table while
// keeping .shstrtab last.
func TestAddSection(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	name := "reloc.o"
	orig := openFixture(t, name)
	origShstr := orig.Shstrndx
	data := []byte("added-by-AddSection")
	sec := &elf.Section{
		SectionHeader: elf.SectionHeader{Name: ".test_added", Type: elf.SHT_PROGBITS, Addralign: 2},
		Data:          data,
	}
	f := openFixture(t, name)
	if err := f.AddSection(sec); err != nil {
		t.Fatalf("%s: AddSection: %v", name, err)
	}
	if f.Shstrndx != origShstr+1 {
		t.Errorf("%s: Shstrndx %d after AddSection, want %d", name, f.Shstrndx, origShstr+1)
	}
	if f.Shstrndx != len(f.Sections)-1 {
		t.Errorf("%s: .shstrtab is not last after AddSection (Shstrndx %d, %d sections)",
			name, f.Shstrndx, len(f.Sections))
	}
	dst := writeELF(t, f, 0o644, name)
	assertReadelfParses(t, dst)
	g, err := elf.Open(dst)
	if err != nil {
		t.Fatalf("%s: reparse after AddSection: %v", name, err)
	}
	assertReadelfMatchesModel(t, dst, g)
	added := g.Section(".test_added")
	if added == nil || !bytes.Equal(added.Data, data) {
		t.Fatalf("%s: added section missing or has wrong data: %+v", name, added)
	}
	if si, ai := indexOfSection(g, ".symtab"), indexOfSection(g, ".test_added"); si >= 0 && ai > si {
		t.Errorf("%s: AddSection put the new section at %d, after .symtab at %d", name, ai, si)
	}
	if g.Section(".shstrtab") == nil || g.Shstrndx != len(g.Sections)-1 {
		t.Errorf("%s: .shstrtab placement invalid after reparse", name)
	}
	// Removing the added section must restore the original semantics.
	ok, err := g.RemoveSectionByName(".test_added")
	if err != nil || !ok {
		t.Fatalf("%s: RemoveSectionByName(.test_added) = %v, %v", name, ok, err)
	}
	back := reparse(t, mustBytes(t, g), name+" after add/remove")
	assertDumpsEqual(t, name+" add/remove", orig, back)
}

// mustBytes serialises f and fails the test on error.
func mustBytes(t *testing.T, f *elf.File) []byte {
	t.Helper()
	b, err := f.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	return b
}

// TestAddSectionExecutable adds a non-allocated section to an executable and
// checks that it still runs.
func TestAddSectionExecutable(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	name := "hello"
	path := fixture(t, name)
	wantExit, wantOut := runBinary(t, path)
	f := openFixture(t, name)
	sec := &elf.Section{
		SectionHeader: elf.SectionHeader{Name: ".test_added", Type: elf.SHT_PROGBITS, Addralign: 1},
		Data:          []byte("extra payload"),
	}
	if err := f.AddSection(sec); err != nil {
		t.Fatalf("%s: AddSection: %v", name, err)
	}
	dst := writeELF(t, f, 0o755, name)
	assertReadelfParses(t, dst)
	gotExit, gotOut := runBinary(t, dst)
	if gotExit != wantExit || gotOut != wantOut {
		t.Errorf("%s: executable with added section: exit %d/%q, want %d/%q",
			name, gotExit, gotOut, wantExit, wantOut)
	}
}

// TestInsertSectionErrors covers invalid insertion positions.
func TestInsertSectionErrors(t *testing.T) {
	t.Parallel()
	f := openFixture(t, "reloc.o")
	before := len(f.Sections)
	sec := &elf.Section{SectionHeader: elf.SectionHeader{Name: ".x", Type: elf.SHT_PROGBITS}}
	for _, pos := range []int{-1, 0, len(f.Sections) + 1} {
		if err := f.InsertSection(pos, sec); err == nil {
			t.Errorf("InsertSection(%d) succeeded, want error", pos)
		}
	}
	if err := f.InsertSection(1, nil); err == nil {
		t.Error("InsertSection(1, nil) succeeded, want error")
	}
	if len(f.Sections) != before {
		t.Errorf("failed InsertSection calls changed the section count: %d != %d", len(f.Sections), before)
	}
}
