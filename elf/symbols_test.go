package elf_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

func firstNonLocal(entries []elf.Symbol) int {
	for i, s := range entries {
		if s.Bind() != elf.STB_LOCAL {
			return i
		}
	}
	return len(entries)
}

// TestSetSymtabDeleteEntries removes symbols from the middle of .symtab and
// checks both the model and readelf -s afterwards.
func TestSetSymtabDeleteEntries(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	for _, name := range []string{"reloc.o", "reloc32.o", "hello"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := openFixture(t, name)
			st := f.Symtab()
			if st == nil {
				t.Skipf("%s has no .symtab", name)
			}
			if len(st.Entries) < 5 {
				t.Skipf("%s: only %d symbols", name, len(st.Entries))
			}
			// Delete up to two local symbols from the middle of the table.
			var del []int
			for i := 1; i < len(st.Entries) && len(del) < 2; i++ {
				if st.Entries[i].Bind() == elf.STB_LOCAL {
					del = append(del, i)
				}
			}
			if len(del) == 0 {
				t.Skipf("%s: no local symbols to delete", name)
			}
			drop := map[int]bool{}
			for _, i := range del {
				drop[i] = true
			}
			kept := make([]elf.Symbol, 0, len(st.Entries)-len(del))
			for i, sym := range st.Entries {
				if !drop[i] {
					kept = append(kept, sym)
				}
			}
			removed := make([]string, 0, len(del))
			for _, i := range del {
				removed = append(removed, st.Entries[i].Name)
			}
			st.Entries = kept
			if err := f.SetSymtab(st); err != nil {
				t.Fatalf("%s: SetSymtab: %v", name, err)
			}
			if want := firstNonLocal(kept); int(st.Section.Info) != want {
				t.Errorf("%s: .symtab sh_info %d after deletion, want %d (first non-local)",
					name, st.Section.Info, want)
			}
			if st.Section.Type != elf.SHT_SYMTAB {
				t.Errorf("%s: .symtab type %d, want SHT_SYMTAB", name, st.Section.Type)
			}
			dst := writeELF(t, f, 0o644, name)
			mustReadelf(t, dst, "-sW")
			g, err := elf.Open(dst)
			if err != nil {
				t.Fatalf("%s: reparse: %v", name, err)
			}
			gst := g.Symtab()
			if gst == nil {
				t.Fatalf("%s: .symtab missing after deletion", name)
			}
			if !reflect.DeepEqual(gst.Entries, kept) {
				t.Errorf("%s: symbol table differs after round-trip:\n got %+v\nwant %+v",
					name, gst.Entries, kept)
			}
			if got := sectionName(g, gst.Section.Link); got != ".strtab" {
				t.Errorf("%s: .symtab sh_link points at %q, want .strtab", name, got)
			}
			for _, rn := range removed {
				if rn == "" {
					continue
				}
				for _, sym := range gst.Entries {
					if sym.Name == rn {
						t.Errorf("%s: removed symbol %q is still present", name, rn)
					}
				}
			}
			assertReadelfMatchesModel(t, dst, g)
		})
	}
}

// TestSetSymtabEditsAttributes changes symbol attributes and appends a new
// symbol, then verifies the result through the model and readelf.
func TestSetSymtabEditsAttributes(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	for _, name := range []string{"reloc.o", "reloc32.o"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := openFixture(t, name)
			st := f.Symtab()
			if st == nil {
				t.Skipf("%s has no .symtab", name)
			}
			idx := -1
			for i, sym := range st.Entries {
				if sym.Bind() == elf.STB_GLOBAL && sym.Type() == elf.STT_FUNC && sym.Name != "" {
					idx = i
					break
				}
			}
			if idx < 0 {
				t.Skipf("%s: no global function symbol to edit", name)
			}
			sym := &st.Entries[idx]
			old := *sym
			sym.SetBind(elf.STB_WEAK)
			sym.SetType(elf.STT_OBJECT)
			sym.SetVisibility(elf.STV_HIDDEN)
			sym.Value += 0x10
			sym.Size = 0x20
			if target := indexOfSection(f, ".data"); target > 0 {
				sym.Shndx = uint16(target)
			}
			added := elf.Symbol{Name: "gobjcopy_added_symbol", Info: byte(elf.STB_GLOBAL << 4), Shndx: elf.SHN_ABS, Value: 0x1234, Size: 4}
			st.Entries = append(st.Entries, added)
			if err := f.SetSymtab(st); err != nil {
				t.Fatalf("%s: SetSymtab: %v", name, err)
			}
			dst := writeELF(t, f, 0o644, name)
			mustReadelf(t, dst, "-sW")
			g, err := elf.Open(dst)
			if err != nil {
				t.Fatalf("%s: reparse: %v", name, err)
			}
			gst := g.Symtab()
			if gst == nil {
				t.Fatalf("%s: .symtab missing", name)
			}
			var got *elf.Symbol
			for i := range gst.Entries {
				if gst.Entries[i].Name == old.Name {
					got = &gst.Entries[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("%s: symbol %q lost after edit", name, old.Name)
			}
			if *got != *sym {
				t.Errorf("%s: edited symbol %q changed across serialisation:\n got %+v\nwant %+v",
					name, old.Name, *got, *sym)
			}
			if got.Bind() != elf.STB_WEAK || got.Type() != elf.STT_OBJECT ||
				got.Visibility() != elf.STV_HIDDEN || got.Value != old.Value+0x10 || got.Size != 0x20 {
				t.Errorf("%s: edited symbol attributes not preserved: %+v", name, *got)
			}
			var addedBack *elf.Symbol
			for i := range gst.Entries {
				if gst.Entries[i].Name == added.Name {
					addedBack = &gst.Entries[i]
					break
				}
			}
			if addedBack == nil {
				t.Fatalf("%s: appended symbol %q missing", name, added.Name)
			}
			if *addedBack != added {
				t.Errorf("%s: appended symbol changed: got %+v want %+v", name, *addedBack, added)
			}
			assertReadelfMatchesModel(t, dst, g)
		})
	}
}

// TestSetSymtabDynsymPreservesDynstr edits .dynsym and verifies that the
// dynamic string table (which .gnu.version* also reference) stays intact and
// that the executable still runs.
func TestSetSymtabDynsymPreservesDynstr(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	name := "hello-pie"
	path := fixture(t, name)
	wantExit, wantOut := runBinary(t, path)
	f := openFixture(t, name)
	st := f.Dynsym()
	if st == nil {
		t.Skipf("%s has no .dynsym", name)
	}
	if st.Section.Type != elf.SHT_DYNSYM {
		t.Fatalf("%s: .dynsym type %d before edit", name, st.Section.Type)
	}
	if int(st.Section.Link) >= len(f.Sections) {
		t.Fatalf("%s: .dynsym has invalid sh_link %d", name, st.Section.Link)
	}
	dynstr := f.Sections[st.Section.Link]
	before := append([]byte(nil), dynstr.Data...)
	if !bytes.Contains(before, []byte("GLIBC_2.2.5")) {
		t.Fatalf("%s: .dynstr unexpectedly lacks version strings: %q", name, before)
	}
	if err := f.SetSymtab(st); err != nil {
		t.Fatalf("%s: SetSymtab(.dynsym): %v", name, err)
	}
	if st.Section.Type != elf.SHT_DYNSYM {
		t.Errorf("%s: .dynsym became type %d, want SHT_DYNSYM", name, st.Section.Type)
	}
	if !bytes.HasPrefix(dynstr.Data, before) {
		t.Errorf("%s: .dynstr lost strings during .dynsym rewrite:\n before %q\n after  %q",
			name, before, dynstr.Data)
	}
	dst := writeELF(t, f, 0o755, name)
	assertReadelfParses(t, dst)
	mustReadelf(t, dst, "--dyn-syms", "-W")
	mustReadelf(t, dst, "--version-info", "-W")
	gotExit, gotOut := runBinary(t, dst)
	if gotExit != wantExit || gotOut != wantOut {
		t.Errorf("%s: executable after .dynsym rewrite: exit %d/%q, want %d/%q",
			name, gotExit, gotOut, wantExit, wantOut)
	}
	g, err := elf.Open(dst)
	if err != nil {
		t.Fatalf("%s: reparse: %v", name, err)
	}
	assertReadelfMatchesModel(t, dst, g)
}

// TestRelocCodecRoundTrip encodes and decodes synthetic relocations for every
// class/format combination, including negative addends.
func TestRelocCodecRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		class  elf.Class
		typ    uint32
		relocs []elf.Reloc
	}{
		{
			name:  "elf64-rela",
			class: elf.Class64,
			typ:   elf.SHT_RELA,
			relocs: []elf.Reloc{
				{Offset: 0x1122334455667788, Sym: 0x12345678, Type: 0xab, Addend: -12345, HasAddend: true},
				{Offset: 0, Sym: 0, Type: 0, Addend: 0x7fffffff, HasAddend: true},
			},
		},
		{
			name:  "elf64-rel",
			class: elf.Class64,
			typ:   elf.SHT_REL,
			relocs: []elf.Reloc{
				{Offset: 0xdeadbeef, Sym: 0x11, Type: 0x22},
			},
		},
		{
			name:  "elf32-rela",
			class: elf.Class32,
			typ:   elf.SHT_RELA,
			relocs: []elf.Reloc{
				{Offset: 0x11223344, Sym: 0x123456, Type: 0xff, Addend: -2, HasAddend: true},
			},
		},
		{
			name:  "elf32-rel",
			class: elf.Class32,
			typ:   elf.SHT_REL,
			relocs: []elf.Reloc{
				{Offset: 0xaabbccdd, Sym: 0xffffff, Type: 0x7f},
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &elf.File{Header: elf.Header{Class: tc.class, Data: elf.DataLSB}}
			sec := &elf.Section{SectionHeader: elf.SectionHeader{Name: ".test_rel", Type: tc.typ}}
			if err := f.SetRelocs(sec, tc.relocs); err != nil {
				t.Fatalf("SetRelocs: %v", err)
			}
			if want := len(tc.relocs) * f.RelSize(sec); len(sec.Data) != want {
				t.Errorf("encoded %d bytes, want %d", len(sec.Data), want)
			}
			if uint64(len(sec.Data)) != sec.Size {
				t.Errorf("section Size %d != len(Data) %d", sec.Size, len(sec.Data))
			}
			got, err := f.ReadRelocs(sec)
			if err != nil {
				t.Fatalf("ReadRelocs: %v", err)
			}
			want := append([]elf.Reloc(nil), tc.relocs...)
			if tc.typ == elf.SHT_REL {
				for i := range want {
					want[i].HasAddend = false
					want[i].Addend = 0
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("relocations changed:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

// TestRelocRoundTripFiles rewrites every relocation section of the corpus and
// compares the reparsed results, including the 32-bit reloc32.o.
func TestRelocRoundTripFiles(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	for _, name := range fixtureNames(t) {
		name := name
		f := openFixture(t, name)
		has := false
		for _, sec := range f.Sections {
			if sec.Type == elf.SHT_REL || sec.Type == elf.SHT_RELA {
				has = true
			}
		}
		if !has {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := openFixture(t, name)
			type relocSet struct {
				section string
				relocs  []elf.Reloc
			}
			var want []relocSet
			for _, sec := range f.Sections {
				if sec.Type != elf.SHT_REL && sec.Type != elf.SHT_RELA {
					continue
				}
				relocs, err := f.ReadRelocs(sec)
				if err != nil {
					t.Fatalf("%s: ReadRelocs(%s): %v", name, sec.Name, err)
				}
				want = append(want, relocSet{sec.Name, append([]elf.Reloc(nil), relocs...)})
				if err := f.SetRelocs(sec, relocs); err != nil {
					t.Fatalf("%s: SetRelocs(%s): %v", name, sec.Name, err)
				}
				if uint64(len(sec.Data)) != sec.Size {
					t.Errorf("%s: %s Size %d != len(Data) %d", name, sec.Name, sec.Size, len(sec.Data))
				}
				if wantSize := f.RelSize(sec); sec.Entsize != uint64(wantSize) {
					t.Errorf("%s: %s Entsize %d, want %d", name, sec.Name, sec.Entsize, wantSize)
				}
			}
			dst := writeELF(t, f, 0o644, name)
			assertReadelfParses(t, dst)
			g, err := elf.Open(dst)
			if err != nil {
				t.Fatalf("%s: reparse: %v", name, err)
			}
			for _, rs := range want {
				sec := g.Section(rs.section)
				if sec == nil {
					t.Fatalf("%s: relocation section %q missing", name, rs.section)
				}
				got, err := g.ReadRelocs(sec)
				if err != nil {
					t.Fatalf("%s: ReadRelocs(%s) after rewrite: %v", name, rs.section, err)
				}
				if !reflect.DeepEqual(got, rs.relocs) {
					t.Errorf("%s: %s relocations changed:\n got %+v\nwant %+v",
						name, rs.section, got, rs.relocs)
				}
			}
			assertReadelfMatchesModel(t, dst, g)
			if name == "reloc32.o" {
				if g.Class != elf.Class32 {
					t.Errorf("%s: class %d, want ELF32", name, g.Class)
				}
				foundRel := false
				for _, sec := range g.Sections {
					if sec.Type == elf.SHT_REL {
						foundRel = true
					}
				}
				if !foundRel {
					t.Errorf("%s: no SHT_REL section after rewrite", name)
				}
			}
		})
	}
}

// TestRelocEdit changes relocation addends and symbol indices and ensures they
// survive a full write/parse cycle.
func TestRelocEdit(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	for _, name := range []string{"reloc.o", "reloc32.o"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := openFixture(t, name)
			var target *elf.Section
			for _, sec := range f.Sections {
				if (sec.Type == elf.SHT_REL || sec.Type == elf.SHT_RELA) && len(sec.Data) > 0 {
					target = sec
					break
				}
			}
			if target == nil {
				t.Skipf("%s has no non-empty relocation section", name)
			}
			relocs, err := f.ReadRelocs(target)
			if err != nil {
				t.Fatalf("%s: ReadRelocs(%s): %v", name, target.Name, err)
			}
			want := append([]elf.Reloc(nil), relocs...)
			want[0].Offset += 4
			want[0].Type ^= 1
			if target.Type == elf.SHT_RELA {
				want[0].Addend -= 0x1234
			}
			if st := f.Symtab(); st != nil && len(st.Entries) > 1 {
				if int(want[0].Sym)+1 < len(st.Entries) {
					want[0].Sym++
				}
			}
			if err := f.SetRelocs(target, want); err != nil {
				t.Fatalf("%s: SetRelocs: %v", name, err)
			}
			dst := writeELF(t, f, 0o644, name)
			assertReadelfParses(t, dst)
			g, err := elf.Open(dst)
			if err != nil {
				t.Fatalf("%s: reparse: %v", name, err)
			}
			sec := g.Section(target.Name)
			if sec == nil {
				t.Fatalf("%s: section %q missing", name, target.Name)
			}
			got, err := g.ReadRelocs(sec)
			if err != nil {
				t.Fatalf("%s: ReadRelocs after edit: %v", name, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s: edited relocations changed:\n got %+v\nwant %+v", name, got, want)
			}
			assertReadelfMatchesModel(t, dst, g)
		})
	}
}

// TestRelocErrors covers decoding sections that are not relocation tables.
func TestRelocErrors(t *testing.T) {
	t.Parallel()
	f := openFixture(t, "reloc.o")
	text := f.Section(".text")
	if text == nil {
		t.Skip("reloc.o has no .text")
	}
	if _, err := f.ReadRelocs(text); err == nil {
		t.Error("ReadRelocs(.text) succeeded, want error")
	}
	if _, err := f.ReadSymtab(text); err == nil {
		t.Error("ReadSymtab(.text) succeeded, want error")
	}
}

var _ = bytes.Equal
