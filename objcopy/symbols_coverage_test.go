package objcopy

// Coverage-oriented tests for the symbol manipulation code. They exercise the
// individual predicates (matchSymbol, isLocalLabel, ...) plus every branch of
// applySymbols through the public Transform entry point.

import (
	"testing"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/fixtures"
)

func openFixtureFile(t *testing.T, name string) *elf.File {
	t.Helper()
	p, err := fixtures.BuildOne(t.TempDir(), name)
	if err != nil {
		t.Skipf("fixture %s unavailable: %v", name, err)
	}
	f, err := elf.Open(p)
	if err != nil {
		t.Fatalf("open fixture %s: %v", name, err)
	}
	return f
}

// symbolMap returns the static symbol table keyed by name.
func symbolMap(t *testing.T, f *elf.File) map[string]elf.Symbol {
	t.Helper()
	sec := f.SectionByType(elf.SHT_SYMTAB)
	if sec == nil {
		return nil
	}
	st, err := f.ReadSymtab(sec)
	if err != nil {
		t.Fatalf("read symtab: %v", err)
	}
	out := make(map[string]elf.Symbol, len(st.Entries))
	for _, sym := range st.Entries[1:] {
		out[sym.Name] = sym
	}
	return out
}

func TestIsLocalLabel(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{".Lfoo", true},
		{".L", true},
		{"L1", true},
		{"L.", true},
		{"Lx", false},
		{"foo", false},
		{"", false},
		{".L.1", true},
	}
	for _, c := range cases {
		if got := isLocalLabel(c.in); got != c.want {
			t.Errorf("isLocalLabel(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestMatchSymbol(t *testing.T) {
	exact := Default()
	if !exact.matchSymbol([]string{"foo", "bar"}, "foo") {
		t.Error("exact match failed")
	}
	if exact.matchSymbol([]string{"foo"}, "fo") {
		t.Error("exact matching must not match prefixes")
	}

	wild := Default()
	wild.Wildcard = true
	cases := []struct {
		pats []string
		name string
		want bool
	}{
		{[]string{"fo*"}, "foo", true},
		{[]string{"fo*"}, "bar", false},
		{[]string{"*", "!foo"}, "foo", false},
		{[]string{"*", "!foo"}, "bar", true},
		{[]string{"*", "!fo*"}, "fo", false},
		{[]string{"?oo"}, "foo", true},
		{nil, "foo", false},
	}
	for _, c := range cases {
		if got := wild.matchSymbol(c.pats, c.name); got != c.want {
			t.Errorf("matchSymbol(%v, %q) = %v, want %v", c.pats, c.name, got, c.want)
		}
	}
	if !exact.symMatch("foo", "foo") || exact.symMatch("fo*", "foo") {
		t.Error("symMatch must be exact without Wildcard")
	}
	if !wild.symMatch("fo*", "foo") {
		t.Error("symMatch must use fnmatch with Wildcard")
	}
}

func TestIsHiddenSymbol(t *testing.T) {
	cases := []struct {
		vis  byte
		want bool
	}{
		{elf.STV_DEFAULT, false},
		{elf.STV_HIDDEN, true},
		{elf.STV_INTERNAL, true},
		{elf.STV_PROTECTED, false},
	}
	for _, c := range cases {
		sym := elf.Symbol{}
		sym.SetVisibility(c.vis)
		if got := isHiddenSymbol(&sym); got != c.want {
			t.Errorf("isHiddenSymbol(vis=%d) = %v, want %v", c.vis, got, c.want)
		}
	}
}

func TestFatalErrorMessage(t *testing.T) {
	err := &FatalError{Msg: "boom"}
	if err.Error() != "boom" {
		t.Errorf("Error() = %q", err.Error())
	}
}

// applyOn runs Transform on a fresh fixture and returns the resulting model.
func applyOn(t *testing.T, fixture string, mutate func(*Config)) *elf.File {
	t.Helper()
	f := openFixtureFile(t, fixture)
	c := Default()
	mutate(c)
	if err := Transform(f, c); err != nil {
		t.Fatalf("Transform: %v", err)
	}
	return f
}

func TestApplySymbolsStripAllRemovesTable(t *testing.T) {
	f := applyOn(t, "reloc.o", func(c *Config) { c.StripAll = true })
	if f.SectionByType(elf.SHT_SYMTAB) != nil {
		t.Error("--strip-all must drop .symtab")
	}
	for _, name := range []string{".strtab", ".rela.text", ".rela.eh_frame"} {
		if f.Section(name) != nil {
			t.Errorf("--strip-all must drop %s", name)
		}
	}
}

func TestApplySymbolsKeepWithStrip(t *testing.T) {
	f := applyOn(t, "reloc.o", func(c *Config) {
		c.StripAll = true
		c.KeepSymbols = []string{"func_a"}
	})
	syms := symbolMap(t, f)
	if _, ok := syms["func_a"]; !ok {
		t.Fatalf("func_a not kept: %v", syms)
	}
	for _, gone := range []string{"func_b", "local_var", "ext_var"} {
		if _, ok := syms[gone]; ok {
			t.Errorf("%s should have been stripped", gone)
		}
	}
	// Whatever relocation sections remain must reference valid entries.
	for _, s := range f.Sections {
		if s.Type != elf.SHT_REL && s.Type != elf.SHT_RELA {
			continue
		}
		relocs, err := f.ReadRelocs(s)
		if err != nil {
			t.Fatalf("read %s: %v", s.Name, err)
		}
		for _, r := range relocs {
			if int(r.Sym) > len(syms)+1 {
				t.Errorf("%s: relocation symbol index %d out of range", s.Name, r.Sym)
			}
		}
	}
}

func TestApplySymbolsLocalizeGlobalizeWeaken(t *testing.T) {
	f := applyOn(t, "reloc.o", func(c *Config) { c.LocalizeSymbols = []string{"func_a"} })
	if got := symbolMap(t, f)["func_a"].Bind(); got != elf.STB_LOCAL {
		t.Errorf("localized func_a bind = %d", got)
	}

	// Localize first so that the globalize branch has a local symbol to act on.
	f = applyOn(t, "reloc.o", func(c *Config) {
		c.LocalizeSymbols = []string{"func_a"}
		c.GlobalizeSymbols = []string{"func_a"}
	})
	if got := symbolMap(t, f)["func_a"].Bind(); got != elf.STB_GLOBAL {
		t.Errorf("globalized func_a bind = %d", got)
	}

	f = applyOn(t, "reloc.o", func(c *Config) { c.WeakenSymbols = []string{"func_a"} })
	if got := symbolMap(t, f)["func_a"].Bind(); got != elf.STB_WEAK {
		t.Errorf("weakened func_a bind = %d", got)
	}

	f = applyOn(t, "reloc.o", func(c *Config) { c.WeakenAll = true })
	for name, sym := range symbolMap(t, f) {
		if sym.Bind() == elf.STB_GLOBAL {
			t.Errorf("%s still global after --weaken", name)
		}
	}
}

func TestApplySymbolsRedefineAndAdd(t *testing.T) {
	f := applyOn(t, "reloc.o", func(c *Config) {
		c.Redefines = []Redefine{{Old: "func_a", New: "renamed_a"}}
		c.AddSymbols = []AddSymbol{
			{Name: "abs_new", Value: 0x1234, Bind: elf.STB_GLOBAL},
			{Name: "data_new", Section: ".data", Value: 0x10, Bind: elf.STB_LOCAL},
		}
	})
	syms := symbolMap(t, f)
	if _, ok := syms["renamed_a"]; !ok {
		t.Errorf("redefine didn't rename func_a: %v", syms)
	}
	abs, ok := syms["abs_new"]
	if !ok || abs.Shndx != elf.SHN_ABS || abs.Value != 0x1234 {
		t.Errorf("added absolute symbol = %+v", abs)
	}
	data, ok := syms["data_new"]
	if !ok {
		t.Fatalf("added .data symbol missing")
	}
	if data.Bind() != elf.STB_LOCAL || data.Value != 0x10 {
		t.Errorf("added .data symbol = %+v", data)
	}
	if data.Shndx >= uint16(len(f.Sections)) || f.Sections[data.Shndx].Name != ".data" {
		t.Errorf("added .data symbol shndx = %d", data.Shndx)
	}
}

func TestApplySymbolsAddMissingSectionIsFatal(t *testing.T) {
	f := openFixtureFile(t, "reloc.o")
	c := Default()
	c.AddSymbols = []AddSymbol{{Name: "x", Section: ".nosuch", Value: 1}}
	err := Transform(f, c)
	if err == nil {
		t.Fatal("expected a fatal error for a missing section")
	}
	if _, ok := err.(*FatalError); !ok {
		t.Fatalf("error type = %T, want *FatalError", err)
	}
}

func TestApplySymbolsDiscard(t *testing.T) {
	f := applyOn(t, "reloc.o", func(c *Config) { c.DiscardAll = true })
	syms := symbolMap(t, f)
	// Local labels and locals not referenced by relocations disappear.
	if _, ok := syms["local_var"]; ok {
		t.Error("local_var should be discarded by -x")
	}

	f = applyOn(t, "reloc.o", func(c *Config) { c.DiscardLocals = true })
	if _, ok := symbolMap(t, f)["local_var"]; ok {
		t.Error("local_var should be discarded by -X")
	}
}

func TestApplySymbolsStripDebug(t *testing.T) {
	f := applyOn(t, "reloc.o", func(c *Config) { c.StripDebug = true })
	for name, sym := range symbolMap(t, f) {
		if sym.Type() == elf.STT_FILE {
			t.Errorf("file symbol %q survived -g", name)
		}
	}
	if _, ok := symbolMap(t, f)["func_a"]; !ok {
		t.Error("func_a must survive -g")
	}
}

func TestApplySymbolsOnlySections(t *testing.T) {
	f := applyOn(t, "hello", func(c *Config) {
		c.OnlySections = []string{".text"}
	})
	syms := symbolMap(t, f)
	if len(syms) == 0 {
		t.Skip("no static symbols kept on this fixture")
	}
	for name, sym := range syms {
		if sym.Shndx == elf.SHN_UNDEF || sym.Shndx == elf.SHN_ABS {
			continue
		}
		if int(sym.Shndx) >= len(f.Sections) {
			t.Errorf("%s: bad shndx %d", name, sym.Shndx)
			continue
		}
		if got := f.Sections[sym.Shndx].Name; got != ".text" {
			t.Errorf("%s defined in %s survives -j .text", name, got)
		}
	}
}

func TestApplySymbolsNoSymtab(t *testing.T) {
	// --strip-section-headers plus a binary-ish file has no symbol table;
	// applySymbols must simply do nothing.
	f := openFixtureFile(t, "hello-stripped")
	if f.SectionByType(elf.SHT_SYMTAB) != nil {
		t.Skip("fixture unexpectedly has a static symbol table")
	}
	if err := Transform(f, Default()); err != nil {
		t.Fatalf("Transform: %v", err)
	}
}

func TestApplySymbolsELFSTTCommon(t *testing.T) {
	// reloc.o has no COMMON symbols; only exercise the no-op path here.
	f := applyOn(t, "reloc.o", func(c *Config) { c.ELFSTTCommon = "yes" })
	for name, sym := range symbolMap(t, f) {
		if sym.Shndx == elf.SHN_COMMON && sym.Type() != elf.STT_COMMON {
			t.Errorf("%s: common symbol type = %d, want STT_COMMON", name, sym.Type())
		}
	}
	f = applyOn(t, "reloc.o", func(c *Config) { c.ELFSTTCommon = "no" })
	for name, sym := range symbolMap(t, f) {
		if sym.Shndx == elf.SHN_COMMON && sym.Type() != elf.STT_OBJECT {
			t.Errorf("%s: common symbol type = %d, want STT_OBJECT", name, sym.Type())
		}
	}
}

// setStaticVisibility rewrites the visibility of named static symbols.
func setStaticVisibility(t *testing.T, f *elf.File, vis map[string]byte) {
	t.Helper()
	sec := f.SectionByType(elf.SHT_SYMTAB)
	if sec == nil {
		t.Fatal("fixture has no static symbol table")
	}
	st, err := f.ReadSymtab(sec)
	if err != nil {
		t.Fatalf("read symtab: %v", err)
	}
	for i := range st.Entries {
		if v, ok := vis[st.Entries[i].Name]; ok {
			st.Entries[i].SetVisibility(v)
		}
	}
	if err := f.SetSymtab(st); err != nil {
		t.Fatalf("set symtab: %v", err)
	}
}

func TestApplySymbolsLocalizeHiddenInjected(t *testing.T) {
	f := openFixtureFile(t, "reloc.o")
	setStaticVisibility(t, f, map[string]byte{
		"func_a": elf.STV_HIDDEN,
		"func_b": elf.STV_INTERNAL,
	})
	c := Default()
	c.LocalizeHidden = true
	if err := Transform(f, c); err != nil {
		t.Fatalf("Transform: %v", err)
	}
	syms := symbolMap(t, f)
	for _, name := range []string{"func_a", "func_b"} {
		if got := syms[name].Bind(); got != elf.STB_LOCAL {
			t.Errorf("%s: bind = %d, want LOCAL after --localize-hidden", name, got)
		}
	}
}

func TestApplySymbolsKeepFileAndSectionSymbols(t *testing.T) {
	// --keep-section-symbols only regenerates section symbols for
	// non-relocatable outputs (GNU objcopy.c marks the output sections before
	// filtering); on a relocatable object it has no effect. Use an executable
	// fixture so both rescues are observable.
	f := applyOn(t, "hello", func(c *Config) {
		c.StripAll = true
		c.KeepFileSymbols = true
		c.KeepSectionSymbols = true
	})
	syms := symbolMap(t, f)
	if len(syms) == 0 {
		t.Fatal("no symbols survived")
	}
	var file, section bool
	for _, sym := range syms {
		switch sym.Type() {
		case elf.STT_FILE:
			file = true
		case elf.STT_SECTION:
			section = true
		}
	}
	if !file {
		t.Error("--keep-file-symbols did not keep a FILE symbol")
	}
	if !section {
		t.Error("--keep-section-symbols did not keep a SECTION symbol")
	}
}

func TestApplySymbolsKeepGlobalSymbols(t *testing.T) {
	f := applyOn(t, "reloc.o", func(c *Config) {
		c.KeepGlobalSymbols = []string{"func_a"}
	})
	syms := symbolMap(t, f)
	if got := syms["func_a"].Bind(); got != elf.STB_GLOBAL {
		t.Errorf("listed global func_a bind = %d, want GLOBAL", got)
	}
	if got := syms["func_b"].Bind(); got != elf.STB_LOCAL {
		t.Errorf("unlisted global func_b bind = %d, want LOCAL", got)
	}
}
