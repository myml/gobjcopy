package objcopy

// Coverage-oriented tests for the section handling code. They exercise the
// pure helpers (fnmatch, matchSectionList, isDebugSection, stripSection) as
// well as every branch of the section transformation steps, either directly
// or through Transform.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

// covSymtab builds a minimal but valid symbol table attached to a string
// table, so that elf.SetSymtab can re-encode it.
func covSymtab(f *elf.File, syms []elf.Symbol) *elf.Section {
	strtab := &elf.Section{SectionHeader: elf.SectionHeader{
		Name: ".strtab", Type: elf.SHT_STRTAB, Addralign: 1,
	}}
	symtab := &elf.Section{SectionHeader: elf.SectionHeader{
		Name: ".symtab", Type: elf.SHT_SYMTAB, Addralign: 8,
		Entsize: uint64(f.SymSize()), Link: uint32(len(f.Sections) + 1),
	}}
	f.Sections = append(f.Sections, symtab, strtab)
	if err := f.SetSymtab(&elf.Symtab{Section: symtab, Entries: syms}); err != nil {
		panic(err)
	}
	return symtab
}

// covELF builds a synthetic ELF image with a null section plus the sections
// given by the caller.
func covELF(secs ...*elf.Section) *elf.File {
	f := &elf.File{
		Header: elf.Header{
			Class:   elf.Class64,
			Data:    elf.DataLSB,
			Type:    elf.ET_REL,
			Version: elf.EV_CURRENT,
		},
		SectionHeadersPresent: true,
	}
	f.Sections = append([]*elf.Section{{}}, secs...)
	return f
}

func covData(name string, addr uint64, data []byte) *elf.Section {
	return &elf.Section{
		SectionHeader: elf.SectionHeader{
			Name:      name,
			Type:      elf.SHT_PROGBITS,
			Flags:     elf.SHF_ALLOC | elf.SHF_WRITE,
			Addr:      addr,
			Addralign: 1,
			Size:      uint64(len(data)),
		},
		Data: data,
	}
}

func TestFnmatchEdgeCases(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"", "", true},
		{"", "x", false},
		{"*", "", true},
		{"*", "anything", true},
		{"**", "anything", true},
		{".data", ".data", true},
		{".data", ".data.x", false},
		{".data*", ".data", true},
		{".data*", ".data.x", true},
		{"*.debug*", "x.debug_info", true},
		{".d?ta", ".data", true},
		{".d?ta", ".dta", false},
		{"[abc]", "b", true},
		{"[abc]", "d", false},
		{"[a-c]", "c", true},
		{"[!a-c]", "d", true},
		{"[^a-c]", "d", true},
		{"[!a-c]", "a", false},
		{"]x", "]x", true},
		{"a[b", "a[b", false}, // unterminated class never matches the class
		{"a[b", "ab", false},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"a**b", "ab", true},
		{"*a", "ba", true},
		{"?*", "ab", true},
		{"?.txt", "a.txt", true},
		{"?.txt", "ab.txt", false},
	}
	for _, tc := range cases {
		if got := fnmatch(tc.pattern, tc.name); got != tc.want {
			t.Errorf("fnmatch(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestMatchSectionList(t *testing.T) {
	cases := []struct {
		patterns []string
		name     string
		want     bool
	}{
		{nil, ".text", false},
		{[]string{".text"}, ".text", true},
		{[]string{".text"}, ".data", false},
		{[]string{".data.*"}, ".data.aa.01", true},
		{[]string{".data.*", "!.data.aa.02"}, ".data.aa.02", false},
		{[]string{".data.*", "!.data.aa.02"}, ".data.aa.01", true},
		// The negation wins even when the positive rule is listed last.
		{[]string{"!.data.aa.02", ".data.*"}, ".data.aa.02", false},
		{[]string{"!*"}, ".text", false},
		// "!" negates the empty pattern, which only matches the empty name.
		{[]string{"!", ""}, "", false},
	}
	for _, tc := range cases {
		if got := matchSectionList(tc.patterns, tc.name); got != tc.want {
			t.Errorf("matchSectionList(%v, %q) = %v, want %v", tc.patterns, tc.name, got, tc.want)
		}
	}
}

func TestIsDebugSectionTable(t *testing.T) {
	cases := []struct {
		sec  *elf.Section
		want bool
	}{
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: ".debug_info"}}, true},
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: ".debug_line"}}, true},
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: ".zdebug_info"}}, true},
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: ".line"}}, true},
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: ".stab"}}, true},
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: ".stab.index"}}, true},
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: ".gnu.linkonce.wi.foo"}}, true},
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: ".gnu.debuglto_.debug_info"}}, true},
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: ".gdb_index"}}, true},
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: ".text"}}, false},
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: "debug_info"}}, false},
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: ""}}, false},
		// Allocated sections are never classified as debugging sections.
		{&elf.Section{SectionHeader: elf.SectionHeader{Name: ".debug_info", Flags: elf.SHF_ALLOC}}, false},
	}
	for _, tc := range cases {
		if got := isDebugSection(tc.sec); got != tc.want {
			t.Errorf("isDebugSection(%q) = %v, want %v", tc.sec.Name, got, tc.want)
		}
	}
	if !isDWOSection(&elf.Section{SectionHeader: elf.SectionHeader{Name: "a.dwo"}}) {
		t.Error("isDWOSection must match a .dwo suffix")
	}
	if isDWOSection(&elf.Section{SectionHeader: elf.SectionHeader{Name: "a.dwox"}}) {
		t.Error("isDWOSection must not match a longer suffix")
	}
}

func TestStripSectionBranches(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		sec    *elf.Section
		want   bool
	}{
		{"shstrtab-kept", func(c *Config) { c.RemoveSections = []string{".shstrtab"} },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".shstrtab", Type: elf.SHT_STRTAB}}, false},
		{"keep-section", func(c *Config) {
			c.StripAll = true
			c.KeepSections = []string{".comment"}
		}, &elf.Section{SectionHeader: elf.SectionHeader{Name: ".comment"}}, false},
		{"extract-dwo", func(c *Config) { c.ExtractDWO = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".text"}}, true},
		{"extract-dwo-keeps", func(c *Config) { c.ExtractDWO = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".debug_info.dwo"}}, false},
		{"strip-dwo", func(c *Config) { c.StripDWO = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".debug_info.dwo"}}, true},
		{"strip-dwo-keeps-other", func(c *Config) { c.StripDWO = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".debug_info"}}, false},
		{"only-sections-keeps-symtab", func(c *Config) { c.OnlySections = []string{".text"} },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".symtab", Type: elf.SHT_SYMTAB}}, false},
		{"only-sections-keeps-symtab-shndx", func(c *Config) { c.OnlySections = []string{".text"} },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".symtab_shndx", Type: elf.SHT_SYMTAB_SHNDX}}, false},
		{"only-sections-keeps-strtab", func(c *Config) { c.OnlySections = []string{".text"} },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".strtab", Type: elf.SHT_STRTAB}}, false},
		{"only-sections-drops-other-strtab", func(c *Config) { c.OnlySections = []string{".text"} },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".other", Type: elf.SHT_STRTAB}}, true},
		{"only-sections-drops-data", func(c *Config) { c.OnlySections = []string{".text"} },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".data"}}, true},
		{"only-sections-keeps-matching", func(c *Config) { c.OnlySections = []string{".text"} },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".text"}}, false},
		{"only-sections-negated", func(c *Config) {
			c.OnlySections = []string{".data.*", "!.data.aa.02"}
		}, &elf.Section{SectionHeader: elf.SectionHeader{Name: ".data.aa.02"}}, true},
		{"remove-section", func(c *Config) { c.RemoveSections = []string{".comment"} },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".comment"}}, true},
		{"remove-section-negated", func(c *Config) {
			c.RemoveSections = []string{".data.*", "!.data.aa.02"}
		}, &elf.Section{SectionHeader: elf.SectionHeader{Name: ".data.aa.02"}}, false},
		{"strip-section-headers-alloc", func(c *Config) { c.StripSectionHeaders = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".text", Flags: elf.SHF_ALLOC}}, false},
		{"strip-section-headers-nonalloc", func(c *Config) { c.StripSectionHeaders = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".data"}}, true},
		{"strip-all-debug", func(c *Config) { c.StripAll = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".debug_info"}}, true},
		{"strip-all-keeps-debuglink", func(c *Config) { c.StripAll = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".gnu_debuglink"}}, false},
		{"strip-all-keeps-debugaltlink", func(c *Config) { c.StripAll = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".gnu_debugaltlink"}}, false},
		{"strip-debug", func(c *Config) { c.StripDebug = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".debug_line"}}, true},
		{"strip-unneeded", func(c *Config) { c.StripUnneeded = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".debug_line"}}, true},
		{"discard-all", func(c *Config) { c.DiscardAll = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".debug_line"}}, true},
		{"extract-dwo-debug", func(c *Config) { c.ExtractDWO = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".debug_line"}}, true},
		{"plain-kept", func(c *Config) {},
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".comment"}}, false},
		{"strip-debug-not-debug", func(c *Config) { c.StripDebug = true },
			&elf.Section{SectionHeader: elf.SectionHeader{Name: ".text", Flags: elf.SHF_ALLOC}}, false},
	}
	for _, tc := range cases {
		c := Default()
		tc.mutate(c)
		if got := c.stripSection(tc.sec); got != tc.want {
			t.Errorf("%s: stripSection(%q) = %v, want %v", tc.name, tc.sec.Name, got, tc.want)
		}
	}
}

func TestParseSectionFlagsAll(t *testing.T) {
	cases := []struct {
		spec     string
		want     uint64
		contents bool
	}{
		{"alloc,code", elf.SHF_WRITE | elf.SHF_ALLOC | elf.SHF_EXECINSTR, false},
		{"readonly", 0, false},
		{"contents", elf.SHF_WRITE, true},
		{"noload", elf.SHF_WRITE, false},
		{"debug,data,rom,share", elf.SHF_WRITE, false},
		{"merge,strings", elf.SHF_WRITE | elf.SHF_MERGE | elf.SHF_STRINGS, false},
		{"info_link", elf.SHF_WRITE | elf.SHF_INFO_LINK, false},
		{"link_order", elf.SHF_WRITE | elf.SHF_LINK_ORDER, false},
		{"group", elf.SHF_WRITE | elf.SHF_GROUP, false},
		{"tls", elf.SHF_WRITE | elf.SHF_TLS, false},
		{"compressed", elf.SHF_WRITE | elf.SHF_COMPRESSED, false},
		{"large", elf.SHF_WRITE | elf.SHF_X86_64_LARGE, false},
		{"exclude", elf.SHF_WRITE | elf.SHF_EXCLUDE, false},
		{"norelro,notls", elf.SHF_WRITE, false},
		{"load", elf.SHF_WRITE | elf.SHF_ALLOC, false},
		{"", elf.SHF_WRITE, false},
	}
	for _, tc := range cases {
		flags, contents, err := ParseSectionFlags(tc.spec)
		if err != nil {
			t.Fatalf("ParseSectionFlags(%q): %v", tc.spec, err)
		}
		if flags != tc.want || contents != tc.contents {
			t.Errorf("ParseSectionFlags(%q) = %#x,%v want %#x,%v",
				tc.spec, flags, contents, tc.want, tc.contents)
		}
	}
	if _, _, err := ParseSectionFlags("bogus"); err == nil {
		t.Error("ParseSectionFlags must reject an unknown flag")
	}
	// noload clears the alloc bit that a previous token set.
	if flags, _, _ := ParseSectionFlags("alloc,noload"); flags&elf.SHF_ALLOC != 0 {
		t.Errorf("noload did not clear SHF_ALLOC: %#x", flags)
	}
}

func TestSetSectionFlagsContentsOnNobits(t *testing.T) {
	f := covELF(&elf.Section{SectionHeader: elf.SectionHeader{
		Name: ".bss", Type: elf.SHT_NOBITS, Size: 4,
	}})
	if err := setSectionFlags(f, f.Section(".bss"), "alloc,contents"); err != nil {
		t.Fatal(err)
	}
	sec := f.Section(".bss")
	if sec.Type != elf.SHT_PROGBITS || len(sec.Data) != 4 {
		t.Errorf("contents flag did not materialise .bss: type %#x len %d", sec.Type, len(sec.Data))
	}
}

func TestApplySectionFlagsWildcardAndWarning(t *testing.T) {
	var warned []string
	f := applyOn(t, "custom", func(c *Config) {
		c.SetSectionFlags = []SectionFlags{
			{Name: ".my*", Flags: "readonly,code"},
			{Name: ".nosuch", Flags: "alloc"},
		}
		c.Warnf = func(format string, args ...any) { warned = append(warned, format) }
	})
	for _, name := range []string{".mydata", ".myrodata", ".mydata2"} {
		sec := f.Section(name)
		if sec == nil {
			t.Fatalf("missing section %s", name)
		}
		if sec.Flags&elf.SHF_WRITE != 0 || sec.Flags&elf.SHF_EXECINSTR == 0 {
			t.Errorf("%s: flags not applied: %#x", name, sec.Flags)
		}
	}
	if len(warned) == 0 {
		t.Error("unmatched --set-section-flags must warn")
	}
}

func TestApplySectionAlignment(t *testing.T) {
	f := applyOn(t, "custom", func(c *Config) {
		c.SetSectionAlignment = []SectionAlign{{Name: ".mydata*", Align: 32}}
		c.SetSectionAlignments = []SectionAlign{{Name: ".myrodata", Align: 64}}
	})
	if got := f.Section(".mydata").Addralign; got != 32 {
		t.Errorf(".mydata alignment = %d", got)
	}
	if got := f.Section(".mydata2").Addralign; got != 32 {
		t.Errorf(".mydata2 alignment = %d", got)
	}
	if got := f.Section(".myrodata").Addralign; got != 64 {
		t.Errorf(".myrodata alignment = %d", got)
	}

	f = covELF(covData(".text", 0, []byte{1}))
	err := Transform(f, &Config{SetSectionAlignment: []SectionAlign{{Name: ".text", Align: 3}}})
	if err == nil {
		t.Error("non power of two alignment must fail")
	}
	err = Transform(covELF(covData(".text", 0, []byte{1})),
		&Config{SetSectionAlignment: []SectionAlign{{Name: ".text", Align: 0}}})
	if err == nil {
		t.Error("zero alignment must fail")
	}

	var warned bool
	f = covELF(covData(".text", 0, []byte{1}))
	c := &Config{
		SetSectionAlignment: []SectionAlign{{Name: ".nosuch", Align: 8}},
		Warnf:               func(string, ...any) { warned = true },
	}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if !warned {
		t.Error("unmatched --set-section-alignment must warn")
	}
}

func TestRenameSectionWithFlagsAndWarning(t *testing.T) {
	var warned bool
	f := covELF(covData(".old", 0, []byte{1, 2, 3, 4}))
	c := Default()
	flags := "alloc,code"
	c.Renames = []Rename{
		{Old: ".old", New: ".new", Flags: &flags},
		{Old: ".missing", New: ".other"},
	}
	c.Warnf = func(string, ...any) { warned = true }
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	sec := f.Section(".new")
	if sec == nil {
		t.Fatal("rename did not happen")
	}
	if sec.Flags&elf.SHF_EXECINSTR == 0 {
		t.Errorf("rename flags not applied: %#x", sec.Flags)
	}
	if !warned {
		t.Error("unmatched --rename-section must warn")
	}
}

func TestAddUpdateDumpSections(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "contents")
	if err := os.WriteFile(src, []byte{9, 8, 7, 6}, 0o644); err != nil {
		t.Fatal(err)
	}
	f := covELF(
		covData(".data", 0, []byte{1, 2, 3, 4}),
		&elf.Section{SectionHeader: elf.SectionHeader{Name: ".bss", Type: elf.SHT_NOBITS, Size: 8}},
	)
	c := Default()
	c.AddSections = []AddSection{{Name: ".added", File: src}}
	c.UpdateSections = []UpdateSection{
		{Name: ".data", File: src},
		{Name: ".bss", File: src},
	}
	dump := filepath.Join(dir, "dumped")
	c.DumpSections = []DumpSection{{Name: ".added", File: dump}}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	added := f.Section(".added")
	if added == nil || len(added.Data) != 4 || added.Size != 4 {
		t.Errorf("added section wrong: %+v", added)
	}
	if got := f.Section(".data"); string(got.Data) != string([]byte{9, 8, 7, 6}) {
		t.Errorf("update-section content = %v", got.Data)
	}
	if got := f.Section(".bss"); got.Type != elf.SHT_PROGBITS || len(got.Data) != 4 {
		t.Errorf("update-section on NOBITS = type %#x len %d", got.Type, len(got.Data))
	}
	if data, err := os.ReadFile(dump); err != nil || string(data) != string([]byte{9, 8, 7, 6}) {
		t.Errorf("dump-section = %v, %v", data, err)
	}

	// Missing sections produce diagnostics but not fatal errors for dump.
	var warnings int
	f = covELF(covData(".data", 0, nil))
	c = Default()
	c.Warnf = func(string, ...any) { warnings++ }
	c.DumpSections = []DumpSection{
		{Name: ".nosuch", File: filepath.Join(dir, "x1")},
		{Name: ".bss", File: filepath.Join(dir, "x2")},
	}
	f.Sections = append(f.Sections, &elf.Section{SectionHeader: elf.SectionHeader{Name: ".bss", Type: elf.SHT_NOBITS}})
	if err := applyAddUpdateSections(f, c); err != nil {
		t.Fatalf("dump-section diagnostics must not be fatal: %v", err)
	}
	if warnings != 2 {
		t.Errorf("dump-section warnings = %d, want 2", warnings)
	}

	// Missing add-section file and update-section target are errors.
	if err := applyAddUpdateSections(covELF(),
		&Config{AddSections: []AddSection{{Name: ".x", File: filepath.Join(dir, "nope")}}}); err == nil {
		t.Error("missing --add-section file must fail")
	}
	err := applyAddUpdateSections(covELF(covData(".data", 0, nil)),
		&Config{UpdateSections: []UpdateSection{{Name: ".bar", File: src}}})
	if err == nil {
		t.Error("missing --update-section target must fail")
	} else if msg := err.Error(); msg != "error: .bar not found, can't be updated" {
		t.Errorf("update-section message = %q", msg)
	}
}

func TestUpdateSectionThroughRename(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "contents")
	if err := os.WriteFile(src, []byte{1, 2, 3, 4}, 0o644); err != nil {
		t.Fatal(err)
	}
	f := covELF(covData(".bar", 0, []byte{5}))
	c := Default()
	c.Renames = []Rename{{Old: ".bar", New: ".foo"}}
	c.UpdateSections = []UpdateSection{{Name: ".bar", File: src}}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	sec := f.Section(".foo")
	if sec == nil || len(sec.Data) != 4 {
		t.Fatalf("renamed+updated section wrong: %+v", sec)
	}
	if f.Section(".bar") != nil {
		t.Error("old section name still present")
	}

	// A section that is both updated and removed is a fatal error.
	f = covELF(covData(".foo", 0, []byte{1}))
	c = Default()
	c.UpdateSections = []UpdateSection{{Name: ".foo", File: src}}
	c.RemoveSections = []string{".foo"}
	err := Transform(f, c)
	if err == nil {
		t.Error("update + remove must fail")
	} else if msg := err.Error(); msg != "error: section .foo matches both update and remove options" {
		t.Errorf("update+remove message = %q", msg)
	}
}

func TestRemoveSectionAndCopyConflict(t *testing.T) {
	f := covELF(covData(".text", 0, []byte{1}), covData(".data", 0, []byte{2}))
	c := Default()
	c.OnlySections = []string{".*"}
	c.RemoveSections = []string{".text"}
	err := Transform(f, c)
	if err == nil {
		t.Error("section matching both -j and -R must fail")
	} else if msg := err.Error(); msg != "error: section .text matches both remove and copy options" {
		t.Errorf("remove+copy message = %q", msg)
	}
}

func TestRemoveRelocationsNegation(t *testing.T) {
	mk := func() *elf.File {
		data := covData(".data.one", 0, []byte{1, 2, 3, 4})
		other := covData(".data.two", 0, []byte{5, 6, 7, 8})
		f := covELF(data, other)
		rela := &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".rela.data.one", Type: elf.SHT_RELA, Addralign: 8, Entsize: 24,
			Info: 1, Flags: elf.SHF_INFO_LINK,
		}}
		relb := &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".rela.data.two", Type: elf.SHT_RELA, Addralign: 8, Entsize: 24,
			Info: 2, Flags: elf.SHF_INFO_LINK,
		}}
		f.Sections = append(f.Sections, rela, relb)
		for _, s := range []*elf.Section{rela, relb} {
			s.Data = make([]byte, 24)
			s.Size = 24
		}
		return f
	}
	f := mk()
	if err := applyRemoveRelocations(f, &Config{RemoveRelocations: []string{".data.*", "!.data.two"}}); err != nil {
		t.Fatal(err)
	}
	if f.Section(".rela.data.one") != nil {
		t.Error(".rela.data.one should have been removed")
	}
	if f.Section(".rela.data.two") == nil {
		t.Error(".rela.data.two is negated and must stay")
	}

	// A relocation section with an out of range sh_info falls back to the name.
	f = mk()
	f.Sections[3].Info = 99
	if err := applyRemoveRelocations(f, &Config{RemoveRelocations: []string{".data.one"}}); err != nil {
		t.Fatal(err)
	}
	if f.Section(".rela.data.one") != nil {
		t.Error("name-derived relocation target did not match")
	}
	// Matching the relocation section name directly also works.
	f = mk()
	if err := applyRemoveRelocations(f, &Config{RemoveRelocations: []string{".rela.data.two"}}); err != nil {
		t.Fatal(err)
	}
	if f.Section(".rela.data.two") != nil {
		t.Error("relocation section name pattern did not match")
	}
	if err := applyRemoveRelocations(mk(), Default()); err != nil {
		t.Fatal(err)
	}
}

func TestAddDelta(t *testing.T) {
	if got := addDelta(10, 5); got != 15 {
		t.Errorf("addDelta positive = %d", got)
	}
	if got := addDelta(10, -4); got != 6 {
		t.Errorf("addDelta negative = %d", got)
	}
	if got := addDelta(10, 0); got != 10 {
		t.Errorf("addDelta zero = %d", got)
	}
}

func TestAddressChangesMatrix(t *testing.T) {
	start := uint64(0x2000)
	delta := int64(-0x10)
	d := int64(0x100)
	f := covELF(covData(".text", 0x1000, []byte{1}), covData(".data", 0x2000, []byte{2}))
	c := Default()
	c.SetStart = &start
	c.ChangeStart = &delta
	c.ChangeAddresses = &d
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if want := uint64(0x2000 - 0x10 + 0x100); f.Entry != want {
		t.Errorf("entry = %#x want %#x", f.Entry, want)
	}
	if got := f.Section(".text").Addr; got != 0x1000+0x100 {
		t.Errorf(".text addr = %#x", got)
	}

	// Per section VMA/LMA set/add/sub.
	set := uint64(0x5000)
	f = covELF(covData(".text", 0x1000, []byte{1}))
	c = Default()
	c.ChangeSectionVMA = []SectionAddr{
		{Name: ".text", Op: AddrSet, Val: set},
	}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if got := f.Section(".text").Addr; got != set {
		t.Errorf("VMA set = %#x", got)
	}

	f = covELF(covData(".text", 0x1000, []byte{1}))
	c = Default()
	c.ChangeSectionVMA = []SectionAddr{{Name: ".text", Op: AddrAdd, Val: 16}}
	c.ChangeSectionLMA = []SectionAddr{{Name: ".text", Op: AddrAdd, Val: 32}}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if got := f.Section(".text").Addr; got != 0x1010 {
		t.Errorf("VMA add = %#x", got)
	}
	if lma := f.Section(".text").LMA; lma == nil || *lma != 0x1010+32 {
		t.Errorf("LMA add = %v", lma)
	}

	f = covELF(covData(".text", 0x1000, []byte{1}))
	c = Default()
	c.ChangeSectionVMA = []SectionAddr{{Name: ".text", Op: AddrSub, Val: 16}}
	c.ChangeSectionLMA = []SectionAddr{
		{Name: ".text", Op: AddrSet, Val: 0x9000},
		{Name: ".text", Op: AddrSub, Val: 0x10},
	}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if got := f.Section(".text").Addr; got != 0xff0 {
		t.Errorf("VMA sub = %#x", got)
	}
	if lma := f.Section(".text").LMA; lma == nil || *lma != 0x8ff0 {
		t.Errorf("LMA set/sub = %v", lma)
	}

	// --change-section-address updates both VMA and LMA.
	f = covELF(covData(".text", 0x1000, []byte{1}))
	c = Default()
	c.ChangeSectionAddr = []SectionAddr{{Name: ".text*", Op: AddrSet, Val: 0x7000}}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	sec := f.Section(".text")
	if sec.Addr != 0x7000 || sec.LMA == nil || *sec.LMA != 0x7000 {
		t.Errorf("change-section-address: addr %#x lma %v", sec.Addr, sec.LMA)
	}

	// Unmatched names warn.
	var warned bool
	f = covELF(covData(".text", 0x1000, []byte{1}))
	c = Default()
	c.Warnf = func(string, ...any) { warned = true }
	c.ChangeSectionVMA = []SectionAddr{{Name: ".nosuch", Op: AddrSet, Val: 1}}
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if !warned {
		t.Error("unmatched --change-section-vma must warn")
	}
}

func TestAdjustSymbolValuesForExecutable(t *testing.T) {
	f := openFixtureFile(t, "custom")
	// Symbol my_ro lives in .myrodata; shifting that section must shift the
	// symbol's value because the file is not relocatable.
	sec := f.Section(".myrodata")
	if sec == nil {
		t.Skip("custom fixture lacks .myrodata")
	}
	before := symbolMap(t, f)["my_ro"]
	c := Default()
	c.ChangeSectionVMA = []SectionAddr{{Name: ".myrodata", Op: AddrAdd, Val: 0x1000}}
	if f.Type != elf.ET_REL {
		if err := applyAddressChanges(f, c); err != nil {
			t.Fatal(err)
		}
		after := symbolMap(t, f)["my_ro"]
		if after.Value != before.Value+0x1000 {
			t.Errorf("symbol my_ro value = %#x want %#x", after.Value, before.Value+0x1000)
		}
	}
}

func TestGapFillAndPadTo(t *testing.T) {
	mk := func() *elf.File {
		a := covData(".a", 0x1000, []byte{1, 2, 3, 4})
		b := covData(".b", 0x1010, []byte{5, 6})
		nb := &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".nobits", Type: elf.SHT_NOBITS, Flags: elf.SHF_ALLOC, Size: 4,
		}}
		zero := &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".zero", Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC, Size: 0,
		}}
		nonalloc := &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".comment", Type: elf.SHT_PROGBITS, Addr: 0x5000,
		}}
		nonalloc.Data = []byte{0xaa}
		f := covELF(nb, zero, nonalloc, b, a)
		return f
	}
	fill := uint64(0xaa)
	f := mk()
	c := Default()
	c.GapFill = &fill
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	a := f.Section(".a")
	if len(a.Data) != 0x10 {
		t.Errorf("gap-fill data length = %d, want 16", len(a.Data))
	}
	for i := 4; i < len(a.Data); i++ {
		if a.Data[i] != 0xaa {
			t.Fatalf("gap byte %d = %#x", i, a.Data[i])
		}
	}

	// pad-to with and without a fill byte.
	pad := uint64(0x1020)
	f = mk()
	c = Default()
	c.PadTo = &pad
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if got := len(f.Section(".b").Data); got != 0x10 {
		t.Errorf("pad-to length = %d", got)
	}

	f = mk()
	c = Default()
	c.PadTo = &pad
	c.GapFill = &fill
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	b := f.Section(".b")
	if got := len(b.Data); got != 0x10 {
		t.Errorf("pad-to+gap-fill length = %d", got)
	}
	if b.Data[len(b.Data)-1] != 0xaa {
		t.Errorf("pad-to fill byte = %#x", b.Data[len(b.Data)-1])
	}

	// pad-to below the current end is a no-op.
	small := uint64(1)
	f = mk()
	c = Default()
	c.PadTo = &small
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if got := len(f.Section(".b").Data); got != 2 {
		t.Errorf("pad-to no-op length = %d", got)
	}

	// No allocated sections at all: both steps return early.
	empty := covELF()
	c = Default()
	c.GapFill = &fill
	c.PadTo = &pad
	if err := Transform(empty, c); err != nil {
		t.Fatal(err)
	}
}

func TestPruneSegments(t *testing.T) {
	f := &elf.File{
		Header: elf.Header{Class: elf.Class64, Data: elf.DataLSB, Type: elf.ET_EXEC},
		Segments: []*elf.ProgramHeader{
			{Type: elf.PT_LOAD, Offset: 0, Vaddr: 0x1000, Paddr: 0x1000, Memsz: 0x100},
			{Type: elf.PT_LOAD, Offset: 0x100, Vaddr: 0x2000, Paddr: 0x2000, Memsz: 0x100},
			{Type: elf.PT_INTERP, Vaddr: 0x3000, Memsz: 0x10},
			{Type: elf.PT_DYNAMIC, Vaddr: 0x3000, Memsz: 0x10},
			{Type: elf.PT_TLS, Vaddr: 0x3000, Memsz: 0x10},
			{Type: elf.PT_GNU_EH_FRAME, Vaddr: 0x3000, Memsz: 0x10},
			{Type: elf.PT_GNU_PROPERTY, Vaddr: 0x3000, Memsz: 0x10},
			{Type: elf.PT_NOTE, Vaddr: 0x3000, Memsz: 0x10},
			{Type: elf.PT_PHDR, Vaddr: 0x40, Memsz: 0x10},
		},
	}
	f.Sections = []*elf.Section{
		{},
		covData(".text", 0x1000, []byte{1}),
		// A section in the second PT_LOAD keeps that segment alive.
		covData(".rodata", 0x2010, []byte{2}),
		{SectionHeader: elf.SectionHeader{Name: ".note.mine", Type: elf.SHT_NOTE, Flags: elf.SHF_ALLOC, Addr: 0x3000, Size: 4}},
	}
	// Nothing is removed yet: only the second PT_LOAD loses its section below.
	if err := applyPruneSegments(f, Default()); err != nil {
		t.Fatal(err)
	}
	types := map[uint32]bool{}
	for _, ph := range f.Segments {
		types[ph.Type] = true
	}
	if !types[elf.PT_LOAD] || types[elf.PT_INTERP] || types[elf.PT_DYNAMIC] ||
		types[elf.PT_TLS] || types[elf.PT_GNU_EH_FRAME] || types[elf.PT_GNU_PROPERTY] {
		t.Errorf("unexpected surviving segments: %v", types)
	}
	if !types[elf.PT_NOTE] {
		t.Error("PT_NOTE with a matching note section must survive")
	}
	if !types[elf.PT_PHDR] {
		t.Error("PT_PHDR must survive")
	}

	// A PT_LOAD whose backing section is gone must be dropped.
	f = &elf.File{
		Header: elf.Header{Class: elf.Class64, Data: elf.DataLSB, Type: elf.ET_EXEC},
		Segments: []*elf.ProgramHeader{
			{Type: elf.PT_LOAD, Offset: 0x100, Vaddr: 0x9000, Paddr: 0x9000, Memsz: 0x10},
			{Type: elf.PT_NOTE, Vaddr: 0x9000, Memsz: 0x10},
		},
		Sections: []*elf.Section{{}, covData(".text", 0x1000, []byte{1})},
	}
	if err := applyPruneSegments(f, Default()); err != nil {
		t.Fatal(err)
	}
	if len(f.Segments) != 0 {
		t.Errorf("stale segments survived: %d", len(f.Segments))
	}
}

func TestGroupFixupsAndPrune(t *testing.T) {
	order := elf.DataLSB.Order()
	groupData := func(members ...uint32) []byte {
		data := make([]byte, 4*(1+len(members)))
		order.PutUint32(data, 1) // GRP_COMDAT
		for i, m := range members {
			order.PutUint32(data[4*(i+1):], m)
		}
		return data
	}
	build := func() *elf.File {
		g := &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".group", Type: elf.SHT_GROUP, Addralign: 4,
			Flags: elf.SHF_GROUP, Info: 1,
		}}
		g.Data = groupData(2, 3)
		g.Size = uint64(len(g.Data))
		t1 := covData(".text.foo", 0, []byte{1})
		t1.Flags |= elf.SHF_GROUP
		t2 := covData(".data.foo", 0, []byte{2})
		t2.Flags |= elf.SHF_GROUP
		f := covELF(g, t1, t2)
		covSymtab(f, []elf.Symbol{
			{},
			{Name: "foo", Info: elf.STB_LOCAL << 4, Shndx: 1},
		})
		g.Link = uint32(f.SectionIndex(f.SectionByType(elf.SHT_SYMTAB)))
		return f
	}

	// Removing one member keeps the group but drops its entry.
	f := build()
	remove := map[int]bool{f.SectionIndex(f.Section(".data.foo")): true}
	groups := (&Config{}).groupFixups(f, remove)
	if err := removeSections(f, remove); err != nil {
		t.Fatal(err)
	}
	if err := fixupGroups(f, groups); err != nil {
		t.Fatal(err)
	}
	g := f.Section(".group")
	if g == nil {
		t.Fatal("group section disappeared")
	}
	if len(g.Data) != 8 || g.Size != 8 {
		t.Errorf("group size = %d/%d want 8", len(g.Data), g.Size)
	}
	if got := order.Uint32(g.Data[4:]); got != uint32(f.SectionIndex(f.Section(".text.foo"))) {
		t.Errorf("group member = %d want %d", got, f.SectionIndex(f.Section(".text.foo")))
	}
	if g.Info != 1 {
		t.Errorf("group sh_info = %d want 1", g.Info)
	}

	// Removing every member removes the group and clears SHF_GROUP.
	f = build()
	remove = map[int]bool{}
	for _, name := range []string{".text.foo", ".data.foo"} {
		remove[f.SectionIndex(f.Section(name))] = true
	}
	groups = (&Config{}).groupFixups(f, remove)
	if len(groups) != 0 {
		t.Errorf("group should be stripped, got %d survivors", len(groups))
	}
	if !remove[f.SectionIndex(f.Section(".group"))] {
		t.Error("empty group not scheduled for removal")
	}
	if f.Section(".text.foo").Flags&elf.SHF_GROUP != 0 {
		t.Error("SHF_GROUP not cleared from surviving member")
	}

	// Stripping the signature symbol drops the group.
	f = build()
	c := Default()
	c.StripSymbols = []string{"foo"}
	remove = map[int]bool{}
	(&Config{StripSymbols: c.StripSymbols}).groupFixups(f, remove)
	if !remove[f.SectionIndex(f.Section(".group"))] {
		t.Error("group with a stripped signature must be removed")
	}

	// --strip-all without -K drops it too, -K keeps it.
	f = build()
	remove = map[int]bool{}
	(&Config{StripAll: true}).groupFixups(f, remove)
	if !remove[f.SectionIndex(f.Section(".group"))] {
		t.Error("--strip-all must drop the group")
	}
	f = build()
	remove = map[int]bool{}
	(&Config{StripAll: true, KeepSymbols: []string{"foo"}}).groupFixups(f, remove)
	if remove[f.SectionIndex(f.Section(".group"))] {
		t.Error("-K foo must keep the group")
	}

	// A signature symbol that lives in a removed section takes the group down.
	f = build()
	remove = map[int]bool{}
	sigShndx, ok := groupSigShndx(f, f.Section(".group"))
	if !ok {
		t.Fatal("groupSigShndx failed")
	}
	remove[int(sigShndx)] = true
	(&Config{}).groupFixups(f, remove)
	if !remove[f.SectionIndex(f.Section(".group"))] {
		t.Error("group whose signature section is removed must be removed")
	}

	// readGroup tolerates a missing symtab and fixupGroups a nil group.
	noSym := covELF(&elf.Section{SectionHeader: elf.SectionHeader{
		Name: ".group", Type: elf.SHT_GROUP, Link: 9, Info: 3,
	}, Data: groupData()})
	sig, members := readGroup(noSym, noSym.Section(".group"))
	if sig != "" || len(members) != 0 {
		t.Errorf("readGroup without symtab = %q %v", sig, members)
	}
	if _, ok := groupSigShndx(noSym, noSym.Section(".group")); ok {
		t.Error("groupSigShndx must fail without a symtab")
	}
	if err := fixupGroups(noSym, []groupState{{sec: &elf.Section{SectionHeader: elf.SectionHeader{Name: "gone"}}}}); err != nil {
		t.Errorf("fixupGroups for a missing section: %v", err)
	}
}

func TestApplyOnlyKeepDebugBranches(t *testing.T) {
	debug := &elf.Section{SectionHeader: elf.SectionHeader{
		Name: ".debug_info", Type: elf.SHT_PROGBITS, Flags: elf.SHF_WRITE,
	}, Data: []byte{3}}
	f := covELF(
		covData(".text", 0x1000, []byte{1, 2}),
		debug,
		&elf.Section{SectionHeader: elf.SectionHeader{Name: ".bss", Type: elf.SHT_NOBITS, Flags: elf.SHF_ALLOC, Size: 4}},
		&elf.Section{SectionHeader: elf.SectionHeader{Name: ".note.mine", Type: elf.SHT_NOTE, Flags: elf.SHF_ALLOC, Size: 4}},
		&elf.Section{SectionHeader: elf.SectionHeader{Name: ".text.foo", Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC | elf.SHF_GROUP}, Data: []byte{4}},
		&elf.Section{SectionHeader: elf.SectionHeader{Name: ".comment", Type: elf.SHT_PROGBITS}},
	)
	if err := applyOnlyKeepDebug(f, &Config{OnlyKeepDebug: true}); err != nil {
		t.Fatal(err)
	}
	if f.Section(".text").Type != elf.SHT_NOBITS {
		t.Error(".text must become NOBITS")
	}
	if f.Section(".text").Data != nil {
		t.Error(".text contents must be dropped")
	}
	if f.Section(".debug_info").Type != elf.SHT_PROGBITS {
		t.Error("debug sections keep their type")
	}
	if f.Section(".bss").Type != elf.SHT_NOBITS {
		t.Error("NOBITS sections are untouched")
	}
	if f.Section(".note.mine").Type != elf.SHT_NOTE {
		t.Error("note sections are untouched")
	}
	if f.Section(".text.foo").Type != elf.SHT_PROGBITS {
		t.Error("group sections keep their contents")
	}
	if f.Section(".comment").Type != elf.SHT_PROGBITS {
		t.Error("non-alloc sections are untouched")
	}
}

func TestApplySectionContentsReverseAndInterleave(t *testing.T) {
	f := covELF(covData(".data", 0, []byte{1, 2, 3, 4, 5, 6, 7, 8}))
	c := Default()
	c.ReverseBytes = 4
	if err := c.applySectionContents(f); err != nil {
		t.Fatal(err)
	}
	want := []byte{4, 3, 2, 1, 8, 7, 6, 5}
	if string(f.Section(".data").Data) != string(want) {
		t.Errorf("reversed = %v want %v", f.Section(".data").Data, want)
	}

	// A length that is not a multiple of the chunk size is a fatal error.
	f = covELF(covData(".data", 0, []byte{1, 2, 3}))
	if err := (&Config{ReverseBytes: 4}).applySectionContents(f); err == nil {
		t.Error("non-multiple reverse must fail")
	}

	// --interleave keeps copy_width bytes out of every interleave bytes.
	f = covELF(covData(".data", 0, []byte{1, 2, 3, 4, 5, 6, 7, 8}))
	c = Default()
	c.Interleave = 4
	c.Byte = 0
	c.InterleaveWidth = 2
	if err := c.applySectionContents(f); err != nil {
		t.Fatal(err)
	}
	sec := f.Section(".data")
	if string(sec.Data) != string([]byte{1, 2, 5, 6}) {
		t.Errorf("interleaved = %v", sec.Data)
	}
	if sec.Size != 4 || sec.LMA == nil || *sec.LMA != 0 {
		t.Errorf("interleaved size/lma = %d %v", sec.Size, sec.LMA)
	}

	// A non-zero section address biases the start of the interleave.
	f = covELF(covData(".data", 1, []byte{1, 2, 3, 4, 5, 6, 7, 8}))
	c = Default()
	c.Interleave = 4
	c.Byte = 0
	c.InterleaveWidth = 1
	if err := c.applySectionContents(f); err != nil {
		t.Fatal(err)
	}
	if got := f.Section(".data"); got.Size != 2 {
		t.Errorf("biased interleave size = %d want 2", got.Size)
	}
	// NOBITS and empty sections are skipped.
	f = covELF(&elf.Section{SectionHeader: elf.SectionHeader{Name: ".bss", Type: elf.SHT_NOBITS, Size: 8}})
	if err := (&Config{ReverseBytes: 2}).applySectionContents(f); err != nil {
		t.Errorf("NOBITS reverse: %v", err)
	}
}

func TestPruneSegmentsKeepsProgramHeadersOfRelocatableFiles(t *testing.T) {
	f := covELF(covData(".text", 0, []byte{1}))
	if err := applyPruneSegments(f, Default()); err != nil {
		t.Fatal(err)
	}
	if len(f.Segments) != 0 {
		t.Errorf("segments = %d", len(f.Segments))
	}
}
