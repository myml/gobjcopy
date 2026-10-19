package objcopy

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/myml/gobjcopy/elf"
)

// isDebugSection mirrors BFD's SEC_DEBUGGING classification for ELF: only
// non-allocated sections whose names match the well known debug prefixes.
func isDebugSection(s *elf.Section) bool {
	if s.Flags&elf.SHF_ALLOC != 0 || s.Name == "" || s.Name[0] != '.' {
		return false
	}
	n := s.Name
	switch {
	case strings.HasPrefix(n, ".debug"),
		strings.HasPrefix(n, ".gnu.debuglto_.debug_"),
		strings.HasPrefix(n, ".gnu.linkonce.wi."),
		strings.HasPrefix(n, ".zdebug"),
		strings.HasPrefix(n, ".line"),
		strings.HasPrefix(n, ".stab"),
		n == ".gdb_index":
		return true
	}
	return false
}

func isDWOSection(s *elf.Section) bool {
	return strings.HasSuffix(s.Name, ".dwo")
}

// stripSection decides whether a section is dropped from the output.
func (c *Config) stripSection(s *elf.Section) bool {
	if c.StripSectionHeaders && s.Flags&elf.SHF_ALLOC == 0 {
		return true
	}
	if s.Name == ".shstrtab" {
		return false
	}
	if matchSectionList(c.KeepSections, s.Name) {
		return false
	}
	if c.ExtractDWO {
		return !isDWOSection(s)
	}
	if c.StripDWO && isDWOSection(s) {
		return true
	}
	if len(c.OnlySections) > 0 && !matchSectionList(c.OnlySections, s.Name) {
		// GNU keeps the symbol tables so the selected sections stay
		// interpretable.
		switch s.Type {
		case elf.SHT_SYMTAB, elf.SHT_SYMTAB_SHNDX:
			return false
		case elf.SHT_STRTAB:
			if s.Name == ".strtab" {
				return false
			}
		}
		return true
	}
	if matchSectionList(c.RemoveSections, s.Name) {
		return true
	}
	if c.StripSectionHeaders && s.Flags&elf.SHF_ALLOC == 0 {
		return true
	}
	if isDebugSection(s) {
		if s.Name == ".gnu_debuglink" || s.Name == ".gnu_debugaltlink" {
			return false
		}
		if c.StripAll || c.StripDebug || c.StripUnneeded || c.DiscardAll || c.ExtractDWO {
			return true
		}
	}
	return false
}

// matchSectionList reports whether name is selected by a GNU section list
// (from -j, -R, --keep-section, --set-section-flags, ...). GNU always uses
// fnmatch for section names (no -w needed), and a pattern beginning with '!'
// is a negative rule: if it matches, the section is not selected, whatever
// the other patterns say.
func matchSectionList(patterns []string, name string) bool {
	found := false
	for _, p := range patterns {
		if strings.HasPrefix(p, "!") {
			if fnmatch(p[1:], name) {
				return false
			}
			continue
		}
		if fnmatch(p, name) {
			found = true
		}
	}
	return found
}

// fnmatch is a small glob matcher supporting *, ? and [...] classes.
func fnmatch(pattern, name string) bool {
	// Iterative wildcard matching with backtracking.
	var starPat, starStr = -1, 0
	pi, si := 0, 0
	for si < len(name) {
		if pi < len(pattern) {
			switch pattern[pi] {
			case '*':
				starPat, starStr = pi, si
				pi++
				continue
			case '?':
				pi++
				si++
				continue
			case '[':
				if ok, np := matchClass(pattern, pi, name[si]); ok {
					pi = np
					si++
					continue
				}
			default:
				if pattern[pi] == name[si] {
					pi++
					si++
					continue
				}
			}
		}
		if starPat >= 0 {
			starStr++
			si = starStr
			pi = starPat + 1
			continue
		}
		return false
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// matchClass matches name[si] against a [...] class starting at pattern[pi].
// It returns whether it matched and the index just past the class.
func matchClass(pattern string, pi int, ch byte) (bool, int) {
	j := pi + 1
	negate := false
	if j < len(pattern) && (pattern[j] == '!' || pattern[j] == '^') {
		negate = true
		j++
	}
	matched := false
	first := true
	for j < len(pattern) && (pattern[j] != ']' || first) {
		first = false
		lo := pattern[j]
		if j+2 < len(pattern) && pattern[j+1] == '-' && pattern[j+2] != ']' {
			hi := pattern[j+2]
			if lo <= ch && ch <= hi {
				matched = true
			}
			j += 3
			continue
		}
		if lo == ch {
			matched = true
		}
		j++
	}
	if j >= len(pattern) {
		return false, pi
	}
	if negate {
		matched = !matched
	}
	return matched, j + 1
}

// applySectionStrip removes sections per -R/-j/strip options.
func applySectionStrip(f *elf.File, c *Config) error {
	if err := applyRenamesEarly(f, c); err != nil {
		return err
	}
	// GNU diagnoses a section selected by both -j and -R, and a section that
	// is both updated and removed, as fatal errors.
	for i := 1; i < len(f.Sections); i++ {
		name := f.Sections[i].Name
		if len(c.OnlySections) > 0 && matchSectionList(c.RemoveSections, name) &&
			matchSectionList(c.OnlySections, name) {
			return &FatalError{Msg: fmt.Sprintf("error: section %s matches both remove and copy options", name)}
		}
	}
	remove := map[int]bool{}
	for i := 1; i < len(f.Sections); i++ {
		if c.stripSection(f.Sections[i]) {
			remove[i] = true
		}
	}
	// Relocation sections of removed sections go away with them.
	for i, s := range f.Sections {
		if i == 0 {
			continue
		}
		if s.Type == elf.SHT_REL || s.Type == elf.SHT_RELA {
			if int(s.Info) < len(f.Sections) && remove[int(s.Info)] {
				remove[i] = true
			}
		}
	}
	// --strip-all discards static relocations (dynamic ones stay).
	if c.StripAll && len(c.KeepSymbols) == 0 && len(c.KeepGlobalSymbols) == 0 {
		symIdx := -1
		if s := f.SectionByType(elf.SHT_SYMTAB); s != nil {
			symIdx = f.SectionIndex(s)
		}
		for i, s := range f.Sections {
			if i == 0 {
				continue
			}
			if (s.Type == elf.SHT_REL || s.Type == elf.SHT_RELA) && int(s.Link) == symIdx {
				remove[i] = true
			}
		}
	}
	for _, us := range c.UpdateSections {
		sec := c.updateSectionTarget(f, us.Name)
		if sec == nil {
			continue
		}
		if idx := f.SectionIndex(sec); idx > 0 && remove[idx] {
			return &FatalError{Msg: fmt.Sprintf("error: section %s matches both update and remove options", sec.Name)}
		}
	}
	groups := c.groupFixups(f, remove)
	if err := removeSections(f, remove); err != nil {
		return err
	}
	if err := fixupGroups(f, groups); err != nil {
		return err
	}
	if c.StripSectionHeaders {
		f.NoSectionHeaders = true
	}
	// Reversing bytes and interleaving happen while sections are copied, i.e.
	// after -j/-R selected the kept sections but before --update-section
	// replaces contents and before --gap-fill/--pad-to extend them.
	return c.applySectionContents(f)
}

func removeSections(f *elf.File, remove map[int]bool) error {
	for i := len(f.Sections) - 1; i >= 1; i-- {
		if !remove[i] {
			continue
		}
		if err := f.RemoveSection(i); err != nil {
			return err
		}
	}
	return nil
}

// groupState records what is needed to repair an ELF COMDAT group section
// after other sections were removed.
type groupState struct {
	sec     *elf.Section
	sig     string   // group signature symbol name (from sh_info)
	members []uint32 // member section indices, as read before any removal
}

// groupFixups implements GNU's is_strip_section rule for SHT_GROUP sections:
// a group is dropped when its signature symbol is stripped or when every one
// of its members is stripped. Groups that survive keep their remaining
// members only.
func (c *Config) groupFixups(f *elf.File, remove map[int]bool) []groupState {
	var out []groupState
	for i, s := range f.Sections {
		if s.Type != elf.SHT_GROUP {
			continue
		}
		g := groupState{sec: s}
		g.sig, g.members = readGroup(f, s)
		strip := true
		for _, m := range g.members {
			if !remove[int(m)] {
				strip = false
				break
			}
		}
		if !strip && g.sig != "" {
			// PR binutils/3181: if the group signature symbol is going away,
			// the group cannot be emitted either.
			if c.StripAll && !c.matchSymbol(c.KeepSymbols, g.sig) ||
				c.matchSymbol(c.StripSymbols, g.sig) {
				strip = true
			}
			if sigShndx, ok := groupSigShndx(f, s); ok && int(sigShndx) < len(f.Sections) &&
				remove[int(sigShndx)] {
				strip = true
			}
		}
		if strip {
			remove[i] = true
			// The members survive without their group: drop SHF_GROUP so the
			// output does not reference a group that is no longer there.
			for _, m := range g.members {
				if int(m) < len(f.Sections) {
					f.Sections[m].Flags &^= elf.SHF_GROUP
				}
			}
			continue
		}
		out = append(out, g)
	}
	return out
}

// readGroup decodes a SHT_GROUP section into its signature symbol name and
// its member section indices.
func readGroup(f *elf.File, s *elf.Section) (sig string, members []uint32) {
	if int(s.Link) < len(f.Sections) && f.Sections[s.Link].Type == elf.SHT_SYMTAB {
		if st, err := f.ReadSymtab(f.Sections[s.Link]); err == nil {
			if int(s.Info) > 0 && int(s.Info) < len(st.Entries) {
				sig = st.Entries[s.Info].Name
			}
		}
	}
	order := f.Data.Order()
	for off := 4; off+4 <= len(s.Data); off += 4 {
		members = append(members, order.Uint32(s.Data[off:]))
	}
	return sig, members
}

// groupSigShndx returns the section index the group signature symbol lives in.
func groupSigShndx(f *elf.File, s *elf.Section) (uint16, bool) {
	if int(s.Link) >= len(f.Sections) || f.Sections[s.Link].Type != elf.SHT_SYMTAB {
		return 0, false
	}
	st, err := f.ReadSymtab(f.Sections[s.Link])
	if err != nil || int(s.Info) == 0 || int(s.Info) >= len(st.Entries) {
		return 0, false
	}
	return st.Entries[s.Info].Shndx, true
}

// fixupGroups drops the member entries of removed sections from the surviving
// group sections and re-points their sh_info at the signature symbol, whose
// index may have shifted when symbols were dropped together with sections.
func fixupGroups(f *elf.File, groups []groupState) error {
	for _, g := range groups {
		if f.SectionIndex(g.sec) < 0 {
			continue
		}
		if len(g.sec.Data) >= 4 {
			order := f.Data.Order()
			data := append([]byte(nil), g.sec.Data[:4]...)
			for off := 4; off+4 <= len(g.sec.Data); off += 4 {
				if v := order.Uint32(g.sec.Data[off:]); v != 0 {
					var word [4]byte
					order.PutUint32(word[:], v)
					data = append(data, word[:]...)
				}
			}
			g.sec.Data = data
			g.sec.Size = uint64(len(data))
		}
		if g.sig == "" {
			continue
		}
		symIdx := int(g.sec.Link)
		if symIdx <= 0 || symIdx >= len(f.Sections) || f.Sections[symIdx].Type != elf.SHT_SYMTAB {
			continue
		}
		st, err := f.ReadSymtab(f.Sections[symIdx])
		if err != nil {
			continue
		}
		for i := 1; i < len(st.Entries); i++ {
			if st.Entries[i].Name == g.sig {
				g.sec.Info = uint32(i)
				break
			}
		}
	}
	return nil
}

// updateSectionTarget resolves the section named by an --update-section
// request. GNU matches update requests against input section names before
// --rename-section is applied; renames happen early here, so fall back to the
// rename's new name.
func (c *Config) updateSectionTarget(f *elf.File, name string) *elf.Section {
	if sec := f.Section(name); sec != nil {
		return sec
	}
	for _, r := range c.Renames {
		if r.Old == name {
			return f.Section(r.New)
		}
	}
	return nil
}

// applyRenamesEarly applies --rename-section before section selection, since
// -R/-j may refer to the new names (GNU renames while copying, but the
// observable result is the same).
func applyRenamesEarly(f *elf.File, c *Config) error {
	renamed := map[*elf.Section]bool{}
	for _, r := range c.Renames {
		sec := f.Section(r.Old)
		if sec == nil {
			continue
		}
		sec.Name = r.New
		renamed[sec] = true
	}
	// BFD emits a relocation section under "<.rela|.rel><target output name>",
	// so renaming .text to .mytext also renames .rela.text to .rela.mytext.
	for _, s := range f.Sections {
		if s.Type != elf.SHT_REL && s.Type != elf.SHT_RELA {
			continue
		}
		if int(s.Info) <= 0 || int(s.Info) >= len(f.Sections) {
			continue
		}
		target := f.Sections[s.Info]
		if !renamed[target] {
			continue
		}
		if s.Type == elf.SHT_RELA {
			s.Name = ".rela" + target.Name
		} else {
			s.Name = ".rel" + target.Name
		}
	}
	return nil
}

// applySectionRenames warns about rename targets that never matched.
func applySectionRenames(f *elf.File, c *Config) error {
	for _, r := range c.Renames {
		sec := f.Section(r.New)
		if sec == nil {
			c.warnf("unable to rename section %s: no such section", r.Old)
			continue
		}
		if r.Flags != nil {
			if err := setSectionFlags(f, sec, *r.Flags); err != nil {
				return err
			}
		}
	}
	return nil
}

func setSectionFlags(f *elf.File, sec *elf.Section, spec string) error {
	flags, hasContents, err := ParseSectionFlags(spec)
	if err != nil {
		return err
	}
	if hasContents && sec.IsNoBits() {
		sec.Type = elf.SHT_PROGBITS
		sec.Data = make([]byte, sec.Size)
	}
	sec.Flags = flags
	return nil
}

// isBookkeepingSection reports whether the section is one of the tables BFD
// creates itself rather than copying from the input. --prefix-sections and
// --extract-symbol leave those alone (.symtab/.strtab/.shstrtab stay intact),
// while copied tables such as .dynsym/.dynstr/.gnu.hash are prefixed and
// cleared like any other input section.
func isBookkeepingSection(f *elf.File, idx int, s *elf.Section) bool {
	switch s.Type {
	case elf.SHT_SYMTAB, elf.SHT_SYMTAB_SHNDX:
		return true
	case elf.SHT_STRTAB:
		if idx == f.Shstrndx || s.Name == ".shstrtab" || s.Name == ".strtab" {
			return true
		}
	}
	if st := f.SectionByType(elf.SHT_SYMTAB); st != nil && int(st.Link) == idx {
		return true
	}
	return false
}

// applySectionPrefixes implements --prefix-sections and
// --prefix-alloc-sections. GNU applies the prefix in setup_section after
// --rename-section and after every option that matches input section names,
// and relocation section names are rebuilt from the (prefixed) target name,
// which is why ".rela.text" becomes ".relafoo_.text" rather than
// "foo_.rela.text".
func applySectionPrefixes(f *elf.File, c *Config) error {
	if c.PrefixSections == "" && c.PrefixAllocSections == "" {
		return nil
	}
	prefixed := map[*elf.Section]bool{}
	for i, s := range f.Sections {
		if i == 0 || c.isSynthetic(s) || isBookkeepingSection(f, i, s) {
			continue
		}
		prefix := c.PrefixSections
		if c.PrefixAllocSections != "" && c.wasAlloc(s) {
			prefix = c.PrefixAllocSections
		}
		if prefix == "" {
			continue
		}
		s.Name = prefix + s.Name
		prefixed[s] = true
	}
	// BFD rebuilds a relocation section's name from its target's output name:
	// ".rela.text" whose .text became "foo_.text" is emitted as
	// ".relafoo_.text", with no extra dot, for both SHT_REL and SHT_RELA.
	for _, s := range f.Sections {
		if s.Type != elf.SHT_REL && s.Type != elf.SHT_RELA {
			continue
		}
		if int(s.Info) <= 0 || int(s.Info) >= len(f.Sections) {
			continue
		}
		target := f.Sections[s.Info]
		if !prefixed[target] {
			continue
		}
		if s.Type == elf.SHT_RELA {
			s.Name = ".rela" + target.Name
		} else {
			s.Name = ".rel" + target.Name
		}
	}
	return nil
}

// applyExtractSymbol implements --extract-symbol: every copied section loses
// its contents and size while its type, flags and address survive, and the
// entry point becomes zero. The symbol table is kept untouched (GNU only runs
// filter_symbols when another symbol option asks for it), so all shndx
// references stay valid. Sections objcopy created itself (--add-section,
// --add-gnu-debuglink) and the ELF bookkeeping tables are not touched.
func applyExtractSymbol(f *elf.File, c *Config) error {
	if !c.ExtractSymbol {
		return nil
	}
	f.Entry = 0
	for i, s := range f.Sections {
		if i == 0 || c.isSynthetic(s) || isBookkeepingSection(f, i, s) {
			continue
		}
		s.Data = nil
		s.Size = 0
	}
	return nil
}

// applyAltMachineCode implements --alt-machine-code. ELF BFD targets have no
// alternative machine table, so GNU warns twice and writes the number as the
// absolute e_machine value.
func applyAltMachineCode(f *elf.File, c *Config) error {
	if c.AltMachineCode == 0 {
		return nil
	}
	c.warnf("this target does not support %d alternative machine codes", c.AltMachineCode)
	c.warnf("treating that number as an absolute e_machine value instead")
	f.Machine = uint16(c.AltMachineCode)
	return nil
}
func applySectionFlags(f *elf.File, c *Config) error {
	for _, sf := range c.SetSectionFlags {
		found := false
		for _, sec := range f.Sections {
			if !matchSectionList([]string{sf.Name}, sec.Name) {
				continue
			}
			found = true
			if err := setSectionFlags(f, sec, sf.Flags); err != nil {
				return err
			}
		}
		if !found {
			c.warnf("unable to find section %s", sf.Name)
		}
	}
	return nil
}

func applySectionAlignment(f *elf.File, c *Config) error {
	for _, sa := range append(append([]SectionAlign{}, c.SetSectionAlignment...), c.SetSectionAlignments...) {
		found := false
		for _, sec := range f.Sections {
			if !matchSectionList([]string{sa.Name}, sec.Name) {
				continue
			}
			found = true
			if sa.Align == 0 || sa.Align&(sa.Align-1) != 0 {
				return fmt.Errorf("invalid alignment %d for section %s", sa.Align, sa.Name)
			}
			sec.Addralign = sa.Align
		}
		if !found {
			c.warnf("unable to find section %s", sa.Name)
		}
	}
	return nil
}

func applyOnlyKeepDebug(f *elf.File, c *Config) error {
	if !c.OnlyKeepDebug {
		return nil
	}
	for _, s := range f.Sections {
		switch {
		case s.Type == elf.SHT_NULL, s.Type == elf.SHT_NOBITS, s.Type == elf.SHT_NOTE:
			continue
		case s.Flags&elf.SHF_GROUP != 0:
			continue
		case isDebugSection(s):
			continue
		case s.Flags&elf.SHF_ALLOC == 0:
			continue
		}
		s.Type = elf.SHT_NOBITS
		s.Data = nil
		s.Flags &^= elf.SHF_INFO_LINK
	}
	return nil
}

func applyAddUpdateSections(f *elf.File, c *Config) error {
	for _, as := range c.AddSections {
		data, err := os.ReadFile(as.File)
		if err != nil {
			return fmt.Errorf("%s: %w", as.File, err)
		}
		sec := &elf.Section{
			SectionHeader: elf.SectionHeader{
				Name:      as.Name,
				Type:      elf.SHT_PROGBITS,
				Addralign: 1,
			},
			Data: data,
		}
		if typ, ok := NoteSectionType(as.Name); ok {
			// BFD's special-section table types .note* sections as SHT_NOTE.
			sec.Type = typ
		}
		sec.Size = uint64(len(data))
		if err := f.AddSection(sec); err != nil {
			return err
		}
		c.markSynthetic(sec)
		if c.Verbose {
			c.infof("added section %s", as.Name)
		}
	}
	for _, us := range c.UpdateSections {
		sec := c.updateSectionTarget(f, us.Name)
		if sec == nil {
			return &FatalError{Msg: fmt.Sprintf("error: %s not found, can't be updated", us.Name)}
		}
		data, err := os.ReadFile(us.File)
		if err != nil {
			return fmt.Errorf("%s: %w", us.File, err)
		}
		sec.Data = data
		sec.Size = uint64(len(data))
		if sec.Type == elf.SHT_NOBITS {
			sec.Type = elf.SHT_PROGBITS
		}
	}
	for _, ds := range c.DumpSections {
		sec := f.Section(ds.Name)
		if sec == nil {
			c.warnf("can't dump section '%s' - it does not exist", ds.Name)
			continue
		}
		if sec.IsNoBits() {
			c.warnf("can't dump section - it has no contents")
			continue
		}
		if err := os.WriteFile(ds.File, sec.Data, 0o666); err != nil {
			return err
		}
	}
	return nil
}

func applyRemoveRelocations(f *elf.File, c *Config) error {
	if len(c.RemoveRelocations) == 0 {
		return nil
	}
	remove := map[int]bool{}
	for i, s := range f.Sections {
		if i == 0 || (s.Type != elf.SHT_REL && s.Type != elf.SHT_RELA) {
			continue
		}
		target := ""
		if int(s.Info) < len(f.Sections) {
			target = f.Sections[s.Info].Name
		}
		if target == "" {
			// Derive the target name from the section name.
			target = strings.TrimPrefix(strings.TrimPrefix(s.Name, ".rela"), ".rel")
		}
		if matchSectionList(c.RemoveRelocations, target) ||
			matchSectionList(c.RemoveRelocations, s.Name) {
			remove[i] = true
		}
	}
	return removeSections(f, remove)
}

func addDelta(v uint64, d int64) uint64 {
	if d >= 0 {
		return v + uint64(d)
	}
	return v - uint64(-d)
}

// sectionAlignForVMA reproduces the sh_addralign BFD writes for an output
// section with VMA addr and pre-change alignment align.  bfd/elf.c computes
// it while emitting the section header as the lowest set bit of
// (1 << alignment_power) | sh_addr, i.e. the largest power of two that divides
// the new VMA but never exceeds the original alignment.  A zero VMA keeps the
// original alignment, and a zero alignment behaves like one byte.
func sectionAlignForVMA(align, addr uint64) uint64 {
	pow := align & -align // BFD stores only the lowest set bit as the exponent
	if pow == 0 {
		pow = 1
	}
	mask := addr | pow
	return mask & -mask
}

func applyAddressChanges(f *elf.File, c *Config) error {
	deltas := map[*elf.Section]int64{}
	// The alignment BFD uses for the reduction is the one the section had
	// before any address option ran; watching the mutated Addralign would let
	// repeated --change-section-* options compound the reduction.  Only
	// sections whose VMA was actually set by an option are candidates.
	baseAlign := map[*elf.Section]uint64{}
	movedVMA := map[*elf.Section]bool{}
	noteVMAChange := func(sec *elf.Section) {
		if _, ok := baseAlign[sec]; !ok {
			baseAlign[sec] = sec.Addralign
		}
		movedVMA[sec] = true
	}
	shift := func(sec *elf.Section, d int64) {
		if d == 0 {
			return
		}
		old := sec.Addr
		noteVMAChange(sec)
		sec.Addr = addDelta(sec.Addr, d)
		deltas[sec] += int64(sec.Addr) - int64(old)
	}
	if c.SetStart != nil {
		f.Entry = *c.SetStart
	}
	if c.ChangeStart != nil {
		f.Entry = addDelta(f.Entry, *c.ChangeStart)
	}
	if c.ChangeAddresses != nil {
		d := *c.ChangeAddresses
		f.Entry = addDelta(f.Entry, d)
		for i, s := range f.Sections {
			if i == 0 {
				continue
			}
			if s.Type == elf.SHT_SYMTAB || s.Type == elf.SHT_SYMTAB_SHNDX {
				// BFD always writes address zero for symbol tables.
				continue
			}
			if s.Type == elf.SHT_STRTAB && s.Flags&elf.SHF_ALLOC == 0 {
				continue
			}
			if (s.Type == elf.SHT_REL || s.Type == elf.SHT_RELA) && s.Flags&elf.SHF_ALLOC == 0 {
				continue
			}
			shift(s, d)
		}
		for _, ph := range f.Segments {
			ph.Vaddr = addDelta(ph.Vaddr, d)
			ph.Paddr = addDelta(ph.Paddr, d)
		}
	}
	apply := func(list []SectionAddr, vma, lma bool) error {
		for _, ch := range list {
			found := false
			for _, s := range f.Sections {
				if !fnmatch(ch.Name, s.Name) {
					continue
				}
				found = true
				// The LMA base must be captured before the VMA is changed,
				// otherwise a relative adjustment would be applied twice.
				curLMA := s.Addr
				if s.LMA != nil {
					curLMA = *s.LMA
				}
				if vma {
					noteVMAChange(s)
					var nv uint64
					switch ch.Op {
					case AddrSet:
						nv = ch.Val
					case AddrAdd:
						nv = s.Addr + ch.Val
					case AddrSub:
						nv = s.Addr - ch.Val
					}
					deltas[s] += int64(nv) - int64(s.Addr)
					s.Addr = nv
				}
				if lma {
					var nv uint64
					switch ch.Op {
					case AddrSet:
						nv = ch.Val
					case AddrAdd:
						nv = curLMA + ch.Val
					case AddrSub:
						nv = curLMA - ch.Val
					}
					s.LMA = &nv
				}
			}
			if !found {
				c.warnf("unable to find section %s", ch.Name)
			}
		}
		return nil
	}
	if err := apply(c.ChangeSectionAddr, true, true); err != nil {
		return err
	}
	if err := apply(c.ChangeSectionVMA, true, false); err != nil {
		return err
	}
	if err := apply(c.ChangeSectionLMA, false, true); err != nil {
		return err
	}
	// GNU lowers sh_addralign on the sections whose VMA these options moved:
	// the alignment must divide the new address, otherwise consuming tools may
	// reject the output.  LMA-only changes leave the alignment alone because
	// BFD computes it from sh_addr.
	for sec := range movedVMA {
		if f.SectionIndex(sec) <= 0 {
			continue
		}
		sec.Addralign = sectionAlignForVMA(baseAlign[sec], sec.Addr)
	}
	if f.Type != elf.ET_REL {
		adjustSymbolValues(f, deltas)
	}
	return nil
}

// adjustSymbolValues shifts defined symbol values along with their section.
func adjustSymbolValues(f *elf.File, deltas map[*elf.Section]int64) {
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_SYMTAB && sec.Type != elf.SHT_DYNSYM {
			continue
		}
		st, err := f.ReadSymtab(sec)
		if err != nil {
			continue
		}
		changed := false
		for i := range st.Entries {
			sh := st.Entries[i].Shndx
			if sh == elf.SHN_ABS || sh >= elf.SHN_LORESERVE || int(sh) >= len(f.Sections) {
				continue
			}
			if d := deltas[f.Sections[sh]]; d != 0 {
				st.Entries[i].Value = addDelta(st.Entries[i].Value, d)
				changed = true
			}
		}
		if changed {
			_ = f.SetSymtab(st)
		}
	}
}

// applyPruneSegments drops program headers whose backing sections were removed
// or converted to NOBITS, so the output never carries stale offsets.
func applyPruneSegments(f *elf.File, c *Config) error {
	hasNamed := func(name string) bool {
		return f.Section(name) != nil
	}
	hasType := func(t uint32) bool {
		for _, s := range f.Sections {
			if s.Type == t {
				return true
			}
		}
		return false
	}
	hasFlags := func(fl uint64) bool {
		for _, s := range f.Sections {
			if s.Flags&fl != 0 {
				return true
			}
		}
		return false
	}
	out := f.Segments[:0]
	for _, ph := range f.Segments {
		keep := true
		switch ph.Type {
		case elf.PT_LOAD:
			if ph.Offset != 0 {
				keep = false
				for _, s := range f.Sections {
					if s.IsAlloc() && s.Addr >= ph.Vaddr && s.Addr < ph.Vaddr+ph.Memsz {
						keep = true
						break
					}
				}
			}
		case elf.PT_INTERP:
			keep = hasNamed(".interp")
		case elf.PT_DYNAMIC:
			keep = hasType(elf.SHT_DYNAMIC)
		case elf.PT_TLS:
			keep = hasFlags(elf.SHF_TLS)
		case elf.PT_GNU_EH_FRAME:
			keep = hasNamed(".eh_frame_hdr")
		case elf.PT_GNU_PROPERTY:
			keep = hasNamed(".note.gnu.property")
		case elf.PT_NOTE:
			keep = false
			for _, s := range f.Sections {
				if s.Type == elf.SHT_NOTE && s.Addr >= ph.Vaddr && s.Addr < ph.Vaddr+ph.Memsz {
					keep = true
					break
				}
			}
		}
		if keep {
			out = append(out, ph)
		}
	}
	f.Segments = out
	return nil
}

// applyGapFill implements --gap-fill for ELF output: BFD pads each loadable
// section with contents up to the next section's load address.
func applyGapFill(f *elf.File, c *Config) error {
	if c.GapFill == nil {
		return nil
	}
	fill := byte(*c.GapFill)
	type ent struct {
		sec *elf.Section
		lma uint64
	}
	var list []ent
	for _, s := range f.Sections {
		if !s.IsAlloc() || s.IsNoBits() || len(s.Data) == 0 {
			continue
		}
		list = append(list, ent{sec: s, lma: sectionLMA(f, s)})
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].lma < list[j].lma })
	for i := 0; i+1 < len(list); i++ {
		cur := list[i].sec
		start := list[i].lma + uint64(len(cur.Data))
		stop := list[i+1].lma
		if start >= stop {
			continue
		}
		pad := int(stop - start)
		if pad <= 0 {
			continue
		}
		cur.Data = append(cur.Data, bytes.Repeat([]byte{fill}, pad)...)
		cur.Size = uint64(len(cur.Data))
	}
	return nil
}

// applyPadTo implements --pad-to for ELF output: the last allocated section
// with contents is extended up to the requested address.
func applyPadTo(f *elf.File, c *Config) error {
	if c.PadTo == nil {
		return nil
	}
	var last *elf.Section
	var lastLMA uint64
	for _, s := range f.Sections {
		if !s.IsAlloc() || s.IsNoBits() || len(s.Data) == 0 {
			continue
		}
		l := sectionLMA(f, s)
		if last == nil || l >= lastLMA {
			last, lastLMA = s, l
		}
	}
	if last == nil {
		return nil
	}
	end := lastLMA + uint64(len(last.Data))
	if *c.PadTo <= end {
		return nil
	}
	pad := int(*c.PadTo - end)
	fill := byte(0)
	if c.GapFill != nil {
		fill = byte(*c.GapFill)
	}
	if fill == 0 {
		last.Data = append(last.Data, make([]byte, pad)...)
	} else {
		last.Data = append(last.Data, bytes.Repeat([]byte{fill}, pad)...)
	}
	last.Size = uint64(len(last.Data))
	return nil
}
