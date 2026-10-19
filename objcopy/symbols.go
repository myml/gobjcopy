package objcopy

import (
	"fmt"
	"strings"

	"github.com/myml/gobjcopy/elf"
)

// FatalError is an error that mirrors a GNU objcopy fatal diagnostic: the
// output file is not written and the exit status is 1.
type FatalError struct{ Msg string }

func (e *FatalError) Error() string { return e.Msg }

func isLocalLabel(name string) bool {
	// BFD's _bfd_elf_is_local_label_name: leading ".L" or "L" followed by a
	// digit or'.'.
	if len(name) >= 2 && name[0] == '.' && name[1] == 'L' {
		return true
	}
	if len(name) >= 2 && name[0] == 'L' && (name[1] >= '0' && name[1] <= '9' || name[1] == '.') {
		return true
	}
	return false
}

func (c *Config) symMatch(pattern, name string) bool {
	if c.Wildcard {
		return fnmatch(pattern, name)
	}
	return pattern == name
}

// matchSymbol reports whether name is selected by a GNU symbol list (-N, -K,
// -L, -W, -G, ...). Wildcards are only active with -w; then a pattern
// beginning with '!' is a negative rule that wins over every positive match,
// exactly like GNU's is_specified_symbol.
func (c *Config) matchSymbol(pats []string, name string) bool {
	if !c.Wildcard {
		for _, p := range pats {
			if p == name {
				return true
			}
		}
		return false
	}
	found := false
	for _, p := range pats {
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

// keepUnusedSectionSymbols mirrors the per-target
// keep_unused_section_symbols flag from BFD's target vector. It is true by
// default (bfd/targets.c: TARGET_KEEP_UNUSED_SECTION_SYMBOLS defaults to
// true) and only the x86 backends override it with false
// (bfd/elfxx-x86.h: #define TARGET_KEEP_UNUSED_SECTION_SYMBOLS false).
//
// GNU objcopy uses the flag for non-relocatable outputs: when it is true all
// section symbols are regenerated, otherwise they are all dropped unless
// --keep-section-symbols was given (binutils/objcopy.c, the mark/clear loop
// before filter_symbols).
func keepUnusedSectionSymbols(machine uint16) bool {
	switch machine {
	case elf.EM_386, elf.EM_IAMCU, elf.EM_X86_64:
		return false
	}
	return true
}

// isMappingSymbol reports whether name is an AArch64 or ARM mapping symbol.
// BFD's elf_backend_symbol_processing marks those BSF_KEEP for relocatable
// inputs so that --strip-unneeded keeps them (bfd/elfnn-aarch64.c and
// bfd/elf32-arm.c).
func isMappingSymbol(machine uint16, name string) bool {
	if len(name) < 2 || name[0] != '$' || (len(name) > 2 && name[2] != '.') {
		return false
	}
	switch machine {
	case elf.EM_AARCH64:
		return name[1] == 'd' || name[1] == 'x'
	case elf.EM_ARM:
		return name[1] == 'a' || name[1] == 'd' || name[1] == 't' || name[1] == 'x'
	}
	return false
}

// symbolName returns the name GNU objcopy filters on. BFD names an unnamed
// STT_SECTION symbol after its section (bfd/elf.c: bfd_elf_sym_name_raw), so
// -N/-K/--strip-unneeded-symbol accept section names for section symbols.
func symbolName(f *elf.File, sym *elf.Symbol) string {
	if sym.Name == "" && sym.Type() == elf.STT_SECTION && int(sym.Shndx) > 0 && int(sym.Shndx) < len(f.Sections) {
		return f.Sections[sym.Shndx].Name
	}
	return sym.Name
}

// sectionCopied reports whether idx names a real output section that -j
// selected. GNU applies is_strip_section to a symbol's section: with -j the
// undefined, absolute and common pseudo sections are never on the copy list,
// so those symbols disappear, as do symbols of any section that was not
// copied.
func sectionCopied(f *elf.File, symSec *elf.Section, idx int) bool {
	if idx <= 0 || idx >= len(f.Sections) || idx == f.Shstrndx || idx == f.SectionIndex(symSec) {
		return false
	}
	if int(symSec.Link) == idx {
		return false
	}
	switch f.Sections[idx].Type {
	case elf.SHT_SYMTAB, elf.SHT_SYMTAB_SHNDX:
		return false
	}
	return true
}

// sectionSymbolTarget reports whether BFD would generate a section symbol for
// section idx. The static symbol table, its string table and the
// section-name string table are ELF bookkeeping sections that BFD does not
// expose as output sections, so no symbol is ever generated for them.
func sectionSymbolTarget(f *elf.File, symSec *elf.Section, idx int) bool {
	if idx <= 0 || idx >= len(f.Sections) || idx == f.Shstrndx || idx == f.SectionIndex(symSec) {
		return false
	}
	if int(symSec.Link) == idx {
		return false
	}
	s := f.Sections[idx]
	if s.Type == elf.SHT_SYMTAB || s.Type == elf.SHT_SYMTAB_SHNDX {
		return false
	}
	return true
}

// applySymbols implements GNU objcopy's symbol filtering, localization and
// rewrite rules for the static symbol table. The dynamic symbol table is left
// untouched, matching GNU.
func applySymbols(f *elf.File, c *Config) error {
	symSec := f.SectionByType(elf.SHT_SYMTAB)
	if symSec == nil {
		return nil
	}
	st, err := f.ReadSymtab(symSec)
	if err != nil {
		return err
	}
	symIdx := f.SectionIndex(symSec)
	entries := st.Entries

	if c.ELFSTTCommon != "" {
		for i := 1; i < len(entries); i++ {
			if entries[i].Shndx != elf.SHN_COMMON {
				continue
			}
			switch {
			case c.ELFSTTCommon == "yes" && entries[i].Type() == elf.STT_OBJECT:
				entries[i].SetType(elf.STT_COMMON)
			case c.ELFSTTCommon == "no" && entries[i].Type() == elf.STT_COMMON:
				entries[i].SetType(elf.STT_OBJECT)
			}
		}
	}

	// --add-symbol: append the new symbols before filtering so that they take
	// part in the usual local-before-global ordering.
	for _, as := range c.AddSymbols {
		sym := elf.Symbol{Name: as.Name, Value: as.Value, Info: as.Type | as.Bind<<4}
		if as.Section == "" {
			sym.Shndx = elf.SHN_ABS
		} else {
			sec := f.Section(as.Section)
			if sec == nil {
				return &FatalError{Msg: fmt.Sprintf("can't find section `%s' for symbol `%s'", as.Section, as.Name)}
			}
			sym.Shndx = uint16(f.SectionIndex(sec))
		}
		entries = append(entries, sym)
	}

	used := make(map[int]bool)
	for _, s := range f.Sections {
		if s.Type != elf.SHT_REL && s.Type != elf.SHT_RELA {
			continue
		}
		if int(s.Link) != symIdx {
			continue
		}
		relocs, err := f.ReadRelocs(s)
		if err != nil {
			return err
		}
		for _, r := range relocs {
			used[int(r.Sym)] = true
		}
	}

	relocatable := f.Type == elf.ET_REL

	// BFD also sets BSF_KEEP for a few target-specific symbols while reading
	// the input symbol table. AArch64 and ARM mapping symbols are the only
	// ones that matter for objcopy: they tell the linker where code and data
	// start, so --strip-unneeded must keep them.
	keepByTarget := make([]bool, len(entries))
	if relocatable {
		for i := 1; i < len(entries); i++ {
			if entries[i].Shndx != elf.SHN_ABS && isMappingSymbol(f.Machine, entries[i].Name) {
				keepByTarget[i] = true
			}
		}
	}

	// BFD exposes an unnamed section symbol under its section name, so name
	// based options (-N, -K, -w, ...) match section symbols by section name.
	names := make([]string, len(entries))
	for i := 1; i < len(entries); i++ {
		names[i] = symbolName(f, &entries[i])
	}

	// Symbol redefinition happens before any name based filtering.
	if len(c.Redefines) > 0 {
		redef := func(name string) string {
			for _, r := range c.Redefines {
				if c.symMatch(r.Old, name) {
					return r.New
				}
			}
			return name
		}
		for i := 1; i < len(entries); i++ {
			renamed := redef(names[i])
			names[i] = renamed
			// BFD writes local section symbols without a name, so the new
			// name only matters for the name based filters below.
			if entries[i].Type() != elf.STT_SECTION {
				entries[i].Name = renamed
			}
		}
	}

	// Section symbols need BFD's special treatment. They carry
	// BSF_SECTION_SYM|BSF_DEBUGGING, so filter_symbols only keeps them when a
	// surviving relocation names them (BSF_KEEP) or when no debug stripping
	// was requested. For non-relocatable outputs they are not copied from the
	// input at all: BFD regenerates one per output section, but only when the
	// target keeps unused section symbols or --keep-section-symbols was used.
	generateSectionSyms := !relocatable && (keepUnusedSectionSymbols(f.Machine) || c.KeepSectionSymbols)

	keep := make([]bool, len(entries)) // BFD's filter_symbols decision
	for i := 1; i < len(entries); i++ {
		sym := &entries[i]
		name := names[i]
		u := used[i] || keepByTarget[i]
		usedInReloc := u
		var k bool
		switch {
		case c.StripAll:
			k = false
		case sym.Type() == elf.STT_SECTION:
			k = u || (!c.StripDebug && !c.StripUnneeded)
		case u:
			k = true
		case relocatable && (sym.Bind() == elf.STB_GLOBAL || sym.Bind() == elf.STB_WEAK):
			k = true
		case sym.Shndx == elf.SHN_COMMON:
			k = true
		case sym.Type() == elf.STT_GNU_IFUNC:
			k = true
		case sym.Bind() == elf.STB_GLOBAL || sym.Bind() == elf.STB_WEAK ||
			sym.Shndx == elf.SHN_UNDEF || sym.Shndx == elf.SHN_COMMON:
			k = !c.StripUnneeded
		case sym.Type() == elf.STT_FILE:
			k = !c.StripDebug && !c.StripUnneeded
		case c.DiscardAll:
			k = false
		case c.DiscardLocals:
			k = !isLocalLabel(name)
		default:
			k = !c.StripUnneeded
		}
		if k && c.matchSymbol(c.StripSymbols, name) {
			if usedInReloc {
				return &FatalError{Msg: fmt.Sprintf("not stripping symbol `%s' because it is named in a relocation", name)}
			}
			k = false
		}
		if k && c.matchSymbol(c.StripUnneededSymbols, name) && !usedInReloc {
			k = false
		}
		if !k {
			if c.KeepFileSymbols && sym.Type() == elf.STT_FILE {
				k = true
			}
			if c.matchSymbol(c.KeepSymbols, name) {
				k = true
			}
		}
		if k && len(c.OnlySections) > 0 && !sectionCopied(f, symSec, int(sym.Shndx)) {
			// GNU's is_strip_section(sym->section) runs after -K, so with -j
			// even a kept symbol outside the copied sections is dropped.
			k = false
		}
		undefined := sym.Shndx == elf.SHN_UNDEF
		if k && !undefined && (sym.Bind() == elf.STB_GLOBAL || sym.Bind() == elf.STB_WEAK) {
			if c.LocalizeHidden && isHiddenSymbol(sym) {
				sym.SetBind(elf.STB_LOCAL)
			}
			if c.matchSymbol(c.LocalizeSymbols, name) {
				sym.SetBind(elf.STB_LOCAL)
			}
		}
		if k && !undefined && sym.Bind() == elf.STB_LOCAL && sym.Type() != elf.STT_FILE {
			if c.matchSymbol(c.GlobalizeSymbols, name) {
				sym.SetBind(elf.STB_GLOBAL)
			}
		}
		if k && ((sym.Bind() == elf.STB_GLOBAL || sym.Bind() == elf.STB_GNU_UNIQUE) || undefined) {
			if c.WeakenAll || c.matchSymbol(c.WeakenSymbols, name) {
				sym.SetBind(elf.STB_WEAK)
			}
		}
		keep[i] = k
	}

	// BFD drops the input section symbols of a non-relocatable output when
	// neither the target nor --keep-section-symbols asks for them, even when
	// filter_symbols itself kept them. They are still counted by
	// filter_symbols when deciding whether a symbol table is written, which
	// is why the existence test below uses filterKeep rather than emitKeep.
	filterCount := 0
	emit := make([]bool, len(entries))
	for i := 1; i < len(entries); i++ {
		if keep[i] {
			filterCount++
		}
		emit[i] = keep[i]
		if keep[i] && entries[i].Type() == elf.STT_SECTION && !relocatable && !generateSectionSyms {
			emit[i] = false
		}
	}

	// -G localizes every global not named on the command line.
	if len(c.KeepGlobalSymbols) > 0 {
		for i := 1; i < len(entries); i++ {
			if !emit[i] {
				continue
			}
			sym := &entries[i]
			if sym.Bind() == elf.STB_LOCAL || sym.Shndx == elf.SHN_UNDEF {
				continue
			}
			if !c.matchSymbol(c.KeepGlobalSymbols, sym.Name) {
				sym.SetBind(elf.STB_LOCAL)
			}
		}
	}

	// A relocatable output keeps its symbol table even when nothing survived
	// the filter, as long as it still has relocations: BFD recomputes
	// HAS_RELOC from the output sections (bfd/elf.c: assign_section_numbers).
	// --strip-all clears HAS_RELOC in objcopy itself. Non-relocatable outputs
	// always need at least one filtered symbol for the table to be written.
	hasRelocs := false
	for _, s := range f.Sections {
		if (s.Type == elf.SHT_REL || s.Type == elf.SHT_RELA) && s.Size > 0 {
			hasRelocs = true
			break
		}
	}
	needSymtab := filterCount > 0 || (relocatable && !c.StripAll && hasRelocs)

	if !needSymtab {
		// No symbols left: GNU drops the symbol table and its string table.
		var strtabSec *elf.Section
		if int(symSec.Link) < len(f.Sections) {
			strtabSec = f.Sections[symSec.Link]
		}
		var shndx *elf.Section
		for _, s := range f.Sections {
			if s.Type == elf.SHT_SYMTAB_SHNDX && int(s.Link) == symIdx {
				shndx = s
			}
		}
		// Relocations that referenced the now vanished table are dropped.
		var relocSecs []*elf.Section
		for _, rs := range f.Sections {
			if (rs.Type == elf.SHT_REL || rs.Type == elf.SHT_RELA) && int(rs.Link) == symIdx {
				relocSecs = append(relocSecs, rs)
			}
		}
		for _, rs := range relocSecs {
			if idx := f.SectionIndex(rs); idx > 0 {
				if err := f.RemoveSection(idx); err != nil {
					return err
				}
			}
		}
		// The removals above shift indices: look the table up again.
		symIdx = f.SectionIndex(symSec)
		if err := f.RemoveSection(symIdx); err != nil {
			return err
		}
		if strtabSec != nil {
			if idx := f.SectionIndex(strtabSec); idx > 0 {
				if err := f.RemoveSection(idx); err != nil {
					return err
				}
			}
		}
		if shndx != nil {
			if idx := f.SectionIndex(shndx); idx > 0 {
				if err := f.RemoveSection(idx); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// Collect the survivors, keeping the null symbol first.
	out := make([]elf.Symbol, 0, len(entries))
	out = append(out, entries[0])
	var oldIdx []int // oldIdx[newIndex] = old index
	oldIdx = append(oldIdx, 0)
	for i := 1; i < len(entries); i++ {
		if emit[i] {
			out = append(out, entries[i])
			oldIdx = append(oldIdx, i)
		}
	}

	// For a non-relocatable output BFD adds a fresh section symbol for every
	// output section, in section order, after the surviving local symbols and
	// before the globals (bfd/elf.c: elf_map_symbols). This covers both
	// --keep-section-symbols and targets that always keep section symbols.
	var generated []elf.Symbol
	if generateSectionSyms {
		seen := make(map[int]bool)
		for _, sym := range out[1:] {
			if sym.Type() == elf.STT_SECTION && int(sym.Shndx) < len(f.Sections) {
				seen[int(sym.Shndx)] = true
			}
		}
		for idx := 1; idx < len(f.Sections); idx++ {
			if seen[idx] || !sectionSymbolTarget(f, symSec, idx) {
				continue
			}
			generated = append(generated, elf.Symbol{
				Info:  elf.STT_SECTION | elf.STB_LOCAL<<4,
				Shndx: uint16(idx),
				Value: f.Sections[idx].Addr,
			})
		}
	}

	// ELF requires locals to precede globals. BFD reorders them the same way.
	if len(out) > 1 && out[0].Bind() != elf.STB_LOCAL {
		out[0].SetBind(elf.STB_LOCAL)
	}
	sorted := make([]elf.Symbol, 0, len(out)+len(generated))
	finalIdx := make([]int, len(entries))
	for i := range finalIdx {
		finalIdx[i] = -1
	}
	appendSym := func(sym elf.Symbol, oldI int) {
		sorted = append(sorted, sym)
		if oldI >= 0 {
			finalIdx[oldI] = len(sorted) - 1
		}
	}
	appendSym(out[0], oldIdx[0])
	for i := 1; i < len(out); i++ {
		if out[i].Bind() == elf.STB_LOCAL {
			appendSym(out[i], oldIdx[i])
		}
	}
	for _, sym := range generated {
		appendSym(sym, -1)
	}
	for i := 1; i < len(out); i++ {
		if out[i].Bind() != elf.STB_LOCAL {
			appendSym(out[i], oldIdx[i])
		}
	}
	st.Entries = sorted
	if err := f.SetSymtab(st); err != nil {
		return err
	}

	// Renumber relocations that referenced the static symbol table.
	var emptied []*elf.Section
	for _, s := range f.Sections {
		if s.Type != elf.SHT_REL && s.Type != elf.SHT_RELA {
			continue
		}
		if int(s.Link) != symIdx {
			continue
		}
		relocs, err := f.ReadRelocs(s)
		if err != nil {
			return err
		}
		keepReloc := relocs[:0]
		for _, r := range relocs {
			if int(r.Sym) >= len(finalIdx) || finalIdx[r.Sym] < 0 {
				if c.StripAll {
					// With --strip-all only symbols named by -K survive;
					// relocations naming other symbols are dropped.
					continue
				}
				name := ""
				if int(r.Sym) < len(entries) {
					name = symbolName(f, &entries[r.Sym])
				}
				return &FatalError{Msg: fmt.Sprintf("symbol `%s' required but not present", name)}
			}
			r.Sym = uint32(finalIdx[r.Sym])
			keepReloc = append(keepReloc, r)
		}
		if len(keepReloc) == 0 {
			emptied = append(emptied, s)
			continue
		}
		if err := f.SetRelocs(s, keepReloc); err != nil {
			return err
		}
	}
	for _, s := range emptied {
		if idx := f.SectionIndex(s); idx > 0 {
			if err := f.RemoveSection(idx); err != nil {
				return err
			}
		}
	}
	return nil
}

// isHiddenSymbol reports whether the symbol has hidden or internal visibility,
// which is what GNU's --localize-hidden acts on.
func isHiddenSymbol(s *elf.Symbol) bool {
	v := s.Other & 0x3
	return v == elf.STV_HIDDEN || v == elf.STV_INTERNAL
}
