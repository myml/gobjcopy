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
			entries[i].Name = redef(entries[i].Name)
		}
	}

	keep := make([]bool, len(entries))
	usedInReloc := make([]bool, len(entries))
	for i := 1; i < len(entries); i++ {
		sym := &entries[i]
		name := sym.Name
		u := used[i]
		usedInReloc[i] = u
		var k bool
		switch {
		case c.StripAll:
			k = false
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
		if k && len(c.OnlySections) > 0 {
			// GNU keeps only symbols defined in a copied section.
			if sym.Type() == elf.STT_SECTION || int(sym.Shndx) == 0 || int(sym.Shndx) >= len(f.Sections) {
				k = false
			}
		}
		if k && c.matchSymbol(c.StripSymbols, name) {
			if u {
				return &FatalError{Msg: fmt.Sprintf("not stripping symbol `%s' because it is named in a relocation", name)}
			}
			k = false
		}
		if k && c.matchSymbol(c.StripUnneededSymbols, name) && !u {
			k = false
		}
		if !k {
			if c.KeepFileSymbols && sym.Type() == elf.STT_FILE {
				k = true
			}
			if c.KeepSectionSymbols && sym.Type() == elf.STT_SECTION {
				k = true
			}
			if c.matchSymbol(c.KeepSymbols, name) {
				k = true
			}
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

	// -G localizes every global not named on the command line.
	if len(c.KeepGlobalSymbols) > 0 {
		for i := 1; i < len(entries); i++ {
			if !keep[i] {
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

	// Collect the survivors, keeping the null symbol first.
	out := make([]elf.Symbol, 0, len(entries))
	out = append(out, entries[0])
	var oldIdx []int // oldIdx[newIndex] = old index
	oldIdx = append(oldIdx, 0)
	for i := 1; i < len(entries); i++ {
		if keep[i] {
			out = append(out, entries[i])
			oldIdx = append(oldIdx, i)
		}
	}

	if len(out) <= 1 {
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

	// ELF requires locals to precede globals. BFD reorders them the same way.
	order := make([]int, 0, len(out))
	if len(out) > 1 && out[0].Bind() != elf.STB_LOCAL {
		out[0].SetBind(elf.STB_LOCAL)
	}
	order = append(order, 0)
	for i := 1; i < len(out); i++ {
		if out[i].Bind() == elf.STB_LOCAL {
			order = append(order, i)
		}
	}
	for i := 1; i < len(out); i++ {
		if out[i].Bind() != elf.STB_LOCAL {
			order = append(order, i)
		}
	}
	sorted := make([]elf.Symbol, len(out))
	finalIdx := make([]int, len(entries))
	for i := range finalIdx {
		finalIdx[i] = -1
	}
	for newI, oldI := range order {
		sorted[newI] = out[oldI]
		finalIdx[oldIdx[oldI]] = newI
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
					name = entries[r.Sym].Name
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
