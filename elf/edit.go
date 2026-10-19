package elf

// isSectionIndexInfo reports whether a section's sh_info field holds a section
// index rather than a symbol count or version.
func isSectionIndexInfo(sec *Section) bool {
	switch sec.Type {
	case SHT_REL, SHT_RELA, SHT_GROUP:
		return true
	}
	return sec.Flags&SHF_INFO_LINK != 0
}

// RemoveSection deletes the section at index idx and fixes every reference to
// sections (sh_link, sh_info, symbol st_shndx, group members). Symbols that
// live in the removed section are dropped from the static symbol table (and
// relocations naming them are dropped too), matching BFD. Dynamic symbols are
// never dropped, since the dynamic hash tables would break.
func (f *File) RemoveSection(idx int) error {
	if idx <= 0 || idx >= len(f.Sections) {
		return errf("section index %d out of range", idx)
	}
	for si, sec := range f.Sections {
		if sec.Type != SHT_SYMTAB && sec.Type != SHT_DYNSYM {
			continue
		}
		if sec.Link == 0 || int(sec.Link) >= len(f.Sections) || f.Sections[sec.Link].Type != SHT_STRTAB {
			// The string table is already gone (or was never there); the
			// symbol table cannot be re-encoded reliably, so leave it alone.
			continue
		}
		st, err := f.ReadSymtab(sec)
		if err != nil {
			return err
		}
		drop := sec.Type == SHT_SYMTAB
		remap := make([]int, len(st.Entries))
		if len(remap) > 0 {
			remap[0] = 0
		}
		out := make([]Symbol, 0, len(st.Entries))
		if len(st.Entries) > 0 {
			out = append(out, st.Entries[0])
		}
		changed := false
		for i := 1; i < len(st.Entries); i++ {
			sh := st.Entries[i].Shndx
			switch {
			case int(sh) == idx && drop:
				remap[i] = -1
				changed = true
				continue
			case int(sh) == idx:
				st.Entries[i].Shndx = SHN_UNDEF
				changed = true
			case int(sh) > idx && sh < SHN_LORESERVE:
				st.Entries[i].Shndx = sh - 1
				changed = true
			}
			remap[i] = len(out)
			out = append(out, st.Entries[i])
		}
		if !changed {
			continue
		}
		if drop {
			for _, rs := range f.Sections {
				if rs.Type != SHT_REL && rs.Type != SHT_RELA {
					continue
				}
				if int(rs.Link) != si {
					continue
				}
				relocs, err := f.ReadRelocs(rs)
				if err != nil {
					return err
				}
				kept := relocs[:0]
				for _, r := range relocs {
					if int(r.Sym) < len(remap) && remap[r.Sym] >= 0 {
						r.Sym = uint32(remap[r.Sym])
						kept = append(kept, r)
					}
				}
				if err := f.SetRelocs(rs, kept); err != nil {
					return err
				}
			}
			if err := f.writeSymtab(sec, out); err != nil {
				return err
			}
		} else {
			if err := f.writeSymtab(sec, st.Entries); err != nil {
				return err
			}
		}
	}
	// Section links and group membership.
	for i, sec := range f.Sections {
		if i == idx {
			continue
		}
		if int(sec.Link) == idx {
			sec.Link = 0
		} else if int(sec.Link) > idx {
			sec.Link--
		}
		if isSectionIndexInfo(sec) {
			if int(sec.Info) == idx {
				sec.Info = 0
			} else if int(sec.Info) > idx {
				sec.Info--
			}
		}
		if sec.Type == SHT_GROUP {
			order := f.Data.Order()
			for off := 4; off+4 <= len(sec.Data); off += 4 {
				v := order.Uint32(sec.Data[off:])
				if int(v) == idx {
					order.PutUint32(sec.Data[off:], 0)
				} else if int(v) > idx {
					order.PutUint32(sec.Data[off:], v-1)
				}
			}
		}
	}
	if f.Shstrndx == idx {
		f.Shstrndx = 0
	} else if f.Shstrndx > idx {
		f.Shstrndx--
	}
	f.Sections = append(f.Sections[:idx], f.Sections[idx+1:]...)
	return nil
}

// RemoveSectionByName removes the named section, reporting whether it existed.
func (f *File) RemoveSectionByName(name string) (bool, error) {
	for i, s := range f.Sections {
		if s.Name == name {
			return true, f.RemoveSection(i)
		}
	}
	return false, nil
}

// InsertSection inserts sec at index pos, shifting section references.
func (f *File) InsertSection(pos int, sec *Section) error {
	if pos < 0 || pos > len(f.Sections) {
		return errf("section index %d out of range", pos)
	}
	if pos == 0 {
		return errf("cannot insert at index 0")
	}
	if sec == nil {
		return errf("nil section")
	}
	// Newly built sections usually only carry Data; derive the on-disk size
	// so the writer reserves space for it.
	if !sec.IsNoBits() && sec.Size == 0 && len(sec.Data) > 0 {
		sec.Size = uint64(len(sec.Data))
	}
	// Shift symbol section indices first, while indices still describe the old
	// table (all symbols pointing at >= pos move by one).
	for _, s := range f.Sections {
		if s.Type != SHT_SYMTAB && s.Type != SHT_DYNSYM {
			continue
		}
		st, err := f.ReadSymtab(s)
		if err != nil {
			return err
		}
		changed := false
		for i := range st.Entries {
			sh := st.Entries[i].Shndx
			if int(sh) >= pos && sh < SHN_LORESERVE {
				st.Entries[i].Shndx = sh + 1
				changed = true
			}
		}
		if changed {
			if err := f.writeSymtab(s, st.Entries); err != nil {
				return err
			}
		}
	}
	for i, s := range f.Sections {
		if i == 0 {
			continue
		}
		if int(s.Link) >= pos {
			s.Link++
		}
		if isSectionIndexInfo(s) && int(s.Info) >= pos {
			s.Info++
		}
		if s.Type == SHT_GROUP {
			order := f.Data.Order()
			for off := 4; off+4 <= len(s.Data); off += 4 {
				v := order.Uint32(s.Data[off:])
				if int(v) >= pos {
					order.PutUint32(s.Data[off:], v+1)
				}
			}
		}
	}
	if f.Shstrndx >= pos {
		f.Shstrndx++
	}
	f.Sections = append(f.Sections, nil)
	copy(f.Sections[pos+1:], f.Sections[pos:])
	f.Sections[pos] = sec
	return nil
}

// AddSection inserts sec immediately before the section name string table, so
// that new sections keep the conventional position at the end of the file.
func (f *File) AddSection(sec *Section) error {
	// BFD places sections added by objcopy (--add-section, --add-debuglink)
	// before the symbol table, which always comes last.
	pos := len(f.Sections)
	if f.Shstrndx > 0 && f.Shstrndx < len(f.Sections) {
		pos = f.Shstrndx
	}
	for i, s := range f.Sections {
		if s.Type == SHT_SYMTAB {
			pos = i
			break
		}
	}
	return f.InsertSection(pos, sec)
}
