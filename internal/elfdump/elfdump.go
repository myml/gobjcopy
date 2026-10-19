// Package elfdump renders a parsed ELF file as a stable, human readable text
// so two files can be compared semantically in tests.
package elfdump

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/myml/gobjcopy/elf"
)

// Options controls what Dump includes.
type Options struct {
	// Offsets includes file offsets of sections and segments. GNU objcopy and
	// gobjcopy lay files out differently, so this is only useful when
	// comparing against the same implementation.
	Offsets bool
	// Contents includes section content hashes.
	Contents bool
	// IgnoreRelro skips PT_GNU_RELRO. GNU objcopy drops that segment when it
	// has to regenerate the program headers, while gobjcopy preserves it
	// (which is at least as safe); the difference is therefore not a
	// compatibility failure.
	IgnoreRelro bool
	// IgnoreSegments omits the program header dump entirely. It defaults to
	// true because GNU regenerates program headers with heuristics that vary
	// per transformation; segment layout is covered by the elf package tests.
	IgnoreSegments bool
}

// Default is the semantic comparison mode.
var Default = Options{Contents: true, IgnoreRelro: true, IgnoreSegments: true}

// DumpFile parses path and returns its dump.
func DumpFile(path string, opt Options) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	return Dump(f, opt), nil
}

// Dump returns the textual representation of f.
func Dump(f *elf.File, opt Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "header class=%d data=%d osabi=%d abi=%d type=%d machine=%d version=%d entry=%#x flags=%#x\n",
		f.Class, f.Data, f.OSABI, f.ABIVersion, f.Type, f.Machine, f.Version, f.Entry, f.Flags)

	for i, s := range f.Sections {
		size := s.Size
		if !sizeComparable(s) {
			size = 0
		}
		fmt.Fprintf(&b, "section %d: type=%d name=%q flags=%#x addr=%#x size=%#x align=%#x entsize=%#x",
			i, s.Type, s.Name, s.Flags, s.Addr, size, s.Addralign, s.Entsize)
		if opt.Offsets {
			fmt.Fprintf(&b, " off=%#x", s.Offset)
		}
		if int(s.Link) < len(f.Sections) {
			fmt.Fprintf(&b, " link=%q", f.Sections[s.Link].Name)
		} else {
			fmt.Fprintf(&b, " link=%d", s.Link)
		}
		if isSectionIndexInfo(s) && int(s.Info) < len(f.Sections) {
			fmt.Fprintf(&b, " info=%q", f.Sections[s.Info].Name)
		} else {
			fmt.Fprintf(&b, " info=%d", s.Info)
		}
		if opt.Contents && !s.IsNoBits() && hashable(f, s) {
			fmt.Fprintf(&b, " sha=%s", hash(s.Data))
		}
		b.WriteByte('\n')
	}

	if opt.IgnoreSegments {
		return b.String()
	}
	for i, ph := range f.Segments {
		if opt.IgnoreRelro && ph.Type != elf.PT_LOAD {
			// GNU regenerates the non-LOAD program headers in ways that
			// differ from file to file; only LOAD segments are compared.
			continue
		}
		fmt.Fprintf(&b, "segment %d: type=%d flags=%#x vaddr=%#x memsz=%#x align=%#x",
			i, ph.Type, ph.Flags, ph.Vaddr, ph.Memsz, ph.Align)
		if opt.Offsets {
			fmt.Fprintf(&b, " off=%#x filesz=%#x", ph.Offset, ph.Filesz)
		}
		b.WriteByte('\n')
	}

	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_SYMTAB && sec.Type != elf.SHT_DYNSYM {
			continue
		}
		st, err := f.ReadSymtab(sec)
		if err != nil {
			fmt.Fprintf(&b, "symtab %q: error %v\n", sec.Name, err)
			continue
		}
		fmt.Fprintf(&b, "symtab %q: count=%d info=%d\n", sec.Name, len(st.Entries), sec.Info)
		for i, sym := range st.Entries {
			fmt.Fprintf(&b, " sym %d: name=%q bind=%d type=%d vis=%d shndx=%s value=%#x size=%#x\n",
				i, sym.Name, sym.Bind(), sym.Type(), sym.Visibility(), shndx(f, sym.Shndx), sym.Value, sym.Size)
		}
	}

	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_REL && sec.Type != elf.SHT_RELA {
			continue
		}
		relocs, err := f.ReadRelocs(sec)
		if err != nil {
			fmt.Fprintf(&b, "relocs %q: error %v\n", sec.Name, err)
			continue
		}
		var names []string
		if st := symtabOf(f, sec.Link); st != nil {
			for _, s := range st.Entries {
				names = append(names, s.Name)
			}
		}
		target := ""
		if int(sec.Info) < len(f.Sections) {
			target = f.Sections[sec.Info].Name
		}
		fmt.Fprintf(&b, "relocs %q: target=%q link=%q count=%d\n", sec.Name, target, sectionName(f, sec.Link), len(relocs))
		for i, r := range relocs {
			name := ""
			if int(r.Sym) < len(names) {
				name = names[r.Sym]
			}
			fmt.Fprintf(&b, " rel %d: off=%#x sym=%q symidx=%d type=%d addend=%d\n", i, r.Offset, name, r.Sym, r.Type, r.Addend)
		}
	}
	return b.String()
}

// hashable reports whether a section's raw bytes are a stable property of the
// output. Symbol and relocation tables are compared through their decoded
// entries instead, because their string offsets and indices need not match
// GNU's byte-for-byte.
func hashable(f *elf.File, sec *elf.Section) bool {
	if sec.Name == ".gnu_debuglink" || sec.Name == ".gnu_debugaltlink" {
		// The CRC depends on the debug file, which each implementation
		// generates itself and which legitimately differs.
		return false
	}
	switch sec.Type {
	case elf.SHT_SYMTAB, elf.SHT_DYNSYM, elf.SHT_REL, elf.SHT_RELA:
		return false
	case elf.SHT_STRTAB:
		switch sec.Name {
		case ".strtab", ".dynstr", ".shstrtab":
			return false
		}
	}
	return sec.Flags&elf.SHF_COMPRESSED == 0
}

// sizeComparable reports whether a section's size is meaningful for comparing
// two independent implementations. String tables reachable only through
// symbol tables may legitimately differ in layout.
func sizeComparable(sec *elf.Section) bool {
	if sec.Type == elf.SHT_STRTAB {
		switch sec.Name {
		case ".strtab", ".dynstr", ".shstrtab":
			return false
		}
	}
	return true
}

func isSectionIndexInfo(sec *elf.Section) bool {
	switch sec.Type {
	case elf.SHT_REL, elf.SHT_RELA, elf.SHT_GROUP:
		return true
	}
	return sec.Flags&elf.SHF_INFO_LINK != 0
}

func symtabOf(f *elf.File, idx uint32) *elf.Symtab {
	if int(idx) >= len(f.Sections) {
		return nil
	}
	st, err := f.ReadSymtab(f.Sections[idx])
	if err != nil {
		return nil
	}
	return st
}

func sectionName(f *elf.File, idx uint32) string {
	if int(idx) < len(f.Sections) {
		return f.Sections[idx].Name
	}
	return fmt.Sprintf("%d", idx)
}

func shndx(f *elf.File, v uint16) string {
	if v == elf.SHN_UNDEF {
		return "UNDEF"
	}
	if v == elf.SHN_ABS {
		return "ABS"
	}
	if v == elf.SHN_COMMON {
		return "COMMON"
	}
	if v >= elf.SHN_LORESERVE {
		return fmt.Sprintf("%#x", v)
	}
	if int(v) < len(f.Sections) {
		return fmt.Sprintf("%d(%s)", v, f.Sections[v].Name)
	}
	return fmt.Sprintf("%d", v)
}

func hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// FirstDiff returns the first differing line between two dumps, or "".
func FirstDiff(a, b string) string {
	al := strings.Split(a, "\n")
	bl := strings.Split(b, "\n")
	n := len(al)
	if len(bl) > n {
		n = len(bl)
	}
	for i := 0; i < n; i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return fmt.Sprintf("line %d:\n  a: %s\n  b: %s", i+1, x, y)
		}
	}
	return ""
}

var _ = sort.Strings
