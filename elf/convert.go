package elf

import (
	"encoding/binary"
	"math"
	"sort"
	"strings"
)

// Class conversion (ELF32 <-> ELF64).
//
// The writer derives every header field's width from File.Class, so converting
// a file is a matter of re-encoding the section contents whose layout depends
// on the class:
//
//   - symbol tables (Elf32_Sym is 16 bytes, Elf64_Sym is 24 and the fields are
//     in a different order),
//   - relocation sections (r_info is split differently and entries are wider
//     in ELF64),
//   - SHF_COMPRESSED sections (the Elf_Chdr header is 12 or 24 bytes),
//   - dynamic sections (Elf32_Dyn/Elf64_Dyn),
//   - SHT_RELR (class-sized address words),
//   - SHT_GNU_HASH (class-sized Bloom filter words),
//   - .note.gnu.property (the property list is aligned to the class word
//     size).
//
// Everything else is copied verbatim, matching BFD, whose
// bfd_convert_section_contents only rewrites compressed headers and GNU
// property notes.  ELF32 can represent a strict subset of ELF64, so a 64->32
// conversion first checks every field that has to fit in 32 bits and reports a
// clear error instead of silently truncating.

// dynamicEntry is one decoded .dynamic entry.
type dynamicEntry struct {
	tag int64
	val uint64
}

// gnuProperty is one decoded GNU property note entry.
type gnuProperty struct {
	typ  uint32
	data []byte
}

// The saved* types below hold the class-dependent decoding of a section until
// File.Class has been changed and the data can be re-encoded.

type savedSymtab struct {
	sec     *Section
	entries []Symbol
}

type savedRelocs struct {
	sec    *Section
	relocs []Reloc
}

type savedCompressed struct {
	sec     *Section
	typ     uint32
	size    uint64
	align   uint64
	payload []byte
}

type savedDynamic struct {
	sec     *Section
	entries []dynamicEntry
}

type savedRelr struct {
	sec     *Section
	entries []uint64
}

type savedGNUHash struct {
	sec       *Section
	header    [16]byte
	bloom     []uint64
	rest      []byte
	bloomSize uint32
}

type savedProperty struct {
	sec   *Section
	props []gnuProperty
}

// ConvertClass converts f between ELF32 and ELF64 in place, re-encoding every
// class-dependent structure.  Converting to ELF32 fails when an address, size,
// offset or relocation cannot be represented in 32 bits.
func (f *File) ConvertClass(class Class) error { return ConvertClass(f, class) }

// ConvertClass converts f to class in place.  See File.ConvertClass.
func ConvertClass(f *File, class Class) error {
	if f == nil {
		return errf("nil file")
	}
	if class != Class32 && class != Class64 {
		return errf("invalid ELF class %d", class)
	}
	if f.Class == class {
		return nil
	}
	if !f.SectionHeadersPresent {
		return errf("cannot convert class without section headers")
	}
	// Class conversion is only meaningful for relocatable objects: executable
	// images embed addresses in code, GOT and pointer arrays that would need a
	// complete relayout (and recounting), which objcopy does not do either.
	if f.Type != ET_REL {
		return errf("cannot convert ELF file type %d between classes", f.Type)
	}

	// SHF_X86_64_LARGE only exists in x86-64 targets.  The objcopy hook only
	// knows the destination class, so any conversion to a 32-bit target is
	// treated as a non-x86-64 target here.  This matches GNU's fatal
	// diagnostic for -O elf32-i386 with --set-section-flags ...=large.
	if class == Class32 {
		for _, sec := range f.Sections {
			if sec.Flags&SHF_X86_64_LARGE != 0 {
				return errf("[%s]: 'large' flag is ELF x86-64 specific", sec.Name)
			}
		}
	}

	from := f.Class
	order := f.Data.Order()
	var (
		symtabs   []savedSymtab
		relocs    []savedRelocs
		comp      []savedCompressed
		dynamics  []savedDynamic
		relrs     []savedRelr
		hashes    []savedGNUHash
		propNotes []savedProperty
	)

	for _, sec := range f.Sections {
		switch sec.Type {
		case SHT_SYMTAB, SHT_DYNSYM:
			st, err := f.ReadSymtab(sec)
			if err != nil {
				return err
			}
			symtabs = append(symtabs, savedSymtab{sec: sec, entries: st.Entries})
		case SHT_REL, SHT_RELA:
			rs, err := f.ReadRelocs(sec)
			if err != nil {
				return err
			}
			relocs = append(relocs, savedRelocs{sec: sec, relocs: rs})
		case SHT_DYNAMIC:
			ds, err := decodeDynamic(sec, from, order)
			if err != nil {
				return err
			}
			dynamics = append(dynamics, savedDynamic{sec: sec, entries: ds})
		case SHT_RELR:
			rs, err := decodeRelr(sec, from, order)
			if err != nil {
				return err
			}
			relrs = append(relrs, savedRelr{sec: sec, entries: rs})
		case SHT_GNU_HASH:
			h, err := decodeGNUHash(sec, from, order)
			if err != nil {
				return err
			}
			// Going to ELF64 pairs up 32-bit Bloom words; that is only
			// possible with an even count.
			if class == Class64 && h.bloomSize%2 != 0 {
				return errf("GNU hash section %q has an odd Bloom filter size %d; cannot convert to ELF64",
					sec.Name, h.bloomSize)
			}
			hashes = append(hashes, h)
		case SHT_NOTE:
			if strings.HasPrefix(sec.Name, ".note.gnu.property") {
				props, ok := decodePropertyNotes(sec, from, order)
				if ok {
					propNotes = append(propNotes, savedProperty{sec: sec, props: props})
				}
			}
		}
		if sec.Flags&SHF_COMPRESSED != 0 && !sec.IsNoBits() && len(sec.Data) > 0 {
			c, err := decodeCompressed(sec, from, order)
			if err != nil {
				return err
			}
			comp = append(comp, c)
		}
	}

	if class == Class32 {
		if err := checkClassFits(f, symtabs, relocs, dynamics, relrs, comp); err != nil {
			return err
		}
	}

	f.Class = class

	// Symbol tables.  Their string tables are rewritten by SetSymtab; the
	// section-relative alignment follows the class like BFD's.
	for _, st := range symtabs {
		if err := f.SetSymtab(&Symtab{Section: st.sec, Entries: st.entries}); err != nil {
			return err
		}
		if class == Class32 {
			st.sec.Addralign = 4
		} else {
			st.sec.Addralign = 8
		}
	}

	// Relocations.
	for _, rs := range relocs {
		if err := f.SetRelocs(rs.sec, rs.relocs); err != nil {
			return err
		}
		if class == Class32 {
			rs.sec.Addralign = 4
		} else {
			rs.sec.Addralign = 8
		}
	}

	// Compressed sections: rebuild the class-sized Elf_Chdr in front of the
	// untouched compressed payload.
	for _, c := range comp {
		var hdr int
		if class == Class64 {
			hdr = 24
		} else {
			hdr = 12
		}
		buf := make([]byte, hdr+len(c.payload))
		order.PutUint32(buf[0:], c.typ)
		if class == Class64 {
			order.PutUint64(buf[8:], c.size)
			order.PutUint64(buf[16:], c.align)
		} else {
			order.PutUint32(buf[4:], uint32(c.size))
			order.PutUint32(buf[8:], uint32(c.align))
		}
		copy(buf[hdr:], c.payload)
		c.sec.Data = buf
		c.sec.Size = uint64(len(buf))
	}

	for _, d := range dynamics {
		encodeDynamic(d.sec, d.entries, class, order)
	}
	for _, r := range relrs {
		encodeRelr(r.sec, r.entries, class, order)
	}
	for _, h := range hashes {
		encodeGNUHash(h, class, order)
	}
	for _, p := range propNotes {
		encodePropertyNote(p.sec, p.props, class, order)
	}
	return nil
}

// checkClassFits verifies that everything which has a fixed 32-bit field on
// disk fits after converting to ELF32.
func checkClassFits(f *File, symtabs []savedSymtab, relocs []savedRelocs,
	dynamics []savedDynamic, relrs []savedRelr, comp []savedCompressed) error {

	if err := checkU32("entry point", f.Entry); err != nil {
		return err
	}
	for _, sec := range f.Sections {
		for _, v := range []struct {
			what string
			val  uint64
		}{
			{"address", sec.Addr},
			{"size", sec.Size},
			{"offset", sec.Offset},
			{"alignment", sec.Addralign},
			{"entry size", sec.Entsize},
			{"flags", sec.Flags},
		} {
			if err := checkU32("section "+quote(sec.Name)+" "+v.what, v.val); err != nil {
				return err
			}
		}
	}
	for _, ph := range f.Segments {
		for _, v := range []struct {
			what string
			val  uint64
		}{
			{"offset", ph.Offset},
			{"virtual address", ph.Vaddr},
			{"physical address", ph.Paddr},
			{"file size", ph.Filesz},
			{"memory size", ph.Memsz},
			{"alignment", ph.Align},
		} {
			if err := checkU32("segment "+v.what, v.val); err != nil {
				return err
			}
		}
	}
	for _, st := range symtabs {
		for _, sym := range st.entries {
			if err := checkU32("symbol "+quote(sym.Name)+" value", sym.Value); err != nil {
				return err
			}
			if err := checkU32("symbol "+quote(sym.Name)+" size", sym.Size); err != nil {
				return err
			}
		}
	}
	for _, rs := range relocs {
		for _, r := range rs.relocs {
			if err := checkU32("relocation offset", r.Offset); err != nil {
				return err
			}
			if r.Type > 0xff {
				return errf("relocation type 0x%x in %q does not fit in ELF32", r.Type, rs.sec.Name)
			}
			if r.HasAddend && (r.Addend < math.MinInt32 || r.Addend > math.MaxInt32) {
				return errf("relocation addend %d in %q does not fit in ELF32", r.Addend, rs.sec.Name)
			}
		}
	}
	for _, d := range dynamics {
		for _, e := range d.entries {
			if e.tag < math.MinInt32 || e.tag > math.MaxInt32 {
				return errf("dynamic tag 0x%x does not fit in ELF32", uint64(e.tag))
			}
			if err := checkU32("dynamic value", e.val); err != nil {
				return err
			}
		}
	}
	for _, r := range relrs {
		for _, off := range r.entries {
			if err := checkU32("relative relocation offset", off); err != nil {
				return err
			}
		}
	}
	for _, c := range comp {
		if err := checkU32("section "+quote(c.sec.Name)+" uncompressed size", c.size); err != nil {
			return err
		}
		if err := checkU32("section "+quote(c.sec.Name)+" compressed alignment", c.align); err != nil {
			return err
		}
	}
	return nil
}

func checkU32(what string, v uint64) error {
	if v > math.MaxUint32 {
		return errf("%s 0x%x does not fit in ELF32", what, v)
	}
	return nil
}

func quote(s string) string { return "\"" + s + "\"" }

// ---- compressed sections -------------------------------------------------

func decodeCompressed(sec *Section, class Class, order binary.ByteOrder) (savedCompressed, error) {
	c := savedCompressed{sec: sec}
	var hdr int
	if class == Class64 {
		if len(sec.Data) < 24 {
			return c, errf("section %q: truncated compressed header", sec.Name)
		}
		c.typ = order.Uint32(sec.Data[0:])
		c.size = order.Uint64(sec.Data[8:])
		c.align = order.Uint64(sec.Data[16:])
		hdr = 24
	} else {
		if len(sec.Data) < 12 {
			return c, errf("section %q: truncated compressed header", sec.Name)
		}
		c.typ = order.Uint32(sec.Data[0:])
		c.size = uint64(order.Uint32(sec.Data[4:]))
		c.align = uint64(order.Uint32(sec.Data[8:]))
		hdr = 12
	}
	c.payload = append([]byte(nil), sec.Data[hdr:]...)
	return c, nil
}

// ---- GNU property notes --------------------------------------------------

const (
	gnuPropertyType0   = 5
	gnuPropertyStackSz = 1
)

// decodePropertyNotes parses every NT_GNU_PROPERTY_TYPE_0 note in a
// .note.gnu.property section and merges their properties the way BFD does when
// it reads an object: properties with the same type are combined (OR for
// numeric x86 properties, last value wins for the stack size), and the
// resulting list is what objcopy writes as a single note on class conversion.
// ok is false when the section is not a well formed property note section, in
// which case it is left untouched.
func decodePropertyNotes(sec *Section, class Class, order binary.ByteOrder) ([]gnuProperty, bool) {
	align := int(sec.Addralign)
	if align != 4 && align != 8 {
		align = 4
		if class == Class64 {
			align = 8
		}
	}
	data := sec.Data
	var props []gnuProperty
	found := false
	for pos := 0; pos < len(data); {
		if len(data)-pos < 12 {
			return nil, false
		}
		namesz := int(order.Uint32(data[pos:]))
		descsz := int(order.Uint32(data[pos+4:]))
		noteType := order.Uint32(data[pos+8:])
		nameOff := pos + 12
		if namesz < 0 || namesz > len(data)-nameOff {
			return nil, false
		}
		descOff := pos + alignInt(12+namesz, align)
		if descOff > len(data) || descsz < 0 || descsz > len(data)-descOff {
			return nil, false
		}
		if namesz == 4 && noteType == gnuPropertyType0 &&
			string(data[nameOff:nameOff+4]) == "GNU\x00" {
			ps, ok := parsePropertyList(data[descOff:descOff+descsz], align, order)
			if !ok {
				return nil, false
			}
			found = true
			props = mergeProperties(props, ps, order)
		}
		next := descOff + alignInt(descsz, align)
		if next <= pos {
			return nil, false
		}
		pos = next
	}
	if !found {
		return nil, false
	}
	return props, true
}

// parsePropertyList decodes the descriptor of one GNU property note.
func parsePropertyList(desc []byte, align int, order binary.ByteOrder) ([]gnuProperty, bool) {
	var props []gnuProperty
	for off := 0; off < len(desc); {
		if len(desc)-off < 8 {
			return nil, false
		}
		typ := order.Uint32(desc[off:])
		datasz := int(order.Uint32(desc[off+4:]))
		off += 8
		if datasz < 0 || datasz > len(desc)-off {
			return nil, false
		}
		props = append(props, gnuProperty{
			typ:  typ,
			data: append([]byte(nil), desc[off:off+datasz]...),
		})
		off = alignInt(off+datasz, align)
	}
	return props, true
}

// mergeProperties combines ps into props.  Duplicate x86 properties are ORed
// (this is what _bfd_x86_elf_parse_gnu_properties does for the properties of a
// single object); a later stack size replaces an earlier one.
func mergeProperties(props, ps []gnuProperty, order binary.ByteOrder) []gnuProperty {
	for _, p := range ps {
		idx := -1
		for i := range props {
			if props[i].typ == p.typ {
				idx = i
				break
			}
		}
		if idx < 0 {
			props = append(props, p)
			continue
		}
		old := &props[idx]
		switch {
		case p.typ == gnuPropertyStackSz:
			old.data = p.data
		case len(old.data) == 4 && len(p.data) == 4:
			order.PutUint32(old.data, order.Uint32(old.data)|order.Uint32(p.data))
		case len(old.data) == 8 && len(p.data) == 8:
			order.PutUint64(old.data, order.Uint64(old.data)|order.Uint64(p.data))
		}
	}
	return props
}

// encodePropertyNote rewrites a GNU property note using the output class's
// property alignment.  Properties are sorted by type, as BFD does.
func encodePropertyNote(sec *Section, props []gnuProperty, class Class, order binary.ByteOrder) {
	list := append([]gnuProperty(nil), props...)
	sort.SliceStable(list, func(i, j int) bool { return list[i].typ < list[j].typ })
	outAlign := 4
	if class == Class64 {
		outAlign = 8
	}
	descsz := 0
	for _, p := range list {
		datasz := len(p.data)
		if p.typ == gnuPropertyStackSz {
			datasz = outAlign
		}
		descsz = alignInt(descsz+8+datasz, outAlign)
	}
	buf := make([]byte, 16+descsz)
	order.PutUint32(buf[0:], 4)
	order.PutUint32(buf[4:], uint32(descsz))
	order.PutUint32(buf[8:], gnuPropertyType0)
	copy(buf[12:16], "GNU\x00")
	off := 16
	for _, p := range list {
		datasz := len(p.data)
		if p.typ == gnuPropertyStackSz {
			datasz = outAlign
		}
		order.PutUint32(buf[off:], p.typ)
		order.PutUint32(buf[off+4:], uint32(datasz))
		off += 8
		if p.typ == gnuPropertyStackSz {
			var v uint64
			if len(p.data) >= 8 {
				v = order.Uint64(p.data)
			} else if len(p.data) >= 4 {
				v = uint64(order.Uint32(p.data))
			}
			if outAlign == 8 {
				order.PutUint64(buf[off:], v)
			} else {
				order.PutUint32(buf[off:], uint32(v))
			}
		} else {
			copy(buf[off:], p.data)
		}
		off = alignInt(off+datasz, outAlign)
	}
	sec.Data = buf
	sec.Size = uint64(len(buf))
	sec.Addralign = uint64(outAlign)
}

func alignInt(v, a int) int {
	if a <= 1 {
		return v
	}
	return (v + a - 1) / a * a
}

// ---- .dynamic ------------------------------------------------------------

func decodeDynamic(sec *Section, class Class, order binary.ByteOrder) ([]dynamicEntry, error) {
	ent := 8
	if class == Class64 {
		ent = 16
	}
	if len(sec.Data)%ent != 0 {
		return nil, errf("dynamic section %q has bad size %d", sec.Name, len(sec.Data))
	}
	out := make([]dynamicEntry, 0, len(sec.Data)/ent)
	for off := 0; off < len(sec.Data); off += ent {
		b := sec.Data[off:]
		var e dynamicEntry
		if class == Class64 {
			e.tag = int64(order.Uint64(b[0:]))
			e.val = order.Uint64(b[8:])
		} else {
			e.tag = int64(int32(order.Uint32(b[0:])))
			e.val = uint64(order.Uint32(b[4:]))
		}
		out = append(out, e)
	}
	return out, nil
}

func encodeDynamic(sec *Section, entries []dynamicEntry, class Class, order binary.ByteOrder) {
	ent := 8
	if class == Class64 {
		ent = 16
	}
	buf := make([]byte, len(entries)*ent)
	for i, e := range entries {
		b := buf[i*ent:]
		if class == Class64 {
			order.PutUint64(b[0:], uint64(e.tag))
			order.PutUint64(b[8:], e.val)
		} else {
			order.PutUint32(b[0:], uint32(e.tag))
			order.PutUint32(b[4:], uint32(e.val))
		}
	}
	sec.Data = buf
	sec.Size = uint64(len(buf))
	sec.Entsize = uint64(ent)
}

// ---- SHT_RELR ------------------------------------------------------------

func decodeRelr(sec *Section, class Class, order binary.ByteOrder) ([]uint64, error) {
	word := 4
	if class == Class64 {
		word = 8
	}
	if len(sec.Data)%word != 0 {
		return nil, errf("relative relocation section %q has bad size %d", sec.Name, len(sec.Data))
	}
	out := make([]uint64, 0, len(sec.Data)/word)
	for off := 0; off < len(sec.Data); off += word {
		if class == Class64 {
			out = append(out, order.Uint64(sec.Data[off:]))
		} else {
			out = append(out, uint64(order.Uint32(sec.Data[off:])))
		}
	}
	return out, nil
}

func encodeRelr(sec *Section, entries []uint64, class Class, order binary.ByteOrder) {
	word := 4
	if class == Class64 {
		word = 8
	}
	buf := make([]byte, len(entries)*word)
	for i, v := range entries {
		if class == Class64 {
			order.PutUint64(buf[i*word:], v)
		} else {
			order.PutUint32(buf[i*word:], uint32(v))
		}
	}
	sec.Data = buf
	sec.Size = uint64(len(buf))
	sec.Entsize = uint64(word)
}

// ---- SHT_GNU_HASH --------------------------------------------------------

// decodeGNUHash splits a .gnu.hash section into its fixed header, the Bloom
// filter words (whose width follows the class) and the class-independent
// bucket/chain arrays.
func decodeGNUHash(sec *Section, class Class, order binary.ByteOrder) (savedGNUHash, error) {
	h := savedGNUHash{sec: sec}
	if len(sec.Data) < 16 {
		return h, errf("GNU hash section %q is truncated", sec.Name)
	}
	copy(h.header[:], sec.Data[:16])
	h.bloomSize = order.Uint32(sec.Data[8:])
	word := uint64(4)
	if class == Class64 {
		word = 8
	}
	bloomBytes := uint64(h.bloomSize) * word
	if bloomBytes > uint64(len(sec.Data)-16) {
		return h, errf("GNU hash section %q is truncated", sec.Name)
	}
	h.bloom = make([]uint64, h.bloomSize)
	for i := range h.bloom {
		if class == Class64 {
			h.bloom[i] = order.Uint64(sec.Data[16+uint64(i)*8:])
		} else {
			h.bloom[i] = uint64(order.Uint32(sec.Data[16+uint64(i)*4:]))
		}
	}
	h.rest = append([]byte(nil), sec.Data[16+bloomBytes:]...)
	return h, nil
}

// encodeGNUHash re-emits the header and Bloom filter for the output class.
// Going 64->32 hashes each 64-bit Bloom word into two 32-bit words (word i
// becomes words 2i and 2i+1, which preserves lookups because the Bloom index
// is hash/wordbits modulo the number of words); going 32->64 does the reverse.
func encodeGNUHash(h savedGNUHash, class Class, order binary.ByteOrder) {
	var bloom []uint64
	var bloomSize uint32
	if class == Class64 {
		if h.bloomSize%2 != 0 {
			// Cannot be represented without recomputing the hashes; leave
			// the section untouched rather than corrupting it.
			return
		}
		bloomSize = h.bloomSize / 2
		bloom = make([]uint64, bloomSize)
		for i := range bloom {
			bloom[i] = h.bloom[2*i] | h.bloom[2*i+1]<<32
		}
	} else {
		bloomSize = h.bloomSize * 2
		bloom = make([]uint64, bloomSize)
		for i, w := range h.bloom {
			bloom[2*i] = w & math.MaxUint32
			bloom[2*i+1] = w >> 32
		}
	}
	word := 4
	if class == Class64 {
		word = 8
	}
	buf := make([]byte, 16+len(bloom)*word+len(h.rest))
	copy(buf[:16], h.header[:])
	order.PutUint32(buf[8:], bloomSize)
	for i, w := range bloom {
		if class == Class64 {
			order.PutUint64(buf[16+i*8:], w)
		} else {
			order.PutUint32(buf[16+i*4:], uint32(w))
		}
	}
	copy(buf[16+len(bloom)*word:], h.rest)
	h.sec.Data = buf
	h.sec.Size = uint64(len(buf))
}
