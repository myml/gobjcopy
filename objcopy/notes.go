package objcopy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/myml/gobjcopy/elf"
)

// init registers note merging with the Transform pipeline. The hook runs after
// section renames and after --add-section/--update-section have been applied,
// which is where GNU objcopy merges notes while copying section contents.
func init() {
	noteMerge = mergeNotesStep
}

// mergeNotesStep is the Transform hook for --merge-notes. Notes are merged
// only when the caller asked for it: GNU objcopy 2.44 does not merge notes by
// default (that default belongs to GNU strip, not objcopy).
func mergeNotesStep(f *elf.File, cfg *Config) error {
	if f == nil {
		return nil
	}
	if cfg == nil {
		cfg = Default()
	}
	if cfg.MergeNotes == nil || !*cfg.MergeNotes {
		return nil
	}
	return MergeNotesWithWarn(f, cfg.warnf)
}

// MergeNotes merges the notes in every GNU build attribute section of f,
// removing redundant entries. It implements the --merge-notes phase of GNU
// objcopy: sections whose name starts with ".gnu.build.attributes" are
// rewritten in the version 3 layout, duplicate or overlapping attribute notes
// are dropped, and a note that repeats the previous note's address range is
// emitted with a zero-length descriptor.
//
// Only version 3 notes can be merged; version 1 and 2 sections are left
// untouched, matching BFD's merge_gnu_build_notes() caller. Sections carrying
// relocations against them are skipped as well, since their contents cannot be
// decoded without applying those relocations first.
//
// MergeNotes returns nil when a section cannot be merged for a non-fatal
// reason; malformed build attribute notes are reported as errors.
func MergeNotes(f *elf.File) error {
	return MergeNotesWithWarn(f, nil)
}

// MergeNotesWithWarn is MergeNotes with a diagnostic sink. warnf may be nil.
// It mirrors GNU's non_fatal() messages for skipped sections and for sections
// that lack a version note.
func MergeNotesWithWarn(f *elf.File, warnf func(format string, args ...any)) error {
	if f == nil {
		return fmt.Errorf("objcopy: nil ELF file")
	}
	if warnf == nil {
		warnf = func(string, ...any) {}
	}
	for i, sec := range f.Sections {
		if sec.Type != elf.SHT_NOTE {
			continue
		}
		if !strings.HasPrefix(sec.Name, elf.GNU_BUILD_ATTRS_SECTION_NAME) {
			continue
		}
		if len(sec.Data) == 0 {
			// Happens when a binary is stripped twice; nothing to merge.
			continue
		}
		if hasRelocations(f, i) {
			warnf("%s[%s]: Cannot merge - there are relocations against this section",
				f.Path, sec.Name)
			continue
		}
		merged, err := mergeGNUBuildNotes(f.Class, f.Data.Order(), sec.Data,
			warnf, f.Path+"["+sec.Name+"]")
		if err != nil {
			return err
		}
		if len(merged) < len(sec.Data) {
			sec.Data = merged
			sec.Size = uint64(len(merged))
		}
	}
	return nil
}

// NoteSectionType reports the section type that BFD assigns to a newly created
// section with the given name: GNU's special section table maps names that
// start with ".note" to SHT_NOTE, except for ".note.GNU-stack", which stays
// SHT_PROGBITS. The second result is false when no special mapping applies, in
// which case callers should keep their default type.
//
// objcopy's --add-section creates its section through BFD, so GNU's
//
//	objcopy --add-section .note=file in out
//
// produces an SHT_NOTE section. Callers that synthesise sections themselves
// can use this helper to reproduce that behaviour.
func NoteSectionType(name string) (uint32, bool) {
	if name == ".note.GNU-stack" {
		return elf.SHT_PROGBITS, true
	}
	if strings.HasPrefix(name, ".note") {
		return elf.SHT_NOTE, true
	}
	return 0, false
}

// hasRelocations reports whether the section at index idx has a SHT_REL or
// SHT_RELA section applying to it.
func hasRelocations(f *elf.File, idx int) bool {
	for _, s := range f.Sections {
		if s.Type != elf.SHT_REL && s.Type != elf.SHT_RELA {
			continue
		}
		if int(s.Info) == idx && len(s.Data) > 0 {
			return true
		}
	}
	return false
}

// gnuBuildNote is the internal form of one GNU build attribute note, with the
// address range decoded from the descriptor.
type gnuBuildNote struct {
	name []byte
	typ  uint32
	// start and end are the absolute addresses the note applies to, after
	// inheriting missing values from the previous note of the same kind.
	start uint64
	end   uint64
}

// mergeGNUBuildNotes is a transliteration of merge_gnu_build_notes() from
// binutils' objcopy.c. It returns the new section contents; when the notes do
// not need changing (or cannot be merged because they are not version 3) the
// input slice is returned unchanged.
func mergeGNUBuildNotes(class elf.Class, order binary.ByteOrder, data []byte,
	warnf func(string, ...any), where string) ([]byte, error) {
	notes, version1, version2, version3, err := parseGNUBuildNotes(order, data, where)
	if err != nil {
		return nil, err
	}

	// A zero-length descriptor means "same range as the previous note".
	var previousOpenStart, previousOpenEnd, previousFuncStart, previousFuncEnd uint64
	for i := range notes {
		n := &notes[i]
		if n.typ == elf.NT_GNU_BUILD_ATTRIBUTE_OPEN {
			if n.start != 0 {
				previousOpenStart = n.start
			}
			n.start = previousOpenStart
			if n.end != 0 {
				previousOpenEnd = n.end
			}
			n.end = previousOpenEnd
		} else {
			if n.start != 0 {
				previousFuncStart = n.start
			}
			n.start = previousFuncStart
			if n.end != 0 {
				previousFuncEnd = n.end
			}
			n.end = previousFuncEnd
		}
	}

	if version1 == 0 && version2 == 0 && version3 == 0 {
		// This happens with glibc binaries; BFD assumes version 3.
		warnf("%s: Warning: version note missing - assuming version 3", where)
		version3 = 2
	}
	if (version1 > 0 && version2 > 0) || (version1 > 0 && version3 > 0) ||
		(version2 > 0 && version3 > 0) {
		return nil, fmt.Errorf("%s: bad GNU build attribute notes: multiple different versions", where)
	}
	if version3 == 0 {
		// Only version 3 notes can be merged; leave the section alone.
		return data, nil
	}

	// Sort the notes so that equal attributes are adjacent and ranges are
	// ordered; this is compare_gnu_build_notes() from objcopy.c.
	sort.SliceStable(notes, func(i, j int) bool {
		return compareGNUBuildNotes(&notes[i], &notes[j]) < 0
	})

	// Rule 1: delete zero-range notes.
	// Rule 2: delete notes whose name and range duplicate an earlier note,
	// notes fully contained in an earlier note with the same name, and merge
	// notes of the same kind whose ranges overlap or adjoin.
	prevNote := -1
	for i := range notes {
		pnote := &notes[i]
		if isDeletedNote(pnote) {
			continue
		}
		if pnote.start == pnote.end {
			pnote.typ = 0
			continue
		}
		back := i - 1
		if prevNote >= 0 {
			back = prevNote
		}
		iter := 0
		for ; back >= 0; back-- {
			prev := &notes[back]
			if isDeletedNote(prev) {
				continue
			}
			// Sorting puts all notes with the same attribute together, so
			// a different name ends the search.
			if len(prev.name) != len(pnote.name) || !bytes.Equal(prev.name, pnote.name) {
				break
			}
			if prev.start == pnote.start && prev.end == pnote.end {
				pnote.typ = 0
				break
			}
			if containedBy(pnote, prev) {
				pnote.typ = 0
				break
			}
			if overlapsOrAdjoins(prev, pnote) && isFuncNote(prev) == isFuncNote(pnote) {
				prev.end = maxU64(prev.end, pnote.end)
				prev.start = minU64(prev.start, pnote.start)
				pnote.typ = 0
				break
			}
			// Do not scan too far back (GNU's iteration limit).
			if iter > 16 {
				break
			}
			iter++
		}
		if !isDeletedNote(pnote) {
			prevNote = i
		}
	}

	// sort_gnu_build_notes(): open notes first, then by start address, then
	// by descending end address, then by attribute id.
	sort.SliceStable(notes, func(i, j int) bool {
		return compareFinalGNUBuildNotes(&notes[i], &notes[j]) < 0
	})

	// Rebuild the section. Notes that repeat the previous range use a
	// zero-length descriptor; everything else records the full range.
	var out []byte
	var prevStart, prevEnd uint64
	for i := range notes {
		n := &notes[i]
		if isDeletedNote(n) {
			continue
		}
		if n.start == prevStart && n.end == prevEnd {
			out = appendNoteHeader(out, order, uint32(len(n.name)), 0, n.typ)
			out = append(out, n.name...)
			out = appendNamePadding(out, n.name)
			continue
		}
		descsz := uint32(8)
		if class == elf.Class64 {
			descsz = 16
		}
		out = appendNoteHeader(out, order, uint32(len(n.name)), descsz, n.typ)
		out = append(out, n.name...)
		out = appendNamePadding(out, n.name)
		var desc [16]byte
		if class == elf.Class64 {
			order.PutUint64(desc[0:], n.start)
			order.PutUint64(desc[8:], n.end)
			out = append(out, desc[:16]...)
		} else {
			order.PutUint32(desc[0:], uint32(n.start))
			order.PutUint32(desc[4:], uint32(n.end))
			out = append(out, desc[:8]...)
		}
		prevStart, prevEnd = n.start, n.end
	}
	if len(out) >= len(data) {
		// GNU only installs the merged contents when they are smaller.
		return data, nil
	}
	return out, nil
}

// parseGNUBuildNotes decodes a GNU build attribute section into notes and
// counts the format versions that appear in it. The error messages match the
// diagnostics emitted by BFD/objcopy.
func parseGNUBuildNotes(order binary.ByteOrder, data []byte, where string) (notes []gnuBuildNote, version1, version2, version3 int, err error) {
	remain := uint64(len(data))
	in := uint64(0)
	for remain >= 12 {
		namesz := uint64(order.Uint32(data[in:]))
		descsz := uint64(order.Uint32(data[in+4:]))
		typ := order.Uint32(data[in+8:])
		paddedNamesz := (namesz + 3) &^ uint64(3)

		if descsz&3 != 0 {
			return nil, 0, 0, 0, fmt.Errorf("%s: corrupt GNU build attribute note: description size not a factor of 4", where)
		}
		if typ != elf.NT_GNU_BUILD_ATTRIBUTE_OPEN && typ != elf.NT_GNU_BUILD_ATTRIBUTE_FUNC {
			return nil, 0, 0, 0, fmt.Errorf("%s: corrupt GNU build attribute note: wrong note type", where)
		}
		if namesz < 2 {
			return nil, 0, 0, 0, fmt.Errorf("%s: corrupt GNU build attribute note: name too small", where)
		}
		noteSize := 12 + paddedNamesz + descsz
		if noteSize > remain {
			return nil, 0, 0, 0, fmt.Errorf("%s: corrupt GNU build attribute note: note too big", where)
		}

		name := data[in+12 : in+12+namesz]
		desc := data[in+12+paddedNamesz : in+12+paddedNamesz+descsz]
		remain -= noteSize
		in += noteSize

		switch {
		case namesz > 2 && name[0] == '$' &&
			name[1] == elf.GNU_BUILD_ATTRIBUTE_VERSION && name[2] == '1':
			version1++
		case namesz > 4 && name[0] == 'G' && name[1] == 'A' && name[2] == '$' &&
			name[3] == elf.GNU_BUILD_ATTRIBUTE_VERSION:
			switch name[4] {
			case '2':
				version2++
			case '3':
				version3++
			default:
				return nil, 0, 0, 0, fmt.Errorf("%s: corrupt GNU build attribute note: unsupported version", where)
			}
		}

		var start, end uint64
		switch descsz {
		case 0:
		case 4:
			start = uint64(order.Uint32(desc))
			// Version 1 and 2 notes do not record an end address; GNU uses
			// an artificially large one because gaps were not supported.
			end = ^uint64(0)
		case 8:
			start = uint64(order.Uint32(desc))
			end = uint64(order.Uint32(desc[4:]))
		case 16:
			start = order.Uint64(desc)
			end = order.Uint64(desc[8:])
		default:
			return nil, 0, 0, 0, fmt.Errorf("%s: corrupt GNU build attribute note: bad description size", where)
		}
		if start > end {
			// PPC64LE encodes empty notes as start = end + 4.
			start = end
		}
		if name[namesz-1] != 0 {
			return nil, 0, 0, 0, fmt.Errorf("%s: corrupt GNU build attribute note: name not NUL terminated", where)
		}

		notes = append(notes, gnuBuildNote{name: name, typ: typ, start: start, end: end})
	}
	if remain != 0 {
		return nil, 0, 0, 0, fmt.Errorf("%s: corrupt GNU build attribute notes: excess data at end", where)
	}
	return notes, version1, version2, version3, nil
}

func appendNoteHeader(out []byte, order binary.ByteOrder, namesz, descsz, typ uint32) []byte {
	var hdr [12]byte
	order.PutUint32(hdr[0:], namesz)
	order.PutUint32(hdr[4:], descsz)
	order.PutUint32(hdr[8:], typ)
	return append(out, hdr[:]...)
}

// appendNamePadding appends the NUL padding that aligns a note name to four
// bytes, as merge_gnu_build_notes() does.
func appendNamePadding(out, name []byte) []byte {
	for i := len(name); i%4 != 0; i++ {
		out = append(out, 0)
	}
	return out
}

// compareGNUBuildNotes orders notes by attribute name, then by address range
// with earlier ranges first, then open notes before function notes. It matches
// compare_gnu_build_notes() in objcopy.c.
func compareGNUBuildNotes(a, b *gnuBuildNote) int {
	n := len(a.name)
	if len(b.name) < n {
		n = len(b.name)
	}
	if n > 3 {
		if cmp := bytes.Compare(a.name[3:n], b.name[3:n]); cmp != 0 {
			return cmp
		}
	}
	switch {
	case a.end < b.start:
		return -1
	case a.start > b.end:
		return 1
	case a.start < b.start:
		return -1
	case a.end > b.end:
		return 1
	case a.end < b.end:
		return -1
	}
	aOpen := a.typ == elf.NT_GNU_BUILD_ATTRIBUTE_OPEN
	bOpen := b.typ == elf.NT_GNU_BUILD_ATTRIBUTE_OPEN
	switch {
	case aOpen && !bOpen:
		return -1
	case !aOpen && bOpen:
		return 1
	}
	return 0
}

// compareFinalGNUBuildNotes orders notes for output: open notes before
// function notes before deleted notes, then by start address, then by
// descending end address, then by attribute id. It matches
// sort_gnu_build_notes() in objcopy.c.
func compareFinalGNUBuildNotes(a, b *gnuBuildNote) int {
	if a.typ != b.typ {
		if isDeletedNote(a) {
			return 1
		}
		if a.typ == elf.NT_GNU_BUILD_ATTRIBUTE_OPEN {
			return -1
		}
		if isDeletedNote(b) {
			return -1
		}
		return 1
	}
	switch {
	case a.start < b.start:
		return -1
	case a.start > b.start:
		return 1
	case a.end > b.end:
		return -1
	case a.end < b.end:
		return 1
	}
	if len(a.name) > 4 && len(b.name) > 4 && a.name[3] != b.name[3] {
		return int(a.name[3]) - int(b.name[3])
	}
	return 0
}

func isDeletedNote(n *gnuBuildNote) bool { return n.typ == 0 }

func isFuncNote(n *gnuBuildNote) bool {
	return n.typ == elf.NT_GNU_BUILD_ATTRIBUTE_FUNC
}

func containedBy(needle, haystack *gnuBuildNote) bool {
	return needle.start >= haystack.start && needle.end <= haystack.end
}

// overlapsOrAdjoins mirrors overlaps_or_adjoins() in objcopy.c, including its
// treatment of 16-byte alignment as the boundary of an adjoining range. The
// second test intentionally compares b with itself, as GNU does.
func overlapsOrAdjoins(a, b *gnuBuildNote) bool {
	if a.end < b.start {
		return bfdAlign(a.end, 16) < b.start
	}
	if b.end < b.start {
		return bfdAlign(b.end, 16) < a.start
	}
	if a.end < b.end {
		return true
	}
	if b.end < a.end {
		return true
	}
	return false
}

func bfdAlign(v, a uint64) uint64 {
	return (v + a - 1) &^ (a - 1)
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
