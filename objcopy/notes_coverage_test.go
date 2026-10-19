package objcopy

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

// ---- helpers ------------------------------------------------------------

func ntcHeads(order binary.ByteOrder, namesz, descsz, typ uint32) []byte {
	b := make([]byte, 12)
	order.PutUint32(b[0:], namesz)
	order.PutUint32(b[4:], descsz)
	order.PutUint32(b[8:], typ)
	return b
}

// ntcNote builds a well-formed build attribute note with four-byte name
// padding.
func ntcNote(order binary.ByteOrder, name, desc []byte, typ uint32) []byte {
	b := make([]byte, 12)
	order.PutUint32(b[0:], uint32(len(name)))
	order.PutUint32(b[4:], uint32(len(desc)))
	order.PutUint32(b[8:], typ)
	b = append(b, name...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	b = append(b, desc...)
	return b
}

func ntcDesc16(order binary.ByteOrder, start, end uint64) []byte {
	b := make([]byte, 16)
	order.PutUint64(b[0:], start)
	order.PutUint64(b[8:], end)
	return b
}

func ntcDesc8(order binary.ByteOrder, start, end uint32) []byte {
	b := make([]byte, 8)
	order.PutUint32(b[0:], start)
	order.PutUint32(b[4:], end)
	return b
}

func ntcDesc4(order binary.ByteOrder, start uint32) []byte {
	b := make([]byte, 4)
	order.PutUint32(b[0:], start)
	return b
}

func ntcAppend(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func ntcSilent(string, ...any) {}

// ntcRawNote is one decoded output note, kept in raw form so that a
// zero-length descriptor is visible.
type ntcRawNote struct {
	name   []byte
	descsz uint32
	typ    uint32
}

// ntcScanOutput walks merged section contents without validating them.
func ntcScanOutput(order binary.ByteOrder, data []byte) []ntcRawNote {
	var out []ntcRawNote
	for off := 0; off+12 <= len(data); {
		namesz := int(order.Uint32(data[off:]))
		descsz := int(order.Uint32(data[off+4:]))
		typ := order.Uint32(data[off+8:])
		nameEnd := off + 12 + namesz
		if nameEnd > len(data) {
			break
		}
		name := data[off+12 : nameEnd]
		descOff := (nameEnd + 3) &^ 3
		next := (descOff + descsz + 3) &^ 3
		if descOff+descsz > len(data) || next > len(data) {
			break
		}
		out = append(out, ntcRawNote{name: name, descsz: uint32(descsz), typ: typ})
		off = next
	}
	return out
}

// ---- step and diagnostics ----------------------------------------------

func TestNotesCoverageStep(t *testing.T) {
	if err := mergeNotesStep(nil, nil); err != nil {
		t.Fatalf("mergeNotesStep(nil): %v", err)
	}
	f := &elf.File{Header: elf.Header{Class: elf.Class64, Data: elf.DataLSB}}

	// A nil Config must be tolerated and behaves like the default.
	if err := mergeNotesStep(f, nil); err != nil {
		t.Fatalf("mergeNotesStep(nil cfg): %v", err)
	}
	// nil MergeNotes is the "not requested" case.
	if err := mergeNotesStep(f, Default()); err != nil {
		t.Fatalf("mergeNotesStep(default): %v", err)
	}
	no := false
	cfg := Default()
	cfg.MergeNotes = &no
	if err := mergeNotesStep(f, cfg); err != nil {
		t.Fatalf("mergeNotesStep(false): %v", err)
	}
	yes := true
	cfg = Default()
	cfg.MergeNotes = &yes
	cfg.Warnf = func(string, ...any) {}
	if err := mergeNotesStep(f, cfg); err != nil {
		t.Fatalf("mergeNotesStep(true): %v", err)
	}

	if err := MergeNotesWithWarn(nil, nil); err == nil {
		t.Error("MergeNotesWithWarn(nil) succeeded, want error")
	}
}

// ---- parsing ------------------------------------------------------------

func TestNotesCoverageParseGNU(t *testing.T) {
	o := binary.LittleEndian
	v3 := []byte("GA$\x013p1\x00")
	v2 := []byte("GA$\x012p1\x00")
	v1 := []byte{'$', 1, '1', 0}
	open := uint32(elf.NT_GNU_BUILD_ATTRIBUTE_OPEN)
	funcType := uint32(elf.NT_GNU_BUILD_ATTRIBUTE_FUNC)

	descSizes := ntcAppend(
		ntcNote(o, v3, ntcDesc16(o, 0x100, 0x110), open),
		ntcNote(o, []byte("GA+\x02\x00"), ntcDesc16(o, 0x100, 0x110), open),
		ntcNote(o, []byte("GA!\x02\x00"), ntcDesc8(o, 0x100, 0x104), funcType),
		ntcNote(o, []byte("GA*\x07\x00\x00"), ntcDesc4(o, 0x100), open),
		ntcNote(o, []byte("GA$\x05gcc\x00"), nil, open),
	)
	startAfterEnd := ntcNote(o, v3, ntcDesc16(o, 0x200, 0x100), open)
	excess := ntcAppend(ntcNote(o, []byte{0, 0}, nil, open), []byte{1, 2, 3, 4})

	tests := []struct {
		name      string
		data      []byte
		wantNotes int
		wantV1    int
		wantV2    int
		wantV3    int
		wantErr   string
	}{
		{"empty", nil, 0, 0, 0, 0, ""},
		{"description-sizes", descSizes, 5, 0, 0, 1, ""},
		{"version1", ntcNote(o, v1, ntcDesc4(o, 0x10), open), 1, 1, 0, 0, ""},
		{"version2", ntcNote(o, v2, ntcDesc8(o, 0x100, 0x110), funcType), 1, 0, 1, 0, ""},
		{"start-after-end", startAfterEnd, 1, 0, 0, 1, ""},
		{"unsupported-version",
			ntcNote(o, []byte("GA$\x019p1\x00"), ntcDesc8(o, 0x100, 0x110), open),
			0, 0, 0, 0, "unsupported version"},
		{"name-too-small",
			ntcHeads(o, 1, 0, open), 0, 0, 0, 0, "name too small"},
		{"note-too-big",
			ntcHeads(o, 4, 0, open), 0, 0, 0, 0, "note too big"},
		{"description-not-factor-of-4",
			ntcAppend(ntcHeads(o, 4, 2, open), []byte("GNU\x00")),
			0, 0, 0, 0, "description size not a factor of 4"},
		{"wrong-note-type",
			ntcAppend(ntcHeads(o, 2, 0, 3), []byte{0, 0, 0, 0}),
			0, 0, 0, 0, "wrong note type"},
		{"bad-description-size",
			ntcAppend(ntcHeads(o, 4, 12, open), []byte("GNU\x00"), make([]byte, 12)),
			0, 0, 0, 0, "bad description size"},
		{"name-not-nul-terminated",
			ntcAppend(ntcHeads(o, 4, 16, open), []byte("ABCX"), make([]byte, 16)),
			0, 0, 0, 0, "name not NUL terminated"},
		{"excess-data", excess, 0, 0, 0, 0, "excess data at end"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			notes, v1, v2, v3, err := parseGNUBuildNotes(o, tc.data, "cov")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGNUBuildNotes: %v", err)
			}
			if len(notes) != tc.wantNotes || v1 != tc.wantV1 || v2 != tc.wantV2 || v3 != tc.wantV3 {
				t.Errorf("got %d notes (v1=%d v2=%d v3=%d), want %d (v1=%d v2=%d v3=%d)",
					len(notes), v1, v2, v3, tc.wantNotes, tc.wantV1, tc.wantV2, tc.wantV3)
			}
			if tc.name == "start-after-end" {
				if notes[0].start != 0x100 || notes[0].end != 0x100 {
					t.Errorf("start/end = %#x/%#x, want both 0x100", notes[0].start, notes[0].end)
				}
			}
		})
	}
}

// ---- versions and merge rules ------------------------------------------

func TestNotesCoverageMergeVersions(t *testing.T) {
	o := binary.LittleEndian
	v1 := []byte{'$', 1, '1', 0}
	v2 := []byte("GA$\x012p1\x00")
	v3 := []byte("GA$\x013p1\x00")
	open := uint32(elf.NT_GNU_BUILD_ATTRIBUTE_OPEN)

	// Version 1 and version 3 notes cannot be mixed.
	mixed := ntcAppend(
		ntcNote(o, v1, ntcDesc4(o, 0x10), open),
		ntcNote(o, v3, ntcDesc16(o, 0x100, 0x110), open),
	)
	if _, err := mergeGNUBuildNotes(elf.Class64, o, mixed, ntcSilent, "cov"); err == nil ||
		!strings.Contains(err.Error(), "multiple different versions") {
		t.Fatalf("mixed versions error = %v", err)
	}

	// Version 2 notes cannot be merged and are returned untouched.
	v2only := ntcNote(o, v2, ntcDesc8(o, 0x100, 0x110), open)
	out, err := mergeGNUBuildNotes(elf.Class64, o, v2only, ntcSilent, "cov")
	if err != nil {
		t.Fatalf("version 2 merge: %v", err)
	}
	if !bytes.Equal(out, v2only) {
		t.Errorf("version 2 notes were modified")
	}

	// Version 1 notes alone are also left untouched.
	v1only := ntcNote(o, v1, ntcDesc4(o, 0x10), open)
	out, err = mergeGNUBuildNotes(elf.Class64, o, v1only, ntcSilent, "cov")
	if err != nil {
		t.Fatalf("version 1 merge: %v", err)
	}
	if !bytes.Equal(out, v1only) {
		t.Errorf("version 1 notes were modified")
	}

	// A parse error is propagated.
	if _, err := mergeGNUBuildNotes(elf.Class64, o, ntcHeads(o, 4, 2, open), ntcSilent, "cov"); err == nil {
		t.Error("malformed section was merged without error")
	}
}

func TestNotesCoverageMergeRules(t *testing.T) {
	o := binary.LittleEndian
	v3 := []byte("GA$\x013p1\x00")
	bName := []byte("GA+\x02\x00") // open attributes named b
	cName := []byte("GA!\x03\x00") // open attributes named c
	dName := []byte("GA*\x07\x00\x00")
	open := uint32(elf.NT_GNU_BUILD_ATTRIBUTE_OPEN)

	data := ntcAppend(
		ntcNote(o, v3, ntcDesc16(o, 0x100, 0x130), open),
		// Rule 1: an empty range is deleted.
		ntcNote(o, bName, ntcDesc16(o, 0x100, 0x100), open),
		// Rule 2b: b2 and b3 adjoin and are merged.
		ntcNote(o, bName, ntcDesc16(o, 0x100, 0x104), open),
		ntcNote(o, bName, ntcDesc16(o, 0x104, 0x108), open),
		// Rule 2: exact duplicate of b2.
		ntcNote(o, bName, ntcDesc16(o, 0x100, 0x104), open),
		// Rule 2a: contained by the merged b2 range.
		ntcNote(o, bName, ntcDesc16(o, 0x100, 0x108), open),
		// The c group exercises the scan over a previously deleted note.
		// The two ranges are less than 16 bytes apart, which GNU's
		// overlaps_or_adjoins() deliberately does not treat as mergeable.
		ntcNote(o, cName, ntcDesc16(o, 0x100, 0x100), open),
		ntcNote(o, cName, ntcDesc16(o, 0x100, 0x104), open),
		ntcNote(o, cName, ntcDesc16(o, 0x110, 0x114), open),
		// A different attribute with the same final range as b2, which
		// triggers the zero-length descriptor shorthand.
		ntcNote(o, dName, ntcDesc16(o, 0x100, 0x108), open),
	)

	out, err := mergeGNUBuildNotes(elf.Class64, o, data, ntcSilent, "cov")
	if err != nil {
		t.Fatalf("mergeGNUBuildNotes: %v", err)
	}
	if len(out) >= len(data) {
		t.Fatalf("merged size %d did not shrink from %d", len(out), len(data))
	}
	notes := ntcScanOutput(o, out)
	if len(notes) != 5 {
		t.Fatalf("merged to %d notes, want 5: %+v out=%x", len(notes), notes, out)
	}
	counts := map[string]int{}
	zeroDesc := 0
	for _, n := range notes {
		counts[string(n.name)]++
		if n.descsz == 0 {
			zeroDesc++
		}
	}
	if counts[string(v3)] != 1 || counts[string(bName)] != 1 ||
		counts[string(cName)] != 2 || counts[string(dName)] != 1 {
		t.Errorf("kept notes = %v", counts)
	}
	if zeroDesc != 1 {
		t.Errorf("zero-length descriptors = %d, want 1", zeroDesc)
	}
}

func TestNotesCoverageMergeNoGrow(t *testing.T) {
	o := binary.LittleEndian
	// A four-byte descriptor is rewritten as a 16-byte range, so the merged
	// form is larger and the original section must be kept.
	data := ntcNote(o, []byte("GA$\x013p1\x00"), ntcDesc4(o, 0x100), elf.NT_GNU_BUILD_ATTRIBUTE_OPEN)
	out, err := mergeGNUBuildNotes(elf.Class64, o, data, ntcSilent, "cov")
	if err != nil {
		t.Fatalf("mergeGNUBuildNotes: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("section changed even though its merged form is larger")
	}

	// The same note in a 32-bit object keeps its 8-byte descriptor.
	desc32 := ntcDesc8(o, 0x100, 0x104)
	data32 := ntcNote(o, []byte("GA$\x013p1\x00"), desc32, elf.NT_GNU_BUILD_ATTRIBUTE_OPEN)
	if _, err := mergeGNUBuildNotes(elf.Class32, o, data32, ntcSilent, "cov"); err != nil {
		t.Fatalf("mergeGNUBuildNotes(32-bit): %v", err)
	}
}

func TestNotesCoverageVersionWarning(t *testing.T) {
	o := binary.LittleEndian
	data := ntcAppend(
		ntcNote(o, []byte("GA+\x02\x00"), ntcDesc16(o, 0x100, 0x104), elf.NT_GNU_BUILD_ATTRIBUTE_OPEN),
		ntcNote(o, []byte("GA+\x02\x00"), ntcDesc16(o, 0x100, 0x104), elf.NT_GNU_BUILD_ATTRIBUTE_OPEN),
	)
	var warnings []string
	out, err := mergeGNUBuildNotes(elf.Class64, o, data,
		func(format string, args ...any) { warnings = append(warnings, format) }, "cov")
	if err != nil {
		t.Fatalf("mergeGNUBuildNotes: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "version note missing") {
		t.Errorf("warnings = %v", warnings)
	}
	if len(out) >= len(data) {
		t.Errorf("notes without a version note were not merged")
	}
}

// ---- comparators, overlap helpers --------------------------------------

func TestNotesCoverageCompareGNUBuildNotes(t *testing.T) {
	open := uint32(elf.NT_GNU_BUILD_ATTRIBUTE_OPEN)
	fn := uint32(elf.NT_GNU_BUILD_ATTRIBUTE_FUNC)
	name := []byte("GA+\x02\x00")
	n := func(name []byte, typ uint32, start, end uint64) *gnuBuildNote {
		return &gnuBuildNote{name: name, typ: typ, start: start, end: end}
	}
	less := func(a, b *gnuBuildNote) bool { return compareGNUBuildNotes(a, b) < 0 }
	greater := func(a, b *gnuBuildNote) bool { return compareGNUBuildNotes(a, b) > 0 }

	// Attribute name comparison: the bytes after the "GA*" style prefix.
	if !less(n([]byte("GA+\x02\x00"), open, 0x100, 0x200), n([]byte("GA+\x03\x00"), open, 0x100, 0x200)) {
		t.Error("different attributes did not compare by name")
	}
	// A shorter name is compared over the common prefix only.
	if got := compareGNUBuildNotes(n([]byte("GA+\x02\x00"), open, 0, 0), n([]byte("GA+\x02\x00EXTRA"), open, 0, 0)); got != 0 {
		t.Errorf("equal prefixes compared as %d", got)
	}
	// Names too short to contain an attribute id skip the memcmp.
	if got := compareGNUBuildNotes(n([]byte{0, 0}, open, 0x100, 0x104), n([]byte{0, 0}, open, 0x100, 0x104)); got != 0 {
		t.Errorf("short equal names compared as %d", got)
	}

	cases := []struct {
		name string
		a, b *gnuBuildNote
		want int
	}{
		{"disjoint-before", n(name, open, 0x100, 0x104), n(name, open, 0x200, 0x204), -1},
		{"disjoint-after", n(name, open, 0x300, 0x304), n(name, open, 0x200, 0x204), 1},
		{"earlier-start", n(name, open, 0x100, 0x200), n(name, open, 0x150, 0x250), -1},
		{"bigger-end", n(name, open, 0x200, 0x300), n(name, open, 0x150, 0x250), 1},
		{"smaller-end", n(name, open, 0x200, 0x250), n(name, open, 0x150, 0x300), -1},
		{"open-before-func", n(name, open, 0x100, 0x200), n(name, fn, 0x100, 0x200), -1},
		{"func-after-open", n(name, fn, 0x100, 0x200), n(name, open, 0x100, 0x200), 1},
		{"equal", n(name, open, 0x100, 0x200), n(name, open, 0x100, 0x200), 0},
	}
	for _, tc := range cases {
		if got := compareGNUBuildNotes(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: compare = %d, want %d", tc.name, got, tc.want)
		}
	}

	// Spot-check strict ordering helpers used by sort.SliceStable.
	if !less(n(name, open, 0x100, 0x104), n(name, open, 0x200, 0x204)) ||
		!greater(n(name, open, 0x300, 0x304), n(name, open, 0x200, 0x204)) {
		t.Error("comparator ordering helpers")
	}
}

func TestNotesCoverageCompareFinalGNUBuildNotes(t *testing.T) {
	open := uint32(elf.NT_GNU_BUILD_ATTRIBUTE_OPEN)
	fn := uint32(elf.NT_GNU_BUILD_ATTRIBUTE_FUNC)
	name := []byte("GA+\x02\x00")
	n := func(name []byte, typ uint32, start, end uint64) *gnuBuildNote {
		return &gnuBuildNote{name: name, typ: typ, start: start, end: end}
	}
	cases := []struct {
		name string
		a, b *gnuBuildNote
		want int
	}{
		{"deleted-after", n(name, 0, 0, 0), n(name, open, 0x100, 0x200), 1},
		{"open-before-func", n(name, open, 0x100, 0x200), n(name, fn, 0x100, 0x200), -1},
		{"func-before-deleted", n(name, fn, 0x100, 0x200), n(name, 0, 0, 0), -1},
		{"func-after-open", n(name, fn, 0x100, 0x200), n(name, open, 0x100, 0x200), 1},
		{"start-before", n(name, open, 0x100, 0x200), n(name, open, 0x200, 0x300), -1},
		{"start-after", n(name, open, 0x300, 0x400), n(name, open, 0x200, 0x300), 1},
		{"bigger-range-first", n(name, open, 0x100, 0x300), n(name, open, 0x100, 0x200), -1},
		{"smaller-range-later", n(name, open, 0x100, 0x200), n(name, open, 0x100, 0x300), 1},
		{"attribute-id-order", n([]byte("GA+\x02\x00"), open, 0x100, 0x200), n([]byte("GA+\x05\x00"), open, 0x100, 0x200), -3},
		{"short-names-equal", n([]byte{0, 0}, open, 0x100, 0x200), n([]byte{0, 0}, open, 0x100, 0x200), 0},
	}
	for _, tc := range cases {
		if got := compareFinalGNUBuildNotes(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: compare = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestNotesCoverageOverlapsOrAdjoins(t *testing.T) {
	open := uint32(elf.NT_GNU_BUILD_ATTRIBUTE_OPEN)
	n := func(start, end uint64) *gnuBuildNote {
		return &gnuBuildNote{name: []byte("GA+\x02\x00"), typ: open, start: start, end: end}
	}
	cases := []struct {
		name string
		a, b *gnuBuildNote
		want bool
	}{
		// Adjoining only within the 16-byte alignment window.
		{"aligned-adjoin", n(0x100, 0x104), n(0x110, 0x114), false},
		{"gap-after-alignment", n(0x100, 0x104), n(0x111, 0x114), true},
		// The second test compares b with itself, as GNU does; the branch is
		// only reachable when the range is inverted.
		{"inverted-b-far", n(0x100, 0x300), n(0x200, 0x100), false},
		{"inverted-b-near", n(0x110, 0x400), n(0x180, 0x100), true},
		{"b-extends", n(0x100, 0x200), n(0x150, 0x300), true},
		{"a-extends", n(0x100, 0x400), n(0x150, 0x300), true},
		{"identical", n(0x100, 0x200), n(0x100, 0x200), false},
	}
	for _, tc := range cases {
		if got := overlapsOrAdjoins(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: overlapsOrAdjoins = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNotesCoverageNumericHelpers(t *testing.T) {
	if got := bfdAlign(0, 16); got != 0 {
		t.Errorf("bfdAlign(0, 16) = %d", got)
	}
	if got := bfdAlign(1, 16); got != 16 {
		t.Errorf("bfdAlign(1, 16) = %d", got)
	}
	if got := bfdAlign(0x110, 16); got != 0x110 {
		t.Errorf("bfdAlign(0x110, 16) = %d", got)
	}
	if got := maxU64(5, 3); got != 5 {
		t.Errorf("maxU64(5, 3) = %d", got)
	}
	if got := maxU64(3, 5); got != 5 {
		t.Errorf("maxU64(3, 5) = %d", got)
	}
	if got := minU64(3, 5); got != 3 {
		t.Errorf("minU64(3, 5) = %d", got)
	}
	if got := minU64(5, 3); got != 3 {
		t.Errorf("minU64(5, 3) = %d", got)
	}
	if !containedBy(&gnuBuildNote{start: 0x104, end: 0x108}, &gnuBuildNote{start: 0x100, end: 0x110}) {
		t.Error("containedBy rejected a contained range")
	}
	if !isFuncNote(&gnuBuildNote{typ: elf.NT_GNU_BUILD_ATTRIBUTE_FUNC}) {
		t.Error("isFuncNote rejected a function note")
	}
	if !isDeletedNote(&gnuBuildNote{}) {
		t.Error("isDeletedNote rejected a deleted note")
	}
}
