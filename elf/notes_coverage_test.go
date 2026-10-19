package elf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ntcNoteEntry builds one note entry with the 4-byte name alignment used by
// SHT_NOTE sections.
func ntcNoteEntry(order binary.ByteOrder, name, desc []byte, typ uint32) []byte {
	out := make([]byte, 12)
	order.PutUint32(out[0:], uint32(len(name)))
	order.PutUint32(out[4:], uint32(len(desc)))
	order.PutUint32(out[8:], typ)
	out = append(out, name...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	out = append(out, desc...)
	return out
}

// TestNotesCoverageParseAlignment exercises the alignment clamping and
// rejection paths of ParseNotes, including the descriptor-offset bounds check
// that only triggers when the name fits but its padding does not.
func TestNotesCoverageParseAlignment(t *testing.T) {
	order := binary.LittleEndian
	data := ntcNoteEntry(order, []byte("GNU\x00"), []byte{1, 2, 3, 4}, NT_GNU_BUILD_ID)

	// Alignments below 4 are clamped to 4, like BFD does.
	for _, align := range []int{0, 1, 2, 3, 4} {
		notes, err := ParseNotes(order, align, data)
		if err != nil {
			t.Fatalf("ParseNotes(align=%d): %v", align, err)
		}
		if len(notes) != 1 {
			t.Errorf("ParseNotes(align=%d): got %d notes", align, len(notes))
		}
	}
	// 8-byte notes parse with either alignment when the layout allows it.
	if _, err := ParseNotes(order, 8, data); err != nil {
		t.Errorf("ParseNotes(align=8): %v", err)
	}
	// Anything else is rejected both before and after the loop would run.
	for _, align := range []int{5, 6, 7, 9, 16} {
		if _, err := ParseNotes(order, align, nil); err == nil {
			t.Errorf("ParseNotes(align=%d) succeeded, want error", align)
		}
		if _, err := ParseNotes(order, align, data); err == nil {
			t.Errorf("ParseNotes(align=%d) succeeded, want error", align)
		}
	}

	// namesz=1 fits in 13..15 bytes, but the descriptor offset (16) does not.
	for extra := 0; extra < 3; extra++ {
		raw := make([]byte, 12)
		order.PutUint32(raw[0:], 1)
		order.PutUint32(raw[4:], 0)
		order.PutUint32(raw[8:], NT_GNU_ABI_TAG)
		raw = append(raw, 'A')
		raw = append(raw, make([]byte, extra)...)
		if _, err := ParseNotes(order, 4, raw); err == nil {
			t.Errorf("ParseNotes with descriptor at offset 16 out of %d bytes succeeded", len(raw))
		}
	}
}

// TestNotesCoverageEmptyAndBigEndian covers zero-length names and descriptors
// and a multi-note big-endian section.
func TestNotesCoverageEmptyAndBigEndian(t *testing.T) {
	order := binary.LittleEndian
	empty, err := ParseNotes(order, 4, make([]byte, 12))
	if err != nil {
		t.Fatalf("ParseNotes(empty note): %v", err)
	}
	if len(empty) != 1 || len(empty[0].Name) != 0 || len(empty[0].Desc) != 0 {
		t.Fatalf("empty note parsed as %+v", empty)
	}
	back, err := MarshalNotes(order, 4, empty)
	if err != nil {
		t.Fatalf("MarshalNotes(empty note): %v", err)
	}
	if !bytes.Equal(back, make([]byte, 12)) {
		t.Errorf("empty note round trip = %x", back)
	}

	be := binary.BigEndian
	var data []byte
	data = append(data, ntcNoteEntry(be, []byte("GNU\x00"), []byte{1, 2, 3, 4}, NT_GNU_BUILD_ID)...)
	data = append(data, ntcNoteEntry(be, []byte("AB\x00"), []byte{5, 6, 7, 8, 9, 10, 11, 12}, NT_GNU_PROPERTY_TYPE_0)...)
	notes, err := ParseNotes(be, 4, data)
	if err != nil {
		t.Fatalf("ParseNotes(big endian): %v", err)
	}
	if len(notes) != 2 {
		t.Fatalf("big endian: got %d notes, want 2", len(notes))
	}
	if notes[0].Type != NT_GNU_BUILD_ID || notes[1].Type != NT_GNU_PROPERTY_TYPE_0 {
		t.Errorf("big endian types = %#x, %#x", notes[0].Type, notes[1].Type)
	}
	if !bytes.Equal(notes[1].Desc, []byte{5, 6, 7, 8, 9, 10, 11, 12}) {
		t.Errorf("big endian descriptor = %x", notes[1].Desc)
	}
}

// TestNotesCoverageMarshalLayout covers the alignment clamping and rejection
// paths of MarshalNotes and pins the descriptor offset for 8-byte alignment.
func TestNotesCoverageMarshalLayout(t *testing.T) {
	order := binary.LittleEndian
	notes := []Note{{Name: []byte("GNU\x00"), Desc: []byte{1, 2, 3, 4}, Type: NT_GNU_BUILD_ID}}

	// Below 4 is treated as 4, matching ParseNotes.
	for _, align := range []int{0, 1, 3, 4} {
		if _, err := MarshalNotes(order, align, notes); err != nil {
			t.Fatalf("MarshalNotes(align=%d): %v", align, err)
		}
	}
	for _, align := range []int{5, 6, 9, 16} {
		if _, err := MarshalNotes(order, align, notes); err == nil {
			t.Errorf("MarshalNotes(align=%d) succeeded, want error", align)
		}
	}

	// With 8-byte alignment the descriptor starts at alignUp(12+namesz, 8),
	// not at 12+alignUp(namesz, 8).
	out, err := MarshalNotes(order, 8, notes)
	if err != nil {
		t.Fatalf("MarshalNotes(align=8): %v", err)
	}
	if len(out) != 24 {
		t.Fatalf("8-byte aligned size = %d, want 24", len(out))
	}
	if !bytes.Equal(out[16:20], []byte{1, 2, 3, 4}) {
		t.Errorf("8-byte aligned descriptor at %x", out[16:20])
	}
	// A five-byte name pushes the descriptor to offset 24.
	five := []Note{{Name: []byte("ABCDE"), Desc: []byte{1, 2, 3, 4}, Type: 1}}
	out, err = MarshalNotes(order, 8, five)
	if err != nil {
		t.Fatalf("MarshalNotes(align=8, name=5): %v", err)
	}
	if len(out) != 32 || !bytes.Equal(out[24:28], []byte{1, 2, 3, 4}) {
		t.Errorf("five-byte name layout = %x", out)
	}
	if _, err := MarshalNotes(order, 8, nil); err != nil {
		t.Errorf("MarshalNotes(nil notes): %v", err)
	}
}

// TestNotesCoverageSectionAPI exercises the error paths of File.Notes and
// File.SetNotes.
func TestNotesCoverageSectionAPI(t *testing.T) {
	f := &File{Header: Header{Class: Class64, Data: DataLSB}}
	if _, err := f.Notes(nil); err == nil {
		t.Error("Notes(nil) succeeded, want error")
	}
	badAlign := &Section{
		SectionHeader: SectionHeader{Name: ".note.bad", Type: SHT_NOTE, Addralign: 16},
	}
	if _, err := f.Notes(badAlign); err == nil {
		t.Error("Notes with unsupported alignment succeeded, want error")
	}
	if err := f.SetNotes(nil, nil); err == nil {
		t.Error("SetNotes(nil) succeeded, want error")
	}
	if err := f.SetNotes(badAlign, nil); err == nil {
		t.Error("SetNotes with unsupported alignment succeeded, want error")
	}

	// A zero sh_addralign is clamped to 4 for both setters and getters.
	sec := &Section{SectionHeader: SectionHeader{Name: ".note.ok", Type: SHT_NOTE, Addralign: 0}}
	notes := []Note{{Name: []byte("GNU\x00"), Desc: []byte{1, 2, 3, 4}, Type: NT_GNU_BUILD_ID}}
	if err := f.SetNotes(sec, notes); err != nil {
		t.Fatalf("SetNotes: %v", err)
	}
	got, err := f.Notes(sec)
	if err != nil {
		t.Fatalf("Notes: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0].Desc, notes[0].Desc) {
		t.Errorf("round trip = %+v", got)
	}
}

// TestNotesCoverageHelpers covers NameString edge cases and alignUpInt's
// small-alignment shortcut.
func TestNotesCoverageHelpers(t *testing.T) {
	if got := alignUpInt(5, 1); got != 5 {
		t.Errorf("alignUpInt(5, 1) = %d, want 5", got)
	}
	if got := alignUpInt(5, 0); got != 5 {
		t.Errorf("alignUpInt(5, 0) = %d, want 5", got)
	}
	if got := alignUpInt(5, 4); got != 8 {
		t.Errorf("alignUpInt(5, 4) = %d, want 8", got)
	}
	if got := alignUpInt(8, 8); got != 8 {
		t.Errorf("alignUpInt(8, 8) = %d, want 8", got)
	}

	tests := []struct {
		name []byte
		want string
	}{
		{[]byte("GNU\x00"), "GNU"},
		{[]byte("ABC"), "ABC"},
		{[]byte("A\x00\x00"), "A\x00"},
		{nil, ""},
	}
	for _, tc := range tests {
		if got := (Note{Name: tc.name}).NameString(); got != tc.want {
			t.Errorf("NameString(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}
