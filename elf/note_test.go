package elf_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

// rawNote builds one note entry exactly as it appears on disk.
func rawNote(order binary.ByteOrder, align int, name, desc []byte, typ uint32) []byte {
	out := make([]byte, 12)
	order.PutUint32(out[0:], uint32(len(name)))
	order.PutUint32(out[4:], uint32(len(desc)))
	order.PutUint32(out[8:], typ)
	out = append(out, name...)
	for len(out)%align != 0 {
		out = append(out, 0)
	}
	out = append(out, desc...)
	for len(out)%align != 0 {
		out = append(out, 0)
	}
	return out
}

func TestNoteAlign(t *testing.T) {
	tests := []struct {
		align   uint64
		want    int
		wantErr bool
	}{
		{0, 4, false},
		{1, 4, false},
		{2, 4, false},
		{4, 4, false},
		{8, 8, false},
		{3, 4, false},
		{16, 0, true},
	}
	for _, tc := range tests {
		got, err := elf.NoteAlign(tc.align)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NoteAlign(%d) = %d, want error", tc.align, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NoteAlign(%d): %v", tc.align, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NoteAlign(%d) = %d, want %d", tc.align, got, tc.want)
		}
	}
}

func TestParseNotesLayout(t *testing.T) {
	order := binary.LittleEndian
	data := []byte{
		0x04, 0, 0, 0, // namesz = 4 ("GNU\0")
		0x04, 0, 0, 0, // descsz = 4
		0x03, 0, 0, 0, // type = NT_GNU_BUILD_ID
		'G', 'N', 'U', 0,
		0xde, 0xad, 0xbe, 0xef,
	}
	notes, err := elf.ParseNotes(order, 4, data)
	if err != nil {
		t.Fatalf("ParseNotes: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("got %d notes, want 1", len(notes))
	}
	n := notes[0]
	if n.NameString() != "GNU" {
		t.Errorf("name = %q, want GNU", n.NameString())
	}
	if !bytes.Equal(n.Name, []byte("GNU\x00")) {
		t.Errorf("raw name = %v, want GNU\\0", n.Name)
	}
	if !bytes.Equal(n.Desc, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("desc = %x", n.Desc)
	}
	if n.Type != elf.NT_GNU_BUILD_ID {
		t.Errorf("type = %#x, want %#x", n.Type, elf.NT_GNU_BUILD_ID)
	}
	out, err := elf.MarshalNotes(order, 4, notes)
	if err != nil {
		t.Fatalf("MarshalNotes: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("round trip = %x, want %x", out, data)
	}
}

func TestNotesRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		order binary.ByteOrder
		align int
		notes []elf.Note
	}{
		{
			name:  "empty",
			order: binary.LittleEndian,
			align: 4,
			notes: nil,
		},
		{
			name:  "name-padding-1",
			order: binary.LittleEndian,
			align: 4,
			notes: []elf.Note{{Name: []byte("GNU\x00"), Desc: []byte{1, 2, 3, 4}, Type: 3}},
		},
		{
			name:  "name-padding-2",
			order: binary.LittleEndian,
			align: 4,
			notes: []elf.Note{{Name: []byte("AB\x00"), Desc: []byte{1, 2, 3, 4, 5, 6, 7, 8}, Type: 5}},
		},
		{
			name:  "name-padding-3",
			order: binary.LittleEndian,
			align: 4,
			notes: []elf.Note{{Name: []byte("A\x00"), Desc: nil, Type: 1}},
		},
		{
			name:  "desc-padding",
			order: binary.LittleEndian,
			align: 4,
			notes: []elf.Note{{Name: []byte("GNU\x00"), Desc: []byte{1, 2, 3}, Type: 1}},
		},
		{
			name:  "eight-byte-alignment",
			order: binary.LittleEndian,
			align: 8,
			notes: []elf.Note{
				{Name: []byte("GNU\x00"), Desc: make([]byte, 8), Type: 4},
				{Name: []byte("A\x00"), Desc: []byte{9}, Type: 1},
			},
		},
		{
			name:  "big-endian",
			order: binary.BigEndian,
			align: 4,
			notes: []elf.Note{
				{Name: []byte("GNU\x00"), Desc: []byte{1, 2, 3, 4}, Type: 3},
				{Name: []byte("GA$\x013p1\x00"), Desc: make([]byte, 16), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
			},
		},
		{
			name:  "long-names",
			order: binary.LittleEndian,
			align: 4,
			notes: []elf.Note{
				{Name: []byte("GNU\x00"), Desc: nil, Type: 1},
				{Name: []byte(".note.gnu.property\x00"), Desc: []byte{0, 1, 2, 3, 4, 5, 6, 7}, Type: 5},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := elf.MarshalNotes(tc.order, tc.align, tc.notes)
			if err != nil {
				t.Fatalf("MarshalNotes: %v", err)
			}
			if len(data)%tc.align != 0 && len(data) != 0 {
				t.Errorf("serialised size %d is not a multiple of %d", len(data), tc.align)
			}
			notes, err := elf.ParseNotes(tc.order, tc.align, data)
			if err != nil {
				t.Fatalf("ParseNotes: %v", err)
			}
			if len(notes) != len(tc.notes) {
				t.Fatalf("got %d notes, want %d", len(notes), len(tc.notes))
			}
			for i := range notes {
				if !bytes.Equal(notes[i].Name, tc.notes[i].Name) {
					t.Errorf("note %d name = %v, want %v", i, notes[i].Name, tc.notes[i].Name)
				}
				if !bytes.Equal(notes[i].Desc, tc.notes[i].Desc) {
					t.Errorf("note %d desc = %v, want %v", i, notes[i].Desc, tc.notes[i].Desc)
				}
				if notes[i].Type != tc.notes[i].Type {
					t.Errorf("note %d type = %#x, want %#x", i, notes[i].Type, tc.notes[i].Type)
				}
			}
			again, err := elf.MarshalNotes(tc.order, tc.align, notes)
			if err != nil {
				t.Fatalf("MarshalNotes (second): %v", err)
			}
			if !bytes.Equal(again, data) {
				t.Errorf("round trip changed bytes:\n got %x\nwant %x", again, data)
			}
		})
	}
}

func TestParseNotesNormalisesPadding(t *testing.T) {
	order := binary.LittleEndian
	data := rawNote(order, 4, []byte("AB\x00"), []byte{1, 2}, 7)
	// Poison every padding byte; ParseNotes must ignore them and MarshalNotes
	// must write zeros.
	data[15] = 0xee // name padding
	data[19] = 0xee // descriptor padding
	notes, err := elf.ParseNotes(order, 4, data)
	if err != nil {
		t.Fatalf("ParseNotes: %v", err)
	}
	out, err := elf.MarshalNotes(order, 4, notes)
	if err != nil {
		t.Fatalf("MarshalNotes: %v", err)
	}
	if out[15] != 0 || out[19] != 0 {
		t.Errorf("padding not zeroed: %x", out)
	}
	if out[12] != 'A' || out[13] != 'B' || out[14] != 0 {
		t.Errorf("name corrupted: %x", out)
	}
	if out[16] != 1 || out[17] != 2 {
		t.Errorf("descriptor corrupted: %x", out)
	}
}

func TestParseNotesMultiple(t *testing.T) {
	order := binary.LittleEndian
	var data []byte
	data = append(data, rawNote(order, 4, []byte("GNU\x00"), []byte{1, 2, 3, 4}, 3)...)
	data = append(data, rawNote(order, 4, []byte("GNU\x00"), []byte{5, 6, 7, 8}, 5)...)
	notes, err := elf.ParseNotes(order, 4, data)
	if err != nil {
		t.Fatalf("ParseNotes: %v", err)
	}
	if len(notes) != 2 {
		t.Fatalf("got %d notes, want 2", len(notes))
	}
	if !bytes.Equal(notes[0].Desc, []byte{1, 2, 3, 4}) || !bytes.Equal(notes[1].Desc, []byte{5, 6, 7, 8}) {
		t.Errorf("descriptors = %x, %x", notes[0].Desc, notes[1].Desc)
	}
}

func TestParseNotesErrors(t *testing.T) {
	order := binary.LittleEndian
	tests := []struct {
		name  string
		align int
		data  []byte
	}{
		{"truncated-header", 4, []byte{1, 0, 0, 0, 0, 0, 0, 0}},
		{"name-out-of-bounds", 4, []byte{
			0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			'A', 0,
		}},
		{"desc-out-of-bounds", 4, []byte{
			0x01, 0, 0, 0, 0x08, 0, 0, 0, 0, 0, 0, 0,
			'A', 0, 0, 0,
			1, 2, 3,
		}},
		{"bad-alignment-5", 5, nil},
		{"bad-alignment-16", 16, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := elf.ParseNotes(order, tc.align, tc.data); err == nil {
				t.Errorf("ParseNotes(%s) succeeded, want error", tc.name)
			}
		})
	}
}

func TestParseNotesTrailingPaddingOptional(t *testing.T) {
	order := binary.LittleEndian
	// A final note may omit the padding after its descriptor.
	data := rawNote(order, 4, []byte("GNU\x00"), []byte{1, 2, 3}, 1)
	data = data[:len(data)-1]
	if _, err := elf.ParseNotes(order, 4, data); err != nil {
		t.Fatalf("ParseNotes: %v", err)
	}
}

func TestSetNotes(t *testing.T) {
	f := &elf.File{Header: elf.Header{Class: elf.Class64, Data: elf.DataLSB}}
	sec := &elf.Section{
		SectionHeader: elf.SectionHeader{Name: ".note.test", Type: elf.SHT_NOTE, Addralign: 4},
	}
	notes := []elf.Note{{Name: []byte("GNU\x00"), Desc: []byte{1, 2, 3, 4}, Type: 3}}
	if err := f.SetNotes(sec, notes); err != nil {
		t.Fatalf("SetNotes: %v", err)
	}
	if sec.Size != uint64(len(sec.Data)) {
		t.Errorf("size = %d, data length %d", sec.Size, len(sec.Data))
	}
	got, err := f.Notes(sec)
	if err != nil {
		t.Fatalf("Notes: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0].Desc, notes[0].Desc) {
		t.Errorf("round trip via section failed: %+v", got)
	}
	if _, err := f.Notes(&elf.Section{SectionHeader: elf.SectionHeader{Type: elf.SHT_PROGBITS}}); err == nil {
		t.Error("Notes on a non-note section succeeded, want error")
	}
}
