package objcopy_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/objcopy"
)

var (
	noteNameVersion3 = []byte("GA$\x013p1\x00")
	noteNameVersion2 = []byte("GA$\x012p1\x00")
	noteNameTool     = []byte("GA$\x05gcc\x00")
	noteNameStack    = []byte("GA+\x02\x00")
	noteNameStackOff = []byte("GA!\x02\x00")
	noteNamePIC      = []byte("GA*\x07\x00\x00")
)

func desc64(start, end uint64) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b, start)
	binary.LittleEndian.PutUint64(b[8:], end)
	return b
}

func desc32(start, end uint32) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, start)
	binary.LittleEndian.PutUint32(b[4:], end)
	return b
}

func makeNotes(t *testing.T, order binary.ByteOrder, notes []elf.Note) []byte {
	t.Helper()
	data, err := elf.MarshalNotes(order, 4, notes)
	if err != nil {
		t.Fatalf("MarshalNotes: %v", err)
	}
	return data
}

func noteSection(t *testing.T, order binary.ByteOrder, name string, notes []elf.Note) *elf.Section {
	t.Helper()
	data := makeNotes(t, order, notes)
	return &elf.Section{
		SectionHeader: elf.SectionHeader{
			Name: name, Type: elf.SHT_NOTE, Addralign: 4, Size: uint64(len(data)),
		},
		Data: data,
	}
}

func noteFile(class elf.Class, data elf.Data, secs ...*elf.Section) *elf.File {
	return &elf.File{
		Header:   elf.Header{Class: class, Data: data},
		Sections: secs,
		Path:     "test.o",
	}
}

func wantNotes(t *testing.T, order binary.ByteOrder, want []elf.Note) []byte {
	t.Helper()
	return makeNotes(t, order, want)
}

func checkMerged(t *testing.T, f *elf.File, want []elf.Note) {
	t.Helper()
	sec := f.Sections[0]
	got := wantNotes(t, f.Data.Order(), want)
	if !bytes.Equal(sec.Data, got) {
		t.Fatalf("merged notes mismatch\n got %x\nwant %x", sec.Data, got)
	}
	if sec.Size != uint64(len(sec.Data)) {
		t.Errorf("section size = %d, len(data) = %d", sec.Size, len(sec.Data))
	}
}

func TestMergeNotesDeduplicates(t *testing.T) {
	order := binary.LittleEndian
	sec := noteSection(t, order, elf.GNU_BUILD_ATTRS_SECTION_NAME, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
	f := noteFile(elf.Class64, elf.DataLSB, sec)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	checkMerged(t, f, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
}

func TestMergeNotesReusesRangeDescriptor(t *testing.T) {
	order := binary.LittleEndian
	sec := noteSection(t, order, elf.GNU_BUILD_ATTRS_SECTION_NAME, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameTool, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
	f := noteFile(elf.Class64, elf.DataLSB, sec)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	// The second note repeats the first note's range, so it is emitted with a
	// zero-length descriptor, exactly like GNU objcopy.
	checkMerged(t, f, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameTool, Desc: nil, Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
}

func TestMergeNotesMergesAdjoiningRanges(t *testing.T) {
	order := binary.LittleEndian
	sec := noteSection(t, order, elf.GNU_BUILD_ATTRS_SECTION_NAME, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x130), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameStack, Desc: desc64(0x100, 0x104), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameStack, Desc: desc64(0x104, 0x108), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
	f := noteFile(elf.Class64, elf.DataLSB, sec)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	checkMerged(t, f, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x130), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameStack, Desc: desc64(0x100, 0x108), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
}

func TestMergeNotesDropsContainedRange(t *testing.T) {
	order := binary.LittleEndian
	sec := noteSection(t, order, elf.GNU_BUILD_ATTRS_SECTION_NAME, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x130), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameTool, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameTool, Desc: desc64(0x104, 0x106), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
	f := noteFile(elf.Class64, elf.DataLSB, sec)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	checkMerged(t, f, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x130), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameTool, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
}

func TestMergeNotesDropsEmptyRange(t *testing.T) {
	order := binary.LittleEndian
	sec := noteSection(t, order, elf.GNU_BUILD_ATTRS_SECTION_NAME, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x130), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameStackOff, Desc: desc64(0x110, 0x110), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
	f := noteFile(elf.Class64, elf.DataLSB, sec)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	checkMerged(t, f, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x130), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
}

func TestMergeNotesDoesNotMergeDifferentKinds(t *testing.T) {
	order := binary.LittleEndian
	sec := noteSection(t, order, elf.GNU_BUILD_ATTRS_SECTION_NAME, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x130), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameStack, Desc: desc64(0x100, 0x104), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameStack, Desc: desc64(0x104, 0x108), Type: elf.NT_GNU_BUILD_ATTRIBUTE_FUNC},
		// A duplicate function note makes the section shrink, so the merge is
		// actually installed and the open/function split can be observed.
		{Name: noteNameStack, Desc: desc64(0x104, 0x108), Type: elf.NT_GNU_BUILD_ATTRIBUTE_FUNC},
	})
	f := noteFile(elf.Class64, elf.DataLSB, sec)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	checkMerged(t, f, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x130), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameStack, Desc: desc64(0x100, 0x104), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameStack, Desc: desc64(0x104, 0x108), Type: elf.NT_GNU_BUILD_ATTRIBUTE_FUNC},
	})
}

func TestMergeNotesSkipsVersion2(t *testing.T) {
	order := binary.LittleEndian
	data := makeNotes(t, order, []elf.Note{
		{Name: noteNameVersion2, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameVersion2, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
	sec := &elf.Section{
		SectionHeader: elf.SectionHeader{Name: elf.GNU_BUILD_ATTRS_SECTION_NAME, Type: elf.SHT_NOTE, Addralign: 4, Size: uint64(len(data))},
		Data:          data,
	}
	f := noteFile(elf.Class64, elf.DataLSB, sec)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	if !bytes.Equal(sec.Data, data) {
		t.Errorf("version 2 notes were modified")
	}
}

func TestMergeNotesIgnoresOtherSections(t *testing.T) {
	order := binary.LittleEndian
	dup := func() []elf.Note {
		return []elf.Note{
			{Name: noteNameVersion3, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
			{Name: noteNameVersion3, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		}
	}
	data := makeNotes(t, order, dup())
	sec := &elf.Section{
		SectionHeader: elf.SectionHeader{Name: ".note.mynote", Type: elf.SHT_NOTE, Addralign: 4, Size: uint64(len(data))},
		Data:          data,
	}
	f := noteFile(elf.Class64, elf.DataLSB, sec)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	if !bytes.Equal(sec.Data, data) {
		t.Errorf("a non-build-attribute note section was modified")
	}

	// BFD matches the section name as a prefix.
	prefixed := noteSection(t, order, elf.GNU_BUILD_ATTRS_SECTION_NAME+".extra", dup())
	f = noteFile(elf.Class64, elf.DataLSB, prefixed)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	if len(prefixed.Data) >= len(data) {
		t.Errorf("prefixed build attribute section was not merged (%d bytes)", len(prefixed.Data))
	}
}

func TestMergeNotesSkipsSectionWithRelocations(t *testing.T) {
	order := binary.LittleEndian
	sec := noteSection(t, order, elf.GNU_BUILD_ATTRS_SECTION_NAME, []elf.Note{
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameVersion3, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
	orig := append([]byte(nil), sec.Data...)
	rela := &elf.Section{
		SectionHeader: elf.SectionHeader{Name: ".rela.gnu.build.attributes", Type: elf.SHT_RELA, Info: 0},
		Data:          make([]byte, 24),
	}
	f := noteFile(elf.Class64, elf.DataLSB, sec, rela)
	var warnings []string
	if err := objcopy.MergeNotesWithWarn(f, func(format string, args ...any) {
		warnings = append(warnings, format)
	}); err != nil {
		t.Fatalf("MergeNotesWithWarn: %v", err)
	}
	if !bytes.Equal(sec.Data, orig) {
		t.Errorf("section with relocations was merged")
	}
	if len(warnings) == 0 {
		t.Errorf("no warning about relocations")
	}
}

func TestMergeNotesMalformed(t *testing.T) {
	order := binary.LittleEndian
	// descsz = 5 is not a multiple of 4.
	data := make([]byte, 0, 32)
	var hdr [12]byte
	order.PutUint32(hdr[0:], 4)
	order.PutUint32(hdr[4:], 5)
	order.PutUint32(hdr[8:], elf.NT_GNU_BUILD_ATTRIBUTE_OPEN)
	data = append(data, hdr[:]...)
	data = append(data, []byte("GNU\x00")...)
	data = append(data, 1, 2, 3, 4, 5, 0, 0, 0)
	sec := &elf.Section{
		SectionHeader: elf.SectionHeader{Name: elf.GNU_BUILD_ATTRS_SECTION_NAME, Type: elf.SHT_NOTE, Addralign: 4, Size: uint64(len(data))},
		Data:          data,
	}
	f := noteFile(elf.Class64, elf.DataLSB, sec)
	err := objcopy.MergeNotes(f)
	if err == nil || !strings.Contains(err.Error(), "description size") {
		t.Fatalf("MergeNotes error = %v, want description size error", err)
	}

	// A non-build-attribute note type is rejected.
	hdr = [12]byte{}
	order.PutUint32(hdr[0:], 4)
	order.PutUint32(hdr[4:], 4)
	order.PutUint32(hdr[8:], 3)
	data = append(append([]byte(nil), hdr[:]...), []byte("GNU\x00")...)
	data = append(data, 1, 2, 3, 4)
	sec.Data = data
	sec.Size = uint64(len(data))
	err = objcopy.MergeNotes(f)
	if err == nil || !strings.Contains(err.Error(), "wrong note type") {
		t.Fatalf("MergeNotes error = %v, want wrong note type error", err)
	}
}

func TestMergeNotesVersionWarning(t *testing.T) {
	order := binary.LittleEndian
	sec := noteSection(t, order, elf.GNU_BUILD_ATTRS_SECTION_NAME, []elf.Note{
		{Name: noteNameTool, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameTool, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
	f := noteFile(elf.Class64, elf.DataLSB, sec)
	var warnings []string
	if err := objcopy.MergeNotesWithWarn(f, func(format string, args ...any) {
		warnings = append(warnings, format)
	}); err != nil {
		t.Fatalf("MergeNotesWithWarn: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "version note missing") {
		t.Errorf("warnings = %v, want version note missing", warnings)
	}
	if len(sec.Data) >= len(makeNotes(t, order, []elf.Note{
		{Name: noteNameTool, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameTool, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})) {
		t.Errorf("notes without a version notice were not merged")
	}
}

func TestMergeNotes32Bit(t *testing.T) {
	order := binary.LittleEndian
	sec := noteSection(t, order, elf.GNU_BUILD_ATTRS_SECTION_NAME, []elf.Note{
		{Name: noteNameVersion3, Desc: desc32(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameVersion3, Desc: desc32(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
	f := noteFile(elf.Class32, elf.DataLSB, sec)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	checkMerged(t, f, []elf.Note{
		{Name: noteNameVersion3, Desc: desc32(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
}

func TestMergeNotesDoesNotGrowSection(t *testing.T) {
	order := binary.LittleEndian
	// A four-byte descriptor is rewritten as a full 16-byte range, which makes
	// the section bigger; GNU leaves the input untouched in that case.
	data := makeNotes(t, order, []elf.Note{
		{Name: noteNameVersion3, Desc: []byte{0x00, 0x01, 0x00, 0x00}, Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
	sec := &elf.Section{
		SectionHeader: elf.SectionHeader{Name: elf.GNU_BUILD_ATTRS_SECTION_NAME, Type: elf.SHT_NOTE, Addralign: 4, Size: uint64(len(data))},
		Data:          data,
	}
	f := noteFile(elf.Class64, elf.DataLSB, sec)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	if !bytes.Equal(sec.Data, data) {
		t.Errorf("section contents changed even though the merged form is larger")
	}
}

func TestMergeNotesEmptySection(t *testing.T) {
	sec := &elf.Section{SectionHeader: elf.SectionHeader{Name: elf.GNU_BUILD_ATTRS_SECTION_NAME, Type: elf.SHT_NOTE}}
	f := noteFile(elf.Class64, elf.DataLSB, sec)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	if len(sec.Data) != 0 {
		t.Errorf("empty section gained contents")
	}
}

func TestMergeNotesBigEndian(t *testing.T) {
	order := binary.BigEndian
	desc := make([]byte, 16)
	order.PutUint64(desc, 0x100)
	order.PutUint64(desc[8:], 0x120)
	sec := noteSection(t, order, elf.GNU_BUILD_ATTRS_SECTION_NAME, []elf.Note{
		{Name: noteNameVersion3, Desc: desc, Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		{Name: noteNameVersion3, Desc: desc, Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
	f := noteFile(elf.Class64, elf.DataMSB, sec)
	if err := objcopy.MergeNotes(f); err != nil {
		t.Fatalf("MergeNotes: %v", err)
	}
	checkMerged(t, f, []elf.Note{
		{Name: noteNameVersion3, Desc: desc, Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
	})
}

func TestNoteSectionType(t *testing.T) {
	tests := []struct {
		name string
		typ  uint32
		ok   bool
	}{
		{".note", elf.SHT_NOTE, true},
		{".note.foo", elf.SHT_NOTE, true},
		{".noteXYZ", elf.SHT_NOTE, true},
		{".note.GNU-stack", elf.SHT_PROGBITS, true},
		{".text", 0, false},
		{".notes", elf.SHT_NOTE, true},
		{".noteworthy", elf.SHT_NOTE, true},
		{".nop", 0, false},
	}
	for _, tc := range tests {
		typ, ok := objcopy.NoteSectionType(tc.name)
		if ok != tc.ok || typ != tc.typ {
			t.Errorf("NoteSectionType(%q) = %#x, %v; want %#x, %v", tc.name, typ, ok, tc.typ, tc.ok)
		}
	}
}

// TestTransformMergesNotes verifies that the noteMerge hook is registered and
// honours Config.MergeNotes. GNU objcopy does not merge notes unless asked to,
// so a nil switch must leave the section untouched.
func TestTransformMergesNotes(t *testing.T) {
	order := binary.LittleEndian
	newFile := func() *elf.File {
		sec := noteSection(t, order, elf.GNU_BUILD_ATTRS_SECTION_NAME, []elf.Note{
			{Name: noteNameVersion3, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
			{Name: noteNameVersion3, Desc: desc64(0x100, 0x120), Type: elf.NT_GNU_BUILD_ATTRIBUTE_OPEN},
		})
		null := &elf.Section{SectionHeader: elf.SectionHeader{Name: "", Type: elf.SHT_NULL}}
		return noteFile(elf.Class64, elf.DataLSB, null, sec)
	}
	mergedData := func(f *elf.File) []byte {
		return f.Sections[1].Data
	}
	unmergedLen := len(newFile().Sections[1].Data)

	t.Run("explicit-yes", func(t *testing.T) {
		f := newFile()
		yes := true
		cfg := objcopy.Default()
		cfg.MergeNotes = &yes
		if err := objcopy.Transform(f, cfg); err != nil {
			t.Fatalf("Transform: %v", err)
		}
		if len(mergedData(f)) >= unmergedLen {
			t.Errorf("notes were not merged with MergeNotes=true")
		}
	})
	t.Run("explicit-no", func(t *testing.T) {
		f := newFile()
		no := false
		cfg := objcopy.Default()
		cfg.MergeNotes = &no
		if err := objcopy.Transform(f, cfg); err != nil {
			t.Fatalf("Transform: %v", err)
		}
		if len(mergedData(f)) != unmergedLen {
			t.Errorf("notes were merged with MergeNotes=false")
		}
	})
	t.Run("default-no-merge", func(t *testing.T) {
		f := newFile()
		cfg := objcopy.Default()
		if err := objcopy.Transform(f, cfg); err != nil {
			t.Fatalf("Transform: %v", err)
		}
		if len(mergedData(f)) != unmergedLen {
			t.Errorf("notes were merged without MergeNotes being set")
		}
	})
	t.Run("default-strip-debug", func(t *testing.T) {
		f := newFile()
		cfg := objcopy.Default()
		cfg.StripDebug = true
		if err := objcopy.Transform(f, cfg); err != nil {
			t.Fatalf("Transform: %v", err)
		}
		if len(mergedData(f)) != unmergedLen {
			t.Errorf("notes were merged while stripping debug info")
		}
	})
}
