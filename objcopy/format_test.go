package objcopy

import (
	"bytes"
	"testing"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/bfdtarget"
)

// recordELF builds a small synthetic ELF file with the given loadable
// sections, used to test the textual writers without external tools.
func recordELF(entry uint64, data elf.Data, region ...recordSection) *elf.File {
	f := &elf.File{
		Header: elf.Header{
			Class:   elf.Class64,
			Data:    data,
			Type:    elf.ET_REL,
			Version: elf.EV_CURRENT,
			Entry:   entry,
		},
		SectionHeadersPresent: true,
	}
	f.Sections = []*elf.Section{{}}
	for i, r := range region {
		addr := r.addr
		f.Sections = append(f.Sections, &elf.Section{
			SectionHeader: elf.SectionHeader{
				Name:  ".sec" + string(rune('1'+i)),
				Type:  elf.SHT_PROGBITS,
				Flags: elf.SHF_ALLOC,
				Addr:  addr,
				Size:  uint64(len(r.data)),
			},
			Data: r.data,
			LMA:  &addr,
		})
	}
	return f
}

func TestWriteIHex(t *testing.T) {
	f := recordELF(0x1000, elf.DataLSB,
		recordSection{addr: 0x1000, data: []byte{1, 2, 3}},
		recordSection{addr: 0x1003, data: []byte{4, 5}},
	)
	got, err := writeIHex(f, Default())
	if err != nil {
		t.Fatal(err)
	}
	want := ":03100000010203E7\r\n" +
		":021003000405E2\r\n" +
		":0400000300001000E9\r\n" +
		":00000001FF\r\n"
	if string(got) != want {
		t.Errorf("ihex output:\n got %q\nwant %q", got, want)
	}
}

func TestWriteIHexExtendedAddress(t *testing.T) {
	// An address above 0xfffff needs an extended linear address record.
	f := recordELF(0, elf.DataLSB, recordSection{addr: 0x12345678, data: []byte{0xAA, 0xBB}})
	got, err := writeIHex(f, Default())
	if err != nil {
		t.Fatal(err)
	}
	want := ":020000041234B4\r\n" +
		":02567800AABBCB\r\n" +
		":00000001FF\r\n"
	if string(got) != want {
		t.Errorf("ihex output:\n got %q\nwant %q", got, want)
	}
}

func TestWriteIHexSegmentAddress(t *testing.T) {
	// Addresses above 0xffff but at or below 0xfffff use the segment form.
	f := recordELF(0, elf.DataLSB, recordSection{addr: 0x10000, data: []byte{0x11}})
	got, err := writeIHex(f, Default())
	if err != nil {
		t.Fatal(err)
	}
	want := ":020000021000EC\r\n" +
		":0100000011EE\r\n" +
		":00000001FF\r\n"
	if string(got) != want {
		t.Errorf("ihex output:\n got %q\nwant %q", got, want)
	}
}

func TestReadIHex(t *testing.T) {
	in := ":03100000010203E7\r\n" +
		":021003000405E2\r\n" +
		":0400000300001000E9\r\n" +
		":00000001FF\r\n"
	f, err := readIHex([]byte(in), "in.hex", Default(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.Entry != 0x1000 {
		t.Errorf("entry = %#x, want 0x1000", f.Entry)
	}
	var got []recordSection
	for _, s := range f.Sections[1 : len(f.Sections)-1] {
		got = append(got, recordSection{addr: s.Addr, data: s.Data})
	}
	want := []recordSection{
		{addr: 0x1000, data: []byte{1, 2, 3, 4, 5}},
	}
	if len(got) != len(want) {
		t.Fatalf("sections = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].addr != want[i].addr || !bytes.Equal(got[i].data, want[i].data) {
			t.Errorf("section %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestReadIHexBadChecksum(t *testing.T) {
	if _, err := readIHex([]byte(":0100000001FF\r\n"), "in.hex", Default(), nil); err == nil {
		t.Fatal("readIHex accepted a bad checksum")
	}
}

func TestWriteSREC(t *testing.T) {
	name := "out.srec"
	SetOutputName(&name)
	defer SetOutputName(nil)

	f := recordELF(0x1000, elf.DataLSB, recordSection{addr: 0x1000, data: []byte{1, 2, 3, 4, 5}})
	got, err := writeSREC(f, Default())
	if err != nil {
		t.Fatal(err)
	}
	want := "S00B00006F75742E73726563C1\r\n" +
		"S10810000102030405D8\r\n" +
		"S9031000EC\r\n"
	if string(got) != want {
		t.Errorf("srec output:\n got %q\nwant %q", got, want)
	}
}

func TestWriteSRECForceS3AndLength(t *testing.T) {
	name := "out.srec"
	SetOutputName(&name)
	defer SetOutputName(nil)

	f := recordELF(0, elf.DataLSB, recordSection{addr: 0x1000, data: []byte{1, 2, 3, 4, 5}})
	cfg := Default()
	cfg.SrecForceS3 = true
	cfg.SrecLen = 2
	got, err := writeSREC(f, cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := "S00B00006F75742E73726563C1\r\n" +
		"S307000010000102E5\r\n" +
		"S307000010020304DF\r\n" +
		"S3060000100405E0\r\n" +
		"S70500000000FA\r\n"
	if string(got) != want {
		t.Errorf("srec output:\n got %q\nwant %q", got, want)
	}
}

func TestReadSREC(t *testing.T) {
	in := "S00B00006F75742E73726563C1\r\n" +
		"S10810000102030405D8\r\n" +
		"S9031000EC\r\n"
	f, err := readSREC([]byte(in), "in.srec", Default(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.Entry != 0x1000 {
		t.Errorf("entry = %#x, want 0x1000", f.Entry)
	}
	if len(f.Sections) != 3 {
		t.Fatalf("got %d sections, want 3", len(f.Sections))
	}
	sec := f.Sections[1]
	if sec.Name != ".sec1" || sec.Addr != 0x1000 || !bytes.Equal(sec.Data, []byte{1, 2, 3, 4, 5}) {
		t.Errorf("section = %+v", sec)
	}
}

func TestReadSRECBadChecksum(t *testing.T) {
	if _, err := readSREC([]byte("S10810000102030405D3\r\n"), "in.srec", Default(), nil); err == nil {
		t.Fatal("readSREC accepted a bad checksum")
	}
}

func TestWriteVerilog(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	f := recordELF(0, elf.DataLSB, recordSection{addr: 0x100, data: data})

	cases := []struct {
		width int
		want  string
	}{
		{1, "@00000100\r\n01 02 03 04 05 06 07 08\r\n"},
		{2, "@00000080\r\n0201 0403 0605 0807\r\n"},
		{4, "@00000040\r\n04030201 08070605\r\n"},
		{8, "@00000020\r\n0807060504030201\r\n"},
	}
	for _, tc := range cases {
		cfg := Default()
		cfg.VerilogDataWidth = tc.width
		got, err := writeVerilog(f, cfg)
		if err != nil {
			t.Fatalf("width %d: %v", tc.width, err)
		}
		if string(got) != tc.want {
			t.Errorf("width %d:\n got %q\nwant %q", tc.width, got, tc.want)
		}
	}
}

func TestWriteVerilogBigEndian(t *testing.T) {
	f := recordELF(0, elf.DataMSB, recordSection{addr: 0, data: []byte{1, 2, 3, 4, 5, 6, 7, 8}})
	cfg := Default()
	cfg.VerilogDataWidth = 4
	got, err := writeVerilog(f, cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := "@00000000\r\n01020304 05060708 \r\n"
	if string(got) != want {
		t.Errorf("verilog output:\n got %q\nwant %q", got, want)
	}
}

func TestWriteVerilogBadWidth(t *testing.T) {
	cfg := Default()
	cfg.VerilogDataWidth = 3
	if _, err := writeVerilog(recordELF(0, elf.DataLSB), cfg); err == nil {
		t.Fatal("writeVerilog accepted width 3")
	}
}

func TestIHexRoundTrip(t *testing.T) {
	// Addresses in the segment and extended-linear ranges exercise both base
	// record types on the way out and their parsing on the way back in.
	want := []recordSection{
		{addr: 0x1234, data: []byte("hello")},
		{addr: 0x12345678, data: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
	}
	f := recordELF(0x1234, elf.DataLSB, want...)
	out, err := writeIHex(f, Default())
	if err != nil {
		t.Fatal(err)
	}
	back, err := readIHex(out, "roundtrip.hex", Default(), nil)
	if err != nil {
		t.Fatalf("reading back %q: %v", out, err)
	}
	var got []recordSection
	for _, s := range back.Sections[1 : len(back.Sections)-1] {
		got = append(got, recordSection{addr: s.Addr, data: s.Data})
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sections, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i].addr != want[i].addr || !bytes.Equal(got[i].data, want[i].data) {
			t.Errorf("section %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if back.Entry != 0x1234 {
		t.Errorf("entry = %#x, want 0x1234", back.Entry)
	}
}

func TestSRECRoundTrip(t *testing.T) {
	want := []recordSection{
		{addr: 0x1000, data: []byte("hello")},
		{addr: 0x100000, data: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
	}
	f := recordELF(0x1000, elf.DataLSB, want...)
	cfg := Default()
	cfg.SrecForceS3 = true
	out, err := writeSREC(f, cfg)
	if err != nil {
		t.Fatal(err)
	}
	back, err := readSREC(out, "roundtrip.srec", Default(), nil)
	if err != nil {
		t.Fatalf("reading back %q: %v", out, err)
	}
	var got []recordSection
	for _, s := range back.Sections[1 : len(back.Sections)-1] {
		got = append(got, recordSection{addr: s.Addr, data: s.Data})
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sections, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i].addr != want[i].addr || !bytes.Equal(got[i].data, want[i].data) {
			t.Errorf("section %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestRecordReaderDefaultsOutputTarget(t *testing.T) {
	cfg := Default()
	tgt, err := bfdtarget.Parse("ihex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readIHex([]byte(":00000001FF\r\n"), "empty.hex", cfg, tgt); err != nil {
		t.Fatal(err)
	}
	if cfg.OutputTarget != "ihex" {
		t.Errorf("OutputTarget = %q, want %q (GNU reuses the input target)", cfg.OutputTarget, "ihex")
	}
}
