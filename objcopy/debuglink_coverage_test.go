package objcopy

// Coverage-oriented tests for .gnu_debuglink handling: the CRC helper, the
// section layout (name, NUL padding and little endian CRC) and the
// --add-gnu-debuglink wiring through Transform.

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/fixtures"
)

func TestDebugLinkCRCKnownValues(t *testing.T) {
	// CRC-32/ISO-HDLC check value: the standard test vector for this
	// polynomial, and the value GNU's gnu_debuglink_crc32 produces.
	if got := DebugLinkCRC([]byte("123456789")); got != 0xcbf43926 {
		t.Errorf("DebugLinkCRC(123456789) = %#08x want 0xcbf43926", got)
	}
	if got := DebugLinkCRC(nil); got != 0 {
		t.Errorf("DebugLinkCRC(nil) = %#08x want 0", got)
	}
	if got, want := DebugLinkCRC([]byte("hello world")), crc32.ChecksumIEEE([]byte("hello world")); got != want {
		t.Errorf("DebugLinkCRC(hello world) = %#08x want %#08x", got, want)
	}
	// Appending data changes the CRC.
	a := DebugLinkCRC([]byte("abc"))
	b := DebugLinkCRC([]byte("abc\x00"))
	if a == b {
		t.Error("CRC must depend on the trailing NUL")
	}
}

func TestDebugLinkSectionLayout(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"a", 8},      // "a\0" padded to 4, plus 4 CRC bytes
		{"ab", 8},     // "ab\0\0"
		{"abc", 8},    // "abc\0"
		{"abcd", 12},  // "abcd\0" needs one padding word
		{"abcde", 12}, // 4 bytes of name+NUL, then 4 zero pad
		{"a.debug", 12},
	}
	for _, tc := range cases {
		got := DebugLinkSection(tc.name, 0x11223344)
		if len(got) != tc.size {
			t.Errorf("DebugLinkSection(%q) length = %d want %d", tc.name, len(got), tc.size)
		}
		if len(got)%4 != 0 {
			t.Errorf("DebugLinkSection(%q) is not 4-byte aligned", tc.name)
		}
		name := string(got[:len(tc.name)])
		if name != tc.name {
			t.Errorf("DebugLinkSection(%q) name = %q", tc.name, name)
		}
		for i := len(tc.name); i < len(got)-4; i++ {
			if got[i] != 0 {
				t.Errorf("DebugLinkSection(%q) padding byte %d = %#x", tc.name, i, got[i])
			}
		}
		if crc := binary.LittleEndian.Uint32(got[len(got)-4:]); crc != 0x11223344 {
			t.Errorf("DebugLinkSection(%q) crc = %#08x", tc.name, crc)
		}
	}
}

func TestApplyDebugLinkAddsSection(t *testing.T) {
	dir := t.TempDir()
	fixture, err := fixtures.BuildOne(dir, "reloc.o")
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	debugData := []byte("debug payload")
	debugFile := filepath.Join(dir, "program.debug")
	if err := os.WriteFile(debugFile, debugData, 0o644); err != nil {
		t.Fatal(err)
	}

	f := openFixtureFile(t, "reloc.o")
	var infos int
	c := Default()
	c.AddDebugLink = debugFile
	c.Verbose = true
	c.Infof = func(string, ...any) { infos++ }
	if err := Transform(f, c); err != nil {
		t.Fatalf("Transform: %v", err)
	}
	sec := f.Section(".gnu_debuglink")
	if sec == nil {
		t.Fatal(".gnu_debuglink was not created")
	}
	if sec.Addralign != 4 {
		t.Errorf("alignment = %d want 4", sec.Addralign)
	}
	want := DebugLinkSection("program.debug", DebugLinkCRC(debugData))
	if string(sec.Data) != string(want) {
		t.Errorf("contents = % x want % x", sec.Data, want)
	}
	if sec.Size != uint64(len(want)) {
		t.Errorf("size = %d want %d", sec.Size, len(want))
	}
	if infos == 0 {
		t.Error("verbose debuglink must report progress")
	}

	// The section survives a round trip through the writer.
	out := filepath.Join(dir, "with-debuglink.o")
	if err := Run(c, fixture, out); err != nil {
		t.Fatal(err)
	}
	g, err := elf.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	if sec := g.Section(".gnu_debuglink"); sec == nil || string(sec.Data) != string(want) {
		t.Errorf("round-tripped debuglink = %+v", sec)
	}

	// Missing debug files are reported.
	c = Default()
	c.AddDebugLink = filepath.Join(dir, "no-such.debug")
	if err := Transform(openFixtureFile(t, "reloc.o"), c); err == nil {
		t.Error("missing --add-gnu-debuglink file must fail")
	}

	// An input that already carries a .gnu_debuglink must not grow a second
	// one; GNU warns and keeps the old section (PR 15125).
	g = openFixtureFile(t, "reloc.o")
	existing := DebugLinkSection("old.debug", 0xdeadbeef)
	g.Sections = append(g.Sections, &elf.Section{
		SectionHeader: elf.SectionHeader{
			Name: ".gnu_debuglink", Type: elf.SHT_PROGBITS, Addralign: 4,
		},
		Data: existing,
	})
	g.Section(".gnu_debuglink").Size = uint64(len(existing))
	var warnings []string
	c = Default()
	c.AddDebugLink = debugFile
	c.Warnf = func(format string, args ...any) { warnings = append(warnings, format) }
	if err := applyDebugLink(g, c); err != nil {
		t.Fatalf("existing debuglink: %v", err)
	}
	count := 0
	for _, s := range g.Sections {
		if s.Name == ".gnu_debuglink" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicate .gnu_debuglink sections: %d", count)
	}
	if len(warnings) == 0 {
		t.Error("an existing .gnu_debuglink must produce a warning")
	}
}
