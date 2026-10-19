package objcopy

// Coverage-oriented tests for the debug-section compression code in
// compress.go: the zlib helpers, the gabi and GNU header formats, all
// compress/decompress entry points, section renaming (including relocation
// sections), and the error paths for corrupt input.

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

// ccFile wraps covELF and lets callers choose the ELF class and byte order.
func ccFile(class elf.Class, data elf.Data, secs ...*elf.Section) *elf.File {
	f := covELF(secs...)
	f.Class = class
	f.Data = data
	return f
}

// ccSection builds a debug or relocation section with explicit flags/type.
func ccSection(name string, typ uint32, flags uint64, data []byte) *elf.Section {
	return &elf.Section{
		SectionHeader: elf.SectionHeader{
			Name:      name,
			Type:      typ,
			Flags:     flags,
			Addralign: 1,
			Size:      uint64(len(data)),
		},
		Data: data,
	}
}

// ccGabi builds an SHF_COMPRESSED section payload in the gabi format.
func ccGabi(t *testing.T, class elf.Class, data elf.Data, raw []byte, align uint64) []byte {
	t.Helper()
	payload, err := compressZlib(raw)
	if err != nil {
		t.Fatal(err)
	}
	hdr := debugHeader(data.Order(), class, false, uint64(len(raw)), align)
	return append(hdr, payload...)
}

// ccGNU builds a ".zdebug_*" style payload: "ZLIB" + big-endian size + zlib.
func ccGNU(t *testing.T, raw []byte) []byte {
	t.Helper()
	payload, err := compressZlib(raw)
	if err != nil {
		t.Fatal(err)
	}
	hdr := debugHeader(binary.LittleEndian, elf.Class64, true, uint64(len(raw)), 0)
	return append(hdr, payload...)
}

func TestCoverageZlibHelpers(t *testing.T) {
	raw := bytes.Repeat([]byte("debug payload "), 40)
	comp, err := compressZlib(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(comp, raw) {
		t.Fatal("compressZlib did not change the data")
	}
	back, err := decompressZlib(comp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, raw) {
		t.Fatalf("roundtrip mismatch: %d vs %d bytes", len(back), len(raw))
	}

	// Invalid and truncated streams both fail cleanly.
	if _, err := decompressZlib([]byte("not a zlib stream")); err == nil {
		t.Error("decompressZlib accepted garbage")
	}
	if _, err := decompressZlib(comp[:len(comp)-3]); err == nil {
		t.Error("decompressZlib accepted a truncated stream")
	}
}

func TestCoverageApplyCompressionModes(t *testing.T) {
	raw := bytes.Repeat([]byte{0}, 256)

	// --decompress-debug-sections dispatches to decompressDebugSections.
	f := ccFile(elf.Class64, elf.DataLSB,
		ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED,
			ccGabi(t, elf.Class64, elf.DataLSB, raw, 1)))
	if err := applyCompression(f, &Config{DecompressDebug: true}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.Section(".debug_info").Data, raw) {
		t.Error("DecompressDebug did not decompress")
	}

	for _, mode := range []string{"", "none"} {
		g := ccFile(elf.Class64, elf.DataLSB, ccSection(".debug_info", elf.SHT_PROGBITS, 0, raw))
		if err := applyCompression(g, &Config{CompressDebug: mode}); err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if !bytes.Equal(g.Section(".debug_info").Data, raw) {
			t.Errorf("mode %q modified the section", mode)
		}
	}

	for _, mode := range []string{"zlib", "zlib-gabi"} {
		g := ccFile(elf.Class64, elf.DataLSB, ccSection(".debug_info", elf.SHT_PROGBITS, 0, raw))
		if err := applyCompression(g, &Config{CompressDebug: mode}); err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if g.Section(".debug_info").Flags&elf.SHF_COMPRESSED == 0 {
			t.Errorf("mode %q did not set SHF_COMPRESSED", mode)
		}
	}

	g := ccFile(elf.Class64, elf.DataLSB, ccSection(".debug_info", elf.SHT_PROGBITS, 0, raw))
	if err := applyCompression(g, &Config{CompressDebug: "zlib-gnu"}); err != nil {
		t.Fatal(err)
	}
	if g.Section(".zdebug_info") == nil {
		t.Error("zlib-gnu did not rename the section")
	}

	g = ccFile(elf.Class64, elf.DataLSB, ccSection(".debug_info", elf.SHT_PROGBITS, 0, raw))
	if err := applyCompression(g, &Config{CompressDebug: "bogus"}); err == nil ||
		!strings.Contains(err.Error(), "unknown compression type") {
		t.Errorf("unknown mode error = %v", err)
	}
}

func TestCoverageDecompressDebugSections(t *testing.T) {
	raw := bytes.Repeat([]byte("hello debug "), 20)

	t.Run("gabi64", func(t *testing.T) {
		data := ccGabi(t, elf.Class64, elf.DataLSB, raw, 16)
		f := ccFile(elf.Class64, elf.DataLSB,
			ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, data))
		if err := decompressDebugSections(f); err != nil {
			t.Fatal(err)
		}
		sec := f.Section(".debug_info")
		if !bytes.Equal(sec.Data, raw) || sec.Size != uint64(len(raw)) {
			t.Error("gabi64 contents not restored")
		}
		if sec.Flags&elf.SHF_COMPRESSED != 0 {
			t.Error("SHF_COMPRESSED not cleared")
		}
		if sec.Addralign != 16 {
			t.Errorf("Addralign = %d want 16", sec.Addralign)
		}
	})

	t.Run("gabi32 big endian", func(t *testing.T) {
		data := ccGabi(t, elf.Class32, elf.DataMSB, raw, 4)
		f := ccFile(elf.Class32, elf.DataMSB,
			ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, data))
		if err := decompressDebugSections(f); err != nil {
			t.Fatal(err)
		}
		sec := f.Section(".debug_info")
		if !bytes.Equal(sec.Data, raw) || sec.Addralign != 4 {
			t.Error("gabi32 contents/alignment not restored")
		}
	})

	t.Run("gabi zero alignment", func(t *testing.T) {
		data := ccGabi(t, elf.Class64, elf.DataLSB, raw, 0)
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, data)
		sec.Addralign = 3
		f := ccFile(elf.Class64, elf.DataLSB, sec)
		if err := decompressDebugSections(f); err != nil {
			t.Fatal(err)
		}
		if sec.Addralign != 3 {
			t.Errorf("Addralign = %d want the original 3", sec.Addralign)
		}
	})

	t.Run("gnu and relocations", func(t *testing.T) {
		sec := ccSection(".zdebug_line", elf.SHT_PROGBITS, 0, ccGNU(t, raw))
		rela := ccSection(".rela.zdebug_line", elf.SHT_RELA, 0, []byte{0})
		rela.Info = 1
		rel := ccSection(".rel.zdebug_line", elf.SHT_REL, 0, []byte{0})
		rel.Info = 1
		other := ccSection(".rela.text", elf.SHT_RELA, 0, []byte{0})
		other.Info = 2
		badInfo := ccSection(".rela.zdebug_line", elf.SHT_RELA, 0, []byte{0})
		badInfo.Info = 99
		f := ccFile(elf.Class64, elf.DataLSB, sec, rela, rel, other, badInfo)
		if err := decompressDebugSections(f); err != nil {
			t.Fatal(err)
		}
		if f.Section(".debug_line") == nil {
			t.Fatal("zdebug section not renamed")
		}
		if !bytes.Equal(f.Section(".debug_line").Data, raw) {
			t.Error("gnu contents not restored")
		}
		if f.Section(".rela.debug_line") == nil || f.Section(".rel.debug_line") == nil {
			t.Error("relocation sections not renamed")
		}
		if f.Section(".rela.text") == nil {
			t.Error("unrelated relocation section was renamed")
		}
		if len(badInfo.Data) != 1 {
			t.Error("out-of-range relocation was modified")
		}
	})

	t.Run("reloc without rel prefix", func(t *testing.T) {
		sec := ccSection(".zdebug_info", elf.SHT_PROGBITS, 0, ccGNU(t, raw))
		rel := ccSection(".weird", elf.SHT_RELA, 0, []byte{0})
		rel.Info = 1
		f := ccFile(elf.Class64, elf.DataLSB, sec, rel)
		if err := decompressDebugSections(f); err != nil {
			t.Fatal(err)
		}
		if rel.Name != ".weird" {
			t.Errorf("relocation without .rel prefix renamed to %q", rel.Name)
		}
	})

	t.Run("skipped sections", func(t *testing.T) {
		nobits := &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".debug_info", Type: elf.SHT_NOBITS, Flags: elf.SHF_COMPRESSED, Size: 4,
		}}
		empty := ccSection(".debug_line", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, nil)
		plain := ccSection(".text", elf.SHT_PROGBITS, elf.SHF_ALLOC, []byte{1, 2})
		f := ccFile(elf.Class64, elf.DataLSB, nobits, empty, plain)
		if err := decompressDebugSections(f); err != nil {
			t.Fatal(err)
		}
		if nobits.Data != nil || !bytes.Equal(plain.Data, []byte{1, 2}) {
			t.Error("skipped sections changed")
		}
	})

	for _, tc := range []struct {
		name string
		sec  *elf.Section
		want string
	}{
		{"truncated header", ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, []byte{1, 2}), "truncated compression header"},
		{"bad type", func() *elf.Section {
			data := make([]byte, 24)
			binary.LittleEndian.PutUint32(data, 99)
			return ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, data)
		}(), "unsupported compression type"},
		{"size mismatch", func() *elf.Section {
			data := ccGabi(t, elf.Class64, elf.DataLSB, []byte{1, 2, 3}, 0)
			binary.LittleEndian.PutUint64(data[8:], 4)
			return ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, data)
		}(), "decompressed size mismatch"},
		{"bad gabi payload", func() *elf.Section {
			data := debugHeader(binary.LittleEndian, elf.Class64, false, 4, 0)
			data = append(data, []byte("junk")...)
			return ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, data)
		}(), "zlib"},
		{"bad gnu payload", func() *elf.Section {
			data := debugHeader(binary.LittleEndian, elf.Class64, true, 4, 0)
			data = append(data, []byte("junk")...)
			return ccSection(".zdebug_info", elf.SHT_PROGBITS, 0, data)
		}(), "zlib"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := ccFile(elf.Class64, elf.DataLSB, tc.sec)
			err := decompressDebugSections(f)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestCoverageDecodeDebugCompression(t *testing.T) {
	raw := bytes.Repeat([]byte("decode me "), 30)

	t.Run("raw", func(t *testing.T) {
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, 0, raw)
		sec.Addralign = 2
		dec, err := decodeDebugCompression(ccFile(elf.Class64, elf.DataLSB, sec), sec)
		if err != nil {
			t.Fatal(err)
		}
		if dec.compressed || dec.size != uint64(len(raw)) || dec.align != 2 ||
			!bytes.Equal(dec.payload, raw) {
			t.Errorf("raw decode = %+v", dec)
		}
	})

	t.Run("gabi", func(t *testing.T) {
		for _, class := range []elf.Class{elf.Class32, elf.Class64} {
			for _, data := range []elf.Data{elf.DataLSB, elf.DataMSB} {
				sec := ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED,
					ccGabi(t, class, data, raw, 8))
				dec, err := decodeDebugCompression(ccFile(class, data, sec), sec)
				if err != nil {
					t.Fatalf("class %v data %v: %v", class, data, err)
				}
				if !dec.compressed || dec.size != uint64(len(raw)) || dec.align != 8 {
					t.Errorf("class %v data %v decode = %+v", class, data, dec)
				}
				back, err := decompressZlib(dec.payload)
				if err != nil || !bytes.Equal(back, raw) {
					t.Errorf("class %v data %v payload mismatch", class, data)
				}
			}
		}
	})

	t.Run("gnu", func(t *testing.T) {
		sec := ccSection(".zdebug_info", elf.SHT_PROGBITS, 0, ccGNU(t, raw))
		dec, err := decodeDebugCompression(ccFile(elf.Class64, elf.DataLSB, sec), sec)
		if err != nil {
			t.Fatal(err)
		}
		if !dec.compressed || dec.size != uint64(len(raw)) || dec.align != 1 {
			t.Errorf("gnu decode = %+v", dec)
		}
	})

	t.Run("errors", func(t *testing.T) {
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, []byte{1, 2})
		if _, err := decodeDebugCompression(ccFile(elf.Class64, elf.DataLSB, sec), sec); err == nil {
			t.Error("truncated header accepted")
		}
		bad := make([]byte, 12)
		binary.LittleEndian.PutUint32(bad, 42)
		sec = ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, bad)
		if _, err := decodeDebugCompression(ccFile(elf.Class32, elf.DataLSB, sec), sec); err == nil {
			t.Error("unknown compression type accepted")
		}
	})
}

func TestCoverageDebugHeader(t *testing.T) {
	// The GNU header ignores the class and byte order.
	for _, class := range []elf.Class{elf.Class32, elf.Class64} {
		for _, data := range []elf.Data{elf.DataLSB, elf.DataMSB} {
			hdr := debugHeader(data.Order(), class, true, 0x1122334455667788, 16)
			if len(hdr) != 12 || string(hdr[:4]) != "ZLIB" {
				t.Fatalf("gnu header = % x", hdr)
			}
			if got := binary.BigEndian.Uint64(hdr[4:]); got != 0x1122334455667788 {
				t.Errorf("gnu size = %#x", got)
			}
		}
	}

	for _, data := range []elf.Data{elf.DataLSB, elf.DataMSB} {
		order := data.Order()
		hdr := debugHeader(order, elf.Class64, false, 0x1000, 32)
		if len(hdr) != 24 || order.Uint32(hdr) != elfCompressZlib ||
			order.Uint64(hdr[8:]) != 0x1000 || order.Uint64(hdr[16:]) != 32 {
			t.Errorf("%v gabi64 header = % x", data, hdr)
		}
		hdr = debugHeader(order, elf.Class32, false, 0x2000, 16)
		if len(hdr) != 12 || order.Uint32(hdr) != elfCompressZlib ||
			order.Uint32(hdr[4:]) != 0x2000 || order.Uint32(hdr[8:]) != 16 {
			t.Errorf("%v gabi32 header = % x", data, hdr)
		}
	}
}

func TestCoverageRenameDebug(t *testing.T) {
	cases := []struct {
		name string
		gnu  bool
		want string
		ok   bool
	}{
		{".debug_info", true, ".zdebug_info", true},
		{".zdebug_info", true, ".zdebug_info", true},
		{".text", true, ".text", false},
		{".debug_info", false, ".debug_info", true},
		{".zdebug_info", false, ".debug_info", true},
		{".text", false, ".text", true},
	}
	for _, tc := range cases {
		got, ok := renameDebug(tc.name, tc.gnu)
		if got != tc.want || ok != tc.ok {
			t.Errorf("renameDebug(%q, %v) = %q, %v; want %q, %v",
				tc.name, tc.gnu, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCoverageDebugRaw(t *testing.T) {
	raw := bytes.Repeat([]byte("raw "), 30)

	t.Run("raw", func(t *testing.T) {
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, 0, raw)
		got, compressed, err := debugRaw(ccFile(elf.Class64, elf.DataLSB, sec), sec)
		if err != nil || compressed || !bytes.Equal(got, raw) {
			t.Errorf("raw = %q %v %v", got, compressed, err)
		}
	})

	t.Run("gabi", func(t *testing.T) {
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED,
			ccGabi(t, elf.Class64, elf.DataLSB, raw, 1))
		got, compressed, err := debugRaw(ccFile(elf.Class64, elf.DataLSB, sec), sec)
		if err != nil || !compressed || !bytes.Equal(got, raw) {
			t.Errorf("gabi = %q %v %v", got, compressed, err)
		}
	})

	t.Run("gnu", func(t *testing.T) {
		sec := ccSection(".zdebug_info", elf.SHT_PROGBITS, 0, ccGNU(t, raw))
		got, compressed, err := debugRaw(ccFile(elf.Class64, elf.DataLSB, sec), sec)
		if err != nil || !compressed || !bytes.Equal(got, raw) {
			t.Errorf("gnu = %q %v %v", got, compressed, err)
		}
	})

	t.Run("zdebug without magic is raw", func(t *testing.T) {
		sec := ccSection(".zdebug_info", elf.SHT_PROGBITS, 0, []byte("short"))
		got, compressed, err := debugRaw(ccFile(elf.Class64, elf.DataLSB, sec), sec)
		if err != nil || compressed || string(got) != "short" {
			t.Errorf("short zdebug = %q %v %v", got, compressed, err)
		}
	})

	t.Run("errors", func(t *testing.T) {
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, []byte{1})
		if _, _, err := debugRaw(ccFile(elf.Class64, elf.DataLSB, sec), sec); err == nil {
			t.Error("truncated header accepted")
		}
		bad := make([]byte, 24)
		binary.LittleEndian.PutUint32(bad, 7)
		sec = ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, bad)
		if _, _, err := debugRaw(ccFile(elf.Class64, elf.DataLSB, sec), sec); err == nil {
			t.Error("bad compression type accepted")
		}
		sec = ccSection(".zdebug_info", elf.SHT_PROGBITS, 0, append(
			debugHeader(binary.LittleEndian, elf.Class64, true, 4, 0), []byte("junk")...))
		if _, compressed, err := debugRaw(ccFile(elf.Class64, elf.DataLSB, sec), sec); err == nil || !compressed {
			t.Errorf("bad gnu payload = %v, %v", compressed, err)
		}
	})
}

func TestCoverageCompressDebugGABI(t *testing.T) {
	raw := bytes.Repeat([]byte("compress me "), 50)

	t.Run("64-bit", func(t *testing.T) {
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, 0, raw)
		sec.Addralign = 1
		f := ccFile(elf.Class64, elf.DataLSB, sec)
		if err := compressDebugGABI(f); err != nil {
			t.Fatal(err)
		}
		if sec.Flags&elf.SHF_COMPRESSED == 0 || sec.Size != uint64(len(sec.Data)) {
			t.Fatal("section not marked compressed")
		}
		if sec.Addralign != 8 {
			t.Errorf("Addralign = %d want 8", sec.Addralign)
		}
		if len(sec.Data) < 24 || binary.LittleEndian.Uint32(sec.Data) != elfCompressZlib {
			t.Fatal("bad gabi header")
		}
		if binary.LittleEndian.Uint64(sec.Data[8:]) != uint64(len(raw)) {
			t.Error("bad uncompressed size")
		}
		back, err := decompressZlib(sec.Data[24:])
		if err != nil || !bytes.Equal(back, raw) {
			t.Error("payload does not roundtrip")
		}
	})

	t.Run("32-bit", func(t *testing.T) {
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, 0, raw)
		f := ccFile(elf.Class32, elf.DataLSB, sec)
		if err := compressDebugGABI(f); err != nil {
			t.Fatal(err)
		}
		if len(sec.Data) < 12 || binary.LittleEndian.Uint32(sec.Data[4:]) != uint32(len(raw)) {
			t.Error("bad 32-bit gabi header")
		}
		if sec.Addralign != 4 {
			t.Errorf("Addralign = %d want 4", sec.Addralign)
		}
	})

	t.Run("not profitable", func(t *testing.T) {
		small := []byte{1, 2, 3}
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, 0, small)
		f := ccFile(elf.Class64, elf.DataLSB, sec)
		if err := compressDebugGABI(f); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sec.Data, small) || sec.Flags&elf.SHF_COMPRESSED != 0 {
			t.Error("incompressible section was compressed")
		}
	})

	t.Run("already compressed is skipped", func(t *testing.T) {
		data := ccGabi(t, elf.Class64, elf.DataLSB, raw, 1)
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, data)
		f := ccFile(elf.Class64, elf.DataLSB, sec)
		if err := compressDebugGABI(f); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sec.Data, data) {
			t.Error("already compressed section was rewritten")
		}
	})

	t.Run("gnu input is converted and relocs renamed", func(t *testing.T) {
		gnu := ccGNU(t, raw)
		sec := ccSection(".zdebug_info", elf.SHT_PROGBITS, 0, gnu)
		rela := ccSection(".rela.zdebug_info", elf.SHT_RELA, 0, []byte{0})
		rela.Info = 1
		f := ccFile(elf.Class64, elf.DataLSB, sec, rela)
		if err := compressDebugGABI(f); err != nil {
			t.Fatal(err)
		}
		if sec.Name != ".debug_info" || sec.Flags&elf.SHF_COMPRESSED == 0 {
			t.Fatalf("section = %q flags %#x", sec.Name, sec.Flags)
		}
		if !bytes.Equal(sec.Data[24:], gnu[12:]) {
			t.Error("zlib payload was recompressed instead of moved")
		}
		if rela.Name != ".rela.debug_info" {
			t.Errorf("relocation = %q", rela.Name)
		}
	})

	t.Run("gnu input not profitable keeps contents", func(t *testing.T) {
		// A .zdebug payload whose gabi form would be larger: 12+P < size but
		// 24+P >= size, i.e. P in [size-24, size-12).
		var rawSmall []byte
		var payload []byte
		for size := 32; size < 200; size++ {
			candidate := bytes.Repeat([]byte{0}, size)
			comp, err := compressZlib(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if 12+len(comp) < size && 24+len(comp) >= size {
				rawSmall, payload = candidate, comp
				break
			}
		}
		if payload == nil {
			t.Skip("no size with the required compression ratio")
		}
		gnu := append(debugHeader(binary.LittleEndian, elf.Class64, true,
			uint64(len(rawSmall)), 0), payload...)
		sec := ccSection(".zdebug_info", elf.SHT_PROGBITS, 0, gnu)
		rel := ccSection(".rel.zdebug_info", elf.SHT_REL, 0, []byte{0})
		rel.Info = 1
		f := ccFile(elf.Class64, elf.DataLSB, sec, rel)
		if err := compressDebugGABI(f); err != nil {
			t.Fatal(err)
		}
		if sec.Name != ".debug_info" || !bytes.Equal(sec.Data, rawSmall) ||
			sec.Flags&elf.SHF_COMPRESSED != 0 {
			t.Errorf("section = %q len %d flags %#x", sec.Name, len(sec.Data), sec.Flags)
		}
		if rel.Name != ".rel.debug_info" {
			t.Errorf("relocation = %q", rel.Name)
		}
	})

	t.Run("non-debug sections untouched", func(t *testing.T) {
		nobits := &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".debug_nobits", Type: elf.SHT_NOBITS, Size: 8,
		}}
		empty := ccSection(".debug_empty", elf.SHT_PROGBITS, 0, nil)
		alloc := ccSection(".debug_alloc", elf.SHT_PROGBITS, elf.SHF_ALLOC, raw)
		text := ccSection(".text", elf.SHT_PROGBITS, elf.SHF_ALLOC, raw)
		other := ccSection(".comment", elf.SHT_PROGBITS, 0, raw)
		f := ccFile(elf.Class64, elf.DataLSB, nobits, empty, alloc, text, other)
		if err := compressDebugGABI(f); err != nil {
			t.Fatal(err)
		}
		for _, s := range []*elf.Section{nobits, empty, alloc, text, other} {
			if s.Flags&elf.SHF_COMPRESSED != 0 {
				t.Errorf("%s was compressed", s.Name)
			}
		}
	})
}

func TestCoverageCompressDebugGNU(t *testing.T) {
	raw := bytes.Repeat([]byte("gunzip me "), 50)

	t.Run("raw section", func(t *testing.T) {
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, 0, raw)
		rela := ccSection(".rela.debug_info", elf.SHT_RELA, 0, []byte{0})
		rela.Info = 1
		rel := ccSection(".rel.debug_info", elf.SHT_REL, 0, []byte{0})
		rel.Info = 1
		f := ccFile(elf.Class64, elf.DataLSB, sec, rela, rel)
		if err := compressDebugGNU(f); err != nil {
			t.Fatal(err)
		}
		if sec.Name != ".zdebug_info" || sec.Flags&elf.SHF_COMPRESSED != 0 {
			t.Fatalf("section = %q flags %#x", sec.Name, sec.Flags)
		}
		if string(sec.Data[:4]) != "ZLIB" || binary.BigEndian.Uint64(sec.Data[4:]) != uint64(len(raw)) {
			t.Fatal("bad GNU header")
		}
		back, err := decompressZlib(sec.Data[12:])
		if err != nil || !bytes.Equal(back, raw) {
			t.Error("payload does not roundtrip")
		}
		if rela.Name != ".rela.zdebug_info" || rel.Name != ".rel.zdebug_info" {
			t.Errorf("relocations = %q %q", rela.Name, rel.Name)
		}
	})

	t.Run("renames even when larger", func(t *testing.T) {
		// The GNU .zdebug_* form always renames, unlike zlib-gabi: binutils'
		// archive tests rely on a tiny .debug_line still becoming .zdebug_line.
		small := []byte{1, 2, 3}
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, 0, small)
		f := ccFile(elf.Class64, elf.DataLSB, sec)
		if err := compressDebugGNU(f); err != nil {
			t.Fatal(err)
		}
		if sec.Name != ".zdebug_info" || string(sec.Data[:4]) != "ZLIB" {
			t.Errorf("section = %q data % x", sec.Name, sec.Data[:4])
		}
		if binary.BigEndian.Uint64(sec.Data[4:]) != uint64(len(small)) {
			t.Error("bad uncompressed size")
		}
	})

	t.Run("gabi payload is moved", func(t *testing.T) {
		gabi := ccGabi(t, elf.Class64, elf.DataLSB, raw, 1)
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, gabi)
		f := ccFile(elf.Class64, elf.DataLSB, sec)
		if err := compressDebugGNU(f); err != nil {
			t.Fatal(err)
		}
		if sec.Name != ".zdebug_info" || sec.Flags&elf.SHF_COMPRESSED != 0 {
			t.Fatalf("section = %q flags %#x", sec.Name, sec.Flags)
		}
		if !bytes.Equal(sec.Data[12:], gabi[24:]) {
			t.Error("zlib payload was recompressed instead of moved")
		}
		if string(sec.Data[:4]) != "ZLIB" {
			t.Error("missing ZLIB magic")
		}
	})

	t.Run("gabi input with a large payload is still moved", func(t *testing.T) {
		// Even when the GNU header would not make the section smaller, the
		// zlib stream is moved and the section renamed.
		rawBytes := make([]byte, 64)
		for i := range rawBytes {
			rawBytes[i] = byte(i*37 + 11)
		}
		payload, err := compressZlib(rawBytes)
		if err != nil {
			t.Fatal(err)
		}
		data := debugHeader(binary.LittleEndian, elf.Class64, false, uint64(len(rawBytes)), 1)
		data = append(data, payload...)
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, data)
		f := ccFile(elf.Class64, elf.DataLSB, sec)
		if err := compressDebugGNU(f); err != nil {
			t.Fatal(err)
		}
		if sec.Name != ".zdebug_info" || sec.Flags&elf.SHF_COMPRESSED != 0 {
			t.Errorf("section = %q flags %#x", sec.Name, sec.Flags)
		}
		if !bytes.Equal(sec.Data[12:], payload) {
			t.Error("payload was not moved verbatim")
		}
	})

	t.Run("already gnu is skipped", func(t *testing.T) {
		data := ccGNU(t, raw)
		sec := ccSection(".zdebug_info", elf.SHT_PROGBITS, 0, data)
		f := ccFile(elf.Class64, elf.DataLSB, sec)
		if err := compressDebugGNU(f); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sec.Data, data) || sec.Name != ".zdebug_info" {
			t.Error("gnu section was rewritten")
		}
	})

	t.Run("errors", func(t *testing.T) {
		sec := ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, []byte{1, 2})
		if err := compressDebugGNU(ccFile(elf.Class64, elf.DataLSB, sec)); err == nil {
			t.Error("truncated header accepted")
		}
		bad := make([]byte, 24)
		binary.LittleEndian.PutUint32(bad, 9)
		sec = ccSection(".debug_info", elf.SHT_PROGBITS, elf.SHF_COMPRESSED, bad)
		if err := compressDebugGNU(ccFile(elf.Class64, elf.DataLSB, sec)); err == nil {
			t.Error("unknown compression type accepted")
		}
	})

	t.Run("non-debug sections untouched", func(t *testing.T) {
		text := ccSection(".text", elf.SHT_PROGBITS, elf.SHF_ALLOC, raw)
		nobits := &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".debug_bss", Type: elf.SHT_NOBITS, Size: 4,
		}}
		empty := ccSection(".debug_empty", elf.SHT_PROGBITS, 0, nil)
		f := ccFile(elf.Class64, elf.DataLSB, text, nobits, empty)
		if err := compressDebugGNU(f); err != nil {
			t.Fatal(err)
		}
		for _, s := range []*elf.Section{text, nobits, empty} {
			if s.Flags&elf.SHF_COMPRESSED != 0 {
				t.Errorf("%s was compressed", s.Name)
			}
		}
	})
}

func TestCoverageRenameRelocsTo(t *testing.T) {
	debug := ccSection(".debug_info", elf.SHT_PROGBITS, 0, []byte{1})
	rela := ccSection(".rela.debug_info", elf.SHT_RELA, 0, []byte{0})
	rela.Info = 1
	rel := ccSection(".rel.debug_info", elf.SHT_REL, 0, []byte{0})
	rel.Info = 1
	other := ccSection(".rela.text", elf.SHT_RELA, 0, []byte{0})
	other.Info = 2
	bad := ccSection(".rela.debug_info", elf.SHT_RELA, 0, []byte{0})
	bad.Info = 42
	f := ccFile(elf.Class64, elf.DataLSB, debug, rela, rel, other, bad)

	// The target section is renamed before renameRelocsTo runs, exactly as
	// compressDebugGNU/compressDebugGABI do.
	debug.Name = ".zdebug_info"
	renameRelocsTo(f, map[string]string{".debug_info": ".zdebug_info"})
	if rela.Name != ".rela.zdebug_info" || rel.Name != ".rel.zdebug_info" {
		t.Errorf("relocations = %q %q", rela.Name, rel.Name)
	}
	if other.Name != ".rela.text" {
		t.Errorf("unrelated relocation = %q", other.Name)
	}

	// An empty map is a no-op.
	before := rela.Name
	renameRelocsTo(f, nil)
	if rela.Name != before {
		t.Error("nil rename map changed names")
	}

	// A relocation applying to a section that was not renamed is left alone.
	plain := ccSection(".rela.other", elf.SHT_RELA, 0, []byte{0})
	plain.Info = 1
	g := ccFile(elf.Class64, elf.DataLSB,
		ccSection(".other", elf.SHT_PROGBITS, 0, []byte{1}), plain)
	renameRelocsTo(g, map[string]string{".debug_info": ".zdebug_info"})
	if plain.Name != ".rela.other" {
		t.Errorf("relocation = %q", plain.Name)
	}
}

func TestCoverageSectionHasRelocs(t *testing.T) {
	f := ccFile(elf.Class64, elf.DataLSB,
		ccSection(".text", elf.SHT_PROGBITS, elf.SHF_ALLOC, []byte{1}),
		ccSection(".rela.text", elf.SHT_RELA, 0, []byte{0}),
		ccSection(".rel.text", elf.SHT_REL, 0, []byte{0}))
	f.Sections[2].Info = 1
	f.Sections[3].Info = 2

	if !sectionHasRelocs(f, 1) || !sectionHasRelocs(f, 2) {
		t.Error("relocations not detected")
	}
	if sectionHasRelocs(f, 0) || sectionHasRelocs(f, 3) || sectionHasRelocs(f, 99) {
		t.Error("false positive relocation")
	}
}
