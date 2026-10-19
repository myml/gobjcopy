package objcopy

// Coverage-oriented tests for contents.go: --reverse-bytes, the --interleave
// family, the section-content filter, and their interaction with -j and with
// both binary and ELF output.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

func ccWriteELF(t *testing.T, class elf.Class, data elf.Data, secs ...*elf.Section) string {
	t.Helper()
	f := ccFile(class, data, secs...)
	b, err := f.Bytes()
	if err != nil {
		t.Fatalf("serialise input: %v", err)
	}
	p := filepath.Join(t.TempDir(), "in.o")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCoverageApplySectionContentsNoop(t *testing.T) {
	orig := []byte{1, 2, 3, 4}
	f := ccFile(elf.Class64, elf.DataLSB, covData(".data", 0, append([]byte(nil), orig...)))
	if err := Default().applySectionContents(f); err != nil {
		t.Fatal(err)
	}
	if got := f.Section(".data"); !bytes.Equal(got.Data, orig) || got.Size != 4 {
		t.Errorf("no-op changed the section: %v", got.Data)
	}

	// ReverseBytes alone must not enable interleaving, and vice versa.
	f = ccFile(elf.Class64, elf.DataLSB, covData(".data", 0, append([]byte(nil), orig...)))
	if err := (&Config{ReverseBytes: 2}).applySectionContents(f); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.Section(".data").Data, []byte{2, 1, 4, 3}) {
		t.Errorf("reverse-only = %v", f.Section(".data").Data)
	}

	f = ccFile(elf.Class64, elf.DataLSB, covData(".data", 0, append([]byte(nil), orig...)))
	c := Default()
	c.Interleave = 2
	// A negative Byte (the "unset" sentinel) disables interleaving.
	if err := c.applySectionContents(f); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.Section(".data").Data, orig) {
		t.Errorf("unset byte interleaved: %v", f.Section(".data").Data)
	}
}

func TestCoverageReverseChunks(t *testing.T) {
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	reverseChunks(data, 4)
	want := []byte{3, 2, 1, 0, 7, 6, 5, 4, 8, 9}
	if !bytes.Equal(data, want) {
		t.Errorf("reverseChunks = %v want %v", data, want)
	}
	// A chunk larger than the data and a chunk of one are both no-ops.
	reverseChunks(data, 100)
	reverseChunks(data, 1)
	if !bytes.Equal(data, want) {
		t.Error("reverseChunks modified data for a no-op chunk size")
	}
}

func TestCoverageReverseBytesSections(t *testing.T) {
	f := ccFile(elf.Class64, elf.DataLSB,
		covData(".text", 0, []byte{1, 2, 3, 4}),
		covData(".data", 0x10, []byte{5, 6, 7, 8, 9, 10}),
		ccSection(".symtab", elf.SHT_SYMTAB, 0, []byte{1, 2}),
		ccSection(".strtab", elf.SHT_STRTAB, 0, []byte{3, 4}),
		ccSection(".group", elf.SHT_GROUP, 0, []byte{5, 6}),
		&elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".bss", Type: elf.SHT_NOBITS, Flags: elf.SHF_ALLOC, Size: 4,
		}},
		&elf.Section{SectionHeader: elf.SectionHeader{Name: ".empty", Type: elf.SHT_PROGBITS}},
	)
	c := Default()
	c.ReverseBytes = 2
	if err := c.applySectionContents(f); err != nil {
		t.Fatal(err)
	}
	if got := f.Section(".text"); !bytes.Equal(got.Data, []byte{2, 1, 4, 3}) {
		t.Errorf(".text = %v", got.Data)
	}
	if got := f.Section(".data"); !bytes.Equal(got.Data, []byte{6, 5, 8, 7, 10, 9}) {
		t.Errorf(".data = %v", got.Data)
	}
	for _, name := range []string{".symtab", ".strtab", ".group"} {
		if got := f.Section(name); len(got.Data) != 2 || got.Data[0] != map[string]byte{
			".symtab": 1, ".strtab": 3, ".group": 5,
		}[name] {
			t.Errorf("%s was transformed: %v", name, got.Data)
		}
	}
	if got := f.Section(".bss"); got.Data != nil {
		t.Errorf(".bss was transformed: %v", got.Data)
	}
}

func TestCoverageReverseBytesFatalError(t *testing.T) {
	f := ccFile(elf.Class64, elf.DataLSB, covData(".data", 0, []byte{1, 2, 3}))
	err := (&Config{ReverseBytes: 4}).applySectionContents(f)
	if err == nil {
		t.Fatal("non-multiple reverse must fail")
	}
	var fatal *FatalError
	if !errors.As(err, &fatal) {
		t.Fatalf("error = %T, want *FatalError", err)
	}
	if !strings.Contains(fatal.Error(), "must be evenly divisible by 4") {
		t.Errorf("error = %q", fatal.Error())
	}
}

func TestCoverageHasCopiedContents(t *testing.T) {
	for _, tc := range []struct {
		sec  *elf.Section
		want bool
	}{
		{ccSection(".text", elf.SHT_PROGBITS, 0, []byte{1}), true},
		{ccSection(".data", elf.SHT_PROGBITS, 0, []byte{1}), true},
		{&elf.Section{}, false}, // SHT_NULL
		{ccSection(".symtab", elf.SHT_SYMTAB, 0, []byte{1}), false},
		{ccSection(".dynsym", elf.SHT_DYNSYM, 0, []byte{1}), false},
		{ccSection(".strtab", elf.SHT_STRTAB, 0, []byte{1}), false},
		{ccSection(".symtab_shndx", elf.SHT_SYMTAB_SHNDX, 0, []byte{1}), false},
		{ccSection(".group", elf.SHT_GROUP, 0, []byte{1}), false},
		{&elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".bss", Type: elf.SHT_NOBITS, Size: 4,
		}}, false},
		{ccSection(".empty", elf.SHT_PROGBITS, 0, nil), false},
	} {
		if got := hasCopiedContents(tc.sec); got != tc.want {
			t.Errorf("hasCopiedContents(%q, type %d) = %v want %v",
				tc.sec.Name, tc.sec.Type, got, tc.want)
		}
	}
}

func TestCoverageInterleaveAlgorithm(t *testing.T) {
	cases := []struct {
		name  string
		data  []byte
		lma   uint64
		il    int
		byt   int
		width int
		want  []byte
		wantL uint64
	}{
		{
			name: "basic",
			data: []byte("12345678\n"),
			il:   4, byt: 0, width: 2,
			want: []byte("1256\n6"),
			// The trailing bytes past the compacted ones keep the old value.
			wantL: 0,
		},
		{
			name: "lma bias and width boundary",
			data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
			lma:  1,
			il:   4, byt: 0, width: 4,
			// from = 0 - 1 + 4 = 3: 3,4,5,6 then 7,8; newSize = 12 and the
			// bytes at offsets 6..8 keep their original values.
			want:  []byte{4, 5, 6, 7, 8, 9, 7, 8, 9, 0, 0, 0},
			wantL: 1,
		},
		{
			name: "byte at extra",
			data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
			lma:  2,
			il:   4, byt: 2, width: 2,
			want:  []byte{1, 2, 5, 6},
			wantL: 0,
		},
		{
			name: "max width",
			data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
			lma:  0,
			il:   4, byt: 1, width: 3,
			want:  []byte{2, 3, 4, 6, 7, 8},
			wantL: 0,
		},
		{
			name: "byte last",
			data: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			lma:  0,
			il:   4, byt: 3, width: 1,
			want:  []byte{4, 8},
			wantL: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sec := covData(".data", tc.lma, append([]byte(nil), tc.data...))
			f := ccFile(elf.Class64, elf.DataLSB, sec)
			c := Default()
			c.Interleave = tc.il
			c.Byte = tc.byt
			c.InterleaveWidth = tc.width
			if err := c.applySectionContents(f); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sec.Data, tc.want) {
				t.Errorf("data = %v want %v", sec.Data, tc.want)
			}
			if sec.Size != uint64(len(sec.Data)) {
				t.Errorf("size = %d want %d", sec.Size, len(sec.Data))
			}
			if sec.LMA == nil || *sec.LMA != tc.wantL {
				t.Errorf("lma = %v want %d", sec.LMA, tc.wantL)
			}
		})
	}
}

func TestCoverageInterleaveWithOnlySection(t *testing.T) {
	text := covData(".text", 0, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	data := covData(".data", 0, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	f := ccFile(elf.Class64, elf.DataLSB, text, data)
	c := Default()
	c.OnlySections = []string{".data"}
	c.Interleave = 4
	c.Byte = 0
	c.InterleaveWidth = 1
	if err := Transform(f, c); err != nil {
		t.Fatal(err)
	}
	if f.Section(".text") != nil {
		t.Error("-j did not remove .text")
	}
	if got := f.Section(".data"); !bytes.Equal(got.Data, []byte{1, 5}) {
		t.Errorf("interleaved .data = %v", got.Data)
	}
}

func TestCoverageInterleaveValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{"missing byte", &Config{Interleave: 4, InterleaveWidth: 1, Byte: -1}, "interleave start byte must be set with --byte"},
		{"byte too large", &Config{Interleave: 4, InterleaveWidth: 1, Byte: 4}, "byte number must be less than interleave"},
		{"width too large", &Config{Interleave: 4, InterleaveWidth: 3, Byte: 2}, "interleave width must be less than or equal to interleave - byte"},
		{"valid", &Config{Interleave: 4, InterleaveWidth: 2, Byte: 1}, ""},
	}
	for _, tc := range cases {
		err := tc.cfg.Validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error = %v want %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestCoverageInterleaveBinaryOutput(t *testing.T) {
	in := ccWriteELF(t, elf.Class64, elf.DataLSB,
		covData(".text", 0, []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}))
	out := filepath.Join(t.TempDir(), "out.bin")
	c := Default()
	c.OutputTarget = "binary"
	c.Interleave = 4
	c.Byte = 0
	c.InterleaveWidth = 2
	if err := Run(c, in, out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0xAA, 0xBB, 0xEE, 0xFF}) {
		t.Errorf("binary interleave = % x", got)
	}
}

func TestCoverageInterleaveELFOutput(t *testing.T) {
	in := ccWriteELF(t, elf.Class64, elf.DataLSB,
		covData(".data", 0, []byte("abcdefgh")))
	out := filepath.Join(t.TempDir(), "out.o")
	c := Default()
	c.OutputTarget = "elf64-x86-64"
	c.Interleave = 4
	c.Byte = 0
	c.InterleaveWidth = 2
	if err := Run(c, in, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.Parse(data)
	if err != nil {
		t.Fatalf("output is not ELF: %v", err)
	}
	sec := f.Section(".data")
	if sec == nil {
		t.Fatal("missing .data")
	}
	if !bytes.Equal(sec.Data, []byte("abef")) {
		t.Errorf(".data = %q", sec.Data)
	}
	if sec.Size != 4 {
		t.Errorf(".data size = %d", sec.Size)
	}
}
