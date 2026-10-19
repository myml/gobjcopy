package objcopy

// Coverage-oriented tests for raw binary output, the synthetic ELF image built
// from "-I binary", and the Run/Transform driver paths (target selection,
// verbatim copies, validation errors and the digest shortcut).

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/fixtures"
)

func TestBinarySymbolBase(t *testing.T) {
	cases := map[string]string{
		"/tmp/a.o":         "a_o",
		"dir/sub/file.bin": "file_bin",
		"plain":            "plain",
		"weird name-1+x":   "weird_name_1_x",
		// filepath.Base("") is ".", which mangles to "_".
		"": "_",
	}
	for in, want := range cases {
		if got := binarySymbolBase(in); got != want {
			t.Errorf("binarySymbolBase(%q) = %q want %q", in, got, want)
		}
	}
}

func TestGrow(t *testing.T) {
	if got := grow(nil, 3, 0); len(got) != 3 || got[2] != 0 {
		t.Errorf("grow zero fill = %v", got)
	}
	got := grow([]byte{1}, 4, 0xaa)
	if len(got) != 4 || got[0] != 1 || got[1] != 0xaa || got[3] != 0xaa {
		t.Errorf("grow fill = %v", got)
	}
	if got := grow([]byte{1, 2, 3}, 2, 0xff); len(got) != 3 {
		t.Errorf("grow shrinking = %v", got)
	}
}

func TestToBinaryLayout(t *testing.T) {
	// Sections out of LMA order are sorted, the lowest LMA becomes offset 0.
	a := covData(".a", 0x2000, []byte{0xaa, 0xbb})
	b := covData(".b", 0x1000, []byte{1, 2})
	nb := &elf.Section{SectionHeader: elf.SectionHeader{
		Name: ".nobits", Type: elf.SHT_NOBITS, Flags: elf.SHF_ALLOC, Addr: 0x1000, Size: 4,
	}}
	small := &elf.Section{SectionHeader: elf.SectionHeader{
		Name: ".empty", Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC, Addr: 0x1000,
	}}
	f := covELF(a, b, nb, small)

	out, err := ToBinary(f, Default())
	if err != nil {
		t.Fatal(err)
	}
	// .b at 0x1000 makes the base address; .a at 0x2000 leaves a gap.
	want := append([]byte{1, 2}, make([]byte, 0xffe)...)
	want = append(want, 0xaa, 0xbb)
	if !bytes.Equal(out, want) {
		t.Fatalf("ToBinary = % x (len %d) want len %d", out[:8], len(out), len(want))
	}

	// --gap-fill fills the hole with the requested byte.
	fill := uint64(0x55)
	out, err = ToBinary(covELF(a, b), &Config{GapFill: &fill})
	if err != nil {
		t.Fatal(err)
	}
	if out[2] != 0x55 || out[0xfff] != 0x55 {
		t.Errorf("gap fill bytes = %#x %#x", out[2], out[0xfff])
	}

	// --pad-to extends the image from the base address.
	pad := uint64(0x2004)
	out, err = ToBinary(covELF(a, b), &Config{PadTo: &pad})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0x1004 {
		t.Errorf("pad-to length = %#x want 0x1004", len(out))
	}
	// .a sits at 0x2000, i.e. offset 0x1000; its last byte is followed by the
	// two zero pad bytes.
	if out[0x1001] != 0xbb || out[0x1002] != 0 || out[0x1003] != 0 {
		t.Errorf("pad-to tail = %#x %#x %#x", out[0x1000], out[0x1001], out[0x1002])
	}

	// pad-to beyond the last section, with a fill.
	pad = uint64(0x2006)
	out, err = ToBinary(covELF(a, b), &Config{PadTo: &pad, GapFill: &fill})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0x1006 || out[len(out)-1] != 0x55 {
		t.Errorf("padded length/fill = %#x %#x", len(out), out[len(out)-1])
	}

	// A nil Config and a file with no allocated contents both work.
	if out, err := ToBinary(covELF(), nil); err != nil || out != nil {
		t.Errorf("empty ToBinary = %v, %v", out, err)
	}
	// Sections with an explicit LMA are honoured (bfd_set_section_lma).
	lma := uint64(0x10)
	sec := covData(".lma", 0x1000, []byte{7})
	sec.LMA = &lma
	out, err = ToBinary(covELF(sec), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0] != 7 {
		t.Errorf("explicit LMA output = %v", out)
	}
}

func TestSectionLMAFromSegments(t *testing.T) {
	f := &elf.File{
		Header: elf.Header{Class: elf.Class64, Data: elf.DataLSB, Type: elf.ET_EXEC},
		Segments: []*elf.ProgramHeader{
			{Type: elf.PT_LOAD, Vaddr: 0x1000, Paddr: 0x8000, Memsz: 0x100},
			{Type: elf.PT_LOAD, Vaddr: 0x2000, Memsz: 0},
		},
	}
	s := covData(".text", 0x1010, []byte{1})
	if got := sectionLMA(f, s); got != 0x8010 {
		t.Errorf("sectionLMA in segment = %#x want 0x8010", got)
	}
	// A section outside every segment falls back to its address.
	s = covData(".out", 0x5000, []byte{1})
	if got := sectionLMA(f, s); got != 0x5000 {
		t.Errorf("sectionLMA outside segments = %#x", got)
	}
}

func TestBinaryToELFAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(in, []byte("ABCD"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "blob.o")
	c := Default()
	c.InputTarget = "binary"
	c.OutputTarget = "elf64-x86-64"
	if err := Run(c, in, out); err != nil {
		t.Fatal(err)
	}
	f, err := elf.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	if sec := f.Section(".data"); sec == nil || string(sec.Data) != "ABCD" {
		t.Fatalf(".data = %+v", sec)
	}
	syms := symbolMap(t, f)
	for _, suffix := range []string{"_start", "_end", "_size"} {
		if _, ok := syms["_binary_blob_bin"+suffix]; !ok {
			t.Errorf("missing _binary_blob_bin%s symbol in %v", suffix, syms)
		}
	}

	// -B selects the architecture of the synthetic image.
	out = filepath.Join(dir, "blob32.o")
	c = Default()
	c.InputTarget = "binary"
	c.OutputTarget = "elf64-x86-64"
	c.BinaryArch = "i386"
	if err := Run(c, in, out); err != nil {
		t.Fatal(err)
	}

	// An unknown architecture is rejected when the output is not ELF.
	c = Default()
	c.InputTarget = "binary"
	c.OutputTarget = "binary"
	c.BinaryArch = "not-an-arch"
	if err := Run(c, in, filepath.Join(dir, "bad.o")); err == nil {
		t.Error("unknown -B architecture must fail")
	}
}

func TestBinaryInputReverseAndInterleave(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "seq")
	if err := os.WriteFile(in, []byte("abcdefgh"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(cfg *Config) []byte {
		t.Helper()
		out := filepath.Join(dir, "out")
		if err := Run(cfg, in, out); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	c := Default()
	c.InputTarget = "binary"
	c.OutputTarget = "binary"
	c.Interleave = 4
	c.Byte = 0
	c.InterleaveWidth = 2
	if got := run(c); string(got) != "abef" {
		t.Errorf("interleave = %q want %q", got, "abef")
	}

	c = Default()
	c.InputTarget = "binary"
	c.OutputTarget = "binary"
	c.ReverseBytes = 8
	c.PadTo = func() *uint64 { v := uint64(10); return &v }()
	c.GapFill = func() *uint64 { v := uint64(0x41); return &v }()
	if got := run(c); string(got) != "hgfedcbaAA" {
		t.Errorf("reverse+pad = %q", got)
	}
}

func TestRunInputErrors(t *testing.T) {
	dir := t.TempDir()
	if err := Run(Default(), filepath.Join(dir, "missing"), filepath.Join(dir, "out")); err == nil {
		t.Error("missing input must fail")
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Run(Default(), sub, filepath.Join(dir, "out")); err == nil {
		t.Error("directory input must fail")
	}
	junk := filepath.Join(dir, "junk")
	if err := os.WriteFile(junk, []byte("not an elf"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Run(Default(), junk, filepath.Join(dir, "out")); err == nil {
		t.Error("junk input must fail without -I")
	} else if !strings.Contains(err.Error(), "file format not recognized") {
		t.Errorf("junk error = %v", err)
	}
	// An output path in a missing directory is a write error.
	src, err := fixtures.BuildOne(dir, "reloc.o")
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	if err := Run(Default(), src, filepath.Join(dir, "nodir", "out")); err == nil {
		t.Error("unwritable output must fail")
	}
}

func TestRunOutputTargetErrors(t *testing.T) {
	dir := t.TempDir()
	src, err := fixtures.BuildOne(dir, "reloc.o")
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	out := filepath.Join(dir, "out")

	// Unknown target name.
	c := Default()
	c.OutputTarget = "no-such-target"
	if err := Run(c, src, out); err == nil {
		t.Error("unknown output target must fail")
	}

	// Byte order conversion is not supported.
	c = Default()
	c.OutputTarget = "elf64-big"
	if err := Run(c, src, out); err == nil {
		t.Error("endianness conversion must fail")
	} else if !strings.Contains(err.Error(), "cannot convert") {
		t.Errorf("endianness error = %v", err)
	}

	// --add-gnu-debuglink with binary output is rejected by Validate.
	c = Default()
	c.OutputTarget = "binary"
	c.AddDebugLink = src
	if err := Run(c, src, out); err == nil {
		t.Error("binary output with debuglink must fail")
	}

	// Binary input without -O defaults to binary output, like GNU.
	c = Default()
	c.InputTarget = "binary"
	raw := filepath.Join(dir, "raw")
	if err := os.WriteFile(raw, []byte("rawdata"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Run(c, raw, out); err != nil {
		t.Fatalf("binary input with default output: %v", err)
	}
	if data, err := os.ReadFile(out); err != nil || string(data) != "rawdata" {
		t.Errorf("binary passthrough = %q, %v", data, err)
	}

	// Binary to binary is a plain copy and must succeed.
	c = Default()
	c.InputTarget = "binary"
	c.OutputTarget = "binary"
	if err := Run(c, raw, out); err != nil {
		t.Errorf("binary to binary: %v", err)
	}
}

func TestRunValidationErrors(t *testing.T) {
	dir := t.TempDir()
	src, err := fixtures.BuildOne(dir, "reloc.o")
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"interleave-needs-byte", func(c *Config) { c.Interleave = 4 }, "interleave start byte must be set"},
		{"byte-too-large", func(c *Config) {
			c.Interleave = 2
			c.Byte = 3
		}, "byte number must be less than interleave"},
		{"width-too-large", func(c *Config) {
			c.Interleave = 4
			c.Byte = 2
			c.InterleaveWidth = 5
		}, "interleave width must be less than or equal to interleave - byte"},
		{"rename-empty-new", func(c *Config) { c.Renames = []Rename{{Old: ".text", New: ""}} }, "bad format for --rename-section"},
	}
	for _, tc := range cases {
		c := Default()
		tc.mutate(c)
		err := Run(c, src, filepath.Join(dir, "out"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v want %q", tc.name, err, tc.want)
		}
	}
}

func TestRunVerbatimCopyAndInPlace(t *testing.T) {
	dir := t.TempDir()
	src, err := fixtures.BuildOne(dir, "reloc.o")
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	orig, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "copy.o")
	var infos []string
	c := Default()
	c.OutputTarget = "elf64-x86-64"
	c.Infof = func(format string, args ...any) { infos = append(infos, format) }
	c.Verbose = true
	if err := Run(c, src, out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// The default target matches the input, so the file must be copied
	// verbatim.
	if !bytes.Equal(got, orig) {
		t.Error("verbatim copy differs from the input")
	}
	if len(infos) == 0 {
		t.Error("verbose run produced no progress messages")
	}

	// In place copy (no output operand) rewrites the same file.
	in := filepath.Join(dir, "inplace.o")
	if err := os.WriteFile(in, orig, 0o755); err != nil {
		t.Fatal(err)
	}
	c = Default()
	c.RemoveSections = []string{".comment"}
	if err := Run(c, in, ""); err != nil {
		t.Fatal(err)
	}
	mutated, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(mutated, orig) {
		t.Error("in place copy did not modify the file")
	}
	if fi, err := os.Stat(in); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("in place permissions = %v, %v", fi.Mode(), err)
	}

	// --preserve-dates keeps the modification time.
	old := filepath.Join(dir, "old.o")
	if err := os.WriteFile(old, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	late := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(old, late, late); err != nil {
		t.Fatal(err)
	}
	c = Default()
	c.PreserveDates = true
	c.RemoveSections = []string{".comment"}
	dst := filepath.Join(dir, "preserved.o")
	if err := Run(c, old, dst); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := os.Stat(old)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(ref.ModTime()) {
		t.Errorf("-p mtime = %v want %v", fi.ModTime(), ref.ModTime())
	}
}

func TestWarnMissing(t *testing.T) {
	var got []string
	c := Default()
	c.Warnf = func(format string, args ...any) { got = append(got, format) }
	c.warnMissing("section", ".missing")
	c.warnMissing("symbol", "missing")
	c.warnMissing("other", "x")
	if len(got) != 2 {
		t.Errorf("warnMissing calls = %v", got)
	}

	// warnf/infof without callbacks must not panic.
	quiet := Default()
	quiet.warnf("x")
	quiet.infof("y")
}

func TestTransformsContentAndDigest(t *testing.T) {
	if Default().transformsContent() {
		t.Error("the default config must not transform anything")
	}
	c := Default()
	c.PreserveDates = true
	c.Verbose = true
	c.Quiet = true
	if c.transformsContent() {
		t.Error("informational options must not change the output")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.StripAll = true },
		func(c *Config) { c.StripSymbols = []string{"x"} },
		func(c *Config) { c.Renames = []Rename{{Old: "a", New: "b"}} },
		func(c *Config) { c.SetSectionFlags = []SectionFlags{{Name: ".x", Flags: "alloc"}} },
		func(c *Config) { c.AddSections = []AddSection{{Name: ".x", File: "f"}} },
		func(c *Config) { c.UpdateSections = []UpdateSection{{Name: ".x", File: "f"}} },
		func(c *Config) { c.DumpSections = []DumpSection{{Name: ".x", File: "f"}} },
		func(c *Config) { c.AddSymbols = []AddSymbol{{Name: "n"}} },
		func(c *Config) { c.ChangeSectionVMA = []SectionAddr{{Name: ".x"}} },
		func(c *Config) { c.SetStart = new(uint64) },
		func(c *Config) { c.ChangeStart = new(int64) },
		func(c *Config) { c.ChangeAddresses = new(int64) },
		func(c *Config) { c.PadTo = new(uint64) },
		func(c *Config) { c.GapFill = new(uint64) },
		func(c *Config) { c.AddDebugLink = "f" },
		func(c *Config) { c.CompressDebug = "zlib" },
		func(c *Config) { c.Interleave = 2 },
		func(c *Config) { c.ReverseBytes = 2 },
		func(c *Config) { c.OnlySections = []string{".text"} },
		func(c *Config) { c.RemoveSections = []string{".text"} },
		func(c *Config) { c.KeepSections = []string{".text"} },
		func(c *Config) { c.RemoveRelocations = []string{".text"} },
		func(c *Config) { c.StripSectionHeaders = true },
		func(c *Config) { c.OnlyKeepDebug = true },
		func(c *Config) { c.ExtractDWO = true },
		func(c *Config) { c.DecompressDebug = true },
		func(c *Config) { c.ELFSTTCommon = "yes" },
		func(c *Config) { c.WeakenAll = true },
	} {
		cfg := Default()
		mutate(cfg)
		if !cfg.transformsContent() {
			t.Errorf("option %+v not detected as transforming", cfg)
		}
	}

	f := covELF(covData(".text", 0x1000, []byte{1, 2}))
	d1 := fileDigest(f)
	if d1 != fileDigest(f) {
		t.Error("digest is not stable")
	}
	f.Section(".text").Data[0] = 9
	if fileDigest(f) == d1 {
		t.Error("digest ignores section contents")
	}
	f = covELF(covData(".text", 0x1000, []byte{1}))
	f.Segments = []*elf.ProgramHeader{{Type: elf.PT_LOAD, Vaddr: 1, Memsz: 1}}
	d2 := fileDigest(f)
	f.Segments[0].Vaddr = 2
	if fileDigest(f) == d2 {
		t.Error("digest ignores segments")
	}
	lma := uint64(5)
	f.Section(".text").LMA = &lma
	d3 := fileDigest(f)
	lma = 6
	if fileDigest(f) == d3 {
		t.Error("digest ignores the LMA override")
	}
	f = covELF(covData(".text", 0x1000, []byte{1}))
	d4 := fileDigest(f)
	f.NoSectionHeaders = true
	if fileDigest(f) == d4 {
		t.Error("digest ignores NoSectionHeaders")
	}
}

func TestTransformStepOrder(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "newsec")
	if err := os.WriteFile(src, []byte{1, 2, 3, 4}, 0o644); err != nil {
		t.Fatal(err)
	}
	f := openFixtureFile(t, "custom")
	c := Default()
	c.Renames = []Rename{{Old: ".myrodata", New: ".renamed"}}
	c.SetSectionFlags = []SectionFlags{{Name: ".renamed", Flags: "alloc,code"}}
	c.AddSections = []AddSection{{Name: ".added", File: src}}
	c.UpdateSections = []UpdateSection{{Name: ".added", File: src}}
	c.RemoveRelocations = []string{".text"}
	c.ChangeSectionVMA = []SectionAddr{{Name: ".renamed", Op: AddrAdd, Val: 0x1000}}
	c.LocalizeSymbols = []string{"my_ro"}
	c.StripSymbols = []string{"hidden_local"}
	c.GapFill = func() *uint64 { v := uint64(0); return &v }()
	c.PadTo = func() *uint64 { v := uint64(0); return &v }()
	if err := Transform(f, c); err != nil {
		t.Fatalf("Transform: %v", err)
	}
	if sec := f.Section(".renamed"); sec == nil || sec.Flags&elf.SHF_EXECINSTR == 0 {
		t.Errorf("rename + set flags: %+v", f.Section(".renamed"))
	}
	if sec := f.Section(".added"); sec == nil || len(sec.Data) != 4 {
		t.Errorf("add + update section: %+v", sec)
	}
	syms := symbolMap(t, f)
	if _, ok := syms["hidden_local"]; ok {
		t.Error("strip-symbol did not remove the symbol")
	}
	if sym, ok := syms["my_ro"]; ok && sym.Bind() != elf.STB_LOCAL {
		t.Errorf("localize-symbol bind = %d", sym.Bind())
	}
}

func TestRunNilConfigAndInputTargetPaths(t *testing.T) {
	dir := t.TempDir()
	src, err := fixtures.BuildOne(dir, "reloc.o")
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	out := filepath.Join(dir, "out")
	// A nil Config means defaults.
	if err := Run(nil, src, out); err != nil {
		t.Fatalf("Run(nil): %v", err)
	}

	junk := filepath.Join(dir, "junk")
	if err := os.WriteFile(junk, []byte("not an elf at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	// An explicit ELF input target reports the parse error.
	c := Default()
	c.InputTarget = "elf64-x86-64"
	if err := Run(c, junk, out); err == nil {
		t.Error("bad ELF input with -I must fail")
	}

	// An input target that this build does not implement is unsupported.
	c = Default()
	c.InputTarget = "tekhex"
	if err := Run(c, junk, out); err == nil {
		t.Error("unsupported input target must fail")
	} else if !strings.Contains(err.Error(), "unsupported file format") {
		t.Errorf("unsupported target error = %v", err)
	}

	// A bad textual record makes the registered reader fail.
	bad := filepath.Join(dir, "bad.hex")
	if err := os.WriteFile(bad, []byte(":00000001XX\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c = Default()
	c.InputTarget = "ihex"
	if err := Run(c, bad, out); err == nil {
		t.Error("malformed ihex must fail")
	}

	// Transform also accepts a nil Config.
	if err := Transform(openFixtureFile(t, "reloc.o"), nil); err != nil {
		t.Errorf("Transform(nil): %v", err)
	}
}

func TestRunLegacyBinaryBranch(t *testing.T) {
	// The binary reader is registered by format_binary.go; unregister it
	// temporarily to exercise run.go's direct binary-input fallback.
	saved, had := inputReaders["binary"]
	delete(inputReaders, "binary")
	defer func() {
		if had {
			inputReaders["binary"] = saved
		}
	}()

	dir := t.TempDir()
	in := filepath.Join(dir, "blob")
	if err := os.WriteFile(in, []byte{1, 2, 3, 4}, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "blob.o")
	c := Default()
	c.InputTarget = "binary"
	c.OutputTarget = "elf64-x86-64"
	if err := Run(c, in, out); err != nil {
		t.Fatalf("binary fallback: %v", err)
	}
	f, err := elf.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	if sec := f.Section(".data"); sec == nil || len(sec.Data) != 4 {
		t.Errorf(".data = %+v", sec)
	}

	// The same fallback reports binaryOutputTarget failures.
	c = Default()
	c.InputTarget = "binary"
	if err := Run(c, in, out); err == nil {
		t.Error("binary input without -O must fail in the fallback path")
	}
	c = Default()
	c.InputTarget = "binary"
	c.OutputTarget = "binary"
	if err := Run(c, in, out); err == nil {
		t.Error("binary to binary must fail in the fallback path")
	}
	c = Default()
	c.InputTarget = "binary"
	c.OutputTarget = "ihex"
	if err := Run(c, in, out); err == nil {
		t.Error("binary to ihex must fail in the fallback path")
	}
	c = Default()
	c.InputTarget = "binary"
	c.OutputTarget = "elf64-x86-64"
	c.BinaryArch = "bogus-arch"
	if err := Run(c, in, out); err == nil {
		t.Error("unknown -B architecture must fail in the fallback path")
	}
}

func TestBinaryOutputTarget(t *testing.T) {
	cases := []struct {
		name   string
		cfg    *Config
		wantOK bool
		want   string
	}{
		{"no-target", &Config{}, false, "no output format specified"},
		{"bad-name", &Config{OutputTarget: "nonsense"}, false, ""},
		{"binary", &Config{OutputTarget: "binary"}, false, "cannot produce binary output"},
		{"ihex", &Config{OutputTarget: "ihex"}, false, "unsupported file format"},
		{"ok", &Config{OutputTarget: "elf64-x86-64"}, true, ""},
		{"bad-arch", &Config{OutputTarget: "elf64-x86-64", BinaryArch: "nope"}, false, "unrecognized architecture"},
	}
	for _, tc := range cases {
		tgt, err := binaryOutputTarget(tc.cfg)
		if tc.wantOK {
			if err != nil || tgt == nil || !tgt.IsELF {
				t.Errorf("%s: target = %v, err = %v", tc.name, tgt, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: expected an error, got %v", tc.name, tgt)
			continue
		}
		if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v want %q", tc.name, err, tc.want)
		}
	}
	// -B is applied to the resolved target.
	tgt, err := binaryOutputTarget(&Config{OutputTarget: "elf64-x86-64", BinaryArch: "i386"})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Class != elf.Class32 {
		t.Errorf("-B i386 class = %v", tgt.Class)
	}
}

func TestRunDigestShortcutWithUnmatchedOption(t *testing.T) {
	dir := t.TempDir()
	src, err := fixtures.BuildOne(dir, "reloc.o")
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	orig, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	var infos []string
	c := Default()
	c.RemoveSections = []string{".section-that-does-not-exist"}
	c.GapFill = func() *uint64 { v := uint64(0); return &v }()
	c.Verbose = true
	c.Infof = func(format string, args ...any) { infos = append(infos, format) }
	if err := Run(c, src, out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// The options changed nothing, so the input is copied verbatim and the
	// verbose shortcut messages fire.
	if !bytes.Equal(got, orig) {
		t.Error("unchanged transformation must copy the input verbatim")
	}
	joined := strings.Join(infos, "\n")
	if !strings.Contains(joined, "copy from") || !strings.Contains(joined, "copying to") {
		t.Errorf("verbose messages = %q", joined)
	}
}

func TestWriteResultErrors(t *testing.T) {
	dir := t.TempDir()
	src, err := fixtures.BuildOne(dir, "reloc.o")
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	fi, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing-dir", "out")
	if err := writeResult(missing, []byte("x"), fi, false, false); err == nil {
		t.Error("writeResult into a missing directory must fail")
	}
	if err := writeResult(missing, []byte("x"), fi, false, true); err == nil {
		t.Error("in-place writeResult into a missing directory must fail")
	}
	dst := filepath.Join(dir, "ok")
	if err := writeResult(dst, []byte("x"), fi, true, false); err != nil {
		t.Errorf("writeResult with preserve-dates: %v", err)
	}
}

func TestApplyNotesNilMerge(t *testing.T) {
	// Simulate a build without note merging: the hook must be a no-op.
	saved := noteMerge
	noteMerge = nil
	defer func() { noteMerge = saved }()
	if err := applyNotes(covELF(covData(".text", 0, []byte{1})), Default()); err != nil {
		t.Errorf("applyNotes without hook: %v", err)
	}
}
