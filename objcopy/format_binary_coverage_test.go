package objcopy

// Coverage-oriented tests for format_binary.go: the "-I binary" reader, its
// default output target, the ELF target/metadata handling, -B parsing, and
// the interaction with Run's verbatim-copy shortcut.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/bfdtarget"
)

func fbTarget(t *testing.T, name string) *bfdtarget.Target {
	t.Helper()
	tgt, err := bfdtarget.Parse(name)
	if err != nil {
		t.Fatalf("parse target %q: %v", name, err)
	}
	return tgt
}

func fbSymbols(t *testing.T, f *elf.File) map[string]elf.Symbol {
	t.Helper()
	sec := f.SectionByType(elf.SHT_SYMTAB)
	if sec == nil {
		t.Fatal("no .symtab")
	}
	st, err := f.ReadSymtab(sec)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]elf.Symbol{}
	for _, s := range st.Entries {
		if s.Name != "" {
			out[s.Name] = s
		}
	}
	return out
}

func TestCoverageReadBinaryDefault(t *testing.T) {
	data := []byte("hello binary")
	cfg := Default()
	f, err := readBinary(data, "/tmp/hello.bin", cfg, fbTarget(t, "binary"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputTarget != "binary" {
		t.Errorf("OutputTarget = %q, want binary (GNU output_target = input_target)", cfg.OutputTarget)
	}
	if f.Class != elf.Class64 || f.Data != elf.DataLSB || f.Machine != elf.EM_NONE {
		t.Errorf("header = class %v data %v machine %v", f.Class, f.Data, f.Machine)
	}
	if f.Type != elf.ET_REL || f.Version != elf.EV_CURRENT {
		t.Errorf("type/version = %v/%v", f.Type, f.Version)
	}
	sec := f.Section(".data")
	if sec == nil || !bytes.Equal(sec.Data, data) || sec.Size != uint64(len(data)) {
		t.Fatalf(".data = %+v", sec)
	}
	if sec.Flags&elf.SHF_ALLOC == 0 || sec.Flags&elf.SHF_WRITE == 0 {
		t.Error(".data flags lack ALLOC|WRITE")
	}
	syms := fbSymbols(t, f)
	for _, suffix := range []string{"_start", "_end", "_size"} {
		name := "_binary_hello_bin" + suffix
		if _, ok := syms[name]; !ok {
			t.Errorf("missing symbol %s (have %v)", name, syms)
		}
	}
	if got := syms["_binary_hello_bin_start"].Value; got != 0 {
		t.Errorf("start = %#x", got)
	}
	if got := syms["_binary_hello_bin_end"].Value; got != uint64(len(data)) {
		t.Errorf("end = %#x", got)
	}
	if got := syms["_binary_hello_bin_size"]; got.Value != uint64(len(data)) || got.Shndx != elf.SHN_ABS {
		t.Errorf("size symbol = %+v", got)
	}
}

func TestCoverageReadBinaryNilConfigAndTarget(t *testing.T) {
	f, err := readBinary([]byte{1, 2, 3}, "input", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.Class != elf.Class64 || f.Machine != elf.EM_NONE {
		t.Errorf("nil config header = %v/%v", f.Class, f.Machine)
	}
	if got := f.Section(".data"); !bytes.Equal(got.Data, []byte{1, 2, 3}) {
		t.Errorf(".data = %v", got.Data)
	}

	// A nil target with a usable Config must not panic or set the output.
	cfg := Default()
	if _, err := readBinary([]byte{4}, "input", cfg, nil); err != nil {
		t.Fatal(err)
	}
	if cfg.OutputTarget != "" {
		t.Errorf("OutputTarget = %q, want empty", cfg.OutputTarget)
	}
}

func TestCoverageReadBinarySymbolNames(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/tmp/a-b c.bin", "_binary_a_b_c_bin_start"},
		{"plain", "_binary_plain_start"},
		{"dir/9lives.dat", "_binary_9lives_dat_start"},
	} {
		cfg := Default()
		f, err := readBinary([]byte{0}, tc.path, cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := fbSymbols(t, f)[tc.want]; !ok {
			t.Errorf("path %q: missing %s", tc.path, tc.want)
		}
	}
}

func TestCoverageReadBinaryELFTargets(t *testing.T) {
	cases := []struct {
		target string
		class  elf.Class
		data   elf.Data
	}{
		{"elf32-i386", elf.Class32, elf.DataLSB},
		{"elf64-x86-64", elf.Class64, elf.DataLSB},
		{"elf32-big", elf.Class32, elf.DataMSB},
		{"elf64-little", elf.Class64, elf.DataLSB},
	}
	for _, tc := range cases {
		cfg := Default()
		cfg.OutputTarget = tc.target
		f, err := readBinary([]byte{1, 2}, "data.bin", cfg, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.target, err)
		}
		if f.Class != tc.class || f.Data != tc.data {
			t.Errorf("%s: class/data = %v/%v want %v/%v",
				tc.target, f.Class, f.Data, tc.class, tc.data)
		}
		// The machine type is deliberately left to applyFormat so that the
		// model cannot match run.go's verbatim-copy test.
		if f.Machine != elf.EM_NONE {
			t.Errorf("%s: Machine = %v, want none", tc.target, f.Machine)
		}
		if cfg.OutputTarget != tc.target {
			t.Errorf("%s: OutputTarget changed to %q", tc.target, cfg.OutputTarget)
		}
	}
}

func TestCoverageReadBinaryArchitecture(t *testing.T) {
	// A non-ELF output target lets -B set the architecture.
	cfg := Default()
	cfg.OutputTarget = "verilog"
	cfg.BinaryArch = "i386:x86-64"
	f, err := readBinary([]byte{1}, "in.bin", cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.Class != elf.Class64 || f.Machine != elf.EM_X86_64 {
		t.Errorf("-B i386:x86-64 model = class %v machine %v", f.Class, f.Machine)
	}

	// With no output target the architecture still applies.
	cfg = Default()
	cfg.BinaryArch = "i386"
	f, err = readBinary([]byte{1}, "in.bin", cfg, fbTarget(t, "binary"))
	if err != nil {
		t.Fatal(err)
	}
	if f.Class != elf.Class32 || f.Machine != elf.EM_386 {
		t.Errorf("-B i386 model = class %v machine %v", f.Class, f.Machine)
	}
	if cfg.OutputTarget != "binary" {
		t.Errorf("OutputTarget = %q", cfg.OutputTarget)
	}

	// An ELF output target wins over -B for the machine type.
	cfg = Default()
	cfg.OutputTarget = "elf64-x86-64"
	cfg.BinaryArch = "i386"
	f, err = readBinary([]byte{1}, "in.bin", cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.Class != elf.Class64 || f.Machine != elf.EM_NONE {
		t.Errorf("ELF target with -B model = class %v machine %v", f.Class, f.Machine)
	}

	cfg = Default()
	cfg.BinaryArch = "not-an-architecture"
	if _, err := readBinary([]byte{1}, "in.bin", cfg, nil); err == nil {
		t.Fatal("invalid -B was accepted")
	} else if _, ok := err.(*FatalError); !ok {
		t.Errorf("invalid -B error = %T", err)
	} else if !strings.Contains(err.Error(), "unrecognized architecture") {
		t.Errorf("invalid -B error = %q", err)
	}
}

func TestCoverageReadBinaryNonELFTargetKeepsDefaultModel(t *testing.T) {
	for _, target := range []string{"ihex", "srec", "binary"} {
		cfg := Default()
		cfg.OutputTarget = target
		f, err := readBinary([]byte{7}, "in.bin", cfg, nil)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if f.Class != elf.Class64 || f.Machine != elf.EM_NONE {
			t.Errorf("%s model = class %v machine %v", target, f.Class, f.Machine)
		}
		if cfg.OutputTarget != target {
			t.Errorf("%s: OutputTarget = %q", target, cfg.OutputTarget)
		}
	}
}

func TestCoverageReadBinaryEmptyData(t *testing.T) {
	cfg := Default()
	f, err := readBinary(nil, "empty.bin", cfg, fbTarget(t, "binary"))
	if err != nil {
		t.Fatal(err)
	}
	sec := f.Section(".data")
	if sec == nil || sec.Size != 0 || len(sec.Data) != 0 {
		t.Errorf(".data = %+v", sec)
	}
	syms := fbSymbols(t, f)
	if syms["_binary_empty_bin_size"].Value != 0 {
		t.Error("size symbol for empty input is not zero")
	}
}

func TestCoverageBinaryInputDefaultOutputRuns(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "payload")
	data := []byte("raw payload\n")
	if err := os.WriteFile(in, data, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "copy")
	cfg := Default()
	cfg.InputTarget = "binary"
	if err := Run(cfg, in, out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("default binary output = %q want %q", got, data)
	}
}

func TestCoverageBinaryInputIsReserialised(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "payload")
	data := []byte("raw payload\n")
	if err := os.WriteFile(in, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// The generic ELF target matches the synthetic model's default class and
	// byte order exactly; run.go must still re-serialise instead of copying
	// the binary input verbatim.
	for _, target := range []string{"elf64-little", "elf64-x86-64", "elf32-little"} {
		out := filepath.Join(dir, "out-"+target)
		cfg := Default()
		cfg.InputTarget = "binary"
		cfg.OutputTarget = target
		if err := Run(cfg, in, out); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(got, data) {
			t.Fatalf("%s: binary input was copied verbatim", target)
		}
		if !isELF(got) {
			t.Fatalf("%s: output is not ELF", target)
		}
		f, err := elf.Parse(got)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if sec := f.Section(".data"); sec == nil || !bytes.Equal(sec.Data, data) {
			t.Fatalf("%s: .data was not preserved", target)
		}
		if f.Class != fbTarget(t, target).Class || f.Data != fbTarget(t, target).Data {
			t.Errorf("%s: class/data = %v/%v", target, f.Class, f.Data)
		}
	}
}

func TestCoverageBinaryInputELFRunMetadata(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "payload")
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if err := os.WriteFile(in, data, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.o")
	cfg := Default()
	cfg.InputTarget = "binary"
	cfg.OutputTarget = "elf32-i386"
	if err := Run(cfg, in, out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if f.Class != elf.Class32 || f.Machine != elf.EM_386 {
		t.Errorf("header = class %v machine %v", f.Class, f.Machine)
	}
	sec := f.Section(".data")
	if sec == nil || !bytes.Equal(sec.Data, data) {
		t.Fatalf(".data = %+v", sec)
	}
	syms := fbSymbols(t, f)
	if _, ok := syms["_binary_payload_start"]; !ok {
		t.Errorf("symbols = %v", syms)
	}
}
