package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/fixtures"
	"github.com/myml/gobjcopy/objcopy"
)

// TestCoverParseAddSymbol exercises every flag and every failure path of the
// --add-symbol parser.
func TestCoverParseAddSymbol(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want objcopy.AddSymbol
	}{
		{
			name: "absolute value",
			arg:  "sym=0x10",
			want: objcopy.AddSymbol{Name: "sym", Value: 0x10, Bind: elf.STB_GLOBAL},
		},
		{
			name: "section value",
			arg:  "sym=.text:0x20",
			want: objcopy.AddSymbol{Name: "sym", Section: ".text", Value: 0x20, Bind: elf.STB_GLOBAL},
		},
		{
			name: "local",
			arg:  "sym=.text:1,local",
			want: objcopy.AddSymbol{Name: "sym", Section: ".text", Value: 1, Bind: elf.STB_LOCAL},
		},
		{
			name: "global",
			arg:  "sym=.text:1,global",
			want: objcopy.AddSymbol{Name: "sym", Section: ".text", Value: 1, Bind: elf.STB_GLOBAL},
		},
		{
			name: "export",
			arg:  "sym=.text:1,export",
			want: objcopy.AddSymbol{Name: "sym", Section: ".text", Value: 1, Bind: elf.STB_GLOBAL},
		},
		{
			name: "weak",
			arg:  "sym=.text:1,weak",
			want: objcopy.AddSymbol{Name: "sym", Section: ".text", Value: 1, Bind: elf.STB_WEAK},
		},
		{
			name: "function",
			arg:  "sym=.text:1,function",
			want: objcopy.AddSymbol{Name: "sym", Section: ".text", Value: 1, Bind: elf.STB_GLOBAL, Type: elf.STT_FUNC},
		},
		{
			name: "indirect-function",
			arg:  "sym=.text:1,indirect-function",
			want: objcopy.AddSymbol{Name: "sym", Section: ".text", Value: 1, Bind: elf.STB_GLOBAL, Type: elf.STT_FUNC},
		},
		{
			name: "object",
			arg:  "sym=.text:1,object",
			want: objcopy.AddSymbol{Name: "sym", Section: ".text", Value: 1, Bind: elf.STB_GLOBAL, Type: elf.STT_OBJECT},
		},
		{
			name: "file",
			arg:  "sym=1,file",
			want: objcopy.AddSymbol{Name: "sym", Value: 1, Bind: elf.STB_LOCAL, Type: elf.STT_FILE},
		},
		{
			name: "section",
			arg:  "sym=1,section",
			want: objcopy.AddSymbol{Name: "sym", Value: 1, Bind: elf.STB_LOCAL, Type: elf.STT_SECTION},
		},
		{
			name: "unique-object",
			arg:  "sym=.text:1,unique-object",
			want: objcopy.AddSymbol{Name: "sym", Section: ".text", Value: 1, Bind: elf.STB_GNU_UNIQUE, Type: elf.STT_OBJECT},
		},
		{
			name: "before",
			arg:  "sym=.text:1,before=other",
			want: objcopy.AddSymbol{Name: "sym", Section: ".text", Value: 1, Bind: elf.STB_GLOBAL, Before: "other"},
		},
		{
			name: "combined and case insensitive",
			arg:  "sym=.text:1,LOCAL,WEAK,FUNCTION,before=OTHER",
			want: objcopy.AddSymbol{Name: "sym", Section: ".text", Value: 1, Bind: elf.STB_WEAK, Type: elf.STT_FUNC, Before: "OTHER"},
		},
		{
			name: "empty section name",
			arg:  "sym=:1",
			want: objcopy.AddSymbol{Name: "sym", Value: 1, Bind: elf.STB_GLOBAL},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAddSymbol(tc.arg)
			if err != nil {
				t.Fatalf("parseAddSymbol(%q) error: %v", tc.arg, err)
			}
			if got != tc.want {
				t.Errorf("parseAddSymbol(%q) = %+v, want %+v", tc.arg, got, tc.want)
			}
		})
	}

	bad := []struct {
		name string
		arg  string
	}{
		{"empty", ""},
		{"no equals", "sym"},
		{"empty name", "=1"},
		{"bad absolute value", "sym=zzz"},
		{"empty absolute value", "sym="},
		{"bad section value", "sym=.text:zzz"},
		{"empty section value", "sym=.text:"},
		{"unknown flag", "sym=1,bogus"},
		{"empty flag list", "sym=1,"},
		{"empty flag among flags", "sym=1,local,,weak"},
	}
	for _, tc := range bad {
		t.Run("error/"+tc.name, func(t *testing.T) {
			if _, err := parseAddSymbol(tc.arg); err == nil {
				t.Errorf("parseAddSymbol(%q) succeeded, want error", tc.arg)
			}
		})
	}
}

// TestCoverParseVMA covers parseVMA's accepted bases and rejected inputs.
func TestCoverParseVMA(t *testing.T) {
	good := []struct {
		in   string
		want uint64
	}{
		{"0", 0},
		{"42", 42},
		{"0x10", 16},
		{"010", 8},
		{"+0x20", 32},
		{" 42 ", 42},
		{"18446744073709551615", 1<<64 - 1},
	}
	for _, tc := range good {
		got, err := parseVMA(tc.in, "--opt")
		if err != nil {
			t.Errorf("parseVMA(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseVMA(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}

	bad := []string{
		"",
		"   ",
		"+",
		"zzz",
		"0x",
		"1x",
		"18446744073709551616", // overflow
	}
	for _, in := range bad {
		if _, err := parseVMA(in, "--opt"); err == nil {
			t.Errorf("parseVMA(%q) succeeded, want error", in)
		}
	}
}

// TestCoverParseDelta covers signed adjustments.
func TestCoverParseDelta(t *testing.T) {
	good := []struct {
		in   string
		want int64
	}{
		{"16", 16},
		{"+16", 16},
		{"-16", -16},
		{"  -0x10", -16},
		{"0x10", 16},
		{" 42 ", 42},
	}
	for _, tc := range good {
		got, err := parseDelta(tc.in, "--opt")
		if err != nil {
			t.Errorf("parseDelta(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseDelta(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}

	bad := []string{
		"",
		"   ",
		"+",
		"-",
		"zzz",
		"0x8000000000000000", // does not fit in the signed 63-bit range
	}
	for _, in := range bad {
		if _, err := parseDelta(in, "--opt"); err == nil {
			t.Errorf("parseDelta(%q) succeeded, want error", in)
		}
	}
}

// TestCoverParseCInt covers atoi-style parsing, including whitespace and junk.
func TestCoverParseCInt(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"42", 42},
		{"  +42", 42},
		{"\t-7", -7},
		{"\n\r\f\v12", 12},
		{"42abc", 42},
		{"abc", 0},
		{"0x10", 0},
		{"  ", 0},
	}
	for _, tc := range tests {
		if got := parseCInt(tc.in); got != tc.want {
			t.Errorf("parseCInt(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestCoverParseRenameSection covers flag handling and both bad-format paths.
func TestCoverParseRenameSection(t *testing.T) {
	withFlags := func(s string) *string { return &s }
	tests := []struct {
		arg  string
		want objcopy.Rename
	}{
		{".old=.new", objcopy.Rename{Old: ".old", New: ".new"}},
		{".old=.new,alloc", objcopy.Rename{Old: ".old", New: ".new", Flags: withFlags("alloc")}},
		{".old=.new,alloc,code", objcopy.Rename{Old: ".old", New: ".new", Flags: withFlags("alloc,code")}},
		{".old=.new,", objcopy.Rename{Old: ".old", New: ".new", Flags: withFlags("")}},
	}
	for _, tc := range tests {
		got, err := parseRenameSection(tc.arg)
		if err != nil {
			t.Errorf("parseRenameSection(%q) error: %v", tc.arg, err)
			continue
		}
		if got.Old != tc.want.Old || got.New != tc.want.New {
			t.Errorf("parseRenameSection(%q) = %+v, want %+v", tc.arg, got, tc.want)
		}
		switch {
		case tc.want.Flags == nil && got.Flags != nil:
			t.Errorf("parseRenameSection(%q) flags = %q, want nil", tc.arg, *got.Flags)
		case tc.want.Flags != nil && got.Flags == nil:
			t.Errorf("parseRenameSection(%q) flags = nil, want %q", tc.arg, *tc.want.Flags)
		case tc.want.Flags != nil && got.Flags != nil && *got.Flags != *tc.want.Flags:
			t.Errorf("parseRenameSection(%q) flags = %q, want %q", tc.arg, *got.Flags, *tc.want.Flags)
		}
	}

	for _, arg := range []string{"", "noequals", "=new", ".old=", ".old=,alloc"} {
		if _, err := parseRenameSection(arg); err == nil {
			t.Errorf("parseRenameSection(%q) succeeded, want error", arg)
		}
	}
}

// TestCoverParseSectionAddr covers all three operators, the documented
// precedence when a section name contains '-', and rejected inputs.
func TestCoverParseSectionAddr(t *testing.T) {
	tests := []struct {
		arg  string
		want objcopy.SectionAddr
	}{
		{".text=0x1000", objcopy.SectionAddr{Name: ".text", Op: objcopy.AddrSet, Val: 0x1000}},
		{".text+16", objcopy.SectionAddr{Name: ".text", Op: objcopy.AddrAdd, Val: 16}},
		{".text-8", objcopy.SectionAddr{Name: ".text", Op: objcopy.AddrSub, Val: 8}},
		{".foo-bar=1", objcopy.SectionAddr{Name: ".foo-bar", Op: objcopy.AddrSet, Val: 1}},
		{".foo-bar+2", objcopy.SectionAddr{Name: ".foo-bar", Op: objcopy.AddrAdd, Val: 2}},
	}
	for _, tc := range tests {
		got, err := parseSectionAddr(tc.arg, "--change-section-address")
		if err != nil {
			t.Errorf("parseSectionAddr(%q) error: %v", tc.arg, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseSectionAddr(%q) = %+v, want %+v", tc.arg, got, tc.want)
		}
	}

	for _, arg := range []string{".text", "", ".text=zzz", ".text="} {
		if _, err := parseSectionAddr(arg, "--change-section-address"); err == nil {
			t.Errorf("parseSectionAddr(%q) succeeded, want error", arg)
		}
	}
}

// TestCoverApplyOptionHelpBranch exercises applyOption's help case directly;
// parseCommandLine normally short-circuits before it.
func TestCoverApplyOptionHelpBranch(t *testing.T) {
	pa := &parsedArgs{cfg: objcopy.Default()}
	var useGlobalize, useKeepGlobal bool
	if err := applyOption(pa, "help", "", &useGlobalize, &useKeepGlobal); err != nil {
		t.Fatalf("applyOption(help) error: %v", err)
	}
	if !pa.help {
		t.Errorf("applyOption(help) did not set pa.help")
	}
}

// TestCoverOptionErrorPaths drives every remaining error-return branch in
// applyOption and the helpers it calls.
func TestCoverOptionErrorPaths(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.txt")
	cases := []struct {
		name string
		args []string
	}{
		{"strip-symbols file", []string{"--strip-symbols", missing}},
		{"strip-unneeded-symbols file", []string{"--strip-unneeded-symbols", missing}},
		{"keep-symbols file", []string{"--keep-symbols", missing}},
		{"localize-symbols file", []string{"--localize-symbols", missing}},
		{"globalize-symbols file", []string{"--globalize-symbols", missing}},
		{"keep-global-symbols file", []string{"--keep-global-symbols", missing}},
		{"weaken-symbols file", []string{"--weaken-symbols", missing}},
		{"redefine-syms file", []string{"--redefine-syms", missing}},
		{"redefine-sym format", []string{"--redefine-sym", "old"}},
		{"set-section-alignment format", []string{"--set-section-alignment", "noequals"}},
		{"add-section format", []string{"--add-section", "noequals"}},
		{"update-section format", []string{"--update-section", "noequals"}},
		{"dump-section format", []string{"--dump-section", "noequals"}},
		{"change-start empty", []string{"--change-start", ""}},
		{"change-start bad", []string{"--change-start", "zzz"}},
		{"change-addresses empty", []string{"--change-addresses", ""}},
		{"change-addresses bad", []string{"--change-addresses", "zzz"}},
		{"set-start bad", []string{"--set-start", "zzz"}},
		{"pad-to bad", []string{"--pad-to", "zzz"}},
		{"gap-fill bad", []string{"--gap-fill", "zzz"}},
		{"elf-stt-common bad", []string{"--elf-stt-common", "maybe"}},
		{"add-symbol format", []string{"--add-symbol", "bad"}},
		{"add-symbol bad value", []string{"--add-symbol", "sym=zzz"}},
		{"reverse-bytes too small", []string{"--reverse-bytes", "1"}},
		{"reverse-bytes odd", []string{"--reverse-bytes", "3"}},
		{"srec-len zero", []string{"--srec-len", "0"}},
		{"verilog width invalid", []string{"--verilog-data-width", "3"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseArgs(tc.args); err == nil {
				t.Errorf("parseArgs(%q) succeeded, want error", tc.args)
			}
		})
	}
}

// TestCoverReadRedefineFileErrorPaths covers the unreadable-file and
// extra-column diagnostics.
func TestCoverReadRedefineFileErrorPaths(t *testing.T) {
	dir := t.TempDir()
	if _, err := readRedefineFile(filepath.Join(dir, "missing")); err == nil {
		t.Errorf("readRedefineFile(missing) succeeded, want error")
	}

	garbage := filepath.Join(dir, "garbage.txt")
	if err := os.WriteFile(garbage, []byte("old new extra\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRedefineFile(garbage); err == nil {
		t.Errorf("readRedefineFile(garbage) succeeded, want error")
	} else if !strings.Contains(err.Error(), "garbage found at end of line") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// TestCoverRunVerboseAndFailure covers main.go's verbose Infof branch and its
// Run-failure exit path.
func TestCoverRunVerboseAndFailure(t *testing.T) {
	t.Run("missing input file", func(t *testing.T) {
		dir := t.TempDir()
		code, _, stderr := runCLI(t, filepath.Join(dir, "does-not-exist"))
		if code != 1 {
			t.Errorf("exit = %d, want 1", code)
		}
		if !strings.Contains(stderr, programName+":") {
			t.Errorf("stderr = %q, want a %s: diagnostic", stderr, programName)
		}
	})

	t.Run("verbose success", func(t *testing.T) {
		dir := t.TempDir()
		hello, err := fixtures.BuildOne(dir, "hello-nopie")
		if err != nil {
			t.Skip("cannot build ELF fixture:", err)
		}
		out := filepath.Join(dir, "hello.out")
		code, stdout, stderr := runCLI(t, "-v", hello, out)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
		}
		if !strings.Contains(stdout, programName+":") {
			t.Errorf("verbose stdout = %q, want a %s: progress line", stdout, programName)
		}
	})
}
