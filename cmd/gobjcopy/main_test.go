package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/internal/fixtures"
	"github.com/myml/gobjcopy/internal/getopt"
	"github.com/myml/gobjcopy/objcopy"
)

// TestParseArgsMapping is the table-driven option -> Config mapping test.
func TestParseArgsMapping(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, c *objcopy.Config)
	}{
		{
			name: "defaults",
			args: nil,
			check: func(t *testing.T, c *objcopy.Config) {
				if c.InterleaveWidth != 1 {
					t.Errorf("default InterleaveWidth = %d, want 1", c.InterleaveWidth)
				}
				if c.StripAll || c.StripDebug || c.OnlyKeepDebug {
					t.Errorf("default strip flags not clean: %+v", c)
				}
			},
		},
		{
			name: "formats",
			args: []string{"-I", "elf32-i386", "-O", "binary", "-B", "i386", "-F", "elf64-x86-64"},
			check: func(t *testing.T, c *objcopy.Config) {
				if c.InputTarget != "elf64-x86-64" || c.OutputTarget != "elf64-x86-64" || c.Target != "elf64-x86-64" {
					t.Errorf("targets = %q/%q/%q", c.InputTarget, c.OutputTarget, c.Target)
				}
				if c.BinaryArch != "i386" {
					t.Errorf("BinaryArch = %q", c.BinaryArch)
				}
			},
		},
		{
			name: "later -I overrides -F",
			args: []string{"-F", "elf32-i386", "-I", "binary"},
			check: func(t *testing.T, c *objcopy.Config) {
				if c.InputTarget != "binary" || c.OutputTarget != "elf32-i386" || c.Target != "" {
					t.Errorf("targets = %q/%q/%q", c.InputTarget, c.OutputTarget, c.Target)
				}
			},
		},
		{
			name: "short -s and -d aliases",
			args: []string{"-s", "binary", "-d", "elf64-x86-64"},
			check: func(t *testing.T, c *objcopy.Config) {
				if c.InputTarget != "binary" || c.OutputTarget != "elf64-x86-64" {
					t.Errorf("targets = %q/%q", c.InputTarget, c.OutputTarget)
				}
				if c.StripAll || c.StripDebug {
					t.Errorf("-d was mistaken for strip-debug")
				}
			},
		},
		{
			name: "obsolete format long options",
			args: []string{"--input-format=elf32-i386", "--output-format", "binary", "--format=elf64-x86-64"},
			check: func(t *testing.T, c *objcopy.Config) {
				// --format sets all three, so it wins over the earlier pair.
				if c.InputTarget != "elf64-x86-64" || c.OutputTarget != "elf64-x86-64" {
					t.Errorf("targets = %q/%q", c.InputTarget, c.OutputTarget)
				}
			},
		},
		{
			name: "preserve and verbose",
			args: []string{"-p", "-v"},
			check: func(t *testing.T, c *objcopy.Config) {
				if !c.PreserveDates || !c.Verbose {
					t.Errorf("PreserveDates=%v Verbose=%v", c.PreserveDates, c.Verbose)
				}
			},
		},
		{
			name: "strip all then strip debug: last wins",
			args: []string{"-S", "-g"},
			check: func(t *testing.T, c *objcopy.Config) {
				if c.StripAll || !c.StripDebug {
					t.Errorf("StripAll=%v StripDebug=%v, want false/true", c.StripAll, c.StripDebug)
				}
			},
		},
		{
			name: "long strip forms last wins",
			args: []string{"--strip-all", "--strip-debug"},
			check: func(t *testing.T, c *objcopy.Config) {
				if c.StripAll || !c.StripDebug {
					t.Errorf("StripAll=%v StripDebug=%v, want false/true", c.StripAll, c.StripDebug)
				}
			},
		},
		{
			name: "only-section survives only-keep-debug",
			args: []string{"-j", ".text", "--only-keep-debug"},
			check: func(t *testing.T, c *objcopy.Config) {
				if !reflect.DeepEqual(c.OnlySections, []string{".text"}) {
					t.Errorf("OnlySections = %v, want [.text]", c.OnlySections)
				}
				if !c.OnlyKeepDebug {
					t.Errorf("OnlyKeepDebug not set together with -j")
				}
			},
		},
		{
			name: "strip debug then strip all: last wins",
			args: []string{"-g", "-S"},
			check: func(t *testing.T, c *objcopy.Config) {
				if !c.StripAll || c.StripDebug {
					t.Errorf("StripAll=%v StripDebug=%v, want true/false", c.StripAll, c.StripDebug)
				}
			},
		},
		{
			name: "strip modes are one enumeration",
			args: []string{"-S", "--strip-dwo", "--strip-unneeded", "--only-keep-debug", "--extract-dwo"},
			check: func(t *testing.T, c *objcopy.Config) {
				if c.StripAll || c.StripDebug || c.StripDWO || c.StripUnneeded || c.OnlyKeepDebug {
					t.Errorf("earlier strip modes remain set: %+v", c)
				}
				if !c.ExtractDWO {
					t.Errorf("ExtractDWO not set by last option")
				}
			},
		},
		{
			name: "discard",
			args: []string{"-x", "-X"},
			check: func(t *testing.T, c *objcopy.Config) {
				if !c.DiscardAll || !c.DiscardLocals {
					t.Errorf("DiscardAll=%v DiscardLocals=%v", c.DiscardAll, c.DiscardLocals)
				}
			},
		},
		{
			name: "symbol lists repeat",
			args: []string{"-N", "foo", "--strip-symbol", "bar", "--strip-unneeded-symbol", "baz",
				"-K", "keep1", "-K", "keep2", "-L", "loc1", "--globalize-symbol", "g1",
				"-W", "weak1", "--weaken", "-w"},
			check: func(t *testing.T, c *objcopy.Config) {
				if !reflect.DeepEqual(c.StripSymbols, []string{"foo", "bar"}) {
					t.Errorf("StripSymbols = %v", c.StripSymbols)
				}
				if !reflect.DeepEqual(c.StripUnneededSymbols, []string{"baz"}) {
					t.Errorf("StripUnneededSymbols = %v", c.StripUnneededSymbols)
				}
				if !reflect.DeepEqual(c.KeepSymbols, []string{"keep1", "keep2"}) {
					t.Errorf("KeepSymbols = %v", c.KeepSymbols)
				}
				if !reflect.DeepEqual(c.LocalizeSymbols, []string{"loc1"}) {
					t.Errorf("LocalizeSymbols = %v", c.LocalizeSymbols)
				}
				if !reflect.DeepEqual(c.GlobalizeSymbols, []string{"g1"}) {
					t.Errorf("GlobalizeSymbols = %v", c.GlobalizeSymbols)
				}
				if !reflect.DeepEqual(c.WeakenSymbols, []string{"weak1"}) {
					t.Errorf("WeakenSymbols = %v", c.WeakenSymbols)
				}
				if !c.WeakenAll || !c.Wildcard {
					t.Errorf("WeakenAll=%v Wildcard=%v", c.WeakenAll, c.Wildcard)
				}
			},
		},
		{
			name: "keep-global-symbol repeats",
			args: []string{"-G", "glob1", "--keep-global-symbol", "glob2"},
			check: func(t *testing.T, c *objcopy.Config) {
				if !reflect.DeepEqual(c.KeepGlobalSymbols, []string{"glob1", "glob2"}) {
					t.Errorf("KeepGlobalSymbols = %v", c.KeepGlobalSymbols)
				}
			},
		},
		{
			name: "keep symbol flags",
			args: []string{"--keep-file-symbols", "--localize-hidden", "--keep-section-symbols", "ignored"},
			check: func(t *testing.T, c *objcopy.Config) {
				if !c.KeepFileSymbols || !c.LocalizeHidden || !c.KeepSectionSymbols {
					t.Errorf("KeepFileSymbols=%v LocalizeHidden=%v KeepSectionSymbols=%v",
						c.KeepFileSymbols, c.LocalizeHidden, c.KeepSectionSymbols)
				}
			},
		},
		{
			name: "redefine-sym",
			args: []string{"--redefine-sym", "old=new", "--redefine-sym=two=three"},
			check: func(t *testing.T, c *objcopy.Config) {
				want := []objcopy.Redefine{{Old: "old", New: "new"}, {Old: "two", New: "three"}}
				if !reflect.DeepEqual(c.Redefines, want) {
					t.Errorf("Redefines = %v, want %v", c.Redefines, want)
				}
			},
		},
		{
			name: "sections",
			args: []string{"-j", ".text", "-j", ".data", "-R", ".comment", "--keep-section", ".foo",
				"--remove-relocations", ".rela.text", "--strip-section-headers"},
			check: func(t *testing.T, c *objcopy.Config) {
				if !reflect.DeepEqual(c.OnlySections, []string{".text", ".data"}) {
					t.Errorf("OnlySections = %v", c.OnlySections)
				}
				if !reflect.DeepEqual(c.RemoveSections, []string{".comment"}) {
					t.Errorf("RemoveSections = %v", c.RemoveSections)
				}
				if !reflect.DeepEqual(c.KeepSections, []string{".foo"}) {
					t.Errorf("KeepSections = %v", c.KeepSections)
				}
				if !reflect.DeepEqual(c.RemoveRelocations, []string{".rela.text"}) {
					t.Errorf("RemoveRelocations = %v", c.RemoveRelocations)
				}
				if !c.StripSectionHeaders {
					t.Errorf("StripSectionHeaders not set")
				}
			},
		},
		{
			name: "rename-section with and without flags",
			args: []string{"--rename-section", ".old=.new,code,alloc", "--rename-section=.a=.b"},
			check: func(t *testing.T, c *objcopy.Config) {
				if len(c.Renames) != 2 {
					t.Fatalf("Renames = %v", c.Renames)
				}
				r := c.Renames[0]
				if r.Old != ".old" || r.New != ".new" || r.Flags == nil || *r.Flags != "code,alloc" {
					t.Errorf("first rename = %+v", r)
				}
				if c.Renames[1].Old != ".a" || c.Renames[1].New != ".b" || c.Renames[1].Flags != nil {
					t.Errorf("second rename = %+v", c.Renames[1])
				}
			},
		},
		{
			name: "section flags and alignment",
			args: []string{"--set-section-flags", ".text=alloc,code", "--set-section-alignment", ".data=16"},
			check: func(t *testing.T, c *objcopy.Config) {
				want := []objcopy.SectionFlags{{Name: ".text", Flags: "alloc,code"}}
				if !reflect.DeepEqual(c.SetSectionFlags, want) {
					t.Errorf("SetSectionFlags = %v", c.SetSectionFlags)
				}
				wantAlign := []objcopy.SectionAlign{{Name: ".data", Align: 16}}
				if !reflect.DeepEqual(c.SetSectionAlignment, wantAlign) {
					t.Errorf("SetSectionAlignment = %v", c.SetSectionAlignment)
				}
			},
		},
		{
			name: "add update dump",
			args: []string{"--add-section", ".foo=/tmp/foo", "--update-section=.text=/tmp/text",
				"--dump-section", ".data=/tmp/data"},
			check: func(t *testing.T, c *objcopy.Config) {
				if !reflect.DeepEqual(c.AddSections, []objcopy.AddSection{{Name: ".foo", File: "/tmp/foo"}}) {
					t.Errorf("AddSections = %v", c.AddSections)
				}
				if !reflect.DeepEqual(c.UpdateSections, []objcopy.UpdateSection{{Name: ".text", File: "/tmp/text"}}) {
					t.Errorf("UpdateSections = %v", c.UpdateSections)
				}
				if !reflect.DeepEqual(c.DumpSections, []objcopy.DumpSection{{Name: ".data", File: "/tmp/data"}}) {
					t.Errorf("DumpSections = %v", c.DumpSections)
				}
			},
		},
		{
			name: "debug options",
			args: []string{"--only-keep-debug", "--add-gnu-debuglink", "foo.debug"},
			check: func(t *testing.T, c *objcopy.Config) {
				if !c.OnlyKeepDebug {
					t.Errorf("OnlyKeepDebug not set")
				}
				if c.AddDebugLink != "foo.debug" {
					t.Errorf("AddDebugLink = %q", c.AddDebugLink)
				}
			},
		},
		{
			// binutils' configure-time default is "none" unless it was built
			// with --enable-compressed-debug-sections, so a bare option is a
			// no-op (this is what objcopy.exp expects).
			name: "compress default",
			args: []string{"--compress-debug-sections"},
			check: func(t *testing.T, c *objcopy.Config) {
				if c.CompressDebug != "" || c.DecompressDebug {
					t.Errorf("CompressDebug=%q DecompressDebug=%v", c.CompressDebug, c.DecompressDebug)
				}
			},
		},
		{
			name: "compress named",
			args: []string{"--compress-debug-sections=zlib-gnu"},
			check: func(t *testing.T, c *objcopy.Config) {
				if c.CompressDebug != "zlib-gnu" {
					t.Errorf("CompressDebug = %q", c.CompressDebug)
				}
			},
		},
		{
			name: "decompress after compress",
			args: []string{"--compress-debug-sections=zstd", "--decompress-debug-sections"},
			check: func(t *testing.T, c *objcopy.Config) {
				if !c.DecompressDebug || c.CompressDebug != "" {
					t.Errorf("CompressDebug=%q DecompressDebug=%v", c.CompressDebug, c.DecompressDebug)
				}
			},
		},
		{
			name: "compress after decompress",
			args: []string{"--decompress-debug-sections", "--compress-debug-sections=none"},
			check: func(t *testing.T, c *objcopy.Config) {
				// GNU maps --compress-debug-sections=none to decompression.
				if !c.DecompressDebug || c.CompressDebug != "" {
					t.Errorf("CompressDebug=%q DecompressDebug=%v", c.CompressDebug, c.DecompressDebug)
				}
			},
		},
		{
			name: "addresses",
			args: []string{"--set-start", "0x401000", "--change-start", "-0x10",
				"--change-addresses=+0x20", "--pad-to", "0x500000", "--gap-fill", "0xff"},
			check: func(t *testing.T, c *objcopy.Config) {
				if c.SetStart == nil || *c.SetStart != 0x401000 {
					t.Errorf("SetStart = %v", c.SetStart)
				}
				if c.ChangeStart == nil || *c.ChangeStart != -16 {
					t.Errorf("ChangeStart = %v", c.ChangeStart)
				}
				if c.ChangeAddresses == nil || *c.ChangeAddresses != 32 {
					t.Errorf("ChangeAddresses = %v", c.ChangeAddresses)
				}
				if c.PadTo == nil || *c.PadTo != 0x500000 {
					t.Errorf("PadTo = %v", c.PadTo)
				}
				if c.GapFill == nil || *c.GapFill != 0xff {
					t.Errorf("GapFill = %v", c.GapFill)
				}
			},
		},
		{
			name: "change section addresses",
			args: []string{
				"--change-section-address", ".text=0x1000",
				"--change-section-vma", ".data+16",
				"--change-section-lma", ".bss-8",
				"--adjust-section-vma", ".rodata=0x2000",
			},
			check: func(t *testing.T, c *objcopy.Config) {
				// --adjust-section-vma is GNU's alias for
				// --change-section-address, which changes both VMA and LMA.
				wantAddr := []objcopy.SectionAddr{
					{Name: ".text", Op: objcopy.AddrSet, Val: 0x1000},
					{Name: ".rodata", Op: objcopy.AddrSet, Val: 0x2000},
				}
				if !reflect.DeepEqual(c.ChangeSectionAddr, wantAddr) {
					t.Errorf("ChangeSectionAddr = %v", c.ChangeSectionAddr)
				}
				if !reflect.DeepEqual(c.ChangeSectionVMA, []objcopy.SectionAddr{{Name: ".data", Op: objcopy.AddrAdd, Val: 16}}) {
					t.Errorf("ChangeSectionVMA = %v", c.ChangeSectionVMA)
				}
				if !reflect.DeepEqual(c.ChangeSectionLMA, []objcopy.SectionAddr{{Name: ".bss", Op: objcopy.AddrSub, Val: 8}}) {
					t.Errorf("ChangeSectionLMA = %v", c.ChangeSectionLMA)
				}
			},
		},
		{
			name: "interleave default",
			args: []string{"--interleave"},
			check: func(t *testing.T, c *objcopy.Config) {
				if c.Interleave != 4 {
					t.Errorf("Interleave = %d, want 4", c.Interleave)
				}
			},
		},
		{
			name: "interleave attached",
			args: []string{"--interleave=2"},
			check: func(t *testing.T, c *objcopy.Config) {
				if c.Interleave != 2 {
					t.Errorf("Interleave = %d, want 2", c.Interleave)
				}
			},
		},
		{
			name: "interleave short attached and separate",
			args: []string{"-i2", "-b", "1", "--interleave-width", "3"},
			check: func(t *testing.T, c *objcopy.Config) {
				if c.Interleave != 2 || c.InterleaveWidth != 3 {
					t.Errorf("Interleave=%d InterleaveWidth=%d", c.Interleave, c.InterleaveWidth)
				}
			},
		},
		{
			name: "byte option is accepted",
			// --byte has no Config field yet; the option must still parse.
			args: []string{"-b", "0"},
			check: func(t *testing.T, c *objcopy.Config) {
				_ = c
			},
		},
		{
			name: "unimplemented options are accepted",
			args: []string{
				"--debugging", "--extract-symbol", "--change-leading-char", "--remove-leading-char",
				"--long-section-names=enable", "--reverse-bytes=4", "--add-symbol", "x=.text:0",
				"--alt-machine-code", "3", "--writable-text", "--readonly-text", "--pure", "--impure",
				"--prefix-symbols", "_", "--prefix-sections", "sec_", "--prefix-alloc-sections", "a_",
				"--file-alignment", "512", "--heap", "1,2", "--image-base", "0x400000",
				"--section-alignment", "4096", "--stack", "1,2", "--subsystem", "console",
				"--elf-stt-common=yes", "--verilog-data-width", "4", "-M", "--no-merge-notes",
				"-D", "-U", "--change-warnings", "--no-change-warnings",
				"--adjust-warnings", "--no-adjust-warnings", "--srec-len", "16", "--srec-forceS3",
			},
			check: func(t *testing.T, c *objcopy.Config) {
				_ = c // all of these are parsed but intentionally no-ops
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := parseArgs(tc.args)
			if err != nil {
				t.Fatalf("parseArgs(%q) error: %v", tc.args, err)
			}
			tc.check(t, cfg)
		})
	}
}

func TestParseArgsOperands(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"none", nil, nil},
		{"one", []string{"in"}, []string{"in"}},
		{"two", []string{"in", "out"}, []string{"in", "out"}},
		{"permuted", []string{"in", "-S", "out"}, []string{"in", "out"}},
		{"end of options", []string{"--", "-S"}, []string{"-S"}},
		{"lone dash", []string{"-"}, []string{"-"}},
		{"optional long arg not separate", []string{"--interleave", "2"}, []string{"2"}},
		{"keep-section-symbols takes an argument", []string{"--keep-section-symbols", "ignored", "in", "out"}, []string{"in", "out"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, operands, err := parseArgs(tc.args)
			if err != nil {
				t.Fatalf("parseArgs(%q) error: %v", tc.args, err)
			}
			if !reflect.DeepEqual(operands, tc.want) {
				t.Errorf("operands = %v, want %v", operands, tc.want)
			}
		})
	}
}

func TestParseArgsSymbolFiles(t *testing.T) {
	dir := t.TempDir()
	symbols := filepath.Join(dir, "symbols.txt")
	if err := os.WriteFile(symbols, []byte("# comment\nfoo\n  bar  # trailing\n\nbaz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	redefs := filepath.Join(dir, "redefs.txt")
	if err := os.WriteFile(redefs, []byte("old1 new1\nold2 new2 # note\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := parseArgs([]string{
		"--strip-symbols", symbols,
		"--keep-symbols", symbols,
		"--localize-symbols", symbols,
		"--globalize-symbols", symbols,
		"--keep-global-symbols", symbols,
		"--weaken-symbols", symbols,
		"--strip-unneeded-symbols", symbols,
		"--redefine-syms", redefs,
	})
	// --globalize-symbols together with --keep-global-symbols is a GNU error.
	if err == nil || !strings.Contains(err.Error(), "incompatible") {
		t.Fatalf("expected globalize/keep-global conflict, got %v", err)
	}

	cfg, _, err = parseArgs([]string{"--strip-symbols", symbols, "--redefine-syms", redefs})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.StripSymbols, []string{"foo", "bar", "baz"}) {
		t.Errorf("StripSymbols = %v", cfg.StripSymbols)
	}
	want := []objcopy.Redefine{{Old: "old1", New: "new1"}, {Old: "old2", New: "new2"}}
	if !reflect.DeepEqual(cfg.Redefines, want) {
		t.Errorf("Redefines = %v, want %v", cfg.Redefines, want)
	}

	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte("onlyone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseArgs([]string{"--redefine-syms", bad}); err == nil {
		t.Errorf("expected error for a redefine line with one name")
	}
	if _, _, err := parseArgs([]string{"--strip-symbols", filepath.Join(dir, "missing")}); err == nil {
		t.Errorf("expected error for a missing symbol file")
	}
}

func TestParseArgsErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		kind getopt.ErrorKind
		text string
	}{
		{"unknown long", []string{"--bogus"}, getopt.ErrUnknownLongOption, "unrecognized option"},
		{"unknown short", []string{"-Z"}, getopt.ErrUnknownShortOption, "invalid option"},
		{"missing long argument", []string{"--rename-section"}, getopt.ErrMissingLongArgument, "requires an argument"},
		{"missing short argument", []string{"-j"}, getopt.ErrMissingShortArgument, "requires an argument"},
		{"short interleave needs argument", []string{"-i"}, getopt.ErrMissingShortArgument, "requires an argument"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseArgs(tc.args)
			if err == nil {
				t.Fatalf("parseArgs(%q) succeeded, want error", tc.args)
			}
			var ge *getopt.Error
			if !errors.As(err, &ge) {
				t.Fatalf("error %v is not a *getopt.Error", err)
			}
			if ge.Kind != tc.kind {
				t.Errorf("kind = %v, want %v", ge.Kind, tc.kind)
			}
			if !strings.Contains(ge.Msg, tc.text) {
				t.Errorf("message %q does not contain %q", ge.Msg, tc.text)
			}
		})
	}

	semantic := []struct {
		name string
		args []string
	}{
		{"bad rename", []string{"--rename-section", "noequals"}},
		{"empty rename", []string{"--rename-section", "=new"}},
		{"bad section flags", []string{"--set-section-flags", "noequals"}},
		{"bad alignment value", []string{"--set-section-alignment", ".text=abc"}},
		{"alignment not power of two", []string{"--set-section-alignment", ".text=3"}},
		{"bad section address", []string{"--change-section-address", ".text"}},
		{"bad number", []string{"--set-start", "zzz"}},
		{"negative byte", []string{"-b", "-1"}},
		{"zero interleave", []string{"--interleave=0"}},
		{"bad interleave width", []string{"--interleave-width", "0"}},
		{"bad compression", []string{"--compress-debug-sections=bogus"}},
		{"globalize and keep-global", []string{"--globalize-symbol", "a", "-G", "b"}},
	}
	for _, tc := range semantic {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseArgs(tc.args); err == nil {
				t.Errorf("parseArgs(%q) succeeded, want error", tc.args)
			}
		})
	}
}

func TestParseCommandLineModes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want func(*parsedArgs) bool
	}{
		{"help long", []string{"--help"}, func(p *parsedArgs) bool { return p.help }},
		{"help short", []string{"-h"}, func(p *parsedArgs) bool { return p.help }},
		{"help H", []string{"-H"}, func(p *parsedArgs) bool { return p.help }},
		{"version", []string{"--version"}, func(p *parsedArgs) bool { return p.version }},
		{"version short", []string{"-V"}, func(p *parsedArgs) bool { return p.version }},
		{"info", []string{"--info"}, func(p *parsedArgs) bool { return p.info }},
		{"none", nil, func(p *parsedArgs) bool { return !p.help && !p.version && !p.info }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pa, err := parseCommandLine(tc.args)
			if err != nil {
				t.Fatalf("parseCommandLine(%q): %v", tc.args, err)
			}
			if !tc.want(pa) {
				t.Errorf("mode flags = %+v", pa)
			}
		})
	}

	// GNU exits at -h before it ever sees a later bad option.
	pa, err := parseCommandLine([]string{"-h", "--bogus"})
	if err != nil {
		t.Fatalf("-h before a bad option returned error: %v", err)
	}
	if !pa.help {
		t.Errorf("-h before a bad option did not request help")
	}
	// A bad option before -h is still an error.
	if _, err := parseCommandLine([]string{"--bogus", "-h"}); err == nil {
		t.Errorf("--bogus before -h should fail")
	}
}

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestRun(t *testing.T) {
	t.Run("no operands", func(t *testing.T) {
		code, _, stderr := runCLI(t)
		if code != 1 {
			t.Errorf("exit = %d, want 1", code)
		}
		if !strings.Contains(stderr, "Usage: gobjcopy") {
			t.Errorf("stderr does not contain usage: %q", stderr)
		}
	})
	t.Run("three operands", func(t *testing.T) {
		code, _, stderr := runCLI(t, "a", "b", "c")
		if code != 1 {
			t.Errorf("exit = %d, want 1", code)
		}
		if !strings.Contains(stderr, "Usage: gobjcopy") {
			t.Errorf("stderr does not contain usage: %q", stderr)
		}
	})
	t.Run("version", func(t *testing.T) {
		code, stdout, _ := runCLI(t, "--version")
		if code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
		if !strings.Contains(stdout, "GNU objcopy (gobjcopy)") {
			t.Errorf("version output = %q", stdout)
		}
	})
	t.Run("version short", func(t *testing.T) {
		code, stdout, _ := runCLI(t, "-V")
		if code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
		if !strings.Contains(stdout, "gobjcopy") {
			t.Errorf("version output = %q", stdout)
		}
	})
	t.Run("info", func(t *testing.T) {
		code, stdout, _ := runCLI(t, "--info")
		if code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
		if !strings.Contains(stdout, "elf64-x86-64") && !strings.Contains(stdout, "BFD") {
			t.Errorf("info output = %q", stdout)
		}
	})
	t.Run("help", func(t *testing.T) {
		code, stdout, _ := runCLI(t, "--help")
		if code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
		for _, want := range []string{"Usage: gobjcopy", "--only-section", "--rename-section", "--info"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("help output does not contain %q", want)
			}
		}
	})
	t.Run("unknown option", func(t *testing.T) {
		code, _, stderr := runCLI(t, "--bogus")
		if code != 1 {
			t.Errorf("exit = %d, want 1", code)
		}
		if !strings.Contains(stderr, "gobjcopy: unrecognized option '--bogus'") {
			t.Errorf("stderr = %q", stderr)
		}
	})
}

// TestRunWarningsDoNotAffectExitStatus pins GNU's observed behaviour: non-fatal
// warnings (an unmatched section for --set-section-flags or
// --change-section-address, an unmatched -R, an unmatched -N) are printed but
// leave the exit status at 0. Only a failing Run exits non-zero.
func TestRunWarningsDoNotAffectExitStatus(t *testing.T) {
	dir := t.TempDir()
	hello, err := fixtures.BuildOne(dir, "hello-nopie")
	if err != nil {
		t.Skip("cannot build ELF fixture:", err)
	}

	cases := []struct {
		name string
		args []string
	}{
		{"set-section-flags unknown", []string{"--set-section-flags", ".nosuch=alloc", hello, filepath.Join(dir, "a.out")}},
		{"change-section-address unknown", []string{"--change-section-address", ".nosuch+0x10", "--change-warnings", hello, filepath.Join(dir, "b.out")}},
		{"remove-section unknown", []string{"-R", ".nosuch", hello, filepath.Join(dir, "c.out")}},
		{"strip-symbol unknown", []string{"-N", "nosuchsym", hello, filepath.Join(dir, "d.out")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, tc.args...)
			if code != 0 {
				t.Errorf("exit = %d, want 0 (stderr: %s)", code, stderr)
			}
		})
	}
}

// TestOptionsCoverGNUHelp parses `objcopy --help` and verifies that every
// option name it advertises is present in optionSpecs with the same spelling.
func TestOptionsCoverGNUHelp(t *testing.T) {
	objcopyPath, err := exec.LookPath("objcopy")
	if err != nil {
		t.Skip("GNU objcopy not available:", err)
	}
	cmd := exec.Command(objcopyPath, "--help")
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("objcopy --help failed: %v", err)
	}
	help := string(out)

	ours := make(map[string]bool)
	for _, spec := range optionSpecs {
		if spec.long != "" {
			ours["--"+spec.long] = true
		}
		if spec.short != 0 {
			ours["-"+string(spec.short)] = true
		}
	}

	// Options GNU advertises but gobjcopy deliberately does not support would
	// be listed here. The table parses all of them today, so it is empty.
	exceptions := map[string]bool{}

	longRe := regexp.MustCompile(`--[A-Za-z0-9][A-Za-z0-9_-]*`)
	for _, name := range longRe.FindAllString(help, -1) {
		if !ours[name] && !exceptions[name] {
			t.Errorf("GNU help long option %s is missing from the option table", name)
		}
	}

	// Short options appear as "-X" at the start of a field in the help text.
	shortRe := regexp.MustCompile(`(?m)(?:^|[\s({|])-([A-Za-z])(?:[\s,.\[]|$)`)
	for _, m := range shortRe.FindAllStringSubmatch(help, -1) {
		name := "-" + m[1]
		if !ours[name] && !exceptions[name] {
			t.Errorf("GNU help short option %s is missing from the option table", name)
		}
	}
}

// TestOptionSpecsUnique guards the getopt registration rules: duplicate long
// names or short options would silently shadow later entries.
func TestOptionSpecsUnique(t *testing.T) {
	seenLong := map[string]bool{}
	seenShort := map[rune]bool{}
	for _, spec := range optionSpecs {
		if spec.long != "" {
			if seenLong[spec.long] {
				t.Errorf("duplicate long option --%s", spec.long)
			}
			seenLong[spec.long] = true
		}
		if spec.short != 0 {
			if seenShort[spec.short] {
				t.Errorf("duplicate short option -%c", spec.short)
			}
			seenShort[spec.short] = true
		}
		if spec.long == "" && spec.key == "" {
			t.Errorf("short-only option -%c has no action key", spec.short)
		}
	}
}
