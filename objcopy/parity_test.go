package objcopy_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/internal/elfdump"
	"github.com/myml/gobjcopy/internal/fixtures"
	"github.com/myml/gobjcopy/objcopy"
)

// parityCase runs the same transformation through GNU objcopy and through the
// library, then compares the two results semantically.
type parityCase struct {
	name    string
	fixture string
	gnu     []string
	cfg     func() *objcopy.Config
	// ignoreSegments skips program header comparison for transformations
	// where GNU synthesises new segments (documented limitation).
	ignoreSegments bool
	// knownDivergence explains why a case cannot match GNU today.
	knownDivergence string
}

func cases() []parityCase {
	return []parityCase{
		{"strip-all", "hello", []string{"-S"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.StripAll = true
			return c
		}, false, ""},
		{"strip-debug", "hello", []string{"-g"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.StripDebug = true
			return c
		}, false, ""},
		{"strip-unneeded-exe", "hello", []string{"--strip-unneeded"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.StripUnneeded = true
			return c
		}, false, ""},
		{"strip-unneeded-obj", "reloc.o", []string{"--strip-unneeded"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.StripUnneeded = true
			return c
		}, false, ""},
		{"strip-all-obj", "reloc.o", []string{"-S"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.StripAll = true
			return c
		}, false, ""},
		{"discard-all", "hello", []string{"-x"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.DiscardAll = true
			return c
		}, false, ""},
		{"discard-locals", "hello", []string{"-X"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.DiscardLocals = true
			return c
		}, false, ""},
		{"discard-locals-obj", "reloc.o", []string{"-X"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.DiscardLocals = true
			return c
		}, false, ""},
		{"remove-comment", "hello", []string{"-R", ".comment"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.RemoveSections = []string{".comment"}
			return c
		}, false, ""},
		{"remove-wildcard", "hello", []string{"-R", ".note*"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.RemoveSections = []string{".note*"}
			return c
		}, false, ""},
		{"only-section-text", "reloc.o", []string{"-j", ".text"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.OnlySections = []string{".text"}
			return c
		}, false, "GNU fails on relocatable input because its symbol table ends up empty; gobjcopy drops the relocations instead"},
		{"only-section-debug", "hello", []string{"-j", ".text"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.OnlySections = []string{".text"}
			return c
		}, true, ""},
		{"rename-section", "hello", []string{"--rename-section", ".comment=.mynote"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.Renames = []objcopy.Rename{{Old: ".comment", New: ".mynote"}}
			return c
		}, false, ""},
		{"set-section-flags", "hello", []string{"--set-section-flags", ".comment=alloc,code"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.SetSectionFlags = []objcopy.SectionFlags{{Name: ".comment", Flags: "alloc,code"}}
			return c
		}, false, ""},
		{"set-section-flags-contents", "hello", []string{"--set-section-flags", ".bss=alloc,load,contents"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.SetSectionFlags = []objcopy.SectionFlags{{Name: ".bss", Flags: "alloc,load,contents"}}
			return c
		}, false, ""},
		{"keep-symbol", "hello", []string{"-K", "main"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.KeepSymbols = []string{"main"}
			return c
		}, false, ""},
		{"strip-symbol", "hello", []string{"-N", "main"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.StripSymbols = []string{"main"}
			return c
		}, false, ""},
		{"keep-global", "hello", []string{"-G", "main"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.KeepGlobalSymbols = []string{"main"}
			return c
		}, false, ""},
		{"localize", "hello", []string{"-L", "main"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.LocalizeSymbols = []string{"main"}
			return c
		}, false, ""},
		{"globalize", "hello", []string{"--globalize-symbol", "completed.0"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.GlobalizeSymbols = []string{"completed.0"}
			return c
		}, false, ""},
		{"weaken", "hello", []string{"--weaken"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.WeakenAll = true
			return c
		}, false, ""},
		{"redefine", "hello", []string{"--redefine-sym", "main=entry_point"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.Redefines = []objcopy.Redefine{{Old: "main", New: "entry_point"}}
			return c
		}, false, ""},
		{"only-keep-debug", "hello", []string{"--only-keep-debug"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.OnlyKeepDebug = true
			return c
		}, false, ""},
		{"change-addresses", "hello", []string{"--change-addresses", "0x1000"}, func() *objcopy.Config {
			c := objcopy.Default()
			d := int64(0x1000)
			c.ChangeAddresses = &d
			return c
		}, false, ""},
		{"set-start", "hello", []string{"--set-start", "0x2000"}, func() *objcopy.Config {
			c := objcopy.Default()
			v := uint64(0x2000)
			c.SetStart = &v
			return c
		}, false, ""},
		{"change-section-vma", "custom", []string{"--change-section-vma", ".myrodata=0x500000"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.ChangeSectionVMA = []objcopy.SectionAddr{{Name: ".myrodata", Op: objcopy.AddrSet, Val: 0x500000}}
			return c
		}, false, ""},
		{"change-section-address", "custom", []string{"--change-section-address", ".mydata=0x400000"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.ChangeSectionAddr = []objcopy.SectionAddr{{Name: ".mydata", Op: objcopy.AddrSet, Val: 0x400000}}
			return c
		}, true, ""},
		{"binary-custom", "custom", []string{"-O", "binary"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.OutputTarget = "binary"
			return c
		}, false, ""},
		{"binary-gapfill", "hello", []string{"-O", "binary", "--gap-fill", "0xaa"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.OutputTarget = "binary"
			g := uint64(0xaa)
			c.GapFill = &g
			return c
		}, false, ""},
		{"binary-padto", "hello", []string{"-O", "binary", "--pad-to", "0x500000"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.OutputTarget = "binary"
			p := uint64(0x500000)
			c.PadTo = &p
			return c
		}, false, ""},
		{"strip-section-headers", "hello", []string{"--strip-section-headers"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.StripSectionHeaders = true
			return c
		}, false, ""},
		{"prefix-sections", "reloc.o", []string{"--prefix-sections", "foo_"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.PrefixSections = "foo_"
			return c
		}, false, ""},
		{"prefix-alloc-sections", "reloc.o", []string{"--prefix-alloc-sections", "al_"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.PrefixAllocSections = "al_"
			return c
		}, false, ""},
		{"prefix-sections-both", "reloc.o", []string{"--prefix-sections", "foo_", "--prefix-alloc-sections", "al_"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.PrefixSections = "foo_"
			c.PrefixAllocSections = "al_"
			return c
		}, false, ""},
		{"prefix-sections-with-rename", "reloc.o", []string{"--prefix-sections", "foo_", "--rename-section", ".text=.mytext"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.PrefixSections = "foo_"
			c.Renames = []objcopy.Rename{{Old: ".text", New: ".mytext"}}
			return c
		}, false, ""},
		{"prefix-symbols", "reloc.o", []string{"--prefix-symbols", "bar_"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.PrefixSymbols = "bar_"
			return c
		}, false, ""},
		{"prefix-symbols-exe", "hello", []string{"--prefix-symbols", "bar_"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.PrefixSymbols = "bar_"
			return c
		}, false, ""},
		{"prefix-symbols-both", "reloc.o", []string{"--prefix-sections", "foo_", "--prefix-symbols", "bar_"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.PrefixSections = "foo_"
			c.PrefixSymbols = "bar_"
			return c
		}, false, ""},
		{"prefix-symbols-with-add-symbol", "reloc.o", []string{"--prefix-symbols", "bar_", "--add-symbol", "NEW=0x1234"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.PrefixSymbols = "bar_"
			c.AddSymbols = []objcopy.AddSymbol{{Name: "NEW", Value: 0x1234, Bind: 1}}
			return c
		}, false, ""},
		{"extract-symbol-obj", "reloc.o", []string{"--extract-symbol"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.ExtractSymbol = true
			return c
		}, false, ""},
		{"extract-symbol-exe", "hello-nopie", []string{"--extract-symbol"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.ExtractSymbol = true
			return c
		}, false, ""},
		{"extract-symbol-pie", "hello-pie", []string{"--extract-symbol"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.ExtractSymbol = true
			return c
		}, false, ""},
		{"extract-symbol-shared", "lib.so", []string{"--extract-symbol"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.ExtractSymbol = true
			return c
		}, false, ""},
		{"alt-machine-code", "reloc.o", []string{"--alt-machine-code", "40"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.AltMachineCode = 40
			return c
		}, false, ""},
		{"alt-machine-code-exe", "hello-nopie", []string{"--alt-machine-code", "40"}, func() *objcopy.Config {
			c := objcopy.Default()
			c.AltMachineCode = 40
			return c
		}, false, ""},
	}
}

func TestGNUSemanticParity(t *testing.T) {
	ref, err := exec.LookPath("objcopy")
	if err != nil {
		t.Skip("GNU objcopy not available")
	}
	dir := t.TempDir()
	fx, err := fixtures.Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.knownDivergence != "" {
				t.Skip(tc.knownDivergence)
			}
			src, ok := fx[tc.fixture]
			if !ok {
				t.Skipf("fixture %s unavailable", tc.fixture)
			}
			work := t.TempDir()
			in := filepath.Join(work, "in")
			if data, err := os.ReadFile(src); err != nil {
				t.Fatal(err)
			} else if err := os.WriteFile(in, data, 0o755); err != nil {
				t.Fatal(err)
			}
			if len(tc.gnu) >= 2 && tc.gnu[0] == "-O" && tc.gnu[1] == "binary" {
				t.Skip("binary output is covered by TestGNUBinaryParity")
			}
			gnuOut := filepath.Join(work, "gnu.out")
			ourOut := filepath.Join(work, "our.out")

			gnuCmd := exec.Command(ref, append(append([]string{}, tc.gnu...), in, gnuOut)...)
			gnuCmd.Env = append(os.Environ(), "LC_ALL=C")
			gnuLog, gnuErr := gnuCmd.CombinedOutput()

			var ourLog strings.Builder
			cfg := tc.cfg()
			cfg.Warnf = func(f string, a ...any) {
				ourLog.WriteString("warning\n")
			}
			ourErr := objcopy.Run(cfg, in, ourOut)

			if gnuErr != nil || ourErr != nil {
				if gnuErr == nil || ourErr == nil {
					t.Fatalf("exit mismatch: gnu=%v our=%v\nGNU: %s\nours: %s",
						gnuErr, ourErr, trimLog(gnuLog), trimLog([]byte(ourLog.String())))
				}
				t.Logf("both failed as expected")
				return
			}
			opt := elfdump.Default
			if tc.ignoreSegments {
				opt.IgnoreSegments = true
			}
			gnuDump, err := elfdump.DumpFile(gnuOut, opt)
			if err != nil {
				t.Fatalf("GNU output not ELF (%v); probably binary output", err)
			}
			ourDump, err := elfdump.DumpFile(ourOut, opt)
			if err != nil {
				t.Fatalf("our output not ELF: %v", err)
			}
			if d := elfdump.FirstDiff(gnuDump, ourDump); d != "" {
				t.Errorf("semantic difference from GNU:\n%s", d)
			}
		})
	}
}

func TestGNUBinaryParity(t *testing.T) {
	ref, err := exec.LookPath("objcopy")
	if err != nil {
		t.Skip("GNU objcopy not available")
	}
	dir := t.TempDir()
	fx, err := fixtures.Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases() {
		if tc.gnu[0] != "-O" || tc.gnu[1] != "binary" {
			continue
		}
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src, ok := fx[tc.fixture]
			if !ok {
				t.Skipf("fixture %s unavailable", tc.fixture)
			}
			work := t.TempDir()
			in := filepath.Join(work, "in")
			if data, err := os.ReadFile(src); err != nil {
				t.Fatal(err)
			} else if err := os.WriteFile(in, data, 0o755); err != nil {
				t.Fatal(err)
			}
			gnuOut := filepath.Join(work, "gnu.bin")
			ourOut := filepath.Join(work, "our.bin")
			gnuCmd := exec.Command(ref, append(append([]string{}, tc.gnu...), in, gnuOut)...)
			gnuCmd.Env = append(os.Environ(), "LC_ALL=C")
			if out, err := gnuCmd.CombinedOutput(); err != nil {
				t.Fatalf("GNU: %v: %s", err, out)
			}
			cfg := tc.cfg()
			if err := objcopy.Run(cfg, in, ourOut); err != nil {
				t.Fatalf("ours: %v", err)
			}
			want, err := os.ReadFile(gnuOut)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(ourOut)
			if err != nil {
				t.Fatal(err)
			}
			if len(want) != len(got) {
				t.Fatalf("binary size %d != GNU %d", len(got), len(want))
			}
			for i := range want {
				if want[i] != got[i] {
					t.Fatalf("binary differs at offset %#x: %#x != GNU %#x", i, got[i], want[i])
				}
			}
		})
	}
}

func trimLog(b []byte) string {
	s := string(b)
	if len(s) > 800 {
		return s[:800]
	}
	return s
}
