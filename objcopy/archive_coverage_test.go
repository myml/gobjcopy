package objcopy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/ar"
	"github.com/myml/gobjcopy/internal/fixtures"
)

// arcCovObject returns the bytes of a real relocatable object.
func arcCovObject(t *testing.T) []byte {
	t.Helper()
	p, err := fixtures.BuildOne(t.TempDir(), "reloc.o")
	if err != nil {
		t.Skipf("fixture reloc.o unavailable: %v", err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

// arcCovArchive builds a deterministic archive in memory. A symbol index is
// written only when withIndex is true; the members need not carry symbols.
func arcCovArchive(t *testing.T, withIndex bool, members ...*ar.Member) []byte {
	t.Helper()
	return arcCovArchiveMeta(t, withIndex, true, members...)
}

// arcCovArchiveMeta is arcCovArchive with control over metadata normalization.
func arcCovArchiveMeta(t *testing.T, withIndex, deterministic bool, members ...*ar.Member) []byte {
	t.Helper()
	a := &ar.Archive{Members: members, HasSymbolTable: withIndex}
	blob, err := a.Bytes(ar.WriteOptions{Deterministic: deterministic, SymbolTable: withIndex})
	if err != nil {
		t.Fatalf("build archive: %v", err)
	}
	return blob
}

func arcCovWrite(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func arcCovRead(t *testing.T, path string) *ar.Archive {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	a, err := ar.Parse(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return a
}

func arcCovBool(b bool) *bool { return &b }

// TestArchiveCoverageDispatch exercises every early return of runArchive:
// non-archive input, thin archives, non-ELF input targets, invalid output
// targets, non-ELF output targets, unparsable archives and stat failures.
func TestArchiveCoverageDispatch(t *testing.T) {
	obj := arcCovObject(t)
	data := arcCovArchive(t, true, &ar.Member{Name: "reloc.o", Data: obj})
	dir := t.TempDir()
	inPath := arcCovWrite(t, dir, "lib.a", data)

	if handled, err := runArchive(Default(), filepath.Join(dir, "plain"), "", []byte("hello")); handled || err != nil {
		t.Errorf("non-archive: handled=%v err=%v, want false,nil", handled, err)
	}

	handled, err := runArchive(Default(), filepath.Join(dir, "thin.a"), "", []byte(ar.ThinMagic))
	if !handled || err == nil || !strings.Contains(err.Error(), "thin archives") {
		t.Errorf("thin archive: handled=%v err=%v", handled, err)
	}

	// A non-ELF input target makes the archive bytes ordinary input for the
	// normal pipeline, so runArchive declines to handle them.
	cfg := Default()
	cfg.InputTarget = "binary"
	if handled, err := runArchive(cfg, inPath, filepath.Join(dir, "bin"), data); handled || err != nil {
		t.Errorf("-I binary: handled=%v err=%v, want false,nil", handled, err)
	}

	// An ELF input target still leaves the file an archive.
	cfg = Default()
	cfg.InputTarget = "elf64-x86-64"
	if handled, err := runArchive(cfg, inPath, filepath.Join(dir, "outed.a"), data); !handled || err != nil {
		t.Errorf("-I elf64-x86-64: handled=%v err=%v, want true,nil", handled, err)
	}

	// An unparsable output target is reported before any member is touched.
	cfg = Default()
	cfg.OutputTarget = "no-such-target"
	if handled, err := runArchive(cfg, inPath, filepath.Join(dir, "bad.a"), data); !handled || err == nil {
		t.Errorf("bad -O: handled=%v err=%v, want true,error", handled, err)
	}

	for _, target := range []string{"binary", "ihex", "srec", "verilog"} {
		cfg := Default()
		cfg.OutputTarget = target
		out := filepath.Join(dir, "out-"+target)
		handled, err := runArchive(cfg, inPath, out, data)
		if !handled || err == nil || !strings.Contains(err.Error(), "invalid operation") {
			t.Errorf("-O %s: handled=%v err=%v", target, handled, err)
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Errorf("-O %s created an output file", target)
		}
	}

	// Magic followed by garbage is an archive that fails to parse.
	broken := append([]byte(ar.Magic), []byte("garbage")...)
	if handled, err := runArchive(Default(), filepath.Join(dir, "broken.a"), "", broken); !handled || err == nil {
		t.Errorf("broken archive: handled=%v err=%v, want true,error", handled, err)
	}

	// A valid archive read from a path that disappeared fails at stat time.
	if handled, err := runArchive(Default(), filepath.Join(dir, "missing.a"), "", data); !handled || err == nil {
		t.Errorf("missing input: handled=%v err=%v, want true,error", handled, err)
	}
}

// TestArchiveCoverageMembers covers the per-member branches: opaque members,
// members that look like ELF but do not parse, transform errors, output target
// conversion and the symbol index decision.
func TestArchiveCoverageMembers(t *testing.T) {
	obj := arcCovObject(t)
	dir := t.TempDir()

	// An ELF identification followed by nonsense makes elf.Parse fail while
	// isELF still reports true.
	badELF := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1}, bytes.Repeat([]byte{0xff}, 16)...)
	data := arcCovArchive(t, true,
		&ar.Member{Name: "reloc.o", Data: obj},
		&ar.Member{Name: "notes.txt", Data: []byte("plain text")},
		&ar.Member{Name: "bad.o", Data: badELF},
	)
	inPath := arcCovWrite(t, dir, "lib.a", data)

	cfg := Default()
	var warnings []string
	cfg.Warnf = func(format string, args ...any) { warnings = append(warnings, format) }
	outPath := filepath.Join(dir, "out.a")
	handled, err := runArchive(cfg, inPath, outPath, data)
	if !handled || err != nil {
		t.Fatalf("runArchive: handled=%v err=%v", handled, err)
	}
	out := arcCovRead(t, outPath)
	if got := len(out.Members); got != 3 {
		t.Fatalf("members = %d, want 3", got)
	}
	if out.Members[1].Name != "notes.txt" || string(out.Members[1].Data) != "plain text" {
		t.Errorf("opaque member = %q %q", out.Members[1].Name, out.Members[1].Data)
	}
	if out.Members[2].Name != "bad.o" || !bytes.Equal(out.Members[2].Data, badELF) {
		t.Errorf("unparsable member was not copied verbatim")
	}
	if !out.HasSymbolTable {
		t.Error("symbol index was not rebuilt")
	}
	if len(warnings) < 2 {
		t.Errorf("warnings = %v, want one per unrecognized member", warnings)
	}

	// A transform that fails aborts the whole archive and names the member.
	c := Default()
	c.AddSections = []AddSection{{Name: ".extra", File: filepath.Join(dir, "does-not-exist")}}
	if handled, err := runArchive(c, inPath, filepath.Join(dir, "fail.a"), data); !handled || err == nil || !strings.Contains(err.Error(), "reloc.o") {
		t.Errorf("transform error: handled=%v err=%v", handled, err)
	}

	// Cross-endian output targets pass the archive-level check but fail when
	// the member is serialized.
	c = Default()
	c.OutputTarget = "elf64-big"
	handled, err = runArchive(c, inPath, filepath.Join(dir, "big.a"), data)
	if !handled || err == nil || !strings.Contains(err.Error(), "endian") {
		t.Errorf("cross-endian output: handled=%v err=%v", handled, err)
	}

	// An explicit, compatible output target exercises the applyFormat path.
	c = Default()
	c.OutputTarget = "elf64-x86-64"
	okPath := filepath.Join(dir, "conv.a")
	if handled, err := runArchive(c, inPath, okPath, data); !handled || err != nil {
		t.Fatalf("compatible output: handled=%v err=%v", handled, err)
	}
	f, err := elf.Parse(arcCovRead(t, okPath).Members[0].Data)
	if err != nil {
		t.Fatalf("parse converted member: %v", err)
	}
	if f.Section(".text") == nil {
		t.Error("converted member lost .text")
	}

	// Strip-all drops the index even though the input had one.
	c = Default()
	c.StripAll = true
	stripPath := filepath.Join(dir, "strip.a")
	if handled, err := runArchive(c, inPath, stripPath, data); !handled || err != nil {
		t.Fatalf("strip-all: handled=%v err=%v", handled, err)
	}
	if arcCovRead(t, stripPath).HasSymbolTable {
		t.Error("strip-all archive kept the symbol index")
	}

	// An input without an index must not gain one.
	noIndex := arcCovArchive(t, false, &ar.Member{Name: "reloc.o", Data: obj})
	noIndexPath := arcCovWrite(t, dir, "noindex.a", noIndex)
	plainPath := filepath.Join(dir, "plain.a")
	if handled, err := runArchive(Default(), noIndexPath, plainPath, noIndex); !handled || err != nil {
		t.Fatalf("no-index archive: handled=%v err=%v", handled, err)
	}
	if arcCovRead(t, plainPath).HasSymbolTable {
		t.Error("archive without an index gained one")
	}

	// --add-gnu-debuglink is ignored for archives.
	c = Default()
	c.AddDebugLink = filepath.Join(dir, "reloc.debug")
	var linkWarnings []string
	c.Warnf = func(format string, args ...any) { linkWarnings = append(linkWarnings, format) }
	linkPath := filepath.Join(dir, "link.a")
	if handled, err := runArchive(c, noIndexPath, linkPath, noIndex); !handled || err != nil {
		t.Fatalf("debuglink: handled=%v err=%v", handled, err)
	}
	found := false
	for _, w := range linkWarnings {
		if strings.Contains(w, "--add-gnu-debuglink ignored for archive") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing debuglink warning, got %v", linkWarnings)
	}
	if fm, err := elf.Parse(arcCovRead(t, linkPath).Members[0].Data); err == nil && fm.Section(".gnu_debuglink") != nil {
		t.Error("member gained a .gnu_debuglink section")
	}
}

// TestArchiveCoverageMetadataAndOrder covers member order, long names, -D/-U,
// in-place output, -p and verbose reporting.
func TestArchiveCoverageMetadataAndOrder(t *testing.T) {
	obj := arcCovObject(t)
	data := arcCovArchiveMeta(t, false, false,
		&ar.Member{Name: "averyverylongmembername.o", Data: obj, Mtime: 1234, UID: 5, GID: 6, Mode: 0o100644},
		&ar.Member{Name: "second.o", Data: obj, Mtime: 1234, UID: 5, GID: 6, Mode: 0o100755},
		&ar.Member{Name: "third.o", Data: obj, Mtime: 1234, UID: 5, GID: 6, Mode: 0o100644},
	)
	dir := t.TempDir()
	inPath := arcCovWrite(t, dir, "in.a", data)

	// -U keeps the recorded metadata.
	c := Default()
	c.DeterministicArchives = arcCovBool(false)
	outPath := filepath.Join(dir, "preserve.a")
	if handled, err := runArchive(c, inPath, outPath, data); !handled || err != nil {
		t.Fatalf("runArchive -U: handled=%v err=%v", handled, err)
	}
	out := arcCovRead(t, outPath)
	wantNames := []string{"averyverylongmembername.o", "second.o", "third.o"}
	wantModes := []uint32{0o100644, 0o100755, 0o100644}
	for i, m := range out.Members {
		if m.Name != wantNames[i] {
			t.Errorf("member %d = %q, want %q", i, m.Name, wantNames[i])
		}
		if m.Mtime != 1234 || m.UID != 5 || m.GID != 6 || m.Mode != wantModes[i] {
			t.Errorf("member %q metadata = %d/%d/%d/%o, want 1234/5/6/%o",
				m.Name, m.Mtime, m.UID, m.GID, m.Mode, wantModes[i])
		}
	}

	// The default is deterministic.
	detPath := filepath.Join(dir, "det.a")
	if handled, err := runArchive(Default(), inPath, detPath, data); !handled || err != nil {
		t.Fatalf("runArchive -D: handled=%v err=%v", handled, err)
	}
	for _, m := range arcCovRead(t, detPath).Members {
		if m.Mtime != 0 || m.UID != 0 || m.GID != 0 || m.Mode != 0o644 {
			t.Errorf("member %q not deterministic: %d/%d/%d/%o", m.Name, m.Mtime, m.UID, m.GID, m.Mode)
		}
	}

	// In-place output keeps the file mode and, with -p, its timestamp.
	ipPath := arcCovWrite(t, dir, "inplace.a", data)
	if err := os.Chmod(ipPath, 0o640); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1_000_000_000, 0)
	if err := os.Chtimes(ipPath, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	c = Default()
	c.PreserveDates = true
	c.Verbose = true
	var messages []string
	c.Infof = func(format string, args ...any) { messages = append(messages, format) }
	if handled, err := runArchive(c, ipPath, "", data); !handled || err != nil {
		t.Fatalf("runArchive in place: handled=%v err=%v", handled, err)
	}
	st, err := os.Stat(ipPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o640 {
		t.Errorf("in-place mode = %o, want 640", got)
	}
	if got := st.ModTime().Unix(); got != stamp.Unix() {
		t.Errorf("in-place mtime = %d, want %d", got, stamp.Unix())
	}
	if len(messages) == 0 || !strings.Contains(messages[0], "copying archive") {
		t.Errorf("verbose messages = %v", messages)
	}
	if got := len(arcCovRead(t, ipPath).Members); got != 3 {
		t.Errorf("in-place members = %d, want 3", got)
	}
}
