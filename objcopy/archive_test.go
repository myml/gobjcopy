package objcopy_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/ar"
	"github.com/myml/gobjcopy/internal/fixtures"
	"github.com/myml/gobjcopy/objcopy"
)

// archiveTool returns the path of a system tool or skips the test.
func archiveTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not available", name)
	}
	return p
}

// archiveWorkdir builds the ELF fixtures in a scratch directory.
func archiveWorkdir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	fx, err := fixtures.Build(dir)
	if err != nil {
		t.Fatalf("build fixtures: %v", err)
	}
	for _, name := range []string{"reloc.o", "hello"} {
		if _, ok := fx[name]; !ok {
			t.Skipf("fixture %s unavailable on this host", name)
		}
	}
	return dir
}

// runArchiveTool runs a tool in dir and returns combined output.
func runArchiveTool(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	prog := archiveTool(t, name)
	cmd := exec.Command(prog, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// unpackArchive parses an archive file written in dir.
func unpackArchive(t *testing.T, dir, name string) *ar.Archive {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	a, err := ar.Parse(data)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return a
}

// archiveMemberNames returns the names of a's real members.
func archiveMemberNames(a *ar.Archive) []string {
	names := make([]string, len(a.Members))
	for i, m := range a.Members {
		names[i] = m.Name
	}
	return names
}

// requireNames compares the archive member list against want.
func requireNames(t *testing.T, a *ar.Archive, want []string) {
	t.Helper()
	if got := archiveMemberNames(a); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("members = %v, want %v", got, want)
	}
}

// parseMember parses an ELF member, skipping non-ELF data.
func parseMember(t *testing.T, m *ar.Member) *elf.File {
	t.Helper()
	f, err := elf.Parse(m.Data)
	if err != nil {
		t.Fatalf("parse member %s: %v", m.Name, err)
	}
	return f
}

// compressedDebugSections counts SHF_COMPRESSED debug sections.
func compressedDebugSections(f *elf.File) int {
	n := 0
	for _, s := range f.Sections {
		if isDebugName(s.Name) && s.Flags&elf.SHF_COMPRESSED != 0 {
			n++
		}
	}
	return n
}

func isDebugName(name string) bool {
	return strings.HasPrefix(name, ".debug") || strings.HasPrefix(name, ".zdebug")
}

func sectionsByName(f *elf.File) map[string]*elf.Section {
	m := make(map[string]*elf.Section, len(f.Sections))
	for _, s := range f.Sections {
		m[s.Name] = s
	}
	return m
}

func boolValue(b bool) *bool { return &b }

func TestArchiveCompressDebug(t *testing.T) {
	dir := archiveWorkdir(t)
	runArchiveTool(t, dir, "ar", "rc", "lib.a", "reloc.o", "hello")

	cfg := objcopy.Default()
	cfg.CompressDebug = "zlib-gabi"
	if err := objcopy.Run(cfg, filepath.Join(dir, "lib.a"), filepath.Join(dir, "out.a")); err != nil {
		t.Fatalf("Run: %v", err)
	}

	out := unpackArchive(t, dir, "out.a")
	requireNames(t, out, []string{"reloc.o", "hello"})
	for _, m := range out.Members {
		f := parseMember(t, m)
		if n := compressedDebugSections(f); n == 0 {
			t.Errorf("member %s has no compressed debug sections", m.Name)
		}
	}
	// GNU ar must be able to read the rebuilt archive and its index.
	if got := strings.Fields(runArchiveTool(t, dir, "ar", "t", "out.a")); strings.Join(got, ",") != "reloc.o,hello" {
		t.Fatalf("ar t = %v", got)
	}
	if out := runArchiveTool(t, dir, "nm", "-s", "out.a"); !strings.Contains(out, "func_a in reloc.o") {
		t.Errorf("rebuilt archive index is missing reloc.o symbols:\n%s", out)
	}
	// readelf must parse every member.
	runArchiveTool(t, dir, "readelf", "-S", "--wide", "out.a")
}

func TestArchiveDecompressDebug(t *testing.T) {
	dir := archiveWorkdir(t)
	runArchiveTool(t, dir, "ar", "rc", "lib.a", "reloc.o", "hello")

	compress := objcopy.Default()
	compress.CompressDebug = "zlib-gabi"
	if err := objcopy.Run(compress, filepath.Join(dir, "lib.a"), filepath.Join(dir, "compressed.a")); err != nil {
		t.Fatalf("compress: %v", err)
	}

	decompress := objcopy.Default()
	decompress.DecompressDebug = true
	if err := objcopy.Run(decompress, filepath.Join(dir, "compressed.a"), filepath.Join(dir, "out.a")); err != nil {
		t.Fatalf("decompress: %v", err)
	}

	in := unpackArchive(t, dir, "lib.a")
	out := unpackArchive(t, dir, "out.a")
	requireNames(t, out, archiveMemberNames(in))
	for i, m := range out.Members {
		f := parseMember(t, m)
		for _, s := range f.Sections {
			if isDebugName(s.Name) && s.Flags&elf.SHF_COMPRESSED != 0 {
				t.Errorf("member %s section %s is still compressed", m.Name, s.Name)
			}
		}
		// Decompression must restore the original bytes of every debug
		// section that the compressor rewrote.
		want := sectionsByName(parseMember(t, in.Members[i]))
		for name, got := range sectionsByName(f) {
			if !isDebugName(name) || got.Flags&elf.SHF_COMPRESSED != 0 {
				continue
			}
			if orig, ok := want[name]; ok && !bytes.Equal(orig.Data, got.Data) {
				t.Errorf("member %s section %s data changed", m.Name, name)
			}
		}
	}
	runArchiveTool(t, dir, "readelf", "-S", "--wide", "out.a")
	runArchiveTool(t, dir, "nm", "-s", "out.a")
}

func TestArchiveDeterministicAndPreserve(t *testing.T) {
	dir := archiveWorkdir(t)
	// rcU keeps the real timestamps and modes, which gives -U something to
	// preserve and the deterministic path something to zero.
	runArchiveTool(t, dir, "ar", "rcU", "lib.a", "reloc.o", "hello")
	in := unpackArchive(t, dir, "lib.a")
	if in.Members[0].Mtime == 0 || in.Members[0].Mode == 0o644 && in.Members[1].Mode == 0o644 {
		t.Fatal("test setup did not preserve metadata")
	}

	// The default (nil DeterministicArchives) follows GNU -D.
	if err := objcopy.Run(objcopy.Default(), filepath.Join(dir, "lib.a"), filepath.Join(dir, "det1.a")); err != nil {
		t.Fatalf("Run det1: %v", err)
	}
	explicit := objcopy.Default()
	explicit.DeterministicArchives = boolValue(true)
	if err := objcopy.Run(explicit, filepath.Join(dir, "lib.a"), filepath.Join(dir, "det2.a")); err != nil {
		t.Fatalf("Run det2: %v", err)
	}
	det1, err := os.ReadFile(filepath.Join(dir, "det1.a"))
	if err != nil {
		t.Fatal(err)
	}
	det2, err := os.ReadFile(filepath.Join(dir, "det2.a"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(det1, det2) {
		t.Fatal("deterministic archive output is not byte stable")
	}
	for _, m := range unpackArchive(t, dir, "det1.a").Members {
		if m.Mtime != 0 || m.UID != 0 || m.GID != 0 || m.Mode != 0o644 {
			t.Errorf("member %s metadata = mtime %d uid %d gid %d mode %o, want deterministic",
				m.Name, m.Mtime, m.UID, m.GID, m.Mode)
		}
	}

	preserve := objcopy.Default()
	preserve.DeterministicArchives = boolValue(false)
	if err := objcopy.Run(preserve, filepath.Join(dir, "lib.a"), filepath.Join(dir, "undet.a")); err != nil {
		t.Fatalf("Run -U: %v", err)
	}
	for i, m := range unpackArchive(t, dir, "undet.a").Members {
		want := in.Members[i]
		if m.Mtime != want.Mtime || m.UID != want.UID || m.GID != want.GID || m.Mode != want.Mode {
			t.Errorf("member %s metadata = mtime %d uid %d gid %d mode %o, want mtime %d uid %d gid %d mode %o",
				m.Name, m.Mtime, m.UID, m.GID, m.Mode,
				want.Mtime, want.UID, want.GID, want.Mode)
		}
	}
}

func TestArchiveInPlace(t *testing.T) {
	dir := archiveWorkdir(t)
	runArchiveTool(t, dir, "ar", "rc", "lib.a", "reloc.o", "hello")
	path := filepath.Join(dir, "work.a")
	if err := os.Rename(filepath.Join(dir, "lib.a"), path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}

	cfg := objcopy.Default()
	cfg.StripDebug = true
	if err := objcopy.Run(cfg, path, ""); err != nil {
		t.Fatalf("Run in place: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o640 {
		t.Errorf("in-place mode = %o, want 640", got)
	}
	out := unpackArchive(t, dir, "work.a")
	requireNames(t, out, []string{"reloc.o", "hello"})
	for _, m := range out.Members {
		f := parseMember(t, m)
		for _, s := range f.Sections {
			if strings.HasPrefix(s.Name, ".debug") {
				t.Errorf("member %s still has %s after --strip-debug", m.Name, s.Name)
			}
		}
	}
}

func TestArchiveLongNamesAndOpaqueMembers(t *testing.T) {
	dir := archiveWorkdir(t)
	reloc, err := os.ReadFile(filepath.Join(dir, "reloc.o"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "averyverylongmembername.o"), reloc, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("plain text\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runArchiveTool(t, dir, "ar", "rc", "lib.a", "averyverylongmembername.o", "notes.txt", "reloc.o")

	cfg := objcopy.Default()
	var warnings []string
	cfg.Warnf = func(format string, args ...any) {
		warnings = append(warnings, format)
	}
	if err := objcopy.Run(cfg, filepath.Join(dir, "lib.a"), filepath.Join(dir, "out.a")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := unpackArchive(t, dir, "out.a")
	requireNames(t, out, []string{"averyverylongmembername.o", "notes.txt", "reloc.o"})
	if got := string(out.Members[1].Data); got != "plain text\n" {
		t.Errorf("opaque member = %q", got)
	}
	if len(warnings) == 0 {
		t.Error("expected a warning for the non-object member")
	}
	runArchiveTool(t, dir, "ar", "t", "out.a")
}

func TestArchiveStripAllDropsIndex(t *testing.T) {
	dir := archiveWorkdir(t)
	runArchiveTool(t, dir, "ar", "rc", "lib.a", "reloc.o", "hello")

	cfg := objcopy.Default()
	cfg.StripAll = true
	if err := objcopy.Run(cfg, filepath.Join(dir, "lib.a"), filepath.Join(dir, "out.a")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := unpackArchive(t, dir, "out.a")
	if out.HasSymbolTable {
		t.Error("--strip-all archive still has a symbol table")
	}
	if strings.Contains(runArchiveTool(t, dir, "nm", "-s", "out.a"), "Archive index:") {
		t.Error("--strip-all archive still has an index")
	}
	for _, m := range out.Members {
		if parseMember(t, m).Symtab() != nil {
			t.Errorf("member %s still has a symbol table", m.Name)
		}
	}
}

func TestArchiveAddDebugLinkIgnored(t *testing.T) {
	dir := archiveWorkdir(t)
	runArchiveTool(t, dir, "ar", "rc", "lib.a", "reloc.o")
	if err := os.WriteFile(filepath.Join(dir, "reloc.debug"), []byte("debug"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := objcopy.Default()
	cfg.AddDebugLink = filepath.Join(dir, "reloc.debug")
	var warnings []string
	cfg.Warnf = func(format string, args ...any) {
		warnings = append(warnings, format)
	}
	if err := objcopy.Run(cfg, filepath.Join(dir, "lib.a"), filepath.Join(dir, "out.a")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "--add-gnu-debuglink ignored for archive") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing --add-gnu-debuglink warning, got %v", warnings)
	}
	for _, m := range unpackArchive(t, dir, "out.a").Members {
		if parseMember(t, m).Section(".gnu_debuglink") != nil {
			t.Errorf("member %s got a .gnu_debuglink section", m.Name)
		}
	}
}

func TestArchiveOutputBinaryFails(t *testing.T) {
	dir := archiveWorkdir(t)
	runArchiveTool(t, dir, "ar", "rc", "lib.a", "reloc.o")
	cfg := objcopy.Default()
	cfg.OutputTarget = "binary"
	err := objcopy.Run(cfg, filepath.Join(dir, "lib.a"), filepath.Join(dir, "out.bin"))
	if err == nil || !strings.Contains(err.Error(), "invalid operation") {
		t.Fatalf("Run with -O binary error = %v, want invalid operation", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out.bin")); !os.IsNotExist(statErr) {
		t.Errorf("output file was created despite the error")
	}
}

func TestArchiveThinFails(t *testing.T) {
	dir := archiveWorkdir(t)
	runArchiveTool(t, dir, "ar", "rcT", "thin.a", "reloc.o")
	err := objcopy.Run(objcopy.Default(), filepath.Join(dir, "thin.a"), filepath.Join(dir, "out.a"))
	if err == nil || !strings.Contains(err.Error(), "thin archives") {
		t.Fatalf("Run on thin archive error = %v, want thin archive diagnostic", err)
	}
}
