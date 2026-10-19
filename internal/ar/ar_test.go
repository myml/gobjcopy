package ar_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/ar"
	"github.com/myml/gobjcopy/internal/fixtures"
)

// requireTool returns the path of a system tool or skips the test.
func requireTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not available", name)
	}
	return p
}

// archiveDir builds the ELF fixtures and copies the ones the archive tests
// need into a scratch directory with stable names.
func archiveDir(t *testing.T) string {
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

// runTool runs a tool in dir and returns combined output.
func runTool(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	prog := requireTool(t, name)
	cmd := exec.Command(prog, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// writeFile writes data in dir under name.
func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// readArchive reads and parses an archive file.
func readArchive(t *testing.T, path string) (*ar.Archive, []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	a, err := ar.Parse(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return a, data
}

// arList returns the member names reported by GNU ar.
func arList(t *testing.T, dir, archive string) []string {
	t.Helper()
	out := runTool(t, dir, "ar", "t", archive)
	return strings.Fields(out)
}

func memberNames(a *ar.Archive) []string {
	names := make([]string, len(a.Members))
	for i, m := range a.Members {
		names[i] = m.Name
	}
	return names
}

func TestParseSystemArchive(t *testing.T) {
	dir := archiveDir(t)
	// A name longer than 15 characters forces the "//" extended name table.
	reloc, err := os.ReadFile(filepath.Join(dir, "reloc.o"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "averyverylongmembername.o", reloc)
	runTool(t, dir, "ar", "rc", "lib.a", "reloc.o", "hello", "averyverylongmembername.o")

	a, _ := readArchive(t, filepath.Join(dir, "lib.a"))
	want := []string{"reloc.o", "hello", "averyverylongmembername.o"}
	if got := memberNames(a); !equalStrings(got, want) {
		t.Fatalf("member names = %v, want %v", got, want)
	}
	if !a.HasSymbolTable {
		t.Error("HasSymbolTable = false, want true")
	}
	hello, err := os.ReadFile(filepath.Join(dir, "hello"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Members[1].Data, hello) {
		t.Error("hello member data does not match the input file")
	}
	if !bytes.Equal(a.Members[2].Data, reloc) {
		t.Error("long-named member data does not match the input file")
	}
	if got := arList(t, dir, "lib.a"); !equalStrings(got, want) {
		t.Fatalf("ar t = %v, want %v", got, want)
	}
	if len(a.Members[2].Name) <= 15 {
		t.Fatal("test setup did not produce a long name")
	}
}

func TestWritePreservesNamesAndData(t *testing.T) {
	dir := archiveDir(t)
	reloc, err := os.ReadFile(filepath.Join(dir, "reloc.o"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "averyverylongmembername.o", reloc)
	writeFile(t, dir, "notes.txt", []byte("not an object\n"))
	runTool(t, dir, "ar", "rc", "in.a", "reloc.o", "hello", "averyverylongmembername.o", "notes.txt")

	in, _ := readArchive(t, filepath.Join(dir, "in.a"))
	outData, err := in.Bytes(ar.WriteOptions{Deterministic: true})
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	writeFile(t, dir, "out.a", outData)

	out, _ := readArchive(t, filepath.Join(dir, "out.a"))
	if got, want := memberNames(out), memberNames(in); !equalStrings(got, want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	for i := range in.Members {
		if !bytes.Equal(out.Members[i].Data, in.Members[i].Data) {
			t.Errorf("member %s data changed", in.Members[i].Name)
		}
	}
	if got, want := arList(t, dir, "out.a"), memberNames(in); !equalStrings(got, want) {
		t.Fatalf("ar t out.a = %v, want %v", got, want)
	}
	// The non-object member must have been copied verbatim.
	if got := string(out.Members[3].Data); got != "not an object\n" {
		t.Errorf("non-object member = %q", got)
	}
}

func TestSymbolTableRebuilt(t *testing.T) {
	dir := archiveDir(t)
	runTool(t, dir, "ar", "rc", "in.a", "reloc.o", "hello")

	in, _ := readArchive(t, filepath.Join(dir, "in.a"))
	for _, m := range in.Members {
		m.Symbols = elfSymbols(t, m.Data)
	}
	outData, err := in.Bytes(ar.WriteOptions{Deterministic: true, SymbolTable: true})
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	writeFile(t, dir, "out.a", outData)

	// GNU nm -s prints the archive index that our writer rebuilt. It must
	// name the same symbols in the same members as the system ar index.
	before := runTool(t, dir, "nm", "-s", "in.a")
	after := runTool(t, dir, "nm", "-s", "out.a")
	if before != after {
		t.Errorf("nm -s differs after round trip\n--- input ---\n%s\n--- output ---\n%s", before, after)
	}
	if !strings.Contains(after, "func_a in reloc.o") {
		t.Errorf("rebuilt index is missing reloc.o symbols:\n%s", after)
	}
	if got, want := arList(t, dir, "out.a"), []string{"reloc.o", "hello"}; !equalStrings(got, want) {
		t.Fatalf("ar t out.a = %v, want %v", got, want)
	}
}

func TestDeterministicMetadataAndStability(t *testing.T) {
	dir := archiveDir(t)
	runTool(t, dir, "ar", "rcU", "in.a", "reloc.o", "hello")
	in, _ := readArchive(t, filepath.Join(dir, "in.a"))
	if in.Members[0].Mtime == 0 {
		t.Fatal("ar rcU did not preserve a timestamp")
	}

	first, err := in.Bytes(ar.WriteOptions{Deterministic: true, SymbolTable: true})
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	second, err := in.Bytes(ar.WriteOptions{Deterministic: true, SymbolTable: true})
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("deterministic output is not byte stable")
	}

	path := writeFile(t, dir, "det.a", first)
	out, _ := readArchive(t, path)
	for _, m := range out.Members {
		if m.Mtime != 0 || m.UID != 0 || m.GID != 0 || m.Mode != 0o644 {
			t.Errorf("member %s metadata = mtime %d uid %d gid %d mode %o, want all deterministic",
				m.Name, m.Mtime, m.UID, m.GID, m.Mode)
		}
	}

	// Rewriting the deterministic archive must reproduce it exactly.
	again, err := out.Bytes(ar.WriteOptions{Deterministic: true, SymbolTable: true})
	if err != nil {
		t.Fatalf("Bytes again: %v", err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("deterministic output is not idempotent")
	}
}

func TestNonDeterministicPreservesMetadata(t *testing.T) {
	dir := archiveDir(t)
	runTool(t, dir, "ar", "rcU", "in.a", "reloc.o", "hello")
	in, _ := readArchive(t, filepath.Join(dir, "in.a"))

	data, err := in.Bytes(ar.WriteOptions{Deterministic: false})
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	out, err := ar.Parse(data)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	for i := range in.Members {
		want, got := in.Members[i], out.Members[i]
		if got.Mtime != want.Mtime || got.UID != want.UID || got.GID != want.GID || got.Mode != want.Mode {
			t.Errorf("member %s metadata = mtime %d uid %d gid %d mode %o, want mtime %d uid %d gid %d mode %o",
				want.Name, got.Mtime, got.UID, got.GID, got.Mode,
				want.Mtime, want.UID, want.GID, want.Mode)
		}
	}
}

func TestEmptyArchive(t *testing.T) {
	a, err := ar.Parse([]byte(ar.Magic))
	if err != nil {
		t.Fatalf("parse empty archive: %v", err)
	}
	if len(a.Members) != 0 {
		t.Fatalf("members = %d, want 0", len(a.Members))
	}
	out, err := a.Bytes(ar.WriteOptions{Deterministic: true})
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if string(out) != ar.Magic {
		t.Fatalf("empty archive bytes = %q, want %q", out, ar.Magic)
	}
}

func TestParseBSDName(t *testing.T) {
	// BSD archives store the member name at the start of the member data and
	// record its length as "#1/<n>".
	body := append([]byte("hello.txt\x00\x00"), []byte("payload")...)
	var h [60]byte
	for i := range h {
		h[i] = ' '
	}
	copy(h[0:16], "#1/11")
	copy(h[16:28], "0")
	copy(h[28:34], "0")
	copy(h[34:40], "0")
	copy(h[40:48], "644")
	copy(h[48:58], fmt.Sprint(len(body)))
	h[58], h[59] = '`', '\n'
	data := append([]byte(ar.Magic), h[:]...)
	data = append(data, body...)
	if len(data)%2 == 1 {
		data = append(data, '\n')
	}

	a, err := ar.Parse(data)
	if err != nil {
		t.Fatalf("parse BSD archive: %v", err)
	}
	if len(a.Members) != 1 {
		t.Fatalf("members = %d, want 1", len(a.Members))
	}
	if got, want := a.Members[0].Name, "hello.txt"; got != want {
		t.Errorf("name = %q, want %q", got, want)
	}
	if got, want := string(a.Members[0].Data), "payload"; got != want {
		t.Errorf("data = %q, want %q", got, want)
	}
}

func TestParseErrors(t *testing.T) {
	header := func(name, size string) []byte {
		var h [60]byte
		for i := range h {
			h[i] = ' '
		}
		copy(h[0:16], name)
		copy(h[48:58], size)
		h[58], h[59] = '`', '\n'
		return h[:]
	}
	withMagic := func(parts ...[]byte) []byte {
		data := []byte(ar.Magic)
		for _, p := range parts {
			data = append(data, p...)
		}
		return data
	}
	badMagic := header("x/", "0")
	badMagic[58] = '\n'

	cases := []struct {
		name string
		data []byte
	}{
		{"not an archive", []byte("hello")},
		{"thin archive", []byte(ar.ThinMagic)},
		{"truncated header", withMagic([]byte("short"))},
		{"bad header magic", withMagic(badMagic)},
		{"truncated member", withMagic(header("x/", "10"), []byte("abc"))},
		{"bad extended reference", withMagic(header("/7", "0"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ar.Parse(tc.data); err == nil {
				t.Fatal("Parse succeeded, want an error")
			}
		})
	}
}

// elfSymbols extracts the global symbols of an ELF member using the same rule
// as the archive writer's caller.
func elfSymbols(t *testing.T, data []byte) []string {
	t.Helper()
	f, err := elf.Parse(data)
	if err != nil {
		t.Fatalf("parse member: %v", err)
	}
	st := f.Symtab()
	if st == nil {
		return nil
	}
	var names []string
	for _, sym := range st.Entries {
		if sym.Name == "" || sym.Shndx == elf.SHN_UNDEF {
			continue
		}
		bind := sym.Bind()
		if bind == elf.STB_GLOBAL || bind == elf.STB_WEAK || bind == elf.STB_GNU_UNIQUE || sym.Shndx == elf.SHN_COMMON {
			names = append(names, sym.Name)
		}
	}
	return names
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
