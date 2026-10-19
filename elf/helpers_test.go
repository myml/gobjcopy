package elf_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/elfdump"
	"github.com/myml/gobjcopy/internal/fixtures"
)

// fixtureMap caches the ELF corpus built once in TestMain. Tests must not
// modify the files it points at.
var (
	fixtureMap map[string]string
	fixtureErr error
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gobjcopy-fixtures-")
	if err != nil {
		fixtureErr = err
	} else {
		fixtureMap, fixtureErr = fixtures.Build(dir)
	}
	code := m.Run()
	if dir != "" {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

// allFixtures returns the built samples, skipping the test when the corpus is
// empty (for example when gcc is not installed).
func allFixtures(t *testing.T) map[string]string {
	t.Helper()
	if fixtureErr != nil {
		t.Skipf("fixtures unavailable: %v", fixtureErr)
	}
	if len(fixtureMap) == 0 {
		t.Skip("fixtures unavailable: no samples could be built (missing gcc?)")
	}
	return fixtureMap
}

// fixture returns one named sample, skipping when it was not built.
func fixture(t *testing.T, name string) string {
	t.Helper()
	allFixtures(t)
	p, ok := fixtureMap[name]
	if !ok {
		t.Skipf("fixture %q was not built on this host", name)
	}
	return p
}

// fixtureNames returns the sorted names of all available samples.
func fixtureNames(t *testing.T) []string {
	t.Helper()
	m := allFixtures(t)
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ---- tool helpers -------------------------------------------------------

func requireTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("required tool %q not found: %v", name, err)
	}
	return p
}

func lookPath(name string) (string, error) { return exec.LookPath(name) }

// runTool executes a tool with a timeout and returns its combined output.
func runTool(t *testing.T, binary string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("%s %s: timed out", binary, strings.Join(args, " "))
	}
	return string(out), err
}

// mustReadelf runs readelf and fails the test on a non-zero exit status. A
// non-zero status means readelf could not make sense of the file.
func mustReadelf(t *testing.T, path string, args ...string) string {
	t.Helper()
	readelf := requireTool(t, "readelf")
	out, err := runTool(t, readelf, append(append([]string(nil), args...), path)...)
	if err != nil {
		t.Fatalf("readelf %s %s failed: %v\n%s", strings.Join(args, " "), path, err, tail(out))
	}
	return out
}

func tail(s string) string {
	const max = 2000
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max:]
}

// writeELF serialises f to a fresh temporary file and returns its path.
func writeELF(t *testing.T, f *elf.File, perm os.FileMode, name string) string {
	t.Helper()
	b, err := f.Bytes()
	if err != nil {
		t.Fatalf("%s: Bytes: %v", name, err)
	}
	return writeBytes(t, b, perm, name)
}

func writeBytes(t *testing.T, b []byte, perm os.FileMode, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, perm); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatalf("chmod %s: %v", p, err)
	}
	return p
}

// runBinary runs path and returns its exit code and combined output. A binary
// that cannot be executed at all fails the test.
func runBinary(t *testing.T, path string) (int, string) {
	t.Helper()
	var out []byte
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		out, err = exec.CommandContext(ctx, path).CombinedOutput()
		cancel()
		if !errors.Is(err, syscall.ETXTBSY) {
			break
		}
		// The file may still be open for writing by this process on some
		// filesystems; retry briefly instead of reporting a spurious failure.
		time.Sleep(20 * time.Millisecond)
	}
	if err == nil {
		return 0, string(out)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	t.Fatalf("running %s: %v (output %q)", path, err, out)
	return 0, ""
}

// isRunnable reports whether f is an executable image (as opposed to a
// relocatable object or a shared library).
func isRunnable(f *elf.File) bool {
	if f.Type == elf.ET_EXEC {
		return true
	}
	if f.Type == elf.ET_DYN {
		for _, ph := range f.Segments {
			if ph.Type == elf.PT_INTERP {
				return true
			}
		}
	}
	return false
}

// openFixture parses a named fixture.
func openFixture(t *testing.T, name string) *elf.File {
	t.Helper()
	p := fixture(t, name)
	f, err := elf.Open(p)
	if err != nil {
		t.Fatalf("%s: Open(%s): %v", name, p, err)
	}
	return f
}

// reparse parses data and fails with per-test context.
func reparse(t *testing.T, data []byte, context string) *elf.File {
	t.Helper()
	f, err := elf.Parse(data)
	if err != nil {
		t.Fatalf("%s: Parse after serialisation: %v", context, err)
	}
	return f
}

// ---- semantic comparison ------------------------------------------------

// assertDumpsEqual compares the stable semantic dumps of two files and reports
// the first differing line.
func assertDumpsEqual(t *testing.T, name string, a, b *elf.File) {
	t.Helper()
	da := elfdump.Dump(a, elfdump.Default)
	db := elfdump.Dump(b, elfdump.Default)
	if diff := elfdump.FirstDiff(da, db); diff != "" {
		t.Errorf("%s: semantic dump mismatch:\n%s", name, diff)
	}
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// assertSemanticEqual compares every semantic property of the two files except
// file offsets. That includes section contents, symbols and relocations.
func assertSemanticEqual(t *testing.T, name string, a, b *elf.File) {
	t.Helper()
	if a.Header != b.Header {
		t.Errorf("%s: header mismatch: %+v != %+v", name, a.Header, b.Header)
	}
	if len(a.Sections) != len(b.Sections) {
		t.Fatalf("%s: section count %d != %d", name, len(a.Sections), len(b.Sections))
	}
	for i := range a.Sections {
		x, y := a.Sections[i], b.Sections[i]
		if x.Name != y.Name {
			t.Errorf("%s: section %d name %q != %q", name, i, x.Name, y.Name)
		}
		if x.Type != y.Type || x.Flags != y.Flags || x.Addr != y.Addr || x.Size != y.Size ||
			x.Link != y.Link || x.Info != y.Info || x.Addralign != y.Addralign || x.Entsize != y.Entsize {
			t.Errorf("%s: section %q header mismatch:\n  a: %+v\n  b: %+v",
				name, x.Name, x.SectionHeader, y.SectionHeader)
		}
		if x.IsNoBits() {
			continue
		}
		if !bytes.Equal(x.Data, y.Data) {
			t.Errorf("%s: section %q contents differ (sha %s != %s, len %d != %d)",
				name, x.Name, sha(x.Data), sha(y.Data), len(x.Data), len(y.Data))
		}
	}
	if len(a.Segments) != len(b.Segments) {
		t.Fatalf("%s: segment count %d != %d", name, len(a.Segments), len(b.Segments))
	}
	for i := range a.Segments {
		x, y := a.Segments[i], b.Segments[i]
		if x.Type != y.Type || x.Flags != y.Flags || x.Vaddr != y.Vaddr || x.Paddr != y.Paddr ||
			x.Memsz != y.Memsz || x.Align != y.Align {
			t.Errorf("%s: segment %d mismatch:\n  a: %+v\n  b: %+v", name, i, *x, *y)
		}
	}
	for i, sec := range a.Sections {
		if sec.Type != elf.SHT_SYMTAB && sec.Type != elf.SHT_DYNSYM {
			continue
		}
		if i >= len(b.Sections) || (b.Sections[i].Type != elf.SHT_SYMTAB && b.Sections[i].Type != elf.SHT_DYNSYM) {
			t.Errorf("%s: symbol table %q missing after rewrite", name, sec.Name)
			continue
		}
		sa, err := a.ReadSymtab(sec)
		if err != nil {
			t.Fatalf("%s: ReadSymtab(%q): %v", name, sec.Name, err)
		}
		sb, err := b.ReadSymtab(b.Sections[i])
		if err != nil {
			t.Fatalf("%s: ReadSymtab(%q) after rewrite: %v", name, sec.Name, err)
		}
		if len(sa.Entries) != len(sb.Entries) {
			t.Errorf("%s: symbol table %q count %d != %d", name, sec.Name, len(sa.Entries), len(sb.Entries))
		}
		for j := 0; j < len(sa.Entries) && j < len(sb.Entries); j++ {
			if sa.Entries[j] != sb.Entries[j] {
				t.Errorf("%s: symbol table %q entry %d mismatch: %+v != %+v",
					name, sec.Name, j, sa.Entries[j], sb.Entries[j])
			}
		}
	}
	for i, sec := range a.Sections {
		if sec.Type != elf.SHT_REL && sec.Type != elf.SHT_RELA {
			continue
		}
		ra, err := a.ReadRelocs(sec)
		if err != nil {
			t.Fatalf("%s: ReadRelocs(%q): %v", name, sec.Name, err)
		}
		if i >= len(b.Sections) {
			t.Errorf("%s: relocation section %q missing after rewrite", name, sec.Name)
			continue
		}
		rb, err := b.ReadRelocs(b.Sections[i])
		if err != nil {
			t.Fatalf("%s: ReadRelocs(%q) after rewrite: %v", name, sec.Name, err)
		}
		if len(ra) != len(rb) {
			t.Errorf("%s: relocation section %q count %d != %d", name, sec.Name, len(ra), len(rb))
		}
		for j := 0; j < len(ra) && j < len(rb); j++ {
			if ra[j] != rb[j] {
				t.Errorf("%s: relocation section %q entry %d mismatch: %+v != %+v",
					name, sec.Name, j, ra[j], rb[j])
			}
		}
	}
	if diff := elfdump.FirstDiff(elfdump.Dump(a, elfdump.Default), elfdump.Dump(b, elfdump.Default)); diff != "" {
		t.Errorf("%s: semantic dump mismatch:\n%s", name, diff)
	}
}

// ---- readelf model views ------------------------------------------------

type sectionView struct {
	Index int
	Name  string
	Type  string
	Addr  uint64
	Off   uint64
	Size  uint64
	Link  uint64
	Info  uint64
	Align uint64
}

type symbolView struct {
	Index int
	Value uint64
	Size  uint64
	Type  string
	Bind  string
	Vis   string
	Ndx   string
	Name  string
}

var shdrLineRE = regexp.MustCompile(`^\s*\[\s*(\d+)\]\s+(.+?)\s*$`)

var readelfSectionTypes = map[string]bool{
	"NULL": true, "PROGBITS": true, "SYMTAB": true, "STRTAB": true,
	"RELA": true, "HASH": true, "DYNAMIC": true, "NOTE": true,
	"NOBITS": true, "REL": true, "SHLIB": true, "DYNSYM": true,
	"INIT_ARRAY": true, "FINI_ARRAY": true, "PREINIT_ARRAY": true,
	"GROUP": true, "RELR": true, "GNU_ATTRIBUTES": true,
	"GNU_HASH": true, "GNU_LIBLIST": true, "CHECKSUM": true,
	"VERDEF": true, "VERNEED": true, "VERSYM": true,
	"ARM_ATTRIBUTES": true, "IA_64_EXT": true, "IA_64_UNWIND": true,
}

func parseHex(t *testing.T, what, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		t.Fatalf("parsing %s %q as hex: %v", what, s, err)
	}
	return v
}

func parseDec(t *testing.T, what, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("parsing %s %q as decimal: %v", what, s, err)
	}
	return v
}

// readSectionHeaders parses the table printed by "readelf -SW".
func readSectionHeaders(t *testing.T, path string) []sectionView {
	t.Helper()
	out := mustReadelf(t, path, "-SW")
	var views []sectionView
	for _, line := range strings.Split(out, "\n") {
		m := shdrLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		idx, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("%s: parsing section index in %q: %v", path, line, err)
		}
		rest := strings.TrimSpace(m[2])
		var name, typ string
		if strings.HasPrefix(rest, "SYMTAB SECTION INDICES") {
			typ = "SYMTAB SECTION INDICES"
			rest = strings.TrimSpace(strings.TrimPrefix(rest, typ))
		} else {
			fields := strings.Fields(rest)
			if len(fields) < 7 {
				t.Fatalf("%s: cannot parse section header line %q", path, line)
			}
			if readelfSectionTypes[fields[0]] {
				name, typ = "", fields[0]
				fields = fields[1:]
			} else {
				name, typ = fields[0], fields[1]
				fields = fields[2:]
			}
			rest = strings.Join(fields, " ")
		}
		fields := strings.Fields(rest)
		if len(fields) < 4 {
			t.Fatalf("%s: cannot parse section header line %q", path, line)
		}
		// fields holds addr off size [es] [flags] link info align.
		views = append(views, sectionView{
			Index: idx,
			Name:  name,
			Type:  typ,
			Addr:  parseHex(t, "section address", fields[0]),
			Off:   parseHex(t, "section offset", fields[1]),
			Size:  parseHex(t, "section size", fields[2]),
			Link:  parseDec(t, "section link", fields[len(fields)-3]),
			Info:  parseDec(t, "section info", fields[len(fields)-2]),
			Align: parseDec(t, "section alignment", fields[len(fields)-1]),
		})
	}
	return views
}

var (
	readelfSymtabRE = regexp.MustCompile(`^Symbol table '([^']+)' contains (\d+) entries:`)
	readelfSymRE    = regexp.MustCompile(`^\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*?))?\s*$`)
)

// readSymbolTables parses "readelf -sW" into per-table symbol views.
func readSymbolTables(t *testing.T, path string) map[string][]symbolView {
	t.Helper()
	out := mustReadelf(t, path, "-sW")
	tables := map[string][]symbolView{}
	current := ""
	for _, line := range strings.Split(out, "\n") {
		if m := readelfSymtabRE.FindStringSubmatch(line); m != nil {
			current = m[1]
			if _, ok := tables[current]; !ok {
				tables[current] = nil
			}
			continue
		}
		if current == "" {
			continue
		}
		m := readelfSymRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		idx, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("%s: parsing symbol index in %q: %v", path, line, err)
		}
		fields := strings.Fields(m[7])
		ndx, name := "", ""
		if len(fields) > 0 {
			ndx = fields[0]
			name = strings.Join(fields[1:], " ")
		}
		tables[current] = append(tables[current], symbolView{
			Index: idx,
			Value: parseHex(t, "symbol value", m[2]),
			Size:  parseDec(t, "symbol size", m[3]),
			Type:  m[4],
			Bind:  m[5],
			Vis:   m[6],
			Ndx:   ndx,
			Name:  name,
		})
	}
	return tables
}

func stTypeName(t byte) string {
	switch t {
	case elf.STT_NOTYPE:
		return "NOTYPE"
	case elf.STT_OBJECT:
		return "OBJECT"
	case elf.STT_FUNC:
		return "FUNC"
	case elf.STT_SECTION:
		return "SECTION"
	case elf.STT_FILE:
		return "FILE"
	case elf.STT_COMMON:
		return "COMMON"
	case elf.STT_TLS:
		return "TLS"
	case elf.STT_GNU_IFUNC:
		return "IFUNC"
	}
	return fmt.Sprintf("%d", t)
}

func stBindName(b byte) string {
	switch b {
	case elf.STB_LOCAL:
		return "LOCAL"
	case elf.STB_GLOBAL:
		return "GLOBAL"
	case elf.STB_WEAK:
		return "WEAK"
	case elf.STB_GNU_UNIQUE:
		return "GNU_UNIQUE"
	}
	return fmt.Sprintf("%d", b)
}

func stVisName(v byte) string {
	switch v {
	case elf.STV_DEFAULT:
		return "DEFAULT"
	case elf.STV_INTERNAL:
		return "INTERNAL"
	case elf.STV_HIDDEN:
		return "HIDDEN"
	case elf.STV_PROTECTED:
		return "PROTECTED"
	}
	return fmt.Sprintf("%d", v)
}

var sectionTypeNames = map[uint32]string{
	elf.SHT_NULL:           "NULL",
	elf.SHT_PROGBITS:       "PROGBITS",
	elf.SHT_SYMTAB:         "SYMTAB",
	elf.SHT_STRTAB:         "STRTAB",
	elf.SHT_RELA:           "RELA",
	elf.SHT_HASH:           "HASH",
	elf.SHT_DYNAMIC:        "DYNAMIC",
	elf.SHT_NOTE:           "NOTE",
	elf.SHT_NOBITS:         "NOBITS",
	elf.SHT_REL:            "REL",
	elf.SHT_SHLIB:          "SHLIB",
	elf.SHT_DYNSYM:         "DYNSYM",
	elf.SHT_INIT_ARRAY:     "INIT_ARRAY",
	elf.SHT_FINI_ARRAY:     "FINI_ARRAY",
	elf.SHT_PREINIT_ARRAY:  "PREINIT_ARRAY",
	elf.SHT_GROUP:          "GROUP",
	elf.SHT_RELR:           "RELR",
	elf.SHT_GNU_ATTRIBUTES: "GNU_ATTRIBUTES",
	elf.SHT_GNU_HASH:       "GNU_HASH",
	elf.SHT_GNU_LIBLIST:    "GNU_LIBLIST",
	elf.SHT_CHECKSUM:       "CHECKSUM",
	elf.SHT_GNU_verdef:     "VERDEF",
	elf.SHT_GNU_verneed:    "VERNEED",
	elf.SHT_GNU_versym:     "VERSYM",
}

func modelShndxName(f *elf.File, v uint16) string {
	switch v {
	case elf.SHN_UNDEF:
		return "UND"
	case elf.SHN_ABS:
		return "ABS"
	case elf.SHN_COMMON:
		return "COM"
	}
	if int(v) < len(f.Sections) {
		return f.Sections[v].Name
	}
	return fmt.Sprintf("%d", v)
}

func readelfShndxName(ndx string, sections []sectionView) string {
	switch strings.ToUpper(ndx) {
	case "UND", "":
		return "UND"
	case "ABS":
		return "ABS"
	case "COM", "COMMON":
		return "COM"
	}
	n, err := strconv.Atoi(ndx)
	if err != nil {
		return ndx
	}
	if n >= 0 && n < len(sections) {
		return sections[n].Name
	}
	return fmt.Sprintf("%d", n)
}

// cleanSymName removes readelf's version decoration ("@GLIBC_2.34 (2)").
func cleanSymName(s string) string {
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, " ("); i >= 0 && strings.HasSuffix(s, ")") {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// assertReadelfMatchesModel checks that GNU readelf sees exactly the sections
// and symbols in our parsed model, including sh_link/sh_info and st_shndx.
func assertReadelfMatchesModel(t *testing.T, path string, f *elf.File) {
	t.Helper()
	sections := readSectionHeaders(t, path)
	if len(sections) != len(f.Sections) {
		t.Fatalf("%s: readelf sees %d sections, model has %d", path, len(sections), len(f.Sections))
	}
	for i, sec := range f.Sections {
		v := sections[i]
		if v.Index != i {
			t.Fatalf("%s: section order: readelf index %d at position %d", path, v.Index, i)
		}
		if v.Name != sec.Name {
			t.Errorf("%s: section %d name: readelf %q != model %q", path, i, v.Name, sec.Name)
		}
		if want, ok := sectionTypeNames[sec.Type]; ok && v.Type != want {
			t.Errorf("%s: section %q type: readelf %q != model %q", path, sec.Name, v.Type, want)
		}
		if v.Addr != sec.Addr || v.Off != sec.Offset || v.Size != sec.Size || v.Align != sec.Addralign {
			t.Errorf("%s: section %q layout: readelf addr=%#x off=%#x size=%#x align=%#x, model addr=%#x off=%#x size=%#x align=%#x",
				path, sec.Name, v.Addr, v.Off, v.Size, v.Align, sec.Addr, sec.Offset, sec.Size, sec.Addralign)
		}
		if v.Link != uint64(sec.Link) || v.Info != uint64(sec.Info) {
			t.Errorf("%s: section %q sh_link/sh_info: readelf %d/%d != model %d/%d",
				path, sec.Name, v.Link, v.Info, sec.Link, sec.Info)
		}
	}

	all := readSymbolTables(t, path)
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_SYMTAB && sec.Type != elf.SHT_DYNSYM {
			continue
		}
		st, err := f.ReadSymtab(sec)
		if err != nil {
			t.Fatalf("%s: ReadSymtab(%q): %v", path, sec.Name, err)
		}
		views := all[sec.Name]
		if len(views) != len(st.Entries) {
			t.Fatalf("%s: symbol table %q: readelf has %d entries, model has %d",
				path, sec.Name, len(views), len(st.Entries))
		}
		for i, sym := range st.Entries {
			v := views[i]
			if v.Index != i {
				t.Errorf("%s: %s symbol order: readelf index %d at position %d", path, sec.Name, v.Index, i)
			}
			if v.Value != sym.Value || v.Size != sym.Size {
				t.Errorf("%s: %s symbol %d (%q): readelf value=%#x size=%d, model value=%#x size=%d",
					path, sec.Name, i, sym.Name, v.Value, v.Size, sym.Value, sym.Size)
			}
			if v.Type != stTypeName(sym.Type()) || v.Bind != stBindName(sym.Bind()) || v.Vis != stVisName(sym.Visibility()) {
				t.Errorf("%s: %s symbol %d (%q): readelf %s/%s/%s, model %s/%s/%s",
					path, sec.Name, i, sym.Name, v.Bind, v.Type, v.Vis,
					stBindName(sym.Bind()), stTypeName(sym.Type()), stVisName(sym.Visibility()))
			}
			wantNdx := modelShndxName(f, sym.Shndx)
			gotNdx := readelfShndxName(v.Ndx, sections)
			if wantNdx != gotNdx {
				t.Errorf("%s: %s symbol %d (%q): readelf section %q != model %q",
					path, sec.Name, i, sym.Name, gotNdx, wantNdx)
			}
			if sym.Type() == elf.STT_SECTION {
				// readelf synthesises the section name for STT_SECTION entries.
				if name := cleanSymName(v.Name); name != "" && gotNdx != "UND" && name != gotNdx {
					t.Errorf("%s: %s section symbol %d: readelf name %q not section %q",
						path, sec.Name, i, name, gotNdx)
				}
				continue
			}
			if got, want := cleanSymName(v.Name), cleanSymName(sym.Name); got != want {
				t.Errorf("%s: %s symbol %d name: readelf %q != model %q", path, sec.Name, i, got, want)
			}
		}
	}
}

// assertReadelfParses requires readelf -a to succeed for path.
func assertReadelfParses(t *testing.T, path string) {
	t.Helper()
	mustReadelf(t, path, "-aW")
}

// ---- binary header helpers ---------------------------------------------

func orderFor(f *elf.File) binary.ByteOrder { return f.Data.Order() }

func readHeaderU16(order binary.ByteOrder, b []byte, off int) uint16 {
	return order.Uint16(b[off:])
}

// readELFHeaderShoff reads e_shoff for either ELF class.
func readELFHeaderShoff(class elf.Class, order binary.ByteOrder, b []byte) uint64 {
	if class == elf.Class32 {
		return uint64(order.Uint32(b[32:]))
	}
	return order.Uint64(b[40:])
}
func readHeaderU32(order binary.ByteOrder, b []byte, off int) uint32 {
	return order.Uint32(b[off:])
}
func readHeaderU64(order binary.ByteOrder, b []byte, off int) uint64 {
	return order.Uint64(b[off:])
}

// sectionField returns a field of the shdrSize-byte section header at off.
func sectionField(class elf.Class, order binary.ByteOrder, b []byte, off int, kind string) uint64 {
	if class == elf.Class64 {
		base := map[string]int{"name": 0, "type": 4, "flags": 8, "addr": 16, "offset": 24, "size": 32, "link": 40, "info": 44, "addralign": 48, "entsize": 56}
		switch kind {
		case "name", "type", "link", "info":
			return uint64(order.Uint32(b[off+base[kind]:]))
		case "flags":
			return order.Uint64(b[off+base[kind]:])
		default:
			return order.Uint64(b[off+base[kind]:])
		}
	}
	base := map[string]int{"name": 0, "type": 4, "flags": 8, "addr": 12, "offset": 16, "size": 20, "link": 24, "info": 28, "addralign": 32, "entsize": 36}
	return uint64(order.Uint32(b[off+base[kind]:]))
}
