package ar

import (
	"bytes"
	"strconv"
	"testing"
)

// covRawHeader builds a valid 60-byte member header. It is deliberately
// separate from writeHeader so that tests can produce malformed headers.
func covRawHeader(name string, size int) []byte {
	h := make([]byte, headerSize)
	for i := range h {
		h[i] = ' '
	}
	covField(h[0:16], name)
	covField(h[16:28], "0")
	covField(h[28:34], "0")
	covField(h[34:40], "0")
	covField(h[40:48], "644")
	covField(h[48:58], strconv.Itoa(size))
	h[58], h[59] = '`', '\n'
	return h
}

func covField(dst []byte, s string) {
	copy(dst, s)
	for i := len(s); i < len(dst); i++ {
		dst[i] = ' '
	}
}

// covArchive concatenates headers and bodies into a syntactically valid
// archive without going through the writer, so tests can inject odd sizes.
func covArchive(parts ...[]byte) []byte {
	data := []byte(Magic)
	for _, p := range parts {
		data = append(data, p...)
	}
	return data
}

func covMember(name string, body []byte) []byte {
	part := append(covRawHeader(name, len(body)), body...)
	if len(body)%2 == 1 {
		part = append(part, '\n')
	}
	return part
}

func TestCoverParseOddPaddingAndTrailingWhitespace(t *testing.T) {
	// An odd-sized member must skip its padding byte, and a short tail of
	// whitespace is accepted as trailing padding rather than an error.
	data := covArchive(
		covMember("odd/", []byte("abc")),
		covMember("even/", []byte("xy")),
		[]byte(" \n\n"),
	)
	a, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(a.Members) != 2 {
		t.Fatalf("members = %d, want 2", len(a.Members))
	}
	if a.Members[0].Name != "odd" || string(a.Members[0].Data) != "abc" {
		t.Errorf("first member = %q %q", a.Members[0].Name, a.Members[0].Data)
	}
	if a.Members[1].Name != "even" || string(a.Members[1].Data) != "xy" {
		t.Errorf("second member = %q %q", a.Members[1].Name, a.Members[1].Data)
	}
}

func TestCoverParseBlankSizeAndBadMetadata(t *testing.T) {
	// A blank size field means zero bytes, and unparsable metadata fields are
	// tolerated as zero rather than rejected.
	h := covRawHeader("zero/", 0)
	covField(h[48:58], "")
	covField(h[16:28], "notanumber")
	covField(h[40:48], "notoctal")
	a, err := Parse(covArchive(h))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(a.Members) != 1 {
		t.Fatalf("members = %d, want 1", len(a.Members))
	}
	m := a.Members[0]
	if m.Name != "zero" || len(m.Data) != 0 {
		t.Errorf("member = %q len %d", m.Name, len(m.Data))
	}
	if m.Mtime != 0 || m.Mode != 0 {
		t.Errorf("metadata = mtime %d mode %d, want zero", m.Mtime, m.Mode)
	}
}

func TestCoverParseBadSizeField(t *testing.T) {
	h := covRawHeader("bad/", 0)
	covField(h[48:58], "xyz")
	if _, err := Parse(covArchive(h)); err == nil {
		t.Fatal("Parse succeeded with a non-numeric size field")
	}
}

func TestCoverParseBSDNameErrors(t *testing.T) {
	badLength := covRawHeader("#1/x", 0)
	if _, err := Parse(covArchive(badLength)); err == nil {
		t.Fatal("Parse succeeded with a bad BSD name length")
	}
	tooLong := covRawHeader("#1/9", 2)
	if _, err := Parse(covArchive(tooLong, []byte("ab"))); err == nil {
		t.Fatal("Parse succeeded with an overlong BSD name")
	}
}

func TestCoverParseSymdefMembers(t *testing.T) {
	// BSD symbol-table members are recognized (and dropped) by name.
	for _, name := range []string{"__.SYMDEF", "__.SYMDEF SORTED"} {
		data := covArchive(covMember(name, []byte("junk")))
		a, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: Parse: %v", name, err)
		}
		if !a.HasSymbolTable {
			t.Errorf("%s: HasSymbolTable = false", name)
		}
		if len(a.Members) != 0 {
			t.Errorf("%s: members = %d, want 0", name, len(a.Members))
		}
	}
}

func TestCoverParseNonDigitLongReference(t *testing.T) {
	// "/x" is not a long-name reference; it is an ordinary member name.
	a, err := Parse(covArchive(covMember("/x", []byte("data"))))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(a.Members) != 1 || a.Members[0].Name != "/x" {
		t.Fatalf("members = %+v", a.Members)
	}
	if isDigits("") || isDigits("1a") || !isDigits("123") {
		t.Error("isDigits is wrong")
	}
	if isPadding([]byte("x")) || !isPadding([]byte(" \n\x00")) {
		t.Error("isPadding is wrong")
	}
}

func TestCoverBytesOddDataAndEmptySymbols(t *testing.T) {
	a := &Archive{Members: []*Member{
		// Odd-sized data exercises the newline padding in Bytes/layoutWith.
		{Name: "odd", Data: []byte("abc")},
		// Long name forces the extended name table; the empty symbol name is
		// skipped; "ab" makes the string table odd so the armap is padded.
		{Name: "averyverylongmembername.o", Data: []byte("x"), Symbols: []string{"", "ab"}},
	}}
	blob, err := a.Bytes(WriteOptions{Deterministic: true, SymbolTable: true})
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	out, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(out.Members) != 2 {
		t.Fatalf("members = %d, want 2", len(out.Members))
	}
	if out.Members[0].Name != "odd" || string(out.Members[0].Data) != "abc" {
		t.Errorf("first member = %q %q", out.Members[0].Name, out.Members[0].Data)
	}
	if out.Members[1].Name != "averyverylongmembername.o" {
		t.Errorf("long name = %q", out.Members[1].Name)
	}
	// The symbol table member is the first one and its declared size must
	// include the alignment byte.
	if !out.HasSymbolTable {
		t.Error("HasSymbolTable = false")
	}
}

func TestCoverLayoutNeeds64BitOffsets(t *testing.T) {
	// A long-name table larger than 4GiB pushes the first member offset past
	// the 32-bit limit, which selects the /SYM64/ index layout. Only the
	// layout arithmetic runs here; no such table is allocated.
	a := &Archive{Members: []*Member{{Name: "m", Data: []byte("x")}}}
	offs, armapSize, use64 := a.layout(WriteOptions{SymbolTable: true}, 1<<32, 5, 1)
	if !use64 {
		t.Fatal("layout did not select the 64-bit symbol table")
	}
	if offs[0] <= 0xffffffff {
		t.Fatalf("first member offset = %d, want > 4GiB", offs[0])
	}
	// 8-byte count + 8-byte offset + 5-byte string table, padded to 8.
	if armapSize != 24 {
		t.Fatalf("armapSize = %d, want 24", armapSize)
	}
	// The 32-bit layout must be used when everything fits.
	_, _, small := (&Archive{Members: []*Member{{Name: "m"}}}).layout(WriteOptions{SymbolTable: true}, 0, 5, 1)
	if small {
		t.Fatal("layout selected the 64-bit symbol table for a small archive")
	}
}

func TestCoverBytesEmptyNameSymbolTable(t *testing.T) {
	a := &Archive{Members: []*Member{{Name: "m", Data: []byte("d")}}}
	// No symbols at all still writes a valid, four-byte empty index.
	blob, err := a.Bytes(WriteOptions{Deterministic: false, SymbolTable: true})
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !bytes.Contains(blob, []byte("!<arch>\n/")) {
		t.Fatalf("archive does not start with an index: %q", blob[:16])
	}
	out, err := Parse(blob)
	if err != nil || !out.HasSymbolTable || len(out.Members) != 1 {
		t.Fatalf("reparse = %+v, %v", out, err)
	}
}
