// Package ar reads and writes GNU ar archives.
//
// The reader understands the formats binutils produces and consumes: GNU
// style members with a trailing '/' in the name field, the "//" extended name
// table with "/<offset>" references, the "/" (32-bit) and "/SYM64/" (64-bit)
// symbol tables, and BSD style "#1/<length>" member names. Thin archives are
// recognized but not supported, matching objcopy itself.
//
// The writer always produces GNU style archives. It rebuilds the extended name
// table and, when asked, the symbol table, because member offsets and symbols
// change whenever members are transformed.
package ar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// Magic starts every GNU ar archive.
	Magic = "!<arch>\n"
	// ThinMagic starts a thin archive.
	ThinMagic = "!<thin>\n"

	headerSize = 60
	nameSize   = 16
	// maxInlineName is the longest member name that fits in the 16-byte name
	// field together with GNU's trailing '/' terminator.
	maxInlineName = 15
)

var (
	// ErrNotArchive reports input that does not start with Magic.
	ErrNotArchive = errors.New("ar: not an archive")
	// ErrThinArchive reports a thin archive, which this package cannot read.
	ErrThinArchive = errors.New("ar: thin archives are not supported")
)

// Member is one archive element. Data is the member content as stored in the
// archive (for BSD style names this is the payload after the name bytes).
type Member struct {
	Name  string
	Data  []byte
	Mtime int64
	UID   int
	GID   int
	Mode  uint32 // octal mode as stored in the header, e.g. 0o644

	// Symbols lists the global symbols the member defines. It is not filled
	// in by Parse: the caller supplies it when it wants Bytes to rebuild the
	// archive symbol table.
	Symbols []string
}

// Archive is a parsed ar archive.
type Archive struct {
	// Members holds the real members in archive order. Symbol tables and the
	// extended name table are not included.
	Members []*Member
	// HasSymbolTable records whether the input carried an archive symbol
	// table. GNU objcopy preserves that property on output.
	HasSymbolTable bool
}

// IsArchive reports whether data starts with the GNU ar magic.
func IsArchive(data []byte) bool {
	return bytes.HasPrefix(data, []byte(Magic))
}

// IsThinArchive reports whether data starts with the thin archive magic.
func IsThinArchive(data []byte) bool {
	return bytes.HasPrefix(data, []byte(ThinMagic))
}

// Parse decodes a GNU or BSD style ar archive.
func Parse(data []byte) (*Archive, error) {
	if !IsArchive(data) {
		if IsThinArchive(data) {
			return nil, ErrThinArchive
		}
		return nil, ErrNotArchive
	}

	a := &Archive{}
	var longNames []byte
	off := len(Magic)
	for off < len(data) {
		if off+headerSize > len(data) {
			// Tolerate trailing padding: some writers round the file up.
			if isPadding(data[off:]) {
				break
			}
			return nil, fmt.Errorf("ar: truncated member header at offset %d", off)
		}
		hdr := data[off : off+headerSize]
		if string(hdr[58:60]) != "`\n" {
			return nil, fmt.Errorf("ar: bad member header magic at offset %d", off)
		}
		size, err := parseDecimal(hdr[48:58])
		if err != nil {
			return nil, fmt.Errorf("ar: bad member size at offset %d: %w", off, err)
		}
		start := off + headerSize
		if size < 0 || start+size > len(data) || start+size < start {
			return nil, fmt.Errorf("ar: member at offset %d is truncated", off)
		}
		body := data[start : start+size]
		rawName := strings.TrimRight(string(hdr[0:nameSize]), " ")

		member := &Member{
			Data:  body,
			Mtime: parseInt(hdr[16:28], 10),
			UID:   int(parseInt(hdr[28:34], 10)),
			GID:   int(parseInt(hdr[34:40], 10)),
			Mode:  uint32(parseInt(hdr[40:48], 8)),
		}

		special := true
		switch {
		case rawName == "/" || rawName == "/SYM64/":
			a.HasSymbolTable = true
		case rawName == "//":
			longNames = body
		case rawName == "__.SYMDEF" || rawName == "__.SYMDEF SORTED":
			a.HasSymbolTable = true
		case strings.HasPrefix(rawName, "#1/"):
			n, err := strconv.Atoi(rawName[len("#1/"):])
			if err != nil || n < 0 || n > len(body) {
				return nil, fmt.Errorf("ar: bad BSD name length %q at offset %d", rawName, off)
			}
			member.Name = strings.TrimRight(string(body[:n]), "\x00")
			member.Data = body[n:]
			special = false
		case len(rawName) > 1 && rawName[0] == '/' && isDigits(rawName[1:]):
			idx, err := strconv.Atoi(rawName[1:])
			if err != nil || idx >= len(longNames) {
				return nil, fmt.Errorf("ar: bad extended name reference %q at offset %d", rawName, off)
			}
			member.Name = longName(longNames[idx:])
			special = false
		default:
			member.Name = strings.TrimSuffix(rawName, "/")
			special = false
		}
		if !special {
			a.Members = append(a.Members, member)
		}

		off = start + size
		if size%2 == 1 {
			// Members are padded to an even offset.
			off++
		}
	}
	return a, nil
}

// longName extracts one name from an extended name table. GNU terminates
// entries with "/\n"; other writers have used a bare newline or NUL.
func longName(b []byte) string {
	if i := bytes.IndexAny(b, "\n\x00"); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSuffix(string(b), "/")
}

// WriteOptions controls archive serialization.
type WriteOptions struct {
	// Deterministic fakes the metadata of every member: mtime, uid and gid
	// become zero and the mode becomes 0644, as GNU's -D does. This is the
	// default objcopy behaviour.
	Deterministic bool
	// SymbolTable writes a GNU archive symbol index built from
	// Member.Symbols. GNU objcopy writes one when the input had one.
	SymbolTable bool
}

// symRef is one symbol index entry: the member that defines it and its name.
type symRef struct {
	member int
	name   string
}

// Bytes serializes the archive in GNU ar format.
func (a *Archive) Bytes(opts WriteOptions) ([]byte, error) {
	longTable, refs := buildLongNameTable(a.Members)

	// Collect the symbols in member order; an archive index groups symbols by
	// the member that defines them.
	var syms []symRef
	var strTab []byte
	if opts.SymbolTable {
		for i, m := range a.Members {
			for _, name := range m.Symbols {
				if name == "" {
					continue
				}
				syms = append(syms, symRef{member: i, name: name})
				strTab = append(strTab, name...)
				strTab = append(strTab, 0)
			}
		}
	}

	offs, armapSize, use64 := a.layout(opts, len(longTable), len(strTab), len(syms))

	var buf bytes.Buffer
	buf.WriteString(Magic)

	if opts.SymbolTable {
		writeArmapHeader(&buf, armapSize, opts.Deterministic)
		var count [8]byte
		if use64 {
			binary.BigEndian.PutUint64(count[:], uint64(len(syms)))
			buf.Write(count[:8])
		} else {
			binary.BigEndian.PutUint32(count[:4], uint32(len(syms)))
			buf.Write(count[:4])
		}
		for _, sym := range syms {
			var off [8]byte
			if use64 {
				binary.BigEndian.PutUint64(off[:], uint64(offs[sym.member]))
				buf.Write(off[:8])
			} else {
				binary.BigEndian.PutUint32(off[:4], uint32(offs[sym.member]))
				buf.Write(off[:4])
			}
		}
		buf.Write(strTab)
		for buf.Len() < armapEnd(armapSize) {
			buf.WriteByte(0)
		}
	}

	if len(longTable) > 0 {
		writeLongNameHeader(&buf, int64(len(longTable)))
		buf.Write(longTable)
	}

	for i, m := range a.Members {
		name := m.Name
		if refs[i] >= 0 {
			name = "/" + strconv.Itoa(refs[i])
		} else {
			name += "/"
		}
		mtime, uid, gid, mode := m.Mtime, m.UID, m.GID, m.Mode
		if opts.Deterministic {
			mtime, uid, gid, mode = 0, 0, 0, 0o644
		}
		writeHeader(&buf, name, mtime, int64(uid), int64(gid), int64(mode), int64(len(m.Data)))
		buf.Write(m.Data)
		if len(m.Data)%2 == 1 {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes(), nil
}

// armapEnd is the archive offset just past the symbol table data.
func armapEnd(armapSize int) int {
	return len(Magic) + headerSize + armapSize
}

// layout computes member header offsets, the symbol table size, and whether a
// 64-bit symbol table is required. It must agree exactly with Bytes.
func (a *Archive) layout(opts WriteOptions, longTableLen, strTabLen, symCount int) ([]int64, int, bool) {
	offs, armapSize := a.layoutWith(opts, longTableLen, strTabLen, symCount, false)
	for _, off := range offs {
		if off > 0xffffffff {
			offs, armapSize = a.layoutWith(opts, longTableLen, strTabLen, symCount, true)
			return offs, armapSize, true
		}
	}
	return offs, armapSize, false
}

func (a *Archive) layoutWith(opts WriteOptions, longTableLen, strTabLen, symCount int, use64 bool) ([]int64, int) {
	pos := int64(len(Magic))
	armapSize := 0
	if opts.SymbolTable {
		armapSize = 4 + 4*symCount + strTabLen
		if use64 {
			armapSize = 8 + 8*symCount + strTabLen
		}
		if armapSize%2 == 1 {
			armapSize++
		}
		if use64 {
			for armapSize%8 != 0 {
				armapSize++
			}
		}
		pos += int64(headerSize + armapSize)
	}
	if longTableLen > 0 {
		pos += int64(headerSize + longTableLen)
	}
	offs := make([]int64, len(a.Members))
	for i, m := range a.Members {
		offs[i] = pos
		pos += int64(headerSize + len(m.Data))
		if len(m.Data)%2 == 1 {
			pos++
		}
	}
	return offs, armapSize
}

// buildLongNameTable returns the "//" table and, for each member, the offset
// of its name in the table or -1 when the name fits inline.
func buildLongNameTable(members []*Member) ([]byte, []int) {
	refs := make([]int, len(members))
	var table []byte
	for i, m := range members {
		if len(m.Name) <= maxInlineName {
			refs[i] = -1
			continue
		}
		refs[i] = len(table)
		table = append(table, m.Name...)
		table = append(table, '/', '\n')
	}
	if len(table)%2 == 1 {
		table = append(table, '\n')
	}
	return table, refs
}

func writeHeader(buf *bytes.Buffer, name string, mtime, uid, gid, mode, size int64) {
	var h [headerSize]byte
	for i := range h {
		h[i] = ' '
	}
	pad(h[0:nameSize], name)
	pad(h[16:28], strconv.FormatInt(mtime, 10))
	pad(h[28:34], strconv.FormatInt(uid, 10))
	pad(h[34:40], strconv.FormatInt(gid, 10))
	pad(h[40:48], strconv.FormatInt(mode, 8))
	pad(h[48:58], strconv.FormatInt(size, 10))
	h[58] = '`'
	h[59] = '\n'
	buf.Write(h[:])
}

func writeArmapHeader(buf *bytes.Buffer, size int, deterministic bool) {
	date := time.Now().Unix()
	if deterministic {
		date = 0
	}
	writeHeader(buf, "/", date, 0, 0, 0, int64(size))
}

// writeLongNameHeader writes the "//" member header. binutils leaves all the
// metadata fields blank for this member.
func writeLongNameHeader(buf *bytes.Buffer, size int64) {
	var h [headerSize]byte
	for i := range h {
		h[i] = ' '
	}
	pad(h[0:nameSize], "//")
	pad(h[48:58], strconv.FormatInt(size, 10))
	h[58] = '`'
	h[59] = '\n'
	buf.Write(h[:])
}

// pad copies s into dst and space-pads the rest, truncating s if necessary.
func pad(dst []byte, s string) {
	n := copy(dst, s)
	for i := n; i < len(dst); i++ {
		dst[i] = ' '
	}
}

func parseDecimal(b []byte) (int, error) {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 0, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q", s)
	}
	return v, nil
}

func parseInt(b []byte, base int) int64 {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, base, 64)
	if err != nil {
		return 0
	}
	return v
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isPadding(b []byte) bool {
	for _, c := range b {
		if c != '\n' && c != 0 && c != ' ' {
			return false
		}
	}
	return true
}
