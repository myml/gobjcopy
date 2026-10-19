package objcopy

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/myml/gobjcopy/elf"
)

// ELFCOMPRESS_ZLIB is the only compression type binutils writes today.
const elfCompressZlib = 1

func compressZlib(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompressZlib(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func applyCompression(f *elf.File, c *Config) error {
	if c.DecompressDebug {
		return decompressDebugSections(f)
	}
	switch c.CompressDebug {
	case "", "none":
		return nil
	case "zlib", "zlib-gabi":
		return compressDebugGABI(f)
	case "zlib-gnu":
		return compressDebugGNU(f)
	default:
		return fmt.Errorf("unknown compression type %q", c.CompressDebug)
	}
}

func decompressDebugSections(f *elf.File) error {
	order := f.Data.Order()
	renames := map[string]string{}
	for _, s := range f.Sections {
		if s.IsNoBits() || len(s.Data) == 0 {
			continue
		}
		if s.Flags&elf.SHF_COMPRESSED != 0 {
			hdrSize := 12
			if f.Class == elf.Class64 {
				hdrSize = 24
			}
			if len(s.Data) < hdrSize {
				return fmt.Errorf("%s: truncated compression header", s.Name)
			}
			if order.Uint32(s.Data[0:]) != elfCompressZlib {
				return fmt.Errorf("%s: unsupported compression type", s.Name)
			}
			var size, align uint64
			if f.Class == elf.Class64 {
				size = order.Uint64(s.Data[8:])
				align = order.Uint64(s.Data[16:])
			} else {
				size = uint64(order.Uint32(s.Data[4:]))
				align = uint64(order.Uint32(s.Data[8:]))
			}
			raw, err := decompressZlib(s.Data[hdrSize:])
			if err != nil {
				return fmt.Errorf("%s: %w", s.Name, err)
			}
			if uint64(len(raw)) != size {
				return fmt.Errorf("%s: decompressed size mismatch", s.Name)
			}
			s.Data = raw
			s.Size = uint64(len(raw))
			s.Flags &^= elf.SHF_COMPRESSED
			if align != 0 {
				s.Addralign = align
			}
			continue
		}
		if strings.HasPrefix(s.Name, ".zdebug") && len(s.Data) >= 12 && string(s.Data[:4]) == "ZLIB" {
			raw, err := decompressZlib(s.Data[12:])
			if err != nil {
				return fmt.Errorf("%s: %w", s.Name, err)
			}
			s.Data = raw
			s.Size = uint64(len(raw))
			old := s.Name
			s.Name = ".debug" + strings.TrimPrefix(s.Name, ".zdebug")
			renames[old] = s.Name
		}
	}
	renamedTo := make(map[string]bool, len(renames))
	for _, newName := range renames {
		renamedTo[newName] = true
	}
	for _, r := range f.Sections {
		if r.Type != elf.SHT_REL && r.Type != elf.SHT_RELA || int(r.Info) >= len(f.Sections) {
			continue
		}
		target := f.Sections[r.Info]
		if !renamedTo[target.Name] {
			continue
		}
		switch {
		case strings.HasPrefix(r.Name, ".rela"):
			r.Name = ".rela" + target.Name
		case strings.HasPrefix(r.Name, ".rel"):
			r.Name = ".rel" + target.Name
		}
	}
	return nil
}

// debugCompression is the decoded on-disk compression state of a debug
// section: either the raw bytes (compressed == false) or a compressed payload
// together with its uncompressed size.
type debugCompression struct {
	payload    []byte
	size       uint64 // uncompressed size
	align      uint64 // ch_addralign, or the raw section's alignment
	compressed bool
}

func decodeDebugCompression(f *elf.File, s *elf.Section) (debugCompression, error) {
	order := f.Data.Order()
	var c debugCompression
	if s.Flags&elf.SHF_COMPRESSED != 0 {
		hdr := 12
		if f.Class == elf.Class64 {
			hdr = 24
		}
		if len(s.Data) < hdr {
			return c, fmt.Errorf("%s: truncated compression header", s.Name)
		}
		if order.Uint32(s.Data[0:]) != elfCompressZlib {
			return c, fmt.Errorf("%s: unsupported compression type", s.Name)
		}
		if f.Class == elf.Class64 {
			c.size = order.Uint64(s.Data[8:])
			c.align = order.Uint64(s.Data[16:])
		} else {
			c.size = uint64(order.Uint32(s.Data[4:]))
			c.align = uint64(order.Uint32(s.Data[8:]))
		}
		c.payload = append([]byte(nil), s.Data[hdr:]...)
		c.compressed = true
		return c, nil
	}
	if strings.HasPrefix(s.Name, ".zdebug") && len(s.Data) >= 12 && string(s.Data[:4]) == "ZLIB" {
		c.size = binary.BigEndian.Uint64(s.Data[4:])
		c.align = 1
		c.payload = append([]byte(nil), s.Data[12:]...)
		c.compressed = true
		return c, nil
	}
	c.payload = s.Data
	c.size = uint64(len(s.Data))
	c.align = s.Addralign
	return c, nil
}

// debugHeader builds the compression header for the requested format.
func debugHeader(order binary.ByteOrder, class elf.Class, gnu bool, size, align uint64) []byte {
	if gnu {
		hdr := make([]byte, 12)
		copy(hdr, "ZLIB")
		binary.BigEndian.PutUint64(hdr[4:], size)
		return hdr
	}
	if class == elf.Class64 {
		hdr := make([]byte, 24)
		order.PutUint32(hdr[0:], elfCompressZlib)
		order.PutUint64(hdr[8:], size)
		order.PutUint64(hdr[16:], align)
		return hdr
	}
	hdr := make([]byte, 12)
	order.PutUint32(hdr[0:], elfCompressZlib)
	order.PutUint32(hdr[4:], uint32(size))
	order.PutUint32(hdr[8:], uint32(align))
	return hdr
}

// renameDebug maps a debug section name to the requested compression variant.
// ok is false when the name carries no matching prefix, so callers can use it
// to decide whether the section participates at all.
func renameDebug(name string, gnu bool) (string, bool) {
	if gnu {
		if strings.HasPrefix(name, ".debug") {
			return ".zdebug" + strings.TrimPrefix(name, ".debug"), true
		}
		if strings.HasPrefix(name, ".zdebug") {
			return name, true
		}
		return name, false
	}
	if strings.HasPrefix(name, ".zdebug") {
		return ".debug" + strings.TrimPrefix(name, ".zdebug"), true
	}
	return name, true
}

// debugRaw returns the uncompressed contents of a debug section and whether
// it was compressed (either SHF_COMPRESSED or the .zdebug_* convention).
func debugRaw(f *elf.File, s *elf.Section) ([]byte, bool, error) {
	order := f.Data.Order()
	if s.Flags&elf.SHF_COMPRESSED != 0 {
		hdrSize := 12
		if f.Class == elf.Class64 {
			hdrSize = 24
		}
		if len(s.Data) < hdrSize {
			return nil, false, fmt.Errorf("%s: truncated compression header", s.Name)
		}
		if order.Uint32(s.Data[0:]) != elfCompressZlib {
			return nil, false, fmt.Errorf("%s: unsupported compression type", s.Name)
		}
		raw, err := decompressZlib(s.Data[hdrSize:])
		return raw, true, err
	}
	if strings.HasPrefix(s.Name, ".zdebug") && len(s.Data) >= 12 && string(s.Data[:4]) == "ZLIB" {
		raw, err := decompressZlib(s.Data[12:])
		return raw, true, err
	}
	return s.Data, false, nil
}

func compressDebugGABI(f *elf.File) error {
	order := f.Data.Order()
	align := uint64(4)
	if f.Class == elf.Class64 {
		align = 8
	}
	renamed := map[string]string{}
	for _, s := range f.Sections {
		if !isDebugSection(s) || s.IsNoBits() || len(s.Data) == 0 {
			continue
		}
		if s.Flags&elf.SHF_COMPRESSED != 0 {
			// Already in the requested (gabi) form.
			continue
		}
		dec, err := decodeDebugCompression(f, s)
		if err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		raw := dec.payload
		if dec.compressed {
			// Converting from .zdebug_*: keep the zlib stream and only
			// replace the header, exactly like BFD.
			raw, err = decompressZlib(dec.payload)
			if err != nil {
				return fmt.Errorf("%s: %w", s.Name, err)
			}
		}
		payload := dec.payload
		if !dec.compressed {
			payload, err = compressZlib(raw)
			if err != nil {
				return err
			}
		}
		hdr := debugHeader(order, f.Class, false, dec.size, s.Addralign)
		if uint64(len(hdr)+len(payload)) >= dec.size {
			// BFD keeps the uncompressed form when compression would not
			// make a gabi section smaller.  A section that arrived in the
			// GNU .zdebug_* form must still be renamed back, since the
			// output uses the SHF_COMPRESSED convention.
			if strings.HasPrefix(s.Name, ".zdebug") {
				s.Data = raw
				s.Size = uint64(len(raw))
				s.Flags &^= elf.SHF_COMPRESSED
				old := s.Name
				s.Name = ".debug" + strings.TrimPrefix(s.Name, ".zdebug")
				renamed[old] = s.Name
			}
			continue
		}
		s.Data = append(hdr, payload...)
		s.Size = uint64(len(s.Data))
		s.Flags = s.Flags&^elf.SHF_COMPRESSED | elf.SHF_COMPRESSED
		s.Addralign = align
		if strings.HasPrefix(s.Name, ".zdebug") {
			old := s.Name
			s.Name = ".debug" + strings.TrimPrefix(s.Name, ".zdebug")
			renamed[old] = s.Name
		}
	}
	renameRelocsTo(f, renamed)
	return nil
}

func compressDebugGNU(f *elf.File) error {
	order := f.Data.Order()
	renamed := map[string]string{}
	for _, s := range f.Sections {
		if !isDebugSection(s) || s.IsNoBits() || len(s.Data) == 0 {
			continue
		}
		if strings.HasPrefix(s.Name, ".zdebug") {
			// Already in gnu form.
			continue
		}
		dec, err := decodeDebugCompression(f, s)
		if err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		// Converting from zlib-gabi reuses the existing zlib stream and only
		// replaces the header.  Unlike the gabi writer, the GNU
		// .zdebug_* encoding always renames the section, even when the
		// result is slightly larger; binutils' compress.exp depends on this
		// for the .debug_line sections of its dw2 fixtures.
		payload := dec.payload
		if !dec.compressed {
			payload, err = compressZlib(dec.payload)
			if err != nil {
				return err
			}
		}
		hdr := debugHeader(order, f.Class, true, dec.size, s.Addralign)
		s.Data = append(hdr, payload...)
		s.Size = uint64(len(s.Data))
		s.Flags &^= elf.SHF_COMPRESSED
		old := s.Name
		s.Name = ".zdebug" + strings.TrimPrefix(s.Name, ".debug")
		renamed[old] = s.Name
	}
	renameRelocsTo(f, renamed)
	return nil
}

// renameRelocsTo renames relocation sections whose target was renamed.
func renameRelocsTo(f *elf.File, renamed map[string]string) {
	if len(renamed) == 0 {
		return
	}
	renamedTo := make(map[string]bool, len(renamed))
	for _, newName := range renamed {
		renamedTo[newName] = true
	}
	for _, r := range f.Sections {
		if (r.Type != elf.SHT_REL && r.Type != elf.SHT_RELA) || int(r.Info) >= len(f.Sections) {
			continue
		}
		target := f.Sections[r.Info]
		if !renamedTo[target.Name] {
			continue
		}
		switch {
		case strings.HasPrefix(r.Name, ".rela"):
			r.Name = ".rela" + target.Name
		case strings.HasPrefix(r.Name, ".rel"):
			r.Name = ".rel" + target.Name
		}
	}
}

// sectionHasRelocs reports whether any relocation section applies to the
// section at index idx.
func sectionHasRelocs(f *elf.File, idx int) bool {
	for _, r := range f.Sections {
		if (r.Type == elf.SHT_REL || r.Type == elf.SHT_RELA) && int(r.Info) == idx {
			return true
		}
	}
	return false
}
