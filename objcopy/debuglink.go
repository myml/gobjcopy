package objcopy

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"

	"github.com/myml/gobjcopy/elf"
)

// DebugLinkCRC computes the CRC32 used by .gnu_debuglink.
func DebugLinkCRC(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

// DebugLinkSection builds the contents of a .gnu_debuglink section.
func DebugLinkSection(name string, crc uint32) []byte {
	buf := make([]byte, 0, len(name)+8)
	buf = append(buf, name...)
	buf = append(buf, 0)
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], crc)
	return append(buf, c[:]...)
}

func applyDebugLink(f *elf.File, c *Config) error {
	if c.AddDebugLink == "" {
		return nil
	}
	// PR 15125: if the section already exists, warn and leave the old one in
	// place instead of emitting a duplicate (GNU is non-fatal here).
	if f.Section(".gnu_debuglink") != nil {
		c.warnf("debuglink section already exists")
		return nil
	}
	data, err := os.ReadFile(c.AddDebugLink)
	if err != nil {
		return fmt.Errorf("%s: %w", c.AddDebugLink, err)
	}
	name := filepath.Base(c.AddDebugLink)
	content := DebugLinkSection(name, DebugLinkCRC(data))
	sec := &elf.Section{
		SectionHeader: elf.SectionHeader{
			Name:      ".gnu_debuglink",
			Type:      elf.SHT_PROGBITS,
			Addralign: 4,
		},
		Data: content,
	}
	sec.Size = uint64(len(content))
	if err := f.AddSection(sec); err != nil {
		return err
	}
	if c.Verbose {
		c.infof("added .gnu_debuglink for %s (crc %#08x)", name, DebugLinkCRC(data))
	}
	return nil
}
