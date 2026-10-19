package objcopy

import (
	"fmt"
	"sort"
	"sync"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/bfdtarget"
)

// This file holds the pieces shared by the textual output formats (ihex, srec
// and verilog) and by their readers. The formats themselves live in
// format_ihex.go, format_srec.go and format_verilog.go and register through
// the extension points in run.go.

const (
	defaultSrecLen          = 16 // BFD's DEFAULT_CHUNK
	defaultVerilogDataWidth = 1  // BFD's VerilogDataWidth
)

// outputName returns the output file name used by formats that embed one
// (BFD writes it into srec S0 records). Run sets Config.OutputName; tests and
// library callers may override it with SetOutputName.
func outputName(cfg *Config) string {
	outputNameMu.Lock()
	defer outputNameMu.Unlock()
	if outputNameOverride != nil {
		return *outputNameOverride
	}
	if cfg != nil {
		return cfg.OutputName
	}
	return ""
}

var (
	outputNameMu       sync.Mutex
	outputNameOverride *string
)

// SetOutputName overrides the name used in the srec header record. It is meant
// for library callers and tests; a nil argument restores argument-vector
// detection.
func SetOutputName(name *string) {
	outputNameMu.Lock()
	defer outputNameMu.Unlock()
	outputNameOverride = name
}

// formatDisplayName is the file name used in diagnostics.
func formatDisplayName(f *elf.File, outName string) string {
	if outName != "" {
		return outName
	}
	if f != nil && f.Path != "" {
		return f.Path
	}
	return "<unknown>"
}

// loadRegion is one allocated section with contents, at the load address the
// textual writers place it at.
type loadRegion struct {
	sec  *elf.Section
	lma  uint64
	data []byte
}

// loadRegions returns the sections GNU objcopy would emit for a non-ELF
// output: SEC_ALLOC and SEC_HAS_CONTENTS (SEC_LOAD) with a non-zero size.
// The result is in input section order, which is the order BFD visits output
// sections in.
func loadRegions(f *elf.File) []loadRegion {
	if f == nil {
		return nil
	}
	var out []loadRegion
	for _, s := range f.Sections {
		if s == nil || !s.IsAlloc() || s.IsNoBits() {
			continue
		}
		n := len(s.Data)
		if s.Size == 0 || n == 0 {
			continue
		}
		if uint64(n) > s.Size {
			n = int(s.Size)
		}
		out = append(out, loadRegion{sec: s, lma: sectionLMA(f, s), data: s.Data[:n]})
	}
	return out
}

// sortedLoadRegions returns loadRegions sorted by load address, stable for
// equal addresses, matching BFD's sorted record lists.
func sortedLoadRegions(f *elf.File) []loadRegion {
	regions := loadRegions(f)
	sort.SliceStable(regions, func(i, j int) bool { return regions[i].lma < regions[j].lma })
	return regions
}

// appendHex appends the two uppercase hexadecimal digits of b.
func appendHex(buf []byte, b byte) []byte {
	const digs = "0123456789ABCDEF"
	return append(buf, digs[b>>4], digs[b&0xf])
}

// hexValue decodes one hexadecimal digit.
func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// parseHexBytes decodes s as hexadecimal bytes.
func parseHexBytes(s []byte) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd number of hex digits")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		hi, ok1 := hexValue(s[2*i])
		lo, ok2 := hexValue(s[2*i+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("invalid hex digit")
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

// recordSection is one section assembled by a textual input reader.
type recordSection struct {
	addr uint64
	data []byte
}

// newRecordELF builds the ELF model for a textual input format such as ihex or
// srec. GNU objcopy reuses the output target's class, byte order and machine;
// without an explicit output target the architecture selected with -B (or a
// 64-bit little-endian default) is used.
func newRecordELF(path string, cfg *Config, entry uint64, secs []recordSection) *elf.File {
	class, data, machine := elf.Class64, elf.DataLSB, uint16(0)
	outputIsELF := false
	if cfg != nil && cfg.OutputTarget != "" {
		if t, err := bfdtarget.Parse(cfg.OutputTarget); err == nil && t.IsELF {
			class, data = t.Class, t.Data
			outputIsELF = true
			// The machine type is left to applyFormat, which fills it in
			// from the output target. Keeping it unset here also stops the
			// run.go fast path from treating the synthetic model as an
			// unchanged copy of the input file.
		}
	}
	if cfg != nil && !outputIsELF && cfg.BinaryArch != "" {
		if c, m, ok := bfdtarget.ParseArch(cfg.BinaryArch); ok {
			machine = m
			if class == 0 {
				class = c
			}
		}
	}
	f := &elf.File{
		Header: elf.Header{
			Class:   class,
			Data:    data,
			Type:    elf.ET_REL,
			Machine: machine,
			Version: elf.EV_CURRENT,
			Entry:   entry,
		},
		SectionHeadersPresent: true,
		Path:                  path,
	}

	null := &elf.Section{}
	f.Sections = append(f.Sections, null)
	for i := range secs {
		addr := secs[i].addr
		f.Sections = append(f.Sections, &elf.Section{
			SectionHeader: elf.SectionHeader{
				Name:      fmt.Sprintf(".sec%d", i+1),
				Type:      elf.SHT_PROGBITS,
				Flags:     elf.SHF_ALLOC | elf.SHF_WRITE,
				Addr:      addr,
				Size:      uint64(len(secs[i].data)),
				Addralign: 1,
			},
			Data: secs[i].data,
			LMA:  &addr,
		})
	}
	shstr := &elf.Section{SectionHeader: elf.SectionHeader{
		Name:      ".shstrtab",
		Type:      elf.SHT_STRTAB,
		Addralign: 1,
	}}
	f.Sections = append(f.Sections, shstr)
	f.Shstrndx = len(f.Sections) - 1
	return f
}
