package objcopy

import (
	"fmt"

	"github.com/myml/gobjcopy/elf"
)

const verilogChunk = 16

func init() {
	outputWriters["verilog"] = writeVerilog
}

// writeVerilog renders f as a Verilog hex memory dump, following BFD's
// verilog.c: an address line "@xxxxxxxx" (the load address divided by the
// data width) followed by records of up to 16 bytes. The byte order of the
// emitted words follows the input file's endianness.
func writeVerilog(f *elf.File, cfg *Config) ([]byte, error) {
	width := defaultVerilogDataWidth
	if cfg != nil && cfg.VerilogDataWidth != 0 {
		width = cfg.VerilogDataWidth
	}
	switch width {
	case 1, 2, 4, 8, 16:
	default:
		return nil, fmt.Errorf("error: verilog data width must be 1, 2, 4, 8 or 16")
	}
	bigEndian := f != nil && f.Data == elf.DataMSB

	out := make([]byte, 0, 1024)
	for _, r := range sortedLoadRegions(f) {
		if r.lma%uint64(width) != 0 {
			return nil, fmt.Errorf("%s: section %s load address %#x is not a multiple of the verilog data width %d",
				formatDisplayName(f, outputName(cfg)), r.sec.Name, r.lma, width)
		}
		out = appendVerilogAddress(out, r.lma/uint64(width))
		for off := 0; off < len(r.data); off += verilogChunk {
			end := off + verilogChunk
			if end > len(r.data) {
				end = len(r.data)
			}
			out = appendVerilogRecord(out, r.data[off:end], width, bigEndian)
		}
	}
	return out, nil
}

// appendVerilogAddress appends "@%08X\r\n" (16 digits for addresses that do
// not fit in 32 bits).
func appendVerilogAddress(out []byte, address uint64) []byte {
	out = append(out, '@')
	if address >= 1<<32 {
		for shift := 56; shift >= 0; shift -= 8 {
			out = appendHex(out, byte(address>>uint(shift)))
		}
	} else {
		for shift := 24; shift >= 0; shift -= 8 {
			out = appendHex(out, byte(address>>uint(shift)))
		}
	}
	return append(out, '\r', '\n')
}

// appendVerilogRecord appends one data line. Width 1 writes single bytes
// separated by spaces. For wider words little-endian input is emitted with
// each word's bytes reversed, while big-endian input is emitted in order;
// a partial trailing word is printed without padding, matching BFD.
func appendVerilogRecord(out []byte, data []byte, width int, bigEndian bool) []byte {
	switch {
	case width == 1:
		for i, b := range data {
			if i > 0 {
				out = append(out, ' ')
			}
			out = appendHex(out, b)
		}
	case bigEndian:
		for i, b := range data {
			out = appendHex(out, b)
			if (i+1)%width == 0 {
				out = append(out, ' ')
			}
		}
	default:
		src := 0
		for ; src < len(data)-width; src += width {
			for i := width - 1; i >= 0; i-- {
				out = appendHex(out, data[src+i])
			}
			out = append(out, ' ')
		}
		for end := len(data); end > src; {
			end--
			out = appendHex(out, data[end])
		}
	}
	return append(out, '\r', '\n')
}
