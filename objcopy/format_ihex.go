package objcopy

import (
	"fmt"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/bfdtarget"
)

// ihexChunk is the number of data bytes per Intel Hex record. Unlike srec it
// cannot be changed from the command line (--srec-len only affects srec).
const ihexChunk = 16

func init() {
	outputWriters["ihex"] = writeIHex
	inputReaders["ihex"] = readIHex
}

// writeIHex renders f as an Intel Hex file, following BFD's ihex.c.
func writeIHex(f *elf.File, cfg *Config) ([]byte, error) {
	out := make([]byte, 0, 1024)
	segbase, extbase := uint64(0), uint64(0)
	for _, r := range sortedLoadRegions(f) {
		where := r.lma
		// IHex only supports 32-bit addresses. Some targets use signed
		// 32-bit addresses, so only complain when both the unsigned and
		// signed interpretations overflow.
		if where > 0xffffffff && where+0x80000000 > 0xffffffff {
			return nil, fmt.Errorf("%s: 64-bit address %#x out of range for Intel Hex file",
				formatDisplayName(f, outputName(cfg)), where)
		}
		where &= 0xffffffff

		data := r.data
		for len(data) > 0 {
			now := len(data)
			if now > ihexChunk {
				now = ihexChunk
			}

			if where < extbase || where-extbase < segbase || where-extbase-segbase > 0xffff {
				// A new base address is needed.
				if extbase == 0 && where <= 0xfffff {
					segbase = where & 0xf0000
					addr := []byte{byte(segbase >> 12), byte(segbase >> 4)}
					out = appendIHexRecord(out, 2, 0, 2, addr)
				} else {
					// Some readers combine the extended address and
					// extended linear address records, so zero out a
					// previous segment base first.
					if segbase != 0 {
						out = appendIHexRecord(out, 2, 0, 2, []byte{0, 0})
						segbase = 0
					}
					extbase = where & 0xffff0000
					if where > extbase+0xffff {
						return nil, fmt.Errorf("%s: address %#x out of range for Intel Hex file",
							formatDisplayName(f, outputName(cfg)), where)
					}
					addr := []byte{byte(extbase >> 24), byte(extbase >> 16)}
					out = appendIHexRecord(out, 2, 0, 4, addr)
				}
			}

			recAddr := where - (extbase + segbase)
			// Records must not cross a 64K boundary.
			if recAddr+uint64(now) > 0xffff {
				now = int(0x10000 - recAddr)
			}
			out = appendIHexRecord(out, uint8(now), uint16(recAddr), 0, data[:now])
			where += uint64(now)
			data = data[now:]
		}
	}

	if f.Entry != 0 {
		start := f.Entry
		var data [4]byte
		var typ uint8
		if start <= 0xfffff {
			// Segment:offset form.
			data[0] = byte((start & 0xf0000) >> 12)
			data[1] = 0
			data[2] = byte(start >> 8)
			data[3] = byte(start)
			typ = 3
		} else {
			data[0] = byte(start >> 24)
			data[1] = byte(start >> 16)
			data[2] = byte(start >> 8)
			data[3] = byte(start)
			typ = 5
		}
		out = appendIHexRecord(out, 4, 0, typ, data[:])
	}
	out = appendIHexRecord(out, 0, 0, 1, nil)
	return out, nil
}

// appendIHexRecord appends one ":llaaaatt<data>cc\r\n" record.
func appendIHexRecord(out []byte, count uint8, addr uint16, typ uint8, data []byte) []byte {
	out = append(out, ':')
	out = appendHex(out, count)
	out = appendHex(out, byte(addr>>8))
	out = appendHex(out, byte(addr))
	out = appendHex(out, typ)
	sum := count + byte(addr>>8) + byte(addr) + typ
	for _, b := range data {
		out = appendHex(out, b)
		sum += b
	}
	out = appendHex(out, -sum)
	return append(out, '\r', '\n')
}

// readIHex parses an Intel Hex file into the ELF model used by the rest of the
// pipeline. Data records become ".secN" sections (one per contiguous run) and
// the start address becomes the ELF entry point, mirroring bfd/ihex.c.
func readIHex(data []byte, path string, cfg *Config, t *bfdtarget.Target) (*elf.File, error) {
	var secs []recordSection
	var cur *recordSection
	segbase, extbase := uint64(0), uint64(0)
	var start uint64
	lineno := 1
	i := 0
	for i < len(data) {
		c := data[i]
		switch c {
		case '\r':
			i++
			continue
		case '\n':
			lineno++
			i++
			continue
		case ':':
			// A data record follows.
		default:
			return nil, fmt.Errorf("%s:%d: unexpected character in Intel Hex file", path, lineno)
		}
		i++
		if len(data)-i < 8 {
			return nil, fmt.Errorf("%s:%d: truncated Intel Hex record", path, lineno)
		}
		hdr, err := parseHexBytes(data[i : i+8])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: bad hex digit in Intel Hex file", path, lineno)
		}
		i += 8
		length := hdr[0]
		addr := uint64(hdr[1])<<8 | uint64(hdr[2])
		typ := hdr[3]
		chars := int(length)*2 + 2
		if len(data)-i < chars {
			return nil, fmt.Errorf("%s:%d: truncated Intel Hex record", path, lineno)
		}
		payload, err := parseHexBytes(data[i : i+chars])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: bad hex digit in Intel Hex file", path, lineno)
		}
		i += chars
		recData := payload[:len(payload)-1]
		sum := int(length) + int(hdr[1]) + int(hdr[2]) + int(typ)
		for _, b := range recData {
			sum += int(b)
		}
		if byte(-sum) != payload[len(payload)-1] {
			return nil, fmt.Errorf("%s:%d: bad checksum in Intel Hex file (expected %d, found %d)",
				path, lineno, byte(-sum), payload[len(payload)-1])
		}

		switch typ {
		case 0:
			full := extbase + segbase + addr
			if cur != nil && cur.addr+uint64(len(cur.data)) == full {
				cur.data = append(cur.data, recData...)
			} else if len(recData) > 0 {
				secs = append(secs, recordSection{addr: full, data: append([]byte(nil), recData...)})
				cur = &secs[len(secs)-1]
			}
		case 1:
			if start == 0 {
				start = addr
			}
			return finishRecordELF(path, cfg, t, start, secs), nil
		case 2:
			if length != 2 {
				return nil, fmt.Errorf("%s:%d: bad extended address record length in Intel Hex file", path, lineno)
			}
			segbase = (uint64(recData[0])<<8 | uint64(recData[1])) << 4
			cur = nil
		case 3:
			if length != 4 {
				return nil, fmt.Errorf("%s:%d: bad extended start address length in Intel Hex file", path, lineno)
			}
			start += (uint64(recData[0])<<8|uint64(recData[1]))<<4 +
				(uint64(recData[2])<<8 | uint64(recData[3]))
			cur = nil
		case 4:
			if length != 2 {
				return nil, fmt.Errorf("%s:%d: bad extended linear address record length in Intel Hex file", path, lineno)
			}
			extbase = (uint64(recData[0])<<8 | uint64(recData[1])) << 16
			cur = nil
		case 5:
			if length != 2 && length != 4 {
				return nil, fmt.Errorf("%s:%d: bad extended linear start address record length in Intel Hex file", path, lineno)
			}
			if length == 2 {
				start += (uint64(recData[0])<<8 | uint64(recData[1])) << 16
			} else {
				start = (uint64(recData[0])<<8|uint64(recData[1]))<<16 |
					uint64(recData[2])<<8 | uint64(recData[3])
			}
			cur = nil
		default:
			return nil, fmt.Errorf("%s:%d: unrecognized ihex type %d in Intel Hex file", path, lineno, typ)
		}
	}
	return finishRecordELF(path, cfg, t, start, secs), nil
}

// finishRecordELF builds the ELF model and applies GNU's default of reusing
// the input target when no output target was requested.
func finishRecordELF(path string, cfg *Config, t *bfdtarget.Target, entry uint64, secs []recordSection) *elf.File {
	f := newRecordELF(path, cfg, entry, secs)
	if cfg != nil && cfg.OutputTarget == "" && t != nil {
		cfg.OutputTarget = t.Name
	}
	return f
}
