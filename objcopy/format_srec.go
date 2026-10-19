package objcopy

import (
	"fmt"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/bfdtarget"
)

const srecMaxChunk = 0xff

func init() {
	outputWriters["srec"] = writeSREC
	inputReaders["srec"] = readSREC
}

// writeSREC renders f as Motorola S-records, following BFD's srec.c.
func writeSREC(f *elf.File, cfg *Config) ([]byte, error) {
	regions := loadRegions(f)

	// BFD chooses the record type while copying sections, in output section
	// order, and never lowers it afterwards.
	typ := 1
	if cfg != nil && cfg.SrecForceS3 {
		typ = 3
	} else {
		for _, r := range regions {
			if len(r.data) == 0 {
				continue
			}
			end := r.lma + uint64(len(r.data)) - 1
			if end <= 0xffff {
				continue
			}
			if end <= 0xffffff && typ <= 2 {
				typ = 2
			} else {
				typ = 3
			}
		}
	}

	out := make([]byte, 0, 1024)
	name := outputName(cfg)
	if len(name) > 40 {
		name = name[:40]
	}
	out = appendSRECRecord(out, 0, 0, []byte(name))

	maxLen := srecMaxChunk - typ - 2
	srecLen := defaultSrecLen
	if cfg != nil && cfg.SrecLen != 0 {
		srecLen = cfg.SrecLen
	}
	if srecLen > maxLen {
		srecLen = maxLen
	}

	for _, r := range sortedLoadRegions(f) {
		for off := 0; off < len(r.data); off += srecLen {
			end := off + srecLen
			if end > len(r.data) {
				end = len(r.data)
			}
			out = appendSRECRecord(out, typ, r.lma+uint64(off), r.data[off:end])
		}
	}

	out = appendSRECRecord(out, 10-typ, f.Entry, nil)
	return out, nil
}

// appendSRECRecord appends S<type><len><address><data><checksum>\r\n.
func appendSRECRecord(out []byte, typ int, address uint64, data []byte) []byte {
	out = append(out, 'S', byte('0'+typ))
	addrLen := 2
	switch typ {
	case 2, 8:
		addrLen = 3
	case 3, 7:
		addrLen = 4
	}
	length := addrLen + len(data) + 1
	out = appendHex(out, byte(length))
	sum := byte(length)
	for shift := (addrLen - 1) * 8; shift >= 0; shift -= 8 {
		b := byte(address >> uint(shift))
		out = appendHex(out, b)
		sum += b
	}
	for _, b := range data {
		out = appendHex(out, b)
		sum += b
	}
	out = appendHex(out, 255-sum)
	return append(out, '\r', '\n')
}

// readSREC parses a Motorola S-record file into the ELF model used by the rest
// of the pipeline. Data records become ".secN" sections and the termination
// record supplies the entry point, mirroring bfd/srec.c.
func readSREC(data []byte, path string, cfg *Config, t *bfdtarget.Target) (*elf.File, error) {
	var secs []recordSection
	var cur *recordSection
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
		case 'S':
			// A record follows.
		default:
			return nil, fmt.Errorf("%s:%d: unexpected character in S-record file", path, lineno)
		}
		i++
		if len(data)-i < 3 {
			return nil, fmt.Errorf("%s:%d: truncated S-record", path, lineno)
		}
		typ := data[i]
		count, ok1 := hexValue(data[i+1])
		count2, ok2 := hexValue(data[i+2])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("%s:%d: bad hex digit in S-record file", path, lineno)
		}
		bytes := int(count)<<4 | int(count2)
		i += 3

		minBytes := 3
		switch typ {
		case '0', '1', '5', '9':
			minBytes = 3
		case '2', '8':
			minBytes = 4
		case '3', '7':
			minBytes = 5
		}
		if bytes < minBytes {
			return nil, fmt.Errorf("%s:%d: byte count %d too small", path, lineno, bytes)
		}
		if len(data)-i < bytes*2 {
			return nil, fmt.Errorf("%s:%d: truncated S-record", path, lineno)
		}
		payload, err := parseHexBytes(data[i : i+bytes*2])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: bad hex digit in S-record file", path, lineno)
		}
		i += bytes * 2

		// The last payload byte is the checksum.
		body := payload[:len(payload)-1]
		checksum := payload[len(payload)-1]
		validChecksum := func() bool {
			sum := byte(bytes)
			for _, b := range body {
				sum += b
			}
			return 255-sum == checksum
		}

		switch typ {
		case '0', '5':
			// Prologue: the file name is ignored (its checksum is not
			// verified), but it ends the current section.
			cur = nil
		case '1', '2', '3':
			if !validChecksum() {
				return nil, fmt.Errorf("%s:%d: bad checksum in S-record file", path, lineno)
			}
			addrLen := 2
			if typ == '2' {
				addrLen = 3
			} else if typ == '3' {
				addrLen = 4
			}
			var address uint64
			for _, b := range body[:addrLen] {
				address = address<<8 | uint64(b)
			}
			recData := body[addrLen:]
			if cur != nil && cur.addr+uint64(len(cur.data)) == address {
				cur.data = append(cur.data, recData...)
			} else {
				secs = append(secs, recordSection{addr: address, data: append([]byte(nil), recData...)})
				cur = &secs[len(secs)-1]
			}
		case '7', '8', '9':
			if !validChecksum() {
				return nil, fmt.Errorf("%s:%d: bad checksum in S-record file", path, lineno)
			}
			addrLen := 2
			if typ == '8' {
				addrLen = 3
			} else if typ == '7' {
				addrLen = 4
			}
			var address uint64
			for _, b := range body[:addrLen] {
				address = address<<8 | uint64(b)
			}
			start = address
			return finishRecordELF(path, cfg, t, start, secs), nil
		default:
			// Unknown record types are ignored, as in BFD.
		}
	}
	return finishRecordELF(path, cfg, t, start, secs), nil
}
