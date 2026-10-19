package elf_test

import (
	"math"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

// TestELF32Bounds checks that a 32-bit rewrite stays within uint32 limits for
// the ELF header, section headers and program headers.
func TestELF32Bounds(t *testing.T) {
	t.Parallel()
	requireTool(t, "readelf")
	name := "reloc32.o"
	f := openFixture(t, name)
	if f.Class != elf.Class32 {
		t.Fatalf("%s: class %d, want ELF32", name, f.Class)
	}
	out := mustBytes(t, f)
	if uint64(len(out)) > math.MaxUint32 {
		t.Fatalf("%s: output is %d bytes, larger than uint32", name, len(out))
	}
	order := f.Data.Order()
	shoff := uint64(readHeaderU32(order, out, 32))
	phoff := uint64(readHeaderU32(order, out, 28))
	if shoff > math.MaxUint32 || phoff > math.MaxUint32 {
		t.Fatalf("%s: e_shoff=%#x e_phoff=%#x exceed uint32", name, shoff, phoff)
	}
	shnum := int(readHeaderU16(order, out, 48))
	shentsize := int(readHeaderU16(order, out, 46))
	if shentsize != 40 {
		t.Fatalf("%s: e_shentsize %d, want 40", name, shentsize)
	}
	if shnum != len(f.Sections) {
		t.Fatalf("%s: e_shnum %d, want %d", name, shnum, len(f.Sections))
	}
	if shoff+uint64(shnum)*40 > uint64(len(out)) {
		t.Fatalf("%s: section header table [%#x,%#x) outside %d-byte file",
			name, shoff, shoff+uint64(shnum)*40, len(out))
	}
	dst := writeBytes(t, out, 0o644, name)
	assertReadelfParses(t, dst)
	g, err := elf.Open(dst)
	if err != nil {
		t.Fatalf("%s: reparse: %v", name, err)
	}
	for i := 0; i < shnum; i++ {
		off := int(shoff) + i*40
		secOff := uint64(order.Uint32(out[off+16:]))
		secSize := uint64(order.Uint32(out[off+20:]))
		secAddr := uint64(order.Uint32(out[off+12:]))
		align := uint64(order.Uint32(out[off+32:]))
		if secOff > math.MaxUint32 || secSize > math.MaxUint32 || secAddr > math.MaxUint32 || align > math.MaxUint32 {
			t.Errorf("%s: section %d fields exceed uint32", name, i)
		}
		if secOff+secSize > uint64(len(out)) {
			t.Errorf("%s: section %d range [%#x,%#x) outside %d-byte file",
				name, i, secOff, secOff+secSize, len(out))
		}
		sec := g.Sections[i]
		if sec.Offset != secOff || sec.Size != secSize || sec.Addr != secAddr || sec.Addralign != align {
			t.Errorf("%s: section %d header mismatch: raw off=%#x size=%#x addr=%#x align=%#x, model off=%#x size=%#x addr=%#x align=%#x",
				name, i, secOff, secSize, secAddr, align, sec.Offset, sec.Size, sec.Addr, sec.Addralign)
		}
	}
	phnum := int(readHeaderU16(order, out, 44))
	if phnum > 0 {
		phentsize := int(readHeaderU16(order, out, 42))
		if phentsize != 32 {
			t.Fatalf("%s: e_phentsize %d, want 32", name, phentsize)
		}
		if phoff+uint64(phnum)*32 > uint64(len(out)) {
			t.Fatalf("%s: program header table outside file", name)
		}
		for i := 0; i < phnum; i++ {
			off := int(phoff) + i*32
			pOff := uint64(order.Uint32(out[off+4:]))
			pFilesz := uint64(order.Uint32(out[off+16:]))
			pVaddr := uint64(order.Uint32(out[off+8:]))
			pMemsz := uint64(order.Uint32(out[off+20:]))
			if pOff+pFilesz > uint64(len(out)) {
				t.Errorf("%s: segment %d range [%#x,%#x) outside %d-byte file",
					name, i, pOff, pOff+pFilesz, len(out))
			}
			seg := g.Segments[i]
			if seg.Offset != pOff || seg.Filesz != pFilesz || seg.Vaddr != pVaddr || seg.Memsz != pMemsz {
				t.Errorf("%s: segment %d raw header disagrees with model", name, i)
			}
		}
	}
	assertSemanticEqual(t, name, f, g)

	// Every fixture built as ELF32 (currently only reloc32.o) must satisfy the
	// same bounds.
	for _, fx := range fixtureNames(t) {
		p := fixtureMap[fx]
		h, err := elf.Open(p)
		if err != nil || h.Class != elf.Class32 {
			continue
		}
		b, err := h.Bytes()
		if err != nil {
			t.Errorf("%s: Bytes: %v", fx, err)
			continue
		}
		if len(b) > math.MaxUint32 {
			t.Errorf("%s: ELF32 output is %d bytes", fx, len(b))
		}
		o := h.Data.Order()
		if uint64(o.Uint32(b[32:]))+uint64(o.Uint16(b[48:]))*uint64(o.Uint16(b[46:])) > uint64(len(b)) {
			t.Errorf("%s: ELF32 section headers outside file", fx)
		}
	}
}
