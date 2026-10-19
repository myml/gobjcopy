package objcopy

import (
	"testing"

	"github.com/myml/gobjcopy/elf"
)

// TestSectionAlignForVMA pins down BFD's sh_addralign rule: the value is the
// lowest set bit of (new VMA | original alignment), i.e. the largest power of
// two dividing the VMA that does not exceed the original alignment.
func TestSectionAlignForVMA(t *testing.T) {
	tests := []struct {
		name  string
		align uint64
		addr  uint64
		want  uint64
	}{
		// x86-64 hello: .text addr 0x1050 align 16.
		{"x86 +8", 16, 0x1058, 8},
		{"x86 +0x10", 16, 0x1060, 16},
		{"x86 +0x40", 16, 0x1090, 16},
		// aarch64 hello: .text addr 0x680 align 64.
		{"aarch64 +0x10", 64, 0x690, 16},
		{"aarch64 +0x20", 64, 0x6a0, 32},
		{"aarch64 +0x40", 64, 0x6c0, 64},
		{"aarch64 +0x80 capped", 64, 0x700, 64},
		// A zero VMA preserves the original alignment.
		{"zero stays 64", 64, 0, 64},
		{"zero stays 16", 16, 0, 16},
		{"zero stays 1", 1, 0, 1},
		// A zero (or non power of two) input alignment behaves like one byte.
		{"zero align", 0, 0x8, 1},
		{"zero align zero addr", 0, 0, 1},
		{"odd align", 3, 0x8, 1},
		// Alignment never grows and always divides the new address.
		{"aligned keeps", 8, 0x4008, 8},
		{"odd address", 8, 0x400a, 2},
		{"byte aligned", 1, 0x401f, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sectionAlignForVMA(tt.align, tt.addr)
			if got != tt.want {
				t.Fatalf("sectionAlignForVMA(%#x, %#x) = %#x want %#x",
					tt.align, tt.addr, got, tt.want)
			}
			base := tt.align & -tt.align
			if base == 0 {
				base = 1
			}
			if got > base {
				t.Errorf("alignment %#x exceeds original %#x", got, base)
			}
			if tt.addr != 0 && tt.addr%got != 0 {
				t.Errorf("alignment %#x does not divide address %#x", got, tt.addr)
			}
			// The rule is idempotent: feeding the result back must not shrink
			// the alignment further.
			if again := sectionAlignForVMA(got, tt.addr); again != got {
				t.Errorf("rule not idempotent: %#x then %#x", got, again)
			}
		})
	}
}

func alignFixture() *elf.File {
	text := covData(".text", 0x1050, []byte{1, 2, 3, 4})
	text.Addralign = 16
	data := covData(".data", 0x4008, []byte{5, 6, 7, 8})
	data.Addralign = 8
	comment := &elf.Section{SectionHeader: elf.SectionHeader{
		Name: ".comment", Type: elf.SHT_PROGBITS, Addralign: 1,
	}}
	comment.Data = []byte("gcc")
	return covELF(text, data, comment)
}

// TestAddressChangesLowerAlignment checks the observable behaviour on sections
// whose VMA an option actually moved, and that untouched sections keep their
// alignment.
func TestAddressChangesLowerAlignment(t *testing.T) {
	t.Run("addr add lowers", func(t *testing.T) {
		f := alignFixture()
		c := Default()
		c.ChangeSectionAddr = []SectionAddr{{Name: ".text", Op: AddrAdd, Val: 8}}
		if err := Transform(f, c); err != nil {
			t.Fatal(err)
		}
		text := f.Section(".text")
		if text.Addr != 0x1058 || text.Addralign != 8 {
			t.Errorf(".text addr=%#x align=%d want addr=0x1058 align=8",
				text.Addr, text.Addralign)
		}
		if text.LMA == nil || *text.LMA != 0x1058 {
			t.Errorf(".text lma=%v want 0x1058", text.LMA)
		}
		// Sections whose address was not changed must not be touched.
		data := f.Section(".data")
		if data.Addr != 0x4008 || data.Addralign != 8 {
			t.Errorf(".data addr=%#x align=%d want addr=0x4008 align=8",
				data.Addr, data.Addralign)
		}
		comment := f.Section(".comment")
		if comment.Addr != 0 || comment.Addralign != 1 {
			t.Errorf(".comment addr=%#x align=%d want addr=0 align=1",
				comment.Addr, comment.Addralign)
		}
	})

	t.Run("addr add keeps when divisible", func(t *testing.T) {
		f := alignFixture()
		c := Default()
		c.ChangeSectionVMA = []SectionAddr{{Name: ".text", Op: AddrAdd, Val: 0x10}}
		if err := Transform(f, c); err != nil {
			t.Fatal(err)
		}
		if got := f.Section(".text").Addralign; got != 16 {
			t.Errorf(".text align = %d want 16", got)
		}
	})

	t.Run("addr set lowers", func(t *testing.T) {
		f := alignFixture()
		c := Default()
		c.ChangeSectionAddr = []SectionAddr{{Name: ".text", Op: AddrSet, Val: 0x1234}}
		if err := Transform(f, c); err != nil {
			t.Fatal(err)
		}
		if got := f.Section(".text").Addralign; got != 4 {
			t.Errorf(".text align = %d want 4", got)
		}
	})

	t.Run("addr set to zero keeps", func(t *testing.T) {
		f := alignFixture()
		c := Default()
		c.ChangeSectionAddr = []SectionAddr{{Name: ".text", Op: AddrSet, Val: 0}}
		if err := Transform(f, c); err != nil {
			t.Fatal(err)
		}
		text := f.Section(".text")
		if text.Addr != 0 || text.Addralign != 16 {
			t.Errorf(".text addr=%#x align=%d want addr=0 align=16",
				text.Addr, text.Addralign)
		}
	})

	t.Run("lma only keeps alignment", func(t *testing.T) {
		f := alignFixture()
		c := Default()
		c.ChangeSectionLMA = []SectionAddr{{Name: ".text", Op: AddrAdd, Val: 8}}
		if err := Transform(f, c); err != nil {
			t.Fatal(err)
		}
		text := f.Section(".text")
		if text.Addr != 0x1050 || text.Addralign != 16 {
			t.Errorf(".text addr=%#x align=%d want addr=0x1050 align=16",
				text.Addr, text.Addralign)
		}
		if text.LMA == nil || *text.LMA != 0x1058 {
			t.Errorf(".text lma=%v want 0x1058", text.LMA)
		}
	})

	t.Run("adjust vma", func(t *testing.T) {
		f := alignFixture()
		d := int64(8)
		c := Default()
		c.ChangeAddresses = &d
		if err := Transform(f, c); err != nil {
			t.Fatal(err)
		}
		text := f.Section(".text")
		if text.Addr != 0x1058 || text.Addralign != 8 {
			t.Errorf(".text addr=%#x align=%d want addr=0x1058 align=8",
				text.Addr, text.Addralign)
		}
		// --adjust-vma also moves non-allocated sections, but their alignment
		// only shrinks when it does not divide the new address.
		comment := f.Section(".comment")
		if comment.Addr != 8 || comment.Addralign != 1 {
			t.Errorf(".comment addr=%#x align=%d want addr=8 align=1",
				comment.Addr, comment.Addralign)
		}
		// Section zero is never adjusted.
		if f.Sections[0].Addr != 0 || f.Sections[0].Addralign != 0 {
			t.Errorf("section 0 addr=%#x align=%d want zeros",
				f.Sections[0].Addr, f.Sections[0].Addralign)
		}
	})

	t.Run("repeated changes do not compound", func(t *testing.T) {
		f := alignFixture()
		c := Default()
		// Both patterns hit .text.  BFD derives the output alignment from the
		// input alignment and the final VMA, so the reduction must not be
		// applied once per request.
		c.ChangeSectionAddr = []SectionAddr{
			{Name: ".text", Op: AddrAdd, Val: 8},
			{Name: ".te*", Op: AddrAdd, Val: 8},
		}
		if err := Transform(f, c); err != nil {
			t.Fatal(err)
		}
		text := f.Section(".text")
		if text.Addr == 0x1050 {
			t.Fatal("address options were not applied")
		}
		if want := sectionAlignForVMA(16, text.Addr); text.Addralign != want {
			t.Errorf(".text addr=%#x align=%d want %d from the original alignment",
				text.Addr, text.Addralign, want)
		}
	})
}

// TestAddressChangesAlignmentEdgeSections covers NOBITS sections, sections at
// address zero and non-allocated sections, all of which BFD treats the same way
// as ordinary allocated PROGBITS sections.
func TestAddressChangesAlignmentEdgeSections(t *testing.T) {
	mk := func() *elf.File {
		bss := &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".bss", Type: elf.SHT_NOBITS, Flags: elf.SHF_ALLOC | elf.SHF_WRITE,
			Addralign: 32, Size: 32,
		}}
		noload := &elf.Section{SectionHeader: elf.SectionHeader{
			Name: ".foo", Type: elf.SHT_PROGBITS, Addralign: 32,
		}}
		noload.Data = []byte{1, 2, 3, 4}
		data := covData(".data", 0x4008, []byte{1})
		data.Addralign = 8
		return covELF(bss, noload, data)
	}

	t.Run("nobits from zero", func(t *testing.T) {
		f := mk()
		c := Default()
		c.ChangeSectionAddr = []SectionAddr{{Name: ".bss", Op: AddrAdd, Val: 8}}
		if err := Transform(f, c); err != nil {
			t.Fatal(err)
		}
		bss := f.Section(".bss")
		if bss.Addr != 8 || bss.Addralign != 8 {
			t.Errorf(".bss addr=%#x align=%d want addr=8 align=8",
				bss.Addr, bss.Addralign)
		}
	})

	t.Run("nobits to zero keeps", func(t *testing.T) {
		f := mk()
		c := Default()
		c.ChangeSectionAddr = []SectionAddr{{Name: ".bss", Op: AddrSet, Val: 0}}
		if err := Transform(f, c); err != nil {
			t.Fatal(err)
		}
		bss := f.Section(".bss")
		if bss.Addr != 0 || bss.Addralign != 32 {
			t.Errorf(".bss addr=%#x align=%d want addr=0 align=32",
				bss.Addr, bss.Addralign)
		}
	})

	t.Run("non-alloc lowers", func(t *testing.T) {
		f := mk()
		c := Default()
		c.ChangeSectionVMA = []SectionAddr{{Name: ".foo", Op: AddrSet, Val: 0x10}}
		if err := Transform(f, c); err != nil {
			t.Fatal(err)
		}
		foo := f.Section(".foo")
		if foo.Addr != 0x10 || foo.Addralign != 16 {
			t.Errorf(".foo addr=%#x align=%d want addr=0x10 align=16",
				foo.Addr, foo.Addralign)
		}
	})

	t.Run("untouched nobits with zero addr keeps", func(t *testing.T) {
		f := mk()
		c := Default()
		c.ChangeSectionVMA = []SectionAddr{{Name: ".data", Op: AddrAdd, Val: 4}}
		if err := Transform(f, c); err != nil {
			t.Fatal(err)
		}
		bss := f.Section(".bss")
		if bss.Addr != 0 || bss.Addralign != 32 {
			t.Errorf("untouched .bss addr=%#x align=%d want addr=0 align=32",
				bss.Addr, bss.Addralign)
		}
		if got := f.Section(".data").Addralign; got != 4 {
			t.Errorf(".data align = %d want 4", got)
		}
	})
}
