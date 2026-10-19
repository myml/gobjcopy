package objcopy

import "github.com/myml/gobjcopy/elf"

// ELF class conversion is wired in here rather than in run.go so that the
// pipeline stays independent of the elf package's conversion implementation.
func init() {
	convertClass = convertELFFileClass
}

// convertELFFileClass converts f between ELF32 and ELF64 in place.  The writer
// derives all header widths from File.Class; elf.ConvertClass re-encodes the
// symbol tables, relocations and other class-dependent section contents.
func convertELFFileClass(f *elf.File, class elf.Class) error {
	return elf.ConvertClass(f, class)
}
