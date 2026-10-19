package objcopy

import (
	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/bfdtarget"
)

func init() {
	// GNU objcopy defaults -I binary to binary output. Handling the reader
	// here also allows binary input to feed the textual writers; the binary
	// writer itself stays in binary.go, and --interleave is applied by
	// applySectionContents before the flat image is laid out.
	inputReaders["binary"] = readBinary
}

// readBinary builds the synthetic ELF object GNU objcopy creates for
// "-I binary". Without an explicit output target the output defaults to
// binary, matching GNU's output_target = input_target rule.
func readBinary(data []byte, path string, cfg *Config, t *bfdtarget.Target) (*elf.File, error) {
	target := &bfdtarget.Target{
		Name:    "elf64-little",
		Class:   elf.Class64,
		Data:    elf.DataLSB,
		Machine: elf.EM_NONE,
		IsELF:   true,
	}
	outputIsELF := false
	if cfg != nil && cfg.OutputTarget != "" {
		if out, err := bfdtarget.Parse(cfg.OutputTarget); err == nil && out.IsELF {
			target = out
			outputIsELF = true
			// applyFormat supplies the output machine type; leaving it unset
			// also keeps the synthetic model out of run.go's verbatim-copy
			// fast path.
			target.Machine = 0
		}
	}
	if cfg != nil && !outputIsELF && cfg.BinaryArch != "" {
		class, machine, ok := bfdtarget.ParseArch(cfg.BinaryArch)
		if !ok {
			return nil, &FatalError{Msg: "unrecognized architecture " + cfg.BinaryArch}
		}
		target.Class = class
		target.Machine = machine
	}
	f, err := binaryToELF(data, path, cfg, target)
	if err != nil {
		return nil, err
	}
	if cfg != nil && cfg.OutputTarget == "" && t != nil {
		cfg.OutputTarget = t.Name
	}
	return f, nil
}
