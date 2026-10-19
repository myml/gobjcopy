package objcopy

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/bfdtarget"
)

// ErrUnsupported reports an input or output format that this implementation
// cannot handle yet.
var ErrUnsupported = errors.New("unsupported file format")

// Extension points. Formats and archive handling live in their own files and
// register here so that this pipeline stays stable.
var (
	// outputWriters maps a BFD target name (e.g. "ihex") to a writer.
	outputWriters = map[string]func(*elf.File, *Config) ([]byte, error){}
	// inputReaders maps a BFD target name to a reader producing an ELF model.
	inputReaders = map[string]func(data []byte, path string, cfg *Config, t *bfdtarget.Target) (*elf.File, error){}
	// archiveRun, when set, handles ar archives; it reports whether it did.
	archiveRun func(cfg *Config, inPath, outPath string, data []byte) (bool, error)
	// convertClass converts a file to another ELF class in place.
	convertClass func(f *elf.File, class elf.Class) error
	// noteMerge merges duplicate notes; GNU does this while copying sections.
	noteMerge func(f *elf.File, cfg *Config) error
)

func (c *Config) warnf(format string, args ...any) {
	if c.Warnf != nil {
		c.Warnf(format, args...)
	}
}

func (c *Config) infof(format string, args ...any) {
	if c.Infof != nil {
		c.Infof(format, args...)
	}
}

// Run performs one objcopy invocation: it reads inPath, applies cfg, and
// writes the result to outPath. An empty outPath means in-place modification.
func Run(cfg *Config, inPath, outPath string) error {
	if cfg == nil {
		cfg = Default()
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	st, err := os.Stat(inPath)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("%s: is a directory", inPath)
	}
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	if archiveRun != nil {
		if handled, err := archiveRun(cfg, inPath, outPath, data); handled {
			return err
		}
	}

	var inTgt *bfdtarget.Target
	if cfg.InputTarget != "" {
		inTgt, err = bfdtarget.Parse(cfg.InputTarget)
		if err != nil {
			return err
		}
	}

	var f *elf.File
	if inTgt != nil {
		if r, ok := inputReaders[inTgt.Name]; ok {
			f, err = r(data, inPath, cfg, inTgt)
			if err != nil {
				return err
			}
			goto haveFile
		}
	}
	if inTgt != nil && inTgt.IsBinary {
		outTgt, err := binaryOutputTarget(cfg)
		if err != nil {
			return err
		}
		f, err = binaryToELF(data, inPath, cfg, outTgt)
		if err != nil {
			return err
		}
	} else if inTgt != nil && inTgt.IsELF {
		f, err = elf.Parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", inPath, err)
		}
	} else if inTgt != nil {
		return fmt.Errorf("%s: %w: %s", inPath, ErrUnsupported, inTgt.Name)
	} else {
		if !isELF(data) {
			return fmt.Errorf("%s: file format not recognized", inPath)
		}
		f, err = elf.Parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", inPath, err)
		}
	}

haveFile:
	outTgt, err := outputTarget(cfg, f)
	if err != nil {
		return err
	}
	// A no-op copy must reproduce the input byte for byte, exactly like GNU
	// objcopy (binutils' tests compare the files with cmp).
	// Verbatim copying is only valid when both sides are ELF: a model parsed
	// from binary/ihex/srec must always be re-serialised.
	inputIsELF := inTgt == nil || inTgt.IsELF
	sameFormat := outTgt.IsELF && inputIsELF && f.SectionHeadersPresent &&
		outTgt.Class == f.Class && outTgt.Data == f.Data &&
		(outTgt.Machine == f.Machine || outTgt.Machine == 0)
	if outPath != "" {
		cfg.OutputName = outPath
	} else {
		cfg.OutputName = inPath
	}
	if sameFormat && !cfg.transformsContent() {
		if cfg.Verbose {
			cfg.infof("copy from %s to %s", inPath, outPath)
		}
		dst := outPath
		if dst == "" {
			dst = inPath
		}
		return writeResult(dst, data, st, cfg.PreserveDates, dst == inPath)
	}

	if cfg.Verbose {
		cfg.infof("%s: %d sections, %d segments", inPath, len(f.Sections), len(f.Segments))
	}
	digestBefore := fileDigest(f)
	if err := Transform(f, cfg); err != nil {
		return err
	}

	var out []byte
	if sameFormat && fileDigest(f) == digestBefore {
		// The requested options did not actually change the file; GNU copies
		// the input verbatim in that case (its tests compare with cmp).
		if cfg.Verbose {
			cfg.infof("copy from %s to %s", inPath, outPath)
		}
		out = data
	} else if w, ok := outputWriters[outTgt.Name]; ok {
		out, err = w(f, cfg)
	} else if outTgt.IsBinary {
		out, err = ToBinary(f, cfg)
	} else {
		if err := applyFormat(f, outTgt); err != nil {
			return err
		}
		out, err = f.Bytes()
	}
	if err != nil {
		return err
	}

	dst := outPath
	inPlace := dst == "" || dst == inPath
	if dst == "" {
		dst = inPath
	}
	if cfg.Verbose {
		cfg.infof("copying to %s", dst)
	}
	return writeResult(dst, out, st, cfg.PreserveDates, inPlace)
}

// Transform applies all configured modifications to a parsed ELF image.
func Transform(f *elf.File, cfg *Config) error {
	if cfg == nil {
		cfg = Default()
	}
	steps := []func(*elf.File, *Config) error{
		applySectionStrip,
		applyOnlyKeepDebug,
		applySectionRenames,
		applySectionFlags,
		applySectionAlignment,
		applyAddUpdateSections,
		applyNotes,
		applyRemoveRelocations,
		applyPruneSegments,
		applyAddressChanges,
		applySymbols,
		applyDebugLink,
		applyCompression,
		applyGapFill,
		applyPadTo,
	}
	for _, step := range steps {
		if err := step(f, cfg); err != nil {
			return err
		}
	}
	return nil
}

func isELF(data []byte) bool {
	return len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F'
}

func binaryOutputTarget(cfg *Config) (*bfdtarget.Target, error) {
	name := cfg.OutputTarget
	if name == "" {
		return nil, fmt.Errorf("no output format specified for binary input")
	}
	t, err := bfdtarget.Parse(name)
	if err != nil {
		return nil, err
	}
	if t.IsBinary {
		return nil, fmt.Errorf("cannot produce binary output from binary input")
	}
	if !t.IsELF {
		return nil, fmt.Errorf("%s: %w", t.Name, ErrUnsupported)
	}
	if cfg.BinaryArch != "" {
		class, machine, ok := bfdtarget.ParseArch(cfg.BinaryArch)
		if !ok {
			return nil, fmt.Errorf("unrecognized architecture %q", cfg.BinaryArch)
		}
		t.Class = class
		t.Machine = machine
	}
	return t, nil
}

func outputTarget(cfg *Config, f *elf.File) (*bfdtarget.Target, error) {
	if cfg.OutputTarget != "" {
		return bfdtarget.Parse(cfg.OutputTarget)
	}
	name := bfdtarget.String(f.Class, f.Data, f.Machine)
	return bfdtarget.Parse(name)
}

func applyFormat(f *elf.File, t *bfdtarget.Target) error {
	if t.Class != f.Class {
		if convertClass != nil {
			return convertClass(f, t.Class)
		}
		return fmt.Errorf("cannot convert %s output to %s", f.Class, t.Class)
	}
	if false {
		if t.Class == elf.Class32 {
			for _, s := range f.Sections {
				if s.Addr > 0xffffffff || s.Size > 0xffffffff || s.Offset > 0xffffffff {
					return fmt.Errorf("section %s does not fit in ELF32", s.Name)
				}
			}
			if f.Entry > 0xffffffff {
				return fmt.Errorf("entry point does not fit in ELF32")
			}
		}
		f.Class = t.Class
	}
	if t.Data != f.Data {
		return fmt.Errorf("cannot convert %s to %s", f.Data, t.Data)
	}
	if t.Machine != 0 {
		f.Machine = t.Machine
	}
	return nil
}

func writeResult(dst string, data []byte, st os.FileInfo, preserveDates, inPlace bool) error {
	perm := st.Mode().Perm()
	if inPlace {
		dir := filepath.Dir(dst)
		tmp, err := os.CreateTemp(dir, ".objcopy-*")
		if err != nil {
			return err
		}
		name := tmp.Name()
		defer os.Remove(name)
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := os.Chmod(name, perm); err != nil {
			return err
		}
		if err := os.Rename(name, dst); err != nil {
			return err
		}
	} else {
		if err := os.WriteFile(dst, data, perm); err != nil {
			return err
		}
		if err := os.Chmod(dst, perm); err != nil {
			return err
		}
	}
	if preserveDates {
		mtime := st.ModTime()
		atime := mtime
		if err := os.Chtimes(dst, atime, mtime); err != nil {
			return err
		}
	}
	_ = time.Now
	return nil
}

// warnMissing reports a name that did not match, mirroring GNU's wording.
func (c *Config) warnMissing(kind, name string) {
	switch kind {
	case "section":
		c.warnf("unable to find section %s", name)
	case "symbol":
		c.warnf("unable to find symbol %s", name)
	}
}

var _ = strings.EqualFold

// transformsContent reports whether any option can change the bytes of the
// output. Purely informational options (-v, -p, --info, format selection, the
// output file name) do not count. Reflection keeps this correct as Config
// grows; embedded option structs are inspected field by field.
func (c *Config) transformsContent() bool {
	skip := map[string]bool{
		"PreserveDates": true, "Verbose": true, "Quiet": true,
		"InputTarget": true, "OutputTarget": true, "Target": true,
		"BinaryArch": true, "InterleaveWidth": true, "Byte": true,
		"Warnf": true, "Infof": true, "OutputName": true,
	}
	var walk func(reflect.Value) bool
	walk = func(v reflect.Value) bool {
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			fv := v.Field(i)
			if f.Anonymous && fv.Kind() == reflect.Struct {
				if walk(fv) {
					return true
				}
				continue
			}
			if skip[f.Name] {
				continue
			}
			if !fv.IsZero() {
				return true
			}
		}
		return false
	}
	return walk(reflect.ValueOf(*c))
}

// fileDigest fingerprints everything that would change the bytes written for
// an ELF file, so a transformation that changed nothing can be detected.
func fileDigest(f *elf.File) [32]byte {
	h := sha256.New()
	var buf [8]byte
	put := func(v uint64) {
		binary.LittleEndian.PutUint64(buf[:], v)
		h.Write(buf[:])
	}
	put(uint64(f.Class))
	put(uint64(f.Data))
	put(f.Entry)
	put(uint64(len(f.Sections)))
	put(uint64(f.Shstrndx))
	if f.NoSectionHeaders {
		put(1)
	} else {
		put(0)
	}
	if f.Segments != nil {
		put(1)
	} else {
		put(0)
	}
	for _, s := range f.Sections {
		h.Write([]byte(s.Name))
		put(uint64(s.Type))
		put(s.Flags)
		put(s.Addr)
		put(s.Offset)
		put(s.Size)
		put(uint64(s.Link))
		put(uint64(s.Info))
		put(s.Addralign)
		put(s.Entsize)
		if s.LMA != nil {
			put(1)
			put(*s.LMA)
		} else {
			put(0)
		}
		h.Write(s.Data)
	}
	for _, p := range f.Segments {
		put(uint64(p.Type))
		put(uint64(p.Flags))
		put(p.Offset)
		put(p.Vaddr)
		put(p.Paddr)
		put(p.Filesz)
		put(p.Memsz)
		put(p.Align)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// applyNotes runs the registered note-merging implementation, if any.
func applyNotes(f *elf.File, c *Config) error {
	if noteMerge == nil {
		return nil
	}
	return noteMerge(f, c)
}
