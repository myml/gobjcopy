package objcopy

import (
	"fmt"
	"os"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/ar"
	"github.com/myml/gobjcopy/internal/bfdtarget"
)

// Archive support. Run calls archiveRun after reading the input and before
// trying to parse it as ELF; returning handled=false means "not an archive, go
// on with the normal objcopy pipeline".
func init() {
	archiveRun = runArchive
}

// deterministicArchives applies GNU's -D/-U default for archive output.
// objcopy's -D/--enable-deterministic-archives is the default (metadata is
// zeroed and mode becomes 0644); -U/--disable-deterministic-archives preserves
// the values recorded in the input.
func deterministicArchives(cfg *Config) bool {
	if cfg.DeterministicArchives == nil {
		return true
	}
	return *cfg.DeterministicArchives
}

// runArchive handles ar archive input. It transforms each ELF member with the
// same pipeline used for standalone files and writes a fresh GNU archive with
// rebuilt long-name and symbol tables.
func runArchive(cfg *Config, inPath, outPath string, data []byte) (bool, error) {
	if ar.IsThinArchive(data) {
		// GNU objcopy refuses thin archives too (objcopy.c copy_archive).
		return true, fmt.Errorf("%s: sorry: copying thin archives is not currently supported", inPath)
	}
	if !ar.IsArchive(data) {
		return false, nil
	}

	// An explicit non-ELF input target (notably -I binary) makes BFD treat
	// the file as that format rather than as an archive.
	if cfg.InputTarget != "" {
		if t, err := bfdtarget.Parse(cfg.InputTarget); err == nil && !t.IsELF {
			return false, nil
		}
	}

	outName := outPath
	if outName == "" {
		outName = inPath
	}

	// BFD can only write an archive when the output target itself supports
	// archives; binary/ihex/srec output fails with "invalid operation".
	if cfg.OutputTarget != "" {
		t, err := bfdtarget.Parse(cfg.OutputTarget)
		if err != nil {
			return true, err
		}
		if !t.IsELF {
			return true, fmt.Errorf("%s: invalid operation", outName)
		}
	}

	in, err := ar.Parse(data)
	if err != nil {
		return true, fmt.Errorf("%s: %w", inPath, err)
	}

	// GNU objcopy ignores --add-gnu-debuglink for archives (objcopy.c
	// copy_file), so the per-member transforms must not apply it.
	memberCfg := *cfg
	if memberCfg.AddDebugLink != "" {
		memberCfg.AddDebugLink = ""
		cfg.warnf("--add-gnu-debuglink ignored for archive %s", inPath)
	}

	out := &ar.Archive{HasSymbolTable: in.HasSymbolTable}
	for _, m := range in.Members {
		nm := &ar.Member{
			Name:  m.Name,
			Mtime: m.Mtime,
			UID:   m.UID,
			GID:   m.GID,
			Mode:  m.Mode,
		}
		if !isELF(m.Data) {
			// Symbol tables, string tables and other non-object members are
			// copied verbatim, as GNU's copy_unknown_object does.
			nm.Data = m.Data
			cfg.warnf("%s(%s): Unable to recognise the format of file: file format not recognized", inPath, m.Name)
			out.Members = append(out.Members, nm)
			continue
		}
		f, err := elf.Parse(m.Data)
		if err != nil {
			// BFD warns about unreadable members and copies them unchanged.
			cfg.warnf("%s(%s): Unable to recognise the format of file: %v", inPath, m.Name, err)
			nm.Data = m.Data
			out.Members = append(out.Members, nm)
			continue
		}
		if err := Transform(f, &memberCfg); err != nil {
			return true, fmt.Errorf("%s(%s): %w", inPath, m.Name, err)
		}
		nm.Symbols = archiveSymbols(f)
		nm.Data, err = archiveMemberBytes(f, &memberCfg)
		if err != nil {
			return true, fmt.Errorf("%s(%s): %w", inPath, m.Name, err)
		}
		out.Members = append(out.Members, nm)
	}

	// GNU drops the index when stripping all symbols; otherwise it preserves
	// the presence of the input's symbol table.
	writeOpts := ar.WriteOptions{
		Deterministic: deterministicArchives(cfg),
		SymbolTable:   in.HasSymbolTable && !cfg.StripAll,
	}
	blob, err := out.Bytes(writeOpts)
	if err != nil {
		return true, fmt.Errorf("%s: %w", outName, err)
	}

	st, err := os.Stat(inPath)
	if err != nil {
		return true, err
	}
	inPlace := outPath == "" || outPath == inPath
	if cfg.Verbose {
		cfg.infof("copying archive %s to %s", inPath, outName)
	}
	return true, writeResult(outName, blob, st, cfg.PreserveDates, inPlace)
}

// archiveMemberBytes serializes one transformed member. Without an explicit
// -O the member keeps its own format; with one, the output target is applied
// exactly as it would be for a standalone file.
func archiveMemberBytes(f *elf.File, cfg *Config) ([]byte, error) {
	if cfg.OutputTarget != "" {
		t, err := outputTarget(cfg, f)
		if err != nil {
			return nil, err
		}
		if err := applyFormat(f, t, cfg); err != nil {
			return nil, err
		}
	}
	return f.Bytes()
}

// archiveSymbols returns the names that belong in the archive index: global,
// weak and unique symbols that the member defines, plus common symbols. This
// mirrors _bfd_compute_and_write_armap's filter.
func archiveSymbols(f *elf.File) []string {
	st := f.Symtab()
	if st == nil {
		return nil
	}
	var names []string
	for _, sym := range st.Entries {
		if sym.Name == "" || sym.Shndx == elf.SHN_UNDEF {
			continue
		}
		bind := sym.Bind()
		global := bind == elf.STB_GLOBAL || bind == elf.STB_WEAK || bind == elf.STB_GNU_UNIQUE
		if !global && sym.Shndx != elf.SHN_COMMON {
			continue
		}
		names = append(names, sym.Name)
	}
	return names
}
