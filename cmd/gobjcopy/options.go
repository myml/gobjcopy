package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/myml/gobjcopy/elf"
	"github.com/myml/gobjcopy/internal/getopt"
	"github.com/myml/gobjcopy/objcopy"
)

// optionSpec describes one command-line option. A non-empty key is the
// canonical action name used by applyOption; an empty key means the action is
// named after the long option itself. Short-only entries (like -s, -d, -H and
// the short form of -i) must set key.
//
// The table is a one-for-one transcription of GNU binutils 2.44
// binutils/objcopy.c copy_options[] plus the extra short options from the
// getopt_long option string "b:B:i:I:j:K:MN:s:O:d:F:L:G:R:SpgxXHhVvW:wDU".
// Argument modes therefore match GNU exactly, including two long-standing
// quirks: --keep-section-symbols is declared required_argument (its argument
// is ignored) and --interleave is an optional_argument.
type optionSpec struct {
	long  string
	short rune
	arg   getopt.ArgMode
	key   string
}

func (s optionSpec) action() string {
	if s.key != "" {
		return s.key
	}
	return s.long
}

var optionSpecs = []optionSpec{
	// GNU copy_options[] order.
	{long: "add-gnu-debuglink", arg: getopt.RequiredArg},
	{long: "add-section", arg: getopt.RequiredArg},
	{long: "add-symbol", arg: getopt.RequiredArg},
	{long: "adjust-section-vma", arg: getopt.RequiredArg, key: "change-section-address"},
	{long: "adjust-start", arg: getopt.RequiredArg, key: "change-start"},
	{long: "adjust-vma", arg: getopt.RequiredArg, key: "change-addresses"},
	{long: "adjust-warnings", key: "change-warnings"},
	{long: "alt-machine-code", arg: getopt.RequiredArg},
	{long: "binary-architecture", short: 'B', arg: getopt.RequiredArg},
	{long: "byte", short: 'b', arg: getopt.RequiredArg},
	{long: "change-addresses", arg: getopt.RequiredArg},
	{long: "change-leading-char"},
	{long: "change-section-address", arg: getopt.RequiredArg},
	{long: "change-section-lma", arg: getopt.RequiredArg},
	{long: "change-section-vma", arg: getopt.RequiredArg},
	{long: "change-start", arg: getopt.RequiredArg},
	{long: "change-warnings"},
	{long: "compress-debug-sections", arg: getopt.OptionalArg},
	{long: "debugging"},
	{long: "decompress-debug-sections"},
	{long: "disable-deterministic-archives", short: 'U'},
	{long: "discard-all", short: 'x'},
	{long: "discard-locals", short: 'X'},
	{long: "dump-section", arg: getopt.RequiredArg},
	{long: "elf-stt-common", arg: getopt.RequiredArg},
	{long: "enable-deterministic-archives", short: 'D'},
	{long: "extract-dwo"},
	{long: "extract-symbol"},
	{long: "file-alignment", arg: getopt.RequiredArg},
	{long: "format", arg: getopt.RequiredArg, key: "target"},
	{long: "gap-fill", arg: getopt.RequiredArg},
	{long: "globalize-symbol", arg: getopt.RequiredArg},
	{long: "globalize-symbols", arg: getopt.RequiredArg},
	{long: "heap", arg: getopt.RequiredArg},
	{long: "help", short: 'h'},
	{long: "image-base", arg: getopt.RequiredArg},
	{long: "impure"},
	{long: "info"},
	{long: "input-format", arg: getopt.RequiredArg, key: "input-target"},
	{long: "input-target", short: 'I', arg: getopt.RequiredArg},
	{long: "interleave", arg: getopt.OptionalArg},
	{long: "interleave-width", arg: getopt.RequiredArg},
	{long: "keep-file-symbols"},
	{long: "keep-global-symbol", short: 'G', arg: getopt.RequiredArg},
	{long: "keep-global-symbols", arg: getopt.RequiredArg},
	{long: "keep-section", arg: getopt.RequiredArg},
	{long: "keep-symbol", short: 'K', arg: getopt.RequiredArg},
	{long: "keep-symbols", arg: getopt.RequiredArg},
	// GNU 2.44 declares this one required_argument (see optionSpec above).
	{long: "keep-section-symbols", arg: getopt.RequiredArg},
	{long: "localize-hidden"},
	{long: "localize-symbol", short: 'L', arg: getopt.RequiredArg},
	{long: "localize-symbols", arg: getopt.RequiredArg},
	{long: "long-section-names", arg: getopt.RequiredArg},
	{long: "merge-notes", short: 'M'},
	{long: "no-merge-notes"},
	{long: "no-adjust-warnings", key: "no-change-warnings"},
	{long: "no-change-warnings"},
	{long: "only-keep-debug"},
	{long: "only-section", short: 'j', arg: getopt.RequiredArg},
	{long: "output-format", arg: getopt.RequiredArg, key: "output-target"},
	{long: "output-target", short: 'O', arg: getopt.RequiredArg},
	{long: "pad-to", arg: getopt.RequiredArg},
	{long: "prefix-alloc-sections", arg: getopt.RequiredArg},
	{long: "prefix-sections", arg: getopt.RequiredArg},
	{long: "prefix-symbols", arg: getopt.RequiredArg},
	{long: "preserve-dates", short: 'p'},
	{long: "pure"},
	{long: "readonly-text"},
	{long: "redefine-sym", arg: getopt.RequiredArg},
	{long: "redefine-syms", arg: getopt.RequiredArg},
	{long: "remove-leading-char"},
	{long: "remove-section", short: 'R', arg: getopt.RequiredArg},
	{long: "remove-relocations", arg: getopt.RequiredArg},
	{long: "strip-section-headers"},
	{long: "rename-section", arg: getopt.RequiredArg},
	{long: "reverse-bytes", arg: getopt.RequiredArg},
	{long: "section-alignment", arg: getopt.RequiredArg},
	{long: "set-section-flags", arg: getopt.RequiredArg},
	{long: "set-section-alignment", arg: getopt.RequiredArg},
	{long: "set-start", arg: getopt.RequiredArg},
	{long: "srec-forceS3"},
	{long: "srec-len", arg: getopt.RequiredArg},
	{long: "stack", arg: getopt.RequiredArg},
	{long: "strip-all", short: 'S'},
	{long: "strip-debug", short: 'g'},
	{long: "strip-dwo"},
	{long: "strip-symbol", short: 'N', arg: getopt.RequiredArg},
	{long: "strip-symbols", arg: getopt.RequiredArg},
	{long: "strip-unneeded"},
	{long: "strip-unneeded-symbol", arg: getopt.RequiredArg},
	{long: "strip-unneeded-symbols", arg: getopt.RequiredArg},
	{long: "subsystem", arg: getopt.RequiredArg},
	{long: "target", short: 'F', arg: getopt.RequiredArg},
	{long: "update-section", arg: getopt.RequiredArg},
	{long: "verbose", short: 'v'},
	{long: "verilog-data-width", arg: getopt.RequiredArg},
	{long: "version", short: 'V'},
	{long: "weaken"},
	{long: "weaken-symbol", short: 'W', arg: getopt.RequiredArg},
	{long: "weaken-symbols", arg: getopt.RequiredArg},
	{long: "wildcard", short: 'w'},
	{long: "writable-text"},

	// Short-only forms from GNU's getopt_long string. GNU maps -s to the
	// input target ("source") and -d to the output target ("destination");
	// both are historical aliases that have no long form. -H is an alias for
	// -h. The short -i requires an argument even though --interleave's
	// argument is optional, which is why it needs its own table entry.
	{long: "", short: 's', arg: getopt.RequiredArg, key: "input-target"},
	{long: "", short: 'd', arg: getopt.RequiredArg, key: "output-target"},
	{long: "", short: 'H', key: "help"},
	{long: "", short: 'i', arg: getopt.RequiredArg, key: "interleave"},
}

// parsedArgs is the result of a successful command-line parse.
type parsedArgs struct {
	cfg      *objcopy.Config
	operands []string
	help     bool
	version  bool
	info     bool
}

// newParser builds a getopt parser for the option table together with a map
// from each registered option back to its canonical action name.
func newParser() (*getopt.Parser, map[*getopt.Option]string) {
	options := make([]getopt.Option, len(optionSpecs))
	actions := make(map[*getopt.Option]string, len(optionSpecs))
	for i, spec := range optionSpecs {
		options[i] = getopt.Option{Long: spec.long, Short: spec.short, Arg: spec.arg}
		actions[&options[i]] = spec.action()
	}
	return getopt.New(options), actions
}

// parseCommandLine parses args (without the program name), applies every
// option to a fresh Config, and returns the operands and mode flags.
//
// Like GNU objcopy, -h/--help takes effect as soon as it is seen: options to
// its left are processed, options to its right are not. This matters when a
// later option would be an error, so a getopt failure is reported as "help"
// when a help occurrence was already recognized.
func parseCommandLine(args []string) (*parsedArgs, error) {
	parser, actions := newParser()
	occurrences, operands, parseErr := parser.Parse(args)

	pa := &parsedArgs{cfg: objcopy.Default()}
	var useGlobalize, useKeepGlobal bool
	for _, occ := range occurrences {
		action := actions[occ.Option]
		if action == "help" {
			pa.help = true
			return pa, nil
		}
		if err := applyOption(pa, action, occ.Arg, &useGlobalize, &useKeepGlobal); err != nil {
			return nil, err
		}
	}
	if parseErr != nil {
		return nil, parseErr
	}
	if useGlobalize && useKeepGlobal {
		return nil, fmt.Errorf("--globalize-symbol(s) is incompatible with -G/--keep-global-symbol(s)")
	}
	pa.operands = operands
	return pa, nil
}

// parseArgs is the testable core of the CLI: it returns the Config and the
// operands, ignoring the help/version/info mode flags.
func parseArgs(args []string) (*objcopy.Config, []string, error) {
	pa, err := parseCommandLine(args)
	if err != nil {
		return nil, nil, err
	}
	return pa.cfg, pa.operands, nil
}

// Multiple options feed GNU's single strip_symbols enumeration, so the last
// one on the command line wins. Config models the modes as separate booleans,
// which setStripMode keeps mutually exclusive.
type stripMode int

const (
	stripNone stripMode = iota
	stripAll
	stripDebug
	stripDWO
	stripUnneeded
	onlyKeepDebug
	extractDWO
)

func setStripMode(c *objcopy.Config, mode stripMode) {
	c.StripAll = mode == stripAll
	c.StripDebug = mode == stripDebug
	c.StripDWO = mode == stripDWO
	c.StripUnneeded = mode == stripUnneeded
	c.OnlyKeepDebug = mode == onlyKeepDebug
	c.ExtractDWO = mode == extractDWO
}

// setInputTarget records -I/-s/--input-format. A later input target cancels
// -F's "both formats" setting so that Config.Validate cannot overwrite it.
func setInputTarget(c *objcopy.Config, target string) {
	c.InputTarget = target
	c.Target = ""
}

// setOutputTarget records -O/-d/--output-format, cancelling -F in the same
// way.
func setOutputTarget(c *objcopy.Config, target string) {
	c.OutputTarget = target
	c.Target = ""
}

// applyOption maps one option occurrence onto cfg.
func applyOption(pa *parsedArgs, action, arg string, useGlobalize, useKeepGlobal *bool) error {
	cfg := pa.cfg
	switch action {
	case "help":
		pa.help = true
	case "version":
		pa.version = true
	case "info":
		pa.info = true

	case "input-target":
		setInputTarget(cfg, arg)
	case "output-target":
		setOutputTarget(cfg, arg)
	case "target":
		// GNU sets input_target = output_target = optarg.
		cfg.Target = arg
		cfg.InputTarget = arg
		cfg.OutputTarget = arg
	case "binary-architecture":
		cfg.BinaryArch = arg
	case "preserve-dates":
		cfg.PreserveDates = true
	case "verbose":
		cfg.Verbose = true

	case "strip-all":
		setStripMode(cfg, stripAll)
	case "strip-debug":
		setStripMode(cfg, stripDebug)
	case "strip-dwo":
		setStripMode(cfg, stripDWO)
	case "strip-unneeded":
		setStripMode(cfg, stripUnneeded)
	case "only-keep-debug":
		setStripMode(cfg, onlyKeepDebug)
	case "extract-dwo":
		setStripMode(cfg, extractDWO)

	case "discard-all":
		cfg.DiscardAll = true
	case "discard-locals":
		cfg.DiscardLocals = true

	case "strip-symbol":
		cfg.StripSymbols = append(cfg.StripSymbols, arg)
	case "strip-unneeded-symbol":
		cfg.StripUnneededSymbols = append(cfg.StripUnneededSymbols, arg)
	case "keep-symbol":
		cfg.KeepSymbols = append(cfg.KeepSymbols, arg)
	case "keep-global-symbol":
		*useKeepGlobal = true
		cfg.KeepGlobalSymbols = append(cfg.KeepGlobalSymbols, arg)
	case "localize-symbol":
		cfg.LocalizeSymbols = append(cfg.LocalizeSymbols, arg)
	case "globalize-symbol":
		*useGlobalize = true
		cfg.GlobalizeSymbols = append(cfg.GlobalizeSymbols, arg)
	case "weaken-symbol":
		cfg.WeakenSymbols = append(cfg.WeakenSymbols, arg)
	case "weaken":
		cfg.WeakenAll = true
	case "wildcard":
		cfg.Wildcard = true
	case "keep-file-symbols":
		cfg.KeepFileSymbols = true
	case "keep-section-symbols":
		// GNU declares this option required_argument but ignores the value.
		cfg.KeepSectionSymbols = true
	case "localize-hidden":
		cfg.LocalizeHidden = true

	case "strip-symbols":
		names, err := readSymbolList(arg)
		if err != nil {
			return err
		}
		cfg.StripSymbols = append(cfg.StripSymbols, names...)
	case "strip-unneeded-symbols":
		names, err := readSymbolList(arg)
		if err != nil {
			return err
		}
		cfg.StripUnneededSymbols = append(cfg.StripUnneededSymbols, names...)
	case "keep-symbols":
		names, err := readSymbolList(arg)
		if err != nil {
			return err
		}
		cfg.KeepSymbols = append(cfg.KeepSymbols, names...)
	case "localize-symbols":
		names, err := readSymbolList(arg)
		if err != nil {
			return err
		}
		cfg.LocalizeSymbols = append(cfg.LocalizeSymbols, names...)
	case "globalize-symbols":
		names, err := readSymbolList(arg)
		if err != nil {
			return err
		}
		*useGlobalize = true
		cfg.GlobalizeSymbols = append(cfg.GlobalizeSymbols, names...)
	case "keep-global-symbols":
		names, err := readSymbolList(arg)
		if err != nil {
			return err
		}
		*useKeepGlobal = true
		cfg.KeepGlobalSymbols = append(cfg.KeepGlobalSymbols, names...)
	case "weaken-symbols":
		names, err := readSymbolList(arg)
		if err != nil {
			return err
		}
		cfg.WeakenSymbols = append(cfg.WeakenSymbols, names...)

	case "redefine-sym":
		old, newName, err := splitPair(arg, "--redefine-sym")
		if err != nil {
			return err
		}
		cfg.Redefines = append(cfg.Redefines, objcopy.Redefine{Old: old, New: newName})
	case "redefine-syms":
		redefs, err := readRedefineFile(arg)
		if err != nil {
			return err
		}
		cfg.Redefines = append(cfg.Redefines, redefs...)

	case "add-gnu-debuglink":
		cfg.AddDebugLink = arg
	case "compress-debug-sections":
		// With no argument GNU uses the configure-time default, which is
		// "none" unless binutils was built with
		// --enable-compressed-debug-sections.  Match that: bare
		// --compress-debug-sections is a no-op.
		kind := ""
		if arg != "" {
			kind = strings.ToLower(arg)
		}
		switch kind {
		case "":
			cfg.CompressDebug = ""
			cfg.DecompressDebug = false
		case "none":
			// GNU maps "none" to decompression (objcopy.c:
			// do_debug_sections = decompress).
			cfg.CompressDebug = ""
			cfg.DecompressDebug = true
		case "zlib", "zlib-gnu", "zlib-gabi", "zstd":
			cfg.CompressDebug = kind
			cfg.DecompressDebug = false // last option wins
		default:
			return fmt.Errorf("unrecognized --compress-debug-sections type `%s'", arg)
		}
	case "decompress-debug-sections":
		cfg.DecompressDebug = true
		cfg.CompressDebug = "" // last option wins

	case "only-section":
		// GNU diagnoses a section that matches both a -j and a -R pattern as
		// a fatal error ("section X matches both remove and copy options").
		// The objcopy library instead keeps -j selection first and then
		// drops -R matches, so such a section is simply removed; this CLI
		// accepts that simplified behaviour rather than pre-scanning the
		// section table (the library owns the section list).
		cfg.OnlySections = append(cfg.OnlySections, arg)
	case "remove-section":
		cfg.RemoveSections = append(cfg.RemoveSections, arg)
	case "keep-section":
		cfg.KeepSections = append(cfg.KeepSections, arg)
	case "remove-relocations":
		cfg.RemoveRelocations = append(cfg.RemoveRelocations, arg)
	case "strip-section-headers":
		cfg.StripSectionHeaders = true

	case "rename-section":
		rename, err := parseRenameSection(arg)
		if err != nil {
			return err
		}
		cfg.Renames = append(cfg.Renames, rename)
	case "set-section-flags":
		name, flags, err := splitPair(arg, "--set-section-flags")
		if err != nil {
			return err
		}
		cfg.SetSectionFlags = append(cfg.SetSectionFlags, objcopy.SectionFlags{Name: name, Flags: flags})
	case "set-section-alignment":
		name, value, err := splitPair(arg, "--set-section-alignment")
		if err != nil {
			return err
		}
		align := parseCInt(value)
		if align <= 0 {
			return fmt.Errorf("bad format for --set-section-alignment: numeric argument needed")
		}
		if align&(align-1) != 0 {
			return fmt.Errorf("bad format for --set-section-alignment: alignment is not a power of two")
		}
		cfg.SetSectionAlignment = append(cfg.SetSectionAlignment, objcopy.SectionAlign{Name: name, Align: uint64(align)})
	case "add-section":
		name, file, err := splitPair(arg, "--add-section")
		if err != nil {
			return err
		}
		cfg.AddSections = append(cfg.AddSections, objcopy.AddSection{Name: name, File: file})
	case "update-section":
		name, file, err := splitPair(arg, "--update-section")
		if err != nil {
			return err
		}
		cfg.UpdateSections = append(cfg.UpdateSections, objcopy.UpdateSection{Name: name, File: file})
	case "dump-section":
		name, file, err := splitPair(arg, "--dump-section")
		if err != nil {
			return err
		}
		cfg.DumpSections = append(cfg.DumpSections, objcopy.DumpSection{Name: name, File: file})

	case "set-start":
		v, err := parseVMA(arg, "--set-start")
		if err != nil {
			return err
		}
		cfg.SetStart = &v
	case "change-start":
		v, err := parseDelta(arg, "--change-start")
		if err != nil {
			return err
		}
		cfg.ChangeStart = &v
	case "change-addresses":
		v, err := parseDelta(arg, "--change-addresses")
		if err != nil {
			return err
		}
		cfg.ChangeAddresses = &v
	case "change-section-address", "change-section-vma", "change-section-lma":
		option := "--" + action
		change, err := parseSectionAddr(arg, option)
		if err != nil {
			return err
		}
		switch action {
		case "change-section-address":
			cfg.ChangeSectionAddr = append(cfg.ChangeSectionAddr, change)
		case "change-section-vma":
			cfg.ChangeSectionVMA = append(cfg.ChangeSectionVMA, change)
		default:
			cfg.ChangeSectionLMA = append(cfg.ChangeSectionLMA, change)
		}
	case "pad-to":
		v, err := parseVMA(arg, "--pad-to")
		if err != nil {
			return err
		}
		cfg.PadTo = &v
	case "gap-fill":
		v, err := parseVMA(arg, "--gap-fill")
		if err != nil {
			return err
		}
		cfg.GapFill = &v

	case "interleave":
		n := 4 // GNU's default when --interleave has no =<number>
		if arg != "" {
			n = parseCInt(arg)
		}
		if n < 1 {
			return fmt.Errorf("interleave must be positive")
		}
		cfg.Interleave = n
	case "interleave-width":
		n := parseCInt(arg)
		if n < 1 {
			return fmt.Errorf("interleave width must be positive")
		}
		cfg.InterleaveWidth = n
	case "byte":
		n := parseCInt(arg)
		if n < 0 {
			return fmt.Errorf("byte number must be non-negative")
		}
		cfg.Byte = n
	case "elf-stt-common":
		v := strings.ToLower(arg)
		if v != "yes" && v != "no" {
			return fmt.Errorf("--elf-stt-common: unknown argument `%s'", arg)
		}
		cfg.ELFSTTCommon = v
	case "add-symbol":
		as, err := parseAddSymbol(arg)
		if err != nil {
			return err
		}
		cfg.AddSymbols = append(cfg.AddSymbols, as)
	case "reverse-bytes":
		n := parseCInt(arg)
		if n < 2 || n%2 != 0 {
			// GNU: "number of bytes to reverse must be positive and even".
			return fmt.Errorf("number of bytes to reverse must be positive and even")
		}
		cfg.ReverseBytes = n
	case "srec-len":
		n := parseCInt(arg)
		if n <= 0 {
			return fmt.Errorf("srec length must be positive")
		}
		cfg.SrecLen = n
	case "srec-forceS3":
		cfg.SrecForceS3 = true
	case "merge-notes":
		v := true
		cfg.MergeNotes = &v
	case "no-merge-notes":
		v := false
		cfg.MergeNotes = &v
	case "enable-deterministic-archives":
		v := true
		cfg.DeterministicArchives = &v
	case "disable-deterministic-archives":
		v := false
		cfg.DeterministicArchives = &v
	case "verilog-data-width":
		n := parseCInt(arg)
		switch n {
		case 1, 2, 4, 8, 16:
			cfg.VerilogDataWidth = n
		default:
			return fmt.Errorf("error: verilog data width must be 1, 2, 4, 8 or 16")
		}

	default:
		// Options that are parsed for GNU command-line compatibility but do
		// not change the output yet.  Everything objcopy.exp exercises is
		// implemented; what remains needs a PE/COFF backend or is rarely
		// used on ELF:
		//
		//   --extract-symbol, --prefix-symbols, --prefix-sections,
		//   --prefix-alloc-sections, --change-leading-char,
		//   --remove-leading-char, --add-leading-char, --alt-machine-code,
		//   --long-section-names, --file-alignment, --heap, --image-base,
		//   --section-alignment, --stack, --subsystem, --writable-text,
		//   --readonly-text, --pure, --impure.
		//   --debugging and the --change-warnings family only affect
		//   diagnostics in GNU.
	}
	return nil
}

// parseAddSymbol parses name=[section:]value[,flags] for --add-symbol.
func parseAddSymbol(arg string) (objcopy.AddSymbol, error) {
	var as objcopy.AddSymbol
	eq := strings.IndexByte(arg, '=')
	if eq <= 0 {
		return as, fmt.Errorf("bad format for %s", "--add-symbol")
	}
	as.Name = arg[:eq]
	rest := arg[eq+1:]
	valPart := rest
	flagPart := ""
	hasFlags := false
	if i := strings.IndexByte(rest, ','); i >= 0 {
		valPart = rest[:i]
		flagPart = rest[i+1:]
		hasFlags = true
	}
	if c := strings.IndexByte(valPart, ':'); c >= 0 {
		as.Section = valPart[:c]
		v, err := parseVMA(valPart[c+1:], "--add-symbol")
		if err != nil {
			return as, err
		}
		as.Value = v
	} else {
		v, err := parseVMA(valPart, "--add-symbol")
		if err != nil {
			return as, err
		}
		as.Value = v
	}
	as.Bind = elf.STB_GLOBAL
	if hasFlags {
		// A comma introduces an explicit (possibly empty) flag list. GNU's
		// parse_symflags rejects the empty list with "unrecognized symbol
		// flag", so "sym=1," is an error rather than a bare symbol.
		for _, f := range strings.Split(flagPart, ",") {
			lf := strings.ToLower(f)
			switch {
			case lf == "local":
				as.Bind = elf.STB_LOCAL
			case lf == "global" || lf == "export":
				as.Bind = elf.STB_GLOBAL
			case lf == "weak":
				as.Bind = elf.STB_WEAK
			case lf == "function" || lf == "indirect-function":
				as.Type = elf.STT_FUNC
			case lf == "object":
				as.Type = elf.STT_OBJECT
			case lf == "file":
				as.Bind = elf.STB_LOCAL
				as.Type = elf.STT_FILE
			case lf == "section":
				as.Bind = elf.STB_LOCAL
				as.Type = elf.STT_SECTION
			case lf == "unique-object":
				as.Bind = elf.STB_GNU_UNIQUE
				as.Type = elf.STT_OBJECT
			case strings.HasPrefix(lf, "before="):
				as.Before = f[len("before="):]
			default:
				return as, fmt.Errorf("unrecognized symbol flag `%s'", f)
			}
		}
	}
	return as, nil
}

// splitPair splits "name=value" at the first '='.
func splitPair(arg, option string) (string, string, error) {
	name, value, ok := strings.Cut(arg, "=")
	if !ok {
		return "", "", fmt.Errorf("bad format for %s", option)
	}
	return name, value, nil
}

// parseRenameSection parses old=new[,flags] into a Rename request.
func parseRenameSection(arg string) (objcopy.Rename, error) {
	old, rest, ok := strings.Cut(arg, "=")
	if !ok || old == "" {
		return objcopy.Rename{}, fmt.Errorf("bad format for --rename-section")
	}
	newName := rest
	var flags *string
	if i := strings.IndexByte(rest, ','); i >= 0 {
		newName = rest[:i]
		f := rest[i+1:]
		flags = &f
	}
	if newName == "" {
		return objcopy.Rename{}, fmt.Errorf("bad format for --rename-section")
	}
	return objcopy.Rename{Old: old, New: newName, Flags: flags}, nil
}

// parseSectionAddr parses name{=|+|-}value. GNU searches for '=' first, then
// '+', then '-' anywhere in the argument, which means a '-' inside a section
// name is treated as the operator when no '=' or '+' is present.
func parseSectionAddr(arg, option string) (objcopy.SectionAddr, error) {
	idx := strings.IndexByte(arg, '=')
	op := objcopy.AddrSet
	if idx < 0 {
		idx = strings.IndexByte(arg, '+')
		op = objcopy.AddrAdd
	}
	if idx < 0 {
		idx = strings.IndexByte(arg, '-')
		op = objcopy.AddrSub
	}
	if idx < 0 {
		return objcopy.SectionAddr{}, fmt.Errorf("bad format for %s", option)
	}
	value, err := parseVMA(arg[idx+1:], option)
	if err != nil {
		return objcopy.SectionAddr{}, err
	}
	return objcopy.SectionAddr{Name: arg[:idx], Op: op, Val: value}, nil
}

// parseVMA parses an unsigned number the way GNU's parse_vma does with
// strtoull(..., 0): base 0, so 0x prefixes, octal with a leading 0, and plain
// decimal all work.
func parseVMA(s, option string) (uint64, error) {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "+") {
		t = t[1:]
	}
	if t == "" {
		return 0, fmt.Errorf("%s: can't parse number: %s", option, s)
	}
	v, err := strconv.ParseUint(t, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: can't parse number: %s", option, s)
	}
	return v, nil
}

// parseDelta parses a signed adjustment for --change-start/--change-addresses.
func parseDelta(s, option string) (int64, error) {
	t := strings.TrimSpace(s)
	negative := false
	if strings.HasPrefix(t, "+") {
		t = t[1:]
	} else if strings.HasPrefix(t, "-") {
		negative = true
		t = t[1:]
	}
	if t == "" {
		return 0, fmt.Errorf("%s: can't parse number: %s", option, s)
	}
	v, err := strconv.ParseUint(t, 0, 63)
	if err != nil {
		return 0, fmt.Errorf("%s: can't parse number: %s", option, s)
	}
	if negative {
		return -int64(v), nil
	}
	return int64(v), nil
}

// parseCInt reproduces C's atoi: optional leading whitespace, optional sign,
// then decimal digits; anything after the digits is ignored.
func parseCInt(s string) int {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == '\f' || s[i] == '\v') {
		i++
	}
	sign := 1
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		if s[i] == '-' {
			sign = -1
		}
		i++
	}
	n := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		n = n*10 + int(s[i]-'0')
		i++
	}
	return sign * n
}

// readSymbolList reads a file for --strip-symbols and friends: one symbol name
// per line, '#' starts a comment, surrounding whitespace is ignored. Only the
// first whitespace-separated token of a line is used, matching GNU's
// add_specific_symbols (which warns about trailing rubbish but keeps the
// name).
func readSymbolList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open '%s': %v", path, err)
	}
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		names = append(names, fields[0])
	}
	return names, nil
}

// readRedefineFile reads an --redefine-syms file: one "old new" pair per line,
// with '#' comments. GNU treats a line with one name and no replacement, or
// with extra junk after the replacement, as a fatal error.
func readRedefineFile(path string) ([]objcopy.Redefine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("couldn't open symbol redefinition file %s (error: %v)", path, err)
	}
	var redefs []objcopy.Redefine
	for i, line := range strings.Split(string(data), "\n") {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 1 {
			return nil, fmt.Errorf("%s:%d: missing new symbol name", path, i+1)
		}
		if len(fields) > 2 {
			return nil, fmt.Errorf("%s:%d: garbage found at end of line", path, i+1)
		}
		redefs = append(redefs, objcopy.Redefine{Old: fields[0], New: fields[1]})
	}
	return redefs, nil
}
