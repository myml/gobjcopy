// Package objcopy implements GNU objcopy compatible binary transformations on
// top of the elf package.
package objcopy

import (
	"fmt"
	"strings"

	"github.com/myml/gobjcopy/elf"
)

// Rename is a --rename-section request: old=new[,flags].
type Rename struct {
	Old   string
	New   string
	Flags *string // optional replacement flag list
}

// SectionFlags is a --set-section-flags request.
type SectionFlags struct {
	Name  string
	Flags string
}

// SectionAlign is a --set-section-alignment request.
type SectionAlign struct {
	Name  string
	Align uint64
}

// AddSection is a --add-section request.
type AddSection struct {
	Name string
	File string
}

// UpdateSection is an --update-section request.
type UpdateSection struct {
	Name string
	File string
}

// DumpSection is a --dump-section request.
type DumpSection struct {
	Name string
	File string
}

// RemoveRelocs is a --remove-relocations request.
type RemoveRelocs struct {
	Name     string
	KeepOnly bool // --keep-relocations? reserved
}

// AddrOp is one of '=', '+', '-'.
type AddrOp byte

const (
	AddrSet AddrOp = '='
	AddrAdd AddrOp = '+'
	AddrSub AddrOp = '-'
)

// SectionAddr is a --change-section-{vma,lma,address} request.
type SectionAddr struct {
	Name string
	Op   AddrOp
	Val  uint64
}

// Redefine is a --redefine-sym request.
type Redefine struct {
	Old string
	New string
}

// AddSymbol is a --add-symbol request: name=[section:]value[,flags].
type AddSymbol struct {
	Name    string
	Section string // empty means an absolute symbol
	Value   uint64
	Bind    byte   // STB_* binding; BSF_NO_FLAGS (local) is the GNU default
	Type    byte   // STT_* type
	Before  string // before=<symbol>: insert in front of that symbol
}

// Config mirrors the GNU objcopy command line.
type Config struct {
	// Formats.
	InputTarget  string // -I
	OutputTarget string // -O
	Target       string // -F
	BinaryArch   string // -B

	// General.
	PreserveDates bool // -p
	Verbose       bool // -v
	Quiet         bool

	// Symbol stripping.
	StripAll      bool // -S / --strip-all
	StripDebug    bool // -g / --strip-debug
	StripDWO      bool // --strip-dwo
	StripUnneeded bool // --strip-unneeded
	DiscardAll    bool // -x / --discard-all
	DiscardLocals bool // -X / --discard-locals

	StripSymbols         []string // -N
	StripUnneededSymbols []string // --strip-unneeded-symbol
	KeepSymbols          []string // -K
	KeepGlobalSymbols    []string // -G
	LocalizeSymbols      []string // -L
	GlobalizeSymbols     []string // --globalize-symbol
	WeakenSymbols        []string // -W
	WeakenAll            bool     // --weaken
	Redefines            []Redefine
	Wildcard             bool // -w
	KeepFileSymbols      bool
	KeepSectionSymbols   bool
	LocalizeHidden       bool

	// Debug handling.
	OnlyKeepDebug   bool   // --only-keep-debug
	ExtractDWO      bool   // --extract-dwo
	StripDWOOnly    bool   // alias of StripDWO
	AddDebugLink    string // --add-gnu-debuglink
	CompressDebug   string // --compress-debug-sections=...
	DecompressDebug bool   // --decompress-debug-sections

	// Sections.
	OnlySections        []string // -j
	RemoveSections      []string // -R
	KeepSections        []string // --keep-section
	Renames             []Rename
	SetSectionFlags     []SectionFlags
	SetSectionAlignment []SectionAlign
	AddSections         []AddSection
	UpdateSections      []UpdateSection
	DumpSections        []DumpSection
	RemoveRelocations   []string
	StripSectionHeaders bool

	// Addresses and layout.
	SetStart             *uint64
	ChangeStart          *int64
	ChangeAddresses      *int64
	ChangeSectionAddr    []SectionAddr
	ChangeSectionVMA     []SectionAddr
	ChangeSectionLMA     []SectionAddr
	PadTo                *uint64
	GapFill              *uint64
	Interleave           int
	InterleaveWidth      int
	Byte                 int            // start byte for --interleave; -1 means unset
	SetSectionAlignments []SectionAlign // alias
	ReverseBytes         int            // --reverse-bytes; 0 means unset

	// Symbol creation and ELF common symbol handling.
	AddSymbols []AddSymbol
	// ELFSTTCommon is --elf-stt-common: "" (unchanged), "yes" or "no".
	ELFSTTCommon string

	// Format-specific and archive options (see options_format.go).
	formatOptions

	// Warnf receives non-fatal diagnostics. nil discards them.
	Warnf func(format string, args ...any)
	// Infof receives verbose progress messages.
	Infof func(format string, args ...any)
}

// Default returns a Config with GNU defaults.
func Default() *Config {
	return &Config{InterleaveWidth: 1, Byte: -1}
}

// Validate checks option combinations the same way GNU objcopy does.
func (c *Config) Validate() error {
	if c.Target != "" {
		c.InputTarget = c.Target
		c.OutputTarget = c.Target
	}
	if c.OnlyKeepDebug && c.StripAll {
		// GNU allows the combination; --only-keep-debug wins.
	}
	if c.AddDebugLink != "" && c.OutputTarget == "binary" {
		return fmt.Errorf("--add-gnu-debuglink is not supported for binary output")
	}
	if c.Interleave > 0 {
		if c.Byte < 0 {
			return fmt.Errorf("interleave start byte must be set with --byte")
		}
		if c.Byte >= c.Interleave {
			return fmt.Errorf("byte number must be less than interleave")
		}
		if c.InterleaveWidth > c.Interleave-c.Byte {
			return fmt.Errorf("interleave width must be less than or equal to interleave - byte")
		}
	}
	for _, r := range c.Renames {
		if r.New == "" {
			return fmt.Errorf("bad format for --rename-section: %s", r.Old)
		}
	}
	return nil
}

// sectionFlagNames maps GNU --set-section-flags words to ELF flags.
var sectionFlagNames = map[string]uint64{
	"alloc":      elf.SHF_ALLOC,
	"load":       elf.SHF_ALLOC,
	"noload":     0, // clears SHF_ALLOC, handled specially
	"readonly":   0, // clears SHF_WRITE, handled specially
	"code":       elf.SHF_EXECINSTR,
	"data":       0,
	"rom":        0,
	"exclude":    elf.SHF_EXCLUDE,
	"share":      0,
	"debug":      0,
	"contents":   0,
	"merge":      elf.SHF_MERGE,
	"strings":    elf.SHF_STRINGS,
	"info_link":  elf.SHF_INFO_LINK,
	"link_order": elf.SHF_LINK_ORDER,
	"group":      elf.SHF_GROUP,
	"tls":        elf.SHF_TLS,
	"compressed": elf.SHF_COMPRESSED,
	"large":      elf.SHF_X86_64_LARGE,
	"norelro":    0,
	"notls":      0,
}

// ParseSectionFlags interprets a --set-section-flags flag list. Following
// BFD, a section is writable unless "readonly" is given.
func ParseSectionFlags(s string) (flags uint64, hasContents bool, err error) {
	flags = elf.SHF_WRITE
	readonly := false
	for _, tok := range strings.Split(s, ",") {
		if tok == "" {
			continue
		}
		switch tok {
		case "readonly":
			readonly = true
		case "contents":
			hasContents = true
		case "noload":
			flags &^= elf.SHF_ALLOC
		case "data", "rom", "share", "debug", "norelro", "notls":
			// No ELF section flag corresponds to these BFD flags.
		case "large":
			flags |= elf.SHF_X86_64_LARGE
		default:
			v, ok := sectionFlagNames[tok]
			if !ok {
				return 0, false, fmt.Errorf("unrecognized section flag %q", tok)
			}
			flags |= v
		}
	}
	if readonly {
		flags &^= elf.SHF_WRITE
	}
	return flags, hasContents, nil
}
