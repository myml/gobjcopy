// Package getopt implements command-line parsing compatible with GNU
// getopt_long.
//
// The parser supports argument permutation (options and operands may be
// interleaved), long-option abbreviations, required and optional arguments,
// short-option bundling, and the GNU "--" end-of-options marker. Diagnostics
// deliberately match GNU getopt_long's wording; the program name and the
// "program: " prefix are omitted so that a CLI targeting GNU compatibility can
// print them itself, for example:
//
//	objcopy: unrecognized option '--bogus'
//
// Parse never writes to stdout or stderr.
package getopt

import (
	"fmt"
	"strings"
)

// ArgMode describes whether an Option takes an argument and, if so, how.
type ArgMode int

const (
	// NoArg means the option does not accept an argument. Supplying one with
	// the "--opt=value" form is an error.
	NoArg ArgMode = iota
	// RequiredArg means the option requires an argument. Both "--opt=value"
	// and "--opt value" are accepted for long options; short options accept
	// "-ovalue" and "-o value".
	RequiredArg
	// OptionalArg means the option accepts an argument only in the attached
	// form ("--opt=value" or "-ovalue"). A separate word is never consumed.
	OptionalArg
)

// Option describes one command-line option.
//
// Long is the long name without the leading "--"; an empty Long means the
// option has no long form. Short is the option character without the leading
// "-"; a zero Short means the option has no short form. Either or both may be
// set.
type Option struct {
	Long  string
	Short rune
	Arg   ArgMode
}

// Occurrence is one option occurrence on the command line, recorded in
// command-line order.
type Occurrence struct {
	// Option points at the element of the slice passed to New that describes
	// this option. Callers may therefore compare it against &options[i].
	Option *Option
	// Arg is the actual argument value for RequiredArg and OptionalArg, and
	// is empty for NoArg or when an OptionalArg option was given without a
	// value.
	Arg string
}

// longOption is one entry of the long-option lookup table, in registration
// order.
type longOption struct {
	name  string
	index int // index into Parser.options
}

// Parser parses a command line according to a fixed option table. A Parser
// keeps no per-parse state and may be reused for multiple Parse calls.
type Parser struct {
	// options is the caller's option table, kept by reference so that
	// Occurrence.Option can point at the caller's entries. The caller must
	// not modify the slice or its elements while the Parser is in use.
	options []Option

	longs  []longOption
	shorts map[rune]int
}

// New returns a Parser for options.
//
// Registration rules:
//   - An Option with an empty Long never takes part in long-option matching;
//     one with a zero Short never takes part in short-option matching.
//   - If several entries register the same short option, the first one wins.
//   - If several entries register the same long name, the first one wins too.
//     (GNU getopt_long would also choose the first exact match; skipping
//     later duplicates keeps the ambiguity list free of duplicate names.)
func New(options []Option) *Parser {
	p := &Parser{
		options: options,
		shorts:  make(map[rune]int),
	}
	for i := range options {
		o := &options[i]
		if o.Long != "" && !p.hasLong(o.Long) {
			p.longs = append(p.longs, longOption{name: o.Long, index: i})
		}
		if o.Short != 0 {
			if _, ok := p.shorts[o.Short]; !ok {
				p.shorts[o.Short] = i
			}
		}
	}
	return p
}

// hasLong reports whether name is already registered.
func (p *Parser) hasLong(name string) bool {
	for _, lo := range p.longs {
		if lo.name == name {
			return true
		}
	}
	return false
}

// Parse parses args, which must not include the program name.
//
// It returns the options in command-line order and the non-option operands in
// their original order. Options and operands may be interleaved (GNU's default
// permutation behavior); a lone "-" is an operand, and everything after "--"
// is an operand.
//
// Parse stops at the first malformed option and returns the occurrences and
// operands recognized before that point together with an *Error whose text
// matches GNU getopt_long's diagnostic (without the "program: " prefix).
func (p *Parser) Parse(args []string) (opts []Occurrence, operands []string, err error) {
	terminated := false
	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch {
		case terminated:
			operands = append(operands, arg)

		case arg == "--":
			terminated = true

		case strings.HasPrefix(arg, "--"):
			occ, consumedNext, err := p.parseLong(arg, args, i)
			if err != nil {
				return opts, operands, err
			}
			opts = append(opts, occ)
			if consumedNext {
				i++
			}

		case len(arg) > 1 && arg[0] == '-':
			occs, consumedNext, err := p.parseShort(arg[1:], args, i)
			// Occurrences recognized inside the cluster before the failing
			// character are still reported; GNU getopt similarly returns the
			// earlier options of a bundle before reporting the error.
			opts = append(opts, occs...)
			if err != nil {
				return opts, operands, err
			}
			if consumedNext {
				i++
			}

		default:
			operands = append(operands, arg)
		}
	}
	return opts, operands, nil
}

// parseLong parses one long-option token. It reports whether the option's
// required argument was taken from the following element of args.
func (p *Parser) parseLong(token string, args []string, i int) (Occurrence, bool, error) {
	name, value, hasValue := strings.Cut(token[2:], "=")
	entry, found, matches := p.matchLong(name)
	if !found {
		if len(matches) > 1 {
			return Occurrence{}, false, ambiguousError(token, matches)
		}
		// GNU reports the whole original token, including any "=value".
		return Occurrence{}, false, newError(ErrUnknownLongOption, "unrecognized option '%s'", token)
	}

	option := &p.options[entry.index]
	occ := Occurrence{Option: option}
	switch option.Arg {
	case RequiredArg:
		if hasValue {
			occ.Arg = value
			return occ, false, nil
		}
		if i+1 >= len(args) {
			// GNU names the canonical long option, not the abbreviation used.
			return Occurrence{}, false, newError(ErrMissingLongArgument, "option '--%s' requires an argument", entry.name)
		}
		// The following word is consumed even if it looks like an option or is
		// "--"; GNU getopt_long does the same.
		occ.Arg = args[i+1]
		return occ, true, nil

	case OptionalArg:
		if hasValue {
			occ.Arg = value
		}
		// "--opt value" never consumes value; only "--opt=value" does.
		return occ, false, nil

	default: // NoArg, plus any unrecognized mode treated as NoArg.
		if hasValue {
			return Occurrence{}, false, newError(ErrUnexpectedArgument, "option '--%s' doesn't allow an argument", entry.name)
		}
		return occ, false, nil
	}
}

// parseShort parses a short-option cluster (the text after the leading "-").
// It reports whether the final option's required argument was taken from the
// following element of args.
func (p *Parser) parseShort(cluster string, args []string, i int) ([]Occurrence, bool, error) {
	runes := []rune(cluster)
	var occs []Occurrence

	for pos := 0; pos < len(runes); pos++ {
		c := runes[pos]
		index, ok := p.shorts[c]
		if !ok {
			return occs, false, newError(ErrUnknownShortOption, "invalid option -- '%c'", c)
		}

		option := &p.options[index]
		occ := Occurrence{Option: option}
		rest := string(runes[pos+1:])

		switch option.Arg {
		case RequiredArg:
			if rest != "" {
				// "-j.text": the remainder of the cluster is the argument.
				occ.Arg = rest
				return append(occs, occ), false, nil
			}
			if i+1 >= len(args) {
				return occs, false, newError(ErrMissingShortArgument, "option requires an argument -- '%c'", c)
			}
			// "-j .text": the next word is consumed unconditionally.
			occ.Arg = args[i+1]
			return append(occs, occ), true, nil

		case OptionalArg:
			// "-pval" attaches val; "-p val" and "-p" carry no value.
			occ.Arg = rest
			return append(occs, occ), false, nil

		default: // NoArg, plus any unrecognized mode treated as NoArg.
			occs = append(occs, occ)
		}
	}
	return occs, false, nil
}

// matchLong finds the long option for name. Exact matches win over prefixes.
// If found is false, matches holds the candidate prefix matches: zero means
// "no such option" and more than one means "ambiguous".
//
// An empty name (from a token such as "--=x") is a prefix of every long
// option, matching GNU's behavior.
func (p *Parser) matchLong(name string) (entry longOption, found bool, matches []longOption) {
	for _, lo := range p.longs {
		if lo.name == name {
			return lo, true, nil
		}
	}
	for _, lo := range p.longs {
		if strings.HasPrefix(lo.name, name) {
			matches = append(matches, lo)
		}
	}
	if len(matches) == 1 {
		return matches[0], true, nil
	}
	return longOption{}, false, matches
}

// ErrorKind classifies an *Error returned by Parse.
type ErrorKind int

const (
	// ErrUnknownLongOption is an unrecognized "--name" (or "--name=value").
	ErrUnknownLongOption ErrorKind = iota
	// ErrAmbiguousLongOption is a long-option abbreviation matching several
	// registered options.
	ErrAmbiguousLongOption
	// ErrUnexpectedArgument is a value supplied to a NoArg long option.
	ErrUnexpectedArgument
	// ErrMissingLongArgument is a RequiredArg long option at end of input.
	ErrMissingLongArgument
	// ErrUnknownShortOption is an unregistered short option character.
	ErrUnknownShortOption
	// ErrMissingShortArgument is a RequiredArg short option at end of input.
	ErrMissingShortArgument
)

// Error is a command-line syntax error. Its text matches GNU getopt_long's
// diagnostic with the leading "program: " prefix removed.
type Error struct {
	Kind ErrorKind
	Msg  string
}

// Error implements the error interface.
func (e *Error) Error() string { return e.Msg }

// newError builds an *Error with a formatted GNU-style message.
func newError(kind ErrorKind, format string, a ...any) *Error {
	return &Error{Kind: kind, Msg: fmt.Sprintf(format, a...)}
}

// ambiguousError builds the GNU ambiguity diagnostic. token is the original
// command-line word (including any "=value"); matches are listed in
// registration order.
func ambiguousError(token string, matches []longOption) *Error {
	var b strings.Builder
	fmt.Fprintf(&b, "option '%s' is ambiguous; possibilities:", token)
	for _, m := range matches {
		fmt.Fprintf(&b, " '--%s'", m.name)
	}
	return &Error{Kind: ErrAmbiguousLongOption, Msg: b.String()}
}
