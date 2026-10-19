package getopt

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Indices into stdOptions, used to build expected Occurrence values. Because
// New keeps the caller's slice, &stdOptions[i] is the same pointer Parse
// reports.
const (
	optStripAll = iota
	optStripDebug
	optStripSymbol
	optSection
	optVerbose
	optOutputTarget
	optOptional
	optShortOnly
	optLongOnly
)

var stdOptions = []Option{
	{Long: "strip-all", Short: 'S', Arg: NoArg},
	{Long: "strip-debug", Short: 'g', Arg: NoArg},
	{Long: "strip-symbol", Short: 'N', Arg: RequiredArg},
	{Long: "section", Short: 'j', Arg: RequiredArg},
	{Long: "verbose", Short: 'v', Arg: NoArg},
	{Long: "output-target", Short: 'O', Arg: RequiredArg},
	{Long: "optional-arg", Short: 'p', Arg: OptionalArg},
	{Short: 'x', Arg: NoArg},         // short-only: never matches "--x"
	{Long: "long-only", Arg: NoArg},  // long-only
	{Long: "", Short: 0, Arg: NoArg}, // ignored entirely
}

// ambiguousOptions is the pair from the GNU getopt_long documentation excerpt
// in the task, used to check the exact ambiguity diagnostic.
var ambiguousOptions = []Option{
	{Long: "strip-all", Arg: NoArg},
	{Long: "strip-debug", Arg: NoArg},
}

// exactOptions checks that an exact long name wins over longer names sharing
// it as a prefix.
var exactOptions = []Option{
	{Long: "strip", Arg: NoArg},
	{Long: "strip-all", Arg: NoArg},
	{Long: "strip-debug", Arg: NoArg},
}

// duplicateOptions checks first-registration-wins behavior for duplicate short
// options and duplicate long names.
var duplicateOptions = []Option{
	{Long: "first", Short: 'a', Arg: NoArg},
	{Long: "second", Short: 'a', Arg: NoArg}, // duplicate short 'a': ignored
	{Long: "dup", Short: 'b', Arg: NoArg},
	{Long: "dup", Short: 'c', Arg: NoArg}, // duplicate long "dup": ignored
	{Short: 'x', Arg: NoArg},
	{Long: "long-only", Arg: NoArg},
}

func occAt(options []Option, index int, arg string) Occurrence {
	return Occurrence{Option: &options[index], Arg: arg}
}

func stdOcc(index int, arg string) Occurrence {
	return occAt(stdOptions, index, arg)
}

// parseCase is one row of the table-driven parser test.
type parseCase struct {
	name         string
	args         []string
	wantOpts     []Occurrence
	wantOperands []string
	wantErr      string    // exact GNU text, without the "program: " prefix
	wantKind     ErrorKind // checked when wantErr is non-empty
}

func TestParse(t *testing.T) {
	tests := []parseCase{
		// ---- Long options: exact and unique-prefix matching (requirement 1)
		{
			name:     "long exact",
			args:     []string{"--verbose"},
			wantOpts: []Occurrence{stdOcc(optVerbose, "")},
		},
		{
			name:     "long unique prefix",
			args:     []string{"--verb"},
			wantOpts: []Occurrence{stdOcc(optVerbose, "")},
		},
		{
			name:     "long prefix canonicalizes required arg attached",
			args:     []string{"--output-tar=tgt"},
			wantOpts: []Occurrence{stdOcc(optOutputTarget, "tgt")},
		},
		{
			name:     "long prefix canonicalizes required arg separate",
			args:     []string{"--output-tar", "tgt"},
			wantOpts: []Occurrence{stdOcc(optOutputTarget, "tgt")},
		},
		{
			name:     "long long-only option",
			args:     []string{"--long-only"},
			wantOpts: []Occurrence{stdOcc(optLongOnly, "")},
		},
		{
			name:     "long short-only entry is not a long option",
			args:     []string{"--x"},
			wantErr:  "unrecognized option '--x'",
			wantKind: ErrUnknownLongOption,
		},
		{
			name:     "long unknown",
			args:     []string{"--bogus"},
			wantErr:  "unrecognized option '--bogus'",
			wantKind: ErrUnknownLongOption,
		},
		{
			// GNU includes the "=value" part in the quoted token.
			name:     "long unknown with value",
			args:     []string{"--bogus=1"},
			wantErr:  "unrecognized option '--bogus=1'",
			wantKind: ErrUnknownLongOption,
		},
		{
			// A triple dash is a long option named "-verbose".
			name:     "long triple dash unknown",
			args:     []string{"---verbose"},
			wantErr:  "unrecognized option '---verbose'",
			wantKind: ErrUnknownLongOption,
		},
		{
			name:         "long unknown keeps earlier operands",
			args:         []string{"in", "--bogus"},
			wantOperands: []string{"in"},
			wantErr:      "unrecognized option '--bogus'",
			wantKind:     ErrUnknownLongOption,
		},
		{
			name:     "long unknown keeps earlier options",
			args:     []string{"-v", "--bogus"},
			wantOpts: []Occurrence{stdOcc(optVerbose, "")},
			wantErr:  "unrecognized option '--bogus'",
			wantKind: ErrUnknownLongOption,
		},

		// ---- Long options with arguments (requirements 2-4)
		{
			name:     "long required attached",
			args:     []string{"--section=.text"},
			wantOpts: []Occurrence{stdOcc(optSection, ".text")},
		},
		{
			name:     "long required separate",
			args:     []string{"--section", ".text"},
			wantOpts: []Occurrence{stdOcc(optSection, ".text")},
		},
		{
			name:     "long required empty attached value",
			args:     []string{"--section="},
			wantOpts: []Occurrence{stdOcc(optSection, "")},
		},
		{
			name:     "long required prefix empty attached value",
			args:     []string{"--output-tar="},
			wantOpts: []Occurrence{stdOcc(optOutputTarget, "")},
		},
		{
			name:         "long required consumes double dash",
			args:         []string{"--section", "--", "in"},
			wantOpts:     []Occurrence{stdOcc(optSection, "--")},
			wantOperands: []string{"in"},
		},
		{
			name:     "long required consumes option-looking word",
			args:     []string{"--section", "--verbose"},
			wantOpts: []Occurrence{stdOcc(optSection, "--verbose")},
		},
		{
			name:     "long noarg refuses attached value",
			args:     []string{"--verbose=1"},
			wantErr:  "option '--verbose' doesn't allow an argument",
			wantKind: ErrUnexpectedArgument,
		},
		{
			// The diagnostic uses the canonical name, not the abbreviation.
			name:     "long noarg refuses value via abbreviation",
			args:     []string{"--verb=1"},
			wantErr:  "option '--verbose' doesn't allow an argument",
			wantKind: ErrUnexpectedArgument,
		},
		{
			name:     "long ambiguity lists all candidates in registration order",
			args:     []string{"--strip-"},
			wantErr:  "option '--strip-' is ambiguous; possibilities: '--strip-all' '--strip-debug' '--strip-symbol'",
			wantKind: ErrAmbiguousLongOption,
		},
		{
			name:     "long required missing at end",
			args:     []string{"--output-target"},
			wantErr:  "option '--output-target' requires an argument",
			wantKind: ErrMissingLongArgument,
		},
		{
			name:     "long required missing uses canonical name",
			args:     []string{"--output-tar"},
			wantErr:  "option '--output-target' requires an argument",
			wantKind: ErrMissingLongArgument,
		},

		// ---- Optional long arguments (requirement 3)
		{
			name:     "long optional attached",
			args:     []string{"--optional-arg=val"},
			wantOpts: []Occurrence{stdOcc(optOptional, "val")},
		},
		{
			name:     "long optional empty attached",
			args:     []string{"--optional-arg="},
			wantOpts: []Occurrence{stdOcc(optOptional, "")},
		},
		{
			name:     "long optional absent",
			args:     []string{"--optional-arg"},
			wantOpts: []Occurrence{stdOcc(optOptional, "")},
		},
		{
			name:         "long optional does not consume separate word",
			args:         []string{"--optional-arg", "val"},
			wantOpts:     []Occurrence{stdOcc(optOptional, "")},
			wantOperands: []string{"val"},
		},
		{
			name:     "long optional via unique prefix",
			args:     []string{"--optional=val"},
			wantOpts: []Occurrence{stdOcc(optOptional, "val")},
		},

		// ---- Short options: aggregation and arguments (requirement 5)
		{
			name:     "short single",
			args:     []string{"-v"},
			wantOpts: []Occurrence{stdOcc(optVerbose, "")},
		},
		{
			name:     "short repeated in bundle",
			args:     []string{"-vv"},
			wantOpts: []Occurrence{stdOcc(optVerbose, ""), stdOcc(optVerbose, "")},
		},
		{
			name:     "short bundle",
			args:     []string{"-Sg"},
			wantOpts: []Occurrence{stdOcc(optStripAll, ""), stdOcc(optStripDebug, "")},
		},
		{
			name:     "short bundle with trailing required arg attached",
			args:     []string{"-Sj.text"},
			wantOpts: []Occurrence{stdOcc(optStripAll, ""), stdOcc(optSection, ".text")},
		},
		{
			name:     "short bundle with three options and arg",
			args:     []string{"-SgNfoo"},
			wantOpts: []Occurrence{stdOcc(optStripAll, ""), stdOcc(optStripDebug, ""), stdOcc(optStripSymbol, "foo")},
		},
		{
			name:     "short required attached",
			args:     []string{"-j.text"},
			wantOpts: []Occurrence{stdOcc(optSection, ".text")},
		},
		{
			name:     "short required separate",
			args:     []string{"-j", ".text"},
			wantOpts: []Occurrence{stdOcc(optSection, ".text")},
		},
		{
			// GNU treats everything after the option character as the value.
			name:     "short required attached equals sign",
			args:     []string{"-j=.text"},
			wantOpts: []Occurrence{stdOcc(optSection, "=.text")},
		},
		{
			name:     "short required empty separate value",
			args:     []string{"-j", ""},
			wantOpts: []Occurrence{stdOcc(optSection, "")},
		},
		{
			name:     "short required consumes option-looking word",
			args:     []string{"-j", "-v"},
			wantOpts: []Occurrence{stdOcc(optSection, "-v")},
		},
		{
			name:         "short required consumes double dash",
			args:         []string{"-j", "--", "foo"},
			wantOpts:     []Occurrence{stdOcc(optSection, "--")},
			wantOperands: []string{"foo"},
		},
		{
			name:     "short optional attached",
			args:     []string{"-pval"},
			wantOpts: []Occurrence{stdOcc(optOptional, "val")},
		},
		{
			name:     "short optional alone",
			args:     []string{"-p"},
			wantOpts: []Occurrence{stdOcc(optOptional, "")},
		},
		{
			name:         "short optional does not consume separate word",
			args:         []string{"-p", "val"},
			wantOpts:     []Occurrence{stdOcc(optOptional, "")},
			wantOperands: []string{"val"},
		},
		{
			name:     "short optional in bundle",
			args:     []string{"-Spfoo"},
			wantOpts: []Occurrence{stdOcc(optStripAll, ""), stdOcc(optOptional, "foo")},
		},
		{
			name:     "short optional before long option",
			args:     []string{"-p", "--verbose"},
			wantOpts: []Occurrence{stdOcc(optOptional, ""), stdOcc(optVerbose, "")},
		},
		{
			name:     "short-only option",
			args:     []string{"-x"},
			wantOpts: []Occurrence{stdOcc(optShortOnly, "")},
		},

		// ---- Short-option errors (requirement 8)
		{
			name:     "short unknown",
			args:     []string{"-Z"},
			wantErr:  "invalid option -- 'Z'",
			wantKind: ErrUnknownShortOption,
		},
		{
			name:     "short unknown mid-bundle keeps earlier options",
			args:     []string{"-SZ"},
			wantOpts: []Occurrence{stdOcc(optStripAll, "")},
			wantErr:  "invalid option -- 'Z'",
			wantKind: ErrUnknownShortOption,
		},
		{
			name:     "short required missing at end",
			args:     []string{"-j"},
			wantErr:  "option requires an argument -- 'j'",
			wantKind: ErrMissingShortArgument,
		},
		{
			name:     "short required missing at end of bundle",
			args:     []string{"-Sj"},
			wantOpts: []Occurrence{stdOcc(optStripAll, "")},
			wantErr:  "option requires an argument -- 'j'",
			wantKind: ErrMissingShortArgument,
		},

		// ---- "--" and lone "-" (requirement 6)
		{
			name:         "double dash terminates options",
			args:         []string{"-v", "--", "-S", "--verbose"},
			wantOpts:     []Occurrence{stdOcc(optVerbose, "")},
			wantOperands: []string{"-S", "--verbose"},
		},
		{
			name:         "double dash first",
			args:         []string{"--", "-v"},
			wantOperands: []string{"-v"},
		},
		{
			name: "double dash only",
			args: []string{"--"},
		},
		{
			name:         "lone dash is operand",
			args:         []string{"-", "-v"},
			wantOpts:     []Occurrence{stdOcc(optVerbose, "")},
			wantOperands: []string{"-"},
		},
		{
			name:         "lone dash kept in operand order",
			args:         []string{"in", "-", "out"},
			wantOperands: []string{"in", "-", "out"},
		},
		{
			name:         "lone dash before terminator",
			args:         []string{"-", "--", "-v"},
			wantOperands: []string{"-", "-v"},
		},

		// ---- Permutation (requirement 7)
		{
			name:         "operands between options are permuted",
			args:         []string{"in", "-v", "out", "-S"},
			wantOpts:     []Occurrence{stdOcc(optVerbose, ""), stdOcc(optStripAll, "")},
			wantOperands: []string{"in", "out"},
		},
		{
			name:         "operand order is preserved",
			args:         []string{"a", "-v", "b", "c", "-g", "d"},
			wantOpts:     []Occurrence{stdOcc(optVerbose, ""), stdOcc(optStripDebug, "")},
			wantOperands: []string{"a", "b", "c", "d"},
		},
		{
			name:         "options before operands",
			args:         []string{"-v", "in", "out"},
			wantOpts:     []Occurrence{stdOcc(optVerbose, "")},
			wantOperands: []string{"in", "out"},
		},
		{
			name:         "operands only",
			args:         []string{"in", "out"},
			wantOperands: []string{"in", "out"},
		},
		{
			name: "empty command line",
			args: []string{},
		},

		// ---- Repeated options (requirement 9)
		{
			name: "repeated noarg options keep order",
			args: []string{"-v", "--verbose", "-vv"},
			wantOpts: []Occurrence{
				stdOcc(optVerbose, ""),
				stdOcc(optVerbose, ""),
				stdOcc(optVerbose, ""),
				stdOcc(optVerbose, ""),
			},
		},
		{
			name: "repeated options with args keep order",
			args: []string{"-j.a", "--section=.b", "-j", ".c"},
			wantOpts: []Occurrence{
				stdOcc(optSection, ".a"),
				stdOcc(optSection, ".b"),
				stdOcc(optSection, ".c"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkParse(t, stdOptions, tc.args, tc.wantOpts, tc.wantOperands, tc.wantErr, tc.wantKind)
		})
	}
}

func checkParse(t *testing.T, options []Option, args []string, wantOpts []Occurrence, wantOperands []string, wantErr string, wantKind ErrorKind) {
	t.Helper()

	gotOpts, gotOperands, err := New(options).Parse(args)

	if !slices.Equal(gotOpts, wantOpts) {
		t.Errorf("options = %s, want %s", formatOccs(gotOpts), formatOccs(wantOpts))
	}
	if !slices.Equal(gotOperands, wantOperands) {
		t.Errorf("operands = %q, want %q", gotOperands, wantOperands)
	}

	if wantErr == "" {
		if err != nil {
			t.Fatalf("Parse() error = %v, want nil", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("Parse() error = nil, want %q", wantErr)
	}
	if got := err.Error(); got != wantErr {
		t.Errorf("error text = %q, want %q", got, wantErr)
	}
	var parseErr *Error
	if !errors.As(err, &parseErr) {
		t.Fatalf("error type = %T, want *getopt.Error", err)
	}
	if parseErr.Kind != wantKind {
		t.Errorf("Error.Kind = %d, want %d", parseErr.Kind, wantKind)
	}
	if parseErr.Msg != wantErr {
		t.Errorf("Error.Msg = %q, want %q", parseErr.Msg, wantErr)
	}
}

func formatOccs(occs []Occurrence) string {
	parts := make([]string, len(occs))
	for i, occ := range occs {
		name := "<nil>"
		if occ.Option != nil {
			if occ.Option.Long != "" {
				name = "--" + occ.Option.Long
			} else {
				name = "-" + string(occ.Option.Short)
			}
		}
		parts[i] = fmt.Sprintf("%s=%q", name, occ.Arg)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func TestAmbiguousLongOption(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    []Occurrence
		wantErr string
		kind    ErrorKind
	}{
		{
			// Exact text required by the task.
			name:    "full ambiguity",
			args:    []string{"--strip-"},
			wantErr: "option '--strip-' is ambiguous; possibilities: '--strip-all' '--strip-debug'",
			kind:    ErrAmbiguousLongOption,
		},
		{
			name:    "abbreviation ambiguity",
			args:    []string{"--strip"},
			wantErr: "option '--strip' is ambiguous; possibilities: '--strip-all' '--strip-debug'",
			kind:    ErrAmbiguousLongOption,
		},
		{
			// GNU quotes the whole original word, including "=value".
			name:    "ambiguity with attached value",
			args:    []string{"--strip-=x"},
			wantErr: "option '--strip-=x' is ambiguous; possibilities: '--strip-all' '--strip-debug'",
			kind:    ErrAmbiguousLongOption,
		},
		{
			// An empty long name is a prefix of every long option.
			name:    "empty name is prefix of all",
			args:    []string{"--=x"},
			wantErr: "option '--=x' is ambiguous; possibilities: '--strip-all' '--strip-debug'",
			kind:    ErrAmbiguousLongOption,
		},
		{
			name: "unambiguous prefix strips all",
			args: []string{"--strip-a"},
			want: []Occurrence{occAt(ambiguousOptions, 0, "")},
		},
		{
			name: "unambiguous prefix strips debug",
			args: []string{"--strip-d"},
			want: []Occurrence{occAt(ambiguousOptions, 1, "")},
		},
		{
			name:    "no match",
			args:    []string{"--strip-zzz"},
			wantErr: "unrecognized option '--strip-zzz'",
			kind:    ErrUnknownLongOption,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkParse(t, ambiguousOptions, tc.args, tc.want, nil, tc.wantErr, tc.kind)
		})
	}
}

func TestExactMatchBeatsPrefix(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    []Occurrence
		wantErr string
		kind    ErrorKind
	}{
		{
			name: "exact wins",
			args: []string{"--strip"},
			want: []Occurrence{occAt(exactOptions, 0, "")},
		},
		{
			name: "prefix of strip-all",
			args: []string{"--strip-a"},
			want: []Occurrence{occAt(exactOptions, 1, "")},
		},
		{
			name: "prefix of strip-debug",
			args: []string{"--strip-d"},
			want: []Occurrence{occAt(exactOptions, 2, "")},
		},
		{
			name:    "exact noarg refuses value",
			args:    []string{"--strip=x"},
			wantErr: "option '--strip' doesn't allow an argument",
			kind:    ErrUnexpectedArgument,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkParse(t, exactOptions, tc.args, tc.want, nil, tc.wantErr, tc.kind)
		})
	}
}

func TestDuplicateRegistration(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    []Occurrence
		wantErr string
		kind    ErrorKind
	}{
		{
			name: "duplicate short keeps first",
			args: []string{"-a"},
			want: []Occurrence{occAt(duplicateOptions, 0, "")},
		},
		{
			name: "long names still reachable",
			args: []string{"--first", "--second"},
			want: []Occurrence{occAt(duplicateOptions, 0, ""), occAt(duplicateOptions, 1, "")},
		},
		{
			name: "duplicate long keeps first",
			args: []string{"--dup"},
			want: []Occurrence{occAt(duplicateOptions, 2, "")},
		},
		{
			name: "duplicate long first short still works",
			args: []string{"-b"},
			want: []Occurrence{occAt(duplicateOptions, 2, "")},
		},
		{
			name: "duplicate long later short still works",
			args: []string{"-c"},
			want: []Occurrence{occAt(duplicateOptions, 3, "")},
		},
		{
			name: "ignored empty entry",
			args: []string{"-"},
			want: nil,
		},
		{
			name:    "empty long never matches",
			args:    []string{"--"},
			want:    nil,
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var wantOperands []string
			if tc.name == "ignored empty entry" {
				wantOperands = []string{"-"}
			}
			checkParse(t, duplicateOptions, tc.args, tc.want, wantOperands, tc.wantErr, tc.kind)
		})
	}
}

func TestParserReuse(t *testing.T) {
	p := New(stdOptions)

	first, operands, err := p.Parse([]string{"-v", "a"})
	if err != nil {
		t.Fatalf("first Parse() error = %v", err)
	}
	if !slices.Equal(first, []Occurrence{stdOcc(optVerbose, "")}) {
		t.Fatalf("first Parse() options = %s", formatOccs(first))
	}
	if !slices.Equal(operands, []string{"a"}) {
		t.Fatalf("first Parse() operands = %q", operands)
	}

	second, operands, err := p.Parse([]string{"--", "-v"})
	if err != nil {
		t.Fatalf("second Parse() error = %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("second Parse() options = %s, want none", formatOccs(second))
	}
	if !slices.Equal(operands, []string{"-v"}) {
		t.Fatalf("second Parse() operands = %q, want [-v]", operands)
	}
}

// TestGNUErrorTexts pins the handful of diagnostics that GNU objcopy emits in
// practice (checked against glibc getopt_long and GNU objcopy).
func TestGNUErrorTexts(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"unknown long", []string{"--bogus"}, "unrecognized option '--bogus'"},
		{"unknown short", []string{"-Z"}, "invalid option -- 'Z'"},
		{"noarg with value", []string{"--verbose=1"}, "option '--verbose' doesn't allow an argument"},
		{"missing long arg", []string{"--output-target"}, "option '--output-target' requires an argument"},
		{"missing short arg", []string{"-j"}, "option requires an argument -- 'j'"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := New(stdOptions).Parse(tc.args)
			if err == nil {
				t.Fatalf("Parse() error = nil, want %q", tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("Parse() error = %q, want %q", err, tc.wantErr)
			}
			var parseErr *Error
			if !errors.As(err, &parseErr) {
				t.Fatalf("error type = %T, want *getopt.Error", err)
			}
		})
	}
}
