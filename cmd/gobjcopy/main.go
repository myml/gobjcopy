// Command gobjcopy is a GNU objcopy compatible command-line interface built on
// the github.com/myml/gobjcopy/objcopy package.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/myml/gobjcopy/internal/bfdtarget"
	"github.com/myml/gobjcopy/internal/getopt"
	"github.com/myml/gobjcopy/objcopy"
)

// programName is used as the diagnostic prefix, mirroring GNU's program_name.
const programName = "gobjcopy"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one gobjcopy invocation and returns the process exit status.
// It is separate from main so that tests can drive it with in-memory streams.
func run(args []string, stdout, stderr io.Writer) int {
	pa, err := parseCommandLine(args)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", programName, err)
		// GNU's getopt failure path falls through to copy_usage(stderr, 1);
		// fatal option errors print only the diagnostic.
		var getoptErr *getopt.Error
		if errors.As(err, &getoptErr) {
			printUsage(stderr)
		}
		return 1
	}

	// GNU checks --info before --version, and -h/--help has already exited
	// during option parsing.
	if pa.help {
		printHelp(stdout)
		return 0
	}
	if pa.info {
		fmt.Fprint(stdout, bfdtarget.Info())
		return 0
	}
	if pa.version {
		printVersion(stdout)
		return 0
	}

	if len(pa.operands) == 0 || len(pa.operands) > 2 {
		printUsage(stderr)
		return 1
	}

	inPath := pa.operands[0]
	outPath := ""
	if len(pa.operands) == 2 {
		outPath = pa.operands[1]
	}

	// Non-fatal diagnostics are printed but do not change the exit status,
	// matching observed GNU objcopy 2.44 behaviour: non_fatal() warnings such
	// as a missing --set-section-flags/--change-section-address target, an
	// unmatched -R, or an unmatched -N leave the exit status at 0. Only a
	// failed Run (including a fatal *objcopy.FatalError) or a command-line
	// error exits non-zero. Verbose progress goes to stdout, like GNU -v.
	cfg := pa.cfg
	cfg.Warnf = func(format string, a ...any) {
		fmt.Fprintf(stderr, "%s: %s\n", programName, fmt.Sprintf(format, a...))
	}
	cfg.Infof = func(format string, a ...any) {
		if cfg.Verbose {
			fmt.Fprintf(stdout, "%s: %s\n", programName, fmt.Sprintf(format, a...))
		}
	}

	if err := objcopy.Run(cfg, inPath, outPath); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", programName, err)
		return 1
	}
	return 0
}
