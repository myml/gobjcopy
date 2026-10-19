package objcopy

// formatOptions bundles options for the less common output formats and for
// archive handling. It is embedded in Config so that these fields can be
// maintained without touching the main struct definition.
type formatOptions struct {
	// SrecLen is --srec-len; 0 means the BFD default.
	SrecLen int
	// SrecForceS3 is --srec-forceS3.
	SrecForceS3 bool
	// VerilogDataWidth is --verilog-data-width; 0 means the BFD default.
	VerilogDataWidth int
	// MergeNotes maps -M/--merge-notes (true) and --no-merge-notes (false).
	// nil keeps the default: merge notes unless debug info is stripped.
	MergeNotes *bool
	// DeterministicArchives maps -D (true) and -U (false); nil means the
	// binutils default, deterministic output.
	DeterministicArchives *bool
	// OutputName is the file name the output is written to. Formats that
	// embed a name (srec S0 records) use it; Run fills it in.
	OutputName string
}
