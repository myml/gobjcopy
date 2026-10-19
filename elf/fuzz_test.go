package elf_test

import (
	"os"
	"sort"
	"testing"

	"github.com/myml/gobjcopy/elf"
)

type fuzzSeed struct {
	name string
	data []byte
}

// seedCorpus returns /bin/true plus every built fixture. Missing inputs are
// silently ignored so the fuzz target still works on a bare host.
func seedCorpus() []fuzzSeed {
	var seeds []fuzzSeed
	if b, err := os.ReadFile("/bin/true"); err == nil {
		seeds = append(seeds, fuzzSeed{name: "bin-true", data: b})
	}
	names := make([]string, 0, len(fixtureMap))
	for name := range fixtureMap {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b, err := os.ReadFile(fixtureMap[name])
		if err != nil {
			continue
		}
		seeds = append(seeds, fuzzSeed{name: name, data: b})
	}
	return seeds
}

// checkParse is the shared seed/fuzz body: Parse must never panic, and a
// successfully parsed input must survive Bytes and a second Parse (the second
// Parse is allowed to fail).
func checkParse(t *testing.T, data []byte) {
	t.Helper()
	f, err := elf.Parse(data)
	if err != nil {
		return
	}
	out, err := f.Bytes()
	if err != nil {
		return
	}
	if _, err := elf.Parse(out); err != nil {
		t.Logf("reparse of serialised output failed (allowed): %v", err)
	}
}

// FuzzParse seeds the fuzzer with /bin/true and the fixture corpus. Run it
// with, for example:
//
//	go test ./elf -run '^$' -fuzz=FuzzParse -fuzztime=1x
//	go test ./elf -run '^$' -fuzz=FuzzParse -fuzztime=30s
func FuzzParse(f *testing.F) {
	for _, seed := range seedCorpus() {
		f.Add(seed.data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		checkParse(t, data)
	})
}

// TestFuzzSeeds is the regular `go test` entry point for the fuzz corpus: it
// replays every seed without starting the mutation engine.
func TestFuzzSeeds(t *testing.T) {
	t.Parallel()
	seeds := seedCorpus()
	if len(seeds) == 0 {
		t.Skip("no fuzz seeds available (missing /bin/true and fixtures)")
	}
	for _, seed := range seeds {
		seed := seed
		t.Run(seed.name, func(t *testing.T) {
			t.Parallel()
			checkParse(t, seed.data)
		})
	}
}
