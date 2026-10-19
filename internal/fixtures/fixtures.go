// Package fixtures builds a corpus of ELF files used by the test suites.
package fixtures

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const hello = `#include <stdio.h>
static int counter = 7;
static int helper(int x) { return x * 3 + counter; }
int global_data = 42;
const char *msg = "hello";
int main(void) { printf("%s %d\n", msg, helper(global_data)); return 0; }
`

const reloc = `extern int ext_var;
static int local_var = 3;
int func_a(int x) { return x + local_var; }
int func_b(void) { return ext_var + func_a(2); }
`

const lib = `static int base = 11;
int add_base(int x) { return x + base; }
int lib_entry(int x) { return add_base(x) * 2; }
`

const customAsm = `
.section .mydata,"aw",@progbits
.globl my_blob
.type my_blob,@object
my_blob:
    .ascii "BLOB1234"
    .size my_blob, .-my_blob
.local hidden_local
hidden_local:
    .quad 0x1122334455667788

.section .myrodata,"a",@progbits
.globl my_ro
my_ro:
    .long 1,2,3

.section .note.mynote,"a",@note
    .long 4
    .long 8
    .long 1
    .asciz "GNU"
    .long 0x12345678

.section .mydata2,"aw",@progbits
.globl my_tail
my_tail:
    .byte 0x41,0x42
`

const customC = `extern char my_blob[];
extern const int my_ro[3];
int main(void) { return my_blob[0] + my_ro[0]; }
`

// Build compiles the fixture corpus into dir and returns a map from fixture
// name to the path of the resulting file. Fixtures that cannot be built on
// this host are silently skipped.
func Build(dir string) (map[string]string, error) {
	src := func(name, body string) (string, error) {
		p := filepath.Join(dir, name)
		return p, os.WriteFile(p, []byte(body), 0o644)
	}
	helloC, err := src("hello.c", hello)
	if err != nil {
		return nil, err
	}
	relocC, err := src("reloc.c", reloc)
	if err != nil {
		return nil, err
	}
	libC, err := src("lib.c", lib)
	if err != nil {
		return nil, err
	}
	asmS, err := src("custom.s", customAsm)
	if err != nil {
		return nil, err
	}
	customMain, err := src("custom.c", customC)
	if err != nil {
		return nil, err
	}
	gcc, err := exec.LookPath("gcc")
	if err != nil {
		return map[string]string{}, nil
	}

	out := map[string]string{}
	run := func(name string, args ...string) {
		dst := filepath.Join(dir, name)
		cmd := exec.Command(gcc, append(args, "-o", dst)...)
		cmd.Dir = dir
		if b, err := cmd.CombinedOutput(); err == nil {
			out[name] = dst
			_ = b
		}
	}
	run("hello", helloC, "-O1", "-g")
	run("hello-nopie", helloC, "-O1", "-g", "-no-pie", "-fno-pie")
	run("hello-pie", helloC, "-O1", "-g", "-fPIE", "-pie")
	run("hello-nodbg", helloC, "-O2")
	run("hello-gz", helloC, "-O1", "-g", "-gz=zlib")
	run("hello-32", helloC, "-O1", "-g", "-m32")
	run("reloc.o", relocC, "-O1", "-g", "-c")
	// Some distributions (Ubuntu) enable -fcf-protection by default, which
	// adds .note.gnu.property to every object.  Build one explicitly so the
	// note handling paths are exercised everywhere.
	run("reloc-cfp.o", relocC, "-O1", "-g", "-c", "-fcf-protection=full")
	run("reloc32.o", relocC, "-O1", "-g", "-m32", "-c")
	run("lib.so", libC, "-O1", "-g", "-shared", "-fPIC")
	run("custom", asmS, customMain, "-O1", "-g", "-no-pie", "-fno-pie")
	run("static", helloC, "-O1", "-static")
	run("hello-stripped", helloC, "-O2", "-s")
	return out, nil
}

// BuildOne builds a single fixture by name, for focused debugging.
func BuildOne(dir, name string) (string, error) {
	m, err := Build(dir)
	if err != nil {
		return "", err
	}
	p, ok := m[name]
	if !ok {
		return "", fmt.Errorf("fixture %q not available on this host", name)
	}
	return p, nil
}
