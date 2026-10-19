#!/bin/bash
# repro.sh -- 复现 docs/gnu-objcopy-behavior.md 中的关键观测。
# 用法: bash docs/notes/repro.sh [--check]
#   --check: 对每个硬性事实做断言，失败则 exit 1（便于 gobjcopy 回归）。
# 只写 docs/notes/lab 目录。
set -u
cd "$(dirname "$0")" || exit 1
LAB="$PWD/lab"
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1
mkdir -p "$LAB" && cd "$LAB" || exit 1

OBJCOPY=/usr/bin/objcopy
PASS=0; FAIL=0
note() { printf '\n### %s\n' "$*"; }
run()  { printf '$ %s\n' "$*"; eval "$@"; }
chk()  { # chk <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '  ok   %-52s = %s\n' "$1" "$3"
  else FAIL=$((FAIL+1)); printf '  FAIL %-52s expected=%s actual=%s\n' "$1" "$2" "$3"; fi
}
chk_contains() { # chk_contains <desc> <needle> <haystack>
  case "$3" in *"$2"*) PASS=$((PASS+1)); printf '  ok   %-52s contains %s\n' "$1" "$2";;
    *) FAIL=$((FAIL+1)); printf '  FAIL %-52s missing %s (got: %s)\n' "$1" "$2" "$3";; esac
}

# readelf field helpers (robust for 1/2/3-digit section indexes)
sectype()  { readelf -SW "$1" | sed -n "s/^ *\[ *[0-9]*\] *$2 *\([A-Z_]*\).*/\1/p" | head -1; }
secsize()  { readelf -SW "$1" | sed -n "s/^ *\[ *[0-9]*\] *$2 *[A-Z_]* *[0-9a-f]* *[0-9a-f]* *\([0-9a-f]*\).*/\1/p" | head -1; }
secalign() { readelf -SW "$1" | sed -n "s/^ *\[ *[0-9]*\] *$2 *[A-Z_]* *[0-9a-f]* *[0-9a-f]* *[0-9a-f]* *[0-9a-f]* *[^ ]* *[0-9-]* *[0-9-]* *\([0-9]*\).*/\1/p" | head -1; }
secinfo()  { readelf -SW "$1" | sed -n "s/^ *\[ *[0-9]*\] *$2 *[A-Z_]* *[0-9a-f]* *[0-9a-f]* *[0-9a-f]* *[0-9a-f]* *[^ ]* *[0-9-]* *\([0-9-]*\) *[0-9]*.*/\1/p" | head -1; }
shnum()    { readelf -hW "$1" | awk '/Number of section headers/{print $5}'; }

# ---------------------------------------------------------------- samples
note "build samples"
cat > sample.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
static int helper_static(int x) { return x * 3; }
int global_counter = 42;
static int static_counter = 7;
static const char *local_str = "local";
int exported_fn(int a) { return helper_static(a) + global_counter; }
__attribute__((weak)) int weak_fn(int a) { return a - 1; }
__attribute__((visibility("hidden"))) int hidden_fn(int a) { return a + static_counter; }
int main(void) {
    int v = exported_fn(atoi("5"));
    printf("%d %s %d\n", v, local_str, weak_fn(v));
    return 0;
}
EOF
cat > lib.c <<'EOF'
#include <stdlib.h>
int lib_global = 5;
static int lib_static = 2;
int lib_add(int a, int b) { return a + b + lib_static; }
const char *lib_name(void) { return "lib"; }
EOF
cat > loc.s <<'EOF'
	.text
	.globl asm_global
asm_global:
	nop
	.local asm_local_obj
asm_local_obj:
	.long 7
EOF
cat > uselib.c <<'EOF'
#include <stdio.h>
extern int lib_add(int,int); extern const char *lib_name(void);
int main(){ printf("%d %s\n", lib_add(2,3), lib_name()); return 0; }
EOF
mkdir -p samples
gcc -g -O0 -c sample.c -o samples/sample.o
gcc -g -O0 sample.c -o samples/sample_exec
gcc -shared -fPIC -g -O0 lib.c -o samples/libsample.so
gcc -c loc.s -o samples/loc.o
S=samples/sample_exec; O=samples/sample.o; L=samples/libsample.so
chk "sample.o size" 5640 "$(stat -c%s $O)"
chk "sample_exec size" 18024 "$(stat -c%s $S)"
chk "libsample.so size" 16472 "$(stat -c%s $L)"

# ------------------------------------------------- 2. default / in-place
note "in-place: temp file + copy back (inode/mode preserved)"
cp $S i1; chmod 6755 i1; touch -d '2020-01-02 03:04:05' i1
before_inode=$(stat -c%i i1)
$OBJCOPY -S i1
chk "inode preserved" "$before_inode" "$(stat -c%i i1)"
chk "mode+setuid preserved" 6755 "$(stat -c%a i1)"
chk "stripped size" 14496 "$(stat -c%s i1)"
cp $S i2; touch -a -d '2021-03-04 05:06:07.123456789' i2; touch -m -d '2022-05-06 07:08:09.987654321' i2
at_before=$(stat -c%x i2); mt_before=$(stat -c%y i2)
$OBJCOPY -p -S i2 i3
chk "-p mtime ns" "$mt_before" "$(stat -c%y i3)"
chk "-p atime ns" "$at_before" "$(stat -c%x i3)"

note "explicit out-file: symlink replaced, hardlink broken, empty kept"
cp $S t; ln -sf t t.link; $OBJCOPY -S $S t.link
chk "symlink -> regular" "regular file" "$(stat -c%F t.link)"
chk "symlink target untouched" "$(stat -c%s $S)" "$(stat -c%s t)"
rm -f h1 h2; cp $S h1; ln h1 h2; $OBJCOPY -S $S h1
chk "hardlink broken (h1 size)" 14496 "$(stat -c%s h1)"
chk "hardlink h2 unchanged" "$(stat -c%s $S)" "$(stat -c%s h2)"
rm -f e0; touch e0; ino=$(stat -c%i e0); $OBJCOPY -S $S e0
chk "empty out keeps inode" "$ino" "$(stat -c%i e0)"
chk "exec chmod (0644->0755)" 755 "$(stat -c%a e0)"
cp $O m; chmod 0604 m; $OBJCOPY -S m
chk "ET_REL in-place mode kept" 604 "$(stat -c%a m)"

# --------------------------------------------------------- 3. strip stats
note "strip matrix (size/shnum/symcount)"
for f in $O $S $L; do b=$(basename $f)
  orig=$(stat -c%s $f)
  for opt in -S -g --strip-unneeded -x -X --only-keep-debug; do
    tag=$(echo "$opt" | tr -d '-')
    $OBJCOPY $opt $f out.$b.$tag 2>/dev/null
    printf '  %-12s %-18s size=%-6s secs=%-3s syms=%s\n' "$b" "$opt" \
      "$(stat -c%s out.$b.$tag)" \
      "$(readelf -SW out.$b.$tag | grep -c '^ *\[')" \
      "$(readelf -sW out.$b.$tag 2>/dev/null | grep -c '^ *[0-9]')"
  done
done
chk "sample.o -S has no symtab" 0 "$(readelf -SW out.sample.o.S | grep -c '\.symtab')"
chk "sample.o -S has no rela" 0 "$(readelf -SW out.sample.o.S | grep -c '\.rela')"
chk "exec -S keeps dynsym" 8 "$(readelf -sW out.sample_exec.S | grep -c '^ *[0-9]')"
chk "exec -S drops symtab" 0 "$(readelf -SW out.sample_exec.S | grep -c '\.symtab')"
chk "exec -g keeps symtab" 1 "$(readelf -SW out.sample_exec.g | grep -c '\.symtab')"

note "only-keep-debug: alloc -> NOBITS, notes keep contents"
$OBJCOPY --only-keep-debug $S dbg
chk "text NOBITS" "NOBITS" "$(sectype dbg .text)"
chk "note.gnu.build-id NOTE" "NOTE" "$(sectype dbg .note.gnu.build-id)"
chk "e_entry unchanged" "$(readelf -hW $S | awk '/Entry point/{print $4}')" "$(readelf -hW dbg | awk '/Entry point/{print $4}')"

note "gnu_debuglink: basename + NUL pad to 4 + LE CRC32"
cp $S exe; $OBJCOPY --only-keep-debug exe exe.dbg
$OBJCOPY --strip-debug --add-gnu-debuglink=exe.dbg exe
$OBJCOPY --dump-section .gnu_debuglink=dl.bin exe
chk "debuglink size (7+1->8 +4)" 12 "$(stat -c%s dl.bin)"
chk "debuglink name+pad" "65 78 65 2e 64 62 67 00" "$(od -An -v -tx1 -N8 dl.bin | tr -s ' ' | sed 's/^ //;s/ $//')"
crc_le=$(od -An -v -tx1 -j8 -N4 dl.bin | tr -d ' \n')
crc_be=$(python3 -c "import zlib;c=zlib.crc32(open('exe.dbg','rb').read())&0xffffffff;print('%02x%02x%02x%02x'%(c&255,(c>>8)&255,(c>>16)&255,(c>>24)&255))")
chk "debuglink CRC32 = zlib.crc32(debug), LE" "$crc_be" "$crc_le"

# -------------------------------------------------------- 4. -O binary
note "-O binary: base = min LMA of content sections, size = max(lma+size)-base"
$OBJCOPY -O binary $S b.bin
chk "exec binary size" 15584 "$(stat -c%s b.bin)"
$OBJCOPY -O binary --pad-to 0x5000 $S p.bin
chk "pad-to 0x5000 size" 19632 "$(stat -c%s p.bin)"
$OBJCOPY -S -O binary $S bs.bin
chk "-S binary identical" 0 "$(cmp -l b.bin bs.bin | wc -l)"
$OBJCOPY -O binary $O o.bin
chk "ET_REL binary size = max section" 184 "$(stat -c%s o.bin)"
chk "ET_REL last writer wins (.eh_frame)" "14" "$(od -An -tx1 -N1 o.bin | tr -d ' ')"

# ------------------------------------------------------- 5. section ops
note "section options"
$OBJCOPY -j .text $S j1
chk "-j .text shnum" 5 "$(shnum j1)"
chk "-j generates symtab" 1 "$(readelf -SW j1 | grep -c '\.symtab')"
$OBJCOPY --rename-section .rodata=.rd,alloc,code $S rn1
chk "rename w/o contents -> NOBITS" "NOBITS" "$(sectype rn1 .rd)"
$OBJCOPY --rename-section .rodata=.rd,alloc,contents $S rn2
chk "rename w/ contents -> PROGBITS" "PROGBITS" "$(sectype rn2 .rd)"
$OBJCOPY --add-section .my=exe.dbg $S ad 2>/dev/null
chk "add-section PROGBITS" "PROGBITS" "$(sectype ad .my)"
chk "add-section align=1" 1 "$(secalign ad .my)"
$OBJCOPY --strip-section-headers $S sh
chk "strip-section-headers shnum" 0 "$(shnum sh)"
msg=$($OBJCOPY -R .text --update-section .text=exe.dbg $S x 2>&1); rc=$?
chk "R+update conflict rc" 1 "$rc"
chk_contains "R+update message" "matches both update and remove options" "$msg"
msg=$($OBJCOPY -j .text -R .text $S x 2>&1); rc=$?
chk "j+R conflict rc" 1 "$rc"
chk_contains "j+R message" "both copied and removed" "$msg"
msg=$($OBJCOPY --dump-section .nosuch=nd $S 2>&1); rc=$?
chk "dump missing rc=0" 0 "$rc"
chk_contains "dump missing message" "it does not exist" "$msg"

# ------------------------------------------------------- 6. addresses
note "address/layout"
$OBJCOPY --change-addresses 0x1000 $S ca
chk "entry shifted" 0x2060 "$(readelf -hW ca | awk '/Entry point/{print $4}')"
chk "DT_STRTAB NOT shifted" 0x498 "$(readelf -dW ca | awk '/STRTAB/{print $NF}')"
$OBJCOPY --change-section-address .text=0x2000 $S cs
chk "new PT_LOAD count" 5 "$(readelf -lW cs | grep -c '^  LOAD')"
$OBJCOPY --set-section-alignment .text=4096 $S al
chk "alignment capped to 32" 32 "$(secalign al .text)"
$OBJCOPY --set-section-alignment .init=4096 $S al2
chk "page-aligned section allows 4096" 4096 "$(secalign al2 .init)"
msg=$($OBJCOPY --change-section-address .nosuch+0x10 $S /dev/null 2>&1)
chk_contains "change warning default on" "never used" "$msg"

# -------------------------------------------------------- 7. symbols
note "symbols"
$OBJCOPY -S -K exported_fn $O k1.o
chk "-S -K leaves 2 syms" 2 "$(readelf -sW k1.o | grep -c '^ *[0-9]')"
chk "-S -K sh_info=1" 1 "$(secinfo k1.o .symtab)"
msg=$($OBJCOPY -N global_counter $O k2.o 2>&1); rc=$?
chk "-N reloc symbol rc" 1 "$rc"
chk_contains "-N reloc message" "named in a relocation" "$msg"
$OBJCOPY -S --keep-file-symbols $O k3.o
chk "--keep-file-symbols" 2 "$(readelf -sW k3.o | grep -c '^ *[0-9]')"
$OBJCOPY -G exported_fn $O k4.o
chk "-G localizes others" "LOCAL" "$(readelf -sW k4.o | awk '/ main$/{print $5}')"
$OBJCOPY --globalize-symbol helper_static $O k5.o
chk "--globalize moves local to global" "GLOBAL" "$(readelf -sW k5.o | awk '/ helper_static$/{print $5}')"
$OBJCOPY -w -N 'exported*' $O k6.o 2>/dev/null; rc=$?
chk "-w wildcard hits reloc symbol rc" 1 "$rc"
$OBJCOPY -N 'exported*' $O k7.o 2>/dev/null
chk "no -w => literal, symbol kept" 1 "$(readelf -sW k7.o | grep -c exported_fn)"
$OBJCOPY --redefine-sym atoi=my_atoi $O k8.o
chk "redefine updates relocs" 1 "$(readelf -rW k8.o | grep -c my_atoi)"

# ------------------------------------------------------ 8. compression
note "compression: zlib==zlib-gabi, gnu=ZLIB+BE size"
$OBJCOPY --compress-debug-sections=zlib $O cz.o
$OBJCOPY --compress-debug-sections=zlib-gabi $O cg.o
chk "zlib == zlib-gabi bytes" 0 "$(cmp -l cz.o cg.o | wc -l)"
$OBJCOPY --dump-section .debug_info=di.bin cz.o
chk "chdr type/size" "01 00 00 00 00 00 00 00 d7 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00" \
  "$(od -An -v -tx1 -N24 di.bin | tr '\n' ' ' | tr -s ' ' | sed 's/^ //;s/ $//')"
$OBJCOPY --compress-debug-sections=zlib-gnu $O cn.o
$OBJCOPY --dump-section .zdebug_info=dz.bin cn.o
chk "gnu header ZLIB+BE" "5a 4c 49 42 00 00 00 00 00 00 01 d7" "$(od -An -v -tx1 -N12 dz.bin | tr '\n' ' ' | tr -s ' ' | sed 's/^ //;s/ $//')"
$OBJCOPY --decompress-debug-sections cn.o dec.o
chk "decompress restores size" "$(secsize $O .debug_info)" "$(secsize dec.o .debug_info)"

# ------------------------------------------------------ 9. errors
note "errors / exit codes (expect rc=1)"
for cmd in \
  "$OBJCOPY nosuch eout1" \
  "$OBJCOPY -O nosuch $S eout2" \
  ": > empty; $OBJCOPY empty eout3" \
  "echo hi > txt; $OBJCOPY txt eout4" \
  "$OBJCOPY $S nodir/eout5" \
  "$OBJCOPY $S a b c" \
  "$OBJCOPY -O elf64-big $O eout7" \
  "$OBJCOPY -B nosuch -I binary -O elf64-x86-64 $S eout8" ; do
  msg=$(eval "$cmd" 2>&1); rc=$?
  chk "rc=1: ${cmd#*objcopy }" 1 "$rc"
  printf '       msg: %s\n' "$(echo "$msg" | head -1)"
done

# ---------------------------------------------- 10. option table quirks
note "option table quirks"
cp $S st; strip -S st
chk "strip -S = strip-debug" 16128 "$(stat -c%s st)"
cp $S st2; strip --strip-all st2
chk "strip --strip-all" 14496 "$(stat -c%s st2)"
msg=$($OBJCOPY -S --keep-section-symbols $O q.o 2>&1); rc=$?
chk "objcopy --keep-section-symbols eats input" 1 "$rc"
chk_contains "quirk message" "No such file" "$msg"
$OBJCOPY -S --keep-section-symbols=yes $O q2.o
chk "with =value works" 0 "$?"
chk "-S --keep-section-symbols still no syms" 0 "$(readelf -sW q2.o 2>/dev/null | grep -c '^ *[0-9]')"

# ------------------------------------------------ 10b. info / targets
note "info output"
$OBJCOPY --info > objcopy-info.txt
chk "info line 1" "BFD header file version (GNU Binutils for Debian) 2.44" "$(head -1 objcopy-info.txt)"
chk "elf targets in info" 8 "$(grep -cE '^elf(32|64)-' objcopy-info.txt)"
$OBJCOPY --info | tail -22

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$CHECK" = 1 ] && [ "$FAIL" != 0 ] && exit 1
exit 0
