# GNU objcopy 2.44 行为规格（Linux x86-64 实测）

对象：`/usr/bin/objcopy`（GNU Binutils for Debian 2.44，动态链接 `libbfd-2.44-system.so`）。
环境：Debian 13，gcc 14.2，无 clang/elfutils，**无 xxd**（本文用 `od -Ax -tx1z` 代替，字节等价）。
源码核实：`binutils-2.44.tar.xz`（ftp.gnu.org），引用函数名。样本与全部命令见 `docs/notes/lab/`，
一键复现脚本：`docs/notes/repro.sh`。样本：`sample.o`（ET_REL）、`sample_exec`（PIE/ET_DYN）、
`libsample.so`（ET_DYN）、`loc.o`（汇编本地符号）、`grp.o`（C++ COMDAT/SHT_GROUP）。

约定：下文 `$` 行均可直接复制运行（在 `docs/notes/lab` 下，先跑一次 `repro.sh` 生成样本）；
`O=samples/sample.o; S=samples/sample_exec; L=samples/libsample.so`。

---

## 1 完整选项清单

`objcopy --help` 共 124 行、约 100 个选项（`docs/notes/objcopy-help.txt`）。按类别：

### 1.1 格式/目标
| 选项 | 参数 | 可重复 | 行为/要点 |
|---|---|---|---|
| `-I --input-target` | bfdname | 否（后者覆盖） | 强制输入格式；`default` = 编译期默认目标 `elf64-x86-64` |
| `-O --output-target` | bfdname | 否 | 缺省时 **= 输入 target**（显式 `-I` 或探测所得），不是"默认目标" |
| `-F --target` | bfdname | 否 | 同时设 I/O |
| `-B --binary-architecture` | arch | 否 | 仅对无架构输入（binary/ihex…）有效；对 ELF 输入只警告 `Input file `x' ignores binary architecture parameter.`；合法名仅 `i386`/`iamcu`（`x86-64` 报 unknown） |
| `--info` | – | – | 打印 BFD 目标/架构矩阵，exit 0 |
| `--alt-machine-code` | index | 否 | 选目标机 index（ELF 上基本 no-op） |
| `--long-section-names` | enable/disable/keep | 否 | 仅 COFF |
| `--change-leading-char` / `--remove-leading-char` | – | – | 符号前导字符（ELF 无前导字符 → no-op，rc=0） |

### 1.2 文件与输出
`-p --preserve-dates`、`-D/-U --[enable|disable]-deterministic-archives`（仅 archive）、`-v --verbose`（打印
`copy from `in' [fmt] to `out' [fmt]`）、`-V`、`-h`、`@file`（每行一个选项）。

### 1.3 strip / 符号选择（全部可重复，除 `--weaken`/`--localize-hidden`）
`-S --strip-all`、`-g --strip-debug`、`--strip-dwo`、`--strip-unneeded`（无短选项）、
`-N --strip-symbol NAME`、`--strip-unneeded-symbol NAME`、`-K --keep-symbol NAME`、
`-G --keep-global-symbol NAME`、`-L --localize-symbol NAME`、`--globalize-symbol NAME`、
`-W --weaken-symbol NAME`、`--weaken`、`-x --discard-all`、`-X --discard-locals`、
`--keep-file-symbols`、`--keep-section-symbols`、`--localize-hidden`、`-w --wildcard`、
`--only-keep-debug`、`--extract-symbol`、`--extract-dwo`、
`--{strip,keep,localize,globalize,weaken,strip-unneeded,keep-global}-symbols FILE`（文件版）。

### 1.4 节
`-R --remove-section NAME`、`-j --only-section NAME`、`--keep-section NAME`（均可重复，支持通配符）、
`--remove-relocations NAME`、`--strip-section-headers`、`--add-section NAME=FILE`（可重复）、
`--update-section NAME=FILE`、`--dump-section NAME=FILE`（可重复）、`--rename-section OLD=NEW[,FLAGS]`、
`--set-section-flags NAME=FLAGS`、`--set-section-alignment NAME=ALIGN`、`--add-gnu-debuglink=FILE`、
`-M --merge-notes` / `--no-merge-notes`。

`--set-section-flags` 的 FLAGS 为**逗号分隔、大小写不敏感、前缀匹配**（`strncasecmp`）：完整取值：
`alloc load noload readonly debug code data rom exclude share contents merge strings large`。
未知 flag → `unrecognized section flag `x'` + `supported flags: ...`，exit 1。
同名 flag 重复给（如 `--set-section-flags .x=alloc` 两次）→ 合并（`p->context |=`）。

### 1.5 地址/布局（详见 §6）
`--set-start ADDR`、`{--change-start|--adjust-start} INCR`、
`{--change-addresses|--adjust-vma} INCR`、
`{--change-section-address|--adjust-section-vma} name{=|+|-}val`、
`--change-section-lma name{=|+|-}val`、`--change-section-vma name{=|+|-}val`、
`{--[no-]change-warnings|--[no-]adjust-warnings}`、`--gap-fill VAL`、`--pad-to ADDR`、
`--set-section-alignment`。
语法要点：`=` **绝对设置**，`+`/`-` **相对增减**（`--change-section-address .text=0x2000`；`.text+0x100`）。
同一节"既 set 又 alter" → `error: %s both sets and alters VMA`（fatal）。

### 1.6 内容变换与其它
`-i --interleave[=N]`、`--interleave-width N`、`-b --byte N`、`--reverse-bytes=N`、
`--redefine-sym OLD=NEW`、`--redefine-syms FILE`、`--add-symbol NAME=[SECT:]VAL[,FLAGS]`、
`--prefix-symbols`、`--prefix-sections`、`--prefix-alloc-sections`、
`--elf-stt-common=yes|no`、`--compress-debug-sections[=none|zlib|zlib-gnu|zlib-gabi|zstd]`、
`--decompress-debug-sections`、`--verilog-data-width`、`--srec-len`、`--srec-forceS3`；
PE 专用（ELF 上 no-op、rc=0）：`--file-alignment --heap --image-base --section-alignment --stack
--subsystem --writable-text --readonly-text --pure --impure`。

**-i/-b/--interleave-width 关系**：`-i N` 表示每 N 字节取块；`--interleave-width W`（默认 1）为每块取 W 字节；
`-b B` 指定块内起始字节（0-based，必须 `< N`）。`-i` 不带值 → `interleave must be positive`；`-i N` 缺 `-b` →
`interleave start byte must be set with --byte`；`B>=N` → `byte number must be less than interleave`（均 exit 1）。
输出节大小 = `(size + N - 1 - B)/N * W`，且 `osection->lma /= N`（实现见 `copy_section`）。

**--add-symbol 语法**：`NAME=[SECTION:]VALUE[,FLAGS]`；FLAGS 同 `parse_symflags`：`global local weak
section file object func indirect debugging constructor warning indirect-function` 等；节不存在 →
`Section .nope not found`，exit 1。

**--redefine-syms 文件格式**（`add_redefine_syms_file`）：每行 `OLD NEW`，空白分隔；`#` 起注释（行内亦可）；
**不允许行首空白**（否则得空 OLD，报 `garbage found at end of line`）；只给一个名字 →
`missing new symbol name`；行尾多一个 token → `garbage found at end of line`；文件末尾无换行 →
`premature end of file`；`OLD` 重复 → `--redefine-sym: Multiple redefinition of symbol "x"`。全部 fatal，exit 1，不产出输出文件。

### 1.7 选项表陷阱（strip vs objcopy）
`/usr/bin/objcopy` 永远走 `copy_main`（`main()` 只按 argv[0] 是否以 `strip` 结尾分流）；`/usr/bin/strip`
走 `strip_main`，两者 long option 表不同：
- `copy_options` 中 `--keep-section-symbols` 声明为 **required_argument**（源码 2.44 `objcopy.c:473`），
  因此 `objcopy --keep-section-symbols in out` 会把 `in` 当参数吃掉，只剩 `out` 作输入 →
  `objcopy: 'out': No such file`（rc=1）；必须写 `--keep-section-symbols=任意值`。
- `strip -S` 表示 **strip-debug**（不是 strip-all！）；`strip -s`/`strip --strip-all` 才是 strip-all；
  `strip -g`/`-d`/`--strip-debug` 都是 strip-debug。验证：
```bash
cp $S st; strip -S st; stat -c%s st        # 16128 = -g 大小
cp $S st; strip --strip-all st; stat -c%s st  # 14496
```

---

## 2 默认行为（无 out-file / 权限 / 时间 / 链接）

**无 out-file 或 in==out 时：临时文件 + 拷回，不是 rename**（`rename.c:smart_rename`+`simple_copy`）：
1. `stat()` 输入得到 `statbuf`；`make_tempname()` 在**输入同目录**创建 `stXXXXXX`（mkstemp，0600）；
2. BFD 写临时文件；关闭时对 ET_EXEC/ET_DYN 做 `chmod(0777 & (mode|(0111 & ~umask)))`；
3. `open(input, O_WRONLY|O_TRUNC)` 拷回 + `fchmod(input, statbuf.st_mode)`，再 `unlink(temp)`。

因此**原地修改保留 inode、属主、全部权限位（含 setuid/setgid）**；mtime/atime=当前时间，除非 `-p`。
`-p` 用 `utimensat` 复制输入的 atime+mtime（**纳秒精度**）。

```bash
cp $S i1; chmod 6755 i1; touch -d '2020-01-02 03:04:05' i1
stat -c '%i %a %Y' i1; objcopy -S i1; stat -c '%i %a %Y' i1   # inode/6755 不变，mtime 变新
objcopy -p -S i1 i2; stat -c '%x %y' i1 i2                     # 完全相同(含 ns)
```

**显式 out-file**：`bfd_openw` → `cache.c:bfd_open_file`：若目标 `stat` 成功、`st_size != 0` 且是普通文件，
先 `unlink()` 再 `fopen("w+b")`。后果：
- 非空**普通文件**：换 inode，权限重置为 `0666 & ~umask`；ET_EXEC/ET_DYN 再 `| (0111 & ~umask)`；
- **符号链接**：`stat` 跟随 → 链接被 unlink，**替换成新普通文件**，链接目标不变；
- **硬链接**：只有该名字换成新 inode，其它链接仍指向旧文件；
- **空文件（size==0）**：不 unlink，保留 inode/权限，只 `|0111`（exec 时）；
- 目录/设备：目录报错；`/dev/null` 正常写入（非普通文件不 chmod）。

```bash
cp $S t; ln -s t t.link; objcopy -S $S t.link; ls -l t t.link   # t.link 变普通文件，t 未变
cp $S h1; ln h1 h2; objcopy -S $S h1; stat -c '%i %h %s' h1 h2  # h1 新 inode，h2 旧内容
rm -f e; touch e; objcopy -S $S e; stat -c '%i %a' e            # inode 保留，0644→0755
cp $O m; chmod 0604 m; objcopy -S m; stat -c '%a' m             # 0604（非 exec 不 chmod）
```

**默认输出格式/目标**：`output_target = input_target`；若没给 `-I` 且自动探测，则用探测到的 target 名
（即默认"格式不变"，不是全量重写为默认目标）。`-O default`/`-I default` 解析为编译期默认 `elf64-x86-64`。
输出文件**不复制**输入权限/属主；只复制内容（`-p` 才复制时间）。原地修改走拷回路径所以"看起来"保留。

**符号链接输入**：读取跟随链接；原地修改时通过链接写目标（链接保留）。

**临时文件失败**（目录不可写 / 输入不可读且原地）：`objcopy: warning: could not create temporary file
whilst copying 'rodir/x', (error: Permission denied)`，exit 1，输入不动。
（注意文本带 `warning:` 但属 fatal 路径。）

---

## 3 strip 语义（实测统计）

样本基数：`sample.o` 5640B/25 sh/21 sym；`sample_exec` 18024B/38 sh/52 sym；`libsample.so` 16472B/32 sh/36 sym
（sh/sym 为 `readelf -SW`/`-sW` 行数，含 NULL 与 index 0）。输出：

| 选项 | .o | exec | .so |
|---|---|---|---|
| 原始 | 5640 / 25 / 21 | 18024 / 38 / 52 | 16472 / 32 / 36 |
| `-S` | 1216 / 11 / **0** | 14496 / 30 / **8**(dynsym) | 14000 / 24 / **8** |
| `-g` | 2392 / 16 / 15 | 16128 / 32 / 47 | 15080 / 26 / 32 |
| `--strip-unneeded` | 2280 / 16 / **12** | 14496 / 30 / 8 | 14000 / 24 / 8 |
| `-x` | 2312 / 16 / 13 | 15664 / 32 / 37 | 14560 / 26 / 20 |
| `-X` | 5640 / 25 / 21 | 18024 / 38 / 52 | 16472 / 32 / 36 |
| `--only-keep-debug` | 5248 / 25 / 21 | 10216 / 38 / 44 | 4768 / 32 / 28 |

### 3.1 `-S --strip-all`
- **.o**：保留 `NULL .text .data .bss .rodata .data.rel.local .comment .note.GNU-stack .eh_frame .shstrtab`；
  删除 `.symtab/.strtab`、全部 `.debug_*`、以及**全部 `.rela.*`**。原因：重定位节从不是"拷贝"的，而是
  `copy_relocations_in_section()` 重新生成，而它在 `strip_symbols == STRIP_ALL` 时直接返回（objcopy.c:4501）。
  输出无任何符号（含节符号）。
- **exec/.so**：删除 `.symtab/.strtab` 与 debug 节；**保留 `.dynsym/.dynstr/.gnu.hash/.gnu.version*`、
  所有 SHF_ALLOC 节、`.comment`、`.shstrtab`**。`.dynsym` 顺序**逐字节不变**，链接运行正常。
- `e_type`、`e_entry`、程序头不变（文件仅变小）。
```bash
objcopy -S $O s.o; readelf -SW s.o | sed -n '5,20p'; readelf -sW s.o   # 无 .symtab/.rela
objcopy -S $L s.so; readelf --dyn-syms -W $L | awk '{print $8}' > a
readelf --dyn-syms -W s.so | awk '{print $8}' > b; diff a b && echo dynsym-order-same
gcc uselib.c -o u -L. -l:s.so -Wl,-rpath,$PWD && ./u   # 7 lib
```

### 3.2 `-g` / `--strip-unneeded` / `-x` / `-X`
- `-g`：只删 `SEC_DEBUGGING` 节及其重定位；`.symtab` 保留，其中"调试符号"（FILE、被删节的 SECTION 符号）
  被滤掉（21→15，52→47）。全局/局部普通符号保留。
- `--strip-unneeded`：删 debug 节 + 所有"重定位不需要"的符号。可重定位文件里被重定位引用的符号/节符号保留
  （.o 12 个）；exec/.so 中 `.symtab` 没有任何符号需要 → **整个 `.symtab/.strtab` 消失**（与 -S 结果同大小，
  但仍保留 dynsym）。
- `-x`：等价"删所有非全局符号"，但 **FILE 符号（BSF_DEBUGGING 类）与重定位引用的 SECTION 符号保留**
  （.o：FILE+4 个节符号+7 全局=13；exec 37=52-15 局部）。
- `-X`：只删 `bfd_is_local_label_name()` 为真的局部符号：`.L*`、`..*`、`_.L_*`、`L<数字><控制字符>…`；
  不删 SECTION/FILE/全局（`-O0` 样本无此类符号，故字节不变）。验证：
```bash
objcopy --redefine-sym asm_local_obj=.Lhidden -X samples/loc.o x1.o; readelf -sW x1.o
objcopy --redefine-sym asm_local_obj=Lhidden  -X samples/loc.o x2.o; readelf -sW x2.o  # Lhidden 保留
```
- 优先级：`-g/-S/--strip-unneeded/--only-keep-debug` 共用一个枚举，**最后一个生效**：
  `-g -S` = strip-all；`-S -g` = strip-debug。`-x/-X` 独立叠加。

### 3.3 `--only-keep-debug`
- 所有 **SHF_ALLOC 且非 SHT_NOTE** 的节 → `SHT_NOBITS`（sh_size/sh_addr/sh_flags 不变，内容丢弃）；
  `SHT_NOTE`（`.note.gnu.property/.build-id/.ABI-tag`）**保留内容**；非 ALLOC 节（`.comment`、debug、
  `.symtab/.strtab/.shstrtab`）保留内容。
- 头部：`e_type`、`e_flags`、`e_entry` **不变**（PIE 仍为 ET_DYN；readelf 的 "Shared object file" 只因
  `.interp` 变 NOBITS）；程序头被重算：NOBITS 段的 `p_filesz=0`，`p_offset` 变化，`.interp` 段 filesz=0。
```bash
objcopy --only-keep-debug $S d; readelf -SW d | grep -E 'NOBITS|NOTE'
readelf -hW $S > h1; readelf -hW d > h2; diff h1 h2     # 仅 shoff 与 Type 显示差异
readelf -lW $S > p1; readelf -lW d > p2; diff p1 p2     # p_filesz/p_offset 重算
```

### 3.4 `--add-gnu-debuglink`
节内容 = **basename**（路径被剥离）+ NUL 填充到 4 字节边界 + CRC32（IEEE/zlib，`bfd_calc_gnu_debuglink_crc32`）
**小端 4 字节**，CRC 覆盖**整个 debug 文件**。填充规则：`namelen+1` 向上取整到 4 的倍数（若 `strlen%4==0`
仍至少补 1 个 NUL，即 `"1234"` → 8 字节）。节 `sh_addralign=4`、无 ALLOC。
```bash
objcopy --only-keep-debug $S exe.dbg; cp $S exe; objcopy --strip-debug --add-gnu-debuglink=exe.dbg exe
readelf -SW exe | grep gnu_debuglink
objcopy --dump-section .gnu_debuglink=dl.bin exe; od -Ax -tx1z dl.bin
python3 -c "import zlib;print(hex(zlib.crc32(open('exe.dbg','rb').read())))"
```
实测（`"exe.dbg"` 7 字符 → 8+4=12 字节）：
`65 78 65 2e 64 62 67 00 f3 9a 71 20`，CRC=0x20719af3（zlib.crc32 结果一致，小端存放）。
已存在 `.gnu_debuglink` → `objcopy: %s: debuglink section already exists`，**rc=0 且原节不变**；
文件不存在 → `cannot fill debug link section `x': No such file or directory`，rc=1。

---

## 4 `-O binary`

规则（`bfd/binary.c:binary_set_section_contents`）：
- 基准 `low` = **满足 `(HAS_CONTENTS|LOAD|ALLOC)` 全置位且 size>0** 的节中最小 **LMA**；
- 每个节的 `filepos = lma - low`；写入时仅要求 `(LOAD|ALLOC)` 任一置位且非 `SEC_NEVER_LOAD`；
- 输出长度 = `max(lma+size) - low`；**不含** NOBITS 的尾部（`.bss` 不贡献长度）；
- 排序依据是 **LMA**，与节头顺序无关；LMA 相同的节互相覆盖（后写者赢）；
- 空洞默认是文件空洞（读为 0）；`--gap-fill V` 把 V 写入空洞（通过**增大前一节 sh_size**实现，因此对 ELF
  输出同样生效）；`--pad-to A` 把 LMA 最大节的 size 扩到 `A-lma`（绝对地址）；`--change-addresses` 平移所有
  LMA/VMA，若基准随之平移则长度不变；`--change-section-lma` 可改变基准；
- 可与 `-S` 组合，**输出字节完全相同**（符号不影响）。

```bash
objcopy -O binary $S b.bin; ls -l b.bin          # 0x4030-0x350 = 15584
objcopy -O binary --gap-fill 0xAA $S g.bin; od -Ax -tx1 -j 0x100 -N 8 g.bin
objcopy -O binary --pad-to 0x5000 $S p.bin; ls -l p.bin   # 0x5000-0x350 = 19632
objcopy -S -O binary $S bs.bin; cmp b.bin bs.bin && echo identical
objcopy -O binary $O o.bin; ls -l o.bin          # 184 = 最大节(.eh_frame)，各节 LMA=0 互相覆盖
od -Ax -tx1z -N 8 o.bin                          # 内容来自 .eh_frame（最后写入者）
```

`-O binary` 与节过滤：`-j/-R` 先决定节集合；`--set-section-flags x=noload` 会把它排除出 binary（`SEC_NEVER_LOAD`），
`--set-section-flags x=alloc`（无 load）会得到 `filepos=0`（只由 LOAD+ALLOC 的节决定 low/filepos）→ 写在文件头。

---

## 5 节的增删改

| 操作 | 行为/限制 | 警告/错误 |
|---|---|---|
| `-R NAME` | 删除节；对 **.o 中带重定位的节**会因重定位引用了该节符号而失败 | `objcopy: out: symbol `.debug_info' required but not present` + `objcopy: out: no symbols`，exit 1，**无输出文件** |
| `-R .rela.*` | **静默 no-op**（BFD 不把重定位节当节暴露） | 无 |
| `-R .shstrtab` | 静默忽略，输出仍重建 `.shstrtab` | 无 |
| `-R 不存在的节` | 静默 no-op | 无 |
| `-j NAME`（可多次） | 只保留列出的节 + 自动 `.shstrtab`；若仍有符号，**自动生成 `.symtab/.strtab`** | 丢掉的 alloc 节可能触发 `warning: empty loadable segment detected at vaddr=0x..., is this intentional?` |
| `-j` + `-R` 同名 | fatal | `error: .text both copied and removed`（注意无 "section" 一词） |
| `-R` + `--update-section` 同名 | fatal | `error: section .text matches both update and remove options` |
| `--keep-section NAME` | 只压过 `-R`/`-j`（配合 `-j` 时两边都留）；**不阻止 `-S` 删 debug 节** | – |
| `--remove-relocations NAME` | 删除"属于该节"的重定位（如 `--remove-relocations .text` → 去掉 `.rela.text`）；支持通配符；不存在→静默 | – |
| `--strip-section-headers` | `e_shoff=e_shnum=e_shentsize=e_shstrndx=0`；同时**删除所有非 ALLOC 节**；ET_REL 输出只剩内容碎片（456B） | – |
| `--add-section N=F` | 追加为**最后一节**（在 `.symtab/.strtab/.shstrtab` 之前），默认 flags=`HAS_CONTENTS|READONLY|DATA`（**无 ALLOC**），`sh_addralign=1`，`sh_offset` 紧跟原文件尾 | alloc 时 `warning: allocated section `.mysec' not in segment`，且**不进入任何 PT_LOAD**；重名 → `can't add section '.text': file format not recognized`（消息 bug），exit 1 |
| `--update-section N=F` | 用文件内容替换；**允许改变 sh_size**（截短/加长）；无大小校验；不存在→`error: .nope not found, can't be updated`，exit 1 | – |
| `--dump-section N=F` | 在 strip **之前**读输入并写出原始内容；不存在→`can't dump section '.nosuch' - it does not exist: file format not recognized`，但 **exit 0**、不建文件 | – |
| `--rename-section OLD=NEW[,FLAGS]` | 改名；给出 FLAGS 时**整体替换**（缺 `contents` → 节变 `SHT_NOBITS`！）；允许重名；OLD 不存在→静默 | 未知 flag → fatal + supported 列表 |
| `--set-section-flags N=FLAGS` | **整体替换**，仅保留输入的 `SEC_HAS_CONTENTS/SEC_RELOC` 位；作用于**输出**，不影响 strip 判定（strip 看输入 flags） | 未知 flag fatal |
| `--set-section-alignment N=A` | 必须是 2 的幂且非 0；**在段内的节会被静默截断**为"能整除 VMA/offset 的最大 2 的幂" | `=0`→`numeric argument needed`；非 2 幂→`alignment is not a power of two`；节不存在→静默 |

`--set-section-flags` → SHF 映射（实测 `readelf -SW` 的 Flg 列）：

| flag | BFD 位 | ELF 可见效果 |
|---|---|---|
| `alloc` | SEC_ALLOC | `A` |
| `load` | SEC_LOAD | 无 SHF；影响 binary/段归属判定 |
| `noload` | SEC_NEVER_LOAD | 无 SHF；从 binary 输出排除 |
| `readonly` | SEC_READONLY | **清除** `W`（默认非 readonly 即 `W`） |
| `code` | SEC_CODE | `X` |
| `data` | SEC_DATA | 无 |
| `rom` | SEC_ROM | 无 |
| `debug` | SEC_DEBUGGING | 无；仅 BFD 内部（且不改 strip 结果） |
| `exclude` | SEC_EXCLUDE | `E` |
| `share` | SEC_COFF_SHARED | 无（COFF 专用） |
| `contents` | SEC_HAS_CONTENTS | 决定 `SHT_PROGBITS` vs `SHT_NOBITS` |
| `merge` | SEC_MERGE | `M` |
| `strings` | SEC_STRINGS | `S` |
| `large` | SEC_ELF_LARGE | `l`（x86-64） |

```bash
objcopy --set-section-flags .data=alloc,code $S f1; readelf -SW f1 | grep ' .data '
objcopy --set-section-flags .data=readonly $S f2; readelf -SW f2 | grep ' .data '   # 无 W
objcopy --rename-section .rodata=.rd2,alloc,code $S f3; readelf -SW f3 | grep rd2   # NOBITS!
objcopy --rename-section .rodata=.rd2,alloc,contents $S f4; readelf -SW f4 | grep rd2 # PROGBITS
objcopy -j .text $S f5; readelf -SW f5     # 含自动 .symtab/.strtab/.shstrtab
objcopy -S --keep-section .debug_info $S f6; readelf -SW f6 | grep -c debug  # 0，keep 不敌 -S
objcopy --strip-section-headers $S f7; readelf -hW f7 | grep -E 'section headers|Number of section'
```

---

## 6 地址与布局

| 选项 | ET_REL | ET_EXEC / ET_DYN |
|---|---|---|
| `--change-addresses N` / `--adjust-vma N` | 所有节 `sh_addr += N`（`.rela.*` 的 sh_addr 仍 0）；`e_entry += N` | 所有 VMA **和 LMA**、`e_entry` 加 N；`p_offset` 不变；程序头按新 VMA 重建；**`.dynamic` 内容不更新**（`DT_INIT/STRTAB/...` 仍是旧地址 → 运行时损坏） |
| `--change-section-address n=v` | 仅改该节 `sh_addr`（=VMA；LMA 对 ET_REL 无意义） | 同时改 VMA+LMA；可能**新增/拆分 PT_LOAD**，文件偏移重排 |
| `--change-section-vma n=v` | 改 `sh_addr` | 只改 `p_vaddr`；若新 VMA 无法放入原段 → `objcopy: out: section `.data' can't be allocated in segment 5`（rc 仍 0） |
| `--change-section-lma n=v` | 无可见效果（ELF 无 LMA 字段） | 只改 `p_paddr`（可产生同 vaddr 的新 PT_LOAD），`p_offset/p_filesz` 随之调整 |
| `--set-start A` / `--change-start N` | 改 `e_entry`（无警告） | 改 `e_entry`（无警告，即使指向段外） |
| `--pad-to A` | 扩 LMA 最大节的 size | 同上；若最大节是 NOBITS 会先告警 `section .bss lma 0x4030 adjusted to 0x5000` |
| `--gap-fill V` | 增大前一节 size 并写填充 | 同左（影响 ELF 布局与文件大小） |

实测要点：
- `--change-section-address .text=0x2000` 在 exec 上生成**新的 PT_LOAD**（5 个 LOAD），`.text` 文件偏移变为
  0x2000，`.rodata` 与之地址重叠也不报错；`--change-section-address .text-0x10` 触发
  `out: section .text lma 0x1050 adjusted to 0x1058`（ELF 写回时按段边界校正 LMA）。
- 所有"节名不存在"的告警默认**开启**（`change_warn=true`）：`--change-section-vma .nosuch+0x10 never used`
  并列打印 lma/vma 两行；`--no-change-warnings` 关闭；`--change-warnings` 重新开启。语法错 →
  `bad format for --change-section-address`（exit 1）。
- `--change-section-vma` 与 `--change-section-address` 的 `=` 语义是"绝对设置"，`+`/`-` 为相对。
- `.dynamic`/`.hash/.gnu.hash`/重定位内容不随地址改写；需要自行重建（否则产出不可运行）。

```bash
objcopy --change-addresses 0x1000 $S c1; readelf -lW c1 | grep LOAD; readelf -dW c1 | head -6
objcopy --change-section-vma .data+0x1000 $S c2 2>&1; readelf -lW c2 | grep LOAD
objcopy --change-section-lma .data+0x1000 $S c3; readelf -lW c3 | grep -A1 'LOAD.*0x4010'
objcopy --set-section-alignment .text=4096 $S a1; readelf -SW a1 | grep ' .text '   # Al=32 (VMA 0x1060)
objcopy --set-section-alignment .init=4096 $S a2; readelf -SW a2 | grep ' .init '    # Al=4096 (VMA 0x1000)
objcopy --change-start 0x100 $S a3; readelf -hW a3 | grep Entry                    # 0x1160
```

---

## 7 符号操作

`filter_symbols()`（objcopy.c:1533）顺序要点：重命名 → 保留/删除判定（`STRIP_ALL` 一票否决）→
`-N`（strip_specific）→ `--strip-unneeded-symbol` → `-K`/`--keep-file-symbols` 救回 → 节被删则连带删符号 →
`-L/-G/--localize-hidden/--globalize-symbol` → `-W/--weaken`。

| 选项 | 效果 | 实测/注意 |
|---|---|---|
| `-K NAME` | 在 `-S` 下保留该符号 | `-S -K exported_fn` → `.symtab` 仅 [0]+exported_fn 两条，`sh_info=1`；节符号**不**保留 |
| `-N NAME` | 删除符号 | 若符号被重定位引用 → `not stripping symbol `x' because it is named in a relocation`，**整次复制失败**（exit 1，无输出） |
| `--strip-unneeded-symbol NAME` | 仅在未被重定位引用时删 | `-N` 与它都作用于全局/局部 |
| `-G NAME` | 除 NAME 外的**已定义**全局符号本地化 | 未定义全局（atoi/printf）保持 GLOBAL |
| `-L NAME` | 指定全局→LOCAL | 更新 `.symtab sh_info`（首全局索引） |
| `--globalize-symbol NAME` | 已定义 LOCAL→GLOBAL | 符号被移到全局块，`sh_info` 减 1；未定义符号不受理 |
| `-W NAME` / `--weaken` | 指定/全部已定义全局→WEAK | 未定义符号不变 |
| `--localize-hidden` | `STV_HIDDEN` 且已定义 → LOCAL | 只对 GLOBAL/WEAK |
| `--keep-file-symbols` | `-S` 下保留 STT_FILE | `-S --keep-file-symbols` → 只剩 [0]+`sample.c` |
| `--keep-section-symbols` | 仅对"不可重定位输出"补节符号 | `-S` 下仍不保留节符号；且 copy 表需要 `=值`（§1.7） |
| `-w` | 启用 `fnmatch(3)` 通配；`!pattern` 为否定义 | 无 `-w` 时按字面比较（`-N 'exported*'` 不匹配）；有 `-w` 时 `-N '*'` 会命中节符号 `.text` 而因重定位引用失败 |
| `--redefine-sym OLD=NEW` | 改名并同步重定位里的符号名 | 未定义符号也可改；同一 OLD 定义两次 fatal |
| `--redefine-syms FILE` | 批量 | 格式见 §1.6；解析错误 fatal、无输出 |

优先级实测：`-S -K main` 与 `-K main -S` 结果相同（都是只留 main），说明符号"保留"判定在 strip 决定之后统一做；
但"strip 等级"是单值，`-g -S` → strip-all，`-S -g` → strip-debug；`-S --only-keep-debug` → only-keep-debug；
`--only-keep-debug -S` → strip-all。

```bash
objcopy -S -K exported_fn $O k1.o; readelf -sW k1.o
objcopy -S --keep-file-symbols $O k2.o; readelf -sW k2.o
objcopy -N global_counter $O k3.o; echo rc=$?        # 失败，无 k3.o
objcopy -G exported_fn $O k4.o; readelf -sW k4.o | awk '$5!="LOCAL"'
objcopy --globalize-symbol helper_static $O k5.o; readelf -sW k5.o | grep helper
objcopy -w -N 'exported*' $O k6.o; echo rc=$?        # 命中重定位引用 → rc=1
objcopy -w -N '!exported_fn' $O k7.o; readelf -sW k7.o | grep -c exported_fn  # 1，! 排除
objcopy --redefine-sym atoi=my_atoi $O k8.o; readelf -rW k8.o | grep my_atoi
```

---

## 8 调试节压缩

| 选项 | 节名 | 节类型/标志 | 头部字节 | 对齐 |
|---|---|---|---|---|
| `zlib` | 不变 `.debug_info` | `SHT_PROGBITS`+`SHF_COMPRESSED`（readelf `C`） | `Elf64_Chdr`: `ch_type=1`(ZLIB), `ch_reserved=0`, `ch_size=原大小`, `ch_addralign=1`（小端） | 8 |
| `zlib-gabi` | 同上 | 同上 | 同上，**与 zlib 输出逐字节相同**（2.44） | 8 |
| `zlib-gnu` | `.debug_*` → `.zdebug_*`（`.rela.debug_*` → `.rela.zdebug_*`） | 无 SHF_COMPRESSED | 4 字节 `"ZLIB"` + **8 字节大端**原大小 + zlib 流 | 1 |
| `zstd` | 不变 | `SHF_COMPRESSED` | `ch_type=2`(ZSTD) | 8 |
| `none` / 不带值 | 不带值等价 `zlib`；`none` 不压缩 | – | – | – |

字节实测（`.debug_info`，原 0x1d7）：
```
zlib-gabi: 01 00 00 00 00 00 00 00 d7 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00 78 9c ...
zlib-gnu : 5a 4c 49 42 00 00 00 00 00 00 01 d7 78 9c ...
```
- `SHF_COMPRESSED` 节的 `sh_size` = 24(Chdr) + 压缩流；`zdebug` 节 = 12 + 压缩流，`sh_addralign=1`。
- **压缩率不划算则跳过**：`compress.c` 在 `compressed_size >= uncompressed_size` 时保持原节不压缩
  （实测 exec 的 `.debug_line/.debug_aranges/.debug_str` 未压缩，而 `.debug_info/.debug_abbrev` 压缩）。
- `--decompress-debug-sections`：两种格式都支持，恢复原名与原字节（`cmp` 相同），未压缩输入为 no-op，rc=0。
- `-S` 与压缩同时给时，`-S` 始终生效（debug 节先被删，压缩无从谈起），与选项先后无关。

```bash
objcopy --compress-debug-sections=zlib-gabi $O c.o
objcopy --dump-section .debug_info=di.bin c.o; od -Ax -tx1z -N 32 di.bin
objcopy --compress-debug-sections=zlib-gnu $O cg.o; readelf -SW cg.o | grep zdebug_info
objcopy --dump-section .zdebug_info=dz.bin cg.o; od -Ax -tx1z -N 16 dz.bin
objcopy --decompress-debug-sections cg.o d.o; readelf -SW d.o | grep debug_info
cmp <(objcopy -O binary -j .debug_info $O /dev/stdout) <(objcopy -O binary -j .debug_info d.o /dev/stdout)
```

---

## 9 错误、退出码与续做

通用：成功 0，任何 fatal/失败 1；**警告不改变退出码**；消息前缀 `objcopy: `（程序名）。常见实测（原始文本）：

| 场景 | stderr | rc | 产物/续做 |
|---|---|---|---|
| 输入不存在 | `objcopy: 'nosuchfile': No such file` | 1 | 无 |
| `-O` 非法目标 | `objcopy: out: invalid bfd target` | 1 | 无 |
| 空文件 | `objcopy: error: the input file 'empty.bin' is empty` | 1 | 无 |
| 非目标文件 | `objcopy: notobj.txt: file format not recognized` | 1 | 无 |
| 输出目录不存在 | `objcopy: nodir/out: No such file or directory` | 1 | 无 |
| 3 个文件参数 | 打印 usage 到 stderr | 1 | 无 |
| in==out（显式同名） | 无 | 0 | 走临时文件，正常 |
| 改字节序 | `objcopy: unable to change endianness of 'samples/sample.o'` | 1 | 无 |
| 跨架构重定位 | `objcopy: out: unsupported relocation type: 0x1` / `R_X86_64_64 unsupported` / `sorry, cannot handle this file` | 1 | 无 |
| 写 `/dev/full` | `objcopy: /dev/full[.note.gnu.property]: No space left on device` | 1 | 部分写入 |
| `-B` 非法 arch | `objcopy: architecture nosuch unknown` | 1 | 无 |
| thin archive | `objcopy: sorry: copying thin archives is not currently supported` | 1 | 无 |
| archive + debuglink | `objcopy: --add-gnu-debuglink ignored for archive %s` | 0 | 继续 |
| archive → binary | `objcopy: libfoo.bin: invalid operation` | 1 | 无 |
| `-R` 冲突（见 §5） | fatal 文本 | 1 | 无 |
| 临时文件创建失败 | `objcopy: warning: could not create temporary file whilst copying 'x', (error: Permission denied)` | 1 | 输入不动 |
| `-N` 命中重定位符号 | `not stripping symbol `x' because it is named in a relocation` | 1 | 整次复制放弃 |
| 未识别调试信息（`--debugging`） | `objcopy: x: no recognized debugging information` | 0 | 继续 |

**续做行为**：单文件模式失败即终止；archive 模式对每个成员独立处理（`copy_archive` 循环），成员失败会
置 status=1 但继续处理后续成员。`--dump-section` 的"节不存在"仅警告且 rc=0；
`--add-section` 重名、`--update-section` 缺节、`--redefine-*` 解析错都是致命（无输出文件）。

**跨类转换**：`-O elf32-i386` 从 ELF64 输入可"成功"（rc=0，无警告），地址/符号被**静默截断**
（`--change-section-address .text=0x100000000 -O elf32-i386` → `.text` 的 sh_addr 变 0，rc=0）。
`-I elf32-i386` 读 ELF64 输入同样被"转换"为 ELF32（rc=0）。

---

## 10 `--info`、合法 target 与架构

`objcopy --info`（88 行，`docs/notes/objcopy-info.txt`）格式逐行：
1. `BFD header file version (GNU Binutils for Debian) 2.44`；
2. 每个 target 一段：`<bfdname>` 顶格；下一行缩进 1 空格 ` (header <e> endian, data <e> endian)`；
   之后每行缩进 2 空格列出架构名；
3. 空行后是"架构 × 目标"矩阵：每 8 个目标一组，组标题行缩进 9 空格，随后每个架构一行
   （`   <arch> ` + 每个目标列宽 11，缺失写 `-----------` 或 `--------`）。

本 build 的 target（`--help` 末尾同列表）：
`elf64-x86-64 elf32-i386 elf32-iamcu elf32-x86-64 pei-i386 pe-x86-64 pei-x86-64 elf64-little elf64-big
elf32-little elf32-big pe-bigobj-x86-64 pe-i386 pdb srec symbolsrec verilog tekhex binary ihex plugin`。
其中 ELF：`elf64-x86-64 elf32-i386 elf32-iamcu elf32-x86-64 elf64-little elf64-big elf32-little elf32-big`。
架构名（`-B` 合法值）：`i386`、`iamcu`（`--info` 里每组 target 只列这两个）；
`x86-64`、`i686`、`elf64-x86-64` 均报 `architecture ... unknown`。
`elf32-little`/`elf64-big` 是通用目标：用于跨架构/跨字节序时，重定位类型不匹配会失败
（`R_X86_64_PC32 unsupported`），改字节序直接 `unable to change endianness`。

```bash
objcopy --info | sed -n '1,20p'; objcopy --info | tail -22
for a in i386 iamcu x86-64; do objcopy -I binary -O elf64-x86-64 -B $a raw.bin r.o \
  && readelf -hW r.o | grep Machine; done
```

---

## 11 兼容性陷阱清单（重写时最容易做错的点）

1. **`.shstrtab` 必须整体重建**：按输出节顺序生成、`sh_name` 重算，旧名不保留（`--rename-section` 后
   `strings out | grep rodata` = 0）。节头表顺序 = 输出节链顺序 = 原输入节顺序（过滤后）。
2. **重定位节不是"节"**：`.rela.*` 由 `copy_relocations_in_section()` 依据符号表重建，位置随目标节；
   `-R .rela.text` 静默无效；`-S` 因该函数提前返回而整体消失。
3. **`sh_link`/`sh_info` 必须重算**：`.symtab.info` = 首个非 local 索引；`.rela.info` = 目标节索引、
   `.rela.link` = 符号表索引；`SHT_GROUP` 的 `link`=符号表、`info`=签名符号索引。丢一个就会让 gdb/ld 拒绝。
4. **符号表 local/global 分区**：BFD 输出时 local 在前、global 在后，`--globalize-symbol` 会把符号移入
   global 块并使 `sh_info` 变化（15→13 实测）。不能只改 `st_info` 的 bind 位。
5. **`SHT_GROUP` 语义**：`-g` 保留组（link/info 随索引更新）；**`-S` 会把组整节删除**（签名符号被 strip）；
   `--only-keep-debug` 必须完整保留组（PR 29532）。重写时组签名符号必须一并保留/重排。
6. **PT_LOAD 的 `p_offset % p_align == p_vaddr % p_align`**，且文件偏移随 VMA 重排：改地址会导致段拆分/新增，
   不能只 patch `sh_addr`。实测 `--change-section-address .text=0x2000` 生成新 PT_LOAD、`.text` 文件偏移变 0x2000。
7. **`--change-addresses` 不修 `.dynamic`/重定位/`.hash`**：可产出"结构合法但不可运行"的文件（`readelf -d` 仍是旧地址）。
   要真正可运行必须重写 `DT_*`、`.rela.dyn`、`.gnu.hash`（objcopy 不做，保持兼容就不要多做）。
8. **NOBITS 的 `sh_offset` 不为 0**：它等于"若真有内容会放的位置"（原 `.bss` = 0x3030，等于 `.comment` 偏移）；
   `--only-keep-debug` 把大量节转 NOBITS 后 offset 仍是旧区域的起点。
9. **ELF32 溢出静默截断**：`-O elf32-i386` / `-I elf32-i386` 对 >4GiB 地址无警告、无错误，直接取低 32 位。
10. **`-O binary` 对 ET_REL 会互相覆盖**：所有节 LMA=0，输出长度 = 最大节 size，内容 = 最后写入的节（`.eh_frame`）。
    基址 = 满足 `HAS_CONTENTS|LOAD|ALLOC` 的最小 LMA（exec 上是 0x350 的 `.note.gnu.property`，不是 0x1000）。
11. **输出文件语义**：非空普通文件先 unlink（换 inode、权限重置）；符号链接被替换成普通文件；硬链接断开；
    空文件保留 inode。原地模式则是 `stXXXXXX` 临时文件 + `O_TRUNC` 拷回 + `fchmod(原 st_mode)`（保留 setuid）。
12. **可执行位 chmod 补丁**：ET_EXEC/ET_DYN 输出关闭时执行 `chmod(0777 & (mode|(0111&~umask)))`；
    ET_REL 不执行。新文件因此常见 0644→0755，umask 077 → 0700。
13. **`--gap-fill`/`--pad-to` 改的是节 `sh_size`**，不是"只在写 binary 时补零"；会改变 ELF 输出布局；
    `--pad-to` 对 NOBITS 尾节会产生 `section .bss lma ... adjusted to ...` 告警并挪 LMA。
14. **`--set-section-flags`/`--rename-section` 是"整体替换"**：缺 `contents` → `SHT_NOBITS`；
    `readonly` 缺省即 `W`；且 flags 作用于输出，不改变 strip 判定（strip 看输入节的 flags）。
15. **选项表 bug/差异**：`objcopy --keep-section-symbols` 需要 `=值`（copy_options 声明 required_argument）；
    `strip -S` 是 strip-debug、`strip -s` 才是 strip-all（strip_options 的 long option 映射不同）。
16. **节对齐会被截断**：段内节 `--set-section-alignment` 只能是能整除其 VMA/offset 的 2 的幂
    （`.text` 0x1060 → 最大 32；`.init` 0x1000 → 4096），静默截断无警告；ET_REL 不截断。
17. **压缩细节**：`zlib` == `zlib-gabi`（2.44 逐字节相同）；gabi 用 `Elf_Chdr`（24 字节，`ch_type` 1/2）；
    gnu 用 `.zdebug_` + `"ZLIB"` + 8 字节**大端**长度；`sh_addralign` 8 vs 1；压缩后不更小则放弃压缩。
18. **`.dynsym` 顺序与 hash 不可动**：`-S` 保持 `.dynsym` 顺序、保留 `.gnu.hash/.hash` 原样；链接/运行验证通过。
    若重写时重排 dynsym，必须重建 `.gnu.hash`（objcopy 不重建，重写也不要重建以保持兼容）。
19. **`--add-section` 的 alloc 节不进 PT_LOAD**，且打印 `warning: allocated section `.x' not in segment`；
    默认 flags 无 ALLOC、align=1、追加在最后。
20. **告警文本本身是兼容面**：例如 dump-section 缺节是 warning+rc0、`can't add section` 尾部带
    `: file format not recognized`（bfd 错误串残留）、原地失败消息以 `warning:` 开头但 rc=1。
    对照 `docs/notes/repro.sh` 的 golden 输出逐条比对。

---

## 附：源码索引（binutils 2.44）
- `binutils/objcopy.c`: `setup_section`(4142)、`copy_section`(4573)、`filter_symbols`(1533)、
  `is_strip_section_1`(1325)、`copy_relocations_in_section`(4486)、`copy_object`(2645)、
  `add_redefine_syms_file`(1806)、`strip_options`(384)/`copy_options`(423)。
- `binutils/rename.c`: `smart_rename`/`simple_copy`；`binutils/bucomm.c`: `make_tempname`（`stXXXXXX`）。
- `bfd/cache.c:bfd_open_file`（out 文件先 unlink）；`bfd/opncls.c:_maybe_make_executable`（chmod +x）、
  `bfd_openw`；`bfd/binary.c:binary_set_section_contents`（binary 基址/LMA）；
  `bfd/compress.c`（压缩/不更小则跳过）；`bfd/elf.c:assign_file_positions_for_load_sections`（段重排、
  6222 行 LMA 校正告警）、`_bfd_elf_is_local_label_name`（-X 规则）。
