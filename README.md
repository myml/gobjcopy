# gobjcopy

纯 Go 实现的 objcopy 工具链，不依赖 cgo、不依赖任何第三方库。

项目分三层，依赖方向严格单向：

```
cmd/gobjcopy   CLI：GNU getopt 解析、选项映射、退出码
    │
objcopy/       变换管线：Transform / Run，节、符号、地址、压缩、debuglink…
    │
elf/           纯 ELF 模型与读写：只 import 标准库
```

配套包：

| 包 | 作用 |
| --- | --- |
| `internal/getopt` | GNU getopt_long 语义（前缀缩写、粘参、可选参数、`--`） |
| `internal/bfdtarget` | BFD target / `-B` 架构名 ↔ Class / Data / Machine |
| `internal/ar` | GNU ar 归档读写 |
| `internal/elfdump`、`internal/fixtures` | 测试辅助：语义快照、样例构建 |
| `test/` | 与 GNU objcopy 的 CLI 差分测试 |
| `scripts/` | 官方 testsuite 与覆盖率脚本 |
| `docs/` | binutils 2.44 行为调研与实测记录 |

## 构建与使用

```bash
go build -o gobjcopy ./cmd/gobjcopy
./gobjcopy --help
./gobjcopy --info
```

Go 1.24+。也可以直接当库用：

```go
import (
    "github.com/myml/gobjcopy/elf"
    "github.com/myml/gobjcopy/objcopy"
)

f, err := elf.Open("a.out")        // 解析
// …直接修改 f.Sections / f.Segments / f.Entry …
err = f.WriteFile("b.out", 0o755)  // 重新布局并写出

// 或直接跑一次 objcopy 变换
cfg := objcopy.Default()
cfg.StripDebug = true
cfg.RemoveSections = []string{".comment"}
err = objcopy.Run(cfg, "in", "out")
```

`elf` 包的能力：

- 读：ELF32/ELF64、大小端、扩展编号、无节头表、`SHT_SYMTAB_SHNDX`。
- 写：自动重算节偏移、`PT_LOAD` 的 `p_offset % p_align == p_vaddr % p_align` 约束、
  `p_filesz/p_memsz`、非 LOAD 段偏移、节头表；字符串表按 BFD 风格做后缀共享。
- 改：`RemoveSection`（同时丢弃该节符号并重映射重定位）、`InsertSection`、
  `AddSection`、`SetSymtab`、`SetRelocs`、`ConvertClass`（ELF32↔ELF64）。
- 安全：畸形的超大偏移/尺寸会被拒绝，不会尝试分配几百 GB。

## CLI 兼容性

选项表与 GNU objcopy 2.44 的 `copy_options` 一一对应（102 个长选项 + 全部短选项），
包括前缀缩写、`-j.text`、`-Sg`、`--` 等 getopt_long 行为。

| 类别 | 支持情况 |
| --- | --- |
| 节 | `-R`/`-j`/`--keep-section`（含 `!` 否定与通配符）、`--rename-section`、`--set-section-flags`、`--set-section-alignment`、`--add-section`、`--update-section`、`--dump-section`、`--remove-relocations`、`--strip-section-headers` |
| 符号 | `-S`、`-g`、`--strip-unneeded`、`-x`、`-X`、`-K`、`-N`、`-G`、`-L`、`--globalize-symbol`、`-W`、`--weaken`、`--redefine-sym(s)`、`-w`、`--keep-file-symbols`、`--keep-section-symbols`、`--localize-hidden`、`--add-symbol`、`--elf-stt-common` |
| 调试 | `--only-keep-debug`、`--add-gnu-debuglink`、`--compress-debug-sections=zlib/zlib-gabi/zlib-gnu`、`--decompress-debug-sections`、`--strip-dwo`、`--extract-dwo`、`-M/--merge-notes` |
| 地址/布局 | `--change-addresses`、`--adjust-vma`、`--change-section-address/vma/lma`、`--set-start`、`--change-start`、`--gap-fill`、`--pad-to`、`--reverse-bytes`、`--interleave/--byte/--interleave-width` |
| 格式 | `-O binary/ihex/srec/verilog`、`-I binary/ihex/srec`、`-I/-O/-F elf{32,64}-*`、`-B`、`--info`、`--srec-len`、`--srec-forceS3`、`--verilog-data-width`、ELF32↔ELF64 类转换（x32） |
| 归档 | `.a` 读写、成员逐个变换、符号索引重建、`-D/-U` 确定性归档 |
| 其他 | `-p`、`-v`、`--version`、原地修改、权限位复制；warning 不影响退出码 |

`-O binary`、`-I binary`、`--strip-section-headers` 的输出与 GNU **逐字节一致**。

## 验收结果

验收标准是 binutils 2.44 自带的官方 testsuite，而不是本项目自己的测试。

```bash
scripts/binutils-objcopy-tests.sh        # 只跑 objcopy.exp（验收目标）
scripts/binutils-objcopy-tests.sh full   # 整个 binutils testsuite
```

主机 x86_64-pc-linux-gnu 上的结果：

```
objcopy.exp     115 PASS / 0 FAIL / 2 unsupported     ← 与 GNU 自身的 115 PASS 完全一致
全部 binutils    320 PASS / 4 FAIL / 1 xfail / 3 unsupported
```

仅剩的 4 个 FAIL 全部来自 `compress.exp`，原因见下一节；它们不在 `objcopy.exp` 内。

### 交叉目标（aarch64 / loongarch64）

同一套官方 testsuite 也可以跑交叉 binutils。先准备一个 `configure --target=...`
并执行过 `make all-binutils all-gas all-ld` 的构建目录，再用 `--target` 指定三元组、
`--build-dir` 指定该目录：

```bash
scripts/binutils-objcopy-tests.sh --target aarch64-linux-gnu --build-dir /tmp/bu-arm64
scripts/binutils-objcopy-tests.sh --target loongarch64-linux-gnu --build-dir /tmp/bu-la64
```

脚本会构建当前 gobjcopy、替换构建目录里的 `binutils/objcopy`、执行
`make check-binutils RUNTESTFLAGS="objcopy.exp"`，并输出 PASS/FAIL 计数、失败列表
和日志路径；多次运行之间用 flock 串行化。binutils 的 testsuite 用
`<target>-cc` / `<target>-gcc` 编译可执行样例，而发行版可能只装了带版本号的名字
（例如 Debian 只有 `loongarch64-linux-gnu-gcc-13`），脚本会自动在 `PATH` 前插入
只含符号链接的目录补齐这两个名字，因此 executable 用例不会被记成 UNTESTED。

实测（binutils 2.44，0 FAIL）：

```
aarch64-linux-gnu        110 PASS / 0 FAIL / 5 unsupported（另 1 个 XFAIL）
loongarch64-linux-gnu    111 PASS / 0 FAIL / 5 unsupported
```

`test/crossarch_test.go` 在两种交叉 gcc 与交叉 objcopy 都在 `PATH` 上时，用
hello.c 构造 PIE、非 PIE 和 `.o`，逐项做交叉差分：copy、`-S`、`-g`、
`--only-keep-debug`、`-K`、`--strip-unneeded`、`-j .text`、`-R .comment`、
`--add-symbol`、`--change-section-address .text+0x10`、`--strip-section-headers`、
`-O binary`。ELF 结果用 `internal/elfdump.Default` 比较节/符号/重定位/内容
（忽略文件偏移与程序头布局，`-O binary` 逐字节比较）；compress 类操作因 zlib
字节差异不参与比较。工具链缺失时该测试自动 skip。

## 为什么 compress.exp 里有 4 个 zlib 用例过不了

这 4 个用例是：

```
objcopy compress debug sections 3 with zlib-gabi
objcopy decompress compressed debug sections 3 with zlib-gabi
objcopy zlib-gabi compress debug sections 3 with zlib-gnu
objcopy zlib-gabi compress debug sections with zlib-gnu
```

它们不是“功能不对”，而是**要求压缩后的字节与 GNU 完全相同**：测试用 `cmp`
比较 gobjcopy 的输出和 gas/GNU objcopy 生成的 `.o`，一个字节都不能差。

问题出在 deflate 实现上：

- GNU 用的是 **C zlib** 的 deflate（默认压缩级别），gobjcopy 用的是 Go 标准库
  `compress/flate`。两者都是合法的 zlib 流，但匹配策略、块划分、Huffman 树构造
  都不同，**同一段输入压缩出来的字节数和内容不一样**。
- 具体到测试里的 dw2-3 对象：`.debug_line` 有 66 字节，C zlib 压出 50 字节，
  Go 的 flate 压出 58 字节。差 8 字节就意味着文件布局、`e_shoff`、
  后续所有偏移都不同，`cmp` 必然失败。
- 这不是“压缩得不好”：我们产出的仍然是标准 zlib 流，GNU 的 `objcopy`/`readelf`/
  `objdump` 都能正常读取和解压；反过来，GNU 压出来的文件我们也能正确解压。
  `--decompress-debug-sections`、gabi↔gnu 互转的语义都是对的，只是字节不同。
- 另外 `objcopy decompress ... 3 with zlib-gabi` 这一项，解压本身正确，
  失败点是重写后的 `.shstrtab` 顺序与 BFD 不同（BFD 会把 `.debug_info` 当作
  `.rela.debug_info` 的后缀共享，我们的表按节顺序追加，大了 24 字节），
  同样导致 `cmp` 失败。

要做到逐字节一致只有两条路：

1. **引入 cgo + 系统 zlib**（或 vendored C 代码）。这是 GNU 工具链的做法，
   能立刻通过这 4 个用例，但会破坏本项目“纯 Go、无 cgo、无第三方依赖”的约束。
2. **用纯 Go 复刻 zlib 的 deflate 算法**（`deflate.c`/`trees.c` 的匹配与块划分），
   工作量大且极易出错，收益只是 4 个字节级测试。

因此当前选择是：保持纯 Go，语义与互操作完全正确，接受这 4 个字节级差异。
如果将来更看重“与 GNU 逐字节一致”，可以加一个 `cgo` 构建标签作为可选后端，
默认构建仍保持纯 Go。

## 测试覆盖率

```bash
scripts/coverage.sh                 # 全仓按文件统计（-coverpkg=./...）
go test ./... -cover               # 各包自身覆盖率
```

当前总覆盖率 **94.4%（4226/4475 statements）**。主要模块：

| 文件 | 覆盖率 | 文件 | 覆盖率 |
| --- | ---: | --- | ---: |
| `elf/names.go`、`elf/types.go` | 100% | `elf/convert.go` | 99.4% |
| `internal/elfdump`、`internal/getopt` | 100% | `elf/reader.go` / `writer.go` | 99.3 / 99.1% |
| `cmd/gobjcopy/options.go` | 100% | `objcopy/notes.go` | 99.2% |
| `internal/ar` | 97.9% | `objcopy/contents.go` | 97.8% |
| `objcopy/archive.go` | 97.5% | `objcopy/compress.go` | 97.3% |
| `objcopy/debuglink.go` | 96.2% | `elf/note.go` | 95.4% |
| `objcopy/sections.go` | 94.6% | `objcopy/symbols.go` | 86.9% |
| `objcopy/run.go` | 89.6% | `objcopy/format_srec.go` | 84.8% |

未覆盖的主要是不可达的防御分支（如 `Write`/`Close` 的 zlib 错误、`runtime.GOARCH`
其它架构的 switch 分支、`Bytes` 永不失败的错误返回）以及 ASCII 格式的少数错误路径。

## 已知差异与限制

1. **未实现的格式**：PE/COFF、Mach-O、symbolsrec、tekhex。
   对应的 PE 专用选项（`--file-alignment/--heap/--image-base/--section-alignment/--stack/--subsystem/--writable-text/--readonly-text/--pure/--impure`）
   以及 `--extract-symbol`、`--prefix-*`、`--*-leading-char`、`--alt-machine-code`、
   `--long-section-names` 仍然只解析、不生效。
2. **类转换仅支持 ET_REL**：ET_EXEC/ET_DYN 会明确报错（GOT、`init_array`、
   代码里内嵌的地址无法安全重排）。
3. **程序头重建策略不同**：GNU 在重排时可能丢弃 `PT_GNU_RELRO`，或把被删节对应的段
   清成 0 长度；gobjcopy 保留 RELRO（更安全）并丢弃失去节的段。节、符号、重定位、
   段内数据一致，差分测试只比较 LOAD 段。
4. **`--rename-section` 同时替换 flags** 时，GNU 2.44 会把节内容清零（疑似 bug），
   gobjcopy 保留内容。
5. **字符串表布局**：GNU 的 `_bfd_elf_strtab` 后缀合并更激进，`.strtab/.shstrtab`
   通常比我们小几字节；符号名与索引语义一致。
6. **`-j` 在可重定位文件上**：GNU 2.44 会因子符号表为空而致命失败，gobjcopy 会丢弃
   失效重定位并成功输出。
7. 非 x86 目标使用简化 target 名（`elf64-aarch64` 而非 `elf64-littleaarch64`），
   但 `--info` 列出的名字都能解析回来。
8. 大端 ELF 的写出路径已实现，但测试环境没有大端样本，未做真机验证。
9. **`-R` 删掉可重定位文件里被重定位引用的节**：GNU 会以
   `symbol '.debug_info' required but not present` 致命退出；gobjcopy 在
   `elf.RemoveSection` 里已把引用被删符号的重定位一并丢弃，因此能成功输出。
10. **手工构造的 x86 可执行文件做无操作复制**：如果输入里带未使用的 section
    符号，GNU 会重写文件并丢弃它们；gobjcopy 的“无变化就逐字节复制”捷径会原样
    保留。官方 `objcopy.exp` 的 `cmp` 用例不受影响（ld 生成的可执行文件没有这类
    符号）。

## 测试

```bash
go test ./...                                      # 单元 + 往返 + 差分
GOBJCOPY=$PWD/gobjcopy go test ./test -run TestDifferential -v
go test ./objcopy -run TestGNUSemanticParity -v    # 与 GNU 逐项对比
scripts/binutils-objcopy-tests.sh                  # 官方 objcopy.exp
scripts/binutils-objcopy-tests.sh full             # 整个 binutils testsuite
```

- **elf 测试**：全 fixture 往返（PIE/非 PIE/静态/共享库/32 位/压缩调试/自定义节），
  重写后的可执行文件实际运行并比对输出，readelf 交叉校验，序列化幂等性，fuzz 种子，
  以及 convert/names/note 等模块的表驱动测试。
- **objcopy 对拍**：35+ 个变换分别经 GNU 与库执行，用 `internal/elfdump` 比较
  节/符号/重定位/内容的语义等价；二进制输出逐字节比较。
- **CLI 差分**：`test/` 下 51 个用例、76 个子测试，比较退出码、错误文本、输出文件；
  脚手架可将被测程序换成 `/usr/bin/objcopy` 自检。
- **官方套件**：直接替换 binutils 构建目录里的 `objcopy`，用 DejaGnu 跑 `objcopy.exp`。
- **GNU 行为依据**：`docs/gnu-objcopy-behavior.md` 记录了 binutils 2.44 源码
  （`binutils/objcopy.c`、`bfd/elf.c`、`bfd/compress.c` 等）与实测结论。

## 目录

```
elf/            reader.go writer.go symbols.go edit.go convert.go names.go note.go types.go
objcopy/        run.go options.go sections.go symbols.go contents.go binary.go
                compress.go debuglink.go notes.go archive.go classconv.go format_*.go
cmd/gobjcopy/   main.go options.go help.go
internal/       getopt/ bfdtarget/ ar/ elfdump/ fixtures/
test/           differ_test.go helpers_test.go
scripts/        binutils-objcopy-tests.sh coverage.sh
docs/           gnu-objcopy-behavior.md notes/
```

## 许可证

GNU General Public License v3.0，见 `LICENSE`。
