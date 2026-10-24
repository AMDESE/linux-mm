# kunused

Find functions and variables in the Linux kernel that nothing uses.

```
$ scripts/kunused/kunused.py scan '^mm/' '^include/linux/mm'
include/linux/mm.h (7)
     60  totalram_pages_inc                 also tools/include/linux/mm.h:36
     65  totalram_pages_dec
   2448  cpupid_cpu_unset
...
mm/kmsan/hooks.c (1)
    383  kmsan_poison_memory                function [exported]

mm/memory.c (1)
   3031  vmf_insert_mixed_mkwrite           function
...
```

It looks for two kinds of dead code:

- **`static inline` functions** anywhere in the tree, mostly in headers,
  that have no caller.
- **Non-static functions and global variables** in `.c` files whose name
  shows up nowhere except in their own definition, prototypes, `extern`
  declarations, `!CONFIG` stubs, `#ifdef` lines, comments and
  `EXPORT_SYMBOL()`.

## Why the compiler doesn't catch these

`-Wunused-function` only covers `static` functions in the file being
compiled, and GCC never applies it to `static inline` functions. Clang
does, but the kernel marks every `inline` function `__maybe_unused`
unless you build with `W=2`. Even with `W=2`, clang skips inlines defined
in headers, because most files that include a header use only part of it.

A non-static function with a prototype in a header looks fine to every
compiler and linker check; nothing needs to call it. Object-file tools
such as `nm`/`readelf` collation only see one config at a time and never
see inlines.

kunused looks at the source of the whole tree at once, so it doesn't
depend on any config or architecture. A build is only used to cross-check
the results.

## Running it

It needs only Python 3.8 or later and git, with no other dependencies and
nothing to install. The build cross-check (`run`, or `mark` and `check`)
also needs what a kernel build needs (see
`Documentation/process/changes.rst`), including `gawk`: allmodconfig
turns on `BUILTIN_MODULE_RANGES`, which runs it at link time. The
examples below assume an alias, set from the top of your kernel tree:

```
alias kunused="$PWD/scripts/kunused/kunused.py"
```

The tool leaves its own directory out of the scan, because this README
and the tests name kernel symbols.

## Quick start

```
kunused run
```

This does everything for the whole kernel at HEAD:

1. scans the tree,
2. marks the candidates in a scratch worktree,
3. builds it with `allmodconfig`,
4. sorts the warnings,
5. writes the report.

Everything goes into `kunused-out/` next to the tree. Open
`report.html` in a browser.

| file | contents |
|---|---|
| `report.html` | the report; filter it by status, kind and tag |
| `results.tsv` | one line per candidate: status, name, kind, location, tags, MAINTAINERS section and list |
| `candidates.tsv` | the raw scan, for `list`, `mark` and `report` |
| `verify.json` | what the build cross-check found |
| `build.log` | the build's KUNUSED warnings and its errors |

The build is a full kernel build: about 10 minutes on 128 CPUs, an hour
or more on a laptop, and about 15 GB of disk while it runs. The worktree
and build directory are deleted at the end; `--keep` keeps them so the
next run builds incrementally. Other options:

```
kunused run -o DIR                 # put the output somewhere else
kunused run --no-build             # scan and report only, no build check
kunused run --config defconfig     # another config target, or a .config file
ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- kunused run   # another arch
LLVM=1 kunused run                 # build with clang
```

Local changes in the tree are left out: `run` scans and builds HEAD.
`results.tsv` is easy to filter from the shell:

```
awk -F'\t' '$1 == "verified" && $3 == "function"' kunused-out/results.tsv
grep -P '^verified\t' kunused-out/results.tsv | grep -v exported
```

The commands below are the steps `run` takes. Use them on their own to
look at one subsystem or to run the build yourself.

## Usage

Run inside a kernel git checkout, or pass `-C <tree>`.

```
kunused scan                       # list candidates, grouped by file
kunused scan '^mm/' '^include/linux/mm'   # only these paths
kunused scan --all                 # include [paste?], [non-c?], [uapi]
kunused scan -o cands.tsv          # save everything for later steps
kunused list cands.tsv '^fs/'      # list from a saved file
kunused report cands.tsv           # HTML report, see below
```

A whole-tree scan takes about two minutes on 128 CPUs. Each candidate
may carry tags:

| tag | meaning |
|---|---|
| `[via-unused]` | only called from other unused code; goes in the same patch |
| `[paste?]` | a `##` macro could build this name and not all of its uses could be followed; check by hand |
| `[paste-used]` | a `##` macro call builds this name, so it is used; `kunused paste NAME` shows where |
| `[non-c?]` | also named in a non-C file (Makefile, build rule, script); check by hand |
| `[uapi]` | in a uapi header; userspace may use it, so leave it alone |
| `[exported]` | has an `EXPORT_SYMBOL()`; out-of-tree modules don't count, but say so in the commit message |

By default the listing hides `[paste?]`, `[paste-used]`, `[non-c?]` and
`[uapi]` entries. `-o` writes all of them.

### Names built with `##`

A macro such as `#define LOCK(t) t##desc_lock` could build `zpdesc_lock`,
but only if something calls `LOCK(zp)`. For every name that some `##`
macro could spell, kunused works out each way the macro could spell it
(`t=zp` here) and reads every use of that macro in the tree. That is
plain text, so it covers every architecture and config at once:

- a call passes exactly those arguments: the name is used, `[paste-used]`;
- every use is shown to pass something else: no tag, the name is
  treated like any other candidate;
- anything it can't settle keeps `[paste?]`.

What it follows:

- calls from inside other macros, `#define WRAP(x) LOCK(x)` or
  `#define WRAP(x) LOCK(pre_##x)`, on to WRAP's callers, four levels deep;
- an argument that is itself a macro: it only counts as "something else"
  if no `#define` of it in the tree could give the needed text;
- a macro handed to a list macro, `LIST(LOCK)`, by reading where LIST's
  body calls it and with what;
- `#define ALIAS LOCK`, by reading ALIAS's uses;
- calls split over several lines, and comments inside macros.

A macro name that isn't followed by `(` and isn't handed to another
macro is never expanded, so it doesn't count. A `#define` in a `.c` or
`.S` file only counts in that file, unless some file includes it. Rust
code can't call a C macro, so `.rs` files are not read.

What stays `[paste?]` is mostly a wrapper whose arguments come from
another macro and may carry extra commas (`IBA_GET()` passes a field
macro that expands to four arguments), an argument whose `#define`
expands to several tokens, or a variadic list. Templates made only of
parameters, such as `a##b`, would match nearly every name and are not
used; see [Known limits](#known-limits).

`kunused paste NAME...` prints the reasoning:

```
$ kunused paste zpdesc_lock _iba_get16
zpdesc_lock: unused (3 ways to spell it, no use passes the pieces)
  SEQCOUNT_LOCKNAME(lockname, locktype, preemptible, lockbase) in include/linux/seqlock.h: needs lockbase=zpdesc; 8 uses -> unused
  wait_var_event_any_lock(var, condition, lock, type, state) in include/linux/wait_bit.h: needs type=zpdesc; 2 uses -> unused
  PLL_OUT(_num, _offset, _div_shift, _div_flags, _rst_shift, _id) in drivers/clk/tegra/clk-tegra-periph.c: needs _offset=zpdesc; 6 uses -> unused
_iba_get16: open (the args at include/rdma/iba.h:91 are put in from a macro and may hold commas)
  PORT_10(pn, fn, pfx, sfx) in drivers/pinctrl/renesas/sh_pfc.h: needs pfx=_iba_get1; 48 uses -> unused
  ...
  _IBA_GET(field_struct, field_offset, field_mask, num_bits, ptr) in include/rdma/iba.h: needs num_bits=16; 1 uses -> open (the args at include/rdma/iba.h:91 are put in from a macro and may hold commas)
```

Only source files count as uses: C, headers, assembly, Rust, linker
scripts, devicetree, syscall tables and a few similar types. A name that
also shows up in another tracked file gets `[non-c?]` instead of being dropped,
because such files sometimes generate code that calls it (the xe driver's
`.rules` files do) but more often mention it by coincidence. Files under
`Documentation/` don't count at all.

The scan for non-static code covers the whole tree except `tools/`,
`samples/`, `scripts/`, `rust/` and `usr/`. Code there is userspace, host
tools or Rust glue, whose functions are called by name from places this
tool can't see. Uses found in those directories still count. Use
`--extern-dir DIR` (repeatable) to restrict the scan to some directories.

## The HTML report

```
kunused report cands.tsv [--verify kunused-verify.json] \
        [--filter linux-mm@kvack.org] [--tsv results.tsv] -o report.html
```

This writes one self-contained page. Candidates are grouped by
MAINTAINERS section, showing its mailing list, and sections are ranked by
how many verified and not-built entries they have. Every candidate gets
one status:

| status | tier | meaning |
|---|---|---|
| verified | Sure: build-verified unused | no reference anywhere in the tree, no `##` doubt left, and a build compiled it and saw no use |
| not built | Unsure: not built | no reference anywhere, but no build compiled it; build a config that does first |
| unverified | Unsure: no build check | the same, when there was no build at all |
| check | Unsure: check by hand | `[non-c?]` or `[paste?]`, whatever the build said |
| uapi | Keep: userspace API | `[uapi]` |
| generated | Keep: generated or imported | generated file (it says "do not edit" etc.), or code synced from elsewhere (ACPICA, zstd, xz) |
| rejected | Rejected: a user was found | the build or a `##` macro call uses it; the report shows where |

Only "verified" is safe to remove without further checks.

Each row shows the status, the kind (`inline`, `function` or `variable`)
and the tags. The page can filter on all three, plus a text search:

- **Status:** tick a tier's box to show it. Only verified and not-built
  entries are shown at first.
- **Kind:** untick a kind to hide it.
- **Tags:** for each tag, choose to show any entry, only entries with
  the tag, or only entries without it. For example, `exported: without`
  leaves out everything with an `EXPORT_SYMBOL()`.

`--filter` matches a path, a MAINTAINERS section name or a mailing
list, so `--filter linux-mm@kvack.org` gives everything mm owns. Run
`report` inside the kernel tree so it can read MAINTAINERS.

## Cross-checking with a build

Text matching can be fooled. The usual cause is a `##` macro that builds
the name at compile time. To check the results against a real build,
kunused tags every definition and declaration of every candidate with
`__attribute__((__deprecated__("KUNUSED <name>")))` in a scratch
worktree. The compiler then warns at every reference it actually
compiles. `kunused run` does all of this; by hand, the steps are:

```
KSRC=~/linux                       # your kernel tree
cd $KSRC
kunused scan -o ~/cands.tsv
git worktree add --detach ~/linux-kunused HEAD
kunused mark ~/linux-kunused ~/cands.tsv

cd ~/linux-kunused
B=~/build-kunused
make O=$B allmodconfig
./scripts/config --file $B/.config -d WERROR \
    -d DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT -d DEBUG_INFO_DWARF4 \
    -d DEBUG_INFO_DWARF5 -e DEBUG_INFO_NONE
make O=$B olddefconfig
make -k -j$(nproc) O=$B KCFLAGS=-Wno-error=deprecated-declarations 2>&1 |
    grep -E 'deprecated: KUNUSED| error: ' > $B/kunused.log
grep -v 'deprecated: KUNUSED' $B/kunused.log   # compile errors, if any
kunused check ~/linux-kunused $B $B/kunused.log -o ~/kunused-verify.json

cd $KSRC
kunused report ~/cands.tsv --verify ~/kunused-verify.json -o ~/report.html
```

`mark` refuses to run if the worktree isn't at the commit the candidates
were scanned at, because the line numbers would not match. Turning off
`WERROR` and debug info keeps the build going and makes it faster. The
`grep` keeps the log small; without it, the log runs to gigabytes
because every warning comes with notes. Errors are kept so you can see
whether anything failed to build. Files that failed don't count as
compiled.

`check` sorts the warnings into three groups: references inside another
candidate's body (expected), `EXPORT_SYMBOL` lines (expected), and real
uses (the scanner was wrong). The warning message carries the
candidate's name, so a use is still attributed correctly when a macro
renames the symbol. `check` reads kbuild's `.*.cmd` files to tell which
candidates were in compiled files at all.

"Verified" therefore means three things together. The scanner found
no use anywhere in the tree, for any config or architecture. Every `##`
macro that could build the name was followed to its callers, again
across the whole tree. And the compiler saw no use in the code this
config builds, which catches anything the first two missed there. A
build can't see uses from Makefiles or scripts, nor a `##` use in code
it didn't compile, so `[non-c?]` and `[paste?]` candidates stay in
"check by hand" even when the build saw nothing.

A `[via-unused]` helper is only as unused as the code that calls it.
The build sees its call inside a candidate's body and counts it as
expected, so if that caller turns out to be used (rejected), or is only
"not built" or "check by hand", the helper gets the same status, and
the report says which caller it came from.

Cleanup: `git worktree remove --force ~/linux-kunused; rm -rf $B`.

### Other architectures and configs

A candidate that x86 allmodconfig doesn't compile (riscv-only code,
`mm/nommu.c`, KMSAN) is "not built" until some build compiles it. Clang
builds every architecture without a cross toolchain, so run `run` again
for the config that covers it, then give `report` both results:

```
kunused run                                   # x86 allmodconfig
ARCH=riscv LLVM=1 kunused run --config nommu_virt_defconfig -o ../kunused-nommu
kunused report ../kunused-out/candidates.tsv \
        --verify ../kunused-out/verify.json \
        --verify ../kunused-nommu/verify.json -o report.html
```

A candidate is verified when at least one build compiled it and no build
saw a use. Both runs have to be of the same commit; `report` checks.

## How accurate is it?

These numbers are from v7.3-2415-g7be4bc52fd9e, cross-checked with an
x86 allmodconfig build of the whole tree (about 10 minutes on 128 CPUs).

- The scan found 6054 candidates. 4560 of them were in files the build
  compiled, and 4221 of those (92.6%) had no compiled reference at all.
- The build found a use for the other 339, and the scan had already
  caught every one: 329 `[paste-used]`, where a `##` macro call builds
  the name, and 10 `[paste?]`, 2 of them also `[non-c?]`, where a build
  rule generates the call.
- The build can be fooled too. For 202 names it saw no use, yet a `##`
  macro call builds them: the caller sees a declaration the same macro
  pasted together, which carries no mark. octeontx2's mbox handler
  lists and BPF kfuncs are most of them. They come out as rejected.
- Another 341 build-clean names keep `[paste?]` and go to "check by
  hand".
- 11 build-clean `[via-unused]` helpers take the status of their
  caller instead: one is rejected, since a `##` call uses the function
  calling it, and 10 go to "check by hand".

In the report that gives 3003 "Sure", 1094 "not built", 403 "check by
hand" and 592 rejected. "No compiled reference" only holds for x86
allmodconfig; the "not built" entries are mostly other architectures'
code. Build those for their architecture and merge the results (see
[Other architectures and configs](#other-architectures-and-configs))
before sending patches.

## Known limits

- **Names built from pieces:** a stringified name looked up at runtime,
  or a symbol referenced from a linker script or assembly under a
  different name. A macro such as `#define foo bar` also hides callers
  that use `bar`. For `##`, only templates with some fixed text are
  followed: a call through an all-parameter paste such as
  `__PASTE(foo_, bar)()` is not seen by the scan. The build catches
  these in the code it compiles, which is why "Sure" needs a build that
  compiled the candidate.
- **Brand-new code:** an unused function added recently may have its
  first user still in flight on the list. Check `git log -S<name>` before
  sending a removal.
- **Heuristic parsing:** definitions are found with regexes, not a C
  parser, so an unusual declaration style can be missed. That only causes
  misses: every name that is reported has been counted across the whole
  tree.

## Sending patches

Group removals by MAINTAINERS section; the report already does this.
For each symbol, `git log -S'name(' --oneline` usually shows the commit
that removed the last user, which is worth citing in the changelog. Keep
`[via-unused]` helpers in the same patch as the function that called them.

## Prior art

- Nick Desaulniers' 2020 grep pipeline, discussed in Joe Perches'
  [follow-up](https://lkml.indiana.edu/2003.0/07547.html) with a list of
  about 1400 header inlines. It was a one-off script that left `##`
  pastes, config variants and uapi to manual review.
- Dr. David Alan Gilbert's
  [readelf collation](https://lists.openwall.net/linux-kernel/2024/09/16/565),
  which finds unreferenced symbols in built objects. It covers one config
  and doesn't see inlines.
- [uselex.rb](https://lkml.indiana.edu/1308.0/04097.html) (2013): `nm`
  based, with the same limits.
- [xunused](https://github.com/mgehre/xunused): clang based. It needs a
  `compile_commands.json`, so it is limited to one config.
- `W=1`/`W=2` builds: only unused `static` functions in `.c` files.

## Tests

```
python3 scripts/kunused/test_kunused.py
```

The fixture tree in `test_kunused.py` covers each case the scanners have to get
right: `#define`/`#ifdef` variants, arch overrides, strings and comments,
`##` pastes, chains, `!CONFIG` stubs, attribute macros, and marking or
checking a build. For `##` it has a case for each rule above, used and
unused, including the ones that must stay `[paste?]`: arguments that
expand to commas, several tokens, or a `(`.

## How it was written

The scripts were written with the help of an LLM-based coding assistant,
and reviewed and tested by the author.
