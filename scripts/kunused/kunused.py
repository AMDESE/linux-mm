#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Shivank Garg <shivankg@amd.com>
"""kunused: find unused functions and variables in the Linux kernel tree.

'%(prog)s run' does everything: it scans the whole tree, cross-checks
the results with an allmodconfig build and writes an HTML report.  The
other commands are the steps it runs, for use on their own.  Run
'%(prog)s <command> -h' for details; see scripts/kunused/README.md.
"""
import argparse
import json
import os
import re
import sys

import externs
import pastes
import pipeline
import verify
from candidates import (TAGS, print_listing, read_tsv, summary, tsv_commit,
                        write_tsv)
from pipeline import git_out, tree_commit
from report import Report
from source import Index, tree_files

__version__ = "0.1.0"


def path_filter(cands, regexes):
    if not regexes:
        return cands
    rx = re.compile("|".join(regexes))
    return [c for c in cands if any(rx.search(p) for p, _ in c.sites)]


def cmd_scan(args):
    cands = path_filter(pipeline.scan(args.jobs, args.only, args.extern_dir),
                        args.paths)
    if args.output:
        with open(args.output, "w") as f:
            write_tsv(cands, f, tree_commit())
        print(summary(cands), f"-> {args.output}")
    else:
        print_listing(cands, args.all)


def cmd_list(args):
    print_listing(path_filter(list(read_tsv(args.candidates)), args.paths),
                  args.all)


def cmd_mark(args):
    wt = args.worktree
    if not args.force:
        scanned = tsv_commit(args.candidates)
        head = git_out("rev-parse", "HEAD", cwd=wt)
        if scanned and (scanned.endswith("-dirty") or scanned != head):
            sys.exit(f"kunused: candidates were scanned at {scanned} but "
                     f"{wt} is at {head}; line numbers would not match "
                     "(--force to mark anyway)")
        if not os.path.exists(os.path.join(wt, verify.MARKS_FILE)) and \
           tree_commit(wt) != head:
            sys.exit(f"kunused: {wt} is not a clean git checkout; 'mark' "
                     "edits sources, use a scratch worktree (or --force)")
    n, files, skipped = verify.mark(wt, list(read_tsv(args.candidates)),
                                    args.jobs)
    print(f"marked {n} definition sites in {files} files"
          f" ({len(skipped)} skipped)")
    for s in skipped:
        print("  skipped:", s)


def cmd_check(args):
    res = verify.check(args.worktree, args.build, args.log)
    with open(args.output, "w") as f:
        json.dump(res, f, indent=1)
    w = res["warnings"]
    print(f"{res['build']} build: {res['compiled']} candidates compiled, "
          f"{len(res['not_built'])} not compiled\n"
          f"  confirmed unused: {len(res['confirmed'])}\n"
          f"  real uses found : {len(res['real_use'])} names "
          f"({w['real_use']} warnings; plus {w['chain']} inside other "
          f"candidates, {w['export']} EXPORT_SYMBOL lines)")
    for name, (loc, code) in list(res["real_use"].items())[:args.show]:
        print(f"    {name:<36} {loc}: {code[:60]}")
    if len(res["real_use"]) > args.show:
        print(f"    ... {len(res['real_use']) - args.show} more in "
              f"{args.output}")
    print(f"-> {args.output}")


def cmd_paste(args):
    pastes.explain(Index(tree_files(), args.jobs), args.names, args.jobs)


def cmd_report(args):
    ver = None
    if args.verify:
        results = []
        for path in args.verify:
            with open(path) as f:
                results.append(json.load(f))
        ver = verify.merge(results)
        scanned = tsv_commit(args.candidates)
        if scanned and ver.get("commit") and scanned != ver["commit"]:
            sys.exit(f"kunused: {args.candidates} was scanned at "
                     f"{scanned[:12]} but the build is of "
                     f"{ver['commit'][:12]}")
    if not os.path.exists("MAINTAINERS"):
        print("kunused: no MAINTAINERS here, everything lands in THE REST;"
              " run in the kernel tree or pass -C", file=sys.stderr)
    rep = Report(list(read_tsv(args.candidates)), ver, args.filter)
    with open(args.output, "w") as f:
        f.write(rep.html())
    if args.tsv:
        with open(args.tsv, "w") as f:
            f.write(rep.tsv())
    print(rep.text())
    print(f"-> {args.output}")


def parser():
    tags = "\n".join(f"  {'[' + t + ']':<13} {d}" for t, d in TAGS.items())
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version",
                    version=f"kunused {__version__}")
    ap.add_argument("-C", dest="tree", metavar="DIR",
                    help="kernel tree to work in (default: current directory)")
    ap.add_argument("-j", "--jobs", type=int, metavar="N",
                    help="worker processes (default: all CPUs)")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="command")

    p = sub.add_parser(
        "run", help="do it all: scan, build cross-check, report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Scan the whole tree at HEAD, mark the candidates in a "
        "scratch worktree,\nbuild it, check the warnings and write the "
        "report.  ARCH, LLVM,\nCROSS_COMPILE and other make variables "
        "come from the environment.",
        epilog="outputs:\n" + "\n".join(f"  {f:<15} {w}"
                                         for f, w in pipeline.OUTPUTS))
    p.add_argument("-o", "--output", metavar="DIR",
                   help="where to put everything (default: kunused-out "
                   "next to the tree)")
    p.add_argument("--config", default="allmodconfig",
                   metavar="TARGET|FILE",
                   help="config target or .config file to build "
                   "(default: %(default)s)")
    p.add_argument("--no-build", action="store_true",
                   help="scan and report only, without the build "
                   "cross-check")
    p.add_argument("--keep", action="store_true",
                   help="keep the worktree and build directory, so the "
                   "next run builds incrementally")
    p.set_defaults(func=pipeline.run)

    p = sub.add_parser("scan", help="scan the tree for unused code",
                       formatter_class=argparse.RawDescriptionHelpFormatter,
                       epilog="tags:\n" + tags)
    p.add_argument("paths", nargs="*", metavar="PATH_RE",
                   help="only keep candidates with a site matching a regex")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="write all candidates to a TSV file instead of "
                   "listing them")
    p.add_argument("--only", choices=("inlines", "externs"),
                   help="run just one of the two scanners")
    p.add_argument("--extern-dir", action="append", metavar="DIR",
                   help="look for unused non-static code only in .c files "
                   "under DIR (repeatable; default: whole tree except "
                   + ", ".join(externs.DEFAULT_SKIP) + ")")
    p.add_argument("--all", action="store_true",
                   help="also list [paste?], [non-c?] and [uapi] candidates")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("list", help="list candidates from a TSV file")
    p.add_argument("candidates", metavar="CANDIDATES.tsv")
    p.add_argument("paths", nargs="*", metavar="PATH_RE")
    p.add_argument("--all", action="store_true",
                   help="also list [paste?], [non-c?] and [uapi] candidates")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("mark", help="mark candidates in a scratch worktree")
    p.add_argument("worktree")
    p.add_argument("candidates", metavar="CANDIDATES.tsv")
    p.add_argument("--force", action="store_true",
                   help="mark even if the worktree has local changes or is "
                        "at another commit")
    p.set_defaults(func=cmd_mark)

    p = sub.add_parser("check", help="classify the marked build's warnings")
    p.add_argument("worktree")
    p.add_argument("build", metavar="BUILD_DIR", help="the O= directory")
    p.add_argument("log", metavar="BUILD_LOG",
                   help="make's output (see README for the grep)")
    p.add_argument("-o", "--output", default="kunused-verify.json",
                   metavar="FILE", help="default: %(default)s")
    p.add_argument("--show", type=int, default=20, metavar="N",
                   help="real uses to print (default: %(default)s)")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("report", help="write the HTML report")
    p.add_argument("candidates", metavar="CANDIDATES.tsv")
    p.add_argument("--verify", action="append", metavar="JSON",
                   help="output of 'check' or verify.json from 'run'; "
                   "repeat it to combine builds of other architectures "
                   "or configs")
    p.add_argument("--filter", action="append", default=[], metavar="RE",
                   help="only keep candidates whose path, MAINTAINERS "
                   "section or list matches (repeatable)")
    p.add_argument("-o", "--output", default="kunused-report.html",
                   metavar="FILE", help="default: %(default)s")
    p.add_argument("--tsv", metavar="FILE",
                   help="also write one line per candidate with its status")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("paste", help="show why a name is [paste?] or "
                       "[paste-used]",
                       description="List every '##' macro that could spell "
                       "each NAME, what arguments it would need, and what "
                       "its uses across the whole tree pass.")
    p.add_argument("names", nargs="+", metavar="NAME")
    p.set_defaults(func=cmd_paste)
    return ap


def main(argv=None):
    args = parser().parse_args(argv)
    for a in ("candidates", "worktree", "build", "log", "output", "tsv"):
        if getattr(args, a, None):
            setattr(args, a, os.path.abspath(getattr(args, a)))
    if getattr(args, "verify", None):
        args.verify = [os.path.abspath(v) for v in args.verify]
    if getattr(args, "config", None) and os.path.isfile(args.config):
        args.config = os.path.abspath(args.config)
    if args.tree:
        os.chdir(args.tree)
    top = git_out("rev-parse", "--show-toplevel")
    if top:
        os.chdir(top)                   # paths are relative to the tree top
    try:
        args.func(args)
    except BrokenPipeError:                     # e.g. 'kunused scan | head'
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
