# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Shivank Garg <shivankg@amd.com>
"""The whole workflow in one command: scan, mark, build, check, report."""
import json
import os
import shutil
import subprocess
import sys
import time

import externs
import inlines
import pastes
import verify
from candidates import write_tsv
from report import Report
from source import Index, tree_files

WARNING = f"deprecated: {verify.TAG}"
OUTPUTS = (
    ("report.html", "open in a browser; filter by status, kind and tag"),
    ("results.tsv", "one line per candidate: status, name, kind, location,"
                    " tags, section"),
    ("candidates.tsv", "the raw scan, for 'list', 'mark' and 'report'"),
    ("verify.json", "what the build cross-check found"),
    ("build.log", "the build's KUNUSED warnings and its errors"),
)


def git_out(*args, cwd=None):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                       text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def tree_commit(cwd=None):
    """HEAD, with '-dirty' if tracked files have local changes."""
    head = git_out("rev-parse", "HEAD", cwd=cwd)
    if head and git_out("status", "--porcelain", "--untracked-files=no",
                        cwd=cwd):
        head += "-dirty"
    return head


def scan(jobs=None, only=None, extern_dirs=None):
    """Candidates in the tree at the current directory."""
    index = Index(tree_files(), jobs)
    cands = []
    if only != "externs":
        cands += inlines.find(index)
    if only != "inlines":
        cands += externs.find(index, extern_dirs, jobs)
    pastes.settle(index, cands, jobs)
    return cands


def say(msg):
    print(f"kunused: {msg}", flush=True)


def minutes(seconds):
    return f"{seconds / 60:.0f}m" if seconds >= 60 else f"{seconds:.0f}s"


def run_quiet(cmd, cwd):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                       errors="replace")
    if r.returncode:
        sys.exit(f"kunused: '{' '.join(cmd)}' failed:\n{r.stderr[-3000:]}")


def configure(src, build, config, jobs):
    os.makedirs(build, exist_ok=True)
    make = ["make", f"-j{jobs}", f"O={build}"]
    if os.path.isfile(config):
        shutil.copy(config, os.path.join(build, ".config"))
        run_quiet(make + ["olddefconfig"], src)
    else:
        run_quiet(make + [config], src)
    run_quiet([os.path.join(src, "scripts", "config"), "--file",
               os.path.join(build, ".config"), "-d", "WERROR",
               "-e", "DEBUG_INFO_NONE"], src)
    run_quiet(make + ["olddefconfig"], src)


def build_tree(src, build, jobs, log_path):
    """Build with make -k, keeping only KUNUSED warnings and errors.
    Returns (files compiled, error lines)."""
    kcflags = os.environ.get("KCFLAGS", "")
    cmd = ["make", "-k", f"-j{jobs}", f"O={build}",
           f"KCFLAGS={kcflags} -Wno-error=deprecated-declarations".strip()]
    start = shown = time.monotonic()
    units, errors = 0, []
    tty = sys.stdout.isatty()
    with open(log_path, "w") as log, \
         subprocess.Popen(cmd, cwd=src, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True,
                          errors="replace") as p:
        for line in p.stdout:
            if WARNING in line:
                log.write(line)
            elif " error: " in line or line.startswith("make") and \
                    "***" in line:
                log.write(line)
                errors.append(line.rstrip())
            elif line.startswith("  CC"):
                units += 1
            now = time.monotonic()
            if now - shown >= (2 if tty else 60):
                shown = now
                msg = (f"  building: {units} files compiled, "
                       f"{len(errors)} error lines, {minutes(now - start)}")
                print("\r" + msg if tty else msg, end="" if tty else "\n",
                      flush=True)
    if tty:
        print()
    return units, errors


def remove_worktree(src):
    if os.path.exists(src):
        git_out("worktree", "remove", "--force", src)
        if os.path.exists(src):
            sys.exit(f"kunused: {src} exists and is not a worktree of "
                     "this tree; remove it or pick another -o")


def run(args):
    start = time.monotonic()
    out = args.output or os.path.join(os.path.dirname(os.getcwd()),
                                      "kunused-out")
    os.makedirs(out, exist_ok=True)
    jobs = args.jobs or os.cpu_count()
    path = {f: os.path.join(out, f) for f, _ in OUTPUTS}
    ver = None

    if args.no_build:
        for f in ("verify.json", "build.log"):      # from an earlier run
            if os.path.exists(path[f]):
                os.remove(path[f])
        say("scanning the whole tree")
        cands = scan(jobs)
        with open(path["candidates.tsv"], "w") as f:
            write_tsv(cands, f, tree_commit())
    else:
        top, head = os.getcwd(), git_out("rev-parse", "HEAD")
        if not head:
            sys.exit("kunused: 'run' needs a git checkout of the kernel")
        if tree_commit() != head:
            say(f"local changes are left out: the scan and build use "
                f"HEAD ({head[:12]})")
        src, build = os.path.join(out, "src"), os.path.join(out, "build")
        remove_worktree(src)
        git_out("worktree", "prune")
        if git_out("worktree", "add", "--detach", src, head) is None:
            sys.exit(f"kunused: could not create a worktree at {src}")
        os.chdir(src)

        say(f"scanning the whole tree at {head[:12]}")
        cands = scan(jobs)
        with open(path["candidates.tsv"], "w") as f:
            write_tsv(cands, f, head)
        n, files, _ = verify.mark(src, cands, jobs)
        say(f"{len(cands)} candidates; marked {n} sites in {files} files")

        say(f"configuring {args.config} in {build}")
        configure(src, build, args.config, jobs)
        say(f"building with -j{jobs}; this is a full kernel build")
        units, errors = build_tree(src, build, jobs, path["build.log"])
        if errors:
            say(f"{len(errors)} error lines; files that failed don't count "
                "as compiled. First ones:")
            for e in errors[:5]:
                print("   ", e[:150])

        ver = verify.check(src, build, path["build.log"])
        ver["config"] = os.path.basename(args.config)
        ver["commit"] = head
        with open(path["verify.json"], "w") as f:
            json.dump(ver, f, indent=1)
        if not ver["compiled"]:
            say("the build compiled none of the candidates; see build.log."
                " The report is not cross-checked.")
            ver = None

    rep = Report(cands, ver)
    with open(path["report.html"], "w") as f:
        f.write(rep.html())
    with open(path["results.tsv"], "w") as f:
        f.write(rep.tsv())
    print()
    print(rep.text())

    if not args.no_build:
        os.chdir(top)
        if args.keep:
            say(f"kept the worktree {src} and the build {build}")
        else:
            remove_worktree(src)
            shutil.rmtree(build, ignore_errors=True)
    print(f"\nDone in {minutes(time.monotonic() - start)}. In {out}:")
    for f, what in OUTPUTS:
        if os.path.exists(path[f]):
            print(f"  {f:<15} {what}")
