# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Shivank Garg <shivankg@amd.com>
"""Cross-check candidates against a real kernel build.

'mark' prefixes every definition and declaration of every candidate in a
scratch worktree with __attribute__((__deprecated__("KUNUSED"))), on the
same line so line numbers do not move.  After building that worktree with
warnings allowed, the compiler has reported every reference it compiled.
'check' sorts those warnings into:

  chain     inside the body of another candidate (expected)
  export    an EXPORT_SYMBOL*() line (expected)
  real use  anything else: the scanner was wrong about that name

and works out which candidates live in files the build compiled at all.
"""
import json
import os
import re
import subprocess

import externs
from source import brace_body, lex, tree_files

TAG = "KUNUSED"
# Every mark starts with MARK; the message names the candidate, since a
# macro may rename the symbol the compiler warns about.
MARK = f'__attribute__((__deprecated__("{TAG}'


def mark_attr(name):
    return f'{MARK} {name}"))) '
MARKS_FILE = ".kunused-marks.json"
# The build verifies checksums of these generated headers.
UNMARKABLE = ("include/linux/atomic/",)


def stmt_start(lines, idx, want_static):
    """Index of the line where the declaration containing lines[idx] starts."""
    for i in range(idx, max(idx - 5, -1), -1):
        s = lines[i].lstrip()
        if i < idx:
            p = lines[i].rstrip()
            if not p or p.endswith((";", "}", "{", "*/", "\\")) or \
               s.startswith(("#", "//")) or \
               (i > 0 and lines[i - 1].rstrip().endswith("\\")):
                return None if want_static else i + 1
        if s.startswith(MARK) or (want_static and s.startswith("static")):
            return i
    return None if want_static else idx


def body_range(text, line):
    """(first, last) line of the {...} body of the definition at 'line'."""
    lexed = lex(text)
    off = sum(len(l) + 1 for l in lexed.split("\n")[:line - 1])
    m = re.compile(r"\)\s*(?:__\w+\s*(?:\([^()]*\))?\s*)*\{").search(lexed, off)
    if not m or lexed.count("\n", off, m.start()) > 6:
        return None
    body = brace_body(lexed, m.end() - 1)
    first = lexed.count("\n", 0, m.end() - 1) + 1
    return first, first + body.count("\n")


class Files:
    """Line-level view of files under 'root', written back on demand."""

    def __init__(self, root):
        self.root, self.cache, self.dirty = root, {}, set()

    def lines(self, path):
        if path not in self.cache:
            with open(os.path.join(self.root, path), encoding="utf-8",
                      errors="surrogateescape") as f:
                self.cache[path] = f.read().split("\n")
        return self.cache[path]

    def mark(self, path, idx, name):
        lines = self.lines(path)
        if MARK in lines[idx]:
            return
        body = lines[idx].lstrip()
        lines[idx] = lines[idx][:len(lines[idx]) - len(body)] + \
            mark_attr(name) + body
        self.dirty.add(path)

    def write(self):
        for path in self.dirty:
            with open(os.path.join(self.root, path), "w", encoding="utf-8",
                      errors="surrogateescape") as f:
                f.write("\n".join(self.cache[path]))


def mark(worktree, cands, jobs=None):
    """Mark 'cands' in 'worktree'.  Returns (definition sites recorded,
    files changed, sites that could not be marked)."""
    os.chdir(worktree)
    tree, marks, skipped = Files("."), [], []
    ext = []
    for c in cands:
        if c.kind != "inline":
            ext.append(c)
            continue
        if "uapi" in c.tags:
            continue
        for path, line in c.sites:
            if path.startswith(("tools/",) + UNMARKABLE):
                continue
            lines = tree.lines(path)
            i = stmt_start(lines, line - 1, True)
            if i is None:
                skipped.append(f"{c.name} {path}:{line}")
                continue
            tree.mark(path, i, c.name)
            marks.append({"name": c.name, "kind": c.kind, "file": path,
                          "line": line, "tags": c.tags,
                          "body": body_range("\n".join(lines), line)})

    files = [f for f in tree_files()
             if f.endswith((".c", ".h")) and not f.startswith("tools/")]
    hits = externs.grep(files, {c.name for c in ext}, jobs)
    for c in ext:
        path, line = c.sites[0]
        lines = tree.lines(path)
        tree.mark(path, stmt_start(lines, line - 1, False), c.name)
        marks.append({"name": c.name, "kind": c.kind, "file": path,
                      "line": line, "tags": c.tags,
                      "body": None if c.kind == "variable" else
                      body_range("\n".join(lines), line)})
        for h, decl in hits[c.name]:            # prototypes, stubs, externs
            f, ln, code = h.split(":", 2)
            if not decl or (f, int(ln)) == (path, line) or \
               re.match(r"\s*(/\*|\*|//|#)", code) or "EXPORT_SYMBOL" in code:
                continue
            stub = re.match(r"\s*static\s", code) is not None
            i = stmt_start(tree.lines(f), int(ln) - 1, stub)
            if i is not None:
                tree.mark(f, i, c.name)

    tree.write()
    if os.path.exists(MARKS_FILE):          # marking again adds to the list
        seen = {(m["name"], m["file"], m["line"]) for m in marks}
        with open(MARKS_FILE) as f:
            marks += [m for m in json.load(f)
                      if (m["name"], m["file"], m["line"]) not in seen]
    with open(MARKS_FILE, "w") as f:
        json.dump(marks, f)
    return len(marks), len(tree.dirty), skipped


def _norm(root, build, p):
    i = p.find(root + "/")
    if i >= 0:
        return os.path.normpath(p[i + len(root) + 1:])
    return os.path.relpath(os.path.realpath(os.path.join(build, p)), root)


def compiled_files(root, build):
    """Source files the build read, from kbuild's .*.cmd dependency files."""
    raw = set()
    tok = re.compile(r"[^\s:\\$()]+\.[chS]\b")
    for d, _, files in os.walk(build):
        for fn in files:
            if fn.endswith(".cmd") and fn.startswith("."):
                with open(os.path.join(d, fn), errors="replace") as f:
                    raw.update(tok.findall(f.read()))
    return {_norm(root, build, t) for t in raw}


def build_name(build):
    """'Linux/x86 7.3.0-rc7' from the .config header, if there is one."""
    try:
        with open(os.path.join(build, ".config")) as f:
            for line in f:
                m = re.match(r"# (Linux/\S+ \S+) Kernel Configuration", line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return "kernel"


def check(worktree, build, log):
    """Classify the build's warnings; returns the result dict."""
    root = os.path.realpath(worktree)
    build = os.path.realpath(build)
    with open(os.path.join(root, MARKS_FILE)) as f:
        marks = json.load(f)
    bodies, by_name = {}, {}
    for m in marks:
        if m["body"]:
            bodies.setdefault(m["file"], []).append((m["body"], m["name"]))
        if not m["file"].startswith(UNMARKABLE):
            by_name.setdefault(m["name"], []).append(m)

    warn_re = re.compile(r"^(\S+?):(\d+):\d+: (?:warning|error): "
                         rf"['\u2018](\w+)['\u2019] is deprecated: "
                         rf"{TAG}(?: (\w+))? \[")
    seen, counts, real = set(), {"chain": 0, "export": 0}, {}
    tree = Files(root)
    with open(log, errors="replace") as f:
        for line in f:
            if f"deprecated: {TAG}" not in line:
                continue
            w = warn_re.match(line)
            if not w:
                continue
            path, ln = _norm(root, build, w.group(1)), int(w.group(2))
            name = w.group(4) or w.group(3)
            if (path, ln, name) in seen:
                continue
            seen.add((path, ln, name))
            try:
                code = tree.lines(path)[ln - 1].strip()
            except (OSError, IndexError):
                code = ""
            if any(a <= ln <= b for (a, b), _ in bodies.get(path, ())):
                counts["chain"] += 1
            elif "EXPORT_SYMBOL" in code:
                counts["export"] += 1
            else:
                real.setdefault(name, []).append((f"{path}:{ln}", code))

    files = compiled_files(root, build)
    built = {n for n, ms in by_name.items() if any(m["file"] in files
                                                    for m in ms)}
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
                          capture_output=True, text=True).stdout.strip()
    return {
        "build": build_name(build),
        "commit": head or None,
        "compiled": len(built),
        "built": sorted(built),
        "confirmed": sorted(built - set(real)),
        "real_use": {n: sorted(u)[0] for n, u in sorted(real.items())},
        "not_built": sorted(set(by_name) - built),
        "warnings": dict(counts, real_use=sum(map(len, real.values()))),
    }


def merge(results):
    """Several builds of the same scan as one result, e.g. other
    architectures or configs.  A candidate is confirmed when some build
    compiled it and no build found a use."""
    if len(results) == 1:
        return results[0]
    commits = {r.get("commit") for r in results} - {None}
    if len(commits) > 1:
        raise SystemExit("kunused: the --verify results are from different "
                         "commits: " + ", ".join(sorted(c[:12]
                                                        for c in commits)))
    real = {}
    for r in results:
        for name, use in r["real_use"].items():
            real.setdefault(name, use)
    built = set().union(*(set(r.get("built", r["confirmed"])) |
                          set(r["real_use"]) for r in results))
    return {
        "build": " and ".join(f"{r['build']} {r.get('config', '')}".strip()
                              for r in results),
        "builds": len(results),
        "commit": commits.pop() if commits else None,
        "compiled": len(built),
        "built": sorted(built),
        "confirmed": sorted(set().union(*(r["confirmed"] for r in results))
                            - set(real)),
        "real_use": real,
        "not_built": sorted(set.intersection(*(set(r["not_built"])
                                               for r in results))),
        "warnings": {k: sum(r["warnings"].get(k, 0) for r in results)
                     for k in ("chain", "export", "real_use")},
    }
