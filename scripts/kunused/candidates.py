# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Shivank Garg <shivankg@amd.com>
"""The candidate list: TSV storage and the grouped text listing."""
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field

TSV_HEADER = ("# kunused candidates: name, kind, path:line[, ...], tags, "
              "callers")

# Tags a scanner may attach.  The listing hides HIDDEN_TAGS unless --all.
TAGS = {
    "via-unused": "only referenced from other unused code",
    "paste?": "a '##' macro could build this name and its uses could not "
              "all be followed; check by hand",
    "paste-used": "a '##' macro call builds this name, so it is used",
    "non-c?": "also named in a non-C file, e.g. a Makefile; check by hand",
    "uapi": "userspace API header; in-tree users are not the whole story",
    "exported": "has an EXPORT_SYMBOL*()",
}
HIDDEN_TAGS = {"paste?", "paste-used", "non-c?", "uapi"}


@dataclass
class Candidate:
    name: str
    kind: str                       # inline, function or variable
    sites: list                     # [(path, line), ...], sorted
    tags: list = field(default_factory=list)
    callers: list = field(default_factory=list)  # for [via-unused]

    @property
    def path(self):
        return self.sites[0][0]


def write_tsv(cands, f, commit=None):
    print(TSV_HEADER, file=f)
    if commit:
        print(f"# commit {commit}", file=f)
    for c in sorted(cands, key=lambda c: (c.sites[0], c.name)):
        locs = ", ".join(f"{p}:{l}" for p, l in c.sites)
        print(f"{c.name}\t{c.kind}\t{locs}\t{' '.join(c.tags)}\t"
              f"{' '.join(c.callers)}", file=f)


def tsv_commit(path):
    """The commit a TSV file was scanned at, if it says."""
    with open(path) as f:
        for line in f:
            if not line.startswith("#"):
                break
            if line.startswith("# commit "):
                return line.split()[2]
    return None


def read_tsv(path):
    with open(path) as f:
        for n, line in enumerate(f, 1):
            if line.startswith("#") or not line.strip():
                continue
            try:
                name, kind, locs, tags, *callers = \
                    line.rstrip("\n").split("\t")
                sites = [(p, int(l)) for p, l in
                         (s.rsplit(":", 1) for s in locs.split(", "))]
                if len(callers) > 1:
                    raise ValueError
            except ValueError:
                raise SystemExit(f"{path}:{n}: not a kunused candidates line")
            yield Candidate(name, kind, sites, tags.split(),
                            callers[0].split() if callers else [])


def print_listing(cands, show_all=False, out=sys.stdout):
    """Group by file, one line per candidate; summary line at the end."""
    hidden = 0
    if not show_all:
        shown = [c for c in cands if not HIDDEN_TAGS & set(c.tags)]
        hidden, cands = len(cands) - len(shown), shown
    cands = sorted(cands, key=lambda c: (c.sites[0], c.name))

    width = max((len(c.name) for c in cands), default=0)
    by_file = defaultdict(list)
    for c in cands:
        by_file[c.path].append(c)
    for path, group in by_file.items():
        print(f"{path} ({len(group)})", file=out)
        for c in group:
            path0, line0 = c.sites[0]
            also = ", ".join(f":{l}" if p == path0 else f"{p}:{l}"
                             for p, l in c.sites[1:])
            extra = [f"[{t}]" for t in c.tags]
            if c.kind != "inline":
                extra.insert(0, c.kind)
            if also:
                extra.append(f"also {also}")
            print(f"  {line0:>5}  {c.name:<{width}}  {' '.join(extra)}"
                  .rstrip(), file=out)
        print(file=out)
    print(summary(cands, hidden), file=out)


def summary(cands, hidden=0):
    kinds = Counter(c.kind for c in cands)
    tags = Counter(t for c in cands for t in c.tags)
    s = (f"# {len(cands)} candidates in {len({c.path for c in cands})} files"
         f" ({', '.join(f'{n} {k}' for k, n in sorted(kinds.items()))})")
    if tags:
        s += "; tags: " + ", ".join(f"[{t}] {n}" for t, n in
                                    sorted(tags.items()))
    if hidden:
        s += (f"; {hidden} [paste?]/[paste-used]/[non-c?]/[uapi] hidden, "
              "use --all")
    return s
