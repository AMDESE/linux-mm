# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Shivank Garg <shivankg@amd.com>
"""Map a path to its MAINTAINERS section without running get_maintainer.pl."""
import fnmatch
import re
from collections import defaultdict

REST = ("THE REST", "linux-kernel@vger.kernel.org")


class Maintainers:
    """lookup(path) -> (section title, mailing list) of the most specific
    F: pattern that covers the path and is not excluded by an X: line."""

    def __init__(self, path="MAINTAINERS"):
        self.exact, self.prefix, self.globs = {}, {}, []
        self.excl = defaultdict(list)
        try:
            with open(path, errors="replace") as f:
                text = f.read()
        except OSError:
            return
        title, fields = None, defaultdict(list)
        for line in text.split("\n") + [""]:
            m = re.match(r"^([A-Z]):\s*(.*)", line)
            if m:
                fields[m.group(1)].append(m.group(2).strip())
            elif line and not line[0].isspace():
                self._add(title, fields)
                title, fields = line.strip(), defaultdict(list)
        self._add(title, fields)

    def _add(self, title, fields):
        if not title or "F" not in fields:
            return
        lists = [l.split()[0] for l in fields.get("L", [])]
        lists.sort(key=lambda l: "linux-kernel@" in l)
        sec = (title, lists[0] if lists else "")
        for p in fields["F"]:
            if any(c in p for c in "*?["):
                self.globs.append((re.compile(fnmatch.translate(p)), len(p),
                                   sec))
            elif p.endswith("/"):
                self.prefix.setdefault(p, []).append(sec)
            else:
                self.exact.setdefault(p, []).append(sec)
                self.prefix.setdefault(p + "/", []).append(sec)
        self.excl[sec] += fields.get("X", [])

    def lookup(self, path):
        best, score = REST, -1
        cands = [(len(path) + 1, s) for s in self.exact.get(path, ())]
        parts = path.split("/")
        for i in range(1, len(parts)):
            p = "/".join(parts[:i]) + "/"
            cands += [(len(p), s) for s in self.prefix.get(p, ())]
        cands += [(n, s) for rx, n, s in self.globs if rx.match(path)]
        for n, sec in cands:
            if n > score and not any(path.startswith(x) or
                                     fnmatch.fnmatch(path, x)
                                     for x in self.excl.get(sec, ())):
                best, score = sec, n
        return best
