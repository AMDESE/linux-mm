# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Shivank Garg <shivankg@amd.com>
"""Unused 'static inline' functions.

Compilers cannot report these when they live in headers: the definition is
legitimately unused in most translation units that include the header, so
only a whole-tree view can tell.  A name is unused when every occurrence of
it (comments and strings excluded) is one of its own definitions, a
'#define NAME' variant, a preprocessor conditional ('#ifndef NAME'
arch-override checks), or sits inside the body of another unused inline.
"""
from candidates import Candidate


def find(index):
    tokens = index.tokens.copy()
    defs = index.inlines

    # Peel off unused inlines until nothing changes, so helpers whose only
    # callers are themselves unused are found too.
    unused, round_of, rnd = set(), {}, 0
    while True:
        new = {n for n, sites in defs.items()
               if n not in unused and tokens[n] <= len(sites)}
        if not new:
            break
        for n in new:
            round_of[n] = rnd
            for _, _, body in defs[n]:
                tokens.subtract(body)
        unused |= new
        rnd += 1

    callers = {}
    for n in unused:
        for _, _, body in defs[n]:
            for t in body:
                if t in unused and t != n:
                    callers.setdefault(t, set()).add(n)

    out = []
    for name in unused:
        sites = sorted((p, l) for p, l, _ in defs[name])
        if all(p.startswith("tools/") for p, _ in sites):
            continue
        tags, via = [], []
        if round_of[name]:
            tags.append("via-unused")
            via = sorted(callers.get(name, ()))
        if index.pastes.match(name):
            tags.append("paste?")
        if index.other[name]:
            tags.append("non-c?")
        if any("/uapi/" in p for p, _ in sites):
            tags.append("uapi")
        out.append(Candidate(name, "inline", sites, tags, via))
    return out
