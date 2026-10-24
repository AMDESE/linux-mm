# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Shivank Garg <shivankg@amd.com>
"""Unused non-static functions and global variables.

A function or variable defined in a .c file is unused when its name never
appears anywhere else in the tree except at the definition, header
prototypes / extern declarations, 'static inline' !CONFIG stubs, '#define'
and '#if' lines, comments and EXPORT_SYMBOL*().
"""
import functools
import os
import re
from multiprocessing import Pool

from candidates import Candidate
from source import IDENT_RE, lex, line_of, read

# Names seen more often than this are not worth grepping for.
MAX_TOKENS = 10
# Userspace, host tools and Rust glue: their functions are entry points
# (main, BPF programs, bindgen helpers), not things C code calls by name.
DEFAULT_SKIP = ("tools/", "samples/", "scripts/", "rust/", "usr/")
FUNC_OPEN_RE = re.compile(r"\)[ \t]*\n\{", re.M)
VAR_RE = re.compile(
    r"^(?!(?:static|extern|typedef|return)\b|(?:struct|union|enum)\s+\w+\s*[{;])"
    r"[A-Za-z_][\w \t*]*?[\s*]([A-Za-z_]\w*)\s*(?:\[[^\]\n]*\]\s*)*"
    r"(?:__\w+(?:\([^)\n]*\))?\s*)*(?:=|;)", re.M)
COMPILER_EMITTED = re.compile(r"^__(?:asan|hwasan|msan|tsan|kcsan|ubsan|"
                              r"sanitizer|gcov|cyg_profile|stack_chk)_")
KEYWORDS = r"(?:return|else|do|case|goto|sizeof|typeof)\b"


def func_name(sig):
    """Name owning the parameter list that ends 'sig', skipping trailing
    __attr(...) groups such as __acquires(x).  Returns (name, offset)."""
    end = len(sig) - 1
    while end >= 0 and sig[end] == ")":
        depth = 0
        for i in range(end, -1, -1):
            depth += {")": 1, "(": -1}.get(sig[i], 0)
            if depth == 0:
                break
        else:
            return None, -1
        m = re.search(r"([A-Za-z_]\w*)\s*$", sig[:i])
        if not m:
            return None, -1
        before = sig[:m.start()].rstrip()
        if m.group(1).startswith("__") and before.endswith(")"):
            end = len(before) - 1
            continue
        return m.group(1), m.start()
    return None, -1


def definitions(path):
    """Non-static definitions in a .c file: [(name, line, var)], where var
    is False for functions and the previous identifier (or True) for
    variables, in case the captured name turns out to be an attribute
    macro."""
    text = lex(read(path))
    out = []
    for m in FUNC_OPEN_RE.finditer(text):
        start = max(text.rfind(c, 0, m.start()) for c in ";}") + 1
        sig = text[start:m.start() + 1]
        sig = re.sub(r"^[ \t]*#[^\n]*", lambda p: " " * len(p.group(0)), sig,
                     flags=re.M)
        if re.match(r"(SYSCALL_DEFINE|COMPAT_SYSCALL)", sig.lstrip()):
            continue
        name, pos = func_name(sig)
        decl = sig[:pos].lstrip()
        if decl.startswith("static") or \
           re.search(r"\bstatic\b", re.split(r"\)[ \t]*\n", decl)[-1]):
            continue
        if name and not name.isupper():
            out.append((name, line_of(text, start + pos), False))
    for m in VAR_RE.finditer(text):
        start = text.rfind("\n", 0, m.start()) + 1
        prev = text.rfind("\n", 0, max(start - 1, 0)) + 1
        if text[prev:start].rstrip().endswith("\\"):
            continue
        before = IDENT_RE.findall(text[m.start():m.start(1)])
        out.append((m.group(1), line_of(text, m.start(1)),
                    before[-1] if len(before) > 1 else True))
    return path, out


COMMENT_RE = re.compile(r"\s*(//|/\*\*?(\s|$)|\*(\s|$))")
# What may come before the name in a declaration: types, qualifiers,
# attribute macros without arguments, '*'.  No operators, so a call on a
# continuation line ('rc : foo(x),', 'A + foo(x);') never qualifies.
DECL_PREFIX = r"[A-Za-z_][\w \t*]*?"


@functools.lru_cache(maxsize=4096)
def _patterns(name):
    n = re.escape(name)
    return (
        re.compile(rf"EXPORT_SYMBOL\w*\(\s*{n}\s*\)"),
        re.compile(rf"\s*#\s*(if|ifdef|ifndef|elif|undef|define\s+{n}\b)"),
        re.compile(rf"[ \t]*(?!{KEYWORDS})(?:extern\s+)?{DECL_PREFIX}"
                   rf"\b{n}\s*\([^;{{]*\)?\s*;?$"),
        re.compile(rf"\s*extern\b[^;()=]*\b{n}\s*(\[[^\]]*\]\s*)*;"),
        re.compile(rf"\s*static\s+(__always_)?inline\b[^(=;]*\b{n}\s*\("),
        re.compile(rf"(?!{KEYWORDS}){DECL_PREFIX}\b{n}\s*\("),
    )


def declares(code, name):
    """Is this line about 'name' without using it, wherever it appears?"""
    export, cpp, proto, extern, stub, _ = _patterns(name)
    return bool(COMMENT_RE.match(code) or     # comment line
                export.search(code) or cpp.match(code) or
                proto.match(code) or          # prototype
                extern.match(code) or         # extern variable
                stub.match(code))             # static inline !CONFIG stub


def defines(code, name):
    """Is this line the definition of function or variable 'name'?"""
    if _patterns(name)[5].match(code) and not code.rstrip().endswith(";"):
        return True
    v = VAR_RE.match(code)
    return bool(v and name in IDENT_RE.findall(code[:v.end(1)]))


_names = set()


def _set_names(names):
    global _names
    _names = names


def _grep_file(path):
    try:
        raw = read(path)
    except OSError:
        return []
    if not _names.intersection(IDENT_RE.findall(raw)):
        return []
    return [(name, f"{path}:{n}:{line}", declares(line, name))
            for n, line in enumerate(raw.split("\n"), 1)
            for name in _names.intersection(IDENT_RE.findall(line))]


def grep(files, names, jobs=None):
    """Like 'git grep -nw' for every name, run in parallel.  Returns
    {name: [(path:n:line, declares), ...]}, where 'declares' says the line
    is a prototype, comment or similar rather than a use."""
    hits = {n: [] for n in names}
    with Pool(jobs or os.cpu_count(), initializer=_set_names,
              initargs=(set(names),)) as pool:
        for found in pool.imap_unordered(_grep_file, files, chunksize=64):
            for name, h, decl in found:
                hits[name].append((h, decl))
    return hits


def find(index, dirs=None, jobs=None):
    """Candidates among .c files under 'dirs' (default: the whole tree
    except DEFAULT_SKIP)."""
    prefixes = tuple(d.rstrip("/") + "/" for d in dirs or ())
    targets = [f for f in index.files if f.endswith(".c") and
               (f.startswith(prefixes) if prefixes else
                not f.startswith(DEFAULT_SKIP))]
    with Pool(jobs or os.cpu_count()) as pool:
        defs = pool.map(definitions, targets, chunksize=16)

    cands = []
    for path, ds in defs:
        for name, line, var in ds:
            if var and name in index.macros:    # 'type name ATTR_MACRO;'
                if var is True:
                    continue
                name = var
            if index.tokens[name] <= MAX_TOKENS and \
               not COMPILER_EMITTED.match(name):
                cands.append((path, name, line, bool(var)))
    hits = grep(index.files, {c[1] for c in cands}, jobs)

    seen, out = set(), []
    for path, name, line, var in cands:
        if (path, name) in seen:
            continue
        seen.add((path, name))
        rest = [h.split(":", 2) for h, decl in hits[name] if not decl]
        if any(f != path or not defines(code, name) for f, _, code in rest):
            continue
        tags = []
        if any("EXPORT_SYMBOL" in h for h, _ in hits[name]):
            tags.append("exported")
        if index.pastes.match(name):
            tags.append("paste?")
        if index.other[name]:
            tags.append("non-c?")
        out.append(Candidate(name, "variable" if var else "function",
                             [(path, line)], tags))
    return out
