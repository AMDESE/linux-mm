# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Shivank Garg <shivankg@amd.com>
"""Lexing and whole-tree token counting shared by both scanners."""
import functools
import os
import re
import subprocess
from collections import Counter, defaultdict, namedtuple
from multiprocessing import Pool

# The tool's own README and tests name kernel symbols.
EXCLUDE = ("Documentation/", "scripts/kunused/")
# Lexed as C (comments and strings dropped); every other tracked text file
# just has its identifiers counted.
SRC_EXT = (".c", ".h", ".S", ".rs", ".lds", ".dts", ".dtsi",
           ".tbl", ".asn1", ".inc", ".uc", ".j2")
# How many '##' steps deep a pasted macro argument is looked for.
MAX_PIECE_DEPTH = 2

LEX_RE = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"|'
                    r"'(?:\\.|[^'\\\n])*'", re.S)
COND_RE = re.compile(r"^[ \t]*#[ \t]*(?:if|ifdef|ifndef|elif|elifdef|elifndef"
                     r"|undef)\b[^\n]*", re.M)
DEFINE_RE = re.compile(r"^([ \t]*#[ \t]*define[ \t]+)([A-Za-z_]\w*)", re.M)
SELFDEF_RE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+(\w+)[ \t]+\1[ \t]*$", re.M)
IDENT_RE = re.compile(r"[A-Za-z_]\w*")
MACRO_RE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+(\w+)(?:\(([^)]*)\))?"
                      r"((?:[^\n]*\\\n)*[^\n]*)", re.M)
CHAIN_RE = re.compile(r"(?<![\w#])\w+(?:[ \t\\\n]*##[ \t\\\n]*\w+)+")

ATTR = r"\b__\w+\s*\((?:[^()]|\([^()]*\))*\)"
PARAMS = r"\(((?:[^;{()]|\([^;{()]*\))*)\)"
INLINE_DEF_RE = re.compile(
    r"^[ \t]*static\s+(?:__maybe_unused\s+)?"
    r"(?:__always_inline|inline|__inline__|__inline)\b"
    rf"(?:[^;{{}}()=#]|{ATTR})*?(?<![#\w])([A-Za-z_]\w*)\s*{PARAMS}"
    rf"\s*(?:{ATTR}\s*)*\{{",
    re.M | re.S)


def read(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "replace")


def lex(text):
    """Blank comments, strings and char literals, keeping line numbers."""
    def blank(m):
        s = m.group(0)
        return ('""' if s[0] in "\"'" else "") + "\n" * s.count("\n")
    return LEX_RE.sub(blank, text)


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def in_macro_body(text, pos):
    """Is 'pos' on a backslash-continued '#define' line?"""
    start = text.rfind("\n", 0, pos) + 1
    prev = text.rfind("\n", 0, max(start - 1, 0)) + 1
    end = text.find("\n", pos)
    return text[prev:start].rstrip().endswith("\\") or \
        text[start:end if end >= 0 else None].rstrip().endswith("\\")


def brace_body(text, open_pos):
    depth = 0
    for i in range(open_pos, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_pos:i + 1]
    return text[open_pos:]


def macro_params(text):
    """('a', 'b', '__VA_ARGS__'), True for '(a, b, ...)'; GNU 'args...'
    is named 'args'.  The second item says whether the last is variadic."""
    if text is None:
        return None, False
    params = [p.strip() for p in text.split(",")]
    if params == [""]:
        return (), False
    if params[-1].endswith("..."):
        params[-1] = params[-1][:-3].strip() or "__VA_ARGS__"
        return tuple(params), True
    return tuple(params), False


# A '##' chain in the body of a function-like macro.  'pieces' is
# ((is_param, text), ...).
Template = namedtuple("Template", "macro params variadic pieces path")


def paste_templates(text, path=""):
    """Every 'a##param##b' chain in the macros of 'text'."""
    out = set()
    for m in MACRO_RE.finditer(text):
        if "##" not in m.group(3):
            continue
        params, variadic = macro_params(m.group(2))
        names = set(params or ())
        for chain in CHAIN_RE.findall(m.group(3)):
            pieces = re.split(r"[ \t\\\n]*##[ \t\\\n]*", chain)
            out.add(Template(m.group(1), params, variadic,
                             tuple((p in names, p) for p in pieces), path))
    return out


def could_spell(pieces, name):
    """Quick test before splits(): literal ends and middles fit."""
    (w0, p0), (wn, pn) = pieces[0], pieces[-1]
    return (w0 or name.startswith(p0)) and (wn or name.endswith(pn)) and \
        all(p in name for wild, p in pieces if not wild)


def splits(pieces, name):
    """Every way the wildcard pieces can be filled to spell 'name', as
    {param: text}.  A parameter used twice gets the same text both times."""
    out, n = [], len(pieces)
    rest = [0] * (n + 1)              # least length pieces[i:] can take
    for i in range(n - 1, -1, -1):
        wild, text = pieces[i]
        rest[i] = rest[i + 1] + (1 if wild else len(text))

    def fill(i, pos, bound):
        if i == n:
            if pos == len(name):
                out.append(dict(bound))
            return
        wild, text = pieces[i]
        if not wild:
            if name.startswith(text, pos):
                fill(i + 1, pos + len(text), bound)
            return
        if text in bound:
            if name.startswith(bound[text], pos):
                fill(i + 1, pos + len(bound[text]), bound)
            return
        last = len(name) - rest[i + 1]
        if i + 1 == n:
            ends = [len(name)] if pos < len(name) else []
        elif not pieces[i + 1][0]:
            lit = pieces[i + 1][1]
            ends, e = [], name.find(lit, pos + 1)
            while 0 <= e <= last:
                ends.append(e)
                e = name.find(lit, e + 1)
        else:
            ends = range(pos + 1, last + 1)
        for end in ends:
            bound[text] = name[pos:end]
            fill(i + 1, end, bound)
        bound.pop(text, None)

    fill(0, 0, {})
    return out


def scan_file(path):
    """(path, token counts, inline defs, '#define' names, paste templates).

    Tokens exclude comments, strings, preprocessor conditionals and the
    names on '#define NAME' lines, so none of those count as uses.  Files
    that are not SRC_EXT only get their identifiers counted.
    """
    try:
        text = read(path)
    except OSError:
        return path, Counter(), [], Counter(), set()
    if "\0" in text:
        return path, Counter(), [], Counter(), set()
    if not path.endswith(SRC_EXT):
        return path, Counter(IDENT_RE.findall(text)), [], Counter(), set()
    text = lex(text)

    pastes = paste_templates(text, path) if "##" in text else set()
    macros = Counter(m.group(2) for m in DEFINE_RE.finditer(text))
    text = COND_RE.sub("", text)
    text = SELFDEF_RE.sub("", text)
    text = DEFINE_RE.sub(lambda m: m.group(1), text)

    defs = []
    for m in INLINE_DEF_RE.finditer(text):
        if in_macro_body(text, m.start()):
            continue
        body = brace_body(text, m.end() - 1)
        defs.append((m.group(1), line_of(text, m.start(1)),
                     Counter(IDENT_RE.findall(body))))
    return path, Counter(IDENT_RE.findall(text)), defs, macros, pastes


def tree_files():
    """Files tracked by git in the current directory, minus EXCLUDE."""
    try:
        files = subprocess.run(["git", "ls-files", "-z"], capture_output=True,
                               text=True, check=True).stdout.split("\0")
    except (OSError, subprocess.CalledProcessError) as e:
        raise SystemExit(f"kunused: needs a git checkout of the kernel ({e})")
    return [f for f in files if f and not f.startswith(EXCLUDE)]


class Index:
    """Whole-tree token counts plus every 'static inline' definition.

    'tokens' counts identifiers in source files.  'other' counts them in
    every other tracked file: Makefiles, build rules such as
    xe_wa_oob.rules, scripts, data.  A name there may be a real use or a
    coincidence, so it only earns a tag.
    """

    def __init__(self, files, jobs=None):
        self.files = [f for f in files if f.endswith(SRC_EXT)]
        self.other = Counter()
        self.tokens = Counter()
        self.inlines = defaultdict(list)     # name -> [(path, line, body)]
        self.macros = Counter()
        templates = set()
        with Pool(jobs or os.cpu_count()) as pool:
            for path, cnt, defs, macros, pastes in pool.imap_unordered(
                    scan_file, files, chunksize=64):
                if not path.endswith(SRC_EXT):
                    self.other.update(cnt)
                    continue
                self.tokens.update(cnt)
                self.macros.update(macros)
                templates |= pastes
                for name, line, body in defs:
                    self.inlines[name].append((path, line, body))
        self.pastes = Pastes(templates, self.tokens)


class Pastes:
    """Can a name be produced by one of the collected '##' templates?"""

    def __init__(self, templates, tokens):
        self.prefix, self.suffix = defaultdict(list), defaultdict(list)
        self.middle, self.short = [], []
        self.tokens = tokens
        for t in templates:
            lits = [p for wild, p in t.pieces if not wild]
            if not lits:
                continue                  # all-wildcard
            if max(map(len, lits)) < 3 and not all(p.isdigit() for p in lits):
                self.short.append(t)      # matches too much to tag with
            elif not t.pieces[0][0]:
                self.prefix[t.pieces[0][1]].append(t)
            elif not t.pieces[-1][0]:
                self.suffix[t.pieces[-1][1]].append(t)
            else:
                self.middle.append((max(lits, key=len), t))

    def templates_for(self, name, short=False):
        """[(template, [{param: text}, ...]), ...] for every template that
        can spell 'name'; with 'short', also those with only short
        literals, like 'p##_a'."""
        maybe = [t for i in range(1, len(name) + 1)
                 for bucket in (self.prefix.get(name[:i], ()),
                                self.suffix.get(name[-i:], ()))
                 for t in bucket]
        maybe += [t for lit, t in self.middle if lit in name]
        if short:
            maybe += [t for t in self.short if could_spell(t.pieces, name)]
        out = []
        for t in maybe:
            fills = splits(t.pieces, name)
            if fills:
                out.append((t, fills))
        return out

    def plausible(self, fill, depth=0):
        """Do the wildcard parts look like real macro arguments?  A part
        must be in the tree as a token, or be built by '##' itself, as
        'c0_status' is by '#define W(n) M(c0_##n)'."""
        return all(self.piece(v, depth) for v in fill.values())

    @functools.lru_cache(maxsize=None)
    def piece(self, v, depth):
        if v.isdigit() or self.tokens[v] > 0 or self.tokens[v.strip("_")] > 0:
            return True
        return depth < MAX_PIECE_DEPTH and any(
            self.plausible(f, depth + 1)
            for _, fills in self.templates_for(v, short=True) for f in fills)

    def match(self, name):
        return any(self.plausible(f) for _, fills in self.templates_for(name)
                   for f in fills)
