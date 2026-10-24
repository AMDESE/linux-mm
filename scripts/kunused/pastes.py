# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Shivank Garg <shivankg@amd.com>
"""Settle '[paste?]': does any use of a '##' macro really build the name?

A name gets [paste?] when some macro, say '#define LOCK(t) t##_lock',
could spell it.  That only says LOCK(zpdesc) would build zpdesc_lock;
whether anything calls LOCK(zpdesc) is a question about LOCK's callers,
and those are plain text, so every architecture and config is covered
at once.  For each way the macro could spell the name, every use of the
macro in the tree is read:

  used    a call passes exactly the needed arguments
  unused  every use is shown to pass something else
  open    a use cannot be followed

What is followed:

  - a call inside another macro, '#define WRAP(x) LOCK(x)' or
    '#define WRAP(x) LOCK(pre_##x)', goes on to WRAP's callers, with
    the needed text split over the pasted pieces the same way;
  - a WRAP argument that is itself a macro is looked up: unused only if
    no '#define' of it in the tree could expand to the needed text;
  - LOCK handed to another macro, 'LIST(LOCK)', follows LIST's body to
    where it calls LOCK and reads those arguments;
  - '#define ALIAS LOCK' goes on to ALIAS's uses;
  - a bare 'LOCK' that is not followed by '(' and not handed to a macro
    is never expanded, so it is skipped.

Anything else is 'open', and 'unused' needs every way to spell the name
to be unused, so an unclear case is never dropped.
"""
import bisect
import itertools
import os
import re
import subprocess
from collections import defaultdict, namedtuple
from multiprocessing import Pool

from source import IDENT_RE, LEX_RE, macro_params, read, splits

MAX_DEPTH = 4
MAX_ROUNDS = 12
MAX_ARGS_SPAN = 20000
MAX_BACK = 5000

WORD_RE = re.compile(r"\w+\Z")
ORDER = ("unused", "open", "pending", "used")
UNUSED = ("unused", None)
PENDING = ("pending", None)

DIRECTIVE_RE = re.compile(r"^[ \t]*#[ \t]*(\w*)[^\n]*(?:(?<=\\)\n[^\n]*)*",
                          re.M)
DEFINE_HEAD_RE = re.compile(r"[ \t]*#[ \t]*define[ \t]+(\w+)(?:\(([^)]*)\))?")

# A macro definition.  'params' is None for an object-like macro; 'body'
# is kept for definitions that were asked for and for object-like macros
# around a use.
Macro = namedtuple("Macro", "name params variadic body loc")
# One use of a macro name.  'args' is the argument list of a call, None
# when it is not a call, False when the call cannot be read.  'define' is
# the Macro whose body holds it.  'outer' is (macro, index, args) when it
# is a whole argument of another call, (None, None, None) when it is part
# of one.  'nextc' is the name after it, or the character after it, ""
# at the end of a macro.
Use = namedtuple("Use", "loc args define outer nextc")


def file_of(loc):
    return loc.rsplit(":", 1)[0] if loc else None


def included_names():
    """Base names of every file some '#include', '.include' or
    '-include' in the tree names; None if git cannot tell."""
    try:
        p = subprocess.run(
            ["git", "grep", "-h", "-o", "-I", "-E",
             r'include[[:space:]]*([<"][^>"]+[>"]|[^[:space:]]+)'],
            capture_output=True, text=True)
    except OSError:
        return None
    if p.returncode > 1:
        return None
    out = p.stdout
    return {os.path.basename(m.strip('<>"'))
            for m in re.findall(r'include\s*(\S+)', out)}


def worse(a, b):
    return b if ORDER.index(b[0]) > ORDER.index(a[0]) else a


def edges(text):
    """First and last token: a '##' next to an argument of several
    tokens only joins the one at that end."""
    toks = re.findall(r"\w+|[^\w\s\\]", text)
    return (toks[0], toks[-1]) if toks else ()


def lex_spliced(text):
    """Like lex(), but a comment spanning lines inside a '#define' keeps
    the macro going: the preprocessor sees a single space there."""
    def blank(m):
        s = m.group(0)
        if s[0] in "\"'":
            return '""'
        return " " + "\\\n" * s.count("\n")
    return LEX_RE.sub(blank, text)


def norm(arg):
    return re.sub(r"\\\n", " ", arg).strip()


def call_args(text, open_pos, limit):
    """Top-level arguments of the call whose '(' is at open_pos."""
    depth, start, args = 0, open_pos + 1, []
    for i in range(open_pos, min(limit, open_pos + MAX_ARGS_SPAN)):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append(text[start:i])
                return args
        elif c == "," and depth == 1:
            args.append(text[start:i])
            start = i + 1
    return None


def pasted(text, pos, end):
    before = text[max(0, pos - 3):pos].rstrip(" \t\\\n")
    after = text[end:end + 4].lstrip(" \t\\\n")
    return before.endswith("#") or after.startswith("##")


def next_char(text, end, limit):
    """Where the next token starts, and the token if it is a name, else
    its first character ("" at the limit)."""
    j = end
    while j < limit and text[j] in " \t\n\\":
        j += 1
    m = IDENT_RE.match(text, j, limit)
    return j, m.group(0) if m else text[j] if j < limit else ""


def enclosing_call(text, pos, end, lo, limit):
    """(macro, index, args) when text[pos:end] is a whole argument of a
    call, (None, None, None) when it is part of one, None otherwise."""
    depth, commas = 0, 0
    for q in range(pos - 1, max(lo, pos - MAX_BACK) - 1, -1):
        c = text[q]
        if c in ")]}":
            depth += 1
        elif c in "([{":
            if depth:
                depth -= 1
                continue
            if c != "(":
                return None
            head = re.search(r"(\w+)[ \t\\\n]*\Z", text[max(lo, q - 200):q])
            if not head or head.group(1)[0].isdigit():
                return None
            args = call_args(text, q, limit)
            if args is None or commas >= len(args):
                return None, None, None
            if norm(args[commas]) != text[pos:end]:
                return None, None, None
            return head.group(1), commas, [norm(a) for a in args]
        elif depth == 0 and c == ",":
            commas += 1
        elif depth == 0 and c == ";":
            return None
    return None if pos - MAX_BACK <= lo else (None, None, None)


def uses_in(path, names, defs=frozenset()):
    """Every use of the macros in 'names' and every definition of those
    in 'defs' in one file, as [(kind, name, Use or Macro)]."""
    try:
        raw = read(path)
    except OSError:
        return []
    idents = set(IDENT_RE.findall(raw))
    if names.isdisjoint(idents) and defs.isdisjoint(idents):
        return []
    text = lex_spliced(raw)
    directives = [(m.start(), m.end(), m.group(1))
                  for m in DIRECTIVE_RE.finditer(text)]
    starts = [d[0] for d in directives]
    newlines = [m.start() for m in re.finditer("\n", text)]
    out = []
    for d_start, d_end, kind in directives:
        head = DEFINE_HEAD_RE.match(text, d_start) if kind == "define" \
            else None
        if head and head.group(1) in defs:
            params, variadic = macro_params(head.group(2))
            line = bisect.bisect_left(newlines, head.start(1)) + 1
            out.append(("def", head.group(1),
                        Macro(head.group(1), params, variadic,
                              text[head.end():d_end], f"{path}:{line}")))
    if names.isdisjoint(idents):
        return out
    for m in IDENT_RE.finditer(text):
        name, pos, end = m.group(0), m.start(), m.end()
        if name not in names or (pos and text[pos - 1].isdigit()):
            continue
        if pasted(text, pos, end):
            continue                    # pasted or stringified, not a use
        loc = f"{path}:{bisect.bisect_left(newlines, pos) + 1}"
        i = bisect.bisect_right(starts, pos) - 1
        define, lo, limit = None, 0, len(text)
        if i >= 0 and pos < directives[i][1]:
            d_start, d_end, kind = directives[i]
            if kind != "define":
                continue                # #ifdef NAME, #undef NAME, ...
            head = DEFINE_HEAD_RE.match(text, d_start)
            if not head or pos < head.end() or head.group(1) == name:
                continue                # its name, a param, or itself
            params, variadic = macro_params(head.group(2))
            body = text[head.end():d_end] if params is None else None
            define = Macro(head.group(1), params, variadic, body, None)
            lo, limit = head.end(), d_end
        j, nextc = next_char(text, end, limit)
        if nextc == "(":
            args = call_args(text, j, limit)
            out.append(("use", name, Use(loc, [norm(a) for a in args]
                                         if args is not None else False,
                                         define, None, "(")))
        else:
            outer = enclosing_call(text, pos, end, lo, limit)
            out.append(("use", name, Use(loc, None, define, outer, nextc)))
    return out


_names = _defs = frozenset()


def _init(names, defs):
    global _names, _defs
    _names, _defs = names, defs


def _uses_in(path):
    return uses_in(path, _names, _defs)


def subst(arg, params, args):
    """'arg' from a macro body with the call's 'args' put in for
    'params'.  Returns (text, plain): plain if a parameter went in
    without '##', so the call's argument was macro-expanded first."""
    def value(p):
        i = params.index(p)
        return args[i] if i < len(args) else ""
    if "##" in arg:
        return "".join(value(p) if p in params else p
                       for p in (x.strip() for x in arg.split("##"))), False
    plain = any(t in params for t in IDENT_RE.findall(arg))
    return norm(IDENT_RE.sub(lambda m: value(m.group(0))
                             if m.group(0) in params else m.group(0),
                             arg)), plain


class Resolver:
    def __init__(self, index, jobs=None):
        self.pastes = index.pastes
        self.macros = index.macros
        self.files = [f for f in index.files if not f.endswith(".rs")]
        self.jobs = jobs or os.cpu_count()
        self.uses = {}                  # macro name -> [Use, ...]
        self.defs = {}                  # macro name -> [Macro, ...]
        self.split = {}                 # by_arg()
        self.memo = {}                  # check()
        self.calls = {}                 # calls_of()
        self.included = None            # private()

    def load(self, missing):
        """Read the uses or definitions in 'missing', a set of
        ("use"|"def", name), in one pass over the tree."""
        names = frozenset(n for k, n in missing
                          if k == "use" and n not in self.uses)
        defs = frozenset(n for k, n in missing
                         if k == "def" and n not in self.defs)
        if not names and not defs:
            return
        for n in names:
            self.uses[n] = []
        for n in defs:
            self.defs[n] = []
        with Pool(self.jobs, initializer=_init,
                  initargs=(names, defs)) as pool:
            for found in pool.imap_unordered(_uses_in, self.files,
                                             chunksize=64):
                for kind, name, item in found:
                    (self.uses if kind == "use" else self.defs)[name] \
                        .append(item)

    def private(self, path):
        """Is a '#define' in 'path' seen by that file alone?  True for a
        .c or .S file that nothing includes."""
        if not path or not path.endswith((".c", ".S")):
            return False
        if self.included is None:
            self.included = included_names() or False
        return self.included is not False and \
            os.path.basename(path) not in self.included

    def visible(self, defs, path):
        """The definitions in 'defs' that a use in 'path' can see."""
        return [d for d in defs
                if file_of(d.loc) == path or not self.private(file_of(d.loc))]

    def get(self, table, name, missing):
        if name not in table:
            missing.add(("use" if table is self.uses else "def", name))
            return None
        return table[name]

    def by_arg(self, macro, i):
        """Uses of 'macro' as ({literal arg i: [Use]}, [other Use]).  A
        literal is plain text with no macro, parameter or '#' in it, so
        it gives exactly itself, unless a parameter before it expands to
        commas; every other use needs a closer look."""
        key = (macro, i)
        if key not in self.split:
            exact, other = defaultdict(list), []
            for use in self.uses[macro]:
                a = use.args[i] if use.args and i < len(use.args) else None
                op = use.define.params if use.define and use.define.params \
                    else ()
                if a is None or not WORD_RE.match(a) or self.macros[a] or \
                   a in op or any(set(IDENT_RE.findall(b)) & set(op)
                                  for b in use.args[:i]):
                    other.append(use)
                else:
                    exact[a].append(use)
            self.split[key] = exact, other
        return self.split[key]

    def check(self, macro, params, variadic, want, expand, depth, missing,
              home):
        """Does any use of 'macro', defined in file 'home', pass want =
        {arg index: text}?  The args at the indexes in 'expand' are
        macro-expanded before they reach the paste.  Returns (verdict,
        where); verdict is used, open, pending or unused."""
        home = home if self.private(home) else None
        key = (macro, params, variadic, tuple(sorted(want.items())),
               frozenset(expand), depth, home)
        if key in self.memo:
            return self.memo[key]
        uses = self.get(self.uses, macro, missing)
        if uses is None:
            return PENDING
        if params is None:              # object-like: every use expands
            r = ("used", uses[0].loc) if uses else UNUSED
        else:
            r = self.check_uses(macro, params, variadic, want, expand, depth,
                                missing, home)
        if r[0] != "pending":
            self.memo[key] = r
        return r

    def check_uses(self, macro, params, variadic, want, expand, depth,
                   missing, home):
        if want:
            i = min(want)
            exact, other = self.by_arg(macro, i)
            uses = exact.get(want[i], []) + other
        else:
            uses = self.uses[macro]
        if home:
            uses = [u for u in uses if file_of(u.loc) == home]
        best = UNUSED
        for use in uses:
            if use.args is None:
                r = self.mention(macro, params, variadic, want, expand, use,
                                 depth, missing)
            elif use.args is False:
                r = ("open", f"cannot read the call at {use.loc}")
            else:
                r = self.call(params, variadic, want, expand, use.args,
                              use.define, use.loc, depth, missing,
                              path=file_of(use.loc))
            if r[0] == "used":
                return r
            best = worse(best, r)
        return best

    def call(self, params, variadic, want, expand, args, outer, loc, depth,
             missing, spliced=False, path=None):
        """One call with 'args' in file 'path'; 'outer' is the macro
        around it.  With 'spliced', some args were put in from another
        call."""
        n = len(params)
        if not variadic and len(args) > n and not (n == 0 and args == [""]):
            return UNUSED               # commas from expansions only add args
        oparams = set(outer.params) if outer and outer.params else set()
        shifts = [j for j, a in enumerate(args)
                  if spliced or oparams & set(IDENT_RE.findall(a))]
        if (variadic and len(args) < n - 1) or (not variadic and len(args) < n):
            if shifts:
                return "open", (f"the args at {loc} are put in from a "
                                "macro and may hold commas")
            return UNUSED               # a different macro of that name
        if variadic and want and shifts and shifts[0] < max(want):
            return "open", (f"the args at {loc} are put in from a macro "
                            "and may hold commas")
        alts = []
        for i, v in want.items():
            if i >= len(args):
                return UNUSED
            a = self.match_arg(args[i], v, i in expand, outer, loc, missing,
                               path)
            if isinstance(a, tuple):
                return a
            if not a:
                return UNUSED
            alts.append(a)
        best = UNUSED
        for combo in itertools.product(*alts):
            bind, exp, ok = {}, set(), True
            for b, e in combo:
                for p, x in b.items():
                    ok = ok and bind.setdefault(p, x) == x
                exp |= e
            if not ok:
                continue
            if not bind:
                return "used", loc
            if depth >= MAX_DEPTH:
                best = worse(best, ("open", f"nested deeper than {MAX_DEPTH} "
                                    f"macros at {loc}"))
                continue
            idx = outer.params.index
            r = self.check(outer.name, outer.params, outer.variadic,
                           {idx(p): x for p, x in bind.items()},
                           {idx(p) for p in exp}, depth + 1, missing, path)
            if r[0] == "used":
                return r
            best = worse(best, r)
        return best

    def match_arg(self, a, v, expanded, outer, loc, missing, path):
        """Can argument text 'a' give 'v'?  A list of ways, each
        ({outer param: text it must get}, {params passed on plainly}),
        [] if it cannot, or an (open|pending, why) verdict."""
        if a == v:
            return [({}, set())]
        oparams = outer.params if outer and outer.params else ()
        pieces = [p.strip() for p in a.split("##")]
        if oparams and any(p in oparams for p in pieces):
            if not all(WORD_RE.match(p) for p in pieces):
                return "open", f"built inside {outer.name}() at {loc}"
            if outer.variadic and oparams[-1] in pieces:
                return "open", (f"{outer.name}() passes its variable "
                                f"arguments at {loc}")
            if len(pieces) == 1:
                return [({a: v}, {a})]
            return [(b, set()) for b in
                    splits(tuple((p in oparams, p) for p in pieces), v)]
        if len(pieces) > 1:
            if not all(WORD_RE.match(p) for p in pieces):
                return "open", f"'{a}' is pasted at {loc}"
            return [({}, set())] if "".join(pieces) == v else []
        if oparams and ("#" in a or
                        set(IDENT_RE.findall(a)) & set(oparams)):
            return "open", f"built inside {outer.name}() at {loc}"
        if not WORD_RE.match(a) and v in edges(a):
            return "open", f"'{a}' is pasted by its end token at {loc}"
        if expanded:
            return self.expands_to(a, v, loc, missing, 0, path)
        return []

    def expands_to(self, a, v, loc, missing, level, path):
        """Could 'a', macro-expanded, give 'v'?  [] if no '#define' in the
        tree can make it, or an (open|pending, why) verdict."""
        toks = IDENT_RE.findall(a)
        if not WORD_RE.match(a):
            if any(self.macros[t] for t in toks):
                return "open", f"'{a}' holds a macro, at {loc}"
            return []
        if not toks or not self.macros[a]:
            return []
        defs = self.get(self.defs, a, missing)
        if defs is None:
            return PENDING
        for d in self.visible(defs, path):
            if d.params is not None:
                continue                # not followed by '(': not expanded
            b = norm(d.body)
            if b == v:
                return "open", f"'{a}' at {loc} may expand to {v} ({d.loc})"
            if "##" in b or "#" in b:
                return "open", f"'{a}' at {loc} is built at {d.loc}"
            if WORD_RE.match(b) and self.macros[b]:
                if level >= MAX_DEPTH:
                    return "open", f"'{a}' at {loc} expands too deep"
                r = self.expands_to(b, v, d.loc, missing, level + 1, path)
                if r:
                    return r
            elif not WORD_RE.match(b) and \
                    ("," in b or v in edges(b) or
                     any(self.macros[t] for t in IDENT_RE.findall(b))):
                return "open", f"'{a}' at {loc} expands to '{b}' ({d.loc})"
        return []

    def mention(self, macro, params, variadic, want, expand, use, depth,
                missing):
        """'macro' named without a call: it only expands if a '(' ends
        up after it."""
        d = use.define
        if use.outer is not None:
            if use.outer[0] is None:
                return "open", (f"{macro} is passed on inside an "
                                f"expression at {use.loc}")
            return self.passed(macro, params, variadic, want, use, depth,
                               missing)
        if use.nextc == "":
            if d is not None and d.params is None and norm(d.body) == macro:
                if depth >= MAX_DEPTH:
                    return "open", f"aliases nested too deep at {use.loc}"
                return self.check(d.name, params, variadic, want, expand,
                                  depth + 1, missing, file_of(use.loc))
            return "open", (f"{macro} ends the body of "
                            f"{d.name if d else '?'} at {use.loc}")
        if self.macros[use.nextc]:
            return "open", (f"{macro} is followed by the macro "
                            f"{use.nextc} at {use.loc}")
        return UNUSED

    def passed(self, macro, params, variadic, want, use, depth, missing):
        """'macro' is a whole argument of a call to another macro, which
        may call it: read where it does."""
        name, k, args = use.outer
        if not self.macros[name]:
            return UNUSED               # a function: macro is not expanded
        defs = self.get(self.defs, name, missing)
        if defs is None:
            return PENDING
        defs = self.visible(defs, file_of(use.loc))
        if not defs:
            return UNUSED               # a function: macro is not expanded
        if depth >= MAX_DEPTH:
            return "open", f"nested deeper than {MAX_DEPTH} macros at {use.loc}"
        best = UNUSED
        for d in defs:
            if d.params is None:
                best = worse(best, ("open", f"{macro} is passed to {name}, "
                                    f"an object-like macro, at {use.loc}"))
                continue
            calls = self.calls_of(d, k, args, use, depth, missing)
            if isinstance(calls, tuple):
                best = worse(best, calls)
                continue
            for cargs, exp, where in calls:
                r = self.call(params, variadic, want, exp, cargs, use.define,
                              where, depth + 1, missing, spliced=bool(exp),
                              path=file_of(use.loc))
                if r[0] == "used":
                    return r
                best = worse(best, r)
        return best

    def calls_of(self, d, k, args, use, depth, missing):
        """Calls of parameter k in the body of macro d, called with
        'args': [(call args, plainly substituted indexes, where)], or an
        (open|pending, why) verdict."""
        key = (d.name, d.loc, k, tuple(args), use.loc, depth)
        if key not in self.calls:
            r = self.find_calls(d, k, args, use, depth, missing)
            if r == PENDING:
                return r
            self.calls[key] = r
        return self.calls[key]

    def find_calls(self, d, k, args, use, depth, missing):
        if k >= len(d.params) or (d.variadic and k == len(d.params) - 1):
            return "open", f"{d.name}() takes it as a variable argument"
        p, body, out = d.params[k], d.body, []
        where = f"{use.loc} via {d.name}() at {d.loc}"
        for m in IDENT_RE.finditer(body):
            pos, end = m.start(), m.end()
            if m.group(0) != p or (pos and body[pos - 1].isdigit()) or \
               pasted(body, pos, end):
                continue
            j, nextc = next_char(body, end, len(body))
            if nextc == "(":
                cargs = call_args(body, j, len(body))
                if cargs is None:
                    return "open", f"cannot read the call at {where}"
                new, exp = [], set()
                for i, a in enumerate(cargs):
                    s, plain = subst(norm(a), d.params, args)
                    new.append(s)
                    if plain:
                        exp.add(i)
                out.append((new, exp, where))
                continue
            inner = enclosing_call(body, pos, end, 0, len(body))
            if inner is None:
                if nextc == "" or self.macros[nextc]:
                    return "open", f"{d.name}() hands it on at {where}"
                continue
            if inner[0] is None:
                return "open", f"{d.name}() hands it on at {where}"
            if not self.macros[inner[0]]:
                continue
            if depth + 1 >= MAX_DEPTH:
                return "open", f"nested deeper than {MAX_DEPTH} macros at {where}"
            defs = self.get(self.defs, inner[0], missing)
            if defs is None:
                return PENDING
            iargs = [subst(a, d.params, args)[0] for a in inner[2]]
            for d2 in self.visible(defs, file_of(use.loc)):
                if d2.params is None:
                    return "open", f"{d.name}() hands it on at {where}"
                r = self.calls_of(d2, inner[1], iargs, use, depth + 1, missing)
                if isinstance(r, tuple):
                    return r
                out += r
        return out

    def ways(self, name):
        """[(template, fill), ...]: every way a macro could spell name."""
        return [(t, f) for t, fills in self.pastes.templates_for(name)
                for f in fills]

    def one(self, t, fill, missing):
        if t.variadic and t.params[-1] in fill:
            return "open", f"{t.macro}() pastes its variable arguments"
        want = {t.params.index(p): v for p, v in fill.items()} \
            if t.params is not None else {}
        return self.check(t.macro, t.params, t.variadic, want, set(), 0,
                          missing, t.path)

    def resolve(self, name, missing):
        ways = self.ways(name)
        if not ways:
            return "open", "no template found"
        best = ("unused", f"{len(ways)} ways to spell it, no use passes "
                "the pieces")
        for t, fill in ways:
            r = self.one(t, fill, missing)
            if r[0] == "used":
                return "used", f"{t.macro}() at {r[1]}"
            if ORDER.index(r[0]) > ORDER.index(best[0]):
                best = r
        return best

    def resolve_all(self, names):
        """{name: (verdict, why)} with verdict used, unused or open."""
        todo, done = set(names), {}
        for _ in range(MAX_ROUNDS):
            missing = set()
            for n in sorted(todo):
                v = self.resolve(n, missing)
                if v[0] != "pending":
                    done[n] = v
            todo -= set(done)
            if not todo or not missing:
                break
            self.load(missing)
        for n in todo:
            done[n] = ("open", "macro uses nested too deep to follow")
        return done

    def one_loaded(self, t, fill):
        for _ in range(MAX_ROUNDS):
            missing = set()
            r = self.one(t, fill, missing)
            if r[0] != "pending" or not missing:
                return r
            self.load(missing)
        return "open", "macro uses nested too deep to follow"


def settle(index, cands, jobs=None):
    """Drop [paste?] where no macro use builds the name; turn it into
    [paste-used] where one does."""
    tagged = [c for c in cands if "paste?" in c.tags]
    if not tagged:
        return {}
    res = Resolver(index, jobs).resolve_all({c.name for c in tagged})
    for c in tagged:
        verdict = res[c.name][0]
        if verdict == "unused":
            c.tags.remove("paste?")
        elif verdict == "used":
            c.tags[c.tags.index("paste?")] = "paste-used"
    return res


def explain(index, names, jobs=None, out=None):
    """Print every way each name could be spelled and what decided it."""
    r = Resolver(index, jobs)
    res = r.resolve_all(names)
    for name in names:
        verdict, why = res[name]
        print(f"{name}: {verdict} ({why})", file=out)
        for t, fill in r.ways(name):
            v, where = r.one_loaded(t, fill)
            args = ", ".join(f"{p}={x}" for p, x in fill.items())
            uses = len(r.uses.get(t.macro, ()))
            print(f"  {t.macro}({', '.join(t.params or ())}) in {t.path}: "
                  f"needs {args or 'nothing'}; {uses} uses -> {v}"
                  + (f" ({where})" if where else ""), file=out)
