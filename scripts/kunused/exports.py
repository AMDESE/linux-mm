# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Shivank Garg <shivankg@amd.com>
"""Exports that no module needs.

An EXPORT_SYMBOL*() only matters while some module links against the
symbol.  Each export leaves an __export_symbol_<name> marker in the
object that defines it (include/linux/export.h), each module object
lists what it imports as undefined symbols, and symbol_get() keeps the
names it looks up in a .no_trim_symbol section.  collect() reads all
three from a build with CONFIG_MODULES=y, along with the sources that
make up each module.

find() reports every export that no module of any collected build
imports: "unexport" when the tree still uses the symbol, so only the
EXPORT_SYMBOL line goes, and "unused" when nothing does.  check_patch()
asks the same question for just the symbols a patch touches.

Use allmodconfig: every tristate user is a module there, so a symbol
that some module could use is imported by one.  Modules that only build
on other architectures need a build of each.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

import externs
from pipeline import git_out
from source import EXCLUDE, IDENT_RE
from verify import build_name, nm_tool, object_source

MARKER = "__export_symbol_"
SYMBOL_GET = {"__symbol_get", "__symbol_get_gpl"}
EXPORT_LINE_RE = re.compile(
    r"\b(EXPORT_SYMBOL\w*)\(\s*([A-Za-z_]\w*)\s*[,)]")
READELF_STRING_RE = re.compile(r"^\s*\[\s*[0-9a-f]+\]\s+(\S+)", re.M)
HUNK_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
# Userspace and host tools: a name there is not a kernel user.
NOT_KERNEL = ("tools/", "scripts/", "usr/")
TSV_HEADER = ("# kunused exports: status, name, defined in, export sites, "
              "uses, builds, tags, macro")


def readelf_tool():
    if os.environ.get("READELF"):
        return os.environ["READELF"]
    if os.environ.get("LLVM"):
        return "llvm-readelf"
    return os.environ.get("CROSS_COMPILE", "") + "readelf"


def _symbols(objs):
    """[(object, type, name)] for every symbol of 'objs'."""
    r = subprocess.run([nm_tool(), "-A", "--no-sort", *objs],
                       capture_output=True, text=True, errors="replace")
    out = []
    for line in r.stdout.splitlines():
        f = line.split()
        if len(f) >= 2:
            out.append((f[0].split(":", 1)[0], f[-2], f[-1]))
    return out


def _symbol_gets(obj):
    """Names that symbol_get() looks up by string in 'obj'."""
    r = subprocess.run([readelf_tool(), "-p", ".no_trim_symbol", obj],
                       capture_output=True, text=True, errors="replace")
    return READELF_STRING_RE.findall(r.stdout)


def _sources(root, build, objs):
    return {s for s in (object_source(root, build, os.path.join(build, o))
                        for o in objs) if s}


def collect(build, jobs=None):
    """What one build exports, what its modules import and which sources
    went into which module, as a dict that json.dump() can save."""
    build = os.path.realpath(build)
    vmlinux = os.path.join(build, "vmlinux.o")
    order = os.path.join(build, "modules.order")
    if not os.path.isfile(vmlinux) or not os.path.isfile(order):
        sys.exit(f"kunused: {build} has no vmlinux.o or modules.order; "
                 "it needs a finished build with CONFIG_MODULES=y")
    link = os.path.join(build, "source")
    root = os.path.realpath(link) if os.path.isdir(link) else os.getcwd()
    with open(order) as f:
        mods = [re.sub(r"\.ko$", ".o", l.strip()) for l in f if l.strip()]
    owner = {vmlinux: "vmlinux"}
    owner.update({os.path.join(build, m): m[:-2] for m in mods})
    objs = list(owner)[1:]

    with ThreadPoolExecutor(jobs or os.cpu_count()) as ex:
        found = [s for ss in ex.map(_symbols, [[vmlinux]] +
                                    [objs[i:i + 256]
                                     for i in range(0, len(objs), 256)])
                 for s in ss]
    exports, imports, getters = {}, defaultdict(set), {vmlinux}
    for obj, typ, name in found:
        mod = owner.get(obj)
        if not mod:
            continue
        if typ == "U":
            if mod != "vmlinux":
                imports[name].add(mod)
                if name in SYMBOL_GET:
                    getters.add(obj)
        elif name.startswith(MARKER):
            exports.setdefault(name[len(MARKER):], mod)
    # symbol_get() goes through the export table even from built-in code
    for obj in sorted(getters):
        for name in _symbol_gets(obj):
            imports[name].add(owner[obj] + " (symbol_get)")

    modules = {}
    for m in mods:
        try:
            with open(os.path.join(build, m[:-2] + ".mod")) as f:
                members = f.read().split()
        except OSError:
            members = [m]
        modules[m[:-2]] = sorted(_sources(root, build, members))
    built = set()
    for d, _, files in os.walk(build):
        built |= _sources(root, build, [
            os.path.relpath(os.path.join(d, f), build) for f in files
            if f.endswith(".o") and not f.endswith(".mod.o")])
    return {"build": build_name(build), "dir": build,
            "commit": git_out("rev-parse", "HEAD", cwd=root),
            "exports": exports,
            "imports": {n: sorted(m) for n, m in imports.items()
                        if n in exports},
            "modules": modules, "built": sorted(built)}


def load(sources, jobs=None):
    """collect() each build directory, json.load() each saved file."""
    out = []
    for s in sources:
        if os.path.isdir(s):
            print(f"kunused: reading {s}", file=sys.stderr)
            out.append(collect(s, jobs))
        else:
            with open(s) as f:
                out.append(json.load(f))
    return out


class Builds:
    """The union of several collected builds."""

    def __init__(self, data):
        self.names = [d["build"] for d in data]
        self.exported = defaultdict(list)       # name -> builds exporting it
        self.owner = {}                         # name -> vmlinux or module
        self.imports = defaultdict(set)         # name -> importing modules
        self.src_mods = defaultdict(set)        # source -> its modules
        self.built = set()                      # every source compiled
        for d in data:
            for name, mod in d["exports"].items():
                self.exported[name].append(d["build"])
                self.owner.setdefault(name, mod)
            for name, mods in d["imports"].items():
                self.imports[name].update(mods)
            for mod, srcs in d["modules"].items():
                for s in srcs:
                    self.src_mods[s].add(mod)
            self.built.update(d["built"])


def tree_hits(names, jobs=None):
    """({name: [(path, n, code)]}, {name: [("path:n", macro)]}): the
    lines of the tree that use each name, without its definitions,
    declarations, comments and exports, and the lines that export it."""
    uses, sites = defaultdict(list), defaultdict(list)
    if not names:
        return uses, sites
    with tempfile.NamedTemporaryFile("w", suffix=".names") as pat:
        pat.write("\n".join(sorted(names)) + "\n")
        pat.flush()
        r = subprocess.run(["git", "grep", "--untracked", "-lwF", "-f",
                            pat.name], capture_output=True, text=True)
    files = [f for f in r.stdout.split("\n")
             if f and not f.startswith(EXCLUDE + NOT_KERNEL)]
    for name, hits in externs.grep(files, set(names), jobs).items():
        for h, decl in hits:
            path, n, code = h.split(":", 2)
            m = [m for m in EXPORT_LINE_RE.findall(code) if m[1] == name]
            if m:
                sites[name].append((f"{path}:{n}", m[0][0]))
            elif not decl and not externs.defines(code, name):
                uses[name].append((path, int(n), code.strip()))
    return uses, sites


class Unneeded:
    def __init__(self, name, status, owner, sites, uses, builds, tags,
                 built=()):
        self.name, self.status, self.owner = name, status, owner
        self.sites = [loc for loc, _ in sites]
        self.macro = sites[0][1] if sites else ""
        self.uses, self.builds, self.tags = uses, builds, tags
        # did a build compile an export line, and a built-in use?
        self.site_built = any(s.rsplit(":", 1)[0] in built
                              for s in self.sites)
        self.use_built = any(p in built and p.endswith((".c", ".S"))
                             for p, _, _ in uses)

    def path(self):
        return self.sites[0].rsplit(":", 1)[0] if self.sites else ""

    def tsv(self):
        uses = ",".join(f"{p}:{n}" for p, n, _ in self.uses)
        return "\t".join((self.status, self.name, self.owner,
                          ",".join(self.sites), uses, ",".join(self.builds),
                          ",".join(self.tags), self.macro))


def find(builds, jobs=None):
    """Exports that no module of any build imports, sorted by site."""
    names = [n for n in builds.exported if not builds.imports.get(n) and
             not externs.COMPILER_EMITTED.match(n)]
    uses, sites = tree_hits(names, jobs)
    out = []
    for name in names:
        u = uses.get(name, [])
        tags = [] if sites.get(name) else ["no-site"]
        if any(p.endswith(".h") for p, _, _ in u):
            tags.append("header")
        if len(set(builds.exported[name])) < len(set(builds.names)):
            tags.append("some-builds")
        out.append(Unneeded(name, "unexport" if u else "unused",
                            builds.owner[name], sites.get(name, []), u,
                            builds.exported[name], tags, builds.built))
    return sorted(out, key=lambda c: (c.path(), c.name))


def filtered(cands, regexes, maint):
    if not regexes:
        return cands
    rx = re.compile("|".join(regexes))
    return [c for c in cands
            if any(rx.search(s) for s in
                   (c.path(), c.owner, *maint.lookup(c.path())))]


def print_unneeded(cands, builds, maint, show_all=False, out=sys.stdout):
    by_sec = defaultdict(list)
    shown = [c for c in cands if show_all or "no-site" not in c.tags]
    for c in shown:
        by_sec[maint.lookup(c.path()) if c.path() else ("(no export line "
                                                        "found)", "")]\
            .append(c)
    for (title, lst), cs in sorted(by_sec.items()):
        print(f"{title}" + (f" <{lst}>" if lst else ""), file=out)
        for c in cs:
            where = c.sites[0] if c.sites else c.owner
            more = ""
            if c.uses:
                p, n, _ = c.uses[0]
                more = f"  used in {p}:{n}" + (f" (+{len(c.uses) - 1})"
                                              if len(c.uses) > 1 else "")
            tags = "".join(f" [{t}]" for t in c.tags)
            print(f"  {where:<40} {c.name:<36} {c.status}{tags}{more}",
                  file=out)
    n = Counter(c.status for c in shown)
    hidden = len(cands) - len(shown)
    print(f"{len(shown)} exports no module imports in "
          f"{', '.join(sorted(set(builds.names)))}: "
          f"{n['unexport']} unexport, {n['unused']} unused" +
          (f" ({hidden} [no-site] hidden, --all shows them)" if hidden
           else ""), file=out)


def write_tsv(cands, f):
    f.write(TSV_HEADER + "\n")
    for c in cands:
        f.write(c.tsv() + "\n")


# ------------------------------- patches -------------------------------

def _diff_path(p):
    p = p.split("\t")[0].strip()
    if p == "/dev/null":
        return None
    return p[2:] if p.startswith(("a/", "b/")) else p


def parse_diff(text):
    """{path: (added, removed)} for a unified diff: added lines as
    (line number in the new file, code), removed lines as code."""
    files, old, path = {}, None, None
    left = right = new = 0
    for line in text.split("\n"):
        if left > 0 or right > 0:
            tag, code = line[:1], line[1:]
            if tag == "+":
                files[path][0].append((new, code))
                new, right = new + 1, right - 1
            elif tag == "-":
                files[path][1].append(code)
                left -= 1
            elif tag != "\\":
                new, left, right = new + 1, left - 1, right - 1
            continue
        m = HUNK_RE.match(line)
        if m and path:
            left = int(m.group(1)) if m.group(1) is not None else 1
            right = int(m.group(3)) if m.group(3) is not None else 1
            new = int(m.group(2))
        elif line.startswith("--- "):
            old = _diff_path(line[4:])
        elif line.startswith("+++ "):
            path = _diff_path(line[4:]) or old
            files.setdefault(path, ([], []))
    return files


def read_patch(arg):
    """The diff text for a patch file, '-' (stdin), or a git revision or
    range."""
    if arg == "-":
        return sys.stdin.read()
    if os.path.isfile(arg):
        with open(arg, errors="replace") as f:
            return f.read()
    cmd = ["diff", arg] if ".." in arg else ["show", "--format=", arg]
    r = subprocess.run(["git", *cmd, "--no-color", "--no-ext-diff"],
                       capture_output=True, text=True, errors="replace")
    if r.returncode:
        sys.exit(f"kunused: {arg} is neither a file nor a git revision")
    return r.stdout


def is_applied(text):
    r = subprocess.run(["git", "apply", "--check", "-R", "-"], input=text,
                       capture_output=True, text=True)
    return r.returncode == 0


def verdict(builds, name, uses, dropped_from):
    """('needed', {module: why}) when a module still uses 'name',
    ('unsure', [locations]) when the only uses are where no module
    mapping reaches (headers, Rust, files no build compiled), else
    ('unneeded', [built-in uses])."""
    mods = {m: "imports it" for m in builds.imports.get(name, ())
            if m not in dropped_from}
    loose, builtin = [], []
    for path, n, _ in uses:
        if path.startswith(NOT_KERNEL):
            continue
        loc = f"{path}:{n}"
        if path in builds.src_mods:
            for m in builds.src_mods[path]:
                mods.setdefault(m, f"uses it at {loc}")
        elif path.endswith((".c", ".S")) and path in builds.built:
            builtin.append(loc)
        else:
            loose.append(loc)
    if mods:
        return "needed", mods
    if loose:
        return "unsure", loose
    return "unneeded", builtin


def _few(locs, n=3):
    return ", ".join(locs[:n]) + (f" (+{len(locs) - n})" if len(locs) > n
                                  else "")


def _mods(mods, n=3):
    items = [f"{m} ({why})" for m, why in sorted(mods.items())]
    return _few(items, n)


def check_patch(builds, text, jobs=None):
    """[(level, message)] about the exports a patch adds or removes, and
    about exports whose last module user it removes."""
    diff = parse_diff(text)
    added, removed = {}, {}
    plus, minus = defaultdict(Counter), defaultdict(Counter)
    for path, (adds, dels) in diff.items():
        for n, code in adds:
            for _, name in EXPORT_LINE_RE.findall(code):
                added.setdefault(name, f"{path}:{n}")
            plus[path].update(IDENT_RE.findall(code))
        for code in dels:
            for _, name in EXPORT_LINE_RE.findall(code):
                removed.setdefault(name, path)
            minus[path].update(IDENT_RE.findall(code))
    for name in added:                  # moved, not removed
        removed.pop(name, None)
    # modules the patch removes a direct reference from, per name
    dropped_from = defaultdict(set)
    for path, names in minus.items():
        for name, k in names.items():
            if k > plus[path][name] and name in builds.exported:
                dropped_from[name] |= builds.src_mods.get(path, set())
    lost = {n for n, mods in dropped_from.items()
            if mods & builds.imports.get(n, set()) and
            n not in added and n not in removed}

    uses, sites = tree_hits(set(added) | set(removed) | lost, jobs)
    out = []
    for name, loc in sorted(added.items()):
        v, why = verdict(builds, name, uses.get(name, []),
                         dropped_from[name])
        if v == "needed":
            out.append(("ok", f"{name}: exported at {loc}, used by "
                        f"{_mods(why)}"))
        elif v == "unsure":
            out.append(("CHECK", f"{name}: no module in the builds uses it, "
                        f"but it is used from {_few(why)}; check whether a "
                        "module reaches it from there"))
        else:
            users = (f"only built-in code uses it: {_few(why)}" if why else
                     "nothing uses it at all")
            out.append(("WARNING", f"{name}: the export at {loc} is not "
                        f"needed, no module uses it; {users}"))
    for name, path in sorted(removed.items()):
        v, why = verdict(builds, name, uses.get(name, []),
                         dropped_from[name])
        if v == "needed":
            out.append(("ERROR", f"{name}: its export is removed from {path}"
                        f", but modules still use it: {_mods(why)}"))
        elif v == "unsure":
            out.append(("CHECK", f"{name}: its export is removed from {path}"
                        f"; no module in the builds uses it, but it is used "
                        f"from {_few(why)}"))
        else:
            out.append(("ok", f"{name}: no module uses it, removing its "
                        "export is fine"))
    for name in sorted(lost):
        v, why = verdict(builds, name, uses.get(name, []),
                         dropped_from[name])
        gone = ", ".join(sorted(dropped_from[name] &
                                builds.imports[name]))
        at = _few([loc for loc, _ in sites.get(name, [])]) or \
            builds.owner.get(name, "?")
        if v == "unneeded":
            rest = (f"built-in code still uses it: {_few(why)}" if why else
                    "nothing else uses it, so it can go entirely")
            out.append(("NOTE", f"{name}: this patch removes its last module "
                        f"user ({gone}); the export at {at} can go; {rest}"))
        elif v == "unsure":
            out.append(("CHECK", f"{name}: this patch removes its use from "
                        f"{gone}; no other module in the builds uses it, but "
                        f"it is used from {_few(why)}"))
        else:
            out.append(("ok", f"{name}: still used by {_mods(why)}"))
    return out
