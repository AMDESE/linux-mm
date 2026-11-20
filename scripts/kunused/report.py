# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Shivank Garg <shivankg@amd.com>
"""One self-contained HTML page, grouped by MAINTAINERS section and ranked
by how much each section can act on."""
import html
import re
from collections import Counter, defaultdict

from candidates import TAGS
from maintainers import Maintainers

# (key, label, short label for rows, colour, what to do)
TIERS = [
    ("confirmed", "Sure: build-verified unused", "verified", "#1a7f37",
     "no reference anywhere in the tree, every '##' macro that could "
     "build the name was followed, and a build compiled it and saw no "
     "use: send patches"),
    ("likely", "Unsure: not built", "not built", "#3b6fd4",
     "no reference anywhere in the tree, but no build compiled it: build "
     "a config that does (e.g. ARCH=riscv LLVM=1) before removing it"),
    ("check", "Unsure: check by hand", "check", "#b7791f",
     "a '##' macro could build this name and not all its uses could be"
     " followed, or a Makefile or script names it: read the code"),
    ("uapi", "Keep: userspace API", "uapi", "#6e7781",
     "uapi header, userspace may use it"),
    ("generated", "Keep: generated or imported", "generated", "#8250df",
     "generated file or code synced from another project: fix it there"),
    ("rejected", "Rejected: a user was found", "rejected", "#cf222e",
     "the build, or a '##' macro call, uses these"),
]
ACTIONABLE = ("confirmed", "likely")
UNVERIFIED = ("Unsure: no build check", "unverified",
              "no sign of a user; not cross-checked with a build")
COLOR = {t[0]: t[3] for t in TIERS}
KINDS = (("inline", "static inline"), ("function", "function"),
         ("variable", "variable"))
FILTER_TAGS = ("exported", "via-unused", "paste?", "paste-used", "non-c?")

GENERATED_RE = re.compile(r"auto-?generated|automatically generated|"
                          r"do not edit|this file is generated", re.I)
IMPORTED = ("include/linux/atomic/", "drivers/acpi/acpica/", "include/acpi/",
            "lib/zstd/", "lib/xz/")
_generated = {}


def is_generated(path):
    """Generated files say so in their first lines; IMPORTED code is
    maintained in another project."""
    if path not in _generated:
        try:
            with open(path, errors="replace") as f:
                head = "".join(f.readline() for _ in range(30))
        except OSError:
            head = ""
        _generated[path] = (path.startswith(IMPORTED) or
                            bool(GENERATED_RE.search(head)))
    return _generated[path]


def tier_of(c, verify):
    if "uapi" in c.tags:
        return "uapi"
    if verify and c.name in verify["real_use"] or "paste-used" in c.tags:
        return "rejected"
    if all(is_generated(p) for p, _ in c.sites):
        return "generated"
    # A build cannot see uses outside C, nor a '##' macro in code that
    # it did not compile, so neither is ever "verified".
    if "non-c?" in c.tags or "paste?" in c.tags:
        return "check"
    if verify and c.name in verify["confirmed"]:
        return "confirmed"
    return "likely"


# From best to worst; a tier not in here counts as "check" for a callee.
RANK = ("confirmed", "likely", "check", "rejected")


def tiers(cands, verify):
    """tier_of() of each candidate, made no better than that of the unused
    code calling it: a helper is only unused if its callers are.  Returns
    [(tier, caller it took the tier from, "" if unknown, or None)]."""
    out = [(tier_of(c, verify), None) for c in cands]
    while True:
        status = {}
        for c, (t, _) in zip(cands, out):
            t = t if t in RANK else "check"
            status[c.name] = max(t, status.get(c.name, t), key=RANK.index)
        changed = False
        for i, c in enumerate(cands):
            t, via = out[i]
            if t not in RANK or "via-unused" not in c.tags:
                continue
            for p in c.callers or [""]:
                s = status.get(p, "check")
                if RANK.index(s) > RANK.index(t):
                    t, via = s, p
            if t != out[i][0]:
                out[i], changed = (t, via), True
        if not changed:
            return out


# Unneeded exports: (key, label, colour, what to do)
XSTATUS = [
    ("unexport", "Unexport", "#0969da",
     "only built-in code uses the symbol: drop the EXPORT_SYMBOL line"),
    ("unused", "Unused", "#1a7f37",
     "nothing uses the symbol: remove it along with its export"),
]
XCOLOR = {k: c for k, _, c, _ in XSTATUS}
# Export macros get a checkbox each; the rest are "other".
XMACROS = ("EXPORT_SYMBOL", "EXPORT_SYMBOL_GPL", "EXPORT_SYMBOL_NS",
           "EXPORT_SYMBOL_NS_GPL")
XTAGS = {"header": "used from a header, maybe by an inline a module of "
                   "another config could call",
         "some-builds": "not exported in every build given"}


XCHECK = [
    ("verified", "build-verified", "#1a7f37",
     "a build compiled the export line and no module imported the symbol; "
     "for unexport a compiled built-in file uses it, for unused the build "
     "cross-check saw no use"),
    ("check", "check by hand", "#b7791f",
     "the build did not settle it; the note says why"),
]


XCHECKCOLOR = {k: c for k, _, c, _ in XCHECK}
XCHECKSHORT = {"verified": "verified", "check": "check"}


def macro_group(c):
    if not c.macro:
        return "none"
    return c.macro if c.macro in XMACROS else "other"


def export_check(c, verify):
    """('verified' or 'check', why) for an unneeded export.  A use the
    build saw turns 'unused' into 'unexport'."""
    if not c.sites:
        return "check", "exported by a macro or a generated file"
    if not c.site_built:
        return "check", "no build compiled the export line shown"
    if c.status == "unused" and verify and c.name in verify["real_use"]:
        loc, _ = verify["real_use"][c.name]
        c.status = "unexport"
        return "verified", f"the build saw a use at {loc}"
    if c.status == "unexport":
        if c.use_built:
            return "verified", ""
        return "check", ("no compiled file uses it, only headers or code "
                         "no build compiled: it may be unused")
    if not verify:
        return "check", "not cross-checked with a build (report --verify)"
    if c.name in verify["confirmed"]:
        return "verified", ""
    return "check", "the build cross-check did not cover it"


class Report:
    def __init__(self, cands, verify=None, filters=(), maintainers=None,
                 exports=None, export_builds=()):
        self.verify = verify
        if verify:
            verify["confirmed"] = set(verify["confirmed"])
        maint = maintainers or Maintainers()
        filt = re.compile("|".join(filters)) if filters else None
        self.rows, self.via = [], {}
        for c, (tier, via) in zip(cands, tiers(cands, verify)):
            sub = maint.lookup(c.path)
            if filt and not (any(filt.search(p) for p, _ in c.sites) or
                             any(filt.search(s) for s in sub)):
                continue
            if via is not None:
                self.via[c.name] = via
            self.rows.append((c, tier, sub))
        self.by_sub = defaultdict(list)
        for r in self.rows:
            self.by_sub[r[2]].append(r)
        self.order = sorted(self.by_sub, key=lambda s: (
            -self.actionable(s), s[0]))
        self.total = Counter(t for _, t, _ in self.rows)
        self.tiers = []
        for key, label, short, color, what in TIERS:
            if key == "likely" and not verify:
                label, short, what = UNVERIFIED
            self.tiers.append((key, label, short, color, what))
        self.short = {t[0]: t[2] for t in self.tiers}

        self.exports, self.export_builds = exports, sorted(set(export_builds))
        self.xby_sub, self.xcheck = defaultdict(list), {}
        for c in exports or ():
            self.xcheck[id(c)] = export_check(c, verify)
            sub = (maint.lookup(c.path()) if c.path() else
                   ("(no EXPORT_SYMBOL line in the tree)", ""))
            if filt and not (filt.search(c.path()) or filt.search(c.owner)
                             or any(filt.search(s) for s in sub)):
                continue
            self.xby_sub[sub].append(c)
        self.xrows = [c for cs in self.xby_sub.values() for c in cs]
        self.xorder = sorted(self.xby_sub, key=lambda s: (
            -len(self.xby_sub[s]), s[0]))

    def actionable(self, sub):
        return sum(t in ACTIONABLE for _, t, _ in self.by_sub[sub])

    def source(self):
        if not self.verify:
            return ("Found by a whole-tree scan, not cross-checked with a "
                    "build (the 'run' command does that).")
        cfg = self.verify.get("config", "")
        n = self.verify.get("builds", 1)
        what = (f"a {self.verify['build']} {cfg} build, which compiled"
                if n == 1 else f"{n} builds ({self.verify['build']}), which "
                "together compiled")
        return (f"Found by a whole-tree scan and cross-checked against "
                f"{what} {self.verify['compiled']} of the candidates. "
                f"\u201cVerified\u201d means the scan found no use anywhere "
                f"in the tree and no build saw a reference either."
                ).replace("  ", " ")

    def breakdown(self, tier):
        rows = [c for c, t, _ in self.rows if t == tier]
        kinds = Counter(c.kind for c in rows)
        parts = [f"{kinds[k]} {label}" for k, label in KINDS if kinds[k]]
        exported = sum("exported" in c.tags for c in rows)
        return ", ".join(parts) + (f"; {exported} exported" if exported
                                   else "")

    def text(self, top=12):
        out = [f"{len(self.rows)} candidates"]
        for k, label, _, _, _ in self.tiers:
            if self.total[k]:
                extra = (f"  ({self.breakdown(k)})" if k in ACTIONABLE
                         else "")
                out.append(f"  {self.total[k]:5}  {label}{extra}")
        out.append("\nTop sections (verified + not built):")
        out += [f"  {self.actionable(s):5}  {s[0]}" +
                (f"  <{s[1]}>" if s[1] else "")
                for s in self.order[:top] if self.actionable(s)]
        if self.exports is not None:
            n = Counter(c.status for c in self.xrows)
            macros = Counter(macro_group(c) for c in self.xrows)
            out.append(f"\n{len(self.xrows)} exports no module imports in "
                       f"{', '.join(self.export_builds)}: "
                       f"{n['unexport']} unexport, {n['unused']} unused")
            out.append("  " + ", ".join(f"{macros[m]} {m}" for m in
                                        XMACROS + ("other", "none")
                                        if macros[m]))
            ver = Counter((c.status, self.xcheck[id(c)][0])
                          for c in self.xrows if c.sites)
            out.append("  with an export line: " + ", ".join(
                f"{ver[(s, k)]} {s} {label}" for s, _, _, _ in XSTATUS
                for k, label, _, _ in XCHECK if ver[(s, k)]))
        return "\n".join(out)

    def _note(self, c, tier):
        e, note = html.escape, []
        if c.name in self.via:
            via = self.via[c.name]
            note.append(f"called from <code>{e(via)}</code> "
                        f"({self.short[tier]})" if via else
                        "its callers are not known")
        elif tier == "rejected" and self.verify and \
           c.name in self.verify["real_use"]:
            loc, code = self.verify["real_use"][c.name]
            note.append(f"used at <code>{e(loc)}</code>: "
                        f"<code>{e(code[:80])}</code>")
        elif tier == "rejected":
            note.append(f"a '##' macro call builds it; <code>kunused.py "
                        f"paste {e(c.name)}</code> shows where")
        p = c.path
        if c.sites[1:]:
            note.append("also " + ", ".join(
                f":{l}" if mp == p else f"{e(mp)}:{l}"
                for mp, l in c.sites[1:]))
        return "; ".join(note)

    def tsv(self):
        out = ["# status\tname\tkind\tlocation\ttags\tsection\tlist"]
        for sub in self.order:
            for c, tier, _ in sorted(self.by_sub[sub],
                                     key=lambda r: r[0].sites[0]):
                p, l = c.sites[0]
                out.append("\t".join((self.short[tier], c.name, c.kind,
                                      f"{p}:{l}", " ".join(c.tags),
                                      sub[0], sub[1])))
        return "\n".join(out) + "\n"

    def html(self):
        e = html.escape
        o = ['<!doctype html><meta charset="utf-8">'
             "<title>Unused kernel code</title>",
             f"<style>{CSS}</style><h1>Unused kernel code</h1>"]
        if self.exports is not None:
            o.append('<nav class="tabs"><a href="#code">Unused code '
                     f"<small>{len(self.rows)}</small></a>"
                     '<a href="#exports">Unneeded exports '
                     f"<small>{len(self.xrows)}</small></a></nav>"
                     '<section id="code">')
        o += [f'<p class="sub">{len(self.rows)} candidates. '
              f"{e(self.source())}</p>", '<div class="cards">']
        for key, label, _, color, what in self.tiers:
            if self.total[key]:
                o.append(f'<label class="card" style="--c:{color}" '
                         f'title="{e(what)}"><input type="checkbox" '
                         f'data-tier="{key}"'
                         f'{" checked" if key in ACTIONABLE else ""}>'
                         f'<b>{self.total[key]}</b><span>{e(label)}</span>'
                         "</label>")
        kinds = Counter(c.kind for c, _, _ in self.rows)
        tags = Counter(t for c, _, _ in self.rows for t in c.tags)
        o.append('</div><div class="filters"><span>kind</span>')
        o += [f'<label><input type="checkbox" data-kind="{k}" checked>'
              f"{label} <small>{kinds[k]}</small></label>"
              for k, label in KINDS if kinds[k]]
        o.append("<span>tags</span>")
        o += [f'<label title="{e(TAGS[t])}">{t} <select data-tag="{t}">'
              '<option value="">any</option><option value="1">with'
              '</option><option value="0">without</option></select>'
              f"<small>{tags[t]}</small></label>"
              for t in FILTER_TAGS if tags[t]]
        o.append('</div><input id="q" placeholder="filter by name, file or '
                 'section…"><p class="hint"><span id="shown"></span> Tick '
                 "a box to show that tier; hover a box or a tag for what "
                 "it means. Sections are ranked by verified and not-built "
                 "entries.</p>")

        for sub in self.order:
            title, mlist = sub
            cnt = Counter(t for _, t, _ in self.by_sub[sub])
            pills = "".join(f'<i style="--c:{t[3]}" title="{e(t[1])}">'
                            f"{cnt[t[0]]}</i>"
                            for t in self.tiers if cnt[t[0]])
            o.append(f'<details class="sub"><summary><span class="t">'
                     f'{e(title)}</span><span class="l">{e(mlist)}</span>'
                     f'<span class="cnt"></span>{pills}</summary><table>'
                     "<tr><th>location</th><th>symbol</th><th>kind</th>"
                     "<th>status</th><th>tags</th><th>note</th></tr>")
            for c, tier, _ in sorted(self.by_sub[sub],
                                     key=lambda r: r[0].sites[0]):
                p, l = c.sites[0]
                badges = "".join(f'<em title="{e(TAGS.get(t, ""))}">'
                                 f"{e(t)}</em>" for t in c.tags)
                o.append(f'<tr data-tier="{tier}" data-kind="{c.kind}" '
                         f'data-tags="{e(" ".join(c.tags))}" '
                         f'style="--c:{COLOR[tier]}">'
                         f'<td class="loc">{e(p)}:{l}</td>'
                         f'<td class="n">{e(c.name)}</td><td>{c.kind}</td>'
                         f'<td><b class="st">{e(self.short[tier])}</b></td>'
                         f"<td>{badges}</td>"
                         f"<td>{self._note(c, tier)}</td></tr>")
            o.append("</table></details>")
        if self.exports is not None:
            o.append("</section>")
            o += self.exports_html()
            o.append(f"<script>const XTOTAL={len(self.xrows)};{XJS}"
                     "</script>")
        o.append(f"<script>const TOTAL={len(self.rows)};{JS}</script>")
        return "\n".join(o)

    def exports_html(self):
        e = html.escape
        builds = ", ".join(self.export_builds)
        o = ['<section id="exports" hidden>',
             f'<p class="sub">{len(self.xrows)} exports that no module '
             f"imports in {e(builds)}. An EXPORT_SYMBOL*() is only needed "
             "while some module links against the symbol; these lose the "
             "export line (\u201cunexport\u201d), or go entirely when "
             "nothing uses them (\u201cunused\u201d). A module of another "
             "architecture may still need one: give one allmodconfig "
             "build per architecture before sending patches.</p>",
             '<div class="cards">']
        n = Counter(c.status for c in self.xrows)
        for key, label, color, what in XSTATUS:
            if n[key]:
                o.append(f'<label class="card" style="--c:{color}" '
                         f'title="{e(what)}"><input type="checkbox" '
                         f'data-xstatus="{key}" checked><b>{n[key]}</b>'
                         f"<span>{e(label)}</span></label>")
        macros = Counter(macro_group(c) for c in self.xrows)
        owners = Counter("vmlinux" if c.owner == "vmlinux" else "module"
                         for c in self.xrows)
        tags = Counter(t for c in self.xrows for t in c.tags)
        o.append('</div><div class="filters"><span>export</span>')
        labels = {"other": "other EXPORT_*", "none": "macro-generated"}
        nosite = "no EXPORT_SYMBOL*(name) line in the tree"
        o += [f'<label title="{nosite if m == "none" else ""}">'
              f'<input type="checkbox" data-xmacro="{m}"'
              f'{"" if m == "none" else " checked"}>{labels.get(m, m)} '
              f"<small>{macros[m]}</small></label>"
              for m in XMACROS + ("other", "none") if macros[m]]
        checks = Counter(self.xcheck[id(c)][0] for c in self.xrows)
        o.append("<span>build</span>")
        o += [f'<label title="{e(what)}"><input type="checkbox" '
              f'data-xcheck="{k}" checked>{label} <small>{checks[k]}'
              "</small></label>"
              for k, label, _, what in XCHECK if checks[k]]
        o.append("<span>defined in</span>")
        o += [f'<label><input type="checkbox" data-xowner="{k}" checked>'
              f"{k} <small>{owners[k]}</small></label>"
              for k in ("vmlinux", "module") if owners[k]]
        o.append("<span>tags</span>")
        o += [f'<label title="{e(XTAGS[t])}">{t} <select data-xtag="{t}">'
              '<option value="">any</option><option value="1">with'
              '</option><option value="0">without</option></select>'
              f"<small>{tags[t]}</small></label>"
              for t in XTAGS if tags[t]]
        o.append('</div><input id="xq" placeholder="filter by name, file, '
                 'module or section…"><p class="hint"><span id="xshown">'
                 "</span> Macro-generated exports (tracepoints, retpoline "
                 "thunks, generated test modules) have no line to drop and "
                 "are hidden unless ticked.</p>")
        for sub in self.xorder:
            title, mlist = sub
            cs = self.xby_sub[sub]
            cnt = Counter(c.status for c in cs)
            pills = "".join(f'<i style="--c:{color}" title="{e(label)}">'
                            f"{cnt[key]}</i>"
                            for key, label, color, _ in XSTATUS if cnt[key])
            o.append(f'<details class="xsub"><summary><span class="t">'
                     f'{e(title)}</span><span class="l">{e(mlist)}</span>'
                     f'<span class="cnt"></span>{pills}</summary><table>'
                     "<tr><th>location</th><th>symbol</th><th>export</th>"
                     "<th>status</th><th>build</th><th>defined in</th>"
                     "<th>tags</th><th>used in</th></tr>")
            for c in sorted(cs, key=lambda c: (c.sites or [""])[0]):
                uses = ", ".join(f"<code>{e(p)}:{l}</code>"
                                 for p, l, _ in c.uses[:3])
                if len(c.uses) > 3:
                    uses += f" +{len(c.uses) - 3}"
                if c.sites[1:]:
                    uses += ("; also exported at " +
                             ", ".join(e(s) for s in c.sites[1:]))
                badges = "".join(f'<em title="{e(XTAGS.get(t, ""))}">'
                                 f"{e(t)}</em>" for t in c.tags
                                 if t != "no-site")
                owner = "vmlinux" if c.owner == "vmlinux" else "module"
                check, why = self.xcheck[id(c)]
                if why:
                    uses += ("; " if uses else "") + e(why)
                o.append(f'<tr data-xstatus="{c.status}" '
                         f'data-xmacro="{macro_group(c)}" '
                         f'data-xcheck="{check}" '
                         f'data-xowner="{owner}" '
                         f'data-xtags="{e(" ".join(c.tags))}" '
                         f'style="--c:{XCOLOR[c.status]}">'
                         f'<td class="loc">{e(c.sites[0] if c.sites else "")}'
                         f'</td><td class="n">{e(c.name)}</td>'
                         f"<td>{e(c.macro or '(macro)')}</td>"
                         f'<td><b class="st">{c.status}</b></td>'
                         f'<td><b class="st" style="--c:{XCHECKCOLOR[check]}"'
                         f">{XCHECKSHORT[check]}</b></td>"
                         f"<td>{e(c.owner)}</td><td>{badges}</td>"
                         f"<td>{uses}</td></tr>")
            o.append("</table></details>")
        o.append("</section>")
        return o


CSS = """
body{font:14px/1.45 system-ui,sans-serif;margin:24px auto;max-width:1200px;
     padding:0 16px;color:#1f2328}
h1{margin:0 0 4px} .sub{color:#57606a;margin:0 0 16px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.card{border:1px solid #d0d7de;border-left:5px solid var(--c);border-radius:6px;
      padding:8px 12px;display:flex;gap:8px;align-items:center;cursor:pointer}
.card b{font-size:20px;color:var(--c)} .card span{color:#57606a}
#q,#xq{width:100%;padding:8px;border:1px solid #d0d7de;border-radius:6px;
   font-size:14px;box-sizing:border-box}
.hint{color:#6e7781;font-size:12px;margin:4px 0 14px}
details.sub,details.xsub{border:1px solid #d0d7de;border-radius:6px;
                         margin:6px 0}
details.sub[hidden],details.xsub[hidden],section[hidden]{display:none}
nav.tabs{display:flex;gap:4px;border-bottom:1px solid #d0d7de;
         margin:8px 0 14px}
nav.tabs a{padding:6px 14px;text-decoration:none;color:#57606a;
           border:1px solid transparent;border-bottom:none;
           border-radius:6px 6px 0 0;margin-bottom:-1px}
nav.tabs a.on{color:#1f2328;border-color:#d0d7de;background:#fff;
              font-weight:600}
summary{padding:8px 12px;cursor:pointer;display:flex;gap:10px;
        align-items:center}
summary .t{font-weight:600} summary .l{color:#6e7781;font-size:12px;flex:1}
summary i{font-style:normal;background:var(--c);color:#fff;border-radius:10px;
          padding:0 8px;font-size:12px}
table{border-collapse:collapse;width:100%;font-size:13px}
th{text-align:left;color:#57606a;font-weight:500;border-top:1px solid #d0d7de}
td,th{padding:4px 12px;vertical-align:top}
tr[data-tier] td:first-child,tr[data-xstatus] td:first-child{
  border-left:4px solid var(--c)}
tr[hidden]{display:none}
td.loc{font-family:ui-monospace,monospace;color:#57606a;white-space:nowrap}
td.n{font-family:ui-monospace,monospace;font-weight:600}
code{font-size:12px;background:#f6f8fa;padding:0 3px;border-radius:3px}
.filters{display:flex;gap:12px;flex-wrap:wrap;align-items:center;
         margin-bottom:10px;font-size:13px}
.filters>span{color:#57606a;font-weight:600}
.filters label{display:flex;gap:4px;align-items:center}
small{color:#6e7781}
b.st{background:var(--c);color:#fff;border-radius:4px;padding:0 6px;
     font-size:12px;font-weight:500;white-space:nowrap}
em{font-style:normal;font-size:12px;border:1px solid #d0d7de;
   border-radius:10px;padding:0 6px;margin-right:3px;white-space:nowrap}
summary .cnt{color:#57606a;font-size:12px}
"""

JS = """
const boxes=[...document.querySelectorAll('.card input[data-tier]')];
const kinds=[...document.querySelectorAll('input[data-kind]')];
const tags=[...document.querySelectorAll('select[data-tag]')];
const q=document.getElementById('q');
function apply(){
  const on=new Set(boxes.filter(b=>b.checked).map(b=>b.dataset.tier));
  const ks=new Set(kinds.filter(b=>b.checked).map(b=>b.dataset.kind));
  const want=tags.filter(t=>t.value).map(t=>[t.dataset.tag,t.value==='1']);
  const s=q.value.toLowerCase();
  let shown=0;
  document.querySelectorAll('details.sub').forEach(d=>{
    const head=d.querySelector('summary').textContent.toLowerCase();
    let n=0;
    d.querySelectorAll('tr[data-tier]').forEach(tr=>{
      const tg=tr.dataset.tags.split(' ');
      const ok=on.has(tr.dataset.tier)&&ks.has(tr.dataset.kind)&&
        want.every(([t,w])=>tg.includes(t)===w)&&
        (!s||head.includes(s)||tr.textContent.toLowerCase().includes(s));
      tr.hidden=!ok; n+=ok;
    });
    d.hidden=!n; if(s&&n) d.open=true; shown+=n;
    d.querySelector('.cnt').textContent=n+' shown';
  });
  document.getElementById('shown').textContent=
    'Showing '+shown+' of '+TOTAL+'.';
}
[...boxes,...kinds].forEach(b=>b.onchange=apply);
tags.forEach(t=>t.onchange=apply); q.oninput=apply; apply();
"""

XJS = """
const tabs=[...document.querySelectorAll('nav.tabs a')];
function tab(){
  const id=location.hash==='#exports'?'exports':'code';
  tabs.forEach(a=>a.classList.toggle('on',a.getAttribute('href')==='#'+id));
  document.getElementById('code').hidden=id!=='code';
  document.getElementById('exports').hidden=id!=='exports';
}
window.onhashchange=tab; tab();
(()=>{
const pick=(k)=>[...document.querySelectorAll('input[data-'+k+']')];
const st=pick('xstatus'),mc=pick('xmacro'),ow=pick('xowner'),
      ck=pick('xcheck');
const tg=[...document.querySelectorAll('select[data-xtag]')];
const q=document.getElementById('xq');
const on=(v,k)=>new Set(v.filter(b=>b.checked).map(b=>b.dataset[k]));
function apply(){
  const S=on(st,'xstatus'),M=on(mc,'xmacro'),O=on(ow,'xowner'),
        C=on(ck,'xcheck');
  const want=tg.filter(t=>t.value).map(t=>[t.dataset.xtag,t.value==='1']);
  const s=q.value.toLowerCase();
  let shown=0;
  document.querySelectorAll('details.xsub').forEach(d=>{
    const head=d.querySelector('summary').textContent.toLowerCase();
    let n=0;
    d.querySelectorAll('tr[data-xstatus]').forEach(tr=>{
      const t=tr.dataset.xtags.split(' ');
      const ok=S.has(tr.dataset.xstatus)&&M.has(tr.dataset.xmacro)&&
        O.has(tr.dataset.xowner)&&C.has(tr.dataset.xcheck)&&
        want.every(([k,w])=>t.includes(k)===w)&&
        (!s||head.includes(s)||tr.textContent.toLowerCase().includes(s));
      tr.hidden=!ok; n+=ok;
    });
    d.hidden=!n; if(s&&n) d.open=true; shown+=n;
    d.querySelector('.cnt').textContent=n+' shown';
  });
  document.getElementById('xshown').textContent=
    'Showing '+shown+' of '+XTOTAL+'.';
}
[...st,...mc,...ow,...ck].forEach(b=>b.onchange=apply);
tg.forEach(t=>t.onchange=apply); q.oninput=apply; apply();
})();
"""
