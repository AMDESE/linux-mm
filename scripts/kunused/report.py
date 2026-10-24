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


class Report:
    def __init__(self, cands, verify=None, filters=(), maintainers=None):
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
             f"<style>{CSS}</style><h1>Unused kernel code</h1>",
             f'<p class="sub">{len(self.rows)} candidates. '
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
        o.append(f"<script>const TOTAL={len(self.rows)};{JS}</script>")
        return "\n".join(o)


CSS = """
body{font:14px/1.45 system-ui,sans-serif;margin:24px auto;max-width:1200px;
     padding:0 16px;color:#1f2328}
h1{margin:0 0 4px} .sub{color:#57606a;margin:0 0 16px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.card{border:1px solid #d0d7de;border-left:5px solid var(--c);border-radius:6px;
      padding:8px 12px;display:flex;gap:8px;align-items:center;cursor:pointer}
.card b{font-size:20px;color:var(--c)} .card span{color:#57606a}
#q{width:100%;padding:8px;border:1px solid #d0d7de;border-radius:6px;
   font-size:14px;box-sizing:border-box}
.hint{color:#6e7781;font-size:12px;margin:4px 0 14px}
details.sub{border:1px solid #d0d7de;border-radius:6px;margin:6px 0}
details.sub[hidden]{display:none}
summary{padding:8px 12px;cursor:pointer;display:flex;gap:10px;
        align-items:center}
summary .t{font-weight:600} summary .l{color:#6e7781;font-size:12px;flex:1}
summary i{font-style:normal;background:var(--c);color:#fff;border-radius:10px;
          padding:0 8px;font-size:12px}
table{border-collapse:collapse;width:100%;font-size:13px}
th{text-align:left;color:#57606a;font-weight:500;border-top:1px solid #d0d7de}
td,th{padding:4px 12px;vertical-align:top}
tr[data-tier] td:first-child{border-left:4px solid var(--c)}
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
const boxes=[...document.querySelectorAll('.card input')];
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
