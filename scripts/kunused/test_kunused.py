# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Shivank Garg <shivankg@amd.com>
"""Fixture tests: a tiny git tree with known used and unused symbols."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import report                                                # noqa: E402
import verify                                                # noqa: E402
from candidates import Candidate, read_tsv                    # noqa: E402
from maintainers import Maintainers                           # noqa: E402

KUNUSED = os.path.join(HERE, "kunused.py")

FILES = {
    # ---------------- static inline cases ----------------
    "include/linux/t.h": r'''
static inline int unused_inline(int x) { return x; }
static inline int used_inline(int x) { return x; }

#ifdef CONFIG_FOO
static inline int config_pair(void) { return 1; }
#else
static inline int config_pair(void) { return 0; }
#endif

#ifdef CONFIG_BAR
static inline int macro_variant(int x) { return x; }
#else
#define macro_variant(x) 0
#endif

static inline __printf(1, 2) void attr_parens(const char *f, ...) {}
static inline int __attribute__((const)) attr_gnu(int x) { return x; }

static inline int str_comment_user(void) { return 0; }
static inline int str_url_user(void) { return 0; }
static inline int charlit_user(void) { return 0; }

static inline int samples_user(void) { return 0; }
static inline int tools_testing_user(void) { return 0; }

static inline int chain_leaf(void) { return 0; }
static inline int chain_top(void)
{
	return chain_leaf();
}

static inline int paste_leaf(void) { return 0; }
static inline int paste_target(void) { return paste_leaf(); }

static inline int doc_only(void) { return 0; }
static inline int gen_only_inline(void) { return 0; }

#define BODY_MACRO(n) \
static inline int n##_gen(void) { return 0; }
''',
    "include/uapi/linux/u.h": r'''
static inline int uapi_helper(void) { return 0; }
''',
    "arch/x86/include/asm/ovr.h": r'''
#define arch_override arch_override
static inline int arch_override(void) { return 1; }
''',
    "include/asm-generic/ovr.h": r'''
#ifndef arch_override
static inline int arch_override(void) { return 0; }
#endif
''',
    "kernel/user.c": r'''
#include <linux/t.h>
#define GEN(n) paste_##n()
int k(char c)
{
	const char *s = "/*";
	str_comment_user();
	foo("http://example.com"); str_url_user();
	return c == '"' ? charlit_user() : bar("x");
}
/* doc_only() is mentioned in a comment */
int k2(void)
{
	return used_inline(1) + GEN(target);
}
''',
    "samples/s.c": r'''
int s(void) { return samples_user() + ext_samples_user(); }
int sample_entry(void)
{
	return 0;
}
''',
    "tools/testing/vma/t.c": r'''
int t(void) { return tools_testing_user() + ext_tools_user(); }
int tools_entry(void)
{
	return 0;
}
''',
    "drivers/gpu/wa_oob.rules": r'''
1402	GRAPHICS_VERSION(2001), FUNC(ext_rules_user)
''',
    "scripts/gen_inline.py": r'''
print("x = gen_only_inline();  # emitted into a generated header")
''',
    "Documentation/x.c": r'''
int d(void) { return unused_inline(0) + ext_unused(); }
''',

    # ---------------- extern function / variable cases ----------------
    "include/linux/e.h": r'''
extern int ext_unused(void);
int ext_exported(void);
#ifdef CONFIG_E
int ext_stub(struct page *p);
#else
static inline int ext_stub(struct page *p) { return 0; }
#endif
int ext_else_user(void);
int ext_asm_user(void);
int ext_samples_user(void);
int ext_tools_user(void);
int ext_used(void);
extern int ext_var_unused;
extern unsigned long ext_var_used;
extern int ext_var_array[];
int ext_ternary_user(void);
int ext_plus_user(void);
int ext_case_user(void);
int ext_wrapped(void);
static inline int ext_wrap(void) { return ext_wrapped(); }
int ext_after_comment(void);
#define put_int(v) \
	ext_used(v, \
		 ALIGN(v))
int ext_after_macro(void);
''',
    "mm/e.c": r'''
#include <linux/e.h>
int ext_var_unused;
unsigned long ext_var_used __read_mostly = 1;
int ext_var_array[4] = { 1, 2 };

/**
 * ext_unused - nobody calls me
 */
int ext_unused(void)
{
	return 0;
}

int ext_exported(void)
{
	return 0;
}
EXPORT_SYMBOL_GPL(ext_exported);

int ext_stub(struct page *p)
{
	return 0;
}

int ext_else_user(void)
{
	return 0;
}

int ext_asm_user(void)
{
	return 0;
}

int ext_samples_user(void)
{
	return 0;
}

int ext_tools_user(void)
{
	return 0;
}

int ext_used(void)
{
	return ext_var_used;
}

void __asan_report_load1(unsigned long addr)
{
}

#define SHOW(name) \
static int name##_show(void) { return 0; }
SHOW(attr)

static int attr_store(void)
{
	return 0;
}

static __printf(1, 2)
void static_attr_line(const char *f, ...)
{
}

#ifdef CONFIG_X
#endif
int ext_after_ifdef(void)
{
	return 0;
}

int ext_paste_user(void)
{
	return 0;
}

int ext_ternary_user(void)
{
	return 0;
}

int ext_plus_user(void)
{
	return 0;
}

int ext_case_user(void)
{
	return 0;
}

int ext_wrapped(void)
{
	return 0;
}

int ext_after_macro(void)
{
	return 0;
}

int ext_rules_user(void)
{
	return 0;
}

// a C++-style comment right above a definition
int ext_after_comment(void)
{
	return 0;
}
''',
    "mm/paste.c": r'''
#define CALL(x) ext_paste_##x()
void p(void) { CALL(user); }
#define OPS(_name) [0] = & _name ## _prog_ops,
const void *tbl[] = { OPS(myname) };
#define CLS(_name) class_##_name##_constructor
void q(void) { CLS(mylock)(); }
#define LE(bits) put_le##bits
void r(void) { LE(8)(0); }
#define SZ(fn, a) (sizeof(a) == 4 ? fn##32(a) : fn##64(a))
void s(int a) { SZ(ffz, a); }
''',
    "include/linux/p.h": r'''
static inline void class_mylock_constructor(void) {}
static inline void put_le8(int x) {}
static inline int ffz32(int x) { return x; }
''',
    # Settling [paste?]: which '##' uses really build a name.
    "include/linux/pc.h": r'''
static inline void zpdesc_lock(void) {}
static inline void qqdesc_lock(void) {}
static inline void zz_pfx_none(void) {}
static inline void amb_mid_b_mid_c(void) {}
static inline void fwd_wrapped_fn(void) {}
static inline void nofwd_wrapped_fn(void) {}
static inline void fwdm_wrapped2_fn(void) {}
static inline void xm1_xgen_fn(void) {}
static inline void mlarg_multi_fn(void) {}
static inline void cmt_wrapped3_fn(void) {}
static inline void c0_status_w4_fn(void) {}
static inline void zz_status_w4_fn(void) {}
static inline void foo5_w5_fn(void) {}
static inline void bar5_w5_fn(void) {}
static inline void baz5_w5_fn(void) {}
static inline void qux5_w5_fn(void) {}
static inline void aa2_xg2_fn(void) {}
static inline void cc2_xg2_fn(void) {}
static inline void bb2_xg3_fn(void) {}
static inline void dd_xg3_fn(void) {}
static inline void pp_a_xg4_fn(void) {}
static inline void pp_xg4_fn(void) {}
static inline void qq_xg4_fn(void) {}
static inline void al_xg5_fn(void) {}
static inline void am_xg5_fn(void) {}
static inline void ee_xg6_fn(void) {}
static inline void hh_xg7_fn(void) {}
static inline void ii_xg8_fn(void) {}
static inline int _gt16(void *p) { return 0; }
static inline void aa9_mt_fn(void) {}
static inline void vv_vs_fn(void) {}
static inline void jj_xg9_fn(void) {}
static inline void kk_xg10_fn(void) {}
static inline void ll_t3_fn(void) {}
static inline void foo6_w6_fn(void) {}
static inline void foo7_w6_fn(void) {}
static inline void nn_t8_fn(void) {}
static inline void ww_sh11_fn(void) {}
static inline void yy_sh12_fn(void) {}
static inline void ww_sh13_fn(void) {}
static inline void rr_xg11_fn(void) {}
static inline void ss_xg12_fn(void) {}
#define XGEN12(n) n##_xg12_fn
''',
    # Rust code cannot use a C macro, whatever it looks like.
    "rust/kernel/x.rs": r'''
fn f() { XGEN12(ss); }
''',
    # '#define's in a .c file are private to it unless it is included.
    "mm/pc2.c": r'''
#define MA6 foo6
''',
    "mm/pc3.c": r'''
#define MA7 foo7
''',
    "mm/pc4.c": r'''
#include "pc3.c"
''',
    "mm/pc5.c": r'''
#define T8(x) x##_t8_fn
''',
    "mm/pc.c": r'''
#define LOCKFN(t) t##desc_lock
#define PFX(s) zz_pfx_##s
void z1(int zp, int none) { LOCKFN(abc)(); LOCKFN(qq)(); PFX(other)(); }
#define TWO(a, b) a##_mid_##b
void z2(void) { TWO(amb_mid_b, c)(); }
#define INNER(x) x##_wrapped_fn
#define OUTER(y) INNER(y)
void z3(int nofwd) { OUTER(fwd)(); }
#define INNER2(x) x##_wrapped2_fn
#define OUTER2(y) INNER2(y)
#define NAMEM fwdm
void z4(void) { OUTER2(NAMEM)(); }
#define XGEN(n) n##_xgen_fn
#define LIST(X) X(xm1) X(xm2)
void z5(void) { LIST(XGEN); }
#define MULTI(a) a##_multi_fn
void z6(void)
{
	MULTI(
	      mlarg)();
}
#define INNER3(x) x##_wrapped3_fn
#define OUTER3(y) /* a comment
	over two lines */ INNER3(y)
void z7(void) { OUTER3(cmt)(); }
#define INNER4(x) x##_w4_fn
#define OUTER4(n) INNER4(c0_##n)
void z8(void) { OUTER4(status)(); }
#define INNER5(x) x##_w5_fn
#define OUTER5(y) INNER5(y)
#define MA5 foo5
#define fl5(a) a
#define MB5 MC5
#define MC5 qux5
void z9(void) { OUTER5(MA5)(); OUTER5(fl5)(); OUTER5(MB5)(); }
#define XGEN2(n) n##_xg2_fn
#define LIST2(X) X(aa2) X(bb2)
void z10(void) { LIST2(XGEN2); }
#define XGEN3(n) n##_xg3_fn
#define LIST3(X) LIST2(X)
void z11(void) { LIST3(XGEN3); }
#define XGEN4(n) n##_xg4_fn
#define LIST4(X, p) X(p##_a) X(p)
void z12(void) { LIST4(XGEN4, pp); }
#define XGEN5(n) n##_xg5_fn
#define ALIAS5 XGEN5
void z13(void) { ALIAS5(al)(); }
#define XGEN6(n) n##_xg6_fn
struct s6 { int XGEN6; };
#define XGEN7(n) n##_xg7_fn
#define HANDON(X) X
void z14(void) { HANDON(XGEN7)(hh)(); }
#define XGEN8(n) n##_xg8_fn
#define CALLM(f) f
void z15(void) { CALLM(&XGEN8)(ii); }
#define FLD_LOC(s, o) s, o, 16
#define GETN(s, o, n, p) _gt##n(p)
#define GETF(f, p) GETN(f, p)
#define MYFLD FLD_LOC(x, 4)
void z16(void *q) { GETF(MYFLD, q); }
#define MK(x) x##_mt_fn
void z17(void) { MK(static aa9)(); }
#define VINNER(a, ...) a##_vs_fn
#define VOUTER(f) VINNER(f, 1)
#define VPAIR vv, ww
void z18(void) { VOUTER(VPAIR)(); }
#define XGEN9(n) n##_xg9_fn
XGEN9 jj;
#define XGEN10(n) n##_xg10_fn
#define LP (
void z19(void) { XGEN10 LP kk)(); }
#define T3(a) a##_t3_fn
#define W3(x) T3(x, 1)
void z20(void) { W3(ll); }
#define INNER6(x) x##_w6_fn
#define OUTER6(y) INNER6(y)
void z21(void) { OUTER6(MA6)(); OUTER6(MA7)(); }
#define T8(x) x
void z22(void) { T8(nn)(); }
#define SH11(a, b, c) b##_sh11_fn
#define WSH11(f) SH11(f, foo11)
#define PAIR11 xx, ww
void z23(void) { WSH11(PAIR11)(); }
#define SH12(a, b, ...) b##_sh12_fn
#define WSH12(f) SH12(f, foo12, 1)
#define PAIR12 xx, yy
void z24(void) { WSH12(PAIR12)(); }
#define SH13(a, b, c) b##_sh13_fn
#define WSH13(f) SH13(f, foo13, 1)
void z25(void) { WSH13(PAIR11)(); }
#define XGEN11(n) n##_xg11_fn
#define HOLD11(a, b) a(b)
''' + "void z26(void) { HOLD11(" + " " * 6000 + "XGEN11, rr); }\n",
    "mm/m.c": r'''
#define ATTR_MACRO
int real_var ATTR_MACRO;
int used_var ATTR_MACRO;
void m(void) { used_var = 1; }
''',
    "mm/ops.c": r'''
const int myname_prog_ops = 1;
''',
    "mm/caller.c": r'''
void c(int x)
{
	if (x)
		ext_used();
	else ext_else_user();
	asm volatile("call ext_asm_user");
}

int c2(int rc, int A, int B)
{
	rc = rc < 0 ?
	     rc : ext_ternary_user();
	rc += A +
		B + ext_plus_user();
	switch (rc) {
	default: return ext_case_user() + ext_wrap();
	}
}
''',
    "scripts/config": r'''
#!/bin/sh
exit 0
''',
    "MAINTAINERS": r'''
Descriptions of section entries and preferred order
	F: *Files* and directories wildcard patterns.

MEMORY MANAGEMENT
L:	linux-mm@kvack.org
F:	mm/
F:	include/linux/e.h
X:	mm/ops.c

MM PASTE
L:	paste@example.org
F:	mm/p*.c

THE REST
L:	linux-kernel@vger.kernel.org
F:	*
''',
}

# True: reported; False: not reported; "tag": reported with that tag.
EXPECT_INLINE = {
    "unused_inline": True, "used_inline": False, "config_pair": True,
    "macro_variant": True, "attr_parens": True, "attr_gnu": True,
    "str_comment_user": False, "str_url_user": False, "charlit_user": False,
    "samples_user": False, "tools_testing_user": False,
    "chain_leaf": "via-unused", "chain_top": True,
    "paste_target": "paste-used", "paste_leaf": "via-unused",
    "doc_only": True, "gen_only_inline": "non-c?", "arch_override": True,
    "uapi_helper": "uapi",
    "__printf": False, "__attribute__": False, "n": False,
    "class_mylock_constructor": "paste-used", "put_le8": "paste-used",
    "ffz32": "paste-used",
}

# Exact tags after settling [paste?].
EXPECT_PASTE = {
    "zpdesc_lock": [],                  # LOCKFN(t) needs t=zp; only abc, qq
    "zz_pfx_none": [],                  # PFX(s) needs s=none; only other
    "qqdesc_lock": ["paste-used"],
    "amb_mid_b_mid_c": ["paste-used"],  # the second way to split it
    "fwd_wrapped_fn": ["paste-used"],   # through OUTER(y) INNER(y)
    "nofwd_wrapped_fn": [],
    "fwdm_wrapped2_fn": ["paste?"],     # OUTER2(NAMEM): NAMEM is a macro
    "xm1_xgen_fn": ["paste-used"],      # LIST(XGEN) calls XGEN(xm1)
    "mlarg_multi_fn": ["paste-used"],   # call split over two lines
    "cmt_wrapped3_fn": ["paste-used"],  # comment over two lines in OUTER3
    "c0_status_w4_fn": ["paste-used"],  # OUTER4(status) passes c0_##n
    "zz_status_w4_fn": [],              # c0_##n never gives zz_status
    "foo5_w5_fn": ["paste?"],           # OUTER5(MA5): MA5 is foo5
    "bar5_w5_fn": [],                   # no macro argument gives bar5
    "baz5_w5_fn": [],                   # fl5 is function-like, not expanded
    "qux5_w5_fn": ["paste?"],           # OUTER5(MB5): MB5 is MC5 is qux5
    "aa2_xg2_fn": ["paste-used"],       # LIST2(XGEN2) calls XGEN2(aa2)
    "cc2_xg2_fn": [],                   # LIST2 calls it with aa2, bb2
    "bb2_xg3_fn": ["paste-used"],       # LIST3(X) LIST2(X)
    "dd_xg3_fn": [],
    "pp_a_xg4_fn": ["paste-used"],      # LIST4(XGEN4, pp): X(p##_a)
    "pp_xg4_fn": ["paste-used"],        # X(p)
    "qq_xg4_fn": [],
    "al_xg5_fn": ["paste-used"],        # ALIAS5 is XGEN5
    "am_xg5_fn": [],
    "ee_xg6_fn": [],                    # a struct member, never expanded
    "hh_xg7_fn": ["paste?"],            # HANDON(X) X: hands it on
    "ii_xg8_fn": ["paste?"],           # CALLM(&XGEN8)(ii): part of an argument
    "_gt16": ["paste?"],                # GETF(MYFLD, q): MYFLD holds commas
    "aa9_mt_fn": ["paste?"],            # MK(static aa9): last token pasted
    "vv_vs_fn": ["paste?"],             # VPAIR shifts VINNER's args
    "jj_xg9_fn": [],                    # 'XGEN9 jj': no '(' can follow
    "kk_xg10_fn": ["paste?"],           # 'XGEN10 LP kk)': LP is '('
    "ll_t3_fn": [],                     # W3 calls T3 with too many args
    "foo6_w6_fn": [],                   # MA6 is defined in mm/pc2.c only
    "foo7_w6_fn": ["paste?"],           # mm/pc3.c is included by pc4.c
    "nn_t8_fn": [],                     # T8 in pc.c is not pc5.c's T8
    "ww_sh11_fn": ["paste?"],           # PAIR11's comma shifts SH11's args
    "yy_sh12_fn": ["paste?"],           # and a variadic macro's
    "ww_sh13_fn": [],                   # SH13 already has all its args
    "rr_xg11_fn": ["paste?"],           # the '(' is too far back to find
    "ss_xg12_fn": [],                   # only Rust "calls" XGEN12
}

EXPECT_EXTERN = {
    "ext_unused": True, "ext_exported": "exported", "ext_stub": True,
    "ext_else_user": False, "ext_asm_user": False,
    "ext_samples_user": False, "ext_tools_user": False, "ext_used": False,
    "ext_var_unused": True, "ext_var_used": False, "ext_var_array": True,
    "__asan_report_load1": False, "attr_store": False,
    "static_attr_line": False, "ext_after_ifdef": True,
    "ext_paste_user": "paste-used", "myname_prog_ops": "paste-used",
    "real_var": True, "used_var": False, "ATTR_MACRO": False,
    "ext_ternary_user": False, "ext_plus_user": False,
    "ext_case_user": False, "ext_wrapped": False, "ext_after_comment": True,
    "ext_after_macro": True, "ext_rules_user": "non-c?",
}


def slurp(path):
    with open(path) as f:
        return f.read()


def git(d, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                    *args], cwd=d, check=True, capture_output=True)


def make_tree(d):
    for path, body in FILES.items():
        p = os.path.join(d, path)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(body.lstrip("\n"))
        if body.startswith("\n#!"):
            os.chmod(p, 0o755)
    git(d, "init", "-q")
    git(d, "add", ".")
    git(d, "commit", "-qm", "fixture")


def kunused(d, *args, env=None):
    r = subprocess.run([sys.executable, KUNUSED, "-C", d, *args],
                       capture_output=True, text=True, env=env)
    if r.returncode:
        raise AssertionError(f"kunused {' '.join(args)} failed:\n{r.stderr}")
    return r.stdout


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tree = cls.tmp.name
        make_tree(cls.tree)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def scan(self, *args):
        out = os.path.join(self.tree, ".out.tsv")
        kunused(self.tree, "scan", "-o", out, *args)
        return {c.name: c for c in read_tsv(out)}

    def expect(self, got, expect):
        for name, want in expect.items():
            with self.subTest(name=name):
                self.assertEqual(name in got, bool(want),
                                 f"{name}: {got.get(name)}")
                if isinstance(want, str):
                    self.assertIn(want, got[name].tags)


class TestScan(Fixture):
    def test_inlines(self):
        self.expect(self.scan("--only", "inlines"), EXPECT_INLINE)

    def test_externs(self):
        got = self.scan("--only", "externs", "--extern-dir", "mm")
        self.expect(got, EXPECT_EXTERN)
        self.assertEqual(got["ext_unused"].sites, [("mm/e.c", 9)])
        self.assertEqual(got["ext_after_ifdef"].sites, [("mm/e.c", 70)])
        self.assertEqual(got["ext_var_unused"].kind, "variable")
        self.assertEqual(got["ext_unused"].kind, "function")

    def test_default_skips_userspace(self):
        got = self.scan("--only", "externs")
        self.assertIn("k", got)                 # kernel/ is scanned
        self.assertNotIn("sample_entry", got)
        self.assertNotIn("tools_entry", got)

    def test_arch_override_sites(self):
        got = self.scan("--only", "inlines")
        self.assertEqual([p for p, _ in got["arch_override"].sites],
                         ["arch/x86/include/asm/ovr.h",
                          "include/asm-generic/ovr.h"])

    def test_listing_hides_paste_and_uapi(self):
        out = kunused(self.tree, "scan", "--only", "inlines")
        self.assertIn("unused_inline", out)
        self.assertNotIn("put_le8", out)
        self.assertNotIn("uapi_helper", out)
        self.assertIn("hidden, use --all", out)
        out = kunused(self.tree, "scan", "--only", "inlines", "--all")
        self.assertIn("put_le8", out)

    def test_path_filter(self):
        got = self.scan("--extern-dir", "mm", "^mm/")
        self.assertTrue(got)
        self.assertTrue(all(c.path.startswith("mm/") for c in got.values()))

    def test_paste_settled(self):
        got = self.scan("--only", "inlines")
        for name, tags in EXPECT_PASTE.items():
            with self.subTest(name=name):
                self.assertIn(name, got)
                self.assertEqual(got[name].tags, tags)

    def test_paste_explain(self):
        out = kunused(self.tree, "paste", "zpdesc_lock", "qqdesc_lock",
                      "xm1_xgen_fn", "hh_xg7_fn")
        self.assertIn("zpdesc_lock: unused", out)
        self.assertIn("LOCKFN(t) in mm/pc.c: needs t=zp; 2 uses -> unused",
                      out)
        self.assertIn("qqdesc_lock: used (LOCKFN() at mm/pc.c:3)", out)
        self.assertIn("xm1_xgen_fn: used (XGEN() at mm/pc.c:15 via LIST() "
                      "at mm/pc.c:14)", out)
        self.assertIn("hh_xg7_fn: open (HANDON() hands it on at mm/pc.c:",
                      out)
        self.assertNotIn("pending", out)


class TestSplits(unittest.TestCase):
    def test_every_split(self):
        from source import splits
        two = ((True, "a"), (False, "_mid_"), (True, "b"))
        self.assertEqual(splits(two, "x_mid_y_mid_z"),
                         [{"a": "x", "b": "y_mid_z"},
                          {"a": "x_mid_y", "b": "z"}])
        self.assertEqual(splits(((True, "t"), (False, "desc_lock")),
                                "zpdesc_lock"), [{"t": "zp"}])
        self.assertEqual(splits(((False, "zz_"), (True, "s")), "zz_"), [])
        same = ((True, "x"), (False, "_"), (True, "x"))
        self.assertEqual(splits(same, "ab_ab"), [{"x": "ab"}])
        self.assertEqual(splits(same, "ab_cd"), [])

    def test_merge(self):
        x86 = {"build": "Linux/x86 7.0.0", "config": "allmodconfig",
               "commit": "abc", "compiled": 2, "built": ["a", "b"],
               "confirmed": ["a"], "real_use": {"b": ["x.c:1", "b();"]},
               "not_built": ["c", "d"],
               "warnings": {"chain": 1, "export": 0, "real_use": 1}}
        rv = {"build": "Linux/riscv 7.0.0", "config": "nommu_virt_defconfig",
              "commit": "abc", "compiled": 2, "built": ["a", "c"],
              "confirmed": ["a", "c"], "real_use": {},
              "not_built": ["b", "d"],
              "warnings": {"chain": 0, "export": 2, "real_use": 0}}
        m = verify.merge([x86, rv])
        self.assertEqual(m["confirmed"], ["a", "c"])
        self.assertEqual(m["not_built"], ["d"])
        self.assertEqual(list(m["real_use"]), ["b"])
        self.assertEqual(m["compiled"], 3)
        self.assertEqual(m["builds"], 2)
        self.assertIn("nommu_virt_defconfig", m["build"])
        self.assertEqual(m["warnings"]["export"], 2)
        with self.assertRaises(SystemExit):
            verify.merge([x86, dict(rv, commit="def")])


class TestVerify(Fixture):
    def test_mark_and_check(self):
        wt = os.path.join(self.tree, ".wt")
        git(self.tree, "worktree", "add", "-q", "--detach", wt, "HEAD")
        tsv = os.path.join(self.tree, ".cands.tsv")
        kunused(self.tree, "scan", "-o", tsv, "--extern-dir", "mm")
        out = kunused(self.tree, "mark", wt, tsv)
        self.assertIn("marked", out)

        def line(path, n):
            with open(os.path.join(wt, path)) as f:
                return f.read().split("\n")[n - 1]
        self.assertTrue(line("include/linux/t.h", 1).startswith(verify.MARK))
        self.assertFalse(line("include/linux/t.h", 2).startswith(verify.MARK))
        self.assertTrue(line("mm/e.c", 9).startswith(verify.MARK))
        n = slurp(os.path.join(wt, "mm/e.c")).split("\n").index(
            verify.mark_attr("ext_after_comment") +
            "int ext_after_comment(void)")
        self.assertTrue(line("mm/e.c", n).startswith("// a C++"))
        with open(os.path.join(wt, "include/linux/e.h")) as f:
            eh = f.read()
        self.assertIn("\t\t ALIGN(v))\n" +
                      verify.mark_attr("ext_after_macro") +
                      "int ext_after_macro", eh)
        self.assertTrue(line("include/linux/e.h", 1).startswith(verify.MARK))
        self.assertTrue(line("include/linux/e.h", 6).startswith(
            verify.mark_attr("ext_stub") + "static inline"))
        self.assertFalse(line("include/uapi/linux/u.h", 1)
                         .startswith(verify.MARK))

        # Marking again must not lose the first run's entries.
        before = json.loads(slurp(os.path.join(wt, verify.MARKS_FILE)))
        kunused(self.tree, "mark", wt, tsv)
        after = json.loads(slurp(os.path.join(wt, verify.MARKS_FILE)))
        self.assertEqual(len(before), len(after))

        build = os.path.join(self.tree, ".build")
        os.makedirs(os.path.join(build, "mm"))
        with open(os.path.join(build, ".config"), "w") as f:
            f.write("#\n# Linux/x86 7.0.0 Kernel Configuration\n#\n")
        with open(os.path.join(build, "mm", ".e.o.cmd"), "w") as f:
            f.write(f"deps_mm/e.o := \\\n  {wt}/mm/e.c \\\n"
                    f"  {wt}/include/linux/e.h \\\n"
                    f"  {wt}/include/linux/t.h \\\n")
        log = os.path.join(build, "build.log")
        w = ("{}:{}:5: warning: '{}' is deprecated: KUNUSED {}"
             "[-Wdeprecated-declarations]\n")
        with open(log, "w") as f:
            f.write(w.format(f"{wt}/include/linux/t.h", 29, "chain_leaf",
                             "chain_leaf "))
            f.write(w.format(f"{wt}/mm/e.c", 18, "ext_exported",
                             "ext_exported "))
            f.write(w.format("../.wt/mm/caller.c", 4, "ext_stub", ""))
            f.write(w.format(f"{wt}/mm/caller.c", 4, "ext_stub", ""))
            # a macro renamed the symbol; the message names the candidate
            f.write(w.format(f"{wt}/mm/caller.c", 5, "renamed_sym",
                             "ext_after_comment "))
        res_path = os.path.join(self.tree, ".verify.json")
        kunused(self.tree, "check", wt, build, log, "-o", res_path)
        res = json.loads(slurp(res_path))

        self.assertEqual(res["build"], "Linux/x86 7.0.0")
        self.assertEqual(res["warnings"],
                         {"chain": 1, "export": 1, "real_use": 2})
        self.assertEqual(list(res["real_use"]),
                         ["ext_after_comment", "ext_stub"])
        self.assertEqual(res["real_use"]["ext_stub"][0], "mm/caller.c:4")
        self.assertNotIn("ext_after_comment", res["confirmed"])
        self.assertIn("ext_unused", res["confirmed"])
        self.assertIn("unused_inline", res["confirmed"])
        self.assertNotIn("ext_stub", res["confirmed"])
        self.assertIn("arch_override", res["not_built"])


    def test_mark_refuses_other_commit(self):
        tsv = os.path.join(self.tree, ".old.tsv")
        kunused(self.tree, "scan", "-o", tsv, "--only", "inlines")
        text = slurp(tsv)
        self.assertIn("# commit ", text)
        with open(tsv, "w") as f:
            f.write(re.sub(r"# commit \w+", "# commit 0123abc", text))
        wt = os.path.join(self.tree, ".wt2")
        git(self.tree, "worktree", "add", "-q", "--detach", wt, "HEAD")
        r = subprocess.run([sys.executable, KUNUSED, "mark", wt, tsv],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("line numbers would not match", r.stderr)


class TestReport(Fixture):
    def test_maintainers(self):
        m = Maintainers(os.path.join(self.tree, "MAINTAINERS"))
        self.assertEqual(m.lookup("mm/e.c"),
                         ("MEMORY MANAGEMENT", "linux-mm@kvack.org"))
        self.assertEqual(m.lookup("include/linux/e.h")[0],
                         "MEMORY MANAGEMENT")
        self.assertEqual(m.lookup("mm/paste.c")[0], "MM PASTE")
        self.assertEqual(m.lookup("mm/ops.c")[0], "THE REST")
        self.assertEqual(m.lookup("kernel/user.c")[0], "THE REST")

    def test_tiers(self):
        c = lambda name, tags=(), path="mm/e.c": Candidate(
            name, "function", [(path, 1)], list(tags))
        ver = {"confirmed": {"a"}, "real_use": {"b": ["x.c:1", "b();"]}}
        self.assertEqual(report.tier_of(c("a"), ver), "confirmed")
        self.assertEqual(report.tier_of(c("b"), ver), "rejected")
        self.assertEqual(report.tier_of(c("z"), ver), "likely")
        self.assertEqual(report.tier_of(c("z", ["paste?"]), ver), "check")
        # the build compiled it, but a '##' use may live in code it skipped
        self.assertEqual(report.tier_of(c("a", ["paste?"]), ver), "check")
        self.assertEqual(report.tier_of(c("a", ["paste-used"]), ver),
                         "rejected")
        self.assertEqual(report.tier_of(c("z", ["paste-used"]), None),
                         "rejected")
        self.assertEqual(report.tier_of(c("a", ["uapi"]), ver), "uapi")
        self.assertEqual(report.tier_of(c("a", path="lib/zstd/x.c"), ver),
                         "generated")
        self.assertEqual(report.tier_of(c("a", ["non-c?"]), ver), "check")

    def test_callers(self):
        def c(name, callers=None, tags=()):
            return Candidate(name, "inline", [("mm/e.c", 1)],
                             list(tags) + ["via-unused"] * (callers is not None),
                             callers or [])
        ver = {"confirmed": {"a", "b", "c", "d", "e", "f", "g", "sure"},
               "real_use": {"top": ["x.c:1", "top();"]}}
        cands = [c("top"), c("a", ["top"]), c("b", ["a"]), c("c", ["ok"]),
                 c("ok"), c("d", ["ok", "u"]), c("u", tags=["uapi"]),
                 c("e", []), c("f", ["gone"]), c("sure"), c("g", ["sure"])]
        got = dict(zip((x.name for x in cands), report.tiers(cands, ver)))
        self.assertEqual(got["g"], ("confirmed", None))
        self.assertEqual(got["a"], ("rejected", "top"))
        self.assertEqual(got["b"], ("rejected", "a"))
        self.assertEqual(got["c"], ("likely", "ok"))
        self.assertEqual(got["d"], ("check", "u"))
        self.assertEqual(got["e"], ("check", ""))
        self.assertEqual(got["f"], ("check", "gone"))
        self.assertEqual(got["u"], ("uapi", None))

    def test_html(self):
        tsv = os.path.join(self.tree, ".r.tsv")
        html_out = os.path.join(self.tree, ".r.html")
        kunused(self.tree, "scan", "-o", tsv, "--extern-dir", "mm")
        out = kunused(self.tree, "report", tsv, "-o", html_out,
                      "--filter", "linux-mm@")
        self.assertIn("MEMORY MANAGEMENT", out)
        page = slurp(html_out)
        self.assertIn("ext_unused", page)
        self.assertNotIn("unused_inline", page)     # filtered out
        self.assertEqual(page.count("<details"), page.count("</details>"))
        self.assertIn('data-kind="function"', page)
        self.assertIn('<select data-tag="exported">', page)
        self.assertIn("not cross-checked with a build", page)


# Stands in for the kernel's make: configures, then "compiles" mm/e.c and
# reports one real use of ext_stub.
FAKE_MAKE = r'''#!/usr/bin/env python3
import os, sys
build = next(a[2:] for a in sys.argv if a.startswith("O="))
os.makedirs(os.path.join(build, "mm"), exist_ok=True)
if sys.argv[-1].endswith("config"):
    with open(os.path.join(build, ".config"), "w") as f:
        f.write("#\n# Linux/x86 7.0.0 Kernel Configuration\n#\n")
    sys.exit(0)
src = os.getcwd()
with open(os.path.join(build, "mm", ".e.o.cmd"), "w") as f:
    f.write(f"deps_mm/e.o := \\\n  {src}/mm/e.c \\\n"
            f"  {src}/include/linux/e.h \\\n  {src}/include/linux/t.h\n")
print("  CC      mm/e.o")
print(f"{src}/mm/caller.c:4:5: warning: 'ext_stub' is deprecated: "
      "KUNUSED ext_stub [-Wdeprecated-declarations]")
'''


class TestRun(Fixture):
    def results(self, out):
        rows = [l.split("\t") for l in slurp(os.path.join(out, "results.tsv"))
                .splitlines() if not l.startswith("#")]
        return {r[1]: r[0] for r in rows}

    def test_run_no_build(self):
        out = os.path.join(self.tree, ".run-nb")
        kunused(self.tree, "run", "--no-build", "-o", out)
        got = self.results(out)
        self.assertEqual(got["ext_unused"], "unverified")
        self.assertEqual(got["paste_target"], "rejected")
        self.assertEqual(got["paste_leaf"], "rejected")
        self.assertEqual(got["hh_xg7_fn"], "check")
        self.assertEqual(got["zpdesc_lock"], "unverified")
        self.assertFalse(os.path.exists(os.path.join(out, "verify.json")))

    def test_run_with_build(self):
        out = os.path.join(self.tree, ".run")
        bindir = os.path.join(self.tree, ".bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "make"), "w") as f:
            f.write(FAKE_MAKE)
        os.chmod(os.path.join(bindir, "make"), 0o755)
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"])
        text = kunused(self.tree, "run", "-o", out, env=env)
        got = self.results(out)
        self.assertEqual(got["ext_unused"], "verified")
        self.assertEqual(got["unused_inline"], "verified")
        self.assertEqual(got["chain_leaf"], "verified")
        # compiled and only "used" inside paste_target, which is used
        self.assertEqual(got["paste_leaf"], "rejected")
        self.assertEqual(got["ext_stub"], "rejected")
        self.assertEqual(got["arch_override"], "not built")
        self.assertIn("Sure: build-verified unused", text)
        page = slurp(os.path.join(out, "report.html"))
        self.assertIn("Linux/x86 7.0.0 allmodconfig build", page)
        # the worktree and build directory are cleaned up
        self.assertFalse(os.path.exists(os.path.join(out, "src")))
        self.assertFalse(os.path.exists(os.path.join(out, "build")))
        self.assertNotIn(os.path.join(out, "src"),
                         subprocess.run(["git", "worktree", "list"],
                                        cwd=self.tree, capture_output=True,
                                        text=True).stdout)


if __name__ == "__main__":
    unittest.main()
