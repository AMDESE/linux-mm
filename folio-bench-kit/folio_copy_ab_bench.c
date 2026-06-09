// SPDX-License-Identifier: GPL-2.0
/*
 * folio_copy_ab_bench - A/B benchmark for folio_mc_copy() and folio_copy().
 *
 * Allocates a (src, dst) folio pair of the requested order and times
 * folio_mc_copy() / folio_copy() between them via ktime_get_ns().  The
 * caller picks order, src/dst NUMA node, total bytes to copy
 * (iters = bytes_total / folio_bytes), whether to flush caches between
 * iterations, and a warmup count.
 *
 * Boot each kernel in turn (e.g. one with and one without a candidate
 * mm patch), run the bench, then diff the two logs with
 * parse-folio-copy.py.
 *
 * debugfs interface (/sys/kernel/debug/folio_copy_ab/):
 *
 *     order         folio order (0..MAX_PAGE_ORDER)
 *     src_node      source NUMA node for folio allocation
 *     dst_node      destination NUMA node for folio allocation
 *     bytes_total   total bytes to copy; iters = bytes_total / folio_bytes
 *     flush         1: evict caches before each timed copy, 0: keep hot
 *     warmup        minimum number of untimed copies before timing
 *     max_iters     cap derived iters at this value (0 = unlimited)
 *     copy_fn       0: folio_mc_copy, 1: folio_copy, 2: both
 *     run           read-only; triggers the bench and emits RESULT lines
 *     kernel        read-only; returns UTS_RELEASE + UTS_VERSION of the
 *                   running kernel so the bench driver can tag logs
 *                   with exactly which kernel produced each row
 *     selftest      read-only; runs a quick correctness check across a
 *                   small order set and reports pass/fail
 *
 * RESULT line format (one per selected copy_fn):
 *
 *   RESULT fn=<folio_mc_copy|folio_copy>
 *          order=N src=A dst=B pages=P bytes=B iters=I
 *          bytes_total=T flush=F warmup=W warmup_eff=E
 *          total_ns=... avg_ns=... min_ns=... max_ns=...
 *          throughput_GBps=<amortized over iters, bytes/ns>
 *
 * `warmup_eff` is the effective warmup count actually executed.  For
 * cache-hot scenarios (flush=0) with small bytes_total the module
 * automatically scales warmup up so the L2/L3 working set is fully
 * seeded before timing begins.
 */

#define pr_fmt(fmt) "folio_copy_ab: " fmt

#include <linux/debugfs.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/nodemask.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>

#include <generated/utsrelease.h>

#define DEFAULT_ORDER		9		/* 2MB folio on 4K base pages */
#define DEFAULT_BYTES		(2UL << 20)	/* 2 MiB per run */
#define DEFAULT_WARMUP		1
#define MAX_ITERS_CAP		(16UL << 20)	/* safety cap */
#define FLUSH_BYTES		(128UL << 20)

enum copy_fn_sel {
	COPY_FN_MC   = 0,	/* folio_mc_copy() */
	COPY_FN_PLAIN = 1,	/* folio_copy() */
	COPY_FN_BOTH = 2,
	COPY_FN_MAX  = COPY_FN_BOTH,
};

struct bench_params {
	u32 order;
	u32 src_node;
	u32 dst_node;
	u32 flush;
	u32 warmup;
	u32 copy_fn;
	u64 bytes_total;
	u64 max_iters;
};

static struct bench_params params = {
	.order = DEFAULT_ORDER,
	.src_node = 0,
	.dst_node = 0,
	.flush = 1,
	.warmup = DEFAULT_WARMUP,
	.copy_fn = COPY_FN_BOTH,
	.bytes_total = DEFAULT_BYTES,
	.max_iters = 0,
};

static DEFINE_MUTEX(bench_lock);
static struct dentry *bench_dir;
static void *flush_buf_node[MAX_NUMNODES];

struct bench_result {
	const char *label;
	u64 total_ns;
	u64 min_ns;
	u64 max_ns;
	u64 bytes_per_iter;
	u64 iters;
	u64 warmup_iters;
	int err;
};

static int alloc_folios(int order, int src_node, int dst_node,
			struct folio **src_out, struct folio **dst_out)
{
	gfp_t gfp = GFP_KERNEL | __GFP_THISNODE | __GFP_NOWARN;
	struct folio *src, *dst;

	if (order > 0)
		gfp |= __GFP_COMP;

	src = __folio_alloc_node(gfp, order, src_node);
	if (!src)
		return -ENOMEM;
	dst = __folio_alloc_node(gfp, order, dst_node);
	if (!dst) {
		folio_put(src);
		return -ENOMEM;
	}

	/* Commit the pages. */
	memset(page_address(&src->page), 0xaa,
	       folio_nr_pages(src) << PAGE_SHIFT);
	memset(page_address(&dst->page), 0x55,
	       folio_nr_pages(dst) << PAGE_SHIFT);

	*src_out = src;
	*dst_out = dst;
	return 0;
}

static void free_folios(struct folio *src, struct folio *dst)
{
	if (src)
		folio_put(src);
	if (dst)
		folio_put(dst);
}

static noinline bool flush_node(int nid)
{
	const u8 *p;
	size_t i;
	u8 sink = 0;

	if (nid < 0 || nid >= MAX_NUMNODES)
		return false;
	p = flush_buf_node[nid];
	if (!p)
		return false;

	for (i = 0; i < FLUSH_BYTES; i += SMP_CACHE_BYTES)
		sink ^= READ_ONCE(p[i]);
	WRITE_ONCE(*(volatile u8 *)p, sink);
	return true;
}

static noinline void flush_caches(int src_nid, int dst_nid)
{
	flush_node(src_nid);
	if (dst_nid != src_nid)
		flush_node(dst_nid);
}

/* Thin wrappers so we can invoke them via a function pointer. */
static int do_folio_mc_copy(struct folio *dst, struct folio *src)
{
	return folio_mc_copy(dst, src);
}

static int do_folio_copy(struct folio *dst, struct folio *src)
{
	folio_copy(dst, src);
	return 0;
}

typedef int (*copy_fn_t)(struct folio *dst, struct folio *src);

/*
 * Target working-set the warmup should pre-seed before timing begins.
 * 32 MB covers L2 + L3 on Zen 5, Ice Lake-SP and Sapphire Rapids SKUs
 * we care about; the goal is that the first timed copy sees the same
 * cache state as every subsequent one.
 */
#define BENCH_HOT_WARMUP_BYTES	(32ULL << 20)

static int run_one(const char *label, copy_fn_t copy, u64 iters,
		   struct folio *src, struct folio *dst,
		   struct bench_result *r)
{
	u64 i, min_ns = U64_MAX, max_ns = 0, total_ns = 0;
	u64 warmup_iters;
	int ret;

	r->label = label;
	r->err = 0;
	r->iters = iters;
	r->bytes_per_iter = folio_nr_pages(src) << PAGE_SHIFT;

	/*
	 * Warmup. For cache-hot scenarios (!flush) with small
	 * bytes_total, a single warmup copy is not enough to seed L2/L3
	 * when the working set is bigger than the folio. Scale up so at
	 * least BENCH_HOT_WARMUP_BYTES worth of data passes through the
	 * caches before the first timed iteration. Cache-cold (flush=1)
	 * scenarios flush every iteration and don't need this.
	 */
	warmup_iters = params.warmup;
	if (!params.flush && r->bytes_per_iter &&
	    params.bytes_total < BENCH_HOT_WARMUP_BYTES) {
		u64 need = div64_u64(BENCH_HOT_WARMUP_BYTES + r->bytes_per_iter - 1,
				     r->bytes_per_iter);

		if (need > warmup_iters)
			warmup_iters = need;
	}

	r->warmup_iters = warmup_iters;

	for (i = 0; i < warmup_iters; i++) {
		ret = copy(dst, src);
		if (ret) {
			r->err = ret;
			return ret;
		}
	}

	for (i = 0; i < iters; i++) {
		u64 t0, t1, dt;

		if (params.flush)
			flush_caches(params.src_node, params.dst_node);
		/*
		 * Use __cond_resched() instead of cond_resched(): the
		 * latter goes through a static-call trampoline whose
		 * key symbol (__SCK__cond_resched) is not exported to
		 * modules on CONFIG_HAVE_STATIC_CALL_INLINE kernels.
		 * __cond_resched() is a regular EXPORT_SYMBOL and
		 * does the same thing from a module's point of view.
		 *
		 * On fully-preemptible kernels (CONFIG_PREEMPT=y without
		 * CONFIG_PREEMPT_DYNAMIC) __cond_resched() is not
		 * compiled in at all - the scheduler can preempt this
		 * loop at any time, so there is nothing to call.
		 */
#if defined(CONFIG_PREEMPT_DYNAMIC) || !defined(CONFIG_PREEMPTION)
		__cond_resched();
#endif

		t0 = ktime_get_ns();
		ret = copy(dst, src);
		t1 = ktime_get_ns();
		if (ret) {
			r->err = ret;
			return ret;
		}

		dt = t1 - t0;
		total_ns += dt;
		if (dt < min_ns)
			min_ns = dt;
		if (dt > max_ns)
			max_ns = dt;
	}

	r->total_ns = total_ns;
	r->min_ns = min_ns;
	r->max_ns = max_ns;
	return 0;
}

static void print_result(struct seq_file *s, const struct bench_result *r)
{
	u64 bytes_total, avg_ns, tput_gbps_1000;

	if (r->err) {
		seq_printf(s,
			   "RESULT fn=%s order=%u src=%u dst=%u "
			   "iters=%llu err=%d\n",
			   r->label, params.order, params.src_node,
			   params.dst_node, r->iters, r->err);
		return;
	}

	bytes_total = r->bytes_per_iter * r->iters;
	avg_ns = r->iters ? div64_u64(r->total_ns, r->iters) : 0;
	tput_gbps_1000 = r->total_ns ?
		div64_u64(bytes_total * 1000ULL, r->total_ns) : 0;

	seq_printf(s,
		   "RESULT fn=%s order=%u src=%u dst=%u pages=%lu bytes=%llu iters=%llu bytes_total=%llu flush=%u warmup=%u warmup_eff=%llu total_ns=%llu avg_ns=%llu min_ns=%llu max_ns=%llu throughput_GBps=%llu.%03llu\n",
		   r->label, params.order, params.src_node,
		   params.dst_node,
		   (unsigned long)(r->bytes_per_iter >> PAGE_SHIFT),
		   r->bytes_per_iter, r->iters, params.bytes_total,
		   params.flush, params.warmup, r->warmup_iters,
		   r->total_ns, avg_ns, r->min_ns, r->max_ns,
		   tput_gbps_1000 / 1000ULL,
		   tput_gbps_1000 % 1000ULL);
}

static int validate(void)
{
	if (params.order > MAX_PAGE_ORDER)
		return -EINVAL;
	if (params.bytes_total == 0)
		return -EINVAL;
	if (params.src_node >= MAX_NUMNODES ||
	    !node_online(params.src_node))
		return -EINVAL;
	if (params.dst_node >= MAX_NUMNODES ||
	    !node_online(params.dst_node))
		return -EINVAL;
	if (params.copy_fn > COPY_FN_MAX)
		return -EINVAL;
	if (params.flush > 1)
		return -EINVAL;
	return 0;
}

static u64 derive_iters(void)
{
	u64 folio_bytes = (1ULL << params.order) << PAGE_SHIFT;
	u64 iters = div64_u64(params.bytes_total + folio_bytes - 1,
			      folio_bytes);

	if (iters < 1)
		iters = 1;
	if (iters > MAX_ITERS_CAP)
		iters = MAX_ITERS_CAP;
	if (params.max_iters && iters > params.max_iters)
		iters = params.max_iters;
	return iters;
}

static int bench_run_show(struct seq_file *s, void *unused)
{
	struct folio *src = NULL, *dst = NULL;
	struct bench_result r;
	u64 iters;
	int ret;

	mutex_lock(&bench_lock);

	ret = validate();
	if (ret) {
		seq_printf(s, "ERR invalid params: %d\n", ret);
		goto out;
	}

	iters = derive_iters();

	ret = alloc_folios(params.order, params.src_node, params.dst_node,
			   &src, &dst);
	if (ret) {
		seq_printf(s, "ERR alloc_folios: %d\n", ret);
		goto out;
	}

	if (params.copy_fn == COPY_FN_MC ||
	    params.copy_fn == COPY_FN_BOTH) {
		memset(&r, 0, sizeof(r));
		run_one("folio_mc_copy", do_folio_mc_copy, iters, src, dst, &r);
		print_result(s, &r);
	}

	if (params.copy_fn == COPY_FN_PLAIN ||
	    params.copy_fn == COPY_FN_BOTH) {
		memset(&r, 0, sizeof(r));
		run_one("folio_copy", do_folio_copy, iters, src, dst, &r);
		print_result(s, &r);
	}

	free_folios(src, dst);
out:
	mutex_unlock(&bench_lock);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(bench_run);

/*
 * Selftest: happy-path correctness of folio_mc_copy() and folio_copy()
 * across all online NUMA directions and a representative subset of
 * folio orders ({0, 4, 8, 9}, i.e. base / 64 KB / 1 MB / 2 MB on a
 * 4 KB-base-page system). Any non-zero return from folio_mc_copy()
 * (which would indicate a spurious -EHWPOISON propagation) or a
 * corrupted byte in the destination fails the test. No-op on !MMU /
 * non-NUMA systems.
 *
 * True MCE injection is out of scope: hardware ECC errors cannot be
 * produced in software, and the MCE exception-table contract of the
 * underlying copy_mc_to_kernel() is already tested by upstream
 * infrastructure.
 */
static int selftest_verify_bytes(struct folio *dst, unsigned long nr)
{
	unsigned long bytes = nr << PAGE_SHIFT;
	const u8 *p = page_address(&dst->page);
	unsigned long i;

	/* alloc_folios() memset()'s src with 0xaa before each run. */
	for (i = 0; i < bytes; i++)
		if (p[i] != 0xaa)
			return -EINVAL;
	return 0;
}

struct selftest_ctx {
	struct seq_file *s;
	int pass;
	int fail;
};

#define ST_PASS(c, name) do { \
	seq_printf((c)->s, "PASS %s\n", name); \
	(c)->pass++; \
} while (0)

#define ST_FAIL(c, name, fmt, ...) do { \
	seq_printf((c)->s, "FAIL %s: " fmt "\n", name, ##__VA_ARGS__); \
	(c)->fail++; \
} while (0)

static void selftest_all(struct selftest_ctx *c)
{
	const int orders[] = {0, 4, 8, 9};
	struct folio *src = NULL, *dst = NULL;
	unsigned int cells_run = 0, cells_skipped = 0;
	int s_nid, d_nid, oi, ret;

	for_each_online_node(s_nid) {
		for_each_online_node(d_nid) {
			for (oi = 0; oi < ARRAY_SIZE(orders); oi++) {
				int order = orders[oi];

				if (alloc_folios(order, s_nid, d_nid,
						 &src, &dst)) {
					cells_skipped++;
					continue;
				}
				cells_run++;

				/*
				 * folio_mc_copy path.
				 */
				memset(page_address(&dst->page), 0x55,
				       folio_nr_pages(dst) << PAGE_SHIFT);
				ret = folio_mc_copy(dst, src);
				if (ret) {
					ST_FAIL(c, "mc_happy",
						"src=%d dst=%d order=%d ret=%d",
						s_nid, d_nid, order, ret);
					free_folios(src, dst);
					return;
				}
				if (selftest_verify_bytes(dst, folio_nr_pages(dst))) {
					ST_FAIL(c, "mc_verify",
						"src=%d dst=%d order=%d",
						s_nid, d_nid, order);
					free_folios(src, dst);
					return;
				}

				/*
				 * folio_copy path (non-MCE variant).
				 */
				memset(page_address(&dst->page), 0x33,
				       folio_nr_pages(dst) << PAGE_SHIFT);
				folio_copy(dst, src);
				if (selftest_verify_bytes(dst, folio_nr_pages(dst))) {
					ST_FAIL(c, "plain_verify",
						"src=%d dst=%d order=%d",
						s_nid, d_nid, order);
					free_folios(src, dst);
					return;
				}

				free_folios(src, dst);
			}
		}
	}

	seq_printf(c->s, "  cells run=%u skipped=%u\n",
		   cells_run, cells_skipped);
	if (cells_run == 0)
		ST_FAIL(c, "happy_path",
			"no (src,dst,order) cell allocated successfully");
	else
		ST_PASS(c, "happy_path_mc_and_plain");
}

static int bench_selftest_show(struct seq_file *s, void *unused)
{
	struct selftest_ctx c = { .s = s };

	mutex_lock(&bench_lock);
	seq_puts(s, "folio_copy A/B selftest\n");
	seq_puts(s, "=======================\n\n");
	seq_puts(s,
		 "Note: this selftest checks happy-path correctness of\n"
		 "folio_mc_copy() and folio_copy() - destination contents\n"
		 "match source across all online (src,dst) NUMA pairs and\n"
		 "orders {0,4,8,9} (4K base / 64K / 1M / 2M on a 4 KB-base-\n"
		 "page system). True MCE injection is out of scope.\n\n");

	selftest_all(&c);

	seq_printf(s, "\nSELFTEST: %d pass, %d fail\n", c.pass, c.fail);
	mutex_unlock(&bench_lock);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(bench_selftest);

static int kernel_show(struct seq_file *s, void *unused)
{
	struct new_utsname *u = init_utsname();

	seq_printf(s, "sysname=%s\n",   u->sysname);
	seq_printf(s, "nodename=%s\n",  u->nodename);
	seq_printf(s, "release=%s\n",   u->release);
	seq_printf(s, "version=%s\n",   u->version);
	seq_printf(s, "machine=%s\n",   u->machine);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(kernel);

static void free_flush_bufs(void)
{
	int nid;

	for (nid = 0; nid < MAX_NUMNODES; nid++) {
		vfree(flush_buf_node[nid]);
		flush_buf_node[nid] = NULL;
	}
}

static int __init ab_init(void)
{
	int nid, err;

	for_each_online_node(nid) {
		void *p = vmalloc_node(FLUSH_BYTES, nid);

		if (!p) {
			pr_err("failed to allocate %lu-byte flush buffer on node %d\n",
			       FLUSH_BYTES, nid);
			free_flush_bufs();
			return -ENOMEM;
		}
		memset(p, 0x5a, FLUSH_BYTES);
		flush_buf_node[nid] = p;
	}

	bench_dir = debugfs_create_dir("folio_copy_ab", NULL);
	if (IS_ERR(bench_dir)) {
		err = PTR_ERR(bench_dir);
		pr_err("failed to create debugfs dir: %d\n", err);
		free_flush_bufs();
		return err;
	}

	debugfs_create_u32("order", 0644, bench_dir, &params.order);
	debugfs_create_u32("src_node", 0644, bench_dir, &params.src_node);
	debugfs_create_u32("dst_node", 0644, bench_dir, &params.dst_node);
	debugfs_create_u32("flush", 0644, bench_dir, &params.flush);
	debugfs_create_u32("warmup", 0644, bench_dir, &params.warmup);
	debugfs_create_u32("copy_fn", 0644, bench_dir, &params.copy_fn);
	debugfs_create_u64("bytes_total", 0644, bench_dir, &params.bytes_total);
	debugfs_create_u64("max_iters", 0644, bench_dir, &params.max_iters);
	debugfs_create_file("run", 0444, bench_dir, NULL, &bench_run_fops);
	debugfs_create_file("selftest", 0444, bench_dir, NULL,
			    &bench_selftest_fops);
	debugfs_create_file("kernel", 0444, bench_dir, NULL, &kernel_fops);

	pr_info("ready. See /sys/kernel/debug/folio_copy_ab/\n");
	return 0;
}

static void __exit ab_exit(void)
{
	debugfs_remove_recursive(bench_dir);
	free_flush_bufs();
}

module_init(ab_init);
module_exit(ab_exit);

MODULE_AUTHOR("mt-test");
MODULE_DESCRIPTION("A/B bench of folio_mc_copy()/folio_copy() between kernels");
MODULE_LICENSE("GPL");
