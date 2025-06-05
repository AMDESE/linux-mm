// SPDX-License-Identifier: GPL-2.0
/*
 * Maintains information about hot pages from slower tier nodes and
 * promotes them.
 *
 * Per-PFN hotness information is stored for lower tier nodes in
 * mem_section.
 *
 * In the default mode, a single byte (u8) is used to store
 * the frequency of access and last access time. Promotions are done
 * to a default toptier NID.
 *
 * In the precision mode, 4 bytes are used to store the frequency
 * of access, last access time and the accessing NID.
 *
 * A kernel thread named kmigrated is provided to migrate or promote
 * the hot pages. kmigrated runs for each lower tier node. It iterates
 * over the node's PFNs and  migrates pages marked for migration into
 * their targeted nodes.
 *
 * Migration rate-limiting and dynamic threshold logic implementations
 * were moved from NUMA Balancing mode 2.
 *
 * Note on time tracking and its inherent limitation:
 *
 * Both modes track the last access time in a fixed-width field of the per-PFN
 * record (14 bits in precision mode, 5 bucketed bits in default mode), and the
 * access latency is computed as a masked subtraction over that field. As with
 * any limited-width timestamp, the latency wraps once two accesses are farther
 * apart than the field can represent (~16 s in precision mode, ~4 s in default
 * mode, at HZ=1000); beyond that a long-idle page can alias to a small latency
 * and appear recently hot. This is not specific to pghot: the existing NUMA
 * Balancing tiering mode (numa_balancing=2) has the same property in
 * numa_hint_fault_latency(), which computes
 * "(time - last_time) & PAGE_ACCESS_TIME_MASK" over the page-flags time field.
 * The promotion window (pghot_promote_window_ms) is capped well below the
 * field span, so this should not affect correctness in practice.
 */
#include <linux/mm.h>
#include <linux/migrate.h>
#include <linux/memory.h>
#include <linux/memory-tiers.h>
#include <linux/debugfs.h>
#include <linux/rcupdate.h>
#include <linux/memory_hotplug.h>
#include <linux/pghot.h>

unsigned int pghot_promote_window_min = PGHOT_PROMOTE_WINDOW_MIN;
unsigned int pghot_promote_window_max;
unsigned int pghot_freq_threshold_max = PGHOT_FREQ_MAX;
unsigned int kmigrated_sleep_ms = KMIGRATED_SLEEP_MS_DEFAULT;
unsigned int kmigrated_batch_nr = KMIGRATED_BATCH_NR_DEFAULT;

unsigned int sysctl_pghot_src_enabled = PGHOT_HINTFAULTS_ENABLED;
unsigned int sysctl_pghot_target_nid = PGHOT_DEFAULT_NODE;
unsigned int sysctl_pghot_promote_window = PGHOT_PROMOTE_WINDOW_DEFAULT;
unsigned int sysctl_pghot_freq_threshold = PGHOT_FREQ_THRESHOLD_DEFAULT;

/* Restrict the NUMA promotion throughput (MB/s) for each target node. */
static unsigned int sysctl_pghot_promote_rate_limit = 65536;

#define KMIGRATED_MIGRATION_ADJUST_STEPS	16
#define KMIGRATED_PROMOTION_THRESHOLD_WINDOW	60000

DEFINE_STATIC_KEY_FALSE(pghot_src_hwhints);
DEFINE_STATIC_KEY_FALSE(pghot_src_hintfaults);
DEFINE_MUTEX(pghot_tunables_lock);

#ifdef CONFIG_SYSCTL
static void pghot_src_enabled_update(unsigned int enabled)
{
	unsigned int changed = sysctl_pghot_src_enabled ^ enabled;

	if (changed & PGHOT_HINTFAULTS_ENABLED) {
		if (enabled & PGHOT_HINTFAULTS_ENABLED)
			static_branch_enable(&pghot_src_hintfaults);
		else
			static_branch_disable(&pghot_src_hintfaults);
	}

	if (changed & PGHOT_HWHINTS_ENABLED) {
		if (enabled & PGHOT_HWHINTS_ENABLED)
			static_branch_enable(&pghot_src_hwhints);
		else
			static_branch_disable(&pghot_src_hwhints);
	}
}

static int sysctl_src_enabled_handler(const struct ctl_table *table, int write,
				      void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	unsigned int enabled;

	guard(mutex)(&pghot_tunables_lock);

	enabled = sysctl_pghot_src_enabled;
	t = *table;
	t.data = &enabled;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;

	if (write) {
		if (enabled & ~PGHOT_SRC_ENABLED_MASK)
			return -EINVAL;
		pghot_src_enabled_update(enabled);
		sysctl_pghot_src_enabled = enabled;
	}
	return err;
}

static int sysctl_target_nid_handler(const struct ctl_table *table, int write,
				     void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	unsigned int nid;

	guard(mutex)(&pghot_tunables_lock);

	nid = sysctl_pghot_target_nid;
	t = *table;
	t.data = &nid;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;

	if (write) {
		if (!numa_valid_node(nid) || nid > PGHOT_NID_MAX ||
		    !node_online(nid) || !node_is_toptier(nid))
			return -EINVAL;
		WRITE_ONCE(sysctl_pghot_target_nid, nid);
	}
	return err;
}

static const struct ctl_table pghot_sysctls[] = {
	{
		.procname	= "pghot_enabled_sources",
		.data		= &sysctl_pghot_src_enabled,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sysctl_src_enabled_handler,
	},
	{
		.procname       = "pghot_promote_window_ms",
		.data           = &sysctl_pghot_promote_window,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &pghot_promote_window_min,
		.extra2         = &pghot_promote_window_max,
	},
	{
		.procname	= "pghot_target_nid",
		.data		= &sysctl_pghot_target_nid,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sysctl_target_nid_handler,
	},
	{
		.procname	= "pghot_freq_threshold",
		.data		= &sysctl_pghot_freq_threshold,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= &pghot_freq_threshold_max,
	},
	{
		.procname	= "pghot_promote_rate_limit_MBps",
		.data		= &sysctl_pghot_promote_rate_limit,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
};

/*
 * numa_balancing_promote_rate_limit_MBps has been replaced by
 * pghot_promote_rate_limit_MBps but retained here for compatibility.
 */
static const struct ctl_table compat_pghot_sysctls[] = {
	{
		.procname	= "numa_balancing_promote_rate_limit_MBps",
		.data		= &sysctl_pghot_promote_rate_limit,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
};

static void __init pghot_sysctl_init(void)
{
	register_sysctl_init("vm", pghot_sysctls);
	register_sysctl_init("kernel", compat_pghot_sysctls);
}
#else
static inline void pghot_sysctl_init(void) { }
#endif

static bool kmigrated_started __ro_after_init;

/**
 * pghot_record_access() - Record page accesses from lower tier memory
 * for the purpose of tracking page hotness and subsequent promotion.
 *
 * @pfn: PFN of the page
 * @nid: Target NID to where the page needs to be migrated in precision
 *       mode but unused in default mode
 * @src: The identifier of the sub-system that reports the access
 * @now: Access time in jiffies
 *
 * Updates the NID (in precision mode only), frequency and time of access
 * and marks the page as ready for migration if the frequency crosses a
 * threshold. The pages marked for migration are migrated by kmigrated
 * kernel thread.
 *
 * Return: 0 on success and -EINVAL on failure to record the access.
 */
int pghot_record_access(unsigned long pfn, int nid, int src, unsigned long now)
{
	struct mem_section *ms;
	struct folio *folio;
	struct pghot_hot_map *hot_map;
	phi_t *phi;
	struct page *page;
	int src_nid;

	if (!kmigrated_started)
		return 0;

	switch (src) {
	case PGHOT_HINTFAULTS:
		if (!static_branch_unlikely(&pghot_src_hintfaults))
			return 0;
		count_vm_event(PGHOT_REPORTED_HINTFAULTS);
		break;
	case PGHOT_HWHINTS:
		if (!static_branch_unlikely(&pghot_src_hwhints))
			return 0;
		count_vm_event(PGHOT_REPORTED_HWHINTS);
		break;
	default:
		return -EINVAL;
	}

	if (!pghot_nid_valid(nid))
		return -EINVAL;

	/*
	 * Validate the PFN and reject the non-migratable pages right away.
	 */
	page = pfn_to_online_page(pfn);
	if (!page || is_zone_device_page(page))
		return 0;

	/*
	 * Record only accesses from lower tiers.
	 */
	src_nid = page_to_nid(page);
	if (node_is_toptier(src_nid))
		return 0;

	folio = page_folio(page);
	if (!folio_try_get(folio))
		return 0;

	if (unlikely(page_folio(page) != folio))
		goto out;

	if (!folio_test_lru(folio))
		goto out;

	/* Get the hotness slot corresponding to the 1st PFN of the folio */
	pfn = folio_pfn(folio);
	ms = __pfn_to_section(pfn);

	rcu_read_lock();
	hot_map = ms ? rcu_dereference(ms->hot_map) : NULL;
	if (!hot_map) {
		rcu_read_unlock();
		goto out;
	}

	phi = &hot_map->phi[pfn % PAGES_PER_SECTION];

	count_vm_event(PGHOT_RECORDED_ACCESSES);

	/*
	 * Update the hotness parameters.
	 */
	if (pghot_update_record(phi, nid, now)) {
		set_bit(pghot_subsection_idx(pfn), hot_map->hot_subsections);
		/*
		 * The sub-section bit has to be visible before the section bit
		 * that sends kmigrated to the bitmap. In the other order a pass
		 * could see the section bit, find no sub-section bit set, clear
		 * the section bit and leave this record waiting for a further
		 * access to re-arm the section. Pairs with the ordering the
		 * consumer's test_and_clear_bit() already provides.
		 */
		smp_mb__before_atomic();
		set_bit(PGHOT_SECTION_HOT_BIT, &hot_map->flags);
		set_bit(PGDAT_KMIGRATED_ACTIVATE, &page_pgdat(page)->flags);
	}
	rcu_read_unlock();
out:
	folio_put(folio);
	return 0;
}

/*
 * For memory tiering mode, if there are enough free pages (more than
 * enough watermark defined here) in fast memory node, to take full
 * advantage of fast memory capacity, all recently accessed slow
 * memory pages will be migrated to fast memory node without
 * considering hot threshold.
 */
static bool pgdat_free_space_enough(struct pglist_data *pgdat)
{
	int z;
	unsigned long enough_wmark;

	enough_wmark = max(1UL * 1024 * 1024 * 1024 >> PAGE_SHIFT,
			   pgdat->node_present_pages >> 4);
	for (z = pgdat->nr_zones - 1; z >= 0; z--) {
		struct zone *zone = pgdat->node_zones + z;

		if (!populated_zone(zone))
			continue;

		if (zone_watermark_ok(zone, 0,
				      promo_wmark_pages(zone) + enough_wmark,
				      ZONE_MOVABLE, 0))
			return true;
	}
	return false;
}

/*
 * For memory tiering mode, too high promotion/demotion throughput may
 * hurt application latency.  So we provide a mechanism to rate limit
 * the number of pages that are tried to be promoted.
 */
static bool kmigrated_promotion_rate_limit(struct pglist_data *pgdat, unsigned long rate_limit,
					   int nr, unsigned int now_ms)
{
	unsigned long nr_cand;
	unsigned int start;

	mod_node_page_state(pgdat, PGPROMOTE_CANDIDATE, nr);
	nr_cand = node_page_state(pgdat, PGPROMOTE_CANDIDATE);
	start = pgdat->nbp_rl_start;
	if (now_ms - start > MSEC_PER_SEC &&
	    cmpxchg(&pgdat->nbp_rl_start, start, now_ms) == start)
		pgdat->nbp_rl_nr_cand = nr_cand;
	if (nr_cand - pgdat->nbp_rl_nr_cand >= rate_limit)
		return true;
	return false;
}

static void kmigrated_promotion_adjust_threshold(struct pglist_data *pgdat,
						 unsigned long rate_limit, unsigned int ref_th,
						 unsigned int now_ms)
{
	unsigned int start, th_period, unit_th, th;
	unsigned long nr_cand, ref_cand, diff_cand;

	th_period = KMIGRATED_PROMOTION_THRESHOLD_WINDOW;
	start = pgdat->nbp_th_start;
	if (now_ms - start > th_period &&
	    cmpxchg(&pgdat->nbp_th_start, start, now_ms) == start) {
		ref_cand = rate_limit *
			KMIGRATED_PROMOTION_THRESHOLD_WINDOW / MSEC_PER_SEC;
		nr_cand = node_page_state(pgdat, PGPROMOTE_CANDIDATE);
		diff_cand = nr_cand - pgdat->nbp_th_nr_cand;
		unit_th = ref_th * 2 / KMIGRATED_MIGRATION_ADJUST_STEPS;
		th = pgdat->nbp_threshold ? : ref_th;
		if (diff_cand > ref_cand * 11 / 10)
			th = max(th - unit_th, unit_th);
		else if (diff_cand < ref_cand * 9 / 10)
			th = min(th + unit_th, ref_th * 2);
		/*
		 * pghot_access_latency() saturates at pghot_promote_window_max.
		 * A threshold above it can never be reached, which silently
		 * disables the latency filter. Hence clamp so the threshold
		 * stays within that range.
		 */
		th = min(th, pghot_promote_window_max);
		pgdat->nbp_th_nr_cand = nr_cand;
		pgdat->nbp_threshold = th;
	}
}

static bool kmigrated_should_migrate_memory(unsigned long nr_pages, int nid,
					    unsigned long time)
{
	struct pglist_data *pgdat;
	unsigned long rate_limit;
	unsigned int th, def_th;
	unsigned int now_ms = jiffies_to_msecs(jiffies); /* Based on full-width jiffies */
	unsigned long now = jiffies;

	pgdat = NODE_DATA(nid);
	if (pgdat_free_space_enough(pgdat)) {
		/* workload changed, reset hot threshold */
		pgdat->nbp_threshold = 0;
		mod_node_page_state(pgdat, PGPROMOTE_CANDIDATE_NRL, nr_pages);
		return true;
	}

	def_th = READ_ONCE(sysctl_pghot_promote_window);
	rate_limit = MB_TO_PAGES(READ_ONCE(sysctl_pghot_promote_rate_limit));
	kmigrated_promotion_adjust_threshold(pgdat, rate_limit, def_th, now_ms);

	th = pgdat->nbp_threshold ? : def_th;
	if (pghot_access_latency(time, now) >= th)
		return false;

	return !kmigrated_promotion_rate_limit(pgdat, rate_limit, nr_pages, now_ms);
}

static int pghot_get_hotness(unsigned long pfn, int *nid, int *freq,
			     unsigned long *time)
{
	struct pghot_hot_map *hot_map;
	struct mem_section *ms;
	phi_t *phi;
	int ret;

	ms = __pfn_to_section(pfn);

	rcu_read_lock();
	hot_map = ms ? rcu_dereference(ms->hot_map) : NULL;
	if (!hot_map) {
		rcu_read_unlock();
		return -EINVAL;
	}

	phi = &hot_map->phi[pfn % PAGES_PER_SECTION];
	ret = pghot_get_record(phi, nid, freq, time);
	rcu_read_unlock();

	return ret;
}

/*
 * Consume (clear) the hotness record for @pfn. Called only after a folio has
 * been committed to migration (a successful migrate_misplaced_folio_prepare()),
 * so that skipped or failed-to-isolate folios retain their accumulated
 * frequency/time.
 */
static void pghot_clear_hotness(unsigned long pfn)
{
	struct pghot_hot_map *hot_map;
	struct mem_section *ms;

	ms = __pfn_to_section(pfn);

	rcu_read_lock();
	hot_map = ms ? rcu_dereference(ms->hot_map) : NULL;
	if (hot_map)
		WRITE_ONCE(hot_map->phi[pfn % PAGES_PER_SECTION], 0);
	rcu_read_unlock();
}

/**
 * struct kmigrated_batch - folios accumulated for one promotion batch
 * @folios: isolated folios awaiting promote_misplaced_memcg_folios().
 * @memcg:  batching key only, never dereferenced (see the folio_memcg() note
 *          in kmigrated_walk_zone()).
 * @nid:    promotion target shared by every folio in @folios.
 * @nr:     number of folios in @folios.
 *
 * The batch is carried across every chunk of every section in one kmigrated
 * pass, so that it still fills up when each chunk holds only a handful of
 * ready folios. At a fine granularity a whole section can yield a single ready
 * folio, so flushing per chunk (or even per section) would spend a
 * migrate_pages() and its TLB shootdown on one folio at a time. The folios
 * sit isolated until the batch is flushed, which is bounded by
 * kmigrated_batch_nr or the end of the pass, whichever comes first.
 */
struct kmigrated_batch {
	struct list_head folios;
	struct mem_cgroup *memcg;
	int nid;
	int nr;
};

static void kmigrated_batch_init(struct kmigrated_batch *batch)
{
	INIT_LIST_HEAD(&batch->folios);
	batch->memcg = NULL;
	batch->nid = NUMA_NO_NODE;
	batch->nr = 0;
}

static void kmigrated_batch_flush(struct kmigrated_batch *batch)
{
	if (list_empty(&batch->folios))
		return;

	promote_misplaced_memcg_folios(&batch->folios, batch->nid);
	batch->nr = 0;
}

/*
 * Walks the PFNs of the zone, isolates and migrates them in batches.
 */
static void kmigrated_walk_zone(unsigned long start_pfn, unsigned long end_pfn,
				int src_nid, struct kmigrated_batch *batch)
{
	struct folio *folio;
	struct page *page;
	unsigned long pfn;

	pfn = start_pfn;
	do {
		int nid = NUMA_NO_NODE, nr = 1;
		struct mem_cgroup *memcg;
		unsigned long time = 0;
		int freq = 0;

		if (!pfn_valid(pfn))
			goto out_next;

		page = pfn_to_online_page(pfn);
		if (!page)
			goto out_next;

		folio = page_folio(page);
		if (!folio_try_get(folio))
			goto out_next;

		if (unlikely(page_folio(page) != folio)) {
			folio_put(folio);
			goto out_next;
		}

		/*
		 * Page may be a tail page (e.g. a prior single-page advance
		 * landed inside this folio, or a large folio spans the section
		 * start). Advance by the pages remaining to the folio's end so
		 * we neither overshoot into (and skip) the next folio nor
		 * rescan pages already covered.
		 */
		nr = folio_nr_pages(folio) - folio_page_idx(folio, page);
		if (folio_nid(folio) != src_nid) {
			folio_put(folio);
			goto out_next;
		}

		if (!folio_test_lru(folio)) {
			folio_put(folio);
			goto out_next;
		}

		if (pghot_get_hotness(folio_pfn(folio), &nid, &freq, &time)) {
			folio_put(folio);
			goto out_next;
		}

		if (!pghot_nid_valid(nid)) {
			folio_put(folio);
			goto out_next;
		}

		if (folio_nid(folio) == nid) {
			folio_put(folio);
			goto out_next;
		}

		if (!kmigrated_should_migrate_memory(nr, nid, time)) {
			folio_put(folio);
			goto out_next;
		}

		if (migrate_misplaced_folio_prepare(folio, NULL, nid)) {
			folio_put(folio);
			goto out_next;
		}

		/* Committed to migration: consume the hotness record now. */
		pghot_clear_hotness(folio_pfn(folio));

		/*
		 * memcg is used only as a batching key here and is not
		 * dereferenced or passed on. promote_misplaced_memcg_folios()
		 * re-derives the memcg from the batch. The per-cgroup promotion
		 * stats are best-effort. The read is RCU-protected only to
		 * satisfy folio_memcg()'s contract.
		 */
		rcu_read_lock();
		memcg = folio_memcg(folio);
		rcu_read_unlock();
		if (batch->nid == NUMA_NO_NODE) {
			batch->nid = nid;
			batch->memcg = memcg;
		}

		/* If NID or memcg changed, flush the previous batch first */
		if (batch->nid != nid || batch->memcg != memcg) {
			kmigrated_batch_flush(batch);
			batch->nid = nid;
			batch->memcg = memcg;
			cond_resched();
		}

		list_add(&folio->lru, &batch->folios);
		folio_put(folio);

		if (++batch->nr > READ_ONCE(kmigrated_batch_nr)) {
			kmigrated_batch_flush(batch);
			cond_resched();
		}
out_next:
		pfn += nr;
	} while (pfn < end_pfn);
}

/*
 * Claim the next hot chunk of @ms at or after @idx, or PGHOT_SUBSECTIONS when
 * the section has none left. The bit is cleared before its chunk is walked
 * rather than after, so a chunk marked hot during its own walk stays marked
 * and the PGHOT_SECTION_HOT_BIT it re-arms brings kmigrated back to it.
 *
 * The bitmap is re-located under RCU on every call because kmigrated_walk_zone()
 * sleeps and the hot_map can be freed by a memory offline in between.
 */
static unsigned long kmigrated_claim_subsection(struct mem_section *ms,
						unsigned long idx)
{
	struct pghot_hot_map *hot_map;

	guard(rcu)();

	hot_map = rcu_dereference(ms->hot_map);
	if (!hot_map)
		return PGHOT_SUBSECTIONS;

	idx = find_next_bit(hot_map->hot_subsections, PGHOT_SUBSECTIONS, idx);
	if (idx < PGHOT_SUBSECTIONS)
		clear_bit(idx, hot_map->hot_subsections);

	return idx;
}

static void kmigrated_do_work(pg_data_t *pgdat)
{
	unsigned long section_nr, s_begin, start_pfn, idx;
	struct pghot_hot_map *hot_map;
	struct kmigrated_batch batch;
	struct mem_section *ms;
	bool hot;
	int nid;

	clear_bit(PGDAT_KMIGRATED_ACTIVATE, &pgdat->flags);
	kmigrated_batch_init(&batch);
	s_begin = next_present_section_nr(-1);
	for_each_present_section_nr(s_begin, section_nr) {
		/*
		 * A single walk is bounded by one chunk, but a node can have
		 * many hot sections; yield once per section so a pass that
		 * migrates nothing (all pages skipped) can't hog the CPU on
		 * non-preemptible kernels. Migration-heavy sections
		 * additionally reschedule at each batch flush in
		 * kmigrated_walk_zone().
		 */
		cond_resched();

		start_pfn = section_nr_to_pfn(section_nr);
		ms = __nr_to_section(section_nr);

		if (!pfn_valid(start_pfn))
			continue;

		nid = pfn_to_nid(start_pfn);
		if (nid != pgdat->node_id || node_is_toptier(nid))
			continue;

		rcu_read_lock();
		hot_map = rcu_dereference(ms->hot_map);
		hot = hot_map &&
		      test_and_clear_bit(PGHOT_SECTION_HOT_BIT, &hot_map->flags);
		rcu_read_unlock();

		if (!hot)
			continue;

		for (idx = 0; idx < PGHOT_SUBSECTIONS; idx++) {
			unsigned long chunk_pfn;

			idx = kmigrated_claim_subsection(ms, idx);
			if (idx >= PGHOT_SUBSECTIONS)
				break;

			chunk_pfn = start_pfn + (idx << PGHOT_SUBSECTION_SHIFT);
			kmigrated_walk_zone(chunk_pfn,
					    chunk_pfn + PGHOT_SUBSECTION_PAGES,
					    pgdat->node_id, &batch);
			cond_resched();
		}
	}
	kmigrated_batch_flush(&batch);
}

static inline bool kmigrated_work_requested(pg_data_t *pgdat)
{
	return test_bit(PGDAT_KMIGRATED_ACTIVATE, &pgdat->flags);
}

/*
 * Per-node kthread that iterates over its PFNs and migrates the
 * pages that have been marked for migration.
 */
static int kmigrated(void *p)
{
	pg_data_t *pgdat = p;

	while (!kthread_should_stop()) {
		long timeout = msecs_to_jiffies(READ_ONCE(kmigrated_sleep_ms));

		if (wait_event_timeout(pgdat->kmigrated_wait,
				       kmigrated_work_requested(pgdat) ||
				       kthread_should_stop(),
				       timeout)) {
			if (!kthread_should_stop())
				kmigrated_do_work(pgdat);
		}
	}
	return 0;
}

static int kmigrated_run(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	int ret;

	if (!pgdat->kmigrated) {
		pgdat->kmigrated = kthread_create_on_node(kmigrated, pgdat, nid,
							  "kmigrated%d", nid);
		if (IS_ERR(pgdat->kmigrated)) {
			ret = PTR_ERR(pgdat->kmigrated);
			pgdat->kmigrated = NULL;
			pr_err("Failed to start kmigrated%d, ret %d\n", nid, ret);
			return ret;
		}
		pr_info("pghot: Started kmigrated thread for node %d\n", nid);
	}
	wake_up_process(pgdat->kmigrated);
	return 0;
}

static void pghot_free_hot_map(struct mem_section *ms)
{
	struct pghot_hot_map *hot_map;

	hot_map = rcu_dereference_protected(ms->hot_map, 1);
	if (!hot_map)
		return;

	RCU_INIT_POINTER(ms->hot_map, NULL);
	kvfree_rcu(hot_map, rcu);
}

static int pghot_alloc_hot_map(struct mem_section *ms, int nid)
{
	struct pghot_hot_map *hot_map;

	hot_map = kvzalloc_node(struct_size(hot_map, phi, PAGES_PER_SECTION),
				GFP_KERNEL, nid);
	if (!hot_map)
		return -ENOMEM;

	rcu_assign_pointer(ms->hot_map, hot_map);
	return 0;
}

static void pghot_offline_sec_hotmap(unsigned long start_pfn,
				     unsigned long nr_pages)
{
	unsigned long start, end, pfn;
	struct mem_section *ms;

	start = SECTION_ALIGN_DOWN(start_pfn);
	end = SECTION_ALIGN_UP(start_pfn + nr_pages);

	for (pfn = start; pfn < end; pfn += PAGES_PER_SECTION) {
		ms = __pfn_to_section(pfn);
		if (!ms)
			continue;

		pghot_free_hot_map(ms);
	}
}

static int pghot_online_sec_hotmap(unsigned long start_pfn,
				   unsigned long nr_pages)
{
	int nid = pfn_to_nid(start_pfn);
	unsigned long start, end, pfn;
	struct mem_section *ms;
	int fail = 0;

	/*
	 * No section hot maps for toptier sections.
	 */
	if (node_is_toptier(nid))
		return 0;

	start = SECTION_ALIGN_DOWN(start_pfn);
	end = SECTION_ALIGN_UP(start_pfn + nr_pages);

	for (pfn = start; !fail && pfn < end; pfn += PAGES_PER_SECTION) {
		ms = __pfn_to_section(pfn);
		/*
		 * A section in a going-online range normally has no hot_map:
		 * freshly hot-added sections had none at boot-time setup, and
		 * re-onlined sections had theirs freed on the prior MEM_OFFLINE /
		 * MEM_CANCEL_ONLINE. Setup and this notifier are serialized under
		 * get_online_mems() (notifier registered under the lock, and
		 * unregistered before teardown frees), so setup cannot leave a
		 * stale map for a going-online section either. The skip is thus
		 * defensive: it only matters if a section is somehow already
		 * mapped (e.g. present-but-offline at boot), where it avoids
		 * re-allocating over and leaking the existing map. Because the
		 * range is otherwise all-NULL, the rollback below frees exactly
		 * the maps this call allocated.
		 *
		 * MEM_ONLINE catch-up (see pghot_memhp_callback) does not change
		 * that: it invokes this helper only when the range is still
		 * all-NULL (MEM_GOING_ONLINE skipped the node as toptier because
		 * memtier was not yet assigned). Later blocks already have maps
		 * from MEM_GOING_ONLINE, so catch-up does not call here and the
		 * skip does not become the common path.
		 */
		if (!ms || rcu_access_pointer(ms->hot_map))
			continue;

		fail = pghot_alloc_hot_map(ms, nid);
	}

	if (!fail)
		return 0;

	/* rollback: free the sections allocated before the failure */
	end = pfn - PAGES_PER_SECTION;
	for (pfn = start; pfn < end; pfn += PAGES_PER_SECTION) {
		ms = __pfn_to_section(pfn);
		if (ms)
			pghot_free_hot_map(ms);
	}
	return -ENOMEM;
}

static int pghot_memhp_callback(struct notifier_block *self,
				unsigned long action, void *arg)
{
	struct memory_notify *mn = arg;
	int ret = 0;

	switch (action) {
	case MEM_GOING_ONLINE:
		ret = pghot_online_sec_hotmap(mn->start_pfn, mn->nr_pages);
		break;
	case MEM_ONLINE: {
		struct mem_section *ms;

		/*
		 * MEM_GOING_ONLINE is the normal alloc path, but it runs
		 * before NODE_ADDED_FIRST_MEMORY. Until memtier is assigned,
		 * node_is_toptier() treats a memoryless node as toptier, so
		 * the first block of a new lower-tier node is skipped there.
		 *
		 * MEM_ONLINE is after NODE_ADDED_FIRST_MEMORY, so the tier
		 * check is accurate. Catch up only when this range still has
		 * no map: that keeps pghot_online_sec_hotmap() on an
		 * all-NULL range (same rollback invariant as MEM_GOING_ONLINE)
		 * and avoids re-entering it on later blocks that already
		 * allocated at MEM_GOING_ONLINE. online_pages() ignores the
		 * MEM_ONLINE return, so a catch-up ENOMEM is best-effort.
		 */
		ms = __pfn_to_section(mn->start_pfn);
		if (ms && !rcu_access_pointer(ms->hot_map))
			ret = pghot_online_sec_hotmap(mn->start_pfn, mn->nr_pages);
		break;
	}
	case MEM_OFFLINE:
	case MEM_CANCEL_ONLINE:
		pghot_offline_sec_hotmap(mn->start_pfn, mn->nr_pages);
		break;
	}

	return notifier_from_errno(ret);
}

static struct notifier_block pghot_mem_notifier = {
	.notifier_call = pghot_memhp_callback,
	.priority = DEFAULT_CALLBACK_PRI,
};

static void pghot_destroy_hot_map(void)
{
	unsigned long section_nr, s_begin;
	struct mem_section *ms;

	/*
	 * Hold the hotplug lock across unregister + free: it blocks
	 * online/offline for the whole teardown, so no notifier callback can
	 * run and the present-section set can't change under the walk.
	 */
	get_online_mems();
	unregister_memory_notifier(&pghot_mem_notifier);
	s_begin = next_present_section_nr(-1);
	for_each_present_section_nr(s_begin, section_nr) {
		ms = __nr_to_section(section_nr);
		pghot_free_hot_map(ms);
	}
	put_online_mems();
}

static int pghot_setup_hot_map(void)
{
	unsigned long section_nr, s_begin, start_pfn;
	struct mem_section *ms;
	int nid, ret;

	/*
	 * get_online_mems() blocks online/offline so the walk below can't race
	 * with a notifier callback
	 */
	get_online_mems();
	ret = register_memory_notifier(&pghot_mem_notifier);
	if (ret) {
		put_online_mems();
		return ret;
	}

	s_begin = next_present_section_nr(-1);
	for_each_present_section_nr(s_begin, section_nr) {
		ms = __nr_to_section(section_nr);
		start_pfn = section_nr_to_pfn(section_nr);

		if (!pfn_valid(start_pfn))
			continue;

		nid = pfn_to_nid(start_pfn);
		if (node_is_toptier(nid))
			continue;

		if (pghot_alloc_hot_map(ms, nid))
			goto out_free_hot_map;
	}
	put_online_mems();
	return 0;

out_free_hot_map:
	put_online_mems();
	pghot_destroy_hot_map();
	return -ENOMEM;
}

static int pghot_parse_uint(const char __user *ubuf, size_t cnt, unsigned int *val)
{
	char buf[16];

	if (cnt > sizeof(buf) - 1)
		cnt = sizeof(buf) - 1;
	if (copy_from_user(buf, ubuf, cnt))
		return -EFAULT;
	buf[cnt] = '\0';
	if (kstrtouint(buf, 0, val))
		return -EINVAL;
	return 0;
}

static ssize_t pghot_kmigrated_sleep_ms_write(struct file *filp, const char __user *ubuf,
					      size_t cnt, loff_t *ppos)
{
	unsigned int val;
	int ret;

	guard(mutex)(&pghot_tunables_lock);

	ret = pghot_parse_uint(ubuf, cnt, &val);
	if (ret)
		return ret;
	if (val < KMIGRATED_SLEEP_MS_MIN  || val > KMIGRATED_SLEEP_MS_MAX)
		return -EINVAL;

	WRITE_ONCE(kmigrated_sleep_ms, val);
	*ppos += cnt;
	return cnt;
}

static ssize_t pghot_kmigrated_batch_nr_write(struct file *filp, const char __user *ubuf,
					      size_t cnt, loff_t *ppos)
{
	unsigned int val;
	int ret;

	guard(mutex)(&pghot_tunables_lock);

	ret = pghot_parse_uint(ubuf, cnt, &val);
	if (ret)
		return ret;
	if (val < KMIGRATED_BATCH_NR_MIN  || val > KMIGRATED_BATCH_NR_MAX)
		return -EINVAL;

	WRITE_ONCE(kmigrated_batch_nr, val);
	*ppos += cnt;
	return cnt;
}

#define PGHOT_SHOW(name)						\
static int pghot_##name##_show(struct seq_file *m, void *v)		\
{									\
	seq_printf(m, "%u\n", name);				\
	return 0;							\
}									\
static int pghot_##name##_open(struct inode *inode, struct file *filp)	\
{									\
	return single_open(filp, pghot_##name##_show, NULL);		\
}

PGHOT_SHOW(kmigrated_sleep_ms)
PGHOT_SHOW(kmigrated_batch_nr)

#define PGHOT_FOPS(name)						\
static const struct file_operations pghot_##name##_fops = {		\
	.open		= pghot_##name##_open,				\
	.read		= seq_read,					\
	.write		= pghot_##name##_write,				\
	.llseek		= seq_lseek,					\
	.release	= single_release,				\
}

PGHOT_FOPS(kmigrated_sleep_ms);
PGHOT_FOPS(kmigrated_batch_nr);

static void pghot_debug_init(void)
{
	struct dentry *dir = debugfs_create_dir("pghot", NULL);

	debugfs_create_file("kmigrated_sleep_ms", 0644, dir, NULL,
			    &pghot_kmigrated_sleep_ms_fops);
	debugfs_create_file("kmigrated_batch_nr", 0644, dir, NULL,
			    &pghot_kmigrated_batch_nr_fops);
}

static void __init pghot_src_enabled_init(void)
{
	if (sysctl_pghot_src_enabled & PGHOT_HINTFAULTS_ENABLED)
		static_branch_enable(&pghot_src_hintfaults);
	if (sysctl_pghot_src_enabled & PGHOT_HWHINTS_ENABLED)
		static_branch_enable(&pghot_src_hwhints);
}

static int pghot_node_cb(struct notifier_block *self, unsigned long action,
			 void *arg)
{
	struct node_notify *nn = arg;
	int nid = nn->nid;
	pg_data_t *pgdat;

	switch (action) {
	case NODE_ADDED_FIRST_MEMORY:
		if (!node_is_toptier(nid) && kmigrated_run(nid))
			pr_err("Failed to start kmigrated for Node %d\n", nid);
		break;
	case NODE_REMOVED_LAST_MEMORY:
		pgdat = NODE_DATA(nid);
		if (pgdat->kmigrated) {
			kthread_stop(pgdat->kmigrated);
			pgdat->kmigrated = NULL;
		}
		break;
	}
	return NOTIFY_OK;
}

static int __init pghot_init(void)
{
	pg_data_t *pgdat;
	int nid, ret;

	ret = pghot_setup_hot_map();
	if (ret)
		return ret;

	for_each_node_state(nid, N_MEMORY) {
		if (node_is_toptier(nid))
			continue;

		ret = kmigrated_run(nid);
		if (ret)
			goto out_stop_kthread;
	}

	ret = hotplug_node_notifier(pghot_node_cb, DEFAULT_CALLBACK_PRI);
	if (ret)
		goto out_stop_kthread;

	/*
	 * The freq window is tracked/compared in the jiffies domain but exposed
	 * as a millisecond sysctl; derive the ms upper bound from the maximum
	 * representable jiffies window so the cap is correct for any HZ.
	 */
	pghot_promote_window_max = jiffies_to_msecs(PGHOT_PROMOTE_WINDOW_MAX_JIFFIES);

	pghot_sysctl_init();
	pghot_debug_init();
	pghot_src_enabled_init();

	kmigrated_started = true;
	return 0;

out_stop_kthread:
	for_each_node_state(nid, N_MEMORY) {
		pgdat = NODE_DATA(nid);
		if (pgdat->kmigrated) {
			kthread_stop(pgdat->kmigrated);
			pgdat->kmigrated = NULL;
		}
	}
	pghot_destroy_hot_map();
	return ret;
}

late_initcall_sync(pghot_init)
