// SPDX-License-Identifier: GPL-2.0
/*
 * Maintains information about hot pages from slower tier nodes and
 * promotes them.
 *
 * Info about accessed pages are stored in hash lists indexed by PFN.
 * Info about pages that are hot enough to be promoted are stored in
 * a per-toptier-node max_heap.
 *
 * kpromoted is a kernel thread that runs on each toptier node and
 * promotes pages from max_heap.
 *
 * Migration rate-limiting and dynamic threshold logic implementations
 * were moved from NUMA Balancing mode 2.
 */
#include <linux/pghot.h>
#include <linux/kthread.h>
#include <linux/mmzone.h>
#include <linux/migrate.h>
#include <linux/memory-tiers.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/hashtable.h>
#include <linux/min_heap.h>

struct pghot_hash {
	struct hlist_head hash;
	spinlock_t lock;
};

static struct pghot_hash *phi_hash;
static int phi_hash_order;
static int phi_heap_entries;
static struct kmem_cache *phi_cache __ro_after_init;
static bool kpromoted_started __ro_after_init;

static unsigned int sysctl_pghot_freq_window = KPROMOTED_FREQ_WINDOW;

/* Restrict the NUMA promotion throughput (MB/s) for each target node. */
static unsigned int sysctl_pghot_promote_rate_limit = 65536;

#ifdef CONFIG_SYSCTL
static const struct ctl_table pghot_sysctls[] = {
	{
		.procname	= "pghot_promote_freq_window_ms",
		.data		= &sysctl_pghot_freq_window,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
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
#endif

static bool phi_heap_less(const void *lhs, const void *rhs, void *args)
{
	return (*(struct pghot_info **)lhs)->frequency >
		(*(struct pghot_info **)rhs)->frequency;
}

static void phi_heap_swp(void *lhs, void *rhs, void *args)
{
	struct pghot_info **l = (struct pghot_info **)lhs;
	struct pghot_info **r = (struct pghot_info **)rhs;
	int lindex = l - (struct pghot_info **)args;
	int rindex = r - (struct pghot_info **)args;
	struct pghot_info *tmp = *l;

	*l = *r;
	*r = tmp;

	(*l)->heap_idx = lindex;
	(*r)->heap_idx = rindex;
}

static const struct min_heap_callbacks phi_heap_cb = {
	.less = phi_heap_less,
	.swp = phi_heap_swp,
};

static void phi_heap_update_entry(struct max_heap *phi_heap, struct pghot_info *phi)
{
	int orig_idx = phi->heap_idx;

	min_heap_sift_up(phi_heap, phi->heap_idx, &phi_heap_cb,
			 phi_heap->data);
	if (phi_heap->data[phi->heap_idx]->heap_idx == orig_idx)
		min_heap_sift_down(phi_heap, phi->heap_idx,
				   &phi_heap_cb, phi_heap->data);
}

static bool phi_heap_insert(struct max_heap *phi_heap, struct pghot_info *phi)
{
	if (phi_heap->nr >= phi_heap_entries)
		return false;

	phi->heap_idx = phi_heap->nr;
	min_heap_push(phi_heap, &phi, &phi_heap_cb, phi_heap->data);

	return true;
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
static bool kpromoted_promotion_rate_limit(struct pglist_data *pgdat,
					   unsigned long rate_limit, int nr,
					   unsigned long time)
{
	unsigned long nr_cand;
	unsigned int now, start;

	now = jiffies_to_msecs(time);
	mod_node_page_state(pgdat, PGPROMOTE_CANDIDATE, nr);
	nr_cand = node_page_state(pgdat, PGPROMOTE_CANDIDATE);
	start = pgdat->nbp_rl_start;
	if (now - start > MSEC_PER_SEC &&
	    cmpxchg(&pgdat->nbp_rl_start, start, now) == start)
		pgdat->nbp_rl_nr_cand = nr_cand;
	if (nr_cand - pgdat->nbp_rl_nr_cand >= rate_limit)
		return true;
	return false;
}

static void kpromoted_promotion_adjust_threshold(struct pglist_data *pgdat,
						 unsigned long rate_limit,
						 unsigned int ref_th,
						 unsigned long now)
{
	unsigned int start, th_period, unit_th, th;
	unsigned long nr_cand, ref_cand, diff_cand;

	now = jiffies_to_msecs(now);
	th_period = KPROMOTED_PROMOTION_THRESHOLD_WINDOW;
	start = pgdat->nbp_th_start;
	if (now - start > th_period &&
	    cmpxchg(&pgdat->nbp_th_start, start, now) == start) {
		ref_cand = rate_limit *
			KPROMOTED_PROMOTION_THRESHOLD_WINDOW / MSEC_PER_SEC;
		nr_cand = node_page_state(pgdat, PGPROMOTE_CANDIDATE);
		diff_cand = nr_cand - pgdat->nbp_th_nr_cand;
		unit_th = ref_th * 2 / KPROMOTED_MIGRATION_ADJUST_STEPS;
		th = pgdat->nbp_threshold ? : ref_th;
		if (diff_cand > ref_cand * 11 / 10)
			th = max(th - unit_th, unit_th);
		else if (diff_cand < ref_cand * 9 / 10)
			th = min(th + unit_th, ref_th * 2);
		pgdat->nbp_th_nr_cand = nr_cand;
		pgdat->nbp_threshold = th;
	}
}

static inline unsigned int pghot_access_latency(struct pghot_info *phi, u32  now)
{
	return (now - phi->last_update);
}

static bool phi_is_pfn_hot(struct pghot_info *phi)
{
	struct page *page = pfn_to_online_page(phi->pfn);
	struct folio *folio;
	struct pglist_data *pgdat;
	unsigned long rate_limit;
	unsigned int latency, th, def_th;
	unsigned long now = jiffies;

	if (!page || is_zone_device_page(page))
		return false;

	folio = page_folio(page);
	if (!folio_test_lru(folio)) {
		count_vm_event(KPROMOTED_NON_LRU);
		return false;
	}
	if (folio_nid(folio) == phi->nid) {
		count_vm_event(KPROMOTED_RIGHT_NODE);
		return false;
	}

	pgdat = NODE_DATA(phi->nid);
	if (pgdat_free_space_enough(pgdat)) {
		/* workload changed, reset hot threshold */
		pgdat->nbp_threshold = 0;
		return true;
	}

	def_th = sysctl_pghot_freq_window;
	rate_limit = sysctl_pghot_promote_rate_limit << (20 - PAGE_SHIFT);
	kpromoted_promotion_adjust_threshold(pgdat, rate_limit, def_th, now);

	th = pgdat->nbp_threshold ? : def_th;
	latency = pghot_access_latency(phi, now & PGHOT_TIME_MASK);
	if (latency >= th)
		return false;

	return !kpromoted_promotion_rate_limit(pgdat, rate_limit,
					       folio_nr_pages(folio), now);
}

static struct folio *kpromoted_isolate_folio(struct pghot_info *phi)
{
	struct page *page = pfn_to_page(phi->pfn);
	struct folio *folio;

	if (!page)
		return NULL;

	folio = page_folio(page);
	if (migrate_misplaced_folio_prepare(folio, NULL, phi->nid))
		return NULL;
	else
		return folio;
}

static struct pghot_info *phi_alloc(unsigned long pfn)
{
	struct pghot_info *phi;

	phi = kmem_cache_zalloc(phi_cache, GFP_NOWAIT);
	if (!phi)
		return NULL;

	phi->pfn = pfn;
	phi->heap_idx = -1;
	return phi;
}

static inline void phi_free(struct pghot_info *phi)
{
	kmem_cache_free(phi_cache, phi);
}

static int phi_heap_extract(pg_data_t *pgdat, int batch_count, int freq_th,
			    struct list_head *migrate_list, int *count)
{
	spinlock_t *phi_heap_lock = &pgdat->heap_lock;
	struct max_heap *phi_heap = &pgdat->heap;
	int max_retries = 10;
	int bkt, i = 0;

	if (batch_count < 0 || !migrate_list || !count || freq_th < 1 ||
	    freq_th > KPROMOTED_FREQ_THRESHOLD)
		return -EINVAL;

	*count = 0;
	for (i = 0; i < batch_count; i++) {
		struct pghot_info *top = NULL;
		bool should_continue = false;
		struct folio *folio;
		int retries = 0;

		while (retries < max_retries) {
			spin_lock(phi_heap_lock);
			if (phi_heap->nr > 0 && phi_heap->data[0]->frequency >= freq_th) {
				should_continue = true;
				bkt = hash_min(phi_heap->data[0]->pfn, phi_hash_order);
				top = phi_heap->data[0];
			}
			spin_unlock(phi_heap_lock);

			if (!should_continue)
				goto done;

			spin_lock(&phi_hash[bkt].lock);
			spin_lock(phi_heap_lock);
			if (phi_heap->nr == 0 || phi_heap->data[0] != top ||
			    phi_heap->data[0]->frequency < freq_th) {
				spin_unlock(phi_heap_lock);
				spin_unlock(&phi_hash[bkt].lock);
				retries++;
				continue;
			}

			top = phi_heap->data[0];
			hlist_del_init(&top->hnode);

			phi_heap->nr--;
			if (phi_heap->nr > 0) {
				phi_heap->data[0] = phi_heap->data[phi_heap->nr];
				phi_heap->data[0]->heap_idx = 0;
				min_heap_sift_down(phi_heap, 0, &phi_heap_cb,
						   phi_heap->data);
			}

			spin_unlock(phi_heap_lock);
			spin_unlock(&phi_hash[bkt].lock);

			if (!phi_is_pfn_hot(top)) {
				count_vm_event(KPROMOTED_DROPPED);
				goto skip;
			}

			folio = kpromoted_isolate_folio(top);
			if (folio) {
				list_add(&folio->lru, migrate_list);
				(*count)++;
			}
skip:
			phi_free(top);
			break;
		}
		if (retries >= max_retries) {
			pr_warn("%s: Too many retries\n", __func__);
			break;
		}

	}
done:
	return 0;
}

static void phi_heap_add_or_adjust(struct pghot_info *phi)
{
	pg_data_t *pgdat = NODE_DATA(phi->nid);
	struct max_heap *phi_heap = &pgdat->heap;

	spin_lock(&pgdat->heap_lock);
	if (phi->heap_idx >= 0 && phi->heap_idx < phi_heap->nr &&
	    phi_heap->data[phi->heap_idx] == phi) {
		/* Entry exists in heap */
		if (phi->frequency < KPROMOTED_FREQ_THRESHOLD) {
			/* Below threshold, remove from the heap */
			phi_heap->nr--;
			if (phi->heap_idx < phi_heap->nr) {
				phi_heap->data[phi->heap_idx] =
					phi_heap->data[phi_heap->nr];
				phi_heap->data[phi->heap_idx]->heap_idx =
					phi->heap_idx;
				min_heap_sift_down(phi_heap, phi->heap_idx,
						   &phi_heap_cb, phi_heap->data);
			}
			phi->heap_idx = -1;

		} else {
			/* Update position in heap */
			phi_heap_update_entry(phi_heap, phi);
		}
	} else if (phi->frequency >= KPROMOTED_FREQ_THRESHOLD) {
		/*
		 * Add to the heap. If heap is full we will have
		 * to wait for the next access reporting to elevate
		 * it to heap.
		 */
		if (phi_heap_insert(phi_heap, phi))
			count_vm_event(PGHOT_RECORDS_HEAP);
	}
	spin_unlock(&pgdat->heap_lock);
}

static struct pghot_info *phi_lookup(unsigned long pfn, int bkt)
{
	struct pghot_info *phi;

	hlist_for_each_entry(phi, &phi_hash[bkt].hash, hnode) {
		if (phi->pfn == pfn)
			return phi;
	}
	return NULL;
}

/*
 * Called by subsystems that generate page hotness/access information.
 *
 *  @pfn: The PFN of the memory accessed
 *  @nid: The accessing NUMA node ID
 *  @src: The temperature source (sub-system) that generated the
 *        access info
 *  @time: The access time in jiffies
 *
 * Maintains the access records per PFN, classifies them as
 * hot based on subsequent accesses and finally hands over
 * them to kpromoted for migration.
 */
int pghot_record_access(u64 pfn, int nid, int src, unsigned long now)
{
	struct pghot_info *phi;
	struct page *page;
	struct folio *folio;
	int bkt;
	bool new_entry = false, new_window = false;
	u32 cur_time = now & PGHOT_TIME_MASK;

	if (!kpromoted_started)
		return -EINVAL;

	if (nid >= PGHOT_NID_MAX)
		return -EINVAL;

	count_vm_event(PGHOT_RECORDED_ACCESSES);

	switch (src) {
	case PGHOT_HW_HINTS:
		count_vm_event(PGHOT_RECORD_HWHINTS);
		break;
	case PGHOT_PGTABLE_SCAN:
		count_vm_event(PGHOT_RECORD_PGTSCANS);
		break;
	case PGHOT_HINT_FAULT:
		count_vm_event(PGHOT_RECORD_HINTFAULTS);
		break;
	default:
		return -EINVAL;
	}

	/*
	 * Record only accesses from lower tiers.
	 */
	if (node_is_toptier(pfn_to_nid(pfn)))
		return 0;

	/*
	 * Reject the non-migratable pages right away.
	 */
	page = pfn_to_online_page(pfn);
	if (!page || is_zone_device_page(page))
		return 0;

	folio = page_folio(page);
	if (!folio_test_lru(folio))
		return 0;

	bkt = hash_min(pfn, phi_hash_order);
	spin_lock(&phi_hash[bkt].lock);
	phi = phi_lookup(pfn, bkt);
	if (!phi) {
		phi = phi_alloc(pfn);
		if (!phi)
			goto out;
		new_entry = true;
	}

	/*
	 * If the previous access was beyond the threshold window
	 * start frequency tracking afresh.
	 *
	 * Bypass the new window logic for NUMA hint fault source
	 * as it is too slow in reporting accesses.
	 * TODO: Fix this.
	 */
	if ((((cur_time - phi->last_update) > msecs_to_jiffies(sysctl_pghot_freq_window))
	    && (src != PGHOT_HINT_FAULT)) || (nid != NUMA_NO_NODE && phi->nid != nid))
		new_window = true;

	if (new_entry || new_window) {
		/* New window */
		phi->frequency = 1; /* TODO: Factor in the history */
	} else if (phi->frequency < PGHOT_FREQ_MAX)
		phi->frequency++;
	phi->last_update = cur_time;
	phi->nid = (nid == NUMA_NO_NODE) ? KPROMOTED_DEFAULT_NODE : nid;

	if (new_entry) {
		/* Insert the new entry into hash table */
		hlist_add_head(&phi->hnode, &phi_hash[bkt].hash);
		count_vm_event(PGHOT_RECORDS_HASH);
	} else {
		/* Add/update the position in heap */
		phi_heap_add_or_adjust(phi);
	}
out:
	spin_unlock(&phi_hash[bkt].lock);
	return 0;
}

/*
 * Extract the hot page records and batch-migrate the
 * hot pages.
 */
static void kpromoted_migrate(pg_data_t *pgdat)
{
	int count, ret;
	LIST_HEAD(migrate_list);

	/*
	 * Extract the top N elements from the heap that match
	 * the requested hotness threshold.
	 *
	 * PFNs ineligible from migration standpoint are removed
	 * from the heap and hash.
	 *
	 * Folios eligible for migration are isolated and returned
	 * in @migrate_list.
	 */
	ret = phi_heap_extract(pgdat, KPROMOTED_MIGRATE_BATCH,
			       KPROMOTED_FREQ_THRESHOLD, &migrate_list, &count);
	if (ret)
		return;

	if (!list_empty(&migrate_list))
		migrate_misplaced_folios_batch(&migrate_list, pgdat->node_id);
}

static int kpromoted(void *p)
{
	pg_data_t *pgdat = (pg_data_t *)p;

	while (!kthread_should_stop()) {
		wait_event_timeout(pgdat->kpromoted_wait, false,
				   msecs_to_jiffies(KPROMOTE_DELAY));
		kpromoted_migrate(pgdat);
	}
	return 0;
}

static int kpromoted_run(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	int ret = 0;

	if (!node_is_toptier(nid))
		return 0;

	if (!pgdat->phi_buf) {
		pgdat->phi_buf = vzalloc_node(phi_heap_entries * sizeof(struct pghot_info *),
					      nid);
		if (!pgdat->phi_buf)
			return -ENOMEM;

		min_heap_init(&pgdat->heap, pgdat->phi_buf, phi_heap_entries);
		spin_lock_init(&pgdat->heap_lock);
	}

	if (!pgdat->kpromoted)
		pgdat->kpromoted = kthread_create_on_node(kpromoted, pgdat, nid,
							  "kpromoted%d", nid);
	if (IS_ERR(pgdat->kpromoted)) {
		ret = PTR_ERR(pgdat->kpromoted);
		pgdat->kpromoted = NULL;
		pr_info("Failed to start kpromoted%d, ret %d\n", nid, ret);
	} else {
		wake_up_process(pgdat->kpromoted);
	}
	return ret;
}

/*
 * TODO: Handle cleanup during node offline.
 */
static int __init pghot_init(void)
{
	unsigned int hash_size;
	size_t hash_entries;
	size_t nr_pages = 0;
	pg_data_t *pgdat;
	int i, nid, ret;

	/*
	 * Arrive at the hash and heap sizes based on the
	 * number of pages present in the lower tier nodes.
	 */
	for_each_node_state(nid, N_MEMORY) {
		if (!node_is_toptier(nid))
			nr_pages += NODE_DATA(nid)->node_present_pages;
	}

	if (!nr_pages)
		return 0;

	hash_entries = nr_pages * PGHOT_HASH_PCT / 100;
	hash_size = hash_entries / PGHOT_HASH_ENTRIES;
	phi_hash_order = ilog2(hash_size);

	phi_hash = vmalloc(sizeof(struct pghot_hash) * hash_size);
	if (!phi_hash) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < hash_size; i++) {
		INIT_HLIST_HEAD(&phi_hash[i].hash);
		spin_lock_init(&phi_hash[i].lock);
	}

	phi_cache = KMEM_CACHE(pghot_info, 0);
	if (unlikely(!phi_cache)) {
		ret = -ENOMEM;
		goto out;
	}

	phi_heap_entries = hash_entries * PGHOT_HEAP_PCT / 100;
	for_each_node_state(nid, N_CPU) {
		ret = kpromoted_run(nid);
		if (ret)
			goto out_stop_kthread;
	}

	register_sysctl_init("vm", pghot_sysctls);
	kpromoted_started = true;
	pr_info("pghot: Started page hotness monitoring and promotion thread\n");
	pr_info("pghot: nr_pages %ld hash_size %d hash_entries %ld hash_order %d heap_entries %d\n",
	       nr_pages, hash_size, hash_entries, phi_hash_order, phi_heap_entries);
	return 0;

out_stop_kthread:
	for_each_node_state(nid, N_CPU) {
		pgdat = NODE_DATA(nid);
		if (pgdat->kpromoted) {
			kthread_stop(pgdat->kpromoted);
			pgdat->kpromoted = NULL;
			vfree(pgdat->phi_buf);
		}
	}
out:
	kmem_cache_destroy(phi_cache);
	vfree(phi_hash);
	return ret;
}

late_initcall(pghot_init)
