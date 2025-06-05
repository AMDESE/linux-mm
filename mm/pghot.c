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
 * A kernel thread named kmigrated is provided to migrate or promote
 * the hot pages. kmigrated runs for each lower tier node. It iterates
 * over the node's PFNs and  migrates pages marked for migration into
 * their targeted nodes.
 */
#include <linux/mm.h>
#include <linux/migrate.h>
#include <linux/memory-tiers.h>
#include <linux/pghot.h>

unsigned int pghot_target_nid = PGHOT_DEFAULT_NODE;
unsigned int pghot_src_enabled;
unsigned int pghot_freq_threshold = PGHOT_DEFAULT_FREQ_THRESHOLD;
unsigned int kmigrated_sleep_ms = KMIGRATED_DEFAULT_SLEEP_MS;
unsigned int kmigrated_batch_nr = KMIGRATED_DEFAULT_BATCH_NR;

unsigned int sysctl_pghot_freq_window = PGHOT_DEFAULT_FREQ_WINDOW;

DEFINE_STATIC_KEY_FALSE(pghot_src_hwhints);
DEFINE_STATIC_KEY_FALSE(pghot_src_pgtscans);
DEFINE_STATIC_KEY_FALSE(pghot_src_hintfaults);

#ifdef CONFIG_SYSCTL
static const struct ctl_table pghot_sysctls[] = {
	{
		.procname       = "pghot_promote_freq_window_ms",
		.data           = &sysctl_pghot_freq_window,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
	},
};
#endif

static bool kmigrated_started __ro_after_init;

/**
 * pghot_record_access() - Record page accesses from lower tier memory
 * for the purpose of tracking page hotness and subsequent promotion.
 *
 * @pfn: PFN of the page
 * @nid: Unused
 * @src: The identifier of the sub-system that reports the access
 * @now: Access time in jiffies
 *
 * Updates the frequency and time of access and marks the page as
 * ready for migration if the frequency crosses a threshold. The pages
 * marked for migration are migrated by kmigrated kernel thread.
 *
 * Return: 0 on success and -EINVAL on failure to record the access.
 */
int pghot_record_access(unsigned long pfn, int nid, int src, unsigned long now)
{
	struct mem_section *ms;
	struct folio *folio;
	phi_t *phi, *hot_map;
	struct page *page;

	if (!kmigrated_started)
		return -EINVAL;

	if (nid >= PGHOT_NID_MAX)
		return -EINVAL;

	switch (src) {
	case PGHOT_HW_HINTS:
		if (!static_branch_likely(&pghot_src_hwhints))
			return -EINVAL;
		count_vm_event(PGHOT_RECORD_HWHINTS);
		break;
	case PGHOT_PGTABLE_SCAN:
		if (!static_branch_likely(&pghot_src_pgtscans))
			return -EINVAL;
		count_vm_event(PGHOT_RECORD_PGTSCANS);
		break;
	case PGHOT_HINT_FAULT:
		if (!static_branch_likely(&pghot_src_hintfaults))
			return -EINVAL;
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

	/* Get the hotness slot corresponding to the 1st PFN of the folio */
	pfn = folio_pfn(folio);
	ms = __pfn_to_section(pfn);
	if (!ms || !ms->hot_map)
		return -EINVAL;

	hot_map = (phi_t *)(((unsigned long)(ms->hot_map)) & ~PGHOT_SECTION_HOT_MASK);
	phi = &hot_map[pfn % PAGES_PER_SECTION];

	count_vm_event(PGHOT_RECORDED_ACCESSES);

	/*
	 * Update the hotness parameters.
	 */
	if (pghot_update_record(phi, nid, now)) {
		set_bit(PGHOT_SECTION_HOT_BIT, (unsigned long *)&ms->hot_map);
		set_bit(PGDAT_KMIGRATED_ACTIVATE, &page_pgdat(page)->flags);
	}
	return 0;
}

static int pghot_get_hotness(unsigned long pfn, int *nid, int *freq,
			     unsigned long *time)
{
	phi_t *phi, *hot_map;
	struct mem_section *ms;

	ms = __pfn_to_section(pfn);
	if (!ms || !ms->hot_map)
		return -EINVAL;

	hot_map = (phi_t *)(((unsigned long)(ms->hot_map)) & ~PGHOT_SECTION_HOT_MASK);
	phi = &hot_map[pfn % PAGES_PER_SECTION];

	return pghot_get_record(phi, nid, freq, time);
}

/*
 * Walks the PFNs of the zone, isolates and migrates them in batches.
 */
static void kmigrated_walk_zone(unsigned long start_pfn, unsigned long end_pfn,
				int src_nid)
{
	int cur_nid = NUMA_NO_NODE;
	LIST_HEAD(migrate_list);
	int batch_count = 0;
	struct folio *folio;
	struct page *page;
	unsigned long pfn;

	pfn = start_pfn;
	do {
		int nid = NUMA_NO_NODE, nr = 1;
		int freq = 0;
		unsigned long time = 0;

		if (!pfn_valid(pfn))
			goto out_next;

		page = pfn_to_online_page(pfn);
		if (!page)
			goto out_next;

		folio = page_folio(page);
		nr = folio_nr_pages(folio);
		if (folio_nid(folio) != src_nid)
			goto out_next;

		if (!folio_test_lru(folio))
			goto out_next;

		if (pghot_get_hotness(pfn, &nid, &freq, &time))
			goto out_next;

		if (nid == NUMA_NO_NODE)
			nid = pghot_target_nid;

		if (folio_nid(folio) == nid)
			goto out_next;

		if (migrate_misplaced_folio_prepare(folio, NULL, nid))
			goto out_next;

		if (cur_nid == NUMA_NO_NODE)
			cur_nid = nid;

		/* If NID changed, flush the previous batch first */
		if (cur_nid != nid) {
			if (!list_empty(&migrate_list))
				migrate_misplaced_folios_batch(&migrate_list, cur_nid);
			cur_nid = nid;
			batch_count = 0;
			cond_resched();
		}

		list_add(&folio->lru, &migrate_list);

		if (++batch_count > kmigrated_batch_nr) {
			migrate_misplaced_folios_batch(&migrate_list, cur_nid);
			batch_count = 0;
			cond_resched();
		}
out_next:
		pfn += nr;
	} while (pfn < end_pfn);
	if (!list_empty(&migrate_list))
		migrate_misplaced_folios_batch(&migrate_list, cur_nid);
}

static void kmigrated_do_work(pg_data_t *pgdat)
{
	unsigned long section_nr, s_begin, start_pfn;
	struct mem_section *ms;
	int nid;

	clear_bit(PGDAT_KMIGRATED_ACTIVATE, &pgdat->flags);
	/* s_begin = first_present_section_nr(); */
	s_begin = next_present_section_nr(-1);
	for_each_present_section_nr(s_begin, section_nr) {
		start_pfn = section_nr_to_pfn(section_nr);
		ms = __nr_to_section(section_nr);

		if (!pfn_valid(start_pfn))
			continue;

		nid = pfn_to_nid(start_pfn);
		if (node_is_toptier(nid) || nid != pgdat->node_id)
			continue;

		if (!test_and_clear_bit(PGHOT_SECTION_HOT_BIT, (unsigned long *)&ms->hot_map))
			continue;

		kmigrated_walk_zone(start_pfn, start_pfn + PAGES_PER_SECTION,
				    pgdat->node_id);
	}
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
	long timeout = msecs_to_jiffies(kmigrated_sleep_ms);
	pg_data_t *pgdat = p;

	while (!kthread_should_stop()) {
		if (wait_event_timeout(pgdat->kmigrated_wait, kmigrated_work_requested(pgdat),
				       timeout))
			kmigrated_do_work(pgdat);
	}
	return 0;
}

static int kmigrated_run(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	int ret;

	if (node_is_toptier(nid))
		return 0;

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

static void pghot_free_hot_map(void)
{
	unsigned long section_nr, s_begin;
	struct mem_section *ms;

	/* s_begin = first_present_section_nr(); */
	s_begin = next_present_section_nr(-1);
	for_each_present_section_nr(s_begin, section_nr) {
		ms = __nr_to_section(section_nr);
		kfree(ms->hot_map);
	}
}

static int pghot_alloc_hot_map(void)
{
	unsigned long section_nr, s_begin, start_pfn;
	struct mem_section *ms;
	int nid;

	/* s_begin = first_present_section_nr(); */
	s_begin = next_present_section_nr(-1);
	for_each_present_section_nr(s_begin, section_nr) {
		ms = __nr_to_section(section_nr);
		start_pfn = section_nr_to_pfn(section_nr);
		nid = pfn_to_nid(start_pfn);

		if (node_is_toptier(nid) || !pfn_valid(start_pfn))
			continue;

		ms->hot_map = kcalloc_node(PAGES_PER_SECTION, PGHOT_RECORD_SIZE, GFP_KERNEL,
					   nid);
		if (!ms->hot_map)
			goto out_free_hot_map;
	}
	return 0;

out_free_hot_map:
	pghot_free_hot_map();
	return -ENOMEM;
}

static int __init pghot_init(void)
{
	pg_data_t *pgdat;
	int nid, ret;

	ret = pghot_alloc_hot_map();
	if (ret)
		return ret;

	for_each_node_state(nid, N_MEMORY) {
		ret = kmigrated_run(nid);
		if (ret)
			goto out_stop_kthread;
	}
	register_sysctl_init("vm", pghot_sysctls);
	pghot_debug_init();

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
	pghot_free_hot_map();
	return ret;
}

late_initcall_sync(pghot_init)
