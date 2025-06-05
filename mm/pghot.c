// SPDX-License-Identifier: GPL-2.0
/*
 * Maintains information about hot pages from slower tier nodes and
 * promotes them.
 *
 * Per-PFN hotness information is stored for lower tier nodes in
 * mem_section. An unsigned long variable is used to store the
 * frequency of access, last access time and the nid to which the
 * page needs to be migrated.
 *
 * A kernel thread named kmigrated is provided to migrate or promote
 * the hot pages. kmigrated runs for each lower tier node. It iterates
 * over the node's PFNs and  migrates pages marked for migration into
 * their targeted nodes.
 */
#include <linux/mm.h>
#include <linux/migrate.h>
#include <linux/memory-tiers.h>
#include <linux/cpuhotplug.h>
#include <linux/pghot.h>

static unsigned int sysctl_pghot_freq_window = PGHOT_FREQ_WINDOW;

/*
 * Sysctl tunables to selectively enable access recording from different
 * sources.
 */
static unsigned int sysctl_pghot_record_hwhints_enable;
static unsigned int sysctl_pghot_record_pgtscans_enable;
static unsigned int sysctl_pghot_record_hintfaults_enable;

static DEFINE_STATIC_KEY_FALSE(pghot_record_hwhints);
static DEFINE_STATIC_KEY_FALSE(pghot_record_pgtscans);
static DEFINE_STATIC_KEY_FALSE(pghot_record_hintfaults);

#ifdef CONFIG_SYSCTL
static int sysctl_record_enable_handler(const struct ctl_table *table, int write,
					void *buffer, size_t *lenp, loff_t *ppos)
{
	int err, val;

	err = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (err || !write)
		return err;

	val = *(int *)table->data;

	if (table->data == &sysctl_pghot_record_hwhints_enable) {
		if (val)
			static_branch_enable(&pghot_record_hwhints);
		else
			static_branch_disable(&pghot_record_hwhints);
	} else if (table->data == &sysctl_pghot_record_pgtscans_enable) {
		if (val)
			static_branch_enable(&pghot_record_pgtscans);
		else
			static_branch_disable(&pghot_record_pgtscans);
	} else if (table->data == &sysctl_pghot_record_hintfaults_enable) {
		if (val)
			static_branch_enable(&pghot_record_hintfaults);
		else
			static_branch_disable(&pghot_record_hintfaults);
	}
	return 0;
}

static const struct ctl_table pghot_sysctls[] = {
	{
		.procname       = "pghot_record_hwhints_enable",
		.data           = &sysctl_pghot_record_hwhints_enable,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = sysctl_record_enable_handler,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "pghot_record_pgtscans_enable",
		.data           = &sysctl_pghot_record_pgtscans_enable,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = sysctl_record_enable_handler,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "pghot_record_hintfaults_enable",
		.data           = &sysctl_pghot_record_hintfaults_enable,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = sysctl_record_enable_handler,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
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
 *
 * pghot_record_access - Record page accesses from lower tier memory
 * for the purpose of tracking page hotness and subsequent promotion.
 *
 * @pfn - PFN of the page
 * @nid - Target NID to were the page needs to be migrated
 * @src - The identifier of the sub-system that reports the access
 * @now - Access time in jiffies
 *
 * Updates the NID, frequency and time of access and marks the page as
 * ready for migration if the frequency crosses a threshold. The pages
 * marked for migration are migrated by kmigrated kernel thread.
 *
 * Return: 0 on success and -EAGAIN on failure to record the access.
 */
int pghot_record_access(unsigned long pfn, int nid, int src, unsigned long now)
{
	unsigned long time = now & PGHOT_TIME_MASK;
	unsigned long old_nid, old_freq, old_time;
	unsigned long *phi, old_hotness, hotness;
	bool new_window = false;
	struct mem_section *ms;
	struct folio *folio;
	struct page *page;
	unsigned long freq;

	if (!kmigrated_started)
		return -EINVAL;

	if (nid >= PGHOT_NID_MAX)
		return -EINVAL;

	count_vm_event(PGHOT_RECORDED_ACCESSES);
	switch (src) {
	case PGHOT_HW_HINTS:
		if (!static_branch_likely(&pghot_record_hwhints))
			return -EINVAL;
		count_vm_event(PGHOT_RECORD_HWHINTS);
		break;
	case PGHOT_PGTABLE_SCAN:
		if (!static_branch_likely(&pghot_record_pgtscans))
			return -EINVAL;
		count_vm_event(PGHOT_RECORD_PGTSCANS);
		break;
	case PGHOT_HINT_FAULT:
		if (!static_branch_likely(&pghot_record_hintfaults))
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
	if (!ms)
		return -EINVAL;
	phi = &ms->hot_map[pfn % PAGES_PER_SECTION];

	/*
	 * Update the hotness parameters.
	 */
	old_hotness = READ_ONCE(*phi);
	do {
		hotness = old_hotness;
		old_nid = (hotness >> PGHOT_NID_SHIFT) & PGHOT_NID_MASK;
		old_freq = (hotness >> PGHOT_FREQ_SHIFT) & PGHOT_FREQ_MASK;
		old_time = (hotness >> PGHOT_TIME_SHIFT) & PGHOT_TIME_MASK;

		if (((time - old_time) > msecs_to_jiffies(sysctl_pghot_freq_window))
		    || (nid != NUMA_NO_NODE && old_nid != nid))
			new_window = true;

		if (new_window)
			freq = 1;
		else if (old_freq < PGHOT_FREQ_MAX)
			freq = old_freq + 1;
		nid = (nid == NUMA_NO_NODE) ? PGHOT_DEFAULT_NODE : nid;

		hotness &= ~(PGHOT_NID_MASK << PGHOT_NID_SHIFT);
		hotness &= ~(PGHOT_FREQ_MASK << PGHOT_FREQ_SHIFT);
		hotness &= ~(PGHOT_TIME_MASK << PGHOT_TIME_SHIFT);

		hotness |= (nid & PGHOT_NID_MASK) << PGHOT_NID_SHIFT;
		hotness |= (freq & PGHOT_FREQ_MASK) << PGHOT_FREQ_SHIFT;
		hotness |= (time & PGHOT_TIME_MASK) << PGHOT_TIME_SHIFT;

		if (freq > PGHOT_FREQ_THRESHOLD)
			set_bit(PGHOT_MIGRATE_READY, &hotness);
	} while (unlikely(!try_cmpxchg(phi, &old_hotness, hotness)));

	if (test_bit(PGHOT_MIGRATE_READY, &hotness))
		set_bit(PGDAT_KMIGRATED_ACTIVATE, &page_pgdat(page)->flags);
	return 0;
}

static int pghot_get_hotness(unsigned long pfn, unsigned long *nid, unsigned long *freq,
				    unsigned long *time)
{
	unsigned long *phi, old_hotness, hotness;
	struct mem_section *ms;

	ms = __pfn_to_section(pfn);
	if (!ms)
		return -EINVAL;

	phi = &ms->hot_map[pfn % PAGES_PER_SECTION];
	if (!test_and_clear_bit(PGHOT_MIGRATE_READY, phi))
		return -EINVAL;

	old_hotness = READ_ONCE(*phi);
	do {
		hotness = old_hotness;
		*nid = (hotness >> PGHOT_NID_SHIFT) & PGHOT_NID_MASK;
		*freq = (hotness >> PGHOT_FREQ_SHIFT) & PGHOT_FREQ_MASK;
		*time = (hotness >> PGHOT_TIME_SHIFT) & PGHOT_TIME_MASK;
		hotness = 0;

	} while (unlikely(!try_cmpxchg(phi, &old_hotness, hotness)));
	return 0;
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
		unsigned long nid = NUMA_NO_NODE, freq = 0, time = 0, nr = 1;

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
			goto out_next;

		if (folio_nid(folio) == nid)
			goto out_next;

		if (migrate_misplaced_folio_prepare(folio, NULL, nid))
			goto out_next;

		if (cur_nid != NUMA_NO_NODE)
			cur_nid = nid;

		if (++batch_count >= KMIGRATE_BATCH || cur_nid != nid) {
			migrate_misplaced_folios_batch(&migrate_list, cur_nid);
			cur_nid = nid;
			batch_count = 0;
			cond_resched();
		}
		list_add(&folio->lru, &migrate_list);
out_next:
		pfn += nr;
	} while (pfn < end_pfn);
	if (!list_empty(&migrate_list))
		migrate_misplaced_folios_batch(&migrate_list, cur_nid);
}

static void kmigrated_do_work(pg_data_t *pgdat)
{
	struct zone *zone;
	int zone_idx;

	clear_bit(PGDAT_KMIGRATED_ACTIVATE, &pgdat->flags);
	for (zone_idx = 0; zone_idx < MAX_NR_ZONES; zone_idx++) {
		zone = &pgdat->node_zones[zone_idx];

		if (!populated_zone(zone))
			continue;

		if (zone_is_zone_device(zone))
			continue;

		kmigrated_walk_zone(zone->zone_start_pfn, zone_end_pfn(zone),
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
	long timeout = msecs_to_jiffies(KMIGRATE_DELAY_MS);
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

		ms->hot_map = kcalloc_node(PAGES_PER_SECTION, sizeof(*ms->hot_map), GFP_KERNEL,
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
