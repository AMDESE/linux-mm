// SPDX-License-Identifier: GPL-2.0
/*
 * pghot: Default mode
 *
 * 1 byte hotness record per PFN.
 * Bucketed time and frequency tracked as part of the record.
 * Promotion to @sysctl_pghot_target_nid by default.
 */

#include <linux/pghot.h>
#include <linux/jiffies.h>

/* pghot-default doesn't store and hence no NID validation is required */
bool pghot_nid_valid(int nid)
{
	return true;
}

/*
 * @time is regular time, @old_time is bucketed time.
 */
unsigned long pghot_access_latency(unsigned long old_time, unsigned long time)
{
	time &= PGHOT_TIME_BUCKETS_MASK;
	old_time <<= PGHOT_TIME_BUCKETS_SHIFT;

	return jiffies_to_msecs((time - old_time) & PGHOT_TIME_BUCKETS_MASK);
}

bool pghot_update_record(phi_t *phi, int nid, unsigned long now)
{
	phi_t freq, old_freq, hotness, old_hotness, old_time;
	phi_t time = now >> PGHOT_TIME_BUCKETS_SHIFT;
	unsigned int promote_window = READ_ONCE(sysctl_pghot_promote_window);
	unsigned int freq_threshold = READ_ONCE(sysctl_pghot_freq_threshold);

	old_hotness = READ_ONCE(*phi);
	do {
		bool new_window = false;

		old_freq = (old_hotness >> PGHOT_FREQ_SHIFT) & PGHOT_FREQ_MASK;
		old_time = (old_hotness >> PGHOT_TIME_SHIFT) & PGHOT_TIME_MASK;

		if (pghot_access_latency(old_time, now) > promote_window)
			new_window = true;

		if (new_window)
			freq = 1;
		else if (old_freq < PGHOT_FREQ_MAX)
			freq = old_freq + 1;
		else
			freq = old_freq;

		hotness = 0;
		hotness |= (freq & PGHOT_FREQ_MASK) << PGHOT_FREQ_SHIFT;
		hotness |= (time & PGHOT_TIME_MASK) << PGHOT_TIME_SHIFT;

		if (freq >= freq_threshold)
			hotness |= BIT(PGHOT_MIGRATE_READY);
	} while (unlikely(!try_cmpxchg(phi, &old_hotness, hotness)));
	return !!(hotness & BIT(PGHOT_MIGRATE_READY));
}

/*
 * Consume the MIGRATE_READY signal (but keep freq/time) so a ready record is
 * counted as a promotion candidate only once per readiness epoch, restoring the
 * ~1:1 pgpromote_candidate accounting. The freq/time data is cleared only on
 * commit (pghot_clear_hotness()), so a folio that is skipped (rate limited,
 * wrong nid) or fails to isolate keeps its accumulated hotness and re-earns
 * readiness with a single in-window access instead of from scratch.
 */
int pghot_get_record(phi_t *phi, int *nid, int *freq, unsigned long *time)
{
	phi_t old_hotness = READ_ONCE(*phi), hotness;

	do {
		if (!(old_hotness & BIT(PGHOT_MIGRATE_READY)))
			return -EINVAL;
		hotness = old_hotness & ~BIT(PGHOT_MIGRATE_READY);
	} while (unlikely(!try_cmpxchg(phi, &old_hotness, hotness)));

	*nid = READ_ONCE(sysctl_pghot_target_nid);
	*freq = (old_hotness >> PGHOT_FREQ_SHIFT) & PGHOT_FREQ_MASK;
	*time = (old_hotness >> PGHOT_TIME_SHIFT) & PGHOT_TIME_MASK;
	return 0;
}
