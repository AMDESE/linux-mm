/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PGHOT_H
#define _LINUX_PGHOT_H

#include <linux/types.h>

#ifdef CONFIG_HWMEM_PROFILER
bool hwmem_access_profiler_inuse(void);
void hwmem_access_profiling_start(void);
void hwmem_access_profiling_stop(void);
#else
static inline bool hwmem_access_profiler_inuse(void) { return false; }
static inline void hwmem_access_profiling_start(void) {}
static inline void hwmem_access_profiling_stop(void) {}
#endif

/* Page hotness temperature sources */
enum pghot_src {
	PGHOT_HW_HINTS,
	PGHOT_PGTABLE_SCAN,
	PGHOT_HINT_FAULT,
	PGHOT_FMA,
};

#ifdef CONFIG_PGHOT
#include <linux/static_key.h>

extern unsigned int pghot_target_nid;
extern unsigned int pghot_src_enabled;
extern unsigned int pghot_freq_threshold;
extern unsigned int kmigrated_sleep_ms;
extern unsigned int kmigrated_batch_nr;
extern unsigned int sysctl_pghot_freq_window;

void pghot_debug_init(void);

DECLARE_STATIC_KEY_FALSE(pghot_src_hwhints);
DECLARE_STATIC_KEY_FALSE(pghot_src_pgtscans);
DECLARE_STATIC_KEY_FALSE(pghot_src_hintfaults);
DECLARE_STATIC_KEY_FALSE(pghot_src_fma);

/*
 * Bit positions to enable individual sources in pghot/records_enabled
 * of debugfs.
 */
enum pghot_src_enabled {
	PGHOT_HWHINTS_BIT = 0,
	PGHOT_PGTSCAN_BIT,
	PGHOT_HINTFAULT_BIT,
	PGHOT_FMA_BIT,
	PGHOT_MAX_BIT
};

#define PGHOT_HWHINTS_ENABLED		BIT(PGHOT_HWHINTS_BIT)
#define PGHOT_PGTSCAN_ENABLED		BIT(PGHOT_PGTSCAN_BIT)
#define PGHOT_HINTFAULT_ENABLED		BIT(PGHOT_HINTFAULT_BIT)
#define PGHOT_SRC_ENABLED_MASK		GENMASK(PGHOT_MAX_BIT - 1, 0)
#define PGHOT_FMA_ENABLED		BIT(PGHOT_FMA_BIT)
#define PGHOT_SRC_ENABLED_MASK		GENMASK(PGHOT_MAX_BIT - 1, 0)

#define PGHOT_DEFAULT_FREQ_THRESHOLD	2

#define KMIGRATED_DEFAULT_SLEEP_MS	100
#define KMIGRATED_DEFAULT_BATCH_NR	512

#define PGHOT_DEFAULT_NODE		0

#if defined(CONFIG_PGHOT_PRECISE)
#define PGHOT_DEFAULT_FREQ_WINDOW	(5 * MSEC_PER_SEC)

/*
 * Bits 0-26 are used to store nid, frequency and time.
 * Bits 27-30 are unused now.
 * Bit 31 is used to indicate the page is ready for migration.
 */
#define PGHOT_MIGRATE_READY		31

#define PGHOT_NID_WIDTH			10
#define PGHOT_FREQ_WIDTH		3
/* time is stored in 14 bits which can represent up to 16s with HZ=1000 */
#define PGHOT_TIME_WIDTH		14

#define PGHOT_NID_SHIFT			0
#define PGHOT_FREQ_SHIFT		(PGHOT_NID_SHIFT + PGHOT_NID_WIDTH)
#define PGHOT_TIME_SHIFT		(PGHOT_FREQ_SHIFT + PGHOT_FREQ_WIDTH)

#define PGHOT_NID_MASK			GENMASK(PGHOT_NID_WIDTH - 1, 0)
#define PGHOT_FREQ_MASK			GENMASK(PGHOT_FREQ_WIDTH - 1, 0)
#define PGHOT_TIME_MASK			GENMASK(PGHOT_TIME_WIDTH - 1, 0)

#define PGHOT_NID_MAX			((1 << PGHOT_NID_WIDTH) - 1)
#define PGHOT_FREQ_MAX			((1 << PGHOT_FREQ_WIDTH) - 1)
#define PGHOT_TIME_MAX			((1 << PGHOT_TIME_WIDTH) - 1)

typedef u32 phi_t;

#else	/* !CONFIG_PGHOT_PRECISE */
#define PGHOT_DEFAULT_FREQ_WINDOW	(4 * MSEC_PER_SEC)

/*
 * Bits 0-6 are used to store frequency and time.
 * Bit 7 is used to indicate the page is ready for migration.
 */
#define PGHOT_MIGRATE_READY		7

#define PGHOT_FREQ_WIDTH		2
/* Bucketed time is stored in 5 bits which can represent up to 4s with HZ=1000 */
#define PGHOT_TIME_BUCKETS_WIDTH	7
#define PGHOT_TIME_WIDTH		5
#define PGHOT_NID_WIDTH			10

#define PGHOT_FREQ_SHIFT		0
#define PGHOT_TIME_SHIFT		(PGHOT_FREQ_SHIFT + PGHOT_FREQ_WIDTH)

#define PGHOT_FREQ_MASK			GENMASK(PGHOT_FREQ_WIDTH - 1, 0)
#define PGHOT_TIME_MASK			GENMASK(PGHOT_TIME_WIDTH - 1, 0)
#define PGHOT_TIME_BUCKETS_MASK		(PGHOT_TIME_MASK << PGHOT_TIME_BUCKETS_WIDTH)

#define PGHOT_NID_MAX			((1 << PGHOT_NID_WIDTH) - 1)
#define PGHOT_FREQ_MAX			((1 << PGHOT_FREQ_WIDTH) - 1)
#define PGHOT_TIME_MAX			((1 << PGHOT_TIME_WIDTH) - 1)

typedef u8 phi_t;
#endif /* CONFIG_PGHOT_PRECISE */

#define PGHOT_RECORD_SIZE		sizeof(phi_t)

#define PGHOT_SECTION_HOT_BIT		0
#define PGHOT_SECTION_HOT_MASK		BIT(PGHOT_SECTION_HOT_BIT)

unsigned long pghot_access_latency(unsigned long old_time, unsigned long time);
bool pghot_update_record(phi_t *phi, int nid, unsigned long now);
int pghot_get_record(phi_t *phi, int *nid, int *freq, unsigned long *time);

int pghot_record_access(unsigned long pfn, int nid, int src, unsigned long now);
#else
static inline int pghot_record_access(unsigned long pfn, int nid, int src, unsigned long now)
{
	return 0;
}
#endif /* CONFIG_PGHOT */
#endif /* _LINUX_PGHOT_H */
