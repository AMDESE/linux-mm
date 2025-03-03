/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PGHOT_H
#define _LINUX_PGHOT_H

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
};

#ifdef CONFIG_PGHOT
/*
 * Bit positions to enable individual sources in pghot/records_enabled
 * of debugfs.
 */
enum pghot_src_enabed {
	PGHOT_HWHINTS_BIT	= 0,
	PGHOT_PGTSCAN_BIT,
	PGHOT_HINTFAULT_BIT,
	PGHOT_MAX_BIT
};

#define PGHOT_HWHINTS_ENABLED	BIT(PGHOT_HWHINTS_BIT)
#define PGHOT_PGTSCAN_ENABLED	BIT(PGHOT_PGTSCAN_BIT)
#define PGHOT_HINTFAULT_ENABLED	BIT(PGHOT_HINTFAULT_BIT)
#define PGHOT_SRC_ENABLED_MASK	GENMASK(PGHOT_MAX_BIT - 1, 0)

#define PGHOT_DEFAULT_FREQ_WINDOW	(5 * MSEC_PER_SEC)
#define PGHOT_DEFAULT_FREQ_THRESHOLD	2

#define KMIGRATED_DEFAULT_SLEEP_MS	100
#define KMIGRATED_DEFAULT_BATCH_NR	512

#define PGHOT_DEFAULT_NODE	0

/*
 * Bits 0-31 are used to store nid, frequency and time.
 * Bits 32-62 are unused now.
 * Bit 63 is used to indicate the page is ready for migration.
 */
#define PGHOT_MIGRATE_READY	63

#define PGHOT_NID_WIDTH		10
#define PGHOT_FREQ_WIDTH	3
/* time is stored in 19 bits which can represent up to 8.73s with HZ=1000 */
#define PGHOT_TIME_WIDTH	19

#define PGHOT_NID_SHIFT		0
#define PGHOT_FREQ_SHIFT	(PGHOT_NID_SHIFT + PGHOT_NID_WIDTH)
#define PGHOT_TIME_SHIFT	(PGHOT_FREQ_SHIFT + PGHOT_FREQ_WIDTH)

#define PGHOT_NID_MASK		((1UL << PGHOT_NID_SHIFT) - 1)
#define PGHOT_FREQ_MASK		((1UL << PGHOT_FREQ_SHIFT) - 1)
#define PGHOT_TIME_MASK		((1UL << PGHOT_TIME_SHIFT) - 1)

#define PGHOT_NID_MAX		(1 << PGHOT_NID_WIDTH)
#define PGHOT_FREQ_MAX		(1 << PGHOT_FREQ_WIDTH)
#define PGHOT_TIME_MAX		(1 << PGHOT_TIME_WIDTH)

#define PGHOT_SECTION_HOT_BIT	BIT(0)
#define PGHOT_SECTION_HOT_MASK	GENMASK(PGHOT_SECTION_HOT_BIT - 1, 0)

int pghot_record_access(unsigned long pfn, int nid, int src, unsigned long now);
#else
static inline int pghot_record_access(unsigned long pfn, int nid, int src, unsigned long now)
{
	return 0;
}
#endif /* CONFIG_PGHOT */
#endif /* _LINUX_PGHOT_H */
