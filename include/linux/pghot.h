/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PGHOT_H
#define _LINUX_PGHOT_H

/* Page hotness temperature sources */
enum pghot_src {
	PGHOT_HW_HINTS,
	PGHOT_PGTABLE_SCAN,
	PGHOT_HINT_FAULT,
};

#ifdef CONFIG_PGHOT
#define PGHOT_FREQ_WINDOW	(5 * MSEC_PER_SEC)
#define PGHOT_FREQ_THRESHOLD	2

#define KMIGRATE_DELAY_MS	100
#define KMIGRATE_BATCH		512

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

#define KMIGRATED_MIGRATION_ADJUST_STEPS	16
#define KMIGRATED_PROMOTION_THRESHOLD_WINDOW	60000

int pghot_record_access(unsigned long pfn, int nid, int src, unsigned long now);
#else
static inline int pghot_record_access(unsigned long pfn, int nid, int src, unsigned long now)
{
	return 0;
}
#endif /* CONFIG_PGHOT */
#endif /* _LINUX_PGHOT_H */
