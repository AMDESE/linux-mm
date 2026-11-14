/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MIGRATE_MODE_H_INCLUDED
#define MIGRATE_MODE_H_INCLUDED

#include <linux/bits.h>
#include <linux/types.h>

/*
 * MIGRATE_ASYNC means never block
 * MIGRATE_SYNC_LIGHT in the current implementation means to allow blocking
 *	on most operations but not ->writepage as the potential stall time
 *	is too significant
 * MIGRATE_SYNC will block when migrating pages
 */
enum migrate_mode {
	MIGRATE_ASYNC,
	MIGRATE_SYNC_LIGHT,
	MIGRATE_SYNC,
};

enum migrate_reason {
	MR_COMPACTION,
	MR_MEMORY_FAILURE,
	MR_MEMORY_HOTPLUG,
	MR_SYSCALL,		/* also applies to cpusets */
	MR_MEMPOLICY_MBIND,
	MR_NUMA_MISPLACED,
	MR_CONTIG_RANGE,
	MR_LONGTERM_PIN,
	MR_DEMOTION,
	MR_DAMON,
	MR_NEVER,		/* page has never been migrated */
	MR_TYPES
};

/*
 * Behavior a migration request asks for that does not depend on how long
 * migration may block.  Each flag is honored by the migration core or by
 * ->migrate_folio(); behavior must not be derived from the reason instead.
 */
typedef unsigned int __bitwise migrate_flags_t;

/* Do not split a large folio when its destination cannot be allocated. */
#define MIGRATE_F_NO_SPLIT		((__force migrate_flags_t)BIT(0))
/* Retry that split in a later pass, rather than fail, on -EAGAIN. */
#define MIGRATE_F_RETRY_SPLIT		((__force migrate_flags_t)BIT(1))

/**
 * struct migrate_control - Policy for one migration request
 * @mode: How long migration may block.
 * @flags: Requested behavior, a combination of MIGRATE_F_* flags.
 * @reason: Why migration was requested.
 *
 * The caller builds this on its stack and the migration core passes it down
 * read-only.  Where the core runs a pass with a weaker @mode than requested,
 * it uses a copy with only @mode changed.
 */
struct migrate_control {
	enum migrate_mode mode;
	migrate_flags_t flags;
	enum migrate_reason reason;
};

#endif		/* MIGRATE_MODE_H_INCLUDED */
