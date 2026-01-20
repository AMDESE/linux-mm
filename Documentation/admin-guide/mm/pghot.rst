.. SPDX-License-Identifier: GPL-2.0

================================================
pghot: Hot Page Tracking and Promotion Subsystem
================================================

Overview
========
The pghot subsystem tracks frequently accessed pages in lower-tier memory and
promotes them to faster tiers. It uses per-PFN hotness metadata and asynchronous
migration via per-node kernel threads (kmigrated).

This document describes tunables available via **debugfs** and **sysctl** for
pghot.

Debugfs Interface
=================
Path: /sys/kernel/debug/pghot/

1. **kmigrated_sleep_ms**
   - Sleep interval (ms) for kmigrated thread between scans.
   - Default: 100

2. **kmigrated_batch_nr**
   - Maximum number of folios migrated in one batch.
   - Default: 512

Sysctl Interface
================
1. pghot_enabled_sources

Path: /proc/sys/vm/pghot_enabled_sources

- Bitmask to enable/disable hotness sources.
- Bits:
  - 0: Hint faults (value 0x1)
  - 1: Hardware hints (value 0x2)
- Default: 0 (disabled)
- Example:
  # echo 0x3 > /proc/sys/vm/pghot_enabled_sources
  Enables both hint faults and hwhints sources

2. pghot_target_nid

Path: /proc/sys/vm/pghot_target_nid

- Toptier NUMA node ID to which hot pages should be promoted when source
  does not provide nid. Used when hotness source can't provide accessing
  NID or when the tracking mode is default.
- Default: 0
- The default (node 0) is only a best guess for the common case where node 0
  is a top tier node. In default mode, the promotion target is governed
  entirely by this tunable. So on topologies where node 0 is not a top tier
  node, the administrator must set this to a valid top tier node.
  Writes are validated to be an online top tier node; the boot-time default
  value is not.
- Example:
  # echo 1 > /proc/sys/vm/pghot_target_nid

3. pghot_freq_threshold

Path: /proc/sys/vm/pghot_freq_threshold

- Minimum access frequency before a page is marked ready for promotion.
  Range is 1 to 3 in default mode and 1 to 7 in precision mode.
- Default: 1
- Example:
  # sysctl vm.pghot_freq_threshold=2

4. pghot_promote_window_ms

Path: /proc/sys/vm/pghot_promote_window_ms

- Controls the time window (in ms) for counting access frequency. A page is
  considered hot only when **pghot_freq_threshold** number of accesses occur
  with this time period.
- Default: 3000 (3 seconds) in default mode and 5000 (5s) in precision mode.
- Example:
  # sysctl vm.pghot_promote_window_ms=3000

pghot Vmstat Counters
=====================
Following vmstat counters provide some stats about pghot subsystem.

Path: /proc/vmstat

1. **pghot_recorded_accesses**
   - Number of accesses that pghot recorded as worthy of action, i.e. the
     subset of reported accesses that passed pghot's filters (lower-tier
     source page, migratable LRU folio, etc.).

2. **pghot_reported_hintfaults**
   - Number of accesses reported to pghot by the NUMA Balancing hint-faults
     source, before pghot's filtering. Only a subset of these become
     recorded accesses (see pghot_recorded_accesses).

3. **pghot_reported_hwhints**
   - Number of accesses reported to pghot by the hwhints source, before
     pghot's filtering. Only a subset of these become recorded accesses.
