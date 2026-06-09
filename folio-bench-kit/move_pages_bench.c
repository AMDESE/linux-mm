// SPDX-License-Identifier: GPL-2.0
/*
 * move_pages_bench - end-to-end page migration throughput via move_pages(2).
 *
 * Allocates an anonymous region (THP-encouraged), faults it in, then
 * migrates it back and forth between two NUMA nodes with move_pages(2),
 * timing each migration and reporting GB/s.
 *
 * No libnuma dependency: move_pages(2) is called via syscall().
 *
 *   cc -O2 -o move_pages_bench move_pages_bench.c
 *   ./move_pages_bench [size_MB] [node_a] [node_b] [iters]
 *   ./move_pages_bench 1024 0 1 10
 *
 * Defaults: size_MB=512, node_a=0, node_b=1, iters=10.
 *
 * Note: to exercise large folios, ensure THP is enabled, e.g.
 *   echo always > /sys/kernel/mm/transparent_hugepage/enabled
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#ifndef MPOL_MF_MOVE
#define MPOL_MF_MOVE	(1 << 1)	/* from <numaif.h> / linux/mempolicy.h */
#endif

static long move_pages_sys(int pid, unsigned long count, void **pages,
			   const int *nodes, int *status, int flags)
{
	return syscall(__NR_move_pages, pid, count, pages, nodes, status, flags);
}

static double now_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	size_t size_mb = argc > 1 ? strtoul(argv[1], NULL, 0) : 512;
	int node_a     = argc > 2 ? atoi(argv[2]) : 0;
	int node_b     = argc > 3 ? atoi(argv[3]) : 1;
	int iters      = argc > 4 ? atoi(argv[4]) : 10;

	long page_sz = sysconf(_SC_PAGESIZE);
	size_t size = size_mb << 20;
	size_t nr = size / page_sz;
	void **pages;
	int *nodes, *status;
	char *region;
	double gbps_sum = 0;
	int it, target = node_b;

	printf("size=%zuMB page_sz=%ldKB nr_pages=%zu node_a=%d node_b=%d iters=%d\n",
	       size_mb, page_sz >> 10, nr, node_a, node_b, iters);

	region = mmap(NULL, size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	madvise(region, size, MADV_HUGEPAGE);
	memset(region, 0xab, size);		/* fault everything in */

	pages  = calloc(nr, sizeof(*pages));
	nodes  = calloc(nr, sizeof(*nodes));
	status = calloc(nr, sizeof(*status));
	if (!pages || !nodes || !status) {
		perror("calloc");
		return 1;
	}

	/* Place the whole region on node_a first. */
	for (size_t i = 0; i < nr; i++) {
		pages[i] = region + i * page_sz;
		nodes[i] = node_a;
	}
	if (move_pages_sys(0, nr, pages, nodes, status, MPOL_MF_MOVE) < 0)
		perror("move_pages (initial placement)");

	for (it = 0; it < iters; it++) {
		double t0, t1, gbps;
		long ret;
		size_t ok = 0;

		for (size_t i = 0; i < nr; i++)
			nodes[i] = target;

		t0 = now_sec();
		ret = move_pages_sys(0, nr, pages, nodes, status, MPOL_MF_MOVE);
		t1 = now_sec();
		if (ret < 0) {
			perror("move_pages");
			break;
		}

		for (size_t i = 0; i < nr; i++)
			if (status[i] == target)
				ok++;

		gbps = (double)size / (t1 - t0) / 1e9;
		gbps_sum += gbps;
		printf("iter=%2d -> node %d  %.3f GB/s  (%zu/%zu pages on target)\n",
		       it, target, gbps, ok, nr);

		target = (target == node_a) ? node_b : node_a;
	}

	if (iters > 0)
		printf("mean: %.3f GB/s\n", gbps_sum / iters);

	free(pages);
	free(nodes);
	free(status);
	munmap(region, size);
	return 0;
}
