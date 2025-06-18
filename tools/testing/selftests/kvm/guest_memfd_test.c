// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright Intel Corporation, 2023
 *
 * Author: Chao Peng <chao.p.peng@linux.intel.com>
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <numa.h>
#include <numaif.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#include <linux/bitmap.h>
#include <linux/falloc.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "kvm_util.h"
#include "test_util.h"

static void test_file_read_write(int fd)
{
	char buf[64];

	TEST_ASSERT(read(fd, buf, sizeof(buf)) < 0,
		    "read on a guest_mem fd should fail");
	TEST_ASSERT(write(fd, buf, sizeof(buf)) < 0,
		    "write on a guest_mem fd should fail");
	TEST_ASSERT(pread(fd, buf, sizeof(buf), 0) < 0,
		    "pread on a guest_mem fd should fail");
	TEST_ASSERT(pwrite(fd, buf, sizeof(buf), 0) < 0,
		    "pwrite on a guest_mem fd should fail");
}

static void test_mmap_supported(int fd, size_t page_size, size_t total_size)
{
	const char val = 0xaa;
	char *mem;
	size_t i;
	int ret;

	mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	TEST_ASSERT(mem == MAP_FAILED, "Copy-on-write not allowed by guest_memfd.");

	mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT(mem != MAP_FAILED, "mmap() for shared guest memory should succeed.");

	memset(mem, val, total_size);
	for (i = 0; i < total_size; i++)
		TEST_ASSERT_EQ(READ_ONCE(mem[i]), val);

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 0,
			page_size);
	TEST_ASSERT(!ret, "fallocate the first page should succeed.");

	for (i = 0; i < page_size; i++)
		TEST_ASSERT_EQ(READ_ONCE(mem[i]), 0x00);
	for (; i < total_size; i++)
		TEST_ASSERT_EQ(READ_ONCE(mem[i]), val);

	memset(mem, val, page_size);
	for (i = 0; i < total_size; i++)
		TEST_ASSERT_EQ(READ_ONCE(mem[i]), val);

	ret = munmap(mem, total_size);
	TEST_ASSERT(!ret, "munmap() should succeed.");
}

static sigjmp_buf jmpbuf;
void fault_sigbus_handler(int signum)
{
	siglongjmp(jmpbuf, 1);
}

static void test_fault_overflow(int fd, size_t page_size, size_t total_size)
{
	struct sigaction sa_old, sa_new = {
		.sa_handler = fault_sigbus_handler,
	};
	size_t map_size = total_size * 4;
	const char val = 0xaa;
	char *mem;
	size_t i;
	int ret;

	mem = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT(mem != MAP_FAILED, "mmap() for shared guest memory should succeed.");

	sigaction(SIGBUS, &sa_new, &sa_old);
	if (sigsetjmp(jmpbuf, 1) == 0) {
		memset(mem, 0xaa, map_size);
		TEST_ASSERT(false, "memset() should have triggered SIGBUS.");
	}
	sigaction(SIGBUS, &sa_old, NULL);

	for (i = 0; i < total_size; i++)
		TEST_ASSERT_EQ(READ_ONCE(mem[i]), val);

	ret = munmap(mem, map_size);
	TEST_ASSERT(!ret, "munmap() should succeed.");
}

static void test_mmap_not_supported(int fd, size_t page_size, size_t total_size)
{
	char *mem;

	mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT_EQ(mem, MAP_FAILED);

	mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT_EQ(mem, MAP_FAILED);
}

#define TEST_REQUIRE_NUMA_MULTIPLE_NODES()	\
	TEST_REQUIRE(numa_available() != -1 && numa_max_node() >= 1)

static void test_mbind(int fd, size_t page_size, size_t total_size)
{
	unsigned long nodemask = 1; /* nid: 0 */
	unsigned long maxnode = 8;
	unsigned long get_nodemask;
	int get_policy;
	char *mem;
	int ret;

	TEST_REQUIRE_NUMA_MULTIPLE_NODES();

	mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT(mem != MAP_FAILED, "mmap for mbind test should succeed");

	/* Test MPOL_INTERLEAVE policy */
	ret = syscall(__NR_mbind, mem, page_size * 2, MPOL_INTERLEAVE,
		      &nodemask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind with INTERLEAVE to node 0 should succeed");
	ret = syscall(__NR_get_mempolicy, &get_policy, &get_nodemask,
		      maxnode, mem, MPOL_F_ADDR);
	TEST_ASSERT(!ret && get_policy == MPOL_INTERLEAVE && get_nodemask == nodemask,
		    "Policy should be MPOL_INTERLEAVE and nodes match");

	/* Test basic MPOL_BIND policy */
	ret = syscall(__NR_mbind, mem + page_size * 2, page_size * 2, MPOL_BIND,
		      &nodemask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind with MPOL_BIND to node 0 should succeed");
	ret = syscall(__NR_get_mempolicy, &get_policy, &get_nodemask,
		      maxnode, mem + page_size * 2, MPOL_F_ADDR);
	TEST_ASSERT(!ret && get_policy == MPOL_BIND && get_nodemask == nodemask,
		    "Policy should be MPOL_BIND and nodes match");

	/* Test MPOL_DEFAULT policy */
	ret = syscall(__NR_mbind, mem, total_size, MPOL_DEFAULT, NULL, 0, 0);
	TEST_ASSERT(!ret, "mbind with MPOL_DEFAULT should succeed");
	ret = syscall(__NR_get_mempolicy, &get_policy, &get_nodemask,
		      maxnode, mem, MPOL_F_ADDR);
	TEST_ASSERT(!ret && get_policy == MPOL_DEFAULT && get_nodemask == 0,
		    "Policy should be MPOL_DEFAULT and nodes zero");

	/* Test with invalid policy */
	ret = syscall(__NR_mbind, mem, page_size, 999, &nodemask, maxnode, 0);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "mbind with invalid policy should fail with EINVAL");

	TEST_ASSERT(munmap(mem, total_size) == 0, "munmap should succeed");
}

static void test_numa_allocation(int fd, size_t page_size, size_t total_size)
{
	unsigned long node0_mask = 1;  /* Node 0 */
	unsigned long node1_mask = 2;  /* Node 1 */
	unsigned long maxnode = 8;
	void *pages[4];
	int status[4];
	char *mem;
	int ret, i;

	TEST_REQUIRE_NUMA_MULTIPLE_NODES();

	/* Clean slate: deallocate all file space, if any */
	ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, total_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) should succeed");

	mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT(mem != MAP_FAILED, "mmap should succeed");

	for (i = 0; i < 4; i++)
		pages[i] = (char *)mem + page_size * i;

	/* Set NUMA policy after allocation */
	memset(mem, 0xaa, page_size);
	ret = syscall(__NR_mbind, pages[0], page_size, MPOL_BIND, &node0_mask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind after allocation page 0 to node 0 should succeed");
	ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, page_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) should succeed");

	/* Set NUMA policy before allocation */
	ret = syscall(__NR_mbind, pages[0], page_size * 2, MPOL_BIND, &node1_mask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind page 0, 1 to node 1 should succeed");
	ret = syscall(__NR_mbind, pages[2], page_size * 2, MPOL_BIND, &node0_mask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind page 2, 3 to node 0 should succeed");
	memset(mem, 0xaa, total_size);

	/* Validate if pages are allocated on specified NUMA nodes */
	ret = syscall(__NR_move_pages, 0, 4, pages, NULL, status, 0);
	TEST_ASSERT(ret >= 0, "move_pages should succeed for status check");
	TEST_ASSERT(status[0] == 1, "Page 0 should be allocated on node 1");
	TEST_ASSERT(status[1] == 1, "Page 1 should be allocated on node 1");
	TEST_ASSERT(status[2] == 0, "Page 2 should be allocated on node 0");
	TEST_ASSERT(status[3] == 0, "Page 3 should be allocated on node 0");

	/* Punch hole for all pages */
	ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, total_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) should succeed");

	/* Change NUMA policy nodes and reallocate */
	ret = syscall(__NR_mbind, pages[0], page_size * 2, MPOL_BIND, &node0_mask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind page 0, 1 to node 0 should succeed");
	ret = syscall(__NR_mbind, pages[2], page_size * 2, MPOL_BIND, &node1_mask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind page 2, 3 to node 1 should succeed");
	memset(mem, 0xaa, total_size);

	ret = syscall(__NR_move_pages, 0, 4, pages, NULL, status, 0);
	TEST_ASSERT(ret >= 0, "move_pages should succeed after reallocation");
	TEST_ASSERT(status[0] == 0, "Page 0 should be allocated on node 0");
	TEST_ASSERT(status[1] == 0, "Page 1 should be allocated on node 0");
	TEST_ASSERT(status[2] == 1, "Page 2 should be allocated on node 1");
	TEST_ASSERT(status[3] == 1, "Page 3 should be allocated on node 1");

	TEST_ASSERT(munmap(mem, total_size) == 0, "munmap should succeed");
}

static void test_file_size(int fd, size_t page_size, size_t total_size)
{
	struct stat sb;
	int ret;

	ret = fstat(fd, &sb);
	TEST_ASSERT(!ret, "fstat should succeed");
	TEST_ASSERT_EQ(sb.st_size, total_size);
	TEST_ASSERT_EQ(sb.st_blksize, page_size);
}

static void test_fallocate(int fd, size_t page_size, size_t total_size)
{
	int ret;

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, total_size);
	TEST_ASSERT(!ret, "fallocate with aligned offset and size should succeed");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			page_size - 1, page_size);
	TEST_ASSERT(ret, "fallocate with unaligned offset should fail");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, total_size, page_size);
	TEST_ASSERT(ret, "fallocate beginning at total_size should fail");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, total_size + page_size, page_size);
	TEST_ASSERT(ret, "fallocate beginning after total_size should fail");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			total_size, page_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) at total_size should succeed");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			total_size + page_size, page_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) after total_size should succeed");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			page_size, page_size - 1);
	TEST_ASSERT(ret, "fallocate with unaligned size should fail");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			page_size, page_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) with aligned offset and size should succeed");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, page_size, page_size);
	TEST_ASSERT(!ret, "fallocate to restore punched hole should succeed");
}

static void test_invalid_punch_hole(int fd, size_t page_size, size_t total_size)
{
	struct {
		off_t offset;
		off_t len;
	} testcases[] = {
		{0, 1},
		{0, page_size - 1},
		{0, page_size + 1},

		{1, 1},
		{1, page_size - 1},
		{1, page_size},
		{1, page_size + 1},

		{page_size, 1},
		{page_size, page_size - 1},
		{page_size, page_size + 1},
	};
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(testcases); i++) {
		ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
				testcases[i].offset, testcases[i].len);
		TEST_ASSERT(ret == -1 && errno == EINVAL,
			    "PUNCH_HOLE with !PAGE_SIZE offset (%lx) and/or length (%lx) should fail",
			    testcases[i].offset, testcases[i].len);
	}
}

static void test_create_guest_memfd_invalid_sizes(struct kvm_vm *vm,
						  uint64_t guest_memfd_flags,
						  size_t page_size)
{
	size_t size;
	int fd;

	for (size = 1; size < page_size; size++) {
		fd = __vm_create_guest_memfd(vm, size, guest_memfd_flags);
		TEST_ASSERT(fd < 0 && errno == EINVAL,
			    "guest_memfd() with non-page-aligned page size '0x%lx' should fail with EINVAL",
			    size);
	}
}

static void test_create_guest_memfd_multiple(struct kvm_vm *vm)
{
	int fd1, fd2, ret;
	struct stat st1, st2;
	size_t page_size = getpagesize();

	fd1 = __vm_create_guest_memfd(vm, page_size, 0);
	TEST_ASSERT(fd1 != -1, "memfd creation should succeed");

	ret = fstat(fd1, &st1);
	TEST_ASSERT(ret != -1, "memfd fstat should succeed");
	TEST_ASSERT(st1.st_size == page_size, "memfd st_size should match requested size");

	fd2 = __vm_create_guest_memfd(vm, page_size * 2, 0);
	TEST_ASSERT(fd2 != -1, "memfd creation should succeed");

	ret = fstat(fd2, &st2);
	TEST_ASSERT(ret != -1, "memfd fstat should succeed");
	TEST_ASSERT(st2.st_size == page_size * 2, "second memfd st_size should match requested size");

	ret = fstat(fd1, &st1);
	TEST_ASSERT(ret != -1, "memfd fstat should succeed");
	TEST_ASSERT(st1.st_size == page_size, "first memfd st_size should still match requested size");
	TEST_ASSERT(st1.st_ino != st2.st_ino, "different memfd should have different inode numbers");

	close(fd2);
	close(fd1);
}

static bool check_vm_type(unsigned long vm_type)
{
	/*
	 * Not all architectures support KVM_CAP_VM_TYPES. However, those that
	 * support guest_memfd have that support for the default VM type.
	 */
	if (vm_type == VM_TYPE_DEFAULT)
		return true;

	return kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(vm_type);
}

static void test_with_type(unsigned long vm_type, uint64_t guest_memfd_flags,
			   bool expect_mmap_allowed)
{
	struct kvm_vm *vm;
	size_t total_size;
	size_t page_size;
	int fd;

	if (!check_vm_type(vm_type))
		return;

	page_size = getpagesize();
	total_size = page_size * 4;

	vm = vm_create_barebones_type(vm_type);

	test_create_guest_memfd_multiple(vm);
	test_create_guest_memfd_invalid_sizes(vm, guest_memfd_flags, page_size);

	fd = vm_create_guest_memfd(vm, total_size, guest_memfd_flags);

	test_file_read_write(fd);

	if (expect_mmap_allowed) {
		test_mmap_supported(fd, page_size, total_size);
		test_fault_overflow(fd, page_size, total_size);
		test_mbind(fd, page_size, total_size);
		test_numa_allocation(fd, page_size, total_size);
	} else {
		test_mmap_not_supported(fd, page_size, total_size);
	}

	test_file_size(fd, page_size, total_size);
	test_fallocate(fd, page_size, total_size);
	test_invalid_punch_hole(fd, page_size, total_size);

	close(fd);
	kvm_vm_free(vm);
}

static void test_vm_type_gmem_flag_validity(unsigned long vm_type,
					    uint64_t expected_valid_flags)
{
	size_t page_size = getpagesize();
	struct kvm_vm *vm;
	uint64_t flag = 0;
	int fd;

	if (!check_vm_type(vm_type))
		return;

	vm = vm_create_barebones_type(vm_type);

	for (flag = BIT(0); flag; flag <<= 1) {
		fd = __vm_create_guest_memfd(vm, page_size, flag);

		if (flag & expected_valid_flags) {
			TEST_ASSERT(fd >= 0,
				    "guest_memfd() with flag '0x%lx' should be valid",
				    flag);
			close(fd);
		} else {
			TEST_ASSERT(fd < 0 && errno == EINVAL,
				    "guest_memfd() with flag '0x%lx' should fail with EINVAL",
				    flag);
		}
	}

	kvm_vm_free(vm);
}

static void test_gmem_flag_validity(void)
{
	uint64_t non_coco_vm_valid_flags = 0;

	if (kvm_has_cap(KVM_CAP_GMEM_SHARED_MEM))
		non_coco_vm_valid_flags = GUEST_MEMFD_FLAG_SUPPORT_SHARED;

	test_vm_type_gmem_flag_validity(VM_TYPE_DEFAULT, non_coco_vm_valid_flags);

#ifdef __x86_64__
	test_vm_type_gmem_flag_validity(KVM_X86_SW_PROTECTED_VM, non_coco_vm_valid_flags);
	test_vm_type_gmem_flag_validity(KVM_X86_SEV_VM, 0);
	test_vm_type_gmem_flag_validity(KVM_X86_SEV_ES_VM, 0);
	test_vm_type_gmem_flag_validity(KVM_X86_SNP_VM, 0);
	test_vm_type_gmem_flag_validity(KVM_X86_TDX_VM, 0);
#endif
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_GUEST_MEMFD));

	test_gmem_flag_validity();

	test_with_type(VM_TYPE_DEFAULT, 0, false);
	if (kvm_has_cap(KVM_CAP_GMEM_SHARED_MEM)) {
		test_with_type(VM_TYPE_DEFAULT, GUEST_MEMFD_FLAG_SUPPORT_SHARED,
			       true);
	}

#ifdef __x86_64__
	test_with_type(KVM_X86_SW_PROTECTED_VM, 0, false);
	if (kvm_has_cap(KVM_CAP_GMEM_SHARED_MEM)) {
		test_with_type(KVM_X86_SW_PROTECTED_VM,
			       GUEST_MEMFD_FLAG_SUPPORT_SHARED, true);
	}
#endif
}
