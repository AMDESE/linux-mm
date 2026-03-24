// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt)	"amd_ibs_memprof: " fmt

#include <linux/init.h>
#include <linux/pghot.h>
#include <linux/percpu.h>
#include <linux/workqueue.h>
#include <linux/mm.h>
#include <linux/vm_event_item.h>
#include <linux/vmstat.h>
#include <linux/cpuhotplug.h>
#include <linux/syscore_ops.h>

#include <asm/ibs-mprof.h>
#include <asm/ibs-caps.h>
#include <asm/irq_vectors.h>
#include <asm/idtentry.h>
#include <asm/apic.h>
#include <asm/cpuid/api.h>

#define IBS_NR_SAMPLES		150	/* Percpu sample buffer size */

static DEFINE_PER_CPU(bool, mprof_work_pending);

/*
 * Basic access info captured for each memory access.
 */
struct mprof_sample {
	unsigned long pfn;
	unsigned long time;	/* jiffies when accessed */
	int nid;		/* Accessing node ID, if known */
};

/*
 * Percpu buffer of access samples. Samples are accumulated here
 * before pushing them to pghot sub-system for further action.
 */
struct mprof_sample_pcpu {
	struct mprof_sample samples[IBS_NR_SAMPLES];
	int head, tail;
};

static struct mprof_sample_pcpu __percpu *mprof_s;

/*
 * Per-CPU work for pushing the percpu access samples to pghot sub-system.
 *
 * @cpu records which CPU's sample ring this work item is responsible for
 * draining.
 */
struct mprof_worker {
	struct work_struct work;
	unsigned int cpu;
};
static DEFINE_PER_CPU(struct mprof_worker, mprof_work);
static int mprof_cpuhp_state = CPUHP_INVALID;

/*
 * Record the IBS-reported access sample in percpu buffer.
 * Called from IBS interrupt handler.
 */
static bool mprof_push_sample(unsigned long pfn, int nid, unsigned long time)
{
	struct mprof_sample_pcpu *pcpu = raw_cpu_ptr(mprof_s);
	int head = READ_ONCE(pcpu->head);
	int tail = READ_ONCE(pcpu->tail);
	int next = head + 1;

	if (next >= IBS_NR_SAMPLES)
		next = 0;

	if (next == tail) {
		count_vm_event(HWHINT_DROPPED_EVENTS);
		return false;
	}

	pcpu->samples[head].pfn = pfn;
	pcpu->samples[head].time = time;
	pcpu->samples[head].nid = nid;

	/*
	 * Publish the sample slot stores before advancing head; pairs
	 * with the smp_load_acquire() of head in mprof_pop_sample().
	 */
	smp_store_release(&pcpu->head, next);
	return true;
}

static bool mprof_pop_sample(struct mprof_sample_pcpu *pcpu, struct mprof_sample *s)
{
	int tail = READ_ONCE(pcpu->tail);
	/*
	 * Pairs with the smp_store_release() of head in mprof_push_sample();
	 * ensures the sample slot stores are visible before we read the slot.
	 */
	int head = smp_load_acquire(&pcpu->head);
	int next = tail + 1;

	if (head == tail)
		return false;

	if (next >= IBS_NR_SAMPLES)
		next = 0;

	*s = pcpu->samples[tail];

	/*
	 * Publish the freed slot via tail with release semantics so the plain
	 * sample read above cannot be reordered past it. The ring's one-empty-
	 * slot invariant already keeps the producer from ever writing the slot
	 * being read, so this is not strictly required on x86; it makes the
	 * ordering explicit and symmetric with the head release/acquire, at no
	 * runtime cost (compiler barrier only).
	 */
	smp_store_release(&pcpu->tail, next);
	return true;
}

/*
 * Drain any samples remaining in @cpu's ring into pghot. Called from the
 * cpuhp offline callback after flush_work(), with the producer silenced.
 */
static void mprof_drain_ring(unsigned int cpu)
{
	struct mprof_sample_pcpu *pcpu = per_cpu_ptr(mprof_s, cpu);
	struct mprof_sample s;

	while (mprof_pop_sample(pcpu, &s))
		pghot_record_access(s.pfn, s.nid, PGHOT_HWHINTS, s.time);
}

/*
 * Remove access samples from percpu buffer and send them
 * to pghot sub-system for further action.
 */
static void mprof_work_handler(struct work_struct *work)
{
	struct mprof_worker *mw = container_of(work, struct mprof_worker, work);
	unsigned int cpu = mw->cpu;
	struct mprof_sample_pcpu *pcpu = per_cpu_ptr(mprof_s, cpu);
	struct mprof_sample s;

	for (;;) {
		while (mprof_pop_sample(pcpu, &s))
			pghot_record_access(s.pfn, s.nid, PGHOT_HWHINTS,
					    s.time);

		/*
		 * Publish the cleared pending flag before re-checking the
		 * ring so a racing IRQ cannot leave a just-pushed sample
		 * unprocessed.
		 */
		WRITE_ONCE(per_cpu(mprof_work_pending, cpu), false);

		if (READ_ONCE(pcpu->head) == READ_ONCE(pcpu->tail))
			return;

		/*
		 * A sample was pushed after we exited the drain loop; the
		 * producer may have skipped re-queuing because pending was
		 * still set. Keep draining until the ring is observably empty
		 * with pending cleared.
		 */
	}
}

/*
 * L3MissOnly + Exclude kernel RIP
 */
static void mprof_enable_profiling(void)
{
	u64 mprof_config = IBS_MPROF_CTL_CNT_CTL | IBS_MPROF_CTL_L3MISSONLY;
	unsigned int period = IBS_MPROF_SAMPLE_PERIOD;
	u64 ctl, ctl2;

	/*
	 * Assemble bits 26:20 and 19:4 of periodic op counter in ctl.
	 * The lower 4 bits are always 0000b.
	 */
	ctl = (period >> 4) & IBS_MPROF_CTL_MAXCNT_MASK;
	ctl |= (period & IBS_MPROF_CTL_MAXCNT_EXT_MASK);
	ctl |= mprof_config;
	wrmsrq(MSR_AMD64_IBS_MPROF_CTL, ctl);

	/*
	 * Exclude samples that have bit 63 of their RIP set.
	 */
	ctl2 = IBS_MPROF_CTL2_EXCLUDE_KERNEL;
	wrmsrq(MSR_AMD64_IBS_MPROF_CTL2, ctl2);
}

static void mprof_disable_profiling(u64 mem_ctl)
{
	mem_ctl &= ~IBS_MPROF_CTL_ENABLE;
	mem_ctl &= ~IBS_MPROF_CTL_VAL;
	wrmsrq(MSR_AMD64_IBS_MPROF_CTL, mem_ctl);

	wrmsrq(MSR_AMD64_IBS_MPROF_CTL2, IBS_MPROF_CTL2_DISABLE);
}

/*
 * IBS interrupt handler: Process the memory access info reported by IBS.
 *
 * Reads the MSRs to collect all the information about the reported
 * memory access, validates the access, stores the valid sample and
 * schedules the work on this CPU to further process the sample.
 */
static void mprof_overflow_handler(void)
{
	u64 mem_ctl, mem_data3, mem_data2, paddr, data_src;
	struct work_struct *w = &this_cpu_ptr(&mprof_work)->work;
	unsigned long pfn;
	struct page *page;

	rdmsrq(MSR_AMD64_IBS_MPROF_CTL, mem_ctl);
	if (!(mem_ctl & IBS_MPROF_CTL_VAL))
		return;

	mprof_disable_profiling(mem_ctl);
	count_vm_event(HWHINT_TOTAL_EVENTS);

	rdmsrq(MSR_AMD64_IBS_MPROF_DATA3, mem_data3);

	/* Data source is valid only if the sample isn't an L1 or L2 hit */
	if (!(mem_data3 & (IBS_MPROF_DATA3_DCMISS | IBS_MPROF_DATA3_L2MISS))) {
		count_vm_event(HWHINT_CACHE_ACCESSES);
	} else {
		rdmsrq(MSR_AMD64_IBS_MPROF_DATA2, mem_data2);
		data_src = mem_data2 & IBS_MPROF_DATA2_DATASRC_MASK;
		data_src |= ((mem_data2 & IBS_MPROF_DATA2_DATASRC_MASK_HIGH) >>
				IBS_MPROF_DATA2_DATASRC_MASK_HIGH_SHIFT);

		switch (data_src) {
		case IBS_MPROF_DATA2_DATASRC_DRAM:
		case IBS_MPROF_DATA2_DATASRC_DRAM_FAR:
			/* local and remote DRAM are both DRAM accesses */
			count_vm_event(HWHINT_DRAM_ACCESSES);
			break;
		case IBS_MPROF_DATA2_DATASRC_EXT_MEM:
			count_vm_event(HWHINT_EXTMEM_ACCESSES);
			break;
		}
	}

	/* Is linear addr valid? */
	if (!(mem_data3 & IBS_MPROF_DATA3_LADDR_VALID))
		goto handled;

	/* Is phys addr valid? */
	if (!(mem_data3 & IBS_MPROF_DATA3_PADDR_VALID))
		goto handled;
	rdmsrq(MSR_AMD64_IBS_MPROF_PHYADDR, paddr);

	pfn = PHYS_PFN(paddr);
	page = pfn_to_online_page(pfn);
	if (!page)
		goto handled;

	/*
	 * Use the accessing CPU's node as the migration target. On
	 * topologies where all CPUs reside on toptier nodes (the common
	 * case), this is the desired behaviour.
	 */
	if (!mprof_push_sample(pfn, numa_node_id(), jiffies))
		goto handled;

	if (!this_cpu_read(mprof_work_pending)) {
		this_cpu_write(mprof_work_pending, true);
		schedule_work_on(smp_processor_id(), w);
	}
	count_vm_event(HWHINT_USEFUL_EVENTS);

handled:
	mprof_enable_profiling();
}

DEFINE_IDTENTRY_SYSVEC(sysvec_ibs_memprof)
{
	inc_irq_stat(IBS_MEMPROF);
	mprof_overflow_handler();
	apic_eoi();
}

static int get_mprof_lvt_offset(void)
{
	u64 val;

	rdmsrq(MSR_AMD64_IBSCTL, val);
	if (!(val & IBSCTL_MPROF_LVT_OFFSET_VALID))
		return -EINVAL;

	return (val & IBSCTL_MPROF_LVT_OFFSET_MASK) >>
		IBSCTL_MPROF_LVT_OFFSET_SHIFT;
}

/*
 * Confirm the IBS memory-profiler extended-LVT offset is valid and routable,
 * mirroring the perf IBS driver's ibs_eilvt_valid(). The trial uses mask=1 so
 * it programs nothing that can fire; the per-CPU startup callback unmasks it
 * later. setup_APIC_eilvt() touches the local APIC, so this must run with
 * preemption disabled.
 */
static bool mprof_eilvt_valid(void)
{
	int offset;
	bool valid = false;

	preempt_disable();

	offset = get_mprof_lvt_offset();
	if (offset < 0)
		goto out;

	if (!setup_APIC_eilvt(offset, IBS_MEMPROF_VECTOR, APIC_DELIVERY_MODE_FIXED, 1))
		valid = true;
out:
	preempt_enable();
	return valid;
}

/*
 * Arm the memory profiler on the current CPU: route the extended-LVT entry
 * to IBS_MEMPROF_VECTOR and program IBS from the published config snapshot.
 * Runs on the target CPU (cpuhp ONLINE callback and syscore resume).
 */
static int mprof_arm_cpu(void)
{
	int offset = get_mprof_lvt_offset();

	if (offset < 0) {
		pr_warn("offset not valid on cpu #%d\n", smp_processor_id());
		return -ENODEV;
	}

	if (setup_APIC_eilvt(offset, IBS_MEMPROF_VECTOR, APIC_DELIVERY_MODE_FIXED, 0)) {
		pr_warn("APIC setup failed on cpu #%d\n", smp_processor_id());
		return -EBUSY;
	}

	mprof_enable_profiling();
	return 0;
}

/*
 * Disarm the memory profiler on the current CPU: mask the extended-LVT entry
 * (silences the producer) and clear the IBS enable/valid bits.
 */
static void mprof_disarm_cpu(void)
{
	int offset = get_mprof_lvt_offset();
	u64 mem_ctl;

	if (offset >= 0)
		setup_APIC_eilvt(offset, IBS_MEMPROF_VECTOR, APIC_DELIVERY_MODE_FIXED, 1);

	rdmsrq(MSR_AMD64_IBS_MPROF_CTL, mem_ctl);
	mprof_disable_profiling(mem_ctl);
}

static int x86_amd_ibs_mprof_online(unsigned int cpu)
{
	/*
	 * If profiler can't be armed, that must not stop
	 * CPU online. Hence ignoring the return value of
	 * mprof_arm_cpu().
	 */
	mprof_arm_cpu();
	return 0;
}

static int x86_amd_ibs_mprof_offline(unsigned int cpu)
{
	struct mprof_worker *mw = per_cpu_ptr(&mprof_work, cpu);

	WARN_ON(cpu != smp_processor_id());

	/*
	 * The teardown callback runs on this CPU before
	 * CPUHP_AP_WORKQUEUE_ONLINE offline, while this CPU's worker is still
	 * per-CPU bound. Silence the producer, flush the pending worker, then
	 * drain any remaining ring samples synchronously.
	 */
	local_irq_disable();
	mprof_disarm_cpu();
	local_irq_enable();
	flush_work(&mw->work);
	mprof_drain_ring(cpu);
	WRITE_ONCE(per_cpu(mprof_work_pending, cpu), false);

	return 0;
}

#ifdef CONFIG_PM
/*
 * The local APIC does not preserve the extended-LVT registers across S3/S4
 * (lapic_suspend()/lapic_resume() save only the architectural LVTs), and the
 * boot CPU never re-runs the cpuhp ONLINE callback on resume. Re-arm it via
 * syscore so the profiler survives suspend/resume; secondary CPUs are handled
 * by their offline/online cpuhp callbacks.
 */
static int mprof_suspend(void *data)
{
	mprof_disarm_cpu();
	return 0;
}

static void mprof_resume(void *data)
{
	mprof_arm_cpu();
}

static const struct syscore_ops mprof_syscore_ops = {
	.resume		= mprof_resume,
	.suspend	= mprof_suspend,
};

static struct syscore mprof_syscore = {
	.ops = &mprof_syscore_ops,
};

static void mprof_pm_init(void)
{
	register_syscore(&mprof_syscore);
}
#else
static void mprof_pm_init(void) {}
#endif

static int __init mprof_access_profiling_init(void)
{
	u32 mprof_caps;
	int cpu, ret;

	if (!boot_cpu_has(X86_FEATURE_IBS))
		return -ENODEV;

	mprof_caps = cpuid_eax(IBS_CPUID_FEATURES);
	if (!(mprof_caps & IBS_CAPS_MEM_PROFILER)) {
		pr_info("capability is unavailable for access profiling\n");
		return -ENODEV;
	}

	/*
	 * Don't initialize the profiler if EILVT offset can't be armed.
	 */
	if (!mprof_eilvt_valid()) {
		pr_info("extended-LVT offset unavailable; access profiling disabled\n");
		return -EINVAL;
	}

	mprof_s = alloc_percpu_gfp(struct mprof_sample_pcpu, GFP_KERNEL | __GFP_ZERO);
	if (!mprof_s)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		struct mprof_worker *mw = per_cpu_ptr(&mprof_work, cpu);

		INIT_WORK(&mw->work, mprof_work_handler);
		mw->cpu = cpu;
	}

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				"x86/amd/ibs_mprof:online",
				x86_amd_ibs_mprof_online,
				x86_amd_ibs_mprof_offline);
	if (ret < 0)
		goto out_free;
	mprof_cpuhp_state = ret;

	mprof_pm_init();

	pr_info("IBS Memory Profiler is available for memory access profiling\n");
	return 0;

out_free:
	free_percpu(mprof_s);
	pr_info("IBS Memory Profiler failed to initialize\n");
	return ret;
}

device_initcall(mprof_access_profiling_init);
