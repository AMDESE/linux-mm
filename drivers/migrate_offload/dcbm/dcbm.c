// SPDX-License-Identifier: GPL-2.0-only
/*
 * DMA Core Batch Migrator (DCBM)
 *
 * Uses DMAEngine memcpy channels to offload batch folio copies during
 * page migration. Reference driver meant for testing the offload
 * infrastructure.
 *
 * Copyright (C) 2024-26 Advanced Micro Devices, Inc.
 */

#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/migrate.h>
#include <linux/migrate_copy_offload.h>

#define MAX_DMA_CHANNELS	1

/*
 * TODO: SDXI driver have some bug where it hangs when its ring overflows when\
 * we submit more than the ring holds.
 * As a workaround, limit the number of folios submitted to SDXI.
 */
#define DCBM_RING_LIMIT	512

static atomic_long_t folios_migrated;
static atomic_long_t folios_failures;

static bool offloading_enabled;
static unsigned int nr_dma_channels = 1;
static DEFINE_MUTEX(dcbm_mutex);

struct dma_work {
	struct dma_chan *chan;
	struct completion done;
	atomic_t pending;
	struct sg_table *src_sgt;
	struct sg_table *dst_sgt;
	bool mapped;
};

static void dma_completion_callback(void *data)
{
	struct dma_work *work = data;

	if (atomic_dec_and_test(&work->pending))
		complete(&work->done);
}

static int setup_sg_tables(struct dma_work *work, struct list_head **src_pos,
			   struct list_head **dst_pos, int nr)
{
	struct scatterlist *sg_src, *sg_dst;
	struct device *dev;
	int i, ret;

	work->src_sgt = kmalloc_obj(*work->src_sgt, GFP_KERNEL);
	if (!work->src_sgt)
		return -ENOMEM;
	work->dst_sgt = kmalloc_obj(*work->dst_sgt, GFP_KERNEL);
	if (!work->dst_sgt) {
		ret = -ENOMEM;
		goto err_free_src;
	}

	ret = sg_alloc_table(work->src_sgt, nr, GFP_KERNEL);
	if (ret)
		goto err_free_dst;
	ret = sg_alloc_table(work->dst_sgt, nr, GFP_KERNEL);
	if (ret)
		goto err_free_src_table;

	sg_src = work->src_sgt->sgl;
	sg_dst = work->dst_sgt->sgl;
	for (i = 0; i < nr; i++) {
		struct folio *src = list_entry(*src_pos, struct folio, lru);
		struct folio *dst = list_entry(*dst_pos, struct folio, lru);

		sg_set_folio(sg_src, src, folio_size(src), 0);
		sg_set_folio(sg_dst, dst, folio_size(dst), 0);

		*src_pos = (*src_pos)->next;
		*dst_pos = (*dst_pos)->next;

		if (i < nr - 1) {
			sg_src = sg_next(sg_src);
			sg_dst = sg_next(sg_dst);
		}
	}

	dev = dmaengine_get_dma_device(work->chan);
	if (!dev) {
		ret = -ENODEV;
		goto err_free_dst_table;
	}
	ret = dma_map_sgtable(dev, work->src_sgt, DMA_TO_DEVICE,
			      DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_NO_KERNEL_MAPPING);
	if (ret)
		goto err_free_dst_table;
	ret = dma_map_sgtable(dev, work->dst_sgt, DMA_FROM_DEVICE,
			      DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_NO_KERNEL_MAPPING);
	if (ret)
		goto err_unmap_src;

	/*
	 * TODO: IOMMU may merge segments unevenly on the two sides, fall back
	 * bail to CPU copy. In practice, I have not observed merging in tests.
	 * Handling unequal nents is left for follow-up.
	 */
	if (work->src_sgt->nents != work->dst_sgt->nents) {
		ret = -EINVAL;
		goto err_unmap_dst;
	}
	work->mapped = true;
	return 0;

err_unmap_dst:
	dma_unmap_sgtable(dev, work->dst_sgt, DMA_FROM_DEVICE,
			  DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_NO_KERNEL_MAPPING);
err_unmap_src:
	dma_unmap_sgtable(dev, work->src_sgt, DMA_TO_DEVICE,
			  DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_NO_KERNEL_MAPPING);
err_free_dst_table:
	sg_free_table(work->dst_sgt);
err_free_src_table:
	sg_free_table(work->src_sgt);
err_free_dst:
	kfree(work->dst_sgt);
	work->dst_sgt = NULL;
err_free_src:
	kfree(work->src_sgt);
	work->src_sgt = NULL;
	return ret;
}

static void cleanup_dma_work(struct dma_work *work, bool aborted)
{
	struct device *dev;

	if (!work->chan)
		return;

	dev = dmaengine_get_dma_device(work->chan);

	if (aborted && work->mapped)
		dmaengine_terminate_sync(work->chan);

	if (dev && work->mapped) {
		if (work->src_sgt) {
			dma_unmap_sgtable(dev, work->src_sgt, DMA_TO_DEVICE,
					  DMA_ATTR_SKIP_CPU_SYNC |
					  DMA_ATTR_NO_KERNEL_MAPPING);
			sg_free_table(work->src_sgt);
			kfree(work->src_sgt);
		}
		if (work->dst_sgt) {
			dma_unmap_sgtable(dev, work->dst_sgt, DMA_FROM_DEVICE,
					  DMA_ATTR_SKIP_CPU_SYNC |
					  DMA_ATTR_NO_KERNEL_MAPPING);
			sg_free_table(work->dst_sgt);
			kfree(work->dst_sgt);
		}
	}
}

static int submit_dma_transfers(struct dma_work *work)
{
	struct scatterlist *sg_src, *sg_dst;
	struct dma_async_tx_descriptor *tx;
	unsigned long flags = DMA_CTRL_ACK;
	dma_cookie_t cookie;
	int i;

	atomic_set(&work->pending, 1);

	sg_src = work->src_sgt->sgl;
	sg_dst = work->dst_sgt->sgl;
	for_each_sgtable_dma_sg(work->src_sgt, sg_src, i) {
		if (i == work->src_sgt->nents - 1)
			flags |= DMA_PREP_INTERRUPT;

		tx = dmaengine_prep_dma_memcpy(work->chan,
					       sg_dma_address(sg_dst),
					       sg_dma_address(sg_src),
					       sg_dma_len(sg_src), flags);
		if (!tx) {
			atomic_set(&work->pending, 0);
			return -EIO;
		}

		if (i == work->src_sgt->nents - 1) {
			tx->callback = dma_completion_callback;
			tx->callback_param = work;
		}

		cookie = dmaengine_submit(tx);
		if (dma_submit_error(cookie)) {
			atomic_set(&work->pending, 0);
			return -EIO;
		}
		sg_dst = sg_next(sg_dst);
	}
	return 0;
}

/**
 * folios_copy_dma - copy a batch of folios via DMA memcpy
 * @dst_list: destination folio list
 * @src_list: source folio list
 * @nr_folios: number of folios in each list
 *
 * Return: 0 on success, negative errno on failure.
 */
static int folios_copy_dma(struct list_head *dst_list,
			   struct list_head *src_list, unsigned int nr_folios)
{
	struct list_head *src_pos = src_list->next;
	struct list_head *dst_pos = dst_list->next;
	unsigned int remaining = nr_folios;
	unsigned int done = 0;
	struct dma_chan *chan;
	int ret = 0;

	if (!nr_folios)
		return 0;

	/*
	 * use dma_find_channel() for SDXI DMA_MEMCPY channels.
	 * TODO: Handle both private (PTDMA) and shared channels.
	 */
	chan = dma_find_channel(DMA_MEMCPY);
	if (!chan)
		return -ENODEV;

	while (remaining) {
		unsigned int chunk = min(remaining, DCBM_RING_LIMIT);
		struct dma_work work = { .chan = chan };
		struct list_head *dst_chunk = dst_pos;
		unsigned int i;

		init_completion(&work.done);

		ret = setup_sg_tables(&work, &src_pos, &dst_pos, chunk);
		if (ret)
			goto out;

		ret = submit_dma_transfers(&work);
		if (ret) {
			cleanup_dma_work(&work, true);
			goto out;
		}

		if (atomic_read(&work.pending) > 0)
			dma_async_issue_pending(work.chan);

		if (atomic_read(&work.pending) > 0 &&
		    !wait_for_completion_timeout(&work.done,
						 msecs_to_jiffies(10000))) {
			ret = -ETIMEDOUT;
			cleanup_dma_work(&work, true);
			goto out;
		}
		/*
		 * All folios copied; mark each dst with FOLIO_CONTENT_COPIED so
		 * __migrate_folio() skips the per-folio copy in the move phase.
		 */

		for (i = 0; i < chunk; i++) {
			struct folio *dst = list_entry(dst_chunk, struct folio, lru);

			dst->migrate_info |= FOLIO_CONTENT_COPIED;
			dst_chunk = dst_chunk->next;
		}

		cleanup_dma_work(&work, false);
		done += chunk;
		remaining -= chunk;
	}

out:
	if (done)
		atomic_long_add(done, &folios_migrated);
	if (ret) {
		pr_warn_ratelimited("dcbm: DMA copy failed (%d) after %u/%u folios; CPU fallback for the rest\n",
				    ret, done, nr_folios);
		atomic_long_add(nr_folios - done, &folios_failures);
	}
	return ret;
}

static const struct migrator dma_migrator = {
	.name = "DCBM",
	.offload_copy = folios_copy_dma,
	.owner = THIS_MODULE,
};

static unsigned long dcbm_reason_mask = MIGRATE_OFFLOAD_REASONS_ALLOWED;

/* offloading: enable/disable DMA migration offload */
static int offloading_param_set(const char *val, const struct kernel_param *kp)
{
	bool enable;
	int ret;

	ret = kstrtobool(val, &enable);
	if (ret)
		return ret;

	mutex_lock(&dcbm_mutex);
	if (enable == offloading_enabled) {
		mutex_unlock(&dcbm_mutex);
		return 0;
	}
	if (enable) {
		ret = migrate_offload_register(&dma_migrator,
					       READ_ONCE(dcbm_reason_mask));
		if (ret) {
			mutex_unlock(&dcbm_mutex);
			return ret;
		}
		WRITE_ONCE(offloading_enabled, true);
	} else {
		migrate_offload_unregister(&dma_migrator);
		WRITE_ONCE(offloading_enabled, false);
	}
	mutex_unlock(&dcbm_mutex);
	return 0;
}

static int offloading_param_get(char *buffer, const struct kernel_param *kp)
{
	return sysfs_emit(buffer, "%d\n", READ_ONCE(offloading_enabled));
}

static const struct kernel_param_ops offloading_param_ops = {
	.set = offloading_param_set,
	.get = offloading_param_get,
};
module_param_cb(offloading, &offloading_param_ops, NULL, 0644);
MODULE_PARM_DESC(offloading, "Enable DMA migration offload (0/1)");

/* nr_dma_chan: max DMA channels to use per batch */
static int nr_dma_chan_param_set(const char *val, const struct kernel_param *kp)
{
	unsigned int new_val;
	int ret;

	ret = kstrtouint(val, 0, &new_val);
	if (ret)
		return ret;
	if (new_val < 1 || new_val > MAX_DMA_CHANNELS)
		return -EINVAL;

	mutex_lock(&dcbm_mutex);
	WRITE_ONCE(nr_dma_channels, new_val);
	mutex_unlock(&dcbm_mutex);
	return 0;
}

static int nr_dma_chan_param_get(char *buffer, const struct kernel_param *kp)
{
	return sysfs_emit(buffer, "%u\n", READ_ONCE(nr_dma_channels));
}

static const struct kernel_param_ops nr_dma_chan_param_ops = {
	.set = nr_dma_chan_param_set,
	.get = nr_dma_chan_param_get,
};
module_param_cb(nr_dma_chan, &nr_dma_chan_param_ops, NULL, 0644);
MODULE_PARM_DESC(nr_dma_chan, "Max DMA channels to use (1..16)");

/* reason_mask: set of MR_* reasons this migrator handles */
static int reason_mask_param_set(const char *val, const struct kernel_param *kp)
{
	unsigned long mask;
	int ret;

	ret = migrate_offload_reason_mask_parse(val, &mask);
	if (ret)
		return ret;

	mutex_lock(&dcbm_mutex);
	WRITE_ONCE(dcbm_reason_mask, mask);
	if (offloading_enabled)
		migrate_offload_set_reason_mask(&dma_migrator, mask);
	mutex_unlock(&dcbm_mutex);
	return 0;
}

static int reason_mask_param_get(char *buffer, const struct kernel_param *kp)
{
	return migrate_offload_reason_mask_format(buffer, READ_ONCE(dcbm_reason_mask));
}

static const struct kernel_param_ops reason_mask_param_ops = {
	.set = reason_mask_param_set,
	.get = reason_mask_param_get,
};
module_param_cb(reason_mask, &reason_mask_param_ops, NULL, 0644);
MODULE_PARM_DESC(reason_mask,
		 "Reasons to offload: comma-separated names (e.g. compaction,demotion), 'all', 'none', or a raw hex mask");

/* folios_migrated / folios_failures: counters; any write resets to 0 */
static int folios_migrated_param_set(const char *val, const struct kernel_param *kp)
{
	atomic_long_set(&folios_migrated, 0);
	return 0;
}

static int folios_migrated_param_get(char *buffer, const struct kernel_param *kp)
{
	return sysfs_emit(buffer, "%ld\n", atomic_long_read(&folios_migrated));
}

static const struct kernel_param_ops folios_migrated_param_ops = {
	.set = folios_migrated_param_set,
	.get = folios_migrated_param_get,
};
module_param_cb(folios_migrated, &folios_migrated_param_ops, NULL, 0644);
MODULE_PARM_DESC(folios_migrated, "Folios DMA-copied (write to reset)");

static int folios_failures_param_set(const char *val, const struct kernel_param *kp)
{
	atomic_long_set(&folios_failures, 0);
	return 0;
}

static int folios_failures_param_get(char *buffer, const struct kernel_param *kp)
{
	return sysfs_emit(buffer, "%ld\n", atomic_long_read(&folios_failures));
}

static const struct kernel_param_ops folios_failures_param_ops = {
	.set = folios_failures_param_set,
	.get = folios_failures_param_get,
};
module_param_cb(folios_failures, &folios_failures_param_ops, NULL, 0644);
MODULE_PARM_DESC(folios_failures, "DMA-copy failure count (write to reset)");

static int __init dcbm_init(void)
{
	dmaengine_get();
	pr_info("dcbm: DMA Core Batch Migrator initialized\n");
	return 0;
}

static void __exit dcbm_exit(void)
{
	mutex_lock(&dcbm_mutex);
	if (offloading_enabled) {
		migrate_offload_unregister(&dma_migrator);
		offloading_enabled = false;
	}
	mutex_unlock(&dcbm_mutex);

	dmaengine_put();

	pr_info("dcbm: DMA Core Batch Migrator unloaded\n");
}

module_init(dcbm_init);
module_exit(dcbm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shivank Garg");
MODULE_DESCRIPTION("DMA Core Batch Migrator");
