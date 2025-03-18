// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * DMA batch-offlading interface driver
 *
 * Copyright (C) 2024 Advanced Micro Devices, Inc.
 */

/*
 * This code exemplifies how to leverage mm layer's migration offload support
 * for batch page offloading using DMA Engine APIs.
 * Developers can use this template to write interface for custom hardware
 * accelerators with specialized capabilities for batch page migration.
 * This interface driver is end-to-end working and can be used for testing the
 * patch series without special hardware given DMAEngine support is available.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/migrate.h>
#include <linux/migrate_offc.h>
#include <linux/printk.h>
#include <linux/sysfs.h>

#define MAX_DMA_CHANNELS 16

static int is_dispatching;
static int nr_dma_chan;

static int folios_copy_dma(struct list_head *dst_list, struct list_head *src_list, int folios_cnt);
static int folios_copy_dma_parallel(struct list_head *dst_list, struct list_head *src_list, int folios_cnt, int thread_count);
static bool can_migrate_dma(struct folio *dst, struct folio *src);

static DEFINE_MUTEX(migratecfg_mutex);

/* DMA Core Batch Migrator */
struct migrator dmigrator = {
	.name = "DCBM\0",
	.migrate_offc = folios_copy_dma,
	.can_migrate_offc = can_migrate_dma,
	.owner = THIS_MODULE,
};

static ssize_t offloading_set(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int ccode;
	int action;

	ccode = kstrtoint(buf, 0, &action);
	if (ccode) {
		pr_debug("(%s:) error parsing input %s\n", __func__, buf);
		return ccode;
	}

	/*
	 * action is 0: User wants to disable DMA offloading.
	 * action is 1: User wants to enable DMA offloading.
	 */
	switch (action) {
	case 0:
		mutex_lock(&migratecfg_mutex);
		if (is_dispatching == 1) {
			stop_offloading();
			is_dispatching = 0;
		} else
			pr_debug("migration offloading is already OFF\n");
		mutex_unlock(&migratecfg_mutex);
		break;
	case 1:
		mutex_lock(&migratecfg_mutex);
		if (is_dispatching == 0) {
			start_offloading(&dmigrator);
			is_dispatching = 1;
		} else
			pr_debug("migration offloading is already ON\n");
		mutex_unlock(&migratecfg_mutex);
		break;
	default:
		pr_debug("input should be zero or one, parsed as %d\n", action);
	}
	return sizeof(action);
}

static ssize_t offloading_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", is_dispatching);
}

static ssize_t nr_dma_chan_set(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int ccode;
	int action;

	ccode = kstrtoint(buf, 0, &action);
	if (ccode) {
		pr_err("(%s:) error parsing input %s\n", __func__, buf);
		return ccode;
	}

	if (action < 1) {
		pr_err("%s: invalid value, at least 1 channel\n",__func__);
		return -EINVAL;
	}
	if (action >= MAX_DMA_CHANNELS)
		action = MAX_DMA_CHANNELS;

	mutex_lock(&migratecfg_mutex);
	nr_dma_chan = action;
	mutex_unlock(&migratecfg_mutex);

	return sizeof(action);
}

static ssize_t nr_dma_chan_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", nr_dma_chan);
}

static bool can_migrate_dma(struct folio *dst, struct folio *src)
{

//	printk("folio_size %d\n",folio_size(src));
	if (folio_test_hugetlb(src) || folio_test_hugetlb(dst) ||
			folio_has_private(src) || folio_has_private(dst) ||
			(folio_nr_pages(src) != folio_nr_pages(dst))) {
		pr_err("can NOT DMA migrate this folio %p\n",src);
		return false;
	}
	return true;
}

/**
 * DMA channel and track its transfers
 */
struct dma_channel_work {
	struct dma_chan *chan;
	struct completion done;
	int active_transfers;
	spinlock_t lock;
};

/**
 * Callback for DMA completion
 */
static void folios_dma_completion_callback(void *param)
{
	struct dma_channel_work *chan_work = param;

	spin_lock(&chan_work->lock);
	chan_work->active_transfers--;
	if (chan_work->active_transfers == 0)
		complete(&chan_work->done);
	spin_unlock(&chan_work->lock);
}

/**
 * process dma transfer: preparation part: map, prep_memcpy
 */
static int process_folio_dma_transfer(struct dma_channel_work *chan_work,
				      struct folio *src, struct folio *dst)
{
	struct dma_chan *chan = chan_work->chan;
	struct dma_device *dev = chan->device;
	struct device *dma_dev = dmaengine_get_dma_device(chan);
	dma_cookie_t cookie;
	struct dma_async_tx_descriptor *tx;
	enum dma_ctrl_flags flags = DMA_CTRL_ACK | DMA_PREP_INTERRUPT;
	dma_addr_t srcdma_handle, dstdma_handle;
	size_t data_size = folio_size(src);

	/* Map source and destination pages */
	srcdma_handle = dma_map_page(dma_dev, &src->page, 0, data_size, DMA_TO_DEVICE);
	if (dma_mapping_error(dma_dev, srcdma_handle)) {
		pr_err("src mapping error\n");
		return -ENOMEM;
	}

	dstdma_handle = dma_map_page(dma_dev, &dst->page, 0, data_size, DMA_FROM_DEVICE);
	if (dma_mapping_error(dma_dev, dstdma_handle)) {
		pr_err("dst mapping error\n");
		dma_unmap_page(dma_dev, srcdma_handle, data_size, DMA_TO_DEVICE);
		return -ENOMEM;
	}

	/* Prepare DMA descriptor */
	tx = dev->device_prep_dma_memcpy(chan, dstdma_handle, srcdma_handle,
					 data_size, flags);
	if (unlikely(!tx)) {
		pr_err("prep_dma_memcpy error\n");
		dma_unmap_page(dma_dev, dstdma_handle, data_size, DMA_FROM_DEVICE);
		dma_unmap_page(dma_dev, srcdma_handle, data_size, DMA_TO_DEVICE);
		return -EBUSY;
	}

	/* Set up completion callback */
	tx->callback = folios_dma_completion_callback;
	tx->callback_param = chan_work;

	/* Submit DMA transaction */
	spin_lock(&chan_work->lock);
	chan_work->active_transfers++;
	spin_unlock(&chan_work->lock);

	cookie = tx->tx_submit(tx);
	if (dma_submit_error(cookie)) {
		pr_err("dma_submit_error\n");
		spin_lock(&chan_work->lock);
		chan_work->active_transfers--;
		spin_unlock(&chan_work->lock);
		dma_unmap_page(dma_dev, dstdma_handle, data_size, DMA_FROM_DEVICE);
		dma_unmap_page(dma_dev, srcdma_handle, data_size, DMA_TO_DEVICE);
		return -EINVAL;
	}

	return 0;
}

/**
 * Copy folios using DMA in parallel.
 * Divide into chunks, submit to DMA channels.
 * if error, falls back to CPU
 * Note: return 0 for all cases as error is taken care.
 * TODO: Add poison recovery support.
 */
int folios_copy_dma_parallel(struct list_head *dst_list,
			      struct list_head *src_list,
			      int folios_cnt_total, int thread_count)
{
	struct dma_channel_work *chan_works;
	struct dma_chan **channels;
	int i, actual_channels = 0;
	struct folio *src, *dst;
	dma_cap_mask_t mask;
	int channel_idx = 0;
	int failed = 0;
	int ret;

	/* TODO: optimise actual number of channels needed
	at what point DMA set-up overheads < mig cost for N folio*/
	thread_count = min(thread_count, folios_cnt_total);

	/* Allocate memory for channels */
	channels = kmalloc_array(thread_count, sizeof(struct dma_chan *), GFP_KERNEL);
	if (unlikely(!channels)) {
		pr_err("failed to allocate memory for channels\n");
		folios_copy(dst_list, src_list, folios_cnt_total);
		return 0;
	}

	/* Request DMA channels */
	dma_cap_zero(mask);
	dma_cap_set(DMA_MEMCPY, mask);
	for (i = 0; i < thread_count; i++) {
		channels[i] = dma_request_channel(mask, NULL, NULL);
		if (!channels[i]) {
			pr_err("could only allocate %d DMA channels\n", i);
			break;
		}
		actual_channels++;
	}

	if (unlikely(actual_channels == 0)) {
		pr_err("couldn't allocate any DMA channels, falling back to CPU copy\n");
		kfree(channels);
		folios_copy(dst_list, src_list, folios_cnt_total);
		return 0;
	}

	/* Allocate work structures */
	chan_works = kmalloc_array(actual_channels, sizeof(*chan_works), GFP_KERNEL);
	if (unlikely(!chan_works)) {
		pr_err("failed to allocate memory for work structures\n");
		for (i = 0; i < actual_channels; i++)
			dma_release_channel(channels[i]);
		kfree(channels);
		folios_copy(dst_list, src_list, folios_cnt_total);
		return 0;
	}

	/* Initialize work structures */
	for (i = 0; i < actual_channels; i++) {
		chan_works[i].chan = channels[i];
		init_completion(&chan_works[i].done);
		chan_works[i].active_transfers = 0;
		spin_lock_init(&chan_works[i].lock);
	}

	/* STEP 1: Submit all DMA transfers across all channels */
	dst = list_first_entry(dst_list, struct folio, lru);
	list_for_each_entry(src, src_list, lru) {
		ret = process_folio_dma_transfer(&chan_works[channel_idx], src, dst);
		if (unlikely(ret)) {
			/* Fallback to CPU */
			folio_copy(dst, src);
			failed++;
		}

		channel_idx = (channel_idx + 1) % actual_channels;

		dst = list_next_entry(dst, lru);
	}

	/* STEP 2: Issue all pending DMA requests */
	for (i = 0; i < actual_channels; i++) {
		dma_async_issue_pending(chan_works[i].chan);
	}

	/* STEP 3: Wait for all DMA operations to complete */
	for (i = 0; i < actual_channels; i++) {
		wait_for_completion(&chan_works[i].done);
	}

	if (failed)
		pr_err("processed %d fallback with CPU\n", failed);

	/* Release all resources */
	for (i = 0; i < actual_channels; i++) {
		dma_release_channel(channels[i]);
	}

	kfree(chan_works);
	kfree(channels);

	return 0;
}

/**
 * Similar to folios_copy but use dma.
 */
static int folios_copy_dma(struct list_head *dst_list,
			    struct list_head *src_list,
			    int folios_cnt)
{
	return folios_copy_dma_parallel(dst_list, src_list, folios_cnt, nr_dma_chan);
}

static struct kobject *kobj_ref;
static struct kobj_attribute offloading_attribute = __ATTR(offloading, 0664,
		offloading_show, offloading_set);
static struct kobj_attribute nr_dma_chan_attribute = __ATTR(nr_dma_chan, 0664,
		nr_dma_chan_show, nr_dma_chan_set);

static int __init dma_module_init(void)
{
	int ret = 0;

	kobj_ref = kobject_create_and_add("dcbm", kernel_kobj);
	if (!kobj_ref)
		return -ENOMEM;

	ret = sysfs_create_file(kobj_ref, &offloading_attribute.attr);
	if (ret)
		goto out;

	ret = sysfs_create_file(kobj_ref, &nr_dma_chan_attribute.attr);
	if (ret)
		goto out;

	is_dispatching = 0;
	nr_dma_chan = 1;

	return 0;
out:
	kobject_put(kobj_ref);
	return ret;
}

static void __exit dma_module_exit(void)
{
	/* Stop the DMA offloading to unload the module */
	sysfs_remove_file(kobj_ref, &offloading_attribute.attr);
	sysfs_remove_file(kobj_ref, &nr_dma_chan_attribute.attr);
	kobject_put(kobj_ref);
}

module_init(dma_module_init);
module_exit(dma_module_exit);

/* DMA Core Batch Migrator */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shivank Garg");
MODULE_DESCRIPTION("DCBM");
