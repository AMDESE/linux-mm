// SPDX-License-Identifier: GPL-2.0
/*
 * pghot tunables in debugfs
 */
#include <linux/debugfs.h>

static struct dentry *debugfs_pghot;

static ssize_t pghot_freq_th_write(struct file *filp, const char __user *ubuf,
				   size_t cnt, loff_t *ppos)
{
	char buf[16];
	unsigned int freq;

	if (cnt > 15)
		cnt = 15;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;
	buf[cnt] = '\0';

	if (kstrtouint(buf, 10, &freq))
		return -EINVAL;

	if (!freq || freq > PGHOT_FREQ_MAX)
		return -EINVAL;

	pghot_freq_threshold = freq;

	*ppos += cnt;
	return cnt;
}

static int pghot_freq_th_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", pghot_freq_threshold);
	return 0;
}

static int pghot_freq_th_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, pghot_freq_th_show, NULL);
}

static const struct file_operations pghot_freq_th_fops = {
	.open		= pghot_freq_th_open,
	.write		= pghot_freq_th_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static ssize_t pghot_target_nid_write(struct file *filp, const char __user *ubuf,
				      size_t cnt, loff_t *ppos)
{
	char buf[16];
	unsigned int nid;

	if (cnt > 15)
		cnt = 15;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;
	buf[cnt] = '\0';

	if (kstrtouint(buf, 10, &nid))
		return -EINVAL;

	if (nid > PGHOT_NID_MAX || !node_online(nid) || !node_is_toptier(nid))
		return -EINVAL;
	pghot_target_nid = nid;

	*ppos += cnt;
	return cnt;
}

static int pghot_target_nid_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", pghot_target_nid);
	return 0;
}

static int pghot_target_nid_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, pghot_target_nid_show, NULL);
}

static const struct file_operations pghot_target_nid_fops = {
	.open		= pghot_target_nid_open,
	.write		= pghot_target_nid_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static void pghot_src_enabled_update(unsigned int enabled)
{
	unsigned int changed = pghot_src_enabled ^ enabled;

	if (changed & PGHOT_HWHINTS_ENABLED) {
		if (enabled & PGHOT_HWHINTS_ENABLED)
			static_branch_enable(&pghot_src_hwhints);
		else
			static_branch_disable(&pghot_src_hwhints);
	}

	if (changed & PGHOT_PGTSCAN_ENABLED) {
		if (enabled & PGHOT_PGTSCAN_ENABLED)
			static_branch_enable(&pghot_src_pghtscans);
		else
			static_branch_disable(&pghot_src_pghtscans);
	}

	if (changed & PGHOT_HINTFAULT_ENABLED) {
		if (enabled & PGHOT_HINTFAULT_ENABLED)
			static_branch_enable(&pghot_src_hintfaults);
		else
			static_branch_disable(&pghot_src_hintfaults);
	}
}

static ssize_t pghot_src_enabled_write(struct file *filp, const char __user *ubuf,
					   size_t cnt, loff_t *ppos)
{
	char buf[16];
	unsigned int enabled;

	if (cnt > 15)
		cnt = 15;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;
	buf[cnt] = '\0';

	if (kstrtouint(buf, 0, &enabled))
		return -EINVAL;

	if (enabled & ~PGHOT_SRC_ENABLED_MASK)
		return -EINVAL;

	pghot_src_enabled_update(enabled);
	pghot_src_enabled = enabled;

	*ppos += cnt;
	return cnt;
}

static int pghot_src_enabled_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", pghot_src_enabled);
	return 0;
}

static int pghot_src_enabled_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, pghot_src_enabled_show, NULL);
}

static const struct file_operations pghot_src_enabled_fops = {
	.open		= pghot_src_enabled_open,
	.write		= pghot_src_enabled_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static void pghot_debug_init(void)
{
	debugfs_pghot = debugfs_create_dir("pghot", NULL);
	debugfs_create_file("enabled_sources", 0644, debugfs_pghot, NULL,
			    &pghot_src_enabled_fops);
	debugfs_create_file("target_nid", 0644, debugfs_pghot, NULL,
			    &pghot_target_nid_fops);
	debugfs_create_file("freq_threshold", 0644, debugfs_pghot, NULL,
			    &pghot_freq_th_fops);
	debugfs_create_u32("kmigrated_sleep_ms", 0644, debugfs_pghot,
			    &kmigrated_sleep_ms);
	debugfs_create_u32("kmigrated_batch_nr", 0644, debugfs_pghot,
			    &kmigrated_batch_nr);
}
