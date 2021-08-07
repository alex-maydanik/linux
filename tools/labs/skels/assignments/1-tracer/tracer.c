// SPDX-License-Identifier: GPL-2.0+
/*
 * tracer.c - Kprobe based tracer
 *
 * Author: Alexander Maydanik <alexander.maydanik@gmail.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/rwsem.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "tracer.h"

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Alexander Maydanik <alexander.maydanik@gmail.com>");
MODULE_LICENSE("GPL v2");

#define TRACER_PROCFS_NAME		"tracer"

struct proc_dir_entry *proc_tracer;

/*
 * Holds tracing data for a single process.
 * Hashed by PID.
 */
struct trace_data {
	pid_t pid;

	/* In bytes */
	u64 kmalloc_mem;
	u64 kfree_mem;

	/* Function calls counters */
	u64 kmalloc_calls;
	u64 kfree_calls;
	u64 sched_calls;
	u64 up_calls;
	u64 down_calls;
	u64 lock_calls;
	u64 unlock_calls;

	struct hlist_node hnode;
};

#define TRACED_PROCS_HASH_BITS	5
static DEFINE_HASHTABLE(traced_procs_hash, TRACED_PROCS_HASH_BITS);
static DECLARE_RWSEM(traced_procs_lock);

static int tracer_add_process(pid_t pid)
{
	struct trace_data *td;
	int ret = 0;

	down_write(&traced_procs_lock);

	/* Check if process exists in the system */
	if (!find_vpid(pid)) {
		pr_err("%s: Error - Process with pid %d doesn't exists\n", __FUNCTION__, pid);
		ret = -ESRCH;
		goto error;
	}

	/* Check if process is already being traced */
	hash_for_each_possible(traced_procs_hash, td, hnode, pid) {
		if (td->pid == pid) {
			pr_err("%s: Error - Process with pid %d is already traced\n", __FUNCTION__, pid);
			ret = -EEXIST;
			goto error;
		}
	}
		
	td = kzalloc(sizeof(*td), GFP_KERNEL);
	if (!td) {
		ret = -ENOMEM;
		goto error;
	}
	td->pid = pid;
	hash_add(traced_procs_hash, &td->hnode, pid);

error:
	up_write(&traced_procs_lock);

	return ret;
}

/* TODO: Call in case process is killed / finished running */
static int tracer_remove_process(pid_t pid)
{
	struct trace_data *td;

	down_write(&traced_procs_lock);

	/* Find process */
	hash_for_each_possible(traced_procs_hash, td, hnode, pid) {
		if (td->pid == pid)
			goto found;
	}

	up_write(&traced_procs_lock);
	return -ESRCH;

found:
	hash_del(&td->hnode);
	up_write(&traced_procs_lock);
	kfree(td);

	return 0;
}

static long
tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	switch(cmd) {
	case TRACER_ADD_PROCESS:
		ret = tracer_add_process((pid_t)arg);
		break;
	case TRACER_REMOVE_PROCESS:
		ret = tracer_remove_process((pid_t)arg);
		break;
	default:
		return -ENOTTY;
	}

	return ret;
}

static int tracer_proc_show(struct seq_file *m, void *v)
{
	struct trace_data *td;
	int i;

	seq_printf(m, "%-6s%-8s%-6s%-12s%-11s%-8s%-7s%-7s%-6s%-6s\n",
		"PID", "kmalloc", "kfree", "kmalloc_mem", "kfree_mem", "sched",
		"up", "down", "lock", "unlock");

	down_read(&traced_procs_lock);
	hash_for_each(traced_procs_hash, i, td, hnode) {
		seq_printf(m, "%-6d%-8llu%-6llu%-12llu%-11llu%-8llu%-7llu%-7llu%-6llu%-6llu\n",
			td->pid, td->kmalloc_calls, td->kfree_calls,
			td->kmalloc_mem, td->kfree_mem, td->sched_calls,
			td->up_calls, td->down_calls,
			td->lock_calls, td->unlock_calls);
	}
	up_read(&traced_procs_lock);

	return 0;
}

static int tracer_procfs_open(struct inode *inode, struct file *file)
{
	return single_open(file, tracer_proc_show, NULL);
}

static const struct proc_ops r_pops = {
	.proc_open		= tracer_procfs_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static const struct file_operations tracer_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tracer_ioctl,
};

static struct miscdevice tracer_device = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &tracer_fops,
};

static int tracer_init(void)
{
	int err = 0;

	err = misc_register(&tracer_device);
	if (err != 0)
		return err;
		
	proc_tracer= proc_create(TRACER_PROCFS_NAME, 0000, proc_tracer, &r_pops);
	if (!proc_tracer) {
		proc_remove(proc_tracer);
		misc_deregister(&tracer_device);
		return -ENOMEM;
	}

	return 0;
}

static void tracer_exit(void)
{
	struct trace_data *td;
	struct hlist_node *tmp;
	int i;

	/* Free hashtable */
	down_write(&traced_procs_lock);
	hash_for_each_safe(traced_procs_hash, i, tmp, td, hnode) {
		hash_del(&td->hnode);
		kfree(td);
	}	
	up_write(&traced_procs_lock);

	proc_remove(proc_tracer);
	misc_deregister(&tracer_device);
}

module_init(tracer_init);
module_exit(tracer_exit);