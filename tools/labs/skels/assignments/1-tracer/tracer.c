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

#include "tracer.h"

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Alexander Maydanik <alexander.maydanik@gmail.com>");
MODULE_LICENSE("GPL v2");

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

	spinlock_t lock;
	struct hlist_node hnode;
};

#define TRACED_PROCS_HASH_BITS	5
static DEFINE_HASHTABLE(traced_procs_hash, TRACED_PROCS_HASH_BITS);
static DEFINE_MUTEX(traced_procs_lock);

static int tracer_add_process(pid_t pid)
{
	struct trace_data *td;
	int ret = 0;

	mutex_lock(&traced_procs_lock);

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
	mutex_unlock(&traced_procs_lock);

	return ret;
}

/* TODO: Call in case process is killed / finished running */
static int tracer_remove_process(pid_t pid)
{
	struct trace_data *td;

	mutex_lock(&traced_procs_lock);

	/* Find process */
	hash_for_each_possible(traced_procs_hash, td, hnode, pid) {
		if (td->pid == pid)
			goto found;
	}

	mutex_unlock(&traced_procs_lock);
	return -ESRCH;

found:
	hash_del_rcu(&td->hnode);
	mutex_unlock(&traced_procs_lock);
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
	int err;

	err = misc_register(&tracer_device);
	if (err != 0) {
		return err;
	}

	return 0;
}

static void tracer_exit(void)
{
	struct trace_data *td;
	struct hlist_node *tmp;
	int i;

	/* Free hashtable */
	mutex_lock(&traced_procs_lock);
	hash_for_each_safe(traced_procs_hash, i, tmp, td, hnode) {
		hash_del(&td->hnode);
		kfree(td);
	}	
	mutex_unlock(&traced_procs_lock);

	misc_deregister(&tracer_device);
}

module_init(tracer_init);
module_exit(tracer_exit);