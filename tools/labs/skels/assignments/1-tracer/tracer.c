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
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>

#include "tracer.h"

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Alexander Maydanik <alexander.maydanik@gmail.com>");
MODULE_LICENSE("GPL v2");

#define TRACER_PROCFS_NAME		"tracer"
struct proc_dir_entry *proc_tracer;

#define KRETPROBE_MAX_ACTIVE	64

static int tracer_remove_process(pid_t pid);

/* kmalloc() data */
struct kmalloc_data {
	void *addr;
	size_t size;
	struct list_head list;
};

static void free_mem_list(struct list_head *mem_list)
{
	struct list_head *i, *n;
	struct kmalloc_data *mem_data;	

	list_for_each_safe(i, n, mem_list) {
		mem_data = list_entry(i, struct kmalloc_data, list);
		list_del(i);
		kfree(mem_data);
	}
}

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

	/* List of memory allocations */
	struct list_head mem_list;

	struct hlist_node hnode;
};

#define TRACED_PROCS_HASH_BITS	5
static DEFINE_HASHTABLE(traced_procs_hash, TRACED_PROCS_HASH_BITS);
static DEFINE_SPINLOCK(traced_procs_lock);

static int kprobe_calls_count_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct trace_data *td;
	const char* symbol_name;
	pid_t pid = task_pid_nr(ri->task);
	
	spin_lock(&traced_procs_lock);

	hash_for_each_possible(traced_procs_hash, td, hnode, pid) {
		if (td->pid == pid) {
			symbol_name = ri->rp->kp.symbol_name;

			if (strcmp(symbol_name, "up") == 0)
				td->up_calls++;
			else if (strcmp(symbol_name, "down_interruptible") == 0)
				td->down_calls++;
			else if (strcmp(symbol_name, "schedule") == 0)
				td->sched_calls++;
			else if (strcmp(symbol_name, "mutex_lock_nested") == 0)
				td->lock_calls++;
			else if (strcmp(symbol_name, "mutex_unlock") == 0)
				td->unlock_calls++;

			break;
		}
	}

	spin_unlock(&traced_procs_lock);
	return 1; /* No need to hook on return */
}

static int kprobe_free_task_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *tsk = (struct task_struct *)regs_get_kernel_argument(regs, 0);

	/* We don't care about the return value. If the task isn't traced, nothing is done */
	tracer_remove_process(task_pid_nr(tsk));
	
	return 1; /* No need to hook on return */
}

static int kprobe_kmalloc_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct trace_data *td;
	struct kmalloc_data *data = (struct kmalloc_data *)ri->data;
	
	spin_lock(&traced_procs_lock);

	hash_for_each_possible(traced_procs_hash, td, hnode, task_pid_nr(ri->task)) {
		if (td->pid == task_pid_nr(ri->task)) {
			td->kmalloc_calls++;
			data->size = regs_get_kernel_argument(regs, 0);
			break;
		}
	}

	spin_unlock(&traced_procs_lock);
	return 0;
}

static int kprobe_kmalloc_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct trace_data *td;
	struct kmalloc_data *data = (struct kmalloc_data *)ri->data;
	struct kmalloc_data *copy;
	
	spin_lock(&traced_procs_lock);

	hash_for_each_possible(traced_procs_hash, td, hnode, task_pid_nr(ri->task)) {
		if (td->pid == task_pid_nr(ri->task)) {
			data->addr = (void*)regs_return_value(regs);

			/* Check if memory allocation is successful */
			if (data->addr) {
				td->kmalloc_mem += data->size;

				/*
				 * Add allocated memory area to kmalloc_memory_list
				 * Note - If memory allocation failed, nothing we can do
				 */
				copy = kmalloc(sizeof(*copy), GFP_ATOMIC);
				if (copy) {
					copy->addr = data->addr;
					copy->size = data->size;
					list_add(&copy->list, &td->mem_list);
				}
			}
			break;
		}
	}

	spin_unlock(&traced_procs_lock);
	return 0;
}

static int kprobe_kfree_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct trace_data *td;
	void *addr;
	struct list_head *i, *tmp;
	struct kmalloc_data *mem_data;

	spin_lock(&traced_procs_lock);

	hash_for_each_possible(traced_procs_hash, td, hnode, task_pid_nr(ri->task)) {
		if (td->pid == task_pid_nr(ri->task)) {
			td->kfree_calls++;

			/* Lookup for allocated memory data */
			addr = (void*)regs_get_kernel_argument(regs, 0);
			list_for_each_safe(i, tmp, &td->mem_list) {
				mem_data = list_entry(i, struct kmalloc_data, list);
				if (mem_data->addr == addr) {
					td->kfree_mem += mem_data->size;
					mem_data->addr = 0; /* Invalidate the entry */
					break;
				}
			}

			break;
		}
	}

	spin_unlock(&traced_procs_lock);
	return 1; /* No need to hook on return */
}

static struct kretprobe up_probe = {
	.entry_handler = 	kprobe_calls_count_handler,
	.maxactive = 		KRETPROBE_MAX_ACTIVE,
	.kp.symbol_name = 	"up"
};

static struct kretprobe down_probe = {
	.entry_handler = 	kprobe_calls_count_handler,
	.maxactive = 		KRETPROBE_MAX_ACTIVE,
	.kp.symbol_name = 	"down_interruptible"
};

static struct kretprobe schedule_probe = {
	.entry_handler = 	kprobe_calls_count_handler,
	.maxactive = 		KRETPROBE_MAX_ACTIVE,
	.kp.symbol_name = 	"schedule"
};

static struct kretprobe mutex_lock_probe = {
	.entry_handler = 	kprobe_calls_count_handler,
	.maxactive = 		KRETPROBE_MAX_ACTIVE,
	.kp.symbol_name = 	"mutex_lock_nested"
};

static struct kretprobe mutex_unlock_probe = {
	.entry_handler = 	kprobe_calls_count_handler,
	.maxactive = 		KRETPROBE_MAX_ACTIVE,
	.kp.symbol_name = 	"mutex_unlock"
};

static struct kretprobe kmalloc_probe = {
	.entry_handler = 	kprobe_kmalloc_entry_handler,
	.handler =		kprobe_kmalloc_ret_handler,
	.maxactive = 		KRETPROBE_MAX_ACTIVE,
	.data_size =		sizeof(struct kmalloc_data),
	.kp.symbol_name = 	"__kmalloc"
};

static struct kretprobe kfree_probe = {
	.entry_handler = 	kprobe_kfree_entry_handler,
	.maxactive = 		KRETPROBE_MAX_ACTIVE,
	.kp.symbol_name = 	"kfree"
};

static struct kretprobe free_task_probe = {
	.entry_handler = 	kprobe_free_task_entry_handler,
	.maxactive = 		KRETPROBE_MAX_ACTIVE,
	.kp.symbol_name = 	"free_task"
};

static struct kretprobe *tracer_kretprobes[] = {
	&up_probe,
	&down_probe,
	&schedule_probe,
	&mutex_lock_probe,
	&mutex_unlock_probe,
	&kmalloc_probe,
	&kfree_probe,
	&free_task_probe,
};

static int tracer_add_process(pid_t pid)
{
	struct trace_data *td;
	int ret = 0;

	/* Check if process exists in the system */
	if (!find_vpid(pid)) {
		pr_err("%s: Error - Process with pid %d doesn't exists\n", __FUNCTION__, pid);
		ret = -ESRCH;
		goto error;
	}

	spin_lock(&traced_procs_lock);

	/* Check if process is already being traced */
	hash_for_each_possible(traced_procs_hash, td, hnode, pid) {
		if (td->pid == pid) {
			pr_err("%s: Error - Process with pid %d is already traced\n", __FUNCTION__, pid);
			ret = -EEXIST;
			goto error;
		}
	}
		
	td = kzalloc(sizeof(*td), GFP_ATOMIC);
	if (!td) {
		ret = -ENOMEM;
		goto error;
	}
	td->pid = pid;
	INIT_LIST_HEAD(&td->mem_list);
	hash_add(traced_procs_hash, &td->hnode, pid);

error:
	spin_unlock(&traced_procs_lock);

	return ret;
}

static int tracer_remove_process(pid_t pid)
{
	struct trace_data *td;

	spin_lock(&traced_procs_lock);

	/* Find process */
	hash_for_each_possible(traced_procs_hash, td, hnode, pid) {
		if (td->pid == pid)
			goto found;
	}

	spin_unlock(&traced_procs_lock);
	return -ESRCH;

found:
	hash_del(&td->hnode);
	spin_unlock(&traced_procs_lock);

	/* It is ok to free the lock - 'td' is not accessible anymore */
	free_mem_list(&td->mem_list);
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

	spin_lock(&traced_procs_lock);
	hash_for_each(traced_procs_hash, i, td, hnode) {
		seq_printf(m, "%-6d%-8llu%-6llu%-12llu%-11llu%-8llu%-7llu%-7llu%-6llu%-6llu\n",
			td->pid, td->kmalloc_calls, td->kfree_calls,
			td->kmalloc_mem, td->kfree_mem, td->sched_calls,
			td->up_calls, td->down_calls,
			td->lock_calls, td->unlock_calls);
	}
	spin_unlock(&traced_procs_lock);

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
	int ret = 0;

	ret = misc_register(&tracer_device);
	if (ret != 0)
		return ret;
		
	proc_tracer = proc_create(TRACER_PROCFS_NAME, 0000, proc_tracer, &r_pops);
	if (!proc_tracer) {
		ret = -ENOMEM;
		goto error;
	}

	ret = register_kretprobes(tracer_kretprobes, ARRAY_SIZE(tracer_kretprobes));
	if (ret != 0)
		goto error;

	return 0;

error:
	proc_remove(proc_tracer);
	misc_deregister(&tracer_device);
	return ret;
}

static void tracer_exit(void)
{
	struct trace_data *td;
	struct hlist_node *tmp;
	int i;

	proc_remove(proc_tracer);
	misc_deregister(&tracer_device);
	unregister_kretprobes(tracer_kretprobes, ARRAY_SIZE(tracer_kretprobes));

	/* Free hashtable */
	spin_lock(&traced_procs_lock);
	hash_for_each_safe(traced_procs_hash, i, tmp, td, hnode) {
		hash_del(&td->hnode);
		free_mem_list(&td->mem_list);
		kfree(td);
	}	
	spin_unlock(&traced_procs_lock);
}

module_init(tracer_init);
module_exit(tracer_exit);