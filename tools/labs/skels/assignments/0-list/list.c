// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * TODO 1/0: Fill in name / email
 * Author: Alexander Maydanik <alexander.maydanik@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define PROCFS_MAX_SIZE		512

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

#define CMD_ADD_TOP_STR		"addf "
#define CMD_ADD_END_STR		"adde "
#define CMD_DEL_FIRST_STR	"delf "
#define CMD_DEL_ALL_STR		"dela "
#define CMD_LEN 		(sizeof(CMD_ADD_TOP_STR) - 1)

enum command {
	CMD_INVALID = 0,
	CMD_ADD_TOP,
	CMD_ADD_END,
	CMD_DEL_FIRST,
	CMD_DEL_ALL,
	CMD_NUM
};

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

/* TODO 2: define your list! */
struct string_list {
    char* str;
    struct list_head list;
};
LIST_HEAD(my_list);

static int list_proc_show(struct seq_file *m, void *v)
{
	/* TODO 3: print your list. One element / line. */
	struct string_list *elem;

	list_for_each_entry(elem, &my_list, list) {
		seq_puts(m, elem->str);
	}

	return 0;
}

static enum command list_parse_command(const char *buf)
{
	if (!buf)
		return CMD_INVALID;

	if (str_has_prefix(buf, CMD_ADD_TOP_STR))
		return CMD_ADD_TOP;
	if (str_has_prefix(buf, CMD_ADD_END_STR))
		return CMD_ADD_END;
	if (str_has_prefix(buf, CMD_DEL_FIRST_STR))
		return CMD_DEL_FIRST;
	if (str_has_prefix(buf, CMD_DEL_ALL_STR))
		return CMD_DEL_ALL;
	
	return CMD_INVALID;
}

static struct string_list* list_alloc_new_elem(const char *str, size_t str_len)
{
	struct string_list *new_elem = NULL;
	char *new_str = NULL;

	new_elem = kmalloc(sizeof *new_elem, GFP_KERNEL);
	if (!new_elem)
		return NULL;
	
	new_str = kmalloc(str_len + 1, GFP_KERNEL);
	if (!new_str)
		goto alloc_failure;
	strncpy(new_str, str, str_len);
	new_str[str_len] = '\0';
	new_elem->str = new_str;

	return new_elem;

alloc_failure:
	kfree(new_elem);
	kfree(new_str);

	return NULL;
}

static int list_cmd_add_top(const char *str, size_t str_len)
{
	struct string_list *new_elem = list_alloc_new_elem(str, str_len);
	if (!new_elem)
		return -ENOMEM;
	
	list_add(&new_elem->list, &my_list);

	return 0;
}

static int list_cmd_add_end(const char *str, size_t str_len)
{
	struct string_list *new_elem = list_alloc_new_elem(str, str_len);
	if (!new_elem)
		return -ENOMEM;
	
	list_add_tail(&new_elem->list, &my_list);

	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;
	enum command current_cmd = CMD_INVALID;
	char *cmd_str_arg = NULL;
	size_t cmd_str_arg_len = 0;
	int res = 0;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	/* local_buffer contains your command written in /proc/list/management
	 * TODO 4/0: parse the command and add/delete elements.
	 */
	current_cmd = list_parse_command(local_buffer);
	if (current_cmd == CMD_INVALID) {
		pr_err("Error: Invalid command provided: %s\n", local_buffer);
		return -EINVAL;
	}

	/* Parse string argument */
	cmd_str_arg = local_buffer + CMD_LEN;
	cmd_str_arg_len = strnlen(cmd_str_arg, PROCFS_MAX_SIZE - CMD_LEN);

	switch (current_cmd) {
		case CMD_ADD_TOP: {
			pr_debug("ADD_TOP: %s\n", cmd_str_arg);
			if ((res = list_cmd_add_top(cmd_str_arg, cmd_str_arg_len)) != 0)
				return res;
			break;
		}
		case CMD_ADD_END: {
			pr_debug("ADD_END: %s\n", cmd_str_arg);
			if ((res = list_cmd_add_end(cmd_str_arg, cmd_str_arg_len)) != 0)
				return res;
			break;
		}
		case CMD_DEL_FIRST: {
			pr_debug("DEL_FIRST: %s\n", cmd_str_arg);
			break;
		}
		case CMD_DEL_ALL: {
			pr_debug("DEL_ALL: %s\n", cmd_str_arg);
			break;
		}
		default: {
			pr_err("Error: Invalid command provided: %s\n", local_buffer);
			return -EINVAL;
		}
	}

	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open		= list_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static const struct proc_ops w_pops = {
	.proc_open		= list_write_open,
	.proc_write		= list_write,
	.proc_release	= single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	/* TODO 6: Add d-tor for list */
	/* TODO 7: Add mutexes (rw locks) for safe access */
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
/* TODO 5: Fill in your name / email address */
MODULE_AUTHOR("Alexander Maydanik <alexander.maydanik@gmail.com>");
MODULE_LICENSE("GPL v2");
