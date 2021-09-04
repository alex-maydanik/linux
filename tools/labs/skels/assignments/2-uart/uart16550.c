/*
 * uart16550.c - Driver for Serial Port (UART16550)
 *
 * Author: Alexander Maydanik <alexander.maydanik@gmail.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/moduleparam.h>

#include "uart16550.h"

MODULE_DESCRIPTION("UART16550 serial port driver");
MODULE_AUTHOR("Alexander Maydanik <alexander.maydanik@gmail.com>");
MODULE_LICENSE("GPL v2");

#define MODULE_NAME			"uart16550"

static int major = 	42;
static int option =	OPTION_BOTH;
static int start_minor;
static int num_devices;

module_param(major, int, 0);
MODULE_PARM_DESC(major, "UART16550 character device major");
module_param(option, int, 0);
MODULE_PARM_DESC(option, "UART16550 operation option: OPTION_BOTH (default) / OPTION_COM1 / OPTION_COM2");

struct uart16550 {
	struct cdev cdev;
} devs[MAX_NUMBER_DEVICES];

static long
uart16550_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return 0;
}

static ssize_t uart16550_write(struct file *file, const char __user *user_buffer,
			 size_t size, loff_t *offset)
{
	return size;
}

static ssize_t uart16550_read(struct file *file,  char __user *user_buffer,
			size_t size, loff_t *offset)
{
	return size;
}

static int uart16550_open(struct inode *inode, struct file *file)
{
	struct uart16550 *data = container_of(inode->i_cdev, struct uart16550, cdev);

	file->private_data = data;
	return 0;
}

static const struct file_operations uart16550_fops = {
	.owner = THIS_MODULE,
	.open = uart16550_open,
	.read = uart16550_read,
	.write = uart16550_write,
	.unlocked_ioctl = uart16550_ioctl,
};

static int parse_option_arg(void)
{
	switch (option) {
	case OPTION_COM1:
		start_minor = 0;
		num_devices = 1;
		break;
	case OPTION_COM2:
		start_minor = 1;
		num_devices = 1;
		break;
	case OPTION_BOTH:
		start_minor = 0;
		num_devices = 2;
		break;
	default:
		pr_err("%s: option parameter must be one of: %d,%d,%d\n",
			MODULE_NAME, OPTION_COM1, OPTION_COM2, OPTION_BOTH);
		return -EINVAL;
	}

	return 0;
}

static int uart16550_init(void)
{
	int err, i;

	err = parse_option_arg();
	if (err != 0)
		goto out;
	
	err = register_chrdev_region(MKDEV(major, start_minor),
				     num_devices, MODULE_NAME);
	if (err != 0) {
		pr_err("%s: register_chrdev_region() failed: %d\n", MODULE_NAME, err);
		goto out;
	}

	for (i = start_minor; i < start_minor + num_devices; i++) {
		cdev_init(&devs[i].cdev, &uart16550_fops);
		err = cdev_add(&devs[i].cdev, MKDEV(major, i), 1);
		if (err != 0) {
			pr_err("%s: cdev_add() failed: %d\n", MODULE_NAME, err);
			goto out_unregister;
		}
	}

	pr_notice("%s: loaded\n", MODULE_NAME);
	return 0;

out_unregister:
	for (i = start_minor; i < start_minor + num_devices; i++)
		cdev_del(&devs[i].cdev);
	unregister_chrdev_region(MKDEV(major, start_minor),
				 num_devices);
out:
	return err;
}

static void uart16550_exit(void)
{
	int i;

	for (i = start_minor; i < start_minor + num_devices; i++)
		cdev_del(&devs[i].cdev);

	unregister_chrdev_region(MKDEV(major, start_minor),
				 num_devices);

	pr_notice("%s: unloaded\n", MODULE_NAME);
}

module_init(uart16550_init);
module_exit(uart16550_exit);
