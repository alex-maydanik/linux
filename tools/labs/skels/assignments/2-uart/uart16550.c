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

#include "uart16550.h"

MODULE_DESCRIPTION("UART16550 serial port driver");
MODULE_AUTHOR("Alexander Maydanik <alexander.maydanik@gmail.com>");
MODULE_LICENSE("GPL v2");

#define MODULE_NAME			"uart16550"
#define UART16550_DEFAULT_MAJOR		42

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

static int uart16550_init(void)
{
	int err, i;

	err = register_chrdev_region(MKDEV(UART16550_DEFAULT_MAJOR, 0),
				     MAX_NUMBER_DEVICES, MODULE_NAME);
	if (err != 0) {
		pr_err("%s: register_chrdev_region() failed: %d\n", MODULE_NAME, err);
		goto out;
	}

	for (i = 0; i < MAX_NUMBER_DEVICES; i++) {
		cdev_init(&devs[i].cdev, &uart16550_fops);
		err = cdev_add(&devs[i].cdev, MKDEV(UART16550_DEFAULT_MAJOR, i), 1);
		if (err != 0) {
			pr_err("%s: cdev_add() failed: %d\n", MODULE_NAME, err);
			goto out_unregister;
		}
	}

	pr_notice("%s: loaded\n", MODULE_NAME);
	return 0;

out_unregister:
	for (i = 0; i < MAX_NUMBER_DEVICES; i++)
		cdev_del(&devs[i].cdev);
	unregister_chrdev_region(MKDEV(UART16550_DEFAULT_MAJOR, 0),
				 MAX_NUMBER_DEVICES);
out:
	return err;
}

static void uart16550_exit(void)
{
	int i;

	for (i = 0; i < MAX_NUMBER_DEVICES; i++)
		cdev_del(&devs[i].cdev);

	unregister_chrdev_region(MKDEV(UART16550_DEFAULT_MAJOR, 0),
				 MAX_NUMBER_DEVICES);

	pr_notice("%s: unloaded\n", MODULE_NAME);
}

module_init(uart16550_init);
module_exit(uart16550_exit);
