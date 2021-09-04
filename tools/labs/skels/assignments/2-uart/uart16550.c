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
#include <linux/ioport.h>
#include <asm/io.h>

#include "uart16550.h"

MODULE_DESCRIPTION("UART16550 serial port driver");
MODULE_AUTHOR("Alexander Maydanik <alexander.maydanik@gmail.com>");
MODULE_LICENSE("GPL v2");

#define MODULE_NAME			"uart16550"
#define MINOR_COM1			(0)
#define MINOR_COM2			(1)

#define IO_PORT_BASE_COM1		(0x3f8)
#define IO_PORT_BASE_COM2		(0x2f8)
#define IO_PORT_NUM			(8)

/* UART 16550 registers */
#define UART_16550_THR(base)		((base) + 0x0)
#define UART_16550_RBR(base)		UART_16550_THR(base)
#define UART_16550_DLL(base)		UART_16550_THR(base)
#define UART_16550_IER(base)		((base) + 0x1)
#define UART_16550_DLH(base)		UART_16550_IER(base)
#define UART_16550_IIR(base)		((base) + 0x2)
#define UART_16550_FCR(base)		UART_16550_IIR(base)
#define UART_16550_LCR(base)		((base) + 0x3)
#define UART_16550_LSR(base)		((base) + 0x5)

/* UART 16550 registers useful values */
#define UART_16550_LCR_DLA_EN		(0x128)

static int major = 	42;
static int option =	OPTION_BOTH;
static int start_minor;
static int num_devices;

module_param(major, int, 0);
MODULE_PARM_DESC(major, "UART16550 character device major");
module_param(option, int, 0);
MODULE_PARM_DESC(option, "UART16550 operation option: OPTION_BOTH (default) / OPTION_COM1 / OPTION_COM2");

static const struct uart16550_line_info default_line_info = {
	.baud =		UART16550_BAUD_115200,
	.len =		UART16550_LEN_8,
	.par =		UART16550_PAR_NONE,
	.stop =		UART16550_STOP_1,
};

struct uart16550 {
	struct cdev cdev;
	u32 io_base;
	struct uart16550_line_info line_info;
} devs[MAX_NUMBER_DEVICES] = {
	{
		.io_base = IO_PORT_BASE_COM1,
		.line_info = default_line_info,
	},
	{
		.io_base = IO_PORT_BASE_COM2,
		.line_info = default_line_info,
	},
};

static void enable_interrupts(int minor)
{
	struct uart16550 *dev = &devs[minor];
	u8 ier;		/* IER - Interrupt Enable Register */

	/*
	 * Enable the following interrupts:
	 * 1. Received Data Available Interrupt
	 * 2. Transmitter Holding Register Empty Interrupt
	 * 3. Receiver Line Status Interrupt
	 */
	ier = 0x1 | 0x2 | 0x4;
	outb(ier, UART_16550_IER(dev->io_base));
}

static void disable_interrupts(int minor)
{
	struct uart16550 *dev = &devs[minor];
	u8 ier = 0;		/* IER - Interrupt Enable Register */

	outb(ier, UART_16550_IER(dev->io_base));
}

static void reset_fifo(int minor)
{
	struct uart16550 *dev = &devs[minor];
	u8 fcr;			/* FCR - FIFO Control Register */

	/*
	 * Enable FIFO & Clear TX and RX FIFOs
	 */
	fcr = 0x1 | 0x2 | 0x4;
	outb(fcr, UART_16550_FCR(dev->io_base));
}

/* Writes 'struct uart16550_line_info' parameters to the HW */
static void set_communication_params(int minor)
{
	struct uart16550 *dev = &devs[minor];
	u8 lcr;		/* LCR - Line Control Register */
	u8 dll;		/* DLL - Divisor Latch Lower Byte */

	/* Set word-length, parity, stop-bits and enable Divisor Latch access */
	lcr =	dev->line_info.len | dev->line_info.stop |
		dev->line_info.par | UART_16550_LCR_DLA_EN;
	outb(lcr, UART_16550_LCR(dev->io_base));

	/* Set DLL according to baud-rate */
	dll = dev->line_info.baud;
	outb(dll, UART_16550_DLL(dev->io_base));

	/* Disable Divisor Latch access */
	lcr = inb(UART_16550_LCR(dev->io_base));
	lcr &= ~UART_16550_LCR_DLA_EN;
	outb(lcr, UART_16550_LCR(dev->io_base));
}

static long
uart16550_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct uart16550 *dev = (struct uart16550 *) file->private_data;
	int minor = iminor(file->f_path.dentry->d_inode);
	struct uart16550_line_info new_line_info;

	if (cmd != UART16550_IOCTL_SET_LINE)
		return -EINVAL;

	if (copy_from_user(&new_line_info, (struct uart16550 *)arg, sizeof(new_line_info)) != 0)
		return -EFAULT;

	/* Line Info validation */
	if (new_line_info.baud != UART16550_BAUD_1200 &&
		new_line_info.baud != UART16550_BAUD_2400 &&
		new_line_info.baud != UART16550_BAUD_4800 &&
		new_line_info.baud != UART16550_BAUD_9600 &&
		new_line_info.baud != UART16550_BAUD_19200 &&
		new_line_info.baud != UART16550_BAUD_38400 &&
		new_line_info.baud != UART16550_BAUD_56000 &&
		new_line_info.baud != UART16550_BAUD_115200) {
		pr_err("%s: invalid baud rate provided\n", MODULE_NAME);
		return -EINVAL;
	}

	if (new_line_info.len != UART16550_LEN_5 &&
		new_line_info.len != UART16550_LEN_6 &&
		new_line_info.len != UART16550_LEN_7 &&
		new_line_info.len != UART16550_LEN_8) {
		pr_err("%s: invalid word length provided\n", MODULE_NAME);
		return -EINVAL;
	}

	if (new_line_info.par != UART16550_PAR_NONE &&
		new_line_info.par != UART16550_PAR_ODD &&
		new_line_info.par != UART16550_PAR_EVEN &&
		new_line_info.par != UART16550_PAR_STICK) {
		pr_err("%s: invalid parity provided\n", MODULE_NAME);
		return -EINVAL;
	}

	if (new_line_info.stop != UART16550_STOP_1 &&
		new_line_info.stop != UART16550_STOP_2) {
		pr_err("%s: invalid number of stop bits provided\n", MODULE_NAME);
		return -EINVAL;
	}

	/* Update line info parameters in HW */
	dev->line_info = new_line_info;

	disable_interrupts(minor);
	reset_fifo(minor);
	set_communication_params(minor);
	enable_interrupts(minor);

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

/* Initialization for one of 'struct uart16550' devices */
static int uart16550_init_minor(int minor)
{
	int err;

	/* Request IO region access */
	if (request_region(devs[minor].io_base, IO_PORT_NUM, MODULE_NAME) == NULL) {
		err = -EBUSY;
		goto out;
	}

	/* Initialize HW */
	disable_interrupts(minor);
	reset_fifo(minor);
	set_communication_params(minor);
	enable_interrupts(minor);

	/* Character device initialization */
	cdev_init(&devs[minor].cdev, &uart16550_fops);
	err = cdev_add(&devs[minor].cdev, MKDEV(major, minor), 1);
	if (err != 0) {
		pr_err("%s: cdev_add() failed: %d\n", MODULE_NAME, err);
		goto out_release_region;
	}

	return 0;

out_release_region:
	release_region(devs[minor].io_base, IO_PORT_NUM);
out:
	return err;
}

/* Free() for one of 'struct uart16550' devices */
static void uart16550_free_minor(int minor)
{
	cdev_del(&devs[minor].cdev);
	release_region(devs[minor].io_base, IO_PORT_NUM);
}

static int uart16550_init(void)
{
	int err;

	err = parse_option_arg();
	if (err != 0)
		goto out;
	
	err = register_chrdev_region(MKDEV(major, start_minor),
				     num_devices, MODULE_NAME);
	if (err != 0) {
		pr_err("%s: register_chrdev_region() failed: %d\n", MODULE_NAME, err);
		goto out;
	}

	if (option == OPTION_COM1 || option == OPTION_BOTH) {
		err = uart16550_init_minor(MINOR_COM1);
		if (err != 0)
			goto out_unregister;
	}

	if (option == OPTION_COM2 || option == OPTION_BOTH) {
		err = uart16550_init_minor(MINOR_COM2);
		if (err != 0) {
			if (option == OPTION_BOTH)
				uart16550_free_minor(MINOR_COM1);
			goto out_unregister;
		}
	}

	pr_notice("%s: loaded\n", MODULE_NAME);
	return 0;

out_unregister:
	unregister_chrdev_region(MKDEV(major, start_minor),
				 num_devices);
out:
	return err;
}

static void uart16550_exit(void)
{
	if (option == OPTION_COM1 || option == OPTION_BOTH)
		uart16550_free_minor(MINOR_COM1);
	if (option == OPTION_COM2 || option == OPTION_BOTH)
		uart16550_free_minor(MINOR_COM2);

	unregister_chrdev_region(MKDEV(major, start_minor),
				 num_devices);

	pr_notice("%s: unloaded\n", MODULE_NAME);
}

module_init(uart16550_init);
module_exit(uart16550_exit);
