/*
 * ssr.c - Driver for Software-Defined RAID
 *
 * Author: Alexander Maydanik <alexander.maydanik@gmail.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/genhd.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/vmalloc.h>

#include "ssr.h"

MODULE_DESCRIPTION("Simple Software RAID");
MODULE_AUTHOR("Alexander Maydanik <alexander.maydanik@gmail.com>");
MODULE_LICENSE("GPL v2");

#define SSR_MODULE_NAME "ssr"

static struct ssr_block_dev {
	struct gendisk *logical_disk;
	struct request_queue *queue;
} ssr_dev;

static int ssr_block_transfer(struct ssr_block_dev *dev, sector_t sector,
		unsigned long len, char *buffer, int dir)
{
	unsigned long offset = sector * KERNEL_SECTOR_SIZE;

	/* Check for read/write beyond end of block device */
	if ((offset + len) > LOGICAL_DISK_SIZE)
		return -ENOSPC;

	return 0;
}

static blk_qc_t ssr_submit_bio(struct bio *bio)
{
	struct ssr_block_dev *dev = bio->bi_disk->private_data;
	struct bio_vec bvec;
	struct bvec_iter iter;
	int dir = bio_data_dir(bio);
	int err;

	bio_for_each_segment(bvec, bio, iter) {
		sector_t sector = iter.bi_sector;
		unsigned long offset = bvec.bv_offset;
        	size_t len = bvec.bv_len;
		char *buffer = kmap_atomic(bvec.bv_page);

		pr_debug("SSR: Got BIO: sector %llu offset %lu len %u dir %c\n", sector, offset, len, dir ? 'W' : 'R');

		err = ssr_block_transfer(dev, sector, len, buffer + offset, dir);
		kunmap_atomic(buffer);

		if (err < 0)
			goto io_error;
	}

	bio_endio(bio);
	return BLK_QC_T_NONE;
io_error:
	bio_io_error(bio);
	return BLK_QC_T_NONE;
}

static const struct block_device_operations ssr_block_ops = {
	.owner = THIS_MODULE,
	.submit_bio = ssr_submit_bio,
};

static int create_block_device(struct ssr_block_dev *dev)
{
	/* Initialize request queue */
	dev->queue = blk_alloc_queue(NUMA_NO_NODE);
	if (dev->queue == NULL) {
		pr_err("SRR: blk_alloc_queue() failure\n");
		return -ENOMEM;
	}
	blk_queue_logical_block_size(dev->queue, KERNEL_SECTOR_SIZE);

	/* Initialize logical disk 'genhd' structure */
	dev->logical_disk = alloc_disk(SSR_NUM_MINORS);
	if (!dev->logical_disk) {
		pr_err("SRR: alloc_disk() failure\n");
		goto free_queue;
	}

	dev->logical_disk->major = SSR_MAJOR;
	dev->logical_disk->first_minor = SSR_FIRST_MINOR;
	dev->logical_disk->fops = &ssr_block_ops;
	dev->logical_disk->private_data = dev;
	dev->logical_disk->queue = dev->queue;
	snprintf(dev->logical_disk->disk_name, sizeof(SSR_MODULE_NAME), SSR_MODULE_NAME);
	set_capacity(dev->logical_disk, LOGICAL_DISK_SECTORS);

	add_disk_no_queue_reg(dev->logical_disk);

	return 0;

free_queue:
	blk_cleanup_queue(dev->queue);
	return -ENOMEM;
}

static void delete_block_device(struct ssr_block_dev *dev)
{
	del_gendisk(dev->logical_disk);
	put_disk(dev->logical_disk);

	blk_cleanup_queue(dev->queue);
}

static int __init ssr_init(void)
{
	int err = 0;

	err = register_blkdev(SSR_MAJOR, SSR_MODULE_NAME);
	if (err < 0) {
		pr_err("SSR: unable to register SSR block device\n");
		return -EBUSY;
	}

	err = create_block_device(&ssr_dev);
	if (err < 0)
		goto error;

	return 0;

error:
	unregister_blkdev(SSR_MAJOR, SSR_MODULE_NAME);
	return err;
}

static void ssr_exit(void)
{
	delete_block_device(&ssr_dev);
	unregister_blkdev(SSR_MAJOR, SSR_MODULE_NAME);
}

module_init(ssr_init);
module_exit(ssr_exit);