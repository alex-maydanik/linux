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

#include <linux/workqueue.h>

#include "ssr.h"

MODULE_DESCRIPTION("Simple Software RAID");
MODULE_AUTHOR("Alexander Maydanik <alexander.maydanik@gmail.com>");
MODULE_LICENSE("GPL v2");

#define SSR_MODULE_NAME "ssr"

static struct ssr_block_dev {
	struct gendisk *logical_disk;
	struct request_queue *queue;
	struct block_device *physical_disk1, *physical_disk2;

	/* Work queue for submitting bio requests to the physical disks */
	struct workqueue_struct *physical_wq;
} ssr_dev;

/* Struct representing a single bio request work item */
struct ssr_bio_req {
	struct ssr_block_dev *dev;
	struct bio *bio;
	struct work_struct work;
	int err; /* 0 - success or ERRNO */
};

static void ssr_bio_rq_work_handler(struct work_struct *work)
{
	struct ssr_bio_req *rq = container_of(work, struct ssr_bio_req, work);

	pr_info("SSR: got bio request\n");
}

static blk_qc_t ssr_submit_bio(struct bio *bio)
{
	struct ssr_block_dev *dev = bio->bi_disk->private_data;
	struct ssr_bio_req *rq = kzalloc(sizeof(*rq), GFP_ATOMIC);
	if (!rq)
		goto io_error;

	/* Initialize ssr_bio_req work item and send it to work queue for processing */
	rq->dev = dev;
	rq->bio = bio;
	INIT_WORK(&rq->work, ssr_bio_rq_work_handler);

	queue_work(dev->physical_wq, &rq->work);
	flush_workqueue(dev->physical_wq);

	if (rq->err < 0)
		goto io_error;

	kfree(rq);
	bio_endio(bio);
	return BLK_QC_T_NONE;

io_error:
	kfree(rq);
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

	ssr_dev.physical_wq = create_singlethread_workqueue(SSR_MODULE_NAME "_wq");
	if (!ssr_dev.physical_wq) {
		pr_err("SSR: Failed to create workqueue.\n");
		err = -ENOMEM;
		goto error;
	}

	/* Get physical disks 'block_device' struct */
	ssr_dev.physical_disk1 = blkdev_get_by_path(PHYSICAL_DISK1_NAME, FMODE_READ|FMODE_WRITE, THIS_MODULE);
	ssr_dev.physical_disk2 = blkdev_get_by_path(PHYSICAL_DISK2_NAME, FMODE_READ|FMODE_WRITE, THIS_MODULE);
	if (!ssr_dev.physical_disk1 || !ssr_dev.physical_disk2) {
		pr_err("SSR: Failed to access physical disk. blkdev_get_by_path() failed.\n");
		err = -EINVAL;
		goto error;
	}

	err = create_block_device(&ssr_dev);
	if (err < 0) {
		pr_err("SSR: failed to create SSR block device\n");
		goto error;
	}

	return 0;

error:
	if (ssr_dev.physical_disk1)
		blkdev_put(ssr_dev.physical_disk1, FMODE_READ|FMODE_WRITE);
	if (ssr_dev.physical_disk2)
		blkdev_put(ssr_dev.physical_disk2, FMODE_READ|FMODE_WRITE);

	if (ssr_dev.physical_wq)
		destroy_workqueue(ssr_dev.physical_wq);

	unregister_blkdev(SSR_MAJOR, SSR_MODULE_NAME);
	return err;
}

static void ssr_exit(void)
{
	delete_block_device(&ssr_dev);

	blkdev_put(ssr_dev.physical_disk1, FMODE_READ|FMODE_WRITE);
	blkdev_put(ssr_dev.physical_disk2, FMODE_READ|FMODE_WRITE);

	destroy_workqueue(ssr_dev.physical_wq);

	unregister_blkdev(SSR_MAJOR, SSR_MODULE_NAME);
}

module_init(ssr_init);
module_exit(ssr_exit);