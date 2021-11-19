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
#include <linux/mutex.h>

#include <linux/workqueue.h>
#include <linux/crc32.h>

#include "ssr.h"

MODULE_DESCRIPTION("Simple Software RAID");
MODULE_AUTHOR("Alexander Maydanik <alexander.maydanik@gmail.com>");
MODULE_LICENSE("GPL v2");

#define SSR_MODULE_NAME "ssr"
#define SSR_NUM_PHYSICAL_DISKS 2

static struct ssr_block_dev {
	struct gendisk *logical_disk;
	struct request_queue *queue;
	struct block_device *physical_disks[SSR_NUM_PHYSICAL_DISKS];

	/* Work queue for submitting bio requests to the physical disks */
	struct workqueue_struct *physical_wq;
	/* bio_set for cloned BIO requests */
	struct bio_set ssr_bioset;

	/* Used to make sure only 1 active submit_bio handled a time */
	struct mutex lock;
} ssr_dev;

/* Struct representing a single bio request work item */
struct ssr_bio_req {
	struct ssr_block_dev *dev;
	struct block_device *phy_dev; /* Physical device targeted by bio_req */
	struct bio *bio;
	struct work_struct work;
	int err; /* 0 - success or ERRNO */
};

static void ssr_bio_rq_work_handler(struct work_struct *work)
{
	struct ssr_bio_req *rq = container_of(work, struct ssr_bio_req, work);
	struct ssr_block_dev *dev = rq->dev;

	struct bio *bio_copy = bio_clone_fast(rq->bio, GFP_NOIO, &dev->ssr_bioset);
	if (!bio_copy) {
		rq->err = -ENOMEM;
		return;
	}
	bio_copy->bi_disk = rq->phy_dev->bd_disk;
	
	rq->err = submit_bio_wait(bio_copy);
	bio_put(bio_copy);
}

static inline sector_t sector_to_crc32_sector(sector_t sector)
{
	sector_t crc32_sector = sector * sizeof(u32) / KERNEL_SECTOR_SIZE;
	return LOGICAL_DISK_SECTORS + crc32_sector;
}

static inline unsigned int sector_to_crc32_sector_offset(sector_t sector)
{
	return (sector * sizeof(u32)) % KERNEL_SECTOR_SIZE;
}

/* 
 * Allocates and returns `bio` request for reading crc32 sectors matching `data_bio`.
 * Caller is responsible to free both physical pages and the bio struct.
 */
static struct bio *ssr_create_crc32_bio_read(struct bio *data_bio)
{
	int i;
	sector_t sector = data_bio->bi_iter.bi_sector;
	u32 num_sectors = bio_sectors(data_bio);
	u32 num_crc32_pages = roundup(num_sectors * sizeof(u32), PAGE_SIZE) / PAGE_SIZE;
	
	struct bio *bio_crc32 = bio_alloc(GFP_NOIO, num_crc32_pages);
	if (!bio_crc32)
		return NULL;
	
	/* 
	 * Specify start sector & direction.
	 */
	bio_crc32->bi_disk = data_bio->bi_disk;
	bio_crc32->bi_iter.bi_sector = sector_to_crc32_sector(sector);
	bio_crc32->bi_opf = REQ_OP_READ;

	/* Allocate and add pages */
	for (i = 0; i < num_crc32_pages; i++) {
		struct page *page = alloc_page(GFP_NOIO);
		if (!page)
			goto failure;
		if (bio_add_page(bio_crc32, page, PAGE_SIZE, 0) != PAGE_SIZE)
			goto failure;
	}

	return bio_crc32;

failure:
	bio_free_pages(bio_crc32);
	bio_put(bio_crc32);
	return NULL;
}

/*
 * Computes crc32 over 'bio' pages and compares against 'bio_crc32'.
 * Returns 0 if crc32 is correct.
 *
 * if update == 1: updates crc32 values in 'bio_crc32' and always returns 0.
 */
static int ssr_compute_crc32(struct bio *bio, struct bio *bio_crc32, int update)
{
	int i;
	struct bio_vec bvec, bvec_crc32;
	struct bvec_iter iter, iter_crc32;

	bio_for_each_segment(bvec, bio, iter) {
		sector_t sector = iter.bi_sector;
		char *data = kmap_atomic(bvec.bv_page);

		/* Go over all sectors in the page */
		for (i = 0; i < bvec.bv_len / KERNEL_SECTOR_SIZE; i++, sector++) {
			u32 crc32 = crc32(0, data + i * KERNEL_SECTOR_SIZE, KERNEL_SECTOR_SIZE);

			/* Go to matching crc32 page & update */
			bio_for_each_segment(bvec_crc32, bio_crc32, iter_crc32) {
				sector_t sector_crc32 = iter_crc32.bi_sector;

				if (sector_to_crc32_sector(sector) >= sector_crc32 &&
				    sector_to_crc32_sector(sector) < sector_crc32 + PAGE_SIZE / KERNEL_SECTOR_SIZE) {
					char *crc32_page = kmap_atomic(bvec_crc32.bv_page);

					u32 crc32_offset = sector_to_crc32_sector_offset(sector);

					if (update) {
						memcpy(crc32_page + crc32_offset, &crc32, sizeof(u32));
					} else {
						if (memcmp(crc32_page + crc32_offset, &crc32, sizeof(u32)) != 0) {
							/* Invalid crc */
							kunmap_atomic(crc32_page);
							kunmap_atomic(data);
							return -1;
						}
					}

					kunmap_atomic(crc32_page);
					break;
				}
			}
		}

		kunmap_atomic(data);
	}

	return 0;
}

/* Creates bio request and submits to the specified physical device */
static int _ssr_submit_bio(struct bio *bio, struct block_device *phy_dev)
{
	int err;
	struct ssr_block_dev *dev = bio->bi_disk->private_data;
	struct ssr_bio_req *rq = kzalloc(sizeof(*rq), GFP_NOIO);
	if (!rq) {
		err = -ENOMEM;
		goto end;
	}	

	/* Initialize ssr_bio_req work item and send it to work queue for processing */
	rq->dev = dev;
	rq->phy_dev = phy_dev;
	rq->bio = bio;
	INIT_WORK(&rq->work, ssr_bio_rq_work_handler);

	queue_work(dev->physical_wq, &rq->work);
	flush_workqueue(dev->physical_wq);
	err = rq->err;

end:
	if (rq)
		kfree(rq);
	return err;
}

static inline int _ssr_read_data_crc(struct bio *bio, struct bio *bio_crc32, struct block_device *phy_dev)
{
	if (_ssr_submit_bio(bio, phy_dev) != 0)
		return -EIO;
	if (_ssr_submit_bio(bio_crc32, phy_dev) != 0)
		return -EIO;
	return 0;
}

static inline int _ssr_write_data_crc(struct bio *bio, struct bio *bio_crc32, struct block_device *phy_dev)
{
	/* Backup bi_opf, and specify write operation */
	unsigned int bi_opf_backup = bio->bi_opf;
	bio->bi_opf = REQ_OP_WRITE;

	/* Write Data */
	if (_ssr_submit_bio(bio, phy_dev) != 0) {
		bio->bi_opf = bi_opf_backup;
		return -EIO;
	}
	bio->bi_opf = bi_opf_backup;
		
	/* Read relevant CRC sectors */
	if (_ssr_submit_bio(bio_crc32, phy_dev) != 0)
		return -EIO;
	/* Compute & Update CRC sectors */
	ssr_compute_crc32(bio, bio_crc32, 1);
	/* Write back CRC sectors */
	bio_crc32->bi_opf = REQ_OP_WRITE;
	if (_ssr_submit_bio(bio_crc32, phy_dev) != 0)
		return -EIO;
	return 0;
}

static blk_qc_t ssr_submit_bio(struct bio *bio)
{
	int i, res1, res2;
	struct ssr_block_dev *dev = bio->bi_disk->private_data;
	struct bio *bio_crc32 = ssr_create_crc32_bio_read(bio);

	mutex_lock(&ssr_dev.lock);
	if (!bio_crc32)
		goto bio_error;

	if (bio_data_dir(bio) == READ) {
		/* Read data & crc from both disks and check correctness */
		if (_ssr_read_data_crc(bio, bio_crc32, dev->physical_disks[0]) != 0)
			goto bio_error;
		res1 = ssr_compute_crc32(bio, bio_crc32, 0);

		if (_ssr_read_data_crc(bio, bio_crc32, dev->physical_disks[1]) != 0)
			goto bio_error;
		res2 = ssr_compute_crc32(bio, bio_crc32, 0);

		if (res1 != 0 && res2 != 0) {
			goto bio_error;
		} else if (res1 != 0) {
			/* Error recovery for disk1 */
			if (_ssr_write_data_crc(bio, bio_crc32, dev->physical_disks[0]) != 0)
				goto bio_error;
		} else if (res2 != 0) {
			/* Error recovery for disk2 */
			if (_ssr_read_data_crc(bio, bio_crc32, dev->physical_disks[0]) != 0)
				goto bio_error;
			if (_ssr_write_data_crc(bio, bio_crc32, dev->physical_disks[1]) != 0)
				goto bio_error;
		}
	} else {
		for (i = 0; i < SSR_NUM_PHYSICAL_DISKS; i++) {
			if (_ssr_write_data_crc(bio, bio_crc32, dev->physical_disks[i]) != 0)
				goto bio_error;
		}
	}
	
	if (bio_crc32) {
		bio_free_pages(bio_crc32);
		bio_put(bio_crc32);
	}

	bio_endio(bio);
	mutex_unlock(&ssr_dev.lock);
	return BLK_QC_T_NONE;

bio_error:
	if (bio_crc32) {
		bio_free_pages(bio_crc32);
		bio_put(bio_crc32);
	}

	bio_io_error(bio);
	mutex_unlock(&ssr_dev.lock);
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
	int i;

	mutex_init(&ssr_dev.lock);

	err = register_blkdev(SSR_MAJOR, SSR_MODULE_NAME);
	if (err < 0) {
		pr_err("SSR: unable to register SSR block device\n");
		return -EBUSY;
	}

	err = bioset_init(&ssr_dev.ssr_bioset, BIO_POOL_SIZE, 0, 0);
	if (err < 0) {
		pr_err("SSR: unable to initialize bioset\n");
		goto error;
	}

	ssr_dev.physical_wq = create_singlethread_workqueue(SSR_MODULE_NAME "_wq");
	if (!ssr_dev.physical_wq) {
		pr_err("SSR: Failed to create workqueue.\n");
		err = -ENOMEM;
		goto error;
	}

	/* Get physical disks 'block_device' struct */
	ssr_dev.physical_disks[0] = blkdev_get_by_path(PHYSICAL_DISK1_NAME, FMODE_READ|FMODE_WRITE, THIS_MODULE);
	ssr_dev.physical_disks[1] = blkdev_get_by_path(PHYSICAL_DISK2_NAME, FMODE_READ|FMODE_WRITE, THIS_MODULE);
	if (!ssr_dev.physical_disks[0] || !ssr_dev.physical_disks[1]) {
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
	for (i = 0; i < SSR_NUM_PHYSICAL_DISKS; i++)
		if (ssr_dev.physical_disks[i])
			blkdev_put(ssr_dev.physical_disks[i], FMODE_READ|FMODE_WRITE);

	if (ssr_dev.physical_wq)
		destroy_workqueue(ssr_dev.physical_wq);

	bioset_exit(&ssr_dev.ssr_bioset);
	unregister_blkdev(SSR_MAJOR, SSR_MODULE_NAME);
	return err;
}

static void ssr_exit(void)
{
	int i;

	delete_block_device(&ssr_dev);

	for (i = 0; i < SSR_NUM_PHYSICAL_DISKS; i++)
		blkdev_put(ssr_dev.physical_disks[i], FMODE_READ|FMODE_WRITE);

	destroy_workqueue(ssr_dev.physical_wq);
	bioset_exit(&ssr_dev.ssr_bioset);

	unregister_blkdev(SSR_MAJOR, SSR_MODULE_NAME);
}

module_init(ssr_init);
module_exit(ssr_exit);