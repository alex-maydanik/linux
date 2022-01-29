// SPDX-License-Identifier: GPL-2.0-only
/*
 * pitix_bitmap.c contains the code that handles the inode and block bitmaps
 *
 * Author: Alexander Maydanik <alexander.maydanik@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>

#include "pitix.h"

static DEFINE_SPINLOCK(bitmap_lock);

static __u32 count_used(__u8 *map, u32 block_size)
{
	__u32 used = 0;
	int i;

	for (i = 0; i < block_size; i++)
		used += hweight8(*map++);

	return used;
}

int pitix_alloc_block(struct super_block *sb)
{
	struct pitix_super_block *sbi = pitix_sb(sb);
	u32 num_blocks = get_blocks(sb);
	int free_block;

	/* Lookup DMAP for free slot */
	spin_lock(&bitmap_lock);
	free_block = find_first_zero_bit((void*)sbi->dmap, num_blocks);
	if (free_block >= num_blocks) {
		spin_unlock(&bitmap_lock);
		return -ENOSPC;
	}
	set_bit(free_block, (void*)sbi->dmap);
	sbi->bfree--;
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(sbi->dmap_bh);

	return free_block;
}

void pitix_free_block(struct super_block *sb, int block)
{
	struct pitix_super_block *sbi = pitix_sb(sb);

	/* Mark block as unused in DMAP */
	spin_lock(&bitmap_lock);
	clear_bit(block, (void*)sbi->dmap);
	sbi->bfree++;
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(sbi->dmap_bh);
}

unsigned long pitix_count_free_blocks(struct super_block *sb)
{
	struct pitix_super_block *sbi = pitix_sb(sb);

	return get_blocks(sb) - count_used(sbi->dmap, sb->s_blocksize);
}

int pitix_get_block(struct inode *inode, sector_t block,
		struct buffer_head *bh_result, int create)
{
	struct pitix_super_block *psb = pitix_sb(inode->i_sb);
	sector_t disk_block = 0;
	struct buffer_head *bh;
	__u16 *indirect_blocks;
	__u16 max_blocks = INODE_DIRECT_DATA_BLOCKS + inode->i_sb->s_blocksize / sizeof(__u16);
	struct pitix_inode *pi = &(container_of(inode,
			struct pitix_inode_info, vfs_inode))->p_inode;
	
	if (block >= max_blocks) {
		pr_err("PITIX: reached maximum blocks per inode\n");
		return -EIO;
	}
	
	if (block < INODE_DIRECT_DATA_BLOCKS) {
		disk_block = pi->direct_data_blocks[block];
		if (disk_block)
			goto success;

		/* Allocate direct data block */
		if (create) {
			disk_block = pitix_alloc_block(inode->i_sb);
			if (disk_block < 0)
				return disk_block;
			pi->direct_data_blocks[block] = disk_block;
			mark_inode_dirty(inode);
			goto success;
		}

		return -EIO;
	} else {
		/* Indirect data block - allocate if required */
		if (pi->indirect_data_block == 0) {
			if (!create)
				return -EIO;

			disk_block = pitix_alloc_block(inode->i_sb);
			if (disk_block < 0)
				return disk_block;
			pi->indirect_data_block = disk_block;
			mark_inode_dirty(inode);
		}
		
		bh = sb_bread(inode->i_sb, psb->dzone_block + pi->indirect_data_block);
		if (bh == NULL) {
			pr_err("PITIX: could not read block\n");
			return -EIO;
		}
		indirect_blocks = (__u16 *)bh->b_data;
		disk_block = indirect_blocks[block - INODE_DIRECT_DATA_BLOCKS];

		if (disk_block == 0) {
			if (!create) {
				brelse(bh);
				return -EIO;
			}

			/* Allocate data block pointed by indirect block */
			disk_block = pitix_alloc_block(inode->i_sb);
			if (disk_block < 0) {
				brelse(bh);
				return disk_block;
			}

			indirect_blocks[block - INODE_DIRECT_DATA_BLOCKS] = disk_block;
			mark_buffer_dirty(bh);
		}

		brelse(bh);
	}

success:
	map_bh(bh_result, inode->i_sb, psb->dzone_block + disk_block);
	return 0;
}

int pitix_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, pitix_get_block, wbc);
}

int pitix_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, pitix_get_block);
}

static void pitix_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		/* TODO: Implement truncate */
		// pitix_truncate(inode);
	}
}

int pitix_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	ret = block_write_begin(mapping, pos, len, flags, pagep,
				pitix_get_block);
	if (unlikely(ret))
		pitix_write_failed(mapping, pos + len);

	return ret;
}

sector_t pitix_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, pitix_get_block);
}

struct pitix_inode *
pitix_raw_inode(struct super_block *sb, ino_t ino, struct buffer_head **bh)
{
	u32 block;
	struct pitix_super_block *psb = pitix_sb(sb);
	struct pitix_inode *p;

	*bh = NULL;
	if (ino > get_inodes(sb)) {
		pr_err("PITIX: Bad inode number on dev %s: %ld is out of range\n",
		       sb->s_id, (long)ino);
		return NULL;
	}

	block = psb->izone_block + ino / pitix_inodes_per_block(sb);
	*bh = sb_bread(sb, block);
	if (!*bh) {
		pr_err("PITIX: Unable to read inode block\n");
		return NULL;
	}
	p = (void *)(*bh)->b_data;
	return p + ino % pitix_inodes_per_block(sb);
}

int pitix_alloc_inode(struct super_block *sb)
{
	struct pitix_super_block *sbi = pitix_sb(sb);
	struct inode *inode = new_inode(sb);
	u32 num_inodes = get_inodes(sb);
	int free_ino;

	if (!inode)
		return -ENOMEM;

	/* Lookup IMAP for free slot */
	spin_lock(&bitmap_lock);
	free_ino = find_first_zero_bit((void*)sbi->imap, num_inodes);
	if (free_ino >= num_inodes) {
		spin_unlock(&bitmap_lock);
		iput(inode);
		return -ENOSPC;
	}
	set_bit(free_ino, (void*)sbi->imap);
	sbi->ffree--;
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(sbi->imap_bh);

	/* Initialize inode fields */
	inode->i_ino = free_ino;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_blocks = 0;
	insert_inode_hash(inode);
	mark_inode_dirty(inode);
	iput(inode);

	return free_ino;
}

void pitix_free_inode(struct super_block *sb, int ino)
{
	struct pitix_super_block *sbi = pitix_sb(sb);
	struct pitix_inode *pi;
	struct buffer_head *bh = NULL;
	
	/* Clear on-disk inode */
	pi = pitix_raw_inode(sb, ino, &bh);
	if (!pi) {
		pr_err("PITIX: inode %d not found\n", ino);
		return;
	}
	memset(pi, 0, sizeof(*pi));
	mark_buffer_dirty(bh);

	/* Mark inode as unused in IMAP */
	spin_lock(&bitmap_lock);
	clear_bit(ino, (void*)sbi->imap);
	sbi->ffree++;
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(sbi->imap_bh);

	brelse(bh);
}

unsigned long pitix_count_free_inodes(struct super_block *sb)
{
	struct pitix_super_block *sbi = pitix_sb(sb);

	return get_inodes(sb) - count_used(sbi->imap, sb->s_blocksize);
}

void pitix_truncate(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct pitix_inode *pi = &(container_of(inode,
			struct pitix_inode_info, vfs_inode))->p_inode;
	sector_t new_block_count = DIV_ROUND_UP((u32)inode->i_size, (u32)sb->s_blocksize);
	sector_t iblock = new_block_count;
	__u16 max_blocks = INODE_DIRECT_DATA_BLOCKS + sb->s_blocksize / sizeof(__u16);
	int disk_block;
	struct buffer_head *bh;
	__u16 *indirect_blocks = NULL;

	/* Fill with zeros the space that was left unused from the last block */
	block_truncate_page(inode->i_mapping, inode->i_size, pitix_get_block);

	/* Free unused blocks */
	do {
		if (iblock < INODE_DIRECT_DATA_BLOCKS) {
			disk_block = pi->direct_data_blocks[iblock];	
			pi->direct_data_blocks[iblock] = 0;
		} else {
			/* Indirect-Block */
			if (pi->indirect_data_block == 0)
				break;
			
			/* Read indirect block */
			if (indirect_blocks == NULL) {
				bh = sb_bread(inode->i_sb, pitix_sb(sb)->dzone_block + pi->indirect_data_block);
				if (bh == NULL) {
					pr_err("PITIX: could not read block\n");
					return;
				}
				indirect_blocks = (__u16 *)bh->b_data;
			}
			
			disk_block = indirect_blocks[iblock - INODE_DIRECT_DATA_BLOCKS];
			indirect_blocks[iblock - INODE_DIRECT_DATA_BLOCKS] = 0;
			mark_buffer_dirty(bh);
		}

		/* Check if done freeing */
		if (!disk_block)
			break;
		
		pitix_free_block(sb, disk_block);
	} while (++iblock < max_blocks);

	/* Free indirect data block if required */
	if (indirect_blocks) {
		pitix_free_block(sb, pi->indirect_data_block);
		pi->indirect_data_block = 0;
		brelse(bh);
	}

	/* Update inode */
	inode->i_mtime = inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);
}