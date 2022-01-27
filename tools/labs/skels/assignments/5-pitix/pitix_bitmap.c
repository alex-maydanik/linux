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
	mark_buffer_dirty(sbi->sb_bh);

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
	mark_buffer_dirty(sbi->sb_bh);
}

int pitix_get_block(struct inode *inode, sector_t block,
		struct buffer_head *bh_result, int create)
{
	/* TODO: Support block allocation - indirect */
	struct pitix_super_block *psb = pitix_sb(inode->i_sb);
	sector_t disk_block = 0;
	struct buffer_head *bh;
	__u16 *indirect_blocks;
	struct pitix_inode *pi = &(container_of(inode,
			struct pitix_inode_info, vfs_inode))->p_inode;
	
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
			goto success;
		}

		return -EIO;
	} else {
		/* Indirect data block */
		if (pi->indirect_data_block == 0)
			return -EIO;
		
		bh = sb_bread(inode->i_sb, psb->dzone_block + pi->indirect_data_block);
		if (bh == NULL) {
			pr_err("PITIX: could not read block\n");
			return -EIO;
		}
		indirect_blocks = (__u16 *)bh->b_data;
		disk_block = indirect_blocks[block - INODE_DIRECT_DATA_BLOCKS];

		if (disk_block == 0) {
			brelse(bh);
			return -EIO;
		}


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
	mark_buffer_dirty(sbi->sb_bh);

	/* Initialize inode fields */
	inode->i_ino = free_ino;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_blocks = 0;
	insert_inode_hash(inode);
	mark_inode_dirty(inode);

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
	mark_buffer_dirty(sbi->sb_bh);

	brelse(bh);
}