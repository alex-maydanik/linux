// SPDX-License-Identifier: GPL-2.0-only
/*
 * pitix_inode.c contains the code that handles the inode operations
 *
 * Author: Alexander Maydanik <alexander.maydanik@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>

#include "pitix.h"

struct file_operations pitix_file_operations = {
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.llseek		= generic_file_llseek,
};

struct inode_operations pitix_file_inode_operations = {
	.getattr	= simple_getattr,
};

struct file_operations pitix_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= pitix_readdir,
};

struct inode_operations pitix_dir_inode_operations = {
	.lookup		= pitix_lookup,
	.mkdir		= pitix_mkdir,
	.create 	= pitix_create,
};

struct address_space_operations pitix_aops = {
	.readpage = pitix_readpage,
	//.writepage = minix_writepage,
	//.write_begin = minix_write_begin,
	//.write_end = generic_write_end,
	.bmap = pitix_bmap
};

void pitix_set_inode(struct inode *inode)
{
	inode->i_mapping->a_ops = &pitix_aops;

	if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &pitix_dir_inode_operations;
		inode->i_fop = &pitix_dir_operations;
		inc_nlink(inode);
	} else if (S_ISREG(inode->i_mode)) {
		inode->i_op = &pitix_file_inode_operations;
		inode->i_fop = &pitix_file_operations;
	}
}

struct inode *pitix_iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode;
	struct buffer_head *bh;
	struct pitix_inode *raw_inode;
	struct pitix_inode_info *pii;

	/* Allocate VFS inode. */
	inode = iget_locked(sb, ino);
	if (inode == NULL) {
		pr_err("PITIX: error allocating VFS inode\n");
		return ERR_PTR(-ENOMEM);
	}

	/* Return inode from cache */
	if (!(inode->i_state & I_NEW))
		return inode;

	/* Read relevant block from izone */
	raw_inode = pitix_raw_inode(sb, ino, &bh);
	if (!raw_inode) {
		iget_failed(inode);
		return ERR_PTR(-EIO);
	}

	/* Fill VFS inode */
	inode->i_mode = raw_inode->mode;
	i_uid_write(inode, raw_inode->uid);
	i_gid_write(inode, raw_inode->gid);
	inode->i_size = raw_inode->size;
	inode->i_blocks = 0;
	inode->i_mtime.tv_sec = inode->i_atime.tv_sec = inode->i_ctime.tv_sec = raw_inode->time;

	/* Fill inode operations */
	pitix_set_inode(inode);

	if (S_ISDIR(inode->i_mode))
		inc_nlink(inode);

	/* Fill data for pitix_inode_info */
	pii = container_of(inode, struct pitix_inode_info, vfs_inode);
	memcpy(&pii->p_inode, raw_inode, inode_size());

	/* Free resources. */
	brelse(bh);
	unlock_new_inode(inode);

	return inode;
}

int pitix_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct pitix_inode *raw_inode;
	struct buffer_head *bh;
	struct pitix_inode *p_inode = &container_of(inode, struct pitix_inode_info, vfs_inode)->p_inode;
	int i;
	int err = 0;

	raw_inode = pitix_raw_inode(inode->i_sb, inode->i_ino, &bh);
	if (!raw_inode)
		return -EIO;

	/* Update inode data on disk */
	raw_inode->mode = inode->i_mode;
	raw_inode->uid = i_uid_read(inode);
	raw_inode->gid = i_gid_read(inode);
	raw_inode->size = inode->i_size;
	raw_inode->time = inode->i_mtime.tv_sec;
	for (i = 0; i < INODE_DIRECT_DATA_BLOCKS; i++)
		raw_inode->direct_data_blocks[i] = p_inode->direct_data_blocks[i];
	raw_inode->indirect_data_block = p_inode->indirect_data_block;
	mark_buffer_dirty(bh);

	if (wbc->sync_mode == WB_SYNC_ALL && buffer_dirty(bh)) {
		sync_dirty_buffer(bh);
		if (buffer_req(bh) && !buffer_uptodate(bh)) {
			pr_err("PITIX: IO error syncing pitix inode [%s:%08lx]\n",
				inode->i_sb->s_id, inode->i_ino);
			err = -EIO;
		}
	}

	brelse(bh);
	return err;
}

void pitix_destroy_inode(struct inode *inode)
{
	kfree(container_of(inode, struct pitix_inode_info, vfs_inode));
}

struct inode *pitix_new_inode(struct super_block *sb)
{
	struct pitix_inode_info *pii;

	pii = kzalloc(sizeof(struct pitix_inode_info), GFP_KERNEL);
	if (pii == NULL)
		return NULL;

	inode_init_once(&pii->vfs_inode);

	return &pii->vfs_inode;
}