// SPDX-License-Identifier: GPL-2.0-only
/*
 * pitix_inode.c contains the code that handles dentry related operations
 *
 * Author: Alexander Maydanik <alexander.maydanik@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>

#include "pitix.h"

static struct pitix_dir_entry *pitix_find_entry(struct dentry *dentry,
		struct buffer_head **bhp)
{
	struct buffer_head *bh;
	struct inode *dir = dentry->d_parent->d_inode;
	struct pitix_inode *pi = &(container_of(dir,
			struct pitix_inode_info, vfs_inode))->p_inode;
	struct super_block *sb = dir->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	const char *name = dentry->d_name.name;
	struct pitix_dir_entry *final_de = NULL;
	struct pitix_dir_entry *de;
	int i;

	/* 
	 * Read parent folder data block (contains dentries).
	 * Fill bhp with return value.
	 */
	bh = sb_bread(sb, psb->dzone_block + pi->direct_data_blocks[0]);
	if (bh == NULL) {
		pr_err("PITIX: could not read block\n");
		return NULL;
	}
	*bhp = bh;

	for (i = 0; i < dir_entries_per_block(sb); i++) {
		/* 
		 * Traverse all entries, find entry by name
		 * Use `de' to traverse. Use `final_de' to store dentry
		 * found, if existing.
		 */
		de = ((struct pitix_dir_entry *) bh->b_data) + i;
		if (de->ino != 0) {
			/* found it */
			if (strncmp(name, de->name, PITIX_NAME_LEN) == 0) {
				pr_debug("PITIX: Found entry %s on position: %zd\n",
					name, i);
				final_de = de;
				break;
			}
		}
	}

	/* bh needs to be released by caller. */
	return final_de;
}

struct dentry *pitix_lookup(struct inode *dir,
		struct dentry *dentry, unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct pitix_dir_entry *de;
	struct buffer_head *bh = NULL;
	struct inode *inode = NULL;

	dentry->d_op = sb->s_root->d_op;

	de = pitix_find_entry(dentry, &bh);
	if (de != NULL) {
		pr_debug("PITIX: getting entry: name: %s, ino: %d\n",
			de->name, de->ino);
		inode = pitix_iget(sb, de->ino);
		if (IS_ERR(inode)) {
			brelse(bh);
			return ERR_CAST(inode);
		}
			
	}

	d_add(dentry, inode);
	brelse(bh);

	pr_debug("PITIX: looked up dentry %s\n", dentry->d_name.name);

	return NULL;
}

int pitix_readdir(struct file *filp, struct dir_context *ctx)
{
	struct buffer_head *bh;
	struct pitix_dir_entry *de;
	struct pitix_inode *pi;
	struct inode *inode;
	struct super_block *sb;
	struct pitix_super_block *psb;
	int over;
	int err = 0;

	/* Get inode of directory and container inode. */
	inode = file_inode(filp);
	pi = &(container_of(inode, struct pitix_inode_info, vfs_inode))->p_inode;

	/* Get superblock from inode (i_sb). */
	sb = inode->i_sb;
	psb = pitix_sb(sb);

	/* Read data block for directory inode. */
	bh = sb_bread(sb, psb->dzone_block + pi->direct_data_blocks[0]);
	if (bh == NULL) {
		pr_err("PITIX: could not read block\n");
		err = -ENOMEM;
		goto out_bad_sb;
	}

	for (; ctx->pos < dir_entries_per_block(sb); ctx->pos++) {
		de = (struct pitix_dir_entry *) bh->b_data + ctx->pos;

		if (de->ino == 0) {
			continue;
		}

		/*
		 * Use `over` to store return value of dir_emit and exit
		 * if required.
		 */
		over = dir_emit(ctx, de->name, PITIX_NAME_LEN, de->ino,
				DT_UNKNOWN);
		if (over) {
			pr_debug("PITIX: Read %s from folder %s, ctx->pos: %lld\n",
				de->name,
				filp->f_path.dentry->d_name.name,
				ctx->pos);
			ctx->pos++;
			goto done;
		}
	}

done:
	brelse(bh);
out_bad_sb:
	return err;
}

int pitix_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int block;
	struct inode *inode;
	struct pitix_inode *pi;

	int err = pitix_create(dir, dentry, S_IFDIR | mode, 0);
	if (err < 0) {
		pr_err("PITIX: Failed on pitix_create()\n");
		return err;
	}

	inode = pitix_iget(dir->i_sb, dentry->d_inode->i_ino);
	if (!inode) {
		pr_err("PITIX: Failed to get inode\n");
		return -EIO;
	}
	pi = &(container_of(inode, struct pitix_inode_info, vfs_inode))->p_inode;

	/* Allocate data block for the directory dentries */
	err = block = pitix_alloc_block(dir->i_sb);
	if (err < 0) {
		pr_err("PITIX: Failed to allocate block\n");
		inode_dec_link_count(inode);
		iput(inode);
		return err;
	}
	pi->direct_data_blocks[0] = block;
	i_size_write(inode, inode->i_sb->s_blocksize);
	mark_inode_dirty(inode);
	iput(inode);

	return err;
}

int pitix_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	struct inode *inode;
	int ino, err;

	/* Allocate new inode on disk */
	ino = pitix_alloc_inode(dir->i_sb);
	if (ino < 0) {
		pr_err("PITIX: Failed to allocate inode\n");
		return ino;
	}
	inode = pitix_iget(dir->i_sb, ino);
	if (!inode) {
		pr_err("PITIX: Failed to get inode\n");
		return -EIO;
	}

	/* Configure inode mode and set inode operations */
	inode->i_mode = mode;
	pitix_set_inode(inode);
	mark_inode_dirty(inode);
	
	/* Add dentry -> inode link */
	err = pitix_add_link(dentry, inode);
	if (!err) {
		d_instantiate(dentry, inode);
		return 0;
	}
	inode_dec_link_count(inode);
	iput(inode);
	return err;
}

int pitix_add_link(struct dentry *dentry, struct inode *inode)
{
	struct buffer_head *bh;
	/* Get inode of directory and container inode. */
	struct inode *dir = d_inode(dentry->d_parent);
	struct pitix_inode *dir_pi = &(container_of(dir,
			struct pitix_inode_info, vfs_inode))->p_inode;
	struct super_block *sb = dir->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	struct pitix_dir_entry *de;
	int i;
	
	/* Read parent folder data block (contains dentries) */
	bh = sb_bread(sb, psb->dzone_block + dir_pi->direct_data_blocks[0]);
	if (bh == NULL) {
		pr_err("PITIX: could not read block\n");
		return -EIO;
	}

	/* Check if link already exists */
	for (i = 0; i < dir_entries_per_block(sb); i++) {
		de = ((struct pitix_dir_entry *) bh->b_data) + i;
		if (de->ino == inode->i_ino || !strncmp(de->name, dentry->d_name.name, PITIX_NAME_LEN)) {
			brelse(bh);
			return -EEXIST;
		}
	}

	/* Find empty dentry and create link */
	for (i = 0; i < dir_entries_per_block(sb); i++) {
		de = ((struct pitix_dir_entry *) bh->b_data) + i;
		if (de->ino == 0) {
			de->ino = inode->i_ino;
			strncpy(de->name, dentry->d_name.name, PITIX_NAME_LEN);
			goto found_it;
		}
	}

	brelse(bh);
	return -ENOSPC;

found_it:
	/* Update directory inode fields */
	dir->i_mtime = dir->i_ctime = current_time(dir);
	mark_inode_dirty(dir);

	mark_buffer_dirty(bh);
	brelse(bh);
	return 0;
}