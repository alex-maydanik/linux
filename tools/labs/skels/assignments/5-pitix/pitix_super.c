// SPDX-License-Identifier: GPL-2.0-only
/*
 * pitix.c - PITIX filesystem.
 *
 * Author: Alexander Maydanik <alexander.maydanik@gmail.com>
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>
#include <linux/statfs.h>

#include "pitix.h"

MODULE_DESCRIPTION("PITIX Filesystem");
MODULE_AUTHOR("Alexander Maydanik <alexander.maydanik@gmail.com>");
MODULE_LICENSE("GPL v2");

static void pitix_put_super(struct super_block *sb)
{
	struct pitix_super_block *ps = sb->s_fs_info;

	/* Free superblock buffer head. */
	mark_buffer_dirty(ps->sb_bh);
	brelse(ps->sb_bh);

	/* Free IMAP & DMAP & Write-Back */
	mark_buffer_dirty(ps->dmap_bh);
	brelse(ps->dmap_bh);
	mark_buffer_dirty(ps->imap_bh);
	brelse(ps->imap_bh);

	sb->s_fs_info = NULL;
}

static int pitix_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct pitix_super_block *sbi = pitix_sb(sb);

	buf->f_type = sb->s_magic;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = get_blocks(sb);
	buf->f_bfree = sbi->bfree;
	buf->f_bavail = buf->f_bfree;
	buf->f_files = get_inodes(sb);
	buf->f_ffree = sbi->ffree;
	buf->f_namelen = PITIX_NAME_LEN;

	return 0;
}

struct super_operations pitix_sops = {
	.alloc_inode	= pitix_new_inode,
	.destroy_inode	= pitix_destroy_inode,
	// .evict_inode	= pitix_evict_inode,
	// .write_inode	= pitix_write_inode,
	.put_super	= pitix_put_super,
	.statfs		= pitix_statfs,
};

/* Valid block sizes are: 512, 1024, 2048 or 4096 */
static inline int pitix_validate_block_size(u8 block_size_bits)
{
	if (block_size_bits >= 9 && block_size_bits <= 12)
		return 1;
	return 0;
}

int pitix_fill_super(struct super_block *s, void *data, int silent)
{
	struct pitix_super_block *ps, *psi;
	struct buffer_head *bh, *dmap_bh, *imap_bh;
	struct inode *root_inode;
	struct dentry *root_dentry;
	int ret = -EINVAL;

	psi = kzalloc(sizeof(struct pitix_super_block), GFP_KERNEL);
	if (!psi)
		return -ENOMEM;
	s->s_fs_info = psi;

	/* Read PITIX super block from disk */
	bh = sb_bread(s, PITIX_SUPER_BLOCK);
	if (bh == NULL)
		goto out_bad_sb;
	ps = (struct pitix_super_block *) bh->b_data;

	/* Validate magic & version */
	if (ps->magic != PITIX_MAGIC || ps->version != PITIX_VERSION)
		goto out_bad_magic_version;

	s->s_magic = PITIX_MAGIC;
	s->s_op = &pitix_sops;
	psi->magic = ps->magic;
	psi->version = ps->version;
	psi->block_size_bits = ps->block_size_bits;
	psi->imap_block = ps->imap_block;
	psi->dmap_block = ps->dmap_block;
	psi->izone_block = ps->izone_block;
	psi->dzone_block = ps->dzone_block;
	psi->bfree = ps->bfree;
	psi->ffree = ps->ffree;

	/* Set block size for superblock. */
	if (!pitix_validate_block_size(ps->block_size_bits) || 
	    !sb_set_blocksize(s, 1 << ps->block_size_bits))
		goto out_bad_blocksize;

	/* Read imap & dmap */
	imap_bh = sb_bread(s, psi->imap_block);
	if (imap_bh == NULL)
		goto out_bad_imap;
	psi->imap = imap_bh->b_data;

	dmap_bh = sb_bread(s, psi->dmap_block);
	if (dmap_bh == NULL)
		goto out_bad_dmap;
	psi->dmap = dmap_bh->b_data;

	/* Allocate root inode and root dentry */
	root_inode = pitix_iget(s, PITIX_ROOT_INODE);
	if (!root_inode)
		goto out_bad_inode;

	root_dentry = d_make_root(root_inode);
	if (!root_dentry)
		goto out_iput;
	s->s_root = root_dentry;
	
	/* Store buffer_heads for further use. */
	psi->sb_bh = bh;
	psi->dmap_bh = dmap_bh;
	psi->imap_bh = imap_bh;

	return 0;

out_iput:
	iput(root_inode);
out_bad_inode:
	pr_err("PITIX: failed to get root inode\n");
	brelse(dmap_bh);
out_bad_dmap:
	pr_err("PITIX: error reading DMAP\n");
	brelse(imap_bh);
out_bad_imap:
	pr_err("PITIX: error reading IMAP\n");
out_bad_blocksize:
	pr_err("PITIX: bad block size\n");
out_bad_magic_version:
	pr_err("PITIX: bad magic/version number\n");
	brelse(bh);
out_bad_sb:
	pr_err("PITIX: error reading super-block\n");
	s->s_fs_info = NULL;
	kfree(psi);
	return ret;
}

static struct dentry *pitix_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, pitix_fill_super);
}

static void pitix_kill_block_super(struct super_block *sb)
{
	struct pitix_super_block *psi = pitix_sb(sb);
	kill_block_super(sb);
	kfree(psi);
}

static struct file_system_type pitix_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "pitix",
	.mount		= pitix_mount,
	.kill_sb	= pitix_kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};

static int __init init_pitix_fs(void)
{
	int err = 0;

	err = register_filesystem(&pitix_fs_type);
	if (err != 0) {
		pr_err("PITIX: register_filesystem() failed\n");
		return err;
	}

	return 0;
}

static void __exit exit_pitix_fs(void)
{
        unregister_filesystem(&pitix_fs_type);
}

module_init(init_pitix_fs)
module_exit(exit_pitix_fs)