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
#include <linux/bitops.h>

#include "pitix.h"

#define DEBUG

MODULE_DESCRIPTION("PITIX Filesystem");
MODULE_AUTHOR("Alexander Maydanik <alexander.maydanik@gmail.com>");
MODULE_LICENSE("GPL v2");

#define PITIX_SUPER_BLOCK	0
#define PITIX_VERSION		2
#define PITIX_ROOT_INODE	0

static DEFINE_SPINLOCK(bitmap_lock);

struct pitix_inode_info {
	struct pitix_inode p_inode;
	struct inode vfs_inode;
};

struct file_operations pitix_file_operations = {
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.llseek		= generic_file_llseek,
};

struct inode_operations pitix_file_inode_operations = {
	.getattr	= simple_getattr,
};

int pitix_get_block(struct inode *inode, sector_t block,
		struct buffer_head *bh_result, int create)
{
	/* TODO: Support create() */
	struct pitix_super_block *psb = pitix_sb(inode->i_sb);
	sector_t disk_block = 0;
	struct buffer_head *bh;
	__u16 *indirect_blocks;
	struct pitix_inode *pi = &(container_of(inode,
			struct pitix_inode_info, vfs_inode))->p_inode;
	
	if (block < INODE_DIRECT_DATA_BLOCKS) {
		disk_block = pi->direct_data_blocks[block];
		if (disk_block == 0)
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

	map_bh(bh_result, inode->i_sb, psb->dzone_block + disk_block);
	return 0;
}

static int pitix_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, pitix_get_block);
}

static sector_t pitix_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, pitix_get_block);
}

struct address_space_operations pitix_aops = {
	.readpage = pitix_readpage,
	//.writepage = minix_writepage,
	//.write_begin = minix_write_begin,
	//.write_end = generic_write_end,
	.bmap = pitix_bmap
};

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

static struct dentry *pitix_lookup(struct inode *dir,
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
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}

	d_add(dentry, inode);
	brelse(bh);

	pr_debug("PITIX: looked up dentry %s\n", dentry->d_name.name);

	return NULL;
}

static int pitix_readdir(struct file *filp, struct dir_context *ctx)
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

struct inode *pitix_new_inode(struct super_block *sb)
{
	struct pitix_inode_info *pii;

	pii = kzalloc(sizeof(struct pitix_inode_info), GFP_KERNEL);
	if (pii == NULL)
		return NULL;

	inode_init_once(&pii->vfs_inode);

	return &pii->vfs_inode;
}

struct file_operations pitix_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= pitix_readdir,
};

struct inode_operations pitix_dir_inode_operations = {
	.lookup		= pitix_lookup,
};

int pitix_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	return 0;
}

static void pitix_destroy_inode(struct inode *inode)
{
	kfree(container_of(inode, struct pitix_inode_info, vfs_inode));
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
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(sbi->imap_bh);

	/* Initialize inode fields */
	/* TODO: inode_init_owner(inode, dir, mode); */
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
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(sbi->imap_bh);
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
	inode->i_mapping->a_ops = &pitix_aops;

	if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &pitix_dir_inode_operations;
		inode->i_fop = &pitix_dir_operations;
		inc_nlink(inode);
	}

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &pitix_file_inode_operations;
		inode->i_fop = &pitix_file_operations;
	}

	/* Fill data for pitix_inode_info */
	pii = container_of(inode, struct pitix_inode_info, vfs_inode);
	memcpy(&pii->p_inode, raw_inode, inode_size());

	/* Free resources. */
	brelse(bh);
	unlock_new_inode(inode);

	return inode;
}

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