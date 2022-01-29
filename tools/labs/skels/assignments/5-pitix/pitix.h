#ifndef _PITIX_H
#define _PITIX_H

#define PITIX_MAGIC			0x58495450 /* ascii little endian for PTIX */
#define IZONE_BLOCKS		32
#define INODE_DIRECT_DATA_BLOCKS 5
#define PITIX_NAME_LEN			16
#define PITIX_SUPER_BLOCK	0
#define PITIX_VERSION		2
#define PITIX_ROOT_INODE	0

/*
 *	filesystem layout:
 *
 *		SB		IMAP		DMAP		IZONE		DATA
 *	^		^ (1 block)  (1 block)  (32 blocks)
 *	|		|
 *	+-0		+-- 4096
 */

struct pitix_super_block {
	unsigned long magic;
	__u8 version;
	__u8 block_size_bits;
	__u8 imap_block;
	__u8 dmap_block;
	__u8 izone_block;
	__u8 dzone_block;
	__u16 bfree;
	__u16 ffree;
#ifdef __KERNEL__
	struct buffer_head *sb_bh, *dmap_bh, *imap_bh;
	__u8 *dmap, *imap;
#endif
};

struct pitix_dir_entry {
	__u32 ino;
	char name[PITIX_NAME_LEN];
};

struct pitix_inode {
	__u32 mode;
	uid_t uid;
	gid_t gid;
	__u32 size;
	__u32 time;
	__u16 direct_data_blocks[INODE_DIRECT_DATA_BLOCKS];
	__u16 indirect_data_block;
};

#ifdef __KERNEL__
static inline int inode_size(void)
{
	return sizeof(struct pitix_inode);
}

static inline int dir_entry_size(void)
{
	return sizeof(struct pitix_dir_entry);
}

static inline int dir_entries_per_block(struct super_block *sb)
{
	return sb->s_blocksize/dir_entry_size();
}

static inline long get_blocks(struct super_block *sb)
{
	return 8*sb->s_blocksize;
}

static inline long get_inodes(struct super_block *sb)
{
	return IZONE_BLOCKS*sb->s_blocksize/inode_size();
}

static inline long pitix_inodes_per_block(struct super_block *sb)
{
	return sb->s_blocksize / inode_size();
}

struct pitix_inode_info {
	struct pitix_inode p_inode;
	struct inode vfs_inode;
};

/* Bitmap operations */
extern int pitix_alloc_block(struct super_block *sb);
extern void pitix_free_block(struct super_block *sb, int block);
extern int pitix_alloc_inode(struct super_block *sb);
extern void pitix_free_inode(struct super_block *sb, int ino);
extern unsigned long pitix_count_free_blocks(struct super_block *sb);
extern unsigned long pitix_count_free_inodes(struct super_block *sb);
extern struct pitix_inode * pitix_raw_inode(struct super_block *sb, ino_t ino,
		struct buffer_head **bh);
extern int pitix_get_block(struct inode *inode, sector_t block,
		struct buffer_head *bh_result, int create);
extern sector_t pitix_bmap(struct address_space *mapping, sector_t block);
extern struct address_space_operations pitix_aops;

/* Dir operations */
extern struct inode_operations pitix_dir_inode_operations;
extern struct file_operations pitix_dir_operations;
ino_t pitix_inode_by_name(struct dentry *dentry, int delete);
extern struct dentry *pitix_lookup(struct inode *dir,
		struct dentry *dentry, unsigned int flags);
extern int pitix_readdir(struct file *filp, struct dir_context *ctx);
int pitix_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl);
int pitix_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode);
int pitix_add_link(struct dentry *dentry, struct inode *inode);

/* File operations */
extern struct file_operations pitix_file_operations;
extern struct inode_operations pitix_file_inode_operations;
void pitix_truncate(struct inode *inode);
int pitix_readpage(struct file *file, struct page *page);
int pitix_writepage(struct page *page, struct writeback_control *wbc);
int pitix_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata);
int pitix_setattr(struct dentry *dentry, struct iattr *attr);

/* Inode operations */
extern struct inode *pitix_new_inode(struct super_block *sb);
extern void pitix_destroy_inode(struct inode *inode);
extern int pitix_write_inode(struct inode *inode, struct writeback_control *wbc);
extern void pitix_evict_inode(struct inode *inode);
void pitix_set_inode(struct inode *inode);

extern struct inode *pitix_iget(struct super_block *sb, unsigned long ino);

/* Super operations */
extern int pitix_fill_super(struct super_block *sb, void *data, int silent);
extern struct super_operations pitix_sops;
#endif

static inline struct pitix_super_block *pitix_sb(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct pitix_inode *pitix_i(struct inode *inode)
{
	return inode->i_private;
}

#endif
