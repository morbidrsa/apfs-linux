// SPDX-License-Identifier: GPL-2.0
/*
 * inode.c - APFS inode handling
 *
 * Copyright (C) 2018 Johannes Thumshirn
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>

#include "apfs.h"

#define APFS_KEY_SHIFT			60
enum apfs_key_type {
	KEY_TYPE_INODE =		3,
	KEY_TYPE_XATTR =		4,
	KEY_TYPE_FILE_EXTENT =		8,
	KEY_TYPE_DIR_RECORD =		9,
};

static int apfs_readdir(struct file *file, struct dir_context *ctx)
{
	return 0;
}

static const struct file_operations apfs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= apfs_readdir,
};

static struct dentry *apfs_lookup(struct inode *inode, struct dentry *dentry,
				  unsigned int flags)
{
	return ERR_PTR(-ENOENT);
}

static const struct inode_operations apfs_dir_inode_ops = {
	.lookup		= apfs_lookup,
};

int apfs_dir_keycmp(void *skey, size_t skey_len, void *ekey,
		    size_t ekey_len, void *ctx)
{
	u64				ks = *(u64 *) skey;
	u64				ke = *(u64 *) ekey;

	ks = (ks << 4) | (ks >> APFS_KEY_SHIFT);
	ke = (ke << 4) | (ke >> APFS_KEY_SHIFT);

	if (ke < ks)
		return -1;
	if (ke > ks)
		return 1;

	if (skey_len <= 8)
		return 0;

	switch (ks & 0xf) {
	case KEY_TYPE_DIR_RECORD:
		break;
	case KEY_TYPE_FILE_EXTENT:
		break;
	case KEY_TYPE_XATTR:
		break;
	}

	return 0;
}


/**
 * apfs_get_time() - convert the disk inode's time to a timespec64
 * @ts:		the @timespec64 to be filled
 * @dit:	the 64 Bit time of the disk inode
 */
static void apfs_get_time(struct timespec64 *ts, u64 dit)
{
	ts->tv_nsec = dit % 1000000000ull;
	ts->tv_sec = dit / 1000000000ull;
}

static int apfs_lookup_disk_inode(struct super_block *sb,
				  struct apfs_inode *apfs_inode,
				  ino_t ino)
{
	struct apfs_info 		*apfs_info = APFS_SBI(sb);
	struct inode			*inode = &apfs_inode->vfs_inode;
	struct apfs_dinode		*dinode = NULL;
	u64				key;
	struct apfs_btree_search_entry	*bte;
	int i;

	key = (u64) KEY_TYPE_INODE << APFS_KEY_SHIFT;
	key |= ino;

	bte = apfs_btree_lookup(apfs_info->dir_tree_root, &key, sizeof(key));
	if (!bte)
		return -ENOENT;

	dinode = bte->val;

	apfs_inode->mode = le32_to_cpu(dinode->mode);
	apfs_inode->nlink = le32_to_cpu(dinode->children);
	apfs_inode->uid = le32_to_cpu(dinode->uid);
	apfs_inode->gid = le32_to_cpu(dinode->gid);
	apfs_inode->size = le64_to_cpu(dinode->size);
	apfs_inode->mtime = le64_to_cpu(dinode->mtime);
	apfs_inode->atime = le64_to_cpu(dinode->atime);
	apfs_inode->ctime = le64_to_cpu(dinode->ctime);
	apfs_inode->generation = le32_to_cpu(dinode->generation);

	inode->i_mode = apfs_inode->mode;
	i_uid_write(inode, (uid_t)apfs_inode->uid);
	i_gid_write(inode, (gid_t)apfs_inode->gid);
	inode->i_size = apfs_inode->size;
	set_nlink(inode, apfs_inode->nlink);
	inode->i_generation = apfs_inode->generation;

	apfs_get_time(&inode->i_atime, apfs_inode->atime);
	apfs_get_time(&inode->i_mtime, apfs_inode->mtime);
	apfs_get_time(&inode->i_ctime, apfs_inode->ctime);

	apfs_btree_free_search_entry(bte);

	return 0;
}

/**
 * apfs_iget() - Get an inode
 * @sb:		the super block to get the inode for
 * @ino:	the number of the inode to get
 */
struct inode *apfs_iget(struct super_block *sb, ino_t ino)
{
	struct inode			*inode;
	struct apfs_inode		*apfs_inode;
	int				ret;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode->i_state & I_NEW))
		return inode;

	apfs_inode = APFS_INO(inode);
	ret = apfs_lookup_disk_inode(sb, apfs_inode, APFS_ROOT_INODE);
	if (ret) {
		iget_failed(inode);
		return ERR_PTR(ret);
	}

	if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &apfs_dir_inode_ops;
		inode->i_fop = &apfs_dir_fops;
	}

	unlock_new_inode(inode);
	return inode;
}

