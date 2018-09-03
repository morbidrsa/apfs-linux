// SPDX-License-Identifier: GPL-2.0
/*
 * inode.c - APFS inode handling
 *
 * Copyright (C) 2018 Johannes Thumshirn
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>

#include "apfs.h"

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

/**
 * apfs_iget() - Get an inode
 * @sb:		the super block to get the inode for
 * @ino:	the number of the inode to get
 */
struct inode *apfs_iget(struct super_block *sb, ino_t ino)
{
	struct inode			*inode;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode->i_state & I_NEW))
		return inode;

	if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &apfs_dir_inode_ops;
		inode->i_fop = &apfs_dir_fops;
	}

	unlock_new_inode(inode);
	return inode;
}

