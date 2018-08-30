// SPDX-License-Identifier: GPL-2.0
/*
 * super.c - APFS kernel super block handling
 *
 * Copyright (C) 2018 Johannes Thumshirn
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/buffer_head.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>

#include "apfs.h"

/**
 * apfs_fill_super - mount an APFS file system
 * @sb:		VFS super block to fill
 * @dp:		fs private mount data
 * @silent:	remain silent even if errors are detected
 *
 * apfs_fill_super() is called by the VFS to mount the device
 * described by @sb with a APFS file system.
 *
 * NOTE: @sb->s_flags will get SB_RDONLY flag added.
 */
static int apfs_fill_super(struct super_block *sb, void *dp, int silent)
{
	struct apfs_nxsb_info		*apfs_info;
	unsigned long			bsize;

	sb->s_flags |= SB_RDONLY;

	apfs_info = kzalloc(sizeof(*apfs_info), GFP_KERNEL);
	if (!apfs_info)
		return -ENOMEM;

	sb->s_fs_info = apfs_info;

	bsize = sb_min_blocksize(sb, BLOCK_SIZE);
	if (!bsize) {
		pr_err("unable to set blocksize\n");
		goto free_info;
	}

	return 0;

free_info:
	kfree(apfs_info);

	return -EINVAL;
}

/**
 * apfs_mount - mount an APFS file system
 * @fs_type:	the filesytem type
 * @flags:	mount flags passed in
 * @dev_name:	block device name to mount
 * @data:	mount options
 *
 * This is only a wrapper over the generic mount_bdev() function. It
 * passes apfs_fill_super() as the fill_super callback.
 */
static struct dentry *apfs_mount(struct file_system_type *fs_type, int flags,
				 const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, apfs_fill_super);
}

static struct file_system_type apfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "apfs",
	.mount = apfs_mount,
	.kill_sb = kill_block_super,
	.fs_flags = FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("apfs");

static int __init apfs_init(void)
{
	int err;

	err = register_filesystem(&apfs_fs_type);
	if (err) {
		pr_err("failed to register APFS: %d\n", err);
		return err;
	}

	return 0;
}
module_init(apfs_init);

static void __exit apfs_exit(void)
{
	unregister_filesystem(&apfs_fs_type);
	return;
}
module_exit(apfs_exit);

MODULE_AUTHOR("Johannes Thumshirn");
MODULE_LICENSE("GPL v2");
