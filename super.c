// SPDX-License-Identifier: GPL-2.0
/*
 * super.c - APFS kernel super block handling
 *
 * Copyright (C) 2018 Johannes Thumshirn
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/fs.h>


/**
 * apfs_mount - mount an APFS file system
 * @fs_type:	the filesytem type
 * @flags:	mount flags passed in
 * @dev_name:	block device name to mount
 * @data:	mount options
 */
static struct dentry *apfs_mount(struct file_system_type *fs_type, int flags,
				 const char *dev_name, void *data)
{
	return NULL;
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
