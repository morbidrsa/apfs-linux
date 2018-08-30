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

#define APFS_BLOCK_SIZE		4096

/**
 * apfs_put_super - free super block resources
 * @sb:		VFS superblock
 *
 * apfs_put_super() frees all resources for @sb after the last
 * instance is unmounted.
 */
static void apfs_put_super(struct super_block *sb)
{
	struct apfs_info		*apfs_info = APFS_SBI(sb);

	brelse(apfs_info->bp);
	kfree(apfs_info);
}

static const struct super_operations apfs_super_ops = {
	.put_super	= apfs_put_super,
};

/**
 * apfs_get_nxsb_magic - read on-disk container superblock
 * @sb:		VFS super block to save the on-disk super block
 * @silent:	remain silent even if errors are detected
 * @blk:	Disk block number to read the container super block from
 *
 * apfs_get_nxsb_magic() is called by apfs_fill_super() to read the
 * on-disk container super block and verify the magic number.
 */
static int apfs_get_nxsb_magic(struct super_block *sb, int silent, u64 blk)
{
	struct apfs_info		*apfs_info = APFS_SBI(sb);
	struct apfs_container_sb	*nxsb;
	struct buffer_head		*bp;
	int 				rc = -ENOMEM;

	bp = sb_bread(sb, blk);
	if (!bp || !buffer_mapped(bp)) {
		if (!silent)
			pr_warn("unable to read container super block at disk block %llu\n",
				blk);
		goto release_buffer;
	}

	rc = -EINVAL;
	nxsb = (struct apfs_container_sb *) bp->b_data;
	if (le32_to_cpu(nxsb->magic) != APFS_NXSB_MAGIC) {
		if (!silent)
			pr_warn("wrong container super block magic 0x%x at disk block %llu\n",
				le32_to_cpu(nxsb->magic), blk);
		goto release_buffer;
	}

	pr_debug("found container super block at disk block %llu\n", blk);

	apfs_info->nxsb = nxsb;
	apfs_info->bp = bp;

	return 0;

release_buffer:
	apfs_info->nxsb = NULL;
	apfs_info->bp = NULL;
	brelse(bp);

	return rc;
}

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
	struct apfs_info		*apfs_info;
	struct apfs_container_sb	*nxsb;
	unsigned int			bsize;

	sb->s_flags |= SB_RDONLY;

	apfs_info = kzalloc(sizeof(*apfs_info), GFP_KERNEL);
	if (!apfs_info)
		return -ENOMEM;

	sb->s_fs_info = apfs_info;
	sb->s_op = &apfs_super_ops;

	bsize = sb_min_blocksize(sb, APFS_BLOCK_SIZE);
	if (!bsize) {
		pr_err("unable to set blocksize\n");
		goto free_info;
	}

	if (apfs_get_nxsb_magic(sb, silent, 0))
		goto free_info;

	nxsb = apfs_info->nxsb;

	sb->s_magic = le32_to_cpu(nxsb->magic);

	bsize = le32_to_cpu(nxsb->block_size);
	if (!sb_set_blocksize(sb, bsize)) {
		pr_warn("unable to set final block size to: %u\n", bsize);
		goto free_bp;
	}

	pr_debug("creating container supberblock's object mapper b-tree from block: 0x%llx\n",
		 le64_to_cpu(nxsb->omap_oid));

	pr_debug("searching for filesystem at object id: 0x%llx\n",
		 le64_to_cpu(nxsb->fs_oid));

	 /* Until we have a root directoty */
	goto free_bp;
	return 0;

free_bp:
	brelse(apfs_info->bp);
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
