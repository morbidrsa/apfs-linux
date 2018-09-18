// SPDX-License-Identifier: GPL-2.0
/*
 * super.c - APFS kernel super block handling
 *
 * Copyright (C) 2018 Johannes Thumshirn
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/buffer_head.h>
#include <linux/module.h>
#include <linux/statfs.h>
#include <linux/slab.h>
#include <linux/fs.h>

#include "apfs.h"

#define APFS_BLOCK_SIZE		4096

static struct kmem_cache *apfs_inode_cachep;

/**
 * omap_keycmp - compare object mapper keys
 * @skey:	search key
 * @skey_len:	search key length
 * @ekey:	expected key
 * @ekey_len:	expected key length
 * @ctx:	arbitratry context
 *
 * omap_keycmp() compares two %apfs_node_id_map_keys against
 * each other by looking at the object IDs and transaction IDs. This
 * is used to find the values in the container super block's object
 * mapper b-tree.
 */
static int omap_keycmp(void *skey, size_t skey_len, void *ekey,
		       size_t ekey_len, void *ctx)
{
	struct apfs_node_id_map_key		*skey_map = skey;
	struct apfs_node_id_map_key		*ekey_map = ekey;

	if (ekey_map->oid < skey_map->oid)
		return -1;
	if (ekey_map->oid > skey_map->oid)
		return 1;
	if (ekey_map->xid < skey_map->xid)
		return -1;
	if (ekey_map->xid > skey_map->xid)
		return 1;
	return 0;
}

/**
 * oid_keycmp - compare object mapper keys
 * @skey:	search key
 * @skey_len:	search key length
 * @ekey:	expected key
 * @ekey_len:	expected key length
 * @ctx:	arbitratry context
 *
 * oid_keycmp() compares two %apfs_node_id_map_keys against
 * each other by looking only at the object IDs.
 */
static int oid_keycmp(void *skey, size_t skey_len, void *ekey,
		      size_t ekey_len, void *ctx)
{
	struct apfs_node_id_map_key		*skey_map = skey;
	struct apfs_node_id_map_key		*ekey_map = ekey;

	if (ekey_map->oid < skey_map->oid)
		return -1;
	if (ekey_map->oid > skey_map->oid)
		return 1;
	return 0;
}

/**
 * apfs_statfs() - provide statistics for filesystem
 * @dentry:	dentry representing the filesystem
 * @kstatfs:	the struct kstatfs to fill with infos
 */
static int apfs_statfs(struct dentry *dentry, struct kstatfs *kstatfs)
{
	kstatfs->f_type = APFS_NXSB_MAGIC;
	kstatfs->f_bsize = dentry->d_sb->s_blocksize;
	kstatfs->f_bavail = 0;
	kstatfs->f_files = 0;
	kstatfs->f_namelen = APFS_MAX_NAME;
	return 0;
}

/**
 * apfs_put_super() - free super block resources
 * @sb:		VFS superblock
 *
 * apfs_put_super() frees all resources for @sb after the last
 * instance is unmounted.
 */
static void apfs_put_super(struct super_block *sb)
{
	struct apfs_info		*apfs_info = APFS_SBI(sb);

	brelse(apfs_info->apsb_bp);
	brelse(apfs_info->nxsb_bp);
	kfree(apfs_info);
}

/**
 * apfs_alloc_inode() - Allocate an APFS inode
 * @sb:		VFS superblock
 *
 * apfs_alloc_inode() allocates an inode for the APFS filesystem
 * mounted at @sb.
 */
static struct inode *apfs_alloc_inode(struct super_block *sb)
{
	struct apfs_inode		*apfs_inode;

	apfs_inode = kmem_cache_alloc(apfs_inode_cachep, GFP_KERNEL);
	if (!apfs_inode)
		return NULL;

	inode_init_once(&apfs_inode->vfs_inode);
	return &apfs_inode->vfs_inode;
}

/**
 * apfs_i_callback() - rcu callback to free an APFS inode
 * @head:	the RCU head on which we're called
 */
static void apfs_i_callback(struct rcu_head *head)
{
	struct inode	*inode = container_of(head, struct inode, i_rcu);

	kmem_cache_free(apfs_inode_cachep, APFS_INO(inode));
}

/**
 * apfs_destroy_inode() - free an APFS inode
 * @inode:	the corresponding VFS inode
 */
static void apfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, apfs_i_callback);
}

static const struct super_operations apfs_super_ops = {
	.alloc_inode	= apfs_alloc_inode,
	.destroy_inode	= apfs_destroy_inode,
	.evict_inode	= apfs_evict_inode,
	.put_super	= apfs_put_super,
	.statfs		= apfs_statfs,
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
	apfs_info->nxsb_bp = bp;

	return 0;

release_buffer:
	apfs_info->nxsb = NULL;
	apfs_info->nxsb_bp = NULL;
	brelse(bp);

	return rc;
}

/**
 * apfs_get_apsb_magic - read on-disk volume superblock
 * @sb:		VFS super block to save the on-disk super block
 * @silent:	remain silent even if errors are detected
 * @blk:	Disk block number to read the volume super block from
 *
 * apfs_get_apsb_magic() is called by apfs_fill_super() to read the
 * on-disk volume super block and verify the magic number.
 */
static int apfs_get_apsb_magic(struct super_block *sb, int silent, u64 blk)
{
	struct apfs_info		*apfs_info = APFS_SBI(sb);
	struct apfs_volume_sb		*apsb;
	struct buffer_head		*bp;
	int 				rc = -ENOMEM;

	bp = sb_bread(sb, blk);
	if (!bp || !buffer_mapped(bp)) {
		if (!silent)
			pr_warn("unable to read volume super block at disk block %llu\n",
				blk);
		goto release_buffer;
	}

	rc = -EINVAL;
	apsb = (struct apfs_volume_sb *) bp->b_data;
	if (le32_to_cpu(apsb->magic) != APFS_APSB_MAGIC) {
		if (!silent)
			pr_warn("wrong volume super block magic 0x%x at disk block %llu\n",
				le32_to_cpu(apsb->magic), blk);
		goto release_buffer;
	}

	pr_debug("found volume super block at disk block 0x%llx\n", blk);

	apfs_info->apsb = apsb;
	apfs_info->apsb_bp = bp;

	return 0;

release_buffer:
	apfs_info->apsb = NULL;
	apfs_info->apsb_bp = NULL;
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
	struct apfs_volume_sb		*apsb;
	struct apfs_node_id_map_key	key;
	struct apfs_node_id_map_value	*val;
	struct inode			*inode;
	u64				omap_oid;
	u64				root_tree_oid;
	unsigned int			bsize;
	struct apfs_btree_entry 	*bte;

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
	apfs_info->blocksize  = le32_to_cpu(nxsb->block_size);
	apfs_info->xid = le64_to_cpu(nxsb->hdr.xid);

	bsize = le32_to_cpu(nxsb->block_size);
	if (!sb_set_blocksize(sb, bsize)) {
		pr_warn("unable to set final block size to: %u\n", bsize);
		goto free_bp;
	}

	omap_oid = le64_to_cpu(nxsb->omap_oid);
	apfs_info->nxsb_omap_root = apfs_btree_create(sb, omap_oid,
						      omap_keycmp, NULL);
	if (!apfs_info->nxsb_omap_root)
		goto free_bp;

	key.oid = le64_to_cpu(nxsb->fs_oid);
	key.xid = apfs_info->xid;
	bte = apfs_btree_lookup(apfs_info->nxsb_omap_root, &key, sizeof(key));
	if (!bte)
		goto free_bp;
	val = bte->val;

	pr_debug("searching for filesystem at object id: 0x%llx, block: 0x%llx\n",
		 le64_to_cpu(nxsb->fs_oid), le64_to_cpu(val->block));

	if (apfs_get_apsb_magic(sb, silent, val->block))
		goto free_bp;

	apfs_btree_free_entry(bte);
	apsb = apfs_info->apsb;
	root_tree_oid = le64_to_cpu(apsb->root_tree_oid);
	apfs_info->apsb_omap_root = apfs_btree_create(sb, apsb->omap_oid,
						      oid_keycmp, NULL);
	if (!apfs_info->apsb_omap_root)
		goto free_bp;

	apfs_info->dir_tree_root = apfs_btree_create(sb, root_tree_oid,
						     apfs_dir_keycmp,
						     apfs_info->apsb_omap_root);
	if (!apfs_info->dir_tree_root)
		goto free_bp;

	inode = apfs_iget(sb, APFS_ROOT_INODE);
	if (IS_ERR(inode))
		goto free_bp;

	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		goto free_bp;

	return 0;

free_bp:
	brelse(apfs_info->nxsb_bp);
	brelse(apfs_info->apsb_bp);
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

	apfs_inode_cachep = kmem_cache_create("apfs_inode",
					sizeof(struct apfs_inode), 0,
					SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
					NULL);
	if (!apfs_inode_cachep)
		return -ENOMEM;


	err = register_filesystem(&apfs_fs_type);
	if (err) {
		pr_err("failed to register APFS: %d\n", err);
		goto free_inode_cache;
	}

	return 0;

free_inode_cache:
	kmem_cache_destroy(apfs_inode_cachep);
	return err;
}
module_init(apfs_init);

static void __exit apfs_exit(void)
{
	unregister_filesystem(&apfs_fs_type);
	kmem_cache_destroy(apfs_inode_cachep);
	return;
}
module_exit(apfs_exit);

MODULE_AUTHOR("Johannes Thumshirn");
MODULE_LICENSE("GPL v2");
