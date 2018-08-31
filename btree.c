// SPDX-License-Identifier: GPL-2.0
/*
 * btree.c - APFS B-Tree handling
 *
 * Copyright (C) 2018 Johannes Thumshirn
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/buffer_head.h>

#include "apfs.h"

static struct kmem_cache *apfs_btree_cachep;

/**
 * apfs_btree_create_node - create a B-Tree Node
 *
 * @root:	the tree root this node belongs to
 * @parent:	the nodeid of this node's parent node
 * @block:	the block number
 * @gfp:	allocation flags for memory pool
 *
 * apfs_btree_create_node() creates the in memory representation of a
 * APFS B-Tree node.
 *
 * If @parent is %0 it is assumed it's the root node.
 */
struct apfs_bnode *apfs_btree_create_node(struct apfs_btree *root, u64 parent,
					  u64 block, gfp_t gfp)
{
	struct super_block		*sb = root->sb;
	struct apfs_info		*apfs_info = APFS_SBI(sb);
	struct buffer_head 		*bp;
	struct apfs_bnode 		*node;
	struct apfs_obj_header		*ohdr;
	struct apfs_btree_header	*bh;
	u32				size = apfs_info->blocksize;

	pr_debug("creating btree node with parent: 0x%llx for block: 0x%llx\n",
		 parent, block);

	node = mempool_alloc(root->mempool, gfp);
	if (!node)
		return NULL;

	bp = sb_bread(sb, block);
	if (!bp || !buffer_mapped(bp))
		goto release_buffer;

	ohdr = (struct apfs_obj_header *) bp->b_data;
	bh = (struct apfs_btree_header *) bp->b_data
		+ sizeof(struct apfs_obj_header);

	node->bp = bp;
	node->bh = bh;
	node->ohdr = ohdr;

	node->keys_start = 0x38 + le16_to_cpu(bh->keys_len);
	node->vals_start = (parent != 0) ? size : size
		- sizeof(struct apfs_btree_footer);
	node->entries = (struct apfs_btree_entry *) bp->b_data + 0x38;

	return node;

release_buffer:
	brelse(bp);
	kmem_cache_free(apfs_btree_cachep, node);
	return NULL;
}

/**
 * apfs_btree_alloc - allocate function for the mempool
 * @gfp_mask:	gfp mask for the allocation
 * @unused:	unused
 */
static void *apfs_btree_alloc(gfp_t gfp_mask, void *unused)
{
	return kmem_cache_alloc(apfs_btree_cachep, gfp_mask);
}

/**
 * apfs_btree_free - free function for the mempool
 * @element:	the element to free
 * @unused:	unused
 */
static void apfs_btree_free(void *element, void *unused)
{
	kmem_cache_free(apfs_btree_cachep, element);
}

/**
 * apfs_btree_create - create an APFS B-Tree
 *
 * @sb:		the VFS super block this B-Tree belongs to
 * @block:	the disk block the of the B-Tree root
 */
struct apfs_btree *apfs_btree_create(struct super_block *sb, u64 block)
{
	struct apfs_info		*apfs_info = APFS_SBI(sb);
	struct apfs_btree		*tree;
	struct apfs_btree_root		*disk_tree;
	struct buffer_head		*bp;
	struct apfs_bnode		*root_node;
	u64 				root_block;
	u32				foff;

	tree = kzalloc(sizeof(*tree), GFP_KERNEL);
	if (!tree)
		return ERR_PTR(-ENOMEM);

	tree->mempool = mempool_create(0, apfs_btree_alloc,
				       apfs_btree_free, NULL);
	if (!tree->mempool)
		goto free_tree;

	tree->sb = sb;

	bp = sb_bread(sb, block);
	if (!bp || !buffer_mapped(bp))
		goto release_buffer;

	disk_tree = (struct apfs_btree_root *) bp->b_data;
	root_block = disk_tree->entry[0].block;
	foff = apfs_info->blocksize - sizeof(struct apfs_btree_footer);

	root_node = apfs_btree_create_node(tree, 0, root_block, GFP_KERNEL);
	if (!root_node)
		goto release_buffer;

	tree->root = root_node;
	tree->entries = le32_to_cpu(disk_tree->entries);
	tree->bf = (struct apfs_btree_footer *) root_node->bp->b_data + foff;

	brelse(bp);
	return tree;

release_buffer:
	mempool_destroy(tree->mempool);
	brelse(bp);
free_tree:
	kfree(tree);
	return ERR_PTR(-ENOMEM);
}

/**
 * apfs_create_btree_cache - create the btree's node cache
 *
 * Create the kmem cache for the btree's internal node memory pool
 *
 * Returns: 0 on success %ENOMEM otherwise
 */
int apfs_create_btree_cache(void)
{
	apfs_btree_cachep = kmem_cache_create("apfs_btree_node",
					      sizeof(struct apfs_bnode),
					      0, SLAB_HWCACHE_ALIGN, NULL);
	if (!apfs_btree_cachep)
		return -ENOMEM;

	return 0;
}

/**
 * apfs_destroy_btree_cache - destroy the btree's node cache
 *
 * Destroy the kmem cache for the btree's internal node memory pool
 */
void apfs_destroy_btree_cache(void)
{
	kmem_cache_destroy(apfs_btree_cachep);
}
