// SPDX-License-Identifier: GPL-2.0
/*
 * btree.c - APFS B-Tree handling
 *
 * Copyright (C) 2018 Johannes Thumshirn
 */

#include <linux/slab.h>

#include "apfs.h"

static struct kmem_cache *apfs_btree_cachep;

/**
 * apfs_btree_create_node - create a B-Tree Node
 *
 * @root:	the tree root this node belongs to
 * @parent:	the nodeid of this node's parent node
 * @block:	the block number
 *
 * apfs_btree_create_node() creates the in memory representation of a
 * APFS B-Tree node.
 *
 * If @parent is %0 it is assumed it's the root node.
 */
struct apfs_bnode *apfs_btree_create_node(struct apfs_btree *root,
					  u64 parent, u64 block)
{
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
 * @sb:		th VFS super block this B-Tree belongs to
 */
struct apfs_btree *apfs_btree_create(struct super_block *sb)
{
	struct apfs_btree		*tree;

	tree = kzalloc(sizeof(*tree), GFP_KERNEL);
	if (!tree)
		return ERR_PTR(-ENOMEM);

	tree->mempool = mempool_create(0, apfs_btree_alloc,
				       apfs_btree_free, NULL);
	if (!tree->mempool)
		goto free_tree;

	tree->sb = sb;

	return tree;

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
