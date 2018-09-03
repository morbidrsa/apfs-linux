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

static struct apfs_btree_search_entry *
apfs_btree_get_entry(struct apfs_btree *tree, struct apfs_bnode *node, int idx)
{
	struct apfs_btree_search_entry *se;
	struct apfs_btree_entry	e;
	int			koff;
	int			voff;
	struct buffer_head	*bp;
	struct super_block	*sb = tree->sb;

	if (idx >= node->ecnt)
		return NULL;

	e = node->entries[idx];

	se = kmalloc(sizeof(*se), GFP_KERNEL);
	if (!se)
		return NULL;

	se->node = node;
	se->key_len = tree->bf->min_key_size;

	koff = node->keys_start + e.key_offs;

	bp = sb_bread(sb, node->block);
	if (!bp || !buffer_mapped(bp)) {
		brelse(bp);
		return NULL;
	}

	se->key = kmemdup(&bp->b_data[koff], se->key_len, GFP_KERNEL);
	if (!se->key)
		goto free_entry;

	if (node->entries[idx].val_offs != 0xffff) {
		voff = node->vals_start - e.val_offs;

		se->val_len = (node->level > 0) ?
			sizeof(u64) : tree->bf->min_val_size;

		se->val = kmemdup(&bp->b_data[voff], se->val_len, GFP_KERNEL);
		if (!se->val)
			goto free_key;
	}

	brelse(bp);

	return se;

free_key:
	kfree(se->key);
free_entry:
	kfree(se);
	return NULL;
}



static int afps_btree_find_bin(struct apfs_btree *tree, struct apfs_bnode *node,
			       void *key, size_t key_size)
{
	struct apfs_btree_search_entry *se;
	int			begin;
	int			end;
	int			mid;
	int			cnt;
	int			res;
	int			rc;

	cnt = node->ecnt;
	if (cnt <= 0)
		return -1;

	begin = 0;
	end = cnt - 1;

	while (begin <= end) {
		mid = (begin + end) / 2;

		se = apfs_btree_get_entry(tree, node, mid);
		if (!se)
			return -1;
		rc = tree->keycmp(key, key_size, se->key, se->key_len, NULL);
		if (!rc) /* found */
			break;
		else if (rc == -1)
			begin = mid + 1;
		else if (rc == 1)
			end = mid - 1;
	}

	res = (rc == 0) ? mid : -1;

	if (res == cnt)
		res = -1;

	return res;
}

bool apfs_btree_lookup(struct apfs_btree *tree, void *key, size_t key_size,
		       void *val, size_t val_size)
{
	struct apfs_bnode	*node = tree->root;
	struct apfs_btree_search_entry *entry;
	int			index;
	u64			nodeid;
	u64			parentid;

	while (node->level > 0) {
		index = afps_btree_find_bin(tree, node, key, key_size);
		if (index < 0)
			return false;

		entry = apfs_btree_get_entry(tree, node, index);
		if (!entry)
			return false;

		nodeid = (u64) entry->val;
		parentid = node->ohdr->oid;
		node = entry->node;
		if (!node)
			return false;
		kfree(entry);
	}

	index = afps_btree_find_bin(tree, node, key, key_size);
	if (index < 0)
		return false;

	entry = apfs_btree_get_entry(tree, node, index);
	if (!entry)
		return false;

	memcpy(val, entry->val, val_size);
	kfree(entry);

	return true;
}

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
	size_t				hsize = sizeof(struct apfs_obj_header);
	void				*buf;

	pr_debug("creating btree node with parent: 0x%llx for block: 0x%llx\n",
		 parent, block);

	node = kzalloc(sizeof(struct apfs_bnode), gfp);
	if (!node)
		return NULL;

	node->parent = parent;
	node->block = block;

	bp = sb_bread(sb, node->block);
	if (!bp || !buffer_mapped(bp))
		goto release_buffer;

	buf = bp->b_data;
	ohdr = (struct apfs_obj_header *) bp->b_data;
	bh = (struct apfs_btree_header *) &bp->b_data[hsize];

	node->bp = bp;
	node->bh = bh;
	node->ohdr = ohdr;

	node->keys_start = 0x38 + le16_to_cpu(bh->keys_len);
	node->vals_start = (parent != 0) ? size : size
		- sizeof(struct apfs_btree_footer);
	node->entries = (struct apfs_btree_entry *) &bp->b_data[0x38];
	node->ecnt = le16_to_cpu(bh->entries);
	node->level = le16_to_cpu(bh->level);

	return node;

release_buffer:
	brelse(bp);
	kmem_cache_free(apfs_btree_cachep, node);
	return NULL;
}

/**
 * apfs_btree_create - create an APFS B-Tree
 *
 * @sb:		the VFS super block this B-Tree belongs to
 * @block:	the disk block the of the B-Tree root
 * @keycmp:	callback to the key compare helper function
 */
struct apfs_btree *apfs_btree_create(struct super_block *sb, u64 block,
				     apfs_btree_keycmp keycmp)
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
	tree->bf = (struct apfs_btree_footer *) &root_node->bp->b_data[foff];
	tree->keycmp = keycmp;

	brelse(bp);
	return tree;

release_buffer:
	brelse(bp);
	kfree(tree);
	return ERR_PTR(-ENOMEM);
}

