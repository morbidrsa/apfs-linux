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
 * apfs_btree_free_search_entry() - free a %apfs_btree_search_entry
 * @se:		the apfs_btree_search_entry to free
 */
static void apfs_btree_free_search_entry(struct apfs_btree_search_entry *se)
{
	if (!se)
		return;

	kfree(se->key);
	kfree(se->val);
	kfree(se);
}

/**
 * apfs_btree_get_entry() - lookup a btree entry from disk
 * @tree:	the tree to look up in
 * @node:	the node the entry belongs to
 * @idx:	the enrty's index in the node
 */
static struct apfs_btree_search_entry *
apfs_btree_get_entry(struct apfs_btree *tree, struct apfs_bnode *node, int idx)
{
	struct apfs_btree_search_entry *se;
	struct apfs_btree_entry_fixed	fe;
	struct apfs_btree_entry_var	ve;
	int			koff;
	int			voff;
	struct buffer_head	*bp;
	struct super_block	*sb = tree->sb;

	if (idx >= node->ecnt)
		return NULL;

	fe = node->fe[idx];
	ve = node->ve[idx];

	se = kmalloc(sizeof(*se), GFP_KERNEL);
	if (!se)
		return NULL;

	se->node = node;


	if (node->type == APFS_NODE_TYPE_FIXED) {
		koff = node->keys_start + fe.key_offs;
		se->key_len = tree->bf->min_key_size;
	} else {
		koff = node->keys_start + ve.key_offs;
		se->key_len = ve.key_len;
	}

	bp = sb_bread(sb, node->block);
	if (!bp || !buffer_mapped(bp)) {
		brelse(bp);
		return NULL;
	}

	se->key = kmemdup(&bp->b_data[koff], se->key_len, GFP_KERNEL);
	if (!se->key)
		goto free_entry;

	voff = 0;
	if (node->type == APFS_NODE_TYPE_FIXED) {
		if (node->fe[idx].val_offs != 0xffff) {
			voff = node->vals_start - fe.val_offs;

			se->val_len = (node->level > 0) ?
				sizeof(u64) : tree->bf->min_val_size;
		}
	} else {
		if (ve.val_offs != 0xffff) {
			voff = node->vals_start - ve.val_offs;
			se->val_len = ve.val_len;
		}
	}

	if (!se->val_len || !voff)
		goto free_key;

	se->val = kmemdup(&bp->b_data[voff], se->val_len, GFP_KERNEL);
	if (!se->val)
		goto free_key;

	brelse(bp);

	return se;

free_key:
	kfree(se->key);
free_entry:
	kfree(se);
	return NULL;
}

/**
 * afps_btree_find_bin() - do a binary search for a key in a btree
 * @tree:	the btree to search in
 * @node:	the node to take as a starting point
 * @key:	the key to look up
 * @key_len:	the key's size
 *
 * afps_btree_find_bin() performs a binary search for a given @key in
 * a @tree starting at @node. It returns a %apfs_btree_search_entry
 * which must be freed with apfs_btree_free_search_entry() when
 * finished.
 */
static struct apfs_btree_search_entry *
afps_btree_find_bin(struct apfs_btree *tree, struct apfs_bnode *node,
		    void *key, size_t key_size)
{
	struct apfs_btree_search_entry *se;
	int			begin;
	int			end;
	int			mid;
	int			cnt;
	int			rc;

	cnt = node->ecnt;
	if (cnt <= 0)
		return NULL;

	begin = 0;
	end = cnt - 1;

	while (begin <= end) {
		mid = (begin + end) / 2;

		se = apfs_btree_get_entry(tree, node, mid);
		if (!se)
			return NULL;
		rc = tree->keycmp(key, key_size, se->key, se->key_len, NULL);
		if (!rc) /* found */
			break;
		else if (rc == -1)
			begin = mid + 1;
		else if (rc == 1)
			end = mid - 1;
	}

	return (rc == 0) ? se : NULL;
}

bool apfs_btree_lookup(struct apfs_btree *tree, void *key, size_t key_size,
		       void *val, size_t val_size)
{
	struct apfs_bnode	*node = tree->root;
	struct apfs_btree_search_entry *entry;
	u64			nodeid;
	u64			parentid;

	while (node->level > 0) {
		entry = afps_btree_find_bin(tree, node, key, key_size);
		if (!entry)
			return false;

		nodeid = (u64) entry->val;
		parentid = node->ohdr->oid;
		node = entry->node;
		if (!node)
			return false;
		apfs_btree_free_search_entry(entry);
	}

	entry = afps_btree_find_bin(tree, node, key, key_size);
	if (!entry)
		return false;

	memcpy(val, entry->val, val_size);
	apfs_btree_free_search_entry(entry);

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
	node->ecnt = le16_to_cpu(bh->entries);
	node->level = le16_to_cpu(bh->level);

	if (bh->flags & 4)
		node->fe = (struct apfs_btree_entry_fixed *) &bp->b_data[0x38];
	else
		node->ve = (struct apfs_btree_entry_var *) &bp->b_data[0x38];

	return node;

release_buffer:
	brelse(bp);
	kmem_cache_free(apfs_btree_cachep, node);
	return NULL;
}

static u64 apfs_btree_get_blockid(struct apfs_btree *tree, u64 oid, u64 xid)
{
	struct apfs_node_id_map_key	key;
	struct apfs_node_id_map_value	val;

	key.oid = oid;
	key.xid = xid;

	if (apfs_btree_lookup(tree, &key, sizeof(key), &val, sizeof(val)))
		return val.block;
	return 0;
}

/**
 * apfs_btree_create - create an APFS B-Tree
 *
 * @sb:		the VFS super block this B-Tree belongs to
 * @block:	the disk block the of the B-Tree root
 * @keycmp:	callback to the key compare helper function
 * @omap:	object mapper for lookups in this tree
 *
 * apfs_btree_create() create a in memory representation of an APFS
 * b-tree. There are two kinds of b-trees, normal b-trees which use an
 * object mapper for object to block translation and the object mapper
 * b-trees themselves.
 */
struct apfs_btree *apfs_btree_create(struct super_block *sb, u64 block,
				     apfs_btree_keycmp keycmp,
				     struct apfs_btree *omap)
{
	struct apfs_info		*apfs_info = APFS_SBI(sb);
	struct apfs_btree		*tree;
	struct apfs_btree_root		*disk_tree;
	struct apfs_obj_header		*ohdr;
	struct buffer_head		*bp;
	struct apfs_bnode		*root_node;
	u64 				root_block = 0;
	u32				foff;

	pr_debug("creating b-tree for object: 0x%llx\n", block);

	tree = kzalloc(sizeof(*tree), GFP_KERNEL);
	if (!tree)
		return ERR_PTR(-ENOMEM);

	tree->sb = sb;
	tree->omap = omap;
	tree->keycmp = keycmp;

	foff = apfs_info->blocksize - sizeof(struct apfs_btree_footer);

	if (tree->omap){
		block = apfs_btree_get_blockid(tree->omap, block,
						    apfs_info->xid);
		if (!block)
			goto free_tree;
	}

	bp = sb_bread(sb, block);
	if (!bp || !buffer_mapped(bp))
		goto release_buffer;

	ohdr = (struct apfs_obj_header *) bp->b_data;
	switch (ohdr->type) {
	case APFS_OBJ_BTREE_ROOT_PTR:
		disk_tree = (struct apfs_btree_root *) bp->b_data;
		root_block = disk_tree->entry[0].block;

		root_node = apfs_btree_create_node(tree, 0, root_block,
						   GFP_KERNEL);
		if (!root_node)
			goto release_buffer;

		tree->root = root_node;
		tree->entries = le32_to_cpu(disk_tree->entries);
		tree->bf = (struct apfs_btree_footer *)
			&root_node->bp->b_data[foff];
		break;
	case APFS_OBJ_BTROOT:
		root_node = apfs_btree_create_node(tree, 0, block, GFP_KERNEL);
		if (!root_node)
			goto release_buffer;
		tree->root = root_node;
		tree->bf = (struct apfs_btree_footer *)
			&root_node->bp->b_data[foff];
		tree->entries = tree->bf->entries_cnt;
		break;
	default:
		pr_debug("Unknown B-Tree type: 0x%x\n", ohdr->type);
		goto release_buffer;
	}

	brelse(bp);
	return tree;

release_buffer:
	brelse(bp);
free_tree:
	kfree(tree);
	return ERR_PTR(-ENOMEM);
}

