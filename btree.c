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
 * apfs_btree_free_entry() - free a %apfs_btree_entry
 * @se:		the %apfs_btree_entry to free
 */
void apfs_btree_free_entry(struct apfs_btree_entry *se)
{
	kfree(se);
}

/**
 * apfs_btree_get_entry() - lookup a btree entry from disk
 * @tree:	the tree to look up in
 * @node:	the node the entry belongs to
 * @idx:	the enrty's index in the node
 */
static struct apfs_btree_entry *
apfs_btree_get_entry(struct apfs_btree *tree, struct apfs_bnode *node, int idx)
{
	struct apfs_btree_entry *se;
	struct apfs_btree_entry_fixed	fe;
	struct apfs_btree_entry_var	ve;
	int			koff;
	int			voff;
	struct buffer_head	*bp = node->bp;

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
		se->key_len = tree->bf->key_size;
	} else {
		koff = node->keys_start + ve.key_offs;
		se->key_len = ve.key_len;
	}

	se->key = &bp->b_data[koff];

	if (node->type == APFS_NODE_TYPE_FIXED && fe.val_offs != 0xffff) {
		voff = node->vals_start - fe.val_offs;

		se->val_len = (node->level > 0) ?
			sizeof(u64) : tree->bf->val_size;
	} else if (ve.val_offs != 0xffff) {
		voff = node->vals_start - ve.val_offs;
		se->val_len = ve.val_len;
	} else
		goto free_entry;

	se->val = &bp->b_data[voff];

	return se;

free_entry:
	kfree(se);
	return NULL;
}

/**
 * apfs_btree_find_bin() - do a binary search for a key in a btree
 * @tree:	the btree to search in
 * @node:	the node to take as a starting point
 * @key:	the key to look up
 * @key_len:	the key's size
 *
 * apfs_btree_find_bin() performs a binary search for a given @key in
 * a @tree starting at @node. It returns a %apfs_btree_entry
 * which must be freed with apfs_btree_free_entry() when
 * finished.
 */
static struct apfs_btree_entry *
apfs_btree_find_bin(struct apfs_btree *tree, struct apfs_bnode *node,
		    void *key, size_t key_size)
{
	struct apfs_btree_entry *se;
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
		apfs_btree_free_entry(se);
	}

	if (rc)
		apfs_btree_free_entry(se);

	return (rc == 0) ? se : NULL;
}

/**
 * apfs_btree_lookup() - perform a B-Tree lookup
 * @tree:	the B-Tree to perform the lookup in
 * @key:	the key to search for in @tree
 * @key_size:	the size of @key
 *
 * apfs_btree_lookup() performs a B-Tree lookup for the key pointed to
 * by @key with in the B-Tree pointed to by @tree. As keys can have
 * different size, it is passed in via @key_size.
 */
struct apfs_btree_entry *
apfs_btree_lookup(struct apfs_btree *tree, void *key, size_t key_size)
{
	struct apfs_bnode	*node = tree->root;
	struct apfs_btree_entry *entry;
	u64			nodeid;
	u64			parentid;

	while (node->level > 0) {
		entry = apfs_btree_find_bin(tree, node, key, key_size);
		if (!entry)
			return NULL;

		nodeid = *(u64*) entry->val;
		parentid = node->ohdr->oid;
		apfs_btree_free_entry(entry);

		/* XXX: free old node here */
		node = apfs_btree_create_node(tree, parentid, nodeid, GFP_KERNEL);
		if (!node)
			return NULL;
	}

	return apfs_btree_find_bin(tree, node, key, key_size);
}

/**
 * apfs_btree_iter_dup() - check for duplicate B-Tree iter entrys
 * @it:		the APFS B-Tree iterator
 * @bte:	the APFS B-Tree search entry to check
 *
 * apfs_btree_iter_dup() checks the B-Tree iterator @it wheather the
 * entry pointed ot by @bte has already been found while iterating
 * over the tree.
 */
bool apfs_btree_iter_dup(struct apfs_btree_iter *it,
			 struct apfs_btree_entry *bte)
{
	int				i;
	struct apfs_btree_entry *sbte;

	for (i = 0; i < it->pos - 1; i++) {
		if (!it->se[i])
			continue;
		sbte = it->se[i];
		if (bte->val_len != sbte->val_len)
			continue;
		if (!memcmp(bte->val, sbte->val, bte->val_len))
			return true;
	}
	return false;
}

/**
 * apfs_btree_iter_next() - position iterator to the next entry
 * @it:		the B-Tree iterator
 * @key:	the key to look for
 * @key_len:	the lenght of @key
 *
 * apfs_btree_iter_next() takes the B-Tree pointed to by @it->tree
 * starting at position @it->pos and returns the next position where
 * it can find key @key in it and then updates the new position.
 */
struct apfs_btree_iter *
apfs_btree_iter_next(struct apfs_btree_iter *it, void *key, size_t key_len)
{
	struct apfs_btree_entry		*bte = NULL;
	struct apfs_bnode		*node = it->node;
	loff_t 				pos = it->pos + 1;
	int 				rc;
	apfs_btree_keycmp		keycmp = it->tree->keycmp;

	apfs_btree_free_entry(it->bte);
	it->bte = NULL;

	if (pos >= node->ecnt) {
		it->pos = APFS_BTREE_ITER_END;
		return it;
	}

	if (it->se[pos]) {
		it->bte = it->se[pos];
		it->pos = pos;
		return it;
	}

	for (;;) {
		bte = apfs_btree_get_entry(it->tree, node, pos);
		if (!bte)
			break;

		rc = keycmp(key, key_len, bte->key, bte->key_len, NULL);
		if (rc == 0)
			break;

		apfs_btree_free_entry(bte);
		bte = NULL;
		if (++pos >= node->ecnt)
			break;
	}

	if (pos >= node->ecnt) {
		pos = APFS_BTREE_ITER_END;
	} else if (bte) {
		it->bte = bte;
		it->se[pos] = bte;
	}

	it->pos = pos;
	return it;
}

/**
 * apfs_btree_get_iter() - get an iterator for B-Tree nodes
 * @tree:	the B-tree to get the iterator for
 * @key:	the key to lookup in @tree
 * @key_size:	the size of @key
 * @start:	the starting offset for the iterator
 *
 * apfs_btree_get_iter() creates an iterator for the B-Tree @tree to
 * look up a key @key with size @key_size starting at position @start.
 */
struct apfs_btree_iter *
apfs_btree_get_iter(struct apfs_btree *tree, void *key, size_t key_size,
		    loff_t start)
{
	struct apfs_btree_iter		*it = NULL;
	struct apfs_bnode		*root = tree->root;
	struct apfs_bnode		*node;
	struct apfs_btree_entry		*bte;

	it = kzalloc(sizeof(struct apfs_btree_iter), GFP_KERNEL);
	if (!it)
		return ERR_PTR(-ENOMEM);

	it->tree = tree;
	it->pos = start;
	it->node = node = root;
	while (node->level > 0) {
		bte = apfs_btree_find_bin(it->tree, node, key, key_size);
		if (!bte)
			goto out;

		node = bte->node;
		apfs_btree_free_entry(bte);
	}

	bte = apfs_btree_find_bin(it->tree, node, key, key_size);
	if (!bte)
		goto out;

	it->node = bte->node;
	it->bte = bte;

	it->se[it->pos] = bte;

out:
	return it;
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
	size_t				ohsize;
	size_t				hsize;

	pr_debug("creating btree node with parent: 0x%llx for block: 0x%llx\n",
		 parent, block);

	ohsize = sizeof(struct apfs_obj_header);
	hsize = ohsize + sizeof(struct apfs_btree_header);

	node = kzalloc(sizeof(struct apfs_bnode), gfp);
	if (!node)
		return NULL;

	node->parent = parent;
	node->block = block;

	bp = sb_bread(sb, node->block);
	if (!bp || !buffer_mapped(bp))
		goto release_buffer;

	ohdr = (struct apfs_obj_header *) bp->b_data;
	bh = (struct apfs_btree_header *) &bp->b_data[ohsize];

	node->bp = bp;
	node->bh = bh;
	node->ohdr = ohdr;

	node->keys_start = hsize + le16_to_cpu(bh->table_space_length);
	node->vals_start = (parent != 0) ? size : size
		- sizeof(struct apfs_btree_footer);
	node->ecnt = le16_to_cpu(bh->key_count);
	node->level = le16_to_cpu(bh->level);

	if (bh->flags & 4) {
		node->type = APFS_NODE_TYPE_FIXED;
		node->fe = (struct apfs_btree_entry_fixed *) &bp->b_data[hsize];
	} else {
		node->type = APFS_NODE_TYPE_VAR;
		node->ve = (struct apfs_btree_entry_var *) &bp->b_data[hsize];
	}

	return node;

release_buffer:
	brelse(bp);
	kmem_cache_free(apfs_btree_cachep, node);
	return NULL;
}

/**
 * apfs_btree_get_blockid() - lookup a specific block by ID
 * @tree:	the tree to do the lookup in
 * @oid:	the object ID of the block to search
 * @xid:	the transaction ID of the block to search
 *
 * apfs_btree_get_blockid() lookup the LBA number of a block with
 * object ID @oid and transaction ID @xid in B-Tree @tree.
 */
static u64 apfs_btree_get_blockid(struct apfs_btree *tree, u64 oid, u64 xid)
{
	struct apfs_node_id_map_key	key;
	struct apfs_node_id_map_value	*val;
	struct apfs_btree_entry		*bte;
	u64				block;

	key.oid = oid;
	key.xid = xid;

	bte = apfs_btree_lookup(tree, &key, sizeof(key));
	if (!bte)
		return 0;
	val = bte->val;
	block = val->block;
	apfs_btree_free_entry(bte);

	return block;
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
		tree->bf = kmemdup(&root_node->bp->b_data[foff],
				   sizeof(struct apfs_btree_footer),
				   GFP_KERNEL);
		if (!tree->bf)
			goto release_node;
		break;
	case APFS_OBJ_BTROOT:
		root_node = apfs_btree_create_node(tree, 0, block, GFP_KERNEL);
		if (!root_node)
			goto release_buffer;
		tree->root = root_node;
		tree->bf = kmemdup(&root_node->bp->b_data[foff],
				   sizeof(struct apfs_btree_footer),
				   GFP_KERNEL);
		if (!tree->bf)
			goto release_node;
		tree->entries = tree->bf->entries_cnt;
		break;
	default:
		pr_debug("Unknown B-Tree type: 0x%x\n", ohdr->type);
		goto release_buffer;
	}

	brelse(bp);
	return tree;

release_node:
	kfree(root_node);
release_buffer:
	brelse(bp);
free_tree:
	kfree(tree);
	return ERR_PTR(-ENOMEM);
}

