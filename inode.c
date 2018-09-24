// SPDX-License-Identifier: GPL-2.0
/*
 * inode.c - APFS inode handling
 *
 * Copyright (C) 2018 Johannes Thumshirn
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/fs.h>

#include "apfs.h"

#define APFS_KEY_SHIFT			60
enum apfs_key_type {
	KEY_TYPE_INODE =		3,
	KEY_TYPE_XATTR =		4,
	KEY_TYPE_FILE_EXTENT =		8,
	KEY_TYPE_DIR_RECORD =		9,
};

/**
 * apfs_readdir() - iterate over directory contents
 * @file:	the struct file representing the directory
 * @ctx:	the context of readdir
 *
 * apfs_readdir() iterates over the contents of the directory pointed
 * to by @file starting at the position in @ctx->pos. It adds found
 * directories to @ctx, updates the position and returns from there.
 */
static int apfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode			*inode = file_inode(file);
	struct apfs_info		*apfs_info = APFS_SBI(inode->i_sb);
	struct apfs_btree		*dir_tree = apfs_info->dir_tree_root;
	struct apfs_dir_key		*key;
	struct apfs_dir_key		*dkey;
	struct apfs_dir_val		*drec;
	struct apfs_btree_iter		*it = file->private_data;
	struct apfs_btree_entry		*bte;
	int				rc;

	if (!dir_emit_dots(file, ctx))
		return 0;

	key = kzalloc(sizeof(struct apfs_dir_key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;

	key->parent_id = (u64) KEY_TYPE_DIR_RECORD << APFS_KEY_SHIFT;
	key->parent_id |= inode->i_ino;
	memset(key->name, 0, APFS_MAX_NAME);

	if (!it) {
		it = apfs_btree_get_iter(dir_tree, key, sizeof(*key), ctx->pos);
		if (IS_ERR(it)) {
			rc = PTR_ERR(it);
			goto free_key;
		}
		file->private_data = it;
	} else if (apfs_btree_iter_end(it)) {
		apfs_btree_free_iter(it);
		file->private_data = NULL;
		rc = 0;
		goto free_key;
	} else {
		it = apfs_btree_iter_next(it, key, sizeof(*key));
	}

	while (!apfs_btree_iter_end(it)) {
		bte = it->bte;
		if (!bte)
			break;

		if (apfs_btree_iter_end(it))
			break;

		/*
		 * check if we've already found this entry at another
		 * position, this works around a bug in the iterator
		 * code, where we return some entries twice.
		 */
		if (apfs_btree_iter_dup(it, bte))
			goto next;

		dkey = bte->key;
		drec = bte->val;

		rc = dir_emit(ctx, dkey->name, strlen(dkey->name),
			      le64_to_cpu(drec->file_id),
			      le16_to_cpu(drec->flags));
		if (!rc)
			goto free_key;

		ctx->pos++;
next:
		it = apfs_btree_iter_next(it, key, sizeof(*key));
	}

	rc = 0;
free_key:
	kfree(key);
	return rc;

}

static const struct file_operations apfs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= apfs_readdir,
};

/**
 * apfs_inode_by_name() - lookup an APFS inode by name
 * @dir:	parent directory of the inode to lookup
 * @dentry:	dentry encoding the name of the inode to lookup
 *
 * apfs_inode_by_name() searches for an inode identified by
 * @dentry->d_name.name in the directory with an inode pointed to by
 * @dir.
 */
static ino_t apfs_inode_by_name(struct inode *dir, struct dentry *dentry)
{
	struct apfs_info		*apfs_info = APFS_SBI(dir->i_sb);
	struct apfs_dir_key		*key;
	struct apfs_dir_val		*drec;
	struct apfs_btree_entry		*bte;
	ino_t				ino = 0;

	key = kzalloc(sizeof(struct apfs_dir_key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;

	key->parent_id = (u64) KEY_TYPE_DIR_RECORD << APFS_KEY_SHIFT;
	key->parent_id |= dir->i_ino;
	memcpy(key->name, dentry->d_name.name, APFS_MAX_NAME);

	bte = apfs_btree_lookup(apfs_info->dir_tree_root, key, sizeof(*key), true);
	if (!bte)
		goto free_key;

	drec = bte->val;
	ino = drec->file_id;

	apfs_btree_free_entry(bte);
free_key:
	kfree(key);
	return ino;
}

/**
 * apfs_lookup() - lookup an APFS inode
 * @dir:	parent directory of the inode to lookup
 * @dentry:	dentry encoding the name of the inode to lookup
 * @flags:	unused
 *
 * apfs_lookup() searches for an inode identified by
 * @dentry->d_name.name in the directory with an inode pointed to by
 * @dir.

 */
static struct dentry *apfs_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct inode			*inode = NULL;
	ino_t				ino;

	if (dentry->d_name.len > APFS_MAX_NAME)
		return ERR_PTR(-ENAMETOOLONG);

	ino = apfs_inode_by_name(dir, dentry);
	if (ino)
		inode = apfs_iget(dir->i_sb, ino);

	return d_splice_alias(inode, dentry);
}

static const struct inode_operations apfs_dir_inode_ops = {
	.lookup		= apfs_lookup,
};

/**
 * apfs_dir_keycmp() - B-Tree key compare callback for dir contents
 * @skey:	search key
 * @skey_len:	search key length
 * @ekey:	expected key
 * @ekey_len:	expected key length
 * @ctx:	arbitratry context
 *
 * apfs_dir_keycmp() compares two keys for lookup of directory
 * contents. These keys can either be of %KEY_TYPE_DIR_RECORD,
 * %KEY_TYPE_FILE_EXTENT or %KEY_TYPE_XATTR.
 */
int apfs_dir_keycmp(void *skey, size_t skey_len, void *ekey,
		    size_t ekey_len, void *ctx)
{
	struct apfs_dir_key		*sdir;
	struct apfs_dir_key		*edir;
	u64				ks = *(u64 *) skey;
	u64				ke = *(u64 *) ekey;

	ks = (ks << 4) | (ks >> APFS_KEY_SHIFT);
	ke = (ke << 4) | (ke >> APFS_KEY_SHIFT);

	if (ke < ks)
		return -1;
	if (ke > ks)
		return 1;

	if (skey_len <= 8)
		return 0;

	switch (ks & 0xf) {
	case KEY_TYPE_DIR_RECORD:
		sdir = skey;
		edir = ekey;
		if (strlen(sdir->name) && strlen(edir->name))
			return strncmp(edir->name, sdir->name, APFS_MAX_NAME);
		break;
	case KEY_TYPE_FILE_EXTENT:
		break;
	case KEY_TYPE_XATTR:
		break;
	}

	return 0;
}


/**
 * apfs_get_time() - convert the disk inode's time to a timespec64
 * @ts:		the @timespec64 to be filled
 * @dit:	the 64 Bit time of the disk inode
 */
static void apfs_get_time(struct timespec64 *ts, u64 dit)
{
	ts->tv_nsec = dit % 1000000000ull;
	ts->tv_sec = dit / 1000000000ull;
}

/**
 * apfs_lookup_disk_inode() - lookup an inode from disk
 * @sb:		the VFS superblock
 * @apfs_inode:	the apfs_inode to fill
 * @ino:	the inode number to lookup
 *
 * apfs_lookup_disk_inode() searches for the inode with inode number
 * @ino on the filesystem pointed to by @sb and fills the APFS
 * specific inode structure @apfs_inode with the respective
 * information found.
 */
static int apfs_lookup_disk_inode(struct super_block *sb,
				  struct apfs_inode *apfs_inode,
				  ino_t ino)
{
	struct apfs_info 		*apfs_info = APFS_SBI(sb);
	struct inode			*inode = &apfs_inode->vfs_inode;
	struct apfs_dinode		*dinode = NULL;
	struct apfs_ext_dstream		*dstream;
	u64				key;
	struct apfs_btree_entry		*bte;
	int 				i;
	u16				entry_base;

	key = (u64) KEY_TYPE_INODE << APFS_KEY_SHIFT;
	key |= ino;

	bte = apfs_btree_lookup(apfs_info->dir_tree_root, &key, sizeof(key), false);
	if (!bte)
		return -ENOENT;

	dinode = bte->val;

	apfs_inode->mode = le16_to_cpu(dinode->mode);
	apfs_inode->nlink = le32_to_cpu(dinode->children);
	apfs_inode->uid = le32_to_cpu(dinode->uid);
	apfs_inode->gid = le32_to_cpu(dinode->gid);
	apfs_inode->mtime = le64_to_cpu(dinode->mtime);
	apfs_inode->atime = le64_to_cpu(dinode->atime);
	apfs_inode->ctime = le64_to_cpu(dinode->ctime);
	apfs_inode->generation = le32_to_cpu(dinode->generation);

	inode->i_mode = apfs_inode->mode;
	i_uid_write(inode, (uid_t)apfs_inode->uid);
	i_gid_write(inode, (gid_t)apfs_inode->gid);
	set_nlink(inode, apfs_inode->nlink);
	inode->i_generation = apfs_inode->generation;

	apfs_get_time(&inode->i_atime, apfs_inode->atime);
	apfs_get_time(&inode->i_mtime, apfs_inode->mtime);
	apfs_get_time(&inode->i_ctime, apfs_inode->ctime);

	entry_base = sizeof(struct apfs_dinode) +
		(dinode->extent_header.num_extents *
		 sizeof(struct apfs_extent_entry));

	for (i = 0; i < dinode->extent_header.num_extents; i++) {
		switch (dinode->extents[i].type) {
		case APFS_INO_EXT_TYPE_NAME:
			strncpy(apfs_inode->name, bte->val + entry_base,
				APFS_MAX_NAME);
			break;
		case APFS_INO_EXT_TYPE_DSTREAM:
			dstream = bte->val + entry_base;
			inode->i_size = le64_to_cpu(dstream->allocated_size);
			inode_set_bytes(inode, le64_to_cpu(dstream->size));
			break;
		case APFS_INO_EXT_TYPE_SPARSE_BYTES:
			break;
		}

		entry_base += ((dinode->extents[i].length + 7) & 0xfff8);
	}

	apfs_btree_free_entry(bte);

	return 0;
}

/**
 * @apfs_getblk() - get a block from disk
 * @inode:	the inode we're reading the block for
 * @iblock:	the inode block
 * @bh:		the buffer head to fill
 * @create:	flag indicating we want to create a block
 *
 * apfs_getblk() reads the block @iblock of inode @inode from disk and
 * populates the buffer_head @bh with it's content.
 */
static int apfs_getblk(struct inode *inode, sector_t iblock,
		       struct buffer_head *bh, int create)
{
	struct apfs_info		*apfs_info = APFS_SBI(inode->i_sb);
	struct apfs_file_ext_key	key;
	struct apfs_file_ext_key	*extent_key;
	struct apfs_file_ext_val	*extent;
	struct apfs_btree_entry		*bte;
	u64				extent_size;

	key.oid = (u64) KEY_TYPE_FILE_EXTENT << APFS_KEY_SHIFT;
	key.oid |= inode->i_ino;
	key.offs = iblock;

	bte = apfs_btree_lookup(apfs_info->dir_tree_root, &key, sizeof(key), true);
	if (!bte)
		return -EIO;

	extent = bte->val;
	extent_key = bte->key;

	extent_size = extent->flags_length & 0x00ffffffffffffff;

	map_bh(bh, inode->i_sb, extent->phys_blocks);
	bh->b_size = extent_size;

	apfs_btree_free_entry(bte);
	return 0;
}

/**
 * apfs_readpage() - read a page from a file
 * @file:	the file we're reading the page for
 * @page:	the page we want to fill
 *
 * apfs_readpage() reads a page @page from a file @file on disk. It is
 * only a wrapper over block_read_full_page() passing in apfs_getblk()
 * as %get_block callback for block_read_full_page().
 */
static int apfs_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, apfs_getblk);
}

static struct address_space_operations apfs_aops = {
	.readpage		= apfs_readpage,
};

/**
 * apfs_iget() - Get an inode
 * @sb:		the super block to get the inode for
 * @ino:	the number of the inode to get
 */
struct inode *apfs_iget(struct super_block *sb, ino_t ino)
{
	struct inode			*inode;
	struct apfs_inode		*apfs_inode;
	int				ret;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode->i_state & I_NEW))
		return inode;

	apfs_inode = APFS_INO(inode);
	ret = apfs_lookup_disk_inode(sb, apfs_inode, ino);
	if (ret) {
		iget_failed(inode);
		return ERR_PTR(ret);
	}

	if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &apfs_dir_inode_ops;
		inode->i_fop = &apfs_dir_fops;
	} else if (S_ISREG(inode->i_mode)) {
		inode->i_fop = &generic_ro_fops;
		inode->i_mapping->a_ops = &apfs_aops;
	}

	unlock_new_inode(inode);
	return inode;
}

/**
 * apfs_evict_inode() - remove inode from main memory
 * @inode:	inode to discard
 *
 * apfs_evict_inode() is called on the final iput and frees the
 * private inode area.
 */
void apfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
}
