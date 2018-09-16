// SPDX-License-Identifier: GPL-2.0
/*
 * apfs.h - APFS data structures
 *
 * Copyright (C) 2018 Johannes Thumshirn
 */

#ifndef _APFS_H
#define _APFS_H

#include <linux/mempool.h>
#include <linux/fs.h>

/*
 * On-disk Data Structures
 *
 * Based on:
 * https://static.ernw.de/whitepaper/ERNW_Whitepaper65_APFS-forensics_signed.pdf
 */

#define APFS_NXSB_MAGIC		0x4253584e /* NXSB */
#define APFS_APSB_MAGIC		0x42535041 /* APSB */

#define APFS_MAX_NAME			1024

#define APFS_INO_EXT_TYPE_NAME		0x4
#define APFS_INO_EXT_TYPE_DSTREAM	0x8
#define APFS_INO_EXT_TYPE_SPARSE_BYTES	0xd


enum apfs_obj_types {
	APFS_OBJ_NXSB		= 0x1,
	APFS_OBJ_BTROOT		= 0x2,
	APFS_OBJ_BTNODE		= 0x3,
	APFS_OBJ_SPACEMAN_HDR	= 0x5,
	APFS_OBJ_BITMAP_HDR	= 0x7,
	APFS_OBJ_BTREE_ROOT_PTR = 0xb,
	APFS_OBJ_ID_MAPPING	= 0xc,
	APFS_OBJ_APSB		= 0xd,
};

enum apfs_obj_subtype {
	APFS_OBJ_SUB_NONE	= 0x00,
	APFS_OBJ_SUB_HISTORY	= 0x09,
	APFS_OBJ_SUB_LOCATION	= 0x0b,
	APFS_OBJ_SUB_FILES	= 0x0e,
	APFS_OBJ_SUB_EXTENTS	= 0x0f,
	APFS_OBJ_SUB_UNKOWN	= 0x10,
};

/*
 * APFS On-Disk Object Header
 *
 * From APFS Forensics Table 1
 */
struct apfs_obj_header {
	__le64			checksum;
	__le64			oid;
	__le64			xid;
	__le16			type;
	__le16			flags;
	__le16			subtype;
	__le16			pad;
} __packed;

/*
 * APFS Container Super Block (NSXB)
 *
 * From APFS Forensics Table 2
 */
struct apfs_container_sb {
        struct apfs_obj_header	hdr;
        __le32 			magic;
        __le32 			block_size;
        __le64 			block_count;
        __le64 			features;
        __le64 			ro_compat_features;
        __le64 			incompat_features;
        u8 			uuid[16];
        __le64 			next_oid;
        __le64 			next_xid;
        __le32 			xp_desc_blocks;
        __le32 			xp_data_blocks;
        __le64 			xp_desc_base;
        __le64 			xp_data_base;
        __le32 			xp_desc_len;
        __le32 			xp_data_len;
        __le32 			xp_desc_index;
        __le32 			xp_desc_index_len;
        __le32 			xp_data_index;
        __le32 			xp_data_index_len;
        __le64 			spaceman_oid;
        __le64 			omap_oid;
        __le64 			reaper_oid;
        __le32 			unknown1;
        __le32 			max_file_systems;
        __le64 			fs_oid;
} __packed;

struct apfs_apsb_accessor_info {
	__le64			last_xid;
	char			id[32];
	__le64			timestamp;
};

struct apfs_volume_sb {
	struct apfs_obj_header	hdr;
	__le32 			magic;
	__le32 			fsidx;
	__le64 			features;
	__le64 			unk1;
	__le64 			unk2;
	__le64 			unk3;
	__le64 			fs_reseve_blk_cnt;
	__le64 			fs_quota_blk_cnt;
	__le64 			fs_alloc_count;
	__le64 			unk4;
	__le64 			unk5;
	__le64 			unk6;
	__le64 			unk7;
	__le64 			omap_oid;
	__le64 			root_tree_oid;
	__le64 			extentref_tree_oid;
	__le64 			snap_meta_tree_oid;
	__le64 			next_doc_id;
	__le64 			num_files;
	__le64 			num_directories;
	__le64 			num_symlinks;
	__le64 			num_other_fsobjects;
	__le64 			num_snapshots;
	__le64 			unk8;
	__le64 			unk9;
	__le64 			unk10;
	__le64 			unk11;
	u8			vol_uuid[16];
	__le64			last_mod_time;
	struct apfs_apsb_accessor_info ai[9];
	__le64			unk12;
	char			volname[0x100];
	__le64			unk13;
	__le64			unk14;
} __packed;

struct apfs_extent_header {
	__le16			num_extents;
	__le16			used_data;
} __packed;

struct apfs_extent_entry {
	u8			type;
	u8			flags;
	__le16			length;
} __packed;

struct apfs_dinode {
	__le64			parent_id;
	__le64			private_id;
	__le64			birthtime;
	__le64			mtime;
	__le64			ctime;
	__le64			atime;
	__le64			flags;
	__le32			children;
	__le32			protection_class;
	__le32			generation;
	__le32			bsd_flags;
	__le32			uid;
	__le32			gid;
	__le16			mode;
	__le16			pad;
	__le64			uncomp_size;
	struct apfs_extent_header extent_header;
	struct apfs_extent_entry  extents[];
} __packed;

struct apfs_btree_header {
        __le16			flags;
	__le16			level;
        __le32			key_count;
        __le16			table_space_offset;
        __le16			table_space_length;
        __le16			free_space_offset;
        __le16			free_space_length;
        __le16			key_free_list_space_offset;
        __le16			key_free_list_space_length;
        __le16			val_free_list_space_offset;
        __le16			val_free_list_space_length;
} __packed;

struct apfs_btree_root {
	struct apfs_obj_header	ohdr;
	__le16			flags;
	__le16			level;
	__le32			entries;
	struct {
		__le64		unknown;
		__le64		block;
	} entry[253];
} __packed;

struct apfs_btree_entry_fixed {
	__le16			key_offs;
	__le16			val_offs;
} __packed;

struct apfs_btree_entry_var {
	__le16			key_offs;
	__le16			key_len;
	__le16			val_offs;
	__le16			val_len;
} __packed;

struct apfs_btree_footer {
	__le32			unknown;
	__le32			nodesize;
	__le32			key_size;
	__le32			val_size;
	__le32			max_key_size;
	__le32			max_val_size;
	__le64			entries_cnt;
	__le64			nodes_cnt;
} __packed;

struct apfs_node_id_map_key {
	__le64			oid;
	__le64			xid;
} __packed;

struct apfs_node_id_map_value {
	__le32			flags;
	__le32			size;
	__le64			block;
} __packed;

struct apfs_dir_key {
	__le64			parent_id;
	__le32			hash;
	char			name[APFS_MAX_NAME];
} __packed;

struct apfs_dir_val {
	__le64			file_id;
	__le64			date_added;
	__le16			flags;
} __packed;

struct apfs_ext_dstream {
	__le64			size;
	__le64			allocated_size;
	__le64			crypto_id;
	__le64			unk[2];
} __packed;

struct apfs_file_ext_key {
	__le64			oid;
	__le64			offs;
} __packed;

struct apfs_file_ext_val {
	__le64			flags_length;
	__le64			phys_blocks;
	__le64			crypto_id;
} __packed;

/*
 * In Kernel Constants
 */
#define APFS_ROOT_INODE			2

/*
 * In Kernel Data Structures
 */

/**
 * apfs_info - In kernel superblock filesystem private data for APFS
 * @nxsb:	cached version of the container super block
 * @nxsb_bp:	buffer bead for raw container superblock
 * @blocksize:	cached version of the FS' block size
 * @xid:	super block transaction id
 * @nxsb_omap_root:	pointer to the container's object mapper b-tree root
 * @apsb:	cached version of the volume super block
 * @apsb_bp:	buffer head for the raw colume super block
 * @apsb_omap_root:	pointer to the container's object mapper b-tree root
 */
struct apfs_info {
	struct apfs_container_sb	*nxsb;
	struct buffer_head		*nxsb_bp;
	u32				blocksize;
	u64				xid;
	struct apfs_btree		*nxsb_omap_root;
	struct apfs_volume_sb		*apsb;
	struct buffer_head		*apsb_bp;
	struct apfs_btree		*apsb_omap_root;
	struct apfs_btree		*dir_tree_root;
};

struct apfs_inode {
	struct inode			vfs_inode;

	u16				mode;
	u32				nlink;
	u32				uid;
	u32				gid;
	u64				size;
	u64				mtime;
	u64				ctime;
	u64				atime;
	u32				generation;
	char				name[APFS_MAX_NAME];
};

typedef int (*apfs_btree_keycmp)(void *skey, size_t skey_len, void *ekey,
				 size_t ekey_len, void *ctx);
/**
 * apfs_btree - In kernel filesystem object B-Tree
 * @sb:		pointer to the tree's file systems's VFS super block
 * @root:	pointer to the root node
 * @entries:	number of entries in this tree
 * @bf:		btree footer of this tree
 */
struct apfs_btree {
	struct super_block	*sb;
	struct apfs_bnode	*root;
	struct apfs_btree	*omap;
	u32			entries;
	struct apfs_btree_footer *bf;
	apfs_btree_keycmp	keycmp;
};

enum apfs_btree_node_type {
	APFS_NODE_TYPE_FIXED,
	APFS_NODE_TYPE_VAR,
};

/**
 * apfs_bnode - In kernel filesystem object B-Tree node
 * @tree:	the B-Tree this node belongs to
 * @bp:		pointer to the node's buffer head
 * @keys_start: start of the key area
 * @vals_start: start of the value area
 * @level:	the level of the node
 * @ecnt:	number of entries
 * @parent:	node id of the parent, 0 if root
 * @block:	the disk block the node is located at
 * @key:	the key
 * @key_len:	the lenghth of the key
 * @val:	the value
 * @val_len:	the length of the value
 * @ohdr:	the object header on disk
 * @bh:		the btree header on disk
 * @entries:	the on-disk child nodes
 */
struct apfs_bnode {
	struct apfs_btree	*tree;
	struct buffer_head	*bp;

	u16			keys_start;
	u16			vals_start;
	u16			level;
	u16			ecnt;
	u64			parent;
	u64			block;

	void			*key;
	size_t			key_len;
	void			*val;
	size_t			val_len;

	struct apfs_obj_header	*ohdr;
	struct apfs_btree_header *bh;
	enum apfs_btree_node_type type;
	union {
		struct apfs_btree_entry_var	*ve;
		struct apfs_btree_entry_fixed	*fe;
	};
};

struct apfs_btree_search_entry {
	struct apfs_bnode	*node;
	void			*key;
	size_t			key_len;
	void			*val;
	size_t			val_len;
};

struct apfs_btree_iter {
	struct apfs_btree	*tree;
	struct apfs_bnode	*node;
	loff_t			pos;
	struct apfs_btree_search_entry *bte;
	struct apfs_btree_search_entry *se[253];
};

/*
 * B-Tree related functions
 */

extern struct apfs_btree *apfs_btree_create(struct super_block *sb, u64 block,
					    apfs_btree_keycmp keycmp,
					    struct apfs_btree *omap);
extern struct apfs_bnode *apfs_btree_create_node(struct apfs_btree *root,
					 u64 parent, u64 block, gfp_t gfp);
struct apfs_btree_search_entry *apfs_btree_lookup(struct apfs_btree *tree,
						  void *key, size_t key_size);
void apfs_btree_free_search_entry(struct apfs_btree_search_entry *se);
struct apfs_btree_iter *apfs_btree_get_iter(struct apfs_btree *tree,
					    void *key, size_t key_size,
					    loff_t start);
struct apfs_btree_iter *
apfs_btree_iter_next(struct apfs_btree_iter *it, void *key, size_t key_len);

bool apfs_btree_iter_dup(struct apfs_btree_iter *it,
			 struct apfs_btree_search_entry *bte);

#define APFS_BTREE_ITER_END	(loff_t)~0
static inline bool apfs_btree_iter_end(struct apfs_btree_iter *it)
{
	return it->pos == APFS_BTREE_ITER_END;
}

static inline void apfs_btree_free_iter(struct apfs_btree_iter *it)
{
	if (!it)
		return;

	apfs_btree_free_search_entry(it->bte);
	kfree(it);
}

extern int apfs_dir_keycmp(void *skey, size_t skey_len, void *ekey,
			   size_t ekey_len, void *ctx);

/*
 * Inode related functions
 */

extern struct inode *apfs_iget(struct super_block *sb, ino_t ino);

/*
 * Helper Functions
 */

/**
 * APFS_SBI() - get filesystem private data from VFS super block
 *
 * @sb:		the VFS super block
 */
static inline struct apfs_info* APFS_SBI(struct super_block *sb)
{
	return sb->s_fs_info;
}

/**
 * APFS_INO() - get filesystem private inode from VFS inode
 */
static inline struct apfs_inode *APFS_INO(struct inode *inode)
{
	return container_of(inode, struct apfs_inode, vfs_inode);
}
#endif /* _APFS_H */
