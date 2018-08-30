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

/*
 * In Kernel Data Structures
 */

/**
 * apfs_info - In kernel superblock filesystem private data for APFS
 * @bp:		buffer bead for raw superblock
 */
struct apfs_info {
	struct apfs_container_sb	*nxsb;
	struct buffer_head		*bp;
};

/**
 * apfs_btree - In kernel filesystem object B-Tree
 * @mempool:	memory pool for allocations in this tree
 * @sb:		pointer to the tree's file systems's VFS super block
 * @root:	pointer to the root node
 */
struct apfs_btree {
	mempool_t		*mempool;
	struct super_block	*sb;
	struct apfs_bnode	*root;
};

/**
 * apfs_bnode - In kernel filesystem object B-Tree node
 * @tree:	the B-Tree this node belongs to
 * @block:	the disk block the node is located at
 */
struct apfs_bnode {
	struct apfs_btree	*tree;
	u64			block;
};

extern int apfs_create_btree_cache(void);
extern void apfs_destroy_btree_cache(void);
extern struct apfs_btree *apfs_btree_create(struct super_block *sb);
extern struct apfs_bnode *apfs_btree_create_node(struct apfs_btree *root,
						 u64 parent, u64 block);

/*
 * Helper Functions
 */

/**
 * APFS_SBI - get filesystem private data from VFS super block
 *
 * @sb:		the VFS super block
 */
static inline struct apfs_info* APFS_SBI(struct super_block *sb)
{
	return sb->s_fs_info;
}

#endif /* _APFS_H */
