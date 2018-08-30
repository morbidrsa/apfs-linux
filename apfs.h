// SPDX-License-Identifier: GPL-2.0
/*
 * apfs.h - APFS data structures
 *
 * Copyright (C) 2018 Johannes Thumshirn
 */

#ifndef _APFS_H
#define _APFS_H

/*
 * On-disk Data Structures
 *
 * Based on:
 * https://static.ernw.de/whitepaper/ERNW_Whitepaper65_APFS-forensics_signed.pdf
 */

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
 * apfs_nxsb_info - In kernel superblock filesystem private data for APFS
 * @bp:		buffer bead for raw superblock
 */
struct apfs_nxsb_info {
	struct apfs_container_sb	*nxsb;
	struct buffer_head		*bp;
};

#endif /* _APFS_H */
