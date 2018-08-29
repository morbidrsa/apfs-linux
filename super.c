// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 Johannes Thumshirn
 */

#include <linux/module.h>

static int __init apfs_init(void)
{
	return 0;
}
module_init(apfs_init);

static void __exit apfs_exit(void)
{
	return;
}
module_exit(apfs_exit);

MODULE_AUTHOR("Johannes Thumshirn");
MODULE_LICENSE("GPL v2");
