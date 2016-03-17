/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
AppCL - LSM appcl_lsm.h

Linux kernel security module to implement program based access control mechanisms

    Author - James Johnson
    License - GNU General Public License v3.0
    Copyright (C) 2015  James Johnson

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    For a full copy of the GNU General Public License, see <http://www.gnu.org/licenses/>.

 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef __APPCL_LSM_H
#define __APPCL_LSM_H

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/file.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <linux/xattr.h>

/*
 * xattr security namespace
 */
#define XATTR_APPCL_SUFFIX "appcl"
#define XATTR_NAME_APPCL XATTR_SECURITY_PREFIX XATTR_APPCL_SUFFIX

/*
 * Default behaviour
 * - ALLOW, blacklisting
 * - DENY, whitelisting
 */
#define APPCL_DEFAULT_ALLOW "allow"
#define APPCL__ALLOW 			0
#define APPCL_DEFAULT_DENY "deny"
#define APPCL__DENY			1

/*
 * e_perm entry in appcl_pacl_entry, permission values
 */
#define APPCL_READ                	(0x04)
#define APPCL_WRITE               	(0x02)
#define APPCL_EXECUTE             	(0x01)
#define APPCL_DEFAULT_PERM             	(0x00)

/*
 * xattr e_perm representation
 */
#define XATTR_READ                	"r"
#define XATTR_WRITE               	"w"
#define XATTR_EXECUTE             	"x"

/*
 * xattr label definitions
 */
#define VALID_XV 			0
#define INVALID_XV			1
#define INITVALUELEN 			255
#define LOWERVALUELEN 			4

/*
 * maximum entries in permission entries array [a_entries]
 */
#define APPCL_MAX_INODE_ENTRIES		10

/*
 * maximum label length
 */
#define APPCL_LNG_LABEL	 		128

/*
 * inode inode_security_label->flags
 */
#define APPCL_INODE_INSTANT		8
#define APPCL_ATTR_SET			16

/*
 * default label values
 */
#define APPCL_VALUE_UNLABELLED "-/appcl-unlabelled"
#define APPCL_INIT_TASK "-/appcl-init-task"
#define appcl_known_star "*"
#define appcl_known_huh "?"
#define appcl_known_default "DEFAULT"

/*
 * e_tag entry in appcl_pacl_entry
 */
#define APPCL_DEFINE                	(0x02)
#define APPCL_GROUP               	(0x08)
#define APPCL_DEFAULT                	(0x10)
#define APPCL_OTHER               	(0x20)

/*
 *
 * appcl_pacl_entry
 *      - permission entry to a_entries array of inode_security_label
 *      - e_perm, file system permission to enforce
 *	- e_tag, entry tag, for future use (default group tags etc)
 *	- inode_sec_pathname, path of application to enfore entry
 *
 */

struct appcl_pacl_entry {
	short			e_tag;
        unsigned short          e_perm;
	const char *inode_sec_pathname; /* app path name */
};

/*
 *
 * inode_security_label
 *      - stored at inode->i_security
 *      - a_entries[APPCL_MAX_INODE_ENTRIES], array containing the file system
 	  permission entries for inode
 *
 */

struct inode_security_label {
	const char			*xvalue; /* xattr representation */
	const char 			*d_behaviour; /* default behaviour */
	/*
	 * permission entries array
	 */
	struct appcl_pacl_entry 	a_entries[APPCL_MAX_INODE_ENTRIES];
	unsigned int            	a_count; /* count of permission entries */
	int				flags;
	int 				valid_xvalue;
	union {
                struct list_head list;  /* list of inode_security_label */
                struct rcu_head rcu;    /* for freeing the inode_security_label */
        };
	struct inode *inode;    /* back pointer to inode object */
        struct mutex lock;
};

/*
 *
 * superblock_security_label
 *      - stored at superblock->s_security
 *
 */

struct superblock_security_label {
	struct super_block *sb;
        struct mutex lock;
	struct list_head isec_head;
	spinlock_t isec_lock;
};

/*
 *
 * file_security_label (currently unused)
 *      - stored at file->f_security
 *      - entries_count, count of permission entries for file object
 *	- perms, current permission for file object
 *
 */

struct file_security_label {
	unsigned short          perms;
	unsigned int		entries_count;
        union {
        	struct list_head list;  /* list of file_security_label */
                struct rcu_head rcu;    /* for freeing the file_security_label */
        };
	struct file *file;    /* back pointer to file object */
        struct mutex lock;
};

#endif /* __APPCL_LSM_H */
