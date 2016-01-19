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
//#include <linux/xattr.h>

//#define FILE__READ     1
//#define FILE__APPEND   2
//#define FILE__WRITE    4
//#define FILE__IOCTL    8

#define PACL_UNDEFINED_ID        (-1)

/* a_type field in acl_user_posix_entry_t */
#define PACL_TYPE_ACCESS         (0x8000)
#define PACL_TYPE_DEFAULT        (0x4000)

/* e_tag entry in struct posix_acl_entry */
//#define ACL_USER_OBJ           (0x01)
#define APPCL_DEFINE                	(0x02)
//#define ACL_USER               (0x02)
//#define ACL_GROUP_OBJ          (0x04)
#define APPCL_GROUP               	(0x08)
//#define ACL_GROUP              (0x08)
#define APPCL_DEFAULT                	(0x10)
//#define ACL_MASK               (0x10)
#define APPCL_OTHER               	(0x20)

/* permissions in the e_perm field */
#define APPCL_READ                (0x04)
#define APPCL_WRITE               (0x02)
#define APPCL_EXECUTE             (0x01)

/* mask definitions */
#define A_READ                4
#define A_WRITE               2
#define A_EXEC		      1

/* maximum entries in permission entries array */
#define APPCL_MAX_INODE_ENTRIES	10

/*
 *
 * appcl_posix_pacl_entry
 *      - permission entry to a_entries array of inode_security_label
 *      - e_perm, file system permission to enforce
 *	- e_tag, entry tag, for future use (default group tags etc)
 *	- inode_sec_pathname, path of application to enfore entry
 *
 */

struct appcl_posix_pacl_entry {
	short			e_tag;
        unsigned short          e_perm;
	const char *inode_sec_pathname; /* path name */
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
	unsigned int            a_count;
	struct appcl_posix_pacl_entry a_entries[APPCL_MAX_INODE_ENTRIES];
	union {
                struct list_head list;  /* list of file_security_label */
                struct rcu_head rcu;    /* for freeing the inode_security_struct */
        };
	struct inode *inode;    /* back pointer to inode object */
        struct mutex lock;
};

/*
 *
 * file_security_label
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
                struct rcu_head rcu;    /* for freeing the inode_security_struct */
        };
	struct file *file;    /* back pointer to file object */
        struct mutex lock;
};

#endif /* __APPCL_LSM_H */
