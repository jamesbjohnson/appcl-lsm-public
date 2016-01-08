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

#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/lsm_hooks.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/tty.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/nfs_mount.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/export.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <stdbool.h>

#include "appcl_posix.h"

#define FILE__READ     1
#define FILE__APPEND   2
#define FILE__WRITE    4
#define FILE__IOCTL    8

#define PACL_UNDEFINED_ID        (-1)

/* a_type field in acl_user_posix_entry_t */
#define PACL_TYPE_ACCESS         (0x8000)
#define PACL_TYPE_DEFAULT        (0x4000)

/* e_tag entry in struct posix_acl_entry */
#define PACL_USER_OBJ            (0x01)
#define PACL_USER                (0x02)
#define PACL_GROUP_OBJ           (0x04)
#define PACL_GROUP               (0x08)
#define PACL_MASK                (0x10)
#define PACL_OTHER               (0x20)

/* permissions in the e_perm field */
#define PACL_READ                (0x04)
#define PACL_WRITE               (0x02)
#define PACL_EXECUTE             (0x01)

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
