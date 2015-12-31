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

#define FILE__READ     1
#define FILE__APPEND   2
#define FILE__WRITE    4
#define FILE__IOCTL    8

/* APPCL_to_text flags */
#define APPCL_TEXT_LONG		1
#define APPCL_TEXT_FILE_CONTEXT	2
#define APPCL_TEXT_DIRECTORY_CONTEXT	4
#define APPCL_TEXT_SHOW_MASKS		8
#define APPCL_TEXT_SIMPLIFY		16
#define APPCL_TEXT_ALIGN		32
#define APPCL_TEXT_NUMERIC_IDS	64

/* APPCL_from_text flags */
#define APPCL_TEXT_OWNER_MASK		1
#define APPCL_TEXT_GROUP_MASK		2
#define APPCL_TEXT_OTHER_MASK		4
#define APPCL_TEXT_FLAGS		8


/* a_flags values */
#define APPCL_AUTO_INHERIT			0x01
#define APPCL_PROTECTED			0x02
#define APPCL_DEFAULTED			0x04
#define APPCL_WRITE_THROUGH			0x40
#define APPCL_MASKED				0x80

/* e_type values */
#define RICHACE_ACCESS_ALLOWED_ACE_TYPE		0x0000
#define RICHACE_ACCESS_DENIED_ACE_TYPE		0x0001

/* e_flags bitflags */
#define RICHACE_FILE_INHERIT_ACE		0x0001
#define RICHACE_DIRECTORY_INHERIT_ACE		0x0002
#define RICHACE_NO_PROPAGATE_INHERIT_ACE	0x0004
#define RICHACE_INHERIT_ONLY_ACE		0x0008
#define RICHACE_IDENTIFIER_GROUP		0x0040
#define RICHACE_INHERITED_ACE			0x0080
#define RICHACE_UNMAPPED_WHO			0x2000
#define RICHACE_SPECIAL_WHO			0x4000

/* e_mask bitflags */
#define RICHACE_READ_DATA			0x00000001
#define RICHACE_LIST_DIRECTORY			0x00000001
#define RICHACE_WRITE_DATA			0x00000002
#define RICHACE_ADD_FILE			0x00000002
#define RICHACE_APPEND_DATA			0x00000004
#define RICHACE_ADD_SUBDIRECTORY		0x00000004
#define RICHACE_READ_NAMED_ATTRS		0x00000008
#define RICHACE_WRITE_NAMED_ATTRS		0x00000010
#define RICHACE_EXECUTE				0x00000020
#define RICHACE_DELETE_CHILD			0x00000040
#define RICHACE_READ_ATTRIBUTES			0x00000080
#define RICHACE_WRITE_ATTRIBUTES		0x00000100
#define RICHACE_WRITE_RETENTION			0x00000200
#define RICHACE_WRITE_RETENTION_HOLD		0x00000400
#define RICHACE_DELETE				0x00010000
#define RICHACE_READ_ACL			0x00020000
#define RICHACE_WRITE_ACL			0x00040000
#define RICHACE_WRITE_OWNER			0x00080000
#define RICHACE_SYNCHRONIZE			0x00100000

/* e_id values */
#define RICHACE_OWNER_SPECIAL_ID		0
#define RICHACE_GROUP_SPECIAL_ID		1
#define RICHACE_EVERYONE_SPECIAL_ID		2

#define APPCL_VALID_FLAGS (					\
	APPCL_AUTO_INHERIT |					\
	APPCL_PROTECTED |					\
	APPCL_DEFAULTED |					\
	APPCL_WRITE_THROUGH |					\
	APPCL_MASKED )

#define RICHACE_VALID_FLAGS (					\
	RICHACE_FILE_INHERIT_ACE |				\
	RICHACE_DIRECTORY_INHERIT_ACE |				\
	RICHACE_NO_PROPAGATE_INHERIT_ACE |			\
	RICHACE_INHERIT_ONLY_ACE |				\
	RICHACE_IDENTIFIER_GROUP |				\
	RICHACE_INHERITED_ACE |					\
	RICHACE_UNMAPPED_WHO |					\
	RICHACE_SPECIAL_WHO )

#define RICHACE_INHERITANCE_FLAGS (				\
	RICHACE_FILE_INHERIT_ACE |				\
	RICHACE_DIRECTORY_INHERIT_ACE |				\
	RICHACE_NO_PROPAGATE_INHERIT_ACE |			\
	RICHACE_INHERIT_ONLY_ACE |				\
	RICHACE_INHERITED_ACE )

/* Valid RICHACE_* flags for directories and non-directories */
#define RICHACE_VALID_MASK (					\
	RICHACE_READ_DATA | RICHACE_LIST_DIRECTORY |		\
	RICHACE_WRITE_DATA | RICHACE_ADD_FILE |			\
	RICHACE_APPEND_DATA | RICHACE_ADD_SUBDIRECTORY |	\
	RICHACE_READ_NAMED_ATTRS |				\
	RICHACE_WRITE_NAMED_ATTRS |				\
	RICHACE_EXECUTE |					\
	RICHACE_DELETE_CHILD |					\
	RICHACE_READ_ATTRIBUTES |				\
	RICHACE_WRITE_ATTRIBUTES |				\
	RICHACE_WRITE_RETENTION |				\
	RICHACE_WRITE_RETENTION_HOLD |				\
	RICHACE_DELETE |					\
	RICHACE_READ_ACL |					\
	RICHACE_WRITE_ACL |					\
	RICHACE_WRITE_OWNER |					\
	RICHACE_SYNCHRONIZE )

struct inode_security_label {
          const char *inode_sec_pathname;
          struct inode *inode;    /* back pointer to inode object */
          union {
                  struct list_head list;  /* list of inode_security_struct */
                  struct rcu_head rcu;    /* for freeing the inode_security_struct */
          };
          u16 sclass;             /* security class of this object */
          struct mutex lock;
};

struct richace {
	unsigned short	e_type;
	unsigned short	e_flags;
	unsigned int	e_mask;
	union {
		kuid_t		e_id;
		char *		e_who;
	};
};

#define appcl_for_each_entry(_ace, _isl) \
	for ((_ace) = (_isl)->a_entries; \
	     (_ace) != (_isl)->a_entries + (_isl)->a_count; \
	     (_ace)++)

#define appcl_for_each_entry_reverse(_ace, _isl) \
	for ((_ace) = (_isl)->a_entries + (_isl)->a_count - 1; \
	     (_ace) != (_isl)->a_entries - 1; \
	     (_ace)--)

struct file_security_label {
          struct file *file;    /* back pointer to file object */
          union {
                  struct list_head list;  /* list of inode_security_struct */
                  struct rcu_head rcu;    /* for freeing the inode_security_struct */
          };

          unsigned char	a_flags;
          unsigned short a_count;
          unsigned int a_owner_mask;
          unsigned int a_group_mask;
          unsigned int a_other_mask;

          u16 sclass;             /* security class of this object */
          struct mutex lock;
};

enum path_flags {
	PATH_IS_DIR = 0x1,	/* Path is  directory */
	PATH_CONNECT_PATH = 0x4, /* connect disconnected paths to / */
	PATH_CHROOT_REL = 0x8,	/* do path lookup relative to chroot */
	PATH_CHROOT_NSCONNECT = 0x10,	/* connect paths that are at ns root */

	PATH_DELEGATE_DELETED = 0x08000, /* delegate deleted file */
	PATH_MEDIATE_DELETED = 0x10000,	/* mediate deleted paths */
};
#endif /* __APPCL_LSM_H */
