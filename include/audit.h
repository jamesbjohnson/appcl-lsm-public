/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
AppCL - LSM audit.h

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

#ifndef __AUDIT_H
#define __AUDIT_H

#include <linux/stddef.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/audit.h>
#include <linux/path.h>
#include <linux/key.h>
#include <linux/skbuff.h>

/*
 *
 * task_audit_data - task security label
 * contains information for current process
 *      - binprm_pathname, path of binary application
 *
 */
struct task_audit_data {
        char type;
        const char *bprm_pathname;
#define APPCL_TASK_FREE     1
#define APPCL_TASK_PERM     0
        u16 tclass;
        u32 sid;
        union {
                struct dentry *dentry;
                struct inode *inode;
        } u;
};

/*
 *
 * common_audit_data
 * contains information for common audits
 *
 */
struct common_audit_data {
        char type;
        const char *tpath_name;
#define LSM_AUDIT_DATA_PATH     1
#define LSM_AUDIT_DATA_TASK     1
#define LSM_AUDIT_DATA_NONE     1
#define LSM_AUDIT_DATA_INODE    1
#define LSM_AUDIT_DATA_DENTRY   1
        union {
                const char *binprm_pathname;
                struct path path;
                struct dentry *dentry;
                struct inode *inode;
        } u;
};

#endif /* __AUDIT_H */
