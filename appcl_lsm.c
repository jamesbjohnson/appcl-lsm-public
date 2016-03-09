/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
AppCL - LSM appcl_lsm.c
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
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * INCLUDES
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

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
#include <linux/magic.h>
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
#include <linux/parser.h>
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

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/list.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/fsnotify.h>
#include <linux/path.h>
#include <linux/fdtable.h>
#include <linux/binfmts.h>
#include <linux/time.h>

#include "include/appcl_lsm.h"
#include "include/audit.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * APPCL-LSM MODULE PARAMS/VARS/FUNCTIONS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

MODULE_LICENSE("GPLv3");
MODULE_AUTHOR("James Johnson");

static struct kmem_cache *sel_inode_cache;
static struct kmem_cache *sel_file_cache;

struct appcl_pacl_entry make_appcl_entry(char *value)
{
	struct appcl_pacl_entry t_pe;
	const char *path = NULL;
	char *permSplit = NULL;
	char delim[1] = ";"; char split[1] = ":";
	char perm[1];
	int pe_perm;
	int len;

	len = strlen(value);

	/* GET PATH VALUE */
	if ((permSplit = strsep(&value, split)) != NULL) {
		len = strlen(permSplit);
		path = kstrdup(permSplit, GFP_KERNEL);
	}

	/* GET PERMISSION VALUE */
	if ((permSplit = strsep(&value, delim)) != NULL) {
		len = strlen(permSplit);
		perm[0] = permSplit[0];

		if (strncmp(perm, XATTR_READ, 1) == 0)
			pe_perm = APPCL_READ;
		else if (strncmp(perm, XATTR_WRITE, 1) == 0)
			pe_perm = APPCL_WRITE;
		else if (strncmp(perm, XATTR_EXECUTE, 1) == 0)
			pe_perm = APPCL_EXECUTE;
		else
			pe_perm = APPCL_OTHER;
	}

	int buf = 32;
	const char *nano = "/bin/nano";
	const char *vim = "/usr/bin/vim.basic";
	const char *cat = "/bin/cat";
	if (path != NULL) {
		if (strncmp(path, nano, buf) == 0) {
			t_pe.inode_sec_pathname = nano;
		} else if (strncmp(path, vim, buf) == 0){
			t_pe.inode_sec_pathname = vim;
		} else if (strncmp(path, cat, buf) == 0){
			t_pe.inode_sec_pathname = cat;
		} else {
			t_pe.inode_sec_pathname = APPCL_VALUE_UNLABELLED;
		}
	}

	if (pe_perm)
		t_pe.e_perm = pe_perm;
	else
		t_pe.e_perm = APPCL_OTHER;

	t_pe.e_tag = APPCL_DEFINE;

	return t_pe;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * LSM SECURITY HOOK FUNCTIONS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * XATTR HOOKS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int appcl_inode_setotherxattr(struct dentry *dentry, const char *name)
{
	if (strncmp(name, XATTR_SECURITY_PREFIX, sizeof XATTR_SECURITY_PREFIX - 1) == 0) {
		if (strcmp(name, XATTR_NAME_CAPS) == 0) {
			if (!capable(CAP_SETFCAP))
				return -EPERM;
		} else if (!capable(CAP_SYS_ADMIN)) {
			/* A different attribute to the security namespace
			   Restrict to administrator. */
			   return -EPERM;
		}
	}
	/* Not an attribute we recogise, todo: so just check for 'WRITE?'
	(setattr) permission */
	return 0;
}

static int appcl_lsm_inode_setxattr(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags)
{
	int ret;

	if (strncmp(name, XATTR_NAME_APPCL, sizeof XATTR_NAME_APPCL - 1) == 0) {
		ret = 0;
	} else {
		ret = appcl_inode_setotherxattr(dentry, name);
	}

	return ret;
}

static void appcl_lsm_inode_post_setxattr(struct dentry *dentry, const char *name,
                                   const void *value, size_t size, int flags)
{
	struct inode *inode = d_backing_inode(dentry);
	struct inode_security_label *ilabel = inode->i_security;
	struct appcl_pacl_entry pe;
	const char *xvalue;

	if (strncmp(name, XATTR_NAME_APPCL, sizeof XATTR_NAME_APPCL - 1) == 0) {
		if (value) {

			char *temp = (char*)value;
			char *opt = NULL;
			char delim[1] = ";";

			printk(KERN_ALERT "POSTSETXATTR VALUE: %s\n", temp);

			xvalue = kstrdup(temp, GFP_KERNEL);
			ilabel->xvalue = kstrdup(xvalue, GFP_KERNEL);

			size_t i;
			for (i = 0; i < APPCL_MAX_INODE_ENTRIES; i++) {
				if ((opt = strsep(&temp, delim)) != NULL) {
					pe = make_appcl_entry(opt);
					ilabel->a_entries[i] = pe;
				} else {
					break;
				}
			}

			ilabel->a_count = i - 1;
			pe = ilabel->a_entries[0];
			if (pe.e_perm == APPCL_OTHER)
				ilabel->valid_xvalue = INVALID_XV;
			else
				ilabel->valid_xvalue = VALID_XV;

			ilabel->inode = inode;

			printk(KERN_ALERT "POSTSETXATTR I_XVALUE: %s\n", ilabel->xvalue);
			printk(KERN_ALERT "POSTSETXATTR XVALUE FLAG: %d\n", ilabel->valid_xvalue);
			printk(KERN_ALERT "POSTSETXATTR A_COUNT: %d\n", ilabel->a_count);


		}
	}

	return;
}

static int appcl_lsm_inode_getxattr(struct dentry *dentry, const char *name)
{

	if (!strncmp(name, XATTR_NAME_APPCL, sizeof XATTR_NAME_APPCL - 1))
		return 0;

	return 0;
}
/*
static int appcl_lsm_inode_listxattr(struct dentry *dentry)
{
	return 0;
}
*/
static int appcl_lsm_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (strcmp(name, XATTR_NAME_APPCL))
		return appcl_inode_setotherxattr(dentry, name);

	/* No one is allowed to remove AppCL label at present todo: */
	return -EACCES;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * XATTR SECURITY HOOKS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int appcl_lsm_inode_init_security(struct inode *inode, struct inode *dir,
                                        const struct qstr *qstr, const char **name,
					void **value, size_t *len)
{
	struct inode_security_label *ilabel = inode->i_security;
	struct inode_security_label *dirlabel = dir->i_security;
	const char *nano = "/bin/nano:w;";

	if (name)
		*name = XATTR_APPCL_SUFFIX;

	if (value && len) {
		ilabel = dirlabel;

		*value = kstrdup(nano, GFP_NOFS);
		if (*value == NULL) {
			printk(KERN_ALERT "INITSECURITY -ENOMEM \n");
			return -ENOMEM;
		}

		*len = strlen(nano);

		printk(KERN_ALERT "INITSECURITY HASLEN! \n");
	}

	return 0;
}

/*
static int appcl_lsm_inode_getsecurity(const struct inode *inode, const char *name,
                                        void **buffer, bool alloc)
{

	struct inode_security_label *ilabel = inode->i_security;
	struct inode *x_inode = (struct inode *)inode;
	const char *i_xvalue;
	int ilen;
	const char *nano = "/bin/nano:w;";


	if (strcmp(name, XATTR_APPCL_SUFFIX) == 0) {

		ilen = strlen(nano);
		*buffer = nano;

		printk(KERN_ALERT "GETSECURITY RETURN BUFFER: %s \n", nano);
		printk(KERN_ALERT "GETSECURITY RETURN ILEN: %d \n", ilen);

		return ilen;
	}

	return 0;
}
*/
static int appcl_lsm_inode_setsecurity(struct inode *inode, const char *name,
                                        const void *value, size_t size, int flags)
{
	struct inode_security_label *ilabel = inode->i_security;
	struct appcl_pacl_entry pe;
	const char *xvalue;

	if (strcmp(name, XATTR_APPCL_SUFFIX))
		return -EOPNOTSUPP;

	if (value == NULL || size > APPCL_LNG_LABEL || size == 0)
		return -EINVAL;

		if (value) {

			char *temp = (char*)value;
			char *opt = NULL;
			char delim[1] = ";";

			printk(KERN_ALERT "POSTSETXATTR VALUE: %s\n", temp);

			xvalue = kstrdup(temp, GFP_KERNEL);
			ilabel->xvalue = kstrdup(xvalue, GFP_KERNEL);

			size_t i;
			for (i = 0; i < APPCL_MAX_INODE_ENTRIES; i++) {
				if ((opt = strsep(&temp, delim)) != NULL) {
					pe = make_appcl_entry(opt);
					ilabel->a_entries[i] = pe;
				} else {
					break;
				}
			}

			ilabel->a_count = i - 1;
			pe = ilabel->a_entries[0];
			if (pe.e_perm == APPCL_OTHER)
				ilabel->valid_xvalue = INVALID_XV;
			else
				ilabel->valid_xvalue = VALID_XV;

			ilabel->inode = inode;
		}
	return 0;
}

static int isvalid_xvalue(char *xvalue, int LOWERVALUELEN)
{
	if (xvalue == NULL)
		return INVALID_XV;

	if ((strncmp(xvalue, appcl_known_huh, LOWERVALUELEN) == 0) ||
 		(strncmp(xvalue, appcl_known_star, LOWERVALUELEN) == 0) ||
		(strncmp(xvalue, appcl_known_default, LOWERVALUELEN) == 0)) {
		return INVALID_XV;
	} else {
		if (strlen(xvalue) > LOWERVALUELEN)
			return VALID_XV;
		else
			return INVALID_XV;
	}
}

static int inode_do_init(struct inode *inode, struct dentry *dentry)
{
	struct inode_security_label *ilabel = inode->i_security;
	struct dentry *x_dentry;
#define INITVALUELEN 255
#define LOWERVALUELEN 4
	char *value = NULL;
	char *final_xvalue = NULL;
	unsigned int len = 0;
	int rc = 0;

	struct super_block *sbp;
	sbp = inode->i_sb;

	mutex_lock(&ilabel->lock);

	if (ilabel->flags & APPCL_INODE_INSTANT)
		goto outunlock;

	if (dentry->d_parent == dentry) {
		/* root inode */
		switch (sbp->s_magic) {
			case  CGROUP_SUPER_MAGIC:
				final_xvalue = appcl_known_star;
				break;
			case TMPFS_MAGIC:
				final_xvalue = appcl_known_star;
				break;
			case PIPEFS_MAGIC:
				final_xvalue = appcl_known_star;
				break;
			default:
				final_xvalue = appcl_known_default;
				break;
		}
		if (final_xvalue)
			ilabel->xvalue = final_xvalue;
		else
			ilabel->xvalue = appcl_known_huh;

		ilabel->flags = APPCL_INODE_INSTANT;

		goto outunlock;
	}

	switch (sbp->s_magic) {
		case SMACK_MAGIC:
		case PIPEFS_MAGIC:
		case SOCKFS_MAGIC:
		case CGROUP_SUPER_MAGIC:
			final_xvalue = appcl_known_star;
			break;
		case DEVPTS_SUPER_MAGIC:
			final_xvalue = appcl_known_star;
			break;
		case PROC_SUPER_MAGIC:
			final_xvalue = appcl_known_star;
			break;
		case TMPFS_MAGIC:
			final_xvalue = appcl_known_star;
		default:
			if (!inode->i_op->getxattr)
				goto outunlock;

			if (dentry)
				x_dentry = dget(dentry);
			if (!x_dentry)
				goto outunlock;

			len = INITVALUELEN;
			value = kmalloc(len+1, GFP_NOFS);
			if (!value) {
				rc = -ENOMEM;
				dput(x_dentry);
				goto outunlock;
			}
			value[len] = '\0';
			rc = inode->i_op->getxattr(x_dentry, XATTR_NAME_APPCL, value, len);
			if (value != NULL) {
				struct appcl_pacl_entry pe;
				char *opt = NULL;
				char delim[1] = ";";
				char *temp = (char*)value;

				final_xvalue = kstrdup(temp, GFP_KERNEL);

				size_t i;
				for (i = 0; i < APPCL_MAX_INODE_ENTRIES; i++) {
					if ((opt = strsep(&temp, delim)) != NULL) {
						pe = make_appcl_entry(opt);
						ilabel->a_entries[i] = pe;
					} else {
						break;
					}
				}
				ilabel->a_count = i - 1;
			}
			dput(x_dentry);
			kfree(value);
	}

	if (final_xvalue != NULL) {
		if (strlen(final_xvalue) > LOWERVALUELEN)
			ilabel->xvalue = final_xvalue;
		else
			ilabel->xvalue = appcl_known_huh;
	}

	ilabel->valid_xvalue = isvalid_xvalue(ilabel->xvalue, LOWERVALUELEN);
	ilabel->flags = APPCL_INODE_INSTANT;

	goto outunlock;

outunlock:
	if (!ilabel->a_count)
		ilabel->a_count = 0;
	ilabel->inode = inode;
	mutex_unlock(&ilabel->lock);
	return rc;
}

static void appcl_lsm_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	if (inode)
		inode_do_init(inode, dentry);
}
/*
static int appcl_lsm_inode_listsecurity(struct inode *inode, char *buffer,
                                        size_t buffer_size)
{
	int len = sizeof(XATTR_NAME_APPCL);
        if (buffer != NULL && len <= buffer_size)
                memcpy(buffer, XATTR_NAME_APPCL, len);
        return len;
}

static int appcl_lsm_ismaclabel(const char *name)
{
	return (strcmp(name, XATTR_APPCL_SUFFIX) == 0);
}
*/
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * SECURITY CONTEXT HOOKS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*
static void appcl_lsm_release_secctx(char *secdata, u32 seclen)
{
}

static int appcl_lsm_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return appcl_lsm_inode_setsecurity(inode, XATTR_APPCL_SUFFIX, ctx, ctxlen, 0);
	//return 0;
}

static int appcl_lsm_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return __vfs_setxattr_noperm(dentry, XATTR_NAME_APPCL, ctx, ctxlen, 0);
	//return 0;
}
*/
/*
static int appcl_lsm_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	int len = 0;
        len = appcl_lsm_inode_getsecurity(inode, XATTR_APPCL_SUFFIX, ctx, true);

        if (len < 0)
                return len;
        *ctxlen = len;
        return 0;
}
*/
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * INODE SECURITY HOOKS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int appcl_lsm_inode_alloc_security(struct inode *inode)
{
	struct inode_security_label *ilabel;

	ilabel = kmem_cache_zalloc(sel_inode_cache, GFP_NOFS);
	if (!ilabel)
        	return -ENOMEM;

	mutex_init(&ilabel->lock);
        INIT_LIST_HEAD(&ilabel->list);

	size_t i;
	struct appcl_pacl_entry pe;
	for (i = 0; i < APPCL_MAX_INODE_ENTRIES; i++) {
		pe.inode_sec_pathname = NULL;
		pe.e_perm = 0;
		pe.e_tag = 0;
		ilabel->a_entries[i] = pe;
        }
	ilabel->xvalue = APPCL_VALUE_UNLABELLED;
	ilabel->valid_xvalue = INVALID_XV;
	ilabel->a_count = 0;
	ilabel->flags = 0;
	ilabel->inode = inode;
	inode->i_security = ilabel;

	return 0;
}

static void inode_free_rcu(struct rcu_head *head)
{
         struct inode_security_label *ilabel;

         ilabel = container_of(head, struct inode_security_label, rcu);
         kmem_cache_free(sel_inode_cache, ilabel);
	 return;
}

static void appcl_lsm_inode_free_security(struct inode *inode)
{
	struct inode_security_label *ilabel = inode->i_security;
	struct superblock_security_label *slabel = inode->i_sb->s_security;

	if (!list_empty_careful(&ilabel->list)) {
		spin_lock(&slabel->isec_lock);
                list_del_init(&ilabel->list);
		spin_unlock(&slabel->isec_lock);
	}

	call_rcu(&ilabel->rcu, inode_free_rcu);

	return;
}

static int appcl_lsm_inode_permission(struct inode *inode, int mask)
{
	const struct cred *c_cred;
	struct inode_security_label *ilabel;

	ilabel = inode->i_security;
	if (!ilabel || !mask)
		return 0;

	c_cred = get_current_cred();
        validate_creds(c_cred);

        if (unlikely(IS_PRIVATE(inode)))
                return 0;

if (check_inode_path_match(inode, c_cred)) {
	if (appcl_check_permission_mask_match(ilabel, c_cred, mask)) {
		printk(KERN_ALERT "INODE PERMISSION: MATCH -EACCES: %d \n", mask);
		put_cred(c_cred);
		return -EACCES;
	} else {
		put_cred(c_cred);
		return 0;
	}
}

	put_cred(c_cred);
	return 0;
}

static int appcl_lsm_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	return 0;
}

static int appcl_lsm_inode_getattr(const struct path *path)
{
	return 0;
}

/*
static int appcl_lsm_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return 0;
}
static int appcl_lsm_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return 0;
}
static int appcl_lsm_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	return 0;
}
*/
static int appcl_lsm_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
				  struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *inode = d_backing_inode(old_dentry);
	struct inode_security_label *ilabel = inode->i_security;

	if (!ilabel)
		return 0;

	const char *i_xvalue = ilabel->xvalue;
	if (i_xvalue != NULL) {
		if (strlen(i_xvalue) > 2)
			if (strcmp(i_xvalue, APPCL_VALUE_UNLABELLED))
				printk(KERN_ALERT "INODE RENAME: I_XVALUE: %s \n", i_xvalue);
	}

	const struct cred *c_cred;
	c_cred = get_current_cred();

	if (check_inode_path_match(inode, c_cred)) {
		if (appcl_check_rperm_match(ilabel, c_cred, MAY_WRITE, MAY_WRITE)) {
			printk(KERN_ALERT "INODE RENAME: MATCH WRITE PERM \n");
			put_cred(c_cred);
			return -EACCES;
		} else {
			put_cred(c_cred);
			return -EACCES;
		}
	}

	put_cred(c_cred);
	return 0;
}

static int appcl_lsm_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode_security_label *ilabel = dir->i_security;
	const struct cred *c_cred;
	c_cred = get_current_cred();

	if (check_inode_path_match(dir, c_cred)) {
		if (appcl_check_rperm_match(ilabel, c_cred, MAY_WRITE, MAY_WRITE)) {
			printk(KERN_ALERT "INODE CREATE: MATCH WRITE PERM \n");
			put_cred(c_cred);
			return 0;
		} else {
			put_cred(c_cred);
			return -EACCES;
		}
	}

	put_cred(c_cred);
	return 0;
}

/*
static int appcl_lsm_inode_readlink(struct dentry *dentry)
{
	return 0;
}

static int appcl_lsm_inode_follow_link(struct dentry *dentry, struct inode *inode, bool rcu)
{
	return 0;
}

static int appcl_lsm_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	return 0;
}

static int appcl_lsm_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

static int appcl_lsm_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name)
{
	return 0;
}

static int appcl_lsm_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	return 0;
}

static int appcl_lsm_inode_getattr(const struct path *path)
{
	return 0;
}
*/

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * FILE SECURITY HOOKS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int appcl_lsm_file_alloc_security(struct file *file)
{
	struct file_security_label *flabel;

	flabel = kmem_cache_zalloc(sel_file_cache, GFP_NOFS);
	if (!flabel)
        	return -ENOMEM;

	mutex_init(&flabel->lock);
        INIT_LIST_HEAD(&flabel->list);

        flabel->perms = 0x00;
        flabel->entries_count = 0;
        flabel->file = file;

	file->f_security = flabel;

	return 0;
}

static void file_free_rcu(struct rcu_head *head)
{
         struct file_security_label *flabel;

         flabel = container_of(head, struct file_security_label, rcu);
         kmem_cache_free(sel_file_cache, flabel);
	 return;
}

static void appcl_lsm_file_free_security(struct file *file)
{
	struct file_security_label *flabel = file->f_security;

	if (!list_empty_careful(&flabel->list))
                 list_del_init(&flabel->list);

	call_rcu(&flabel->rcu, file_free_rcu);
	return;
}

static int appcl_lsm_file_permission(struct file *file, int mask)
{
        struct inode *inode = file_inode(file);
	const struct cred *c_cred;
	struct inode_security_label *ilabel;

	ilabel = inode->i_security;
	if (!ilabel || !mask)
		return 0;

	c_cred = get_current_cred();
	validate_creds(c_cred);

	if (unlikely(IS_PRIVATE(inode)))
		return 0;

if (check_inode_path_match(inode, c_cred)) {
	if (appcl_check_permission_mask_match(ilabel, c_cred, mask)) {
		put_cred(c_cred);
		printk(KERN_ALERT "INODE PERMISSION: MATCH -EACCES: %d \n", mask);
		return -EACCES;
	} else {
		put_cred(c_cred);
		return 0;
	}
}

	put_cred(c_cred);
	return 0;
}

static int appcl_lsm_file_open(struct file *file, const struct cred *cred)
{
        struct inode *inode = file_inode(file);
        struct inode_security_label *ilabel;

        ilabel = inode->i_security;
        if (!ilabel)
                return 0;
	/*
	const char *i_xvalue = ilabel->xvalue;
	if (ilabel->xvalue != NULL) {
		if (strlen(i_xvalue) > 2)
			if (strcmp(i_xvalue, APPCL_VALUE_UNLABELLED))
				printk(KERN_ALERT "FILE OPEN: I_XVALUE: %s \n", i_xvalue);
	}
	*/
	const struct cred *c_cred;
	c_cred = get_current_cred();

if (check_inode_path_match(inode, c_cred)) {
	if (appcl_check_rperm_match(ilabel, c_cred, MAY_READ, MAY_READ)) {
		printk(KERN_ALERT "FILE OPEN: MATCH READ PERM \n");
		put_cred(c_cred);
		return 0;
	} else {
		put_cred(c_cred);
		return -EACCES;
	}
}

	put_cred(c_cred);
        return 0;
}
/*
static int appcl_lsm_file_receive(struct file *file)
{
	return 0;
}
*/
static int appcl_lsm_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return 0;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * SUPERBLOCK SECURITY HOOKS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int appcl_lsm_sb_alloc_security(struct super_block *sb)
{
	struct superblock_security_label *slabel;

	slabel = kzalloc(sizeof(struct superblock_security_label), GFP_KERNEL);
        if (!slabel)
                return -ENOMEM;

        mutex_init(&slabel->lock);
        INIT_LIST_HEAD(&slabel->isec_head);
        spin_lock_init(&slabel->isec_lock);
	slabel->sb = sb;

	sb->s_security = slabel;

	return 0;
}

static void appcl_lsm_sb_free_security(struct super_block *sb)
{
	struct superblock_security_struct *slabel = sb->s_security;
        sb->s_security = NULL;
        kfree(slabel);
	return;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * BPRM SECURITY HOOKS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int appcl_lsm_bprm_set_creds(struct linux_binprm *bprm)
{
	struct task_audit_data *newtd; /* cred security label */
        struct inode *inode = file_inode(bprm->file);
        char *fpath_name; /* temp path name */
        char *cred_path; /* saved path name */
        char *tmp;
        struct path *fpath;

	if (bprm->cred_prepared)
		return 0;

	newtd = bprm->cred->security;

	spin_lock(&bprm->file->f_lock);
	fpath = &bprm->file->f_path;
        path_get(fpath);
	spin_unlock(&bprm->file->f_lock);

        tmp = (char *)__get_free_page(GFP_TEMPORARY);
        if (!tmp) {
	        path_put(fpath);
	        return -ENOMEM;
	}

	fpath_name = d_path(fpath, tmp, PAGE_SIZE);
	path_put(fpath);

        if (IS_ERR(fpath_name))
                fpath_name = bprm->filename;

        if (fpath_name == NULL || strlen(fpath_name) < 1)
                cred_path = APPCL_VALUE_UNLABELLED;
        else
                cred_path = fpath_name;

        newtd->bprm_pathname = cred_path;
        newtd->u.inode = inode;
        bprm->cred->security = newtd;

        free_page((unsigned long) tmp);
        return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * CRED SECURITY HOOKS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int appcl_lsm_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct task_audit_data *newtd;

        newtd = kzalloc(sizeof(struct task_audit_data), gfp);
        if (!newtd)
                return -ENOMEM;

        cred->security = newtd;
	return 0;
}

static void appcl_lsm_cred_free(struct cred *cred)
{
	struct task_audit_data *newtd = cred->security;

        cred->security = (void *) 0x7UL;
        kfree(newtd);

	return;
}

static int appcl_lsm_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	const struct task_audit_data *td;
        struct task_audit_data *newtd;

        td = old->security;

        newtd = kmemdup(td, sizeof(struct task_audit_data), gfp);
        if (!newtd)
                return -ENOMEM;

        new->security = newtd;

        return 0;
}

static void appcl_lsm_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct task_audit_data *td = old->security;
        struct task_audit_data *newtd = new->security;

        *newtd = *td;

	return;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * APPCL-LSM SECURITY HOOK LIST STRUCTURE
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static struct security_hook_list appcl_hooks[] = {
	/* XATTR HOOKS */
	LSM_HOOK_INIT(inode_setxattr, appcl_lsm_inode_setxattr),
	LSM_HOOK_INIT(inode_post_setxattr, appcl_lsm_inode_post_setxattr),
	LSM_HOOK_INIT(inode_getxattr, appcl_lsm_inode_getxattr),
	//LSM_HOOK_INIT(inode_listxattr, appcl_lsm_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr, appcl_lsm_inode_removexattr),
	/* SUPERBLOCK HOOKS */
	LSM_HOOK_INIT(sb_alloc_security, appcl_lsm_sb_alloc_security),
	LSM_HOOK_INIT(sb_free_security, appcl_lsm_sb_free_security),
	/* INODE HOOKS */
	LSM_HOOK_INIT(inode_alloc_security, appcl_lsm_inode_alloc_security),
        LSM_HOOK_INIT(inode_free_security, appcl_lsm_inode_free_security),
	LSM_HOOK_INIT(inode_permission, appcl_lsm_inode_permission),
	//LSM_HOOK_INIT(inode_setattr, appcl_lsm_inode_setattr),
	//LSM_HOOK_INIT(inode_getattr, appcl_lsm_inode_getattr),
	LSM_HOOK_INIT(inode_create, appcl_lsm_inode_create),
	//LSM_HOOK_INIT(inode_link, appcl_lsm_inode_link),
	//LSM_HOOK_INIT(inode_unlink, appcl_lsm_inode_unlink),
	//LSM_HOOK_INIT(inode_symlink, appcl_lsm_inode_symlink),
	//LSM_HOOK_INIT(inode_mkdir, appcl_lsm_inode_mkdir),
	//LSM_HOOK_INIT(inode_rmdir, appcl_lsm_inode_rmdir),
	//LSM_HOOK_INIT(inode_mknod, appcl_lsm_inode_mknod),
	LSM_HOOK_INIT(inode_rename, appcl_lsm_inode_rename),
	//LSM_HOOK_INIT(inode_readlink, appcl_lsm_inode_readlink),
	//LSM_HOOK_INIT(inode_follow_link, appcl_lsm_inode_follow_link),
	//LSM_HOOK_INIT(inode_init_security, appcl_lsm_inode_init_security),
	LSM_HOOK_INIT(inode_setsecurity, appcl_lsm_inode_setsecurity),
	//LSM_HOOK_INIT(inode_getsecurity, appcl_lsm_inode_getsecurity),
	//LSM_HOOK_INIT(inode_listsecurity, appcl_lsm_inode_listsecurity),
	LSM_HOOK_INIT(d_instantiate, appcl_lsm_d_instantiate),

	//LSM_HOOK_INIT(ismaclabel, appcl_lsm_ismaclabel),
	//LSM_HOOK_INIT(release_secctx, appcl_lsm_release_secctx),
	//LSM_HOOK_INIT(inode_notifysecctx, appcl_lsm_inode_notifysecctx),
	//LSM_HOOK_INIT(inode_setsecctx, appcl_lsm_inode_setsecctx),
	//LSM_HOOK_INIT(inode_getsecctx, appcl_lsm_inode_getsecctx),

	/* FILE HOOKS */
	LSM_HOOK_INIT(file_alloc_security, appcl_lsm_file_alloc_security),
	LSM_HOOK_INIT(file_free_security, appcl_lsm_file_free_security),
	LSM_HOOK_INIT(file_permission, appcl_lsm_file_permission),
	LSM_HOOK_INIT(file_fcntl, appcl_lsm_file_fcntl),
	LSM_HOOK_INIT(file_open, appcl_lsm_file_open),
	//LSM_HOOK_INIT(file_receive, appcl_lsm_file_receive),
	/* CRED HOOKS */
	LSM_HOOK_INIT(bprm_set_creds, appcl_lsm_bprm_set_creds),
	LSM_HOOK_INIT(cred_alloc_blank, appcl_lsm_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, appcl_lsm_cred_free),
	LSM_HOOK_INIT(cred_prepare, appcl_lsm_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, appcl_lsm_cred_transfer),
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * APPCL-LSM MODULE INIT
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
 static void init_task_audit_data(void) {

 	struct cred *cred;
        struct task_audit_data *newtd;
 	cred = get_current_cred();

        newtd = kzalloc(sizeof(struct task_audit_data), GFP_KERNEL);
        if (!newtd) {
                put_cred(cred);
                panic("AppCL LSM:  Failed to initialise initial task.\n");
        }

 	newtd->bprm_pathname = APPCL_INIT_TASK;
        cred->security = newtd;

 	put_cred(cred);
 	return;
 }

static int __init appcl_lsm_init(void)
{
	printk(KERN_ALERT "AppCL - LSM Security Module Initialising ... \n");

	/*
	 * Set security attributes for initial task
	 */
	init_task_audit_data();

	sel_inode_cache = kmem_cache_create("appcl_lsm_inode_security",
                                	sizeof(struct inode_security_label),
                                             0, SLAB_PANIC, NULL);

	sel_file_cache = kmem_cache_create("appcl_lsm_file_security",
				        sizeof(struct file_security_label),
				        	0, SLAB_PANIC, NULL);
	/*
	 * Register with LSM
	 */
	security_add_hooks(appcl_hooks, ARRAY_SIZE(appcl_hooks));

	printk(KERN_ALERT "AppCL - LSM Security Module Successfully Initialised\n");

	return 0;
}

security_initcall(appcl_lsm_init);
