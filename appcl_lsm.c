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
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <linux/string.h>
#include <linux/selinux.h>
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

#include "include/appcl_lsm.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * LSM SECURITY HOOK FUNCTIONS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static struct kmem_cache *sel_inode_cache;

/*
static int appcl_lsm_capable(const struct cred *cred, struct user_namespace *ns,
			    int cap, int audit)
{
	return 0;
}
*/
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * BPRM SECURITY HOOKS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int appcl_lsm_bprm_set_creds(struct linux_binprm *bprm)
{
	//printk(KERN_ALERT "AppCL LSM bprm_set_creds security hook\n");
	return 0;
}
/*
static int appcl_lsm_bprm_check(struct linux_binprm *bprm)
{
	return 0;
}
*/
static void appcl_lsm_bprm_committing_creds(struct linux_binprm *bprm)
{
	return;
}

static void appcl_lsm_bprm_committed_creds(struct linux_binprm *bprm)
{
	return;
}

static int appcl_lsm_bprm_secureexec(struct linux_binprm *bprm)
{
	return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * INODE SECURITY HOOKS
 * With thanks to SELinux
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int appcl_lsm_inode_alloc_security(struct inode *inode)
{
	printk(KERN_ALERT "INODE ALLOC SECURITY START \n");
	struct inode_security_struct *isec;
	kuid_t sid = current_suid();

	isec = kmem_cache_zalloc(sel_inode_cache, GFP_NOFS);
	if (!isec)
        	return -ENOMEM;

	mutex_init(&isec->lock);
        INIT_LIST_HEAD(&isec->list);
	isec->inode = inode;
	isec->sid = sid;
	isec->sclass = 0x4000;
	isec->task_sid = sid;
	inode->i_security = isec;

	printk(KERN_ALERT "INODE INODE ADDR: 0x%08x\n", &inode);
	printk(KERN_ALERT "INODE SID: %08x\n", isec->sid );
	printk(KERN_ALERT "INODE SCLASS: %08x\n", isec->sclass );
	printk(KERN_ALERT "INODE ISEC ADDR: 0x%08x\n", &isec );
	printk(KERN_ALERT "INODE ALLOC SECURITY END \n");

	return 0;
}

static void inode_free_rcu(struct rcu_head *head)
{
         struct inode_security_struct *isec;

         isec = container_of(head, struct inode_security_struct, rcu);
         kmem_cache_free(sel_inode_cache, isec);
	 return;
}

static void appcl_lsm_inode_free_security(struct inode *inode)
{
	printk(KERN_ALERT "INODE FREE SECURITY START \n");
	struct inode_security_struct *isec = inode->i_security;

	if (!list_empty_careful(&isec->list))
                 list_del_init(&isec->list);

	call_rcu(&isec->rcu, inode_free_rcu);

	printk(KERN_ALERT "INODE FREE SECURITY END \n");
	return;
}

/*
static int appcl_lsm_inode_init_security(struct inode *inode, struct inode *dir,
                                  const struct qstr *qstr,
                                  initxattrs initxattrs, void *fs_data)
{
	return 0;
}
*/

static int appcl_lsm_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return 0;
}

static int appcl_lsm_inode_link(struct dentry *old_dentry, struct inode *dir,
                          	struct dentry *new_dentry)
{
	return 0;
}

static int appcl_lsm_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

static int appcl_lsm_inode_symlink(struct inode *dir, struct dentry *dentry,
                            	const char *old_name)
{
	return 0;
}

static int appcl_lsm_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return 0;
}

static int appcl_lsm_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

static int appcl_lsm_inode_mknod(struct inode *dir, struct dentry *dentry,
				umode_t mode, dev_t dev)
{
	return 0;
}
/*
static int appcl_lsm_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                           	struct inode *new_dir, struct dentry *new_dentry,
                           	unsigned int flags)
{
	return 0;
}
*/
static int appcl_lsm_inode_readlink(struct dentry *dentry)
{
	return 0;
}

static int appcl_lsm_inode_follow_link(struct dentry *dentry, struct inode *inode,
                                	bool rcu)
{
	return 0;
}

static int appcl_lsm_inode_permission(struct inode *inode, int mask)
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

static int appcl_lsm_inode_setxattr(struct dentry *dentry, const char *name,
                             	const void *value, size_t size, int flags)
{
	return 0;
}

static void appcl_lsm_inode_post_setxattr(struct dentry *dentry, const char *name,
                                   	const void *value, size_t size, int flags)
{
	return;
}

static int appcl_lsm_inode_getxattr(struct dentry *dentry, const char *name)
{
	return 0;
}

static int appcl_lsm_inode_listxattr(struct dentry *dentry)
{
	return 0;
}

static int appcl_lsm_inode_removexattr(struct dentry *dentry, const char *name)
{
	return 0;
}

static int appcl_lsm_inode_need_killpriv(struct dentry *dentry)
{
	return 0;
}

static int appcl_lsm_inode_killpriv(struct dentry *dentry)
{
	return 0;
}

static int appcl_lsm_inode_getsecurity(const struct inode *inode, const char *name,
					void **buffer, bool alloc)
{
	/* GET SECURITY ATTR */
	return 0;
}

static int appcl_lsm_inode_setsecurity(struct inode *inode, const char *name,
				const void *value, size_t size, int flags)
{
	/* SET SECURITY ATTR */
	return 0;
}

static int appcl_lsm_inode_listsecurity(struct inode *inode, char *buffer,
					size_t buffer_size)
{
	return 0;
}

static void appcl_lsm_inode_getsecid(const struct inode *inode, u32 *secid)
{
	return;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * FILE SECURITY HOOKS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int appcl_lsm_file_permission(struct file *file, int mask)
{
	return 0;
}

static int appcl_lsm_file_alloc_security(struct file *file)
{
	//printk(KERN_ALERT "FILE ALLOC SECURITY START\n");

	//printk(KERN_ALERT "FILE ALLOC SECURITY START\n");
	return 0;
}


static void appcl_lsm_file_free_security(struct file *file)
{
	//printk(KERN_ALERT "FILE FREE SECURITY START\n");

	//printk(KERN_ALERT "FILE FREE SECURITY START\n");
	return;
}

static int appcl_lsm_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return 0;
}

static int appcl_lsm_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
                            	unsigned long prot)
{
	return 0;
}

static int appcl_lsm_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static int appcl_lsm_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return 0;
}

static void appcl_lsm_file_set_fowner(struct file *file)
{
	return;
}

static int appcl_lsm_file_send_sigiotask(struct task_struct *tsk,
                                  	struct fown_struct *fown, int sig)
{
	return 0;
}

static int appcl_lsm_file_receive(struct file *file)
{
	return 0;
}

static int appcl_lsm_file_open(struct file *file, const struct cred *cred)
{
	return 0;
}

static int appcl_lsm_task_create(unsigned long clone_flags)
{
	return 0;
}

static void appcl_lsm_task_free(struct task_struct *task)
{
	return;
}

static int appcl_lsm_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	return 0;
}

static void appcl_lsm_cred_free(struct cred *cred)
{
	return;
}

static int appcl_lsm_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	return 0;
}

static void appcl_lsm_cred_transfer(struct cred *new, const struct cred *old)
{
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
	LSM_HOOK_INIT(bprm_set_creds, appcl_lsm_bprm_set_creds),
	//LSM_HOOK_INIT(bprm_check, appcl_lsm_bprm_check),
	LSM_HOOK_INIT(bprm_committing_creds, appcl_lsm_bprm_committing_creds),
	LSM_HOOK_INIT(bprm_committed_creds, appcl_lsm_bprm_committed_creds),
	LSM_HOOK_INIT(bprm_secureexec, appcl_lsm_bprm_secureexec),

	LSM_HOOK_INIT(inode_alloc_security, appcl_lsm_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security, appcl_lsm_inode_free_security),
	//LSM_HOOK_INIT(inode_init_security, appcl_lsm_inode_init_security),
	LSM_HOOK_INIT(inode_create, appcl_lsm_inode_create),
	LSM_HOOK_INIT(inode_link, appcl_lsm_inode_link),
	LSM_HOOK_INIT(inode_unlink, appcl_lsm_inode_unlink),
	LSM_HOOK_INIT(inode_symlink, appcl_lsm_inode_symlink),
	LSM_HOOK_INIT(inode_mkdir, appcl_lsm_inode_mkdir),
	LSM_HOOK_INIT(inode_rmdir, appcl_lsm_inode_rmdir),
	LSM_HOOK_INIT(inode_mknod, appcl_lsm_inode_mknod),
	//LSM_HOOK_INIT(inode_rename, appcl_lsm_inode_rename),
	LSM_HOOK_INIT(inode_readlink, appcl_lsm_inode_readlink),
	LSM_HOOK_INIT(inode_follow_link, appcl_lsm_inode_follow_link),
	LSM_HOOK_INIT(inode_permission, appcl_lsm_inode_permission),
	LSM_HOOK_INIT(inode_setattr, appcl_lsm_inode_setattr),
	LSM_HOOK_INIT(inode_getattr, appcl_lsm_inode_getattr),
	LSM_HOOK_INIT(inode_setxattr, appcl_lsm_inode_setxattr),
	LSM_HOOK_INIT(inode_post_setxattr, appcl_lsm_inode_post_setxattr),
	LSM_HOOK_INIT(inode_getxattr, appcl_lsm_inode_getxattr),
	LSM_HOOK_INIT(inode_listxattr, appcl_lsm_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr, appcl_lsm_inode_removexattr),
	LSM_HOOK_INIT(inode_need_killpriv, appcl_lsm_inode_need_killpriv),
	LSM_HOOK_INIT(inode_killpriv, appcl_lsm_inode_killpriv),
	LSM_HOOK_INIT(inode_getsecurity, appcl_lsm_inode_getsecurity),
	LSM_HOOK_INIT(inode_setsecurity, appcl_lsm_inode_setsecurity),
	LSM_HOOK_INIT(inode_listsecurity, appcl_lsm_inode_listsecurity),
	LSM_HOOK_INIT(inode_getsecid, appcl_lsm_inode_getsecid),

	LSM_HOOK_INIT(file_permission, appcl_lsm_file_permission),
	LSM_HOOK_INIT(file_alloc_security, appcl_lsm_file_alloc_security),
	LSM_HOOK_INIT(file_free_security, appcl_lsm_file_free_security),
	LSM_HOOK_INIT(file_ioctl, appcl_lsm_file_ioctl),
	LSM_HOOK_INIT(file_mprotect, appcl_lsm_file_mprotect),
	LSM_HOOK_INIT(file_lock, appcl_lsm_file_lock),
	LSM_HOOK_INIT(file_fcntl, appcl_lsm_file_fcntl),
	LSM_HOOK_INIT(file_set_fowner, appcl_lsm_file_set_fowner),
	LSM_HOOK_INIT(file_send_sigiotask, appcl_lsm_file_send_sigiotask),
	LSM_HOOK_INIT(file_receive, appcl_lsm_file_receive),
	LSM_HOOK_INIT(file_open, appcl_lsm_file_open),

	LSM_HOOK_INIT(task_create, appcl_lsm_task_create),
	LSM_HOOK_INIT(task_free, appcl_lsm_task_free),
	LSM_HOOK_INIT(task_create, appcl_lsm_task_create),

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

static int __init appcl_lsm_init(void)
{
	printk(KERN_ALERT "AppCL - LSM Security Module Initialising ... \n");
	sel_inode_cache = kmem_cache_create("appcl_lsm_inode_security",
                                	sizeof(struct inode_security_struct),
                                             0, SLAB_PANIC, NULL);

	security_add_hooks(appcl_hooks, ARRAY_SIZE(appcl_hooks));
	printk(KERN_ALERT "AppCL - LSM Security Module Successfully Initialised\n");
	return 0;
}

security_initcall(appcl_lsm_init);
