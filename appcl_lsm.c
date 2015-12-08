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

#include <linux/list.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/fdtable.h>
#include <linux/binfmts.h>

#include "include/appcl_lsm.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * LSM SECURITY HOOK FUNCTIONS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static struct kmem_cache *sel_inode_cache;
static struct kmem_cache *sel_file_cache;

static void init_task_cred_attr(void) {

	printk(KERN_ALERT "AppCL LSM: init_task_cred_attr Initialising ... \n");

	struct cred *cred = (struct cred *) current->real_cred;
        struct task_cred_attr *credattr;

        credattr = kzalloc(sizeof(struct task_cred_attr), GFP_KERNEL);
        if (!credattr)
                panic("AppCL LSM:  Failed to initialise initial task.\n");

        credattr->tpath_name = NULL;
	credattr->tclass = 0x8000;
        cred->security = credattr;

	printk(KERN_ALERT "CRED ATTR ADDR: 0x%08x\n", &credattr);
	printk(KERN_ALERT "CRED ATTR TPATH_NAME: %s\n", credattr->tpath_name );
	printk(KERN_ALERT "CRED ATTR TCLASS: %04x\n", credattr->tclass );
	printk(KERN_ALERT "AppCL LSM: init_task_cred_attr Initialised ... \n");
	return;
}

/*
static inline u32 current_sid(void)
{
        const struct task_cred_attr *credattr = current_security();

        return credattr->sid;
}
*/
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
	const struct task_cred_attr *old_cred;
        struct task_cred_attr *credattr;
	struct inode_security_label *ilabel;
	struct inode *inode = file_inode(bprm->file);

	old_cred = current_security();
	credattr = bprm->cred->security;
	ilabel = inode->i_security;

	//credattr->tpath_name = NULL;

	char *tmp;
	char *fpath_name;
	struct path *fpath;

	spin_lock(&file->f_lock);
	fpath = &bprm->file->f_path;
	credattr->tpath = fpath;
	path_get(fpath);
	spin_unlock(&file->f_lock);

	tmp = (char *)__get_free_page(GFP_TEMPORARY);

	if (!tmp) {
		path_put(fpath);
		return -ENOMEM;
	}

	fpath_name = d_path(fpath, tmp, PAGE_SIZE);
	path_put(fpath);

	if (IS_ERR(fpath_name)) {
		free_page((unsigned long) tmp);
		return PTR_ERR(fpath_name);
	}

	//char *check_name = "/bin/nano";

	/*
	if ((strcmp(check_name, fpath_name))) {
		printk(KERN_ALERT "SET CREDS BPRM PATH NAME %s \n", fpath_name);
	}
	*/
	credattr->tpath_name = fpath_name;
	credattr->tclass = 0x4000;

	if (credattr->tpath_name)
		printk(KERN_INFO "SET CREDS CREDATTR PATH NAME %s \n", credattr->tpath_name);

	/*
	 *
	 *
	 * fpath_name contains path of current file
	 *
	 *
	 */

	free_page((unsigned long) tmp);
	/*
	//printk(KERN_INFO "AppCL LSM bprm_set_creds security hook\n");
	if (set_cred_count < 20)
		printk(KERN_INFO "BPRM SET CREDS START \n");



        old_cred = current_security();

         Default to the current task SID.
        credattr->sid = old_cred->sid;
        credattr->osid = old_cred->sid;

         Reset fs, key, and sock SIDs on execve.
        credattr->create_sid = 0;
        credattr->keycreate_sid = 0;
        credattr->sockcreate_sid = 0;

        if (old_cred->exec_sid) {
                credattr->sid = old_cred->exec_sid;
                  Reset exec SID on execve.
                credattr->exec_sid = 0;
        }

	if (set_cred_count < 20) {
		printk(KERN_INFO "CRED ATTR ADDR: 0x%08x\n", &credattr);
		printk(KERN_INFO "CRED ATTR SID: %08x\n", credattr->sid );
		printk(KERN_INFO "CRED ATTR OSID: %08x\n", credattr->osid );
		printk(KERN_INFO "BPRM SET CREDS END \n");
	}

	set_cred_count++; */
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

static int inode_alloc_security(struct inode *inode)
{
	//printk(KERN_INFO "INODE ALLOC SECURITY START \n");

	struct inode_security_label *ilabel;
	//kuid_t sid = current_suid();

	ilabel = kmem_cache_zalloc(sel_inode_cache, GFP_NOFS);
	if (!ilabel)
        	return -ENOMEM;

	mutex_init(&ilabel->lock);
        INIT_LIST_HEAD(&ilabel->list);
	ilabel->inode = inode;
	ilabel->sclass = 0x4000;

	ilabel->a_flags = APPCL_AUTO_INHERIT;
	ilabel->a_count = 1;
	ilabel->a_owner_mask = 1;
	ilabel->a_group_mask = 1;
	ilabel->a_other_mask = 2;

	inode->i_security = ilabel;

	//printk(KERN_INFO "INODE INODE ADDR: 0x%08x\n", &inode);
	//printk(KERN_INFO "INODE FLAGS: %08x\n", ilabel->a_flags );
	//printk(KERN_INFO "INODE COUNT: %08x\n", ilabel->a_count );
	//printk(KERN_INFO "INODE OWNER MASK: %08x\n", ilabel->a_owner_mask );
	//printk(KERN_INFO "INODE ILABEL ADDR: 0x%08x\n", &ilabel );
	//printk(KERN_INFO "INODE ALLOC SECURITY END \n");

	return 0;
}

static int appcl_lsm_inode_alloc_security(struct inode *inode)
{
	return inode_alloc_security(inode);
}

static void inode_free_rcu(struct rcu_head *head)
{
         struct inode_security_label *ilabel;

         ilabel = container_of(head, struct inode_security_label, rcu);
         kmem_cache_free(sel_inode_cache, ilabel);
	 return;
}

static void inode_free_security(struct inode *inode)
{
	//printk(KERN_INFO "INODE FREE SECURITY START \n");
	struct inode_security_label *ilabel = inode->i_security;

	if (!list_empty_careful(&ilabel->list))
                 list_del_init(&ilabel->list);

	call_rcu(&ilabel->rcu, inode_free_rcu);

	//printk(KERN_INFO "INODE FREE SECURITY END \n");
	return;
}

static void appcl_lsm_inode_free_security(struct inode *inode)
{
	inode_free_security(inode);
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

static int file_alloc_security(struct file *file)
{
	struct file_security_label *flabel;

	flabel = kmem_cache_zalloc(sel_file_cache, GFP_NOFS);
	if (!flabel)
        	return -ENOMEM;

	mutex_init(&flabel->lock);
        INIT_LIST_HEAD(&flabel->list);
	flabel->file = file;
	flabel->sclass = 0x8000;

	flabel->a_flags = APPCL_AUTO_INHERIT;
	flabel->a_count = 1;
	flabel->a_owner_mask = 2;
	flabel->a_group_mask = 2;
	flabel->a_other_mask = 4;

	file->f_security = flabel;

	return 0;
}

static int appcl_lsm_file_alloc_security(struct file *file)
{
	return file_alloc_security(file);
	return 0;
}

static void file_free_rcu(struct rcu_head *head)
{
         struct file_security_label *flabel;

         flabel = container_of(head, struct file_security_label, rcu);
         kmem_cache_free(sel_file_cache, flabel);
	 return;
}

static void file_free_security(struct file *file)
{

	//printk(KERN_INFO "FILE FREE SECURITY START\n");
	struct file_security_label *flabel = file->f_security;

	if (!list_empty_careful(&flabel->list))
                 list_del_init(&flabel->list);

	call_rcu(&flabel->rcu, file_free_rcu);
	//printk(KERN_INFO "FILE FREE SECURITY START\n");

	return;
}

static void appcl_lsm_file_free_security(struct file *file)
{
	file_free_security(file);
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
	const struct task_cred_attr *credattr;
	const char *tpath_name;
	char *fpath_name;
	struct file_security_label *flabel;
	struct inode *inode = file_inode(file);
	struct inode_security_label *ilabel;
	int file_path_set = 0;
	int task_f_path = 0;

	credattr = cred->security;
	if (!credattr)
		printk(KERN_ALERT "NO CRED SECURITY \n");
	else
		tpath_name = credattr->tpath_name;
	/*
	 *
	 * If no cred path (tpath_name) exists,
	 * attempt to retrieve from 'tpath' (fpath_name)
	 *
	 */
	if (!tpath_name) {
		printk(KERN_INFO "NO TPATH_NAME \n");

		char *tmp;
		const struct path *tpath;

		spin_lock(&file->f_lock);
		tpath = &credattr->tpath;
		path_get(tpath);
		tmp = (char *)__get_free_page(GFP_TEMPORARY);
		spin_unlock(&file->f_lock);

		if (!tmp) {
			path_put(tpath);
			return -ENOMEM;
		}

		tpath_name = d_path(tpath, tmp, PAGE_SIZE);
		path_put(tpath);

		if (IS_ERR(tpath_name)) {
			free_page((unsigned long) tmp);
			goto error;
			//return PTR_ERR(tpath_name);
		}
		task_f_path = 1;
		free_page((unsigned long) tmp);
	}
	/*
	 *
	 * If no tpath_name can be found,
	 * attempt to retrieve file path name (fpath_name)
	 *
	 */
	if (!tpath_name) {
		printk(KERN_INFO "NO TPATH_NAME \n");

		char *tmp;
		struct path *fpath;

		spin_lock(&file->f_lock);
		fpath = &file->f_path;
		path_get(fpath);
		spin_unlock(&file->f_lock);

		tmp = (char *)__get_free_page(GFP_TEMPORARY);

		if (!tmp) {
			path_put(fpath);
			return -ENOMEM;
		}

		fpath_name = d_path(fpath, tmp, PAGE_SIZE);
		path_put(fpath);

		if (IS_ERR(fpath_name)) {
			free_page((unsigned long) tmp);
			goto error;
			//return PTR_ERR(fpath_name);
		}

		file_path_set = 1;
		free_page((unsigned long) tmp);
	}

	if (task_f_path)
		printk(KERN_ALERT "*FILE OPEN TASK F_PATH SET*  \n");

	if (file_path_set)
		printk(KERN_ALERT "FILE OPEN FILE PATH SET: %s \n", fpath_name);
	/*
	if (task_f_path)
		printk(KERN_ALERT "FILE OPEN TASK PATH SET: %s \n", tpath_name);
	*/
	if (!inode)
		printk(KERN_ALERT "NO INODE \n");

	flabel = file->f_security;
	if (!flabel)
		printk(KERN_ALERT "NO FILE LABEL \n");

	ilabel = inode->i_security;
	if (!ilabel)
		printk(KERN_ALERT "NO INODE LABEL \n");

	/*
	 *
	 * tpath_name contains current process application path.
	 * If tpath_name not set - fpath_name contains path of current file
	 *
	 *
	 */

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

	struct task_cred_attr *credattr;

        credattr = kzalloc(sizeof(struct task_cred_attr), gfp);
        if (!credattr)
                return -ENOMEM;

        cred->security = credattr;
	//printk(KERN_INFO "CRED ATTR ADDR: 0x%08x\n", &credattr);
	printk(KERN_INFO "AppCL LSM: cred_alloc_blank ... \n");

	return 0;
}

static void appcl_lsm_cred_free(struct cred *cred)
{

	struct task_cred_attr *credattr = cred->security;

        cred->security = (void *) 0x7UL;
        kfree(credattr);

	return;
}

static int appcl_lsm_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{

	const struct task_cred_attr *old_attr;
        struct task_cred_attr *credattr;

        old_attr = old->security;

        credattr = kmemdup(old_attr, sizeof(struct task_cred_attr), gfp);
        if (!credattr)
                return -ENOMEM;

        new->security = credattr;

	//printk(KERN_INFO "CRED ATTR ADDR: 0x%08x\n", &credattr);
	//printk(KERN_INFO "AppCL LSM: cred_prepare ... \n");

        return 0;
}

static void appcl_lsm_cred_transfer(struct cred *new, const struct cred *old)
{

	const struct task_cred_attr *old_attr = old->security;
        struct task_cred_attr *credattr = new->security;

        *credattr = *old_attr;

	//printk(KERN_INFO "CRED ATTR ADDR: 0x%08x\n", &credattr);
	printk(KERN_INFO "AppCL LSM: cred_transfer ... \n");

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

	/* Initital task security attributes */
	init_task_cred_attr();

	sel_inode_cache = kmem_cache_create("appcl_lsm_inode_security",
                                	sizeof(struct inode_security_label),
                                             0, SLAB_PANIC, NULL);

	sel_file_cache = kmem_cache_create("appcl_lsm_file_security",
				        sizeof(struct file_security_label),
				        	0, SLAB_PANIC, NULL);

	security_add_hooks(appcl_hooks, ARRAY_SIZE(appcl_hooks));
	printk(KERN_ALERT "AppCL - LSM Security Module Successfully Initialised\n");
	return 0;
}

security_initcall(appcl_lsm_init);
