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
#include <linux/time.h>

#include "include/appcl_lsm.h"
#include "include/audit.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * LSM SECURITY HOOK FUNCTIONS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static struct kmem_cache *sel_inode_cache;
static struct kmem_cache *sel_file_cache;

static void init_task_audit_data(void) {

	printk(KERN_ALERT "AppCL LSM: init_task_audit_data Initialising ... \n");
	struct cred *cred;
        struct task_audit_data *newtd;
	cred = get_current_cred();
        newtd = kzalloc(sizeof(struct task_audit_data), GFP_KERNEL);
        if (!newtd) {
                put_cred(cred);
                panic("AppCL LSM:  Failed to initialise initial task.\n");
        }

	newtd->bprm_pathname = "-init-task";
        cred->security = newtd;

	put_cred(cred);
	return;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * INODE SECURITY HOOKS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int inode_alloc_security(struct inode *inode)
{
	struct inode_security_label *ilabel;
        const char *test_nano = "/bin/nano";              /*TEST*   /bin/nano   *TEST*/
	const char *test_cat = "/bin/cat";              /*TEST*   /bin/cat   *TEST*/
	const char *test_ls = "/bin/ls";              /*TEST*   /bin/ls   *TEST*/
	struct appcl_posix_pacl_entry pe;
	struct appcl_posix_pacl_entry pe1;
	struct appcl_posix_pacl_entry pe2;
	struct appcl_posix_pacl_entry pe3;
	struct appcl_posix_pacl_entry pe4;
	struct appcl_posix_pacl_entry pe5;

	ilabel = kmem_cache_zalloc(sel_inode_cache, GFP_NOFS);
	if (!ilabel)
        	return -ENOMEM;

	mutex_init(&ilabel->lock);
        INIT_LIST_HEAD(&ilabel->list);

	pe.inode_sec_pathname = test_nano;
	pe.e_perm = PACL_READ;
	ilabel->a_entries[0] = pe;

	pe1.inode_sec_pathname = test_nano;
	pe1.e_perm = PACL_WRITE;
	ilabel->a_entries[1] = pe1;

	pe2.inode_sec_pathname = test_cat;
	pe2.e_perm = PACL_EXECUTE;
	ilabel->a_entries[2] = pe2;

	pe3.inode_sec_pathname = test_ls;
	pe3.e_perm = PACL_READ;
	ilabel->a_entries[3] = pe3;

	pe4.inode_sec_pathname = test_cat;
	pe4.e_perm = PACL_READ;
	ilabel->a_entries[4] = pe4;

	pe5.inode_sec_pathname = test_cat;
	pe5.e_perm = PACL_READ;
	ilabel->a_entries[5] = pe5;

	ilabel->a_count = 0;
	ilabel->inode = inode;
	inode->i_security = ilabel;

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
	struct inode_security_label *ilabel = inode->i_security;

	if (!list_empty_careful(&ilabel->list))
                 list_del_init(&ilabel->list);

	call_rcu(&ilabel->rcu, inode_free_rcu);

	return;
}

static void appcl_lsm_inode_free_security(struct inode *inode)
{
	inode_free_security(inode);
	return;
}

static int appcl_lsm_inode_permission(struct inode *inode, int mask)
{
	return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * FILE SECURITY HOOKS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int file_alloc_security(struct file *file)
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

static int appcl_lsm_file_alloc_security(struct file *file)
{
	return file_alloc_security(file);
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
	struct file_security_label *flabel = file->f_security;

	if (!list_empty_careful(&flabel->list))
                 list_del_init(&flabel->list);

	call_rcu(&flabel->rcu, file_free_rcu);
	return;
}

static void appcl_lsm_file_free_security(struct file *file)
{
	file_free_security(file);
	return;
}

static int appcl_lsm_file_permission(struct file *file, int mask)
{
        struct inode *inode = file_inode(file);
        struct inode_security_label *ilabel;
        ilabel = inode->i_security;
        if (!ilabel)
                return 0;
/*
        if (check_inode_path_match(inode, file->f_cred)) {
                printk(KERN_ALERT "FILE PERMISSION: INODE SEC LABEL SET \n");

		struct file_security_label *flabel;
		flabel = file->f_security;

		unsigned int p_count = 0;
		p_count = flabel->entries_count;

		if (p_count)
			printk(KERN_ALERT "FILE PERMISSION: INODE PERM COUNT SET: %d \n", p_count);

		unsigned int m_count = 0;
		spin_lock(&file->f_lock);
		m_count = get_current_inode_perm_count(ilabel, file->f_cred);
		spin_unlock(&file->f_lock);

		if (m_count)
			printk(KERN_ALERT "FILE PERMISSION: INODE CURRENT PERM COUNT SET: %d \n", m_count);
	}
*/
        return 0;
}

static int appcl_lsm_file_open(struct file *file, const struct cred *cred)
{
        struct inode *inode = file_inode(file);
        struct inode_security_label *ilabel;
        ilabel = inode->i_security;
        if (!ilabel)
                return 0;

        if (check_inode_path_match(inode, file->f_cred)) {
                printk(KERN_ALERT "FILE OPEN: INODE SEC LABEL SET \n");
		struct file_security_label *flabel;
		flabel = file->f_security;

		unsigned int p_count = 0;
		p_count = get_inode_perm_count(ilabel);
		flabel->entries_count = p_count;

		if (flabel->entries_count)
			printk(KERN_ALERT "FILE OPEN: INODE PERM COUNT SET: %d \n", flabel->entries_count);

		unsigned int m_count = 0;
		spin_lock(&file->f_lock);
		m_count = get_current_inode_perm_count(ilabel, file->f_cred);
		spin_unlock(&file->f_lock);

		if (m_count)
			printk(KERN_ALERT "FILE OPEN: INODE CURRENT PERM COUNT SET: %d \n", m_count);

	}

        return 0;
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
                cred_path = "-";
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
	LSM_HOOK_INIT(inode_alloc_security, appcl_lsm_inode_alloc_security),
        LSM_HOOK_INIT(inode_free_security, appcl_lsm_inode_free_security),
	LSM_HOOK_INIT(inode_permission, appcl_lsm_inode_permission),
	LSM_HOOK_INIT(file_alloc_security, appcl_lsm_file_alloc_security),
	LSM_HOOK_INIT(file_free_security, appcl_lsm_file_free_security),
	LSM_HOOK_INIT(file_permission, appcl_lsm_file_permission),
	LSM_HOOK_INIT(file_open, appcl_lsm_file_open),
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

static int __init appcl_lsm_init(void)
{
	printk(KERN_ALERT "AppCL - LSM Security Module Initialising ... \n");

	/* Initital task security attributes */
	init_task_audit_data();

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
