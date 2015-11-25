/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * INCLUDES
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/limits.h>
#include <linux/stat.h>

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/ctype.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/user_namespace.h>

#include "include/appcl_lsm.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * LSM SECURITY HOOK FUNCTIONS
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

unsigned int appcl_path_max = 2 * PATH_MAX;
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
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*
static int appcl_lsm_inode_alloc(struct inode *inode)
{
	return 0;
}
*/
/*
static void appcl_lsm_inode_free(struct inode *inode)
{
	return;
}
*/
/*
static int appcl_lsm_inode_init_security(struct inode *inode, struct inode *dir,
                                  const struct qstr *qstr,
                                  initxattrs initxattrs, void *fs_data)
{
	return 0;
}
*/
/*
static int appcl_lsm_old_inode_init_security(struct inode *inode, struct inode *dir,
                                      const struct qstr *qstr, const char **name,
                                      void **value, size_t *len)
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
/*
static int appcl_lsm_file_alloc(struct file *file)
{
	return 0;
}
*/
/*
static void appcl_lsm_file_free(struct file *file)
{
	return;
}
*/
static int appcl_lsm_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return 0;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * APPCL-LSM SECURITY OPERATIONS STRUCTURE
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
static struct security_hook_list appcl_hooks[] = {
	LSM_HOOK_INIT(bprm_set_creds, appcl_lsm_bprm_set_creds),
	//LSM_HOOK_INIT(bprm_check, appcl_lsm_bprm_check),
	LSM_HOOK_INIT(bprm_committing_creds, appcl_lsm_bprm_committing_creds),
	LSM_HOOK_INIT(bprm_committed_creds, appcl_lsm_bprm_committed_creds),
	LSM_HOOK_INIT(bprm_secureexec, appcl_lsm_bprm_secureexec),

	//LSM_HOOK_INIT(inode_alloc, appcl_lsm_inode_alloc),
	//LSM_HOOK_INIT(inode_free, appcl_lsm_inode_free),
	//LSM_HOOK_INIT(inode_init_security, appcl_lsm_inode_init_security),
	//LSM_HOOK_INIT(old_inode_init_security, appcl_lsm_old_inode_init_security),
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
	//LSM_HOOK_INIT(file_alloc, appcl_lsm_file_alloc),
	//LSM_HOOK_INIT(file_free, appcl_lsm_file_free),
	LSM_HOOK_INIT(file_ioctl, appcl_lsm_file_ioctl),
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
	security_add_hooks(appcl_hooks, ARRAY_SIZE(appcl_hooks));
	printk(KERN_ALERT "AppCL - LSM Security Module Initialised\n");
	return 0;
}

security_initcall(appcl_lsm_init);
