#include <linux/security.h>
#include <linux/limits.h>
#include <linux/stat.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "include/appcl_lsm.h"
#include "include/path.h"

/*
 * LSM hook functions
 */

unsigned int appcl_path_max = 2 * PATH_MAX;

/* unsigned int *name_p = NULL; */

static int appcl_lsm_capable(const struct cred *cred, struct user_namespace *ns,
			    int cap, int audit)
{
	return 0;
}

static int appcl_lsm_inode_setxattr(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags)
{
	printk(KERN_ALERT "AppCL LSM inode_setxattr hook initialized");
	return 0;
}

static void appcl_lsm_inode_post_setxattr(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags)
{
	printk(KERN_ALERT "AppCL LSM inode_post_setxattr hook initialized");
	return;
}

static int appcl_lsm_inode_getxattr(struct dentry *dentry, const char *name)
{
	printk(KERN_ALERT "AppCL LSM inode_getxattr hook initialized");
	return 0;
}

static int appcl_lsm_inode_listxattr(struct dentry *dentry)
{
	printk(KERN_ALERT "AppCL LSM inode_listxattr hook initialized");
	return 0;
}

static int appcl_lsm_inode_removexattr(struct dentry *dentry, const char *name)
{
	printk(KERN_ALERT "AppCL LSM inode_removexattr hook initialized");
	return 0;
}

static int appcl_bprm_set_creds(struct linux_binprm *bprm)
{
			return 0;
}

static struct security_operations appcl_lsm_ops = {
	.name =				"appcl",

	.capable =			appcl_lsm_capable,
	.inode_setxattr =		appcl_lsm_inode_setxattr,
	.inode_post_setxattr =		appcl_lsm_inode_post_setxattr,
	.inode_getxattr =		appcl_lsm_inode_getxattr,
	.inode_listxattr =		appcl_lsm_inode_listxattr,
	.inode_removexattr =		appcl_lsm_inode_removexattr,
	.bprm_set_creds =		appcl_bprm_set_creds
};

static int __init appcl_lsm_init(void)
{
	int error;

	error = register_security(&appcl_lsm_ops);
	if (error) {
		printk(KERN_ALERT "Unable to register AppCL LSM\n");
	} else {
		printk(KERN_ALERT "AppCL LSM successfully registered!\n");
	}
	return error;

}

security_initcall(appcl_lsm_init);
