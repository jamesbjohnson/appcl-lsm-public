/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
AppCL - LSM audit.c

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

 #include <linux/kernel.h>
 #include <linux/errno.h>
 #include <linux/sched.h>
 #include <linux/security.h>
 #include <linux/mm.h>
 #include <linux/slab.h>
 #include <linux/spinlock.h>
 #include <linux/file.h>
 #include <linux/types.h>
 #include <linux/string.h>
 #include <linux/mutex.h>

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
  * AUDIT.C
  * audit functions
  *
  *
  * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

 /*
  *
  * check_current_cred_path
  *      - current_pathname, path defined in cred security label (task_audit_data)
  *      - sec_pathname, path to check against cred
  *      - return 1 if match, 0 on error
  *
  */

int check_current_cred_path(const char *sec_pathname, const struct cred *cred)
{
         const struct task_audit_data *current_td; /* current task data */
         const char *current_pathname = "/";
         size_t buf = 32;

         current_td = cred->security;
         current_pathname = current_td->bprm_pathname;
         if (!current_pathname)
                 return 0;

         if (strncmp(current_pathname, sec_pathname, buf) == 0)
                 return 1;

         return 0;
}
EXPORT_SYMBOL(check_current_cred_path);

/*
 *
 * get_current_perm_enforce
 *      - return e_perm corresponding to first matching entry to a_entries
 *
 */

unsigned short get_current_perm_enforce(struct inode_security_label *ilabel, const struct cred *cred)
{
        size_t i;

        for (i = 0; i < APPCL_MAX_INODE_ENTRIES; i++) {
                struct appcl_pacl_entry entry;
                entry = ilabel->a_entries[i];
                if (entry.e_perm) {
                        const char *sec_pathname = "/";
                        sec_pathname = entry.inode_sec_pathname;
                        if (check_current_cred_path(sec_pathname, cred))
                                return entry.e_perm;
                }
        }
        return 0;
}
EXPORT_SYMBOL(get_current_perm_enforce);

unsigned short get_next_perm_enforce(struct inode_security_label *ilabel, const struct cred *cred, size_t n)
{
        struct appcl_pacl_entry entry;
        entry = ilabel->a_entries[n];
        if (entry.e_perm) {
                const char *sec_pathname = "/";
                sec_pathname = entry.inode_sec_pathname;
                if (check_current_cred_path(sec_pathname, cred))
                        return entry.e_perm;
        }
        return 0;
}
EXPORT_SYMBOL(get_next_perm_enforce);

/*
 *
 * get_inode_perm_count
 *      - check each entry to a_entries array
 *      - p_count, number of entries with e_perm
 *
 */

unsigned int get_inode_perm_count(struct inode_security_label *ilabel)
{
        unsigned int p_count = 0;
        size_t i;

        for (i = 0; i < APPCL_MAX_INODE_ENTRIES; i++) {
                struct appcl_pacl_entry entry;
                entry = ilabel->a_entries[i];
                if (entry.e_tag)
                        p_count++;
                else
                        return p_count;
        }
        return p_count;
}
EXPORT_SYMBOL(get_inode_perm_count);

/*
 *
 * get_current_inode_perm_count
 *      - check each entry to a_entries array
 *      - pass path attribute (inode_sec_pathname) to check_current_cred_path
          to check against cred
 *      - p_count, number of entries that match cred path
 *
 */

unsigned int get_current_inode_perm_count(struct inode_security_label *ilabel, const struct cred *cred)
{
        unsigned int p_count = 0;
        size_t i;

        for (i = 0; i < APPCL_MAX_INODE_ENTRIES; i++) {
                struct appcl_pacl_entry entry;
                entry = ilabel->a_entries[i];
                if (entry.e_tag) {
                        const char *sec_pathname = "/";
                        sec_pathname = entry.inode_sec_pathname;
                        if (check_current_cred_path(sec_pathname, cred))
                                p_count++;
                }
        }
        return p_count;
}
EXPORT_SYMBOL(get_current_inode_perm_count);

/*
 *
 * appcl_check_rperm_match
 *      - check all inode permission entries for requested permission (mask)
 *      - permission to check passed through 'r_perm'
 *      - pass 'MAY_READ | MAY_WRITE | MAY_EXEC' to mask and r_perm to check for
 *        related permissions
 *
 */

int appcl_check_rperm_match(struct inode_security_label *ilabel, const struct cred *cred,
                                      int mask, int r_perm)
{
        size_t i;
        unsigned short c_perm = 0;
        unsigned short p_count = 0;
        p_count = get_inode_perm_count(ilabel);
        if (!p_count)
                return 0;

        r_perm &= MAY_READ | MAY_WRITE | MAY_APPEND | MAY_EXEC;

	for (i = 0; i < APPCL_MAX_INODE_ENTRIES; i++) {
		if (mask == r_perm) {
                        c_perm = get_next_perm_enforce(ilabel, cred, i);
                        if (c_perm == r_perm)
                                return 1;
                }
        }
        return 0;
}
EXPORT_SYMBOL(appcl_check_rperm_match);

/*
 *
 * appcl_check_permission_file_match
 *      - chech permissions from file (file->f_mode) instead of mask
 *      - return rough privileges from file mode
 *
 */

int appcl_check_permission_file_match(struct file *file, struct inode *inode, const struct cred *cred)
{
        struct inode_security_label *ilabel;
        unsigned short c_perm = 0;
        fmode_t file_mode = 0;
        size_t i;

        ilabel = inode->i_security;
        if (!ilabel)
                return 0;

        file_mode = file->f_mode;

        file_mode &= FMODE_READ | FMODE_WRITE | FMODE_EXEC;

        for (i = 0; i < APPCL_MAX_INODE_ENTRIES; i++) {
                c_perm = get_next_perm_enforce(ilabel, cred, i);
                if (c_perm) {
                        switch (file_mode) {
                                case FMODE_READ:
                                        if (c_perm == APPCL_READ)
                                                return 0;
                                break;

                                case FMODE_WRITE:
                                        //if (file->f_flags & O_APPEND)
                                        if (c_perm == APPCL_WRITE)
                                                return 0;
                                break;

                                case FMODE_EXEC:
                                        if (c_perm == APPCL_EXECUTE)
                                                return 0;
                                break;
                        }
                }
        }
        return 0;
}
EXPORT_SYMBOL(appcl_check_permission_file_match);

/*
 *
 * appcl_check_permission_mask_match
 *      - check requested permission mask against labelled permissions
 *      - return rough privileges from mask
 *
 */

int appcl_check_permission_mask_match(struct inode_security_label *ilabel, const struct cred *cred, int mask)
{
	size_t i;
        unsigned short c_perm = 0;
        unsigned short p_count = 0;
        p_count = get_inode_perm_count(ilabel);
        if (!p_count)
                return 0;

	mask &= MAY_READ | MAY_WRITE | MAY_APPEND | MAY_EXEC;

	for (i = 0; i < APPCL_MAX_INODE_ENTRIES; i++) {
		size_t n = i;
		c_perm = get_next_perm_enforce(ilabel, cred, n);
                if (c_perm) {
                        switch (mask) {
                                case MAY_READ:
                                        if (c_perm == APPCL_READ)
                                                return 1;
                                break;

                                case MAY_WRITE:
                                        if (c_perm == APPCL_WRITE)
                                                return 1;
                                break;
                                case MAY_APPEND:
                                        if (c_perm == APPCL_WRITE)
                                                return 1;
                                break;

                                case MAY_EXEC:
                                        if (c_perm == APPCL_EXECUTE)
                                                return 1;
                                break;
                        }
                }
	}
	return 0;
}
EXPORT_SYMBOL(appcl_check_permission_mask_match);

/*
 *
 * check_inode_path_match
 *      - check for inode security label
 *      - pass this to get_current_inode_perm_count to
          check ilabel entries against cred
 *      - p_count, number of entries that match cred path
 *
 */

int check_inode_path_match(struct inode *inode, const struct cred *cred)
{
       struct inode_security_label *ilabel;
       unsigned int p_count = 0;

       ilabel = inode->i_security;
       if (!ilabel)
              return 0;

       p_count = get_current_inode_perm_count(ilabel, cred);

       return p_count;
}
EXPORT_SYMBOL(check_inode_path_match);

int check_fpath_match(struct file *file, const struct cred *cred)
{
       struct path *fpath;
       char *tmp;
       const char *fpath_name;

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
       if (IS_ERR(fpath_name))
               goto err;

       free_page((unsigned long) tmp);
       return check_current_cred_path(fpath_name, cred);

err:
       free_page((unsigned long) tmp);
       return 0;

}
EXPORT_SYMBOL(check_fpath_match);
