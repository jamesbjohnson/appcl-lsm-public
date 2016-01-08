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
         size_t buf = 64;

         current_td = cred->security;
         current_pathname = current_td->bprm_pathname;
         if (!current_pathname)
                 return 0;

         if (strncmp(current_pathname, sec_pathname, buf) == 0) {
                 printk(KERN_ALERT "CHECK CURRENT PATH: INODE SEC LABEL SET: %s \n", current_pathname);
                 return 1;
         }

         return 0;
}
EXPORT_SYMBOL(check_current_cred_path);

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
                struct appcl_posix_pacl_entry entry;
                entry = ilabel->a_entries[i];
                if (entry.e_perm)
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
                struct appcl_posix_pacl_entry entry;
                entry = ilabel->a_entries[i];
                if (entry.e_perm) {
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
       ilabel = inode->i_security;
       if (!ilabel)
              return 0;

       unsigned int p_count = 0;
       p_count = get_current_inode_perm_count(ilabel, cred);

       if (p_count)
                printk(KERN_ALERT "INODE PATH MATCH: INODE P_COUNT SET: %d \n", p_count);

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
