/*
*
* path.c
*
*/

#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>

#include "include/appcl_lsm.h"
#include "include/path.h"

/* modified from dcache.c */
static int prepend(char **buffer, int buflen, const char *str, int namelen)
{
      buflen -= namelen;
      if (buflen < 0)
          return -ENAMETOOLONG;
      *buffer -= namelen;
      memcpy(*buffer, str, namelen);
      return 0;
}

#define CHROOT_NSCONNECT (PATH_CHROOT_REL | PATH_CHROOT_NSCONNECT)

static int d_namespace_path(struct path *path, char *buf, int buflen,
                            char **name, int flags)
{
      char *res;
      int error = 0;
      int connected = 1;

      if (path->mnt->mnt_flags & MNT_INTERNAL) {
            /* its not mounted anywhere */
            res = dentry_path(path->dentry, buf, buflen);
            *name = res;
            if (IS_ERR(res)) {
                  *name = buf;
                  return PTR_ERR(res);
                  printk(KERN_ALERT "IS_ERR name: %p \n", &name);
            }
            if (path->dentry->d_sb->s_magic == PROC_SUPER_MAGIC &&
                      strncmp(*name, "/sys/", 5) == 0) {
                      return prepend(name, *name - buf, "/proc", 5);
                      printk(KERN_ALERT "d_namespace_path PROC_SUPER_MAGIC name: %s \n", *name);
            }
            return 0;
      }

      /* resolve paths relative to chroot? */
      if (flags & PATH_CHROOT_REL) {
            struct path root;
            get_fs_root(current->fs, &root);
            res = __d_path(path, &root, buf, buflen);
            path_put(&root);
            printk(KERN_ALERT "d_namespace_path relative to chroot if: %s, %x \n", *res, connected);
      } else {
            res = d_absolute_path(path, buf, buflen);
            if (!our_mnt(path->mnt))
                  connected = 0;
            printk(KERN_ALERT "d_namespace_path relative to chroot else: %s, %x \n", *res, connected);
      }

      /* handle error conditions - and still allow a partial path
       * to be returned
       */
       if (!res || IS_ERR(res)) {
            if (PTR_ERR(res) == -ENAMETOOLONG)
                  return -ENAMETOOLONG;
            connected = 0;
            res = dentry_path_raw(path->dentry, buf, buflen);
            if (IS_ERR(res)) {
                  error = PTR_ERR(res);
                  *name = buf;
                  goto out;
            }
        } else if (!our_mnt(path->mnt))
            connected = 0;

        *name = res;
        printk(KERN_ALERT "d_namespace_path name: %s \n", *name);

        /* Handle two cases
         * A deleted dentry && profile is not allowing mediation of deletion
         * On some filesystems, newly allocated dentries appear to security_path
         * hooks as deleted dentry except without an inode allocated
         */

         if (d_unlinked(path->dentry) && d_is_positive(path->dentry) &&
              !(flags & PATH_MEDIATE_DELETED)) {
                  error = -ENOENT;
                  goto out;
         }

         if (!connected) {
              if (!(flags & PATH_CONNECT_PATH) &&
                  !(((flags & CHROOT_NSCONNECT) == CHROOT_NSCONNECT) &&
                      our_mnt(path->mnt))) {
                  /* disconnected path, don't return pathname starting
                   * with '/'
                   */
                  error = -EACCES;
                  if (*res == '/')
                      *name = res + 1;
              }
         }

out:
      printk(KERN_ALERT "d_namespace_path error: 0x%08x \n", error);
      printk(KERN_ALERT "d_namespace_path goto out name: %s \n", *name);

      /*
       *
       * todo : *name contains path of application
       * move this to appcl_lsm.c within security hook (open file)
       *
       */
       
      return error;

}

/* get_name_to_buffer
 * get the pathname to a buffer, ensure dir / is appended
 */

static int get_name_to_buffer(struct path *path, int flags, char *buffer,
                              int size, char **name, const char **info)
{
      int adjust = (flags & PATH_IS_DIR) ? 1 : 0;
      int error = d_namespace_path(path, buffer, size - adjust, name, flags);

      if (!error && (flags & PATH_IS_DIR) && (*name)[1] != '\0')
            /* Append "/" to the pathname */
            strcpy(&buffer[size - 2], "/");

      if (info && error) {
            if (error == -ENOENT) {
                  *info = "Failed name lookup - deleted entry";
                  printk(KERN_ALERT "info & error ENOENT: %p, %p \n", &info, &error);
            } else if (error == -EACCES) {
                  *info = "Failed name lookup - deleted entry";
                  printk(KERN_ALERT "info & error EACCES: %p, %p \n", &info, &error);
            } else if (error == -ENAMETOOLONG) {
                  *info = "Failed name lookup - name too long";
                    printk(KERN_ALERT "info & error ENAMETOOLONG: %p, %p \n", &info, &error);
            } else {
                  *info = "Failed name lookup";
                    printk(KERN_ALERT "info & error else: %p, %p \n", &info, &error);
            }
      }

      printk(KERN_ALERT "get_name_to_buffer error: 0x%08x \n", error);
      printk(KERN_ALERT "get_name_to_buffer info: %s \n", *info);
      return error;
}

/* appcl_path_name - compute the pathname of a file */

int appcl_path_name(struct path *path, int flags, char **buffer,
                  const char **name, const char **info)
{
      char *buf, *str = NULL;
      int size = 256;
      int error;

      *name = NULL;
      *buffer = NULL;
      for (;;) {
            /* freed by caller */
            buf = kmalloc(size, GFP_KERNEL);
            if (!buf)
                  return -ENOMEM;

            error = get_name_to_buffer(path, flags, buf, size, &str, info);
            if (error != -ENAMETOOLONG)
                  break;

            kfree(buf);
            size <<= 1;
            if (size > appcl_path_max)
                  return -ENAMETOOLONG;
            *info = NULL;
      }

      *buffer = buf;
      *name = str;
      printk(KERN_ALERT "appcl_path_name error: 0x%08x \n", error);
      return error;
}
