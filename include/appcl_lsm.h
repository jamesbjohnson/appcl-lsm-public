/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *
 * AppCL LSM appcl_lsm.h
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef __APPCL_LSM_H
#define __APPCL_LSM_H

#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/lsm_hooks.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>
#include <stdbool.h>

#define current_cred_xxx(xxx)                   \
({                                              \
        current_cred()->xxx;                    \
})

#define current_uid()           (current_cred_xxx(uid))
#define current_gid()           (current_cred_xxx(gid))
#define current_euid()          (current_cred_xxx(euid))
#define current_egid()          (current_cred_xxx(egid))
#define current_suid()          (current_cred_xxx(suid))
#define current_sgid()          (current_cred_xxx(sgid))
#define current_fsuid()         (current_cred_xxx(fsuid))
#define current_fsgid()         (current_cred_xxx(fsgid))
#define current_cap()           (current_cred_xxx(cap_effective))
#define current_user()          (current_cred_xxx(user))
#define current_security()      (current_cred_xxx(security))

struct inode_security_struct {
          struct inode *inode;    /* back pointer to inode object */
          union {
                  struct list_head list;  /* list of inode_security_struct */
                  struct rcu_head rcu;    /* for freeing the inode_security_struct */
          };
          kuid_t task_sid;           /* SID of creating task */
          kuid_t sid;                /* SID of this object */
          u16 sclass;             /* security class of this object */
          struct mutex lock;
};
/*
static inline void appcl_free_inode_struct(struct inode_security_struct *isc)
{
        if (isc)
                 kzfree(isc);
        return;
}

static inline struct appcl_alloc_inode_struct(struct inode_security_struct *isc)
{
        return kzalloc(sizeof(struct isc), gfp);
}
*/
#endif /* __APPCL_LSM_H */
