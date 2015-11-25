
#ifndef __POLICY_H
#define __POLICY_H

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/socket.h>

#include <linux/resource.h>

#include "domain.h"
#include "file.h"

extern const char *const pacl_profile_mode_names[];
#define PACL_MODE_NAMES_MAX_INDEX 4

#define PROFILE_MODE(_profile, _mode)			\
		((pacl_g_profile_mode == (_mode)) || 	\
		 ((_profile)->mode == (_mode)))

#define COMPLAIN_MODE(_profile) PROFILE_MODE((_profile), PACL_COMPLAIN)

#define KILL_MODE(_profile) PROFILE_MODE((_profile), PACL_KILL)

#define PROFILE_IS_HAT(_profile) ((_profile)->flags & PFLAG_HAT)

#define PROFILE_INVALID(_profile) ((_profile)->flags & PFLAG_INVALID)

#define on_list_rcu(X) (!list_empty(X) && (X)->prev != LIST_POISON2)

enum profile_mode {
	PACL_ENFORCE,		/* enforce access rules */
	PACL_COMPLAIN,		/* allow and log access violations */
	PACL_KILL,			/* kill task on access violation */
	PACL_UNCONFINED,	/* profile set to unconfined */
};

enum profile_flags {
	PFLAG_HAT = 1,					/* profile is a hat */
	PFLAG_NULL = 4, 				/* profile is a null learning profile */
	PFLAG_IX_ON_NAME_ERROR = 8,		/* fallback to ix on name lookup failed */
	PFLAG_IMMUTABLE = 0x10, 		/* dont allow changes/replacement */
	PFLAG_USER_DEFINED = 0x20, 		/* user based profile - lower privs */
	PFLAG_NO_LIST_REF = 0x40,		/* list doesnt keep profile ref */
	PFLAG_OLD_NULL_TRANS = 0x100,	/* use // as the null transition */
	PFLAG_INVALID = 0x200,			/* profile replaced/removed */
	PFLAG_NS_COUNT = 0x400, 		/* carries NS ref count */
	
	/* These flags must correspond with PATH_FLAGS */
	PFLAG_MEDIATE_DELETED = 0x10000, 
};

struct pacl_profile;

/* stuct pacl_policy - common part of namespaces and profiles
 * name: name of the object
 * hname: hierarchical name
 * list: list policy object is on
 * head of the profiles list contained in the object
 */

struct pacl_policy {
	char *name;
	char *hname;
	struct list_head list;
	struct list_head profiles;
};

/*struct pacl_ns_acct - accounting of profiles in namespace
 * max_size: maximum space allowed for all profiles in namespace
 * max_count: maximum number of profile that can be in this namespace
 * size: current size of profiles
 * count: current count of profiles (includes null profiles)
 */
 
struct pacl_ns_acct {
	int max_size;
	int max_count;
	int size;
	int count;
};

/* struct pacl_namespace - namespace for a set of profiles
 * base: common policy
 * parent: parent of namespace
 * lock: lock for modifying the object
 * acct: accounting for the namespace
 * unconfined: special unconfined profile for the namespace
 * sub_ns: list of namespaces under the current namespace
 * uniq_null: uniq value used for null learning profiles
 * uniq_id: a unique id count for the profiles in the namespace
 * //dents: dentries for the namespaces file entries in 'apparmorfs' FIX
 * 
 * pacl_namespace defines the set profiles that are searched
 * to determine which profile to attach to a task.
 * 
 * namespaces are hierarchical and only namespaces and profiles
 * below the current namespace are visible
 * 
 * namespace names must be unique and can not contain 
 * the characters :/\0
 */
 
struct pacl_namespace {
	struct pacl_policy base;
	struct pacl_namespace *parent;
	struct mutex lock;
	struct pacl_ns_acct acct;
	struct pacl_profile *unconfined
	struct list_head sub_ns;
	atomic_t uniq_null;
	long uniq_id;
	
	/* // struct dentry *dents[AAFS_NS_SIZEOF]; */
};

/* struct pacl_policy_db - match engine for a policy
 * dfa: dfa pattern match
 * start: set of start states for the different classes of data
 */
 
struct pacl_policydb {
	struct pacl_dfa *dfa;
	unsigned int start[PACL_CLASS_LIST + 1];
};

struct pacl_replacedby {
	struct kref count;
	struct pacl_profile __rcu *profile;
};

/* struct pacl_profile - basic confinement data
 * 
 */
 
struct pacl_rlimit {
	unsigned int mask;
	struct rlimit limits[RLIM_NLIMITS];
};
 
struct pacl_caps {
	kernel_cap_t allow;
	kernel_cap_t audit;
	kernel_cap_t quiet;
	kernel_cap_t kill;
	kernel_cap_t extended;
};

struct pacl_profile {
	struct pacl_policy base;
	struct kref count;
	struct rcu_head rcu;
	struct pacl_profile __rcu *parent
	
	struct pacl_namespace *ns;
	struct pacl_replacedby *replacedby;
	const char *rename;
	
	const char *attach;
	struct pacl_dfa *xmatch;
	int xmatch_len;
	enum audit_mode audit;
	long mode;
	long flags;
	u32 path_flags;
	int size;
	
	struct pacl_policydb policy;
	struct pacl_file_rules file;
	struct pacl_caps caps;
	struct pacl_rlimit rlimits;
	
	unsigned char *hash;
	char *dirname;
	/* // struct dentry *dents[AAFS_PROF_SIZEOF]; */
};
#endif /* __POLICY_H */
