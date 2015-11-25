
#ifndef __FILE_H
#define __FILE_H

#include "domain.h"
#include "policy.h"
/*TODO match.h, policy.h*/

struct pacl_profile;
struct path;

/* Profile permissions */

#define PACL_MAY_CREATE				0x0010
#define PACL_MAY_DELETE				0x0020
#define PACL_MAY_META_WRITE			0x0040
#define PACL_MAY_META_READ			0x0080

#define PACL_MAY_CHMOD				0x0100
#define PACL_MAY_CHOWN				0x0200
#define PACL_MAY_LOCK				0x0400
#define PACL_EXEC_MMAP				0x0800

#define PACL_MAY_LINK				0x1000
#define PACL_LINK_SUBSET			PACL_MAY_LOCK
#define PACL_MAY_ONEEXEC			0x40000000
#define PACL_MAY_CHANGE_PROFILE		0x80000000
#define PACL_MAY_CHANGEHAT			0x80000000

#define PACL_AUDIT_FILE_MASK(MAY_READ | 			\
							 MAY_WRITE | 			\
							 MAY_EXEC | 			\
							 MAY_APPEND | 			\
							 PACL_MAY_CREATE | 		\
							 PACL_MAY_DELETE |		\
							 PACL_MAY_META_WRITE | 	\
							 PACL_MAY_META_READ |	\
							 PACL_MAY_CHMOD | 		\
							 PACL_MAY_CHOWN |		\
							 PACL_MAY_LOCK | 		\
							 PACL_EXEC_MMAP |		\
							 PACL_MAY_LINK)
							 
/* xindex */

#define PACL_X_INDEX_MASK		0x03ff

#define PACL_X_TYPE_MASK		0x0c00
#define PACL_X_TYPE_SHIFT		10
#define PACL_X_NONE				0x0000
#define PACL_X_NAME				0x0400 /* use executable name px */
#define PACL_X_TABLE			0x0800 /* use a specified name */

#define PACL_X_UNSAFE			0x1000
#define PACL_X_CHILD			0x2000 /* make >AA_X_NONE apply to children */
#define PACL_X_INHERIT			0x4000
#define PACL_X_UNCONFINED		0x8000

/* passed in the bprm->unsafe field */
#define PACL_SECURE_X_NEEDED	0x8000

/* need to make conditional which ones are being set */
struct path_cond {
	kuid_t uid;
	umode_t mode;
};

/* file_perms - file permission
 * allow: mask of permissions that are allowed
 * audit: mask of permissions to force an audit message for
 * quiet: mask of permissions to quiet audit messages for
 * kill: mask of permissions that when matched will kill the task
 * xindex: exec transition index if @allow contains MAY_EXEC
 * 
 * audit and quiet mask should be mutually exclusive
 */
struct file_perms {
	u32 allow;
	u32 audit;
	u32 quiet;
	u32 kill;
	u16 xindex;
};

extern struct file_perms nullperms;

#define COMBINED_PERM_MASK(X) ((X).allow | (X).audit | (X).quiet | (X).kill)

static inline u16 dfa_map_xindex(u16 mask)
{
	u16 old_index = (mask >> 10) & 0xf;
	u16 index = 0;
	
	if (mask & 0x100)
		index |= PACL_X_UNSAFE;
	if (mask & 0x200)
		index |= PACL_X_INHERIT;
	if (mask & 0x80)
		index |= PACL_X_UNCONFINED;
		
	if (old_index == 1) {
		index |= PACL_X_UNCONFINED;
	} else if (old_index == 2) {
		index |= PACL_X_NAME;
	} else if (old_index == 3) {
		index |= PACL_X_NAME | PACL_X_CHILD;
	} else if (old_index) {
		index |= PACL_X_TABLE;
		index |= old_index - 4;
	}
	
	return index;
}

/* map old dfa inline permissions to new format */
#define dfa_user_allow(dfa, state)	(((ACCEPT_TABLE(dfa)[state]) & 0x7f) | \
									 ((ACCEPT_TABLE(dfa)[state]) & 0x80000000))
#define dfa_user_audit(dfa, state)	((ACCEPT_TABLE2(dfa)[state]) & 0x7f)
#define dfa_user_quiet(dfa, state)	(((ACCEPT_TABLE2(dfa)[state]) >> 7) & 0x7f)
#define dfa_user_xindex(dfa, state)	\
			(dfa_map_xindex(ACCEPT_TABLE(dfa)[state] & 0x3fff))
			
#define dfa_other_allow(dfa, state) ((((ACCEPT_TABLE(dfa)[state]) >> 14) & 0x7f) \
									  ((ACCEPT_TABLE(dfa)[state]) & 0x80000000))
#define dfa_other_audit(dfa, state)	(((ACCEPT_TABLE2(dfa)[state]) >>14) & 0x7f)
#define dfa_other_quiet(dfa, state)	\
			((((ACCEPT_TABLE2(dfa)[state]) >> 7) >> 14) & 0x7f)
#define dfa_other_xindex(dfa, state)	\
			(dfa_map_xindex((ACCEPT_TABLE(dfa)[state] >>14) & 0x3fff))
			
int pacl_audit_file (struct pacl_profile *profile, struct file_perms *perms,
					 gfp_t gfp, int op, u32 request, const char *name,
					 const char *target, kuid_t ouid, const char *info, int error);

/* struct pacl_file_rules
 * dfa: dfa to match path names and conditionals against
 * perms: permission table 
 * trans: transition table for indexed by named x transitions
 * 
 * file permissions are determined by matching a path against @dfa 
 * and then using the value of the accept entry for the matching state
 * as index into "perms". Id a named exec transition is required it 
 * is looked up in the transition table.
 */
 
struct pacl_file_rules {
	unsigned int start;
	struct pacl_dfa *dfa;
	/*struct perms perms;*/
	struct pacl_domain trans;
};

unsigned int pacl_str_perms(struct pacl_dfa *dfa, unsigned int start,
							const char *name, struct path_cond *cond,
							struct file_perms *perms);
							
int pacl_path_perm(int op, struct pacl_profile *profile, struct path *path,
				   int flags, u32 request, struct path_cond *cond);
				   
int pacl_path_link(struct pacl_profile *profile, struct dentry *old_dentry,
				   struct path *new_dir, struct dentry *new_dentry);
				   
int pacl_file_perm(int op, struct pacl_profile *profile, struct file *file,
				   u32 request);
				   
static inline void pacl_free_file_rules(struct pacl_file_rules *rules)
{
	pacl_put_dfa(rules->dfa);
	pacl_free_domain_entries(&rules->trans);
}

/* 
 * pacl_map_file_perms - map file flags to pacl permissions
 * file: open file to map flags to pacl permissions
 */

static inline u32 pacl_map_file_to_perms(struct file *file)
{
	int flags = file->f_flags;
	u32 perms = 0;
	
	if (file->f_mode & FMODE_WRITE)
		perms |= MAY_WRITE;
	if (file->f_mode & FMODE_READ)
		perms |= MAY_READ;
		
	if ((flags & O_APPEND) && (perms & MAY_WRITE))
		perms = (perms & ~MAY_WRITE) | MAY_APPEND;
	/* trunc implies write permission */
	if (flags & O_TRUNC)
		perms |= MAY_WRITE;
	if (flags & O_CREAT)
		perms |= PACL_MAY_CREATE;
		
	return perms;
}

#endif /* __FILE_H */
