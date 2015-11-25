
#ifndef __DOMAIN_H
#define __DOMAIN_H

#include <linux/binfmts.h>
#include <linux/types.h>

struct pacl_domain {
	int size;
	char **table;
};

int somethinglsm_bprm_set_creds(struct linux_binprm *bprm);
int somethinglsm_bprm_secureexec(struct linux_binprm *bprm);
void somethinglsm_committing_creds(struct linux_binprm *bprm);
void somethinglsm_committed_creds(struct linux_binprm *bprm);

void pacl_free_domain_entries(struct pacl_domain *domain)
int pacl_change_hat(const char *hats[], int count, u64 token, bool permtest);
int pacl_change_profile(const char *ns_name, const char *name,
						bool onexec, bool permtest);

#endif /* __DOMAIN_H */
