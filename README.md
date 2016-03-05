# appcl-lsm

- Linux kernel security module to implement program based access control mechanisms
- Author - James Johnson
- Website - www.appcl-lsm.org
- License - GNU General Public License v3.0

- Final year project at Leeds Beckett University, BSc (Hons) Computer Forensics and Security

#appcl_lsm.c
- Contains the Linux Security Module (LSM) hook functions
- Module initialisation and security module registration

#appcl_lsm.h
- Defines kernel structure security labels
- Defines PACL permission entries
- Defines AppCL LSM values and labels

#audit.c
- Audit functions for permforming access control (key audit functions detailed below)
- check_current_cred_path()
        - Compares PACL pathname, with current credentials path name
- appcl_check_permission_mask_match()
        - Check permission mask, against inode PACL entries permissions
- appcl_check_rperm_match()
        - Check for a specific requested permission, in inode PACL entries

#audit.h
- defines audit functions
- audit specific values and labels

#Security labelling
The current process credentials are labelling with the path of the binary application relating to that process.
E.g. The credentials for the 'nano' process, store the path '/bin/nano', for identifying the current application.
The protected file stores the path of an application and its permissions (rwx) in the relevant inode security label.

#Extended attributes
AppCL LSM stores the security label in the file system extended attribute.
The Linux utility 'setfattr' is used to set the permissions for an inode and store in the extended attribute.
It populates the security information when a user sets an extended attribute (appcl_lsm_inode_post_setxattr)

#Permissions
appcl_lsm_inode_permission, checks if the current process path matches a security path on the requested inode 'check_current_cred_path()'.
It then checks the requested permission mask against the permission entries for the inode, 'appcl_check_permission_mask_match()', and grants access based on this.

#Current issue
When the system is powered off/reboots, AppCL must reset the security information for the inodes with an AppCL extended attribute. This is because the inode security label is stored in RAM and the extended attribute is used to retain a representation of this on disk.
The 'security_inode_setsecurity', 'security_inode_getsecurity', 'security_inode_d_instantiate', 'security_inode_init_security' are all security hooks relating to the extended attributes.
The 'appcl_lsm_inode_post_setxattr' hook in 'appcl_lsm.c' passes the extended attribute to the function 'make_appcl_entry()' to set up the security information based on the extended attribute value. AppCL must now do this with the extended attribute when the system reboots.
