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

#Permissions
- General permission mask.
'appcl_lsm_inode_permission' security hook, uses the 'appcl_mask_perm_check()' function to: check if the current process path matches a security path on the requested inode 'check_current_cred_path()'.
It then checks the requested permission mask against the permission entries for the inode, 'appcl_check_permission_mask_match()', and grants access based on this.
- Specific requested permission. Hooks such as appcl_lsm_inode_create use the 'appcl_specific_perm_check()' function to: check for a specific permissions to complete the action, such as 'read' or 'write'.
E.g. The inode_create hook, first checks the process path as with the 'appcl_mask_perm_check()' hook, and then checks for specific WRITE permission 'appcl_check_rperm_match()'.
E.g. The file_open hook, first checks the process path as with the inode_permission hook, and then checks for specific READ permission 'appcl_check_rperm_match()'.

#Default DENY behaviour
- To ensure that only the labelled permissions are enforced and all other actions are denied (whitelisting), AppCL LSM supports default deny behaviour.
- To enable, add the deny attribute 'deny:-;' to the extended attribute. Extended attribute format section shows the format for this.

#Extended attributes
AppCL LSM stores the security label in the file system extended attribute.
The Linux utility 'setfattr' is used to set the permissions for an inode and store in the extended attribute.
It populates the security information when a user sets an extended attribute (appcl_lsm_inode_post_setxattr)

- The 'appcl_lsm_inode_post_setxattr' hook in 'appcl_lsm.c' passes the extended attribute to the function 'make_appcl_entry()' to set up the security information based on the extended attribute value. AppCL must now do this with the extended attribute when the system reboots.
- The 'appcl_lsm_d_instantiate' hook initialises the inode security label and is used to retain the permissions after power loss. It checks the superblocks 'smagic' attribute to avoid getting the extended attribute from a filesystem that does not support it or for cases such as inodes that have not been fully initialised, such as during boot. It then uses the 'getxattr' interface to receive the extended attribute value. As with the 'appcl_lsm_inode_post_setxattr' hook, the 'appcl_lsm_d_instantiate' hook passes the extended attribute to the function 'make_appcl_entry()' to set up the security information based on the extended attribute value. This handles the repopulation of the inode security label when the system reboots.

#Extended attribute format
- The extended attribute value takes the following format:
# /path/to/app:perm;

- Multiple permission entries can be set in the following:
# /path/to/app:perm;/path/to/app:perm;/path/to/app:perm;

- Set the default DENY behaviour with the deny attribute [deny:-;]:
# /path/to/app:perm;deny:-;

#appcl.py
- Python tool to manage the security labelling of files/directories for the AppCL LSM access control module [appcl-lsm/security-config/tools/appcl.py].
- Help:
python appcl.py -h

- DESCRIPTION
The appcl.py script handles the extended attributes associated with the AppCL LSM security module. The setfattr and getfattr system utilities can also be used to manage extended attributes. If using these utilities the appcl security namespace must be specified [-n security.appcl] for AppCL LSM to process and enforce the attribute. The attr package is still required for appcl.py functionality.

- EXAMPLE USAGE
-- Set Attributes:
- Directory - python appcl.py --dir <input-directory> --set <xattr-value>
- File - python appcl.py --file <input-file> --set <xattr-value>
-- Get Attributes:
- Directory - python appcl.py --dir <input-directory> --get
- File - python appcl.py --file <input-file> --get
-- Remove Attributes:
- Directory - python appcl.py --dir <input-directory> --remove
- File - python appcl.py --file <input-file> --remove

- OPTIONS
--   -f file, --file=file
- Specifies a file input.
--   -d directory, --dir=directory
- Specifies a directory input.
--   -v, --set
- Sets the new AppCL LSM value of the extended attribute, and associated permissions.
--   -g, --get
- View the AppCL LSM stored extended attribute for file/directory contents.
--   -x, --remove
- Remove the AppCL LSM extended attribute and associated permission entries.
--   -h, --help
- Help page
