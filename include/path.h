/* with thanks to apparmor */

#ifndef __PATH_H
#define __PATH_H

enum path_flags {
	PATH_IS_DIR = 0x1,	/* Path is  directory */
	PATH_CONNECT_PATH = 0x4, /* connect disconnected paths to / */
	PATH_CHROOT_REL = 0x8,	/* do path lookup relative to chroot */
	PATH_CHROOT_NSCONNECT = 0x10,	/* connect paths that are at ns root */

	PATH_DELEGATE_DELETED = 0x08000, /* delegate deleted file */
	PATH_MEDIATE_DELETED = 0x10000,	/* mediate deleted paths */
};

int appcl_path_name(struct path *path, int flags, char **buffer,
					const char **name, const char **info);

#endif /* __PATH_H */
