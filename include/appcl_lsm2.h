/* with thanks to richacl */

#ifndef __APPCL_LSM2_H
#define __APPCL_LSM2_H

#include <linux/types.h>
#include <linux/string.h>
#include <stdbool.h>

/* control parameters */
extern bool appcl_g_debug;
extern unsigned int appcl_path_max;


/* pacl structure */
/* pacl flags values */
#define PACL_AUTO_INHERIT	0x01
#define PACL_PROTECTED		0x02
#define	PACL_DEFAULTED		0x04
/* specific acl flag */
#define PACL_WRITE_THROUGH	0x40
#define PACL_MASKED			0x80
/* valid flags */
#define PACL_VALID_FLAGS (			\
		PACL_AUTO_INHERIT |					\
		PACL_PROTECTED |						\
		PACL_DEFAULTED |						\
		PACL_WRITE_THROUGH |				\
		PACL_MASKED)

/* pacl_o structure */
/* pacl_o, o_type values */
#define PACL_ACCESS_GRANTED	0x0000
#define PACL_ACCESS_DENIED	0x0001

/* pacl_o, o_flags bitflags */
#define PACL_FILE_INHERIT_ACE			0x0001
#define PACL_DIRECTORY_INHERIT_ACE		0x0002
#define PACL_INHERIT_ONLY_ACE			0x0004
#define PACL_IDENTIFIER_GROUP			0x0008
#define PACL_INHERITED_ACE				0x0040
/* specific entry flag */
#define PACL_UNMAPPED_WHO				0x2000
#define PACL_SPECIAL_WHO				0x4000
/* valid flags */
#define PACL_O_VALID_FLAGS (				\
		PACL_FILE_INHERIT_ACE |			\
		PACL_DIRECTORY_INHERIT_ACE |	\
		PACL_INHERIT_ONLY_ACE |			\
		PACL_IDENTIFIER_GROUP |			\
		PACL_INHERITED_ACE |			\
		PACL_UNMAPPED_WHO |				\
		PACL_SPECIAL_WHO)

/* pacl_o o_mask bitflags */
#define PACL_READ_DATA				0x00000001
#define PACL_LIST_DIRECTORY			0x00000001
#define PACL_WRITE_DATA				0x00000002
#define PACL_ADD_FILE				0x00000002
#define PACL_APPEND_DATA			0x00000004
#define PACL_ADD_SUBDIRECTORY		0x00000004
#define PACL_READ_NAMED_ATTRS		0x00000008
#define PACL_WRITE_NAMED_ATTRS		0x00000010
#define PACL_EXECUTE				0x00000020
#define PACL_DELETE_CHILD			0x00000040
#define PACL_READ_ATTRIBUTES		0x00000080
#define PACL_WRITE_ATTRIBUTES		0x00000100
#define PACL_WRITE_RETENTION		0x00000200
#define PACL_WRITE_RETENTION_HOLD	0x00000400
#define PACL_DELETE					0x00010000
#define PACL_READ_ACL				0x00020000
#define PACL_WRITE_ACL				0x00040000
#define PACL_WRITE_OWNER			0x00080000
#define PACL_SYNCHRONIZE			0x00100000

/* valid masks */
#define PACL_VALID_MASK (							\
		PACL_READ_DATA | PACL_LIST_DIRECTORY |		\
		PACL_WRITE_DATA | PACL_ADD_FILE |			\
		PACL_APPEND_DATA | PACL_ADD_SUBDIRECTORY |	\
		PACL_READ_NAMED_ATTRS | 					\
		PACL_WRITE_NAMED_ATTRS | PACL_EXECUTE |		\
		PACL_DELETE_CHILD | PACL_READ_ATTRIBUTES |	\
		PACL_WRITE_ATTRIBUTES | 					\
		PACL_WRITE_RETENTION |						\
		PACL_WRITE_RETENTION_HOLD | PACL_DELETE |	\
		PACL_READ_ACL | PACL_WRITE_ACL |			\
		PACL_WRITE_OWNER | PACL_SYNCHRONIZE)

/* special values for pacl_o flags and PACL_SPECIAL_WHO */
#define PACL_OWNER_SPECIAL_ID		0
#define PACL_LOW_SPECIAL_ID			1
#define PACL_HIGH_SPECIAL_ID		2
#define PACL_SYSTEM_SPECIAL_ID		4


struct pacl_o
{
	unsigned short o_type;
	unsigned short o_flags;
	unsigned int o_mask;
	union
	{
			u32	o_id;
			char *	o_who;
	};
};

struct pacl
{
	unsigned char 	pacl_flags;
	unsigned short 	pacl_count;
	unsigned int 	pacl_owner_mask;
	unsigned int 	pacl_group_mask;
	unsigned int 	pacl_other_mask;
	struct pacl_o 	pacl_entries[0];
};


#define pacl_for_each_entry(_pacl_o, _pacl)		\
		for ((_pacl_o) = (_pacl)->pacl_entries;	\
			 (_pacl_o) != (_pacl)->pacl_entries + (_pacl)->pacl_count;	\
			 (_pacl_o)++)

#define pacl_for_each_entry_reverse(_pacl_o, _pacl)		\
		for ((_pacl_o) = (_pacl)->pacl_entries + (_pacl)->pacl_count - 1;	\
			 (_pacl_o) != (_pacl)->pacl_entries - 1;	\
			 (_pacl_o)--)

/* pacl to text flags */
#define PACL_TEXT_LONG					1
#define PACL_TEXT_FILE_CONTEXT			2
#define PACL_TEXT_DIRECTION_CONTEXT		4
#define PACL_TEXT_SHOW_MASKS			8
#define PACL_TEXT_SIMPLIFY				16
#define PACL_TEXT_ALIGN					32
#define PACL_TEXT_NUMERIC_IDS			64

/* pacl from text flags */
#define PACL_TEXT_OWNER_MASK			1
#define PACL_TEXT_GROUP_MASK			2
#define PACL_TEXT_OTHER_MASK			4
#define PACL_TEXT_FLAGS					8

extern bool pacl_is_owner_group(const struct pacl_o *);
extern bool pacl_is_high_group(const struct pacl_o *);
extern bool pacl_is_low_group(const struct pacl_o *);
extern bool pacl_is_system_group(const struct pacl_o *);
extern bool pacl_is_everyone(const struct pacl_o *);

static inline bool pacl_is_allow(const struct pacl_o *paclo)
{
	return paclo->o_type == PACL_ACCESS_GRANTED;
}

static inline bool pacl_is_deny(const struct pacl_o *paclo)
{
	return paclo->o_type == PACL_ACCESS_DENIED;
}

static inline bool pacl_is_inheritable(const struct pacl_o *paclo)
{
	return paclo->o_flags == (PACL_FILE_INHERIT_ACE |
								PACL_DIRECTORY_INHERIT_ACE);
}

static inline bool pacl_is_inherit_only(const struct pacl_o *paclo)
{
	return paclo->o_flags == PACL_INHERIT_ONLY_ACE;
}

static inline bool pacl_is_auto_inherit(const struct pacl_o *paclo)
{
	return paclo->o_flags == PACL_AUTO_INHERIT;
}

static inline bool pacl_is_inherited(const struct pacl_o *paclo)
{
	return paclo->o_flags == PACL_INHERITED_ACE;
}

extern void pacl_set_uid(struct pacl_o *, uid_t);
extern void pacl_set_gid(struct pacl_o *, gid_t);
extern int pacl_set_special_who(struct pacl_o *, const char *);
extern int pacl_set_unmapped_who(struct pacl_o *, const char *, unsigned int);

#endif /* __APPCL_LSM2_H */
