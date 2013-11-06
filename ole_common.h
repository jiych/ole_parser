#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef signed short int16_t;
typedef signed int int32_t;
typedef struct ole_header_tag
{
	unsigned char magic[8];		/* should be: 0xd0cf11e0a1b11ae1 */
	unsigned char clsid[16];
	uint16_t minor_version __attribute__ ((packed));
	uint16_t dll_version __attribute__ ((packed));
	int16_t byte_order __attribute__ ((packed));			/* -2=intel */

	uint16_t log2_big_block_size __attribute__ ((packed));		/* usually 9 (2^9 = 512) */
	uint32_t log2_small_block_size __attribute__ ((packed));	/* usually 6 (2^6 = 64) */

	int32_t reserved[2] __attribute__ ((packed));
	int32_t bat_count __attribute__ ((packed));
	int32_t prop_start __attribute__ ((packed));

	uint32_t signature __attribute__ ((packed));
	uint32_t sbat_cutoff __attribute__ ((packed));			/* cutoff for files held in small blocks (4096) */

	int32_t sbat_start __attribute__ ((packed));
	int32_t sbat_block_count __attribute__ ((packed));
	int32_t xbat_start __attribute__ ((packed));
	int32_t xbat_count __attribute__ ((packed));
	int32_t bat_array[109] __attribute__ ((packed));

}ole_header_t;

typedef struct ole_property_tag
{
	char name[64];		/* in unicode */
	uint16_t name_size __attribute__ ((packed));
	unsigned char type;		/* 1=dir 2=file 5=root */
	unsigned char color;		/* black or red */
	uint32_t prev __attribute__ ((packed));
	uint32_t next __attribute__ ((packed));
	uint32_t child __attribute__ ((packed));

	unsigned char clsid[16];
	uint32_t user_flags __attribute__ ((packed));

	uint32_t create_lowdate __attribute__ ((packed));
	uint32_t create_highdate __attribute__ ((packed));
	uint32_t mod_lowdate __attribute__ ((packed));
	uint32_t mod_highdate __attribute__ ((packed));
	int32_t  start_block __attribute__ ((packed));
	uint32_t size __attribute__ ((packed));
	unsigned char reserved[4];
}ole_property_t;
