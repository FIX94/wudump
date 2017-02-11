
#ifndef _STRUCTS_H_
#define _STRUCTS_H_

typedef struct _toc_t {
	char name[0x1f];
	char unk; //always 0x1?
	uint32_t offsetBE;
	char unk2[0x5C];
} __attribute__ ((gcc_struct, __packed__)) toc_t;

typedef struct _app_tbl_t {
	uint32_t offsetBE;
	uint32_t size;
	uint64_t tid;
	uint32_t gid;
	char unk[0xC];
} __attribute__ ((gcc_struct, __packed__)) app_tbl_t;

#endif
