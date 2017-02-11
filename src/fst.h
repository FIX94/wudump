
#ifndef _FST_H_
#define _FST_H_

typedef struct _FEntry
{
	union
	{
		struct
		{
			uint32_t Type		:8;
			uint32_t NameOffset	:24;
		};
		uint32_t TypeName;
	};
	union
	{
		struct		// File Entry
		{
			uint32_t FileOffset;
			uint32_t FileLength;
		};
		struct		// Dir Entry
		{
			uint32_t ParentOffset;
			uint32_t NextOffset;
		};
		uint32_t entry[2];
	};
	uint16_t Flags;
	uint16_t ContentID;
} __attribute__ ((gcc_struct, __packed__)) FEntry;

#endif
