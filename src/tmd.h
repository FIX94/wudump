
#ifndef _TMD_H_
#define _TMD_H_

typedef struct
{
	uint16_t IndexOffset;			//	0	 0x204
	uint16_t CommandCount;			//	2	 0x206
	uint8_t	SHA2[32];				//	12	 0x208
} __attribute__ ((gcc_struct, __packed__)) ContentInfo;

typedef struct
{
	uint32_t ID;					//	0	 0xB04
	uint16_t Index;					//	4	 0xB08
	uint16_t Type;					//	6	 0xB0A
	uint64_t Size;					//	8	 0xB0C
	uint8_t	SHA2[32];				//	16	 0xB14
} __attribute__ ((gcc_struct, __packed__)) Content;

typedef struct _TitleMetaData
{
	uint32_t SignatureType;			// 0x000
	uint8_t	Signature[0x100];		// 0x004

	uint8_t	Padding0[0x3C];			// 0x104
	uint8_t	Issuer[0x40];			// 0x140

	uint8_t	Version;				// 0x180
	uint8_t	CACRLVersion;			// 0x181
	uint8_t	SignerCRLVersion;		// 0x182
	uint8_t	Padding1;				// 0x183

	uint64_t SystemVersion;			// 0x184
	uint64_t TitleID;				// 0x18C
	uint32_t TitleType;				// 0x194
	uint16_t GroupID;				// 0x198
	uint8_t	Reserved[62];			// 0x19A
	uint32_t AccessRights;			// 0x1D8
	uint16_t TitleVersion;			// 0x1DC
	uint16_t ContentCount;			// 0x1DE
	uint16_t BootIndex;				// 0x1E0
	uint8_t	Padding3[2];			// 0x1E2
	uint8_t	SHA2[32];				// 0x1E4

	ContentInfo ContentInfos[64];

	Content Contents[];				// 0x1E4

} __attribute__ ((gcc_struct, __packed__)) TitleMetaData;

#endif
