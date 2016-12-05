
#define FS_MEMSET ((void* (*)(void*, int, unsigned int))0x107F5018)
#define IOS_FS_DECRYPT ((void (*)(int,void*,unsigned int,const void*,unsigned int,void*,unsigned int))0x107F3FE0)

void odm_readkey(unsigned int base, void *key)
{
	char iv[0x10];
	FS_MEMSET(iv, 0, 0x10);
	//session key fd, used to decrypt drive data
	int fd = *(volatile int*)(base + 0x409CC);
	//decrypt disc key with the session key
	IOS_FS_DECRYPT(fd, iv, 0x10, key, 0x10, (void*)0x1E10C00, 0x10);
}
