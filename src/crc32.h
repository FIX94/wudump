
#ifndef CRC32_H
#define CRC32_H

#ifdef __cplusplus
extern "C"
{
#endif

#define UPDC32(octet, crc) (crc_32_tab[((crc)\
			^ (octet)) & 0xff] ^ ((crc) >> 8))

unsigned int crc32buffer(const unsigned char *buffer, const unsigned int len, unsigned int oldcrc32);

#ifdef __cplusplus
}
#endif
#endif /* CRC32_H */
