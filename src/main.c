/*
 * Copyright (C) 2016-2017 FIX94
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <stdio.h>
#include <fat.h>
#include <sys/stat.h>
#include <polarssl/md5.h>
#include <polarssl/sha1.h>
#include <iosuhax.h>
#include "dynamic_libs/os_functions.h"
#include "dynamic_libs/sys_functions.h"
#include "dynamic_libs/vpad_functions.h"
#include "system/memory.h"
#include "common/common.h"
#include "main.h"
#include "exploit.h"
#include "../payload/wupserver_bin.h"
#include "rijndael.h"
#include "fst.h"
#include "tmd.h"
#include "structs.h"

#define ALIGN_FORWARD(x, alignment) (((x) + ((alignment)-1)) & (~((alignment)-1)))

//just to be able to call async
void someFunc(void *arg)
{
	(void)arg;
}

static int mcp_hook_fd = -1;
int MCPHookOpen()
{
	//take over mcp thread
	mcp_hook_fd = MCP_Open();
	if(mcp_hook_fd < 0)
		return -1;
	IOS_IoctlAsync(mcp_hook_fd, 0x62, (void*)0, 0, (void*)0, 0, (void*)someFunc, (void*)0);
	//let wupserver start up
	sleep(1);
	if(IOSUHAX_Open("/dev/mcp") < 0)
		return -1;
	return 0;
}

void MCPHookClose()
{
	if(mcp_hook_fd < 0)
		return;
	//close down wupserver, return control to mcp
	IOSUHAX_Close();
	//wait for mcp to return
	sleep(1);
	MCP_Close(mcp_hook_fd);
	mcp_hook_fd = -1;
}

void println_noflip(int line, const char *msg)
{
	OSScreenPutFontEx(0,0,line,msg);
	OSScreenPutFontEx(1,0,line,msg);
}

void println(int line, const char *msg)
{
	int i;
	for(i = 0; i < 2; i++)
	{	//double-buffered font write
		println_noflip(line,msg);
		OSScreenFlipBuffersEx(0);
		OSScreenFlipBuffersEx(1);
	}
}

#define SECTOR_SIZE 2048
#define NUM_SECTORS 1024
#define MAX_SECTORS 0xBA7400

static uint64_t odd_offset = 0;

int fsa_odd_read_sectors(int fsa_fd, int fd, void *buf, unsigned int sector, unsigned int count, int retry) {
	int res;
	if (sector + count > MAX_SECTORS) return -1;
	do {
		res = IOSUHAX_FSA_RawRead(fsa_fd, buf, SECTOR_SIZE, count, sector, fd);
	} while(retry && res < 0);
	// Failed to read
	return res;
}

int fsa_odd_read(int fsa_fd, int fd, char *buf, size_t len, int retry)
{
	if (!len) return 0;

	unsigned int sector = odd_offset / SECTOR_SIZE;
	// Read unaligned first sector
	size_t unaligned_length = (-odd_offset)%SECTOR_SIZE;
	if (unaligned_length > len) unaligned_length = len;
	if (unaligned_length)
	{
		char sector_buf[SECTOR_SIZE];
		if (fsa_odd_read_sectors(fsa_fd, fd, sector_buf, sector, 1, retry) < 0) return -1;
		memcpy(buf, sector_buf + (odd_offset%SECTOR_SIZE), unaligned_length);
		odd_offset += unaligned_length;
		buf += unaligned_length;
		len -= unaligned_length;
		sector += 1;
	}
	if (!len) return 0;
	unsigned int full_sectors = len / SECTOR_SIZE;
	if (full_sectors) {
		
		if (fsa_odd_read_sectors(fsa_fd, fd, buf, sector, full_sectors, retry) < 0) return -1;
		sector += full_sectors;
		odd_offset += full_sectors * SECTOR_SIZE;
		buf += full_sectors * SECTOR_SIZE;
		len -= full_sectors * SECTOR_SIZE;
	}
	// Read unaligned last sector
	if (len)
	{
		char sector_buf[SECTOR_SIZE];
		if (fsa_odd_read_sectors(fsa_fd, fd, sector_buf, sector, 1, retry) < 0) return -1;
		memcpy(buf, sector_buf, len);
		odd_offset += len;
	}
	return 0;
}

static void fsa_odd_seek(uint64_t offset)
{
	odd_offset = offset;
}

int fsa_write(int fsa_fd, int fd, void *buf, int len)
{
	int done = 0;
	uint8_t *buf_u8 = (uint8_t*)buf;
	while(done < len)
	{
		size_t write_size = len - done;
		int result = IOSUHAX_FSA_WriteFile(fsa_fd, buf_u8 + done, 0x01, write_size, fd, 0);
		if(result < 0)
			return result;
		else
			done += result;
	}
	return done;
}

static const char *hdrStr = "disc2app v1.0 (based on wudump and wud2app by FIX94)";
void printhdr_noflip()
{
	println_noflip(0,hdrStr);
}

int Menu_Main(void)
{
	InitOSFunctionPointers();
	InitSysFunctionPointers();
	InitVPadFunctionPointers();
	VPADInit();
	memoryInitialize();

	// Init screen
	OSScreenInit();
	int screen_buf0_size = OSScreenGetBufferSizeEx(0);
	int screen_buf1_size = OSScreenGetBufferSizeEx(1);
	uint8_t *screenBuffer = (uint8_t*)MEMBucket_alloc(screen_buf0_size+screen_buf1_size, 0x100);
	OSScreenSetBufferEx(0, screenBuffer);
	OSScreenSetBufferEx(1, (screenBuffer + screen_buf0_size));
	OSScreenEnableEx(0, 1);
	OSScreenEnableEx(1, 1);
	OSScreenClearBufferEx(0, 0);
	OSScreenClearBufferEx(1, 0);

	printhdr_noflip();
	println_noflip(2,"Please make sure to take out any currently inserted disc.");
	println_noflip(3,"Also make sure you have at least 23.3GB free on your device.");
	println_noflip(4,"Press A to continue with a FAT32 SD Card as destination.");
	println_noflip(5,"Press B to continue with a FAT32 USB Device as destination.");
	println_noflip(6,"Press HOME to return to the Homebrew Launcher.");
	OSScreenFlipBuffersEx(0);
	OSScreenFlipBuffersEx(1);

	int vpadError = -1;
	VPADData vpad;
	int action = 0;
	while(1)
	{
		VPADRead(0, &vpad, 1, &vpadError);
		if(vpadError == 0)
		{
			if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_HOME)
			{
				MEMBucket_free(screenBuffer);
				memoryRelease();
				return EXIT_SUCCESS;
			}
			else if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_A)
				break;
			else if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_B)
			{
				action = 1;
				break;
			}
		}
		usleep(50000);
	}
	int j;
	for(j = 0; j < 2; j++)
	{
		OSScreenClearBufferEx(0, 0);
		OSScreenClearBufferEx(1, 0);
		printhdr_noflip();
		OSScreenFlipBuffersEx(0);
		OSScreenFlipBuffersEx(1);
		usleep(25000);
	}
	int line = 2;
	//will inject our custom mcp code
	println(line++,"Doing IOSU Exploit...");
	*(volatile unsigned int*)0xF5E70000 = wupserver_bin_len;
	memcpy((void*)0xF5E70020, &wupserver_bin, wupserver_bin_len);
	DCStoreRange((void*)0xF5E70000, wupserver_bin_len + 0x40);
	IOSUExploit();
	int fsaFd = -1;
	int oddFd = -1;
	int ret;
	char outDir[64];
	FILE *f = NULL;
	sha1_context sha1ctx;

	//done with iosu exploit, take over mcp
	if(MCPHookOpen() < 0)
	{
		println(line++,"MCP hook could not be opened!");
		goto prgEnd;
	}
	memset((void*)0xF5E10C00, 0, 0x20);
	DCFlushRange((void*)0xF5E10C00, 0x20);
	println(line++,"Done!");

	//mount with full permissions
	fsaFd = IOSUHAX_FSA_Open();
	if(fsaFd < 0)
	{
		println(line++,"FSA could not be opened!");
		goto prgEnd;
	}
	fatInitDefault();

	println(line++,"Please insert the disc you want to dump now to begin.");
	//wait for disc key to be written
	while(1)
	{
		DCInvalidateRange((void*)0xF5E10C00, 0x20);
		if(*(volatile unsigned int*)0xF5E10C00 != 0)
			break;
		VPADRead(0, &vpad, 1, &vpadError);
		if(vpadError == 0)
		{
			if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_HOME)
				goto prgEnd;
		}
		usleep(50000);
	}

	//opening raw odd might take a bit
	int retry = 10;
	ret = -1;
	while(ret < 0)
	{
		ret = IOSUHAX_FSA_RawOpen(fsaFd, "/dev/odd01", &oddFd);
		retry--;
		if(retry < 0)
			break;
		sleep(1);
	}
	if(ret < 0)
	{
		println(line++,"Failed to open Raw ODD!");
		goto prgEnd;
	}

	//get disc name for folder
	char discId[11];
	discId[10] = '\0';
	fsa_odd_seek(0);
	if(fsa_odd_read(fsaFd, oddFd, discId, 10, 0))
	{
		println(line++,"Failed to read first disc sector!");
		goto prgEnd;		
	}
	char discStr[64];
	sprintf(discStr, "Inserted %s", discId);
	println(line++, discStr);

	// make install dir we will write to
	char *device = (action == 0) ? "sd:" : "usb:";
	sprintf(outDir, "%s/install", device);
	mkdir(outDir, 0x600);
	sprintf(outDir, "%s/install/%s", device, discId);
	mkdir(outDir, 0x600);

	// Read common key
	u8 cKey[0x10];
	memcpy(cKey, (void*)0xF5E104E0, 0x10);

	// Read disc key
	u8 discKey[0x10];
	memcpy(discKey, (void*)0xF5E10C00, 0x10);

	int apd_enabled = 0;
	IMIsAPDEnabled(&apd_enabled);
	if(apd_enabled)
	{
		if(IMDisableAPD() == 0)
			println(line++, "Disabled Auto Power-Down.");
	}

	sprintf(discStr, "Converting %s to app...", discId);

	println(line++, "Reading Disc FST from WUD");
	//read out and decrypt partition table
	uint8_t *partTblEnc = MEMBucket_alloc(0x8000, 0x100);
	fsa_odd_seek(0x18000);
	fsa_odd_read(fsaFd, oddFd, partTblEnc, 0x8000, 1);
	uint8_t iv[16];
	memset(iv,0,16);
	aes_set_key(discKey);
	uint8_t *partTbl = MEMBucket_alloc(0x8000, 0x100);
	aes_decrypt(iv,partTblEnc,partTbl,0x8000);
	MEMBucket_free(partTblEnc);

	if(*(uint32_t*)partTbl != 0xCCA6E67B)
	{
		println(line++, "Invalid FST!");
		goto prgEnd;
	}

	//make sure TOC is actually valid
	unsigned int expectedHash[5];
	expectedHash[0] = *(uint32_t*)(partTbl+8);
	expectedHash[1] = *(uint32_t*)(partTbl+12);
	expectedHash[2] = *(uint32_t*)(partTbl+16);
	expectedHash[3] = *(uint32_t*)(partTbl+20);
	expectedHash[4] = *(uint32_t*)(partTbl+24);

	sha1_starts(&sha1ctx);
	sha1_update(&sha1ctx, partTbl+0x800, 0x7800);
	unsigned int sha1[5];
	sha1_finish(&sha1ctx, (unsigned char*)sha1);

	if(memcmp(sha1, expectedHash, 0x14) != 0)
	{
		println(line++,"Invalid TOC SHA1!");
		goto prgEnd;
	}

	int numPartitions = *(uint32_t*)(partTbl+0x1C);
	int siPart;
	toc_t *tbl = (toc_t*)(partTbl+0x800);
	void *tmdBuf = NULL;
	bool certFound = false, tikFound = false, tmdFound = false;
	uint8_t tikKey[16];

	println(line++,"Searching for SI Partition");
	//start by getting cert, tik and tmd
	for(siPart = 0; siPart < numPartitions; siPart++)
	{
		if(strncasecmp(tbl[siPart].name,"SI",3) == 0)
			break;
	}
	if(strncasecmp(tbl[siPart].name,"SI",3) != 0)
	{
		println(line++,"No SI Partition found!");
		goto prgEnd;
	}

	//dont care about first header but only about data
	uint64_t offset = ((uint64_t)tbl[siPart].offsetBE)*0x8000;
	offset += 0x8000;
	//read out FST
	println(line++,"Reading SI FST from WUD");
	void *fstEnc = MEMBucket_alloc(0x8000, 0x100);
	fsa_odd_seek(offset);
	fsa_odd_read(fsaFd, oddFd, fstEnc, 0x8000, 1);
	void *fstDec = MEMBucket_alloc(0x8000, 0x100);
	memset(iv, 0, 16);
	aes_set_key(discKey);
	aes_decrypt(iv, fstEnc, fstDec, 0x8000);
	MEMBucket_free(fstEnc);
	uint32_t EntryCount = (*(uint32_t*)(fstDec + 8) << 5);
	uint32_t Entries = *(uint32_t*)(fstDec + 0x20 + EntryCount + 8);
	uint32_t NameOff = 0x20 + EntryCount + (Entries << 4);
	FEntry *fe = (FEntry*)(fstDec + 0x20 + EntryCount);

	//increase offset past fst for actual files
	offset += 0x8000;
	uint32_t entry;
	for(entry = 1; entry < Entries; ++entry)
	{
		if(certFound && tikFound && tmdFound)
			break;
		uint32_t cNameOffset = fe[entry].NameOffset;
		const char *name = (const char*)(fstDec + NameOff + cNameOffset);
		if(strncasecmp(name, "title.", 6) != 0)
			continue;
		uint32_t CNTSize = fe[entry].FileLength;
		uint64_t CNTOff = ((uint64_t)fe[entry].FileOffset) << 5;
		uint64_t CNT_IV = CNTOff >> 16;
		void *titleF = MEMBucket_alloc(ALIGN_FORWARD(CNTSize,16), 0x100);
		fsa_odd_seek(offset + CNTOff);
		fsa_odd_read(fsaFd, oddFd, titleF, ALIGN_FORWARD(CNTSize,16), 1);
		uint8_t *titleDec = MEMBucket_alloc(ALIGN_FORWARD(CNTSize,16), 0x100);
		memset(iv,0,16);
		memcpy(iv + 8, &CNT_IV, 8);
		aes_set_key(discKey);
		aes_decrypt(iv,titleF,titleDec,ALIGN_FORWARD(CNTSize,16));
		MEMBucket_free(titleF);
		char outF[64];
		sprintf(outF,"%s/%s",outDir,name);
		//just write the first found cert, they're all the same anyways
		if(strncasecmp(name, "title.cert", 11) == 0 && !certFound)
		{
			println(line++,"Writing title.cert");
			FILE *t = fopen(outF, "wb");
			if (t == NULL) {
				println(line++,"Failed to create file");
				goto prgEnd;
			}
			fwrite(titleDec, 1, CNTSize, t);
			fclose(t);
			certFound = true;
		}
		else if(strncasecmp(name, "title.tik", 10) == 0 && !tikFound)
		{
			uint32_t tidHigh = *(uint32_t*)(titleDec+0x1DC);
			if(tidHigh == 0x00050000)
			{
				println(line++,"Writing title.tik");
				FILE *t = fopen(outF, "wb");
				if (t == NULL) {
					println(line++,"Failed to create file");
					goto prgEnd;
				}
				fwrite(titleDec, 1, CNTSize, t);
				fclose(t);
				tikFound = true;
				uint8_t *title_id = titleDec+0x1DC;
				int k;
				for(k = 0; k < 8; k++)
				{
					iv[k] = title_id[k];
					iv[k + 8] = 0x00;
				}
				uint8_t *tikKeyEnc = titleDec+0x1BF;
				aes_set_key(cKey);
				aes_decrypt(iv,tikKeyEnc,tikKey,16);
			}
		}
		else if(strncasecmp(name, "title.tmd", 10) == 0 && !tmdFound)
		{
			uint32_t tidHigh = *(uint32_t*)(titleDec+0x18C);
			if(tidHigh == 0x00050000)
			{
				println(line++,"Writing title.tmd");
				FILE *t = fopen(outF, "wb");
				if (t == NULL) {
					println(line++,"Failed to create file");
					goto prgEnd;
				}
				fwrite(titleDec, 1, CNTSize, t);
				fclose(t);
				tmdFound = true;
				tmdBuf = MEMBucket_alloc(CNTSize, 0x100);
				memcpy(tmdBuf, titleDec, CNTSize);
			}
		}
		MEMBucket_free(titleDec);
	}
	OSScreenClearBufferEx(0, 0);
	OSScreenClearBufferEx(1, 0);
	MEMBucket_free(fstDec);

	if(!tikFound || !tmdFound)
	{
		println(line++,"tik or tmd not found!");
		goto prgEnd;
	}
	TitleMetaData *tmd = (TitleMetaData*)tmdBuf;
	char gmChar[19];
	char gmmsg[64];
	uint64_t fullTid = tmd->TitleID;
	sprintf(gmChar,"GM%016" PRIx64, fullTid);
	sprintf(gmmsg,"Searching for %s Partition", gmChar);
	println(line++,gmmsg);
	uint32_t appBufLen = SECTOR_SIZE*NUM_SECTORS;
	void *appBuf = MEMBucket_alloc(appBufLen, 0x100);
	//write game .app data next
	int gmPart;
	for(gmPart = 0; gmPart < numPartitions; gmPart++)
	{
		if(strncasecmp(tbl[gmPart].name,gmChar,18) == 0)
			break;
	}
	if(strncasecmp(tbl[gmPart].name,gmChar,18) != 0)
	{
		println(line++,"No GM Partition found!");
		goto prgEnd;
	}
	println(line++,"Reading GM Header from WUD");
	offset = ((uint64_t)tbl[gmPart].offsetBE)*0x8000;
	uint8_t *fHdr = MEMBucket_alloc(0x8000, 0x100);
	fsa_odd_seek(offset);
	fsa_odd_read(fsaFd, oddFd, fHdr, 0x8000, 1);
	uint32_t fHdrCnt = *(uint32_t*)(fHdr+0x10);
	uint8_t *hashPos = fHdr + 0x40 + (fHdrCnt*4);

	//grab FST first
	println(line++,"Reading GM FST from WUD");
	uint64_t fstSize = tmd->Contents[0].Size;
	fstEnc = MEMBucket_alloc(ALIGN_FORWARD(fstSize,16), 0x100);
	fsa_odd_seek(offset + 0x8000);
	fsa_odd_read(fsaFd, oddFd, fstEnc, ALIGN_FORWARD(fstSize,16), 1);
	//write FST to file
	uint32_t fstContentCid = tmd->Contents[0].ID;
	char outF[64];
	char outbuf[64];
	sprintf(outF,"%s/%08x.app",outDir,fstContentCid);
	sprintf(outbuf, "Writing %08x.app",fstContentCid);
	println(line, outbuf);
	FILE *t = fopen(outF, "wb");
	if (t == NULL) {
		println(line++,"Failed to create file");
		goto prgEnd;
	}
	fwrite(fstEnc, 1, ALIGN_FORWARD(fstSize,16), t);
	fclose(t);
	//decrypt FST to use now
	memset(iv, 0, 16);
	uint16_t content_index = tmd->Contents[0].Index;
	memcpy(iv, &content_index, 2);
	aes_set_key(tikKey);
	fstDec = MEMBucket_alloc(ALIGN_FORWARD(fstSize,16), 0x100);
	aes_decrypt(iv, fstEnc, fstDec, ALIGN_FORWARD(fstSize,16));
	MEMBucket_free(fstEnc);
	app_tbl_t *appTbl = (app_tbl_t*)(fstDec+0x20);

	//write in files
	uint16_t titleCnt = tmd->ContentCount;
	uint16_t curCont;
	char progress[64];
	for(curCont = 1; curCont < titleCnt; curCont++)
	{
		uint64_t appOffset = ((uint64_t)appTbl[curCont].offsetBE)*0x8000;
		uint64_t totalAppOffset = offset + appOffset;
		fsa_odd_seek(totalAppOffset);
		uint64_t tSize = tmd->Contents[curCont].Size;
		uint32_t curContentCid = tmd->Contents[curCont].ID;
		char outF[64];
		char outbuf[64];
		char titlesmsg[64];
		sprintf(titlesmsg,"Dumping title %d/%d",curCont,titleCnt-1);
		sprintf(outF,"%s/%08x.app",outDir,curContentCid);
		sprintf(outbuf,"Writing %08x.app",curContentCid);
		OSScreenClearBufferEx(0, 0);
		OSScreenClearBufferEx(1, 0);
		printhdr_noflip();
		println_noflip(2,discStr);
		println_noflip(3,titlesmsg);
		println_noflip(4,outbuf);
		OSScreenFlipBuffersEx(0);
		OSScreenFlipBuffersEx(1);
		line=5;
		FILE *t = fopen(outF, "wb");
		if (t == NULL) {
			println(line++,"Failed to create file");
			goto prgEnd;
		}
		uint64_t total = tSize;
		while(total > 0)
		{
			uint32_t toWrite = ((total > (uint64_t)appBufLen) ? (appBufLen) : (uint32_t)(total));
			sprintf(progress,"0x%08X/0x%08X (%i%%)",(uint32_t)(tSize-total),(uint32_t)tSize,(uint32_t)((tSize-total)*100/tSize));
			fsa_odd_read(fsaFd, oddFd, appBuf, toWrite, 1);
			fwrite(appBuf, 1, toWrite, t);
			total -= toWrite;
			OSScreenClearBufferEx(0, 0);
			OSScreenClearBufferEx(1, 0);
			printhdr_noflip();
			println_noflip(2,discStr);
			println_noflip(3,titlesmsg);
			println_noflip(4,outbuf);
			println_noflip(5,progress);
			OSScreenFlipBuffersEx(0);
			OSScreenFlipBuffersEx(1);
		}
		line=6;
		fclose(t);
		uint16_t type = tmd->Contents[curCont].Type;
		if(type & 2) //h3 hashes used
		{
			char outF[64];
			char outbuf[64];
			sprintf(outF,"%s/%08x.h3",outDir,curContentCid);
			sprintf(outbuf,"Writing %08x.h3",curContentCid);
			println(line++,outbuf);
			t = fopen(outF, "wb");
			if (t == NULL) {
				println(line++,"Failed to create file");
				goto prgEnd;
			}
			uint32_t hashNum = (uint32_t)((tSize / 0x10000000ULL) + 1);
			fwrite(hashPos, 1, (0x14*hashNum), t);
			fclose(t);
			hashPos += (0x14*hashNum);
		}
	}
	MEMBucket_free(fstDec);
	MEMBucket_free(appBuf);
	MEMBucket_free(tmdBuf);

	println(line++,"Done!");

	if(apd_enabled)
	{
		if(IMEnableAPD() == 0)
			println_noflip(line++, "Re-Enabled Auto Power-Down.");
	}
	OSScreenFlipBuffersEx(0);
	OSScreenFlipBuffersEx(1);

prgEnd:
	//close down everything fsa related
	if(fsaFd >= 0)
	{
		if(f != NULL)
			fclose(f);
		fatUnmount("sd:");
		fatUnmount("usb:");
		if(oddFd >= 0)
			IOSUHAX_FSA_RawClose(fsaFd, oddFd);
		IOSUHAX_FSA_Close(fsaFd);
	}
	//close out old mcp instance
	MCPHookClose();
	sleep(5);
	//will do IOSU reboot
	OSForceFullRelaunch();
	SYSLaunchMenu();
	OSScreenEnableEx(0, 0);
	OSScreenEnableEx(1, 0);
	MEMBucket_free(screenBuffer);
	memoryRelease();
	return EXIT_RELAUNCH_ON_LOAD;
}
