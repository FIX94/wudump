/*
 * Copyright (C) 2016 FIX94
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
#include "dynamic_libs/os_functions.h"
#include "dynamic_libs/sys_functions.h"
#include "dynamic_libs/vpad_functions.h"
#include "system/memory.h"
#include "common/common.h"
#include "main.h"
#include "exploit.h"
#include "iosuhax.h"

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

int fsa_odd_read(int fsa_fd, int fd, void *buf, int offset)
{
	return IOSUHAX_FSA_RawRead(fsa_fd, buf, SECTOR_SIZE, NUM_SECTORS, offset, fd);
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

void printhdr_noflip()
{
	println_noflip(0,"wud2sd v1.0 by FIX94");
}

int Menu_Main(void)
{
	InitOSFunctionPointers();
	InitSysFunctionPointers();
	InitVPadFunctionPointers();
    VPADInit();

    // Init screen
    OSScreenInit();
    int screen_buf0_size = OSScreenGetBufferSizeEx(0);
    int screen_buf1_size = OSScreenGetBufferSizeEx(1);
	uint8_t *screenBuffer = (uint8_t*)memalign(0x100, screen_buf0_size+screen_buf1_size);
    OSScreenSetBufferEx(0, screenBuffer);
    OSScreenSetBufferEx(1, (screenBuffer + screen_buf0_size));
    OSScreenEnableEx(0, 1);
    OSScreenEnableEx(1, 1);
	OSScreenClearBufferEx(0, 0);
	OSScreenClearBufferEx(1, 0);

	printhdr_noflip();
	println_noflip(2,"Please make sure to take out any currently inserted disc.");
	println_noflip(3,"Also make sure you have at least 23.3GB free on your sd card.");
	println_noflip(4,"Press A to continue or HOME to abort now.");
	OSScreenFlipBuffersEx(0);
	OSScreenFlipBuffersEx(1);

    int vpadError = -1;
    VPADData vpad;

	while(1)
	{
        VPADRead(0, &vpad, 1, &vpadError);
        if(vpadError == 0)
		{
			if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_HOME)
			{
				free(screenBuffer);
				return EXIT_SUCCESS;
			}
			else if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_A)
				break;
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
	IOSUExploit();
	int fsaFd = -1;
	int oddFd = -1;
	int ret;
	char sdPath[64];
	FILE *f = NULL;

	//done with iosu exploit, take over mcp
	if(MCPHookOpen() < 0)
	{
		println(line++,"MCP hook could not be opened!");
		goto prgEnd;
	}
	memset((void*)0xF5E00000, 0, 0x20);
	DCFlushRange((void*)0xF5E00000, 0x20);
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

	while(1)
	{
		DCInvalidateRange((void*)0xF5E00000, 0x20);
		if(*(volatile unsigned int*)0xF5E00000 != 0)
			break;
        VPADRead(0, &vpad, 1, &vpadError);
        if(vpadError == 0)
		{
			if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_HOME)
				goto prgEnd;
		}
		usleep(50000);
	}
	mkdir("sd:/wud2sd",0x600);

	u8 discKey[0x10];
	memcpy(discKey, (void*)0xF5E00000, 0x10);

	f = fopen("sd:/wud2sd/key.bin", "wb");
	if(f == NULL)
	{
		println(line++,"Failed to write Disc Key!");
		goto prgEnd;
	}
	fwrite(discKey, 1, 0x10, f);
	fclose(f);
	f = NULL;
	println(line++,"Disc Key dumped!");

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
	char progress[64];
	bool newF = true;
	int part = 1;
	unsigned int readSectors = 0;
	int bufSize = SECTOR_SIZE*NUM_SECTORS;
	void *sectorBuf = malloc(bufSize);
	//0xBA7400 = full disc
	while(readSectors < 0xBA7400)
	{
		if(newF)
		{
			if(f)
				fclose(f);
			f = NULL;
			sprintf(sdPath, "sd:/wud2sd/game_part%i.wud", part);
			f = fopen(sdPath, "wb");
			if(f == NULL)
			{
				println(line++,"Failed to write Disc WUD!");
				goto prgEnd;
			}
			part++;
			newF = false;
		}
		ret = fsa_odd_read(fsaFd, oddFd, sectorBuf, readSectors);
		if(ret < 0)
			continue;
		fwrite(sectorBuf, 1, bufSize, f);
		readSectors += NUM_SECTORS;
		if((readSectors % 0x100000) == 0)
			newF = true; //new file every 2gb
		if((readSectors % 0x2000) == 0)
		{
			OSScreenClearBufferEx(0, 0);
			OSScreenClearBufferEx(1, 0);
			sprintf(progress,"0x%06X/0xBA7400 (%i%%)",readSectors,(readSectors*100)/0xBA7400);
			printhdr_noflip();
			println_noflip(2,progress);
			OSScreenFlipBuffersEx(0);
			OSScreenFlipBuffersEx(1);
		}
	}
	free(sectorBuf);
	OSScreenClearBufferEx(0, 0);
	OSScreenClearBufferEx(1, 0);
	sprintf(progress,"0x%08x/0xBA7400 (100%%)",readSectors);
	printhdr_noflip();
	println_noflip(2,progress);
	println_noflip(3,"Disc dumped!");
	OSScreenFlipBuffersEx(0);
	OSScreenFlipBuffersEx(1);

prgEnd:
	//close down everything fsa related
	if(fsaFd >= 0)
	{
		if(f != NULL)
			fclose(f);
		fatUnmount("sd:");
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
	free(screenBuffer);
    return EXIT_RELAUNCH_ON_LOAD;
}
