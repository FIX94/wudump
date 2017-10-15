# wudump
dump raw images from a wiiu game disc
# Usage
Download and run the .elf from homebrew launcher with a fat32 sd card/usb device or NTFS usb device inserted that has at least 23.3gb free.  
On fat32 devices the files will be dumped in 2gb parts, you will have to merge them yourself afterwards if you need the full game.wud. On NTFS devices it will be dumped into a single file.

A full dump can take a little over one and a half hours.  
After it has been dumped the wud, common.key and game.key will be in a "wudump" folder on your sd card/usb device.

## Merging the wud parts on FAT32 devices.
This step is not needed, when the file was dumped to a ntfs device.

To get the full game.wud with FAT32 devices you will have to merge them.  
If you are on windows you can use something like this for example to merge them into a game.wud on a "wudump" folder on your C drive from a cmd in the sd/usb folder:
```
copy /b game_part1.wud + game_part2.wud + game_part3.wud + game_part4.wud + game_part5.wud + game_part6.wud + game_part7.wud + game_part8.wud + game_part9.wud + game_part10.wud + game_part11.wud + game_part12.wud C:\wudump\game.wud
```

## wud2app
If you would just like to install your game using wupinstaller then grab wud2app:  
https://github.com/FIX94/wud2app/releases  
If you dont want to merge all .wud files you can put wud2app into a folder on your pc and run it from a cmd with the wudump folder path as argument, for example if the sd/usb folder happens to be in "P:\wudump\WUP-P-TEST" on windows you can just run wud2app like:
```
wud2app "P:\wudump\WUP-P-TEST"
```
If you do have all .wud files merged then put wud2app into the folder of the merged .wud and run it like run it like:  
```
wud2app common.key game.key game.wud
```
Make sure to copy the common.key and game.key into that folder as well if you use that method.  

The folder it creates can just be installed by wupinstaller.

# Build
For building you need: 
- [libfat](https://github.com/aliaspider/libfat/)
- [libiosuhax](https://github.com/dimok789/libiosuhax) (Build WITHOUT the WUT flag set.)
- [libntfs](https://github.com/Maschell/libntfs-wiiu) (Build with make wiiu-install)