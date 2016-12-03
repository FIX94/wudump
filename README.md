# wudump
dump raw images from a wiiu game disc
# Usage
Download and run the .elf from homebrew launcher with a sd card/usb device inserted that has at least 23.3gb free.  
The files will be dumped in 2gb parts, you will have to merge them yourself afterwards.  
A full dump can take a little over one and a half hours.  
After it has been dumped the wud parts and the key.bin will be in a "wudump" folder on your sd card/usb device.  
If you are on windows you can use something like this for example to merge them into a game.wud on a "wudump" folder on your C drive from a cmd in the sd/usb folder:
```
copy /b game_part1.wud + game_part2.wud + game_part3.wud + game_part4.wud + game_part5.wud + game_part6.wud + game_part7.wud + game_part8.wud + game_part9.wud + game_part10.wud + game_part11.wud + game_part12.wud C:\wudump\game.wud
```
