# OnlyKey-Firmware

This is the official firmware for **OnlyKey** - The Two-factor Authentication & Password Solution. For general information on OnlyKey check out the Kickstarter page: [OnlyKey Kickstarter Page](http://www.crp.to/ok)

OnlyKey pre-orders are available here: [OnlyKey Pre-order](http://www.crp.to/po)
 
## Introduction ##
There are two available version of the OnlyKey firmware: 

**OnlyKey Firmware US** is the U.S. version of the OnlyKey firmware that comes pre-installed on the OnlyKey (U.S. Customers). 

**OnlyKey Firmware IN** is the International version of the OnlyKey firmware that comes pre-installed on the OnlyKey (International Customers). 

For more information on the difference between the two versions see the [OnlyKey FAQ](https://github.com/onlykey/OnlyKey-Firmware/wiki/FAQs).

In order to configure an OnlyKey that already has firmware loaded install the [OnlyKey Chrome App](https://github.com/onlykey/OnlyKey-Chrome-App).

## Installation ##
In order to install the latest version of the OnlyKey firmware:  
- Download the zip [here](https://github.com/onlykey/OnlyKey-Firmware-US/archive/master.zip) and save it to a convenient location on your PC.
- To load the US version you will use the OnlyKey_Alpha_US.cpp.hex firmware included in the zip file (OnlyKey-Firmware-master/OnlyKey_Beta_US/OnlyKey_Beta_US.cpp.hex).
- To load the International version you will use the OnlyKey_Alpha_IN.cpp.hex firmware included in the zip file (OnlyKey-Firmware-master/OnlyKey_Beta_IN/OnlyKey_Beta_IN.cpp.hex).
- Ensure that your copy of the firmware has not been tampered with by checking to see if the SHA256 hash of the downloaded file matches these:
- OnlyKey_Alpha_US.cpp.hex - f1390f31fe426efc8979d5b8c59391957582de94d81ff5abfaab89bdc3710103
- OnlyKey_Alpha_IN.cpp.hex - 54746d8c26a3e87e16139aed2889905f3f4b7269d866e2fefd79c2bb02ee12e5
- (To do this in Windows open a command prompt and type certUtil -hashfile pathToFileToCheck SHA256)
- Load the firmware that you downloaded (OnlyKey_XXXXXXX.hex) using the instructional video here [![Load Firmware using Teensy Loader](http://img.youtube.com/vi/qJUjz0gFhqg/0.jpg)](http://www.youtube.com/watch?v=qJUjz0gFhqg)

## Development ##
OnlyKey is currently released as a fully functional Beta. Development will be ongoing as additional features are added. To see a list of current and future features see [OnlyKey Features] (https://github.com/onlykey/OnlyKey-Firmware/wiki/OnlyKey-Features).

## Support ##

Check out the [OnlyKey Support Forum](https://groups.google.com/forum/#!forum/onlykey).

Check out the [OnlyKey Wiki](https://github.com/onlykey/OnlyKey-Firmware/wiki/Table-of-Contents)

## Libraries ##

Check out the [OnlyKey Libraries Here](https://github.com/onlykey/libraries).

A special thanks to those who made this project possible:

PJRC - https://www.pjrc.com/teensy/td_libs.html

Arduino - http://playground.arduino.cc/Main/LibraryList

Yubico - https://github.com/Yubico/

pagong/arduino-yksim - https://github.com/pagong/arduino-yksim 

lucadentella/ArduinoLib_TOTP - https://github.com/lucadentella/ArduinoLib_TOTP

damico/ARDUINO-OATH-TOKEN - https://github.com/damico/ARDUINO-OATH-TOKEN

Cathedrow/Cryptosuite - https://github.com/Cathedrow/Cryptosuite 

Frank Boesing - https://github.com/FrankBoesing/Arduino-Teensy3-Flash 

Yohanes - https://github.com/yohanes/teensy-u2f 

Ken MacKay - https://github.com/kmackay/micro-ecc

Rhys Weatherley - https://github.com/rweather/arduinolibs

Defragster - https://forum.pjrc.com/threads/91-teensy-3-MAC-address/page2


