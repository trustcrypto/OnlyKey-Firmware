# OnlyKey-Firmware-US

This is the official firmware for **OnlyKey** - The Two-factor Authentication & Password Solution. For general information on OnlyKey check out the Kickstarter page: [OnlyKey Kickstarter Page](http://www.crp.to/ok)

OnlyKey pre-orders are available here: [OnlyKey Pre-order](http://www.crp.to/po)
 
## Introduction ##
**OnlyKey Firmware US** is the U.S. version of the OnlyKey firmware that comes pre-installed on the OnlyKey (U.S. Customers). In order to configure an OnlyKey that already has firmware loaded install the [OnlyKey Chrome App](https://github.com/onlykey/OnlyKey-Chrome-App).

## Installation ##
In order to install the latest version of the OnlyKey firmware:  
- Click here to download the latest version of the OnlyKey firmware and save it to a convenient location on your PC.
- Ensure that your copy of the firmware has not been tampered with by checking the digital signature
- Load the firmware that you downloaded (OnlyKeyUS_vX_X.hex) using the instructional video here [![Load Firmware using Teensy Loader](http://img.youtube.com/vi/qJUjz0gFhqg/0.jpg)](http://www.youtube.com/watch?v=qJUjz0gFhqg)

## Development ##
OnlyKey is currently in development **WARNING** The OnlyKey firmware alpha is available for testing purposes only and is not to be used to store any sensitive information. The following items are in progress:
- U2F Certificate set/wipe - Receive U2F cerificate from chrome app and store to flash/ erase from flash (untested)
- Self Destruct PIN feature
- Plausible Deniability PIN feature
- Selectable self destruct wipe mode
- U2F key generation
- U2F - Investigate using deterministic signing - https://github.com/kmackay/micro-ecc/issues/37
- U2F - Remove placeholder handlekey, generate from nonce.
- U2F - Key wrapping (using RNG, hmac) follow Yubikey architecture - https://www.yubico.com/2014/11/yubicos-u2f-key-wrapping/
- Flash Security - Currently Mass Erase is enabled. Need to identify the correct flash security settings that do not brick MK20.
- Ensure YubiKey, U2F, seeds from RNG
- Ensure all license files are properly posted
- Breaking okcore to multiple appropriately named libraries
- General code cleanup
- Remove debugging
- Consider using different SHA256 library. Currently using library from Brad Conte, considering using  Southern Storm Software

## Testing ##
The current publicly available test case document is [here] (https://docs.google.com/spreadsheets/d/1SEByiDpYqyAhNw-Xv2Eix7-MW8PP0Hj5bA2UC55slaI/edit)

To suggest additional test cases or to report your findings email k@crp.to



