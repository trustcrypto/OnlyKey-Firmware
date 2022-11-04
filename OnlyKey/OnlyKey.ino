/* 
 * Copyright (c) 2015-2022, CryptoTrust LLC.
 * All rights reserved.
 * 
 * Author : Tim Steiner <t@crp.to>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by CryptoTrust LLC. for
 *    the OnlyKey Project (https://crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "CryptoTrust" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    admin@crp.to.
 *
 * 5. Products derived from this software may not be called "OnlyKey"
 *    nor may "OnlyKey" or "CryptoTrust" appear in their names without
 *    specific prior written permission. For written permission, please
 *    contact admin@crp.to.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by CryptoTrust LLC. for
 *    the OnlyKey Project (https://crp.to/ok)"
 *
 * 7. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for this software and any
 *    accompanying software that uses this software. The source code
 *    must either be included in the distribution or be available for
 *    no more than the cost of distribution plus a nominal fee, and must
 *    be freely redistributable under reasonable conditions. For a
 *    binary file, complete source code means the source code for all
 *    modules it contains.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS
 * ARE GRANTED BY THIS LICENSE. IF SOFTWARE RECIPIENT INSTITUTES PATENT
 * LITIGATION AGAINST ANY ENTITY (INCLUDING A CROSS-CLAIM OR COUNTERCLAIM
 * IN A LAWSUIT) ALLEGING THAT THIS SOFTWARE (INCLUDING COMBINATIONS OF THE
 * SOFTWARE WITH OTHER SOFTWARE OR HARDWARE) INFRINGES SUCH SOFTWARE
 * RECIPIENT'S PATENT(S), THEN SUCH SOFTWARE RECIPIENT'S RIGHTS GRANTED BY
 * THIS LICENSE SHALL TERMINATE AS OF THE DATE SUCH LITIGATION IS FILED. IF
 * ANY PROVISION OF THIS AGREEMENT IS INVALID OR UNENFORCEABLE UNDER
 * APPLICABLE LAW, IT SHALL NOT AFFECT THE VALIDITY OR ENFORCEABILITY OF THE
 * REMAINDER OF THE TERMS OF THIS AGREEMENT, AND WITHOUT FURTHER ACTION
 * BY THE PARTIES HERETO, SUCH PROVISION SHALL BE REFORMED TO THE MINIMUM
 * EXTENT NECESSARY TO MAKE SUCH PROVISION VALID AND ENFORCEABLE. ALL
 * SOFTWARE RECIPIENT'S RIGHTS UNDER THIS AGREEMENT SHALL TERMINATE IF IT
 * FAILS TO COMPLY WITH ANY OF THE MATERIAL TERMS OR CONDITIONS OF THIS
 * AGREEMENT AND DOES NOT CURE SUCH FAILURE IN A REASONABLE PERIOD OF
 * TIME AFTER BECOMING AWARE OF SUCH NONCOMPLIANCE. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR  PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,  EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*************************************/
//Firmware Build Options
/*************************************/
#define DEBUG //Enable Serial Monitor, debug firmware
#define STD_VERSION //Define for STD edition firmare, undefine for IN TRVL edition firmware
#define OK_Color //Define for hardware with color LED
//#define FACTORYKEYS2 // Attestation key and other keys encrypted using CHIP ID and RNG for unique per device
#ifndef STD_VERSION
#undef FACTORYKEYS2
#endif
/*************************************/
//Standard Libraries 
/*************************************/
#include "sha256.h"
#include "EEPROM.h"
#include "T3MacLib.h"
#include "SoftTimer.h"
#include "password.h"
#include "sha1.h"
#include "totp.h"
#include "Time.h"
#include "onlykey.h"
#include "flashkinetis.h"
#include "RNG.h"
#include "base64.h"
#include "ADC.h"
#include "usb_dev.h"
/*************************************/
//Color LED Libraries 
/*************************************/
#ifdef OK_Color
#include "Adafruit_NeoPixel.h"
#endif
/*************************************/
//Additional Libraries to Load for STD firmware version
//These libraries will only be used if STD_VERSION is defined
/*************************************/
extern uint8_t profilemode;
#ifdef STD_VERSION
#define OKSOLO //Using FIDO2 from SOLO
#include "yksim.h"
#include "uECC.h"
#include "ykcore.h"
#include "AES.h"
#include "GCM.h"
#include "rsa.h"
#include "tweetnacl.h"
/*************************************/
//FIDO2 Libraries
/*************************************/
#ifdef OKSOLO
#include "ctap.h"
#include "ctaphid.h"
#include "cbor.h"
#include "ctap_parse.h"
#include "ctap_errors.h"
#include "device.h"
#include "storage.h"
#include "wallet.h"
#include "solo.h"
#include "extensions.h"
#include "ok_extension.h"
#include "crypto.h"
#include "u2f.h"
#endif
#endif
/*************************************/
//LED Assignments
/*************************************/
extern uint8_t NEO_Color;
extern uint8_t NEO_Brightness[1];
extern uint8_t touchoffset;
extern uint8_t Profile_Offset;
/*************************************/
//RNG Assignments
/*************************************/
bool calibrating = false;
extern char ID[36];
/*************************************/
//PIN Assigment Variables
/*************************************/
extern uint8_t BLINKPIN;
extern uint8_t TOUCHPIN1;
extern uint8_t TOUCHPIN2;
extern uint8_t TOUCHPIN3;
extern uint8_t TOUCHPIN4;
extern uint8_t TOUCHPIN5;
extern uint8_t TOUCHPIN6;
extern uint8_t ANALOGPIN1;
extern uint8_t ANALOGPIN2;
extern unsigned int sumofall;
/*************************************/
//Keypad / Password Assignments
/*************************************/
extern int button_selected;    //Key selected 1-6
static int pass_keypress = 1;  //The number key presses in current password attempt
static int session_attempts = 0; //The number of password attempts this session
static bool firsttime = true;
extern Password password;
extern uint8_t TIMEOUT[1];
extern uint8_t TYPESPEED[1];
extern uint8_t KeyboardLayout[1];
extern uint8_t mod_keys_enabled;
/*************************************/
//Capacitive Touch Variables
/*************************************/
extern unsigned int touchread1;
extern unsigned int touchread2;
extern unsigned int touchread3;
extern unsigned int touchread4;
extern unsigned int touchread5;
extern unsigned int touchread6;
extern unsigned int touchread1ref;
extern unsigned int touchread2ref;
extern unsigned int touchread3ref;
extern unsigned int touchread4ref;
extern unsigned int touchread5ref;
extern unsigned int touchread6ref;
/*************************************/
//Keys, Hashes, Integrity Counters
/*************************************/
extern uint8_t profilekey[32];
extern uint8_t p1hash[32];
extern uint8_t sdhash[32];
extern uint8_t p2hash[32];
extern uint8_t nonce[32];
extern int initcheck;
extern int integrityctr1;
extern int integrityctr2;
/*************************************/
//SoftTimer Tasks
/*************************************/
#define TIME_POLL 50 // poll "key" every 50 ms
Task taskKey(TIME_POLL, checkKey);
Task taskKB(50, sendKey); // Default send kb codes every 50 ms
Task taskInitialized(1000, sendInitialized);
/*************************************/
//CRYPTO
/*************************************/
extern uint8_t Challenge_button1;
extern uint8_t Challenge_button2;
extern uint8_t Challenge_button3;
extern uint8_t CRYPTO_AUTH;
extern int packet_buffer_offset;
extern uint8_t packet_buffer_details[5];
extern uint8_t outputmode;
extern uint8_t derived_key_challenge_mode;
extern uint8_t stored_key_challenge_mode;
/*************************************/
//Other
/*************************************/
extern uint8_t recv_buffer[64];
char keybuffer[EElen_url+EElen_addchar+EElen_delay+EElen_addchar+EElen_username+EElen_delay+EElen_addchar+EElen_password+EElen_addchar+EElen_2FAtype+64+EElen_addchar+EElen_addchar+10]; //Buffer to hold all keystrokes
char *pos;
extern uint8_t isfade;
#ifdef STD_VERSION
extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
#endif
extern uint8_t pending_operation;
uint8_t modkey;
extern uint8_t onlykeyhw;
extern uint8_t Duo_config[2];

extern "C" {
  int _getpid(){ return -1;}
  int _kill(int pid, int sig){ return -1; }
  int _write(){return -1;}
}

/*************************************/
//Arduino Setup
/*************************************/
void setup() {
  // Delay may be needed for serial debug
  // delay(3000);
  analogReadResolution(16);
  #ifdef DEBUG
  Serial.begin(9600);
  #endif
  #ifdef STD_VERSION
  profilemode = STDPROFILE1;
  #else
  profilemode = NONENCRYPTEDPROFILE; 
  #endif
  /*************************************/
  //PIN Assigments
  /*************************************/
  BLINKPIN=6;
  TOUCHPIN1=1; // #define CORE_PIN1_CONFIG  PORTB_PCR17
  TOUCHPIN2=22; //#define CORE_PIN22_CONFIG  PORTC_PCR1
  TOUCHPIN3=23; //#define CORE_PIN23_CONFIG  PORTC_PCR2 OnlyKey DUO Button #1
  TOUCHPIN4=17; //#define CORE_PIN17_CONFIG  PORTB_PCR1
  TOUCHPIN5=15; //#define CORE_PIN15_CONFIG  PORTC_PCR0 OnlyKey DUO Button #2
  TOUCHPIN6=16; //#define CORE_PIN16_CONFIG  PORTB_PCR0
  ANALOGPIN1=A0; //#define CORE_PIN14_CONFIG PORTD_PCR1
  ANALOGPIN2=A7; //#define CORE_PIN21_CONFIG PORTD_PCR6
  /*************************************/
  initcheck = okcore_flashget_noncehash ((uint8_t*)nonce, 32); //Check if first time use
  CHIP_ID(); // Get Unique chip ID from ROM
  unsigned int analog1 = analogRead(ANALOGPIN1);
  unsigned int analog2 = analogRead(ANALOGPIN2);
  integrityctr1++;
  /* 
  //dump flash storage, useful for verifying contents
  Serial.println(initcheck);
  char temp[32];
  wipeEEPROM();
  unsigned long readadr = flashstorestart;
  while (readadr <= flashend) {
    for(int i =0; i<=2048; i=i+4){
      sprintf (temp, "%.8X", *((unsigned int*)readadr));
      Serial.print(temp);
      readadr = readadr + 4;
    }
    Serial.println();
  }
  */  
  //FSEC currently set to 0x44, everything disabled except mass erase https://forum.pjrc.com/threads/28783-Upload-Hex-file-from-Teensy-3-1
  if (FTFL_FSEC!=0x44) {
    // First time starting up, three steps to complete:
    // 1) Read factory loaded device keys and generate custom device keys
    // Get factory default flash contents
    #ifdef FACTORYKEYS2
    okcore_flashget_common(ctap_buffer, (unsigned long *)factorysectoradr, 1025);
    #ifdef DEBUG
    Serial.println("Factory Key Values");
    byteprint(ctap_buffer, 1025);
    #endif
    if (ctap_buffer[480] != 0xFF) { // Attestation key loaded
      // Hash factory bytes with unique chip ID and random 
      SHA256_CTX hash;
      for (int i=0; i<=14; i++) {
        analog1 = analogRead(ANALOGPIN1);
        analog2 = analogRead(ANALOGPIN1);
        sha256_init(&hash);
        sha256_update(&hash, ctap_buffer+(32*i), 32);
        sha256_update(&hash, ctap_buffer+(32*(i+1)), 32);
        sha256_update(&hash, (uint8_t*)ID, 36);
        sha256_update(&hash, (uint8_t*)&analog1, 4);
        sha256_update(&hash, (uint8_t*)&analog2, 4);
        sha256_final(&hash, ctap_buffer+(32*i));
      }
      #ifdef DEBUG
      Serial.println("KDF Hashed Factory Values");
      byteprint(ctap_buffer, 512);
      #endif
      // Write everything to flash
      if (*certified_hw != 1) {
        // Encrypt attestation key with generated KEK
        ctap_buffer[435]=3;
        //Write keys
        okcore_flashset_common(ctap_buffer, (unsigned long *)enckeysectoradr, 436); 
        okcrypto_aes_gcm_encrypt2(ctap_buffer+480, ctap_buffer+436, ctap_buffer+448, 32, true);
        //Write encrypted contents to flash
        okcore_flashset_common(ctap_buffer, (unsigned long *)enckeysectoradr, 513); 
        // Set write flag 
        ctap_buffer[435]=1;
        // Write flag to flash
        okcore_flashset_common(ctap_buffer, (unsigned long *)enckeysectoradr, 513); 
      }
      // Erase factory keys
      memset(ctap_buffer, 0, 2048);
      okcore_flashset_common(ctap_buffer, (unsigned long *)factorysectoradr, 512); 
    } 
    #endif // end FACTORYKEYS
    // 2) Store factory firmware hash for integrity verification
    //create hash of firmware in hash buffer
    #ifdef STD_VERSION
    fw_hash(ctap_buffer); 
    for (int i = 0; i < crypto_hash_BYTES; i++) { //write 64byte hash to eeprom
      eeprom_write_byte((unsigned char*)(2+i), ctap_buffer[i]); // 2-65 used for fw integrity hash
    }
    memset(ctap_buffer, 0, 2048);
    #endif
    // 3) Enable flash security after writing
    int nn = 0;
    nn=flashSecurityLockBits();
    #ifdef DEBUG
    Serial.print("Flash security bits ");
    if(nn) Serial.print("not ");
    Serial.println("written successfully");
    #endif
  }
  if(!initcheck) {
      wipeEEPROM();
      eeprom_write_byte((unsigned char *)1984, (OKversionmaj[0] - '0')); //write fwvermaj, prevents downgrade to previous majver
      okeeprom_eeset_timeout((uint8_t*)TIMEOUT); //Default lockout 30 min
      unlocked = true; //Flash is not protected, First time use
      initialized = false;
      #ifdef DEBUG
      Serial.println("UNLOCKED, NO PIN SET");
      #endif
  } else if(FTFL_FSEC==0x44 && initcheck) {
        okcore_flashget_pinhashpublic ((uint8_t*)p1hash, 32); //store PIN hash
        okcore_flashget_selfdestructhash ((uint8_t*)sdhash); //store self destruct PIN hash
        okcore_flashget_2ndpinhashpublic ((uint8_t*)p2hash); //store plausible deniability PIN hash
        okeeprom_eeget_typespeed((uint8_t*)TYPESPEED, 0);
        okeeprom_eeget_modkey(&mod_keys_enabled);
        #ifdef DEBUG
        Serial.println("typespeed = ");
        Serial.println(TYPESPEED[0]);
        #endif
        if (TYPESPEED[0] == 0) {
          TYPESPEED[0] = 4;
         } else if (TYPESPEED[0] <= 10) {
         }
        okeeprom_eeget_ledbrightness((uint8_t*)NEO_Brightness);
        okeeprom_eeget_touchoffset(&touchoffset);
        okeeprom_eeget_timeout((uint8_t*)TIMEOUT);
        okeeprom_eeget_keyboardlayout((uint8_t*)KeyboardLayout);
        #ifdef DEBUG
        Serial.println("KeyboardLayout = ");
        Serial.println(KeyboardLayout[0]);
        #endif
        update_keyboard_layout();
        unlocked = false;
        initialized = true;
        #ifdef DEBUG
        Serial.println("INITIALIZED");
        #endif
        SoftTimer.add(&taskInitialized);
  } else { //Glitch detect, somehow device is initialized but flash security is not on
    CPU_RESTART();
  }
  integrityctr2++;
  /*************************************/
  //Initialize the random number generator with analog noise, stored NONCE, and chip ID
  /*************************************/
  RNG.begin(OKversion, 2045); //Start RNG with the device version
  RNG.stir((uint8_t *)&analog1, 2, 4);
  RNG.stir((uint8_t *)&analog2, 2, 4);
  #ifdef DEBUG
  Serial.print("EEPROM Used ");
  Serial.println(EEpos_slottypespeed+12);
  Serial.println(FTFL_FSEC, HEX);
  #endif
  rngloop(); //Start RNG
  #ifdef OK_Color
  initColor();
  rainbowCycle();
  #else
  pinMode(BLINKPIN, OUTPUT);
  fadein();//Additional delay to make sure button is not pressed during plug into USB
  fadeout();
  fadein();
  fadeout();
  #endif
  SoftTimer.add(&taskKey);

   if (!initcheck) {
    //Default set to no challenge code required for OnlyKey Agent
    //User can enable challenge code in OnlyKey app preferences
    derived_key_challenge_mode = 1;
    stored_key_challenge_mode = 1;
    okeeprom_eeset_derived_key_challenge_mode(&derived_key_challenge_mode); 
    okeeprom_eeset_stored_key_challenge_mode(&stored_key_challenge_mode);
  } 
  
  if (onlykeyhw==OK_HW_DUO) {
      if (initialized == true && password.profile1hashevaluate()) {
          payload(10); 
      }
  }
}

extern elapsedMillis idletimer;

/*************************************/
//Main Loop, Read Key Press Using Capacitive Touch
//Called every 50ms
/*************************************/
void checkKey(Task* me) {
  
  //Check for bootloader trigger
  if (!digitalRead(33)) { //Trigger bootloader to load firmware by PTA4 low for 3 sec
    elapsedMillis waiting;
    int jumptobootloader = 0;
    while (waiting < 3000) {
    delay(100);
    jumptobootloader = jumptobootloader + digitalRead(33);
    }
    if (jumptobootloader==0) {
    eeprom_write_byte(0x00, 1); //Go to bootloader
    eeprom_write_byte((unsigned char *)0x01, 1); //Firmware ready to load
    CPU_RESTART(); //Reboot
    }
  }

  #ifndef STD_VERSION
  // Disable OK_HW_DUO hardware for IN_TRVL firmware
  if (onlykeyhw==OK_HW_DUO) {
    eeprom_write_byte(0x00, 1); //Go to bootloader
    eeprom_write_byte((unsigned char *)0x01, 1); //Firmware ready to load
    CPU_RESTART(); //Reboot
  }
  #endif

  if (setBuffer[8] == 1 && (!isfade || configmode)) //Done receiving packets
  {                 
    if (outputmode != KEYBOARD_USB) changeoutputmode(KEYBOARD_USB); //Keyboard USB
    process_setreport();
  }
  //Check integrity counters and recv usb data
  integrityctr1++;
  delay(sumofall % 6); //delay 0 - 5 ms
  if (unlocked) {
    integrityctr2++;
    recvmsg(0);
    if(initialized && initcheck) {
    #ifdef STD_VERSION
    yubikey_incr_time();
    #endif
    if (TIMEOUT[0] && idletimer >= (TIMEOUT[0]*60000)) {
      unlocked = false;
      firsttime = true;
      password.reset(); //reset the guessed password to NULL
      pass_keypress=1;
      memset(profilekey, 0, 32);  
      SoftTimer.add(&taskInitialized);
      CPU_RESTART();
    }
    }
  } else{
    integrityctr2++;
  }

  if(configmode && unlocked && !isfade) {
    #ifdef OK_Color
    NEO_Color = 1; //Red
    #endif
    fadeon(1);
  }

  #ifdef DEBUG
  // Auto set default PINs and passphrase for testing
  //if (!initialized) {
  // okeeprom_eeset_timeout(0); //Disable lockout
  //  okcore_quick_setup(AUTO_PIN_SET);  
  //}
  #endif
  

  int press_duration = touch_sense_loop();
  if (pending_operation==0xF6 || pending_operation==0xF7) { //CTAP2_ERR_DATA_READY or CTAP2_ERR_DATA_WIPE
    setcolor(45); //yellow
  } else {
    if (press_duration) payload(press_duration);
  }

}
/*************************************/
//Type out on Keyboard the contents of Keybuffer
/*************************************/
void sendKey(Task* me) {
    while ( isfade && NEO_Color == 170 && (uint8_t)*pos != 00 && (uint8_t)*pos != 9 ) {
       pos++;
    }
    int delay1 = (TYPESPEED[0]*TYPESPEED[0]/3)*8;
    int delay2 = ((TYPESPEED[0]*TYPESPEED[0])*2);
    if ((uint8_t)*pos == 00) {
      #ifdef DEBUG
      Serial.print(pos);
      #endif
      Keyboard.end();
      SoftTimer.remove(&taskKB);
      SoftTimer.add(&taskKey);
      // Set back to default type speed
      okeeprom_eeget_typespeed((uint8_t*)TYPESPEED, 0);
      if (TYPESPEED[0]==0) TYPESPEED[0] = 4;
      return;
    }
    else if ((uint8_t)*pos == 1) {
        if (!isfade) {
          Keyboard.press(KEY_TAB);
          delay(delay1);
          Keyboard.releaseAll();
          delay(delay2);
        }
        pos++;
    }
    else if ((uint8_t)*pos == 2) {
        if (!isfade) {
          Keyboard.press(KEY_RETURN);
          delay(delay1);
          Keyboard.releaseAll();
          delay(delay2);
        }
        pos++;
    }
    else if ((uint8_t)*pos == 9) {
        if(profilemode==NONENCRYPTEDPROFILE) return;
        #ifdef STD_VERSION
        #ifdef DEBUG
        Serial.println("Starting U2F...");
        #endif
        u2f_button = 1;
        unsigned long u2fwait = millis() + 4000;
        while(u2f_button && millis() < u2fwait) {
        recvmsg(0);
        }
        u2f_button = 0;
        Keyboard.end();
        SoftTimer.remove(&taskKB);
        SoftTimer.add(&taskKey);
        #endif
        return;
    }
    else if ((uint8_t)*pos >= 10 && (uint8_t)*pos <= 31) {
        if (!isfade) {    
          delay((*pos - 10)*1000);
          pos++;       
        }       
    }
    else if ((uint8_t)*pos == ' ' && (uint8_t)*(pos+1) == 0x5c) {
        pos++; 
        if (!isfade) {
          while(*pos) {
            if ((uint8_t)*pos == 0x5c) { //modifier/special key comes next
              pos++;
              keymap_press(0);
              delay(delay1);
            } else { //regular key
              keymap_press(1);
              delay(delay1);
            }
            pos++;
            if ((uint8_t)*pos == ' ' || (uint8_t)*pos == 0) {
              if ((uint8_t)*pos == ' ') pos++;
              Keyboard.releaseAll();
              delay(delay1);  
              Keyboard.releaseAll();
              resetkeys();
              delay(delay2);
              return;
            } 
          }
        }   
    }
    else if (*pos){
        if (!isfade) {
          Keyboard.press(*pos);
          delay(delay1);
          Keyboard.releaseAll();
          delay(delay2);
        }
        pos++;
    }
}
/*************************************/
//Password Checking Loop
/*************************************/
void payload(int duration) {   
    if (!unlocked) {
      // OnlyKey Go has only 3 buttons, longer press to enter PIN of 4 - 6
      if (onlykeyhw==OK_HW_DUO && duration >= 21) { 
        // <1 sec OK_HW_DUO buttons 1,2,3 = 4,5,6
        button_selected = button_selected + 3;
      }
      #ifdef OK_Color
      setcolor(45); // NEO Pixel ON Yellow
      #else
      analogWrite(BLINKPIN, 255); //LED ON
      #endif
    }
    else {
      #ifdef OK_Color
      setcolor(0); // NEO Pixel OFF
      #else
      analogWrite(BLINKPIN, 0); //LED OFF
      #endif
    }
    uint8_t pass_attempts[1];
    uint8_t sincelastregularlogin[1];
    if (session_attempts >= 3) { //Limit 3 password attempts per session to make sure that someone does not accidentally wipe device
      exceeded_login_attempts();
    return;
    }
    integrityctr1++;
    if (firsttime) //Get failed login counter from eeprom and increment for new login attempt
    {
      okeeprom_eeget_failedlogins ((uint8_t*)pass_attempts);
      if (pass_attempts[0]) {
        okeeprom_eeget_sincelastregularlogin ((uint8_t*)sincelastregularlogin);
        if (sincelastregularlogin[0] >= 20) {
          for (int i =0; i<32; i++) {
            p1hash[i] = 0xFF;
          }
          okcore_flashset_pinhashpublic ((uint8_t*)p1hash); //permanently wipe pinhash
          okeeprom_eeset_sincelastregularlogin (0);
       } else {
        sincelastregularlogin[0]++;
        okeeprom_eeset_sincelastregularlogin ((uint8_t*)sincelastregularlogin);
       }
       #ifdef DEBUG
       Serial.println("Failed PIN attempts since last successful regular PIN entry");
       Serial.println(sincelastregularlogin[0]);
       #endif
     }
     integrityctr2++;
     pass_attempts[0]++;
     integrityctr1++;
     if (pass_attempts[0] > 10) {
        #ifdef DEBUG
        Serial.println("Password attempts exhausted");
        Serial.println(pass_attempts[0]);
        #endif
        factorydefault();
        pass_attempts[0] = 0;
        return;
     }
     okeeprom_eeset_failedlogins ((uint8_t*)pass_attempts);
     firsttime = false;
   }
   integrityctr2++;
   password.append(button_selected);
   integrityctr1++;
   delay((sumofall % 4)+(sumofall % 3)); //delay 0 - 5 ms
   if (unlocked || password.profile1hashevaluate() || password.profile2hashevaluate()) {
    integrityctr2++;
    if (unlocked != true) { //A correct PIN was just entered do the following for first login
      okeeprom_eeset_failedlogins(0); //Set failed login counter to 0
      password.reset(); //reset the guessed password to NULL
      session_attempts=0;
      if (!configmode) hidprint(HW_MODEL(UNLOCKED));
      SoftTimer.remove(&taskInitialized);
      #ifdef DEBUG
      Serial.println("UNLOCKED"); 
      #endif      
      fadeon(NEO_Color);
      fadeoff(85);  
      if (profilemode!=NONENCRYPTEDPROFILE) {
        #ifdef STD_VERSION
        U2Finit();
        okeeprom_eeset_sincelastregularlogin(0); //Set failed logins since last regular login to 0
        fw_version_changes();
        #endif
      }
      idletimer=0;
      unlocked = true;
      if (configmode) {
        #ifdef OK_Color
        NEO_Color = 1; //Red
        #endif
        fadeon(1);
      }

      unsigned long wait = millis() + 200;
      while(millis() < wait) { //Process waiting messages
          recvmsg(0);
      }
      
      wipe_usb_buffer(); // Wipe old responses
      return;
    } else if (!initialized && duration >= 85 && button_selected=='1' && profilemode!=NONENCRYPTEDPROFILE) {
      if (onlykeyhw==OK_HW_DUO) okcore_quick_setup(KEYBOARD_ONLYKEY_DUO_NO_BACKUP);
      else okcore_quick_setup(KEYBOARD_MANUAL_PIN_SET);
      return;
    } else if (!initialized && duration >= 85 && button_selected=='2' && profilemode!=NONENCRYPTEDPROFILE) {
      if (onlykeyhw==OK_HW_DUO) okcore_quick_setup(KEYBOARD_ONLYKEY_DUO_BACKUP);
      else okcore_quick_setup(KEYBOARD_AUTO_PIN_SET);
      return;
    } else if (!initialized && duration >= 85 && button_selected=='3' && profilemode!=NONENCRYPTEDPROFILE) {
      okcore_quick_setup(0); //Setup with keyboard prompt
      return;
    } else if (pin_set==0 && !initcheck) {
      return;
    }
    else if (pin_set==0) {
    }
    else if (pin_set<=3) { 
      #ifdef DEBUG
      Serial.print("password appended with ");
      Serial.println(button_selected-'0');
      #endif
      if (configmode) {
        NEO_Color = 45;
        blink(1);
        NEO_Color = 1;
      }
      return;
    }
    else if (pin_set<=6) {
        #ifdef DEBUG
        Serial.print("SD password appended with ");
        Serial.println(button_selected-'0');
        #endif
        if (configmode) {
          NEO_Color = 45;
          blink(1);
          NEO_Color = 1;
        }
        return;
    }
    else if (pin_set<=9) {
        if(profilemode!=NONENCRYPTEDPROFILE){
        #ifdef STD_VERSION
        #ifdef DEBUG
        Serial.print("2nd profile password appended with ");
        Serial.println(button_selected-'0');
        #endif
        #endif
        }
        if (configmode) {
          NEO_Color = 45;
          blink(1);
          NEO_Color = 1;
        }
        return;
    } else if (pin_set==10) {
        cancelfadeoffafter20();
        if (button_selected=='1') okcore_quick_setup(KEYBOARD_MANUAL_PIN_SET); //Manual
        else okcore_quick_setup(KEYBOARD_AUTO_PIN_SET); //Manual
        return;
    }
    Keyboard.begin();
    *keybuffer = '\0';
    #ifdef DEBUG
    Serial.print("Button selected ");
    Serial.println(button_selected-'0');
    #endif
    idletimer=0;
    if (profilemode!=NONENCRYPTEDPROFILE) {
      #ifdef STD_VERSION
      if (CRYPTO_AUTH == 1 && button_selected==Challenge_button1 && isfade) {
          #ifdef DEBUG
          Serial.print("Challenge1 entered");
          Serial.println(button_selected-'0');
          #endif
          CRYPTO_AUTH++;
          return;
      } else if (CRYPTO_AUTH == 2 && button_selected==Challenge_button2 && isfade) {
        #ifdef DEBUG
        Serial.print("Challenge2 entered");
        Serial.println(button_selected-'0');
        #endif
        CRYPTO_AUTH++;
        return;
      } else if ((CRYPTO_AUTH == 3 && button_selected==Challenge_button3 && isfade && packet_buffer_details[0]) || (derived_key_challenge_mode==1 && isfade && packet_buffer_details[0]) || (stored_key_challenge_mode==1 && isfade && packet_buffer_details[0]) || (CRYPTO_AUTH == 3 && packet_buffer_details[0] == OKHMAC && isfade) || (packet_buffer_details[0] == OKWEBAUTHN && isfade)) {
        #ifdef DEBUG
        Serial.print("Challenge3 entered");
        Serial.println(button_selected-'0');
        #endif
        CRYPTO_AUTH = 4;
        derived_key_challenge_mode = 0;
        stored_key_challenge_mode = 0;
        if(packet_buffer_details[0] == OKSIGN) {
          recv_buffer[4] = packet_buffer_details[0];
          recv_buffer[5] = packet_buffer_details[1];
          okcrypto_sign(recv_buffer);
        } else if (packet_buffer_details[0] == OKDECRYPT) {
          recv_buffer[4] = packet_buffer_details[0];
          recv_buffer[5] = packet_buffer_details[1];
          okcrypto_decrypt(recv_buffer);
        } else if (packet_buffer_details[0] == OKHMAC) {
          okcrypto_hmacsha1();
        } else if (packet_buffer_details[0] == OKWEBAUTHN) {
          u2f_button = 1;
          unsigned long u2fwait = millis() + 4000;
          while(u2f_button && millis() < u2fwait) {
          recvmsg(0);
          }
          u2f_button = 0;
        }
          CRYPTO_AUTH = 0;
          packet_buffer_details[0]=0;
          fadeoff(0);
          return;
        } else if (CRYPTO_AUTH) { //Wrong challenge was entered
            CRYPTO_AUTH = 0;
            Challenge_button1 = 0;
            Challenge_button2 = 0;
            Challenge_button3 = 0;
            fadeoff(1);
            hidprint("Error incorrect challenge was entered");
            analogWrite(BLINKPIN, 255); //LED ON
            return;
        } else if (duration < 180 && duration >= 72 && button_selected=='1' && !isfade) {
            // Backup <4 sec 
            SoftTimer.remove(&taskKey);
            backup();
            SoftTimer.add(&taskKey);
            return;
        } else if (onlykeyhw==OK_HW_DUO && duration >= 360 && button_selected=='2' && configmode==true) {
          factorydefault();
        } else if (duration >= 72 && button_selected=='2' && !isfade) {
            // Slot Labels <4 sec 
            get_slot_labels(1);
            if (duration >= 140) get_key_labels(1);
            return;
        } else if (duration >= 72 && button_selected=='3' && !isfade) {
            // Lock and/or switch profiles <4 sec
            if (onlykeyhw==OK_HW_DUO && duration < 180) {
              if (Duo_config[1] == 0){ // Profile 1
                Profile_Offset = 84; //Profile 2 Blue
                Duo_config[1] = 1;
              } else if (Duo_config[1] == 1){ // Profile 2 
                Profile_Offset = -42; //Profile 3 Yellow
                Duo_config[1] = 2;
              } else if (Duo_config[1] == 2){ // Profile 3
                Profile_Offset = 128; //Profile 4 Purple
                Duo_config[1] = 3;
              } else if (Duo_config[1] == 3){ // Profile 4
                Profile_Offset = 0; //Profile 1 Green
                Duo_config[1] = 0;
              }
              return;
            }
            unlocked = false;
            firsttime = true;
            password.reset(); //reset the guessed password to NULL
            pass_keypress=1;
            memset(profilekey, 0, 32);        
            SoftTimer.add(&taskInitialized);
            button_selected=0;
            CPU_RESTART(); 
            return;
        } 
        else if (((onlykeyhw==OK_HW_DUO && duration >= 180 && button_selected=='1') || (onlykeyhw!=OK_HW_DUO && duration >= 72 && button_selected=='6')) && !isfade) {
          // Config mode 
          integrityctr1++;
          configmode=true;
          if (Duo_config[0]!=1) {
            unlocked = false;
            firsttime = true;
            password.reset(); //reset the guessed password to NULL
            pass_keypress=1;
            SoftTimer.add(&taskInitialized);
          }
          integrityctr2++;
          return;
        }
      #endif
     }
    #ifdef OK_Color
    setcolor(0); // NEO Pixel OFF
    #else
    analogWrite(BLINKPIN, 0); //LED OFF
    #endif
      
    if (duration <= 20 && !configmode) {
      gen_press();
    }
    else if (duration >= 21 && duration < 90 && !configmode) {
      gen_hold();
    }
    else if (duration >= 90 && !configmode) {
      NEO_Color = 1;
      blink(2);
    }
    pos = keybuffer;
    SoftTimer.remove(&taskKey);
    SoftTimer.add(&taskKB, (unsigned long)TYPESPEED[0]);
    return;
  }
  else if (password.sdhashevaluate()) {
    #ifdef DEBUG
    Serial.println("Self Destruct PIN entered");
    #endif
    factorydefault();
  }
  else {
    integrityctr2++;
    if (pass_keypress < 10) {
      #ifdef DEBUG
      Serial.print("password appended with ");
      Serial.println(button_selected-'0');
      Serial.print("Number of keys entered for this passcode = ");
      Serial.println(pass_keypress);
      #endif
      pass_keypress++;
      return;
    } else {
      firsttime = true;
      session_attempts++;
      #ifdef OK_Color
      NEO_Color = 1;
      #endif
      blink(3);
      #ifdef DEBUG
      Serial.print("Login Failed, there are ");
      #endif
      okeeprom_eeget_failedlogins ((uint8_t*)pass_attempts);
      #ifdef DEBUG
      Serial.print(10 - pass_attempts[0]);
      Serial.println(" remaining attempts before a factory reset will occur");
      Serial.println("WARNING: This will render all device information unrecoverable");
      #endif
      password.reset(); //reset the guessed password to NULL
      pass_keypress=1;
      if (session_attempts >= 3) { //Limit 3 password attempts per session to make sure that someone does not accidentally wipe device
        exceeded_login_attempts();
      }
      return;
    }
 }
}
/*************************************/
//Trigger on short button press
/*************************************/
void gen_press(void) {
  int slot;

  if (profilemode || Duo_config[1] == 2) {
    slot=(button_selected-'0')+12;
  } else if (Duo_config[1] == 1) {
    slot=(button_selected-'0')+6;
  } else if (Duo_config[1] == 3) {
    slot=(button_selected-'0')+18;
  } else {
    slot=button_selected-'0';
  }
      process_slot(slot);
}
/*************************************/
//Trigger on long button press
/*************************************/
void gen_hold(void) {
  int slot;
  if (profilemode || Duo_config[1] == 2) {
    slot=(button_selected-'0')+12;
  } else if (Duo_config[1] == 1) {
    slot=(button_selected-'0')+6;
  } else if (Duo_config[1] == 3) {
    slot=(button_selected-'0')+18;
  } else {
    slot=button_selected-'0';
  }

  if (onlykeyhw==OK_HW_DUO){
    process_slot(slot+3);
  } else {
    process_slot(slot+6);
  }
      
}
/*************************************/
//Load Set Values to Keybuffer
/*************************************/
void process_slot(int s) {
      long GMT;
      char* newcode;
      static uint8_t index;
      uint8_t temp[64];
      int urllength;
      int usernamelength;
      int passwordlength;
      int otplength;
      uint8_t addchar1;
      uint8_t addchar2;
      uint8_t addchar3;
      uint8_t addchar4;
      uint8_t addchar5;
      uint8_t addchar6;
      uint8_t autolockslot;
      int delay1 = 0;
      int delay2 = 0;
      int delay3 = 0;
      uint8_t *ptr;
      int slot=s;
      bool scripted_mode = false;
      index = 0;
      
      okeeprom_eeget_autolockslot(&autolockslot);
      if ((profilemode==STDPROFILE1 && (slot==(autolockslot & 0xF))) || (profilemode==STDPROFILE2 && slot==((autolockslot >> 4) & 0xF)+12)) {
        lock_ok_and_screen ();
        return;
      }
      okeeprom_eeget_typespeed((uint8_t*)TYPESPEED, slot);
      if (TYPESPEED[0]==0) okeeprom_eeget_typespeed((uint8_t*)TYPESPEED, 0);
      if (TYPESPEED[0]==0) TYPESPEED[0] = 4;
      
      okeeprom_eeget_addchar(&addchar5, slot);
      #ifdef DEBUG
      Serial.println("Additional Character");
      Serial.println(addchar5); 
      #endif
      addchar1 = addchar5 & 0x3; //After Username
      addchar2 = (addchar5 >> 4) & 0x3; //After Password
      addchar3 = (addchar5 >> 6) & 0x1; //After OTP
      addchar6 = (addchar5 >> 7) & 0x1; //After OTP 2
      addchar4 = (addchar5 >> 2) & 0x1; //Before Username
      addchar5 = (addchar5 >> 3) & 0x1; //Before OTP
      
      if (isfade) return; 
      #ifdef DEBUG
      Serial.print("Slot Number ");
      Serial.println(button_selected-'0');
      #endif
      memset(temp, 0, 64); //Wipe all data from buffer
      memset(keybuffer, 0, sizeof(keybuffer)); //Wipe all data from keybuffer
      ptr = temp;
      urllength = okcore_flashget_url(ptr, slot);
      if(urllength > 0)
      {
        #ifdef DEBUG
        Serial.println("Reading URL from Flash...");
        Serial.print("URL Length = ");
        Serial.println(urllength);
        #endif
        #ifdef DEBUG
        Serial.println("Encrypted");
        byteprint(temp, urllength);
        #endif
        okcore_aes_gcm_decrypt(temp, slot, 15, profilekey, urllength);
        if (temp[0]==0x08) { // Scripted Mode
          scripted_mode=true;
          ByteToChar2(temp+1, keybuffer, urllength-1, index);
          index=urllength-1;
        } else {
          ByteToChar2(temp, keybuffer, urllength, index);
          index=urllength;
          keybuffer[index] = 2;
          index++;
          #ifdef DEBUG
          Serial.println("Unencrypted");
          byteprint(temp, urllength);
          Serial.println("Setting RETURN after URL");
          #endif
        }
      }
      memset(temp, 0, 64); //Wipe all data from buffer
      okeeprom_eeget_delay1(ptr, slot);
      if(temp[0] > 0 && !scripted_mode)
      {
        #ifdef DEBUG
        Serial.println("Reading Delay1 from EEPROM...");
        Serial.print("Delay ");
        Serial.print(temp[0]);
        Serial.println(" Seconds before entering username");
        #endif
        if (temp[0] <= 30)
        {
        delay1=temp[0];
        keybuffer[index] = temp[0] + 10;
        index++;
        }
      }
      if(addchar4 && !scripted_mode)
      {
        #ifdef DEBUG
        Serial.println("Reading before Username addchar...");
        #endif
        keybuffer[index] = 1;
        #ifdef DEBUG
        Serial.println("TAB");
        #endif
        index++;
      }
      usernamelength = okcore_flashget_username(ptr, slot);
      if(usernamelength > 0)
      {
        #ifdef DEBUG
        Serial.println("Reading Username from Flash...");
        Serial.print("Username Length = ");
        Serial.println(usernamelength);
        byteprint(temp, usernamelength);
        #endif
        okcore_aes_gcm_decrypt(temp, slot, 2, profilekey, usernamelength);
        
        ByteToChar2(temp, keybuffer, usernamelength, index);
        #ifdef DEBUG
        byteprint(temp, usernamelength);
        #endif
        index=usernamelength+index;
      }
      memset(temp, 0, 64); //Wipe all data from buffer
      if(addchar1 && !scripted_mode)
      {
        if(addchar1 == 1) {
        #ifdef DEBUG
        Serial.println("Reading after username addchar...");
        #endif
        keybuffer[index] = 1;
        #ifdef DEBUG
        Serial.println("TAB");
        #endif
        index++;
        }
        else if(addchar1 == 2) {
        #ifdef DEBUG
        Serial.println("Reading after username addchar...");
        #endif
        keybuffer[index] = 2;
        #ifdef DEBUG
        Serial.println("RETURN");
        #endif
        index++;
        }
      }
      memset(temp, 0, 64); //Wipe all data from buffer
      okeeprom_eeget_delay2(ptr, slot);
      if(temp[0] > 0 && !scripted_mode)
      {
        #ifdef DEBUG
        Serial.println("Reading Delay2 from EEPROM...");
        Serial.print("Delay ");
        Serial.print(temp[0]);
        Serial.println(" Seconds before entering password");
        #endif
        if (temp[0] <= 30)
        {
        delay2=temp[0];
        keybuffer[index] = temp[0] + 10;
        index++;
        }
      }
      passwordlength = okeeprom_eeget_password(ptr, slot);
      if(passwordlength > 0)
      {
        #ifdef DEBUG
        Serial.println("Reading Password from EEPROM...");
        Serial.print("Password Length = ");
        Serial.println(passwordlength);
        Serial.println("Encrypted");
        byteprint(temp, passwordlength);
        #endif
        okcore_aes_gcm_decrypt(temp, slot, 5, profilekey, passwordlength);
        ByteToChar2(temp, keybuffer, passwordlength, index);
        #ifdef DEBUG
        Serial.println("Unencrypted");
        byteprint(temp, passwordlength);
        #endif
        index=passwordlength+index;
      }
      memset(temp, 0, 64); //Wipe all data from buffer
      if(addchar2 && !scripted_mode)
      {
        #ifdef DEBUG
        Serial.println("Reading after password addchar...");
        #endif
        if(addchar2 == 1) {
        keybuffer[index] = 1;
        #ifdef DEBUG
        Serial.println("TAB");
        #endif
        index++;
        }
        else if(addchar2 == 2) {
        keybuffer[index] = 2;
        #ifdef DEBUG
        Serial.println("RETURN");
        #endif
        index++;
        }
      }
      memset(temp, 0, 64); //Wipe all data from buffer
      okeeprom_eeget_delay3(ptr, slot);
      if(temp[0] > 0 && !scripted_mode)
      {
        #ifdef DEBUG
        Serial.println("Reading Delay3 from EEPROM...");
        Serial.print("Delay ");
        Serial.print(temp[0]);
        Serial.println(" Seconds before entering 2FA");
        #endif
        if (temp[0] <= 30)
        {
        delay3=temp[0];
        keybuffer[index] = temp[0] + 10;
        index++;
        }
      }
      memset(temp, 0, 64); //Wipe all data from buffer
      if(addchar5 && !scripted_mode)
      {
        #ifdef DEBUG
        Serial.println("Reading before OTP addchar...");
        #endif
        keybuffer[index] = 1;
        #ifdef DEBUG
        Serial.println("TAB");
        #endif
        index++;
      }
      otplength = okeeprom_eeget_2FAtype(ptr, slot);
      if(temp[0] > 0)
      {
        if(temp[0] == MFAGOOGLEAUTH) { //Google Auth
          #ifdef DEBUG
          Serial.println("Reading TOTP Key from Flash...");
          #endif
          otplength = okcore_flashget_2fa_key(ptr, slot);
        #ifdef DEBUG
        Serial.println("Encrypted");
        byteprint(temp, otplength);
        Serial.print("TOTP Key Length = ");
        Serial.println(otplength);
        #endif  
        okcore_aes_gcm_decrypt(temp, slot, 9, profilekey, otplength); 
        ByteToChar2(temp, keybuffer, otplength, index);
        #ifdef DEBUG
        Serial.println("Unencrypted");
        byteprint(temp, otplength);
        #endif
          TOTP totp1 = TOTP(temp, otplength);
          GMT = now();
          GMT = GMT + delay1 + delay2 + delay3;
          #ifdef DEBUG
          Serial.println(GMT);
          #endif
          newcode = totp1.getCode(GMT);
          if (timeStatus() == timeNotSet) {
            keybuffer[index]='N';
            keybuffer[index+1]='O';
            keybuffer[index+2]='T';
            keybuffer[index+3]='S';
            keybuffer[index+4]='E';
            keybuffer[index+5]='T';
          } else {
            keybuffer[index]=*newcode;
            keybuffer[index+1]=*(newcode+1);
            keybuffer[index+2]=*(newcode+2);
            keybuffer[index+3]=*(newcode+3);
            keybuffer[index+4]=*(newcode+4);
            keybuffer[index+5]=*(newcode+5);
          }
          index=index+6;
          memset(temp, 0, 64); //Wipe all data from buffer
        }
        if(temp[0] == MFAOLDYUBIOTP && profilemode!=NONENCRYPTEDPROFILE) {
          #ifdef DEBUG
          Serial.println("Generating Yubico OTP Legacy...");
          #endif
          #ifdef STD_VERSION
          yubikeysim(keybuffer + index, 0);
          index=index+44;
          #endif
        }
        if((temp[0] == MFAYUBIOTPandHMACSHA1 || temp[0] == MFAYUBIOTP) && profilemode!=NONENCRYPTEDPROFILE) {
          #ifdef DEBUG
          Serial.println("Generating Yubico OTP...");
          #endif
          #ifdef STD_VERSION
          int publen;
          publen = yubikeysim(keybuffer + index, slot);
          index=index+32+(publen*2);
          #endif
        }
        if(temp[0] == MFAOLDU2F && profilemode!=NONENCRYPTEDPROFILE) { //U2F
          keybuffer[index] = 9;
          index++;
        }
      }
      if(addchar6)
      {
        #ifdef DEBUG
        Serial.println("Reading after OTP addchar...");
        #endif
        keybuffer[index] = 1;
        #ifdef DEBUG
        Serial.println("TAB");
        #endif
        index++;
      }
      if(addchar3)
      {
        #ifdef DEBUG
        Serial.println("Reading after OTP addchar...");
        #endif
        keybuffer[index] = 2;
        #ifdef DEBUG
        Serial.println("RETURN");
        #endif
        index++;
      }
      keybuffer[index] = 0;
          #ifdef DEBUG
          Serial.println("Displaying Full Keybuffer");
          for (int i=0; keybuffer[i]!=0x00; i++) {
            Serial.print
            (keybuffer[i]);
          }
          #endif
}

void sendInitialized(Task* me) {
    if (onlykeyhw==OK_HW_DUO){
      int n = RawHID.recv(recv_buffer, 0); // 0 timeout = do not wait
      if (n && recv_buffer[4] == OKPIN && recv_buffer[5]>='0' && initialized == true && unlocked == false && onlykeyhw==OK_HW_DUO) {
        unlocked = false;
        firsttime = true;
        password.reset(); //reset the guessed password to NULL
        okcore_pin_login(); // Received PIN Login Attempt for OnlyKey Duo
        pass_keypress=10;
        button_selected=0;
        payload(10); // Try the PIN
        memset(recv_buffer, 0, sizeof(recv_buffer));
        if (unlocked == true) {
          hidprint(HW_MODEL(UNLOCKED));
        }
      } else {
        hidprint("INITIALIZED-D");
      }
    } else hidprint("INITIALIZED");
    #ifdef DEBUG
    Serial.println("INITIALIZED");
    #endif
}

void resetkeys () {
  delay(200);
  Keyboard.set_key1(0);
  Keyboard.set_key2(0);
  Keyboard.set_key3(0);
  Keyboard.set_key4(0);
  Keyboard.set_key5(0);
  Keyboard.set_key6(0);
  Keyboard.set_modifier(0);
  Keyboard.set_media(0);
  Keyboard.send_now();
}

void ctrl_alt_del () {
  //Keyboard.set_modifier(MODIFIERKEY_CTRL);  
 // Keyboard.send_now();
 // Keyboard.set_modifier(MODIFIERKEY_CTRL | MODIFIERKEY_ALT);  
  Keyboard.send_now();
 // Keyboard.set_key1(KEY_DELETE);  
  Keyboard.send_now();
  resetkeys();
 // Keyboard.set_key1(KEY_ESC);  
  Keyboard.send_now();
  resetkeys();
}

void lock_ok_and_screen () {
    unlocked = false;
    firsttime = true;
    password.reset(); //reset the guessed password to NULL
    pass_keypress=1;
    memset(profilekey, 0, 32);
    //Lock Windows and Linux (Gnome Super+L to lock)
    Keyboard.set_modifier(MODIFIERKEY_GUI);  
    Keyboard.send_now();
    Keyboard.set_key1(KEY_L);  
    Keyboard.send_now();
    resetkeys();
    //Lock Mac
    Keyboard.set_modifier(MODIFIERKEY_CTRL);  
    Keyboard.send_now();
    Keyboard.set_modifier(MODIFIERKEY_CTRL | MODIFIERKEY_GUI); 
    Keyboard.send_now();
    Keyboard.set_key1(KEY_Q); 
    Keyboard.send_now();  
    delay(500);  // Mac OS-X will not recognize a very short eject press
    Keyboard.set_media(0);
    Keyboard.send_now(); 
    resetkeys();
    CPU_RESTART();
}

void fw_hash(unsigned char* hashptr) {
  #ifdef STD_VERSION
   unsigned char smesg[17000];
   unsigned long adr = fwstartadr;
   //Hash current fw in hashptr   
   while (adr <= 0x36060) { //13 blocks of 16384 bytes, last block 0x36060 - 0x3A060
     okcore_flashget_common (smesg, (unsigned long*)adr, 16384); //Read each block
     if (adr == (unsigned long)fwstartadr) { 
       crypto_hash(hashptr,smesg,16384); //hash this block
     }
     else { //if not first block, hash with previous block hash
     memcpy(smesg + 16384, hashptr, crypto_hash_BYTES);
     crypto_hash(hashptr,smesg,(16384+crypto_hash_BYTES)); 
     }
     adr = adr + 16384;
  }
  return;
  #endif
}

void keymap_press (char key) {
  extern uint8_t keyboard_modifier_keys;
  extern uint8_t keyboard_keys[6];
  if ((uint8_t)*pos>'0' && (uint8_t)*pos<='9') {
    delay((*(pos)-'0')*1000);
  } else if ((uint8_t)*pos=='t' || (uint8_t)*pos=='r') {
    if (key) {
      Keyboard.press(*pos);
      key=0;
    }
    else if ((uint8_t)*pos=='t') {
      key = KEY_TAB;
    }
    else if ((uint8_t)*pos=='r') {
      key = KEY_RETURN;
    }
  } else if (mod_keys_enabled) {
    if (key) {
      Keyboard.press(*pos);
      key=0;
    } else {  
      if ((uint8_t)*pos=='p') key = KEY_PRINTSCREEN;
      else if ((uint8_t)*pos=='h') key = KEY_HOME;
      else if ((uint8_t)*pos=='u') key = KEY_PAGE_UP;
      else if ((uint8_t)*pos=='o') key = KEY_PAGE_DOWN;
      else if ((uint8_t)*pos=='e') key = KEY_END;
      else if ((uint8_t)*pos=='d') key = KEY_DELETE;
      else if ((uint8_t)*pos=='b') key = KEY_BACKSPACE;
      else if ((uint8_t)*pos=='L') key = KEY_LEFT;
      else if ((uint8_t)*pos=='R') key = KEY_RIGHT;
      else if ((uint8_t)*pos=='U') key = KEY_UP;
      else if ((uint8_t)*pos=='D') key = KEY_DOWN;
      else if ((uint8_t)*pos=='E') key = KEY_ESC;

      if ((uint8_t)*pos=='c') keyboard_modifier_keys |= MODIFIERKEY_CTRL;
      else if ((uint8_t)*pos=='s') keyboard_modifier_keys |= MODIFIERKEY_SHIFT;
      else if ((uint8_t)*pos=='a') keyboard_modifier_keys |= MODIFIERKEY_ALT;
      else if ((uint8_t)*pos=='g') keyboard_modifier_keys |= MODIFIERKEY_GUI; 
    }
  } 
  
  if (keyboard_keys[0] == 0) keyboard_keys[0] = key;
  else if (keyboard_keys[1] == 0) keyboard_keys[1] = key;
  else if (keyboard_keys[2] == 0) keyboard_keys[2] = key;
  else if (keyboard_keys[3] == 0) keyboard_keys[3] = key;
  else if (keyboard_keys[4] == 0) keyboard_keys[4] = key;
  else if (keyboard_keys[5] == 0) keyboard_keys[5] = key;
  Keyboard.send_now();
}

void exceeded_login_attempts() {
  #ifdef DEBUG
  Serial.print("password attempts for this session exceeded, remove OnlyKey and reinsert to attempt login");
  #endif
  while(1==1)
    {
    hidprint("Error password attempts for this session exceeded, remove OnlyKey and reinsert to attempt login");
    #ifdef OK_Color
    NEO_Color = 1; //Red
    #endif
    blink(5);
    }
}



