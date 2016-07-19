// OnlyKey Beta US Version
/*
 * Tim Steiner
 * Copyright (c) 2016 , CryptoTrust LLC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
*/

#include "sha256.h"
#include <EEPROM.h>
#include <softtimer.h>
#include <password.h>
#include "sha1.h"
#include "totp.h"
#include "Time.h"
#include "onlykey.h"
#include "flashkinetis.h"
#include <RNG.h>
#include "T3MacLib.h"
/*************************************/
//Additional Libraries to Load for US Version
//These libraries will only be used if US_Version is defined
/*************************************/
#define US_VERSION
//Define for US Version Firmare
//#define DEBUG
extern bool PDmode;
#ifdef US_VERSION
#include "yksim.h"
#include "uECC.h"
#include "ykcore.h"
#include <Crypto.h>
#include <AES.h>
#include <GCM.h>
#endif
/*************************************/
//RNG assignments
/*************************************/
bool calibrating = false;

byte data[32];
#define OKversion "v0.2-beta.0"
/*************************************/
//SoftTimer
/*************************************/
#define THRESHOLD   .5
#define TIME_POLL 100 // poll "key" every 100 ms
#define TIME_SEND  50 // send kb codes every 50 ms
Task taskKey(TIME_POLL, checkKey);
Task taskKB (TIME_SEND, sendKey);
char keybuffer[EElen_username+2+EElen_password+2+64]; //Buffer to hold all keystrokes
char *pos;
/*************************************/
//Keypad / password assignments
/*************************************/
static int button_selected = 0;    //Key selected 1-6
static int pass_keypress = 1;  //The number key presses in current password attempt
static int session_attempts = 0; //The number of password attempts this session
static bool firsttime = true;
extern Password password;
static uint8_t TIMEOUT[1] = {0x15};
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
/*************************************/
//Capacitive Touch Variables
/*************************************/
extern unsigned int touchread1;
extern unsigned int touchread2;
extern unsigned int touchread3;
extern unsigned int touchread4;
extern unsigned int touchread5;
extern unsigned int touchread6;
/*************************************/
//PIN HASH
/*************************************/
extern uint8_t phash[32];
extern uint8_t sdhash[32];
extern uint8_t pdhash[32];
extern uint8_t nonce[32];
/*************************************/
//Arduino Setup 
/*************************************/
void setup() {
  #ifdef DEBUG
  Serial.begin(9600);
  #endif
  //delay(7000); 
  #ifdef US_VERSION
  PDmode = false;
  #else
  PDmode = true; 
  #endif
  /*************************************/
  //PIN Assigments
  /*************************************/
  BLINKPIN=6;
  TOUCHPIN1=1;
  TOUCHPIN2=22;
  TOUCHPIN3=23;
  TOUCHPIN4=17;
  TOUCHPIN5=15;
  TOUCHPIN6=16;
  ANALOGPIN1=A0;
  ANALOGPIN2=A7;
  /*************************************/
  pinMode(BLINKPIN, OUTPUT);
  uint8_t *ptr;
  ptr = phash;
  int isinit = onlykey_flashget_pinhash (ptr, 32);
  //TODO consider changing flow, set FSEC to 0x64 https://forum.pjrc.com/threads/28783-Upload-Hex-file-from-Teensy-3-1
  if(FTFL_FSEC==0xDE) { 
      int nn;
      wipeEEPROM();
      nn=flashSecurityLockBits();
      #ifdef DEBUG
      Serial.print("Flash security bits ");
      if(nn) Serial.print("not ");
      Serial.println("written successfully");
      #endif
      onlykey_flashget_pinhash (ptr, 32);
      unlocked = true; //Flash is not protected, First time use
      initialized = false;
      #ifdef DEBUG
      Serial.println("UNLOCKED, FIRST TIME USE");
      #endif
  } else if(FTFL_FSEC==0x44 && isinit>=1) { 
        ptr = nonce;
        onlykey_flashget_noncehash (ptr, 32); //Get nonce from EEPROM
        ptr = sdhash;
        onlykey_flashget_selfdestructhash (ptr); //store self destruct PIN hash
        ptr = pdhash;
        onlykey_flashget_plausdenyhash (ptr); //store plausible deniability PIN hash
        ptr = TIMEOUT;
        onlykey_eeget_timeout(ptr);
        if (TIMEOUT[0]< 0x02) TIMEOUT[0] = 0x15; //Default 15 min idle timeout
        unlocked = false;
        initialized = true;
        #ifdef DEBUG
        Serial.println("INITIALIZED");
        #endif
  } else {
        unlocked = true;
        initialized = false;
        #ifdef DEBUG
        Serial.println("UNLOCKED, PIN HAS NOT BEEN SET");
        #endif
  } 
  /*************************************/
  //Initialize the random number generator with analog noise, stored NONCE, and chip ID
  /*************************************/
  RNG.begin(OKversion, 2045); //Start RNG with the device version
  CHIP_ID();
  RNG.stir((byte*)ID, sizeof(ID)); //Stir in unique 128 bit Freescale chip ID
  RNG.stir((byte*)nonce, sizeof(nonce)); //Stir in unique nonce that is generated from user entropy when OK is first initialized
  unsigned int analog1 = analogRead(ANALOGPIN1);
  RNG.stir((uint8_t *)analog1, sizeof(analog1), sizeof(analog1)*2);
  unsigned int analog2 = analogRead(ANALOGPIN2);
  RNG.stir((uint8_t *)analog2, sizeof(analog2), sizeof(analog2)*2);
  #ifdef DEBUG
  Serial.print("EEPROM Used ");
  Serial.println(EEpos_failedlogins);
  Serial.println(FTFL_FSEC, HEX); 
  Serial.print("PDmode = ");
  Serial.println(PDmode); 
  #endif
  rngloop(); //Start RNG
  SoftTimer.add(&taskKey);
}
/*************************************/
elapsedMillis sincelast; 
elapsedMillis idletimer; 
//Main Loop, Read Key Press Using Capacitive Touch
/*************************************/
void checkKey(Task* me) {
  static int key_press = 0;
  static int key_on = 0;
  static int key_off = 0;
  static int count;

  if (unlocked) {
    recvmsg();
    if(initialized) {
    #ifdef US_VERSION
    yubikey_incr_time();
    #endif
    if (idletimer >= (TIMEOUT[0]*900000)) unlocked = false; 
    }
  }
  else if (sincelast >= 1000 && initialized)
  {
    hidprint("INITIALIZED");
    #ifdef DEBUG
    Serial.println("INITIALIZED");
    #endif
    sincelast = sincelast - 1000;
  }
  
    //Uncomment to test RNG
    //RNG2(data, 32);
    //printHex(data, 32);

  rngloop(); //Perform regular housekeeping on the random number generator.

  if (touchread1 > 1500) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '5';
    //Serial.println(touchread1);
  }      
    else if (touchread2 > 1500) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '2';
    //Serial.println(touchread2);
  } 
    else if (touchread3 > 1500) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '1';
    //Serial.println(touchread3);
  } 
   else if (touchread4 > 1500) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '3';
    //Serial.println(touchread4);
  } 
   else if (touchread5 > 1500) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '4';
    //Serial.println(touchread5);
  } 
   else if (touchread6 > 1500) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '6';
    //Serial.println(touchread6);
  } 

  else {
    if (key_on > THRESHOLD) key_press = key_on;
    key_on = 0;
    key_off += 1;
    if (!unlocked) digitalWrite(BLINKPIN, LOW); //LED OFF
    else digitalWrite(BLINKPIN, HIGH); //LED ON
  }

  if ((key_press > 0) && (key_off > THRESHOLD)) {
    payload(key_press);
    key_press = 0;
   }
}
/*************************************/
//Type out on Keyboard the contents of Keybuffer
/*************************************/
void sendKey(Task* me) {
   if ((byte)*pos == 128) {
        Keyboard.press(KEY_TAB); 
        Keyboard.release(KEY_TAB); 
        pos++;  
    } 
    else if ((byte)*pos == 129) {
        Keyboard.press(KEY_RETURN); 
        Keyboard.release(KEY_RETURN); 
        pos++;  
    } 
    else if ((byte)*pos == 130 && !PDmode) {
        #ifdef DEBUG
        Serial.println("Starting U2F...");
        #endif
        int timer = sincelast;
        while(sincelast < (timer+8000)) {
          digitalWrite(BLINKPIN, LOW);
          u2f_button = 1;
          #ifdef US_VERSION
          uECC_set_rng(&RNG2);
          #endif
          recvmsg();
          }
        digitalWrite(BLINKPIN, HIGH);
        u2f_button = 0;
        Keyboard.end();
        SoftTimer.remove(&taskKB);
        SoftTimer.add(&taskKey);
        return;
    }
    else if ((byte)*pos >= 131) {
        delay((*pos - 131)*1000);   
        pos++;  
    } 
    else if (*pos){
        Keyboard.write(*pos);
        pos++;
    }
    else {
    #ifdef DEBUG
    Serial.print(pos);
    #endif
    Keyboard.press(KEY_RETURN); 
    Keyboard.release(KEY_RETURN);  
    Keyboard.end();
    SoftTimer.remove(&taskKB);
    SoftTimer.add(&taskKey);
    }
}
/*************************************/
//Password Checking Loop
/*************************************/
void payload(int duration) {
   if (!unlocked) digitalWrite(BLINKPIN, HIGH); //LED ON
   else digitalWrite(BLINKPIN, LOW); //LED OFF
   uint8_t pass_attempts[1];
   uint8_t *ptr;
   ptr = pass_attempts;
    if (session_attempts >= 3) { //Limit 3 password attempts per session to make sure that someone does not accidentally wipe device
    #ifdef DEBUG
    Serial.print("password attempts for this session exceeded, remove OnlyKey and reinsert to attempt login");
    #endif
      while(1==1)
        {
        hidprint("Error password attempts for this session exceeded, remove OnlyKey and reinsert to attempt login");
        blink(5);
        }
    return;
    }
   
   if (firsttime) //Get failed login counter from eeprom and increment for new login attempt
   {
   onlykey_eeget_failedlogins (ptr);
   pass_attempts[0]++;
   //Serial.println(pass_attempts[0]);
   if (pass_attempts[0] > 10) {
    #ifdef DEBUG
    Serial.println("Password attempts exhausted");
    Serial.println(pass_attempts[0]);
    #endif
   factorydefault();
   pass_attempts[0] = 0;
   return;
   }
   onlykey_eeset_failedlogins (ptr); 
   firsttime = false;
   }
   password.append(button_selected);
   if (unlocked || password.hashevaluate() || password.pdhashevaluate()) { 
        if (unlocked != true) //A correct PIN was just entered do the following for first login
        {
          onlykey_eeset_failedlogins(0); //Set failed login counter to 0
          password.reset(); //reset the guessed password to NULL
          hidprint("UNLOCKED"); 
          #ifdef DEBUG
          Serial.println("UNLOCKED");
          #endif
          if (!PDmode) {
          yubikeyinit(); 
          U2Finit();
          }
          idletimer=0; 
          unlocked = true;
          
          return;
        }
        else if (PINSET==0) { 
        }
        else if (PINSET<=3) { 
            #ifdef DEBUG
            Serial.print("password appended with ");
            Serial.println(button_selected-'0');
            #endif
            return;
        }
        else if (PINSET<=6) {
            #ifdef DEBUG
            Serial.print("SD password appended with ");
            Serial.println(button_selected-'0');
            #endif
            return;
        }
        else {
            if(!PDmode){
            #ifdef DEBUG
            Serial.print("PD password appended with ");
            Serial.println(button_selected-'0');
            #endif
            }
            return;
        }
      Keyboard.begin();
      *keybuffer = '\0';
      if (duration <= 10) gen_press();
      if (duration >= 11) gen_hold();
      pos = keybuffer;
      SoftTimer.remove(&taskKey);
      SoftTimer.add(&taskKB);
      return;
  }
   else if (password.sdhashevaluate()) {
    #ifdef DEBUG
    Serial.println("Self Destruct PIN entered"); 
    #endif
    factorydefault(); 
   }
   else {
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
        blink(3);
        #ifdef DEBUG
        Serial.print("Login Failed, there are ");
        #endif
        onlykey_eeget_failedlogins (ptr);
        #ifdef DEBUG
        Serial.print(10 - pass_attempts[0]);
        Serial.println(" remaining attempts before a factory reset will occur");
        Serial.println("WARNING: This will render all device information unrecoverable");
        #endif
        password.reset(); //reset the guessed password to NULL
        pass_keypress=1;
        return;
      }
   }
}
/*************************************/
//Trigger on short button press
/*************************************/
void gen_press(void) {
  if (!initialized) {
    #ifdef DEBUG
    Serial.println("UNINITIALIZED - You must set a password first");
    #endif
    hidprint("UNINITIALIZED - You must set a password first");
    return;
  }
  digitalWrite(BLINKPIN, LOW); //LED OFF
  idletimer=0; 
  int slot;
  if (PDmode) {
    slot=(button_selected-'0')+12;
  } else {
    slot=button_selected-'0';
  }
      process_slot(slot);   
}
/*************************************/
//Trigger on long button press
/*************************************/
void gen_hold(void) {
  if (!initialized) {
    #ifdef DEBUG
    Serial.println("UNINITIALIZED - You must set a password first");
    #endif
    hidprint("UNINITIALIZED - You must set a password first");
    return;
  }
  digitalWrite(BLINKPIN, LOW); //LED OFF
  idletimer=0; 
  int slot;
  if (PDmode) {
    slot=(button_selected-'0')+12;
  } else {
    slot=button_selected-'0';
  }
      process_slot(slot+6);   
}
/*************************************/
//Load Set Values to Keybuffer
/*************************************/
void process_slot(int s) {
  long GMT;
  char* newcode;
  static uint8_t index;
  uint8_t temp[64];
  int usernamelength;
  int passwordlength;
  int otplength;
  int delay1 = 0;
  int delay2 = 0;
  uint8_t *ptr;
  int slot=s;
index = 0;
      #ifdef DEBUG
      Serial.print("Slot Number ");
      Serial.println(button_selected-'0');
      #endif
      memset(temp, 0, 64); //Wipe all data from buffer
      memset(keybuffer, 0, sizeof(keybuffer)); //Wipe all data from keybuffer
      ptr = temp;
      usernamelength = onlykey_eeget_username(ptr, slot);
      if(usernamelength > 0)
      {
        #ifdef DEBUG
        Serial.println("Reading Username from EEPROM...");
        Serial.print("Username Length = ");
        Serial.println(usernamelength);
        #endif
        if (!PDmode) {
        #ifdef DEBUG
        Serial.println("Encrypted");
            for (int z = 0; z < usernamelength; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
        #endif
        #ifdef US_VERSION
        aes_gcm_decrypt(temp, (uint8_t*)('u'+ID[34]+slot), phash, usernamelength);
        #endif
        }
        ByteToChar2(temp, keybuffer, usernamelength, index);
        #ifdef DEBUG
            Serial.println("Unencrypted");
            for (int z = 0; z < usernamelength; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
        #endif
        index=usernamelength;
      }
      memset(temp, 0, 64); //Wipe all data from buffer
      onlykey_eeget_addchar1(ptr, slot);
      if(temp[0] > 0)
      {
        if(temp[0] == 0x31) {
        #ifdef DEBUG
        Serial.println("Reading addchar1 from EEPROM...");
        #endif
        keybuffer[index] = 128;
        #ifdef DEBUG
        Serial.println("TAB");
        #endif
        index++;
        }
        else if(temp[0] == 0x32) {
        #ifdef DEBUG
        Serial.println("Reading addchar1 from EEPROM...");
        #endif
        keybuffer[index] = 129;
        #ifdef DEBUG
        Serial.println("RETURN");
        #endif
        index++;
        }
      }
      memset(temp, 0, 64); //Wipe all data from buffer
      onlykey_eeget_delay1(ptr, slot);
      if(temp[0] > 0)
      {
        #ifdef DEBUG
        Serial.println("Reading Delay from EEPROM...");
        Serial.print("Delay ");
        Serial.print(temp[0]);
        Serial.println(" Seconds before entering password");
        #endif
        delay1=temp[0];
        keybuffer[index] = temp[0] + 131;
        index++;
      }
      passwordlength = onlykey_eeget_password(ptr, slot);
      if(passwordlength > 0)
      {
        #ifdef DEBUG
        Serial.println("Reading Password from EEPROM...");
        Serial.print("Password Length = ");
        Serial.println(passwordlength);
        #endif
        if (!PDmode) {
        #ifdef DEBUG
        Serial.println("Encrypted");
            for (int z = 0; z < passwordlength; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
          #endif
        #ifdef US_VERSION
        aes_gcm_decrypt(temp, (uint8_t*)('p'+ID[34]+slot), phash, passwordlength);
        #endif
        }
        ByteToChar2(temp, keybuffer, passwordlength, index);
        #ifdef DEBUG
        Serial.println("Unencrypted");
            for (int z = 0; z < passwordlength; z++) {
            Serial.print(temp[z], HEX);
            }
         Serial.println();
        #endif
        index=passwordlength+index;
      }
      memset(temp, 0, 64); //Wipe all data from buffer    
      onlykey_eeget_addchar2(ptr, slot);
      if(temp[0] > 0)
      {
        if(temp[0] == 0x31) {
        #ifdef DEBUG
        Serial.println("Reading addchar2 from EEPROM...");
        Serial.println("TAB");
        #endif
        keybuffer[index] = 128;
        index++;
        }
        else if(temp[0] == 0x32) {
        #ifdef DEBUG
        Serial.println("Reading addchar2 from EEPROM...");      
        Serial.println("Return");
        #endif
        keybuffer[index] = 129;
        index++;
        }
      }
      memset(temp, 0, 64); //Wipe all data from buffer    
      onlykey_eeget_delay2(ptr, slot);
      if(temp[0] > 0)
      {
        #ifdef DEBUG
        Serial.println("Reading Delay2 from EEPROM...");
        Serial.print("Delay ");
        Serial.print(temp[0]);
        Serial.println(" Seconds before entering 2FA");
        #endif
        delay2=temp[0];
        keybuffer[index] = temp[0] + 131;
        index++;
      }
      memset(temp, 0, 64); //Wipe all data from buffer 
      otplength = onlykey_eeget_2FAtype(ptr, slot);
      if(temp[0] > 0)
      {
        if(temp[0] == 103) { //Google Auth
          #ifdef DEBUG
          Serial.println("Reading TOTP Key from EEPROM...");
          #endif
          otplength = onlykey_flashget_totpkey(ptr, slot);
        #ifdef DEBUG
        Serial.println("Encrypted");
            for (int z = 0; z < otplength; z++) {
            Serial.print(temp[z], HEX);
            }
           Serial.println();
          
        Serial.print("TOTP Key Length = ");
        Serial.println(otplength);
        #endif
          #ifdef US_VERSION
          aes_gcm_decrypt(temp, (uint8_t*)('t'+ID[34]+slot), phash, otplength);
          #endif
        ByteToChar2(temp, keybuffer, otplength, index);
        #ifdef DEBUG
        Serial.println("Unencrypted");
            for (int z = 0; z < otplength; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
        #endif
          TOTP totp1 = TOTP(temp, otplength);
          GMT = now();
          GMT = GMT + delay1 + delay2;
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
            keybuffer[index+6]=0x00;
          } else {
            keybuffer[index]=*newcode;
            keybuffer[index+1]=*(newcode+1);
            keybuffer[index+2]=*(newcode+2);
            keybuffer[index+3]=*(newcode+3);
            keybuffer[index+4]=*(newcode+4);
            keybuffer[index+5]=*(newcode+5);
            keybuffer[index+6]=0x00;
          }
          index=index+6;
        }
        if(temp[0] == 121 && !PDmode) { 
        #ifdef DEBUG
        Serial.println("Generating Yubico OTP...");
        #endif
        #ifdef US_VERSION
        yubikeysim(keybuffer + index);
        index=index+44;
        #endif
        }
        if(temp[0] == 117 && !PDmode) { //U2F
        keybuffer[index] = 130;
        index++;
        }
      }
          
          #ifdef DEBUG
          Serial.println("Displaying Full Keybuffer");
          for (int i=0; keybuffer[i]!=0x00; i++) {
            Serial.print
            (keybuffer[i]);
          }
          #endif

}

