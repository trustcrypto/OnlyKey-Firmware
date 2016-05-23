// OnlyKey Standalone test - Use with Teensy 3.2 without keypad
/* WARNING - For testing only, No keypad means no PIN protection of sensitive data
 *  
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
#include "uecc.h"
#include "yksim.h"
#include "ykcore.h"
#include <softtimer.h>
#include <password.h>
//http://www.arduino.cc/playground/uploads/Code/Password.zip
#include "sha1.h"
#include "totp.h"
#include "Time.h"
#include "onlykey.h"
#include "flashkinetis.h"
#include <Crypto.h>
#include <AES.h>
#include <GCM.h>
#include <RNG.h>
#include <transistornoisesource.h>
#include "T3MacLib.h"
#define DEBUG

//PIN assignments
/*************************************/
#define BLINKPIN   13
#define TOUCHPIN1    01
#define TOUCHPIN2    15
#define TOUCHPIN3    16
#define TOUCHPIN4    17
#define TOUCHPIN5    22
#define TOUCHPIN6    23
/*************************************/

//RNG assignments
/*************************************/
// Noise source to seed the random number generator.
TransistorNoiseSource noise(A0);
bool calibrating = false;
/*************************************/

//SoftTimer
/*************************************/
#define THRESHOLD   .5
#define TIME_POLL 100 // poll "key" every 100 ms
#define TIME_SEND  50 // send kb codes every 50 ms
Task taskKey(TIME_POLL, checkKey);
Task taskKB (TIME_SEND, sendKey);
char keybuffer[EElen_username+2+EElen_password+2+YUBIKEY_OTP_MAXSIZE];
char *pos;
/*************************************/

//Keypad password set assignments
/*************************************/
static int button_selected = 0;    //Key selected 1-6
static int pass_keypress = 1;  //The number key presses in current password attempt
static int session_attempts = 0; //The number of password attempts this session
static bool firsttime = true;
extern Password password;
static uint8_t TIMEOUT[1] = {0x15};
/*************************************/

//yubikey
/*************************************/
yubikey_ctx_st ctx;
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
  Serial.begin(9600);
  //while (!Serial) ; // wait for serial
  delay(1000);
  pinMode(BLINKPIN, OUTPUT);
  delay(7000);
  uint8_t *ptr;
  ptr = phash;
 int isinit = onlykey_flashget_pinhash (ptr, 32);
  //TODO consider changing flow, set FSEC to 0x64 https://forum.pjrc.com/threads/28783-Upload-Hex-file-from-Teensy-3-1
  if(FTFL_FSEC==0xDE) { 
    factorydefault();
      int nn;
      nn=flashSecurityLockBits();
      Serial.print("Flash security bits ");
      if(nn) Serial.print("not ");
      Serial.println("written successfully");
      onlykey_flashget_pinhash (ptr, 32);
      unlocked = true; //Flash is not protected, First time use
      initialized = false;
      Serial.println("UNLOCKED, FIRST TIME USE");  
  } else if(FTFL_FSEC==0x44 && isinit) { 
        ptr = nonce;
        onlykey_flashget_noncehash (ptr, 32); //Get nonce from EEPROM
        ptr = sdhash;
        onlykey_flashget_selfdestructhash (ptr); //store self destruct PIN hash
        ptr = pdhash;
        onlykey_flashget_plausdenyhash (ptr); //store plausible deniability PIN hash
        ptr = TIMEOUT;
        onlykey_eeget_timeout(ptr);
        if (TIMEOUT[0]==0) TIMEOUT[0] = 15; //Default 15 min idle timeout
        unlocked = false;
        initialized = true;
        Serial.println("INITIALIZED");
  } else {
        unlocked = true;
        initialized = false;
        Serial.println("UNLOCKED, PIN HAS NOT BEEN SET");
  } 

  // Initialize the random number generator with stored NONCE, MAC, and chip ID
  read_mac();
  RNG.begin((char*)mac, 0); //Start RNG with the device mac and whatever is in EEPROM
  CHIP_ID();
  RNG.stir((byte*)ID, sizeof(ID)); //Stir in unique 128 bit Freescale chip ID
  RNG.stir((byte*)nonce, sizeof(nonce)); //Stir in unique nonce that is generated from user entropy when OK is first initialized
  Serial.print("EEPROM Used ");
  Serial.println(EEpos_failedlogins);
  Serial.println(FTFL_FSEC, HEX); 
  unlocked=true;
  initialized=true;
  rngloop(); //Start RNG
  ptr = nonce;
  onlykey_flashset_noncehash (ptr); //Get nonce from EEPROM
  ptr = phash;
  onlykey_flashset_pinhash (ptr);
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

    
  rngloop(); //
  
  if (unlocked) {
    recvmsg();
    if(initialized) {
    uECC_set_rng(&RNG2); 
    yubikey_incr_timestamp(&ctx);
    if (idletimer >= (TIMEOUT[0]*900000)) unlocked = false; 
    }
  }
  else if (sincelast >= 1000 && initialized)
  {
    hidprint("INITIALIZED");
    Serial.println("INITIALIZED");
    sincelast = sincelast - 1000;
  }
  
  
  // Stir the touchread values into the entropy pool.
  unsigned int touchread1 = touchRead(TOUCHPIN1);
  RNG.stir((uint8_t *)touchread1, sizeof(touchread1), sizeof(touchread1) * 2);
  unsigned int touchread2 = touchRead(TOUCHPIN2);
  RNG.stir((uint8_t *)touchread2, sizeof(touchread2), sizeof(touchread2) * 2);
  unsigned int touchread3 = touchRead(TOUCHPIN3);
  RNG.stir((uint8_t *)touchread3, sizeof(touchread3), sizeof(touchread3) * 2);
  unsigned int touchread4 = touchRead(TOUCHPIN4);
  RNG.stir((uint8_t *)touchread4, sizeof(touchread4), sizeof(touchread4) * 2);
  unsigned int touchread5 = touchRead(TOUCHPIN5);
  RNG.stir((uint8_t *)touchread5, sizeof(touchread5), sizeof(touchread5) * 2);
  unsigned int touchread6 = touchRead(TOUCHPIN6);
  RNG.stir((uint8_t *)touchread6, sizeof(touchread6), sizeof(touchread6) * 2);

  if (touchread1 > 1000) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '5';
    //Serial.println(touchread1);
  }      
    else if (touchread2 > 1000) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '2';
    //Serial.println(touchread2);
  } 
    else if (touchread3 > 1000) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '1';
    //Serial.println(touchread3);
  } 
   else if (touchread4 > 1000) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '3';
    //Serial.println(touchread4);
  } 
   else if (touchread5 > 1000) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '4';
    //Serial.println(touchread5);
  } 
   else if (touchread6 > 1000) {
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

//Type out on Keyboard
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
    else if ((byte)*pos > 129) {
        delay((*pos - 129)*1000);   
        pos++;  
    } 
    else if (*pos){
        Keyboard.write(*pos);
        pos++;
    }
    else {
    Serial.print(pos);
    Keyboard.press(KEY_RETURN); 
    Keyboard.release(KEY_RETURN);  
    Keyboard.end();
    SoftTimer.remove(&taskKB);
    SoftTimer.add(&taskKey);
    }
}
/*************************************/
//Keypad passcode checker
/*************************************/
void payload(int duration) {
   if (!unlocked) digitalWrite(BLINKPIN, HIGH); //LED ON
   else digitalWrite(BLINKPIN, LOW); //LED OFF
   uint8_t pass_attempts[1];
   uint8_t *ptr;
   ptr = pass_attempts;
    if (session_attempts >= 3) { //Limit 3 password attempts per session to make sure that someone does not accidentally wipe device
    Serial.print("password attempts for this session exceeded, remove OnlyKey and reinsert to attempt login");
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
   if (pass_attempts[0] >= 10) {
    Serial.println("Password attempts exhausted");
    Serial.println(pass_attempts[0]);
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
          Serial.println("UNLOCKED");
          if (!PDmode) yubikeyinit();
          idletimer=0; 
          unlocked = true;
          return;
        }
        else if (PINSET==0) { 
        }
        else if (PINSET<=3) { 
            Serial.print("password appended with ");
            Serial.println(button_selected-'0');
            return;
        }
        else if (PINSET<=6) {
            Serial.print("SD password appended with ");
            Serial.println(button_selected-'0');
            return;
        }
        else {
            Serial.print("PD password appended with ");
            Serial.println(button_selected-'0');
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
    Serial.println("Self Destruct PIN entered"); //TODO remove debug
    factorydefault(); 
   }
   else {
    if (pass_keypress < 10) {
        Serial.print("password appended with ");
        Serial.println(button_selected-'0');
        Serial.print("Number of keys entered for this passcode = ");
        Serial.println(pass_keypress);
        pass_keypress++; 
        return;  
      } else {
        firsttime = true;
        session_attempts++;
        blink(3);
        Serial.print("Login Failed, there are ");
        onlykey_eeget_failedlogins (ptr);
        Serial.print(9 - pass_attempts[0]);
        Serial.println(" remaining attempts before a factory reset will occur");
        Serial.println("WARNING: This will render all device information unrecoverable");
        password.reset(); //reset the guessed password to NULL
        pass_keypress=1;
        return;
      }
   }
}
/*************************************/

void gen_press(void) {
  if (!initialized) {
    Serial.println("UNINITIALIZED - You must set a password first");
    hidprint("UNINITIALIZED - You must set a password first");
    return;
  }
  digitalWrite(BLINKPIN, LOW); //LED OFF
  idletimer=0;
  int slot;
  uint8_t *ptr;
  if (PDmode==true) {
    slot=(button_selected-'0')+12;
  } else {
    slot=button_selected-'0';
  }
      process_slot(slot);   
}



/*************************************/

void gen_hold(void) {
  if (!initialized) {
    Serial.println("UNINITIALIZED - You must set a password first");
    hidprint("UNINITIALIZED - You must set a password first");
    return;
  }
  digitalWrite(BLINKPIN, LOW); //LED OFF
  idletimer=0;
  int slot;
  if (PDmode==true) {
    slot=(button_selected-'0')+12;
  } else {
    slot=button_selected-'0';
  }
      process_slot(slot+6);   
     
}
/*************************************/

void yubikeyinit() {
  
  uint32_t seed;
  uint8_t *ptr = (uint8_t *)&seed;
  getrng(ptr, 32); //Seed the onlyKey with random data

  uint8_t temp[32];
  uint8_t aeskey[16];
  uint8_t privID[6];
  uint8_t pubID[16];
  uint16_t counter;
  char public_id[32+1];
  char private_id[12+1];

  
  Serial.println("Initializing onlyKey ...");
  
  memset(temp, 0, 32); //Clear temp buffer
  
  ptr = temp;
  onlykey_eeget_aeskey(ptr);
  
  ptr = (temp+EElen_aeskey);
  onlykey_eeget_private(ptr);

  ptr = (temp+EElen_aeskey+EElen_private);
  onlykey_eeget_public(ptr);

  aes_gcm_decrypt(temp, (uint8_t*)('y'+ID[34]), phash, (EElen_aeskey+EElen_private+EElen_aeskey));

  for (int i = 0; i <= EElen_aeskey; i++) {
    aeskey[i] = temp[i];
  }
  for (int i = 0; i <= EElen_private; i++) {
    privID[i] = temp[i+EElen_aeskey];
  }
  for (int i = 0; i <= EElen_public; i++) {
    pubID[i] = temp[i+EElen_aeskey+EElen_private];
  }
  memset(temp, 0, 32); //Clear temp buffer
  
  ptr = (uint8_t*) &counter;
  yubikey_eeget_counter(ptr);

  uint32_t time = 0x010203; //TODO why is time set to this?

  yubikey_hex_encode(private_id, (char *)privID, 6);
  yubikey_hex_encode(public_id, (char *)pubID, 6);
  
  yubikey_init1(&ctx, aeskey, public_id, private_id, counter, time, seed);
 
  yubikey_incr_counter(&ctx);
 
  ptr = (uint8_t*) &(ctx.counter);
  yubikey_eeset_counter(ptr);
}

/*************************************/

void rngloop() {
    // Track changes to the calibration state on the noise source.
    bool newCalibrating = noise.calibrating();
    if (newCalibrating != calibrating) {
        calibrating = newCalibrating;
    }
    // Perform regular housekeeping on the random number generator.
    RNG.loop();
}

void process_slot(int s) {
  long GMT;
  char* newcode;
  static uint8_t index;
  uint8_t temp[32];
  int usernamelength;
  int passwordlength;
  int otplength;
  uint8_t *ptr;
  int slot=s;
index = 0;
      Serial.print("Slot Number ");
      Serial.println(button_selected-'0');
      memset(temp, 0, 32); //Wipe all data from buffer
      ptr = temp;
      usernamelength = onlykey_eeget_username(ptr, slot);
      if(usernamelength > 0)
      {
        Serial.println("Reading Username from EEPROM...");
        Serial.print("Username Length = ");
        Serial.println(usernamelength);
        if (!PDmode) {
        #ifdef DEBUG
        Serial.println("Encrypted");
            for (int z = 0; z < 32; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
          #endif
        aes_gcm_decrypt(temp, (uint8_t*)('u'+ID[34]+slot), phash, usernamelength);
        }
        ByteToChar2(temp, keybuffer, usernamelength, index);
        #ifdef DEBUG
            Serial.println("Unencrypted");
            for (int z = 0; z < 32; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
        #endif
        index=usernamelength;
      }
      memset(temp, 0, 32); //Wipe all data from buffer
      onlykey_eeget_addchar1(ptr, slot);
      if(temp[0] > 0)
      {
        if(temp[0] == 0x31) {
        Serial.println("Reading addchar1 from EEPROM...");
        keybuffer[index] = 128;
        Serial.println("TAB");
        index++;
        }
        else if(temp[0] == 0x32) {
        Serial.println("Reading addchar1 from EEPROM...");
        keybuffer[index] = 129;
        Serial.println("RETURN");
        index++;
        }
      }
      memset(temp, 0, 32); //Wipe all data from buffer
      onlykey_eeget_delay1(ptr, slot);
      if(temp[0] > 0)
      {
        Serial.println("Reading Delay from EEPROM...");
        Serial.print("Delay ");
        Serial.print(temp[0]);
        Serial.println(" Seconds before entering password");
        keybuffer[index] = temp[0] + 129;
        index++;
      }
      passwordlength = onlykey_eeget_password(ptr, slot);
      if(passwordlength > 0)
      {
        Serial.println("Reading Password from EEPROM...");
        Serial.print("Password Length = ");
        Serial.println(passwordlength);
        if (!PDmode) {
        #ifdef DEBUG
        Serial.println("Encrypted");
            for (int z = 0; z < 32; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
          #endif
        aes_gcm_decrypt(temp, (uint8_t*)('p'+ID[34]+slot), phash, passwordlength);
        }
        ByteToChar2(temp, keybuffer, passwordlength, index);
        #ifdef DEBUG
        Serial.println("Unencrypted");
            for (int z = 0; z < 32; z++) {
            Serial.print(temp[z], HEX);
            }
         Serial.println();
        #endif
        index=passwordlength+index;
      }
      memset(temp, 0, 32); //Wipe all data from buffer    
      onlykey_eeget_addchar2(ptr, slot);
      if(temp[0] > 0)
      {
        if(temp[0] == 0x31) {
        Serial.println("Reading addchar2 from EEPROM...");
        keybuffer[index] = 128;
        Serial.println("TAB");
        index++;
        }
        else if(temp[0] == 0x32) {
        Serial.println("Reading addchar2 from EEPROM...");
        keybuffer[index] = 129;
        Serial.println("Return");
        index++;
        }
      }
      memset(temp, 0, 32); //Wipe all data from buffer    
      onlykey_eeget_delay2(ptr, slot);
      if(temp[0] > 0)
      {
        Serial.println("Reading Delay2 from EEPROM...");
        Serial.print("Delay ");
        Serial.print(temp[0]);
        Serial.println(" Seconds before entering 2FA");
        keybuffer[index] = temp[0] + 129;
        index++;
      }
      memset(temp, 0, 32); //Wipe all data from buffer 
      otplength = onlykey_eeget_2FAtype(ptr, slot);
      if(temp[0] > 0)
      {
        if(temp[0] == 103) { //Google Auth
          Serial.println("Reading TOTP Key from EEPROM...");
          otplength = onlykey_flashget_totpkey(ptr, slot);
        #ifdef DEBUG
        Serial.println("Encrypted");
            for (int z = 0; z < 32; z++) {
            Serial.print(temp[z], HEX);
            }
           Serial.println();
          #endif
        Serial.print("TOTP Key Length = ");
        Serial.println(otplength);
        aes_gcm_decrypt(temp, (uint8_t*)('t'+ID[34]+slot), phash, otplength);
        ByteToChar2(temp, keybuffer, otplength, index);
        #ifdef DEBUG
        Serial.println("Unencrypted");
            for (int z = 0; z < 32; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
        #endif
          TOTP totp1 = TOTP(temp, otplength);
          GMT = now();
          newcode = totp1.getCode(GMT);
          
            keybuffer[index]=*newcode;
            keybuffer[index+1]=*(newcode+1);
            keybuffer[index+2]=*(newcode+2);
            keybuffer[index+3]=*(newcode+3);
            keybuffer[index+4]=*(newcode+4);
            keybuffer[index+5]=*(newcode+5);
            keybuffer[index+6]=0x00;
          
          index=index+6;
        }
        if(temp[0] == 121) { //onlykey
        Serial.println("Generating onlykey OTP...");
        yubikey_simulate1((char*)keybuffer[index], &ctx);
        yubikey_incr_usage(&ctx);
        index=index+44;
        }
        if(temp[0] == 117) { //U2F
        Serial.println("Starting U2F...");
        u2f_button = 1;
        }
      }
          //TODO remove debug print full keybuffer
          Serial.println("Displaying Full Keybuffer");
          for (int i=0; keybuffer[i]!=0x00; i++) {
            Serial.print
            (keybuffer[i]);
          }

}

