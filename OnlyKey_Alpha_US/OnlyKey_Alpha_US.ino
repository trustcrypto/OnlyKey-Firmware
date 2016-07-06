// OnlyKey Alpha US Version
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
#include <transistornoisesource.h>
#include "T3MacLib.h"
/*************************************/
//Additional Libraries to Load for US Version
//These libraries will only be used if US_Version is defined
/*************************************/
#define US_VERSION //Define for US Version Firmare
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
#define OKversion "v0.1-alpha.0"
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
//yubikey
/*************************************/
#ifdef US_VERSION
yubikey_ctx_st ctx;
#endif
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
  Serial.begin(9600);
  //delay(7000); 
  PDmode = false; ///Must be false for US Version
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
      #ifdef US_VERSION
      YubikeyEEInit();  //TODO remove once chrome app supports Yubico OTP SETSLOT
      #endif
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
  RNG.stir((uint8_t *)analog1, sizeof(analog1), sizeof(analog1 * 2));
  unsigned int analog2 = analogRead(ANALOGPIN2);
  RNG.stir((uint8_t *)analog2, sizeof(analog2), sizeof(analog2 * 2));
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
    yubikey_incr_timestamp(&ctx);
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
        
        Serial.println("Starting U2F...");
        
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
   if (pass_attempts[0] > 10) {
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
          if (!PDmode) {
          yubikeyinit(); 
          }
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
            if(!PDmode){
            Serial.print("PD password appended with ");
            Serial.println(button_selected-'0');
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
        Serial.print(10 - pass_attempts[0]);
        Serial.println(" remaining attempts before a factory reset will occur");
        Serial.println("WARNING: This will render all device information unrecoverable");
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
    Serial.println("UNINITIALIZED - You must set a password first");
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
    Serial.println("UNINITIALIZED - You must set a password first");
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
//Initialize Yubico OTP
/*************************************/
void yubikeyinit() {
#ifdef US_VERSION
  uint32_t seed;
  uint8_t *ptr = (uint8_t *)&seed;
  RNG2(ptr, 32); //Seed the onlyKey with random data

  uint8_t temp[32];
  uint8_t aeskey[16];
  uint8_t privID[6];
  uint8_t pubID[16];
  uint16_t counter;
  char public_id[32+1];
  char private_id[12+1];

  
  Serial.println("Initializing onlyKey ...");
  /*
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

  yubikey_hex_encode(private_id, (char *)privID, 6);
  yubikey_hex_encode(public_id, (char *)pubID, 6);

    Serial.println("public_id");
  Serial.println(public_id);
    Serial.println("private_id");
  Serial.println(private_id);
    Serial.println("counter");
  Serial.println(counter);
  */ //TODO enable this once chrome app supports Yubi OTP key load
  ptr = (uint8_t*) &counter;
  yubikey_eeget_counter(ptr);
  uint32_t time = 0x010203; //TODO why is time set to this?
  ptr = aeskey;
  onlykey_eeget_aeskey(ptr); 
  ptr = privID;
  onlykey_eeget_private(ptr);
  yubikey_hex_encode(private_id, (char *)privID, 6);
  ptr = pubID;
  onlykey_eeget_public(ptr);
  yubikey_hex_encode(public_id, (char *)pubID, 6);
  yubikey_init1(&ctx, aeskey, public_id, private_id, counter, time, seed);
 
  yubikey_incr_counter(&ctx);
 
  ptr = (uint8_t*) &(ctx.counter);
  yubikey_eeset_counter(ptr);
#endif
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
      Serial.print("Slot Number ");
      Serial.println(button_selected-'0');
      memset(temp, 0, 64); //Wipe all data from buffer
      memset(keybuffer, 0, sizeof(keybuffer)); //Wipe all data from keybuffer
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
      memset(temp, 0, 64); //Wipe all data from buffer
      onlykey_eeget_delay1(ptr, slot);
      if(temp[0] > 0)
      {
        Serial.println("Reading Delay from EEPROM...");
        Serial.print("Delay ");
        Serial.print(temp[0]);
        Serial.println(" Seconds before entering password");
        delay1=temp[0];
        keybuffer[index] = temp[0] + 131;
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
      memset(temp, 0, 64); //Wipe all data from buffer    
      onlykey_eeget_delay2(ptr, slot);
      if(temp[0] > 0)
      {
        Serial.println("Reading Delay2 from EEPROM...");
        Serial.print("Delay ");
        Serial.print(temp[0]);
        Serial.println(" Seconds before entering 2FA");
        delay2=temp[0];
        keybuffer[index] = temp[0] + 131;
        index++;
      }
      memset(temp, 0, 64); //Wipe all data from buffer 
      otplength = onlykey_eeget_2FAtype(ptr, slot);
      if(temp[0] > 0)
      {
        if(temp[0] == 103) { //Google Auth
          Serial.println("Reading TOTP Key from EEPROM...");
          otplength = onlykey_flashget_totpkey(ptr, slot);
        #ifdef DEBUG
        Serial.println("Encrypted");
            for (int z = 0; z < otplength; z++) {
            Serial.print(temp[z], HEX);
            }
           Serial.println();
          #endif
        Serial.print("TOTP Key Length = ");
        Serial.println(otplength);
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
          Serial.println(GMT);
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
        if(temp[0] == 121 && !PDmode) { 
        Serial.println("Generating Yubico OTP...");
        #ifdef US_VERSION
        yubikey_simulate1((keybuffer + index), &ctx);
        yubikey_incr_usage(&ctx);
        index=index+44;
        #endif
        }
        if(temp[0] == 117 && !PDmode) { //U2F
        keybuffer[index] = 130;
        index++;
        }
      }
          //TODO remove debug print full keybuffer
          Serial.println("Displaying Full Keybuffer");
          for (int i=0; keybuffer[i]!=0x00; i++) {
            Serial.print
            (keybuffer[i]);
          }

}
/*************************************/
//Load Yubico AES, PUB, PRIV to EEPROM
/*************************************/
void YubikeyEEInit() {
  #ifdef US_VERSION
  uint8_t *ptr;
  uint8_t buffer[20];
  uint16_t counter  = 0x0000;

  ptr = (uint8_t *) &counter;
  yubikey_eeset_counter(ptr);
  
  memset (&buffer, 0, 20);
  yubikey_modhex_decode ((char *) &buffer, "vdhchdlbufru", 6); //Input Yubico OTP Public Identity
  onlykey_eeset_public(buffer, 6);
  //ptr = buffer;
  memset (&buffer, 0, 20);
  yubikey_hex_decode ((char *) &buffer, "47b3b9db8094", 6); //Input Yubico OTP Private Identity
  //ptr = (uint8_t *)"47b3b9db8094"; //Input Yubico OTP Private Identity
  onlykey_eeset_private(buffer);
  //ptr = (uint8_t *)"001768ad1525a6dce2730ab21a230758"; 
  memset (&buffer, 0, 20);
  yubikey_hex_decode ((char *) &buffer, "001768ad1525a6dce2730ab21a230758", 16); //Input Yubico OTP Secret Key
  onlykey_eeset_aeskey(buffer, 16);
  Serial.println("Yubico OTP Public, Private, and Secret Written");
  #endif
}

