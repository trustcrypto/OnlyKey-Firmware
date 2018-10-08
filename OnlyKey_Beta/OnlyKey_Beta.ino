/* Tim Steiner
 * Copyright (c) 2015-2018, CryptoTrust LLC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
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
 *    the OnlyKey Project (http://www.crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "OnlyKey Project" must not be used to
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
 *    the OnlyKey Project (http://www.crp.to/ok)"
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
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE
 * GRANTED BY THIS LICENSE. IF SOFTWARE RECIPIENT INSTITUTES PATENT LITIGATION
 * AGAINST ANY ENTITY (INCLUDING A CROSS-CLAIM OR COUNTERCLAIM IN A LAWSUIT)
 * ALLEGING THAT THIS SOFTWARE (INCLUDING COMBINATIONS OF THE SOFTWARE WITH
 * OTHER SOFTWARE OR HARDWARE) INFRINGES SUCH SOFTWARE RECIPIENT'S PATENT(S),
 * THEN SUCH SOFTWARE RECIPIENT'S RIGHTS GRANTED BY THIS LICENSE SHALL TERMINATE
 * AS OF THE DATE SUCH LITIGATION IS FILED. IF ANY PROVISION OF THIS AGREEMENT
 * IS INVALID OR UNENFORCEABLE UNDER APPLICABLE LAW, IT SHALL NOT AFFECT
 * THE VALIDITY OR ENFORCEABILITY OF THE REMAINDER OF THE TERMS OF THIS
 * AGREEMENT, AND WITHOUT FURTHER ACTION BY THE PARTIES HERETO, SUCH
 * PROVISION SHALL BE REFORMED TO THE MINIMUM EXTENT NECESSARY TO MAKE
 * SUCH PROVISION VALID AND ENFORCEABLE. ALL SOFTWARE RECIPIENT'S RIGHTS UNDER
 * THIS AGREEMENT SHALL TERMINATE IF IT FAILS TO COMPLY WITH ANY OF THE MATERIAL
 * TERMS OR CONDITIONS OF THIS AGREEMENT AND DOES NOT CURE SUCH FAILURE IN
 * A REASONABLE PERIOD OF TIME AFTER BECOMING AWARE OF SUCH NONCOMPLIANCE.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#define DEBUG //Enable Serial Monitor
#define US_VERSION //Define for US Version Firmware
#define OK_Color //Color Version

#include "sha256.h"
#include <EEPROM.h>
#include "T3MacLib.h"
#include <SoftTimer.h>
#include <password.h>
#include "sha1.h"
#include "totp.h"
#include "Time.h"
#include "onlykey.h"
#include "flashkinetis.h"
#include <RNG.h>
#include "base64.h"
#include <ADC.h>

#ifdef OK_Color
#include "Adafruit_NeoPixel.h"
#endif

/*************************************/
//Additional Libraries to Load for US Version
//These libraries will only be used if US_Version is defined
/*************************************/
extern uint8_t profilemode;
#ifdef US_VERSION
#include "yksim.h"
#include "uECC.h"
#include "ykcore.h"
#include <Crypto.h>
#include <AES.h>
#include <GCM.h>
#include "rsa.h"
#include <newhope.h>
#include "tweetnacl.h"
#endif
#ifdef OK_Color
#define OKversion "v0.2-beta.7c"
#else
#define OKversion "v0.2-beta.7o"
#endif
#define UNLOCKED "UNLOCKED" OKversion
#define UNINITIALIZED "UNINITIALIZED" OKversion
extern uint8_t NEO_Color;
/*************************************/
//RNG assignments
/*************************************/
bool calibrating = false;
uint8_t data[32];
extern uint8_t recv_buffer[64];
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
//Keypad / password assignments
/*************************************/
static int button_selected = 0;    //Key selected 1-6
static int pass_keypress = 1;  //The number key presses in current password attempt
static int session_attempts = 0; //The number of password attempts this session
static bool firsttime = true;
extern Password password;
extern uint8_t TIMEOUT[1];
extern uint8_t TYPESPEED[1];
extern uint8_t KeyboardLayout[1];
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
//PIN HASH
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
//SoftTimer
/*************************************/
#define THRESHOLD   .5
#define TIME_POLL 75 // poll "key" every 75 ms
Task taskKey(TIME_POLL, checkKey);
Task taskKB(50, sendKey); // Default send kb codes every 50 ms
Task taskInitialized(1000, sendInitialized);
char keybuffer[EElen_url+EElen_addchar+EElen_delay+EElen_addchar+EElen_username+EElen_delay+EElen_addchar+EElen_password+EElen_addchar+EElen_2FAtype+64+EElen_addchar]; //Buffer to hold all keystrokes
char *pos;
extern uint8_t isfade;
/*************************************/
//CRYPTO
/*************************************/
extern uint8_t Challenge_button1;
extern uint8_t Challenge_button2;
extern uint8_t Challenge_button3;
extern uint8_t CRYPTO_AUTH;
extern int packet_buffer_offset;
extern uint8_t packet_buffer_details[2];
extern uint8_t outputU2F;
extern uint8_t sshchallengemode;
extern uint8_t pgpchallengemode;
/*************************************/
//Arduino Setup
/*************************************/
void setup() {
  delay(100);
  #ifdef DEBUG
  Serial.begin(9600);
  #endif
  #ifdef US_VERSION
  profilemode = STDPROFILE1;
  #else
  profilemode = NONENCRYPTEDPROFILE; 
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
  uint8_t *ptr;
  ptr = nonce;
  initcheck = onlykey_flashget_noncehash (ptr, 32); //Check if first time use
  integrityctr1++;
  /* //dump flash storage
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
      unlocked = true; //Flash is not protected, First time use
      initialized = false;
      #ifdef DEBUG
      Serial.println("UNLOCKED, NO PIN SET");
      #endif
  } else if(FTFL_FSEC==0x44 && initcheck) {
        ptr = p1hash;
        onlykey_flashget_pinhashpublic (ptr, 32); //store PIN hash
        ptr = sdhash;
        onlykey_flashget_selfdestructhash (ptr); //store self destruct PIN hash
        ptr = p2hash;
        onlykey_flashget_2ndpinhashpublic (ptr); //store plausible deniability PIN hash
        ptr = TYPESPEED;
        onlykey_eeget_typespeed(ptr);
        #ifdef DEBUG
        Serial.println("typespeed = ");
        Serial.println(*ptr);
        #endif
        if (*ptr  == 0) {
          TYPESPEED[0] = 4;
         } else if (*ptr  <= 10) {
          TYPESPEED[0]=*ptr;
         }
        ptr = TIMEOUT;
        onlykey_eeget_timeout(ptr);
        ptr = KeyboardLayout;
        onlykey_eeget_keyboardlayout(ptr);
        #ifdef DEBUG
        Serial.println("KeyboardLayout = ");
        Serial.println(*ptr);
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
  CHIP_ID();
  RNG.stir((uint8_t*)ID, sizeof(ID)); //Stir in unique 128 bit Freescale chip ID
  RNG.stir((uint8_t*)nonce, sizeof(nonce)); //Stir in unique nonce that is generated from user entropy when OK is first initialized
  unsigned int analog1 = analogRead(ANALOGPIN1);
  RNG.stir((uint8_t *)analog1, sizeof(analog1), sizeof(analog1)*2);
  unsigned int analog2 = analogRead(ANALOGPIN2);
  RNG.stir((uint8_t *)analog2, sizeof(analog2), sizeof(analog2)*2);
  #ifdef DEBUG
  Serial.print("EEPROM Used ");
  Serial.println(EEpos_failedlogins);
  Serial.println(FTFL_FSEC, HEX);
  #endif
  rngloop(); //Start RNG
  #ifdef OK_Color
  initColor();
  rainbowCycle(4, 2);
  #else
  pinMode(BLINKPIN, OUTPUT);
  fadein();//Additional delay to make sure button is not pressed during plug into USB
  fadeout();
  fadein();
  fadeout();
  #endif
/*For testing with python-onlykey to disable PIN
 unlocked=true;
 configmode=true;
 initialized=true;
*/


  SoftTimer.add(&taskKey);
}

/*************************************/

extern elapsedMillis idletimer;
//Main Loop, Read Key Press Using Capacitive Touch
/*************************************/
void checkKey(Task* me) {
  static int key_press = 0;
  static int key_on = 0;
  static int key_off = 0;

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

  if (unlocked) {
    recvmsg();
    if(initialized && initcheck) {
    #ifdef US_VERSION
    yubikey_incr_time();
    #endif
    if (TIMEOUT[0] && idletimer >= (TIMEOUT[0]*60000)) {
      unlocked = false;
      firsttime = true;
      password.reset(); //reset the guessed password to NULL
      pass_keypress=1;
      memset(profilekey, 0, 32);  
    }
    }
  }

  if(configmode && unlocked && !isfade) {
      #ifdef OK_Color
      NEO_Color = 1; //Red
      #endif
      fadeon();
  }

    //Uncomment to test RNG
    //RNG2(data, 32);
    //printHex(data, 32);

  rngloop(); //Perform regular housekeeping on the random number generator.

  if (touchread1 > (touchread1ref+100)) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '5';
    //Serial.println(touchread1);
  }
    else if (touchread2 > (touchread2ref+100)) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '2';
    //Serial.println(touchread2);
  }
    else if (touchread3 > (touchread3ref+100)) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '1';
    //Serial.println(touchread3);
  }
   else if (touchread4 > (touchread4ref+100)) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '3';
    //Serial.println(touchread4);
  }
   else if (touchread5 > (touchread5ref+100)) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '4';
    //Serial.println(touchread5);
  }
   else if (touchread6 > (touchread6ref+100)) {
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
    if (!unlocked){
      #ifdef OK_Color
      setcolor(0); // NEO Pixel OFF
      #else
      analogWrite(BLINKPIN, 0); //LED OFF
      #endif
    } else if (!isfade) {
      #ifdef OK_Color
      setcolor(85); // NEO Pixel ON Green
      #else
      analogWrite(BLINKPIN, 255); //LED ON
      #endif
    }
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
    while ( isfade && NEO_Color == 170 && (uint8_t)*pos != 00 && (uint8_t)*pos != 9 ) {
       pos++;
    }
    if ((uint8_t)*pos == 00){
    #ifdef DEBUG
    Serial.print(pos);
    #endif
    Keyboard.end();
    SoftTimer.remove(&taskKB);
    SoftTimer.add(&taskKey);
    return;
    }
    else if ((uint8_t)*pos == 1) {
        if (!isfade) {
          Keyboard.press(KEY_TAB);
          delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
          Keyboard.releaseAll();
          delay(((TYPESPEED[0]*TYPESPEED[0])*2));
        }
        pos++;
    }
    else if ((uint8_t)*pos == 2) {
        if (!isfade) {
          Keyboard.press(KEY_RETURN);
          delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
          Keyboard.releaseAll();
          delay(((TYPESPEED[0]*TYPESPEED[0])*2));
        }
        pos++;
    }
    else if ((uint8_t)*pos == 9) {
        if(profilemode==NONENCRYPTEDPROFILE) return;
        #ifdef US_VERSION
        #ifdef DEBUG
        Serial.println("Starting U2F...");
        #endif
        u2f_button = 1;
        uECC_set_rng(&RNG2);
        unsigned long u2fwait = millis() + 4000;
        while(u2f_button && millis() < u2fwait) {
        recvmsg();
        }
        u2f_button = 0;
        Keyboard.end();
        SoftTimer.remove(&taskKB);
        SoftTimer.add(&taskKey);
        #endif
        return;
    }
    else if ((uint8_t)*pos >= 10 && (uint8_t)*pos <= 31) {
        if (!isfade) delay((*pos - 10)*1000);
        pos++;
    }
    else if (*pos){
        if (!isfade) {
          Keyboard.press(*pos);
          delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
          Keyboard.releaseAll();
          delay(((TYPESPEED[0]*TYPESPEED[0])*2));
        }
        pos++;
    }
}
/*************************************/
//Password Checking Loop
/*************************************/
void payload(int duration) {
   if (!unlocked) {
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
   uint8_t *ptr;
   ptr = pass_attempts;
    if (session_attempts >= 3) { //Limit 3 password attempts per session to make sure that someone does not accidentally wipe device
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
    return;
    }
   integrityctr1++;
   if (firsttime) //Get failed login counter from eeprom and increment for new login attempt
   {
   onlykey_eeget_failedlogins (ptr);
   if (pass_attempts[0]) {
    ptr = sincelastregularlogin;
    onlykey_eeget_sincelastregularlogin (ptr);
    #ifdef DEBUG
    Serial.println("Failed PIN attempts since last successful regular PIN entry");
    Serial.println(sincelastregularlogin[0]);
    #endif
    if (sincelastregularlogin[0] >= 20) {
    for (int i =0; i<32; i++) {
      p1hash[i] = 0xFF;
    }
    ptr = p1hash;
    onlykey_flashset_pinhashpublic (ptr); //permanently wipe pinhash
    onlykey_eeset_sincelastregularlogin (0);
   } else {
    sincelastregularlogin[0]++;
    onlykey_eeset_sincelastregularlogin (ptr);
   }
   }
   ptr = pass_attempts;
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
   onlykey_eeset_failedlogins (ptr);
   firsttime = false;
   }
   integrityctr2++;
   password.append(button_selected);
   integrityctr1++;
   if (unlocked || password.profile1hashevaluate() || password.profile2hashevaluate()) {
    integrityctr2++;
        if (unlocked != true) //A correct PIN was just entered do the following for first login
        {
          onlykey_eeset_failedlogins(0); //Set failed login counter to 0
          password.reset(); //reset the guessed password to NULL
          session_attempts=0;
          hidprint(UNLOCKED);
          SoftTimer.remove(&taskInitialized);
          #ifdef DEBUG
          Serial.println("UNLOCKED");
          #endif
          fadeon();
          fadeoff(85);
          if (profilemode!=NONENCRYPTEDPROFILE) {
#ifdef US_VERSION
        yubikeyinit();
          U2Finit();
          onlykey_eeset_sincelastregularlogin(0); //Set failed logins since last regular login to 0
#endif
          }
          idletimer=0;
          unlocked = true;
          if (configmode) {
            #ifdef OK_Color
            NEO_Color = 1; //Red
            #endif
            fadeon();
          }
          return;
        }
        else if (PINSET==0 && !initcheck) {
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
        else if (PINSET<=9) {
            if(profilemode!=NONENCRYPTEDPROFILE){
            #ifdef US_VERSION
            #ifdef DEBUG
            Serial.print("2nd profile password appended with ");
            Serial.println(button_selected-'0');
            #endif
            #endif
            }
            return;
        }      
      Keyboard.begin();
      *keybuffer = '\0';
      #ifdef DEBUG
      Serial.print("Button selected");
      Serial.println(button_selected-'0');
      #endif
      if (CRYPTO_AUTH == 1 && button_selected==Challenge_button1 && isfade) {
        if (profilemode==NONENCRYPTEDPROFILE) return;
        #ifdef US_VERSION
        #ifdef DEBUG
        Serial.print("Challenge1 entered");
        Serial.println(button_selected-'0');
        #endif
        CRYPTO_AUTH++;
        #endif
        return;
      } else if (CRYPTO_AUTH == 2 && button_selected==Challenge_button2 && isfade) {
        #ifdef DEBUG
        Serial.print("Challenge2 entered");
        Serial.println(button_selected-'0');
        #endif
        CRYPTO_AUTH++;
        return;
      } else if ((CRYPTO_AUTH == 3 && button_selected==Challenge_button3 && isfade) || (sshchallengemode==1 && isfade) || (pgpchallengemode==1 && isfade)) {
        if (profilemode==NONENCRYPTEDPROFILE) return;
        #ifdef US_VERSION
        #ifdef DEBUG
        Serial.print("Challenge3 entered");
        Serial.println(button_selected-'0');
        #endif
        CRYPTO_AUTH = 4;
        sshchallengemode = 0;
        pgpchallengemode = 0;
        if (!outputU2F) {
        Keyboard.press(KEY_RETURN);
        delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
        Keyboard.releaseAll();
        delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
        }
        if(packet_buffer_details[0] == 0xED) {
          recv_buffer[4] = packet_buffer_details[0];
          recv_buffer[5] = packet_buffer_details[1];
          SIGN(recv_buffer);
        }
        if(packet_buffer_details[0] == 0xF0) {
          recv_buffer[4] = packet_buffer_details[0];
          recv_buffer[5] = packet_buffer_details[1];
          DECRYPT(recv_buffer);
        }
        fadeoff(0);
        #endif
        return;
      } else if (CRYPTO_AUTH) { //Wrong challenge was entered
        if (profilemode==NONENCRYPTEDPROFILE) return;
        #ifdef US_VERSION
        CRYPTO_AUTH = 0;
        Challenge_button1 = 0;
        Challenge_button2 = 0;
        Challenge_button3 = 0;
        fadeoff(1);
        if (!outputU2F) {
          hidprint("Error incorrect challenge was entered");
          analogWrite(BLINKPIN, 255); //LED ON
          Keyboard.press(KEY_RETURN);
          delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
          Keyboard.releaseAll();
          delay((TYPESPEED[0]*TYPESPEED[0]/3)*8);
        }
        return;
        #endif
      } else if (duration >= 50 && button_selected=='1' && !isfade) {
        if (profilemode==NONENCRYPTEDPROFILE) return;
        #ifdef US_VERSION
        SoftTimer.remove(&taskKey);
        backup();
        SoftTimer.add(&taskKey);
        #endif
        return;
      } else if (duration >= 50 && button_selected=='2' && !isfade) {
        GETSLOTLABELS(1);
        return;
      } else if (duration >= 50 && button_selected=='3' && !isfade) {
        GETKEYLABELS(1);
        return;
      } else if (duration >= 50 && button_selected=='6' && !isfade) {
          if(profilemode!=NONENCRYPTEDPROFILE) {
            #ifdef US_VERSION
            integrityctr1++;
            configmode=true;
            unlocked = false;
            firsttime = true;
            password.reset(); //reset the guessed password to NULL
            integrityctr2++;
            pass_keypress=1;
            #endif
          }
          return;
      } else {
        #ifdef OK_Color
        setcolor(0); // NEO Pixel OFF
        #else
        analogWrite(BLINKPIN, 0); //LED OFF
        #endif
        if (duration <= 10 && !configmode) gen_press();
        if (duration >= 11 && !configmode) gen_hold();
        pos = keybuffer;
        SoftTimer.remove(&taskKey);
        SoftTimer.add(&taskKB, (unsigned long)TYPESPEED[0]);
      }
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
  idletimer=0;
  int slot;
  if (profilemode) {
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
  idletimer=0;
  int slot;
  if (profilemode) {
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
  int urllength;
  int usernamelength;
  int passwordlength;
  int otplength;
  uint8_t addchar1;
  uint8_t addchar2;
  uint8_t addchar3;
  uint8_t addchar4;
  uint8_t addchar5;
  int delay1 = 0;
  int delay2 = 0;
  int delay3 = 0;
  uint8_t *ptr;
  int slot=s;
  index = 0;
      onlykey_eeget_addchar(&addchar5, slot);
      #ifdef DEBUG
      Serial.println("Additional Character");
      Serial.println(addchar5);
      #endif
      addchar1 = addchar5 & 0x3; //After Username
      addchar2 = (addchar5 >> 4) & 0x3; //After Password
      addchar3 = (addchar5 >> 6) & 0x1; //After OTP
      addchar4 = (addchar5 >> 2) & 0x1; //Before Username
      addchar5 = (addchar5 >> 3) & 0x1; //Before OTP
      if (isfade && NEO_Color != 170) return; //Only U2F Button
      #ifdef DEBUG
      Serial.print("Slot Number ");
      Serial.println(button_selected-'0');
      #endif
      memset(temp, 0, 64); //Wipe all data from buffer
      memset(keybuffer, 0, sizeof(keybuffer)); //Wipe all data from keybuffer
      ptr = temp;
      urllength = onlykey_flashget_url(ptr, slot);
      if(urllength > 0)
      {
        #ifdef DEBUG
        Serial.println("Reading URL from Flash...");
        Serial.print("URL Length = ");
        Serial.println(urllength);
        #endif
        if (profilemode!=NONENCRYPTEDPROFILE) {
        #ifdef DEBUG
        Serial.println("Encrypted");
            for (int z = 0; z < urllength; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
        #endif
        #ifdef US_VERSION
        aes_gcm_decrypt(temp, slot, 15, profilekey, urllength);
        #endif
        }
        ByteToChar2(temp, keybuffer, urllength, index);
        #ifdef DEBUG
            Serial.println("Unencrypted");
            for (int z = 0; z < urllength; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
        #endif
        index=urllength;
        #ifdef DEBUG
        Serial.println("Setting RETURN after URL");
        #endif
        keybuffer[index] = 2;
        index++;
      }
      memset(temp, 0, 64); //Wipe all data from buffer
      onlykey_eeget_delay1(ptr, slot);
      if(temp[0] > 0)
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
      if(addchar4)
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
      usernamelength = onlykey_flashget_username(ptr, slot);
      if(usernamelength > 0)
      {
        #ifdef DEBUG
        Serial.println("Reading Username from Flash...");
        Serial.print("Username Length = ");
        Serial.println(usernamelength);
        #endif
        if (profilemode!=NONENCRYPTEDPROFILE) {
        #ifdef DEBUG
        Serial.println("Encrypted");
            for (int z = 0; z < usernamelength; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
        #endif
        #ifdef US_VERSION
        aes_gcm_decrypt(temp, slot, 2, profilekey, usernamelength);
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
        index=usernamelength+index;
      }
      memset(temp, 0, 64); //Wipe all data from buffer
      if(addchar1)
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
      onlykey_eeget_delay2(ptr, slot);
      if(temp[0] > 0)
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
      passwordlength = onlykey_eeget_password(ptr, slot);
      if(passwordlength > 0)
      {
        #ifdef DEBUG
        Serial.println("Reading Password from EEPROM...");
        Serial.print("Password Length = ");
        Serial.println(passwordlength);
        #endif
        if (profilemode!=NONENCRYPTEDPROFILE) {
        #ifdef DEBUG
        Serial.println("Encrypted");
            for (int z = 0; z < passwordlength; z++) {
            Serial.print(temp[z], HEX);
            }
            Serial.println();
          #endif
        #ifdef US_VERSION
        aes_gcm_decrypt(temp, slot, 5, profilekey, passwordlength);
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
      if(addchar2)
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
      onlykey_eeget_delay3(ptr, slot);
      if(temp[0] > 0)
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
      if(addchar5)
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
      otplength = onlykey_eeget_2FAtype(ptr, slot);
      if(temp[0] > 0)
      {
        if(temp[0] == 103) { //Google Auth
          #ifdef DEBUG
          Serial.println("Reading TOTP Key from Flash...");
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
          if (profilemode!=NONENCRYPTEDPROFILE) aes_gcm_decrypt(temp, slot, 9, profilekey, otplength);
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
        if(temp[0] == 121 && profilemode!=NONENCRYPTEDPROFILE) {
        #ifdef DEBUG
        Serial.println("Generating Yubico OTP...");
        #endif
        #ifdef US_VERSION
        yubikeysim(keybuffer + index);
        index=index+44;
        #endif
        }
        if(temp[0] == 117 && profilemode!=NONENCRYPTEDPROFILE) { //U2F
        keybuffer[index] = 9;
        index++;
        }
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
    hidprint("INITIALIZED");
    #ifdef DEBUG
    Serial.println("INITIALIZED");
    #endif
}
