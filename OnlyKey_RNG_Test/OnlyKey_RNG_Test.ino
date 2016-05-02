// OnlyKey Alpha

#include "sha256.h"
#include <EEPROM.h>
#include "uecc.h"
#include "ykcore.h"
#include "yksim.h"
#include <softtimer.h>
#include <password.h>
//http://www.arduino.cc/playground/uploads/Code/Password.zip
#include "sha1.h"
#include "totp.h"
#include "Time.h"
#include "onlykey.h"
#include "flashkinetis.h"
#include <Crypto.h>
#include <RNG.h>
#include <transistornoisesource.h>

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
#define RNG_APP_TAG "OnlyKey"
// Noise source to seed the random number generator.
TransistorNoiseSource noise(A0);
bool calibrating = false;
/*************************************/

//SoftTimer
/*************************************/
#define THRESHOLD   .5
#define TIME_POLL 100 // poll "key" every 100 ms
#define TIME_SEND  10 // send kb codes every 10 ms
Task taskKey(TIME_POLL, checkKey);
Task taskKB (TIME_SEND, sendKey);
char otp[YUBIKEY_OTP_MAXSIZE];
char *pos;
/*************************************/

//Keypad password assignments
/*************************************/
static int button_selected = 0;    //Key selected 1-6
static int pass_keypress = 1;  //The number key presses in current password attempt
static int session_attempts = 0; //The number of password attempts this session
static bool firsttime = true;
extern Password password;
/*************************************/

//Google Auth key converted from base 32 to hex
/*************************************/
uint8_t hmacKey1[] PROGMEM = {0x60, 0xAF, 0x89, 0x87, 0x65, 0xF0, 0x39, 0xAC, 0xF9, 0x51};
TOTP totp1 = TOTP(hmacKey1, 10);
uint8_t hmacKey2[] = {0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72, 0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72};
TOTP totp2 = TOTP(hmacKey2, 20);
uint8_t hmacKey3[] = {0x60, 0xAF, 0x89, 0x87, 0x65, 0xF0, 0x39, 0xAC, 0xF9, 0x51};
TOTP totp3 = TOTP(hmacKey3, 10);
uint8_t hmacKey4[] = {0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72, 0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72};
TOTP totp4 = TOTP(hmacKey4, 20);
uint8_t hmacKey5[] = {0x60, 0xAF, 0x89, 0x87, 0x65, 0xF0, 0x39, 0xAC, 0xF9, 0x51};
TOTP totp5 = TOTP(hmacKey5, 10);
uint8_t hmacKey6[] = {0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72, 0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72};
TOTP totp6 = TOTP(hmacKey6, 20);
uint8_t hmacKey7[] = {0x60, 0xAF, 0x89, 0x87, 0x65, 0xF0, 0x39, 0xAC, 0xF9, 0x51};
TOTP totp7 = TOTP(hmacKey7, 10);
uint8_t hmacKey8[] = {0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72, 0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72};
TOTP totp8 = TOTP(hmacKey8, 20);
uint8_t hmacKey9[] = {0x60, 0xAF, 0x89, 0x87, 0x65, 0xF0, 0x39, 0xAC, 0xF9, 0x51};
TOTP totp9 = TOTP(hmacKey9, 10);
uint8_t hmacKey10[] = {0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72, 0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72};
TOTP totp10 = TOTP(hmacKey10, 20);
uint8_t hmacKey11[] = {0x60, 0xAF, 0x89, 0x87, 0x65, 0xF0, 0x39, 0xAC, 0xF9, 0x51};
TOTP totp11 = TOTP(hmacKey11, 10);
uint8_t hmacKey12[] = {0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72, 0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72};
TOTP totp12 = TOTP(hmacKey12, 20);
/*************************************/

//U2F assignments
/*************************************/
static int u2f_button = 0;
/*************************************/

//Yubikey 
/*************************************/
yubikey_ctx_st ctx;
/*************************************/

unsigned long previousMillis = 0;  
//Arduino Setup 
/*************************************/
void setup() {
  Serial.begin(9600);
  //while (!Serial) ; // wait for serial
  delay(1000);
  pinMode(BLINKPIN, OUTPUT);
  // Initialize the random number generator.
  RNG.begin(RNG_APP_TAG, EEpos_noncehash);
  YubikeyInit(); //Set keys and counters
  
  //TODO remove this rescue function once flash security is tested
  for (int i = 0; i < 100; i++)
  {
    Serial.print(".");
    switch(Serial.read()) {
    case 'a':
      Serial.print("FTFL_FSEC=0x");
      Serial.println(FTFL_FSEC,HEX);
    break;
    case 'b':
      //FTFL_FSEC!=0x64;
      //flashSecurityLockBits();
      Serial.print("Flash security bits ");
      Serial.println("written successfully");
      Serial.println("\nHit the program button to very basically reset Teensy now.");
    break;
    case 'c':
      Serial.println("By the time you read this it should be safe");
      Serial.println("to hit the program button to upload a new (or");
      Serial.println("the previous) sketch. Teensy will not be");
      Serial.println("responsive again until you do.");
      flashQuickUnlockBits();
     break;
  }
  delay(70);
  }
  
  Serial.print("FTFL_FSEC=0x");
  Serial.println(FTFL_FSEC,HEX);
  //TODO fix mass storage write should be 0x64 https://forum.pjrc.com/threads/28783-Upload-Hex-file-from-Teensy-3-1
  if(FTFL_FSEC!=0x44) { 
    unlocked = true; //Flash is not protected, First time use
  }
  SoftTimer.add(&taskKey);
}
/*************************************/

//Main Loop, Read Key Press Using Capacitive Touch
/*************************************/
void checkKey(Task* me) {
  static int key_press = 0;
  static int key_on = 0;
  static int key_off = 0;
  static int count;
  uint8_t temp[32];
      uint8_t *ptr;
      ptr = temp;
 

  rngloop(); //
  unsigned long currentMillis = millis();
  if (currentMillis - previousMillis >= 1000) {
    previousMillis = currentMillis;
  getrng(ptr, 32);
    Keyboard.println();
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

  /*
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
  }
  */

  if ((key_press > 0) && (key_off > THRESHOLD)) {
    payload(key_press);
    key_press = 0;
   }
}
/*************************************/

//Type out on Keyboard
/*************************************/
void sendKey(Task* me) {
  if (*pos) {
    Keyboard.write(*pos);
    pos++;
  } else {
    Keyboard.write('\n');
    Keyboard.end();
    SoftTimer.remove(&taskKB);
    SoftTimer.add(&taskKey);
  }

}
/*************************************/

//Keypad passcode checker
/*************************************/
void payload(int duration) {
   blink(1);
   extern int PINSET;
   uint8_t pass_attempts[1];
   uint8_t *ptr;
   ptr = pass_attempts;

    if (session_attempts >= 3) { //Limit 3 password attempts per session to make sure that someone does not accidentally wipe device
    Serial.print("password attempts for this session exceeded, remove OnlyKey and reinsert to attempt login");
    Serial.println();
    return;
    }
   
   if (firsttime==true) //Get failed login counter from eeprom and increment for new login attempt
   {
   yubikey_eeget_failedlogins (ptr);
   pass_attempts[0]++;
   //Serial.println(pass_attempts[0]);
   if (pass_attempts[0] >= 10) {
   factorydefault();
   pass_attempts[0] = 0;
   return;
   }
   yubikey_eeset_failedlogins (ptr); 
   firsttime = false;
   }
   
   if (unlocked == true || password.hashevaluate() == true) { 
        yubikey_eeset_failedlogins(0);
        unlocked = true;
      if (PINSET > 0) {
       password.append(button_selected);
       return;
        }
      *otp = '\0';
      if (duration <= 10) gen_token();
      if (duration >= 11) gen_static();
      pos = otp;
      Keyboard.begin();
      SoftTimer.remove(&taskKey);
      SoftTimer.add(&taskKB);
  }
       
      // if (selfdestruct.evaluate() == true) factorydefault(); //TODO Self Destruct PIN
   else {
    if (pass_keypress <= MAX_PASSWORD_LENGTH) {
        password.append(button_selected);
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
        yubikey_eeget_failedlogins (ptr);
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



void gen_token(void) {
  
  long GMT;
  char* newcode;
  blink(1);
  char buffer[32];
  switch (button_selected) {
    case '1': 
      break;
    case '2':
      break;
    case '3':
      break;
    case '4':
      break;
    case '5':
      break;
    case '6':
      break;
    default:
      break;
    
  }
}


/*************************************/

void gen_static(void) {
  char buffer[16];
  switch (button_selected) {
    case '1':
      break;
    case '2':
      break;
    case '3':
      break;
    case '4':
      break;
    case '5':
      break;
    case '6':
      break;
    default:
      break;
  }
}
/*************************************/

void YubikeyInit() {
  unsigned long time1, time2;
  
  uint32_t seed1         = analogRead(0);

  uint8_t aeskey1[16];

  uint8_t privID1[6];

  uint8_t pubID1[16];

  uint16_t counter;
  uint8_t *ptr;

  char aes_id1[32+1];

  char public_id1[32+1];

  char private_id1[12+1];


  uint32_t time = 0x010203;

  Serial.println("Initializing YubiKey ...");
  time1 = micros();

  ptr = aeskey1;
  yubikey_eeget_aeskey(ptr);
  yubikey_hex_encode(aes_id1, (char *)aeskey1, 6);
  
  ptr = (uint8_t*) &counter;
  yubikey_eeget_counter(ptr);

  
  ptr = privID1;
  yubikey_eeget_private(ptr);
  yubikey_hex_encode(private_id1, (char *)privID1, 6);

  
  ptr = pubID1;
  yubikey_eeget_public(ptr);
  yubikey_hex_encode(public_id1, (char *)pubID1, 6);

      Serial.println("aeskey1");
    Serial.println(aes_id1);

    Serial.println("public_id1");
  Serial.println(public_id1);
    Serial.println("private_id1");
  Serial.println(private_id1);
    Serial.println("counter");
  Serial.println(counter);
      Serial.println("time");
  Serial.println(time);
      Serial.println("seed1");
  Serial.println(seed1);
  
 
  
  yubikey_init1(&ctx, aeskey1, public_id1, private_id1, counter, time, seed1);
 
  yubikey_incr_counter(&ctx);
 
  
  ptr = (uint8_t*) &(ctx.counter);
  yubikey_eeset_counter(ptr);
  
  time2 = micros();
  Serial.print("done in ");
  Serial.print(time2-time1);
  Serial.println(" micros");
}

/*************************************/

void YubikeyEEInit() {
  
  unsigned long time1, time2;
  uint8_t *ptr, len;
  uint16_t counter  = 0x0000;
  uint8_t buffer[20];

  Serial.println("Resetting EEPROM of YubiKeySim ...");
  time1 = micros();

  memset (&buffer, 0, 20);
  yubikey_modhex_decode ((char *) &buffer, "idhgelivduibtjjeuvrggeeiluuictrf", 16);
  //yubikey_eeset_aeskey1(buffer, 16);
 

  ptr = (uint8_t *) &counter;
  //yubikey_eeset_counter1(ptr);
  
  memset (&buffer, 0, 20);
  yubikey_modhex_decode ((char *) &buffer, "hdulurfvtubk", 6);
  //yubikey_eeset_private1(buffer);

  memset (&buffer, 0, 20);
  yubikey_modhex_decode ((char *) &buffer, "vvncrccvidvh", 6);
  //yubikey_eeset_public1(buffer, 6);
 
  memset (&buffer, 0, 20);
  yubikey_modhex_decode ((char *) &buffer, "OpenKey", 16);
  //yubikey_eeset_password(buffer, 16);
 

  time2 = micros();
  Serial.print("done in ");
  Serial.print(time2-time1);
  Serial.println(" micros");

  
  Serial.print(EEpos_aeskey);
  Serial.println("= aeskey1 pos");

  Serial.print(EEpos_counter);
  Serial.println("= counter1 pos");
  Serial.print(EElen_counter);
    Serial.println("= counter1 len");

  Serial.print(EEpos_private);
  Serial.println("= private1 pos");
  Serial.print(EElen_private);
    Serial.println("= private1 len");
    
  Serial.print(EEpos_public);
    Serial.println("= public1 pos");
  Serial.print(EElen_public);
    Serial.println("= public1 len");
    
  Serial.print(EEpos_password1);
    Serial.println("= static1 pos");
  Serial.print(EElen_password);
    Serial.println("= static1 len");
    
  Serial.print(EEpos_keylen);
  Serial.println("= keylen1 pos");
  Serial.print(EElen_keylen);
  Serial.println("= keylen1 len");
  yubikey_eeget_keylen(&len);
  Serial.print("> ");
  Serial.println(len);

  Serial.print(EEpos_ctrlen);
  Serial.println("=ctrlen1 pos");
  Serial.print(EElen_ctrlen);
    Serial.println("=ctrlen1 len");
  yubikey_eeget_ctrlen(&len);
  Serial.print("> ");
  Serial.println(len);

  Serial.print(EEpos_prvlen);
  Serial.println("= prvlen1 pos");
  Serial.print(EElen_prvlen);
    Serial.println("= prvlen1 len");
  yubikey_eeget_prvlen(&len);
  Serial.print("> ");
  Serial.println(len);

  Serial.print(EEpos_publen);
  Serial.println("= publen1 pos");
  Serial.print(EElen_publen);
    Serial.println("= publen1 len");
  yubikey_eeget_publen(&len);
  Serial.print("> ");
  Serial.println(len);

  Serial.print(EEpos_password1len);
  Serial.println("= statlen1 pos");
  Serial.print(EElen_passwordlen);
    Serial.println("= statlen1 len");
  yubikey_eeget_passwordlen1(&len);
  Serial.print("> ");
  Serial.println(len);

 
}


/*************************************/



void rngloop() {
    // Track changes to the calibration state on the noise source.
    bool newCalibrating = noise.calibrating();
    if (newCalibrating != calibrating) {
        calibrating = newCalibrating;
        Serial.println("calibrating");
    }
    // Perform regular housekeeping on the random number generator.
    RNG.loop();
}



