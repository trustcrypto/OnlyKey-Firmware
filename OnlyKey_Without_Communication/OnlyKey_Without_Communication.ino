// Six Button Yubikey, Google Authenticator, and U2F simulator using Teensy 3.x capacitive touch sensors
//
// use touch sensor on Pins 01, 15, 16, 17, 22, and 23 as key press

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
#include "okconfig.h"
//#include "u2f.h"



//Teensy PIN assignments
/*************************************/
#define BLINKPIN   13
#define TOUCHPIN1    01
#define TOUCHPIN2    15
#define TOUCHPIN3    16
#define TOUCHPIN4    17
#define TOUCHPIN5    22
#define TOUCHPIN6    23
/*************************************/

//2FA Slot Assignments
/*************************************/
#define Yubikey1    '1'  //Slot 1
#define Yubikey2    '2'  //Slot2
#define TOTP1    '3'  //Slot3
#define TOTP2    '4'  //Slot4
#define TOTP3    '5'  //Slot5
#define U2F   '6'  //Slot6
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

//Keypad password variables and set password
/*************************************/
static int button_selected = 0;    //Key selected 1-6
static int pass_keypress = 1;  //The number key presses in current password attempt
static int failed_attempts = 0; //Need to have this counter stored in EEPROM and flashSecurityLockBits enabled
Password password = Password( "3436353" );
Password selfdestruct = Password( "6565656" );
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
static int u2f_button = 0;

//Yubikey 
/*************************************/
yubikey_ctx_st1 ctx1;

/*************************************/



//Random Number Generator
/*************************************/
extern "C" {

  static int RNG(uint8_t *dest, unsigned size) {
    // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
    // random noise). This can take a long time to generate random data if the result of analogRead(0)
    // doesn't change very frequently.
    while (size) {
      uint8_t val = 0;
      for (unsigned i = 0; i < 8; ++i) {
        int init = analogRead(0);
        int count = 0;
        while (analogRead(0) == init) {
          ++count;
        }

        if (count == 0) {
          val = (val << 1) | (init & 0x01);
        } else {
          val = (val << 1) | (count & 0x01);
        }
      }
      *dest = val;
      ++dest;
      --size;
    }
    // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
    return 1;
  }

}  // extern "C"
/*************************************/


//Arduino Setup 
/*************************************/
void setup() {
  Serial.begin(9600);
  //while (!Serial) ; // wait for serial
  delay(1000);
  pinMode(BLINKPIN, OUTPUT);
  //uncomment YubikeyEEInit to overwrite keys and counters
  //YubikeyEEInit();
  YubikeyInit(); //Set keys and counters
  SoftTimer.add(&taskKey);
}
/*************************************/

//Main Loop to Read Key Press Using Capacitive Touch
/*************************************/
void checkKey(Task* me) {
  static int key_press = 0;
  static int key_on = 0;
  static int key_off = 0;
  static int count;
  yubikey_incr_timestamp1(&ctx1);



  //u2f.recvmsg(); //TODO move this to inside if statement below
  //OK.recvmsg(); //TODO move this to inside if statement below
  if (password.evaluate() == true) {
    uECC_set_rng(&RNG); //seed random number generator
    
  }
  
  if (touchRead(TOUCHPIN1) > 1000) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '5';
    Serial.println("Button #5 Pressed, Sensor reads ");
    Serial.println(touchRead(TOUCHPIN1));
    //delay(5);
  } 
    else if (touchRead(TOUCHPIN2) > 1000) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '2';
    //Serial.println("Button #2 Pressed, Sensor reads ");
    //Serial.println(touchRead(TOUCHPIN2));
    //delay(5);
  } 
    else if (touchRead(TOUCHPIN3) > 1000) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '1';
    //Serial.println("Button #1 Pressed, Sensor reads ");
    //Serial.println(touchRead(TOUCHPIN3));
    //delay(5);
  } 
   else if (touchRead(TOUCHPIN4) > 1000) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '3';
    //Serial.println("Button #3 Pressed, Sensor reads ");
    //Serial.println(touchRead(TOUCHPIN4));
    //delay(5);
  } 
   else if (touchRead(TOUCHPIN5) > 1000) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '4';
    //Serial.println("Button #4 Pressed, Sensor reads ");
    //Serial.println(touchRead(TOUCHPIN5));
    //delay(5);
  } 
   else if (touchRead(TOUCHPIN6) > 1000) {
    key_off = 0;
    key_press = 0;
    key_on += 1;
    button_selected = '6';
    //Serial.println("Button #6 Pressed, Sensor reads ");
    //Serial.println(touchRead(TOUCHPIN6));
    //delay(5);
  } 

  else {
    if (key_on > THRESHOLD) key_press = key_on;
    key_on = 0;
    key_off += 1;
  }

  if ((key_press > 0) && (key_off > THRESHOLD)) {
    payload(key_press);
    key_press = 0;
   }
}
/*************************************/

//Type out values
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
   OK.blink(1);
   if (password.evaluate() != true) {
     if (pass_keypress < MAX_PASSWORD_LENGTH) {
        password.append(button_selected);
        Serial.print("password appended with ");
        Serial.println(button_selected-'0');
        Serial.print("Number of keys entered for this passcode = ");
        Serial.println(pass_keypress);
        pass_keypress++;   
      } else {
        failed_attempts++;
        OK.blink(3);
        Serial.print("Login Failed, there are ");
        Serial.print(10 - failed_attempts);
        Serial.println(" remaining attempts before a factory reset will occur");
        Serial.println("WARNING: This will render all device information unrecoverable");
        password.reset(); //reset the guessed password to NULL
        pass_keypress=1;
      }
       if (failed_attempts >= 10) factorydefault(); //TODO Factory Default function to wipe sensitive flash and EEPROM
       if (selfdestruct.evaluate() == true) factorydefault(); //TODO Self Destruct PIN
  } else {
    *otp = '\0';
    if (duration <= 10) gen_token();
    if (duration >= 11) gen_static();
  }
  pos = otp;
  Keyboard.begin();
  SoftTimer.remove(&taskKey);
  SoftTimer.add(&taskKB);
}
/*************************************/

void factorydefault(void) {
  //To do add function from flashKinetis to wipe secure flash and eeprom values and flashQuickUnlockBits 
        Serial.println("factory reset has been completed");
        failed_attempts=0;
}
/*************************************/

void gen_token(void) {
  
  long GMT;
  char* newcode;
  OK.blink(1);
  char buffer[32];
  switch (button_selected) {
    case '1': //TODO - Future code commented out below
    //yubikey_eeget_user1 ((uint8_t *) buffer);    
    //if (buffer != 0) {
    //Keyboard.println(buffer);
    //}
    Keyboard.println("openkey1234567@gmail.com");
    //yubikey_eeget_delay1 ((uint8_t *) buffer);  
    //if (buffer != 0) {
    //delay(buffer);
    //}
    delay(2000);
    //yubikey_eeget_password1 ((uint8_t *) buffer);  
    //if (buffer != 0) {
    //TODO -Figure out how to encrypt/dectypt buffer using function below
    //yubikey_aes_decrypt (uint8_t * state, const uint8_t * key);  
    //Keyboard.println(buffer);
    //}
    Keyboard.println("OpenKey!#!");
    //yubikey_eeget_delay1 ((uint8_t *) buffer);  
    //if (buffer != 0) {
    //delay(buffer);
    //}
    delay(1000);
    //yubikey_eeget_2FAmode1 ((uint8_t *) buffer); 
      //switch (2FAmode1) { 
      //case '1':
          GMT = now();
          newcode = totp1.getCode(GMT);
          if(strcmp(otp, newcode) != 0) {
          strcpy(otp, newcode);
          } 
          Keyboard.println(otp);
      //break;
      //case '2':
      //u2f_button = 1;
      //break;
      //case '3':
      //u2f_button = 1;
      //break;
      //default:
      //break;
  //}

    case '2':

      Serial.print("Generate YubiKey OTP slot ");
      Serial.println(button_selected-'0');

      break;

    case '3':
 
      Serial.print("Generate YubiKey OTP slot ");
      Serial.println(button_selected-'0');

      break;

    case '4':

      break;

    case '5':
     Keyboard.write('s');

      Keyboard.write('\n');


      Serial.print("Generate Google Auth OTP slot ");
      Serial.println(button_selected-'0');
      GMT = now();
      newcode = totp5.getCode(GMT);
        if(strcmp(otp, newcode) != 0) {
        strcpy(otp, newcode);
        } 
      Serial.println(otp);
      break;
    case '6':
      //u2f_button = 1;
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
      digitalWrite(BLINKPIN, LOW);
      yubikey_eeget_static1 ((uint8_t *) buffer);
      yubikey_modhex_encode (otp, buffer, 16);
      Serial.print("Gen static slot ");
      Serial.println(button_selected-'0');
      Serial.println(otp);
      break;

    case '2':
      digitalWrite(BLINKPIN, LOW);

      Serial.print("Gen static slot ");
      Serial.println(button_selected-'0');

      break;

    case '3':
      digitalWrite(BLINKPIN, LOW);
      Serial.print("Gen static slot ");
      Serial.println(button_selected-'0');
      break;

    case '4':
      digitalWrite(BLINKPIN, LOW);
      //yubikey_eeget_static4 ((uint8_t *) buffer);
      //yubikey_modhex_encode (otp, buffer, 16);
      Serial.print("Gen static slot ");
      Serial.println(button_selected-'0');
      //Serial.println(otp);
      break;

    case '5':
      digitalWrite(BLINKPIN, LOW);
      //yubikey_eeget_static5 ((uint8_t *) buffer);
      //yubikey_modhex_encode (otp, buffer, 16);
      Serial.print("Gen static slot ");
      Serial.println(button_selected-'0');
      //Serial.println(otp);
      break;

    case '6':
      digitalWrite(BLINKPIN, LOW);
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
  yubikey_eeget_aeskey1(ptr);
  yubikey_hex_encode(aes_id1, (char *)aeskey1, 6);
  
  ptr = (uint8_t*) &counter;
  yubikey_eeget_counter1(ptr);

  
  ptr = privID1;
  yubikey_eeget_private1(ptr);
  yubikey_hex_encode(private_id1, (char *)privID1, 6);

  
  ptr = pubID1;
  yubikey_eeget_public1(ptr);
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
  
 
  
  yubikey_init1(&ctx1, aeskey1, public_id1, private_id1, counter, time, seed1);
 
  yubikey_incr_counter1(&ctx1);
 
  
  ptr = (uint8_t*) &(ctx1.counter1);
  yubikey_eeset_counter1(ptr);
  
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
  yubikey_eeset_aeskey1(buffer, 16);
 

  ptr = (uint8_t *) &counter;
  yubikey_eeset_counter1(ptr);
  
  memset (&buffer, 0, 20);
  yubikey_modhex_decode ((char *) &buffer, "hdulurfvtubk", 6);
  yubikey_eeset_private1(buffer);

  memset (&buffer, 0, 20);
  yubikey_modhex_decode ((char *) &buffer, "vvncrccvidvh", 6);
  yubikey_eeset_public1(buffer, 6);
 
  memset (&buffer, 0, 20);
  yubikey_modhex_decode ((char *) &buffer, "OpenKey", 16);
  yubikey_eeset_static1(buffer, 16);
 

  time2 = micros();
  Serial.print("done in ");
  Serial.print(time2-time1);
  Serial.println(" micros");

  
  Serial.print(EEpos_aeskey1);
  Serial.println("= aeskey1 pos");

  Serial.print(EEpos_counter1);
  Serial.println("= counter1 pos");
  Serial.print(EElen_counter1);
    Serial.println("= counter1 len");

  Serial.print(EEpos_private1);
  Serial.println("= private1 pos");
  Serial.print(EElen_private1);
    Serial.println("= private1 len");
    
  Serial.print(EEpos_public1);
    Serial.println("= public1 pos");
  Serial.print(EElen_public1);
    Serial.println("= public1 len");
    
  Serial.print(EEpos_static1);
    Serial.println("= static1 pos");
  Serial.print(EElen_static1);
    Serial.println("= static1 len");
    
  Serial.print(EEpos_keylen1);
  Serial.println("= keylen1 pos");
  Serial.print(EElen_keylen1);
  Serial.println("= keylen1 len");
  yubikey_eeget_keylen1(&len);
  Serial.print("> ");
  Serial.println(len);

  Serial.print(EEpos_ctrlen1);
  Serial.println("=ctrlen1 pos");
  Serial.print(EElen_ctrlen1);
    Serial.println("=ctrlen1 len");
  yubikey_eeget_ctrlen1(&len);
  Serial.print("> ");
  Serial.println(len);

  Serial.print(EEpos_prvlen1);
  Serial.println("= prvlen1 pos");
  Serial.print(EElen_prvlen1);
    Serial.println("= prvlen1 len");
  yubikey_eeget_prvlen1(&len);
  Serial.print("> ");
  Serial.println(len);

  Serial.print(EEpos_publen1);
  Serial.println("= publen1 pos");
  Serial.print(EElen_publen1);
    Serial.println("= publen1 len");
  yubikey_eeget_publen1(&len);
  Serial.print("> ");
  Serial.println(len);

  Serial.print(EEpos_statlen1);
  Serial.println("= statlen1 pos");
  Serial.print(EElen_statlen1);
    Serial.println("= statlen1 len");
  yubikey_eeget_statlen1(&len);
  Serial.print("> ");
  Serial.println(len);

 
}


/*************************************/






