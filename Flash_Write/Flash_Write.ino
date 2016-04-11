/*
  Arduino - Kinetis ("Teensy") Flashing Library
  (c) Frank Boesing, f.boesing@gmx.de
  License:
  Private and educational use allowed.
  If you need this library for commecial use, please
  ask me.
  In every case, keep this header.
*/


//  This example performs various tests.


#include "flashkinetis.h"


  
void setup()

{

  Serial.begin(9600);
  while(!Serial);
  delay(1000);
 

  //char PINHASH[32] = "1234567890123456789012345678901";
  char PINHASH[] = "\xD3\x0C\x9C\xAC\x7D\xA2\xB4\xA7\xD7\x1B"
  "\x00\x2A\x40\xA3\xB5\x9A\x96\xCA\x50\x8B\xA9\xC7\xDC\x61"
  "\x7D\x98\x2C\x4B\x11\xD9\x52\xE6";
  unsigned long pinhash1 = PINHASH[0] | (PINHASH[1] << 8L) | (PINHASH[2] << 16L) | (PINHASH[3] << 24L);
  unsigned long pinhash2 = PINHASH[4] | (PINHASH[5] << 8L) | (PINHASH[6] << 16L) | (PINHASH[7] << 24L);
  unsigned long pinhash3 = PINHASH[8] | (PINHASH[9] << 8L) | (PINHASH[10] << 16L) | (PINHASH[11] << 24L);
  unsigned long pinhash4 = PINHASH[12] | (PINHASH[13] << 8L) | (PINHASH[14] << 16L) | (PINHASH[15] << 24L);
  unsigned long pinhash5 = PINHASH[16] | (PINHASH[17] << 8L) | (PINHASH[18] << 16L) | (PINHASH[19] << 24L);
  unsigned long pinhash6 = PINHASH[20] | (PINHASH[21] << 8L) | (PINHASH[22] << 16L) | (PINHASH[23] << 24L);
  unsigned long pinhash7 = PINHASH[24] | (PINHASH[25] << 8L) | (PINHASH[26] << 16L) | (PINHASH[27] << 24L);
  unsigned long pinhash8 = PINHASH[28] | (PINHASH[29] << 8L) | (PINHASH[30] << 16L) | (PINHASH[31] << 24L);
 
  //Set pointer to first empty flash sector
  uintptr_t adr = flashFirstEmptySector();
  //Write long to empty sector 
  Serial.printf("Program 0x%X, value 0x%X ", adr, pinhash1);
  if ( flashProgramWord((unsigned long*)adr, &pinhash1) ) Serial.printf("NOT ");
  Serial.printf("successful. Read Value:0x%X\r\n", *((unsigned int*)adr));
  //Increment to next sector
  adr=adr+4;
  //Write long to empty sector and read value back from flash
  Serial.printf("Program 0x%X, value 0x%X ", adr, pinhash2);
  if ( flashProgramWord((unsigned long*)adr, &pinhash2) ) Serial.printf("NOT ");
  Serial.printf("successful. Read Value:0x%X\r\n", *((unsigned int*)adr));
  //Increment to next sector
  adr=adr+4;
  //Write long to empty sector and read value back from flash
  Serial.printf("Program 0x%X, value 0x%X ", adr, pinhash3);
  if ( flashProgramWord((unsigned long*)adr, &pinhash3) ) Serial.printf("NOT ");
  Serial.printf("successful. Read Value:0x%X\r\n", *((unsigned int*)adr));
  //Increment to next sector
  adr=adr+4;
  //Write long to empty sector and read value back from flash
  Serial.printf("Program 0x%X, value 0x%X ", adr, pinhash4);
  if ( flashProgramWord((unsigned long*)adr, &pinhash4) ) Serial.printf("NOT ");
  Serial.printf("successful. Read Value:0x%X\r\n", *((unsigned int*)adr));
  //Increment to next sector
  adr=adr+4;
  //Write long to empty sector and read value back from flash
  Serial.printf("Program 0x%X, value 0x%X ", adr, pinhash5);
  if ( flashProgramWord((unsigned long*)adr, &pinhash5) ) Serial.printf("NOT ");
  Serial.printf("successful. Read Value:0x%X\r\n", *((unsigned int*)adr));
  //Increment to next sector
  adr=adr+4;
  //Write long to empty sector and read value back from flash
  Serial.printf("Program 0x%X, value 0x%X ", adr, pinhash6);
  if ( flashProgramWord((unsigned long*)adr, &pinhash6) ) Serial.printf("NOT ");
  Serial.printf("successful. Read Value:0x%X\r\n", *((unsigned int*)adr));
  //Increment to next sector
  adr=adr+4;
  //Write long to empty sector and read value back from flash
  Serial.printf("Program 0x%X, value 0x%X ", adr, pinhash7);
  if ( flashProgramWord((unsigned long*)adr, &pinhash7) ) Serial.printf("NOT ");
  Serial.printf("successful. Read Value:0x%X\r\n", *((unsigned int*)adr));
  //Increment to next sector
  adr=adr+4;
  //Write long to empty sector and read value back from flash
  Serial.printf("Program 0x%X, value 0x%X ", adr, pinhash8);
  if ( flashProgramWord((unsigned long*)adr, &pinhash8) ) Serial.printf("NOT ");
  Serial.printf("successful. Read Value:0x%X\r\n", *((unsigned int*)adr));
  
  char PINHASH2[32];
  
  Serial.print("PINHASH2 = ");
  
  for(int i=31; i > 1; i=i-4, adr=adr-4) {
  PINHASH2[i-3] = *((unsigned int*)adr);
  PINHASH2[i-2] = (*((unsigned int*)adr) >> 8L);
  PINHASH2[i-1] = (*((unsigned int*)adr) >> 16L);
  PINHASH2[i] = (*((unsigned int*)adr) >> 24L);
  }
  
  for(int i=0; i < 32; i++) {
    Serial.print(PINHASH2[i], HEX);
  }



 
  Serial.printf("Ready.\r\n");
  while(1){;}
  
}


void loop()
{}
