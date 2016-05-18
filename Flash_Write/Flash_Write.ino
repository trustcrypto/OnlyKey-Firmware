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
  delay(5000);
 


  unsigned long value = 0x00000000;
  //Set pointer to first empty flash sector
  uintptr_t adr = 0x14820;
  for (int i = 0; i < 7000; i++)
  {
  
  //Write long to empty sector 
  Serial.printf("0x%X", adr);
  if ( flashProgramWord((unsigned long*)adr, &value) ) Serial.printf("NOT ");
  Serial.printf(" 0x%X", *((unsigned int*)adr));
  Serial.println();
  adr=adr+4;
  }
  
}


void loop()
{}
