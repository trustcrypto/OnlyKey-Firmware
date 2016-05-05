#include "T3MacLib.h"


void setup()
{
delay( 2000);
Serial.begin(115200);
delay( 2000);
read_mac();

Serial.print(" MAC =: ");
Serial.print( ( mac[0] & 0xF0 ) >> 4 ,HEX );
Serial.print( ( mac[0] & 0x0F ) ,HEX );
Serial.print( ( mac[1] & 0xF0 ) >> 4 ,HEX );
Serial.print( ( mac[1] & 0x0F ) ,HEX );
Serial.print( ( mac[2] & 0xF0 ) >> 4 ,HEX );
Serial.print( ( mac[2] & 0x0F ) ,HEX );
Serial.print( ( mac[3] & 0xF0 ) >> 4 ,HEX );
Serial.print( ( mac[3] & 0x0F ) ,HEX );
Serial.print( ( mac[4] & 0xF0 ) >> 4 ,HEX );
Serial.print( ( mac[4] & 0x0F ) ,HEX );
Serial.print( ( mac[5] & 0xF0 ) >> 4 ,HEX );
Serial.print( ( mac[5] & 0x0F ) ,HEX );

Serial.println();

CHIP_ID();
Serial.print(" Chip ID =: ");
for (int i = 0; i < 37; i++)
{
Serial.print(ID[i], HEX);
}
}


void loop() {
}
