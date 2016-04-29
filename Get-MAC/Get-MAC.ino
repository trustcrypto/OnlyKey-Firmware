#include "T3Mac.h"


void setup()
{
delay( 2000);
Serial.begin(115200);
delay( 2000);
read_mac();

Serial.print(" Chip ID =: ");
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

}


void loop() {
}
