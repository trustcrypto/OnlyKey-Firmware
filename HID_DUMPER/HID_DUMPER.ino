#include <EEPROM.h>
#include "sha256.h"
#include "uecc.h"
#include "ykcore.h"
#include "yksim.h"




#undef DEBUG
#define DEBUG
#define U2F_BUTTON

#define CID_BROADCAST           0xffffffff  // Broadcast channel id

#define TYPE_MASK               0x80  // Frame type mask
#define TYPE_INIT               0x80  // Initial frame identifier
#define TYPE_CONT               0x00  // Continuation frame identifier


#define U2FHID_PING         (TYPE_INIT | 0x01)  // Echo data through local processor only
#define U2FHID_MSG          (TYPE_INIT | 0x03)  // Send U2F message frame
#define U2FHID_LOCK         (TYPE_INIT | 0x04)  // Send lock channel command
#define U2FHID_INIT         (TYPE_INIT | 0x06)  // Channel initialization
#define U2FHID_WINK         (TYPE_INIT | 0x08)  // Send device identification wink
#define U2FHID_ERROR        (TYPE_INIT | 0x3f)  // Error response

#define OKSETPIN (TYPE_INIT | 0x61)  // First vendor defined commanD
#define OKSETTIME (TYPE_INIT | 0x62)  // 
#define OKGETLABELS (TYPE_INIT | 0x63)  //
#define OKSETSLOT  (TYPE_INIT | 0x64)  // 
#define OKWIPESLOT  (TYPE_INIT | 0x65)  // 
#define OKSETU2FPRIV (TYPE_INIT | 0x66)  // 
#define OKWIPEU2FPRIV (TYPE_INIT | 0x67)  // 
#define OKSETU2FCERT (TYPE_INIT | 0x68)  // 
#define OKWIPEU2FCERT  (TYPE_INIT | 0x69)  // Last vendor defined command


// Errors
#define ERR_NONE  0
#define ERR_INVALID_CMD  1
#define ERR_INVALID_PAR  2
#define ERR_INVALID_LEN  3
#define ERR_INVALID_SEQ  4
#define ERR_MSG_TIMEOUT  5
#define ERR_CHANNEL_BUSY  6
#define ERR_LOCK_REQUIRED  10
#define ERR_INVALID_CID  11
#define ERR_OTHER  127
#define ERR_UTC  99

#define U2F_INS_REGISTER  0x01
#define U2F_INS_AUTHENTICATE  0x02
#define U2F_INS_VERSION  0x03


#define STATE_CHANNEL_AVAILABLE 0
#define STATE_CHANNEL_WAIT_PACKET 1
#define STATE_CHANNEL_WAIT_CONT 2
#define STATE_CHANNEL_TIMEOUT 3
#define STATE_LARGE_PACKET 4

#define MAX_TOTAL_PACKET 7609

#define MAX_INITIAL_PACKET 57
#define MAX_CONTINUATION_PACKET 59
#define SET_MSG_LEN(b, v) do { (b)[5] = ((v) >> 8) & 0xff;  (b)[6] = (v) & 0xff; } while(0)


#define U2FHID_IF_VERSION       2  // Current interface implementation version

byte expected_next_packet;
int large_data_len;
int large_data_offset;
byte large_buffer[1024];
byte large_resp_buffer[1024];
byte recv_buffer[64];
byte resp_buffer[64];
byte handle[64];
byte sha256_hash[32];
#define MAX_CHANNEL 4


// Using self signed cert from https://github.com/mplatt/virtual-u2f as proof of concept, must be replaced 
const char attestation_key[] = "\xD3\x0C\x9C\xAC\x7D\xA2\xB4\xA7\xD7\x1B"
  "\x00\x2A\x40\xA3\xB5\x9A\x96\xCA\x50\x8B\xA9\xC7\xDC\x61"
  "\x7D\x98\x2C\x4B\x11\xD9\x52\xE6";
//const char attestation_key[] = "\xf3\xfc\xcc\x0d\x00\xd8\x03\x19\x54\xf9"
//  "\x08\x64\xd4\x3c\x24\x7f\x4b\xf5\xf0\x66\x5c\x6b\x50\xcc"
//  "\x17\x74\x9a\x27\xd1\xcf\x76\x64";
const char attestation_der[] = "\x30\x82\x01\xB4\x30\x82\x01\x58\xA0\x03"
  "\x02\x01\x02\x02\x01\x01\x30\x0C\x06\x08\x2A\x86\x48\xCE"
  "\x3D\x04\x03\x02\x05\x00\x30\x61\x31\x0B\x30\x09\x06\x03"
  "\x55\x04\x06\x13\x02\x44\x45\x31\x26\x30\x24\x06\x03\x55"
  "\x04\x0A\x0C\x1D\x55\x6E\x74\x72\x75\x73\x74\x77\x6F\x72"
  "\x74\x68\x79\x20\x43\x41\x20\x4F\x72\x67\x61\x6E\x69\x73"
  "\x61\x74\x69\x6F\x6E\x31\x0F\x30\x0D\x06\x03\x55\x04\x08"
  "\x0C\x06\x42\x65\x72\x6C\x69\x6E\x31\x19\x30\x17\x06\x03"
  "\x55\x04\x03\x0C\x10\x55\x6E\x74\x72\x75\x73\x74\x77\x6F"
  "\x72\x74\x68\x79\x20\x43\x41\x30\x22\x18\x0F\x32\x30\x31"
  "\x34\x30\x39\x32\x34\x31\x32\x30\x30\x30\x30\x5A\x18\x0F"
  "\x32\x31\x31\x34\x30\x39\x32\x34\x31\x32\x30\x30\x30\x30"
  "\x5A\x30\x5E\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02"
  "\x44\x45\x31\x21\x30\x1F\x06\x03\x55\x04\x0A\x0C\x18\x76"
  "\x69\x72\x74\x75\x61\x6C\x2D\x75\x32\x66\x2D\x6D\x61\x6E"
  "\x75\x66\x61\x63\x74\x75\x72\x65\x72\x31\x0F\x30\x0D\x06"
  "\x03\x55\x04\x08\x0C\x06\x42\x65\x72\x6C\x69\x6E\x31\x1B"
  "\x30\x19\x06\x03\x55\x04\x03\x0C\x12\x76\x69\x72\x74\x75"
  "\x61\x6C\x2D\x75\x32\x66\x2D\x76\x30\x2E\x30\x2E\x31\x30"
  "\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x08"
  "\x2A\x86\x48\xCE\x3D\x03\x01\x07\x03\x42\x00\x04\xC3\xC9"
  "\x1F\x25\x2E\x20\x10\x7B\x5E\x8D\xEA\xB1\x90\x20\x98\xF7"
  "\x28\x70\x71\xE4\x54\x18\xB8\x98\xCE\x5F\xF1\x7C\xA7\x25"
  "\xAE\x78\xC3\x3C\xC7\x01\xC0\x74\x60\x11\xCB\xBB\xB5\x8B"
  "\x08\xB6\x1D\x20\xC0\x5E\x75\xD5\x01\xA3\xF8\xF7\xA1\x67"
  "\x3F\xBE\x32\x63\xAE\xBE\x30\x0C\x06\x08\x2A\x86\x48\xCE"
  "\x3D\x04\x03\x02\x05\x00\x03\x48\x00\x30\x45\x02\x21\x00"
  "\x8E\xB9\x20\x57\xA1\xF3\x41\x4F\x1B\x79\x1A\x58\xE6\x07"
  "\xAB\xA4\x66\x1C\x93\x61\xFB\xC4\xBA\x89\x65\x5C\x8A\x3B"
  "\xEC\x10\x68\xDA\x02\x20\x15\x90\xA8\x76\xF0\x80\x47\xDF"
  "\x60\x8E\x23\xB2\x2A\xA0\xAA\xD2\x4B\x0D\x49\xC9\x75\x33"
  "\x00\xAF\x32\xB6\x90\x73\xF0\xA1\xA4\xDB";
/*const char attestation_der[] = "\x30\x82\x01\x3c\x30\x81\xe4\xa0\x03\x02"
  "\x01\x02\x02\x0a\x47\x90\x12\x80\x00\x11\x55\x95\x73\x52"
  "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x17"
  "\x31\x15\x30\x13\x06\x03\x55\x04\x03\x13\x0c\x47\x6e\x75"
  "\x62\x62\x79\x20\x50\x69\x6c\x6f\x74\x30\x1e\x17\x0d\x31"
  "\x32\x30\x38\x31\x34\x31\x38\x32\x39\x33\x32\x5a\x17\x0d"
  "\x31\x33\x30\x38\x31\x34\x31\x38\x32\x39\x33\x32\x5a\x30"
  "\x31\x31\x2f\x30\x2d\x06\x03\x55\x04\x03\x13\x26\x50\x69"
  "\x6c\x6f\x74\x47\x6e\x75\x62\x62\x79\x2d\x30\x2e\x34\x2e"
  "\x31\x2d\x34\x37\x39\x30\x31\x32\x38\x30\x30\x30\x31\x31"
  "\x35\x35\x39\x35\x37\x33\x35\x32\x30\x59\x30\x13\x06\x07"
  "\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d"
  "\x03\x01\x07\x03\x42\x00\x04\x8d\x61\x7e\x65\xc9\x50\x8e"
  "\x64\xbc\xc5\x67\x3a\xc8\x2a\x67\x99\xda\x3c\x14\x46\x68"
  "\x2c\x25\x8c\x46\x3f\xff\xdf\x58\xdf\xd2\xfa\x3e\x6c\x37"
  "\x8b\x53\xd7\x95\xc4\xa4\xdf\xfb\x41\x99\xed\xd7\x86\x2f"
  "\x23\xab\xaf\x02\x03\xb4\xb8\x91\x1b\xa0\x56\x99\x94\xe1"
  "\x01\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x03"
  "\x47\x00\x30\x44\x02\x20\x60\xcd\xb6\x06\x1e\x9c\x22\x26"
  "\x2d\x1a\xac\x1d\x96\xd8\xc7\x08\x29\xb2\x36\x65\x31\xdd"
  "\xa2\x68\x83\x2c\xb8\x36\xbc\xd3\x0d\xfa\x02\x20\x63\x1b"
  "\x14\x59\xf0\x9e\x63\x30\x05\x57\x22\xc8\xd8\x9b\x7f\x48"
  "\x88\x3b\x90\x89\xb8\x8d\x60\xd1\xd9\x79\x59\x02\xb3\x04"
  "\x10\xdf";
  */

//key handle: (private key + app parameter) ^ this array
const char handlekey[] = "-YOHANES-NUGROHO-YOHANES-NUGROHO-";

const struct uECC_Curve_t * curve = uECC_secp256r1(); //P-256
uint8_t private_k[36]; //32
uint8_t public_k[68]; //64

struct ch_state {
  int cid;
  byte state;
  int last_millis;
};

ch_state channel_states[MAX_CHANNEL];

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


#define TIMEOUT_VALUE 1000

void setup() {
  Serial.begin(9600);
  Keyboard.begin();
  Serial.println(F("U2F"));
  uECC_set_rng(&RNG);
}

void cleanup_timeout()
{
  int i;
  for (i = 0;  i < MAX_CHANNEL; i++) {
    //free channel that is inactive
    ch_state &c = channel_states[i];
    int m = millis();
    if (c.state != STATE_CHANNEL_AVAILABLE) {
      if ((m - c.last_millis) > TIMEOUT_VALUE) {
        c.state = STATE_CHANNEL_AVAILABLE;
      }
    }
  }
}

int allocate_new_channel()
{
  int i;
  //alloace new channel_id
  int channel_id = 1;
  int retry = 2;
  do {
    bool found = false;
    for (i = 0;  i < MAX_CHANNEL; i++) {
      if (channel_states[i].state != STATE_CHANNEL_AVAILABLE) {
        if (channel_states[i].cid == channel_id) {
          found = true;
          channel_id++;
          break;
        }
      }
    }
    if (!found)
      break;
  } while (true);
  return channel_id;
}

int allocate_channel(int channel_id)
{
  int i;
  if (channel_id==0) {
    channel_id =  allocate_new_channel();
  }

  bool has_free_slots = false;
  for (i = 0;  i < MAX_CHANNEL; i++) {
    if (channel_states[i].state == STATE_CHANNEL_AVAILABLE) {
      has_free_slots = true;
      break;
    }
  }
  if (!has_free_slots)
    cleanup_timeout();

  for (i = 0;  i < MAX_CHANNEL; i++) {
    ch_state &c = channel_states[i];
    if (c.state == STATE_CHANNEL_AVAILABLE) {
      c.cid = channel_id;
      c.state = STATE_CHANNEL_WAIT_PACKET;
      c.last_millis = millis();
      return channel_id;
    }
  }
  return 0;
}

int initResponse(byte *buffer)
{
#ifdef DEBUG
  Serial.print("INIT RESPONSE");
#endif
  int cid = *(int*)buffer;
#ifdef DEBUG
  Serial.println(cid, HEX);
#endif
  int len = buffer[5] << 8 | buffer[6];
  int i;
  memcpy(resp_buffer, buffer, 5);
  SET_MSG_LEN(resp_buffer, 17);
  memcpy(resp_buffer + 7, buffer + 7, len); //nonce
  i = 7 + len;
  if (cid==-1) {
    cid = allocate_channel(0);
  } else {
#ifdef DEBUG
    Serial.println("using existing CID");
#endif
    allocate_channel(cid);
  }
  memcpy(resp_buffer + i, &cid, 4);
  i += 4;
  resp_buffer[i++] = U2FHID_IF_VERSION;
  resp_buffer[i++] = 1; //major
  resp_buffer[i++] = 0;
  resp_buffer[i++] = 1; //build
  //resp_buffer[i++] = CAPABILITY_WINK; //capabilities
  resp_buffer[i++] = 0; //capabilities
#ifdef DEBUG
  Serial.println("SENT RESPONSE 1");
#endif  
  RawHID.send(resp_buffer, 100);
#ifdef DEBUG
  Serial.println(cid, HEX);
#endif  
  return cid;
}


void errorResponse(byte *buffer, int code)
{
        memcpy(resp_buffer, buffer, 4);
        resp_buffer[4] = U2FHID_ERROR;
        SET_MSG_LEN(resp_buffer, 1);
        resp_buffer[7] = code & 0xff;
#ifdef DEBUG
  Serial.print("SENT RESPONSE error:");
  Serial.println(code);
#endif
  RawHID.send(resp_buffer, 100);
}


//find channel index and update last access
int find_channel_index(int channel_id)
{
  int i;

  for (i = 0;  i < MAX_CHANNEL; i++) {
    if (channel_states[i].cid==channel_id) {
      channel_states[i].last_millis = millis();
      return i;
    }
  }

  return -1;
}

#define IS_CONTINUATION_PACKET(x) ( (x) < 0x80)
#define IS_NOT_CONTINUATION_PACKET(x) ( (x) >= 0x80)

#define SW_NO_ERROR                       0x9000
#define SW_CONDITIONS_NOT_SATISFIED       0x6985
#define SW_WRONG_DATA                     0x6A80
#define SW_WRONG_LENGTH                     0x6700
#define SW_INS_NOT_SUPPORTED 0x6D00
#define SW_CLA_NOT_SUPPORTED 0x6E00


#define APPEND_SW(x, v1, v2) do { (*x++)=v1; (*x++)=v2;} while (0)
#define APPEND_SW_NO_ERROR(x) do { (*x++)=0x90; (*x++)=0x00;} while (0)



void respondErrorPDU(byte *buffer, int err)
{
  SET_MSG_LEN(buffer, 2); //len("") + 2 byte SW
  byte *datapart = buffer + 7;
  APPEND_SW(datapart, (err >> 8) & 0xff, err & 0xff);
  RawHID.send(buffer, 100);
}

void sendLargeResponse(byte *request, int len)
{
#ifdef DEBUG  
  Serial.print("Sending large response ");
  Serial.println(len);
  for (int i = 0; i < len; i++) {
    Serial.print(large_resp_buffer[i], HEX);
    Serial.print(" ");
  }
  Serial.println("\n--\n");
#endif  
  memcpy(resp_buffer, request, 4); //copy cid
  resp_buffer[4] = U2FHID_MSG;
  int r = len;
  if (r>MAX_INITIAL_PACKET) {
    r = MAX_INITIAL_PACKET;
  }

  SET_MSG_LEN(resp_buffer, len);
  memcpy(resp_buffer + 7, large_resp_buffer, r);

  RawHID.send(resp_buffer, 100);
  len -= r;
  byte p = 0;
  int offset = MAX_INITIAL_PACKET;
  while (len > 0) {
    //memcpy(resp_buffer, request, 4); //copy cid, doesn't need to recopy
    resp_buffer[4] = p++;
    memcpy(resp_buffer + 5, large_resp_buffer + offset, MAX_CONTINUATION_PACKET);
    RawHID.send(resp_buffer, 100);
    len-= MAX_CONTINUATION_PACKET;
    offset += MAX_CONTINUATION_PACKET;
    delayMicroseconds(2500);
  }
}



int getCounter() {
  unsigned int eeAddress = 0; //EEPROM address to start reading from
  unsigned int counter;
  EEPROM.get( eeAddress, counter );
  return counter;
}

void setCounter(int counter)
{
  unsigned int eeAddress = 0; //EEPROM address to start reading from
  EEPROM.put( eeAddress, counter );
}

#ifdef U2F_BUTTON
//for now just simulate this
int button_pressed = 0;
#endif

void processMessage(byte *buffer)
{
  int len = buffer[5] << 8 | buffer[6];
#ifdef DEBUG  
  Serial.println(F("Got message"));
  Serial.println(len);
  Serial.println(F("Data:"));
#endif  
  byte *message = buffer + 7;
#ifdef DEBUG
  for (int i = 7; i < 7+len; i++) {
    Serial.print(buffer[i], HEX);
  }
  Serial.println(F(""));
#endif  
  //todo: check CLA = 0
  byte CLA = message[0];

  if (CLA!=0) {
    respondErrorPDU(buffer, SW_CLA_NOT_SUPPORTED);
    return;
  }

  byte INS = message[1];
  byte P1 = message[2];
  byte P2 = message[3];
  int reqlength = (message[4] << 16) | (message[5] << 8) | message[6];

  switch (INS) {
  case U2F_INS_REGISTER:
    {
      if (reqlength!=64) {
        respondErrorPDU(buffer, SW_WRONG_LENGTH);
        return;
      }

#ifdef U2F_BUTTON      
      if (!button_pressed) {
        respondErrorPDU(buffer, SW_CONDITIONS_NOT_SATISFIED);
          if (touchRead(23) > 1000) {
            button_pressed = 1;
          }
        return;
      }
#endif      

      byte *datapart = message + 7;
      byte *challenge_parameter = datapart;
      byte *application_parameter = datapart+32;

      memset(public_k, 0, sizeof(public_k));
      memset(private_k, 0, sizeof(private_k));
      uECC_make_key(public_k + 1, private_k, curve); //so we ca insert 0x04
      public_k[0] = 0x04;
#ifdef DEBUG
      Serial.println(F("Public K"));
      for (int i =0; i < sizeof(public_k); i++) {
        Serial.print(public_k[i], HEX);
        Serial.print(" ");
      }
      Serial.println("");
      Serial.println(F("Private K"));
      for (int i =0; i < sizeof(private_k); i++) {
        Serial.print(private_k[i], HEX);
        Serial.print(" ");
      }
      Serial.println("");
#endif      
      //construct hash

      memcpy(handle, application_parameter, 32);
      memcpy(handle+32, private_k, 32);
      for (int i =0; i < 64; i++) {
        handle[i] ^= handlekey[i%(sizeof(handlekey)-1)];
      }

      SHA256_CTX ctx;
      sha256_init(&ctx);
      large_resp_buffer[0] = 0x00;
      sha256_update(&ctx, large_resp_buffer, 1);
#ifdef DEBUG      
      Serial.println(F("App Parameter:"));
      for (int i =0; i < 32; i++) {
        Serial.print(application_parameter[i], HEX);
        Serial.print(" ");
      }
      Serial.println("");
#endif
      sha256_update(&ctx, application_parameter, 32);
#ifdef DEBUG
      Serial.println(F("Chal Parameter:"));
      for (int i =0; i < 32; i++) {
        Serial.print(challenge_parameter[i], HEX);
        Serial.print(" ");
      }
      Serial.println("");
#endif
      sha256_update(&ctx, challenge_parameter, 32);
#ifdef DEBUG
      Serial.println(F("Handle Parameter:"));
      for (int i =0; i < 64; i++) {
        Serial.print(handle[i], HEX);
        Serial.print(" ");
      }
      Serial.println("");
#endif
      sha256_update(&ctx, handle, 64);
      sha256_update(&ctx, public_k, 65);
#ifdef DEBUG      
      Serial.println(F("Public key:"));
      for (int i =0; i < 65; i++) {
        Serial.print(public_k[i], HEX);
        Serial.print(" ");
      }
      Serial.println("");
#endif
      sha256_final(&ctx, sha256_hash);
#ifdef DEBUG
      Serial.println(F("Hash:"));
      for (int i =0; i < 32; i++) {
        Serial.print(sha256_hash[i], HEX);
        Serial.print(" ");
      }
      Serial.println("");
#endif

      uint8_t *signature = resp_buffer; //temporary

      uECC_sign((uint8_t *)attestation_key,
          sha256_hash,
          32,
          signature,
          curve);

      int len = 0;
      large_resp_buffer[len++] = 0x05;
      memcpy(large_resp_buffer + len, public_k, 65);
      len+=65;
      large_resp_buffer[len++] = 64; //length of handle
      memcpy(large_resp_buffer+len, handle, 64);
      len += 64;
      memcpy(large_resp_buffer+len, attestation_der, sizeof(attestation_der));
      len += sizeof(attestation_der)-1;
      //convert signature format
      //http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
      large_resp_buffer[len++] = 0x30; //header: compound structure
      large_resp_buffer[len++] = 0x44; //total length (32 + 32 + 2 + 2)
      large_resp_buffer[len++] = 0x02;  //header: integer
      large_resp_buffer[len++] = 32;  //32 byte
      memcpy(large_resp_buffer+len, signature, 32); //R value
      len +=32;
      large_resp_buffer[len++] = 0x02;  //header: integer
      large_resp_buffer[len++] = 32;  //32 byte
      memcpy(large_resp_buffer+len, signature+32, 32); //R value
      len +=32;

      byte *last = large_resp_buffer+len;
      APPEND_SW_NO_ERROR(last);
      len += 2;
#ifdef U2F_BUTTON      
      button_pressed = 0;
#endif      
      sendLargeResponse(buffer, len);
    }

    break;
  case U2F_INS_AUTHENTICATE:
    {

      //minimum is 64 + 1 + 64
      if (reqlength!=(64+1+64)) {
        respondErrorPDU(buffer, SW_WRONG_LENGTH);
        return;
      }

      byte *datapart = message + 7;
      byte *challenge_parameter = datapart;
      byte *application_parameter = datapart+32;
      byte handle_len = datapart[64];
      byte *client_handle = datapart+65;

      if (handle_len!=64) {
        //not from this device
        respondErrorPDU(buffer, SW_WRONG_DATA);
        return;
      }
#ifdef U2F_BUTTON      
      if (!button_pressed) {
        respondErrorPDU(buffer, SW_CONDITIONS_NOT_SATISFIED);
          if (touchRead(23) > 1000) {
            button_pressed = 1;
          }
        return;
      }
#endif

      memcpy(handle, client_handle, 64);
      for (int i =0; i < 64; i++) {
        handle[i] ^= handlekey[i%(sizeof(handlekey)-1)];
      }
      uint8_t *key = handle + 32;

      if (memcmp(handle, application_parameter, 32)!=0) {
        //this handle is not from us
        respondErrorPDU(buffer, SW_WRONG_DATA);
        return;
      }

      if (P1==0x07) { //check-only
        respondErrorPDU(buffer, SW_CONDITIONS_NOT_SATISFIED);
      } else if (P1==0x03) { //enforce-user-presence-and-sign
        int counter = getCounter();
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, application_parameter, 32);
        large_resp_buffer[0] = 0x01; // user_presence

        int ctr = ((counter>>24)&0xff) | // move byte 3 to byte 0
          ((counter<<8)&0xff0000) | // move byte 1 to byte 2
          ((counter>>8)&0xff00) | // move byte 2 to byte 1
          ((counter<<24)&0xff000000); // byte 0 to byte 3

        memcpy(large_resp_buffer + 1, &ctr, 4);

        sha256_update(&ctx, large_resp_buffer, 5); //user presence + ctr

        sha256_update(&ctx, challenge_parameter, 32);
        sha256_final(&ctx, sha256_hash);

        uint8_t *signature = resp_buffer; //temporary

        uECC_sign((uint8_t *)key,
            sha256_hash,
            32,
            signature,
            curve);

        int len = 5;

        //convert signature format
        //http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
        large_resp_buffer[len++] = 0x30; //header: compound structure
        large_resp_buffer[len++] = 0x44; //total length (32 + 32 + 2 + 2)
        large_resp_buffer[len++] = 0x02;  //header: integer
        large_resp_buffer[len++] = 32;  //32 byte
        memcpy(large_resp_buffer+len, signature, 32); //R value
        len +=32;
        large_resp_buffer[len++] = 0x02;  //header: integer
        large_resp_buffer[len++] = 32;  //32 byte
        memcpy(large_resp_buffer+len, signature+32, 32); //R value
        len +=32;
        byte *last = large_resp_buffer+len;
        APPEND_SW_NO_ERROR(last);
        len += 2;
#ifdef DEBUG
        Serial.print("Len to send ");
        Serial.println(len);
#endif
#ifdef U2F_BUTTON              
        button_pressed = 0;
#endif        
        sendLargeResponse(buffer, len);

        setCounter(counter+1);
        Serial.print("counter is ");
        Serial.println(counter);
      } else {
        //return error
      }
    }
    break;
  case U2F_INS_VERSION:
    {
      if (reqlength!=0) {
        respondErrorPDU(buffer, SW_WRONG_LENGTH);
        return;
      }
      //reuse input buffer for sending
      SET_MSG_LEN(buffer, 8); //len("U2F_V2") + 2 byte SW
      byte *datapart = buffer + 7;
      memcpy(datapart, "U2F_V2", 6);
      datapart += 6;
      APPEND_SW_NO_ERROR(datapart);
      RawHID.send(buffer, 100);
    }
    break;
  default:
    {
      respondErrorPDU(buffer, SW_INS_NOT_SUPPORTED);
    }
    ;
  }

}

void processPacket(byte *buffer)
{
#ifdef DEBUG  
  Serial.print("Process CMD ");
#endif
  char cmd = buffer[4]; //cmd or continuation
#ifdef DEBUG
  Serial.println((int)cmd, HEX);
#endif

  int len = buffer[5] << 8 | buffer[6];
  
          switch (cmd) {
              case OKSETPIN:
                  Serial.print(" Received CMD OKSETPIN");
            // statements
                break;
              case OKSETTIME:
                  Serial.print(" Received CMD OKSETTIME");
                break;
              case OKGETLABELS:
                  Serial.print(" Received CMD OKGETLABELS");
                break;
              case OKSETSLOT:
                  Serial.print(" Received CMD OKSETSLOT");
            // statements
                break;
              case OKWIPESLOT:
                  Serial.print(" Received CMD OKWIPESLOT");
                break;
              case OKSETU2FPRIV:
                  Serial.print(" Received CMD OKSETU2FPRIV");
                break;
              case OKWIPEU2FPRIV:
                  Serial.print(" Received CMD OKWIPEU2FPRIV");
            // statements
                break;
              case OKSETU2FCERT:
                  Serial.print(" Received CMD OKSETU2FCERT");
                break;
              case OKWIPEU2FCERT:
                  Serial.print(" Received CMD OKWIPEU2FCERT");
                break;
              default: 
            // statements
              break;
          }

  
  if (cmd > U2FHID_INIT || cmd==U2FHID_LOCK) {
    errorResponse(recv_buffer, ERR_INVALID_CMD);
    return;
  }
  if (cmd==U2FHID_PING) {
    if (len <= MAX_INITIAL_PACKET) {
#ifdef DEBUG      
      Serial.println("Sending ping response");
#endif      
      RawHID.send(buffer, 100);
    } else {
      //large packet
      //send first one
#ifdef DEBUG      
      Serial.println("SENT RESPONSE 3");
#endif      
      RawHID.send(buffer, 100);
      len -= MAX_INITIAL_PACKET;
      byte p = 0;
      int offset = 7 + MAX_INITIAL_PACKET;
      while (len > 0) {
        memcpy(resp_buffer, buffer, 4); //copy cid
        resp_buffer[4] = p++;
        memcpy(resp_buffer + 5, buffer + offset, MAX_CONTINUATION_PACKET);
        RawHID.send(resp_buffer, 100);
        len-= MAX_CONTINUATION_PACKET;
        offset += MAX_CONTINUATION_PACKET;
        delayMicroseconds(2500);
      }
#ifdef DEBUG      
      Serial.println("Sending large ping response");
#endif      
    }
  }
  if (cmd==U2FHID_MSG) {
    processMessage(buffer);
  }

}

void setOtherTimeout()
{
  //we can process the data
  //but if we find another channel is waiting for continuation, we set it as timeout
  for (int i = 0; i < MAX_CHANNEL; i++) {
    if (channel_states[i].state==STATE_CHANNEL_WAIT_CONT) {
#ifdef DEBUG      
      Serial.println("Set other timeout");
#endif      
      channel_states[i].state= STATE_CHANNEL_TIMEOUT;
    }
  }

}

int cont_start = 0;

void loop() {
  int n;
  int z;
 

  

n = RawHID.recv(recv_buffer, 0); // 0 timeout = do not wait
  Serial.println("Waiting for packet");
  if (n > 0) {
#ifdef DEBUG    

    Serial.print(F("\n\nReceived packet: "));
#endif    
    int cid = *(int*)recv_buffer;
#ifdef DEBUG  
  for (int z = 0; z < 64; z++) {
    Serial.print(recv_buffer[z], HEX);

  }
      Serial.println(); //newline
      
      uint8_t aeskey1[16] = "abcdefghijklmno"; //128 Bit Key
      
      //Encrypt each block
      Serial.print("Using AES Key = ");
      for (int z = 0; z < 16; z++) {
        Serial.print(aeskey1[z], HEX);
        }
      Serial.println(); //newline
      Serial.print("Encrypted packet = ");
      yubikey_aes_encrypt (recv_buffer, aeskey1);
      yubikey_aes_encrypt ((recv_buffer + 16), aeskey1);
      for (int z = 0; z < 32; z++) {
      Serial.print(recv_buffer[z], HEX);
        }
        
      //Set value in EEPROM
      Serial.println(); //newline
      yubikey_eeset_static1(recv_buffer, 32);
      Serial.print("Writing to EEPROM...");
    
      uint8_t static1[32];
      uint8_t *ptr;
      char stat_id1[32+1];
      
      //Get value from EEPROM
      ptr = static1;
      yubikey_eeget_static1(ptr);
      yubikey_hex_encode(stat_id1, (char *)static1, 32);
      Serial.println(); //newline
      Serial.print("Read from EEPROM = ");
      Serial.println(stat_id1);

       //Decrypt each block
      Serial.print("Using AES Key = ");
      for (int z = 0; z < 16; z++) {
        Serial.print(aeskey1[z], HEX);
        }
      Serial.println(); //newline
      Serial.print("Decrypted EEPROM = ");
      yubikey_aes_decrypt (static1, aeskey1);
      yubikey_aes_decrypt ((static1 + 16), aeskey1);
      Serial.print("Typing it out on the keyboard...");
      //delay(1000);
      for (int z = 0; z < 32; z++) {
      Serial.print((int)static1[z], HEX);
      Keyboard.print(static1[z], HEX);
        }
      Serial.println(); //newline
      

   

      
      //delay(10000);
#endif    
    if (cid==0) {
      errorResponse(recv_buffer, ERR_INVALID_CID);
      return;
    }

    char cmd_or_cont = recv_buffer[4]; //cmd or continuation


    int len = (recv_buffer[5]) << 8 | recv_buffer[6];

#ifdef DEBUG
    if (IS_NOT_CONTINUATION_PACKET(cmd_or_cont)) {
      Serial.print(F("LEN "));
      Serial.println((int)len);
    }
#endif


    //don't care about cid
    if (cmd_or_cont==U2FHID_INIT) {
      setOtherTimeout();
      cid = initResponse(recv_buffer);
      int cidx = find_channel_index(cid);
      channel_states[cidx].state= STATE_CHANNEL_WAIT_PACKET;
      return;
    }

    if (cid==-1) {
      errorResponse(recv_buffer, ERR_INVALID_CID);
      return;
    }

    int cidx = find_channel_index(cid);

    if (cidx==-1) {
#ifdef DEBUG      
      Serial.println("allocating new CID");
#endif      
      allocate_channel(cid);
      cidx = find_channel_index(cid);
      if (cidx==-1) {
        errorResponse(recv_buffer, ERR_INVALID_CID);
        return;
      }

    }

    if (IS_NOT_CONTINUATION_PACKET(cmd_or_cont)) {

      if (len > MAX_TOTAL_PACKET) {
        errorResponse(recv_buffer, ERR_INVALID_LEN); //invalid length
        return;
      }

      if (len > MAX_INITIAL_PACKET) {
        //if another channel is waiting for continuation, we respond with busy
        for (int i = 0; i < MAX_CHANNEL; i++) {
          if (channel_states[i].state==STATE_CHANNEL_WAIT_CONT) {
            if (i==cidx) {
              errorResponse(recv_buffer, ERR_INVALID_SEQ); //invalid sequence
              channel_states[i].state= STATE_CHANNEL_WAIT_PACKET;
            } else {
              errorResponse(recv_buffer, ERR_CHANNEL_BUSY);
              return;
            }

            return;
          }
        }
        //no other channel is waiting
        channel_states[cidx].state=STATE_CHANNEL_WAIT_CONT;
        cont_start = millis();
        memcpy(large_buffer, recv_buffer, 64);
        large_data_len = len;
        large_data_offset = MAX_INITIAL_PACKET;
        expected_next_packet = 0;
        return;
      }

      setOtherTimeout();
      processPacket(recv_buffer);
      channel_states[cidx].state= STATE_CHANNEL_WAIT_PACKET;
    } else {

      if (channel_states[cidx].state!=STATE_CHANNEL_WAIT_CONT) {
#ifdef DEBUG        
        Serial.println("ignoring stray packet");
        Serial.println(cid, HEX);
#endif        
        return;
      }

      //this is a continuation
      if (cmd_or_cont != expected_next_packet) {
        errorResponse(recv_buffer, ERR_INVALID_SEQ); //invalid sequence
        channel_states[cidx].state= STATE_CHANNEL_WAIT_PACKET;
        return;
      } else {

        memcpy(large_buffer + large_data_offset + 7, recv_buffer + 5, MAX_CONTINUATION_PACKET);
        large_data_offset += MAX_CONTINUATION_PACKET;

        if (large_data_offset < large_data_len) {
          expected_next_packet++;
#ifdef DEBUG          
          Serial.println("Expecting next cont");
#endif          
          return;
        }
#ifdef DEBUG        
        Serial.println("Completed");
#endif        
        channel_states[cidx].state= STATE_CHANNEL_WAIT_PACKET;
        processPacket(large_buffer);
        return;
      }
    }
  } else {

    for (int i = 0; i < MAX_CHANNEL; i++) {
      if (channel_states[i].state==STATE_CHANNEL_TIMEOUT) {
#ifdef DEBUG        
        Serial.println("send timeout");
        Serial.println(channel_states[i].cid, HEX);
#endif        
        memcpy(recv_buffer, &channel_states[i].cid, 4);
        errorResponse(recv_buffer, ERR_MSG_TIMEOUT);
        channel_states[i].state= STATE_CHANNEL_WAIT_PACKET;

      }
      if (channel_states[i].state==STATE_CHANNEL_WAIT_CONT) {

        int now = millis();
        if ((now - channel_states[i].last_millis)>500) {
#ifdef DEBUG          
          Serial.println("SET timeout");
#endif          
          channel_states[i].state=STATE_CHANNEL_TIMEOUT;
        }
      }
    }
  }
}

