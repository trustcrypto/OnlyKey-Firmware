/* Modifications
 * Copyright (c) 2015-2020, CryptoTrust LLC.
 * All rights reserved.
 * 
 * Author : Tim Steiner <t@crp.to>
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
 *    the OnlyKey Project (https://www.crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "CryptoTrust" must not be used to
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
 *    the OnlyKey Project (https://www.crp.to/ok)"
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
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS
 * ARE GRANTED BY THIS LICENSE. IF SOFTWARE RECIPIENT INSTITUTES PATENT
 * LITIGATION AGAINST ANY ENTITY (INCLUDING A CROSS-CLAIM OR COUNTERCLAIM
 * IN A LAWSUIT) ALLEGING THAT THIS SOFTWARE (INCLUDING COMBINATIONS OF THE
 * SOFTWARE WITH OTHER SOFTWARE OR HARDWARE) INFRINGES SUCH SOFTWARE
 * RECIPIENT'S PATENT(S), THEN SUCH SOFTWARE RECIPIENT'S RIGHTS GRANTED BY
 * THIS LICENSE SHALL TERMINATE AS OF THE DATE SUCH LITIGATION IS FILED. IF
 * ANY PROVISION OF THIS AGREEMENT IS INVALID OR UNENFORCEABLE UNDER
 * APPLICABLE LAW, IT SHALL NOT AFFECT THE VALIDITY OR ENFORCEABILITY OF THE
 * REMAINDER OF THE TERMS OF THIS AGREEMENT, AND WITHOUT FURTHER ACTION
 * BY THE PARTIES HERETO, SUCH PROVISION SHALL BE REFORMED TO THE MINIMUM
 * EXTENT NECESSARY TO MAKE SUCH PROVISION VALID AND ENFORCEABLE. ALL
 * SOFTWARE RECIPIENT'S RIGHTS UNDER THIS AGREEMENT SHALL TERMINATE IF IT
 * FAILS TO COMPLY WITH ANY OF THE MATERIAL TERMS OR CONDITIONS OF THIS
 * AGREEMENT AND DOES NOT CURE SUCH FAILURE IN A REASONABLE PERIOD OF
 * TIME AFTER BECOMING AWARE OF SUCH NONCOMPLIANCE. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR  PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,  EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Original Teensyduino Core Library
 * http://www.pjrc.com/teensy/
 * Copyright (c) 2013 PJRC.COM, LLC.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * 1. The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * 2. If the Software is incorporated into a build system that allows
 * selection among a list of target devices, then similar target
 * devices manufactured by PJRC.COM must be included in the list of
 * target devices and selectable in the same manner.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "usb_dev.h"
#include "usb_keyboard.h"
#include "core_pins.h" // for yield()
#include "keylayouts.h"
//#include "HardwareSerial.h"
#include <string.h> // for memcpy()

#ifdef KEYBOARD_INTERFACE // defined by usb_dev.h -> usb_desc.h
#if F_CPU >= 20000000

// which modifier keys are currently pressed
// 1=left ctrl,	   2=left shift,   4=left alt,	  8=left gui
// 16=right ctrl, 32=right shift, 64=right alt, 128=right gui
uint8_t keyboard_modifier_keys=0;

// which media keys are currently pressed
uint8_t keyboard_media_keys=0;

// which keys are currently pressed, up to 6 keys may be down at once
uint8_t keyboard_keys[6]={0,0,0,0,0,0};

// protocol setting from the host.  We use exactly the same report
// either way, so this variable only stores the setting since we
// are required to be able to report which setting is in use.
uint8_t keyboard_protocol=1;

// the idle configuration, how often we send the report to the
// host (ms * 4) even when it hasn't changed
uint8_t keyboard_idle_config=125;

// count until idle timeout
uint8_t keyboard_idle_count=0;

// 1=num lock, 2=caps lock, 4=scroll lock, 8=compose, 16=kana
volatile uint8_t keyboard_leds=0;



static KEYCODE_TYPE unicode_to_keycode(uint16_t cpoint);
static void write_key(KEYCODE_TYPE keycode);
static uint8_t keycode_to_modifier(KEYCODE_TYPE keycode);
static uint8_t keycode_to_key(KEYCODE_TYPE keycode);
static void usb_keyboard_press_key(uint8_t key, uint8_t modifier);
static void usb_keyboard_release_key(uint8_t key, uint8_t modifier);
static KEYCODE_TYPE deadkey_to_keycode(KEYCODE_TYPE keycode);

extern uint16_t SHIFT_MASK;
extern uint16_t ALTGR_MASK;
extern uint16_t RCTRL_MASK;
extern uint16_t KEY_NON_US_100;
extern uint16_t DEADKEYS_MASK;
extern uint16_t CIRCUMFLEX_BITS;
extern uint16_t ACUTE_ACCENT_BITS;
extern uint16_t GRAVE_ACCENT_BITS;
extern uint16_t TILDE_BITS;
extern uint16_t DIAERESIS_BITS;
extern uint16_t DEADKEY_CIRCUMFLEX;
extern uint16_t DEADKEY_ACUTE_ACCENT;
extern uint16_t DEADKEY_GRAVE_ACCENT;
extern uint16_t DEADKEY_TILDE;
extern uint16_t DEADKEY_DIAERESIS;
extern uint16_t UNICODE_20AC;
extern uint16_t CEDILLA_BITS;
extern uint16_t DEADKEY_CEDILLA;
extern uint16_t RING_ABOVE_BITS;
extern uint16_t DEADKEY_RING_ABOVE;
extern uint16_t DEGREE_SIGN_BITS;
extern uint16_t CARON_BITS;
extern uint16_t BREVE_BITS;
extern uint16_t OGONEK_BITS;
extern uint16_t DOT_ABOVE_BITS;
extern uint16_t DOUBLE_ACUTE_BITS;
extern uint16_t DEADKEY_DEGREE_SIGN;
extern uint16_t DEADKEY_CARON;
extern uint16_t DEADKEY_BREVE;
extern uint16_t DEADKEY_OGONEK;
extern uint16_t DEADKEY_DOT_ABOVE;
extern uint16_t DEADKEY_DOUBLE_ACUTE;
extern uint16_t UNICODE_EXTRA0A;
extern uint16_t KEYCODE_EXTRA0A;
extern uint16_t ISO_8859_1_A0;
extern uint16_t UNICODE_EXTRA00;
extern uint16_t UNICODE_EXTRA01;
extern uint16_t UNICODE_EXTRA02;
extern uint16_t UNICODE_EXTRA03;
extern uint16_t UNICODE_EXTRA04;
extern uint16_t UNICODE_EXTRA05;
extern uint16_t UNICODE_EXTRA06;
extern uint16_t UNICODE_EXTRA07;
extern uint16_t UNICODE_EXTRA08;
extern uint16_t UNICODE_EXTRA09;
extern uint16_t KEYCODE_EXTRA00;
extern uint16_t KEYCODE_EXTRA01;
extern uint16_t KEYCODE_EXTRA02;
extern uint16_t KEYCODE_EXTRA03;
extern uint16_t KEYCODE_EXTRA04;
extern uint16_t KEYCODE_EXTRA05;
extern uint16_t KEYCODE_EXTRA06;
extern uint16_t KEYCODE_EXTRA07;
extern uint16_t KEYCODE_EXTRA08;
extern uint16_t KEYCODE_EXTRA09;
extern uint16_t KEYCODE_MASK;


// Step #1, decode UTF8 to Unicode code points
//
void usb_keyboard_write(uint8_t c)
{
	static int utf8_state=0;
	static uint16_t unicode_wchar=0;

	if (c < 0x80) {
		// single byte encoded, 0x00 to 0x7F
		utf8_state = 0;
		usb_keyboard_write_unicode(c);
	} else if (c < 0xC0) {
		// 2nd, 3rd or 4th byte, 0x80 to 0xBF
		c &= 0x3F;
		if (utf8_state == 1) {
			utf8_state = 0;
			usb_keyboard_write_unicode(unicode_wchar | c);
		} else if (utf8_state == 2) {
			unicode_wchar |= ((uint16_t)c << 6);
			utf8_state = 1;
		}
	} else if (c < 0xE0) {
		// begin 2 byte sequence, 0xC2 to 0xDF
		// or illegal 2 byte sequence, 0xC0 to 0xC1
		unicode_wchar = (uint16_t)(c & 0x1F) << 6;
		utf8_state = 1;
	} else if (c < 0xF0) {
		// begin 3 byte sequence, 0xE0 to 0xEF
		unicode_wchar = (uint16_t)(c & 0x0F) << 12;
		utf8_state = 2;
	} else {
		// begin 4 byte sequence (not supported), 0xF0 to 0xF4
		// or illegal, 0xF5 to 0xFF
		utf8_state = 255;
	}
}


// Step #2: translate Unicode code point to keystroke sequence
//
static KEYCODE_TYPE unicode_to_keycode(uint16_t cpoint)
{
	// Unicode code points beyond U+FFFF are not supported
	// technically this input should probably be called UCS-2
	if (cpoint < 32) {
		if (cpoint == 10) return KEY_ENTER & KEYCODE_MASK;
		if (cpoint == 11) return KEY_TAB & KEYCODE_MASK;
		return 0;
	}
	if (cpoint < 128) {
		return keycodes_ascii[cpoint - 0x20];
	}
	if (ISO_8859_1_A0) {
	if (cpoint >= 0xA0 && cpoint < 0x100) {
		return keycodes_iso_8859_1[cpoint - 0xA0];
	}
	}
	//#ifdef UNICODE_20AC
	//if (cpoint == 0x20AC) return UNICODE_20AC & 0x3FFF;
	//#endif
	if (KEYCODE_EXTRA00) if (cpoint == UNICODE_EXTRA00) return (KEYCODE_EXTRA00) & 0x3FFF;
	if (KEYCODE_EXTRA01) if (cpoint == UNICODE_EXTRA01) return (KEYCODE_EXTRA01) & 0x3FFF;
	if (KEYCODE_EXTRA02) if (cpoint == UNICODE_EXTRA02) return (KEYCODE_EXTRA02) & 0x3FFF;
	if (KEYCODE_EXTRA03) if (cpoint == UNICODE_EXTRA03) return (KEYCODE_EXTRA03) & 0x3FFF;
    if (KEYCODE_EXTRA04) if (cpoint == UNICODE_EXTRA04) return (KEYCODE_EXTRA04) & 0x3FFF;
    if (KEYCODE_EXTRA05) if (cpoint == UNICODE_EXTRA05) return (KEYCODE_EXTRA05) & 0x3FFF;
    if (KEYCODE_EXTRA06) if (cpoint == UNICODE_EXTRA06) return (KEYCODE_EXTRA06) & 0x3FFF;
    if (KEYCODE_EXTRA07) if (cpoint == UNICODE_EXTRA07) return (KEYCODE_EXTRA07) & 0x3FFF;
    if (KEYCODE_EXTRA08) if (cpoint == UNICODE_EXTRA08) return (KEYCODE_EXTRA08) & 0x3FFF;
    if (KEYCODE_EXTRA09) if (cpoint == UNICODE_EXTRA09) return (KEYCODE_EXTRA09) & 0x3FFF;
    if (KEYCODE_EXTRA0A) if (cpoint == UNICODE_EXTRA0A) return (KEYCODE_EXTRA0A) & 0x3FFF;
	return 0;
}

// Step #3: execute keystroke sequence
//

static KEYCODE_TYPE deadkey_to_keycode(KEYCODE_TYPE keycode)
{
	if(DEADKEYS_MASK) {
	keycode &= DEADKEYS_MASK;
	if (keycode == 0) return 0;
	if(ACUTE_ACCENT_BITS) if (keycode == ACUTE_ACCENT_BITS) return DEADKEY_ACUTE_ACCENT;
	if(CEDILLA_BITS) if (keycode == CEDILLA_BITS) return DEADKEY_CEDILLA;
	if(CIRCUMFLEX_BITS) if (keycode == CIRCUMFLEX_BITS) return DEADKEY_CIRCUMFLEX;
	if(DIAERESIS_BITS) if (keycode == DIAERESIS_BITS) return DEADKEY_DIAERESIS;
	if(GRAVE_ACCENT_BITS) if (keycode == GRAVE_ACCENT_BITS) return DEADKEY_GRAVE_ACCENT;
	if(TILDE_BITS) if (keycode == TILDE_BITS) return DEADKEY_TILDE;
	if(RING_ABOVE_BITS) if (keycode == RING_ABOVE_BITS) return DEADKEY_RING_ABOVE;
	if(DEGREE_SIGN_BITS) if (keycode == DEGREE_SIGN_BITS) return DEADKEY_DEGREE_SIGN;
	if(CARON_BITS) if (keycode == CARON_BITS) return DEADKEY_CARON;
	if(BREVE_BITS) if (keycode == BREVE_BITS) return DEADKEY_BREVE;
	if(OGONEK_BITS) if (keycode == OGONEK_BITS) return DEADKEY_OGONEK;
	if(DOT_ABOVE_BITS) if (keycode == DOT_ABOVE_BITS) return DEADKEY_DOT_ABOVE;
	if(DOUBLE_ACUTE_BITS) if (keycode == DOUBLE_ACUTE_BITS) return DEADKEY_DOUBLE_ACUTE;
}
	return 0;
}


void usb_keyboard_write_unicode(uint16_t cpoint)
{
	KEYCODE_TYPE keycode;

	keycode = unicode_to_keycode(cpoint);
	if (keycode) {
		if(DEADKEYS_MASK) {
		KEYCODE_TYPE deadkeycode = deadkey_to_keycode(keycode);
		if (deadkeycode) write_key(deadkeycode);
		}
		write_key(keycode);
	}
}


// Step #4: do each keystroke
//
static void write_key(KEYCODE_TYPE keycode)
{
/*
	uint8_t key, modifier=0;

	#ifdef SHIFT_MASK
	if (keycode & SHIFT_MASK) modifier |= MODIFIERKEY_SHIFT;
	#endif
	#ifdef ALTGR_MASK
	if (keycode & ALTGR_MASK) modifier |= MODIFIERKEY_RIGHT_ALT;
	#endif
	#ifdef RCTRL_MASK
	if (keycode & RCTRL_MASK) modifier |= MODIFIERKEY_RIGHT_CTRL;
	#endif
	key = keycode & 0x3F;
	#ifdef KEY_NON_US_100
	if (key == KEY_NON_US_100) key = 100;
	#endif
	usb_keyboard_press(key, modifier);
*/
	usb_keyboard_press(keycode_to_key(keycode), keycode_to_modifier(keycode));
}

static uint8_t keycode_to_modifier(KEYCODE_TYPE keycode)
{
	uint8_t modifier=0;
	
	if (SHIFT_MASK) if (keycode & SHIFT_MASK) modifier |= MODIFIERKEY_SHIFT;

	if (ALTGR_MASK) if (keycode & ALTGR_MASK) modifier |= MODIFIERKEY_RIGHT_ALT;

	if (RCTRL_MASK) if (keycode & RCTRL_MASK) modifier |= MODIFIERKEY_RIGHT_CTRL;

	return modifier;
}

static uint8_t keycode_to_key(KEYCODE_TYPE keycode)
{
	uint8_t key = keycode & 0x3F;
	if (KEY_NON_US_100) if (key == KEY_NON_US_100) key = 100;
	return key;
}

// Input can be:
//     32 - 127     ASCII direct (U+0020 to U+007F) <-- uses layout
//    128 - 0xC1FF  Unicode direct (U+0080 to U+C1FF) <-- uses layout
// 0xC200 - 0xDFFF  Unicode UTF8 packed (U+0080 to U+07FF) <-- uses layout
// 0xE000 - 0xE0FF  Modifier key (bitmap, 8 keys, shift/ctrl/alt/gui)
// 0xE200 - 0xE2FF  System key (HID usage code, within usage page 1)
// 0xE400 - 0xE7FF  Media/Consumer key (HID usage code, within usage page 12)
// 0xF000 - 0xFFFF  Normal key (HID usage code, within usage page 7)

void usb_keyboard_press_keycode(uint16_t n)
{
	uint8_t key, mod, msb, modrestore=0;
	KEYCODE_TYPE keycode;
	KEYCODE_TYPE deadkeycode;

	msb = n >> 8;
	if (msb >= 0xC2) {
		if (msb <= 0xDF) {
			n = (n & 0x3F) | ((uint16_t)(msb & 0x1F) << 6);
		} else if (msb == 0xF0) {
			usb_keyboard_press_key(n, 0);
			return;
		} else if (msb == 0xE0) {
			usb_keyboard_press_key(0, n);
			return;
#ifdef KEYMEDIA_INTERFACE
		} else if (msb == 0xE2) {
			// TODO: system keys
			return;
		} else if (msb >= 0xE4 && msb <= 0xE7) {
			// TODO: media/consumer keys
			return;
#endif
		} else {
			return;
		}
	}
	keycode = unicode_to_keycode(n);
	if (!keycode) return;
	if (DEADKEYS_MASK) {
	deadkeycode = deadkey_to_keycode(keycode);
	if (deadkeycode) {
		modrestore = keyboard_modifier_keys;
		if (modrestore) {
			keyboard_modifier_keys = 0;
			usb_keyboard_send();
		}
		// TODO: test if operating systems recognize
		// deadkey sequences when other keys are held
		mod = keycode_to_modifier(deadkeycode);
		key = keycode_to_key(deadkeycode);
		usb_keyboard_press_key(key, mod);
		usb_keyboard_release_key(key, mod);
	}
	}
	mod = keycode_to_modifier(keycode);
	key = keycode_to_key(keycode);
	usb_keyboard_press_key(key, mod | modrestore);
}


void usb_keyboard_release_keycode(uint16_t n)
{
	uint8_t key, mod, msb;

	msb = n >> 8;
	if (msb >= 0xC2) {
		if (msb <= 0xDF) {
			n = (n & 0x3F) | ((uint16_t)(msb & 0x1F) << 6);
		} else if (msb == 0xF0) {
			usb_keyboard_release_key(n, 0);
			return;
		} else if (msb == 0xE0) {
			usb_keyboard_release_key(0, n);
			return;
#ifdef KEYMEDIA_INTERFACE
		} else if (msb == 0xE2) {
			// TODO: system keys
			return;
		} else if (msb >= 0xE4 && msb <= 0xE7) {
			// TODO: media/consumer keys
			return;
#endif
		} else {
			return;
		}
	}
	KEYCODE_TYPE keycode = unicode_to_keycode(n);
	if (!keycode) return;
	mod = keycode_to_modifier(keycode);
	key = keycode_to_key(keycode);
	usb_keyboard_release_key(key, mod);
}


static void usb_keyboard_press_key(uint8_t key, uint8_t modifier)
{
	int i, send_required = 0;

	if (modifier) {
		if ((keyboard_modifier_keys & modifier) != modifier) {
			keyboard_modifier_keys |= modifier;
			send_required = 1;
			usb_keyboard_send();
			// SEND MODKEY MULTIPLE TIMES, FIXES RDP ISSUE 
			usb_keyboard_send();
			usb_keyboard_send();
			usb_keyboard_send();
			usb_keyboard_send();
		}
	}
	if (key) {
		for (i=0; i < 6; i++) {
			if (keyboard_keys[i] == key) goto end;
		}
		for (i=0; i < 6; i++) {
			if (keyboard_keys[i] == 0) {
				keyboard_keys[i] = key;
				send_required = 1;
				goto end;
			}
		}
	}
	end:
	if (send_required) usb_keyboard_send();
}


static void usb_keyboard_release_key(uint8_t key, uint8_t modifier)
{
	int i, send_required = 0;

	if (modifier) {
		if ((keyboard_modifier_keys & modifier) != 0) {
			keyboard_modifier_keys &= ~modifier;
			send_required = 1;
			usb_keyboard_send();
			// SEND MODKEY MULTIPLE TIMES
			usb_keyboard_send();
			usb_keyboard_send();
			usb_keyboard_send();
			usb_keyboard_send();
		}
	}
	if (key) {
		for (i=0; i < 6; i++) {
			if (keyboard_keys[i] == key) {
				keyboard_keys[i] = 0;
				send_required = 1;
			}
		}
	}
	if (send_required) usb_keyboard_send();
}

void usb_keyboard_release_all(void)
{
	uint8_t i, anybits;

	anybits = keyboard_modifier_keys;
	keyboard_modifier_keys = 0;
	anybits |= keyboard_media_keys;
	keyboard_media_keys = 0;
	for (i=0; i < 6; i++) {
		anybits |= keyboard_keys[i];
		keyboard_keys[i] = 0;
	}
	if (anybits) usb_keyboard_send();
}


int usb_keyboard_press(uint8_t key, uint8_t modifier)
{
	int r;
	keyboard_modifier_keys = modifier;
	keyboard_keys[0] = key;
	keyboard_keys[1] = 0;
	keyboard_keys[2] = 0;
	keyboard_keys[3] = 0;
	keyboard_keys[4] = 0;
	keyboard_keys[5] = 0;
	r = usb_keyboard_send();
	if (r) return r;
	keyboard_modifier_keys = 0;
	keyboard_keys[0] = 0;
	return usb_keyboard_send();
}


// Maximum number of transmit packets to queue so we don't starve other endpoints for memory
#define TX_PACKET_LIMIT 4

static uint8_t transmit_previous_timeout=0;

// When the PC isn't listening, how long do we wait before discarding data?
#define TX_TIMEOUT_MSEC 50

#if F_CPU == 168000000
  #define TX_TIMEOUT (TX_TIMEOUT_MSEC * 1100)
#elif F_CPU == 144000000
  #define TX_TIMEOUT (TX_TIMEOUT_MSEC * 932)
#elif F_CPU == 120000000
  #define TX_TIMEOUT (TX_TIMEOUT_MSEC * 764)
#elif F_CPU == 96000000
  #define TX_TIMEOUT (TX_TIMEOUT_MSEC * 596)
#elif F_CPU == 72000000
  #define TX_TIMEOUT (TX_TIMEOUT_MSEC * 512)
#elif F_CPU == 48000000
  #define TX_TIMEOUT (TX_TIMEOUT_MSEC * 428)
#elif F_CPU == 24000000
  #define TX_TIMEOUT (TX_TIMEOUT_MSEC * 262)
#endif


// send the contents of keyboard_keys and keyboard_modifier_keys
int usb_keyboard_send(void)
{
#if 0
	serial_print("Send:");
	serial_phex(keyboard_modifier_keys);
	serial_phex(keyboard_keys[0]);
	serial_phex(keyboard_keys[1]);
	serial_phex(keyboard_keys[2]);
	serial_phex(keyboard_keys[3]);
	serial_phex(keyboard_keys[4]);
	serial_phex(keyboard_keys[5]);
	serial_print("\n");
#endif
#if 1
	uint32_t wait_count=0;
	usb_packet_t *tx_packet;

	while (1) {
		if (!usb_configuration) {
			return -1;
		}
		if (usb_tx_packet_count(KEYBOARD_ENDPOINT) < TX_PACKET_LIMIT) {
			tx_packet = usb_malloc();
			if (tx_packet) break;
		}
		if (++wait_count > TX_TIMEOUT || transmit_previous_timeout) {
			transmit_previous_timeout = 1;
			return -1;
		}
		yield();
	}
	*(tx_packet->buf) = keyboard_modifier_keys;
	*(tx_packet->buf + 1) = keyboard_media_keys;
	memcpy(tx_packet->buf + 2, keyboard_keys, 6);
	tx_packet->len = 8;
	usb_tx(KEYBOARD_ENDPOINT, tx_packet);
#endif
	return 0;
}


#endif // F_CPU
#endif // KEYBOARD_INTERFACE
