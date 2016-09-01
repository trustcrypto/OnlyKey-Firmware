/* Modifications by Tim Steiner
 * Copyright (c) 2016 , CryptoTrust LLC.
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
 *    "This product includes software developed by the OnlyKey Project
 *    (http://www.crp.to/ok)"
 *
 * 4. The names "OnlyKey" and "OnlyKey Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    admin@crp.to.
 *
 * 5. Products derived from this software may not be called "OnlyKey"
 *    nor may "OnlyKey" appear in their names without prior written
 *    permission of the OnlyKey Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OnlyKey Project
 *    (http://www.crp.to/ok)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OnlyKey PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OnlyKey PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Original Teensyduino Core Library
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

#ifndef KEYLAYOUTS_H__
#define KEYLAYOUTS_H__

#include <stdint.h>
#include <avr/pgmspace.h>



#ifdef __cplusplus
extern "C"{
#endif

#define LAYOUT_US_ENGLISH	0x01
#define LAYOUT_CANADIAN_FRENCH	0x02
#define LAYOUT_CANADIAN_MULTILINGUAL	0x03
#define LAYOUT_DANISH	0x04
#define LAYOUT_FINNISH	0x05
#define LAYOUT_FRENCH	0x06
#define LAYOUT_FRENCH_BELGIAN	0x07
#define LAYOUT_FRENCH_SWISS	0x08
#define LAYOUT_GERMAN	0x09
#define LAYOUT_GERMAN_MAC	0x0A
#define LAYOUT_GERMAN_SWISS	0x0B
#define LAYOUT_ICELANDIC	0x0C
#define LAYOUT_IRISH	0x0D
#define LAYOUT_ITALIAN	0x0E
#define LAYOUT_NORWEGIAN	0x0F
#define LAYOUT_PORTUGUESE	0x10
#define LAYOUT_PORTUGUESE_BRAZILIAN	0x11
#define LAYOUT_SPANISH	0x12
#define LAYOUT_SPANISH_LATIN_AMERICA	0x13
#define LAYOUT_SWEDISH	0x14
#define LAYOUT_TURKISH	0x15
#define LAYOUT_UNITED_KINGDOM	0x16
#define LAYOUT_US_INTERNATIONAL	0x17
#define LAYOUT_CZECH	0x18
#define LAYOUT_SERBIAN_LATIN_ONLY	0x19


// http://en.wikipedia.org/wiki/Keyboard_layout


#define MODIFIERKEY_CTRL        ( 0x01 | 0x8000 )
#define MODIFIERKEY_SHIFT       ( 0x02 | 0x8000 )
#define MODIFIERKEY_ALT         ( 0x04 | 0x8000 )
#define MODIFIERKEY_GUI         ( 0x08 | 0x8000 )
#define MODIFIERKEY_LEFT_CTRL   ( 0x01 | 0x8000 )
#define MODIFIERKEY_LEFT_SHIFT  ( 0x02 | 0x8000 )
#define MODIFIERKEY_LEFT_ALT    ( 0x04 | 0x8000 )
#define MODIFIERKEY_LEFT_GUI    ( 0x08 | 0x8000 )
#define MODIFIERKEY_RIGHT_CTRL  ( 0x10 | 0x8000 )
#define MODIFIERKEY_RIGHT_SHIFT ( 0x20 | 0x8000 )
#define MODIFIERKEY_RIGHT_ALT   ( 0x40 | 0x8000 )
#define MODIFIERKEY_RIGHT_GUI   ( 0x80 | 0x8000 )

#define KEY_MEDIA_VOLUME_INC    0x01
#define KEY_MEDIA_VOLUME_DEC    0x02
#define KEY_MEDIA_MUTE          0x04
#define KEY_MEDIA_PLAY_PAUSE    0x08
#define KEY_MEDIA_NEXT_TRACK    0x10
#define KEY_MEDIA_PREV_TRACK    0x20
#define KEY_MEDIA_STOP          0x40
#define KEY_MEDIA_EJECT         0x80

#define KEY_A           ( 4   | 0x4000 )
#define KEY_B           ( 5   | 0x4000 )
#define KEY_C           ( 6   | 0x4000 )
#define KEY_D           ( 7   | 0x4000 )
#define KEY_E           ( 8   | 0x4000 )
#define KEY_F           ( 9   | 0x4000 )
#define KEY_G           ( 10  | 0x4000 )
#define KEY_H           ( 11  | 0x4000 )
#define KEY_I           ( 12  | 0x4000 )
#define KEY_J           ( 13  | 0x4000 )
#define KEY_K           ( 14  | 0x4000 )
#define KEY_L           ( 15  | 0x4000 )
#define KEY_M           ( 16  | 0x4000 )
#define KEY_N           ( 17  | 0x4000 )
#define KEY_O           ( 18  | 0x4000 )
#define KEY_P           ( 19  | 0x4000 )
#define KEY_Q           ( 20  | 0x4000 )
#define KEY_R           ( 21  | 0x4000 )
#define KEY_S           ( 22  | 0x4000 )
#define KEY_T           ( 23  | 0x4000 )
#define KEY_U           ( 24  | 0x4000 )
#define KEY_V           ( 25  | 0x4000 )
#define KEY_W           ( 26  | 0x4000 )
#define KEY_X           ( 27  | 0x4000 )
#define KEY_Y           ( 28  | 0x4000 )
#define KEY_Z           ( 29  | 0x4000 )
#define KEY_1           ( 30  | 0x4000 )
#define KEY_2           ( 31  | 0x4000 )
#define KEY_3           ( 32  | 0x4000 )
#define KEY_4           ( 33  | 0x4000 )
#define KEY_5           ( 34  | 0x4000 )
#define KEY_6           ( 35  | 0x4000 )
#define KEY_7           ( 36  | 0x4000 )
#define KEY_8           ( 37  | 0x4000 )
#define KEY_9           ( 38  | 0x4000 )
#define KEY_0           ( 39  | 0x4000 )
#define KEY_ENTER       ( 40  | 0x4000 )
#define KEY_ESC         ( 41  | 0x4000 )
#define KEY_BACKSPACE   ( 42  | 0x4000 )
#define KEY_TAB         ( 43  | 0x4000 )
#define KEY_SPACE       ( 44  | 0x4000 )
#define KEY_MINUS       ( 45  | 0x4000 )
#define KEY_EQUAL       ( 46  | 0x4000 )
#define KEY_LEFT_BRACE  ( 47  | 0x4000 )
#define KEY_RIGHT_BRACE ( 48  | 0x4000 )
#define KEY_BACKSLASH   ( 49  | 0x4000 )
#define KEY_NON_US_NUM  ( 50  | 0x4000 )
#define KEY_SEMICOLON   ( 51  | 0x4000 )
#define KEY_QUOTE       ( 52  | 0x4000 )
#define KEY_TILDE       ( 53  | 0x4000 )
#define KEY_COMMA       ( 54  | 0x4000 )
#define KEY_PERIOD      ( 55  | 0x4000 )
#define KEY_SLASH       ( 56  | 0x4000 )
#define KEY_CAPS_LOCK   ( 57  | 0x4000 )
#define KEY_F1          ( 58  | 0x4000 )
#define KEY_F2          ( 59  | 0x4000 )
#define KEY_F3          ( 60  | 0x4000 )
#define KEY_F4          ( 61  | 0x4000 )
#define KEY_F5          ( 62  | 0x4000 )
#define KEY_F6          ( 63  | 0x4000 )
#define KEY_F7          ( 64  | 0x4000 )
#define KEY_F8          ( 65  | 0x4000 )
#define KEY_F9          ( 66  | 0x4000 )
#define KEY_F10         ( 67  | 0x4000 )
#define KEY_F11         ( 68  | 0x4000 )
#define KEY_F12         ( 69  | 0x4000 )
#define KEY_PRINTSCREEN ( 70  | 0x4000 )
#define KEY_SCROLL_LOCK ( 71  | 0x4000 )
#define KEY_PAUSE       ( 72  | 0x4000 )
#define KEY_INSERT      ( 73  | 0x4000 )
#define KEY_HOME        ( 74  | 0x4000 )
#define KEY_PAGE_UP     ( 75  | 0x4000 )
#define KEY_DELETE      ( 76  | 0x4000 )
#define KEY_END         ( 77  | 0x4000 )
#define KEY_PAGE_DOWN   ( 78  | 0x4000 )
#define KEY_RIGHT       ( 79  | 0x4000 )
#define KEY_LEFT        ( 80  | 0x4000 )
#define KEY_DOWN        ( 81  | 0x4000 )
#define KEY_UP          ( 82  | 0x4000 )
#define KEY_NUM_LOCK    ( 83  | 0x4000 )
#define KEYPAD_SLASH    ( 84  | 0x4000 )
#define KEYPAD_ASTERIX  ( 85  | 0x4000 )
#define KEYPAD_MINUS    ( 86  | 0x4000 )
#define KEYPAD_PLUS     ( 87  | 0x4000 )
#define KEYPAD_ENTER    ( 88  | 0x4000 )
#define KEYPAD_1        ( 89  | 0x4000 )
#define KEYPAD_2        ( 90  | 0x4000 )
#define KEYPAD_3        ( 91  | 0x4000 )
#define KEYPAD_4        ( 92  | 0x4000 )
#define KEYPAD_5        ( 93  | 0x4000 )
#define KEYPAD_6        ( 94  | 0x4000 )
#define KEYPAD_7        ( 95  | 0x4000 )
#define KEYPAD_8        ( 96  | 0x4000 )
#define KEYPAD_9        ( 97  | 0x4000 )
#define KEYPAD_0        ( 98  | 0x4000 )
#define KEYPAD_PERIOD   ( 99  | 0x4000 )
#define KEY_MENU	( 101 | 0x4000 )
#define KEY_F13         ( 104 | 0x4000 )
#define KEY_F14         ( 105 | 0x4000 )
#define KEY_F15         ( 106 | 0x4000 )
#define KEY_F16         ( 107 | 0x4000 )
#define KEY_F17         ( 108 | 0x4000 )
#define KEY_F18         ( 109 | 0x4000 )
#define KEY_F19         ( 110 | 0x4000 )
#define KEY_F20         ( 111 | 0x4000 )
#define KEY_F21         ( 112 | 0x4000 )
#define KEY_F22         ( 113 | 0x4000 )
#define KEY_F23         ( 114 | 0x4000 )
#define KEY_F24         ( 115 | 0x4000 )


// for compatibility with Leonardo's slightly different names
#define KEY_UP_ARROW	KEY_UP
#define KEY_DOWN_ARROW	KEY_DOWN
#define KEY_LEFT_ARROW	KEY_LEFT
#define KEY_RIGHT_ARROW	KEY_RIGHT
#define KEY_RETURN	KEY_ENTER
#define KEY_LEFT_CTRL	MODIFIERKEY_LEFT_CTRL
#define KEY_LEFT_SHIFT	MODIFIERKEY_LEFT_SHIFT
#define KEY_LEFT_ALT	MODIFIERKEY_LEFT_ALT
#define KEY_LEFT_GUI	MODIFIERKEY_LEFT_GUI
#define KEY_RIGHT_CTRL	MODIFIERKEY_RIGHT_CTRL
#define KEY_RIGHT_SHIFT	MODIFIERKEY_RIGHT_SHIFT
#define KEY_RIGHT_ALT	MODIFIERKEY_RIGHT_ALT
#define KEY_RIGHT_GUI	MODIFIERKEY_RIGHT_GUI

#define KEYCODE_TYPE	uint16_t




extern void update_keyboard_layout(uint8_t *ptr);
extern KEYCODE_TYPE keycodes_ascii[];
extern KEYCODE_TYPE keycodes_iso_8859_1[];

#ifdef __cplusplus
} // extern "C"
#endif

#endif
