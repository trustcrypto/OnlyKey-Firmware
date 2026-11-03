/* Fault handlers, stack/heap check and the optional watchdog.
 *
 * Kept out of OnlyKey.ino because Arduino 1.6.5 generates C++ prototypes for
 * every function in the sketch, which conflicts with the extern "C" fault
 * vectors and with static functions inside #ifdef blocks.
 */
#ifndef OK_FAULT_H
#define OK_FAULT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Wipe the key buffers with volatile stores, then reset. Never returns. */
void ok_fault_reset(void) __attribute__((noreturn));

/* Reset if the stack has grown to within 256 bytes of the heap. */
void check_stack_bounds(void);

/* Refresh the hardware watchdog; a no-op unless built with -DOK_WATCHDOG_MS. */
void wdog_kick(void);

/* Start the hardware watchdog (only compiled with OK_WATCHDOG_MS). */
void wdog_init(uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif
