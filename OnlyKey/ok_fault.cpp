/* Fault handlers, stack/heap check and the optional watchdog. See ok_fault.h.
 *
 * Everything here is Cortex-M specific. A host build of the firmware (the
 * emulator, OK_EMULATOR) has no fault vectors, no watchdog and a different
 * stack, so it gets do-nothing versions that keep the sketch linking.
 */
#include "ok_fault.h"
#include "okcore.h" // MAX_RSA_KEY_SIZE, MAX_ECC_KEY_SIZE

#if defined(__arm__) && !defined(OK_EMULATOR)

#include "kinetis.h"

extern uint8_t profilekey[32];
extern uint8_t transit_key[32];
extern uint8_t rsa_private_key[MAX_RSA_KEY_SIZE];
extern uint8_t ecc_private_key[MAX_ECC_KEY_SIZE];
extern "C" char *sbrk(int incr);

static inline void ok_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

// Fault handlers run on whatever stack is left, so they wipe with plain
// loops, never return, and reset through a volatile AIRCR store. The core's
// fault_isr() is a strong symbol; the vectors below are its weak aliases.
extern "C" __attribute__((noreturn, used)) void ok_fault_reset(void) {
    __asm__ volatile("cpsid i" ::: "memory");
    ok_wipe(profilekey, sizeof(profilekey));
    ok_wipe(transit_key, sizeof(transit_key));
    ok_wipe(rsa_private_key, MAX_RSA_KEY_SIZE);
    ok_wipe(ecc_private_key, MAX_ECC_KEY_SIZE);
    __asm__ volatile("dsb" ::: "memory");
    *(volatile uint32_t *)0xE000ED0C = 0x05FA0004;
    __asm__ volatile("dsb" ::: "memory");
    for (;;) {}
}
extern "C" void hard_fault_isr(void) { ok_fault_reset(); }
extern "C" void memmanage_fault_isr(void) { ok_fault_reset(); }
extern "C" void bus_fault_isr(void) { ok_fault_reset(); }
extern "C" void usage_fault_isr(void) { ok_fault_reset(); }

// The stack grows down towards the heap with no guard between them.
extern "C" void check_stack_bounds(void) {
    uint32_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    if (sp <= (uint32_t)sbrk(0) + 256) ok_fault_reset();
}

// Optional hardware watchdog. Off by default: an RSA-4096 private-key
// operation alone takes about 8 s, and backup/restore loops do not kick it.
#ifdef OK_WATCHDOG_MS
static inline uint32_t ok_irq_save(void) {
    uint32_t primask;
    __asm__ volatile("mrs %0, primask\n\tcpsid i" : "=r"(primask)::"memory");
    return primask;
}
static inline void ok_irq_restore(uint32_t primask) {
    __asm__ volatile("msr primask, %0" ::"r"(primask) : "memory");
}
extern "C" void wdog_kick(void) {
    uint32_t primask = ok_irq_save();
    WDOG_REFRESH = 0xA602;
    WDOG_REFRESH = 0xB480;
    ok_irq_restore(primask);
}
extern "C" void wdog_init(uint32_t timeout_ms) {
    uint32_t primask = ok_irq_save();
    WDOG_UNLOCK = WDOG_UNLOCK_SEQ1;
    WDOG_UNLOCK = WDOG_UNLOCK_SEQ2;
    __asm__ volatile("nop\n\tnop");
    WDOG_TOVALH = timeout_ms >> 16; // 1 kHz LPO clock: one count per ms
    WDOG_TOVALL = timeout_ms & 0xFFFF;
    WDOG_PRESC = 0;
    WDOG_STCTRLH = WDOG_STCTRLH_WDOGEN | WDOG_STCTRLH_ALLOWUPDATE;
    ok_irq_restore(primask);
}
#else
extern "C" void wdog_kick(void) {}
extern "C" void wdog_init(uint32_t timeout_ms) { (void)timeout_ms; }
#endif

#else // host build

#include <stdlib.h>

extern "C" void ok_fault_reset(void) { abort(); }
extern "C" void check_stack_bounds(void) {}
extern "C" void wdog_kick(void) {}
extern "C" void wdog_init(uint32_t timeout_ms) { (void)timeout_ms; }

#endif
