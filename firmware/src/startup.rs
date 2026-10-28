//! Reset-time CPU state for an application started by a bootloader.
//!
//! koptserg's MCUboot and `bootloader/` jump to the reset handler at
//! `0x4100` with whatever SysTick, NVIC and PRIMASK state they left behind;
//! MCUboot's TI port also does not point VTOR at the application. The
//! `set-vtor` and `set-sp` features of `cortex-m-rt` load VTOR and MSP from
//! this image's vector table; `__pre_init` (called by `cortex-m-rt` before
//! RAM initialisation, so it must not touch RAM) stops SysTick, disables
//! and un-pends every NVIC interrupt, clears pending SysTick/PendSV, and
//! re-enables interrupts at the core, which is the state of a cold reset.

core::arch::global_asm!(
    ".section .text.__pre_init,\"ax\"",
    ".global __pre_init",
    ".type __pre_init,%function",
    ".thumb_func",
    "__pre_init:",
    "    cpsid i",
    // SysTick CSR: counter and interrupt off.
    "    ldr r0, =0xE000E010",
    "    movs r1, #0",
    "    str r1, [r0]",
    // NVIC ICER0 / ICPR0: disable and un-pend all 32 lines.
    "    mvns r1, r1",
    "    ldr r0, =0xE000E180",
    "    str r1, [r0]",
    "    ldr r0, =0xE000E280",
    "    str r1, [r0]",
    // ICSR: PENDSVCLR | PENDSTCLR.
    "    ldr r0, =0xE000ED04",
    "    ldr r1, =0x0A000000",
    "    str r1, [r0]",
    "    dsb",
    "    isb",
    "    cpsie i",
    "    bx lr",
    ".ltorg",
    ".size __pre_init, . - __pre_init",
);
