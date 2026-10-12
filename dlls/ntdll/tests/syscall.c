/*
 * Tests for raw syscall emulation
 *
 * Copyright 2026 the Wine project authors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Native Windows code (notably anti-cheat loaders) bypasses the ntdll
 * syscall stubs and executes the syscall instruction directly with the
 * Windows syscall ABI (first argument in r10, stack arguments at
 * rsp+0x28).  The unix side must service such syscalls exactly like the
 * corresponding Nt function, or the caller detects the substitution.
 */

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/test.h"

#ifdef __x86_64__

/* NtGetNlsSectionPtr on Windows 10 build 19045 (x86-64) */
#define WIN10_19045_NtGetNlsSectionPtr 0x00fa
/* one past the highest syscall number on Windows 10 build 19045 (x86-64) */
#define WIN10_19045_SYSCALL_COUNT 0x01d9

static NTSTATUS (WINAPI *pNtGetNlsSectionPtr)(ULONG, ULONG, void *, void **, SIZE_T *);

/* Execute a syscall instruction directly, with the register and stack
 * state the Windows kernel expects at the instruction:
 *   rax = syscall number, r10 = 1st argument, rdx = 2nd, r8 = 3rd,
 *   r9 = 4th, [rsp+0x28] = 5th. */
static NTSTATUS raw_syscall( unsigned int nr, ULONG_PTR arg1, ULONG_PTR arg2,
                             ULONG_PTR arg3, ULONG_PTR arg4, ULONG_PTR arg5 )
{
    NTSTATUS status;
    __asm__( "movq %2, %%rcx\n\t"
             "movq %3, %%rdx\n\t"
             "movq %4, %%r8\n\t"
             "movq %5, %%r9\n\t"
             "movq %%rcx, %%r10\n\t"
             "subq $0x28, %%rsp\n\t"
             "movq %6, 0x28(%%rsp)\n\t"
             "movl %1, %%eax\n\t"
             "syscall\n\t"
             "addq $0x28, %%rsp\n\t"
             : "=a"(status)
             : "g"(nr), "g"(arg1), "g"(arg2), "g"(arg3), "g"(arg4), "g"(arg5)
             : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory" );
    return status;
}

static void test_raw_syscall_dispatch( void )
{
    NTSTATUS direct, raw;

    /* The same call through the ntdll stub and through a raw syscall with
     * the Windows number must return the same status.  An invalid NLS
     * section type fails with STATUS_INVALID_PARAMETER, like on Windows,
     * before any output pointer is dereferenced. */
    direct = pNtGetNlsSectionPtr( 0xdeadbeef, 0, NULL, NULL, NULL );
    ok( direct == STATUS_INVALID_PARAMETER, "NtGetNlsSectionPtr returned %08lx, expected STATUS_INVALID_PARAMETER\n", direct );

    raw = raw_syscall( WIN10_19045_NtGetNlsSectionPtr, 0xdeadbeef, 0, 0, 0, 0 );
    ok( raw == direct, "raw syscall %#x returned %08lx, expected %08lx (stub result)\n",
        WIN10_19045_NtGetNlsSectionPtr, raw, direct );
}

/* Execute a syscall instruction directly with distinctive flags set, and
 * report the register state the Windows kernel leaves behind: the status
 * in rax, the return address in rcx, the pre-syscall flags in r11, and
 * the post-syscall flags. */
static NTSTATUS raw_syscall_probe( unsigned int nr, ULONG_PTR arg1, ULONG_PTR arg2,
                                   ULONG_PTR arg3, ULONG_PTR arg4, ULONG_PTR arg5,
                                   ULONG64 set_flags, ULONG64 *ret_rcx,
                                   ULONG64 *ret_r11, ULONG64 *post_flags )
{
    NTSTATUS status;
    ULONG64 r11, after;
    ULONG64 rcx_out;
    __asm__( "movq %[a1], %%rcx\n\t"
             "movq %[a2], %%rdx\n\t"
             "movq %[a3], %%r8\n\t"
             "movq %[a4], %%r9\n\t"
             "movq %%rcx, %%r10\n\t"
             "subq $0x28, %%rsp\n\t"
             "movq %[a5], 0x28(%%rsp)\n\t"
             "pushfq\n\t"
             "popq %%rsi\n\t"             /* original flags */
             "orq %[sf], %%rsi\n\t"       /* force the bits under test */
             "pushq %%rsi\n\t"
             "popfq\n\t"
             "movl %[nr], %%eax\n\t"
             "syscall\n\t"
             "movq %%r11, %[r11]\n\t"
             "movq %%rcx, %[rcxo]\n\t"
             "pushfq\n\t"
             "popq %[after]\n\t"
             "addq $0x28, %%rsp\n\t"
             : [out] "=a"(status), [r11] "=r"(r11), [rcxo] "=r"(rcx_out), [after] "=r"(after)
             : [nr] "g"(nr), [a1] "g"(arg1), [a2] "g"(arg2), [a3] "g"(arg3),
               [a4] "g"(arg4), [a5] "g"(arg5), [sf] "r"(set_flags)
             : "rcx", "rdx", "r8", "r9", "r10", "rsi", "memory" );
    *ret_rcx = rcx_out;
    *ret_r11 = r11;
    *post_flags = after;
    return status;
}

static void test_raw_syscall_register_semantics( void )
{
    static const struct { ULONG64 mask; const char *name; } flag_tests[] =
    {
        { 0x202,   "IF|bit1" },   /* interrupt flag + always-one bit */
        { 0x400,   "DF" },        /* direction flag */
        { 0x40000, "AC" },       /* alignment check */
    };
    NTSTATUS status, direct;
    ULONG64 rcx, r11, post_flags;
    unsigned int i;

    /* Windows semantics: syscall stores RFLAGS in r11 and leaves the
     * return address in rcx; sysret restores the flags.  The emulated
     * syscall must do the same, for every flag bit the caller set. */
    for (i = 0; i < ARRAY_SIZE(flag_tests); i++)
    {
        status = raw_syscall_probe( WIN10_19045_NtGetNlsSectionPtr, 0xdeadbeef, 0, 0, 0, 0,
                                    flag_tests[i].mask, &rcx, &r11, &post_flags );

        ok( (r11 & flag_tests[i].mask) == flag_tests[i].mask,
            "%s: r11 = %s, expected set flags preserved\n",
            flag_tests[i].name, wine_dbgstr_longlong( r11 ) );
        ok( (post_flags & flag_tests[i].mask) == flag_tests[i].mask,
            "%s: post-syscall flags = %s, expected set flags restored\n",
            flag_tests[i].name, wine_dbgstr_longlong( post_flags ) );
    }

    status = raw_syscall_probe( WIN10_19045_NtGetNlsSectionPtr, 0xdeadbeef, 0, 0, 0, 0,
                                0x202, &rcx, &r11, &post_flags );
    direct = pNtGetNlsSectionPtr( 0xdeadbeef, 0, NULL, NULL, NULL );
    ok( status == direct, "raw syscall returned %08lx, expected %08lx\n", status, direct );
    /* rcx must hold the address of the instruction after the syscall */
    ok( (rcx & 0xfff) != 0, "rcx = %s, expected a return address\n", wine_dbgstr_longlong( rcx ) );
}

static void test_raw_syscall_invalid_number( void )
{
    NTSTATUS raw;

    /* A number outside the Windows syscall table must fail the way the
     * Windows kernel fails an unknown syscall, and execution must resume
     * at the instruction after the syscall instruction. */
    raw = raw_syscall( WIN10_19045_SYSCALL_COUNT, 0xdeadbeef, 0, 0, 0, 0 );
    ok( raw == STATUS_INVALID_SYSTEM_SERVICE, "unknown syscall returned %08lx\n", raw );
}

static void init_function_pointers( void )
{
    HMODULE ntdll = GetModuleHandleW( L"ntdll.dll" );

    pNtGetNlsSectionPtr = (void *)GetProcAddress( ntdll, "NtGetNlsSectionPtr" );
    ok( pNtGetNlsSectionPtr != NULL, "NtGetNlsSectionPtr not found\n" );
}

#endif /* __x86_64__ */

START_TEST(syscall)
{
#ifdef __x86_64__
    init_function_pointers();
    if (!pNtGetNlsSectionPtr) return;
    test_raw_syscall_dispatch();
    test_raw_syscall_invalid_number();
    test_raw_syscall_register_semantics();
#endif
}
