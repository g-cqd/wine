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
#endif
}
