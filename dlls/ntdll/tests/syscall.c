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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/asm.h"
#include "wine/test.h"

#ifdef __x86_64__

#include "../unix/win10_19045_syscalls.h"

/* NtGetNlsSectionPtr on Windows 10 build 19045 (x86-64) */
#define WIN10_19045_NtGetNlsSectionPtr 0x00fa
/* NtInitializeRegistry on Windows 10 build 19045 (x86-64) */
#define WIN10_19045_NtInitializeRegistry 0x0101
/* NtWaitForSingleObject on Windows 10 build 19045 (x86-64) */
#define WIN10_19045_NtWaitForSingleObject 0x0004
/* NtWaitLowEventPair on Windows 10 build 19045 (x86-64) - highest number in the 19045 table */
#define WIN10_19045_NtWaitLowEventPair 0x01d8
static NTSTATUS (WINAPI *pNtGetNlsSectionPtr)(ULONG, ULONG, void *, void **, SIZE_T *);
static NTSTATUS (WINAPI *pNtWaitForSingleObject)(HANDLE, BOOLEAN, const LARGE_INTEGER *);
static NTSTATUS (WINAPI *pZwSetThreadExecutionState)(EXECUTION_STATE, EXECUTION_STATE *);
static NTSTATUS (WINAPI *pNtAccessCheck)(SECURITY_DESCRIPTOR *, HANDLE, ACCESS_MASK, GENERIC_MAPPING *,
                                        PRIVILEGE_SET *, ULONG *, ACCESS_MASK *, NTSTATUS *);
static NTSTATUS (WINAPI *pNtWaitLowEventPair)(HANDLE);

/* Keep the caller's Windows stack arguments at rsp+0x28 through rsp+0x40. */
extern ULONG64 WINAPI raw_access_check( SECURITY_DESCRIPTOR *, HANDLE, ACCESS_MASK, GENERIC_MAPPING *,
                                        PRIVILEGE_SET *, ULONG *, ACCESS_MASK *, NTSTATUS * );
__ASM_GLOBAL_FUNC( raw_access_check,
                   __ASM_SEH(".seh_endprologue\n\t")
                   "movq %rcx,%r10\n\t"
                   "xorl %eax,%eax\n\t" /* NtAccessCheck is Windows syscall zero. */
                   "syscall\n\t"
                   "ret" );

static void test_access_check_dispatch( BOOL patched )
{
    static const struct
    {
        BOOL empty_dacl;
        NTSTATUS access_status;
        ACCESS_MASK granted;
    } cases[] =
    {
        { FALSE, STATUS_SUCCESS, KEY_QUERY_VALUE },
        { TRUE, STATUS_ACCESS_DENIED, 0 }
    };
    SID_IDENTIFIER_AUTHORITY world_authority = { SECURITY_WORLD_SID_AUTHORITY };
    GENERIC_MAPPING mapping = { KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS };
    SECURITY_DESCRIPTOR descriptor;
    PRIVILEGE_SET direct_privs, raw_privs;
    HANDLE process_token, token;
    NTSTATUS direct, direct_access, raw_access;
    ACCESS_MASK direct_granted, raw_granted;
    ULONG direct_len, raw_len;
    ULONG64 raw;
    DWORD exception;
    SID world;
    ACL empty_acl;
    unsigned int i;
    BOOL ret;

    ret = InitializeSid( &world, &world_authority, 1 );
    ok( ret, "InitializeSid failed, error %lu\n", GetLastError() );
    if (!ret) return;
    world.SubAuthority[0] = SECURITY_WORLD_RID;
    ret = InitializeSecurityDescriptor( &descriptor, SECURITY_DESCRIPTOR_REVISION );
    ok( ret, "InitializeSecurityDescriptor failed, error %lu\n", GetLastError() );
    if (!ret) return;
    ret = SetSecurityDescriptorOwner( &descriptor, &world, FALSE );
    ok( ret, "SetSecurityDescriptorOwner failed, error %lu\n", GetLastError() );
    if (!ret) return;
    ret = SetSecurityDescriptorGroup( &descriptor, &world, FALSE );
    ok( ret, "SetSecurityDescriptorGroup failed, error %lu\n", GetLastError() );
    if (!ret) return;
    ret = InitializeAcl( &empty_acl, sizeof(empty_acl), ACL_REVISION );
    ok( ret, "InitializeAcl failed, error %lu\n", GetLastError() );
    if (!ret) return;
    ret = OpenProcessToken( GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &process_token );
    ok( ret, "OpenProcessToken failed, error %lu\n", GetLastError() );
    if (!ret) return;
    ret = DuplicateToken( process_token, SecurityImpersonation, &token );
    CloseHandle( process_token );
    ok( ret, "DuplicateToken failed, error %lu\n", GetLastError() );
    if (!ret) return;

    for (i = 0; i < ARRAY_SIZE(cases); i++)
    {
        winetest_push_context( "%s, empty DACL %u", patched ? "patched" : "native/raw", cases[i].empty_dacl );
        ret = SetSecurityDescriptorDacl( &descriptor, TRUE, cases[i].empty_dacl ? &empty_acl : NULL, FALSE );
        ok( ret, "SetSecurityDescriptorDacl failed, error %lu\n", GetLastError() );
        if (!ret)
        {
            winetest_pop_context();
            break;
        }
        memset( &direct_privs, 0, sizeof(direct_privs) );
        direct_len = sizeof(direct_privs);
        direct = direct_access = direct_granted = 0xdeadbeef;
        exception = 0;
        __try
        {
            direct = pNtAccessCheck( &descriptor, token, KEY_QUERY_VALUE, &mapping, &direct_privs,
                                    &direct_len, &direct_granted, &direct_access );
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            exception = GetExceptionCode();
        }
        ok( !exception, "NtAccessCheck raised exception %08lx\n", exception );
        if (!exception)
        {
            ok( direct == STATUS_SUCCESS, "NtAccessCheck returned %08lx\n", direct );
            ok( direct_access == cases[i].access_status && direct_granted == cases[i].granted,
                "NtAccessCheck access %08lx, granted %08lx\n", direct_access, direct_granted );
        }
        if (!patched)
        {
            memset( &raw_privs, 0, sizeof(raw_privs) );
            raw_len = sizeof(raw_privs);
            raw_access = raw_granted = 0xdeadbeef;
            raw = raw_access_check( &descriptor, token, KEY_QUERY_VALUE, &mapping, &raw_privs,
                                    &raw_len, &raw_granted, &raw_access );
            ok( raw == (ULONG)direct, "raw NtAccessCheck returned %s, expected %08lx\n",
                wine_dbgstr_longlong( raw ), direct );
            ok( raw_access == direct_access && raw_granted == direct_granted,
                "raw NtAccessCheck access %08lx, granted %08lx; expected %08lx, %08lx\n",
                raw_access, raw_granted, direct_access, direct_granted );
        }
        winetest_pop_context();
    }
    CloseHandle( token );
}

/* Execute a syscall instruction directly, with the register and stack
 * state the Windows kernel expects at the instruction:
 *   rax = syscall number, r10 = 1st argument, rdx = 2nd, r8 = 3rd,
 *   r9 = 4th, [rsp+0x28] = 5th. */
static ULONG64 raw_syscall( unsigned int nr, ULONG_PTR arg1, ULONG_PTR arg2,
                            ULONG_PTR arg3, ULONG_PTR arg4, ULONG_PTR arg5 )
{
    ULONG64 status;
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

static void test_raw_syscall_wait( void )
{
    LARGE_INTEGER zero_timeout;
    HANDLE invalid_handle = (HANDLE)(ULONG_PTR)0xffffffffffffd8f0ULL;
    const LARGE_INTEGER *invalid_timeout = (const LARGE_INTEGER *)(ULONG_PTR)0xffffffffffffd8f0ULL;
    HANDLE event;
    NTSTATUS direct, raw;

    zero_timeout.QuadPart = 0;

    /* Match the waits used by the EA anti-cheat loader. */
    direct = pNtWaitForSingleObject( GetCurrentProcess(), FALSE, &zero_timeout );
    ok( direct == STATUS_TIMEOUT, "NtWaitForSingleObject(process) returned %08lx\n", direct );
    raw = raw_syscall( WIN10_19045_NtWaitForSingleObject, (ULONG_PTR)GetCurrentProcess(), FALSE,
                       (ULONG_PTR)&zero_timeout, 0, 0 );
    ok( raw == direct, "raw NtWaitForSingleObject(process) returned %08lx, expected %08lx\n", raw, direct );

    direct = pNtWaitForSingleObject( GetCurrentProcess(), FALSE, invalid_timeout );
    ok( direct == STATUS_ACCESS_VIOLATION, "NtWaitForSingleObject(invalid timeout) returned %08lx\n", direct );
    raw = raw_syscall( WIN10_19045_NtWaitForSingleObject, (ULONG_PTR)GetCurrentProcess(), FALSE,
                       (ULONG_PTR)invalid_timeout, 0, 0 );
    ok( raw == direct, "raw NtWaitForSingleObject(invalid timeout) returned %08lx, expected %08lx\n", raw, direct );

    direct = pNtWaitForSingleObject( invalid_handle, FALSE, NULL );
    ok( direct == STATUS_INVALID_HANDLE, "NtWaitForSingleObject(invalid handle) returned %08lx\n", direct );
    raw = raw_syscall( WIN10_19045_NtWaitForSingleObject, (ULONG_PTR)invalid_handle, FALSE, 0, 0, 0 );
    ok( raw == direct, "raw NtWaitForSingleObject(invalid handle) returned %08lx, expected %08lx\n", raw, direct );

    event = CreateEventW( NULL, TRUE, TRUE, NULL );
    ok( event != NULL, "CreateEventW failed, error %lu\n", GetLastError() );
    if (!event) return;
    direct = pNtWaitForSingleObject( event, FALSE, &zero_timeout );
    ok( direct == STATUS_SUCCESS, "NtWaitForSingleObject(signaled event) returned %08lx\n", direct );
    raw = raw_syscall( WIN10_19045_NtWaitForSingleObject, (ULONG_PTR)event, FALSE,
                       (ULONG_PTR)&zero_timeout, 0, 0 );
    ok( raw == direct, "raw NtWaitForSingleObject(signaled event) returned %08lx, expected %08lx\n", raw, direct );
    CloseHandle( event );
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
    ULONG64 raw;

    /* A number outside the Windows syscall table must fail the way the
     * Windows kernel fails an unknown syscall, and execution must resume
     * at the instruction after the syscall instruction. */
    raw = raw_syscall( WIN10_19045_SYSCALL_COUNT, 0xdeadbeef, 0, 0, 0, 0 );
    ok( raw == (ULONG)STATUS_INVALID_SYSTEM_SERVICE, "unknown syscall returned %s\n",
        wine_dbgstr_longlong( raw ) );
}

static void test_raw_syscall_registry_invalid_condition( void )
{
    static const ULONG_PTR invalid_conditions[] =
    {
        3, 0xfff, 0x13e9, 0xffff,
        0xffffffffffffd8f0ULL, 0x123456780000d8f0ULL
    };
    ULONG64 raw;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(invalid_conditions); i++)
    {
        raw = raw_syscall( WIN10_19045_NtInitializeRegistry, invalid_conditions[i], 0, 0, 0, 0 );
        ok( raw == (ULONG)STATUS_INVALID_PARAMETER,
            "raw NtInitializeRegistry(%s) returned %s, expected zero-extended STATUS_INVALID_PARAMETER\n",
            wine_dbgstr_longlong( invalid_conditions[i] ), wine_dbgstr_longlong( raw ) );
    }
}

/* the six ntdll Zw stubs the EA anti-cheat (Javelin) loader hashes in
 * its first verification round, plus two it resolves in later rounds;
 * the syscall numbers they carry on Windows 10 build 19045 (x86-64) */
static const struct { const char *name; unsigned int nr; } eaac_zw_stubs[] =
{
    { "ZwSetInformationKey",           0x19a },
    { "ZwSetInformationToken",         0x19d },
    { "ZwSetInformationVirtualMemory", 0x1a0 },
    { "ZwSetIntervalProfile",          0x1a2 },
    { "ZwSetSystemTime",               0x1ae },
    { "ZwSetThreadExecutionState",     0x1af },
    { "ZwTraceEvent",                 0x5e },
    { "ZwUnloadDriver",               0x1c8 },
};

/* Format 32 bytes as hex string for diagnostics */
static void format_32_bytes_hex( const BYTE *bytes, char *buf, size_t bufsize )
{
    unsigned int i;
    size_t pos = 0;
    for (i = 0; i < 32 && pos + 3 < bufsize; i++)
    {
        pos += snprintf( buf + pos, bufsize - pos, "%02x ", bytes[i] );
    }
    if (pos < bufsize)
        buf[pos] = '\0';
}

/* Expected count of patched Zw stubs from the unix patcher (signal_x86_64.c TRACE).
 * Update this value deliberately when the stub set changes.
 * Current value from: TRACE "patched 257 Zw stubs to Windows 19045 bytes" */
#define EAAC_EXPECTED_PATCHED_STUBS 257

static void test_zw_stub_windows_bytes( void )
{
    static const BYTE win10_stub[32] =
    {
        0x4c,0x8b,0xd1,                    /* mov r10,rcx */
        0xb8,0,0,0,0,                      /* mov eax,<nr> */
        0xf6,0x04,0x25,0x08,0x03,0xfe,0x7f,0x01,  /* test byte [0x7ffe0308],1 */
        0x75,0x03,                         /* jne +3 */
        0x0f,0x05,                         /* syscall */
        0xc3,                              /* ret */
        0xcd,0x2e,                         /* int 0x2e */
        0xc3,                              /* ret */
        0x0f,0x1f,0x84,0,0,0,0,0           /* eight-byte NOP */
    };
    HMODULE ntdll = GetModuleHandleW( L"ntdll.dll" );
    BYTE expect[sizeof(win10_stub)];
    BYTE *page;
    unsigned int i;
    DWORD old_prot;
    EXECUTION_STATE old;
    unsigned int resolved = 0, patched = 0;

    /* reference call through the unpatched wine stub */
    ok( pZwSetThreadExecutionState( ES_CONTINUOUS, &old ) == STATUS_SUCCESS,
        "ZwSetThreadExecutionState failed before the patch\n" );

    /* the anti-cheat gate dance: an execute fault on a read-only page.
     * The unix side must patch the fingerprinted Zw stubs here. */
    page = VirtualAlloc( NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE );
    ok( page != NULL, "VirtualAlloc failed\n" );
    if (!page) return;
    page[0] = 0xc3;
    ok( VirtualProtect( page, 0x1000, PAGE_READONLY, &old_prot ), "VirtualProtect failed\n" );
    __try { ((void (*)(void))page)(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    for (i = 0; i < ARRAY_SIZE(eaac_zw_stubs); i++)
    {
        const BYTE *stub = (const BYTE *)GetProcAddress( ntdll, eaac_zw_stubs[i].name );
        ok( stub != NULL, "%s not found\n", eaac_zw_stubs[i].name );
        if (!stub) continue;
        memcpy( expect, win10_stub, sizeof(expect) );
        *(DWORD *)(expect + 4) = eaac_zw_stubs[i].nr;
        ok( memcmp( stub, expect, sizeof(expect) ) == 0,
            "%s does not hold the Windows 10 19045 stub (nr %x)\n",
            eaac_zw_stubs[i].name, eaac_zw_stubs[i].nr );
    }

    for (i = 0; i < ARRAY_SIZE(windows_syscalls_WIN10_19045); i++)
    {
        const struct windows_syscall *syscall = &windows_syscalls_WIN10_19045[i];
        const BYTE *stub = (const BYTE *)GetProcAddress( ntdll, syscall->name );

        if (!stub || memcmp( stub, win10_stub, 4 )) continue;
        resolved++;
        memcpy( expect, win10_stub, sizeof(expect) );
        *(DWORD *)(expect + 4) = syscall->nr;
        if (memcmp( stub, expect, sizeof(expect) ) == 0)
            patched++;
        ok( memcmp( stub, expect, sizeof(expect) ) == 0,
            "%s does not hold the Windows 10 19045 stub (nr %x)\n", syscall->name, syscall->nr );
    }
    ok( patched == resolved, "%u of %u resolved Nt syscall stubs hold the Windows 10 19045 bytes\n",
        patched, resolved );
    ok( resolved == EAAC_EXPECTED_PATCHED_STUBS, "resolved count %u, expected %u patched stubs\n",
        resolved, EAAC_EXPECTED_PATCHED_STUBS );
    trace( "patched %u / resolved %u Zw stubs to Windows 10 19045 bytes\n", patched, resolved );

    /* a call through a patched stub must still dispatch to the wine
     * implementation: STATUS_SUCCESS and the state set by the reference
     * call (ES_CONTINUOUS) reported as the previous state */
    ok( pZwSetThreadExecutionState( ES_CONTINUOUS, &old ) == STATUS_SUCCESS
        && old == ES_CONTINUOUS,
        "patched ZwSetThreadExecutionState returned old state %08lx\n", old );
}

static void test_zw_stub_independent_golden( void )
{
    /* Microsoft ntdll 19041.5794 x64 reference ZwClose cell, corroborated against
     * 19041.5440 and 19041.6093; deliberately NOT derived from the implementation's
     * template (win10_stub) or syscall table (windows_syscalls_WIN10_19045) */
    static const BYTE golden_zw_close[32] =
    {
        0x4c,0x8b,0xd1,                    /* mov r10,rcx */
        0xb8,0x0f,0x00,0x00,0x00,          /* mov eax,0x0f (NtClose) */
        0xf6,0x04,0x25,0x08,0x03,0xfe,0x7f,0x01,  /* test byte [0x7ffe0308],1 */
        0x75,0x03,                         /* jne +3 */
        0x0f,0x05,                         /* syscall */
        0xc3,                              /* ret */
        0xcd,0x2e,                         /* int 0x2e */
        0xc3,                              /* ret */
        0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00  /* eight-byte NOP */
    };
    HMODULE ntdll = GetModuleHandleW( L"ntdll.dll" );
    const BYTE *stub_zw = (const BYTE *)GetProcAddress( ntdll, "ZwClose" );
    const BYTE *stub_nt = (const BYTE *)GetProcAddress( ntdll, "NtClose" );
    char actual_hex[256];

    ok( stub_zw != NULL, "ZwClose not found\n" );
    if (stub_zw)
    {
        if (memcmp( stub_zw, golden_zw_close, 32 ) != 0)
        {
            format_32_bytes_hex( stub_zw, actual_hex, sizeof(actual_hex) );
            ok( 0, "ZwClose stub does not match golden bytes. Actual: %s\n", actual_hex );
        }
        ok( stub_zw[4] == 0x0f, "ZwClose syscall number at [4] should be 0x0f\n" );
    }

    ok( stub_nt != NULL, "NtClose not found\n" );
    if (stub_nt)
    {
        if (memcmp( stub_nt, golden_zw_close, 32 ) != 0)
        {
            format_32_bytes_hex( stub_nt, actual_hex, sizeof(actual_hex) );
            ok( 0, "NtClose stub does not match golden bytes. Actual: %s\n", actual_hex );
        }
        ok( stub_nt[4] == 0x0f, "NtClose syscall number at [4] should be 0x0f\n" );
    }
}

static void test_raw_syscall_registry_flag_boundaries( void )
{
    static const struct { ULONG_PTR flag; NTSTATUS expect; } tests[] =
    {
        { 0x1000, STATUS_ACCESS_DENIED },     /* lowest accepted flag */
        { 0x13e8, STATUS_ACCESS_DENIED },     /* highest accepted flag */
        { 0x13e9, STATUS_INVALID_PARAMETER }, /* first rejected flag above the range */
    };
    ULONG64 raw;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(tests); i++)
    {
        raw = raw_syscall( WIN10_19045_NtInitializeRegistry, tests[i].flag, 0, 0, 0, 0 );
        /* Real Windows returns STATUS_ACCESS_DENIED post-boot for accepted
         * flags; the emulation now accurately returns STATUS_ACCESS_DENIED. */
        ok( raw == (ULONG)tests[i].expect,
            "raw NtInitializeRegistry(%#Ix) returned %s, expected %#lx\n",
            tests[i].flag, wine_dbgstr_longlong( raw ), (ULONG)tests[i].expect );
    }
}

static void test_raw_syscall_number_boundaries( void )
{
    ULONG64 raw;
    NTSTATUS direct;
    HANDLE invalid_handle = (HANDLE)(ULONG_PTR)0xdeadbeef;

    /* Max valid syscall number: NtWaitLowEventPair (0x1d8).
     * It is inside the table and must not be rejected as unknown. */
    raw = raw_syscall( WIN10_19045_NtWaitLowEventPair, (ULONG_PTR)invalid_handle, 0, 0, 0, 0 );
    ok( raw != (ULONG)STATUS_INVALID_SYSTEM_SERVICE,
        "raw NtWaitLowEventPair with invalid handle returned STATUS_INVALID_SYSTEM_SERVICE\n" );

    /* If the export exists, compare raw dispatch with direct call. */
    if (pNtWaitLowEventPair)
    {
        direct = pNtWaitLowEventPair( invalid_handle );
        ok( raw == (ULONG)direct,
            "raw NtWaitLowEventPair returned %s, expected %#lx (direct call result)\n",
            wine_dbgstr_longlong( raw ), (ULONG)direct );
    }
    else
    {
        trace( "NtWaitLowEventPair export not available in ntdll\n" );
    }

    /* A number way outside the table must fail with STATUS_INVALID_SYSTEM_SERVICE. */
    raw = raw_syscall( 0xffffffff, (ULONG_PTR)invalid_handle, 0, 0, 0, 0 );
    ok( raw == (ULONG)STATUS_INVALID_SYSTEM_SERVICE,
        "raw syscall with number 0xffffffff returned %s, expected STATUS_INVALID_SYSTEM_SERVICE\n",
        wine_dbgstr_longlong( raw ) );
}

/* The unix side walks ntdll's export table in guest-writable memory from the
 * signal handler that applies the EA anti-cheat Zw stub patch.  A corrupted
 * header or export directory must make the lookup fail closed: no patch and
 * no crash.  Patching is one-shot per process, so every corruption variant
 * runs in its own child process. */
enum eaac_corrupt_variant
{
    EAAC_CONTROL,                   /* no corruption: the stubs must be patched */
    EAAC_LFANEW_HUGE,
    EAAC_LFANEW_HIGH_BIT,
    EAAC_EXPORT_RVA_BEYOND_IMAGE,
    EAAC_NAMES_ARRAY_OVERRUN,
    EAAC_NUMBER_OF_NAMES_MAX,
    EAAC_NAME_RVAS_AT_IMAGE_END,
    EAAC_FUNCTIONS_ARRAY_OVERRUN,
    EAAC_NUMBER_OF_FUNCTIONS_MAX,
    EAAC_FUNCTION_RVAS_AT_IMAGE_END,
    EAAC_NO_EXPORT_DIRECTORY_ENTRY,
    EAAC_VARIANT_COUNT
};

/* a range of ntdll image memory made writable, with the original bytes and
 * the original per-page protection kept for the restore */
struct guest_range
{
    BYTE *addr;
    SIZE_T size;
    BYTE *saved;
    DWORD *prot;
    SIZE_T pages;
};

static BOOL guest_range_open( struct guest_range *range, void *addr, SIZE_T size )
{
    ULONG_PTR first = (ULONG_PTR)addr & ~(ULONG_PTR)0xfff;
    ULONG_PTR last = ((ULONG_PTR)addr + size - 1) & ~(ULONG_PTR)0xfff;
    DWORD old;
    SIZE_T i;

    memset( range, 0, sizeof(*range) );
    range->addr = addr;
    range->size = size;
    range->pages = (last - first) / 0x1000 + 1;
    range->prot = HeapAlloc( GetProcessHeap(), 0, range->pages * sizeof(DWORD) );
    range->saved = HeapAlloc( GetProcessHeap(), 0, size );
    if (range->prot && range->saved)
    {
        memcpy( range->saved, addr, size );  /* before any protection change */
        for (i = 0; i < range->pages; i++)
        {
            void *page = (void *)(first + i * 0x1000);

            if (VirtualProtect( page, 0x1000, PAGE_EXECUTE_READWRITE, &range->prot[i] )) continue;
            ok( 0, "VirtualProtect failed at %p, error %lu\n", page, GetLastError() );
            break;
        }
        if (i == range->pages) return TRUE;
        while (i--) VirtualProtect( (void *)(first + i * 0x1000), 0x1000, range->prot[i], &old );
    }
    else ok( 0, "out of memory\n" );

    /* a failed range is all zero, so guest_range_close is a no-op on it */
    if (range->saved) HeapFree( GetProcessHeap(), 0, range->saved );
    if (range->prot) HeapFree( GetProcessHeap(), 0, range->prot );
    memset( range, 0, sizeof(*range) );
    return FALSE;
}

static void guest_range_close( struct guest_range *range )
{
    ULONG_PTR first = (ULONG_PTR)range->addr & ~(ULONG_PTR)0xfff;
    DWORD old;
    SIZE_T i;

    if (!range->saved) return;
    memcpy( range->addr, range->saved, range->size );
    for (i = 0; i < range->pages; i++)
        if (range->prot[i]) VirtualProtect( (void *)(first + i * 0x1000), 0x1000, range->prot[i], &old );
    HeapFree( GetProcessHeap(), 0, range->saved );
    HeapFree( GetProcessHeap(), 0, range->prot );
    memset( range, 0, sizeof(*range) );
}

/* Windows exception dispatch walks the ntdll frames with ntdll's own headers
 * (e_lfanew, the exception directory), so the headers must be good again by
 * the time the exception reaches the Windows side.  The unix side has already
 * run the patch lookup by then.  A vectored handler restores the corrupted
 * bytes; the fake cell is not part of it. */
static struct guest_range *eaac_restore_ranges[3];

static LONG CALLBACK eaac_restore_handler( EXCEPTION_POINTERS *info )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(eaac_restore_ranges); i++)
    {
        const struct guest_range *range = eaac_restore_ranges[i];

        if (range && range->saved) memcpy( range->addr, range->saved, range->size );
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void eaac_call_nonexecutable_page( void *page )
{
    __try { ((void (*)(void))page)(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void eaac_corrupt_child( unsigned int variant )
{
    static const char *const stub_names[] = { "ZwSetThreadExecutionState", "ZwClose", "NtAccessCheck" };
    static const BYTE win_prefix[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };
    /* offsets 8..22 of the Windows stub; wine's own stub shares the first 21 bytes
     * and differs at the int 0x2e (wine has "jmp +1; ret" there) */
    static const BYTE win_tail[15] = { 0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,
                                       0x75, 0x03, 0x0f, 0x05, 0xc3, 0xcd, 0x2e };
    BYTE *base = (BYTE *)GetModuleHandleW( L"ntdll.dll" );
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)(base + dir->VirtualAddress);
    DWORD size = nt->OptionalHeader.SizeOfImage;
    DWORD *names = (DWORD *)(base + exports->AddressOfNames);
    DWORD *functions = (DWORD *)(base + exports->AddressOfFunctions);
    DWORD num_names = exports->NumberOfNames, num_functions = exports->NumberOfFunctions;
    struct guest_range hdr = {0}, dir_range = {0}, table = {0}, cell = {0};
    BYTE fake_cell[31] = { 0 };
    SIZE_T fake_size = 0;
    const BYTE *stubs[ARRAY_SIZE(stub_names)];
    BYTE before[ARRAY_SIZE(stub_names)][32];
    BOOL opened = TRUE;
    DWORD old_prot;
    void *veh;
    BYTE *page;
    DWORD i;

    ok( variant < EAAC_VARIANT_COUNT, "unknown variant %u\n", variant );
    if (variant >= EAAC_VARIANT_COUNT) return;

    for (i = 0; i < ARRAY_SIZE(stub_names); i++)
    {
        stubs[i] = (const BYTE *)GetProcAddress( (HMODULE)base, stub_names[i] );
        ok( stubs[i] != NULL, "%s not found\n", stub_names[i] );
        if (!stubs[i]) return;
        memcpy( before[i], stubs[i], 32 );
        ok( memcmp( before[i] + 8, win_tail, sizeof(win_tail) ), "%s is already patched\n", stub_names[i] );
    }

    page = VirtualAlloc( NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE );
    ok( page != NULL, "VirtualAlloc failed\n" );
    if (!page) return;
    page[0] = 0xc3;
    ok( VirtualProtect( page, 0x1000, PAGE_READONLY, &old_prot ), "VirtualProtect failed\n" );

    switch (variant)
    {
    case EAAC_LFANEW_HUGE:
    case EAAC_LFANEW_HIGH_BIT:
        opened = guest_range_open( &hdr, &dos->e_lfanew, sizeof(dos->e_lfanew) );
        break;
    case EAAC_EXPORT_RVA_BEYOND_IMAGE:
    case EAAC_NO_EXPORT_DIRECTORY_ENTRY:
        opened = guest_range_open( &hdr, &nt->OptionalHeader.NumberOfRvaAndSizes,
                                   (BYTE *)(dir + 1) - (BYTE *)&nt->OptionalHeader.NumberOfRvaAndSizes );
        break;
    case EAAC_NAMES_ARRAY_OVERRUN:
    case EAAC_NUMBER_OF_NAMES_MAX:
    case EAAC_FUNCTIONS_ARRAY_OVERRUN:
    case EAAC_NUMBER_OF_FUNCTIONS_MAX:
        opened = guest_range_open( &dir_range, exports, sizeof(*exports) );
        break;
    case EAAC_NAME_RVAS_AT_IMAGE_END:
        /* an unterminated "NtAccessCheck" in the last 13 bytes of the image,
         * which every name RVA points at: a len+1 compare has to read one
         * byte past the end of the image */
        fake_size = 13;
        memcpy( fake_cell, "NtAccessCheck", fake_size );
        opened = guest_range_open( &table, names, num_names * sizeof(*names) ) &&
                 guest_range_open( &cell, base + size - fake_size, fake_size );
        break;
    case EAAC_FUNCTION_RVAS_AT_IMAGE_END:
        /* A contract guard: this cannot discriminate old from new code.
         * SizeOfImage is page-aligned, so the 32-byte stub write past the
         * last 31 bytes lands on the next page, where write_windows_stub's
         * mprotect fails. */
        fake_size = sizeof(fake_cell);
        memcpy( fake_cell, win_prefix, sizeof(win_prefix) );
        opened = guest_range_open( &table, functions, num_functions * sizeof(*functions) ) &&
                 guest_range_open( &cell, base + size - fake_size, fake_size );
        break;
    }
    if (opened && cell.addr) memcpy( cell.addr, fake_cell, fake_size );

    if (opened)
    {
        /* ntdll's headers are corrupt from here until the vectored handler
         * (or the close below) restores them: nothing in this window may
         * resolve an ntdll export */
        eaac_restore_ranges[0] = &hdr;
        eaac_restore_ranges[1] = &dir_range;
        eaac_restore_ranges[2] = &table;
        veh = AddVectoredExceptionHandler( 1, eaac_restore_handler );
        ok( veh != NULL, "AddVectoredExceptionHandler failed\n" );
        switch (variant)
        {
        case EAAC_LFANEW_HUGE:                dos->e_lfanew = 0x7fffffff; break;
        case EAAC_LFANEW_HIGH_BIT:            dos->e_lfanew = 0xfffff000; break;
        case EAAC_EXPORT_RVA_BEYOND_IMAGE:    dir->VirtualAddress = size + 0x100000; break;
        case EAAC_NAMES_ARRAY_OVERRUN:        exports->AddressOfNames = size - 8; break;
        case EAAC_NUMBER_OF_NAMES_MAX:        exports->NumberOfNames = 0xffffffff; break;
        case EAAC_NAME_RVAS_AT_IMAGE_END:
            for (i = 0; i < num_names; i++) names[i] = size - fake_size;
            break;
        case EAAC_FUNCTIONS_ARRAY_OVERRUN:    exports->AddressOfFunctions = size - 8; break;
        case EAAC_NUMBER_OF_FUNCTIONS_MAX:    exports->NumberOfFunctions = 0xffffffff; break;
        case EAAC_FUNCTION_RVAS_AT_IMAGE_END:
            for (i = 0; i < num_functions; i++) functions[i] = size - fake_size;
            break;
        case EAAC_NO_EXPORT_DIRECTORY_ENTRY:
            nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_DIRECTORY_ENTRY_EXPORT;
            break;
        }
        eaac_call_nonexecutable_page( page );
        RemoveVectoredExceptionHandler( veh );
        memset( eaac_restore_ranges, 0, sizeof(eaac_restore_ranges) );
    }

    /* the vectored handler has already restored the headers; the fake cell is
     * restored by the close below.  The checks only read the stubs and the
     * fake cell; the ranges are closed in reverse order of opening, in case
     * they share a page */
    ok( opened, "could not make the ntdll headers writable\n" );
    for (i = 0; i < ARRAY_SIZE(stub_names); i++)
    {
        if (variant == EAAC_CONTROL)
            ok( !memcmp( stubs[i], win_prefix, sizeof(win_prefix) ) &&
                !memcmp( stubs[i] + 8, win_tail, sizeof(win_tail) ),
                "%s was not patched to the Windows stub\n", stub_names[i] );
        else
            ok( !memcmp( stubs[i], before[i], 32 ), "%s was patched despite the corrupt export table\n",
                stub_names[i] );
    }
    if (cell.addr)
        ok( !memcmp( cell.addr, fake_cell, fake_size ), "the cell at the end of the image was written\n" );

    guest_range_close( &cell );
    guest_range_close( &table );
    guest_range_close( &dir_range );
    guest_range_close( &hdr );
    VirtualFree( page, 0, MEM_RELEASE );
}

static void test_eaac_corrupt_exports( void )
{
    STARTUPINFOA si = { sizeof(si) };
    char **argv;
    unsigned int i;

    winetest_get_mainargs( &argv );
    for (i = 0; i < EAAC_VARIANT_COUNT; i++)
    {
        PROCESS_INFORMATION pi;
        char cmdline[2 * MAX_PATH];

        winetest_push_context( "variant %u", i );
        snprintf( cmdline, sizeof(cmdline), "\"%s\" %s eaac_corrupt %u", argv[0], argv[1], i );
        if (!CreateProcessA( NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi ))
            ok( 0, "CreateProcess failed, error %lu\n", GetLastError() );
        else wait_child_process( &pi );
        winetest_pop_context();
    }
}

static void init_function_pointers( void )
{
    HMODULE ntdll = GetModuleHandleW( L"ntdll.dll" );

    pNtGetNlsSectionPtr = (void *)GetProcAddress( ntdll, "NtGetNlsSectionPtr" );
    ok( pNtGetNlsSectionPtr != NULL, "NtGetNlsSectionPtr not found\n" );
    pNtWaitForSingleObject = (void *)GetProcAddress( ntdll, "NtWaitForSingleObject" );
    ok( pNtWaitForSingleObject != NULL, "NtWaitForSingleObject not found\n" );
    pZwSetThreadExecutionState = (void *)GetProcAddress( ntdll, "ZwSetThreadExecutionState" );
    ok( pZwSetThreadExecutionState != NULL, "ZwSetThreadExecutionState not found\n" );
    pNtAccessCheck = (void *)GetProcAddress( ntdll, "NtAccessCheck" );
    ok( pNtAccessCheck != NULL, "NtAccessCheck not found\n" );
    pNtWaitLowEventPair = (void *)GetProcAddress( ntdll, "NtWaitLowEventPair" );
    /* NtWaitLowEventPair is optional; the test will handle its absence */
}

static BOOL is_wine_19045_macos( void )
{
    RTL_OSVERSIONINFOEXW ver = { sizeof(ver) };
    const char *(CDECL *pwine_get_host_version)( const char **sysname, const char **release );
    const char *sysname = NULL;

    if (strcmp( winetest_platform, "wine" ))
    {
        skip( "EAAC syscall emulation tests are Wine-specific (platform %s)\n", winetest_platform );
        return FALSE;
    }
    if (RtlGetVersion( &ver ) || ver.dwBuildNumber != 19045)
    {
        skip( "EAAC syscall emulation targets Windows build 19045, prefix reports %lu\n", ver.dwBuildNumber );
        return FALSE;
    }
    pwine_get_host_version = (void *)GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "wine_get_host_version" );
    if (!pwine_get_host_version) { skip( "wine_get_host_version not available\n" ); return FALSE; }
    pwine_get_host_version( &sysname, NULL );
    if (!sysname || strcmp( sysname, "Darwin" ))
    {
        skip( "raw syscall emulation is macOS-only (host %s)\n", sysname ? sysname : "(null)" );
        return FALSE;
    }
    return TRUE;
}

#endif /* __x86_64__ */

START_TEST(syscall)
{
#ifdef __x86_64__
    char **argv;
    int argc = winetest_get_mainargs( &argv );

    if (argc >= 4 && !strcmp( argv[2], "eaac_corrupt" ))
    {
        eaac_corrupt_child( atoi( argv[3] ) );
        return;
    }
    if (!is_wine_19045_macos()) return;
    init_function_pointers();
    if (!pNtGetNlsSectionPtr || !pNtWaitForSingleObject || !pZwSetThreadExecutionState || !pNtAccessCheck) return;
    test_access_check_dispatch( FALSE );
    test_raw_syscall_dispatch();
    test_raw_syscall_wait();
    test_raw_syscall_invalid_number();
    test_raw_syscall_registry_invalid_condition();
    test_raw_syscall_registry_flag_boundaries();
    test_raw_syscall_number_boundaries();
    test_raw_syscall_register_semantics();
    test_zw_stub_windows_bytes();
    test_zw_stub_independent_golden();
    test_access_check_dispatch( TRUE );
    test_eaac_corrupt_exports();
#endif
}
