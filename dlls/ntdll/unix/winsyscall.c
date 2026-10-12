/*
 * Windows syscall emulation
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
 * Native Windows code can bypass the ntdll syscall stubs and execute the
 * syscall instruction directly, with the Windows syscall ABI: number in
 * rax, first argument in r10, further register arguments in rdx/r8/r9 and
 * stack arguments at rsp+0x28.  On macOS such an instruction raises SIGSYS,
 * and sigsys_handler dispatches it to the ntdll function with the same
 * name, so the caller observes the same behavior as on Windows.
 */

#if 0
#pragma makedep unix
#endif

#include <assert.h>
#include <stdarg.h>
#include <pthread.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "unix_private.h"
#include "wine/debug.h"

#ifdef __x86_64__

#include "win10_19045_syscalls.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);

/* set by the unix loader from the ntdll mapping it created itself, so
 * that native code tampering with the loader list cannot hide ntdll */
void *ntdll_image_base;
unsigned int ntdll_image_size;

static const void *ntdll_base;
static const void *win32u_base;
static unsigned int ntdll_size;
static unsigned int win32u_size;
static unsigned int win_nr_to_id[WIN10_19045_SYSCALL_COUNT];
static BOOL nr_cache_loaded;

/* compare a loader-entry BaseDllName with an ASCII name, case-insensitively */
static BOOL match_base_dll_name( const LDR_DATA_TABLE_ENTRY *mod, const char *name, size_t len )
{
    const WCHAR *buffer = mod->BaseDllName.Buffer;
    size_t i;

    if (!buffer || mod->BaseDllName.Length != len * sizeof(WCHAR)) return FALSE;
    for (i = 0; i < len; i++)
    {
        char c = name[i];
        WCHAR w = buffer[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (w >= 'A' && w <= 'Z') w += 'a' - 'A';
        if (w != (unsigned char)c) return FALSE;
    }
    return TRUE;
}

/* find the images that contain wine syscall stubs; called lazily, also from
 * a signal handler, so it only reads memory that is stable after startup.
 * ntdll is normally known from the loader; the loader list is only walked
 * for win32u, and as a fallback if the loader did not record ntdll. */
static void find_wine_syscall_modules( void )
{
    LIST_ENTRY *head, *entry;
    int count = 0;

    if (ntdll_image_base)
    {
        ntdll_base = ntdll_image_base;
        ntdll_size = ntdll_image_size;
    }

    head = &NtCurrentTeb()->Peb->LdrData->InLoadOrderModuleList;
    for (entry = head->Flink; entry != head && count++ < 32; entry = entry->Flink)
    {
        LDR_DATA_TABLE_ENTRY *mod = CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

        if (!ntdll_base && match_base_dll_name( mod, "ntdll.dll", 9 ))
        {
            ntdll_base = mod->DllBase;
            ntdll_size = mod->SizeOfImage;
        }
        else if (match_base_dll_name( mod, "win32u.dll", 10 ))
        {
            win32u_base = mod->DllBase;
            win32u_size = mod->SizeOfImage;
        }
    }
}

/* is an address inside an image that contains wine syscall stubs (ntdll or win32u) */
BOOL is_wine_syscall_stub_address( ULONG64 addr )
{
    if (!ntdll_base && !win32u_base) find_wine_syscall_modules();
    if (ntdll_base && addr - (ULONG64)ntdll_base < ntdll_size) return TRUE;
    if (win32u_base && addr - (ULONG64)win32u_base < win32u_size) return TRUE;
    return FALSE;
}

/* the wine ntdll syscall stubs start with "mov r10,rcx; mov eax,<id>" */
static const BYTE stub_prefix[] = { 0x4c, 0x8b, 0xd1, 0xb8 };

/* return the wine syscall id stored in the ntdll stub exporting name,
 * or 0 if ntdll does not export such a syscall stub */
static unsigned int get_wine_syscall_id( const char *name )
{
    const IMAGE_DOS_HEADER *dos = ntdll_base;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_EXPORT_DIRECTORY *exports;
    const DWORD *names, *functions;
    const WORD *ordinals;
    size_t len = strlen( name );
    unsigned int i;

    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (const IMAGE_NT_HEADERS64 *)((const char *)ntdll_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) return 0;
    exports = (const IMAGE_EXPORT_DIRECTORY *)((const char *)ntdll_base
              + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (const DWORD *)((const char *)ntdll_base + exports->AddressOfNames);
    ordinals = (const WORD *)((const char *)ntdll_base + exports->AddressOfNameOrdinals);
    functions = (const DWORD *)((const char *)ntdll_base + exports->AddressOfFunctions);

    for (i = 0; i < exports->NumberOfNames; i++)
    {
        const char *export_name = (const char *)ntdll_base + names[i];
        if (memcmp( export_name, name, len + 1 )) continue;
        if (ordinals[i] >= exports->NumberOfFunctions) return 0;
        {
            const char *func = (const char *)ntdll_base + functions[ordinals[i]];
            if ((ULONG64)(func + 8 - (const char *)ntdll_base) >= ntdll_size) return 0;
            if (memcmp( func, stub_prefix, sizeof(stub_prefix) )) return 0;
            return *(const unsigned int *)(func + 4);
        }
    }
    return 0;
}

/* resolve the Windows syscall numbers to wine syscall ids; called lazily,
 * benign race: every thread computes the same values */
static void load_windows_syscall_cache( void )
{
    unsigned int i, resolved = 0;

    if (!ntdll_base) find_wine_syscall_modules();
    for (i = 0; i < ARRAY_SIZE( windows_syscalls_WIN10_19045 ); i++)
    {
        unsigned int nr = windows_syscalls_WIN10_19045[i].nr;
        unsigned int id = get_wine_syscall_id( windows_syscalls_WIN10_19045[i].name );

        win_nr_to_id[nr] = id ? id : WIN_SYSCALL_KNOWN;
        if (id) resolved++;
    }
    TRACE( "%u of %u Windows syscalls resolved to wine stubs\n",
           resolved, (unsigned int)ARRAY_SIZE( windows_syscalls_WIN10_19045 ) );
    nr_cache_loaded = TRUE;
}

/* map a Windows 10 19045 syscall number to the wine syscall id of the
 * matching ntdll stub, with WIN_SYSCALL_KNOWN set if the number exists on
 * Windows but wine has no stub for it; 0 for numbers that are not Windows
 * syscalls at all */
unsigned int wine_syscall_id_for_windows_nr( unsigned int nr )
{
    if (nr >= ARRAY_SIZE( win_nr_to_id )) return 0;
    if (!nr_cache_loaded) load_windows_syscall_cache();
    return win_nr_to_id[nr];
}

#endif /* __x86_64__ */
