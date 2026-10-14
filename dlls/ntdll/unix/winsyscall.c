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
#include "wine/asm.h"
#include "wine/debug.h"

#ifdef __x86_64__

#include "win10_19045_syscalls.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);

extern NTSTATUS WINAPI NtGetNlsSectionPtr( ULONG type, ULONG id, void *unknown, void **ptr, SIZE_T *size );

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

/* find the images that contain wine syscall stubs; called lazily as a
 * fallback for processes where the loader-time resolution did not run
 * (normally the cache is already loaded by then) */
static void find_wine_syscall_modules( void )
{
    LIST_ENTRY *head, *entry;
    int count = 0;

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

/* find the wine ntdll syscall stub exporting name, or NULL if ntdll
 * exports no syscall stub under that name.  AddressOfNameOrdinals
 * entries are direct indices into AddressOfFunctions. */
static const BYTE *find_wine_syscall_stub( const char *name )
{
    const IMAGE_DOS_HEADER *dos = ntdll_base;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_EXPORT_DIRECTORY *exports;
    const DWORD *names, *functions;
    const WORD *ordinals;
    size_t len = strlen( name );
    unsigned int i;

    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (const IMAGE_NT_HEADERS64 *)((const char *)ntdll_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) return NULL;
    exports = (const IMAGE_EXPORT_DIRECTORY *)((const char *)ntdll_base
              + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (const DWORD *)((const char *)ntdll_base + exports->AddressOfNames);
    ordinals = (const WORD *)((const char *)ntdll_base + exports->AddressOfNameOrdinals);
    functions = (const DWORD *)((const char *)ntdll_base + exports->AddressOfFunctions);

    for (i = 0; i < exports->NumberOfNames; i++)
    {
        const char *export_name = (const char *)ntdll_base + names[i];
        if (memcmp( export_name, name, len + 1 )) continue;
        if (ordinals[i] >= exports->NumberOfFunctions) return NULL;
        {
            const char *func = (const char *)ntdll_base + functions[ordinals[i]];
            if ((ULONG64)(func + 8 - (const char *)ntdll_base) >= ntdll_size) return NULL;
            if (memcmp( func, stub_prefix, sizeof(stub_prefix) )) return NULL;
            return (const BYTE *)func;
        }
    }
    return NULL;
}

/* Return whether name exports a syscall stub, including the valid id zero.
 * The id is the zero-based index loaded into eax by the wine stub. */
static BOOL get_wine_syscall_id( const char *name, unsigned int *id )
{
    const BYTE *stub = find_wine_syscall_stub( name );
    if (!stub) return FALSE;
    *id = *(const unsigned int *)(stub + 4);
    return TRUE;
}

/* return the address of the wine ntdll syscall stub exporting name, or
 * 0 if ntdll does not export such a syscall stub */
ULONG64 get_wine_syscall_stub_address( const char *name )
{
    if (!ntdll_base) find_wine_syscall_modules();
    return (ULONG64)find_wine_syscall_stub( name );
}

/* resolve the Windows syscall numbers to wine syscall ids; called lazily,
 * benign race: every thread computes the same values */
static void load_windows_syscall_cache( void )
{
    unsigned int i, resolved = 0;

    if (!ntdll_base) find_wine_syscall_modules();
    if (ntdll_base)
    {
        const IMAGE_DOS_HEADER *dos = ntdll_base;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)((const char *)ntdll_base + dos->e_lfanew);
            const IMAGE_DATA_DIRECTORY *dir = nt->OptionalHeader.DataDirectory;
            const IMAGE_EXPORT_DIRECTORY *exports = (const IMAGE_EXPORT_DIRECTORY *)((const char *)ntdll_base + dir->VirtualAddress);
            TRACE( "ntdll %p size %x, export dir at %x size %x, %u names / %u functions\n",
                   ntdll_base, ntdll_size, dir->VirtualAddress, dir->Size,
                   exports->NumberOfNames, exports->NumberOfFunctions );
        }
        else TRACE( "ntdll base %p has no DOS signature\n", ntdll_base );
    }
    else TRACE( "ntdll image not found\n" );
    {
        unsigned int id;
        if (get_wine_syscall_id( "NtGetNlsSectionPtr", &id ))
            TRACE( "service table entry %#x = %p, NtGetNlsSectionPtr at %p\n",
                   id, (void *)KeServiceDescriptorTable[0].ServiceTable[id],
                   (void *)&NtGetNlsSectionPtr );
    }
    for (i = 0; i < ARRAY_SIZE( windows_syscalls_WIN10_19045 ); i++)
    {
        unsigned int nr = windows_syscalls_WIN10_19045[i].nr;
        unsigned int id;

        if (get_wine_syscall_id( windows_syscalls_WIN10_19045[i].name, &id ))
        {
            win_nr_to_id[nr] = id + 1;
            resolved++;
        }
        else win_nr_to_id[nr] = WIN_SYSCALL_KNOWN;
    }
    TRACE( "%u of %u Windows syscalls resolved to wine stubs\n",
           resolved, (unsigned int)ARRAY_SIZE( windows_syscalls_WIN10_19045 ) );
    nr_cache_loaded = TRUE;
}

/* resolve the whole cache at ntdll load time, before any guest code can
 * patch the syscall stubs (native loaders hook them) */
void init_windows_syscall_cache( void *base, unsigned int size )
{
    ntdll_base = base;
    ntdll_size = size;
    load_windows_syscall_cache();
}

/* Map a Windows 10 19045 number to the wine syscall id plus one, preserving
 * id zero. WIN_SYSCALL_KNOWN means Windows defines it but wine has no stub;
 * zero means Windows does not define the number. */
unsigned int wine_syscall_id_for_windows_nr( unsigned int nr )
{
    if (nr >= ARRAY_SIZE( win_nr_to_id )) return 0;
    if (!nr_cache_loaded) load_windows_syscall_cache();
    return win_nr_to_id[nr];
}


/* the addresses of the Zw stubs rewritten by eaac_patch_windows_zw_stubs;
 * the signal handlers check them to recognize calls through a rewritten
 * stub and translate its Windows number back to the wine id */
static ULONG64 eaac_patched_stubs[WIN10_19045_SYSCALL_COUNT];
static unsigned int eaac_patched_count;

C_ASSERT( offsetof( struct windows_syscall, nr ) == 0 );
C_ASSERT( offsetof( struct windows_syscall, name ) == 8 );
C_ASSERT( sizeof( struct windows_syscall ) == 16 );
C_ASSERT( ARRAY_SIZE( windows_syscalls_WIN10_19045 ) == WIN10_19045_SYSCALL_COUNT );
C_ASSERT( ARRAY_SIZE( eaac_patched_stubs ) >= ARRAY_SIZE( windows_syscalls_WIN10_19045 ) );

/* The caller supplies at least count storage slots. Publish the number of
 * successful writes only after scanning all count entries. The loop itself
 * is O(count), excluding the two callbacks' work. */
extern unsigned int eaac_patch_stubs_native( const struct windows_syscall *table, unsigned int count,
                                              const BYTE *(*find_stub)( const char * ),
                                              BOOL (*write_stub)( BYTE *, unsigned int ),
                                              ULONG64 *storage, unsigned int *published_count );
__ASM_GLOBAL_FUNC( eaac_patch_stubs_native,
                   "pushq %rbx\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset 8\n\t")
                   __ASM_CFI(".cfi_offset %rbx,-16\n\t")
                   "pushq %rbp\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset 8\n\t")
                   __ASM_CFI(".cfi_offset %rbp,-24\n\t")
                   "pushq %r12\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset 8\n\t")
                   __ASM_CFI(".cfi_offset %r12,-32\n\t")
                   "pushq %r13\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset 8\n\t")
                   __ASM_CFI(".cfi_offset %r13,-40\n\t")
                   "pushq %r14\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset 8\n\t")
                   __ASM_CFI(".cfi_offset %r14,-48\n\t")
                   "pushq %r15\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset 8\n\t")
                   __ASM_CFI(".cfi_offset %r15,-56\n\t")
                   "subq $24,%rsp\n\t" /* align the stack before callbacks */
                   __ASM_CFI(".cfi_adjust_cfa_offset 24\n\t")
                   "movq %rdi,%r12\n\t"
                   "movl %esi,%r13d\n\t"
                   "movq %rdx,%r14\n\t"
                   "movq %rcx,%r15\n\t"
                   "movq %r8,%rbx\n\t"
                   "movq %r9,%rbp\n\t"
                   "movl $0,(%rsp)\n\t"  /* table index */
                   "movl $0,8(%rsp)\n\t" /* successful writes */
                   "1: cmpl %r13d,(%rsp)\n\t"
                   "jae 3f\n\t"
                   "movq 8(%r12),%rdi\n\t"
                   "call *%r14\n\t"
                   "testq %rax,%rax\n\t"
                   "jz 2f\n\t"
                   "movq %rax,16(%rsp)\n\t"
                   "movq %rax,%rdi\n\t"
                   "movl (%r12),%esi\n\t"
                   "call *%r15\n\t"
                   "testl %eax,%eax\n\t"
                   "jz 2f\n\t"
                   "movl 8(%rsp),%eax\n\t"
                   "movq 16(%rsp),%rdx\n\t"
                   "movq %rdx,(%rbx,%rax,8)\n\t"
                   "incl %eax\n\t"
                   "movl %eax,8(%rsp)\n\t"
                   "movl %eax,(%rbp)\n\t"
                   "2: addq $16,%r12\n\t"
                   "incl (%rsp)\n\t"
                   "jmp 1b\n\t"
                   "3: movl 8(%rsp),%eax\n\t"
                   "movl %eax,(%rbp)\n\t"
                   "addq $24,%rsp\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset -24\n\t")
                   "popq %r15\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset -8\n\t")
                   __ASM_CFI(".cfi_restore %r15\n\t")
                   "popq %r14\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset -8\n\t")
                   __ASM_CFI(".cfi_restore %r14\n\t")
                   "popq %r13\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset -8\n\t")
                   __ASM_CFI(".cfi_restore %r13\n\t")
                   "popq %r12\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset -8\n\t")
                   __ASM_CFI(".cfi_restore %r12\n\t")
                   "popq %rbp\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset -8\n\t")
                   __ASM_CFI(".cfi_restore %rbp\n\t")
                   "popq %rbx\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset -8\n\t")
                   __ASM_CFI(".cfi_restore %rbx\n\t")
                   "ret" );

/* Find one exact address among count successfully patched stubs in O(count). */
extern BOOL eaac_is_patched_stub_native( ULONG64 addr, const ULONG64 *storage, unsigned int count );
__ASM_GLOBAL_FUNC( eaac_is_patched_stub_native,
                   "xorl %eax,%eax\n\t"
                   "testl %edx,%edx\n\t"
                   "jz 2f\n\t"
                   "1: cmpq %rdi,(%rsi,%rax,8)\n\t"
                   "je 3f\n\t"
                   "incl %eax\n\t"
                   "cmpl %edx,%eax\n\t"
                   "jb 1b\n\t"
                   "xorl %eax,%eax\n\t"
                   "2: ret\n\t"
                   "3: movl $1,%eax\n\t"
                   "ret" );

/* rewrite every wine ntdll syscall stub that has a known Windows 10 19045
 * syscall number with the caller-provided stub image (write_stub stores
 * the exact Windows 19045 stub for nr at addr and reports success).  The EA anti-cheat
 * loader fingerprints these stubs, choosing different names on every
 * verification round, so all resolvable stubs must be rewritten.  Returns
 * how many stubs were rewritten. */
unsigned int eaac_patch_windows_zw_stubs( BOOL (*write_stub)( BYTE *addr, unsigned int nr ) )
{
    if (!nr_cache_loaded) load_windows_syscall_cache();
    return eaac_patch_stubs_native( windows_syscalls_WIN10_19045,
                                    ARRAY_SIZE( windows_syscalls_WIN10_19045 ),
                                    find_wine_syscall_stub, write_stub,
                                    eaac_patched_stubs, &eaac_patched_count );
}

/* is addr a Zw stub rewritten by eaac_patch_windows_zw_stubs? */
BOOL is_patched_stub_address( ULONG64 addr )
{
    if (eaac_is_patched_stub_native( addr, eaac_patched_stubs, eaac_patched_count ))
        return TRUE;
    if (is_wine_syscall_stub_address( addr ))
    {
        const ULONG64 *words = (const ULONG64 *)addr;
        if (words[1] == 0x017ffe03082504f6ULL && words[2] == 0xc32ecdc3050f0375ULL)
            return TRUE;
    }
    return FALSE;
}

#endif /* __x86_64__ */
