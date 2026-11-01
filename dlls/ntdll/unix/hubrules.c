/*
 * Runtime rules: per-program settings shipped with the runtime
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
 * <data_dir>/hub-rules.txt holds two kinds of lines:
 *
 *   name=...;exe=...;key=value          a compatdb rule, passed through as is
 *   when pred[;pred...] => key=value;.. a detection rule: when every
 *                                       predicate holds for the executable
 *                                       that is starting, the settings apply
 *                                       to it as a compatdb rule
 *
 * Predicates read the PE headers only: machine=i386|amd64, exe=<basename>,
 * section=<name> (a section with that name exists), imports=<dll>[,<dll>...]
 * (every listed DLL is imported). Before compatdb.so is loaded, the rules are
 * placed in WINE_COMPATDB ahead of the rules of the launcher, so that the
 * launcher's rules still win. Each process evaluates the detection rules for
 * its own executable.
 *
 * The rules themselves (parsing, predicates, the PE header facts) are WineKit's
 * HubRules, in Swift (GameHub winekit/, winekit.h), linked from
 * ${WINEKIT_DIR}/libwinekit.a. This file keeps what touches the process: the
 * rules file, the executable's bytes, the environment, the PEB and the main
 * image.
 */

#if 0
#pragma makedep unix
#endif

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "unix_private.h"
#include "wine/debug.h"
#include <winekit.h>  /* ${WINEKIT_DIR}: swift package wine-objects */

WINE_DEFAULT_DEBUG_CHANNEL(module);

#define MAX_RULES_FILE  (256 * 1024)
#define BASE_ENV        "HUB_RULES_LAUNCHER_COMPATDB"  /* WINE_COMPATDB as the launcher set it */

/* Set by a detection rule with gate_selector_fixup=true: rewrite the 64-bit code selector of the
 * Heaven's-gate far jumps in the main image (see hub_rules_fixup_main_image). */
static BOOL gate_selector_fixup;
static char *hub_dll_dir;   /* relative to the runtime's lib/wine, e.g. dxgi/d3dmetal */

static char *read_rules_file(void)
{
    char *name = NULL, *buf = NULL;
    ssize_t len;
    int fd;

    if (!data_dir || asprintf( &name, "%s/hub-rules.txt", data_dir ) == -1) return NULL;
    fd = open( name, O_RDONLY );
    free( name );
    if (fd == -1) return NULL;
    if ((buf = malloc( MAX_RULES_FILE + 1 )))
    {
        if ((len = read( fd, buf, MAX_RULES_FILE )) < 0) len = 0;
        if (len == MAX_RULES_FILE) ERR( "hub-rules.txt is larger than %u bytes, the rest is ignored\n", MAX_RULES_FILE );
        buf[len] = 0;
    }
    close( fd );
    return buf;
}

/***********************************************************************
 *           hub_rules_dll_dir
 *
 * The DLL directory a detection rule chose for this process (hub_dll_dir=), relative to lib/wine, or NULL.
 * compatdb.so knows only its own backends (dxmt, gptk, wined3d) and its built-in rules choose them for some
 * programs (gptk for steamwebhelper.exe); this puts another directory ahead of them for one program.
 */
const char *hub_rules_dll_dir(void)
{
    return hub_dll_dir;
}

/***********************************************************************
 *           hub_rules_fixup_main_image
 *
 * For an i386 main image that a rule marked with gate_selector_fixup=true,
 * rewrite `push imm32; ljmp 0x33:imm32` in its executable sections to jump to
 * the 64-bit code selector of this process. Windows' 64-bit code selector is
 * 0x33; macOS uses 0x2b and Rosetta stops on a far jump to 0x33 ("invalid gdt
 * selector index 6"). The image is still unexecuted when this runs.
 */
void hub_rules_fixup_main_image( void *base )
{
    IMAGE_DOS_HEADER *dos = base;
    IMAGE_NT_HEADERS32 *nt;
    IMAGE_SECTION_HEADER *sec;
    unsigned int i, count = 0;
    USHORT cs64;

    if (!gate_selector_fixup || !base || dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (IMAGE_NT_HEADERS32 *)((char *)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return;
    __asm__( "movw %%cs,%0" : "=r" (cs64) );
    if (cs64 == 0x33) return;

    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        BYTE *start = (BYTE *)base + sec[i].VirtualAddress, *p;
        SIZE_T size = min( sec[i].Misc.VirtualSize, sec[i].SizeOfRawData ), prot_size = size;
        void *prot_addr = start;
        ULONG old;

        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) || size < 12) continue;
        if (NtProtectVirtualMemory( NtCurrentProcess(), &prot_addr, &prot_size, PAGE_EXECUTE_READWRITE, &old ))
            continue;
        /* 68 imm32 EA imm32 33 00 */
        for (p = start; p + 12 <= start + size; p++)
        {
            if (p[0] != 0x68 || p[5] != 0xea || p[10] != 0x33 || p[11] != 0) continue;
            p[10] = cs64;
            count++;
            p += 11;
        }
        NtProtectVirtualMemory( NtCurrentProcess(), &prot_addr, &prot_size, old, &old );
    }
    fprintf( stderr, "hubrules: rewrote %u far jump(s) to selector 0x33 into 0x%x\n", count, cs64 );
}

/* winekit_read_fn over the executable's file descriptor */
static long read_executable( void *context, int64_t offset, void *buffer, size_t count )
{
    return pread( *(int *)context, buffer, count, offset );
}

/***********************************************************************
 *           hub_rules_apply
 *
 * Put the runtime rules for the executable at unix_path in WINE_COMPATDB,
 * ahead of the rules of the launcher. Call before compatdb.so is loaded.
 * A missing or empty rules file leaves WINE_COMPATDB unchanged.
 */
void hub_rules_apply( const char *unix_path )
{
    const char *exe, *base;
    char *rules, *compatdb = NULL, *dll_dir = NULL, *messages = NULL, *line, *end;
    unsigned int matched = 0;
    int fd, fixup = 0;

    if (!unix_path || !(rules = read_rules_file())) return;
    exe = strrchr( unix_path, '/' );
    exe = exe ? exe + 1 : unix_path;

    /* the launcher part: the value the first process of the tree saw, so that the
     * rules of a parent are not added a second time in its children */
    if (!(base = getenv( BASE_ENV )))
    {
        base = getenv( "WINE_COMPATDB" );
        setenv( BASE_ENV, base ? base : "", 1 );
        base = getenv( BASE_ENV );
    }

    fd = open( unix_path, O_RDONLY );
    if (winekit_hub_rules_apply( rules, strlen( rules ), exe, strlen( exe ), fd == -1 ? NULL : read_executable, &fd,
                                 base ? base : "", base ? strlen( base ) : 0, &compatdb, &dll_dir, &messages, &fixup ))
    {
        ERR( "WineKit refused the call\n" );
        goto done;
    }
    /* in rule order: 'R' a match, reported on stderr; 'W' a rule that can't be used */
    for (line = messages; *line; line = end + 1)
    {
        if (!(end = strchr( line, '\n' ))) break;
        *end = 0;
        if (*line == 'R') { fprintf( stderr, "%s\n", line + 1 ); matched++; }
        else WARN( "%s\n", line + 1 );
    }
    if (fixup) gate_selector_fixup = TRUE;
    if (dll_dir) { free( hub_dll_dir ); hub_dll_dir = strdup( dll_dir ); }

    setenv( "WINE_COMPATDB", compatdb, 1 );
    /* compatdb.so reads the Windows environment block of the process, which a child started by
     * another process (a service, for one) inherits without these rules: set it there as well */
    if (peb && peb->ProcessParameters)
    {
        set_process_env_var( BASE_ENV, base ? base : "" );
        set_process_env_var( "WINE_COMPATDB", compatdb );
    }
    TRACE( "%s: %u detection rule(s) matched\n", debugstr_a(exe), matched );

done:
    if (fd != -1) close( fd );
    winekit_free( compatdb );
    winekit_free( dll_dir );
    winekit_free( messages );
    free( rules );
}
