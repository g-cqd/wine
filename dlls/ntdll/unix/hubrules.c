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

WINE_DEFAULT_DEBUG_CHANNEL(module);

#define MAX_RULES_FILE  (256 * 1024)
#define MAX_SECTIONS    96
#define MAX_IMPORTS     256
#define MAX_IMPORT_SPAN (64 * 1024)
#define BASE_ENV        "HUB_RULES_LAUNCHER_COMPATDB"  /* WINE_COMPATDB as the launcher set it */
#define GATE_KEY        "gate_selector_fixup=true"

/* Set by a detection rule with gate_selector_fixup=true: rewrite the 64-bit code selector of the
 * Heaven's-gate far jumps in the main image (see hub_rules_fixup_main_image). */
static BOOL gate_selector_fixup;
#define DLL_DIR_KEY     "hub_dll_dir="
static char *hub_dll_dir;   /* relative to the runtime's lib/wine, e.g. dxgi/d3dmetal */

struct pe_facts
{
    WORD machine;
    unsigned int nsections;
    char sections[MAX_SECTIONS][9];
    unsigned int nimports;
    char imports[MAX_IMPORTS][64];
};

static BOOL read_at( int fd, off_t pos, void *buf, size_t size )
{
    return pread( fd, buf, size, pos ) == (ssize_t)size;
}

/* the file offset of rva, or -1 if no section holds it */
static off_t rva_to_offset( const IMAGE_SECTION_HEADER *sec, unsigned int count, DWORD rva )
{
    unsigned int i;

    for (i = 0; i < count; i++)
    {
        DWORD size = max( sec[i].Misc.VirtualSize, sec[i].SizeOfRawData );
        if (rva >= sec[i].VirtualAddress && rva - sec[i].VirtualAddress < size)
        {
            if (rva - sec[i].VirtualAddress >= sec[i].SizeOfRawData) return -1;  /* not backed by the file */
            return (off_t)sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
        }
    }
    return -1;
}

/* Read the machine, the section names and the imported DLL names of the PE file at path. */
static BOOL get_pe_facts( const char *path, struct pe_facts *facts )
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;  /* the 32-bit header is a prefix up to the data directories, read below by machine */
    IMAGE_SECTION_HEADER sec[MAX_SECTIONS];
    IMAGE_DATA_DIRECTORY dir;
    unsigned int i, count;
    off_t sec_pos, imp_pos;
    BOOL ret = FALSE;
    int fd;

    memset( facts, 0, sizeof(*facts) );
    if ((fd = open( path, O_RDONLY )) == -1) return FALSE;
    if (!read_at( fd, 0, &dos, sizeof(dos) ) || dos.e_magic != IMAGE_DOS_SIGNATURE) goto done;
    if (!read_at( fd, dos.e_lfanew, &nt, offsetof( IMAGE_NT_HEADERS64, OptionalHeader.Magic ) + sizeof(WORD) )) goto done;
    if (nt.Signature != IMAGE_NT_SIGNATURE) goto done;
    facts->machine = nt.FileHeader.Machine;

    count = min( nt.FileHeader.NumberOfSections, MAX_SECTIONS );
    sec_pos = dos.e_lfanew + offsetof( IMAGE_NT_HEADERS64, OptionalHeader ) + nt.FileHeader.SizeOfOptionalHeader;
    if (!read_at( fd, sec_pos, sec, count * sizeof(sec[0]) )) goto done;
    for (i = 0; i < count; i++)
        memcpy( facts->sections[i], sec[i].Name, IMAGE_SIZEOF_SHORT_NAME );  /* the array keeps a NUL after 8 bytes */
    facts->nsections = count;
    ret = TRUE;  /* machine and sections are known; imports are optional */

    if (nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        if (nt.FileHeader.SizeOfOptionalHeader < offsetof( IMAGE_OPTIONAL_HEADER64, DataDirectory[2] )) goto done;
        if (!read_at( fd, dos.e_lfanew + offsetof( IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory[1] ), &dir, sizeof(dir) ))
            goto done;
    }
    else if (nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        if (nt.FileHeader.SizeOfOptionalHeader < offsetof( IMAGE_OPTIONAL_HEADER32, DataDirectory[2] )) goto done;
        if (!read_at( fd, dos.e_lfanew + offsetof( IMAGE_NT_HEADERS32, OptionalHeader.DataDirectory[1] ), &dir, sizeof(dir) ))
            goto done;
    }
    else goto done;
    if (!dir.VirtualAddress || (imp_pos = rva_to_offset( sec, count, dir.VirtualAddress )) == -1) goto done;

    for (i = 0; facts->nimports < MAX_IMPORTS; i++)
    {
        IMAGE_IMPORT_DESCRIPTOR desc;
        off_t name_pos;
        char *name = facts->imports[facts->nimports];

        if (i * sizeof(desc) >= MAX_IMPORT_SPAN) break;
        if (!read_at( fd, imp_pos + i * sizeof(desc), &desc, sizeof(desc) ) || !desc.Name) break;
        if ((name_pos = rva_to_offset( sec, count, desc.Name )) == -1) continue;
        if (pread( fd, name, sizeof(facts->imports[0]) - 1, name_pos ) <= 0) continue;
        name[sizeof(facts->imports[0]) - 1] = 0;
        if (name[0]) facts->nimports++;
    }

done:
    close( fd );
    return ret;
}

static BOOL has_import( const struct pe_facts *facts, const char *dll )
{
    size_t len = strlen( dll );
    unsigned int i;

    for (i = 0; i < facts->nimports; i++)
    {
        const char *name = facts->imports[i];
        if (!strcasecmp( name, dll )) return TRUE;
        /* "d3d9" matches "d3d9.dll" */
        if (!strncasecmp( name, dll, len ) && !strcasecmp( name + len, ".dll" )) return TRUE;
    }
    return FALSE;
}

/* whether every predicate of the ';'-separated list in preds holds; preds is modified */
static BOOL predicates_hold( char *preds, const char *exe, const struct pe_facts *facts, BOOL have_facts )
{
    char *pred, *next, *value, *item, *item_next, *end;
    unsigned int i;

    for (pred = preds; pred; pred = next)
    {
        if ((next = strchr( pred, ';' ))) *next++ = 0;
        while (*pred == ' ') pred++;
        if (!*pred) continue;
        if (!(value = strchr( pred, '=' ))) return FALSE;
        *value++ = 0;
        for (end = value + strlen( value ); end > value && (end[-1] == ' ' || end[-1] == '\t'); end--) end[-1] = 0;

        if (!strcmp( pred, "exe" ))
        {
            if (strcasecmp( value, exe )) return FALSE;
        }
        else if (!strcmp( pred, "machine" ))
        {
            WORD want = !strcasecmp( value, "i386" ) ? IMAGE_FILE_MACHINE_I386 :
                        !strcasecmp( value, "amd64" ) ? IMAGE_FILE_MACHINE_AMD64 : 0;
            if (!have_facts || !want || facts->machine != want) return FALSE;
        }
        else if (!strcmp( pred, "section" ))
        {
            if (!have_facts) return FALSE;
            for (i = 0; i < facts->nsections; i++) if (!strcmp( facts->sections[i], value )) break;
            if (i == facts->nsections) return FALSE;
        }
        else if (!strcmp( pred, "imports" ))
        {
            if (!have_facts) return FALSE;
            for (item = value; item; item = item_next)
            {
                if ((item_next = strchr( item, ',' ))) *item_next++ = 0;
                if (*item && !has_import( facts, item )) return FALSE;
            }
        }
        else
        {
            WARN( "unknown predicate %s\n", debugstr_a(pred) );
            return FALSE;
        }
    }
    return TRUE;
}

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

/* append the line and a newline to the growing buffer */
static BOOL append_line( char **out, size_t *len, size_t *cap, const char *a, const char *b, const char *c )
{
    size_t add = strlen( a ) + strlen( b ) + strlen( c ) + 1;
    char *grown;

    if (*len + add + 1 > *cap)
    {
        size_t ncap = max( *cap * 2, *len + add + 1 );
        if (!(grown = realloc( *out, ncap ))) return FALSE;
        *out = grown;
        *cap = ncap;
    }
    *len += snprintf( *out + *len, *cap - *len, "%s%s%s\n", a, b, c );
    return TRUE;
}

/* Remove the ';'-separated field equal to setting from the settings string, in place;
 * returns whether it was there. */
static BOOL strip_setting( char *settings, const char *setting )
{
    size_t len = strlen( setting );
    char *p = settings;

    while (*p)
    {
        char *end = strchr( p, ';' );
        size_t field = end ? (size_t)(end - p) : strlen( p );

        if (field == len && !strncmp( p, setting, len ))
        {
            if (end) memmove( p, end + 1, strlen( end + 1 ) + 1 );
            else if (p > settings) p[-1] = 0;   /* drop the ';' before the last field */
            else *p = 0;
            return TRUE;
        }
        if (!end) break;
        p = end + 1;
    }
    return FALSE;
}

/* Remove the field starting with key from the ;-separated settings and return a copy of its value. */
static char *take_setting_value( char *settings, const char *key )
{
    size_t len = strlen( key );
    char *p = settings, *value = NULL;

    while (*p)
    {
        char *end = strchr( p, ';' );
        size_t field = end ? (size_t)(end - p) : strlen( p );

        if (field > len && !strncmp( p, key, len ))
        {
            value = strndup( p + len, field - len );
            if (end) memmove( p, end + 1, strlen( end + 1 ) + 1 );
            else if (p > settings) p[-1] = 0;
            else *p = 0;
            return value;
        }
        if (!end) break;
        p = end + 1;
    }
    return NULL;
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

/***********************************************************************
 *           hub_rules_apply
 *
 * Put the runtime rules for the executable at unix_path in WINE_COMPATDB,
 * ahead of the rules of the launcher. Call before compatdb.so is loaded.
 * A missing or empty rules file leaves WINE_COMPATDB unchanged.
 */
void hub_rules_apply( const char *unix_path )
{
    struct pe_facts facts;
    const char *exe, *base, *launcher;
    char *rules, *line, *next, *arrow, *out = NULL, tag[32];
    size_t len = 0, cap = 0;
    unsigned int lineno = 0, matched = 0;
    BOOL have_facts;

    if (!unix_path || !(rules = read_rules_file())) return;
    exe = strrchr( unix_path, '/' );
    exe = exe ? exe + 1 : unix_path;
    have_facts = get_pe_facts( unix_path, &facts );

    /* the launcher part: the value the first process of the tree saw, so that the
     * rules of a parent are not added a second time in its children */
    if (!(base = getenv( BASE_ENV )))
    {
        base = getenv( "WINE_COMPATDB" );
        setenv( BASE_ENV, base ? base : "", 1 );
        base = getenv( BASE_ENV );
    }
    launcher = base;

    if (!append_line( &out, &len, &cap, "v=3", "", "" )) goto done;
    for (line = rules; line; line = next)
    {
        if ((next = strchr( line, '\n' ))) *next++ = 0;
        lineno++;
        line[strcspn( line, "\r" )] = 0;
        while (*line == ' ' || *line == '\t') line++;
        if (!*line || *line == '#') continue;
        if (strncmp( line, "when ", 5 ))
        {
            if (!append_line( &out, &len, &cap, line, "", "" )) goto done;
            continue;
        }
        if (!(arrow = strstr( line, "=>" ))) { WARN( "line %u: no =>\n", lineno ); continue; }
        *arrow = 0;
        if (!predicates_hold( line + 5, exe, &facts, have_facts )) continue;
        arrow += 2;
        while (*arrow == ' ') arrow++;
        matched++;
        fprintf( stderr, "hubrules: %s matches line %u: %s\n", exe, lineno, arrow );
        if (strip_setting( arrow, GATE_KEY )) gate_selector_fixup = TRUE;
        {
            char *dir = take_setting_value( arrow, DLL_DIR_KEY );
            if (dir && (strstr( dir, ".." ) || *dir == '/'))
            {
                WARN( "line %u: %s%s must be relative to lib/wine, ignored\n", lineno, DLL_DIR_KEY, dir );
                free( dir );
                dir = NULL;
            }
            if (dir) { free( hub_dll_dir ); hub_dll_dir = dir; }
        }
        if (!*arrow) continue;  /* only runtime capabilities, nothing for compatdb */
        snprintf( tag, sizeof(tag), "name=hubrules-%u;exe=", lineno );
        if (!append_line( &out, &len, &cap, tag, exe, "" ) ) goto done;
        len--;  /* continue the same line with the settings */
        if (!append_line( &out, &len, &cap, ";", arrow, "" )) goto done;
    }

    /* the launcher's rules last, without its own "v=" header line */
    if (base && *base)
    {
        if (!strncmp( base, "v=", 2 ) && (line = strchr( base, '\n' ))) base = line + 1;
        else if (!strncmp( base, "v=", 2 )) base = "";
        if (*base && !append_line( &out, &len, &cap, base, "", "" )) goto done;
    }
    if (len && out[len - 1] == '\n') out[--len] = 0;
    setenv( "WINE_COMPATDB", out, 1 );
    /* compatdb.so reads the Windows environment block of the process, which a child started by
     * another process (a service, for one) inherits without these rules: set it there as well */
    if (peb && peb->ProcessParameters)
    {
        set_process_env_var( BASE_ENV, launcher ? launcher : "" );
        set_process_env_var( "WINE_COMPATDB", out );
    }
    TRACE( "%s: %u detection rule(s) matched\n", debugstr_a(exe), matched );

done:
    free( out );
    free( rules );
}
