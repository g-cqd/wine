/*
 * Tests for the wine-only ntdll export renames.
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
 * Foreign fingerprinting code (anti-cheat loaders) identifies wine by
 * resolving wine-only ntdll exports, through GetProcAddress as well as
 * raw export-table scans of the mapped image.  The probed name is renamed
 * so both lookups fail cleanly.  Exports that wine's own PE modules import
 * by name (shell32's shell-folder registration, recycle bin) must keep
 * their original names or the loader binds an unimplemented stub to the
 * importer and wineboot dies mid-prefix-update.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/test.h"

static void test_wine_export_renames( void )
{
    HMODULE module = GetModuleHandleA( "ntdll.dll" );
    const char * (CDECL *p_xine_get_version)(void);
    void (CDECL *p_wine_get_host_version)( const char **, const char ** );
    const char *sysname = NULL, *release = NULL;

    ok( module != NULL, "expected ntdll.dll to be loaded\n" );

    /* The name foreign code probes must not resolve. */
    ok( GetProcAddress( module, "wine_get_version" ) == NULL,
        "ntdll must not export wine_get_version\n" );

    /* The renamed export must still resolve and work. */
    p_xine_get_version = (void *)GetProcAddress( module, "xine_get_version" );
    ok( p_xine_get_version != NULL, "ntdll should export xine_get_version\n" );
    if (p_xine_get_version)
        ok( p_xine_get_version()[0] != 0, "xine_get_version returned an empty string\n" );

    /* shell32 (shellpath.c, recyclebin.c) imports these by name; renaming
     * them makes rundll32 abort shell-folder registration with
     * "unimplemented function ntdll.dll.wine_get_host_version". */
    p_wine_get_host_version = (void *)GetProcAddress( module, "wine_get_host_version" );
    ok( p_wine_get_host_version != NULL, "ntdll must export wine_get_host_version\n" );
    if (p_wine_get_host_version)
    {
        p_wine_get_host_version( &sysname, &release );
        ok( sysname != NULL && sysname[0] != 0,
            "wine_get_host_version returned no sysname\n" );
    }

    ok( GetProcAddress( module, "wine_get_build_id" ) != NULL,
        "ntdll must export wine_get_build_id\n" );
}

START_TEST(exports)
{
    test_wine_export_renames();
}
