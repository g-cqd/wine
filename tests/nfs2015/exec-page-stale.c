/*
 * Executable-page staleness probe for the Rosetta route (patch 0007 experiments).
 *
 * Build: x86_64-w64-mingw32-gcc -O1 -o exec-page-stale.exe exec-page-stale.c
 * Run:   wine exec-page-stale.exe [rounds|trace]            (add WINE_ROSETTA_FLUSH_TOGGLE=1 / WINE_ROSETTA_PROTECT_TOGGLE=1,
 *                                             WINE_TRACE_PAGE=50000000-50010000 to see wine-trace lines)
 *
 * Each case builds `mov eax,N; ret` in a private page at 0x50000000, runs it, rewrites N in place and runs it
 * again. A stale translation shows as the first value coming back after the rewrite. Prints one line per case:
 * "case <name> first=<n> second=<n> stale=<0|1>". Exit status = number of stale cases.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef int (*fn_t)(void);
static const unsigned char tmpl[6] = { 0xb8, 0, 0, 0, 0, 0xc3 };
static int stale_cases, rounds = 200;
#define BASE ((void *)0x50000000)

static void put( unsigned char *p, int n ) { memcpy( p, tmpl, 6 ); *(int *)(p + 1) = n; }

/* mode 0: RW alloc, write, VirtualProtect to RWX, run, rewrite + FlushInstructionCache, run
 * mode 1: RWX alloc, write, run, rewrite + FlushInstructionCache, run
 * mode 2: RWX alloc, write, run, rewrite WITHOUT any flush, run (informational: native x86 also tolerates it)
 * mode 3: RW alloc, write, VirtualProtect to RX, run, VirtualProtect RW, rewrite, VirtualProtect RX (no flush), run */
static int run_case( int mode, const char *name )
{
    int i, bad = 0, first = 0, second = 0;

    for (i = 0; i < rounds; i++)
    {
        DWORD old;
        unsigned char *p;
        fn_t f;

        p = VirtualAlloc( BASE, 0x1000, MEM_COMMIT | MEM_RESERVE, (mode == 1 || mode == 2) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE );
        if (!p) { printf( "FAIL alloc %lu\n", GetLastError() ); return 1; }
        f = (fn_t)p;
        put( p, 1000 + i );
        if (mode == 0) VirtualProtect( p, 0x1000, PAGE_EXECUTE_READWRITE, &old );
        if (mode == 3) VirtualProtect( p, 0x1000, PAGE_EXECUTE_READ, &old );
        first = f();
        if (mode == 3) VirtualProtect( p, 0x1000, PAGE_READWRITE, &old );
        put( p, 2000 + i );
        if (mode == 3) VirtualProtect( p, 0x1000, PAGE_EXECUTE_READ, &old );
        if (mode != 2 && mode != 3) FlushInstructionCache( GetCurrentProcess(), p, 6 );
        second = f();
        if (first != 1000 + i || second != 2000 + i) bad++;
        VirtualFree( p, 0, MEM_RELEASE );
    }
    printf( "case %s first=%d second=%d stale=%d rounds=%d bad=%d\n", name, first, second, bad ? 1 : 0, rounds, bad );
    return bad ? 1 : 0;
}

/* "trace" mode: one call of each kind that WINE_TRACE_PAGE reports, inside the window 0x50000000-0x50010000 */
static int trace_calls(void)
{
    unsigned char code[6] = { 0xb8, 1, 0, 0, 0, 0xc3 };
    SIZE_T written = 0;
    DWORD old;
    HANDLE map;
    unsigned char *p = VirtualAlloc( BASE, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if (!p) return 1;
    WriteProcessMemory( GetCurrentProcess(), p, code, sizeof(code), &written );
    VirtualProtect( p, 0x1000, PAGE_EXECUTE_READ, &old );
    FlushInstructionCache( GetCurrentProcess(), p, sizeof(code) );
    VirtualFree( p, 0, MEM_RELEASE );
    map = CreateFileMappingW( INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 0x1000, NULL );
    p = MapViewOfFileEx( map, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, 0x1000, BASE );
    if (p) UnmapViewOfFile( p );
    CloseHandle( map );
    printf( "trace calls done, written=%lu\n", (unsigned long)written );
    return 0;
}

int main( int argc, char **argv )
{
    if (argc > 1 && !strcmp( argv[1], "trace" )) return trace_calls();
    if (argc > 1) rounds = atoi( argv[1] );
    stale_cases += run_case( 0, "rw-alloc,write,protect-rwx,run,rewrite+flush,run" );
    stale_cases += run_case( 1, "rwx-alloc,write,run,rewrite+flush,run" );
    stale_cases += run_case( 2, "rwx-alloc,write,run,rewrite-no-flush,run" );
    stale_cases += run_case( 3, "rx-roundtrip-no-flush" );
    return stale_cases;
}
