/* W^X emulation coverage: the NFS16 CPUID-builder stub on pages created through different Windows paths.
 * Every case allocates a page (fixed address 0x1B30000 + n*0x40000 when possible), fills it with 512 qword stores,
 * copies the stub to +0x100 and runs it; a faulting stub (Rosetta resumed late) is caught and counted.
 * Prints "CASE <name> faults=<n>/<rounds>" and "RESULT bad=<n>". With the emulation on every case must give 0. */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static volatile LONG faults; static void *landing;
static LONG CALLBACK veh( EXCEPTION_POINTERS *p )
{
    if (p->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && landing)
    { InterlockedIncrement( &faults ); p->ContextRecord->Rsp += 8; p->ContextRecord->Rip = (DWORD64)landing; return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}
static const unsigned char stub[] = { 0x53, 0x66,0xC7,0x05,0x09,0x00,0x00,0x00,0x90,0xF0, 0x66,0x81,0x35,0x00,0x00,0x00,0x00,0x9F,0x52, 0x00,0x00, 0x5B, 0xC3 };
static int bad;
static unsigned char *land;

/* run the stub on page p (must be writable+executable by Windows rules) */
static int exercise( const char *name, unsigned char *p, int rounds )
{
    int i, r; LONG before = faults;
    if (!p) { printf( "CASE %s alloc-failed err=%lu\n", name, GetLastError() ); bad++; return -1; }
    for (r = 0; r < rounds; r++)
    {
        for (i = 0; i < 512; i++) ((volatile UINT64 *)p)[i] = 0x9090909090909090ull;
        memcpy( p + 0x100, stub, sizeof(stub) );
        ((void (*)(void))(p + 0x100))();
    }
    printf( "CASE %-34s faults=%ld/%d %s\n", name, (long)(faults - before), rounds, faults == before ? "ok" : "FAULT" );
    fflush( stdout );
    if (faults != before) bad++;
    return 0;
}

static void *addr_n = (void *)0x1B30000;
static void *next_addr( void ) { void *a = addr_n; addr_n = (char *)addr_n + 0x40000; return a; }

typedef NTSTATUS (WINAPI *NtCreateSection_t)( HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, LARGE_INTEGER *, ULONG, ULONG, HANDLE );

int main( int argc, char **argv )
{
    unsigned char *p; DWORD old; int rounds = 3;
    if (argc > 1) rounds = atoi( argv[1] );
    AddVectoredExceptionHandler( 1, veh );
    land = VirtualAlloc( NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ); land[0] = 0xc3; landing = land;

    /* P1: the usual: reserve+commit RWX at a fixed address in one call */
    p = VirtualAlloc( next_addr(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ); exercise( "P1 alloc fixed RWX 1 page", p, rounds );
    /* P1b: same, system-chosen address */
    p = VirtualAlloc( NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ); exercise( "P1b alloc anywhere RWX", p, rounds );
    /* P2: reserve 64K, then commit one page RWX */
    p = VirtualAlloc( next_addr(), 0x10000, MEM_RESERVE, PAGE_NOACCESS );
    if (p) p = VirtualAlloc( p, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE ); exercise( "P2 reserve then commit RWX", p, rounds );
    /* P2b: reserve RWX 64K, commit second page RWX */
    p = VirtualAlloc( next_addr(), 0x10000, MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    if (p) p = VirtualAlloc( p + 0x1000, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE ); exercise( "P2b reserve RWX commit page 2", p, rounds );
    /* P3: RW page, then VirtualProtect to RWX */
    p = VirtualAlloc( next_addr(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if (p) VirtualProtect( p, 0x1000, PAGE_EXECUTE_READWRITE, &old ); exercise( "P3 RW then protect RWX", p, rounds );
    /* P4: RX page, then VirtualProtect to RWX */
    p = VirtualAlloc( next_addr(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ );
    if (p) VirtualProtect( p, 0x1000, PAGE_EXECUTE_READWRITE, &old ); exercise( "P4 RX then protect RWX", p, rounds );
    /* P5: NOACCESS commit then protect RWX */
    p = VirtualAlloc( next_addr(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS );
    if (p) VirtualProtect( p, 0x1000, PAGE_EXECUTE_READWRITE, &old ); exercise( "P5 NOACCESS then protect RWX", p, rounds );
    /* P6: pagefile-backed section mapped RWX at a fixed address */
    {
        HANDLE m = CreateFileMappingA( INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 0x1000, NULL );
        p = m ? MapViewOfFileEx( m, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, 0x1000, next_addr() ) : NULL;
        exercise( "P6 section view RWX fixed", p, rounds );
    }
    /* P7: 64K RWX allocation, stub on the 3rd page */
    p = VirtualAlloc( next_addr(), 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ); exercise( "P7 64K RWX, page 0", p, rounds );
    if (p) exercise( "P7b 64K RWX, page 3", p + 0x3000, rounds );
    /* P8: commit a big RW range, make just one page RWX */
    p = VirtualAlloc( next_addr(), 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if (p) { VirtualProtect( p + 0x5000, 0x1000, PAGE_EXECUTE_READWRITE, &old ); p += 0x5000; } exercise( "P8 one RWX page inside RW range", p, rounds );
    /* P9: free and re-allocate the same fixed address (stale state) */
    {
        void *a = next_addr();
        p = VirtualAlloc( a, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ); exercise( "P9 first use of address", p, rounds );
        if (p) VirtualFree( p, 0, MEM_RELEASE );
        p = VirtualAlloc( a, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ); exercise( "P9b same address again", p, rounds );
    }
    /* P10: the page goes RWX -> RX -> RWX (a VM that toggles) */
    p = VirtualAlloc( next_addr(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    if (p) { VirtualProtect( p, 0x1000, PAGE_EXECUTE_READ, &old ); VirtualProtect( p, 0x1000, PAGE_EXECUTE_READWRITE, &old ); } exercise( "P10 RWX->RX->RWX", p, rounds );
    /* P11: top-down / write-watch flags */
    p = VirtualAlloc( NULL, 0x1000, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE ); exercise( "P11 top-down RWX", p, rounds );
    p = VirtualAlloc( NULL, 0x1000, MEM_COMMIT | MEM_RESERVE | MEM_WRITE_WATCH, PAGE_EXECUTE_READWRITE ); exercise( "P11b write-watch RWX", p, rounds );
    printf( "RESULT bad=%d\n", bad );
    return bad;
}
