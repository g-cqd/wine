/* W^X emulation: (T16) the CPUID-builder stub run in a loop on one page: the page must never be given up (released), the
 * stub must never fault; (T17) a page that was released (kernel write into it) and then goes RWX->RX->RWX or is
 * decommitted and committed again must be emulated again (no stale "released" state); (T18) a pure data page that is
 * hammered from code elsewhere is still released (the designed fallback, so a JIT/heap page does not cost 70 us a store). */
#include <windows.h>
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
#define CHECK(name, cond) do { int ok_ = !!(cond); printf("%-52s %s\n", name, ok_ ? "PASS" : "FAIL"); if (!ok_) bad++; fflush(stdout); } while (0)

static void run_stub( unsigned char *p ) { memcpy( p + 0x100, stub, sizeof(stub) ); ((void (*)(void))(p + 0x100))(); }

static void kernel_write_release( unsigned char *p )
{
    /* a ReadFile into the page: the kernel write releases an emulated page */
    char path[MAX_PATH]; HANDLE h; DWORD n;
    GetModuleFileNameA( NULL, path, sizeof(path) );
    h = CreateFileA( path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
    if (h != INVALID_HANDLE_VALUE) { ReadFile( h, p + 0x800, 64, &n, NULL ); CloseHandle( h ); }
}

int main( int argc, char **argv )
{
    unsigned char *p, *land; DWORD old; int i, loops = argc > 1 ? atoi( argv[1] ) : 20000; LONG f0; DWORD t0, t1;
    AddVectoredExceptionHandler( 1, veh );
    land = VirtualAlloc( NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ); land[0] = 0xc3; landing = land;

    /* T16 */
    p = VirtualAlloc( (void *)0x1B30000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    f0 = faults; t0 = GetTickCount();
    for (i = 0; i < loops; i++) run_stub( p );
    t1 = GetTickCount();
    printf( "   t16: %d runs in %lu ms (%.1f us/run), faults=%ld\n", loops, (unsigned long)(t1 - t0), (t1 - t0) * 1000.0 / loops, (long)(faults - f0) );
    CHECK( "T16 stub loop on one page never faults", faults == f0 );

    /* T17a: released by a kernel write, then RWX -> RX -> RWX */
    p = VirtualAlloc( NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    kernel_write_release( p );
    VirtualProtect( p, 0x1000, PAGE_EXECUTE_READ, &old ); VirtualProtect( p, 0x1000, PAGE_EXECUTE_READWRITE, &old );
    f0 = faults; for (i = 0; i < 5; i++) run_stub( p );
    CHECK( "T17a released, RWX->RX->RWX: emulated again", faults == f0 );

    /* T17b: released by a kernel write, then decommit and commit again */
    p = VirtualAlloc( (void *)0x1C30000, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    kernel_write_release( p );
    VirtualFree( p, 0x1000, MEM_DECOMMIT ); p = VirtualAlloc( p, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    f0 = faults; for (i = 0; i < 5; i++) run_stub( p );
    CHECK( "T17b released, decommit+commit RWX: emulated again", p && faults == f0 );

    /* T17c: released, RWX -> RW -> RWX */
    p = VirtualAlloc( NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    kernel_write_release( p );
    VirtualProtect( p, 0x1000, PAGE_READWRITE, &old ); VirtualProtect( p, 0x1000, PAGE_EXECUTE_READWRITE, &old );
    f0 = faults; for (i = 0; i < 5; i++) run_stub( p );
    CHECK( "T17c released, RWX->RW->RWX: emulated again", faults == f0 );

    /* T18: a data page hammered by a loop elsewhere is released and then costs nothing */
    p = VirtualAlloc( NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    t0 = GetTickCount();
    for (i = 0; i < 2000000; i++) ((volatile DWORD *)p)[(i & 0x3f) + 0x40] = i;
    t1 = GetTickCount();
    printf( "   t18: 2M data stores in %lu ms\n", (unsigned long)(t1 - t0) );
    CHECK( "T18 hammered data page is released (fast)", t1 - t0 < 3000 );

    printf( "RESULT bad=%d\n", bad );
    return bad;
}
