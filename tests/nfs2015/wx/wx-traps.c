/* W^X emulation trap tests (WINE_RWX_WX_EMULATION): every test must give the same answer with the switch off and on */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <emmintrin.h>
#include <stdlib.h>

static const unsigned char mov_ret[] = { 0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3 }; /* mov eax,0x12345678; ret */
static int fails;
#define CHECK(name, cond) do { int ok_ = !!(cond); printf("%-34s %s\n", name, ok_ ? "PASS" : "FAIL"); if (!ok_) fails++; fflush(stdout); } while (0)

static unsigned char *rwx(void *at) { return VirtualAlloc( at, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ); }
static int run(unsigned char *p) { return ((int (*)(void))p)(); }

static void t1(void)
{
    unsigned char *p = rwx( NULL ); int i, bad = 0;
    for (i = 0; i < 2000; i++)
    {
        memcpy( p, mov_ret, sizeof(mov_ret) );
        *(DWORD *)(p + 1) = 0x1000 + i;               /* patch the immediate right ahead of the next call */
        if (run( p ) != 0x1000 + i) bad++;
    }
    CHECK( "T1 guest stores + execute x2000", p && !bad );
    VirtualFree( p, 0, MEM_RELEASE );
}

static void t2(void)
{
    char name[MAX_PATH]; HANDLE h; DWORD n = 0; unsigned char *p = rwx( NULL ); BOOL ok;
    snprintf( name, sizeof(name), "wx-t2-%lu.bin", GetCurrentProcessId() );
    h = CreateFileA( name, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
    WriteFile( h, mov_ret, sizeof(mov_ret), &n, NULL ); SetFilePointer( h, 0, NULL, FILE_BEGIN );
    ok = ReadFile( h, p + 0x100, sizeof(mov_ret), &n, NULL );
    CloseHandle( h ); DeleteFileA( name );
    CHECK( "T2 ReadFile into RWX page + run", ok && n == sizeof(mov_ret) && run( p + 0x100 ) == 0x12345678 );
    VirtualFree( p, 0, MEM_RELEASE );
}

static void t3(void)
{
    unsigned char *p = rwx( NULL ); int ok;
    memset( p, 0xcc, 0x1000 ); RtlMoveMemory( p + 0x200, mov_ret, sizeof(mov_ret) );
    ok = (run( p + 0x200 ) == 0x12345678) && p[0] == 0xcc && p[0xfff] == 0xcc;
    CHECK( "T3 memset/RtlMoveMemory + run", ok );
    VirtualFree( p, 0, MEM_RELEASE );
}

static void t4(void)
{
    unsigned char *p = rwx( NULL ), *q = rwx( NULL ); SIZE_T n = 0; BOOL a, b;
    a = WriteProcessMemory( GetCurrentProcess(), p + 0x40, mov_ret, sizeof(mov_ret), &n );
    b = ReadProcessMemory( GetCurrentProcess(), p + 0x40, q + 0x80, sizeof(mov_ret), &n );
    CHECK( "T4 Write/ReadProcessMemory self", a && b && run( p + 0x40 ) == 0x12345678 && run( q + 0x80 ) == 0x12345678 );
    VirtualFree( p, 0, MEM_RELEASE ); VirtualFree( q, 0, MEM_RELEASE );
}

static void t5(void)
{
    unsigned char *p = rwx( NULL ); PROCESS_BASIC_INFORMATION *pbi = (void *)(p + 0x100); ULONG len = 0; NTSTATUS st;
    char *s = (char *)(p + 0x400); DWORD n1, n2; char *env = (char *)(p + 0x800);
    st = NtQueryInformationProcess( GetCurrentProcess(), ProcessBasicInformation, pbi, sizeof(*pbi), &len );
    n1 = GetModuleFileNameA( NULL, s, 200 );
    n2 = GetEnvironmentVariableA( "PATH", env, 100 );
    CHECK( "T5 syscall outputs into RWX page", !st && pbi->UniqueProcessId && n1 > 3 && n2 > 0 );
    VirtualFree( p, 0, MEM_RELEASE );
}

static unsigned char *g_page;
static volatile LONG g_go;
static DWORD WINAPI storer( void *arg )
{
    volatile DWORD *slot = (volatile DWORD *)(g_page + 0x400 + (INT_PTR)arg * 64); int i;
    while (!g_go) Sleep( 0 );
    for (i = 0; i < 20000; i++) *slot = i;
    return *slot == 19999;
}
static void t6(void)
{
    HANDLE h[2]; DWORD r0 = 0, r1 = 0;
    g_page = rwx( NULL ); g_go = 0;
    h[0] = CreateThread( NULL, 0, storer, (void *)0, 0, NULL );
    h[1] = CreateThread( NULL, 0, storer, (void *)1, 0, NULL );
    g_go = 1; WaitForMultipleObjects( 2, h, TRUE, 60000 );
    GetExitCodeThread( h[0], &r0 ); GetExitCodeThread( h[1], &r1 );
    memcpy( g_page, mov_ret, sizeof(mov_ret) );
    CHECK( "T6 two threads store to one page", r0 == 1 && r1 == 1 && run( g_page ) == 0x12345678 );
    VirtualFree( g_page, 0, MEM_RELEASE );
}

static LONG av_hits;
static void *jb[5];
static volatile int jb_armed;
static LONG CALLBACK veh( EXCEPTION_POINTERS *e )
{
    if (jb_armed && e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    {
        av_hits++;
        if (e->ContextRecord->EFlags & 0x100) printf("   NOTE: TF leaked into the guest exception context\n");
        jb_armed = 0;
        __builtin_longjmp( jb, 1 );
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#define TRY_STORE(stmt, counter) do { if (__builtin_setjmp( jb ) == 0) { jb_armed = 1; stmt; jb_armed = 0; } else { counter++; } } while (0)
static void t7(void)
{
    unsigned char *p = rwx( (void *)0x2a40000 ); DWORD old; int ok = 1, i; volatile int caught = 0;
    if (!p) p = rwx( NULL );
    for (i = 0; i < 50; i++)
    {
        memcpy( p, mov_ret, sizeof(mov_ret) );
        VirtualProtect( p, 0x1000, PAGE_EXECUTE_READ, &old );
        ok &= run( p ) == 0x12345678;
        TRY_STORE( p[10] = 1, caught );   /* RX page: must fault */
        VirtualProtect( p, 0x1000, PAGE_EXECUTE_READWRITE, &old );
        p[10] = 7; ok &= p[10] == 7;                                               /* RWX again: store works */
    }
    CHECK( "T7 RWX->RX->RWX x50 (RX store faults)", ok && caught == 50 );
    VirtualFree( p, 0, MEM_RELEASE );
    p = rwx( (void *)0x2a40000 ); memcpy( p, mov_ret, sizeof(mov_ret) );          /* free + same address again */
    CHECK( "T7b free and realloc same address", p && run( p ) == 0x12345678 );
    if (p) VirtualFree( p, 0, MEM_RELEASE );
}

static void t8(void)
{
    unsigned char *p = rwx( NULL ); volatile DWORD *ctr = (volatile DWORD *)(p + 0x800); int i, N = getenv("WXT8N") ? atoi(getenv("WXT8N")) : 5000000; DWORD t0, t1;
    memcpy( p, mov_ret, sizeof(mov_ret) ); *ctr = 0;
    t0 = GetTickCount();
    for (i = 0; i < N; i++) (*ctr)++;
    t1 = GetTickCount();
    printf("   T8 mixed page: %d data stores took %lu ms\n", N, t1 - t0 );
    CHECK( "T8 mixed code/data page store loop", *ctr == (DWORD)N && run( p ) == 0x12345678 );
    VirtualFree( p, 0, MEM_RELEASE );
}

static int step_seen, null_seen;
static LONG CALLBACK veh2( EXCEPTION_POINTERS *e )
{
    if (e->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) { step_seen++; return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}
static void t9(void)
{
    unsigned char *p = rwx( NULL ); volatile int *np = NULL; volatile int caught = 0; int tf_leak = 0;
    memcpy( p, mov_ret, sizeof(mov_ret) );
    TRY_STORE( (p[20] = 1, *np = 5), caught );  /* store, then an unrelated fault right after */
    p[20] = 2;
    CHECK( "T9 SEH after a store to the page", caught == 1 && p[20] == 2 && run( p ) == 0x12345678 );
    {
        PVOID h = AddVectoredExceptionHandler( 1, veh2 );
        step_seen = 0;
        __asm__ volatile ( "pushfq\n orq $0x100,(%%rsp)\n popfq\n movb $9,(%0)\n nop\n nop\n" :: "r"(p + 24) : "memory" );
        RemoveVectoredExceptionHandler( h );
        CHECK( "T9b guest-set TF + store: guest step seen", step_seen >= 1 && p[24] == 9 );
    }
    (void)tf_leak;
    VirtualFree( p, 0, MEM_RELEASE );
}

static void t11(void)
{
    char cmd[MAX_PATH + 16]; STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi; DWORD code = 99; char me[MAX_PATH];
    GetModuleFileNameA( NULL, me, sizeof(me) );
    snprintf( cmd, sizeof(cmd), "\"%s\" child", me );
    if (CreateProcessA( NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi ))
    {
        WaitForSingleObject( pi.hProcess, 60000 ); GetExitCodeProcess( pi.hProcess, &code );
        CloseHandle( pi.hProcess ); CloseHandle( pi.hThread );
    }
    CHECK( "T11 child process runs the stub too", code == 0 );
}

static void t12(void)
{
    unsigned char *pages[100]; int i, ok = 1;
    for (i = 0; i < 100; i++) { pages[i] = rwx( NULL ); if (!pages[i]) { ok = 0; break; } memcpy( pages[i], mov_ret, sizeof(mov_ret) ); pages[i][0x300] = (unsigned char)i; ok &= run( pages[i] ) == 0x12345678; }
    for (i = 0; i < 100 && pages[i]; i++) { ok &= pages[i][0x300] == (unsigned char)i; VirtualFree( pages[i], 0, MEM_RELEASE ); }
    CHECK( "T12 100 pages, each written then freed", ok );
}


/* ---- patch 0009 regression tests ---- */
static volatile LONG t14_leaks, t14_stop, t14_iters;
static LONG CALLBACK veh14( EXCEPTION_POINTERS *p )
{
    if (p->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) { InterlockedIncrement( &t14_leaks ); p->ContextRecord->EFlags &= ~0x100u; return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}
static DWORD WINAPI t14_worker( void *arg )
{
    unsigned char *r = arg; unsigned seed = 12345;
    while (!t14_stop)
    {
        unsigned char *f = r + 0x10 + (seed % 0x400);
        seed = seed * 1103515245u + 12345u;
        f[0] = 0xb8; *(DWORD *)(f + 1) = seed; f[5] = 0xc3;
        if (((int (*)(void))f)() != (int)seed) InterlockedIncrement( &t14_leaks );
        r[0x2000 + (seed & 0xfff)] = (unsigned char)seed;      /* data store in the same region, other page */
        InterlockedIncrement( &t14_iters );
    }
    return 0;
}
static void t14(void)
{
    unsigned char *r = VirtualAlloc( NULL, 4 * 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    HANDLE th, vh = AddVectoredExceptionHandler( 1, veh14 ); int i; LONG tfctx = 0;
    th = CreateThread( NULL, 0, t14_worker, r, 0, NULL );
    for (i = 0; i < 1500; i++)
    {
        CONTEXT c; memset( &c, 0, sizeof(c) ); c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (SuspendThread( th ) == (DWORD)-1) continue;
        if (GetThreadContext( th, &c ) && (c.EFlags & 0x100)) tfctx++;
        SetThreadContext( th, &c );      /* writes the captured context back, as a profiler or debugger helper does */
        ResumeThread( th );
        if (!(i & 7)) Sleep( 0 );
    }
    t14_stop = 1; WaitForSingleObject( th, 20000 ); CloseHandle( th );
    RemoveVectoredExceptionHandler( vh );
    printf( "   t14: iterations=%ld trap flag seen in %ld captured contexts, stray single-steps=%ld\n", t14_iters, tfctx, t14_leaks );
    CHECK( "T14 suspend/Get/SetThreadContext storm: no stray step, no TF in contexts", t14_leaks == 0 && tfctx == 0 && t14_iters > 100 );
    VirtualFree( r, 0, MEM_RELEASE );
}

static void t13(void)
{
    unsigned char *p = VirtualAlloc( NULL, 4 * 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    DWORD t0 = GetTickCount(), dt; int i, bad = 0;
    for (i = 0; i < 3000; i++)
    {
        *(UINT64 *)(p + 0xffc) = 0x1122334455667788ull + i;              /* straddles page 0 / page 1 */
        _mm_storeu_si128( (__m128i *)(p + 0x1ff8), _mm_set1_epi32( i ) );  /* straddles page 1 / page 2 */
        memset( p + 0x2ff0, i, 32 );                                      /* straddles page 2 / page 3 */
        if (*(UINT64 *)(p + 0xffc) != 0x1122334455667788ull + i || p[0x2fff] != (unsigned char)i || p[0x3000] != (unsigned char)i) bad++;
    }
    dt = GetTickCount() - t0;
    printf( "   t13: 3000 rounds of three page-straddling stores took %lu ms\n", dt );
    CHECK( "T13 page-straddling stores complete quickly", !bad && dt < 5000 );
    VirtualFree( p, 0, MEM_RELEASE );
}


/* ---- T15: a page that is filled first (512 qword stores), then holds the two-store CPUID stub ---- */
static volatile LONG t15_faults; static void *t15_landing;
static LONG CALLBACK veh15( EXCEPTION_POINTERS *p )
{
    if (p->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && t15_landing)
    { InterlockedIncrement( &t15_faults ); p->ContextRecord->Rsp += 8; p->ContextRecord->Rip = (DWORD64)t15_landing; return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}
static void t15(void)
{
    static const unsigned char stub[] = { 0x53, 0x66,0xC7,0x05,0x09,0x00,0x00,0x00,0x90,0xF0, 0x66,0x81,0x35,0x00,0x00,0x00,0x00,0x9F,0x52, 0x00,0x00, 0x5B, 0xC3 };
    unsigned char *p = rwx( NULL ), *land = rwx( NULL ); int i, round, bad = 0;
    HANDLE vh = AddVectoredExceptionHandler( 1, veh15 );
    land[0] = 0xc3; t15_landing = land;
    for (round = 0; round < 5; round++)
    {
        if (round) { VirtualFree( p, 0, MEM_RELEASE ); p = rwx( NULL ); }              /* a stub page is written once, on a fresh page */
        for (i = 0; i < 512; i++) ((volatile UINT64 *)p)[i] = 0x9090909090909090ull;   /* fill the whole page first */
        memcpy( p + 0x100, stub, sizeof(stub) );
        ((void (*)(void))(p + 0x100))();
    }
    bad = t15_faults;
    RemoveVectoredExceptionHandler( vh ); t15_landing = NULL;
    printf( "   t15: 5 fresh pages, stub faults=%d\n", bad );
    CHECK( "T15 filled page then CPUID stub runs (default hot limit)", bad == 0 );
    VirtualFree( p, 0, MEM_RELEASE ); VirtualFree( land, 0, MEM_RELEASE );
}

int main( int argc, char **argv )
{
    if (argc > 1 && !strcmp( argv[1], "child" ))
    {
        unsigned char *p = rwx( NULL ); int ok;
        memcpy( p, mov_ret, sizeof(mov_ret) ); *(DWORD *)(p + 1) = 0x777; ok = run( p ) == 0x777;
        return ok ? 0 : 1;
    }
    (void)null_seen;
    AddVectoredExceptionHandler( 1, veh );
    t1(); t2(); t3(); t4(); t5(); t6(); t7(); t8(); t9(); t11(); t12(); t13(); t14(); t15();
    printf( "RESULT fails=%d\n", fails );
    return fails;
}
