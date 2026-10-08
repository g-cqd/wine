/* W^X emulation with the trap-flag emulation armed: a thread created suspended gets Dr0/Dr7 (an execution breakpoint) through
 * SetThreadContext (what Denuvo's hardware-breakpoint check does), then runs the CPUID-builder stub in a loop. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static volatile LONG faults, bp_hits; static void *landing;
static LONG CALLBACK veh( EXCEPTION_POINTERS *p )
{
    if (p->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && landing)
    { InterlockedIncrement( &faults ); p->ContextRecord->Rsp += 8; p->ContextRecord->Rip = (DWORD64)landing; return EXCEPTION_CONTINUE_EXECUTION; }
    if (p->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) { InterlockedIncrement( &bp_hits ); return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}
static const unsigned char stub[] = { 0x53, 0x66,0xC7,0x05,0x09,0x00,0x00,0x00,0x90,0xF0, 0x66,0x81,0x35,0x00,0x00,0x00,0x00,0x9F,0x52, 0x00,0x00, 0x5B, 0xC3 };
static unsigned char *page; static int loops = 3000;
static DWORD WINAPI worker( void *arg )
{
    int i;
    for (i = 0; i < loops; i++) ((void (*)(void))(page + 0x100))();
    return 0;
}
int main( int argc, char **argv )
{
    unsigned char *land; CONTEXT ctx; HANDLE th; DWORD t0, t1; int use_dr = argc > 1 ? atoi( argv[1] ) : 1;
    if (argc > 2) loops = atoi( argv[2] );
    AddVectoredExceptionHandler( 1, veh );
    land = VirtualAlloc( NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ); land[0] = 0xc3; landing = land;
    page = VirtualAlloc( (void *)0x1B30000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    memcpy( page + 0x100, stub, sizeof(stub) );
    th = CreateThread( NULL, 0, worker, NULL, CREATE_SUSPENDED, NULL );
    if (use_dr)
    {
        memset( &ctx, 0, sizeof(ctx) ); ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        ctx.Dr0 = (DWORD64)(land + 0); ctx.Dr7 = 1;      /* execution breakpoint on the landing byte (never hit unless a fault lands) */
        printf( "   SetThreadContext(Dr) -> %d\n", SetThreadContext( th, &ctx ) );
    }
    t0 = GetTickCount(); ResumeThread( th ); WaitForSingleObject( th, 120000 ); t1 = GetTickCount();
    printf( "   %d runs in %lu ms, faults=%ld, bp_steps=%ld\n", loops, (unsigned long)(t1 - t0), (long)faults, (long)bp_hits );
    {   /* phase 2: the stub runs again on this thread, no debug registers, after the armed thread is gone */
        LONG f1 = faults; int i;
        for (i = 0; i < 200; i++) ((void (*)(void))(page + 0x100))();
        printf( "   phase 2 (no Dr, 200 runs): faults=%ld\n", (long)(faults - f1) );
    }
    printf( "RESULT dr=%d faults=%ld %s\n", use_dr, (long)faults, faults ? "FAIL" : "PASS" );
    return faults != 0;
}
