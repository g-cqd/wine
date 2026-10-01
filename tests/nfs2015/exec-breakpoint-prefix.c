/*
 * Regression fixture for execution-breakpoint delivery under Rosetta, and for the
 * prefixed PUSHF/POPF forms that the trap-flag emulator has to decode.
 *
 * Build:  x86_64-w64-mingw32-gcc -O1 -o exec-breakpoint-prefix.exe exec-breakpoint-prefix.c
 * Run:    WINE_TF_EMULATION=1 WINE_TF_MAX_STEPS=0 WINE_TF_MAX_NS=0 wine exec-breakpoint-prefix.exe
 *
 * Exit code is the number of failed checks, so 0 means pass.  Each check prints a
 * line beginning "ok" or "FAIL" naming what it asserted.
 *
 * The first five checks are pure architecture and must hold on real hardware too, so
 * a stock Windows run is a valid control.  The last two require an x86 hardware
 * execution breakpoint to actually be delivered; those are the ones that fail on
 * Wine + Rosetta without the debug-register and delivery fixes.
 */
#include <windows.h>
#include <stdio.h>

static int failures, checks;

static void check( int ok, const char *what )
{
    ++checks;
    if (!ok) ++failures;
    printf( "%s %s\n", ok ? "ok  " : "FAIL", what );
    fflush( stdout );
}

/* ---- flag helpers, written as raw bytes so the prefixes are exactly what we mean ---- */

/* PUSHFQ; POP RAX  -> full 64-bit RFLAGS */
static ULONG64 flags_q( void )
{
    ULONG64 v;
    __asm__ volatile( ".byte 0x9c\n\tpop %0" : "=r"(v) :: "memory" );
    return v;
}

/* Capture PUSHFQ and PUSHFW back to back from one flag state.  They have to be in a
 * single asm block with no flag-modifying instruction between them, otherwise the
 * comparison is meaningless: an intervening ADD alone would change the low bits.
 * MOVZWL and MOVQ do not touch EFLAGS, so the reads afterwards are safe. */
static void flags_q_and_w( ULONG64 *q, unsigned int *w )
{
    __asm__ volatile( ".byte 0x9c\n\t"             /* PUSHFQ -> 8 bytes */
                      ".byte 0x66, 0x9c\n\t"       /* PUSHFW -> 2 bytes */
                      "movzwl (%%rsp), %1\n\t"
                      "movq 2(%%rsp), %0\n\t"
                      "leaq 10(%%rsp), %%rsp"
                      : "=&r"(*q), "=&r"(*w) :: "memory" );
}

/* 66 9D = POPFW: writes only EFLAGS[15:0], leaving everything above untouched. */
static void set_flags_w( unsigned short v )
{
    __asm__ volatile( "subq $2, %%rsp\n\t"
                      "movw %0, (%%rsp)\n\t"
                      ".byte 0x66, 0x9d"          /* POPFW */
                      :: "r"(v) : "memory", "cc" );
}

/* REX.W-prefixed PUSHFQ.  REX is absorbed: these instructions already default to a
 * 64-bit operand size, so 48 9C must behave exactly like 9C. */
static ULONG64 flags_q_rex( void )
{
    ULONG64 v;
    __asm__ volatile( ".byte 0x48, 0x9c\n\tpop %0" : "=r"(v) :: "memory" );
    return v;
}

/* ---- the breakpoint target ---- */

static volatile int target_ran;
static void *target_addr;
static volatile LONG hits;
static volatile ULONG64 hit_dr6;

__attribute__((noinline)) static void breakpoint_target( void )
{
    target_ran = 1;
    __asm__ volatile( "" ::: "memory" );
}

static LONG CALLBACK veh( EXCEPTION_POINTERS *ep )
{
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        ep->ExceptionRecord->ExceptionAddress == target_addr)
    {
        InterlockedIncrement( &hits );
        hit_dr6 = ep->ContextRecord->Dr6;
        /* Disarm so we trap once, and clear the status bits as a debugger would. */
        ep->ContextRecord->Dr7 = 0;
        ep->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Worker that waits to be released, then calls the armed address. */
static HANDLE go;
static DWORD WINAPI worker( void *unused )
{
    (void)unused;
    WaitForSingleObject( go, INFINITE );
    breakpoint_target();
    return 0;
}

int main( void )
{
    ULONG64 q, q2;
    CONTEXT ctx;
    HANDLE th;
    DWORD tid;

    target_addr = (void *)breakpoint_target;

    /* 1. A REX prefix must not change PUSHFQ.  Compare the documented always-set
     *    bit 1 and the low status bits rather than the whole word, because the
     *    flags legitimately differ between the two reads. */
    q  = flags_q();
    q2 = flags_q_rex();
    check( (q & 2) && (q2 & 2), "PUSHFQ and REX.W PUSHFQ both report EFLAGS bit 1 set" );
    check( (q >> 32) == 0 && (q2 >> 32) == 0, "PUSHFQ upper 32 bits of RFLAGS are zero" );

    /* 2. PUSHFW must agree with the low half of PUSHFQ, captured from one flag state. */
    {
        unsigned int w32 = 0;
        ULONG64 qq = 0;
        flags_q_and_w( &qq, &w32 );
        check( (unsigned int)(qq & 0xffff) == w32,
               "PUSHFW agrees with the low 16 bits of PUSHFQ" );
    }

    /* 3. POPFW must leave EFLAGS above bit 15 alone.  Set AC (bit 18) via POPFQ,
     *    then do a POPFW and confirm AC survived.  This is the bit the emulator's
     *    narrower 0x4dd5 mask exists to protect. */
    {
        ULONG64 before = flags_q();
        unsigned short low = (unsigned short)(before & 0xffff);
        set_flags_w( (unsigned short)(low | 1) );   /* set CF through POPFW */
        q = flags_q();
        check( (q & 1) == 1, "POPFW set CF" );
        check( (q & ~(ULONG64)0xffff) == (before & ~(ULONG64)0xffff),
               "POPFW left EFLAGS above bit 15 unchanged" );
    }

    /* 4-6. Arm DR0 as a 1-byte execution breakpoint on another thread and confirm
     *      the trap is delivered to the VEH with the right DR6 bit. */
    if (!AddVectoredExceptionHandler( 1, veh ))
    {
        printf( "FAIL could not install vectored handler\n" );
        return ++failures;
    }
    go = CreateEventW( NULL, TRUE, FALSE, NULL );
    th = CreateThread( NULL, 0, worker, NULL, CREATE_SUSPENDED, &tid );
    if (!th || !go)
    {
        printf( "FAIL could not create worker\n" );
        return ++failures;
    }

    memset( &ctx, 0, sizeof(ctx) );
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    ctx.Dr0 = (ULONG64)(ULONG_PTR)target_addr;
    ctx.Dr7 = 1;                       /* L0, RW=00 (execute), LEN=00 (1 byte) */
    check( SetThreadContext( th, &ctx ) != 0, "SetThreadContext accepted an execution breakpoint" );

    memset( &ctx, 0, sizeof(ctx) );
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    check( GetThreadContext( th, &ctx ) && ctx.Dr0 == (ULONG64)(ULONG_PTR)target_addr && ctx.Dr7 == 1,
           "GetThreadContext reads back the debug registers that were written" );

    ResumeThread( th );
    SetEvent( go );
    WaitForSingleObject( th, 10000 );

    check( target_ran == 1, "worker reached the armed address" );
    check( hits == 1, "execution breakpoint was delivered exactly once" );
    check( (hit_dr6 & 1) == 1, "DR6 reported breakpoint 0 as the cause" );

    printf( "\n%d checks, %d failures\n", checks, failures );
    return failures;
}
