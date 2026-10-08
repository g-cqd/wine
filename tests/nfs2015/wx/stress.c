/* Chromium/V8-like stress for WINE_RWX_WX_EMULATION: counts stray EXCEPTION_SINGLE_STEP and wrong results */
#include <windows.h>
#include <emmintrin.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile LONG leak_steps, bad_results, vch_other, tf_seen_in_ctx, iterations, stop_flag;
static int opt_workers = 4, opt_secs = 10, opt_suspend = 1, opt_cross = 1, opt_exc = 1, opt_dr = 0, opt_setctx = 1;
static HANDLE workers[16];

static LONG CALLBACK veh(EXCEPTION_POINTERS *p)
{
    DWORD c = p->ExceptionRecord->ExceptionCode;
    if (c == EXCEPTION_SINGLE_STEP) { InterlockedIncrement(&leak_steps); p->ContextRecord->EFlags &= ~0x100u; return EXCEPTION_CONTINUE_EXECUTION; }
    if (c == 0xE0001234) return EXCEPTION_CONTINUE_EXECUTION;
    InterlockedIncrement(&vch_other);
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI worker(void *arg)
{
    unsigned seed = (unsigned)(UINT_PTR)arg * 2654435761u + 1;
    unsigned char *r = VirtualAlloc(NULL, 16 * 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!r) return 1;
    while (!stop_flag)
    {
        unsigned off, k;
        seed = seed * 1103515245u + 12345u;
        off = (seed >> 8) % (7 * 0x1000);
        if (opt_cross && (seed & 3) == 0) off = ((off & ~0xfffu) + 0xfff) - ((seed >> 4) % 6);   /* page 0..6 boundary */   /* straddle a page boundary */
        {
            unsigned char *f = r + off;
            DWORD v = 0x10000000u + (seed & 0xffffff);
            f[0] = 0xb8;                          /* mov eax, imm32 */
            *(DWORD *)(f + 1) = v;                /* unaligned dword store, may cross pages */
            f[5] = 0xc3;                          /* ret */
            k = (seed >> 12) & 7;
            if (k == 1) { __movsb(r + 0x8000 + (seed % 0x1800), r + off, 0x40 + (seed & 0xff)); }
            else if (k == 2) { __stosb(r + 0x9000 + (seed % 0x1800), 0x90, 1 + (seed & 0x7f)); }
            else if (k == 3) { _mm_storeu_si128((__m128i *)(r + 0xaff8 - (seed & 7)), _mm_set1_epi8(0xcc)); }
            else if (k == 4) { InterlockedExchange((LONG *)(r + 0xc000 + (seed & 0xfc)), (LONG)seed); }
            else if (k == 5) { InterlockedCompareExchange((LONG *)(r + 0xdffc), (LONG)seed, 0); }
            else if (k == 6) { _mm_store_si128((__m128i *)(r + 0xe000 + (seed & 0x7f0)), _mm_set1_epi32((int)seed)); }
            if (((int (*)(void))f)() != (int)v) InterlockedIncrement(&bad_results);
            InterlockedIncrement(&iterations);
        }
    }
    return 0;
}

static DWORD WINAPI suspender(void *a)
{
    int i = 0;
    while (!stop_flag)
    {
        HANDLE h = workers[i++ % opt_workers];
        CONTEXT ctx; memset(&ctx, 0, sizeof ctx); ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (SuspendThread(h) == (DWORD)-1) continue;
        if (GetThreadContext(h, &ctx) && (ctx.EFlags & 0x100)) InterlockedIncrement(&tf_seen_in_ctx);
        if (opt_setctx) SetThreadContext(h, &ctx);
        ResumeThread(h);
        Sleep(0);
    }
    return 0;
}

static DWORD WINAPI exceptor(void *a)
{
    while (!stop_flag) { RaiseException(0xE0001234, 0, 0, NULL); Sleep(1); }
    return 0;
}

static DWORD WINAPI dr_arm(void *a)  /* arms a hardware execution breakpoint on a worker like an anti-debug check */
{
    int i = 0;
    while (!stop_flag)
    {
        HANDLE h = workers[i++ % opt_workers];
        CONTEXT ctx; memset(&ctx, 0, sizeof ctx); ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (SuspendThread(h) == (DWORD)-1) continue;
        if (GetThreadContext(h, &ctx)) { ctx.Dr0 = 0; ctx.Dr7 = 0; SetThreadContext(h, &ctx); }
        ResumeThread(h);
        Sleep(2);
    }
    return 0;
}

int main(int argc, char **argv)
{
    int i; HANDLE aux[4]; int na = 0;
    for (i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-w")) opt_workers = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t")) opt_secs = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-nosusp")) opt_suspend = 0;
        else if (!strcmp(argv[i], "-nocross")) opt_cross = 0;
        else if (!strcmp(argv[i], "-noexc")) opt_exc = 0;
        else if (!strcmp(argv[i], "-nosetctx")) opt_setctx = 0;
        else if (!strcmp(argv[i], "-dr")) opt_dr = 1;
    }
    AddVectoredExceptionHandler(1, veh);
    for (i = 0; i < opt_workers; i++) workers[i] = CreateThread(NULL, 0, worker, (void *)(UINT_PTR)(i + 1), 0, NULL);
    if (opt_suspend) aux[na++] = CreateThread(NULL, 0, suspender, NULL, 0, NULL);
    if (opt_exc) aux[na++] = CreateThread(NULL, 0, exceptor, NULL, 0, NULL);
    if (opt_dr) aux[na++] = CreateThread(NULL, 0, dr_arm, NULL, 0, NULL);
    Sleep(opt_secs * 1000);
    stop_flag = 1;
    WaitForMultipleObjects(opt_workers, workers, TRUE, 20000);
    printf("STRESS iter=%ld bad=%ld STEPLEAK=%ld tf_in_ctx=%ld veh_other=%ld\n", iterations, bad_results, leak_steps, tf_seen_in_ctx, vch_other);
    fflush(stdout);
    return (leak_steps || bad_results) ? 1 : 0;
}
