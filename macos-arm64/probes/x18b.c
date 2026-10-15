// Probe (a) part 2: os_set_custom_x18_abi_enabled(true) -- is x18 then a persistent GPR across signal, syscall, thread switch?
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/mman.h>
#include <os/arch/arm64.h>

static inline void set18(uint64_t v) { __asm__ volatile("mov x18, %0" :: "r"(v) :); }
static inline uint64_t get18(void) { uint64_t v; __asm__ volatile("mov %0, x18" : "=r"(v)); return v; }
#define MAGIC 0x1122334455667788ull
static volatile uint64_t g_ent1, g_ent2, g_ent1_mode, g_ent2_mode;
static volatile int g_hits;
static char *g_page;
// handlers: run (possibly) in custom-x18 mode; must not call libc. Record only.
static void on_usr1(int sig, siginfo_t *si, void *uc) {
    g_ent1 = get18(); g_ent1_mode = os_custom_x18_abi_enabled(); g_hits++;
    set18(0xdeadbeefdeadbeefull);          // handler scribbles x18; sigreturn must restore the interrupted value
}
static void on_segv(int sig, siginfo_t *si, void *uc) {
    g_ent2 = get18(); g_ent2_mode = os_custom_x18_abi_enabled();
    set18(0xabad1deaabad1deaull);
    // fix up the fault: needs libc -> bracket with toggle off as the SDK doc says (and save/restore x18 ourselves)
    uint64_t s = get18(); (void)s;
    os_set_custom_x18_abi_enabled(false);
    mprotect(g_page, 0x4000, PROT_READ | PROT_WRITE);
    os_set_custom_x18_abi_enabled(true);
}
static long raw_svc1(long no, long a0) {
    register long x0 __asm__("x0") = a0; register long x16 __asm__("x16") = no;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory", "cc");
    return x0;
}
static long raw_select_sleep(long usec) { // BSD select(0,0,0,0,&tv)
    struct timeval { long s; int us; } tv = { 0, (int)usec };
    register long x0 __asm__("x0") = 0, x1 __asm__("x1") = 0, x2 __asm__("x2") = 0, x3 __asm__("x3") = 0, x4 __asm__("x4") = (long)&tv, x16 __asm__("x16") = 93;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x16) : "memory", "cc");
    return x0;
}
static long raw_swtch_pri(void) { // mach trap swtch_pri(0) = -59
    register long x0 __asm__("x0") = 0; register long x16 __asm__("x16") = -59;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory", "cc");
    return x0;
}
static int ok(uint64_t v) { return v == MAGIC; }
static uint64_t R[16]; static int nr;
static void rec(uint64_t v) { R[nr++] = v; }

struct tctx { uint64_t m; uint64_t start18; long bad; long iters; };
static void *thr(void *a) {
    struct tctx *c = a;
    os_set_custom_x18_abi_enabled(true);
    c->start18 = get18();
    set18(c->m);
    for (long i = 0; i < c->iters; i++) {
        if ((i & 0x3ff) == 0) raw_swtch_pri();
        if ((i & 0xffff) == 0) raw_select_sleep(50);
        if (get18() != c->m) { c->bad++; set18(c->m); }
    }
    uint64_t end = get18();
    os_set_custom_x18_abi_enabled(false);
    if (end != c->m) c->bad++;
    return NULL;
}

int main(void) {
    printf("x18 custom-ABI probe: pid %d pagesize %d, custom_enabled(initial)=%d\n", getpid(), getpagesize(), (int)os_custom_x18_abi_enabled());
    struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = on_usr1; sigaction(SIGUSR1, &sa, NULL);
    sa.sa_sigaction = on_segv; sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL);
    g_page = mmap(NULL, 0x4000, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
    // time the toggle round trip
    struct timespec a, b; clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < 1000000; i++) { os_set_custom_x18_abi_enabled(true); os_set_custom_x18_abi_enabled(false); }
    clock_gettime(CLOCK_MONOTONIC, &b);
    printf("  toggle true+false pair: %.1f ns\n", ((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec)) / 1e6);

    uint64_t sig_pid = getpid();
    os_set_custom_x18_abi_enabled(true);
    // ---- custom mode: no libc below until toggled off ----
    set18(MAGIC); rec(get18());                         // 0 immediate
    raw_svc1(20, 0); rec(get18());                      // 1 raw svc getpid
    raw_select_sleep(1000); rec(get18());               // 2 raw select 1ms
    raw_swtch_pri(); rec(get18());                      // 3 mach trap swtch_pri
    raw_svc1(37, 0); (void)sig_pid;                     // (kill is 37: kill(pid,sig) -> need args; below)
    set18(MAGIC);
    { register long x0 __asm__("x0") = (long)sig_pid, x1 __asm__("x1") = SIGUSR1, x16 __asm__("x16") = 37;
      __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x16) : "memory", "cc"); }
    rec(get18());                                       // 4 after SIGUSR1 handler return
    set18(MAGIC);
    *(volatile int *)g_page = 1;                        // SIGSEGV
    rec(get18());                                       // 5 after SIGSEGV handler return
    uint64_t end18 = get18();
    os_set_custom_x18_abi_enabled(false);
    // ---- back to normal ----
    const char *lbl[] = { "immediate", "raw svc getpid", "raw select(1ms)", "mach trap swtch_pri", "after SIGUSR1 return", "after SIGSEGV return" };
    for (int i = 0; i < nr; i++) printf("  %-24s x18=0x%016llx %s\n", lbl[i], (unsigned long long)R[i], ok(R[i]) ? "OK" : "CLOBBERED");
    printf("  SIGUSR1 handler entry: x18=0x%llx custom_mode_at_entry=%llu hits=%d\n", (unsigned long long)g_ent1, (unsigned long long)g_ent1_mode, g_hits);
    printf("  SIGSEGV handler entry: x18=0x%llx custom_mode_at_entry=%llu\n", (unsigned long long)g_ent2, (unsigned long long)g_ent2_mode);
    (void)end18;
    // thread storm
    enum { N = 24 }; pthread_t t[N]; struct tctx c[N];
    for (int i = 0; i < N; i++) { c[i].m = 0x1000000000000000ull + i * 0x0101010101010101ull + 1; c[i].bad = 0; c[i].iters = 3000000; pthread_create(&t[i], NULL, thr, &c[i]); }
    long bad = 0; int zero = 0;
    for (int i = 0; i < N; i++) { pthread_join(t[i], NULL); bad += c[i].bad; zero += (c[i].start18 == 0); }
    printf("  %d threads x %ld iters (raw swtch_pri + select sleeps): clobbers=%ld; initial x18 zero in %d/%d\n", N, c[0].iters, bad, zero, N);
    // busy loop with timer preemption in custom mode
    os_set_custom_x18_abi_enabled(true); set18(MAGIC); long bad2 = 0;
    for (long i = 0; i < 400000000; i++) if (get18() != MAGIC) { bad2++; set18(MAGIC); }
    os_set_custom_x18_abi_enabled(false);
    printf("  400M busy loop (timer preemption): clobbers=%ld\n", bad2);
    int sigok = ok(R[4]) && ok(R[5]);
    printf("RESULT %s (syscalls %s, signals %s)\n", (bad == 0 && bad2 == 0 && ok(R[1]) && ok(R[2]) && ok(R[3]) && sigok) ? "PERSISTENT" : "NOT-PERSISTENT",
           (ok(R[1]) && ok(R[2]) && ok(R[3])) ? "ok" : "bad", sigok ? "ok" : "bad");
    return 0;
}
