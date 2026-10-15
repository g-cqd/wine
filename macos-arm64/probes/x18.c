// Probe (a): does x18 behave as a persistent per-thread register? arm64 macOS only.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <mach/mach.h>

static inline void set18(uint64_t v) { __asm__ volatile("mov x18, %0" :: "r"(v) : ); }
static inline uint64_t get18(void) { uint64_t v; __asm__ volatile("mov %0, x18" : "=r"(v)); return v; }

#define MAGIC 0x1122334455667788ull
static volatile uint64_t g_handler_entry, g_handler_entry2;
static volatile int g_hits;

static void on_usr1(int sig, siginfo_t *si, void *uc) { g_handler_entry = get18(); set18(0xdeadbeefdeadbeefull); g_hits++; }
static char *g_page;
static void on_segv(int sig, siginfo_t *si, void *uc) { g_handler_entry2 = get18(); mprotect(g_page, 0x4000, PROT_READ | PROT_WRITE); set18(0xabad1deaabad1deaull); }

static int syscall_getpid_raw(void) {
    register long x0 __asm__("x0"); register long x16 __asm__("x16") = 20;
    __asm__ volatile("svc #0x80" : "=r"(x0) : "r"(x16) : "memory", "cc");
    return (int)x0;
}

struct tctx { uint64_t m; int id; uint64_t start18; long bad; long iters; };
static void *thr(void *a) {
    struct tctx *c = a;
    c->start18 = get18();
    set18(c->m);
    for (long i = 0; i < c->iters; i++) {
        if ((i & 0x3ff) == 0) { sched_yield(); }
        if ((i & 0xffff) == 0) usleep(50);
        if (get18() != c->m) { c->bad++; set18(c->m); }
    }
    return NULL;
}

#define CHECK(label, expect) do { uint64_t v = get18(); printf("  %-34s x18=0x%016llx %s\n", label, (unsigned long long)v, v == (expect) ? "OK" : "CLOBBERED"); } while (0)

int main(void) {
    printf("x18 probe: pid %d pagesize %d\n", getpid(), getpagesize());
    set18(MAGIC); CHECK("immediate", MAGIC);
    printf("  (printf with x18 live)\n"); CHECK("after printf", MAGIC);
    syscall_getpid_raw(); CHECK("after raw svc getpid", MAGIC);
    write(1, "", 0); CHECK("after libc write", MAGIC);
    usleep(1000); CHECK("after usleep(1ms)", MAGIC);
    sched_yield(); CHECK("after sched_yield", MAGIC);
    struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_sigaction = on_usr1; sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);
    set18(MAGIC); kill(getpid(), SIGUSR1);
    printf("  SIGUSR1: hits=%d handler-entry x18=0x%llx (%s)\n", g_hits, (unsigned long long)g_handler_entry, g_handler_entry == MAGIC ? "inherited" : (g_handler_entry == 0 ? "zero" : "other"));
    CHECK("after SIGUSR1 return (handler set x18)", MAGIC);
    sa.sa_sigaction = on_segv; sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL);
    g_page = mmap(NULL, 0x4000, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
    set18(MAGIC); *(volatile int *)g_page = 1;
    printf("  SIGSEGV: handler-entry x18=0x%llx (%s)\n", (unsigned long long)g_handler_entry2, g_handler_entry2 == MAGIC ? "inherited" : (g_handler_entry2 == 0 ? "zero" : "other"));
    CHECK("after SIGSEGV return", MAGIC);
    // threads: more threads than cores, each with its own value, many context switches
    enum { N = 24 }; pthread_t t[N]; struct tctx c[N];
    set18(MAGIC);
    for (int i = 0; i < N; i++) { c[i].m = 0x1000000000000000ull + i * 0x0101010101010101ull + 1; c[i].id = i; c[i].bad = 0; c[i].iters = 3000000; pthread_create(&t[i], NULL, thr, &c[i]); }
    long bad = 0; int zero_start = 0, inherit_start = 0;
    for (int i = 0; i < N; i++) { pthread_join(t[i], NULL); bad += c[i].bad; if (c[i].start18 == 0) zero_start++; else if (c[i].start18 == MAGIC) inherit_start++; }
    printf("  %d threads x %ld iters (yield+usleep): clobber count=%ld; new-thread initial x18: zero=%d inherited=%d other=%d\n", N, c[0].iters, bad, zero_start, inherit_start, N - zero_start - inherit_start);
    CHECK("main after thread storm", MAGIC);
    // a long busy loop in main to be preempted by timer ticks
    uint64_t t0 = 0; long bad2 = 0; for (long i = 0; i < 400000000; i++) { if (get18() != MAGIC) { bad2++; set18(MAGIC); } } (void)t0;
    printf("  400M-iteration busy loop (timer preemption): clobbers=%ld\n", bad2);
    printf("RESULT %s\n", (bad == 0 && bad2 == 0 && get18() == MAGIC) ? "PERSISTENT" : "NOT-PERSISTENT");
    return 0;
}
