// Probe (b): executing code from file-backed / mprotected mappings at low addresses (unsigned "PE-like" file).
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <libkern/OSCacheControl.h>

static const uint32_t code[] = { 0xd2800540 /* mov x0,#42 */, 0xd65f03c0 /* ret */ };
static sigjmp_buf jb; static volatile int got_sig;
static void on_sig(int s) { got_sig = s; siglongjmp(jb, 1); }
static void run(const char *label, void *p) {
    struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = on_sig; sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL); sigaction(SIGILL, &sa, NULL);
    got_sig = 0;
    if (sigsetjmp(jb, 1) == 0) { int r = ((int (*)(void))p)(); printf("    %s: executed, returned %d\n", label, r); }
    else printf("    %s: FAULT signal %d on execute\n", label, got_sig);
}
#define M(p) ((p) == MAP_FAILED ? "FAIL" : "ok"), ((p) == MAP_FAILED ? errno : 0)

int main(void) {
    printf("mapexec: pid %d pagesize %d\n", getpid(), getpagesize());
    const char *path = "/tmp/wa64p/pe_like.bin";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    char *buf = calloc(1, 0x3000); memcpy(buf + 0x1000, code, sizeof code);   // code at file offset 0x1000 (4K aligned, "section")
    memcpy(buf, "MZ-fake-unsigned", 16);
    write(fd, buf, 0x3000);
    const uintptr_t addrs[] = { 0x10000000UL, 0x400000UL, 0x7ffe0000UL };
    for (int ai = 0; ai < 3; ai++) {
        uintptr_t A = addrs[ai];
        printf("  --- base 0x%lx ---\n", (unsigned long)A);
        // b1: file-backed R|X private fixed
        void *p = mmap((void *)A, 0x1000, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd, 0x1000);
        printf("  b1 mmap(R|X, PRIVATE|FIXED, file@0x1000) -> %s errno %d\n", M(p));
        if (p != MAP_FAILED) run("b1 exec", p);
        munmap((void *)A, 0x1000);
        // b1b: file-backed R|X, length 0x2000 (as Wine maps sections)
        p = mmap((void *)A, 0x2000, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd, 0x1000);
        printf("  b1b mmap(R|X, 0x2000, file@0x1000) -> %s errno %d\n", M(p));
        munmap((void *)A, 0x2000);
        // b2: file-backed RW private, write code (COW), mprotect RX
        p = mmap((void *)A, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, 0x1000);
        printf("  b2 mmap(RW, PRIVATE|FIXED, file) -> %s errno %d\n", M(p));
        if (p != MAP_FAILED) {
            memcpy(p, code, sizeof code);
            int r = mprotect(p, 0x1000, PROT_READ | PROT_EXEC);
            printf("  b2 mprotect(R|X) after write -> %d errno %d\n", r, r ? errno : 0);
            if (r == 0) { sys_icache_invalidate(p, 8); run("b2 exec", p); }
            r = mprotect(p, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
            printf("  b2 mprotect(RWX) -> %d errno %d\n", r, r ? errno : 0);
        }
        munmap((void *)A, 0x1000);
        // b3: anon RW then mprotect RX
        p = mmap((void *)A, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
        printf("  b3 anon RW fixed -> %s errno %d\n", M(p));
        if (p != MAP_FAILED) {
            memcpy(p, code, sizeof code);
            int r = mprotect(p, 0x1000, PROT_READ | PROT_EXEC);
            printf("  b3 mprotect(R|X) after write -> %d errno %d\n", r, r ? errno : 0);
            if (r == 0) { sys_icache_invalidate(p, 8); run("b3 exec", p); }
        }
        munmap((void *)A, 0x1000);
        // b8: RX -> RW -> write -> RX cycle (self-modifying / relocation patch pattern)
        p = mmap((void *)A, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
        if (p != MAP_FAILED) {
            memcpy(p, code, sizeof code); mprotect(p, 0x1000, PROT_READ | PROT_EXEC); sys_icache_invalidate(p, 8); run("b8 exec#1", p);
            int r1 = mprotect(p, 0x1000, PROT_READ | PROT_WRITE);
            ((uint32_t *)p)[0] = 0xd2800560; /* mov x0,#43 */
            int r2 = mprotect(p, 0x1000, PROT_READ | PROT_EXEC); sys_icache_invalidate(p, 8);
            printf("  b8 RX->RW %d, write, RW->RX %d (expect exec returns 43)\n", r1, r2);
            run("b8 exec#2", p);
        }
        munmap((void *)A, 0x1000);
        // b9: clean (never written) file-backed private mapping: RO, then mprotect R|X ; and MAP_SHARED RO -> R|X
        p = mmap((void *)A, 0x1000, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0x1000);
        if (p != MAP_FAILED) { int r = mprotect(p, 0x1000, PROT_READ | PROT_EXEC); printf("  b9 clean MAP_PRIVATE RO -> mprotect(R|X) -> %d errno %d\n", r, r ? errno : 0); if (!r) run("b9 exec", p); }
        munmap((void *)A, 0x1000);
        p = mmap((void *)A, 0x1000, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0x1000);
        if (p != MAP_FAILED) { int r = mprotect(p, 0x1000, PROT_READ | PROT_EXEC); printf("  b9s clean MAP_SHARED RO -> mprotect(R|X) -> %d errno %d\n", r, r ? errno : 0); }
        munmap((void *)A, 0x1000);
        // b4: anon RWX without MAP_JIT
        p = mmap((void *)A, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
        printf("  b4 anon RWX no MAP_JIT fixed -> %s errno %d\n", M(p));
        if (p != MAP_FAILED) { memcpy(p, code, sizeof code); sys_icache_invalidate(p, 8); run("b4 exec", p); }
        munmap((void *)A, 0x1000);
        // b5: anon MAP_JIT RWX fixed
        p = mmap((void *)A, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT | MAP_FIXED, -1, 0);
        printf("  b5 anon RWX MAP_JIT|MAP_FIXED -> %s errno %d\n", M(p));
        if (p != MAP_FAILED) { pthread_jit_write_protect_np(0); memcpy(p, code, sizeof code); pthread_jit_write_protect_np(1); sys_icache_invalidate(p, 8); run("b5 exec", p); }
        munmap((void *)A, 0x1000);
        // b7: file-backed R|X, MAP_SHARED
        p = mmap((void *)A, 0x1000, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, fd, 0x1000);
        printf("  b7 file R|X MAP_SHARED|FIXED -> %s errno %d\n", M(p));
        if (p != MAP_FAILED) run("b7 exec", p);
        munmap((void *)A, 0x1000);
    }
    return 0;
}
