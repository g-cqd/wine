// Minimal reproducer: x86-64 self-modifying code that builds the NEXT instruction with two stores.
// Build:  clang -arch x86_64 -O1 -o rosetta_smc rosetta_smc.c
// Run:    ./rosetta_smc          (on Apple silicon this runs under Rosetta 2)
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

static sigjmp_buf env;
static volatile uintptr_t fault_rip, fault_addr;

static void on_fault(int sig, siginfo_t *si, void *uc_) {
    ucontext_t *uc = uc_;
    fault_rip = uc->uc_mcontext->__ss.__rip;
    fault_addr = (uintptr_t)si->si_addr;
    siglongjmp(env, 1);
}

int main(int argc, char **argv) {
    int gap = argc > 1 ? atoi(argv[1]) : 0;
    int mode = argc > 2 ? atoi(argv[2]) : 0;  // 0 = mov+xor (NFS16 pattern), 1 = one store of 0F A2, 2 = mov+xor but built from C before the call   // NOPs between the stores and the built instruction
    // Stub, offsets in bytes:
    //  0: 53                      push rbx             (cpuid clobbers rbx)
    //  1: 66 C7 05 09 00 00 00 90 F0   mov word [rip+9], 0xF090   ; stores 90 F0 at offset 19
    // 10: 66 81 35 00 00 00 00 9F 52   xor word [rip+0], 0x529F   ; 0xF090 ^ 0x529F = 0xA20F -> bytes 0F A2 (CPUID)
    // 19: 00 00                  placeholder, becomes "0F A2" = cpuid, the very next instruction
    // 21: 5B                     pop rbx
    // 22: C3                     ret
    int translated = 0; size_t tl = sizeof translated;
    sysctlbyname("sysctl.proc_translated", &translated, &tl, NULL, 0);
    printf("running translated by Rosetta: %s\n", translated ? "yes" : "NO (native?)");
    uint8_t stub[256];
    size_t n = 0;
    stub[n++] = 0x53;
    const uint8_t mov[] = {0x66, 0xC7, 0x05, 0x09, 0x00, 0x00, 0x00, 0x90, 0xF0};
    const uint8_t xr[]  = {0x66, 0x81, 0x35, 0x00, 0x00, 0x00, 0x00, 0x9F, 0x52};
    if (mode == 1) {                                               // single store: mov word [rip+gap], 0xA20F
        memcpy(stub + n, mov, 9); stub[n + 3] = gap; stub[n + 7] = 0x0F; stub[n + 8] = 0xA2; n += 9;
    } else {
        memcpy(stub + n, mov, 9); stub[n + 3] = 9 + gap; n += 9;  // disp32 of the mov
        memcpy(stub + n, xr, 9);  stub[n + 3] = gap;     n += 9;  // disp32 of the xor
    }
    for (int g = 0; g < gap; g++) stub[n++] = 0x90;  // optional NOP gap (0 = the NFS16 pattern)
    stub[n++] = 0x00; stub[n++] = 0x00;              // becomes 0F A2 (cpuid)
    stub[n++] = 0x5B; stub[n++] = 0xC3;
    uint8_t *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); return 2; }

    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_fault; sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);

    long ok = 0, bad = 0, rounds = argc > 3 ? atol(argv[3]) : 2000;
    uintptr_t first_rip_off = 0;
    for (long i = 0; i < rounds; i++) {
        memcpy(page, stub, n);           // plain stores, same page every round
        if (sigsetjmp(env, 1) == 0) {
            ((void (*)(void))page)();              // expected: returns normally
            ok++;
        } else {
            if (!bad) first_rip_off = fault_rip - (uintptr_t)page;
            bad++;
        }
    }
    printf("rounds=%ld ok=%ld faulted=%ld\n", rounds, ok, bad);
    if (bad)
        printf("first fault: rip = page+%#lx (cpuid starts at page+%#x), si_addr=%#lx\n",
               (unsigned long)first_rip_off, 0x13 + gap, (unsigned long)fault_addr);
    return bad ? 1 : 0;
}
