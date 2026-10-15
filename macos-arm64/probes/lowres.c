// Probe (d): what occupies the low address space of an entitled 4K arm64 process, and can we reserve [0x1000, 4 GiB)?
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>

extern const struct mach_header_64 _mh_execute_header;
extern const void *_dyld_get_shared_cache_range(size_t *length);

static void dump(const char *tag, uint64_t lo, uint64_t hi) {
    int maxl = 14;
    printf("  [%s] regions in [0x%llx, 0x%llx):\n", tag, (unsigned long long)lo, (unsigned long long)hi);
    mach_vm_address_t a = lo; int n = 0;
    while (a < hi) {
        mach_vm_size_t sz = 0; vm_region_basic_info_data_64_t bi; mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64; mach_port_t obj;
        kern_return_t kr = mach_vm_region(mach_task_self(), &a, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&bi, &cnt, &obj);
        if (kr != KERN_SUCCESS || a >= hi) break;
        if (n >= maxl) { n++; a += sz; continue; }
        printf("    0x%011llx-0x%011llx %8lluK prot %c%c%c/%c%c%c %s\n", (unsigned long long)a, (unsigned long long)(a + sz), (unsigned long long)(sz >> 10),
               (bi.protection & 1) ? 'r' : '-', (bi.protection & 2) ? 'w' : '-', (bi.protection & 4) ? 'x' : '-',
               (bi.max_protection & 1) ? 'r' : '-', (bi.max_protection & 2) ? 'w' : '-', (bi.max_protection & 4) ? 'x' : '-',
               bi.reserved ? "reserved" : "");
        a += sz; n++;
    }
    if (!n) printf("    (none)\n"); else if (n > maxl) printf("    ... %d regions total in range\n", n);
}
static uint64_t min_addr(void) { task_vm_info_data_t i; mach_msg_type_number_t n = TASK_VM_INFO_COUNT; task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&i, &n); return i.min_address; }
static void *thr(void *a) { sleep(0); return NULL; }

int main(void) {
    printf("lowres: pid %d pagesize %d min_address 0x%llx image at %p\n", getpid(), getpagesize(), (unsigned long long)min_addr(), (void *)&_mh_execute_header);
    size_t scl = 0; const void *sc = _dyld_get_shared_cache_range(&scl);
    printf("  dyld shared cache: %p + 0x%zx (end %p)\n", sc, scl, (char *)sc + scl);
    dump("at start, below 8 GiB", 0, 0x200000000ull);
    uint64_t freed = 0;
    // Reserve [0x1000, 4 GiB): replace the soft page-zero entry with an inaccessible anonymous reservation owned by us
    void *r = mmap((void *)0x1000, 0xFFFFF000ull, PROT_NONE, MAP_PRIVATE | MAP_ANON | MAP_FIXED | MAP_NORESERVE, -1, 0);
    printf("  reserve mmap(0x1000, 0xFFFFF000, PROT_NONE, FIXED|NORESERVE) -> %s errno %d\n", r == MAP_FAILED ? "FAIL" : "ok", r == MAP_FAILED ? errno : 0);
    if (r == MAP_FAILED) {   // fallback: hole walk
        mach_vm_address_t a = 0x1000; mach_vm_address_t end = 0x100000000ull; int holes = 0;
        while (a < end) {
            mach_vm_address_t q = a; mach_vm_size_t sz = 0; vm_region_basic_info_data_64_t bi; mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64; mach_port_t obj;
            kern_return_t kr = mach_vm_region(mach_task_self(), &q, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&bi, &cnt, &obj);
            mach_vm_address_t hole_end = (kr == KERN_SUCCESS && q < end) ? q : end;
            if (hole_end > a) { mach_vm_address_t p = a; kern_return_t k2 = mach_vm_map(mach_task_self(), &p, hole_end - a, 0, VM_FLAGS_FIXED, MEMORY_OBJECT_NULL, 0, 0, VM_PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY); if (k2 == KERN_SUCCESS) { holes++; freed += hole_end - a; } else printf("   hole 0x%llx-0x%llx: mach_vm_map kr=%d\n", (unsigned long long)a, (unsigned long long)hole_end, k2); }
            if (kr != KERN_SUCCESS || q >= end) break;
            a = q + sz;
        }
        printf("  hole walk reserved %d holes, 0x%llx bytes\n", holes, (unsigned long long)freed);
    }
    dump("after reserve, below 8 GiB", 0, 0x200000000ull);
    // Now hammer the allocator: nothing should land below 4 GiB unless we hand it out.
    int low = 0, total = 0; uint64_t minseen = ~0ull;
    for (int i = 0; i < 2000; i++) { void *p = mmap(NULL, 0x10000 + (i % 7) * 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0); if (p != MAP_FAILED) { total++; if ((uint64_t)p < minseen) minseen = (uint64_t)p; if ((uint64_t)p < 0x100000000ull) low++; } }
    void *big = malloc(512u << 20); void *p2 = malloc(100); if ((uint64_t)big < 0x100000000ull || (uint64_t)p2 < 0x100000000ull) low++;
    pthread_t t[8]; for (int i = 0; i < 8; i++) pthread_create(&t[i], NULL, thr, NULL); for (int i = 0; i < 8; i++) pthread_join(t[i], NULL);
    const char *libs[] = { "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", "/System/Library/Frameworks/Metal.framework/Metal", "/System/Library/Frameworks/CoreAudio.framework/CoreAudio",
                           "/System/Library/Frameworks/AppKit.framework/AppKit", "/usr/lib/libz.dylib", "/opt/homebrew/opt/freetype/lib/libfreetype.6.dylib", "/opt/homebrew/opt/gnutls/lib/libgnutls.30.dylib", NULL };
    for (int i = 0; libs[i]; i++) { void *h = dlopen(libs[i], RTLD_NOW); printf("  dlopen %-72s %s\n", libs[i], h ? "ok" : "FAIL"); }
    for (int i = 0; i < 2000; i++) { void *p = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0); if (p != MAP_FAILED) { total++; if ((uint64_t)p < minseen) minseen = (uint64_t)p; if ((uint64_t)p < 0x100000000ull) low++; } }
    printf("  after hammering (%d NULL-hint mmaps, 512MiB malloc, 8 threads, 7 dlopens): allocations below 4 GiB = %d, lowest address seen 0x%llx\n", total, low, (unsigned long long)minseen);
    // Carving: can we punch an executable-capable area out of the reservation with MAP_FIXED?
    void *c = mmap((void *)0x10000000, 0x400000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    void *d = mmap((void *)0x7ffe0000, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    void *e = mmap((void *)0xfffe0000, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    void *f = mmap((void *)0x1000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    printf("  carve: 0x10000000 %s, 0x7ffe0000 %s, 0xfffe0000 %s, 0x1000 %s\n", c == MAP_FAILED ? "FAIL" : "ok", d == MAP_FAILED ? "FAIL" : "ok", e == MAP_FAILED ? "FAIL" : "ok", f == MAP_FAILED ? "FAIL" : "ok");
    int rr = munmap((void *)0x10000000, 0x400000);
    printf("  munmap of carved area -> %d (hole now returns to the process; a re-reserve step is needed after munmap)\n", rr);
    return 0;
}
