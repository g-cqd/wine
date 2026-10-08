/* Reproducer of the NFS16 two-store self-modifying-code stub (page 0x1B30000, entry +0xE3).
   Same source builds as PE (mingw) and as a native x86_64 Mach-O (clang -arch x86_64). */
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#define SYM(x) #x
#else
#include <pthread.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#define SYM(x) "_" #x
#endif

/* bytes 0xA0..0x1FF of the page as printed in the wine-crash block (11 rows x 32) */
static const char *rows[] = {
"00 00 57 56 31 f6 73 01 56 53 48 8d 1d 17 c0 02 00 31 56 53 48 8d 1d 17 c0 02 00 31 57 52 48 8d",
"15 bc 5b 02 00 31 ff 73 01 b8 48 8d 92 56 a4 fd ff ff d2 f3 80 08 b7 48 8d 64 24 08 5a 48 96 e8",
"01 00 00 57 f9 72 01 22 2d 29 54 9f ed e8 01 00 00 00 22 48 83 c4 08 35 4a a1 fa 6c 48 95 e8 01",
"00 00 00 75 83 04 24 07 c3 69 48 95 e8 01 00 00 00 b0 48 83 c4 08 48 93 e8 01 00 00 00 51 48 93",
"48 83 c4 08 e8 01 00 00 00 1f 48 83 c4 08 05 53 0a d5 67 48 96 e8 01 00 00 00 f6 48 83 c4 08 48",
"96 35 9f 52 a8 3e 66 c7 05 09 00 00 00 90 f0 66 81 35 00 00 00 00 9f 52 00 00 31 ff 73 01 85 35",
"bc 85 e8 ac 52 48 8d 15 ba 8b 01 00 31 ff 73 01 b8 48 8d 92 57 74 fe ff ff d2 1f 5a 76 48 8d 64",
"24 08 5a 81 f3 c7 2e 0a 12 f9 72 01 e9 81 f1 66 f8 19 2b 48 91 e8 01 00 00 00 ff 83 04 24 07 c3",
"d0 48 91 81 f2 10 37 61 8d 31 ff 73 01 a3 5f c3 48 8d 64 24 08 59 81 f2 fd 0c e5 fd e8 01 00 00",
"00 e8 48 83 c4 08 5f c3 72 01 e9 5e c3 cf 56 42 48 8d 64 24 08 59 5f c3 ff ff d2 f7 4d 8d d7 48",
"8d 64 24 08 5a 5e c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"};
static uint8_t tmpl[0x1000];
#define TMPL_OFF 0xA0
#define ENTRY_OFF 0xE3
#define STORE_OFF 0x158

void *g_entry; void *g_saved_rsp; int g_tf; volatile int g_step; static long stepcount, guard_enter, guard_leave; static uint8_t *g_guardpage; int g_guard; int g_wx; volatile int g_wxstep; static long wx_faults;
extern int run_stub(void);
__asm__(".text\n.globl " SYM(run_stub) "\n" SYM(run_stub) ":\n"
 "push %rbx\npush %rbp\npush %r12\npush %r13\npush %r14\npush %r15\npush %rsi\npush %rdi\nsub $8,%rsp\n"
 "mov %rsp," SYM(g_saved_rsp) "(%rip)\nmov " SYM(g_entry) "(%rip),%rax\n"
 "cmpl $0," SYM(g_tf) "(%rip)\nje 2f\nmovl $1," SYM(g_step) "(%rip)\npushfq\norq $0x100,(%rsp)\npopfq\n2:\ncall *%rax\n"
 "movl $0," SYM(g_step) "(%rip)\npushfq\nandq $-257,(%rsp)\npopfq\nxor %eax,%eax\njmp 1f\n"
 ".globl " SYM(run_stub_recover) "\n" SYM(run_stub_recover) ":\nmov $1,%eax\n"
 "1:\nadd $8,%rsp\npop %rdi\npop %rsi\npop %r15\npop %r14\npop %r13\npop %r12\npop %rbp\npop %rbx\nret\n");
extern char run_stub_recover[];

static void set_prot3(int mode){ /* 0 RW, 1 RWX, 2 RX */
#ifdef _WIN32
  DWORD old; VirtualProtect(g_guardpage,0x1000,mode==0?PAGE_READWRITE:mode==1?PAGE_EXECUTE_READWRITE:PAGE_EXECUTE_READ,&old);
#else
  mprotect(g_guardpage,0x1000,mode==0?PROT_READ|PROT_WRITE:mode==1?PROT_READ|PROT_WRITE|PROT_EXEC:PROT_READ|PROT_EXEC);
#endif
}
static void set_exec(int on){
#ifdef _WIN32
  DWORD old; VirtualProtect(g_guardpage,0x1000,on?PAGE_EXECUTE_READWRITE:PAGE_READWRITE,&old);
#else
  mprotect(g_guardpage,0x1000,PROT_READ|PROT_WRITE|(on?PROT_EXEC:0));
#endif
}
#define MAXRIP 16
static uintptr_t rip_val[MAXRIP]; static long rip_cnt[MAXRIP]; static int nrip; static long sigcount;
static void note(uintptr_t rip){ sigcount++; for(int i=0;i<nrip;i++) if(rip_val[i]==rip){rip_cnt[i]++;return;} if(nrip<MAXRIP){rip_val[nrip]=rip;rip_cnt[nrip++]=1;} }
#ifdef _WIN32
static LONG CALLBACK veh(EXCEPTION_POINTERS *p){
  if(g_wx && p->ExceptionRecord->ExceptionCode==0xc0000005 && p->ExceptionRecord->ExceptionInformation[0]==1 &&
     (uintptr_t)p->ExceptionRecord->ExceptionInformation[1]-(uintptr_t)g_guardpage<0x1000){ wx_faults++; set_prot3(1); g_wxstep=1; p->ContextRecord->EFlags|=0x100u; return EXCEPTION_CONTINUE_EXECUTION; }
  if(g_wx && p->ExceptionRecord->ExceptionCode==0x80000004 && g_wxstep){ stepcount++; set_prot3(2); g_wxstep=0; p->ContextRecord->EFlags&=~0x100u; return EXCEPTION_CONTINUE_EXECUTION; }
  if(g_guard && p->ExceptionRecord->ExceptionCode==0xc0000005 && p->ExceptionRecord->ExceptionInformation[0]==8 &&
     (uintptr_t)p->ExceptionRecord->ExceptionInformation[1]-(uintptr_t)g_guardpage<0x1000){ guard_enter++; set_exec(1); g_step=1; p->ContextRecord->EFlags|=0x100u; return EXCEPTION_CONTINUE_EXECUTION; }
  if(p->ExceptionRecord->ExceptionCode==0x80000004 && g_guard){ stepcount++; if((uintptr_t)p->ContextRecord->Rip-(uintptr_t)g_guardpage<0x1000) p->ContextRecord->EFlags|=0x100u; else { p->ContextRecord->EFlags&=~0x100u; if(g_step){ g_step=0; guard_leave++; set_exec(0);} } return EXCEPTION_CONTINUE_EXECUTION; }
  if(p->ExceptionRecord->ExceptionCode==0x80000004){ stepcount++; if(g_step) p->ContextRecord->EFlags|=0x100u; else p->ContextRecord->EFlags&=~0x100u; return EXCEPTION_CONTINUE_EXECUTION; }
  note((uintptr_t)p->ContextRecord->Rip);
  p->ContextRecord->Rip=(DWORD64)(uintptr_t)run_stub_recover; p->ContextRecord->Rsp=(DWORD64)(uintptr_t)g_saved_rsp;
  p->ContextRecord->EFlags &= ~0x100u;
  return EXCEPTION_CONTINUE_EXECUTION; }
#else
static void sh(int sig, siginfo_t *si, void *uc_){ ucontext_t *uc=uc_; (void)si;
  if(g_wx && (sig==SIGSEGV||sig==SIGBUS) && (uintptr_t)si->si_addr-(uintptr_t)g_guardpage<0x1000){ wx_faults++; set_prot3(1); g_wxstep=1; uc->uc_mcontext->__ss.__rflags|=0x100; return; }
  if(g_wx && sig==SIGTRAP && g_wxstep){ stepcount++; set_prot3(2); g_wxstep=0; uc->uc_mcontext->__ss.__rflags&=~0x100ULL; return; }
  if(g_guard && (sig==SIGSEGV||sig==SIGBUS) && (uintptr_t)si->si_addr-(uintptr_t)g_guardpage<0x1000 && (uintptr_t)uc->uc_mcontext->__ss.__rip-(uintptr_t)g_guardpage<0x1000){ guard_enter++; set_exec(1); g_step=1; uc->uc_mcontext->__ss.__rflags|=0x100; return; }
  if(g_guard && sig==SIGTRAP){ stepcount++; if((uintptr_t)uc->uc_mcontext->__ss.__rip-(uintptr_t)g_guardpage<0x1000) uc->uc_mcontext->__ss.__rflags|=0x100; else { uc->uc_mcontext->__ss.__rflags&=~0x100ULL; if(g_step){ g_step=0; guard_leave++; set_exec(0);} } return; }
  if(sig==SIGTRAP){ stepcount++; if(g_step) uc->uc_mcontext->__ss.__rflags|=0x100; else uc->uc_mcontext->__ss.__rflags&=~0x100ULL; return; }
  note((uintptr_t)uc->uc_mcontext->__ss.__rip);
  uc->uc_mcontext->__ss.__rip=(uint64_t)(uintptr_t)run_stub_recover; uc->uc_mcontext->__ss.__rsp=(uint64_t)(uintptr_t)g_saved_rsp; }
#endif

static volatile int stop_spin; static volatile uint8_t *spinbuf;
#ifdef _WIN32
static DWORD WINAPI spinner(void *a){ uintptr_t k=(uintptr_t)a; uint64_t x=k*77+1; while(!stop_spin){ for(int i=0;i<4096;i++){ x=x*6364136223846793005ULL+1442695040888963407ULL; spinbuf[(x>>20)&0x3FFFFFF]++; } } return 0; }
#else
static void *spinner(void *a){ uintptr_t k=(uintptr_t)a; uint64_t x=k*77+1; while(!stop_spin){ for(int i=0;i<4096;i++){ x=x*6364136223846793005ULL+1442695040888963407ULL; spinbuf[(x>>20)&0x3FFFFFF]++; } } return 0; }
#endif

static uint8_t *alloc_page(uintptr_t fixed){
#ifdef _WIN32
  return VirtualAlloc((void*)fixed,0x1000,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
#else
  int fl=MAP_PRIVATE|MAP_ANON|(fixed?MAP_FIXED:0);
  void *p=mmap((void*)fixed,0x1000,PROT_READ|PROT_WRITE|PROT_EXEC,fl,-1,0); return p==MAP_FAILED?NULL:p;
#endif
}
static void free_page(uint8_t *p){
#ifdef _WIN32
  VirtualFree(p,0,MEM_RELEASE);
#else
  munmap(p,0x1000);
#endif
}

int main(int argc,char**argv){
  long n=100000; int reinit=1, spin=0, flush=0, fresh=0; uintptr_t fixed=0; const char *name="A";
  for(int i=1;i<argc;i++){
    if(!strcmp(argv[i],"-n")) n=atol(argv[++i]); else if(!strcmp(argv[i],"-reinit")) reinit=atoi(argv[++i]);
    else if(!strcmp(argv[i],"-spin")) spin=atoi(argv[++i]); else if(!strcmp(argv[i],"-flush")) flush=1;
    else if(!strcmp(argv[i],"-fresh")) fresh=1; else if(!strcmp(argv[i],"-tf")) g_tf=1; else if(!strcmp(argv[i],"-guard")) g_guard=1; else if(!strcmp(argv[i],"-wx")) g_wx=1; else if(!strcmp(argv[i],"-fixed")) fixed=0x1B30000; else if(!strcmp(argv[i],"-name")) name=argv[++i]; }
  for(int r=0;r<11;r++){ char *s=(char*)rows[r]; for(int c=0;c<32;c++){ tmpl[TMPL_OFF+r*32+c]=(uint8_t)strtoul(s,&s,16); } }
  tmpl[STORE_OFF]=0; tmpl[STORE_OFF+1]=0;
#ifdef _WIN32
  AddVectoredExceptionHandler(1,veh);
#else
  struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_sigaction=sh; sa.sa_flags=SA_SIGINFO|SA_NODEFER; sigemptyset(&sa.sa_mask);
  sigaction(SIGSEGV,&sa,0); sigaction(SIGBUS,&sa,0); sigaction(SIGILL,&sa,0); sigaction(SIGTRAP,&sa,0);
#endif
  if(spin){ spinbuf=calloc(1,0x4000000);
    for(int i=0;i<spin;i++){
#ifdef _WIN32
      CreateThread(0,0,spinner,(void*)(uintptr_t)i,0,0);
#else
      pthread_t t; pthread_create(&t,0,spinner,(void*)(uintptr_t)i);
#endif
    } }
  uint8_t *page=alloc_page(fixed);
  if(!page){ printf("%s: alloc failed\n",name); return 2; }
  g_guardpage=page; if(g_guard) set_exec(0); if(g_wx) set_prot3(2);
  long ok=0,bad=0; struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
  for(long k=0;k<n;k++){
    if(fresh && k){ free_page(page); page=alloc_page(fixed); if(!page){ printf("realloc failed at %ld\n",k); break; } g_guardpage=page; if(g_guard) set_exec(0); if(g_wx) set_prot3(2); }
    if(reinit||k==0||fresh){ if(g_wx) set_prot3(1); memcpy(page+TMPL_OFF,tmpl+TMPL_OFF,0x160); if(g_wx) set_prot3(2); }
    if(flush){
#ifdef _WIN32
      FlushInstructionCache(GetCurrentProcess(),page,0x1000);
#else
      __builtin___clear_cache((char*)page,(char*)page+0x1000);
#endif
    }
    g_entry=page+ENTRY_OFF;
    if(run_stub()) bad++; else ok++;
  }
  clock_gettime(CLOCK_MONOTONIC,&t1); double us=((t1.tv_sec-t0.tv_sec)*1e9+(t1.tv_nsec-t0.tv_nsec))/1e3/(double)(ok+bad);
  stop_spin=1;
  printf("RESULT %s n=%ld ok=%ld fault=%ld steps=%ld genter=%ld gleave=%ld wxf=%ld us_per_round=%.2f page=%p base_offset_rips:",name,ok+bad,ok,bad,stepcount,guard_enter,guard_leave,wx_faults,us,(void*)page);
  for(int i=0;i<nrip;i++) printf(" %#lx(off %#lx)x%ld",(unsigned long)rip_val[i],(unsigned long)((rip_val[i])-(uintptr_t)page),rip_cnt[i]);
  printf("\n"); fflush(stdout); return 0; }
