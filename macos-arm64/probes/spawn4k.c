// Probe (c): 4K page size across posix_spawn / POSIX_SPAWN_SETEXEC / execve / fork+exec. Entitled arm64 binary with multiple modes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
#include <mach/mach.h>
extern char **environ;
static void report(const char *tag) {
    task_vm_info_data_t i; mach_msg_type_number_t n = TASK_VM_INFO_COUNT; int ps = -1; unsigned long long mn = 0;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&i, &n) == KERN_SUCCESS) { ps = i.page_size; mn = i.min_address; }
    printf("[%s pid %d] getpagesize=%d vm_page_size=%lu task page_size=%d min_address=0x%llx\n", tag, getpid(), getpagesize(), (unsigned long)vm_page_size, ps, mn);
    fflush(stdout);
}
static int sp(const char *path, char **args, int attr4k, int setexec) {
    posix_spawnattr_t at; posix_spawnattr_init(&at);
    if (attr4k) posix_spawnattr_set_4k_page_size_np(&at);
    if (setexec) posix_spawnattr_setflags(&at, POSIX_SPAWN_SETEXEC);
    pid_t pid; fflush(stdout);
    int r = posix_spawn(&pid, path, NULL, &at, args, environ);
    if (r) { printf("  posix_spawn(%s, 4k=%d, setexec=%d) rc=%d (%s)\n", path, attr4k, setexec, r, strerror(r)); fflush(stdout); return r; }
    int st; waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) printf("  child killed by signal %d\n", WTERMSIG(st)); else printf("  child exit %d\n", WEXITSTATUS(st));
    fflush(stdout); return 0;
}
int main(int argc, char **argv) {
    const char *self = argv[0]; const char *m = argc > 1 ? argv[1] : "report";
    if (!strcmp(m, "report")) { report(argc > 2 ? argv[2] : "report"); return 0; }
    report("parent");
    char *rep[] = { (char *)self, "report", "child", NULL };
    if (!strcmp(m, "exec_attr"))   { char *a[] = { (char *)self, "report", "SETEXEC+4k-attr", NULL }; int r = sp(self, a, 1, 1); printf("  setexec failed rc=%d\n", r); return 1; }
    if (!strcmp(m, "exec_plain"))  { char *a[] = { (char *)self, "report", "SETEXEC-no-attr", NULL };  int r = sp(self, a, 0, 1); printf("  setexec failed rc=%d\n", r); return 1; }
    if (!strcmp(m, "execve"))      { char *a[] = { (char *)self, "report", "execve", NULL }; execve(self, a, environ); printf("  execve failed %s\n", strerror(errno)); return 1; }
    if (!strcmp(m, "spawn_attr"))  { rep[2] = "spawn+4k-attr";  return sp(self, rep, 1, 0); }
    if (!strcmp(m, "spawn_plain")) { rep[2] = "spawn-no-attr";  return sp(self, rep, 0, 0); }
    if (!strcmp(m, "forkexec"))    { fflush(stdout); pid_t p = fork(); if (p == 0) { rep[2] = "fork+execve"; execve(self, rep, environ); _exit(99); } int st; waitpid(p, &st, 0); printf("  forkexec child status %d\n", WEXITSTATUS(st)); return 0; }
    if (!strcmp(m, "sys_plain"))   { char *a[] = { "/usr/bin/pagesize", NULL }; printf("  system binary /usr/bin/pagesize, no attr:\n"); fflush(stdout); return sp("/usr/bin/pagesize", a, 0, 0); }
    if (!strcmp(m, "sys_attr"))    { char *a[] = { "/usr/bin/pagesize", NULL }; printf("  system binary /usr/bin/pagesize, 4k attr:\n"); fflush(stdout); return sp("/usr/bin/pagesize", a, 1, 0); }
    if (!strcmp(m, "exec_sys"))    { char *a[] = { "/usr/bin/pagesize", NULL }; printf("  SETEXEC (no attr) of system /usr/bin/pagesize:\n"); fflush(stdout); int r = sp("/usr/bin/pagesize", a, 0, 1); printf("  rc=%d\n", r); return 1; }
    return 2;
}
