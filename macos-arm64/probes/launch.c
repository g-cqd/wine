// launch [plain|4k] path [args...]  -- unentitled launcher; prints spawn rc and child status.
#include <stdio.h>
#include <string.h>
#include <spawn.h>
#include <sys/wait.h>
extern char **environ;
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    posix_spawnattr_t at; posix_spawnattr_init(&at);
    if (!strcmp(argv[1], "4k")) posix_spawnattr_set_4k_page_size_np(&at);
    pid_t pid = 0; fflush(stdout);
    int r = posix_spawn(&pid, argv[2], NULL, &at, argv + 2, environ);
    if (r) { printf("spawn[%s] rc=%d (%s)\n", argv[1], r, strerror(r)); return 1; }
    int st = 0; waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) printf("spawn[%s] child killed by signal %d\n", argv[1], WTERMSIG(st));
    else printf("spawn[%s] child exit=%d\n", argv[1], WEXITSTATUS(st));
    return 0;
}
