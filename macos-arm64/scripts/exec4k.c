// exec4k <program> [args...]
// Unentitled launcher: replaces itself (POSIX_SPAWN_SETEXEC) with <program> created with a 4 KiB page size.
// <program> must be the main executable of the signed winehost bundle (or a symlink to it); the 4K attribute is
// refused (EBADMACHO, rc 88) for any binary that does not carry com.apple.developer.cross-architecture-support.
#include <stdio.h>
#include <string.h>
#include <spawn.h>

extern char **environ;

int main(int argc, char **argv)
{
    posix_spawnattr_t attr;
    int ret;

    if (argc < 2) { fprintf(stderr, "usage: exec4k program [args...]\n"); return 2; }
    posix_spawnattr_init(&attr);
    posix_spawnattr_set_4k_page_size_np(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
    ret = posix_spawn(NULL, argv[1], NULL, &attr, argv + 1, environ);
    fprintf(stderr, "exec4k: posix_spawn(%s) failed: rc=%d (%s)\n", argv[1], ret, strerror(ret));
    return 1;
}
