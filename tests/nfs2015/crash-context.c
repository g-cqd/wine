/*
 * Fixture for the "wine-crash:" register dump printed by UnhandledExceptionFilter.
 *
 * Build:  x86_64-w64-mingw32-gcc -O1 -o crash-context.exe crash-context.c
 * Run:    crash-context-check.sh /path/to/wine crash-context.exe
 *
 * With no argument the program starts itself with "fault" and waits.  The child loads
 * known values into the integer registers and stores through a non-canonical pointer,
 * the fault seen on NFS16.exe.  The dump goes to Wine's stderr, not to a Windows
 * handle, so the check is done by the script on the Wine log; this program only
 * reports the child's exit status.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static void __attribute__((noreturn)) fault( void )
{
    __asm__ volatile(
        "movabs $0x1111111111111111,%%rax\n\t"
        "movabs $0x2222222222222222,%%rbx\n\t"
        "movabs $0x3333333333333333,%%rdx\n\t"
        "movabs $0x4444444444444444,%%rsi\n\t"
        "movabs $0x5555555555555555,%%rdi\n\t"
        "movabs $0x0808080808080808,%%r8\n\t"
        "movabs $0x0909090909090909,%%r9\n\t"
        "movabs $0x1010101010101010,%%r10\n\t"
        "movabs $0x1111000011110000,%%r11\n\t"
        "movabs $0x1212121212121212,%%r12\n\t"
        "movabs $0x1313131313131313,%%r13\n\t"
        "movabs $0x1414141414141414,%%r14\n\t"
        "movabs $0x1515151515151515,%%r15\n\t"
        "movabs $0x85bc35850173ff31,%%rcx\n\t"
        "movq %%rax,(%%rcx)\n\t"
        ::: "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "memory" );
    __builtin_unreachable();
}

int main( int argc, char **argv )
{
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH + 16];
    DWORD status = 0;

    if (argc > 1 && !strcmp( argv[1], "fault" )) fault();

    snprintf( cmd, sizeof(cmd), "\"%s\" fault", argv[0] );
    if (!CreateProcessA( NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi ))
    {
        printf( "FAIL CreateProcess %lu\n", GetLastError() );
        return 1;
    }
    WaitForSingleObject( pi.hProcess, INFINITE );
    GetExitCodeProcess( pi.hProcess, &status );
    printf( "child exit status %08lx\n", status );
    return 0;
}
