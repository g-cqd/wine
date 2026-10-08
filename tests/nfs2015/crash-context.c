/*
 * Fixture for the "wine-crash:" register dump printed by UnhandledExceptionFilter.
 *
 * Build:  x86_64-w64-mingw32-gcc -O1 -o crash-context.exe crash-context.c
 * Run:    crash-context-check.sh /path/to/wine crash-context.exe        (register values)
 *         crash-context-check.sh /path/to/wine crash-context.exe page   (junk executable page, page/code rows)
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

/* Executable private page whose code is junk, the shape of the NFS16 fault: jump into the middle of it. */
static void __attribute__((noreturn)) page_fault( void )
{
    static const unsigned char junk[16] = { 0xa2, 0x31, 0xff, 0x73, 0x01, 0x85, 0x35, 0xbc,
                                            0x85, 0xe8, 0xac, 0x52, 0x48, 0x8d, 0x15, 0xba };
    unsigned char *page = VirtualAlloc( NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    unsigned long long hash = 0xcbf29ce484222325ull;
    unsigned int i;

    for (i = 0; i < 0x1000; i++) page[i] = (i % 16 == 0 || i % 7 == 0) ? 0 : (unsigned char)(i * 31 + 7);
    memcpy( page + 0x159, junk, sizeof(junk) );
    for (i = 0; i < 0x1000; i++) hash = (hash ^ page[i]) * 0x100000001b3ull;
    printf( "expect page=%p fnv1a64=%016llx pc=%p\n", page, hash, page + 0x159 );
    fflush( stdout );
    __asm__ volatile( "movq %0,%%r12\n\tjmp *%1\n\t" :: "r"(page + 0xe3), "r"(page + 0x159) : "r12" );
    __builtin_unreachable();
}

int main( int argc, char **argv )
{
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH + 16];
    DWORD status = 0;

    if (argc > 1 && !strcmp( argv[1], "fault" )) fault();
    if (argc > 1 && !strcmp( argv[1], "pagefault" )) page_fault();

    snprintf( cmd, sizeof(cmd), "\"%s\" %s", argv[0], argc > 1 && !strcmp( argv[1], "page" ) ? "pagefault" : "fault" );
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
