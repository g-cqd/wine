/* arm64 PE: PAGE_EXECUTE_READWRITE policy test (native arm64 code).
 * build: aarch64-w64-mingw32-clang -O1 -nostdlib -Wl,--entry,start -o rwx_arm64.exe rwx_arm64.c -lkernel32 */
#include <windows.h>

static void say(const char *s) { DWORD n; WriteFile( GetStdHandle(STD_OUTPUT_HANDLE), s, lstrlenA(s), &n, NULL ); }

void start(void)
{
    static const DWORD code42[] = { 0xd2800540 /* mov x0,#42 */, 0xd65f03c0 /* ret */ };
    static const DWORD code43[] = { 0xd2800560 /* mov x0,#43 */, 0xd65f03c0 };
    DWORD *p, old;
    int r, fail = 0;
    HANDLE heap;

    p = VirtualAlloc( NULL, 0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    if (!p) { say( "FAIL VirtualAlloc RWX\r\n" ); ExitProcess( 1 ); }
    p[0] = code42[0]; p[1] = code42[1];
    r = ((int (*)(void))p)();
    say( r == 42 ? "ok exec#1 =42\r\n" : "FAIL exec#1\r\n" ); fail |= r != 42;
    p[0] = code43[0];                                  /* write after execute: back to RW */
    r = ((int (*)(void))p)();
    say( r == 43 ? "ok exec#2 =43 (rewrite after exec)\r\n" : "FAIL exec#2\r\n" ); fail |= r != 43;
    VirtualQuery( p, &(MEMORY_BASIC_INFORMATION){0}, sizeof(MEMORY_BASIC_INFORMATION) );
    {
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery( p, &mbi, sizeof(mbi) );
        say( mbi.Protect == PAGE_EXECUTE_READWRITE ? "ok VirtualQuery reports PAGE_EXECUTE_READWRITE\r\n" : "FAIL VirtualQuery protect\r\n" );
        fail |= mbi.Protect != PAGE_EXECUTE_READWRITE;
    }
    /* RW -> VirtualProtect(RWX) */
    VirtualFree( p, 0, MEM_RELEASE );
    p = VirtualAlloc( NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    p[0] = code42[0]; p[1] = code42[1];
    if (!VirtualProtect( p, 0x1000, PAGE_EXECUTE_READWRITE, &old )) { say( "FAIL VirtualProtect RWX\r\n" ); fail = 1; }
    else { r = ((int (*)(void))p)(); say( r == 42 ? "ok VirtualProtect(RW->RWX) exec\r\n" : "FAIL VirtualProtect exec\r\n" ); fail |= r != 42; }
    /* executable heap */
    heap = HeapCreate( HEAP_CREATE_ENABLE_EXECUTE, 0, 0 );
    say( heap ? "ok HeapCreate(ENABLE_EXECUTE)\r\n" : "FAIL HeapCreate(ENABLE_EXECUTE)\r\n" ); fail |= !heap;
    ExitProcess( fail );
}
