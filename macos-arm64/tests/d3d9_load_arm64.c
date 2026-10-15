/* arm64 PE, console only: LoadLibraryW(d3d9.dll) + GetProcAddress(Direct3DCreate9). No device, no window.
 * build: aarch64-w64-mingw32-clang -O1 -nostdlib -Wl,--entry,start -o d3d9_load_arm64.exe d3d9_load_arm64.c -lkernel32 */
#include <windows.h>

static const char *StrStrA_( const char *h, const char *n )
{
    for (; *h; h++) { const char *a = h, *b = n; while (*a && *b && *a == *b) a++, b++; if (!*b) return h; }
    return 0;
}

static void say(const char *s) { DWORD n; WriteFile( GetStdHandle(STD_OUTPUT_HANDLE), s, lstrlenA(s), &n, NULL ); }
static void hex(const char *label, ULONG_PTR v)
{
    char b[32]; int i;
    b[0] = '0'; b[1] = 'x';
    for (i = 0; i < 16; i++) b[2 + i] = "0123456789abcdef"[(v >> (60 - 4 * i)) & 15];
    b[18] = 0; say( label ); say( b ); say( "\r\n" );
}

void start(void)
{
    WCHAR path[MAX_PATH];
    HMODULE m = LoadLibraryW( L"d3d9.dll" );
    FARPROC p;
    if (!m) { hex( "FAIL LoadLibrary d3d9.dll, GetLastError = ", GetLastError() ); ExitProcess( 1 ); }
    hex( "d3d9.dll base          = ", (ULONG_PTR)m );
    if (GetModuleFileNameW( m, path, MAX_PATH ))
    {
        char a[MAX_PATH]; int i;
        for (i = 0; path[i] && i < MAX_PATH - 1; i++) a[i] = (char)path[i];
        a[i] = 0; say( "d3d9.dll path          = " ); say( a ); say( "\r\n" );
    }
    p = GetProcAddress( m, "Direct3DCreate9" );
    hex( "Direct3DCreate9        = ", (ULONG_PTR)p );
    hex( "mtld3d.dll base        = ", (ULONG_PTR)GetModuleHandleW( L"mtld3d.dll" ) );
    if (StrStrA_( GetCommandLineA(), "wait" )) Sleep( 6000 );   /* lets an outside tool (vmmap) inspect the process */
    ExitProcess( p ? 0 : 2 );
}
