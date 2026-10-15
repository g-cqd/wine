/* arm64 PE console test: WriteFile + ExitProcess, no CRT. Build:
 *   aarch64-w64-mingw32-clang -O1 -nostdlib -Wl,--entry,start -o hello_arm64.exe hello_arm64.c -lkernel32 */
#include <windows.h>

void start(void)
{
    static const char msg[] = "hello from arm64 PE on native arm64 Wine\r\n";
    DWORD written = 0;
    HANDLE out = GetStdHandle( STD_OUTPUT_HANDLE );
    WriteFile( out, msg, sizeof(msg) - 1, &written, NULL );
    ExitProcess( written == sizeof(msg) - 1 ? 0 : 1 );
}
