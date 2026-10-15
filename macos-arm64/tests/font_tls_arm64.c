/* arm64 PE: FreeType (GetTextExtentPoint32W with a TrueType/bitmap font) and GnuTLS (SChannel credentials).
 * build: aarch64-w64-mingw32-clang -O1 -nostdlib -Wl,--entry,start -o font_tls_arm64.exe font_tls_arm64.c -lkernel32 -lgdi32 -lsecur32 -luser32 */
#define SECURITY_WIN32
#include <windows.h>
#include <schannel.h>
#include <security.h>

static void say(const char *s) { DWORD n; WriteFile( GetStdHandle(STD_OUTPUT_HANDLE), s, lstrlenA(s), &n, NULL ); }
static void num(const char *label, long v)
{
    char b[64]; int i = 62; unsigned long u = v < 0 ? -v : v;
    b[63] = 0; do { b[i--] = '0' + u % 10; u /= 10; } while (u);
    if (v < 0) b[i--] = '-';
    say( label ); say( b + i + 1 ); say( "\r\n" );
}

void start(void)
{
    int fail = 0;
    HDC dc = CreateCompatibleDC( NULL );
    LOGFONTW lf = { 0 };
    HFONT font, old;
    SIZE sz = { 0 };
    TEXTMETRICW tm;
    WCHAR text[] = L"Hello, Wine arm64";
    SCHANNEL_CRED cred = { 0 };
    CredHandle ch;
    TimeStamp ts;
    SECURITY_STATUS ss;
    WCHAR face[LF_FACESIZE] = { 0 };

    lf.lfHeight = -24; lf.lfWeight = FW_NORMAL; lf.lfCharSet = DEFAULT_CHARSET;
    lstrcpyW( lf.lfFaceName, L"Tahoma" );
    font = CreateFontIndirectW( &lf );
    old = SelectObject( dc, font );
    GetTextExtentPoint32W( dc, text, lstrlenW( text ), &sz );
    GetTextMetricsW( dc, &tm );
    GetTextFaceW( dc, LF_FACESIZE, face );
    num( "text width  = ", sz.cx ); num( "text height = ", sz.cy ); num( "tm.tmHeight = ", tm.tmHeight );
    /* a scalable font through FreeType gives a width well above the 8x16 fallback of 17 chars * 8 = 136 only if hinting differs;
     * the discriminator is the face name: without FreeType Wine has no fonts and falls back to a stub */
    say( "face = " ); { char a[LF_FACESIZE]; int i; for (i = 0; face[i]; i++) a[i] = (char)face[i]; a[i] = 0; say( a ); say( "\r\n" ); }
    if (sz.cx <= 0 || sz.cy <= 0) fail |= 1;
    SelectObject( dc, old ); DeleteObject( font ); DeleteDC( dc );

    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
    ss = AcquireCredentialsHandleW( NULL, (WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &ch, &ts );
    num( "AcquireCredentialsHandle(SChannel) status (0=SEC_E_OK) = ", ss );
    if (ss == SEC_E_OK) FreeCredentialsHandle( &ch ); else fail |= 2;
    ExitProcess( fail );
}
