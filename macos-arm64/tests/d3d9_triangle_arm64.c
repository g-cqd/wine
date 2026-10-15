/* arm64 PE, ON-SCREEN D3D9 test (do not run without the owner's agreement): opens a 320x240 window, creates a D3D9 device
 * (mtld3d -> Metal), draws a red/green/blue gradient triangle on a dark blue background for ~5 s, prints status, exits.
 * build: aarch64-w64-mingw32-clang -O1 -nostdlib -Wl,--entry,start -o d3d9_triangle_arm64.exe d3d9_triangle_arm64.c \
 *        -lkernel32 -luser32 -lgdi32 -ld3d9 */
#define COBJMACROS
#include <windows.h>
#include <d3d9.h>

static void say(const char *s) { DWORD n; WriteFile( GetStdHandle(STD_OUTPUT_HANDLE), s, lstrlenA(s), &n, NULL ); }
static void hex(const char *label, ULONG_PTR v)
{
    char b[32]; int i;
    b[0] = '0'; b[1] = 'x';
    for (i = 0; i < 16; i++) b[2 + i] = "0123456789abcdef"[(v >> (60 - 4 * i)) & 15];
    b[18] = 0; say( label ); say( b ); say( "\r\n" );
}
static LRESULT CALLBACK wndproc( HWND h, UINT m, WPARAM w, LPARAM l )
{
    if (m == WM_DESTROY) { PostQuitMessage( 0 ); return 0; }
    return DefWindowProcA( h, m, w, l );
}

struct vertex { float x, y, z, rhw; DWORD color; };

void start(void)
{
    WNDCLASSA wc = { 0 };
    HWND hwnd;
    IDirect3D9 *d3d;
    IDirect3DDevice9 *dev = NULL;
    D3DPRESENT_PARAMETERS pp = { 0 };
    static const struct vertex tri[3] = {
        { 160.0f,  40.0f, 0.5f, 1.0f, 0xffff0000 },
        { 260.0f, 200.0f, 0.5f, 1.0f, 0xff00ff00 },
        {  60.0f, 200.0f, 0.5f, 1.0f, 0xff0000ff },
    };
    DWORD t0, frames = 0;
    HRESULT hr;

    wc.lpfnWndProc = wndproc; wc.hInstance = GetModuleHandleA( NULL ); wc.lpszClassName = "mtld3d_tri";
    RegisterClassA( &wc );
    hwnd = CreateWindowA( "mtld3d_tri", "mtld3d triangle", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 336, 279, NULL, NULL, wc.hInstance, NULL );
    if (!hwnd) { say( "FAIL CreateWindow\r\n" ); ExitProcess( 1 ); }

    d3d = Direct3DCreate9( D3D_SDK_VERSION );
    hex( "Direct3DCreate9 -> ", (ULONG_PTR)d3d );
    if (!d3d) ExitProcess( 2 );
    pp.Windowed = TRUE; pp.SwapEffect = D3DSWAPEFFECT_DISCARD; pp.BackBufferFormat = D3DFMT_UNKNOWN;
    pp.BackBufferWidth = 320; pp.BackBufferHeight = 240; pp.hDeviceWindow = hwnd;
    hr = IDirect3D9_CreateDevice( d3d, D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &dev );
    hex( "CreateDevice hr = ", (ULONG_PTR)(ULONG)hr );
    if (FAILED( hr )) ExitProcess( 3 );

    t0 = GetTickCount();
    while (GetTickCount() - t0 < 5000)
    {
        MSG msg;
        while (PeekMessageA( &msg, NULL, 0, 0, PM_REMOVE )) { TranslateMessage( &msg ); DispatchMessageA( &msg ); }
        IDirect3DDevice9_Clear( dev, 0, NULL, D3DCLEAR_TARGET, 0xff102040, 1.0f, 0 );
        IDirect3DDevice9_BeginScene( dev );
        IDirect3DDevice9_SetRenderState( dev, D3DRS_LIGHTING, FALSE );
        IDirect3DDevice9_SetRenderState( dev, D3DRS_CULLMODE, D3DCULL_NONE );
        IDirect3DDevice9_SetFVF( dev, D3DFVF_XYZRHW | D3DFVF_DIFFUSE );
        IDirect3DDevice9_DrawPrimitiveUP( dev, D3DPT_TRIANGLELIST, 1, tri, sizeof(tri[0]) );
        IDirect3DDevice9_EndScene( dev );
        hr = IDirect3DDevice9_Present( dev, NULL, NULL, NULL, NULL );
        if (FAILED( hr )) { hex( "Present hr = ", (ULONG_PTR)(ULONG)hr ); break; }
        frames++;
    }
    hex( "frames presented = ", frames );
    IDirect3DDevice9_Release( dev ); IDirect3D9_Release( d3d ); DestroyWindow( hwnd );
    ExitProcess( 0 );
}
