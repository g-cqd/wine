#include <windows.h>
#include <stdio.h>
#include <string.h>
static const char klass[] = "NFSMWCursorProbe";
static int hidden = 1;
static void report(void) {
    CURSORINFO ci = {sizeof(ci), 0, NULL, {0,0}};
    if (!GetCursorInfo(&ci)) fprintf(stderr, "GetCursorInfo failed: %lu\n", GetLastError());
    else printf("hidden_requested=%d flags=%lu cursor=%p foreground=%d\n", hidden, ci.flags, (void*)ci.hCursor, GetForegroundWindow()==FindWindowA(klass,NULL));
    fflush(stdout);
}
static LRESULT CALLBACK procedure(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m==WM_SETCURSOR && LOWORD(l)==HTCLIENT) { SetCursor(hidden ? NULL : LoadCursorA(NULL,IDC_ARROW)); return TRUE; }
    if (m==WM_APP+1) { hidden=(w==0); SetCursor(hidden ? NULL : LoadCursorA(NULL,IDC_ARROW)); report(); return 1; }
    if (m==WM_APP+3) { POINT pt={400,300}; if (w) { pt.x=10; pt.y=200; } else if (!ClientToScreen(h,&pt)) return 0; return SetCursorPos(pt.x,pt.y); }
    if (m==WM_APP+2) { report(); return 1; }
    if (m==WM_CLOSE) { DestroyWindow(h); return 0; }
    if (m==WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcA(h,m,w,l);
}
int main(int argc, char **argv) {
    if (argc==2) {
        HWND h=FindWindowA(klass,NULL); DWORD_PTR reply;
        if (!h) return 2;
        UINT message=WM_APP+1; WPARAM w=0;
        if (!strcmp(argv[1],"show")) w=1;
        else if (!strcmp(argv[1],"hide")) w=0;
        else if (!strcmp(argv[1],"inside")) message=WM_APP+3;
        else if (!strcmp(argv[1],"outside")) { message=WM_APP+3; w=1; }
        else if (!strcmp(argv[1],"state")) message=WM_APP+2;
        else if (!strcmp(argv[1],"quit")) message=WM_CLOSE;
        else return 3;
        return SendMessageTimeoutA(h,message,w,0,SMTO_ABORTIFHUNG,2000,&reply)?0:4;
    }
    WNDCLASSA wc={0}; wc.lpfnWndProc=procedure; wc.hInstance=GetModuleHandleA(NULL); wc.lpszClassName=klass;
    wc.hbrBackground=CreateSolidBrush(RGB(32,48,80));
    if (!wc.hbrBackground || !RegisterClassA(&wc)) return 5;
    HWND h=CreateWindowExA(0,klass,"Native cursor recovery probe",WS_OVERLAPPEDWINDOW,200,150,1000,750,NULL,NULL,wc.hInstance,NULL);
    if (!h) return 6;
    SetCursor(NULL); ShowWindow(h,SW_SHOW); SetForegroundWindow(h); UpdateWindow(h); report();
    MSG m; int result;
    while ((result=GetMessageA(&m,NULL,0,0))>0) { TranslateMessage(&m); DispatchMessageA(&m); }
    DeleteObject(wc.hbrBackground);
    return result<0?7:0;
}
