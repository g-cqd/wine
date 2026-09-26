# Stationary cursor recovery on macOS

Based on athei/wine d82e36650b034b7ba63eb671c672c578c88e282f, the runtime used by athei/wine-build.

The macOS driver refreshes the window beneath a stationary cursor when Wine becomes active, posts its position to the Windows client and reapplies cursor visibility. Repeated hide/show requests no longer rely only on cached visibility. No timer or frame polling is added.

The synthetic Win32 reproduction is included. Build cursor_window.c with an i686 Windows C compiler and run it in a disposable prefix. Compare screenshots with and without the cursor plane while switching focus without moving the pointer. Verify initial hidden focus, three focus returns, a visible-cursor request, hiding again, leaving the window and returning.

On Apple M1, macOS 27 beta, the original module failed stationary focus and return from outside. The patched module passed ten visibility/focus cases. Three additional game focus returns kept the native cursor hidden. The driver built and loaded; existing upstream compiler warnings remain. The full Wine suite and other macOS releases were not tested. No game data is included.
