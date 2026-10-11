/*
 * MACDRV Cocoa window declarations
 *
 * Copyright 2011, 2012, 2013 Ken Thomases for CodeWeavers Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#import <AppKit/AppKit.h>
#import <QuartzCore/QuartzCore.h>


@class WineEventQueue;


@interface WineWindow : NSPanel <NSWindowDelegate>
{
    BOOL disabled;
    BOOL noForeground;
    BOOL preventsAppActivation;
    BOOL floating;
    BOOL resizable;
    BOOL maximized;
    BOOL fullscreen;
    BOOL pendingMinimize;
    BOOL pendingOrderOut;
    BOOL savedVisibleState;
    BOOL drawnSinceShown;
    BOOL closing;
    WineWindow* latentParentWindow;
    NSMutableArray* latentChildWindows;

    void* hwnd;
    WineEventQueue* queue;

    CGDirectDisplayID _lastDisplayID;
    NSTimeInterval _lastDisplayTime;

    NSRect wineFrame;
    NSRect roundedWineFrame;

    BOOL shapeChangedSinceLastDraw;

    BOOL usePerPixelAlpha;

    NSUInteger lastModifierFlags;

    NSRect frameAtResizeStart;
    BOOL resizingFromLeft, resizingFromTop;

    void* himc;
    BOOL commandDone;

    NSSize savedContentMinSize;
    NSSize savedContentMaxSize;

    BOOL enteringFullScreen;
    BOOL exitingFullScreen;
    NSRect nonFullscreenFrame;
    NSTimeInterval enteredFullScreenTime;

    int draggingPhase;
    NSPoint dragStartPosition;
    NSPoint dragWindowStartPosition;

    NSTimeInterval lastDockIconSnapshot;

    BOOL allowKeyRepeats;

    BOOL ignore_windowDeminiaturize;
    BOOL ignore_windowResize;
    BOOL fakingClose;

    CAShapeLayer* contentViewMaskLayer;

    /* Native full-screen space for a window covering its monitor
       (FullscreenMode=native).  While the window is in that space, its Cocoa
       frame is the one AppKit chose, which on a display with a camera housing
       is shorter than the screen; Windows keeps the frame it set, held in
       fullScreenWineFrame, and the content is scaled to fit. */
    BOOL wantsNativeFullScreen;       /* Win32 asked for the space */
    BOOL inAutoFullScreen;            /* we entered the space for Win32 */
    BOOL suppressAutoFullScreen;      /* the user left it; don't re-enter */
    NSRect fullScreenWineFrame;       /* frame Win32 set, Cocoa coordinates */
    NSRect fullScreenSourceRect;      /* mask rect in content coordinates, or empty */
}

@property (retain, readonly, nonatomic) WineEventQueue* queue;
@property (readonly, nonatomic) BOOL disabled;
@property (readonly, nonatomic) BOOL noForeground;
@property (readonly, nonatomic) BOOL preventsAppActivation;
@property (readonly, nonatomic) BOOL floating;
@property (readonly, getter=isFullscreen, nonatomic) BOOL fullscreen;
@property (readonly, getter=isFakingClose, nonatomic) BOOL fakingClose;
/* Set on the main thread when the window is being destroyed. From then on
   the references that events and queries hold may be the last ones. */
@property (readonly, nonatomic) BOOL closing;
@property (readonly, nonatomic) NSRect wine_fractionalFrame;

/* Whether this window, when ordered in and not miniaturized, would appear to
   the user on-screen. That means it has a non-zero size and is not empty-
   shaped, or has a child window that meets those criteria. */
@property (readonly, nonatomic) BOOL presentsVisibleContent;

    - (NSInteger) minimumLevelForActive:(BOOL)active;
    - (void) updateFullscreen;
    - (BOOL) coversMenuBarScreen;

    - (void) postKeyEvent:(NSEvent *)theEvent;
    - (void) postBroughtForwardEvent;

    - (WineWindow*) ancestorWineWindow;

    - (void) updateForCursorClipping;

    - (void) setRetinaMode:(BOOL)mode;

    /* Mapping of global points (Quartz coordinates: top-left origin, in
       points) between where the content shows on screen and where Win32
       placed it, while the window is scaled in a native full-screen space. */
    - (BOOL) isScaledInFullScreen;
    - (CGPoint) winePointFromScreenPoint:(CGPoint)point;
    - (CGPoint) screenPointFromWinePoint:(CGPoint)point;
    - (CGFloat) wineUnitsPerScreenUnit;

@end
