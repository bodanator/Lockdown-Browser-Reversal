// =============================================================================
//  LockDown Browser — Input Lockdown DLL Pseudocode
//  Reverse engineered from LockDownBrowser.dll
//  SHA256: 2a5c10...4f7951
//  PE x86_64, 118,720 bytes (~116 KB), 473 procedures, 302 strings
//
//  Exhaustive analysis of all procedures and strings.
//  This DLL contains ZERO VM detection logic. It is exclusively a
//  keyboard/mouse input hooking companion DLL.
//
//  Imports: USER32.DLL (SetWindowsHookExA, UnhookWindowsHookEx,
//           CallNextHookEx, GetAsyncKeyState, SendInput)
//           KERNEL32.DLL (standard CRT functions)
//
//  Custom PE sections:
//    .cldb    (512 bytes) — hook handle storage (3x HHOOK)
//    .fptable (512 bytes) — UCRT delayed function pointer cache
// =============================================================================

#include <windows.h>

#pragma data_seg(".cldb")
static HHOOK g_hKeyboardHook = NULL;   // DAT_18001c000
static HHOOK g_hCBTHook      = NULL;   // DAT_18001c008
static HHOOK g_hShellHook    = NULL;   // DAT_18001c010
#pragma data_seg()


// =============================================================================
//  EXPORT 1: CLDBDoSomeStuff
//  Address: 0x180001110
//
//  Main entry point. Installs WH_KEYBOARD_LL + WH_SHELL + WH_CBT hooks.
//  Caller passes a bitmask selecting keyboard/mouse blocking aggressiveness.
//
//  Bit flags:
//    0x40   — Enable hooks (vs disable/cleanup)
//    0x80   — Mouse hook variant selection
//    0x100  — Win-key suppression mode
//    0x200  — Aggressive mode
//    0x2000 — Right-click blocking CBT
//    0x4000 — Injected-key blocking (bit 0xE)
//    0x8000 — Most-restrictive mode (bit 0xF)
// =============================================================================

extern "C" __declspec(dllexport)
void CLDBDoSomeStuff(DWORD flags) {
    if (!(flags & 0x40)) {
        // Disable mode — unhook everything
        if (g_hKeyboardHook) UnhookWindowsHookEx(g_hKeyboardHook);
        if (g_hCBTHook)      UnhookWindowsHookEx(g_hCBTHook);
        if (g_hShellHook)    UnhookWindowsHookEx(g_hShellHook);
        g_hKeyboardHook = g_hCBTHook = g_hShellHook = NULL;
        return;
    }

    // Select keyboard callback based on aggressiveness bits
    HOOKPROC kbCallback;
    if (flags & 0x8000)      kbCallback = KeyboardHook_MostRestrictive;
    else if (flags & 0x4000) kbCallback = KeyboardHook_InjectedBlocking;
    else if (flags & 0x200)  kbCallback = KeyboardHook_Aggressive;
    else if (flags & 0x100)  kbCallback = KeyboardHook_WinKeySuppress;
    else                     kbCallback = KeyboardHook_Moderate;

    g_hKeyboardHook = SetWindowsHookExA(
        WH_KEYBOARD_LL, kbCallback, GetModuleHandle(NULL), 0
    );

    // Select CBT callback
    HOOKPROC cbtCallback = (flags & 0x2000)
        ? CBTHook_Aggressive
        : CBTHook_Moderate;

    g_hCBTHook = SetWindowsHookExA(WH_CBT, cbtCallback, NULL, 0);
    g_hShellHook = SetWindowsHookExA(WH_SHELL, ShellHookProc, NULL, 0);
}


// =============================================================================
//  EXPORT 2: CLDBDoSomeOtherStuff
//  Address: 0x180001000
//  Reinstalls keyboard hook only (preserves CBT/Shell).
// =============================================================================

extern "C" __declspec(dllexport)
void CLDBDoSomeOtherStuff(DWORD flags) {
    if (g_hKeyboardHook) UnhookWindowsHookEx(g_hKeyboardHook);
    // Reinstall with potentially different callback
    // Uses same flag-based selection as CLDBDoSomeStuff
}


// =============================================================================
//  EXPORT 3: CLDBDoSomeOtherStuffs
//  Address: 0x1800010e0
//  Returns bitmask of currently active hooks.
//    0x400  = keyboard hook active
//    0x800  = CBT hook active
//    0x1000 = shell hook active
// =============================================================================

extern "C" __declspec(dllexport)
DWORD CLDBDoSomeOtherStuffs() {
    DWORD result = 0;
    if (g_hKeyboardHook) result |= 0x400;
    if (g_hCBTHook)      result |= 0x800;
    if (g_hShellHook)    result |= 0x1000;
    return result;
}


// =============================================================================
//  EXPORT 4: CLDBDoYetMoreStuff
//  Address: 0x180001330
//  Reinstalls CBT hook only.
// =============================================================================

extern "C" __declspec(dllexport)
void CLDBDoYetMoreStuff(DWORD flags) {
    if (g_hCBTHook) UnhookWindowsHookEx(g_hCBTHook);
    // Reinstall with selected callback
}


// =============================================================================
//  KEYBOARD HOOK — Moderate (FUN_1800013a0)
//  Blocks: Alt+Tab, Win keys (VK_LWIN/VK_RWIN), Ctrl+Esc, Ctrl+K
//  Passes: everything else
// =============================================================================

static LRESULT CALLBACK KeyboardHook_Moderate(
    int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* kb = (KBDLLHOOKSTRUCT*)lParam;

        // Block Alt+Tab
        if (kb->vkCode == VK_TAB && (kb->flags & LLKHF_ALTDOWN))
            return 1;

        // Block Win keys
        if (kb->vkCode == VK_LWIN || kb->vkCode == VK_RWIN)
            return 1;

        // Block Ctrl+Esc (Start menu)
        if (kb->vkCode == VK_ESCAPE &&
            (GetAsyncKeyState(VK_CONTROL) & 0x8000))
            return 1;

        // Block Ctrl+K (search/link shortcut)
        if (kb->vkCode == 0x4B &&
            (GetAsyncKeyState(VK_CONTROL) & 0x8000))
            return 1;
    }
    return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
}


// =============================================================================
//  KEYBOARD HOOK — Win-Key Suppression (FUN_1800014a0)
//  Active suppression: injects synthetic key-up events via SendInput
//  to neutralize partially-formed Win+key shortcut sequences.
//
//  State machine:
//    DAT_180019ad8 — which Win key is held
//    DAT_180019adc — Win+H detected (dictation/voice typing)
//    DAT_180019ae0 — Win+other key detected
//    DAT_180019ae4 — Win released, pending cleanup
// =============================================================================

static DWORD g_winKeyHeld     = 0;  // DAT_180019ad8
static DWORD g_winH_detected  = 0;  // DAT_180019adc
static DWORD g_winCombo       = 0;  // DAT_180019ae0
static DWORD g_winPending     = 0;  // DAT_180019ae4

static LRESULT CALLBACK KeyboardHook_WinKeySuppress(
    int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* kb = (KBDLLHOOKSTRUCT*)lParam;

        // Track Win key state
        if (kb->vkCode == VK_LWIN || kb->vkCode == VK_RWIN) {
            if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
                g_winKeyHeld = kb->vkCode;
                return 1;
            }
            if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
                g_winKeyHeld = 0;
                g_winPending = 1;
                return 1;
            }
        }

        // If Win key is held and another key pressed
        if (g_winKeyHeld) {
            // Special case: Win+H = Windows dictation/voice typing
            if (kb->vkCode == 0x48)  // 'H'
                g_winH_detected = 1;
            else
                g_winCombo = 1;
            return 1;
        }

        // If Win was released, inject synthetic key-ups to cancel combos
        if (g_winPending) {
            g_winPending = 0;

            INPUT inputs[2] = {};

            // Send key-up for the pending key
            inputs[0].type = INPUT_KEYBOARD;
            inputs[0].ki.wVk = (WORD)kb->vkCode;
            inputs[0].ki.dwFlags = KEYEVENTF_KEYUP;

            // Send key-up for VK_LWIN to cancel any Win combo
            inputs[1].type = INPUT_KEYBOARD;
            inputs[1].ki.wVk = VK_LWIN;
            inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;

            SendInput(2, inputs, sizeof(INPUT));

            g_winH_detected = 0;
            g_winCombo = 0;
        }

        // Standard blocks still apply
        if (kb->vkCode == VK_TAB && (kb->flags & LLKHF_ALTDOWN))
            return 1;
        if (kb->vkCode == VK_ESCAPE &&
            (GetAsyncKeyState(VK_CONTROL) & 0x8000))
            return 1;
    }
    return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
}


// =============================================================================
//  KEYBOARD HOOK — Most Restrictive (FUN_1800017c0)
//  Blocks nearly ALL keys. Only passes:
//    - F-keys (F1-F24): VK_F1 (0x70) through VK_F24 (0x87)
//    - Unmodified non-system keys (no Alt, no Ctrl)
//  Everything else is eaten.
// =============================================================================

static LRESULT CALLBACK KeyboardHook_MostRestrictive(
    int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* kb = (KBDLLHOOKSTRUCT*)lParam;

        // Allow F-keys unconditionally
        if (kb->vkCode >= VK_F1 && kb->vkCode <= 0x87)
            return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);

        // Block system keys (Alt combinations)
        if (wParam == WM_SYSKEYDOWN || wParam == WM_SYSKEYUP)
            return 1;

        // Block any modified keys (Ctrl+anything, Alt+anything)
        if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) ||
            (GetAsyncKeyState(VK_MENU) & 0x8000) ||
            (GetAsyncKeyState(VK_LWIN) & 0x8000) ||
            (GetAsyncKeyState(VK_RWIN) & 0x8000))
            return 1;

        // Allow unmodified regular keys
    }
    return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
}


// =============================================================================
//  CBT HOOK — Aggressive Mouse Blocking (FUN_180001ad0)
//  Blocks: right-click, middle-click, extended mouse buttons,
//          Ctrl+left-click, non-client area right-clicks
// =============================================================================

static LRESULT CALLBACK CBTHook_Aggressive(
    int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HCBT_CLICKSKIPPED || nCode == HCBT_QS) {
        // Block right-click (WM_RBUTTONDOWN = 0x204)
        // Block middle-click (WM_MBUTTONDOWN = 0x207)
        // Block extended mouse buttons (WM_XBUTTONDOWN = 0x20B)
        // Uses bitmask: (0x387UL >> offset) for WM_RB/MB/XB range
        //               (0x70fUL >> offset) for WM_NCRB range

        DWORD msg = (DWORD)wParam;

        // Right-click family
        if (msg == WM_RBUTTONDOWN || msg == WM_RBUTTONUP)
            return 1;

        // Middle-click family
        if (msg == WM_MBUTTONDOWN || msg == WM_MBUTTONUP)
            return 1;

        // Extended mouse buttons
        if (msg == WM_XBUTTONDOWN)
            return 1;

        // Non-client area right-click (WM_NCRBUTTONDOWN = 0xA4)
        if (msg >= 0xA4 && msg <= 0xA6)
            return 1;

        // Ctrl+left-click (prevents opening links in new tabs)
        if ((msg >= WM_LBUTTONDOWN && msg <= WM_LBUTTONDBLCLK) &&
            (GetAsyncKeyState(VK_CONTROL) & 0x8000))
            return 1;
    }
    return CallNextHookEx(g_hCBTHook, nCode, wParam, lParam);
}


// =============================================================================
//  CBT HOOK — Moderate Mouse Blocking (FUN_180001a30)
//  Blocks: extended mouse buttons, NC right-clicks, Ctrl+left-click
//  Allows: regular right-click, middle-click (less restrictive)
// =============================================================================

static LRESULT CALLBACK CBTHook_Moderate(
    int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HCBT_CLICKSKIPPED || nCode == HCBT_QS) {
        DWORD msg = (DWORD)wParam;

        // Extended mouse buttons only
        if (msg >= WM_XBUTTONDOWN && msg <= 0x20D)
            return 1;

        // NC right-click
        if (msg >= 0xA4 && msg <= 0xA6)
            return 1;

        // Ctrl+left-click
        if ((msg >= WM_LBUTTONDOWN && msg <= WM_LBUTTONDBLCLK) &&
            (GetAsyncKeyState(VK_CONTROL) & 0x8000))
            return 1;
    }
    return CallNextHookEx(g_hCBTHook, nCode, wParam, lParam);
}
