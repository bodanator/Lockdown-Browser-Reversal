// =============================================================================
//  LockDown Browser — Usermode Detection Pseudocode
//  Reverse engineered from LockDownBrowser.exe
//  SHA256: 86f39c5a239a0ff69f3e6b3bd8833f455eecbbacc2890fe68819425098bc8040
//  PE x86_64, ~20MB
// =============================================================================

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

// =============================================================================
//  1. FOREGROUND WINDOW POLLING (Primary Detection)
//
//  The #1 detection vector. LDB runs a timer that calls GetForegroundWindow()
//  and compares the result against its own main HWND and tab HWNDs.
//
//  If the foreground window is NOT one of theirs, they log:
//    "v2 GetForegroundWindow() == CLDB main or tab"
//  and set internal focus flags.
//
//  String evidence:
//    0x140b34598: "v2 GetForegroundWindow() == CLDB main or tab"
//    0x140b338c0: "rldbfocus=1"
//    0x140b338d0: "rldbfocus=2"
//    0x140b2b720: "MAIN MOUSE focus = %d, pApp focus = %d mainframe = %d"
// =============================================================================

class CLDBFocusMonitor {
    HWND m_hwndMain;
    HWND m_hwndTab;
    int  m_focusState;       // 0 = unknown, 1 = LDB focused, 2 = LDB lost focus
    bool m_flagged;

    void CheckForeground() {
        HWND hwFg = GetForegroundWindow();

        if (hwFg == m_hwndMain || hwFg == m_hwndTab) {
            m_focusState = 1;
            // Log: "rldbfocus=1"
            // Append to telemetry URL params
        } else {
            m_focusState = 2;
            // Log: "rldbfocus=2"
            // FLAG EVENT — foreground was stolen
            // This is what triggers "flagged=" server-side
            m_flagged = true;
            ReportFocusLoss(hwFg);
        }
    }

    void ReportFocusLoss(HWND hwForeign) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwForeign, &pid);

        char windowText[256] = {};
        GetWindowTextA(hwForeign, windowText, sizeof(windowText));

        char className[256] = {};
        GetClassNameA(hwForeign, className, sizeof(className));

        // Package into telemetry:
        //   "flagged=" + focusState + window info
        // Sent to server via encrypted channel
    }

    // Called on a timer — fires every few hundred ms
    // Timer is set up in the main message loop
    void OnTimer() {
        CheckForeground();
    }
};


// =============================================================================
//  2. PROCESS ENUMERATION (PProcessListPSAPI)
//
//  Enumerates all running processes using PSAPI. Builds a list of process
//  image names and sends it encrypted to the server.
//
//  String evidence:
//    0x140b35af0: "process.list", "Process List", "process.list.processes"
//    0x140b35420: "Failed to send 1st process enumerate request"
//    0x140b354b0: "PProcessListPSAPI::GetProcessIDArray() FAILED"
//
//  Imports:
//    K32EnumProcesses, K32EnumProcessModules, K32EnumProcessModulesEx
//    QueryFullProcessImageNameA, QueryFullProcessImageNameW
//    OpenProcess, TerminateProcess, GetWindowThreadProcessId
// =============================================================================

class PProcessListPSAPI {
    DWORD  m_pids[4096];
    DWORD  m_count;

    struct ProcessInfo {
        DWORD       pid;
        std::string imageName;
        std::string fullPath;
    };

    std::vector<ProcessInfo> m_processList;

    bool GetProcessIDArray() {
        DWORD cbNeeded = 0;
        if (!EnumProcesses(m_pids, sizeof(m_pids), &cbNeeded)) {
            // "PProcessListPSAPI::GetProcessIDArray() FAILED"
            return false;
        }
        m_count = cbNeeded / sizeof(DWORD);
        return true;
    }

    void BuildProcessList() {
        if (!GetProcessIDArray()) return;

        m_processList.clear();

        for (DWORD i = 0; i < m_count; i++) {
            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE, m_pids[i]);

            if (!hProc) continue;

            char fullPath[MAX_PATH] = {};
            DWORD pathSize = MAX_PATH;
            QueryFullProcessImageNameA(hProc, 0, fullPath, &pathSize);

            ProcessInfo pi;
            pi.pid = m_pids[i];
            pi.fullPath = fullPath;

            // Extract just the filename
            char* slash = strrchr(fullPath, '\\');
            pi.imageName = slash ? (slash + 1) : fullPath;

            m_processList.push_back(pi);
            CloseHandle(hProc);
        }
    }

    // Encrypts the process list and sends to server
    // Format: "process.list" key with structured data
    // Uses the same encrypted channel as focus telemetry
    void SendToServer() {
        // Build JSON-like structure:
        // "process.list" -> "Process List"
        // "process.list.processes" -> array of process names
        // Encrypted with AES-CBC via the kernel driver's crypto channel
    }
};


// =============================================================================
//  3. WINDOW ENUMERATION
//
//  EnumWindows + FindWindowW to scan all visible windows.
//  Reads window text and class names to detect known tools.
//
//  Imports:
//    FindWindowW, EnumWindows, GetWindowTextA/W
//    GetWindowThreadProcessId
// =============================================================================

class WindowScanner {
    struct WindowInfo {
        HWND        hwnd;
        DWORD       pid;
        std::string text;
        std::string className;
    };

    std::vector<WindowInfo> m_windows;

    static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
        auto* self = reinterpret_cast<WindowScanner*>(lParam);

        WindowInfo wi;
        wi.hwnd = hwnd;

        char text[512] = {};
        GetWindowTextA(hwnd, text, sizeof(text));
        wi.text = text;

        char cls[256] = {};
        GetClassNameA(hwnd, cls, sizeof(cls));
        wi.className = cls;

        GetWindowThreadProcessId(hwnd, &wi.pid);

        self->m_windows.push_back(wi);
        return TRUE;
    }

    void ScanAllWindows() {
        m_windows.clear();
        EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(this));
    }
};


// =============================================================================
//  4. AUTOHOTKEY DETECTION
//
//  Specifically targets AutoHotkey by window class name.
//  If found, terminates the process immediately.
//
//  String evidence:
//    0x140b34350: "AutoHotkeyGUI"
//    0x140b34360: "AUTOHOTKEY - killing in timer kill"
// =============================================================================

class AutoHotkeyDetector {
    void Detect() {
        HWND ahk = FindWindowW(L"AutoHotkeyGUI", NULL);
        if (ahk) {
            DWORD pid = 0;
            GetWindowThreadProcessId(ahk, &pid);

            if (pid) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                if (hProc) {
                    // "AUTOHOTKEY - killing in timer kill"
                    TerminateProcess(hProc, 1);
                    CloseHandle(hProc);
                }
            }
        }
    }
};


// =============================================================================
//  5. PROCESS CLOSE / BLOCK DIALOGS
//
//  When a blocked process is detected, LDB shows modal dialogs
//  prompting the user to close or force-killing the process.
//
//  String evidence:
//    "ProcessCloseDlg"  — Ask user to close
//    "ProcessBlockAllDlg" — Block all instances
// =============================================================================

class ProcessCloseDlg {
    std::string m_processName;
    DWORD       m_pid;

    // Shows a dialog: "Close [process] to continue your exam"
    // If user doesn't close within timeout, force-terminates
    void Show() {
        // Modal dialog with process name
        // Timer starts — if still running after N seconds:
        //   OpenProcess(PROCESS_TERMINATE) -> TerminateProcess()
    }
};

class ProcessBlockAllDlg {
    // Blocks ALL instances of a given process name
    // Scans with EnumProcesses, terminates each match
    void BlockAll(const char* processName) {
        DWORD pids[4096];
        DWORD cbNeeded;
        EnumProcesses(pids, sizeof(pids), &cbNeeded);
        DWORD count = cbNeeded / sizeof(DWORD);

        for (DWORD i = 0; i < count; i++) {
            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                FALSE, pids[i]);
            if (!hProc) continue;

            char path[MAX_PATH] = {};
            DWORD sz = MAX_PATH;
            QueryFullProcessImageNameA(hProc, 0, path, &sz);

            if (strstr(path, processName)) {
                TerminateProcess(hProc, 1);
            }
            CloseHandle(hProc);
        }
    }
};


// =============================================================================
//  6. SCREEN RECORDING DETECTION
//
//  Detects Xbox Game Bar, OBS, and other screen recording software.
//  When detected, enables "BlockRecording" mode.
//
//  String evidence:
//    0x140b356b0: "DetectXboxAppRecordings() - capture detected, enabling BlockRecording"
//    0x140b347c8: "EnableBlockRecording() - called before blocklist"
//    0x140b34808: "Allow screen recording - %s"
//    0x140b34830: "EnableBlockRecording - SUPPRESS - asr=%d, apd=%d, ilp=%d, rec=%d"
//    0x140b34880: "EnableBlockRecording - ENABLE - asr=%d, apd=%d, ilp=%d, rec=%d"
//    0x140b348c8: "EnableBlockRecording - Already blocking"
// =============================================================================

class ScreenRecordingDetector {
    bool m_blockRecording;
    bool m_alreadyBlocking;

    // asr = allow screen recording (server config flag)
    // apd = ? (unknown flag)
    // ilp = ? (unknown flag)
    // rec = recording detected
    int m_asr, m_apd, m_ilp, m_rec;

    void DetectXboxAppRecordings() {
        // Checks Windows.Gaming.Preview registry keys
        // Queries for active Game DVR / Game Bar sessions
        // If capture is detected:
        //   "DetectXboxAppRecordings() - capture detected, enabling BlockRecording"
        m_rec = 1;
        EnableBlockRecording();
    }

    void EnableBlockRecording() {
        if (m_alreadyBlocking) {
            // "EnableBlockRecording - Already blocking"
            return;
        }

        if (m_asr) {
            // "EnableBlockRecording - SUPPRESS"
            // Server says recording is allowed for this exam
            return;
        }

        // "EnableBlockRecording - ENABLE"
        m_blockRecording = true;
        m_alreadyBlocking = true;

        // Attempts to:
        // 1. Kill recording process
        // 2. Force close recording tabs
        // 3. Set display affinity on LDB windows to prevent capture
    }
};


// =============================================================================
//  7. CLIPBOARD MONITORING
//
//  LDB registers as a clipboard format listener and aggressively
//  manages clipboard contents during exams.
//
//  Imports:
//    OpenClipboard, CloseClipboard, EmptyClipboard
//    GetClipboardOwner, EnumClipboardFormats
//    AddClipboardFormatListener, SetClipboardData
//
//  String evidence:
//    0x140b2b6a0: "Clipboard emptied"
//    0x140b34260: "Windows.ApplicationModel.DataTransfer.Clipboard"
// =============================================================================

class ClipboardMonitor {
    void InstallListener() {
        AddClipboardFormatListener(m_hwndMain);
    }

    void OnClipboardChange() {
        // Empties clipboard to prevent copy-paste cheating
        if (OpenClipboard(m_hwndMain)) {
            EmptyClipboard();
            CloseClipboard();
            // "Clipboard emptied"
        }
    }

    // Also monitors UWP clipboard API:
    // "Windows.ApplicationModel.DataTransfer.Clipboard"
    // This catches modern Windows apps using the WinRT clipboard

    HWND m_hwndMain;
};


// =============================================================================
//  8. FOCUS TRACKING VIA SetWinEventHook
//
//  Uses accessibility hooks to receive notifications when ANY window
//  gains or loses focus system-wide.
//
//  Import: USER32.DLL::SetWinEventHook
//
//  This is a secondary focus detection mechanism — the primary one
//  is the timer-based GetForegroundWindow() polling. This one catches
//  focus changes in real-time via the accessibility event system.
// =============================================================================

class AccessibilityFocusHook {
    HWINEVENTHOOK m_hook;

    static void CALLBACK WinEventProc(
        HWINEVENTHOOK hWinEventHook,
        DWORD event,
        HWND hwnd,
        LONG idObject,
        LONG idChild,
        DWORD dwEventThread,
        DWORD dwmsEventTime)
    {
        if (event == EVENT_SYSTEM_FOREGROUND) {
            // A window gained foreground focus
            // Compare against LDB HWNDs
            // If mismatch -> flag event
        }
    }

    void Install() {
        m_hook = SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND,
            NULL, WinEventProc,
            0, 0,  // All processes, all threads
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS
        );
    }
};


// =============================================================================
//  9. SERVER-SIDE FLAGGING SYSTEM
//
//  When a detection event fires, LDB sends a "flagged" key-value
//  pair to the server. The server stores this and can trigger
//  warnings or bans.
//
//  String evidence:
//    0x140b2d8f0: "flagged="
//    0x140b2d9a0: "flagged"
// =============================================================================

class FlagReporter {
    void ReportFlag(const char* reason, int severity) {
        // Builds URL parameter: "flagged=" + encoded_reason
        // Appends to the next telemetry POST
        // Server stores flag in student's exam session

        // Flag data includes:
        // - What triggered the flag (focus loss, blocked process, etc.)
        // - Timestamp
        // - Window/process info of the offending application
        // - Focus state values (rldbfocus=1 or rldbfocus=2)
    }
};


// =============================================================================
//  10. THREAD CREATION HOOKING (Usermode Side)
//
//  The usermode binary sets up thread creation hooks and monitors
//  new threads for signs of injection or manipulation.
//
//  String evidence:
//    0x140b0c880: "setup:hook_thread_create"
//    0x140b0c8a0: "setup:unhook_thread_create"
//    0x140b0c8c0: "setup:enumerating_threads"
//    0x140b0c8f8: "setup:hooked_thread_create"
//    0x140b0c990: "setup:hwbp_thread_create_setup"
//    0x140b0c9d0: "setup:make_handler_thread"
//
//  Uses hardware breakpoints (HWBP) on NtCreateThread to detect
//  when new threads are created — including injected ones.
//
//  Imports:
//    CreateRemoteThread, GetThreadContext, SetThreadContext
//    SuspendThread, ResumeThread, Thread32First, Thread32Next
//    OpenThread, GetThreadId
// =============================================================================

class ThreadCreationMonitor {
    void Setup() {
        // "setup:enumerating_threads"
        // Enumerate all existing threads via Thread32First/Thread32Next
        EnumerateExistingThreads();

        // "setup:hwbp_thread_create_setup"
        // Set hardware breakpoints on thread creation functions
        SetupHardwareBreakpoints();

        // "setup:hook_thread_create"
        // Install the hook
        // "setup:hooked_thread_create"

        // "setup:make_handler_thread"
        // Create a dedicated thread to handle hook callbacks
    }

    void EnumerateExistingThreads() {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return;

        THREADENTRY32 te = {};
        te.dwSize = sizeof(te);
        if (Thread32First(hSnap, &te)) {
            do {
                // Record thread ID and owner PID
                // Used as baseline — new threads after this are monitored
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }

    void SetupHardwareBreakpoints() {
        // Uses DR0-DR3 debug registers to set HWBP on
        // NtCreateThread or similar thread creation path
        // This catches thread injection from external processes

        HANDLE hThread = GetCurrentThread();
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(hThread, &ctx);

        // ctx.Dr0 = address_of_NtCreateThread;
        // ctx.Dr7 = enable DR0 breakpoint;
        SetThreadContext(hThread, &ctx);
    }
};


// =============================================================================
//  11. RESOURCE EDITOR HACK DETECTION
//
//  Detects if someone has modified LDB's own resources (dialogs,
//  strings, etc.) using a resource editor.
//
//  String evidence:
//    0x140b35670: "DetectResourceEditorHacksByThread()"
// =============================================================================

class ResourceIntegrityChecker {
    void DetectResourceEditorHacksByThread() {
        // Verifies that LDB's PE resources haven't been tampered with
        // Checks resource section checksums against known-good values
        // If modified -> flag event, possible self-terminate
    }
};


// =============================================================================
//  12. NTREADVIRTUALMEMORY — MEMORY READING
//
//  Uses NtReadVirtualMemory (resolved dynamically from ntdll.dll)
//  to read other processes' memory. Purpose: inspect DWM or other
//  system processes for integrity.
//
//  String evidence:
//    0x140b14108: " : NtReadVirtualMemory()"
//    0x140b14180: "NtReadVirtualMemory"
// =============================================================================

class MemoryInspector {
    typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToRead,
        PSIZE_T NumberOfBytesRead
    );

    pNtReadVirtualMemory m_NtReadVirtualMemory;

    void Init() {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        m_NtReadVirtualMemory = (pNtReadVirtualMemory)
            GetProcAddress(ntdll, "NtReadVirtualMemory");
    }

    // Used in conjunction with the kernel driver's DWM integrity check
    // Reads DWM process memory to verify it hasn't been hooked or modified
};


// =============================================================================
//  13. DRIVER COMMUNICATION (ApDriverPort)
//
//  The usermode binary connects to the kernel driver via a
//  filter communication port named "\ApDriverPort".
//
//  String evidence:
//    0x140b10738: "\\ApDriverPort"
//    0x140b13910: " : Cannot verify DWM integrity because the driver started after DWM"
//    0x140b138e0: " : Failed to encrypt thread info request"
//    0x140b13958: " : Failed to send 1st thread info request"
//    0x140b139e8: "Port is closed, stopping notification thread"
//
//  Uses: FilterConnectCommunicationPort (FLTLIB.DLL)
//  Communication is encrypted with AES-CBC, key exchanged via RSA
// =============================================================================

class DriverComm {
    HANDLE m_hPort;

    bool Connect() {
        // FilterConnectCommunicationPort(L"\\ApDriverPort", ...)
        // Driver validates connecting PID matches LDB
        // Establishes encrypted channel via RSA key exchange
        // All subsequent messages encrypted with AES-CBC
        return true;
    }

    void SendThreadInfoRequest() {
        // Encrypt thread info with AES-CBC
        // Send via FilterSendMessage
        // If fails: "Failed to encrypt thread info request"
        // Then: "Failed to send 1st thread info request"
    }

    void ReceiveNotifications() {
        // Background thread listening for driver messages
        // Driver sends:
        //   - Process create/terminate events
        //   - Thread create events (with fileless execution flags)
        //   - Image load events
        //   - DWM integrity status
        // If port closes: "Port is closed, stopping notification thread"
    }
};


// =============================================================================
//  14. DISPLAY MONITOR FINGERPRINTING
//
//  Enumerates all display monitors and collects hardware info.
//  Used to detect virtual displays, remote desktop, and display
//  configuration changes during an exam.
//
//  Imports:
//    EnumDisplayMonitors, GetMonitorInfoA/W, MonitorFromWindow
//    GetScaleFactorForMonitor
//    DXVA2: GetMonitorBrightness, GetMonitorContrast,
//           GetMonitorColorTemperature, GetPhysicalMonitorsFromHMONITOR
// =============================================================================

class DisplayMonitorFingerprint {
    void EnumerateMonitors() {
        EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, 0);
    }

    static BOOL CALLBACK MonitorEnumProc(
        HMONITOR hMonitor, HDC hdc, LPRECT lprc, LPARAM lp)
    {
        MONITORINFOEXA mi = {};
        mi.cbSize = sizeof(mi);
        GetMonitorInfoA(hMonitor, &mi);

        // Collect:
        // - Monitor device name
        // - Resolution
        // - DPI / Scale factor (GetScaleFactorForMonitor)
        // - Physical monitor properties via DXVA2:
        //   brightness, contrast, color temperature
        // - Whether this is a physical or virtual monitor

        return TRUE;
    }
};
