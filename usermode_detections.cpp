// =============================================================================
//  LockDown Browser — Usermode Detection Pseudocode
//  Reverse engineered from LockDownBrowser.exe
//  SHA256: 86f39c5a239a0ff69f3e6b3bd8833f455eecbbacc2890fe68819425098bc8040
//  PE x86_64, 20,826,048 bytes
//
//  Full analysis via Ghidra 12.2 and targeted string extraction.
//  All addresses verified against binary.
// =============================================================================

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wininet.h>
#include <bcrypt.h>
#include <fltuser.h>
#include <mmsystem.h>
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


// =============================================================================
//  15. CEF/CHROMIUM NAVIGATION LOCKDOWN
//
//  5 distinct OnBeforeBrowse handlers controlling all browser navigation.
//  Dual blacklist/whitelist URL filtering with stem matching.
//  Canvas LMS monitoring via OnBeforeResourceLoad state parameters.
//
//  String evidence:
//    0x00B1657D: "OnBeforeBrowse - browser ID = %d, is-subframe = %d, type = %d, URL = %s"
//    0x00B165C5: "OnBeforeBrowse - ignoring because i, e, c = %d %d %d"
//    0x00B289B8: "OnBeforeBrowseLiveProctoring - %s"
//    0x00B2B778: "OnBeforeBrowseLiveChatSysCheck bid = %d url = %s"
//    0x00B2B950: "OnBeforeBrowseLiveChatGeneric bid = %d url = %s"
// =============================================================================

class CLDBRequestHandler {
public:
    bool OnBeforeBrowse(HWND browser, const char* url, int browserId, bool isSubframe) {
        // "OnBeforeBrowse - ignoring because i, e, c = %d %d %d"
        if (shouldIgnore(browserId))
            return false;

        // "OnBeforeBrowse - browser ID = %d, is-subframe = %d, type = %d, URL = %s"
        if (isBlacklisted(url)) return true;
        if (!isWhitelisted(url)) return true;
        return false;
    }

    bool OnBeforeBrowseLiveProctoring(const char* url) {
        // "OnBeforeBrowseLiveProctoring - %s"
        return validateProctoringUrl(url);
    }

    bool OnBeforeBrowseLiveChatSysCheck(int browserId, const char* url) {
        // "OnBeforeBrowseLiveChatSysCheck bid = %d url = %s"
        return true;
    }

    bool OnBeforeBrowseLiveChatGeneric(int browserId, const char* url) {
        // "OnBeforeBrowseLiveChatGeneric bid = %d url = %s"
        return true;
    }

    // "OnBeforeResourceLoad - Canvas mon=%d ps=%d pcom=%d st=%d stcom=%d msg=%d"
    int OnBeforeResourceLoad(const char* url) {
        // Canvas monitoring parameters:
        //   mon  = canvas monitor active
        //   ps   = process state
        //   pcom = process complete
        //   st   = state
        //   stcom = state complete
        //   msg  = message count

        if (isFilteredChromeCommand(url)) return 1;  // "filter-chrome-commands"
        if (isFilteredUrl(url)) return 1;             // "filter-url"
        return 0;
    }

private:
    int m_canvasMonitorActive;
    int m_processState;
    int m_processComplete;
    int m_state;
    int m_stateComplete;
    int m_messageCount;

    bool isBlacklisted(const char* url);
    bool isWhitelisted(const char* url);
    bool isFilteredChromeCommand(const char* url);
    bool isFilteredUrl(const char* url);
    bool shouldIgnore(int browserId);
    bool validateProctoringUrl(const char* url);
};


// =============================================================================
//  16. NETWORK & TELEMETRY MANAGER
//
//  AWS S3 direct upload with SigV4 authentication.
//  MAC address fingerprinting on exam data uploads.
//  Google Analytics telemetry embedded.
//
//  String evidence:
//    0x00B0F740: "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s/us-east-1/s3/aws4_request,
//                 SignedHeaders=content-md5;content-type;host;x"
//    "upload_zip.do?token=%s&key=%s&studentKey=%s&type=%s&time=%s&mac=%s"
//    "upload_logs.do"
//    "s3.amazonaws.com (Help Center logs)"
//
//  Server endpoints:
//    ask.respondus.com, file.respondus.com, extension.respondus.com,
//    downloads.respondus.com, d9unvfzorf0bo.cloudfront.net (CDN),
//    ws.readspeaker.com (TTS), tiny.cloud (TinyMCE), google-analytics.com
// =============================================================================

class NetworkManager {
public:
    bool uploadToS3(const void* data, size_t length, const char* bucket, const char* key) {
        char authHeader[512];
        snprintf(authHeader, sizeof(authHeader),
            "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s/us-east-1/s3/aws4_request,"
            "SignedHeaders=content-md5;content-type;host;x",
            m_accessKeyId, m_dateStamp);
        return httpPut(bucket, key, data, length, authHeader, "binary/octet-stream");
    }

    // MAC address fingerprinting in every exam upload
    bool uploadExamData(const char* token, const char* key,
                        const char* studentKey, const char* type) {
        char macAddress[18];
        getDeviceMac(macAddress);

        char url[512];
        snprintf(url, sizeof(url),
            "upload_zip.do?token=%s&key=%s&studentKey=%s&type=%s&time=%s&mac=%s",
            token, key, studentKey, type, getCurrentTime(), macAddress);
        return httpPost(url, m_examZipData, m_examZipSize);
    }

    bool uploadLogs() {
        // "upload_logs.do"
        return httpPost("upload_logs.do", m_logBuffer, m_logSize);
    }

private:
    char m_accessKeyId[64];
    char m_dateStamp[16];
    void* m_examZipData;
    size_t m_examZipSize;
    void* m_logBuffer;
    size_t m_logSize;

    bool httpPut(const char*, const char*, const void*, size_t, const char*, const char*);
    bool httpPost(const char*, const void*, size_t);
    void getDeviceMac(char*);
    const char* getCurrentTime();
};


// =============================================================================
//  17. REGISTRY POLICY MANAGER
//
//  Manipulates Windows group policy registry keys to enforce lockdown.
//
//  String evidence:
//    0x00B1AC39: "Policies\Google\Chrome"
//    "Policies\System"
//    "Policies\Explorer"
// =============================================================================

class RegistryPolicyManager {
public:
    void lockdownChromePolicies() {
        // HKLM\SOFTWARE\Policies\Google\Chrome
        setRegistryPolicy(L"SOFTWARE\\Policies\\Google\\Chrome");
    }

    void lockdownSystemPolicies() {
        // HKLM\SOFTWARE\...\Policies\System
        setRegistryPolicy(
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
    }

    void lockdownExplorerPolicies() {
        // HKLM\SOFTWARE\...\Policies\Explorer
        setRegistryPolicy(
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer");
    }

private:
    void setRegistryPolicy(const wchar_t* path);
};


// =============================================================================
//  18. SINGLE INSTANCE ENFORCEMENT
//
//  Two mutexes prevent multiple instances of LDB.
//
//  String evidence:
//    0x00B4C8F8: "Local\{C15730E2-145C-4c5e-B005-3BC753F42475}-once-flag"
//    0x00B32D60: "Local\87543720949%u41187%u2617649587"
// =============================================================================

class SingleInstanceManager {
public:
    bool acquireLock() {
        // Static GUID mutex — global single instance
        m_onceFlagMutex = CreateMutexW(nullptr, TRUE,
            L"Local\\{C15730E2-145C-4c5e-B005-3BC753F42475}-once-flag");
        if (GetLastError() == ERROR_ALREADY_EXISTS)
            return false;

        // Dynamic session mutex — numeric obfuscation with PID
        wchar_t sessionMutex[128];
        swprintf_s(sessionMutex, L"Local\\87543720949%u41187%u2617649587",
                   GetCurrentProcessId());
        m_sessionMutex = CreateMutexW(nullptr, TRUE, sessionMutex);

        return true;
    }

private:
    HANDLE m_onceFlagMutex;
    HANDLE m_sessionMutex;
};


// =============================================================================
//  19. ANTI-DEBUG (Minimal)
//
//  Only two anti-debug checks found — no advanced techniques.
//
//  String evidence:
//    Import: IsDebuggerPresent (KERNEL32)
//    0x00B0BA6E: "debug_registers"
// =============================================================================

class AntiDebug {
public:
    bool isDebuggerAttached() {
        return IsDebuggerPresent();  // PEB.BeingDebugged
    }

    bool areHardwareBreakpointsSet() {
        // "debug_registers" — DR0-DR3 inspection
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(GetCurrentThread(), &ctx);
        return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
    }

    // No NtQueryInformationProcess
    // No ThreadHideFromDebugger
    // No timing checks
    // No int2d tricks
};


// =============================================================================
//  20. INTEGRITY CHECKER — PE checksum + TLSH fuzzy hash
//
//  Validates binary integrity with both exact and fuzzy methods.
//  TLSH catches patched binaries that differ from expected hash.
//
//  String evidence:
//    0x00B4F50F: "checksum = %ld; the header checksum = %ld"
//    0x00B379F6: "tlsh that is already valid"
// =============================================================================

class IntegrityChecker {
public:
    bool validateChecksum(const wchar_t* filePath) {
        // "checksum = %ld; the header checksum = %ld"
        DWORD calculated = calculatePEChecksum(filePath);
        DWORD header = readHeaderChecksum(filePath);
        return calculated == header;
    }

    bool validateFuzzyHash(const void* data, size_t len) {
        // TLSH (Trend Micro Locality Sensitive Hash)
        // "tlsh that is already valid"
        // Detects modified/patched versions even if exact hash differs
        return computeTLSH(data, len, m_expectedTLSH);
    }

private:
    char m_expectedTLSH[72];
    DWORD calculatePEChecksum(const wchar_t*);
    DWORD readHeaderChecksum(const wchar_t*);
    bool computeTLSH(const void*, size_t, const char*);
};


// =============================================================================
//  21. WEBCAM & AUDIO CAPTURE (Respondus Monitor)
//
//  Camera hotplug detection with retry logic.
//  Legacy WinMM audio capture (waveIn* APIs).
//  No local ML/face detection — server-side processing.
//
//  String evidence:
//    0x00B16BF0: "webcam new camera connected = (%s)"
//    "webcam DISconnected = (%s)"
//    "webcam RE-connected = (%s)"
//    "camera reconnect = %d, camera retry = %d"
//    "webcam check" / "webcam check complete, closing - %d"
//
//  Proctoring endpoints:
//    "proctoring_start_cancel.do"
//    "proctoring_continue.do"
// =============================================================================

class WebcamCapture {
public:
    void startCapture(const char* cameraName) {
        // "webcam check" → "webcam check complete, closing - %d"
        // "webcam new camera connected = (%s)"
    }

    void onDisconnect(const char* cameraName) {
        // "webcam DISconnected = (%s)"
        attemptReconnect();
    }

    void onReconnect(const char* cameraName) {
        // "webcam RE-connected = (%s)"
    }

    void attemptReconnect() {
        m_retryCount++;
        // "camera reconnect = %d, camera retry = %d"
    }

private:
    int m_reconnectCount;
    int m_retryCount;
};

class AudioCapture {
public:
    // waveIn* API — legacy WinMM microphone capture
    bool startRecording() {
        UINT numDevs = waveInGetNumDevs();
        if (numDevs == 0) return false;

        WAVEFORMATEX fmt = {};
        fmt.wFormatTag = WAVE_FORMAT_PCM;
        fmt.nChannels = 1;
        fmt.nSamplesPerSec = 44100;
        fmt.wBitsPerSample = 16;
        fmt.nBlockAlign = 2;
        fmt.nAvgBytesPerSec = 88200;

        return waveInOpen(&m_hWaveIn, 0, &fmt, (DWORD_PTR)waveInProc, 0,
                         CALLBACK_FUNCTION) == MMSYSERR_NOERROR;
    }

private:
    HWAVEIN m_hWaveIn;
    static void CALLBACK waveInProc(HWAVEIN, UINT, DWORD_PTR, DWORD_PTR, DWORD_PTR);
};


// =============================================================================
//  22. DISPLAY AFFINITY CONTROLLER
//
//  Prevents screen capture via SetWindowDisplayAffinity.
//
//  Import evidence:
//    SetWindowDisplayAffinity at 0x00CACF8E
// =============================================================================

class DisplayAffinityController {
public:
    bool setExcludeFromCapture(HWND hwnd) {
        // WDA_EXCLUDEFROMCAPTURE — Windows 10 2004+, content appears black
        BOOL result = SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
        if (!result) {
            // WDA_MONITOR fallback — older Windows, shows wallpaper
            result = SetWindowDisplayAffinity(hwnd, WDA_MONITOR);
        }
        return result != FALSE;
    }
};


// =============================================================================
//  23. OFFLINE EXAM CACHING
//
//  Supports offline exam delivery with retry logic.
//
//  String evidence:
//    0x00B2C1F3: "offline=%d course=%s test=%s cached=%d cached-id=%s Is retry = %d"
// =============================================================================

class OfflineManager {
public:
    void cacheExam(const char* courseId, const char* testId) {
        // "offline=%d course=%s test=%s cached=%d cached-id=%s Is retry = %d"
    }

private:
    bool m_offline;
    bool m_cached;
    char m_cachedId[64];
    int m_isRetry;
};


// =============================================================================
//  24. PING / KEEPALIVE THREAD
//
//  Background thread maintaining server session heartbeat.
//
//  String evidence:
//    0x00B12BFC: "ping notification thread"
//    "ping EndExam() -- quiz_active = %d, quiz_completed = %d"
//    "ping suggestions"
// =============================================================================

class PingThread {
public:
    static DWORD WINAPI threadProc(LPVOID param) {
        PingThread* self = static_cast<PingThread*>(param);
        while (self->m_running) {
            // "ping EndExam() -- quiz_active = %d, quiz_completed = %d"
            self->sendPing(self->m_quizActive, self->m_quizCompleted);
            Sleep(self->m_intervalMs);
        }
        return 0;
    }

private:
    bool m_running;
    bool m_quizActive;
    bool m_quizCompleted;
    DWORD m_intervalMs;

    void sendPing(bool quizActive, bool quizCompleted);
};
