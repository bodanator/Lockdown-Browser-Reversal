# Reverse Engineering Analysis

A complete reverse engineering breakdown of Respondus LockDown Browser's anti-cheat detection systems, covering both the usermode application (`LockDownBrowser.exe`) and the kernel driver (`LockDownService215.sys`).

---

## Target Binaries

| Binary | Path | Size | SHA256 |
|---|---|---|---|
| `LockDownBrowser.exe` | `C:\Program Files\Respondus\LockDown Browser\` | 20,826,048 bytes (~20 MB) | `86f39c5a239a0ff69f3e6b3bd8833f455eecbbacc2890fe68819425098bc8040` |
| `LockDownService215.sys` | `...\Service\x64\` | 71,944 bytes (~72 KB) | `a6d54547a8db751a2f0844252848fc1b997f56b594c78f82a6259496e221b501` |
| `LockDownBrowser.dll` | `C:\Program Files\Respondus\LockDown Browser\` | 118,720 bytes (~116 KB) | Input hooking companion DLL |

- **LockDownBrowser.exe**: PE x86_64, MFC/CEF-based application built with MSVC from `C:\vs12\LockDownChrome\`
- **LockDownService215.sys**: PE x86_64, FLTMGR minifilter kernel driver, v2.16.0.0
  - PDB: `LockDownService215.pdb` (GUID `db54a35f-f261-4d2f-8bcf-1b3f554f1a77`)
  - Signed with **WDK test certificate**, not production DigiCert

---

## Binary Hardening

| Property | EXE | Driver | Notes |
|----------|-----|--------|-------|
| ASLR | **DISABLED** | Enabled | 20MB static-base binary — all ROP gadgets at fixed addresses |
| DEP/NX | Enabled | Enabled | — |
| CFG | Empty table | Enabled | Compiled with CFG but function table is empty — not enforced |
| TLS Callbacks | 1 | 0 | — |
| Authenticode | DigiCert EV | **WDK Test Cert** | Driver uses dev cert, not production |
| FORCE_INTEGRITY | No | Yes | — |

**Implications:** The EXE has ASLR disabled and an empty CFG table — the entire 20MB binary sits at a predictable base address with no control-flow guard enforcement. Combined with the extensive import table, this is a significant attack surface for code injection.

---

## Methodology

### Tools Used
- **Ghidra 12.2** — Primary disassembler and decompiler
- **Python targeted string extraction** — 672 categorized string hits from EXE
- **PE header inspection** — Hardening, certificates, imports, load config
- **Manual string analysis** — LDB ships with extensive debug/logging strings that reveal function names, class names, and control flow

### Approach
1. **String harvesting** — LDB's debug strings are the Rosetta Stone. Searched for detection-related keywords: `focus`, `process`, `flagged`, `detect`, `monitor`, `hook`, `recording`, `clipboard`, `AutoHotkey`, `driver`, `encrypt`, `DWM`, `thread`
2. **Import table analysis** — Mapped all Win32 API imports (27 DLLs) to identify detection capabilities
3. **Cross-referencing** — Traced string references back to their containing functions to understand control flow
4. **Driver analysis** — Full Ghidra analysis of the kernel driver: 310 procedures, 294 strings, complete class hierarchy verified from debug strings
5. **Pseudocode reconstruction** — Combined string evidence, imports, and decompiler output into readable C++ pseudocode

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                       Respondus Server                          │
│  ask.respondus.com | file.respondus.com | extension.respondus   │
│  downloads.respondus.com | d9unvfzorf0bo.cloudfront.net (CDN)   │
│  AWS S3 (SigV4 direct upload) | Google Analytics telemetry      │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTPS + AWS SigV4
                               │ AES-256 encrypted payloads
                               │
┌──────────────────────────────┴──────────────────────────────────┐
│                 LockDownBrowser.exe (Usermode, 20 MB)            │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ Focus Monitor│  │ Process      │  │ CEF/Chromium Lockdown  │ │
│  │ GetForeground│  │ Scanner      │  │ 5 OnBeforeBrowse       │ │
│  │ WinEventHook │  │ PSAPI Enum   │  │ URL BL/WL + devtools   │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ Window Scan  │  │ Recording    │  │ Registry Policy Mgr    │ │
│  │ EnumWindows  │  │ Xbox/OBS     │  │ Chrome+System+Explorer │ │
│  │ FindWindowW  │  │ Screencastify│  │ policies               │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ Clipboard    │  │ Thread Mon   │  │ Network / Telemetry    │ │
│  │ AddFormat    │  │ HWBP hook    │  │ AWS S3 SigV4 upload    │ │
│  │ Listener     │  │ Thread32First│  │ MAC addr fingerprint   │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ Display      │  │ Integrity    │  │ Webcam / Monitor       │ │
│  │ Affinity     │  │ PE checksum  │  │ waveIn* audio          │ │
│  │ EXCLUDECAP   │  │ TLSH fuzzy   │  │ Camera hotplug detect  │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ Anti-Debug   │  │ Single       │  │ Offline Caching        │ │
│  │ (minimal)    │  │ Instance     │  │ Exam retry logic       │ │
│  │ IsDebugger   │  │ GUID mutex   │  │                        │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
│                    ┌──────────────┐                               │
│                    │ Driver Comm  │                               │
│                    │ \ApDriverPort│                               │
│                    │ RSA+AES      │                               │
│                    └──────┬───────┘                               │
└───────────────────────────┼──────────────────────────────────────┘
                            │ FilterPort (encrypted)
                            │
┌───────────────────────────┼──────────────────────────────────────┐
│                           │   LockDownService215.sys (72 KB)     │
│                ┌──────────┴───────────┐                          │
│                │  Communication Port  │                          │
│                │  \ApDriverPort       │                          │
│                │  PID validation      │                          │
│                └──────────┬───────────┘                          │
│                           │                                      │
│  ┌────────────────────────┼─────────────────────┐                │
│  │                        │                     │                │
│  ▼                        ▼                     ▼                │
│ ProcessMonitor      ThreadMonitor         ImageMonitor           │
│ PsSetCreate         PsSetCreate           PsSetLoad              │
│ ProcessNotify       ThreadNotify          ImageNotify             │
│ RoutineEx           Routine               Routine                │
│  │                        │                     │                │
│  │  ┌─────────────────────┴──────┐              │                │
│  │  │ verifyFilelessExecution    │              │                │
│  │  │ (code injection detect)    │              │                │
│  │  └────────────────────────────┘              │                │
│  │                                              │                │
│  ▼                                              ▼                │
│ CodeIntegrity              DwmImageResolver                      │
│ CiValidateFileObject       Verify dwm.exe path + SID            │
│ SHA1/SHA256 hashing        Owner SID check                       │
│ Signature verify           Boot-order integrity                  │
│                                                                  │
│ CryptoKernel               UserModeDetector                      │
│ RSA-2048 keypair gen       SMSS.exe boot chain                   │
│ AES-CBC encryption         Startup integrity                     │
│ BCrypt kernel stack         (anti-sandbox)                        │
│                                                                  │
│ BrowserImageResolver       DriverLogger                          │
│ LDB path validation        File-based logging                    │
│ OEM variant check          Auto-rotation                         │
│                                                                  │
│ NOT PRESENT: ObRegisterCallbacks, CmRegisterCallbackEx,          │
│              WFP network filter, SSDT hooks                      │
└──────────────────────────────────────────────────────────────────┘
```

---

## Application Startup & Enforcement Chain

The enforcement pipeline runs sequentially at startup before any exam content loads. Failure at any stage displays a dialog and exits.

```
FUN_1401903b0 (WinMain)
├── Global state allocation
│   DAT_140cedf40 = 0x4aa78 bytes (~305 KB)
│   DAT_140cedf48 = server string tables
│   DAT_140cedf50 = server config (0xb08 bytes)
│   DAT_140cedf80 = secondary state
│
├── Single-instance mutex
│   "CLDB{52FBA03B-9E7A-4786-A9A8-F61730C505DA}"
│
├── OS gate: Windows 10+ required (dialog on failure)
│
├── FUN_140275970 — DriverComm_Init
│   └── FilterConnectCommunicationPort(\ApDriverPort)
│       Returns: 0=fail, 1=connected
│
├── FUN_1402a6e00 — PreFlightEnforcement
│   ├── FUN_1402ae7e0 — DriverServiceChecker
│   │   OpenSCManagerW → OpenServiceW → QueryServiceStatusEx
│   │   Returns: 0=not found, 1=SCM fail, 2=svc error, 3=query fail, 4=running
│   │
│   ├── License validation (FUN_140a4917c)
│   │   Server strings: table indices 0xf00, 0xf20, 0xf40, 0xf60
│   │   Error codes: 0x02, 0x03, 0x35, 0x40, 0x7b, 0x10b
│   │   Bit 10 of response = server-side VM permission override
│   │
│   └── Enforcement dialogs:
│       0x65 (101) = blocked     0x67 (103) = license fail
│       0x68 (104) = unknown     0x69 (105) = driver missing
│       0x66 (102) = version     0x6a (106) = hash mismatch
│
├── FUN_14015f690 — InitOrchestrator
│   ├── PrimaryVMDetection (FUN_1402a5f20)
│   │   Server-pattern device fingerprinting + FNV-1a hashing
│   └── Returns: 0=blocked (CefShutdown), 1=proceed
│
├── Detection monitoring threads start
│
├── CEF browser init (Chrome/150.0.0.0)
│   User-Agent: CLDB 2.1.6.02
│
└── Message loop
    └── FUN_14022ab00 — TelemetryReporter (called periodically)
        20+ detection flags read, process list uploaded
```

**Build identifiers:** Version `2.1.6.02`, dated September 28, 2026, Chrome/150.0.0.0 engine.

### TelemetryReporter Detail (FUN_14022ab00)

10,313-byte function at `0x14022ab00` (22 non-contiguous ranges). Performs:

1. **IFEO anti-forensics** — `RegDeleteKeyExA` removes `utilman.exe` Image File Execution Options (debugger persistence vector)
2. **Display device matching** — Iterates display adapter list (`+0x9c0`), matches each against ~18 server-downloaded patterns from string table `0x12`
3. **Kernel timing cross-reference** — If `+0x46568 AND +0x4656c` both non-zero (SecureRDTSC detected VM overhead), reinforces display detection flags
4. **Audio/input device matching** — Second device list (`+0x9e0`), 8+ server patterns matched
5. **File existence check** — `PathFileExistsA` with server-supplied path (table `0x12[0x54d]`) → flag `0x47`
6. **Module blacklist scanning** — `K32EnumProcessModules` + `K32GetModuleFileNameExA` on own process, matches against two server-supplied blacklists
7. **Spyrix detection** — Hardcoded "Spyrix" string match (keylogger software)
8. **Process list upload** — Full process enumeration sent as `"process.list"` telemetry payload
9. **Flag dispatch** — `FUN_14013cc70(code, 0, 0)` as central flag reporter with codes: `5`, `0x47`, `0x49`, `0x4b`, `0x6d`, `0x6e`

### Detection Flag Map

| Offset | Type | Source | Description |
|--------|------|--------|-------------|
| `+0x0311` | byte | Display match | Server pattern `0xe77` |
| `+0x0312` | byte | Display match | Server pattern `0xe8e` |
| `+0x02e9` | byte | Display match | Server pattern `0xd35` |
| `+0x031c` | byte | Display match | Server pattern `0xe60` |
| `+0x04b8` | byte | Audio/input match | Server pattern `0xf18` |
| `+0x04b9` | byte | Display match | Server pattern `0x633` |
| `+0x04bb` | byte | VM composite | Display match `0x4ac` OR kernel timing |
| `+0x04bc` | byte | Audio/input match | Server pattern `0x68f` |
| `+0x0540` | byte | Audio/input match | Server pattern `0x564` |
| `+0x09b9` | byte | Display match | Server pattern `0xea5` |
| `+0x46465` | byte | Display match | Server pattern `0xe49` |
| `+0x46466` | byte | Audio/input match | Server pattern `0xf01` |
| `+0x46568` | int | Kernel IOCTL | SecureRDTSC result 1 |
| `+0x4656c` | int | Kernel IOCTL | SecureRDTSC result 2 |
| `+0x46690` | byte | Display match | Server pattern (table entry) |
| `+0x46693` | byte | Module scan | Any injected DLL detected |
| `+0x46694` | byte | Module scan | Injected DLL category B |
| `+0x46696` | byte | Module scan | Injected DLL category A |
| `+0x468b4` | dword | Process scan | Spyrix process info |
| `+0x46970` | int | Driver comm | FilterPort connection status |
| `+0x4696c` | int | Driver comm | Handshake result |

---

## Detection Systems — Usermode (LockDownBrowser.exe)

### 1. Foreground Window Polling 
**Window Security:** LDB runs a timer that calls `GetForegroundWindow()` and compares it against its own HWND. If ANY other window becomes foreground, the student is flagged.

| Evidence | Address |
|---|---|
| `"v2 GetForegroundWindow() == CLDB main or tab"` | `0x140b34598` |
| `"rldbfocus=1"` | `0x140b338c0` |
| `"rldbfocus=2"` | `0x140b338d0` |
| `"MAIN MOUSE focus = %d, pApp focus = %d mainframe = %d"` | `0x140b2b720` |

**How it works:**
- Timer fires every few hundred ms
- `GetForegroundWindow()` returns current foreground HWND
- If result != LDB main window AND result != LDB tab window → **FLAGGED**
- Focus state 1 = LDB has focus, state 2 = LDB lost focus
- Focus loss event packaged with window text, class name, PID of offending window
- Sent to server as `"flagged="` telemetry

**Bypass:** `WS_EX_NOACTIVATE` window style. Windows with this extended style never become the foreground window, so `GetForegroundWindow()` never returns their HWND.

### 2. Process Enumeration (PProcessListPSAPI)
Enumerates every running process and sends the full list to the server.

| Evidence | Address |
|---|---|
| `"process.list"`, `"Process List"`, `"process.list.processes"` | `0x140b35af0` |
| `"PProcessListPSAPI::GetProcessIDArray() FAILED"` | Various |
| `"Failed to send 1st process enumerate request"` | Various |

**APIs:** `K32EnumProcesses`, `K32EnumProcessModules`, `QueryFullProcessImageNameA/W`, `OpenProcess`

**How it works:**
- Calls `EnumProcesses()` to get all PIDs
- For each PID: `OpenProcess()` → `QueryFullProcessImageNameA()` → extract image name
- Builds structured list and sends encrypted to server
- Server compares against blocklist

**Bypass:** Process name must not match any blocked names.

### 3. Window Enumeration
Scans all visible windows to detect tools.

**APIs:** `FindWindowW`, `EnumWindows`, `GetWindowTextA/W`, `GetWindowThreadProcessId`

**How it works:**
- `EnumWindows()` iterates every top-level window
- For each: read window text, class name, owner PID
- Check against known tool signatures

### 4. AutoHotkey Detection
Specifically targets AutoHotkey by class name, then kills it.

| Evidence | Address |
|---|---|
| `"AutoHotkeyGUI"` | `0x140b34350` |
| `"AUTOHOTKEY - killing in timer kill"` | `0x140b34360` |

**How it works:**
- `FindWindowW(L"AutoHotkeyGUI", NULL)` — looks for AHK windows
- If found: `GetWindowThreadProcessId()` → `OpenProcess(PROCESS_TERMINATE)` → `TerminateProcess()`
- Runs on a timer — continuously checks

### 5. Screen Recording Detection
Detects and blocks Xbox Game Bar, OBS, and other recording software.

| Evidence | Address |
|---|---|
| `"DetectXboxAppRecordings() - capture detected, enabling BlockRecording"` | `0x140b356b0` |
| `"EnableBlockRecording - ENABLE - asr=%d, apd=%d, ilp=%d, rec=%d"` | `0x140b34880` |
| `"Allow screen recording - %s"` | `0x140b34808` |

Also specifically detects **Screencastify extension in Edge** — Portuguese-language error strings reference forced uninstall of Screencastify from all Edge profiles.

### 6. Clipboard Monitoring
Empties the clipboard to prevent copy-paste.

| Evidence | Address |
|---|---|
| `"Clipboard emptied"` | `0x140b2b6a0` |
| `"Windows.ApplicationModel.DataTransfer.Clipboard"` | `0x140b34260` |

**APIs:** `AddClipboardFormatListener`, `OpenClipboard`, `EmptyClipboard`, `CloseClipboard`

### 7. Thread Creation Hooks (HWBP)
Uses hardware breakpoints to detect thread injection.

| Evidence | Address |
|---|---|
| `"setup:hook_thread_create"` | `0x140b0c880` |
| `"setup:hwbp_thread_create_setup"` | `0x140b0c990` |
| `"setup:enumerating_threads"` | `0x140b0c8c0` |
| `"DetectResourceEditorHacksByThread()"` | `0x140b35670` |

**APIs:** `GetThreadContext`, `SetThreadContext`, `Thread32First`, `Thread32Next`, `CreateRemoteThread`

### 8. Focus Tracking via SetWinEventHook
Secondary focus detection using accessibility events.

**API:** `SetWinEventHook` — listens for `EVENT_SYSTEM_FOREGROUND` system-wide

### 9. Server-Side Flagging
All detection events are sent to the server as `"flagged="` key-value pairs.

| Evidence | Address |
|---|---|
| `"flagged="` | `0x140b2d8f0` |
| `"flagged"` | `0x140b2d9a0` |

### 10. NtReadVirtualMemory
Reads other processes' memory — likely for DWM integrity verification.

| Evidence | Address |
|---|---|
| `" : NtReadVirtualMemory()"` | `0x140b14108` |
| `"NtReadVirtualMemory"` | `0x140b14180` |

### 11. Display Monitor Fingerprinting
Enumerates all monitors including hardware properties.

**APIs:** `EnumDisplayMonitors`, `GetMonitorInfoA/W`, `DXVA2::GetMonitorBrightness/Contrast/ColorTemperature`, `GetPhysicalMonitorsFromHMONITOR`

### 12. CEF/Chromium Navigation Lockdown
Five distinct `OnBeforeBrowse` handlers control all browser navigation. The main handler (`CLDB_OnBeforeBrowse`, FUN_14006d100, 9853 bytes) is a 57,255-code-unit decision tree that intercepts every URL load. Full architecture documented in `cef_navigation.cpp`.

| Evidence | Address |
|---|---|
| `"OnBeforeBrowse - browser ID = %d, is-subframe = %d, type = %d, URL = %s"` | `0x00B1657D` |
| `"OnBeforeBrowse - ignoring because i, e, c = %d %d %d"` | `0x00B165C5` |
| `"OnBeforeBrowseLiveProctoring - %s"` | `0x00B289B8` |
| `"OnBeforeBrowseLiveChatSysCheck bid = %d url = %s"` | `0x00B2B778` |
| `"OnBeforeBrowseLiveChatGeneric bid = %d url = %s"` | `0x00B2B950` |
| `"AllowNavigation - rejecting from match with blacklist"` | String table |
| `"AllowNavigation - rejecting from match with profile blacklist"` | String table |
| `"AllowNavigation - matched SDK stem"` | String table |

**How it works:**
- Main handler: logs browser ID, subframe flag, navigation type, URL — applies dual blacklist/whitelist URL filtering with stem matching
- Conditional ignore handler: skips navigation checks based on internal flags (i, e, c)
- LiveProctoring handler: validates URLs for live proctoring sessions
- LiveChatSysCheck handler: system check for live chat feature
- LiveChatGeneric handler: generic live chat navigation
- `OnBeforeResourceLoad` monitors Canvas LMS state: `mon`, `ps`, `pcom`, `st`, `stcom`, `msg` parameters
- Chrome internal commands filtered (`filter-chrome-commands`) — blocks `chrome://` and DevTools
- DevTools conditionally disabled via `use_views` flag

**Hardcoded domain blocks:**
- `chromewebstore.google.com` — Chrome Web Store (extension installs blocked)
- `facebook.com` — Social media (exception: Moodle LMS type 0x51 with sub-type 0x73)
- `hangouts.google.com` — Google chat
- `twitter.com` — Social media
- `download.moodle.org/mobile` — Moodle mobile page

**Hardcoded domain allows:**
- `extension.respondus.com` — Respondus extension server
- `google-analytics.com` — Telemetry passthrough
- `tiny.cloud` / `tinymce.com` — Rich text editor CDN
- `chrome-extension://` — Conditional on browser state

**Custom protocols:** `rldb:` triggers app restart with new quiz URL (GetModuleFileNameA + relaunch). `&rldb` prefix on URL query params triggers CGI parameter handler (FUN_1401f9e10, 1121 bytes) — parses `rldbacv` (AES-256 challenge), `rldbcv` (standard challenge), `rldbwn` (navigation whitelist stem up to 32KB), `rldbtxt` (text injection), `rldbxb` (session flag), and 5 `rldbs*` settings params.

**Per-LMS routing** (DAT_140cedf60+0x480):
| Code | LMS | Main Handler | Special Behavior |
|------|-----|-------------|------------------|
| 0x15 | Blackboard | FUN_140053cb0 | launchAssessment.jsp quiz detect, /bbcswebdav/ file download |
| 0x3D | Canvas | FUN_140080ad0 | /files/.../download pattern |
| 0x47 | Sakai | FUN_1401ed3a0 | Dual handler variants |
| 0x51 | Moodle | FUN_140202db0 | facebook.com exception, rldbqn=1 |
| 0x5B | D2L | FUN_1401f3520 | rldbxb=1, quickLink.d2l subframe forcing |

**AllowNavigation core (FUN_1401cfc80) — OBFUSCATED:** This is the only VM/hash-chain protected function in the entire 20MB binary. Uses opaque predicates (`(retaddr-1)*retaddr & 1` ≡ 0), hash chain control flow (`val >> 0x1c ^ val << 4 ^ table[offset]`), and two 256+ entry data tables (0x140737258, 0x140737358). Ghidra decompiles to `halt_baddata()`. This function enforces the server-supplied URL blacklist/whitelist, profile blacklist, and SDK stem matching.

**Browser slot type system** (at DAT_140cedf80+0x8BCE per browser ID):
| Code | Slot Type | Trigger URL |
|------|----------|-------------|
| 0x02 | Generic popup | New window navigation |
| 0x03 | Blackboard quiz | launchAssessment.jsp |
| 0x05 | Monitor recording | ask.respondus.com/m1.htm |
| 0x06 | Monitor feedback | student_feedback_close.do |
| 0x07 | Webcam check | String table (0x23, 0x3AF) |
| 0x08 | Help center | String table (0x23, 0x3C6) |
| 0x09 | Spreadsheet | /ldb/spreadsheet_load.do |
| 0x0F | Live proctoring | ask.respondus.com/m15.htm |

**Tab limit enforcement:** Tracks at DAT_140cedf80+0x1E68, max at +0x1C68. Exceeding shows error dialog 0x55: "Too many tabs, current = %d, max = %d".

**Document download detection:** File extension matching against DAT_140b169ec for Word (.doc), Excel (.xls), PowerPoint (.ppt). Per-type enable flags at DAT_140cedf40+0x2AB/+0x2AC/+0x2AD. Downloads only processed when quiz is active.

**Kurzweil accessibility:** Special passthrough for Kurzweil text-to-speech (DAT_140cb17b0 active flag, URL pattern matching at DAT_140cb17c8).

### 13. Network & Telemetry Infrastructure
Direct AWS S3 upload with SigV4 authentication and MAC address fingerprinting.

| Evidence | Address |
|---|---|
| `"Authorization: AWS4-HMAC-SHA256 Credential=%s/%s/us-east-1/s3/aws4_request"` | `0x00B0F740` |
| `"upload_zip.do?token=%s&key=%s&studentKey=%s&type=%s&time=%s&mac=%s"` | Various |
| `"https://www.google-analytics.com/"` | Various |

**Server endpoints:**
- `ask.respondus.com` — primary API
- `file.respondus.com` — file transfer
- `extension.respondus.com` — browser extension management
- `downloads.respondus.com` — updates + Office template downloads (blank pptx/docx/xlsx)
- `d9unvfzorf0bo.cloudfront.net` — CloudFront CDN
- `ws.readspeaker.com` — ReadSpeaker text-to-speech integration
- `tiny.cloud` — TinyMCE rich text editor
- AWS S3 (`us-east-1`) — direct exam data upload with SigV4
- Google Analytics — embedded telemetry

**Upload format:** `upload_zip.do?token=%s&key=%s&studentKey=%s&type=%s&time=%s&mac=%s` — includes device MAC address as hardware fingerprint.

### 14. Registry Policy Manipulation
Modifies Windows group policy registry keys to enforce lockdown.

| Target | Purpose |
|---|---|
| `Policies\Google\Chrome` | Prevents parallel Chrome browser use |
| `Policies\System` | May disable Task Manager, Registry Editor, CMD |
| `Policies\Explorer` | May disable Run dialog, context menu items |

### 15. Anti-Debug
Minimal anti-debug — `IsDebuggerPresent` (PEB.BeingDebugged) and hardware breakpoint detection (`debug_registers` — DR0-DR3 inspection). No `NtQueryInformationProcess`, no `ThreadHideFromDebugger`, no timing checks, no `int2d` tricks.

### 16. Integrity Checking (PE + TLSH)
Validates binary integrity using two methods:

| Method | Evidence |
|---|---|
| PE checksum | `"checksum = %ld; the header checksum = %ld"` |
| TLSH fuzzy hash | `"tlsh that is already valid"` |

**TLSH** (Trend Micro Locality Sensitive Hash) detects modified/patched binaries even when the exact hash differs — catches binary patches that traditional hash checks would miss.

### 17. Single Instance Enforcement
Two mutexes prevent multiple instances:

| Mutex | Purpose |
|---|---|
| `Local\{C15730E2-145C-4c5e-B005-3BC753F42475}-once-flag` | Static GUID — global single instance |
| `Local\87543720949%u41187%u2617649587` | Dynamic — numeric obfuscation with PID |

### 18. Webcam & Audio Capture (Respondus Monitor)
Camera hotplug detection with retry logic and legacy WinMM audio capture.

| Evidence | Address |
|---|---|
| `"webcam new camera connected = (%s)"` | `0x00B16BF0` |
| `"webcam DISconnected = (%s)"` | Various |
| `"webcam RE-connected = (%s)"` | Various |
| `"camera reconnect = %d, camera retry = %d"` | Various |

**Audio:** Uses `waveIn*` APIs (WinMM), not Media Foundation. No local ML/face detection — all processing is server-side.

**Proctoring endpoints:** `proctoring_start_cancel.do`, `proctoring_continue.do`

### 19. Display Affinity
Uses `SetWindowDisplayAffinity` to prevent screen capture.

- `WDA_EXCLUDEFROMCAPTURE` (Windows 10 2004+) — content appears black in captures
- `WDA_MONITOR` fallback for older Windows — shows wallpaper instead
- Backed by driver-side DWM.exe integrity verification

### 20. Offline Exam Caching
Supports offline exam delivery with retry logic.

| Evidence |
|---|
| `"offline=%d course=%s test=%s cached=%d cached-id=%s Is retry = %d"` |

### 21. VM Detection
LDB uses a **hybrid client-engine / server-data VM detection architecture**. The binary contains the detection ENGINE but stores ZERO detection DATA — all VM vendor strings, registry paths, and device patterns are **downloaded from Respondus servers at runtime**. This design deliberately defeats static analysis.

**Layer 1 — Server-Driven Device Fingerprinting (Primary):**

| Component | Address | Mechanism |
|---|---|---|
| Primary Engine | `FUN_1402a5f20` (3752 bytes) | `SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_PRESENT\|DIGCF_ALLCLASSES)` → reads `SPDRP_DEVICEDESC` + `SPDRP_PHYSICAL_DEVICE_OBJECT_NAME` → compares against 17+ server patterns from `DAT_140cedf80+0x233e8` using case-insensitive matching |
| Secondary Engine | `FUN_140231310` (1619 bytes) | Structured pattern vector at `DAT_140cedf40+0x46678` with AND/OR compound logic, >1 mismatch threshold |
| FNV-1a Hash Lookup | Within `FUN_1402a5f20` | 64-bit hash (basis `0xcbf29ce484222325`, prime `0x100000001b3`) for fast device fingerprinting |
| String Table Indexer | `FUN_14021ad30` | Indexes into server-populated SSO `std::string` arrays at `DAT_140cedf48`. Called with indices `(0x12, 0xa83)`, `(0x12, 0xcab)`, `(0x12, 0xcc2)`, `(0x12, 0x26d)` |
| Server Config Structure | `DAT_140cedf80 + 0x233e8` | 17+ string pointers: registry key paths (+0x00/+0x28/+0x50), value names (+0x18/+0x30/+0x58), VM patterns (+0x10/+0x20/+0x38/+0x40/+0x48/+0x60/+0x80) |

**Layer 2 — Kernel-Level Timing Analysis (Supplementary):**

| IOCTL Command | String Address | Purpose |
|---|---|---|
| `SecureRDTSC` | `0x140b0c780` | Executes RDTSC from **ring 0**, bypassing usermode VM exit interception |
| `FSecureClock` | `0x140b0c7a0` | Tamper-resistant clock source, harder to manipulate in VM |
| `ActiveCheck` | IOCTL table `0x140cb01f8` | Undocumented — likely liveness check |
| `UserCheck` | IOCTL table | Undocumented — likely environment check |
| `AntiDebug` | IOCTL table | Kernel-level debug detection |

**Layer 3 — Server-Side Telemetry Analysis (Parallel):**
Hardware fingerprint uploaded to Respondus servers includes MAC addresses (in URL: `&mac=%s`), CPU name/MHz, RAM, OS version, monitor info, webcam names. Server can independently detect VMs via MAC OUI analysis (VMware `00:0C:29`, VirtualBox `08:00:27`, etc.).

**Virtual Webcam Detection:**
`FUN_140260c50` at `0x140260c50` — uses DirectShow COM to enumerate webcams, checks FriendlyName for `"virtual"` substring (the **only** plaintext VM keyword in the entire binary) + encrypted name from server string table index `0xbdc`. Result flag: `DAT_140cedf40+0x46582`.

**Detection Result Flags (all at base `DAT_140cedf40`):**

| Offset | Purpose | Set By |
|---|---|---|
| `+0x46560` | Primary device match bitmask | `FUN_1402a5f20` |
| `+0x46564` | Extra pattern match bitmask | `FUN_1402a5f20` |
| `+0x46580` | Mismatch threshold exceeded | `FUN_140231310` |
| `+0x46582` | Virtual webcam detected | `FUN_140260c50` |

**v3 Negative Results (confirmed absent from all binaries):**
- Zero VM vendor strings in any binary (VMware, VirtualBox, QEMU, Hyper-V, KVM, Xen)
- Zero WMI queries (no `SELECT`, `Win32_ComputerSystem`, etc.)
- Zero CPUID hypervisor detection in any binary
- Zero SMBIOS/firmware table queries
- Zero MAC OUI prefix comparison logic (client-side)
- Zero VM-specific process name lists
- LockDownBrowser.dll contains zero detection logic (pure input hooking)
- Kernel driver contains zero VM detection logic (confirmed across 310 procedures)

### 22. JavaScript DOM Injection Engine
LDB embeds **11 JavaScript scripts** directly in the EXE's `.rdata` section, injected into loaded LMS pages via CEF's `CefFrame::ExecuteJavaScript()`. All use `window.setInterval()` for persistent enforcement (re-run every 1000-2500ms). Full catalog in `dom_injection.cpp`.

| # | Address | Size | Target | Key Elements Stripped |
|---|---------|------|--------|----------------------|
| 1 | `0x140b14cf0` | 428B | Canvas/Generic | "Insert/edit link", "Add content", "Source code" buttons |
| 2 | `0x140b17d50` | 536B | Panopto | save/mp3/report/share buttons, `#pw-main-sidenav` |
| 3 | `0x140b2b460` | 364B | ALL (additive) | **Injects** ReadSpeaker TTS from `ws.readspeaker.com` |
| 4 | `0x140b2d9e0` | 3124B | Moodle | nav-drawer, TinyMCE/Atto editor, messaging, breadcrumbs, 15+ elements |
| 5 | `0x140b2e620` | 188B | Moodle | `.m-t-2.m-b-1` margin element |
| 6 | `0x140b31290` | 1164B | Blackboard | audiorecorder, print icon, SCAYT spell check, exittoc button |
| 7 | `0x140b31d10` | 336B | Sakai | Image/Media button (`original-title`) |
| 8 | `0x140b31e60` | 172B | Generic | `#header` element |
| 9 | `0x140b31f10` | 212B | D2L | `.js-save-draft-button` |
| 10 | `0x140b32100` | 524B | Canvas RCE | links/images/record-upload-media div buttons |
| 11 | `0x140b32ba0` | 452B | Generic | Preview links → replaced with "Click to open:" text |

**Three-layer lockdown architecture:**
1. **URL layer** — `CLDB_OnBeforeBrowse` controls which pages load
2. **DOM layer** — JavaScript injection controls what content is visible/accessible
3. **Input layer** — `LockDownBrowser.dll` hooks control what keys/actions function

### 23. Exit Password (Multilingual)
Exit password prompt appears in 5 languages: English, German, French, Portuguese, Italian — indicating international deployment.

---

## Detection Systems — Kernel Driver (LockDownService215.sys)

The driver is a **FLTMGR minifilter** that provides kernel-level monitoring capabilities that usermode processes cannot detect or circumvent.

**Verified class map**: 12 C++ classes, 30+ methods — all names from debug strings in `.rdata` section.

### 1. Communication Port (\ApDriverPort)
Encrypted bidirectional channel between driver and LDB.

| Evidence | Address |
|---|---|
| `"BrowserCommunicationPort::onConnect"` | `0x14000A310` |
| `"BrowserCommunicationPort::onDisconnect"` | `0x14000A3D0` |
| `"\ApDriverPort"` (UTF-16) | `0x14000D510` |
| `"%s: Detect new browser PID %d"` | `0x14000A3B0` |
| `"%s: FltCreateCommunicationPort() \| status = 0x%08X"` | `0x14000BA50` |
| `"%s: FltSendMessage() \| status = 0x%08X"` | `0x14000BAC0` |
| `"%s: Invalid IRQL for FltCloseCommunicationPort (IRQL:%u)"` | `0x14000B9A0` |

- Port name: `\ApDriverPort`
- PID validation on connect — only the verified LDB process can connect
- RSA-2048 **keypair generated in kernel** → public key exported to usermode → AES session key exchange → AES-CBC encrypted messages
- Validates both retail and OEM paths: `\Program Files\Respondus\LockDown Browser\LockDownBrowser.exe` and `\Program Files\Respondus\LockDown Browser OEM\LockDownBrowserOEM.exe`

#### FilterPort Command Protocol

Complete command dispatch decompiled from `BrowserCommunicationPort::onMessage` (FUN_1400015c0, vtable slot 4 at 0x14000d558+0x20).

| Cmd | Tag | EXE Name | Description |
|-----|-----|----------|-------------|
| 0 | — | *(handshake)* | Export RSA-2048 public key (RSAPUBLICBLOB) |
| 1 | — | *(handshake)* | Import AES session key (RSA-encrypted by client) |
| 2 | — | *(handshake)* | Activate encrypted channel (sets per-connection flag) |
| 3 | — | *(envelope)* | AES-CBC decrypt → recursive re-dispatch of inner command |
| 4 | 0x05 | UserCheck | Full process table from AVL tree (0xf0c bytes/entry) |
| 6 | 0x07 | AntiDebug | Image/module load data for LDB process (slot 0, 0x710 bytes/entry) |
| 8 | 0x09 | AntiDebug | Image/module load data for DWM process (slot 1, 0x710 bytes/entry) |
| 0xC | copy | UserCheck | Single process detail lookup by PID |
| 0xD | 0x0E | UserCheck | Compact PID list (count × 4 + 8 bytes) |
| 0xF | 0x10 | FSecureClock | Thread creation counters (2 × DWORD: LDB slot + DWM slot) |
| 0x11 | 0x12 | *(internal)* | RSA key fingerprint / identifier (0x18 bytes) |
| 0x13 | — | ActiveCheck | Set per-connection heartbeat byte (flags connection alive) |
| 0x14 | 0x15 | SecureRDTSC | Verify thread start addresses — anti-injection check |

**Key insight:** "SecureRDTSC" on the EXE side does NOT measure RDTSC. The kernel handler (`ThreadMonitor::verifyFilelessExecution`) validates that each reported thread's start address maps to a file-backed memory region. Returns 2 (clean) or 3 (fileless/injected code detected). This is the core **anti-injection mechanism** — catches manual-mapped DLLs, shellcode, and reflective loading.

**Encryption protocol:** After the 3-step RSA/AES handshake (cmds 0→1→2), all subsequent commands are wrapped in cmd 3 (AES-CBC envelope). The encrypted response header is 0x108 (264) bytes: AES IV + padding + ciphertext alignment.

**Subsystem pointers:**
- `DAT_14000f080` → ProcessMonitor (AVL tree, PsSetCreateProcessNotifyRoutineEx)
- `DAT_14000f088` → ImageLoadMonitor (PsSetLoadImageNotifyRoutine, dual PID slots)
- `DAT_14000f090` → ThreadMonitor (PsSetCreateThreadNotifyRoutine, counters)
- `DAT_14000f098` → DriverLogger

### 2. Process Monitor (PsSetCreateProcessNotifyRoutineEx)
**Kernel-level process creation/termination callbacks.** Catches EVERY process start/stop on the system — cannot be evaded from usermode.

| Evidence | Address |
|---|---|
| `"ProcessMonitor::start"` | `0x14000BD20` |
| `"ProcessMonitor::processCallback"` | `0x14000BE60` |
| `"ProcessMonitor::notifyProcessInfo::<lambda_1>::operator ()"` | `0x14000BDE0` |

- Tracks all processes in an AVL tree (`RtlInitializeGenericTableAvl`) — each entry = **0xf0c (3852) bytes**
- Gets image path, parent PID, command line (via PEB), signing level
- Special tracking for DWM PID — clears ImageLoadMonitor slot 1 and ThreadMonitor counter 1 on DWM exit
- Sends all events to usermode LDB via FltSendMessage
- Uses deferred work items (`FltQueueGenericWorkItem`) for IRQL safety
- Full callback decompiled (FUN_140008900): on creation populates 0x58-byte info struct → AVL insert → notify usermode; on termination removes entry, clears tracked PID slots if matching, notifies usermode even for uncached processes

### 3. Thread Monitor (PsSetCreateThreadNotifyRoutine)
Monitors all thread creation system-wide.

| Evidence | Address |
|---|---|
| `"ThreadMonitor::start"` | `0x14000BF80` |
| `"ThreadMonitor::stop"` | `0x14000BFE0` |
| `"ThreadMonitor::verifyFilelessExecution"` | `0x14000C040` |

**Key feature: Fileless execution detection.**
- For each new thread, queries `ZwQueryInformationThread` for start address
- Checks if start address maps to a legitimate loaded image via `ZwQueryVirtualMemory`
- If start address is NOT in any loaded module → **code injection detected**
- This catches DLL injection, shellcode execution, reflective loading
- Full decompilation of `verifyFilelessExecution` (FUN_1400094e0): opens process/thread by ID → `ZwQueryInformationThread(ThreadQuerySetWin32StartAddress)` → `ZwQueryVirtualMemory(MemoryMappedFilenameInformation)` on start address → returns 2 (file-backed, clean) or 3 (fileless, injected). Error paths return -1.
- Thread callback (FUN_140009460) tracks exactly 2 PID slots: slot 0 = LDB process, slot 1 = DWM process. Threads in untracked processes are silently ignored.

### 4. Image Load Monitor (PsSetLoadImageNotifyRoutine)
Monitors every DLL/EXE load in every process on the system.

| Evidence | Address |
|---|---|
| `"ImageMonitor::imageCallback"` | `0x14000B8E0` |

- Reports each image load path and base address to usermode
- Used to detect injected DLLs and hooking frameworks
- Dual PID slot architecture: slot 0 (offset +0x278) = LDB PID, slot 1 (offset +0x318) = DWM PID. Each slot stores up to 0x710 (1808) bytes per loaded image. Initialized in FUN_140006dac via `PsSetLoadImageNotifyRoutine(FUN_140006a60)`.

### 5. Code Integrity Verification
Validates digital signatures at the kernel level using `ci.dll`.

| Evidence | Address |
|---|---|
| `"CodeIntegrity::calculateSha1"` | `0x14000AA50` |
| `"CiValidateFileObject() \| status = 0x%08X"` | `0x14000A980` |
| `"SHA1"` (UTF-16) | `0x14000AA40` |
| `"SHA256"` (UTF-16) | `0x14000B4D0` |

- `CiValidateFileObject()` — undocumented CI.DLL export, resolved at runtime via `RtlFindExportedRoutineByName`
- SHA1 and SHA256 hashing of binaries
- Checks signer: `"Respondus, Inc."`
- Checks CA: `"DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"`

### 6. DWM Integrity Verification
Verifies Desktop Window Manager hasn't been tampered with.

| Evidence | Address |
|---|---|
| `"DwmImageResolver::init"` | `0x14000AF10` |
| `"DwmImageResolver::initPath"` | `0x14000AF30` |
| `"\Windows\System32\dwm.exe"` (UTF-16) | `0x14000D738` |

- Locates `\Windows\System32\dwm.exe`
- Validates owner SID: `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464` (NT SERVICE\DWM)
- Maps DWM into kernel space for byte-level inspection
- Validates signature is Microsoft-signed
- Limitation: Cannot verify if driver loaded after DWM

### 7. Browser Binary Validation
Verifies the connecting LDB binary is genuine.

| Evidence | Address |
|---|---|
| `"BrowserImageResolver::init"` | `0x14000A7D0` |
| `"\Program Files\Respondus\LockDown Browser\LockDownBrowser.exe"` (UTF-16) | `0x14000D5A0` |
| `"\Program Files\Respondus\LockDown Browser OEM\LockDownBrowserOEM.exe"` (UTF-16) | `0x14000D620` |
| `"DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"` | `0x14000D6C0` |

- Checks path against known install locations (retail + OEM)
- Parses PE version info: CompanyName, FileVersion, OriginalFilename
- Validates code signature via `FltCreateFileEx` → `CiValidateFileObject`
- Calculates SHA1 hash

### 8. Kernel Cryptography
Full RSA + AES-CBC stack in kernel mode. RSA keypair is **generated in kernel**, not just imported.

| Evidence | Address |
|---|---|
| `"CryptoKernel::generateRsaKeypair"` | `0x14000B610` |
| `"CryptoKernel::setRsaKey"` | `0x14000B480` |
| `"CryptoKernel::setAesKey"` | `0x14000B4E0` |
| `"CryptoKernel::randomIv16"` | `0x14000B400` |
| `"CryptoKernel::aesCbcEncrypt"` | `0x14000B6F0` |
| `"CryptoKernel::aesCbcDecrypt"` | `0x14000B6A0` |
| `"CryptoKernel::decryptIV"` | `0x14000B5F0` |

**Protocol**:
1. Driver generates RSA-2048 keypair in kernel (`BCryptGenerateKeyPair`)
2. Public key exported to usermode via FilterPort (`RSAPUBLICBLOB`)
3. Usermode encrypts AES session key with driver's RSA public key
4. Driver decrypts with private key (`CryptoKernel::decryptIV`)
5. All subsequent messages AES-CBC encrypted with random 16-byte IVs (`BCryptGenRandom`)
6. 17 BCrypt API imports total

### 9. PEB Command Line Reader
Reads any process's command line from kernel space.

- `KeStackAttachProcess` — Attaches to target process context
- `PsGetProcessPeb` — Gets PEB address
- Reads `ProcessParameters->CommandLine` with SEH protection (`"SEH: %lu"`)
- `KeUnstackDetachProcess` — Detaches

### 10. System Boot Chain Validation
Verifies system startup is legitimate.

| Evidence | Address |
|---|---|
| `"UserModeDetector::init"` | `0x14000C120` |
| `"UserModeDetector::getStartupInfo"` | `0x14000C140` |
| `"UserModeDetector::findSmss"` | `0x14000C170` |

- `UserModeDetector::findSmss` — Locates `\Windows\System32\smss.exe`
- Validates the Session Manager is running and legitimate
- Part of anti-sandbox/anti-VM detection

### 11. Dynamic Function Resolution
Resolves undocumented kernel APIs at runtime to avoid static import detection.

| Evidence | Address |
|---|---|
| `"DynamicFunctionsKm::psGetProcessPeb"` | `0x14000B2C0` |
| `"DynamicFunctionsKm::ciFreePolicyInfo"` | `0x14000B2F0` |
| `"DynamicFunctionsKm::ciValidateFileObject"` | `0x14000B320` |

Resolved via `MmGetSystemRoutineAddress`:
- `PsGetProcessInheritedFromUniqueProcessId`
- `PsGetProcessPeb`
- `PsGetProcessSignatureLevel`
- `SeGetCachedSigningLevel`

Resolved via `RtlFindExportedRoutineByName` from `\systemroot\system32\ci.dll`:
- `CiValidateFileObject`
- `CiFreePolicyInfo`

### 12. Driver Logging
File-based kernel logging with auto-rotation — 6 methods verified from debug strings.

| Method | Purpose |
|---|---|
| `DriverLogger::createLogFile` | Create timestamped log file |
| `DriverLogger::buildTodaysLogFilePath` | Construct daily log path |
| `DriverLogger::findNextLogFileSuffix` | Numeric suffix for log rotation |
| `DriverLogger::deleteOldLogFiles` | Purge expired logs |
| `DriverLogger::deleteLogFile` | Remove specific log file |
| `DriverLogger::log` | Write formatted message |

All kernel log messages follow format: `"%s: <function>() | status = 0x%08X\n"`

### What the Driver Does NOT Do
Verified absent from 310 procedures and 294 strings:
- **ObRegisterCallbacks** — no process/thread handle protection
- **CmRegisterCallbackEx** — no registry monitoring/filtering
- **WFP (Wfp\*/FWPM\*)** — no network filtering
- **MmCopyVirtualMemory** — no cross-process memory operations
- **SSDT hooking** — no syscall table modification
- **String obfuscation** — all debug strings in cleartext `.rdata`

---

## Server-Side Detection Configuration Parser

**Address:** `FUN_1402905b0` (7066 bytes, 43 callees)

The EXE downloads an XML configuration blob from Respondus servers at startup. This parser populates the global state structure (`DAT_140cedf40`, ~305KB) with server-driven detection parameters. All detection patterns are **dynamic** — the server controls what gets flagged.

### XML Schema (from decompiled parser)

```xml
<institution>
  <!-- License validation -->
  <!-- param_1 + 0x1518: institution name -->
  <!-- param_1 + 0x14f8: institution ID -->
  <!-- param_1 + 0x1538: license month (1-12) -->
  <!-- param_1 + 0x153c: license year (must be 2005-2039) -->

  <vmkb>
    <!-- VM keyboard detection patterns — up to 50 entries -->
    <!-- Each pattern is a string > 8 chars, stored at param_1 + 0xcb0 -->
    <!-- Counter at param_1 + 0x12f0, max 0x32 (50) -->
    <!-- These are WMI/registry signature strings downloaded from server -->
  </vmkb>

  <resedit>
    <rerow>
      <!-- Resource editor whitelist — 3 fields per row + byte count -->
      <!-- Field 1: process name -->
      <!-- Field 2: "white" (whitelist hash/signature) -->
      <!-- Field 3: additional identifier -->
      <!-- Field 4: "bytes" (file size for verification) -->
      <!-- Each entry = 0x68 bytes in vector at DAT_140cedf80 + 0xef68 -->
    </rerow>
  </resedit>

  <navbl>
    <!-- Navigation blacklist — up to 24 (0x18) LMS-type entries -->
    <!-- Stored at DAT_140cedf60 + 0x3e60 (count) + 0x3e64 (type array) -->
    <nitem>
      <!-- Each item checked against hardcoded LMS types: -->
      <!--   Blackboard 6, Instructure, Sakai, SDK 2015, Moodle, -->
      <!--   Angel, Desire2Learn - Beta, WebCT Vista/6/4 -->
      <!-- Unrecognized LMS → type code 0x29a (666) -->
    </nitem>
  </navbl>

  <appswitch>
    <api>
      <!-- Application switching policies — per-API rules -->
      <!-- Field 1: API name string -->
      <!-- Field 2: type code ('E'=1 Enable, 'P'=2 Prompt, 'S'=3 Suppress) -->
      <!-- Field 3: secondary name string -->
      <!-- Field 4: secondary type code (same E/P/S scheme) -->
      <!-- Field 5: boolean flag -->
      <!-- Each entry = 0x50 bytes in vector at DAT_140cedf40 + 0x464a0 -->
    </api>
  </appswitch>

  <hackfiles>
    <hackfile>
      <!-- Binary tamper detection — server-supplied byte patterns -->
      <!-- "offset": file offset to check (integer) -->
      <!-- "bytes": hex-encoded known-good bytes (must be >= 51 chars, even) -->
      <!-- Decoded to binary via FUN_14029ff20 (hex-to-bytes) -->
      <!-- Each entry = 0x10 bytes in vector at DAT_140cedf80 + 0xf388 -->
      <!-- Used to detect patched/modified LDB executables -->
    </hackfile>
  </hackfiles>

  <!-- Additional tokenizer-parsed config fields: -->
  <!-- Per-detection boolean enable/disable flags (checks against "false") -->
  <!-- Numeric parameters with range validation (3-500) -->
  <!-- Bracket-delimited URL/pattern arrays parsed via 0x5b ('[') delimiter -->
</institution>
```

**Detection surface implications:**
- VM detection patterns are entirely server-driven (no hardcoded signatures in the binary)
- Binary tamper detection compares specific file offsets against server-supplied known-good bytes
- Navigation blacklist uses LMS-type identification to apply per-institution URL policies
- Application switching rules are per-API and server-configurable
- All of this config is downloaded fresh each session — patterns can change without an update

---

## Server Infrastructure

| Endpoint | Purpose |
|---|---|
| `ask.respondus.com` | Primary API server |
| `file.respondus.com` | File transfer |
| `extension.respondus.com` | Browser extension management |
| `downloads.respondus.com` | Software updates, Office template downloads |
| `d9unvfzorf0bo.cloudfront.net` | CloudFront CDN |
| `s3.amazonaws.com` (us-east-1) | Direct exam data upload (SigV4 auth) |
| `ws.readspeaker.com` | ReadSpeaker text-to-speech integration |
| `tiny.cloud` | TinyMCE rich text editor |
| `google-analytics.com` | Embedded telemetry |

---

## Source Files

```
├── README.md                        ← This file
├── usermode_detections.cpp          ← Pseudocode for LockDownBrowser.exe detections
├── driver_detections.cpp            ← Pseudocode for LockDownService215.sys
├── vm_detection.cpp                 ← VM detection engine pseudocode
├── input_lockdown.cpp               ← LockDownBrowser.dll input hooking pseudocode
├── cef_navigation.cpp               ← CEF URL filtering & navigation policy engine
└── dom_injection.cpp                ← 11 hardcoded JavaScript DOM manipulation scripts
```

Each pseudocode file contains:
- Reconstructed C++ class structures matching the binary's debug strings
- Every referenced Win32/kernel API call
- String evidence with exact addresses in the binary
- Inline explanation of detection logic and bypass vectors

---

## Key Takeaways

1. **Foreground polling is the weakest link.** `GetForegroundWindow()` is trivially bypassed with `WS_EX_NOACTIVATE`. LDB relies heavily on this for real-time detection.

2. **The kernel driver is serious.** Process/thread/image callbacks at the kernel level cannot be evaded from usermode. However, the driver only *monitors and reports* — it does not block. All enforcement happens in usermode.

3. **Communication is encrypted.** Driver↔usermode messages use RSA+AES-CBC. The RSA keypair is generated **in kernel** — sniffing the FilterPort won't reveal detection data.

4. **Process names are checked server-side.** The full process list is sent to the server. Disguising as a system process avoids server-side blocklist matching.

5. **DWM integrity is checked.** If you hook DWM to bypass `SetWindowDisplayAffinity`, the driver will detect the tampering.

6. **Debug strings are everywhere.** Respondus ships with extensive logging — this is how most detection routines were identified. A release build with stripped strings would be significantly harder to reverse.

7. **Binary hardening is weak.** ASLR disabled on the 20MB EXE, CFG table compiled but empty, driver signed with WDK test cert. The EXE is a fixed-address target with no control-flow guard.

8. **MAC address fingerprinting.** Exam uploads include device MAC address. Each submission is hardware-fingerprinted.

9. **TLSH fuzzy hashing catches patches.** Beyond simple checksums, TLSH locality-sensitive hashing detects modified binaries even when exact hashes differ.

10. **VM detection is server-driven.** The binary contains the detection ENGINE (SetupDi device enumeration, FNV-1a hash matching, string comparison) but all VM vendor names and patterns are downloaded from Respondus servers at runtime. Static analysis alone cannot enumerate detection vectors.

11. **Anti-debug is minimal.** Only `IsDebuggerPresent` and hardware breakpoint checks. No advanced anti-debug techniques — a standard debugger with PEB patch bypasses it.

12. **Kernel timing detection.** The driver provides `SecureRDTSC` (ring 0 RDTSC execution) and `FSecureClock` IOCTL commands. VM-induced RDTSC latency is measurable from ring 0 and extremely difficult to mask.

13. **Code signing is CA-pinned.** The kernel driver pins to `DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1` — not just any valid Authenticode signature. Prevents loading of arbitrary signed DLLs.

14. **LockDownBrowser.dll is pure input hooking.** 116KB, 473 procedures, 302 strings — zero VM detection. Exports 4 functions implementing configurable WH_KEYBOARD_LL + WH_CBT + WH_SHELL hooks with 5 keyboard aggression levels.

15. **UserModeDetector is boot chain integrity, NOT anti-VM.** Despite the name, it only verifies smss.exe runs from the expected boot device and reports system uptime. No VM detection decision made in driver.

16. **URL blacklist core is the most protected code in the binary.** AllowNavigation (FUN_1401cfc80) uses VM-style hash-chain obfuscation with opaque predicates — the ONLY function in the entire 20MB EXE with this level of protection. The URL policy is considered more security-critical than any other detection mechanism.

17. **Navigation filtering is multi-layered.** Five hardcoded domain blocks, server-driven blacklist/whitelist from XML config, per-LMS URL routing for 5 LMS types, CGI challenge-response authentication (AES-256 + standard), browser slot type assignment, tab limits, and document download detection — all enforced through the 9853-byte CLDB_OnBeforeBrowse handler.

18. **CGI parameter protocol is the server→browser control channel.** The `rldb*` URL query parameter system lets the LMS server inject whitelist entries (`rldbwn`, up to 32KB), trigger authentication challenges (`rldbacv`/`rldbcv`), set session flags (`rldbxb`), and inject text content (`rldbtxt`) — all via crafted URLs in the exam page.

19. **11 JavaScript DOM injection scripts strip LMS features at page level.** Hardcoded in the EXE's .rdata section, injected via CEF's ExecuteJavaScript on setInterval (1000-2500ms). They remove navigation (nav drawers, breadcrumbs, headers, activity links), rich text editor features (image/link/media insert, HTML source, SCAYT spell check), communication tools (messaging overlay/drawer), and media controls (audio recorder, video save/share, file preview). Coverage: Moodle (most targeted), Canvas, Sakai, D2L, Blackboard, Panopto. ReadSpeaker TTS is the only ADDITIVE injection — accessibility compliance.

20. **Three-layer enforcement architecture.** Layer 1: URL-level filtering (OnBeforeBrowse — which pages load). Layer 2: DOM-level injection (JavaScript — what content is visible). Layer 3: Input-level hooking (LockDownBrowser.dll — what keys/actions work). All three must be bypassed to fully escape the lockdown.

---

## Disclaimer

This is an independent security analysis. All information was derived from static analysis of locally-installed software.
