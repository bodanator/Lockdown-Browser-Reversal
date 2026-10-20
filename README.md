# Reverse Engineering Analysis

A complete reverse engineering breakdown of Respondus LockDown Browser's anti-cheat detection systems, covering both the usermode application (`LockDownBrowser.exe`) and the kernel driver (`LockDownService215.sys`).

---

## Target Binaries

| Binary | Path | Size | SHA256 |
|---|---|---|---|
| `LockDownBrowser.exe` | `C:\Program Files\Respondus\LockDown Browser\` | ~20 MB | `86f39c5a239a0ff69f3e6b3bd8833f455eecbbacc2890fe68819425098bc8040` |
| `LockDownService215.sys` | `...\Service\x64\` | ~45 KB | `a6d54547a8db751a2f0844252848fc1b997f56b594c78f82a6259496e221b501` |

- **LockDownBrowser.exe**: PE x86_64, MFC/CEF-based application built with MSVC from `C:\vs12\LockDownChrome\`
- **LockDownService215.sys**: PE x86_64, FLTMGR minifilter kernel driver, v2.16.0.0, signed by Respondus via DigiCert RSA4096 SHA384

---

## Methodology

### Tools Used
- **Ghidra 12.1.2** — Primary disassembler and decompiler
- **Manual string analysis** — LDB ships with extensive debug/logging strings that reveal function names, class names, and control flow

### Approach
1. **String harvesting** — LDB's debug strings are the Rosetta Stone. Searched for detection-related keywords: `focus`, `process`, `flagged`, `detect`, `monitor`, `hook`, `recording`, `clipboard`, `AutoHotkey`, `driver`, `encrypt`, `DWM`, `thread`
2. **Import table analysis** — Mapped all Win32 API imports to identify detection capabilities
3. **Cross-referencing** — Traced string references back to their containing functions to understand control flow
4. **Driver analysis** — Full string dump of the kernel driver revealed its class hierarchy and monitoring architecture
5. **Pseudocode reconstruction** — Combined string evidence, imports, and decompiler output into readable C++ pseudocode

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                    Respondus Server                       │
│  (receives "flagged=" events, process lists, telemetry)  │
└─────────────────────────┬────────────────────────────────┘
                          │ HTTPS (AWS S3 / custom endpoints)
                          │ AES-256 encrypted payloads
                          │
┌─────────────────────────┴────────────────────────────────┐
│              LockDownBrowser.exe (Usermode)               │
│                                                          │
│  ┌─────────────────┐  ┌──────────────────┐              │
│  │ Focus Monitor   │  │ Process Scanner  │              │
│  │ GetForeground   │  │ PSAPI Enum       │              │
│  │ SetWinEventHook │  │ TerminateProcess │              │
│  └────────┬────────┘  └────────┬─────────┘              │
│           │                    │                         │
│  ┌────────┴────────┐  ┌───────┴──────────┐              │
│  │ Window Scanner  │  │ Recording Block  │              │
│  │ EnumWindows     │  │ Xbox/OBS detect  │              │
│  │ FindWindowW     │  │ Display Affinity │              │
│  └────────┬────────┘  └────────┬─────────┘              │
│           │                    │                         │
│  ┌────────┴────────┐  ┌───────┴──────────┐              │
│  │ Clipboard Mon   │  │ Thread Monitor   │              │
│  │ AddClipboard    │  │ HWBP hooking     │              │
│  │ FormatListener  │  │ Thread32First    │              │
│  └────────┬────────┘  └────────┬─────────┘              │
│           │                    │                         │
│           └────────┬───────────┘                         │
│                    │                                     │
│         ┌──────────┴───────────┐                         │
│         │  Driver Comm Client  │                         │
│         │  \ApDriverPort       │                         │
│         │  RSA+AES encrypted   │                         │
│         └──────────┬───────────┘                         │
└────────────────────┼─────────────────────────────────────┘
                     │ FilterPort (encrypted)
                     │
┌────────────────────┼─────────────────────────────────────┐
│                    │   LockDownService215.sys (Kernel)    │
│         ┌──────────┴───────────┐                         │
│         │  Communication Port  │                         │
│         │  \ApDriverPort       │                         │
│         │  PID validation      │                         │
│         └──────────┬───────────┘                         │
│                    │                                     │
│  ┌─────────────────┼──────────────────────┐              │
│  │                 │                      │              │
│  ▼                 ▼                      ▼              │
│ ProcessMonitor  ThreadMonitor      ImageMonitor          │
│ PsSetCreate     PsSetCreate        PsSetLoad             │
│ ProcessNotify   ThreadNotify       ImageNotify            │
│ RoutineEx       Routine            Routine               │
│  │                 │                      │              │
│  │  ┌──────────────┴──────┐               │              │
│  │  │ verifyFileless      │               │              │
│  │  │ Execution           │               │              │
│  │  │ (injection detect)  │               │              │
│  │  └─────────────────────┘               │              │
│  │                                        │              │
│  ▼                                        ▼              │
│ CodeIntegrity          DwmImageResolver                  │
│ CiValidateFileObject   Verify dwm.exe                    │
│ SHA1 hashing           Owner SID check                   │
│ Signature verify       Memory integrity                  │
│                                                          │
│ CryptoKernel                                             │
│ RSA-2048 key exchange                                    │
│ AES-CBC message encryption                               │
│ BCrypt kernel crypto stack                               │
└──────────────────────────────────────────────────────────┘
```

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

---

## Detection Systems — Kernel Driver (LockDownService215.sys)

The driver is a **FLTMGR minifilter** that provides kernel-level monitoring capabilities that usermode processes cannot detect or circumvent.

### 1. Communication Port (\ApDriverPort)
Encrypted bidirectional channel between driver and LDB.

- Port name: `\ApDriverPort`
- PID validation on connect — only the verified LDB process can connect
- RSA-2048 key exchange → AES-CBC encrypted messages
- All monitoring events sent through this encrypted channel

### 2. Process Monitor (PsSetCreateProcessNotifyRoutineEx)
**Kernel-level process creation/termination callbacks.** Catches EVERY process start/stop on the system — cannot be evaded from usermode.

- Tracks all processes in an AVL tree
- Gets image path, parent PID, command line (via PEB), signing level
- Special tracking for DWM PID
- Sends all events to usermode LDB

### 3. Thread Monitor (PsSetCreateThreadNotifyRoutine)
Monitors all thread creation system-wide.

**Key feature: Fileless execution detection.**
- For each new thread, queries `ZwQueryInformationThread` for start address
- Checks if start address maps to a legitimate loaded image via `ZwQueryVirtualMemory`
- If start address is NOT in any loaded module → **code injection detected**
- This catches DLL injection, shellcode execution, reflective loading

### 4. Image Load Monitor (PsSetLoadImageNotifyRoutine)
Monitors every DLL/EXE load in every process on the system.

- Reports each image load path and base address to usermode
- Used to detect injected DLLs and hooking frameworks

### 5. Code Integrity Verification
Validates digital signatures at the kernel level using `ci.dll`.

- `CiValidateFileObject()` — verifies file signatures
- SHA1 hashing of binaries
- Checks signer: `"Respondus, Inc."`
- Checks CA: `"DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"`

### 6. DWM Integrity Verification
Verifies Desktop Window Manager hasn't been tampered with.

- Locates `\Windows\System32\dwm.exe`
- Validates owner SID: `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464` (NT SERVICE\DWM)
- Maps DWM into kernel space for byte-level inspection
- Validates signature is Microsoft-signed
- Limitation: Cannot verify if driver loaded after DWM

### 7. Browser Binary Validation
Verifies the connecting LDB binary is genuine.

- Checks path against known install locations
- Parses PE version info: CompanyName, FileVersion, OriginalFilename
- Validates code signature
- Calculates SHA1 hash

### 8. Kernel Cryptography
Full RSA + AES-CBC stack in kernel mode.

- `BCryptGenerateKeyPair` — RSA-2048 keypair
- `BCryptGenerateSymmetricKey` — AES key from RSA-exchanged secret
- `BCryptEncrypt/Decrypt` — AES-CBC for all port messages
- `BCryptGenRandom` — IV generation
- `BCryptHash*` — SHA1/SHA256 for integrity checks

### 9. PEB Command Line Reader
Reads any process's command line from kernel space.

- `KeStackAttachProcess` — Attaches to target process context
- `PsGetProcessPeb` — Gets PEB address
- Reads `ProcessParameters->CommandLine` with SEH protection
- `KeUnstackDetachProcess` — Detaches

### 10. System Boot Chain Validation
Verifies system startup is legitimate.

- `UserModeDetector::findSmss` — Locates `\Windows\System32\smss.exe`
- Validates the Session Manager is running and legitimate
- Part of anti-sandbox/anti-VM detection

---

## Source Files

```
lockdown-re/
├── README.md                          ← This file
└── src/
    ├── usermode_detections.cpp        ← Pseudocode for LockDownBrowser.exe detections
    └── driver_detections.cpp          ← Pseudocode for LockDownService215.sys
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

3. **Communication is encrypted.** Driver↔usermode messages use RSA+AES-CBC. Sniffing the FilterPort won't reveal detection data.

4. **Process names are checked server-side.** The full process list is sent to the server. Disguising as a system process avoids server-side blocklist matching.

5. **DWM integrity is checked.** If you hook DWM to bypass `SetWindowDisplayAffinity`, the driver will detect the tampering.

6. **Debug strings are everywhere.** Respondus ships with extensive logging — this is how most detection routines were identified. A release build with stripped strings would be significantly harder to reverse.

---

## Disclaimer

This is an independent security analysis. All information was derived from static analysis of locally-installed software.
