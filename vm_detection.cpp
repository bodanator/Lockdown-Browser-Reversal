// =============================================================================
//  LockDown Browser — VM Detection Engine Pseudocode
//  Reverse engineered from LockDownBrowser.exe
//  SHA256: 86f39c5a239a0ff69f3e6b3bd8833f455eecbbacc2890fe68819425098bc8040
//
//  Full analysis across 3 binaries via Ghidra 12.2.
//  Exhaustive search of 11,197 strings across 25,509 procedures confirmed ZERO
//  VM vendor strings exist in any analyzed binary. VM detection uses a hybrid
//  client-engine / server-data architecture — the binary contains the detection
//  ENGINE but all detection DATA is downloaded from Respondus servers at runtime.
//
//  ARCHITECTURE:
//    Layer 1: Server-driven device fingerprinting (SetupDi + server patterns)
//    Layer 2: Kernel-level timing analysis (SecureRDTSC/FSecureClock via IOCTL)
//    Layer 3: Server-side telemetry analysis (MAC + hardware uploaded to cloud)
// =============================================================================

#include <windows.h>
#include <setupapi.h>
#include <bcrypt.h>
#include <fltuser.h>
#include <dshow.h>
#include <string>
#include <vector>


// =============================================================================
//  1. STRING TABLE INDEXER — The Core Anti-Analysis Mechanism
//
//  All VM detection strings are accessed through this function from
//  server-populated SSO std::string arrays. No VM vendor names, registry
//  paths, or device patterns exist as static data in the binary.
//
//  Called with indices: (0x12, 0xa83), (0x12, 0xcab), (0x12, 0xcc2),
//                       (0x12, 0x26d) from VM detection functions.
//
//  Base pointer DAT_140cedf48 populated from server data at runtime.
// =============================================================================

struct ServerStringTable {
    // Three distinct string arrays, selected by table_id:
    //   0x12 -> array at param_1[6]
    //   0x17 -> array at param_1[3]
    //   0x23 -> array at *param_1
    // Each entry is 0x20 bytes (SSO std::string)

    void* arrays[3];        // base pointers populated from server
    size_t array_counts[3]; // element counts

    // FUN_14021ad30 at 0x14021ad30
    const char* GetString(int table_id, int index) {
        void* base;
        if (table_id == 0x12)      base = arrays[2];  // param_1[6]
        else if (table_id == 0x17) base = arrays[1];  // param_1[3]
        else if (table_id == 0x23) base = arrays[0];  // *param_1
        else return "";  // DAT_140b0cd98 — empty string fallback

        // Index into SSO std::string array
        // Each entry is 0x20 bytes
        char** entry = (char**)((char*)base + (index / 0x17) * 0x20);

        // SSO threshold: strings <= 15 bytes stored inline
        if ((size_t)entry[3] > 0xf) {
            return (const char*)*entry;  // heap-allocated
        }
        return (const char*)entry;       // inline SSO buffer
    }
};

// Global: populated from server communication
// DAT_140cedf48
static ServerStringTable g_serverStringTable;


// =============================================================================
//  2. STRING MATCHING PRIMITIVES
//
//  Three layered comparison functions form the matching engine used by
//  both VM detection functions. All use custom ASCII case folding.
//
//  FUN_140a91550 at 0x140a91550 — custom _strnicmp
//  FUN_1402a0c70 at 0x1402a0c70 — prefix match (starts with)
//  FUN_1402a0e10 at 0x1402a0e10 — substring search (contains)
// =============================================================================

// Custom case-insensitive comparison (ASCII only)
// FUN_140a91550 at 0x140a91550
int CaseInsensitiveCompareN(const char* s1, const char* s2, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char c1 = s1[i];
        char c2 = s2[i];
        // ASCII case folding: A-Z -> a-z
        if ((unsigned char)(c1 - 0x41) < 0x1a) c1 += 0x20;
        if ((unsigned char)(c2 - 0x41) < 0x1a) c2 += 0x20;
        if (c1 != c2) return c1 - c2;
        if (c1 == 0) return 0;
    }
    return 0;
}

// Prefix match: does haystack START WITH needle? (case-insensitive)
// FUN_1402a0c70 at 0x1402a0c70
bool PrefixMatch(const char* haystack, const char* needle) {
    size_t len = strlen(needle);
    return CaseInsensitiveCompareN(haystack, needle, len) == 0;
}

// Substring search: does haystack CONTAIN needle? (case-insensitive)
// FUN_1402a0e10 at 0x1402a0e10
bool SubstringSearch(const char* haystack, const char* needle) {
    size_t needleLen = strlen(needle);
    size_t haystackLen = strlen(haystack);
    if (needleLen > haystackLen) return false;

    for (size_t i = 0; i <= haystackLen - needleLen; i++) {
        if (CaseInsensitiveCompareN(haystack + i, needle, needleLen) == 0) {
            return true;
        }
    }
    return false;
}


// =============================================================================
//  3. PRIMARY VM DETECTION ENGINE — Device Enumeration + Server Patterns
//
//  FUN_1402a5f20 at 0x1402a5f20 (3752 bytes)
//  Called from init function FUN_14015f690 at address 0x14015f903
//
//  Enumerates ALL system devices via SetupDi APIs, reads device descriptions
//  and object paths, then compares against server-downloaded patterns using
//  case-insensitive matching AND FNV-1a hash table lookups.
//
//  Also queries HKLM registry paths provided by the server config.
//
//  Detection results stored in global flags:
//    DAT_140cedf40 + 0x46560  (device match result 1)
//    DAT_140cedf40 + 0x46564  (device match result 2)
//
//  Server config structure at DAT_140cedf80 + 0x233e8:
//    +0x00: HKLM registry key path #1
//    +0x10: VM pattern string #1
//    +0x18: Registry value name #1
//    +0x20: VM pattern string #2
//    +0x28: HKLM registry key path #2
//    +0x30: Registry value name #2
//    +0x38: VM pattern string #3
//    +0x40: VM pattern string #4
//    +0x48: VM pattern string #5
//    +0x50: HKLM registry key path #3
//    +0x58: Registry value name #3
//    +0x60: VM pattern string #6
//    +0x80: VM pattern string #7
//
//  Additional variable-length array:
//    DAT_140cedf80 + 0x233d8  (pointer to string array)
//    DAT_140cedf80 + 0x233e0  (count of entries)
//
//  Imports: SetupDiGetClassDevsW, SetupDiEnumDeviceInfo,
//           SetupDiGetDeviceRegistryPropertyA, SetupDiDestroyDeviceInfoList,
//           RegOpenKeyExA, RegQueryValueExA
// =============================================================================

struct ServerVMConfig {
    // Populated from server at runtime — exact string values unknown
    // These would contain things like "VMware", "VirtualBox", "QEMU", etc.
    std::string regKey1;         // +0x00
    std::string vmPattern1;      // +0x10
    std::string regValueName1;   // +0x18
    std::string vmPattern2;      // +0x20
    std::string regKey2;         // +0x28
    std::string regValueName2;   // +0x30
    std::string vmPattern3;      // +0x38
    std::string vmPattern4;      // +0x40
    std::string vmPattern5;      // +0x48
    std::string regKey3;         // +0x50
    std::string regValueName3;   // +0x58
    std::string vmPattern6;      // +0x60
    std::string reserved;        // +0x68..+0x78
    std::string vmPattern7;      // +0x80
};

struct DevicePatternArray {
    std::string* patterns;       // DAT_140cedf80 + 0x233d8
    int count;                   // DAT_140cedf80 + 0x233e0
};

// FNV-1a 64-bit hash constants
#define FNV_OFFSET_BASIS 0xcbf29ce484222325ULL
#define FNV_PRIME        0x100000001b3ULL

uint64_t FNV1aHash(const char* data, size_t len) {
    uint64_t hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)data[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

// FUN_1402a5f20 at 0x1402a5f20
void PrimaryVMDetection() {
    ServerVMConfig* config = *(ServerVMConfig**)(DAT_140cedf80 + 0x233e8);
    DevicePatternArray* extraPatterns =
        (DevicePatternArray*)(DAT_140cedf80 + 0x233d8);

    int resultFlags1 = 0;  // -> DAT_140cedf40 + 0x46560
    int resultFlags2 = 0;  // -> DAT_140cedf40 + 0x46564

    // --- Phase 1: Enumerate all system devices ---

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(
        NULL, NULL, NULL,
        DIGCF_PRESENT | DIGCF_ALLCLASSES  // 0x6
    );

    SP_DEVINFO_DATA devInfo = {};
    devInfo.cbSize = sizeof(devInfo);

    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfo); i++) {
        char deviceDesc[512] = {};
        char deviceObjName[512] = {};

        // SPDRP_DEVICEDESC = 0x0
        SetupDiGetDeviceRegistryPropertyA(
            hDevInfo, &devInfo,
            SPDRP_DEVICEDESC, NULL,
            (PBYTE)deviceDesc, sizeof(deviceDesc), NULL
        );

        // SPDRP_PHYSICAL_DEVICE_OBJECT_NAME = 0xC
        SetupDiGetDeviceRegistryPropertyA(
            hDevInfo, &devInfo,
            0xC, NULL,
            (PBYTE)deviceObjName, sizeof(deviceObjName), NULL
        );

        // Compare device description against server patterns
        // Uses case-insensitive prefix matching and substring search
        if (SubstringSearch(deviceDesc, config->vmPattern1.c_str()))
            resultFlags1 |= 1;
        if (SubstringSearch(deviceDesc, config->vmPattern2.c_str()))
            resultFlags1 |= 2;
        if (SubstringSearch(deviceDesc, config->vmPattern3.c_str()))
            resultFlags1 |= 4;
        // ... continues for all pattern offsets

        // Compare against variable-length pattern array
        for (int p = 0; p < extraPatterns->count; p++) {
            if (SubstringSearch(deviceDesc, extraPatterns->patterns[p].c_str()))
                resultFlags2 |= (1 << p);
        }

        // FNV-1a hash lookup for fast matching
        size_t descLen = strlen(deviceDesc);
        uint64_t hash = FNV1aHash(deviceDesc, descLen);

        // Hash table lookup: (hash & mask) * 2 + 1 indexes into table
        // If not found in hash table -> device is unknown/new
        // If found -> confirmed via memcmp
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);

    // --- Phase 2: Registry checks with server-provided paths ---

    HKEY hKey;
    char regValue[256] = {};
    DWORD regSize = sizeof(regValue);

    // Check registry key #1 from server config
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, config->regKey1.c_str(),
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, config->regValueName1.c_str(),
                        NULL, NULL, (LPBYTE)regValue, &regSize);
        if (SubstringSearch(regValue, config->vmPattern1.c_str()))
            resultFlags1 |= 0x100;
        RegCloseKey(hKey);
    }
    // ... repeat for regKey2/regKey3

    // Store results in global flags
    *(int*)(DAT_140cedf40 + 0x46560) |= resultFlags1;
    *(int*)(DAT_140cedf40 + 0x46564) |= resultFlags2;
}


// =============================================================================
//  4. SECONDARY VM DETECTION ENGINE — Pattern Vector Matching
//
//  FUN_140231310 at 0x140231310 (1619 bytes)
//  Called from FUN_14016f020 at 0x14016f74a
//
//  Enumerates devices and matches against a pre-loaded vector of structured
//  pattern entries. Each entry supports AND/OR compound matching logic with
//  a mismatch threshold — more than 1 mismatch triggers the flag.
//
//  Pattern vector at DAT_140cedf40 + 0x46678
//  Result flag at DAT_140cedf40 + 0x46580
// =============================================================================

struct PatternEntry {
    char padding[0x08];
    std::string* matchStrings;  // +0x08
    size_t matchStringCount;    // +0x10
    char padding2[0x08];
    bool andMode;               // +0x21 (true=AND, false=OR)
    bool expectedResult;        // +0x22
    char padding3[0x05];
};  // total 0x28 bytes

// FUN_140231310 at 0x140231310
void SecondaryVMDetection() {
    PatternEntry* patterns = *(PatternEntry**)(DAT_140cedf40 + 0x46678);
    size_t patternCount = *(size_t*)(DAT_140cedf40 + 0x46680);
    int mismatchCount = 0;

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(
        NULL, NULL, NULL,
        DIGCF_PRESENT | DIGCF_ALLCLASSES
    );

    SP_DEVINFO_DATA devInfo = {};
    devInfo.cbSize = sizeof(devInfo);

    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfo); i++) {
        char deviceDesc[512] = {};
        SetupDiGetDeviceRegistryPropertyA(
            hDevInfo, &devInfo,
            SPDRP_DEVICEDESC, NULL,
            (PBYTE)deviceDesc, sizeof(deviceDesc), NULL
        );

        for (size_t p = 0; p < patternCount; p++) {
            PatternEntry* entry = &patterns[p];
            bool matched = false;

            if (entry->andMode) {
                // AND mode: ALL strings must match
                matched = true;
                for (size_t s = 0; s < entry->matchStringCount; s++) {
                    if (!SubstringSearch(deviceDesc,
                            entry->matchStrings[s].c_str())) {
                        matched = false;
                        break;
                    }
                }
            } else {
                // OR mode: ANY string matches
                for (size_t s = 0; s < entry->matchStringCount; s++) {
                    if (SubstringSearch(deviceDesc,
                            entry->matchStrings[s].c_str())) {
                        matched = true;
                        break;
                    }
                }
            }

            if (matched != entry->expectedResult) {
                mismatchCount++;
                // Append formatted mismatch code to telemetry string
            }
        }
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);

    // Threshold: more than 1 mismatch = flagged
    if (mismatchCount > 1) {
        *(int*)(DAT_140cedf40 + 0x46580) = 1;
    }
}


// =============================================================================
//  5. VIRTUAL WEBCAM DETECTION
//
//  FUN_140260c50 at 0x140260c50
//  Uses DirectShow COM to enumerate webcams, checks FriendlyName for
//  "virtual" substring AND an encrypted string from server table (0xbdc).
//
//  One of the ONLY plaintext detection keywords in the entire binary.
//
//  Result flag at DAT_140cedf40 + 0x46582
//
//  String evidence:
//    "webcam new camera connected = (%s)"    — 0x00B16BF0
//    "webcam DISconnected = (%s)"
//    "webcam RE-connected = (%s)"
// =============================================================================

void DetectVirtualWebcam() {
    ICreateDevEnum* pDevEnum = NULL;
    CoCreateInstance(
        CLSID_SystemDeviceEnum, NULL, CLSCTX_INPROC_SERVER,
        IID_ICreateDevEnum, (void**)&pDevEnum
    );

    IEnumMoniker* pEnum = NULL;
    pDevEnum->CreateClassEnumerator(
        CLSID_VideoInputDeviceCategory, &pEnum, 0
    );

    IMoniker* pMoniker = NULL;
    while (pEnum->Next(1, &pMoniker, NULL) == S_OK) {
        IPropertyBag* pPropBag = NULL;
        pMoniker->BindToStorage(0, 0, IID_IPropertyBag, (void**)&pPropBag);

        VARIANT varName;
        VariantInit(&varName);
        pPropBag->Read(L"FriendlyName", &varName, 0);

        char friendlyName[256];
        WideCharToMultiByte(CP_ACP, 0, varName.bstrVal, -1,
                           friendlyName, sizeof(friendlyName), NULL, NULL);

        // Check 1: plaintext "virtual" substring
        if (SubstringSearch(friendlyName, "virtual")) {
            *(BYTE*)(DAT_140cedf40 + 0x46582) = 1;
        }

        // Check 2: encrypted string from server table index 0xbdc
        const char* encryptedName =
            g_serverStringTable.GetString(0x12, 0xbdc);
        if (SubstringSearch(friendlyName, encryptedName)) {
            *(BYTE*)(DAT_140cedf40 + 0x46582) = 1;
        }

        VariantClear(&varName);
        pPropBag->Release();
        pMoniker->Release();
    }

    pEnum->Release();
    pDevEnum->Release();
}


// =============================================================================
//  6. KERNEL TIMING DETECTION — SecureRDTSC & FSecureClock IOCTLs
//
//  The kernel driver (accessed via \\ApDriverPort) provides ring 0
//  RDTSC execution that bypasses usermode VM exit interception.
//  VMs that intercept RDTSC introduce measurable timing delays.
//
//  IOCTL command table at 0x140cb01f8:
//    - "SecureRDTSC:responsecall"    at 0x140b0c780
//    - "FSecureClock:responsecall"   at 0x140b0c7a0
//    - "ActiveCheck:responsecall"    (undocumented)
//    - "UserCheck:responsecall"      (undocumented)
//    - "AntiDebug:responsecall"      (undocumented)
//
//  String evidence:
//    0x140b10738: "\\ApDriverPort"
//    0x140b0c780: "SecureRDTSC:responsecall"
//    0x140b0c7a0: "FSecureClock:responsecall"
// =============================================================================

struct KernelTimingDetection {
    HANDLE hPort;  // \\ApDriverPort

    bool Connect() {
        // FilterConnectCommunicationPort(L"\\ApDriverPort", ...)
        // Driver validates PID + code signature
        return true;
    }

    // Execute RDTSC from ring 0 — bypasses usermode VM exit hooks
    // Timing difference between ring 0 RDTSC and expected value
    // reveals hypervisor-induced latency
    uint64_t SecureRDTSC() {
        // Send "SecureRDTSC" IOCTL via FilterSendMessage
        // Driver executes RDTSC at ring 0 privilege
        // Returns raw TSC value
        // Usermode compares against expected timing
        return 0;
    }

    // Tamper-resistant clock source
    // VMs may manipulate usermode clock sources
    // Kernel-level clock bypasses this
    uint64_t FSecureClock() {
        // Send "FSecureClock" IOCTL via FilterSendMessage
        // Driver queries high-resolution timer
        // Returns secure timestamp
        return 0;
    }

    // Additional IOCTL commands (not yet fully analyzed):
    // - ActiveCheck: likely liveness verification
    // - UserCheck: likely user environment verification
    // - AntiDebug: kernel-level debug detection
};


// =============================================================================
//  7. HARDWARE TELEMETRY COLLECTION
//
//  Collects comprehensive hardware fingerprint during startup and
//  uploads to Respondus servers. Enables server-side VM detection
//  independent of client-side checks.
//
//  FUN_14015f690 at 0x14015f690 (init orchestrator)
//  FUN_1402aafa0 at 0x1402aafa0 (CPU/RAM/arch collection)
//  FUN_140256220 at 0x140256220 (MAC address collection)
//  FUN_140138c00 at 0x140138c00 (diagnostics report builder)
//
//  Upload endpoint:
//    "/MONServer/ldb/spreadsheet_upload_zip.do?
//     token=%s&key=%s&studentKey=%s&type=%s&time=%s&mac=%s"
//
//  Server endpoints:
//    smc-service-cloud.respondus2.com (Monitor + Help Center)
//    help-center-respondus-com.s3.amazonaws.com (logs)
//    server-profiles-respondus-com.s3-external-1.amazonaws.com (profiles)
//    static-public-downloads-cloud.respondus.com (patches)
// =============================================================================

struct HardwareTelemetry {
    char macAddresses[4][18];   // up to 4 MACs, format "xx:xx:xx:xx:xx:xx"
    int  macCount;
    char cpuName[256];          // from registry CentralProcessor\0
    int  cpuMHz;                // from registry ~MHz value
    int  ramMB;                 // GlobalMemoryStatusEx >> 20
    int  processorCount;        // GetNativeSystemInfo
    int  architecture;          // IsWow64Process2
    bool isWindows11;           // OS version detection
    bool isWindows10;
    int  osBuild;
    char username[256];         // GetUserNameA
    char keyboardLayout[16];    // GetKeyboardLayout
    // Monitor info: resolution, DPI (GetMonitorInfoA, GetScaleFactorForMonitor)
    // Webcam list: DirectShow enumeration
};

// FUN_1402aafa0 at 0x1402aafa0
void CollectSystemInfo(HardwareTelemetry* info) {
    // CPU name from registry
    // HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0
    // Value: ProcessorNameString (implied)
    // Address of registry path: 0x140b37b70

    // CPU frequency
    // Registry value "~MHz" or fallback:
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    info->cpuMHz = (int)(freq.QuadPart / 1000000);

    // RAM
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    info->ramMB = (int)(ms.ullTotalPhys >> 20);

    // Architecture
    // FUN_1402ad640: dynamically resolves IsWow64Process2 from kernel32
    // Falls back to GetSystemInfo if unavailable
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    info->processorCount = si.dwNumberOfProcessors;
}

// FUN_140256220 at 0x140256220
void CollectMACAddresses(HardwareTelemetry* info) {
    // GetAdaptersInfo — enumerates Ethernet (Type=6) adapters
    // Skips WiFi adapters
    // Formats as "%02x:%02x:%02x:%02x:%02x:%02x"
    // Stores up to 4 addresses
    // Also used by PACE/iLok DRM for machine identity
}

// FUN_140138c00 at 0x140138c00
void BuildAndUploadDiagnostics(HardwareTelemetry* info) {
    // Format: "CLDB %s - %s\r\n"
    //         "Created: %04d-%02d-%02d %02d:%02d:%02d\r\n"
    //         "OS: Windows %s %s-bit\r\n"
    //         "PC: %s, %01.1f GHz, %d MB RAM\r\n"
    //         "Webcam(s): ..."
    //
    // Version: 2.1.6.02, September 28 2026
    //
    // Tests connectivity to 5 Respondus servers
    // Uploads to: help-center-respondus-com.s3.amazonaws.com
    // Returns: "Help Center ID for Respondus Support: %s"
}


// =============================================================================
//  8. SERVER CONFIGURATION DELIVERY
//
//  Detection patterns arrive via multiple channels:
//    1. Server profiles from S3 (encrypted)
//    2. MonitorGetExamSettings from cloud (exam-specific)
//    3. XML settings via /settings endpoint (parsed by FUN_1402905b0)
//
//  String evidence:
//    "Auto-Launch - Using server profile %d"
//    "Profile - no valid buffer after decoding"
//    "Profile - 0 profiles"
//    "MonitorGetExamSettings() - offline=%d course=%s test=%s"
//    "MonitorGetExamSettings ok= %d, dwRet= %u ( %s )"
//    "smc-service-cloud.respondus2.com (Monitor and Help Center)"
//    XML: <settings> at 0x140b36da8, </settings> at 0x140b36db8
//    /settings URL path at 0x140b18660
// =============================================================================

struct ServerConfigDelivery {
    // Server profiles — downloaded from S3, encrypted
    // server-profiles-respondus-com.s3-external-1.amazonaws.com
    void* profileData;
    int   profileCount;

    // Exam settings — per-exam configuration from cloud
    // smc-service-cloud.respondus2.com
    void* examSettings;

    // XML settings parser (FUN_1402905b0, 7066 bytes, 42 callees)
    // Parses <settings>...</settings> blocks
    // Setting key names accessed via encrypted string table
    void* xmlSettings;
};


// =============================================================================
//  9. DETECTION RESULT FLAGS — Global State
//
//  All VM detection functions write to global flags in the DAT_140cedf40
//  structure. These flags are read by enforcement code (not yet traced)
//  to determine whether to block exam access.
//
//  DAT_140cedf40 + 0x46560  — Primary device detection result 1
//  DAT_140cedf40 + 0x46564  — Primary device detection result 2
//  DAT_140cedf40 + 0x46580  — Secondary detection mismatch flag
//  DAT_140cedf40 + 0x46582  — Virtual webcam detected
//
//  INVESTIGATION GAP: The consumers of these flags (enforcement code)
//  have not been traced. The function(s) that read these values and
//  decide to block/allow the exam remain unidentified.
// =============================================================================

struct DetectionResultFlags {
    // All at base DAT_140cedf40
    int  deviceResult1;      // +0x46560 — OR'd bitmask from primary engine
    int  deviceResult2;      // +0x46564 — OR'd bitmask from extra patterns
    int  mismatchFlag;       // +0x46580 — set to 1 if >1 mismatch
    BYTE virtualWebcam;      // +0x46582 — set to 1 if virtual webcam found
};


// =============================================================================
//  10. INIT ORCHESTRATOR — Startup Detection Sequence
//
//  FUN_14015f690 at 0x14015f690
//  Called from main application function FUN_1401903b0
//
//  Orchestrates the complete hardware collection and VM detection
//  sequence during application startup.
//
//  String evidence:
//    "OS info: is-11 = %d, is-10 = %d, build = %d, compat = %d, ..."
//    "ID = %s"
//    Debug account ID check: strcmp(ID, "747232230")
// =============================================================================

void StartupDetectionSequence() {
    // 1. Collect MAC addresses
    //    FUN_140256220()

    // 2. Get keyboard layout
    //    GetKeyboardLayout(0)

    // 3. Detect OS version (Win10 vs Win11, build number)
    //    "OS info: is-11 = %d, is-10 = %d, build = %d, ..."

    // 4. Detect architecture
    //    FUN_1402ad640() — IsWow64Process2

    // 5. Get username
    //    GetUserNameA()

    // 6. Get monitor info
    //    GetMonitorInfoA, GetScaleFactorForMonitor

    // 7. Install focus tracking
    //    SetWinEventHook(EVENT_SYSTEM_FOREGROUND, ...)
    //    RegisterSuspendResumeNotification()

    // 8. Run VM detection (after server config loaded)
    //    PrimaryVMDetection()   — FUN_1402a5f20 at 0x14015f903

    // 9. Username check against configured value
    //    strcmp(ID, "747232230") — test/debug account
}


// =============================================================================
//  10. VM DETECTION ENFORCEMENT CHAIN
//
//  Traced via xrefs to DAT_140cedf40 (global state base) — 400+ references
//  across the binary. The enforcement chain runs at startup before any exam
//  content loads. Three distinct enforcement phases:
//
//    Phase 1: Pre-flight (service check + license validation)
//    Phase 2: VM detection (Primary + Secondary scan)
//    Phase 3: Telemetry (flag collection + server reporting)
//
//  Address: WinMain = FUN_1401903b0
// =============================================================================


// ---------------------------------------------------------------------------
//  WinMain (FUN_1401903b0) — Application entry point
//  Decompiled from LockDownBrowser.exe at 0x1401903b0
//
//  Allocates the global detection state structure (DAT_140cedf40, 0x4aa78 bytes
//  = ~305 KB), enforces single-instance via named mutex, checks OS version,
//  connects to the kernel driver, and gates exam launch through a multi-stage
//  enforcement pipeline.
//
//  Build: "2.1.6.02", dated "September 28, 2026"
//  CEF: Chrome/150.0.0.0
//  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
//              (KHTML, like Gecko) CLDB 2.1.6.02; Chrome/150.0.0.0;
//              Safari/537.36
// ---------------------------------------------------------------------------

void WinMain_Enforcement(HINSTANCE hInstance) {

    // --- Phase 0: Global state allocation ---
    // DAT_140cedf40 = new DetectionState[0x4aa78];  // ~305 KB
    // DAT_140cedf48 = new ServerStringTable[0x6e0];
    // DAT_140cedf50 = new ServerConfig[0xb08];
    // DAT_140cedf58 = new NetworkState[0x50];
    // DAT_140cedf60 = new ProfileState[0x1c4a0];

    // --- Phase 1: Single instance + OS gate ---
    HANDLE hMutex = CreateMutexW(
        NULL, TRUE, L"CLDB{52FBA03B-9E7A-4786-A9A8-F61730C505DA}"
    );
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // Retry loop with 1500ms sleep, then:
        MessageBoxA(NULL,
            "Unable to continue because another copy of LockDown Browser "
            "is still running. You might need to restart your computer "
            "to fix this.",
            "LockDown Browser", MB_SETFOREGROUND);
    }

    // Win10+ enforcement
    if (*(char*)(g_ServerConfig + 0x12d) == '\0') {
        ShowDialog(
            "This program is not compatible with Windows 7 or 8. "
            "You must upgrade your computer to Windows 10 or 11, "
            "or use LockDown Browser on another device."
        );
    }

    // --- Phase 2: Driver connection ---
    // FUN_140275970: Allocates driver comm state (DAT_140cedea0 = 0x158 bytes)
    // Calls FUN_140043480 → FilterConnectCommunicationPort(\ApDriverPort)
    // If driver connected: FUN_140024260 validates the connection
    // Returns: 0 = failed, 1 = connected to kernel driver
    int driverConnected = DriverComm_Init(g_DetectionState);

    // --- Phase 3: Pre-flight server validation ---
    // FUN_1402a6e00 — multi-step enforcement gate
    int preflightResult = PreflightValidation();

    // Inside PreflightValidation():
    // Step 1: Check kernel driver service state
    //   FUN_1402ae7e0 → OpenSCManagerW / OpenServiceW / QueryServiceStatusEx
    //   Opens service by name from string table index 0x20 (wide)
    //   Returns: 0=not found, 1=SCM fail, 2=service error, 3=query fail, 4=running
    //
    // Step 2 (only if service running = 4):
    //   License/server validation via FUN_140a4917c
    //   Gets 4 config strings from table indices 0xf00, 0xf20, 0xf40, 0xf60
    //   Builds validation payload → FUN_1402a58f0
    //   Server responds with error codes:
    //     0x00  — success (no error)
    //     0x02  — known transient error (retry)
    //     0x03  — known transient error (retry)
    //     0x35  — specific rejection
    //     0x40  — certificate/auth error
    //     0x7b  — server rejection
    //     0x10b — protocol error
    //   On success, checks bit 10 of result flags for VM-allow override
    //
    // Step 3: Enforcement decision
    //   Based on combined verdict, shows one of these dialogs:
    //     Dialog 0x65 (101) — Exam blocked / unable to start
    //     Dialog 0x66 (102) — Version or server mismatch
    //     Dialog 0x67 (103) — License validation failed
    //     Dialog 0x68 (104) — Unknown / unrecoverable error
    //     Dialog 0x69 (105) — Driver not found / not installed
    //     Dialog 0x6a (106) — Integrity hash mismatch

    // --- Phase 4: Init orchestrator (VM detection runs here) ---
    // FUN_14015f690(hInstance, 1) — the main init
    // If this returns 0: logs "IninitInstance returned FALSE - calling CefShutdown()"
    // If returns 1: proceeds to detection + CEF browser init
    int initResult = InitOrchestrator(hInstance, 1);

    if (initResult == 0) {
        g_ExitCode = 0x67932;
        LogMessage("IninitInstance returned FALSE - calling CefShutdown()");
        return;
    }

    LogMessage("InitInstance completed");

    // Check accessibility mode (NVDA screen reader)
    // FUN_140234e90() — if detected, sets single-threaded mode
    if (IsNVDADetected()) {
        *(int*)(g_DetectionState2 + 0x1eec) = 0;
        LogMessage("NVDA detected, using single-threaded mode");
    }

    // Start detection monitoring
    // FUN_140222940() — detection thread orchestrator
    // FUN_140223d70(g_DetectionState) — detection state init
    StartDetectionThreads();

    // Check if driver communication established
    if (*(int*)(g_DetectionState + 0x46970) == 0) {
        LogMessage("Driver communication not established");
    }

    // Enter message loop
    // Standard Win32 GetMessageW loop with CEF integration
    // cef_do_message_loop_work() called on shutdown (10 iterations)
}


// ---------------------------------------------------------------------------
//  TelemetryReporter (FUN_14022ab00) — Detection Flag Consumer
//  10,313 bytes, 22 non-contiguous address ranges
//  Decompiled from LockDownBrowser.exe at 0x14022ab00
//
//  Central telemetry builder. Reads ALL detection flags from global state,
//  performs additional runtime checks (module scanning, file existence, display
//  matching), and builds the full telemetry payload for the Respondus server.
//
//  Called with param_1 = output status pointer (set to 0 at entry).
//
//  Operations performed (in order):
//    1. Anti-forensics: RegDeleteKeyExA on IFEO\utilman.exe
//    2. Display device matching against ~18 server-downloaded patterns
//    3. Kernel timing cross-reference (+0x46568 && +0x4656c)
//    4. Audio/input device matching against server patterns
//    5. Conditional flag enforcement via FUN_14013cc70 (central flag setter)
//    6. File existence check with server-supplied path (PathFileExistsA)
//    7. K32EnumProcessModules + module blacklist scanning
//    8. Spyrix keylogger detection (hardcoded "Spyrix" string)
//    9. Full process list telemetry construction ("process.list")
//   10. Payload encoding and submission
// ---------------------------------------------------------------------------

void TelemetryReporter(int* pStatus) {
    *pStatus = 0;

    // --- Step 1: Anti-forensics / IFEO cleanup ---
    // Removes the utilman.exe debugger hook — a common persistence vector
    // used by attackers to get SYSTEM shell from the login screen.
    // LDB cleans this to prevent students from exploiting it during exams.
    RegDeleteKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Image File Execution Options\\utilman.exe",
        KEY_WOW64_64KEY, 0
    );

    // --- Step 2: Display device matching (list at +0x9c0, count at +0x9d8) ---
    // Iterates over all display adapters (populated by SetupDi enumeration
    // from PrimaryVMDetection). Matches each device name against ~18 server-
    // downloaded patterns from string table 0x12.
    //
    // Pattern indices and their target flags:
    //   "MiraCast" (hardcoded)       → local_4240 (MiraCast detected)
    //   Table[0x12][0x6a6]           → DAT_140cedf80 + 0xf36d
    //   Table[0x12][0xe77]           → DAT_140cedf40 + 0x311
    //   Table[0x12][0xe8e]           → DAT_140cedf40 + 0x312
    //   Table[0x12][0x4ac]           → DAT_140cedf40 + 0x4bb
    //   Table[0x12][0x633]           → DAT_140cedf40 + 0x4b9
    //   Table[0x12][0xd35]           → DAT_140cedf40 + 0x2e9
    //   Table[0x12][0xea5]           → DAT_140cedf40 + 0x9b9
    //   Table[0x12][0x564]           → local flag (accumulator)
    //   Table[0x12][0xe49]           → DAT_140cedf40 + 0x46465
    //   Table[0x12][0xe60]           → DAT_140cedf40 + 0x31c
    //   Table[0x12][0x46690]         → DAT_140cedf40 + 0x46690
    //
    // All matches use OR semantics — once a device matches, the flag stays set.
    // FUN_140a8b6b0 is _stricmp; match is when return == 0.

    bool miracastDetected = false;
    for (int i = 0; i < g_State->displayDeviceCount; i++) {
        std::string* devName = &g_State->displayDevices[i];
        if (_stricmp(devName->c_str(), "MiraCast") == 0)
            miracastDetected = true;

        // Match against each server pattern and set corresponding flags
        // (18 pattern checks per device in the display list)
    }

    // --- Step 3: Kernel timing cross-reference ---
    // If BOTH SecureRDTSC results are non-zero, OR the flag at +0x4bb.
    // This means: kernel timing detected VM overhead → reinforce display detection.
    if (g_State->secureRDTSC_result1 != 0 && g_State->secureRDTSC_result2 != 0) {
        g_State->flags_0x4bb |= 1;
    }

    // --- Step 4: Audio/input device matching (list at +0x9e0, count at +0x9f8) ---
    // Second device list — likely audio capture devices or USB input devices.
    // Pattern indices and flags:
    //   Table[0x12][0xeea]           → local_4244
    //   Table[0x12][0xed3]           → local_4258
    //   Table[0x12][0x64a]           → local accumulator
    //   Table[0x12][0xdbf]           → local_4248
    //   Table[0x12][0xf18]           → DAT_140cedf40 + 0x4b8
    //   Table[0x12][0x68f]           → DAT_140cedf40 + 0x4bc
    //   Table[0x12][0xf01]           → DAT_140cedf40 + 0x46466
    //   Table[0x12][0xda8]           → not stored (compare only)
    //   Table[0x12][0x564]           → DAT_140cedf40 + 0x540

    // --- Step 5: Conditional flag enforcement ---
    // Uses FUN_14013cc70(flag_code, 0, 0) as the central flag reporting dispatch.
    // Each flag code represents a specific detection category.
    //
    // Flag codes observed:
    //   5    — VM display adapter flagged (when +0x4bb is clear but secondary check fires)
    //   0x47 — Blacklisted file found on disk (PathFileExistsA or registry check)
    //   0x49 — Specific device class detected (+0x4bc set + secondary validation)
    //   0x4b — FUN_14026a3c0 check failed (unknown pre-check)
    //   0x6d — Device at +0x4b8 flagged + secondary validation
    //   0x6e — Config requires feature (+0xa94) but display flag +0x31c is clear

    if (g_State->flags_0x4bb == 0) {
        if (FUN_140232f90() != 0)  // secondary VM validation
            FUN_14013cc70(5, 0, 0);
    }
    if (g_State->flags_0x4bc != 0) {
        if (FUN_1402319b0() != 0)
            FUN_14013cc70(0x49, 0, 0);
    }

    // --- Step 6: File existence check ---
    // Server supplies a filesystem path (table 0x12, index 0x54d).
    // If that file exists on disk → flag 0x47.
    // Also checks two registry/path patterns (indices 0x57b, 0x592).
    const char* checkPath = GetServerString(0x12, 0x54d);
    if (PathFileExistsA(checkPath) || FUN_1402a19e0(/*...*/) != 0)
        FUN_14013cc70(0x47, 0, 0);

    // --- Step 7: Loaded module blacklist scanning ---
    // Enumerates all modules loaded in the LDB process itself.
    // K32EnumProcessModules → store handles at +0x3e00 (max 0x200 = 512 modules)
    // Module count stored at +0x4e00.
    // For each module:
    //   K32GetModuleFileNameExA → get full path
    //   Match against two blacklists from FUN_140226e70:
    //     List 8  → if match: +0x46696 = 1 (injected DLL category A)
    //     List 10 → if match: +0x46694 = 1 (injected DLL category B)
    //   Either match: +0x46693 = 1 (any injected DLL detected)
    //   On match, logs: "%s%s %s" with server labels (lists 1 and 7)

    DWORD pid = GetCurrentProcessId();
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    K32EnumProcessModules(hProc, g_State->moduleHandles, 0x1000, &cbNeeded);
    g_State->moduleCount = min(cbNeeded, 0x1000) / sizeof(HMODULE);
    for (int i = 1; i < g_State->moduleCount; i++) {
        char modPath[260];
        K32GetModuleFileNameExA(hProc, g_State->moduleHandles[i], modPath, 260);
        // Pattern match against blacklists
    }

    // --- Step 8: Spyrix keylogger detection ---
    // Hardcoded string "Spyrix" (0x20786972797053 little-endian) compared against
    // something at DAT_140cedf80 + 0xf370 → offset 0x4008 (stored at +0x468b4).
    // This is explicit detection of Spyrix monitoring software.

    // --- Step 9: Process list telemetry ---
    // Builds JSON-like payload:
    //   "process.list", "Process List", "process.list.processes", "Process List"
    // Iterates all processes via FUN_14024b1e0, collects names into a 16KB buffer
    // (local_4058[4096] + local_2858[10240]). Submits full process enumeration
    // to the Respondus server as part of the telemetry report.

    snprintf(g_SecondaryState->telemetryBuffer, 0x4000,
        "\"process.list\", \"Process List\", "
        "\"process.list.processes\", \"Process List\", \"");
    for (int i = 0; i < processCount; i++) {
        // Append each process name/path to the telemetry payload
    }
}


// ---------------------------------------------------------------------------
//  FUN_14013cc70 — Central Flag Reporter / Detection Event Dispatcher
//  Called from TelemetryReporter and other detection subsystems.
//
//  Takes a numeric flag code identifying the detection category.
//  Known flag codes (from TelemetryReporter calls):
//    5     — VM display adapter detected (secondary check)
//    0x47  — Blacklisted file found on disk
//    0x49  — Specific device class detected
//    0x4b  — Pre-check validation failed
//    0x6d  — Device flag + secondary validation match
//    0x6e  — Config mismatch (feature required but display flag clear)
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
//  Detection Flag Map — Global State Structure Offsets
//
//  DAT_140cedf40 (primary state, 0x4aa78 bytes):
//    +0x0311  — Display device match (server pattern 0xe77)
//    +0x0312  — Display device match (server pattern 0xe8e)
//    +0x031c  — Display device match (server pattern 0xe60)
//    +0x02e9  — Display device match (server pattern 0xd35)
//    +0x04b8  — Audio/input device match (server pattern 0xf18)
//    +0x04b9  — Display device match (server pattern 0x633)
//    +0x04bb  — VM display match (pattern 0x4ac) | kernel timing cross-ref
//    +0x04bc  — Audio/input device match (server pattern 0x68f)
//    +0x0540  — Audio/input device match (server pattern 0x564)
//    +0x09b9  — Display device match (server pattern 0xea5)
//    +0x09c0  — Display device list base pointer (std::string array)
//    +0x09d8  — Display device list count
//    +0x09e0  — Audio/input device list base pointer
//    +0x09f8  — Audio/input device list count
//    +0x09fc  — Device removal index
//    +0x0a00  — Device removal count
//    +0x0bf0  — Process flag (cleared in telemetry builder)
//    +0x1bf0  — Process counter (cleared in telemetry builder)
//    +0x3e00  — HMODULE array (K32EnumProcessModules, max 512)
//    +0x4e00  — Loaded module count
//    +0x4e04  — Module scan complete flag
//    +0x46465 — Display device match (server pattern 0xe49)
//    +0x46466 — Audio/input device match (server pattern 0xf01)
//    +0x46568 — Kernel SecureRDTSC result 1 (non-zero = VM timing)
//    +0x4656c — Kernel SecureRDTSC result 2 (non-zero = VM timing)
//    +0x46690 — Display device match (server pattern, table entry)
//    +0x46693 — Any injected DLL detected (bool)
//    +0x46694 — Injected DLL category B detected (bool)
//    +0x46696 — Injected DLL category A detected (bool)
//    +0x468b4 — Spyrix process info field
//    +0x46970 — Driver communication status
//    +0x4696c — Driver handshake result
//
//  DAT_140cedf80 (secondary state):
//    +0x4acc  — Telemetry payload buffer (0x4000 bytes)
//    +0xf36d  — Display device match (server pattern 0x6a6)
//    +0xf370  — Process list structure pointer
//
//  DAT_140cedf50 (server config):
//    +0x0a94  — Feature requirement flag
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
//  PostInitDetectionSetup (FUN_140192870) — Detection State Consumer
//  7,038 bytes, contiguous
//  Decompiled from LockDownBrowser.exe at 0x140192870
//
//  Called after InitOrchestrator completes. Reads detection flags from the
//  global state to configure runtime detection behavior — which monitors to
//  activate, which enforcement level to use, etc.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
//  ServerProfileHandler (FUN_14016f020) — Secondary VM Detection Caller
//  Decompiled from LockDownBrowser.exe at 0x14016f020
//
//  Handles server profile decoding and auto-launch. This is where
//  SecondaryVMDetection (FUN_140231310) is invoked — called from within
//  the profile processing loop after the server profile is downloaded
//  and decrypted.
//
//  Also performs:
//    - AddClipboardFormatListener (clipboard monitoring)
//    - Pearson TPI domain whitelisting:
//      "tpi.bb.pearsoncmg.com,login.pearsoncmg.com,
//       www.mathxl.com,xlitemprod.pearsoncmg.com"
//    - Multi-institution auto-launch retry loop
//    - D2L autolaunch focus restoration
//
//  Error dialog codes on failure:
//    0x12 (18) — Profile decoding failed
//    0x28 (40) — No server response
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
//  DriverServiceChecker (FUN_1402ae7e0) — Kernel Driver Prerequisite
//  Decompiled from LockDownBrowser.exe at 0x1402ae7e0
//
//  Checks whether the LockDownService215 kernel driver is installed and
//  running before the application proceeds. Uses the Windows Service
//  Control Manager API chain.
//
//  Return codes:
//    0 — Service not found (ERROR_SERVICE_DOES_NOT_EXIST = 0x424)
//    1 — SCM open failed (no admin rights or policy block)
//    2 — Service exists but OpenService failed (access denied?)
//    3 — QueryServiceStatusEx failed
//    4 — Service is running (SERVICE_RUNNING) → proceed
// ---------------------------------------------------------------------------

int DriverServiceChecker() {
    char serviceName[64];     // from string table index 0x20
    wchar_t serviceNameW[64]; // wide version for Win32 API

    GetStringFromTable(g_ServerStrings, serviceName, 0x20);
    GetWideStringFromTable(g_ServerStrings, serviceNameW, 0x20);

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) {
        GetLastError();
        LogMessage("SCM open failed, code = %d", 1);
        return 1;
    }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceNameW, SERVICE_QUERY_STATUS);
    if (hService == NULL) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST)
            return 0;
        LogMessage("Service open failed, code = %d", 2);
        return 2;
    }

    SERVICE_STATUS_PROCESS ssp = {};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                              (BYTE*)&ssp, sizeof(ssp), &needed)) {
        GetLastError();
        LogMessage("Query failed, code = %d", 3);
        CloseServiceHandle(hSCM);
        return 3;
    }

    LogMessage("Service state = %d, code = %d", ssp.dwCurrentState, 4);

    // ssp.dwCurrentState:
    //   1 = SERVICE_STOPPED
    //   2 = SERVICE_START_PENDING
    //   3 = SERVICE_STOP_PENDING
    //   4 = SERVICE_RUNNING      ← success
    //   5 = SERVICE_CONTINUE_PENDING
    //   6 = SERVICE_PAUSE_PENDING
    //   7 = SERVICE_PAUSED

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return ssp.dwCurrentState;  // caller checks for 4
}
