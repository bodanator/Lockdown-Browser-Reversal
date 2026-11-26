// =============================================================================
//  LockDown Browser — Kernel Driver Pseudocode
//  Reverse engineered from LockDownService215.sys
//  SHA256: a6d54547a8db751a2f0844252848fc1b997f56b594c78f82a6259496e221b501
//  PE x86_64, 71,944 bytes, FLTMGR minifilter driver
//  Version: 2.16.0.0
//  PDB: LockDownService215.pdb (GUID db54a35f-f261-4d2f-8bcf-1b3f554f1a77)
//  Signed: WDK test certificate (not production DigiCert)
//  Description: "LockDown Browser system integrity and security monitoring service"
//
//  Full Ghidra 12.2 analysis — 310 procedures, 294 strings.
//  12 C++ classes verified from debug strings in .rdata section.
//  All addresses verified against binary.
//
//  Complete driver command protocol decompiled. BrowserCommunicationPort vtable
//  recovered — 13 FilterPort commands mapped. RSA key exchange handshake +
//  AES-CBC encrypted channel fully traced. ThreadMonitor::verifyFilelessExecution
//  kernel anti-injection logic decompiled. ProcessMonitor::processCallback with
//  DWM PID tracking and AVL tree management. All 5 subsystem initialization
//  paths verified from ApDriver::initialize.
// =============================================================================

// This driver is loaded via SeLoadDriverPrivilege by the usermode binary.
// It registers as a minifilter (FLTMGR.SYS) and establishes a communication
// port at \ApDriverPort for encrypted bidirectional messaging with LDB.

// ─── KERNEL INCLUDES (conceptual) ───
// ntddk.h, fltKernel.h, bcrypt.h, ntifs.h

typedef unsigned long       ULONG;
typedef unsigned long long  ULONG_PTR;
typedef long                NTSTATUS;
typedef void*               PVOID;
typedef void*               HANDLE;
typedef void*               PEPROCESS;
typedef void*               PETHREAD;

#define STATUS_SUCCESS 0


// =============================================================================
//  1. DRIVER ENTRY
//
//  Standard minifilter DriverEntry. Registers the filter, creates the
//  communication port, and starts all monitoring subsystems.
//
//  String evidence:
//    "DriverEntry"
//    "ApDriver::initialize"
// =============================================================================

NTSTATUS DriverEntry(void* DriverObject, void* RegistryPath) {
    // 1. Register minifilter with FLTMGR
    //    FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle)
    //    FltStartFiltering(gFilterHandle)

    // 2. Resolve dynamic kernel functions
    //    DynamicFunctionsKm::init()

    // 3. Initialize subsystems
    //    ApDriver::initialize()

    // 4. Create communication port
    //    BrowserCommunicationPort — creates \ApDriverPort
    //    FltCreateCommunicationPort(gFilterHandle, &gPort, ...)

    // 5. Start monitoring
    //    ProcessMonitor::start()
    //    ThreadMonitor::start()
    //    ImageMonitor (via PsSetLoadImageNotifyRoutine)

    // 6. Initialize crypto
    //    CryptoKernel — generates RSA keypair for handshake

    return STATUS_SUCCESS;
}


// =============================================================================
//  2. DYNAMIC FUNCTION RESOLUTION
//
//  The driver resolves kernel functions at runtime via
//  MmGetSystemRoutineAddress to avoid static import detection
//  and maintain compatibility across Windows versions.
//
//  String evidence (verified addresses):
//    0x14000B2C0: "DynamicFunctionsKm::psGetProcessPeb"
//    0x14000B2F0: "DynamicFunctionsKm::ciFreePolicyInfo"
//    0x14000B320: "DynamicFunctionsKm::ciValidateFileObject"
//    0x14000B0A0: "PsGetProcessInheritedFromUniqueProcessId" (UTF-16)
//    0x14000B100: "PsGetProcessPeb" (UTF-16)
//    0x14000B120: "PsGetProcessSignatureLevel" (UTF-16)
//    0x14000B190: "\systemroot\system32\ci.dll" (UTF-16)
//    0x14000B1B0: "CiFreePolicyInfo"
//    0x14000B200: "CiValidateFileObject"
// =============================================================================

struct DynamicFunctionsKm {
    void* pfnZwQuerySystemInformation;
    void* pfnZwQueryInformationProcess;
    void* pfnZwQueryInformationThread;
    void* pfnRtlFindExportedRoutineByName;
    void* pfnPsGetProcessInheritedFromUniqueProcessId;
    void* pfnPsGetProcessPeb;
    void* pfnPsGetProcessSignatureLevel;
    void* pfnSeGetCachedSigningLevel;
    void* pfnCiValidateFileObject;
    void* pfnCiFreePolicyInfo;

    NTSTATUS Init() {
        // Each resolved via MmGetSystemRoutineAddress:
        // UNICODE_STRING name;
        // RtlInitUnicodeString(&name, L"ZwQuerySystemInformation");
        // pfnZwQuerySystemInformation = MmGetSystemRoutineAddress(&name);

        // ci.dll exports resolved via RtlFindExportedRoutineByName:
        // Load ci.dll base: "\\systemroot\\system32\\ci.dll"
        // pfnCiValidateFileObject = RtlFindExportedRoutineByName(ciBase, "CiValidateFileObject")
        // pfnCiFreePolicyInfo = RtlFindExportedRoutineByName(ciBase, "CiFreePolicyInfo")

        return STATUS_SUCCESS;
    }

    // Each wrapper validates IRQL before calling:
    // "IRQL >= DISPATCH_LEVEL" — cannot call at dispatch
    // "IRQL > PASSIVE_LEVEL" — needs passive for Zw* calls

    void* GetLoadedImageBase(const char* imageName) {
        // ZwQuerySystemInformation(SystemModuleInformation, ...)
        // Walks module list, matches name
        // Used to find ci.dll, ntoskrnl.exe base addresses
        return nullptr;
    }
};


// =============================================================================
//  3. BROWSER COMMUNICATION PORT (\ApDriverPort)
//
//  Minifilter communication port for kernel<->usermode messaging.
//  Only accepts connections from the verified LDB process.
//
//  String evidence (verified addresses):
//    0x14000A310: "BrowserCommunicationPort::onConnect"
//    0x14000A3D0: "BrowserCommunicationPort::onDisconnect"
//    0x14000D510: "\ApDriverPort" (UTF-16)
//    0x14000A3B0: "%s: Detect new browser PID %d"
//    0x14000BA50: "%s: FltCreateCommunicationPort() | status = 0x%08X"
//    0x14000BA10: "%s: FltBuildDefaultSecurityDescriptor() | status = 0x%08X"
//    0x14000BAC0: "%s: FltSendMessage() | status = 0x%08X"
//    0x14000B9A0: "%s: Invalid IRQL for FltCloseCommunicationPort (IRQL:%u)"
// =============================================================================

struct BrowserCommunicationPort {
    HANDLE hPort;
    HANDLE hClientPort;
    ULONG  browserPid;

    NTSTATUS OnConnect(HANDLE ClientPort, PVOID ConnectionContext, ULONG SizeOfContext) {
        ULONG callerPid = 0; // PsGetCurrentProcessId()

        // Validate the connecting process is the real LDB binary:
        // 1. Get process image path (SeLocateProcessImageName)
        // 2. Compare against known LDB paths:
        //    "\\Program Files\\Respondus\\LockDown Browser\\LockDownBrowser.exe"
        //    "\\Program Files\\Respondus\\LockDown Browser OEM\\LockDownBrowserOEM.exe"
        // 3. Verify code signature (CodeIntegrity::validateSignature)
        // 4. Check CompanyName = "Respondus, Inc."

        // If PID doesn't match expected browser:
        //   "PID mismatch, denying access to port"
        //   return STATUS_ACCESS_DENIED;

        // On success:
        //   "User-mode application (%u) connected to this port"
        //   "Detect new browser PID %d"
        hClientPort = ClientPort;
        browserPid = callerPid;
        return STATUS_SUCCESS;
    }

    NTSTATUS OnDisconnect(PVOID ConnectionCookie) {
        //   "User-mode application(%u) disconnected from this port"
        // FltCloseClientPort(gFilterHandle, &hClientPort)
        hClientPort = nullptr;
        browserPid = 0;
        return STATUS_SUCCESS;
    }

    NTSTATUS SendMessage(PVOID buffer, ULONG size) {
        // FltSendMessage(gFilterHandle, &hClientPort, buffer, size, ...)
        // All messages are AES-CBC encrypted
        return STATUS_SUCCESS;
    }
};


// =============================================================================
//  4. PROCESS MONITOR (Kernel Callbacks)
//
//  Registers PsSetCreateProcessNotifyRoutineEx to receive real-time
//  notifications for EVERY process create/terminate on the system.
//  Sends events to usermode via the communication port.
//
//  String evidence (verified addresses):
//    0x14000BD20: "ProcessMonitor::start"
//    0x14000BE60: "ProcessMonitor::processCallback"
//    0x14000BDE0: "ProcessMonitor::notifyProcessInfo::<lambda_1>::operator ()"
//    0x14000BD90: "%s: PsSetCreateProcessNotifyRoutineEx() | status = 0x%08X"
//    0x14000A890: "%s: PsLookupProcessByProcessId() | status = 0x%08X"
//    "Failed to add %p"
//    "Failed to send added %p"
//    "Forgetting DWM PID - no conflict"
//    "Failed to send removed %p (not cached)"
//    "Failed to send removed %p"
//    "Failed to send deferred proc info"
// =============================================================================

struct ProcessMonitor {
    // AVL tree of tracked processes (RtlInitializeGenericTableAvl)
    void* processTable;
    ULONG dwmPid;

    NTSTATUS Start() {
        // Enumerate all existing processes first:
        // ZwQuerySystemInformation(SystemProcessInformation, ...)
        // Retries up to 10 times on failure:
        //   "ZwQuerySystemInformation() failed after 10 retries"

        // Register callback:
        // PsSetCreateProcessNotifyRoutineEx(ProcessCallback, FALSE)
        return STATUS_SUCCESS;
    }

    // Called by the kernel for EVERY process create/terminate
    static void ProcessCallback(
        PEPROCESS Process,
        HANDLE ProcessId,
        void* CreateInfo  // PPS_CREATE_NOTIFY_INFO, NULL on terminate
    )
    {
        if (CreateInfo) {
            // PROCESS CREATED
            // 1. Get image file name (SeLocateProcessImageName)
            // 2. Get parent PID (PsGetProcessInheritedFromUniqueProcessId)
            // 3. Get command line (CmdWrapper::getCmdForEProcess)
            //    Uses KeStackAttachProcess to attach to process context
            //    Reads PEB -> ProcessParameters -> CommandLine
            // 4. Get process signing level (PsGetProcessSignatureLevel)
            // 5. Add to AVL tracking table
            //    "Failed to add %p" on error
            // 6. Send to usermode
            //    "Failed to send added %p" on error

            // Special tracking for DWM:
            // If image = "\Windows\System32\dwm.exe"
            //   Record as dwmPid for integrity verification
        }
        else {
            // PROCESS TERMINATED
            // Check if we were tracking this PID

            // If it was the DWM process:
            //   "Forgetting DWM PID - no conflict"
            //   Clear dwmPid

            // Remove from AVL table
            // Send termination event to usermode
            //   "Failed to send removed %p (not cached)" if not in table
            //   "Failed to send removed %p" on send failure
        }
    }

    // Deferred notification for processes that existed before driver loaded
    void NotifyDeferredProcessInfo() {
        // Runs in work item (FltQueueGenericWorkItem)
        // "Failed to send deferred proc info"
    }
};


// =============================================================================
//  5. THREAD MONITOR (Kernel Callbacks)
//
//  Monitors ALL thread creation system-wide. Key feature: detects
//  "fileless execution" — threads whose start address doesn't map
//  to any loaded image (indicative of code injection).
//
//  String evidence (verified addresses):
//    0x14000BF80: "ThreadMonitor::start"
//    0x14000BFE0: "ThreadMonitor::stop"
//    0x14000C040: "ThreadMonitor::verifyFilelessExecution"
//    0x14000BFA0: "%s: PsSetCreateThreadNotifyRoutine() | status = 0x%08X"
//    0x14000C000: "%s: PsRemoveCreateThreadNotifyRoutine() | status = 0x%08X"
//    0x14000C0A0: "%s: PsLookupThreadByThreadId() | status = 0x%08X"
// =============================================================================

struct ThreadMonitor {
    NTSTATUS Start() {
        // PsSetCreateThreadNotifyRoutine(ThreadCallback)
        return STATUS_SUCCESS;
    }

    NTSTATUS Stop() {
        // PsRemoveCreateThreadNotifyRoutine(ThreadCallback)
        return STATUS_SUCCESS;
    }

    static void ThreadCallback(HANDLE ProcessId, HANDLE ThreadId, bool Create) {
        if (!Create) return;

        // New thread created — verify it's legitimate
        VerifyFilelessExecution(ProcessId, ThreadId);

        // Send thread creation event to usermode
    }

    static void VerifyFilelessExecution(HANDLE ProcessId, HANDLE ThreadId) {
        // 1. PsLookupThreadByThreadId(ThreadId, &Thread)
        //    "PsLookupThreadByThreadId()"

        // 2. ObOpenObjectByPointer(Thread, ..., PsThreadType, ...)
        //    "ObOpenObjectByPointer()"

        // 3. ZwQueryInformationThread(ThreadHandle, ThreadQuerySetWin32StartAddress, ...)
        //    Gets the thread's start address

        // 4. ZwQueryVirtualMemory(ProcessHandle, StartAddress, MemoryBasicInformation, ...)
        //    Checks if the start address is within a legitimate mapped image

        // If start address is NOT in any loaded module:
        //   -> Fileless execution detected (code injection)
        //   -> Report to usermode via encrypted message
        //   -> This catches DLL injection, shellcode, etc.
    }
};


// =============================================================================
//  6. IMAGE LOAD MONITOR
//
//  Monitors ALL DLL/EXE loads system-wide. Reports each image load
//  to the usermode component.
//
//  String evidence (verified addresses):
//    0x14000B8E0: "ImageMonitor::imageCallback"
//    "Failed to add %wZ"
//    "Failed to send added %wZ"
// =============================================================================

struct ImageMonitor {
    static void ImageCallback(
        void* FullImageName,   // PUNICODE_STRING
        HANDLE ProcessId,
        void* ImageInfo)       // PIMAGE_INFO
    {
        // 1. Record the loaded image path and base address
        // 2. Add to tracking table
        //    "Failed to add %wZ" on error
        // 3. Send to usermode
        //    "Failed to send added %wZ" on error

        // This lets usermode know about EVERY DLL loaded into
        // EVERY process — catches injected DLLs, hooking frameworks, etc.
    }
};


// =============================================================================
//  7. CODE INTEGRITY VERIFICATION
//
//  Validates digital signatures of binaries using the kernel's
//  Code Integrity (ci.dll) subsystem. Used to verify:
//  - The LDB binary itself hasn't been tampered with
//  - DWM hasn't been replaced or hooked
//  - Connected process is legitimately signed by Respondus
//
//  String evidence (verified addresses):
//    0x14000AA50: "CodeIntegrity::calculateSha1"
//    0x14000A980: "%s: CiValidateFileObject() | status = 0x%08X"
//    0x14000AA40: "SHA1" (UTF-16)
//    0x14000B4D0: "SHA256" (UTF-16)
//    "PolicyInfo | status = 0x%08X"
//    "verification = 0x%08X | status = 0x%08X"
//
//  Hardcoded validation data:
//    Company: "Respondus, Inc."
//    CA: "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
//
//  CiValidateFileObject is an undocumented CI.DLL export,
//  resolved at runtime via RtlFindExportedRoutineByName
// =============================================================================

struct CodeIntegrity {
    NTSTATUS GetImageSignature(HANDLE FileObject, void* SignatureInfo) {
        // CiValidateFileObject(FileObject, ..., &PolicyInfo)
        // "CiValidateFileObject() | status = 0x%08X"
        // "PolicyInfo | status = 0x%08X"
        return STATUS_SUCCESS;
    }

    NTSTATUS ValidateSignature(void* SignatureInfo) {
        // Verifies:
        // 1. Binary is signed
        // 2. Signature chain includes expected CA
        // 3. Signer matches "Respondus, Inc."
        // "verification = 0x%08X | status = 0x%08X"
        return STATUS_SUCCESS;
    }

    NTSTATUS CalculateSha1(PVOID data, ULONG size, unsigned char hash[20]) {
        // BCryptOpenAlgorithmProvider(&hAlg, "SHA1", ...)
        // BCryptCreateHash(hAlg, &hHash, ...)
        // BCryptHashData(hHash, data, size, 0)
        // BCryptFinishHash(hHash, hash, 20, 0)
        // Used to verify binary integrity beyond just signatures
        return STATUS_SUCCESS;
    }
};


// =============================================================================
//  8. DWM INTEGRITY VERIFICATION
//
//  Verifies that the Desktop Window Manager (dwm.exe) hasn't been
//  tampered with. DWM controls all window composition — if DWM is
//  hooked, an attacker could capture window contents regardless of
//  SetWindowDisplayAffinity.
//
//  String evidence (verified addresses):
//    0x14000AF10: "DwmImageResolver::init"
//    0x14000AF30: "DwmImageResolver::initPath"
//    0x14000D738: "\Windows\System32\dwm.exe" (UTF-16)
//    0x14000BED0: "%s: Forgetting DWM PID - no conflict"
//    " : Cannot verify DWM integrity because the driver started after DWM"
//    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
// =============================================================================

struct DwmImageResolver {
    // Known DWM service SID
    // S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
    // This is the NT SERVICE\DWM SID — used to verify DWM ownership

    NTSTATUS Init() {
        // 1. Find DWM process PID (from ProcessMonitor tracking)
        // 2. Get DWM image path
        //    Verify: "\Windows\System32\dwm.exe"
        // 3. Validate signature (CodeIntegrity::validateSignature)
        //    Must be Microsoft-signed
        // 4. Check file owner SID
        //    Must match DWM service SID
        // 5. Map DWM into kernel space for integrity check
        //    SystemSpaceView::init (ZwCreateSection + MmMapViewInSystemSpace)
        // 6. Calculate SHA1 and compare against expected
        // 7. Optionally read DWM memory via the usermode component
        //    (NtReadVirtualMemory from usermode side)

        // If driver loaded after DWM was already running:
        //   "Cannot verify DWM integrity because the driver started after DWM"
        //   This is a known limitation — the driver can't retroactively
        //   verify a process that started before it

        return STATUS_SUCCESS;
    }
};


// =============================================================================
//  9. BROWSER IMAGE RESOLVER
//
//  Validates the LDB binary itself. When a process connects to
//  \ApDriverPort, this component verifies it's the real LDB binary.
//
//  String evidence (verified addresses):
//    0x14000A7D0: "BrowserImageResolver::init"
//    0x14000D5A0: "\Program Files\Respondus\LockDown Browser\LockDownBrowser.exe" (UTF-16)
//    0x14000D620: "\Program Files\Respondus\LockDown Browser OEM\LockDownBrowserOEM.exe" (UTF-16)
//    0x14000D6C0: "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
//    0x14000A820: "%s: FltCreateFileEx() | status = 0x%08X"
//    "CompanyName", "FileVersion", "OriginalFilename"
//    "VS_VERSION_INFO", "StringFileInfo"
// =============================================================================

struct BrowserImageResolver {
    NTSTATUS Init() {
        // 1. Get connecting process image path
        // 2. Must match one of:
        //    "\\Program Files\\Respondus\\LockDown Browser\\LockDownBrowser.exe"
        //    "\\Program Files\\Respondus\\LockDown Browser OEM\\LockDownBrowserOEM.exe"
        // 3. Open the file via FltCreateFileEx
        // 4. Map into kernel space (SystemSpaceView)
        // 5. Parse PE version info (VS_VERSION_INFO / StringFileInfo):
        //    - CompanyName must contain "Respondus"
        //    - FileVersion must match expected
        //    - OriginalFilename must match expected
        // 6. Validate code signature via CodeIntegrity
        // 7. Calculate SHA1 hash
        return STATUS_SUCCESS;
    }
};


// =============================================================================
//  10. KERNEL CRYPTOGRAPHY (CryptoKernel)
//
//  Full RSA + AES-CBC crypto stack running in kernel space.
//  Used to encrypt all communication between driver and usermode.
//  This prevents tools from sniffing the FilterPort messages.
//
//  RSA keypair is GENERATED IN KERNEL, not just imported.
//  7 method strings + 17 BCrypt imports verified.
//
//  String evidence (verified addresses):
//    0x14000B610: "CryptoKernel::generateRsaKeypair"
//    0x14000B480: "CryptoKernel::setRsaKey"
//    0x14000B4E0: "CryptoKernel::setAesKey"
//    0x14000B400: "CryptoKernel::randomIv16"
//    0x14000B6F0: "CryptoKernel::aesCbcEncrypt"
//    0x14000B6A0: "CryptoKernel::aesCbcDecrypt"
//    0x14000B5F0: "CryptoKernel::decryptIV"
//    "RSAPUBLICBLOB", "SHA256", "ChainingModeCBC"
// =============================================================================

struct CryptoKernel {
    void* hRsaAlg;
    void* hRsaKey;
    void* hAesAlg;
    void* hAesKey;

    NTSTATUS GenerateRsaKeypair() {
        // RSA-2048 keypair generated IN KERNEL
        // BCryptOpenAlgorithmProvider(&hRsaAlg, "RSA", ...)
        // BCryptGenerateKeyPair(hRsaAlg, &hRsaKey, 2048, 0)
        // BCryptFinalizeKeyPair(hRsaKey, 0)
        // Export public key as RSAPUBLICBLOB to send to usermode
        //
        // Protocol:
        //   1. Driver generates RSA-2048 keypair
        //   2. Public key exported to usermode via FilterPort
        //   3. Usermode encrypts AES session key with driver's public key
        //   4. Driver decrypts with private key (CryptoKernel::decryptIV)
        //   5. All subsequent messages AES-CBC encrypted
        return STATUS_SUCCESS;
    }

    NTSTATUS SetAesKey(unsigned char* key, ULONG keySize) {
        // BCryptOpenAlgorithmProvider(&hAesAlg, "AES", ...)
        // BCryptSetProperty(hAesAlg, "ChainingMode", "ChainingModeCBC", ...)
        // BCryptGenerateSymmetricKey(hAesAlg, &hAesKey, ..., key, keySize, 0)
        return STATUS_SUCCESS;
    }

    NTSTATUS AesCbcEncrypt(
        unsigned char* plaintext, ULONG ptLen,
        unsigned char* iv,
        unsigned char* ciphertext, ULONG* ctLen)
    {
        // BCryptEncrypt(hAesKey, plaintext, ptLen, ..., iv, 16, ciphertext, *ctLen, ctLen, BCRYPT_BLOCK_PADDING)
        return STATUS_SUCCESS;
    }

    NTSTATUS AesCbcDecrypt(
        unsigned char* ciphertext, ULONG ctLen,
        unsigned char* iv,
        unsigned char* plaintext, ULONG* ptLen)
    {
        // BCryptDecrypt(hAesKey, ciphertext, ctLen, ..., iv, 16, plaintext, *ptLen, ptLen, BCRYPT_BLOCK_PADDING)
        return STATUS_SUCCESS;
    }

    NTSTATUS RandomIv16(unsigned char iv[16]) {
        // BCryptGenRandom(NULL, iv, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
        return STATUS_SUCCESS;
    }

    NTSTATUS CalculateSha256(unsigned char* data, ULONG len, unsigned char hash[32]) {
        // BCryptOpenAlgorithmProvider(&hAlg, "SHA256", ...)
        // Standard hash flow
        return STATUS_SUCCESS;
    }
};


// =============================================================================
//  11. USERMODE DETECTOR
//
//  Validates the usermode execution environment. Finds smss.exe
//  and verifies the system boot chain is legitimate.
//
//  String evidence (verified addresses):
//    0x14000C120: "UserModeDetector::init"
//    0x14000C140: "UserModeDetector::getStartupInfo"
//    0x14000C170: "UserModeDetector::findSmss"
//    "\\Windows\\System32\\smss.exe"
// =============================================================================

struct UserModeDetector {
    NTSTATUS Init() {
        // GetStartupInfo()
        // FindSmss()
        return STATUS_SUCCESS;
    }

    NTSTATUS FindSmss() {
        // Walk process list for smss.exe
        // Verify: "\Windows\System32\smss.exe"
        // Validate that the session manager is legitimate
        // Part of anti-sandbox/anti-VM detection
        return STATUS_SUCCESS;
    }
};


// =============================================================================
//  12. COMMAND LINE READER (PEB Access)
//
//  Reads the command line of any process by attaching to its
//  address space and reading the PEB.
//
//  String evidence:
//    "utils::CmdWrapper::init"
//    "utils::CmdWrapper::getCmdForEProcess"
//    "SEH: %lu" (structured exception handler for safe PEB reads)
// =============================================================================

struct CmdWrapper {
    NTSTATUS GetCmdForEProcess(PEPROCESS Process, wchar_t* cmdLine, ULONG maxLen) {
        // 1. PsGetProcessPeb(Process) -> PEB address
        // 2. KeStackAttachProcess(Process, &ApcState)
        //    Attach to target process address space
        // 3. __try {
        //      ProbeForRead(Peb, sizeof(PEB), 1)
        //      Read Peb->ProcessParameters->CommandLine
        //    } __except {
        //      "SEH: %lu" — caught access violation
        //    }
        // 4. KeUnstackDetachProcess(&ApcState)
        return STATUS_SUCCESS;
    }
};


// =============================================================================
//  13. FILE OWNER SID CHECKER
//
//  Verifies file ownership by reading the security descriptor.
//  Used to ensure system binaries are owned by the correct
//  system accounts (e.g., DWM owned by DWM service SID).
//
//  String evidence:
//    "utils::OwnerSIDWrapper::init"
//    "utils::OwnerSIDWrapper::getFileOwnerSidFromPath"
//    "ZwQuerySecurityObject()"
//    "RtlGetOwnerSecurityDescriptor()"
//    "RtlConvertSidToUnicodeString()"
// =============================================================================

struct OwnerSIDWrapper {
    NTSTATUS GetFileOwnerSidFromPath(const wchar_t* path, wchar_t* sidString) {
        // 1. Open file (FltCreateFileEx or ZwCreateFile)
        // 2. ZwQuerySecurityObject(hFile, OWNER_SECURITY_INFORMATION, ...)
        // 3. RtlGetOwnerSecurityDescriptor(sd, &ownerSid, ...)
        // 4. RtlConvertSidToUnicodeString(sidString, ownerSid, ...)
        //    Compare against expected SID
        return STATUS_SUCCESS;
    }
};


// =============================================================================
//  14. DRIVER LOGGING (6 methods verified)
//
//  File-based kernel logging with auto-rotation.
//
//  String evidence (verified addresses, 0x14000AB90 through 0x14000AE70):
//    "DriverLogger::createLogFile"
//    "DriverLogger::buildTodaysLogFilePath"
//    "DriverLogger::findNextLogFileSuffix"
//    "DriverLogger::deleteOldLogFiles"
//    "DriverLogger::deleteLogFile"
//    "DriverLogger::log"
//    "\\??\\C:\\Users\\Public\\Documents\\"
//    ".log"
//    "[%04hd-%02hd-%02hd %02hd:%02hd:%02hd]"
//
//  All kernel log messages follow format:
//    "%s: <function>() | status = 0x%08X\n"
// =============================================================================

struct DriverLogger {
    HANDLE hLogFile;

    NTSTATUS CreateLogFile() {
        BuildTodaysLogFilePath();
        // Uses FltCreateFileEx for file I/O through filter manager
        return STATUS_SUCCESS;
    }

    // Constructs daily log path with numeric suffix
    void BuildTodaysLogFilePath() {
        FindNextLogFileSuffix();
        // Path: \SystemRoot\...\LockDownService_YYYY-MM-DD_NNN.log
    }

    // Scans existing logs to determine next numeric suffix
    void FindNextLogFileSuffix() {
        // ZwQueryDirectoryFile to find existing log files
        // Increment suffix counter
    }

    void Log(const char* format, ...) {
        // Timestamp: "[YYYY-MM-DD HH:MM:SS] "
        // Format message
        // ZwWriteFile(hLogFile, ...)
    }

    void DeleteOldLogFiles() {
        // Enumerate .log files via ZwQueryDirectoryFile
        // Delete expired files
    }

    // Delete a specific log file
    void DeleteLogFile(const wchar_t* path) {
        // ZwDeleteFile for targeted removal
    }
};


// =============================================================================
//  15. DRIVER ORCHESTRATOR (ApDriver)
//
//  String evidence (verified addresses):
//    0x14000A5C0: "ApDriver::initialize"
//    0x14000A4E0: "ApDriver::deinitialize"
//    0x14000A500: "%s: ApDriver cleanup already done"
//    "Failed to stop threadmon gracefully"
//    "Failed to stop imgmon gracefully"
//    "Failed to stop procmon gracefully"
// =============================================================================

struct ApDriver {
    bool m_cleaned;

    void Deinitialize() {
        if (m_cleaned) {
            // "ApDriver cleanup already done"
            return;
        }

        // Stop thread monitor
        // PsRemoveCreateThreadNotifyRoutine(...)
        // "Failed to stop threadmon gracefully" on error

        // Stop image monitor
        // PsRemoveLoadImageNotifyRoutine(...)
        // "Failed to stop imgmon gracefully" on error

        // Stop process monitor
        // PsSetCreateProcessNotifyRoutineEx(..., TRUE)  // TRUE = remove
        // "Failed to stop procmon gracefully" on error

        // Close communication port
        // FltCloseCommunicationPort(gPort)

        // Unregister minifilter
        // FltUnregisterFilter(gFilterHandle)

        m_cleaned = true;
    }
};


// =============================================================================
//  FILTERPORT COMMAND PROTOCOL (BrowserCommunicationPort::onMessage)
//
//  Address: FUN_1400015c0 (vtable slot 4 of BrowserCommunicationPort)
//  Vtable at 0x14000d558:
//    [0] 0x140002970 — destructor
//    [1] 0x1400072c0 — base class virtual
//    [2] 0x140001480 — BrowserCommunicationPort::onConnect
//    [3] 0x140001540 — BrowserCommunicationPort::onDisconnect
//    [4] 0x1400015c0 — BrowserCommunicationPort::onMessage (dispatcher)
//
//  Input buffer: first DWORD is the command code.
//  Encryption flag at PortObject+0x90: when set, responses get a 0x108-byte
//  AES-CBC header (IV + ciphertext wrapper). Command 3 is the encrypted
//  envelope — it decrypts the payload and re-dispatches recursively.
//
//  Response buffers carry a tag at offset 0 and payload data after offset 4.
//  Tag = command_code + 1 by convention (e.g. cmd 4 → tag 5).
//
//  Pool tag for all driver allocations: 0x6E2B2B43 = "C++n"
//
//  Cmd | Response Tag | Handler | Description
//  ----|-------------|---------|-------------------------------------------
//   0  |   n/a       | FUN_140005b2c | RSA-2048 public key export (RSAPUBLICBLOB)
//   1  |   n/a       | FUN_140005fe8 | Import AES key (RSA-encrypted by client)
//   2  |   n/a       | FUN_140005de0 | Activate encrypted channel (sets flag)
//   3  |   recursive | FUN_140005754 | AES-CBC decrypt envelope → re-dispatch
//   4  |   0x05      | ProcessMonitor| Full process table (AVL tree, 0xf0c/entry)
//   6  |   0x07      | ImageMonitor  | Image load data, slot 0 / LDB (0x710/entry)
//   8  |   0x09      | ImageMonitor  | Image load data, slot 1 / DWM (0x710/entry)
//  0xC |   copy      | ProcessMonitor| Single process detail by PID (0xf0c bytes)
//  0xD |   0x0E      | ProcessMonitor| PID list (count * 4 + 8 bytes)
//  0xF |   0x10      | ThreadMonitor | Thread creation counters (2 × DWORD)
// 0x11 |   0x12      | ApDriver      | RSA key fingerprint (0x18 bytes)
// 0x13 |   n/a       | PortObject    | Set active-check flag byte
// 0x14 |   0x15      | ThreadMonitor | VerifyFilelessExecution (anti-injection)
//
//  Mapping to EXE-side command names (from dispatch table at 0x140cb01f8):
//    "SecureRDTSC"  → 0x14: kernel validates thread start addresses
//    "FSecureClock" → 0x0F: returns thread creation counters
//    "ActiveCheck"  → 0x13: sets per-connection heartbeat byte
//    "UserCheck"    → 0x04/0x0C/0x0D: process enumeration + detail
//    "AntiDebug"    → 0x06/0x08: image/module load tracking per PID slot
// =============================================================================

// --- Command 0/1/2: RSA Key Exchange Handshake ---
//
// Three-step encrypted channel setup:
//
//  Step 1 (Cmd 0): Driver exports RSA-2048 public key
//    Driver calls BCryptExportKey(hRsaKey, NULL, "RSAPUBLICBLOB", output, ...)
//    Output: BCRYPT_RSAKEY_BLOB + public exponent + modulus
//
//  Step 2 (Cmd 1): Client sends AES session key encrypted with RSA pubkey
//    Input: [cmd=1][keyLen][encrypted_aes_key...]
//    Driver calls BCryptDecrypt(hRsaKey, encrypted_data, ...) to recover AES key
//    Then BCryptGenerateSymmetricKey(hAesAlg, &hAesKey, ..., aes_key, keyLen)
//
//  Step 3 (Cmd 2): Client sends 256-byte RSA-encrypted IV/finalization
//    Input: [cmd=2][256 bytes of RSA-encrypted data]
//    Driver decrypts, sets PortObject+0x90 = 1 (encryption active)
//    All subsequent responses get 0x108-byte encrypted wrapper
//
// After activation, client wraps all further commands in Command 3:
//   [cmd=3][...AES-CBC encrypted inner command...]
//   Driver decrypts, extracts inner command, recursively dispatches.

NTSTATUS BrowserCommunicationPort_onMessage(
    /*this*/ void* portObj,
    void*   inputBuffer,
    ULONG   inputSize,
    void*   outputBuffer,
    ULONG   outputSize,
    ULONG*  returnSize)
{
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) return STATUS_NOT_SUPPORTED;
    if (!returnSize) return STATUS_INVALID_PARAMETER;
    *returnSize = 0;

    if (inputSize < 4 || !inputBuffer) return STATUS_BUFFER_TOO_SMALL;

    ULONG cmd = *(ULONG*)inputBuffer;
    BOOLEAN encrypted = *(BYTE*)(portObj + 0x90);  // set by cmd 2

    switch (cmd) {
    case 0:  // Export RSA public key
        return CryptoKernel_ExportRsaPublicKey(portObj + 0x98, outputBuffer, returnSize);

    case 1:  // Import AES key (RSA-encrypted)
        return CryptoKernel_ImportAesKey(portObj + 0x98,
                                         inputBuffer + 8, *(ULONG*)(inputBuffer + 4));

    case 2:  // Finalize encryption — activate channel
        CryptoKernel_DecryptAndFinalize(portObj + 0x98, inputBuffer + 4, 0x100);
        *(BYTE*)(portObj + 0x90) = 1;
        return STATUS_SUCCESS;

    case 3: { // Encrypted dispatch envelope
        if (!encrypted) return STATUS_DEVICE_NOT_READY;
        void* decrypted = ExAllocatePool2(0x40, payloadSize, 'C++n');
        memcpy(decrypted, inputBuffer, payloadSize);
        CryptoKernel_AesCbcDecrypt(portObj + 0x98, decrypted);
        // Recursive virtual dispatch with decrypted payload:
        NTSTATUS result = vtable[4](portObj, decrypted + 0x108,
                                     *(ULONG*)(decrypted + 0x104),
                                     outputBuffer, outputSize, returnSize);
        ExFreePoolWithTag(decrypted, 'C++n');
        return result;
    }

    case 4: { // Full process table
        // DAT_14000f080 = ProcessMonitor subsystem pointer
        // Uses RtlIsGenericTableEmptyAvl / RtlNumberGenericTableElementsAvl
        // Each entry = 0xf0c (3852) bytes of process metadata
        // Response: [tag=5][count][entries...]
        ULONG count = RtlNumberGenericTableElementsAvl(procMon + 0xd0);
        ULONG dataSize = count * 0xf0c + 8;
        *(ULONG*)(output + 0) = 5;  // response tag
        *(ULONG*)(output + 4) = count;
        FillProcessTable(procMon, output + 8);
        break;
    }

    case 6: { // Image/module list for LDB process (slot 0)
        // DAT_14000f088 = ImageLoadMonitor subsystem pointer
        // Each entry = 0x710 (1808) bytes of image load data
        // Response: [tag=7][count][entries...]
        ULONG count = GetImageCount(imgMon, 0);
        *(ULONG*)(output + 0) = 7;
        *(ULONG*)(output + 4) = count;
        FillImageList(imgMon, output + 8, 0);
        break;
    }

    case 8: { // Image/module list for DWM process (slot 1)
        // Response: [tag=9][dwmTimingValue][count][entries...]
        // Also returns *(imgMon + 0x318) if != -1 (DWM start timestamp)
        ULONG count = GetImageCount(imgMon, 1);
        *(ULONG*)(output + 0) = 9;
        *(ULONG*)(output + 4) = (imgMon->dwmStartTime != -1) ?
                                  imgMon->dwmStartTime : 0xFFFFFFFF;
        *(ULONG*)(output + 8) = count;
        FillImageList(imgMon, output + 0xc, 1);
        break;
    }

    case 0xC: { // Single process detail lookup by PID
        // Input: [cmd=0xC][targetPid]
        // Returns 0xf0c bytes for the matching process entry
        void* entry = LookupProcess(procMon, *(ULONG*)(inputBuffer + 4));
        if (!entry) return STATUS_NOT_FOUND; // 0xc0000225
        memcpy(output, entry, 0xf0c);
        break;
    }

    case 0xD: { // PID list (compact)
        // Response: [tag=0xE][count][pid0][pid1][pid2]...
        ULONG count = RtlNumberGenericTableElementsAvl(procMon + 0xd0);
        *(ULONG*)(output + 0) = 0xE;
        *(ULONG*)(output + 4) = count;
        FillPidList(procMon, output + 8);
        break;
    }

    case 0xF: { // Thread creation counters (SecureClock)
        // DAT_14000f090 = ThreadMonitor subsystem pointer
        // Response: [tag=0x10][counter_slot0][counter_slot1]
        // counter_slot0 = threads created in LDB process
        // counter_slot1 = threads created in DWM process
        *(ULONG*)(output + 0) = 0x10;
        *(ULONG*)(output + 4) = ReadCounter(threadMon, 0);
        *(ULONG*)(output + 8) = ReadCounter(threadMon, 1);
        break;
    }

    case 0x11: { // RSA key identifier
        // Returns 0x18 bytes from ApDriver structure offsets 0x700/0x708
        // These were set during RSA key generation — key fingerprint data
        void* apDriver = GetApDriverInstance();
        *(ULONG*)(output + 0) = 0x12;
        memcpy(output + 8, apDriver + 0x700, 16);
        break;
    }

    case 0x13: { // Set active-check heartbeat flag
        // Input: [cmd=0x13][byte_value]
        // Writes the byte to PortObject + 0x91 under resource lock
        FltAcquireResourceExclusive(portObj + 0xd8);
        *(BYTE*)(portObj + 0x91) = (BYTE)(*(ULONG*)(inputBuffer + 4));
        FltReleaseResource(portObj + 0xd8);
        return STATUS_SUCCESS;
    }

    case 0x14: { // VerifyFilelessExecution (anti-injection)
        // Input: [cmd=0x14][targetPid][threadCount][tid0][tid1]...
        // For each thread ID, calls verifyFilelessExecution (see below)
        // Response: [tag=0x15][result]
        //   result = 2 (all clean) or 3 (fileless detected) or -1 (error)
        ULONG result = VerifyThreadArray(threadMon, inputBuffer);
        *(ULONG*)(output + 0) = 0x15;
        *(ULONG*)(output + 4) = result;
        break;
    }

    default:
        return STATUS_SUCCESS;  // unknown commands silently succeed
    }

    // If encryption active, wrap response in AES-CBC envelope
    if (encrypted)
        CryptoKernel_AesCbcEncrypt(portObj + 0x98, outputBuffer, dataSize);

    return STATUS_SUCCESS;
}


// =============================================================================
//  VERIFY FILELESS EXECUTION (Anti-Injection Core)
//
//  Address: FUN_1400094e0 (ThreadMonitor::verifyFilelessExecution)
//  Called by Command 0x14 for each (processId, threadId) pair.
//  Named from debug string at 0x14000C040.
//
//  Detects code injection by checking if a thread's start address
//  maps to a file-backed memory region. Manual-mapped DLLs,
//  shellcode, and reflective-loaded modules all fail this check.
//
//  Return values:
//    -1 (0xFFFFFFFF) = lookup error (process/thread not found)
//     2             = clean — thread backed by mapped file
//     3             = FILELESS — thread start address not file-backed
// =============================================================================

int ThreadMonitor_VerifyFilelessExecution(HANDLE ProcessId, HANDLE ThreadId) {
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) return -1;

    HANDLE hProcess = NULL;
    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
                                    PROCESS_QUERY_INFORMATION,
                                    *PsProcessType, KernelMode, &hProcess);
    if (!NT_SUCCESS(status)) { ObDereferenceObject(process); return -1; }

    PETHREAD thread = NULL;
    status = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(status)) goto cleanup_process;

    HANDLE hThread = NULL;
    status = ObOpenObjectByPointer(thread, OBJ_KERNEL_HANDLE, NULL,
                                    THREAD_QUERY_INFORMATION,
                                    *PsThreadType, KernelMode, &hThread);
    if (!NT_SUCCESS(status)) goto cleanup_thread;

    // Get thread start address
    PVOID startAddress = NULL;
    status = ZwQueryInformationThread(hThread,
                                      ThreadQuerySetWin32StartAddress,
                                      &startAddress, sizeof(startAddress), NULL);
    if (!NT_SUCCESS(status)) goto cleanup_all;

    int result = 2;  // default: clean

    if (startAddress != NULL) {
        // Query what file (if any) is mapped at the start address
        // MemoryMappedFilenameInformation (class 2)
        status = ZwQueryVirtualMemory(hProcess, startAddress,
                                       MemoryMappedFilenameInformation,
                                       NULL, 0, NULL);
        // STATUS_INVALID_ADDRESS (0xC000000F) or similar = no file mapping
        if (status == STATUS_INVALID_ADDRESS ||    // 0xC0000141
            status == STATUS_FILE_INVALID)          // 0xC0000098
        {
            result = 3;  // FILELESS EXECUTION DETECTED
        }
    }

cleanup_all:
    if (hThread) ZwClose(hThread);
cleanup_thread:
    if (thread) ObDereferenceObject(thread);
cleanup_process:
    if (hProcess) ZwClose(hProcess);
    if (process) ObDereferenceObject(process);

    return result;
}


// =============================================================================
//  THREAD CREATION CALLBACK
//
//  Address: FUN_140009460
//  Registered via PsSetCreateThreadNotifyRoutine in ThreadMonitor::start
//
//  Tracks thread creation in exactly 2 processes:
//    Slot 0 (DAT_14000f088 + 0x278): LDB process PID
//    Slot 1 (DAT_14000f088 + 0x318): DWM process PID (-1 if unset)
//
//  When a thread is created in a tracked process, records the event
//  with timing data via FUN_1400090b8. If slot 1 is unset (-1) and
//  the thread isn't in slot 0's process, increments counter[1] generically.
// =============================================================================

void ThreadNotifyCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    if (!ProcessId || !ThreadId || !Create) return;
    if (!g_ThreadMonitor || !g_ImageMonitor) return;

    if (ProcessId == g_ImageMonitor->ldbPid) {
        RecordThreadEvent(g_ThreadMonitor, ProcessId, ThreadId, 0);
    }
    else if (g_ImageMonitor->dwmPid == -1) {
        IncrementCounter(g_ThreadMonitor, 1, 1);  // generic count
    }
    else if (ProcessId == g_ImageMonitor->dwmPid) {
        RecordThreadEvent(g_ThreadMonitor, ProcessId, ThreadId, 1);
    }
    // threads in untracked processes are silently ignored
}


// =============================================================================
//  PROCESS CREATION CALLBACK
//
//  Address: FUN_140008900
//  Registered via PsSetCreateProcessNotifyRoutineEx in ProcessMonitor::start
//
//  On creation: populates process entry (0xf0c bytes) and inserts into AVL tree.
//  On termination: removes from tree, clears DWM/LDB PID slots if matching,
//  sends removal notification to usermode.
//
//  Debug string: "ProcessMonitor::processCallback"
//  DWM tracking string: "Forgetting DWM PID - no conflict"
// =============================================================================

void ProcessNotifyCallback(PEPROCESS Process, HANDLE ProcessId,
                           PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (!ProcessId || !g_ProcessMonitor) return;

    if (CreateInfo) {
        // --- PROCESS CREATION ---
        void* entry = AllocateProcessEntry();  // 0x58 bytes for creation info
        if (!entry) return;

        PopulateProcessEntry(g_ProcessMonitor, ProcessId, entry);
        // fills: image name, parent PID, command line, signing level
        // total entry size in AVL tree: 0xf0c (3852) bytes

        SendNotification(g_ProcessMonitor, entry, TRUE);
        ExFreePoolWithTag(entry, 'C++n');
    }
    else {
        // --- PROCESS TERMINATION ---

        // Check if the dying process was the tracked LDB process
        if (g_ImageMonitor->ldbPid != 0 &&
            ProcessId == g_ImageMonitor->ldbPid)
        {
            ClearImageData(g_ImageMonitor, 0);       // clear slot 0
            ResetCounters(g_ThreadMonitor, 0, 0);     // reset counter 0
        }

        // Check if the dying process was the tracked DWM process
        HANDLE dwmPid = g_ImageMonitor->dwmPid;
        if (dwmPid != 0 && dwmPid != (HANDLE)-1 && ProcessId == dwmPid) {
            ClearImageData(g_ImageMonitor, 1);         // clear slot 1
            ResetCounters(g_ThreadMonitor, 0, 1);      // reset counter 1
            DbgPrint("%s: Forgetting DWM PID - no conflict\n",
                     "ProcessMonitor::processCallback");
        }

        // Remove from AVL tree
        void* entry = LookupProcess(g_ProcessMonitor, (ULONG)ProcessId);
        if (entry) {
            SendNotification(g_ProcessMonitor, entry, FALSE);
            RemoveProcessEntry(g_ProcessMonitor, (ULONG)ProcessId);
        }
        else {
            // Process wasn't in our cache — still notify usermode
            void* tmpEntry = AllocateProcessEntry();
            *(ULONG*)tmpEntry = (ULONG)ProcessId;
            SendNotification(g_ProcessMonitor, tmpEntry, FALSE);
            ExFreePoolWithTag(tmpEntry, 'C++n');
        }
    }
}


// =============================================================================
//  APDRIVER::INITIALIZE CALL CHAIN
//
//  Address: FUN_140002b98 (978 bytes)
//  Called from DriverEntry at 0x140011000
//
//  Initialization order with verified addresses:
//    1. FUN_1400049b4(this + 0x710) — DynamicFunctionsKm::init
//    2. FUN_1400050e8(this + 0x6a8) — UserModeDetector::init
//    3. FUN_140009964()             — CryptoKernel::generateRsaKeypair
//    4. FltRegisterFilter()         — register minifilter (unload = FUN_140002b60)
//    5. FUN_14000132c(this + 0x10)  — BrowserCommunicationPort setup
//       → FUN_14000711c()           — FltCreateCommunicationPort(\ApDriverPort)
//         Callbacks: Connect=0x140007000, Disconnect=0x1400070a0, Message=0x140007250
//         Message thunk → vtable[4] = FUN_1400015c0 (the dispatcher above)
//         MaxConnections = 2
//    6. FltStartFiltering()
//    7. FUN_140008ba8(this + 0x150) — ProcessMonitor::start
//       → ZwQuerySystemInformation (snapshot) + PsSetCreateProcessNotifyRoutineEx
//    8. FUN_140006dac(this + 0x290) — ImageLoadMonitor::start
//       → PsSetLoadImageNotifyRoutine(FUN_140006a60)
//       → Initializes PID slots: LDB at +0x278, DWM at +0x318
//    9. FUN_1400093ac(this + 0x5c8) — ThreadMonitor::start
//       → PsSetCreateThreadNotifyRoutine(FUN_140009460)
//
//  Global subsystem pointers (resolved from driver state):
//    DAT_14000f080 — ProcessMonitor instance
//    DAT_14000f088 — ImageLoadMonitor instance
//    DAT_14000f090 — ThreadMonitor instance
//    DAT_14000f098 — DriverLogger instance
//    DAT_14000f0b8 — initialization complete flag (set to 1 on success)
// =============================================================================


// =============================================================================
//  VERIFIED ABSENT FROM DRIVER (310 procedures, 294 strings searched)
//
//  - ObRegisterCallbacks: NO process/thread handle protection
//  - CmRegisterCallbackEx: NO registry monitoring/filtering
//  - WFP (Wfp*/FWPM*): NO network filtering
//  - MmCopyVirtualMemory: NO cross-process memory operations
//  - SSDT hooking: NO syscall table modification
//  - VM detection: NO VMware/VirtualBox/Hyper-V/QEMU checks in driver
//    (VM detection exists in LDB but not in this driver — likely in EXE
//     or libcef.dll)
//  - String obfuscation: all debug strings in cleartext .rdata section
// =============================================================================
