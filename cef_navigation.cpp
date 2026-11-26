// =============================================================================
//  LockDown Browser — CEF Navigation Filtering & URL Policy Engine
//  Reverse engineered from LockDownBrowser.exe
//  SHA256: 86f39c5a239a0ff69f3e6b3bd8833f455eecbbacc2890fe68819425098bc8040
//
//  Full decompilation of the CEF OnBeforeBrowse navigation
//  interception system. This is the URL-level enforcement layer that
//  decides what pages the locked browser can load.
//
//  Architecture:
//    1. CLDB_OnBeforeBrowse (FUN_14006d100) — 9853-byte main CEF handler
//    2. AllowNavigation (FUN_1401cfc80) — Obfuscated blacklist checker
//    3. CGI Parameter Handler (FUN_1401f9e10) — rldb* cookie/whitelist processing
//    4. Per-LMS dispatch handlers — LMS-specific URL routing
//    5. FUN_1401df2b0 — Domain whitelist comparison
//
//  Key finding: AllowNavigation (the actual blacklist matching core) is
//  protected by a hash-chain VM with opaque predicates — the only function
//  in the EXE with this level of obfuscation. Data tables at 0x140737258
//  and 0x140737358 drive the control flow.
// =============================================================================

#include <windows.h>

// Global state pointers (same as other modules)
// DAT_140cedf40 — primary global struct (~305KB)
// DAT_140cedf60 — LMS/session config
// DAT_140cedf80 — browser window manager
// DAT_140cedf90 — initialization flag

// =============================================================================
//  CLDB_OnBeforeBrowse — Main Navigation Interceptor
//  Address: 0x14006d100
//  Size: 9853 bytes (57,255 decompiled code units)
//
//  CEF callback signature:
//    CefRequestHandler::OnBeforeBrowse(browser, frame, request, user_gesture)
//
//  This function is the central gatekeeper for ALL page loads. Every URL
//  that the browser attempts to navigate to passes through this handler.
//  Returns true to cancel the navigation, false to allow it.
//
//  The handler is a massive decision tree with these layers:
//    1. Early exit checks (initialization, error state)
//    2. Hardcoded domain allow/deny list
//    3. Custom protocol handling (rldb:, ldb1:, chrome-extension://)
//    4. Respondus Monitor window routing (proctoring, webcam, feedback)
//    5. Per-LMS URL routing based on browser type code
//    6. AllowNavigation blacklist check (obfuscated)
//    7. Tab limit enforcement
// =============================================================================

// --- EARLY EXIT CONDITIONS ---
// If any of these are true, navigation is ignored entirely:
//   DAT_140cedf90 == 0                     (not initialized)
//   DAT_140cedf80 + 0x230 != 0             (error state active)
//   browserSlot[lParam].typeCode == 0x01   (slot already assigned)
// Log: "CLDB_OnBeforeBrowse - ignoring because i, e, c = %d %d %d"


// --- HARDCODED DOMAIN RULES (STATIC BLACKLIST) ---
// These are checked via FUN_1402a0d70 (domain substring match)
// and FUN_1402a0e10 (exact prefix match).
//
// BLOCKED domains (hardcoded in binary):

static const char* HARDCODED_BLOCKED_DOMAINS[] = {
    "chromewebstore.google.com",         // Chrome Web Store (extension install)
    "facebook.com",                      // Social media (exception: Moodle+Canvas LMS combos)
    "hangouts.google.com",               // Google chat
    "twitter.com",                       // Social media
    "download.moodle.org/mobile",        // Moodle mobile download page
};
// facebook.com exception: allowed when LMS type == 0x51 (Moodle) AND sub-type == 0x73

// ALLOWED domains/protocols (hardcoded passthrough):
static const char* HARDCODED_ALLOWED[] = {
    "https://extension.respondus.com",    // Respondus own extension server
    "https://www.google-analytics.com/",  // Analytics (tracking)
    "https://www.tiny.cloud/",            // TinyMCE rich text editor
    "https://www.tinymce.com/",           // TinyMCE CDN
    "chrome-extension://",                // Chrome extensions (conditional on browser state)
};

// CUSTOM PROTOCOLS (special handlers):
//   "rldb:"  — Restart LDB with new quiz URL (GetModuleFileNameA + relaunch)
//   "ldb1:"  — Secondary custom protocol
//   "&rldb"  — Query parameter prefix for CGI commands (see below)


// --- SERVER-DRIVEN BLACKLIST/WHITELIST ---
// The actual URL blacklist is NOT hardcoded — it comes from the server
// via XML configuration (see xml_settings_parser notes):
//
//   <program_blacklist> ... </program_blacklist>  — parsed at 0x140291db6
//   <program_whitelist> ... </program_whitelist>  — parsed at same parser
//
// Also loaded dynamically via CGI parameters:
//   rldbbl=...  — Blacklist entries ("Ignoring empty rldbbl blacklist")
//   rldbwl=...  — Whitelist entries ("Ignoring empty rldbwl whitelist")
//
// String evidence:
//   "AllowNavigation - rejecting from match with blacklist"
//   "AllowNavigation - rejecting from match with profile blacklist"
//   "AllowNavigation - matched SDK stem"
//   "AllowNavigation - Blocking nav to / for (%s)"


// --- CGI PARAMETER HANDLER ---
// Address: 0x1401f9e10 (FUN_1401f9e10, 1121 bytes)
//
// Parses URL query parameters with the "rldb" prefix. These are embedded
// in the LMS page URLs and processed when the browser navigates to them.
// Parameters are delimited by "&rldb" and parsed in a while loop.

struct RldbCgiHandler {
    // Authentication parameters:
    // rldbacv — AES-256 CGI challenge. Decoded, verified, sets response cookie "rldbarv"
    //   - Allocates 0x8000 byte buffer
    //   - FUN_14029ed30 extracts value (max 500 chars)
    //   - FUN_140203fe0 validates AES challenge
    //   - Sets DAT_140cedf60 + 0x1320 = 1 on success
    //   - FUN_1402a1ff0 sets cookie "rldbarv" with response
    //   - FUN_140069260 stores in session at DAT_140cedf60 + 0x1184

    // rldbcv — Standard (non-AES) CGI challenge. Sets response cookie "rldbrv"
    //   - FUN_14029ed30 extracts value (max 0xFA = 250 chars)
    //   - FUN_1401f4680 computes response (128-byte buffer)
    //   - Conditional on DAT_140cedfd4 == 10 for session storage

    // Settings parameters (values extracted but handlers not traced):
    // rldbsl=  — Unknown setting L
    // rldbsm=  — Unknown setting M
    // rldbsp=  — Unknown setting P
    // rldbsh=  — Unknown setting H
    // rldbsv=  — Unknown setting V

    // rldbxb — Sets flag at DAT_140cedf60 + 0x20 (one-shot, only if not already set)

    // rldbtxt — Text injection. Extracts value (max 0x3E = 62 chars),
    //   writes to DAT_140cedf58, posts WM_COMMAND (0x111) with wParam=0x414
    //   to window at DAT_140cedf80 + 0x18

    // rldbwn — Navigation whitelist stem (KEY DETECTION SURFACE)
    //   - Extracts URL stem (max 0x8000 = 32KB!)
    //   - Calls FUN_1401d4520(DAT_140cedf60, stem) to register whitelist entry
    //   - Log: "nav whitelist stem (%s)"
};


// --- RESPONDUS MONITOR WINDOW ROUTING ---
// Browser windows are assigned type codes stored at:
//   DAT_140cedf80 + 0x8BCE + (browserID * slotSize)
//
// When a main-frame navigation hits a known Monitor URL, the browser
// slot gets a type code and further navigations are routed to
// specialized handlers:

enum BrowserSlotType {
    SLOT_GENERIC_WINDOW  = 0x02,  // Generic popup window
    SLOT_BLACKBOARD_QUIZ = 0x03,  // Blackboard launchAssessment.jsp
    SLOT_MONITOR_RECORD  = 0x05,  // ask.respondus.com/m1.htm
    SLOT_MONITOR_FEEDBACK= 0x06,  // /MONServer/ldb/student_feedback_close.do
    SLOT_WEBCAM_CHECK    = 0x07,  // Webcam verification URL (from string table)
    SLOT_HELP_CENTER     = 0x08,  // Help center URL (from string table)
    SLOT_SPREADSHEET     = 0x09,  // /ldb/spreadsheet_load.do
    SLOT_LIVE_PROCTORING = 0x0F,  // ask.respondus.com/m15.htm
};

// String table: some URLs are fetched from DAT_140cedf48 via:
//   FUN_14021ad30(DAT_140cedf48, section, index)
// Known indices:
//   (0x23, 0x398)  — Monitor Feedback URL
//   (0x23, 0x3AF)  — Webcam check URL
//   (0x23, 0x3C6)  — Help Center URL
//   (0x23, 0x170)  — Feedback close URL
//   (0x12, 0x747)  — SDK domain check 1
//   (0x12, 0x775)  — SDK domain check 2


// --- PER-LMS URL ROUTING ---
// DAT_140cedf60 + 0x480 holds the LMS type code. The main handler
// dispatches to LMS-specific OnBeforeBrowse implementations:

struct LmsNavigationHandlers {
    // LMS Code 0x15 — Blackboard
    // Main frame: FUN_140053cb0
    // Quiz detection: "/webapps/blackboard/content/launchAssessment.jsp?"
    // File download: "/bbcswebdav/" prefix detection

    // LMS Code 0x3D — Canvas (Instructure)
    // Main frame: FUN_140080ad0
    // File download: "/files/...download" pattern

    // LMS Code 0x47 — Sakai
    // Main frame: FUN_1401ed3a0 / FUN_1401eccf0
    // (Two handler variants for different navigation contexts)

    // LMS Code 0x51 — Moodle
    // Main frame: FUN_140202db0 / FUN_140201cf0
    // Special: rldbqn=1 query parameter detection
    // Special: facebook.com exception when sub-type == 0x73

    // LMS Code 0x5B — Desire2Learn (D2L / Brightspace)
    // Main frame: FUN_1401f3520 / FUN_1401f2bb0
    // Special: rldbxb=1 query parameter detection
    // Special: /d2l/common/dialogs/quickLink/quickLink.d2l subframe forcing
    // Special: rldbqn=1 query parameter detection

    // Unknown LMS: logs "** unknown LMS = %d **"
};


// --- ALLOW-NAVIGATION BLACKLIST CHECKER (OBFUSCATED) ---
// Address: 0x1401cfc80 (FUN_1401cfc80)
//
// THIS IS THE CORE URL POLICY FUNCTION. Called from CLDB_OnBeforeBrowse
// to decide if a child-window navigation should be allowed.
//
// Returns: nonzero = allow, zero = block
// Called: FUN_1401cfc80(url, browserID, isQuizActive, userGesture)
//
// CRITICALLY: This function is VM-protected / obfuscated:
//   - Hash chain control flow: val >> 0x1c ^ val << 4 ^ table[offset]
//   - Data tables at 0x140737258 (256+ entries) and 0x140737358
//   - Opaque predicates: ((retaddr - 1) * retaddr & 1) is always 0
//   - Ghidra halts with "Bad instruction / Truncating control flow"
//
// This is the ONLY function in the EXE with this level of obfuscation,
// confirming that the URL policy enforcement is considered security-critical
// by Respondus and specifically hardened against static analysis.
//
// The function ultimately checks:
//   1. Server-supplied blacklist patterns (from <program_blacklist> XML)
//   2. Profile-specific blacklist (per-exam settings)
//   3. SDK stem matching (Respondus SDK URL patterns)
//   4. Domain whitelist (FUN_1401df2b0)


// --- DOMAIN WHITELIST CHECK ---
// Address: 0x1401df2b0 (FUN_1401df2b0)
//
// Called from multiple places in CLDB_OnBeforeBrowse to check if a URL
// matches the allowed domain list. Also used in the XML parser's
// subdomain fixup logic and the new-window forcing path.
//
// When a URL matches the whitelist AND the current domain list:
//   - Navigation is allowed
//   - Or forced into a new window tab if needed
//
// Tab limit: DAT_140cedf80 + 0x1E68 tracks current tabs
//            DAT_140cedf80 + 0x1C68 points to max tabs value
//            Exceeding triggers: "Too many tabs, current = %d, max = %d"
//            Then shows error dialog 0x55


// --- ADDITIONAL NAVIGATION HANDLERS ---

// OnBeforeBrowseLiveProctoring (string at 0x140b297b8)
// Handler for Respondus Monitor live proctoring navigation events.
// Logs: "OnBeforeBrowseLiveProctoring - %s"

// OnBeforeBrowseLiveChatSysCheck (string at 0x140b2c578)
// Handler for live chat system check navigations.
// Logs: "OnBeforeBrowseLiveChatSysCheck bid = %d url = %s"

// OnBeforeBrowseLiveChatGeneric (string at 0x140b2c750)
// Handler for generic live chat navigations.
// Logs: "OnBeforeBrowseLiveChatGeneric bid = %d url = %s"

// OnSDKManualBlacklistCheck (strings at 0x140b2a500, 0x140b2a530)
// SDK-level manual blacklist verification.
// Logs: "OnSDKManualBlacklistCheck()" and "already completed" variant

// Whitelist logging (string at 0x140b2a4f0)
// Logs: "Whitelist '%s'" when a URL matches the whitelist


// --- DOCUMENT DOWNLOAD DETECTION ---
// CLDB_OnBeforeBrowse also detects file downloads by extension:
//
// Word/PowerPoint: Checked via DAT_140cedf40 + 0x2AC (Word enabled) and
//   DAT_140cedf40 + 0x2AD (PowerPoint enabled)
//   Log: "Downloading Word/powerpoint doc id = %d quiz = %d"
//   Log: "Quiz not active - ignoring Word/PowerPoint"
//
// Excel: Checked via DAT_140cedf40 + 0x2AB
//   Log: "Downloading Excel Sheet id = %d quiz = %d"
//
// File extension check: Last 4 chars of URL compared against DAT_140b169ec
//   (likely ".doc", ".xls", ".ppt" or similar extensions)
//
// Downloads are routed via PostMessageW with:
//   WM_COMMAND (0x111), wParam = 0x40C (normal) or 0x428 (quiz active)
//   WM_COMMAND (0x111), wParam = 0x605 with lParam = 1 (PowerPoint) or 2 (Word)


// --- KURZWEIL TEXT-TO-SPEECH INTEGRATION ---
// Special handling for Kurzweil assistive technology:
//   Log: "Kurzweil - clearing cache"
//   DAT_140cb17b0 — Kurzweil active flag
//   DAT_140cb17b8 — Kurzweil session object (released on cache clear)
//   DAT_140cb17c0 — Kurzweil browser ID
//   DAT_140cb17c8 — Kurzweil URL pattern for matching


// --- PAYPAL INTEGRATION ---
// If a subframe loads a URL containing "paypal", special handling is
// triggered via FUN_1402b97f0(DAT_140cedf58, browserID)


// --- NAVIGATION COUNTING ---
// DAT_140cedf80 + 0x93D0 + (browserSlot * 4) tracks navigation count
// per browser slot. Incremented on each allowed navigation.
// Log: "Link-block: nav-count = %d is_oem = %d pretty-enforce = %d"


// =============================================================================
//  DETECTION SURFACE SUMMARY
//
//  The CEF navigation system has these detection-relevant components:
//
//  1. HARDCODED BLOCKS: 5 social/external domains permanently blocked
//  2. SERVER BLACKLIST: Downloaded via XML config, checked in obfuscated
//     AllowNavigation function (FUN_1401cfc80)
//  3. SERVER WHITELIST: Also from XML config and rldbwn CGI parameter
//  4. PROFILE BLACKLIST: Per-exam blacklist from server configuration
//  5. SDK STEM MATCHING: Respondus SDK URL pattern recognition
//  6. TAB LIMITS: Maximum concurrent tabs enforced
//  7. DOCUMENT DOWNLOADS: File extension-based download detection
//  8. OBFUSCATED CORE: AllowNavigation uses VM/hash-chain protection,
//     the only such protected function in the binary
//  9. CGI CHALLENGE/RESPONSE: AES-256 and standard verification via
//     rldbacv/rldbcv URL parameters with response cookies
// 10. LMS-SPECIFIC ROUTING: 5 LMS types with dedicated navigation handlers
// =============================================================================
