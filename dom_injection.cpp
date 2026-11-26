// =============================================================================
//  LockDown Browser — DOM Injection Scripts (JavaScript Page Manipulation)
//  Reverse engineered from LockDownBrowser.exe
//  SHA256: 86f39c5a239a0ff69f3e6b3bd8833f455eecbbacc2890fe68819425098bc8040
//
//  Discovery and cataloging of 11 hardcoded JavaScript injection
//  scripts embedded directly in the EXE's .rdata section. These are injected
//  into LMS web pages via CEF's CefFrame::ExecuteJavaScript() to strip
//  navigation elements, editor features, messaging UI, and media controls
//  from the page DOM.
//
//  This is a distinct detection surface layer: while CLDB_OnBeforeBrowse
//  controls WHICH pages can be loaded, these scripts control WHAT CONTENT
//  is visible/accessible within allowed pages.
//
//  All scripts use window.setInterval() for persistent enforcement —
//  they re-run every 1000-2500ms to catch dynamically loaded content.
// =============================================================================

#include <windows.h>

// =============================================================================
//  SCRIPT INVENTORY — All window.setInterval injections in .rdata
// =============================================================================


// --- SCRIPT 1: Canvas/Generic Rich Text Editor Lockdown ---
// Address: 0x140b14cf0 (428 bytes)
// Interval: 1500ms
// Target: Generic LMS rich text editors (Canvas New RCE, TinyMCE)
//
// Removes buttons with specific aria-label values:
//   "Insert/edit link"   — Hyperlink insertion (prevents linking to external content)
//   "Add content"        — Content embedding (prevents importing media/files)
//   "Source code"         — HTML source editor (prevents JavaScript injection)
//
// Detection surface: If these buttons are visible during an exam, the script
// either hasn't been injected yet or the DOM structure has changed.


// --- SCRIPT 2: Panopto/Video Platform Lockdown ---
// Address: 0x140b17d50 (536 bytes)
// Interval: 1000ms
// Target: Panopto or similar video/media platform embedded in LMS
//
// Removes buttons with aria-label containing (case-sensitive):
//   'save'     — Prevents saving/downloading video content
//   'mp3'      — Prevents audio export
//   'report'   — Prevents report generation
//   'share'    — Prevents sharing content externally
//
// Also removes: #pw-main-sidenav (Panopto main sidebar navigation)
//
// Detection surface: Panopto sidebar and media export buttons should be
// absent in LDB. If visible, the injection failed.


// --- SCRIPT 3: ReadSpeaker Text-to-Speech Injection ---
// Address: 0x140b2b460 (364 bytes)
// Interval: NONE (one-shot conditional)
// Target: ALL pages (accessibility feature injection)
//
// Logic:
//   if (window.ReadSpeaker && window.ReadSpeaker.TextAidReader) {
//       ReadSpeaker.TextAidReader.showPlayer();
//   } else {
//       // Inject ReadSpeaker script from ws.readspeaker.com
//       <script src="https://ws.readspeaker.com/a/wasp/reader/orglogin">
//   }
//
// This is the ONLY injection script that ADDS functionality rather than
// removing it. ReadSpeaker is a commercial TTS service used for accessibility
// compliance. LDB injects it into pages that don't have it natively.


// --- SCRIPT 4: Moodle Master DOM Stripper ---
// Address: 0x140b2d9e0 (3124 bytes) — LARGEST INJECTION SCRIPT
// Interval: 1500ms
// Target: Moodle LMS pages
//
// Removes buttons by title (case-insensitive):
//   'image'                — Image upload/insert
//   'insert character'     — Special character insertion
//   'accessibility checker' — Moodle accessibility tool
//   'screenreader helper'  — Screen reader assistance
//   'html'                 — HTML source code editor
//
// Removes by aria-controls:
//   'nav-drawer'           — Moodle navigation drawer toggle button
//
// Removes TinyMCE/Atto editor buttons by class:
//   'mce_pdw_toggle'       — TinyMCE paragraph/div wrapper toggle
//   'mce_image'            — TinyMCE image insert
//   'mce_moodlemedia'      — TinyMCE Moodle media insert
//   'atto_image_button'    — Atto editor image button
//   'mceButton mceButtonEnabled mce_image' — TinyMCE image button (enabled state)
//
// Removes navigation elements by ID:
//   'nav-drawer'           — Moodle navigation drawer div
//   'newmessageoverlay'    — Moodle messaging overlay
//   'site-navbar-collapse' — Site navigation collapse
//   'page-navbar'          — Page-level navigation bar
//   'jump-to-activity'     — Activity jump dropdown
//   'prev-activity-link'   — Previous activity navigation
//   'next-activity-link'   — Next activity navigation
//
// Removes navigation elements by class:
//   'navbar'               — Bootstrap navigation bar
//   'site-menubar'         — Site-level menu bar
//   'breadcrumb'           — Breadcrumb navigation trail
//
// Removes links with 'message-drawer-toggl' in ID (Moodle messaging drawer)


// --- SCRIPT 5: Moodle Margin Element Stripper ---
// Address: 0x140b2e620 (188 bytes)
// Interval: 1500ms
// Target: Moodle LMS
//
// Removes first element with class "m-t-2 m-b-1" (Bootstrap margin utility).
// Likely targets a specific Moodle UI element using these margin classes
// that provides navigation or actions outside the exam content area.


// --- SCRIPT 6: Audio Recorder + Print + SCAYT Stripper ---
// Address: 0x140b31290 (1164 bytes)
// Interval: 1000ms
// Target: Multiple LMS platforms (Blackboard, generic)
//
// Removes spans with class containing (case-insensitive):
//   'audiorecorder'  — Audio recording widget (removes parent.parent — full container)
//   '_print_icon'    — Print button icon (removes parent — button wrapper)
//   '_scayt_icon'    — SCAYT spell checker icon (removes parent — button wrapper)
//
// Removes inputs with ID containing (case-insensitive):
//   'exittoc'        — "Exit Table of Contents" button
//
// Uses do-while loop to handle multiple audio recorders on same page.
// SCAYT = "Spell Check As You Type" (CKEditor plugin) — blocked because
// it can be exploited to access a dictionary/thesaurus during exams.


// --- SCRIPT 7: Sakai Image/Media Button Stripper ---
// Address: 0x140b31d10 (336 bytes)
// Interval: 1500ms
// Target: Sakai LMS
//
// Removes links (<a>) with original-title="Image/Media".
// Targets the Sakai rich text editor's image/media insertion button.


// --- SCRIPT 8: Generic Header Stripper ---
// Address: 0x140b31e60 (172 bytes)
// Interval: 1500ms
// Target: Generic LMS (any page with #header element)
//
// Removes element with id="header". Simple header suppression to prevent
// navigation away from exam content via page headers.


// --- SCRIPT 9: D2L/Brightspace Save Draft Stripper ---
// Address: 0x140b31f10 (212 bytes)
// Interval: 1500ms
// Target: D2L Brightspace
//
// Removes buttons with class "button button--secondary js-save-draft-button".
// Prevents students from saving draft answers (must submit through LDB flow).


// --- SCRIPT 10: Canvas Rich Content Editor Stripper ---
// Address: 0x140b32100 (524 bytes)
// Interval: Unknown (string truncated in search)
// Target: Canvas LMS Rich Content Editor (RCE)
//
// Removes div[role="button"] with aria-label (case-insensitive):
//   "links"               — Link insertion button
//   "images"              — Image insertion button
//   "record/upload media" — Media recording/upload button
//
// Targets Canvas's new Rich Content Editor which uses div-based buttons
// with ARIA roles instead of native <button> elements.


// --- SCRIPT 11: Preview Link Neutralizer ---
// Address: 0x140b32ba0 (452 bytes)
// Interval: 2500ms (longest interval)
// Target: Multiple LMS platforms
//
// Finds all <a> links with class containing 'preview'.
// Replaces the entire link element with plain text: " Click to open: "
// This prevents file preview functionality — students must download files
// through the controlled download path instead of previewing in-browser.


// =============================================================================
//  DETECTION SURFACE SUMMARY
//
//  The DOM injection system represents a THIRD enforcement layer:
//    Layer 1: URL-level (OnBeforeBrowse) — which pages can load
//    Layer 2: DOM-level (JavaScript injection) — what content is visible
//    Layer 3: Input-level (LockDownBrowser.dll) — what keys/actions work
//
//  LMS Coverage:
//    - Moodle:     Scripts 4, 5 (most heavily targeted)
//    - Canvas:     Scripts 1, 10
//    - Sakai:      Script 7
//    - D2L:        Script 9
//    - Blackboard: Script 6
//    - Panopto:    Script 2
//    - Generic:    Scripts 3, 8, 11
//
//  Categories stripped:
//    - Navigation: nav drawers, breadcrumbs, headers, activity links, sidebars
//    - Rich text editor: image insert, HTML source, media embed, link insert
//    - Communication: messaging overlay, message drawer
//    - Media: audio recorder, video save/share/export, file preview
//    - Utilities: print, spell check, save draft, accessibility tools
//    - Accessibility: ReadSpeaker TTS is INJECTED (the only additive script)
//
//  Bypass: Since these run on setInterval (1000-2500ms), there's a brief
//  window after page load before the first execution. MutationObserver-based
//  approaches could also re-add elements between interval ticks. The scripts
//  use class/ID/aria-label matching, so renaming these DOM attributes in a
//  proxy would defeat the stripping entirely.
// =============================================================================
