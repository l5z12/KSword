#pragma once

// ============================================================
// ksword/ksword.h
// Purpose:
// - Acts as the top-level aggregate header for the ks namespace.
// - Include sub-namespace headers level by level;
// - Note: External recursive inclusion is resolved via Ksword.h -> ksword/ksword.h.
// ============================================================

// String utilities (UTF8/UTF16 conversion, time text formatting, etc.).
#include "string/String.h"

// Logging tools (KLogEntry, event tracing, streaming log output).
#include "log/Log.h"

// Process tools (enumeration, details, control, priority, etc. Win32 wrappers).
#include "process/Process.h"

// File utilities (path normalization, handle scanning, PE base parsing, and other non-UI backends).
#include "file/File.h"

// Binary scanning tool (structured parsing of PE/ELF/Mach-O and constrained atomic file patching).
#include "scanner/Scanner.h"

// Startup tools (Registry, Services, Scheduled Tasks, Winsock, WMI non-UI enumeration backends).
#include "startup/Startup.h"

// Service tools (Win32 SCM enumeration, query, control, and configuration write encapsulation).
#include "service/Service.h"

// Network tools (traffic capture, PID mapping, process rate limiting, etc.).
#include "network/Network.h"

// Network formatting tools (endpoints, IPv4 ranges, payload previews, byte/time text, etc.).
#include "network/NetworkFormatTools.h"

// Network diagnostics tools (ARP/DNS/ICMP results are purely formatted, and scan range is calculated).
#include "network/NetworkDiagnosticsTools.h"

// Network download tools (Range segmented plan, Range headers, progress and speed calculations).
#include "network/NetworkDownloadTools.h"
