#pragma once

// ============================================================
// framework.h
// Purpose:
// 1) Unify the entry point for underlying Windows headers in APIMonitor_x64.
// 2) Include Winsock headers first to avoid ordering conflicts with Windows.h.
// 3) Provides foundational platform definitions for subsequent Hook, named pipe, registry, and network code.
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>
