#ifndef PCH_H
#define PCH_H

// ============================================================
// pch.h
// Purpose:
// 1) Place high-frequency stable headers for APIMonitor_x64 to reduce recompilation overhead;
// 2) Unify common STL and Windows basic headers to avoid scattered, duplicate includes across cpp files;
// 3) Keep the precompiled header itself as stable as possible; do not include implementation details that change frequently.
// ============================================================

#include "framework.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cctype>
#include <cstdlib>
#include <cwchar>
#include <cwctype>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#endif
