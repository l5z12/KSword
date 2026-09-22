#include "RegistryActions.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>
#include <sstream>

namespace ksword::features::registry {
namespace {

// UniqueRegKey owns an HKEY returned by RegOpenKeyEx/RegCreateKeyEx. Input is a
// raw handle; processing closes it in the destructor; get returns the borrowed
// handle.
class UniqueRegKey final {
public:
    UniqueRegKey() = default;
    explicit UniqueRegKey(HKEY key) noexcept : key_(key) {}
    ~UniqueRegKey() { reset(); }
    UniqueRegKey(const UniqueRegKey&) = delete;
    UniqueRegKey& operator=(const UniqueRegKey&) = delete;
    HKEY get() const noexcept { return key_; }
    bool valid() const noexcept { return key_ != nullptr; }
    void reset(HKEY key = nullptr) noexcept {
        if (key_) {
            ::RegCloseKey(key_);
        }
        key_ = key;
    }

private:
    HKEY key_ = nullptr;
};

// A registry name is documented as substantially smaller than this bound.  A
// hard local ceiling prevents a malformed/racing enumeration response from
// requesting an unbounded allocation in the background search worker.
constexpr DWORD kRegistrySearchMaxNameChars = 32767U;

struct PendingRegistrySearchKey final {
    RegistryPathInfo path;
    std::size_t depth = 0U;
};

bool isRegistrySearchCancelled(const std::shared_ptr<std::atomic_bool>& cancelToken) {
    return cancelToken && cancelToken->load(std::memory_order_relaxed);
}

bool stopRegistrySearchIfCancelled(
    RegistrySearchSnapshot& snapshot,
    const std::shared_ptr<std::atomic_bool>& cancelToken) {
    if (!isRegistrySearchCancelled(cancelToken)) {
        return false;
    }
    snapshot.stopReason = RegistrySearchStopReason::kCancelled;
    return true;
}

void recordRegistrySearchReadFailure(RegistrySearchSnapshot& snapshot, const std::wstring& detail) {
    ++snapshot.counters.readFailureCount;
    if (snapshot.errorText.empty()) {
        snapshot.errorText = detail;
    }
}

bool appendRegistrySearchCandidate(
    RegistrySearchSnapshot& snapshot,
    const RegistrySearchCandidate& candidate) {
    RegistrySearchHit hit = projectRegistrySearchHit(candidate, snapshot.request.maxValuePreviewBytes);
    if (hit.dataPreviewTruncated) {
        ++snapshot.counters.truncatedPreviewCount;
    }
    if (!hit.valid || !registrySearchHitMatches(hit, snapshot.normalizedQuery)) {
        return true;
    }

    if (hit.kind == RegistrySearchEntryKind::kKey) {
        ++snapshot.counters.matchedKeyCount;
    } else {
        ++snapshot.counters.matchedValueCount;
    }
    snapshot.hits.push_back(std::move(hit));
    if (snapshot.hits.size() < snapshot.request.maxResults) {
        return true;
    }

    snapshot.stopReason = RegistrySearchStopReason::kResultLimitReached;
    return false;
}

RegistryPathInfo makeRegistrySearchChildPath(
    const RegistryPathInfo& parent,
    const std::wstring& childName) {
    RegistryPathInfo child = parent;
    child.subKey = parent.subKey.empty() ? childName : parent.subKey + L"\\" + childName;
    child.displayPath = child.rootText + L"\\" + child.subKey;
    if (!child.kernelPath.empty()) {
        child.kernelPath += L"\\" + childName;
    }
    return child;
}

// queryRegistrySearchValueInfo obtains only the value enumeration bounds for a
// handle opened with value-query access.  It keeps partial-ACL value discovery
// separate from subkey enumeration.
LONG queryRegistrySearchValueInfo(HKEY key, DWORD& valueCount, DWORD& maxValueName) {
    valueCount = 0;
    maxValueName = 0;
    return ::RegQueryInfoKeyW(
        key,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &valueCount,
        &maxValueName,
        nullptr,
        nullptr,
        nullptr);
}

// narrowToWide converts ArkDriverClient ASCII diagnostics to UTF-16. Input is
// client message text; output is displayable wide text.
std::wstring narrowToWide(const std::string& text) {
    std::wstring wide;
    wide.reserve(text.size());
    for (unsigned char ch : text) {
        wide.push_back(static_cast<wchar_t>(ch));
    }
    return wide;
}

// makePathError converts a parse failure into a snapshot. Inputs are original
// path, mode and parse result; output is a failed snapshot.
RegistrySnapshot makePathError(const std::wstring& path, const RegistryViewMode mode, const RegistryPathInfo& parsed) {
    RegistrySnapshot snapshot;
    snapshot.mode = mode;
    snapshot.displayPath = path;
    snapshot.statusText = parsed.errorText;
    return snapshot;
}

// makeOperationPathError converts a parse failure into an operation result.
// Input is parse info; output is a failed operation status.
RegistryOperationResult makeOperationPathError(const RegistryPathInfo& parsed) {
    RegistryOperationResult result;
    result.success = false;
    result.win32Error = ERROR_INVALID_PARAMETER;
    result.statusText = parsed.errorText;
    return result;
}

// OpenKey opens a WinAPI registry key. Inputs are parsed path and access mask;
// output is an owning key handle.
UniqueRegKey openKey(const RegistryPathInfo& path, const REGSAM access, LONG* statusOut = nullptr) {
    HKEY raw = nullptr;
    const LONG kStatus = ::RegOpenKeyExW(path.root, path.subKey.c_str(), 0, access, &raw);
    if (statusOut) {
        *statusOut = kStatus;
    }
    if (kStatus != ERROR_SUCCESS) {
        return UniqueRegKey();
    }
    return UniqueRegKey(raw);
}

// BuildStatusLine creates a common R0 status line. Inputs are operation name,
// transport status, protocol status and NT status; output is shown in the UI.
std::wstring buildR0StatusLine(const wchar_t* operation, const bool ok, const std::uint32_t status, const long ntStatus, const std::string& message) {
    std::wostringstream stream;
    stream << L"R0 registry " << operation
           << (ok ? L" transport OK" : L" transport failed")
           << L"; status=" << status
           << L"; nt=0x" << std::hex << std::uppercase << static_cast<unsigned long>(ntStatus)
           << L"; " << narrowToWide(message);
    return stream.str();
}

// appendWinApiValues enumerates values under one WinAPI key. Inputs are key and
// snapshot; processing appends value rows; no return value.
void appendWinApiValues(HKEY key, RegistrySnapshot& snapshot) {
    DWORD valueCount = 0;
    DWORD maxValueName = 0;
    DWORD maxData = 0;
    if (::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            &valueCount, &maxValueName, &maxData, nullptr, nullptr) != ERROR_SUCCESS) {
        return;
    }
    std::vector<wchar_t> name(static_cast<std::size_t>(maxValueName) + 2U);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(std::max<DWORD>(maxData, 1)));
    for (DWORD index = 0; index < valueCount; ++index) {
        DWORD nameChars = static_cast<DWORD>(name.size());
        DWORD dataBytes = static_cast<DWORD>(data.size());
        DWORD type = REG_NONE;
        const LONG kRc = ::RegEnumValueW(key, index, name.data(), &nameChars, nullptr, &type, data.data(), &dataBytes);
        if (kRc != ERROR_SUCCESS) {
            continue;
        }
        RegistryEntry row;
        row.kind = RegistryRowKind::kValue;
        row.name.assign(name.data(), name.data() + nameChars);
        row.valueType = type;
        row.typeText = registryTypeText(type);
        row.data.assign(data.begin(), data.begin() + dataBytes);
        row.dataText = formatRegistryData(type, row.data);
        row.detailText = L"WinAPI value; bytes=" + std::to_wstring(dataBytes);
        snapshot.rows.push_back(std::move(row));
    }
}

// appendWinApiSubKeys enumerates direct child keys. Inputs are key and snapshot;
// processing appends subkey rows; no return value.
void appendWinApiSubKeys(HKEY key, RegistrySnapshot& snapshot) {
    DWORD subKeyCount = 0;
    DWORD maxSubKey = 0;
    if (::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKey, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return;
    }
    std::vector<wchar_t> name(static_cast<std::size_t>(maxSubKey) + 2U);
    for (DWORD index = 0; index < subKeyCount; ++index) {
        DWORD nameChars = static_cast<DWORD>(name.size());
        const LONG kRc = ::RegEnumKeyExW(key, index, name.data(), &nameChars, nullptr, nullptr, nullptr, nullptr);
        if (kRc != ERROR_SUCCESS) {
            continue;
        }
        RegistryEntry row;
        row.kind = RegistryRowKind::kSubKey;
        row.name.assign(name.data(), name.data() + nameChars);
        row.typeText = L"Key";
        row.detailText = L"WinAPI subkey";
        snapshot.rows.push_back(std::move(row));
    }
}

// kernelPathRequired verifies that R0 can address the requested path. Input is
// parsed path; output is true for \REGISTRY\MACHINE/USER paths.
bool kernelPathRequired(const RegistryPathInfo& path, RegistryOperationResult& result) {
    if (!path.kernelPath.empty()) {
        return true;
    }
    result.success = false;
    result.win32Error = ERROR_NOT_SUPPORTED;
    result.statusText = L"R0 registry mode currently supports HKLM/HKU or explicit \\REGISTRY\\MACHINE/USER paths.";
    return false;
}

} // namespace

RegistrySnapshot enumerateRegistryKey(const std::wstring& path, const RegistryViewMode mode) {
    RegistryPathInfo parsed = parseRegistryPath(path);
    if (!parsed.valid) {
        return makePathError(path, mode, parsed);
    }

    RegistrySnapshot snapshot;
    snapshot.mode = mode;
    snapshot.displayPath = parsed.displayPath;
    snapshot.kernelPath = parsed.kernelPath;

    if (mode == RegistryViewMode::kR0) {
        if (parsed.kernelPath.empty()) {
            snapshot.statusText = L"R0 registry mode supports HKLM/HKU or \\REGISTRY\\MACHINE/USER paths.";
            return snapshot;
        }
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryEnumResult kResult = kClient.enumerateRegistryKey(parsed.kernelPath);
        snapshot.success = kResult.io.ok &&
            (kResult.status == KSWORD_ARK_REGISTRY_ENUM_STATUS_SUCCESS ||
                kResult.status == KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL);
        for (const auto& subKey : kResult.subKeys) {
            RegistryEntry row;
            row.kind = RegistryRowKind::kSubKey;
            row.name = subKey.name;
            row.typeText = L"Key";
            row.detailText = L"R0 subkey";
            snapshot.rows.push_back(std::move(row));
        }
        for (const auto& value : kResult.values) {
            RegistryEntry row;
            row.kind = RegistryRowKind::kValue;
            row.name = value.name;
            row.valueType = value.valueType;
            row.typeText = registryTypeText(value.valueType);
            row.data = value.data;
            row.dataText = formatRegistryData(value.valueType, row.data);
            row.detailText = L"R0 value; returned=" + std::to_wstring(value.dataBytes) +
                L"; required=" + std::to_wstring(value.requiredBytes);
            snapshot.rows.push_back(std::move(row));
        }
        snapshot.statusText = buildR0StatusLine(L"enum", kResult.io.ok, kResult.status, kResult.lastStatus, kResult.io.message);
        return snapshot;
    }

    LONG openStatus = ERROR_SUCCESS;
    UniqueRegKey key = openKey(parsed, KEY_READ, &openStatus);
    if (!key.valid()) {
        snapshot.success = false;
        snapshot.statusText = L"RegOpenKeyExW failed: " + std::to_wstring(openStatus);
        return snapshot;
    }
    appendWinApiSubKeys(key.get(), snapshot);
    appendWinApiValues(key.get(), snapshot);
    snapshot.success = true;
    snapshot.statusText = L"WinAPI registry enum OK; rows=" + std::to_wstring(snapshot.rows.size());
    return snapshot;
}

RegistrySearchSnapshot searchRegistryWinApi(
    const RegistrySearchRequest& request,
    const std::shared_ptr<std::atomic_bool>& cancelToken) {
    // Inputs:
    // - request: a user-provided path, keyword, and caller-reduced budgets.
    // - cancelToken: a shared worker/UI cancellation signal, or null.
    // Processing:
    // - validates and clamps the request through the pure model;
    // - walks only the WinAPI registry view with an iterative DFS worklist;
    // - accepts no more keys/values than the fixed budgets and reads no value
    //   payload larger than the fixed preview bound.
    // Output:
    // - one immutable complete or partial snapshot; this function never calls
    //   the driver and never changes the existing R0/WinAPI browser mode.
    RegistrySearchSnapshot snapshot;
    const RegistrySearchValidation kValidation = validateRegistrySearchRequest(request);
    snapshot.request = kValidation.request;
    snapshot.normalizedQuery = kValidation.normalizedQuery;
    if (!kValidation.valid) {
        snapshot.stopReason = RegistrySearchStopReason::kInvalidRequest;
        snapshot.errorText = kValidation.errorText;
        snapshot.statusText = buildRegistrySearchStatusText(snapshot);
        return snapshot;
    }

    const RegistryPathInfo kStartPath = parseRegistryPath(snapshot.request.startPath);
    if (!kStartPath.valid) {
        snapshot.stopReason = RegistrySearchStopReason::kInvalidRequest;
        snapshot.errorText = kStartPath.errorText;
        snapshot.statusText = buildRegistrySearchStatusText(snapshot);
        return snapshot;
    }
    snapshot.request.startPath = kStartPath.displayPath;
    if (stopRegistrySearchIfCancelled(snapshot, cancelToken)) {
        snapshot.statusText = buildRegistrySearchStatusText(snapshot);
        return snapshot;
    }

    std::vector<PendingRegistrySearchKey> pendingKeys;
    pendingKeys.reserve(snapshot.request.maxKeys);
    pendingKeys.push_back({ kStartPath, 0U });
    bool enumeratedAnyKey = false;
    bool keyWorkLimitReached = false;
    bool subKeyEnumerationLimitReached = false;

    while (!pendingKeys.empty()) {
        if (stopRegistrySearchIfCancelled(snapshot, cancelToken)) {
            break;
        }
        if (snapshot.counters.visitedKeyCount >= snapshot.request.maxKeys) {
            snapshot.stopReason = RegistrySearchStopReason::kKeyLimitReached;
            break;
        }

        PendingRegistrySearchKey current = std::move(pendingKeys.back());
        pendingKeys.pop_back();
        ++snapshot.counters.visitedKeyCount;

        // Open values and subkeys independently.  A key can legitimately grant
        // one of these old WinAPI rights without the other; treating the union
        // as mandatory would unnecessarily shrink the search's visible scope.
        LONG valueOpenStatus = ERROR_SUCCESS;
        UniqueRegKey valueKey = openKey(current.path, KEY_QUERY_VALUE, &valueOpenStatus);
        LONG subKeyOpenStatus = ERROR_SUCCESS;
        UniqueRegKey subKey = openKey(current.path, KEY_ENUMERATE_SUB_KEYS, &subKeyOpenStatus);
        if (!valueKey.valid() && !subKey.valid()) {
            recordRegistrySearchReadFailure(
                snapshot,
                L"RegOpenKeyExW failed for values/subkeys at " + current.path.displayPath +
                    L": values=" + std::to_wstring(valueOpenStatus) +
                    L", subkeys=" + std::to_wstring(subKeyOpenStatus));
            continue;
        }
        if (!valueKey.valid()) {
            recordRegistrySearchReadFailure(
                snapshot,
                L"RegOpenKeyExW(value access) failed for " + current.path.displayPath + L": " + std::to_wstring(valueOpenStatus));
        }
        if (!subKey.valid()) {
            recordRegistrySearchReadFailure(
                snapshot,
                L"RegOpenKeyExW(subkey access) failed for " + current.path.displayPath + L": " + std::to_wstring(subKeyOpenStatus));
        }

        RegistrySearchCandidate keyCandidate;
        keyCandidate.kind = RegistrySearchEntryKind::kKey;
        keyCandidate.keyPath = current.path.displayPath;
        keyCandidate.valueTypeText = L"键";
        keyCandidate.depth = current.depth;
        if (!appendRegistrySearchCandidate(snapshot, keyCandidate)) {
            break;
        }
        if (stopRegistrySearchIfCancelled(snapshot, cancelToken)) {
            break;
        }

        if (valueKey.valid()) {
            DWORD valueCount = 0;
            DWORD maxValueName = 0;
            const LONG kValueInfoStatus = queryRegistrySearchValueInfo(valueKey.get(), valueCount, maxValueName);
            if (kValueInfoStatus != ERROR_SUCCESS) {
                recordRegistrySearchReadFailure(
                    snapshot,
                    L"RegQueryInfoKeyW(value access) failed for " + current.path.displayPath + L": " + std::to_wstring(kValueInfoStatus));
            } else if (maxValueName > kRegistrySearchMaxNameChars) {
                recordRegistrySearchReadFailure(
                    snapshot,
                    L"RegQueryInfoKeyW returned an oversized value-name bound for " + current.path.displayPath + L".");
            } else {
                enumeratedAnyKey = true;
                std::vector<wchar_t> valueName(static_cast<std::size_t>(maxValueName) + 2U);
                for (DWORD index = 0; index < valueCount; ++index) {
                    if (stopRegistrySearchIfCancelled(snapshot, cancelToken)) {
                        break;
                    }
                    if (snapshot.counters.visitedValueCount >= snapshot.request.maxValues) {
                        snapshot.stopReason = RegistrySearchStopReason::kValueLimitReached;
                        break;
                    }
                    ++snapshot.counters.visitedValueCount;

                    DWORD valueNameChars = static_cast<DWORD>(valueName.size());
                    DWORD enumeratedDataBytes = 0;
                    DWORD type = REG_NONE;
                    const LONG kEnumStatus = ::RegEnumValueW(
                        valueKey.get(),
                        index,
                        valueName.data(),
                        &valueNameChars,
                        nullptr,
                        &type,
                        nullptr,
                        &enumeratedDataBytes);
                    if (kEnumStatus == ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    if (kEnumStatus != ERROR_SUCCESS) {
                        recordRegistrySearchReadFailure(
                            snapshot,
                            L"RegEnumValueW failed for " + current.path.displayPath + L": " + std::to_wstring(kEnumStatus));
                        continue;
                    }

                    RegistrySearchCandidate valueCandidate;
                    valueCandidate.kind = RegistrySearchEntryKind::kValue;
                    valueCandidate.keyPath = current.path.displayPath;
                    valueCandidate.valueName.assign(valueName.data(), valueName.data() + valueNameChars);
                    valueCandidate.valueTypeText = registryTypeText(type);
                    valueCandidate.dataByteCount = enumeratedDataBytes;
                    valueCandidate.depth = current.depth;

                    DWORD queriedType = type;
                    DWORD fullDataBytes = 0;
                    const wchar_t* valueNamePtr = valueCandidate.valueName.empty()
                        ? nullptr
                        : valueCandidate.valueName.c_str();
                    const LONG kSizeStatus = ::RegQueryValueExW(
                        valueKey.get(),
                        valueNamePtr,
                        nullptr,
                        &queriedType,
                        nullptr,
                        &fullDataBytes);
                    if (kSizeStatus != ERROR_SUCCESS) {
                        recordRegistrySearchReadFailure(
                            snapshot,
                            L"RegQueryValueExW(size) failed for " + current.path.displayPath + L": " + std::to_wstring(kSizeStatus));
                        valueCandidate.dataPreview = L"<数据预览不可读取>";
                    } else {
                        valueCandidate.valueTypeText = registryTypeText(queriedType);
                        valueCandidate.dataByteCount = fullDataBytes;
                        if (fullDataBytes > snapshot.request.maxValuePreviewBytes) {
                            valueCandidate.dataPreview = L"<数据预览超过上限，未读取>";
                        } else if (fullDataBytes != 0U) {
                            std::vector<std::uint8_t> data(static_cast<std::size_t>(fullDataBytes));
                            DWORD readDataBytes = fullDataBytes;
                            const LONG kDataStatus = ::RegQueryValueExW(
                                valueKey.get(),
                                valueNamePtr,
                                nullptr,
                                &queriedType,
                                data.data(),
                                &readDataBytes);
                            if (kDataStatus != ERROR_SUCCESS) {
                                recordRegistrySearchReadFailure(
                                    snapshot,
                                    L"RegQueryValueExW(data) failed for " + current.path.displayPath + L": " + std::to_wstring(kDataStatus));
                                if (kDataStatus == ERROR_MORE_DATA && readDataBytes > valueCandidate.dataByteCount) {
                                    valueCandidate.dataByteCount = readDataBytes;
                                }
                                valueCandidate.dataPreview = kDataStatus == ERROR_MORE_DATA
                                    ? L"<数据读取期间变化，预览跳过>"
                                    : L"<数据预览不可读取>";
                            } else {
                                data.resize(readDataBytes);
                                valueCandidate.valueTypeText = registryTypeText(queriedType);
                                valueCandidate.dataByteCount = readDataBytes;
                                valueCandidate.dataPreview = formatRegistryData(queriedType, data);
                            }
                        }
                    }

                    if (!appendRegistrySearchCandidate(snapshot, valueCandidate)) {
                        break;
                    }
                }
            }
        }
        if (snapshot.stopReason == RegistrySearchStopReason::kCancelled ||
            snapshot.stopReason == RegistrySearchStopReason::kValueLimitReached ||
            snapshot.stopReason == RegistrySearchStopReason::kResultLimitReached) {
            break;
        }

        if (!subKey.valid()) {
            continue;
        }
        // RegQueryInfoKeyW requires KEY_QUERY_VALUE, while RegEnumKeyExW only
        // requires KEY_ENUMERATE_SUB_KEYS.  Use a fixed, documented-safe name
        // buffer here so a subkey-only ACL remains searchable without asking
        // for an additional right that the caller does not have.
        std::vector<wchar_t> subKeyName(static_cast<std::size_t>(kRegistrySearchMaxNameChars) + 1U);
        if (current.depth >= snapshot.request.maxDepth) {
            if (stopRegistrySearchIfCancelled(snapshot, cancelToken)) {
                break;
            }
            if (snapshot.counters.inspectedSubKeyCount >= snapshot.request.maxKeys) {
                subKeyEnumerationLimitReached = true;
                break;
            }
            ++snapshot.counters.inspectedSubKeyCount;
            DWORD subKeyNameChars = static_cast<DWORD>(subKeyName.size());
            const LONG kDepthProbeStatus = ::RegEnumKeyExW(
                subKey.get(),
                0U,
                subKeyName.data(),
                &subKeyNameChars,
                nullptr,
                nullptr,
                nullptr,
                nullptr);
            if (kDepthProbeStatus == ERROR_SUCCESS) {
                enumeratedAnyKey = true;
                ++snapshot.counters.skippedDepthCount;
            } else if (kDepthProbeStatus == ERROR_NO_MORE_ITEMS) {
                enumeratedAnyKey = true;
            } else {
                recordRegistrySearchReadFailure(
                    snapshot,
                    L"RegEnumKeyExW(depth probe) failed for " + current.path.displayPath + L": " + std::to_wstring(kDepthProbeStatus));
            }
            continue;
        }

        for (DWORD index = 0;; ++index) {
            if (stopRegistrySearchIfCancelled(snapshot, cancelToken)) {
                break;
            }
            // The worklist itself is bounded as well as processed keys.  This
            // prevents one key with a huge child count from consuming memory or
            // bypassing the key budget before its children are visited.
            if (snapshot.counters.inspectedSubKeyCount >= snapshot.request.maxKeys) {
                subKeyEnumerationLimitReached = true;
                break;
            }
            if (snapshot.counters.visitedKeyCount + pendingKeys.size() >= snapshot.request.maxKeys) {
                // A full worklist alone does not prove that a child remains.
                // Probe this exact index so an exactly-complete traversal is
                // reported as complete instead of as a false key-limit stop.
                ++snapshot.counters.inspectedSubKeyCount;
                DWORD capacityProbeNameChars = static_cast<DWORD>(subKeyName.size());
                const LONG kCapacityProbeStatus = ::RegEnumKeyExW(
                    subKey.get(),
                    index,
                    subKeyName.data(),
                    &capacityProbeNameChars,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr);
                if (kCapacityProbeStatus == ERROR_NO_MORE_ITEMS) {
                    enumeratedAnyKey = true;
                    break;
                }
                if (kCapacityProbeStatus == ERROR_SUCCESS) {
                    enumeratedAnyKey = true;
                    keyWorkLimitReached = true;
                    break;
                }
                recordRegistrySearchReadFailure(
                    snapshot,
                    L"RegEnumKeyExW(capacity probe) failed for " + current.path.displayPath + L": " + std::to_wstring(kCapacityProbeStatus));
                continue;
            }
            ++snapshot.counters.inspectedSubKeyCount;

            DWORD subKeyNameChars = static_cast<DWORD>(subKeyName.size());
            const LONG kEnumStatus = ::RegEnumKeyExW(
                subKey.get(),
                index,
                subKeyName.data(),
                &subKeyNameChars,
                nullptr,
                nullptr,
                nullptr,
                nullptr);
            if (kEnumStatus == ERROR_NO_MORE_ITEMS) {
                enumeratedAnyKey = true;
                break;
            }
            if (kEnumStatus != ERROR_SUCCESS) {
                recordRegistrySearchReadFailure(
                    snapshot,
                    L"RegEnumKeyExW failed for " + current.path.displayPath + L": " + std::to_wstring(kEnumStatus));
                continue;
            }
            enumeratedAnyKey = true;

            const std::size_t kChildDepth = current.depth + 1U;
            if (kChildDepth > snapshot.request.maxDepth) {
                ++snapshot.counters.skippedDepthCount;
                continue;
            }
            pendingKeys.push_back({
                makeRegistrySearchChildPath(
                    current.path,
                    std::wstring(subKeyName.data(), subKeyName.data() + subKeyNameChars)),
                kChildDepth
            });
        }
        if (snapshot.stopReason == RegistrySearchStopReason::kCancelled) {
            break;
        }
    }

    if (snapshot.stopReason == RegistrySearchStopReason::kNotStarted) {
        if (isRegistrySearchCancelled(cancelToken)) {
            snapshot.stopReason = RegistrySearchStopReason::kCancelled;
        } else if (keyWorkLimitReached) {
            snapshot.stopReason = RegistrySearchStopReason::kKeyLimitReached;
        } else if (subKeyEnumerationLimitReached) {
            snapshot.stopReason = RegistrySearchStopReason::kSubKeyEnumerationLimitReached;
        } else if (snapshot.counters.skippedDepthCount != 0U) {
            snapshot.stopReason = RegistrySearchStopReason::kDepthLimitReached;
        } else if (!enumeratedAnyKey && snapshot.counters.readFailureCount != 0U) {
            snapshot.stopReason = RegistrySearchStopReason::kReadFailure;
        } else {
            snapshot.stopReason = RegistrySearchStopReason::kCompleted;
        }
    }
    snapshot.statusText = buildRegistrySearchStatusText(snapshot);
    return snapshot;
}

std::vector<std::wstring> enumerateRegistrySubKeyNames(const std::wstring& path, const RegistryViewMode mode, std::wstring* statusTextOut) {
    // Inputs:
    // - path: one registry key in display or kernel form.
    // - mode: WinAPI or R0 transport.
    // - statusTextOut: optional status sink for UI feedback.
    // Processing:
    // - parses only the current key;
    // - enumerates direct child key names only;
    // - never walks recursively, so TreeView expansion stays lazy.
    // Output:
    // - direct child key names only.
    std::vector<std::wstring> childNames;
    RegistryPathInfo parsed = parseRegistryPath(path);
    if (!parsed.valid) {
        if (statusTextOut) {
            *statusTextOut = parsed.errorText;
        }
        return childNames;
    }

    if (mode == RegistryViewMode::kR0) {
        if (parsed.kernelPath.empty()) {
            if (statusTextOut) {
                *statusTextOut = L"R0 registry mode supports HKLM/HKU or \\REGISTRY\\MACHINE/USER paths.";
            }
            return childNames;
        }
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryEnumResult kResult = kClient.enumerateRegistryKey(parsed.kernelPath);
        if (statusTextOut) {
            *statusTextOut = buildR0StatusLine(L"enum keys", kResult.io.ok, kResult.status, kResult.lastStatus, kResult.io.message);
        }
        for (const auto& subKey : kResult.subKeys) {
            childNames.push_back(subKey.name);
        }
        return childNames;
    }

    LONG openStatus = ERROR_SUCCESS;
    UniqueRegKey key = openKey(parsed, KEY_READ, &openStatus);
    if (!key.valid()) {
        if (statusTextOut) {
            *statusTextOut = L"RegOpenKeyExW failed: " + std::to_wstring(openStatus);
        }
        return childNames;
    }

    DWORD subKeyCount = 0;
    DWORD maxSubKey = 0;
    if (::RegQueryInfoKeyW(key.get(), nullptr, nullptr, nullptr, &subKeyCount, &maxSubKey, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        if (statusTextOut) {
            *statusTextOut = L"RegQueryInfoKeyW failed.";
        }
        return childNames;
    }
    std::vector<wchar_t> name(static_cast<std::size_t>(maxSubKey) + 2U);
    for (DWORD index = 0; index < subKeyCount; ++index) {
        DWORD nameChars = static_cast<DWORD>(name.size());
        const LONG kRc = ::RegEnumKeyExW(key.get(), index, name.data(), &nameChars, nullptr, nullptr, nullptr, nullptr);
        if (kRc != ERROR_SUCCESS) {
            continue;
        }
        childNames.emplace_back(name.data(), name.data() + nameChars);
    }
    if (statusTextOut) {
        *statusTextOut = L"WinAPI subkey enum OK; subkeys=" + std::to_wstring(childNames.size());
    }
    return childNames;
}

RegistryOperationResult readRegistryValue(const std::wstring& path, const std::wstring& valueName, const RegistryViewMode mode) {
    RegistryPathInfo parsed = parseRegistryPath(path);
    if (!parsed.valid) {
        return makeOperationPathError(parsed);
    }
    RegistryOperationResult result;
    if (mode == RegistryViewMode::kR0) {
        if (!kernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryReadResult kRead = kClient.readRegistryValue(parsed.kernelPath, valueName);
        result.success = kRead.io.ok && kRead.status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS;
        result.win32Error = kRead.io.win32Error;
        result.ntStatus = kRead.lastStatus;
        result.valueType = kRead.valueType;
        result.data = kRead.data;
        result.statusText = buildR0StatusLine(L"read", kRead.io.ok, kRead.status, kRead.lastStatus, kRead.io.message);
        return result;
    }

    LONG openStatus = ERROR_SUCCESS;
    UniqueRegKey key = openKey(parsed, KEY_QUERY_VALUE, &openStatus);
    if (!key.valid()) {
        result.win32Error = static_cast<DWORD>(openStatus);
        result.statusText = L"RegOpenKeyExW failed: " + std::to_wstring(openStatus);
        return result;
    }
    DWORD type = 0;
    DWORD bytes = 0;
    const wchar_t* valuePtr = valueName.empty() ? nullptr : valueName.c_str();
    LONG rc = ::RegQueryValueExW(key.get(), valuePtr, nullptr, &type, nullptr, &bytes);
    if (rc != ERROR_SUCCESS) {
        result.win32Error = static_cast<DWORD>(rc);
        result.statusText = L"RegQueryValueExW(size) failed: " + std::to_wstring(rc);
        return result;
    }
    result.data.resize(bytes);
    rc = ::RegQueryValueExW(key.get(), valuePtr, nullptr, &type, result.data.data(), &bytes);
    if (rc != ERROR_SUCCESS) {
        result.win32Error = static_cast<DWORD>(rc);
        result.statusText = L"RegQueryValueExW(data) failed: " + std::to_wstring(rc);
        return result;
    }
    result.data.resize(bytes);
    result.valueType = type;
    result.success = true;
    result.statusText = L"WinAPI read OK; type=" + registryTypeText(type) + L"; bytes=" + std::to_wstring(bytes);
    return result;
}

RegistryOperationResult writeRegistryValue(const std::wstring& path, const std::wstring& valueName, const std::uint32_t type, const std::vector<std::uint8_t>& data, const RegistryViewMode mode) {
    RegistryPathInfo parsed = parseRegistryPath(path);
    if (!parsed.valid) {
        return makeOperationPathError(parsed);
    }
    RegistryOperationResult result;
    if (mode == RegistryViewMode::kR0) {
        if (!kernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryOperationResult kWrite = kClient.setRegistryValue(parsed.kernelPath, valueName, type, data);
        result.success = kWrite.io.ok && kWrite.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        result.win32Error = kWrite.io.win32Error;
        result.ntStatus = kWrite.lastStatus;
        result.statusText = buildR0StatusLine(L"write", kWrite.io.ok, kWrite.status, kWrite.lastStatus, kWrite.io.message);
        return result;
    }

    LONG openStatus = ERROR_SUCCESS;
    UniqueRegKey key = openKey(parsed, KEY_SET_VALUE, &openStatus);
    if (!key.valid()) {
        result.win32Error = static_cast<DWORD>(openStatus);
        result.statusText = L"RegOpenKeyExW failed: " + std::to_wstring(openStatus);
        return result;
    }
    const LONG kRc = ::RegSetValueExW(key.get(), valueName.empty() ? nullptr : valueName.c_str(), 0, type,
        data.empty() ? nullptr : data.data(), static_cast<DWORD>(data.size()));
    result.success = kRc == ERROR_SUCCESS;
    result.win32Error = static_cast<DWORD>(kRc);
    result.statusText = result.success ? L"WinAPI write OK." : L"RegSetValueExW failed: " + std::to_wstring(kRc);
    return result;
}

RegistryOperationResult deleteRegistryValue(const std::wstring& path, const std::wstring& valueName, const RegistryViewMode mode) {
    RegistryPathInfo parsed = parseRegistryPath(path);
    if (!parsed.valid) {
        return makeOperationPathError(parsed);
    }
    RegistryOperationResult result;
    if (mode == RegistryViewMode::kR0) {
        if (!kernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryOperationResult kDel = kClient.deleteRegistryValue(parsed.kernelPath, valueName);
        result.success = kDel.io.ok && kDel.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        result.win32Error = kDel.io.win32Error;
        result.ntStatus = kDel.lastStatus;
        result.statusText = buildR0StatusLine(L"delete value", kDel.io.ok, kDel.status, kDel.lastStatus, kDel.io.message);
        return result;
    }

    LONG openStatus = ERROR_SUCCESS;
    UniqueRegKey key = openKey(parsed, KEY_SET_VALUE, &openStatus);
    if (!key.valid()) {
        result.win32Error = static_cast<DWORD>(openStatus);
        result.statusText = L"RegOpenKeyExW failed: " + std::to_wstring(openStatus);
        return result;
    }
    const LONG kRc = ::RegDeleteValueW(key.get(), valueName.empty() ? nullptr : valueName.c_str());
    result.success = kRc == ERROR_SUCCESS;
    result.win32Error = static_cast<DWORD>(kRc);
    result.statusText = result.success ? L"WinAPI delete value OK." : L"RegDeleteValueW failed: " + std::to_wstring(kRc);
    return result;
}

RegistryOperationResult createRegistryKey(const std::wstring& path, const RegistryViewMode mode) {
    RegistryPathInfo parsed = parseRegistryPath(path);
    if (!parsed.valid) {
        return makeOperationPathError(parsed);
    }
    RegistryOperationResult result;
    if (mode == RegistryViewMode::kR0) {
        if (!kernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryOperationResult kCreate = kClient.createRegistryKey(parsed.kernelPath);
        result.success = kCreate.io.ok && kCreate.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        result.win32Error = kCreate.io.win32Error;
        result.ntStatus = kCreate.lastStatus;
        result.statusText = buildR0StatusLine(L"create key", kCreate.io.ok, kCreate.status, kCreate.lastStatus, kCreate.io.message);
        return result;
    }

    HKEY raw = nullptr;
    DWORD disposition = 0;
    const LONG kRc = ::RegCreateKeyExW(parsed.root, parsed.subKey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE, nullptr, &raw, &disposition);
    UniqueRegKey key(raw);
    result.success = kRc == ERROR_SUCCESS;
    result.win32Error = static_cast<DWORD>(kRc);
    result.statusText = result.success ? L"WinAPI create/open key OK." : L"RegCreateKeyExW failed: " + std::to_wstring(kRc);
    return result;
}

RegistryOperationResult deleteRegistryKey(const std::wstring& path, const RegistryViewMode mode) {
    RegistryPathInfo parsed = parseRegistryPath(path);
    if (!parsed.valid) {
        return makeOperationPathError(parsed);
    }
    RegistryOperationResult result;
    if (mode == RegistryViewMode::kR0) {
        if (!kernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryOperationResult kDel = kClient.deleteRegistryKey(parsed.kernelPath);
        result.success = kDel.io.ok && kDel.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        result.win32Error = kDel.io.win32Error;
        result.ntStatus = kDel.lastStatus;
        result.statusText = buildR0StatusLine(L"delete key", kDel.io.ok, kDel.status, kDel.lastStatus, kDel.io.message);
        return result;
    }

    const LONG kRc = ::RegDeleteTreeW(parsed.root, parsed.subKey.c_str());
    result.success = kRc == ERROR_SUCCESS;
    result.win32Error = static_cast<DWORD>(kRc);
    result.statusText = result.success ? L"WinAPI delete key tree OK." : L"RegDeleteTreeW failed: " + std::to_wstring(kRc);
    return result;
}

RegistryOperationResult renameRegistryValue(const std::wstring& path, const std::wstring& oldName, const std::wstring& newName, const RegistryViewMode mode) {
    RegistryOperationResult result;
    RegistryPathInfo parsed = parseRegistryPath(path);
    if (!parsed.valid) {
        return makeOperationPathError(parsed);
    }
    if (mode == RegistryViewMode::kR0) {
        if (!kernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryOperationResult kRename = kClient.renameRegistryValue(parsed.kernelPath, oldName, newName);
        result.success = kRename.io.ok && kRename.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        result.win32Error = kRename.io.win32Error;
        result.ntStatus = kRename.lastStatus;
        result.statusText = buildR0StatusLine(L"rename value", kRename.io.ok, kRename.status, kRename.lastStatus, kRename.io.message);
        return result;
    }

    RegistryOperationResult read = readRegistryValue(path, oldName, mode);
    if (!read.success) {
        return read;
    }
    RegistryOperationResult write = writeRegistryValue(path, newName, read.valueType, read.data, mode);
    if (!write.success) {
        return write;
    }
    return deleteRegistryValue(path, oldName, mode);
}

RegistryOperationResult renameRegistryKey(const std::wstring& path, const std::wstring& newName, const RegistryViewMode mode) {
    RegistryOperationResult result;
    RegistryPathInfo parsed = parseRegistryPath(path);
    if (!parsed.valid) {
        return makeOperationPathError(parsed);
    }
    if (mode == RegistryViewMode::kR0) {
        if (!kernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient kClient;
        const ksword::ark::RegistryOperationResult kRename = kClient.renameRegistryKey(parsed.kernelPath, newName);
        result.success = kRename.io.ok && kRename.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        result.win32Error = kRename.io.win32Error;
        result.ntStatus = kRename.lastStatus;
        result.statusText = buildR0StatusLine(L"rename key", kRename.io.ok, kRename.status, kRename.lastStatus, kRename.io.message);
        return result;
    }
    result.success = false;
    result.win32Error = ERROR_NOT_SUPPORTED;
    result.statusText = L"WinAPI key rename is not exposed here; use R0 mode for rename key.";
    return result;
}

bool copyRegistryTextToClipboard(HWND owner, const std::wstring& text) {
    if (!::OpenClipboard(owner)) {
        return false;
    }
    ::EmptyClipboard();
    const SIZE_T kBytes = (text.size() + 1U) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, kBytes);
    if (!memory) {
        ::CloseClipboard();
        return false;
    }
    void* target = ::GlobalLock(memory);
    if (!target) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    std::memcpy(target, text.c_str(), kBytes);
    ::GlobalUnlock(memory);
    if (!::SetClipboardData(CF_UNICODETEXT, memory)) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    ::CloseClipboard();
    return true;
}

} // namespace Ksword::Features::Registry
