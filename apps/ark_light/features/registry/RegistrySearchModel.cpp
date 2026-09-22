#include "RegistrySearchModel.h"

#include <algorithm>
#include <cwctype>
#include <utility>

namespace ksword::features::registry {
namespace {

std::wstring trimCopy(std::wstring text) {
    const auto kFirst = std::find_if(text.begin(), text.end(), [](const wchar_t character) {
        return std::iswspace(static_cast<wint_t>(character)) == 0;
    });
    if (kFirst == text.end()) {
        return {};
    }
    const auto kLast = std::find_if(text.rbegin(), text.rend(), [](const wchar_t character) {
        return std::iswspace(static_cast<wint_t>(character)) == 0;
    }).base();
    return std::wstring(kFirst, kLast);
}

std::size_t clampBudget(const std::size_t requested, const std::size_t hardCap) {
    // A zero budget is normalized to the documented fixed bound.  This keeps
    // an omitted/default-initialized field from accidentally making a search
    // terminate before examining its first key or value.
    if (requested == 0U) {
        return hardCap;
    }
    return (std::min)(requested, hardCap);
}

std::wstring flattenDisplayText(std::wstring value) {
    for (wchar_t& character : value) {
        if (character == L'\t' || character == L'\r' || character == L'\n') {
            character = L' ';
        }
    }
    return value;
}

bool isHighSurrogate(const wchar_t character) {
    return character >= 0xD800 && character <= 0xDBFF;
}

bool isLowSurrogate(const wchar_t character) {
    return character >= 0xDC00 && character <= 0xDFFF;
}

std::wstring boundedPreview(std::wstring value, const std::size_t maxPreviewBytes, bool& truncated) {
    value = flattenDisplayText(std::move(value));
    const std::size_t kMaxChars = maxPreviewBytes / sizeof(wchar_t);
    if (value.size() <= kMaxChars) {
        return value;
    }

    truncated = true;
    if (kMaxChars == 0U) {
        return {};
    }

    // Keep the omission marker within the configured byte budget and avoid
    // leaving a UTF-16 high surrogate at the end of the copied prefix.
    const std::size_t kMarkerChars = kMaxChars >= 3U ? 3U : 0U;
    std::size_t copyChars = kMaxChars - kMarkerChars;
    if (copyChars > 0U && copyChars < value.size() &&
        isHighSurrogate(value[copyChars - 1U]) && isLowSurrogate(value[copyChars])) {
        --copyChars;
    }

    std::wstring preview = value.substr(0U, copyChars);
    if (kMarkerChars != 0U) {
        preview += L"...";
    }
    return preview;
}

std::wstring foldCase(const std::wstring& value) {
    std::wstring folded;
    folded.reserve(value.size());
    for (const wchar_t kCharacter : value) {
        folded.push_back(static_cast<wchar_t>(std::towlower(static_cast<wint_t>(kCharacter))));
    }
    return folded;
}

bool containsIgnoreCase(const std::wstring& text, const std::wstring& query) {
    if (query.empty()) {
        return false;
    }
    return foldCase(text).find(foldCase(query)) != std::wstring::npos;
}

const wchar_t* entryKindText(const RegistrySearchEntryKind kind) {
    return kind == RegistrySearchEntryKind::kKey ? L"键" : L"值";
}

void appendTsvCell(std::wstring& output, const std::wstring& value, const bool firstCell) {
    if (!firstCell) {
        output.push_back(L'\t');
    }
    output += sanitizeRegistrySearchTsvCell(value);
}

void appendTsvHit(std::wstring& output, const RegistrySearchHit& hit) {
    appendTsvCell(output, entryKindText(hit.kind), true);
    appendTsvCell(output, hit.keyPath, false);
    appendTsvCell(output, hit.valueName, false);
    appendTsvCell(output, hit.valueTypeText, false);
    appendTsvCell(output, hit.dataPreview, false);
    appendTsvCell(output, std::to_wstring(hit.dataByteCount), false);
    appendTsvCell(output, std::to_wstring(hit.depth), false);
    appendTsvCell(output, hit.dataPreviewTruncated ? L"已截断" : L"完整", false);
    output += L"\r\n";
}

std::wstring countText(const RegistrySearchSnapshot& snapshot) {
    std::wstring text = L"已扫描 " + std::to_wstring(snapshot.counters.visitedKeyCount) +
        L" 个键、" + std::to_wstring(snapshot.counters.visitedValueCount) +
        L" 个值；进行了 " + std::to_wstring(snapshot.counters.inspectedSubKeyCount) +
        L" 次子键枚举；命中 " + std::to_wstring(snapshot.hits.size()) + L" 项";
    if (snapshot.counters.readFailureCount != 0U) {
        text += L"；跳过 " + std::to_wstring(snapshot.counters.readFailureCount) + L" 个不可读项";
    }
    if (snapshot.counters.truncatedPreviewCount != 0U) {
        text += L"；截断 " + std::to_wstring(snapshot.counters.truncatedPreviewCount) + L" 个预览";
    }
    return text;
}

} // namespace

RegistrySearchValidation validateRegistrySearchRequest(const RegistrySearchRequest& request) {
    RegistrySearchValidation validation;
    validation.request = request;
    validation.request.startPath = trimCopy(request.startPath);
    validation.normalizedQuery = trimCopy(request.query);
    validation.request.query = validation.normalizedQuery;
    validation.request.maxKeys = clampBudget(request.maxKeys, kRegistrySearchMaxKeys);
    validation.request.maxValues = clampBudget(request.maxValues, kRegistrySearchMaxValues);
    validation.request.maxResults = clampBudget(request.maxResults, kRegistrySearchMaxResults);
    validation.request.maxDepth = clampBudget(request.maxDepth, kRegistrySearchMaxDepth);
    validation.request.maxValuePreviewBytes = clampBudget(request.maxValuePreviewBytes, kRegistrySearchMaxValuePreviewBytes);

    if (validation.request.startPath.empty()) {
        validation.errorText = L"注册表搜索起始路径为空。";
        return validation;
    }
    if (validation.normalizedQuery.empty()) {
        validation.errorText = L"注册表搜索关键字为空。";
        return validation;
    }

    validation.valid = true;
    return validation;
}

RegistrySearchHit projectRegistrySearchHit(
    const RegistrySearchCandidate& candidate,
    const std::size_t maxPreviewBytes) {
    RegistrySearchHit hit;
    hit.kind = candidate.kind;
    hit.keyPath = trimCopy(flattenDisplayText(candidate.keyPath));
    hit.valueName = flattenDisplayText(candidate.valueName);
    hit.valueTypeText = flattenDisplayText(candidate.valueTypeText);
    hit.dataByteCount = candidate.dataByteCount;
    hit.depth = candidate.depth;
    hit.dataPreviewTruncated = candidate.dataByteCount > maxPreviewBytes;
    hit.dataPreview = boundedPreview(candidate.dataPreview, maxPreviewBytes, hit.dataPreviewTruncated);
    hit.valid = !hit.keyPath.empty();
    return hit;
}

bool registrySearchHitMatches(const RegistrySearchHit& hit, const std::wstring& normalizedQuery) {
    const std::wstring kQuery = trimCopy(normalizedQuery);
    if (!hit.valid || kQuery.empty()) {
        return false;
    }
    return containsIgnoreCase(hit.keyPath, kQuery) ||
        containsIgnoreCase(hit.valueName, kQuery) ||
        containsIgnoreCase(hit.valueTypeText, kQuery) ||
        containsIgnoreCase(hit.dataPreview, kQuery);
}

std::wstring buildRegistrySearchStatusText(const RegistrySearchSnapshot& snapshot) {
    const std::wstring kCounts = countText(snapshot);
    switch (snapshot.stopReason) {
    case RegistrySearchStopReason::kNotStarted:
        return L"注册表搜索尚未开始。";
    case RegistrySearchStopReason::kCompleted:
        return L"注册表搜索完成：" + kCounts + L"。";
    case RegistrySearchStopReason::kInvalidRequest:
        return snapshot.errorText.empty()
            ? L"注册表搜索请求无效。"
            : L"注册表搜索请求无效：" + snapshot.errorText;
    case RegistrySearchStopReason::kKeyLimitReached:
        return L"注册表搜索已达到 " + std::to_wstring(snapshot.request.maxKeys) +
            L" 个键的上限：" + kCounts + L"。";
    case RegistrySearchStopReason::kSubKeyEnumerationLimitReached:
        return L"注册表搜索已达到 " + std::to_wstring(snapshot.request.maxKeys) +
            L" 次子键枚举工作上限：" + kCounts + L"。";
    case RegistrySearchStopReason::kValueLimitReached:
        return L"注册表搜索已达到 " + std::to_wstring(snapshot.request.maxValues) +
            L" 个值的上限：" + kCounts + L"。";
    case RegistrySearchStopReason::kResultLimitReached:
        return L"注册表搜索已达到 " + std::to_wstring(snapshot.request.maxResults) +
            L" 项结果上限：" + kCounts + L"。";
    case RegistrySearchStopReason::kDepthLimitReached:
        return L"注册表搜索已达到深度 " + std::to_wstring(snapshot.request.maxDepth) +
            L" 的上限，跳过 " + std::to_wstring(snapshot.counters.skippedDepthCount) +
            L" 个分支：" + kCounts + L"。";
    case RegistrySearchStopReason::kCancelled:
        return L"注册表搜索已取消：" + kCounts + L"。";
    case RegistrySearchStopReason::kReadFailure:
        return snapshot.errorText.empty()
            ? L"注册表搜索因读取失败停止：" + kCounts + L"。"
            : L"注册表搜索因读取失败停止：" + snapshot.errorText + L"；" + kCounts + L"。";
    default:
        return L"注册表搜索状态未知：" + kCounts + L"。";
    }
}

std::wstring sanitizeRegistrySearchTsvCell(const std::wstring& text) {
    return flattenDisplayText(text);
}

std::wstring buildRegistrySearchTsv(const std::vector<RegistrySearchHit>& hits) {
    std::wstring output;
    bool wroteHeader = false;
    for (const RegistrySearchHit& hit : hits) {
        if (!hit.valid) {
            continue;
        }
        if (!wroteHeader) {
            output = L"类型\t键路径\t值名称\t值类型\t数据预览\t数据字节\t深度\t预览状态\r\n";
            wroteHeader = true;
        }
        appendTsvHit(output, hit);
    }
    return output;
}

std::wstring buildVisibleRegistrySearchTsv(
    const std::vector<RegistrySearchHit>& hits,
    const std::vector<std::size_t>& visibleIndexes) {
    std::wstring output;
    bool wroteHeader = false;
    for (const std::size_t kIndex : visibleIndexes) {
        if (kIndex >= hits.size() || !hits[kIndex].valid) {
            continue;
        }
        if (!wroteHeader) {
            output = L"类型\t键路径\t值名称\t值类型\t数据预览\t数据字节\t深度\t预览状态\r\n";
            wroteHeader = true;
        }
        appendTsvHit(output, hits[kIndex]);
    }
    return output;
}

} // namespace Ksword::Features::Registry
