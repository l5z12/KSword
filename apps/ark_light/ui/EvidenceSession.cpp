#include "EvidenceSession.h"

#include "../core/Win32Lean.h"

#include <algorithm>
#include <cwctype>
#include <sstream>
#include <unordered_set>

namespace ksword::ui {
namespace {

std::vector<std::wstring> lines(const std::wstring& text) {
    std::vector<std::wstring> lines;
    std::wstring current;
    for (const wchar_t kCh : text) {
        if (kCh == L'\r') {
            continue;
        }
        if (kCh == L'\n') {
            lines.push_back(std::move(current));
            current.clear();
        } else {
            current.push_back(kCh);
        }
    }
    if (!current.empty() || (!text.empty() && text.back() != L'\n')) {
        lines.push_back(std::move(current));
    }
    return lines;
}

std::wstring jsonEscape(const std::wstring& text) {
    std::wstring output;
    output.reserve(text.size() + 16U);
    for (const wchar_t kCh : text) {
        switch (kCh) {
        case L'\\': output += L"\\\\"; break;
        case L'\"': output += L"\\\""; break;
        case L'\r': output += L"\\r"; break;
        case L'\n': output += L"\\n"; break;
        case L'\t': output += L"\\t"; break;
        default: output.push_back(kCh); break;
        }
    }
    return output;
}

std::wstring tsvCell(std::wstring text) {
    for (wchar_t& ch : text) {
        if (ch == L'\t' || ch == L'\r' || ch == L'\n') {
            ch = L' ';
        }
    }
    return text;
}

std::uint64_t currentFileTime100ns() noexcept {
    FILETIME value{};
    ::GetSystemTimeAsFileTime(&value);
    ULARGE_INTEGER integer{};
    integer.LowPart = value.dwLowDateTime;
    integer.HighPart = value.dwHighDateTime;
    return integer.QuadPart;
}

bool startsWithNoCase(const std::wstring& text, const std::size_t offset, const wchar_t* prefix) {
    const std::size_t kLength = std::wcslen(prefix);
    if (offset + kLength > text.size()) {
        return false;
    }
    for (std::size_t index = 0; index < kLength; ++index) {
        if (std::towlower(text[offset + index]) != std::towlower(prefix[index])) {
            return false;
        }
    }
    return true;
}

} // namespace

std::wstring redactEvidenceText(const std::wstring& text, const EvidenceRedaction redaction) {
    if (redaction == EvidenceRedaction::kNone || text.empty()) {
        return text;
    }
    std::wstring output;
    output.reserve(text.size());
    for (std::size_t index = 0; index < text.size();) {
        if (startsWithNoCase(text, index, L"C:\\Users\\")) {
            output += L"C:\\Users\\<redacted>";
            index += 9U;
            while (index < text.size() && text[index] != L'\\' && text[index] != L'/' &&
                text[index] != L'\r' && text[index] != L'\n' && text[index] != L'\t') {
                ++index;
            }
            continue;
        }
        output.push_back(text[index++]);
    }
    return output;
}

EvidenceDiff buildEvidenceDiff(const std::wstring& before, const std::wstring& after) {
    const std::vector<std::wstring> kBeforeLines = lines(before);
    const std::vector<std::wstring> kAfterLines = lines(after);
    const std::unordered_set<std::wstring> kBeforeSet(kBeforeLines.begin(), kBeforeLines.end());
    const std::unordered_set<std::wstring> kAfterSet(kAfterLines.begin(), kAfterLines.end());
    EvidenceDiff diff;
    for (const std::wstring& line : kBeforeLines) {
        if (kAfterSet.contains(line)) {
            diff.unchanged.push_back(line);
        } else {
            diff.removed.push_back(line);
        }
    }
    for (const std::wstring& line : kAfterLines) {
        if (!kBeforeSet.contains(line)) {
            diff.added.push_back(line);
        }
    }
    return diff;
}

std::wstring renderEvidenceDiff(const EvidenceDiff& diff) {
    std::wostringstream output;
    output << L"Evidence diff: +" << diff.added.size() << L" -" << diff.removed.size()
           << L" =" << diff.unchanged.size() << L"\r\n";
    for (const std::wstring& line : diff.removed) {
        output << L"- " << line << L"\r\n";
    }
    for (const std::wstring& line : diff.added) {
        output << L"+ " << line << L"\r\n";
    }
    return output.str();
}

std::uint64_t EvidenceSession::record(std::wstring source, std::wstring format, std::wstring text) {
    if (text.empty()) {
        return 0;
    }
    std::scoped_lock lock(mutex_);
    const std::uint64_t kSequence = nextSequence_++;
    items_.push_back({ kSequence, currentFileTime100ns(), std::move(source), std::move(format), std::move(text) });
    return kSequence;
}

std::vector<EvidenceItem> EvidenceSession::snapshot() const {
    std::scoped_lock lock(mutex_);
    return items_;
}

bool EvidenceSession::erase(const std::uint64_t sequence) {
    std::scoped_lock lock(mutex_);
    const auto kItem = std::find_if(items_.begin(), items_.end(), [sequence](const EvidenceItem& candidate) {
        return candidate.sequence == sequence;
    });
    if (kItem == items_.end()) {
        return false;
    }
    items_.erase(kItem);
    return true;
}

void EvidenceSession::clear() {
    std::scoped_lock lock(mutex_);
    items_.clear();
}

std::size_t EvidenceSession::size() const {
    std::scoped_lock lock(mutex_);
    return items_.size();
}

EvidenceDiff EvidenceSession::latestDiff() const {
    std::scoped_lock lock(mutex_);
    if (items_.size() < 2U) {
        return {};
    }
    return buildEvidenceDiff(items_[items_.size() - 2U].text, items_.back().text);
}

std::wstring EvidenceSession::exportJson(const EvidenceRedaction redaction) const {
    const std::vector<EvidenceItem> kItems = snapshot();
    std::wostringstream output;
    output << L"{\r\n  \"schema\": \"ksword-arklight-evidence-v1\",\r\n  \"items\": [";
    for (std::size_t index = 0; index < kItems.size(); ++index) {
        const EvidenceItem& item = kItems[index];
        output << (index == 0 ? L"\r\n" : L",\r\n")
               << L"    {\"sequence\": " << item.sequence
               << L", \"timestamp100ns\": " << item.timestamp100ns
               << L", \"source\": \"" << jsonEscape(item.source)
               << L"\", \"format\": \"" << jsonEscape(item.format)
               << L"\", \"text\": \"" << jsonEscape(redactEvidenceText(item.text, redaction)) << L"\"}";
    }
    output << (kItems.empty() ? L"]\r\n}" : L"\r\n  ]\r\n}");
    return output.str();
}

std::wstring EvidenceSession::exportTsv(const EvidenceRedaction redaction) const {
    const std::vector<EvidenceItem> kItems = snapshot();
    std::wostringstream output;
    output << L"Sequence\tTimestamp100ns\tSource\tFormat\tText\r\n";
    for (const EvidenceItem& item : kItems) {
        output << item.sequence << L'\t' << item.timestamp100ns << L'\t'
               << tsvCell(item.source) << L'\t' << tsvCell(item.format) << L'\t'
               << tsvCell(redactEvidenceText(item.text, redaction)) << L"\r\n";
    }
    return output.str();
}

EvidenceSession& globalEvidenceSession() {
    static EvidenceSession session;
    return session;
}

} // namespace Ksword::Ui
