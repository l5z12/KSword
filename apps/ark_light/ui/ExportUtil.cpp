#include "ExportUtil.h"

#include "EvidenceSession.h"

#include <commdlg.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#pragma comment(lib, "Comdlg32.lib")

namespace ksword::ui {
namespace {

std::wstring sanitizeTsvCell(std::wstring cell) {
    for (wchar_t& character : cell) {
        if (character == L'\t' || character == L'\r' || character == L'\n') {
            character = L' ';
        }
    }
    return cell;
}

void appendTsvRow(std::wstring& output, const std::vector<std::wstring>& cells) {
    for (std::size_t column = 0; column < cells.size(); ++column) {
        if (column != 0) {
            output.push_back(L'\t');
        }
        output += sanitizeTsvCell(cells[column]);
    }
    output += L"\r\n";
}

bool writeAll(HANDLE file, const void* data, const std::size_t byteCount, std::wstring* errorOut) {
    if (byteCount == 0U) {
        return true;
    }
    if (!data) {
        if (errorOut) {
            *errorOut = L"导出数据为空。";
        }
        return false;
    }
    const auto* bytes = static_cast<const char*>(data);
    std::size_t offset = 0;
    while (offset < byteCount) {
        const std::size_t kRemaining = byteCount - offset;
        const DWORD kChunk = static_cast<DWORD>((std::min)(
            kRemaining, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!::WriteFile(file, bytes + offset, kChunk, &written, nullptr) || written != kChunk) {
            if (errorOut) {
                *errorOut = L"WriteFile 失败，错误 " + std::to_wstring(::GetLastError()) + L"。";
            }
            return false;
        }
        offset += written;
    }
    return true;
}

SaveTextFileResult chooseSavePath(HWND owner,
    const wchar_t* suggestedFileName,
    const wchar_t* dialogTitle,
    const wchar_t* fileFilter,
    const wchar_t* defaultExtension,
    std::array<wchar_t, MAX_PATH>& path,
    std::wstring* errorOut) {
    if (suggestedFileName) {
        ::wcsncpy_s(path.data(), path.size(), suggestedFileName, _TRUNCATE);
    }
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = owner;
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.lpstrTitle = dialogTitle;
    dialog.lpstrFilter = fileFilter;
    dialog.lpstrDefExt = defaultExtension;
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (::GetSaveFileNameW(&dialog)) {
        return SaveTextFileResult::kSaved;
    }
    const DWORD kError = ::CommDlgExtendedError();
    if (kError != 0 && errorOut) {
        *errorOut = L"保存对话框失败，错误 " + std::to_wstring(kError) + L"。";
    }
    return kError == 0 ? SaveTextFileResult::kCancelled : SaveTextFileResult::kFailed;
}

SaveTextFileResult writeExportFile(const std::array<wchar_t, MAX_PATH>& path,
    const void* data,
    const std::size_t byteCount,
    std::wstring* errorOut) {
    HANDLE file = ::CreateFileW(path.data(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (errorOut) {
            *errorOut = L"无法写入文件，错误 " + std::to_wstring(::GetLastError()) + L"。";
        }
        return SaveTextFileResult::kFailed;
    }
    const bool kWritten = writeAll(file, data, byteCount, errorOut);
    const DWORD kCloseError = ::CloseHandle(file) ? ERROR_SUCCESS : ::GetLastError();
    if (!kWritten || kCloseError != ERROR_SUCCESS) {
        if (kWritten && errorOut) {
            *errorOut = L"关闭导出文件失败，错误 " + std::to_wstring(kCloseError) + L"。";
        }
        return SaveTextFileResult::kFailed;
    }
    return SaveTextFileResult::kSaved;
}

std::vector<char> toUtf8WithBom(const std::wstring& text, std::wstring* errorOut) {
    const int kCount = text.empty()
        ? 0
        : ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!text.empty() && kCount <= 0) {
        if (errorOut) {
            *errorOut = L"WideCharToMultiByte 失败，错误 " + std::to_wstring(::GetLastError()) + L"。";
        }
        return {};
    }
    std::vector<char> bytes;
    bytes.reserve(3U + static_cast<std::size_t>(kCount));
    bytes.insert(bytes.end(), { static_cast<char>(0xEF), static_cast<char>(0xBB), static_cast<char>(0xBF) });
    if (kCount > 0) {
        const std::size_t kOffset = bytes.size();
        bytes.resize(kOffset + static_cast<std::size_t>(kCount));
        if (::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), bytes.data() + kOffset,
                kCount, nullptr, nullptr) != kCount) {
            if (errorOut) {
                *errorOut = L"WideCharToMultiByte 失败，错误 " + std::to_wstring(::GetLastError()) + L"。";
            }
            return {};
        }
    }
    return bytes;
}

} // namespace

std::wstring buildVisibleVirtualListTsv(
    const std::vector<std::wstring>& columnTitles,
    const VirtualListView& list) {
    if (columnTitles.empty() || list.visibleIndexes().empty()) {
        return {};
    }
    std::wstring output;
    appendTsvRow(output, columnTitles);
    const auto& rows = list.rows();
    for (const std::size_t kIndex : list.visibleIndexes()) {
        if (kIndex < rows.size()) {
            appendTsvRow(output, rows[kIndex].cells);
        }
    }
    return output;
}

bool copyTextToClipboard(HWND owner, const std::wstring& text, const std::wstring& source) {
    if (text.empty() || !::OpenClipboard(owner)) {
        return false;
    }
    if (!::EmptyClipboard()) {
        ::CloseClipboard();
        return false;
    }
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
    globalEvidenceSession().record(source.empty() ? L"剪贴板导出" : source, L"text", text);
    return true;
}

SaveTextFileResult saveUtf8TextFileWithDialog(
    HWND owner,
    const wchar_t* suggestedFileName,
    const wchar_t* dialogTitle,
    const wchar_t* fileFilter,
    const wchar_t* defaultExtension,
    const std::wstring& text,
    std::wstring* errorOut) {
    if (errorOut) {
        errorOut->clear();
    }
    std::array<wchar_t, MAX_PATH> path{};
    const SaveTextFileResult kSelection = chooseSavePath(owner, suggestedFileName, dialogTitle, fileFilter, defaultExtension, path, errorOut);
    if (kSelection != SaveTextFileResult::kSaved) {
        return kSelection;
    }

    std::wstring conversionError;
    const std::vector<char> kBytes = toUtf8WithBom(text, &conversionError);
    if (kBytes.empty()) {
        if (errorOut) {
            *errorOut = conversionError.empty() ? L"无法转换导出文本。" : conversionError;
        }
        return SaveTextFileResult::kFailed;
    }
    const SaveTextFileResult kWriteResult = writeExportFile(path, kBytes.data(), kBytes.size(), errorOut);
    if (kWriteResult != SaveTextFileResult::kSaved) {
        return kWriteResult;
    }
    globalEvidenceSession().record(
        dialogTitle ? dialogTitle : L"文件导出",
        defaultExtension ? defaultExtension : L"text",
        text);
    return SaveTextFileResult::kSaved;
}

SaveTextFileResult saveBinaryFileWithDialog(
    HWND owner,
    const wchar_t* suggestedFileName,
    const wchar_t* dialogTitle,
    const wchar_t* fileFilter,
    const wchar_t* defaultExtension,
    const std::vector<std::uint8_t>& bytes,
    const std::wstring& evidenceSource,
    const std::wstring& evidenceText,
    std::wstring* errorOut) {
    if (errorOut) {
        errorOut->clear();
    }
    if (bytes.empty()) {
        if (errorOut) {
            *errorOut = L"没有可导出的二进制字节。";
        }
        return SaveTextFileResult::kFailed;
    }
    std::array<wchar_t, MAX_PATH> path{};
    const SaveTextFileResult kSelection = chooseSavePath(owner, suggestedFileName, dialogTitle, fileFilter, defaultExtension, path, errorOut);
    if (kSelection != SaveTextFileResult::kSaved) {
        return kSelection;
    }
    const SaveTextFileResult kWriteResult = writeExportFile(path, bytes.data(), bytes.size(), errorOut);
    if (kWriteResult != SaveTextFileResult::kSaved) {
        return kWriteResult;
    }
    globalEvidenceSession().record(
        evidenceSource.empty() ? L"二进制文件导出" : evidenceSource,
        defaultExtension ? defaultExtension : L"binary",
        evidenceText.empty() ? L"二进制导出已完成。" : evidenceText);
    return SaveTextFileResult::kSaved;
}

} // namespace Ksword::Ui
