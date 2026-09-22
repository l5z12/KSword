#include "Common.h"

namespace ksword::core {

UniqueHandle::UniqueHandle() noexcept : handle_(nullptr) {}

UniqueHandle::UniqueHandle(HANDLE handle) noexcept : handle_(handle) {}

UniqueHandle::~UniqueHandle() {
    reset();
}

UniqueHandle::UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.release()) {}

UniqueHandle& UniqueHandle::operator=(UniqueHandle&& other) noexcept {
    if (this != &other) {
        reset(other.release());
    }
    return *this;
}

void UniqueHandle::reset(HANDLE handle) noexcept {
    if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(handle_);
    }
    handle_ = handle;
}

HANDLE UniqueHandle::release() noexcept {
    HANDLE out = handle_;
    handle_ = nullptr;
    return out;
}

HANDLE UniqueHandle::get() const noexcept {
    return handle_;
}

bool UniqueHandle::valid() const noexcept {
    return handle_ && handle_ != INVALID_HANDLE_VALUE;
}

std::wstring lastErrorMessage(DWORD errorCode) {
    wchar_t* buffer = nullptr;
    const DWORD kFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD kCount = ::FormatMessageW(kFlags, nullptr, errorCode, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::wstring text;
    if (kCount > 0 && buffer) {
        text.assign(buffer, kCount);
        while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ')) {
            text.pop_back();
        }
    }
    if (buffer) {
        ::LocalFree(buffer);
    }
    if (text.empty()) {
        text = L"Win32 error " + std::to_wstring(errorCode);
    }
    return text;
}

std::wstring lastErrorMessage() {
    return lastErrorMessage(::GetLastError());
}

} // namespace Ksword::Core
