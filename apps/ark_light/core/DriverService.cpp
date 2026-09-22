#include "DriverService.h"

#include "Common.h"
#include "PathUtils.h"
#include "resource.h"
#include "../../../shared/ark_client/ArkDriverClient.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>
#include <winsvc.h>

namespace ksword::core {
namespace {
constexpr wchar_t kDriverFileName[] = L"KswordARK.sys";
constexpr wchar_t kDriverServiceName[] = L"KswordARK";
constexpr wchar_t kDriverDisplayName[] = L"KswordARK R0 Driver";
constexpr DWORD kDriverIoChunkBytes = 64 * 1024;

// EmbeddedDriverPayload describes the immutable bytes loaded from the EXE
// resource table. Inputs are provided by loadEmbeddedDriverPayload; processing
// keeps only a pointer/size view owned by the module; there is no destructor work
// because Win32 owns the mapped resource for the lifetime of the process.
struct EmbeddedDriverPayload {
    const std::uint8_t* bytes = nullptr;
    DWORD size = 0;
};

// loadEmbeddedDriverPayload locates the RCDATA driver payload in this module.
// There is no input; processing calls FindResource/LoadResource/LockResource;
// output is true with a valid byte view, or false with a user-facing error.
bool loadEmbeddedDriverPayload(EmbeddedDriverPayload& payload, std::wstring& error) {
    payload = {};
    error.clear();

    HMODULE module = ::GetModuleHandleW(nullptr);
    if (!module) {
        error = L"GetModuleHandleW failed: " + lastErrorMessage();
        return false;
    }

    HRSRC resource = ::FindResourceW(module, MAKEINTRESOURCEW(IDR_KSWORDARKLIGHT_DRIVER_SYS), RT_RCDATA);
    if (!resource) {
        error = L"FindResourceW(IDR_KSWORDARKLIGHT_DRIVER_SYS) failed: " + lastErrorMessage();
        return false;
    }

    const DWORD kSize = ::SizeofResource(module, resource);
    if (kSize == 0) {
        error = L"Embedded KswordARK.sys resource is empty.";
        return false;
    }

    HGLOBAL loaded = ::LoadResource(module, resource);
    if (!loaded) {
        error = L"LoadResource(IDR_KSWORDARKLIGHT_DRIVER_SYS) failed: " + lastErrorMessage();
        return false;
    }

    const void* bytes = ::LockResource(loaded);
    if (!bytes) {
        error = L"LockResource(IDR_KSWORDARKLIGHT_DRIVER_SYS) returned no data.";
        return false;
    }

    payload.bytes = static_cast<const std::uint8_t*>(bytes);
    payload.size = kSize;
    return true;
}

// embeddedDriverPayloadAvailable checks whether the EXE carries the driver
// resource. There is no input; processing performs the same resource lookup used
// by extraction; output is a boolean for status text only.
bool embeddedDriverPayloadAvailable() {
    EmbeddedDriverPayload payload;
    std::wstring ignoredError;
    return loadEmbeddedDriverPayload(payload, ignoredError);
}

// existingDriverMatchesPayload compares the on-disk driver with the embedded
// resource without rewriting it. Inputs are the path and payload view; processing
// reads the file in bounded chunks; output is true when comparison succeeded and
// writes the equality result to matches.
bool existingDriverMatchesPayload(
    const std::wstring& path,
    const EmbeddedDriverPayload& payload,
    bool& matches,
    std::wstring& error) {
    matches = false;
    error.clear();

    UniqueHandle file(::CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!file.valid()) {
        error = L"CreateFileW for existing driver failed: " + lastErrorMessage();
        return false;
    }

    LARGE_INTEGER fileSize{};
    if (!::GetFileSizeEx(file.get(), &fileSize)) {
        error = L"GetFileSizeEx for existing driver failed: " + lastErrorMessage();
        return false;
    }
    if (fileSize.QuadPart != static_cast<LONGLONG>(payload.size)) {
        return true;
    }

    std::vector<std::uint8_t> buffer(kDriverIoChunkBytes);
    DWORD offset = 0;
    while (offset < payload.size) {
        const DWORD kExpected = std::min<DWORD>(payload.size - offset, kDriverIoChunkBytes);
        DWORD read = 0;
        if (!::ReadFile(file.get(), buffer.data(), kExpected, &read, nullptr)) {
            error = L"ReadFile for existing driver failed: " + lastErrorMessage();
            return false;
        }
        if (read != kExpected) {
            return true;
        }
        if (std::memcmp(buffer.data(), payload.bytes + offset, read) != 0) {
            return true;
        }
        offset += read;
    }

    matches = true;
    return true;
}

// writePayloadAtomically writes the embedded driver to disk through a temporary
// file. Inputs are the target path and payload; processing writes all bytes,
// flushes them, and replaces the final file with MoveFileEx; output is true only
// after the final path contains the embedded bytes.
bool writePayloadAtomically(
    const std::wstring& targetPath,
    const EmbeddedDriverPayload& payload,
    std::wstring& error) {
    error.clear();

    const std::wstring kTempPath = targetPath + L".embedded.tmp";
    ::DeleteFileW(kTempPath.c_str());

    UniqueHandle file(::CreateFileW(
        kTempPath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!file.valid()) {
        error = L"CreateFileW for temporary embedded driver failed: " + lastErrorMessage();
        return false;
    }

    DWORD offset = 0;
    while (offset < payload.size) {
        const DWORD kChunkBytes = std::min<DWORD>(payload.size - offset, kDriverIoChunkBytes);
        DWORD written = 0;
        if (!::WriteFile(file.get(), payload.bytes + offset, kChunkBytes, &written, nullptr)) {
            const DWORD kWriteError = ::GetLastError();
            file.reset();
            ::DeleteFileW(kTempPath.c_str());
            error = L"WriteFile for temporary embedded driver failed: " + lastErrorMessage(kWriteError);
            return false;
        }
        if (written == 0) {
            file.reset();
            ::DeleteFileW(kTempPath.c_str());
            error = L"WriteFile for temporary embedded driver wrote zero bytes.";
            return false;
        }
        offset += written;
    }

    if (!::FlushFileBuffers(file.get())) {
        const DWORD kFlushError = ::GetLastError();
        file.reset();
        ::DeleteFileW(kTempPath.c_str());
        error = L"FlushFileBuffers for temporary embedded driver failed: " + lastErrorMessage(kFlushError);
        return false;
    }
    file.reset();

    if (!::MoveFileExW(kTempPath.c_str(), targetPath.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH)) {
        const DWORD kMoveError = ::GetLastError();
        ::DeleteFileW(kTempPath.c_str());
        error = L"MoveFileExW failed while installing embedded driver payload: " + lastErrorMessage(kMoveError);
        return false;
    }

    return true;
}

// ensureDriverFileFromEmbeddedResource makes KswordARK.sys available beside the
// executable. Input is the final service ImagePath; processing compares any
// existing file with the embedded resource and rewrites only when bytes differ;
// output is true when the final file can be used by SCM.
bool ensureDriverFileFromEmbeddedResource(const std::wstring& driverPath, std::wstring& note, std::wstring& error) {
    note.clear();
    error.clear();
    if (driverPath.empty()) {
        error = L"driver output path is empty.";
        return false;
    }

    EmbeddedDriverPayload payload;
    std::wstring loadError;
    if (!loadEmbeddedDriverPayload(payload, loadError)) {
        if (fileExists(driverPath)) {
            return true;
        }
        error = loadError;
        return false;
    }

    if (fileExists(driverPath)) {
        bool matches = false;
        std::wstring compareError;
        if (!existingDriverMatchesPayload(driverPath, payload, matches, compareError)) {
            error = compareError;
            return false;
        }
        if (matches) {
            return true;
        }
    }

    std::wstring writeError;
    if (!writePayloadAtomically(driverPath, payload, writeError)) {
        error = writeError;
        return false;
    }

    note = L"Embedded KswordARK.sys was written beside the executable.";
    return true;
}

// UniqueServiceHandle owns an SCM handle. Inputs are SC_HANDLE values returned
// by service APIs; processing calls CloseServiceHandle on reset/destruction;
// get() returns the raw handle without transferring ownership.
class UniqueServiceHandle final : public NonCopyable {
public:
    UniqueServiceHandle() noexcept : handle_(nullptr) {}
    explicit UniqueServiceHandle(SC_HANDLE handle) noexcept : handle_(handle) {}
    ~UniqueServiceHandle() { reset(); }

    UniqueServiceHandle(UniqueServiceHandle&& other) noexcept : handle_(other.release()) {}
    UniqueServiceHandle& operator=(UniqueServiceHandle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    void reset(SC_HANDLE handle = nullptr) noexcept {
        if (handle_) {
            ::CloseServiceHandle(handle_);
        }
        handle_ = handle;
    }

    SC_HANDLE release() noexcept {
        SC_HANDLE out = handle_;
        handle_ = nullptr;
        return out;
    }

    SC_HANDLE get() const noexcept { return handle_; }
    bool valid() const noexcept { return handle_ != nullptr; }

private:
    SC_HANDLE handle_;
};

// OpenScm opens the service-control manager. Input is requested access;
// processing calls OpenSCManagerW; output is an owning handle or an invalid one.
UniqueServiceHandle openScm(DWORD access) {
    return UniqueServiceHandle(::OpenSCManagerW(nullptr, nullptr, access));
}

// openDriverService opens the KswordARK kernel service. Inputs are an SCM handle
// and desired access; processing calls OpenServiceW; output is an owning handle.
UniqueServiceHandle openDriverService(SC_HANDLE scm, DWORD access) {
    if (!scm) {
        return UniqueServiceHandle();
    }
    return UniqueServiceHandle(::OpenServiceW(scm, kDriverServiceName, access));
}

// fillServiceState copies QueryServiceStatusEx output into the UI state. Inputs
// are a service handle and mutable status; processing tolerates query failure;
// there is no return value because the caller already knows if the service opens.
void fillServiceState(SC_HANDLE service, DriverRuntimeStatus& status) {
    SERVICE_STATUS_PROCESS processStatus{};
    DWORD needed = 0;
    if (::QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&processStatus), sizeof(processStatus), &needed)) {
        status.serviceState = processStatus.dwCurrentState;
        status.serviceRunning = processStatus.dwCurrentState == SERVICE_RUNNING;
    }
}

// probeControlDevice verifies the runtime control path used by every feature
// module. Inputs are the status object already filled from SCM; processing opens
// the shared ArkDriverClient handle instead of touching CreateFileW directly;
// no value is returned because fields are written into status.
void probeControlDevice(DriverRuntimeStatus& status) {
    const ksword::ark::DriverClient kClient;
    ksword::ark::DriverHandle handle = kClient.open(GENERIC_READ | GENERIC_WRITE);
    status.controlDeviceOpen = handle.isValid();
    status.controlDeviceError = status.controlDeviceOpen ? ERROR_SUCCESS : ::GetLastError();
}

// appendControlDeviceMessage adds the control-device state to the user-facing
// status text. Input is a partially formatted message and the runtime status;
// output is the combined message shown in the status bar and message boxes.
std::wstring appendControlDeviceMessage(std::wstring message, const DriverRuntimeStatus& status) {
    if (status.controlDeviceOpen) {
        if (!message.empty()) {
            message += L" ";
        }
        message += L"Control device is open.";
        return message;
    }

    if (!message.empty()) {
        message += L" ";
    }
    message += L"Control device unavailable: " + lastErrorMessage(status.controlDeviceError);
    return message;
}
} // namespace

std::wstring resolveDriverPath() {
    return joinPath(moduleDirectory(), kDriverFileName);
}

DriverRuntimeStatus queryDriverStatus() {
    DriverRuntimeStatus status;
    status.driverPath = resolveDriverPath();
    status.driverFilePresent = fileExists(status.driverPath);

    UniqueServiceHandle scm = openScm(SC_MANAGER_CONNECT);
    if (!scm.valid()) {
        status.message = L"SCM unavailable: " + lastErrorMessage();
        probeControlDevice(status);
        status.message = appendControlDeviceMessage(status.message, status);
        return status;
    }

    UniqueServiceHandle service = openDriverService(scm.get(), SERVICE_QUERY_STATUS);
    if (!service.valid()) {
        status.message = status.driverFilePresent
            ? L"Driver file found; service is not installed."
            : (embeddedDriverPayloadAvailable()
                ? L"KswordARK.sys is embedded in this executable and will be written beside the executable during installation."
                : L"KswordARK.sys not found beside the executable.");
        probeControlDevice(status);
        status.message = appendControlDeviceMessage(status.message, status);
        return status;
    }

    status.serviceInstalled = true;
    fillServiceState(service.get(), status);
    probeControlDevice(status);
    status.message = status.serviceRunning ? L"R0 driver service is running." : L"R0 driver service is installed but stopped.";
    status.message = appendControlDeviceMessage(status.message, status);
    return status;
}

DriverRuntimeStatus installAndStartDriver() {
    DriverRuntimeStatus status = queryDriverStatus();
    std::wstring driverPreparationNote;
    std::wstring driverPreparationError;
    // The running-driver case deliberately avoids replacing an already loaded
    // image. Inputs are the status flags from queryDriverStatus; processing only
    // materializes the embedded payload when start/install still needs a file;
    // there is no return value because errors are folded into status.message.
    if ((!status.serviceRunning || !status.driverFilePresent)
        && !ensureDriverFileFromEmbeddedResource(status.driverPath, driverPreparationNote, driverPreparationError)) {
        status.driverFilePresent = fileExists(status.driverPath);
        status.message = L"Cannot prepare R0 driver file from embedded resource: " + driverPreparationError;
        return status;
    }
    status.driverFilePresent = fileExists(status.driverPath);
    if (!status.driverFilePresent) {
        status.message = L"Cannot install R0 driver because KswordARK.sys was not found: " + status.driverPath;
        return status;
    }

    UniqueServiceHandle scm = openScm(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm.valid()) {
        status.message = L"OpenSCManager failed: " + lastErrorMessage();
        return status;
    }

    UniqueServiceHandle service = openDriverService(scm.get(), SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG);
    if (!service.valid()) {
        SC_HANDLE created = ::CreateServiceW(
            scm.get(),
            kDriverServiceName,
            kDriverDisplayName,
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            status.driverPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);
        if (!created) {
            status.message = L"CreateService failed: " + lastErrorMessage();
            return status;
        }
        service.reset(created);
    } else {
        ::ChangeServiceConfigW(
            service.get(),
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            status.driverPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            kDriverDisplayName);
    }

    status.serviceInstalled = true;
    fillServiceState(service.get(), status);
    if (!status.serviceRunning) {
        if (!::StartServiceW(service.get(), 0, nullptr)) {
            const DWORD kErr = ::GetLastError();
            if (kErr != ERROR_SERVICE_ALREADY_RUNNING) {
                status.message = L"StartService failed: " + lastErrorMessage(kErr);
                fillServiceState(service.get(), status);
                return status;
            }
        }
    }

    fillServiceState(service.get(), status);
    probeControlDevice(status);
    status.message = status.serviceRunning ? L"R0 driver installed and running." : L"R0 driver installed; start state is pending or stopped.";
    if (!driverPreparationNote.empty()) {
        status.message = driverPreparationNote + L" " + status.message;
    }
    status.message = appendControlDeviceMessage(status.message, status);
    return status;
}

DriverRuntimeStatus stopDriverService() {
    DriverRuntimeStatus status = queryDriverStatus();
    UniqueServiceHandle scm = openScm(SC_MANAGER_CONNECT);
    if (!scm.valid()) {
        status.message = L"OpenSCManager failed: " + lastErrorMessage();
        return status;
    }
    UniqueServiceHandle service = openDriverService(scm.get(), SERVICE_QUERY_STATUS | SERVICE_STOP);
    if (!service.valid()) {
        status.message = L"R0 driver service is not installed.";
        return status;
    }
    SERVICE_STATUS serviceStatus{};
    if (!::ControlService(service.get(), SERVICE_CONTROL_STOP, &serviceStatus)) {
        const DWORD kErr = ::GetLastError();
        if (kErr != ERROR_SERVICE_NOT_ACTIVE) {
            status.message = L"ControlService stop failed: " + lastErrorMessage(kErr);
            return status;
        }
    }
    fillServiceState(service.get(), status);
    probeControlDevice(status);
    status.message = status.serviceRunning ? L"R0 driver stop requested." : L"R0 driver service is stopped.";
    status.message = appendControlDeviceMessage(status.message, status);
    return status;
}

} // namespace Ksword::Core
