#pragma once

// ============================================================
// ProcessImageDeleteGuard.h
// Purpose:
// 1) Before terminating the process, verify the same process instance using PID creation time and the real-time image path;
// 2) Hold the DELETE handle for the target image file to bind subsequent deletions to the same file object.
// 3) Fail and close unconditionally when the path is replaced, the PID is reused, or the file identity cannot be verified.
// ============================================================

#include <cstdint>
#include <string>

namespace ks::process
{
    // CapturedProcessImageDeleteTarget: Precise file object deletion credentials that can only be moved.
    class CapturedProcessImageDeleteTarget final
    {
    public:
        CapturedProcessImageDeleteTarget() = default;
        ~CapturedProcessImageDeleteTarget();

        CapturedProcessImageDeleteTarget(const CapturedProcessImageDeleteTarget&) = delete;
        CapturedProcessImageDeleteTarget& operator=(const CapturedProcessImageDeleteTarget&) = delete;
        CapturedProcessImageDeleteTarget(CapturedProcessImageDeleteTarget&& other) noexcept;
        CapturedProcessImageDeleteTarget& operator=(CapturedProcessImageDeleteTarget&& other) noexcept;

        bool valid() const noexcept;
        const std::wstring& finalPath() const noexcept;
        std::uint64_t fileIdentity() const noexcept;
        std::uint32_t volumeSerialNumber() const noexcept;

    private:
        friend bool captureProcessImageDeleteTarget(
            std::uint32_t,
            std::uint64_t,
            const std::wstring&,
            CapturedProcessImageDeleteTarget*,
            std::string*);
        friend bool deleteCapturedProcessImage(
            CapturedProcessImageDeleteTarget*,
            std::string*);

        void close() noexcept;

        void* fileHandle_ = nullptr;
        std::wstring finalPath_;
        std::uint64_t fileIdentity_ = 0;
        std::uint32_t volumeSerialNumber_ = 0;
    };

    // captureProcessImageDeleteTarget: Locks the file object of the live process image before the termination action.
    bool captureProcessImageDeleteTarget(
        std::uint32_t processId,
        std::uint64_t expectedCreationTime100ns,
        const std::wstring& expectedImagePath,
        CapturedProcessImageDeleteTarget* targetOut,
        std::string* detailTextOut = nullptr);

    // deleteCapturedProcessImage: Sets the deletion status only for the same locked file object.
    bool deleteCapturedProcessImage(
        CapturedProcessImageDeleteTarget* target,
        std::string* detailTextOut = nullptr);
}
