#include "../../shared/platform/scanner/AtomicFilePatch.h"
#include "../../shared/platform/scanner/BinaryScanner.h"

// ============================================================
// tools/scanner_tests/scanner_self_test.cpp
// Purpose:
// - Exercise a real KSword PE plus synthetic cross-endian ELF/Mach-O inputs.
// - Exercise ISO9660 traversal and EXIT/GhostSystemDriver attack-path rules.
// - Verify recognized malformed files fail without an out-of-bounds walk.
// - Verify atomic patch backup, compare-before-write, and range rejection.
//
// The test has no framework dependency and returns nonzero on any failure.
// Pass a current KSword executable path as argv[1].
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cwchar>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
    int gFailureCount = 0;

    void expect(const bool condition, const char* message)
    {
        if (condition)
        {
            std::cout << "[PASS] " << message << '\n';
            return;
        }
        ++gFailureCount;
        std::cerr << "[FAIL] " << message << '\n';
    }

    void put16(
        std::vector<std::uint8_t>& bytes,
        const std::size_t offset,
        const std::uint16_t value,
        const ks::scanner::ByteOrder byteOrder)
    {
        if (byteOrder == ks::scanner::ByteOrder::kLittleEndian)
        {
            bytes[offset] = static_cast<std::uint8_t>(value);
            bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8U);
        }
        else
        {
            bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
            bytes[offset + 1] = static_cast<std::uint8_t>(value);
        }
    }

    void put32(
        std::vector<std::uint8_t>& bytes,
        const std::size_t offset,
        const std::uint32_t value,
        const ks::scanner::ByteOrder byteOrder)
    {
        for (std::size_t index = 0; index < 4; ++index)
        {
            const std::size_t kShiftIndex =
                byteOrder == ks::scanner::ByteOrder::kLittleEndian
                    ? index
                    : 3U - index;
            bytes[offset + index] =
                static_cast<std::uint8_t>(value >> (kShiftIndex * 8U));
        }
    }

    void put64(
        std::vector<std::uint8_t>& bytes,
        const std::size_t offset,
        const std::uint64_t value,
        const ks::scanner::ByteOrder byteOrder)
    {
        for (std::size_t index = 0; index < 8; ++index)
        {
            const std::size_t kShiftIndex =
                byteOrder == ks::scanner::ByteOrder::kLittleEndian
                    ? index
                    : 7U - index;
            bytes[offset + index] =
                static_cast<std::uint8_t>(value >> (kShiftIndex * 8U));
        }
    }

    // putBoth16/putBoth32: Generate little-endian/big-endian paired fields required by ISO9660.
    void putBoth16(
        std::vector<std::uint8_t>& bytes,
        const std::size_t offset,
        const std::uint16_t value)
    {
        put16(bytes, offset, value, ks::scanner::ByteOrder::kLittleEndian);
        put16(bytes, offset + 2U, value, ks::scanner::ByteOrder::kBigEndian);
    }

    void putBoth32(
        std::vector<std::uint8_t>& bytes,
        const std::size_t offset,
        const std::uint32_t value)
    {
        put32(bytes, offset, value, ks::scanner::ByteOrder::kLittleEndian);
        put32(bytes, offset + 4U, value, ks::scanner::ByteOrder::kBigEndian);
    }

    std::string base64Encode(const std::span<const std::uint8_t> input)
    {
        static constexpr char kAlphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string output;
        output.reserve(((input.size() + 2U) / 3U) * 4U);
        for (std::size_t offset = 0; offset < input.size(); offset += 3U)
        {
            const std::size_t kRemaining = input.size() - offset;
            const std::uint32_t kValue =
                (static_cast<std::uint32_t>(input[offset]) << 16U) |
                (kRemaining > 1U
                    ? static_cast<std::uint32_t>(input[offset + 1U]) << 8U
                    : 0U) |
                (kRemaining > 2U
                    ? static_cast<std::uint32_t>(input[offset + 2U])
                    : 0U);
            output.push_back(kAlphabet[(kValue >> 18U) & 0x3FU]);
            output.push_back(kAlphabet[(kValue >> 12U) & 0x3FU]);
            output.push_back(kRemaining > 1U ? kAlphabet[(kValue >> 6U) & 0x3FU] : '=');
            output.push_back(kRemaining > 2U ? kAlphabet[kValue & 0x3FU] : '=');
        }
        return output;
    }

    std::string hexEncode(const std::span<const std::uint8_t> input)
    {
        static constexpr char kDigits[] = "0123456789ABCDEF";
        std::string output;
        output.reserve(input.size() * 2U);
        for (const std::uint8_t kByte : input)
        {
            output.push_back(kDigits[kByte >> 4U]);
            output.push_back(kDigits[kByte & 0x0FU]);
        }
        return output;
    }

    // makeMinimalPeWithStrings generates only a PE shell for static rule reading, containing no executable code.
    std::vector<std::uint8_t> makeMinimalPeWithStrings(
        const std::vector<std::string>& strings)
    {
        std::vector<std::uint8_t> bytes(0x100U, 0);
        bytes[0] = 'M';
        bytes[1] = 'Z';
        put32(bytes, 0x3CU, 0x80U, ks::scanner::ByteOrder::kLittleEndian);
        bytes[0x80U] = 'P';
        bytes[0x81U] = 'E';
        for (const std::string& value : strings)
        {
            bytes.insert(bytes.end(), value.begin(), value.end());
            bytes.push_back(0);
        }
        return bytes;
    }

    std::vector<std::uint8_t> makeSyntheticAttackProxy()
    {
        std::vector<std::uint8_t> driver = makeMinimalPeWithStrings({
            "TamperProtection", "DisableRealtimeMonitoring", "WdFilter",
            "WdBoot", "WinDefend", "ZwSetValueKey", "MsMpEng.exe",
            "NisSrv.exe", "360tray.exe", "ZwTerminateProcess",
            "ZwUnloadDriver", "\\Registry\\Machine\\SOFTWARE\\360"
        });
        driver.resize(4096U, 0);
        const std::string kHexLayer = hexEncode(driver);
        const std::string kSecondLayer = base64Encode(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(kHexLayer.data()),
                kHexLayer.size()));
        const std::string kFirstLayer = base64Encode(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(kSecondLayer.data()),
                kSecondLayer.size()));

        std::vector<std::uint8_t> proxy = makeMinimalPeWithStrings({
            "cef_execute_process", "cef_initialize", "cef_shutdown",
            "Elevation:Administrator!new:",
            "3E5FC7F9-9A51-4367-9063-A120244FBEC7",
            "CoGetObject", "CheckTokenMembership", "explorer.exe",
            "NtQueryInformationProcess", "ReadProcessMemory", "GhostSystemDriver",
            "CreateServiceW", "StartServiceW", "avp.exe"
        });
        // The outer string of the real sample is UTF-16LE; the test maintains the same encoding and exceeds the minimum length threshold.
        for (const char kCharacter : kFirstLayer)
        {
            proxy.push_back(static_cast<std::uint8_t>(kCharacter));
            proxy.push_back(0);
        }
        return proxy;
    }

    std::vector<std::uint8_t> makeElf(
        const bool is64,
        const ks::scanner::ByteOrder byteOrder)
    {
        const std::size_t kHeaderSize = is64 ? 64U : 52U;
        std::vector<std::uint8_t> bytes(kHeaderSize, 0);
        bytes[0] = 0x7F;
        bytes[1] = 'E';
        bytes[2] = 'L';
        bytes[3] = 'F';
        bytes[4] = is64 ? 2 : 1;
        bytes[5] = byteOrder == ks::scanner::ByteOrder::kLittleEndian ? 1 : 2;
        bytes[6] = 1;
        bytes[7] = 0;
        put16(bytes, 16, 2, byteOrder);
        put16(bytes, 18, is64 ? 62 : 3, byteOrder);
        put32(bytes, 20, 1, byteOrder);
        if (is64)
        {
            put64(bytes, 24, 0x401000, byteOrder);
            put64(bytes, 32, 0, byteOrder);
            put64(bytes, 40, 0, byteOrder);
            put32(bytes, 48, 0, byteOrder);
            put16(bytes, 52, 64, byteOrder);
            put16(bytes, 54, 56, byteOrder);
            put16(bytes, 56, 0, byteOrder);
            put16(bytes, 58, 64, byteOrder);
            put16(bytes, 60, 0, byteOrder);
            put16(bytes, 62, 0, byteOrder);
        }
        else
        {
            put32(bytes, 24, 0x8048000, byteOrder);
            put32(bytes, 28, 0, byteOrder);
            put32(bytes, 32, 0, byteOrder);
            put32(bytes, 36, 0, byteOrder);
            put16(bytes, 40, 52, byteOrder);
            put16(bytes, 42, 32, byteOrder);
            put16(bytes, 44, 0, byteOrder);
            put16(bytes, 46, 40, byteOrder);
            put16(bytes, 48, 0, byteOrder);
            put16(bytes, 50, 0, byteOrder);
        }
        return bytes;
    }

    std::vector<std::uint8_t> makeMachO(
        const bool is64,
        const ks::scanner::ByteOrder byteOrder)
    {
        std::vector<std::uint8_t> bytes(is64 ? 32U : 28U, 0);
        if (is64 && byteOrder == ks::scanner::ByteOrder::kLittleEndian)
        {
            bytes[0] = 0xCF; bytes[1] = 0xFA; bytes[2] = 0xED; bytes[3] = 0xFE;
        }
        else if (is64)
        {
            bytes[0] = 0xFE; bytes[1] = 0xED; bytes[2] = 0xFA; bytes[3] = 0xCF;
        }
        else if (byteOrder == ks::scanner::ByteOrder::kLittleEndian)
        {
            bytes[0] = 0xCE; bytes[1] = 0xFA; bytes[2] = 0xED; bytes[3] = 0xFE;
        }
        else
        {
            bytes[0] = 0xFE; bytes[1] = 0xED; bytes[2] = 0xFA; bytes[3] = 0xCE;
        }
        put32(bytes, 4, is64 ? 0x01000007U : 7U, byteOrder);
        put32(bytes, 8, 3, byteOrder);
        put32(bytes, 12, 2, byteOrder);
        put32(bytes, 16, 0, byteOrder);
        put32(bytes, 20, 0, byteOrder);
        put32(bytes, 24, 0, byteOrder);
        if (is64)
        {
            put32(bytes, 28, 0, byteOrder);
        }
        return bytes;
    }

    std::vector<std::uint8_t> makeUniversalMachO()
    {
        constexpr std::size_t kFirstSliceOffset = 0x80;
        constexpr std::size_t kSecondSliceOffset = 0xC0;
        const std::vector<std::uint8_t> kFirstSlice =
            makeMachO(false, ks::scanner::ByteOrder::kLittleEndian);
        const std::vector<std::uint8_t> kSecondSlice =
            makeMachO(true, ks::scanner::ByteOrder::kBigEndian);
        std::vector<std::uint8_t> bytes(
            kSecondSliceOffset + kSecondSlice.size(),
            0);
        bytes[0] = 0xCA;
        bytes[1] = 0xFE;
        bytes[2] = 0xBA;
        bytes[3] = 0xBE;
        put32(bytes, 4, 2, ks::scanner::ByteOrder::kBigEndian);

        put32(bytes, 8, 7, ks::scanner::ByteOrder::kBigEndian);
        put32(bytes, 12, 3, ks::scanner::ByteOrder::kBigEndian);
        put32(bytes, 16, kFirstSliceOffset, ks::scanner::ByteOrder::kBigEndian);
        put32(bytes, 20, static_cast<std::uint32_t>(kFirstSlice.size()), ks::scanner::ByteOrder::kBigEndian);
        put32(bytes, 24, 2, ks::scanner::ByteOrder::kBigEndian);

        put32(bytes, 28, 0x01000007U, ks::scanner::ByteOrder::kBigEndian);
        put32(bytes, 32, 3, ks::scanner::ByteOrder::kBigEndian);
        put32(bytes, 36, kSecondSliceOffset, ks::scanner::ByteOrder::kBigEndian);
        put32(bytes, 40, static_cast<std::uint32_t>(kSecondSlice.size()), ks::scanner::ByteOrder::kBigEndian);
        put32(bytes, 44, 3, ks::scanner::ByteOrder::kBigEndian);

        std::copy(kFirstSlice.begin(), kFirstSlice.end(), bytes.begin() + kFirstSliceOffset);
        std::copy(kSecondSlice.begin(), kSecondSlice.end(), bytes.begin() + kSecondSliceOffset);
        return bytes;
    }

    // writeDirectoryRecord generates a single ISO9660 Level 1 directory record and returns the record length.
    std::size_t writeDirectoryRecord(
        std::vector<std::uint8_t>& image,
        const std::size_t offset,
        const std::uint32_t extent,
        const std::uint32_t dataSize,
        const std::uint8_t flags,
        const std::span<const std::uint8_t> identifier)
    {
        const std::size_t kPadding = (identifier.size() % 2U) == 0 ? 1U : 0U;
        const std::size_t kRecordLength = 33U + identifier.size() + kPadding;
        image[offset] = static_cast<std::uint8_t>(kRecordLength);
        image[offset + 1U] = 0;
        putBoth32(image, offset + 2U, extent);
        putBoth32(image, offset + 10U, dataSize);
        image[offset + 25U] = flags;
        putBoth16(image, offset + 28U, 1U);
        image[offset + 32U] = static_cast<std::uint8_t>(identifier.size());
        std::copy(identifier.begin(), identifier.end(), image.begin() + offset + 33U);
        return kRecordLength;
    }

    std::vector<std::uint8_t> makeIso9660(
        const std::string& fileName,
        const std::vector<std::uint8_t>& fileBytes)
    {
        constexpr std::size_t kBlockSize = 2048U;
        constexpr std::uint32_t kRootExtent = 20U;
        constexpr std::uint32_t kFileExtent = 21U;
        const std::size_t kFileBlocks = (fileBytes.size() + kBlockSize - 1U) / kBlockSize;
        const std::size_t kTotalBlocks = kFileExtent + std::max<std::size_t>(kFileBlocks, 1U);
        std::vector<std::uint8_t> image(kTotalBlocks * kBlockSize, 0);

        // Note: The primary volume descriptor only populates key fields required by the parser and ISO specifications.
        const std::size_t kDescriptor = 16U * kBlockSize;
        image[kDescriptor] = 1U;
        const std::string kSignature = "CD001";
        std::copy(kSignature.begin(), kSignature.end(), image.begin() + kDescriptor + 1U);
        image[kDescriptor + 6U] = 1U;
        const std::string kVolumeId = "KSWORD_TEST";
        std::fill(image.begin() + kDescriptor + 40U, image.begin() + kDescriptor + 72U, ' ');
        std::copy(kVolumeId.begin(), kVolumeId.end(), image.begin() + kDescriptor + 40U);
        putBoth32(image, kDescriptor + 80U, static_cast<std::uint32_t>(kTotalBlocks));
        putBoth16(image, kDescriptor + 120U, 1U);
        putBoth16(image, kDescriptor + 124U, 1U);
        putBoth16(image, kDescriptor + 128U, static_cast<std::uint16_t>(kBlockSize));

        const std::array<std::uint8_t, 1> kCurrentIdentifier{ 0U };
        writeDirectoryRecord(
            image,
            kDescriptor + 156U,
            kRootExtent,
            static_cast<std::uint32_t>(kBlockSize),
            0x02U,
            kCurrentIdentifier);
        const std::size_t kTerminator = 17U * kBlockSize;
        image[kTerminator] = 255U;
        std::copy(kSignature.begin(), kSignature.end(), image.begin() + kTerminator + 1U);
        image[kTerminator + 6U] = 1U;

        // The root directory contains records for the current directory, the parent directory, and one regular file.
        std::size_t recordOffset = kRootExtent * kBlockSize;
        recordOffset += writeDirectoryRecord(
            image,
            recordOffset,
            kRootExtent,
            static_cast<std::uint32_t>(kBlockSize),
            0x02U,
            kCurrentIdentifier);
        const std::array<std::uint8_t, 1> kParentIdentifier{ 1U };
        recordOffset += writeDirectoryRecord(
            image,
            recordOffset,
            kRootExtent,
            static_cast<std::uint32_t>(kBlockSize),
            0x02U,
            kParentIdentifier);
        const std::vector<std::uint8_t> kFileIdentifier(fileName.begin(), fileName.end());
        writeDirectoryRecord(
            image,
            recordOffset,
            kFileExtent,
            static_cast<std::uint32_t>(fileBytes.size()),
            0,
            kFileIdentifier);
        std::copy(fileBytes.begin(), fileBytes.end(), image.begin() + kFileExtent * kBlockSize);
        return image;
    }

    bool writeBytes(
        const std::wstring& path,
        const std::vector<std::uint8_t>& bytes)
    {
        HANDLE handle = ::CreateFileW(
            path.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        std::size_t writtenTotal = 0;
        while (writtenTotal < bytes.size())
        {
            const DWORD kRequested = static_cast<DWORD>(std::min<std::size_t>(
                bytes.size() - writtenTotal,
                1024U * 1024U));
            DWORD written = 0;
            if (::WriteFile(
                    handle,
                    bytes.data() + writtenTotal,
                    kRequested,
                    &written,
                    nullptr) == FALSE ||
                written == 0)
            {
                ::CloseHandle(handle);
                return false;
            }
            writtenTotal += written;
        }
        ::CloseHandle(handle);
        return true;
    }

    std::vector<std::uint8_t> readBytes(const std::wstring& path)
    {
        HANDLE handle = ::CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            return {};
        }
        LARGE_INTEGER size{};
        if (::GetFileSizeEx(handle, &size) == FALSE ||
            size.QuadPart < 0 ||
            static_cast<std::uint64_t>(size.QuadPart) >
                static_cast<std::uint64_t>(SIZE_MAX))
        {
            ::CloseHandle(handle);
            return {};
        }
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
        DWORD read = 0;
        const bool kSuccess = bytes.empty() ||
            (::ReadFile(
                handle,
                bytes.data(),
                static_cast<DWORD>(bytes.size()),
                &read,
                nullptr) != FALSE &&
             read == bytes.size());
        ::CloseHandle(handle);
        return kSuccess ? bytes : std::vector<std::uint8_t>{};
    }

    const ks::scanner::BinaryTable* findTable(
        const ks::scanner::BinaryScanResult& result,
        const std::string& id)
    {
        const auto kIterator = std::find_if(
            result.tables.begin(),
            result.tables.end(),
            [&id](const ks::scanner::BinaryTable& table)
            {
                return table.id == id;
            });
        return kIterator == result.tables.end() ? nullptr : &*kIterator;
    }

    bool hasAttackEvidence(
        const ks::scanner::BinaryScanResult& result,
        const std::string_view code)
    {
        return std::any_of(
            result.attackPath.evidence.begin(),
            result.attackPath.evidence.end(),
            [code](const ks::scanner::AttackPathEvidence& evidence)
            {
                return evidence.code == code;
            });
    }

    void scanSynthetic(
        const std::wstring& path,
        const std::vector<std::uint8_t>& bytes,
        const ks::scanner::BinaryFormat expectedFormat,
        const ks::scanner::ByteOrder expectedOrder,
        const char* label)
    {
        expect(writeBytes(path, bytes), "write synthetic input");
        const ks::scanner::BinaryScanResult kResult =
            ks::scanner::scanBinaryFile(path);
        expect(kResult.recognized, label);
        expect(kResult.success, "synthetic input parses successfully");
        expect(kResult.format == expectedFormat, "synthetic format classification");
        expect(kResult.byteOrder == expectedOrder, "synthetic byte-order classification");
        expect(findTable(kResult, "sections") != nullptr ||
            findTable(kResult, "slices") != nullptr,
            "synthetic result exposes sections or slices table");
    }

    std::wstring createTestDirectory()
    {
        wchar_t temporaryRoot[MAX_PATH] = {};
        if (::GetTempPathW(MAX_PATH, temporaryRoot) == 0)
        {
            return {};
        }
        const std::wstring kPath =
            std::wstring(temporaryRoot) +
            L"ksword-scanner-self-test-" +
            std::to_wstring(::GetCurrentProcessId()) +
            L"-" +
            std::to_wstring(::GetTickCount64());
        return ::CreateDirectoryW(kPath.c_str(), nullptr) != FALSE
            ? kPath
            : std::wstring();
    }
}

int wmain(const int argc, wchar_t** argv)
{
    // Unit buffering ensures the last completed synthetic assertion is retained even during rapid termination.
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    const std::wstring kTestDirectory = createTestDirectory();
    expect(!kTestDirectory.empty(), "create isolated test directory");
    if (kTestDirectory.empty())
    {
        return 1;
    }
    const auto kPathFor = [&kTestDirectory](const wchar_t* name)
    {
        return kTestDirectory + L"\\" + name;
    };

    if (argc >= 2)
    {
        const ks::scanner::BinaryScanResult kPe =
            ks::scanner::scanBinaryFile(argv[1]);
        expect(kPe.recognized, "current KSword executable recognized");
        expect(kPe.success, "current KSword executable parsed");
        expect(
            kPe.format == ks::scanner::BinaryFormat::kPe32Plus ||
                kPe.format == ks::scanner::BinaryFormat::kPe32,
            "current KSword executable classified as PE");
        expect(findTable(kPe, "sections") != nullptr, "PE exposes sections table");
        expect(findTable(kPe, "imports") != nullptr, "PE exposes imports table");
        expect(findTable(kPe, "exports") != nullptr, "PE exposes exports table");

        ks::scanner::ScanOptions boundedOptions{};
        boundedOptions.maxRowsPerTable = 1;
        const ks::scanner::BinaryScanResult kBoundedPe =
            ks::scanner::scanBinaryFile(argv[1], boundedOptions);
        const bool kEveryPeTableBounded = std::all_of(
            kBoundedPe.tables.begin(),
            kBoundedPe.tables.end(),
            [](const ks::scanner::BinaryTable& table)
            {
                return table.rows.size() <= 1;
            });
        expect(kBoundedPe.success && kEveryPeTableBounded, "per-table row limit is enforced");
    }
    else
    {
        ++gFailureCount;
        std::cerr << "[FAIL] pass a current KSword executable path as argv[1]\n";
    }

    scanSynthetic(
        kPathFor(L"elf32le.bin"),
        makeElf(false, ks::scanner::ByteOrder::kLittleEndian),
        ks::scanner::BinaryFormat::kElf32,
        ks::scanner::ByteOrder::kLittleEndian,
        "ELF32 little-endian recognized");
    scanSynthetic(
        kPathFor(L"elf32be.bin"),
        makeElf(false, ks::scanner::ByteOrder::kBigEndian),
        ks::scanner::BinaryFormat::kElf32,
        ks::scanner::ByteOrder::kBigEndian,
        "ELF32 big-endian recognized");
    scanSynthetic(
        kPathFor(L"elf64le.bin"),
        makeElf(true, ks::scanner::ByteOrder::kLittleEndian),
        ks::scanner::BinaryFormat::kElf64,
        ks::scanner::ByteOrder::kLittleEndian,
        "ELF64 little-endian recognized");
    scanSynthetic(
        kPathFor(L"elf64be.bin"),
        makeElf(true, ks::scanner::ByteOrder::kBigEndian),
        ks::scanner::BinaryFormat::kElf64,
        ks::scanner::ByteOrder::kBigEndian,
        "ELF64 big-endian recognized");

    scanSynthetic(
        kPathFor(L"macho32le.bin"),
        makeMachO(false, ks::scanner::ByteOrder::kLittleEndian),
        ks::scanner::BinaryFormat::kMachO32,
        ks::scanner::ByteOrder::kLittleEndian,
        "Mach-O 32 little-endian recognized");
    scanSynthetic(
        kPathFor(L"macho32be.bin"),
        makeMachO(false, ks::scanner::ByteOrder::kBigEndian),
        ks::scanner::BinaryFormat::kMachO32,
        ks::scanner::ByteOrder::kBigEndian,
        "Mach-O 32 big-endian recognized");
    scanSynthetic(
        kPathFor(L"macho64le.bin"),
        makeMachO(true, ks::scanner::ByteOrder::kLittleEndian),
        ks::scanner::BinaryFormat::kMachO64,
        ks::scanner::ByteOrder::kLittleEndian,
        "Mach-O 64 little-endian recognized");
    scanSynthetic(
        kPathFor(L"macho64be.bin"),
        makeMachO(true, ks::scanner::ByteOrder::kBigEndian),
        ks::scanner::BinaryFormat::kMachO64,
        ks::scanner::ByteOrder::kBigEndian,
        "Mach-O 64 big-endian recognized");
    scanSynthetic(
        kPathFor(L"universal.bin"),
        makeUniversalMachO(),
        ks::scanner::BinaryFormat::kMachOUniversal,
        ks::scanner::ByteOrder::kBigEndian,
        "Universal Mach-O recognized");
    const ks::scanner::BinaryScanResult kUniversal =
        ks::scanner::scanBinaryFile(kPathFor(L"universal.bin"));
    const ks::scanner::BinaryTable* slices = findTable(kUniversal, "slices");
    expect(slices != nullptr && slices->rows.size() == 2, "universal file lists both slices");

    // Synthetic ISO constructed using pure data; the test will not mount the image or invoke any PE bytes within it.
    const std::wstring kBenignIsoPath = kPathFor(L"benign.iso");
    const std::vector<std::uint8_t> kBenignIso = makeIso9660(
        "README.BIN;1",
        makeMinimalPeWithStrings({ "synthetic benign fixture" }));
    expect(writeBytes(kBenignIsoPath, kBenignIso), "write benign synthetic ISO9660");
    const ks::scanner::BinaryScanResult kBenignIsoResult =
        ks::scanner::scanBinaryFile(kBenignIsoPath);
    expect(kBenignIsoResult.success, "synthetic ISO9660 parses successfully");
    expect(
        kBenignIsoResult.format == ks::scanner::BinaryFormat::kIso9660,
        "synthetic ISO9660 format classified");
    expect(
        findTable(kBenignIsoResult, "container_entries") != nullptr,
        "synthetic ISO9660 exposes container entries");
    expect(!kBenignIsoResult.attackPath.matched, "benign ISO9660 stays below attack threshold");

    const std::wstring kAttackIsoPath = kPathFor(L"attack-path.iso");
    const std::vector<std::uint8_t> kAttackIso = makeIso9660(
        "LIBCEF.DLL;1",
        makeSyntheticAttackProxy());
    expect(writeBytes(kAttackIsoPath, kAttackIso), "write synthetic attack-path ISO9660");
    const ks::scanner::BinaryScanResult kAttackIsoResult =
        ks::scanner::scanBinaryFile(kAttackIsoPath);
    expect(kAttackIsoResult.success, "attack-path ISO9660 parses successfully");
    expect(kAttackIsoResult.attackPath.matched, "EXIT/GhostSystemDriver attack path detected");
    expect(
        hasAttackEvidence(kAttackIsoResult, "proxy.cmstplua_uac"),
        "CMSTPLUA elevation evidence reported");
    expect(
        hasAttackEvidence(kAttackIsoResult, "embedded.double_base64_driver"),
        "double-Base64 embedded driver evidence reported");
    expect(
        hasAttackEvidence(kAttackIsoResult, "driver.defender_registry") &&
            hasAttackEvidence(kAttackIsoResult, "driver.security_process_kill"),
        "decoded driver defense-impairment evidence reported");

    std::vector<std::uint8_t> malformedIso = kBenignIso;
    constexpr std::size_t kRootExtentBigEndian = 16U * 2048U + 156U + 6U;
    malformedIso[kRootExtentBigEndian] ^= 0x01U;
    const std::wstring kMalformedIsoPath = kPathFor(L"malformed.iso");
    expect(writeBytes(kMalformedIsoPath, malformedIso), "write malformed ISO9660");
    const ks::scanner::BinaryScanResult kMalformedIsoResult =
        ks::scanner::scanBinaryFile(kMalformedIsoPath);
    expect(
        kMalformedIsoResult.recognized && !kMalformedIsoResult.success,
        "mismatched ISO9660 both-endian extent rejected safely");

    const std::wstring kTruncatedElfPath = kPathFor(L"truncated-elf.bin");
    writeBytes(kTruncatedElfPath, { 0x7F, 'E', 'L', 'F', 2, 1 });
    const ks::scanner::BinaryScanResult kTruncatedElf =
        ks::scanner::scanBinaryFile(kTruncatedElfPath);
    expect(kTruncatedElf.recognized && !kTruncatedElf.success, "truncated ELF rejected safely");

    const std::wstring kTruncatedMachPath = kPathFor(L"truncated-macho.bin");
    writeBytes(kTruncatedMachPath, { 0xCF, 0xFA, 0xED, 0xFE });
    const ks::scanner::BinaryScanResult kTruncatedMach =
        ks::scanner::scanBinaryFile(kTruncatedMachPath);
    expect(kTruncatedMach.recognized && !kTruncatedMach.success, "truncated Mach-O rejected safely");

    const std::wstring kTruncatedPePath = kPathFor(L"truncated-pe.bin");
    writeBytes(kTruncatedPePath, { 'M', 'Z' });
    const ks::scanner::BinaryScanResult kTruncatedPe =
        ks::scanner::scanBinaryFile(kTruncatedPePath);
    expect(kTruncatedPe.recognized && !kTruncatedPe.success, "truncated PE rejected safely");

    std::vector<std::uint8_t> excessiveElf =
        makeElf(true, ks::scanner::ByteOrder::kLittleEndian);
    put16(excessiveElf, 56, 0xFFFF, ks::scanner::ByteOrder::kLittleEndian);
    const std::wstring kExcessiveElfPath = kPathFor(L"excessive-elf.bin");
    writeBytes(kExcessiveElfPath, excessiveElf);
    const ks::scanner::BinaryScanResult kExcessiveElfResult =
        ks::scanner::scanBinaryFile(kExcessiveElfPath);
    expect(
        kExcessiveElfResult.recognized && !kExcessiveElfResult.success,
        "unresolvable ELF extended count rejected safely");

    std::vector<std::uint8_t> excessiveMach =
        makeMachO(true, ks::scanner::ByteOrder::kLittleEndian);
    put32(excessiveMach, 16, 0xFFFFFFFFU, ks::scanner::ByteOrder::kLittleEndian);
    const std::wstring kExcessiveMachPath = kPathFor(L"excessive-macho.bin");
    writeBytes(kExcessiveMachPath, excessiveMach);
    const ks::scanner::BinaryScanResult kExcessiveMachResult =
        ks::scanner::scanBinaryFile(kExcessiveMachPath);
    expect(
        kExcessiveMachResult.recognized && !kExcessiveMachResult.success,
        "excessive Mach-O command count rejected safely");

    if (argc >= 3 && std::wcscmp(argv[2], L"--attack-sample") != 0)
    {
        const ks::scanner::BinaryScanResult kRealElf =
            ks::scanner::scanBinaryFile(argv[2]);
        const ks::scanner::BinaryTable* programHeaders =
            findTable(kRealElf, "program_headers");
        const ks::scanner::BinaryTable* elfSections =
            findTable(kRealElf, "sections");
        const ks::scanner::BinaryTable* dependencies =
            findTable(kRealElf, "dynamic_dependencies");
        const ks::scanner::BinaryTable* symbols =
            findTable(kRealElf, "symbols");
        expect(kRealElf.success, "real ELF binary parses");
        expect(
            kRealElf.format == ks::scanner::BinaryFormat::kElf64 ||
                kRealElf.format == ks::scanner::BinaryFormat::kElf32,
            "real ELF format classified");
        expect(programHeaders != nullptr && !programHeaders->rows.empty(), "real ELF program headers populated");
        expect(elfSections != nullptr && !elfSections->rows.empty(), "real ELF sections populated");
        expect(dependencies != nullptr && !dependencies->rows.empty(), "real ELF dependencies populated");
        expect(symbols != nullptr && !symbols->rows.empty(), "real ELF symbols populated");
    }

    if (argc >= 4 &&
        std::wcscmp(argv[2], L"--attack-sample") != 0 &&
        std::wcscmp(argv[3], L"--attack-sample") != 0)
    {
        const ks::scanner::BinaryScanResult kRealMach =
            ks::scanner::scanBinaryFile(argv[3]);
        const ks::scanner::BinaryTable* commands =
            findTable(kRealMach, "load_commands");
        const ks::scanner::BinaryTable* machSections =
            findTable(kRealMach, "sections");
        const ks::scanner::BinaryTable* symbols =
            findTable(kRealMach, "symbols");
        const ks::scanner::BinaryTable* imports =
            findTable(kRealMach, "imports");
        const ks::scanner::BinaryTable* exports =
            findTable(kRealMach, "exports");
        expect(kRealMach.success, "real Mach-O object parses");
        expect(
            kRealMach.format == ks::scanner::BinaryFormat::kMachO64 ||
                kRealMach.format == ks::scanner::BinaryFormat::kMachO32,
            "real Mach-O format classified");
        expect(commands != nullptr && !commands->rows.empty(), "real Mach-O load commands populated");
        expect(machSections != nullptr && !machSections->rows.empty(), "real Mach-O sections populated");
        expect(symbols != nullptr && !symbols->rows.empty(), "real Mach-O symbols populated");
        expect(imports != nullptr && !imports->rows.empty(), "real Mach-O imports populated");
        expect(exports != nullptr && !exports->rows.empty(), "real Mach-O exports populated");
    }

    // Optional real sample path only enters scanBinaryFile; this branch does not ShellExecute, load, or mount the target.
    for (int argument = 2; argument + 1 < argc; ++argument)
    {
        if (std::wcscmp(argv[argument], L"--attack-sample") != 0)
        {
            continue;
        }
        const ks::scanner::BinaryScanResult kAttackSample =
            ks::scanner::scanBinaryFile(argv[argument + 1]);
        std::cout << "[INFO] attack sample format="
                  << ks::scanner::formatName(kAttackSample.format)
                  << " score=" << kAttackSample.attackPath.score
                  << " evidence=" << kAttackSample.attackPath.evidence.size()
                  << '\n';
        expect(kAttackSample.success, "external attack sample parses successfully");
        expect(
            kAttackSample.format == ks::scanner::BinaryFormat::kIso9660,
            "external attack sample classified as ISO9660");
        expect(kAttackSample.attackPath.matched, "external attack sample matches attack path");
        expect(
            hasAttackEvidence(kAttackSample, "container.libcef_sideload_pair"),
            "external attack sample contains libcef side-load pair");
        expect(
            hasAttackEvidence(kAttackSample, "driver.defender_registry"),
            "external attack sample contains decoded driver impairment evidence");
        break;
    }

    const std::wstring kPatchPath = kPathFor(L"patch-target.bin");
    const std::wstring kBackupPath = kPathFor(L"patch-target.backup.bin");
    const std::vector<std::uint8_t> kOriginal{ 0, 1, 2, 3, 4, 5, 6, 7 };
    expect(writeBytes(kPatchPath, kOriginal), "write atomic patch target");
    ks::scanner::AtomicPatchOptions patchOptions{};
    patchOptions.backupPath = kBackupPath;
    patchOptions.expectedBytes = { 2, 3 };
    const ks::scanner::AtomicPatchResult kPatch =
        ks::scanner::patchFileAtOffsetAtomic(
            kPatchPath,
            2,
            { 0xAA, 0xBB },
            patchOptions);
    expect(kPatch.success && kPatch.changed, "atomic patch commits");
    expect(
        readBytes(kPatchPath) == std::vector<std::uint8_t>({ 0, 1, 0xAA, 0xBB, 4, 5, 6, 7 }),
        "atomic patch modifies only selected range");
    expect(readBytes(kBackupPath) == kOriginal, "atomic patch preserves original backup");

    ks::scanner::AtomicPatchOptions noBackupOptions{};
    noBackupOptions.createBackup = false;
    noBackupOptions.expectedBytes = { 4, 5 };
    const ks::scanner::AtomicPatchResult kNoBackup =
        ks::scanner::patchFileAtOffsetAtomic(
            kPatchPath,
            4,
            { 0xCC, 0xDD },
            noBackupOptions);
    expect(kNoBackup.success && kNoBackup.changed, "ReplaceFileW commits with a null backup path");
    expect(
        readBytes(kPatchPath) == std::vector<std::uint8_t>({ 0, 1, 0xAA, 0xBB, 0xCC, 0xDD, 6, 7 }),
        "no-backup atomic patch preserves unrelated bytes");

    ks::scanner::AtomicPatchOptions staleOptions{};
    staleOptions.createBackup = false;
    staleOptions.expectedBytes = { 2, 3 };
    const ks::scanner::AtomicPatchResult kStale =
        ks::scanner::patchFileAtOffsetAtomic(
            kPatchPath,
            2,
            { 9, 9 },
            staleOptions);
    expect(!kStale.success && !kStale.changed, "compare-before-write rejects stale bytes");
    expect(
        readBytes(kPatchPath) == std::vector<std::uint8_t>({ 0, 1, 0xAA, 0xBB, 0xCC, 0xDD, 6, 7 }),
        "stale comparison leaves file unchanged");

    const ks::scanner::AtomicPatchResult kOutOfBounds =
        ks::scanner::patchFileAtOffsetAtomic(
            kPatchPath,
            7,
            { 1, 2 },
            staleOptions);
    expect(!kOutOfBounds.success, "out-of-bounds patch rejected");

    const std::wstring kLockedPath = kPathFor(L"locked-target.bin");
    const std::vector<std::uint8_t> kLockedOriginal{ 1, 2, 3, 4 };
    writeBytes(kLockedPath, kLockedOriginal);
    HANDLE competingWriter = ::CreateFileW(
        kLockedPath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    expect(competingWriter != INVALID_HANDLE_VALUE, "open competing writer");
    const ks::scanner::AtomicPatchResult kLockedPatch =
        ks::scanner::patchFileAtOffsetAtomic(
            kLockedPath,
            1,
            { 9 },
            staleOptions);
    expect(!kLockedPatch.success, "active competing writer blocks atomic patch");
    if (competingWriter != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(competingWriter);
    }
    expect(readBytes(kLockedPath) == kLockedOriginal, "writer conflict leaves target unchanged");

    const std::wstring kLinkPath = kPathFor(L"reparse-target-link.bin");
    const DWORD kSymbolicLinkFlags = 0x2U; // SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
    if (::CreateSymbolicLinkW(kLinkPath.c_str(), kPatchPath.c_str(), kSymbolicLinkFlags) != FALSE)
    {
        const std::vector<std::uint8_t> kBeforeLinkAttempt = readBytes(kPatchPath);
        const ks::scanner::AtomicPatchResult kLinkPatch =
            ks::scanner::patchFileAtOffsetAtomic(
                kLinkPath,
                0,
                { 9 },
                staleOptions);
        expect(!kLinkPatch.success, "reparse-point target rejected");
        expect(readBytes(kPatchPath) == kBeforeLinkAttempt, "reparse rejection leaves destination unchanged");
        ::DeleteFileW(kLinkPath.c_str());
    }
    else
    {
        std::cout << "[SKIP] symbolic-link creation unavailable; handle-level reparse check compiled\n";
    }

    const wchar_t* generatedFiles[] = {
        L"elf32le.bin", L"elf32be.bin", L"elf64le.bin", L"elf64be.bin",
        L"macho32le.bin", L"macho32be.bin", L"macho64le.bin", L"macho64be.bin",
        L"universal.bin", L"truncated-elf.bin", L"truncated-macho.bin",
        L"truncated-pe.bin", L"excessive-elf.bin", L"excessive-macho.bin",
        L"benign.iso", L"attack-path.iso", L"malformed.iso",
        L"patch-target.bin", L"patch-target.backup.bin", L"locked-target.bin"
    };
    for (const wchar_t* fileName : generatedFiles)
    {
        ::DeleteFileW(kPathFor(fileName).c_str());
    }
    ::RemoveDirectoryW(kTestDirectory.c_str());

    if (gFailureCount != 0)
    {
        std::cerr << gFailureCount << " scanner self-test assertion(s) failed.\n";
        return 1;
    }
    std::cout << "All scanner self-tests passed.\n";
    return 0;
}
