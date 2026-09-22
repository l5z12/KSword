// DisableDseBackend.cpp
// See DisableDseBackend.h for details. This file only handles location and R0 access, containing no UI.

#include "DisableDseBackend.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"

#include <windows.h>

#include <Zydis.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace
{
    // kSystemModuleInformationClass：
    // - Class number for SystemModuleInformation, used to enumerate kernel modules to obtain the base address of CI modules.
    constexpr unsigned long kSystemModuleInformationClass = 11UL;

    // kSystemCodeIntegrityInformationClass：
    // - Class number for SystemCodeIntegrityInformation; R3 fallback channel reads CodeIntegrityOptions.
    constexpr unsigned long kSystemCodeIntegrityInformationClass = 103UL;

    // kStatusInfoLengthMismatch：
    // - STATUS_INFO_LENGTH_MISMATCH: return value when the buffer is insufficient.
    constexpr long kStatusInfoLengthMismatch = static_cast<long>(0xC0000004L);

    // kFirstCiDllBuild：
    // - Starting from Win8 (build 9200), the DSE switch moved to CI.dll!g_CiOptions; earlier systems use nt!g_CiEnabled.
    constexpr std::uint32_t kFirstCiDllBuild = 9200U;

    // kCipInitializeCallBuild：
    // - Starting from build 16299, CiInitialize calls CipInitialize via a call instruction; earlier versions used a jump.
    constexpr std::uint32_t kCipInitializeCallBuild = 16299U;

    // kScanLimit：
    // - Upper limit of bytes for two disassembly scan segments; target instructions are located very close to the function start.
    constexpr std::size_t kScanLimit = 256U;

    // kCiOptionsSize：
    // - g_CiOptions is a ULONG with a fixed read/write width of 4 bytes.
    constexpr std::uint32_t kCiOptionsSize = 4U;

    // NtQuerySystemInformationFunction：
    // - Calling convention signature for NtQuerySystemInformation.
    using NtQuerySystemInformationFunction = long(NTAPI*)(
        unsigned long systemInformationClass,
        void* systemInformation,
        unsigned long systemInformationLength,
        unsigned long* returnLength);

    // KernelModuleRow / KernelModuleList：
    // - Local definition of RTL_PROCESS_MODULE_INFORMATION and its list head to avoid dependency on DDK headers.
    struct KernelModuleRow
    {
        void* section;
        void* mappedBase;
        void* imageBase;
        unsigned long imageSize;
        unsigned long flags;
        unsigned short loadOrderIndex;
        unsigned short initOrderIndex;
        unsigned short loadCount;
        unsigned short fileNameOffset;
        unsigned char fullPathName[256];
    };

    struct KernelModuleList
    {
        unsigned long count;
        KernelModuleRow rows[1];
    };

    // SystemCodeIntegrityInformationBlock：
    // - Local definition of SYSTEM_CODEINTEGRITY_INFORMATION.
    struct SystemCodeIntegrityInformationBlock
    {
        unsigned long length;
        unsigned long codeIntegrityOptions;
    };

    // CodeIntegrity option bits. Names follow the Windows SDK's CODEINTEGRITY_OPTION_*.
    constexpr std::uint32_t kOptionEnabled = 0x00000001U;
    constexpr std::uint32_t kOptionTestSign = 0x00000002U;
    constexpr std::uint32_t kOptionUmciEnabled = 0x00000004U;
    constexpr std::uint32_t kOptionHvciKmciEnabled = 0x00000400U;
    constexpr std::uint32_t kOptionHvciKmciStrictMode = 0x00001000U;

    // resolveNtQuerySystemInformation：
    // - Purpose: Retrieve NtQuerySystemInformation from ntdll.
    // - Returns: function pointer; nullptr on failure.
    NtQuerySystemInformationFunction resolveNtQuerySystemInformation()
    {
        const HMODULE kNtdll = ::GetModuleHandleW(L"ntdll.dll");
        if (kNtdll == nullptr)
        {
            return nullptr;
        }
        return reinterpret_cast<NtQuerySystemInformationFunction>(
            ::GetProcAddress(kNtdll, "NtQuerySystemInformation"));
    }

    // currentBuildNumber：
    // - Purpose: Read the current internal system build number from the PEB, avoiding influence from the compatibility manifest;
    // - Returns: build number; returns 0 if unavailable.
    std::uint32_t currentBuildNumber()
    {
        // On x64, PEB is located at gs:[0x60], and OSBuildNumber is at PEB+0x120.
        const auto kPeb = reinterpret_cast<const unsigned char*>(__readgsqword(0x60));
        if (kPeb == nullptr)
        {
            return 0U;
        }
        return *reinterpret_cast<const unsigned short*>(kPeb + 0x120);
    }

    // ntHeadersOf：
    // - Input base: SEC_IMAGE mapped base address;
    // - Purpose: Validate DOS/NT signatures and return the 64-bit NT header.
    // - Return: Pointer to the NT header; returns nullptr if not a PE64 image.
    const IMAGE_NT_HEADERS64* ntHeadersOf(const unsigned char* base)
    {
        if (base == nullptr)
        {
            return nullptr;
        }
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return nullptr;
        }
        const auto* nt =
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE
            || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            return nullptr;
        }
        return nt;
    }

    // sectionNameOfRva：
    // - Input base: mapped base address; rva: RVA to check for null.
    // - Purpose: Find which section the RVA falls into.
    // - Return: Section name; returns an empty string if not within any section.
    QString sectionNameOfRva(const unsigned char* base, const std::uint64_t rva)
    {
        const IMAGE_NT_HEADERS64* const kNt = ntHeadersOf(base);
        if (kNt == nullptr)
        {
            return QString();
        }
        const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(kNt);
        for (WORD index = 0; index < kNt->FileHeader.NumberOfSections; ++index, ++section)
        {
            const DWORD kVirtualSize = section->Misc.VirtualSize != 0U
                ? section->Misc.VirtualSize
                : section->SizeOfRawData;
            if (rva >= section->VirtualAddress
                && rva < static_cast<std::uint64_t>(section->VirtualAddress) + kVirtualSize)
            {
                char name[9] = {};
                std::memcpy(name, section->Name, 8);
                return QString::fromLatin1(name);
            }
        }
        return QString();
    }

    // rvaIsInSection：
    // - Input base: mapped base address; rva: RVA to check; name: target section name;
    // - Purpose: Determine if the RVA falls within the specified section.
    // - Returns: true indicates the RVA falls within the section.
    bool rvaIsInSection(
        const unsigned char* const base,
        const std::uint64_t rva,
        const char* const name)
    {
        return sectionNameOfRva(base, rva).compare(
            QString::fromLatin1(name), Qt::CaseInsensitive) == 0;
    }

    // findExportRva：
    // - Input base: SEC_IMAGE mapped base address; name: exported function name;
    // - Purpose: Manually parse the export table to look up RVA by name; the mapping is a read-only resource mapping, so GetProcAddress cannot be used;
    // - Returns: RVA of the export entry; returns 0 if not found.
    std::uint32_t findExportRva(const unsigned char* const base, const char* const name)
    {
        const IMAGE_NT_HEADERS64* const kNt = ntHeadersOf(base);
        if (kNt == nullptr)
        {
            return 0U;
        }
        const IMAGE_DATA_DIRECTORY& directory =
            kNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (directory.VirtualAddress == 0U || directory.Size == 0U)
        {
            return 0U;
        }

        const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            base + directory.VirtualAddress);
        if (exports->AddressOfNames == 0U
            || exports->AddressOfNameOrdinals == 0U
            || exports->AddressOfFunctions == 0U)
        {
            return 0U;
        }

        const auto* nameRvas =
            reinterpret_cast<const DWORD*>(base + exports->AddressOfNames);
        const auto* ordinals =
            reinterpret_cast<const WORD*>(base + exports->AddressOfNameOrdinals);
        const auto* functionRvas =
            reinterpret_cast<const DWORD*>(base + exports->AddressOfFunctions);

        for (DWORD index = 0; index < exports->NumberOfNames; ++index)
        {
            const auto* exportName =
                reinterpret_cast<const char*>(base + nameRvas[index]);
            if (std::strcmp(exportName, name) != 0)
            {
                continue;
            }
            const WORD kOrdinal = ordinals[index];
            if (kOrdinal >= exports->NumberOfFunctions)
            {
                return 0U;
            }
            const DWORD kFunctionRva = functionRvas[kOrdinal];
            // If located within the export directory, it is a forwarded export, which is not accepted for this purpose.
            if (kFunctionRva >= directory.VirtualAddress
                && kFunctionRva < directory.VirtualAddress + directory.Size)
            {
                return 0U;
            }
            return kFunctionRva;
        }
        return 0U;
    }

    // ImageMapping：
    // - Purpose: Map a disk PE as a SEC_IMAGE read-only section into this process; automatically released on destruction.
    class ImageMapping final
    {
    public:
        ImageMapping() = default;

        ~ImageMapping()
        {
            if (base_ != nullptr)
            {
                ::UnmapViewOfFile(base_);
            }
            if (mapping_ != nullptr)
            {
                ::CloseHandle(mapping_);
            }
            if (file_ != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(file_);
            }
        }

        ImageMapping(const ImageMapping&) = delete;
        ImageMapping& operator=(const ImageMapping&) = delete;

        // open：
        // - Input path: PE file path.
        // - Purpose: Create a read-only section view with SEC_IMAGE; sections are laid out by RVA, allowing direct RVA-based addressing.
        // - Returns: true indicates successful mapping.
        bool open(const std::wstring& path)
        {
            file_ = ::CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file_ == INVALID_HANDLE_VALUE)
            {
                lastError_ = ::GetLastError();
                return false;
            }
            mapping_ = ::CreateFileMappingW(
                file_,
                nullptr,
                PAGE_READONLY | SEC_IMAGE,
                0U,
                0U,
                nullptr);
            if (mapping_ == nullptr)
            {
                lastError_ = ::GetLastError();
                return false;
            }
            base_ = ::MapViewOfFile(mapping_, FILE_MAP_READ, 0U, 0U, 0U);
            if (base_ == nullptr)
            {
                lastError_ = ::GetLastError();
                return false;
            }
            return true;
        }

        // base: Returns the mapped base address; nullptr if not mapped.
        const unsigned char* base() const
        {
            return static_cast<const unsigned char*>(base_);
        }

        // lastError: Returns the most recent failed Win32 error code.
        DWORD lastError() const { return lastError_; }

    private:
        HANDLE file_ = INVALID_HANDLE_VALUE; // m_file: PE file handle.
        HANDLE mapping_ = nullptr;           // m_mapping: Section object handle.
        void* base_ = nullptr;               // m_base: Base address of the mapped view.
        DWORD lastError_ = 0U;               // m_lastError: Win32 error code on failure.
    };

    // KernelModuleInfo：
    // - Purpose: A row in the kernel module table, retaining only fields needed for locating.
    struct KernelModuleInfo
    {
        bool found = false;         // found: Whether the target module was found.
        std::uint64_t base = 0;     // base: module load base address.
        std::uint32_t size = 0;     // size: Module image size.
        QString name;               // name: Module file name.
        QString path;               // path: Module NT path.
        QString failureText;        // failureText: Reason for enumeration failure.
    };

    // findKernelModule：
    // - Input candidateNames: candidate module filenames, matched in order (case-insensitive);
    // - Purpose: enumerate the kernel module table to find the base address and size of the target module.
    // - Returns: KernelModuleInfo; requires administrator privileges, otherwise enumeration fails.
    KernelModuleInfo findKernelModule(const std::vector<QString>& candidateNames)
    {
        KernelModuleInfo info;

        const NtQuerySystemInformationFunction kQuery = resolveNtQuerySystemInformation();
        if (kQuery == nullptr)
        {
            info.failureText = QStringLiteral("无法解析系统模块枚举入口 NtQuerySystemInformation。");
            return info;
        }

        unsigned long required = 0U;
        kQuery(kSystemModuleInformationClass, nullptr, 0U, &required);
        if (required < sizeof(KernelModuleList))
        {
            required = 1024U * 1024U;
        }

        for (int attempt = 0; attempt < 4; ++attempt)
        {
            std::vector<unsigned char> buffer(
                static_cast<std::size_t>(required) + 64U * 1024U, 0U);
            unsigned long returned = 0U;
            const long kStatus = kQuery(
                kSystemModuleInformationClass,
                buffer.data(),
                static_cast<unsigned long>(buffer.size()),
                &returned);
            if (kStatus == kStatusInfoLengthMismatch)
            {
                required = std::max<unsigned long>(
                    returned, static_cast<unsigned long>(buffer.size() * 2U));
                continue;
            }
            if (kStatus < 0)
            {
                info.failureText = QStringLiteral(
                    "内核模块枚举失败，NTSTATUS=0x%1；该接口需要管理员权限。")
                    .arg(static_cast<unsigned long>(kStatus), 8, 16, QChar('0'));
                return info;
            }

            const auto* list = reinterpret_cast<const KernelModuleList*>(buffer.data());
            const std::size_t kMaximumRows =
                (buffer.size() - offsetof(KernelModuleList, rows)) / sizeof(KernelModuleRow);
            const std::size_t kRows =
                std::min<std::size_t>(list->count, kMaximumRows);
            for (std::size_t index = 0; index < kRows; ++index)
            {
                const KernelModuleRow& row = list->rows[index];
                const auto* fullPath = reinterpret_cast<const char*>(row.fullPathName);
                const std::size_t kPathLength =
                    ::strnlen_s(fullPath, sizeof(row.fullPathName));
                const QString kNtPath = QString::fromLocal8Bit(
                    fullPath, static_cast<int>(kPathLength));
                const int kNameOffset =
                    std::min<int>(row.fileNameOffset, kNtPath.size());
                const QString kFileName = kNtPath.mid(kNameOffset);

                const bool kMatched = std::any_of(
                    candidateNames.cbegin(),
                    candidateNames.cend(),
                    [&kFileName](const QString& candidate) {
                        return kFileName.compare(candidate, Qt::CaseInsensitive) == 0;
                    });
                if (!kMatched)
                {
                    continue;
                }

                info.found = true;
                info.base = reinterpret_cast<std::uint64_t>(row.imageBase);
                info.size = row.imageSize;
                info.name = kFileName;
                info.path = kNtPath;
                return info;
            }

            info.failureText = QStringLiteral("内核模块表里没有找到 CI 模块。");
            return info;
        }

        info.failureText = QStringLiteral("内核模块列表在多次重试后仍在变化。");
        return info;
    }

    // systemCiDllPath：
    // - Purpose: Construct the full path to %SystemRoot%\System32\CI.dll;
    // - Returns: the path; returns an empty string if the system directory cannot be retrieved.
    std::wstring systemCiDllPath()
    {
        std::array<wchar_t, MAX_PATH> directory{};
        const UINT kLength = ::GetSystemDirectoryW(
            directory.data(), static_cast<UINT>(directory.size()));
        if (kLength == 0U || kLength >= directory.size())
        {
            return std::wstring();
        }
        std::wstring path(directory.data(), kLength);
        path.append(L"\\CI.dll");
        return path;
    }

    // decodeAt：
    // - Input: code: first byte of the instruction; available: number of readable bytes.
    // - Purpose: Decode a 64-bit instruction using Zydis; pass the mapped address as runtimeAddress
    //   so that ZydisCalcAbsoluteAddress directly returns the absolute address within the mapping.
    // - Returns: true indicates successful decoding.
    bool decodeAt(
        const unsigned char* const code,
        const std::size_t available,
        ZydisDisassembledInstruction& instruction)
    {
        return ZYAN_SUCCESS(ZydisDisassembleIntel(
            ZYDIS_MACHINE_MODE_LONG_64,
            reinterpret_cast<ZyanU64>(code),
            code,
            available,
            &instruction));
    }

    // isRelativeBranch：
    // - Purpose: Check if the instruction's first operand is a relative immediate (call/jmp rel32);
    // - Returns: true if it is a relative branch/call.
    bool isRelativeBranch(const ZydisDisassembledInstruction& instruction)
    {
        return instruction.info.operand_count_visible >= 1
            && instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
            && instruction.operands[0].imm.is_relative != 0;
    }

    // isGpr32：
    // - Purpose: Determine if a register is a 32-bit general-purpose register to exclude 16/64-bit writes.
    // - Returns: true if the register is a 32-bit general-purpose register.
    bool isGpr32(const ZydisRegister reg)
    {
        return reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_R15D;
    }

    // driverStatusText：
    // - Input io: transmission result of an IOCTL;
    // - Purpose: Format communication layer errors into readable text.
    // - Returns: Description text.
    QString driverStatusText(const ksword::ark::IoResult& io)
    {
        QString message = QString::fromStdString(io.message);
        if (message.isEmpty())
        {
            message = QStringLiteral("无附加信息");
        }
        return QStringLiteral("Win32=%1 NT=0x%2 信息=%3")
            .arg(io.win32Error)
            .arg(static_cast<unsigned long>(io.ntStatus), 8, 16, QChar('0'))
            .arg(message);
    }
}

namespace ks::misc::disable_dse
{
    bool driverAvailable()
    {
        const ksword::ark::DriverClient kClient;
        const ksword::ark::DriverHandle kHandle =
            kClient.open(GENERIC_READ | GENERIC_WRITE);
        return kHandle.isValid();
    }

    CodeIntegrityPosture queryPosture()
    {
        CodeIntegrityPosture posture;
        posture.buildNumber = currentBuildNumber();

        // Prefer R0: it provides the most complete fields and also confirms that the CI module is present in the kernel module table.
        const ksword::ark::DriverClient kClient;
        const ksword::ark::SecurityStatusAuditResult kAudit = kClient.querySecurityStatus();
        if (kAudit.io.ok && !kAudit.unsupported)
        {
            const auto& response = kAudit.response;
            posture.queried = true;
            posture.source = PostureSource::kDriver;
            posture.options = static_cast<std::uint32_t>(response.codeIntegrityOptions);
            posture.ciEnabled = response.ciEnabled != 0UL;
            posture.testSigningEnabled = response.testSigningEnabled != 0UL;
            posture.umciEnabled = response.umciEnabled != 0UL;
            posture.hvciEnabled = response.hvciKmciEnabled != 0UL;
            posture.hvciStrictMode = response.hvciStrictMode != 0UL;
            posture.secureBootEnabled = response.secureBootEnabled != 0UL;
            posture.ciModuleLoaded = response.ciModuleLoaded != 0UL;
            return posture;
        }

        // Fallback to R3 when R0 is unavailable. This channel cannot retrieve secure boot and module loading status, but it is sufficient to display the current posture.
        const NtQuerySystemInformationFunction kQuery = resolveNtQuerySystemInformation();
        if (kQuery == nullptr)
        {
            posture.failureText =
                QStringLiteral("R0 未上线，且无法解析 NtQuerySystemInformation。");
            return posture;
        }

        SystemCodeIntegrityInformationBlock block{};
        block.length = sizeof(block);
        unsigned long returned = 0U;
        const long kStatus = kQuery(
            kSystemCodeIntegrityInformationClass, &block, sizeof(block), &returned);
        if (kStatus < 0)
        {
            posture.failureText = QStringLiteral(
                "代码完整性状态查询失败，NTSTATUS=0x%1。")
                .arg(static_cast<unsigned long>(kStatus), 8, 16, QChar('0'));
            return posture;
        }

        posture.queried = true;
        posture.source = PostureSource::kWin32;
        posture.options = block.codeIntegrityOptions;
        posture.ciEnabled = (posture.options & kOptionEnabled) != 0U;
        posture.testSigningEnabled = (posture.options & kOptionTestSign) != 0U;
        posture.umciEnabled = (posture.options & kOptionUmciEnabled) != 0U;
        posture.hvciEnabled = (posture.options & kOptionHvciKmciEnabled) != 0U;
        posture.hvciStrictMode = (posture.options & kOptionHvciKmciStrictMode) != 0U;
        return posture;
    }

    BlockReason evaluateBlockReason(
        const CodeIntegrityPosture& posture,
        const TargetLocation& location)
    {
        if (posture.queried && posture.buildNumber != 0U
            && posture.buildNumber < kFirstCiDllBuild)
        {
            return BlockReason::kUnsupportedBuild;
        }
        if (posture.queried && posture.hvciEnabled)
        {
            return BlockReason::kHvciEnabled;
        }
        if (!driverAvailable())
        {
            return BlockReason::kDriverUnavailable;
        }
        if (!location.ok)
        {
            return BlockReason::kNotLocated;
        }
        return BlockReason::kNone;
    }

    QString blockReasonText(const BlockReason reason)
    {
        switch (reason)
        {
        case BlockReason::kDriverUnavailable:
            return QStringLiteral("KswordARK 驱动未上线。g_CiOptions 位于内核，只能由 R0 修改，请先加载驱动。");
        case BlockReason::kUnsupportedBuild:
            return QStringLiteral("当前系统早于 Windows 8，DSE 开关在 nt!g_CiEnabled 而不是 CI.dll!g_CiOptions，本页不支持。");
        case BlockReason::kHvciEnabled:
            return QStringLiteral("已开启内存完整性（HVCI）。此时 g_CiOptions 所在页由 Hypervisor 通过 SLAT 保护，R0 写入不会生效，必须先在“Windows 安全中心 → 设备安全性 → 内核隔离”里关闭内存完整性并重启。");
        case BlockReason::kNotLocated:
            return QStringLiteral("尚未定位到 g_CiOptions，请先执行定位。");
        case BlockReason::kValueMismatch:
            return QStringLiteral("定位地址读回值的强制签名位与系统自报的驱动签名强制状态矛盾，地址存疑，已拒绝写入。");
        case BlockReason::kNone:
        default:
            break;
        }
        return QString();
    }

    TargetLocation locateCiOptions()
    {
        TargetLocation location;

        const std::uint32_t kBuild = currentBuildNumber();
        location.traceLines.append(
            QStringLiteral("系统内部版本号：%1").arg(kBuild));
        if (kBuild != 0U && kBuild < kFirstCiDllBuild)
        {
            location.failureText = QStringLiteral(
                "当前系统早于 Windows 8，DSE 开关不在 CI.dll 中，本页不支持。");
            return location;
        }

        // Step 1: Map CI.dll from disk into memory as a read-only SEC_IMAGE.
        // Read-only resource mapping does not convert kernel modules into executable pages for the current process, nor does it invoke DllMain.
        const std::wstring kPath = systemCiDllPath();
        if (kPath.empty())
        {
            location.failureText = QStringLiteral("无法取得系统目录路径。");
            return location;
        }
        location.traceLines.append(
            QStringLiteral("映射镜像：%1").arg(QString::fromStdWString(kPath)));

        ImageMapping mapping;
        if (!mapping.open(kPath))
        {
            location.failureText = QStringLiteral(
                "映射 CI.dll 失败，Win32 错误=%1。").arg(mapping.lastError());
            return location;
        }
        const unsigned char* const kBase = mapping.base();
        if (ntHeadersOf(kBase) == nullptr)
        {
            location.failureText = QStringLiteral("CI.dll 不是有效的 64 位 PE 映像。");
            return location;
        }

        // Step 2: locate CiInitialize from the export table.
        const std::uint32_t kCiInitializeRva = findExportRva(kBase, "CiInitialize");
        if (kCiInitializeRva == 0U)
        {
            location.failureText = QStringLiteral("CI.dll 未导出 CiInitialize。");
            return location;
        }
        location.traceLines.append(
            QStringLiteral("CiInitialize RVA = 0x%1")
                .arg(kCiInitializeRva, 0, 16));

        // Step 3: Locate the branch entering CipInitialize within CiInitialize.
        // Starting from build 16299, this is a call instruction, and there are several initialization calls in the INIT section that
        // must be skipped; the criterion is that the call target must reside in the PAGE section. Earlier versions used a direct jmp.
        const unsigned char* const kCiInitialize = kBase + kCiInitializeRva;
        const unsigned char* cipInitialize = nullptr;
        {
            std::size_t offset = 0;
            int callCount = 0;
            ZydisDisassembledInstruction instruction{};
            while (offset < kScanLimit)
            {
                if (!decodeAt(kCiInitialize + offset, kScanLimit - offset, instruction))
                {
                    break;
                }
                if (kBuild >= kCipInitializeCallBuild)
                {
                    if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL
                        && isRelativeBranch(instruction))
                    {
                        ++callCount;
                        ZyanU64 target = 0;
                        ZydisCalcAbsoluteAddress(
                            &instruction.info,
                            &instruction.operands[0],
                            reinterpret_cast<ZyanU64>(kCiInitialize + offset),
                            &target);
                        const auto* candidate =
                            reinterpret_cast<const unsigned char*>(target);
                        if (callCount > 1
                            && rvaIsInSection(
                                kBase,
                                static_cast<std::uint64_t>(candidate - kBase),
                                "PAGE"))
                        {
                            cipInitialize = candidate;
                            break;
                        }
                    }
                }
                else if (instruction.info.mnemonic == ZYDIS_MNEMONIC_JMP
                    && isRelativeBranch(instruction))
                {
                    ZyanU64 target = 0;
                    ZydisCalcAbsoluteAddress(
                        &instruction.info,
                        &instruction.operands[0],
                        reinterpret_cast<ZyanU64>(kCiInitialize + offset),
                        &target);
                    cipInitialize = reinterpret_cast<const unsigned char*>(target);
                    break;
                }
                offset += instruction.info.length;
            }
        }

        if (cipInitialize == nullptr)
        {
            location.failureText = QStringLiteral("在 CiInitialize 里没有找到进入 CipInitialize 的分支；该系统版本的 CI.dll 可能改了实现。");
            return location;
        }

        const std::uint64_t kCipRva =
            static_cast<std::uint64_t>(cipInitialize - kBase);
        if (!rvaIsInSection(kBase, kCipRva, "PAGE"))
        {
            location.failureText = QStringLiteral(
                "定位到的 CipInitialize（RVA 0x%1）不在 PAGE 节，判定为误匹配。")
                .arg(kCipRva, 0, 16);
            return location;
        }
        location.traceLines.append(
            QStringLiteral("CipInitialize RVA = 0x%1").arg(kCipRva, 0, 16));

        // Step 4: At the beginning of CipInitialize, the first parameter is written
        // to g_CiOptions, corresponding to `mov dword ptr [rip+disp32], r32`.
        std::uint64_t optionsRva = 0;
        {
            std::size_t offset = 0;
            ZydisDisassembledInstruction instruction{};
            while (offset < kScanLimit)
            {
                if (!decodeAt(cipInitialize + offset, kScanLimit - offset, instruction))
                {
                    break;
                }
                if (instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV
                    && instruction.info.operand_count_visible == 2
                    && instruction.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY
                    && instruction.operands[0].mem.base == ZYDIS_REGISTER_RIP
                    && instruction.operands[0].size == 32
                    && instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && isGpr32(instruction.operands[1].reg.value))
                {
                    ZyanU64 target = 0;
                    ZydisCalcAbsoluteAddress(
                        &instruction.info,
                        &instruction.operands[0],
                        reinterpret_cast<ZyanU64>(cipInitialize + offset),
                        &target);
                    optionsRva = static_cast<std::uint64_t>(
                        reinterpret_cast<const unsigned char*>(target) - kBase);
                    location.traceLines.append(
                        QStringLiteral("命中指令：CipInitialize+0x%1  %2")
                            .arg(offset, 0, 16)
                            .arg(QString::fromLatin1(instruction.text)));
                    break;
                }
                offset += instruction.info.length;
            }
        }

        if (optionsRva == 0)
        {
            location.failureText = QStringLiteral(
                "在 CipInitialize 里没有找到写 g_CiOptions 的指令。");
            return location;
        }

        // Step 5: Section validation. g_CiOptions was located in .data in older versions but has been moved to CiPolicy in newer versions.
        const QString kSectionName = sectionNameOfRva(kBase, optionsRva);
        if (kSectionName.compare(QStringLiteral(".data"), Qt::CaseInsensitive) != 0
            && kSectionName.compare(QStringLiteral("CiPolicy"), Qt::CaseInsensitive) != 0)
        {
            location.failureText = QStringLiteral(
                "候选地址 RVA 0x%1 落在节“%2”，不是 .data 或 CiPolicy，判定为误匹配。")
                .arg(optionsRva, 0, 16)
                .arg(kSectionName.isEmpty() ? QStringLiteral("<无>") : kSectionName);
            return location;
        }
        location.sectionName = kSectionName;
        location.traceLines.append(
            QStringLiteral("g_CiOptions RVA = 0x%1（节 %2）")
                .arg(optionsRva, 0, 16)
                .arg(kSectionName));

        // Step 6: Retrieve the real base address of the CI module in the kernel to convert RVA to kernel virtual address.
        const KernelModuleInfo kModule = findKernelModule(
            { QStringLiteral("ci.dll"), QStringLiteral("ci.sys") });
        if (!kModule.found)
        {
            location.failureText = kModule.failureText.isEmpty()
                ? QStringLiteral("未能取得内核中 CI 模块的基址。")
                : kModule.failureText;
            return location;
        }
        if (optionsRva >= kModule.size)
        {
            location.failureText = QStringLiteral(
                "RVA 0x%1 超出内核模块大小 0x%2，磁盘上的 CI.dll 与内核中已加载的版本不一致。")
                .arg(optionsRva, 0, 16)
                .arg(kModule.size, 0, 16);
            return location;
        }

        location.ok = true;
        location.moduleBase = kModule.base;
        location.moduleSize = kModule.size;
        location.moduleName = kModule.name;
        location.rva = static_cast<std::uint32_t>(optionsRva);
        location.kernelAddress = kModule.base + optionsRva;
        location.traceLines.append(
            QStringLiteral("内核模块 %1 基址 = 0x%2，大小 = 0x%3")
                .arg(kModule.name)
                .arg(kModule.base, 16, 16, QChar('0'))
                .arg(kModule.size, 0, 16));
        location.traceLines.append(
            QStringLiteral("g_CiOptions 内核地址 = 0x%1")
                .arg(location.kernelAddress, 16, 16, QChar('0')));
        return location;
    }

    ReadbackResult readCiOptions(const TargetLocation& location)
    {
        ReadbackResult result;
        if (!location.ok || location.kernelAddress == 0U)
        {
            result.failureText = QStringLiteral("目标尚未定位，无法读取。");
            return result;
        }

        const ksword::ark::DriverClient kClient;
        const ksword::ark::VirtualMemoryReadResult kReadResult =
            kClient.readVirtualMemory(
                0U,
                location.kernelAddress,
                kCiOptionsSize,
                KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS);
        if (!kReadResult.io.ok
            || kReadResult.readStatus != KSWORD_ARK_MEMORY_READ_STATUS_OK
            || kReadResult.data.size() < kCiOptionsSize)
        {
            result.failureText = QStringLiteral(
                "R0 读取 g_CiOptions 失败：读取状态=%1 %2")
                .arg(kReadResult.readStatus)
                .arg(driverStatusText(kReadResult.io));
            return result;
        }

        std::uint32_t value = 0U;
        std::memcpy(&value, kReadResult.data.data(), kCiOptionsSize);
        result.ok = true;
        result.value = value;
        return result;
    }

    ApplyResult writeCiOptions(
        const TargetLocation& location,
        const std::uint32_t expectedValue,
        const std::uint32_t desiredValue)
    {
        ApplyResult result;
        result.previousValue = expectedValue;
        result.writtenValue = desiredValue;

        if (!location.ok || location.kernelAddress == 0U)
        {
            result.detailText = QStringLiteral("目标尚未定位，拒绝写入。");
            return result;
        }
        if (expectedValue == desiredValue)
        {
            result.ok = true;
            result.detailText = QStringLiteral("目标值与当前值相同，无需写入。");
            return result;
        }

        std::vector<std::uint8_t> expectedBytes(kCiOptionsSize, 0U);
        std::vector<std::uint8_t> desiredBytes(kCiOptionsSize, 0U);
        std::memcpy(expectedBytes.data(), &expectedValue, kCiOptionsSize);
        std::memcpy(desiredBytes.data(), &desiredValue, kCiOptionsSize);

        const ksword::ark::DriverClient kClient;

        // PREPARE: With expected-before, the R0 side first reads back the target bytes and compares them.
        ksword::ark::MutationPrepareInput prepareInput{};
        prepareInput.flags =
            KSWORD_ARK_MUTATION_FLAG_DRY_RUN |
            KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT;
        prepareInput.targetKind = KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL;
        prepareInput.bytes = kCiOptionsSize;
        prepareInput.targetAddress = location.kernelAddress;
        prepareInput.afterBytes = desiredBytes;
        prepareInput.expectedBeforeBytes = expectedBytes;

        const ksword::ark::MutationResponseResult kPrepareResult =
            kClient.prepareMutation(prepareInput);
        if (!kPrepareResult.io.ok
            || kPrepareResult.status != KSWORD_ARK_MUTATION_STATUS_PREPARED
            || kPrepareResult.transactionId == 0U
            || kPrepareResult.bytes != kCiOptionsSize
            || kPrepareResult.beforeBytes.size() < kCiOptionsSize
            || !std::equal(
                expectedBytes.cbegin(),
                expectedBytes.cend(),
                kPrepareResult.beforeBytes.cbegin()))
        {
            result.detailText = QStringLiteral(
                "内核字节事务 PREPARE 失败：状态=%1 NT=0x%2 %3")
                .arg(kPrepareResult.status)
                .arg(static_cast<unsigned long>(kPrepareResult.lastStatus), 8, 16, QChar('0'))
                .arg(driverStatusText(kPrepareResult.io));
            return result;
        }

        const std::uint64_t kTransactionId = kPrepareResult.transactionId;
        result.transactionId = kTransactionId;
        result.traceLines.append(
            QStringLiteral("PREPARE 通过，事务号 = %1").arg(kTransactionId));

        // DRY-RUN: Let R0 walk through the security policy and writability without committing.
        const ksword::ark::MutationResponseResult kDryRunResult =
            kClient.commitMutation(kTransactionId, KSWORD_ARK_MUTATION_FLAG_DRY_RUN);
        if (!kDryRunResult.io.ok
            || kDryRunResult.status != KSWORD_ARK_MUTATION_STATUS_DRY_RUN)
        {
            result.detailText = QStringLiteral(
                "内核字节事务 dry-run 失败：状态=%1 NT=0x%2 %3")
                .arg(kDryRunResult.status)
                .arg(static_cast<unsigned long>(kDryRunResult.lastStatus), 8, 16, QChar('0'))
                .arg(driverStatusText(kDryRunResult.io));
            kClient.rollbackMutation(
                kTransactionId,
                KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);
            return result;
        }
        result.traceLines.append(QStringLiteral("dry-run 通过"));

        // COMMIT: performs the actual write. On the R0 side, it uses a writable MDL alias without modifying CR0.WP.
        const ksword::ark::MutationResponseResult kCommitResult =
            kClient.commitMutation(
                kTransactionId,
                KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);
        if (!kCommitResult.io.ok
            || kCommitResult.status != KSWORD_ARK_MUTATION_STATUS_COMMITTED)
        {
            result.detailText = QStringLiteral(
                "内核字节事务提交失败：状态=%1 NT=0x%2 %3")
                .arg(kCommitResult.status)
                .arg(static_cast<unsigned long>(kCommitResult.lastStatus), 8, 16, QChar('0'))
                .arg(driverStatusText(kCommitResult.io));
            kClient.rollbackMutation(
                kTransactionId,
                KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);
            return result;
        }
        result.traceLines.append(QStringLiteral("COMMIT 完成"));

        // Note: A successful submission does not guarantee the value actually changed; protections like HVCI may silently discard the write.
        const ReadbackResult kVerify = readCiOptions(location);
        if (!kVerify.ok)
        {
            result.detailText = QStringLiteral("提交后复读失败：%1").arg(kVerify.failureText);
            return result;
        }
        if (kVerify.value != desiredValue)
        {
            result.detailText = QStringLiteral("提交后复读不一致：期望 0x%1，实际 0x%2。写入很可能被 Hypervisor 或其他保护拦截，系统状态未改变。")
                .arg(desiredValue, 8, 16, QChar('0'))
                .arg(kVerify.value, 8, 16, QChar('0'));
            return result;
        }

        result.ok = true;
        result.traceLines.append(
            QStringLiteral("复读校验通过：0x%1").arg(kVerify.value, 8, 16, QChar('0')));
        return result;
    }

    QString describeOptions(const std::uint32_t options)
    {
        if (options == 0U)
        {
            return QStringLiteral("0（代码完整性全部关闭）");
        }

        struct OptionBit
        {
            std::uint32_t bit;
            const char* name;
        };
        static constexpr OptionBit kBits[] = {
            { 0x00000001U, "ENABLED" },
            { 0x00000002U, "TESTSIGN" },
            { 0x00000004U, "UMCI_ENABLED" },
            { 0x00000008U, "UMCI_AUDITMODE_ENABLED" },
            { 0x00000010U, "UMCI_EXCLUSIONPATHS_ENABLED" },
            { 0x00000020U, "TEST_BUILD" },
            { 0x00000040U, "PREPRODUCTION_BUILD" },
            { 0x00000080U, "DEBUGMODE_ENABLED" },
            { 0x00000100U, "FLIGHT_BUILD" },
            { 0x00000200U, "FLIGHTING_ENABLED" },
            { 0x00000400U, "HVCI_KMCI_ENABLED" },
            { 0x00000800U, "HVCI_KMCI_AUDITMODE_ENABLED" },
            { 0x00001000U, "HVCI_KMCI_STRICTMODE_ENABLED" },
            { 0x00002000U, "HVCI_IUM_ENABLED" },
            { 0x00004000U, "WHQL_ENFORCEMENT_ENABLED" },
            { 0x00008000U, "WHQL_AUDITMODE_ENABLED" }
        };

        QStringList names;
        std::uint32_t remaining = options;
        for (const OptionBit& entry : kBits)
        {
            if ((options & entry.bit) != 0U)
            {
                names.append(QString::fromLatin1(entry.name));
                remaining &= ~entry.bit;
            }
        }
        if (remaining != 0U)
        {
            names.append(QStringLiteral("未知位 0x%1").arg(remaining, 0, 16));
        }
        return names.join(QStringLiteral(" | "));
    }

    QString describeCiOptions(const std::uint32_t value)
    {
        if (value == 0U)
        {
            return QStringLiteral("0：驱动签名强制已完全关闭");
        }

        QStringList parts;
        if ((value & kCiOptionEnforceMask) == kCiOptionEnforceMask)
        {
            parts.append(QStringLiteral("强制驱动签名"));
        }
        else if ((value & kCiOptionEnforceMask) != 0U)
        {
            parts.append(QStringLiteral("强制位部分置位"));
        }
        else
        {
            parts.append(QStringLiteral("未强制驱动签名"));
        }
        if ((value & kCiOptionTestSign) != 0U)
        {
            parts.append(QStringLiteral("放行测试签名"));
        }

        const std::uint32_t kHigh = value & ~(kCiOptionEnforceMask | kCiOptionTestSign);
        if (kHigh != 0U)
        {
            // The high bits are CI internal policy flags (HVCI/WHQL, etc.), which vary by version; display them as-is without interpretation.
            parts.append(QStringLiteral("其余内部标志 0x%1").arg(kHigh, 0, 16));
        }
        return parts.join(QStringLiteral("，"));
    }

    bool ciOptionsAgreesWithPosture(
        const std::uint32_t value,
        const CodeIntegrityPosture& posture)
    {
        if (!posture.queried)
        {
            return false;
        }
        // Immediately reject obvious garbage reads.
        if (value == 0xFFFFFFFFU)
        {
            return false;
        }
        const bool kEnforcing = (value & kCiOptionEnforceMask) != 0U;
        return kEnforcing == posture.ciEnabled;
    }
}
