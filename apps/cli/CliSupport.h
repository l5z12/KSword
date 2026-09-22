#pragma once

// Private contracts shared by the CLI command families.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <udpmib.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <io.h>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "../../shared/KswordArkLogProtocol.h"
#include "../../shared/driver/KswordArkAlpcIoctl.h"
#include "../../shared/driver/KswordArkCallbackIoctl.h"
#include "../../shared/driver/KswordArkCapabilityIoctl.h"
#include "../../shared/driver/KswordArkDynDataIoctl.h"
#include "../../shared/driver/KswordArkDeviceAuditIoctl.h"
#include "../../shared/driver/KswordArkFileIoctl.h"
#include "../../shared/driver/KswordArkFileMonitorIoctl.h"
#include "../../shared/driver/KswordArkFilterIoctl.h"
#include "../../shared/driver/KswordArkHandleIoctl.h"
#include "../../shared/driver/KswordArkHwidIoctl.h"
#include "../../shared/driver/KswordArkKeyboardIoctl.h"
#include "../../shared/driver/KswordArkKernelIoctl.h"
#include "../../shared/driver/KswordArkKernelObjectIoctl.h"
#include "../../shared/driver/KswordArkMemoryIoctl.h"
#include "../../shared/driver/KswordArkDdmaIoctl.h"
#include "../../shared/driver/KswordArkDdmaPlan.h"
#include "../../shared/driver/KswordArkMutationIoctl.h"
#include "../../shared/driver/KswordArkNetworkIoctl.h"
#include "../../shared/driver/KswordArkPreflightIoctl.h"
#include "../../shared/driver/KswordArkProcessIoctl.h"
#include "../../shared/driver/KswordArkRedirectIoctl.h"
#include "../../shared/driver/KswordArkRegistryIoctl.h"
#include "../../shared/driver/KswordArkSafetyIoctl.h"
#include "../../shared/driver/KswordArkSecurityAuditIoctl.h"
#include "../../shared/driver/KswordArkInjectionScanIoctl.h"
#include "../../shared/driver/KswordArkSectionIoctl.h"
#include "../../shared/driver/KswordArkStorageIoctl.h"
#include "../../shared/driver/KswordArkThreadIoctl.h"
#include "../../shared/driver/KswordArkTrustIoctl.h"
#include "../../shared/driver/KswordArkWin32kIoctl.h"
#include "../../shared/driver/KswordArkWslSiloIoctl.h"
#include "ArkDriverExtended.h"

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")


#include "CliArguments.h"
#include "../../shared/ark_client/ArkDriverClient.h"

namespace ksword::cli
{
    using DriverHandle = ksword::ark::DriverHandle;
    using IoctlResult = ksword::ark::IoResult;

    inline constexpr DWORD kDefaultShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;

    inline constexpr DWORD kDefaultDesiredAccess = GENERIC_READ | GENERIC_WRITE;

    inline constexpr std::size_t kSmallResponseBytes = 64U * 1024U;

    inline constexpr std::size_t kLargeResponseBytes = 2U * 1024U * 1024U;

    inline constexpr std::size_t kHugeResponseBytes = 4U * 1024U * 1024U;

    inline constexpr std::size_t kMaxCommandBytes = 64U * 1024U * 1024U;

    inline constexpr std::size_t kMaxHexBytes = 256U;

    inline constexpr std::uint32_t kNetworkStatusBufferOverflow = 0x80000005UL;

    inline constexpr std::uint32_t kNetworkStatusPartialCopy = 0x8000000DUL;

    // FamilyHelp describes one top-level command family for overview output.
    // Inputs: name is argv[1] and summary is human-readable help text.
    // Processing: one registration supplies both help text and command dispatch.
    // Returns: no behavior; callers read fields directly.
    struct FamilyHelp
    {
        const wchar_t* name;
        const wchar_t* summary;
        int (*run)(int argc, wchar_t* argv[]);
    };

    // CommandHelp describes one concrete command or alias accepted by dispatch.
    // Inputs: family/subcommand identify argv tokens; syntax/options/notes are display text.
    // Processing: help lookup matches tokens exactly and never opens the driver.
    // Returns: no behavior; callers read fields directly.
    struct CommandHelp
    {
        const wchar_t* family;
        const wchar_t* subcommand;
        const wchar_t* syntax;
        const wchar_t* summary;
        const wchar_t* options;
        const wchar_t* notes;
    };

    // RuntimeFieldCliItem stores one CLI-requested bounded runtime field sample.
    // Inputs: runtimeItemId, offset, size, and optional flags parsed from --items.
    // Processing: command builders copy these values into process/thread request
    // packets after enforcing the shared protocol limits.
    // Returns: no behavior; this is a simple staging structure.
    struct RuntimeFieldCliItem
    {
        std::uint32_t runtimeItemId = 0U;
        std::uint32_t offset = 0U;
        std::uint32_t size = 0U;
        std::uint32_t flags = 0U;
    };

    // dispatchCommand maps the first CLI token to an IOCTL command family.
    // ========================================================================
    // ddma family: disk direct memory access
    // ========================================================================
    //
    // The sole reason this family exists is to "accept DDMA on the target machine." Since real DDMA reads/writes
    // overwrite disk sectors, the self-test defaults to the **denial path**: requests are blocked by the
    // gatekeeper before the driver touches any disk, ensuring zero bytes are written even after a hundred runs.

    // kDdmaSelfTestName: Provides a stable name for each self-test item to facilitate script comparison.
    struct DdmaCheck
    {
        const wchar_t* name;
        const wchar_t* verdict;   // PASS / FAIL / NOT_APPLICABLE
        std::wstring detail;
    };

    void printWin32Error(const wchar_t* operation, DWORD error);

    DriverHandle openDriver(DWORD desiredAccess = kDefaultDesiredAccess);

    IoctlResult sendIoctl(
        DriverHandle& handle,
        DWORD code,
        void* input,
        DWORD inputBytes,
        void* output,
        DWORD outputBytes);

    std::vector<std::uint8_t> readFileBytes(const std::wstring& path, std::size_t maxBytes);

    std::string fixedAnsi(const char* text, std::size_t maxBytes);

    std::wstring fixedWide(const wchar_t* text, std::size_t maxChars);

    const wchar_t* ipcSummaryStatusName(std::uint32_t status);

    std::wstring fixedUtf16(const unsigned short* text, std::size_t maxChars);

    void copyWideToFixed(wchar_t* destination, std::size_t capacity, const std::wstring& source);

    std::wstring hex64(std::uint64_t value);

    void hexdump(const std::uint8_t* data, std::size_t size, std::size_t width = 16U);

    void dumpWideText(const wchar_t* label, const std::wstring& value);

    void reportFixedResponse(std::uint32_t version, std::uint32_t status, long lastStatus, DWORD bytesReturned);

    void printResponseBanner(std::uint32_t version, std::uint32_t status, long lastStatus, DWORD bytesReturned);

    void reportFixedStatus(std::uint32_t version, std::uint32_t status, long lastStatus);

    std::size_t responseCountLimit(std::size_t reported, std::size_t available, std::size_t limit);

    std::uint64_t currentUtc100ns();

    std::wstring formatGuid128(const KSWORD_ARK_GUID128& guid);

    KSWORD_ARK_GUID128 parseGuid128(const std::wstring& text);

    std::vector<std::uint8_t> loadBytesFromHexOrFile(
        const NamedArgs& args,
        const wchar_t* hexKey,
        const wchar_t* fileKey,
        std::size_t maxBytes,
        bool required);

    DriverHandle openDriverOrReport(DWORD desiredAccess = kDefaultDesiredAccess);

    int runNoOutputIoctl(
        const wchar_t* label,
        DWORD code,
        void* input,
        DWORD inputBytes,
        DWORD desiredAccess = kDefaultDesiredAccess);

    void printSimpleProcessEntry(const KSWORD_ARK_PROCESS_ENTRY& entry);

    void printSimpleThreadEntry(const KSWORD_ARK_THREAD_ENTRY& entry);

    void copyBytesToFixed(unsigned char* destination, std::size_t capacity, const std::vector<std::uint8_t>& source);

    DWORD checkedDwordSize(std::size_t bytes);

    unsigned short boundedPathLength(const std::wstring& pathText, std::size_t capacity);

    int sendRawIoctl(
        const wchar_t* label,
        DWORD code,
        void* input,
        DWORD inputBytes,
        std::vector<std::uint8_t>& output,
        IoctlResult& io,
        DWORD desiredAccess = kDefaultDesiredAccess);

    bool sameToken(const wchar_t* value, const wchar_t* expected);

    bool isHelpToken(const wchar_t* token);

    const FamilyHelp* findFamilyHelp(const std::wstring& family);

    void printCommandHelpEntry(const CommandHelp& entry);

    bool printFamilyHelp(const std::wstring& family);

    bool printSpecificCommandHelp(const std::wstring& family, const std::wstring& subcommand);

    void printUsage();

    int printHelpForTarget(int argc, wchar_t* argv[], int startIndex);

    bool hasTrailingHelpToken(int argc, wchar_t* argv[], int startIndex);

    void printCountHeader(std::uint32_t version, std::uint32_t total, std::uint32_t returned, std::uint32_t entrySize, DWORD bytesReturned);

    std::size_t validateVariable(DWORD bytesReturned, std::size_t headerSize, std::uint32_t entrySize, std::size_t minEntrySize, const wchar_t* label);

    bool isUnsupportedTransportError(DWORD error);

    int normalizeIoctlRc(const wchar_t* feature, const IoctlResult& io, int rc);

    int commandUnsupported(const wchar_t* feature, const wchar_t* reason);

    void printV4ModuleIdentity(const KSW_DYN_V4_MODULE_IDENTITY_PACKET& module);

    int queryDynV4Modules(const NamedArgs& args);

    int queryDynV4CapabilityGroups(const NamedArgs& args);

    int queryDynV4MissingItems(const NamedArgs& args);

    int queryDynV4Items(const NamedArgs& args);

    int commandLogFamily(int argc, wchar_t* argv[]);

    void printProcessEnumRow(const KSWORD_ARK_PROCESS_ENTRY& entry);

    RuntimeFieldCliItem splitRuntimeFieldItem(const std::wstring& token);

    std::vector<RuntimeFieldCliItem> parseRuntimeFieldItems(const std::wstring& text);

    void printKernelGlobals(const KSWORD_ARK_RUNTIME_KERNEL_GLOBALS& globals);

    int printRuntimeFieldSampleRows(
        const std::vector<std::uint8_t>& buffer,
        const IoctlResult& io,
        const NamedArgs& args,
        const wchar_t* label);

    void printProcessDetail(const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& response, DWORD bytesReturned);

    void printThreadDetail(const KSWORD_ARK_THREAD_DETAIL_RESPONSE& response, DWORD bytesReturned);

    std::vector<std::uint8_t> buildProcessRuntimeFieldInput(const NamedArgs& args);

    std::vector<std::uint8_t> buildThreadRuntimeFieldInput(const NamedArgs& args);

    std::uint32_t parseMandatoryIntegrityRid(const NamedArgs& args);

    std::wstring normalizeFilePathForDriver(std::wstring path);

    void printProcessIntegrityResponse(const KSWORD_ARK_SET_PROCESS_INTEGRITY_RESPONSE& response, DWORD bytesReturned);

    void printFileIntegrityResponse(const KSWORD_ARK_SET_FILE_INTEGRITY_RESPONSE& response, DWORD bytesReturned);

    std::vector<std::uint8_t> buildInjectRequestBuffer(
        const NamedArgs& args,
        std::uint32_t injectType,
        const std::vector<std::uint8_t>& payload,
        std::uint64_t entryPointAddress,
        std::uint64_t parameterAddress,
        unsigned long defaultFlags);

    void requireConfirmOption(const NamedArgs& args, const char* label);

    void printInjectResponse(const KSWORD_ARK_INJECT_PROCESS_RESPONSE& response, DWORD bytesReturned);

    std::vector<std::uint8_t> buildDllInjectPayload(const std::wstring& dllPath);

    std::uint64_t resolveLoadLibraryW();

    int commandProcessFamily(int argc, wchar_t* argv[]);

    void printPageTableInfo(const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO& info, DWORD bytesReturned);

    int commandMemoryFamily(int argc, wchar_t* argv[]);

    void printFileInfoResponse(const KSWORD_ARK_QUERY_FILE_INFO_RESPONSE& response, DWORD bytesReturned);

    int queryMinifilterInventory(const NamedArgs& args);

    KSWORD_ARK_STORAGE_AUDIT_REQUEST buildStorageRequest(const NamedArgs& args);

    int queryVolumeStackAudit(const NamedArgs& args);

    int queryBitlockerAudit(const NamedArgs& args);

    int queryMountMgrAudit(const NamedArgs& args);

    int queryFilesystemIntegrityAudit(const NamedArgs& args);

    KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST buildNetworkAuditRequest(const NamedArgs& args);

    const wchar_t* networkAuditStatusText(const unsigned long status);

    bool isRetainableNetworkInventoryPartial(
        const unsigned long status,
        const long lastStatus,
        const unsigned long returnedRows) noexcept;

    bool validateNetworkAuditHeader(
        const unsigned long version,
        const unsigned long size,
        const unsigned long status,
        const unsigned long flags,
        const unsigned long totalRows,
        const unsigned long returnedRows,
        const unsigned long sourceFlags,
        const unsigned long budgetRows,
        const DWORD bytesReturned,
        const std::size_t headerSize,
        const wchar_t* featureLabel);

    void printNetworkAuditState(
        const unsigned long status,
        const long lastStatus,
        const unsigned long sourceFlags,
        const unsigned long budgetRows,
        const unsigned long generation,
        const unsigned long totalRows,
        const unsigned long returnedRows,
        const bool partialRowsAccepted);

    std::wstring networkAuditAddressToText(
        const unsigned long addressFamily,
        const unsigned char addressBytes[16]);

    const wchar_t* networkNdisObjectKindText(const unsigned long kind);

    const wchar_t* networkWfpObjectKindText(const unsigned long kind);

    int queryNetworkEndpoints(const NamedArgs& args, DWORD code, const wchar_t* ioctlLabel, const wchar_t* featureLabel);

    int queryNetworkWfp(const NamedArgs& args);

    int queryNetworkNdis(const NamedArgs& args);

    std::wstring ipv4AddressToText(const DWORD address);

    std::wstring ipv6AddressToText(const UCHAR addressBytes[16], const DWORD scopeId);

    std::uint16_t networkPortToHost(const DWORD portValue);

    DWORD printAfdTcp4Fallback(const std::size_t limit, std::size_t& printedRows);

    DWORD printAfdUdp4Fallback(const std::size_t limit, std::size_t& printedRows);

    int commandNetworkAfdFallback(const NamedArgs& args);

    std::wstring socketAddressToText(const SOCKET_ADDRESS& socketAddress);

    int commandNetworkNsiFallback(const NamedArgs& args);

    int queryDeviceAudit(const NamedArgs& args, DWORD code, unsigned long profileFlags, const wchar_t* ioctlLabel, const wchar_t* featureLabel);

    KSWORD_ARK_WIN32K_QUERY_REQUEST buildWin32kRequest(const NamedArgs& args);

    std::uint32_t applyMessageHookMatchOption(
        const NamedArgs& args,
        std::uint32_t flags);

    const wchar_t* messageHookMatchName(const std::uint32_t flags);

    int queryWin32kProfileStatus(const NamedArgs& args);

    int queryWin32kWindows(const NamedArgs& args);

    int queryWin32kGuiThreads(const NamedArgs& args);

    void printWin32kModuleState(const wchar_t* label, const KSWORD_ARK_WIN32K_MODULE_STATE& module);

    int queryWin32kHotkeysPdb(const NamedArgs& args);

    int queryWin32kHooksPdb(const NamedArgs& args);

    int queryWin32kWindowDetail(const NamedArgs& args);

    int querySecurityStatus(const NamedArgs& args);

    int queryDriverTrustView(const NamedArgs& args);

    int queryHypervSummary(const NamedArgs&);

    int queryAppControlStatus(const NamedArgs&);

    int commandFileFamily(int argc, wchar_t* argv[]);

    std::wstring fixedAnsiWide(const char* text, std::size_t maxBytes);

    void requireWideCapacity(const std::wstring& text, std::size_t capacity, const char* name);

    void copyRequiredWideOption(const NamedArgs& args, const wchar_t* key, wchar_t* destination, std::size_t capacity);

    bool copyOptionalWideOption(const NamedArgs& args, const wchar_t* key, wchar_t* destination, std::size_t capacity);

    void printBytesInline(const wchar_t* label, const unsigned char* data, std::size_t count, std::size_t maxDisplay = 32U);

    std::vector<std::uint8_t> readRequiredBlobOption(const NamedArgs& args, const wchar_t* key, std::size_t maxBytes);

    void printModuleIdentity(const wchar_t* label, const KSW_DYN_MODULE_IDENTITY_PACKET& module);

    int commandKernelFamily(int argc, wchar_t* argv[]);

    void printCallbackEventPacket(const KSWORD_ARK_CALLBACK_EVENT_PACKET& packet, DWORD bytesReturned);

    int queryCallbackInventory(const NamedArgs& args);

    int commandCallbackFamily(int argc, wchar_t* argv[]);

    int commandDynFamily(int argc, wchar_t* argv[]);

    int commandCapabilityFamily(int argc, wchar_t* argv[]);

    int commandThreadFamily(int argc, wchar_t* argv[]);

    int commandHandleFamily(int argc, wchar_t* argv[]);

    void printAlpcPortInfo(const wchar_t* label, const KSWORD_ARK_ALPC_PORT_INFO& info);

    int commandAlpcFamily(int argc, wchar_t* argv[]);

    int commandSectionFamily(int argc, wchar_t* argv[]);

    int commandWslFamily(int argc, wchar_t* argv[]);

    int commandTrustFamily(int argc, wchar_t* argv[]);

    int commandSafetyFamily(int argc, wchar_t* argv[]);

    int commandPreflightFamily(int argc, wchar_t* argv[]);

    void printRegistryOperationResponse(const KSWORD_ARK_REGISTRY_OPERATION_RESPONSE& response, DWORD bytesReturned);

    int commandRegistryFamily(int argc, wchar_t* argv[]);

    int commandRedirectFamily(int argc, wchar_t* argv[]);

    int commandNetworkFamily(int argc, wchar_t* argv[]);

    int commandKeyboardFamily(int argc, wchar_t* argv[]);

    int queryDriverOptionalGlobalEvidence(
        const NamedArgs& args,
        const wchar_t* featureLabel,
        const wchar_t* detailNeedle,
        const wchar_t* displayName);

    int commandDriverFamily(int argc, wchar_t* argv[]);

    int commandHardwareFamily(int argc, wchar_t* argv[]);

    std::uint32_t parseHwidDispatchAction(const std::wstring& text);

    void addHwidTargetToken(const std::wstring& token, std::uint32_t& flags);

    std::uint32_t parseHwidTargetFlags(const NamedArgs& args);

    std::uint32_t parseHwidDiskMode(const NamedArgs& args);

    std::uint32_t parseHwidMacMode(const NamedArgs& args);

    void printHwidDispatchResponse(const KSWORD_ARK_HWID_DISPATCH_RESPONSE& response, DWORD bytesReturned);

    int commandHwidFamily(int argc, wchar_t* argv[]);

    int commandWindowFamily(int argc, wchar_t* argv[]);

    int commandMiscFamily(int argc, wchar_t* argv[]);

    int commandMutationFamily(int argc, wchar_t* argv[]);

    int printDdmaChecks(const std::vector<DdmaCheck>& checks);

    bool sendDdmaRead(
        const KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST& request,
        std::vector<std::uint8_t>& buffer,
        IoctlResult& io);

    unsigned long ddmaReadStatusOf(const std::vector<std::uint8_t>& buffer);

    DdmaCheck expectDdmaReadStatus(
        const wchar_t* name,
        const KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST& request,
        unsigned long expectedStatus);

    int runDdmaSelfTest(std::uint64_t scratchLba, bool hasLba);

    int commandDdmaFamily(int argc, wchar_t* argv[]);

    int dispatchCommand(int argc, wchar_t* argv[]);

    void configureConsole();

    template <typename TResponse>
    bool sendFixedNoInput(
        DWORD code,
        const wchar_t* label,
        TResponse& response,
        IoctlResult& io,
        DWORD desiredAccess = kDefaultDesiredAccess)
    {
        DriverHandle handle = openDriverOrReport(desiredAccess);
        if (!handle.isValid())
        {
            io.win32Error = ::GetLastError();
            return false;
        }

        io = sendIoctl(handle, code, nullptr, 0U, &response, static_cast<DWORD>(sizeof(response)));
        if (!io.ok)
        {
            printWin32Error(label, io.win32Error);
            return false;
        }
        if (io.bytesReturned < sizeof(response))
        {
            std::wcerr << L"error: " << label << L" response too small: " << io.bytesReturned << L" bytes\n";
            io.ok = false;
            io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            return false;
        }
        return true;
    }

    template <typename TRequest, typename TResponse>
    bool sendFixedRequestResponse(
        DWORD code,
        const wchar_t* label,
        const TRequest& request,
        TResponse& response,
        IoctlResult& io,
        DWORD desiredAccess = kDefaultDesiredAccess)
    {
        DriverHandle handle = openDriverOrReport(desiredAccess);
        if (!handle.isValid())
        {
            io.win32Error = ::GetLastError();
            return false;
        }

        io = sendIoctl(
            handle,
            code,
            const_cast<TRequest*>(&request),
            static_cast<DWORD>(sizeof(request)),
            &response,
            static_cast<DWORD>(sizeof(response)));
        if (!io.ok)
        {
            printWin32Error(label, io.win32Error);
            return false;
        }
        if (io.bytesReturned < sizeof(response))
        {
            std::wcerr << L"error: " << label << L" response too small: " << io.bytesReturned << L" bytes\n";
            io.ok = false;
            io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            return false;
        }
        return true;
    }

    // sendBlobFixedResponse sends a raw input blob and receives one fixed response.
    // Inputs: IOCTL label/code, blob bytes, response object, result packet, access.
    // Processing: performs METHOD_BUFFERED DeviceIoControl with size validation.
    // Returns: true on a transport-level success with a full fixed response.
    template <typename TResponse>
    bool sendBlobFixedResponse(
        DWORD code,
        const wchar_t* label,
        std::vector<std::uint8_t>& input,
        TResponse& response,
        IoctlResult& io,
        DWORD desiredAccess = kDefaultDesiredAccess)
    {
        DriverHandle handle = openDriverOrReport(desiredAccess);
        if (!handle.isValid())
        {
            io.win32Error = ::GetLastError();
            return false;
        }

        io = sendIoctl(handle, code, input.data(), checkedDwordSize(input.size()), &response, static_cast<DWORD>(sizeof(response)));
        if (!io.ok)
        {
            printWin32Error(label, io.win32Error);
            return false;
        }
        if (io.bytesReturned < sizeof(response))
        {
            std::wcerr << L"error: " << label << L" response too small: " << io.bytesReturned << L" bytes\n";
            io.ok = false;
            io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            return false;
        }
        return true;
    }
}
