#include "../../../shared/ark_client/ArkDriverAuditSupport.h"
#include "../../../shared/ark_client/ArkDriverNetworkSupport.h"

#include <iostream>
#include <limits>
#include <stdexcept>
#include <utility>

using namespace ksword::ark;
using namespace ksword::ark::detail;

namespace
{
    void require(bool condition, const char* message)
    {
        if (!condition)
            throw std::runtime_error(message);
    }

    void fixedStringsRespectFieldBoundaries()
    {
        require(readFixedString<char>(nullptr, 10).empty(), "null string");
        require(readFixedString("abc", 0).empty(), "zero capacity");
        require(readFixedString("abc", 2) == "ab", "bounded ANSI string");
        require(readFixedString("a\0b", 3) == "a", "embedded NUL");
        require(readFixedString(L"abcd", 3) == L"abc", "bounded wide string");

        // Place unterminated fields immediately before an inaccessible page.
        // An unbounded strlen/wcslen would fault rather than pass this test.
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        auto* memory = static_cast<unsigned char*>(VirtualAlloc(
            nullptr, 2ULL * info.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        require(memory != nullptr, "allocate guard-page fixture");
        struct Allocation
        {
            void* address;
            ~Allocation() { VirtualFree(address, 0, MEM_RELEASE); }
        } allocation{memory};
        DWORD previous = 0;
        require(VirtualProtect(memory + info.dwPageSize, info.dwPageSize,
            PAGE_NOACCESS, &previous) != FALSE, "protect guard page");
        auto* narrow = reinterpret_cast<char*>(memory + info.dwPageSize - 4);
        std::memcpy(narrow, "abcd", 4);
        require(readFixedString(narrow, 4) == "abcd", "unterminated field at guard page");
        auto* wide = reinterpret_cast<wchar_t*>(memory + info.dwPageSize - 4 * sizeof(wchar_t));
        std::memcpy(wide, L"abcd", 4 * sizeof(wchar_t));
        require(readFixedString(wide, 4) == L"abcd", "unterminated wide field at guard page");
    }

    void unsupportedPoliciesRemainDistinct()
    {
        for (auto error : {ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED})
        {
            require(isMissingIoctlError(error), "missing IOCTL");
            require(isUnsupportedIoctlError(error), "legacy unsupported");
            require(isUnsupportedProtocolError(error), "versioned unsupported");
        }
        require(isUnsupportedIoctlError(ERROR_INVALID_PARAMETER), "legacy invalid parameter");
        require(!isUnsupportedProtocolError(ERROR_INVALID_PARAMETER), "versioned invalid parameter");
        require(isUnsupportedProtocolError(ERROR_REVISION_MISMATCH), "protocol version mismatch");
        require(!isUnsupportedIoctlError(ERROR_REVISION_MISMATCH), "legacy version mismatch");
        for (auto error : {ERROR_SUCCESS, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE})
        {
            require(!isMissingIoctlError(error) && !isUnsupportedIoctlError(error)
                && !isUnsupportedProtocolError(error), "transport/access errors are not unsupported");
        }
    }

    void auditBoundsRejectMalformedRows()
    {
        IoResult io;
        io.ok = true;
        io.bytesReturned = 28;
        require(audit::validateAuditRows(io, 8, 8, 4, 10, "test") == 2 && io.ok,
            "only complete strides count");
        require(audit::validateAuditRows(io, 8, 8, 4, 1, "test") == 1, "respect declared count");
        require(audit::validateAuditRows(io, 8, 0, 0, 10, "test") == 0
            && !io.ok && io.win32Error == ERROR_INVALID_DATA, "reject zero stride");
        io.ok = true;
        require(audit::validateAuditRows(io, 8, 3, 4, 10, "test") == 0
            && !io.ok && io.win32Error == ERROR_INVALID_DATA, "reject undersized entry");
        io.ok = true;
        require(audit::validateAuditRows(io, 29, 8, 4, 10, "test") == 0
            && !io.ok && io.win32Error == ERROR_INSUFFICIENT_BUFFER, "reject short header");
    }

    void variableRowsUseStrideAndBoundAllocation()
    {
        struct Row { std::uint32_t value; };
        std::vector<std::uint8_t> buffer(25, 0xCC);
        const Row kFirst{7}, kSecond{42};
        std::memcpy(buffer.data() + 8, &kFirst, sizeof(kFirst));
        std::memcpy(buffer.data() + 16, &kSecond, sizeof(kSecond));
        auto rows = audit::parseVariableRows<Row>(buffer, 8, 8,
            std::numeric_limits<std::size_t>::max());
        require(rows.size() == 2 && rows[0].value == 7 && rows[1].value == 42,
            "ignore padding, partial final stride, and untrusted huge count");
        require(audit::parseVariableRows<Row>(buffer, 8, 8, 1).size() == 1, "count limit");
        require(audit::parseVariableRows<Row>(buffer, 8, 8, 0).empty(), "empty response");
        require(audit::parseVariableRows<Row>(buffer, 8, 0, 2).empty(), "zero stride");
        require(audit::parseVariableRows<Row>(buffer, 8, 3, 2).empty(), "short stride");
        require(audit::parseVariableRows<Row>(buffer,
            std::numeric_limits<std::size_t>::max(), 8, 2).empty(), "header cannot wrap offset");
    }

    void fixedWideRequestsAreTerminated()
    {
        wchar_t field[4] = {L'x', L'x', L'x', L'x'};
        audit::copyAuditWideToFixed(field, 4, L"abcdef");
        require(std::wstring(field) == L"abc", "truncate with terminator");
        audit::copyAuditWideToFixed(field, 4, L"a");
        require(field[0] == L'a' && field[1] == 0 && field[2] == 0 && field[3] == 0,
            "clear stale request data");
        audit::copyAuditWideToFixed(field, 1, L"abc");
        require(field[0] == 0, "one character capacity");
        audit::copyAuditWideToFixed(nullptr, 0, L"abc");
    }

    void networkInventoryPreservesOnlyDocumentedPartialResults()
    {
        // The completeness policy only needs this result contract; acquisition
        // and any specific WFP/NDIS row structure are deliberately absent.
        struct Inventory
        {
            std::uint32_t status = KSWORD_ARK_NETWORK_STATUS_APPLIED;
            long lastStatus = 0;
            std::uint32_t totalCount = 2;
            std::uint32_t returnedCount = 2;
            bool partial = false;
            bool truncated = false;
            std::vector<int> entries{1, 2};
        } result;
        network::finalizeNetworkInventoryCompleteness(result);
        require(!result.partial && !result.truncated && result.entries.size() == 2, "complete inventory");
        result.totalCount = 3;
        network::finalizeNetworkInventoryCompleteness(result);
        require(result.partial && result.truncated && result.entries.size() == 2, "budget-limited inventory");
        result.status = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
        result.lastStatus = static_cast<long>(network::kStatusPartialCopy);
        result.totalCount = 2;
        network::finalizeNetworkInventoryCompleteness(result);
        require(result.partial && !result.truncated && result.entries.size() == 2, "partial collector snapshot");
        result.lastStatus = static_cast<long>(network::kStatusBufferOverflow);
        network::finalizeNetworkInventoryCompleteness(result);
        require(result.partial && result.truncated, "overflow is truncated even when counts match");
        result.lastStatus = static_cast<long>(0xC0000005UL);
        network::finalizeNetworkInventoryCompleteness(result);
        require(!result.partial && !result.truncated && result.entries.empty(), "discard unrelated collector failure");
        require(!network::isRetainableNetworkInventoryPartial(result.status,
            static_cast<long>(network::kStatusPartialCopy), 0), "empty failure is not partial data");
        NetworkEndpointAuditResult endpoint;
        endpoint.status = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
        endpoint.lastStatus = static_cast<long>(network::kStatusPartialCopy);
        endpoint.returnedCount = endpoint.totalCount = 1;
        endpoint.entries.emplace_back();
        network::finalizeNetworkEndpointCompleteness(endpoint);
        require(endpoint.entries.empty() && !endpoint.partial, "endpoint policy rejects all failed rows");
    }

    void networkHeaderRejectsInconsistentMetadata()
    {
        struct Header
        {
            std::uint32_t version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
            std::uint32_t size = sizeof(Header);
            std::uint32_t status = KSWORD_ARK_NETWORK_STATUS_APPLIED;
            std::uint32_t flags = 0, sourceFlags = 0;
            std::uint32_t returnedRowCount = 2, totalRowCount = 3, budgetRows = 2;
        } header;
        auto valid = [](const Header& response) {
            IoResult io;
            io.ok = true;
            io.bytesReturned = sizeof(Header);
            const bool kResult = network::validateNetworkAuditHeader(io, response, sizeof(Header), "test");
            require(kResult == io.ok, "validation updates IO status");
            if (!kResult) require(io.win32Error == ERROR_INVALID_DATA, "invalid metadata error");
            return kResult;
        };
        require(valid(header), "valid network header");
        auto bad = header; ++bad.version; require(!valid(bad), "reject version");
        bad = header; --bad.size; require(!valid(bad), "reject size");
        bad = header; bad.sourceFlags = 0x80000000; require(!valid(bad), "reject unknown source");
        bad = header; bad.flags = 0x80000000; require(!valid(bad), "reject unknown query flags");
        bad = header; bad.status = KSWORD_ARK_NETWORK_STATUS_AUDIT_STUB + 1; require(!valid(bad), "reject status");
        bad = header; bad.totalRowCount = 1; require(!valid(bad), "reject count inversion");
        bad = header; bad.budgetRows = 1; require(!valid(bad), "reject budget overrun");
    }

    void driverHandleTransfersOwnership()
    {
        DriverHandle empty;
        require(!empty.isValid(), "default handle invalid");
        DriverHandle source(CreateEventW(nullptr, FALSE, FALSE, nullptr));
        require(source.isValid(), "event handle created");
        HANDLE first = source.native();
        DriverHandle moved(std::move(source));
        require(!source.isValid() && moved.native() == first, "move transfers ownership");
        HANDLE released = moved.release();
        require(!moved.isValid() && SetEvent(released), "release leaves handle open");
        moved.reset(released);
        DriverHandle target(CreateEventW(nullptr, FALSE, FALSE, nullptr));
        HANDLE replaced = target.native();
        target = std::move(moved);
        DWORD flags = 0;
        require(!GetHandleInformation(replaced, &flags) && GetLastError() == ERROR_INVALID_HANDLE,
            "move assignment closes previous handle");
        require(!moved.isValid() && target.native() == first, "move assignment transfers handle");
        target.reset();
        require(!GetHandleInformation(first, &flags) && GetLastError() == ERROR_INVALID_HANDLE,
            "reset closes owned handle");
    }
}

int main()
{
    struct Test { const char* name; void (*run)(); };
    const Test kTests[] = {
        {"bounded protocol strings", fixedStringsRespectFieldBoundaries},
        {"unsupported error policies", unsupportedPoliciesRemainDistinct},
        {"audit response bounds", auditBoundsRejectMalformedRows},
        {"variable row parsing", variableRowsUseStrideAndBoundAllocation},
        {"fixed wide request fields", fixedWideRequestsAreTerminated},
        {"network completeness", networkInventoryPreservesOnlyDocumentedPartialResults},
        {"network header validation", networkHeaderRejectsInconsistentMetadata},
        {"handle ownership", driverHandleTransfersOwnership},
    };
    int failures = 0;
    for (const auto& test : kTests)
    {
        try { test.run(); std::cout << "PASS " << test.name << '\n'; }
        catch (const std::exception& error)
        {
            ++failures;
            std::cerr << "FAIL " << test.name << ": " << error.what() << '\n';
        }
    }
    return failures == 0 ? 0 : 1;
}
