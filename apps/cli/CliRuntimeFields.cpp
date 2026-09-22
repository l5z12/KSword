#include "CliSupport.h"

namespace ksword::cli
{
    // splitRuntimeFieldItem separates one "id:offset:size[:flags]" token.
    // Inputs: a token from --items where values may be decimal or 0x-prefixed.
    // Processing: validates the three required fields and the optional flags
    // field before protocol bounds are applied by the caller.
    // Returns: parsed item; throws on malformed text.
    RuntimeFieldCliItem splitRuntimeFieldItem(const std::wstring& token)
    {
        std::vector<std::wstring> parts;
        std::wstring current;
        for (const wchar_t kCh : token)
        {
            if (kCh == L':')
            {
                parts.push_back(current);
                current.clear();
                continue;
            }
            current.push_back(kCh);
        }
        parts.push_back(current);

        if (parts.size() < 3U || parts.size() > 4U)
        {
            throw std::invalid_argument("runtime field item");
        }

        RuntimeFieldCliItem item{};
        item.runtimeItemId = parseU32(parts[0].c_str(), "runtime item id");
        item.offset = parseU32(parts[1].c_str(), "runtime item offset");
        item.size = parseU32(parts[2].c_str(), "runtime item size");
        item.flags = (parts.size() == 4U) ? parseU32(parts[3].c_str(), "runtime item flags") : 0U;
        if (item.size == 0U || item.size > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES)
        {
            throw std::out_of_range("runtime item size");
        }
        if (item.offset > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_OFFSET)
        {
            throw std::out_of_range("runtime item offset");
        }
        return item;
    }

    // parseRuntimeFieldItems parses the comma/semicolon/pipe separated --items list.
    // Inputs: text such as "1:0x448:8,2:0x5a8:1".
    // Processing: trims whitespace separators, validates each item, and caps the
    // count at KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS.
    // Returns: ordered item vector used to build variable-sized IOCTL input.
    std::vector<RuntimeFieldCliItem> parseRuntimeFieldItems(const std::wstring& text)
    {
        std::vector<RuntimeFieldCliItem> items;
        std::wstring token;
        const auto kFlush = [&]()
        {
            if (token.empty())
            {
                return;
            }
            if (items.size() >= KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS)
            {
                throw std::out_of_range("runtime item count");
            }
            items.push_back(splitRuntimeFieldItem(token));
            token.clear();
        };

        for (const wchar_t kCh : text)
        {
            if (kCh == L',' || kCh == L';' || kCh == L'|' || std::iswspace(kCh) != 0)
            {
                kFlush();
                continue;
            }
            token.push_back(kCh);
        }
        kFlush();
        if (items.empty())
        {
            throw std::invalid_argument("runtime items");
        }
        return items;
    }

    // printKernelGlobals renders the common process/thread runtime global packet.
    // Inputs: kernelGlobals returned by process/thread detail IOCTLs.
    // Processing: prints RVA/source/address triplets in a compact diagnostic form.
    // Returns: no value.
    void printKernelGlobals(const KSWORD_ARK_RUNTIME_KERNEL_GLOBALS& globals)
    {
        std::wcout << L"kernelGlobals"
                   << L" pspCidTable=" << hex64(globals.pspCidTableAddress) << L"/rva=0x" << std::hex << globals.pspCidTableRva << L"/src=" << globals.pspCidTableSource
                   << L" psLoadedModuleList=" << hex64(globals.psLoadedModuleListAddress) << L"/rva=0x" << globals.psLoadedModuleListRva << L"/src=" << globals.psLoadedModuleListSource
                   << L" mmUnloadedDrivers=" << hex64(globals.mmUnloadedDriversAddress) << L"/rva=0x" << globals.mmUnloadedDriversRva << L"/src=" << globals.mmUnloadedDriversSource
                   << L" piDdbCacheTable=" << hex64(globals.piDdbCacheTableAddress) << L"/rva=0x" << globals.piDdbCacheTableRva << L"/src=" << globals.piDdbCacheTableSource
                   << L" shadowSsdt=" << hex64(globals.keServiceDescriptorTableShadowAddress) << L"/rva=0x" << globals.keServiceDescriptorTableShadowRva << L"/src=" << globals.keServiceDescriptorTableShadowSource
                   << std::dec << L"\n";
    }

    // printRuntimeFieldSampleRows renders a variable process/thread sample response.
    // Inputs: raw returned buffer and a label used for validation diagnostics.
    // Processing: validates row size, prints object/capability metadata, and then
    // prints every bounded sample row up to --limit.
    // Returns: CLI exit code.
    int printRuntimeFieldSampleRows(
        const std::vector<std::uint8_t>& buffer,
        const IoctlResult& io,
        const NamedArgs& args,
        const wchar_t* label)
    {
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE) - sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW), label); }
        catch (...) { return 4; }

        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"object=" << hex64(response->objectAddress)
                   << L" dyn=0x" << std::hex << response->dynDataCapabilityMask
                   << std::dec << L" flags=0x" << std::hex << response->flags << std::dec << L"\n";

        const bool kDump = getOptionBool(args, L"--hexdump");
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 64U));
        for (std::size_t i = 0U; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] item=" << row->runtimeItemId
                       << L" offset=0x" << std::hex << row->offset
                       << L" size=" << std::dec << row->size
                       << L" status=" << row->status
                       << L" bytesRead=" << row->bytesRead
                       << L" last=0x" << std::hex << static_cast<unsigned long>(row->lastStatus)
                       << L" value=" << hex64(row->valueU64)
                       << std::dec << L"\n";
            if (kDump && row->bytesRead != 0U)
            {
                hexdump(row->sampleBytes, std::min<unsigned long>(row->bytesRead, KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES));
            }
        }
        return 0;
    }

    // printProcessDetail renders IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL output.
    // Inputs: fixed response and DeviceIoControl byte count.
    // Processing: prints identity, object pointers, security bytes, offsets and
    // source masks in a format suitable for scripts and manual triage.
    // Returns: no value.
    void printProcessDetail(const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.status, response.lastStatus, bytesReturned);
        std::wcout << L"pid=" << response.processId
                   << L" fields=0x" << std::hex << response.fieldFlags
                   << L" requested=0x" << response.requestedFlags
                   << L" dyn=0x" << response.dynDataCapabilityMask
                   << L" missing=0x" << response.missingCapabilityMask
                   << L" eprocess=" << hex64(response.processObjectAddress)
                   << L" uniquePidValue=" << hex64(response.uniqueProcessIdValue)
                   << L" apl.flink=" << hex64(response.activeProcessLinksFlink)
                   << L" apl.blink=" << hex64(response.activeProcessLinksBlink)
                   << L" threadList.flink=" << hex64(response.threadListHeadFlink)
                   << L" threadList.blink=" << hex64(response.threadListHeadBlink)
                   << L" tokenFastRef=" << hex64(response.tokenFastRef)
                   << L" tokenObject=" << hex64(response.tokenObjectAddress)
                   << L" objectTable=" << hex64(response.objectTableAddress)
                   << L" section=" << hex64(response.sectionObjectAddress)
                   << std::dec << L"\n";
        std::wcout << L"security protection=0x" << std::hex << static_cast<unsigned int>(response.protection)
                   << L" signature=0x" << static_cast<unsigned int>(response.signatureLevel)
                   << L" sectionSignature=0x" << static_cast<unsigned int>(response.sectionSignatureLevel)
                   << std::dec << L" image='" << fixedAnsi(response.imageName, KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS).c_str() << L"'\n";
        std::wcout << L"offsets uniquePid=0x" << std::hex << response.offsets.epUniqueProcessId
                   << L" activeLinks=0x" << response.offsets.epActiveProcessLinks
                   << L" threadList=0x" << response.offsets.epThreadListHead
                   << L" image=0x" << response.offsets.epImageFileName
                   << L" token=0x" << response.offsets.epToken
                   << L" objectTable=0x" << response.offsets.epObjectTable
                   << L" section=0x" << response.offsets.epSectionObject
                   << L" protection=0x" << response.offsets.epProtection
                   << L" signature=0x" << response.offsets.epSignatureLevel
                   << L" sectionSignature=0x" << response.offsets.epSectionSignatureLevel
                   << std::dec << L"\n";
        printKernelGlobals(response.kernelGlobals);
        dumpWideText(L"detail", fixedWide(response.detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS));
    }

    // printThreadDetail renders IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL output.
    // Inputs: fixed response and DeviceIoControl byte count.
    // Processing: prints ETHREAD/KTHREAD object pointers, start/stack/IO evidence,
    // offsets, and human-readable detail text.
    // Returns: no value.
    void printThreadDetail(const KSWORD_ARK_THREAD_DETAIL_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.status, response.lastStatus, bytesReturned);
        std::wcout << L"tid=" << response.threadId
                   << L" pid=" << response.processId
                   << L" fields=0x" << std::hex << response.fieldFlags
                   << L" requested=0x" << response.requestedFlags
                   << L" dyn=0x" << response.dynDataCapabilityMask
                   << L" missing=0x" << response.missingCapabilityMask
                   << L" ethread=" << hex64(response.threadObjectAddress)
                   << L" eprocess=" << hex64(response.processObjectAddress)
                   << L" cidPid=" << hex64(response.cidUniqueProcess)
                   << L" cidTid=" << hex64(response.cidUniqueThread)
                   << L" list.flink=" << hex64(response.threadListEntryFlink)
                   << L" list.blink=" << hex64(response.threadListEntryBlink)
                   << L" start=" << hex64(response.startAddress)
                   << L" win32Start=" << hex64(response.win32StartAddress)
                   << L" ktProcess=" << hex64(response.kthreadProcessObject)
                   << std::dec << L"\n";
        std::wcout << L"stack initial=" << hex64(response.initialStack)
                   << L" limit=" << hex64(response.stackLimit)
                   << L" base=" << hex64(response.stackBase)
                   << L" kernel=" << hex64(response.kernelStack)
                   << L" io(read/write/other)=" << response.readOperationCount << L"/"
                   << response.writeOperationCount << L"/" << response.otherOperationCount
                   << L" bytes(read/write/other)=" << response.readTransferCount << L"/"
                   << response.writeTransferCount << L"/" << response.otherTransferCount << L"\n";
        std::wcout << L"offsets cid=0x" << std::hex << response.offsets.etCid
                   << L" list=0x" << response.offsets.etThreadListEntry
                   << L" start=0x" << response.offsets.etStartAddress
                   << L" win32Start=0x" << response.offsets.etWin32StartAddress
                   << L" ktProcess=0x" << response.offsets.ktProcess
                   << L" initialStack=0x" << response.offsets.ktInitialStack
                   << L" stackLimit=0x" << response.offsets.ktStackLimit
                   << L" stackBase=0x" << response.offsets.ktStackBase
                   << L" kernelStack=0x" << response.offsets.ktKernelStack
                   << std::dec << L"\n";
        printKernelGlobals(response.kernelGlobals);
        dumpWideText(L"detail", fixedWide(response.detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS));
    }

    // buildProcessRuntimeFieldInput creates the variable input packet for EPROCESS sampling.
    // Inputs: parsed CLI args with --pid, --items, and optional --flags.
    // Processing: allocates a byte vector sized to the requested item count and
    // copies each validated item into the protocol array.
    // Returns: byte vector ready for DeviceIoControl input.
    std::vector<std::uint8_t> buildProcessRuntimeFieldInput(const NamedArgs& args)
    {
        const std::vector<RuntimeFieldCliItem> kItems = parseRuntimeFieldItems(requireOptionText(args, L"--items"));
        const std::size_t kHeaderBytes = offsetof(KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST, items);
        std::vector<std::uint8_t> bytes(kHeaderBytes + (kItems.size() * sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST)), 0U);
        auto* request = reinterpret_cast<KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST*>(bytes.data());
        request->version = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_PROTOCOL_VERSION;
        request->flags = getOptionU32(args, L"--flags", 0U);
        request->processId = requireOptionU32(args, L"--pid");
        request->itemCount = static_cast<unsigned long>(kItems.size());
        for (std::size_t index = 0U; index < kItems.size(); ++index)
        {
            request->items[index].runtimeItemId = kItems[index].runtimeItemId;
            request->items[index].offset = kItems[index].offset;
            request->items[index].size = kItems[index].size;
            request->items[index].flags = kItems[index].flags;
        }
        return bytes;
    }

    // buildThreadRuntimeFieldInput creates the variable input packet for ETHREAD sampling.
    // Inputs: parsed CLI args with --tid, optional --pid, --items, and --flags.
    // Processing: allocates a byte vector sized to the requested item count and
    // copies each validated item into the protocol array.
    // Returns: byte vector ready for DeviceIoControl input.
    std::vector<std::uint8_t> buildThreadRuntimeFieldInput(const NamedArgs& args)
    {
        const std::vector<RuntimeFieldCliItem> kItems = parseRuntimeFieldItems(requireOptionText(args, L"--items"));
        const std::size_t kHeaderBytes = offsetof(KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST, items);
        std::vector<std::uint8_t> bytes(kHeaderBytes + (kItems.size() * sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST)), 0U);
        auto* request = reinterpret_cast<KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST*>(bytes.data());
        request->version = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_PROTOCOL_VERSION;
        request->flags = getOptionU32(args, L"--flags", 0U);
        request->threadId = requireOptionU32(args, L"--tid");
        request->processId = getOptionU32(args, L"--pid", 0U);
        request->itemCount = static_cast<unsigned long>(kItems.size());
        for (std::size_t index = 0U; index < kItems.size(); ++index)
        {
            request->items[index].runtimeItemId = kItems[index].runtimeItemId;
            request->items[index].offset = kItems[index].offset;
            request->items[index].size = kItems[index].size;
            request->items[index].flags = kItems[index].flags;
        }
        return bytes;
    }
}
