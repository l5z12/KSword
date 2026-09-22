#include "CliSupport.h"

namespace ksword::cli
{
    constexpr FamilyHelp kFamilyHelps[] = {
        { L"log", L"Read bounded frames from the KswordARK log device.", commandLogFamily },
        { L"process", L"Inspect and control process visibility, PPL, DKOM, and cross-view state.", commandProcessFamily },
        { L"memory", L"Query, read, write, translate, and audit virtual/physical memory.", commandMemoryFamily },
        { L"file", L"Inspect files, filters, storage evidence, and file-monitor runtime state.", commandFileFamily },
        { L"kernel", L"Inspect SSDT, hooks, driver objects, CPU, physical layout, CID, and IPC state.", commandKernelFamily },
        { L"callback", L"Manage callback rules, pending decisions, callback inventory, and bypass PIDs.", commandCallbackFamily },
        { L"dyn", L"Query or apply dynamic kernel symbol/profile data.", commandDynFamily },
        { L"thread", L"Enumerate threads and compare R0/R3 thread evidence.", commandThreadFamily },
        { L"handle", L"Enumerate process handles and inspect object metadata.", commandHandleFamily },
        { L"driver", L"Driver integrity, device stack, and optional global evidence aliases.", commandDriverFamily },
        { L"hardware", L"Device, input, USB, and PnP stack audit views.", commandHardwareFamily },
        { L"hwid", L"HWID Dispatch query and guarded control operations.", commandHwidFamily },
        { L"window", L"Win32k, GUI, GPU, display, and watchdog audit views.", commandWindowFamily },
        { L"misc", L"Security, CI/VBS, Hyper-V, AppLocker/BAM, and driver trust posture.", commandMiscFamily },
        { L"alpc", L"ALPC port diagnostics for a process handle.", commandAlpcFamily },
        { L"section", L"Process and file section mapping diagnostics.", commandSectionFamily },
        { L"trust", L"Image trust and signing diagnostics.", commandTrustFamily },
        { L"safety", L"Safety policy query and update controls.", commandSafetyFamily },
        { L"preflight", L"Release-readiness and driver capability preflight checks.", commandPreflightFamily },
        { L"registry", L"Registry read, enumeration, and mutation helpers.", commandRegistryFamily },
        { L"redirect", L"File/registry redirect rules and runtime status.", commandRedirectFamily },
        { L"network", L"Network rules, endpoints, WFP/NDIS evidence, and R3 fallbacks.", commandNetworkFamily },
        { L"keyboard", L"Keyboard hotkey and hook inventory.", commandKeyboardFamily },
        { L"mutation", L"Prepare, commit, rollback, and audit bounded mutation transactions.", commandMutationFamily },
        { L"capability", L"Unified driver feature capability query.", commandCapabilityFamily },
        { L"wsl", L"WSL silo and Linux PID/TID diagnostics.", commandWslFamily },
        { L"r0", L"Desktop-parity R0 forensic queries and bounded evidence reads.", commandArkDriverExtended },
        { L"ddma", L"DDMA capability, bounded physical reads, and explicit self-tests.", commandDdmaFamily },
    };

    constexpr CommandHelp kCommandHelps[] = {
        { L"log", L"", L"KswordCLI.exe log [--max-frames N]", L"Read up to N log frames from the shared log device.", L"--max-frames defaults to 64.", L"No subcommand is used for the log family." },
        { L"process", L"terminate", L"KswordCLI.exe process terminate --pid PID [--exit-status NTSTATUS]", L"Terminate one process through the driver.", L"Required: --pid. Optional: --exit-status defaults to 0xC000013A.", L"" },
        { L"process", L"suspend", L"KswordCLI.exe process suspend --pid PID", L"Suspend one process.", L"Required: --pid.", L"" },
        { L"process", L"resume", L"KswordCLI.exe process resume --pid PID", L"Resume one suspended process.", L"Required: --pid.", L"Pairs with process suspend; the driver prefers PsResumeProcess and falls back to Zw/NtResumeProcess." },
        { L"process", L"set-ppl", L"KswordCLI.exe process set-ppl --pid PID --level LEVEL", L"Set the process protection level byte.", L"Required: --pid, --level.", L"" },
        { L"process", L"set-integrity", L"KswordCLI.exe process set-integrity --pid PID (--rid RID | --level untrusted|low|medium|medium-plus|high|system) [--flags 0xN] [--confirm]", L"Set a process mandatory integrity label through R0.", L"Required: --pid and one integrity selector. Optional: --flags, --confirm adds UI-confirmed protocol bit.", L"Backed by IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY." },
        { L"process", L"inject-dll", L"KswordCLI.exe process inject-dll --pid PID --dll PATH [--flags 0xN] [--wait-thread] --confirm", L"Inject a DLL path through the R0 process injection protocol.", L"Required: --pid, --dll, --confirm. Optional: --flags overrides request flags; --wait-thread adds wait flag.", L"Backed by IOCTL_KSWORD_ARK_INJECT_PROCESS with LoadLibraryW entrypoint." },
        { L"process", L"inject-shellcode", L"KswordCLI.exe process inject-shellcode --pid PID --blob PATH [--flags 0xN] --confirm", L"Inject a raw shellcode blob through the R0 process injection protocol.", L"Required: --pid, --blob, --confirm. Optional: --flags overrides request flags.", L"Payload is capped by KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES." },
        { L"process", L"enum", L"KswordCLI.exe process enum [--flags 0xN] [--start-pid PID] [--end-pid PID] [--limit N]", L"Enumerate processes from R0 evidence.", L"Optional: --flags, --start-pid, --end-pid, --limit.", L"" },
        { L"process", L"set-visibility", L"KswordCLI.exe process set-visibility --action ACTION [--pid PID] [--flags 0xN]", L"Apply a process visibility action.", L"Required: --action. Optional: --pid defaults to 0, --flags.", L"" },
        { L"process", L"set-special-flags", L"KswordCLI.exe process set-special-flags --pid PID --action ACTION [--flags 0xN]", L"Apply special process flags.", L"Required: --pid, --action. Optional: --flags.", L"" },
        { L"process", L"dkom", L"KswordCLI.exe process dkom --pid PID [--action ACTION] [--flags 0xN]", L"Run the configured process DKOM action.", L"Required: --pid. Optional: --action, --flags.", L"" },
        { L"process", L"crossview", L"KswordCLI.exe process crossview [--flags 0xN] [--start-pid PID] [--end-pid PID] [--max-nodes N] [--limit N]", L"Compare process evidence across supported sources.", L"Optional: --flags, --start-pid, --end-pid, --max-nodes, --limit.", L"" },
        { L"process", L"detail", L"KswordCLI.exe process detail --pid PID [--flags 0xN]", L"Query fixed R0 process runtime detail.", L"Required: --pid. Optional: --flags defaults to include-all.", L"Backed by IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL." },
        { L"process", L"runtime-fields", L"KswordCLI.exe process runtime-fields --pid PID --items id:offset:size[:flags][,id:offset:size[:flags]...] [--flags 0xN] [--hexdump]", L"Sample bounded EPROCESS runtime fields by checked offsets.", L"Required: --pid, --items. Optional: --flags, --hexdump.", L"Backed by IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS; each item is bounded by KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES." },
        { L"memory", L"query-va", L"KswordCLI.exe memory query-va --pid PID --address VA [--flags 0xN]", L"Query virtual memory metadata for one address.", L"Required: --pid, --address. Optional: --flags.", L"" },
        { L"memory", L"read-va", L"KswordCLI.exe memory read-va --pid PID --address VA --bytes N [--flags 0xN] [--hexdump]", L"Read virtual memory bytes.", L"Required: --pid, --address, --bytes. Optional: --flags, --hexdump.", L"With the kernel-address read flag, --pid may be omitted." },
        { L"memory", L"write-va", L"KswordCLI.exe memory write-va --pid PID --address VA (--hex HEX | --data-file PATH) [--flags 0xN]", L"Write virtual memory bytes.", L"Required: --pid, --address, and exactly one payload option. Optional: --flags.", L"With the kernel-address write flag, --pid may be omitted." },
        { L"memory", L"read-phys", L"KswordCLI.exe memory read-phys --address PA --bytes N [--hexdump]", L"Read physical memory bytes.", L"Required: --address, --bytes. Optional: --hexdump.", L"" },
        { L"memory", L"write-phys", L"KswordCLI.exe memory write-phys --address PA (--hex HEX | --data-file PATH) [--flags 0xN]", L"Write physical memory bytes.", L"Required: --address and exactly one payload option. Optional: --flags.", L"" },
        { L"memory", L"translate-va", L"KswordCLI.exe memory translate-va --pid PID --address VA [--flags 0xN]", L"Translate a virtual address to page-table evidence.", L"Required: --pid, --address. Optional: --flags.", L"" },
        { L"memory", L"query-pte", L"KswordCLI.exe memory query-pte --pid PID --address VA [--flags 0xN]", L"Query page-table entries for one virtual address.", L"Required: --pid, --address. Optional: --flags.", L"" },
        { L"memory", L"scan-kexec", L"KswordCLI.exe memory scan-kexec [--flags 0xN] [--max-entries N] [--start VA] [--end VA] [--limit N]", L"Scan executable kernel memory evidence.", L"Optional: --flags, --max-entries, --start, --end, --limit.", L"" },
        { L"memory", L"enum-vad", L"KswordCLI.exe memory enum-vad --pid PID [--start VA] [--end VA] [--cursor-vpn VPN] [--max-entries N] [--flags 0xN] [--limit N]", L"Enumerate the target process VAD tree as an independent region view.", L"Required: --pid. Optional: --start, --end, --cursor-vpn, --max-entries, --flags, --limit.", L"Backed by IOCTL_KSWORD_ARK_ENUMERATE_PROCESS_VAD; profileVerified=0 means the DynData VadRoot offset is not validated for this build and the result cannot support absence inference." },
        { L"memory", L"scan-exec-pte", L"KswordCLI.exe memory scan-exec-pte --pid PID [--start VA] [--end VA] [--cursor VA] [--max-entries N] [--max-table-reads N] [--flags 0xN] [--limit N]", L"Scan the target process page tables for user-space executable leaves.", L"Required: --pid. Optional: --start, --end, --cursor, --max-entries, --max-table-reads, --flags, --limit.", L"Backed by IOCTL_KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE; reports what the processor treats as executable, independent of VAD protection." },
        { L"memory", L"read-section-pages", L"KswordCLI.exe memory read-section-pages --pid PID --start VA --end VA [--cursor VA] [--max-pages N] [--flags 0xN] [--limit N]", L"Read the image section object's clean reference pages for a mapped range.", L"Required: --pid, --start, --end. Optional: --cursor, --max-pages, --flags, --limit.", L"Backed by IOCTL_KSWORD_ARK_READ_IMAGE_SECTION_PAGES; a second reference source independent of the file on disk. Only prototype PTEs in the architectural valid form are resolved - transition and pagefile encodings are version specific and are reported as not resident rather than decoded, and pages are never faulted in. Set --flags 0x1 to also return the page bytes." },
        { L"memory", L"scan-evidence", L"KswordCLI.exe memory scan-evidence [--flags 0xN] [--max-rows N] [--start VA] [--end VA] [--max-bytes N] [--max-bigpool-rows N] [--sample-bytes N] [--limit N]", L"Scan kernel memory evidence rows.", L"Optional: --flags, --max-rows, --start, --end, --max-bytes, --max-bigpool-rows, --sample-bytes, --limit.", L"" },
        { L"file", L"delete-path", L"KswordCLI.exe file delete-path --path PATH [--flags 0xN]", L"Delete one path through the driver.", L"Required: --path. Optional: --flags.", L"" },
        { L"file", L"query-info", L"KswordCLI.exe file query-info --path PATH [--flags 0xN]", L"Query file object and basic file metadata.", L"Required: --path. Optional: --flags.", L"" },
        { L"file", L"set-integrity", L"KswordCLI.exe file set-integrity --path PATH (--rid RID | --level untrusted|low|medium|medium-plus|high|system) [--directory] [--flags 0xN] [--confirm]", L"Set a file or directory mandatory integrity label through R0.", L"Required: --path and one integrity selector. Optional: --directory, --flags, --confirm adds UI-confirmed protocol bit.", L"Win32/UNC paths are normalized to the driver NT path convention before IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY." },
        { L"file", L"fileobject", L"KswordCLI.exe file fileobject --path PATH [--flags 0xN]", L"Alias for file query-info.", L"Required: --path. Optional: --flags.", L"Prints an alias banner before query-info output." },
        { L"file", L"minifilter", L"KswordCLI.exe file minifilter [--flags 0xN] [--max-rows N] [--limit N]", L"Enumerate minifilter inventory rows.", L"Optional: --flags, --max-rows, --limit.", L"" },
        { L"file", L"section", L"KswordCLI.exe file section", L"Report that the file section alias is unsupported.", L"No options.", L"Use section query-file-mappings --path PATH for the implemented section protocol." },
        { L"file", L"bitlocker", L"KswordCLI.exe file bitlocker [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]", L"Query BitLocker/FVE storage audit rows.", L"Optional: --flags, --max-rows, --max-depth, --volume, --limit.", L"" },
        { L"file", L"storage", L"KswordCLI.exe file storage [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]", L"Query volume stack audit rows.", L"Optional: --flags, --max-rows, --max-depth, --volume, --limit.", L"" },
        { L"file", L"mountmgr", L"KswordCLI.exe file mountmgr [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]", L"Query MountMgr mapping audit rows.", L"Optional: --flags, --max-rows, --max-depth, --volume, --limit.", L"" },
        { L"file", L"filesystem", L"KswordCLI.exe file filesystem [--flags 0xN] [--max-rows N] [--max-depth N] [--volume PATH] [--limit N]", L"Query filesystem integrity audit rows.", L"Optional: --flags, --max-rows, --max-depth, --volume, --limit.", L"" },
        { L"file", L"monitor-control", L"KswordCLI.exe file monitor-control --action ACTION [--operation-mask 0xN] [--pid PID] [--flags 0xN]", L"Control file monitor runtime state.", L"Required: --action. Optional: --operation-mask, --pid, --flags.", L"" },
        { L"file", L"monitor-drain", L"KswordCLI.exe file monitor-drain [--max-events N] [--flags 0xN]", L"Drain file monitor events.", L"Optional: --max-events, --flags.", L"" },
        { L"file", L"monitor-status", L"KswordCLI.exe file monitor-status", L"Query file monitor runtime status.", L"No options.", L"" },
        { L"kernel", L"ssdt", L"KswordCLI.exe kernel ssdt [--flags 0xN] [--limit N]", L"Enumerate SSDT entries.", L"Optional: --flags, --limit.", L"" },
        { L"kernel", L"shadow-ssdt", L"KswordCLI.exe kernel shadow-ssdt [--flags 0xN] [--limit N]", L"Enumerate shadow SSDT entries.", L"Optional: --flags, --limit.", L"" },
        { L"kernel", L"scan-inline-hooks", L"KswordCLI.exe kernel scan-inline-hooks [--flags 0xN] [--max-entries N] [--module NAME] [--limit N]", L"Scan inline hook evidence.", L"Optional: --flags, --max-entries, --module, --limit.", L"" },
        { L"kernel", L"enum-iat-eat-hooks", L"KswordCLI.exe kernel enum-iat-eat-hooks [--flags 0xN] [--max-entries N] [--module NAME] [--limit N]", L"Enumerate IAT/EAT hook evidence.", L"Optional: --flags, --max-entries, --module, --limit.", L"" },
        { L"kernel", L"patch-inline-hook", L"KswordCLI.exe kernel patch-inline-hook --mode MODE --function VA (--expected-hex HEX | --expected-file PATH) [--restore-hex HEX | --restore-file PATH] [--flags 0xN]", L"Patch or restore an inline hook using bounded byte evidence.", L"Required: --mode, --function, and expected payload. Optional: restore payload, --flags.", L"Hex and file payload forms are mutually exclusive per payload." },
        { L"kernel", L"query-driver-object", L"KswordCLI.exe kernel query-driver-object --driver NAME [--flags 0xN] [--max-devices N] [--max-attached N] [--limit N]", L"Query one DriverObject and device chain.", L"Required: --driver. Optional: --flags, --max-devices, --max-attached, --limit.", L"" },
        { L"kernel", L"query-driver-integrity", L"KswordCLI.exe kernel query-driver-integrity [--driver NAME] [--module-base VA] [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--limit N]", L"Query driver integrity evidence rows.", L"Optional: --driver, --module-base, --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --limit.", L"" },
        { L"kernel", L"force-unload-driver", L"KswordCLI.exe kernel force-unload-driver --driver NAME [--module-base VA] [--timeout-ms N] [--flags 0xN]", L"Force an unload path for one driver.", L"Required: --driver. Optional: --module-base, --timeout-ms, --flags.", L"" },
        { L"kernel", L"query-cpu", L"KswordCLI.exe kernel query-cpu", L"Query CPU hardware summary.", L"No options.", L"" },
        { L"kernel", L"query-phys-layout", L"KswordCLI.exe kernel query-phys-layout", L"Query physical memory layout summary.", L"No options.", L"" },
        { L"kernel", L"cid", L"KswordCLI.exe kernel cid [--flags 0xN] [--max-entries N] [--max-visits N] [--start-cid CID] [--end-cid CID] [--limit N]", L"Enumerate CID table evidence.", L"Optional: --flags, --max-entries, --max-visits, --start-cid, --end-cid, --limit.", L"" },
        { L"kernel", L"object-summary", L"KswordCLI.exe kernel object-summary --target-kind KIND [--cid CID] [--object ADDRESS] [--flags 0xN]", L"Query object header/type/counter summary for CID or object evidence.", L"Required: --target-kind. Optional: --cid, --object, --flags.", L"Backed by IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY." },
        { L"kernel", L"ipc", L"KswordCLI.exe kernel ipc [--flags 0xN] [--pid PID] [--handle HANDLE] [--max-entries N]", L"Query IPC summary for a process/handle context.", L"Optional: --flags, --pid, --handle, --max-entries.", L"" },
        { L"kernel", L"callbacks", L"KswordCLI.exe kernel callbacks [--flags 0xN] [--max-entries N] [--limit N]", L"Alias for callback inventory.", L"Optional: --flags, --max-entries, --limit.", L"" },
        { L"kernel", L"hooks", L"KswordCLI.exe kernel hooks [--flags 0xN] [--max-entries N] [--module NAME] [--limit N]", L"Alias-style inline hook scan.", L"Optional: --flags, --max-entries, --module, --limit.", L"" },
        { L"callback", L"set-rules", L"KswordCLI.exe callback set-rules --blob PATH", L"Load callback rule bytes.", L"Required: --blob.", L"" },
        { L"callback", L"runtime-state", L"KswordCLI.exe callback runtime-state", L"Query callback runtime state.", L"No options.", L"" },
        { L"callback", L"monitor-start", L"KswordCLI.exe callback monitor-start [--categories LIST]", L"Start callback monitor capture with named categories.", L"Optional: --categories process,thread,image,registry,object,minifilter,core,all; defaults to core.", L"IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL; minifilter is high frequency and is not in core." },
        { L"callback", L"monitor-stop", L"KswordCLI.exe callback monitor-stop", L"Stop callback monitor capture without changing existing callback rules.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL." },
        { L"callback", L"monitor-status", L"KswordCLI.exe callback monitor-status", L"Query callback monitor capture state and ring counters.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_CALLBACK_MONITOR_QUERY." },
        { L"callback", L"monitor-read", L"KswordCLI.exe callback monitor-read [--after-sequence N] [--max-records N] [--limit N]", L"Read callback monitor records through an independent cursor.", L"Optional: --after-sequence, --max-records, --limit.", L"Backed by IOCTL_KSWORD_ARK_CALLBACK_MONITOR_READ; use next_sequence for the next read." },
        { L"callback", L"wait-event", L"KswordCLI.exe callback wait-event [--waiter-tag N]", L"Wait for one callback event packet.", L"Optional: --waiter-tag.", L"" },
        { L"callback", L"answer-event", L"KswordCLI.exe callback answer-event --event-guid GUID --decision N --source-session-id N [--answered-at UTC100NS]", L"Answer one pending callback event.", L"Required: --event-guid, --decision, --source-session-id. Optional: --answered-at.", L"" },
        { L"callback", L"cancel-pending", L"KswordCLI.exe callback cancel-pending", L"Cancel all pending callback decisions.", L"No options.", L"" },
        { L"callback", L"remove", L"KswordCLI.exe callback remove --class N --callback VA [--flags 0xN]", L"Remove a callback through an address-based public API path.", L"Required: --class, --callback. Object, Registry, and ETW classes are not supported by this legacy command.", L"" },
        { L"callback", L"remove-ex", L"KswordCLI.exe callback remove-ex --class N --callback VA [--registration VA] [--raw-storage VA] [--generation N] [--identity-hash N] [--source N] [--operation-mask 0xN] [--object-type-mask 0xN] [--trust-flags 0xN] [--remove-behavior N] [--flags 0xN]", L"Remove an external callback with extended row identity.", L"Object removal requires every identity field copied from one verified V3 enumeration row plus revalidation flags. Registry and ETW removal are disabled.", L"" },
        { L"callback", L"set-minifilter-bypass-pids", L"KswordCLI.exe callback set-minifilter-bypass-pids --pids PID[,PID...] [--flags 0xN]", L"Set minifilter bypass PID list.", L"Required: --pids. Optional: --flags.", L"" },
        { L"callback", L"query-minifilter-bypass-pids", L"KswordCLI.exe callback query-minifilter-bypass-pids", L"Query minifilter bypass PID list.", L"No options.", L"" },
        { L"callback", L"enum", L"KswordCLI.exe callback enum [--flags 0xN] [--max-entries N] [--limit N]", L"Enumerate callback inventory.", L"Optional: --flags, --max-entries, --limit.", L"" },
        { L"dyn", L"status", L"KswordCLI.exe dyn status", L"Query DynData status.", L"No options.", L"" },
        { L"dyn", L"fields", L"KswordCLI.exe dyn fields [--limit N]", L"List DynData fields.", L"Optional: --limit.", L"" },
        { L"dyn", L"capabilities", L"KswordCLI.exe dyn capabilities", L"Query DynData capability mask.", L"No options.", L"" },
        { L"dyn", L"profile", L"KswordCLI.exe dyn profile [--limit N]", L"List v4 DynData module profile rows.", L"Optional: --limit.", L"Alias: dyn v4-modules." },
        { L"dyn", L"v4-modules", L"KswordCLI.exe dyn v4-modules [--limit N]", L"List v4 DynData module profile rows.", L"Optional: --limit.", L"Alias: dyn profile." },
        { L"dyn", L"v4-capabilities", L"KswordCLI.exe dyn v4-capabilities [--limit N]", L"List v4 DynData capability groups.", L"Optional: --limit.", L"Alias: dyn capability-groups." },
        { L"dyn", L"capability-groups", L"KswordCLI.exe dyn capability-groups [--limit N]", L"List v4 DynData capability groups.", L"Optional: --limit.", L"Alias: dyn v4-capabilities." },
        { L"dyn", L"v4-missing", L"KswordCLI.exe dyn v4-missing [--limit N]", L"List missing v4 DynData items.", L"Optional: --limit.", L"Alias: dyn missing-items." },
        { L"dyn", L"missing-items", L"KswordCLI.exe dyn missing-items [--limit N]", L"List missing v4 DynData items.", L"Optional: --limit.", L"Alias: dyn v4-missing." },
        { L"dyn", L"v4-items", L"KswordCLI.exe dyn v4-items [--limit N]", L"List every v4 DynData item status row.", L"Optional: --limit.", L"Backed by IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS." },
        { L"dyn", L"apply-profile-v4", L"KswordCLI.exe dyn apply-profile-v4 --blob PATH", L"Apply a raw v4 DynData profile packet.", L"Required: --blob.", L"" },
        { L"dyn", L"apply-profile", L"KswordCLI.exe dyn apply-profile --blob PATH", L"Apply a raw legacy DynData profile packet.", L"Required: --blob.", L"" },
        { L"dyn", L"apply-profile-ex", L"KswordCLI.exe dyn apply-profile-ex --blob PATH", L"Apply a raw extended DynData profile packet.", L"Required: --blob.", L"" },
        { L"capability", L"query-driver-capabilities", L"KswordCLI.exe capability query-driver-capabilities [--limit N]", L"Query unified driver feature capability rows.", L"Optional: --limit.", L"" },
        { L"thread", L"enum", L"KswordCLI.exe thread enum [--flags 0xN] [--pid PID] [--limit N]", L"Enumerate threads.", L"Optional: --flags, --pid, --limit.", L"" },
        { L"thread", L"crossview", L"KswordCLI.exe thread crossview [--flags 0xN] [--pid PID] [--start-tid TID] [--end-tid TID] [--max-nodes N] [--limit N]", L"Compare thread evidence across supported sources.", L"Optional: --flags, --pid, --start-tid, --end-tid, --max-nodes, --limit.", L"" },
        { L"thread", L"detail", L"KswordCLI.exe thread detail --tid TID [--pid PID] [--flags 0xN]", L"Query fixed R0 ETHREAD/KTHREAD runtime detail.", L"Required: --tid. Optional: --pid, --flags defaults to include-all.", L"Backed by IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL." },
        { L"thread", L"runtime-fields", L"KswordCLI.exe thread runtime-fields --tid TID [--pid PID] --items id:offset:size[:flags][,id:offset:size[:flags]...] [--flags 0xN] [--hexdump]", L"Sample bounded ETHREAD/KTHREAD runtime fields by checked offsets.", L"Required: --tid, --items. Optional: --pid, --flags, --hexdump.", L"Backed by IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS; each item is bounded by KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES." },
        { L"handle", L"enum", L"KswordCLI.exe handle enum --pid PID [--flags 0xN] [--limit N]", L"Enumerate handles in one process.", L"Required: --pid. Optional: --flags, --limit.", L"Alias: handle object-table." },
        { L"handle", L"object-table", L"KswordCLI.exe handle object-table --pid PID [--flags 0xN] [--limit N]", L"Enumerate handles in one process.", L"Required: --pid. Optional: --flags, --limit.", L"Alias: handle enum." },
        { L"handle", L"query-object", L"KswordCLI.exe handle query-object --pid PID --handle HANDLE [--access 0xN] [--flags 0xN]", L"Query one handle object.", L"Required: --pid, --handle. Optional: --access, --flags.", L"Aliases: handle object-header, handle type-matrix." },
        { L"handle", L"object-header", L"KswordCLI.exe handle object-header --pid PID --handle HANDLE [--access 0xN] [--flags 0xN]", L"Query one handle object header projection.", L"Required: --pid, --handle. Optional: --access, --flags.", L"Alias: handle query-object." },
        { L"handle", L"type-matrix", L"KswordCLI.exe handle type-matrix --pid PID --handle HANDLE [--access 0xN] [--flags 0xN]", L"Query one handle object type projection.", L"Required: --pid, --handle. Optional: --access, --flags.", L"Alias: handle query-object." },
        { L"alpc", L"query-port", L"KswordCLI.exe alpc query-port --pid PID --handle HANDLE [--flags 0xN]", L"Query ALPC port information for one handle.", L"Required: --pid, --handle. Optional: --flags.", L"" },
        { L"section", L"query-process", L"KswordCLI.exe section query-process --pid PID [--flags 0xN] [--max-mappings N] [--limit N]", L"Query section mappings for one process.", L"Required: --pid. Optional: --flags, --max-mappings, --limit.", L"" },
        { L"section", L"query-file-mappings", L"KswordCLI.exe section query-file-mappings --path PATH [--flags 0xN] [--max-mappings N] [--limit N]", L"Query section mappings for one file path.", L"Required: --path. Optional: --flags, --max-mappings, --limit.", L"" },
        { L"wsl", L"query-silo", L"KswordCLI.exe wsl query-silo [--pid PID] [--tid TID] [--flags 0xN]", L"Query WSL silo process/thread evidence.", L"Optional: --pid, --tid, --flags.", L"" },
        { L"r0", L"workqueue", L"KswordCLI.exe r0 workqueue [--flags 0xN] [--max-entries N] [--limit N]", L"Enumerate kernel worker queues through the desktop R0 client.", L"Optional: --flags, --max-entries, --limit.", L"Backed by IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE." },
        { L"r0", L"directory", L"KswordCLI.exe r0 directory --path PATH [--max-entries N] [--limit N]", L"Enumerate a directory through R0 ZwQueryDirectoryFile.", L"Required: --path. Optional: --max-entries, --limit.", L"Win32 and UNC paths are normalized to the driver NT-path convention." },
        { L"r0", L"directory-irp", L"KswordCLI.exe r0 directory-irp --path PATH [--layer N] [--max-entries N] [--limit N]", L"Enumerate a directory through a selected R0 file-system stack layer.", L"Required: --path. Optional: --layer, --max-entries, --limit.", L"Reports the resolved receiving layer and driver." },
        { L"r0", L"image-signature", L"KswordCLI.exe r0 image-signature --path PATH [--module-base VA] [--flags 0xN]", L"Read Authenticode certificate-table and CI evidence through R0.", L"Required: --path. Optional: --module-base, --flags.", L"Backed by IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE." },
        { L"r0", L"debug-output", L"KswordCLI.exe r0 debug-output [--after-sequence N] [--max-records N] [--limit N]", L"Drain captured kernel debug-output records.", L"Optional: --after-sequence, --max-records, --limit.", L"Backed by IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN; capture state remains driver-managed." },
        { L"ddma", L"selftest", L"KswordCLI.exe ddma selftest [--lba N]", L"Run the DDMA acceptance checks; every check is a refusal path, so no disk sector is written.", L"Optional: --lba enables the ATA DMA transfer probe on that scratch sector.", L"Verdicts are PASS / FAIL / NOT_APPLICABLE. Missing ATA pass-through is NOT_APPLICABLE, not a failure." },
        { L"ddma", L"probe", L"KswordCLI.exe ddma probe [--lba N] [--max-disks N]", L"Enumerate disks usable for DDMA and report capability flags.", L"Optional: --lba issues a real ATA DMA read on that sector; --max-disks.", L"Backed by IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY. Without --lba it only enumerates." },
        { L"ddma", L"read", L"KswordCLI.exe ddma read --disk N --pa ADDR --lba N [--bytes N]", L"Read physical memory through disk DMA.", L"Required: --disk, --pa, --lba. Optional: --bytes (default 64, one page max).", L"Temporarily overwrites the scratch sectors at --lba and restores them; the range must not cross a page." },
        { L"r0", L"hvm-status", L"KswordCLI.exe r0 hvm-status", L"Query HVM v6 VMX/EPT or experimental SVM/NPT lifecycle and capability state.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_QUERY_HVM." },
        { L"r0", L"hvm-metrics", L"KswordCLI.exe r0 hvm-metrics", L"Read HVM metrics v4 timing, resource counters and AMD raw exit evidence.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_HVM_METRICS. Full per-CPU and bounded SVM probe JSON: hvm_ctl --json metrics." },
        { L"r0", L"hvm-events", L"KswordCLI.exe r0 hvm-events [--after-sequence N] [--max-rows N]", L"Read HVM event-ring evidence without clearing it.", L"Optional: --after-sequence, --max-rows.", L"Backed by IOCTL_KSWORD_ARK_HVM_EVENTS." },
        { L"r0", L"hvm-platform", L"KswordCLI.exe r0 hvm-platform", L"Read CR4/CPUID/CET-MSR platform calibration without entering VMX.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_HVM_PLATFORM." },
        { L"r0", L"ioctl-registry", L"KswordCLI.exe r0 ioctl-registry [--flags 0xN] [--max-entries N]", L"Query the driver's registered IOCTL dispatch inventory.", L"Optional: --flags, --max-entries.", L"Backed by IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY." },
        { L"r0", L"timer-dpc", L"KswordCLI.exe r0 timer-dpc [--max-entries N] [--max-per-bucket N]", L"Enumerate kernel timer and DPC evidence.", L"Optional: --max-entries, --max-per-bucket.", L"Backed by IOCTL_KSWORD_ARK_ENUM_TIMER_DPC." },
        { L"r0", L"unloaded", L"KswordCLI.exe r0 unloaded [--source mm|piddb|hash] [--max-rows N]", L"Query unloaded-driver, PiDDB, or hash-bucket evidence.", L"Optional: --source defaults to mm; --max-rows.", L"Backed by IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS." },
        { L"r0", L"wfp-events", L"KswordCLI.exe r0 wfp-events [--after-sequence N] [--max-rows N]", L"Read bounded WFP event-ring metadata.", L"Optional: --after-sequence, --max-rows.", L"Backed by IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS." },
        { L"r0", L"traffic", L"KswordCLI.exe r0 traffic [--after-sequence N] [--max-rows N]", L"Read bounded traffic-capture metadata from the driver's existing ring.", L"Optional: --after-sequence, --max-rows.", L"Backed by IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS; this command does not enable capture." },
        { L"r0", L"piddb", L"KswordCLI.exe r0 piddb [--max-rows N]", L"Enumerate PiDDBCacheTable evidence without deleting entries.", L"Optional: --max-rows.", L"Backed by IOCTL_KSWORD_ARK_QUERY_PIDDB." },
        { L"r0", L"cpu-power", L"KswordCLI.exe r0 cpu-power", L"Query CPU power-management state and raw capability evidence.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_QUERY_CPU_POWER." },
        { L"r0", L"process-protect", L"KswordCLI.exe r0 process-protect", L"Query the driver process-protection configuration and counters.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE." },
        { L"r0", L"raw-disk-backend", L"KswordCLI.exe r0 raw-disk-backend [--disk N] [--backend N] [--flags 0xN]", L"Query the selected raw-disk read backend.", L"Optional: --disk defaults to 0, --backend defaults to Windows stack, --flags.", L"Backed by IOCTL_KSWORD_ARK_QUERY_RAW_DISK_BACKEND." },
        { L"r0", L"raw-disk-read", L"KswordCLI.exe r0 raw-disk-read --length N [--disk N] [--backend N] [--offset N] [--flags 0xN] [--hexdump]", L"Read a bounded raw-disk range for forensic inspection.", L"Required: --length. Optional: --disk, --backend, --offset, --flags, --hexdump.", L"Backed by IOCTL_KSWORD_ARK_READ_RAW_DISK; default display is capped at 256 bytes." },
        { L"r0", L"system-time", L"KswordCLI.exe r0 system-time", L"Query system-time virtualization and conflict state.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME." },
        { L"r0", L"slat-iommu", L"KswordCLI.exe r0 slat-iommu [--include-mmio]", L"Query SLAT and IOMMU firmware/runtime evidence.", L"Optional: --include-mmio.", L"Backed by IOCTL_KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT." },
        { L"r0", L"platform", L"KswordCLI.exe r0 platform [--scope 0xN] [--max-rows N]", L"Query HAL and WDF platform-audit evidence.", L"Optional: --scope defaults to all, --max-rows.", L"Backed by IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT." },
        { L"r0", L"i8042", L"KswordCLI.exe r0 i8042 [--max-rows N]", L"Query i8042prt callback and stack evidence without reading input data.", L"Optional: --max-rows.", L"Backed by IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT." },
        { L"r0", L"object-types", L"KswordCLI.exe r0 object-types [--flags 0xN] [--max-entries N] [--start-index N]", L"Enumerate the kernel object-type table.", L"Optional: --flags, --max-entries, --start-index.", L"Backed by IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE." },
        { L"r0", L"win32k-timers", L"KswordCLI.exe r0 win32k-timers [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N]", L"Query PDB-backed win32k timer evidence.", L"Optional: --flags, --session-id, --pid, --tid, --max-entries.", L"Backed by IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS." },
        { L"r0", L"win32k-events", L"KswordCLI.exe r0 win32k-events [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N]", L"Query PDB-backed WinEvent-hook evidence.", L"Optional: --flags, --session-id, --pid, --tid, --max-entries.", L"Backed by IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS." },
        { L"trust", L"query-image", L"KswordCLI.exe trust query-image --path PATH [--flags 0xN]", L"Query image trust and signing evidence.", L"Required: --path. Optional: --flags.", L"" },
        { L"safety", L"query-policy", L"KswordCLI.exe safety query-policy [--flags 0xN]", L"Query safety policy state.", L"Optional: --flags.", L"" },
        { L"safety", L"set-policy", L"KswordCLI.exe safety set-policy [--set-flags 0xN] [--clear-flags 0xN] [--expected-generation N]", L"Update safety policy flags.", L"Optional: --set-flags, --clear-flags, --expected-generation.", L"" },
        { L"preflight", L"query", L"KswordCLI.exe preflight query [--flags 0xN] [--limit N]", L"Run release-readiness preflight checks.", L"Optional: --flags, --limit.", L"" },
        { L"registry", L"read-value", L"KswordCLI.exe registry read-value --key KEY [--value NAME] [--max-data-bytes N] [--flags 0xN] [--hexdump]", L"Read one registry value or default value.", L"Required: --key. Optional: --value, --max-data-bytes, --flags, --hexdump.", L"" },
        { L"registry", L"enum-key", L"KswordCLI.exe registry enum-key --key KEY [--flags 0xN] [--max-subkeys N] [--max-values N] [--max-value-data-bytes N] [--limit N]", L"Enumerate registry subkeys and values.", L"Required: --key. Optional: --flags, --max-subkeys, --max-values, --max-value-data-bytes, --limit.", L"" },
        { L"registry", L"set-value", L"KswordCLI.exe registry set-value --key KEY --type TYPE --data-file PATH [--value NAME] [--flags 0xN]", L"Set one registry value.", L"Required: --key, --type, --data-file. Optional: --value, --flags.", L"" },
        { L"registry", L"delete-value", L"KswordCLI.exe registry delete-value --key KEY [--value NAME] [--flags 0xN]", L"Delete one registry value or default value.", L"Required: --key. Optional: --value, --flags.", L"" },
        { L"registry", L"create-key", L"KswordCLI.exe registry create-key --key KEY [--flags 0xN]", L"Create one registry key.", L"Required: --key. Optional: --flags.", L"" },
        { L"registry", L"delete-key", L"KswordCLI.exe registry delete-key --key KEY [--flags 0xN]", L"Delete one registry key.", L"Required: --key. Optional: --flags.", L"" },
        { L"registry", L"rename-value", L"KswordCLI.exe registry rename-value --key KEY --old-value NAME --new-value NAME [--flags 0xN]", L"Rename one registry value.", L"Required: --key, --old-value, --new-value. Optional: --flags.", L"" },
        { L"registry", L"rename-key", L"KswordCLI.exe registry rename-key --key KEY --new-name NAME [--flags 0xN]", L"Rename one registry key.", L"Required: --key, --new-name. Optional: --flags.", L"" },
        { L"redirect", L"set-rules", L"KswordCLI.exe redirect set-rules --blob PATH", L"Load file/registry redirect rules.", L"Required: --blob.", L"" },
        { L"redirect", L"query-status", L"KswordCLI.exe redirect query-status [--limit N]", L"Query redirect runtime state and rules.", L"Optional: --limit.", L"" },
        { L"network", L"set-rules", L"KswordCLI.exe network set-rules --blob PATH", L"Load network rule bytes.", L"Required: --blob.", L"" },
        { L"network", L"query-status", L"KswordCLI.exe network query-status [--limit N]", L"Query network runtime state and rules.", L"Optional: --limit.", L"" },
        { L"network", L"audit", L"KswordCLI.exe network audit [--flags 0xN] [--max-rows N] [--limit N]", L"Query TCP endpoint audit as the default network audit view.", L"Optional: --flags, --max-rows, --limit.", L"Use network wfp or network ndis for chain-specific views." },
        { L"network", L"tcp", L"KswordCLI.exe network tcp [--flags 0xN] [--max-rows N] [--limit N]", L"Query TCP endpoint audit rows.", L"Optional: --flags, --max-rows, --limit.", L"" },
        { L"network", L"udp", L"KswordCLI.exe network udp [--flags 0xN] [--max-rows N] [--limit N]", L"Query UDP endpoint audit rows.", L"Optional: --flags, --max-rows, --limit.", L"" },
        { L"network", L"wfp", L"KswordCLI.exe network wfp [--flags 0xN] [--max-rows N] [--limit N]", L"Query WFP inventory rows.", L"Optional: --flags, --max-rows, --limit.", L"" },
        { L"network", L"ndis", L"KswordCLI.exe network ndis [--flags 0xN] [--max-rows N] [--limit N]", L"Query NDIS chain rows.", L"Optional: --flags, --max-rows, --limit.", L"" },
        { L"network", L"afd", L"KswordCLI.exe network afd [--limit N]", L"Print degraded R3 AFD endpoint fallback evidence.", L"Optional: --limit.", L"No dedicated R0 AFD audit IOCTL is used." },
        { L"network", L"nsi", L"KswordCLI.exe network nsi [--limit N]", L"Print degraded R3 NSI adapter/address fallback evidence.", L"Optional: --limit.", L"No dedicated R0 NSI audit IOCTL is used." },
        { L"keyboard", L"enum-hotkeys", L"KswordCLI.exe keyboard enum-hotkeys [--flags 0xN] [--pid PID] [--max-entries N] [--limit N]", L"Enumerate keyboard hotkeys.", L"Optional: --flags, --pid, --max-entries, --limit.", L"" },
        { L"keyboard", L"enum-hooks", L"KswordCLI.exe keyboard enum-hooks [--flags 0xN] [--pid PID] [--max-entries N] [--limit N]", L"Enumerate keyboard hooks.", L"Optional: --flags, --pid, --max-entries, --limit.", L"" },
        { L"driver", L"integrity", L"KswordCLI.exe driver integrity [--driver NAME] [--module-base VA] [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--limit N]", L"Query driver integrity evidence.", L"Optional: --driver, --module-base, --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --limit.", L"" },
        { L"driver", L"detail", L"KswordCLI.exe driver detail --driver NAME [--flags 0xN] [--max-devices N] [--max-attached N] [--limit N]", L"Query one DriverObject detail projection.", L"Required: --driver. Optional: --flags, --max-devices, --max-attached, --limit.", L"" },
        { L"driver", L"device", L"KswordCLI.exe driver device [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Query driver device stack audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Aliases: driver major, driver fastio." },
        { L"driver", L"major", L"KswordCLI.exe driver major [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Alias for driver device audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Alias: driver device." },
        { L"driver", L"fastio", L"KswordCLI.exe driver fastio [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Alias for driver device audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Alias: driver device." },
        { L"driver", L"unloaded", L"KswordCLI.exe driver unloaded [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--module-base VA] [--limit N]", L"Project MmUnloadedDrivers optional-global evidence.", L"Optional: --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --module-base, --limit.", L"" },
        { L"driver", L"piddb", L"KswordCLI.exe driver piddb [--flags 0xN] [--max-rows N] [--max-idt-vectors N] [--max-devices N] [--max-attached N] [--module-base VA] [--limit N]", L"Project PiDDBCacheTable optional-global evidence.", L"Optional: --flags, --max-rows, --max-idt-vectors, --max-devices, --max-attached, --module-base, --limit.", L"" },
        { L"hardware", L"audit", L"KswordCLI.exe hardware audit [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Query generic hardware device stack audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Alias: hardware pnp." },
        { L"hardware", L"pnp", L"KswordCLI.exe hardware pnp [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Alias for hardware audit.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Alias: hardware audit." },
        { L"hardware", L"input", L"KswordCLI.exe hardware input [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Query input stack audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"" },
        { L"hardware", L"usb", L"KswordCLI.exe hardware usb [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Query USB topology audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"" },
        { L"hwid", L"dispatch-query", L"KswordCLI.exe hwid dispatch-query", L"Query HWID Dispatch hook state.", L"No options.", L"Backed by IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY." },
        { L"hwid", L"dispatch-control", L"KswordCLI.exe hwid dispatch-control --action query|enable|disable|disable-all [--targets LIST] [--dry-run] [--flags 0xN] [--disk-mode custom|random|null] [--mac-mode random|custom] [--disk-serial TEXT] [--disk-product TEXT] [--disk-revision TEXT] [--gpu-serial TEXT] [--permanent-mac TEXT] [--current-mac TEXT] --confirm", L"Control HWID Dispatch hook targets with an explicit confirmation flag.", L"Required: --action and --confirm for non-query actions. Optional: --targets defaults to storage; --dry-run sets request dry-run.", L"Targets: disk, partmgr, mountmgr, nvidia, nsiproxy, storage, network, all. Behavior bits can be passed through --flags." },
        { L"window", L"win32k", L"KswordCLI.exe window win32k [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]", L"Query win32k profile/session status.", L"Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit.", L"" },
        { L"window", L"gui", L"KswordCLI.exe window gui [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]", L"Query GUI window snapshot rows.", L"Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit.", L"" },
        { L"window", L"gui-threads", L"KswordCLI.exe window gui-threads [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]", L"Query GUI thread snapshot rows.", L"Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit.", L"" },
        { L"window", L"hotkeys-pdb", L"KswordCLI.exe window hotkeys-pdb [--flags 0xN] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]", L"Query PDB-backed win32k hotkey chain rows.", L"Optional: --flags, --session-id, --pid, --tid, --max-entries, --limit.", L"Backed by IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB." },
        { L"window", L"hooks-pdb", L"KswordCLI.exe window hooks-pdb [--flags 0xN] [--match legacy|owner|target|both] [--session-id N] [--pid PID] [--tid TID] [--max-entries N] [--limit N]", L"Query PDB-backed win32k hook chain rows.", L"Optional: --flags (default 0x3), --match (overrides only owner/target selector bits in --flags; default legacy), --session-id, --pid, --tid, --max-entries (default 4096; hard maximum 8192), --limit.", L"Backed by IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB; legacy/both require the complete filter to match one side; prints traversal diagnostics." },
        { L"window", L"detail", L"KswordCLI.exe window detail --hwnd HWND [--pid PID] [--tid TID] [--flags 0xN]", L"Query one HWND/tagWND runtime detail packet.", L"Required: --hwnd. Optional: --pid, --tid, --flags.", L"Backed by IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL." },
        { L"window", L"gpu", L"KswordCLI.exe window gpu [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Query GPU/display/watchdog audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Aliases: window display, window watchdog." },
        { L"window", L"display", L"KswordCLI.exe window display [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Alias for window gpu audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Alias: window gpu." },
        { L"window", L"watchdog", L"KswordCLI.exe window watchdog [--profile-flags 0xN] [--max-rows N] [--max-attached N] [--target NAME] [--limit N]", L"Alias for window gpu audit rows.", L"Optional: --profile-flags, --max-rows, --max-attached, --target, --limit.", L"Alias: window gpu." },
        { L"misc", L"security", L"KswordCLI.exe misc security [--flags 0xN]", L"Query security/CI/VBS posture.", L"Optional: --flags.", L"Aliases: misc ci, misc vbs." },
        { L"misc", L"ci", L"KswordCLI.exe misc ci [--flags 0xN]", L"Alias for misc security.", L"Optional: --flags.", L"Alias: misc security." },
        { L"misc", L"vbs", L"KswordCLI.exe misc vbs [--flags 0xN]", L"Alias for misc security.", L"Optional: --flags.", L"Alias: misc security." },
        { L"misc", L"hyperv", L"KswordCLI.exe misc hyperv", L"Query Hyper-V summary posture.", L"No options.", L"" },
        { L"misc", L"applocker", L"KswordCLI.exe misc applocker", L"Query AppLocker/BAM posture.", L"No options.", L"Alias: misc bam." },
        { L"misc", L"bam", L"KswordCLI.exe misc bam", L"Alias for misc applocker.", L"No options.", L"Alias: misc applocker." },
        { L"misc", L"driver-trust", L"KswordCLI.exe misc driver-trust [--flags 0xN] [--max-entries N] [--limit N]", L"Query loaded-driver trust rows.", L"Optional: --flags, --max-entries, --limit.", L"" },
        { L"mutation", L"prepare", L"KswordCLI.exe mutation prepare --target-kind N (--after-hex HEX | --after-file PATH) [--before-hex HEX | --before-file PATH] [--pid PID] [--address VA] [--context N] [--flags 0xN]", L"Prepare a bounded mutation transaction.", L"Required: --target-kind and after payload. Optional: before payload, --pid, --address, --context, --flags.", L"Hex and file payload forms are mutually exclusive per payload." },
        { L"mutation", L"commit", L"KswordCLI.exe mutation commit --transaction-id ID [--flags 0xN]", L"Commit a prepared mutation transaction.", L"Required: --transaction-id. Optional: --flags.", L"" },
        { L"mutation", L"rollback", L"KswordCLI.exe mutation rollback --transaction-id ID [--flags 0xN]", L"Rollback a prepared mutation transaction.", L"Required: --transaction-id. Optional: --flags.", L"" },
        { L"mutation", L"query-audit", L"KswordCLI.exe mutation query-audit [--flags 0xN] [--max-entries N] [--start-sequence N] [--limit N] [--hexdump]", L"Query mutation audit ring entries.", L"Optional: --flags, --max-entries, --start-sequence, --limit, --hexdump.", L"" },
    };

    // sameToken compares an argv token with a metadata token.
    // Inputs: value may be null; expected is a static command token.
    // Processing: uses exact case-sensitive comparison to match dispatch behavior.
    // Returns: true when both tokens contain the same text.
    bool sameToken(const wchar_t* value, const wchar_t* expected)
    {
        return value != nullptr && expected != nullptr && std::wcscmp(value, expected) == 0;
    }

    // isHelpToken reports whether a token requests CLI help.
    // Inputs: raw argv token, possibly null.
    // Processing: accepts the same spellings that dispatch historically treated as help.
    // Returns: true for help, --help, -h, or /?.
    bool isHelpToken(const wchar_t* token)
    {
        return sameToken(token, L"help") ||
               sameToken(token, L"--help") ||
               sameToken(token, L"-h") ||
               sameToken(token, L"/?");
    }

    // findFamilyHelp returns metadata for one top-level family.
    // Inputs: family token from argv.
    // Processing: scans the static help table without side effects.
    // Returns: pointer to metadata or nullptr when the family is unknown.
    const FamilyHelp* findFamilyHelp(const std::wstring& family)
    {
        for (const FamilyHelp& entry : kFamilyHelps)
        {
            if (family == entry.name)
            {
                return &entry;
            }
        }
        return nullptr;
    }

    // printCommandHelpEntry renders detailed help for one command row.
    // Inputs: static CommandHelp metadata.
    // Processing: writes syntax, summary, options, and optional notes to stdout.
    // Returns: no value.
    void printCommandHelpEntry(const CommandHelp& entry)
    {
        std::wcout << L"Command: " << entry.family;
        if (entry.subcommand[0] != L'\0')
        {
            std::wcout << L" " << entry.subcommand;
        }
        std::wcout << L"\n"
                   << L"Syntax:\n  " << entry.syntax << L"\n"
                   << L"Summary:\n  " << entry.summary << L"\n";
        if (entry.options[0] != L'\0')
        {
            std::wcout << L"Options:\n  " << entry.options << L"\n";
        }
        if (entry.notes[0] != L'\0')
        {
            std::wcout << L"Notes:\n  " << entry.notes << L"\n";
        }
    }

    // printFamilyHelp renders all concrete commands for one family.
    // Inputs: top-level family token.
    // Processing: validates the family and lists matching command metadata.
    // Returns: true when the family exists; false otherwise.
    bool printFamilyHelp(const std::wstring& family)
    {
        const FamilyHelp* familyHelp = findFamilyHelp(family);
        if (familyHelp == nullptr)
        {
            std::wcerr << L"error: unknown family '" << family << L"'\n";
            return false;
        }

        std::wcout << L"Family: " << familyHelp->name << L"\n"
                   << L"Summary: " << familyHelp->summary << L"\n"
                   << L"Commands:\n";
        for (const CommandHelp& command : kCommandHelps)
        {
            if (family == command.family)
            {
                std::wcout << L"  " << command.syntax << L"\n"
                           << L"    " << command.summary << L"\n";
            }
        }
        return true;
    }

    // printSpecificCommandHelp renders help for one family/subcommand pair.
    // Inputs: exact family and subcommand tokens from argv.
    // Processing: scans metadata and falls back to family help on misses.
    // Returns: true when a concrete command was found.
    bool printSpecificCommandHelp(const std::wstring& family, const std::wstring& subcommand)
    {
        for (const CommandHelp& command : kCommandHelps)
        {
            if (family == command.family && subcommand == command.subcommand)
            {
                printCommandHelpEntry(command);
                return true;
            }
        }

        std::wcerr << L"error: unknown command '" << family << L" " << subcommand << L"'\n";
        if (findFamilyHelp(family) != nullptr)
        {
            printFamilyHelp(family);
        }
        return false;
    }

    // printUsage prints the CLI command reference.
    // Inputs: none.
    // Processing: groups all registered commands by static command family metadata.
    // Returns: no value; output goes to stdout.
    void printUsage()
    {
        std::wcout
            << L"KswordCLI CLI\n"
            << L"usage: KswordCLI.exe <family> <subcommand> [--named-options]\n"
            << L"       KswordCLI.exe log [--max-frames N]\n"
            << L"       KswordCLI.exe help [family] [subcommand]\n\n"
            << L"Help forms:\n"
            << L"  KswordCLI.exe help\n"
            << L"  KswordCLI.exe help process\n"
            << L"  KswordCLI.exe help process enum\n"
            << L"  KswordCLI.exe process help\n"
            << L"  KswordCLI.exe process enum --help\n\n"
            << L"Families and subcommands:\n";

        for (const FamilyHelp& family : kFamilyHelps)
        {
            std::wcout << L"  " << std::left << std::setw(11) << family.name;
            bool first = true;
            for (const CommandHelp& command : kCommandHelps)
            {
                if (std::wcscmp(family.name, command.family) != 0)
                {
                    continue;
                }
                if (!first)
                {
                    std::wcout << L" | ";
                }
                std::wcout << ((command.subcommand[0] == L'\0') ? L"[no subcommand]" : command.subcommand);
                first = false;
            }
            std::wcout << std::right << L"\n";
        }

        std::wcout
            << L"\nCommon options: --flags 0xN --limit N --hexdump\n"
            << L"Use 'KswordCLI.exe help <family> <subcommand>' for exact syntax.\n"
            << L"Examples:\n"
            << L"  KswordCLI.exe capability query-driver-capabilities\n"
            << L"  KswordCLI.exe process enum --flags 0x1 --limit 32\n"
            << L"  KswordCLI.exe memory read-va --pid 1234 --address 0x7ff700000000 --bytes 64 --hexdump\n"
            << L"  KswordCLI.exe help memory read-va\n";
    }

    // printHelpForTarget handles help command argument routing.
    // Inputs: argc/argv from wmain and index of the first help target token.
    // Processing: prints overview, family help, or exact command help without IOCTLs.
    // Returns: process exit code; zero means help text was found and printed.
    int printHelpForTarget(int argc, wchar_t* argv[], int startIndex)
    {
        if (startIndex >= argc || argv[startIndex] == nullptr || isHelpToken(argv[startIndex]))
        {
            printUsage();
            return 0;
        }

        const std::wstring kFamily = argv[startIndex];
        if (startIndex + 1 >= argc || argv[startIndex + 1] == nullptr || isHelpToken(argv[startIndex + 1]))
        {
            return printFamilyHelp(kFamily) ? 0 : 1;
        }

        const std::wstring kSubcommand = argv[startIndex + 1];
        return printSpecificCommandHelp(kFamily, kSubcommand) ? 0 : 1;
    }

    // hasTrailingHelpToken detects inline help requests after a command target.
    // Inputs: argc/argv plus the first token to inspect.
    // Processing: scans remaining tokens for help spellings and does not parse options.
    // Returns: true when any trailing token asks for help.
    bool hasTrailingHelpToken(int argc, wchar_t* argv[], int startIndex)
    {
        for (int index = startIndex; index < argc; ++index)
        {
            if (isHelpToken(argv[index]))
            {
                return true;
            }
        }
        return false;
    }
}
