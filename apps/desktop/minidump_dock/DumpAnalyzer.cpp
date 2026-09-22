// ============================================================
// DumpAnalyzer.cpp
// Purpose:
// - Implement the comprehensive diagnostics declared in DumpAnalyzer.h;
// - Attribution flow: Collect evidence → accumulate weights by module → downweight system modules → sort
//   and select the top name → combine stop code/exception code to generate conclusions and recommendations.
// - All conclusions are based solely on facts obtained from this analysis; no external queries are performed, no
//   assertions are made on whether the driver actually has a bug, only credibility and evidence chains are provided.
// ============================================================

#include "DumpAnalyzer.h"

#include "DumpBugCheckText.h"
#include "MinidumpCodeText.h"

#include <QHash>

#include <algorithm>

namespace ks::minidump
{
    namespace
    {
        // kSystemModules: Names of core modules bundled with the OS (case-insensitive comparison).
        // These modules almost certainly appear on any kernel/user-mode call stack. Attributing them with
        // the highest weight would only yield trivial results like 'ntoskrnl.exe caused the BSOD'.
        // Therefore, their weight is uniformly reduced to allow third-party drivers/components to surface.
        const char* const kSystemModules[] = {
            // Kernel and HAL
            "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe",
            "hal.dll", "halmacpi.dll", "halacpi.dll",
            // Kernel infrastructure
            "win32k.sys", "win32kbase.sys", "win32kfull.sys", "ci.dll",
            "clfs.sys", "cng.sys", "ksecdd.sys", "msrpc.sys", "tm.sys",
            "pshed.dll", "bootvid.dll", "kdcom.dll", "werkernel.sys",
            // Common system driver stack
            "ntfs.sys", "fltmgr.sys", "volsnap.sys", "volmgr.sys", "partmgr.sys",
            "storport.sys", "storahci.sys", "disk.sys", "classpnp.sys",
            "acpi.sys", "pci.sys", "pcw.sys", "wdf01000.sys", "wdfldr.sys",
            "ndis.sys", "netio.sys", "tcpip.sys", "afd.sys", "http.sys",
            "dxgkrnl.sys", "dxgmms1.sys", "dxgmms2.sys", "watchdog.sys",
            "usbxhci.sys", "usbport.sys", "usbhub.sys", "ucx01000.sys",
            // User-mode core.
            "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
            "gdi32.dll", "gdi32full.dll", "advapi32.dll", "rpcrt4.dll",
            "combase.dll", "ole32.dll", "oleaut32.dll", "sechost.dll",
            "msvcrt.dll", "ucrtbase.dll", "shcore.dll", "shell32.dll",
            "win32u.dll", "wow64.dll", "wow64cpu.dll", "wow64win.dll",
        };

        // kFaultingAddressWeight: Weight for a hit on the crashing instruction address; this is the strongest evidence.
        constexpr int kFaultingAddressWeight = 100;
        // kContextFrameWeight: Weight of the stack frame directly provided by CONTEXT, at the same level as the crash address.
        constexpr int kContextFrameWeight = 100;
        // kScannedFrameBaseWeight/kScannedFrameDecay: Base weight and per-frame decay for scanned stack frames.
        constexpr int kScannedFrameBaseWeight = 60;
        constexpr int kScannedFrameDecay = 3;
        // kScannedFrameMinWeight: Lower bound after attenuation; deeper frames still retain a small number of votes.
        constexpr int kScannedFrameMinWeight = 8;
        // kParameterAddressWeight: Address hit weight within BugCheck/exception parameters.
        constexpr int kParameterAddressWeight = 40;
        // kUnloadedBonus: Extra weight for hitting an unloaded module—calling a module after it has
        // been unloaded is a very strong root cause signal, often sufficient to conclude the case.
        constexpr int kUnloadedBonus = 70;
        // kSystemModuleDivisor: Weight divisor for system core modules.
        constexpr int kSystemModuleDivisor = 5;
        // kMaxBlameEntries: Maximum number of candidates retained in the conclusion.
        constexpr std::size_t kMaxBlameEntries = 6;
        // kMaxEvidencePerModule: Maximum number of evidence entries recorded per candidate to prevent screen flooding.
        constexpr int kMaxEvidencePerModule = 6;

        // Hex function: Formats the value as an uppercase hexadecimal string prefixed with 0x.
        QString hex(const std::uint64_t value)
        {
            return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
        }

        // BlameAccumulator purpose: Intermediate container for accumulating evidence weights by module name.
        struct BlameAccumulator
        {
            // Candidate: Accumulated state of a candidate module.
            // bestWeight records the weight of the strongest evidence so far, used to determine eligibility for setting the representative address.
            struct Candidate
            {
                BlameEntry entry;   // entry: candidate entry for external output.
                int bestWeight = 0; // bestWeight: The maximum single-evidence weight seen so far.
            };

            // add purpose: Register a hit evidence entry.
            // Accepts note (address interpretation result), weight (evidence weight for this entry), and evidence (evidence description).
            void add(const AddressNote& note, const int weight, const QString& evidence)
            {
                if (note.moduleName.isEmpty() || weight <= 0)
                {
                    return;
                }
                // key: Module name in lowercase to avoid splitting the same module into two candidates due to case differences.
                const QString kKey = note.moduleName.toLower();
                Candidate& candidate = entries[kKey];
                BlameEntry& entry = candidate.entry;
                if (entry.moduleName.isEmpty())
                {
                    entry.moduleName = note.moduleName;
                    entry.moduleBase = note.moduleBase;
                    entry.address = note.moduleBase + note.offset;
                    entry.offset = note.offset;
                    entry.unloadedModule = note.unloadedModule;
                }
                // System modules are downweighted: their presence in the stack is normal and cannot be used as definitive evidence.
                int effectiveWeight = isSystemModule(note.moduleName)
                    ? weight / kSystemModuleDivisor
                    : weight;
                if (note.unloadedModule)
                {
                    // Weighting must correlate with evidence strength: If the crash point falls within an unloaded module, it
                    // is almost conclusive and deserves full weight; if it merely appears in a scan frame, it is likely just
                    // residual stack data, and full weight would cause it to unconditionally rank first among candidates.
                    effectiveWeight += weight >= kContextFrameWeight
                        ? kUnloadedBonus
                        : kUnloadedBonus / 4;
                    entry.unloadedModule = true;
                }
                entry.weight += effectiveWeight;
                if (entry.evidence.size() < kMaxEvidencePerModule && !evidence.isEmpty())
                {
                    entry.evidence.append(evidence);
                }
                // The address is taken over only by the 'strongest evidence so far'.
                // If changed to 'overwrite upon reaching a threshold', later secondary evidence (e.g., the 3rd frame of the call stack) would
                // displace the crash instruction address, causing the offset displayed in the candidate to no longer reflect the crash point.
                if (effectiveWeight > candidate.bestWeight)
                {
                    candidate.bestWeight = effectiveWeight;
                    entry.address = note.moduleBase + note.offset;
                    entry.offset = note.offset;
                }
            }

            // sorted purpose: Export candidate list in descending order by weight, up to kMaxBlameEntries entries.
            // QHash traversal order is unstable; use module name as a tie-breaker during sorting to ensure reproducible output.
            std::vector<BlameEntry> sorted() const
            {
                std::vector<BlameEntry> list;
                list.reserve(static_cast<std::size_t>(entries.size()));
                for (auto iterator = entries.cbegin(); iterator != entries.cend(); ++iterator)
                {
                    list.push_back(iterator.value().entry);
                }
                std::sort(
                    list.begin(),
                    list.end(),
                    [](const BlameEntry& left, const BlameEntry& right)
                    {
                        if (left.weight != right.weight)
                        {
                            return left.weight > right.weight;
                        }
                        return left.moduleName < right.moduleName;
                    });
                if (list.size() > kMaxBlameEntries)
                {
                    list.resize(kMaxBlameEntries);
                }
                return list;
            }

            QHash<QString, Candidate> entries; // entries: Module name (lowercase) → accumulating candidates.
        };

        // categoryFromExceptionCode: Categorizes user-mode exception codes for use in conclusions.
        // Input: exception code; Return: the closest fault category.
        BugCheckCategory categoryFromExceptionCode(const std::uint32_t code)
        {
            switch (code)
            {
            case 0xC0000005u: // EXCEPTION_ACCESS_VIOLATION
            case 0xC0000006u: // EXCEPTION_IN_PAGE_ERROR
            case 0xC00000FDu: // EXCEPTION_STACK_OVERFLOW
                return BugCheckCategory::kMemory;
            case 0xC0000374u: // STATUS_HEAP_CORRUPTION
            case 0xC0000409u: // STATUS_STACK_BUFFER_OVERRUN
            case 0xC0000602u: // STATUS_FAIL_FAST_EXCEPTION
                return BugCheckCategory::kSecurity;
            case 0xC0000135u: // STATUS_DLL_NOT_FOUND
            case 0xC0000138u: // STATUS_ORDINAL_NOT_FOUND
            case 0xC0000139u: // STATUS_ENTRYPOINT_NOT_FOUND
            case 0xC0000142u: // STATUS_DLL_INIT_FAILED
            case 0xC000007Bu: // STATUS_INVALID_IMAGE_FORMAT
                return BugCheckCategory::kBoot;
            default:
                return BugCheckCategory::kSoftware;
            }
        }

        // userExceptionSuggestions purpose: provide troubleshooting suggestions based on user-mode exception codes.
        // Takes code (exception code); returns several Chinese suggestions.
        QStringList userExceptionSuggestions(const std::uint32_t code)
        {
            switch (code)
            {
            case 0xC0000005u:
                return {
                    QStringLiteral("确认崩溃地址所属模块：若是自家模块，用同版本 PDB 在调试器里定位到具体函数。"),
                    QStringLiteral("访问地址落在 NULL 页时，检查该指针的来源函数是否漏判返回值失败。"),
                    QStringLiteral("访问地址是哨兵值（0xCCCC…/0xDDDD…/0xFEEEFEEE）时，按“未初始化”或“释放后使用”方向排查。"),
                    QStringLiteral("崩溃点在第三方模块（注入的钩子、杀软、输入法、录屏组件）时，先在干净环境复现以排除干扰。"),
                };
            case 0xC0000374u:
                return {
                    QStringLiteral("堆损坏的崩溃点通常离真正的越界写很远，必须开页堆定位：gflags /p /enable <exe> /full。"),
                    QStringLiteral("用 Application Verifier 打开堆检查，能在越界发生的那一刻断下来。"),
                    QStringLiteral("重点检查最近改动过的缓冲区拷贝、数组下标与 realloc 之后的旧指针使用。"),
                };
            case 0xC0000409u:
            case 0xC0000602u:
                return {
                    QStringLiteral("这是主动终止而非被动崩溃：参数 1 的 fast-fail 子码说明了触发的具体安全检查。"),
                    QStringLiteral("子码为栈 cookie 检查失败时，查栈上缓冲区的写入长度计算。"),
                    QStringLiteral("子码为 CFG/间接调用检查失败时，查函数指针是否被覆盖或指向非法目标。"),
                };
            case 0xC00000FDu:
                return {
                    QStringLiteral("检查是否存在无限递归：崩溃线程的调用栈里会出现同一模块的地址反复出现。"),
                    QStringLiteral("检查是否在栈上分配了超大对象或用了过大的 alloca/可变长数组。"),
                    QStringLiteral("线程栈保留大小不足时，可通过链接选项 /STACK 或 CreateThread 参数调大。"),
                };
            case 0xC0000135u:
            case 0xC0000138u:
            case 0xC0000139u:
            case 0xC0000142u:
            case 0xC000007Bu:
                return {
                    QStringLiteral("这是加载期失败而非运行期崩溃：核对依赖 DLL 的位数、版本与部署路径。"),
                    QStringLiteral("用依赖查看工具比对目标机上的实际加载结果，注意 SxS/清单与运行库版本。"),
                    QStringLiteral("查看模块列表里该 DLL 是否被加载到了非预期路径（DLL 劫持）。"),
                };
            case 0xE06D7363u:
                return {
                    QStringLiteral("这是一个未被接住的 C++ 异常：崩溃点是抛出点而不是缺陷点。"),
                    QStringLiteral("参数里的异常对象指针配合 PDB 可以还原异常类型与消息。"),
                    QStringLiteral("检查线程入口/回调边界是否缺少 catch，跨模块抛异常尤其容易漏接。"),
                };
            default:
                return {
                    QStringLiteral("用同版本 PDB 在调试器中打开本转储，可把崩溃点从“模块+偏移”还原到具体函数与行号。"),
                    QStringLiteral("对照模块列表确认崩溃模块的版本，与已知问题的修复版本比对。"),
                };
            }
        }
    }

    bool isSystemModule(const QString& moduleName)
    {
        if (moduleName.isEmpty())
        {
            return false;
        }
        // baseName: Compare only the filename portion and normalize to lowercase.
        const QString kBaseName = baseModuleName(moduleName).toLower();
        for (const char* const kName : kSystemModules)
        {
            if (kBaseName == QLatin1String(kName))
            {
                return true;
            }
        }
        return false;
    }

    QString analysisConfidenceText(const AnalysisConfidence confidence)
    {
        switch (confidence)
        {
        case AnalysisConfidence::kHigh:   return QStringLiteral("高（崩溃指令直接落在该模块内）");
        case AnalysisConfidence::kMedium: return QStringLiteral("中（有地址级证据，但来自栈扫描或指向系统模块）");
        case AnalysisConfidence::kLow:    return QStringLiteral("低（仅按停止码分类推断，无地址级证据）");
        default:                         return QStringLiteral("无结论");
        }
    }

    void buildAnalysis(const ModuleIndex& modules, DumpParseResult& result)
    {
        DumpAnalysis analysis{};
        BlameAccumulator accumulator;
        // strongEvidenceModules: Module names (lowercase) that have obtained 'crash-instruction-level evidence'.
        // Recording just a boolean is insufficient: the credibility claim states 'the crashing instruction falls directly within this
        // module', but the top candidate may not be the module containing that strong evidence—Module A appears at the crash point,
        // while Module B reaches a higher score via a stack of scanned frames; assigning 'High' to B in this case would be a lie.
        QStringList strongEvidenceModules;

        // ---------- Evidence 1: Faulting instruction address ----------
        if (result.faultingAddress != 0)
        {
            const AddressNote kNote = modules.resolve(result.faultingAddress);
            if (!kNote.moduleName.isEmpty())
            {
                strongEvidenceModules.append(kNote.moduleName.toLower());
                accumulator.add(
                    kNote,
                    kFaultingAddressWeight,
                    QStringLiteral("崩溃指令地址 %1 位于 %2")
                        .arg(hex(result.faultingAddress), kNote.symbolText));
            }
        }

        // ---------- Evidence 2: Call stack of the crashing thread ---------- Only the crashing thread's
        // stack participates in attribution. A dump typically contains hundreds of threads; most are stuck at
        // their respective wait points. Including their stack frames would drown the vote count in irrelevant
        // modules, causing the final conclusion to always point to ubiquitous modules like ntdll/kernel32.
        // Kernel dumps do not have a thread ID; all frames have threadId = 0, which is equivalent to the 'crashing thread'.
        const std::uint32_t kBlameThreadId =
            result.kind == DumpKind::kUserMinidump ? result.faultingThreadId : 0u;
        for (const StackFrameEntry& frame : result.stackFrames)
        {
            if (frame.moduleName.isEmpty() || frame.threadId != kBlameThreadId)
            {
                continue;
            }
            // Re-parse to obtain the accurate base/offset, without relying on the already-formatted text in the frame.
            const AddressNote kNote = modules.resolve(frame.address);
            if (kNote.moduleName.isEmpty())
            {
                continue;
            }
            if (frame.fromContext)
            {
                strongEvidenceModules.append(kNote.moduleName.toLower());
                accumulator.add(
                    kNote,
                    kContextFrameWeight,
                    QStringLiteral("崩溃线程栈顶为 %1").arg(kNote.symbolText));
            }
            else
            {
                // Frames closer to the stack top are more likely part of the real call chain; weights decay per frame.
                const int kWeight = std::max(
                    kScannedFrameMinWeight,
                    kScannedFrameBaseWeight - frame.index * kScannedFrameDecay);
                accumulator.add(
                    kNote,
                    kWeight,
                    QStringLiteral("疑似调用栈第 %1 帧为 %2")
                        .arg(frame.index)
                        .arg(kNote.symbolText));
            }
        }

        // ---------- Evidence 3: Addresses in the bug check code / exception parameters ----------
        if (result.kind != DumpKind::kUserMinidump && result.bugCheckCode != 0)
        {
            for (int index = 0; index < 4; ++index)
            {
                const std::uint64_t kParameter = result.bugCheckParameters[index];
                if (kParameter == 0)
                {
                    continue;
                }
                const AddressNote kNote = modules.resolve(kParameter);
                if (kNote.moduleName.isEmpty())
                {
                    continue;
                }
                accumulator.add(
                    kNote,
                    kParameterAddressWeight,
                    QStringLiteral("停止码参数 %1（%2）落在 %3")
                        .arg(index + 1)
                        .arg(hex(kParameter), kNote.symbolText));
            }
        }

        analysis.blame = accumulator.sorted();

        // ---------- Assembly Conclusion ----------
        // topBlame: The candidate with the highest weight; null indicates no address-level evidence exists.
        const BlameEntry* topBlame = analysis.blame.empty() ? nullptr : &analysis.blame.front();
        // suspectThirdParty: Whether the top blame is a third-party module determines the conclusion scope.
        const bool kSuspectThirdParty =
            topBlame != nullptr && !isSystemModule(topBlame->moduleName);

        if (result.kind == DumpKind::kUserMinidump)
        {
            // ===== User Mode: Exception Code as the Main Thread =====
            const std::uint32_t kCode = result.exceptionCode;
            const QString kCodeName = exceptionCodeName(kCode);
            const QString kMeaning = exceptionCodeMeaning(kCode);

            if (kCode == 0)
            {
                // No exception record doesn't mean there's nothing to say: this conclusion is exactly what the user needs to
                // see; otherwise, they'd be searching a list of threads and modules for a crash point that doesn't exist.
                // Leave fault classification empty—snapshot dumps have no 'fault' to classify; forcing one would be misleading.
                analysis.headline = QStringLiteral(
                    "本转储不含异常记录：多半是主动生成的快照（任务管理器/ProcDump），而不是崩溃现场；"
                    "下面的线程、模块与内存信息仍然有效，但没有崩溃点可供归因。");
                analysis.confidence = AnalysisConfidence::kNone;
            }
            else
            {
                analysis.category = bugCheckCategoryText(categoryFromExceptionCode(kCode));
                // headline: module + exception code name + meaning, concisely explaining 'who crashed where and why' in one sentence.
                // Priority is given to the crashing instruction address itself; if it cannot be attributed to a module, fall back to the candidate with the highest weight.
                const QString kFaultSymbol = result.faultingAddress != 0
                    ? modules.symbolText(result.faultingAddress)
                    : QString();
                QString where = kFaultSymbol;
                if (where.isEmpty())
                {
                    // When the crash address cannot be attributed to a module, do not substitute the offset of the top candidate to fill
                    // this message—that offset comes from a stack-scanned frame and is unrelated to the crash point. Doing so would directly
                    // contradict the report's statement that "the crash instruction address does not fall within any known module range."
                    where = result.faultingAddress != 0
                        ? QStringLiteral("%1（不属于任何已加载模块）")
                            .arg(hex(result.faultingAddress))
                        : QStringLiteral("未知位置");
                }
                analysis.headline = QStringLiteral("进程崩溃于 %1，异常 %2%3。")
                    .arg(where)
                    .arg(hex(kCode))
                    .arg(kCodeName.isEmpty() ? QString() : QStringLiteral(" (%1)").arg(kCodeName));
                if (!kMeaning.isEmpty())
                {
                    analysis.findings.append(kMeaning);
                }
            }
            analysis.suggestions = userExceptionSuggestions(kCode);
        }
        else
        {
            // ===== Kernel mode: centered on stop codes =====
            const std::uint32_t kCode = result.bugCheckCode;
            const QString kCodeName = bugCheckCodeNameEx(kCode);
            const QString kMeaning = bugCheckMeaning(kCode);
            const BugCheckCategory kCategory = bugCheckCategoryOf(kCode);
            analysis.category = bugCheckCategoryText(kCategory);

            // codeText: Stop code value + official name, used repeatedly in conclusions and evidence.
            const QString kCodeText = kCodeName.isEmpty()
                ? hex(kCode)
                : QStringLiteral("%1 (%2)").arg(hex(kCode), kCodeName);
            if (kSuspectThirdParty)
            {
                analysis.headline = QStringLiteral("疑似由 %1 引起的 %2。")
                    .arg(topBlame->moduleName, kCodeText);
            }
            else if (topBlame != nullptr)
            {
                analysis.headline = QStringLiteral("%1；崩溃点位于系统模块 %2，通常说明真正的触发者在调用链更上游。")
                    .arg(kCodeText, topBlame->moduleName);
            }
            else
            {
                analysis.headline = QStringLiteral("%1；本转储未能把崩溃地址归属到任何模块。")
                    .arg(kCodeText);
            }
            if (!kMeaning.isEmpty())
            {
                analysis.findings.append(kMeaning);
            }
            analysis.suggestions = bugCheckSuggestions(kCode);

            // Hardware-class bug check additional note: changing drivers is ineffective for this issue.
            if (kCategory == BugCheckCategory::kHardware)
            {
                analysis.findings.append(QStringLiteral(
                    "该停止码由硬件错误报告机制产生，通常不是某个驱动的代码缺陷，"
                    "优先按内存/CPU/供电/超频方向排查。"));
            }
        }

        // ---------- Evidence Chain Supplement ----------
        if (result.faultingAddress != 0)
        {
            const QString kSymbol = modules.symbolText(result.faultingAddress);
            analysis.findings.append(
                kSymbol.isEmpty()
                    ? QStringLiteral("崩溃指令地址 %1（未落在任何已知模块区间内，可能是已释放的代码页或动态生成的代码）。")
                        .arg(hex(result.faultingAddress))
                    : QStringLiteral("崩溃指令地址 %1 位于 %2。")
                        .arg(hex(result.faultingAddress), kSymbol));
        }
        // A hit on an unloaded module warrants a separate warning, but the wording must not be an assertion:
        // The stack is full of historical residual values. An address of an old module appearing on the stack might mean it is still being called, or it might
        // just be garbage that hasn't been overwritten yet. Conclusions are only drawn when it is simultaneously evidence at the crash instruction level.
        for (const BlameEntry& blame : analysis.blame)
        {
            if (!blame.unloadedModule)
            {
                continue;
            }
            const bool kFromCrashPoint =
                strongEvidenceModules.contains(blame.moduleName.toLower());
            analysis.findings.append(
                kFromCrashPoint
                    ? QStringLiteral("崩溃点落在已卸载的模块 %1 内：驱动卸载后仍有代码在执行，"
                        "这是典型的“卸载时未取消挂起操作”缺陷。")
                        .arg(blame.moduleName)
                    : QStringLiteral("栈上出现了已卸载模块 %1 的地址。这可能说明它卸载后仍被回调，"
                        "也可能只是栈上尚未被覆盖的残留值——需要结合是否反复出现来判断。")
                        .arg(blame.moduleName));
            break;
        }
        if (!result.stackFrames.empty())
        {
            // faultingFrames: Number of frames belonging to the crashing thread—only these are used for attribution; the report must clarify this.
            std::size_t faultingFrames = 0;
            for (const StackFrameEntry& frame : result.stackFrames)
            {
                if (frame.threadId == kBlameThreadId)
                {
                    ++faultingFrames;
                }
            }
            analysis.findings.append(
                QStringLiteral("调用栈由栈内存扫描重建（无符号），崩溃线程 %1 帧、全部线程共 %2 帧；"
                    "顺序为近似值且可能含残留帧，归因只采用崩溃线程的帧。")
                    .arg(faultingFrames)
                    .arg(result.stackFrames.size()));
        }

        // ---------- Confidence Level ----------
        if (topBlame == nullptr)
        {
            analysis.confidence = result.bugCheckCode != 0 || result.exceptionCode != 0
                ? AnalysisConfidence::kLow
                : AnalysisConfidence::kNone;
        }
        else if (kSuspectThirdParty &&
                 strongEvidenceModules.contains(topBlame->moduleName.toLower()))
        {
            analysis.confidence = AnalysisConfidence::kHigh;
        }
        else
        {
            analysis.confidence = AnalysisConfidence::kMedium;
        }
        // User-mode snapshots without exception records are not given confidence; it was already set to None above, so do not overwrite it here.
        if (result.kind == DumpKind::kUserMinidump && result.exceptionCode == 0)
        {
            analysis.confidence = AnalysisConfidence::kNone;
        }

        result.analysis = std::move(analysis);
    }
}
