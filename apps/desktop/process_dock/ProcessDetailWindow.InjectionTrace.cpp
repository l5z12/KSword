#include "ProcessDetailWindow.InternalCommon.h"

#include "../../../shared/platform/process/InjectionTraceCollector.h"

#include <QBrush>
#include <QFont>
#include <QVariant>

#include <map>

using namespace process_detail_window_internal;

namespace
{
    namespace ev = ksword::evidence;

    QString injectionText(const char* const key, const QString& sourceText)
    {
        static_cast<void>(key);
        return ks::i18n::sourceText(sourceText);
    }

    QString hex64(const ev::OptionalU64& value)
    {
        if (!value.present)
        {
            // Unknown is unknown: never display 0x0, as it would be misread as 'address is 0'.
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value.value), 0, 16)
            .toUpper()
            .replace(QStringLiteral("0X"), QStringLiteral("0x"));
    }

    QString sizeText(const ev::OptionalU64& value)
    {
        if (!value.present)
        {
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value.value), 0, 16).toUpper()
            .replace(QStringLiteral("0X"), QStringLiteral("0x"));
    }

    // FILETIME (100ns since 1601-01-01) -> Local time text. Unknown remains unknown; do not convert to 1601.
    QString firstObservedText(const ev::OptionalU64& utc100ns)
    {
        if (!utc100ns.present)
        {
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        constexpr std::uint64_t kUnixEpochIn100ns = 116444736000000000ULL;
        if (utc100ns.value < kUnixEpochIn100ns)
        {
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        const qint64 kUnixMilliseconds =
            static_cast<qint64>((utc100ns.value - kUnixEpochIn100ns) / 10000ULL);
        return QDateTime::fromMSecsSinceEpoch(kUnixMilliseconds, QTimeZone::UTC)
            .toLocalTime()
            .toString(Qt::ISODate);
    }

    QString conclusionText(const ev::AnalysisConclusion conclusion)
    {
        switch (conclusion)
        {
        case ev::AnalysisConclusion::kNoEvidence:
            return injectionText(
                "process.detail.injection.conclusion.no_evidence",
                QStringLiteral("没有可用观测（不是\"未被注入\"）"));
        case ev::AnalysisConclusion::kNoDifferenceObserved:
            return injectionText(
                "process.detail.injection.conclusion.no_difference",
                QStringLiteral("已覆盖范围内未发现相应异常（不是\"从未被注入\"）"));
        case ev::AnalysisConclusion::kDifferenceObserved:
            return injectionText(
                "process.detail.injection.conclusion.difference",
                QStringLiteral("观测到差异"));
        case ev::AnalysisConclusion::kIndeterminate:
        default:
            return injectionText(
                "process.detail.injection.conclusion.indeterminate",
                QStringLiteral("有观测但不足以判断"));
        }
    }

    QColor conclusionColor(const ev::AnalysisConclusion conclusion)
    {
        switch (conclusion)
        {
        case ev::AnalysisConclusion::kDifferenceObserved:
            return ksword_theme::errorColor();
        case ev::AnalysisConclusion::kIndeterminate:
            return ksword_theme::warningColor();
        case ev::AnalysisConclusion::kNoDifferenceObserved:
            return ksword_theme::successColor();
        case ev::AnalysisConclusion::kNoEvidence:
        default:
            return ksword_theme::textSecondaryColor();
        }
    }

    QString ruleText(const std::string& ruleId)
    {
        if (ruleId == ev::kRuleIdDynamicCodeRegion)
        {
            return injectionText("process.detail.injection.rule.dynamic_code",
                                 QStringLiteral("动态/非映像可执行内存"));
        }
        if (ruleId == ev::kRuleIdImageBytesUnexplained)
        {
            return injectionText("process.detail.injection.rule.image_diff",
                                 QStringLiteral("映像代码与可靠参考不同"));
        }
        if (ruleId == ev::kRuleIdImageReferenceUncertain)
        {
            return injectionText("process.detail.injection.rule.image_reference_uncertain",
                                 QStringLiteral("映像有差异但参考不确定"));
        }
        if (ruleId == ev::kRuleIdImageWithoutLoaderEntry)
        {
            return injectionText("process.detail.injection.rule.image_without_loader",
                                 QStringLiteral("映像映射无加载器项"));
        }
        if (ruleId == ev::kRuleIdLoaderEntryWithoutMapping)
        {
            return injectionText("process.detail.injection.rule.loader_without_mapping",
                                 QStringLiteral("加载器项无合理映射"));
        }
        if (ruleId == ev::kRuleIdModuleIdentityMismatch)
        {
            return injectionText("process.detail.injection.rule.module_identity",
                                 QStringLiteral("模块名称/大小不一致"));
        }
        if (ruleId == ev::kRuleIdMainImageConflict)
        {
            return injectionText("process.detail.injection.rule.main_image_conflict",
                                 QStringLiteral("主映像身份自相矛盾"));
        }
        if (ruleId == ev::kRuleIdThreadStartOutsideImage)
        {
            return injectionText("process.detail.injection.rule.thread_outside_image",
                                 QStringLiteral("线程起点不在模块代码内"));
        }
        if (ruleId == ev::kRuleIdThreadStartUnknown)
        {
            return injectionText("process.detail.injection.rule.thread_unknown",
                                 QStringLiteral("线程起点未采集到"));
        }
        if (ruleId == ev::kRuleIdThreadStartTrampoline)
        {
            return injectionText("process.detail.injection.rule.thread_trampoline",
                                 QStringLiteral("线程入口立即跳出本模块"));
        }
        if (ruleId == ev::kRuleIdPayloadStructure)
        {
            return injectionText("process.detail.injection.rule.payload_structure",
                                 QStringLiteral("非映像内存含载荷结构"));
        }
        if (ruleId == ev::kRuleIdKernelRegionHiddenFromR3)
        {
            return injectionText("process.detail.injection.rule.kernel_hidden",
                                 QStringLiteral("内核 VAD 有、用户态查询没有"));
        }
        if (ruleId == ev::kRuleIdKernelRegionMissingInVad)
        {
            return injectionText("process.detail.injection.rule.kernel_missing_vad",
                                 QStringLiteral("用户态有、内核 VAD 没有"));
        }
        if (ruleId == ev::kRuleIdKernelExecutableBeyondView)
        {
            return injectionText("process.detail.injection.rule.kernel_exec_beyond",
                                 QStringLiteral("页表说可执行，其它视图说不可执行"));
        }
        if (ruleId == ev::kRuleIdKernelVadLinkBroken)
        {
            return injectionText("process.detail.injection.rule.vad_link_broken",
                                 QStringLiteral("内存区域清单被人动过手脚"));
        }
        return QString::fromStdString(ruleId);
    }

    QString regionTypeText(const ev::RegionType type)
    {
        switch (type)
        {
        case ev::RegionType::kImage: return QStringLiteral("IMAGE");
        case ev::RegionType::kMapped: return QStringLiteral("MAPPED");
        case ev::RegionType::kPrivate: return QStringLiteral("PRIVATE");
        case ev::RegionType::kUnknown:
        default:
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
    }

    // The protection text must strictly follow the four ExecuteProtection levels combined with the read/write bit; do not use any bitwise AND checks for executability.
    QString protectionText(const ev::RegionProtection& protection)
    {
        if (!protection.rawValue.present)
        {
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        const ev::ProtectionFacts kFacts = ev::classifyWin32Protection(protection.rawValue);
        if (kFacts.unrecognizedBase)
        {
            return injectionText("process.detail.injection.protect.unrecognized",
                                 QStringLiteral("无法识别(0x%1)"))
                .arg(static_cast<qulonglong>(protection.rawValue.value), 0, 16);
        }
        QString text;
        text += kFacts.readable ? QChar('R') : QChar('-');
        text += kFacts.writable ? QChar('W') : QChar('-');
        text += ev::executeProtectionIsExecutable(kFacts.execute) ? QChar('X') : QChar('-');
        if (kFacts.copyOnWrite)
        {
            text += QStringLiteral("C");
        }
        if (kFacts.guard)
        {
            text += QStringLiteral("+GUARD");
        }
        if (kFacts.noAccess)
        {
            text = QStringLiteral("NOACCESS");
        }
        return text;
    }

    QString confidenceText(const ev::EvidenceConfidence confidence)
    {
        switch (confidence)
        {
        case ev::EvidenceConfidence::kCorroboratedIndependent:
            return injectionText("process.detail.injection.confidence.corroborated",
                                 QStringLiteral("多来源互证"));
        case ev::EvidenceConfidence::kSingleObservation:
            return injectionText("process.detail.injection.confidence.single",
                                 QStringLiteral("单一观测"));
        case ev::EvidenceConfidence::kInputIncomplete:
        default:
            return injectionText("process.detail.injection.confidence.incomplete",
                                 QStringLiteral("输入不完整"));
        }
    }

    QString exceptionText(const ev::ExceptionMatchResult& exception)
    {
        if (exception.match == ev::ExceptionMatch::kMatched)
        {
            return injectionText("process.detail.injection.exception.matched",
                                 QStringLiteral("已由例外解释：%1"))
                .arg(QString::fromStdString(exception.ruleId));
        }
        if (exception.match == ev::ExceptionMatch::kNoRule)
        {
            return injectionText("process.detail.injection.exception.none",
                                 QStringLiteral("无例外规则"));
        }
        return injectionText("process.detail.injection.exception.unmatched",
                             QStringLiteral("未命中例外（%1）"))
            .arg(QString::fromLatin1(ev::exceptionMatchName(exception.match)));
    }

    // Gap key -> user-readable 'this item could not be found'. Defaults to the original key for unknown items instead of hiding them.
    QString gapText(const std::string& key)
    {
        if (key == ev::kGapAddressSpaceIncomplete)
        {
            return injectionText("process.detail.injection.gap.address_space",
                                 QStringLiteral("地址空间枚举不完整或有读不到的字节"));
        }
        if (key == ev::kGapLoaderViewUnavailable)
        {
            return injectionText("process.detail.injection.gap.loader_view",
                                 QStringLiteral("加载器模块列表不可用，缺项推断已停用"));
        }
        if (key == ev::kGapImageViewUnavailable)
        {
            return injectionText("process.detail.injection.gap.image_view",
                                 QStringLiteral("映像映射视图不完整，缺项推断已停用"));
        }
        if (key == ev::kGapPayloadViewUnavailable)
        {
            return injectionText("process.detail.injection.gap.payload_view",
                                 QStringLiteral("非映像载荷候选视图不完整"));
        }
        if (key == ev::kGapMappedPathUnavailable)
        {
            return injectionText("process.detail.injection.gap.mapped_path",
                                 QStringLiteral("部分映射来源路径查询失败（不等于\"无文件植入\"）"));
        }
        if (key == ev::kGapWorkingSetUnavailable)
        {
            return injectionText("process.detail.injection.gap.working_set",
                                 QStringLiteral("工作集页状态未能全部取得"));
        }
        if (key == ev::kGapThreadStartUnavailable)
        {
            return injectionText("process.detail.injection.gap.thread_start",
                                 QStringLiteral("部分线程起始地址未采集到"));
        }
        if (key == ev::kGapReferenceUncertain)
        {
            return injectionText("process.detail.injection.gap.reference",
                                 QStringLiteral("参考映像不确定，差异不能归为修改已证实"));
        }
        if (key == ev::kGapBudgetTruncated)
        {
            return injectionText("process.detail.injection.gap.budget",
                                 QStringLiteral("命中扫描预算，本次结果已截断"));
        }
        if (key == ev::kGapIdentityChanged)
        {
            return injectionText("process.detail.injection.gap.identity_changed",
                                 QStringLiteral("扫描期间进程身份发生变化，证据已作废"));
        }
        if (key == ev::kGapIdentityUnverifiable)
        {
            return injectionText("process.detail.injection.gap.identity_unverifiable",
                                 QStringLiteral("进程身份信息不足，无法确认前后是同一实例"));
        }
        if (key == ev::kGapModuleEnumerationWow64)
        {
            return injectionText("process.detail.injection.gap.wow64",
                                 QStringLiteral("WOW64 采集器的模块过滤参数被忽略，列表不完整"));
        }
        if (key == ev::kGapMainImageSourceMissing)
        {
            return injectionText("process.detail.injection.gap.main_image",
                                 QStringLiteral("主映像身份来源不足，无法交叉核对"));
        }
        if (key == ev::kGapVadLinkUncheckable)
        {
            return injectionText(
                "process.detail.injection.gap.vad_link",
                QStringLiteral("内存区域清单没能一次读完（条目太多被截断，或有节点读不到），所以“清单有没有被动过”这一项没查成"));
        }
        if (key == ev::kGapStackWalkUntrusted)
        {
            return injectionText(
                "process.detail.injection.gap.stack_untrusted",
                QStringLiteral("查线程调用栈时，没有一个线程是停着的——运行中的线程读到的调用栈不可信，所以这一项没查成"));
        }
        if (key == ev::kGapKernelBackendUnavailable)
        {
            return injectionText("process.detail.injection.gap.kernel_backend",
                                 QStringLiteral("内核扫描后端不可用或未走完（驱动未加载、权限不足或被截断）"));
        }
        if (key == ev::kGapKernelProfileUnverified)
        {
            return injectionText("process.detail.injection.gap.kernel_profile",
                                 QStringLiteral("当前系统版本没有经过验证的 VadRoot 偏移，内核区域视图已降级"));
        }
        return QString::fromStdString(key);
    }

    // Capability limitations and coverage gaps are displayed separately: the former means 'this version does not do this,' while the latter means 'intended to check but failed to complete.'
    QString limitText(const std::string& key)
    {
        if (key == ev::kLimitNonExecutableNotScanned)
        {
            return injectionText("process.detail.injection.limit.non_executable",
                                 QStringLiteral("未扫描非可执行内存：休眠载荷可以不保持执行权限"));
        }
        if (key == ev::kLimitStackUnwindUnavailable)
        {
            return injectionText("process.detail.injection.limit.stack_unwind",
                                 QStringLiteral("没有可靠展开的调用帧，执行关联无法建立"));
        }
        if (key == ev::kLimitPayloadHeaderErased)
        {
            return injectionText("process.detail.injection.limit.payload_erased",
                                 QStringLiteral("本版本只按残留 PE 头识别载荷，识别不了被擦除头部的载荷"));
        }
        if (key == ev::kLimitRuntimeAttribution)
        {
            return injectionText("process.detail.injection.limit.runtime",
                                 QStringLiteral("本版本不做 CLR 等运行时归因：JIT/ReadyToRun 的就地改写会表现为未解释差异"));
        }
        if (key == ev::kLimitKernelTrustAssumption)
        {
            return injectionText("process.detail.injection.limit.kernel_trust",
                                 QStringLiteral("内核采集依赖内核可信：有内核能力的对手可以改写这里读到的元数据，本功能不承诺“有驱动便无法隐藏”"));
        }
        if (key == ev::kLimitKernelVadFlagsUnverified)
        {
            return injectionText("process.detail.injection.limit.kernel_vad_flags",
                                 QStringLiteral("VAD 保护位的位布局未经版本验证，因此只比地址范围、不比保护属性"));
        }
        if (key == ev::kLimitKernelSectionCompare)
        {
            return injectionText("process.detail.injection.limit.kernel_section",
                                 QStringLiteral("本版本未做“进程映像页与 Image Section Object 参考页比较”（内核增强第三层）"));
        }
        if (key == ev::kLimitKernelBackendAbsent)
        {
            return injectionText("process.detail.injection.limit.kernel_absent",
                                 QStringLiteral("本机未加载 KswordARK 驱动，内核扫描后端本次未参与"));
        }
        if (key == ev::kLimitKernelBenignBaseline)
        {
            return injectionText("process.detail.injection.limit.kernel_baseline",
                                 QStringLiteral("内核交叉差异的合法成因目录尚未在实机数据上建立，因此这类差异一律只到“待解释”"));
        }
        return QString::fromStdString(key);
    }

    QString checkText(const std::string& key)
    {
        if (key == ev::kCheckAddressSpaceIndex)
        {
            return injectionText("process.detail.injection.check.address_space",
                                 QStringLiteral("全地址空间索引"));
        }
        if (key == ev::kCheckModuleCrossView)
        {
            return injectionText("process.detail.injection.check.module_cross_view",
                                 QStringLiteral("模块交叉视图"));
        }
        if (key == ev::kCheckWorkingSetScreen)
        {
            return injectionText("process.detail.injection.check.working_set",
                                 QStringLiteral("工作集页筛选"));
        }
        if (key == ev::kCheckThreadStart)
        {
            return injectionText("process.detail.injection.check.thread_start",
                                 QStringLiteral("线程起点及落点"));
        }
        if (key == ev::kCheckNormalizedImageDiff)
        {
            return injectionText("process.detail.injection.check.image_diff",
                                 QStringLiteral("归一化映像比较"));
        }
        if (key == ev::kCheckPayloadStructure)
        {
            return injectionText("process.detail.injection.check.payload_structure",
                                 QStringLiteral("非映像载荷结构"));
        }
        if (key == ev::kCheckNonExecutableScan)
        {
            return injectionText("process.detail.injection.check.non_executable",
                                 QStringLiteral("非可执行内存扫描"));
        }
        if (key == ev::kCheckVadLinkIntegrity)
        {
            return injectionText("process.detail.injection.check.vad_link",
                                 QStringLiteral("核对内存区域清单有没有被动过"));
        }
        if (key == ev::kCheckReliableStackWalk)
        {
            return injectionText("process.detail.injection.check.stack_walk",
                                 QStringLiteral("查线程当前的调用栈"));
        }
        if (key == ev::kCheckKernelVadCrossView)
        {
            return injectionText("process.detail.injection.check.kernel_vad",
                                 QStringLiteral("内核 VAD 交叉视图"));
        }
        if (key == ev::kCheckKernelPteScan)
        {
            return injectionText("process.detail.injection.check.kernel_pte",
                                 QStringLiteral("内核页表可执行页扫描"));
        }
        return QString::fromStdString(key);
    }

    QString observationText(const ev::ObservationClass observation)
    {
        switch (observation)
        {
        case ev::ObservationClass::kPrivateOrMappedExecutablePresent:
            return injectionText(
                "process.detail.injection.observation.dynamic_code",
                QStringLiteral("存在私有/映射可执行内存 → 可以说\"存在待解释的动态代码\"，不能说\"已被恶意注入\""));
        case ev::ObservationClass::kNormalizedImageDiffers:
            return injectionText(
                "process.detail.injection.observation.image_diff",
                QStringLiteral("归一化后代码仍与可靠参考不同 → 可以说\"映像代码修改已证实\"，不能说\"已确定修改者和修改目的\""));
        case ev::ObservationClass::kPayloadStructureWithReliableFrame:
            return injectionText(
                "process.detail.injection.observation.payload_frame",
                QStringLiteral("非映像内存有自洽载荷结构且可靠栈帧进入其中 → 可以说\"未知内存载荷与线程执行相关联\"，不能说\"一定由远程进程注入\""));
        case ev::ObservationClass::kMappedModuleOutsideBaseline:
            return injectionText(
                "process.detail.injection.observation.module_baseline",
                QStringLiteral("模块交叉视图存在矛盾 → 可以说\"存在非预期模块\"，不能说\"一定通过某种特定注入 API 进入\""));
        case ev::ObservationClass::kVadTreeLinkageInconsistent:
            return injectionText(
                "process.detail.injection.observation.vad_link",
                QStringLiteral("系统记录内存区域的那棵树自己对不上 → 可以说\"有内存区域被从清单里摘掉了\"，不能说\"摘掉它的是谁、摘的是哪一块\""));
        case ev::ObservationClass::kScanCompleteNoStrongEvidence:
            return injectionText(
                "process.detail.injection.observation.no_strong_evidence",
                QStringLiteral("扫描完成但无强证据 → 只能说\"在已覆盖范围内未发现相应异常\"，不能说\"从未被注入过\""));
        case ev::ObservationClass::kKeyInputUnavailable:
        default:
            return injectionText(
                "process.detail.injection.observation.input_unavailable",
                QStringLiteral("关键页面/线程/参考文件不可获得 → 只能说\"检查受限、结论不完整\"，不能说\"目标干净\""));
        }
    }

    QString failureText(const ks::process::InjectionTraceResult& result)
    {
        switch (result.status)
        {
        case ks::process::InjectionTraceStatus::kProcessIdentityUnavailable:
            return injectionText(
                "process.detail.injection.failure.identity_unavailable",
                QStringLiteral("无法确认进程实例身份（读不到创建时间），本次检查未执行。"));
        case ks::process::InjectionTraceStatus::kProcessIdentityMismatch:
            return injectionText(
                "process.detail.injection.failure.identity_mismatch",
                QStringLiteral("PID 已被复用或进程已重建，本次检查未执行。"));
        case ks::process::InjectionTraceStatus::kProcessOpenDenied:
            return injectionText(
                "process.detail.injection.failure.access_denied",
                QStringLiteral("访问受限：无法以只读权限打开目标进程（受保护进程或权限不足）。这不是\"未发现注入\"。"));
        case ks::process::InjectionTraceStatus::kProcessOpenFailed:
            return injectionText(
                "process.detail.injection.failure.open_failed",
                QStringLiteral("打开目标进程失败，本次检查未执行。"));
        case ks::process::InjectionTraceStatus::kCompleted:
        default:
            return QString();
        }
    }

    // Forward declaration: the report copied out and the one seen on the UI must be rendered from the same source; otherwise, the two will eventually diverge.
    QString conclusionHeadline(ev::AnalysisConclusion conclusion);
    QString conclusionCaveatText(ev::AnalysisConclusion conclusion);
    QString readableFindingDetailText(const ev::InjectionFinding& finding);

    QString buildReportText(const ks::process::InjectionTraceResult& result,
                            const QString& processName)
    {
        QStringList lines;
        lines << injectionText("process.detail.injection.report.title",
                               QStringLiteral("进程注入痕迹检查报告"));
        lines << injectionText("process.detail.injection.report.target",
                               QStringLiteral("目标：%1 (PID %2)    映像：%3    架构：%4"))
                     .arg(processName)
                     .arg(result.pid)
                     .arg(result.imagePath)
                     .arg(result.architectureText);
        const QString kFailure = failureText(result);
        if (!kFailure.isEmpty())
        {
            lines << kFailure;
            if (!result.diagnosticText.isEmpty())
            {
                lines << injectionText("process.detail.injection.report.diagnostic",
                                       QStringLiteral("技术信息：%1"))
                             .arg(result.diagnosticText);
            }
            return lines.join(QChar('\n'));
        }

        const ev::SurveyReport& report = result.report;
        lines << injectionText("process.detail.injection.report.mode",
                               QStringLiteral("模式：%1    检测器：%2    规则集：v%3"))
                     .arg(result.requestedMode == ev::SurveyMode::kDeep
                              ? injectionText("process.detail.injection.mode.deep",
                                              QStringLiteral("深度"))
                              : injectionText("process.detail.injection.mode.fast",
                                              QStringLiteral("快速")))
                     .arg(QString::fromStdString(report.detectorVersion))
                     .arg(report.ruleSetVersion);
        lines << injectionText("process.detail.injection.report.conclusion",
                               QStringLiteral("结论：%1"))
                     .arg(conclusionText(report.conclusion));
        // Follow the conclusion with a plain-language version and 'what it should not be read as', keeping consistency with the first screen of the UI.
        lines << conclusionHeadline(report.conclusion);
        lines << conclusionCaveatText(report.conclusion);
        lines << injectionText("process.detail.injection.report.counts",
                               QStringLiteral("动态代码区域 %1，模块交叉问题 %2（其中矛盾 %3），未解释映像差异 %4，线程起点异常 %5，例外解释 %6"))
                     .arg(report.dynamicCodeRegionCount)
                     .arg(report.moduleCrossIssueCount)
                     .arg(report.moduleCrossConflictCount)
                     .arg(report.unexplainedImageDiffCount)
                     .arg(report.threadStartAnomalyCount)
                     .arg(report.exceptionExplainedCount);
        lines << injectionText("process.detail.injection.report.scale",
                               QStringLiteral("区域 %1，加载器模块 %2，映像映射 %3，线程 %4，比较模块 %5（%6 段），工作集页 %7，读取 %8 字节，用时 %9 ms"))
                     .arg(result.regionCount)
                     .arg(result.loaderModuleCount)
                     .arg(result.imageMappingCount)
                     .arg(result.threadCount)
                     .arg(result.comparedModuleCount)
                     .arg(result.comparedRangeCount)
                     .arg(result.workingSetPagesQueried)
                     .arg(result.bytesRead)
                     .arg(result.elapsedMs);

        lines << injectionText("process.detail.injection.report.kernel",
                               QStringLiteral("R0 扫描后端：VAD=%1（%2 条，不可读节点 %3），页表=%4（%5 段，可执行页 %6，表读 %7），交叉差异 %8"))
                     .arg(QString::fromLatin1(
                         ev::kernelBackendStateName(result.kernelVadState)))
                     .arg(result.kernelVadRegionCount)
                     .arg(result.kernelVadUnreadableNodes)
                     .arg(QString::fromLatin1(
                         ev::kernelBackendStateName(result.kernelPteState)))
                     .arg(result.kernelExecutableExtentCount)
                     .arg(result.kernelExecutablePageCount)
                     .arg(result.kernelPteTableReads)
                     .arg(report.kernelCrossIssueCount);
        if (!result.kernelDiagnosticText.isEmpty())
        {
            lines << injectionText("process.detail.injection.report.kernel_diagnostic",
                                   QStringLiteral("R0 后端诊断：%1"))
                         .arg(result.kernelDiagnosticText);
        }

        lines << QString();
        lines << injectionText("process.detail.injection.report.observations",
                               QStringLiteral("[观测语义：能说什么 / 不能说什么]"));
        if (report.observations.empty())
        {
            lines << injectionText("process.detail.injection.report.no_observation",
                                   QStringLiteral("    （无）"));
        }
        for (const ev::ObservationClass kObservation : report.observations)
        {
            lines << QStringLiteral("    ") + observationText(kObservation);
        }

        lines << QString();
        lines << injectionText("process.detail.injection.report.completed_checks",
                               QStringLiteral("[已完成的检查]"));
        for (const std::string& key : report.completedCheckKeys)
        {
            lines << QStringLiteral("    ") + checkText(key);
        }
        lines << injectionText("process.detail.injection.report.skipped_checks",
                               QStringLiteral("[未执行的检查]"));
        for (const std::string& key : report.notPerformedCheckKeys)
        {
            lines << QStringLiteral("    ") + checkText(key);
        }
        lines << injectionText("process.detail.injection.report.gaps",
                               QStringLiteral("[检查缺口：打算查但没查成]"));
        if (report.coverageGapKeys.empty())
        {
            lines << injectionText("process.detail.injection.report.no_gap",
                                   QStringLiteral("    （无）"));
        }
        for (const std::string& key : report.coverageGapKeys)
        {
            lines << QStringLiteral("    ") + gapText(key);
        }
        lines << injectionText("process.detail.injection.report.limits",
                               QStringLiteral("[能力限制：本版本不做这件事]"));
        if (report.capabilityLimitKeys.empty())
        {
            lines << injectionText("process.detail.injection.report.no_gap",
                                   QStringLiteral("    （无）"));
        }
        for (const std::string& key : report.capabilityLimitKeys)
        {
            lines << QStringLiteral("    ") + limitText(key);
        }

        lines << QString();
        lines << injectionText("process.detail.injection.report.findings",
                               QStringLiteral("[结果条目 %1 条]"))
                     .arg(report.findings.size());
        for (const ev::InjectionFinding& finding : report.findings)
        {
            lines << QString();
            lines << readableFindingDetailText(finding);
        }
        return lines.join(QChar('\n'));
    }

    // ---------------------------------------------------------------------
    // The following functions only translate conclusions from the criteria layer into plain language. The semantic
    // boundary must not be loosened: four states remain four states. This step simply extracts the limiting
    // conditions previously hidden in parentheses for users to deduce and presents them as an independent sentence.
    // ---------------------------------------------------------------------

    QString conclusionHeadline(const ev::AnalysisConclusion conclusion)
    {
        switch (conclusion)
        {
        case ev::AnalysisConclusion::kNoEvidence:
            return injectionText("process.detail.injection.headline.no_evidence",
                                 QStringLiteral("这次没能检查成"));
        case ev::AnalysisConclusion::kNoDifferenceObserved:
            return injectionText("process.detail.injection.headline.no_difference",
                                 QStringLiteral("查过的地方没发现问题"));
        case ev::AnalysisConclusion::kDifferenceObserved:
            return injectionText("process.detail.injection.headline.difference",
                                 QStringLiteral("发现了对不上的地方，建议人工确认"));
        case ev::AnalysisConclusion::kIndeterminate:
        default:
            return injectionText("process.detail.injection.headline.indeterminate",
                                 QStringLiteral("有现象需要人工判断，工具不替你下结论"));
        }
    }

    // Each state's "cannot be read as" must be a standalone sentence, not enclosed in parentheses within the conclusion.
    QString conclusionCaveatText(const ev::AnalysisConclusion conclusion)
    {
        switch (conclusion)
        {
        case ev::AnalysisConclusion::kNoEvidence:
            return injectionText(
                "process.detail.injection.caveat.no_evidence",
                QStringLiteral("没有拿到可用的观测数据，所以既不能说有问题，也不能说没问题。原因写在「查了什么」页里。"));
        case ev::AnalysisConclusion::kNoDifferenceObserved:
            return injectionText(
                "process.detail.injection.caveat.no_difference",
                QStringLiteral("这句话只对「查了什么」页里列出的范围成立，不等于这个进程从来没有被注入过。"));
        case ev::AnalysisConclusion::kDifferenceObserved:
            return injectionText(
                "process.detail.injection.caveat.difference",
                QStringLiteral("发现的是「和原本该有的样子对不上」，不是「谁在什么时候注入的」——事后看内存查不出注入者是谁。"));
        case ev::AnalysisConclusion::kIndeterminate:
        default:
            return injectionText(
                "process.detail.injection.caveat.indeterminate",
                QStringLiteral("看到的现象既可能来自正常功能（即时编译、加壳、杀软或输入法插桩），也可能来自注入。每一类是什么意思，下面每组标题下面都写了。"));
        }
    }

    // The line below the group header: what this class of phenomena is, and what common benign causes exist.
    // Without this line, users are left helpless when facing 'Dynamic/Non-image Executable Memory at 874 locations'.
    QString ruleMeaningText(const std::string& ruleId)
    {
        if (ruleId == ev::kRuleIdDynamicCodeRegion)
        {
            return injectionText(
                "process.detail.injection.meaning.dynamic_code",
                QStringLiteral("不属于任何磁盘文件的可执行内存。正常来源很多：.NET / JavaScript 等即时编译、加壳程序自解压、杀软与输入法的插桩。几乎每个进程都有，数量本身不是问题，明显比同类进程多才值得看。"));
        }
        if (ruleId == ev::kRuleIdImageBytesUnexplained)
        {
            return injectionText(
                "process.detail.injection.meaning.image_diff",
                QStringLiteral("模块的代码和磁盘上的原文件不一样，并且已经排除了重定位这类系统自己做的正常改写。这是本工具能给出的最硬的一类证据。"));
        }
        if (ruleId == ev::kRuleIdImageReferenceUncertain)
        {
            return injectionText(
                "process.detail.injection.meaning.image_reference_uncertain",
                QStringLiteral("模块代码和磁盘文件对不上，但磁盘上那份文件本身没法确认是不是原版（读不到、被占用、或来源不可靠），所以这个差异暂时不能算数。"));
        }
        if (ruleId == ev::kRuleIdImageWithoutLoaderEntry)
        {
            return injectionText(
                "process.detail.injection.meaning.image_without_loader",
                QStringLiteral("内存里映射着一个 PE 映像，但系统的已加载模块清单里没登记它。资源文件和 .NET 元数据映像天然就是这样；被手工映射进来的 DLL 也是这样。"));
        }
        if (ruleId == ev::kRuleIdLoaderEntryWithoutMapping)
        {
            return injectionText(
                "process.detail.injection.meaning.loader_without_mapping",
                QStringLiteral("模块清单里登记了这个模块，内存里却找不到与之对应的映射。"));
        }
        if (ruleId == ev::kRuleIdModuleIdentityMismatch)
        {
            return injectionText(
                "process.detail.injection.meaning.module_identity",
                QStringLiteral("同一个模块，清单里写的名字或大小，和内存里实际映射的那一份对不上。"));
        }
        if (ruleId == ev::kRuleIdMainImageConflict)
        {
            return injectionText(
                "process.detail.injection.meaning.main_image_conflict",
                QStringLiteral("进程主程序自己的身份信息前后矛盾：两处来源说的不是同一个文件。"));
        }
        if (ruleId == ev::kRuleIdThreadStartOutsideImage)
        {
            return injectionText(
                "process.detail.injection.meaning.thread_outside_image",
                QStringLiteral("有线程的起始地址不落在任何模块的代码里。远程线程注入是这个样子，某些运行时自己生成的跳板也是这个样子。"));
        }
        if (ruleId == ev::kRuleIdThreadStartUnknown)
        {
            return injectionText(
                "process.detail.injection.meaning.thread_unknown",
                QStringLiteral("线程的起始地址没取到（权限不够，或线程在采集途中退出了）。这是没查成，不是查出了问题。"));
        }
        if (ruleId == ev::kRuleIdThreadStartTrampoline)
        {
            return injectionText(
                "process.detail.injection.meaning.thread_trampoline",
                QStringLiteral("线程入口的第一条指令就跳到别的模块去了，等于这个起点只是个壳，真正要跑的代码在别处。"));
        }
        if (ruleId == ev::kRuleIdPayloadStructure)
        {
            return injectionText(
                "process.detail.injection.meaning.payload_structure",
                QStringLiteral("一段不属于任何模块的内存里，出现了完整可执行文件才有的结构特征——像是有人把一个程序整个搬进了内存。如果这一条还标着「有多个独立来源互相印证」，说明有线程的调用栈确实落在这块内存里，也就是它不只是躺着，而是在被执行。"));
        }
        if (ruleId == ev::kRuleIdKernelRegionHiddenFromR3)
        {
            return injectionText(
                "process.detail.injection.meaning.kernel_hidden",
                QStringLiteral("内核的内存记录里有这块区域，从用户态查却看不到它。两个视图对不上，但正常成因的目录还没建立，所以只作为线索。"));
        }
        if (ruleId == ev::kRuleIdKernelRegionMissingInVad)
        {
            return injectionText(
                "process.detail.injection.meaning.kernel_missing_vad",
                QStringLiteral("从用户态查能看到这块内存，内核的内存记录里却没有对应条目。"));
        }
        if (ruleId == ev::kRuleIdKernelExecutableBeyondView)
        {
            return injectionText(
                "process.detail.injection.meaning.kernel_exec_beyond",
                QStringLiteral("页表说这些页可以执行，但其它视图认为它们不可执行。"));
        }
        if (ruleId == ev::kRuleIdKernelVadLinkBroken)
        {
            return injectionText(
                "process.detail.injection.meaning.vad_link_broken",
                QStringLiteral("系统内部记录内存区域用的是一棵树，这棵树自己对不上了——有节点的“父节点”不认它这个孩子，或者系统记的区域个数比树上实际找到的多。把一块内存从这棵树上摘下去，是隐藏内存最直接的做法：摘掉之后从外面就再也查询不到它，但内存本身还在、还能跑。本机 90 个进程、10199 个节点实测全部对得上，所以这一条出现即值得追查。"));
        }
        return QString();
    }

    // Short description for a finding displayed in the table: prioritize address, then module, and finally source path.
    QString findingHeadlineText(const ev::InjectionFinding& finding)
    {
        if (!finding.moduleName.empty())
        {
            return QString::fromStdString(finding.moduleName);
        }
        if (!finding.mappedPath.empty())
        {
            return QFileInfo(QString::fromStdString(finding.mappedPath)).fileName();
        }
        if (!finding.relatedThreads.empty())
        {
            return injectionText("process.detail.injection.finding.thread",
                                 QStringLiteral("线程 %1"))
                .arg(finding.relatedThreads.front().tid.valueOr(0U));
        }
        return injectionText("process.detail.injection.finding.anonymous_region",
                             QStringLiteral("匿名内存区域"));
    }

    // Display size in human-readable units. Previously, everything was in 0x1000 hexadecimal, requiring mental calculation to realize it was 4 KB.
    QString humanSizeText(const ev::OptionalU64& value)
    {
        if (!value.present)
        {
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        const double kBytes = static_cast<double>(value.value);
        if (value.value < 1024ULL)
        {
            return injectionText("process.detail.injection.size.bytes",
                                 QStringLiteral("%1 字节"))
                .arg(static_cast<qulonglong>(value.value));
        }
        if (value.value < 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 KB").arg(kBytes / 1024.0, 0, 'f', 1);
        }
        if (value.value < 1024ULL * 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 MB").arg(kBytes / (1024.0 * 1024.0), 0, 'f', 1);
        }
        return QStringLiteral("%1 GB").arg(kBytes / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    // Changed permission from "RWX" to "readable, writable, executable". The three-letter format is not self-explanatory to users.
    QString humanProtectionText(const ev::RegionProtection& protection)
    {
        if (!protection.rawValue.present)
        {
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        const ev::ProtectionFacts kFacts = ev::classifyWin32Protection(protection.rawValue);
        if (kFacts.noAccess)
        {
            return injectionText("process.detail.injection.protect.no_access",
                                 QStringLiteral("不可访问"));
        }
        if (kFacts.unrecognizedBase)
        {
            return protectionText(protection);
        }
        const bool kExecutable = ev::executeProtectionIsExecutable(kFacts.execute);
        if (kFacts.writable && kExecutable)
        {
            return injectionText("process.detail.injection.protect.rwx",
                                 QStringLiteral("可写＋可执行"));
        }
        if (kExecutable)
        {
            return injectionText("process.detail.injection.protect.rx",
                                 QStringLiteral("可执行"));
        }
        if (kFacts.writable)
        {
            return injectionText("process.detail.injection.protect.rw",
                                 QStringLiteral("可写"));
        }
        return injectionText("process.detail.injection.protect.ro",
                             QStringLiteral("只读"));
    }

    QString humanRegionTypeText(const ev::RegionType type)
    {
        switch (type)
        {
        case ev::RegionType::kImage:
            return injectionText("process.detail.injection.region.image",
                                 QStringLiteral("模块映像"));
        case ev::RegionType::kMapped:
            return injectionText("process.detail.injection.region.mapped",
                                 QStringLiteral("映射文件"));
        case ev::RegionType::kPrivate:
            return injectionText("process.detail.injection.region.private",
                                 QStringLiteral("私有内存"));
        case ev::RegionType::kUnknown:
        default:
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
    }

    // Detail panel: segmented layout with subsection headers; machine-style key=value pairs are pushed to the final segment.
    QString readableFindingDetailText(const ev::InjectionFinding& finding)
    {
        QStringList lines;
        lines << ruleText(finding.ruleId);
        const QString kMeaning = ruleMeaningText(finding.ruleId);
        if (!kMeaning.isEmpty())
        {
            lines << kMeaning;
        }
        lines << QString();

        lines << injectionText("process.detail.injection.detail.section.where",
                               QStringLiteral("【位置】"));
        lines << injectionText("process.detail.injection.detail.address_line",
                               QStringLiteral("    地址 %1，大小 %2，类型 %3，权限 %4"))
                     .arg(hex64(finding.address))
                     .arg(humanSizeText(finding.size))
                     .arg(humanRegionTypeText(finding.regionType))
                     .arg(humanProtectionText(finding.protection));
        if (!finding.moduleName.empty())
        {
            lines << injectionText("process.detail.injection.detail.module_line",
                                   QStringLiteral("    所属模块 %1"))
                         .arg(QString::fromStdString(finding.moduleName));
        }
        if (!finding.sectionName.empty() || finding.rva.present)
        {
            lines << injectionText("process.detail.injection.detail.section_line",
                                   QStringLiteral("    模块内位置：节 %1，偏移 %2"))
                         .arg(finding.sectionName.empty()
                                  ? QStringLiteral("-")
                                  : QString::fromStdString(finding.sectionName))
                         .arg(hex64(finding.rva));
        }
        if (!finding.mappedPath.empty())
        {
            lines << injectionText("process.detail.injection.detail.path_line",
                                   QStringLiteral("    对应文件 %1"))
                         .arg(QString::fromStdString(finding.mappedPath));
        }
        else
        {
            lines << injectionText("process.detail.injection.detail.no_path_line",
                                   QStringLiteral("    这块内存不对应任何磁盘文件"));
        }
        if (!finding.relatedThreads.empty())
        {
            QStringList threads;
            for (const ev::ThreadInstanceId& thread : finding.relatedThreads)
            {
                threads << QString::number(thread.tid.valueOr(0U));
            }
            lines << injectionText("process.detail.injection.detail.thread_line",
                                   QStringLiteral("    相关线程 %1"))
                         .arg(threads.join(QStringLiteral("、")));
        }
        lines << QString();

        lines << injectionText("process.detail.injection.detail.section.howsure",
                               QStringLiteral("【这条有多可靠】"));
        lines << QStringLiteral("    ") + confidenceText(finding.confidence);
        if (finding.confidence == ev::EvidenceConfidence::kInputIncomplete)
        {
            lines << injectionText("process.detail.injection.detail.incomplete_hint",
                                   QStringLiteral("    采集时有数据没拿到，这条不能单独拿来下判断。"));
        }
        if (finding.exception.match == ev::ExceptionMatch::kMatched)
        {
            lines << injectionText("process.detail.injection.detail.exception_line",
                                   QStringLiteral("    已被已知例外规则解释（规则 %1），按预期行为处理。"))
                         .arg(QString::fromStdString(finding.exception.ruleId));
        }
        if (!finding.coverageGapKeys.empty())
        {
            lines << injectionText("process.detail.injection.detail.gap_line",
                                   QStringLiteral("    这条本身还带着没查成的部分："));
            for (const std::string& gap : finding.coverageGapKeys)
            {
                lines << QStringLiteral("        · ") + gapText(gap);
            }
        }
        lines << QString();

        lines << injectionText("process.detail.injection.detail.section.time",
                               QStringLiteral("【时间与来源】"));
        lines << injectionText("process.detail.injection.detail.observed_line",
                               QStringLiteral("    首次观测到：%1（这是本次看到它的时间，不是注入发生的时间）"))
                     .arg(firstObservedText(finding.firstObservedUtc100ns));
        lines << injectionText("process.detail.injection.detail.injector_line",
                               QStringLiteral("    是谁放进来的：未知。事后看内存查不出注入者，要查这个必须有事前的实时记录。"));
        lines << QString();

        lines << injectionText("process.detail.injection.detail.section.raw",
                               QStringLiteral("【技术细节】以下是原始记录，供需要深挖时核对"));
        lines << injectionText("process.detail.injection.detail.raw_rule",
                               QStringLiteral("    规则 %1 v%2，检测器 %3"))
                     .arg(QString::fromStdString(finding.ruleId))
                     .arg(finding.ruleVersion)
                     .arg(QString::fromStdString(finding.detectorVersion));
        for (const std::string& fact : finding.facts)
        {
            lines << QStringLiteral("    ") + QString::fromStdString(fact);
        }
        return lines.join(QChar('\n'));
    }

    void showInjectionTraceDialog(QWidget* const parent,
                                  const ks::process::InjectionTraceResult& result,
                                  const QString& processName)
    {
        QDialog dialog(parent);
        dialog.setWindowTitle(
            injectionText("process.detail.injection.dialog.title",
                          QStringLiteral("%1注入检查 - %2"))
                .arg(result.requestedMode == ev::SurveyMode::kDeep
                         ? injectionText("process.detail.injection.mode.deep_prefix",
                                         QStringLiteral("深度"))
                         : injectionText("process.detail.injection.mode.fast_prefix",
                                         QStringLiteral("快速")))
                .arg(processName));
        dialog.resize(1240, 780);

        QVBoxLayout* const kLayout = new QVBoxLayout(&dialog);
        kLayout->setContentsMargins(10, 10, 10, 10);
        kLayout->setSpacing(8);

        const ev::SurveyReport& report = result.report;
        const QString kFailure = failureText(result);

        // Top three lines, one thing per line: what the conclusion is / what this sentence must not be interpreted as / how many were actually scanned this time.
        // Originally, the layout was 'Conclusion + 11 digits squeezed into one line + four lines of boundary notes', making it unreadable.
        QLabel* const kConclusionLabel = new QLabel(&dialog);
        kConclusionLabel->setWordWrap(true);
        if (!kFailure.isEmpty())
        {
            kConclusionLabel->setText(
                injectionText("process.detail.injection.headline.not_run",
                              QStringLiteral("这次检查没有执行")));
            kConclusionLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700; font-size:16px;")
                    .arg(ksword_theme::warningHex()));
        }
        else
        {
            kConclusionLabel->setText(conclusionHeadline(report.conclusion));
            kConclusionLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700; font-size:16px;")
                    .arg(ksword_theme::themeColorName(conclusionColor(report.conclusion))));
        }
        kLayout->addWidget(kConclusionLabel);

        QLabel* const kCaveatLabel = new QLabel(&dialog);
        kCaveatLabel->setWordWrap(true);
        kCaveatLabel->setText(kFailure.isEmpty() ? conclusionCaveatText(report.conclusion)
                                               : kFailure);
        kCaveatLabel->setStyleSheet(QStringLiteral("color:%1;")
                                       .arg(ksword_theme::textPrimaryHex()));
        kLayout->addWidget(kCaveatLabel);

        QLabel* const kStatsLabel = new QLabel(&dialog);
        kStatsLabel->setWordWrap(true);
        if (kFailure.isEmpty())
        {
            const QString kElapsed =
                result.elapsedMs >= 1000ULL
                    ? injectionText("process.detail.injection.stats.seconds",
                                    QStringLiteral("%1 秒"))
                          .arg(static_cast<double>(result.elapsedMs) / 1000.0, 0, 'f', 1)
                    : injectionText("process.detail.injection.stats.milliseconds",
                                    QStringLiteral("%1 毫秒"))
                          .arg(result.elapsedMs);
            kStatsLabel->setText(
                injectionText("process.detail.injection.stats.line",
                              QStringLiteral("%1　用时 %2　扫过 %3 块内存、%4 个模块、%5 个线程，逐字节比对了 %6 段代码"))
                    .arg(result.requestedMode == ev::SurveyMode::kDeep
                             ? injectionText("process.detail.injection.mode.deep",
                                             QStringLiteral("深度检查"))
                             : injectionText("process.detail.injection.mode.fast",
                                             QStringLiteral("快速检查")))
                    .arg(kElapsed)
                    .arg(result.regionCount)
                    .arg(result.loaderModuleCount)
                    .arg(result.threadCount)
                    .arg(result.comparedRangeCount));
            if (report.stackThreadsWalked != 0U)
            {
                // This line is printed only when a stack walk was actually performed. Since `walked` is typically much smaller than
                // `threadCount`, the reason must be explicitly stated to avoid being misinterpreted as "half the threads were missed."
                kStatsLabel->setText(
                    kStatsLabel->text() +
                    injectionText("process.detail.injection.stats.stack_line",
                                  QStringLiteral("\n另查了 %1 个停着的线程的调用栈（共 %2 个线程；运行中的线程读到的调用栈不可信，只查停着的），其中 %3 个拿到了可信结果"))
                        .arg(report.stackThreadsWalked)
                        .arg(result.threadCount)
                        .arg(report.stackThreadsTrusted));
            }
        }
        else if (!result.diagnosticText.isEmpty())
        {
            kStatsLabel->setText(injectionText("process.detail.injection.report.diagnostic",
                                              QStringLiteral("技术信息：%1"))
                                    .arg(result.diagnosticText));
        }
        kStatsLabel->setStyleSheet(QStringLiteral("color:%1;")
                                      .arg(ksword_theme::textSecondaryHex()));
        kLayout->addWidget(kStatsLabel);

        QTabWidget* const kTabs = new QTabWidget(&dialog);

        // --- What was found ---
        QWidget* const kFindingPage = new QWidget(kTabs);
        QVBoxLayout* const kFindingLayout = new QVBoxLayout(kFindingPage);
        kFindingLayout->setContentsMargins(0, 0, 0, 0);
        // A tree grouped by rules. A single process can have up to 874 entries of 'dynamic/non-image executable
        // memory'; flattening this into 874 rows × 10 columns is unreadable. Instead, collapse them into an expandable
        // group: the header row explains the category and count, and details are revealed only upon expansion.
        QTreeWidget* const kTree = new QTreeWidget(kFindingPage);
        const QStringList kHeaders{
            injectionText("process.detail.injection.header.item",
                          QStringLiteral("发现的内容")),
            injectionText("process.detail.injection.header.address", QStringLiteral("地址")),
            injectionText("process.detail.injection.header.size", QStringLiteral("大小")),
            injectionText("process.detail.injection.header.protect", QStringLiteral("权限")),
            injectionText("process.detail.injection.header.type", QStringLiteral("内存类型")),
            injectionText("process.detail.injection.header.note", QStringLiteral("备注"))
        };
        kTree->setColumnCount(kHeaders.size());
        kTree->setHeaderLabels(kHeaders);
        kTree->setSelectionMode(QAbstractItemView::SingleSelection);
        kTree->setUniformRowHeights(true);
        kTree->setAlternatingRowColors(true);
        kTree->setRootIsDecorated(true);

        // Grouping order follows the order provided by the criteria layer (rules appearing earlier come first); no
        // reordering is performed to avoid the appearance of sorting by 'severity'—this layer does not generate severity.
        std::vector<std::string> ruleOrder;
        std::map<std::string, std::vector<std::size_t>> groupedIndices;
        for (std::size_t index = 0; index < report.findings.size(); ++index)
        {
            const std::string& ruleId = report.findings[index].ruleId;
            if (groupedIndices.find(ruleId) == groupedIndices.end())
            {
                ruleOrder.push_back(ruleId);
            }
            groupedIndices[ruleId].push_back(index);
        }

        constexpr int kFindingIndexRole = Qt::UserRole + 1;
        // Expand threshold: groups with many items are collapsed by default, while small ones are expanded directly to avoid manual clicks.
        constexpr std::size_t kAutoExpandLimit = 12U;
        for (const std::string& ruleId : ruleOrder)
        {
            const std::vector<std::size_t>& indices = groupedIndices[ruleId];
            std::size_t explainedCount = 0;
            for (const std::size_t kIndex : indices)
            {
                if (report.findings[kIndex].explainedByException())
                {
                    ++explainedCount;
                }
            }

            QTreeWidgetItem* const kGroupItem = new QTreeWidgetItem(kTree);
            kGroupItem->setText(0, injectionText("process.detail.injection.group.title",
                                                QStringLiteral("%1 — %2 处"))
                                      .arg(ruleText(ruleId))
                                      .arg(indices.size()));
            kGroupItem->setData(0, kFindingIndexRole, -1);
            if (explainedCount > 0)
            {
                kGroupItem->setText(5, injectionText("process.detail.injection.group.explained",
                                                    QStringLiteral("其中 %1 处已被已知例外解释"))
                                          .arg(explainedCount));
            }
            QFont groupFont = kGroupItem->font(0);
            groupFont.setBold(true);
            kGroupItem->setFont(0, groupFont);
            const QString kMeaning = ruleMeaningText(ruleId);
            if (!kMeaning.isEmpty())
            {
                // Full-row tooltip: hovering over a group reveals what that category is without needing to expand it first.
                for (int column = 0; column < kHeaders.size(); ++column)
                {
                    kGroupItem->setToolTip(column, kMeaning);
                }
            }

            for (const std::size_t kIndex : indices)
            {
                const ev::InjectionFinding& finding = report.findings[kIndex];
                QTreeWidgetItem* const kItem = new QTreeWidgetItem(kGroupItem);
                kItem->setText(0, findingHeadlineText(finding));
                kItem->setText(1, hex64(finding.address));
                kItem->setText(2, humanSizeText(finding.size));
                kItem->setText(3, humanProtectionText(finding.protection));
                kItem->setText(4, humanRegionTypeText(finding.regionType));
                if (finding.explainedByException())
                {
                    kItem->setText(5, injectionText("process.detail.injection.note.explained",
                                                   QStringLiteral("已被已知例外解释")));
                }
                else if (finding.confidence == ev::EvidenceConfidence::kInputIncomplete)
                {
                    kItem->setText(5, injectionText("process.detail.injection.note.incomplete",
                                                   QStringLiteral("采集不完整，不能单独作判断")));
                }
                else if (finding.confidence ==
                         ev::EvidenceConfidence::kCorroboratedIndependent)
                {
                    kItem->setText(5, injectionText("process.detail.injection.note.corroborated",
                                                   QStringLiteral("有多个独立来源互相印证")));
                }
                kItem->setData(0, kFindingIndexRole, static_cast<qulonglong>(kIndex));
                // Exception-hit entries are retained but dimmed: verifiable, no longer treated as unexplained.
                const QColor kColor = finding.explainedByException()
                    ? ksword_theme::textSecondaryColor()
                    : (finding.confidence == ev::EvidenceConfidence::kInputIncomplete
                           ? ksword_theme::warningColor()
                           : ksword_theme::textPrimaryColor());
                for (int column = 0; column < kHeaders.size(); ++column)
                {
                    kItem->setForeground(column, QBrush(kColor));
                }
            }
            kGroupItem->setExpanded(indices.size() <= kAutoExpandLimit);
        }

        kTree->setColumnWidth(0, 300);
        kTree->setColumnWidth(1, 150);
        kTree->setColumnWidth(2, 90);
        kTree->setColumnWidth(3, 110);
        kTree->setColumnWidth(4, 90);
        kTree->setColumnWidth(5, 220);
        kFindingLayout->addWidget(kTree, 1);

        QPlainTextEdit* const kDetailPane = new QPlainTextEdit(kFindingPage);
        kDetailPane->setReadOnly(true);
        kDetailPane->setMaximumHeight(260);
        const QString kEmptyDetailText =
            kFailure.isEmpty()
                ? injectionText("process.detail.injection.dialog.no_finding",
                                QStringLiteral("这次没有找出需要解释的东西。这不等于「没有被注入过」——只说明在「查了什么」页列出的范围内没发现。选中上面任意一条可以在这里看它的完整信息。"))
                : kFailure;
        kDetailPane->setPlainText(
            report.findings.empty() ? kEmptyDetailText
                                    : readableFindingDetailText(report.findings.front()));
        kFindingLayout->addWidget(kDetailPane);
        QObject::connect(
            kTree, &QTreeWidget::currentItemChanged, &dialog,
            [kDetailPane, report, kEmptyDetailText](QTreeWidgetItem* const current,
                                                  QTreeWidgetItem*) {
                if (current == nullptr)
                {
                    return;
                }
                const QVariant kStored = current->data(0, kFindingIndexRole);
                if (!kStored.isValid() || kStored.toLongLong() < 0)
                {
                    // When the selected item is a group header, provide the overall description for this category instead of leaving the previous one unchanged.
                    const QString kMeaning = current->toolTip(0);
                    kDetailPane->setPlainText(kMeaning.isEmpty() ? kEmptyDetailText : kMeaning);
                    return;
                }
                const std::size_t kIndex = static_cast<std::size_t>(kStored.toULongLong());
                if (kIndex < report.findings.size())
                {
                    kDetailPane->setPlainText(
                        readableFindingDetailText(report.findings[kIndex]));
                }
            });
        kTabs->addTab(kFindingPage,
                     injectionText("process.detail.injection.tab.findings",
                                   QStringLiteral("发现了什么 (%1)"))
                         .arg(report.findings.size()));

        // --- What was checked and what failed --- Originally, these were three bare lists: [Completed Checks],
        // [Check Gaps], and [Capability Limitations]. The lists themselves were fine, but no one knew the difference
        // between "gaps" and "limitations." Therefore, a plain-language explanation was added before each section.
        QPlainTextEdit* const kCoveragePane = new QPlainTextEdit(kTabs);
        kCoveragePane->setReadOnly(true);
        {
            QStringList lines;
            if (report.scopeIntact)
            {
                lines << injectionText(
                    "process.detail.injection.coverage.intro_intact",
                    QStringLiteral("这次打算查的都查成了，所以上面那句结论是站得住的。"));
            }
            else
            {
                lines << injectionText(
                    "process.detail.injection.coverage.intro_broken",
                    QStringLiteral("有本来要查的东西没查成，所以这次不可能给出「没发现问题」——哪怕什么都没找到，也只能说「没查全」。没查成的原因列在下面。"));
            }
            lines << QString();

            lines << injectionText("process.detail.injection.coverage.section.gaps",
                                   QStringLiteral("■ 本来要查、但没查成的（这些会让结论打折扣）"));
            if (report.coverageGapKeys.empty())
            {
                lines << injectionText("process.detail.injection.coverage.none_gap",
                                       QStringLiteral("    没有，这次要查的都查到了。"));
            }
            for (const std::string& key : report.coverageGapKeys)
            {
                lines << QStringLiteral("    · ") + gapText(key);
            }
            lines << QString();

            lines << injectionText("process.detail.injection.coverage.section.done",
                                   QStringLiteral("■ 这次实际做了哪些检查"));
            if (report.completedCheckKeys.empty())
            {
                lines << injectionText("process.detail.injection.coverage.none_done",
                                       QStringLiteral("    一项都没做成。"));
            }
            for (const std::string& key : report.completedCheckKeys)
            {
                lines << QStringLiteral("    · ") + checkText(key);
            }
            lines << QString();

            lines << injectionText("process.detail.injection.coverage.section.skipped",
                                   QStringLiteral("■ 这次没做的检查"));
            if (report.notPerformedCheckKeys.empty())
            {
                lines << injectionText("process.detail.injection.coverage.none_skipped",
                                       QStringLiteral("    没有，该做的都做了。"));
            }
            for (const std::string& key : report.notPerformedCheckKeys)
            {
                lines << QStringLiteral("    · ") + checkText(key);
            }
            lines << QString();

            lines << injectionText("process.detail.injection.coverage.section.limits",
                                   QStringLiteral("■ 这个版本本来就不做的事（不影响上面的结论，只是说明它管到哪儿为止）"));
            if (report.capabilityLimitKeys.empty())
            {
                lines << injectionText("process.detail.injection.coverage.none_limit",
                                       QStringLiteral("    无。"));
            }
            for (const std::string& key : report.capabilityLimitKeys)
            {
                lines << QStringLiteral("    · ") + limitText(key);
            }
            kCoveragePane->setPlainText(lines.join(QChar('\n')));
        }
        kTabs->addTab(kCoveragePane,
                     injectionText("process.detail.injection.tab.coverage",
                                   QStringLiteral("查了什么 (%1 项没查成)"))
                         .arg(report.coverageGapKeys.size()));

        // --- How to read results --- Move boundary explanation from the top four lines here
        // and merge it with 'what can/cannot be said' into one page: both sections describe
        // the same thing; splitting them forces users to piece it together themselves.
        QPlainTextEdit* const kSemanticsPane = new QPlainTextEdit(kTabs);
        kSemanticsPane->setReadOnly(true);
        {
            QStringList lines;
            lines << injectionText("process.detail.injection.semantics.section.boundary",
                                   QStringLiteral("■ 这个功能能回答什么、不能回答什么"));
            lines << injectionText(
                "process.detail.injection.semantics.boundary_can",
                QStringLiteral("    能回答：这块内存里有没有来路不明的代码、某个模块的代码是不是和磁盘上的原件不一样。"));
            lines << injectionText(
                "process.detail.injection.semantics.boundary_cannot",
                QStringLiteral("    不能回答：是哪个进程、在什么时候、用什么手法放进来的。这些要靠事前的实时记录，翻事后的内存翻不出来。"));
            lines << injectionText(
                "process.detail.injection.semantics.boundary_time",
                QStringLiteral("    时间字段一律是「本次第一次看到它」的时间，不是注入发生的时间。"));
            lines << QString();

            lines << injectionText("process.detail.injection.semantics.section.observation",
                                   QStringLiteral("■ 这次看到的现象，各自能支撑到什么程度"));
            if (report.observations.empty())
            {
                lines << injectionText("process.detail.injection.semantics.none",
                                       QStringLiteral("    这次没有取得任何可用观测。"));
            }
            for (const ev::ObservationClass kObservation : report.observations)
            {
                lines << QStringLiteral("    · ") + observationText(kObservation);
                lines << QString();
            }
            kSemanticsPane->setPlainText(lines.join(QChar('\n')));
        }
        kTabs->addTab(kSemanticsPane,
                     injectionText("process.detail.injection.tab.semantics",
                                   QStringLiteral("结果怎么读")));

        kLayout->addWidget(kTabs, 1);

        QHBoxLayout* const kButtonLayout = new QHBoxLayout();
        kButtonLayout->addStretch(1);
        QPushButton* const kCopyButton = new QPushButton(
            QIcon(":/Icon/process_copy_row.svg"),
            injectionText("process.detail.injection.action.copy_report",
                          QStringLiteral("复制报告")),
            &dialog);
        QPushButton* const kCloseButton = new QPushButton(
            injectionText("process.detail.injection.action.close", QStringLiteral("关闭")),
            &dialog);
        kCopyButton->setStyleSheet(buildBlueButtonStyle());
        kCloseButton->setStyleSheet(buildBlueButtonStyle());
        kButtonLayout->addWidget(kCopyButton);
        kButtonLayout->addWidget(kCloseButton);
        kLayout->addLayout(kButtonLayout);

        const QString kReportText = buildReportText(result, processName);
        QObject::connect(kCopyButton, &QPushButton::clicked, &dialog, [kReportText]() {
            QApplication::clipboard()->setText(kReportText);
        });
        QObject::connect(kCloseButton, &QPushButton::clicked, &dialog, &QDialog::accept);

        if (kTree->topLevelItemCount() > 0)
        {
            kTree->setCurrentItem(kTree->topLevelItem(0));
        }
        dialog.exec();
    }
}

void ProcessDetailWindow::requestAsyncInjectionTraceScan(const bool deepMode)
{
    if (injectionTraceRunning_)
    {
        return;
    }

    injectionTraceRunning_ = true;
    const std::uint64_t kLocalTicket = ++injectionTraceTicket_;
    // Both buttons share a single scan, so disable them together: graying out only the clicked one would imply the other is still clickable.
    if (injectionTraceButton_ != nullptr)
    {
        injectionTraceButton_->setEnabled(false);
    }
    if (injectionTraceDeepButton_ != nullptr)
    {
        injectionTraceDeepButton_->setEnabled(false);
    }
    updateModuleStatusLabel(
        deepMode ? injectionText("process.detail.injection.status.scanning_deep",
                                 QStringLiteral("● 正在做深度注入检查，可能要一两分钟..."))
                 : injectionText("process.detail.injection.status.scanning",
                                 QStringLiteral("● 正在做快速注入检查...")),
        true);

    const std::uint32_t kPid = baseRecord_.pid;
    const std::uint64_t kCreationTime100ns = baseRecord_.creationTime100ns;
    const QString kFallbackImagePath = QString::fromStdString(baseRecord_.imagePath);
    const QString kProcessName = QString::fromStdString(baseRecord_.processName);

    KLogEvent scanStartEvent;
    info << scanStartEvent
        << "[ProcessDetailWindow] injection trace scan start, pid="
        << kPid
        << ", creationTime100ns="
        << kCreationTime100ns
        << ", deep="
        << (deepMode ? 1 : 0)
        << eol;

    QPointer<ProcessDetailWindow> guard(this);
    QRunnable* const kTask = QRunnable::create([
        guard,
        kLocalTicket,
        kPid,
        kCreationTime100ns,
        kFallbackImagePath,
        kProcessName,
        deepMode]()
    {
        ks::process::InjectionTraceOptions options;
        options.deepMode = deepMode;
        if (deepMode)
        {
            // In deep mode, the entire executable image range must be compared, so the budget is relaxed;
            // the hit limit is still displayed as truncated in the report, not silently turned into "clean".
            options.maxDurationMs = 120000ULL;
            options.maxReadBytes = 512ULL * 1024ULL * 1024ULL;
        }
        const ks::process::InjectionTraceResult kResult =
            ks::process::scanProcessInjectionTrace(
                kPid, kCreationTime100ns, kFallbackImagePath, options);
        if (guard == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(
            guard,
            [guard, kLocalTicket, kPid, kProcessName, kResult]()
            {
                if (guard == nullptr || kLocalTicket != guard->injectionTraceTicket_)
                {
                    return;
                }

                guard->injectionTraceRunning_ = false;
                if (guard->injectionTraceButton_ != nullptr)
                {
                    guard->injectionTraceButton_->setEnabled(true);
                }
                if (guard->injectionTraceDeepButton_ != nullptr)
                {
                    guard->injectionTraceDeepButton_->setEnabled(true);
                }

                if (kResult.completed())
                {
                    guard->updateModuleStatusLabel(
                        injectionText(
                            "process.detail.injection.status.completed",
                            QStringLiteral("● %1，列出 %2 条待看的内容"))
                            .arg(conclusionHeadline(kResult.report.conclusion))
                            .arg(kResult.report.findings.size()),
                        false);
                }
                else
                {
                    guard->updateModuleStatusLabel(
                        injectionText("process.detail.injection.status.failed",
                                      QStringLiteral("● 注入检查没能执行：打不开这个进程，或者它已经换了一个")),
                        false);
                    if (guard->moduleStatusLabel_ != nullptr)
                    {
                        guard->moduleStatusLabel_->setStyleSheet(
                            buildStateLabelStyle(statusErrorColor(), 700));
                    }
                }

                KLogEvent scanFinishEvent;
                info << scanFinishEvent
                    << "[ProcessDetailWindow] injection trace scan finish, pid="
                    << kPid
                    << ", status="
                    << static_cast<int>(kResult.status)
                    << ", conclusion="
                    << ksword::evidence::analysisConclusionName(kResult.report.conclusion)
                    << ", findings="
                    << kResult.report.findings.size()
                    << ", gaps="
                    << kResult.report.coverageGapKeys.size()
                    << ", elapsedMs="
                    << kResult.elapsedMs
                    << eol;

                showInjectionTraceDialog(guard, kResult, kProcessName);
            },
            Qt::QueuedConnection);
    });
    kTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(kTask);
}
