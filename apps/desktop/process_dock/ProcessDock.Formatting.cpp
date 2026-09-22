#include "ProcessDock.Support.h"

namespace ksword::ui::process_dock
{
    // affinityRestoreRetryDelay:
    // - Calculate exponential backoff (1, 2, 4, 8... seconds) based on the consecutive failure count.
    // - Input parameter consecutiveFailureCount: the count of consecutive failures, which must be at least 1.
    // - Returns: The next wait duration, capped at 60 seconds.
    std::chrono::milliseconds affinityRestoreRetryDelay(
        const std::uint32_t consecutiveFailureCount)
    {
        // exponent: limits the left shift count to prevent integer overflow triggered by extremely long-lived processes.
        const std::uint32_t kExponent = std::min<std::uint32_t>(
            consecutiveFailureCount > 0U ? consecutiveFailureCount - 1U : 0U,
            6U);

        // scaledDelayMilliseconds: Stores the millisecond value after exponential backoff for this round.
        const std::uint32_t kScaledDelayMilliseconds =
            kAffinityRestoreRetryBaseMilliseconds << kExponent;

        // boundedDelayMilliseconds: Limits the actual wait time to a defined maximum value.
        const std::uint32_t kBoundedDelayMilliseconds = std::min(
            kScaledDelayMilliseconds,
            kAffinityRestoreRetryMaximumMilliseconds);
        return std::chrono::milliseconds(kBoundedDelayMilliseconds);
    }

    QString processContextText(const char* const key, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    }

    QString processContextText(const QString& key, const QString& sourceText)
    {
        return ks::i18n::contextText(key, sourceText);
    }

    // Text for the injection surface column. Hard rule: Non-screened entries must always display the status
    // word; never display '0'. 'Cannot open process' and 'Truly nothing' must be distinct in this column.
    QString processInjectionSurfaceText(const ks::process::ProcessRecord& processRecord)
    {
        using ksword::evidence::SurfaceScreenState;
        const auto kState = static_cast<SurfaceScreenState>(processRecord.injectionSurfaceState);
        switch (kState)
        {
        case SurfaceScreenState::kNotScreened:
            return processContextText("process.table.cell.injection.not_screened",
                                      QStringLiteral("未筛选"));
        case SurfaceScreenState::kAccessDenied:
            return processContextText("process.table.cell.injection.access_denied",
                                      QStringLiteral("访问受限"));
        case SurfaceScreenState::kIdentityMismatch:
            return processContextText("process.table.cell.injection.identity_mismatch",
                                      QStringLiteral("身份不符"));
        case SurfaceScreenState::kFailed:
            return processContextText("process.table.cell.injection.failed",
                                      QStringLiteral("筛选失败"));
        case SurfaceScreenState::kScreened:
            break;
        }
        return processContextText("process.table.cell.injection.counts",
                                  QStringLiteral("%1 块 / %2 可写可执行"))
            .arg(processRecord.injectionDynamicRegions)
            .arg(processRecord.injectionWritableExecRegions);
    }

    QString translatedProcessHeader(const int section, const QString& sourceText)
    {
        if (section < 0 || section >= kProcessTableHeaders.size())
        {
            return sourceText;
        }
        const QString kTranslatedBase = processContextText(kProcessTableHeaderKeys[section], kProcessTableHeaders.at(section));
        const QString kSourceBase = kProcessTableHeaders.at(section);
        if (sourceText == kSourceBase)
        {
            return kTranslatedBase;
        }
        if (sourceText.startsWith(kSourceBase + QChar(' ')))
        {
            return kTranslatedBase + sourceText.mid(kSourceBase.size());
        }
        return sourceText;
    }

    // processGroupedNumberText function: Adds thousand separators to integers according to the current locale.
    QString processGroupedNumberText(const std::uint64_t value)
    {
        return QLocale::system().toString(static_cast<qulonglong>(value));
    }

    // processGroupedSignedNumberText:
    // - Input: Increment value that may be negative;
    // - Processing: Add '+' for positive, '-' for negative, and display '0' for zero to facilitate quick direction change detection.
    // - Returns: Signed text with thousand separators.
    QString processGroupedSignedNumberText(const std::int64_t value)
    {
        if (value == 0)
        {
            return QStringLiteral("0");
        }

        // Take the absolute value first, then restore the sign: negating INT64_MIN directly causes overflow, so use unsigned intermediate conversion here.
        const std::uint64_t kMagnitude = (value > 0)
            ? static_cast<std::uint64_t>(value)
            : (~static_cast<std::uint64_t>(value) + 1ULL);
        return (value > 0 ? QStringLiteral("+") : QStringLiteral("-")) + processGroupedNumberText(kMagnitude);
    }

    // processKilobyteText:
    // - Convert byte count to Task Manager-style "N K" format;
    // - Round up to 1 KB to avoid displaying actual usage of a few hundred bytes as 0 KB.
    QString processKilobyteText(const std::uint64_t bytes)
    {
        const std::uint64_t kKilobytes = (bytes == 0ULL) ? 0ULL : ((bytes + 1023ULL) / 1024ULL);
        return processGroupedNumberText(kKilobytes) + QStringLiteral(" K");
    }

    // processSignedKilobyteText purpose: Convert a signed byte delta into "+N K" / "-N K" format.
    QString processSignedKilobyteText(const std::int64_t deltaBytes)
    {
        if (deltaBytes == 0)
        {
            return QStringLiteral("0 K");
        }

        const std::uint64_t kMagnitude = (deltaBytes > 0)
            ? static_cast<std::uint64_t>(deltaBytes)
            : (~static_cast<std::uint64_t>(deltaBytes) + 1ULL);
        const std::uint64_t kKilobytes = (kMagnitude + 1023ULL) / 1024ULL;
        return (deltaBytes > 0 ? QStringLiteral("+") : QStringLiteral("-"))
            + processGroupedNumberText(kKilobytes)
            + QStringLiteral(" K");
    }

    // processMegabyteText function: Display GPU memory column in MB following Task Manager conventions.
    QString processMegabyteText(const std::uint64_t bytes)
    {
        return QString::number(static_cast<double>(bytes) / (1024.0 * 1024.0), 'f', 1)
            + QStringLiteral(" MB");
    }

    // processCpuTimeText: Formats cumulative CPU time in 100ns units to H:MM:SS.
    QString processCpuTimeText(const std::uint64_t cpuTime100ns)
    {
        const std::uint64_t kTotalSeconds = cpuTime100ns / 10000000ULL;
        const std::uint64_t kHours = kTotalSeconds / 3600ULL;
        const std::uint64_t kMinutes = (kTotalSeconds / 60ULL) % 60ULL;
        const std::uint64_t kSeconds = kTotalSeconds % 60ULL;
        return QStringLiteral("%1:%2:%3")
            .arg(static_cast<qulonglong>(kHours))
            .arg(static_cast<qulonglong>(kMinutes), 2, 10, QChar('0'))
            .arg(static_cast<qulonglong>(kSeconds), 2, 10, QChar('0'));
    }

    // processFeatureStateText:
    // - Convert the three- or four-state enumeration for UAC virtualization, Data Execution Protection (DEP), and Control Flow Protection (CFP) into display text.
    // - 'Unknown' indicates data has not been collected or the query was denied; display a placeholder instead of 'Disabled'.
    QString processFeatureStateText(const ks::process::ProcessFeatureState featureState)
    {
        switch (featureState)
        {
        case ks::process::ProcessFeatureState::kNotAllowed:
            return processContextText("process.table.cell.feature_not_allowed", QStringLiteral("不允许"));
        case ks::process::ProcessFeatureState::kDisabled:
            return processContextText("process.table.cell.feature_disabled", QStringLiteral("已禁用"));
        case ks::process::ProcessFeatureState::kEnabled:
            return processContextText("process.table.cell.feature_enabled", QStringLiteral("已启用"));
        case ks::process::ProcessFeatureState::kEnabledPermanent:
            return processContextText("process.table.cell.feature_enabled_permanent", QStringLiteral("已启用(永久)"));
        default:
            return kProcessColumnUnavailableText;
        }
    }

    // processDpiAwarenessText:
    // - Converts DPI awareness level to display text matching Task Manager;
    // - Unknown indicates data not yet collected or query denied; display a placeholder uniformly.
    QString processDpiAwarenessText(const ks::process::ProcessDpiAwarenessLevel awarenessLevel)
    {
        switch (awarenessLevel)
        {
        case ks::process::ProcessDpiAwarenessLevel::kUnaware:
            return processContextText("process.table.cell.dpi_unaware", QStringLiteral("无法识别"));
        case ks::process::ProcessDpiAwarenessLevel::kUnawareGdiScaled:
            return processContextText("process.table.cell.dpi_unaware_gdi", QStringLiteral("无法识别(GDI 缩放)"));
        case ks::process::ProcessDpiAwarenessLevel::kSystemAware:
            return processContextText("process.table.cell.dpi_system", QStringLiteral("系统"));
        case ks::process::ProcessDpiAwarenessLevel::kPerMonitorAware:
            return processContextText("process.table.cell.dpi_per_monitor", QStringLiteral("每监视器"));
        case ks::process::ProcessDpiAwarenessLevel::kPerMonitorAwareV2:
            return processContextText("process.table.cell.dpi_per_monitor_v2", QStringLiteral("每监视器(V2)"));
        default:
            return kProcessColumnUnavailableText;
        }
    }

    // processFeatureStateSortValue:
    // - Provide a stable numeric sort key for the above enumeration;
    // - Unknown is placed first (-1) to help users quickly identify rows with missing data.
    double processFeatureStateSortValue(const ks::process::ProcessFeatureState featureState)
    {
        return (featureState == ks::process::ProcessFeatureState::kUnknown)
            ? -1.0
            : static_cast<double>(static_cast<int>(featureState));
    }
}
