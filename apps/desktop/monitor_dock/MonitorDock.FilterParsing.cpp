#include "MonitorDock.Support.h"

namespace ksword::ui::monitor_dock
{
    QStringList splitEtwFilterTokens(const QString& inputText)
    {
        static const QRegularExpression kSeparatorRegex(QStringLiteral("[,;\\s]+"));
        return inputText.split(kSeparatorRegex, Qt::SkipEmptyParts);
    }

    bool tryParseUInt64Text(const QString& text, std::uint64_t& valueOut)
    {
        QString trimmed = text.trimmed();
        if (trimmed.isEmpty())
        {
            return false;
        }

        bool parseOk = false;
        std::uint64_t parsedValue = 0;
        if (trimmed.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            parsedValue = trimmed.mid(2).toULongLong(&parseOk, 16);
        }
        else
        {
            parsedValue = trimmed.toULongLong(&parseOk, 10);
            if (!parseOk)
            {
                parsedValue = trimmed.toULongLong(&parseOk, 16);
            }
        }
        if (!parseOk)
        {
            return false;
        }
        valueOut = parsedValue;
        return true;
    }

    bool tryParseUInt64RangeToken(
        const QString& tokenText,
        MonitorDock::EtwFilterNumericRange& rangeOut)
    {
        const QString kTrimmed = tokenText.trimmed();
        if (kTrimmed.isEmpty())
        {
            return false;
        }

        const int kDashIndex = kTrimmed.indexOf('-');
        if (kDashIndex > 0)
        {
            const QString kBeginText = kTrimmed.left(kDashIndex).trimmed();
            const QString kEndText = kTrimmed.mid(kDashIndex + 1).trimmed();
            std::uint64_t beginValue = 0;
            std::uint64_t endValue = 0;
            if (!tryParseUInt64Text(kBeginText, beginValue) || !tryParseUInt64Text(kEndText, endValue))
            {
                return false;
            }
            rangeOut.minValue = std::min(beginValue, endValue);
            rangeOut.maxValue = std::max(beginValue, endValue);
            return true;
        }

        std::uint64_t singleValue = 0;
        if (!tryParseUInt64Text(kTrimmed, singleValue))
        {
            return false;
        }
        rangeOut.minValue = singleValue;
        rangeOut.maxValue = singleValue;
        return true;
    }

    bool tryParsePortRangeToken(
        const QString& tokenText,
        MonitorDock::EtwFilterPortRange& rangeOut)
    {
        MonitorDock::EtwFilterNumericRange numericRange;
        if (!tryParseUInt64RangeToken(tokenText, numericRange))
        {
            return false;
        }
        if (numericRange.minValue > 65535ULL || numericRange.maxValue > 65535ULL)
        {
            return false;
        }
        rangeOut.minValue = static_cast<std::uint16_t>(numericRange.minValue);
        rangeOut.maxValue = static_cast<std::uint16_t>(numericRange.maxValue);
        return true;
    }

    bool tryParseIpv4Text(const QString& text, std::uint32_t& valueOut)
    {
        const QString kTrimmed = text.trimmed();
        const QStringList kPartList = kTrimmed.split('.', Qt::KeepEmptyParts);
        if (kPartList.size() != 4)
        {
            return false;
        }

        std::uint32_t value = 0;
        for (const QString& partText : kPartList)
        {
            bool parseOk = false;
            const int kPartValue = partText.toInt(&parseOk, 10);
            if (!parseOk || kPartValue < 0 || kPartValue > 255)
            {
                return false;
            }
            value = (value << 8) | static_cast<std::uint32_t>(kPartValue);
        }

        valueOut = value;
        return true;
    }

    bool tryParseIpv4RangeToken(
        const QString& tokenText,
        MonitorDock::EtwFilterIpRange& rangeOut)
    {
        const QString kTrimmed = tokenText.trimmed();
        if (kTrimmed.isEmpty())
        {
            return false;
        }

        const int kSlashIndex = kTrimmed.indexOf('/');
        if (kSlashIndex > 0)
        {
            const QString kIpText = kTrimmed.left(kSlashIndex).trimmed();
            const QString kMaskText = kTrimmed.mid(kSlashIndex + 1).trimmed();
            std::uint32_t baseIp = 0;
            if (!tryParseIpv4Text(kIpText, baseIp))
            {
                return false;
            }

            bool parseOk = false;
            const int kPrefixLength = kMaskText.toInt(&parseOk, 10);
            if (!parseOk || kPrefixLength < 0 || kPrefixLength > 32)
            {
                return false;
            }

            const std::uint32_t kMask = kPrefixLength == 0
                ? 0U
                : (kPrefixLength == 32 ? 0xFFFFFFFFU : (0xFFFFFFFFU << (32 - kPrefixLength)));
            const std::uint32_t kNetwork = baseIp & kMask;
            const std::uint32_t kBroadcast = kNetwork | (~kMask);
            rangeOut.minValue = std::min(kNetwork, kBroadcast);
            rangeOut.maxValue = std::max(kNetwork, kBroadcast);
            return true;
        }

        const int kDashIndex = kTrimmed.indexOf('-');
        if (kDashIndex > 0)
        {
            const QString kBeginText = kTrimmed.left(kDashIndex).trimmed();
            const QString kEndText = kTrimmed.mid(kDashIndex + 1).trimmed();
            std::uint32_t beginIp = 0;
            std::uint32_t endIp = 0;
            if (!tryParseIpv4Text(kBeginText, beginIp) || !tryParseIpv4Text(kEndText, endIp))
            {
                return false;
            }
            rangeOut.minValue = std::min(beginIp, endIp);
            rangeOut.maxValue = std::max(beginIp, endIp);
            return true;
        }

        std::uint32_t singleIp = 0;
        if (!tryParseIpv4Text(kTrimmed, singleIp))
        {
            return false;
        }
        rangeOut.minValue = singleIp;
        rangeOut.maxValue = singleIp;
        return true;
    }

    QString etwFilterRegexPatternFromToken(const QString& tokenText, const EtwStringMatchMode mode)
    {
        const QString kEscapedText = QRegularExpression::escape(tokenText);
        switch (mode)
        {
        case EtwStringMatchMode::kExact:
            return QStringLiteral("^%1$").arg(kEscapedText);
        case EtwStringMatchMode::kContains:
            return kEscapedText;
        case EtwStringMatchMode::kPrefix:
            return QStringLiteral("^%1").arg(kEscapedText);
        case EtwStringMatchMode::kSuffix:
            return QStringLiteral("%1$").arg(kEscapedText);
        case EtwStringMatchMode::kRegex:
        default:
            return tokenText;
        }
    }
}
