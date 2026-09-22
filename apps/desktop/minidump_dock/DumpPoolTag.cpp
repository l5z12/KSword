#include "DumpPoolTag.h"

#include "DumpSymbolIndex.h"

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QSet>

#include <algorithm>

namespace ks::minidump
{
    namespace
    {
        // kMaxScanBytes: Maximum bytes to scan per image. Driver images are typically much
        // smaller; the limit exists to prevent excessively large files from stalling the parser.
        constexpr qint64 kMaxScanBytes = 64LL * 1024LL * 1024LL;

        // kMaxScanModules: maximum number of modules to scan. Kernel dumps often contain hundreds of drivers; scanning all
        // of them requires hundreds of MB of disk I/O. Hits usually occur early, and this is merely an auxiliary clue.
        constexpr int kMaxScanModules = 200;

        // poolTagCharOk: Determines if a single byte can appear in a pool tag.
        // Accepts a value byte; returns whether it is valid.
        // The spec allows printable ASCII for tags; in practice, they are mostly alphanumeric, with the last character often padded with a space.
        bool poolTagCharOk(const unsigned char value)
        {
            if (value == ' ')
            {
                return true;
            }
            if (value >= '0' && value <= '9')
            {
                return true;
            }
            if (value >= 'A' && value <= 'Z')
            {
                return true;
            }
            if (value >= 'a' && value <= 'z')
            {
                return true;
            }
            // A few tags use these symbols; allow them but do not relax to all printable characters.
            // If the criterion is too loose, any integer would be treated as a tag, rendering the conclusion meaningless.
            return value == '_' || value == '.' || value == '?';
        }

        // loadKnownPoolTags: Read the pooltag.txt file bundled with the WDK debugger.
        // Returns a mapping of 'tag → usage description'; returns an empty table if the file does not exist.
        // Use the official table instead of hard-coding one: there are thousands of pool tags; relying on memory will inevitably
        // introduce errors, and a single incorrect attribution can misdirect troubleshooting toward completely unrelated components.
        const QHash<QString, QString>& loadKnownPoolTags()
        {
            static const QHash<QString, QString> kTable = []()
            {
                QHash<QString, QString> result; // result: mapping to be populated.
                const QStringList kCandidates = {
                    QStringLiteral("C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\triage\\pooltag.txt"),
                    QStringLiteral("C:\\Program Files\\Windows Kits\\10\\Debuggers\\x64\\triage\\pooltag.txt"),
                    QStringLiteral("C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\triage\\pooltag.txt"),
                };
                for (const QString& path : kCandidates)
                {
                    QFile file(path);
                    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
                    {
                        continue;
                    }
                    while (!file.atEnd())
                    {
                        // The line format in pooltag.txt is: Tag - Binary - Description
                        const QString kLine = QString::fromLatin1(file.readLine()).trimmed();
                        if (kLine.isEmpty() || kLine.startsWith(QLatin1Char('/')))
                        {
                            continue;
                        }
                        const int kFirstDash = kLine.indexOf(QLatin1Char('-'));
                        if (kFirstDash <= 0)
                        {
                            continue;
                        }
                        const QString kTag = kLine.left(kFirstDash).trimmed();
                        if (kTag.isEmpty() || kTag.size() > 4)
                        {
                            continue;
                        }
                        const QString kRest = kLine.mid(kFirstDash + 1).trimmed();
                        if (!result.contains(kTag))
                        {
                            result.insert(kTag, kRest);
                        }
                    }
                    break;
                }
                return result;
            }();
            return kTable;
        }

        // normalizeModulePath purpose: convert kernel-style module paths into paths that can be opened.
        // Input raw: original path; returns normalized result, or empty string if normalization fails.
        QString normalizeModulePath(const QString& raw)
        {
            if (raw.isEmpty())
            {
                return QString();
            }
            QString path = raw; // path: path being converted.
            if (path.startsWith(QStringLiteral("\\??\\"), Qt::CaseInsensitive))
            {
                path = path.mid(4);
            }
            else if (path.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive))
            {
                const QString kSystemRoot = QString::fromLocal8Bit(qgetenv("SystemRoot"));
                if (kSystemRoot.isEmpty())
                {
                    return QString();
                }
                path = kSystemRoot + QStringLiteral("\\") + path.mid(12);
            }
            if (path.size() >= 2 && path.at(1) == QLatin1Char(':'))
            {
                return QDir::toNativeSeparators(path);
            }
            // When only a filename is provided, complete it using the driver directory; this pattern is common in kernel dumps.
            if (!path.contains(QLatin1Char('\\')) && !path.contains(QLatin1Char('/')))
            {
                const QString kSystemRoot = QString::fromLocal8Bit(qgetenv("SystemRoot"));
                if (kSystemRoot.isEmpty())
                {
                    return QString();
                }
                const QString kDriverPath = QDir::toNativeSeparators(
                    kSystemRoot + QStringLiteral("\\System32\\drivers\\") + path);
                if (QFileInfo::exists(kDriverPath))
                {
                    return kDriverPath;
                }
                return QDir::toNativeSeparators(
                    kSystemRoot + QStringLiteral("\\System32\\") + path);
            }
            return QString();
        }

        // findTagOwners purpose: Search for pool tag byte sequences in the disk images of loaded modules.
        // Parameters: tagBytes is the 4-byte tag; modules is the module table. Returns: a list of matching module names.
        // Rationale: When a driver calls ExAllocatePoolWithTag, the tag is a
        // compile-time immediate constant and must appear in its image as these 4 bytes.
        QStringList findTagOwners(
            const QByteArray& tagBytes,
            const std::vector<ModuleEntry>& modules)
        {
            QStringList owners;  // owners: Hit module names.
            QSet<QString> seen;  // seen: Path deduplication; scan each module name only once.
            int scanned = 0;     // scanned: Number of scanned modules.

            for (const ModuleEntry& module : modules)
            {
                if (scanned >= kMaxScanModules)
                {
                    break;
                }
                const QString kPath = normalizeModulePath(module.name);
                if (kPath.isEmpty() || seen.contains(kPath.toLower()))
                {
                    continue;
                }
                seen.insert(kPath.toLower());

                QFile file(kPath);
                if (!file.open(QIODevice::ReadOnly))
                {
                    continue;
                }
                if (file.size() > kMaxScanBytes)
                {
                    continue;
                }
                ++scanned;
                const QByteArray kContent = file.readAll();
                if (kContent.contains(tagBytes))
                {
                    owners.append(baseModuleName(module.name));
                }
            }
            owners.removeDuplicates();
            return owners;
        }
    }

    bool looksLikePoolTag(const std::uint32_t value)
    {
        if (value == 0)
        {
            return false;
        }
        // Check byte-by-byte; require at least two letters. Pure-digit or pure-symbol 4-byte
        // combinations are too common in parameters; treating them as markers would only create noise.
        int letters = 0; // letters: number of letters.
        for (int shift = 0; shift < 32; shift += 8)
        {
            const auto kPart = static_cast<unsigned char>((value >> shift) & 0xFFU);
            if (!poolTagCharOk(kPart))
            {
                return false;
            }
            if ((kPart >= 'A' && kPart <= 'Z') || (kPart >= 'a' && kPart <= 'z'))
            {
                ++letters;
            }
        }
        return letters >= 2;
    }

    QString poolTagText(const std::uint32_t value)
    {
        QString text; // text: Restored tag.
        text.reserve(4);
        for (int shift = 0; shift < 32; shift += 8)
        {
            const auto kPart = static_cast<unsigned char>((value >> shift) & 0xFFU);
            text.append(QLatin1Char(static_cast<char>(kPart)));
        }
        return text;
    }

    void applyPoolTagAttribution(DumpParseResult& result)
    {
        // candidates: Collects entries as 'original value → source description'; the same tag may appear in multiple locations.
        std::vector<PoolTagCandidate> candidates;
        QSet<std::uint32_t> seenValues; // seenValues: each value is registered only once.

        // addCandidate purpose: Register a candidate; duplicate values only supplement the source description.
        const auto kAddCandidate =
            [&candidates, &seenValues](const std::uint32_t value, const QString& source)
        {
            if (!looksLikePoolTag(value))
            {
                return;
            }
            if (seenValues.contains(value))
            {
                for (PoolTagCandidate& existing : candidates)
                {
                    if (existing.rawValue == value)
                    {
                        existing.source += QStringLiteral("、") + source;
                        return;
                    }
                }
                return;
            }
            seenValues.insert(value);
            PoolTagCandidate candidate;
            candidate.rawValue = value;
            candidate.tagText = poolTagText(value);
            candidate.source = source;
            candidates.push_back(candidate);
        };

        // Stop code parameters: pool-type stop codes place relevant addresses and types in the parameters, occasionally including the tag directly.
        if (result.bugCheckCode != 0)
        {
            for (int index = 0; index < 4; ++index)
            {
                const std::uint64_t kParameter = result.bugCheckParameters[index];
                // Check only the lower 32 bits: the tag is a ULONG, so the high bits being part of an address should not cause a false positive.
                if (kParameter <= 0xFFFFFFFFULL)
                {
                    kAddCandidate(
                        static_cast<std::uint32_t>(kParameter),
                        QStringLiteral("停止码参数 %1").arg(index + 1));
                }
            }
        }

        // Crash point registers: The second parameter of ExFreePoolWithTag is the tag; when crashing in the release
        // path, it is clearly visible in the registers — this project's 0x50 incident was exactly like that.
        for (const RegisterEntry& reg : result.registers)
        {
            if (reg.value <= 0xFFFFFFFFULL)
            {
                kAddCandidate(
                    static_cast<std::uint32_t>(reg.value),
                    QStringLiteral("寄存器 %1").arg(reg.name));
            }
        }

        if (candidates.empty())
        {
            return;
        }

        const QHash<QString, QString>& known = loadKnownPoolTags();
        for (PoolTagCandidate& candidate : candidates)
        {
            const auto kHit = known.constFind(candidate.tagText.trimmed());
            if (kHit != known.constEnd())
            {
                candidate.knownPurpose = kHit.value();
            }
            // If the tag is known, no need to scan the image: the official table answer is more reliable
            // than byte search, and scanning involves hundreds of MB of disk reads, so save what you can.
            if (candidate.knownPurpose.isEmpty())
            {
                candidate.ownerModules = findTagOwners(
                    candidate.tagText.toLatin1(), result.modules);
            }
        }

        result.poolTags = candidates;

        // Write the most valuable entry to the conclusion: unknown tags attributed to specific modules.
        for (const PoolTagCandidate& candidate : result.poolTags)
        {
            if (!candidate.ownerModules.isEmpty())
            {
                result.analysis.findings.append(
                    QStringLiteral("池标记 %1（来自%2）出现在这些模块的映像中：%3。池损坏类停止码里，被损坏内存归谁所有往往比调用栈更能指向肇事者——栈上出现的通常只是下一个来分配内存、因而撞上坏链表的发现者。")
                        .arg(candidate.tagText,
                             candidate.source,
                             candidate.ownerModules.join(QStringLiteral("、"))));
            }
        }
    }
}
