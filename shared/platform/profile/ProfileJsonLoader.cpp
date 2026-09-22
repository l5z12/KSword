#include "ProfileJsonLoader.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QIODevice>
#include <QStringList>

namespace
{
    // hasQtCompressedJsonSuffix:
    // - Input pathText: candidate profile path.
    // - Processing: performs a case-insensitive suffix check for the local
    //   "*.json.qz" convention used by the release copy target.
    // - Return: true when the path names a Qt-compressed profile payload.
    bool hasQtCompressedJsonSuffix(const QString& pathText)
    {
        return pathText.endsWith(QStringLiteral(".json.qz"), Qt::CaseInsensitive);
    }

    // appendUniqueCleanPath:
    // - Input paths/pathText: mutable path list and a candidate path.
    // - Processing: trims, normalizes separators, and keeps the first
    //   case-insensitive occurrence so diagnostics stay readable.
    // - Return: no return value; paths is updated in place.
    void appendUniqueCleanPath(QStringList& paths, const QString& pathText)
    {
        const QString kTrimmedPath = pathText.trimmed();
        if (kTrimmedPath.isEmpty())
        {
            return;
        }

        const QString kCleanPath = QDir::cleanPath(kTrimmedPath);
        if (!kCleanPath.isEmpty() && !paths.contains(kCleanPath, Qt::CaseInsensitive))
        {
            paths.push_back(kCleanPath);
        }
    }

    // profileCandidatePaths:
    // - Input jsonPath: canonical plain JSON path or explicit compressed path.
    // - Processing: constructs the exact search order used by the runtime:
    //   compressed first for normal "*.json" callers, plain fallback second.
    // - Return: ordered candidate list, possibly empty when input is blank.
    QStringList profileCandidatePaths(const QString& jsonPath)
    {
        QStringList paths;
        const QString kCleanPath = QDir::cleanPath(jsonPath.trimmed());
        if (kCleanPath.isEmpty())
        {
            return paths;
        }

        if (hasQtCompressedJsonSuffix(kCleanPath))
        {
            appendUniqueCleanPath(paths, kCleanPath);
            appendUniqueCleanPath(paths, kCleanPath.left(kCleanPath.size() - 3));
        }
        else
        {
            appendUniqueCleanPath(paths, kCleanPath + QStringLiteral(".qz"));
            appendUniqueCleanPath(paths, kCleanPath);
        }

        return paths;
    }
}

namespace ks::profile
{
    QString resolveProfileJsonPath(const QString& jsonPath)
    {
        // The resolver intentionally does not parse or open files.  It only
        // answers "which candidate exists" so old search loops can keep using
        // their "*.json" names while Release deployments ship "*.json.qz".
        for (const QString& candidatePath : profileCandidatePaths(jsonPath))
        {
            const QFileInfo kFileInfo(candidatePath);
            if (kFileInfo.exists() && kFileInfo.isFile())
            {
                return kFileInfo.absoluteFilePath();
            }
        }

        return QString();
    }

    QByteArray readProfileJsonBytes(const QString& jsonPath, QString* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        QStringList diagnostics;
        for (const QString& candidatePath : profileCandidatePaths(jsonPath))
        {
            const QFileInfo kFileInfo(candidatePath);
            if (!kFileInfo.exists() || !kFileInfo.isFile())
            {
                diagnostics << QStringLiteral("not found: %1").arg(QDir::toNativeSeparators(candidatePath));
                continue;
            }

            const QString kResolvedPath = kFileInfo.absoluteFilePath();
            QFile file(kResolvedPath);
            if (!file.open(QIODevice::ReadOnly))
            {
                diagnostics << QStringLiteral("open failed: %1 (%2)")
                    .arg(QDir::toNativeSeparators(kResolvedPath), file.errorString());
                continue;
            }

            const QByteArray kFileBytes = file.readAll();
            if (!hasQtCompressedJsonSuffix(kResolvedPath))
            {
                if (kFileBytes.isEmpty())
                {
                    diagnostics << QStringLiteral("plain profile JSON is empty: %1")
                        .arg(QDir::toNativeSeparators(kResolvedPath));
                    continue;
                }
                return kFileBytes;
            }

            // qCompress writes a four-byte big-endian uncompressed length
            // followed by a zlib stream.  The Python build helper mirrors that
            // exact layout, so qUncompress is the safest reader and avoids
            // maintaining a custom decompressor in application code.  If this
            // compressed candidate is broken, the loop intentionally continues
            // to a plain JSON fallback when one exists.
            if (kFileBytes.size() < 4)
            {
                diagnostics << QStringLiteral("compressed profile JSON is truncated: %1")
                    .arg(QDir::toNativeSeparators(kResolvedPath));
                continue;
            }

            const QByteArray kJsonBytes = qUncompress(kFileBytes);
            if (kJsonBytes.isEmpty())
            {
                diagnostics << QStringLiteral("qUncompress failed: %1")
                    .arg(QDir::toNativeSeparators(kResolvedPath));
                continue;
            }

            return kJsonBytes;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("Profile JSON not readable: %1%2")
                .arg(QDir::toNativeSeparators(jsonPath))
                .arg(diagnostics.isEmpty()
                    ? QString()
                    : QStringLiteral(" (%1)").arg(diagnostics.join(QStringLiteral("; "))));
        }
        return {};
    }

    QJsonDocument readProfileJsonDocument(
        const QString& jsonPath,
        QJsonParseError* parseErrorOut,
        QString* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        if (parseErrorOut != nullptr)
        {
            *parseErrorOut = QJsonParseError{};
        }

        QString readErrorText;
        const QByteArray kJsonBytes = readProfileJsonBytes(jsonPath, &readErrorText);
        if (kJsonBytes.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = readErrorText;
            }
            return {};
        }

        QJsonParseError localParseError{};
        const QJsonDocument kDocument = QJsonDocument::fromJson(kJsonBytes, &localParseError);
        if (parseErrorOut != nullptr)
        {
            *parseErrorOut = localParseError;
        }
        if (localParseError.error != QJsonParseError::NoError && errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("Profile JSON parse failed: %1").arg(localParseError.errorString());
        }

        return kDocument;
    }
}
