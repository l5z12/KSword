#include "FileDock.Support.h"

namespace ksword::ui::file_dock
{
    bool isCriticalProcessName(const QString& processName)
    {
        const QString kNormalizedName = processName.trimmed().toLower();
        if (kNormalizedName.isEmpty())
        {
            return false;
        }

        static const std::set<QString> kCriticalNameSet =
        {
            QStringLiteral("smss.exe"),
            QStringLiteral("csrss.exe"),
            QStringLiteral("wininit.exe"),
            QStringLiteral("services.exe"),
            QStringLiteral("lsass.exe"),
            QStringLiteral("winlogon.exe")
        };
        return kCriticalNameSet.find(kNormalizedName) != kCriticalNameSet.end();
    }

    // isPathReparsePoint：
    // - Purpose: Determines if the target path is a reparse point (e.g., symbolic link, Junction).
    // - Used to avoid inadvertently following link targets during recursive directory deletion.
    bool isPathReparsePoint(const QString& path)
    {
        const std::wstring kNativePathText = QDir::toNativeSeparators(path).toStdWString();
        if (kNativePathText.empty())
        {
            return false;
        }

        const DWORD kFileAttributes = ::GetFileAttributesW(kNativePathText.c_str());
        if (kFileAttributes == INVALID_FILE_ATTRIBUTES)
        {
            return false;
        }
        return (kFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U;
    }

    QString formatWin32ErrorText(const std::uint32_t errorCode)
    {
        if (errorCode == ERROR_SUCCESS)
        {
            return QStringLiteral("0");
        }

        wchar_t* messageBuffer = nullptr;
        const DWORD kChars = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            nullptr);
        QString messageText;
        if (kChars > 0 && messageBuffer != nullptr)
        {
            messageText = QString::fromWCharArray(messageBuffer, static_cast<int>(kChars)).trimmed();
        }
        if (messageBuffer != nullptr)
        {
            ::LocalFree(messageBuffer);
        }
        return messageText.isEmpty()
            ? QString::number(errorCode)
            : QStringLiteral("%1 (%2)").arg(errorCode).arg(messageText);
    }

    QString formatReparseTagText(const std::uint32_t tagValue)
    {
        return QStringLiteral("0x%1")
            .arg(tagValue, 8, 16, QChar('0'))
            .toUpper();
    }

    ks::file::ReparsePointQueryResult queryReparsePointForUi(const QString& path)
    {
        const QString kNativePathText = QDir::toNativeSeparators(path).trimmed();
        if (kNativePathText.isEmpty())
        {
            ks::file::ReparsePointQueryResult result{};
            result.errorText = L"路径为空。";
            result.win32Error = ERROR_INVALID_PARAMETER;
            return result;
        }

        const DWORD kAttributes = ::GetFileAttributesW(kNativePathText.toStdWString().c_str());
        const bool kDirectoryHint = kAttributes != INVALID_FILE_ATTRIBUTES
            && ((kAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U);
        return ks::file::queryReparsePointInfo(kNativePathText.toStdWString(), kDirectoryHint);
    }

    QString reparseKindMarkerForPath(const QString& path)
    {
        const QString kNativePathText = QDir::toNativeSeparators(path).trimmed();
        if (kNativePathText.isEmpty())
        {
            return QString();
        }

        const DWORD kAttributes = ::GetFileAttributesW(kNativePathText.toStdWString().c_str());
        if (kAttributes == INVALID_FILE_ATTRIBUTES || (kAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U)
        {
            return QString();
        }

        const ks::file::ReparsePointQueryResult kResult = queryReparsePointForUi(kNativePathText);
        const QString kKindText = QString::fromStdWString(kResult.kindName).trimmed();
        return kKindText.isEmpty() ? QStringLiteral("UNKNOWN_REPARSE") : kKindText;
    }

    QString reparseTargetFromResult(const ks::file::ReparsePointQueryResult& result)
    {
        QString targetText = QString::fromStdWString(result.resolvedTargetPath).trimmed();
        if (targetText.isEmpty())
        {
            targetText = QString::fromStdWString(result.printName).trimmed();
        }
        if (targetText.isEmpty())
        {
            targetText = QString::fromStdWString(result.substituteName).trimmed();
        }
        return QDir::toNativeSeparators(targetText);
    }

    QString formatReparsePointText(const QString& path)
    {
        const ks::file::ReparsePointQueryResult kResult = queryReparsePointForUi(path);
        QString content;
        content += QStringLiteral("目标路径: %1\n").arg(QDir::toNativeSeparators(path));

        if (!kResult.pathOpened)
        {
            content += QStringLiteral("状态: 无法打开目标（使用 FILE_FLAG_OPEN_REPARSE_POINT）\n");
            content += QStringLiteral("Win32错误: %1\n").arg(formatWin32ErrorText(kResult.win32Error));
            content += QStringLiteral("原因: %1\n").arg(QString::fromStdWString(kResult.errorText));
            return content;
        }

        if (!kResult.querySucceeded)
        {
            content += QStringLiteral("状态: FSCTL_GET_REPARSE_POINT 查询失败\n");
            content += QStringLiteral("是否重解析点: %1\n").arg(kResult.isReparsePoint ? QStringLiteral("是") : QStringLiteral("否"));
            content += QStringLiteral("Win32错误: %1\n").arg(formatWin32ErrorText(kResult.win32Error));
            content += QStringLiteral("原因: %1\n").arg(QString::fromStdWString(kResult.errorText));
            return content;
        }

        content += QStringLiteral("状态: OK\n");
        content += QStringLiteral("Reparse Tag: %1\n").arg(formatReparseTagText(kResult.tag));
        content += QStringLiteral("Tag名称: %1\n").arg(QString::fromStdWString(kResult.tagName));
        content += QStringLiteral("类型标记: %1\n").arg(QString::fromStdWString(kResult.kindName));
        content += QStringLiteral("Microsoft Tag: %1\n").arg(kResult.isMicrosoftTag ? QStringLiteral("是") : QStringLiteral("否"));
        content += QStringLiteral("Name Surrogate: %1\n").arg(kResult.isNameSurrogate ? QStringLiteral("是") : QStringLiteral("否"));
        content += QStringLiteral("是否相对链接: %1\n").arg(kResult.isRelative ? QStringLiteral("是") : QStringLiteral("否"));
        content += QStringLiteral("Substitute Name: %1\n").arg(QString::fromStdWString(kResult.substituteName));
        content += QStringLiteral("Print Name: %1\n").arg(QString::fromStdWString(kResult.printName));
        content += QStringLiteral("解析目标路径: %1\n").arg(reparseTargetFromResult(kResult));
        content += QStringLiteral("原始信息: %1\n").arg(QString::fromStdWString(kResult.rawPayloadText));
        content += QStringLiteral("Raw Hex Preview: %1\n").arg(QString::fromStdWString(kResult.rawHexPreview));
        if (!kResult.errorText.empty())
        {
            content += QStringLiteral("解析提示: %1\n").arg(QString::fromStdWString(kResult.errorText));
        }
        return content;
    }

    // buildDriverNtPath：
    // - Purpose: Convert Win32 paths to NT paths directly usable by the driver;
    // - Rule: Convert standard drive letter paths to \??\C:\..., and UNC paths to \??\UNC\...
    QString buildDriverNtPath(const QString& path)
    {
        const QString kNativePathText = QDir::toNativeSeparators(path).trimmed();
        if (kNativePathText.isEmpty())
        {
            return QString();
        }
        if (kNativePathText.startsWith(QStringLiteral("\\??\\")))
        {
            return kNativePathText;
        }
        if (kNativePathText.startsWith(QStringLiteral("\\\\?\\")))
        {
            return QStringLiteral("\\??\\") + kNativePathText.mid(4);
        }
        if (kNativePathText.startsWith(QStringLiteral("\\Device\\")))
        {
            return kNativePathText;
        }
        if (kNativePathText.startsWith(QStringLiteral("\\\\")))
        {
            return QStringLiteral("\\??\\UNC\\") + kNativePathText.mid(2);
        }
        return QStringLiteral("\\??\\") + kNativePathText;
    }

    // buildLiteralNameFilterPattern：
    // - Purpose: Convert the keyword into a wildcard pattern compatible with QFileSystemModel::setNameFilters for inclusion matching.
    // - Note: Escape *, ?, [, ] to prevent user input from being interpreted as wildcard syntax.
    QString buildLiteralNameFilterPattern(const QString& keywordText)
    {
        QString escapedKeyword = keywordText;
        escapedKeyword.replace(QStringLiteral("["), QStringLiteral("[[]"));
        escapedKeyword.replace(QStringLiteral("]"), QStringLiteral("[]]"));
        escapedKeyword.replace(QStringLiteral("*"), QStringLiteral("[*]"));
        escapedKeyword.replace(QStringLiteral("?"), QStringLiteral("[?]"));
        return QStringLiteral("*%1*").arg(escapedKeyword);
    }

    // queryShortPathText：
    // - Purpose: Query the Win32 short path (8.3) corresponding to the target path.
    // - On failure, return an empty string; the caller decides whether to fall back to the original name.
    QString queryShortPathText(const QString& path)
    {
        const std::wstring kNativePathText = QDir::toNativeSeparators(path).toStdWString();
        if (kNativePathText.empty())
        {
            return QString();
        }

        const DWORD kRequiredChars = ::GetShortPathNameW(kNativePathText.c_str(), nullptr, 0);
        if (kRequiredChars == 0)
        {
            return QString();
        }

        QVector<wchar_t> shortPathBuffer(static_cast<int>(kRequiredChars) + 2, L'\0');
        const DWORD kCopiedChars = ::GetShortPathNameW(
            kNativePathText.c_str(),
            shortPathBuffer.data(),
            static_cast<DWORD>(shortPathBuffer.size()));
        if (kCopiedChars == 0 || kCopiedChars >= static_cast<DWORD>(shortPathBuffer.size()))
        {
            return QString();
        }
        return QString::fromWCharArray(shortPathBuffer.data(), static_cast<int>(kCopiedChars));
    }

    QString normalizeFileDockPath(const QString& path)
    {
        return QDir::toNativeSeparators(QDir::cleanPath(path.trimmed()));
    }

    bool pathEqualsCaseInsensitive(const QString& left, const QString& right)
    {
        return normalizeFileDockPath(left).compare(
            normalizeFileDockPath(right),
            Qt::CaseInsensitive) == 0;
    }

    void closeWin32Handle(HANDLE& handleValue)
    {
        if (handleValue != nullptr && handleValue != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(handleValue);
            handleValue = INVALID_HANDLE_VALUE;
        }
    }

    QString oplockCompletionText(const bool completionOk, const unsigned long completionError)
    {
        if (completionOk)
        {
            return QStringLiteral("已触发/完成");
        }
        if (completionError == ERROR_OPERATION_ABORTED)
        {
            return QStringLiteral("已取消");
        }
        if (completionError == ERROR_HANDLE_EOF)
        {
            return QStringLiteral("目标句柄已关闭");
        }
        return QStringLiteral("完成失败，Win32=%1").arg(completionError);
    }
}
