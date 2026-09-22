#include "SandboxUploadActions.h"

#include "OnlineScanSupport.h"
#include "VirusTotalOnlineScan.h"
#include "../../../shared/platform/process/Process.h"

#include <QAction>
#include <QDir>
#include <QFileInfo>
#include <QIcon>
#include <QMenu>
#include <QMessageBox>
#include <QRegularExpression>
#include <QStringList>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <iterator>
#include <string>
#include <utility>

namespace
{
    // sandboxUploadIcon:
    // - Returns a unified upload/sandbox menu icon;
    // - No dedicated cloud sandbox alias exists in the qrc resources, so the existing virus icon is reused.
    // Returns: a QIcon that can be directly used with QMenu/QAction.
    QIcon sandboxUploadIcon()
    {
        return QIcon(QStringLiteral(":/Icon/process_critical.svg"));
    }

    // windowsDirectoryPath:
    // - Reads the current Windows directory, prioritizing GetWindowsDirectoryW, with fallback to the SystemRoot environment variable on failure;
    // - Converts \SystemRoot\System32\drivers\xxx.sys to C:\Windows\System32\drivers\xxx.sys.
    // Return: The local Windows directory; returns an empty string if reading fails.
    QString windowsDirectoryPath()
    {
        wchar_t windowsPathBuffer[MAX_PATH] = {};
        const UINT kCopiedChars = ::GetWindowsDirectoryW(windowsPathBuffer, MAX_PATH);
        if (kCopiedChars > 0 && kCopiedChars < MAX_PATH)
        {
            return QDir::toNativeSeparators(QString::fromWCharArray(windowsPathBuffer));
        }

        return QDir::toNativeSeparators(qEnvironmentVariable("SystemRoot"));
    }

    // stripOuterQuotes:
    // - Remove outer double quotes from the path;
    // - Strip quotes only when both the start and end are quotes, to avoid breaking command lines that contain quotes in the middle.
    // Input text: original path string.
    // Returns: the text with outer quotes stripped.
    QString stripOuterQuotes(const QString& text)
    {
        QString trimmedText = text.trimmed();
        while (trimmedText.size() >= 2 &&
            trimmedText.front() == QLatin1Char('"') &&
            trimmedText.back() == QLatin1Char('"'))
        {
            trimmedText = trimmedText.mid(1, trimmedText.size() - 2).trimmed();
        }
        return trimmedText;
    }

    // expandEnvironmentPath:
    // - Expand Windows environment variables such as %SystemRoot% and %ProgramFiles%.
    // - Qt does not automatically expand percent-formatted variables, so Win32 ExpandEnvironmentStringsW is used.
    // Input pathText: Path that may contain environment variables.
    // Returns the expanded path; returns the original path if expansion fails.
    QString expandEnvironmentPath(const QString& pathText)
    {
        const QString kTrimmedText = pathText.trimmed();
        if (!kTrimmedText.contains(QLatin1Char('%')))
        {
            return kTrimmedText;
        }

        const std::wstring kWideInput = kTrimmedText.toStdWString();
        DWORD requiredChars = ::ExpandEnvironmentStringsW(kWideInput.c_str(), nullptr, 0);
        if (requiredChars == 0)
        {
            return kTrimmedText;
        }

        std::wstring expandedText(requiredChars, L'\0');
        const DWORD kCopiedChars = ::ExpandEnvironmentStringsW(
            kWideInput.c_str(),
            expandedText.data(),
            requiredChars);
        if (kCopiedChars == 0 || kCopiedChars > requiredChars)
        {
            return kTrimmedText;
        }
        if (!expandedText.empty() && expandedText.back() == L'\0')
        {
            expandedText.pop_back();
        }
        return QString::fromStdWString(expandedText);
    }

    // mapNtDevicePathToDosPath:
    // - Map \Device\HarddiskVolumeX\... paths to C:\... format;
    // - enumerate local drive letters and their corresponding NT device prefixes via QueryDosDeviceW.
    // Input ntPathText: NT device path.
    // Return: The DOS path on successful mapping; an empty string on failure.
    QString mapNtDevicePathToDosPath(const QString& ntPathText)
    {
        const QString kNormalizedNtPath = QDir::toNativeSeparators(ntPathText.trimmed());
        if (!kNormalizedNtPath.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
        {
            return QString();
        }

        for (wchar_t driveLetter = L'A'; driveLetter <= L'Z'; ++driveLetter)
        {
            const QString kDriveText = QStringLiteral("%1:").arg(QChar(driveLetter));
            wchar_t deviceNameBuffer[1024] = {};
            const DWORD kCopiedChars = ::QueryDosDeviceW(
                reinterpret_cast<LPCWSTR>(kDriveText.utf16()),
                deviceNameBuffer,
                static_cast<DWORD>(std::size(deviceNameBuffer)));
            if (kCopiedChars == 0)
            {
                continue;
            }

            const QString kDeviceName = QDir::toNativeSeparators(QString::fromWCharArray(deviceNameBuffer));
            if (kDeviceName.isEmpty() || !kNormalizedNtPath.startsWith(kDeviceName, Qt::CaseInsensitive))
            {
                continue;
            }

            const QString kSuffixText = kNormalizedNtPath.mid(kDeviceName.size());
            if (!kSuffixText.isEmpty() && !kSuffixText.startsWith(QLatin1Char('\\')))
            {
                continue;
            }
            return QDir::toNativeSeparators(kDriveText + kSuffixText);
        }

        return QString();
    }

    // extractQuotedCommandPath:
    // - Extract the first path enclosed in quotes from a command line in the format "C:\Path\App.exe" -arg;
    // - Return only if the file exists to avoid mistaking ordinary arguments for paths.
    // Input parameter commandText: command-line text.
    // Returns: The first quoted path if found; an empty string on failure.
    QString extractQuotedCommandPath(const QString& commandText)
    {
        const QRegularExpression kQuotedPathExpression(QStringLiteral("\"([^\"]+)\""));
        QRegularExpressionMatchIterator matchIterator = kQuotedPathExpression.globalMatch(commandText);
        while (matchIterator.hasNext())
        {
            const QRegularExpressionMatch kMatch = matchIterator.next();
            const QString kCandidatePath = ks::online_scan::normalizeKernelImagePathForUpload(kMatch.captured(1));
            if (QFileInfo(kCandidatePath).isFile())
            {
                return QFileInfo(kCandidatePath).absoluteFilePath();
            }
        }
        return QString();
    }

    // extractUnquotedCommandPath:
    // - Attempt to extract an existing .exe/.dll/.sys/.ocx file path from an unquoted command line.
    // - Supports paths containing spaces by incrementally concatenating segments and checking file existence.
    // Input parameter commandText: command-line text.
    // Returns the existing file path; returns an empty string on failure.
    QString extractUnquotedCommandPath(const QString& commandText)
    {
        const QString kNormalizedText = ks::online_scan::normalizeKernelImagePathForUpload(commandText);
        const QStringList kTokenList = kNormalizedText.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        QString candidateText;
        for (const QString& tokenText : kTokenList)
        {
            candidateText = candidateText.isEmpty()
                ? tokenText
                : (candidateText + QLatin1Char(' ') + tokenText);
            const QString kStrippedCandidate = stripOuterQuotes(candidateText);
            const QFileInfo kCandidateInfo(kStrippedCandidate);
            if (kCandidateInfo.isFile())
            {
                return kCandidateInfo.absoluteFilePath();
            }

            const QString kLowerCandidate = kStrippedCandidate.toLower();
            if (kLowerCandidate.endsWith(QStringLiteral(".exe")) ||
                kLowerCandidate.endsWith(QStringLiteral(".dll")) ||
                kLowerCandidate.endsWith(QStringLiteral(".sys")) ||
                kLowerCandidate.endsWith(QStringLiteral(".ocx")))
            {
                break;
            }
        }
        return QString();
    }

    // defaultSourceText:
    // - Generate a unified fallback source text.
    // - Avoid showing an empty source in the result window.
    // Input sourceText: source text from the caller.
    // Returns: Non-empty source text.
    QString defaultSourceText(const QString& sourceText)
    {
        const QString kTrimmedText = sourceText.trimmed();
        return kTrimmedText.isEmpty() ? QStringLiteral("右键上传到沙箱") : kTrimmedText;
    }
}

QAction* ks::online_scan::addVirusTotalSandboxMenu(
    QMenu* menu,
    QWidget* parentWidget,
    QFilePathResolver resolver)
{
    if (menu == nullptr)
    {
        return nullptr;
    }

    // The menu structure is fixed as 'Upload to Sandbox -> VT-*'; ThreatBook is not displayed in this round.
    QMenu* sandboxMenu = menu->addMenu(sandboxUploadIcon(), QStringLiteral("上传到沙箱"));
    const auto kAddVirusTotalAction =
        [sandboxMenu, menu, parentWidget, &resolver](
            const QString& actionText,
            const VirusTotalOnlineScan::VtApiKind initialApi) -> QAction*
        {
            QAction* action = sandboxMenu->addAction(sandboxUploadIcon(), actionText);
            QObject::connect(action, &QAction::triggered, menu, [resolver, parentWidget, initialApi, actionText]()
                {
                    // Input: Current UI state when triggered by the right-click menu.
                    // Processing: Delay path resolution and enter the unified VT multi-API console; show a dialog for resolution exceptions.
                    // Returns: Nothing.
                    if (!resolver)
                    {
                        showErrorDialog(
                            parentWidget,
                            QStringLiteral("上传到沙箱"),
                            QStringLiteral("当前入口没有提供文件路径解析器。"));
                        return;
                    }

                    const SandboxUploadTarget kTarget = resolver();
                    if (kTarget.filePath.trimmed().isEmpty())
                    {
                        showErrorDialog(
                            parentWidget,
                            QStringLiteral("上传到沙箱 - %1").arg(actionText),
                            kTarget.errorText.trimmed().isEmpty()
                                ? QStringLiteral("未解析到可上传文件路径。若来源是 PID，进程可能已退出，或当前权限不足。")
                                : kTarget.errorText.trimmed());
                        return;
                    }
                    uploadFileToVirusTotal(kTarget.filePath, kTarget.sourceText, initialApi, parentWidget);
                });
            return action;
        };

    QAction* shallowAction = kAddVirusTotalAction(QStringLiteral("VT-浅分析"), VirusTotalOnlineScan::VtApiKind::kShallowAnalysis);
    kAddVirusTotalAction(QStringLiteral("VT-文件画像"), VirusTotalOnlineScan::VtApiKind::kFileProfile);
    kAddVirusTotalAction(QStringLiteral("VT-IOC"), VirusTotalOnlineScan::VtApiKind::kIoc);
    kAddVirusTotalAction(QStringLiteral("VT-沙箱"), VirusTotalOnlineScan::VtApiKind::kSandbox);
    kAddVirusTotalAction(QStringLiteral("VT-全部API"), VirusTotalOnlineScan::VtApiKind::kAllApis);
    return shallowAction;
}

void ks::online_scan::uploadFileToVirusTotal(
    const QString& filePath,
    const QString& sourceText,
    QWidget* parentWidget)
{
    uploadFileToVirusTotal(filePath, sourceText, VirusTotalOnlineScan::VtApiKind::kShallowAnalysis, parentWidget);
}

void ks::online_scan::uploadFileToVirusTotal(
    const QString& filePath,
    const QString& sourceText,
    const VirusTotalOnlineScan::VtApiKind initialApi,
    QWidget* parentWidget)
{
    const QString kNormalizedPath = extractExistingFilePathForUpload(filePath);
    QString fileErrorText;
    if (!validateReadableFile(kNormalizedPath, kVirusTotalLargeUploadMaxBytes, &fileErrorText))
    {
        showErrorDialog(
            parentWidget,
            QStringLiteral("上传到沙箱 - VT"),
            fileErrorText);
        return;
    }

    VirusTotalOnlineScan::scanFileAndAutoDelete(
        QFileInfo(kNormalizedPath).absoluteFilePath(),
        defaultSourceText(sourceText),
        initialApi,
        parentWidget);
}

void ks::online_scan::uploadProcessImageByPid(
    const std::uint32_t pid,
    const QString& sourceText,
    QWidget* parentWidget)
{
    if (pid == 0)
    {
        showErrorDialog(
            parentWidget,
            QStringLiteral("上传到沙箱 - VT"),
            QStringLiteral("PID 无效，无法解析进程镜像路径。"));
        return;
    }

    const QString kProcessPath = QString::fromStdString(ks::process::queryProcessPathByPid(pid)).trimmed();
    if (kProcessPath.isEmpty())
    {
        showErrorDialog(
            parentWidget,
            QStringLiteral("上传到沙箱 - VT"),
            QStringLiteral("无法解析 PID=%1 的进程镜像路径。进程可能已退出，或当前权限不足。").arg(pid));
        return;
    }

    // resolvedSourceText:
    // - Uses the caller-provided source description as-is;
    // - Explicitly write the PID when the source is empty to avoid the result window showing only the generic 'Right-click upload to sandbox'.
    const QString kResolvedSourceText = sourceText.trimmed().isEmpty()
        ? QStringLiteral("PID=%1").arg(pid)
        : sourceText.trimmed();
    uploadFileToVirusTotal(kProcessPath, kResolvedSourceText, parentWidget);
}

QString ks::online_scan::normalizeKernelImagePathForUpload(const QString& rawPathText)
{
    QString pathText = stripOuterQuotes(rawPathText);
    if (pathText.isEmpty())
    {
        return QString();
    }

    pathText.replace(QLatin1Char('/'), QLatin1Char('\\'));

    if (pathText.startsWith(QStringLiteral("\\??\\")))
    {
        pathText = pathText.mid(4);
    }
    else if (pathText.startsWith(QStringLiteral("\\\\?\\")))
    {
        pathText = pathText.mid(4);
    }

    const QString kWindowsPath = windowsDirectoryPath();
    if (pathText.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive) && !kWindowsPath.isEmpty())
    {
        pathText = kWindowsPath + pathText.mid(QStringLiteral("\\SystemRoot").size());
    }
    else if (pathText.compare(QStringLiteral("\\SystemRoot"), Qt::CaseInsensitive) == 0 && !kWindowsPath.isEmpty())
    {
        pathText = kWindowsPath;
    }
    else if (pathText.startsWith(QStringLiteral("SystemRoot\\"), Qt::CaseInsensitive) && !kWindowsPath.isEmpty())
    {
        pathText = kWindowsPath + QStringLiteral("\\") + pathText.mid(QStringLiteral("SystemRoot\\").size());
    }
    else if (pathText.startsWith(QStringLiteral("%SystemRoot%"), Qt::CaseInsensitive))
    {
        pathText = expandEnvironmentPath(pathText);
    }
    else if (pathText.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
    {
        const QString kMappedPath = mapNtDevicePathToDosPath(pathText);
        if (!kMappedPath.isEmpty())
        {
            pathText = kMappedPath;
        }
    }
    else
    {
        pathText = expandEnvironmentPath(pathText);
    }

    return QDir::toNativeSeparators(pathText);
}

QString ks::online_scan::extractExistingFilePathForUpload(const QString& rawPathText)
{
    QString pathText = normalizeKernelImagePathForUpload(rawPathText);
    if (pathText.isEmpty())
    {
        return QString();
    }

    const QFileInfo kDirectInfo(pathText);
    if (kDirectInfo.isFile())
    {
        return kDirectInfo.absoluteFilePath();
    }

    const QString kQuotedPath = extractQuotedCommandPath(pathText);
    if (!kQuotedPath.isEmpty())
    {
        return kQuotedPath;
    }

    const QString kUnquotedPath = extractUnquotedCommandPath(pathText);
    if (!kUnquotedPath.isEmpty())
    {
        return kUnquotedPath;
    }

    return pathText;
}

bool ks::online_scan::tryParsePidFromText(const QString& pidText, std::uint32_t* pidOut)
{
    if (pidOut != nullptr)
    {
        *pidOut = 0;
    }

    const QString kText = pidText.trimmed();
    if (kText.isEmpty())
    {
        return false;
    }

    // Process pure numbers first to avoid accidentally extracting fragments from fields like hexadecimal addresses.
    bool parseOk = false;
    const quint64 kDirectValue = kText.toULongLong(&parseOk, 10);
    if (parseOk && kDirectValue > 0 && kDirectValue <= 0xFFFFFFFFULL)
    {
        if (pidOut != nullptr)
        {
            *pidOut = static_cast<std::uint32_t>(kDirectValue);
        }
        return true;
    }

    const QRegularExpression kPidExpression(QStringLiteral("(?:PID|Pid|pid)?\\s*[:=]?\\s*(\\d{1,10})"));
    const QRegularExpressionMatch kMatch = kPidExpression.match(kText);
    if (!kMatch.hasMatch())
    {
        return false;
    }

    const quint64 kValue = kMatch.captured(1).toULongLong(&parseOk, 10);
    if (!parseOk || kValue == 0 || kValue > 0xFFFFFFFFULL)
    {
        return false;
    }

    if (pidOut != nullptr)
    {
        *pidOut = static_cast<std::uint32_t>(kValue);
    }
    return true;
}
