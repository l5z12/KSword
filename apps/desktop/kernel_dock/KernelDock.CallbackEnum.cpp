#include "KernelDock.h"
#include "../ui/TableInteractionSupport.h"

#include <memory>
#include "../ui/VisibleTableWidget.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../file_dock/FilePropertyPeAnalyzer.h"
#include "../online_scan/SandboxUploadActions.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/DetailLayoutHost.h"
#include "../ui/DetailLayoutRegistry.h"
/* Unified entry point: this page does not need to know GPA, EPT leaf, or ruleId. */
#include "../ui/KvmWatchDialog.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QClipboard>
#include <QColor>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileInfo>
#include <QFontMetrics>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QHash>
#include <QIcon>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QList>
#include <QMenu>
#include <QMetaObject>
#include <QMessageBox>
#include <QPoint>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QStringList>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "Version.lib")

using ksword::kernel_dock_internal::kernelText;

namespace
{
    struct CallbackEnumVersionText
    {
        QString company;
        QString fileVersion;
        QString description;
    };

    QString callbackEnumQueryVersionString(const QString& filePath, const wchar_t* valueName)
    {
        // Purpose: Read CompanyName, FileVersion, and FileDescription from the driver version resource.
        // Return: The value from the first matching translation table; returns an empty string if resources are missing.
        DWORD ignoredHandle = 0;
        const std::wstring kNativePath = QDir::toNativeSeparators(filePath).toStdWString();
        const DWORD kVersionBytes = ::GetFileVersionInfoSizeW(kNativePath.c_str(), &ignoredHandle);
        if (kVersionBytes == 0U || valueName == nullptr)
        {
            return QString();
        }

        std::vector<unsigned char> versionBuffer(kVersionBytes);
        if (::GetFileVersionInfoW(kNativePath.c_str(), 0, kVersionBytes, versionBuffer.data()) == FALSE)
        {
            return QString();
        }

        struct LanguageAndCodePage
        {
            WORD language;
            WORD codePage;
        };
        LanguageAndCodePage* translations = nullptr;
        UINT translationBytes = 0;
        std::vector<LanguageAndCodePage> candidates;
        if (::VerQueryValueW(
                versionBuffer.data(),
                L"\\VarFileInfo\\Translation",
                reinterpret_cast<void**>(&translations),
                &translationBytes) != FALSE
            && translations != nullptr
            && translationBytes >= sizeof(LanguageAndCodePage))
        {
            const std::size_t kTranslationCount = translationBytes / sizeof(LanguageAndCodePage);
            candidates.assign(translations, translations + kTranslationCount);
        }
        candidates.push_back({ 0x0409, 0x04B0 });
        candidates.push_back({ 0x0000, 0x04B0 });

        for (const LanguageAndCodePage& candidate : candidates)
        {
            const QString kQueryPath = QStringLiteral("\\StringFileInfo\\%1%2\\%3")
                .arg(candidate.language, 4, 16, QLatin1Char('0'))
                .arg(candidate.codePage, 4, 16, QLatin1Char('0'))
                .arg(QString::fromWCharArray(valueName));
            wchar_t* valueText = nullptr;
            UINT valueChars = 0;
            if (::VerQueryValueW(
                    versionBuffer.data(),
                    reinterpret_cast<LPCWSTR>(kQueryPath.utf16()),
                    reinterpret_cast<void**>(&valueText),
                    &valueChars) != FALSE
                && valueText != nullptr
                && valueChars != 0U)
            {
                return QString::fromWCharArray(valueText, static_cast<int>(valueChars - 1U)).trimmed();
            }
        }
        return QString();
    }

    CallbackEnumVersionText callbackEnumQueryVersionText(const QString& filePath)
    {
        // Purpose: Read the company name, file version, and file description of any callback module in one go.
        // Returns: version text with fields allowed to be empty.
        CallbackEnumVersionText result;
        result.company = callbackEnumQueryVersionString(filePath, L"CompanyName");
        result.fileVersion = callbackEnumQueryVersionString(filePath, L"FileVersion");
        result.description = callbackEnumQueryVersionString(filePath, L"FileDescription");
        return result;
    }

    QString callbackEnumButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    QString callbackEnumInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:2px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    QString callbackEnumHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    QString callbackEnumSelectionStyle()
    {
        return QString();
    }

    QString callbackEnumStatusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    // callbackEnumStatusNotSupported：
    // - Purpose: Provides a 'not supported' return value consistent with NTSTATUS for user-mode compilation units;
    // - Inputs: None;
    // - Return: Equivalent long constant for STATUS_NOT_SUPPORTED, avoiding dependency on additional ntstatus headers in this file.
    constexpr long callbackEnumStatusNotSupported()
    {
        return static_cast<long>(0xC00000BBL);
    }

    QString callbackEnumSafeText(
        const QString& valueText,
        const QString& fallbackText = kernelText("kernel.callback.enum.placeholder.empty", QStringLiteral("<空>")))
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    // callbackEnumIoMessageText：
    // - Input: Raw message text returned by ArkDriverClient;
    // - Processing: Convert low-level terms such as DeviceIoControl, unsupported, capability, and buffer into readable descriptions for the callback enumeration page.
    // - Returns: A concise Chinese phrase suitable for the details dialog and the last column of the table, avoiding direct exposure of IOCTL debug logs.
    QString callbackEnumIoMessageText(const QString& rawMessageText)
    {
        const QString kTrimmedText = rawMessageText.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return kernelText("kernel.callback.enum.message.no_driver_message", QStringLiteral("驱动未返回额外说明。"));
        }

        const QString kLowerText = kTrimmedText.toLower();
        if (kLowerText.contains(QStringLiteral("deviceiocontrol")))
        {
            return kernelText("kernel.callback.enum.message.communication_failure", QStringLiteral("驱动 IOCTL 调用失败或当前驱动版本不匹配。"));
        }
        if (kLowerText.contains(QStringLiteral("unsupported")) ||
            kLowerText.contains(QStringLiteral("not supported")) ||
            kLowerText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return kernelText("kernel.callback.enum.message.unsupported", QStringLiteral("当前驱动暂不支持该回调枚举/移除接口。"));
        }
        if (kLowerText.contains(QStringLiteral("capability")) ||
            kLowerText.contains(QStringLiteral("dyndata")))
        {
            return kernelText("kernel.callback.enum.message.capability", QStringLiteral("动态偏移能力未满足，回调结构或全局地址暂不可用。"));
        }
        if (kLowerText.contains(QStringLiteral("buffer")) &&
            (kLowerText.contains(QStringLiteral("small")) || kLowerText.contains(QStringLiteral("trunc"))))
        {
            return kernelText("kernel.callback.enum.message.buffer_short", QStringLiteral("驱动返回缓冲区不足，结果可能被截断。"));
        }
        return kTrimmedText;
    }

    QString callbackEnumFormatAddress(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString callbackEnumWindowsDirectoryPath()
    {
        // Purpose: Parse the Windows directory to convert \SystemRoot\xxx paths into accessible Win32 paths.
        // Return: Absolute path of the Windows directory; fall back to environment variables on failure.
        wchar_t windowsPathBuffer[MAX_PATH] = {};
        const UINT kCopiedChars = ::GetWindowsDirectoryW(windowsPathBuffer, MAX_PATH);
        if (kCopiedChars > 0U && kCopiedChars < MAX_PATH)
        {
            return QDir::toNativeSeparators(QString::fromWCharArray(windowsPathBuffer));
        }

        const QString kEnvPath = qEnvironmentVariable("SystemRoot");
        return kEnvPath.isEmpty()
            ? QStringLiteral("C:\\Windows")
            : QDir::toNativeSeparators(kEnvPath);
    }

    QString callbackEnumSystemDrivePrefix()
    {
        // Purpose: Extract the system drive letter from the Windows directory, handling kernel paths like \Windows\xxx.
        // Returns: A drive letter in the format 'C:'; defaults to 'C:' if undeterminable.
        const QString kWindowsPath = callbackEnumWindowsDirectoryPath();
        if (kWindowsPath.size() >= 2 && kWindowsPath.at(1) == QLatin1Char(':'))
        {
            return kWindowsPath.left(2);
        }
        return QStringLiteral("C:");
    }

    QString callbackEnumMapNtDevicePathToDosPath(const QString& ntPathText)
    {
        // Purpose: Attempt to map \Device\HarddiskVolumeX\... to C:\... .
        // Return: Returns Win32 path on success; empty string on failure.
        const QString kNormalizedNtPath = QDir::toNativeSeparators(ntPathText.trimmed());
        if (!kNormalizedNtPath.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
        {
            return QString();
        }

        for (wchar_t driveLetter = L'A'; driveLetter <= L'Z'; ++driveLetter)
        {
            const QString kDriveName = QStringLiteral("%1:").arg(QChar(driveLetter));
            wchar_t deviceNameBuffer[1024] = {};
            const DWORD kCopiedChars = ::QueryDosDeviceW(
                reinterpret_cast<LPCWSTR>(kDriveName.utf16()),
                deviceNameBuffer,
                static_cast<DWORD>(sizeof(deviceNameBuffer) / sizeof(deviceNameBuffer[0])));
            if (kCopiedChars == 0U)
            {
                continue;
            }

            const QString kDeviceName = QDir::toNativeSeparators(QString::fromWCharArray(deviceNameBuffer));
            if (kDeviceName.isEmpty() || !kNormalizedNtPath.startsWith(kDeviceName, Qt::CaseInsensitive))
            {
                continue;
            }

            const QString kSuffixText = kNormalizedNtPath.mid(kDeviceName.size());
            return QDir::toNativeSeparators(kDriveName + kSuffixText);
        }

        return QString();
    }

    QString callbackEnumNormalizeModulePath(const QString& modulePathText)
    {
        // Purpose: normalize the module path returned in R0 to a Win32 file path accessible from R3.
        // Returns: accessible Win32 path; returns an empty string if conversion fails.
        QString pathText = modulePathText.trimmed();
        if (pathText.isEmpty() || pathText == QStringLiteral("<未解析>"))
        {
            return QString();
        }

        pathText = QDir::toNativeSeparators(pathText);
        if (pathText.startsWith(QStringLiteral("\\??\\"), Qt::CaseInsensitive))
        {
            pathText = pathText.mid(4);
        }
        if (pathText.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive))
        {
            pathText = callbackEnumWindowsDirectoryPath() + pathText.mid(QStringLiteral("\\SystemRoot").size());
        }
        else if (pathText.startsWith(QStringLiteral("SystemRoot\\"), Qt::CaseInsensitive))
        {
            pathText = callbackEnumWindowsDirectoryPath() + QStringLiteral("\\") + pathText.mid(QStringLiteral("SystemRoot\\").size());
        }
        else if (pathText.startsWith(QStringLiteral("\\Windows\\"), Qt::CaseInsensitive))
        {
            pathText = callbackEnumSystemDrivePrefix() + pathText;
        }
        else if (pathText.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
        {
            pathText = callbackEnumMapNtDevicePathToDosPath(pathText);
        }

        if (pathText.size() >= 2 && pathText.at(1) == QLatin1Char(':'))
        {
            const QFileInfo kFileInfo(pathText);
            return kFileInfo.exists() ? kFileInfo.absoluteFilePath() : QDir::toNativeSeparators(pathText);
        }
        return QString();
    }

    QString callbackEnumBuildModuleFileGeneralText(const QString& filePath)
    {
        // Purpose: Generate the general information page of the module file details window.
        // Returns: Plain text containing the path, size, and timestamp.
        const QFileInfo kFileInfo(filePath);
        const QString kUnavailableText = QStringLiteral("<不可用>");
        const auto kYesNoText = [](const bool value) {
            return value ? QStringLiteral("是") : QStringLiteral("否");
        };
        return QStringLiteral(
            "文件路径：%1\n"
            "文件名：%2\n"
            "所在目录：%3\n"
            "是否存在：%4\n"
            "大小：%5 字节\n"
            "创建时间：%6\n"
            "修改时间：%7\n"
            "访问时间：%8\n"
            "可读：%9\n"
            "可写：%10\n"
            "可执行：%11")
            .arg(QDir::toNativeSeparators(kFileInfo.absoluteFilePath()))
            .arg(kFileInfo.fileName())
            .arg(QDir::toNativeSeparators(kFileInfo.absolutePath()))
            .arg(kYesNoText(kFileInfo.exists()))
            .arg(kFileInfo.exists() ? QString::number(kFileInfo.size()) : kUnavailableText)
            .arg(kFileInfo.birthTime().isValid() ? kFileInfo.birthTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")) : kUnavailableText)
            .arg(kFileInfo.lastModified().isValid() ? kFileInfo.lastModified().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")) : kUnavailableText)
            .arg(kFileInfo.lastRead().isValid() ? kFileInfo.lastRead().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")) : kUnavailableText)
            .arg(kYesNoText(kFileInfo.isReadable()))
            .arg(kYesNoText(kFileInfo.isWritable()))
            .arg(kYesNoText(kFileInfo.isExecutable()));
    }

    void callbackEnumShowModuleFileDetailDialog(QWidget* parentWidget, const QString& filePath)
    {
        // Purpose: Display the module file details dialog, reusing the PE parsing report from FileDock.
        // Return: None; the window is modal and local objects are automatically released upon closing.
        QDialog detailDialog(parentWidget);
        detailDialog.setObjectName(QStringLiteral("CallbackEnumModuleFileDetailDialog"));
        detailDialog.setWindowTitle(kernelText("kernel.callback.enum.file.title", QStringLiteral("模块文件详细信息 - %1"))
            .arg(QFileInfo(filePath).fileName()));
        detailDialog.resize(980, 680);
        detailDialog.setStyleSheet(ksword_theme::opaqueDialogStyle(detailDialog.objectName()));

        QVBoxLayout* rootLayout = new QVBoxLayout(&detailDialog);
        QTabWidget* tabWidget = new QTabWidget(&detailDialog);
        rootLayout->addWidget(tabWidget, 1);

        CodeEditorWidget* generalEditor = new CodeEditorWidget(&detailDialog);
        generalEditor->setReadOnly(true);
        generalEditor->setLocalizedText(callbackEnumBuildModuleFileGeneralText(filePath));
        tabWidget->addTab(generalEditor, kernelText("kernel.callback.enum.file.tab.general", QStringLiteral("常规信息")));

        CodeEditorWidget* peEditor = new CodeEditorWidget(&detailDialog);
        peEditor->setReadOnly(true);
        peEditor->setLocalizedText(file_dock_detail::buildPeAnalysisText(filePath));
        tabWidget->addTab(peEditor, kernelText("kernel.callback.enum.file.tab.pe", QStringLiteral("PE信息")));

        QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &detailDialog);
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &detailDialog, &QDialog::reject);
        QObject::connect(buttonBox, &QDialogButtonBox::accepted, &detailDialog, &QDialog::accept);
        rootLayout->addWidget(buttonBox, 0);
        detailDialog.exec();
    }

    bool callbackEnumOpenModuleInExplorer(const QString& filePath)
    {
        // Purpose: Locate the module file using Explorer; return false on failure to allow the caller to update the status bar.
        // Returns: true if Explorer starts successfully.
        if (filePath.trimmed().isEmpty())
        {
            return false;
        }
        const QString kNativePath = QDir::toNativeSeparators(filePath);
        const QString kSelectArgument = QStringLiteral("/select,\"%1\"").arg(kNativePath);
        return QProcess::startDetached(QStringLiteral("explorer.exe"), QStringList{ kSelectArgument });
    }

    QString callbackEnumClassText(const std::uint32_t callbackClass)
    {
        switch (callbackClass)
        {
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY:
            return kernelText("kernel.callback.enum.class.registry", QStringLiteral("注册表 CmCallback"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS:
            return kernelText("kernel.callback.enum.class.process", QStringLiteral("进程 Notify"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD:
            return kernelText("kernel.callback.enum.class.thread", QStringLiteral("线程 Notify"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE:
            return kernelText("kernel.callback.enum.class.image", QStringLiteral("镜像加载 Notify"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT:
            return QStringLiteral("Object Callback");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER:
            return QStringLiteral("Minifilter");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
            return QStringLiteral("WFP Callout");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
            return QStringLiteral("ETW Provider/Consumer");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_GENERIC_KERNEL:
            return kernelText("kernel.callback.enum.class.generic_kernel", QStringLiteral("通用内核 CallbackObject"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK:
            return kernelText("kernel.callback.enum.class.bugcheck", QStringLiteral("BugCheck 回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK_REASON:
            return kernelText("kernel.callback.enum.class.bugcheck_reason", QStringLiteral("BugCheckReason 回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_SHUTDOWN:
            return kernelText("kernel.callback.enum.class.shutdown", QStringLiteral("Shutdown 回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_FILE_SYSTEM:
            return kernelText("kernel.callback.enum.class.file_system", QStringLiteral("文件系统注册变化"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_LOGON_SESSION:
            return kernelText("kernel.callback.enum.class.logon_session", QStringLiteral("登录会话终止"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE_VERIFICATION:
            return kernelText("kernel.callback.enum.class.image_verification", QStringLiteral("镜像验证回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI:
            return kernelText("kernel.callback.enum.class.nmi", QStringLiteral("NMI 回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_LEGACY_FS_FILTER:
            return kernelText(
                "kernel.callback.enum.class.legacy_fs_filter",
                QStringLiteral("旧式 FS Filter pre/post 链"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_POWER_SETTING:
            return kernelText("kernel.callback.enum.class.power_setting", QStringLiteral("电源设置回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_COALESCING:
            return kernelText("kernel.callback.enum.class.coalescing", QStringLiteral("Coalescing 回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_PRIORITY:
            return kernelText("kernel.callback.enum.class.priority", QStringLiteral("优先级回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_DEBUG_PRINT:
            return kernelText("kernel.callback.enum.class.debug_print", QStringLiteral("调试打印回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_EMP:
            return kernelText("kernel.callback.enum.class.emp", QStringLiteral("EMP Provider 回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_PLUG_PLAY:
            return kernelText("kernel.callback.enum.class.plug_play", QStringLiteral("即插即用回调"));
        default:
            return kernelText("kernel.callback.enum.placeholder.unknown_with_value", QStringLiteral("未知(%1)"))
                .arg(callbackClass);
        }
    }

    QString callbackEnumSourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF:
            return kernelText("kernel.callback.enum.source.ksword_self", QStringLiteral("Ksword 自身注册"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION:
            return kernelText("kernel.callback.enum.source.fltmgr", QStringLiteral("FltMgr 公开枚举"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED:
            return kernelText("kernel.callback.enum.source.private_unsupported", QStringLiteral("私有结构诊断"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN:
            return kernelText("kernel.callback.enum.source.private_pattern", QStringLiteral("私有特征定位"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY:
            return kernelText("kernel.callback.enum.source.private_notify_array", QStringLiteral("Psp Notify 数组"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST:
            return kernelText("kernel.callback.enum.source.private_registry_list", QStringLiteral("Cm 回调链表"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST:
            return kernelText("kernel.callback.enum.source.private_object_type_list", QStringLiteral("Ob 对象类型链表"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_WFP_MGMT_API:
            return kernelText("kernel.callback.enum.source.wfp_api", QStringLiteral("WFP 管理 API"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_ETW_DYNDATA:
            return QStringLiteral("ETW DynData");
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE:
            return kernelText("kernel.callback.enum.source.pdb_profile", QStringLiteral("PDB 可信 profile"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PUBLIC_API:
            return kernelText("kernel.callback.enum.source.public_api", QStringLiteral("公开 API"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_BUGCHECK_LIST:
            return kernelText("kernel.callback.enum.source.bugcheck_list", QStringLiteral("BugCheck 记录链"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_FILESYSTEM_LIST:
            return kernelText("kernel.callback.enum.source.filesystem_list", QStringLiteral("文件系统通知链"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_LOGON_LIST:
            return kernelText("kernel.callback.enum.source.logon_list", QStringLiteral("登录会话通知链"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_CALLBACK_OBJECT:
            return kernelText("kernel.callback.enum.source.callback_object", QStringLiteral("CallbackObject 注册链"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_DRIVER_OBJECT_SCAN:
            return kernelText("kernel.callback.enum.source.driver_object_scan", QStringLiteral("DriverObject/DeviceObject 扫描"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_OBJECT_DIRECTORY:
            return kernelText("kernel.callback.enum.source.object_directory", QStringLiteral("对象目录枚举"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST:
            return kernelText("kernel.callback.enum.source.nmi_list", QStringLiteral("NMI 私有注册链"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL:
            return kernelText(
                "kernel.callback.enum.source.legacy_fs_public_structural",
                QStringLiteral("公开 FS Filter 枚举 + ClassInitData 结构签名"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_SPECIAL_CALLBACK:
            return kernelText(
                "kernel.callback.enum.source.private_special_callback",
                QStringLiteral("私有特殊回调表/链"));
        default:
            return kernelText("kernel.callback.enum.placeholder.unknown_with_value", QStringLiteral("未知(%1)"))
                .arg(source);
        }
    }

    QString callbackEnumRegistrationTypeText(const std::uint32_t registrationType)
    {
        // Purpose: Map the specific registration API type of the current protocol to filterable text.
        // Returns: displays "Unclassified" for unknown or legacy protocol rows.
        switch (registrationType)
        {
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_LEGACY:
            return kernelText(
                "kernel.callback.enum.registration_type.process_legacy",
                QStringLiteral("进程 Notify（Legacy）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_EX:
            return kernelText(
                "kernel.callback.enum.registration_type.process_ex",
                QStringLiteral("进程 Notify（Ex）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_EX2:
            return kernelText(
                "kernel.callback.enum.registration_type.process_ex2",
                QStringLiteral("进程 Notify（Ex2）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_THREAD_LEGACY:
            return kernelText(
                "kernel.callback.enum.registration_type.thread_legacy",
                QStringLiteral("线程 Notify（Legacy）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_THREAD_EX_NON_SYSTEM:
            return kernelText(
                "kernel.callback.enum.registration_type.thread_ex_non_system",
                QStringLiteral("线程 Notify（Ex/NonSystem）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_THREAD_EX_SUBSYSTEMS:
            return kernelText(
                "kernel.callback.enum.registration_type.thread_ex_subsystems",
                QStringLiteral("线程 Notify（Ex/Subsystems）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_LEGACY_OR_EX_DEFAULT:
            return kernelText(
                "kernel.callback.enum.registration_type.image_legacy_or_ex_default",
                QStringLiteral("镜像 Notify（Legacy/Ex 默认）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_EX_CONFLICTING_ARCHITECTURE:
            return kernelText(
                "kernel.callback.enum.registration_type.image_ex_conflicting_architecture",
                QStringLiteral("镜像 Notify（Ex/冲突架构）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_CLASSIC:
            return kernelText(
                "kernel.callback.enum.registration_type.bugcheck_classic",
                QStringLiteral("BugCheck（经典）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_SECONDARY_DUMP:
            return kernelText(
                "kernel.callback.enum.registration_type.bugcheck_secondary_dump",
                QStringLiteral("BugCheckReason（SecondaryDump）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_DUMP_IO:
            return kernelText(
                "kernel.callback.enum.registration_type.bugcheck_dump_io",
                QStringLiteral("BugCheckReason（DumpIo）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_TRIAGE_DUMP:
            return kernelText(
                "kernel.callback.enum.registration_type.bugcheck_triage_dump",
                QStringLiteral("BugCheckReason（TriageDump）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_REASON_OTHER:
            return kernelText(
                "kernel.callback.enum.registration_type.bugcheck_reason_other",
                QStringLiteral("BugCheckReason（其他）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_SHUTDOWN:
            return kernelText(
                "kernel.callback.enum.registration_type.shutdown",
                QStringLiteral("Shutdown 通知"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_FILE_SYSTEM_CHANGE:
            return kernelText(
                "kernel.callback.enum.registration_type.file_system_change",
                QStringLiteral("文件系统注册变化"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LOGON_LEGACY:
            return kernelText(
                "kernel.callback.enum.registration_type.logon_legacy",
                QStringLiteral("登录会话（Legacy）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LOGON_EX:
            return kernelText(
                "kernel.callback.enum.registration_type.logon_ex",
                QStringLiteral("登录会话（Ex）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_VERIFY_INFORMATIONAL:
            return kernelText(
                "kernel.callback.enum.registration_type.image_verify_informational",
                QStringLiteral("镜像验证（Informational）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_VERIFY_BLOCK:
            return kernelText(
                "kernel.callback.enum.registration_type.image_verify_block",
                QStringLiteral("镜像验证（Block）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_GENERIC_CALLBACK_OBJECT:
            return kernelText(
                "kernel.callback.enum.registration_type.generic_callback_object",
                QStringLiteral("通用 CallbackObject"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI:
            return kernelText(
                "kernel.callback.enum.registration_type.nmi",
                QStringLiteral("NMI 回调"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_DESKTOP_OBJECT:
            return kernelText(
                "kernel.callback.enum.registration_type.desktop_object",
                QStringLiteral("Desktop 对象回调"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_CLASS_INIT:
            return kernelText(
                "kernel.callback.enum.registration_type.legacy_fs_class_init",
                QStringLiteral("Legacy FS ClassInitData"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_PRE:
            return kernelText(
                "kernel.callback.enum.registration_type.legacy_fs_pre",
                QStringLiteral("Legacy FS Pre 回调"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_POST:
            return kernelText(
                "kernel.callback.enum.registration_type.legacy_fs_post",
                QStringLiteral("Legacy FS Post 回调"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_POWER_SETTING:
            return kernelText(
                "kernel.callback.enum.registration_type.power_setting",
                QStringLiteral("PoRegisterPowerSettingCallback"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_COALESCING:
            return kernelText(
                "kernel.callback.enum.registration_type.coalescing",
                QStringLiteral("PoRegisterCoalescingCallback"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PRIORITY:
            return kernelText(
                "kernel.callback.enum.registration_type.priority",
                QStringLiteral("IoRegisterPriorityCallback"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_DEBUG_PRINT:
            return kernelText(
                "kernel.callback.enum.registration_type.debug_print",
                QStringLiteral("DbgSetDebugPrintCallback"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_EMP:
            return kernelText(
                "kernel.callback.enum.registration_type.emp",
                QStringLiteral("EmpProviderRegister"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PLUG_PLAY:
            return kernelText(
                "kernel.callback.enum.registration_type.plug_play",
                QStringLiteral("IoRegisterPlugPlayNotification"));
        default:
            return kernelText("kernel.callback.enum.registration_type.unclassified", QStringLiteral("未分类"));
        }
    }

    enum class CallbackEnumRemovePolicyKind : int
    {
        kNotRemovable = 0,
        kRemovableVerified,
        kRemovableCandidate,
        kExperimentalOnly
    };

    bool callbackEnumHasField(const KernelCallbackEnumEntry& entry, const std::uint32_t fieldFlag)
    {
        // Input: one cached callback row and one KSWORD_ARK_CALLBACK_ENUM_FIELD_* bit.
        // Processing: masks the legacy fieldFlags value without looking at future protocol bytes.
        // Return: true only when the existing protocol explicitly marks the field as present.
        return (entry.fieldFlags & fieldFlag) != 0U;
    }

    bool callbackEnumFieldIndicatesTrusted(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: checks the optional trusted field bit only when the shared header has it.
        // Return: true when R0 explicitly marked this row as trusted; false on old headers.
#if defined(KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED)
        return callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED);
#else
        return false;
#endif
    }

    bool callbackEnumFieldIndicatesVerifiedRemove(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: checks the optional verified-remove field bit when available.
        // Return: true when R0 says the safe remove path is verified; false on old headers.
#if defined(KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE)
        return callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE);
#else
        return false;
#endif
    }

    bool callbackEnumFieldIndicatesExperimentalRemove(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: checks the optional experimental-remove field bit when available.
        // Return: true when R0 says this row only has an experimental unlink path; false otherwise.
#if defined(KSWORD_ARK_CALLBACK_ENUM_FIELD_EXPERIMENTAL_REMOVE)
        return callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_EXPERIMENTAL_REMOVE);
#else
        return false;
#endif
    }

    bool callbackEnumTrustFlagsIndicateTrusted(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: reads optional trust flags without making old shared headers incompatible.
        // Return: true for PDB/revalidated trust; false when the flags are absent or unrelated.
#if defined(KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE) && defined(KSWORD_ARK_CALLBACK_TRUST_REVALIDATED)
        return (entry.trustFlags & (KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE | KSWORD_ARK_CALLBACK_TRUST_REVALIDATED)) != 0U;
#else
        return entry.trustFlags != 0U;
#endif
    }

    bool callbackEnumTrustFlagsIndicatePublicApi(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: checks optional trust flags for public API provenance.
        // Return: true when R0 explicitly reports public API trust; false on old headers.
#if defined(KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API)
        return (entry.trustFlags & KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API) != 0U;
#else
        return false;
#endif
    }

    bool callbackEnumTrustFlagsIndicateFallbackPattern(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: checks optional trust flags for fallback/pattern provenance.
        // Return: true when R0 explicitly reports fallback evidence; false on old headers.
#if defined(KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN)
        return (entry.trustFlags & KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN) != 0U;
#else
        return false;
#endif
    }

    bool callbackEnumRemoveBehaviorIndicatesPublicApi(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: reads optional remove-behavior flags for the safe public API path.
        // Return: true when the future protocol marks public API removal; false on old headers.
#if defined(KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API)
        return (entry.removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API) != 0U;
#else
        return false;
#endif
    }

    bool callbackEnumRemoveBehaviorIndicatesExperimentalUnlink(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: reads optional remove-behavior flags for experimental unlink.
        // Return: true when the future protocol marks unlink-only behavior; false on old headers.
#if defined(KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK)
        return (entry.removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK) != 0U;
#else
        return false;
#endif
    }

    bool callbackEnumIsPublicApiSource(const std::uint32_t source)
    {
        // Input: the shared callback enumeration source id.
        // Processing: maps sources that came from documented management/enumeration APIs.
        // Return: true for public API backed sources; false for private/fallback diagnostics.
        return source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION
            || source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_WFP_MGMT_API
            || source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PUBLIC_API
            || source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_DRIVER_OBJECT_SCAN
            || source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL;
    }

    bool callbackEnumIsFallbackPatternSource(const std::uint32_t source)
    {
        // Input: the shared callback enumeration source id.
        // Processing: groups private arrays/lists/pattern probes as fallback-style evidence.
        // Return: true when the source should be presented as fallback/pattern only.
        switch (source)
        {
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_ETW_DYNDATA:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_BUGCHECK_LIST:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_FILESYSTEM_LIST:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_LOGON_LIST:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_CALLBACK_OBJECT:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_OBJECT_DIRECTORY:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_SPECIAL_CALLBACK:
            return true;
        default:
            return false;
        }
    }

    bool callbackEnumIsUnsupportedSource(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: combines the explicit unsupported source with unsupported row status.
        // Return: true when UI should show unsupported instead of trusted/public/fallback.
        return entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED
            || entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED;
    }

    bool callbackEnumIsTrustedSource(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row with legacy and reserved trust metadata.
        // Processing: treats Ksword-owned rows as trusted today and leaves PDB trust flags
        //             reserved for future protocol parsing.
        // Return: true for rows that are trusted without requiring private fallback evidence.
        return entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF
            || callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNED_BY_KSWORD)
            || callbackEnumFieldIndicatesTrusted(entry)
            || callbackEnumTrustFlagsIndicateTrusted(entry);
    }

    QString callbackEnumSourceTrustText(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: collapses current source ids plus reserved trust flags into the four
        //             UX buckets requested for PDB trusted callback readiness.
        // Return: display text that includes trusted/fallback/public api/unsupported keywords.
        if (callbackEnumIsUnsupportedSource(entry))
        {
            return kernelText("kernel.callback.enum.trust.unsupported", QStringLiteral("unsupported（当前协议/平台未支持）"));
        }
        if (callbackEnumIsTrustedSource(entry))
        {
            return kernelText("kernel.callback.enum.trust.trusted", QStringLiteral("trusted（可信/自有或预留 PDB）"));
        }
        if (callbackEnumIsPublicApiSource(entry.source)
            || callbackEnumTrustFlagsIndicatePublicApi(entry)
            || callbackEnumRemoveBehaviorIndicatesPublicApi(entry))
        {
            return kernelText("kernel.callback.enum.trust.public_api", QStringLiteral("public api（公开 API）"));
        }
        if (callbackEnumIsFallbackPatternSource(entry.source)
            || callbackEnumTrustFlagsIndicateFallbackPattern(entry))
        {
            return kernelText("kernel.callback.enum.trust.fallback_pattern", QStringLiteral("fallback/pattern（私有结构诊断）"));
        }
        return kernelText("kernel.callback.enum.trust.fallback", QStringLiteral("fallback（未知来源保守展示）"));
    }

    std::uint32_t callbackEnumRemoveTypeForClass(const std::uint32_t callbackClass)
    {
        // Input: callback enum class from the shared enum protocol.
        // Processing: maps enum classes to the old REMOVE_EXTERNAL_CALLBACK request classes.
        // Return: external remove class id; 0 means no compatible old remove request exists.
        switch (callbackClass)
        {
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER;
        default:
            return 0U;
        }
    }

    std::uint64_t callbackEnumRemoveRequestValue(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: chooses the value accepted by the legacy remove protocol. The field is
        //             named callbackAddress, but WFP currently carries calloutId there.
        // Return: non-zero request value for removeExternalCallback, or 0 when unavailable.
        if (entry.callbackAddress != 0U
            && (callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS)
                || callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER)
                || callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE)
                || (entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE) != 0U))
        {
            return entry.callbackAddress;
        }
        if (entry.registrationAddress != 0U
            && callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER))
        {
            return entry.registrationAddress;
        }
        return 0U;
    }

    bool callbackEnumHasExperimentalStorageValue(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: checks legacy diagnostic addresses and reserved raw storage metadata.
        // Return: true when UI can describe an unlink-only candidate without sending IOCTLs.
        return entry.rawStorageValue != 0U
            || entry.callbackAddress != 0U
            || entry.registrationAddress != 0U
            || entry.contextAddress != 0U;
    }

    CallbackEnumRemovePolicyKind callbackEnumRemovePolicyKind(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: derives a conservative UI policy from legacy removable-candidate bits,
        //             source trust class, and the presence of a legacy remove request value.
        // Return: the display policy; this does not create any new driver protocol.
        if (callbackEnumIsUnsupportedSource(entry)
            || entry.status != KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
            || callbackEnumRemoveTypeForClass(entry.callbackClass) == 0U)
        {
            return CallbackEnumRemovePolicyKind::kNotRemovable;
        }

        // Registry and ETW have no reliable safe removal path. Object callbacks
        // are removable only when R0 published a real profile-gated handle plus
        // complete V3 row identity; diagnostic nodes and heuristic fields never qualify.
        if (entry.callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY
            || entry.callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER)
        {
            return CallbackEnumRemovePolicyKind::kNotRemovable;
        }
        if (entry.callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT)
        {
            const std::uint32_t kRequiredTrustFlags =
                KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE |
                KSWORD_ARK_CALLBACK_TRUST_PROFILE_GATED |
                KSWORD_ARK_CALLBACK_TRUST_STORAGE_VALIDATED |
                KSWORD_ARK_CALLBACK_TRUST_STRUCTURE_SIGNATURE |
                KSWORD_ARK_CALLBACK_TRUST_OWNER_MODULE_RESOLVED;
            const bool kVerifiedObjectHandle =
                entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE
                && callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE)
                && callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE)
                && callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH)
                && callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION)
                && entry.registrationAddress != 0U
                && entry.rawStorageValue != 0U
                && entry.identityHash != 0U
                && entry.generation != 0U
                && (entry.trustFlags & kRequiredTrustFlags) == kRequiredTrustFlags
                && (entry.trustFlags & KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN) == 0U
                && (entry.removeBehavior &
                    (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
                     KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION)) ==
                    (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
                     KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION);
            if (kVerifiedObjectHandle)
            {
                return CallbackEnumRemovePolicyKind::kRemovableVerified;
            }

            const bool kHeuristicObjectCandidate =
                entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST
                && callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE)
                && callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS)
                && callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH)
                && callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION)
                && entry.registrationAddress != 0U
                && entry.rawStorageValue != 0U
                && entry.identityHash != 0U
                && entry.generation != 0U
                && callbackEnumTrustFlagsIndicateFallbackPattern(entry)
                && (entry.removeBehavior &
                    (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
                     KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION)) ==
                    (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
                     KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION);
            return kHeuristicObjectCandidate
                ? CallbackEnumRemovePolicyKind::kRemovableCandidate
                : CallbackEnumRemovePolicyKind::kNotRemovable;
        }

        const bool kRemovableCandidate =
            callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE);
        const bool kHasLegacyRemoveValue = callbackEnumRemoveRequestValue(entry) != 0U;
        const bool kVerifiedRemove =
            callbackEnumFieldIndicatesVerifiedRemove(entry)
            || callbackEnumRemoveBehaviorIndicatesPublicApi(entry);
        const bool kExperimentalRemove =
            callbackEnumFieldIndicatesExperimentalRemove(entry)
            || callbackEnumRemoveBehaviorIndicatesExperimentalUnlink(entry);
        if (kHasLegacyRemoveValue
            && (kVerifiedRemove || (kRemovableCandidate && callbackEnumIsPublicApiSource(entry.source))))
        {
            return CallbackEnumRemovePolicyKind::kRemovableVerified;
        }
        if (kRemovableCandidate && kHasLegacyRemoveValue)
        {
            return CallbackEnumRemovePolicyKind::kRemovableCandidate;
        }
        if ((kExperimentalRemove
            || callbackEnumIsFallbackPatternSource(entry.source)
            || callbackEnumTrustFlagsIndicateFallbackPattern(entry))
            && callbackEnumHasExperimentalStorageValue(entry))
        {
            return CallbackEnumRemovePolicyKind::kExperimentalOnly;
        }
        return CallbackEnumRemovePolicyKind::kNotRemovable;
    }

    QString callbackEnumRemovePolicyText(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: converts the derived policy to stable UX wording.
        // Return: display text containing the requested removable policy keywords.
        const CallbackEnumRemovePolicyKind kPolicy = callbackEnumRemovePolicyKind(entry);
        if (kPolicy == CallbackEnumRemovePolicyKind::kNotRemovable
            && entry.callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT)
        {
            return kernelText(
                "kernel.callback.enum.remove_policy.object_unverified",
                QStringLiteral("unsupported/unverified（句柄或行身份无法验证）"));
        }
        if (kPolicy == CallbackEnumRemovePolicyKind::kNotRemovable
            && (entry.callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY
                || entry.callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER))
        {
            return kernelText(
                "kernel.callback.enum.remove_policy.disabled",
                QStringLiteral("unsupported（移除入口已禁用）"));
        }

        switch (kPolicy)
        {
        case CallbackEnumRemovePolicyKind::kRemovableVerified:
            return kernelText("kernel.callback.enum.remove_policy.verified", QStringLiteral("removable verified（公开 API 可验证）"));
        case CallbackEnumRemovePolicyKind::kRemovableCandidate:
            return kernelText("kernel.callback.enum.remove_policy.candidate", QStringLiteral("removable candidate（旧协议候选）"));
        case CallbackEnumRemovePolicyKind::kExperimentalOnly:
            return kernelText("kernel.callback.enum.remove_policy.experimental", QStringLiteral("experimental only（仅预留 unlink）"));
        case CallbackEnumRemovePolicyKind::kNotRemovable:
        default:
            return kernelText("kernel.callback.enum.remove_policy.not_removable", QStringLiteral("not removable（不可移除）"));
        }
    }

    QString callbackEnumRemovePolicyGlyph(const KernelCallbackEnumEntry& entry)
    {
        switch (callbackEnumRemovePolicyKind(entry))
        {
        case CallbackEnumRemovePolicyKind::kRemovableVerified:
            return QStringLiteral("✓");
        case CallbackEnumRemovePolicyKind::kRemovableCandidate:
        case CallbackEnumRemovePolicyKind::kExperimentalOnly:
            return QStringLiteral("!");
        case CallbackEnumRemovePolicyKind::kNotRemovable:
        default:
            return QStringLiteral("×");
        }
    }

    void callbackEnumApplyRemovePolicyPresentation(
        QTableWidgetItem* item,
        const KernelCallbackEnumEntry& entry)
    {
        if (item == nullptr)
        {
            return;
        }

        item->setText(callbackEnumRemovePolicyGlyph(entry));
        item->setTextAlignment(Qt::AlignCenter);
        item->setToolTip(callbackEnumRemovePolicyText(entry));
    }

    bool callbackEnumIsVisibleSuccess(const KernelCallbackEnumEntry& entry)
    {
        return entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    }

    bool callbackEnumReadSourceIndex(
        const QTableWidgetItem* item,
        const std::size_t sourceCount,
        std::size_t& sourceIndexOut)
    {
        sourceIndexOut = 0U;
        if (item == nullptr)
        {
            return false;
        }

        bool conversionOk = false;
        const qulonglong kRawSourceIndex = item->data(Qt::UserRole).toULongLong(&conversionOk);
        if (!conversionOk)
        {
            return false;
        }

        sourceIndexOut = static_cast<std::size_t>(kRawSourceIndex);
        return sourceIndexOut < sourceCount;
    }

    bool callbackEnumCanUseLegacySafeRemove(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: allows only verified/candidate policies to call old removeExternalCallback.
        // Return: true when the context menu may invoke ArkDriverClient::removeExternalCallback.
        const CallbackEnumRemovePolicyKind kPolicy = callbackEnumRemovePolicyKind(entry);
        return kPolicy == CallbackEnumRemovePolicyKind::kRemovableVerified
            || kPolicy == CallbackEnumRemovePolicyKind::kRemovableCandidate;
    }

    bool callbackEnumRequiresSecondConfirmation(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: requires confirmation for every row that can change kernel callback
        //             state, and especially for fallback/pattern or unlink-only rows.
        // Return: true when the detail pane/menu should require a QMessageBox confirmation.
        return callbackEnumRemovePolicyKind(entry) != CallbackEnumRemovePolicyKind::kNotRemovable;
    }

    QString callbackEnumYesNoText(const bool value)
    {
        // Input: boolean UI state.
        // Processing: maps it to localized yes/no text.
        // Return localized yes/no text, using `是` for true and `否` for false as the fallback labels.
        return kernelText(
            value ? "kernel.callback.enum.boolean.yes" : "kernel.callback.enum.boolean.no",
            value ? QStringLiteral("是") : QStringLiteral("否"));
    }

    QString callbackEnumIdentityHashText(const std::uint64_t identityHash)
    {
        // Input: reserved identity hash from ArkDriverClient.
        // Processing: keeps the current v1 protocol compatible by showing an empty value for 0.
        // Return: hex hash text or an explicit empty placeholder.
        if (identityHash == 0U)
        {
            return kernelText("kernel.callback.enum.placeholder.empty", QStringLiteral("<空>"));
        }
        return callbackEnumFormatAddress(identityHash);
    }

    QString callbackEnumNtStatusText(const long ntstatus)
    {
        // Input: NTSTATUS value returned by the driver response.
        // Processing: formats the signed status as the conventional 8-digit hex value.
        // Return: uppercase NTSTATUS text suitable for labels and detail panes.
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(ntstatus)), 8, 16, QChar('0'))
            .toUpper();
    }

    QString callbackEnumRemoveMappingText(const std::uint32_t mappingFlags)
    {
        // Input: KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_* bits from the old remove response.
        // Processing: expands known bits while keeping unknown future bits visible.
        // Return: human-readable mapping flag summary.
        QStringList flagList;
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE) != 0U)
        {
            flagList.push_back(QStringLiteral("module"));
        }
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED) != 0U)
        {
            flagList.push_back(QStringLiteral("enumerated"));
        }
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API) != 0U)
        {
            flagList.push_back(QStringLiteral("public api"));
        }
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PDB_TRUSTED) != 0U)
        {
            flagList.push_back(QStringLiteral("pdb trusted"));
        }
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_EXPERIMENTAL) != 0U)
        {
            flagList.push_back(QStringLiteral("experimental"));
        }
        const std::uint32_t kKnownFlags =
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE |
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED |
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API |
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PDB_TRUSTED |
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_EXPERIMENTAL;
        const std::uint32_t kUnknownFlags = mappingFlags & ~kKnownFlags;
        if (kUnknownFlags != 0U)
        {
            flagList.push_back(QStringLiteral("unknown=0x%1")
                .arg(static_cast<qulonglong>(kUnknownFlags), 8, 16, QChar('0'))
                .toUpper());
        }
        return flagList.isEmpty()
            ? kernelText("kernel.callback.enum.placeholder.none", QStringLiteral("<无>"))
            : flagList.join(QStringLiteral(", "));
    }

    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST callbackEnumBuildLegacyRemoveRequest(const KernelCallbackEnumEntry& entry)
    {
        // Input: one selected callback enumeration row.
        // Processing: maps enum metadata to the existing v1 removeExternalCallback request.
        // Return: initialized request packet; callbackClass/address are zero when not compatible.
        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST requestPacket{};
        requestPacket.size = sizeof(requestPacket);
        requestPacket.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
        requestPacket.callbackClass = callbackEnumRemoveTypeForClass(entry.callbackClass);
        requestPacket.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_NONE;
        requestPacket.callbackAddress = callbackEnumRemoveRequestValue(entry);
        return requestPacket;
    }

    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST callbackEnumBuildExRemoveRequest(
        const KernelCallbackEnumEntry& entry,
        const std::uint32_t removeFlags,
        const std::uint32_t removeBehavior)
    {
        // Input: one selected callback enumeration row plus remove policy/flags.
        // Processing: copies row metadata into the EX request packet for R0 validation.
        // Return: initialized EX request packet.
        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST requestPacket{};
        requestPacket.size = sizeof(requestPacket);
        requestPacket.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
        requestPacket.callbackClass = callbackEnumRemoveTypeForClass(entry.callbackClass);
        requestPacket.flags = removeFlags;
        requestPacket.callbackAddress = callbackEnumRemoveRequestValue(entry);
        requestPacket.registrationAddress = entry.registrationAddress;
        requestPacket.rawStorageValue = entry.rawStorageValue;
        requestPacket.enumerationGeneration = entry.generation;
        requestPacket.identityHash = entry.identityHash;
        requestPacket.source = entry.source;
        requestPacket.operationMask = entry.operationMask;
        requestPacket.objectTypeMask = entry.objectTypeMask;
        requestPacket.trustFlags = entry.trustFlags;
        requestPacket.removeBehavior = removeBehavior;
        return requestPacket;
    }

    QString callbackEnumExRemoveDetailText(
        const KernelCallbackEnumEntry& entry,
        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST& requestPacket,
        const ksword::ark::CallbackRemoveExResult& removeResult)
    {
        // Input: selected row, EX request packet, and EX remove result.
        // Processing: renders the full semantic response.
        // Return: detail text for the callback enum detail pane.
        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE& responsePacket = removeResult.response;
        const QString kModulePath = QString::fromWCharArray(responsePacket.modulePath);
        const QString kServiceName = QString::fromWCharArray(responsePacket.serviceName);
        const QString kMessageText = QString::fromWCharArray(responsePacket.message);
        return kernelText("kernel.callback.enum.remove.ex.detail", QStringLiteral(
            "EX移除请求已执行。\n"
            "- 类型：%1\n"
            "- 来源：%2\n"
            "- 可信状态：%3\n"
            "- 移除策略：%4\n"
            "- 请求类：%5\n"
            "- 请求值：%6\n"
            "- RemoveBehavior：0x%7\n"
            "- TrustFlags：0x%8\n"
            "- Generation：%9\n"
            "- IdentityHash：%10\n"
            "- Win32：%11\n"
            "- 返回字节：%12\n"
            "- NTSTATUS：%13\n"
            "- Revalidation：%14\n"
            "- 映射标志：%15\n"
            "- 模块路径：%16\n"
            "- 模块基址：%17\n"
            "- 模块大小：0x%18\n"
            "- 服务名：%19\n"
            "- 消息：%20\n"
            "- ArkDriverClient：%21"))
            .arg(entry.classText)
            .arg(entry.sourceText)
            .arg(entry.sourceTrustText)
            .arg(entry.removePolicyText)
            .arg(static_cast<qulonglong>(requestPacket.callbackClass))
            .arg(callbackEnumFormatAddress(requestPacket.callbackAddress))
            .arg(QString::number(static_cast<qulonglong>(requestPacket.removeBehavior), 16).toUpper())
            .arg(QString::number(static_cast<qulonglong>(requestPacket.trustFlags), 16).toUpper())
            .arg(static_cast<qulonglong>(requestPacket.enumerationGeneration))
            .arg(callbackEnumIdentityHashText(requestPacket.identityHash))
            .arg(static_cast<qulonglong>(removeResult.io.win32Error))
            .arg(static_cast<qulonglong>(removeResult.io.bytesReturned))
            .arg(callbackEnumNtStatusText(responsePacket.ntstatus))
            .arg(callbackEnumNtStatusText(responsePacket.revalidationStatus))
            .arg(callbackEnumRemoveMappingText(responsePacket.mappingFlags))
            .arg(kModulePath.isEmpty() ? kernelText("kernel.callback.enum.placeholder.unresolved", QStringLiteral("<未解析>")) : kModulePath)
            .arg(callbackEnumFormatAddress(responsePacket.moduleBase))
            .arg(QString::number(static_cast<qulonglong>(responsePacket.moduleSize), 16).toUpper())
            .arg(kServiceName.isEmpty() ? kernelText("kernel.callback.enum.placeholder.unmatched", QStringLiteral("<未匹配>")) : kServiceName)
            .arg(kMessageText.isEmpty() ? kernelText("kernel.callback.enum.placeholder.none", QStringLiteral("<无>")) : kMessageText)
            .arg(callbackEnumIoMessageText(QString::fromStdString(removeResult.io.message)));
    }

    QString callbackEnumLegacyRemoveDetailText(
        const KernelCallbackEnumEntry& entry,
        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST& requestPacket,
        const ksword::ark::CallbackRemoveResult& removeResult)
    {
        // Input: selected row, request packet, and ArkDriverClient remove result.
        // Processing: renders both transport and R0 semantic fields without assuming success.
        // Return: full detail text for the callback enum detail pane.
        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE& responsePacket = removeResult.response;
        const QString kModulePath = QString::fromWCharArray(responsePacket.modulePath);
        const QString kServiceName = QString::fromWCharArray(responsePacket.serviceName);
        return kernelText("kernel.callback.enum.remove.legacy.detail", QStringLiteral(
            "安全移除请求已执行。\n"
            "- 类型：%1\n"
            "- 来源：%2\n"
            "- 可信状态：%3\n"
            "- 移除策略：%4\n"
            "- 请求类：%5\n"
            "- 请求值：%6\n"
            "- Win32：%7\n"
            "- 返回字节：%8\n"
            "- NTSTATUS：%9\n"
            "- 映射标志：%10\n"
            "- 模块路径：%11\n"
            "- 模块基址：%12\n"
            "- 模块大小：0x%13\n"
            "- 服务名：%14\n"
            "- 驱动消息：%15"))
            .arg(entry.classText)
            .arg(entry.sourceText)
            .arg(entry.sourceTrustText)
            .arg(entry.removePolicyText)
            .arg(static_cast<qulonglong>(requestPacket.callbackClass))
            .arg(callbackEnumFormatAddress(requestPacket.callbackAddress))
            .arg(static_cast<qulonglong>(removeResult.io.win32Error))
            .arg(static_cast<qulonglong>(removeResult.io.bytesReturned))
            .arg(callbackEnumNtStatusText(responsePacket.ntstatus))
            .arg(callbackEnumRemoveMappingText(responsePacket.mappingFlags))
            .arg(kModulePath.isEmpty() ? kernelText("kernel.callback.enum.placeholder.unresolved", QStringLiteral("<未解析>")) : kModulePath)
            .arg(callbackEnumFormatAddress(responsePacket.moduleBase))
            .arg(QString::number(static_cast<qulonglong>(responsePacket.moduleSize), 16).toUpper())
            .arg(kServiceName.isEmpty() ? kernelText("kernel.callback.enum.placeholder.unmatched", QStringLiteral("<未匹配>")) : kServiceName)
            .arg(callbackEnumIoMessageText(QString::fromStdString(removeResult.io.message)));
    }

    bool callbackEnumConfirmSafeRemove(QWidget* parentWidget, const KernelCallbackEnumEntry& entry)
    {
        // Input: parent widget and selected row.
        // Processing: shows a second confirmation before any EX public-API remove IOCTL is sent.
        // Return: true when the user explicitly confirms the safe public/API remove action.
        const QString kWarningText = kernelText("kernel.callback.enum.remove.safe.confirm", QStringLiteral(
            "即将执行安全移除。\n\n"
            "类别：%1\n"
            "名称：%2\n"
            "来源：%3\n"
            "可信状态：%4\n"
            "移除策略：%5\n"
            "请求值：%6\n"
            "可信：%7\n\n"
            "此操作会修改内核回调注册，可能影响系统稳定性。是否继续？"))
            .arg(entry.classText)
            .arg(callbackEnumSafeText(entry.nameText))
            .arg(entry.sourceText)
            .arg(entry.sourceTrustText)
            .arg(entry.removePolicyText)
            .arg(callbackEnumFormatAddress(callbackEnumRemoveRequestValue(entry)))
            .arg(callbackEnumYesNoText(callbackEnumIsTrustedSource(entry)));
        return QMessageBox::question(
            parentWidget,
            kernelText("kernel.callback.enum.remove.safe.title", QStringLiteral("安全移除")),
            kWarningText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) == QMessageBox::Yes;
    }

    bool callbackEnumExecuteSafeRemove(
        QWidget* parentWidget,
        QLabel* statusLabel,
        CodeEditorWidget* detailEditor,
        const KernelCallbackEnumEntry& entry)
    {
        // Input: UI sinks plus the selected callback row.
        // Processing: validates the EX packet, asks for confirmation, then calls ArkDriverClient.
        // Return: true only when R0 completed and confirmed the removal.
        if (!callbackEnumCanUseLegacySafeRemove(entry))
        {
            QMessageBox::information(
                parentWidget,
                kernelText("kernel.callback.enum.remove.safe.title", QStringLiteral("安全移除")),
                kernelText("kernel.callback.enum.remove.safe.unavailable", QStringLiteral("当前记录不支持安全移除。")));
            return false;
        }

        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST kRequestPacket =
            callbackEnumBuildExRemoveRequest(
                entry,
                KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_REQUIRE_REVALIDATION,
                KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
                KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION);
        if (kRequestPacket.callbackClass == 0U || kRequestPacket.callbackAddress == 0U)
        {
            QMessageBox::warning(
                parentWidget,
                kernelText("kernel.callback.enum.remove.safe.title", QStringLiteral("安全移除")),
                kernelText("kernel.callback.enum.remove.safe.missing_value", QStringLiteral("当前记录缺少可用的类型或地址/标识值。")));
            return false;
        }

        if (!callbackEnumConfirmSafeRemove(parentWidget, entry))
        {
            if (statusLabel != nullptr)
            {
                statusLabel->setText(kernelText("kernel.callback.enum.remove.safe.cancelled", QStringLiteral("状态：已取消安全移除")));
            }
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::CallbackRemoveExResult kRemoveResult =
            kDriverClient.removeExternalCallbackEx(kRequestPacket);
        if (detailEditor != nullptr)
        {
            detailEditor->setLocalizedText(callbackEnumExRemoveDetailText(entry, kRequestPacket, kRemoveResult));
        }

        if (!kRemoveResult.io.ok)
        {
            if (statusLabel != nullptr)
            {
                statusLabel->setText(
                    kernelText("kernel.callback.enum.remove.safe.io_failed", QStringLiteral("状态：安全移除失败，Win32=%1"))
                    .arg(static_cast<qulonglong>(kRemoveResult.io.win32Error)));
            }
            QMessageBox::warning(
                parentWidget,
                kernelText("kernel.callback.enum.remove.safe.title", QStringLiteral("安全移除")),
                kernelText("kernel.callback.enum.remove.safe.call_failed", QStringLiteral("回调移除失败，Win32=%1。"))
                    .arg(static_cast<qulonglong>(kRemoveResult.io.win32Error)));
            return false;
        }

        if (kRemoveResult.response.ntstatus >= 0)
        {
            if (statusLabel != nullptr)
            {
                statusLabel->setText(kernelText("kernel.callback.enum.remove.safe.completed", QStringLiteral("状态：安全移除完成")));
            }
            return true;
        }
        else
        {
            if (statusLabel != nullptr)
            {
                statusLabel->setText(
                    kernelText("kernel.callback.enum.remove.safe.driver_failed", QStringLiteral("状态：驱动返回失败，NTSTATUS=%1"))
                    .arg(callbackEnumNtStatusText(kRemoveResult.response.ntstatus)));
            }
            QMessageBox::warning(
                parentWidget,
                kernelText("kernel.callback.enum.remove.safe.title", QStringLiteral("安全移除")),
                kernelText("kernel.callback.enum.remove.safe.driver_failed_message", QStringLiteral("驱动返回失败，NTSTATUS=%1。"))
                    .arg(callbackEnumNtStatusText(kRemoveResult.response.ntstatus)));
        }
        return false;
    }

    void callbackEnumShowExperimentalUnlinkNotice(
        QWidget* parentWidget,
        QLabel* statusLabel,
        CodeEditorWidget* detailEditor,
        const KernelCallbackEnumEntry& entry)
    {
        // Input: UI sinks plus the selected callback row.
        // Processing: presents a strong confirmation and then sends the EX request
        //             with experimental-unlink flags. R0 currently rejects the path.
        // Return: no return value; result details are shown in UI.
        if (callbackEnumRemovePolicyKind(entry) == CallbackEnumRemovePolicyKind::kNotRemovable
            || callbackEnumRemoveRequestValue(entry) == 0U)
        {
            if (statusLabel != nullptr)
            {
                statusLabel->setText(kernelText("kernel.callback.enum.remove.experimental.not_target", QStringLiteral("状态：当前条目无法移除")));
            }
            QMessageBox::information(
                parentWidget,
                kernelText("kernel.callback.enum.remove.experimental.title", QStringLiteral("强制移除（实验性）")),
                kernelText("kernel.callback.enum.remove.experimental.no_value", QStringLiteral("当前条目没有可用的回调地址或标识值，无法执行移除。")));
            return;
        }

        const QString kConfirmText = kernelText("kernel.callback.enum.remove.experimental.confirm", QStringLiteral(
            "强制移除可能破坏内核数据，导致系统不稳定、蓝屏或安全产品状态异常。\n\n"
            "类别：%1\n"
            "名称：%2\n"
            "来源：%3\n"
            "可信状态：%4\n"
            "移除策略：%5\n"
            "存储值：%6\n\n"
            "仅在已确认目标异常并接受上述风险时继续。"))
            .arg(entry.classText)
            .arg(callbackEnumSafeText(entry.nameText))
            .arg(entry.sourceText)
            .arg(entry.sourceTrustText)
            .arg(entry.removePolicyText)
            .arg(callbackEnumFormatAddress(entry.rawStorageValue));
        const QMessageBox::StandardButton kReply = QMessageBox::warning(
            parentWidget,
            kernelText("kernel.callback.enum.remove.experimental.title", QStringLiteral("强制移除（实验性）")),
            kConfirmText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kReply != QMessageBox::Yes)
        {
            if (statusLabel != nullptr)
            {
                statusLabel->setText(kernelText("kernel.callback.enum.remove.experimental.cancelled", QStringLiteral("状态：已取消强制移除")));
            }
            return;
        }

        const ksword::ark::DriverClient kDriverClient;
        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST kRequestPacket =
            callbackEnumBuildExRemoveRequest(
                entry,
                KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_EXPERIMENTAL_UNLINK |
                KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_REQUIRE_REVALIDATION,
                KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK |
                KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION |
                KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_FORCE_AFTER_PUBLIC_FAILURE);
        const ksword::ark::CallbackRemoveExResult kRemoveResult =
            kDriverClient.removeExternalCallbackEx(kRequestPacket);
        if (detailEditor != nullptr)
        {
            detailEditor->setLocalizedText(callbackEnumExRemoveDetailText(entry, kRequestPacket, kRemoveResult));
        }
        if (statusLabel != nullptr)
        {
            statusLabel->setText(kRemoveResult.io.ok && kRemoveResult.response.ntstatus == callbackEnumStatusNotSupported()
                ? kernelText("kernel.callback.enum.remove.experimental.rejected", QStringLiteral("状态：强制移除被驱动拒绝"))
                : kernelText("kernel.callback.enum.remove.experimental.completed", QStringLiteral("状态：强制移除请求已完成")));
        }
        QMessageBox::information(
            parentWidget,
            kernelText("kernel.callback.enum.remove.experimental.title", QStringLiteral("强制移除（实验性）")),
            kRemoveResult.io.ok
                ? kernelText("kernel.callback.enum.remove.experimental.processed", QStringLiteral("强制移除请求已处理，请查看详情中的状态码。"))
                : kernelText("kernel.callback.enum.remove.experimental.io_failed", QStringLiteral("强制移除请求失败，Win32=%1。"))
                    .arg(static_cast<qulonglong>(kRemoveResult.io.win32Error)));
    }

    QString callbackEnumPrimaryAddressText(const KernelCallbackEnumEntry& entry)
    {
        // Purpose: Select the table's primary address based on fieldFlags to avoid displaying localization/diagnostic rows as 0 addresses.
        // Returns: the actual callback address, global/node address, diagnostic address, or the placeholder text "No callback address".
        if ((entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS) != 0U
            && entry.callbackAddress != 0U)
        {
            return callbackEnumFormatAddress(entry.callbackAddress);
        }
        if ((entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER) != 0U
            && entry.callbackAddress != 0U)
        {
            return kernelText("kernel.callback.enum.address.identifier", QStringLiteral("标识 %1"))
                .arg(callbackEnumFormatAddress(entry.callbackAddress));
        }
        if ((entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE) != 0U
            && entry.callbackAddress != 0U)
        {
            return kernelText("kernel.callback.enum.address.handle", QStringLiteral("句柄 %1"))
                .arg(callbackEnumFormatAddress(entry.callbackAddress));
        }
        if ((entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS) != 0U
            && entry.registrationAddress != 0U)
        {
            const bool kLocateRow = entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN;
            return kernelText("kernel.callback.enum.address.registration", QStringLiteral("%1 %2"))
                .arg(kLocateRow
                    ? kernelText("kernel.callback.enum.address.global", QStringLiteral("全局"))
                    : kernelText("kernel.callback.enum.address.node", QStringLiteral("节点")))
                .arg(callbackEnumFormatAddress(entry.registrationAddress));
        }
        if ((entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS) != 0U
            && entry.contextAddress != 0U)
        {
            return kernelText("kernel.callback.enum.address.diagnostic", QStringLiteral("诊断 %1"))
                .arg(callbackEnumFormatAddress(entry.contextAddress));
        }
        return kernelText("kernel.callback.enum.address.none", QStringLiteral("<无回调地址>"));
    }

    QString callbackEnumNtStatusText(const std::uint64_t value)
    {
        return QString::number(
            static_cast<quint32>(value),
            16).rightJustified(8, QLatin1Char('0')).toUpper();
    }

    QString callbackEnumLegacyFsPairStateText(const std::uint64_t pairEvidence)
    {
        return (pairEvidence & (1ULL << 32)) != 0ULL
            ? kernelText(
                "kernel.callback.enum.legacy_fs.pair.paired",
                QStringLiteral("pre/post 成对"))
            : kernelText(
                "kernel.callback.enum.legacy_fs.pair.single",
                QStringLiteral("单边回调"));
    }

    QString callbackEnumLocalizedDetailText(
        const ksword::ark::CallbackEnumEntry& source,
        const KernelCallbackEnumEntry& entry)
    {
        if (source.callbackClass != KSWORD_ARK_CALLBACK_ENUM_CLASS_LEGACY_FS_FILTER ||
            (source.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_DETAIL_ARGS) == 0U ||
            source.detailCode == KSWORD_ARK_CALLBACK_ENUM_DETAIL_NONE)
        {
            return entry.detailText;
        }

        switch (source.detailCode)
        {
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_PUBLIC_EMPTY:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.public_empty",
                QStringLiteral("公开 API 未返回旧式文件系统过滤驱动；NTSTATUS=0x%1。"))
                .arg(callbackEnumNtStatusText(source.detailArgs[0]));
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_COUNT_LIMIT:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.count_limit",
                QStringLiteral("公开 API 报告 %1 个过滤驱动，超过 %2 行安全上限；本轮失败关闭。"))
                .arg(source.detailArgs[0])
                .arg(source.detailArgs[1]);
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_CLASS_INIT_NOT_FOUND:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.class_init_not_found",
                QStringLiteral("%1：公开枚举确认旧式 FS filter，但在 DriverExtension+0x%2..0x%3 未找到结构签名唯一的 ClassInitData（NTSTATUS=0x%4）。"))
                .arg(entry.nameText)
                .arg(QString::number(source.detailArgs[1], 16).toUpper())
                .arg(QString::number(source.detailArgs[2], 16).toUpper())
                .arg(callbackEnumNtStatusText(source.detailArgs[3]));
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_CLASS_INIT_AMBIGUOUS:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.class_init_ambiguous",
                QStringLiteral("%1：DriverExtension+0x%2..0x%3 出现多个结构签名候选；为避免误判，本轮失败关闭（NTSTATUS=0x%4）。"))
                .arg(entry.nameText)
                .arg(QString::number(source.detailArgs[1], 16).toUpper())
                .arg(QString::number(source.detailArgs[2], 16).toUpper())
                .arg(callbackEnumNtStatusText(source.detailArgs[3]));
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_CLASS_INIT_VALIDATED:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.class_init_validated",
                QStringLiteral("ClassInitData=%1；DriverExtension+0x%2；Size=%3；登记 %4 个 pre/post 回调；结构/版本证据已独立验证，各槽 owner 将逐项判定。"))
                .arg(callbackEnumFormatAddress(source.detailArgs[0]))
                .arg(QString::number(source.detailArgs[1], 16).toUpper())
                .arg(source.detailArgs[2])
                .arg(source.detailArgs[3]);
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_OWNER_MATCH:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.owner_match",
                QStringLiteral("ClassInitData=%1；DriverExtension+0x%2；%3；pair=%4；回调 owner 与登记驱动匹配（base=%5）。"))
                .arg(callbackEnumFormatAddress(source.detailArgs[0]))
                .arg(QString::number(source.detailArgs[1], 16).toUpper())
                .arg(callbackEnumLegacyFsPairStateText(source.detailArgs[2]))
                .arg(source.detailArgs[2] & 0xFFFFFFFFULL)
                .arg(callbackEnumFormatAddress(source.detailArgs[3]));
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_OWNER_MISMATCH:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.owner_mismatch",
                QStringLiteral("ClassInitData=%1；DriverExtension+0x%2；%3；pair=%4；回调模块 base=%5，与登记驱动 base=%6 不匹配，标记为可疑。"))
                .arg(callbackEnumFormatAddress(source.detailArgs[0]))
                .arg(QString::number(source.detailArgs[1], 16).toUpper())
                .arg(callbackEnumLegacyFsPairStateText(source.detailArgs[2]))
                .arg(source.detailArgs[2] & 0xFFFFFFFFULL)
                .arg(callbackEnumFormatAddress(entry.moduleBase))
                .arg(callbackEnumFormatAddress(source.detailArgs[3]));
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_OWNER_UNRESOLVED:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.owner_unresolved",
                QStringLiteral("ClassInitData=%1；DriverExtension+0x%2；%3；pair=%4；无法解析回调 owner（NTSTATUS=0x%5），状态保持未知。"))
                .arg(callbackEnumFormatAddress(source.detailArgs[0]))
                .arg(QString::number(source.detailArgs[1], 16).toUpper())
                .arg(callbackEnumLegacyFsPairStateText(source.detailArgs[2]))
                .arg(source.detailArgs[2] & 0xFFFFFFFFULL)
                .arg(callbackEnumNtStatusText(
                    static_cast<std::uint64_t>(
                        static_cast<std::uint32_t>(entry.lastStatus))));
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_PUBLIC_ENUM_FAILED:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.public_enum_failed",
                QStringLiteral("公开 API 枚举失败；NTSTATUS=0x%1，返回数量=%2，分配容量=%3；未解释可能不完整的 DriverObject 数组。"))
                .arg(callbackEnumNtStatusText(source.detailArgs[0]))
                .arg(source.detailArgs[1])
                .arg(source.detailArgs[2]);
        default:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.unknown_code",
                QStringLiteral("Legacy FS 诊断代码未知：%1。"))
                .arg(source.detailCode);
        }
    }

    QString callbackEnumRowStatusText(const std::uint32_t status, const long lastStatus)
    {
        switch (status)
        {
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_UNKNOWN:
            return kernelText("kernel.callback.enum.status.unknown", QStringLiteral("未知"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_OK:
            return kernelText("kernel.callback.enum.status.ok", QStringLiteral("可见/成功"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED:
            return kernelText("kernel.callback.enum.status.not_registered", QStringLiteral("未注册"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED:
            return kernelText("kernel.callback.enum.status.unsupported", QStringLiteral("当前不支持"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED:
            return kernelText("kernel.callback.enum.status.query_failed", QStringLiteral("查询失败(0x%1)"))
                .arg(QString::number(static_cast<quint32>(lastStatus), 16).rightJustified(8, QLatin1Char('0')).toUpper());
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_BUFFER_TRUNCATED:
            return kernelText("kernel.callback.enum.status.buffer_truncated", QStringLiteral("缓冲截断"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_SUSPICIOUS:
            return kernelText("kernel.callback.enum.status.suspicious", QStringLiteral("可疑"));
        default:
            return kernelText("kernel.callback.enum.placeholder.unknown_with_value", QStringLiteral("未知(%1)"))
                .arg(status);
        }
    }

    KernelCallbackEnumEntry callbackEnumConvertEntry(const ksword::ark::CallbackEnumEntry& source)
    {
        KernelCallbackEnumEntry row;
        row.callbackClass = source.callbackClass;
        row.source = source.source;
        row.status = source.status;
        row.fieldFlags = source.fieldFlags;
        row.trustFlags = source.trustFlags;
        row.removeBehavior = source.removeBehavior;
        row.removeFlags = source.removeBehavior;
        row.operationMask = source.operationMask;
        row.objectTypeMask = source.objectTypeMask;
        row.registrationType = source.registrationType;
        row.generation = source.generation;
        row.lastStatus = source.lastStatus;
        row.callbackAddress = source.callbackAddress;
        row.contextAddress = source.contextAddress;
        row.registrationAddress = source.registrationAddress;
        row.identityHash = source.identityHash;
        row.rawStorageValue = source.rawStorageValue;
        row.moduleBase = source.moduleBase;
        row.moduleSize = source.moduleSize;
        row.classText = callbackEnumClassText(source.callbackClass);
        row.registrationTypeText = callbackEnumRegistrationTypeText(source.registrationType);
        row.sourceText = callbackEnumSourceText(source.source);
        row.sourceTrustText = callbackEnumSourceTrustText(row);
        row.removePolicyText = callbackEnumRemovePolicyText(row);
        row.statusText = callbackEnumRowStatusText(source.status, source.lastStatus);
        row.nameText = QString::fromStdWString(source.name);
        row.altitudeText = QString::fromStdWString(source.altitude);
        row.modulePathText = QString::fromStdWString(source.modulePath);
        row.detailText = QString::fromStdWString(source.detail);
        row.detailText = callbackEnumLocalizedDetailText(source, row);
        row.requiresSecondConfirmation = callbackEnumRequiresSecondConfirmation(row);
        row.fallbackPatternOnly = callbackEnumIsFallbackPatternSource(row.source);
        return row;
    }

    enum class CallbackEnumColumn : int
    {
        kClass = 0,
        kRegistrationType,
        kSource,
        kTrust,
        kStatus,
        kRemovePolicy,
        kName,
        kCallbackAddress,
        kModule,
        kCompany,
        kFileVersion,
        kFileDescription,
        kAltitude,
        kCount
    };

    QString callbackEnumColumnHeaderText(const CallbackEnumColumn column)
    {
        // Purpose: Map the callback enumeration table column to right-click menu and clipboard header text.
        // Returns: Chinese header for the column; returns "Unknown Column" for unknown columns.
        switch (column)
        {
        case CallbackEnumColumn::kClass:
            return kernelText("kernel.callback.enum.header.class", QStringLiteral("类别"));
        case CallbackEnumColumn::kRegistrationType:
            return kernelText("kernel.callback.enum.header.registration_type", QStringLiteral("注册类型"));
        case CallbackEnumColumn::kSource:
            return kernelText("kernel.callback.enum.header.source", QStringLiteral("来源"));
        case CallbackEnumColumn::kTrust:
            return kernelText("kernel.callback.enum.header.trust", QStringLiteral("可信状态"));
        case CallbackEnumColumn::kStatus:
            return kernelText("kernel.callback.enum.header.status", QStringLiteral("状态"));
        case CallbackEnumColumn::kRemovePolicy:
            return kernelText("kernel.callback.enum.header.remove_policy", QStringLiteral("可移除"));
        case CallbackEnumColumn::kName:
            return kernelText("kernel.callback.enum.header.name", QStringLiteral("名称"));
        case CallbackEnumColumn::kCallbackAddress:
            return kernelText("kernel.callback.enum.header.callback_address", QStringLiteral("回调/对象地址"));
        case CallbackEnumColumn::kModule:
            return kernelText("kernel.callback.enum.header.module", QStringLiteral("模块"));
        case CallbackEnumColumn::kCompany:
            return kernelText("kernel.callback.enum.header.company", QStringLiteral("公司"));
        case CallbackEnumColumn::kFileVersion:
            return kernelText("kernel.callback.enum.header.file_version", QStringLiteral("文件版本"));
        case CallbackEnumColumn::kFileDescription:
            return kernelText("kernel.callback.enum.header.file_description", QStringLiteral("文件描述"));
        case CallbackEnumColumn::kAltitude:
            return QStringLiteral("Altitude");
        default:
            return kernelText("kernel.callback.enum.header.unknown", QStringLiteral("未知列"));
        }
    }

    int callbackEnumVisibleColumnCount(QTableWidget* table)
    {
        // Purpose: Count visible columns to prevent the header menu from hiding the last column.
        // Returns: The number of currently visible columns.
        if (table == nullptr)
        {
            return 0;
        }

        int visibleCount = 0;
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            if (!table->isColumnHidden(columnIndex))
            {
                ++visibleCount;
            }
        }
        return visibleCount;
    }

    void callbackEnumInstallHeaderColumnMenu(QTableWidget* table)
    {
        // Purpose: Install a right-click column visibility menu for the header; all columns are shown by default, and users can hide them as needed.
        // Returns: Nothing.
        if (table == nullptr || table->horizontalHeader() == nullptr)
        {
            return;
        }

        QHeaderView* headerView = table->horizontalHeader();
        headerView->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            headerView,
            &QHeaderView::customContextMenuRequested,
            table,
            [table, headerView](const QPoint& localPosition)
            {
                QMenu menu(table);
                menu.setStyleSheet(ksword_theme::contextMenuStyle());
                for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
                {
                    const QTableWidgetItem* headerItem =
                        table->horizontalHeaderItem(columnIndex);
                    QAction* columnAction = menu.addAction(
                        headerItem != nullptr
                            ? headerItem->text()
                            : QStringLiteral("Column %1").arg(columnIndex));
                    columnAction->setCheckable(true);
                    columnAction->setChecked(!table->isColumnHidden(columnIndex));
                    columnAction->setData(columnIndex);
                }

                QAction* selectedAction =
                    menu.exec(headerView->viewport()->mapToGlobal(localPosition));
                if (selectedAction == nullptr)
                {
                    return;
                }

                const int kColumnIndex = selectedAction->data().toInt();
                const bool kShouldShow = selectedAction->isChecked();
                if (!kShouldShow && callbackEnumVisibleColumnCount(table) <= 1)
                {
                    table->setColumnHidden(kColumnIndex, false);
                    return;
                }

                table->setColumnHidden(kColumnIndex, !kShouldShow);
            });
    }

    QString callbackEnumEntryColumnText(
        const KernelCallbackEnumEntry& entry,
        const CallbackEnumColumn column)
    {
        // Purpose: Extract text for a specified table column from the cache line, ensuring the copy menu does not depend on the current cell object.
        // Returns: single-column text ready to be written to the clipboard.
        switch (column)
        {
        case CallbackEnumColumn::kClass:
            return entry.classText;
        case CallbackEnumColumn::kRegistrationType:
            return entry.registrationTypeText;
        case CallbackEnumColumn::kSource:
            return entry.sourceText;
        case CallbackEnumColumn::kTrust:
            return entry.sourceTrustText;
        case CallbackEnumColumn::kStatus:
            return entry.statusText;
        case CallbackEnumColumn::kRemovePolicy:
            return entry.removePolicyText;
        case CallbackEnumColumn::kName:
            return callbackEnumSafeText(entry.nameText);
        case CallbackEnumColumn::kCallbackAddress:
            return callbackEnumPrimaryAddressText(entry);
        case CallbackEnumColumn::kModule:
            return entry.modulePathText.isEmpty()
                ? kernelText("kernel.callback.enum.placeholder.unresolved", QStringLiteral("<未解析>"))
                : entry.modulePathText;
        case CallbackEnumColumn::kCompany:
            return callbackEnumSafeText(entry.companyText);
        case CallbackEnumColumn::kFileVersion:
            return callbackEnumSafeText(entry.fileVersionText);
        case CallbackEnumColumn::kFileDescription:
            return callbackEnumSafeText(entry.fileDescriptionText);
        case CallbackEnumColumn::kAltitude:
            return callbackEnumSafeText(entry.altitudeText);
        default:
            return QString();
        }
    }

    QString callbackEnumEntryAsTsv(const KernelCallbackEnumEntry& entry)
    {
        // Purpose: Serialize a single callback traversal record into TSV format according to table column order.
        // Returns: single-line TSV without newlines.
        QStringList fieldList;
        fieldList.reserve(static_cast<int>(CallbackEnumColumn::kCount));
        for (int columnIndex = 0; columnIndex < static_cast<int>(CallbackEnumColumn::kCount); ++columnIndex)
        {
            fieldList.push_back(callbackEnumEntryColumnText(
                entry,
                static_cast<CallbackEnumColumn>(columnIndex)));
        }
        return fieldList.join('\t');
    }

    QString callbackEnumHeaderAsTsv()
    {
        // Purpose: Generate a TSV header for the callback enumeration table, to be used with 'copy header + selected rows'.
        // Return: Single-line TSV for the header row.
        QStringList headerList;
        headerList.reserve(static_cast<int>(CallbackEnumColumn::kCount));
        for (int columnIndex = 0; columnIndex < static_cast<int>(CallbackEnumColumn::kCount); ++columnIndex)
        {
            headerList.push_back(callbackEnumColumnHeaderText(static_cast<CallbackEnumColumn>(columnIndex)));
        }
        return headerList.join('\t');
    }

    std::vector<int> callbackEnumSelectedVisualRows(
        const QTableWidget* tableWidget,
        const int fallbackRow)
    {
        // Purpose: Collect all selected rows in the current visible table, sort by visible row index, and deduplicate.
        // Returns: an array of visible row indices; falls back to fallbackRow if no explicit selection exists.
        std::vector<int> selectedRows;
        if (tableWidget == nullptr)
        {
            return selectedRows;
        }

        const QList<QTableWidgetItem*> kSelectedItems = tableWidget->selectedItems();
        selectedRows.reserve(static_cast<std::size_t>(kSelectedItems.size()));
        for (QTableWidgetItem* item : kSelectedItems)
        {
            if (item != nullptr)
            {
                selectedRows.push_back(item->row());
            }
        }

        if (selectedRows.empty() && fallbackRow >= 0)
        {
            selectedRows.push_back(fallbackRow);
        }

        std::sort(selectedRows.begin(), selectedRows.end());
        selectedRows.erase(std::unique(selectedRows.begin(), selectedRows.end()), selectedRows.end());
        return selectedRows;
    }

    std::vector<std::size_t> callbackEnumSelectedSourceIndices(
        const QTableWidget* tableWidget,
        const std::vector<KernelCallbackEnumEntry>& sourceRows,
        const int fallbackRow)
    {
        // Purpose: Convert the visually selected rows in the table to source indices for `m_callbackEnumRows`.
        // Returns: Array of valid source indices, ordered to match the current sorted/filtered visible order.
        std::vector<std::size_t> sourceIndices;
        if (tableWidget == nullptr)
        {
            return sourceIndices;
        }

        const std::vector<int> kSelectedRows = callbackEnumSelectedVisualRows(tableWidget, fallbackRow);
        sourceIndices.reserve(kSelectedRows.size());
        for (const int kVisualRow : kSelectedRows)
        {
            const QTableWidgetItem* classItem = tableWidget->item(
                kVisualRow,
                static_cast<int>(CallbackEnumColumn::kClass));
            if (classItem == nullptr)
            {
                continue;
            }

            std::size_t sourceIndex = 0U;
            if (callbackEnumReadSourceIndex(classItem, sourceRows.size(), sourceIndex))
            {
                sourceIndices.push_back(sourceIndex);
            }
        }
        return sourceIndices;
    }

    void callbackEnumCopyTextToClipboard(const QString& contentText)
    {
        // Purpose: Uniformly write to the system clipboard; silently skip if QApplication is not ready.
        // Returns: Nothing.
        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard != nullptr)
        {
            clipboard->setText(contentText);
        }
    }
}

void KernelDock::initializeCallbackEnumTab()
{
    if (callbackEnumPage_ == nullptr || callbackEnumLayout_ != nullptr)
    {
        return;
    }

    callbackEnumLayout_ = new QVBoxLayout(callbackEnumPage_);
    callbackEnumLayout_->setContentsMargins(4, 4, 4, 4);
    callbackEnumLayout_->setSpacing(6);

    callbackEnumToolLayout_ = new QHBoxLayout();
    callbackEnumToolLayout_->setContentsMargins(0, 0, 0, 0);
    callbackEnumToolLayout_->setSpacing(6);

    refreshCallbackEnumButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), callbackEnumPage_);
    refreshCallbackEnumButton_->setToolTip(kernelText("kernel.callback.enum.toolbar.refresh.tooltip", QStringLiteral("刷新回调遍历结果")));
    refreshCallbackEnumButton_->setStyleSheet(callbackEnumButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(refreshCallbackEnumButton_);

    callbackEnumFilterEdit_ = new QLineEdit(callbackEnumPage_);
    callbackEnumFilterEdit_->setPlaceholderText(kernelText("kernel.callback.enum.toolbar.filter.placeholder", QStringLiteral("按类别/注册类型/来源/名称/地址/模块/公司/版本/描述筛选")));
    callbackEnumFilterEdit_->setToolTip(kernelText("kernel.callback.enum.toolbar.filter.tooltip", QStringLiteral("输入关键字后实时过滤回调遍历结果")));
    callbackEnumFilterEdit_->setClearButtonEnabled(true);
    callbackEnumFilterEdit_->setStyleSheet(callbackEnumInputStyle());

    callbackEnumStatusLabel_ = new QLabel(kernelText("kernel.callback.enum.status.waiting", QStringLiteral("状态：等待刷新")), callbackEnumPage_);
    callbackEnumStatusLabel_->setStyleSheet(callbackEnumStatusLabelStyle(ksword_theme::textSecondaryHex()));

    callbackEnumToolLayout_->addWidget(refreshCallbackEnumButton_, 0);
    callbackEnumToolLayout_->addWidget(callbackEnumFilterEdit_, 1);
    callbackEnumToolLayout_->addWidget(callbackEnumStatusLabel_, 0);
    callbackEnumLayout_->addLayout(callbackEnumToolLayout_);

    QSplitter* splitter = new QSplitter(Qt::Vertical, callbackEnumPage_);
    callbackEnumLayout_->addWidget(splitter, 1);

    QTabWidget* callbackViewTabs = new QTabWidget(splitter);
    callbackEnumTable_ = new ks::ui::VisibleTableWidget(callbackViewTabs);
    callbackEnumTable_->setColumnCount(static_cast<int>(CallbackEnumColumn::kCount));
    callbackEnumTable_->setHorizontalHeaderLabels(QStringList{
        callbackEnumColumnHeaderText(CallbackEnumColumn::kClass),
        callbackEnumColumnHeaderText(CallbackEnumColumn::kRegistrationType),
        callbackEnumColumnHeaderText(CallbackEnumColumn::kSource),
        callbackEnumColumnHeaderText(CallbackEnumColumn::kTrust),
        callbackEnumColumnHeaderText(CallbackEnumColumn::kStatus),
        callbackEnumColumnHeaderText(CallbackEnumColumn::kRemovePolicy),
        callbackEnumColumnHeaderText(CallbackEnumColumn::kName),
        callbackEnumColumnHeaderText(CallbackEnumColumn::kCallbackAddress),
        callbackEnumColumnHeaderText(CallbackEnumColumn::kModule),
        callbackEnumColumnHeaderText(CallbackEnumColumn::kCompany),
        callbackEnumColumnHeaderText(CallbackEnumColumn::kFileVersion),
        callbackEnumColumnHeaderText(CallbackEnumColumn::kFileDescription),
        callbackEnumColumnHeaderText(CallbackEnumColumn::kAltitude)
        });
    callbackEnumTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    callbackEnumTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    callbackEnumTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    callbackEnumTable_->setAlternatingRowColors(true);
    callbackEnumTable_->setStyleSheet(callbackEnumSelectionStyle());
    callbackEnumTable_->setCornerButtonEnabled(false);
    callbackEnumTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    callbackEnumTable_->verticalHeader()->setVisible(false);
    callbackEnumTable_->horizontalHeader()->setStyleSheet(callbackEnumHeaderStyle());
    callbackEnumTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    callbackEnumTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(CallbackEnumColumn::kName), QHeaderView::Stretch);
    callbackEnumTable_->setColumnWidth(static_cast<int>(CallbackEnumColumn::kTrust), 170);
    const int kRemovePolicyColumn = static_cast<int>(CallbackEnumColumn::kRemovePolicy);
    callbackEnumTable_->horizontalHeader()->setSectionResizeMode(kRemovePolicyColumn, QHeaderView::Fixed);
    const QFontMetrics kRemovePolicyHeaderMetrics(callbackEnumTable_->horizontalHeader()->font());
    callbackEnumTable_->setColumnWidth(
        kRemovePolicyColumn,
        kRemovePolicyHeaderMetrics.horizontalAdvance(callbackEnumColumnHeaderText(CallbackEnumColumn::kRemovePolicy)) + 12);
    callbackEnumTable_->setColumnWidth(static_cast<int>(CallbackEnumColumn::kCallbackAddress), 180);
    callbackEnumTable_->setColumnWidth(static_cast<int>(CallbackEnumColumn::kModule), 220);
    callbackEnumTable_->setColumnWidth(static_cast<int>(CallbackEnumColumn::kFileDescription), 220);
    callbackEnumTable_->setColumnHidden(static_cast<int>(CallbackEnumColumn::kClass), true);
    callbackEnumTable_->setColumnHidden(static_cast<int>(CallbackEnumColumn::kTrust), true);
    callbackEnumTable_->setColumnHidden(static_cast<int>(CallbackEnumColumn::kStatus), true);
    callbackEnumTable_->setSortingEnabled(false);
    callbackEnumInstallHeaderColumnMenu(callbackEnumTable_);
    callbackViewTabs->addTab(
        callbackEnumTable_,
        kernelText("kernel.callback.enum.view.list", QStringLiteral("回调列表")));

    minifilterCallbackTree_ = new QTreeWidget(callbackViewTabs);
    minifilterCallbackTree_->setColumnCount(10);
    minifilterCallbackTree_->setHeaderLabels(QStringList{
        kernelText("kernel.callback.enum.minifilter.header.filter_operation", QStringLiteral("Filter / 操作")),
        kernelText("kernel.callback.enum.minifilter.header.stage", QStringLiteral("类型")),
        kernelText("kernel.callback.enum.minifilter.header.callback", QStringLiteral("Pre/Post 回调")),
        kernelText("kernel.callback.enum.minifilter.header.driver", QStringLiteral("驱动")),
        kernelText("kernel.callback.enum.minifilter.header.path", QStringLiteral("驱动路径")),
        kernelText("kernel.callback.enum.minifilter.header.company", QStringLiteral("公司")),
        kernelText("kernel.callback.enum.minifilter.header.file_version", QStringLiteral("文件版本")),
        kernelText("kernel.callback.enum.minifilter.header.description", QStringLiteral("描述")),
        QStringLiteral("Altitude"),
        kernelText("kernel.callback.enum.minifilter.header.source", QStringLiteral("来源/可信状态"))
        });
    minifilterCallbackTree_->setSelectionMode(QAbstractItemView::SingleSelection);
    minifilterCallbackTree_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    minifilterCallbackTree_->setAlternatingRowColors(true);
    minifilterCallbackTree_->setUniformRowHeights(true);
    minifilterCallbackTree_->setStyleSheet(callbackEnumSelectionStyle());
    minifilterCallbackTree_->header()->setStyleSheet(callbackEnumHeaderStyle());
    minifilterCallbackTree_->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    minifilterCallbackTree_->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    minifilterCallbackTree_->setColumnWidth(2, 180);
    minifilterCallbackTree_->setColumnWidth(4, 280);
    minifilterCallbackTree_->setToolTip(kernelText(
        "kernel.callback.enum.minifilter.tooltip",
        QStringLiteral("按 Filter 展开真实 IRP_MJ_* Pre/Post 回调；双击回调可查看驱动文件详情")));
    callbackViewTabs->addTab(
        minifilterCallbackTree_,
        kernelText("kernel.callback.enum.view.minifilter_tree", QStringLiteral("Minifilter 回调树")));

    callbackEnumDetailEditor_ = new CodeEditorWidget(splitter);
    callbackEnumDetailEditor_->setReadOnly(true);
    callbackEnumDetailEditor_->setText(kernelText("kernel.callback.enum.detail.initial", QStringLiteral("请选择一条回调记录查看详情。")));

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    // Callback traversal is controlled by the same global four-category detail layout as the CID table. QTabWidget is a direct child panel of
    // the splitter; after registration, it is rearranged by the unified host between collapsed, right-side, inline, and standalone windows.
    ks::ui::DetailLayoutHost* const kCallbackDetailLayoutHost =
        ks::ui::DetailLayoutRegistry::registerHost(
            callbackEnumTable_,
            callbackEnumDetailEditor_,
            callbackEnumPage_);

    initializeCallbackRemovePanel();

    connect(refreshCallbackEnumButton_, &QPushButton::clicked, this, [this]() {
        refreshCallbackEnumAsync();
    });
    connect(callbackEnumFilterEdit_, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildCallbackEnumTable(filterText.trimmed());
    });
    connect(callbackViewTabs, &QTabWidget::currentChanged, this,
        [this, callbackViewTabs, kCallbackDetailLayoutHost](const int tabIndex) {
            if (kCallbackDetailLayoutHost == nullptr)
            {
                return;
            }
            kCallbackDetailLayoutHost->clearEmbeddedDetails();
            kCallbackDetailLayoutHost->setTableView(
                tabIndex == callbackViewTabs->indexOf(minifilterCallbackTree_)
                    ? static_cast<QAbstractItemView*>(minifilterCallbackTree_)
                    : static_cast<QAbstractItemView*>(callbackEnumTable_));
        });
    connect(callbackEnumTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showCallbackEnumDetailByCurrentRow();
    });
    connect(callbackEnumTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showCallbackEnumContextMenu(localPosition);
    });
    connect(minifilterCallbackTree_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* currentItem) {
        if (currentItem == nullptr)
        {
            showCallbackEnumDetail(nullptr);
            return;
        }
        const std::size_t kSourceIndex = static_cast<std::size_t>(
            currentItem->data(0, Qt::UserRole).toULongLong());
        showCallbackEnumDetail(
            kSourceIndex < callbackEnumRows_.size() ? &callbackEnumRows_[kSourceIndex] : nullptr);
    });
    connect(minifilterCallbackTree_, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item) {
        if (item == nullptr)
        {
            return;
        }
        const std::size_t kSourceIndex = static_cast<std::size_t>(
            item->data(0, Qt::UserRole).toULongLong());
        if (kSourceIndex >= callbackEnumRows_.size())
        {
            return;
        }
        const QString kModulePath = callbackEnumNormalizeModulePath(
            callbackEnumRows_[kSourceIndex].modulePathText);
        if (!kModulePath.isEmpty() && QFileInfo::exists(kModulePath))
        {
            callbackEnumShowModuleFileDetailDialog(this, kModulePath);
        }
    });
}

void KernelDock::refreshCallbackEnumAsync()
{
    if (callbackEnumRefreshRunning_.exchange(true))
    {
        return;
    }

    if (refreshCallbackEnumButton_ != nullptr)
    {
        refreshCallbackEnumButton_->setEnabled(false);
    }
    if (callbackEnumStatusLabel_ != nullptr)
    {
        callbackEnumStatusLabel_->setText(kernelText("kernel.callback.enum.status.refreshing", QStringLiteral("状态：刷新中...")));
        callbackEnumStatusLabel_->setStyleSheet(callbackEnumStatusLabelStyle(ksword_theme::kPrimaryBlueHex));
    }

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelCallbackEnumEntry> resultRows;
        QString errorText;
        std::uint32_t responseFlags = 0;
        std::uint32_t responseVersion = 0;
        std::uint32_t snapshotPageCount = 0;
        std::uint32_t snapshotRetryCount = 0;
        std::uint64_t snapshotHash = 0;
        bool snapshotConsistent = false;
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::CallbackEnumResult kEnumResult = kDriverClient.enumerateCallbacks();
        const bool kSuccess = kEnumResult.io.ok;

        if (kSuccess)
        {
            QHash<QString, CallbackEnumVersionText> versionCache;
            responseFlags = kEnumResult.flags;
            responseVersion = kEnumResult.version;
            snapshotPageCount = kEnumResult.pageCount;
            snapshotRetryCount = kEnumResult.snapshotRetryCount;
            snapshotHash = kEnumResult.snapshotHash;
            snapshotConsistent = kEnumResult.snapshotConsistent;
            resultRows.reserve(kEnumResult.entries.size());
            for (const ksword::ark::CallbackEnumEntry& entry : kEnumResult.entries)
            {
                KernelCallbackEnumEntry row = callbackEnumConvertEntry(entry);
                const QString kModulePath = callbackEnumNormalizeModulePath(row.modulePathText);
                if (!kModulePath.isEmpty() && QFileInfo::exists(kModulePath))
                {
                    const QString kCacheKey = kModulePath.toLower();
                    auto versionIterator = versionCache.constFind(kCacheKey);
                    if (versionIterator == versionCache.cend())
                    {
                        versionCache.insert(
                            kCacheKey,
                            callbackEnumQueryVersionText(kModulePath));
                        versionIterator = versionCache.constFind(kCacheKey);
                    }
                    const CallbackEnumVersionText kVersionText = versionIterator.value();
                    row.companyText = kVersionText.company;
                    row.fileVersionText = kVersionText.fileVersion;
                    row.fileDescriptionText = kVersionText.description;
                }
                resultRows.push_back(std::move(row));
            }
        }
        else
        {
            errorText = kernelText("kernel.callback.enum.error.io", QStringLiteral("回调遍历 IOCTL 调用失败。\nWin32=%1\n详情=%2"))
                .arg(kEnumResult.io.win32Error)
                .arg(callbackEnumIoMessageText(QString::fromStdString(kEnumResult.io.message)));
        }

        QMetaObject::invokeMethod(
            guardThis,
            [guardThis,
             kSuccess,
             errorText,
             responseFlags,
             responseVersion,
             snapshotPageCount,
             snapshotRetryCount,
             snapshotHash,
             snapshotConsistent,
             resultRows = std::move(resultRows)]() mutable {
            const auto kDeferredRows =
                std::make_shared<std::vector<KernelCallbackEnumEntry>>(std::move(resultRows));
            auto commitResult = [
                guardThis,
                kSuccess,
                errorText,
                responseFlags,
                responseVersion,
                snapshotPageCount,
                snapshotRetryCount,
                snapshotHash,
                snapshotConsistent,
                kDeferredRows]() mutable
            {
            std::vector<KernelCallbackEnumEntry>& resultRows = *kDeferredRows;
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->callbackEnumRefreshRunning_.store(false);
            if (guardThis->refreshCallbackEnumButton_ != nullptr)
            {
                guardThis->refreshCallbackEnumButton_->setEnabled(true);
            }

            if (!kSuccess)
            {
                guardThis->callbackEnumStatusLabel_->setText(kernelText("kernel.callback.enum.status.failed", QStringLiteral("状态：刷新失败")));
                guardThis->callbackEnumStatusLabel_->setStyleSheet(callbackEnumStatusLabelStyle(ksword_theme::errorHex()));
                guardThis->callbackEnumDetailEditor_->setText(errorText);
                return;
            }

            guardThis->callbackEnumRows_ = std::move(resultRows);
            guardThis->rebuildCallbackEnumTable(guardThis->callbackEnumFilterEdit_->text().trimmed());

            std::size_t unsupportedCount = 0U;
            for (const KernelCallbackEnumEntry& entry : guardThis->callbackEnumRows_)
            {
                if (entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED)
                {
                    ++unsupportedCount;
                }
            }

            const bool kTruncated = (responseFlags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_TRUNCATED) != 0U;
            const QString kSnapshotSuffix =
                responseVersion >= KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION && snapshotConsistent
                ? kernelText(
                    "kernel.callback.enum.status.snapshot_consistent_suffix",
                    QStringLiteral("，快照一致（%1 页，重试 %2 次，Hash %3）"))
                    .arg(snapshotPageCount)
                    .arg(snapshotRetryCount)
                    .arg(callbackEnumFormatAddress(snapshotHash))
                : kernelText(
                    "kernel.callback.enum.status.snapshot_legacy_suffix",
                    QStringLiteral("，旧协议未提供快照一致性校验（%1 页）"))
                    .arg(snapshotPageCount);
            guardThis->callbackEnumStatusLabel_->setText(
                kernelText("kernel.callback.enum.status.summary", QStringLiteral("状态：已刷新 %1 项，私有未支持 %2 项%3%4"))
                .arg(guardThis->callbackEnumRows_.size())
                .arg(unsupportedCount)
                .arg(kTruncated ? kernelText("kernel.callback.enum.status.truncated_suffix", QStringLiteral("，响应截断")) : QString())
                .arg(kSnapshotSuffix));
            guardThis->callbackEnumStatusLabel_->setStyleSheet(callbackEnumStatusLabelStyle(
                kTruncated || !snapshotConsistent ? ksword_theme::warningHex() : ksword_theme::successHex()));

            if (guardThis->callbackEnumTable_->rowCount() > 0)
            {
                int firstDataRow = -1;
                for (int rowIndex = 0; rowIndex < guardThis->callbackEnumTable_->rowCount(); ++rowIndex)
                {
                    std::size_t sourceIndex = 0U;
                    if (callbackEnumReadSourceIndex(
                        guardThis->callbackEnumTable_->item(
                            rowIndex,
                            static_cast<int>(CallbackEnumColumn::kClass)),
                        guardThis->callbackEnumRows_.size(),
                        sourceIndex))
                    {
                        firstDataRow = rowIndex;
                        break;
                    }
                }
                if (firstDataRow >= 0)
                {
                    guardThis->callbackEnumTable_->setCurrentCell(
                        firstDataRow,
                        static_cast<int>(CallbackEnumColumn::kRegistrationType));
                }
            }
            else
            {
                guardThis->callbackEnumDetailEditor_->setText(kernelText("kernel.callback.enum.empty", QStringLiteral("当前环境未返回可见回调记录。")));
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-callback-enum-snapshot-apply"),
                { guardThis->callbackEnumTable_, guardThis->minifilterCallbackTree_ },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::rebuildCallbackEnumTable(const QString& filterKeyword)
{
    if (callbackEnumTable_ == nullptr)
    {
        return;
    }

    callbackEnumTable_->setSortingEnabled(false);
    callbackEnumTable_->setRowCount(0);

    std::vector<std::size_t> successfulSourceIndices;
    std::vector<std::size_t> deferredSourceIndices;
    successfulSourceIndices.reserve(callbackEnumRows_.size());
    deferredSourceIndices.reserve(callbackEnumRows_.size());

    for (std::size_t sourceIndex = 0; sourceIndex < callbackEnumRows_.size(); ++sourceIndex)
    {
        const KernelCallbackEnumEntry& entry = callbackEnumRows_[sourceIndex];
        const QString kAddressText = callbackEnumPrimaryAddressText(entry);
        const QString kModuleText = entry.modulePathText.isEmpty()
            ? kernelText("kernel.callback.enum.placeholder.unresolved", QStringLiteral("<未解析>"))
            : entry.modulePathText;
        const bool kMatched = filterKeyword.isEmpty()
            || entry.classText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.registrationTypeText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.sourceText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.sourceTrustText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.statusText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.removePolicyText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.nameText.contains(filterKeyword, Qt::CaseInsensitive)
            || kAddressText.contains(filterKeyword, Qt::CaseInsensitive)
            || kModuleText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.companyText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.fileVersionText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.fileDescriptionText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.altitudeText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.detailText.contains(filterKeyword, Qt::CaseInsensitive);
        if (!kMatched)
        {
            continue;
        }

        if (callbackEnumIsVisibleSuccess(entry))
        {
            successfulSourceIndices.push_back(sourceIndex);
        }
        else
        {
            deferredSourceIndices.push_back(sourceIndex);
        }
    }

    const auto kAppendCallbackRow = [this](const std::size_t sourceIndex) {
        const KernelCallbackEnumEntry& entry = callbackEnumRows_[sourceIndex];
        const QString kAddressText = callbackEnumPrimaryAddressText(entry);
        const QString kModuleText = entry.modulePathText.isEmpty()
            ? kernelText("kernel.callback.enum.placeholder.unresolved", QStringLiteral("<未解析>"))
            : entry.modulePathText;
        const int kRowIndex = callbackEnumTable_->rowCount();
        callbackEnumTable_->insertRow(kRowIndex);

        auto* classItem = new QTableWidgetItem(entry.classText);
        classItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        auto* registrationTypeItem = new QTableWidgetItem(entry.registrationTypeText);
        auto* sourceItem = new QTableWidgetItem(entry.sourceText);
        auto* trustItem = new QTableWidgetItem(entry.sourceTrustText);
        auto* statusItem = new QTableWidgetItem(entry.statusText);
        auto* removePolicyItem = new QTableWidgetItem();
        auto* nameItem = new QTableWidgetItem(callbackEnumSafeText(entry.nameText));
        auto* addressItem = new QTableWidgetItem(kAddressText);
        auto* moduleItem = new QTableWidgetItem(kModuleText);
        auto* companyItem = new QTableWidgetItem(callbackEnumSafeText(entry.companyText));
        auto* fileVersionItem = new QTableWidgetItem(callbackEnumSafeText(entry.fileVersionText));
        auto* fileDescriptionItem = new QTableWidgetItem(callbackEnumSafeText(entry.fileDescriptionText));
        auto* altitudeItem = new QTableWidgetItem(callbackEnumSafeText(entry.altitudeText));

        if (callbackEnumIsTrustedSource(entry))
        {
            trustItem->setForeground(QBrush(ksword_theme::successColor()));
        }
        else if (entry.fallbackPatternOnly)
        {
            trustItem->setForeground(QBrush(ksword_theme::warningColor()));
        }
        else if (callbackEnumIsUnsupportedSource(entry))
        {
            trustItem->setForeground(QBrush(ksword_theme::textSecondaryColor()));
        }

        if (entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_SUSPICIOUS)
        {
            statusItem->setForeground(QBrush(ksword_theme::errorColor()));
        }
        else if (entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_UNKNOWN)
        {
            statusItem->setForeground(QBrush(ksword_theme::warningColor()));
        }
        else if (entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED)
        {
            statusItem->setForeground(QBrush(ksword_theme::warningColor()));
        }
        else if (entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED)
        {
            statusItem->setForeground(QBrush(ksword_theme::errorColor()));
        }

        callbackEnumApplyRemovePolicyPresentation(removePolicyItem, entry);

        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kClass), classItem);
        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kRegistrationType), registrationTypeItem);
        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kSource), sourceItem);
        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kTrust), trustItem);
        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kStatus), statusItem);
        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kRemovePolicy), removePolicyItem);
        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kName), nameItem);
        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kCallbackAddress), addressItem);
        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kModule), moduleItem);
        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kCompany), companyItem);
        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kFileVersion), fileVersionItem);
        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kFileDescription), fileDescriptionItem);
        callbackEnumTable_->setItem(kRowIndex, static_cast<int>(CallbackEnumColumn::kAltitude), altitudeItem);
    };

    for (const std::size_t kSourceIndex : successfulSourceIndices)
    {
        kAppendCallbackRow(kSourceIndex);
    }

    if (!deferredSourceIndices.empty())
    {
        const int kSeparatorRow = callbackEnumTable_->rowCount();
        callbackEnumTable_->insertRow(kSeparatorRow);
        int firstVisibleColumn = -1;
        for (int columnIndex = 0; columnIndex < callbackEnumTable_->columnCount(); ++columnIndex)
        {
            if (!callbackEnumTable_->isColumnHidden(columnIndex))
            {
                firstVisibleColumn = columnIndex;
                break;
            }
        }
        if (firstVisibleColumn >= 0)
        {
            auto* separatorItem = new QTableWidgetItem(kernelText(
                "kernel.callback.enum.separator.failed_or_unsupported",
                QStringLiteral("以下项查询失败/当前不支持")));
            separatorItem->setFlags(Qt::ItemIsEnabled);
            separatorItem->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
            separatorItem->setBackground(ksword_theme::surfaceMutedColor());
            separatorItem->setForeground(ksword_theme::textPrimaryColor());
            separatorItem->setToolTip(separatorItem->text());
            callbackEnumTable_->setItem(kSeparatorRow, firstVisibleColumn, separatorItem);
            callbackEnumTable_->setSpan(
                kSeparatorRow,
                firstVisibleColumn,
                1,
                callbackEnumTable_->columnCount() - firstVisibleColumn);
        }
    }

    for (const std::size_t kSourceIndex : deferredSourceIndices)
    {
        kAppendCallbackRow(kSourceIndex);
    }

    if (minifilterCallbackTree_ == nullptr)
    {
        return;
    }

    minifilterCallbackTree_->setUpdatesEnabled(false);
    minifilterCallbackTree_->clear();
    QHash<qulonglong, QTreeWidgetItem*> filterParents;
    const auto kEntryMatchesFilter = [&filterKeyword](const KernelCallbackEnumEntry& entry) {
        const QString kAddressText = callbackEnumPrimaryAddressText(entry);
        return filterKeyword.isEmpty()
            || entry.classText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.registrationTypeText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.sourceText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.sourceTrustText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.statusText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.nameText.contains(filterKeyword, Qt::CaseInsensitive)
            || kAddressText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.modulePathText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.companyText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.fileVersionText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.fileDescriptionText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.altitudeText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.detailText.contains(filterKeyword, Qt::CaseInsensitive);
    };

    for (std::size_t sourceIndex = 0; sourceIndex < callbackEnumRows_.size(); ++sourceIndex)
    {
        const KernelCallbackEnumEntry& entry = callbackEnumRows_[sourceIndex];
        const bool kIsFilterParent =
            entry.callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER
            && entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION
            && entry.callbackAddress == 0U
            && entry.registrationAddress != 0U;
        if (!kIsFilterParent)
        {
            continue;
        }

        auto* parentItem = new QTreeWidgetItem(minifilterCallbackTree_);
        parentItem->setText(0, callbackEnumSafeText(entry.nameText));
        parentItem->setText(
            1,
            kernelText("kernel.callback.enum.minifilter.type.filter", QStringLiteral("Filter")));
        parentItem->setText(8, callbackEnumSafeText(entry.altitudeText));
        parentItem->setText(9, entry.sourceText + QStringLiteral(" / ") + entry.sourceTrustText);
        parentItem->setData(0, Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        parentItem->setData(0, Qt::UserRole + 1, kEntryMatchesFilter(entry));
        parentItem->setData(0, Qt::UserRole + 2, false);
        parentItem->setToolTip(0, entry.detailText);
        parentItem->setExpanded(true);
        filterParents.insert(static_cast<qulonglong>(entry.registrationAddress), parentItem);
    }

    for (std::size_t sourceIndex = 0; sourceIndex < callbackEnumRows_.size(); ++sourceIndex)
    {
        const KernelCallbackEnumEntry& entry = callbackEnumRows_[sourceIndex];
        if (entry.callbackClass != KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER
            || entry.contextAddress == 0U)
        {
            continue;
        }

        QTreeWidgetItem* parentItem =
            filterParents.value(static_cast<qulonglong>(entry.contextAddress), nullptr);
        if (parentItem == nullptr)
        {
            continue;
        }

        QString modulePath = callbackEnumNormalizeModulePath(entry.modulePathText);
        if (modulePath.isEmpty())
        {
            modulePath = entry.modulePathText;
        }
        const QString kModuleFileName = modulePath.isEmpty()
            ? QString()
            : QFileInfo(modulePath).fileName();
        QString stageText;
        if (entry.nameText.endsWith(QStringLiteral("/ PreOperation"), Qt::CaseInsensitive))
        {
            stageText = QStringLiteral("PreOperation");
        }
        else if (entry.nameText.endsWith(QStringLiteral("/ PostOperation"), Qt::CaseInsensitive))
        {
            stageText = QStringLiteral("PostOperation");
        }
        else
        {
            stageText = entry.statusText;
        }

        auto* callbackItem = new QTreeWidgetItem(parentItem);
        callbackItem->setText(0, callbackEnumSafeText(entry.nameText));
        callbackItem->setText(1, stageText);
        callbackItem->setText(
            2,
            entry.callbackAddress == 0U
                ? kernelText("kernel.callback.enum.address.none", QStringLiteral("<无回调地址>"))
                : callbackEnumFormatAddress(entry.callbackAddress));
        callbackItem->setText(3, kModuleFileName);
        callbackItem->setText(4, modulePath);
        callbackItem->setText(5, entry.companyText);
        callbackItem->setText(6, entry.fileVersionText);
        callbackItem->setText(7, entry.fileDescriptionText);
        callbackItem->setText(8, callbackEnumSafeText(entry.altitudeText));
        callbackItem->setText(9, entry.sourceText + QStringLiteral(" / ") + entry.sourceTrustText);
        callbackItem->setData(0, Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        callbackItem->setData(0, Qt::UserRole + 1, kEntryMatchesFilter(entry));
        callbackItem->setToolTip(0, entry.detailText);
        callbackItem->setToolTip(
            4,
            kernelText(
                "kernel.callback.enum.minifilter.path.tooltip",
                QStringLiteral("双击此回调可查看驱动文件常规信息和 PE 明细")));
        if (entry.fallbackPatternOnly)
        {
            callbackItem->setForeground(9, QBrush(ksword_theme::warningColor()));
        }

        if (parentItem->text(4).isEmpty() && !modulePath.isEmpty())
        {
            parentItem->setText(3, kModuleFileName);
            parentItem->setText(4, modulePath);
            parentItem->setText(5, entry.companyText);
            parentItem->setText(6, entry.fileVersionText);
            parentItem->setText(7, entry.fileDescriptionText);
        }
        if (kEntryMatchesFilter(entry))
        {
            parentItem->setData(0, Qt::UserRole + 2, true);
        }
    }

    for (int parentIndex = 0; parentIndex < minifilterCallbackTree_->topLevelItemCount(); ++parentIndex)
    {
        QTreeWidgetItem* parentItem = minifilterCallbackTree_->topLevelItem(parentIndex);
        const bool kParentMatched = parentItem->data(0, Qt::UserRole + 1).toBool();
        const bool kChildMatched = parentItem->data(0, Qt::UserRole + 2).toBool();
        parentItem->setHidden(!filterKeyword.isEmpty() && !kParentMatched && !kChildMatched);
        for (int childIndex = 0; childIndex < parentItem->childCount(); ++childIndex)
        {
            QTreeWidgetItem* childItem = parentItem->child(childIndex);
            const bool kRowMatched = childItem->data(0, Qt::UserRole + 1).toBool();
            childItem->setHidden(!filterKeyword.isEmpty() && !kParentMatched && !kRowMatched);
        }
    }
    minifilterCallbackTree_->setUpdatesEnabled(true);
}

bool KernelDock::currentCallbackEnumSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0U;
    if (callbackEnumTable_ == nullptr)
    {
        return false;
    }

    const int kCurrentRow = callbackEnumTable_->currentRow();
    if (kCurrentRow < 0)
    {
        return false;
    }

    QTableWidgetItem* classItem = callbackEnumTable_->item(kCurrentRow, static_cast<int>(CallbackEnumColumn::kClass));
    if (classItem == nullptr)
    {
        return false;
    }

    std::size_t sourceIndex = 0U;
    if (!callbackEnumReadSourceIndex(classItem, callbackEnumRows_.size(), sourceIndex))
    {
        return false;
    }

    sourceIndexOut = sourceIndex;
    return true;
}

const KernelCallbackEnumEntry* KernelDock::currentCallbackEnumEntry() const
{
    std::size_t sourceIndex = 0U;
    if (!currentCallbackEnumSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &callbackEnumRows_[sourceIndex];
}

void KernelDock::showCallbackEnumDetailByCurrentRow()
{
    showCallbackEnumDetail(currentCallbackEnumEntry());
}

void KernelDock::showCallbackEnumDetail(const KernelCallbackEnumEntry* entry)
{
    if (callbackEnumDetailEditor_ == nullptr)
    {
        return;
    }

    if (entry == nullptr)
    {
        callbackEnumDetailEditor_->setText(kernelText("kernel.callback.enum.detail.initial", QStringLiteral("请选择一条回调记录查看详情。")));
        return;
    }

    const QString kWin32ModulePath = callbackEnumNormalizeModulePath(entry->modulePathText);
    const QString kDetailText = kernelText("kernel.callback.enum.detail.full_v2", QStringLiteral(
        "类别: %1\n"
        "注册类型: %2\n"
        "来源: %3\n"
        "可信状态: %4\n"
        "移除策略: %5\n"
        "是否需要二次确认: %6\n"
        "是否仅为定位线索: %7\n"
        "状态: %8\n"
        "名称: %9\n"
        "Altitude: %10\n"
        "主地址显示: %11\n"
        "真实回调地址: %12\n"
        "上下文/诊断值: %13\n"
        "注册句柄/Cookie/全局节点: %14\n"
        "模块路径: %15\n"
        "Win32模块路径: %16\n"
        "公司: %17\n"
        "文件版本: %18\n"
        "文件描述: %19\n"
        "模块基址: %20\n"
        "模块大小: 0x%21\n"
        "操作掩码: 0x%22\n"
        "对象类型掩码: 0x%23\n"
        "字段标志: 0x%24\n"
        "可信标志: 0x%25\n"
        "移除行为: 0x%26\n"
        "移除标志: 0x%27\n"
        "Generation: %28\n"
        "IdentityHash: %29\n"
        "RawStorageValue: %30\n"
        "LastStatus: 0x%31\n\n"
        "说明: 主地址优先显示真实回调函数；无法获取时会显示可用于定位的节点或标识值。\n\n"
        "详情:\n%32"))
        .arg(entry->classText)
        .arg(entry->registrationTypeText)
        .arg(entry->sourceText)
        .arg(entry->sourceTrustText)
        .arg(entry->removePolicyText)
        .arg(callbackEnumYesNoText(entry->requiresSecondConfirmation))
        .arg(callbackEnumYesNoText(entry->fallbackPatternOnly))
        .arg(entry->statusText)
        .arg(callbackEnumSafeText(entry->nameText))
        .arg(callbackEnumSafeText(entry->altitudeText))
        .arg(callbackEnumPrimaryAddressText(*entry))
        .arg(callbackEnumFormatAddress(entry->callbackAddress))
        .arg(callbackEnumFormatAddress(entry->contextAddress))
        .arg(callbackEnumFormatAddress(entry->registrationAddress))
        .arg(entry->modulePathText.isEmpty()
            ? kernelText("kernel.callback.enum.placeholder.unresolved", QStringLiteral("<未解析>"))
            : entry->modulePathText)
        .arg(kWin32ModulePath.isEmpty()
            ? kernelText("kernel.callback.enum.placeholder.unmapped", QStringLiteral("<不可映射或不存在>"))
            : kWin32ModulePath)
        .arg(callbackEnumSafeText(entry->companyText))
        .arg(callbackEnumSafeText(entry->fileVersionText))
        .arg(callbackEnumSafeText(entry->fileDescriptionText))
        .arg(callbackEnumFormatAddress(entry->moduleBase))
        .arg(QString::number(static_cast<qulonglong>(entry->moduleSize), 16).toUpper())
        .arg(static_cast<qulonglong>(entry->operationMask), 8, 16, QChar('0'))
        .arg(static_cast<qulonglong>(entry->objectTypeMask), 8, 16, QChar('0'))
        .arg(static_cast<qulonglong>(entry->fieldFlags), 8, 16, QChar('0'))
        .arg(static_cast<qulonglong>(entry->trustFlags), 8, 16, QChar('0'))
        .arg(static_cast<qulonglong>(entry->removeBehavior), 8, 16, QChar('0'))
        .arg(static_cast<qulonglong>(entry->removeFlags), 8, 16, QChar('0'))
        .arg(static_cast<qulonglong>(entry->generation))
        .arg(callbackEnumIdentityHashText(entry->identityHash))
        .arg(callbackEnumFormatAddress(entry->rawStorageValue))
        .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(entry->lastStatus)), 8, 16, QChar('0'))
        .arg(callbackEnumSafeText(entry->detailText, kernelText("kernel.callback.enum.placeholder.no_detail", QStringLiteral("<无详情>"))));

    callbackEnumDetailEditor_->setText(kDetailText);
}

void KernelDock::showCallbackEnumContextMenu(const QPoint& localPosition)
{
    if (callbackEnumTable_ == nullptr)
    {
        return;
    }

    // Right-click selection rules:
    // - Switch to the single row when clicking on an unselected row;
    // - Preserve the Ctrl-multi-selection set when clicking on an already selected row.
    // - When clicking on empty space, preserve the current selection so copy actions continue to apply to it.
    QTableWidgetItem* clickedItem = callbackEnumTable_->itemAt(localPosition);
    const int kClickedRow = clickedItem != nullptr ? clickedItem->row() : -1;
    const int kClickedColumn = callbackEnumTable_->columnAt(localPosition.x());
    if (clickedItem != nullptr)
    {
        if (!clickedItem->isSelected())
        {
            callbackEnumTable_->clearSelection();
            callbackEnumTable_->setCurrentItem(clickedItem);
            callbackEnumTable_->selectRow(kClickedRow);
        }
        else
        {
            if (QItemSelectionModel* selectionModel = callbackEnumTable_->selectionModel())
            {
                // When right-clicking an already selected row, only move the current cell without clearing the Ctrl multi-selection set.
                selectionModel->setCurrentIndex(
                    callbackEnumTable_->indexFromItem(clickedItem),
                    QItemSelectionModel::NoUpdate);
            }
        }
    }

    const int kFallbackRow = kClickedRow >= 0 ? kClickedRow : callbackEnumTable_->currentRow();
    const std::vector<std::size_t> kSelectedSourceIndices =
        callbackEnumSelectedSourceIndices(callbackEnumTable_, callbackEnumRows_, kFallbackRow);
    const bool kHasSelection = !kSelectedSourceIndices.empty();
    QString clickedModulePath;
    if (kClickedRow >= 0)
    {
        std::vector<std::size_t> clickedSourceIndices =
            callbackEnumSelectedSourceIndices(callbackEnumTable_, callbackEnumRows_, kClickedRow);
        if (!clickedSourceIndices.empty() && clickedSourceIndices.front() < callbackEnumRows_.size())
        {
            clickedModulePath = callbackEnumNormalizeModulePath(
                callbackEnumRows_[clickedSourceIndices.front()].modulePathText);
        }
    }
    if (clickedModulePath.isEmpty() && !kSelectedSourceIndices.empty() && kSelectedSourceIndices.front() < callbackEnumRows_.size())
    {
        clickedModulePath = callbackEnumNormalizeModulePath(
            callbackEnumRows_[kSelectedSourceIndices.front()].modulePathText);
    }
    const bool kHasModuleFile = !clickedModulePath.isEmpty() && QFileInfo(clickedModulePath).exists();
    const KernelCallbackEnumEntry* actionEntry = nullptr;
    if (kSelectedSourceIndices.size() == 1U && kSelectedSourceIndices.front() < callbackEnumRows_.size())
    {
        actionEntry = &callbackEnumRows_[kSelectedSourceIndices.front()];
    }
    const bool kHasSingleActionEntry = actionEntry != nullptr;
    const CallbackEnumRemovePolicyKind kSelectedRemovePolicy =
        kHasSingleActionEntry ? callbackEnumRemovePolicyKind(*actionEntry) : CallbackEnumRemovePolicyKind::kNotRemovable;
    const bool kCanUseLegacySafeRemove =
        kHasSingleActionEntry && callbackEnumCanUseLegacySafeRemove(*actionEntry);
    const bool kCanUseExperimentalUnlink =
        kHasSingleActionEntry && kSelectedRemovePolicy == CallbackEnumRemovePolicyKind::kExperimentalOnly;

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());

    QAction* refreshAction = contextMenu.addAction(
        QIcon(":/Icon/process_refresh.svg"),
        kernelText("kernel.callback.enum.menu.refresh", QStringLiteral("刷新回调遍历")));
    QAction* openModuleFolderAction = contextMenu.addAction(
        QIcon(":/Icon/process_open_folder.svg"),
        kernelText("kernel.callback.enum.menu.open_module_folder", QStringLiteral("打开模块所在目录")));
    QAction* moduleFileDetailAction = contextMenu.addAction(
        QIcon(":/Icon/process_details.svg"),
        kernelText("kernel.callback.enum.menu.module_detail", QStringLiteral("模块文件详细信息")));
    openModuleFolderAction->setEnabled(kHasModuleFile);
    moduleFileDetailAction->setEnabled(kHasModuleFile);
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &contextMenu,
        this,
        [clickedModulePath, actionEntry]() -> ks::online_scan::SandboxUploadTarget
        {
            // Input: The normalized module file path of the current callback line.
            // Processing: Directly upload the matched module file; delegate to unified error prompt if no file exists.
            // Returns: Upload path and source description.
            ks::online_scan::SandboxUploadTarget uploadTarget;
            uploadTarget.filePath = clickedModulePath;
            uploadTarget.sourceText = kernelText("kernel.callback.enum.upload.source", QStringLiteral("内核回调模块 %1"))
                .arg(actionEntry != nullptr
                    ? actionEntry->nameText
                    : kernelText("kernel.callback.enum.placeholder.unknown_callback", QStringLiteral("<未知回调>")));
            return uploadTarget;
        });
    if (uploadVirusTotalAction != nullptr)
    {
        uploadVirusTotalAction->setEnabled(kHasModuleFile);
    }
    contextMenu.addSeparator();

    QAction* safeRemoveAction = contextMenu.addAction(kernelText("kernel.callback.enum.remove.safe.title", QStringLiteral("安全移除")));
    safeRemoveAction->setToolTip(kernelText("kernel.callback.enum.remove.safe.tooltip", QStringLiteral("使用受支持的安全方式移除回调。")));
    safeRemoveAction->setEnabled(kCanUseLegacySafeRemove);
    QAction* experimentalUnlinkAction = contextMenu.addAction(kernelText("kernel.callback.enum.remove.experimental.title", QStringLiteral("强制移除（实验性）")));
    experimentalUnlinkAction->setToolTip(kernelText("kernel.callback.enum.remove.experimental.tooltip", QStringLiteral("需要再次确认；只对可操作项目开放。")));
    experimentalUnlinkAction->setEnabled(kCanUseExperimentalUnlink);
    contextMenu.addSeparator();

    /*
     * Three monitoring entries correspond to three distinct issues, not three variations of the same thing.
     *
     * - Write routine header: who modified this callback's code (attribution for inline hook);
     * - Execution routine: When and from which instruction this callback will actually be invoked next.
     * - Writing registration records: who modified the registration structure itself (replaced function pointers, unlinked).
     *
     * The third item does not have an address to monitor for every callback. The type of the registered cookie varies depending on the registration API:
     * The cookie for ObRegisterCallbacks is indeed a pointer to the registration structure, whereas CmRegisterCallbackEx provides
     * a LARGE_INTEGER sequence number, not an address. Treating a sequence number as a virtual address to resolve results not in
     * an error, but in resolving to an unrelated page of memory and waiting there forever — so here we decide whether to enable
     * it based on 'does it look like a valid kernel address', preferring to miss an entry rather than risk this.
     */
    const quint64 kCallbackRoutineAddress = kHasSingleActionEntry
        ? actionEntry->callbackAddress
        : 0ULL;
    const quint64 kCallbackRegistrationAddress = kHasSingleActionEntry
        ? actionEntry->registrationAddress
        : 0ULL;
    const bool kRegistrationLooksLikeKernelAddress =
        kCallbackRegistrationAddress >= 0xFFFF800000000000ULL;
    QMenu* watchMenu = contextMenu.addMenu(
        kernelText("kernel.callback.enum.menu.hvm_watch",
                   QStringLiteral("HVM 监视：下一次访问")));
    watchMenu->setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* watchRoutineWriteAction = watchMenu->addAction(
        kernelText("kernel.callback.enum.menu.hvm_watch.routine_write",
                   QStringLiteral("写入这个回调例程（改代码）")));
    QAction* watchRoutineExecuteAction = watchMenu->addAction(
        kernelText("kernel.callback.enum.menu.hvm_watch.routine_execute",
                   QStringLiteral("执行这个回调例程")));
    QAction* watchRegistrationAction = watchMenu->addAction(
        kernelText("kernel.callback.enum.menu.hvm_watch.registration_write",
                   QStringLiteral("写入这条回调的注册记录")));
    watchMenu->setEnabled(kCallbackRoutineAddress != 0ULL);
    watchRoutineWriteAction->setEnabled(kCallbackRoutineAddress != 0ULL);
    watchRoutineExecuteAction->setEnabled(kCallbackRoutineAddress != 0ULL);
    watchRegistrationAction->setEnabled(kRegistrationLooksLikeKernelAddress);
    watchRegistrationAction->setToolTip(kRegistrationLooksLikeKernelAddress
        ? kernelText("kernel.callback.enum.menu.hvm_watch.registration_write.tip",
                     QStringLiteral("监视注册结构所在的那一页，等下一次有人改它。"))
        : kernelText("kernel.callback.enum.menu.hvm_watch.registration_write.unavailable",
                     QStringLiteral("这种注册方式回报的是序号而不是地址，没有可监视的注册记录地址。")));
    contextMenu.addSeparator();

    QMenu* copyMenu = contextMenu.addMenu(
        QIcon(":/Icon/process_copy_row.svg"),
        kernelText("kernel.context.menu.copy", QStringLiteral("复制")));
    QAction* copyCurrentColumnAction = copyMenu->addAction(
        QIcon(":/Icon/process_copy_cell.svg"),
        kernelText("kernel.callback.enum.menu.copy_current_column", QStringLiteral("复制当前列（选中行）")));
    QAction* copySelectedRowsAction = copyMenu->addAction(
        QIcon(":/Icon/process_copy_row.svg"),
        kernelText("kernel.context.menu.copy_row", QStringLiteral("复制选中行（TSV）")));
    QAction* copySelectedRowsWithHeaderAction = copyMenu->addAction(
        kernelText("kernel.callback.enum.menu.copy_header_rows", QStringLiteral("复制表头+选中行（TSV）")));
    QAction* copyDetailAction = copyMenu->addAction(
        kernelText("kernel.callback.enum.menu.copy_detail", QStringLiteral("复制详情（选中行）")));
    copyMenu->addSeparator();

    QMenu* copyColumnMenu = copyMenu->addMenu(kernelText("kernel.callback.enum.menu.copy_columns", QStringLiteral("复制指定栏目（选中行）")));
    for (int columnIndex = 0; columnIndex < static_cast<int>(CallbackEnumColumn::kCount); ++columnIndex)
    {
        const CallbackEnumColumn kColumn = static_cast<CallbackEnumColumn>(columnIndex);
        QAction* columnAction = copyColumnMenu->addAction(callbackEnumColumnHeaderText(kColumn));
        columnAction->setData(columnIndex);
    }

    copyCurrentColumnAction->setEnabled(kHasSelection);
    copySelectedRowsAction->setEnabled(kHasSelection);
    copySelectedRowsWithHeaderAction->setEnabled(kHasSelection);
    copyDetailAction->setEnabled(kHasSelection);
    copyColumnMenu->setEnabled(kHasSelection);

    QAction* selectedAction = contextMenu.exec(callbackEnumTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == refreshAction)
    {
        refreshCallbackEnumAsync();
        return;
    }

    if (selectedAction == openModuleFolderAction)
    {
        const bool kOpened = callbackEnumOpenModuleInExplorer(clickedModulePath);
        if (callbackEnumStatusLabel_ != nullptr)
        {
            callbackEnumStatusLabel_->setText(kOpened
                ? kernelText("kernel.callback.enum.status.module_folder_opened", QStringLiteral("状态：已打开模块所在目录"))
                : kernelText("kernel.callback.enum.status.module_folder_failed", QStringLiteral("状态：打开模块所在目录失败")));
        }
        return;
    }

    if (selectedAction == moduleFileDetailAction)
    {
        callbackEnumShowModuleFileDetailDialog(this, clickedModulePath);
        if (callbackEnumStatusLabel_ != nullptr)
        {
            callbackEnumStatusLabel_->setText(kernelText("kernel.callback.enum.status.module_detail_opened", QStringLiteral("状态：已打开模块文件详细信息")));
        }
        return;
    }
    if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }

    if (selectedAction == watchRoutineWriteAction ||
        selectedAction == watchRoutineExecuteAction ||
        selectedAction == watchRegistrationAction)
    {
        ks::ui::HvmWatchRequest request;
        request.virtualAddress = true;
        if (selectedAction == watchRegistrationAction)
        {
            request.address = kCallbackRegistrationAddress;
            // The size of the registration structure varies by registration type; do not guess here, request a full page instead.
            request.length = 0ULL;
            request.access = KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
        }
        else
        {
            request.address = kCallbackRoutineAddress;
            /*
             * First 16 bytes. Inline hooks modify only these bytes (jmp rel32 is 5 bytes; mov rax, imm64 + jmp rax is 12
             * bytes). Since this is narrower than a full page, the distinction of "falling within the request range" only
             * matters upon a hit. Hardware still monitors the entire page; this is displayed side-by-side in two columns.
             */
            request.length = 16ULL;
            request.access = selectedAction == watchRoutineExecuteAction
                ? KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE
                : KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
        }
        request.label = kernelText(
            "kernel.callback.enum.menu.hvm_watch.label",
            QStringLiteral("内核回调 %1（%2）"))
            .arg(actionEntry != nullptr && !actionEntry->nameText.isEmpty()
                ? actionEntry->nameText
                : kernelText("kernel.callback.enum.placeholder.unknown_callback",
                             QStringLiteral("<未知回调>")))
            .arg(selectedAction == watchRegistrationAction
                ? kernelText("kernel.callback.enum.menu.hvm_watch.label.registration",
                             QStringLiteral("注册记录"))
                : kernelText("kernel.callback.enum.menu.hvm_watch.label.routine",
                             QStringLiteral("例程首部")));
        ks::ui::openHvmWatch(this, request);
        return;
    }

    if (selectedAction == safeRemoveAction)
    {
        if (actionEntry != nullptr)
        {
            const bool kRemovalConfirmed = callbackEnumExecuteSafeRemove(
                this,
                callbackEnumStatusLabel_,
                callbackEnumDetailEditor_,
                *actionEntry);
            if (kRemovalConfirmed)
            {
                refreshCallbackEnumAsync();
            }
        }
        return;
    }

    if (selectedAction == experimentalUnlinkAction)
    {
        if (actionEntry != nullptr)
        {
            callbackEnumShowExperimentalUnlinkNotice(
                this,
                callbackEnumStatusLabel_,
                callbackEnumDetailEditor_,
                *actionEntry);
        }
        return;
    }

    if (!kHasSelection)
    {
        return;
    }

    const auto kBuildColumnText = [this, &kSelectedSourceIndices](const CallbackEnumColumn column) -> QString
    {
        // Purpose: Concatenates values from the specified column across all selected rows into multi-line text.
        // Return: column values separated by newlines.
        QStringList valueList;
        valueList.reserve(static_cast<int>(kSelectedSourceIndices.size()));
        for (const std::size_t kSourceIndex : kSelectedSourceIndices)
        {
            if (kSourceIndex < callbackEnumRows_.size())
            {
                valueList.push_back(callbackEnumEntryColumnText(callbackEnumRows_[kSourceIndex], column));
            }
        }
        return valueList.join('\n');
    };

    if (selectedAction == copyCurrentColumnAction)
    {
        int activeColumn = kClickedColumn >= 0 ? kClickedColumn : callbackEnumTable_->currentColumn();
        if (activeColumn < 0 || activeColumn >= static_cast<int>(CallbackEnumColumn::kCount))
        {
            activeColumn = static_cast<int>(CallbackEnumColumn::kClass);
        }
        callbackEnumCopyTextToClipboard(kBuildColumnText(static_cast<CallbackEnumColumn>(activeColumn)));
        if (callbackEnumStatusLabel_ != nullptr)
        {
            callbackEnumStatusLabel_->setText(kernelText("kernel.callback.enum.status.column_copied", QStringLiteral("状态：已复制 %1 行的“%2”栏目"))
                .arg(static_cast<qulonglong>(kSelectedSourceIndices.size()))
                .arg(callbackEnumColumnHeaderText(static_cast<CallbackEnumColumn>(activeColumn))));
        }
        return;
    }

    if (selectedAction == copySelectedRowsAction || selectedAction == copySelectedRowsWithHeaderAction)
    {
        QStringList rowList;
        rowList.reserve(static_cast<int>(kSelectedSourceIndices.size()) + 1);
        if (selectedAction == copySelectedRowsWithHeaderAction)
        {
            rowList.push_back(callbackEnumHeaderAsTsv());
        }
        for (const std::size_t kSourceIndex : kSelectedSourceIndices)
        {
            if (kSourceIndex < callbackEnumRows_.size())
            {
                rowList.push_back(callbackEnumEntryAsTsv(callbackEnumRows_[kSourceIndex]));
            }
        }
        callbackEnumCopyTextToClipboard(rowList.join('\n'));
        if (callbackEnumStatusLabel_ != nullptr)
        {
            callbackEnumStatusLabel_->setText(kernelText("kernel.callback.enum.status.rows_copied", QStringLiteral("状态：已复制 %1 行回调记录"))
                .arg(static_cast<qulonglong>(kSelectedSourceIndices.size())));
        }
        return;
    }

    if (selectedAction == copyDetailAction)
    {
        QStringList detailList;
        detailList.reserve(static_cast<int>(kSelectedSourceIndices.size()));
        for (const std::size_t kSourceIndex : kSelectedSourceIndices)
        {
            if (kSourceIndex >= callbackEnumRows_.size())
            {
                continue;
            }

            const KernelCallbackEnumEntry& entry = callbackEnumRows_[kSourceIndex];
            detailList.push_back(kernelText("kernel.callback.enum.copy.detail_item", QStringLiteral("[%1] %2\n%3"))
                .arg(entry.classText)
                .arg(callbackEnumSafeText(entry.nameText))
                .arg(callbackEnumSafeText(entry.detailText, kernelText("kernel.callback.enum.placeholder.no_detail", QStringLiteral("<无详情>")))));
        }
        callbackEnumCopyTextToClipboard(detailList.join(QStringLiteral("\n\n---\n\n")));
        if (callbackEnumStatusLabel_ != nullptr)
        {
            callbackEnumStatusLabel_->setText(kernelText("kernel.callback.enum.status.details_copied", QStringLiteral("状态：已复制 %1 行详情"))
                .arg(static_cast<qulonglong>(kSelectedSourceIndices.size())));
        }
        return;
    }

    const QList<QAction*> kColumnActionList = copyColumnMenu->actions();
    if (kColumnActionList.contains(selectedAction))
    {
        const int kColumnIndex = selectedAction->data().toInt();
        if (kColumnIndex >= 0 && kColumnIndex < static_cast<int>(CallbackEnumColumn::kCount))
        {
            const CallbackEnumColumn kColumn = static_cast<CallbackEnumColumn>(kColumnIndex);
            callbackEnumCopyTextToClipboard(kBuildColumnText(kColumn));
            if (callbackEnumStatusLabel_ != nullptr)
            {
                callbackEnumStatusLabel_->setText(kernelText("kernel.callback.enum.status.column_copied", QStringLiteral("状态：已复制 %1 行的“%2”栏目"))
                    .arg(static_cast<qulonglong>(kSelectedSourceIndices.size()))
                    .arg(callbackEnumColumnHeaderText(kColumn)));
            }
        }
    }
}
