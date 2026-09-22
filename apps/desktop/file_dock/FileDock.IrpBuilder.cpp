#include "FileDock.h"

// ============================================================
// FileDock.IrpBuilder.cpp
// Purpose:
// - Hosts the FileDock "IRP Builder" page: manually assemble and dispatch arbitrary IRP_MJ_* to the file system stack;
// - The parameter region automatically starts/stops based on the current major version to prevent residual values of irrelevant fields from being sent as valid parameters.
// - Write semantics require explicit confirmation for PnP/Power requests; the R0 side performs a token validation check again.
// - Avoid further bloating the main FileDock.cpp file.
// ============================================================

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"
#include "IrpFileSystemParser.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QSplitter>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <cstdint>
#include <thread>
#include <vector>

namespace
{
    // IrpOperationPresetId: Maps common file operations to a set of reviewable IRP parameters.
    // Presets only populate the UI and do not execute directly; write-semantic confirmation checkboxes must still be checked by the user.
    enum IrpOperationPresetId
    {
        kIrpPresetCustom = 0,
        kIrpPresetQueryAllInformation,
        kIrpPresetRead,
        kIrpPresetWrite,
        kIrpPresetFlush,
        kIrpPresetCreateFile,
        kIrpPresetCreateDirectory,
        kIrpPresetEnumerateDirectory,
        kIrpPresetDeleteLegacy,
        kIrpPresetDeletePosix,
        kIrpPresetTruncateZero,
        kIrpPresetSetNormalAttributes,
        kIrpPresetQueryVolume,
        kIrpPresetQuerySecurity
    };

    // kIrpMajorNames:
    // - Provides canonical names for all 28 IRP_MJ_* operations; the index corresponds to the major number.
    // - Names correspond one-to-one with WDK definitions to facilitate direct mapping of UI options to documentation.
    const char* const kIrpMajorNames[] = {
        "IRP_MJ_CREATE",
        "IRP_MJ_CREATE_NAMED_PIPE",
        "IRP_MJ_CLOSE",
        "IRP_MJ_READ",
        "IRP_MJ_WRITE",
        "IRP_MJ_QUERY_INFORMATION",
        "IRP_MJ_SET_INFORMATION",
        "IRP_MJ_QUERY_EA",
        "IRP_MJ_SET_EA",
        "IRP_MJ_FLUSH_BUFFERS",
        "IRP_MJ_QUERY_VOLUME_INFORMATION",
        "IRP_MJ_SET_VOLUME_INFORMATION",
        "IRP_MJ_DIRECTORY_CONTROL",
        "IRP_MJ_FILE_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CONTROL",
        "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        "IRP_MJ_SHUTDOWN",
        "IRP_MJ_LOCK_CONTROL",
        "IRP_MJ_CLEANUP",
        "IRP_MJ_CREATE_MAILSLOT",
        "IRP_MJ_QUERY_SECURITY",
        "IRP_MJ_SET_SECURITY",
        "IRP_MJ_POWER",
        "IRP_MJ_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CHANGE",
        "IRP_MJ_QUERY_QUOTA",
        "IRP_MJ_SET_QUOTA",
        "IRP_MJ_PNP"
    };

    // majorIsWriteLike:
    // - Maintains the same judgment logic as kswordArkFileIrpMajorIsWriteLike on the R0 side.
    // - The UI forces a confirmation check based on this to prevent users from modifying the disk without any warning.
    bool majorIsWriteLike(const int majorFunction)
    {
        switch (majorFunction)
        {
        case 0:   // IRP_MJ_CREATE (FILE_CREATE/OPEN_IF, etc., may create or overwrite the target).
        case 1:   // IRP_MJ_CREATE_NAMED_PIPE
        case 4:   // IRP_MJ_WRITE
        case 6:   // IRP_MJ_SET_INFORMATION
        case 8:   // IRP_MJ_SET_EA
        case 11:  // IRP_MJ_SET_VOLUME_INFORMATION
        case 13:  // IRP_MJ_FILE_SYSTEM_CONTROL
        case 14:  // IRP_MJ_DEVICE_CONTROL
        case 15:  // IRP_MJ_INTERNAL_DEVICE_CONTROL
        case 17:  // IRP_MJ_LOCK_CONTROL
        case 19:  // IRP_MJ_CREATE_MAILSLOT
        case 21:  // IRP_MJ_SET_SECURITY
        case 26:  // IRP_MJ_SET_QUOTA
            return true;
        default:
            return false;
        }
    }

    // majorIsDangerous:
    // - Maintains the same judgment logic as kswordArkFileIrpMajorIsDangerous on the R0 side.
    // - The PnP/power manager issues these requests according to its state machine; constructing them manually can easily put the target driver into an invalid state.
    bool majorIsDangerous(const int majorFunction)
    {
        switch (majorFunction)
        {
        case 16:  // IRP_MJ_SHUTDOWN
        case 22:  // IRP_MJ_POWER
        case 23:  // IRP_MJ_SYSTEM_CONTROL
        case 24:  // IRP_MJ_DEVICE_CHANGE
        case 27:  // IRP_MJ_PNP
            return true;
        default:
            return false;
        }
    }

    // statusHex: Unifies formatting of NTSTATUS to a fixed 8-digit hexadecimal string.
    QString statusHex(const long statusValue)
    {
        return QStringLiteral("0x%1")
            .arg(
                static_cast<qulonglong>(static_cast<unsigned long>(statusValue)),
                8,
                16,
                QChar('0'))
            .toUpper();
    }

    // pointerHex purpose: Formats kernel addresses as 16-digit hexadecimal; displays 0 as a placeholder.
    QString pointerHex(const std::uint64_t addressValue)
    {
        if (addressValue == 0U)
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(addressValue), 16, 16, QChar('0'))
            .toUpper();
    }

    // irpProtocolStatusText: Translate protocol-level status codes into human-readable conclusions.
    QString irpProtocolStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_FILE_IRP_STATUS_OK:
            return QStringLiteral("完成");
        case KSWORD_ARK_FILE_IRP_STATUS_INVALID_REQUEST:
            return QStringLiteral("请求参数被 R0 拒绝");
        case KSWORD_ARK_FILE_IRP_STATUS_OPEN_FAILED:
            return QStringLiteral("目标打开失败");
        case KSWORD_ARK_FILE_IRP_STATUS_LAYER_UNAVAILABLE:
            return QStringLiteral("目标栈层不可用");
        case KSWORD_ARK_FILE_IRP_STATUS_ALLOC_FAILED:
            return QStringLiteral("内核内存不足");
        case KSWORD_ARK_FILE_IRP_STATUS_MAJOR_NOT_ALLOWED:
            return QStringLiteral("该 major 需要额外确认");
        case KSWORD_ARK_FILE_IRP_STATUS_CONFIRMATION_REQUIRED:
            return QStringLiteral("缺少写入确认令牌");
        case KSWORD_ARK_FILE_IRP_STATUS_TIMEOUT:
            return QStringLiteral("等待超时，请求已取消");
        case KSWORD_ARK_FILE_IRP_STATUS_IRP_FAILED:
            return QStringLiteral("IRP 构造失败");
        case KSWORD_ARK_FILE_IRP_STATUS_BUFFER_TOO_SMALL:
            return QStringLiteral("输出缓冲不足");
        case KSWORD_ARK_FILE_IRP_STATUS_DENIED_BY_POLICY:
            return QStringLiteral("被安全策略拒绝");
        default:
            return QStringLiteral("未知状态(%1)").arg(statusValue);
        }
    }

    // Purpose of irpStageText: expand the stage bitmask into a readable list for immediate visibility of which stages actually executed.
    QString irpStageText(const std::uint32_t stageFlags)
    {
        QStringList parts;
        if ((stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CREATE) != 0U)
        {
            parts.append(QStringLiteral("CREATE"));
        }
        if ((stageFlags & KSWORD_ARK_FILE_IRP_STAGE_OPERATION) != 0U)
        {
            parts.append(QStringLiteral("目标请求"));
        }
        if ((stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CLEANUP) != 0U)
        {
            parts.append(QStringLiteral("CLEANUP"));
        }
        if ((stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CLOSE) != 0U)
        {
            parts.append(QStringLiteral("CLOSE"));
        }
        if ((stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CANCELLED) != 0U)
        {
            parts.append(QStringLiteral("已取消"));
        }
        if ((stageFlags & KSWORD_ARK_FILE_IRP_STAGE_OUTPUT_TRUNCATED) != 0U)
        {
            parts.append(QStringLiteral("输出被截断"));
        }
        return parts.isEmpty() ? QStringLiteral("-") : parts.join(QStringLiteral(" / "));
    }

    // irpBuilderInputStyle / irpBuilderButtonStyle purpose:
    // - Themed appearance consistent with the input/button styles of the main FileDock file.
    QString irpBuilderInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QPlainTextEdit,QTextEdit{"
            "  border:1px solid %2;"
            "  border-radius:3px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus,QPlainTextEdit:focus,QTextEdit:focus{"
            "  border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            + ksword_theme::themedComboBoxStyle();
    }

    QString irpBuilderButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }
}

QString FileDock::irpMajorDisplayText(const int majorFunction)
{
    if (majorFunction < 0 ||
        majorFunction >= static_cast<int>(std::size(kIrpMajorNames)))
    {
        return QStringLiteral("0x%1  未知")
            .arg(majorFunction, 2, 16, QChar('0'));
    }
    return QStringLiteral("0x%1  %2")
        .arg(majorFunction, 2, 16, QChar('0'))
        .arg(QString::fromLatin1(kIrpMajorNames[majorFunction]));
}

bool FileDock::parseNumericField(
    const QString& text,
    unsigned long long& valueOut,
    QString& errorTextOut)
{
    valueOut = 0U;
    errorTextOut.clear();

    const QString kTrimmed = text.trimmed();
    if (kTrimmed.isEmpty())
    {
        return true;
    }

    bool convertOk = false;
    if (kTrimmed.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        valueOut = kTrimmed.mid(2).toULongLong(&convertOk, 16);
    }
    else
    {
        valueOut = kTrimmed.toULongLong(&convertOk, 10);
        if (!convertOk)
        {
            // If there is no 0x prefix but hexadecimal characters are present, retry parsing as
            // hexadecimal; users often copy constants from WDK documentation without the prefix.
            valueOut = kTrimmed.toULongLong(&convertOk, 16);
        }
    }
    if (!convertOk)
    {
        errorTextOut = QStringLiteral("无法解析数值: %1").arg(kTrimmed);
        return false;
    }
    return true;
}

bool FileDock::parseHexPayload(
    const QString& text,
    std::vector<std::uint8_t>& bytesOut,
    QString& errorTextOut)
{
    bytesOut.clear();
    errorTextOut.clear();

    QString compact;
    compact.reserve(text.size());
    for (const QChar kCharacter : text)
    {
        if (kCharacter.isSpace() ||
            kCharacter == QChar(',') ||
            kCharacter == QChar('-'))
        {
            continue;
        }
        compact.append(kCharacter);
    }
    if (compact.isEmpty())
    {
        return true;
    }
    if (compact.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        compact = compact.mid(2);
    }
    if ((compact.size() % 2) != 0)
    {
        errorTextOut = QStringLiteral("十六进制输入必须是偶数个字符。");
        return false;
    }

    bytesOut.reserve(static_cast<std::size_t>(compact.size() / 2));
    for (int index = 0; index < compact.size(); index += 2)
    {
        bool convertOk = false;
        const unsigned int kByteValue =
            compact.mid(index, 2).toUInt(&convertOk, 16);
        if (!convertOk)
        {
            errorTextOut = QStringLiteral("十六进制输入含非法字符: %1")
                .arg(compact.mid(index, 2));
            bytesOut.clear();
            return false;
        }
        bytesOut.push_back(static_cast<std::uint8_t>(kByteValue));
    }
    return true;
}

QString FileDock::formatHexDump(const std::vector<std::uint8_t>& data)
{
    if (data.empty())
    {
        return QStringLiteral("(无输出数据)");
    }

    QString dumpText;
    dumpText.reserve(static_cast<int>(data.size() * 4 + 64));
    for (std::size_t offset = 0U; offset < data.size(); offset += 16U)
    {
        QString hexPart;
        QString asciiPart;
        for (std::size_t column = 0U; column < 16U; ++column)
        {
            if (offset + column >= data.size())
            {
                hexPart += QStringLiteral("   ");
                continue;
            }
            const std::uint8_t kByteValue = data[offset + column];
            hexPart += QStringLiteral("%1 ")
                .arg(kByteValue, 2, 16, QChar('0')).toUpper();
            asciiPart += (kByteValue >= 0x20U && kByteValue < 0x7FU)
                ? QChar(static_cast<char>(kByteValue))
                : QChar('.');
        }
        dumpText += QStringLiteral("%1  %2 |%3|\n")
            .arg(static_cast<qulonglong>(offset), 8, 16, QChar('0'))
            .arg(hexPart)
            .arg(asciiPart);
    }
    return dumpText;
}

void FileDock::initializeIrpBuilderPage()
{
    irpBuilderPage_ = new QWidget(rootTabWidget_);
    QVBoxLayout* pageLayout = new QVBoxLayout(irpBuilderPage_);
    pageLayout->setContentsMargins(6, 6, 6, 6);
    pageLayout->setSpacing(6);

    const QString kInputStyle = irpBuilderInputStyle();
    const QString kButtonStyle = irpBuilderButtonStyle();

    // ---------- Target and Request Header ----------
    QGroupBox* targetGroup = new QGroupBox(
        QStringLiteral("目标与请求"),
        irpBuilderPage_);
    QGridLayout* targetLayout = new QGridLayout(targetGroup);
    targetLayout->setContentsMargins(8, 8, 8, 8);
    targetLayout->setHorizontalSpacing(8);
    targetLayout->setVerticalSpacing(6);

    irpPathEdit_ = new QLineEdit(targetGroup);
    irpPathEdit_->setPlaceholderText(
        QStringLiteral("目标路径，例如 C:\\Windows 或 \\??\\C:\\Windows\\notepad.exe"));
    irpPathEdit_->setStyleSheet(kInputStyle);
    irpPathEdit_->setToolTip(QStringLiteral(
        "Win32 路径会自动转换为 \\??\\ 命名空间路径；也可直接填 NT 路径。"));

    irpOperationPresetCombo_ = new QComboBox(targetGroup);
    irpOperationPresetCombo_->setStyleSheet(kInputStyle);
    irpOperationPresetCombo_->addItem(QStringLiteral("自定义（手工参数）"), kIrpPresetCustom);
    irpOperationPresetCombo_->addItem(QStringLiteral("查询文件全部信息"), kIrpPresetQueryAllInformation);
    irpOperationPresetCombo_->addItem(QStringLiteral("读取文件"), kIrpPresetRead);
    irpOperationPresetCombo_->addItem(QStringLiteral("写入文件（填写下方十六进制数据）"), kIrpPresetWrite);
    irpOperationPresetCombo_->addItem(QStringLiteral("刷新文件缓冲"), kIrpPresetFlush);
    irpOperationPresetCombo_->addItem(QStringLiteral("创建空文件"), kIrpPresetCreateFile);
    irpOperationPresetCombo_->addItem(QStringLiteral("创建目录"), kIrpPresetCreateDirectory);
    irpOperationPresetCombo_->addItem(QStringLiteral("枚举目录"), kIrpPresetEnumerateDirectory);
    irpOperationPresetCombo_->addItem(QStringLiteral("删除（FileDispositionInformation）"), kIrpPresetDeleteLegacy);
    irpOperationPresetCombo_->addItem(QStringLiteral("删除（POSIX / FileDispositionInformationEx）"), kIrpPresetDeletePosix);
    irpOperationPresetCombo_->addItem(QStringLiteral("截断为 0 字节"), kIrpPresetTruncateZero);
    irpOperationPresetCombo_->addItem(QStringLiteral("设置基本属性为 NORMAL"), kIrpPresetSetNormalAttributes);
    irpOperationPresetCombo_->addItem(QStringLiteral("查询卷属性"), kIrpPresetQueryVolume);
    irpOperationPresetCombo_->addItem(QStringLiteral("查询安全描述符"), kIrpPresetQuerySecurity);
    irpOperationPresetCombo_->setToolTip(QStringLiteral(
        "选择常用操作后自动填写 Major、访问权、InformationClass 与输入结构。预设只填参数、不自动发送；写操作仍需显式勾选确认。"));

    QPushButton* browseButton = new QPushButton(
        QStringLiteral("浏览..."),
        targetGroup);
    browseButton->setStyleSheet(kButtonStyle);

    irpMajorCombo_ = new QComboBox(targetGroup);
    irpMajorCombo_->setStyleSheet(kInputStyle);
    for (int majorIndex = 0;
         majorIndex < static_cast<int>(std::size(kIrpMajorNames));
         ++majorIndex)
    {
        irpMajorCombo_->addItem(irpMajorDisplayText(majorIndex), majorIndex);
    }
    irpMajorCombo_->setToolTip(QStringLiteral(
        "选择要构造的 IRP 主功能码。参数区会按所选 major 自动启停。"));

    irpMinorEdit_ = new QLineEdit(targetGroup);
    irpMinorEdit_->setStyleSheet(kInputStyle);
    irpMinorEdit_->setPlaceholderText(QStringLiteral("0"));
    irpMinorEdit_->setToolTip(QStringLiteral(
        "IRP_MN_* 次功能码，十进制或 0x 前缀十六进制；不适用时填 0。"));

    irpLayerCombo_ = new QComboBox(targetGroup);
    irpLayerCombo_->setStyleSheet(kInputStyle);
    irpLayerCombo_->addItem(
        QStringLiteral("设备栈顶（等价 Zw* 路径，作为对照基线）"),
        static_cast<unsigned int>(KSWORD_ARK_FILE_IRP_LAYER_RELATED));
    irpLayerCombo_->addItem(
        QStringLiteral("基础文件系统设备（跳过其上的过滤层）"),
        static_cast<unsigned int>(KSWORD_ARK_FILE_IRP_LAYER_BASE_FS));
    irpLayerCombo_->addItem(
        QStringLiteral("VPB 挂载文件系统设备"),
        static_cast<unsigned int>(KSWORD_ARK_FILE_IRP_LAYER_VPB_FS));
    irpLayerCombo_->addItem(
        QStringLiteral("卷设备本身"),
        static_cast<unsigned int>(KSWORD_ARK_FILE_IRP_LAYER_DEVICE));
    irpLayerCombo_->setCurrentIndex(1);
    irpLayerCombo_->setToolTip(QStringLiteral(
        "选择 IRP 投递到设备栈的哪一层。\n"
        "选择非栈顶时，连 IRP_MJ_CREATE 都由 R0 自行构造并直发，不经过过滤层。\n"
        "注意：手工构造的文件对象缺少 I/O 管理器建立的完整关联，NTFS 在后续\n"
        "目录查询等操作上可能回 STATUS_INVALID_PARAMETER，这属于预期现象；\n"
        "只想绕过目录查询请改用文件页的“R0 IRP 解析”读取方式。\n"
        "目标层不可用时 R0 会回退到栈顶，并在结果里如实标出实际生效的层。"));

    irpTimeoutEdit_ = new QLineEdit(targetGroup);
    irpTimeoutEdit_->setStyleSheet(kInputStyle);
    irpTimeoutEdit_->setPlaceholderText(QStringLiteral("10000"));
    irpTimeoutEdit_->setToolTip(QStringLiteral(
        "等待完成的毫秒数，上限 60000；超时后 R0 会取消 IRP 并等待其排空。"));

    int targetRow = 0;
    targetLayout->addWidget(new QLabel(QStringLiteral("常用操作:"), targetGroup), targetRow, 0);
    targetLayout->addWidget(irpOperationPresetCombo_, targetRow, 1, 1, 5);
    ++targetRow;
    targetLayout->addWidget(new QLabel(QStringLiteral("目标路径:"), targetGroup), targetRow, 0);
    targetLayout->addWidget(irpPathEdit_, targetRow, 1, 1, 4);
    targetLayout->addWidget(browseButton, targetRow, 5);
    ++targetRow;
    targetLayout->addWidget(new QLabel(QStringLiteral("MajorFunction:"), targetGroup), targetRow, 0);
    targetLayout->addWidget(irpMajorCombo_, targetRow, 1, 1, 2);
    targetLayout->addWidget(new QLabel(QStringLiteral("MinorFunction:"), targetGroup), targetRow, 3);
    targetLayout->addWidget(irpMinorEdit_, targetRow, 4, 1, 2);
    ++targetRow;
    targetLayout->addWidget(new QLabel(QStringLiteral("目标栈层:"), targetGroup), targetRow, 0);
    targetLayout->addWidget(irpLayerCombo_, targetRow, 1, 1, 2);
    targetLayout->addWidget(new QLabel(QStringLiteral("超时(ms):"), targetGroup), targetRow, 3);
    targetLayout->addWidget(irpTimeoutEdit_, targetRow, 4, 1, 2);
    targetLayout->setColumnStretch(1, 1);
    targetLayout->setColumnStretch(4, 1);
    pageLayout->addWidget(targetGroup, 0);

    // ---------- Parameters Area ----------
    QGroupBox* parameterGroup = new QGroupBox(
        QStringLiteral("IO_STACK_LOCATION 参数"),
        irpBuilderPage_);
    QGridLayout* parameterLayout = new QGridLayout(parameterGroup);
    parameterLayout->setContentsMargins(8, 8, 8, 8);
    parameterLayout->setHorizontalSpacing(8);
    parameterLayout->setVerticalSpacing(6);

    const auto kMakeParameterEdit =
        [&](const QString& placeholderText, const QString& tipText)
        {
            QLineEdit* edit = new QLineEdit(parameterGroup);
            edit->setStyleSheet(kInputStyle);
            edit->setPlaceholderText(placeholderText);
            edit->setToolTip(tipText);
            return edit;
        };

    irpDesiredAccessEdit_ = kMakeParameterEdit(
        QStringLiteral("0x00000080"),
        QStringLiteral("CREATE 阶段 ACCESS_MASK；留空时按只读属性访问打开。"));
    irpShareAccessEdit_ = kMakeParameterEdit(
        QStringLiteral("0x00000007"),
        QStringLiteral("CREATE 阶段共享位；留空时按读/写/删除全共享打开。"));
    irpCreateDispositionEdit_ = kMakeParameterEdit(
        QStringLiteral("1 (FILE_OPEN)"),
        QStringLiteral("CREATE 处置方式：1=FILE_OPEN，2=FILE_CREATE，3=FILE_OPEN_IF 等。"));
    irpCreateOptionsEdit_ = kMakeParameterEdit(
        QStringLiteral("0"),
        QStringLiteral("CREATE 选项位；R0 会额外补上同步与备份语义。"));
    irpFileAttributesEdit_ = kMakeParameterEdit(
        QStringLiteral("0x00000080"),
        QStringLiteral("CREATE 文件属性；留空按 FILE_ATTRIBUTE_NORMAL。"));
    irpInformationClassEdit_ = kMakeParameterEdit(
        QStringLiteral("0"),
        QStringLiteral(
            "信息类：QUERY/SET_INFORMATION 用 FILE_INFORMATION_CLASS，\n"
            "QUERY/SET_VOLUME_INFORMATION 用 FS_INFORMATION_CLASS，\n"
            "DIRECTORY_CONTROL 用目录信息类，POWER 复用为目标电源状态。"));
    irpControlCodeEdit_ = kMakeParameterEdit(
        QStringLiteral("0x00090000"),
        QStringLiteral("DEVICE_CONTROL/FILE_SYSTEM_CONTROL 的控制码，低两位决定缓冲方式。"));
    irpSecurityInformationEdit_ = kMakeParameterEdit(
        QStringLiteral("0"),
        QStringLiteral("QUERY/SET_SECURITY 的 SECURITY_INFORMATION 位。"));
    irpByteOffsetEdit_ = kMakeParameterEdit(
        QStringLiteral("0"),
        QStringLiteral("READ/WRITE/LOCK_CONTROL 的起始字节偏移。"));
    irpLockKeyEdit_ = kMakeParameterEdit(
        QStringLiteral("0"),
        QStringLiteral("READ/WRITE 的 Key，或 LOCK_CONTROL 的锁 Key。"));
    irpLockLengthEdit_ = kMakeParameterEdit(
        QStringLiteral("0"),
        QStringLiteral("LOCK_CONTROL 的加锁字节数。"));
    irpOutputBytesEdit_ = kMakeParameterEdit(
        QStringLiteral("4096"),
        QStringLiteral("期望的输出缓冲长度，上限 256 KiB。"));
    irpPatternEdit_ = kMakeParameterEdit(
        QStringLiteral("*"),
        QStringLiteral("DIRECTORY_CONTROL 的文件名通配符，留空表示不限定。"));

    const auto kAddParameterRow =
        [&](int row, int column, const QString& labelText, QWidget* editWidget)
        {
            parameterLayout->addWidget(
                new QLabel(labelText, parameterGroup), row, column * 2);
            parameterLayout->addWidget(editWidget, row, column * 2 + 1);
        };

    kAddParameterRow(0, 0, QStringLiteral("DesiredAccess:"), irpDesiredAccessEdit_);
    kAddParameterRow(0, 1, QStringLiteral("ShareAccess:"), irpShareAccessEdit_);
    kAddParameterRow(0, 2, QStringLiteral("CreateDisposition:"), irpCreateDispositionEdit_);
    kAddParameterRow(1, 0, QStringLiteral("CreateOptions:"), irpCreateOptionsEdit_);
    kAddParameterRow(1, 1, QStringLiteral("FileAttributes:"), irpFileAttributesEdit_);
    kAddParameterRow(1, 2, QStringLiteral("InformationClass:"), irpInformationClassEdit_);
    kAddParameterRow(2, 0, QStringLiteral("ControlCode:"), irpControlCodeEdit_);
    kAddParameterRow(2, 1, QStringLiteral("SecurityInformation:"), irpSecurityInformationEdit_);
    kAddParameterRow(2, 2, QStringLiteral("ByteOffset:"), irpByteOffsetEdit_);
    kAddParameterRow(3, 0, QStringLiteral("Key:"), irpLockKeyEdit_);
    kAddParameterRow(3, 1, QStringLiteral("LockLength:"), irpLockLengthEdit_);
    kAddParameterRow(3, 2, QStringLiteral("OutputBytes:"), irpOutputBytesEdit_);
    kAddParameterRow(4, 0, QStringLiteral("FileName 通配符:"), irpPatternEdit_);
    for (int column = 0; column < 3; ++column)
    {
        parameterLayout->setColumnStretch(column * 2 + 1, 1);
    }
    pageLayout->addWidget(parameterGroup, 0);

    // ---------- Flags and input data ----------
    QGroupBox* optionGroup = new QGroupBox(
        QStringLiteral("标志与输入数据"),
        irpBuilderPage_);
    QVBoxLayout* optionLayout = new QVBoxLayout(optionGroup);
    optionLayout->setContentsMargins(8, 8, 8, 8);
    optionLayout->setSpacing(6);

    QHBoxLayout* flagLayout = new QHBoxLayout();
    flagLayout->setContentsMargins(0, 0, 0, 0);
    flagLayout->setSpacing(12);

    irpConfirmCheck_ = new QCheckBox(
        QStringLiteral("确认写入语义"),
        optionGroup);
    irpConfirmCheck_->setToolTip(QStringLiteral(
        "写类 major 必须勾选；勾选后客户端才会附带确认令牌，R0 会二次校验。"));

    irpAllowDangerousCheck_ = new QCheckBox(
        QStringLiteral("允许 PnP/电源类请求"),
        optionGroup);
    irpAllowDangerousCheck_->setToolTip(QStringLiteral(
        "IRP_MJ_POWER/PNP/SHUTDOWN/SYSTEM_CONTROL/DEVICE_CHANGE 需要额外勾选。\n"
        "这些请求正常由系统按状态机下发，手工构造可能让目标驱动进入非法状态。"));

    irpCreateOnlyCheck_ = new QCheckBox(
        QStringLiteral("只执行 CREATE"),
        optionGroup);
    irpCreateOnlyCheck_->setToolTip(QStringLiteral(
        "只验证打开阶段，不再下发目标 major，用于单独观察 CREATE 是否被拦截。"));

    irpRestartScanCheck_ = new QCheckBox(
        QStringLiteral("SL_RESTART_SCAN"),
        optionGroup);
    irpSingleEntryCheck_ = new QCheckBox(
        QStringLiteral("SL_RETURN_SINGLE_ENTRY"),
        optionGroup);
    irpReparseCheck_ = new QCheckBox(
        QStringLiteral("FILE_OPEN_REPARSE_POINT"),
        optionGroup);
    irpDirectoryIntentCheck_ = new QCheckBox(
        QStringLiteral("FILE_DIRECTORY_FILE"),
        optionGroup);

    flagLayout->addWidget(irpConfirmCheck_, 0);
    flagLayout->addWidget(irpAllowDangerousCheck_, 0);
    flagLayout->addWidget(irpCreateOnlyCheck_, 0);
    flagLayout->addWidget(irpRestartScanCheck_, 0);
    flagLayout->addWidget(irpSingleEntryCheck_, 0);
    flagLayout->addWidget(irpReparseCheck_, 0);
    flagLayout->addWidget(irpDirectoryIntentCheck_, 0);
    flagLayout->addStretch(1);
    optionLayout->addLayout(flagLayout, 0);

    irpInputHexEdit_ = new QPlainTextEdit(optionGroup);
    irpInputHexEdit_->setStyleSheet(kInputStyle);
    irpInputHexEdit_->setPlaceholderText(
        QStringLiteral("内联输入数据，十六进制，例如 01 00 00 00；留空表示无输入。"));
    irpInputHexEdit_->setMaximumHeight(80);
    irpInputHexEdit_->setToolTip(QStringLiteral(
        "作为 IRP 数据段的输入内容，上限 64 KiB。\n"
        "空白、逗号和短横线会被忽略，方便直接粘贴各种转储格式。"));
    optionLayout->addWidget(irpInputHexEdit_, 0);
    pageLayout->addWidget(optionGroup, 0);

    // ---------- Send and Result ----------
    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(8);

    irpSendButton_ = new QPushButton(
        QStringLiteral("构造并发送 IRP"),
        irpBuilderPage_);
    irpSendButton_->setStyleSheet(kButtonStyle);
    irpSendButton_->setMinimumHeight(30);

    irpStatusLabel_ = new QLabel(
        QStringLiteral("尚未发送。写类与 PnP/电源类请求需要先勾选对应确认项。"),
        irpBuilderPage_);
    irpStatusLabel_->setWordWrap(true);

    actionLayout->addWidget(irpSendButton_, 0);
    actionLayout->addWidget(irpStatusLabel_, 1);
    pageLayout->addLayout(actionLayout, 0);

    QSplitter* resultSplitter = new QSplitter(Qt::Horizontal, irpBuilderPage_);
    resultSplitter->setChildrenCollapsible(false);

    irpResultTable_ = new ks::ui::VisibleTableWidget(resultSplitter);
    irpResultTable_->setColumnCount(2);
    irpResultTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("项目"),
        QStringLiteral("值") });
    irpResultTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    irpResultTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    irpResultTable_->verticalHeader()->setVisible(false);
    irpResultTable_->horizontalHeader()->setStretchLastSection(true);
    irpResultTable_->setAlternatingRowColors(true);

    irpOutputHexEdit_ = new QPlainTextEdit(resultSplitter);
    irpOutputHexEdit_->setStyleSheet(kInputStyle);
    irpOutputHexEdit_->setReadOnly(true);
    irpOutputHexEdit_->setPlaceholderText(
        QStringLiteral("目标驱动写回的数据将以十六进制转储显示。"));

    resultSplitter->addWidget(irpResultTable_);
    resultSplitter->addWidget(irpOutputHexEdit_);
    resultSplitter->setStretchFactor(0, 1);
    resultSplitter->setStretchFactor(1, 1);
    pageLayout->addWidget(resultSplitter, 1);

    connect(browseButton, &QPushButton::clicked, this, [this]() {
        const QString kSelectedPath = QFileDialog::getOpenFileName(
            this,
            QStringLiteral("选择 IRP 目标文件"),
            irpPathEdit_->text().trimmed());
        if (!kSelectedPath.isEmpty())
        {
            irpPathEdit_->setText(QDir::toNativeSeparators(kSelectedPath));
        }
    });
    connect(irpOperationPresetCombo_, &QComboBox::currentIndexChanged, this, [this](int) {
        applyIrpOperationPreset(irpOperationPresetCombo_->currentData().toInt());
    });
    connect(irpMajorCombo_, &QComboBox::currentIndexChanged, this, [this](int) {
        applyIrpMajorPreset(irpMajorCombo_->currentData().toInt());
        if (irpOperationPresetCombo_ != nullptr &&
            irpOperationPresetCombo_->currentData().toInt() != kIrpPresetCustom)
        {
            const QSignalBlocker kBlocker(irpOperationPresetCombo_);
            irpOperationPresetCombo_->setCurrentIndex(0);
        }
    });
    connect(irpSendButton_, &QPushButton::clicked, this, [this]() {
        submitConstructedIrp();
    });

    applyIrpMajorPreset(0);
}

void FileDock::applyIrpOperationPreset(const int presetId)
{
    // Custom mode only clears the preset flag, without clearing user parameters currently being edited.
    if (presetId == kIrpPresetCustom || irpMajorCombo_ == nullptr)
    {
        return;
    }

    const auto kSetEditText = [](QLineEdit* edit, const QString& text) {
        if (edit != nullptr)
        {
            edit->setText(text);
        }
    };
    const auto kSelectMajor = [this](const int majorFunction) {
        const QSignalBlocker kBlocker(irpMajorCombo_);
        const int kComboIndex = irpMajorCombo_->findData(majorFunction);
        if (kComboIndex >= 0)
        {
            irpMajorCombo_->setCurrentIndex(kComboIndex);
        }
        applyIrpMajorPreset(majorFunction);
    };

    // First restore a conservative, auditable CREATE baseline, then override based on specific actions. All presets enter from the
    // RELATED stack top; users can still actively switch to BASE_FS/VPB/DEVICE after filling parameters for differential experiments.
    kSetEditText(irpMinorEdit_, QStringLiteral("0"));
    kSetEditText(irpDesiredAccessEdit_, QStringLiteral("0x00100080"));
    kSetEditText(irpShareAccessEdit_, QStringLiteral("0x00000007"));
    kSetEditText(irpCreateDispositionEdit_, QStringLiteral("1"));
    kSetEditText(irpCreateOptionsEdit_, QStringLiteral("0x00000040"));
    kSetEditText(irpFileAttributesEdit_, QStringLiteral("0x00000080"));
    kSetEditText(irpInformationClassEdit_, QStringLiteral("0"));
    kSetEditText(irpControlCodeEdit_, QStringLiteral("0"));
    kSetEditText(irpSecurityInformationEdit_, QStringLiteral("0"));
    kSetEditText(irpByteOffsetEdit_, QStringLiteral("0"));
    kSetEditText(irpLockKeyEdit_, QStringLiteral("0"));
    kSetEditText(irpLockLengthEdit_, QStringLiteral("0"));
    kSetEditText(irpOutputBytesEdit_, QStringLiteral("0"));
    kSetEditText(irpTimeoutEdit_, QStringLiteral("10000"));
    kSetEditText(irpPatternEdit_, QString());
    if (irpInputHexEdit_ != nullptr)
    {
        irpInputHexEdit_->clear();
    }
    if (irpLayerCombo_ != nullptr)
    {
        const int kRelatedIndex = irpLayerCombo_->findData(
            static_cast<unsigned int>(KSWORD_ARK_FILE_IRP_LAYER_RELATED));
        if (kRelatedIndex >= 0)
        {
            irpLayerCombo_->setCurrentIndex(kRelatedIndex);
        }
    }
    irpConfirmCheck_->setChecked(false);
    irpAllowDangerousCheck_->setChecked(false);
    irpCreateOnlyCheck_->setChecked(false);
    irpRestartScanCheck_->setChecked(false);
    irpSingleEntryCheck_->setChecked(false);
    irpReparseCheck_->setChecked(true);
    irpDirectoryIntentCheck_->setChecked(false);

    QString presetHintText;
    switch (presetId)
    {
    case kIrpPresetQueryAllInformation:
        kSelectMajor(5); // IRP_MJ_QUERY_INFORMATION
        kSetEditText(irpInformationClassEdit_, QStringLiteral("18")); // FileAllInformation
        kSetEditText(irpOutputBytesEdit_, QStringLiteral("4096"));
        presetHintText = QStringLiteral("已填入查询 FileAllInformation 的安全栈顶预设。");
        break;
    case kIrpPresetRead:
        kSelectMajor(3); // IRP_MJ_READ
        kSetEditText(irpDesiredAccessEdit_, QStringLiteral("0x00100001"));
        kSetEditText(irpOutputBytesEdit_, QStringLiteral("4096"));
        presetHintText = QStringLiteral("已填入从偏移 0 读取 4096 字节的预设，可修改偏移与长度。");
        break;
    case kIrpPresetWrite:
        kSelectMajor(4); // IRP_MJ_WRITE
        kSetEditText(irpDesiredAccessEdit_, QStringLiteral("0x00100002"));
        presetHintText = QStringLiteral("已填入写入预设；请在下方填写十六进制数据，并勾选写入确认。");
        break;
    case kIrpPresetFlush:
        kSelectMajor(9); // IRP_MJ_FLUSH_BUFFERS
        kSetEditText(irpDesiredAccessEdit_, QStringLiteral("0x00100002"));
        presetHintText = QStringLiteral("已填入刷新文件缓冲预设。");
        break;
    case kIrpPresetCreateFile:
        kSelectMajor(0); // IRP_MJ_CREATE
        kSetEditText(irpDesiredAccessEdit_, QStringLiteral("0x00100182"));
        kSetEditText(irpCreateDispositionEdit_, QStringLiteral("2")); // FILE_CREATE
        irpReparseCheck_->setChecked(false);
        presetHintText = QStringLiteral("已填入 FILE_CREATE 空文件预设；目标必须不存在，并需勾选写入确认。");
        break;
    case kIrpPresetCreateDirectory:
        kSelectMajor(0); // IRP_MJ_CREATE
        kSetEditText(irpDesiredAccessEdit_, QStringLiteral("0x00100181"));
        kSetEditText(irpCreateDispositionEdit_, QStringLiteral("2")); // FILE_CREATE
        kSetEditText(irpCreateOptionsEdit_, QStringLiteral("0"));
        irpReparseCheck_->setChecked(false);
        irpDirectoryIntentCheck_->setChecked(true);
        presetHintText = QStringLiteral("已填入 FILE_CREATE 目录预设；目标必须不存在，并需勾选写入确认。");
        break;
    case kIrpPresetEnumerateDirectory:
        kSelectMajor(12); // IRP_MJ_DIRECTORY_CONTROL
        kSetEditText(irpMinorEdit_, QStringLiteral("1")); // IRP_MN_QUERY_DIRECTORY
        kSetEditText(irpDesiredAccessEdit_, QStringLiteral("0x00100081"));
        kSetEditText(irpCreateOptionsEdit_, QStringLiteral("0"));
        kSetEditText(irpInformationClassEdit_, QStringLiteral("37")); // FileIdBothDirectoryInformation
        kSetEditText(irpOutputBytesEdit_, QStringLiteral("65536"));
        kSetEditText(irpPatternEdit_, QStringLiteral("*"));
        irpRestartScanCheck_->setChecked(true);
        irpDirectoryIntentCheck_->setChecked(true);
        presetHintText = QStringLiteral("已填入 FileIdBothDirectoryInformation 目录枚举预设。");
        break;
    case kIrpPresetDeleteLegacy:
        kSelectMajor(6); // IRP_MJ_SET_INFORMATION
        kSetEditText(irpDesiredAccessEdit_, QStringLiteral("0x00110000"));
        kSetEditText(irpInformationClassEdit_, QStringLiteral("13")); // FileDispositionInformation
        irpInputHexEdit_->setPlainText(QStringLiteral("01")); // BOOLEAN DeleteFile
        presetHintText = QStringLiteral("已填入传统 IRP 删除预设；目录目标需另勾 FILE_DIRECTORY_FILE，并需写入确认。");
        break;
    case kIrpPresetDeletePosix:
        kSelectMajor(6); // IRP_MJ_SET_INFORMATION
        kSetEditText(irpDesiredAccessEdit_, QStringLiteral("0x00110000"));
        kSetEditText(irpInformationClassEdit_, QStringLiteral("64")); // FileDispositionInformationEx
        // DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE
        irpInputHexEdit_->setPlainText(QStringLiteral("13 00 00 00"));
        presetHintText = QStringLiteral("已填入 IRP POSIX 删除预设；支持情况取决于系统与文件系统，并需写入确认。");
        break;
    case kIrpPresetTruncateZero:
        kSelectMajor(6); // IRP_MJ_SET_INFORMATION
        kSetEditText(irpDesiredAccessEdit_, QStringLiteral("0x00100002"));
        kSetEditText(irpInformationClassEdit_, QStringLiteral("20")); // FileEndOfFileInformation
        irpInputHexEdit_->setPlainText(QStringLiteral("00 00 00 00 00 00 00 00"));
        presetHintText = QStringLiteral("已填入 FileEndOfFileInformation 截断到 0 字节预设，并需写入确认。");
        break;
    case kIrpPresetSetNormalAttributes:
        kSelectMajor(6); // IRP_MJ_SET_INFORMATION
        kSetEditText(irpDesiredAccessEdit_, QStringLiteral("0x00100100"));
        kSetEditText(irpInformationClassEdit_, QStringLiteral("4")); // FileBasicInformation
        // Keep four timestamps at 0 (unchanged), FileAttributes=FILE_ATTRIBUTE_NORMAL, and align the end to x64.
        irpInputHexEdit_->setPlainText(QStringLiteral(
            "00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00\n"
            "00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00\n"
            "80 00 00 00 00 00 00 00"));
        presetHintText = QStringLiteral("已填入 FileBasicInformation 的 NORMAL 属性模板，并需写入确认。");
        break;
    case kIrpPresetQueryVolume:
        kSelectMajor(10); // IRP_MJ_QUERY_VOLUME_INFORMATION
        kSetEditText(irpInformationClassEdit_, QStringLiteral("5")); // FileFsAttributeInformation
        kSetEditText(irpOutputBytesEdit_, QStringLiteral("1024"));
        presetHintText = QStringLiteral("已填入 FileFsAttributeInformation 卷属性查询预设。");
        break;
    case kIrpPresetQuerySecurity:
        kSelectMajor(20); // IRP_MJ_QUERY_SECURITY
        kSetEditText(irpDesiredAccessEdit_, QStringLiteral("0x00120080"));
        kSetEditText(irpSecurityInformationEdit_, QStringLiteral("0x00000007"));
        kSetEditText(irpOutputBytesEdit_, QStringLiteral("4096"));
        presetHintText = QStringLiteral("已填入所有者、组与 DACL 安全描述符查询预设。");
        break;
    default:
        return;
    }

    if (irpStatusLabel_ != nullptr)
    {
        irpStatusLabel_->setText(presetHintText);
    }
}

void FileDock::applyIrpMajorPreset(const int majorFunction)
{
    if (irpMajorCombo_ == nullptr)
    {
        return;
    }

    // Enable only the fields defined for each major function. Disable rather than clear them so that when the user switches back, they can still
    // see the previously entered values; upon submission, only enabled fields are read, and residual values in disabled fields are not sent.
    const bool kIsCreateLike = (majorFunction == 0 || majorFunction == 1 || majorFunction == 19);
    const bool kIsReadWrite = (majorFunction == 3 || majorFunction == 4);
    const bool kIsFileInfo = (majorFunction == 5 || majorFunction == 6);
    const bool kIsEa = (majorFunction == 7 || majorFunction == 8);
    const bool kIsVolumeInfo = (majorFunction == 10 || majorFunction == 11);
    const bool kIsDirectory = (majorFunction == 12);
    const bool kIsControlCode = (majorFunction == 13 || majorFunction == 14 || majorFunction == 15);
    const bool kIsLock = (majorFunction == 17);
    const bool kIsSecurity = (majorFunction == 20 || majorFunction == 21);
    const bool kIsQuota = (majorFunction == 25 || majorFunction == 26);
    const bool kIsPower = (majorFunction == 22);

    // CREATE parameters are meaningful for each major: the target must be opened first before subsequent requests can be issued.
    irpDesiredAccessEdit_->setEnabled(true);
    irpShareAccessEdit_->setEnabled(true);
    irpCreateDispositionEdit_->setEnabled(true);
    irpCreateOptionsEdit_->setEnabled(true);
    irpFileAttributesEdit_->setEnabled(true);
    irpReparseCheck_->setEnabled(true);
    irpDirectoryIntentCheck_->setEnabled(true);

    irpInformationClassEdit_->setEnabled(
        kIsFileInfo || kIsVolumeInfo || kIsDirectory || kIsPower);
    irpControlCodeEdit_->setEnabled(kIsControlCode);
    irpSecurityInformationEdit_->setEnabled(kIsSecurity);
    irpByteOffsetEdit_->setEnabled(kIsReadWrite || kIsLock);
    irpLockKeyEdit_->setEnabled(kIsReadWrite || kIsLock);
    irpLockLengthEdit_->setEnabled(kIsLock);
    irpPatternEdit_->setEnabled(kIsDirectory);
    irpRestartScanCheck_->setEnabled(kIsDirectory);
    irpSingleEntryCheck_->setEnabled(kIsDirectory);
    irpOutputBytesEdit_->setEnabled(
        kIsReadWrite || kIsFileInfo || kIsEa || kIsVolumeInfo || kIsDirectory ||
        kIsControlCode || kIsSecurity || kIsQuota);
    irpInputHexEdit_->setEnabled(
        kIsReadWrite || kIsFileInfo || kIsEa || kIsVolumeInfo || kIsControlCode ||
        kIsSecurity || kIsQuota);
    irpCreateOnlyCheck_->setEnabled(!kIsCreateLike);
    irpMinorEdit_->setEnabled(!kIsCreateLike);

    // Common default value: only fill if the field is currently empty to avoid overwriting user input.
    const auto kSetDefaultIfEmpty =
        [](QLineEdit* edit, const QString& defaultText)
        {
            if (edit != nullptr && edit->text().trimmed().isEmpty())
            {
                edit->setText(defaultText);
            }
        };

    if (kIsDirectory)
    {
        // Defaults to FileIdBothDirectoryInformation (37) + QUERY_DIRECTORY (1), using the same
        // information class as the R0 directory enumeration chain for easy line-by-line comparison.
        kSetDefaultIfEmpty(irpInformationClassEdit_, QStringLiteral("37"));
        kSetDefaultIfEmpty(irpMinorEdit_, QStringLiteral("1"));
        kSetDefaultIfEmpty(irpOutputBytesEdit_, QStringLiteral("65536"));
        irpDirectoryIntentCheck_->setChecked(true);
    }
    else if (kIsFileInfo)
    {
        // FileAllInformation (18) is the most commonly used information class for investigating file object status.
        kSetDefaultIfEmpty(irpInformationClassEdit_, QStringLiteral("18"));
        kSetDefaultIfEmpty(irpOutputBytesEdit_, QStringLiteral("4096"));
    }
    else if (kIsVolumeInfo)
    {
        // FileFsAttributeInformation(5)。
        kSetDefaultIfEmpty(irpInformationClassEdit_, QStringLiteral("5"));
        kSetDefaultIfEmpty(irpOutputBytesEdit_, QStringLiteral("1024"));
    }
    else if (kIsReadWrite)
    {
        kSetDefaultIfEmpty(irpOutputBytesEdit_, QStringLiteral("4096"));
    }

    // Write semantics and dangerous major function requirements are directly reflected in the UI prompt.
    const bool kWriteLike = majorIsWriteLike(majorFunction);
    const bool kDangerous = majorIsDangerous(majorFunction);
    // During the CREATE phase, disposition/options may also cause 'query-type major' to create or delete the target, so the confirmation
    // item is always actionable; whether it is mandatory is determined by the pre-submission pre-check and a dual R0 judgment.
    irpConfirmCheck_->setEnabled(true);
    irpAllowDangerousCheck_->setEnabled(kDangerous);
    if (!kWriteLike && !kDangerous)
    {
        irpConfirmCheck_->setChecked(false);
    }
    if (!kDangerous)
    {
        irpAllowDangerousCheck_->setChecked(false);
    }

    if (irpStatusLabel_ != nullptr)
    {
        if (kDangerous)
        {
            irpStatusLabel_->setText(QStringLiteral(
                "%1 由 PnP/电源管理器按状态机下发，手工构造可能让目标驱动进入非法状态；"
                "需要同时勾选写入确认与 PnP/电源允许项。")
                .arg(irpMajorDisplayText(majorFunction)));
        }
        else if (kWriteLike)
        {
            irpStatusLabel_->setText(QStringLiteral(
                "%1 属于写语义，会改变磁盘或设备状态；需要勾选写入确认。")
                .arg(irpMajorDisplayText(majorFunction)));
        }
        else
        {
            irpStatusLabel_->setText(QStringLiteral(
                "%1 为只读语义，可直接发送。")
                .arg(irpMajorDisplayText(majorFunction)));
        }
    }
}

void FileDock::updateIrpBuilderEnabledState(const bool submitting)
{
    irpSubmitInProgress_ = submitting;
    if (irpSendButton_ != nullptr)
    {
        irpSendButton_->setEnabled(!submitting);
        irpSendButton_->setText(submitting
            ? QStringLiteral("正在发送...")
            : QStringLiteral("构造并发送 IRP"));
    }
    if (irpMajorCombo_ != nullptr)
    {
        irpMajorCombo_->setEnabled(!submitting);
    }
    if (irpOperationPresetCombo_ != nullptr)
    {
        irpOperationPresetCombo_->setEnabled(!submitting);
    }
    if (irpLayerCombo_ != nullptr)
    {
        irpLayerCombo_->setEnabled(!submitting);
    }
    if (irpPathEdit_ != nullptr)
    {
        irpPathEdit_->setEnabled(!submitting);
    }
}

void FileDock::submitConstructedIrp()
{
    if (irpSubmitInProgress_)
    {
        return;
    }
    if (irpPathEdit_ == nullptr || irpMajorCombo_ == nullptr)
    {
        return;
    }

    const QString kRawPath = irpPathEdit_->text().trimmed();
    if (kRawPath.isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("IRP 构造"),
            QStringLiteral("请先填写目标路径。"));
        return;
    }

    const int kMajorFunction = irpMajorCombo_->currentData().toInt();
    unsigned long long createDispositionPreview = 0U;
    unsigned long long createOptionsPreview = 0U;
    QString previewErrorText;
    if (irpCreateDispositionEdit_ != nullptr)
    {
        (void)parseNumericField(
            irpCreateDispositionEdit_->text().trimmed().section(QChar(' '), 0, 0),
            createDispositionPreview,
            previewErrorText);
    }
    previewErrorText.clear();
    if (irpCreateOptionsEdit_ != nullptr)
    {
        (void)parseNumericField(
            irpCreateOptionsEdit_->text().trimmed().section(QChar(' '), 0, 0),
            createOptionsPreview,
            previewErrorText);
    }
    const bool kCreateStageMutates =
        (createDispositionPreview >= 2U && createDispositionPreview <= 5U) ||
        ((createOptionsPreview & 0x00001000ULL) != 0U); // FILE_DELETE_ON_CLOSE
    const bool kWriteLike = majorIsWriteLike(kMajorFunction) || kCreateStageMutates;
    const bool kDangerous = majorIsDangerous(kMajorFunction);
    if ((kWriteLike || kDangerous) && !irpConfirmCheck_->isChecked())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("IRP 构造"),
            QStringLiteral("%1 会改变磁盘或设备状态，请先勾选“确认写入语义”。")
                .arg(irpMajorDisplayText(kMajorFunction)));
        return;
    }
    if (kDangerous && !irpAllowDangerousCheck_->isChecked())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("IRP 构造"),
            QStringLiteral("%1 需要同时勾选“允许 PnP/电源类请求”。")
                .arg(irpMajorDisplayText(kMajorFunction)));
        return;
    }
    if (kDangerous)
    {
        const auto kAnswer = QMessageBox::question(
            this,
            QStringLiteral("IRP 构造"),
            QStringLiteral(
                "即将向文件系统栈手工投递 %1。\n\n"
                "这类请求正常只由 PnP/电源管理器按状态机下发，"
                "手工构造可能让目标驱动进入非法状态甚至触发系统崩溃。\n\n"
                "确认继续？")
                .arg(irpMajorDisplayText(kMajorFunction)),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kAnswer != QMessageBox::Yes)
        {
            return;
        }
    }

    // Parse field by field. If any field fails to parse, abort immediately without falling back
    // to 0. Treating a typo in a control code as 0 is far more dangerous than reporting an error.
    struct FieldSpec
    {
        QLineEdit* edit;
        const char* name;
        unsigned long long* target;
    };
    unsigned long long minorValue = 0U;
    unsigned long long desiredAccess = 0U;
    unsigned long long shareAccess = 0U;
    unsigned long long createDisposition = 0U;
    unsigned long long createOptions = 0U;
    unsigned long long fileAttributes = 0U;
    unsigned long long informationClass = 0U;
    unsigned long long controlCode = 0U;
    unsigned long long securityInformation = 0U;
    unsigned long long byteOffset = 0U;
    unsigned long long lockKey = 0U;
    unsigned long long lockLength = 0U;
    unsigned long long outputBytes = 0U;
    unsigned long long timeoutMs = 0U;

    const FieldSpec kFieldSpecs[] = {
        { irpMinorEdit_, "MinorFunction", &minorValue },
        { irpDesiredAccessEdit_, "DesiredAccess", &desiredAccess },
        { irpShareAccessEdit_, "ShareAccess", &shareAccess },
        { irpCreateDispositionEdit_, "CreateDisposition", &createDisposition },
        { irpCreateOptionsEdit_, "CreateOptions", &createOptions },
        { irpFileAttributesEdit_, "FileAttributes", &fileAttributes },
        { irpInformationClassEdit_, "InformationClass", &informationClass },
        { irpControlCodeEdit_, "ControlCode", &controlCode },
        { irpSecurityInformationEdit_, "SecurityInformation", &securityInformation },
        { irpByteOffsetEdit_, "ByteOffset", &byteOffset },
        { irpLockKeyEdit_, "Key", &lockKey },
        { irpLockLengthEdit_, "LockLength", &lockLength },
        { irpOutputBytesEdit_, "OutputBytes", &outputBytes },
        { irpTimeoutEdit_, "Timeout", &timeoutMs }
    };
    for (const FieldSpec& spec : kFieldSpecs)
    {
        if (spec.edit == nullptr || !spec.edit->isEnabled())
        {
            continue;
        }
        QString parseErrorText;
        // The placeholder text for CreateDisposition includes a descriptive suffix; extract the numeric portion before the first whitespace.
        const QString kFieldText = spec.edit->text().trimmed().section(QChar(' '), 0, 0);
        if (!parseNumericField(kFieldText, *spec.target, parseErrorText))
        {
            QMessageBox::warning(
                this,
                QStringLiteral("IRP 构造"),
                QStringLiteral("字段 %1 解析失败：%2")
                    .arg(QString::fromLatin1(spec.name))
                    .arg(parseErrorText));
            return;
        }
    }

    std::vector<std::uint8_t> inputBytes;
    if (irpInputHexEdit_ != nullptr && irpInputHexEdit_->isEnabled())
    {
        QString payloadErrorText;
        if (!parseHexPayload(
                irpInputHexEdit_->toPlainText(),
                inputBytes,
                payloadErrorText))
        {
            QMessageBox::warning(
                this,
                QStringLiteral("IRP 构造"),
                QStringLiteral("输入数据解析失败：%1").arg(payloadErrorText));
            return;
        }
    }
    if (inputBytes.size() > KSWORD_ARK_FILE_IRP_MAX_INPUT_BYTES)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("IRP 构造"),
            QStringLiteral("输入数据超出上限 %1 字节。")
                .arg(static_cast<qulonglong>(KSWORD_ARK_FILE_IRP_MAX_INPUT_BYTES)));
        return;
    }
    if (outputBytes > KSWORD_ARK_FILE_IRP_MAX_OUTPUT_BYTES)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("IRP 构造"),
            QStringLiteral("输出缓冲超出上限 %1 字节。")
                .arg(static_cast<qulonglong>(KSWORD_ARK_FILE_IRP_MAX_OUTPUT_BYTES)));
        return;
    }

    // Path normalization: uses the same Win32 → NT conversion rules as other R0 entry points.
    QString ntPath = QDir::toNativeSeparators(kRawPath);
    if (!ntPath.startsWith(QStringLiteral("\\??\\")) &&
        !ntPath.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
    {
        if (ntPath.startsWith(QStringLiteral("\\\\?\\UNC\\"), Qt::CaseInsensitive))
        {
            ntPath = QStringLiteral("\\??\\UNC\\") + ntPath.mid(8);
        }
        else if (ntPath.startsWith(QStringLiteral("\\\\?\\")))
        {
            ntPath = QStringLiteral("\\??\\") + ntPath.mid(4);
        }
        else if (ntPath.startsWith(QStringLiteral("\\\\")))
        {
            ntPath = QStringLiteral("\\??\\UNC\\") + ntPath.mid(2);
        }
        else
        {
            ntPath = QStringLiteral("\\??\\") + ntPath;
        }
    }

    ksword::ark::FileIrpSubmitRequestParams params;
    params.ntPath = ntPath.toStdWString();
    params.pattern = (irpPatternEdit_ != nullptr && irpPatternEdit_->isEnabled())
        ? irpPatternEdit_->text().trimmed().toStdWString()
        : std::wstring();
    params.majorFunction = static_cast<std::uint32_t>(kMajorFunction);
    params.minorFunction = static_cast<std::uint32_t>(minorValue);
    params.targetLayer = irpLayerCombo_->currentData().toUInt();
    params.timeoutMs = static_cast<std::uint32_t>(timeoutMs);
    params.desiredAccess = static_cast<std::uint32_t>(desiredAccess);
    params.shareAccess = static_cast<std::uint32_t>(shareAccess);
    params.createDisposition = static_cast<std::uint32_t>(createDisposition);
    params.createOptions = static_cast<std::uint32_t>(createOptions);
    params.fileAttributes = static_cast<std::uint32_t>(fileAttributes);
    params.informationClass = static_cast<std::uint32_t>(informationClass);
    params.controlCode = static_cast<std::uint32_t>(controlCode);
    params.securityInformation = static_cast<std::uint32_t>(securityInformation);
    params.lockKey = static_cast<std::uint32_t>(lockKey);
    params.outputBytes = static_cast<std::uint32_t>(outputBytes);
    params.byteOffset = byteOffset;
    params.lockLength = lockLength;
    params.inputData = inputBytes;
    params.uiConfirmed = irpConfirmCheck_->isChecked();
    params.allowDangerous = irpAllowDangerousCheck_->isChecked();
    if (irpCreateOnlyCheck_->isEnabled() && irpCreateOnlyCheck_->isChecked())
    {
        params.flags |= KSWORD_ARK_FILE_IRP_FLAG_CREATE_ONLY;
    }
    if (irpRestartScanCheck_->isEnabled() && irpRestartScanCheck_->isChecked())
    {
        params.flags |= KSWORD_ARK_FILE_IRP_FLAG_RESTART_SCAN;
    }
    if (irpSingleEntryCheck_->isEnabled() && irpSingleEntryCheck_->isChecked())
    {
        params.flags |= KSWORD_ARK_FILE_IRP_FLAG_RETURN_SINGLE_ENTRY;
    }
    if (irpReparseCheck_->isEnabled() && irpReparseCheck_->isChecked())
    {
        params.flags |= KSWORD_ARK_FILE_IRP_FLAG_OPEN_REPARSE_POINT;
    }
    if (irpDirectoryIntentCheck_->isEnabled() && irpDirectoryIntentCheck_->isChecked())
    {
        params.flags |= KSWORD_ARK_FILE_IRP_FLAG_DIRECTORY_INTENT;
    }

    {
        KLogEvent event;
        info << event
            << "[FileDock] 提交自建 IRP, major="
            << kMajorFunction
            << ", minor="
            << static_cast<qulonglong>(minorValue)
            << ", layer="
            << params.targetLayer
            << ", inputBytes="
            << static_cast<qulonglong>(inputBytes.size())
            << ", outputBytes="
            << static_cast<qulonglong>(outputBytes)
            << ", path="
            << ntPath.toStdString()
            << eol;
    }

    updateIrpBuilderEnabledState(true);
    irpStatusLabel_->setText(QStringLiteral("正在向 R0 提交 %1 ...")
        .arg(irpMajorDisplayText(kMajorFunction)));

    const int kProgressPid = kPro.add(this, "文件", "IRP 构造提交");
    kPro.set(kProgressPid, "提交内核请求", 0, 20.0f);

    QPointer<FileDock> safeThis(this);
    std::thread([safeThis, params, kProgressPid, kMajorFunction, ntPath]() {
        const ksword::ark::FileIrpSubmitResult kResult =
            ksword::ark::DriverClient().submitFileIrp(params);

        kPro.set(kProgressPid, "整理结果", 0, 80.0f);
        if (safeThis.isNull())
        {
            kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
            return;
        }

        QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, kResult, kProgressPid, kMajorFunction, ntPath]() {
                if (safeThis.isNull())
                {
                    kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                safeThis->updateIrpBuilderEnabledState(false);
                QTableWidget* table = safeThis->irpResultTable_;
                table->setRowCount(0);

                const auto kAppendRow =
                    [table](const QString& nameText, const QString& valueText)
                    {
                        const int kRow = table->rowCount();
                        table->insertRow(kRow);
                        table->setItem(kRow, 0, new QTableWidgetItem(nameText));
                        table->setItem(kRow, 1, new QTableWidgetItem(valueText));
                    };

                if (!kResult.io.ok)
                {
                    const QString kFailureText = kResult.unsupported
                        ? QStringLiteral(
                            "当前 KswordARK 驱动不支持自建 IRP 提交，请重新部署本次构建的驱动。")
                        : QStringLiteral("R0 通信失败：Win32=%1；%2")
                            .arg(kResult.io.win32Error)
                            .arg(QString::fromStdString(kResult.io.message));
                    safeThis->irpStatusLabel_->setText(kFailureText);
                    kAppendRow(QStringLiteral("通信结果"), QStringLiteral("失败"));
                    kAppendRow(QStringLiteral("Win32 错误"),
                        QString::number(kResult.io.win32Error));
                    kAppendRow(QStringLiteral("诊断"),
                        QString::fromStdString(kResult.io.message));
                    safeThis->irpOutputHexEdit_->setPlainText(
                        FileDock::formatHexDump({}));
                    kPro.set(kProgressPid, "提交失败", 0, 100.0f);
                    return;
                }

                kAppendRow(QStringLiteral("协议状态"),
                    irpProtocolStatusText(kResult.status));
                kAppendRow(QStringLiteral("执行阶段"),
                    irpStageText(kResult.stageFlags));
                kAppendRow(QStringLiteral("MajorFunction"),
                    FileDock::irpMajorDisplayText(
                        static_cast<int>(kResult.majorFunction)));
                kAppendRow(QStringLiteral("MinorFunction"),
                    QStringLiteral("0x%1").arg(kResult.minorFunction, 2, 16, QChar('0')));
                kAppendRow(QStringLiteral("请求栈层"),
                    ks::file::IrpFileSystemParser::layerDisplayText(kResult.requestedLayer));
                kAppendRow(QStringLiteral("实际栈层"),
                    ks::file::IrpFileSystemParser::layerDisplayText(kResult.resolvedLayer));
                if (kResult.requestedLayer != kResult.resolvedLayer)
                {
                    kAppendRow(QStringLiteral("栈层提示"),
                        QStringLiteral("目标层不可用，R0 已回退到栈顶，本次未绕过过滤层"));
                }
                kAppendRow(QStringLiteral("CREATE 状态"), statusHex(kResult.createStatus));
                kAppendRow(QStringLiteral("目标请求状态"), statusHex(kResult.operationStatus));
                kAppendRow(QStringLiteral("CLEANUP 状态"), statusHex(kResult.cleanupStatus));
                kAppendRow(QStringLiteral("CLOSE 状态"), statusHex(kResult.closeStatus));
                kAppendRow(QStringLiteral("Information"),
                    QStringLiteral("%1 (0x%2)")
                        .arg(static_cast<qulonglong>(kResult.information))
                        .arg(static_cast<qulonglong>(kResult.information), 0, 16));
                kAppendRow(QStringLiteral("输出字节数"),
                    QString::number(kResult.outputData.size()));
                kAppendRow(QStringLiteral("接收驱动"),
                    kResult.driverName.empty()
                        ? QStringLiteral("-")
                        : QString::fromStdWString(kResult.driverName));
                kAppendRow(QStringLiteral("接收设备"),
                    kResult.deviceName.empty()
                        ? QStringLiteral("-")
                        : QString::fromStdWString(kResult.deviceName));
                kAppendRow(QStringLiteral("FILE_OBJECT"),
                    pointerHex(kResult.fileObjectAddress));
                kAppendRow(QStringLiteral("目标 DEVICE_OBJECT"),
                    pointerHex(kResult.targetDeviceAddress));
                kAppendRow(QStringLiteral("栈顶 DEVICE_OBJECT"),
                    pointerHex(kResult.relatedDeviceAddress));
                kAppendRow(QStringLiteral("基础 FS DEVICE_OBJECT"),
                    pointerHex(kResult.baseFsDeviceAddress));
                kAppendRow(QStringLiteral("VPB DEVICE_OBJECT"),
                    pointerHex(kResult.vpbDeviceAddress));
                kAppendRow(QStringLiteral("分发入口"),
                    pointerHex(kResult.dispatchAddress));
                kAppendRow(QStringLiteral("目标 StackSize"),
                    QString::number(kResult.targetStackSize));
                kAppendRow(QStringLiteral("目标 DeviceFlags"),
                    QStringLiteral("0x%1")
                        .arg(kResult.targetDeviceFlags, 8, 16, QChar('0')).toUpper());

                table->resizeColumnToContents(0);
                safeThis->irpOutputHexEdit_->setPlainText(
                    FileDock::formatHexDump(kResult.outputData));

                const bool kSemanticOk =
                    kResult.status == KSWORD_ARK_FILE_IRP_STATUS_OK &&
                    kResult.operationStatus >= 0;
                safeThis->irpStatusLabel_->setText(
                    QStringLiteral("%1：协议=%2；目标请求=%3；Information=%4；输出 %5 字节")
                        .arg(FileDock::irpMajorDisplayText(
                            static_cast<int>(kResult.majorFunction)))
                        .arg(irpProtocolStatusText(kResult.status))
                        .arg(statusHex(kResult.operationStatus))
                        .arg(static_cast<qulonglong>(kResult.information))
                        .arg(kResult.outputData.size()));

                {
                    KLogEvent event;
                    if (kSemanticOk)
                    {
                        info << event
                            << "[FileDock] 自建 IRP 完成, major="
                            << kMajorFunction
                            << ", layer="
                            << kResult.resolvedLayer
                            << ", op=0x"
                            << statusHex(kResult.operationStatus).toStdString()
                            << ", outputBytes="
                            << kResult.outputData.size()
                            << ", path="
                            << ntPath.toStdString()
                            << eol;
                    }
                    else
                    {
                        warn << event
                            << "[FileDock] 自建 IRP 未成功, major="
                            << kMajorFunction
                            << ", protocol="
                            << kResult.status
                            << ", create="
                            << statusHex(kResult.createStatus).toStdString()
                            << ", op="
                            << statusHex(kResult.operationStatus).toStdString()
                            << ", path="
                            << ntPath.toStdString()
                            << eol;
                    }
                }

                kPro.set(kProgressPid, kSemanticOk ? "提交完成" : "提交返回失败状态", 0, 100.0f);
            },
            Qt::QueuedConnection);
    }).detach();
}
