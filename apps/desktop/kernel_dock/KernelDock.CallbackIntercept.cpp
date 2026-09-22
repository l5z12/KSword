#include "KernelDock.h"
#include "../ui/VisibleTableWidget.h"

#include "KernelDock.CallbackIntercept.h"
#include "KernelDock.CallbackPromptManager.h"
#include "../settings_dock/AppearanceSettings.h"
#include "../ui/TableInteractionSupport.h"
#include "../Theme.h"
#include "../../../shared/ark_client/ArkDriverClient.h"

#include <QApplication>
#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QCheckBox>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QHash>
#include <QIcon>
#include <QMenu>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QClipboard>
#include <QIODevice>
#include <QPlainTextEdit>
#include <QPainter>
#include <QPen>
#include <QPixmap>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QSize>
#include <QSpinBox>
#include <QSplitter>
#include <QStringList>
#include <QStyledItemDelegate>
#include <QStyle>
#include <QTabWidget>
#include <QTableView>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QTimeZone>
#include <QUrl>
#include <QVariant>
#include <QVBoxLayout>
#include <QVector>

#include <Windows.h>
#include <sddl.h>

#include <algorithm>
#include <limits>
#include <utility>
#include <vector>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum class GroupColumn : int
    {
        kId = 0,
        kName,
        kEnabled,
        kPriority,
        kComment,
        kCount
    };

    enum class RuleColumn : int
    {
        kEnabled,
        kRuleId,
        kGroupId,
        kRuleName,
        kOperationMask,
        kMatchMode,
        kAction,
        kTimeoutMs,
        kTimeoutDefaultDecision,
        kPriority,
        kCount
    };

    enum class FileMonitorColumn : int
    {
        kTime = 0,
        kPid,
        kProcess,
        kPath,
        kFsctlName,
        kControlCode,
        kStatus,
        kFileObject,
        kInputLength,
        kOutputLength,
        kCount
    };

    enum class MinifilterBypassPidColumn : int
    {
        kPid = 0,
        kProcess,
        kCount
    };

    enum class ProcessProtectRuleColumn : int
    {
        kEnabled = 0,
        kKind,
        kTarget,
        kAccessMask,
        kProtectThreads,
        kKernelProtection,
        kGuard,
        kRuleName,
        kHitCount,
        kKernelApplyCount,
        kCount
    };

    enum class ProcessProtectTrustedColumn : int
    {
        kKind = 0,
        kTarget,
        kCount
    };

    // callbackBackgroundImageReady:
    // - Input rawImagePath: background image path from appearance settings, which can be an absolute path or a path relative to the exe directory.
    // - Processing: Only check if the file exists without loading the image to avoid extra overhead from style evaluation.
    // - Returns: true if the background image is available, otherwise false.
    bool callbackBackgroundImageReady(const QString& rawImagePath)
    {
        const QString kTrimmedPath = rawImagePath.trimmed();
        if (kTrimmedPath.isEmpty())
        {
            return false;
        }

        const QString kResolvedPath = QDir::isAbsolutePath(kTrimmedPath)
            ? QDir::cleanPath(kTrimmedPath)
            : QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(kTrimmedPath);
        const QFileInfo kImageFileInfo(QDir::cleanPath(kResolvedPath));
        return kImageFileInfo.exists() && kImageFileInfo.isFile();
    }

    // callbackAllowWallpaperThroughControls:
    // - Input: None; reads current appearance settings.
    // - Processing: Used by driver callback Tab to determine if local tables or panels should be transparent.
    // - Returns: true indicates content behind should be passed through; local containers should be as transparent as possible.
    //
    // Both conditions must be evaluated, maintaining the same standard as mainWindow::shouldRenderTransparentDockContent():
    // Checking only for the existence of a background image incorrectly classifies the common configuration of 'transparent window background with no
    // image set' as opaque. Since the control's own styleSheet overrides the global QSS from mainWindow, this misclassification cannot be corrected.
    // This is the root cause of issue #161 (see also the comment on the same issue in KernelDock.cpp).
    bool callbackAllowWallpaperThroughControls()
    {
        const ks::settings::AppearanceSettings kSettings = ks::settings::loadAppearanceSettings();
        return callbackBackgroundImageReady(kSettings.backgroundImagePath)
            || kSettings.backgroundTransparencyEnabled;
    }

    class OpaqueTableEditorDelegate final : public QStyledItemDelegate
    {
    public:
        explicit OpaqueTableEditorDelegate(QTableView* tableView)
            : QStyledItemDelegate(tableView)
            , tableView_(tableView)
        {
        }

        void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            QStyleOptionViewItem itemOption(option);
            const bool kRowSelected = (itemOption.state & QStyle::State_Selected) != 0;
            itemOption.state &= ~QStyle::State_Selected;
            itemOption.state &= ~QStyle::State_HasFocus;
            QStyledItemDelegate::paint(painter, itemOption, index);
            if (kRowSelected)
            {
                drawRowSelectionOutline(painter, option, index);
            }
        }

        QWidget* createEditor(
            QWidget* parent,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override
        {
            QWidget* editor = QStyledItemDelegate::createEditor(parent, option, index);
            auto* lineEdit = qobject_cast<QLineEdit*>(editor);
            if (lineEdit != nullptr)
            {
                lineEdit->setAutoFillBackground(true);
                lineEdit->setFrame(true);
                lineEdit->setStyleSheet(
                    QStringLiteral(
                        "QLineEdit{"
                        "  background:%1;"
                        "  color:%2;"
                        "  border:1px solid %3;"
                        "  border-radius:2px;"
                        "  padding:0px 4px;"
                        "}")
                    .arg(ksword_theme::surfaceHex())
                    .arg(ksword_theme::textPrimaryHex())
                    .arg(ksword_theme::borderHex()));
            }
            return editor;
        }

    private:
        void drawRowSelectionOutline(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const
        {
            if (painter == nullptr || tableView_ == nullptr || !index.isValid())
            {
                return;
            }

            QHeaderView* headerView = tableView_->horizontalHeader();
            const QAbstractItemModel* model = index.model();
            if (headerView == nullptr || model == nullptr)
            {
                return;
            }

            int firstVisibleVisualIndex = std::numeric_limits<int>::max();
            int lastVisibleVisualIndex = std::numeric_limits<int>::min();
            const int kColumnCount = model->columnCount(index.parent());
            for (int columnIndex = 0; columnIndex < kColumnCount; ++columnIndex)
            {
                if (tableView_->isColumnHidden(columnIndex))
                {
                    continue;
                }

                const int kVisualIndex = headerView->visualIndex(columnIndex);
                if (kVisualIndex < 0)
                {
                    continue;
                }
                firstVisibleVisualIndex = std::min(firstVisibleVisualIndex, kVisualIndex);
                lastVisibleVisualIndex = std::max(lastVisibleVisualIndex, kVisualIndex);
            }

            const int kCurrentVisualIndex = headerView->visualIndex(index.column());
            if (kCurrentVisualIndex < 0 ||
                firstVisibleVisualIndex == std::numeric_limits<int>::max() ||
                lastVisibleVisualIndex == std::numeric_limits<int>::min())
            {
                return;
            }

            const QRect kBorderRect = option.rect.adjusted(0, 1, -1, -2);
            if (!kBorderRect.isValid())
            {
                return;
            }

            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, false);
            painter->setBrush(Qt::NoBrush);
            painter->setPen(QPen(ksword_theme::primaryBlueColor, 3.0));
            painter->drawLine(kBorderRect.topLeft(), kBorderRect.topRight());
            painter->drawLine(kBorderRect.bottomLeft(), kBorderRect.bottomRight());
            if (kCurrentVisualIndex == firstVisibleVisualIndex)
            {
                painter->drawLine(kBorderRect.topLeft(), kBorderRect.bottomLeft());
            }
            if (kCurrentVisualIndex == lastVisibleVisualIndex)
            {
                painter->drawLine(kBorderRect.topRight(), kBorderRect.bottomRight());
            }
            painter->restore();
        }

        QPointer<QTableView> tableView_;
    };

    quint32 defaultOperationMaskByType(const quint32 callbackType)
    {
        // Purpose: Provide default operation masks for new rules, containing only the basic operation bits exposed by the current UI.
        // Returns: The protocol layer operationMask; additional bits can still be added later via a 'custom mask'.
        switch (callbackType)
        {
        case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
            return KSWORD_ARK_REG_OP_CREATE_KEY |
                KSWORD_ARK_REG_OP_OPEN_KEY |
                KSWORD_ARK_REG_OP_DELETE_KEY |
                KSWORD_ARK_REG_OP_SET_VALUE |
                KSWORD_ARK_REG_OP_DELETE_VALUE |
                KSWORD_ARK_REG_OP_RENAME_KEY |
                KSWORD_ARK_REG_OP_SET_INFO |
                KSWORD_ARK_REG_OP_QUERY_VALUE;
        case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE: return KSWORD_ARK_PROCESS_OP_CREATE;
        case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE: return KSWORD_ARK_THREAD_OP_CREATE | KSWORD_ARK_THREAD_OP_EXIT;
        case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD: return KSWORD_ARK_IMAGE_OP_LOAD;
        case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
            return KSWORD_ARK_OBJECT_OP_HANDLE_CREATE |
                KSWORD_ARK_OBJECT_OP_HANDLE_DUPLICATE |
                KSWORD_ARK_OBJECT_OP_TYPE_PROCESS |
                KSWORD_ARK_OBJECT_OP_TYPE_THREAD;
        case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
            return KSWORD_ARK_MINIFILTER_OP_ALL;
        default:
            return 0U;
        }
    }

    QList<QPair<QString, quint32>> allowedActionListByType(const quint32 callbackType)
    {
        switch (callbackType)
        {
        case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
            return {
                { kernelText("kernel.callback.intercept.action.allow", QStringLiteral("允许")), KSWORD_ARK_RULE_ACTION_ALLOW },
                { kernelText("kernel.callback.intercept.action.deny", QStringLiteral("拒绝")), KSWORD_ARK_RULE_ACTION_DENY },
                { kernelText("kernel.callback.intercept.action.ask_user", QStringLiteral("询问用户")), KSWORD_ARK_RULE_ACTION_ASK_USER },
                { kernelText("kernel.callback.intercept.action.log_only", QStringLiteral("记录日志")), KSWORD_ARK_RULE_ACTION_LOG_ONLY }
            };
        case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE:
            return {
                { kernelText("kernel.callback.intercept.action.allow", QStringLiteral("允许")), KSWORD_ARK_RULE_ACTION_ALLOW },
                { kernelText("kernel.callback.intercept.action.deny", QStringLiteral("拒绝")), KSWORD_ARK_RULE_ACTION_DENY },
                { kernelText("kernel.callback.intercept.action.log_only", QStringLiteral("记录日志")), KSWORD_ARK_RULE_ACTION_LOG_ONLY }
            };
        case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE:
        case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD:
            return {
                { kernelText("kernel.callback.intercept.action.log_only", QStringLiteral("记录日志")), KSWORD_ARK_RULE_ACTION_LOG_ONLY }
            };
        case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
            return {
                { kernelText("kernel.callback.intercept.action.allow", QStringLiteral("允许")), KSWORD_ARK_RULE_ACTION_ALLOW },
                { kernelText("kernel.callback.intercept.action.strip_access", QStringLiteral("降权拦截")), KSWORD_ARK_RULE_ACTION_STRIP_ACCESS },
                { kernelText("kernel.callback.intercept.action.log_only", QStringLiteral("记录日志")), KSWORD_ARK_RULE_ACTION_LOG_ONLY }
            };
        case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
            return {
                { kernelText("kernel.callback.intercept.action.allow", QStringLiteral("允许")), KSWORD_ARK_RULE_ACTION_ALLOW },
                { kernelText("kernel.callback.intercept.action.deny", QStringLiteral("拒绝")), KSWORD_ARK_RULE_ACTION_DENY },
                { kernelText("kernel.callback.intercept.action.ask_user", QStringLiteral("询问用户")), KSWORD_ARK_RULE_ACTION_ASK_USER },
                { kernelText("kernel.callback.intercept.action.log_only", QStringLiteral("记录日志")), KSWORD_ARK_RULE_ACTION_LOG_ONLY }
            };
        default:
            return {};
        }
    }

    QList<QPair<QString, quint32>> allowedMatchModeListByType(const quint32 callbackType)
    {
        // Both registry and filesystem minifilters support Regex rules prefixed with ASK_USER.
        // Must match the R0 blob validation; otherwise, the UI cannot select supported matching modes.
        if (callbackType == KSWORD_ARK_CALLBACK_TYPE_REGISTRY ||
            callbackType == KSWORD_ARK_CALLBACK_TYPE_MINIFILTER)
        {
            return {
                { kernelText("kernel.callback.intercept.match.exact", QStringLiteral("精确匹配")), KSWORD_ARK_MATCH_MODE_EXACT },
                { kernelText("kernel.callback.intercept.match.prefix", QStringLiteral("前缀匹配")), KSWORD_ARK_MATCH_MODE_PREFIX },
                { kernelText("kernel.callback.intercept.match.wildcard", QStringLiteral("通配符匹配")), KSWORD_ARK_MATCH_MODE_WILDCARD },
                { kernelText("kernel.callback.intercept.match.regex", QStringLiteral("正则匹配")), KSWORD_ARK_MATCH_MODE_REGEX }
            };
        }

        return {
            { kernelText("kernel.callback.intercept.match.exact", QStringLiteral("精确匹配")), KSWORD_ARK_MATCH_MODE_EXACT },
            { kernelText("kernel.callback.intercept.match.prefix", QStringLiteral("前缀匹配")), KSWORD_ARK_MATCH_MODE_PREFIX },
            { kernelText("kernel.callback.intercept.match.wildcard", QStringLiteral("通配符匹配")), KSWORD_ARK_MATCH_MODE_WILDCARD }
        };
    }

    bool hasActiveMinifilterRule(const CallbackConfigDocument& configDocument)
    {
        // Purpose: Determine if the applied configuration contains Minifilter rules that will actually enter the R0 fast path.
        // Return: true if there are filesystem minifilter rules with both 'rule enabled' and 'rule group enabled' flags set.
        QHash<quint32, bool> groupEnabledById;
        for (const CallbackRuleGroupModel& groupModel : configDocument.groups)
        {
            groupEnabledById.insert(groupModel.groupId, groupModel.enabled);
        }

        for (const CallbackRuleModel& ruleModel : configDocument.rules)
        {
            if (!ruleModel.enabled)
            {
                continue;
            }
            if (ruleModel.callbackType != KSWORD_ARK_CALLBACK_TYPE_MINIFILTER)
            {
                continue;
            }
            if (!groupEnabledById.value(ruleModel.groupId, false))
            {
                continue;
            }
            return true;
        }
        return false;
    }

    QString formatCallbackNtStatusHex(const long statusValue)
    {
        // Purpose: Uniformly format the R0-returned NTSTATUS as an 8-digit hexadecimal string.
        // Returns: A string in the format 0xC0000184, aligning with driver logs and WinDbg constants.
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(statusValue), 8, 16, QChar('0'))
            .toUpper();
    }

    QList<QPair<QString, quint32>> decisionOptionList()
    {
        return {
            { kernelText("kernel.callback.intercept.decision.allow", QStringLiteral("允许")), KSWORD_ARK_DECISION_ALLOW },
            { kernelText("kernel.callback.intercept.decision.deny", QStringLiteral("拒绝")), KSWORD_ARK_DECISION_DENY }
        };
    }

    bool containsOptionValue(
        const QList<QPair<QString, quint32>>& optionList,
        const quint32 valueToFind)
    {
        for (const QPair<QString, quint32>& optionPair : optionList)
        {
            if (optionPair.second == valueToFind)
            {
                return true;
            }
        }
        return false;
    }

    bool parseUnsignedText(const QString& rawText, quint32* valueOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }

        QString textValue = rawText.trimmed();
        int base = 10;
        if (textValue.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            textValue = textValue.mid(2);
            base = 16;
        }

        bool convertOk = false;
        const qulonglong kParsedValue = textValue.toULongLong(&convertOk, base);
        if (!convertOk || kParsedValue > std::numeric_limits<quint32>::max())
        {
            return false;
        }

        *valueOut = static_cast<quint32>(kParsedValue);
        return true;
    }

    QString operationMaskToText(const quint32 operationMask)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(operationMask), 8, 16, QChar('0'))
            .toUpper();
    }

    QList<QPair<QString, quint32>> operationCheckboxListByType(const quint32 callbackType)
    {
        // Purpose: Split the original 'operation type dropdown preset' into directly checkable base bits.
        // Input callbackType: current callback Tab type; Return value: display name and protocol mask bit.
        switch (callbackType)
        {
        case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
            return {
                { kernelText("kernel.callback.intercept.operation.registry.create_key", QStringLiteral("创建键")), KSWORD_ARK_REG_OP_CREATE_KEY },
                { kernelText("kernel.callback.intercept.operation.registry.open_key", QStringLiteral("打开键")), KSWORD_ARK_REG_OP_OPEN_KEY },
                { kernelText("kernel.callback.intercept.operation.registry.delete_key", QStringLiteral("删除键")), KSWORD_ARK_REG_OP_DELETE_KEY },
                { kernelText("kernel.callback.intercept.operation.registry.set_value", QStringLiteral("写入值")), KSWORD_ARK_REG_OP_SET_VALUE },
                { kernelText("kernel.callback.intercept.operation.registry.delete_value", QStringLiteral("删除值")), KSWORD_ARK_REG_OP_DELETE_VALUE },
                { kernelText("kernel.callback.intercept.operation.registry.rename_key", QStringLiteral("重命名键")), KSWORD_ARK_REG_OP_RENAME_KEY },
                { kernelText("kernel.callback.intercept.operation.registry.set_info", QStringLiteral("设置键信息")), KSWORD_ARK_REG_OP_SET_INFO },
                { kernelText("kernel.callback.intercept.operation.registry.query_value", QStringLiteral("查询值")), KSWORD_ARK_REG_OP_QUERY_VALUE }
            };

        case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE:
            return {
                { kernelText("kernel.callback.intercept.operation.process.create", QStringLiteral("进程创建")), KSWORD_ARK_PROCESS_OP_CREATE }
            };

        case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE:
            return {
                { kernelText("kernel.callback.intercept.operation.thread.create", QStringLiteral("线程创建")), KSWORD_ARK_THREAD_OP_CREATE },
                { kernelText("kernel.callback.intercept.operation.thread.exit", QStringLiteral("线程退出")), KSWORD_ARK_THREAD_OP_EXIT }
            };

        case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD:
            return {
                { kernelText("kernel.callback.intercept.operation.image.load", QStringLiteral("镜像加载")), KSWORD_ARK_IMAGE_OP_LOAD }
            };

        case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
            return {
                { kernelText("kernel.callback.intercept.operation.object.handle_create", QStringLiteral("句柄创建")), KSWORD_ARK_OBJECT_OP_HANDLE_CREATE },
                { kernelText("kernel.callback.intercept.operation.object.handle_duplicate", QStringLiteral("句柄复制")), KSWORD_ARK_OBJECT_OP_HANDLE_DUPLICATE },
                { kernelText("kernel.callback.intercept.operation.object.process", QStringLiteral("进程对象")), KSWORD_ARK_OBJECT_OP_TYPE_PROCESS },
                { kernelText("kernel.callback.intercept.operation.object.thread", QStringLiteral("线程对象")), KSWORD_ARK_OBJECT_OP_TYPE_THREAD }
            };
        case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
            return {
                { kernelText("kernel.callback.intercept.operation.minifilter.create", QStringLiteral("创建/打开")), KSWORD_ARK_MINIFILTER_OP_CREATE },
                { kernelText("kernel.callback.intercept.operation.minifilter.read", QStringLiteral("读取")), KSWORD_ARK_MINIFILTER_OP_READ },
                { kernelText("kernel.callback.intercept.operation.minifilter.write", QStringLiteral("写入")), KSWORD_ARK_MINIFILTER_OP_WRITE },
                { kernelText("kernel.callback.intercept.operation.minifilter.set_info", QStringLiteral("设置信息")), KSWORD_ARK_MINIFILTER_OP_SETINFO },
                { kernelText("kernel.callback.intercept.operation.minifilter.rename", QStringLiteral("重命名/硬链")), KSWORD_ARK_MINIFILTER_OP_RENAME },
                { kernelText("kernel.callback.intercept.operation.minifilter.delete", QStringLiteral("删除")), KSWORD_ARK_MINIFILTER_OP_DELETE },
                { kernelText("kernel.callback.intercept.operation.minifilter.cleanup", QStringLiteral("清理")), KSWORD_ARK_MINIFILTER_OP_CLEANUP },
                { kernelText("kernel.callback.intercept.operation.minifilter.close", QStringLiteral("关闭")), KSWORD_ARK_MINIFILTER_OP_CLOSE }
            };

        default:
            return {};
        }
    }

    QString normalizeMaskTextForEdit(const QString& rawText)
    {
        // Purpose: normalize user-input custom masks; automatically prepend '0x' if missing.
        // Input parameter rawText: The user's original input. Return: Empty text or uppercase 0x hexadecimal text.
        QString textValue = rawText.trimmed();
        if (textValue.isEmpty())
        {
            return QString();
        }

        if (!textValue.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            textValue.prepend(QStringLiteral("0x"));
        }

        return textValue.left(2).toLower() + textValue.mid(2).toUpper();
    }

    QString callbackRulePanelStyle()
    {
        // Purpose: Provide custom cell panel styles; transparent in background image mode, solid in standard theme mode.
        // Returns: Qt stylesheet string, reused by the first-row action checkboxes and the second-row details area.
        const QString kPanelBackground = callbackAllowWallpaperThroughControls()
            ? QStringLiteral("transparent")
            : ksword_theme::surfaceHex();
        return QStringLiteral(
            "QWidget#ksCallbackRuleOperationPanel,"
            "QWidget#ksCallbackRuleDetailPanel{"
            "  background:%1;"
            "  background-color:%1;"
            "  color:%2;"
            "}"
            "QWidget#ksCallbackRuleOperationPanel QCheckBox,"
            "QWidget#ksCallbackRuleDetailPanel QLabel{"
            "  color:%2;"
            "}"
            "QLabel#ksCallbackRuleFieldTitle{"
            "  color:%3;"
            "  font-weight:600;"
            "}")
            .arg(kPanelBackground)
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex);
    }

    QString callbackRuleTableStyle()
    {
        // Purpose: Unify the background, header, selection state, and grid colors of the callback rules table.
        // Return value: Qt stylesheet string, shared across all callback type tabs.
        const bool kAllowWallpaperThrough = callbackAllowWallpaperThroughControls();
        const QString kTableBackground = kAllowWallpaperThrough
            ? QStringLiteral("transparent")
            : ksword_theme::surfaceHex();
        const QString kAlternateBackground = kAllowWallpaperThrough
            ? QStringLiteral("transparent")
            : ksword_theme::surfaceAltHex();
        return QStringLiteral(
            "QTableWidget{"
            "  background:%1;"
            "  background-color:%1;"
            "  alternate-background-color:%2;"
            "  color:%3;"
            "  gridline-color:%4;"
            "}"
            "QTableWidget::viewport{"
            "  background:%1;"
            "  background-color:%1;"
            "}"
            "QHeaderView::section{"
            "  background:transparent; /* %2 */"
            "  color:%5;"
            "  border:1px solid %4;"
            "  padding:3px 6px;"
            "  font-weight:600;"
            "}")
            .arg(kTableBackground)
            .arg(kAlternateBackground)
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::kPrimaryBlueHex);
    }

    QString callbackRuleContextMenuStyle()
    {
        // Purpose: Force the right-click menu to use an opaque background to avoid inheriting black text on a black background in light mode.
        // Returns: Qt stylesheet string, used only for the driver callback rule table menu.
        return QStringLiteral(
            "QMenu{"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "}"
            "QMenu::item{"
            "  background:transparent;"
            "  color:%2;"
            "  padding:5px 26px 5px 26px;"
            "}"
            "QMenu::item:selected{"
            "  background:%4;"
            "  color:palette(highlighted-text);"
            "}"
            "QMenu::item:disabled{"
            "  color:%5;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background:%3;"
            "  margin:4px 8px;"
            "}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::textDisabledColorHex());
    }

    // callbackRuleIoMessageText：
    // - Input: Raw IO/status message returned by ArkDriverClient;
    // - Processing: identify low-level terms such as DeviceIoControl, unsupported, capability, buffer, and version;
    // - Returns: Human-readable descriptions for the callback interception page logs, status bar, and details box.
    QString callbackRuleIoMessageText(const QString& rawMessageText)
    {
        const QString kTrimmedText = rawMessageText.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return kernelText("kernel.callback.intercept.message.no_driver_details", QStringLiteral("驱动未返回额外说明。"));
        }

        const QString kLowerText = kTrimmedText.toLower();
        if (kLowerText.contains(QStringLiteral("deviceiocontrol")))
        {
            return kernelText("kernel.callback.intercept.message.io_failure", QStringLiteral("驱动 IOCTL 调用失败或当前驱动版本不匹配。"));
        }
        if (kLowerText.contains(QStringLiteral("unsupported")) ||
            kLowerText.contains(QStringLiteral("not supported")) ||
            kLowerText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return kernelText("kernel.callback.intercept.message.unsupported", QStringLiteral("当前驱动暂不支持该回调/文件监控接口。"));
        }
        if (kLowerText.contains(QStringLiteral("capability")) ||
            kLowerText.contains(QStringLiteral("dyndata")))
        {
            return kernelText("kernel.callback.intercept.message.capability", QStringLiteral("动态偏移能力未满足，相关回调或文件监控字段暂不可用。"));
        }
        if (kLowerText.contains(QStringLiteral("version mismatch")) ||
            kLowerText.contains(QStringLiteral("protocol")))
        {
            return kernelText("kernel.callback.intercept.message.protocol", QStringLiteral("R3/R0 协议版本不匹配，请同步 shared 协议与驱动。"));
        }
        if (kLowerText.contains(QStringLiteral("buffer")) &&
            (kLowerText.contains(QStringLiteral("small")) || kLowerText.contains(QStringLiteral("trunc"))))
        {
            return kernelText("kernel.callback.intercept.message.buffer_short", QStringLiteral("驱动返回缓冲区不足，当前结果可能被截断。"));
        }
        return kTrimmedText;
    }

    void installCallbackTableCopyMenu(QTableWidget* tableWidget, const int processIdColumn)
    {
        // installCallbackTableCopyMenu：
        // - Input: Table within the callback interception page containing evidence rows to copy;
        // - Processing: Right-click to select the current row and write all columns to the clipboard as TSV;
        // - Return: None. Read-only copy; does not modify rules, driver state, or monitoring state.
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tableWidget, &QTableWidget::customContextMenuRequested, tableWidget, [tableWidget, processIdColumn](const QPoint& localPosition)
        {
            const auto kClickedIndex = tableWidget->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                tableWidget->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            }

            QMenu contextMenu(tableWidget);
            contextMenu.setStyleSheet(callbackRuleContextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                kernelText("kernel.callback.intercept.menu.copy_current_row", QStringLiteral("复制当前行")));
            copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
            const QTableWidgetItem* processIdItem =
                processIdColumn >= 0 && processIdColumn < tableWidget->columnCount() && tableWidget->currentRow() >= 0
                ? tableWidget->item(tableWidget->currentRow(), processIdColumn)
                : nullptr;
            bool processIdOk = false;
            const quint32 kProcessId = processIdItem != nullptr
                ? processIdItem->text().trimmed().toUInt(&processIdOk, 10)
                : 0U;
            QAction* openProcessAction = nullptr;
            if (processIdColumn >= 0)
            {
                openProcessAction = contextMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_details.svg")),
                    QStringLiteral("转到进程详细信息"));
                openProcessAction->setEnabled(processIdOk && kProcessId != 0U);
            }

            QAction* selectedAction = contextMenu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
            if (selectedAction == openProcessAction)
            {
                ks::ui::openProcessDetailByPid(kProcessId);
                return;
            }
            if (selectedAction != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QApplication::clipboard();
            const int kRowIndex = tableWidget->currentRow();
            if (clipboardObject == nullptr || kRowIndex < 0 || kRowIndex >= tableWidget->rowCount())
            {
                return;
            }

            QStringList rowFields;
            rowFields.reserve(tableWidget->columnCount());
            for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* item = tableWidget->item(kRowIndex, columnIndex);
                rowFields.push_back(item != nullptr ? item->text() : QString());
            }
            clipboardObject->setText(rowFields.join(QLatin1Char('\t')));
        });
    }

    // applyCallbackTableTransparency:
    // - Input: tableWidget - Table within the driver callback tab;
    // - Handling: Disable automatic filling of the table and viewport in background image mode to ensure the background image is visible through empty table areas;
    // - Returns: Nothing.
    void applyCallbackTableTransparency(QTableWidget* tableWidget)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        const bool kAllowWallpaperThrough = callbackAllowWallpaperThroughControls();
        tableWidget->setAutoFillBackground(!kAllowWallpaperThrough);
        tableWidget->setAttribute(Qt::WA_StyledBackground, !kAllowWallpaperThrough);
        tableWidget->viewport()->setAutoFillBackground(!kAllowWallpaperThrough);
        tableWidget->viewport()->setAttribute(Qt::WA_StyledBackground, !kAllowWallpaperThrough);
        if (kAllowWallpaperThrough)
        {
            tableWidget->setAlternatingRowColors(false);
        }
    }

    QString normalizeCustomMaskEditText(QLineEdit* maskEdit)
    {
        // Purpose: When the user leaves the custom mask input field, append the 0x prefix and synchronize the display to a normalized format.
        // Input maskEdit: custom mask input box; Return: normalized text, empty string if null.
        if (maskEdit == nullptr)
        {
            return QString();
        }

        const QString kNormalizedText = normalizeMaskTextForEdit(maskEdit->text());
        if (kNormalizedText != maskEdit->text())
        {
            maskEdit->setText(kNormalizedText);
        }
        return kNormalizedText;
    }

    QString initiatorPlaceholderByType(const quint32 callbackType)
    {
        switch (callbackType)
        {
        case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
            return kernelText("kernel.callback.intercept.placeholder.initiator.registry", QStringLiteral("例如：* 或 C:\\Windows\\System32\\reg.exe（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE:
            return kernelText("kernel.callback.intercept.placeholder.initiator.process", QStringLiteral("例如：* 或 C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE:
            return kernelText("kernel.callback.intercept.placeholder.initiator.thread", QStringLiteral("例如：* 或 C:\\Windows\\System32\\notepad.exe（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD:
            return kernelText("kernel.callback.intercept.placeholder.initiator.image", QStringLiteral("例如：* 或 C:\\Windows\\System32\\notepad.exe（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
            return kernelText("kernel.callback.intercept.placeholder.initiator.object", QStringLiteral("例如：* 或 C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
            return kernelText("kernel.callback.intercept.placeholder.initiator.minifilter", QStringLiteral("例如：* 或 C:\\Windows\\System32\\notepad.exe（支持自动转换）"));
        default:
            return kernelText("kernel.callback.intercept.placeholder.initiator.default", QStringLiteral("例如：*"));
        }
    }

    QString targetPlaceholderByType(const quint32 callbackType)
    {
        switch (callbackType)
        {
        case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
            return kernelText("kernel.callback.intercept.placeholder.target.registry", QStringLiteral("例如：HKCU\\Software\\KswordDemo 或 \\REGISTRY\\USER\\*\\Software\\KswordDemo"));
        case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE:
            return kernelText("kernel.callback.intercept.placeholder.target.process", QStringLiteral("例如：C:\\Windows\\System32\\notepad.exe（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE:
            return kernelText("kernel.callback.intercept.placeholder.target.thread", QStringLiteral("例如：C:\\Windows\\System32\\notepad.exe（目标进程镜像，支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD:
            return kernelText("kernel.callback.intercept.placeholder.target.image", QStringLiteral("例如：C:\\Windows\\System32\\kernel32.dll（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
            return kernelText("kernel.callback.intercept.placeholder.target.object", QStringLiteral("例如：C:\\Windows\\System32\\notepad.exe（被打开句柄的目标进程，支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
            return kernelText("kernel.callback.intercept.placeholder.target.minifilter", QStringLiteral("例如：C:\\Users\\*\\Documents\\*.docx 或 \\Device\\HarddiskVolume*\\*.sys"));
        default:
            return kernelText("kernel.callback.intercept.placeholder.target.default", QStringLiteral("例如：*"));
        }
    }

    quint32 currentOperationMaskFromPanel(const QWidget* operationPanel, bool* okOut)
    {
        // Purpose: Synthesize the final operationMask from the "Operation Type" checkboxes and the custom mask input field.
        // Input parameters: operationPanel is the operation cell control in the first row of the table; okOut returns the parsing status.
        if (okOut != nullptr)
        {
            *okOut = false;
        }
        if (operationPanel == nullptr)
        {
            return 0U;
        }

        quint32 operationMask = 0U;
        const QList<QCheckBox*> kCheckBoxList = operationPanel->findChildren<QCheckBox*>(
            QString(),
            Qt::FindDirectChildrenOnly);
        for (const QCheckBox* checkBox : kCheckBoxList)
        {
            if (checkBox == nullptr || !checkBox->isChecked())
            {
                continue;
            }

            bool bitOk = false;
            const quint32 kBitValue = checkBox->property("operationMaskBit").toUInt(&bitOk);
            if (bitOk)
            {
                operationMask |= kBitValue;
            }
        }

        const auto* customMaskEdit = operationPanel->findChild<QLineEdit*>(
            QStringLiteral("ksCallbackRuleCustomMaskEdit"),
            Qt::FindDirectChildrenOnly);
        if (customMaskEdit != nullptr)
        {
            const QString kMaskText = customMaskEdit->text().trimmed();
            if (!kMaskText.isEmpty())
            {
                quint32 customMask = 0U;
                if (!parseUnsignedText(normalizeMaskTextForEdit(kMaskText), &customMask))
                {
                    return 0U;
                }
                operationMask |= customMask;
            }
        }

        if (okOut != nullptr)
        {
            *okOut = true;
        }
        return operationMask;
    }

    QString normalizeMatchAllPattern(const QString& rawPatternText)
    {
        const QString kTrimmedText = rawPatternText.trimmed();
        if (kTrimmedText == QStringLiteral("*") || kTrimmedText == QStringLiteral("**"))
        {
            return QString();
        }
        return rawPatternText;
    }

    QString normalizeUserModeFilePathPatternForKernel(const QString& rawPatternText)
    {
        QString pathPattern = rawPatternText.trimmed();
        if (pathPattern.isEmpty())
        {
            return pathPattern;
        }

        pathPattern.replace('/', '\\');

        auto startsWithInsensitive = [](const QString& textValue, const QString& prefixText) -> bool
            {
                return textValue.startsWith(prefixText, Qt::CaseInsensitive);
            };

        // If the path is already in a common kernel format, pass it through directly.
        if (startsWithInsensitive(pathPattern, QStringLiteral("\\Device\\")) ||
            startsWithInsensitive(pathPattern, QStringLiteral("\\REGISTRY\\")) ||
            startsWithInsensitive(pathPattern, QStringLiteral("\\??\\")))
        {
            return pathPattern;
        }

        // Compatible with the multi-slash format like "\\??\\C:\...".
        if (startsWithInsensitive(pathPattern, QStringLiteral("\\\\??\\")))
        {
            pathPattern.remove(0, 1);
            return pathPattern;
        }

        // Compatible with Win32 extended prefixes "\\?\C:\..." and "\\?\UNC\server\share\...".
        if (startsWithInsensitive(pathPattern, QStringLiteral("\\\\?\\UNC\\")))
        {
            pathPattern = QStringLiteral("\\\\") + pathPattern.mid(8);
        }
        else if (startsWithInsensitive(pathPattern, QStringLiteral("\\\\?\\")))
        {
            pathPattern = pathPattern.mid(4);
        }

        // UNC path conversion: \\server\share\foo -> \Device\Mup\server\share\foo
        if (pathPattern.startsWith(QStringLiteral("\\\\")))
        {
            QString uncRest = pathPattern.mid(2);
            while (uncRest.startsWith('\\'))
            {
                uncRest.remove(0, 1);
            }
            if (uncRest.isEmpty())
            {
                return QStringLiteral("\\Device\\Mup");
            }
            return QStringLiteral("\\Device\\Mup\\%1").arg(uncRest);
        }

        // Drive letter path conversion: C:\foo -> \Device\HarddiskVolumeX\foo (preferred), falling back to \??\C:\foo on failure.
        if (pathPattern.size() >= 2 &&
            pathPattern[0].isLetter() &&
            pathPattern[1] == QLatin1Char(':'))
        {
            const QString kDriveText = pathPattern.left(2).toUpper();
            wchar_t targetBuffer[1024] = {};
            const DWORD kQueryChars = ::QueryDosDeviceW(
                reinterpret_cast<LPCWSTR>(kDriveText.utf16()),
                targetBuffer,
                static_cast<DWORD>(sizeof(targetBuffer) / sizeof(targetBuffer[0])));

            QString restPath = pathPattern.mid(2);
            while (restPath.startsWith('\\'))
            {
                restPath.remove(0, 1);
            }

            if (kQueryChars > 0U && targetBuffer[0] != L'\0')
            {
                const QString kNtDevicePrefix = QString::fromWCharArray(targetBuffer);
                if (!kNtDevicePrefix.trimmed().isEmpty())
                {
                    return restPath.isEmpty()
                        ? kNtDevicePrefix
                        : QStringLiteral("%1\\%2").arg(kNtDevicePrefix, restPath);
                }
            }

            return QStringLiteral("\\??\\%1").arg(pathPattern);
        }

        return pathPattern;
    }

    QString normalizeRegistryTargetPatternForKernel(const QString& rawTargetPattern)
    {
        // Input: Win32 registry path or kernel path entered by the user in the registry rule 'Target Program/Path'.
        // Processing: Strip the common 'Computer\' root display from the regedit address bar and convert
        //       HK* root aliases to the \REGISTRY\... object names actually used by Cm callbacks for matching.
        // Return: A match pattern ready for direct dispatch to the R0 rule engine; if unrecognized, retain the original user input.
        QString targetPattern = rawTargetPattern.trimmed();
        if (targetPattern.isEmpty())
        {
            return targetPattern;
        }

        targetPattern.replace('/', '\\');

        auto stripDisplayComputerRoot = [&targetPattern](const QString& displayRootText) {
            // Input: Root name displayed in the regedit address bar, e.g., "Computer" or "Computer" on English systems.
            // Handling: Strip only when the root name is followed by a path separator to avoid affecting ordinary key names.
            // Returns: None; updates in place via the captured targetPattern.
            if (targetPattern.compare(displayRootText, Qt::CaseInsensitive) == 0)
            {
                targetPattern.clear();
                return;
            }
            const QString kRootPrefix = QStringLiteral("%1\\").arg(displayRootText);
            if (targetPattern.startsWith(kRootPrefix, Qt::CaseInsensitive))
            {
                targetPattern.remove(0, kRootPrefix.size());
            }
        };

        auto trimLeadingSlash = [](QString* textValue) {
            if (textValue == nullptr)
            {
                return;
            }
            while (textValue->startsWith('\\'))
            {
                textValue->remove(0, 1);
            }
        };

        auto queryDwordRegistryValue = [](
            const HKEY rootKey,
            const QString& subKeyText,
            const QString& valueNameText,
            DWORD* valueOut) -> bool {
            // Input: Registry root, subkey, and value name.
            // Processing: Use Win32 API to read REG_DWORD to resolve the two alias layers of HKCC into
            //       the actual ControlSet/Profile object names that Cm callbacks are confirmed to return.
            // Returns: true if a DWORD was read; false on failure, prompting the caller to use a compatible fallback.
            HKEY keyHandle = nullptr;
            DWORD valueType = 0U;
            DWORD valueData = 0U;
            DWORD valueBytes = sizeof(valueData);

            if (valueOut == nullptr)
            {
                return false;
            }
            *valueOut = 0U;

            if (::RegOpenKeyExW(
                rootKey,
                reinterpret_cast<LPCWSTR>(subKeyText.utf16()),
                0U,
                KEY_QUERY_VALUE,
                &keyHandle) != ERROR_SUCCESS)
            {
                return false;
            }

            const LONG kQueryStatus = ::RegQueryValueExW(
                keyHandle,
                reinterpret_cast<LPCWSTR>(valueNameText.utf16()),
                nullptr,
                &valueType,
                reinterpret_cast<LPBYTE>(&valueData),
                &valueBytes);
            ::RegCloseKey(keyHandle);

            if (kQueryStatus != ERROR_SUCCESS ||
                valueType != REG_DWORD ||
                valueBytes != sizeof(valueData) ||
                valueData == 0U)
            {
                return false;
            }

            *valueOut = valueData;
            return true;
        };

        auto currentConfigRegistryRoot = [&queryDwordRegistryValue]() -> QString {
            // Input: None; Reads the local HKLM\SYSTEM\Select\Current and
            //       HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\CurrentConfig。
            // Processing: Parse HKCC/HKEY_CURRENT_CONFIG into the registry callback's actual observed value.
            //       \REGISTRY\MACHINE\SYSTEM\ControlSet00X\Hardware Profiles\000Y。
            // Returns: on success, the real HKCC kernel root; on read failure, falls back to the legacy alias path.
            DWORD controlSetIndex = 0U;
            DWORD hardwareProfileIndex = 0U;

            if (!queryDwordRegistryValue(
                HKEY_LOCAL_MACHINE,
                QStringLiteral("SYSTEM\\Select"),
                QStringLiteral("Current"),
                &controlSetIndex))
            {
                return QStringLiteral("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current");
            }

            if (!queryDwordRegistryValue(
                HKEY_LOCAL_MACHINE,
                QStringLiteral("SYSTEM\\CurrentControlSet\\Control\\IDConfigDB"),
                QStringLiteral("CurrentConfig"),
                &hardwareProfileIndex))
            {
                return QStringLiteral("\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet%1\\Hardware Profiles\\Current")
                    .arg(controlSetIndex, 3, 10, QChar('0'));
            }

            return QStringLiteral("\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet%1\\Hardware Profiles\\%2")
                .arg(controlSetIndex, 3, 10, QChar('0'))
                .arg(hardwareProfileIndex, 4, 10, QChar('0'));
        };

        auto restPathAfterRoot = [&](const QString& rootText) {
            QString restText = targetPattern.mid(rootText.size());
            trimLeadingSlash(&restText);
            return restText;
        };

        auto buildWithRoot = [](const QString& kernelRootText, const QString& restText) {
            if (restText.trimmed().isEmpty())
            {
                return kernelRootText;
            }
            return QStringLiteral("%1\\%2").arg(kernelRootText, restText);
        };

        auto currentUserSidText = []() -> QString {
            HANDLE tokenHandle = nullptr;
            if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
            {
                return QString();
            }

            DWORD tokenBytes = 0;
            (void)::GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &tokenBytes);
            if (tokenBytes == 0U)
            {
                ::CloseHandle(tokenHandle);
                return QString();
            }

            QByteArray tokenBuffer(static_cast<int>(tokenBytes), 0);
            if (::GetTokenInformation(tokenHandle, TokenUser, tokenBuffer.data(), tokenBytes, &tokenBytes) == FALSE)
            {
                ::CloseHandle(tokenHandle);
                return QString();
            }
            ::CloseHandle(tokenHandle);

            const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.constData());
            if (tokenUser == nullptr || tokenUser->User.Sid == nullptr)
            {
                return QString();
            }

            LPWSTR sidWideText = nullptr;
            if (::ConvertSidToStringSidW(tokenUser->User.Sid, &sidWideText) == FALSE || sidWideText == nullptr)
            {
                return QString();
            }

            const QString kSidText = QString::fromWCharArray(sidWideText);
            ::LocalFree(sidWideText);
            return kSidText;
        };

        stripDisplayComputerRoot(QStringLiteral("计算机"));
        stripDisplayComputerRoot(QStringLiteral("Computer"));
        if (targetPattern.isEmpty())
        {
            return targetPattern;
        }

        if (targetPattern.startsWith(QStringLiteral("\\REGISTRY\\"), Qt::CaseInsensitive) ||
            targetPattern.compare(QStringLiteral("\\REGISTRY"), Qt::CaseInsensitive) == 0)
        {
            return targetPattern;
        }

        if (targetPattern.startsWith(QStringLiteral("HKLM"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE"), restPathAfterRoot(QStringLiteral("HKLM")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKEY_LOCAL_MACHINE"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE"), restPathAfterRoot(QStringLiteral("HKEY_LOCAL_MACHINE")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKU"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\USER"), restPathAfterRoot(QStringLiteral("HKU")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKEY_USERS"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\USER"), restPathAfterRoot(QStringLiteral("HKEY_USERS")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKCR"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes"), restPathAfterRoot(QStringLiteral("HKCR")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKEY_CLASSES_ROOT"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes"), restPathAfterRoot(QStringLiteral("HKEY_CLASSES_ROOT")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKCC"), Qt::CaseInsensitive))
        {
            return buildWithRoot(currentConfigRegistryRoot(), restPathAfterRoot(QStringLiteral("HKCC")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKEY_CURRENT_CONFIG"), Qt::CaseInsensitive))
        {
            return buildWithRoot(currentConfigRegistryRoot(), restPathAfterRoot(QStringLiteral("HKEY_CURRENT_CONFIG")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKCU"), Qt::CaseInsensitive))
        {
            const QString kSidText = currentUserSidText();
            const QString kRootText = kSidText.isEmpty()
                ? QStringLiteral("\\REGISTRY\\USER\\*")
                : QStringLiteral("\\REGISTRY\\USER\\%1").arg(kSidText);
            return buildWithRoot(kRootText, restPathAfterRoot(QStringLiteral("HKCU")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKEY_CURRENT_USER"), Qt::CaseInsensitive))
        {
            const QString kSidText = currentUserSidText();
            const QString kRootText = kSidText.isEmpty()
                ? QStringLiteral("\\REGISTRY\\USER\\*")
                : QStringLiteral("\\REGISTRY\\USER\\%1").arg(kSidText);
            return buildWithRoot(kRootText, restPathAfterRoot(QStringLiteral("HKEY_CURRENT_USER")));
        }

        return targetPattern;
    }

    QString utc100nsToDisplayText(const quint64 utc100ns)
    {
        if (utc100ns == 0ULL)
        {
            return QStringLiteral("-");
        }

        constexpr qint64 kFileTimeToUnixEpoch100ns = 116444736000000000LL;
        const qint64 kValue100ns = static_cast<qint64>(utc100ns);
        if (kValue100ns < kFileTimeToUnixEpoch100ns)
        {
            return QStringLiteral("-");
        }

        const qint64 kUnixMs = (kValue100ns - kFileTimeToUnixEpoch100ns) / 10000LL;
        const QDateTime kUtcDateTime = QDateTime::fromMSecsSinceEpoch(kUnixMs, QTimeZone::UTC);
        if (!kUtcDateTime.isValid())
        {
            return QStringLiteral("-");
        }
        return kUtcDateTime.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    }

    QTableWidgetItem* makeReadOnlyItem(const QString& textValue)
    {
        auto* item = new QTableWidgetItem(textValue);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QString formatFileMonitorHex32(const quint32 value)
    {
        return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0')).toUpper();
    }

    // processProtectFixedWideToQString：
    // - Input: textBuffer/maxChars: R0 fixed-width wide character field, may not be null-terminated.
    // - Processing: Search for terminator within capacity; truncate to full length if out of bounds.
    // - Returns: The safely converted QString.
    QString processProtectFixedWideToQString(const wchar_t* const textBuffer, const std::size_t maxChars)
    {
        if (textBuffer == nullptr || maxChars == 0U)
        {
            return {};
        }
        std::size_t textLength = 0U;
        while (textLength < maxChars && textBuffer[textLength] != L'\0')
        {
            ++textLength;
        }
        return QString::fromWCharArray(textBuffer, static_cast<int>(textLength));
    }

    // processProtectCopyQStringToFixedWide：
    // - Input sourceText and target fixed-length buffer;
    // - Processing: Truncate by capacity and force write a terminator to ensure R0-side NUL-terminated comparisons do not overflow.
    // - Returns: Nothing.
    void processProtectCopyQStringToFixedWide(
        const QString& sourceText,
        wchar_t* const destination,
        const std::size_t maxChars)
    {
        if (destination == nullptr || maxChars == 0U)
        {
            return;
        }
        const int kCopyChars = std::min<int>(sourceText.size(), static_cast<int>(maxChars) - 1);
        if (kCopyChars > 0)
        {
            sourceText.left(kCopyChars).toWCharArray(destination);
        }
        destination[kCopyChars > 0 ? kCopyChars : 0] = L'\0';
    }

    QString processProtectKindText(const quint32 targetKind)
    {
        switch (targetKind)
        {
        case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID:
            return kernelText("kernel.callback.intercept.process_protect.kind.pid", QStringLiteral("PID"));
        case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME:
            return kernelText("kernel.callback.intercept.process_protect.kind.image_name", QStringLiteral("映像名"));
        case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH:
            return kernelText("kernel.callback.intercept.process_protect.kind.image_path", QStringLiteral("完整路径"));
        default:
            return kernelText("kernel.callback.intercept.process_protect.kind.unknown", QStringLiteral("未知"));
        }
    }

    // processProtectAccessSummaryText：
    // - Input: accessMask, a combination of KSWORD_ARK_PROCESS_PROTECT_ACCESS_* values.
    // - Processing: Convert bits to human-readable short labels.
    // - Returns: A summary joined by '+', or a placeholder if the mask is empty.
    // processProtectKernelProtectionText：
    // - Input protectionByte: PS_PROTECTION raw byte; 0 indicates no kernel protection applied.
    // - Processing: Split Type/Signer and format as "PP WinTcb [0x62]";
    // - Returns: Display text shared by the table and menu.
    QString processProtectKernelProtectionText(const quint32 protectionByte)
    {
        if (protectionByte == 0U)
        {
            return kernelText("kernel.callback.intercept.process_protect.kernel.none", QStringLiteral("不施加"));
        }

        const quint32 kProtectionType = protectionByte & 0x07U;
        const quint32 kSignerValue = (protectionByte & 0xF0U) >> 4U;
        const QString kTypeText = (kProtectionType == KSWORD_PS_PROTECTED_TYPE_FULL)
            ? QStringLiteral("PP")
            : QStringLiteral("PPL");
        static const char* const kSignerNames[] = {
            "None", "Authenticode", "CodeGen", "Antimalware",
            "Lsa", "Windows", "WinTcb", "WinSystem", "App"
        };
        const QString kSignerText = (kSignerValue < (sizeof(kSignerNames) / sizeof(kSignerNames[0])))
            ? QString::fromLatin1(kSignerNames[kSignerValue])
            : QString::number(kSignerValue);
        return QStringLiteral("%1 %2 [0x%3]")
            .arg(kTypeText)
            .arg(kSignerText)
            .arg(protectionByte, 2, 16, QChar('0'));
    }

    // processProtectGuardSummaryText：
    // - Input: Rule flags and hardenFlags;
    // - Processing: Concatenate 'create-on-use/self-heal/clear-debug-ports' into a summary list.
    // - Returns: Placeholder when no guard actions occur.
    QString processProtectGuardSummaryText(const quint32 ruleFlags, const quint32 hardenFlags)
    {
        QStringList parts;
        if ((ruleFlags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_APPLY_ON_CREATE) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.guard.on_create", QStringLiteral("创建即用"));
        }
        if ((ruleFlags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_SELF_HEAL) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.guard.self_heal", QStringLiteral("自愈"));
        }
        if ((hardenFlags & KSWORD_ARK_PROCESS_PROTECT_HARDEN_CLEAR_DEBUG_PORT) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.guard.clear_debug_port", QStringLiteral("清调试端口"));
        }
        if (parts.isEmpty())
        {
            return QStringLiteral("-");
        }
        return parts.join(QStringLiteral(" + "));
    }

    QString processProtectAccessSummaryText(const quint32 accessMask)
    {
        QStringList parts;
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.terminate", QStringLiteral("结束进程"));
        }
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_READ) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.vm_read", QStringLiteral("读内存"));
        }
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_WRITE) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.vm_write", QStringLiteral("写内存"));
        }
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_CREATE_THREAD) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.create_thread", QStringLiteral("远程建线程"));
        }
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_SUSPEND_RESUME) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.suspend", QStringLiteral("挂起恢复"));
        }
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_SET_INFORMATION) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.set_information", QStringLiteral("改属性"));
        }
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_DUP_HANDLE) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.dup_handle", QStringLiteral("复制句柄"));
        }
        if (parts.isEmpty())
        {
            return kernelText("kernel.callback.intercept.process_protect.access.none", QStringLiteral("（未选择）"));
        }
        return parts.join(QStringLiteral(" + "));
    }

    QString formatFileMonitorHex64(const quint64 value)
    {
        return QStringLiteral("0x%1").arg(value, 16, 16, QChar('0')).toUpper();
    }

    QString fileMonitorFsctlNameText(const quint32 fsControlCode)
    {
        const wchar_t* nameText = KswordARKFileMonitorFsctlCodeToText(fsControlCode);
        return nameText != nullptr
            ? QString::fromWCharArray(nameText)
            : QStringLiteral("UNKNOWN_FSCTL");
    }

    void applyRuleLineEditStyle(QLineEdit* lineEdit)
    {
        if (lineEdit == nullptr)
        {
            return;
        }
        lineEdit->setAutoFillBackground(true);
        lineEdit->setStyleSheet(
            QStringLiteral(
                "QLineEdit{"
                "  background:%1;"
                "  color:%2;"
                "  border:1px solid %3;"
                "  border-radius:2px;"
                "  padding:2px 6px;"
                "}"
                "QLineEdit:focus{"
                "  border:1px solid %4;"
                "}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::kPrimaryBlueHex));
    }

    QString encodeRuleClipboardText(const QString& rawText)
    {
        return QString::fromLatin1(QUrl::toPercentEncoding(rawText));
    }

    QString decodeRuleClipboardText(const QString& encodedText)
    {
        return QUrl::fromPercentEncoding(encodedText.toLatin1());
    }

    QString serializeRuleToClipboardText(const CallbackRuleModel& ruleModel)
    {
        QStringList lineList;
        lineList.push_back(QStringLiteral("KSWORD_CALLBACK_RULE_V1"));
        lineList.push_back(QStringLiteral("enabled=%1").arg(ruleModel.enabled ? 1 : 0));
        lineList.push_back(QStringLiteral("ruleId=%1").arg(ruleModel.ruleId));
        lineList.push_back(QStringLiteral("groupId=%1").arg(ruleModel.groupId));
        lineList.push_back(QStringLiteral("ruleName=%1").arg(encodeRuleClipboardText(ruleModel.ruleName)));
        lineList.push_back(QStringLiteral("callbackType=%1").arg(ruleModel.callbackType));
        lineList.push_back(QStringLiteral("operationMask=%1").arg(operationMaskToText(ruleModel.operationMask)));
        lineList.push_back(QStringLiteral("initiatorPattern=%1").arg(encodeRuleClipboardText(ruleModel.initiatorPattern)));
        lineList.push_back(QStringLiteral("targetPattern=%1").arg(encodeRuleClipboardText(ruleModel.targetPattern)));
        lineList.push_back(QStringLiteral("matchMode=%1").arg(ruleModel.matchMode));
        lineList.push_back(QStringLiteral("action=%1").arg(ruleModel.action));
        lineList.push_back(QStringLiteral("timeoutMs=%1").arg(ruleModel.timeoutMs));
        lineList.push_back(QStringLiteral("timeoutDefaultDecision=%1").arg(ruleModel.timeoutDefaultDecision));
        lineList.push_back(QStringLiteral("priority=%1").arg(ruleModel.priority));
        lineList.push_back(QStringLiteral("comment=%1").arg(encodeRuleClipboardText(ruleModel.comment)));
        return lineList.join(QLatin1Char('\n'));
    }

    bool deserializeRuleFromClipboardText(
        const QString& clipboardText,
        CallbackRuleModel* ruleOut,
        QString* errorTextOut)
    {
        if (ruleOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.clipboard.parse.rule_out_null", QStringLiteral("解析失败：ruleOut 为空。"));
            }
            return false;
        }

        QString textValue = clipboardText;
        textValue.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
        textValue.replace(QStringLiteral("\r"), QStringLiteral("\n"));
        const QStringList kRawLineList = textValue.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        if (kRawLineList.isEmpty() || kRawLineList.front().trimmed() != QStringLiteral("KSWORD_CALLBACK_RULE_V1"))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.clipboard.parse.unsupported_format", QStringLiteral("解析失败：不是支持的规则文本格式。"));
            }
            return false;
        }

        QHash<QString, QString> valueMap;
        for (int lineIndex = 1; lineIndex < kRawLineList.size(); ++lineIndex)
        {
            const QString kLineText = kRawLineList[lineIndex].trimmed();
            const int kSeparatorIndex = kLineText.indexOf('=');
            if (kSeparatorIndex <= 0)
            {
                continue;
            }
            const QString kKeyText = kLineText.left(kSeparatorIndex).trimmed();
            const QString kValueTextPart = kLineText.mid(kSeparatorIndex + 1);
            valueMap.insert(kKeyText, kValueTextPart);
        }

        CallbackRuleModel parsedRuleModel;
        parsedRuleModel.enabled = (valueMap.value(QStringLiteral("enabled")).trimmed() != QStringLiteral("0"));

        auto parseUIntField = [&](const QString& keyText, quint32* valueOut) -> bool {
            return parseUnsignedText(valueMap.value(keyText).trimmed(), valueOut);
        };

        if (!parseUIntField(QStringLiteral("ruleId"), &parsedRuleModel.ruleId) ||
            !parseUIntField(QStringLiteral("groupId"), &parsedRuleModel.groupId) ||
            !parseUIntField(QStringLiteral("callbackType"), &parsedRuleModel.callbackType) ||
            !parseUIntField(QStringLiteral("operationMask"), &parsedRuleModel.operationMask) ||
            !parseUIntField(QStringLiteral("matchMode"), &parsedRuleModel.matchMode) ||
            !parseUIntField(QStringLiteral("action"), &parsedRuleModel.action) ||
            !parseUIntField(QStringLiteral("timeoutMs"), &parsedRuleModel.timeoutMs) ||
            !parseUIntField(QStringLiteral("timeoutDefaultDecision"), &parsedRuleModel.timeoutDefaultDecision))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.clipboard.parse.numeric_invalid", QStringLiteral("解析失败：数值字段不合法。"));
            }
            return false;
        }

        bool priorityOk = false;
        parsedRuleModel.priority = valueMap.value(QStringLiteral("priority")).trimmed().toInt(&priorityOk);
        if (!priorityOk)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.clipboard.parse.priority_invalid", QStringLiteral("解析失败：priority 不合法。"));
            }
            return false;
        }

        parsedRuleModel.ruleName = decodeRuleClipboardText(valueMap.value(QStringLiteral("ruleName")));
        parsedRuleModel.initiatorPattern = decodeRuleClipboardText(valueMap.value(QStringLiteral("initiatorPattern")));
        parsedRuleModel.targetPattern = decodeRuleClipboardText(valueMap.value(QStringLiteral("targetPattern")));
        parsedRuleModel.comment = decodeRuleClipboardText(valueMap.value(QStringLiteral("comment")));

        *ruleOut = parsedRuleModel;
        return true;
    }

    QString callbackRuleComboStyle()
    {
        return ksword_theme::themedComboBoxStyle();
    }

    void applyRuleComboStyle(QComboBox* comboBox)
    {
        if (comboBox == nullptr)
        {
            return;
        }

        comboBox->setStyleSheet(callbackRuleComboStyle());
        if (comboBox->view() != nullptr)
        {
            comboBox->view()->setStyleSheet(ksword_theme::themedComboBoxPopupViewStyle());
        }
    }

    // resolveFileMonitorProcessNameText：
    // - Input processId: Process initiating the R0 event; nameCache: Caller-private PID→process name cache.
    // - Processing: Return immediately if cache hit; otherwise, call OpenProcess + QueryFullProcessImageNameW to retrieve the image name.
    // - Returns: Process name text ready for table insertion; on parse failure, falls back to "PID %1".
    // Note: Uses only Win32 and Qt value types, allowing calls from background threads.
    QString resolveFileMonitorProcessNameText(const quint32 processId, QHash<quint32, QString>& nameCache)
    {
        if (processId == 0U)
        {
            return QStringLiteral("Idle");
        }
        if (processId == 4U)
        {
            return QStringLiteral("System");
        }
        const auto kCacheIterator = nameCache.constFind(processId);
        if (kCacheIterator != nameCache.constEnd())
        {
            return kCacheIterator.value();
        }

        QString processName;
        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (processHandle != nullptr)
        {
            wchar_t imagePathBuffer[MAX_PATH * 4] = {};
            DWORD imagePathChars = static_cast<DWORD>(sizeof(imagePathBuffer) / sizeof(imagePathBuffer[0]));
            if (::QueryFullProcessImageNameW(processHandle, 0, imagePathBuffer, &imagePathChars) != FALSE)
            {
                processName = QFileInfo(QString::fromWCharArray(imagePathBuffer, static_cast<int>(imagePathChars))).fileName();
            }
            ::CloseHandle(processHandle);
        }
        if (processName.isEmpty())
        {
            processName = QStringLiteral("PID %1").arg(processId);
        }
        nameCache.insert(processId, processName);
        return processName;
    }

    // FileMonitorPreparedEvent：
    // - Purpose: Pure value-type row data for background drain tasks to be dispatched back to the UI thread.
    // - Input: R0 event row plus the process name already parsed in the background;
    // - Output: The UI thread only needs to populate the table by field, without accessing OpenProcess.
    struct FileMonitorPreparedEvent
    {
        ksword::ark::FileMonitorEventRow eventRow;  // eventRow: R0 raw event row.
        QString processNameText;                    // processNameText: The process name resolved in the background.
    };

    // FileMonitorDrainSnapshot：
    // - Purpose: Complete result of a single background drain, all value types;
    // - Input: Populated by QThreadPool tasks;
    // - Output: The UI thread appends a table row and refreshes the status label based on this.
    struct FileMonitorDrainSnapshot
    {
        bool ioOk = false;                          // ioOk: Whether draining the IOCTL was successful.
        unsigned long win32Error = 0UL;             // win32Error: Win32 error code on failure.
        quint32 totalQueuedBeforeDrain = 0U;        // totalQueuedBeforeDrain: Queue depth before draining.
        quint32 droppedCount = 0U;                  // droppedCount: Cumulative count of dropped events.
        QVector<FileMonitorPreparedEvent> events;   // events: Rows of events with process names parsed.
        QHash<quint32, QString> resolvedNames;      // resolvedNames: PID-to-process-name mapping resolved in this round, returned and merged into the main cache.
    };
}

class CallbackInterceptController final : public QObject
{
public:
    explicit CallbackInterceptController(QWidget* hostPage, QObject* parent = nullptr)
        : QObject(parent)
        , hostPage_(hostPage)
    {
        initializeUi();
        initializeConnections();

        addDefaultGroupIfNeeded();
        refreshRuleGroupComboOptions();
        reloadRuntimeState();

        promptManager_ = CallbackPromptManager::ensureGlobalManager(
            hostPage_ != nullptr ? hostPage_->window() : nullptr);
        if (promptManager_ != nullptr)
        {
            connect(
                promptManager_,
                &CallbackPromptManager::logLineGenerated,
                hostPage_,
                [this](const QString& logText) {
                    appendEventLog(logText);
                });
            promptManager_->start();
            appendAppLog(kernelText("kernel.callback.intercept.log.prompt_manager_started", QStringLiteral("驱动回调询问管理器已启动。")));
        }
    }

    ~CallbackInterceptController() override = default;

private:
    void initializeUi()
    {
        if (hostPage_ == nullptr)
        {
            return;
        }

        auto* outerLayout = new QVBoxLayout(hostPage_);
        outerLayout->setContentsMargins(0, 0, 0, 0);
        outerLayout->setSpacing(0);

        auto* scrollArea = new QScrollArea(hostPage_);
        scrollArea->setWidgetResizable(true);
        scrollArea->setFrameShape(QFrame::NoFrame);
        scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        scrollArea->setAutoFillBackground(false);
        scrollArea->setAttribute(Qt::WA_StyledBackground, false);
        scrollArea->viewport()->setAutoFillBackground(false);
        scrollArea->viewport()->setAttribute(Qt::WA_StyledBackground, false);
        scrollArea->setStyleSheet(QStringLiteral(
            "QScrollArea,QScrollArea > QWidget,QScrollArea::viewport{"
            "  background:transparent;"
            "  background-color:transparent;"
            "}"));
        outerLayout->addWidget(scrollArea, 1);

        auto* scrollContent = new QWidget(scrollArea);
        scrollContent->setObjectName(QStringLiteral("ksCallbackInterceptScrollContent"));
        scrollContent->setAutoFillBackground(false);
        scrollContent->setAttribute(Qt::WA_StyledBackground, false);
        if (callbackAllowWallpaperThroughControls())
        {
            scrollContent->setStyleSheet(QStringLiteral(
                "QWidget#ksCallbackInterceptScrollContent,"
                "QWidget#ksCallbackInterceptScrollContent QWidget,"
                "QWidget#ksCallbackInterceptScrollContent QSplitter,"
                "QWidget#ksCallbackInterceptScrollContent QTabWidget::pane,"
                "QWidget#ksCallbackInterceptScrollContent QTabBar::tab:!selected{"
                "  background:transparent;"
                "  background-color:transparent;"
                "}"));
        }
        scrollArea->setWidget(scrollContent);

        auto* rootLayout = new QVBoxLayout(scrollContent);
        rootLayout->setContentsMargins(4, 4, 4, 4);
        rootLayout->setSpacing(6);

        auto* topBarLayout = new QHBoxLayout();
        topBarLayout->setContentsMargins(0, 0, 0, 0);
        topBarLayout->setSpacing(6);

        globalEnabledCheck_ = new QCheckBox(kernelText("kernel.callback.intercept.toolbar.global_enabled", QStringLiteral("全局启用")), scrollContent);
        globalEnabledCheck_->setChecked(true);
        applyButton_ = new QPushButton(kernelText("kernel.callback.intercept.toolbar.apply", QStringLiteral("应用")), scrollContent);
        reloadStateButton_ = new QPushButton(kernelText("kernel.callback.intercept.toolbar.reload_state", QStringLiteral("重新加载驱动状态")), scrollContent);
        importButton_ = new QPushButton(kernelText("kernel.callback.intercept.toolbar.import", QStringLiteral("导入配置")), scrollContent);
        exportButton_ = new QPushButton(kernelText("kernel.callback.intercept.toolbar.export", QStringLiteral("导出配置")), scrollContent);

        const auto kSetupIconButton = [this](QPushButton* button, const QIcon& iconValue, const QString& tipText) {
            if (button == nullptr || hostPage_ == nullptr)
            {
                return;
            }
            button->setText(QString());
            button->setIcon(iconValue);
            button->setToolTip(tipText);
            button->setFixedSize(30, 26);
            button->setIconSize(QSize(16, 16));
        };
        kSetupIconButton(applyButton_, QIcon(QStringLiteral(":/Icon/process_start.svg")), kernelText("kernel.callback.intercept.tooltip.apply", QStringLiteral("应用规则")));
        kSetupIconButton(reloadStateButton_, QIcon(QStringLiteral(":/Icon/process_refresh.svg")), kernelText("kernel.callback.intercept.tooltip.reload_state", QStringLiteral("重新加载驱动状态")));
        kSetupIconButton(importButton_, QIcon(QStringLiteral(":/Icon/codeeditor_open.svg")), kernelText("kernel.callback.intercept.tooltip.import", QStringLiteral("导入配置")));
        kSetupIconButton(exportButton_, QIcon(QStringLiteral(":/Icon/log_export.svg")), kernelText("kernel.callback.intercept.tooltip.export", QStringLiteral("导出配置")));

        topBarLayout->addWidget(globalEnabledCheck_, 0);
        topBarLayout->addWidget(applyButton_, 0);
        topBarLayout->addWidget(reloadStateButton_, 0);
        topBarLayout->addWidget(importButton_, 0);
        topBarLayout->addWidget(exportButton_, 0);
        topBarLayout->addStretch(1);
        rootLayout->addLayout(topBarLayout, 0);

        statusLabel_ = new QLabel(kernelText("kernel.callback.intercept.status.waiting_refresh", QStringLiteral("状态：等待刷新")), scrollContent);
        statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
        rootLayout->addWidget(statusLabel_, 0);

        auto* mainSplitter = new QSplitter(Qt::Horizontal, scrollContent);
        rootLayout->addWidget(mainSplitter, 1);

        auto* groupPane = new QWidget(mainSplitter);
        auto* groupLayout = new QVBoxLayout(groupPane);
        groupLayout->setContentsMargins(0, 0, 0, 0);
        groupLayout->setSpacing(6);

        auto* groupButtonLayout = new QHBoxLayout();
        groupButtonLayout->setContentsMargins(0, 0, 0, 0);
        groupButtonLayout->setSpacing(6);
        addGroupButton_ = new QPushButton(kernelText("kernel.callback.intercept.group.add", QStringLiteral("新增组")), groupPane);
        removeGroupButton_ = new QPushButton(kernelText("kernel.callback.intercept.group.remove", QStringLiteral("删除组")), groupPane);
        renameGroupButton_ = new QPushButton(kernelText("kernel.callback.intercept.group.rename", QStringLiteral("重命名")), groupPane);
        moveGroupUpButton_ = new QPushButton(kernelText("kernel.callback.intercept.group.move_up_short", QStringLiteral("上移")), groupPane);
        moveGroupDownButton_ = new QPushButton(kernelText("kernel.callback.intercept.group.move_down_short", QStringLiteral("下移")), groupPane);
        kSetupIconButton(addGroupButton_, QIcon(QStringLiteral(":/Icon/plus.svg")), kernelText("kernel.callback.intercept.group.add_tooltip", QStringLiteral("新增规则组")));
        kSetupIconButton(removeGroupButton_, QIcon(QStringLiteral(":/Icon/log_clear.svg")), kernelText("kernel.callback.intercept.group.remove_tooltip", QStringLiteral("删除当前规则组")));
        kSetupIconButton(renameGroupButton_, QIcon(QStringLiteral(":/Icon/process_details.svg")), kernelText("kernel.callback.intercept.group.rename_tooltip", QStringLiteral("重命名当前规则组")));
        kSetupIconButton(moveGroupUpButton_, QIcon(QStringLiteral(":/Icon/file_nav_up.svg")), kernelText("kernel.callback.intercept.group.move_up_tooltip", QStringLiteral("规则组上移")));
        kSetupIconButton(moveGroupDownButton_, QIcon(QStringLiteral(":/Icon/codeeditor_goto.svg")), kernelText("kernel.callback.intercept.group.move_down_tooltip", QStringLiteral("规则组下移")));
        groupButtonLayout->addWidget(addGroupButton_, 0);
        groupButtonLayout->addWidget(removeGroupButton_, 0);
        groupButtonLayout->addWidget(renameGroupButton_, 0);
        groupButtonLayout->addWidget(moveGroupUpButton_, 0);
        groupButtonLayout->addWidget(moveGroupDownButton_, 0);
        groupButtonLayout->addStretch(1);
        groupLayout->addLayout(groupButtonLayout, 0);

        groupTable_ = new ks::ui::VisibleTableWidget(groupPane);
        groupTable_->setColumnCount(static_cast<int>(GroupColumn::kCount));
        groupTable_->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("groupId"),
            kernelText("kernel.callback.intercept.group.header.name", QStringLiteral("组名称")),
            kernelText("kernel.callback.intercept.group.header.enabled", QStringLiteral("启用")),
            kernelText("kernel.callback.intercept.group.header.priority", QStringLiteral("优先级")),
            kernelText("kernel.callback.intercept.group.header.comment", QStringLiteral("备注"))
            });
        groupTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        groupTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        groupTable_->setEditTriggers(
            QAbstractItemView::DoubleClicked |
            QAbstractItemView::SelectedClicked |
            QAbstractItemView::EditKeyPressed);
        groupTable_->setItemDelegate(new OpaqueTableEditorDelegate(groupTable_));
        groupTable_->setProperty("ksword_preserve_custom_table_delegate", true);
        groupTable_->verticalHeader()->setVisible(false);
        groupTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        groupTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(GroupColumn::kComment), QHeaderView::Stretch);
        groupTable_->setStyleSheet(callbackRuleTableStyle());
        applyCallbackTableTransparency(groupTable_);
        installCallbackTableCopyMenu(groupTable_, -1);
        groupLayout->addWidget(groupTable_, 1);

        auto* rightPane = new QWidget(mainSplitter);
        auto* rightLayout = new QVBoxLayout(rightPane);
        rightLayout->setContentsMargins(0, 0, 0, 0);
        rightLayout->setSpacing(6);

        auto* ruleToolbarLayout = new QHBoxLayout();
        ruleToolbarLayout->setContentsMargins(0, 0, 0, 0);
        ruleToolbarLayout->setSpacing(6);
        addRuleButton_ = new QPushButton(kernelText("kernel.callback.intercept.rule.add", QStringLiteral("新增规则")), rightPane);
        removeRuleButton_ = new QPushButton(kernelText("kernel.callback.intercept.rule.remove", QStringLiteral("删除规则")), rightPane);
        moveRuleUpButton_ = new QPushButton(kernelText("kernel.callback.intercept.rule.move_up", QStringLiteral("规则上移")), rightPane);
        moveRuleDownButton_ = new QPushButton(kernelText("kernel.callback.intercept.rule.move_down", QStringLiteral("规则下移")), rightPane);
        kSetupIconButton(addRuleButton_, QIcon(QStringLiteral(":/Icon/plus.svg")), kernelText("kernel.callback.intercept.rule.add_tooltip", QStringLiteral("新增规则")));
        kSetupIconButton(removeRuleButton_, QIcon(QStringLiteral(":/Icon/log_clear.svg")), kernelText("kernel.callback.intercept.rule.remove_tooltip", QStringLiteral("删除当前规则")));
        kSetupIconButton(moveRuleUpButton_, QIcon(QStringLiteral(":/Icon/file_nav_up.svg")), kernelText("kernel.callback.intercept.rule.move_up_tooltip", QStringLiteral("规则上移")));
        kSetupIconButton(moveRuleDownButton_, QIcon(QStringLiteral(":/Icon/codeeditor_goto.svg")), kernelText("kernel.callback.intercept.rule.move_down_tooltip", QStringLiteral("规则下移")));
        ruleToolbarLayout->addWidget(addRuleButton_, 0);
        ruleToolbarLayout->addWidget(removeRuleButton_, 0);
        ruleToolbarLayout->addWidget(moveRuleUpButton_, 0);
        ruleToolbarLayout->addWidget(moveRuleDownButton_, 0);
        ruleToolbarLayout->addStretch(1);
        rightLayout->addLayout(ruleToolbarLayout, 0);

        ruleTabWidget_ = new QTabWidget(rightPane);
        rightLayout->addWidget(ruleTabWidget_, 1);

        createRuleTableTab(KSWORD_ARK_CALLBACK_TYPE_REGISTRY, kernelText("kernel.callback.intercept.tab.registry", QStringLiteral("注册表")));
        createRuleTableTab(KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE, kernelText("kernel.callback.intercept.tab.process", QStringLiteral("进程创建")));
        createRuleTableTab(KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE, kernelText("kernel.callback.intercept.tab.thread", QStringLiteral("线程创建")));
        createRuleTableTab(KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD, kernelText("kernel.callback.intercept.tab.image", QStringLiteral("镜像加载")));
        createRuleTableTab(KSWORD_ARK_CALLBACK_TYPE_OBJECT, kernelText("kernel.callback.intercept.tab.object", QStringLiteral("对象管理器")));
        createRuleTableTab(KSWORD_ARK_CALLBACK_TYPE_MINIFILTER, kernelText("kernel.callback.intercept.tab.minifilter", QStringLiteral("文件系统微过滤器")));
        createMinifilterBypassPidTab(ruleTabWidget_);
        createProcessProtectTab(ruleTabWidget_);

        auto* logTabWidget = new QTabWidget(scrollContent);
        appLogEditor_ = new QPlainTextEdit(logTabWidget);
        eventLogEditor_ = new QPlainTextEdit(logTabWidget);
        appLogEditor_->setReadOnly(true);
        eventLogEditor_->setReadOnly(true);
        logTabWidget->addTab(appLogEditor_, kernelText("kernel.callback.intercept.log_tab.application", QStringLiteral("应用日志")));
        logTabWidget->addTab(eventLogEditor_, kernelText("kernel.callback.intercept.log_tab.events", QStringLiteral("事件日志")));
        rootLayout->addWidget(logTabWidget, 0);

        auto* fileMonitorFrame = new QFrame(scrollContent);
        fileMonitorFrame->setFrameShape(QFrame::StyledPanel);
        const bool kAllowWallpaperThroughFileMonitor = callbackAllowWallpaperThroughControls();
        fileMonitorFrame->setAutoFillBackground(!kAllowWallpaperThroughFileMonitor);
        fileMonitorFrame->setAttribute(Qt::WA_StyledBackground, !kAllowWallpaperThroughFileMonitor);
        fileMonitorFrame->setStyleSheet(kAllowWallpaperThroughFileMonitor
            ? QStringLiteral("QFrame{background:transparent;background-color:transparent;border:1px solid %1;}")
                .arg(ksword_theme::borderHex())
            : QStringLiteral("QFrame{background:%1;background-color:%1;border:1px solid %2;}")
                .arg(ksword_theme::surfaceHex())
                .arg(ksword_theme::borderHex()));
        auto* fileMonitorLayout = new QVBoxLayout(fileMonitorFrame);
        fileMonitorLayout->setContentsMargins(8, 8, 8, 8);
        fileMonitorLayout->setSpacing(6);

        auto* fileMonitorToolbar = new QHBoxLayout();
        fileMonitorToolbar->setContentsMargins(0, 0, 0, 0);
        fileMonitorToolbar->setSpacing(6);
        auto* fileMonitorTitleLabel = new QLabel(kernelText("kernel.callback.intercept.file_monitor.title", QStringLiteral("文件监控：Oplock / FSCTL")), fileMonitorFrame);
        fileMonitorTitleLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textPrimaryHex()));
        startFileMonitorFsctlButton_ = new QPushButton(fileMonitorFrame);
        drainFileMonitorButton_ = new QPushButton(fileMonitorFrame);
        clearFileMonitorButton_ = new QPushButton(fileMonitorFrame);
        exportFileMonitorButton_ = new QPushButton(fileMonitorFrame);
        kSetupIconButton(startFileMonitorFsctlButton_, QIcon(QStringLiteral(":/Icon/process_start.svg")), kernelText("kernel.callback.intercept.file_monitor.start_tooltip", QStringLiteral("启动/补充 FSCTL 文件监控")));
        kSetupIconButton(drainFileMonitorButton_, QIcon(QStringLiteral(":/Icon/process_refresh.svg")), kernelText("kernel.callback.intercept.file_monitor.read_tooltip", QStringLiteral("读取文件监控事件")));
        kSetupIconButton(clearFileMonitorButton_, QIcon(QStringLiteral(":/Icon/log_clear.svg")), kernelText("kernel.callback.intercept.file_monitor.clear_tooltip", QStringLiteral("清空当前文件监控表格")));
        kSetupIconButton(exportFileMonitorButton_, QIcon(QStringLiteral(":/Icon/log_export.svg")), kernelText("kernel.callback.intercept.file_monitor.export_tooltip", QStringLiteral("导出当前可见文件监控事件")));
        fileMonitorFsctlOnlyCheck_ = new QCheckBox(kernelText("kernel.callback.intercept.file_monitor.fsctl_only", QStringLiteral("仅显示 Oplock / FSCTL")), fileMonitorFrame);
        fileMonitorFsctlOnlyCheck_->setChecked(true);
        fileMonitorStatusLabel_ = new QLabel(kernelText("kernel.callback.intercept.file_monitor.waiting", QStringLiteral("等待启动或读取事件")), fileMonitorFrame);
        fileMonitorStatusLabel_->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));

        fileMonitorToolbar->addWidget(fileMonitorTitleLabel, 0);
        fileMonitorToolbar->addWidget(startFileMonitorFsctlButton_, 0);
        fileMonitorToolbar->addWidget(drainFileMonitorButton_, 0);
        fileMonitorToolbar->addWidget(clearFileMonitorButton_, 0);
        fileMonitorToolbar->addWidget(exportFileMonitorButton_, 0);
        fileMonitorToolbar->addWidget(fileMonitorFsctlOnlyCheck_, 0);
        fileMonitorToolbar->addStretch(1);
        fileMonitorToolbar->addWidget(fileMonitorStatusLabel_, 0);
        fileMonitorLayout->addLayout(fileMonitorToolbar, 0);

        fileMonitorTable_ = new ks::ui::VisibleTableWidget(fileMonitorFrame);
        fileMonitorTable_->setColumnCount(static_cast<int>(FileMonitorColumn::kCount));
        fileMonitorTable_->setHorizontalHeaderLabels(QStringList{
            kernelText("kernel.callback.intercept.file_monitor.header.time", QStringLiteral("时间")),
            QStringLiteral("PID"),
            kernelText("kernel.callback.intercept.file_monitor.header.process", QStringLiteral("进程")),
            kernelText("kernel.callback.intercept.file_monitor.header.path", QStringLiteral("文件路径")),
            kernelText("kernel.callback.intercept.file_monitor.header.fsctl", QStringLiteral("FSCTL 名称")),
            kernelText("kernel.callback.intercept.file_monitor.header.control_code", QStringLiteral("控制码")),
            kernelText("kernel.callback.intercept.file_monitor.header.status", QStringLiteral("状态码")),
            QStringLiteral("FileObject"),
            QStringLiteral("In"),
            QStringLiteral("Out")
            });
        fileMonitorTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        fileMonitorTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        fileMonitorTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        fileMonitorTable_->setAlternatingRowColors(true);
        fileMonitorTable_->setWordWrap(false);
        fileMonitorTable_->verticalHeader()->setVisible(false);
        fileMonitorTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        fileMonitorTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(FileMonitorColumn::kPath), QHeaderView::Stretch);
        fileMonitorTable_->setStyleSheet(callbackRuleTableStyle());
        applyCallbackTableTransparency(fileMonitorTable_);
        installCallbackTableCopyMenu(fileMonitorTable_, static_cast<int>(FileMonitorColumn::kPid));
        fileMonitorLayout->addWidget(fileMonitorTable_, 1);
        rootLayout->addWidget(fileMonitorFrame, 1);

        fileMonitorDrainTimer_ = new QTimer(hostPage_);
        fileMonitorDrainTimer_->setInterval(1500);

        mainSplitter->setStretchFactor(0, 3);
        mainSplitter->setStretchFactor(1, 7);
    }

    void initializeConnections()
    {
        if (globalEnabledCheck_ != nullptr)
        {
            connect(globalEnabledCheck_, &QCheckBox::toggled, hostPage_, [this](bool) {
                setDirtyState(true);
            });
        }

        connect(applyButton_, &QPushButton::clicked, hostPage_, [this]() {
            applyRulesToDriver();
        });
        connect(reloadStateButton_, &QPushButton::clicked, hostPage_, [this]() {
            reloadRuntimeState();
        });
        connect(importButton_, &QPushButton::clicked, hostPage_, [this]() {
            importConfigFromFile();
        });
        connect(exportButton_, &QPushButton::clicked, hostPage_, [this]() {
            exportConfigToFile();
        });

        connect(addGroupButton_, &QPushButton::clicked, hostPage_, [this]() {
            addGroupRow(0U);
        });
        connect(removeGroupButton_, &QPushButton::clicked, hostPage_, [this]() {
            removeCurrentGroup();
        });
        connect(renameGroupButton_, &QPushButton::clicked, hostPage_, [this]() {
            renameCurrentGroup();
        });
        connect(moveGroupUpButton_, &QPushButton::clicked, hostPage_, [this]() {
            moveCurrentGroup(-1);
        });
        connect(moveGroupDownButton_, &QPushButton::clicked, hostPage_, [this]() {
            moveCurrentGroup(1);
        });

        connect(addRuleButton_, &QPushButton::clicked, hostPage_, [this]() {
            addRuleToCurrentTab();
        });
        connect(removeRuleButton_, &QPushButton::clicked, hostPage_, [this]() {
            removeCurrentRule();
        });
        connect(moveRuleUpButton_, &QPushButton::clicked, hostPage_, [this]() {
            moveCurrentRule(-1);
        });
        connect(moveRuleDownButton_, &QPushButton::clicked, hostPage_, [this]() {
            moveCurrentRule(1);
        });

        connect(minifilterBypassAddButton_, &QPushButton::clicked, hostPage_, [this]() {
            addMinifilterBypassPidFromEdit();
        });
        connect(minifilterBypassRemoveButton_, &QPushButton::clicked, hostPage_, [this]() {
            removeCurrentMinifilterBypassPid();
        });
        connect(minifilterBypassApplyButton_, &QPushButton::clicked, hostPage_, [this]() {
            applyMinifilterBypassPidsToDriver();
        });
        connect(minifilterBypassClearButton_, &QPushButton::clicked, hostPage_, [this]() {
            clearMinifilterBypassPidsAndApply();
        });
        connect(minifilterBypassRefreshButton_, &QPushButton::clicked, hostPage_, [this]() {
            refreshMinifilterBypassPidsFromDriver();
        });

        connect(processProtectAddRuleButton_, &QPushButton::clicked, hostPage_, [this]() {
            addProcessProtectRuleFromInput();
        });
        connect(processProtectApplyPresetButton_, &QPushButton::clicked, hostPage_, [this]() {
            applyProcessProtectPresetToSelection();
        });
        connect(processProtectApplyKernelButton_, &QPushButton::clicked, hostPage_, [this]() {
            applyProcessProtectKernelPresetToSelection();
        });
        connect(processProtectRemoveRuleButton_, &QPushButton::clicked, hostPage_, [this]() {
            removeCurrentProcessProtectRule();
        });
        connect(processProtectTargetEdit_, &QLineEdit::returnPressed, hostPage_, [this]() {
            addProcessProtectRuleFromInput();
        });
        connect(processProtectTrustedAddButton_, &QPushButton::clicked, hostPage_, [this]() {
            addProcessProtectTrustedFromInput();
        });
        connect(processProtectTrustedRemoveButton_, &QPushButton::clicked, hostPage_, [this]() {
            removeCurrentProcessProtectTrusted();
        });
        connect(processProtectTrustedTargetEdit_, &QLineEdit::returnPressed, hostPage_, [this]() {
            addProcessProtectTrustedFromInput();
        });
        connect(processProtectApplyButton_, &QPushButton::clicked, hostPage_, [this]() {
            applyProcessProtectToDriver();
        });
        connect(processProtectRefreshButton_, &QPushButton::clicked, hostPage_, [this]() {
            refreshProcessProtectFromDriver();
        });
        connect(processProtectClearButton_, &QPushButton::clicked, hostPage_, [this]() {
            clearProcessProtectAndApply();
        });
        connect(minifilterBypassPidEdit_, &QLineEdit::returnPressed, hostPage_, [this]() {
            addMinifilterBypassPidFromEdit();
        });

        connect(groupTable_, &QTableWidget::itemChanged, hostPage_, [this](QTableWidgetItem*) {
            if (ignoreUiSignal_)
            {
                return;
            }
            refreshRuleGroupComboOptions();
            setDirtyState(true);
        });

        connect(ruleTabWidget_, &QTabWidget::currentChanged, hostPage_, [this](int) {
            // All callback types are now integrated into the rule table; keep tool buttons enabled when switching tabs.
            addRuleButton_->setEnabled(currentRuleTable() != nullptr);
            removeRuleButton_->setEnabled(currentRuleTable() != nullptr);
            moveRuleUpButton_->setEnabled(currentRuleTable() != nullptr);
            moveRuleDownButton_->setEnabled(currentRuleTable() != nullptr);
        });

        connect(startFileMonitorFsctlButton_, &QPushButton::clicked, hostPage_, [this]() {
            startFileMonitorFsctlCapture();
        });
        connect(drainFileMonitorButton_, &QPushButton::clicked, hostPage_, [this]() {
            drainFileMonitorEvents();
        });
        connect(clearFileMonitorButton_, &QPushButton::clicked, hostPage_, [this]() {
            clearFileMonitorEvents();
        });
        connect(exportFileMonitorButton_, &QPushButton::clicked, hostPage_, [this]() {
            exportVisibleFileMonitorEvents();
        });
        connect(fileMonitorFsctlOnlyCheck_, &QCheckBox::toggled, hostPage_, [this](bool) {
            applyFileMonitorEventFilter();
        });
        connect(fileMonitorDrainTimer_, &QTimer::timeout, hostPage_, [this]() {
            drainFileMonitorEvents();
        });
    }

    QString resolveProcessNameForFileMonitor(const quint32 processId)
    {
        // resolveProcessNameForFileMonitor：
        // - Input processId: PID whose process name needs to be displayed;
        // - Processing: Reuse the controller's own PID-to-process-name cache and delegate the Win32 query to the file-level resolution function.
        // - Returns: Process name text ready for direct table insertion.
        // Note: Intended for single-use, low-frequency paths (whitelist table) on the UI thread only. Batch
        // parsing for file monitor drain has been moved to a background thread and no longer uses this path.
        return resolveFileMonitorProcessNameText(processId, fileMonitorProcessNameCache_);
    }

    void startFileMonitorFsctlCapture()
    {
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::FileMonitorStatusResult kBeforeStatus = kDriverClient.queryFileMonitorStatus();
        unsigned long requestedMask = KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL;
        if (kBeforeStatus.io.ok &&
            (kBeforeStatus.runtimeFlags & KSWORD_ARK_FILE_MONITOR_RUNTIME_STARTED) != 0U)
        {
            requestedMask = kBeforeStatus.operationMask | KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL;
        }

        const ksword::ark::IoResult kStartResult = kDriverClient.controlFileMonitor(
            KSWORD_ARK_FILE_MONITOR_ACTION_START,
            requestedMask,
            kBeforeStatus.io.ok ? kBeforeStatus.processIdFilter : 0UL,
            0UL);
        if (!kStartResult.ok)
        {
            const QString kDetailText = callbackRuleIoMessageText(QString::fromStdString(kStartResult.message));
            fileMonitorStatusLabel_->setText(kernelText("kernel.callback.intercept.file_monitor.status.start_failed", QStringLiteral("启动失败：error=%1")).arg(kStartResult.win32Error));
            appendAppLog(kernelText("kernel.callback.intercept.file_monitor.log.start_failed", QStringLiteral("文件监控 FSCTL 启动失败：%1")).arg(kDetailText));
            return;
        }

        fileMonitorStatusLabel_->setText(kernelText("kernel.callback.intercept.file_monitor.status.started", QStringLiteral("FSCTL 文件监控已启动，mask=0x%1"))
            .arg(requestedMask, 8, 16, QChar('0')).toUpper());
        appendAppLog(kernelText("kernel.callback.intercept.file_monitor.log.started", QStringLiteral("文件监控 FSCTL 已启动：mask=0x%1"))
            .arg(requestedMask, 8, 16, QChar('0')).toUpper());
        if (fileMonitorDrainTimer_ != nullptr && !fileMonitorDrainTimer_->isActive())
        {
            fileMonitorDrainTimer_->start();
        }
        drainFileMonitorEvents();
    }

    void drainFileMonitorEvents()
    {
        if (fileMonitorTable_ == nullptr)
        {
            return;
        }

        // Periodic reading consumes the driver queue; when the menu is open, the drain IOCTL must be
        // deferred. Otherwise, the 'latest-wins' policy will only retain the last consumed batch.
        const QPointer<CallbackInterceptController> kGuardThis(this);
        if (ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("kernel-callback-file-monitor-drain"),
            { fileMonitorTable_ },
            [kGuardThis]()
            {
                if (!kGuardThis.isNull())
                {
                    kGuardThis->drainFileMonitorEvents();
                }
            }))
        {
            return;
        }

        // The drain IOCTL requires CreateFileW + synchronous DeviceIoControl every time, and for each batch, it performs OpenProcess +
        // QueryFullProcessImageNameW for every new PID. Running a 1500ms periodic timer directly on the UI thread would cause continuous frame
        // drops. Here, only background tasks are dispatched; the UI thread is responsible solely for populating the table after the tasks complete.
        if (fileMonitorDrainInFlight_)
        {
            return;
        }
        fileMonitorDrainInFlight_ = true;

        const QHash<quint32, QString> kNameCacheSnapshot = fileMonitorProcessNameCache_;
        QThreadPool::globalInstance()->start(
            [kGuardThis, kNameCacheSnapshot]()
            {
                QHash<quint32, QString> workerNameCache = kNameCacheSnapshot;
                FileMonitorDrainSnapshot snapshot;

                const ksword::ark::DriverClient kDriverClient;
                const ksword::ark::FileMonitorDrainResult kDrainResult = kDriverClient.drainFileMonitor(128UL, 0UL);
                snapshot.ioOk = kDrainResult.io.ok;
                snapshot.win32Error = kDrainResult.io.win32Error;
                snapshot.totalQueuedBeforeDrain = kDrainResult.totalQueuedBeforeDrain;
                snapshot.droppedCount = kDrainResult.droppedCount;
                if (snapshot.ioOk)
                {
                    snapshot.events.reserve(static_cast<qsizetype>(kDrainResult.events.size()));
                    for (const ksword::ark::FileMonitorEventRow& eventRow : kDrainResult.events)
                    {
                        FileMonitorPreparedEvent preparedEvent;
                        preparedEvent.eventRow = eventRow;
                        preparedEvent.processNameText =
                            resolveFileMonitorProcessNameText(eventRow.processId, workerNameCache);
                        snapshot.events.push_back(std::move(preparedEvent));
                    }
                    snapshot.resolvedNames = std::move(workerNameCache);
                }

                QCoreApplication* const kAppInstance = QCoreApplication::instance();
                if (kAppInstance == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(kAppInstance,
                    [kGuardThis, snapshot = std::move(snapshot)]() mutable
                    {
                        if (kGuardThis.isNull())
                        {
                            return;
                        }
                        kGuardThis->applyFileMonitorDrainSnapshot(std::move(snapshot));
                    });
            });
    }

    void applyFileMonitorDrainSnapshot(FileMonitorDrainSnapshot snapshot)
    {
        // applyFileMonitorDrainSnapshot：
        // - Input snapshot: pure value-type result produced by the background drain task
        // - Processing: merge process name cache, append table row, refresh filter and status label;
        // - Return: No return value; clears the in-flight flag to allow the next periodic drain.
        fileMonitorDrainInFlight_ = false;
        if (fileMonitorTable_ == nullptr || fileMonitorStatusLabel_ == nullptr)
        {
            return;
        }

        if (!snapshot.ioOk)
        {
            fileMonitorStatusLabel_->setText(kernelText("kernel.callback.intercept.file_monitor.status.read_failed", QStringLiteral("读取失败：error=%1")).arg(snapshot.win32Error));
            return;
        }

        for (auto nameIterator = snapshot.resolvedNames.constBegin();
             nameIterator != snapshot.resolvedNames.constEnd();
             ++nameIterator)
        {
            fileMonitorProcessNameCache_.insert(nameIterator.key(), nameIterator.value());
        }

        for (const FileMonitorPreparedEvent& preparedEvent : snapshot.events)
        {
            appendFileMonitorEventRow(preparedEvent.eventRow, preparedEvent.processNameText);
        }
        applyFileMonitorEventFilter();
        fileMonitorStatusLabel_->setText(
            kernelText("kernel.callback.intercept.file_monitor.status.drained", QStringLiteral("读取 %1 条，队列前=%2，丢弃=%3"))
            .arg(snapshot.events.size())
            .arg(snapshot.totalQueuedBeforeDrain)
            .arg(snapshot.droppedCount));
    }

    void appendFileMonitorEventRow(const ksword::ark::FileMonitorEventRow& eventRow, const QString& processNameText)
    {
        if (fileMonitorTable_ == nullptr)
        {
            return;
        }

        const bool kIsFsctlEvent =
            (eventRow.operationType & KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL) != 0U;
        const int kRowIndex = fileMonitorTable_->rowCount();
        fileMonitorTable_->insertRow(kRowIndex);

        QTableWidgetItem* timeItem = makeReadOnlyItem(utc100nsToDisplayText(static_cast<quint64>(eventRow.timeUtc100ns)));
        timeItem->setData(Qt::UserRole, kIsFsctlEvent);
        fileMonitorTable_->setItem(kRowIndex, static_cast<int>(FileMonitorColumn::kTime), timeItem);
        fileMonitorTable_->setItem(kRowIndex, static_cast<int>(FileMonitorColumn::kPid), makeReadOnlyItem(QString::number(eventRow.processId)));
        fileMonitorTable_->setItem(kRowIndex, static_cast<int>(FileMonitorColumn::kProcess), makeReadOnlyItem(processNameText));
        fileMonitorTable_->setItem(kRowIndex, static_cast<int>(FileMonitorColumn::kPath), makeReadOnlyItem(QString::fromStdWString(eventRow.path)));
        fileMonitorTable_->setItem(kRowIndex, static_cast<int>(FileMonitorColumn::kFsctlName), makeReadOnlyItem(kIsFsctlEvent ? fileMonitorFsctlNameText(eventRow.fsControlCode) : QStringLiteral("-")));
        fileMonitorTable_->setItem(kRowIndex, static_cast<int>(FileMonitorColumn::kControlCode), makeReadOnlyItem(kIsFsctlEvent ? formatFileMonitorHex32(eventRow.fsControlCode) : QStringLiteral("-")));
        fileMonitorTable_->setItem(kRowIndex, static_cast<int>(FileMonitorColumn::kStatus), makeReadOnlyItem(
            (eventRow.fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_RESULT_PRESENT) != 0U
            ? formatFileMonitorHex32(static_cast<quint32>(eventRow.resultStatus))
            : QStringLiteral("-")));
        fileMonitorTable_->setItem(kRowIndex, static_cast<int>(FileMonitorColumn::kFileObject), makeReadOnlyItem(formatFileMonitorHex64(eventRow.fileObjectAddress)));
        fileMonitorTable_->setItem(kRowIndex, static_cast<int>(FileMonitorColumn::kInputLength), makeReadOnlyItem(kIsFsctlEvent ? QString::number(eventRow.fsInputBufferLength) : QStringLiteral("-")));
        fileMonitorTable_->setItem(kRowIndex, static_cast<int>(FileMonitorColumn::kOutputLength), makeReadOnlyItem(kIsFsctlEvent ? QString::number(eventRow.fsOutputBufferLength) : QStringLiteral("-")));
    }

    void applyFileMonitorEventFilter()
    {
        if (fileMonitorTable_ == nullptr || fileMonitorFsctlOnlyCheck_ == nullptr)
        {
            return;
        }

        const bool kFsctlOnly = fileMonitorFsctlOnlyCheck_->isChecked();
        for (int rowIndex = 0; rowIndex < fileMonitorTable_->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* markerItem = fileMonitorTable_->item(rowIndex, static_cast<int>(FileMonitorColumn::kTime));
            const bool kIsFsctlEvent = markerItem != nullptr && markerItem->data(Qt::UserRole).toBool();
            fileMonitorTable_->setRowHidden(rowIndex, kFsctlOnly && !kIsFsctlEvent);
        }
    }

    void clearFileMonitorEvents()
    {
        if (fileMonitorTable_ != nullptr)
        {
            fileMonitorTable_->setRowCount(0);
        }
        if (fileMonitorStatusLabel_ != nullptr)
        {
            fileMonitorStatusLabel_->setText(kernelText("kernel.callback.intercept.file_monitor.status.cleared", QStringLiteral("当前表格已清空")));
        }
    }

    void exportVisibleFileMonitorEvents()
    {
        if (fileMonitorTable_ == nullptr)
        {
            return;
        }

        const QString kFilePath = QFileDialog::getSaveFileName(
            hostPage_,
            kernelText("kernel.callback.intercept.file_monitor.dialog.export_title", QStringLiteral("导出文件监控事件")),
            QStringLiteral("file_monitor_fsctl.tsv"),
            kernelText("kernel.callback.intercept.file_monitor.dialog.file_filter", QStringLiteral("TSV 文件 (*.tsv);;所有文件 (*.*)")));
        if (kFilePath.isEmpty())
        {
            return;
        }

        QFile outputFile(kFilePath);
        if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
        {
            QMessageBox::warning(hostPage_,
                kernelText("kernel.callback.intercept.file_monitor.dialog.title", QStringLiteral("文件监控")),
                kernelText("kernel.callback.intercept.file_monitor.status.export_failed", QStringLiteral("无法写入导出文件：%1")).arg(kFilePath));
            return;
        }

        QStringList lines;
        QStringList headerCells;
        for (int columnIndex = 0; columnIndex < fileMonitorTable_->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* headerItem = fileMonitorTable_->horizontalHeaderItem(columnIndex);
            headerCells << (headerItem != nullptr ? headerItem->text() : QString());
        }
        lines << headerCells.join(QLatin1Char('\t'));

        for (int rowIndex = 0; rowIndex < fileMonitorTable_->rowCount(); ++rowIndex)
        {
            if (fileMonitorTable_->isRowHidden(rowIndex))
            {
                continue;
            }
            QStringList rowCells;
            for (int columnIndex = 0; columnIndex < fileMonitorTable_->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* cellItem = fileMonitorTable_->item(rowIndex, columnIndex);
                QString cellText = cellItem != nullptr ? cellItem->text() : QString();
                cellText.replace(QLatin1Char('\t'), QLatin1Char(' '));
                cellText.replace(QLatin1Char('\n'), QLatin1Char(' '));
                cellText.replace(QLatin1Char('\r'), QLatin1Char(' '));
                rowCells << cellText;
            }
            lines << rowCells.join(QLatin1Char('\t'));
        }

        outputFile.write(lines.join(QLatin1Char('\n')).toUtf8());
        outputFile.write("\n");
        fileMonitorStatusLabel_->setText(kernelText("kernel.callback.intercept.file_monitor.status.exported", QStringLiteral("已导出：%1")).arg(kFilePath));
    }

    void createMinifilterBypassPidTab(QWidget* parentWidget)
    {
        // Input: Parent TabWidget; Processing: Create PID whitelist input area, table, and status bar.
        // Returns: none; the control pointer is stored in a member variable for use by button slot functions.
        if (ruleTabWidget_ == nullptr)
        {
            return;
        }

        auto* tabPage = new QWidget(parentWidget);
        auto* tabLayout = new QVBoxLayout(tabPage);
        tabLayout->setContentsMargins(8, 8, 8, 8);
        tabLayout->setSpacing(8);

        auto* hintLabel = new QLabel(
            kernelText("kernel.callback.intercept.minifilter.hint", QStringLiteral("白名单 PID 的文件系统请求会在 minifilter 入口直接放行，跳过回调规则、重定向和文件监控采集。")),
            tabPage);
        hintLabel->setWordWrap(true);
        hintLabel->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
        tabLayout->addWidget(hintLabel, 0);

        auto* inputLayout = new QHBoxLayout();
        inputLayout->setContentsMargins(0, 0, 0, 0);
        inputLayout->setSpacing(6);

        auto* pidLabel = new QLabel(kernelText("kernel.callback.intercept.minifilter.pid_allowlist", QStringLiteral("PID 白名单")), tabPage);
        pidLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textPrimaryHex()));
        minifilterBypassPidEdit_ = new QLineEdit(tabPage);
        minifilterBypassPidEdit_->setPlaceholderText(kernelText("kernel.callback.intercept.minifilter.input_placeholder", QStringLiteral("输入 PID，支持 1234 / 0x4D2；多个 PID 用空格、逗号或换行分隔")));
        applyRuleLineEditStyle(minifilterBypassPidEdit_);
        minifilterBypassAddButton_ = new QPushButton(kernelText("kernel.callback.intercept.minifilter.add", QStringLiteral("添加")), tabPage);
        minifilterBypassRemoveButton_ = new QPushButton(kernelText("kernel.callback.intercept.minifilter.remove_selected", QStringLiteral("移除选中")), tabPage);
        minifilterBypassApplyButton_ = new QPushButton(kernelText("kernel.callback.intercept.minifilter.apply", QStringLiteral("应用到驱动")), tabPage);
        minifilterBypassClearButton_ = new QPushButton(kernelText("kernel.callback.intercept.minifilter.clear_apply", QStringLiteral("清空并应用")), tabPage);
        minifilterBypassRefreshButton_ = new QPushButton(kernelText("kernel.callback.intercept.minifilter.refresh", QStringLiteral("从驱动刷新")), tabPage);

        inputLayout->addWidget(pidLabel, 0);
        inputLayout->addWidget(minifilterBypassPidEdit_, 1);
        inputLayout->addWidget(minifilterBypassAddButton_, 0);
        inputLayout->addWidget(minifilterBypassRemoveButton_, 0);
        inputLayout->addWidget(minifilterBypassApplyButton_, 0);
        inputLayout->addWidget(minifilterBypassClearButton_, 0);
        inputLayout->addWidget(minifilterBypassRefreshButton_, 0);
        tabLayout->addLayout(inputLayout, 0);

        minifilterBypassPidTable_ = new ks::ui::VisibleTableWidget(tabPage);
        minifilterBypassPidTable_->setColumnCount(static_cast<int>(MinifilterBypassPidColumn::kCount));
        minifilterBypassPidTable_->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("PID"),
            kernelText("kernel.callback.intercept.minifilter.header.process", QStringLiteral("进程"))
            });
        minifilterBypassPidTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        minifilterBypassPidTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        minifilterBypassPidTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        minifilterBypassPidTable_->setSortingEnabled(false);
        minifilterBypassPidTable_->setWordWrap(false);
        minifilterBypassPidTable_->verticalHeader()->setVisible(false);
        minifilterBypassPidTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(MinifilterBypassPidColumn::kPid), QHeaderView::ResizeToContents);
        minifilterBypassPidTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(MinifilterBypassPidColumn::kProcess), QHeaderView::Stretch);
        minifilterBypassPidTable_->setStyleSheet(callbackRuleTableStyle());
        applyCallbackTableTransparency(minifilterBypassPidTable_);
        installCallbackTableCopyMenu(minifilterBypassPidTable_, static_cast<int>(MinifilterBypassPidColumn::kPid));
        tabLayout->addWidget(minifilterBypassPidTable_, 1);

        minifilterBypassStatusLabel_ = new QLabel(kernelText("kernel.callback.intercept.minifilter.status.not_refreshed", QStringLiteral("尚未从驱动刷新；编辑后点击“应用到驱动”生效。")), tabPage);
        minifilterBypassStatusLabel_->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
        tabLayout->addWidget(minifilterBypassStatusLabel_, 0);

        ruleTabWidget_->addTab(tabPage, kernelText("kernel.callback.intercept.minifilter.tab", QStringLiteral("Minifilter PID 放行")));
    }

    QList<quint32> parseMinifilterBypassPidText(const QString& rawText, QString* errorTextOut) const
    {
        // Input: user-entered PID string; Processing: split by whitespace/comma/semicolon and support 0x hexadecimal format;
        // Returns: A deduplicated PID list; on failure, returns an empty list and writes to errorTextOut.
        QList<quint32> pidList;
        QString normalizedText = rawText;
        normalizedText.replace(QLatin1Char(','), QLatin1Char(' '));
        normalizedText.replace(QLatin1Char(';'), QLatin1Char(' '));
        normalizedText.replace(QLatin1Char('\n'), QLatin1Char(' '));
        normalizedText.replace(QLatin1Char('\r'), QLatin1Char(' '));
        normalizedText.replace(QLatin1Char('\t'), QLatin1Char(' '));

        const QStringList kTokenList = normalizedText.split(QLatin1Char(' '), Qt::SkipEmptyParts);
        if (kTokenList.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.minifilter.error.empty", QStringLiteral("请输入至少一个 PID。"));
            }
            return {};
        }

        for (const QString& tokenText : kTokenList)
        {
            quint32 processId = 0U;
            if (!parseUnsignedText(tokenText, &processId) || processId == 0U)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.minifilter.error.invalid_pid", QStringLiteral("PID 无效：%1")).arg(tokenText);
                }
                return {};
            }
            if (!pidList.contains(processId))
            {
                pidList.append(processId);
            }
        }
        return pidList;
    }

    int findMinifilterBypassPidRow(const quint32 processId) const
    {
        // Input: Target PID; Processing: scan PID column in whitelist table for UserRole/text;
        // Returns: The matching row index; returns -1 if no match is found.
        if (minifilterBypassPidTable_ == nullptr)
        {
            return -1;
        }

        for (int rowIndex = 0; rowIndex < minifilterBypassPidTable_->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* pidItem =
                minifilterBypassPidTable_->item(rowIndex, static_cast<int>(MinifilterBypassPidColumn::kPid));
            if (pidItem != nullptr && static_cast<quint32>(pidItem->data(Qt::UserRole).toUInt()) == processId)
            {
                return rowIndex;
            }
        }
        return -1;
    }

    bool appendMinifilterBypassPidRow(const quint32 processId)
    {
        // Input: a valid PID; Processing: skip duplicates and append PID/process name read-only rows;
        // Returns: Returns true on successful append; returns false if duplicate or limit exceeded.
        if (minifilterBypassPidTable_ == nullptr ||
            processId == 0U ||
            findMinifilterBypassPidRow(processId) >= 0)
        {
            return false;
        }
        if (minifilterBypassPidTable_->rowCount() >= static_cast<int>(KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT))
        {
            return false;
        }

        const int kRowIndex = minifilterBypassPidTable_->rowCount();
        minifilterBypassPidTable_->insertRow(kRowIndex);
        QTableWidgetItem* pidItem = makeReadOnlyItem(QString::number(processId));
        pidItem->setData(Qt::UserRole, processId);
        minifilterBypassPidTable_->setItem(kRowIndex, static_cast<int>(MinifilterBypassPidColumn::kPid), pidItem);
        minifilterBypassPidTable_->setItem(
            kRowIndex,
            static_cast<int>(MinifilterBypassPidColumn::kProcess),
            makeReadOnlyItem(resolveProcessNameForFileMonitor(processId)));
        return true;
    }

    void addMinifilterBypassPidFromEdit()
    {
        // Input: PID input box text; Processing: parse and append to local whitelist table;
        // Returns: nothing; errors are indicated via the status bar and a popup dialog.
        if (minifilterBypassPidEdit_ == nullptr)
        {
            return;
        }

        QString errorText;
        const QList<quint32> kPidList = parseMinifilterBypassPidText(minifilterBypassPidEdit_->text(), &errorText);
        if (!errorText.isEmpty())
        {
            if (minifilterBypassStatusLabel_ != nullptr)
            {
                minifilterBypassStatusLabel_->setText(kernelText("kernel.callback.intercept.minifilter.status.add_failed", QStringLiteral("添加失败：%1")).arg(errorText));
            }
            QMessageBox::warning(hostPage_, kernelText("kernel.callback.intercept.minifilter.title", QStringLiteral("Minifilter PID 放行")), errorText);
            return;
        }

        int addedCount = 0;
        for (const quint32 kProcessId : kPidList)
        {
            if (appendMinifilterBypassPidRow(kProcessId))
            {
                ++addedCount;
            }
        }

        if (minifilterBypassPidTable_ != nullptr &&
            minifilterBypassPidTable_->rowCount() >= static_cast<int>(KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) &&
            addedCount < static_cast<int>(kPidList.size()))
        {
            QMessageBox::warning(
                hostPage_,
                kernelText("kernel.callback.intercept.minifilter.title", QStringLiteral("Minifilter PID 放行")),
                kernelText("kernel.callback.intercept.minifilter.warning.limit", QStringLiteral("白名单最多 %1 个 PID，超出的项目未添加。"))
                .arg(KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT));
        }

        if (addedCount > 0)
        {
            minifilterBypassPidEdit_->clear();
        }
        if (minifilterBypassStatusLabel_ != nullptr)
        {
            minifilterBypassStatusLabel_->setText(kernelText("kernel.callback.intercept.minifilter.status.added", QStringLiteral("已添加 %1 个 PID；点击“应用到驱动”后生效。")).arg(addedCount));
        }
    }

    void removeCurrentMinifilterBypassPid()
    {
        // Input: current table selection; Processing: delete selected rows.
        // Return: None. Deletion only affects the UI and requires the user to click to apply and dispatch.
        if (minifilterBypassPidTable_ == nullptr)
        {
            return;
        }

        const int kRowIndex = minifilterBypassPidTable_->currentRow();
        if (kRowIndex < 0)
        {
            return;
        }

        minifilterBypassPidTable_->removeRow(kRowIndex);
        if (minifilterBypassStatusLabel_ != nullptr)
        {
            minifilterBypassStatusLabel_->setText(kernelText("kernel.callback.intercept.minifilter.status.removed", QStringLiteral("已移除选中 PID；点击“应用到驱动”后生效。")));
        }
    }

    std::vector<std::uint32_t> collectMinifilterBypassPidsFromUi() const
    {
        // Input: Current whitelist table; Processing: Read PIDs row by row and skip invalid/duplicate entries.
        // Returns: The std::vector PID list issued to ArkDriverClient.
        std::vector<std::uint32_t> processIds;
        if (minifilterBypassPidTable_ == nullptr)
        {
            return processIds;
        }

        for (int rowIndex = 0; rowIndex < minifilterBypassPidTable_->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* pidItem =
                minifilterBypassPidTable_->item(rowIndex, static_cast<int>(MinifilterBypassPidColumn::kPid));
            const quint32 kProcessId = pidItem != nullptr
                ? static_cast<quint32>(pidItem->data(Qt::UserRole).toUInt())
                : 0U;
            if (kProcessId == 0U)
            {
                continue;
            }
            if (std::find(processIds.cbegin(), processIds.cend(), static_cast<std::uint32_t>(kProcessId)) == processIds.cend())
            {
                processIds.push_back(static_cast<std::uint32_t>(kProcessId));
            }
        }
        return processIds;
    }

    void populateMinifilterBypassPids(const std::vector<std::uint32_t>& processIds)
    {
        // Input: PID list returned by driver or locally organized; Processing: rebuild table;
        // Returns: Nothing; the table content becomes a PID snapshot.
        if (minifilterBypassPidTable_ == nullptr)
        {
            return;
        }

        minifilterBypassPidTable_->setRowCount(0);
        for (const std::uint32_t kProcessId : processIds)
        {
            appendMinifilterBypassPidRow(static_cast<quint32>(kProcessId));
        }
    }

    void applyMinifilterBypassPidsToDriver()
    {
        // Input: current whitelist table; Processing: set the driver whitelist via ArkDriverClient.
        // Return: None; show a failure dialog and write to the application log.
        const std::vector<std::uint32_t> kProcessIds = collectMinifilterBypassPidsFromUi();
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::IoResult kIoResult = kDriverClient.setMinifilterBypassPids(kProcessIds);
        if (!kIoResult.ok)
        {
            const QString kDetailText = callbackRuleIoMessageText(QString::fromStdString(kIoResult.message));
            if (minifilterBypassStatusLabel_ != nullptr)
            {
                minifilterBypassStatusLabel_->setText(kernelText("kernel.callback.intercept.minifilter.status.apply_failed", QStringLiteral("应用失败：error=%1")).arg(kIoResult.win32Error));
            }
            appendAppLog(kernelText("kernel.callback.intercept.minifilter.log.apply_failed", QStringLiteral("Minifilter PID 放行应用失败：error=%1，detail=%2"))
                .arg(kIoResult.win32Error)
                .arg(kDetailText));
            QMessageBox::warning(
                hostPage_,
                kernelText("kernel.callback.intercept.minifilter.title", QStringLiteral("Minifilter PID 放行")),
                kernelText("kernel.callback.intercept.minifilter.error.apply_to_driver", QStringLiteral("应用到驱动失败，error=%1。")).arg(kIoResult.win32Error));
            return;
        }

        if (minifilterBypassStatusLabel_ != nullptr)
        {
            minifilterBypassStatusLabel_->setText(kernelText("kernel.callback.intercept.minifilter.status.applied", QStringLiteral("已应用到驱动：%1 个 PID。")).arg(static_cast<qulonglong>(kProcessIds.size())));
        }
        appendAppLog(kernelText("kernel.callback.intercept.minifilter.log.applied", QStringLiteral("Minifilter PID 放行已应用：count=%1。")).arg(static_cast<qulonglong>(kProcessIds.size())));
    }

    void clearMinifilterBypassPidsAndApply()
    {
        // Input: none; Processing: clear UI table and immediately send whitelist to driver;
        // Return: None; on failure, the driver state may remain unchanged from the whitelist.
        if (minifilterBypassPidTable_ != nullptr)
        {
            minifilterBypassPidTable_->setRowCount(0);
        }
        applyMinifilterBypassPidsToDriver();
    }

    void refreshMinifilterBypassPidsFromDriver()
    {
        // Input: None; Process: Query the driver's current whitelist and refresh the table.
        // Return: None; on failure, only update the status bar/log without modifying the local table.
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::MinifilterBypassPidResult kQueryResult =
            kDriverClient.queryMinifilterBypassPids();
        if (!kQueryResult.io.ok)
        {
            const QString kDetailText = callbackRuleIoMessageText(QString::fromStdString(kQueryResult.io.message));
            if (minifilterBypassStatusLabel_ != nullptr)
            {
                minifilterBypassStatusLabel_->setText(kernelText("kernel.callback.intercept.minifilter.status.refresh_failed", QStringLiteral("刷新失败：error=%1")).arg(kQueryResult.io.win32Error));
            }
            appendAppLog(kernelText("kernel.callback.intercept.minifilter.log.refresh_failed", QStringLiteral("Minifilter PID 放行刷新失败：error=%1，detail=%2"))
                .arg(kQueryResult.io.win32Error)
                .arg(kDetailText));
            return;
        }

        const unsigned long kSafeCount = std::min<unsigned long>(
            kQueryResult.response.pidCount,
            KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT);
        std::vector<std::uint32_t> processIds;
        processIds.reserve(static_cast<std::size_t>(kSafeCount));
        for (unsigned long pidIndex = 0UL; pidIndex < kSafeCount; ++pidIndex)
        {
            const unsigned long kProcessId = kQueryResult.response.processIds[pidIndex];
            if (kProcessId != 0UL)
            {
                processIds.push_back(static_cast<std::uint32_t>(kProcessId));
            }
        }

        populateMinifilterBypassPids(processIds);
        if (minifilterBypassStatusLabel_ != nullptr)
        {
            minifilterBypassStatusLabel_->setText(kernelText("kernel.callback.intercept.minifilter.status.refreshed", QStringLiteral("已从驱动刷新：%1 个 PID。")).arg(static_cast<qulonglong>(processIds.size())));
        }
        appendAppLog(kernelText("kernel.callback.intercept.minifilter.log.refreshed", QStringLiteral("Minifilter PID 放行已刷新：count=%1。")).arg(static_cast<qulonglong>(processIds.size())));
    }

    void createProcessProtectTab(QWidget* parentWidget)
    {
        // Input: Parent TabWidget.
        // Handling: Set up the master switch, protection rules table, trusted whitelist table, and statistics area.
        // Returns: none; the control pointer is stored in a member variable for use by button slot functions.
        if (ruleTabWidget_ == nullptr)
        {
            return;
        }

        auto* tabPage = new QWidget(parentWidget);
        auto* tabLayout = new QVBoxLayout(tabPage);
        tabLayout->setContentsMargins(8, 8, 8, 8);
        tabLayout->setSpacing(8);

        auto* hintLabel = new QLabel(
            kernelText("kernel.callback.intercept.process_protect.hint",
                QStringLiteral("命中保护规则的进程/线程句柄会在对象管理器前置回调里被削权：OpenProcess 仍然成功，但拿到的句柄不再带有被禁用的权限位。目标进程打开自己始终放行；信任项优先于保护规则。")),
            tabPage);
        hintLabel->setWordWrap(true);
        hintLabel->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
        tabLayout->addWidget(hintLabel, 0);

        auto* switchLayout = new QHBoxLayout();
        switchLayout->setContentsMargins(0, 0, 0, 0);
        switchLayout->setSpacing(12);
        processProtectEnabledCheck_ = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.switch.enabled", QStringLiteral("启用进程保护")), tabPage);
        processProtectLogCheck_ = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.switch.log", QStringLiteral("命中写驱动日志")), tabPage);
        processProtectTrustSystemCheck_ = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.switch.trust_system", QStringLiteral("信任 System 进程")), tabPage);
        processProtectTrustSystemCheck_->setChecked(true);
        processProtectTrustSystemCheck_->setToolTip(
            kernelText("kernel.callback.intercept.process_protect.switch.trust_system_tip",
                QStringLiteral("System(4) 负责进程创建与退出清理。关闭后这些系统路径也会被削权，可能导致进程无法正常结束。")));
        processProtectTrustPeersCheck_ = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.switch.trust_peers", QStringLiteral("受保护进程互信")), tabPage);
        processProtectKernelCheck_ = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.switch.kernel", QStringLiteral("启用内核 PP 层")), tabPage);
        processProtectKernelCheck_->setToolTip(
            kernelText("kernel.callback.intercept.process_protect.switch.kernel_tip",
                QStringLiteral("把目标进程打成 PP/PPL，交给 Windows 内核在所有句柄路径上强制执行；绕过本驱动回调也依然生效。")));
        processProtectSelfHealCheck_ = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.switch.self_heal", QStringLiteral("自愈巡检")), tabPage);
        processProtectSelfHealCheck_->setToolTip(
            kernelText("kernel.callback.intercept.process_protect.switch.self_heal_tip",
                QStringLiteral("周期性回读受保护进程的 Protection 字节，被外部改回时自动恢复并记一次篡改。")));
        processProtectScanIntervalSpin_ = new QSpinBox(tabPage);
        processProtectScanIntervalSpin_->setRange(
            static_cast<int>(KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MIN_MS),
            static_cast<int>(KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MAX_MS));
        processProtectScanIntervalSpin_->setSingleStep(500);
        processProtectScanIntervalSpin_->setValue(
            static_cast<int>(KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS));
        processProtectScanIntervalSpin_->setSuffix(
            kernelText("kernel.callback.intercept.process_protect.scan_interval_suffix", QStringLiteral(" ms")));
        processProtectScanIntervalSpin_->setToolTip(
            kernelText("kernel.callback.intercept.process_protect.scan_interval_tip", QStringLiteral("自愈巡检周期")));
        switchLayout->addWidget(processProtectEnabledCheck_, 0);
        switchLayout->addWidget(processProtectLogCheck_, 0);
        switchLayout->addWidget(processProtectTrustSystemCheck_, 0);
        switchLayout->addWidget(processProtectTrustPeersCheck_, 0);
        switchLayout->addWidget(processProtectKernelCheck_, 0);
        switchLayout->addWidget(processProtectSelfHealCheck_, 0);
        switchLayout->addWidget(processProtectScanIntervalSpin_, 0);
        switchLayout->addStretch(1);
        processProtectApplyButton_ = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.apply", QStringLiteral("应用到驱动")), tabPage);
        processProtectRefreshButton_ = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.refresh", QStringLiteral("从驱动刷新")), tabPage);
        processProtectClearButton_ = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.clear_apply", QStringLiteral("清空并应用")), tabPage);
        switchLayout->addWidget(processProtectApplyButton_, 0);
        switchLayout->addWidget(processProtectRefreshButton_, 0);
        switchLayout->addWidget(processProtectClearButton_, 0);
        tabLayout->addLayout(switchLayout, 0);

        auto* ruleInputLayout = new QHBoxLayout();
        ruleInputLayout->setContentsMargins(0, 0, 0, 0);
        ruleInputLayout->setSpacing(6);
        processProtectKindCombo_ = new QComboBox(tabPage);
        processProtectKindCombo_->addItem(
            processProtectKindText(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME));
        processProtectKindCombo_->addItem(
            processProtectKindText(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID));
        processProtectKindCombo_->addItem(
            processProtectKindText(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH));
        processProtectTargetEdit_ = new QLineEdit(tabPage);
        processProtectTargetEdit_->setPlaceholderText(
            kernelText("kernel.callback.intercept.process_protect.target_placeholder",
                QStringLiteral("受保护目标：映像名 notepad.exe / PID 1234 / 完整路径 C:\\Windows\\notepad.exe")));
        applyRuleLineEditStyle(processProtectTargetEdit_);
        processProtectPresetCombo_ = new QComboBox(tabPage);
        processProtectPresetCombo_->addItem(
            kernelText("kernel.callback.intercept.process_protect.preset.standard", QStringLiteral("标准：结束/写内存/建线程/挂起")),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_ACCESS_DEFAULT));
        processProtectPresetCombo_->addItem(
            kernelText("kernel.callback.intercept.process_protect.preset.strict", QStringLiteral("严格：全部危险权限")),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_ACCESS_ALL));
        processProtectPresetCombo_->addItem(
            kernelText("kernel.callback.intercept.process_protect.preset.terminate_only", QStringLiteral("仅防结束进程")),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE));
        processProtectThreadsCheck_ = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.protect_threads", QStringLiteral("含线程句柄")), tabPage);
        processProtectThreadsCheck_->setChecked(true);
        processProtectRuleNameEdit_ = new QLineEdit(tabPage);
        processProtectRuleNameEdit_->setPlaceholderText(
            kernelText("kernel.callback.intercept.process_protect.rule_name_placeholder", QStringLiteral("规则名（可选）")));
        applyRuleLineEditStyle(processProtectRuleNameEdit_);
        processProtectAddRuleButton_ = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.add_rule", QStringLiteral("添加规则")), tabPage);
        processProtectApplyPresetButton_ = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.apply_preset", QStringLiteral("套用到选中")), tabPage);
        processProtectRemoveRuleButton_ = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.remove_rule", QStringLiteral("移除选中")), tabPage);
        ruleInputLayout->addWidget(processProtectKindCombo_, 0);
        ruleInputLayout->addWidget(processProtectTargetEdit_, 2);
        ruleInputLayout->addWidget(processProtectPresetCombo_, 0);
        ruleInputLayout->addWidget(processProtectThreadsCheck_, 0);
        ruleInputLayout->addWidget(processProtectRuleNameEdit_, 1);
        ruleInputLayout->addWidget(processProtectAddRuleButton_, 0);
        ruleInputLayout->addWidget(processProtectApplyPresetButton_, 0);
        ruleInputLayout->addWidget(processProtectRemoveRuleButton_, 0);
        tabLayout->addLayout(ruleInputLayout, 0);

        // Kernel PP layer parameters are on a separate line: they determine whether 'Windows executes protection itself,' which is distinct from
        // the handle privilege reduction on the line above. Combining them on one line makes them easily mistaken for the same set of switches.
        auto* kernelInputLayout = new QHBoxLayout();
        kernelInputLayout->setContentsMargins(0, 0, 0, 0);
        kernelInputLayout->setSpacing(6);
        auto* kernelLabel = new QLabel(
            kernelText("kernel.callback.intercept.process_protect.kernel_label", QStringLiteral("内核保护档位")), tabPage);
        kernelLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textPrimaryHex()));
        processProtectKernelCombo_ = new QComboBox(tabPage);
        processProtectKernelCombo_->addItem(
            processProtectKernelProtectionText(0U), static_cast<uint>(0U));
        {
            static const char* const kSignerNames[] = {
                "Authenticode", "CodeGen", "Antimalware", "Lsa", "Windows", "WinTcb", "WinSystem"
            };
            const unsigned int kTypeValues[] = {
                KSWORD_PS_PROTECTED_TYPE_LIGHT,
                KSWORD_PS_PROTECTED_TYPE_FULL
            };
            for (const unsigned int kTypeValue : kTypeValues)
            {
                for (unsigned int signerIndex = 0U;
                     signerIndex < (sizeof(kSignerNames) / sizeof(kSignerNames[0]));
                     ++signerIndex)
                {
                    const unsigned int kProtectionByte = ((signerIndex + 1U) << 4U) | kTypeValue;
                    processProtectKernelCombo_->addItem(
                        processProtectKernelProtectionText(kProtectionByte),
                        static_cast<uint>(kProtectionByte));
                }
            }
        }
        processProtectApplyOnCreateCheck_ = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.guard.on_create", QStringLiteral("创建即用")), tabPage);
        processProtectApplyOnCreateCheck_->setChecked(true);
        processProtectApplyOnCreateCheck_->setToolTip(
            kernelText("kernel.callback.intercept.process_protect.guard.on_create_tip",
                QStringLiteral("目标进程重启后，在它开始执行之前重新打上保护。")));
        processProtectSelfHealRuleCheck_ = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.guard.self_heal", QStringLiteral("自愈")), tabPage);
        processProtectSelfHealRuleCheck_->setChecked(true);
        processProtectClearDebugPortCheck_ = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.guard.clear_debug_port", QStringLiteral("清调试端口")), tabPage);
        processProtectClearDebugPortCheck_->setToolTip(
            kernelText("kernel.callback.intercept.process_protect.guard.clear_debug_port_tip",
                QStringLiteral("清空 EPROCESS.DebugPort，让已附加的用户态调试器失去调试对象。")));
        processProtectApplyKernelButton_ = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.apply_kernel", QStringLiteral("套用内核档位到选中")), tabPage);
        kernelInputLayout->addWidget(kernelLabel, 0);
        kernelInputLayout->addWidget(processProtectKernelCombo_, 0);
        kernelInputLayout->addWidget(processProtectApplyOnCreateCheck_, 0);
        kernelInputLayout->addWidget(processProtectSelfHealRuleCheck_, 0);
        kernelInputLayout->addWidget(processProtectClearDebugPortCheck_, 0);
        kernelInputLayout->addWidget(processProtectApplyKernelButton_, 0);
        kernelInputLayout->addStretch(1);
        tabLayout->addLayout(kernelInputLayout, 0);

        processProtectRuleTable_ = new ks::ui::VisibleTableWidget(tabPage);
        processProtectRuleTable_->setColumnCount(static_cast<int>(ProcessProtectRuleColumn::kCount));
        processProtectRuleTable_->setHorizontalHeaderLabels(QStringList{
            kernelText("kernel.callback.intercept.process_protect.header.enabled", QStringLiteral("启用")),
            kernelText("kernel.callback.intercept.process_protect.header.kind", QStringLiteral("匹配方式")),
            kernelText("kernel.callback.intercept.process_protect.header.target", QStringLiteral("受保护目标")),
            kernelText("kernel.callback.intercept.process_protect.header.access", QStringLiteral("拦截的权限")),
            kernelText("kernel.callback.intercept.process_protect.header.threads", QStringLiteral("含线程")),
            kernelText("kernel.callback.intercept.process_protect.header.kernel", QStringLiteral("内核保护")),
            kernelText("kernel.callback.intercept.process_protect.header.guard", QStringLiteral("守护")),
            kernelText("kernel.callback.intercept.process_protect.header.rule_name", QStringLiteral("规则名")),
            kernelText("kernel.callback.intercept.process_protect.header.hits", QStringLiteral("削权次数")),
            kernelText("kernel.callback.intercept.process_protect.header.kernel_hits", QStringLiteral("施加次数"))
            });
        processProtectRuleTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        processProtectRuleTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        processProtectRuleTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        processProtectRuleTable_->setSortingEnabled(false);
        processProtectRuleTable_->setWordWrap(false);
        processProtectRuleTable_->verticalHeader()->setVisible(false);
        processProtectRuleTable_->setAlternatingRowColors(true);
        {
            QHeaderView* ruleHeader = processProtectRuleTable_->horizontalHeader();
            ruleHeader->setSectionResizeMode(QHeaderView::Interactive);
            ruleHeader->setStretchLastSection(false);
            processProtectRuleTable_->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::kEnabled), 48);
            processProtectRuleTable_->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::kKind), 86);
            processProtectRuleTable_->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::kTarget), 280);
            processProtectRuleTable_->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::kAccessMask), 280);
            processProtectRuleTable_->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::kProtectThreads), 62);
            processProtectRuleTable_->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::kKernelProtection), 168);
            processProtectRuleTable_->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::kGuard), 190);
            processProtectRuleTable_->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::kRuleName), 130);
            processProtectRuleTable_->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::kHitCount), 76);
            processProtectRuleTable_->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::kKernelApplyCount), 76);
        }
        processProtectRuleTable_->setStyleSheet(callbackRuleTableStyle());
        applyCallbackTableTransparency(processProtectRuleTable_);
        installCallbackTableCopyMenu(processProtectRuleTable_, -1);
        tabLayout->addWidget(processProtectRuleTable_, 3);

        auto* trustedLabel = new QLabel(
            kernelText("kernel.callback.intercept.process_protect.trusted_title",
                QStringLiteral("信任白名单（这些发起方打开受保护进程时不削权）")),
            tabPage);
        trustedLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textPrimaryHex()));
        tabLayout->addWidget(trustedLabel, 0);

        auto* trustedInputLayout = new QHBoxLayout();
        trustedInputLayout->setContentsMargins(0, 0, 0, 0);
        trustedInputLayout->setSpacing(6);
        processProtectTrustedKindCombo_ = new QComboBox(tabPage);
        processProtectTrustedKindCombo_->addItem(
            processProtectKindText(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME));
        processProtectTrustedKindCombo_->addItem(
            processProtectKindText(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID));
        processProtectTrustedKindCombo_->addItem(
            processProtectKindText(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH));
        processProtectTrustedTargetEdit_ = new QLineEdit(tabPage);
        processProtectTrustedTargetEdit_->setPlaceholderText(
            kernelText("kernel.callback.intercept.process_protect.trusted_placeholder",
                QStringLiteral("信任的发起方：映像名 / PID / 完整路径")));
        applyRuleLineEditStyle(processProtectTrustedTargetEdit_);
        processProtectTrustedAddButton_ = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.trusted_add", QStringLiteral("添加信任")), tabPage);
        processProtectTrustedRemoveButton_ = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.trusted_remove", QStringLiteral("移除选中")), tabPage);
        trustedInputLayout->addWidget(processProtectTrustedKindCombo_, 0);
        trustedInputLayout->addWidget(processProtectTrustedTargetEdit_, 1);
        trustedInputLayout->addWidget(processProtectTrustedAddButton_, 0);
        trustedInputLayout->addWidget(processProtectTrustedRemoveButton_, 0);
        tabLayout->addLayout(trustedInputLayout, 0);

        processProtectTrustedTable_ = new ks::ui::VisibleTableWidget(tabPage);
        processProtectTrustedTable_->setColumnCount(static_cast<int>(ProcessProtectTrustedColumn::kCount));
        processProtectTrustedTable_->setHorizontalHeaderLabels(QStringList{
            kernelText("kernel.callback.intercept.process_protect.header.kind", QStringLiteral("匹配方式")),
            kernelText("kernel.callback.intercept.process_protect.header.trusted_target", QStringLiteral("信任的发起方"))
            });
        processProtectTrustedTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        processProtectTrustedTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        processProtectTrustedTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        processProtectTrustedTable_->setSortingEnabled(false);
        processProtectTrustedTable_->setWordWrap(false);
        processProtectTrustedTable_->verticalHeader()->setVisible(false);
        processProtectTrustedTable_->horizontalHeader()->setSectionResizeMode(
            static_cast<int>(ProcessProtectTrustedColumn::kKind), QHeaderView::ResizeToContents);
        processProtectTrustedTable_->horizontalHeader()->setSectionResizeMode(
            static_cast<int>(ProcessProtectTrustedColumn::kTarget), QHeaderView::Stretch);
        processProtectTrustedTable_->setStyleSheet(callbackRuleTableStyle());
        applyCallbackTableTransparency(processProtectTrustedTable_);
        installCallbackTableCopyMenu(processProtectTrustedTable_, -1);
        tabLayout->addWidget(processProtectTrustedTable_, 1);

        processProtectStatusLabel_ = new QLabel(
            kernelText("kernel.callback.intercept.process_protect.status.not_refreshed",
                QStringLiteral("尚未从驱动刷新；编辑后点击“应用到驱动”生效。")),
            tabPage);
        processProtectStatusLabel_->setWordWrap(true);
        processProtectStatusLabel_->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
        tabLayout->addWidget(processProtectStatusLabel_, 0);

        ruleTabWidget_->addTab(
            tabPage,
            kernelText("kernel.callback.intercept.process_protect.tab", QStringLiteral("进程保护")));
    }

    QTableWidgetItem* makeProcessProtectCheckItem(const bool checkedState) const
    {
        auto* checkItem = new QTableWidgetItem();
        checkItem->setFlags((checkItem->flags() & ~Qt::ItemIsEditable) | Qt::ItemIsUserCheckable);
        checkItem->setCheckState(checkedState ? Qt::Checked : Qt::Unchecked);
        return checkItem;
    }

    bool appendProcessProtectRuleRow(
        const quint32 targetKind,
        const quint32 targetProcessId,
        const QString& targetImageText,
        const quint32 accessMask,
        const bool protectThreads,
        const bool ruleEnabled,
        const QString& ruleNameText,
        const qint64 hitCount,
        const quint32 kernelProtection,
        const quint32 guardRuleFlags,
        const quint32 hardenFlags,
        const qint64 kernelApplyCount)
    {
        // Input: A complete protection rule; Processing: append a read-only row after deduplication; checkable columns are directly selectable;
        // Returns: Returns true on successful append; returns false if duplicate or limit exceeded.
        if (processProtectRuleTable_ == nullptr)
        {
            return false;
        }
        if (processProtectRuleTable_->rowCount() >= static_cast<int>(KSWORD_ARK_PROCESS_PROTECT_MAX_RULES))
        {
            return false;
        }

        const QString kTargetText = (targetKind == KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID)
            ? QString::number(targetProcessId)
            : targetImageText;
        for (int rowIndex = 0; rowIndex < processProtectRuleTable_->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* kindItem =
                processProtectRuleTable_->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::kKind));
            const QTableWidgetItem* targetItem =
                processProtectRuleTable_->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::kTarget));
            if (kindItem == nullptr || targetItem == nullptr)
            {
                continue;
            }
            if (static_cast<quint32>(kindItem->data(Qt::UserRole).toUInt()) == targetKind &&
                targetItem->text().compare(kTargetText, Qt::CaseInsensitive) == 0)
            {
                return false;
            }
        }

        const int kRowIndex = processProtectRuleTable_->rowCount();
        processProtectRuleTable_->insertRow(kRowIndex);

        processProtectRuleTable_->setItem(
            kRowIndex, static_cast<int>(ProcessProtectRuleColumn::kEnabled), makeProcessProtectCheckItem(ruleEnabled));

        QTableWidgetItem* kindItem = makeReadOnlyItem(processProtectKindText(targetKind));
        kindItem->setData(Qt::UserRole, targetKind);
        processProtectRuleTable_->setItem(kRowIndex, static_cast<int>(ProcessProtectRuleColumn::kKind), kindItem);

        QTableWidgetItem* targetItem = makeReadOnlyItem(kTargetText);
        targetItem->setData(Qt::UserRole, targetProcessId);
        targetItem->setToolTip(kTargetText);
        processProtectRuleTable_->setItem(kRowIndex, static_cast<int>(ProcessProtectRuleColumn::kTarget), targetItem);

        QTableWidgetItem* accessItem = makeReadOnlyItem(processProtectAccessSummaryText(accessMask));
        accessItem->setData(Qt::UserRole, accessMask);
        processProtectRuleTable_->setItem(kRowIndex, static_cast<int>(ProcessProtectRuleColumn::kAccessMask), accessItem);

        processProtectRuleTable_->setItem(
            kRowIndex, static_cast<int>(ProcessProtectRuleColumn::kProtectThreads), makeProcessProtectCheckItem(protectThreads));

        QTableWidgetItem* kernelItem = makeReadOnlyItem(processProtectKernelProtectionText(kernelProtection));
        kernelItem->setData(Qt::UserRole, kernelProtection);
        processProtectRuleTable_->setItem(
            kRowIndex, static_cast<int>(ProcessProtectRuleColumn::kKernelProtection), kernelItem);

        // The guard column carries both rule flags and hardening flags: UserRole stores rule bits, and UserRole+1 stores hardening bits.
        QTableWidgetItem* guardItem =
            makeReadOnlyItem(processProtectGuardSummaryText(guardRuleFlags, hardenFlags));
        guardItem->setData(Qt::UserRole, guardRuleFlags);
        guardItem->setData(Qt::UserRole + 1, hardenFlags);
        processProtectRuleTable_->setItem(
            kRowIndex, static_cast<int>(ProcessProtectRuleColumn::kGuard), guardItem);

        processProtectRuleTable_->setItem(
            kRowIndex, static_cast<int>(ProcessProtectRuleColumn::kRuleName), makeReadOnlyItem(ruleNameText));

        processProtectRuleTable_->setItem(
            kRowIndex,
            static_cast<int>(ProcessProtectRuleColumn::kHitCount),
            makeReadOnlyItem(hitCount >= 0 ? QString::number(hitCount) : QStringLiteral("-")));
        processProtectRuleTable_->setItem(
            kRowIndex,
            static_cast<int>(ProcessProtectRuleColumn::kKernelApplyCount),
            makeReadOnlyItem(kernelApplyCount >= 0 ? QString::number(kernelApplyCount) : QStringLiteral("-")));
        return true;
    }

    // collectProcessProtectKernelInputs：
    // - Input: Kernel level dropdown and three daemon checkboxes;
    // - Processing: Read PS_PROTECTION byte, rule guard flags, and hardening flags.
    // - Return: None. The three out parameters remain 0 when controls are missing.
    void collectProcessProtectKernelInputs(
        quint32* const kernelProtectionOut,
        quint32* const guardRuleFlagsOut,
        quint32* const hardenFlagsOut) const
    {
        if (kernelProtectionOut != nullptr)
        {
            *kernelProtectionOut = processProtectKernelCombo_ != nullptr
                ? static_cast<quint32>(processProtectKernelCombo_->currentData().toUInt())
                : 0U;
        }
        if (guardRuleFlagsOut != nullptr)
        {
            quint32 guardFlags = 0U;
            if (processProtectApplyOnCreateCheck_ != nullptr && processProtectApplyOnCreateCheck_->isChecked())
            {
                guardFlags |= KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_APPLY_ON_CREATE;
            }
            if (processProtectSelfHealRuleCheck_ != nullptr && processProtectSelfHealRuleCheck_->isChecked())
            {
                guardFlags |= KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_SELF_HEAL;
            }
            *guardRuleFlagsOut = guardFlags;
        }
        if (hardenFlagsOut != nullptr)
        {
            *hardenFlagsOut =
                (processProtectClearDebugPortCheck_ != nullptr && processProtectClearDebugPortCheck_->isChecked())
                ? KSWORD_ARK_PROCESS_PROTECT_HARDEN_CLEAR_DEBUG_PORT
                : 0U;
        }
    }

    void applyProcessProtectKernelPresetToSelection()
    {
        // Input: Current selected row and kernel level control; Processing: Update the kernel protection and daemon columns for that row.
        // Return: None; changes apply only to the UI and require clicking 'Apply' to push.
        if (processProtectRuleTable_ == nullptr)
        {
            return;
        }
        const int kRowIndex = processProtectRuleTable_->currentRow();
        if (kRowIndex < 0)
        {
            return;
        }

        quint32 kernelProtection = 0U;
        quint32 guardRuleFlags = 0U;
        quint32 hardenFlags = 0U;
        collectProcessProtectKernelInputs(&kernelProtection, &guardRuleFlags, &hardenFlags);

        QTableWidgetItem* kernelItem =
            processProtectRuleTable_->item(kRowIndex, static_cast<int>(ProcessProtectRuleColumn::kKernelProtection));
        if (kernelItem != nullptr)
        {
            kernelItem->setText(processProtectKernelProtectionText(kernelProtection));
            kernelItem->setData(Qt::UserRole, kernelProtection);
        }
        QTableWidgetItem* guardItem =
            processProtectRuleTable_->item(kRowIndex, static_cast<int>(ProcessProtectRuleColumn::kGuard));
        if (guardItem != nullptr)
        {
            guardItem->setText(processProtectGuardSummaryText(guardRuleFlags, hardenFlags));
            guardItem->setData(Qt::UserRole, guardRuleFlags);
            guardItem->setData(Qt::UserRole + 1, hardenFlags);
        }
        setProcessProtectStatusText(
            kernelText("kernel.callback.intercept.process_protect.status.kernel_preset_applied",
                QStringLiteral("已套用内核档位到选中规则；点击“应用到驱动”后生效。")));
    }

    bool appendProcessProtectTrustedRow(
        const quint32 targetKind,
        const quint32 processId,
        const QString& imageText)
    {
        if (processProtectTrustedTable_ == nullptr)
        {
            return false;
        }
        if (processProtectTrustedTable_->rowCount() >= static_cast<int>(KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED))
        {
            return false;
        }

        const QString kTargetText = (targetKind == KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID)
            ? QString::number(processId)
            : imageText;
        for (int rowIndex = 0; rowIndex < processProtectTrustedTable_->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* kindItem =
                processProtectTrustedTable_->item(rowIndex, static_cast<int>(ProcessProtectTrustedColumn::kKind));
            const QTableWidgetItem* targetItem =
                processProtectTrustedTable_->item(rowIndex, static_cast<int>(ProcessProtectTrustedColumn::kTarget));
            if (kindItem == nullptr || targetItem == nullptr)
            {
                continue;
            }
            if (static_cast<quint32>(kindItem->data(Qt::UserRole).toUInt()) == targetKind &&
                targetItem->text().compare(kTargetText, Qt::CaseInsensitive) == 0)
            {
                return false;
            }
        }

        const int kRowIndex = processProtectTrustedTable_->rowCount();
        processProtectTrustedTable_->insertRow(kRowIndex);

        QTableWidgetItem* kindItem = makeReadOnlyItem(processProtectKindText(targetKind));
        kindItem->setData(Qt::UserRole, targetKind);
        processProtectTrustedTable_->setItem(kRowIndex, static_cast<int>(ProcessProtectTrustedColumn::kKind), kindItem);

        QTableWidgetItem* targetItem = makeReadOnlyItem(kTargetText);
        targetItem->setData(Qt::UserRole, processId);
        targetItem->setToolTip(kTargetText);
        processProtectTrustedTable_->setItem(kRowIndex, static_cast<int>(ProcessProtectTrustedColumn::kTarget), targetItem);
        return true;
    }

    // parseProcessProtectTargetInput：
    // - Input: Match method and user input text;
    // - Handling: PID mode requires a parseable non-zero value; image mode requires a non-empty value;
    // - Return: Returns true on success and writes PID/Image text; on failure, writes an error description.
    bool parseProcessProtectTargetInput(
        const quint32 targetKind,
        const QString& rawText,
        quint32* processIdOut,
        QString* imageTextOut,
        QString* errorTextOut) const
    {
        const QString kTrimmedText = rawText.trimmed();
        if (processIdOut != nullptr)
        {
            *processIdOut = 0U;
        }
        if (imageTextOut != nullptr)
        {
            imageTextOut->clear();
        }

        if (kTrimmedText.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.process_protect.error.empty_target", QStringLiteral("请输入受保护目标。"));
            }
            return false;
        }

        if (targetKind == KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID)
        {
            quint32 processId = 0U;
            if (!parseUnsignedText(kTrimmedText, &processId) || processId == 0U)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.process_protect.error.invalid_pid", QStringLiteral("PID 无效：%1")).arg(kTrimmedText);
                }
                return false;
            }
            if (processIdOut != nullptr)
            {
                *processIdOut = processId;
            }
            return true;
        }

        if (kTrimmedText.size() >= static_cast<int>(KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.process_protect.error.target_too_long", QStringLiteral("目标文本超过 %1 个字符。"))
                    .arg(KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS - 1U);
            }
            return false;
        }
        if (imageTextOut != nullptr)
        {
            *imageTextOut = kTrimmedText;
        }
        return true;
    }

    void addProcessProtectRuleFromInput()
    {
        if (processProtectKindCombo_ == nullptr ||
            processProtectTargetEdit_ == nullptr ||
            processProtectPresetCombo_ == nullptr)
        {
            return;
        }

        const quint32 kTargetKind = static_cast<quint32>(processProtectKindCombo_->currentData().toUInt());
        quint32 processId = 0U;
        QString imageText;
        QString errorText;
        if (!parseProcessProtectTargetInput(kTargetKind, processProtectTargetEdit_->text(), &processId, &imageText, &errorText))
        {
            QMessageBox::warning(
                hostPage_,
                kernelText("kernel.callback.intercept.process_protect.title", QStringLiteral("进程保护")),
                errorText);
            return;
        }

        const quint32 kAccessMask = static_cast<quint32>(processProtectPresetCombo_->currentData().toUInt());
        const QString kRuleNameText = processProtectRuleNameEdit_ != nullptr
            ? processProtectRuleNameEdit_->text().trimmed().left(KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS - 1U)
            : QString();
        const bool kProtectThreads = processProtectThreadsCheck_ != nullptr && processProtectThreadsCheck_->isChecked();
        quint32 kernelProtection = 0U;
        quint32 guardRuleFlags = 0U;
        quint32 hardenFlags = 0U;
        collectProcessProtectKernelInputs(&kernelProtection, &guardRuleFlags, &hardenFlags);

        if (!appendProcessProtectRuleRow(
                kTargetKind,
                processId,
                imageText,
                kAccessMask,
                kProtectThreads,
                true,
                kRuleNameText,
                -1,
                kernelProtection,
                guardRuleFlags,
                hardenFlags,
                -1))
        {
            setProcessProtectStatusText(
                kernelText("kernel.callback.intercept.process_protect.status.add_rejected",
                    QStringLiteral("规则未添加：目标重复或已达上限 %1 条。")).arg(KSWORD_ARK_PROCESS_PROTECT_MAX_RULES));
            return;
        }

        processProtectTargetEdit_->clear();
        if (processProtectRuleNameEdit_ != nullptr)
        {
            processProtectRuleNameEdit_->clear();
        }
        setProcessProtectStatusText(
            kernelText("kernel.callback.intercept.process_protect.status.rule_added",
                QStringLiteral("已添加规则；点击“应用到驱动”后生效。")));
    }

    void removeCurrentProcessProtectRule()
    {
        if (processProtectRuleTable_ == nullptr)
        {
            return;
        }
        const int kRowIndex = processProtectRuleTable_->currentRow();
        if (kRowIndex < 0)
        {
            return;
        }
        processProtectRuleTable_->removeRow(kRowIndex);
        setProcessProtectStatusText(
            kernelText("kernel.callback.intercept.process_protect.status.rule_removed",
                QStringLiteral("已移除选中规则；点击“应用到驱动”后生效。")));
    }

    void applyProcessProtectPresetToSelection()
    {
        // Input: Current selected row and preset combo box; Processing: Update the permission mask and thread toggle for that row.
        // Return: None; changes apply only to the UI and require clicking 'Apply' to push.
        if (processProtectRuleTable_ == nullptr || processProtectPresetCombo_ == nullptr)
        {
            return;
        }
        const int kRowIndex = processProtectRuleTable_->currentRow();
        if (kRowIndex < 0)
        {
            return;
        }

        const quint32 kAccessMask = static_cast<quint32>(processProtectPresetCombo_->currentData().toUInt());
        QTableWidgetItem* accessItem =
            processProtectRuleTable_->item(kRowIndex, static_cast<int>(ProcessProtectRuleColumn::kAccessMask));
        if (accessItem != nullptr)
        {
            accessItem->setText(processProtectAccessSummaryText(kAccessMask));
            accessItem->setData(Qt::UserRole, kAccessMask);
        }
        QTableWidgetItem* threadItem =
            processProtectRuleTable_->item(kRowIndex, static_cast<int>(ProcessProtectRuleColumn::kProtectThreads));
        if (threadItem != nullptr && processProtectThreadsCheck_ != nullptr)
        {
            threadItem->setCheckState(processProtectThreadsCheck_->isChecked() ? Qt::Checked : Qt::Unchecked);
        }
        setProcessProtectStatusText(
            kernelText("kernel.callback.intercept.process_protect.status.preset_applied",
                QStringLiteral("已套用预设到选中规则；点击“应用到驱动”后生效。")));
    }

    void addProcessProtectTrustedFromInput()
    {
        if (processProtectTrustedKindCombo_ == nullptr || processProtectTrustedTargetEdit_ == nullptr)
        {
            return;
        }

        const quint32 kTargetKind = static_cast<quint32>(processProtectTrustedKindCombo_->currentData().toUInt());
        quint32 processId = 0U;
        QString imageText;
        QString errorText;
        if (!parseProcessProtectTargetInput(kTargetKind, processProtectTrustedTargetEdit_->text(), &processId, &imageText, &errorText))
        {
            QMessageBox::warning(
                hostPage_,
                kernelText("kernel.callback.intercept.process_protect.title", QStringLiteral("进程保护")),
                errorText);
            return;
        }

        if (!appendProcessProtectTrustedRow(kTargetKind, processId, imageText))
        {
            setProcessProtectStatusText(
                kernelText("kernel.callback.intercept.process_protect.status.trusted_rejected",
                    QStringLiteral("信任项未添加：重复或已达上限 %1 条。")).arg(KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED));
            return;
        }

        processProtectTrustedTargetEdit_->clear();
        setProcessProtectStatusText(
            kernelText("kernel.callback.intercept.process_protect.status.trusted_added",
                QStringLiteral("已添加信任项；点击“应用到驱动”后生效。")));
    }

    void removeCurrentProcessProtectTrusted()
    {
        if (processProtectTrustedTable_ == nullptr)
        {
            return;
        }
        const int kRowIndex = processProtectTrustedTable_->currentRow();
        if (kRowIndex < 0)
        {
            return;
        }
        processProtectTrustedTable_->removeRow(kRowIndex);
        setProcessProtectStatusText(
            kernelText("kernel.callback.intercept.process_protect.status.trusted_removed",
                QStringLiteral("已移除选中信任项；点击“应用到驱动”后生效。")));
    }

    quint32 collectProcessProtectGlobalFlags() const
    {
        quint32 globalFlags = 0U;
        if (processProtectEnabledCheck_ != nullptr && processProtectEnabledCheck_->isChecked())
        {
            globalFlags |= KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED;
        }
        if (processProtectLogCheck_ != nullptr && processProtectLogCheck_->isChecked())
        {
            globalFlags |= KSWORD_ARK_PROCESS_PROTECT_FLAG_LOG_BLOCKED;
        }
        if (processProtectTrustSystemCheck_ != nullptr && processProtectTrustSystemCheck_->isChecked())
        {
            globalFlags |= KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_SYSTEM;
        }
        if (processProtectTrustPeersCheck_ != nullptr && processProtectTrustPeersCheck_->isChecked())
        {
            globalFlags |= KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_PROTECTED_PEERS;
        }
        if (processProtectKernelCheck_ != nullptr && processProtectKernelCheck_->isChecked())
        {
            globalFlags |= KSWORD_ARK_PROCESS_PROTECT_FLAG_KERNEL_PROTECTION;
        }
        if (processProtectSelfHealCheck_ != nullptr && processProtectSelfHealCheck_->isChecked())
        {
            globalFlags |= KSWORD_ARK_PROCESS_PROTECT_FLAG_SELF_HEAL_SCAN;
        }
        return globalFlags;
    }

    std::vector<KSWORD_ARK_PROCESS_PROTECT_RULE> collectProcessProtectRulesFromUi() const
    {
        // Input: rule table; Processing: assemble shared protocol rows line by line; ruleId renumbered by line order.
        // Returns: the rule array that can be directly passed to ArkDriverClient.
        std::vector<KSWORD_ARK_PROCESS_PROTECT_RULE> ruleList;
        if (processProtectRuleTable_ == nullptr)
        {
            return ruleList;
        }

        for (int rowIndex = 0; rowIndex < processProtectRuleTable_->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* enabledItem =
                processProtectRuleTable_->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::kEnabled));
            const QTableWidgetItem* kindItem =
                processProtectRuleTable_->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::kKind));
            const QTableWidgetItem* targetItem =
                processProtectRuleTable_->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::kTarget));
            const QTableWidgetItem* accessItem =
                processProtectRuleTable_->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::kAccessMask));
            const QTableWidgetItem* threadItem =
                processProtectRuleTable_->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::kProtectThreads));
            const QTableWidgetItem* nameItem =
                processProtectRuleTable_->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::kRuleName));
            const QTableWidgetItem* kernelItem =
                processProtectRuleTable_->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::kKernelProtection));
            const QTableWidgetItem* guardItem =
                processProtectRuleTable_->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::kGuard));
            if (kindItem == nullptr || targetItem == nullptr || accessItem == nullptr)
            {
                continue;
            }

            KSWORD_ARK_PROCESS_PROTECT_RULE protectRule{};
            protectRule.ruleId = static_cast<unsigned long>(rowIndex) + 1UL;
            protectRule.targetKind = static_cast<unsigned long>(kindItem->data(Qt::UserRole).toUInt());
            protectRule.protectAccessMask = static_cast<unsigned long>(accessItem->data(Qt::UserRole).toUInt());
            protectRule.kernelProtection = kernelItem != nullptr
                ? static_cast<unsigned long>(kernelItem->data(Qt::UserRole).toUInt())
                : 0UL;
            protectRule.hardenFlags = guardItem != nullptr
                ? static_cast<unsigned long>(guardItem->data(Qt::UserRole + 1).toUInt())
                : 0UL;
            if (guardItem != nullptr)
            {
                protectRule.flags |= static_cast<unsigned long>(guardItem->data(Qt::UserRole).toUInt());
            }
            if (enabledItem != nullptr && enabledItem->checkState() == Qt::Checked)
            {
                protectRule.flags |= KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED;
            }
            if (threadItem != nullptr && threadItem->checkState() == Qt::Checked)
            {
                protectRule.flags |= KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_PROTECT_THREADS;
            }
            if (protectRule.targetKind == KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID)
            {
                protectRule.targetProcessId = static_cast<unsigned long>(targetItem->data(Qt::UserRole).toUInt());
            }
            else
            {
                processProtectCopyQStringToFixedWide(
                    targetItem->text(), protectRule.targetImage, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
            }
            processProtectCopyQStringToFixedWide(
                nameItem != nullptr ? nameItem->text() : QString(),
                protectRule.ruleName,
                KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS);

            ruleList.push_back(protectRule);
        }
        return ruleList;
    }

    std::vector<KSWORD_ARK_PROCESS_PROTECT_TRUSTED> collectProcessProtectTrustedFromUi() const
    {
        std::vector<KSWORD_ARK_PROCESS_PROTECT_TRUSTED> trustedList;
        if (processProtectTrustedTable_ == nullptr)
        {
            return trustedList;
        }

        for (int rowIndex = 0; rowIndex < processProtectTrustedTable_->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* kindItem =
                processProtectTrustedTable_->item(rowIndex, static_cast<int>(ProcessProtectTrustedColumn::kKind));
            const QTableWidgetItem* targetItem =
                processProtectTrustedTable_->item(rowIndex, static_cast<int>(ProcessProtectTrustedColumn::kTarget));
            if (kindItem == nullptr || targetItem == nullptr)
            {
                continue;
            }

            KSWORD_ARK_PROCESS_PROTECT_TRUSTED trustedEntry{};
            trustedEntry.flags = KSWORD_ARK_PROCESS_PROTECT_TRUSTED_FLAG_ENABLED;
            trustedEntry.kind = static_cast<unsigned long>(kindItem->data(Qt::UserRole).toUInt());
            if (trustedEntry.kind == KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID)
            {
                trustedEntry.processId = static_cast<unsigned long>(targetItem->data(Qt::UserRole).toUInt());
            }
            else
            {
                processProtectCopyQStringToFixedWide(
                    targetItem->text(), trustedEntry.image, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
            }
            trustedList.push_back(trustedEntry);
        }
        return trustedList;
    }

    void setProcessProtectStatusText(const QString& statusText)
    {
        if (processProtectStatusLabel_ != nullptr)
        {
            processProtectStatusLabel_->setText(statusText);
        }
    }

    void applyProcessProtectToDriver()
    {
        // Input: current table and toggles; Processing: entire table dispatched to R0.
        // Return: None; immediately re-read upon success to align statistics and capability status with the driver.
        const std::vector<KSWORD_ARK_PROCESS_PROTECT_RULE> kRuleList = collectProcessProtectRulesFromUi();
        const std::vector<KSWORD_ARK_PROCESS_PROTECT_TRUSTED> kTrustedList = collectProcessProtectTrustedFromUi();
        const quint32 kGlobalFlags = collectProcessProtectGlobalFlags();

        const unsigned long kScanIntervalMs = processProtectScanIntervalSpin_ != nullptr
            ? static_cast<unsigned long>(processProtectScanIntervalSpin_->value())
            : KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS;

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::IoResult kIoResult =
            kDriverClient.setProcessProtectConfig(kGlobalFlags, kRuleList, kTrustedList, kScanIntervalMs);
        if (!kIoResult.ok)
        {
            const QString kDetailText = callbackRuleIoMessageText(QString::fromStdString(kIoResult.message));
            setProcessProtectStatusText(
                kernelText("kernel.callback.intercept.process_protect.status.apply_failed", QStringLiteral("应用失败：error=%1"))
                .arg(kIoResult.win32Error));
            appendAppLog(
                kernelText("kernel.callback.intercept.process_protect.log.apply_failed", QStringLiteral("进程保护配置应用失败：error=%1，detail=%2"))
                .arg(kIoResult.win32Error)
                .arg(kDetailText));
            QMessageBox::warning(
                hostPage_,
                kernelText("kernel.callback.intercept.process_protect.title", QStringLiteral("进程保护")),
                kernelText("kernel.callback.intercept.process_protect.error.apply_to_driver", QStringLiteral("应用到驱动失败，error=%1。"))
                .arg(kIoResult.win32Error));
            return;
        }

        appendAppLog(
            kernelText("kernel.callback.intercept.process_protect.log.applied", QStringLiteral("进程保护配置已应用：rules=%1，trusted=%2，flags=0x%3。"))
            .arg(static_cast<qulonglong>(kRuleList.size()))
            .arg(static_cast<qulonglong>(kTrustedList.size()))
            .arg(kGlobalFlags, 8, 16, QChar('0')));
        refreshProcessProtectFromDriver();
    }

    void clearProcessProtectAndApply()
    {
        if (processProtectRuleTable_ != nullptr)
        {
            processProtectRuleTable_->setRowCount(0);
        }
        if (processProtectTrustedTable_ != nullptr)
        {
            processProtectTrustedTable_->setRowCount(0);
        }
        if (processProtectEnabledCheck_ != nullptr)
        {
            processProtectEnabledCheck_->setChecked(false);
        }
        applyProcessProtectToDriver();
    }

    void refreshProcessProtectFromDriver()
    {
        // Input: none; Processing: re-read R0 current configuration and rebuild both tables.
        // Return: None; on failure, only update the status bar and log without clearing local edit content.
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::ProcessProtectStateResult kQueryResult = kDriverClient.queryProcessProtectState();
        if (!kQueryResult.io.ok)
        {
            const QString kDetailText = callbackRuleIoMessageText(QString::fromStdString(kQueryResult.io.message));
            setProcessProtectStatusText(
                kernelText("kernel.callback.intercept.process_protect.status.refresh_failed", QStringLiteral("刷新失败：error=%1"))
                .arg(kQueryResult.io.win32Error));
            appendAppLog(
                kernelText("kernel.callback.intercept.process_protect.log.refresh_failed", QStringLiteral("进程保护状态刷新失败：error=%1，detail=%2"))
                .arg(kQueryResult.io.win32Error)
                .arg(kDetailText));
            return;
        }

        const KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE& stateResponse = kQueryResult.response;
        if (processProtectEnabledCheck_ != nullptr)
        {
            processProtectEnabledCheck_->setChecked((stateResponse.globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED) != 0U);
        }
        if (processProtectLogCheck_ != nullptr)
        {
            processProtectLogCheck_->setChecked((stateResponse.globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_LOG_BLOCKED) != 0U);
        }
        if (processProtectTrustSystemCheck_ != nullptr)
        {
            processProtectTrustSystemCheck_->setChecked((stateResponse.globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_SYSTEM) != 0U);
        }
        if (processProtectTrustPeersCheck_ != nullptr)
        {
            processProtectTrustPeersCheck_->setChecked((stateResponse.globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_PROTECTED_PEERS) != 0U);
        }
        if (processProtectKernelCheck_ != nullptr)
        {
            processProtectKernelCheck_->setChecked((stateResponse.globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_KERNEL_PROTECTION) != 0U);
        }
        if (processProtectSelfHealCheck_ != nullptr)
        {
            processProtectSelfHealCheck_->setChecked((stateResponse.globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_SELF_HEAL_SCAN) != 0U);
        }
        if (processProtectScanIntervalSpin_ != nullptr && stateResponse.scanIntervalMs != 0U)
        {
            processProtectScanIntervalSpin_->setValue(static_cast<int>(stateResponse.scanIntervalMs));
        }

        if (processProtectRuleTable_ != nullptr)
        {
            processProtectRuleTable_->setRowCount(0);
        }
        const unsigned long kSafeRuleCount =
            std::min<unsigned long>(stateResponse.ruleCount, KSWORD_ARK_PROCESS_PROTECT_MAX_RULES);
        for (unsigned long ruleIndex = 0UL; ruleIndex < kSafeRuleCount; ++ruleIndex)
        {
            const KSWORD_ARK_PROCESS_PROTECT_RULE& protectRule = stateResponse.rules[ruleIndex];
            appendProcessProtectRuleRow(
                static_cast<quint32>(protectRule.targetKind),
                static_cast<quint32>(protectRule.targetProcessId),
                processProtectFixedWideToQString(protectRule.targetImage, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS),
                static_cast<quint32>(protectRule.protectAccessMask),
                (protectRule.flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_PROTECT_THREADS) != 0UL,
                (protectRule.flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED) != 0UL,
                processProtectFixedWideToQString(protectRule.ruleName, KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS),
                static_cast<qint64>(stateResponse.ruleHitCounts[ruleIndex]),
                static_cast<quint32>(protectRule.kernelProtection),
                static_cast<quint32>(protectRule.flags &
                    (KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_APPLY_ON_CREATE |
                     KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_SELF_HEAL)),
                static_cast<quint32>(protectRule.hardenFlags),
                static_cast<qint64>(stateResponse.ruleKernelApplyCounts[ruleIndex]));
        }

        if (processProtectTrustedTable_ != nullptr)
        {
            processProtectTrustedTable_->setRowCount(0);
        }
        const unsigned long kSafeTrustedCount =
            std::min<unsigned long>(stateResponse.trustedCount, KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED);
        for (unsigned long trustedIndex = 0UL; trustedIndex < kSafeTrustedCount; ++trustedIndex)
        {
            const KSWORD_ARK_PROCESS_PROTECT_TRUSTED& trustedEntry = stateResponse.trusted[trustedIndex];
            appendProcessProtectTrustedRow(
                static_cast<quint32>(trustedEntry.kind),
                static_cast<quint32>(trustedEntry.processId),
                processProtectFixedWideToQString(trustedEntry.image, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS));
        }

        setProcessProtectStatusText(buildProcessProtectStatusText(stateResponse));
    }

    // buildProcessProtectStatusText：
    // - Input: R0 status packet;
    // - Processing: Concatenate capability status, counter, and last interception.
    // - Returns: status bar display text.
    QString buildProcessProtectStatusText(const KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE& stateResponse) const
    {
        QStringList statusParts;
        if (stateResponse.capabilityStatus == KSWORD_ARK_PROCESS_PROTECT_STATUS_CALLBACK_UNAVAILABLE)
        {
            statusParts << kernelText("kernel.callback.intercept.process_protect.status.callback_unavailable",
                QStringLiteral("对象回调未注册（status=0x%1），本机无法执行进程保护。"))
                .arg(static_cast<quint32>(stateResponse.objectCallbackStatus), 8, 16, QChar('0'));
        }
        else
        {
            statusParts << kernelText("kernel.callback.intercept.process_protect.status.summary",
                QStringLiteral("已从驱动刷新：规则 %1 条，信任 %2 条，配置版本 %3。"))
                .arg(stateResponse.ruleCount)
                .arg(stateResponse.trustedCount)
                .arg(static_cast<qulonglong>(stateResponse.configVersion));
        }

        statusParts << kernelText("kernel.callback.intercept.process_protect.status.counters",
            QStringLiteral("判定 %1 次，削权 %2 次，信任放行 %3 次。"))
            .arg(static_cast<qulonglong>(stateResponse.evaluatedCount))
            .arg(static_cast<qulonglong>(stateResponse.strippedCount))
            .arg(static_cast<qulonglong>(stateResponse.trustedBypassCount));

        statusParts << kernelText("kernel.callback.intercept.process_protect.status.kernel_counters",
            QStringLiteral("内核层：施加 %1 次，自愈 %2 次，失败 %3 次，加固 %4 次，在管进程 %5 个，巡检 %6ms。"))
            .arg(static_cast<qulonglong>(stateResponse.kernelApplyCount))
            .arg(static_cast<qulonglong>(stateResponse.selfHealCount))
            .arg(static_cast<qulonglong>(stateResponse.kernelApplyFailureCount))
            .arg(static_cast<qulonglong>(stateResponse.hardenApplyCount))
            .arg(stateResponse.trackedProcessCount)
            .arg(stateResponse.scanIntervalMs);

        if (stateResponse.lastKernelApplyStatus != 0)
        {
            statusParts << kernelText("kernel.callback.intercept.process_protect.status.kernel_last_failure",
                QStringLiteral("最近一次施加失败 status=0x%1（通常是本机 DynData 缺少 EPROCESS 偏移）。"))
                .arg(static_cast<quint32>(stateResponse.lastKernelApplyStatus), 8, 16, QChar('0'));
        }

        if (stateResponse.lastTamperUtc100ns != 0ULL)
        {
            const QString kTamperImageText =
                processProtectFixedWideToQString(stateResponse.lastTamperImage, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
            statusParts << kernelText("kernel.callback.intercept.process_protect.status.last_tamper",
                QStringLiteral("最近一次篡改：%1 PID %2（%3）的保护被改成 0x%4，已恢复为 0x%5，规则 %6。"))
                .arg(utc100nsToDisplayText(static_cast<quint64>(stateResponse.lastTamperUtc100ns)))
                .arg(stateResponse.lastTamperProcessId)
                .arg(kTamperImageText.isEmpty() ? QStringLiteral("-") : kTamperImageText)
                .arg(stateResponse.lastTamperObservedProtection, 2, 16, QChar('0'))
                .arg(stateResponse.lastTamperExpectedProtection, 2, 16, QChar('0'))
                .arg(stateResponse.lastTamperRuleId);
        }

        if (stateResponse.lastBlockedUtc100ns != 0ULL)
        {
            const QString kInitiatorText =
                processProtectFixedWideToQString(stateResponse.lastBlockedInitiatorImage, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
            const QString kTargetText =
                processProtectFixedWideToQString(stateResponse.lastBlockedTargetImage, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
            statusParts << kernelText("kernel.callback.intercept.process_protect.status.last_blocked",
                QStringLiteral("最近一次：%1 发起方 PID %2（%3）访问 PID %4（%5），规则 %6，0x%7 → 0x%8。"))
                .arg(utc100nsToDisplayText(static_cast<quint64>(stateResponse.lastBlockedUtc100ns)))
                .arg(stateResponse.lastBlockedInitiatorPid)
                .arg(kInitiatorText.isEmpty() ? QStringLiteral("-") : kInitiatorText)
                .arg(stateResponse.lastBlockedTargetPid)
                .arg(kTargetText.isEmpty() ? QStringLiteral("-") : kTargetText)
                .arg(stateResponse.lastBlockedRuleId)
                .arg(stateResponse.lastBlockedOriginalAccess, 8, 16, QChar('0'))
                .arg(stateResponse.lastBlockedGrantedAccess, 8, 16, QChar('0'));
        }
        return statusParts.join(QLatin1Char(' '));
    }

    void createRuleTableTab(quint32 callbackType, const QString& titleText)
    {
        auto* tabPage = new QWidget(ruleTabWidget_);
        auto* tabLayout = new QVBoxLayout(tabPage);
        tabLayout->setContentsMargins(0, 0, 0, 0);
        tabLayout->setSpacing(0);

        auto* ruleTable = new ks::ui::VisibleTableWidget(tabPage);
        ruleTable->setColumnCount(static_cast<int>(RuleColumn::kCount));
        ruleTable->setHorizontalHeaderLabels(QStringList{
            kernelText("kernel.callback.intercept.rule.header.enabled", QStringLiteral("启用")),
            QStringLiteral("RuleID"),
            QStringLiteral("GroupID"),
            kernelText("kernel.callback.intercept.rule.header.name", QStringLiteral("规则名称")),
            kernelText("kernel.callback.intercept.rule.header.operation", QStringLiteral("操作类型")),
            kernelText("kernel.callback.intercept.rule.header.match_mode", QStringLiteral("匹配模式")),
            kernelText("kernel.callback.intercept.rule.header.action", QStringLiteral("动作")),
            kernelText("kernel.callback.intercept.rule.header.timeout_ms", QStringLiteral("超时毫秒")),
            kernelText("kernel.callback.intercept.rule.header.timeout_decision", QStringLiteral("超时决策")),
            kernelText("kernel.callback.intercept.rule.header.priority", QStringLiteral("优先级"))
            });
        ruleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        ruleTable->setSelectionMode(QAbstractItemView::SingleSelection);
        ruleTable->setEditTriggers(
            QAbstractItemView::DoubleClicked |
            QAbstractItemView::SelectedClicked |
            QAbstractItemView::EditKeyPressed);
        ruleTable->setItemDelegate(new OpaqueTableEditorDelegate(ruleTable));
        ruleTable->setProperty("ksword_preserve_custom_table_delegate", true);
        ruleTable->setSortingEnabled(false);
        ruleTable->setWordWrap(false);
        ruleTable->setContextMenuPolicy(Qt::CustomContextMenu);
        ruleTable->verticalHeader()->setVisible(false);
        ruleTable->setAlternatingRowColors(true);
        ruleTable->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        ruleTable->setStyleSheet(callbackRuleTableStyle());
        applyCallbackTableTransparency(ruleTable);

        // The header allows users to drag and resize columns; by default, the identity column is compressed first to allocate more space for action and match fields.
        QHeaderView* ruleHeader = ruleTable->horizontalHeader();
        ruleHeader->setSectionResizeMode(QHeaderView::Interactive);
        ruleHeader->setStretchLastSection(false);
        ruleHeader->setSectionsMovable(false);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::kEnabled), 42);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::kRuleId), 58);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::kGroupId), 96);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::kRuleName), 170);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::kOperationMask), 480);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::kMatchMode), 104);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::kAction), 104);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::kTimeoutMs), 72);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::kTimeoutDefaultDecision), 78);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::kPriority), 58);
        tabLayout->addWidget(ruleTable, 1);

        connect(ruleTable, &QTableWidget::itemChanged, hostPage_, [this](QTableWidgetItem*) {
            if (ignoreUiSignal_)
            {
                return;
            }
            setDirtyState(true);
        });
        connect(ruleTable, &QWidget::customContextMenuRequested, hostPage_, [this, ruleTable, callbackType](const QPoint& localPos) {
            showRuleTableContextMenu(ruleTable, callbackType, localPos);
        });

        const int kTabIndex = ruleTabWidget_->addTab(tabPage, titleText);
        tabCallbackTypeMap_.insert(kTabIndex, callbackType);
        ruleTableMap_.insert(callbackType, ruleTable);
    }

    bool collectRuleByLogicalIndex(
        QTableWidget* ruleTable,
        const quint32 callbackType,
        const int logicalRuleIndex,
        CallbackRuleModel* ruleOut,
        QString* errorTextOut) const
    {
        if (ruleOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_out_null", QStringLiteral("内部错误：ruleOut 为空。"));
            }
            return false;
        }
        if (ruleTable == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_table_null", QStringLiteral("内部错误：ruleTable 为空。"));
            }
            return false;
        }

        QList<CallbackRuleModel> ruleList;
        if (!collectRuleListFromTable(ruleTable, callbackType, &ruleList, errorTextOut))
        {
            return false;
        }
        if (logicalRuleIndex < 0 || logicalRuleIndex >= ruleList.size())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.no_selected_rule", QStringLiteral("当前未选中有效规则。"));
            }
            return false;
        }

        *ruleOut = ruleList.at(logicalRuleIndex);
        return true;
    }

    void copyCurrentRuleToClipboard(
        QTableWidget* ruleTable,
        const quint32 callbackType)
    {
        if (ruleTable == nullptr)
        {
            return;
        }

        const int kLogicalRuleIndex = currentRuleLogicalIndex(ruleTable);
        if (kLogicalRuleIndex < 0)
        {
            return;
        }

        CallbackRuleModel selectedRuleModel;
        QString errorText;
        if (!collectRuleByLogicalIndex(
            ruleTable,
            callbackType,
            kLogicalRuleIndex,
            &selectedRuleModel,
            &errorText))
        {
            QMessageBox::warning(
                hostPage_,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.clipboard.copy_failed", QStringLiteral("复制规则失败：%1")).arg(errorText));
            appendAppLog(kernelText("kernel.callback.intercept.clipboard.copy_failed", QStringLiteral("复制规则失败：%1")).arg(errorText));
            return;
        }

        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard == nullptr)
        {
            appendAppLog(kernelText("kernel.callback.intercept.clipboard.unavailable_copy", QStringLiteral("复制规则失败：系统剪贴板不可用。")));
            return;
        }

        clipboard->setText(serializeRuleToClipboardText(selectedRuleModel));
        appendAppLog(
            kernelText("kernel.callback.intercept.clipboard.copy_success", QStringLiteral("已复制规则到剪贴板：ruleId=%1，类型=%2"))
            .arg(selectedRuleModel.ruleId)
            .arg(callbackTypeToDisplayText(callbackType)));
    }

    void pasteRuleFromClipboard(
        QTableWidget* ruleTable,
        const quint32 callbackType)
    {
        if (ruleTable == nullptr)
        {
            return;
        }

        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard == nullptr)
        {
            QMessageBox::warning(
                hostPage_,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.clipboard.unavailable_paste", QStringLiteral("粘贴失败：系统剪贴板不可用。")));
            appendAppLog(kernelText("kernel.callback.intercept.clipboard.unavailable_paste", QStringLiteral("粘贴失败：系统剪贴板不可用。")));
            return;
        }

        const QString kClipboardText = clipboard->text().trimmed();
        if (kClipboardText.isEmpty())
        {
            QMessageBox::information(
                hostPage_,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.clipboard.empty", QStringLiteral("剪贴板为空，无法粘贴规则。")));
            return;
        }

        CallbackRuleModel pastedRuleModel;
        QString parseErrorText;
        if (!deserializeRuleFromClipboardText(kClipboardText, &pastedRuleModel, &parseErrorText))
        {
            QMessageBox::warning(
                hostPage_,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.clipboard.paste_failed", QStringLiteral("粘贴失败：%1")).arg(parseErrorText));
            appendAppLog(kernelText("kernel.callback.intercept.clipboard.paste_failed", QStringLiteral("粘贴失败：%1")).arg(parseErrorText));
            return;
        }

        const quint32 kSourceCallbackType = pastedRuleModel.callbackType;
        pastedRuleModel.ruleId = allocateNextRuleId();
        pastedRuleModel.callbackType = callbackType;
        pastedRuleModel.initiatorPattern = normalizeMatchAllPattern(pastedRuleModel.initiatorPattern);
        pastedRuleModel.targetPattern = normalizeMatchAllPattern(pastedRuleModel.targetPattern);
        if (pastedRuleModel.ruleName.trimmed().isEmpty())
        {
            pastedRuleModel.ruleName = kernelText("kernel.callback.intercept.clipboard.default_rule_name", QStringLiteral("规则%1")).arg(pastedRuleModel.ruleId);
        }
        if (pastedRuleModel.comment.trimmed().isEmpty())
        {
            pastedRuleModel.comment = kernelText("kernel.callback.intercept.clipboard.pasted_rule_comment", QStringLiteral("粘贴规则"));
        }

        addDefaultGroupIfNeeded();
        if (!groupExists(pastedRuleModel.groupId))
        {
            pastedRuleModel.groupId = firstGroupId();
        }
        if (pastedRuleModel.groupId == 0U)
        {
            QMessageBox::warning(
                hostPage_,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.clipboard.no_group", QStringLiteral("粘贴失败：当前没有可用规则组。")));
            appendAppLog(kernelText("kernel.callback.intercept.clipboard.no_group", QStringLiteral("粘贴失败：当前没有可用规则组。")));
            return;
        }

        if (pastedRuleModel.operationMask == 0U)
        {
            pastedRuleModel.operationMask = defaultOperationMaskByType(callbackType);
        }

        const QList<QPair<QString, quint32>> kMatchModeOptionList = allowedMatchModeListByType(callbackType);
        if (!containsOptionValue(kMatchModeOptionList, pastedRuleModel.matchMode))
        {
            pastedRuleModel.matchMode = kMatchModeOptionList.isEmpty()
                ? KSWORD_ARK_MATCH_MODE_EXACT
                : kMatchModeOptionList.front().second;
        }

        const QList<QPair<QString, quint32>> kActionOptionList = allowedActionListByType(callbackType);
        if (!containsOptionValue(kActionOptionList, pastedRuleModel.action))
        {
            pastedRuleModel.action = kActionOptionList.isEmpty()
                ? KSWORD_ARK_RULE_ACTION_LOG_ONLY
                : kActionOptionList.front().second;
        }

        if ((callbackType == KSWORD_ARK_CALLBACK_TYPE_REGISTRY ||
            callbackType == KSWORD_ARK_CALLBACK_TYPE_MINIFILTER) &&
            pastedRuleModel.matchMode == KSWORD_ARK_MATCH_MODE_REGEX &&
            pastedRuleModel.action != KSWORD_ARK_RULE_ACTION_ASK_USER &&
            containsOptionValue(kActionOptionList, KSWORD_ARK_RULE_ACTION_ASK_USER))
        {
            pastedRuleModel.action = KSWORD_ARK_RULE_ACTION_ASK_USER;
        }

        if (pastedRuleModel.action == KSWORD_ARK_RULE_ACTION_ASK_USER)
        {
            if (pastedRuleModel.timeoutMs == 0U)
            {
                pastedRuleModel.timeoutMs = 5000U;
            }
        }
        else
        {
            pastedRuleModel.timeoutMs = 0U;
        }
        if (pastedRuleModel.timeoutDefaultDecision != KSWORD_ARK_DECISION_ALLOW &&
            pastedRuleModel.timeoutDefaultDecision != KSWORD_ARK_DECISION_DENY)
        {
            pastedRuleModel.timeoutDefaultDecision = KSWORD_ARK_DECISION_ALLOW;
        }

        pastedRuleModel.priority = (ruleCountOfTable(ruleTable) + 1) * 10;

        ignoreUiSignal_ = true;
        appendRuleRow(ruleTable, callbackType, pastedRuleModel);
        ignoreUiSignal_ = false;

        const int kNewHeaderRow = ruleTable->rowCount() - 2;
        if (kNewHeaderRow >= 0)
        {
            ruleTable->setCurrentCell(kNewHeaderRow, static_cast<int>(RuleColumn::kRuleName));
        }
        setDirtyState(true);

        if (kSourceCallbackType != callbackType)
        {
            appendAppLog(
                kernelText("kernel.callback.intercept.clipboard.type_converted", QStringLiteral("剪贴板规则类型已转换：%1 -> %2"))
                .arg(callbackTypeToDisplayText(kSourceCallbackType))
                .arg(callbackTypeToDisplayText(callbackType)));
        }
        appendAppLog(kernelText("kernel.callback.intercept.clipboard.paste_success", QStringLiteral("已从剪贴板粘贴规则：newRuleId=%1")).arg(pastedRuleModel.ruleId));
    }

    void showRuleTableContextMenu(
        QTableWidget* ruleTable,
        const quint32 callbackType,
        const QPoint& localPos)
    {
        if (ruleTable == nullptr)
        {
            return;
        }

        const int kClickedRow = ruleTable->rowAt(localPos.y());
        if (kClickedRow >= 0)
        {
            const int kHeaderRow = normalizeRuleHeaderRow(kClickedRow);
            if (kHeaderRow >= 0)
            {
                ruleTable->setCurrentCell(kHeaderRow, static_cast<int>(RuleColumn::kRuleName));
            }
        }

        const int kLogicalRuleIndex = currentRuleLogicalIndex(ruleTable);
        const int kRuleCount = ruleCountOfTable(ruleTable);
        const bool kHasCurrentRule = (kLogicalRuleIndex >= 0 && kLogicalRuleIndex < kRuleCount);

        QMenu contextMenu(ruleTable);
        contextMenu.setStyleSheet(callbackRuleContextMenuStyle());
        QAction* addRuleAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/plus.svg")),
            kernelText("kernel.callback.intercept.context_menu.add_rule", QStringLiteral("新增规则")));
        QAction* removeRuleAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/log_clear.svg")),
            kernelText("kernel.callback.intercept.context_menu.remove_rule", QStringLiteral("删除当前规则")));
        QAction* moveUpRuleAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/file_nav_up.svg")),
            kernelText("kernel.callback.intercept.context_menu.move_up", QStringLiteral("上移当前规则")));
        QAction* moveDownRuleAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/codeeditor_goto.svg")),
            kernelText("kernel.callback.intercept.context_menu.move_down", QStringLiteral("下移当前规则")));
        contextMenu.addSeparator();
        QAction* copyRuleAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
            kernelText("kernel.callback.intercept.context_menu.copy_rule", QStringLiteral("复制规则文本")));
        QAction* pasteRuleAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/codeeditor_paste.svg")),
            kernelText("kernel.callback.intercept.context_menu.paste_rule", QStringLiteral("粘贴为新规则")));

        removeRuleAction->setEnabled(kHasCurrentRule);
        moveUpRuleAction->setEnabled(kHasCurrentRule && kLogicalRuleIndex > 0);
        moveDownRuleAction->setEnabled(kHasCurrentRule && kLogicalRuleIndex < (kRuleCount - 1));
        copyRuleAction->setEnabled(kHasCurrentRule);
        pasteRuleAction->setEnabled(QApplication::clipboard() != nullptr &&
            !QApplication::clipboard()->text().trimmed().isEmpty());

        QAction* selectedAction = contextMenu.exec(ruleTable->viewport()->mapToGlobal(localPos));
        if (selectedAction == nullptr)
        {
            return;
        }

        if (ruleTabWidget_ != nullptr)
        {
            const int kTabIndex = tabCallbackTypeMap_.key(callbackType, -1);
            if (kTabIndex >= 0 && kTabIndex != ruleTabWidget_->currentIndex())
            {
                ruleTabWidget_->setCurrentIndex(kTabIndex);
            }
        }

        if (selectedAction == addRuleAction)
        {
            addRuleToCurrentTab();
            return;
        }
        if (selectedAction == removeRuleAction)
        {
            removeCurrentRule();
            return;
        }
        if (selectedAction == moveUpRuleAction)
        {
            moveCurrentRule(-1);
            return;
        }
        if (selectedAction == moveDownRuleAction)
        {
            moveCurrentRule(1);
            return;
        }
        if (selectedAction == copyRuleAction)
        {
            copyCurrentRuleToClipboard(ruleTable, callbackType);
            return;
        }
        if (selectedAction == pasteRuleAction)
        {
            pasteRuleFromClipboard(ruleTable, callbackType);
            return;
        }
    }

    void addDefaultGroupIfNeeded()
    {
        if (groupTable_->rowCount() > 0)
        {
            return;
        }

        CallbackRuleGroupModel defaultGroup;
        defaultGroup.groupId = 1U;
        defaultGroup.groupName = kernelText("kernel.callback.intercept.default_group.name", QStringLiteral("默认组"));
        defaultGroup.enabled = true;
        defaultGroup.priority = 10;
        defaultGroup.comment = kernelText("kernel.callback.intercept.default_group.comment", QStringLiteral("默认规则组"));
        appendGroupRow(defaultGroup);
        groupTable_->setCurrentCell(0, static_cast<int>(GroupColumn::kName));
    }

    void appendGroupRow(const CallbackRuleGroupModel& groupModel)
    {
        const int kRowIndex = groupTable_->rowCount();
        groupTable_->insertRow(kRowIndex);

        groupTable_->setItem(kRowIndex, static_cast<int>(GroupColumn::kId), makeReadOnlyItem(QString::number(groupModel.groupId)));
        groupTable_->setItem(kRowIndex, static_cast<int>(GroupColumn::kName), new QTableWidgetItem(groupModel.groupName));

        auto* enabledItem = new QTableWidgetItem();
        enabledItem->setFlags(enabledItem->flags() | Qt::ItemIsUserCheckable);
        enabledItem->setCheckState(groupModel.enabled ? Qt::Checked : Qt::Unchecked);
        groupTable_->setItem(kRowIndex, static_cast<int>(GroupColumn::kEnabled), enabledItem);

        groupTable_->setItem(kRowIndex, static_cast<int>(GroupColumn::kPriority), new QTableWidgetItem(QString::number(groupModel.priority)));
        groupTable_->setItem(kRowIndex, static_cast<int>(GroupColumn::kComment), new QTableWidgetItem(groupModel.comment));
    }

    void setDirtyState(const bool dirtyState)
    {
        dirty_ = dirtyState;
        updateStatusLabel();
    }

    void appendAppLog(const QString& logText)
    {
        if (appLogEditor_ == nullptr)
        {
            return;
        }
        const QString kLineText = QStringLiteral("[%1] %2")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
            .arg(logText);
        appLogEditor_->appendPlainText(kLineText);
    }

    void appendEventLog(const QString& logText)
    {
        if (eventLogEditor_ == nullptr)
        {
            return;
        }
        const QString kLineText = QStringLiteral("[%1] %2")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
            .arg(logText);
        eventLogEditor_->appendPlainText(kLineText);
    }

    quint32 allocateNextGroupId() const
    {
        quint32 maxGroupId = 0U;
        for (int rowIndex = 0; rowIndex < groupTable_->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* groupIdItem = groupTable_->item(rowIndex, static_cast<int>(GroupColumn::kId));
            if (groupIdItem == nullptr)
            {
                continue;
            }
            quint32 groupId = 0U;
            if (parseUnsignedText(groupIdItem->text(), &groupId))
            {
                maxGroupId = std::max(maxGroupId, groupId);
            }
        }
        return maxGroupId + 1U;
    }

    quint32 allocateNextRuleId() const
    {
        quint32 maxRuleId = 0U;
        for (auto iterator = ruleTableMap_.begin(); iterator != ruleTableMap_.end(); ++iterator)
        {
            const QTableWidget* ruleTable = iterator.value();
            if (ruleTable == nullptr)
            {
                continue;
            }
            for (int rowIndex = 0; rowIndex < ruleTable->rowCount(); ++rowIndex)
            {
                const QTableWidgetItem* ruleIdItem = ruleTable->item(rowIndex, static_cast<int>(RuleColumn::kRuleId));
                if (ruleIdItem == nullptr)
                {
                    continue;
                }
                quint32 ruleId = 0U;
                if (parseUnsignedText(ruleIdItem->text(), &ruleId))
                {
                    maxRuleId = std::max(maxRuleId, ruleId);
                }
            }
        }
        return maxRuleId + 1U;
    }

    quint32 firstGroupId() const
    {
        for (int rowIndex = 0; rowIndex < groupTable_->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* groupIdItem = groupTable_->item(rowIndex, static_cast<int>(GroupColumn::kId));
            if (groupIdItem == nullptr)
            {
                continue;
            }
            quint32 groupId = 0U;
            if (parseUnsignedText(groupIdItem->text(), &groupId))
            {
                return groupId;
            }
        }
        return 0U;
    }

    bool groupExists(const quint32 groupId) const
    {
        if (groupId == 0U)
        {
            return false;
        }

        for (int rowIndex = 0; rowIndex < groupTable_->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* groupIdItem = groupTable_->item(rowIndex, static_cast<int>(GroupColumn::kId));
            if (groupIdItem == nullptr)
            {
                continue;
            }
            quint32 currentGroupId = 0U;
            if (parseUnsignedText(groupIdItem->text(), &currentGroupId) && currentGroupId == groupId)
            {
                return true;
            }
        }
        return false;
    }

    void setRuleHeaderCell(
        QTableWidget* ruleTable,
        const int headerRow,
        const RuleColumn column,
        QTableWidgetItem* item)
    {
        // Purpose: Write to the first row of ordinary cells while cleaning up old spans to ensure column widths remain adjustable after table reconstruction.
        // Input parameters ruleTable/headerRow/column/item: target table, first row, column enumeration, and the item to take over.
        if (ruleTable == nullptr || item == nullptr)
        {
            delete item;
            return;
        }

        ruleTable->setSpan(headerRow, static_cast<int>(column), 1, 1);
        ruleTable->setItem(headerRow, static_cast<int>(column), item);
    }

    void setRuleHeaderWidget(
        QTableWidget* ruleTable,
        const int headerRow,
        const RuleColumn column,
        QWidget* widget)
    {
        // Purpose: Write to the first row's cell, keeping all fields under header constraints.
        // Input parameter widget: Qt manages the lifecycle; on null pointer, only clean up the span.
        if (ruleTable == nullptr)
        {
            delete widget;
            return;
        }

        ruleTable->setSpan(headerRow, static_cast<int>(column), 1, 1);
        ruleTable->setCellWidget(headerRow, static_cast<int>(column), widget);
    }

    void setRuleDetailWidget(
        QTableWidget* ruleTable,
        const int detailRow,
        QWidget* detailWidget)
    {
        // Purpose: Make the second row span the right field area starting from the GroupID column, while keeping the left fixed identity column.
        // Input detailWidget: a container with a 1:1:1 layout containing the initiating program, target program, and remarks.
        if (ruleTable == nullptr)
        {
            delete detailWidget;
            return;
        }

        const int kFirstColumn = static_cast<int>(RuleColumn::kGroupId);
        const int kColumnCount = static_cast<int>(RuleColumn::kCount) - kFirstColumn;
        ruleTable->setSpan(detailRow, kFirstColumn, 1, kColumnCount);
        ruleTable->setCellWidget(detailRow, kFirstColumn, detailWidget);
    }

    void setRuleIdentityColumnSpan(
        QTableWidget* ruleTable,
        const int headerRow)
    {
        // Purpose: Fix 'Enable' and RuleID as narrow columns spanning two rows, with the rule body and match details carried on the right.
        // Input ruleTable/headerRow: target rule table and current first rule row; no return value.
        if (ruleTable == nullptr)
        {
            return;
        }

        ruleTable->setSpan(headerRow, static_cast<int>(RuleColumn::kEnabled), 2, 1);
        ruleTable->setSpan(headerRow, static_cast<int>(RuleColumn::kRuleId), 2, 1);
    }

    QWidget* createOperationMaskPanel(
        QTableWidget* ruleTable,
        const quint32 callbackType,
        const quint32 operationMask)
    {
        // Purpose: Create the first row of 'Operation Type' checkbox panel and append the 'Custom Mask' input.
        // Input operationMask: current rule mask; Returns: a QWidget suitable for direct insertion into a QTableWidget.
        auto* operationPanel = new QWidget(ruleTable);
        operationPanel->setObjectName(QStringLiteral("ksCallbackRuleOperationPanel"));
        const bool kAllowWallpaperThroughOperationPanel = callbackAllowWallpaperThroughControls();
        operationPanel->setAutoFillBackground(!kAllowWallpaperThroughOperationPanel);
        operationPanel->setAttribute(Qt::WA_StyledBackground, !kAllowWallpaperThroughOperationPanel);
        operationPanel->setStyleSheet(callbackRulePanelStyle());

        auto* panelLayout = new QGridLayout(operationPanel);
        panelLayout->setContentsMargins(3, 1, 3, 1);
        panelLayout->setHorizontalSpacing(6);
        panelLayout->setVerticalSpacing(2);

        // kOperationCheckColumns: Basic operation bits are arranged in four columns; the 8 registry bits are compressed into two rows.
        constexpr int kOperationCheckColumns = 4;
        constexpr int kOperationTotalColumns = 6;
        const QList<QPair<QString, quint32>> kOperationBitList = operationCheckboxListByType(callbackType);
        for (int bitIndex = 0; bitIndex < kOperationBitList.size(); ++bitIndex)
        {
            const QPair<QString, quint32>& bitPair = kOperationBitList.at(bitIndex);
            auto* checkBox = new QCheckBox(bitPair.first, operationPanel);
            checkBox->setProperty("operationMaskBit", QVariant::fromValue(bitPair.second));
            checkBox->setChecked((operationMask & bitPair.second) == bitPair.second);
            checkBox->setToolTip(
                kernelText("kernel.callback.intercept.operation.tooltip", QStringLiteral("%1：%2"))
                .arg(bitPair.first, operationMaskToText(bitPair.second)));
            connect(checkBox, &QCheckBox::toggled, hostPage_, [this](bool) {
                if (!ignoreUiSignal_)
                {
                    setDirtyState(true);
                }
            });

            const int kRowIndex = bitIndex / kOperationCheckColumns;
            const int kColumnIndex = bitIndex % kOperationCheckColumns;
            panelLayout->addWidget(checkBox, kRowIndex, kColumnIndex, Qt::Alignment());
        }

        quint32 checkedOperationMask = 0U;
        for (const QPair<QString, quint32>& bitPair : kOperationBitList)
        {
            if ((operationMask & bitPair.second) == bitPair.second)
            {
                checkedOperationMask |= bitPair.second;
            }
        }

        const quint32 kCustomMask = operationMask & ~checkedOperationMask;
        auto* customMaskEdit = new QLineEdit(operationPanel);
        customMaskEdit->setObjectName(QStringLiteral("ksCallbackRuleCustomMaskEdit"));
        customMaskEdit->setPlaceholderText(kernelText("kernel.callback.intercept.operation.custom_mask", QStringLiteral("自定义掩码")));
        customMaskEdit->setText(kCustomMask != 0U ? operationMaskToText(kCustomMask) : QString());
        customMaskEdit->setToolTip(kernelText("kernel.callback.intercept.operation.custom_mask_tooltip", QStringLiteral("输入十六进制或十进制掩码；缺少 0x 前缀时会自动补全（大小写不敏感）。")));
        applyRuleLineEditStyle(customMaskEdit);

        connect(customMaskEdit, &QLineEdit::textEdited, hostPage_, [this](const QString&) {
            if (!ignoreUiSignal_)
            {
                setDirtyState(true);
            }
        });
        connect(customMaskEdit, &QLineEdit::editingFinished, hostPage_, [customMaskEdit]() {
            normalizeCustomMaskEditText(customMaskEdit);
        });

        // customRowIndex purpose: place custom mask in the first row for small types; place multi-bit types like registry in the second row on the right.
        const int kOperationBitCount = static_cast<int>(kOperationBitList.size());
        const int kCustomRowIndex = (kOperationBitCount > kOperationCheckColumns) ? 1 : 0;
        auto* customMaskLabel = new QLabel(kernelText("kernel.callback.intercept.operation.custom_mask", QStringLiteral("自定义掩码")), operationPanel);
        customMaskLabel->setObjectName(QStringLiteral("ksCallbackRuleFieldTitle"));
        panelLayout->addWidget(customMaskLabel, kCustomRowIndex, 4, 1, 1);
        panelLayout->addWidget(customMaskEdit, kCustomRowIndex, 5, 1, 1);
        for (int columnIndex = 0; columnIndex < kOperationTotalColumns; ++columnIndex)
        {
            const int kStretchValue = (columnIndex == 5) ? 2 : 1;
            panelLayout->setColumnStretch(columnIndex, kStretchValue);
        }

        return operationPanel;
    }

    QLineEdit* createRuleDetailEdit(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& valueText,
        const QString& placeholderText)
    {
        // Purpose: Create a second row of three equal-width field editors with unified titles, placeholders, and styles.
        // Returns: QLineEdit pointer; the caller distinguishes field usage via objectName.
        auto* edit = new QLineEdit(parentWidget);
        edit->setText(valueText);
        edit->setPlaceholderText(placeholderText);
        edit->setToolTip(titleText);
        applyRuleLineEditStyle(edit);
        return edit;
    }

    QWidget* createRuleDetailPanel(
        QTableWidget* ruleTable,
        const quint32 callbackType,
        const CallbackRuleModel& ruleModel)
    {
        // Purpose: Create a second-row horizontal detail panel spanning the full width, with three fields automatically allocated widths in a 1:1:1 ratio.
        // Parameter ruleModel: current rule value; Returns: QWidget to be placed in detailRow.
        auto* detailPanel = new QWidget(ruleTable);
        detailPanel->setObjectName(QStringLiteral("ksCallbackRuleDetailPanel"));
        const bool kAllowWallpaperThroughDetailPanel = callbackAllowWallpaperThroughControls();
        detailPanel->setAutoFillBackground(!kAllowWallpaperThroughDetailPanel);
        detailPanel->setAttribute(Qt::WA_StyledBackground, !kAllowWallpaperThroughDetailPanel);
        detailPanel->setStyleSheet(callbackRulePanelStyle());

        auto* detailLayout = new QGridLayout(detailPanel);
        detailLayout->setContentsMargins(6, 4, 6, 4);
        detailLayout->setHorizontalSpacing(8);
        detailLayout->setVerticalSpacing(3);

        const QStringList kTitleList{
            kernelText("kernel.callback.intercept.detail.initiator", QStringLiteral("发起程序匹配")),
            kernelText("kernel.callback.intercept.detail.target", QStringLiteral("目标程序匹配")),
            kernelText("kernel.callback.intercept.detail.comment", QStringLiteral("备注"))
        };
        for (int columnIndex = 0; columnIndex < kTitleList.size(); ++columnIndex)
        {
            auto* titleLabel = new QLabel(kTitleList.at(columnIndex), detailPanel);
            titleLabel->setObjectName(QStringLiteral("ksCallbackRuleFieldTitle"));
            detailLayout->addWidget(titleLabel, 0, columnIndex);
            detailLayout->setColumnStretch(columnIndex, 1);
        }

        QLineEdit* initiatorEdit = createRuleDetailEdit(
            detailPanel,
            kTitleList.at(0),
            ruleModel.initiatorPattern,
            initiatorPlaceholderByType(callbackType));
        initiatorEdit->setObjectName(QStringLiteral("ksCallbackRuleInitiatorEdit"));

        QLineEdit* targetEdit = createRuleDetailEdit(
            detailPanel,
            kTitleList.at(1),
            ruleModel.targetPattern,
            targetPlaceholderByType(callbackType));
        targetEdit->setObjectName(QStringLiteral("ksCallbackRuleTargetEdit"));

        QLineEdit* commentEdit = createRuleDetailEdit(
            detailPanel,
            kTitleList.at(2),
            ruleModel.comment,
            kernelText("kernel.callback.intercept.detail.comment_placeholder", QStringLiteral("备注")));
        commentEdit->setObjectName(QStringLiteral("ksCallbackRuleCommentEdit"));

        const QList<QLineEdit*> kEditList{ initiatorEdit, targetEdit, commentEdit };
        for (int columnIndex = 0; columnIndex < kEditList.size(); ++columnIndex)
        {
            QLineEdit* edit = kEditList.at(columnIndex);
            connect(edit, &QLineEdit::textEdited, hostPage_, [this](const QString&) {
                if (!ignoreUiSignal_)
                {
                    setDirtyState(true);
                }
            });
            detailLayout->addWidget(edit, 1, columnIndex);
        }

        return detailPanel;
    }

    int ruleCountOfTable(const QTableWidget* ruleTable) const
    {
        if (ruleTable == nullptr || ruleTable->rowCount() <= 0)
        {
            return 0;
        }
        return ruleTable->rowCount() / 2;
    }

    int normalizeRuleHeaderRow(const int anyRowIndex) const
    {
        if (anyRowIndex < 0)
        {
            return -1;
        }
        return (anyRowIndex % 2 == 0) ? anyRowIndex : (anyRowIndex - 1);
    }

    int currentRuleLogicalIndex(const QTableWidget* ruleTable) const
    {
        if (ruleTable == nullptr)
        {
            return -1;
        }
        const int kHeaderRow = normalizeRuleHeaderRow(ruleTable->currentRow());
        if (kHeaderRow < 0)
        {
            return -1;
        }
        return kHeaderRow / 2;
    }

    void addGroupRow(const quint32 preferredId)
    {
        CallbackRuleGroupModel newGroup;
        newGroup.groupId = (preferredId == 0U) ? allocateNextGroupId() : preferredId;
        newGroup.groupName = kernelText("kernel.callback.intercept.group.default_name", QStringLiteral("规则组%1")).arg(newGroup.groupId);
        newGroup.enabled = true;
        newGroup.priority = (groupTable_->rowCount() + 1) * 10;
        newGroup.comment = kernelText("kernel.callback.intercept.group.default_comment", QStringLiteral("新建规则组"));

        ignoreUiSignal_ = true;
        appendGroupRow(newGroup);
        ignoreUiSignal_ = false;

        refreshRuleGroupComboOptions();
        setDirtyState(true);
        appendAppLog(kernelText("kernel.callback.intercept.group.added_log", QStringLiteral("新增规则组成功：groupId=%1")).arg(newGroup.groupId));
    }

    void removeCurrentGroup()
    {
        const int kRowIndex = groupTable_->currentRow();
        if (kRowIndex < 0)
        {
            return;
        }

        QTableWidgetItem* groupIdItem = groupTable_->item(kRowIndex, static_cast<int>(GroupColumn::kId));
        if (groupIdItem == nullptr)
        {
            return;
        }

        quint32 groupId = 0U;
        if (!parseUnsignedText(groupIdItem->text(), &groupId))
        {
            return;
        }

        QList<CallbackRuleModel> allRuleList;
        QString ruleErrorText;
        if (!collectAllRulesFromUi(&allRuleList, &ruleErrorText))
        {
            QMessageBox::warning(hostPage_, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), ruleErrorText);
            return;
        }
        allRuleList.erase(
            std::remove_if(
                allRuleList.begin(),
                allRuleList.end(),
                [groupId](const CallbackRuleModel& ruleModel) {
                    return ruleModel.groupId == groupId;
                }),
            allRuleList.end());

        ignoreUiSignal_ = true;
        groupTable_->removeRow(kRowIndex);
        for (auto iterator = ruleTableMap_.begin(); iterator != ruleTableMap_.end(); ++iterator)
        {
            QTableWidget* ruleTable = iterator.value();
            if (ruleTable != nullptr)
            {
                ruleTable->setRowCount(0);
            }
        }
        for (const CallbackRuleModel& ruleModel : allRuleList)
        {
            QTableWidget* targetRuleTable = ruleTableMap_.value(ruleModel.callbackType, nullptr);
            if (targetRuleTable != nullptr)
            {
                appendRuleRow(targetRuleTable, ruleModel.callbackType, ruleModel);
            }
        }
        ignoreUiSignal_ = false;

        refreshRuleGroupComboOptions();
        addDefaultGroupIfNeeded();
        setDirtyState(true);
        appendAppLog(kernelText("kernel.callback.intercept.group.removed_log", QStringLiteral("删除规则组成功：groupId=%1")).arg(groupId));
    }

    void renameCurrentGroup()
    {
        const int kRowIndex = groupTable_->currentRow();
        if (kRowIndex < 0)
        {
            return;
        }

        QTableWidgetItem* groupNameItem = groupTable_->item(kRowIndex, static_cast<int>(GroupColumn::kName));
        if (groupNameItem == nullptr)
        {
            return;
        }

        bool okPressed = false;
        const QString kNewNameText = QInputDialog::getText(
            hostPage_,
            kernelText("kernel.callback.intercept.group.rename_dialog.title", QStringLiteral("重命名规则组")),
            kernelText("kernel.callback.intercept.group.rename_dialog.prompt", QStringLiteral("请输入组名称：")),
            QLineEdit::Normal,
            groupNameItem->text(),
            &okPressed).trimmed();
        if (!okPressed || kNewNameText.isEmpty())
        {
            return;
        }

        groupNameItem->setText(kNewNameText);
        refreshRuleGroupComboOptions();
        setDirtyState(true);
        appendAppLog(kernelText("kernel.callback.intercept.group.renamed_log", QStringLiteral("规则组重命名成功：%1")).arg(kNewNameText));
    }

    void moveCurrentGroup(const int direction)
    {
        const int kCurrentRow = groupTable_->currentRow();
        if (kCurrentRow < 0)
        {
            return;
        }

        const int kTargetRow = kCurrentRow + direction;
        if (kTargetRow < 0 || kTargetRow >= groupTable_->rowCount())
        {
            return;
        }

        QList<CallbackRuleGroupModel> groupList;
        QString errorText;
        if (!collectGroupsFromUi(&groupList, &errorText))
        {
            QMessageBox::warning(hostPage_, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), errorText);
            return;
        }

        std::swap(groupList[kCurrentRow], groupList[kTargetRow]);
        for (int index = 0; index < groupList.size(); ++index)
        {
            groupList[index].priority = (index + 1) * 10;
        }

        ignoreUiSignal_ = true;
        groupTable_->setRowCount(0);
        for (const CallbackRuleGroupModel& groupModel : groupList)
        {
            appendGroupRow(groupModel);
        }
        groupTable_->setCurrentCell(kTargetRow, static_cast<int>(GroupColumn::kName));
        ignoreUiSignal_ = false;

        refreshRuleGroupComboOptions();
        setDirtyState(true);
    }

    void addRuleToCurrentTab()
    {
        const quint32 kCallbackType = currentRuleCallbackType();
        QTableWidget* ruleTable = currentRuleTable();
        if (ruleTable == nullptr)
        {
            return;
        }

        CallbackRuleModel ruleModel;
        ruleModel.ruleId = allocateNextRuleId();
        ruleModel.groupId = firstGroupId();
        ruleModel.ruleName = kernelText("kernel.callback.intercept.rule.default_name", QStringLiteral("规则%1")).arg(ruleModel.ruleId);
        ruleModel.enabled = true;
        ruleModel.callbackType = kCallbackType;
        ruleModel.operationMask = defaultOperationMaskByType(kCallbackType);
        ruleModel.initiatorPattern.clear();
        ruleModel.targetPattern.clear();
        ruleModel.matchMode = allowedMatchModeListByType(kCallbackType).isEmpty()
            ? KSWORD_ARK_MATCH_MODE_EXACT
            : allowedMatchModeListByType(kCallbackType).front().second;
        ruleModel.action = allowedActionListByType(kCallbackType).isEmpty()
            ? KSWORD_ARK_RULE_ACTION_LOG_ONLY
            : allowedActionListByType(kCallbackType).front().second;
        ruleModel.timeoutMs = (ruleModel.action == KSWORD_ARK_RULE_ACTION_ASK_USER) ? 5000U : 0U;
        ruleModel.timeoutDefaultDecision = KSWORD_ARK_DECISION_ALLOW;
        ruleModel.priority = (ruleCountOfTable(ruleTable) + 1) * 10;
        ruleModel.comment = kernelText("kernel.callback.intercept.rule.default_comment", QStringLiteral("新建规则"));

        ignoreUiSignal_ = true;
        appendRuleRow(ruleTable, kCallbackType, ruleModel);
        ignoreUiSignal_ = false;

        ruleTable->setCurrentCell(ruleTable->rowCount() - 2, static_cast<int>(RuleColumn::kRuleName));
        setDirtyState(true);
        appendAppLog(
            kernelText("kernel.callback.intercept.rule.added_log", QStringLiteral("新增规则成功：ruleId=%1，类型=%2"))
            .arg(ruleModel.ruleId)
            .arg(callbackTypeToDisplayText(kCallbackType)));
    }

    void removeCurrentRule()
    {
        QTableWidget* ruleTable = currentRuleTable();
        const quint32 kCallbackType = currentRuleCallbackType();
        if (ruleTable == nullptr)
        {
            return;
        }

        QList<CallbackRuleModel> ruleList;
        QString errorText;
        if (!collectRuleListFromTable(ruleTable, kCallbackType, &ruleList, &errorText))
        {
            QMessageBox::warning(hostPage_, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), errorText);
            return;
        }

        const int kCurrentRuleIndex = currentRuleLogicalIndex(ruleTable);
        if (kCurrentRuleIndex < 0 || kCurrentRuleIndex >= ruleList.size())
        {
            return;
        }
        ruleList.removeAt(kCurrentRuleIndex);

        ignoreUiSignal_ = true;
        ruleTable->setRowCount(0);
        for (const CallbackRuleModel& ruleModel : ruleList)
        {
            appendRuleRow(ruleTable, kCallbackType, ruleModel);
        }
        ignoreUiSignal_ = false;

        if (ruleCountOfTable(ruleTable) > 0)
        {
            const int kTargetRuleIndex = std::min(kCurrentRuleIndex, ruleCountOfTable(ruleTable) - 1);
            ruleTable->setCurrentCell(kTargetRuleIndex * 2, static_cast<int>(RuleColumn::kRuleName));
        }
        setDirtyState(true);
        appendAppLog(kernelText("kernel.callback.intercept.rule.removed_log", QStringLiteral("删除规则成功。")));
    }

    void moveCurrentRule(const int direction)
    {
        QTableWidget* ruleTable = currentRuleTable();
        const quint32 kCallbackType = currentRuleCallbackType();
        if (ruleTable == nullptr)
        {
            return;
        }

        const int kCurrentRuleIndex = currentRuleLogicalIndex(ruleTable);
        if (kCurrentRuleIndex < 0)
        {
            return;
        }

        QList<CallbackRuleModel> ruleList;
        QString errorText;
        if (!collectRuleListFromTable(ruleTable, kCallbackType, &ruleList, &errorText))
        {
            QMessageBox::warning(hostPage_, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), errorText);
            return;
        }

        const int kTargetRuleIndex = kCurrentRuleIndex + direction;
        if (kTargetRuleIndex < 0 || kTargetRuleIndex >= ruleList.size())
        {
            return;
        }

        std::swap(ruleList[kCurrentRuleIndex], ruleList[kTargetRuleIndex]);
        for (int index = 0; index < ruleList.size(); ++index)
        {
            ruleList[index].priority = (index + 1) * 10;
        }

        ignoreUiSignal_ = true;
        ruleTable->setRowCount(0);
        for (const CallbackRuleModel& ruleModel : ruleList)
        {
            appendRuleRow(ruleTable, kCallbackType, ruleModel);
        }
        ignoreUiSignal_ = false;

        ruleTable->setCurrentCell(kTargetRuleIndex * 2, static_cast<int>(RuleColumn::kRuleName));
        setDirtyState(true);
    }

    void appendRuleRow(
        QTableWidget* ruleTable,
        const quint32 callbackType,
        const CallbackRuleModel& ruleModel)
    {
        if (ruleTable == nullptr)
        {
            return;
        }

        const int kHeaderRow = ruleTable->rowCount();
        const int kDetailRow = kHeaderRow + 1;
        ruleTable->insertRow(kHeaderRow);
        ruleTable->insertRow(kDetailRow);

        // Each rule uses two rows for display: the left side (Enable/RuleID) spans both rows, while the right side's first row displays rule attributes.
        // The second row starts with GroupID for match details to prevent match conditions from breaking the table layout.
        const int kOperationBitCount = operationCheckboxListByType(callbackType).size();
        const int kHeaderRowHeight = (kOperationBitCount > 4) ? 60 : 46;
        ruleTable->setRowHeight(kHeaderRow, kHeaderRowHeight);
        ruleTable->setRowHeight(kDetailRow, 52);

        auto* enabledItem = new QTableWidgetItem();
        enabledItem->setFlags(enabledItem->flags() | Qt::ItemIsUserCheckable);
        enabledItem->setCheckState(ruleModel.enabled ? Qt::Checked : Qt::Unchecked);
        setRuleHeaderCell(ruleTable, kHeaderRow, RuleColumn::kEnabled, enabledItem);
        setRuleHeaderCell(ruleTable, kHeaderRow, RuleColumn::kRuleId, makeReadOnlyItem(QString::number(ruleModel.ruleId)));
        setRuleIdentityColumnSpan(ruleTable, kHeaderRow);

        auto* groupCombo = new QComboBox(ruleTable);
        applyRuleComboStyle(groupCombo);
        setRuleHeaderWidget(ruleTable, kHeaderRow, RuleColumn::kGroupId, groupCombo);
        connect(groupCombo, &QComboBox::currentIndexChanged, hostPage_, [this](int) {
            if (!ignoreUiSignal_)
            {
                setDirtyState(true);
            }
        });
        setRuleHeaderCell(ruleTable, kHeaderRow, RuleColumn::kRuleName, new QTableWidgetItem(ruleModel.ruleName));

        QWidget* operationPanel = createOperationMaskPanel(
            ruleTable,
            callbackType,
            ruleModel.operationMask);
        setRuleHeaderWidget(
            ruleTable,
            kHeaderRow,
            RuleColumn::kOperationMask,
            operationPanel);

        auto* matchModeCombo = new QComboBox(ruleTable);
        applyRuleComboStyle(matchModeCombo);
        for (const QPair<QString, quint32>& optionPair : allowedMatchModeListByType(callbackType))
        {
            matchModeCombo->addItem(optionPair.first, optionPair.second);
        }
        const int kMatchModeIndex = matchModeCombo->findData(ruleModel.matchMode);
        matchModeCombo->setCurrentIndex(kMatchModeIndex >= 0 ? kMatchModeIndex : 0);
        connect(matchModeCombo, &QComboBox::currentIndexChanged, hostPage_, [this, ruleTable, kHeaderRow, callbackType](int) {
            if (ignoreUiSignal_)
            {
                return;
            }

            auto* currentMatchCombo = qobject_cast<QComboBox*>(
                ruleTable->cellWidget(kHeaderRow, static_cast<int>(RuleColumn::kMatchMode)));
            auto* currentActionCombo = qobject_cast<QComboBox*>(
                ruleTable->cellWidget(kHeaderRow, static_cast<int>(RuleColumn::kAction)));
            const quint32 kMatchMode =
                (currentMatchCombo != nullptr)
                ? static_cast<quint32>(currentMatchCombo->currentData().toUInt())
                : KSWORD_ARK_MATCH_MODE_EXACT;
            const quint32 kActionType =
                (currentActionCombo != nullptr)
                ? static_cast<quint32>(currentActionCombo->currentData().toUInt())
                : KSWORD_ARK_RULE_ACTION_ALLOW;

            if ((callbackType == KSWORD_ARK_CALLBACK_TYPE_REGISTRY ||
                callbackType == KSWORD_ARK_CALLBACK_TYPE_MINIFILTER) &&
                kMatchMode == KSWORD_ARK_MATCH_MODE_REGEX &&
                kActionType != KSWORD_ARK_RULE_ACTION_ASK_USER &&
                currentActionCombo != nullptr)
            {
                const int kAskUserIndex = currentActionCombo->findData(
                    QVariant::fromValue(static_cast<uint>(KSWORD_ARK_RULE_ACTION_ASK_USER)));
                if (kAskUserIndex >= 0)
                {
                    ignoreUiSignal_ = true;
                    currentActionCombo->setCurrentIndex(kAskUserIndex);
                    ignoreUiSignal_ = false;
                }
            }
            setDirtyState(true);
        });
        setRuleHeaderWidget(ruleTable, kHeaderRow, RuleColumn::kMatchMode, matchModeCombo);

        auto* actionCombo = new QComboBox(ruleTable);
        applyRuleComboStyle(actionCombo);
        for (const QPair<QString, quint32>& optionPair : allowedActionListByType(callbackType))
        {
            actionCombo->addItem(optionPair.first, optionPair.second);
        }
        const int kActionIndex = actionCombo->findData(ruleModel.action);
        actionCombo->setCurrentIndex(kActionIndex >= 0 ? kActionIndex : 0);
        connect(actionCombo, &QComboBox::currentIndexChanged, hostPage_, [this, ruleTable, kHeaderRow](int) {
            if (ignoreUiSignal_)
            {
                return;
            }
            auto* currentActionCombo = qobject_cast<QComboBox*>(
                ruleTable->cellWidget(kHeaderRow, static_cast<int>(RuleColumn::kAction)));
            auto* currentMatchCombo = qobject_cast<QComboBox*>(
                ruleTable->cellWidget(kHeaderRow, static_cast<int>(RuleColumn::kMatchMode)));
            const quint32 kActionType = (currentActionCombo != nullptr)
                ? static_cast<quint32>(currentActionCombo->currentData().toUInt())
                : KSWORD_ARK_RULE_ACTION_ALLOW;
            const quint32 kMatchMode = (currentMatchCombo != nullptr)
                ? static_cast<quint32>(currentMatchCombo->currentData().toUInt())
                : KSWORD_ARK_MATCH_MODE_EXACT;
            QTableWidgetItem* timeoutItem = ruleTable->item(kHeaderRow, static_cast<int>(RuleColumn::kTimeoutMs));
            if (timeoutItem != nullptr && kActionType != KSWORD_ARK_RULE_ACTION_ASK_USER)
            {
                timeoutItem->setText(QStringLiteral("0"));
            }
            if (timeoutItem != nullptr && kActionType == KSWORD_ARK_RULE_ACTION_ASK_USER)
            {
                quint32 timeoutValue = 0U;
                if (!parseUnsignedText(timeoutItem->text(), &timeoutValue) || timeoutValue == 0U)
                {
                    timeoutItem->setText(QStringLiteral("5000"));
                }
            }

            if (kActionType != KSWORD_ARK_RULE_ACTION_ASK_USER &&
                kMatchMode == KSWORD_ARK_MATCH_MODE_REGEX &&
                currentMatchCombo != nullptr)
            {
                const int kExactIndex = currentMatchCombo->findData(
                    QVariant::fromValue(static_cast<uint>(KSWORD_ARK_MATCH_MODE_EXACT)));
                if (kExactIndex >= 0)
                {
                    ignoreUiSignal_ = true;
                    currentMatchCombo->setCurrentIndex(kExactIndex);
                    ignoreUiSignal_ = false;
                }
            }
            setDirtyState(true);
        });
        setRuleHeaderWidget(ruleTable, kHeaderRow, RuleColumn::kAction, actionCombo);

        setRuleHeaderCell(
            ruleTable,
            kHeaderRow,
            RuleColumn::kTimeoutMs,
            new QTableWidgetItem(QString::number(ruleModel.timeoutMs)));

        auto* timeoutDecisionCombo = new QComboBox(ruleTable);
        applyRuleComboStyle(timeoutDecisionCombo);
        for (const QPair<QString, quint32>& optionPair : decisionOptionList())
        {
            timeoutDecisionCombo->addItem(optionPair.first, optionPair.second);
        }
        const int kTimeoutDecisionIndex = timeoutDecisionCombo->findData(ruleModel.timeoutDefaultDecision);
        timeoutDecisionCombo->setCurrentIndex(kTimeoutDecisionIndex >= 0 ? kTimeoutDecisionIndex : 0);
        connect(timeoutDecisionCombo, &QComboBox::currentIndexChanged, hostPage_, [this](int) {
            if (!ignoreUiSignal_)
            {
                setDirtyState(true);
            }
        });
        setRuleHeaderWidget(
            ruleTable,
            kHeaderRow,
            RuleColumn::kTimeoutDefaultDecision,
            timeoutDecisionCombo);

        setRuleHeaderCell(
            ruleTable,
            kHeaderRow,
            RuleColumn::kPriority,
            new QTableWidgetItem(QString::number(ruleModel.priority)));

        QWidget* detailPanel = createRuleDetailPanel(ruleTable, callbackType, ruleModel);
        setRuleDetailWidget(ruleTable, kDetailRow, detailPanel);

        refreshRuleGroupComboForCell(groupCombo, ruleModel.groupId);
    }

    void refreshRuleGroupComboForCell(QComboBox* groupCombo, const quint32 selectedGroupId)
    {
        if (groupCombo == nullptr)
        {
            return;
        }

        applyRuleComboStyle(groupCombo);
        groupCombo->blockSignals(true);
        groupCombo->clear();
        for (int rowIndex = 0; rowIndex < groupTable_->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* groupIdItem = groupTable_->item(rowIndex, static_cast<int>(GroupColumn::kId));
            QTableWidgetItem* groupNameItem = groupTable_->item(rowIndex, static_cast<int>(GroupColumn::kName));
            if (groupIdItem == nullptr || groupNameItem == nullptr)
            {
                continue;
            }

            quint32 groupId = 0U;
            if (!parseUnsignedText(groupIdItem->text(), &groupId))
            {
                continue;
            }
            groupCombo->addItem(
                QStringLiteral("[%1] %2").arg(groupId).arg(groupNameItem->text().trimmed()),
                groupId);
        }

        int targetIndex = groupCombo->findData(selectedGroupId);
        if (targetIndex < 0)
        {
            targetIndex = 0;
        }
        groupCombo->setCurrentIndex(targetIndex);
        groupCombo->blockSignals(false);
    }

    void refreshRuleGroupComboOptions()
    {
        for (auto iterator = ruleTableMap_.begin(); iterator != ruleTableMap_.end(); ++iterator)
        {
            QTableWidget* ruleTable = iterator.value();
            if (ruleTable == nullptr)
            {
                continue;
            }

            for (int rowIndex = 0; rowIndex < ruleTable->rowCount(); rowIndex += 2)
            {
                auto* groupCombo = qobject_cast<QComboBox*>(
                    ruleTable->cellWidget(rowIndex, static_cast<int>(RuleColumn::kGroupId)));
                quint32 selectedGroupId = firstGroupId();
                if (groupCombo != nullptr)
                {
                    selectedGroupId = static_cast<quint32>(groupCombo->currentData().toUInt());
                }
                refreshRuleGroupComboForCell(groupCombo, selectedGroupId);
            }
        }
    }

    quint32 currentRuleCallbackType() const
    {
        return tabCallbackTypeMap_.value(
            ruleTabWidget_ != nullptr ? ruleTabWidget_->currentIndex() : -1,
            KSWORD_ARK_CALLBACK_TYPE_NONE);
    }

    QTableWidget* currentRuleTable() const
    {
        const quint32 kCallbackType = currentRuleCallbackType();
        return ruleTableMap_.value(kCallbackType, nullptr);
    }

    bool collectGroupsFromUi(
        QList<CallbackRuleGroupModel>* groupListOut,
        QString* errorTextOut) const
    {
        if (groupListOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.group_list_out_null", QStringLiteral("内部错误：groupListOut 为空。"));
            }
            return false;
        }

        groupListOut->clear();
        for (int rowIndex = 0; rowIndex < groupTable_->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* idItem = groupTable_->item(rowIndex, static_cast<int>(GroupColumn::kId));
            QTableWidgetItem* nameItem = groupTable_->item(rowIndex, static_cast<int>(GroupColumn::kName));
            QTableWidgetItem* enabledItem = groupTable_->item(rowIndex, static_cast<int>(GroupColumn::kEnabled));
            QTableWidgetItem* priorityItem = groupTable_->item(rowIndex, static_cast<int>(GroupColumn::kPriority));
            QTableWidgetItem* commentItem = groupTable_->item(rowIndex, static_cast<int>(GroupColumn::kComment));
            if (idItem == nullptr || nameItem == nullptr || enabledItem == nullptr || priorityItem == nullptr || commentItem == nullptr)
            {
                continue;
            }

            CallbackRuleGroupModel groupModel;
            if (!parseUnsignedText(idItem->text(), &groupModel.groupId))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.group_id_invalid", QStringLiteral("规则组行 %1 的 groupId 非法。")).arg(rowIndex + 1);
                }
                return false;
            }

            bool priorityOk = false;
            groupModel.priority = priorityItem->text().trimmed().toInt(&priorityOk);
            if (!priorityOk)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.group_priority_invalid", QStringLiteral("规则组行 %1 的优先级非法。")).arg(rowIndex + 1);
                }
                return false;
            }

            groupModel.groupName = nameItem->text().trimmed();
            groupModel.enabled = (enabledItem->checkState() == Qt::Checked);
            groupModel.comment = commentItem->text().trimmed();
            groupListOut->push_back(groupModel);
        }

        return true;
    }

    bool collectRuleListFromTable(
        QTableWidget* ruleTable,
        const quint32 callbackType,
        QList<CallbackRuleModel>* ruleListOut,
        QString* errorTextOut) const
    {
        if (ruleTable == nullptr || ruleListOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_table_or_list_null", QStringLiteral("内部错误：ruleTable 或 ruleListOut 为空。"));
            }
            return false;
        }

        ruleListOut->clear();
        const int kTotalRuleCount = ruleCountOfTable(ruleTable);
        for (int logicalRuleIndex = 0; logicalRuleIndex < kTotalRuleCount; ++logicalRuleIndex)
        {
            const int kHeaderRow = logicalRuleIndex * 2;
            const int kDetailRow = kHeaderRow + 1;

            QTableWidgetItem* ruleIdItem = ruleTable->item(kHeaderRow, static_cast<int>(RuleColumn::kRuleId));
            QTableWidgetItem* ruleNameItem = ruleTable->item(kHeaderRow, static_cast<int>(RuleColumn::kRuleName));
            QTableWidgetItem* enabledItem = ruleTable->item(kHeaderRow, static_cast<int>(RuleColumn::kEnabled));
            QTableWidgetItem* timeoutItem = ruleTable->item(kHeaderRow, static_cast<int>(RuleColumn::kTimeoutMs));
            QTableWidgetItem* priorityItem = ruleTable->item(kHeaderRow, static_cast<int>(RuleColumn::kPriority));
            auto* groupCombo = qobject_cast<QComboBox*>(ruleTable->cellWidget(kHeaderRow, static_cast<int>(RuleColumn::kGroupId)));
            auto* operationPanel = ruleTable->cellWidget(kHeaderRow, static_cast<int>(RuleColumn::kOperationMask));
            auto* matchModeCombo = qobject_cast<QComboBox*>(ruleTable->cellWidget(kHeaderRow, static_cast<int>(RuleColumn::kMatchMode)));
            auto* actionCombo = qobject_cast<QComboBox*>(ruleTable->cellWidget(kHeaderRow, static_cast<int>(RuleColumn::kAction)));
            auto* timeoutDecisionCombo = qobject_cast<QComboBox*>(ruleTable->cellWidget(kHeaderRow, static_cast<int>(RuleColumn::kTimeoutDefaultDecision)));
            auto* detailPanel = ruleTable->cellWidget(kDetailRow, static_cast<int>(RuleColumn::kGroupId));
            auto* initiatorEdit = detailPanel != nullptr
                ? detailPanel->findChild<QLineEdit*>(QStringLiteral("ksCallbackRuleInitiatorEdit"))
                : nullptr;
            auto* targetEdit = detailPanel != nullptr
                ? detailPanel->findChild<QLineEdit*>(QStringLiteral("ksCallbackRuleTargetEdit"))
                : nullptr;
            auto* commentEdit = detailPanel != nullptr
                ? detailPanel->findChild<QLineEdit*>(QStringLiteral("ksCallbackRuleCommentEdit"))
                : nullptr;

            if (ruleIdItem == nullptr || ruleNameItem == nullptr || enabledItem == nullptr ||
                timeoutItem == nullptr || priorityItem == nullptr ||
                groupCombo == nullptr || operationPanel == nullptr ||
                matchModeCombo == nullptr || actionCombo == nullptr || timeoutDecisionCombo == nullptr ||
                initiatorEdit == nullptr || targetEdit == nullptr || commentEdit == nullptr)
            {
                continue;
            }

            CallbackRuleModel ruleModel;
            if (!parseUnsignedText(ruleIdItem->text(), &ruleModel.ruleId))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_id_invalid", QStringLiteral("规则 %1 的 ruleId 非法。")).arg(logicalRuleIndex + 1);
                }
                return false;
            }

            ruleModel.groupId = static_cast<quint32>(groupCombo->currentData().toUInt());
            if (ruleModel.groupId == 0U)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_group_invalid", QStringLiteral("规则 %1 未选择有效规则组。")).arg(logicalRuleIndex + 1);
                }
                return false;
            }

            bool operationParseOk = false;
            ruleModel.operationMask = currentOperationMaskFromPanel(operationPanel, &operationParseOk);
            if (!operationParseOk || ruleModel.operationMask == 0U)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.operation_mask_invalid", QStringLiteral("规则 %1 的 operationMask 非法。")).arg(logicalRuleIndex + 1);
                }
                return false;
            }

            bool timeoutOk = false;
            const quint32 kTimeoutMs = static_cast<quint32>(timeoutItem->text().trimmed().toUInt(&timeoutOk));
            if (!timeoutOk)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.timeout_invalid", QStringLiteral("规则 %1 的 timeoutMs 非法。")).arg(logicalRuleIndex + 1);
                }
                return false;
            }

            bool priorityOk = false;
            const qint32 kRulePriority = priorityItem->text().trimmed().toInt(&priorityOk);
            if (!priorityOk)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_priority_invalid", QStringLiteral("规则 %1 的优先级非法。")).arg(logicalRuleIndex + 1);
                }
                return false;
            }

            ruleModel.ruleName = ruleNameItem->text().trimmed();
            ruleModel.enabled = (enabledItem->checkState() == Qt::Checked);
            ruleModel.callbackType = callbackType;
            ruleModel.initiatorPattern = normalizeMatchAllPattern(initiatorEdit->text());
            ruleModel.targetPattern = normalizeMatchAllPattern(targetEdit->text());
            ruleModel.matchMode = static_cast<quint32>(matchModeCombo->currentData().toUInt());
            ruleModel.action = static_cast<quint32>(actionCombo->currentData().toUInt());
            ruleModel.timeoutMs = kTimeoutMs;
            ruleModel.timeoutDefaultDecision = static_cast<quint32>(timeoutDecisionCombo->currentData().toUInt());
            ruleModel.priority = kRulePriority;
            ruleModel.comment = commentEdit->text().trimmed();

            if (!ruleModel.initiatorPattern.trimmed().isEmpty())
            {
                // All callback types' initiators are ultimately compared against the kernel-collected process image
                // path; here, common user-mode paths (e.g., C:\...) are uniformly converted to a kernel-matching format.
                ruleModel.initiatorPattern =
                    normalizeUserModeFilePathPatternForKernel(ruleModel.initiatorPattern);
            }

            if (ruleModel.callbackType == KSWORD_ARK_CALLBACK_TYPE_REGISTRY)
            {
                ruleModel.targetPattern = normalizeRegistryTargetPatternForKernel(ruleModel.targetPattern);
            }
            else if (!ruleModel.targetPattern.trimmed().isEmpty())
            {
                ruleModel.targetPattern =
                    normalizeUserModeFilePathPatternForKernel(ruleModel.targetPattern);
            }

            if (ruleModel.action != KSWORD_ARK_RULE_ACTION_ASK_USER)
            {
                ruleModel.timeoutMs = 0U;
            }

            ruleListOut->push_back(ruleModel);
        }

        return true;
    }

    bool collectAllRulesFromUi(
        QList<CallbackRuleModel>* ruleListOut,
        QString* errorTextOut) const
    {
        if (ruleListOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_list_out_null", QStringLiteral("内部错误：ruleListOut 为空。"));
            }
            return false;
        }

        ruleListOut->clear();
        for (auto iterator = ruleTableMap_.begin(); iterator != ruleTableMap_.end(); ++iterator)
        {
            const quint32 kCallbackType = iterator.key();
            QTableWidget* ruleTable = iterator.value();
            QList<CallbackRuleModel> typeRuleList;
            if (!collectRuleListFromTable(ruleTable, kCallbackType, &typeRuleList, errorTextOut))
            {
                return false;
            }
            ruleListOut->append(typeRuleList);
        }

        return true;
    }

    bool collectConfigFromUi(
        CallbackConfigDocument* configOut,
        QString* errorTextOut)
    {
        if (configOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.config_out_null", QStringLiteral("内部错误：configOut 为空。"));
            }
            return false;
        }

        CallbackConfigDocument configDocument;
        configDocument.schemaVersion = KSWORD_ARK_CALLBACK_RULE_SCHEMA_VERSION;
        configDocument.exportedAtUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
        configDocument.appVersion = QStringLiteral("Ksword5.1");
        configDocument.globalEnabled = (globalEnabledCheck_ != nullptr) ? globalEnabledCheck_->isChecked() : true;
        configDocument.ruleVersion = nextRuleVersion_;

        if (!collectGroupsFromUi(&configDocument.groups, errorTextOut))
        {
            return false;
        }
        if (!collectAllRulesFromUi(&configDocument.rules, errorTextOut))
        {
            return false;
        }

        const CallbackValidationResult kValidationResult = validateCallbackConfig(configDocument);
        if (!kValidationResult.success)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kValidationResult.errorList.join(QStringLiteral("；"));
            }
            return false;
        }

        for (const QString& warningText : kValidationResult.warningList)
        {
            appendAppLog(kernelText("kernel.callback.intercept.config.warning", QStringLiteral("配置警告：%1")).arg(warningText));
        }

        *configOut = configDocument;
        return true;
    }

    void updateStatusLabel()
    {
        if (statusLabel_ == nullptr)
        {
            return;
        }

        const QString kStatusText = kernelText("kernel.callback.intercept.status.runtime", QStringLiteral(
            "状态：%1 | 驱动%2 | 规则版本=%3 | 规则数=%4 | 等待接收者=%5 | 待决策=%6 | 生效时间=%7 | 未应用修改=%8"))
            .arg(rulesApplied_
                ? kernelText("kernel.callback.intercept.status.applied", QStringLiteral("已应用"))
                : kernelText("kernel.callback.intercept.status.not_applied", QStringLiteral("未应用")))
            .arg(runtimeState_.driverOnline != 0U
                ? kernelText("kernel.callback.intercept.status.online", QStringLiteral("在线"))
                : kernelText("kernel.callback.intercept.status.offline", QStringLiteral("离线")))
            .arg(runtimeState_.appliedRuleVersion)
            .arg(runtimeState_.ruleCount)
            .arg(runtimeState_.waitingReceiverCount)
            .arg(runtimeState_.pendingDecisionCount)
            .arg(utc100nsToDisplayText(runtimeState_.appliedAtUtc100ns))
            .arg(dirty_
                ? kernelText("kernel.callback.intercept.status.yes", QStringLiteral("是"))
                : kernelText("kernel.callback.intercept.status.no", QStringLiteral("否")));
        statusLabel_->setText(kStatusText);
        statusLabel_->setStyleSheet(
            QStringLiteral("color:%1;font-weight:600;")
            .arg(runtimeState_.driverOnline != 0U
                ? ksword_theme::successHex()
                : ksword_theme::warningAccentColor().name()));
    }

    // describeDegradedCallbacks: Lists kernel callbacks that failed to register on this machine.
    // The driver loads normally in these scenarios, so the UI must indicate 'which capability is missing and the
    // original NTSTATUS value' rather than leading users to believe the rule failure is due to software errors.
    QString describeDegradedCallbacks(const KSWORD_ARK_CALLBACK_RUNTIME_STATE& runtimeState) const
    {
        const auto kAppendItem = [](QStringList& itemList, const QString& capabilityText, const long statusValue) {
            if (statusValue == 0)
            {
                return;
            }
            itemList.append(
                kernelText("kernel.callback.intercept.runtime.degraded_item", QStringLiteral("%1（status=0x%2）"))
                .arg(capabilityText)
                .arg(static_cast<unsigned long>(statusValue), 8, 16, QLatin1Char('0')));
        };

        QStringList degradedItems;
        kAppendItem(
            degradedItems,
            kernelText("kernel.callback.intercept.runtime.capability.ask_user", QStringLiteral("用户询问队列")),
            runtimeState.waitQueueStatus);
        kAppendItem(
            degradedItems,
            kernelText("kernel.callback.intercept.runtime.capability.registry", QStringLiteral("注册表回调")),
            runtimeState.registryCallbackStatus);
        kAppendItem(
            degradedItems,
            kernelText("kernel.callback.intercept.runtime.capability.process", QStringLiteral("进程回调")),
            runtimeState.processCallbackStatus);
        kAppendItem(
            degradedItems,
            kernelText("kernel.callback.intercept.runtime.capability.thread", QStringLiteral("线程回调")),
            runtimeState.threadCallbackStatus);
        kAppendItem(
            degradedItems,
            kernelText("kernel.callback.intercept.runtime.capability.image", QStringLiteral("映像加载回调")),
            runtimeState.imageCallbackStatus);
        kAppendItem(
            degradedItems,
            kernelText("kernel.callback.intercept.runtime.capability.object", QStringLiteral("对象句柄回调")),
            runtimeState.objectCallbackStatus);

        return degradedItems.join(QStringLiteral("、"));
    }

    bool queryRuntimeState(KSWORD_ARK_CALLBACK_RUNTIME_STATE* runtimeStateOut, QString* errorTextOut) const
    {
        if (runtimeStateOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.runtime_state_out_null", QStringLiteral("内部错误：runtimeStateOut 为空。"));
            }
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::CallbackRuntimeResult kRuntimeResult = kDriverClient.queryCallbackRuntimeState();
        if (!kRuntimeResult.io.ok)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.runtime.query_failed", QStringLiteral("获取驱动状态失败，error=%1，detail=%2"))
                    .arg(kRuntimeResult.io.win32Error)
                    .arg(callbackRuleIoMessageText(QString::fromStdString(kRuntimeResult.io.message)));
            }
            return false;
        }

        *runtimeStateOut = kRuntimeResult.state;
        return true;
    }

    void reloadRuntimeState()
    {
        KSWORD_ARK_CALLBACK_RUNTIME_STATE runtimeState{};
        QString errorText;
        if (!queryRuntimeState(&runtimeState, &errorText))
        {
            RtlZeroMemory(&runtimeState_, sizeof(runtimeState_));
            appendAppLog(kernelText("kernel.callback.intercept.runtime.reload_failed", QStringLiteral("重新加载驱动状态失败：%1")).arg(errorText));
            updateStatusLabel();
            return;
        }

        runtimeState_ = runtimeState;
        rulesApplied_ = (runtimeState_.rulesApplied != 0U);
        if (runtimeState_.appliedRuleVersion >= nextRuleVersion_)
        {
            nextRuleVersion_ = runtimeState_.appliedRuleVersion + 1ULL;
        }

        appendAppLog(
            kernelText("kernel.callback.intercept.runtime.refreshed", QStringLiteral("驱动状态已刷新：online=%1, groups=%2, rules=%3, pending=%4, waiting=%5"))
            .arg(runtimeState_.driverOnline)
            .arg(runtimeState_.groupCount)
            .arg(runtimeState_.ruleCount)
            .arg(runtimeState_.pendingDecisionCount)
            .arg(runtimeState_.waitingReceiverCount));

        // On some machines, certain callback types may be missing due to altitude conflicts or callback slot exhaustion;
        // the driver loads normally. This explicitly informs the user of missing items and the original state.
        const QString kDegradedText = describeDegradedCallbacks(runtimeState_);
        if (!kDegradedText.isEmpty())
        {
            appendAppLog(
                kernelText(
                    "kernel.callback.intercept.runtime.degraded",
                    QStringLiteral("本机以降级模式运行，以下内核回调不可用：%1。KSword 其余功能不受影响。"))
                .arg(kDegradedText));
        }
        updateStatusLabel();
    }

    void ensureMinifilterRuntimeStarted(
        const CallbackConfigDocument& configDocument,
        const ksword::ark::DriverClient& driverClient)
    {
        // Action: Automatically starts the shared file-monitor minifilter after applying Minifilter rules.
        // Note: Only send START, do not actively send STOP, to avoid overriding the user's existing run intent on the file monitoring page.
        // Returns: void; on failure, only writes to the application log; the rule application itself remains successful.
        if (!hasActiveMinifilterRule(configDocument))
        {
            return;
        }

        const ksword::ark::FileMonitorStatusResult kBeforeStatus =
            driverClient.queryFileMonitorStatus();
        if (kBeforeStatus.io.ok &&
            (kBeforeStatus.runtimeFlags & KSWORD_ARK_FILE_MONITOR_RUNTIME_STARTED) != 0U)
        {
            appendAppLog(
                kernelText("kernel.callback.intercept.runtime.minifilter.already_started", QStringLiteral("文件系统微过滤器已处于启动状态：mask=0x%1, queued=%2, dropped=%3。"))
                .arg(kBeforeStatus.operationMask, 8, 16, QChar('0')).toUpper()
                .arg(kBeforeStatus.queuedCount)
                .arg(kBeforeStatus.droppedCount));
            return;
        }

        if (!kBeforeStatus.io.ok)
        {
            appendAppLog(
                kernelText("kernel.callback.intercept.runtime.minifilter.query_failed", QStringLiteral("查询文件系统微过滤器状态失败，仍尝试启动：error=%1，detail=%2"))
                .arg(kBeforeStatus.io.win32Error)
                .arg(callbackRuleIoMessageText(QString::fromStdString(kBeforeStatus.io.message))));
        }

        ksword::ark::IoResult startResult = driverClient.controlFileMonitor(
            KSWORD_ARK_FILE_MONITOR_ACTION_START,
            KSWORD_ARK_FILE_MONITOR_OPERATION_ALL,
            0UL,
            0UL);
        if (!startResult.ok)
        {
            const unsigned long kLegacyOperationMask =
                KSWORD_ARK_FILE_MONITOR_OPERATION_ALL & ~KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL;
            const ksword::ark::IoResult kLegacyStartResult = driverClient.controlFileMonitor(
                KSWORD_ARK_FILE_MONITOR_ACTION_START,
                kLegacyOperationMask,
                0UL,
                0UL);
            if (kLegacyStartResult.ok)
            {
                appendAppLog(
                    kernelText("kernel.callback.intercept.runtime.minifilter.legacy_started", QStringLiteral("文件系统微过滤器以旧掩码启动：mask=0x%1；当前驱动可能尚未支持 FSCTL 事件。"))
                    .arg(kLegacyOperationMask, 8, 16, QChar('0')).toUpper());
                startResult = kLegacyStartResult;
            }
        }
        if (!startResult.ok)
        {
            const ksword::ark::FileMonitorStatusResult kFailStatus =
                driverClient.queryFileMonitorStatus();
            const QString kStatusSuffix = kFailStatus.io.ok
                ? kernelText("kernel.callback.intercept.runtime.minifilter.status_suffix", QStringLiteral("；status=%1，flags=0x%2，mask=0x%3，register=%4，start=%5，last=%6，queued=%7，dropped=%8"))
                    .arg(callbackRuleIoMessageText(QString::fromStdString(kFailStatus.io.message)))
                    .arg(kFailStatus.runtimeFlags, 8, 16, QChar('0')).toUpper()
                    .arg(kFailStatus.operationMask, 8, 16, QChar('0')).toUpper()
                    .arg(formatCallbackNtStatusHex(kFailStatus.registerStatus))
                    .arg(formatCallbackNtStatusHex(kFailStatus.startStatus))
                    .arg(formatCallbackNtStatusHex(kFailStatus.lastErrorStatus))
                    .arg(kFailStatus.queuedCount)
                    .arg(kFailStatus.droppedCount)
                : kernelText("kernel.callback.intercept.runtime.minifilter.status_query_failed", QStringLiteral("；status-query-failed error=%1，detail=%2"))
                    .arg(kFailStatus.io.win32Error)
                    .arg(callbackRuleIoMessageText(QString::fromStdString(kFailStatus.io.message)));
            appendAppLog(
                kernelText("kernel.callback.intercept.runtime.minifilter.start_warning", QStringLiteral("警告：文件系统微过滤器启动失败，Minifilter 自定义规则暂时不会收到文件事件：error=%1，detail=%2%3"))
                .arg(startResult.win32Error)
                .arg(callbackRuleIoMessageText(QString::fromStdString(startResult.message)))
                .arg(kStatusSuffix));
            return;
        }

        const ksword::ark::FileMonitorStatusResult kAfterStatus =
            driverClient.queryFileMonitorStatus();
        if (kAfterStatus.io.ok)
        {
            appendAppLog(
                kernelText("kernel.callback.intercept.runtime.minifilter.started", QStringLiteral("文件系统微过滤器已启动：flags=0x%1, mask=0x%2, register=%3, start=%4, last=%5。"))
                .arg(kAfterStatus.runtimeFlags, 8, 16, QChar('0')).toUpper()
                .arg(kAfterStatus.operationMask, 8, 16, QChar('0')).toUpper()
                .arg(formatCallbackNtStatusHex(kAfterStatus.registerStatus))
                .arg(formatCallbackNtStatusHex(kAfterStatus.startStatus))
                .arg(formatCallbackNtStatusHex(kAfterStatus.lastErrorStatus)));
        }
        else
        {
            appendAppLog(
                kernelText("kernel.callback.intercept.runtime.minifilter.post_check_failed", QStringLiteral("文件系统微过滤器启动命令已下发，但状态复查失败：error=%1，detail=%2"))
                .arg(kAfterStatus.io.win32Error)
                .arg(callbackRuleIoMessageText(QString::fromStdString(kAfterStatus.io.message))));
        }
    }

    void applyRulesToDriver()
    {
        CallbackConfigDocument configDocument;
        QString errorText;
        if (!collectConfigFromUi(&configDocument, &errorText))
        {
            QMessageBox::warning(hostPage_,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.apply.failed", QStringLiteral("应用失败：%1")).arg(errorText));
            appendAppLog(kernelText("kernel.callback.intercept.apply.failed", QStringLiteral("应用失败：%1")).arg(errorText));
            return;
        }

        QByteArray blobBytes;
        if (!buildCallbackRuleBlobFromConfig(configDocument, &blobBytes, &errorText))
        {
            QMessageBox::warning(hostPage_,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.apply.compile_failed", QStringLiteral("规则编译失败：%1")).arg(errorText));
            appendAppLog(kernelText("kernel.callback.intercept.apply.compile_failed", QStringLiteral("规则编译失败：%1")).arg(errorText));
            return;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::IoResult kApplyResult = kDriverClient.setCallbackRules(
            blobBytes.data(),
            static_cast<unsigned long>(blobBytes.size()));

        if (!kApplyResult.ok)
        {
            QMessageBox::warning(
                hostPage_,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.apply.error", QStringLiteral("应用到驱动失败，error=%1。")).arg(kApplyResult.win32Error));
            appendAppLog(kernelText("kernel.callback.intercept.apply.log_failed", QStringLiteral("应用到驱动失败，error=%1，detail=%2"))
                .arg(kApplyResult.win32Error)
                .arg(callbackRuleIoMessageText(QString::fromStdString(kApplyResult.message))));
            return;
        }

        rulesApplied_ = true;
        dirty_ = false;
        nextRuleVersion_ = configDocument.ruleVersion + 1ULL;

        appendAppLog(
            kernelText("kernel.callback.intercept.apply.success", QStringLiteral("应用成功：ruleVersion=%1, groupCount=%2, ruleCount=%3, blobBytes=%4"))
            .arg(configDocument.ruleVersion)
            .arg(configDocument.groups.size())
            .arg(configDocument.rules.size())
            .arg(blobBytes.size()));

        ensureMinifilterRuntimeStarted(configDocument, kDriverClient);
        reloadRuntimeState();
        const bool kHasAskUserRule = std::any_of(
            configDocument.rules.cbegin(),
            configDocument.rules.cend(),
            [](const CallbackRuleModel& ruleModel) {
                return ruleModel.enabled &&
                    (ruleModel.callbackType == KSWORD_ARK_CALLBACK_TYPE_REGISTRY ||
                        ruleModel.callbackType == KSWORD_ARK_CALLBACK_TYPE_MINIFILTER) &&
                    ruleModel.action == KSWORD_ARK_RULE_ACTION_ASK_USER;
            });
        if (kHasAskUserRule && runtimeState_.waitingReceiverCount == 0U)
        {
            appendAppLog(
                kernelText("kernel.callback.intercept.apply.ask_user_warning", QStringLiteral("警告：检测到“询问用户”规则，但当前等待接收者为 0。请确认弹窗管理器已启动，否则驱动将按默认决策回退。")));
        }
        updateStatusLabel();
    }

    void importConfigFromFile()
    {
        const QString kFilePath = QFileDialog::getOpenFileName(
            hostPage_,
            kernelText("kernel.callback.intercept.import.dialog_title", QStringLiteral("导入回调规则")),
            QString(),
            QStringLiteral("Ksword Rule File (*.kswrules);;JSON (*.json);;All Files (*)"));
        if (kFilePath.trimmed().isEmpty())
        {
            return;
        }

        QFile inputFile(kFilePath);
        if (!inputFile.open(QIODevice::ReadOnly))
        {
            const QString kErrorText = kernelText("kernel.callback.intercept.import.open_failed", QStringLiteral("打开文件失败：%1")).arg(inputFile.errorString());
            QMessageBox::warning(hostPage_, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), kErrorText);
            appendAppLog(kernelText("kernel.callback.intercept.import.failed", QStringLiteral("导入失败：%1")).arg(kErrorText));
            return;
        }

        const QByteArray kJsonBytes = inputFile.readAll();
        inputFile.close();

        CallbackConfigDocument importedDocument;
        QStringList warningList;
        QString errorText;
        if (!importCallbackConfigFromJson(kJsonBytes, &importedDocument, &warningList, &errorText))
        {
            QMessageBox::warning(hostPage_, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), errorText);
            appendAppLog(kernelText("kernel.callback.intercept.import.failed", QStringLiteral("导入失败：%1")).arg(errorText));
            return;
        }

        const CallbackValidationResult kValidationResult = validateCallbackConfig(importedDocument);
        if (!kValidationResult.success)
        {
            const QString kValidateError = kValidationResult.errorList.join(QStringLiteral("；"));
            QMessageBox::warning(hostPage_,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.import.invalid", QStringLiteral("导入配置不合法：%1")).arg(kValidateError));
            appendAppLog(kernelText("kernel.callback.intercept.import.invalid", QStringLiteral("导入配置不合法：%1")).arg(kValidateError));
            return;
        }

        for (const QString& warningText : warningList)
        {
            appendAppLog(kernelText("kernel.callback.intercept.import.warning", QStringLiteral("导入警告：%1")).arg(warningText));
        }
        for (const QString& warningText : kValidationResult.warningList)
        {
            appendAppLog(kernelText("kernel.callback.intercept.config.warning", QStringLiteral("配置警告：%1")).arg(warningText));
        }

        populateUiFromConfig(importedDocument);
        nextRuleVersion_ = std::max(nextRuleVersion_, importedDocument.ruleVersion + 1ULL);
        setDirtyState(true);
        appendAppLog(kernelText("kernel.callback.intercept.import.success", QStringLiteral("导入成功：%1")).arg(kFilePath));
    }

    void exportConfigToFile()
    {
        CallbackConfigDocument configDocument;
        QString errorText;
        if (!collectConfigFromUi(&configDocument, &errorText))
        {
            QMessageBox::warning(hostPage_,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.export.failed", QStringLiteral("导出失败：%1")).arg(errorText));
            appendAppLog(kernelText("kernel.callback.intercept.export.failed", QStringLiteral("导出失败：%1")).arg(errorText));
            return;
        }

        const QString kFilePath = QFileDialog::getSaveFileName(
            hostPage_,
            kernelText("kernel.callback.intercept.export.dialog_title", QStringLiteral("导出回调规则")),
            QStringLiteral("callback_rules.kswrules"),
            QStringLiteral("Ksword Rule File (*.kswrules);;JSON (*.json);;All Files (*)"));
        if (kFilePath.trimmed().isEmpty())
        {
            return;
        }

        QByteArray jsonBytes;
        if (!exportCallbackConfigToJson(configDocument, &jsonBytes, &errorText))
        {
            QMessageBox::warning(hostPage_,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.export.failed", QStringLiteral("导出失败：%1")).arg(errorText));
            appendAppLog(kernelText("kernel.callback.intercept.export.failed", QStringLiteral("导出失败：%1")).arg(errorText));
            return;
        }

        QFile outputFile(kFilePath);
        if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
        {
            const QString kIoError = kernelText("kernel.callback.intercept.export.write_failed", QStringLiteral("写入失败：%1")).arg(outputFile.errorString());
            QMessageBox::warning(hostPage_, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), kIoError);
            appendAppLog(kernelText("kernel.callback.intercept.export.failed", QStringLiteral("导出失败：%1")).arg(kIoError));
            return;
        }
        outputFile.write(jsonBytes);
        outputFile.close();

        appendAppLog(kernelText("kernel.callback.intercept.export.success", QStringLiteral("导出成功：%1")).arg(kFilePath));
    }

    void populateUiFromConfig(const CallbackConfigDocument& configDocument)
    {
        ignoreUiSignal_ = true;

        if (globalEnabledCheck_ != nullptr)
        {
            globalEnabledCheck_->setChecked(configDocument.globalEnabled);
        }

        groupTable_->setRowCount(0);
        QList<CallbackRuleGroupModel> sortedGroups = configDocument.groups;
        std::sort(sortedGroups.begin(), sortedGroups.end(), [](const CallbackRuleGroupModel& left, const CallbackRuleGroupModel& right) {
            if (left.priority != right.priority)
            {
                return left.priority < right.priority;
            }
            return left.groupId < right.groupId;
        });
        for (const CallbackRuleGroupModel& groupModel : sortedGroups)
        {
            appendGroupRow(groupModel);
        }
        addDefaultGroupIfNeeded();

        for (auto iterator = ruleTableMap_.begin(); iterator != ruleTableMap_.end(); ++iterator)
        {
            QTableWidget* ruleTable = iterator.value();
            if (ruleTable != nullptr)
            {
                ruleTable->setRowCount(0);
            }
        }

        QList<CallbackRuleModel> sortedRules = configDocument.rules;
        std::sort(sortedRules.begin(), sortedRules.end(), [](const CallbackRuleModel& left, const CallbackRuleModel& right) {
            if (left.callbackType != right.callbackType)
            {
                return left.callbackType < right.callbackType;
            }
            if (left.priority != right.priority)
            {
                return left.priority < right.priority;
            }
            return left.ruleId < right.ruleId;
        });
        for (const CallbackRuleModel& ruleModel : sortedRules)
        {
            QTableWidget* ruleTable = ruleTableMap_.value(ruleModel.callbackType, nullptr);
            if (ruleTable == nullptr)
            {
                continue;
            }
            appendRuleRow(ruleTable, ruleModel.callbackType, ruleModel);
        }

        ignoreUiSignal_ = false;
        refreshRuleGroupComboOptions();
    }

private:
    QWidget* hostPage_ = nullptr;
    QPointer<CallbackPromptManager> promptManager_;

    QCheckBox* globalEnabledCheck_ = nullptr;
    QPushButton* applyButton_ = nullptr;
    QPushButton* reloadStateButton_ = nullptr;
    QPushButton* importButton_ = nullptr;
    QPushButton* exportButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QPushButton* addGroupButton_ = nullptr;
    QPushButton* removeGroupButton_ = nullptr;
    QPushButton* renameGroupButton_ = nullptr;
    QPushButton* moveGroupUpButton_ = nullptr;
    QPushButton* moveGroupDownButton_ = nullptr;
    QTableWidget* groupTable_ = nullptr;

    QPushButton* addRuleButton_ = nullptr;
    QPushButton* removeRuleButton_ = nullptr;
    QPushButton* moveRuleUpButton_ = nullptr;
    QPushButton* moveRuleDownButton_ = nullptr;
    QTabWidget* ruleTabWidget_ = nullptr;
    QHash<quint32, QTableWidget*> ruleTableMap_;
    QHash<int, quint32> tabCallbackTypeMap_;

    QLineEdit* minifilterBypassPidEdit_ = nullptr;
    QPushButton* minifilterBypassAddButton_ = nullptr;
    QPushButton* minifilterBypassRemoveButton_ = nullptr;
    QPushButton* minifilterBypassApplyButton_ = nullptr;
    QPushButton* minifilterBypassClearButton_ = nullptr;
    QPushButton* minifilterBypassRefreshButton_ = nullptr;
    QLabel* minifilterBypassStatusLabel_ = nullptr;
    QTableWidget* minifilterBypassPidTable_ = nullptr;

    QCheckBox* processProtectEnabledCheck_ = nullptr;
    QCheckBox* processProtectLogCheck_ = nullptr;
    QCheckBox* processProtectTrustSystemCheck_ = nullptr;
    QCheckBox* processProtectTrustPeersCheck_ = nullptr;
    QComboBox* processProtectKindCombo_ = nullptr;
    QLineEdit* processProtectTargetEdit_ = nullptr;
    QComboBox* processProtectPresetCombo_ = nullptr;
    QCheckBox* processProtectThreadsCheck_ = nullptr;
    QLineEdit* processProtectRuleNameEdit_ = nullptr;
    QPushButton* processProtectAddRuleButton_ = nullptr;
    QPushButton* processProtectApplyPresetButton_ = nullptr;
    QPushButton* processProtectRemoveRuleButton_ = nullptr;
    QTableWidget* processProtectRuleTable_ = nullptr;
    QComboBox* processProtectTrustedKindCombo_ = nullptr;
    QLineEdit* processProtectTrustedTargetEdit_ = nullptr;
    QPushButton* processProtectTrustedAddButton_ = nullptr;
    QPushButton* processProtectTrustedRemoveButton_ = nullptr;
    QTableWidget* processProtectTrustedTable_ = nullptr;
    QPushButton* processProtectApplyButton_ = nullptr;
    QPushButton* processProtectRefreshButton_ = nullptr;
    QPushButton* processProtectClearButton_ = nullptr;
    QLabel* processProtectStatusLabel_ = nullptr;

    QCheckBox* processProtectKernelCheck_ = nullptr;
    QCheckBox* processProtectSelfHealCheck_ = nullptr;
    QSpinBox* processProtectScanIntervalSpin_ = nullptr;
    QComboBox* processProtectKernelCombo_ = nullptr;
    QCheckBox* processProtectApplyOnCreateCheck_ = nullptr;
    QCheckBox* processProtectSelfHealRuleCheck_ = nullptr;
    QCheckBox* processProtectClearDebugPortCheck_ = nullptr;
    QPushButton* processProtectApplyKernelButton_ = nullptr;

    QPlainTextEdit* appLogEditor_ = nullptr;
    QPlainTextEdit* eventLogEditor_ = nullptr;

    QPushButton* startFileMonitorFsctlButton_ = nullptr;
    QPushButton* drainFileMonitorButton_ = nullptr;
    QPushButton* clearFileMonitorButton_ = nullptr;
    QPushButton* exportFileMonitorButton_ = nullptr;
    QCheckBox* fileMonitorFsctlOnlyCheck_ = nullptr;
    QLabel* fileMonitorStatusLabel_ = nullptr;
    QTableWidget* fileMonitorTable_ = nullptr;
    QTimer* fileMonitorDrainTimer_ = nullptr;
    QHash<quint32, QString> fileMonitorProcessNameCache_;
    bool fileMonitorDrainInFlight_ = false;    // m_fileMonitorDrainInFlight: Flag indicating an in-flight background drain task; read/written only on the UI thread to prevent periodic timer request accumulation.

    KSWORD_ARK_CALLBACK_RUNTIME_STATE runtimeState_{};
    quint64 nextRuleVersion_ = 1ULL;
    bool rulesApplied_ = false;
    bool dirty_ = false;
    bool ignoreUiSignal_ = false;
};

void KernelDock::initializeCallbackInterceptTab()
{
    if (callbackInterceptPage_ == nullptr || callbackInterceptController_ != nullptr)
    {
        return;
    }

    callbackInterceptController_ = new CallbackInterceptController(callbackInterceptPage_, this);
}
