#include "HandleDock.h"

#include "../internationalization/LanguageManager.h"
#include "../ui/TableInteractionSupport.h"
#include "../../../shared/platform/log/Log.h"
#include "../Theme.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QHash>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QImage>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPixmap>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QSet>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QSpinBox>
#include <QStringList>
#include <QTabWidget>
#include <QThreadPool>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <QVector>

#include <algorithm>
#include <atomic>
#include <memory>
#include <set>
#include <string>
#include <vector>

// Process icon resolution requires direct calls to Win32/Shell/COM interfaces; these are included uniformly after Qt headers.
// WIN32_LEAN_AND_MEAN and NOMINMAX are uniformly defined by the project preprocessor; no need to redeclare in this file.
#include <Windows.h>
#include <Shellapi.h>
#include <objbase.h>

namespace
{
    // buildBlueButtonStyle:
    // - Generate a unified project button style where all colors come from dynamic theme roles, with real-time switching between light and dark modes.
    // - When iconOnly=true, reduce padding for 28x28 icon buttons.
    QString buildBlueButtonStyle(const bool iconOnly)
    {
        QString buttonStyle = ksword_theme::themedButtonStyle();
        if (iconOnly)
        {
            buttonStyle += QStringLiteral("QPushButton{padding:4px;}");
        }
        return buttonStyle;
    }

    // installReadOnlyTreeCopyMenu:
    // - Install a 'Copy Current Row' right-click menu for the read-only QTreeWidget;
    // - Input treeWidget: read-only tree table for Object Header / Object Type, etc.;
    // - Processing: Concatenate visible columns as TSV when a row is clicked and write to clipboard.
    // - Return: None; silently returns if clipboard or behavior is empty, triggering no handle write operations.
    void installReadOnlyTreeCopyMenu(QTreeWidget* treeWidget)
    {
        if (treeWidget == nullptr)
        {
            return;
        }

        treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(treeWidget, &QTreeWidget::customContextMenuRequested, treeWidget, [treeWidget](const QPoint& localPosition)
            {
                QTreeWidgetItem* clickedItem = treeWidget->itemAt(localPosition);
                if (clickedItem != nullptr)
                {
                    treeWidget->setCurrentItem(clickedItem);
                }

                QMenu menu(treeWidget);
                menu.setStyleSheet(ksword_theme::contextMenuStyle());
                QAction* copyRowAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/handle_copy_row.svg")),
                    QStringLiteral("复制当前行"));
                copyRowAction->setEnabled(clickedItem != nullptr);
                if (menu.exec(treeWidget->viewport()->mapToGlobal(localPosition)) != copyRowAction ||
                    clickedItem == nullptr ||
                    QApplication::clipboard() == nullptr)
                {
                    return;
                }

                QStringList fields;
                fields.reserve(treeWidget->columnCount());
                for (int columnIndex = 0; columnIndex < treeWidget->columnCount(); ++columnIndex)
                {
                    fields.push_back(clickedItem->text(columnIndex));
                }
                QApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
            });
    }

    // buildLineEditStyle purpose: Unify the visual style of filter input fields.
    QString buildLineEditStyle()
    {
        return QStringLiteral(
            "QLineEdit {"
            "  border: 1px solid %1;"
            "  border-radius: 3px;"
            "  background: %2;"
            "  color: %3;"
            "  padding: 3px 6px;"
            "}"
            "QLineEdit:focus {"
            "  border: 1px solid %4;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex);
    }

    // buildComboAndSpinStyle: Unifies the style of combo boxes and spin boxes.
    QString buildComboAndSpinStyle()
    {
        return QStringLiteral(
            "QSpinBox {"
            "  border: 1px solid %1;"
            "  border-radius: 3px;"
            "  background: %2;"
            "  color: %3;"
            "  padding: 2px 6px;"
            "}"
            "QSpinBox:hover {"
            "  border-color: %4;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            + ksword_theme::themedComboBoxStyle();
    }

    // buildHeaderStyle purpose: Unify header styles to maintain theme consistency.
    QString buildHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{"
            "  color:%1;"
            "  background:transparent; /* %2 */"
            "  border:1px solid %3;"
            "  font-weight:600;"
            "}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    // boolText purpose: unifies boolean values into Chinese 'Yes/No' text.
    QString boolText(const bool value)
    {
        return value ? QStringLiteral("是") : QStringLiteral("否");
    }

    // kHandleRenderSplashThreshold:
    // - Controls when to display the splash prompt for rendering the handle list.
    // - Enabled only for large data volume rendering to avoid frequent flickering in small lists.
    constexpr std::size_t kHandleRenderSplashThreshold = 50000;

    // kHandleRenderProgressStep:
    // - Control progress write-back frequency;
    // - Reduces overhead by updating in batches.
    constexpr std::size_t kHandleRenderProgressStep = 4096;

    // HandleRenderSplashScope:
    // - Display the startup splash screen during rendering of a huge handle table.
    // - Continuously write back the progress of 'rendering handle list to GUI' to mitigate the perception of 'program freeze'.
    class HandleRenderSplashScope final
    {
    public:
        explicit HandleRenderSplashScope(const std::size_t totalRowCount)
            : totalRowCount_(totalRowCount)
        {
            if (totalRowCount_ < kHandleRenderSplashThreshold)
            {
                return;
            }

            statusText_ = ks::i18n::contextText(
                QStringLiteral("handle.splash.render_list"),
                QStringLiteral("渲染句柄列表到图形界面")).toUtf8().toStdString();
            visible_ = kSplash.show(statusText_);
            if (!visible_)
            {
                return;
            }

            kSplash.progress(statusText_, 1);
        }

        ~HandleRenderSplashScope()
        {
            if (visible_)
            {
                kSplash.hide();
            }
        }

        void update(const std::size_t renderedRowCount) const
        {
            if (!visible_ || totalRowCount_ == 0)
            {
                return;
            }

            const std::size_t kNormalizedRenderedCount = std::min(renderedRowCount, totalRowCount_);
            const int kProgressPercent = std::max(
                1,
                std::min(99, static_cast<int>((kNormalizedRenderedCount * 100) / totalRowCount_)));
            kSplash.progress(statusText_, kProgressPercent);
        }

        void finish() const
        {
            if (visible_)
            {
                kSplash.progress(statusText_, 100);
            }
        }

    private:
        std::size_t totalRowCount_ = 0; // m_totalRowCount: The total number of rows currently rendered.
        std::string statusText_;        // m_statusText: Startup screen text parsed according to the current language (UTF-8).
        bool visible_ = false;          // m_visible: Whether the startup page was successfully displayed.
    };

    // kHandleProcessIconBatchSize:
    // - Control how many process instance results are returned in a single batch for background icon resolution.
    // - Batched re-injection allows icons to appear gradually while keeping cross-thread calls and viewport repaint counts within a controllable range.
    constexpr qsizetype kHandleProcessIconBatchSize = 32;

    // kHandleProcessIconCacheLimit:
    // - Limit the maximum number of cache entries for 'process instance -> icon'.
    // - Prevent cache from growing indefinitely after repeated long-term refreshes.
    constexpr qsizetype kHandleProcessIconCacheLimit = 4096;

    // HandleProcessIconRequest:
    // - Describes a pending process instance icon resolution request;
    // - Contains only value-type fields, safe to copy to worker threads.
    struct HandleProcessIconRequest
    {
        QString identityKey;                   // identityKey: Process instance key composed of PID and creation time.
        std::uint32_t processId = 0;           // processId: Target process PID.
        std::uint64_t processCreationTime = 0; // processCreationTime: Target process creation time, used to verify PID identity.
    };

    // HandleProcessIconResult:
    // - Describes a process icon result that has been fully resolved in the background.
    // - Carries only QImage; QPixmap/QIcon are left for the UI thread to construct.
    struct HandleProcessIconResult
    {
        QString identityKey; // identityKey: Process instance key used to locate cache and table entries during backfill.
        QImage iconImage;    // iconImage: Bitmap of the icon extracted by the Shell; null indicates parsing failed.
    };

    // HandleProcessIconComScope:
    // - initialize COM for the icon parsing worker thread in apartment mode and release it in the destructor;
    // - Shell icon retrieval may load third-party icon handlers and fail if the COM environment is missing.
    // Input: None.
    // Returns: None (RAII object, automatically released when the scope ends).
    class HandleProcessIconComScope final
    {
    public:
        HandleProcessIconComScope()
        {
            // Failure codes like RPC_E_CHANGED_MODE indicate that the thread apartment was already created by another party; in this case, CoUninitialize cannot be paired.
            const HRESULT kInitializeResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            shouldUninitialize_ = SUCCEEDED(kInitializeResult);
        }

        ~HandleProcessIconComScope()
        {
            if (shouldUninitialize_)
            {
                ::CoUninitialize();
            }
        }

        HandleProcessIconComScope(const HandleProcessIconComScope&) = delete;
        HandleProcessIconComScope& operator=(const HandleProcessIconComScope&) = delete;

    private:
        bool shouldUninitialize_ = false; // m_shouldUninitialize: whether COM was initialized by this object.
    };

    // handleProcessPlaceholderIcon:
    // - Provides a unified placeholder icon when the icon is not resolved or fails to load.
    // - Constructed only once and shared globally to avoid repeatedly reading the resource file for each line.
    // Input: None.
    // Returns: A constant reference to the placeholder QIcon.
    const QIcon& handleProcessPlaceholderIcon()
    {
        static const QIcon kPlaceholderIcon(QStringLiteral(":/Icon/process_main.svg"));
        return kPlaceholderIcon;
    }

    // buildHandleProcessIdentityKey:
    // - Construct a unique key for the process instance using PID + creation time.
    // - Maintain consistency with HandleDock.Icon.cpp in key format; both share the same icon cache.
    // Input parameters: processId is the process PID; processCreationTime is the process creation time.
    // Returns: The process instance key; returns an empty string if any field is 0, indicating the instance cannot be confirmed.
    QString buildHandleProcessIdentityKey(
        const std::uint32_t processId,
        const std::uint64_t processCreationTime)
    {
        if (processId == 0U || processCreationTime == 0U)
        {
            return {};
        }
        return QStringLiteral("%1|%2")
            .arg(static_cast<qulonglong>(processId))
            .arg(static_cast<qulonglong>(processCreationTime));
    }

    // handleProcessFileTimeToUint64:
    // - Fold FILETIME into a 64-bit integer for direct comparison with creation time in snapshots.
    // Input fileTimeValue: Win32 FILETIME structure.
    // Returns: corresponding 64-bit time value.
    std::uint64_t handleProcessFileTimeToUint64(const FILETIME& fileTimeValue)
    {
        ULARGE_INTEGER convertedValue{};
        convertedValue.LowPart = fileTimeValue.dwLowDateTime;
        convertedValue.HighPart = fileTimeValue.dwHighDateTime;
        return convertedValue.QuadPart;
    }

    // queryHandleProcessImagePathInWorker:
    // - Verify the process instance identity and read the image path within the worker thread.
    // - Note: Semantically consistent with the synchronous implementation in HandleDock.Icon.cpp, but moved off the UI thread.
    // - Verifies that the handle used for validation and path query is the same to avoid mismatches caused by PID reuse.
    // Input parameters: processId is the target PID; expectedCreationTime is the creation time recorded in the snapshot.
    // Returns: image path; returns empty string if identity mismatch or query fails.
    QString queryHandleProcessImagePathInWorker(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime)
    {
        if (processId == 0U || expectedCreationTime == 0U)
        {
            return {};
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(processId));
        if (kProcessHandle == nullptr)
        {
            return {};
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const bool kIdentityMatches =
            ::GetProcessTimes(
                kProcessHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime) != FALSE
            && handleProcessFileTimeToUint64(creationTime) == expectedCreationTime;
        if (!kIdentityMatches)
        {
            ::CloseHandle(kProcessHandle);
            return {};
        }

        std::vector<wchar_t> imagePathBuffer(32768, L'\0');
        DWORD imagePathLength = static_cast<DWORD>(imagePathBuffer.size());
        QString processImagePath;
        if (::QueryFullProcessImageNameW(
            kProcessHandle,
            0,
            imagePathBuffer.data(),
            &imagePathLength) != FALSE
            && imagePathLength > 0U)
        {
            processImagePath = QString::fromWCharArray(
                imagePathBuffer.data(),
                static_cast<int>(imagePathLength));
        }
        ::CloseHandle(kProcessHandle);
        return processImagePath;
    }

    // extractHandleProcessIconImage:
    // - Extract the executable's small icon via Shell within a worker thread and convert it to QImage;
    // - QImage can be passed across threads and does not involve QPixmap/QIcon/QFileIconProvider, which are restricted to the UI thread.
    // Parameter imagePath: The process image path with verified instance identity.
    // Returns: Icon bitmap; returns an empty QImage if the path is empty or extraction fails.
    QImage extractHandleProcessIconImage(const QString& imagePath)
    {
        if (imagePath.trimmed().isEmpty())
        {
            return QImage();
        }

        // shellFileInfo stores the HICON allocated by the Shell; after converting to QImage, it must be destroyed by the caller.
        SHFILEINFOW shellFileInfo{};
        const DWORD_PTR kShellQueryResult = ::SHGetFileInfoW(
            reinterpret_cast<const wchar_t*>(imagePath.utf16()),
            0,
            &shellFileInfo,
            sizeof(shellFileInfo),
            SHGFI_ICON | SHGFI_SMALLICON);
        if (kShellQueryResult == 0 || shellFileInfo.hIcon == nullptr)
        {
            return QImage();
        }

        QImage iconImage = QImage::fromHICON(shellFileInfo.hIcon);
        ::DestroyIcon(shellFileInfo.hIcon);
        return iconImage;
    }
}

HandleDock::HandleDock(QWidget* parent)
    : QWidget(parent)
{
    // Configuration is loaded before connection to avoid triggering an extra enumeration when restoring control values.
    initializeUi();
    loadFilterConfiguration();
    applyFilterGlobalSettingsToControls();
    initializeConnections();
    applyLocalHandleFilters(true);
}

void HandleDock::focusProcessId(const std::uint32_t processId, const bool triggerRefresh)
{
    focusProcessIds(QVector<quint32>{ static_cast<quint32>(processId) }, triggerRefresh);
}

void HandleDock::focusProcessIds(const QVector<quint32>& processIds, const bool triggerRefresh)
{
    if (tabWidget_ != nullptr && handleListPage_ != nullptr)
    {
        tabWidget_->setCurrentWidget(handleListPage_);
    }
    QVector<std::uint32_t> normalizedIds;
    QSet<quint32> seenPidSet;
    for (const quint32 kProcessId : processIds)
    {
        if (kProcessId != 0U && !seenPidSet.contains(kProcessId))
        {
            seenPidSet.insert(kProcessId);
            normalizedIds.push_back(kProcessId);
        }
    }

    if (normalizedIds.isEmpty())
    {
        returnToSavedFilters();
        return;
    }

    temporaryFilterRule_ = ks::handle::HandleFilterRule{};
    temporaryFilterRule_.id = QStringLiteral("temporary-") + ks::handle::createHandleFilterRuleId();
    temporaryFilterRule_.name =
        ks::i18n::sourceText(QStringLiteral("临时 PID 筛选"));
    temporaryFilterRule_.enabled = true;
    temporaryFilterRule_.processIds = normalizedIds;
    temporaryFilterActive_ = true;
    if (returnSavedFilterButton_ != nullptr)
    {
        returnSavedFilterButton_->setVisible(true);
    }
    const bool kCachedSnapshotCannotServeTemporaryRule =
        snapshotScopedToTemporarySinglePid_
        && (normalizedIds.size() != 1 || normalizedIds.front() != snapshotScopedProcessId_);
    if (triggerRefresh || kCachedSnapshotCannotServeTemporaryRule)
    {
        requestAsyncRefresh(true);
    }
    else
    {
        applyLocalHandleFilters(true);
    }
}

void HandleDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (initialRefreshDone_)
    {
        return;
    }

    initialRefreshDone_ = true;
    requestObjectTypeRefreshAsync(true);
    requestAsyncRefresh(true);
}

void HandleDock::initializeUi()
{
    setObjectName(QStringLiteral("HandleDockRoot"));
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(8, 8, 8, 8);
    rootLayout_->setSpacing(6);

    tabWidget_ = new QTabWidget(this);
    rootLayout_->addWidget(tabWidget_, 1);

    initializeHandleListTab();
    initializeObjectHeaderTab();
    initializeObjectTypeTab();
}

void HandleDock::initializeHandleListTab()
{
    handleListPage_ = new QWidget(tabWidget_);
    handleListLayout_ = new QVBoxLayout(handleListPage_);
    handleListLayout_->setContentsMargins(6, 6, 6, 6);
    handleListLayout_->setSpacing(6);

    toolbarLayout_ = new QHBoxLayout();
    toolbarLayout_->setContentsMargins(0, 0, 0, 0);
    toolbarLayout_->setSpacing(6);

    // The refresh button uses an 'icon + tooltip' pattern, adhering to the specification for short-semantic buttons to be iconified.
    refreshButton_ = new QPushButton(handleListPage_);
    refreshButton_->setIcon(QIcon(":/Icon/handle_refresh.svg"));
    refreshButton_->setIconSize(QSize(16, 16));
    refreshButton_->setFixedSize(28, 28);
    refreshButton_->setToolTip(QStringLiteral("刷新句柄列表"));
    refreshButton_->setStyleSheet(buildBlueButtonStyle(true));

    manageFilterButton_ = new QPushButton(QStringLiteral("管理规则"), handleListPage_);
    manageFilterButton_->setToolTip(QStringLiteral("新建、编辑、复制、启停和排序句柄筛选规则。"));
    manageFilterButton_->setStyleSheet(buildBlueButtonStyle(false));

    importFilterButton_ = new QPushButton(QStringLiteral("导入配置"), handleListPage_);
    importFilterButton_->setToolTip(QStringLiteral("从 JSON 文件导入句柄筛选规则。"));
    importFilterButton_->setStyleSheet(buildBlueButtonStyle(false));

    exportFilterButton_ = new QPushButton(QStringLiteral("导出配置"), handleListPage_);
    exportFilterButton_->setToolTip(QStringLiteral("将当前已保存筛选规则导出为 JSON 文件。"));
    exportFilterButton_->setStyleSheet(buildBlueButtonStyle(false));

    exportResultsButton_ = new QPushButton(QStringLiteral("导出结果"), handleListPage_);
    exportResultsButton_->setToolTip(QStringLiteral("导出全部启用规则的完整命中结果，不受树中加载数量限制。"));
    exportResultsButton_->setStyleSheet(buildBlueButtonStyle(false));

    returnSavedFilterButton_ = new QPushButton(QStringLiteral("返回已保存筛选器"), handleListPage_);
    returnSavedFilterButton_->setToolTip(QStringLiteral("退出临时 PID 筛选并恢复已保存规则。"));
    returnSavedFilterButton_->setStyleSheet(buildBlueButtonStyle(false));
    returnSavedFilterButton_->setVisible(false);

    enumModeCombo_ = new QComboBox(handleListPage_);
    enumModeCombo_->setToolTip(QStringLiteral("选择句柄枚举来源：用户态快照、DuplicateHandle 增强解析或 R0 HandleTable。"));
    enumModeCombo_->setStyleSheet(buildComboAndSpinStyle());
    enumModeCombo_->setMinimumWidth(180);
    enumModeCombo_->addItem(
        QStringLiteral("User Snapshot"),
        static_cast<int>(ks::handle::FilterEnumMode::kUserSnapshot));
    enumModeCombo_->addItem(
        QStringLiteral("DuplicateHandle"),
        static_cast<int>(ks::handle::FilterEnumMode::kDuplicateHandle));
    enumModeCombo_->addItem(
        QStringLiteral("Kernel HandleTable"),
        static_cast<int>(ks::handle::FilterEnumMode::kKernelHandleTable));

    resolveNameCheckBox_ = new QCheckBox(QStringLiteral("解析对象名"), handleListPage_);
    resolveNameCheckBox_->setChecked(true);
    resolveNameCheckBox_->setToolTip(QStringLiteral("启用后会尝试解析对象名称（更耗时）。"));
    resolveNameCheckBox_->setStyleSheet(
        QStringLiteral("QCheckBox{color:%1;font-weight:600;}").arg(ksword_theme::textPrimaryHex()));

    nameBudgetSpinBox_ = new QSpinBox(handleListPage_);
    nameBudgetSpinBox_->setRange(0, 10000);
    nameBudgetSpinBox_->setValue(1000);
    nameBudgetSpinBox_->setSingleStep(100);
    nameBudgetSpinBox_->setSuffix(QStringLiteral(" 条"));
    nameBudgetSpinBox_->setToolTip(QStringLiteral("对象名解析预算，预算越大越接近全量解析。"));
    nameBudgetSpinBox_->setStyleSheet(buildComboAndSpinStyle());

    toolbarLayout_->addWidget(refreshButton_);
    toolbarLayout_->addWidget(manageFilterButton_);
    toolbarLayout_->addWidget(importFilterButton_);
    toolbarLayout_->addWidget(exportFilterButton_);
    toolbarLayout_->addWidget(exportResultsButton_);
    toolbarLayout_->addWidget(returnSavedFilterButton_);
    toolbarLayout_->addStretch(1);
    toolbarLayout_->addWidget(new QLabel(QStringLiteral("枚举来源"), handleListPage_));
    toolbarLayout_->addWidget(enumModeCombo_);
    toolbarLayout_->addWidget(resolveNameCheckBox_);
    toolbarLayout_->addWidget(new QLabel(QStringLiteral("名称预算"), handleListPage_));
    toolbarLayout_->addWidget(nameBudgetSpinBox_);

    statusLabel_ = new QLabel(QStringLiteral("● 等待首次刷新"), handleListPage_);
    statusLabel_->setWordWrap(true);
    statusLabel_->setMinimumWidth(0);
    statusLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));

    tableWidget_ = new QTreeWidget(handleListPage_);
    initializeHandleTable();

    handleListLayout_->addLayout(toolbarLayout_);
    handleListLayout_->addWidget(statusLabel_);
    handleListLayout_->addWidget(tableWidget_, 1);

    tabWidget_->addTab(handleListPage_, QIcon(":/Icon/process_list.svg"), QStringLiteral("Handle Table"));
}

void HandleDock::initializeObjectHeaderTab()
{
    objectHeaderPage_ = new QWidget(tabWidget_);
    objectHeaderLayout_ = new QVBoxLayout(objectHeaderPage_);
    objectHeaderLayout_->setContentsMargins(6, 6, 6, 6);
    objectHeaderLayout_->setSpacing(6);

    handleDetailStatusLabel_ = new QLabel(QStringLiteral("● 请选择一个句柄查看对象头证据"), objectHeaderPage_);
    handleDetailStatusLabel_->setWordWrap(true);
    handleDetailStatusLabel_->setMinimumWidth(0);
    handleDetailStatusLabel_->setSizePolicy(
        QSizePolicy::Ignored,
        QSizePolicy::Preferred);
    handleDetailStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    handleDetailTable_ = new QTreeWidget(objectHeaderPage_);
    handleDetailTable_->setColumnCount(2);
    handleDetailTable_->setHeaderLabels(QStringList{ QStringLiteral("字段"), QStringLiteral("值") });
    handleDetailTable_->setRootIsDecorated(false);
    handleDetailTable_->setItemsExpandable(false);
    handleDetailTable_->setAlternatingRowColors(true);
    handleDetailTable_->setSelectionMode(QAbstractItemView::NoSelection);
    handleDetailTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    installReadOnlyTreeCopyMenu(handleDetailTable_);
    if (handleDetailTable_->header() != nullptr)
    {
        handleDetailTable_->header()->setStyleSheet(buildHeaderStyle());
        handleDetailTable_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        handleDetailTable_->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    }

    objectHeaderLayout_->addWidget(handleDetailStatusLabel_);
    objectHeaderLayout_->addWidget(handleDetailTable_, 1);

    tabWidget_->addTab(objectHeaderPage_, QIcon(":/Icon/process_critical.svg"), QStringLiteral("Object Header"));
    // The Object Header tab is for read-only evidence display only; it does not support close or modify actions. The tab's responsibility is documented in the tooltip, saving screen space.
    tabWidget_->setTabToolTip(
        tabWidget_->indexOf(objectHeaderPage_),
        QStringLiteral("展示选中句柄的对象头、对象类型归属、解码状态和风险标记。"));
}

void HandleDock::initializeObjectTypeTab()
{
    objectTypePage_ = new QWidget(tabWidget_);
    objectTypeLayout_ = new QVBoxLayout(objectTypePage_);
    objectTypeLayout_->setContentsMargins(6, 6, 6, 6);
    objectTypeLayout_->setSpacing(6);

    objectTypeToolLayout_ = new QHBoxLayout();
    objectTypeToolLayout_->setContentsMargins(0, 0, 0, 0);
    objectTypeToolLayout_->setSpacing(6);

    refreshObjectTypeButton_ = new QPushButton(objectTypePage_);
    refreshObjectTypeButton_->setIcon(QIcon(":/Icon/handle_refresh.svg"));
    refreshObjectTypeButton_->setIconSize(QSize(16, 16));
    refreshObjectTypeButton_->setFixedSize(28, 28);
    refreshObjectTypeButton_->setToolTip(QStringLiteral("刷新对象类型快照"));
    refreshObjectTypeButton_->setStyleSheet(buildBlueButtonStyle(true));

    objectTypeFilterEdit_ = new QLineEdit(objectTypePage_);
    objectTypeFilterEdit_->setPlaceholderText(QStringLiteral("对象类型过滤（类型名或编号）"));
    objectTypeFilterEdit_->setClearButtonEnabled(true);
    objectTypeFilterEdit_->setToolTip(QStringLiteral("输入类型名或编号，过滤对象类型表。"));
    objectTypeFilterEdit_->setStyleSheet(buildLineEditStyle());

    objectTypeStatusLabel_ = new QLabel(QStringLiteral("● 等待首次刷新"), objectTypePage_);
    objectTypeStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));

    objectTypeToolLayout_->addWidget(refreshObjectTypeButton_);
    objectTypeToolLayout_->addWidget(objectTypeFilterEdit_, 1);
    objectTypeToolLayout_->addWidget(objectTypeStatusLabel_);

    objectTypeTable_ = new QTreeWidget(objectTypePage_);
    objectTypeDetailTable_ = new QTreeWidget(objectTypePage_);
    initializeObjectTypeTable();
    installReadOnlyTreeCopyMenu(objectTypeTable_);
    installReadOnlyTreeCopyMenu(objectTypeDetailTable_);

    objectTypeLayout_->addLayout(objectTypeToolLayout_);
    objectTypeLayout_->addWidget(objectTypeTable_, 3);
    objectTypeLayout_->addWidget(objectTypeDetailTable_, 2);

    tabWidget_->addTab(objectTypePage_, QIcon(":/Icon/process_tree.svg"), QStringLiteral("Object Type"));
}

void HandleDock::initializeHandleTable()
{
    const QStringList kHeaders{
        QStringLiteral("PID"),
        QStringLiteral("进程名"),
        QStringLiteral("句柄"),
        QStringLiteral("TypeIndex/类型"),
        QStringLiteral("对象名"),
        QStringLiteral("对象地址"),
        QStringLiteral("访问掩码"),
        QStringLiteral("属性"),
        QStringLiteral("HandleCount"),
        QStringLiteral("PointerCount"),
        QStringLiteral("来源"),
        QStringLiteral("解码状态"),
        QStringLiteral("差异")
    };

    tableWidget_->setColumnCount(static_cast<int>(HandleTableColumn::kCount));
    tableWidget_->setHeaderLabels(kHeaders);
    tableWidget_->setRootIsDecorated(true);
    tableWidget_->setItemsExpandable(true);
    tableWidget_->setAlternatingRowColors(true);
    tableWidget_->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableWidget_->setSelectionMode(QAbstractItemView::SingleSelection);
    tableWidget_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // Rule summaries must maintain the configuration order; detailed sorting via sortLoadedRuleRows applies only to rule child nodes.
    tableWidget_->setSortingEnabled(false);
    tableWidget_->setContextMenuPolicy(Qt::CustomContextMenu);

    QHeaderView* headerView = tableWidget_->header();
    if (headerView != nullptr)
    {
        headerView->setStyleSheet(buildHeaderStyle());
        headerView->setSectionResizeMode(QHeaderView::Interactive);
        headerView->setStretchLastSection(false);
        headerView->setContextMenuPolicy(Qt::CustomContextMenu);
        headerView->setSectionsClickable(true);
        headerView->setSortIndicatorShown(false);
    }
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kProcessId), 80);
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kProcessName), 170);
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kHandleValue), 100);
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kTypeIndex), 180);
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kObjectName), 360);
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kObjectAddress), 130);
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kGrantedAccess), 120);
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kAttributes), 120);
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kHandleCount), 105);
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kPointerCount), 110);
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kSource), 140);
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kDecodeStatus), 140);
    tableWidget_->setColumnWidth(static_cast<int>(HandleTableColumn::kDiffStatus), 120);
}

void HandleDock::initializeObjectTypeTable()
{
    const QStringList kHeaders{
        QStringLiteral("类型编号"),
        QStringLiteral("类型名"),
        QStringLiteral("对象数"),
        QStringLiteral("句柄数"),
        QStringLiteral("访问掩码"),
        QStringLiteral("安全要求"),
        QStringLiteral("维护计数")
    };

    objectTypeTable_->setColumnCount(static_cast<int>(ObjectTypeTableColumn::kCount));
    objectTypeTable_->setHeaderLabels(kHeaders);
    objectTypeTable_->setRootIsDecorated(false);
    objectTypeTable_->setItemsExpandable(false);
    objectTypeTable_->setAlternatingRowColors(true);
    objectTypeTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    objectTypeTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    objectTypeTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    objectTypeTable_->setSortingEnabled(false);
    QHeaderView* typeHeader = objectTypeTable_->header();
    if (typeHeader != nullptr)
    {
        typeHeader->setStyleSheet(buildHeaderStyle());
        typeHeader->setSectionResizeMode(QHeaderView::ResizeToContents);
        typeHeader->setSectionResizeMode(static_cast<int>(ObjectTypeTableColumn::kTypeName), QHeaderView::Stretch);
    }

    // The object type details section uses a key-value tree for quick browsing of all fields.
    objectTypeDetailTable_->setColumnCount(2);
    objectTypeDetailTable_->setHeaderLabels(QStringList{ QStringLiteral("字段"), QStringLiteral("值") });
    objectTypeDetailTable_->setRootIsDecorated(false);
    objectTypeDetailTable_->setItemsExpandable(false);
    objectTypeDetailTable_->setAlternatingRowColors(true);
    objectTypeDetailTable_->setSelectionMode(QAbstractItemView::NoSelection);
    objectTypeDetailTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    QHeaderView* detailHeader = objectTypeDetailTable_->header();
    if (detailHeader != nullptr)
    {
        detailHeader->setStyleSheet(buildHeaderStyle());
        detailHeader->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        detailHeader->setSectionResizeMode(1, QHeaderView::Stretch);
    }
}

void HandleDock::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]()
        {
            requestAsyncRefresh(true);
        });

    connect(manageFilterButton_, &QPushButton::clicked, this, [this]()
        {
            showRuleManagerDialog();
        });

    connect(importFilterButton_, &QPushButton::clicked, this, [this]()
        {
            importFilterConfiguration();
        });

    connect(exportFilterButton_, &QPushButton::clicked, this, [this]()
        {
            exportFilterConfiguration();
        });

    connect(exportResultsButton_, &QPushButton::clicked, this, [this]()
        {
            exportRuleResults();
        });

    connect(returnSavedFilterButton_, &QPushButton::clicked, this, [this]()
        {
            returnToSavedFilters();
        });

    connect(enumModeCombo_, &QComboBox::currentTextChanged, this, [this](const QString&)
        {
            collectFilterGlobalSettingsFromControls();
            saveFilterConfiguration();
            requestAsyncRefresh(true);
        });

    connect(resolveNameCheckBox_, &QCheckBox::toggled, this, [this](const bool)
        {
            collectFilterGlobalSettingsFromControls();
            saveFilterConfiguration();
            requestAsyncRefresh(true);
        });

    connect(nameBudgetSpinBox_, &QSpinBox::valueChanged, this, [this](const int)
        {
            collectFilterGlobalSettingsFromControls();
            saveFilterConfiguration();
            requestAsyncRefresh(true);
        });

    connect(tableWidget_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPoint)
        {
            showHandleTableContextMenu(localPoint);
        });

    connect(tableWidget_, &QTreeWidget::itemExpanded, this, [this](QTreeWidgetItem* item)
        {
            if (item != nullptr &&
                item->data(0, ks::handle::kHandleTreeItemKindRole).toInt() ==
                    static_cast<int>(ks::handle::HandleTreeItemKind::kRuleSummary))
            {
                appendNextRuleResultBatch(
                    item->data(0, ks::handle::kHandleTreeRuleIdRole).toString());
            }
        });

    const auto kActivateLoadMore = [this](QTreeWidgetItem* item)
        {
            if (item != nullptr &&
                item->data(0, ks::handle::kHandleTreeItemKindRole).toInt() ==
                    static_cast<int>(ks::handle::HandleTreeItemKind::kLoadMore))
            {
                appendNextRuleResultBatch(
                    item->data(0, ks::handle::kHandleTreeRuleIdRole).toString());
            }
        };
    connect(tableWidget_, &QTreeWidget::itemClicked, this,
        [kActivateLoadMore](QTreeWidgetItem* item, int)
        {
            kActivateLoadMore(item);
        });
    connect(tableWidget_, &QTreeWidget::itemActivated, this,
        [kActivateLoadMore](QTreeWidgetItem* item, int)
        {
            kActivateLoadMore(item);
        });

    connect(tableWidget_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem*, QTreeWidgetItem*)
        {
            if (selectedHandleRow() == nullptr)
            {
                ++handleDetailRefreshTicket_;
                handleDetailRefreshInProgress_ = false;
                handleDetailRefreshPending_ = false;
                showHandleDetailPlaceholder(QStringLiteral("请选择一个句柄查看详情。"));
                return;
            }
            requestHandleDetailRefresh(false);
        });

    if (tableWidget_->header() != nullptr)
    {
        connect(tableWidget_->header(), &QHeaderView::customContextMenuRequested, this, [this](const QPoint& localPoint)
            {
                showHandleHeaderContextMenu(localPoint);
            });
        connect(tableWidget_->header(), &QHeaderView::sectionClicked, this, [this](const int column)
            {
                if (handleSortColumn_ == column)
                {
                    handleSortOrder_ = handleSortOrder_ == Qt::AscendingOrder
                        ? Qt::DescendingOrder
                        : Qt::AscendingOrder;
                }
                else
                {
                    handleSortColumn_ = column;
                    handleSortOrder_ = Qt::AscendingOrder;
                }
                tableWidget_->header()->setSortIndicatorShown(true);
                tableWidget_->header()->setSortIndicator(handleSortColumn_, handleSortOrder_);
                sortLoadedRuleRows(handleSortColumn_, handleSortOrder_);
            });
    }

    connect(refreshObjectTypeButton_, &QPushButton::clicked, this, [this]()
        {
            requestObjectTypeRefreshAsync(true);
        });

    connect(objectTypeFilterEdit_, &QLineEdit::textChanged, this, [this](const QString& filterKeyword)
        {
            rebuildObjectTypeTable(filterKeyword.trimmed());
        });

    connect(objectTypeTable_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem*, QTreeWidgetItem*)
        {
            showObjectTypeDetailByCurrentRow();
        });
}

void HandleDock::requestAsyncRefresh(const bool forceRefresh)
{
    if (refreshInProgress_)
    {
        if (forceRefresh)
        {
            refreshPending_ = true;
        }
        return;
    }

    if (typeNameMapByIndexFromObjectTab_.empty())
    {
        // Handle object name resolution depends on a stable typeIndex->typeName mapping. If handle enumeration and object type enumeration run in
        // parallel upon first entering the page, the handle table renders once with temporary types, then triggers a second heavy enumeration and table
        // render due to type mapping/object name refresh. Here, handle refresh is downgraded to a pending request, starting the unique handle enumeration
        // only after the object type snapshot completes; if the type snapshot fails, applyObjectTypeRefreshResult provides a fallback to allow execution.
        refreshPending_ = true;
        updateHandleStatusLabel(QStringLiteral("● 等待对象类型快照完成后刷新句柄列表..."), true);
        if (!objectTypeRefreshInProgress_)
        {
            requestObjectTypeRefreshAsync(false);
        }
        return;
    }

    requestAsyncRefreshWithoutTypePrecondition(forceRefresh);
}

void HandleDock::requestAsyncRefreshWithoutTypePrecondition(const bool forceRefresh)
{
    if (refreshInProgress_)
    {
        if (forceRefresh)
        {
            refreshPending_ = true;
        }
        return;
    }

    const HandleRefreshOptions kOptions = collectHandleRefreshOptions();
    const std::uint64_t kCurrentTicket = ++refreshTicket_;
    refreshInProgress_ = true;
    updateHandleStatusLabel(QStringLiteral("● 正在刷新句柄列表..."), true);

    if (refreshProgressPid_ <= 0)
    {
        refreshProgressPid_ = kPro.addReusable(this, "句柄枚举", "准备读取系统句柄快照");
    }
    kPro.set(refreshProgressPid_, "后台枚举系统句柄", 0, 20.0f);

    KLogEvent refreshEvent;
    info << refreshEvent
        << "[HandleDock] requestAsyncRefresh: ticket="
        << kCurrentTicket
        << ", pidFilter="
        << (kOptions.hasPidFilter ? std::to_string(kOptions.pidFilter) : std::string("all"))
        << ", keyword="
        << kOptions.keywordText.toStdString()
        << ", typeFilter="
        << kOptions.typeFilterText.toStdString()
        << ", onlyNamed="
        << (kOptions.onlyNamed ? "true" : "false")
        << ", resolveName="
        << (kOptions.resolveObjectName ? "true" : "false")
        << ", nameBudget="
        << kOptions.nameResolveBudget
        << ", enumMode="
        << static_cast<int>(kOptions.enumMode)
        << ", diffFilter="
        << static_cast<int>(kOptions.diffFilter)
        << ", objectTypeMapSize="
        << kOptions.typeNameMapFromObjectTab.size()
        << eol;

    QPointer<HandleDock> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, kCurrentTicket, kOptions]()
        {
            const HandleRefreshResult kRefreshResult = buildHandleRefreshResult(kOptions);
            if (guardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kCurrentTicket, kRefreshResult]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->applyHandleRefreshResult(kCurrentTicket, kRefreshResult);
                },
                Qt::QueuedConnection);
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void HandleDock::requestObjectTypeRefreshAsync(const bool forceRefresh)
{
    if (objectTypeRefreshInProgress_)
    {
        if (forceRefresh)
        {
            objectTypeRefreshPending_ = true;
        }
        return;
    }

    const std::uint64_t kCurrentTicket = ++objectTypeRefreshTicket_;
    objectTypeRefreshInProgress_ = true;
    updateObjectTypeStatusLabel(QStringLiteral("● 正在刷新对象类型..."), true);

    if (objectTypeRefreshProgressPid_ <= 0)
    {
        objectTypeRefreshProgressPid_ = kPro.addReusable(this, "对象类型", "准备读取对象类型快照");
    }
    kPro.set(objectTypeRefreshProgressPid_, "后台采集对象类型", 0, 20.0f);

    QPointer<HandleDock> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, kCurrentTicket]()
        {
            const ObjectTypeRefreshResult kRefreshResult = buildObjectTypeRefreshResult();
            if (guardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kCurrentTicket, kRefreshResult]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->applyObjectTypeRefreshResult(kCurrentTicket, kRefreshResult);
                },
                Qt::QueuedConnection);
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void HandleDock::applyHandleRefreshResult(
    const std::uint64_t refreshTicket,
    const HandleRefreshResult& refreshResult)
{
    if (refreshTicket < refreshTicket_)
    {
        return;
    }

    const bool kScopedResultStillMatchesTemporaryRule =
        temporaryFilterActive_
        && temporaryFilterRule_.processIds.size() == 1
        && temporaryFilterRule_.processIds.front() == refreshResult.scopedProcessId;
    if (refreshResult.snapshotScopedToPid && !kScopedResultStillMatchesTemporaryRule)
    {
        // While a temporary PID refresh is in progress, the user may have already returned persistent rules, imported a configuration, or switched to another PID.
        // This result cannot be used as a complete snapshot; discard it directly and re-collect based on the current state.
        refreshInProgress_ = false;
        refreshPending_ = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestAsyncRefresh(true);
            }, Qt::QueuedConnection);
        return;
    }

    if (ks::ui::isItemViewUiCommitBlockedByContextMenu({ tableWidget_ }))
    {
        const auto kRefreshSnapshot = std::make_shared<HandleRefreshResult>(refreshResult);
        const QPointer<HandleDock> kSafeThis(this);
        if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("handle-dock-main-snapshot"),
            { tableWidget_ },
            [kSafeThis, refreshTicket, kRefreshSnapshot]()
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyHandleRefreshResult(refreshTicket, *kRefreshSnapshot);
                }
            }))
        {
            return;
        }
    }

    allRows_ = refreshResult.rows;
    snapshotScopedToTemporarySinglePid_ = refreshResult.snapshotScopedToPid;
    snapshotScopedProcessId_ = refreshResult.scopedProcessId;
    lastEnumeratedHandleCount_ = refreshResult.totalHandleCount;
    lastResolvedNameCount_ = refreshResult.resolvedNameCount;
    lastObjectTypeMappedCount_ = refreshResult.objectTypeMappedCount;
    lastKernelHandleCount_ = refreshResult.kernelHandleCount;
    lastRefreshElapsedMs_ = refreshResult.elapsedMs;
    lastRefreshDiagnosticText_ = refreshResult.diagnosticText;
    typeNameCacheByIndex_ = refreshResult.updatedTypeNameCacheByIndex;
    const bool kCanRenderAfterTypeMapping = !typeNameMapByIndexFromObjectTab_.empty();
    const bool kCanRenderWithoutTypeMapping =
        !kCanRenderAfterTypeMapping && !objectTypeRefreshInProgress_;
    if (kCanRenderAfterTypeMapping)
    {
        // When the object type mapping is available, first translate the typeIndex to a stable type name before triggering table rendering.
        // This allows the first refresh to complete object name resolution in the background and then present the final row data in one go.
        for (HandleRow& row : allRows_)
        {
            const auto kTypeIt = typeNameMapByIndexFromObjectTab_.find(row.typeIndex);
            if (kTypeIt != typeNameMapByIndexFromObjectTab_.end() && !kTypeIt->second.empty())
            {
                row.typeName = QString::fromStdString(kTypeIt->second);
            }
        }
    }
    refreshTypeFilterItemsFromAllRows();
    if (kCanRenderAfterTypeMapping || kCanRenderWithoutTypeMapping)
    {
        // Normal path: render once after object type mapping is ready.
        // Fallback path: when the object type snapshot has ended but returns an empty map, do not wait for a second round; render once directly.
        handleRenderDeferredUntilTypeMap_ = false;
        applyLocalHandleFilters(true);
    }
    else
    {
        // Reserved only for legacy/exceptional concurrent paths: handle enumeration is complete, but the object type snapshot
        // is still in flight. Only update the m_rows cache without rebuilding the QTreeWidget to avoid double UI rendering.
        handleRenderDeferredUntilTypeMap_ = true;
        applyLocalHandleFilters(false);
    }

    QString statusText = QStringLiteral(
        "● 完成 %1 ms | 总:%2 | 显示:%3 | 名称:%4 | 类型:%5 | R0:%6")
        .arg(refreshResult.elapsedMs)
        .arg(refreshResult.totalHandleCount)
        .arg(totalRuleMatchCount_)
        .arg(refreshResult.resolvedNameCount)
        .arg(refreshResult.objectTypeMappedCount)
        .arg(refreshResult.kernelHandleCount);
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(" | 有诊断");
    }
    updateHandleStatusLabel(statusText, false);
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setToolTip(QStringLiteral(
            "总句柄:%1\n"
            "当前显示:%2\n"
            "基础信息已读取:%3\n"
            "名称已解析:%4\n"
            "补充解析名称:%5\n"
            "类型已识别:%6\n"
            "内核记录:%7\n"
            "仅用户态发现:%8\n"
            "仅内核发现:%9\n"
            "双来源确认:%10\n"
            "诊断:%11")
            .arg(refreshResult.totalHandleCount)
            .arg(totalRuleMatchCount_)
            .arg(refreshResult.basicInfoResolvedCount)
            .arg(refreshResult.resolvedNameCount)
            .arg(refreshResult.fallbackNameCount)
            .arg(refreshResult.objectTypeMappedCount)
            .arg(refreshResult.kernelHandleCount)
            .arg(refreshResult.userOnlyCount)
            .arg(refreshResult.kernelOnlyCount)
            .arg(refreshResult.bothCount)
            .arg(refreshResult.diagnosticText.trimmed().isEmpty()
                ? QStringLiteral("无")
                : refreshResult.diagnosticText));
    }
    updateHandleSummaryStatus();

    refreshInProgress_ = false;
    kPro.set(refreshProgressPid_, "句柄刷新完成", 0, 100.0f);

    KLogEvent refreshDoneEvent;
    info << refreshDoneEvent
        << "[HandleDock] applyHandleRefreshResult: ticket="
        << refreshTicket
        << ", total="
        << refreshResult.totalHandleCount
        << ", visible="
        << refreshResult.visibleHandleCount
        << ", mapped="
        << refreshResult.objectTypeMappedCount
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << ", diagnostic="
        << refreshResult.diagnosticText.toStdString()
        << eol;

    if (refreshPending_)
    {
        refreshPending_ = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestAsyncRefresh(true);
            }, Qt::QueuedConnection);
    }
}

void HandleDock::applyObjectTypeRefreshResult(
    const std::uint64_t refreshTicket,
    const ObjectTypeRefreshResult& refreshResult)
{
    if (refreshTicket < objectTypeRefreshTicket_)
    {
        return;
    }

    const QList<QAbstractItemView*> kAffectedViews{
        objectTypeTable_,
        objectTypeDetailTable_,
        tableWidget_
    };
    if (ks::ui::isItemViewUiCommitBlockedByContextMenu(kAffectedViews))
    {
        const auto kRefreshSnapshot = std::make_shared<ObjectTypeRefreshResult>(refreshResult);
        const QPointer<HandleDock> kSafeThis(this);
        if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("handle-dock-object-type-snapshot"),
            kAffectedViews,
            [kSafeThis, refreshTicket, kRefreshSnapshot]()
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyObjectTypeRefreshResult(refreshTicket, *kRefreshSnapshot);
                }
            }))
        {
            return;
        }
    }

    objectTypeRows_ = refreshResult.rows;
    typeNameMapByIndexFromObjectTab_ = refreshResult.typeNameMapByIndex;
    rebuildObjectTypeTable(objectTypeFilterEdit_->text().trimmed());

    QString statusText = QStringLiteral("● 刷新完成 %1 ms | 类型数:%2")
        .arg(refreshResult.elapsedMs)
        .arg(refreshResult.rows.size());
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(" | 存在诊断；详情已写入日志。");
        KLogEvent diagnosticEvent;
        warn << diagnosticEvent
            << "[HandleDock] object type refresh completed with diagnostics, rowCount="
            << refreshResult.rows.size()
            << ", detail=" << refreshResult.diagnosticText.toStdString()
            << eol;
    }
    updateObjectTypeStatusLabel(statusText, false);

    objectTypeRefreshInProgress_ = false;
    kPro.set(objectTypeRefreshProgressPid_, "对象类型刷新完成", 0, 100.0f);

    const bool kHasQueuedHandleRefresh = refreshPending_;
    if (!kHasQueuedHandleRefresh)
    {
        // Only synchronize the object type mapping to the existing table cache if there are no pending handle refreshes.
        // If a handle refresh is already queued, the subsequent round will generate the final snapshot and render once, preventing the old cache from rendering first.
        syncHandleTypeNamesFromObjectTypeMap();
    }

    if (kHasQueuedHandleRefresh)
    {
        // Object type refresh is a prerequisite for handle refresh. Consume pending handle refresh requests here to ensure only one background
        // enumeration and one handle table rendering occur subsequently, avoiding extra 'object name re-refresh' that would cause a second stall.
        refreshPending_ = false;
        if (!typeNameMapByIndexFromObjectTab_.empty())
        {
            QMetaObject::invokeMethod(this, [this]()
                {
                    requestAsyncRefresh(true);
                }, Qt::QueuedConnection);
        }
        else
        {
            KLogEvent typeMapFallbackEvent;
            warn << typeMapFallbackEvent
                << "[HandleDock] applyObjectTypeRefreshResult: object type map is empty, running one fallback handle refresh without type precondition."
                << eol;
            QMetaObject::invokeMethod(this, [this]()
                {
                    requestAsyncRefreshWithoutTypePrecondition(true);
                }, Qt::QueuedConnection);
        }
    }

    if (objectTypeRefreshPending_)
    {
        objectTypeRefreshPending_ = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestObjectTypeRefreshAsync(true);
            }, Qt::QueuedConnection);
    }
}

void HandleDock::rebuildHandleTable()
{
    rebuildRuleSummaryTree();
    return;

    tableWidget_->clear();
    // clear() has already destroyed all old table items: immediately increment the generation to invalidate in-flight icon injections and rebuild the 'row index -> table item' mapping.
    ++processIconResolveGeneration_;
    const std::uint64_t kIconResolveGeneration = processIconResolveGeneration_;
    handleTableItemsByRowIndex_.assign(rows_.size(), nullptr);

    // The row index from the previous scan is now invalid; set the cancellation flag to exit the thread pool ASAP, preventing long tasks from piling up during continuous filtering.
    if (processIconResolveCancelFlag_ != nullptr)
    {
        processIconResolveCancelFlag_->store(true);
    }
    processIconResolveCancelFlag_ = std::make_shared<std::atomic_bool>(false);
    const std::shared_ptr<std::atomic_bool> kIconResolveCancelFlag = processIconResolveCancelFlag_;

    const std::size_t kTotalRowCount = rows_.size();
    HandleRenderSplashScope renderSplashScope(kTotalRowCount);

    // Disable sorting during table construction: enabling sorting causes an insertion sort for every addTopLevelItem call, degrading to repeated
    // full-table moves for tens of thousands of rows. Re-enable sorting after construction, allowing Qt to re-sort once based on the current column.
    const bool kSortingEnabledBeforeRebuild = tableWidget_->isSortingEnabled();
    tableWidget_->setSortingEnabled(false);

    // Icon requests are collected in-place during table construction and submitted to the thread pool all at once after construction completes.
    // The UI thread performs only QHash lookups in this round, avoiding per-row OpenProcess + QueryFullProcessImageNameW + Shell icon retrieval.
    QVector<HandleProcessIconRequest> pendingIconRequests;
    QHash<QString, QVector<int>> pendingIconRowIndicesByIdentity;

    for (std::size_t rowIndex = 0; rowIndex < rows_.size(); ++rowIndex)
    {
        const HandleRow& row = rows_[rowIndex];
        // This table is the main focus of this page, containing tens of thousands of rows, yet the entire table is sorted by the DisplayRole string:
        // PIDs are sorted as 1/10/100/11/2, and handle values/object addresses are also disordered because hexadecimal values lack leading zeros.
        // Handle counts/pointer counts are even more chaotic when compared as strings (e.g., 9 > 10). Switch to rows with NumericSortRole: assign
        // actual numeric values to the numeric columns while keeping the display text unchanged (hexadecimal remains hexadecimal).
        auto* item = new ks::ui::NumericTreeItem();
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::kProcessId),
            QString::number(row.processId),
            static_cast<qulonglong>(row.processId));
        item->setText(static_cast<int>(HandleTableColumn::kProcessName), row.processName);
        // Process icons are retrieved from memory cache only: on miss, display a placeholder and register an async request; the real icon is filled in after background parsing completes.
        const QString kProcessIdentityKey =
            buildHandleProcessIdentityKey(row.processId, row.processCreationTime);
        const auto kCachedIconIt = processIconCacheByIdentity_.constFind(kProcessIdentityKey);
        if (kCachedIconIt != processIconCacheByIdentity_.constEnd())
        {
            item->setIcon(
                static_cast<int>(HandleTableColumn::kProcessName),
                kCachedIconIt.value());
        }
        else
        {
            item->setIcon(
                static_cast<int>(HandleTableColumn::kProcessName),
                handleProcessPlaceholderIcon());
            if (!kProcessIdentityKey.isEmpty())
            {
                // A single process instance may occupy hundreds or thousands of rows; aggregate row indices by instance key here to parse icons only once in the background.
                QVector<int>& identityRowIndexList = pendingIconRowIndicesByIdentity[kProcessIdentityKey];
                if (identityRowIndexList.isEmpty())
                {
                    pendingIconRequests.push_back(
                        HandleProcessIconRequest{
                            kProcessIdentityKey,
                            row.processId,
                            row.processCreationTime });
                }
                identityRowIndexList.push_back(static_cast<int>(rowIndex));
            }
        }
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::kHandleValue),
            formatHex(row.handleValue, 0),
            static_cast<qulonglong>(row.handleValue));
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::kTypeIndex),
            formatTypeIndexDisplayText(row.typeIndex, row.typeName),
            static_cast<qulonglong>(row.typeIndex));
        const QString kObjectNameDisplayText = formatObjectNameDisplayText(row);
        item->setText(static_cast<int>(HandleTableColumn::kObjectName), kObjectNameDisplayText);
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::kObjectAddress),
            formatHex(row.objectAddress, 0),
            static_cast<qulonglong>(row.objectAddress));
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::kGrantedAccess),
            formatHex(row.grantedAccess, 8),
            static_cast<qulonglong>(row.grantedAccess));
        item->setText(static_cast<int>(HandleTableColumn::kAttributes), formatHandleAttributes(row.attributes));
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::kHandleCount),
            formatOptionalObjectCount(row.handleCount, row.basicInfoAvailable),
            static_cast<qulonglong>(row.basicInfoAvailable ? row.handleCount : 0));
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::kPointerCount),
            formatOptionalObjectCount(row.pointerCount, row.basicInfoAvailable),
            static_cast<qulonglong>(row.basicInfoAvailable ? row.pointerCount : 0));
        item->setText(static_cast<int>(HandleTableColumn::kSource), formatHandleSourceText(row.sourceMode));
        item->setText(static_cast<int>(HandleTableColumn::kDecodeStatus), formatHandleDecodeStatusText(row.decodeStatus));
        item->setText(static_cast<int>(HandleTableColumn::kDiffStatus), formatHandleDiffStatusText(row.diffStatus));
        item->setData(static_cast<int>(HandleTableColumn::kProcessId), Qt::UserRole, static_cast<qulonglong>(rowIndex));
        item->setToolTip(
            static_cast<int>(HandleTableColumn::kGrantedAccess),
            decodeGrantedAccessText(row.typeName, row.grantedAccess));
        item->setToolTip(
            static_cast<int>(HandleTableColumn::kSource),
            QStringLiteral("Object 地址仅用于展示和差异检测，不可作为后续操作凭据。"));
        item->setToolTip(
            static_cast<int>(HandleTableColumn::kDecodeStatus),
            QStringLiteral("EP.ObjectTable=0x%1, HtContention=0x%2, ObDecodeShift=%3, ObAttributesShift=%4, OtName=0x%5, OtIndex=0x%6")
            .arg(static_cast<qulonglong>(row.epObjectTableOffset), 0, 16)
            .arg(static_cast<qulonglong>(row.htHandleContentionEventOffset), 0, 16)
            .arg(row.obDecodeShift)
            .arg(row.obAttributesShift)
            .arg(static_cast<qulonglong>(row.otNameOffset), 0, 16)
            .arg(static_cast<qulonglong>(row.otIndexOffset), 0, 16));

        // Uniformly weaken the display of the placeholder state and include a tooltip explaining the source to prevent users from mistaking 'no name' and 'not found' as the same state.
        if (!row.objectNameAvailable || row.objectName.trimmed().isEmpty())
        {
            const QColor kSecondaryTextColor = ksword_theme::textSecondaryColor();
            item->setForeground(
                static_cast<int>(HandleTableColumn::kObjectName),
                kSecondaryTextColor);
        }
        if (!row.basicInfoAvailable)
        {
            const QColor kSecondaryTextColor = ksword_theme::textSecondaryColor();
            item->setForeground(static_cast<int>(HandleTableColumn::kHandleCount), kSecondaryTextColor);
            item->setForeground(static_cast<int>(HandleTableColumn::kPointerCount), kSecondaryTextColor);
            item->setToolTip(static_cast<int>(HandleTableColumn::kHandleCount), QStringLiteral("ObjectBasicInformation 未查到。"));
            item->setToolTip(static_cast<int>(HandleTableColumn::kPointerCount), QStringLiteral("ObjectBasicInformation 未查到。"));
        }
        if (row.objectNameAvailable)
        {
            if (row.objectName.trimmed().isEmpty())
            {
                item->setToolTip(static_cast<int>(HandleTableColumn::kObjectName), QStringLiteral("对象已查询，但该对象没有名称。"));
            }
        }
        else if (row.objectNameFailed)
        {
            item->setToolTip(static_cast<int>(HandleTableColumn::kObjectName), QStringLiteral("对象名查询失败。"));
        }
        else
        {
            item->setToolTip(static_cast<int>(HandleTableColumn::kObjectName), QStringLiteral("对象名未查询，可能受预算、类型白名单或开关限制。"));
        }
        tableWidget_->addTopLevelItem(item);
        handleTableItemsByRowIndex_[rowIndex] = item;

        if (kTotalRowCount > 0
            && (((rowIndex + 1) % kHandleRenderProgressStep) == 0 || (rowIndex + 1) == kTotalRowCount))
        {
            renderSplashScope.update(rowIndex + 1);
        }
    }

    if (kSortingEnabledBeforeRebuild)
    {
        tableWidget_->setSortingEnabled(true);
    }

    renderSplashScope.finish();

    if (pendingIconRequests.isEmpty())
    {
        return;
    }

    // Process icon resolution (OpenProcess + GetProcessTimes + QueryFullProcessImageNameW + Shell icon retrieval) is moved entirely to a thread
    // pool: the background only produces QImage value types, while QPixmap/QIcon construction and table refresh remain on the UI thread.
    const QPointer<HandleDock> kGuardedSelf(this);
    auto* iconResolveTask = QRunnable::create(
        [kGuardedSelf,
        kIconResolveGeneration,
        kIconResolveCancelFlag,
        pendingIconRequests,
        pendingIconRowIndicesByIdentity]()
        {
            // The Shell icon processor requires a COM environment; the worker thread initializes it independently and releases it upon task completion.
            const HandleProcessIconComScope kIconWorkerComScope;

            QVector<HandleProcessIconResult> batchedIconResults;
            batchedIconResults.reserve(kHandleProcessIconBatchSize);

            // postBatchedIconResults: Returns a batch of accumulated icon results to the UI thread and clears the batch buffer.
            // Input: none (uses outer batch buffer and row index mapping by reference).
            // Returns: Nothing.
            const auto kPostBatchedIconResults =
                [&kGuardedSelf, kIconResolveGeneration, &pendingIconRowIndicesByIdentity, &batchedIconResults]()
                {
                    if (batchedIconResults.isEmpty())
                    {
                        return;
                    }

                    QCoreApplication* const kAppInstance = QCoreApplication::instance();
                    if (kAppInstance == nullptr)
                    {
                        batchedIconResults.clear();
                        return;
                    }

                    QMetaObject::invokeMethod(
                        kAppInstance,
                        [kGuardedSelf,
                        kIconResolveGeneration,
                        rowIndicesByIdentity = pendingIconRowIndicesByIdentity,
                        iconResults = batchedIconResults]()
                        {
                            if (kGuardedSelf == nullptr || kGuardedSelf->tableWidget_ == nullptr)
                            {
                                return;
                            }
                            // Table items remain valid only if the generation matches, indicating the table was not rebuilt and registered row indices and item pointers are still valid.
                            // Still write to the icon cache when generation numbers are inconsistent (the process instance-to-icon mapping is
                            // independent of generation), but do not backfill table entries; the next table build can directly hit the cache.
                            const bool kTableItemsStillValid =
                                kGuardedSelf->processIconResolveGeneration_ == kIconResolveGeneration;

                            bool anyIconApplied = false;
                            {
                                // Calling setIcon for each row triggers one dataChanged signal and one view row positioning operation; with tens of thousands of rows, this degrades to a full table scan.
                                // Block model signals during the batch write-back, then refresh the viewport once after completion.
                                const QSignalBlocker kTableModelBlocker(kGuardedSelf->tableWidget_->model());
                                for (const HandleProcessIconResult& iconResult : iconResults)
                                {
                                    // QPixmap can only be constructed on the UI thread; even if resolution fails, write the placeholder icon to the cache to avoid reissuing system calls in the next round.
                                    const QIcon kResolvedProcessIcon = iconResult.iconImage.isNull()
                                        ? handleProcessPlaceholderIcon()
                                        : QIcon(QPixmap::fromImage(iconResult.iconImage));
                                    if (kGuardedSelf->processIconCacheByIdentity_.size() >= kHandleProcessIconCacheLimit)
                                    {
                                        kGuardedSelf->processIconCacheByIdentity_.erase(
                                            kGuardedSelf->processIconCacheByIdentity_.begin());
                                    }
                                    kGuardedSelf->processIconCacheByIdentity_.insert(
                                        iconResult.identityKey,
                                        kResolvedProcessIcon);
                                    if (!kTableItemsStillValid)
                                    {
                                        continue;
                                    }

                                    const auto kIdentityRowIndexIt =
                                        rowIndicesByIdentity.constFind(iconResult.identityKey);
                                    if (kIdentityRowIndexIt == rowIndicesByIdentity.constEnd())
                                    {
                                        continue;
                                    }
                                    for (const int kTargetRowIndex : kIdentityRowIndexIt.value())
                                    {
                                        if (kTargetRowIndex < 0 ||
                                            static_cast<std::size_t>(kTargetRowIndex) >=
                                            kGuardedSelf->handleTableItemsByRowIndex_.size())
                                        {
                                            continue;
                                        }
                                        QTreeWidgetItem* const kTargetItem =
                                            kGuardedSelf->handleTableItemsByRowIndex_[
                                                static_cast<std::size_t>(kTargetRowIndex)];
                                        if (kTargetItem == nullptr)
                                        {
                                            continue;
                                        }
                                        kTargetItem->setIcon(
                                            static_cast<int>(HandleTableColumn::kProcessName),
                                            kResolvedProcessIcon);
                                        anyIconApplied = true;
                                    }
                                }
                            }

                            if (anyIconApplied && kGuardedSelf->tableWidget_->viewport() != nullptr)
                            {
                                kGuardedSelf->tableWidget_->viewport()->update();
                            }
                        },
                        Qt::QueuedConnection);
                    batchedIconResults.clear();
                };

            for (const HandleProcessIconRequest& iconRequest : pendingIconRequests)
            {
                if (kGuardedSelf == nullptr ||
                    kIconResolveCancelFlag->load(std::memory_order_relaxed))
                {
                    // Page destroyed or table rebuilt: remaining requests are handed to the next scan; this task immediately yields the thread pool thread.
                    break;
                }

                const QString kProcessImagePath = queryHandleProcessImagePathInWorker(
                    iconRequest.processId,
                    iconRequest.processCreationTime);
                batchedIconResults.push_back(
                    HandleProcessIconResult{
                        iconRequest.identityKey,
                        extractHandleProcessIconImage(kProcessImagePath) });
                if (batchedIconResults.size() >= kHandleProcessIconBatchSize)
                {
                    kPostBatchedIconResults();
                }
            }
            kPostBatchedIconResults();
        });
    iconResolveTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(iconResolveTask);
}

QTreeWidgetItem* HandleDock::createHandleTreeRow(const std::size_t sourceRowIndex)
{
    if (sourceRowIndex >= allRows_.size())
    {
        return nullptr;
    }

    const HandleRow& row = allRows_[sourceRowIndex];
    auto* item = new ks::ui::NumericTreeItem();
    item->setData(0, ks::handle::kHandleTreeItemKindRole,
        static_cast<int>(ks::handle::HandleTreeItemKind::kHandleRow));
    item->setData(0, ks::handle::kHandleTreeSourceRowIndexRole,
        static_cast<qulonglong>(sourceRowIndex));
    item->setNumericCell(
        static_cast<int>(HandleTableColumn::kProcessId),
        QString::number(row.processId),
        static_cast<qulonglong>(row.processId));
    item->setText(static_cast<int>(HandleTableColumn::kProcessName), row.processName);

    const QString kProcessIdentityKey =
        buildHandleProcessIdentityKey(row.processId, row.processCreationTime);
    const auto kCachedIconIt = processIconCacheByIdentity_.constFind(kProcessIdentityKey);
    item->setIcon(
        static_cast<int>(HandleTableColumn::kProcessName),
        kCachedIconIt == processIconCacheByIdentity_.constEnd()
            ? handleProcessPlaceholderIcon()
            : kCachedIconIt.value());

    item->setNumericCell(
        static_cast<int>(HandleTableColumn::kHandleValue),
        formatHex(row.handleValue, 0),
        static_cast<qulonglong>(row.handleValue));
    item->setNumericCell(
        static_cast<int>(HandleTableColumn::kTypeIndex),
        formatTypeIndexDisplayText(row.typeIndex, row.typeName),
        static_cast<qulonglong>(row.typeIndex));
    item->setText(
        static_cast<int>(HandleTableColumn::kObjectName),
        formatObjectNameDisplayText(row));
    item->setNumericCell(
        static_cast<int>(HandleTableColumn::kObjectAddress),
        formatHex(row.objectAddress, 0),
        static_cast<qulonglong>(row.objectAddress));
    item->setNumericCell(
        static_cast<int>(HandleTableColumn::kGrantedAccess),
        formatHex(row.grantedAccess, 8),
        static_cast<qulonglong>(row.grantedAccess));
    item->setText(
        static_cast<int>(HandleTableColumn::kAttributes),
        formatHandleAttributes(row.attributes));
    item->setNumericCell(
        static_cast<int>(HandleTableColumn::kHandleCount),
        formatOptionalObjectCount(row.handleCount, row.basicInfoAvailable),
        static_cast<qulonglong>(row.basicInfoAvailable ? row.handleCount : 0));
    item->setNumericCell(
        static_cast<int>(HandleTableColumn::kPointerCount),
        formatOptionalObjectCount(row.pointerCount, row.basicInfoAvailable),
        static_cast<qulonglong>(row.basicInfoAvailable ? row.pointerCount : 0));
    item->setText(static_cast<int>(HandleTableColumn::kSource), formatHandleSourceText(row.sourceMode));
    item->setText(static_cast<int>(HandleTableColumn::kDecodeStatus), formatHandleDecodeStatusText(row.decodeStatus));
    item->setText(static_cast<int>(HandleTableColumn::kDiffStatus), formatHandleDiffStatusText(row.diffStatus));
    item->setToolTip(
        static_cast<int>(HandleTableColumn::kGrantedAccess),
        decodeGrantedAccessText(row.typeName, row.grantedAccess));
    item->setToolTip(
        static_cast<int>(HandleTableColumn::kSource),
        QStringLiteral("Object 地址仅用于展示和差异检测，不可作为后续操作凭据。"));
    item->setToolTip(
        static_cast<int>(HandleTableColumn::kDecodeStatus),
        QStringLiteral("EP.ObjectTable=0x%1, HtContention=0x%2, ObDecodeShift=%3, ObAttributesShift=%4, OtName=0x%5, OtIndex=0x%6")
        .arg(static_cast<qulonglong>(row.epObjectTableOffset), 0, 16)
        .arg(static_cast<qulonglong>(row.htHandleContentionEventOffset), 0, 16)
        .arg(row.obDecodeShift)
        .arg(row.obAttributesShift)
        .arg(static_cast<qulonglong>(row.otNameOffset), 0, 16)
        .arg(static_cast<qulonglong>(row.otIndexOffset), 0, 16));

    if (!row.objectNameAvailable || row.objectName.trimmed().isEmpty())
    {
        item->setForeground(
            static_cast<int>(HandleTableColumn::kObjectName),
            ksword_theme::textSecondaryColor());
    }
    if (!row.basicInfoAvailable)
    {
        item->setForeground(
            static_cast<int>(HandleTableColumn::kHandleCount),
            ksword_theme::textSecondaryColor());
        item->setForeground(
            static_cast<int>(HandleTableColumn::kPointerCount),
            ksword_theme::textSecondaryColor());
        item->setToolTip(
            static_cast<int>(HandleTableColumn::kHandleCount),
            QStringLiteral("ObjectBasicInformation 未查到。"));
        item->setToolTip(
            static_cast<int>(HandleTableColumn::kPointerCount),
            QStringLiteral("ObjectBasicInformation 未查到。"));
    }
    if (row.objectNameAvailable)
    {
        if (row.objectName.trimmed().isEmpty())
        {
            item->setToolTip(
                static_cast<int>(HandleTableColumn::kObjectName),
                QStringLiteral("对象已查询，但该对象没有名称。"));
        }
    }
    else if (row.objectNameFailed)
    {
        item->setToolTip(
            static_cast<int>(HandleTableColumn::kObjectName),
            QStringLiteral("对象名查询失败。"));
    }
    else
    {
        item->setToolTip(
            static_cast<int>(HandleTableColumn::kObjectName),
            QStringLiteral("对象名未查询，可能受预算、类型白名单或开关限制。"));
    }
    return item;
}

void HandleDock::scheduleProcessIconResolution(
    const QVector<qulonglong>& sourceRowIndices,
    const QVector<QTreeWidgetItem*>& itemList)
{
    if (sourceRowIndices.size() != itemList.size() || sourceRowIndices.isEmpty())
    {
        return;
    }

    QVector<HandleProcessIconRequest> requests;
    QHash<QString, QVector<QTreeWidgetItem*>> itemsByIdentity;
    for (qsizetype itemIndex = 0; itemIndex < sourceRowIndices.size(); ++itemIndex)
    {
        const std::size_t kSourceRowIndex =
            static_cast<std::size_t>(sourceRowIndices.at(itemIndex));
        if (kSourceRowIndex >= allRows_.size() || itemList.at(itemIndex) == nullptr)
        {
            continue;
        }
        const HandleRow& row = allRows_[kSourceRowIndex];
        const QString kIdentityKey =
            buildHandleProcessIdentityKey(row.processId, row.processCreationTime);
        if (kIdentityKey.isEmpty() || processIconCacheByIdentity_.contains(kIdentityKey))
        {
            continue;
        }
        QVector<QTreeWidgetItem*>& targetItems = itemsByIdentity[kIdentityKey];
        if (targetItems.isEmpty())
        {
            requests.push_back(HandleProcessIconRequest{
                kIdentityKey,
                row.processId,
                row.processCreationTime });
        }
        targetItems.push_back(itemList.at(itemIndex));
    }
    if (requests.isEmpty())
    {
        return;
    }

    const std::uint64_t kGeneration = processIconResolveGeneration_;
    const std::shared_ptr<std::atomic_bool> kCancelFlag = processIconResolveCancelFlag_;
    const QPointer<HandleDock> kGuardedSelf(this);
    auto* task = QRunnable::create(
        [kGuardedSelf, kGeneration, kCancelFlag, requests, itemsByIdentity]()
        {
            const HandleProcessIconComScope kIconWorkerComScope;
            QVector<HandleProcessIconResult> results;
            results.reserve(requests.size());
            for (const HandleProcessIconRequest& request : requests)
            {
                if (kGuardedSelf == nullptr ||
                    (kCancelFlag != nullptr && kCancelFlag->load(std::memory_order_relaxed)))
                {
                    return;
                }
                const QString kImagePath = queryHandleProcessImagePathInWorker(
                    request.processId,
                    request.processCreationTime);
                results.push_back(HandleProcessIconResult{
                    request.identityKey,
                    extractHandleProcessIconImage(kImagePath) });
            }
            QMetaObject::invokeMethod(
                QCoreApplication::instance(),
                [kGuardedSelf, kGeneration, results, itemsByIdentity]()
                {
                    if (kGuardedSelf == nullptr ||
                        kGuardedSelf->processIconResolveGeneration_ != kGeneration)
                    {
                        return;
                    }
                    for (const HandleProcessIconResult& result : results)
                    {
                        const QIcon kIcon = result.iconImage.isNull()
                            ? handleProcessPlaceholderIcon()
                            : QIcon(QPixmap::fromImage(result.iconImage));
                        if (kGuardedSelf->processIconCacheByIdentity_.size() >=
                            kHandleProcessIconCacheLimit)
                        {
                            kGuardedSelf->processIconCacheByIdentity_.erase(
                                kGuardedSelf->processIconCacheByIdentity_.begin());
                        }
                        kGuardedSelf->processIconCacheByIdentity_.insert(result.identityKey, kIcon);
                        const auto kItemIt = itemsByIdentity.constFind(result.identityKey);
                        if (kItemIt == itemsByIdentity.constEnd())
                        {
                            continue;
                        }
                        for (QTreeWidgetItem* item : kItemIt.value())
                        {
                            if (item != nullptr && item->treeWidget() == kGuardedSelf->tableWidget_)
                            {
                                item->setIcon(
                                    static_cast<int>(HandleTableColumn::kProcessName),
                                    kIcon);
                            }
                        }
                    }
                },
                Qt::QueuedConnection);
        });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}


void HandleDock::rebuildObjectTypeTable(const QString& filterKeyword)
{
    objectTypeTable_->clear();
    std::size_t visibleCount = 0;
    for (std::size_t sourceIndex = 0; sourceIndex < objectTypeRows_.size(); ++sourceIndex)
    {
        const HandleObjectTypeEntry& row = objectTypeRows_[sourceIndex];
        const bool kMatched = filterKeyword.trimmed().isEmpty()
            || row.typeNameText.contains(filterKeyword, Qt::CaseInsensitive)
            || QString::number(row.typeIndex).contains(filterKeyword, Qt::CaseInsensitive);
        if (!kMatched)
        {
            continue;
        }

        auto* item = new QTreeWidgetItem();
        item->setText(static_cast<int>(ObjectTypeTableColumn::kTypeIndex), QString::number(row.typeIndex));
        item->setText(static_cast<int>(ObjectTypeTableColumn::kTypeName), row.typeNameText);
        item->setText(static_cast<int>(ObjectTypeTableColumn::kObjectCount), QString::number(row.totalObjectCount));
        item->setText(static_cast<int>(ObjectTypeTableColumn::kHandleCount), QString::number(row.totalHandleCount));
        item->setText(static_cast<int>(ObjectTypeTableColumn::kAccessMask), formatHex(row.validAccessMask, 0));
        item->setText(static_cast<int>(ObjectTypeTableColumn::kSecurityRequired), boolText(row.securityRequired));
        item->setText(static_cast<int>(ObjectTypeTableColumn::kMaintainCount), boolText(row.maintainHandleCount));
        item->setData(static_cast<int>(ObjectTypeTableColumn::kTypeIndex), Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        objectTypeTable_->addTopLevelItem(item);
        ++visibleCount;
    }

    if (objectTypeTable_->topLevelItemCount() > 0)
    {
        objectTypeTable_->setCurrentItem(objectTypeTable_->topLevelItem(0));
    }
    else
    {
        objectTypeDetailTable_->clear();
    }

    KLogEvent rebuildTypeEvent;
    dbg << rebuildTypeEvent
        << "[HandleDock] rebuildObjectTypeTable: total="
        << objectTypeRows_.size()
        << ", visible="
        << visibleCount
        << ", filter="
        << filterKeyword.toStdString()
        << eol;
}

HandleDock::HandleRefreshOptions HandleDock::collectHandleRefreshOptions() const
{
    HandleRefreshOptions options{};
    options.resolveObjectName = filterDocument_.globalSettings.resolveObjectName;
    options.nameResolveBudget = filterDocument_.globalSettings.nameResolveBudget;
    switch (filterDocument_.globalSettings.enumMode)
    {
    case ks::handle::FilterEnumMode::kUserSnapshot:
        options.enumMode = HandleEnumMode::kUserSnapshot;
        break;
    case ks::handle::FilterEnumMode::kKernelHandleTable:
        options.enumMode = HandleEnumMode::kKernelHandleTable;
        break;
    case ks::handle::FilterEnumMode::kDuplicateHandle:
    default:
        options.enumMode = HandleEnumMode::kDuplicateHandle;
        break;
    }
    if (options.enumMode == HandleEnumMode::kUserSnapshot)
    {
        options.resolveObjectName = false;
        options.nameResolveBudget = 0;
    }
    options.typeNameCacheByIndex = typeNameCacheByIndex_;
    options.typeNameMapFromObjectTab = typeNameMapByIndexFromObjectTab_;

    // Narrow the background enumeration scope only under temporary single-PID filtering. Persistent rules always share
    // the full snapshot; changes to rule content only re-match memory data and do not trigger system enumeration.
    if (temporaryFilterActive_ && temporaryFilterRule_.processIds.size() == 1)
    {
        options.hasPidFilter = true;
        options.pidFilter = temporaryFilterRule_.processIds.front();
    }

    return options;
}
