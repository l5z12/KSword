#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        FileDetailDialog::FileDetailDialog(
            const QString& filePath,
            QWidget* parent ,
            const QString& initialTabKey )
            : FileDetailDialog(QStringList{ filePath }, parent, initialTabKey)
        {
        }

        FileDetailDialog::FileDetailDialog(
            const QStringList& filePaths,
            QWidget* parent ,
            const QString& initialTabKey )
            : QDialog(parent)
            , filePaths_(filePaths)
            , filePath_(filePaths.value(0))
            , batchMode_(filePaths.size() > 1)
            , initialTabKey_(initialTabKey.trimmed().toLower())
        {
            QStringList normalizedPaths;
            QSet<QString> seenPaths;
            for (const QString& candidatePath : filePaths_)
            {
                const QString kNormalizedPath = QDir::cleanPath(
                    QDir::toNativeSeparators(candidatePath.trimmed()));
                const QString kIdentityKey = kNormalizedPath.toLower();
                if (!kNormalizedPath.isEmpty() && !seenPaths.contains(kIdentityKey))
                {
                    seenPaths.insert(kIdentityKey);
                    normalizedPaths.push_back(kNormalizedPath);
                }
            }
            filePaths_ = normalizedPaths;
            filePath_ = filePaths_.value(0);
            batchMode_ = filePaths_.size() > 1;
            hashCancelRequested_ = std::make_shared<std::atomic_bool>(false);
            usageScanCancelRequested_ = std::make_shared<std::atomic_bool>(false);
            // File and process property dialogs are independent, non-modal detail windows; do not inherit the appearance of hidden Dock child windows.
            setWindowFlag(Qt::Window, true);
            setWindowModality(Qt::NonModal);
            setAttribute(Qt::WA_DeleteOnClose, true);
            setObjectName(QStringLiteral("FileDetailDialogRoot"));
            setWindowTitle(batchMode_
                ? ks::i18n::sourceText(QStringLiteral("批量文件属性 - %1 项")).arg(filePaths_.size())
                : QStringLiteral("文件属性 - %1").arg(QFileInfo(filePath_).fileName()));
            // File property dialog content may contain extremely long paths, certificate chains, and PE fields:
            // - Maximum width is limited to 75% of the parent window's client area.
            // - Synchronize and clip the initial width to prevent the window from being pushed off-screen by long text.
            applyFileStandaloneWindowWidthLimit(
                this,
                resolveVisibleDialogParent(parent),
                QSize(1160, 760),
                0.75);

            // Adopt the same left-side navigation structure as the process properties: QTabWidget continues to host the existing
            // lazy-loading logic, hiding only the native top bar and driving navigation via translatable vertical buttons.
            QVBoxLayout* dialogLayout = new QVBoxLayout(this);
            dialogLayout->setContentsMargins(8, 8, 8, 8);
            dialogLayout->setSpacing(6);
            QHBoxLayout* rootLayout = new QHBoxLayout();
            rootLayout->setContentsMargins(0, 0, 0, 0);
            rootLayout->setSpacing(6);
            dialogLayout->addLayout(rootLayout, 1);

            tabNavigation_ = new QWidget(this);
            tabNavigation_->setObjectName(QStringLiteral("FileDetailTabNavigation"));
            tabNavigation_->setFixedWidth(210);
            tabNavigation_->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);
            QVBoxLayout* navigationLayout = new QVBoxLayout(tabNavigation_);
            navigationLayout->setContentsMargins(5, 5, 5, 5);
            navigationLayout->setSpacing(4);

            tabWidget_ = new QTabWidget(this);
            tabWidget_->tabBar()->hide();
            tabNavigationButtonGroup_ = new QButtonGroup(this);
            tabNavigationButtonGroup_->setExclusive(true);
            rootLayout->addWidget(tabNavigation_);
            rootLayout->addWidget(tabWidget_, 1);

            tabWidget_->addTab(buildGeneralTab(), QStringLiteral("常规信息"));
            tabWidget_->addTab(buildDeferredTab(QStringLiteral("metadata")), QStringLiteral("元数据编辑"));
            tabWidget_->addTab(buildDeferredTab(QStringLiteral("reparse")), QStringLiteral("重解析点 / 符号链接"));
            tabWidget_->addTab(buildDeferredTab(QStringLiteral("security")), QStringLiteral("安全与权限"));
            tabWidget_->addTab(buildHashTab(), QStringLiteral("哈希与完整性"));
            tabWidget_->addTab(buildDeferredTab(QStringLiteral("usage")), QStringLiteral("文件占用与解锁"));
            tabWidget_->addTab(buildDeferredTab(QStringLiteral("fileobject")), QStringLiteral("FileObject / Section / ControlArea"));
            tabWidget_->addTab(buildDeferredTab(QStringLiteral("storage")), QStringLiteral("Storage / MountMgr / FVE"));
            tabWidget_->addTab(buildDeferredTab(QStringLiteral("filters")), QStringLiteral("Minifilter / Instance / Volume"));
            tabWidget_->addTab(buildDeferredTab(QStringLiteral("signature")), QStringLiteral("数字签名"));
            tabWidget_->addTab(buildDeferredTab(QStringLiteral("pe")), QStringLiteral("PE信息"));
            tabWidget_->addTab(buildDeferredTab(QStringLiteral("dependencies")), QStringLiteral("依赖 DLL"));
            tabWidget_->addTab(buildDeferredTab(QStringLiteral("strings")), QStringLiteral("字符串"));
            tabWidget_->addTab(buildDeferredTab(QStringLiteral("hex")), QStringLiteral("十六进制"));
            // addTab causes Qt to re-display the tabBar; it must be hidden again after all pages are ready.
            tabWidget_->tabBar()->hide();

            const QList<QPair<QString, QString>> kDetailTabTranslations{
                {QStringLiteral("file.detail.tab.general"), QStringLiteral("常规信息")},
                {QStringLiteral("file.detail.tab.metadata"), QStringLiteral("元数据编辑")},
                {QStringLiteral("file.detail.tab.reparse"), QStringLiteral("重解析点 / 符号链接")},
                {QStringLiteral("file.detail.tab.security"), QStringLiteral("安全与权限")},
                {QStringLiteral("file.detail.tab.hash"), QStringLiteral("哈希与完整性")},
                {QStringLiteral("file.detail.tab.usage"), QStringLiteral("文件占用与解锁")},
                {QStringLiteral("file.detail.tab.fileobject"), QStringLiteral("FileObject / Section / ControlArea")},
                {QStringLiteral("file.detail.tab.storage"), QStringLiteral("Storage / MountMgr / FVE")},
                {QStringLiteral("file.detail.tab.filters"), QStringLiteral("Minifilter / Instance / Volume")},
                {QStringLiteral("file.detail.tab.signature"), QStringLiteral("数字签名")},
                {QStringLiteral("file.detail.tab.pe"), QStringLiteral("PE信息")},
                {QStringLiteral("file.detail.tab.dependencies"), QStringLiteral("依赖 DLL")},
                {QStringLiteral("file.detail.tab.strings"), QStringLiteral("字符串")},
                {QStringLiteral("file.detail.tab.hex"), QStringLiteral("十六进制")}
            };
            for (int tabIndex = 0; tabIndex < kDetailTabTranslations.size(); ++tabIndex)
            {
                const auto& translation = kDetailTabTranslations.at(tabIndex);
                ks::i18n::LanguageManager::instance().bindTab(
                    tabWidget_,
                    tabWidget_->widget(tabIndex),
                    translation.first,
                    translation.second);
            }

            const QList<QString> kNavigationIconPathList{
                QStringLiteral(":/Icon/process_details.svg"),
                QStringLiteral(":/Icon/process_copy_cell.svg"),
                QStringLiteral(":/Icon/file_nav_forward.svg"),
                QStringLiteral(":/Icon/file_owner.svg"),
                QStringLiteral(":/Icon/process_performance.svg"),
                QStringLiteral(":/Icon/process_main.svg"),
                QStringLiteral(":/Icon/process_details.svg"),
                QStringLiteral(":/Icon/disk_storage.svg"),
                QStringLiteral(":/Icon/filter_funnel.svg"),
                QStringLiteral(":/Icon/process_critical.svg"),
                QStringLiteral(":/Icon/process_list.svg"),
                QStringLiteral(":/Icon/process_copy_row.svg"),
                QStringLiteral(":/Icon/file_find.svg"),
                QStringLiteral(":/Icon/process_copy_cell.svg")
            };
            for (int tabIndex = 0; tabIndex < kDetailTabTranslations.size(); ++tabIndex)
            {
                const auto& translation = kDetailTabTranslations.at(tabIndex);
                QToolButton* navigationButton = new QToolButton(tabNavigation_);
                navigationButton->setCheckable(true);
                navigationButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
                navigationButton->setIcon(QIcon(kNavigationIconPathList.value(tabIndex)));
                navigationButton->setIconSize(QSize(18, 18));
                navigationButton->setMinimumHeight(30);
                navigationButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
                ks::i18n::LanguageManager::instance().bindText(
                    navigationButton,
                    translation.first,
                    translation.second);
                ks::i18n::LanguageManager::instance().bindToolTip(
                    navigationButton,
                    translation.first,
                    translation.second);
                tabNavigationButtonGroup_->addButton(navigationButton, tabIndex);
                tabNavigationButtons_.push_back(navigationButton);
                navigationLayout->addWidget(navigationButton);
                connect(navigationButton, &QToolButton::clicked, this, [this, tabIndex]()
                    {
                        if (tabWidget_ != nullptr)
                        {
                            tabWidget_->setCurrentIndex(tabIndex);
                        }
                    });
            }
            if (batchMode_)
            {
                const QSet<int> kBatchEnabledTabs{ 0, 1, 4 };
                for (int tabIndex = 0; tabIndex < tabNavigationButtons_.size(); ++tabIndex)
                {
                    QToolButton* const kNavigationButton = tabNavigationButtons_.at(tabIndex);
                    if (kNavigationButton == nullptr || kBatchEnabledTabs.contains(tabIndex))
                    {
                        continue;
                    }
                    kNavigationButton->setEnabled(false);
                    tabWidget_->setTabEnabled(tabIndex, false);
                    kNavigationButton->setToolTip(ks::i18n::sourceText(QStringLiteral(
                        "批量模式下此分析页不可用。请只选择一个目标后打开该页。")));
                }
                QLabel* batchHintLabel = new QLabel(
                    ks::i18n::sourceText(QStringLiteral(
                        "批量模式：常规信息显示汇总，哈希与元数据编辑支持批量处理；其余单文件分析页已禁用。")),
                    tabNavigation_);
                batchHintLabel->setWordWrap(true);
                batchHintLabel->setObjectName(QStringLiteral("FileDetailBatchHint"));
                navigationLayout->addWidget(batchHintLabel);
            }
            navigationLayout->addStretch(1);

            QFrame* saveBar = new QFrame(this);
            saveBar->setObjectName(QStringLiteral("FileMetadataSaveBar"));
            QHBoxLayout* saveLayout = new QHBoxLayout(saveBar);
            saveLayout->setContentsMargins(8, 6, 8, 6);
            backupBeforeSaveCheck_ = new QCheckBox(
                ks::i18n::sourceText(QStringLiteral("创建备份再修改")), saveBar);
            backupBeforeSaveCheck_->setChecked(true);
            pendingChangesLabel_ = new QLabel(
                ks::i18n::sourceText(QStringLiteral("● 暂无待保存修改")), saveBar);
            pendingChangesLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
            discardPendingButton_ = new QPushButton(
                ks::i18n::sourceText(QStringLiteral("放弃暂存")), saveBar);
            saveAllButton_ = new QPushButton(
                ks::i18n::sourceText(QStringLiteral("保存全部修改")), saveBar);
            saveAllButton_->setDefault(true);
            discardPendingButton_->setEnabled(false);
            saveAllButton_->setEnabled(false);
            saveLayout->addWidget(backupBeforeSaveCheck_);
            saveLayout->addWidget(pendingChangesLabel_, 1);
            saveLayout->addWidget(discardPendingButton_);
            saveLayout->addWidget(saveAllButton_);
            dialogLayout->addWidget(saveBar, 0);
            connect(discardPendingButton_, &QPushButton::clicked, this,
                [this]() { discardPendingChanges(); });
            connect(saveAllButton_, &QPushButton::clicked, this,
                [this]() { saveAllPendingChanges(); });

            connect(tabWidget_, &QTabWidget::currentChanged, this, [this](const int tabIndex)
                {
                    if (tabIndex >= 0 && tabIndex < tabNavigationButtons_.size())
                    {
                        QToolButton* const kNavigationButton = tabNavigationButtons_.at(tabIndex);
                        if (kNavigationButton != nullptr)
                        {
                            kNavigationButton->setChecked(true);
                        }
                    }
                    activateDeferredTab(tabWidget_, tabIndex);
                });
            constexpr int kUsageTabIndex = 5;
            if (initialTabKey_ == QStringLiteral("usage"))
            {
                tabWidget_->setCurrentIndex(kUsageTabIndex);
            }
            else if (!tabNavigationButtons_.isEmpty())
            {
                tabNavigationButtons_.front()->setChecked(true);
            }
            applyThemeStyle();
        }

        FileDetailDialog::~FileDetailDialog() {
            // A property window that closes and destroys itself must not leave background tasks running for full-system enumeration; both background
            // entry points share only an atomic cancellation flag, avoiding waits in the destructor thread and accessing already released controls.
            if (hashCancelRequested_ != nullptr)
            {
                hashCancelRequested_->store(true);
            }
            if (usageScanCancelRequested_ != nullptr)
            {
                usageScanCancelRequested_->store(true);
            }
        }

        void FileDetailDialog::closeEvent(QCloseEvent* event) {
            if (event == nullptr)
            {
                return;
            }
            if (transactionBusy_)
            {
                QMessageBox::information(
                    this,
                    ks::i18n::sourceText(QStringLiteral("正在保存文件元数据")),
                    ks::i18n::sourceText(QStringLiteral(
                        "保存事务仍在运行。请等待逐操作结果返回后再关闭窗口。")));
                event->ignore();
                return;
            }
            if (pendingTargetCount() > 0)
            {
                const QMessageBox::StandardButton kChoice = QMessageBox::question(
                    this,
                    ks::i18n::sourceText(QStringLiteral("放弃暂存修改")),
                    ks::i18n::sourceText(QStringLiteral(
                        "仍有尚未写入的暂存修改。关闭窗口将放弃这些修改，文件不会变化。是否关闭？")),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No);
                if (kChoice != QMessageBox::Yes)
                {
                    event->ignore();
                    return;
                }
            }
            QDialog::closeEvent(event);
        }

        void FileDetailDialog::changeEvent(QEvent* event) {
            QDialog::changeEvent(event);
            if (event == nullptr)
            {
                return;
            }
            if (event->type() == QEvent::LanguageChange)
            {
                setWindowTitle(batchMode_
                    ? ks::i18n::sourceText(QStringLiteral("批量文件属性 - %1 项")).arg(filePaths_.size())
                    : ks::i18n::displayText(QStringLiteral("文件属性 - %1"))
                        .arg(QFileInfo(filePath_).fileName()));
                refreshGeneralTab();
                return;
            }
            if (event->type() == QEvent::ApplicationPaletteChange ||
                event->type() == QEvent::PaletteChange)
            {
                applyThemeStyle();
            }
        }

        void FileDetailDialog::applyThemeStyle()
        {
            if (themeStyleApplying_)
            {
                return;
            }
            themeStyleApplying_ = true;

            const QPalette kDialogPalette = buildFileDetailDialogPalette(this);
            QPalette surfacePalette = kDialogPalette;
            surfacePalette.setColor(QPalette::Window, ksword_theme::surfaceColor());
            surfacePalette.setColor(QPalette::WindowText, ksword_theme::textPrimaryColor());
            applyFileDetailSurfacePalette(this, kDialogPalette);
            setStyleSheet(buildFileDetailDialogStyle());

            applyFileDetailSurfacePalette(tabNavigation_, surfacePalette);
            applyFileDetailSurfacePalette(tabWidget_, surfacePalette);
            if (tabWidget_ != nullptr)
            {
                for (int tabIndex = 0; tabIndex < tabWidget_->count(); ++tabIndex)
                {
                    applyFileDetailSurfacePalette(tabWidget_->widget(tabIndex), surfacePalette);
                }
            }

            themeStyleApplying_ = false;
        }
}
