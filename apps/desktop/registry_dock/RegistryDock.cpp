#include "RegistryDock.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// RegistryDock.cpp
// Notes:
// 1) Provides key tree navigation and key-value editing similar to regedit;
// 2) Support import/export of .reg files;
// 3) Support background search to avoid blocking the UI.
// ============================================================

#include "../Theme.h"

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <array>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    // Unified button style: consistent with the main interface theme.
    QString blueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    // Unified input style: path and search bars reuse the same style.
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // Header style: improves readability for information-dense lists.
    QString blueHeaderStyle()
    {
        return QStringLiteral("QHeaderView::section{color:%1;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex);
    }

    // TreeItem role constants: Store path and lazy-load status.
    constexpr int kRolePath = Qt::UserRole + 1;
    constexpr int kRoleLoaded = Qt::UserRole + 2;
    constexpr int kRolePlaceholder = Qt::UserRole + 3;

    // Root key mapping structure: supports both full name and abbreviation inputs.
    struct RootEntry
    {
        const wchar_t* fullName = nullptr;
        const wchar_t* shortName = nullptr;
        HKEY root = nullptr;
    };

    const std::array<RootEntry, 5> kRootMap{
        RootEntry{ L"HKEY_CLASSES_ROOT", L"HKCR", HKEY_CLASSES_ROOT },
        RootEntry{ L"HKEY_CURRENT_USER", L"HKCU", HKEY_CURRENT_USER },
        RootEntry{ L"HKEY_LOCAL_MACHINE", L"HKLM", HKEY_LOCAL_MACHINE },
        RootEntry{ L"HKEY_USERS", L"HKU", HKEY_USERS },
        RootEntry{ L"HKEY_CURRENT_CONFIG", L"HKCC", HKEY_CURRENT_CONFIG }
    };

    // trimDefaultValueName: maps the UI "Default Value" to the WinAPI empty name.
    QString trimDefaultValueName(const QString& valueName)
    {
        const QString kTrimmed = valueName.trimmed();
        if (kTrimmed.isEmpty() || kTrimmed == QStringLiteral("(默认)"))
        {
            return QString();
        }
        return kTrimmed;
    }

    // bytesToHex: Converts binary data to a hexadecimal string.
    QString bytesToHex(const QByteArray& bytes, int maxCount)
    {
        QStringList parts;
        const int kShowCount = std::min<int>(maxCount, bytes.size());
        for (int i = 0; i < kShowCount; ++i)
        {
            parts << QStringLiteral("%1").arg(static_cast<unsigned char>(bytes.at(i)), 2, 16, QLatin1Char('0')).toUpper();
        }
        if (bytes.size() > kShowCount)
        {
            parts << QStringLiteral("...");
        }
        return parts.join(' ');
    }
}

RegistryDock::RegistryDock(QWidget* parent)
    : QWidget(parent)
{
    {
        KLogEvent event;
        info << event << "[RegistryDock] 构造开始，准备初始化注册表模块。" << eol;
    }

    initializeUi();
    initializeConnections();
    initializeRootItems();
    navigateToPath(QStringLiteral("HKEY_CURRENT_USER"), true);

    {
        KLogEvent event;
        info << event << "[RegistryDock] 构造完成，默认定位到 HKEY_CURRENT_USER。" << eol;
    }
}

RegistryDock::~RegistryDock()
{
    KLogEvent event;
    info << event << "[RegistryDock] 析构开始，准备停止搜索线程。" << eol;

    stopSearch(true);
    if (searchFlushTimer_ != nullptr)
    {
        searchFlushTimer_->stop();
    }

    KLogEvent finishEvent;
    info << finishEvent << "[RegistryDock] 析构完成，后台资源已回收。" << eol;
}

void RegistryDock::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(4, 4, 4, 4);
    rootLayout_->setSpacing(6);

    toolBarWidget_ = new QWidget(this);
    toolBarLayout_ = new QHBoxLayout(toolBarWidget_);
    toolBarLayout_->setContentsMargins(0, 0, 0, 0);
    toolBarLayout_->setSpacing(4);

    // Navigation icons match the file manager to unify the visual semantics of 'Back/Forward'.
    backButton_ = new QPushButton(QIcon(":/Icon/file_nav_back.svg"), QString(), toolBarWidget_);
    forwardButton_ = new QPushButton(QIcon(":/Icon/file_nav_forward.svg"), QString(), toolBarWidget_);
    refreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), toolBarWidget_);
    newKeyButton_ = new QPushButton(QIcon(":/Icon/process_open_folder.svg"), QString(), toolBarWidget_);
    newValueButton_ = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), toolBarWidget_);
    renameButton_ = new QPushButton(QIcon(":/Icon/process_priority.svg"), QString(), toolBarWidget_);
    deleteButton_ = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), toolBarWidget_);
    importButton_ = new QPushButton(QIcon(":/Icon/process_resume.svg"), QString(), toolBarWidget_);
    exportButton_ = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), toolBarWidget_);
    searchButton_ = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), toolBarWidget_);
    stopSearchButton_ = new QPushButton(QIcon(":/Icon/process_pause.svg"), QString(), toolBarWidget_);

    backButton_->setToolTip(QStringLiteral("后退"));
    forwardButton_->setToolTip(QStringLiteral("前进"));
    refreshButton_->setToolTip(QStringLiteral("刷新"));
    newKeyButton_->setToolTip(QStringLiteral("新建子键"));
    newValueButton_->setToolTip(QStringLiteral("新建值"));
    renameButton_->setToolTip(QStringLiteral("重命名"));
    deleteButton_->setToolTip(QStringLiteral("删除"));
    importButton_->setToolTip(QStringLiteral("导入 .reg"));
    exportButton_->setToolTip(QStringLiteral("导出 .reg"));
    searchButton_->setToolTip(QStringLiteral("开始搜索"));
    stopSearchButton_->setToolTip(QStringLiteral("停止搜索"));

    for (QPushButton* button : { backButton_, forwardButton_, refreshButton_, newKeyButton_, newValueButton_,
            renameButton_, deleteButton_, importButton_, exportButton_, searchButton_, stopSearchButton_ })
    {
        button->setStyleSheet(blueButtonStyle());
        ksword_theme::applyCompactIconButtonMetrics(button);
    }

    pathEdit_ = new QLineEdit(toolBarWidget_);
    pathEdit_->setStyleSheet(blueInputStyle());
    pathEdit_->setPlaceholderText(QStringLiteral("输入路径后回车，例如 HKEY_LOCAL_MACHINE\\SOFTWARE"));

    searchEdit_ = new QLineEdit(toolBarWidget_);
    searchEdit_->setStyleSheet(blueInputStyle());
    searchEdit_->setPlaceholderText(QStringLiteral("搜索键/值/数据"));
    searchEdit_->setMaximumWidth(320);

    toolBarLayout_->addWidget(backButton_);
    toolBarLayout_->addWidget(forwardButton_);
    toolBarLayout_->addWidget(refreshButton_);
    toolBarLayout_->addWidget(newKeyButton_);
    toolBarLayout_->addWidget(newValueButton_);
    toolBarLayout_->addWidget(renameButton_);
    toolBarLayout_->addWidget(deleteButton_);
    toolBarLayout_->addWidget(importButton_);
    toolBarLayout_->addWidget(exportButton_);
    toolBarLayout_->addWidget(pathEdit_, 1);
    toolBarLayout_->addWidget(searchEdit_, 0);
    toolBarLayout_->addWidget(searchButton_);
    toolBarLayout_->addWidget(stopSearchButton_);

    rootLayout_->addWidget(toolBarWidget_, 0);

    mainSplitter_ = new QSplitter(Qt::Horizontal, this);
    rootLayout_->addWidget(mainSplitter_, 1);

    keyTree_ = new QTreeWidget(mainSplitter_);
    keyTree_->setColumnCount(1);
    keyTree_->setHeaderLabel(QStringLiteral("注册表键"));
    keyTree_->header()->setStyleSheet(blueHeaderStyle());
    keyTree_->setContextMenuPolicy(Qt::CustomContextMenu);
    keyTree_->setMinimumWidth(360);

    rightTabWidget_ = new QTabWidget(mainSplitter_);

    valueTable_ = new ks::ui::VisibleTableWidget(rightTabWidget_);
    valueTable_->setColumnCount(3);
    valueTable_->setHorizontalHeaderLabels(QStringList{ QStringLiteral("名称"), QStringLiteral("类型"), QStringLiteral("数据") });
    valueTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    valueTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    valueTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    valueTable_->setAlternatingRowColors(true);
    valueTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    valueTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    valueTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    valueTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    valueTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    searchResultTable_ = new ks::ui::VisibleTableWidget(rightTabWidget_);
    searchResultTable_->setColumnCount(5);
    searchResultTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("键路径"), QStringLiteral("值名"), QStringLiteral("类型"), QStringLiteral("数据预览"), QStringLiteral("命中来源")
        });
    searchResultTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    searchResultTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    searchResultTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    searchResultTable_->setAlternatingRowColors(true);
    searchResultTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    searchResultTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    searchResultTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    searchResultTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    searchResultTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    searchResultTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);

    rightTabWidget_->addTab(valueTable_, QStringLiteral("值列表"));
    rightTabWidget_->addTab(searchResultTable_, QStringLiteral("搜索结果"));
    ks::i18n::LanguageManager::instance().bindTab(
        rightTabWidget_, valueTable_, QStringLiteral("registry.tab.values"), QStringLiteral("值列表"));
    ks::i18n::LanguageManager::instance().bindTab(
        rightTabWidget_, searchResultTable_, QStringLiteral("registry.tab.search_results"), QStringLiteral("搜索结果"));

    mainSplitter_->setStretchFactor(0, 1);
    mainSplitter_->setStretchFactor(1, 2);

    statusBar_ = new QStatusBar(this);
    pathStatusLabel_ = new QLabel(QStringLiteral("路径: -"), statusBar_);
    summaryStatusLabel_ = new QLabel(QStringLiteral("状态: 就绪"), statusBar_);
    statusBar_->addWidget(pathStatusLabel_, 1);
    statusBar_->addPermanentWidget(summaryStatusLabel_, 0);
    rootLayout_->addWidget(statusBar_, 0);

    searchFlushTimer_ = new QTimer(this);
    searchFlushTimer_->setInterval(100);
    stopSearchButton_->setEnabled(false);
}

void RegistryDock::initializeConnections()
{
    connect(backButton_, &QPushButton::clicked, this, [this]() {
        if (navigationIndex_ <= 0 || navigationHistory_.empty()) return;
        navigationIndex_ -= 1;
        navigateToPath(navigationHistory_[static_cast<std::size_t>(navigationIndex_)], false);
    });

    connect(forwardButton_, &QPushButton::clicked, this, [this]() {
        if (navigationHistory_.empty()) return;
        const int kNextIndex = navigationIndex_ + 1;
        if (kNextIndex < 0 || kNextIndex >= static_cast<int>(navigationHistory_.size())) return;
        navigationIndex_ = kNextIndex;
        navigateToPath(navigationHistory_[static_cast<std::size_t>(navigationIndex_)], false);
    });

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refreshCurrentKey(true); });
    connect(pathEdit_, &QLineEdit::returnPressed, this, [this]() { navigateToPath(pathEdit_->text().trimmed(), true); });

    connect(keyTree_, &QTreeWidget::itemExpanded, this, [this](QTreeWidgetItem* item) { ensureTreeItemLoaded(item); });
    connect(keyTree_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* item, QTreeWidgetItem*) {
        if (item == nullptr || item->data(0, kRolePlaceholder).toBool()) return;
        const QString kPath = item->data(0, kRolePath).toString();
        if (!kPath.isEmpty() && kPath.compare(currentPath_, Qt::CaseInsensitive) != 0) navigateToPath(kPath, true);
    });

    connect(keyTree_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& pos) { showTreeContextMenu(pos); });
    connect(valueTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) { showValueContextMenu(pos); });
    connect(valueTable_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem*) { editSelectedValue(); });

    connect(newKeyButton_, &QPushButton::clicked, this, [this]() { createSubKey(); });
    connect(newValueButton_, &QPushButton::clicked, this, [this]() { createValue(); });
    connect(renameButton_, &QPushButton::clicked, this, [this]() { renameSelectedObject(); });
    connect(deleteButton_, &QPushButton::clicked, this, [this]() { deleteSelectedObject(); });
    connect(importButton_, &QPushButton::clicked, this, [this]() { importRegFileAsync(); });
    connect(exportButton_, &QPushButton::clicked, this, [this]() { exportCurrentKeyAsync(); });
    connect(searchButton_, &QPushButton::clicked, this, [this]() { startSearchAsync(); });
    connect(stopSearchButton_, &QPushButton::clicked, this, [this]() { stopSearch(false); });
    connect(searchEdit_, &QLineEdit::returnPressed, this, [this]() { startSearchAsync(); });
    connect(searchFlushTimer_, &QTimer::timeout, this, [this]() { flushPendingSearchRows(); });

    connect(searchResultTable_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* item) {
        if (item == nullptr) return;
        QTableWidgetItem* pathItem = searchResultTable_->item(item->row(), 0);
        if (pathItem == nullptr) return;
        navigateToPath(pathItem->text().trimmed(), true);
        rightTabWidget_->setCurrentWidget(valueTable_);
    });
}

void RegistryDock::initializeRootItems()
{
    keyTree_->clear();
    for (const RootEntry& entry : kRootMap)
    {
        QTreeWidgetItem* item = new QTreeWidgetItem(keyTree_);
        item->setText(0, QString::fromWCharArray(entry.fullName));
        item->setData(0, kRolePath, QString::fromWCharArray(entry.fullName));
        item->setData(0, kRoleLoaded, false);
        item->setData(0, kRolePlaceholder, false);

        QTreeWidgetItem* placeholder = new QTreeWidgetItem(item);
        placeholder->setText(0, QStringLiteral("..."));
        placeholder->setData(0, kRolePlaceholder, true);
    }
}
bool RegistryDock::parseRegistryPath(const QString& pathText, HKEY* rootKeyOut, QString* subPathOut)
{
    if (rootKeyOut == nullptr || subPathOut == nullptr) return false;

    QString text = pathText.trimmed();
    text.replace('/', '\\');
    while (text.contains(QStringLiteral("\\\\"))) text.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
    if (text.endsWith('\\')) text.chop(1);
    if (text.isEmpty()) return false;

    const int kSplit = text.indexOf('\\');
    const QString kRootText = kSplit < 0 ? text : text.left(kSplit);
    const QString kSubPath = kSplit < 0 ? QString() : text.mid(kSplit + 1);

    for (const RootEntry& entry : kRootMap)
    {
        const QString kFull = QString::fromWCharArray(entry.fullName);
        const QString kShortName = QString::fromWCharArray(entry.shortName);
        if (kRootText.compare(kFull, Qt::CaseInsensitive) == 0 || kRootText.compare(kShortName, Qt::CaseInsensitive) == 0)
        {
            *rootKeyOut = entry.root;
            *subPathOut = kSubPath;
            return true;
        }
    }
    return false;
}

QString RegistryDock::normalizeRegistryPath(const QString& pathText)
{
    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(pathText, &root, &subPath)) return QString();
    QString output = rootKeyToText(root);
    if (!subPath.isEmpty()) output += QStringLiteral("\\") + subPath;
    return output;
}

QString RegistryDock::rootKeyToText(HKEY rootKey)
{
    for (const RootEntry& entry : kRootMap)
    {
        if (entry.root == rootKey) return QString::fromWCharArray(entry.fullName);
    }
    return QStringLiteral("<Unknown>");
}

QString RegistryDock::valueTypeToText(DWORD type)
{
    switch (type)
    {
    case REG_NONE: return QStringLiteral("REG_NONE");
    case REG_SZ: return QStringLiteral("REG_SZ");
    case REG_EXPAND_SZ: return QStringLiteral("REG_EXPAND_SZ");
    case REG_BINARY: return QStringLiteral("REG_BINARY");
    case REG_DWORD: return QStringLiteral("REG_DWORD");
    case REG_MULTI_SZ: return QStringLiteral("REG_MULTI_SZ");
    case REG_QWORD: return QStringLiteral("REG_QWORD");
    default: return QStringLiteral("REG_%1").arg(type);
    }
}

QString RegistryDock::formatValueData(DWORD type, const QByteArray& data)
{
    if (data.isEmpty()) return QStringLiteral("<empty>");

    if (type == REG_SZ || type == REG_EXPAND_SZ)
    {
        QString text = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(data.constData()), data.size() / sizeof(wchar_t));
        text.remove(QChar::Null);
        return text;
    }
    if (type == REG_MULTI_SZ)
    {
        QString text = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(data.constData()), data.size() / sizeof(wchar_t));
        return text.split(QChar::Null, Qt::SkipEmptyParts).join(QStringLiteral(" | "));
    }
    if (type == REG_DWORD && data.size() >= static_cast<int>(sizeof(DWORD)))
    {
        const DWORD kValue = *reinterpret_cast<const DWORD*>(data.constData());
        return QStringLiteral("0x%1 (%2)").arg(kValue, 8, 16, QLatin1Char('0')).arg(kValue);
    }
    if (type == REG_QWORD && data.size() >= static_cast<int>(sizeof(quint64)))
    {
        const quint64 kValue = *reinterpret_cast<const quint64*>(data.constData());
        return QStringLiteral("0x%1 (%2)").arg(static_cast<qulonglong>(kValue), 16, 16, QLatin1Char('0')).arg(static_cast<qulonglong>(kValue));
    }
    return bytesToHex(data, 64);
}

QString RegistryDock::winErrorText(LONG code)
{
    wchar_t* buffer = nullptr;
    const DWORD kSize = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(code),
        0,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    QString text = QStringLiteral("错误码 %1").arg(code);
    if (kSize > 0 && buffer != nullptr)
    {
        text += QStringLiteral(": ") + QString::fromWCharArray(buffer, static_cast<int>(kSize)).trimmed();
    }
    if (buffer != nullptr) ::LocalFree(buffer);
    return text;
}

bool RegistryDock::readRegistryValueRaw(HKEY root, const QString& subPath, const QString& valueName, DWORD* typeOut, QByteArray* dataOut, QString* errorOut)
{
    if (typeOut == nullptr || dataOut == nullptr) return false;
    if (errorOut != nullptr) errorOut->clear();

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_QUERY_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        if (errorOut != nullptr) *errorOut = winErrorText(openResult);
        return false;
    }

    const QString kRealName = trimDefaultValueName(valueName);
    const wchar_t* valuePtr = kRealName.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kRealName.utf16());

    DWORD type = REG_NONE;
    DWORD size = 0;
    LONG queryResult = ::RegQueryValueExW(key, valuePtr, nullptr, &type, nullptr, &size);
    if (queryResult != ERROR_SUCCESS)
    {
        ::RegCloseKey(key);
        if (errorOut != nullptr) *errorOut = winErrorText(queryResult);
        return false;
    }

    QByteArray data;
    data.resize(static_cast<int>(size));
    if (size > 0)
    {
        queryResult = ::RegQueryValueExW(key, valuePtr, nullptr, &type, reinterpret_cast<LPBYTE>(data.data()), &size);
        if (queryResult != ERROR_SUCCESS)
        {
            ::RegCloseKey(key);
            if (errorOut != nullptr) *errorOut = winErrorText(queryResult);
            return false;
        }
    }

    ::RegCloseKey(key);
    *typeOut = type;
    *dataOut = data;
    return true;
}

bool RegistryDock::writeRegistryValue(HKEY root, const QString& subPath, const QString& valueName, DWORD type, const QByteArray& rawData, QString* errorOut)
{
    if (errorOut != nullptr) errorOut->clear();

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_SET_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        if (errorOut != nullptr) *errorOut = winErrorText(openResult);
        return false;
    }

    const QString kRealName = trimDefaultValueName(valueName);
    const wchar_t* valuePtr = kRealName.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kRealName.utf16());
    LONG setResult = ::RegSetValueExW(
        key,
        valuePtr,
        0,
        type,
        reinterpret_cast<const BYTE*>(rawData.constData()),
        static_cast<DWORD>(rawData.size()));
    ::RegCloseKey(key);

    if (setResult != ERROR_SUCCESS)
    {
        if (errorOut != nullptr) *errorOut = winErrorText(setResult);
        return false;
    }
    return true;
}

void RegistryDock::updateStatusBar(const QString& message)
{
    pathStatusLabel_->setText(QStringLiteral("路径: %1").arg(currentPath_));
    summaryStatusLabel_->setText(message);
}

void RegistryDock::navigateToPath(const QString& path, bool recordHistory)
{
    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 导航请求, input="
            << path.toStdString()
            << ", recordHistory="
            << (recordHistory ? "true" : "false")
            << eol;
    }

    const QString kNormalized = normalizeRegistryPath(path);
    if (kNormalized.isEmpty())
    {
        KLogEvent event;
        warn << event << "[RegistryDock] 导航失败：无效路径, input=" << path.toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("注册表"), QStringLiteral("无效路径：%1").arg(path));
        return;
    }

    currentPath_ = kNormalized;
    pathEdit_->setText(kNormalized);

    if (recordHistory)
    {
        if (navigationIndex_ + 1 < static_cast<int>(navigationHistory_.size()))
        {
            navigationHistory_.erase(navigationHistory_.begin() + navigationIndex_ + 1, navigationHistory_.end());
        }
        if (navigationHistory_.empty() || navigationHistory_.back().compare(kNormalized, Qt::CaseInsensitive) != 0)
        {
            navigationHistory_.push_back(kNormalized);
        }
        navigationIndex_ = static_cast<int>(navigationHistory_.size()) - 1;
    }

    backButton_->setEnabled(navigationIndex_ > 0);
    forwardButton_->setEnabled(navigationIndex_ >= 0 && (navigationIndex_ + 1) < static_cast<int>(navigationHistory_.size()));

    selectTreeItemByPath(kNormalized);
    refreshCurrentKey(true);

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 导航成功, normalized="
            << kNormalized.toStdString()
            << ", historySize="
            << navigationHistory_.size()
            << ", historyIndex="
            << navigationIndex_
            << eol;
    }
}

void RegistryDock::selectTreeItemByPath(const QString& path)
{
    const QString kNormalized = normalizeRegistryPath(path);
    if (kNormalized.isEmpty()) return;

    const QStringList kSegments = kNormalized.split('\\', Qt::SkipEmptyParts);
    if (kSegments.isEmpty()) return;

    QTreeWidgetItem* current = nullptr;
    for (int i = 0; i < keyTree_->topLevelItemCount(); ++i)
    {
        QTreeWidgetItem* item = keyTree_->topLevelItem(i);
        if (item->text(0).compare(kSegments.first(), Qt::CaseInsensitive) == 0)
        {
            current = item;
            break;
        }
    }
    if (current == nullptr) return;

    ensureTreeItemLoaded(current);
    for (int i = 1; i < kSegments.size(); ++i)
    {
        ensureTreeItemLoaded(current);
        QTreeWidgetItem* next = nullptr;
        for (int childIndex = 0; childIndex < current->childCount(); ++childIndex)
        {
            QTreeWidgetItem* child = current->child(childIndex);
            if (child == nullptr || child->data(0, kRolePlaceholder).toBool()) continue;
            if (child->text(0).compare(kSegments.at(i), Qt::CaseInsensitive) == 0)
            {
                next = child;
                break;
            }
        }
        if (next == nullptr) break;
        current = next;
    }

    QSignalBlocker blocker(keyTree_);
    keyTree_->setCurrentItem(current);
    keyTree_->scrollToItem(current);
}

void RegistryDock::ensureTreeItemLoaded(QTreeWidgetItem* item)
{
    if (item == nullptr || item->data(0, kRolePlaceholder).toBool()) return;
    if (item->data(0, kRoleLoaded).toBool()) return;

    const QString kItemPath = item->data(0, kRolePath).toString();
    {
        KLogEvent event;
        dbg << event << "[RegistryDock] 展开节点并加载子键, path=" << kItemPath.toStdString() << eol;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(kItemPath, &root, &subPath))
    {
        item->setData(0, kRoleLoaded, true);
        return;
    }

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_ENUMERATE_SUB_KEYS, &key);

    item->takeChildren();
    if (openResult != ERROR_SUCCESS)
    {
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("读取注册表子键"), static_cast<unsigned long>(openResult));
        KLogEvent event;
        warn << event
            << "[RegistryDock] 加载子键失败, path="
            << kItemPath.toStdString()
            << ", error="
            << winErrorText(openResult).toStdString()
            << eol;
        item->setData(0, kRoleLoaded, true);
        return;
    }

    wchar_t nameBuffer[512] = {};
    DWORD index = 0;
    DWORD nameLength = static_cast<DWORD>(std::size(nameBuffer));
    int childCount = 0;
    while (::RegEnumKeyExW(key, index, nameBuffer, &nameLength, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
    {
        const QString kName = QString::fromWCharArray(nameBuffer, static_cast<int>(nameLength));
        QTreeWidgetItem* child = new QTreeWidgetItem(item);
        child->setText(0, kName);
        child->setData(0, kRolePath, item->data(0, kRolePath).toString() + QStringLiteral("\\") + kName);
        child->setData(0, kRoleLoaded, false);
        child->setData(0, kRolePlaceholder, false);

        QTreeWidgetItem* placeholder = new QTreeWidgetItem(child);
        placeholder->setText(0, QStringLiteral("..."));
        placeholder->setData(0, kRolePlaceholder, true);

        ++index;
        ++childCount;
        nameLength = static_cast<DWORD>(std::size(nameBuffer));
    }

    ::RegCloseKey(key);
    item->setData(0, kRoleLoaded, true);

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 子键加载完成, path="
            << kItemPath.toStdString()
            << ", childCount="
            << childCount
            << eol;
    }
}

void RegistryDock::refreshCurrentKey(bool)
{
    KLogEvent event;
    info << event << "[RegistryDock] 刷新当前键, path=" << currentPath_.toStdString() << eol;
    refreshValueTable();
}

void RegistryDock::refreshValueTable()
{
    const QPointer<RegistryDock> kGuardThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("registry-value-table-refresh"),
            {valueTable_},
            [kGuardThis]()
            {
                if (!kGuardThis.isNull())
                {
                    kGuardThis->refreshValueTable();
                }
            }))
    {
        return;
    }

    {
        KLogEvent event;
        dbg << event << "[RegistryDock] 开始刷新值列表, path=" << currentPath_.toStdString() << eol;
    }

    valueTable_->setRowCount(0);

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(currentPath_, &root, &subPath))
    {
        KLogEvent event;
        warn << event << "[RegistryDock] 刷新失败：路径无效, path=" << currentPath_.toStdString() << eol;
        updateStatusBar(QStringLiteral("状态: 路径无效"));
        return;
    }

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_QUERY_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        KLogEvent event;
        warn << event
            << "[RegistryDock] 打开键失败, path="
            << currentPath_.toStdString()
            << ", error="
            << winErrorText(openResult).toStdString()
            << eol;
        updateStatusBar(QStringLiteral("状态: 打开失败 - %1").arg(winErrorText(openResult)));
        return;
    }

    DWORD valueCount = 0;
    DWORD maxNameLength = 0;
    DWORD maxDataLength = 0;
    ::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, &maxNameLength, &maxDataLength, nullptr, nullptr);

    DWORD defaultType = REG_NONE;
    DWORD defaultSize = 0;
    LONG defaultQuery = ::RegQueryValueExW(key, nullptr, nullptr, &defaultType, nullptr, &defaultSize);
    if (defaultQuery == ERROR_SUCCESS)
    {
        QByteArray defaultData;
        defaultData.resize(static_cast<int>(defaultSize));
        if (defaultSize > 0)
        {
            ::RegQueryValueExW(key, nullptr, nullptr, &defaultType, reinterpret_cast<LPBYTE>(defaultData.data()), &defaultSize);
        }

        valueTable_->insertRow(0);
        QTableWidgetItem* nameItem = new QTableWidgetItem(QStringLiteral("(默认)"));
        nameItem->setData(Qt::UserRole, QString());
        valueTable_->setItem(0, 0, nameItem);
        valueTable_->setItem(0, 1, new QTableWidgetItem(valueTypeToText(defaultType)));
        valueTable_->setItem(0, 2, new QTableWidgetItem(formatValueData(defaultType, defaultData)));
    }

    std::vector<wchar_t> nameBuffer(static_cast<std::size_t>(maxNameLength + 4), L'\0');
    std::vector<unsigned char> dataBuffer(static_cast<std::size_t>(maxDataLength + 8), 0);

    for (DWORD index = 0; index < valueCount; ++index)
    {
        DWORD nameLength = static_cast<DWORD>(nameBuffer.size() - 1);
        DWORD dataLength = static_cast<DWORD>(dataBuffer.size());
        DWORD type = REG_NONE;
        LONG enumResult = ::RegEnumValueW(key, index, nameBuffer.data(), &nameLength, nullptr, &type, dataBuffer.data(), &dataLength);
        if (enumResult != ERROR_SUCCESS) continue;

        const QString kValueName = QString::fromWCharArray(nameBuffer.data(), static_cast<int>(nameLength));
        if (kValueName.isEmpty()) continue;

        const QByteArray kBytes(reinterpret_cast<const char*>(dataBuffer.data()), static_cast<int>(dataLength));
        const int kRow = valueTable_->rowCount();
        valueTable_->insertRow(kRow);
        QTableWidgetItem* nameItem = new QTableWidgetItem(kValueName);
        nameItem->setData(Qt::UserRole, kValueName);
        valueTable_->setItem(kRow, 0, nameItem);
        valueTable_->setItem(kRow, 1, new QTableWidgetItem(valueTypeToText(type)));
        valueTable_->setItem(kRow, 2, new QTableWidgetItem(formatValueData(type, kBytes)));
    }

    ::RegCloseKey(key);
    updateStatusBar(QStringLiteral("状态: 已加载 %1 个值").arg(valueTable_->rowCount()));

    KLogEvent finishEvent;
    info << finishEvent
        << "[RegistryDock] 值列表刷新完成, path="
        << currentPath_.toStdString()
        << ", valueCount="
        << valueTable_->rowCount()
        << eol;
}
void RegistryDock::showTreeContextMenu(const QPoint& pos)
{
    QTreeWidgetItem* item = keyTree_->itemAt(pos);
    if (item != nullptr && !item->data(0, kRolePlaceholder).toBool()) keyTree_->setCurrentItem(item);

    QMenu menu(this);
    // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* newKeyAction = menu.addAction(QIcon(":/Icon/process_open_folder.svg"), QStringLiteral("新建子键"));
    QAction* renameAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("重命名"));
    QAction* deleteAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除"));
    menu.addSeparator();
    QAction* copyPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制路径"));
    QAction* refreshAction = menu.addAction(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("刷新"));
    menu.addSeparator();
    QAction* exportAction = menu.addAction(QIcon(":/Icon/log_export.svg"), QStringLiteral("导出 .reg"));
    QAction* importAction = menu.addAction(QIcon(":/Icon/process_resume.svg"), QStringLiteral("导入 .reg"));

    QAction* action = menu.exec(keyTree_->viewport()->mapToGlobal(pos));
    if (action == nullptr) return;

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 树右键动作, action="
            << action->text().toStdString()
            << ", currentPath="
            << currentPath_.toStdString()
            << eol;
    }
    if (action == newKeyAction) createSubKey();
    else if (action == renameAction) renameSelectedObject();
    else if (action == deleteAction) deleteSelectedObject();
    else if (action == copyPathAction) copyCurrentPathToClipboard();
    else if (action == refreshAction) refreshCurrentKey(true);
    else if (action == exportAction) exportCurrentKeyAsync();
    else if (action == importAction) importRegFileAsync();
}

void RegistryDock::showValueContextMenu(const QPoint& pos)
{
    const QModelIndex kHit = valueTable_->indexAt(pos);
    if (kHit.isValid()) valueTable_->setCurrentCell(kHit.row(), kHit.column());

    QMenu menu(this);
    // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* editAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("修改"));
    QAction* newAction = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("新建值"));
    QAction* renameAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("重命名"));
    QAction* deleteAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除"));
    QAction* copyPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制路径"));

    QAction* action = menu.exec(valueTable_->viewport()->mapToGlobal(pos));
    if (action == nullptr) return;

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 值右键动作, action="
            << action->text().toStdString()
            << ", currentPath="
            << currentPath_.toStdString()
            << eol;
    }
    if (action == editAction) editSelectedValue();
    else if (action == newAction) createValue();
    else if (action == renameAction) renameSelectedObject();
    else if (action == deleteAction) deleteSelectedObject();
    else if (action == copyPathAction) copyCurrentPathToClipboard();
}

void RegistryDock::createSubKey()
{
    bool ok = false;
    const QString kKeyName = QInputDialog::getText(this, QStringLiteral("新建子键"), QStringLiteral("请输入子键名称："), QLineEdit::Normal, QStringLiteral("New Key"), &ok).trimmed();
    if (!ok || kKeyName.isEmpty()) return;

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 新建子键请求, parentPath="
            << currentPath_.toStdString()
            << ", keyName="
            << kKeyName.toStdString()
            << eol;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(currentPath_, &root, &subPath)) return;

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_CREATE_SUB_KEY, &key);
    if (openResult != ERROR_SUCCESS)
    {
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新建注册表子键"), static_cast<unsigned long>(openResult));
        KLogEvent event;
        warn << event << "[RegistryDock] 新建子键失败：打开父键失败, error=" << winErrorText(openResult).toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("新建子键"), winErrorText(openResult));
        return;
    }

    HKEY created = nullptr;
    LONG createResult = ::RegCreateKeyExW(key, reinterpret_cast<const wchar_t*>(kKeyName.utf16()), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &created, nullptr);
    if (created != nullptr) ::RegCloseKey(created);
    ::RegCloseKey(key);

    if (createResult != ERROR_SUCCESS)
    {
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新建注册表子键"), static_cast<unsigned long>(createResult));
        KLogEvent event;
        warn << event << "[RegistryDock] 新建子键失败：创建失败, error=" << winErrorText(createResult).toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("新建子键"), winErrorText(createResult));
        return;
    }

    KLogEvent event;
    info << event << "[RegistryDock] 新建子键成功, fullPath=" << (currentPath_ + QStringLiteral("\\") + kKeyName).toStdString() << eol;
    navigateToPath(currentPath_ + QStringLiteral("\\") + kKeyName, true);
}

void RegistryDock::createValue()
{
    bool ok = false;
    const QString kValueName = QInputDialog::getText(this, QStringLiteral("新建值"), QStringLiteral("值名称（默认值留空）："), QLineEdit::Normal, QString(), &ok).trimmed();
    if (!ok) return;

    const QStringList kTypeItems{ QStringLiteral("REG_SZ"), QStringLiteral("REG_DWORD"), QStringLiteral("REG_QWORD"), QStringLiteral("REG_BINARY") };
    const QString kTypeText = QInputDialog::getItem(this, QStringLiteral("新建值"), QStringLiteral("值类型："), kTypeItems, 0, false, &ok);
    if (!ok || kTypeText.isEmpty()) return;

    QString dataText = QInputDialog::getText(this, QStringLiteral("新建值"), QStringLiteral("值数据："), QLineEdit::Normal, QString(), &ok);
    if (!ok) return;

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 新建值请求, path="
            << currentPath_.toStdString()
            << ", valueName="
            << kValueName.toStdString()
            << ", type="
            << kTypeText.toStdString()
            << eol;
    }

    DWORD type = REG_SZ;
    QByteArray data;

    if (kTypeText == QStringLiteral("REG_DWORD"))
    {
        type = REG_DWORD;
        bool parseOk = false;
        const quint32 kValue = dataText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)
            ? dataText.mid(2).toUInt(&parseOk, 16)
            : dataText.toUInt(&parseOk, 10);
        if (!parseOk)
        {
            QMessageBox::warning(this, QStringLiteral("新建值"), QStringLiteral("DWORD 格式无效。"));
            return;
        }
        data = QByteArray(reinterpret_cast<const char*>(&kValue), sizeof(kValue));
    }
    else if (kTypeText == QStringLiteral("REG_QWORD"))
    {
        type = REG_QWORD;
        bool parseOk = false;
        const quint64 kValue = dataText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)
            ? dataText.mid(2).toULongLong(&parseOk, 16)
            : dataText.toULongLong(&parseOk, 10);
        if (!parseOk)
        {
            QMessageBox::warning(this, QStringLiteral("新建值"), QStringLiteral("QWORD 格式无效。"));
            return;
        }
        data = QByteArray(reinterpret_cast<const char*>(&kValue), sizeof(kValue));
    }
    else if (kTypeText == QStringLiteral("REG_BINARY"))
    {
        type = REG_BINARY;
        const QStringList kParts = dataText.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        for (const QString& part : kParts)
        {
            bool parseOk = false;
            const int kValue = part.toInt(&parseOk, 16);
            if (!parseOk || kValue < 0 || kValue > 255)
            {
                QMessageBox::warning(this, QStringLiteral("新建值"), QStringLiteral("二进制字节无效：%1").arg(part));
                return;
            }
            data.push_back(static_cast<char>(kValue));
        }
    }
    else
    {
        type = REG_SZ;
        dataText.append(QChar::Null);
        data = QByteArray(reinterpret_cast<const char*>(dataText.utf16()), dataText.size() * sizeof(char16_t));
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(currentPath_, &root, &subPath)) return;

    QString errorText;
    if (!writeRegistryValue(root, subPath, kValueName, type, data, &errorText))
    {
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新建注册表值"), errorText);
        KLogEvent event;
        warn << event << "[RegistryDock] 新建值失败, path=" << currentPath_.toStdString() << ", error=" << errorText.toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("新建值"), errorText);
        return;
    }

    KLogEvent event;
    info << event << "[RegistryDock] 新建值成功, path=" << currentPath_.toStdString() << ", valueName=" << kValueName.toStdString() << eol;
    refreshValueTable();
}

void RegistryDock::renameSelectedObject()
{
    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 重命名请求, path="
            << currentPath_.toStdString()
            << ", valueTableFocus="
            << (valueTable_->hasFocus() ? "true" : "false")
            << eol;
    }

    if (valueTable_->hasFocus() && valueTable_->currentRow() >= 0)
    {
        const int kRow = valueTable_->currentRow();
        QTableWidgetItem* nameItem = valueTable_->item(kRow, 0);
        if (nameItem == nullptr) return;

        const QString kOldName = nameItem->data(Qt::UserRole).toString();
        if (kOldName.isEmpty())
        {
            QMessageBox::information(this, QStringLiteral("重命名"), QStringLiteral("默认值不支持重命名。"));
            return;
        }

        bool ok = false;
        const QString kNewName = QInputDialog::getText(this, QStringLiteral("重命名值"), QStringLiteral("新名称："), QLineEdit::Normal, kOldName, &ok).trimmed();
        if (!ok || kNewName.isEmpty() || kNewName.compare(kOldName, Qt::CaseInsensitive) == 0) return;

        HKEY root = nullptr;
        QString subPath;
        if (!parseRegistryPath(currentPath_, &root, &subPath)) return;

        DWORD type = REG_NONE;
        QByteArray data;
        QString errorText;
        if (!readRegistryValueRaw(root, subPath, kOldName, &type, &data, &errorText))
        {
            QMessageBox::warning(this, QStringLiteral("重命名值"), errorText);
            return;
        }

        if (!writeRegistryValue(root, subPath, kNewName, type, data, &errorText))
        {
            (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("重命名注册表值"), errorText);
            KLogEvent event;
            warn << event << "[RegistryDock] 重命名值失败：写入新值失败, error=" << errorText.toStdString() << eol;
            QMessageBox::warning(this, QStringLiteral("重命名值"), errorText);
            return;
        }

        HKEY key = nullptr;
        LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_SET_VALUE, &key);
        if (openResult == ERROR_SUCCESS)
        {
            ::RegDeleteValueW(key, reinterpret_cast<const wchar_t*>(kOldName.utf16()));
            ::RegCloseKey(key);
        }

        KLogEvent event;
        info << event
            << "[RegistryDock] 重命名值成功, oldName="
            << kOldName.toStdString()
            << ", newName="
            << kNewName.toStdString()
            << eol;

        refreshValueTable();
        return;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(currentPath_, &root, &subPath)) return;
    if (subPath.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("重命名键"), QStringLiteral("根键不可重命名。"));
        return;
    }

    const int kSlashPos = subPath.lastIndexOf('\\');
    const QString kParentPath = kSlashPos < 0 ? QString() : subPath.left(kSlashPos);
    const QString kOldKeyName = kSlashPos < 0 ? subPath : subPath.mid(kSlashPos + 1);

    bool ok = false;
    const QString kNewKeyName = QInputDialog::getText(this, QStringLiteral("重命名键"), QStringLiteral("新键名："), QLineEdit::Normal, kOldKeyName, &ok).trimmed();
    if (!ok || kNewKeyName.isEmpty() || kNewKeyName.compare(kOldKeyName, Qt::CaseInsensitive) == 0) return;

    HKEY parentKey = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, kParentPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kParentPath.utf16()), 0, KEY_WRITE, &parentKey);
    if (openResult != ERROR_SUCCESS)
    {
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("重命名注册表键"), static_cast<unsigned long>(openResult));
        QMessageBox::warning(this, QStringLiteral("重命名键"), winErrorText(openResult));
        return;
    }

    using RegRenameKeyFunc = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR);
    RegRenameKeyFunc renameKey = reinterpret_cast<RegRenameKeyFunc>(::GetProcAddress(::GetModuleHandleW(L"Advapi32.dll"), "RegRenameKey"));
    if (renameKey == nullptr)
    {
        ::RegCloseKey(parentKey);
        QMessageBox::warning(this, QStringLiteral("重命名键"), QStringLiteral("系统不支持 RegRenameKey。"));
        return;
    }

    LONG renameResult = renameKey(parentKey, reinterpret_cast<const wchar_t*>(kOldKeyName.utf16()), reinterpret_cast<const wchar_t*>(kNewKeyName.utf16()));
    ::RegCloseKey(parentKey);
    if (renameResult != ERROR_SUCCESS)
    {
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("重命名注册表键"), static_cast<unsigned long>(renameResult));
        KLogEvent event;
        warn << event << "[RegistryDock] 重命名键失败, error=" << winErrorText(renameResult).toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("重命名键"), winErrorText(renameResult));
        return;
    }

    QString newPath = rootKeyToText(root);
    if (!kParentPath.isEmpty()) newPath += QStringLiteral("\\") + kParentPath;
    newPath += QStringLiteral("\\") + kNewKeyName;

    KLogEvent event;
    info << event
        << "[RegistryDock] 重命名键成功, oldKey="
        << kOldKeyName.toStdString()
        << ", newKey="
        << kNewKeyName.toStdString()
        << ", newPath="
        << newPath.toStdString()
        << eol;
    navigateToPath(newPath, true);
}

void RegistryDock::deleteSelectedObject()
{
    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 删除请求, path="
            << currentPath_.toStdString()
            << ", valueTableFocus="
            << (valueTable_->hasFocus() ? "true" : "false")
            << eol;
    }

    if (valueTable_->hasFocus() && valueTable_->currentRow() >= 0)
    {
        QTableWidgetItem* nameItem = valueTable_->item(valueTable_->currentRow(), 0);
        if (nameItem == nullptr) return;
        const QString kValueName = nameItem->data(Qt::UserRole).toString();

        QMessageBox::StandardButton choice = QMessageBox::question(
            this,
            QStringLiteral("删除值"),
            QStringLiteral("确定删除值“%1”吗？").arg(kValueName.isEmpty() ? QStringLiteral("(默认)") : kValueName),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (choice != QMessageBox::Yes) return;

        HKEY root = nullptr;
        QString subPath;
        if (!parseRegistryPath(currentPath_, &root, &subPath)) return;

        HKEY key = nullptr;
        LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_SET_VALUE, &key);
        if (openResult != ERROR_SUCCESS)
        {
            (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除注册表值"), static_cast<unsigned long>(openResult));
            QMessageBox::warning(this, QStringLiteral("删除值"), winErrorText(openResult));
            return;
        }

        LONG deleteResult = ::RegDeleteValueW(key, kValueName.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kValueName.utf16()));
        ::RegCloseKey(key);
        if (deleteResult != ERROR_SUCCESS)
        {
            (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除注册表值"), static_cast<unsigned long>(deleteResult));
            KLogEvent event;
            warn << event << "[RegistryDock] 删除值失败, error=" << winErrorText(deleteResult).toStdString() << eol;
            QMessageBox::warning(this, QStringLiteral("删除值"), winErrorText(deleteResult));
            return;
        }

        KLogEvent event;
        info << event << "[RegistryDock] 删除值成功, valueName=" << kValueName.toStdString() << eol;
        refreshValueTable();
        return;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(currentPath_, &root, &subPath)) return;
    if (subPath.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("删除键"), QStringLiteral("根键不可删除。"));
        return;
    }

    QMessageBox::StandardButton choice = QMessageBox::question(
        this,
        QStringLiteral("删除键"),
        QStringLiteral("确定删除键“%1”及其子项吗？").arg(currentPath_),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (choice != QMessageBox::Yes) return;

    const int kSlashPos = subPath.lastIndexOf('\\');
    const QString kParentPath = kSlashPos < 0 ? QString() : subPath.left(kSlashPos);
    const QString kKeyName = kSlashPos < 0 ? subPath : subPath.mid(kSlashPos + 1);

    HKEY parentKey = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, kParentPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kParentPath.utf16()), 0, KEY_WRITE, &parentKey);
    if (openResult != ERROR_SUCCESS)
    {
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除注册表键"), static_cast<unsigned long>(openResult));
        QMessageBox::warning(this, QStringLiteral("删除键"), winErrorText(openResult));
        return;
    }

    LONG deleteResult = ::RegDeleteTreeW(parentKey, reinterpret_cast<const wchar_t*>(kKeyName.utf16()));
    ::RegCloseKey(parentKey);
    if (deleteResult != ERROR_SUCCESS)
    {
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除注册表键"), static_cast<unsigned long>(deleteResult));
        KLogEvent event;
        warn << event << "[RegistryDock] 删除键失败, error=" << winErrorText(deleteResult).toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("删除键"), winErrorText(deleteResult));
        return;
    }

    KLogEvent event;
    info << event << "[RegistryDock] 删除键成功, keyName=" << kKeyName.toStdString() << eol;

    QString parentFullPath = rootKeyToText(root);
    if (!kParentPath.isEmpty()) parentFullPath += QStringLiteral("\\") + kParentPath;
    navigateToPath(parentFullPath, true);
}

void RegistryDock::editSelectedValue()
{
    const int kRow = valueTable_->currentRow();
    {
        KLogEvent event;
        info << event << "[RegistryDock] 编辑值请求, path=" << currentPath_.toStdString() << ", row=" << kRow << eol;
    }
    if (kRow < 0) return;
    QTableWidgetItem* nameItem = valueTable_->item(kRow, 0);
    if (nameItem == nullptr) return;

    const QString kValueName = nameItem->data(Qt::UserRole).toString();

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(currentPath_, &root, &subPath)) return;

    DWORD type = REG_NONE;
    QByteArray data;
    QString errorText;
    if (!readRegistryValueRaw(root, subPath, kValueName, &type, &data, &errorText))
    {
        KLogEvent event;
        warn << event << "[RegistryDock] 编辑值失败：读取原值失败, error=" << errorText.toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("编辑值"), errorText);
        return;
    }

    bool ok = false;
    QByteArray outputData = data;

    if (type == REG_DWORD || type == REG_QWORD)
    {
        qulonglong oldValue = 0;
        if (type == REG_DWORD && data.size() >= static_cast<int>(sizeof(DWORD))) oldValue = *reinterpret_cast<const DWORD*>(data.constData());
        if (type == REG_QWORD && data.size() >= static_cast<int>(sizeof(quint64))) oldValue = *reinterpret_cast<const quint64*>(data.constData());

        const QString kText = QInputDialog::getText(this, QStringLiteral("编辑值"), QStringLiteral("输入新数值："), QLineEdit::Normal, QString::number(oldValue), &ok).trimmed();
        if (!ok) return;

        bool parseOk = false;
        const qulonglong kParsed = kText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)
            ? kText.mid(2).toULongLong(&parseOk, 16)
            : kText.toULongLong(&parseOk, 10);
        if (!parseOk)
        {
            QMessageBox::warning(this, QStringLiteral("编辑值"), QStringLiteral("数值格式无效。"));
            return;
        }

        if (type == REG_DWORD)
        {
            const DWORD kV = static_cast<DWORD>(kParsed);
            outputData = QByteArray(reinterpret_cast<const char*>(&kV), sizeof(kV));
        }
        else
        {
            const quint64 kV = static_cast<quint64>(kParsed);
            outputData = QByteArray(reinterpret_cast<const char*>(&kV), sizeof(kV));
        }
    }
    else if (type == REG_BINARY)
    {
        const QString kText = QInputDialog::getText(this, QStringLiteral("编辑值"), QStringLiteral("输入十六进制字节："), QLineEdit::Normal, bytesToHex(data, 512), &ok).trimmed();
        if (!ok) return;

        outputData.clear();
        const QStringList kParts = kText.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        for (const QString& part : kParts)
        {
            bool parseOk = false;
            const int kByteValue = part.toInt(&parseOk, 16);
            if (!parseOk || kByteValue < 0 || kByteValue > 255)
            {
                QMessageBox::warning(this, QStringLiteral("编辑值"), QStringLiteral("字节无效：%1").arg(part));
                return;
            }
            outputData.push_back(static_cast<char>(kByteValue));
        }
    }
    else
    {
        QString text = QInputDialog::getText(this, QStringLiteral("编辑值"), QStringLiteral("输入字符串："), QLineEdit::Normal, formatValueData(type, data), &ok);
        if (!ok) return;
        text.append(QChar::Null);
        outputData = QByteArray(reinterpret_cast<const char*>(text.utf16()), text.size() * sizeof(char16_t));
    }

    if (!writeRegistryValue(root, subPath, kValueName, type, outputData, &errorText))
    {
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("编辑注册表值"), errorText);
        KLogEvent event;
        warn << event << "[RegistryDock] 编辑值失败：写入失败, error=" << errorText.toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("编辑值"), errorText);
        return;
    }

    KLogEvent event;
    info << event
        << "[RegistryDock] 编辑值成功, valueName="
        << kValueName.toStdString()
        << ", type="
        << valueTypeToText(type).toStdString()
        << eol;
    refreshValueTable();
}

void RegistryDock::copyCurrentPathToClipboard()
{
    QApplication::clipboard()->setText(currentPath_);

    KLogEvent event;
    info << event << "[RegistryDock] 复制路径到剪贴板, path=" << currentPath_.toStdString() << eol;
}

void RegistryDock::exportCurrentKeyAsync()
{
    if (currentPath_.isEmpty()) return;

    KLogEvent event;
    info << event << "[RegistryDock] 导出请求, keyPath=" << currentPath_.toStdString() << eol;

    const QString kOutputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出 .reg"),
        QStringLiteral("registry_%1.reg").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))),
        QStringLiteral("REG 文件 (*.reg)"));
    if (kOutputPath.trimmed().isEmpty()) return;

    if (progressPid_ == 0) progressPid_ = kPro.addReusable(this, "注册表", "导出");
    kPro.set(progressPid_, "导出中", 0, 20.0f);

    QPointer<RegistryDock> guardThis(this);
    const QString kKeyPath = currentPath_;
    std::thread([guardThis, kKeyPath, kOutputPath]() {
        QProcess process;
        process.start(QStringLiteral("reg.exe"), QStringList{ QStringLiteral("export"), kKeyPath, kOutputPath, QStringLiteral("/y") });
        process.waitForFinished(-1);

        const bool kOk = process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
        const QString kErrText = QString::fromLocal8Bit(process.readAllStandardError());

        QMetaObject::invokeMethod(qApp, [guardThis, kOk, kErrText, kOutputPath]() {
            if (guardThis == nullptr) return;
            kPro.set(guardThis->progressPid_, "导出完成", 0, 100.0f);
            if (kOk)
            {
                KLogEvent event;
                info << event << "[RegistryDock] 导出成功, outputPath=" << kOutputPath.toStdString() << eol;
                QMessageBox::information(guardThis, QStringLiteral("导出 .reg"), QStringLiteral("导出成功：%1").arg(kOutputPath));
            }
            else
            {
                KLogEvent event;
                warn << event << "[RegistryDock] 导出失败, error=" << kErrText.toStdString() << eol;
                QMessageBox::warning(guardThis, QStringLiteral("导出 .reg"), QStringLiteral("导出失败：\n%1").arg(kErrText));
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void RegistryDock::importRegFileAsync()
{
    const QString kInputPath = QFileDialog::getOpenFileName(this, QStringLiteral("导入 .reg"), QString(), QStringLiteral("REG 文件 (*.reg)"));
    if (kInputPath.trimmed().isEmpty()) return;

    KLogEvent event;
    info << event << "[RegistryDock] 导入请求, inputPath=" << kInputPath.toStdString() << eol;

    if (progressPid_ == 0) progressPid_ = kPro.addReusable(this, "注册表", "导入");
    kPro.set(progressPid_, "导入中", 0, 20.0f);

    QPointer<RegistryDock> guardThis(this);
    std::thread([guardThis, kInputPath]() {
        QProcess process;
        process.start(QStringLiteral("reg.exe"), QStringList{ QStringLiteral("import"), kInputPath });
        process.waitForFinished(-1);

        const bool kOk = process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
        const QString kErrText = QString::fromLocal8Bit(process.readAllStandardError());

        QMetaObject::invokeMethod(qApp, [guardThis, kOk, kErrText]() {
            if (guardThis == nullptr) return;
            kPro.set(guardThis->progressPid_, "导入完成", 0, 100.0f);
            if (kOk)
            {
                KLogEvent event;
                info << event << "[RegistryDock] 导入成功。" << eol;
                QMessageBox::information(guardThis, QStringLiteral("导入 .reg"), QStringLiteral("导入成功。"));
                guardThis->refreshCurrentKey(true);
            }
            else
            {
                KLogEvent event;
                warn << event << "[RegistryDock] 导入失败, error=" << kErrText.toStdString() << eol;
                QMessageBox::warning(guardThis, QStringLiteral("导入 .reg"), QStringLiteral("导入失败：\n%1").arg(kErrText));
            }
        }, Qt::QueuedConnection);
    }).detach();
}
void RegistryDock::startSearchAsync()
{
    if (searchRunning_.load())
    {
        KLogEvent event;
        dbg << event << "[RegistryDock] 搜索请求被忽略：已有搜索在运行。" << eol;
        return;
    }

    const QString kKeyword = searchEdit_->text().trimmed();
    if (kKeyword.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("搜索"), QStringLiteral("请输入关键字。"));
        return;
    }

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 启动搜索, path="
            << currentPath_.toStdString()
            << ", keyword="
            << kKeyword.toStdString()
            << eol;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(currentPath_, &root, &subPath)) return;

    searchRunning_.store(true);
    searchStopFlag_.store(false);
    searchScannedKeys_ = 0;
    searchHitCount_ = 0;
    searchResultTable_->setRowCount(0);
    rightTabWidget_->setCurrentWidget(searchResultTable_);
    searchButton_->setEnabled(false);
    stopSearchButton_->setEnabled(true);

    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingRows_.clear();
    }

    if (progressPid_ == 0) progressPid_ = kPro.addReusable(this, "注册表", "搜索");
    kPro.set(progressPid_, "搜索开始", 0, 5.0f);
    searchFlushTimer_->start();

    QPointer<RegistryDock> guardThis(this);
    SearchOptions options;
    searchThread_ = std::make_unique<std::thread>([guardThis, root, subPath, kKeyword, options]() {
        if (guardThis == nullptr) return;

        std::size_t scanned = 0;
        std::size_t hits = 0;
        guardThis->searchRegistryRecursive(root, subPath, kKeyword, options, &scanned, &hits);

        QMetaObject::invokeMethod(qApp, [guardThis, scanned, hits]() {
            if (guardThis == nullptr) return;
            guardThis->flushPendingSearchRows();
            guardThis->searchRunning_.store(false);
            guardThis->searchStopFlag_.store(false);
            guardThis->searchButton_->setEnabled(true);
            guardThis->stopSearchButton_->setEnabled(false);
            guardThis->searchFlushTimer_->stop();
            guardThis->updateStatusBar(QStringLiteral("状态: 搜索完成，扫描 %1 键，命中 %2 项").arg(scanned).arg(hits));
            kPro.set(guardThis->progressPid_, "搜索完成", 0, 100.0f);

            KLogEvent event;
            info << event
                << "[RegistryDock] 搜索完成, scanned="
                << scanned
                << ", hits="
                << hits
                << eol;
        }, Qt::QueuedConnection);
    });
}

void RegistryDock::stopSearch(bool waitForThread)
{
    KLogEvent event;
    info << event
        << "[RegistryDock] 停止搜索请求, waitForThread="
        << (waitForThread ? "true" : "false")
        << eol;

    searchStopFlag_.store(true);

    if (searchThread_ == nullptr || !searchThread_->joinable())
    {
        searchThread_.reset();
        searchRunning_.store(false);
        searchButton_->setEnabled(true);
        stopSearchButton_->setEnabled(false);
        if (searchFlushTimer_ != nullptr) searchFlushTimer_->stop();
        return;
    }

    if (waitForThread)
    {
        searchThread_->join();
        searchThread_.reset();
        searchRunning_.store(false);
        searchButton_->setEnabled(true);
        stopSearchButton_->setEnabled(false);
        if (searchFlushTimer_ != nullptr) searchFlushTimer_->stop();
        return;
    }

    std::unique_ptr<std::thread> joinThread = std::move(searchThread_);
    QPointer<RegistryDock> guardThis(this);
    std::thread([joinThread = std::move(joinThread), guardThis]() mutable {
        if (joinThread != nullptr && joinThread->joinable()) joinThread->join();
        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr) return;
            guardThis->flushPendingSearchRows();
            guardThis->searchRunning_.store(false);
            guardThis->searchStopFlag_.store(false);
            guardThis->searchButton_->setEnabled(true);
            guardThis->stopSearchButton_->setEnabled(false);
            if (guardThis->searchFlushTimer_ != nullptr) guardThis->searchFlushTimer_->stop();
            guardThis->updateStatusBar(QStringLiteral("状态: 搜索已停止"));
            kPro.set(guardThis->progressPid_, "搜索停止", 0, 100.0f);

            KLogEvent event;
            info << event << "[RegistryDock] 搜索已停止（异步回收完成）。" << eol;
        }, Qt::QueuedConnection);
    }).detach();
}

void RegistryDock::flushPendingSearchRows()
{
    // The search thread only enqueues items; the queue is not consumed when the menu is open to prevent timing/queued
    // flushes from causing drift in rows saved by right-click actions or losing drained rows during latest-wins merges.
    const QPointer<RegistryDock> kGuardThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("registry-search-result-flush"),
            {searchResultTable_},
            [kGuardThis]()
            {
                if (!kGuardThis.isNull())
                {
                    kGuardThis->flushPendingSearchRows();
                }
            }))
    {
        return;
    }

    std::vector<PendingSearchRow> rows;
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        if (pendingRows_.empty()) return;

        constexpr std::size_t kBatch = 200;
        const std::size_t kCount = std::min<std::size_t>(kBatch, pendingRows_.size());
        rows.reserve(kCount);
        for (std::size_t i = 0; i < kCount; ++i) rows.push_back(std::move(pendingRows_[i]));
        using DiffType = std::vector<PendingSearchRow>::difference_type;
        pendingRows_.erase(pendingRows_.begin(), pendingRows_.begin() + static_cast<DiffType>(kCount));
    }

    for (const PendingSearchRow& row : rows)
    {
        const int kIndex = searchResultTable_->rowCount();
        searchResultTable_->insertRow(kIndex);
        searchResultTable_->setItem(kIndex, 0, new QTableWidgetItem(row.keyPathText));
        searchResultTable_->setItem(kIndex, 1, new QTableWidgetItem(row.valueNameText));
        searchResultTable_->setItem(kIndex, 2, new QTableWidgetItem(row.valueTypeText));
        searchResultTable_->setItem(kIndex, 3, new QTableWidgetItem(row.valueDataPreviewText));
        searchResultTable_->setItem(kIndex, 4, new QTableWidgetItem(row.hitSourceText));
    }
}

void RegistryDock::searchRegistryRecursive(HKEY root, const QString& subPath, const QString& keyword, const SearchOptions& options, std::size_t* scanned, std::size_t* hit)
{
    if (searchStopFlag_.load()) return;

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &key);
    if (openResult != ERROR_SUCCESS) return;

    if (scanned != nullptr) *scanned += 1;

    const QString kFullPath = rootKeyToText(root) + (subPath.isEmpty() ? QString() : QStringLiteral("\\") + subPath);
    const QString kKeyName = subPath.isEmpty() ? rootKeyToText(root) : subPath.mid(subPath.lastIndexOf('\\') + 1);

    auto containsText = [&keyword, &options](const QString& text) {
        return options.caseSensitive ? text.contains(keyword) : text.contains(keyword, Qt::CaseInsensitive);
    };

    if (options.searchKeyName && containsText(kKeyName))
    {
        PendingSearchRow row;
        row.keyPathText = kFullPath;
        row.valueNameText = QStringLiteral("<Key>");
        row.valueTypeText = QStringLiteral("<Key>");
        row.valueDataPreviewText = QStringLiteral("-");
        row.hitSourceText = QStringLiteral("KeyName");
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingRows_.push_back(std::move(row));
        if (hit != nullptr) *hit += 1;
    }

    DWORD subKeyCount = 0;
    DWORD maxSubKeyLen = 0;
    DWORD valueCount = 0;
    DWORD maxValueNameLen = 0;
    DWORD maxValueDataLen = 0;
    ::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLen, nullptr, &valueCount, &maxValueNameLen, &maxValueDataLen, nullptr, nullptr);

    std::vector<wchar_t> valueNameBuffer(static_cast<std::size_t>(maxValueNameLen + 4), L'\0');
    std::vector<unsigned char> valueDataBuffer(static_cast<std::size_t>(maxValueDataLen + 8), 0);

    for (DWORD index = 0; index < valueCount; ++index)
    {
        if (searchStopFlag_.load()) break;

        DWORD valueNameLen = static_cast<DWORD>(valueNameBuffer.size() - 1);
        DWORD valueDataLen = static_cast<DWORD>(valueDataBuffer.size());
        DWORD valueType = REG_NONE;
        LONG enumResult = ::RegEnumValueW(key, index, valueNameBuffer.data(), &valueNameLen, nullptr, &valueType, valueDataBuffer.data(), &valueDataLen);
        if (enumResult != ERROR_SUCCESS) continue;

        const QString kValueName = QString::fromWCharArray(valueNameBuffer.data(), static_cast<int>(valueNameLen));
        const QByteArray kValueData(reinterpret_cast<const char*>(valueDataBuffer.data()), static_cast<int>(valueDataLen));
        const QString kValueText = formatValueData(valueType, kValueData);

        bool matched = false;
        QString sourceText;
        if (options.searchValueName && containsText(kValueName))
        {
            matched = true;
            sourceText = QStringLiteral("ValueName");
        }
        if (!matched && options.searchValueData && containsText(kValueText))
        {
            matched = true;
            sourceText = QStringLiteral("ValueData");
        }
        if (!matched) continue;

        PendingSearchRow row;
        row.keyPathText = kFullPath;
        row.valueNameText = kValueName.isEmpty() ? QStringLiteral("(默认)") : kValueName;
        row.valueTypeText = valueTypeToText(valueType);
        row.valueDataPreviewText = kValueText;
        row.hitSourceText = sourceText;

        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingRows_.push_back(std::move(row));
        if (hit != nullptr) *hit += 1;
    }

    if (scanned != nullptr && (*scanned % 64 == 0))
    {
        const std::size_t kScannedSnapshot = *scanned;
        const std::size_t kHitSnapshot = (hit == nullptr) ? 0 : *hit;
        QPointer<RegistryDock> guardThis(this);
        QMetaObject::invokeMethod(qApp, [guardThis, kScannedSnapshot, kHitSnapshot]() {
            if (guardThis == nullptr) return;
            guardThis->updateStatusBar(QStringLiteral("状态: 搜索中，扫描 %1 键，命中 %2 项").arg(kScannedSnapshot).arg(kHitSnapshot));
            const float kProgress = 5.0f + static_cast<float>(std::min<std::size_t>(kScannedSnapshot, 4000)) / 50.0f;
            kPro.set(guardThis->progressPid_, "搜索中", 0, std::min(kProgress, 95.0f));
        }, Qt::QueuedConnection);
    }

    std::vector<wchar_t> subNameBuffer(static_cast<std::size_t>(maxSubKeyLen + 4), L'\0');
    for (DWORD subIndex = 0; subIndex < subKeyCount; ++subIndex)
    {
        if (searchStopFlag_.load()) break;

        DWORD subNameLen = static_cast<DWORD>(subNameBuffer.size() - 1);
        LONG subResult = ::RegEnumKeyExW(key, subIndex, subNameBuffer.data(), &subNameLen, nullptr, nullptr, nullptr, nullptr);
        if (subResult != ERROR_SUCCESS) continue;

        const QString kChildName = QString::fromWCharArray(subNameBuffer.data(), static_cast<int>(subNameLen));
        const QString kChildPath = subPath.isEmpty() ? kChildName : subPath + QStringLiteral("\\") + kChildName;
        searchRegistryRecursive(root, kChildPath, keyword, options, scanned, hit);
    }

    ::RegCloseKey(key);
}
