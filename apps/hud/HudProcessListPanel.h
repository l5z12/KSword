#pragma once

#include <QFutureWatcher>
#include <QColor>
#include <QHash>
#include <QIcon>
#include <QSet>
#include <QVector>
#include <QWidget>

class QFileIconProvider;
class QHideEvent;
class QPoint;
class QShowEvent;
class QStyledItemDelegate;
class QTimer;
class QTreeWidget;
class QTreeWidgetItem;

class HudProcessListPanel final : public QWidget
{
public:
    explicit HudProcessListPanel(QWidget* parent = nullptr);
    ~HudProcessListPanel() override;
    void setTableTextColor(const QColor& colorValue);

protected:
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;

private:
    enum ColumnIndex
    {
        kNameColumn = 0,
        kPidColumn,
        kCpuColumn,
        kRamColumn,
        kDiskColumn,
        kGpuColumn,
        kNetColumn,
        kColumnCount
    };

    enum class ProcessGroupType
    {
        kApplication = 0,
        kBackground,
        kWindowsSystem
    };

    struct CounterSample
    {
        quint64 cpuTime100ns = 0;
        quint64 ioBytes = 0;
        quint64 networkBytes = 0;
        qint64 sampleMs = 0;
    };

    struct ProcessIdentity
    {
        quint32 pid = 0;
        quint64 creationTime100ns = 0;
    };

    struct ProcessEntry
    {
        quint32 pid = 0;
        quint32 parentPid = 0;
        quint32 applicationRootPid = 0;
        quint64 creationTime100ns = 0;
        QString processName;
        QString imagePath;
        ProcessGroupType groupType = ProcessGroupType::kBackground;
        double cpuPercent = 0.0;
        double ramMB = 0.0;
        double diskMBps = 0.0;
        double gpuPercent = 0.0;
        double netKBps = 0.0;
    };

    struct RefreshResult
    {
        QVector<ProcessEntry> entries;
        QHash<QString, CounterSample> nextSamples;
        double totalCpuPercent = 0.0;
        double totalRamMB = 0.0;
        double totalDiskMBps = 0.0;
        double totalGpuPercent = 0.0;
        double totalNetKBps = 0.0;
        double maxRamMB = 0.0;
        double maxDiskMBps = 0.0;
        double maxNetKBps = 0.0;
    };

    void initializeUi();
    void applyTreeWidgetStyle();
    void showContextMenu(const QPoint& localPosition);
    bool terminateProcessByIdentity(const ProcessIdentity& processIdentity);
    int terminateProcessesByIdentityList(const QVector<ProcessIdentity>& processIdentityList);
    void startRefreshing();
    void stopRefreshing();
    void requestRefresh();
    void captureExpandedState();
    void captureExpandedStateForItem(QTreeWidgetItem* itemPointer);
    void restoreExpandedState(QTreeWidgetItem* itemPointer, const QString& stateKey, bool defaultExpanded);
    static RefreshResult collectRefreshResult(
        const QHash<QString, CounterSample>& previousSamples,
        const QHash<QString, QString>& cachedImagePathByIdentity,
        int logicalCpuCount);
    void applyRefreshResult(const RefreshResult& result);
    void updateHeaderSummary(const RefreshResult& result);
    QIcon resolveProcessIcon(const ProcessEntry& entry);
    static void classifyProcessGroups(QVector<ProcessEntry>* entries, const QSet<quint32>& visibleWindowPidSet);
    static quint32 findApplicationRootPid(quint32 pidValue, const QHash<quint32, quint32>& parentPidByPid, const QSet<quint32>& visibleWindowPidSet);
    static bool isWindowsSystemProcess(const ProcessEntry& entry, const QString& windowsDirectoryPath);
    static ProcessEntry aggregateApplicationEntry(const QVector<ProcessEntry>& applicationEntries);
    static QString expansionKeyForGroup(ProcessGroupType groupType);
    static QString expansionKeyForApplication(quint32 rootPidValue);
    static QString expansionKeyForProcess(quint32 pidValue);
    static QString processGroupTitle(ProcessGroupType groupType, int entryCount);
    static int processGroupOrder(ProcessGroupType groupType);
    static QTreeWidgetItem* createProcessGroupItem(ProcessGroupType groupType, int entryCount);
    QTreeWidgetItem* createApplicationRootItem(
        const ProcessEntry& aggregateEntry,
        const QVector<ProcessEntry>& applicationEntries,
        int childProcessCount,
        double maxRamMB,
        double maxDiskMBps,
        double maxNetKBps);
    static QString buildProcessInstanceKey(quint32 pidValue, quint64 creationTime100ns);
    QTreeWidgetItem* updateOrCreateRow(
        const ProcessEntry& entry,
        QTreeWidgetItem* parentItem,
        double maxRamMB,
        double maxDiskMBps,
        double maxNetKBps);
    static double usageRatioForEntry(const ProcessEntry& entry, int columnIndex, double maxRamMB, double maxDiskMBps, double maxNetKBps);
    static QString formatPercent(double value, int decimals = 2);
    static QString formatRamMB(double value);
    static QString formatDiskMBps(double value);
    static QString formatNetKBps(double value);

    QTreeWidget* treeWidget_ = nullptr;
    QStyledItemDelegate* metricDelegate_ = nullptr;
    QFileIconProvider* fileIconProvider_ = nullptr;
    QTimer* refreshTimer_ = nullptr;
    QFutureWatcher<RefreshResult>* refreshWatcher_ = nullptr;
    bool refreshInProgress_ = false;
    int logicalCpuCount_ = 1;
    QColor tableTextColor_ = QColor(255, 255, 255);
    QHash<QString, CounterSample> previousSamples_;
    QHash<QString, QString> imagePathByIdentity_;
    QHash<QString, QIcon> iconCacheByIdentity_;
    QHash<QString, QIcon> iconCacheByPath_;
    QHash<quint32, QTreeWidgetItem*> itemByPid_;
    QHash<QString, bool> expandedStateByKey_;
};
