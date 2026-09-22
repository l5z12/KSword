#pragma once

// Private implementation contracts, never a public Dock API.
#include "ProcessDock.h"
#include "ProcessAffinityUtils.h"
#include "ProcessAffinityPersistence.h"
#include "ProcessCpuCapacityCell.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

#include "../Theme.h"
#include "ProcessDetailWindow.h"
#include "ProcessMessageHookWindow.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../../../shared/platform/process/InjectionTraceCollector.h"
#include "../online_scan/SandboxUploadActions.h"
#include "../ui/FlatTableModel.h"
#include "../ui/TableColumnAutoFit.h"
#include "../internationalization/LanguageManager.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../framework/DestructiveActionConfirmation.h"
#include "../settings_dock/AppearanceSettings.h"
// R-1: The orchestration for handling must go through this layer; do not manually construct controlHvm. Each command has a
// different whitelist of permission bits; manually constructing it would duplicate the driver's rules in a second location.
#include "../ui/KvmControl.h"
// EnumProcessModules / GetModuleInformation: Retrieve the entry point of the
// target's main module to serve as the default value in the action dialog.
#include <psapi.h>
#include "../../../shared/platform/network/NetworkProcessEtwMonitor.h"
#include "../../../shared/platform/process/ProcessImageDeleteGuard.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QAbstractScrollArea>
#include <QApplication>
#include <QBrush>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCursor>
#include <QDateTime>
#include <QEasingCurve>
#include <QVariantAnimation>
#include <QDoubleSpinBox>
#include <QDir>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHelpEvent>
#include <QHBoxLayout>
#include <QItemSelection>
#include <QItemSelectionModel>
#include <QInputDialog>
#include <QDialog>
#include <algorithm>
#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QList>
#include <QListView>
#include <QLocale>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QMouseEvent>
#include <QPaintEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPalette>
#include <QPlainTextEdit>
#include <QPointF>
#include <QPersistentModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QPixmap>
#include <QRectF>
#include <QRunnable>
#include <QResizeEvent>
#include <QScrollArea>
#include <QShortcut>
#include <QSettings>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QSortFilterProxyModel>
#include <QStyle>
#include <QStyleOptionSlider>
#include <QStyledItemDelegate>
#include <QSlider>
#include <QScrollBar>
#include <QSvgRenderer>
#include <QTabBar>
#include <QTableView>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QTextEdit>
#include <QThreadPool>
#include <QTimer>
#include <QToolTip>
#include <QStringList>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QToolButton>
#include <QWidgetAction>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <functional>
#include <limits>
#include <memory>
#include <sstream>
#include <set>
#include <string>
#include <thread>
#include <unordered_set>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>

#pragma comment(lib, "Advapi32.lib")

#ifndef SECURITY_MANDATORY_MEDIUM_PLUS_RID
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID (SECURITY_MANDATORY_MEDIUM_RID + 0x100UL)
#endif

#ifndef SECURITY_MANDATORY_PROTECTED_PROCESS_RID
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID 0x5000UL
#endif

#ifndef SE_GROUP_INTEGRITY
#define SE_GROUP_INTEGRITY 0x00000020L
#endif


namespace ksword::ui::process_dock
{
    class ScopedProcessActionHandle;
    class ProcessTableSortProxy;
    class ProcessWindowPickerDragButton;
    class ProcessRowHighlightDelegate;

    // HvmInjectWakeContext:
    // - Input: Read/written by EnumWindows callback;
    // - Processing logic: Match the top-level window of the target PID and dispatch an empty message to each one.
    // - Return behavior: postedCount being 0 indicates the target has no wakeable top-level windows.
    struct HvmInjectWakeContext
    {
        unsigned long processId = 0UL; // processId: Target process to wake up.
        std::size_t postedCount = 0U;  // postedCount: Number of successfully posted windows.
    };

    // Wait for the execution count limit after installation. Triggering requires waiting for the target to reach that page again; if the count
    // remains zero beyond this duration, stop waiting—failure to reach it does not mean installation failed, as the payload remains attached.
    inline constexpr unsigned long long kHvmInjectSettleMilliseconds = 2000ULL;

    // Back off starting from 1 second after affinity restore failure to avoid repeated handle opens on every refresh due to transient denial.
    inline constexpr std::uint32_t kAffinityRestoreRetryBaseMilliseconds = 1000U;

    // Backoff limit is fixed at 60 seconds; retries continue after reaching the limit without permanently abandoning the process instance.
    inline constexpr std::uint32_t kAffinityRestoreRetryMaximumMilliseconds = 60000U;

    // Column header text constants, with indices corresponding one-to-one with ProcessDock::TableColumn.
    inline const QStringList kProcessTableHeaders{
        "进程名",
        "PID",
        "CPU",
        "内存",
        "磁盘",
        "GPU",
        "网络",
        "数字签名",
        "路径",
        "父进程",
        "命令行",
        "用户",
        "启动时间",
        "管理员",
        "PPL保护级别",
        "保护状态",
        "PPL",
        "句柄数",
        "HandleTable",
        "SectionObject",
        "R0状态",
        // ======== Aligned columns with Task Manager 'Details' page ========
        "程序包名称",
        "状态",
        "会话 ID",
        "作业对象 ID",
        "CPU 时间",
        "周期",
        "工作集(内存)",
        "峰值工作集(内存)",
        "工作集增量(内存)",
        "内存(活动的专用工作集)",
        "内存(专用工作集)",
        "内存(共享工作集)",
        "提交大小",
        "分页缓冲池",
        "非分页缓冲池",
        "页面错误",
        "页面错误增量",
        "基本优先级",
        "线程",
        "用户对象",
        "GDI 对象",
        "I/O 读取",
        "I/O 写入",
        "I/O 其他",
        "I/O 读取字节",
        "I/O 写入字节",
        "I/O 其他字节",
        "操作系统上下文",
        "平台",
        "UAC 虚拟化",
        "描述",
        "数据执行保护",
        "控制流保护",
        "硬件强制实施的堆栈保护",
        "企业上下文",
        "DPI 感知",
        "电源节流",
        "GPU 引擎",
        "专用 GPU 内存",
        "共享 GPU 内存",
        "类型",
        "CPU核心",
        "注入面"
    };

    inline const char* const kProcessTableHeaderKeys[] = {
        "process.table.header.process_name",
        "process.table.header.pid",
        "process.table.header.cpu",
        "process.table.header.ram",
        "process.table.header.disk",
        "process.table.header.gpu",
        "process.table.header.net",
        "process.table.header.signature",
        "process.table.header.path",
        "process.table.header.parent",
        "process.table.header.command_line",
        "process.table.header.user",
        "process.table.header.start_time",
        "process.table.header.admin",
        "process.table.header.ppl_protection",
        "process.table.header.protection",
        "process.table.header.ppl",
        "process.table.header.handle_count",
        "process.table.header.handle_table",
        "process.table.header.section_object",
        "process.table.header.r0_status",
        // ======== Aligned columns with Task Manager 'Details' page ========
        "process.table.header.package_name",
        "process.table.header.status",
        "process.table.header.session_id",
        "process.table.header.job_object",
        "process.table.header.cpu_time",
        "process.table.header.cycle_time",
        "process.table.header.working_set",
        "process.table.header.peak_working_set",
        "process.table.header.working_set_delta",
        "process.table.header.active_private_working_set",
        "process.table.header.private_working_set",
        "process.table.header.shared_working_set",
        "process.table.header.commit_size",
        "process.table.header.paged_pool",
        "process.table.header.non_paged_pool",
        "process.table.header.page_faults",
        "process.table.header.page_fault_delta",
        "process.table.header.base_priority",
        "process.table.header.thread_count",
        "process.table.header.user_objects",
        "process.table.header.gdi_objects",
        "process.table.header.io_reads",
        "process.table.header.io_writes",
        "process.table.header.io_other",
        "process.table.header.io_read_bytes",
        "process.table.header.io_write_bytes",
        "process.table.header.io_other_bytes",
        "process.table.header.os_context",
        "process.table.header.platform",
        "process.table.header.uac_virtualization",
        "process.table.header.description",
        "process.table.header.dep",
        "process.table.header.cfg",
        "process.table.header.hardware_stack_protection",
        "process.table.header.enterprise_context",
        "process.table.header.dpi_awareness",
        "process.table.header.power_throttling",
        "process.table.header.gpu_engine",
        "process.table.header.gpu_dedicated_memory",
        "process.table.header.gpu_shared_memory",
        "process.table.header.process_type",
        "process.table.header.cpu_core",
        "process.table.header.injection_surface"
    };

    // ProcessTableHeaderKeyCount：
    // - Used by initializeProcessTable to verify at runtime that 'header count == TableColumn::Count';
    // - TableColumn is a private nested enum of ProcessDock and cannot be used in a compile-time assertion within an anonymous namespace.
    inline constexpr std::size_t kProcessTableHeaderKeyCount =
        sizeof(kProcessTableHeaderKeys) / sizeof(kProcessTableHeaderKeys[0]);

    // ======== Task Manager Aligned Column Value
    // Formatting Helper ======== Unified convention:
    // - Memory column follows the Task Manager's 'kilobytes + thousand separator' format (e.g., 12,345 K);
    // - Count columns use integers with thousand separators.
    // - Display "-" when the field is not collected or the system does not provide it; never use 0 to fake a real value.

    // ProcessColumnUnavailableText: A unified placeholder for uncollected or unavailable fields.
    inline const QString kProcessColumnUnavailableText = QStringLiteral("-");

    // Common icon path constants (all from qrc resources with the /Icon prefix).
    inline constexpr const char* kIconProcessMain = ":/Icon/process_main.svg";

    inline constexpr const char* kIconRefresh = ":/Icon/process_refresh.svg";

    inline constexpr const char* kIconStart = ":/Icon/process_start.svg";

    inline constexpr const char* kIconPause = ":/Icon/process_pause.svg";

    inline constexpr const char* kIconThreadTab = ":/Icon/process_threads.svg";

    inline constexpr const char* kIconWindowPickerTarget = ":/Icon/window_picker_target.svg";

    struct ProcessIntegrityLevelPreset
    {
        DWORD rid;              // rid: The last RID of the S-1-16-* Mandatory Label.
        const char* nameText;   // nameText: Stable English name in the menu and result prompts.
        const char* detailText; // detailText: Chinese explanation for end users.
    };

    inline const ProcessIntegrityLevelPreset kProcessIntegrityLevelPresets[] =
    {
        { SECURITY_MANDATORY_UNTRUSTED_RID, "Untrusted", "不受信任完整性" },
        { SECURITY_MANDATORY_LOW_RID, "Low", "低完整性" },
        { SECURITY_MANDATORY_MEDIUM_RID, "Medium", "中完整性" },
        { SECURITY_MANDATORY_MEDIUM_PLUS_RID, "MediumPlus", "中高完整性" },
        { SECURITY_MANDATORY_HIGH_RID, "High", "高完整性" },
        { SECURITY_MANDATORY_SYSTEM_RID, "System", "系统完整性" },
        { SECURITY_MANDATORY_PROTECTED_PROCESS_RID, "ProtectedProcess", "受保护进程完整性" }
    };

    inline constexpr QSize kSideTabIconSize(22, 22);

    inline constexpr int kProcessTabMinHeightPx = 22;

    inline constexpr int kProcessNumericSortRole = Qt::UserRole + 200;

    inline constexpr int kProcessEfficiencyModeRole = Qt::UserRole + 201;

    inline constexpr int kProcessEfficiencyModeKnownRole = Qt::UserRole + 202;

    inline constexpr int kProcessTreeDepthRole = Qt::UserRole + 203;

    inline constexpr int kProcessRowKindRole = Qt::UserRole + 204;

    inline constexpr int kProcessExpandableRole = Qt::UserRole + 205;

    inline constexpr int kProcessExpandedRole = Qt::UserRole + 206;

    inline constexpr int kActivityMinimumIntervalMilliseconds = 50;

    inline constexpr int kActivityMaximumIntervalMilliseconds = 60000;

    // CSwitch sessions can remain resident, but the PID/TID × core matrix is settled at most once per second to suppress background allocation under high-frequency refresh.
    inline constexpr int kCpuCoreSnapshotMinimumIntervalMilliseconds = 1000;

    inline constexpr int kProcessTableMinimumIntervalMilliseconds = 500;

    inline constexpr int kProcessTableMaximumIntervalMilliseconds = 60000;

    inline constexpr std::size_t kActivityMaximumSampleCount = 1800;

    inline constexpr qsizetype kActivityIconCacheMaximumCount = 8192;

    // KernelProcessSnapshotEntry:
    // - Carries a process snapshot entry returned by R0 enumeration;
    // - Retains only fields required for UI comparison (PID, parent PID, flags, short process name).
    struct KernelProcessSnapshotEntry
    {
        std::uint32_t processId = 0;
        std::uint32_t parentProcessId = 0;
        std::uint32_t flags = 0;
        std::uint32_t sessionId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t r0Status = KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE;
        std::uint32_t sessionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint8_t protection = 0;
        std::uint8_t signatureLevel = 0;
        std::uint8_t sectionSignatureLevel = 0;
        std::uint32_t protectionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t signatureLevelSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t sectionSignatureLevelSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t objectTableSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t sectionObjectSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t imagePathSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t protectionOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t signatureLevelOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t sectionSignatureLevelOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t objectTableOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t sectionObjectOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint64_t objectTableAddress = 0;
        std::uint64_t sectionObjectAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint64_t creationTime100ns = 0;
        std::string imageName;
        std::string imagePath;
    };

    // Kernel-only records use a fixed creation time seed to avoid conflicts with R3 regular identities.
    inline constexpr std::uint64_t kKernelOnlyCreationTimeSeed = 0xFFFFFFFF00000000ULL;

    // TerminateMethodEntry purpose: Describes a 'process termination principle method'.
    //
    // This table is the **sole source**: the combination chain executes it in order, and the "Advanced Terminate Process" menu builds items from it one by one.
    // If split into two parts, the menu name and the actual execution method will eventually mismatch. Such errors won't
    // throw exceptions—the user thinks they clicked A, but B runs, and the failure reason is still attributed to A.
    struct TerminateMethodEntry
    {
        // All fourteen methods in the table are in user mode; only the items below the menu separator are in R0. Do not categorize
        // by interface; use the comments below to segment the table. Keep the original order grouped by 'who is asked to terminate',
        // because methods of the same class often fail for the same reason (e.g., the two job object methods fail together when the
        // target is not in any Job). This knowledge is needed by those modifying this table, but not by those using the menu.
        const char* methodName = nullptr;
        std::function<bool(std::uint32_t, std::string*)> invokeMethod;
    };

    // BitmaskFlagDefinition:
    // - Uniformly describe 'bitmask definitions that can be checked in checkboxes'.
    // - nameText: display name;
    // - value: the mask value corresponding to this bit flag.
    // - descriptionText: tooltip text to help users understand the semantics.
    struct BitmaskFlagDefinition
    {
        const char* nameText = "";            // Flag name (e.g., CREATE_SUSPENDED).
        std::uint32_t value = 0;              // Flag bitmask (DWORD).
        const char* descriptionText = "";     // Description text for the flag's purpose.
    };

    // CreateProcess.dwCreationFlags: The complete set of common and combinable bit flags.
    inline const std::vector<BitmaskFlagDefinition> kCreateProcessFlagDefinitions{
        { "DEBUG_PROCESS", 0x00000001U, "调试子进程和其后代进程。" },
        { "DEBUG_ONLY_THIS_PROCESS", 0x00000002U, "仅调试当前创建的子进程。" },
        { "CREATE_SUSPENDED", 0x00000004U, "主线程创建后先挂起。" },
        { "DETACHED_PROCESS", 0x00000008U, "控制台进程脱离父控制台。" },
        { "CREATE_NEW_CONSOLE", 0x00000010U, "为新进程分配新控制台窗口。" },
        { "NORMAL_PRIORITY_CLASS", 0x00000020U, "普通优先级类。" },
        { "IDLE_PRIORITY_CLASS", 0x00000040U, "空闲优先级类。" },
        { "HIGH_PRIORITY_CLASS", 0x00000080U, "高优先级类。" },
        { "REALTIME_PRIORITY_CLASS", 0x00000100U, "实时优先级类（高风险）。" },
        { "CREATE_NEW_PROCESS_GROUP", 0x00000200U, "创建新的进程组。" },
        { "CREATE_UNICODE_ENVIRONMENT", 0x00000400U, "环境块按 Unicode 传递。" },
        { "CREATE_SEPARATE_WOW_VDM", 0x00000800U, "16 位应用使用独立 WOW VDM。" },
        { "CREATE_SHARED_WOW_VDM", 0x00001000U, "16 位应用共享 WOW VDM。" },
        { "CREATE_FORCEDOS", 0x00002000U, "强制 DOS 兼容模式（历史选项）。" },
        { "BELOW_NORMAL_PRIORITY_CLASS", 0x00004000U, "低于普通优先级类。" },
        { "ABOVE_NORMAL_PRIORITY_CLASS", 0x00008000U, "高于普通优先级类。" },
        { "INHERIT_PARENT_AFFINITY", 0x00010000U, "继承父进程 CPU 亲和性。" },
        { "CREATE_PROTECTED_PROCESS", 0x00040000U, "创建受保护进程（受系统限制）。" },
        { "EXTENDED_STARTUPINFO_PRESENT", 0x00080000U, "启用 STARTUPINFOEX 扩展结构。" },
        { "PROCESS_MODE_BACKGROUND_BEGIN", 0x00100000U, "进入后台模式（I/O/CPU 降优先级）。" },
        { "PROCESS_MODE_BACKGROUND_END", 0x00200000U, "退出后台模式。" },
        { "CREATE_SECURE_PROCESS", 0x00400000U, "创建安全进程（受系统策略限制）。" },
        { "CREATE_BREAKAWAY_FROM_JOB", 0x01000000U, "允许脱离 Job 对象。" },
        { "CREATE_PRESERVE_CODE_AUTHZ_LEVEL", 0x02000000U, "保持代码授权级别。" },
        { "CREATE_DEFAULT_ERROR_MODE", 0x04000000U, "使用默认错误模式。" },
        { "CREATE_NO_WINDOW", 0x08000000U, "控制台进程不创建窗口。" },
        { "PROFILE_USER", 0x10000000U, "启用用户模式性能统计。" },
        { "PROFILE_KERNEL", 0x20000000U, "启用内核模式性能统计。" },
        { "PROFILE_SERVER", 0x40000000U, "启用服务器性能统计。" },
        { "CREATE_IGNORE_SYSTEM_DEFAULT", 0x80000000U, "忽略系统默认设置（较少使用）。" }
    };

    // Full set of bit flags for STARTUPINFO.dwFlags.
    inline const std::vector<BitmaskFlagDefinition> kStartupInfoFlagDefinitions{
        { "STARTF_USESHOWWINDOW", 0x00000001U, "启用 wShowWindow 字段。" },
        { "STARTF_USESIZE", 0x00000002U, "启用 dwXSize/dwYSize 字段。" },
        { "STARTF_USEPOSITION", 0x00000004U, "启用 dwX/dwY 字段。" },
        { "STARTF_USECOUNTCHARS", 0x00000008U, "启用控制台字符网格大小字段。" },
        { "STARTF_USEFILLATTRIBUTE", 0x00000010U, "启用 dwFillAttribute 字段。" },
        { "STARTF_RUNFULLSCREEN", 0x00000020U, "全屏模式启动（主要针对旧控制台）。" },
        { "STARTF_FORCEONFEEDBACK", 0x00000040U, "强制显示忙碌光标反馈。" },
        { "STARTF_FORCEOFFFEEDBACK", 0x00000080U, "关闭启动忙碌光标反馈。" },
        { "STARTF_USESTDHANDLES", 0x00000100U, "启用标准输入/输出/错误句柄字段。" },
        { "STARTF_USEHOTKEY", 0x00000200U, "启用热键字段（hStdInput 解释为 hotkey）。" },
        { "STARTF_TITLEISLINKNAME", 0x00000800U, "标题解释为 Shell 链接名。" },
        { "STARTF_TITLEISAPPID", 0x00001000U, "标题解释为 AppUserModelID。" },
        { "STARTF_PREVENTPINNING", 0x00002000U, "阻止任务栏固定（需 AppID）。" },
        { "STARTF_UNTRUSTEDSOURCE", 0x00008000U, "标记命令来源不可信。" },
        { "STARTF_HOLOGRAPHIC", 0x00040000U, "全息场景启动标记（特定平台）。" }
    };

    // Complete set of STARTUPINFO.dwFillAttribute console color/style flags.
    inline const std::vector<BitmaskFlagDefinition> kConsoleFillAttributeDefinitions{
        { "FOREGROUND_BLUE", 0x0001U, "前景色：蓝。" },
        { "FOREGROUND_GREEN", 0x0002U, "前景色：绿。" },
        { "FOREGROUND_RED", 0x0004U, "前景色：红。" },
        { "FOREGROUND_INTENSITY", 0x0008U, "前景色高亮。" },
        { "BACKGROUND_BLUE", 0x0010U, "背景色：蓝。" },
        { "BACKGROUND_GREEN", 0x0020U, "背景色：绿。" },
        { "BACKGROUND_RED", 0x0040U, "背景色：红。" },
        { "BACKGROUND_INTENSITY", 0x0080U, "背景色高亮。" },
        { "COMMON_LVB_LEADING_BYTE", 0x0100U, "双字节字符前导字节标记。" },
        { "COMMON_LVB_TRAILING_BYTE", 0x0200U, "双字节字符后继字节标记。" },
        { "COMMON_LVB_GRID_HORIZONTAL", 0x0400U, "水平网格线。" },
        { "COMMON_LVB_GRID_LVERTICAL", 0x0800U, "左垂直网格线。" },
        { "COMMON_LVB_GRID_RVERTICAL", 0x1000U, "右垂直网格线。" },
        { "COMMON_LVB_REVERSE_VIDEO", 0x4000U, "反色显示。" },
        { "COMMON_LVB_UNDERSCORE", 0x8000U, "下划线显示。" }
    };

    // Complete set of common Token DesiredAccess bit flags (OpenProcessToken / DuplicateTokenEx paths).
    inline const std::vector<BitmaskFlagDefinition> kTokenDesiredAccessDefinitions{
        { "TOKEN_ASSIGN_PRIMARY", 0x00000001U, "可把令牌分配给新进程主令牌。" },
        { "TOKEN_DUPLICATE", 0x00000002U, "可复制令牌。" },
        { "TOKEN_IMPERSONATE", 0x00000004U, "可模拟令牌。" },
        { "TOKEN_QUERY", 0x00000008U, "可查询令牌信息。" },
        { "TOKEN_QUERY_SOURCE", 0x00000010U, "可查询令牌来源。" },
        { "TOKEN_ADJUST_PRIVILEGES", 0x00000020U, "可调整令牌特权。" },
        { "TOKEN_ADJUST_GROUPS", 0x00000040U, "可调整令牌组。" },
        { "TOKEN_ADJUST_DEFAULT", 0x00000080U, "可调整默认 DACL/Owner 等。" },
        { "TOKEN_ADJUST_SESSIONID", 0x00000100U, "可调整会话 ID。" },
        { "DELETE", 0x00010000U, "标准删除权限。" },
        { "READ_CONTROL", 0x00020000U, "标准读取安全描述符权限。" },
        { "WRITE_DAC", 0x00040000U, "标准写 DACL 权限。" },
        { "WRITE_OWNER", 0x00080000U, "标准写 Owner 权限。" },
        { "ACCESS_SYSTEM_SECURITY", 0x01000000U, "访问 SACL 权限（高权限）。" },
        { "MAXIMUM_ALLOWED", 0x02000000U, "请求对象允许的最大权限。" },
        { "GENERIC_ALL", 0x10000000U, "通用全部权限映射。" },
        { "GENERIC_EXECUTE", 0x20000000U, "通用执行权限映射。" },
        { "GENERIC_WRITE", 0x40000000U, "通用写权限映射。" },
        { "GENERIC_READ", 0x80000000U, "通用读权限映射。" }
    };

    std::uint64_t hvmProcessEntryPointAddress(const std::uint32_t processId);

    std::uint64_t hvmProcessRunningThreadRip(const std::uint32_t processId);

    BOOL CALLBACK enumHvmInjectWakeProc(HWND windowHandle, LPARAM parameter);

    std::size_t hvmProcessWakeMessageLoops(const unsigned long processId);

    unsigned long long hvmInjectExecutionCount(const unsigned long processId);

    unsigned long long hvmInjectWaitForExecution(
        const unsigned long processId,
        const unsigned long long timeoutMilliseconds);

    std::chrono::milliseconds affinityRestoreRetryDelay(
        const std::uint32_t consecutiveFailureCount);

    QString processContextText(const char* const key, const QString& sourceText);

    QString processContextText(const QString& key, const QString& sourceText);

    QString processInjectionSurfaceText(const ks::process::ProcessRecord& processRecord);

    QString translatedProcessHeader(const int section, const QString& sourceText);

    QString processGroupedNumberText(const std::uint64_t value);

    QString processGroupedSignedNumberText(const std::int64_t value);

    QString processKilobyteText(const std::uint64_t bytes);

    QString processSignedKilobyteText(const std::int64_t deltaBytes);

    QString processMegabyteText(const std::uint64_t bytes);

    QString processCpuTimeText(const std::uint64_t cpuTime100ns);

    QString processFeatureStateText(const ks::process::ProcessFeatureState featureState);

    QString processDpiAwarenessText(const ks::process::ProcessDpiAwarenessLevel awarenessLevel);

    double processFeatureStateSortValue(const ks::process::ProcessFeatureState featureState);

    std::string formatProcessWin32Error(const char* stepText, const DWORD errorCode);

    bool acquireProcessActionIdentityHold(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        HANDLE* const processHandleOut,
        std::string* const detailText);

    bool enableProcessContextPrivilege(const wchar_t* privilegeName);

    bool allocateMandatoryIntegritySid(
        const DWORD integrityRid,
        PSID* sidOut,
        std::string* detailText);

    QString processIntegrityNameFromRid(const DWORD integrityRid);

    bool queryProcessIntegrityRid(
        const DWORD pid,
        DWORD* ridOut,
        std::string* detailText);

    bool setProcessIntegrityLevelByPid(
        const DWORD pid,
        const DWORD integrityRid,
        std::string* detailText);

    double clampPercentValue(const double percentValue);

    double totalPhysicalMemoryMB();

    QString processActivityMetricText(const ProcessDock::ProcessActivityMetric metric);

    QColor processActivityMetricColor(const ProcessDock::ProcessActivityMetric metric);

    QString processActivityMetricUnit(const ProcessDock::ProcessActivityMetric metric);

    QString formatActivityElapsedText(const std::uint64_t elapsedMs);

    QPoint activityMousePosition(const QMouseEvent* eventPointer);

    QColor themeColorFromText(const QString& colorText, const QColor& fallbackColor);

    std::uint64_t steadyNow100ns();

    ks::process::ProcessEnumStrategy toStrategy(const int strategyIndex);

    const char* strategyToText(const ks::process::ProcessEnumStrategy strategy);

    QString processDockIoMessageText(const QString& rawMessageText);

    std::string processDockIoMessageStdString(const std::string& rawMessageText);

    bool isProcessR0ExtensionVisible(const ks::process::ProcessRecord& processRecord);

    bool terminateProcessByR0Driver(
        const std::uint32_t targetPid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const detailTextOut);

    bool suspendProcessByR0Driver(const std::uint32_t targetPid, std::string* const detailTextOut);

    bool resumeProcessByR0Driver(const std::uint32_t targetPid, std::string* const detailTextOut);

    bool setPplProtectionLevelByR0Driver(
        const std::uint32_t targetPid,
        const std::uint8_t protectionLevel,
        std::string* const detailTextOut);

    bool shouldFallbackProcessIntegrityToR3(
        const ksword::ark::IoResult& io,
        const bool unsupported);

    bool setProcessIntegrityLevelByR0ThenR3(
        const DWORD pid,
        const DWORD integrityRid,
        std::string* const detailText);

    bool setProcessVisibilityByR0Driver(
        const std::uint32_t targetPid,
        const unsigned long action,
        const unsigned long flags,
        std::string* const detailTextOut);

    bool setProcessSpecialFlagsByR0Driver(
        const std::uint32_t targetPid,
        const unsigned long action,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const detailTextOut);

    bool dkomProcessByR0Driver(
        const std::uint32_t targetPid,
        const unsigned long action,
        std::string* const detailTextOut);

    std::uint64_t r0ActionExpectedCreationTime(const ks::process::ProcessRecord& processRecord);

    QString processFieldSourceText(const std::uint32_t sourceValue);

    QString dynDataFieldSourceText(const std::uint32_t sourceValue);

    bool dynDataOffsetPresent(const std::uint32_t flags, const std::uint32_t offset);

    QString dynDataOffsetText(const std::uint32_t offset);

    QString dynDataStatusFlagText(const std::uint32_t statusFlags);

    std::string activeProcessLinksDynDataDiagnostic(const ksword::ark::DriverClient& driverClient);

    QString processR0StatusText(const std::uint32_t statusValue);

    QString byteHexText(const std::uint8_t byteValue);

    bool resolvePplSignatureLevelsForUi(
        const std::uint8_t protectionLevel,
        std::uint8_t* const signatureLevelOut,
        std::uint8_t* const sectionSignatureLevelOut);

    QString pplMutationCapabilityText(const ks::process::ProcessRecord& processRecord);

    QString pointerAvailabilityText(
        const bool available,
        const std::uint64_t addressValue,
        const std::uint32_t sourceValue);

    bool enumerateProcessesByR0Driver(
        std::vector<KernelProcessSnapshotEntry>* const processListOut,
        std::string* const detailTextOut);

    void mergeKernelProcessExtension(
        ks::process::ProcessRecord& processRecord,
        const KernelProcessSnapshotEntry& kernelProcess);

    bool enrichProcessRecordWithR0ExtensionByPid(
        ks::process::ProcessRecord& processRecord,
        std::string* const detailTextOut);

    const std::vector<TerminateMethodEntry>& terminateMethodTable();

    bool isProcessPresentBySnapshot(const std::uint32_t targetPid, bool* const queryOkOut);

    bool waitForProcessExitAfterSuccessfulTerminate(
        const std::uint32_t targetPid,
        std::string* const detailTextOut);

    QColor usageRatioToHighlightColor(double usageRatio);

    bool hasDetailWindowSignificantChange(
        const ks::process::ProcessRecord& oldRecord,
        const ks::process::ProcessRecord& newRecord);

    QString buildBlueButtonStyle(const bool iconOnlyButton);

    QString buildBlueComboBoxStyle();

    QString buildBlueComboBoxPopupViewStyle();

    void applyBlueComboBoxRuntimeStyle(QComboBox* comboBoxPointer);

    QString buildBlueLineEditStyle();

    void applyTransparentContainerStyle(QWidget* widgetPointer);

    QStringList tokenPrivilegeNames();

    double processActivitySampleMetricValue(
        const ProcessDock::ProcessActivitySample& sample,
        const ProcessDock::ProcessActivityMetric metric,
        const std::vector<std::string>& selectionKeys);

    // ScopedProcessActionHandle: ensures identity-preserved handles are closed on all return paths during batch operations.
    class ScopedProcessActionHandle final
    {
    public:
        explicit ScopedProcessActionHandle(HANDLE handleValue) : handle_(handleValue) {}
        ~ScopedProcessActionHandle()
        {
            if (handle_ != nullptr)
            {
                ::CloseHandle(handle_);
            }
        }
        ScopedProcessActionHandle(const ScopedProcessActionHandle&) = delete;
        ScopedProcessActionHandle& operator=(const ScopedProcessActionHandle&) = delete;
        bool valid() const { return handle_ != nullptr; }
    private:
        HANDLE handle_ = nullptr;
    };

    class ProcessTableSortProxy final : public QSortFilterProxyModel
    {
    public:
        // Constructor purpose:
        // - initialize the dedicated sort proxy for the process list.
        // - Dynamic sorting is disabled by default to prevent sorting jitter triggered by row-by-row insertion on every setRows call.
        // Parameter parent: Qt parent object.
        // Returns: Nothing.
        explicit ProcessTableSortProxy(QObject* parent = nullptr)
            : QSortFilterProxyModel(parent)
        {
            setDynamicSortFilter(false);
        }

        // setPreserveSourceOrder:
        // - When displaying as a tree, have the proxy sort by source model row index to preserve the parent-child order generated by buildDisplayOrder;
        // - Disable this switch in list/history snapshot modes; continue using numeric sort keys.
        // Parameter preserveSourceOrder: true = preserve source order; false = sort by column.
        // Returns: Nothing.
        void setPreserveSourceOrder(const bool preserveSourceOrder)
        {
            preserveSourceOrder_ = preserveSourceOrder;
        }

        // setHeaderTexts:
        // - Receive the dynamic headers calculated by ProcessDock based on currently visible rows;
        // - Refresh only the horizontal header to avoid resetting the entire table when text like 'Total CPU' changes.
        // - Returns: Nothing.
        void setHeaderTexts(QStringList headerTexts)
        {
            headerTexts_ = std::move(headerTexts);
            if (!headerTexts_.isEmpty())
            {
                emit headerDataChanged(Qt::Horizontal, 0, headerTexts_.size() - 1);
            }
        }

        // headerData:
        // - Return dynamic header text for horizontal DisplayRole.
        // - Other role/orientation combinations retain the default behavior of QSortFilterProxyModel.
        QVariant headerData(const int section, const Qt::Orientation orientation, const int role) const override
        {
            if (orientation == Qt::Horizontal &&
                role == Qt::DisplayRole &&
                section >= 0 &&
                section < headerTexts_.size())
            {
                return translatedProcessHeader(section, headerTexts_.at(section));
            }
            return QSortFilterProxyModel::headerData(section, orientation, role);
        }

    protected:
        // lessThan:
        // - Prioritizes reading the original numeric sort key from ProcessNumericSortRole;
        // - Falls back to localized comparison of display text when numeric values are equal or the column lacks a numeric key;
        // - Returns true if left should be sorted before right.
        bool lessThan(const QModelIndex& leftIndex, const QModelIndex& rightIndex) const override
        {
            if (!leftIndex.isValid() || !rightIndex.isValid())
            {
                return QSortFilterProxyModel::lessThan(leftIndex, rightIndex);
            }

            if (preserveSourceOrder_)
            {
                return leftIndex.row() < rightIndex.row();
            }

            bool leftOk = false;
            bool rightOk = false;
            const double kLeftValue = sourceModel()->data(leftIndex, kProcessNumericSortRole).toDouble(&leftOk);
            const double kRightValue = sourceModel()->data(rightIndex, kProcessNumericSortRole).toDouble(&rightOk);
            if (leftOk && rightOk && kLeftValue != kRightValue)
            {
                return kLeftValue < kRightValue;
            }
            if (leftOk && rightOk)
            {
                return sourceModel()
                    ->data(leftIndex, Qt::DisplayRole)
                    .toString()
                    .localeAwareCompare(sourceModel()->data(rightIndex, Qt::DisplayRole).toString()) < 0;
            }
            return QSortFilterProxyModel::lessThan(leftIndex, rightIndex);
        }

    private:
        QStringList headerTexts_; // m_headerTexts: Current snapshot of horizontal header text for the process table.
        bool preserveSourceOrder_ = false; // m_preserveSourceOrder: Return items in source model order when in tree view mode.
    };

    // ProcessWindowPickerDragButton：
    // - Purpose: Reuse the input model for the window tab's 'crosshair drag pick' feature.
    // - Drag the button to any window and release to callback the global screen coordinates to the host;
    // - Responsible solely for input capture; does not directly read HWND/PID to avoid burdening UI controls with business logic.
    class ProcessWindowPickerDragButton final : public QPushButton
    {
    public:
        using ReleaseCallback = std::function<void(const QPoint&)>;

        // Constructor:
        // - parent: Qt parent control;
        // - Processing: Enable mouse tracking to allow continuous distance calculation during drag operations.
        // - Returns: Nothing.
        explicit ProcessWindowPickerDragButton(QWidget* parent = nullptr)
            : QPushButton(parent)
        {
            setMouseTracking(true);
        }

        // setReleaseCallback：
        // - callback: A function that receives global coordinates when the mouse is released.
        // - Processing: Save to member variable for mouseReleaseEvent to call.
        // - Returns: Nothing.
        void setReleaseCallback(ReleaseCallback callback)
        {
            releaseCallback_ = std::move(callback);
        }

    protected:
        // mousePressEvent：
        // - Input: Qt mouse press event;
        // - Processing: Record the left-click start point, capture the mouse, and switch the cursor to a crosshair.
        // - Returns: Nothing.
        void mousePressEvent(QMouseEvent* eventPointer) override
        {
            if (eventPointer != nullptr && eventPointer->button() == Qt::LeftButton)
            {
                dragTracking_ = true;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
                pressGlobalPos_ = eventPointer->globalPosition().toPoint();
#else
                m_pressGlobalPos = eventPointer->globalPos();
#endif
                hasReachedDragThreshold_ = false;
                grabMouse(QCursor(Qt::CrossCursor));
            }
            QPushButton::mousePressEvent(eventPointer);
        }

        // mouseMoveEvent：
        // - Input: Qt mouse move event;
        // - Processing: Allow release trigger only after exceeding the system drag threshold to avoid accidental capture of ordinary clicks.
        // - Returns: Nothing.
        void mouseMoveEvent(QMouseEvent* eventPointer) override
        {
            if (dragTracking_ && eventPointer != nullptr)
            {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
                const QPoint kCurrentGlobalPos = eventPointer->globalPosition().toPoint();
#else
                const QPoint currentGlobalPos = eventPointer->globalPos();
#endif
                const int kMoveDistance = (kCurrentGlobalPos - pressGlobalPos_).manhattanLength();
                if (kMoveDistance >= QApplication::startDragDistance())
                {
                    hasReachedDragThreshold_ = true;
                }
            }
            QPushButton::mouseMoveEvent(eventPointer);
        }

        // mouseReleaseEvent：
        // - Input: Qt mouse release event;
        // - Processing: Release mouse grab and callback the release coordinates if the drag is valid.
        // - Returns: Nothing.
        void mouseReleaseEvent(QMouseEvent* eventPointer) override
        {
            const bool kShouldDispatch =
                dragTracking_ &&
                hasReachedDragThreshold_ &&
                eventPointer != nullptr &&
                eventPointer->button() == Qt::LeftButton;

            if (dragTracking_)
            {
                releaseMouse();
                dragTracking_ = false;
            }
            hasReachedDragThreshold_ = false;

            QPoint releaseGlobalPos;
            if (eventPointer != nullptr)
            {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
                releaseGlobalPos = eventPointer->globalPosition().toPoint();
#else
                releaseGlobalPos = eventPointer->globalPos();
#endif
            }

            QPushButton::mouseReleaseEvent(eventPointer);

            if (kShouldDispatch && releaseCallback_)
            {
                releaseCallback_(releaseGlobalPos);
            }
        }

    private:
        bool dragTracking_ = false;             // m_dragTracking: Whether currently in the crosshair drag chain.
        bool hasReachedDragThreshold_ = false;  // m_hasReachedDragThreshold: Whether the system drag threshold has been reached.
        QPoint pressGlobalPos_;                 // m_pressGlobalPos: Global coordinates when the left mouse button is pressed.
        ReleaseCallback releaseCallback_;       // m_releaseCallback: Notifies the host to handle PID filtering after release.
    };

    // ProcessRowHighlightDelegate:
    // - Takes over default drawing for each cell in the process table.
    // - Preserves the original background color for new/exit/kernel-difference rows.
    // - Change mouse hover and selection states from 'full-row fill' to 'full-row stroke';
    // - Continue rendering efficiency-mode leaf icons to the right of the 'Process Name' column without adding new table columns.
    class ProcessRowHighlightDelegate final : public QStyledItemDelegate
    {
    public:
        // Constructor:
        // - tableView: The process table view being rendered by the delegate;
        // - Processing: Enable viewport mouse tracking and record the current hovered row;
        // - Returns: Nothing.
        explicit ProcessRowHighlightDelegate(
            QTableView* tableView,
            const int cpuCoreColumn)
            : QStyledItemDelegate(tableView)
            , tableView_(tableView)
            , cpuCoreColumn_(cpuCoreColumn)
        {
            if (tableView_ != nullptr && tableView_->viewport() != nullptr)
            {
                tableView_->setMouseTracking(true);
                tableView_->viewport()->setMouseTracking(true);
                tableView_->viewport()->installEventFilter(this);
            }
        }

        // eventFilter：
        // - Input: Mouse move/leave events from the process table viewport.
        // - Processing: normalize the cell under the mouse to the row start index and trigger a table repaint.
        // - Return: false to avoid intercepting Qt's native table interactions.
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (tableView_ != nullptr &&
                watched == tableView_->viewport() &&
                event != nullptr)
            {
                if (event->type() == QEvent::MouseMove)
                {
                    const QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
                    updateHoveredRowIndex(tableView_->indexAt(activityMousePosition(mouseEvent)));
                }
                else if (event->type() == QEvent::Leave)
                {
                    updateHoveredRowIndex(QModelIndex());
                }
            }
            return QStyledItemDelegate::eventFilter(watched, event);
        }

        // paint：
        // - Input: Qt-provided painter object, cell style, and model index;
        // - Processing: Draw content after clearing default selection/hover fill, then overlay row-level borders.
        // - Returns: Nothing.
        void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            QStyleOptionViewItem itemOption(option);
            const bool kRowSelected = (option.state & QStyle::State_Selected) != 0;
            const bool kRowHovered = isHoveredRow(index);

            // Default styles fill the entire row with selected/hover colors, overwriting the 'Exit Process' gray row;
            // Here, only cancel the interaction state fill, preserving item background, foreground color, and icon rendering.
            itemOption.state &= ~QStyle::State_Selected;
            itemOption.state &= ~QStyle::State_MouseOver;
            itemOption.state &= ~QStyle::State_HasFocus;

            const bool kCustomNameColumn =
                painter != nullptr &&
                index.isValid() &&
                index.column() == 0 &&
                index.data(kProcessTreeDepthRole).isValid();
            const bool kDrawEfficiencyLeaf =
                index.column() == 0 &&
                index.data(kProcessEfficiencyModeRole).toBool();
            const bool kCustomCpuCapacityCell =
                painter != nullptr &&
                index.column() == cpuCoreColumn_ &&
                ks::ui::hasProcessCpuCapacityCellData(index);
            if (kCustomNameColumn)
            {
                drawProcessNameCell(painter, itemOption, index, kDrawEfficiencyLeaf);
            }
            else if (kCustomCpuCapacityCell)
            {
                // CPU capacity cells require model background, foreground colors, and fonts; initialize style options first, then pass to the dedicated painter.
                QStyleOptionViewItem cpuCellOption(itemOption);
                initStyleOption(&cpuCellOption, index);
                cpuCellOption.state = itemOption.state;
                ks::ui::paintProcessCpuCapacityCell(
                    painter,
                    cpuCellOption,
                    index);
            }
            else
            {
                if (kDrawEfficiencyLeaf)
                {
                    itemOption.rect.adjust(0, 0, -22, 0);
                }
                QStyledItemDelegate::paint(painter, itemOption, index);
            }

            if (painter == nullptr)
            {
                return;
            }

            if (kDrawEfficiencyLeaf)
            {
                painter->save();
                painter->setRenderHint(QPainter::Antialiasing, true);
                const int kIconSize = std::min(16, std::max(10, option.rect.height() - 6));
                const QRect kLeafRect(
                    option.rect.right() - kIconSize - 5,
                    option.rect.center().y() - kIconSize / 2,
                    kIconSize,
                    kIconSize);
                const QColor kLeafColor = ksword_theme::successColor();
                QPainterPath leafPath;
                leafPath.moveTo(kLeafRect.left() + kLeafRect.width() * 0.18, kLeafRect.center().y());
                leafPath.cubicTo(
                    kLeafRect.left() + kLeafRect.width() * 0.32,
                    kLeafRect.top() + kLeafRect.height() * 0.08,
                    kLeafRect.right() - kLeafRect.width() * 0.10,
                    kLeafRect.top() + kLeafRect.height() * 0.06,
                    kLeafRect.right() - kLeafRect.width() * 0.08,
                    kLeafRect.center().y());
                leafPath.cubicTo(
                    kLeafRect.right() - kLeafRect.width() * 0.10,
                    kLeafRect.bottom() - kLeafRect.height() * 0.08,
                    kLeafRect.left() + kLeafRect.width() * 0.30,
                    kLeafRect.bottom() - kLeafRect.height() * 0.05,
                    kLeafRect.left() + kLeafRect.width() * 0.18,
                    kLeafRect.center().y());
                painter->fillPath(leafPath, kLeafColor);
                painter->setPen(QPen(ksword_theme::withAlpha(ksword_theme::onAccentColor(), 210), 1.2));
                painter->drawLine(
                    QPointF(kLeafRect.left() + kLeafRect.width() * 0.28, kLeafRect.bottom() - kLeafRect.height() * 0.25),
                    QPointF(kLeafRect.right() - kLeafRect.width() * 0.20, kLeafRect.top() + kLeafRect.height() * 0.22));
                painter->restore();
            }

            if (kRowSelected || kRowHovered)
            {
                drawRowInteractionBorder(painter, option, index, kRowSelected);
            }
        }

        // helpEvent：
        // - Input: Qt tooltip event, table view, current cell geometry, and model index;
        // - Processing: When the mouse hits a small core-level box, display the group number, ID, and occupancy range of the corresponding logical CPU.
        // - Returns: true if the precise core tooltip was displayed; otherwise, delegates to the default ToolTipRole path.
        bool helpEvent(
            QHelpEvent* const event,
            QAbstractItemView* const view,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) override
        {
            if (event != nullptr &&
                view != nullptr &&
                index.column() == cpuCoreColumn_)
            {
                QStyleOptionViewItem cpuCellOption(option);
                initStyleOption(&cpuCellOption, index);
                const QString kCoreToolTip = ks::ui::processCpuCapacityToolTipText(
                    cpuCellOption,
                    index,
                    event->pos());
                if (!kCoreToolTip.isEmpty())
                {
                    QToolTip::showText(
                        event->globalPos(),
                        kCoreToolTip,
                        view->viewport());
                    return true;
                }
            }
            return QStyledItemDelegate::helpEvent(event, view, option, index);
        }

    private:
        // drawProcessNameCell：
        // - Input: Name column model index, drawing state, and whether to draw efficiency-mode leaves;
        // - Handling: Let Qt draw the background first, then manually draw content in the order of 'dashed border -> icon -> text';
        // - Returns: None. Shared presentation layer for both standard tree views and friendly views.
        void drawProcessNameCell(
            QPainter* painter,
            QStyleOptionViewItem itemOption,
            const QModelIndex& index,
            const bool drawEfficiencyLeaf) const
        {
            if (painter == nullptr || !index.isValid())
            {
                return;
            }

            QStyleOptionViewItem backgroundOption(itemOption);
            initStyleOption(&backgroundOption, index);
            backgroundOption.state = itemOption.state;
            backgroundOption.text.clear();
            backgroundOption.icon = QIcon();
            const QWidget* viewWidget = itemOption.widget;
            QStyle* viewStyle = viewWidget != nullptr ? viewWidget->style() : QApplication::style();
            if (viewStyle != nullptr)
            {
                viewStyle->drawControl(QStyle::CE_ItemViewItem, &backgroundOption, painter, viewWidget);
            }

            bool depthOk = false;
            const int kDepth = index.data(kProcessTreeDepthRole).toInt(&depthOk);
            const int kSafeDepth = depthOk ? std::max(0, kDepth) : 0;
            const int kRowKind = index.data(kProcessRowKindRole).toInt();
            const bool kExpandable = index.data(kProcessExpandableRole).toBool();
            const bool kExpanded = index.data(kProcessExpandedRole).toBool();

            QRect contentRect = itemOption.rect.adjusted(6, 0, -6, 0);
            if (drawEfficiencyLeaf)
            {
                contentRect.adjust(0, 0, -22, 0);
            }

            const int kLevelWidth = 18;
            const int kIconSize = std::min(18, std::max(12, itemOption.rect.height() - 6));
            const int kIconTextGap = 6;
            const int kTreeAreaWidth = kSafeDepth * kLevelWidth;
            const QColor kLineColor = ksword_theme::withAlpha(ksword_theme::borderStrongColor(), 165);

            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, true);
            QPen treePen(kLineColor, 1.0, Qt::DotLine, Qt::RoundCap);
            painter->setPen(treePen);

            const int kCenterY = contentRect.center().y();
            for (int level = 0; level < kSafeDepth; ++level)
            {
                const int kX = contentRect.left() + level * kLevelWidth + kLevelWidth / 2;
                painter->drawLine(
                    QPoint(kX, itemOption.rect.top() + 4),
                    QPoint(kX, itemOption.rect.bottom() - 4));
                if (level + 1 == kSafeDepth)
                {
                    painter->drawLine(
                        QPoint(kX, kCenterY),
                        QPoint(contentRect.left() + kTreeAreaWidth - 3, kCenterY));
                }
            }

            int cursorX = contentRect.left() + kTreeAreaWidth;
            if (kExpandable)
            {
                const QRect kMarkerRect(
                    cursorX,
                    kCenterY - 7,
                    14,
                    14);
                painter->setPen(QPen(ksword_theme::primaryBlueColor, 1.2));
                painter->setBrush(Qt::NoBrush);
                const QPointF kP1 = kExpanded
                    ? QPointF(kMarkerRect.left() + 3.5, kMarkerRect.top() + 5.0)
                    : QPointF(kMarkerRect.left() + 5.0, kMarkerRect.top() + 3.5);
                const QPointF kP2 = kExpanded
                    ? QPointF(kMarkerRect.center().x(), kMarkerRect.bottom() - 4.0)
                    : QPointF(kMarkerRect.right() - 4.0, kMarkerRect.center().y());
                const QPointF kP3 = kExpanded
                    ? QPointF(kMarkerRect.right() - 3.5, kMarkerRect.top() + 5.0)
                    : QPointF(kMarkerRect.left() + 5.0, kMarkerRect.bottom() - 3.5);
                QPainterPath markerPath;
                markerPath.moveTo(kP1);
                markerPath.lineTo(kP2);
                markerPath.lineTo(kP3);
                painter->drawPath(markerPath);
                cursorX += kMarkerRect.width() + 2;
            }

            const QIcon kIconValue = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
            if (!kIconValue.isNull())
            {
                const QRect kIconRect(
                    cursorX,
                    kCenterY - kIconSize / 2,
                    kIconSize,
                    kIconSize);
                kIconValue.paint(painter, kIconRect, Qt::AlignCenter, QIcon::Normal);
                cursorX += kIconSize + kIconTextGap;
            }
            else if (kRowKind != 1)
            {
                cursorX += kIconTextGap;
            }

            // Process names and cell values are data, not UI labels. Never
            // translate them through a global source-string table.
            const QString kTextValue = index.data(Qt::DisplayRole).toString();
            QRect textRect(
                cursorX,
                contentRect.top(),
                std::max(0, contentRect.right() - cursorX + 1),
                contentRect.height());
            QFont textFont = itemOption.font;
            if (index.data(Qt::FontRole).isValid())
            {
                textFont = qvariant_cast<QFont>(index.data(Qt::FontRole));
            }
            painter->setFont(textFont);
            const QVariant kForegroundData = index.data(Qt::ForegroundRole);
            if (kForegroundData.canConvert<QBrush>())
            {
                painter->setPen(qvariant_cast<QBrush>(kForegroundData).color());
            }
            else
            {
                painter->setPen(itemOption.palette.color(QPalette::Text));
            }
            painter->drawText(
                textRect,
                Qt::AlignLeft | Qt::AlignVCenter,
                itemOption.fontMetrics.elidedText(kTextValue, Qt::ElideRight, textRect.width()));
            painter->restore();
        }

        // sameModelRow：
        // - Input: Two persistent model indices;
        // - Processing: Compare only model/parent/row, not column.
        // - Returns: true indicates both indices point to the same logical row.
        static bool sameModelRow(
            const QPersistentModelIndex& leftIndex,
            const QPersistentModelIndex& rightIndex)
        {
            if (!leftIndex.isValid() || !rightIndex.isValid())
            {
                return !leftIndex.isValid() && !rightIndex.isValid();
            }
            return leftIndex.model() == rightIndex.model() &&
                leftIndex.parent() == rightIndex.parent() &&
                leftIndex.row() == rightIndex.row();
        }

        // updateHoveredRowIndex：
        // - Input: any column index clicked by the mouse; a null index indicates the mouse has left;
        // - Processing: normalize to column 0 before saving to ensure borders are drawn for all columns in the row.
        // - Returns: Nothing.
        void updateHoveredRowIndex(const QModelIndex& sourceIndex)
        {
            QPersistentModelIndex nextRowIndex;
            if (sourceIndex.isValid())
            {
                nextRowIndex = QPersistentModelIndex(sourceIndex.sibling(sourceIndex.row(), 0));
            }

            if (sameModelRow(hoveredRowIndex_, nextRowIndex))
            {
                return;
            }
            hoveredRowIndex_ = nextRowIndex;

            // Row borders span multiple columns; simply repainting the entire viewport avoids residual lines when column widths or order change.
            if (tableView_ != nullptr && tableView_->viewport() != nullptr)
            {
                tableView_->viewport()->update();
            }
        }

        // isHoveredRow：
        // - Input: The model index currently being rendered;
        // - Processing: Compare the hovered row with the recorded row by model/parent/row.
        // - Returns: true if the current cell belongs to the hovered row.
        bool isHoveredRow(const QModelIndex& index) const
        {
            if (!index.isValid() || !hoveredRowIndex_.isValid())
            {
                return false;
            }
            return index.model() == hoveredRowIndex_.model() &&
                index.parent() == hoveredRowIndex_.parent() &&
                index.row() == hoveredRowIndex_.row();
        }

        // drawRowInteractionBorder：
        // - Input: Current cell drawing context, style option, index, and selection state.
        // - Processing: Draw top and bottom borders for each visible cell; add left and right borders for the first and last visible columns.
        // - Returns: Nothing.
        void drawRowInteractionBorder(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index,
            const bool rowSelected) const
        {
            if (painter == nullptr || tableView_ == nullptr || !index.isValid())
            {
                return;
            }

            QHeaderView* headerView = tableView_->horizontalHeader();
            if (headerView == nullptr)
            {
                return;
            }

            int firstVisibleVisualIndex = std::numeric_limits<int>::max();
            int lastVisibleVisualIndex = std::numeric_limits<int>::min();
            const int kColumnCount = index.model() != nullptr
                ? index.model()->columnCount(index.parent())
                : 0;
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

            QColor borderColor = ksword_theme::primaryBlueColor;
            borderColor.setAlpha(rowSelected ? 245 : 165);
            const QRect kBorderRect = option.rect.adjusted(0, 1, -1, -2);
            if (!kBorderRect.isValid())
            {
                return;
            }

            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, false);
            painter->setBrush(Qt::NoBrush);
            painter->setPen(QPen(borderColor, rowSelected ? 3.0 : 1.4));
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

        QPointer<QTableView> tableView_;         // m_tableView: Proxied process table; not owned.
        int cpuCoreColumn_ = -1;                 // m_cpuCoreColumn: The only logical column allowed to parse per-core shared snapshots.
        QPersistentModelIndex hoveredRowIndex_; // m_hoveredRowIndex: Index of column 0 in the row currently under the mouse.
    };
}

template <typename Destination, typename Source>
void ProcessDock::copyProcessActivityDynamicFields(Destination& destination, const Source& source)
{
    // Two snapshot types share dynamic fields with the same name; copying them in one place prevents drift between sampling and replay field lists.
    destination.cpuPercent = source.cpuPercent;
    destination.cpuCorePercent = source.cpuCorePercent;
    destination.ramMB = source.ramMB;
    destination.workingSetMB = source.workingSetMB;
    destination.diskMBps = source.diskMBps;
    destination.netKBps = source.netKBps;
    destination.netRxKBps = source.netRxKBps;
    destination.netTxKBps = source.netTxKBps;
    destination.gpuPercent = source.gpuPercent;
    destination.threadCount = source.threadCount;
    destination.handleCount = source.handleCount;
    destination.suspendedThreadCount = source.suspendedThreadCount;
    destination.basePriority = source.basePriority;
    destination.processStateKnown = source.processStateKnown;
    destination.processSuspended = source.processSuspended;
    destination.efficiencyModeSupported = source.efficiencyModeSupported;
    destination.efficiencyModeEnabled = source.efficiencyModeEnabled;
    destination.rawCpuTime100ns = source.rawCpuTime100ns;
    destination.cycleTime = source.cycleTime;
    destination.rawWorkingSetBytes = source.rawWorkingSetBytes;
    destination.peakWorkingSetBytes = source.peakWorkingSetBytes;
    destination.privateWorkingSetBytes = source.privateWorkingSetBytes;
    destination.sharedWorkingSetBytes = source.sharedWorkingSetBytes;
    destination.commitSizeBytes = source.commitSizeBytes;
    destination.pagedPoolBytes = source.pagedPoolBytes;
    destination.nonPagedPoolBytes = source.nonPagedPoolBytes;
    destination.pageFaultCount = source.pageFaultCount;
    destination.workingSetDeltaBytes = source.workingSetDeltaBytes;
    destination.pageFaultDeltaCount = source.pageFaultDeltaCount;
    destination.cycleTimeKnown = source.cycleTimeKnown;
    destination.memoryDetailKnown = source.memoryDetailKnown;
    destination.privateWorkingSetKnown = source.privateWorkingSetKnown;
    destination.ioReadOperationCount = source.ioReadOperationCount;
    destination.ioWriteOperationCount = source.ioWriteOperationCount;
    destination.ioOtherOperationCount = source.ioOtherOperationCount;
    destination.ioReadTransferBytes = source.ioReadTransferBytes;
    destination.ioWriteTransferBytes = source.ioWriteTransferBytes;
    destination.ioOtherTransferBytes = source.ioOtherTransferBytes;
    destination.gdiObjectCount = source.gdiObjectCount;
    destination.userObjectCount = source.userObjectCount;
    destination.ioDetailKnown = source.ioDetailKnown;
    destination.guiResourceKnown = source.guiResourceKnown;
    destination.gpuDedicatedMemoryBytes = source.gpuDedicatedMemoryBytes;
    destination.gpuSharedMemoryBytes = source.gpuSharedMemoryBytes;
    destination.gpuEngineText = source.gpuEngineText;
    destination.gpuMemoryKnown = source.gpuMemoryKnown;
}
