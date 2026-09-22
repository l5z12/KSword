#include "HardwareFeature.h"

#include "HardwareHwidDispatchView.h"
#include "HardwareView.h"
#include "../hardware_stats/BusDeviceView.h"
#include "../hardware_stats/DiskActivityView.h"
#include "../hardware_stats/PerformanceView.h"
#include "../hardware_stats/UsbTopologyView.h"
#include "../kernel/KernelFeature.h"
#include "../../ui/WorkspaceHost.h"

#include <utility>
#include <vector>

namespace ksword::features::hardware {
namespace {

constexpr int kDeviceManagerTab = 61100;
constexpr int kCpuIntegrityTab = 61101;
constexpr int kCpuSnapshotTab = 61102;
constexpr int kHwidDispatchTab = 61103;
constexpr int kPerformanceTab = 61104;
constexpr int kDiskActivityTab = 61105;
constexpr int kUsbTopologyTab = 61106;
constexpr int kBusDeviceTab = 61107;
constexpr int kEmbeddedKernelPrimaryTabId = 51001;
constexpr int kEmbeddedKernelSecondaryTabId = 51002;

HWND createEmbeddedKernelPage(HWND host, const RECT& bounds, const int controlId, const kernel::KernelFeatureId featureId) {
    HWND page = kernel::createKernelSingleFeaturePage(host, controlId, bounds, featureId);
    if (page) {
        if (HWND primary = ::GetDlgItem(page, kEmbeddedKernelPrimaryTabId)) {
            ::ShowWindow(primary, SW_HIDE);
        }
        if (HWND secondary = ::GetDlgItem(page, kEmbeddedKernelSecondaryTabId)) {
            ::ShowWindow(secondary, SW_HIDE);
        }
    }
    return page;
}

} // namespace

HWND createHardwareFeaturePage(HWND parent, const RECT& bounds) {
    std::vector<ksword::ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ kDeviceManagerTab, L"设备/输入链审计", L"设备页首次打开时枚举当前设备树。",
        [](HWND host, const RECT& pageBounds) { return createHardwareDeviceManagerView(host, pageBounds); } });
    tabs.push_back({ kCpuIntegrityTab, L"CPU/IDT 完整性", L"按需加载 Kernel CPU/IDT 完整性页。",
        [](HWND host, const RECT& pageBounds) {
            return createEmbeddedKernelPage(host, pageBounds, 61112, kernel::KernelFeatureId::kKernelCpuIntegrity);
        } });
    tabs.push_back({ kCpuSnapshotTab, L"CPU 硬件快照", L"按需加载 CPU 硬件快照。",
        [](HWND host, const RECT& pageBounds) {
            return createEmbeddedKernelPage(host, pageBounds, 61113, kernel::KernelFeatureId::kCpuHardwareSnapshot);
        } });
    tabs.push_back({ kHwidDispatchTab, L"HWID Dispatch", L"按需加载 HWID Dispatch 审计与控制页。",
        [](HWND host, const RECT& pageBounds) { return createHardwareHwidDispatchView(host, pageBounds); } });
    tabs.push_back({ kPerformanceTab, L"性能监控", L"按需启动性能采样。",
        [](HWND host, const RECT& pageBounds) { return hardware_stats::createPerformanceView(host, pageBounds); } });
    tabs.push_back({ kDiskActivityTab, L"磁盘活动", L"按需启动磁盘活动采样。",
        [](HWND host, const RECT& pageBounds) { return hardware_stats::createDiskActivityView(host, pageBounds); } });
    tabs.push_back({ kUsbTopologyTab, L"USB 拓扑", L"按需枚举 USB 拓扑。",
        [](HWND host, const RECT& pageBounds) { return hardware_stats::createUsbTopologyView(host, pageBounds); } });
    tabs.push_back({ kBusDeviceTab, L"系统总线", L"按需枚举系统总线设备。",
        [](HWND host, const RECT& pageBounds) { return hardware_stats::createBusDeviceView(host, pageBounds); } });

    ksword::ui::WorkspaceOptions options{};
    options.tabControlId = 61110;
    options.initialTabId = kDeviceManagerTab;
    return ksword::ui::createWorkspaceHost(parent, bounds, std::move(tabs), std::move(options));
}

} // namespace Ksword::Features::Hardware
