#include "FeatureRegistry.h"

#include "driver/DriverFeature.h"
#include "file/FileFeature.h"
#include "hardware/HardwareFeature.h"
#include "handle/HandleFeature.h"
#include "kernel/KernelFeature.h"
#include "memory/MemoryFeature.h"
#include "misc/MiscFeature.h"
#include "monitor/MonitorFeature.h"
#include "network/NetworkFeature.h"
#include "privilege/PrivilegeFeature.h"
#include "process/ProcessFeature.h"
#include "registry/RegistryFeature.h"
#include "service/ServiceFeature.h"
#include "startup/StartupFeature.h"
#include "sys_tools/SysToolsFeature.h"
#include "window/WindowFeature.h"

namespace ksword::features {

std::vector<ksword::ui::ModuleDescriptor> getModuleDescriptors() {
    return {
        { 40001, L"进程", L"NtQuerySystemInformation 进程列表、友好视图/详细视图、多选、图标、拖动选择和进程右键菜单。", process::createProcessFeaturePage },
        { 40002, L"内存", L"仅保留通过 KswordARK R0 驱动执行的内存读取和写入。", memory::createMemoryFeaturePage },
        { 40010, L"注册表", L"WinAPI/R0 双模式注册表浏览与读写、创建、删除、重命名。", registry::createRegistryFeaturePage },
        { 40003, L"文件", L"Windows API 路径枚举和文件右键菜单；文件属性页已移除。", file::createFileFeaturePage },
        { 40004, L"驱动", L"驱动概览和对象信息。", driver::createDriverFeaturePage },
        { 40005, L"内核", L"保留 SSDT、Shadow SSDT、Hook、对象命名空间、回调等内核功能入口。", [](HWND parent, const RECT& bounds) -> HWND {
            return kernel::createKernelFeaturePage(parent, 40005, bounds);
        } },
        { 40006, L"监控", L"ETW 监控主页面，筛选器通过弹窗配置。", monitor::createMonitorFeaturePage },
        { 40007, L"硬件", L"设备、CPU/HWID 审计、性能监控、磁盘活动、USB 拓扑与系统总线。", hardware::createHardwareFeaturePage },
        { 40008, L"窗口", L"窗口管理、剪贴板查看、捕获保护、层级诊断与全局热键占用探测。", window::createWindowFeaturePage },
        { 40009, L"启动项", L"启动项管理。", startup::createStartupFeaturePage },
        { 40014, L"服务", L"SCM 服务与驱动服务枚举、启停暂停继续、启动类型修改与配置风险标注。", service::createServiceFeaturePage },
        { 40015, L"权限", L"当前进程令牌的身份、完整性级别、组与全部特权，可启用/禁用并标注越权类特权。", privilege::createPrivilegeFeaturePage },
        { 40018, L"系统工具", L"文件占用扫描、事件日志查看、右键菜单扩展禁用与恢复、系统时间与时区信息。", sys_tools::createSysToolsFeaturePage },
        { 40011, L"网络", L"连接管理、网络诊断、防火墙规则与 TCP/UDP/AFD/WFP/NDIS/NSI 网络栈审计。", network::createNetworkFeaturePage },
        { 40012, L"句柄", L"HandleTable/ObjectHeader/ObjectType 只读审计，复用 ArkDriverClient 句柄查询协议。", handle::createHandleFeaturePage },
        { 40013, L"杂项安全", L"Security / CI / VBS / Hyper-V 只读审计入口，显示 R3 证据与 R0 capability 状态。", misc::createMiscFeaturePage }
    };
}

} // namespace Ksword::Features
