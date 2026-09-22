#include "HardwareOtherDevicesPage.h"

// ============================================================
// HardwareOtherDevicesPage.cpp
// Purpose:
// 1) Display detailed lists of hardware devices other than CPU/memory/GPU in the inner sidebar tab of HardwareDock;
// 2) Use PowerShell/CIM to collect data on a background thread to avoid UI blocking.
// 3) Retain original PNP ID, driver version, interface, and status fields for troubleshooting scenarios.
// ============================================================

#include "../Theme.h"
#include "../ui/CodeEditorWidget.h"

#include <QDateTime>
#include <QHBoxLayout>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // runInventoryPowerShellTextSync:
    // - Synchronously execute the hardware inventory collection script;
    // - scriptText: PowerShell command text.
    // - timeoutMs is the wait timeout duration.
    // - Returns stdout text; on failure, returns a displayable diagnostic message.
    QString runInventoryPowerShellTextSync(const QString& scriptText, const int timeoutMs)
    {
        QProcess process;
        process.setProgram(QStringLiteral("powershell.exe"));
        process.setArguments({
            QStringLiteral("-NoProfile"),
            QStringLiteral("-ExecutionPolicy"),
            QStringLiteral("Bypass"),
            QStringLiteral("-Command"),
            scriptText
            });
        process.start();

        // waitStartedOk purpose: confirm the PowerShell process has started.
        const bool kWaitStartedOk = process.waitForStarted(1500);
        if (!kWaitStartedOk)
        {
            return QStringLiteral("PowerShell启动失败，无法采集其他硬件设备。");
        }

        // Purpose of waitFinishedOk: prevent long-blocking WMI Provider from freezing the UI refresh.
        const bool kWaitFinishedOk = process.waitForFinished(timeoutMs);
        if (!kWaitFinishedOk)
        {
            process.kill();
            process.waitForFinished(800);
            return QStringLiteral("PowerShell执行超时（%1 ms），其他硬件设备清单未完整生成。")
                .arg(timeoutMs);
        }

        const QString kStandardOutputText = QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
        const QString kStandardErrorText = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
        {
            return QStringLiteral("PowerShell执行失败。\nExitCode=%1\nError=%2")
                .arg(process.exitCode())
                .arg(kStandardErrorText.isEmpty() ? QStringLiteral("<空>") : kStandardErrorText);
        }
        return kStandardOutputText.isEmpty() ? QStringLiteral("<无输出>") : kStandardOutputText;
    }
}

HardwareOtherDevicesPage::HardwareOtherDevicesPage(QWidget* parent)
    : QWidget(parent)
{
    // Construction flow: build the UI first, then establish connections, and finally asynchronously fetch the initial device inventory.
    initializeUi();
    initializeConnections();
    refreshDeviceInventoryAsync(false);
}

void HardwareOtherDevicesPage::initializeUi()
{
    // The root layout remains lightweight; the outer HardwareDock handles sizing allocation.
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);

    QLabel* titleLabel = new QLabel(QStringLiteral("其他硬件设备"), this);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    headerLayout->addWidget(titleLabel, 0);

    statusLabel_ = new QLabel(QStringLiteral("正在采集设备清单..."), this);
    statusLabel_->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;").arg(ksword_theme::textSecondaryHex()));
    headerLayout->addWidget(statusLabel_, 1);

    refreshButton_ = new QPushButton(QStringLiteral("刷新"), this);
    refreshButton_->setToolTip(QStringLiteral("重新枚举主板、存储、外设、PNP、驱动等硬件信息"));
    headerLayout->addWidget(refreshButton_, 0);
    rootLayout_->addLayout(headerLayout, 0);

    inventoryEditor_ = new CodeEditorWidget(this);
    inventoryEditor_->setReadOnly(true);
    inventoryEditor_->setText(QStringLiteral("设备清单加载中，请稍候..."));
    rootLayout_->addWidget(inventoryEditor_, 1);
}

void HardwareOtherDevicesPage::initializeConnections()
{
    if (refreshButton_ == nullptr)
    {
        return;
    }

    // The refresh button triggers only asynchronous tasks to avoid blocking the main thread after user clicks.
    connect(
        refreshButton_,
        &QPushButton::clicked,
        this,
        [this]()
        {
            refreshDeviceInventoryAsync(true);
        });
}

void HardwareOtherDevicesPage::refreshDeviceInventoryAsync(const bool forceRefresh)
{
    bool expectedFlag = false;
    if (!refreshing_.compare_exchange_strong(expectedFlag, true))
    {
        if (forceRefresh && statusLabel_ != nullptr)
        {
            statusLabel_->setText(QStringLiteral("正在刷新，请等待当前采集完成。"));
        }
        return;
    }

    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(forceRefresh
            ? QStringLiteral("正在重新采集设备清单...")
            : QStringLiteral("正在采集设备清单..."));
    }
    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(false);
    }

    QPointer<HardwareOtherDevicesPage> safeThis(this);
    std::thread([safeThis]()
    {
        const QString kInventoryText = HardwareOtherDevicesPage::buildDeviceInventoryTextSnapshot();
        if (safeThis.isNull())
        {
            return;
        }

        const bool kInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, kInventoryText]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                if (safeThis->inventoryEditor_ != nullptr)
                {
                    safeThis->inventoryEditor_->setText(kInventoryText);
                }
                if (safeThis->statusLabel_ != nullptr)
                {
                    safeThis->statusLabel_->setText(
                        QStringLiteral("最近刷新：%1")
                        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))));
                }
                if (safeThis->refreshButton_ != nullptr)
                {
                    safeThis->refreshButton_->setEnabled(true);
                }
                safeThis->refreshing_.store(false);
            },
            Qt::QueuedConnection);

        if (!kInvokeOk && !safeThis.isNull())
        {
            safeThis->refreshing_.store(false);
        }
    }).detach();
}

QString HardwareOtherDevicesPage::buildDeviceInventoryTextSnapshot()
{
    const QString kScriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; "
        "function Format-Size([object]$bytes){ "
        "  if($null -eq $bytes){ return $null }; "
        "  $value=[double]$bytes; "
        "  if($value -ge 1TB){ return ('{0:N2} TB' -f ($value/1TB)) }; "
        "  if($value -ge 1GB){ return ('{0:N2} GB' -f ($value/1GB)) }; "
        "  if($value -ge 1MB){ return ('{0:N2} MB' -f ($value/1MB)) }; "
        "  return ([string]$bytes + ' B'); "
        "}; "
        "function Format-Speed([object]$bits){ "
        "  if($null -eq $bits){ return $null }; "
        "  $value=[double]$bits; "
        "  if($value -ge 1000000000){ return ('{0:N2} Gbps' -f ($value/1000000000)) }; "
        "  if($value -ge 1000000){ return ('{0:N2} Mbps' -f ($value/1000000)) }; "
        "  if($value -ge 1000){ return ('{0:N2} Kbps' -f ($value/1000)) }; "
        "  return ([string]$bits + ' bps'); "
        "}; "
        "function Write-Section([string]$title,[object]$rows){ "
        "  $text=\"`r`n========== $title ==========`r`n\"; "
        "  if($null -eq $rows){ return $text + '<未检测到>' + \"`r`n\" }; "
        "  $array=@($rows); "
        "  if($array.Count -le 0){ return $text + '<未检测到>' + \"`r`n\" }; "
        "  return $text + (($array | Format-List * | Out-String -Width 4096).Trim()) + \"`r`n\"; "
        "}; "
        "$text=''; "
        "$text += '采集时间: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + \"`r`n\"; "
        "$cs=Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,SystemType,PCSystemType,Domain,Workgroup,UserName,TotalPhysicalMemory,NumberOfProcessors,NumberOfLogicalProcessors; "
        "$board=Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version,SerialNumber,Tag; "
        "$bios=Get-CimInstance Win32_BIOS | Select-Object Manufacturer,Name,SMBIOSBIOSVersion,Version,ReleaseDate,SerialNumber,SMBIOSMajorVersion,SMBIOSMinorVersion; "
        "$enclosure=Get-CimInstance Win32_SystemEnclosure | Select-Object Manufacturer,Model,SerialNumber,SMBIOSAssetTag,ChassisTypes,LockPresent,SecurityStatus; "
        "$processor=Get-CimInstance Win32_Processor | Select-Object SocketDesignation,Name,Manufacturer,Caption,Description,ProcessorId,NumberOfCores,NumberOfEnabledCore,NumberOfLogicalProcessors,MaxClockSpeed,L2CacheSize,L3CacheSize,VirtualizationFirmwareEnabled,SecondLevelAddressTranslationExtensions,VMMonitorModeExtensions; "
        "$memoryArray=Get-CimInstance Win32_PhysicalMemoryArray | ForEach-Object { [pscustomobject]@{Location=$_.Location;Use=$_.Use;MemoryDevices=$_.MemoryDevices;MaxCapacity=Format-Size ([uint64]$_.MaxCapacity * 1KB);MaxCapacityEx=Format-Size $_.MaxCapacityEx} }; "
        "$memoryDevices=Get-CimInstance Win32_PhysicalMemory | ForEach-Object { [pscustomobject]@{BankLabel=$_.BankLabel;DeviceLocator=$_.DeviceLocator;Manufacturer=$_.Manufacturer;PartNumber=$_.PartNumber;SerialNumber=$_.SerialNumber;ConfiguredClockSpeed=$_.ConfiguredClockSpeed;Speed=$_.Speed;Capacity=Format-Size $_.Capacity;FormFactor=$_.FormFactor;MemoryType=$_.MemoryType;SMBIOSMemoryType=$_.SMBIOSMemoryType;DataWidth=$_.DataWidth;TotalWidth=$_.TotalWidth} }; "
        "$disks=Get-CimInstance Win32_DiskDrive | ForEach-Object { [pscustomobject]@{Index=$_.Index;Model=$_.Model;FirmwareRevision=$_.FirmwareRevision;SerialNumber=$_.SerialNumber;InterfaceType=$_.InterfaceType;MediaType=$_.MediaType;Size=Format-Size $_.Size;Partitions=$_.Partitions;BytesPerSector=$_.BytesPerSector;PNPDeviceID=$_.PNPDeviceID;Status=$_.Status} }; "
        "$volumes=Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,VolumeName,DriveType,FileSystem,@{Name='Size';Expression={Format-Size $_.Size}},@{Name='FreeSpace';Expression={Format-Size $_.FreeSpace}},ProviderName,VolumeSerialNumber; "
        "$controllers=@(Get-CimInstance Win32_IDEController; Get-CimInstance Win32_SCSIController; Get-CimInstance Win32_DiskController) | Select-Object Name,Manufacturer,DeviceID,PNPDeviceID,Status; "
        "$gpu=Get-CimInstance Win32_VideoController | ForEach-Object { [pscustomobject]@{Name=$_.Name;VideoProcessor=$_.VideoProcessor;AdapterRAM=Format-Size $_.AdapterRAM;DriverVersion=$_.DriverVersion;DriverDate=$_.DriverDate;CurrentResolution=([string]$_.CurrentHorizontalResolution + 'x' + [string]$_.CurrentVerticalResolution + '@' + [string]$_.CurrentRefreshRate);PNPDeviceID=$_.PNPDeviceID;Status=$_.Status} }; "
        "$monitors=Get-CimInstance Win32_DesktopMonitor | Select-Object Name,MonitorType,ScreenWidth,ScreenHeight,PixelsPerXLogicalInch,PixelsPerYLogicalInch,PNPDeviceID,Status; "
        "$network=Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true -or $_.PNPDeviceID -like 'PCI*' -or $_.PNPDeviceID -like 'USB*' } | ForEach-Object { [pscustomobject]@{Name=$_.Name;Manufacturer=$_.Manufacturer;AdapterType=$_.AdapterType;MACAddress=$_.MACAddress;Speed=Format-Speed $_.Speed;NetConnectionID=$_.NetConnectionID;NetConnectionStatus=$_.NetConnectionStatus;ServiceName=$_.ServiceName;PNPDeviceID=$_.PNPDeviceID;Status=$_.Status} }; "
        "$netConfig=Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -or $_.IPAddress } | Select-Object Description,MACAddress,DHCPEnabled,IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder,DNSDomain; "
        "$audio=Get-CimInstance Win32_SoundDevice | Select-Object Name,Manufacturer,ProductName,DeviceID,PNPDeviceID,Status; "
        "$cameras=Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPClass -in @('Camera','Image') -or $_.Service -like '*usbvideo*' } | Select-Object Name,Manufacturer,Service,PNPClass,DeviceID,PNPDeviceID,Status; "
        "$usbControllers=Get-CimInstance Win32_USBController | Select-Object Name,Manufacturer,DeviceID,PNPDeviceID,Status; "
        "$usbDevices=Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'USB*' } | Select-Object Name,Manufacturer,Service,PNPClass,DeviceID,PNPDeviceID,Status -First 120; "
        "$hid=Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPClass -in @('Keyboard','Mouse','HIDClass','Bluetooth','MEDIA','USB') } | Select-Object Name,Manufacturer,Service,PNPClass,DeviceID,PNPDeviceID,Status -First 160; "
        "$battery=Get-CimInstance Win32_Battery | Select-Object Name,DeviceID,BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime,Chemistry,DesignCapacity,FullChargeCapacity,Status; "
        "$tpm=Get-CimInstance -Namespace root/cimv2/security/microsofttpm -ClassName Win32_Tpm | Select-Object IsEnabled_InitialValue,IsActivated_InitialValue,IsOwned_InitialValue,ManufacturerId,ManufacturerVersion,SpecVersion; "
        "$ports=Get-CimInstance Win32_SerialPort | Select-Object DeviceID,Name,Caption,Description,ProviderType,PNPDeviceID,Status; "
        "$printers=Get-CimInstance Win32_Printer | Select-Object Name,DriverName,PortName,Default,Shared,Network,WorkOffline,Status; "
        "$pci=Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI*' } | Select-Object Name,Manufacturer,Service,PNPClass,DeviceID,PNPDeviceID,Status -First 180; "
        "$problem=Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 } | Select-Object Name,PNPClass,ConfigManagerErrorCode,Manufacturer,DeviceID,PNPDeviceID,Status; "
        "$drivers=Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName,DeviceClass,Manufacturer,DriverProviderName,DriverVersion,DriverDate,InfName,DeviceID -First 220; "
        "$text += Write-Section '整机/机箱' $cs; "
        "$text += Write-Section '主板' $board; "
        "$text += Write-Section 'BIOS/UEFI' $bios; "
        "$text += Write-Section '机箱/资产标识' $enclosure; "
        "$text += Write-Section '处理器扩展信息' $processor; "
        "$text += Write-Section '内存阵列' $memoryArray; "
        "$text += Write-Section '内存条详细信息' $memoryDevices; "
        "$text += Write-Section '磁盘驱动器' $disks; "
        "$text += Write-Section '逻辑卷' $volumes; "
        "$text += Write-Section '存储控制器' $controllers; "
        "$text += Write-Section '显示适配器' $gpu; "
        "$text += Write-Section '显示器' $monitors; "
        "$text += Write-Section '物理/USB网卡' $network; "
        "$text += Write-Section '网络配置' $netConfig; "
        "$text += Write-Section '音频设备' $audio; "
        "$text += Write-Section '摄像头/图像设备' $cameras; "
        "$text += Write-Section 'USB控制器' $usbControllers; "
        "$text += Write-Section 'USB设备(前120项)' $usbDevices; "
        "$text += Write-Section '键鼠/HID/蓝牙/媒体设备(前160项)' $hid; "
        "$text += Write-Section '电池/UPS' $battery; "
        "$text += Write-Section 'TPM' $tpm; "
        "$text += Write-Section '串口/通信端口' $ports; "
        "$text += Write-Section '打印机' $printers; "
        "$text += Write-Section 'PCI/板载设备(前180项)' $pci; "
        "$text += Write-Section '异常PNP设备' $problem; "
        "$text += Write-Section 'PNP签名驱动(前220项)' $drivers; "
        "$text");
    return runInventoryPowerShellTextSync(kScriptText, 18000);
}
