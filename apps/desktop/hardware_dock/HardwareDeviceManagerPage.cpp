#include "HardwareDeviceManagerPage.h"

// ============================================================
// HardwareDeviceManagerPage.cpp
// Purpose:
// 1) enumerate PnP devices using SetupAPI/CfgMgr.
// 2) Construct the device tree using InstanceId/Parent, displaying a column layout similar to System Informer.
// 3) Support switching between current/all devices, highlighting anomalies, search filtering, and viewing details.
// ============================================================

#include "../Theme.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/DetailLayoutRegistry.h"

#include <QAction>
#include <QCheckBox>
#include <QApplication>
#include <QClipboard>
#include <QCoreApplication>
#include <QDateTime>
#include <QDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QHash>
#include <QSignalBlocker>
#include <QSplitter>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <QVariant>

#include <algorithm>
#include <cwchar>
#include <iterator>
#include <memory>
#include <thread>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Cfgmgr32.h>
#include <initguid.h>
#include <devpkey.h>
#include <Objbase.h>
#include <SetupAPI.h>

#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Setupapi.lib")

namespace
{
    // DeviceTreeColumn：
    // - Purpose: Define the column index for the device tree table.
    // - Handling logic: Use unified references when inserting and updating nodes.
    // - Returns behavior: the enumeration itself has no return value.
    enum DeviceTreeColumn : int
    {
        kColumnName = 0,
        kColumnManufacturer,
        kColumnService,
        kColumnClass,
        kColumnEnumerator,
        kColumnInstalled,
        kColumnCount
    };

    // propertyString:
    // - Input: SetupAPI device information handle, device data, and property key.
    // - Processing: Read DEVPROP_TYPE_STRING properties.
    // - Return: On success, returns the string; on failure or type mismatch, returns an empty string.
    QString propertyString(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DEVPROPKEY& propertyKey)
    {
        DEVPROPTYPE propertyType = 0;
        DWORD requiredSize = 0;
        SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            nullptr,
            0,
            &requiredSize,
            0);
        if (requiredSize == 0 || propertyType != DEVPROP_TYPE_STRING)
        {
            return QString();
        }

        std::vector<BYTE> buffer(requiredSize + sizeof(wchar_t), 0);
        if (!SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            nullptr,
            0))
        {
            return QString();
        }

        return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(buffer.data())).trimmed();
    }

    // propertyStringList:
    // - Input: SetupAPI device information handle, device data, and property key.
    // - Processing: Read DEVPROP_TYPE_STRING_LIST multi-string properties.
    // - Returns: A string list joined by newlines; returns an empty string on failure.
    QString propertyStringList(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DEVPROPKEY& propertyKey)
    {
        DEVPROPTYPE propertyType = 0;
        DWORD requiredSize = 0;
        SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            nullptr,
            0,
            &requiredSize,
            0);
        if (requiredSize == 0 || propertyType != DEVPROP_TYPE_STRING_LIST)
        {
            return QString();
        }

        std::vector<BYTE> buffer(requiredSize + sizeof(wchar_t), 0);
        if (!SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            nullptr,
            0))
        {
            return QString();
        }

        QStringList valueList;
        const wchar_t* cursor = reinterpret_cast<const wchar_t*>(buffer.data());
        while (cursor != nullptr && *cursor != L'\0')
        {
            const QString kValueText = QString::fromWCharArray(cursor).trimmed();
            if (!kValueText.isEmpty())
            {
                valueList.append(kValueText);
            }
            cursor += wcslen(cursor) + 1;
        }
        return valueList.join(QStringLiteral("\n"));
    }

    // propertyBool:
    // - Input: SetupAPI device information handle, device data, and property key.
    // - Processing: Read DEVPROP_TYPE_BOOLEAN properties.
    // - Returns: true if read successfully and the value is TRUE.
    bool propertyBool(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DEVPROPKEY& propertyKey)
    {
        DEVPROPTYPE propertyType = 0;
        DEVPROP_BOOLEAN value = DEVPROP_FALSE;
        if (!SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            reinterpret_cast<PBYTE>(&value),
            sizeof(value),
            nullptr,
            0))
        {
            return false;
        }
        return propertyType == DEVPROP_TYPE_BOOLEAN && value == DEVPROP_TRUE;
    }

    // propertyUInt32:
    // - Input: SetupAPI device information handle, device data, and property key.
    // - Processing: Read DEVPROP_TYPE_UINT32 properties.
    // - Returns: The numeric value on success, or 0 otherwise.
    unsigned long propertyUInt32(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DEVPROPKEY& propertyKey)
    {
        DEVPROPTYPE propertyType = 0;
        unsigned long value = 0;
        if (!SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            reinterpret_cast<PBYTE>(&value),
            sizeof(value),
            nullptr,
            0))
        {
            return 0;
        }
        return propertyType == DEVPROP_TYPE_UINT32 ? value : 0;
    }

    // propertyFileTimeText:
    // - Input: SetupAPI device information handle, device data, and property key.
    // - Processing: Read DEVPROP_TYPE_FILETIME and convert to local time text.
    // - Returns: On success, returns 'yyyy-MM-dd HH:mm:ss'; on failure, returns an empty string.
    QString propertyFileTimeText(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DEVPROPKEY& propertyKey)
    {
        DEVPROPTYPE propertyType = 0;
        FILETIME fileTime{};
        if (!SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            reinterpret_cast<PBYTE>(&fileTime),
            sizeof(fileTime),
            nullptr,
            0)
            || propertyType != DEVPROP_TYPE_FILETIME)
        {
            return QString();
        }

        FILETIME localFileTime{};
        SYSTEMTIME systemTime{};
        if (!FileTimeToLocalFileTime(&fileTime, &localFileTime)
            || !FileTimeToSystemTime(&localFileTime, &systemTime))
        {
            return QString();
        }

        return QStringLiteral("%1-%2-%3 %4:%5:%6")
            .arg(systemTime.wYear, 4, 10, QLatin1Char('0'))
            .arg(systemTime.wMonth, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wDay, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wHour, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wMinute, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wSecond, 2, 10, QLatin1Char('0'));
    }

    // propertyGuidText:
    // - Input: SetupAPI device information handle, device data, and property key.
    // - Processing: Read DEVPROP_TYPE_GUID and format as a brace-enclosed GUID.
    // - Returns: The GUID text on success, or an empty string otherwise.
    QString propertyGuidText(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DEVPROPKEY& propertyKey)
    {
        DEVPROPTYPE propertyType = 0;
        GUID guidValue{};
        if (!SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            reinterpret_cast<PBYTE>(&guidValue),
            sizeof(guidValue),
            nullptr,
            0)
            || propertyType != DEVPROP_TYPE_GUID)
        {
            return QString();
        }

        wchar_t buffer[64] = {};
        if (StringFromGUID2(guidValue, buffer, static_cast<int>(std::size(buffer))) <= 0)
        {
            return QString();
        }
        return QString::fromWCharArray(buffer);
    }

    // registryPropertyString:
    // - Input: SetupAPI device info handle, device data, SPDRP_* property index;
    // - Processing: Read legacy device registry properties, filling in unstable DEVPROPKEY fields;
    // - Return: Join string/multi-string properties with newlines; return empty string on failure.
    QString registryPropertyString(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DWORD propertyValue)
    {
        DWORD requiredSize = 0;
        DWORD propertyType = 0;
        SetupDiGetDeviceRegistryPropertyW(
            deviceInfoSet,
            deviceInfoData,
            propertyValue,
            &propertyType,
            nullptr,
            0,
            &requiredSize);
        if (requiredSize == 0)
        {
            return QString();
        }

        std::vector<BYTE> buffer(requiredSize + sizeof(wchar_t) * 2U, 0);
        if (!SetupDiGetDeviceRegistryPropertyW(
            deviceInfoSet,
            deviceInfoData,
            propertyValue,
            &propertyType,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            nullptr))
        {
            return QString();
        }

        if (propertyType == REG_MULTI_SZ)
        {
            QStringList valueList;
            const wchar_t* cursor = reinterpret_cast<const wchar_t*>(buffer.data());
            while (cursor != nullptr && *cursor != L'\0')
            {
                const QString kValueText = QString::fromWCharArray(cursor).trimmed();
                if (!kValueText.isEmpty())
                {
                    valueList.append(kValueText);
                }
                cursor += wcslen(cursor) + 1;
            }
            return valueList.join(QStringLiteral("\n"));
        }

        if (propertyType == REG_SZ || propertyType == REG_EXPAND_SZ)
        {
            return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(buffer.data())).trimmed();
        }

        return QString();
    }

    // serviceImagePath:
    // - Input: Device Service name.
    // - Processing: Read HKLM\SYSTEM\CurrentControlSet\Services\<Service>\ImagePath;
    // - Returns: the driver service image path on success, or an empty string on failure.
    QString serviceImagePath(const QString& serviceNameText)
    {
        if (serviceNameText.trimmed().isEmpty())
        {
            return QString();
        }

        const QString kKeyPath = QStringLiteral("SYSTEM\\CurrentControlSet\\Services\\%1").arg(serviceNameText.trimmed());
        HKEY serviceKey = nullptr;
        if (RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            reinterpret_cast<LPCWSTR>(kKeyPath.utf16()),
            0,
            KEY_READ,
            &serviceKey) != ERROR_SUCCESS)
        {
            return QString();
        }

        DWORD valueType = 0;
        DWORD valueSize = 0;
        const LONG kQuerySizeResult = RegQueryValueExW(
            serviceKey,
            L"ImagePath",
            nullptr,
            &valueType,
            nullptr,
            &valueSize);
        if (kQuerySizeResult != ERROR_SUCCESS || valueSize == 0)
        {
            RegCloseKey(serviceKey);
            return QString();
        }

        std::vector<BYTE> buffer(valueSize + sizeof(wchar_t), 0);
        const LONG kQueryValueResult = RegQueryValueExW(
            serviceKey,
            L"ImagePath",
            nullptr,
            &valueType,
            buffer.data(),
            &valueSize);
        RegCloseKey(serviceKey);
        if (kQueryValueResult != ERROR_SUCCESS || (valueType != REG_SZ && valueType != REG_EXPAND_SZ))
        {
            return QString();
        }

        return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(buffer.data())).trimmed();
    }

    // driverRegistryPathFromClassKey:
    // - Input: ClassGuid and Driver key name, e.g., "0001".
    // - Processing: Concatenate the Device Manager driver registry path.
    // - Return: HKLM\SYSTEM\CurrentControlSet\Control\Class\{GUID}\0001 if fields are complete.
    QString driverRegistryPathFromClassKey(const QString& classGuidText, const QString& driverKeyText)
    {
        if (classGuidText.trimmed().isEmpty() || driverKeyText.trimmed().isEmpty())
        {
            return QString();
        }

        return QStringLiteral("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\%1\\%2")
            .arg(classGuidText.trimmed(), driverKeyText.trimmed());
    }

    // formatWin32Error:
    // - Input: Win32 error code;
    // - Processing: Call FormatMessageW to retrieve system error text.
    // - Returns: A diagnostic string containing decimal, hexadecimal, and message body.
    QString formatWin32Error(const DWORD errorCode)
    {
        wchar_t* messageBuffer = nullptr;
        const DWORD kWrittenLength = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            0,
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            nullptr);

        QString messageText;
        if (kWrittenLength > 0 && messageBuffer != nullptr)
        {
            messageText = QString::fromWCharArray(messageBuffer).trimmed();
            LocalFree(messageBuffer);
        }

        if (messageText.isEmpty())
        {
            messageText = QStringLiteral("未知错误");
        }

        return QStringLiteral("%1 (0x%2): %3")
            .arg(errorCode)
            .arg(errorCode, 8, 16, QLatin1Char('0'))
            .arg(messageText);
    }

    // currentProcessIsElevated:
    // - Input: current process
    // - Processing: query TokenElevation;
    // - Return: true if the current process is running with elevated privileges, otherwise false.
    bool currentProcessIsElevated()
    {
        HANDLE tokenHandle = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
        {
            return false;
        }

        TOKEN_ELEVATION elevation{};
        DWORD returnLength = 0;
        const BOOL kQueryOk = GetTokenInformation(
            tokenHandle,
            TokenElevation,
            &elevation,
            sizeof(elevation),
            &returnLength);
        CloseHandle(tokenHandle);
        return kQueryOk != FALSE && elevation.TokenIsElevated != 0;
    }

    // instanceIdFromDevInst: Forward declaration:
    // - findDeviceInfoDataByInstanceId must fall back to reading the CfgMgr Instance ID when re-enumerating the device.
    // - Implementation placed below; declaration here to avoid compilation failure due to function definition order.
    QString instanceIdFromDevInst(DEVINST devInst);

    // findDeviceInfoDataByInstanceId:
    // - Input: PnP Instance ID.
    // - Processing: Prefer opening a single DevNode precisely via SetupDiOpenDeviceInfoW; fall back to linear enumeration of the entire class on failure.
    // - Return: On success, populate deviceInfoSetOut/deviceInfoDataOut; the caller must call SetupDiDestroyDeviceInfoList.
    bool findDeviceInfoDataByInstanceId(
        const QString& instanceIdText,
        HDEVINFO* const deviceInfoSetOut,
        SP_DEVINFO_DATA* const deviceInfoDataOut,
        QString* const errorTextOut)
    {
        if (deviceInfoSetOut == nullptr || deviceInfoDataOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("内部错误：输出参数为空。");
            }
            return false;
        }

        *deviceInfoSetOut = INVALID_HANDLE_VALUE;
        ZeroMemory(deviceInfoDataOut, sizeof(*deviceInfoDataOut));
        deviceInfoDataOut->cbSize = sizeof(SP_DEVINFO_DATA);
        // normalizedInstanceIdText usage: Uniformly trims leading/trailing whitespace to provide a single text source for precise location and linear fallback.
        const QString kNormalizedInstanceIdText = instanceIdText.trimmed();
        if (kNormalizedInstanceIdText.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("设备 Instance ID 为空。");
            }
            return false;
        }

        // Precise targeting priority:
        // - SetupDiCreateDeviceInfoList + SetupDiOpenDeviceInfoW only parse the target DevNode;
        // - Avoids reading attributes for thousands of historical devices one by one by not using DIGCF_ALLCLASSES (without DIGCF_PRESENT).
        HDEVINFO targetedDeviceInfoSet = SetupDiCreateDeviceInfoList(nullptr, nullptr);
        if (targetedDeviceInfoSet != INVALID_HANDLE_VALUE)
        {
            SP_DEVINFO_DATA targetedDeviceInfoData{};
            targetedDeviceInfoData.cbSize = sizeof(targetedDeviceInfoData);
            if (SetupDiOpenDeviceInfoW(
                targetedDeviceInfoSet,
                reinterpret_cast<LPCWSTR>(kNormalizedInstanceIdText.utf16()),
                nullptr,
                0,
                &targetedDeviceInfoData))
            {
                *deviceInfoSetOut = targetedDeviceInfoSet;
                *deviceInfoDataOut = targetedDeviceInfoData;
                return true;
            }
            SetupDiDestroyDeviceInfoList(targetedDeviceInfoSet);
        }

        // Fallback path: In the rare case where a DevNode cannot be opened by SetupDiOpenDeviceInfoW, continue with the legacy logic of linear scanning.
        HDEVINFO deviceInfoSet = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES);
        if (deviceInfoSet == INVALID_HANDLE_VALUE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("SetupDiGetClassDevsW 失败：%1").arg(formatWin32Error(GetLastError()));
            }
            return false;
        }

        for (DWORD index = 0;; ++index)
        {
            SP_DEVINFO_DATA candidateData{};
            candidateData.cbSize = sizeof(candidateData);
            if (!SetupDiEnumDeviceInfo(deviceInfoSet, index, &candidateData))
            {
                break;
            }

            QString candidateInstanceId = propertyString(deviceInfoSet, &candidateData, DEVPKEY_Device_InstanceId);
            if (candidateInstanceId.isEmpty())
            {
                candidateInstanceId = instanceIdFromDevInst(candidateData.DevInst);
            }
            if (candidateInstanceId.compare(kNormalizedInstanceIdText, Qt::CaseInsensitive) == 0)
            {
                *deviceInfoSetOut = deviceInfoSet;
                *deviceInfoDataOut = candidateData;
                return true;
            }
        }

        SetupDiDestroyDeviceInfoList(deviceInfoSet);
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("未找到设备：%1").arg(instanceIdText);
        }
        return false;
    }

    // instanceIdFromDevInst:
    // - Input: CfgMgr devinst.
    // - Processing: Call CM_Get_Device_IDW to retrieve the instance ID.
    // - Returns: instance ID on success, empty string otherwise.
    QString instanceIdFromDevInst(DEVINST devInst)
    {
        ULONG charCount = 0;
        if (CM_Get_Device_ID_Size(&charCount, devInst, 0) != CR_SUCCESS || charCount == 0)
        {
            return QString();
        }

        std::vector<wchar_t> buffer(static_cast<std::size_t>(charCount) + 2U, L'\0');
        if (CM_Get_Device_IDW(devInst, buffer.data(), static_cast<ULONG>(buffer.size()), 0) != CR_SUCCESS)
        {
            return QString();
        }
        return QString::fromWCharArray(buffer.data()).trimmed();
    }

    // deviceStatusText:
    // - Input: CfgMgr status and problem code;
    // - Processing: Generate a readable status summary in the details area.
    // - Returns: Status string.
    QString deviceStatusText(const ULONG statusFlags, const ULONG problemCode)
    {
        QStringList partList;
        partList.append(QStringLiteral("DN=0x%1").arg(statusFlags, 8, 16, QLatin1Char('0')));
        if ((statusFlags & DN_STARTED) != 0)
        {
            partList.append(QStringLiteral("STARTED"));
        }
        if ((statusFlags & DN_HAS_PROBLEM) != 0)
        {
            partList.append(QStringLiteral("HAS_PROBLEM"));
        }
        if ((statusFlags & DN_DISABLEABLE) != 0)
        {
            partList.append(QStringLiteral("DISABLEABLE"));
        }
        if ((statusFlags & DN_REMOVABLE) != 0)
        {
            partList.append(QStringLiteral("REMOVABLE"));
        }
        if ((statusFlags & DN_PRIVATE_PROBLEM) != 0)
        {
            partList.append(QStringLiteral("PRIVATE_PROBLEM"));
        }
        if (problemCode != 0)
        {
            partList.append(QStringLiteral("Problem=%1").arg(problemCode));
        }
        return partList.join(QStringLiteral(" | "));
    }

    // safeDisplayText:
    // - Input: candidate text
    // - Processing: Display null values uniformly as '-' to avoid large blank areas in the table that hinder readability.
    // - Returns: displayable text.
    QString safeDisplayText(const QString& valueText)
    {
        return valueText.trimmed().isEmpty() ? QStringLiteral("-") : valueText.trimmed();
    }

    // itemMatchesFilter:
    // - Input: Device entry and lowercase filter text;
    // - Processing: Perform substring matching in the primary column and instance ID.
    // - Returns: true if matched; always true if filter is empty.
    bool itemMatchesFilter(
        const HardwareDeviceManagerPage::DeviceEntry& entry,
        const QString& lowerFilterText)
    {
        if (lowerFilterText.isEmpty())
        {
            return true;
        }

        const QString kJoinedText = QStringLiteral("%1\n%2\n%3\n%4\n%5\n%6\n%7\n%8\n%9\n%10\n%11")
            .arg(entry.nameText)
            .arg(entry.manufacturerText)
            .arg(entry.serviceText)
            .arg(entry.classText)
            .arg(entry.enumeratorText)
            .arg(entry.instanceIdText)
            .arg(entry.parentInstanceIdText)
            .arg(entry.hardwareIdsText)
            .arg(entry.driverInfPathText)
            .arg(entry.driverProviderText)
            .arg(entry.serviceImagePathText)
            .toLower();
        return kJoinedText.contains(lowerFilterText);
    }

    // buildDevicePropertiesText:
    // - Input: device snapshot;
    // - Processing: Format into device properties page body text.
    // - Returns: Read-only text suitable for display in CodeEditorWidget.
    QString buildDevicePropertiesText(const HardwareDeviceManagerPage::DeviceEntry& entry)
    {
        return QStringLiteral(
            "[常规]\n"
            "名称: %1\n"
            "制造商: %2\n"
            "设备类: %3\n"
            "Class GUID: %4\n"
            "枚举器: %5\n"
            "位置: %6\n"
            "已安装: %7\n"
            "当前存在: %8\n"
            "存在问题: %9\n"
            "问题: %10\n"
            "状态: %11\n\n"
            "[标识]\n"
            "实例 ID:\n%12\n\n"
            "父实例 ID:\n%13\n\n"
            "硬件 ID:\n%14\n\n"
            "兼容 ID:\n%15\n\n"
            "[驱动绑定]\n"
            "服务: %16\n"
            "驱动键: %17\n"
            "驱动注册表路径: %18\n"
            "驱动 INF: %19\n"
            "提供商: %20\n"
            "版本: %21\n"
            "日期: %22\n"
            "服务 ImagePath: %23\n")
            .arg(safeDisplayText(entry.nameText))
            .arg(safeDisplayText(entry.manufacturerText))
            .arg(safeDisplayText(entry.classText))
            .arg(safeDisplayText(entry.classGuidText))
            .arg(safeDisplayText(entry.enumeratorText))
            .arg(safeDisplayText(entry.locationText))
            .arg(safeDisplayText(entry.installedText))
            .arg(entry.isPresent ? QStringLiteral("Yes") : QStringLiteral("No"))
            .arg(entry.hasProblem ? QStringLiteral("Yes") : QStringLiteral("No"))
            .arg(safeDisplayText(entry.problemText))
            .arg(safeDisplayText(entry.statusText))
            .arg(safeDisplayText(entry.instanceIdText))
            .arg(safeDisplayText(entry.parentInstanceIdText))
            .arg(safeDisplayText(entry.hardwareIdsText))
            .arg(safeDisplayText(entry.compatibleIdsText))
            .arg(safeDisplayText(entry.serviceText))
            .arg(safeDisplayText(entry.driverText))
            .arg(safeDisplayText(entry.driverRegistryPathText))
            .arg(safeDisplayText(entry.driverInfPathText))
            .arg(safeDisplayText(entry.driverProviderText))
            .arg(safeDisplayText(entry.driverVersionText))
            .arg(safeDisplayText(entry.driverDateText))
            .arg(safeDisplayText(entry.serviceImagePathText));
    }

    // buildDriverDetailsText:
    // - Input: device snapshot;
    // - Processing: Format into 'Driver Details' body text;
    // - Returns: INF, Provider, Version, service image path, and other driver troubleshooting information.
    QString buildDriverDetailsText(const HardwareDeviceManagerPage::DeviceEntry& entry)
    {
        return QStringLiteral(
            "[驱动]\n"
            "设备: %1\n"
            "实例 ID:\n%2\n\n"
            "服务: %3\n"
            "服务 ImagePath: %4\n"
            "驱动键: %5\n"
            "驱动注册表路径: %6\n"
            "驱动 INF: %7\n"
            "提供商: %8\n"
            "版本: %9\n"
            "日期: %10\n"
            "设备类: %11\n"
            "Class GUID: %12\n\n"
            "[匹配 ID]\n"
            "硬件 ID:\n%13\n\n"
            "兼容 ID:\n%14\n\n"
            "[说明]\n"
            "- 卸载设备会移除当前 DevNode，可能要求重启或重新扫描硬件。\n"
            "- 删除驱动包只支持 oem*.inf；系统内置 INF 或正在使用的驱动包通常会失败。\n")
            .arg(safeDisplayText(entry.nameText))
            .arg(safeDisplayText(entry.instanceIdText))
            .arg(safeDisplayText(entry.serviceText))
            .arg(safeDisplayText(entry.serviceImagePathText))
            .arg(safeDisplayText(entry.driverText))
            .arg(safeDisplayText(entry.driverRegistryPathText))
            .arg(safeDisplayText(entry.driverInfPathText))
            .arg(safeDisplayText(entry.driverProviderText))
            .arg(safeDisplayText(entry.driverVersionText))
            .arg(safeDisplayText(entry.driverDateText))
            .arg(safeDisplayText(entry.classText))
            .arg(safeDisplayText(entry.classGuidText))
            .arg(safeDisplayText(entry.hardwareIdsText))
            .arg(safeDisplayText(entry.compatibleIdsText));
    }

    // showTextDialog:
    // - Input: Parent widget, title, and body text.
    // - Processing: Use the project's CodeEditorWidget to pop up a read-only text window.
    // - Return value: None.
    void showTextDialog(QWidget* const parentWidget, const QString& titleText, const QString& bodyText)
    {
        QDialog dialog(parentWidget);
        dialog.setWindowTitle(titleText);
        dialog.resize(820, 620);

        QVBoxLayout* layout = new QVBoxLayout(&dialog);
        CodeEditorWidget* editor = new CodeEditorWidget(&dialog);
        editor->setReadOnly(true);
        editor->setLocalizedText(bodyText);
        layout->addWidget(editor, 1);

        QPushButton* closeButton = new QPushButton(QStringLiteral("关闭"), &dialog);
        QObject::connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        QHBoxLayout* buttonLayout = new QHBoxLayout();
        buttonLayout->addStretch(1);
        buttonLayout->addWidget(closeButton);
        layout->addLayout(buttonLayout);

        dialog.exec();
    }

    // uninstallDeviceByInstanceId:
    // - Input: PnP Instance ID.
    // - Processing: Locate the SP_DEVINFO_DATA and call DIF_REMOVE.
    // - Returns: true on success; on failure, errorTextOut contains the Win32 diagnostic.
    bool uninstallDeviceByInstanceId(const QString& instanceIdText, QString* const errorTextOut)
    {
        HDEVINFO deviceInfoSet = INVALID_HANDLE_VALUE;
        SP_DEVINFO_DATA deviceInfoData{};
        QString findErrorText;
        if (!findDeviceInfoDataByInstanceId(instanceIdText, &deviceInfoSet, &deviceInfoData, &findErrorText))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = findErrorText;
            }
            return false;
        }

        SP_REMOVEDEVICE_PARAMS removeParams{};
        removeParams.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        removeParams.ClassInstallHeader.InstallFunction = DIF_REMOVE;
        removeParams.Scope = DI_REMOVEDEVICE_GLOBAL;
        removeParams.HwProfile = 0;

        if (!SetupDiSetClassInstallParamsW(
            deviceInfoSet,
            &deviceInfoData,
            &removeParams.ClassInstallHeader,
            sizeof(removeParams)))
        {
            const DWORD kErrorCode = GetLastError();
            SetupDiDestroyDeviceInfoList(deviceInfoSet);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("SetupDiSetClassInstallParamsW 失败：%1").arg(formatWin32Error(kErrorCode));
            }
            return false;
        }

        if (!SetupDiCallClassInstaller(DIF_REMOVE, deviceInfoSet, &deviceInfoData))
        {
            const DWORD kErrorCode = GetLastError();
            SetupDiDestroyDeviceInfoList(deviceInfoSet);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("SetupDiCallClassInstaller(DIF_REMOVE) 失败：%1").arg(formatWin32Error(kErrorCode));
            }
            return false;
        }

        SetupDiDestroyDeviceInfoList(deviceInfoSet);
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        return true;
    }

    // normalizeOemInfName:
    // - Input: INF field returned by SetupAPI/DEVPROP;
    // - Processing: Extract file name and allow only oem*.inf;
    // - Returns: INF filename suitable for SetupUninstallOEMInfW; returns empty if not an OEM INF.
    QString normalizeOemInfName(const QString& infText)
    {
        QString normalizedText = infText.trimmed();
        if (normalizedText.isEmpty())
        {
            return QString();
        }

        normalizedText.replace(QLatin1Char('/'), QLatin1Char('\\'));
        const int kSeparatorIndex = normalizedText.lastIndexOf(QLatin1Char('\\'));
        if (kSeparatorIndex >= 0)
        {
            normalizedText = normalizedText.mid(kSeparatorIndex + 1);
        }

        if (!normalizedText.startsWith(QStringLiteral("oem"), Qt::CaseInsensitive)
            || !normalizedText.endsWith(QStringLiteral(".inf"), Qt::CaseInsensitive))
        {
            return QString();
        }
        return normalizedText;
    }

    // uninstallOemInfPackage:
    // - Input: INF name or path;
    // - Processing: Call SetupUninstallOEMInfW to remove third-party driver packages;
    // - Returns: true on success; on failure, errorTextOut contains the Win32 diagnostic.
    bool uninstallOemInfPackage(const QString& infText, QString* const errorTextOut)
    {
        const QString kOemInfName = normalizeOemInfName(infText);
        if (kOemInfName.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("当前设备没有可删除的 oem*.inf 驱动包。");
            }
            return false;
        }

        if (!SetupUninstallOEMInfW(
            reinterpret_cast<LPCWSTR>(kOemInfName.utf16()),
            SUOI_FORCEDELETE,
            nullptr))
        {
            const DWORD kErrorCode = GetLastError();
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("SetupUninstallOEMInfW(%1) 失败：%2")
                    .arg(kOemInfName, formatWin32Error(kErrorCode));
            }
            return false;
        }

        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        return true;
    }
}

HardwareDeviceManagerPage::HardwareDeviceManagerPage(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
    refreshDevicesAsync(false);
}

void HardwareDeviceManagerPage::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);

    QLabel* titleLabel = new QLabel(QStringLiteral("设备管理"), this);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    headerLayout->addWidget(titleLabel, 0);

    statusLabel_ = new QLabel(QStringLiteral("正在枚举当前设备..."), this);
    statusLabel_->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;").arg(ksword_theme::textSecondaryHex()));
    headerLayout->addWidget(statusLabel_, 1);

    showAllDevicesCheck_ = new QCheckBox(QStringLiteral("显示全部设备"), this);
    showAllDevicesCheck_->setToolTip(QStringLiteral("关闭时仅枚举当前存在设备；开启后包含历史/非当前设备。"));
    headerLayout->addWidget(showAllDevicesCheck_, 0);

    showProblemOnlyCheck_ = new QCheckBox(QStringLiteral("只显示异常设备"), this);
    showProblemOnlyCheck_->setToolTip(QStringLiteral("仅显示 HasProblem 或 CM_PROB 非 0 的设备节点，并保留其父级路径。"));
    headerLayout->addWidget(showProblemOnlyCheck_, 0);

    searchEdit_ = new QLineEdit(this);
    searchEdit_->setPlaceholderText(QStringLiteral("搜索名称、厂商、服务、类、枚举器、Instance ID..."));
    searchEdit_->setMinimumWidth(220);
    headerLayout->addWidget(searchEdit_, 1);

    refreshButton_ = new QPushButton(QStringLiteral("刷新"), this);
    refreshButton_->setToolTip(QStringLiteral("重新通过 SetupAPI/CfgMgr 枚举 PnP 设备树"));
    headerLayout->addWidget(refreshButton_, 0);
    rootLayout_->addLayout(headerLayout, 0);

    splitter_ = new QSplitter(Qt::Vertical, this);
    splitter_->setChildrenCollapsible(false);
    rootLayout_->addWidget(splitter_, 1);

    deviceTree_ = new QTreeWidget(splitter_);
    deviceTree_->setColumnCount(kColumnCount);
    deviceTree_->setHeaderLabels({
        QStringLiteral("Name"),
        QStringLiteral("Manufacturer"),
        QStringLiteral("Service"),
        QStringLiteral("Class"),
        QStringLiteral("Enumerator"),
        QStringLiteral("Installed")
        });
    deviceTree_->setSelectionBehavior(QAbstractItemView::SelectRows);
    deviceTree_->setSelectionMode(QAbstractItemView::SingleSelection);
    deviceTree_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    deviceTree_->setContextMenuPolicy(Qt::CustomContextMenu);
    deviceTree_->setUniformRowHeights(true);
    deviceTree_->setAlternatingRowColors(true);
    deviceTree_->header()->setStretchLastSection(false);
    deviceTree_->header()->setSectionResizeMode(kColumnName, QHeaderView::Interactive);
    deviceTree_->header()->setSectionResizeMode(kColumnManufacturer, QHeaderView::Interactive);
    deviceTree_->header()->setSectionResizeMode(kColumnService, QHeaderView::ResizeToContents);
    deviceTree_->header()->setSectionResizeMode(kColumnClass, QHeaderView::ResizeToContents);
    deviceTree_->header()->setSectionResizeMode(kColumnEnumerator, QHeaderView::ResizeToContents);
    deviceTree_->header()->setSectionResizeMode(kColumnInstalled, QHeaderView::ResizeToContents);
    deviceTree_->setColumnWidth(kColumnName, 360);
    deviceTree_->setColumnWidth(kColumnManufacturer, 190);
    splitter_->addWidget(deviceTree_);

    detailEditor_ = new CodeEditorWidget(splitter_);
    detailEditor_->setReadOnly(true);
    detailEditor_->setLocalizedText(QStringLiteral("选择一个设备查看详细属性。"));
    splitter_->addWidget(detailEditor_);

    ks::ui::DetailLayoutRegistry::registerHost(
        deviceTree_, detailEditor_, this);
    splitter_->setStretchFactor(0, 4);
    splitter_->setStretchFactor(1, 1);
}

void HardwareDeviceManagerPage::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]()
    {
        refreshDevicesAsync(true);
    });

    connect(showAllDevicesCheck_, &QCheckBox::toggled, this, [this](const bool)
    {
        refreshDevicesAsync(true);
    });

    connect(showProblemOnlyCheck_, &QCheckBox::toggled, this, [this](const bool)
    {
        if (deviceTree_ == nullptr)
        {
            return;
        }
        ks::ui::DetailLayoutRegistry::prepareDataRebuild(detailEditor_);
        const QString kFilterText = searchEdit_ != nullptr ? searchEdit_->text().trimmed().toLower() : QString();
        for (int index = 0; index < deviceTree_->topLevelItemCount(); ++index)
        {
            applyFilterToTree(deviceTree_->topLevelItem(index), kFilterText);
        }
        if (showProblemOnlyCheck_ != nullptr && showProblemOnlyCheck_->isChecked())
        {
            deviceTree_->expandAll();
        }
    });

    connect(searchEdit_, &QLineEdit::textChanged, this, [this](const QString&)
    {
        if (deviceTree_ == nullptr)
        {
            return;
        }
        ks::ui::DetailLayoutRegistry::prepareDataRebuild(detailEditor_);
        const QString kFilterText = searchEdit_ != nullptr ? searchEdit_->text().trimmed().toLower() : QString();
        for (int index = 0; index < deviceTree_->topLevelItemCount(); ++index)
        {
            applyFilterToTree(deviceTree_->topLevelItem(index), kFilterText);
        }
        if (!kFilterText.isEmpty())
        {
            deviceTree_->expandAll();
        }
    });

    connect(
        deviceTree_,
        &QTreeWidget::currentItemChanged,
        this,
        [this](QTreeWidgetItem* currentItem, QTreeWidgetItem*)
        {
            updateDetailForItem(currentItem);
        });

    connect(
        deviceTree_,
        &QTreeWidget::itemDoubleClicked,
        this,
        [this](QTreeWidgetItem*, int)
        {
            showSelectedDeviceProperties();
        });

    connect(
        deviceTree_,
        &QTreeWidget::customContextMenuRequested,
        this,
        [this](const QPoint& localPosition)
        {
            showDeviceContextMenu(localPosition);
        });
}

void HardwareDeviceManagerPage::refreshDevicesAsync(const bool forceRefresh)
{
    bool expectedValue = false;
    if (!refreshing_.compare_exchange_strong(expectedValue, true))
    {
        if (forceRefresh && statusLabel_ != nullptr)
        {
            statusLabel_->setText(QStringLiteral("正在刷新，请等待当前枚举完成。"));
        }
        return;
    }

    const bool kIncludeAllDevices = showAllDevicesCheck_ != nullptr && showAllDevicesCheck_->isChecked();
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(kIncludeAllDevices
            ? QStringLiteral("正在枚举全部设备...")
            : QStringLiteral("正在枚举当前设备..."));
    }
    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(false);
    }
    if (showAllDevicesCheck_ != nullptr)
    {
        showAllDevicesCheck_->setEnabled(false);
    }

    QPointer<HardwareDeviceManagerPage> safeThis(this);
    std::thread([safeThis, kIncludeAllDevices]()
    {
        std::vector<DeviceEntry> deviceList = enumerateDevicesSnapshot(kIncludeAllDevices);
        if (safeThis.isNull())
        {
            return;
        }

        const bool kInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, deviceList = std::move(deviceList), kIncludeAllDevices]() mutable
            {
                if (safeThis.isNull())
                {
                    return;
                }

                safeThis->applyDeviceSnapshot(
                    std::move(deviceList),
                    kIncludeAllDevices);
            },
            Qt::QueuedConnection);

        if (!kInvokeOk && !safeThis.isNull())
        {
            safeThis->refreshing_.store(false);
        }
    }).detach();
}

void HardwareDeviceManagerPage::applyDeviceSnapshot(
    std::vector<DeviceEntry> deviceList,
    const bool includeAllDevices)
{
    if (ks::ui::isItemViewUiCommitBlockedByContextMenu({deviceTree_}))
    {
        const QPointer<HardwareDeviceManagerPage> kSafeThis(this);
        ks::ui::deferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("hardware-device-tree-snapshot-apply"),
            {deviceTree_},
            [kSafeThis,
                deviceList = std::move(deviceList),
                includeAllDevices]() mutable
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyDeviceSnapshot(
                        std::move(deviceList),
                        includeAllDevices);
                }
            });
        return;
    }

    deviceList_ = std::move(deviceList);
    rebuildDeviceTree(deviceList_);

    int problemCount = 0;
    for (const DeviceEntry& entry : deviceList_)
    {
        if (entry.hasProblem)
        {
            ++problemCount;
        }
    }
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(
            QStringLiteral("%1设备：%2 项，异常：%3，刷新：%4")
            .arg(includeAllDevices ? QStringLiteral("全部") : QStringLiteral("当前"))
            .arg(static_cast<int>(deviceList_.size()))
            .arg(problemCount)
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss"))));
    }
    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(true);
    }
    if (showAllDevicesCheck_ != nullptr)
    {
        showAllDevicesCheck_->setEnabled(true);
    }
    refreshing_.store(false);
}

void HardwareDeviceManagerPage::rebuildDeviceTree(const std::vector<DeviceEntry>& deviceList)
{
    if (deviceTree_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(detailEditor_);

    deviceTree_->clear();
    if (deviceList.empty())
    {
        if (detailEditor_ != nullptr)
        {
            detailEditor_->setLocalizedText(QStringLiteral("未枚举到设备。"));
        }
        return;
    }

    QSignalBlocker treeSignalBlocker(deviceTree_);
    QHash<QString, QTreeWidgetItem*> itemByInstanceId;
    itemByInstanceId.reserve(static_cast<qsizetype>(deviceList.size()));
    std::vector<std::unique_ptr<QTreeWidgetItem>> itemOwnerList;
    itemOwnerList.reserve(deviceList.size());

    const QColor kProblemForeground = ksword_theme::errorColor();
    const QColor kMissingForeground = ksword_theme::textSecondaryColor();
    const QColor kNormalForeground = QColor();

    for (const DeviceEntry& entry : deviceList)
    {
        std::unique_ptr<QTreeWidgetItem> itemPointer = std::make_unique<QTreeWidgetItem>();
        itemPointer->setText(kColumnName, safeDisplayText(entry.nameText));
        itemPointer->setText(kColumnManufacturer, safeDisplayText(entry.manufacturerText));
        itemPointer->setText(kColumnService, safeDisplayText(entry.serviceText));
        itemPointer->setText(kColumnClass, safeDisplayText(entry.classText));
        itemPointer->setText(kColumnEnumerator, safeDisplayText(entry.enumeratorText));
        itemPointer->setText(kColumnInstalled, safeDisplayText(entry.installedText));
        itemPointer->setToolTip(kColumnName, entry.instanceIdText);
        itemPointer->setData(
            kColumnName,
            Qt::UserRole,
            QVariant::fromValue(reinterpret_cast<quintptr>(&entry)));

        if (entry.hasProblem)
        {
            for (int column = 0; column < kColumnCount; ++column)
            {
                itemPointer->setForeground(column, kProblemForeground);
            }
            itemPointer->setToolTip(
                kColumnName,
                QStringLiteral("%1\n%2").arg(entry.instanceIdText, entry.problemText));
        }
        else if (!entry.isPresent)
        {
            for (int column = 0; column < kColumnCount; ++column)
            {
                itemPointer->setForeground(column, kMissingForeground);
            }
        }
        else
        {
            Q_UNUSED(kNormalForeground);
        }

        if (!entry.instanceIdText.isEmpty())
        {
            itemByInstanceId.insert(entry.instanceIdText.toLower(), itemPointer.get());
        }
        itemOwnerList.push_back(std::move(itemPointer));
    }

    for (std::size_t index = 0; index < deviceList.size(); ++index)
    {
        QTreeWidgetItem* itemPointer = itemOwnerList[index].get();
        const QString kParentKey = deviceList[index].parentInstanceIdText.toLower();
        QTreeWidgetItem* parentItem = nullptr;
        if (!kParentKey.isEmpty())
        {
            const auto kParentIt = itemByInstanceId.constFind(kParentKey);
            if (kParentIt != itemByInstanceId.constEnd() && kParentIt.value() != itemPointer)
            {
                parentItem = kParentIt.value();
            }
        }

        if (parentItem != nullptr)
        {
            parentItem->addChild(itemOwnerList[index].release());
        }
        else
        {
            deviceTree_->addTopLevelItem(itemOwnerList[index].release());
        }
    }

    deviceTree_->sortItems(kColumnName, Qt::AscendingOrder);

    const QString kFilterText = searchEdit_ != nullptr ? searchEdit_->text().trimmed().toLower() : QString();
    for (int index = 0; index < deviceTree_->topLevelItemCount(); ++index)
    {
        applyFilterToTree(deviceTree_->topLevelItem(index), kFilterText);
    }

    if (deviceList.size() <= 300 || !kFilterText.isEmpty())
    {
        deviceTree_->expandToDepth(kFilterText.isEmpty() ? 1 : 99);
    }
    treeSignalBlocker.unblock();
    if (deviceTree_->topLevelItemCount() > 0)
    {
        deviceTree_->setCurrentItem(deviceTree_->topLevelItem(0));
    }
}

bool HardwareDeviceManagerPage::applyFilterToTree(QTreeWidgetItem* itemPointer, const QString& filterText)
{
    if (itemPointer == nullptr)
    {
        return false;
    }

    bool childMatched = false;
    for (int childIndex = 0; childIndex < itemPointer->childCount(); ++childIndex)
    {
        if (applyFilterToTree(itemPointer->child(childIndex), filterText))
        {
            childMatched = true;
        }
    }

    const quintptr kRawPointer = itemPointer->data(kColumnName, Qt::UserRole).value<quintptr>();
    const DeviceEntry* entryPointer = reinterpret_cast<const DeviceEntry*>(kRawPointer);
    const bool kSelfMatched = entryPointer != nullptr && itemMatchesFilter(*entryPointer, filterText);
    const bool kProblemOnlyEnabled = showProblemOnlyCheck_ != nullptr && showProblemOnlyCheck_->isChecked();
    const bool kSelfProblemMatched = entryPointer != nullptr && (!kProblemOnlyEnabled || entryPointer->hasProblem);
    const bool kVisible = (filterText.isEmpty() || kSelfMatched || childMatched)
        && (!kProblemOnlyEnabled || kSelfProblemMatched || childMatched);
    itemPointer->setHidden(!kVisible);
    return kVisible;
}

void HardwareDeviceManagerPage::updateDetailForItem(QTreeWidgetItem* itemPointer)
{
    if (detailEditor_ == nullptr)
    {
        return;
    }
    if (itemPointer == nullptr)
    {
        detailEditor_->setLocalizedText(QStringLiteral("选择一个设备查看详细属性。"));
        return;
    }

    const quintptr kRawPointer = itemPointer->data(kColumnName, Qt::UserRole).value<quintptr>();
    const DeviceEntry* entryPointer = reinterpret_cast<const DeviceEntry*>(kRawPointer);
    if (entryPointer == nullptr)
    {
        detailEditor_->setLocalizedText(QStringLiteral("当前设备节点没有详情。"));
        return;
    }

    const DeviceEntry& entry = *entryPointer;
    detailEditor_->setLocalizedText(buildDevicePropertiesText(entry));
}

const HardwareDeviceManagerPage::DeviceEntry* HardwareDeviceManagerPage::selectedDeviceEntry() const
{
    // Input: Current device tree selection.
    // Handling: Read the DeviceEntry pointer saved on the QTreeWidgetItem; this pointer references the current snapshot within m_deviceList.
    // Return: Returns the device snapshot pointer if a valid selection exists; otherwise returns nullptr.
    if (deviceTree_ == nullptr || deviceTree_->currentItem() == nullptr)
    {
        return nullptr;
    }

    const quintptr kRawPointer = deviceTree_->currentItem()->data(kColumnName, Qt::UserRole).value<quintptr>();
    return reinterpret_cast<const DeviceEntry*>(kRawPointer);
}

void HardwareDeviceManagerPage::showDeviceContextMenu(const QPoint& localPosition)
{
    // Input: Device tree local coordinates.
    // Handling: If a valid device node is selected, provide common device manager actions; uninstall/remove package actions will be re-confirmed upon execution.
    // Return value: None.
    if (deviceTree_ == nullptr)
    {
        return;
    }

    QTreeWidgetItem* itemPointer = deviceTree_->itemAt(localPosition);
    if (itemPointer == nullptr)
    {
        return;
    }
    deviceTree_->setCurrentItem(itemPointer);

    const DeviceEntry* entryPointer = selectedDeviceEntry();
    if (entryPointer == nullptr)
    {
        return;
    }

    QMenu menu(this);
    // Right-click menu style:
    // - Input: current device tree context menu;
    // - Processing: Explicitly use a theme with an opaque background to prevent unreadability in light mode caused by inheriting a transparent parent.
    // - Return: None. Only affects menu display; does not change device operation logic.
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* propertiesAction = menu.addAction(QStringLiteral("查看属性"));
    QAction* driverDetailsAction = menu.addAction(QStringLiteral("驱动程序详细信息"));
    QAction* copyInstanceIdAction = menu.addAction(QStringLiteral("复制 Instance ID"));
    menu.addSeparator();
    QAction* uninstallDeviceAction = menu.addAction(QStringLiteral("卸载设备..."));
    QAction* deleteDriverPackageAction = menu.addAction(QStringLiteral("删除驱动包..."));
    menu.addSeparator();
    QAction* refreshAction = menu.addAction(QStringLiteral("刷新"));

    const bool kHasOemInf = !normalizeOemInfName(entryPointer->driverInfPathText).isEmpty();
    deleteDriverPackageAction->setEnabled(kHasOemInf);
    if (!kHasOemInf)
    {
        deleteDriverPackageAction->setToolTip(QStringLiteral("仅支持删除 oem*.inf 第三方驱动包。"));
    }

    QAction* selectedAction = menu.exec(deviceTree_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == propertiesAction)
    {
        showSelectedDeviceProperties();
    }
    else if (selectedAction == driverDetailsAction)
    {
        showSelectedDeviceDriverDetails();
    }
    else if (selectedAction == copyInstanceIdAction)
    {
        copySelectedDeviceInstanceId();
    }
    else if (selectedAction == uninstallDeviceAction)
    {
        uninstallSelectedDevice();
    }
    else if (selectedAction == deleteDriverPackageAction)
    {
        deleteSelectedDeviceDriverPackage();
    }
    else if (selectedAction == refreshAction)
    {
        refreshDevicesAsync(true);
    }
}

void HardwareDeviceManagerPage::showSelectedDeviceProperties()
{
    // Input: Currently selected device.
    // Note: Display device properties using the current snapshot to avoid UI thread blocking caused by re-enumeration.
    // Return value: None.
    const DeviceEntry* entryPointer = selectedDeviceEntry();
    if (entryPointer == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("设备属性"), QStringLiteral("请先选择一个设备。"));
        return;
    }

    showTextDialog(
        this,
        QStringLiteral("设备属性 - %1").arg(safeDisplayText(entryPointer->nameText)),
        buildDevicePropertiesText(*entryPointer));
}

void HardwareDeviceManagerPage::showSelectedDeviceDriverDetails()
{
    // Input: Currently selected device.
    // Processing: Display driver details including service, INF, Provider, Version, and service image path.
    // Return value: None.
    const DeviceEntry* entryPointer = selectedDeviceEntry();
    if (entryPointer == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("驱动程序详细信息"), QStringLiteral("请先选择一个设备。"));
        return;
    }

    showTextDialog(
        this,
        QStringLiteral("驱动程序详细信息 - %1").arg(safeDisplayText(entryPointer->nameText)),
        buildDriverDetailsText(*entryPointer));
}

void HardwareDeviceManagerPage::copySelectedDeviceInstanceId()
{
    // Input: Currently selected device.
    // Processing: Copy Instance ID to system clipboard and update status bar text.
    // Return value: None.
    const DeviceEntry* entryPointer = selectedDeviceEntry();
    if (entryPointer == nullptr || entryPointer->instanceIdText.trimmed().isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("复制 Instance ID"), QStringLiteral("当前设备没有可复制的 Instance ID。"));
        return;
    }

    QClipboard* clipboard = QApplication::clipboard();
    if (clipboard != nullptr)
    {
        clipboard->setText(entryPointer->instanceIdText);
    }
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(QStringLiteral("已复制 Instance ID：%1").arg(entryPointer->instanceIdText));
    }
}

void HardwareDeviceManagerPage::uninstallSelectedDevice()
{
    // Input: Currently selected device.
    // Processing: Check administrator privileges and confirm again before calling SetupAPI DIF_REMOVE to unload the device node.
    // Return value: None.
    const DeviceEntry* entryPointer = selectedDeviceEntry();
    if (entryPointer == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("卸载设备"), QStringLiteral("请先选择一个设备。"));
        return;
    }
    if (!currentProcessIsElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("卸载设备"));
        return;
    }

    // targetInstanceIdText usage:
    // - During the confirmation dialog and background task, m_deviceList may be entirely replaced by a new snapshot, causing entryPointer to become invalid.
    // - Therefore, copy all information required for driver unloading by value first; subsequent flows will no longer dereference the snapshot pointer.
    const QString kTargetInstanceIdText = entryPointer->instanceIdText;
    const QString kTargetDeviceNameText = safeDisplayText(entryPointer->nameText);

    const QString kConfirmText = QStringLiteral(
        "确定要卸载此设备吗？\n\n"
        "名称：%1\n"
        "Instance ID：\n%2\n\n"
        "该操作可能导致设备暂时不可用，并可能要求重启。")
        .arg(kTargetDeviceNameText, safeDisplayText(kTargetInstanceIdText));
    if (QMessageBox::question(
        this,
        QStringLiteral("确认卸载设备"),
        kConfirmText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    // Reuse refresh mutex: prevent concurrent access to the same DevNode by background enumeration and this operation during driver unloading.
    bool expectedRefreshingValue = false;
    if (!refreshing_.compare_exchange_strong(expectedRefreshingValue, true))
    {
        if (statusLabel_ != nullptr)
        {
            statusLabel_->setText(QStringLiteral("正在刷新，请等待当前枚举完成。"));
        }
        return;
    }

    // applicationContext shares the lifetime of the event loop; worker threads do not dereference page pointers but only return results to the main thread.
    QObject* const kApplicationContext = QCoreApplication::instance();
    if (kApplicationContext == nullptr)
    {
        refreshing_.store(false);
        return;
    }

    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(QStringLiteral("正在卸载设备，请稍候..."));
    }
    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(false);
    }
    if (showAllDevicesCheck_ != nullptr)
    {
        showAllDevicesCheck_->setEnabled(false);
    }

    const QPointer<HardwareDeviceManagerPage> kSafeThis(this);
    std::thread([kApplicationContext, kSafeThis, kTargetInstanceIdText]()
    {
        // DIF_REMOVE loads class installers and coprocessors, which may use COM;
        // Note: The worker thread must create and pair-release a single-threaded apartment; COM pointers are not passed across threads.
        const HRESULT kComInitializeStatus = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

        QString errorText;
        const bool kUninstallOk = uninstallDeviceByInstanceId(kTargetInstanceIdText, &errorText);

        if (SUCCEEDED(kComInitializeStatus))
        {
            CoUninitialize();
        }

        QMetaObject::invokeMethod(
            kApplicationContext,
            [kSafeThis, kUninstallOk, errorText]()
            {
                if (kSafeThis.isNull())
                {
                    return;
                }

                HardwareDeviceManagerPage* const kPagePointer = kSafeThis.data();
                kPagePointer->refreshing_.store(false);
                if (kPagePointer->refreshButton_ != nullptr)
                {
                    kPagePointer->refreshButton_->setEnabled(true);
                }
                if (kPagePointer->showAllDevicesCheck_ != nullptr)
                {
                    kPagePointer->showAllDevicesCheck_->setEnabled(true);
                }

                if (!kUninstallOk)
                {
                    if (kPagePointer->statusLabel_ != nullptr)
                    {
                        kPagePointer->statusLabel_->setText(QStringLiteral("卸载设备失败"));
                    }

                    // privilegePromptHandled: Records whether the device unloading failure has been handled by the privilege recovery flow.
                    const bool kPrivilegePromptHandled =
                        ks::ui::promptForPrivilegeFailure(
                            kPagePointer,
                            QStringLiteral("卸载设备"),
                            errorText);
                    if (!kPrivilegePromptHandled)
                    {
                        QMessageBox::critical(
                            kPagePointer,
                            QStringLiteral("卸载设备失败"),
                            errorText.isEmpty() ? QStringLiteral("未知错误。") : errorText);
                    }
                    return;
                }

                QMessageBox::information(
                    kPagePointer,
                    QStringLiteral("卸载设备"),
                    QStringLiteral("设备卸载请求已提交。若设备仍显示或状态未变化，请刷新或重启系统。"));
                kPagePointer->refreshDevicesAsync(true);
            },
            Qt::QueuedConnection);
    }).detach();
}

void HardwareDeviceManagerPage::deleteSelectedDeviceDriverPackage()
{
    // Input: Currently selected device.
    // Processing: Check for administrator privileges and confirm deletion of the oem*.inf driver package after secondary confirmation.
    // Return value: None.
    const DeviceEntry* entryPointer = selectedDeviceEntry();
    if (entryPointer == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("删除驱动包"), QStringLiteral("请先选择一个设备。"));
        return;
    }
    if (!currentProcessIsElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("删除驱动包"));
        return;
    }

    const QString kOemInfName = normalizeOemInfName(entryPointer->driverInfPathText);
    if (kOemInfName.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("删除驱动包"),
            QStringLiteral("当前设备没有可删除的 oem*.inf 第三方驱动包。"));
        return;
    }

    // targetDeviceNameText usage: snapshot in confirmation dialog and background task may be replaced; capture value before proceeding.
    const QString kTargetDeviceNameText = safeDisplayText(entryPointer->nameText);

    const QString kConfirmText = QStringLiteral(
        "确定要从 Driver Store 删除此驱动包吗？\n\n"
        "设备：%1\n"
        "INF：%2\n\n"
        "建议先卸载设备，再删除驱动包。该操作可能影响同包驱动的其它设备。")
        .arg(kTargetDeviceNameText, kOemInfName);
    if (QMessageBox::question(
        this,
        QStringLiteral("确认删除驱动包"),
        kConfirmText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    // Reuse the refresh mutex flag: prevent background enumeration and concurrent access to the Driver Store during driver package removal.
    bool expectedRefreshingValue = false;
    if (!refreshing_.compare_exchange_strong(expectedRefreshingValue, true))
    {
        if (statusLabel_ != nullptr)
        {
            statusLabel_->setText(QStringLiteral("正在刷新，请等待当前枚举完成。"));
        }
        return;
    }

    // applicationContext shares the lifetime of the event loop; worker threads do not dereference page pointers but only return results to the main thread.
    QObject* const kApplicationContext = QCoreApplication::instance();
    if (kApplicationContext == nullptr)
    {
        refreshing_.store(false);
        return;
    }

    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(QStringLiteral("正在删除驱动包，请稍候..."));
    }
    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(false);
    }
    if (showAllDevicesCheck_ != nullptr)
    {
        showAllDevicesCheck_->setEnabled(false);
    }

    const QPointer<HardwareDeviceManagerPage> kSafeThis(this);
    std::thread([kApplicationContext, kSafeThis, kOemInfName]()
    {
        // SetupUninstallOEMInfW triggers the Driver Store cleanup process, which may internally use COM.
        // Worker thread creates its own single-threaded apartment and pairs it for release; COM pointers are not passed across threads.
        const HRESULT kComInitializeStatus = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

        QString errorText;
        const bool kDeleteOk = uninstallOemInfPackage(kOemInfName, &errorText);

        if (SUCCEEDED(kComInitializeStatus))
        {
            CoUninitialize();
        }

        QMetaObject::invokeMethod(
            kApplicationContext,
            [kSafeThis, kOemInfName, kDeleteOk, errorText]()
            {
                if (kSafeThis.isNull())
                {
                    return;
                }

                HardwareDeviceManagerPage* const kPagePointer = kSafeThis.data();
                kPagePointer->refreshing_.store(false);
                if (kPagePointer->refreshButton_ != nullptr)
                {
                    kPagePointer->refreshButton_->setEnabled(true);
                }
                if (kPagePointer->showAllDevicesCheck_ != nullptr)
                {
                    kPagePointer->showAllDevicesCheck_->setEnabled(true);
                }

                if (!kDeleteOk)
                {
                    if (kPagePointer->statusLabel_ != nullptr)
                    {
                        kPagePointer->statusLabel_->setText(QStringLiteral("删除驱动包失败"));
                    }

                    // privilegePromptHandled: Records whether the driver package deletion failure has been handled by the privilege recovery flow.
                    const bool kPrivilegePromptHandled =
                        ks::ui::promptForPrivilegeFailure(
                            kPagePointer,
                            QStringLiteral("删除驱动包"),
                            errorText);
                    if (!kPrivilegePromptHandled)
                    {
                        QMessageBox::critical(
                            kPagePointer,
                            QStringLiteral("删除驱动包失败"),
                            errorText.isEmpty() ? QStringLiteral("未知错误。") : errorText);
                    }
                    return;
                }

                QMessageBox::information(
                    kPagePointer,
                    QStringLiteral("删除驱动包"),
                    QStringLiteral("驱动包已删除：%1").arg(kOemInfName));
                kPagePointer->refreshDevicesAsync(true);
            },
            Qt::QueuedConnection);
    }).detach();
}

std::vector<HardwareDeviceManagerPage::DeviceEntry>
HardwareDeviceManagerPage::enumerateDevicesSnapshot(const bool includeAllDevices)
{
    std::vector<DeviceEntry> resultList;

    const DWORD kFlags = DIGCF_ALLCLASSES | (includeAllDevices ? 0U : DIGCF_PRESENT);
    HDEVINFO deviceInfoSet = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, kFlags);
    if (deviceInfoSet == INVALID_HANDLE_VALUE)
    {
        return resultList;
    }

    for (DWORD index = 0;; ++index)
    {
        SP_DEVINFO_DATA deviceInfoData{};
        deviceInfoData.cbSize = sizeof(deviceInfoData);
        if (!SetupDiEnumDeviceInfo(deviceInfoSet, index, &deviceInfoData))
        {
            break;
        }

        DeviceEntry entry;
        entry.nameText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_FriendlyName);
        if (entry.nameText.isEmpty())
        {
            entry.nameText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_DeviceDesc);
        }
        entry.manufacturerText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_Manufacturer);
        entry.serviceText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_Service);
        entry.classText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_Class);
        entry.enumeratorText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_EnumeratorName);
        entry.installedText = propertyFileTimeText(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_InstallDate);
        entry.instanceIdText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_InstanceId);
        entry.parentInstanceIdText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_Parent);
        entry.classGuidText = propertyGuidText(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_ClassGuid);
        entry.driverText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_Driver);
        if (entry.driverText.isEmpty())
        {
            entry.driverText = registryPropertyString(deviceInfoSet, &deviceInfoData, SPDRP_DRIVER);
        }
        entry.driverInfPathText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_DriverInfPath);
        entry.driverProviderText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_DriverProvider);
        entry.driverVersionText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_DriverVersion);
        entry.driverDateText = propertyFileTimeText(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_DriverDate);
        entry.driverRegistryPathText = driverRegistryPathFromClassKey(entry.classGuidText, entry.driverText);
        if (!entry.driverInfPathText.isEmpty())
        {
            entry.driverText = entry.driverText.isEmpty()
                ? entry.driverInfPathText
                : QStringLiteral("%1 | INF=%2").arg(entry.driverText, entry.driverInfPathText);
        }
        entry.locationText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_LocationInfo);
        entry.hardwareIdsText = propertyStringList(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_HardwareIds);
        entry.compatibleIdsText = propertyStringList(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_CompatibleIds);
        entry.serviceImagePathText = serviceImagePath(entry.serviceText);
        entry.isPresent = propertyBool(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_IsPresent);
        if (!includeAllDevices)
        {
            entry.isPresent = true;
        }
        entry.problemCode = propertyUInt32(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_ProblemCode);
        entry.hasProblem = propertyBool(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_HasProblem)
            || entry.problemCode != 0;

        ULONG statusFlags = 0;
        ULONG problemCode = entry.problemCode;
        if (CM_Get_DevNode_Status(&statusFlags, &problemCode, deviceInfoData.DevInst, 0) == CR_SUCCESS)
        {
            entry.problemCode = problemCode;
            entry.hasProblem = entry.hasProblem || ((statusFlags & DN_HAS_PROBLEM) != 0) || problemCode != 0;
            entry.statusText = deviceStatusText(statusFlags, problemCode);
        }
        if (entry.problemCode != 0)
        {
            entry.problemText = QStringLiteral("CM_PROB=%1").arg(entry.problemCode);
        }

        if (entry.instanceIdText.isEmpty())
        {
            entry.instanceIdText = instanceIdFromDevInst(deviceInfoData.DevInst);
        }
        if (!entry.instanceIdText.isEmpty())
        {
            resultList.push_back(std::move(entry));
        }
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);
    std::sort(
        resultList.begin(),
        resultList.end(),
        [](const DeviceEntry& left, const DeviceEntry& right)
        {
            return QString::localeAwareCompare(left.nameText, right.nameText) < 0;
        });
    return resultList;
}
