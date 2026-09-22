#include "HandleDock.h"
#include "../../../shared/ark_client/ArkDriverClient.h"

// ============================================================
// HandleDock.DetailNative.cpp
// Purpose:
// - Carries the semantics decoding for GrantedAccess;
// - Parse the native type branch for handle details;
// - Separated from the main Native file to avoid excessive single-file length.
// ============================================================

#include <QChar>
#include <QStringList>

#include <chrono>
#include <cstdint>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <sddl.h>

namespace
{
    // wideToQString:
    // - Convert the std::wstring returned by ArkDriverClient to QString;
    // - Empty strings remain empty; the caller decides whether to display "No Name" or "Not Returned".
    QString wideToQString(const std::wstring& text)
    {
        if (text.empty())
        {
            return {};
        }
        return QString::fromWCharArray(text.c_str(), static_cast<int>(text.size()));
    }

    // ntStatusHex: Formats NTSTATUS/Win32 long status codes uniformly as 0xXXXXXXXX.
    QString ntStatusHex(const long status)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(status), 8, 16, QChar('0'))
            .toUpper();
    }

    // friendlyHandleIoMessage:
    // - Convert the low-level message returned by ArkDriverClient/IOCTL into a human-readable description for the detail page;
    // - Input messageText: raw narrow string from IoResult::message;
    // - Returns: A short Chinese string to avoid directly displaying DeviceIoControl/raw logs in the Object Header table.
    QString friendlyHandleIoMessage(const std::string& messageText)
    {
        const QString kRawText = QString::fromUtf8(messageText.data(), static_cast<int>(messageText.size())).trimmed();
        if (kRawText.isEmpty())
        {
            return QStringLiteral("驱动未返回额外说明。");
        }
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该句柄对象详情入口。");
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动不支持该句柄对象详情查询。");
        }
        if (kRawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return QStringLiteral("动态偏移能力不足，无法安全解码该句柄对象详情。");
        }
        if (kRawText.contains(QStringLiteral("access"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("denied"), Qt::CaseInsensitive))
        {
            return QStringLiteral("访问被系统策略或目标对象权限限制，已保留可用的只读证据。");
        }
        return kRawText;
    }

    // objectQueryStatusText: Converts R0 object query status to human-readable text for the detail page.
    QString objectQueryStatusText(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_OBJECT_QUERY_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_OBJECT_QUERY_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_OBJECT_QUERY_STATUS_DYNDATA_MISSING:
            return QStringLiteral("DynData Missing");
        case KSWORD_ARK_OBJECT_QUERY_STATUS_PROCESS_LOOKUP_FAILED:
            return QStringLiteral("Process Lookup Failed");
        case KSWORD_ARK_OBJECT_QUERY_STATUS_HANDLE_REFERENCE_FAILED:
            return QStringLiteral("Handle Reference Failed");
        case KSWORD_ARK_OBJECT_QUERY_STATUS_TYPE_QUERY_FAILED:
            return QStringLiteral("Type Query Failed");
        case KSWORD_ARK_OBJECT_QUERY_STATUS_NAME_QUERY_FAILED:
            return QStringLiteral("Name Query Failed");
        case KSWORD_ARK_OBJECT_QUERY_STATUS_NAME_TRUNCATED:
            return QStringLiteral("Name Truncated");
        case KSWORD_ARK_OBJECT_QUERY_STATUS_UNAVAILABLE:
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // Purpose of proxyStatusText: Convert restricted proxy handle policy status to readable text.
    QString proxyStatusText(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_OBJECT_PROXY_STATUS_OPENED:
            return QStringLiteral("Opened then closed (diagnostic only)");
        case KSWORD_ARK_OBJECT_PROXY_STATUS_DENIED_BY_POLICY:
            return QStringLiteral("Denied by policy");
        case KSWORD_ARK_OBJECT_PROXY_STATUS_OPEN_FAILED:
            return QStringLiteral("Open failed");
        case KSWORD_ARK_OBJECT_PROXY_STATUS_REQUESTOR_FAILED:
            return QStringLiteral("Requestor failed");
        case KSWORD_ARK_OBJECT_PROXY_STATUS_NOT_REQUESTED:
        default:
            return QStringLiteral("Not requested");
        }
    }

    // alpcQueryStatusText: converts R0 ALPC query status codes into human-readable text for the details page.
    QString alpcQueryStatusText(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_ALPC_QUERY_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_ALPC_QUERY_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_ALPC_QUERY_STATUS_DYNDATA_MISSING:
            return QStringLiteral("DynData Missing");
        case KSWORD_ARK_ALPC_QUERY_STATUS_PROCESS_LOOKUP_FAILED:
            return QStringLiteral("Process Lookup Failed");
        case KSWORD_ARK_ALPC_QUERY_STATUS_HANDLE_REFERENCE_FAILED:
            return QStringLiteral("Handle Reference Failed");
        case KSWORD_ARK_ALPC_QUERY_STATUS_TYPE_MISMATCH:
            return QStringLiteral("Type Mismatch");
        case KSWORD_ARK_ALPC_QUERY_STATUS_BASIC_QUERY_FAILED:
            return QStringLiteral("Basic Query Failed");
        case KSWORD_ARK_ALPC_QUERY_STATUS_COMMUNICATION_FAILED:
            return QStringLiteral("Communication Query Failed");
        case KSWORD_ARK_ALPC_QUERY_STATUS_NAME_QUERY_FAILED:
            return QStringLiteral("Name Query Failed");
        case KSWORD_ARK_ALPC_QUERY_STATUS_NAME_TRUNCATED:
            return QStringLiteral("Name Truncated");
        case KSWORD_ARK_ALPC_QUERY_STATUS_UNAVAILABLE:
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // isAlpcPortTypeName: Identifies the object type name in handle details that should attempt an R0 ALPC query.
    bool isAlpcPortTypeName(const QString& typeName)
    {
        const QString kNormalizedType = typeName.trimmed().toLower();
        return kNormalizedType == QStringLiteral("alpc port") ||
            kNormalizedType == QStringLiteral("port") ||
            kNormalizedType.contains(QStringLiteral("alpc"));
    }

    // alpcPortPresent: Determines if a relation port exists based on response field flags.
    bool alpcPortPresent(const std::uint32_t responseFieldFlags, const std::uint32_t relation)
    {
        switch (relation)
        {
        case KSWORD_ARK_ALPC_PORT_RELATION_QUERY:
            return (responseFieldFlags & KSWORD_ARK_ALPC_RESPONSE_FIELD_QUERY_PORT_PRESENT) != 0U;
        case KSWORD_ARK_ALPC_PORT_RELATION_CONNECTION:
            return (responseFieldFlags & KSWORD_ARK_ALPC_RESPONSE_FIELD_CONNECTION_PRESENT) != 0U;
        case KSWORD_ARK_ALPC_PORT_RELATION_SERVER:
            return (responseFieldFlags & KSWORD_ARK_ALPC_RESPONSE_FIELD_SERVER_PRESENT) != 0U;
        case KSWORD_ARK_ALPC_PORT_RELATION_CLIENT:
            return (responseFieldFlags & KSWORD_ARK_ALPC_RESPONSE_FIELD_CLIENT_PRESENT) != 0U;
        default:
            return false;
        }
    }

    // alpcRelationTitle purpose: Convert ALPC relation enums to Chinese title prefixes.
    QString alpcRelationTitle(const std::uint32_t relation)
    {
        switch (relation)
        {
        case KSWORD_ARK_ALPC_PORT_RELATION_QUERY:
            return QStringLiteral("ALPC当前端口");
        case KSWORD_ARK_ALPC_PORT_RELATION_CONNECTION:
            return QStringLiteral("ALPC连接端口");
        case KSWORD_ARK_ALPC_PORT_RELATION_SERVER:
            return QStringLiteral("ALPC服务端通信端口");
        case KSWORD_ARK_ALPC_PORT_RELATION_CLIENT:
            return QStringLiteral("ALPC客户端通信端口");
        default:
            return QStringLiteral("ALPC未知端口");
        }
    }
}

QString HandleDock::decodeGrantedAccessText(const QString& typeName, const std::uint32_t grantedAccess)
{
    QStringList accessTextList;

    // Decode common permission bits uniformly to ensure standard permissions are visible across different object types.
    if ((grantedAccess & DELETE) != 0) accessTextList.push_back(QStringLiteral("DELETE"));
    if ((grantedAccess & READ_CONTROL) != 0) accessTextList.push_back(QStringLiteral("READ_CONTROL"));
    if ((grantedAccess & WRITE_DAC) != 0) accessTextList.push_back(QStringLiteral("WRITE_DAC"));
    if ((grantedAccess & WRITE_OWNER) != 0) accessTextList.push_back(QStringLiteral("WRITE_OWNER"));
    if ((grantedAccess & SYNCHRONIZE) != 0) accessTextList.push_back(QStringLiteral("SYNCHRONIZE"));
    if ((grantedAccess & ACCESS_SYSTEM_SECURITY) != 0) accessTextList.push_back(QStringLiteral("ACCESS_SYSTEM_SECURITY"));
    if ((grantedAccess & GENERIC_READ) != 0) accessTextList.push_back(QStringLiteral("GENERIC_READ"));
    if ((grantedAccess & GENERIC_WRITE) != 0) accessTextList.push_back(QStringLiteral("GENERIC_WRITE"));
    if ((grantedAccess & GENERIC_EXECUTE) != 0) accessTextList.push_back(QStringLiteral("GENERIC_EXECUTE"));
    if ((grantedAccess & GENERIC_ALL) != 0) accessTextList.push_back(QStringLiteral("GENERIC_ALL"));

    const QString kNormalizedType = typeName.trimmed().toLower();
    const auto kAppendIf = [&accessTextList, grantedAccess](const std::uint32_t maskValue, const QString& nameText)
        {
            if ((grantedAccess & maskValue) != 0)
            {
                accessTextList.push_back(nameText);
            }
        };

    if (kNormalizedType == QStringLiteral("file") || kNormalizedType == QStringLiteral("directory"))
    {
        kAppendIf(FILE_READ_DATA, QStringLiteral("FILE_READ_DATA/LIST_DIRECTORY"));
        kAppendIf(FILE_WRITE_DATA, QStringLiteral("FILE_WRITE_DATA/ADD_FILE"));
        kAppendIf(FILE_APPEND_DATA, QStringLiteral("FILE_APPEND_DATA/ADD_SUBDIR"));
        kAppendIf(FILE_READ_EA, QStringLiteral("FILE_READ_EA"));
        kAppendIf(FILE_WRITE_EA, QStringLiteral("FILE_WRITE_EA"));
        kAppendIf(FILE_EXECUTE, QStringLiteral("FILE_EXECUTE/TRAVERSE"));
        kAppendIf(FILE_DELETE_CHILD, QStringLiteral("FILE_DELETE_CHILD"));
        kAppendIf(FILE_READ_ATTRIBUTES, QStringLiteral("FILE_READ_ATTRIBUTES"));
        kAppendIf(FILE_WRITE_ATTRIBUTES, QStringLiteral("FILE_WRITE_ATTRIBUTES"));
    }
    else if (kNormalizedType == QStringLiteral("key"))
    {
        kAppendIf(KEY_QUERY_VALUE, QStringLiteral("KEY_QUERY_VALUE"));
        kAppendIf(KEY_SET_VALUE, QStringLiteral("KEY_SET_VALUE"));
        kAppendIf(KEY_CREATE_SUB_KEY, QStringLiteral("KEY_CREATE_SUB_KEY"));
        kAppendIf(KEY_ENUMERATE_SUB_KEYS, QStringLiteral("KEY_ENUMERATE_SUB_KEYS"));
        kAppendIf(KEY_NOTIFY, QStringLiteral("KEY_NOTIFY"));
        kAppendIf(KEY_CREATE_LINK, QStringLiteral("KEY_CREATE_LINK"));
        kAppendIf(KEY_WOW64_32KEY, QStringLiteral("KEY_WOW64_32KEY"));
        kAppendIf(KEY_WOW64_64KEY, QStringLiteral("KEY_WOW64_64KEY"));
    }
    else if (kNormalizedType == QStringLiteral("process"))
    {
        kAppendIf(PROCESS_TERMINATE, QStringLiteral("PROCESS_TERMINATE"));
        kAppendIf(PROCESS_CREATE_THREAD, QStringLiteral("PROCESS_CREATE_THREAD"));
        kAppendIf(PROCESS_SET_SESSIONID, QStringLiteral("PROCESS_SET_SESSIONID"));
        kAppendIf(PROCESS_VM_OPERATION, QStringLiteral("PROCESS_VM_OPERATION"));
        kAppendIf(PROCESS_VM_READ, QStringLiteral("PROCESS_VM_READ"));
        kAppendIf(PROCESS_VM_WRITE, QStringLiteral("PROCESS_VM_WRITE"));
        kAppendIf(PROCESS_DUP_HANDLE, QStringLiteral("PROCESS_DUP_HANDLE"));
        kAppendIf(PROCESS_CREATE_PROCESS, QStringLiteral("PROCESS_CREATE_PROCESS"));
        kAppendIf(PROCESS_SET_QUOTA, QStringLiteral("PROCESS_SET_QUOTA"));
        kAppendIf(PROCESS_SET_INFORMATION, QStringLiteral("PROCESS_SET_INFORMATION"));
        kAppendIf(PROCESS_QUERY_INFORMATION, QStringLiteral("PROCESS_QUERY_INFORMATION"));
        kAppendIf(PROCESS_SUSPEND_RESUME, QStringLiteral("PROCESS_SUSPEND_RESUME"));
        kAppendIf(PROCESS_QUERY_LIMITED_INFORMATION, QStringLiteral("PROCESS_QUERY_LIMITED_INFORMATION"));
    }
    else if (kNormalizedType == QStringLiteral("thread"))
    {
        kAppendIf(THREAD_TERMINATE, QStringLiteral("THREAD_TERMINATE"));
        kAppendIf(THREAD_SUSPEND_RESUME, QStringLiteral("THREAD_SUSPEND_RESUME"));
        kAppendIf(THREAD_GET_CONTEXT, QStringLiteral("THREAD_GET_CONTEXT"));
        kAppendIf(THREAD_SET_CONTEXT, QStringLiteral("THREAD_SET_CONTEXT"));
        kAppendIf(THREAD_SET_INFORMATION, QStringLiteral("THREAD_SET_INFORMATION"));
        kAppendIf(THREAD_QUERY_INFORMATION, QStringLiteral("THREAD_QUERY_INFORMATION"));
        kAppendIf(THREAD_SET_THREAD_TOKEN, QStringLiteral("THREAD_SET_THREAD_TOKEN"));
        kAppendIf(THREAD_IMPERSONATE, QStringLiteral("THREAD_IMPERSONATE"));
        kAppendIf(THREAD_DIRECT_IMPERSONATION, QStringLiteral("THREAD_DIRECT_IMPERSONATION"));
        kAppendIf(THREAD_SET_LIMITED_INFORMATION, QStringLiteral("THREAD_SET_LIMITED_INFORMATION"));
        kAppendIf(THREAD_QUERY_LIMITED_INFORMATION, QStringLiteral("THREAD_QUERY_LIMITED_INFORMATION"));
    }
    else if (kNormalizedType == QStringLiteral("token"))
    {
        kAppendIf(TOKEN_ASSIGN_PRIMARY, QStringLiteral("TOKEN_ASSIGN_PRIMARY"));
        kAppendIf(TOKEN_DUPLICATE, QStringLiteral("TOKEN_DUPLICATE"));
        kAppendIf(TOKEN_IMPERSONATE, QStringLiteral("TOKEN_IMPERSONATE"));
        kAppendIf(TOKEN_QUERY, QStringLiteral("TOKEN_QUERY"));
        kAppendIf(TOKEN_QUERY_SOURCE, QStringLiteral("TOKEN_QUERY_SOURCE"));
        kAppendIf(TOKEN_ADJUST_PRIVILEGES, QStringLiteral("TOKEN_ADJUST_PRIVILEGES"));
        kAppendIf(TOKEN_ADJUST_GROUPS, QStringLiteral("TOKEN_ADJUST_GROUPS"));
        kAppendIf(TOKEN_ADJUST_DEFAULT, QStringLiteral("TOKEN_ADJUST_DEFAULT"));
        kAppendIf(TOKEN_ADJUST_SESSIONID, QStringLiteral("TOKEN_ADJUST_SESSIONID"));
    }
    else if (kNormalizedType == QStringLiteral("section"))
    {
        kAppendIf(SECTION_QUERY, QStringLiteral("SECTION_QUERY"));
        kAppendIf(SECTION_MAP_WRITE, QStringLiteral("SECTION_MAP_WRITE"));
        kAppendIf(SECTION_MAP_READ, QStringLiteral("SECTION_MAP_READ"));
        kAppendIf(SECTION_MAP_EXECUTE, QStringLiteral("SECTION_MAP_EXECUTE"));
        kAppendIf(SECTION_EXTEND_SIZE, QStringLiteral("SECTION_EXTEND_SIZE"));
    }
    else if (kNormalizedType == QStringLiteral("event"))
    {
        kAppendIf(0x0001U, QStringLiteral("EVENT_QUERY_STATE"));
        kAppendIf(EVENT_MODIFY_STATE, QStringLiteral("EVENT_MODIFY_STATE"));
    }
    else if (kNormalizedType == QStringLiteral("mutant"))
    {
        kAppendIf(MUTANT_QUERY_STATE, QStringLiteral("MUTANT_QUERY_STATE"));
    }
    else if (kNormalizedType == QStringLiteral("semaphore"))
    {
        kAppendIf(0x0001U, QStringLiteral("SEMAPHORE_QUERY_STATE"));
        kAppendIf(SEMAPHORE_MODIFY_STATE, QStringLiteral("SEMAPHORE_MODIFY_STATE"));
    }
    else if (kNormalizedType == QStringLiteral("timer"))
    {
        kAppendIf(TIMER_QUERY_STATE, QStringLiteral("TIMER_QUERY_STATE"));
        kAppendIf(TIMER_MODIFY_STATE, QStringLiteral("TIMER_MODIFY_STATE"));
    }

    accessTextList.removeDuplicates();
    if (accessTextList.isEmpty())
    {
        return QStringLiteral("-");
    }
    return accessTextList.join(QStringLiteral(" | "));
}

HandleDock::HandleDetailRefreshResult HandleDock::buildHandleDetailRefreshResult(const HandleRow& row)
{
    HandleDetailRefreshResult result{};
    const auto kBeginTime = std::chrono::steady_clock::now();

    auto addField = [&result](const QString& keyText, const QString& valueText)
        {
            HandleDetailField field{};
            field.keyText = keyText;
            field.valueText = valueText;
            result.fields.push_back(std::move(field));
        };

    addField(QStringLiteral("Object Header Snapshot"), QStringLiteral("Read only"));
    addField(QStringLiteral("PID"), QString::number(row.processId));
    addField(QStringLiteral("进程名"), row.processName);
    addField(QStringLiteral("句柄值"), formatHex(row.handleValue, 0));
    addField(QStringLiteral("对象地址"), formatHex(row.objectAddress, 0));
    addField(QStringLiteral("对象类型索引"), QString::number(row.typeIndex));
    addField(QStringLiteral("对象类型"), row.typeName);
    addField(QStringLiteral("对象名"), formatObjectNameDisplayText(row));
    addField(QStringLiteral("访问掩码"), formatHex(row.grantedAccess, 8));
    addField(QStringLiteral("访问掩码语义"), decodeGrantedAccessText(row.typeName, row.grantedAccess));
    addField(QStringLiteral("属性"), formatHandleAttributes(row.attributes));
    addField(QStringLiteral("HandleCount"), formatOptionalObjectCount(row.handleCount, row.basicInfoAvailable));
    addField(QStringLiteral("PointerCount"), formatOptionalObjectCount(row.pointerCount, row.basicInfoAvailable));
    addField(QStringLiteral("来源"), formatHandleSourceText(row.sourceMode));
    addField(QStringLiteral("解码状态"), formatHandleDecodeStatusText(row.decodeStatus));
    addField(QStringLiteral("差异状态"), formatHandleDiffStatusText(row.diffStatus));
    addField(QStringLiteral("风险标记"), QStringLiteral("%1 / %2")
        .arg(formatHandleDiffStatusText(row.diffStatus))
        .arg(formatHandleDecodeStatusText(row.decodeStatus)));
    addField(QStringLiteral("R0字段位"), formatHex(row.r0FieldFlags, 8));
    addField(QStringLiteral("DynData Capability"), formatHex(row.r0DynDataCapabilityMask, 0));
    addField(QStringLiteral("EPROCESS.ObjectTable偏移"), formatHex(row.epObjectTableOffset, 0));
    addField(QStringLiteral("HandleContentionEvent偏移"), formatHex(row.htHandleContentionEventOffset, 0));
    addField(QStringLiteral("ObDecodeShift"), QString::number(row.obDecodeShift));
    addField(QStringLiteral("ObAttributesShift"), QString::number(row.obAttributesShift));
    addField(QStringLiteral("OBJECT_TYPE.Name偏移"), formatHex(row.otNameOffset, 0));
    addField(QStringLiteral("OBJECT_TYPE.Index偏移"), formatHex(row.otIndexOffset, 0));

    {
        const auto kR0ObjectResult = ksword::ark::DriverClient().queryHandleObject(
            row.processId,
            row.handleValue,
            KSWORD_ARK_QUERY_OBJECT_FLAG_INCLUDE_ALL,
            row.grantedAccess);
        addField(QStringLiteral("R0对象查询说明"), friendlyHandleIoMessage(kR0ObjectResult.io.message));
        if (kR0ObjectResult.io.ok)
        {
            const QString kR0TypeName = wideToQString(kR0ObjectResult.typeName);
            const QString kR0ObjectName = wideToQString(kR0ObjectResult.objectName);
            addField(QStringLiteral("R0查询状态"), objectQueryStatusText(kR0ObjectResult.queryStatus));
            addField(QStringLiteral("R0对象引用状态"), ntStatusHex(kR0ObjectResult.objectReferenceStatus));
            addField(QStringLiteral("R0类型状态"), ntStatusHex(kR0ObjectResult.typeStatus));
            addField(QStringLiteral("R0名称状态"), ntStatusHex(kR0ObjectResult.nameStatus));
            addField(QStringLiteral("R0对象地址"), formatHex(kR0ObjectResult.objectAddress, 0));
            addField(QStringLiteral("R0对象类型索引"), QString::number(kR0ObjectResult.objectTypeIndex));
            addField(QStringLiteral("R0对象类型名"), kR0TypeName.isEmpty() ? QStringLiteral("未返回") : kR0TypeName);
            addField(QStringLiteral("R0对象名"), kR0ObjectName.isEmpty() ? QStringLiteral("无名称/未返回") : kR0ObjectName);
            addField(QStringLiteral("R0实际授权访问"), formatHex(kR0ObjectResult.actualGrantedAccess, 8));
            addField(QStringLiteral("R0代理状态"), proxyStatusText(kR0ObjectResult.proxyStatus));
            addField(QStringLiteral("R0代理NTSTATUS"), ntStatusHex(kR0ObjectResult.proxyNtStatus));
            addField(QStringLiteral("R0代理策略位"), formatHex(kR0ObjectResult.proxyPolicyFlags, 8));
            addField(QStringLiteral("R0 OtName偏移"), formatHex(kR0ObjectResult.otNameOffset, 0));
            addField(QStringLiteral("R0 OtIndex偏移"), formatHex(kR0ObjectResult.otIndexOffset, 0));

            const QString kAlpcCandidateType = kR0TypeName.isEmpty() ? row.typeName : kR0TypeName;
            if (isAlpcPortTypeName(kAlpcCandidateType))
            {
                const auto kAlpcResult = ksword::ark::DriverClient().queryAlpcPort(
                    row.processId,
                    row.handleValue,
                    KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_ALL);
                addField(QStringLiteral("R0 ALPC查询说明"), friendlyHandleIoMessage(kAlpcResult.io.message));
                if (kAlpcResult.io.ok)
                {
                    const auto kAppendAlpcPort = [&addField](const ksword::ark::AlpcPortInfo& portInfo, const std::uint32_t responseFieldFlags)
                        {
                            // Purpose: Expands an ALPC relationship port into detail fields.
                            // Processing: Explicitly display 'Unavailable' when a field is missing, rather than leaving it blank.
                            // Returns: None; directly writes to the detail field list.
                            const QString kPrefix = alpcRelationTitle(portInfo.relation);
                            if (!alpcPortPresent(responseFieldFlags, portInfo.relation))
                            {
                                addField(kPrefix, QStringLiteral("Not present"));
                                return;
                            }

                            const QString kPortName = wideToQString(portInfo.portName);
                            addField(kPrefix + QStringLiteral(".Object"), HandleDock::formatHex(portInfo.objectAddress, 0));
                            addField(kPrefix + QStringLiteral(".OwnerPid"),
                                (portInfo.fieldFlags & KSWORD_ARK_ALPC_PORT_FIELD_OWNER_PID_PRESENT) != 0U ?
                                QString::number(portInfo.ownerProcessId) :
                                QStringLiteral("Unavailable"));
                            addField(kPrefix + QStringLiteral(".Flags"),
                                (portInfo.fieldFlags & KSWORD_ARK_ALPC_PORT_FIELD_FLAGS_PRESENT) != 0U ?
                                HandleDock::formatHex(portInfo.flags, 8) :
                                QStringLiteral("Unavailable"));
                            addField(kPrefix + QStringLiteral(".State"),
                                (portInfo.fieldFlags & KSWORD_ARK_ALPC_PORT_FIELD_STATE_PRESENT) != 0U ?
                                QString::number(portInfo.state) :
                                QStringLiteral("Unavailable"));
                            addField(kPrefix + QStringLiteral(".SequenceNo"),
                                (portInfo.fieldFlags & KSWORD_ARK_ALPC_PORT_FIELD_SEQUENCE_PRESENT) != 0U ?
                                QString::number(portInfo.sequenceNo) :
                                QStringLiteral("Unavailable"));
                            addField(kPrefix + QStringLiteral(".Context"),
                                (portInfo.fieldFlags & KSWORD_ARK_ALPC_PORT_FIELD_CONTEXT_PRESENT) != 0U ?
                                HandleDock::formatHex(portInfo.portContext, 0) :
                                QStringLiteral("Unavailable"));
                            addField(kPrefix + QStringLiteral(".Name"),
                                (portInfo.fieldFlags & KSWORD_ARK_ALPC_PORT_FIELD_NAME_PRESENT) != 0U ?
                                (kPortName.isEmpty() ? QStringLiteral("(unnamed)") : kPortName) :
                                QStringLiteral("Unavailable"));
                            addField(kPrefix + QStringLiteral(".BasicStatus"), ntStatusHex(portInfo.basicStatus));
                            addField(kPrefix + QStringLiteral(".NameStatus"), ntStatusHex(portInfo.nameStatus));
                        };

                    addField(QStringLiteral("R0 ALPC查询状态"), alpcQueryStatusText(kAlpcResult.queryStatus));
                    addField(QStringLiteral("R0 ALPC对象引用状态"), ntStatusHex(kAlpcResult.objectReferenceStatus));
                    addField(QStringLiteral("R0 ALPC类型状态"), ntStatusHex(kAlpcResult.typeStatus));
                    addField(QStringLiteral("R0 ALPC基础状态"), ntStatusHex(kAlpcResult.basicStatus));
                    addField(QStringLiteral("R0 ALPC通信状态"), ntStatusHex(kAlpcResult.communicationStatus));
                    addField(QStringLiteral("R0 ALPC名称状态"), ntStatusHex(kAlpcResult.nameStatus));
                    addField(QStringLiteral("R0 ALPC类型名"), wideToQString(kAlpcResult.typeName));
                    addField(QStringLiteral("R0 ALPC字段位"), formatHex(kAlpcResult.fieldFlags, 8));
                    addField(QStringLiteral("R0 ALPC DynData Capability"), formatHex(kAlpcResult.dynDataCapabilityMask, 0));
                    addField(QStringLiteral("R0 AlpcCommunicationInfo偏移"), formatHex(kAlpcResult.alpcCommunicationInfoOffset, 0));
                    addField(QStringLiteral("R0 AlpcOwnerProcess偏移"), formatHex(kAlpcResult.alpcOwnerProcessOffset, 0));
                    addField(QStringLiteral("R0 AlpcConnectionPort偏移"), formatHex(kAlpcResult.alpcConnectionPortOffset, 0));
                    addField(QStringLiteral("R0 AlpcServerCommunicationPort偏移"), formatHex(kAlpcResult.alpcServerCommunicationPortOffset, 0));
                    addField(QStringLiteral("R0 AlpcClientCommunicationPort偏移"), formatHex(kAlpcResult.alpcClientCommunicationPortOffset, 0));
                    addField(QStringLiteral("R0 AlpcHandleTable偏移"), formatHex(kAlpcResult.alpcHandleTableOffset, 0));
                    addField(QStringLiteral("R0 AlpcHandleTableLock偏移"), formatHex(kAlpcResult.alpcHandleTableLockOffset, 0));
                    addField(QStringLiteral("R0 AlpcAttributes偏移"), formatHex(kAlpcResult.alpcAttributesOffset, 0));
                    addField(QStringLiteral("R0 AlpcAttributesFlags偏移"), formatHex(kAlpcResult.alpcAttributesFlagsOffset, 0));
                    addField(QStringLiteral("R0 AlpcPortContext偏移"), formatHex(kAlpcResult.alpcPortContextOffset, 0));
                    addField(QStringLiteral("R0 AlpcPortObjectLock偏移"), formatHex(kAlpcResult.alpcPortObjectLockOffset, 0));
                    addField(QStringLiteral("R0 AlpcSequenceNo偏移"), formatHex(kAlpcResult.alpcSequenceNoOffset, 0));
                    addField(QStringLiteral("R0 AlpcState偏移"), formatHex(kAlpcResult.alpcStateOffset, 0));
                    kAppendAlpcPort(kAlpcResult.queryPort, kAlpcResult.fieldFlags);
                    kAppendAlpcPort(kAlpcResult.connectionPort, kAlpcResult.fieldFlags);
                    kAppendAlpcPort(kAlpcResult.serverPort, kAlpcResult.fieldFlags);
                    kAppendAlpcPort(kAlpcResult.clientPort, kAlpcResult.fieldFlags);
                }
            }
        }
    }

    if (row.diffStatus == HandleDiffStatus::kKernelOnly)
    {
        addField(QStringLiteral("风险说明"), QStringLiteral("仅内核可见，优先关注对象头与类型归属。"));
    }
    else if (row.diffStatus == HandleDiffStatus::kUserOnly)
    {
        addField(QStringLiteral("风险说明"), QStringLiteral("仅用户态可见，可能存在枚举缺口或访问限制。"));
    }
    else if (row.diffStatus == HandleDiffStatus::kNotCompared)
    {
        addField(QStringLiteral("风险说明"), QStringLiteral("当前未启用双源对比。"));
    }

    HANDLE processHandle = ::OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, row.processId);
    if (processHandle == nullptr)
    {
        processHandle = ::OpenProcess(PROCESS_DUP_HANDLE, FALSE, row.processId);
    }
    if (processHandle == nullptr)
    {
        result.diagnosticText = QStringLiteral("OpenProcess 失败，error=%1").arg(::GetLastError());
        result.elapsedMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kBeginTime).count());
        return result;
    }

    HANDLE duplicatedHandle = nullptr;
    const BOOL kDuplicateOk = ::DuplicateHandle(
        processHandle,
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(row.handleValue)),
        ::GetCurrentProcess(),
        &duplicatedHandle,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS);
    ::CloseHandle(processHandle);
    if (kDuplicateOk == FALSE || duplicatedHandle == nullptr)
    {
        result.diagnosticText = QStringLiteral("DuplicateHandle 失败，error=%1").arg(::GetLastError());
        result.elapsedMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kBeginTime).count());
        return result;
    }

    const QString kNormalizedType = row.typeName.trimmed().toLower();

    if (kNormalizedType == QStringLiteral("file") || kNormalizedType == QStringLiteral("directory"))
    {
        wchar_t pathBuffer[4096] = {};
        const DWORD kPathLength = ::GetFinalPathNameByHandleW(
            duplicatedHandle,
            pathBuffer,
            static_cast<DWORD>(std::size(pathBuffer)),
            FILE_NAME_NORMALIZED);
        if (kPathLength > 0 && kPathLength < std::size(pathBuffer))
        {
            addField(QStringLiteral("最终路径"), QString::fromWCharArray(pathBuffer));
        }
        addField(QStringLiteral("文件类型"), QString::number(::GetFileType(duplicatedHandle)));
    }
    else if (kNormalizedType == QStringLiteral("process"))
    {
        addField(QStringLiteral("目标PID"), QString::number(::GetProcessId(duplicatedHandle)));
        wchar_t imagePathBuffer[2048] = {};
        DWORD bufferChars = static_cast<DWORD>(std::size(imagePathBuffer));
        if (::QueryFullProcessImageNameW(duplicatedHandle, 0, imagePathBuffer, &bufferChars) != FALSE)
        {
            addField(QStringLiteral("目标进程路径"), QString::fromWCharArray(imagePathBuffer));
        }
        addField(QStringLiteral("优先级类"), QString::number(::GetPriorityClass(duplicatedHandle)));
    }
    else if (kNormalizedType == QStringLiteral("thread"))
    {
        addField(QStringLiteral("目标TID"), QString::number(::GetThreadId(duplicatedHandle)));
        addField(QStringLiteral("所属PID"), QString::number(::GetProcessIdOfThread(duplicatedHandle)));
        addField(QStringLiteral("线程优先级"), QString::number(::GetThreadPriority(duplicatedHandle)));
    }
    else if (kNormalizedType == QStringLiteral("token"))
    {
        DWORD requiredLength = 0;
        ::GetTokenInformation(duplicatedHandle, TokenUser, nullptr, 0, &requiredLength);
        if (requiredLength > 0)
        {
            std::vector<std::uint8_t> tokenUserBuffer(requiredLength, 0);
            if (::GetTokenInformation(duplicatedHandle, TokenUser, tokenUserBuffer.data(), requiredLength, &requiredLength) != FALSE)
            {
                const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenUserBuffer.data());
                if (tokenUser != nullptr && tokenUser->User.Sid != nullptr)
                {
                    wchar_t accountName[256] = {};
                    wchar_t domainName[256] = {};
                    DWORD accountNameLength = static_cast<DWORD>(std::size(accountName));
                    DWORD domainNameLength = static_cast<DWORD>(std::size(domainName));
                    SID_NAME_USE sidType = SidTypeUnknown;
                    if (::LookupAccountSidW(
                        nullptr,
                        tokenUser->User.Sid,
                        accountName,
                        &accountNameLength,
                        domainName,
                        &domainNameLength,
                        &sidType) != FALSE)
                    {
                        addField(
                            QStringLiteral("用户"),
                            QStringLiteral("%1\\%2")
                            .arg(QString::fromWCharArray(domainName), QString::fromWCharArray(accountName)));
                    }

                    LPWSTR sidTextRaw = nullptr;
                    if (::ConvertSidToStringSidW(tokenUser->User.Sid, &sidTextRaw) != FALSE && sidTextRaw != nullptr)
                    {
                        addField(QStringLiteral("SID"), QString::fromWCharArray(sidTextRaw));
                        ::LocalFree(sidTextRaw);
                    }
                }
            }
        }

        requiredLength = 0;
        ::GetTokenInformation(duplicatedHandle, TokenIntegrityLevel, nullptr, 0, &requiredLength);
        if (requiredLength > 0)
        {
            std::vector<std::uint8_t> integrityBuffer(requiredLength, 0);
            if (::GetTokenInformation(
                duplicatedHandle,
                TokenIntegrityLevel,
                integrityBuffer.data(),
                requiredLength,
                &requiredLength) != FALSE)
            {
                const auto* tokenLabel = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(integrityBuffer.data());
                if (tokenLabel != nullptr && tokenLabel->Label.Sid != nullptr)
                {
                    const DWORD kIntegrityRid =
                        *::GetSidSubAuthority(
                            tokenLabel->Label.Sid,
                            static_cast<DWORD>(*::GetSidSubAuthorityCount(tokenLabel->Label.Sid) - 1));
                    addField(QStringLiteral("完整性RID"), QString::number(kIntegrityRid));
                }
            }
        }
    }
    else if (kNormalizedType == QStringLiteral("key"))
    {
        addField(QStringLiteral("注册表路径"), formatObjectNameDisplayText(row));
    }
    else
    {
        addField(QStringLiteral("类型专用解析"), QStringLiteral("该类型当前使用通用详情展示。"));
    }

    ::CloseHandle(duplicatedHandle);
    result.elapsedMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - kBeginTime).count());
    return result;
}
