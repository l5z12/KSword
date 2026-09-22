#include "pch.h"
#include "HookTargets.h"
#include "HookEngine.h"
#include "../MonitorAgent.h"
#include "../core/MonitorPipe.h"

#include <WinReg.h>
#include <bcrypt.h>
#include <evntrace.h>
#include <evntprov.h>
#include <ncrypt.h>
#include <objbase.h>
#include <psapi.h>
#include <rpc.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <urlmon.h>
#include <wincrypt.h>
#include <windns.h>
#include <winhttp.h>
#include <winioctl.h>
#include <wininet.h>
#include <winsvc.h>
#include <winternl.h>
#include <wintrust.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef FSCTL_REQUEST_OPLOCK
#define FSCTL_REQUEST_OPLOCK CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 144, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_REQUEST_FILTER_OPLOCK
#define FSCTL_REQUEST_FILTER_OPLOCK CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

typedef enum KsFileInformationClass
{
    kKsFileBasicInformation = 4,
    kKsFileRenameInformation = 10,
    kKsFileDispositionInformation = 13,
    kKsFilePositionInformation = 14,
    kKsFileEndOfFileInformation = 20,
    kKsFileDispositionInformationEx = 64,
    kKsFileRenameInformationEx = 65
} KsFileInformationClass;

typedef enum KsKeyInformationClass
{
    kKsKeyBasicInformation = 0,
    kKsKeyNodeInformation = 1,
    kKsKeyFullInformation = 2,
    kKsKeyNameInformation = 3,
    kKsKeyCachedInformation = 4,
    kKsKeyFlagsInformation = 5,
    kKsKeyVirtualizationInformation = 6,
    kKsKeyHandleTagsInformation = 7,
    kKsKeyTrustInformation = 8,
    kKsKeyLayerInformation = 9
} KsKeyInformationClass;

typedef enum KsKeyValueInformationClass
{
    kKsKeyValueBasicInformation = 0,
    kKsKeyValueFullInformation = 1,
    kKsKeyValuePartialInformation = 2,
    kKsKeyValueFullInformationAlign64 = 3,
    kKsKeyValuePartialInformationAlign64 = 4,
    kKsKeyValueLayerInformation = 5
} KsKeyValueInformationClass;

typedef struct KsClientId
{
    HANDLE uniqueProcess;
    HANDLE uniqueThread;
} KsClientId, *PksClientId;

namespace apimon
{
    namespace
    {
        using CreateFileAFn = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
        using CreateFileWFn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
        using CreateFile2Fn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, DWORD, LPCREATEFILE2_EXTENDED_PARAMETERS);
        using ReadFileFn = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
        using WriteFileFn = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
        using DeviceIoControlFn = BOOL(WINAPI*)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
        using DeleteFileWFn = BOOL(WINAPI*)(LPCWSTR);
        using DeleteFileAFn = BOOL(WINAPI*)(LPCSTR);
        using MoveFileExWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, DWORD);
        using MoveFileExAFn = BOOL(WINAPI*)(LPCSTR, LPCSTR, DWORD);
        using CopyFileWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, BOOL);
        using CopyFileAFn = BOOL(WINAPI*)(LPCSTR, LPCSTR, BOOL);
        using CopyFileExWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD);
        using CopyFileExAFn = BOOL(WINAPI*)(LPCSTR, LPCSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD);
        using GetFileAttributesWFn = DWORD(WINAPI*)(LPCWSTR);
        using GetFileAttributesAFn = DWORD(WINAPI*)(LPCSTR);
        using GetFileAttributesExWFn = BOOL(WINAPI*)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
        using GetFileAttributesExAFn = BOOL(WINAPI*)(LPCSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
        using SetFileAttributesWFn = BOOL(WINAPI*)(LPCWSTR, DWORD);
        using SetFileAttributesAFn = BOOL(WINAPI*)(LPCSTR, DWORD);
        using FindFirstFileExWFn = HANDLE(WINAPI*)(LPCWSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);
        using FindFirstFileExAFn = HANDLE(WINAPI*)(LPCSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);
        using CreateDirectoryWFn = BOOL(WINAPI*)(LPCWSTR, LPSECURITY_ATTRIBUTES);
        using CreateDirectoryAFn = BOOL(WINAPI*)(LPCSTR, LPSECURITY_ATTRIBUTES);
        using RemoveDirectoryWFn = BOOL(WINAPI*)(LPCWSTR);
        using RemoveDirectoryAFn = BOOL(WINAPI*)(LPCSTR);
        using SetFileInformationByHandleFn = BOOL(WINAPI*)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);
        using CreateProcessAFn = BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
        using CreateProcessWFn = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
        using OpenProcessFn = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
        using OpenThreadFn = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
        using TerminateProcessFn = BOOL(WINAPI*)(HANDLE, UINT);
        using CreateThreadFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
        using CreateRemoteThreadFn = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
        using SuspendThreadFn = DWORD(WINAPI*)(HANDLE);
        using ResumeThreadFn = DWORD(WINAPI*)(HANDLE);
        using QueueUserAPCFn = DWORD(WINAPI*)(PAPCFUNC, HANDLE, ULONG_PTR);
        using GetThreadContextFn = BOOL(WINAPI*)(HANDLE, LPCONTEXT);
        using SetThreadContextFn = BOOL(WINAPI*)(HANDLE, const CONTEXT*);
        using VirtualAllocExFn = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
        using VirtualFreeExFn = BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD);
        using VirtualProtectExFn = BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
        using WriteProcessMemoryFn = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
        using ReadProcessMemoryFn = BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
        using WinExecFn = UINT(WINAPI*)(LPCSTR, UINT);
        using ShellExecuteExWFn = BOOL(WINAPI*)(SHELLEXECUTEINFOW*);
        using ShellExecuteExAFn = BOOL(WINAPI*)(SHELLEXECUTEINFOA*);
        using LoadLibraryAFn = HMODULE(WINAPI*)(LPCSTR);
        using LoadLibraryWFn = HMODULE(WINAPI*)(LPCWSTR);
        using LoadLibraryExAFn = HMODULE(WINAPI*)(LPCSTR, HANDLE, DWORD);
        using LoadLibraryExWFn = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
        using LdrLoadDllFn = NTSTATUS(NTAPI*)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
        using RegOpenKeyWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, PHKEY);
        using RegOpenKeyAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, PHKEY);
        using RegOpenKeyExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
        using RegOpenKeyExAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
        using RegCreateKeyWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, PHKEY);
        using RegCreateKeyAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, PHKEY);
        using RegCreateKeyExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
        using RegCreateKeyExAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
        using RegQueryValueExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
        using RegQueryValueExAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
        using RegGetValueWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
        using RegGetValueAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD);
        using RegSetValueExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
        using RegSetValueExAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
        using RegSetKeyValueWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR, DWORD, const void*, DWORD);
        using RegSetKeyValueAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, LPCSTR, DWORD, const void*, DWORD);
        using RegDeleteValueWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR);
        using RegDeleteValueAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR);
        using RegDeleteKeyWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR);
        using RegDeleteKeyAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR);
        using RegDeleteKeyExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, REGSAM, DWORD);
        using RegDeleteKeyExAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, REGSAM, DWORD);
        using RegDeleteTreeWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR);
        using RegDeleteTreeAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR);
        using RegCopyTreeWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, HKEY);
        using RegCopyTreeAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, HKEY);
        using RegLoadKeyWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR);
        using RegLoadKeyAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, LPCSTR);
        using RegSaveKeyWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, const LPSECURITY_ATTRIBUTES);
        using RegSaveKeyAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, const LPSECURITY_ATTRIBUTES);
        using RegRenameKeyFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR);
        using RegEnumKeyExWFn = LSTATUS(WINAPI*)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
        using RegEnumKeyExAFn = LSTATUS(WINAPI*)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
        using RegEnumValueWFn = LSTATUS(WINAPI*)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
        using RegEnumValueAFn = LSTATUS(WINAPI*)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
        using RegCloseKeyFn = LSTATUS(WINAPI*)(HKEY);
        using RegQueryInfoKeyWFn = LSTATUS(WINAPI*)(HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
        using RegQueryInfoKeyAFn = LSTATUS(WINAPI*)(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
        using RegFlushKeyFn = LSTATUS(WINAPI*)(HKEY);
        using RegDeleteKeyValueWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR);
        using RegDeleteKeyValueAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, LPCSTR);
        using RegConnectRegistryWFn = LSTATUS(WINAPI*)(LPCWSTR, HKEY, PHKEY);
        using RegConnectRegistryAFn = LSTATUS(WINAPI*)(LPCSTR, HKEY, PHKEY);
        using ConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int);
        using WSAConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
        using SendFn = int (WSAAPI*)(SOCKET, const char*, int, int);
        using WSASendFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
        using SendToFn = int (WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
        using RecvFn = int (WSAAPI*)(SOCKET, char*, int, int);
        using WSARecvFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
        using RecvFromFn = int (WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);
        using BindFn = int (WSAAPI*)(SOCKET, const sockaddr*, int);
        using ListenFn = int (WSAAPI*)(SOCKET, int);
        using AcceptFn = SOCKET(WSAAPI*)(SOCKET, sockaddr*, int*);
        using SocketFn = SOCKET(WSAAPI*)(int, int, int);
        using WSASocketWFn = SOCKET(WSAAPI*)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
        using WSASocketAFn = SOCKET(WSAAPI*)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
        using CloseSocketFn = int(WSAAPI*)(SOCKET);
        using ShutdownFn = int(WSAAPI*)(SOCKET, int);
        using KsIoApcRoutine = VOID(NTAPI*)(PVOID, PIO_STATUS_BLOCK, ULONG);
        using NtCreateFileFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
        using NtOpenFileFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
        using NtReadFileFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, KsIoApcRoutine, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
        using NtWriteFileFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, KsIoApcRoutine, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
        using NtSetInformationFileFn = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, KsFileInformationClass);
        using NtQueryInformationFileFn = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, KsFileInformationClass);
        using NtDeleteFileFn = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES);
        using NtQueryAttributesFileFn = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES, PVOID);
        using NtQueryFullAttributesFileFn = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES, PVOID);
        using NtDeviceIoControlFileFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, KsIoApcRoutine, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
        using NtFsControlFileFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, KsIoApcRoutine, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
        using NtQueryDirectoryFileFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, KsIoApcRoutine, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, KsFileInformationClass, BOOLEAN, PUNICODE_STRING, BOOLEAN);
        using NtQueryDirectoryFileExFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, KsIoApcRoutine, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, KsFileInformationClass, ULONG, PUNICODE_STRING);
        using NtCreateKeyFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
        using NtOpenKeyFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
        using NtOpenKeyExFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
        using NtSetValueKeyFn = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
        using NtQueryValueKeyFn = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING, KsKeyValueInformationClass, PVOID, ULONG, PULONG);
        using NtEnumerateKeyFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, KsKeyInformationClass, PVOID, ULONG, PULONG);
        using NtEnumerateValueKeyFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, KsKeyValueInformationClass, PVOID, ULONG, PULONG);
        using NtDeleteKeyFn = NTSTATUS(NTAPI*)(HANDLE);
        using NtDeleteValueKeyFn = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING);
        using NtFlushKeyFn = NTSTATUS(NTAPI*)(HANDLE);
        using NtRenameKeyFn = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING);
        using NtLoadKeyFn = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES);
        using NtSaveKeyFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE);
        using NtQueryKeyFn = NTSTATUS(NTAPI*)(HANDLE, KsKeyInformationClass, PVOID, ULONG, PULONG);
        using NtQueryMultipleValueKeyFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, PVOID, PULONG, PULONG);
        using NtNotifyChangeKeyFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, KsIoApcRoutine, PVOID, PIO_STATUS_BLOCK, ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN);
        using NtLoadKey2Fn = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG);
        using NtSaveKeyExFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, ULONG);
        using NtLoadDriverFn = NTSTATUS(NTAPI*)(PUNICODE_STRING);
        using NtUnloadDriverFn = NTSTATUS(NTAPI*)(PUNICODE_STRING);
        using NtOpenProcessFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PksClientId);
        using NtOpenThreadFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PksClientId);
        using NtTerminateProcessFn = NTSTATUS(NTAPI*)(HANDLE, NTSTATUS);
        using NtCreateUserProcessFn = NTSTATUS(NTAPI*)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID, PVOID, PVOID);
        using NtCreateProcessExFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);
        using NtCreateThreadExFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
        using NtAllocateVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using NtFreeVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG);
        using NtProtectVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        using NtWriteVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        using NtReadVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        using NtMapViewOfSectionFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
        using NtUnmapViewOfSectionFn = NTSTATUS(NTAPI*)(HANDLE, PVOID);
        using NtDuplicateObjectFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
        using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        using NtSetInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
        using NtQueryVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
        using NtCreateSectionFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
        using NtOpenSectionFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
        using NtQueueApcThreadFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, PVOID);
        using NtQueueApcThreadExFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID);
        using NtSuspendThreadFn = NTSTATUS(NTAPI*)(HANDLE, PULONG);
        using NtResumeThreadFn = NTSTATUS(NTAPI*)(HANDLE, PULONG);
        using NtGetContextThreadFn = NTSTATUS(NTAPI*)(HANDLE, PCONTEXT);
        using NtSetContextThreadFn = NTSTATUS(NTAPI*)(HANDLE, PCONTEXT);
        using CloseHandleFn = BOOL(WINAPI*)(HANDLE);
        using DuplicateHandleFn = BOOL(WINAPI*)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
        using CreateFileMappingWFn = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
        using CreateFileMappingAFn = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
        using OpenFileMappingWFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCWSTR);
        using OpenFileMappingAFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCSTR);
        using MapViewOfFileFn = LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
        using MapViewOfFileExFn = LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID);
        using UnmapViewOfFileFn = BOOL(WINAPI*)(LPCVOID);
        using FlushViewOfFileFn = BOOL(WINAPI*)(LPCVOID, SIZE_T);
        using FreeLibraryFn = BOOL(WINAPI*)(HMODULE);
        using GetProcAddressFn = FARPROC(WINAPI*)(HMODULE, LPCSTR);
        using LdrGetProcedureAddressFn = NTSTATUS(NTAPI*)(HMODULE, PANSI_STRING, WORD, PVOID*);
        using RegCreateKeyTransactedWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD, HANDLE, PVOID);
        using RegCreateKeyTransactedAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD, HANDLE, PVOID);
        using RegOpenKeyTransactedWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID);
        using RegOpenKeyTransactedAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID);
        using RegDeleteKeyTransactedWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, REGSAM, DWORD, HANDLE, PVOID);
        using RegDeleteKeyTransactedAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, REGSAM, DWORD, HANDLE, PVOID);
        using RegReplaceKeyWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR, LPCWSTR);
        using RegReplaceKeyAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, LPCSTR, LPCSTR);
        using RegRestoreKeyWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD);
        using RegRestoreKeyAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD);
        using RegUnLoadKeyWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR);
        using RegUnLoadKeyAFn = LSTATUS(WINAPI*)(HKEY, LPCSTR);
        using RegLoadAppKeyWFn = LSTATUS(WINAPI*)(LPCWSTR, PHKEY, REGSAM, DWORD, DWORD);
        using RegLoadAppKeyAFn = LSTATUS(WINAPI*)(LPCSTR, PHKEY, REGSAM, DWORD, DWORD);
        using RegNotifyChangeKeyValueFn = LSTATUS(WINAPI*)(HKEY, BOOL, DWORD, HANDLE, BOOL);
        using NtCloseFn = NTSTATUS(NTAPI*)(HANDLE);
        using NtCreateKeyTransactedFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, HANDLE, PULONG);
        using NtOpenKeyTransactedFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE);
        using NtOpenKeyTransactedExFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, HANDLE);
        using NtReplaceKeyFn = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES, HANDLE, POBJECT_ATTRIBUTES);
        using NtRestoreKeyFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, ULONG);
        using NtUnloadKeyFn = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES);
        using NtUnloadKey2Fn = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES, ULONG);
        using NtUnloadKeyExFn = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES, HANDLE);
        using OpenProcessTokenFn = BOOL(WINAPI*)(HANDLE, DWORD, PHANDLE);
        using OpenThreadTokenFn = BOOL(WINAPI*)(HANDLE, DWORD, BOOL, PHANDLE);
        using AdjustTokenPrivilegesFn = BOOL(WINAPI*)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
        using DuplicateTokenFn = BOOL(WINAPI*)(HANDLE, SECURITY_IMPERSONATION_LEVEL, PHANDLE);
        using DuplicateTokenExFn = BOOL(WINAPI*)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
        using CreateProcessAsUserWFn = BOOL(WINAPI*)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
        using CreateProcessAsUserAFn = BOOL(WINAPI*)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
        using CreateProcessWithTokenWFn = BOOL(WINAPI*)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
        using LookupPrivilegeValueWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, PLUID);
        using LookupPrivilegeValueAFn = BOOL(WINAPI*)(LPCSTR, LPCSTR, PLUID);
        using OpenSCManagerWFn = SC_HANDLE(WINAPI*)(LPCWSTR, LPCWSTR, DWORD);
        using OpenSCManagerAFn = SC_HANDLE(WINAPI*)(LPCSTR, LPCSTR, DWORD);
        using OpenServiceWFn = SC_HANDLE(WINAPI*)(SC_HANDLE, LPCWSTR, DWORD);
        using OpenServiceAFn = SC_HANDLE(WINAPI*)(SC_HANDLE, LPCSTR, DWORD);
        using CreateServiceWFn = SC_HANDLE(WINAPI*)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
        using CreateServiceAFn = SC_HANDLE(WINAPI*)(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
        using ChangeServiceConfigWFn = BOOL(WINAPI*)(SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
        using ChangeServiceConfigAFn = BOOL(WINAPI*)(SC_HANDLE, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR);
        using StartServiceWFn = BOOL(WINAPI*)(SC_HANDLE, DWORD, LPCWSTR*);
        using StartServiceAFn = BOOL(WINAPI*)(SC_HANDLE, DWORD, LPCSTR*);
        using ControlServiceFn = BOOL(WINAPI*)(SC_HANDLE, DWORD, LPSERVICE_STATUS);
        using DeleteServiceFn = BOOL(WINAPI*)(SC_HANDLE);
        using CloseServiceHandleFn = BOOL(WINAPI*)(SC_HANDLE);
        using WSAIoctlFn = int(WSAAPI*)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
        using WSASendToFn = int(WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
        using WSARecvFromFn = int(WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
        using GetAddrInfoWFn = INT(WSAAPI*)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
        using GetAddrInfoAFn = INT(WSAAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
        using DnsQueryWFn = DNS_STATUS(WINAPI*)(PCWSTR, WORD, DWORD, PVOID, PDNS_RECORDW*, PVOID*);
        using DnsQueryAFn = DNS_STATUS(WINAPI*)(PCSTR, WORD, DWORD, PVOID, PDNS_RECORDA*, PVOID*);
        using WinHttpOpenFn = HINTERNET(WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
        using WinHttpConnectFn = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
        using WinHttpOpenRequestFn = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
        using WinHttpSendRequestFn = BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
        using WinHttpReceiveResponseFn = BOOL(WINAPI*)(HINTERNET, LPVOID);
        using WinHttpReadDataFn = BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
        using WinHttpWriteDataFn = BOOL(WINAPI*)(HINTERNET, LPCVOID, DWORD, LPDWORD);
        using WinHttpCloseHandleFn = BOOL(WINAPI*)(HINTERNET);
        using InternetOpenWFn = HINTERNET(WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
        using InternetOpenAFn = HINTERNET(WINAPI*)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
        using InternetConnectWFn = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
        using InternetConnectAFn = HINTERNET(WINAPI*)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
        using HttpOpenRequestWFn = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD_PTR);
        using HttpOpenRequestAFn = HINTERNET(WINAPI*)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
        using HttpSendRequestWFn = BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
        using HttpSendRequestAFn = BOOL(WINAPI*)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
        using InternetReadFileFn = BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
        using InternetWriteFileFn = BOOL(WINAPI*)(HINTERNET, LPCVOID, DWORD, LPDWORD);
        using InternetCloseHandleFn = BOOL(WINAPI*)(HINTERNET);
        using CryptAcquireContextWFn = BOOL(WINAPI*)(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
        using CryptAcquireContextAFn = BOOL(WINAPI*)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
        using CryptCreateHashFn = BOOL(WINAPI*)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
        using CryptHashDataFn = BOOL(WINAPI*)(HCRYPTHASH, const BYTE*, DWORD, DWORD);
        using CryptDeriveKeyFn = BOOL(WINAPI*)(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY*);
        using CryptEncryptFn = BOOL(WINAPI*)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
        using CryptDecryptFn = BOOL(WINAPI*)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
        using CryptGenRandomFn = BOOL(WINAPI*)(HCRYPTPROV, DWORD, BYTE*);
        using CryptReleaseContextFn = BOOL(WINAPI*)(HCRYPTPROV, DWORD);
        using BCryptOpenAlgorithmProviderFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
        using BCryptCreateHashFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
        using BCryptHashDataFn = NTSTATUS(WINAPI*)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
        using BCryptFinishHashFn = NTSTATUS(WINAPI*)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
        using BCryptEncryptFn = NTSTATUS(WINAPI*)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
        using BCryptDecryptFn = NTSTATUS(WINAPI*)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
        using BCryptGenRandomFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
        using BCryptCloseAlgorithmProviderFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE, ULONG);
        using BCryptDestroyHashFn = NTSTATUS(WINAPI*)(BCRYPT_HASH_HANDLE);
        using CoCreateInstanceFn = HRESULT(WINAPI*)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
        using CoCreateInstanceExFn = HRESULT(WINAPI*)(REFCLSID, IUnknown*, DWORD, COSERVERINFO*, DWORD, MULTI_QI*);
        using CoGetClassObjectFn = HRESULT(WINAPI*)(REFCLSID, DWORD, COSERVERINFO*, REFIID, LPVOID*);
        using VirtualAllocFn = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
        using VirtualFreeFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD);
        using VirtualProtectFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
        using CreateToolhelp32SnapshotFn = HANDLE(WINAPI*)(DWORD, DWORD);
        using Module32FirstWFn = BOOL(WINAPI*)(HANDLE, LPMODULEENTRY32W);
        using Module32NextWFn = BOOL(WINAPI*)(HANDLE, LPMODULEENTRY32W);
        using Module32FirstAFn = BOOL(WINAPI*)(HANDLE, tagMODULEENTRY32*);
        using Module32NextAFn = BOOL(WINAPI*)(HANDLE, tagMODULEENTRY32*);
        using GetModuleHandleWFn = HMODULE(WINAPI*)(LPCWSTR);
        using GetModuleHandleAFn = HMODULE(WINAPI*)(LPCSTR);
        using GetModuleHandleExWFn = BOOL(WINAPI*)(DWORD, LPCWSTR, HMODULE*);
        using GetModuleHandleExAFn = BOOL(WINAPI*)(DWORD, LPCSTR, HMODULE*);
        using GetModuleFileNameWFn = DWORD(WINAPI*)(HMODULE, LPWSTR, DWORD);
        using GetModuleFileNameAFn = DWORD(WINAPI*)(HMODULE, LPSTR, DWORD);
        using CreateHardLinkWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES);
        using CreateHardLinkAFn = BOOL(WINAPI*)(LPCSTR, LPCSTR, LPSECURITY_ATTRIBUTES);
        using ReplaceFileWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPVOID, LPVOID);
        using ReplaceFileAFn = BOOL(WINAPI*)(LPCSTR, LPCSTR, LPCSTR, DWORD, LPVOID, LPVOID);
        using SetEndOfFileFn = BOOL(WINAPI*)(HANDLE);
        using LockFileExFn = BOOL(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, DWORD, LPOVERLAPPED);
        using UnlockFileExFn = BOOL(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, LPOVERLAPPED);
        using ShellExecuteWFn = HINSTANCE(WINAPI*)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
        using ShellExecuteAFn = HINSTANCE(WINAPI*)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
        using CreateProcessWithLogonWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
        using ChangeServiceConfig2WFn = BOOL(WINAPI*)(SC_HANDLE, DWORD, LPVOID);
        using ChangeServiceConfig2AFn = BOOL(WINAPI*)(SC_HANDLE, DWORD, LPVOID);
        using QueryServiceStatusExFn = BOOL(WINAPI*)(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);
        using QueryServiceConfigWFn = BOOL(WINAPI*)(SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD);
        using QueryServiceConfigAFn = BOOL(WINAPI*)(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD);
        using EnumServicesStatusExWFn = BOOL(WINAPI*)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR);
        using EnumServicesStatusExAFn = BOOL(WINAPI*)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR);
        using WinHttpQueryHeadersFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
        using WinHttpQueryDataAvailableFn = BOOL(WINAPI*)(HINTERNET, LPDWORD);
        using WinHttpSetOptionFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);
        using InternetOpenUrlWFn = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
        using InternetOpenUrlAFn = HINTERNET(WINAPI*)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
        using InternetQueryDataAvailableFn = BOOL(WINAPI*)(HINTERNET, LPDWORD, DWORD, DWORD_PTR);
        using InternetSetOptionWFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);
        using InternetSetOptionAFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);
        using InternetCrackUrlWFn = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTSW);
        using InternetCrackUrlAFn = BOOL(WINAPI*)(LPCSTR, DWORD, DWORD, LPURL_COMPONENTSA);
        using URLDownloadToFileWFn = HRESULT(WINAPI*)(LPUNKNOWN, LPCWSTR, LPCWSTR, DWORD, LPBINDSTATUSCALLBACK);
        using URLDownloadToFileAFn = HRESULT(WINAPI*)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK);
        using CryptImportKeyFn = BOOL(WINAPI*)(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);
        using CryptExportKeyFn = BOOL(WINAPI*)(HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, BYTE*, DWORD*);
        using CryptDestroyKeyFn = BOOL(WINAPI*)(HCRYPTKEY);
        using CryptDestroyHashFn = BOOL(WINAPI*)(HCRYPTHASH);
        using BCryptGenerateSymmetricKeyFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
        using BCryptImportKeyFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
        using BCryptImportKeyPairFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, ULONG);
        using BCryptDestroyKeyFn = NTSTATUS(WINAPI*)(BCRYPT_KEY_HANDLE);
        using CoInitializeExFn = HRESULT(WINAPI*)(LPVOID, DWORD);
        using CoInitializeSecurityFn = HRESULT(WINAPI*)(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD, DWORD, void*, DWORD, void*);
        using CoUninitializeFn = void(WINAPI*)();
        using CreateRemoteThreadExFn = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
        using CreateSymbolicLinkWFn = BOOLEAN(WINAPI*)(LPCWSTR, LPCWSTR, DWORD);
        using CreateSymbolicLinkAFn = BOOLEAN(WINAPI*)(LPCSTR, LPCSTR, DWORD);
        using GetFinalPathNameByHandleWFn = DWORD(WINAPI*)(HANDLE, LPWSTR, DWORD, DWORD);
        using GetFinalPathNameByHandleAFn = DWORD(WINAPI*)(HANDLE, LPSTR, DWORD, DWORD);
        using GetFileSizeExFn = BOOL(WINAPI*)(HANDLE, PLARGE_INTEGER);
        using SetFilePointerExFn = BOOL(WINAPI*)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
        using CreateNamedPipeWFn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
        using CreateNamedPipeAFn = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
        using ConnectNamedPipeFn = BOOL(WINAPI*)(HANDLE, LPOVERLAPPED);
        using DisconnectNamedPipeFn = BOOL(WINAPI*)(HANDLE);
        using WaitNamedPipeWFn = BOOL(WINAPI*)(LPCWSTR, DWORD);
        using WaitNamedPipeAFn = BOOL(WINAPI*)(LPCSTR, DWORD);
        using TransactNamedPipeFn = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
        using CreateMutexWFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
        using CreateMutexAFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
        using OpenMutexWFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCWSTR);
        using OpenMutexAFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCSTR);
        using CreateEventWFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
        using CreateEventAFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
        using OpenEventWFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCWSTR);
        using OpenEventAFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCSTR);
        using CreateSemaphoreWFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR);
        using CreateSemaphoreAFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCSTR);
        using OpenSemaphoreWFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCWSTR);
        using OpenSemaphoreAFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCSTR);
        using WaitForSingleObjectFn = DWORD(WINAPI*)(HANDLE, DWORD);
        using WaitForMultipleObjectsFn = DWORD(WINAPI*)(DWORD, const HANDLE*, BOOL, DWORD);
        using SetEventFn = BOOL(WINAPI*)(HANDLE);
        using ResetEventFn = BOOL(WINAPI*)(HANDLE);
        using ReleaseMutexFn = BOOL(WINAPI*)(HANDLE);
        using ReleaseSemaphoreFn = BOOL(WINAPI*)(HANDLE, LONG, LPLONG);
        using GetEnvironmentVariableWFn = DWORD(WINAPI*)(LPCWSTR, LPWSTR, DWORD);
        using GetEnvironmentVariableAFn = DWORD(WINAPI*)(LPCSTR, LPSTR, DWORD);
        using SetEnvironmentVariableWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR);
        using SetEnvironmentVariableAFn = BOOL(WINAPI*)(LPCSTR, LPCSTR);
        using ExpandEnvironmentStringsWFn = DWORD(WINAPI*)(LPCWSTR, LPWSTR, DWORD);
        using ExpandEnvironmentStringsAFn = DWORD(WINAPI*)(LPCSTR, LPSTR, DWORD);
        using SetDllDirectoryWFn = BOOL(WINAPI*)(LPCWSTR);
        using SetDllDirectoryAFn = BOOL(WINAPI*)(LPCSTR);
        using SetDefaultDllDirectoriesFn = BOOL(WINAPI*)(DWORD);
        using AddDllDirectoryFn = DLL_DIRECTORY_COOKIE(WINAPI*)(PCWSTR);
        using RemoveDllDirectoryFn = BOOL(WINAPI*)(DLL_DIRECTORY_COOKIE);
        using ImpersonateLoggedOnUserFn = BOOL(WINAPI*)(HANDLE);
        using RevertToSelfFn = BOOL(WINAPI*)();
        using SetThreadTokenFn = BOOL(WINAPI*)(PHANDLE, HANDLE);
        using SetWindowsHookExWFn = HHOOK(WINAPI*)(int, HOOKPROC, HINSTANCE, DWORD);
        using SetWindowsHookExAFn = HHOOK(WINAPI*)(int, HOOKPROC, HINSTANCE, DWORD);
        using UnhookWindowsHookExFn = BOOL(WINAPI*)(HHOOK);
        using EnumProcessesFn = BOOL(WINAPI*)(DWORD*, DWORD, DWORD*);
        using EnumProcessModulesFn = BOOL(WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD);
        using EnumProcessModulesExFn = BOOL(WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
        using GetMappedFileNameWFn = DWORD(WINAPI*)(HANDLE, LPVOID, LPWSTR, DWORD);
        using GetMappedFileNameAFn = DWORD(WINAPI*)(HANDLE, LPVOID, LPSTR, DWORD);
        using EnumWindowsFn = BOOL(WINAPI*)(WNDENUMPROC, LPARAM);
        using EnumChildWindowsFn = BOOL(WINAPI*)(HWND, WNDENUMPROC, LPARAM);
        using FindWindowWFn = HWND(WINAPI*)(LPCWSTR, LPCWSTR);
        using FindWindowAFn = HWND(WINAPI*)(LPCSTR, LPCSTR);
        using FindWindowExWFn = HWND(WINAPI*)(HWND, HWND, LPCWSTR, LPCWSTR);
        using FindWindowExAFn = HWND(WINAPI*)(HWND, HWND, LPCSTR, LPCSTR);
        using GetWindowThreadProcessIdFn = DWORD(WINAPI*)(HWND, LPDWORD);
        using GetForegroundWindowFn = HWND(WINAPI*)();
        using GetDCFn = HDC(WINAPI*)(HWND);
        using ReleaseDCFn = int(WINAPI*)(HWND, HDC);
        using CreateCompatibleDCFn = HDC(WINAPI*)(HDC);
        using DeleteDCFn = BOOL(WINAPI*)(HDC);
        using CreateCompatibleBitmapFn = HBITMAP(WINAPI*)(HDC, int, int);
        using BitBltFn = BOOL(WINAPI*)(HDC, int, int, int, int, HDC, int, int, DWORD);
        using StretchBltFn = BOOL(WINAPI*)(HDC, int, int, int, int, HDC, int, int, int, int, DWORD);
        using DeleteObjectFn = BOOL(WINAPI*)(HGDIOBJ);
        using OpenClipboardFn = BOOL(WINAPI*)(HWND);
        using CloseClipboardFn = BOOL(WINAPI*)();
        using GetClipboardDataFn = HANDLE(WINAPI*)(UINT);
        using SetClipboardDataFn = HANDLE(WINAPI*)(UINT, HANDLE);
        using EmptyClipboardFn = BOOL(WINAPI*)();
        using StartTraceWFn = ULONG(WINAPI*)(PTRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES);
        using StartTraceAFn = ULONG(WINAPI*)(PTRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES);
        using ControlTraceWFn = ULONG(WINAPI*)(TRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES, ULONG);
        using ControlTraceAFn = ULONG(WINAPI*)(TRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES, ULONG);
        using EnableTraceEx2Fn = ULONG(WINAPI*)(TRACEHANDLE, LPCGUID, ULONG, UCHAR, ULONGLONG, ULONGLONG, ULONG, void*);
        using OpenTraceWFn = TRACEHANDLE(WINAPI*)(PEVENT_TRACE_LOGFILEW);
        using OpenTraceAFn = TRACEHANDLE(WINAPI*)(PEVENT_TRACE_LOGFILEA);
        using ProcessTraceFn = ULONG(WINAPI*)(PTRACEHANDLE, ULONG, LPFILETIME, LPFILETIME);
        using CloseTraceFn = ULONG(WINAPI*)(TRACEHANDLE);
        using EventRegisterFn = ULONG(WINAPI*)(LPCGUID, PENABLECALLBACK, PVOID, PREGHANDLE);
        using EventUnregisterFn = ULONG(WINAPI*)(REGHANDLE);
        using EventWriteFn = ULONG(WINAPI*)(REGHANDLE, PCEVENT_DESCRIPTOR, ULONG, PEVENT_DATA_DESCRIPTOR);
        using EventWriteExFn = ULONG(WINAPI*)(REGHANDLE, PCEVENT_DESCRIPTOR, ULONG64, ULONG, LPCGUID, LPCGUID, ULONG, PEVENT_DATA_DESCRIPTOR);
        using WinVerifyTrustFn = LONG(WINAPI*)(HWND, GUID*, LPVOID);
        using CryptQueryObjectFn = BOOL(WINAPI*)(DWORD, const void*, DWORD, DWORD, DWORD, DWORD*, DWORD*, DWORD*, HCERTSTORE*, HCRYPTMSG*, const void**);
        using CertOpenStoreFn = HCERTSTORE(WINAPI*)(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void*);
        using CertCloseStoreFn = BOOL(WINAPI*)(HCERTSTORE, DWORD);
        using CertFindCertificateInStoreFn = PCCERT_CONTEXT(WINAPI*)(HCERTSTORE, DWORD, DWORD, DWORD, const void*, PCCERT_CONTEXT);
        using CertGetCertificateChainFn = BOOL(WINAPI*)(HCERTCHAINENGINE, PCCERT_CONTEXT, LPFILETIME, HCERTSTORE, PCERT_CHAIN_PARA, DWORD, LPVOID, PCCERT_CHAIN_CONTEXT*);
        using CertVerifyCertificateChainPolicyFn = BOOL(WINAPI*)(LPCSTR, PCCERT_CHAIN_CONTEXT, PCERT_CHAIN_POLICY_PARA, PCERT_CHAIN_POLICY_STATUS);
        using CryptProtectDataFn = BOOL(WINAPI*)(DATA_BLOB*, LPCWSTR, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
        using CryptUnprotectDataFn = BOOL(WINAPI*)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
        using NCryptOpenStorageProviderFn = SECURITY_STATUS(WINAPI*)(NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
        using NCryptOpenKeyFn = SECURITY_STATUS(WINAPI*)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, DWORD, DWORD);
        using NCryptCreatePersistedKeyFn = SECURITY_STATUS(WINAPI*)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, LPCWSTR, DWORD, DWORD);
        using NCryptFinalizeKeyFn = SECURITY_STATUS(WINAPI*)(NCRYPT_KEY_HANDLE, DWORD);
        using NCryptEncryptFn = SECURITY_STATUS(WINAPI*)(NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD);
        using NCryptDecryptFn = SECURITY_STATUS(WINAPI*)(NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD);
        using NCryptSignHashFn = SECURITY_STATUS(WINAPI*)(NCRYPT_KEY_HANDLE, VOID*, PBYTE, DWORD, PBYTE, DWORD, DWORD*, DWORD);
        using NCryptVerifySignatureFn = SECURITY_STATUS(WINAPI*)(NCRYPT_KEY_HANDLE, VOID*, PBYTE, DWORD, PBYTE, DWORD, DWORD);
        using NCryptExportKeyFn = SECURITY_STATUS(WINAPI*)(NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, VOID*, PBYTE, DWORD, DWORD*, DWORD);
        using NCryptImportKeyFn = SECURITY_STATUS(WINAPI*)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, VOID*, NCRYPT_KEY_HANDLE*, PBYTE, DWORD, DWORD);
        using NCryptDeleteKeyFn = SECURITY_STATUS(WINAPI*)(NCRYPT_KEY_HANDLE, DWORD);
        using NCryptFreeObjectFn = SECURITY_STATUS(WINAPI*)(NCRYPT_HANDLE);
        using RpcStringBindingComposeWFn = RPC_STATUS(RPC_ENTRY*)(RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR*);
        using RpcStringBindingComposeAFn = RPC_STATUS(RPC_ENTRY*)(RPC_CSTR, RPC_CSTR, RPC_CSTR, RPC_CSTR, RPC_CSTR, RPC_CSTR*);
        using RpcBindingFromStringBindingWFn = RPC_STATUS(RPC_ENTRY*)(RPC_WSTR, RPC_BINDING_HANDLE*);
        using RpcBindingFromStringBindingAFn = RPC_STATUS(RPC_ENTRY*)(RPC_CSTR, RPC_BINDING_HANDLE*);
        using RpcBindingFreeFn = RPC_STATUS(RPC_ENTRY*)(RPC_BINDING_HANDLE*);
        using RpcMgmtEpEltInqBeginFn = RPC_STATUS(RPC_ENTRY*)(RPC_BINDING_HANDLE, unsigned long, RPC_IF_ID*, unsigned long, UUID*, RPC_EP_INQ_HANDLE*);
        using RpcMgmtEpEltInqNextWFn = RPC_STATUS(RPC_ENTRY*)(RPC_EP_INQ_HANDLE, RPC_IF_ID*, RPC_BINDING_HANDLE*, UUID*, RPC_WSTR*);
        using RpcMgmtEpEltInqNextAFn = RPC_STATUS(RPC_ENTRY*)(RPC_EP_INQ_HANDLE, RPC_IF_ID*, RPC_BINDING_HANDLE*, UUID*, RPC_CSTR*);
        using RpcMgmtEpEltInqDoneFn = RPC_STATUS(RPC_ENTRY*)(RPC_EP_INQ_HANDLE*);
        using NtQueryInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        using NtSetInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
        using NtAdjustPrivilegesTokenFn = NTSTATUS(NTAPI*)(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG);
        using NtCreateMutantFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN);
        using NtOpenMutantFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
        using NtReleaseMutantFn = NTSTATUS(NTAPI*)(HANDLE, PLONG);
        using NtCreateEventFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN);
        using NtOpenEventFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
        using NtSetEventFn = NTSTATUS(NTAPI*)(HANDLE, PLONG);
        using NtResetEventFn = NTSTATUS(NTAPI*)(HANDLE, PLONG);
        using NtWaitForSingleObjectFn = NTSTATUS(NTAPI*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
        using NtWaitForMultipleObjectsFn = NTSTATUS(NTAPI*)(ULONG, HANDLE*, ULONG, BOOLEAN, PLARGE_INTEGER);
        using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        using NtQueryObjectFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        using LogonUserWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, PHANDLE);
        using LogonUserAFn = BOOL(WINAPI*)(LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, PHANDLE);
        using GetTokenInformationFn = BOOL(WINAPI*)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
        using SetTokenInformationFn = BOOL(WINAPI*)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD);
        using CheckTokenMembershipFn = BOOL(WINAPI*)(HANDLE, PSID, PBOOL);
        using CreateRestrictedTokenFn = BOOL(WINAPI*)(HANDLE, DWORD, DWORD, PSID_AND_ATTRIBUTES, DWORD, PLUID_AND_ATTRIBUTES, DWORD, PSID_AND_ATTRIBUTES, PHANDLE);
        using ImpersonateSelfFn = BOOL(WINAPI*)(SECURITY_IMPERSONATION_LEVEL);
        using ImpersonateNamedPipeClientFn = BOOL(WINAPI*)(HANDLE);
        using CredReadWFn = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD, PVOID*);
        using CredReadAFn = BOOL(WINAPI*)(LPCSTR, DWORD, DWORD, PVOID*);
        using CredEnumerateWFn = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD*, PVOID*);
        using CredEnumerateAFn = BOOL(WINAPI*)(LPCSTR, DWORD, DWORD*, PVOID*);
        using CredWriteWFn = BOOL(WINAPI*)(PVOID, DWORD);
        using CredWriteAFn = BOOL(WINAPI*)(PVOID, DWORD);
        using CredDeleteWFn = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD);
        using CredDeleteAFn = BOOL(WINAPI*)(LPCSTR, DWORD, DWORD);
        using CredFreeFn = VOID(WINAPI*)(PVOID);
        using LsaOpenPolicyFn = NTSTATUS(WINAPI*)(PUNICODE_STRING, PVOID, ACCESS_MASK, PVOID*);
        using LsaCloseFn = NTSTATUS(WINAPI*)(PVOID);
        using LsaEnumerateLogonSessionsFn = NTSTATUS(WINAPI*)(PULONG, PVOID*);
        using LsaGetLogonSessionDataFn = NTSTATUS(WINAPI*)(PVOID, PVOID*);
        using LsaFreeReturnBufferFn = NTSTATUS(WINAPI*)(PVOID);
        using LsaLookupNames2Fn = NTSTATUS(WINAPI*)(PVOID, ULONG, ULONG, PUNICODE_STRING, PVOID*, PVOID*);
        using LsaLookupSids2Fn = NTSTATUS(WINAPI*)(PVOID, ULONG, ULONG, PVOID*, PVOID*, PVOID*);
        using OpenEventLogWFn = HANDLE(WINAPI*)(LPCWSTR, LPCWSTR);
        using OpenEventLogAFn = HANDLE(WINAPI*)(LPCSTR, LPCSTR);
        using RegisterEventSourceWFn = HANDLE(WINAPI*)(LPCWSTR, LPCWSTR);
        using RegisterEventSourceAFn = HANDLE(WINAPI*)(LPCSTR, LPCSTR);
        using ReadEventLogWFn = BOOL(WINAPI*)(HANDLE, DWORD, DWORD, LPVOID, DWORD, DWORD*, DWORD*);
        using ReadEventLogAFn = BOOL(WINAPI*)(HANDLE, DWORD, DWORD, LPVOID, DWORD, DWORD*, DWORD*);
        using ClearEventLogWFn = BOOL(WINAPI*)(HANDLE, LPCWSTR);
        using ClearEventLogAFn = BOOL(WINAPI*)(HANDLE, LPCSTR);
        using ReportEventWFn = BOOL(WINAPI*)(HANDLE, WORD, WORD, DWORD, PSID, WORD, DWORD, LPCWSTR*, LPVOID);
        using ReportEventAFn = BOOL(WINAPI*)(HANDLE, WORD, WORD, DWORD, PSID, WORD, DWORD, LPCSTR*, LPVOID);
        using CloseEventLogFn = BOOL(WINAPI*)(HANDLE);
        using NetUserEnumFn = DWORD(WINAPI*)(LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
        using NetLocalGroupEnumFn = DWORD(WINAPI*)(LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
        using NetGroupEnumFn = DWORD(WINAPI*)(LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
        using NetShareEnumFn = DWORD(WINAPI*)(LPWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
        using NetSessionEnumFn = DWORD(WINAPI*)(LPWSTR, LPWSTR, LPWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
        using NetServerEnumFn = DWORD(WINAPI*)(LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, DWORD, LPCWSTR, LPDWORD);
        using NetWkstaGetInfoFn = DWORD(WINAPI*)(LPWSTR, DWORD, LPBYTE*);
        using NetApiBufferFreeFn = DWORD(WINAPI*)(LPVOID);
        using GetExtendedTcpTableFn = ULONG(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, ULONG, ULONG);
        using GetExtendedUdpTableFn = ULONG(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, ULONG, ULONG);
        using GetTcpTable2Fn = ULONG(WINAPI*)(PVOID, PULONG, BOOL);
        using GetUdpTableFn = ULONG(WINAPI*)(PVOID, PDWORD, BOOL);
        using GetAdaptersAddressesFn = ULONG(WINAPI*)(ULONG, ULONG, PVOID, PVOID, PULONG);
        using GetNetworkParamsFn = DWORD(WINAPI*)(PVOID, PULONG);
        using GetIpNetTable2Fn = ULONG(WINAPI*)(USHORT, PVOID*);
        using GetIfTable2Fn = ULONG(WINAPI*)(PVOID*);
        using FreeMibTableFn = VOID(WINAPI*)(PVOID);
        using WTSOpenServerWFn = HANDLE(WINAPI*)(LPWSTR);
        using WTSOpenServerAFn = HANDLE(WINAPI*)(LPSTR);
        using WTSCloseServerFn = VOID(WINAPI*)(HANDLE);
        using WTSEnumerateSessionsWFn = BOOL(WINAPI*)(HANDLE, DWORD, DWORD, PVOID*, DWORD*);
        using WTSEnumerateSessionsAFn = BOOL(WINAPI*)(HANDLE, DWORD, DWORD, PVOID*, DWORD*);
        using WTSEnumerateProcessesWFn = BOOL(WINAPI*)(HANDLE, DWORD, DWORD, PVOID*, DWORD*);
        using WTSEnumerateProcessesAFn = BOOL(WINAPI*)(HANDLE, DWORD, DWORD, PVOID*, DWORD*);
        using WTSQuerySessionInformationWFn = BOOL(WINAPI*)(HANDLE, DWORD, int, LPWSTR*, DWORD*);
        using WTSQuerySessionInformationAFn = BOOL(WINAPI*)(HANDLE, DWORD, int, LPSTR*, DWORD*);
        using WTSFreeMemoryFn = VOID(WINAPI*)(PVOID);
        using CreateJobObjectWFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, LPCWSTR);
        using CreateJobObjectAFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, LPCSTR);
        using OpenJobObjectWFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCWSTR);
        using OpenJobObjectAFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCSTR);
        using AssignProcessToJobObjectFn = BOOL(WINAPI*)(HANDLE, HANDLE);
        using TerminateJobObjectFn = BOOL(WINAPI*)(HANDLE, UINT);
        using SetInformationJobObjectFn = BOOL(WINAPI*)(HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD);
        using QueryInformationJobObjectFn = BOOL(WINAPI*)(HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD, LPDWORD);
        using AcquireCredentialsHandleWFn = SECURITY_STATUS(WINAPI*)(LPWSTR, LPWSTR, ULONG, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
        using AcquireCredentialsHandleAFn = SECURITY_STATUS(WINAPI*)(LPSTR, LPSTR, ULONG, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
        using InitializeSecurityContextWFn = SECURITY_STATUS(WINAPI*)(PVOID, PVOID, LPWSTR, ULONG, ULONG, ULONG, PVOID, ULONG, PVOID, PVOID, PULONG, PVOID);
        using InitializeSecurityContextAFn = SECURITY_STATUS(WINAPI*)(PVOID, PVOID, LPSTR, ULONG, ULONG, ULONG, PVOID, ULONG, PVOID, PVOID, PULONG, PVOID);
        using AcceptSecurityContextFn = SECURITY_STATUS(WINAPI*)(PVOID, PVOID, PVOID, ULONG, ULONG, PVOID, PVOID, PULONG, PVOID);
        using EncryptMessageFn = SECURITY_STATUS(WINAPI*)(PVOID, ULONG, PVOID, ULONG);
        using DecryptMessageFn = SECURITY_STATUS(WINAPI*)(PVOID, PVOID, ULONG, PULONG);
        using DeleteSecurityContextFn = SECURITY_STATUS(WINAPI*)(PVOID);
        using FreeCredentialsHandleFn = SECURITY_STATUS(WINAPI*)(PVOID);
        using Process32FirstWFn = BOOL(WINAPI*)(HANDLE, PROCESSENTRY32W*);
        using Process32FirstAFn = BOOL(WINAPI*)(HANDLE, tagPROCESSENTRY32*);
        using Process32NextWFn = BOOL(WINAPI*)(HANDLE, PROCESSENTRY32W*);
        using Process32NextAFn = BOOL(WINAPI*)(HANDLE, tagPROCESSENTRY32*);
        using Thread32FirstFn = BOOL(WINAPI*)(HANDLE, LPTHREADENTRY32);
        using Thread32NextFn = BOOL(WINAPI*)(HANDLE, LPTHREADENTRY32);
        using Heap32ListFirstFn = BOOL(WINAPI*)(HANDLE, LPHEAPLIST32);
        using Heap32ListNextFn = BOOL(WINAPI*)(HANDLE, LPHEAPLIST32);
        using Heap32FirstFn = BOOL(WINAPI*)(LPHEAPENTRY32, DWORD, ULONG_PTR);
        using Heap32NextFn = BOOL(WINAPI*)(LPHEAPENTRY32);
        using QueryFullProcessImageNameWFn = BOOL(WINAPI*)(HANDLE, DWORD, LPWSTR, PDWORD);
        using QueryFullProcessImageNameAFn = BOOL(WINAPI*)(HANDLE, DWORD, LPSTR, PDWORD);
        using GetProcessImageFileNameWFn = DWORD(WINAPI*)(HANDLE, LPWSTR, DWORD);
        using GetProcessImageFileNameAFn = DWORD(WINAPI*)(HANDLE, LPSTR, DWORD);
        using GetProcessIdFn = DWORD(WINAPI*)(HANDLE);
        using GetThreadIdFn = DWORD(WINAPI*)(HANDLE);
        using IsWow64ProcessFn = BOOL(WINAPI*)(HANDLE, PBOOL);
        using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
        using Wow64DisableWow64FsRedirectionFn = BOOL(WINAPI*)(PVOID*);
        using Wow64RevertWow64FsRedirectionFn = BOOL(WINAPI*)(PVOID);
        using GetTempPathWFn = DWORD(WINAPI*)(DWORD, LPWSTR);
        using GetTempPathAFn = DWORD(WINAPI*)(DWORD, LPSTR);
        using GetTempFileNameWFn = UINT(WINAPI*)(LPCWSTR, LPCWSTR, UINT, LPWSTR);
        using GetTempFileNameAFn = UINT(WINAPI*)(LPCSTR, LPCSTR, UINT, LPSTR);
        using GetFullPathNameWFn = DWORD(WINAPI*)(LPCWSTR, DWORD, LPWSTR, LPWSTR*);
        using GetFullPathNameAFn = DWORD(WINAPI*)(LPCSTR, DWORD, LPSTR, LPSTR*);
        using SearchPathWFn = DWORD(WINAPI*)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPWSTR, LPWSTR*);
        using SearchPathAFn = DWORD(WINAPI*)(LPCSTR, LPCSTR, LPCSTR, DWORD, LPSTR, LPSTR*);
        using GetShortPathNameWFn = DWORD(WINAPI*)(LPCWSTR, LPWSTR, DWORD);
        using GetShortPathNameAFn = DWORD(WINAPI*)(LPCSTR, LPSTR, DWORD);
        using GetLongPathNameWFn = DWORD(WINAPI*)(LPCWSTR, LPWSTR, DWORD);
        using GetLongPathNameAFn = DWORD(WINAPI*)(LPCSTR, LPSTR, DWORD);
        using CreatePipeFn = BOOL(WINAPI*)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
        using CreateMailslotWFn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
        using CreateMailslotAFn = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
        using CreateDirectoryExWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES);
        using CreateDirectoryExAFn = BOOL(WINAPI*)(LPCSTR, LPCSTR, LPSECURITY_ATTRIBUTES);
        using WSAStartupFn = int(WSAAPI*)(WORD, LPWSADATA);
        using WSACleanupFn = int(WSAAPI*)();
        using SelectFn = int(WSAAPI*)(int, fd_set*, fd_set*, fd_set*, const timeval*);
        using IoctlSocketFn = int(WSAAPI*)(SOCKET, long, u_long*);
        using SetSockOptFn = int(WSAAPI*)(SOCKET, int, int, const char*, int);
        using GetSockOptFn = int(WSAAPI*)(SOCKET, int, int, char*, int*);
        using GetSockNameFn = int(WSAAPI*)(SOCKET, sockaddr*, int*);
        using GetPeerNameFn = int(WSAAPI*)(SOCKET, sockaddr*, int*);
        using WSAEventSelectFn = int(WSAAPI*)(SOCKET, WSAEVENT, long);
        using WSAAsyncSelectFn = int(WSAAPI*)(SOCKET, HWND, unsigned int, long);
        using HostEntPtr = hostent*;
        using GetHostByNameFn = HostEntPtr(WSAAPI*)(const char*);
        using GetHostByAddrFn = HostEntPtr(WSAAPI*)(const char*, int, int);
        using GetNameInfoWFn = INT(WSAAPI*)(const sockaddr*, int, PWCHAR, DWORD, PWCHAR, DWORD, INT);
        using GetNameInfoAFn = INT(WSAAPI*)(const sockaddr*, int, PCHAR, DWORD, PCHAR, DWORD, INT);
        using WinHttpAddRequestHeadersFn = BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, DWORD);
        using WinHttpSetCredentialsFn = BOOL(WINAPI*)(HINTERNET, DWORD, DWORD, LPCWSTR, LPCWSTR, LPVOID);
        using WinHttpCrackUrlFn = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS);
        using WinHttpCreateUrlFn = BOOL(WINAPI*)(LPURL_COMPONENTS, DWORD, LPWSTR, LPDWORD);
        using WinHttpSetTimeoutsFn = BOOL(WINAPI*)(HINTERNET, int, int, int, int);
        using HttpQueryInfoWFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD);
        using HttpQueryInfoAFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD);
        using InternetQueryOptionWFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, LPDWORD);
        using InternetQueryOptionAFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, LPDWORD);
        using NtOpenDirectoryObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
        using NtQueryDirectoryObjectFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
        using NtCreateSymbolicLinkObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
        using NtOpenSymbolicLinkObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
        using NtQuerySymbolicLinkObjectFn = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING, PULONG);
        using NtCreateSemaphoreFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG);
        using NtOpenSemaphoreFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
        using NtReleaseSemaphoreFn = NTSTATUS(NTAPI*)(HANDLE, LONG, PLONG);

        InlineHookRecord gCreateFileAHook{};
        InlineHookRecord gCreateFileWHook{};
        InlineHookRecord gCreateFile2Hook{};
        InlineHookRecord gReadFileHook{};
        InlineHookRecord gWriteFileHook{};
        InlineHookRecord gDeviceIoControlHook{};
        InlineHookRecord gDeleteFileWHook{};
        InlineHookRecord gDeleteFileAHook{};
        InlineHookRecord gMoveFileExWHook{};
        InlineHookRecord gMoveFileExAHook{};
        InlineHookRecord gCopyFileWHook{};
        InlineHookRecord gCopyFileAHook{};
        InlineHookRecord gCopyFileExWHook{};
        InlineHookRecord gCopyFileExAHook{};
        InlineHookRecord gGetFileAttributesWHook{};
        InlineHookRecord gGetFileAttributesAHook{};
        InlineHookRecord gGetFileAttributesExWHook{};
        InlineHookRecord gGetFileAttributesExAHook{};
        InlineHookRecord gSetFileAttributesWHook{};
        InlineHookRecord gSetFileAttributesAHook{};
        InlineHookRecord gFindFirstFileExWHook{};
        InlineHookRecord gFindFirstFileExAHook{};
        InlineHookRecord gCreateDirectoryWHook{};
        InlineHookRecord gCreateDirectoryAHook{};
        InlineHookRecord gRemoveDirectoryWHook{};
        InlineHookRecord gRemoveDirectoryAHook{};
        InlineHookRecord gSetFileInformationByHandleHook{};
        InlineHookRecord gCreateProcessAHook{};
        InlineHookRecord gCreateProcessWHook{};
        InlineHookRecord gOpenProcessHook{};
        InlineHookRecord gOpenThreadHook{};
        InlineHookRecord gTerminateProcessHook{};
        InlineHookRecord gCreateThreadHook{};
        InlineHookRecord gCreateRemoteThreadHook{};
        InlineHookRecord gSuspendThreadHook{};
        InlineHookRecord gResumeThreadHook{};
        InlineHookRecord gQueueUserApcHook{};
        InlineHookRecord gGetThreadContextHook{};
        InlineHookRecord gSetThreadContextHook{};
        InlineHookRecord gVirtualAllocExHook{};
        InlineHookRecord gVirtualFreeExHook{};
        InlineHookRecord gVirtualProtectExHook{};
        InlineHookRecord gWriteProcessMemoryHook{};
        InlineHookRecord gReadProcessMemoryHook{};
        InlineHookRecord gWinExecHook{};
        InlineHookRecord gShellExecuteExWHook{};
        InlineHookRecord gShellExecuteExAHook{};
        InlineHookRecord gLoadLibraryAHook{};
        InlineHookRecord gLoadLibraryWHook{};
        InlineHookRecord gLoadLibraryExAHook{};
        InlineHookRecord gLoadLibraryExWHook{};
        InlineHookRecord gLdrLoadDllHook{};
        InlineHookRecord gRegOpenKeyWHook{};
        InlineHookRecord gRegOpenKeyAHook{};
        InlineHookRecord gRegOpenKeyExWHook{};
        InlineHookRecord gRegOpenKeyExAHook{};
        InlineHookRecord gRegCreateKeyWHook{};
        InlineHookRecord gRegCreateKeyAHook{};
        InlineHookRecord gRegCreateKeyExWHook{};
        InlineHookRecord gRegCreateKeyExAHook{};
        InlineHookRecord gRegQueryValueExWHook{};
        InlineHookRecord gRegQueryValueExAHook{};
        InlineHookRecord gRegGetValueWHook{};
        InlineHookRecord gRegGetValueAHook{};
        InlineHookRecord gRegSetValueExWHook{};
        InlineHookRecord gRegSetValueExAHook{};
        InlineHookRecord gRegSetKeyValueWHook{};
        InlineHookRecord gRegSetKeyValueAHook{};
        InlineHookRecord gRegDeleteValueWHook{};
        InlineHookRecord gRegDeleteValueAHook{};
        InlineHookRecord gRegDeleteKeyWHook{};
        InlineHookRecord gRegDeleteKeyAHook{};
        InlineHookRecord gRegDeleteKeyExWHook{};
        InlineHookRecord gRegDeleteKeyExAHook{};
        InlineHookRecord gRegDeleteTreeWHook{};
        InlineHookRecord gRegDeleteTreeAHook{};
        InlineHookRecord gRegCopyTreeWHook{};
        InlineHookRecord gRegCopyTreeAHook{};
        InlineHookRecord gRegLoadKeyWHook{};
        InlineHookRecord gRegLoadKeyAHook{};
        InlineHookRecord gRegSaveKeyWHook{};
        InlineHookRecord gRegSaveKeyAHook{};
        InlineHookRecord gRegRenameKeyHook{};
        InlineHookRecord gRegEnumKeyExWHook{};
        InlineHookRecord gRegEnumKeyExAHook{};
        InlineHookRecord gRegEnumValueWHook{};
        InlineHookRecord gRegEnumValueAHook{};
        InlineHookRecord gRegCloseKeyHook{};
        InlineHookRecord gRegQueryInfoKeyWHook{};
        InlineHookRecord gRegQueryInfoKeyAHook{};
        InlineHookRecord gRegFlushKeyHook{};
        InlineHookRecord gRegDeleteKeyValueWHook{};
        InlineHookRecord gRegDeleteKeyValueAHook{};
        InlineHookRecord gRegConnectRegistryWHook{};
        InlineHookRecord gRegConnectRegistryAHook{};
        InlineHookRecord gConnectHook{};
        InlineHookRecord gWsaConnectHook{};
        InlineHookRecord gSendHook{};
        InlineHookRecord gWsaSendHook{};
        InlineHookRecord gSendToHook{};
        InlineHookRecord gRecvHook{};
        InlineHookRecord gWsaRecvHook{};
        InlineHookRecord gRecvFromHook{};
        InlineHookRecord gBindHook{};
        InlineHookRecord gListenHook{};
        InlineHookRecord gAcceptHook{};
        InlineHookRecord gSocketHook{};
        InlineHookRecord gWsaSocketWHook{};
        InlineHookRecord gWsaSocketAHook{};
        InlineHookRecord gCloseSocketHook{};
        InlineHookRecord gShutdownHook{};
        InlineHookRecord gNtCreateFileHook{};
        InlineHookRecord gNtOpenFileHook{};
        InlineHookRecord gNtReadFileHook{};
        InlineHookRecord gNtWriteFileHook{};
        InlineHookRecord gNtSetInformationFileHook{};
        InlineHookRecord gNtQueryInformationFileHook{};
        InlineHookRecord gNtDeleteFileHook{};
        InlineHookRecord gNtQueryAttributesFileHook{};
        InlineHookRecord gNtQueryFullAttributesFileHook{};
        InlineHookRecord gNtDeviceIoControlFileHook{};
        InlineHookRecord gNtFsControlFileHook{};
        InlineHookRecord gNtQueryDirectoryFileHook{};
        InlineHookRecord gNtQueryDirectoryFileExHook{};
        InlineHookRecord gNtCreateKeyHook{};
        InlineHookRecord gNtOpenKeyHook{};
        InlineHookRecord gNtOpenKeyExHook{};
        InlineHookRecord gNtSetValueKeyHook{};
        InlineHookRecord gNtQueryValueKeyHook{};
        InlineHookRecord gNtEnumerateKeyHook{};
        InlineHookRecord gNtEnumerateValueKeyHook{};
        InlineHookRecord gNtDeleteKeyHook{};
        InlineHookRecord gNtDeleteValueKeyHook{};
        InlineHookRecord gNtFlushKeyHook{};
        InlineHookRecord gNtRenameKeyHook{};
        InlineHookRecord gNtLoadKeyHook{};
        InlineHookRecord gNtSaveKeyHook{};
        InlineHookRecord gNtQueryKeyHook{};
        InlineHookRecord gNtQueryMultipleValueKeyHook{};
        InlineHookRecord gNtNotifyChangeKeyHook{};
        InlineHookRecord gNtLoadKey2Hook{};
        InlineHookRecord gNtSaveKeyExHook{};
        InlineHookRecord gNtLoadDriverHook{};
        InlineHookRecord gNtUnloadDriverHook{};
        InlineHookRecord gNtOpenProcessHook{};
        InlineHookRecord gNtOpenThreadHook{};
        InlineHookRecord gNtTerminateProcessHook{};
        InlineHookRecord gNtCreateUserProcessHook{};
        InlineHookRecord gNtCreateProcessExHook{};
        InlineHookRecord gNtCreateThreadExHook{};
        InlineHookRecord gNtAllocateVirtualMemoryHook{};
        InlineHookRecord gNtFreeVirtualMemoryHook{};
        InlineHookRecord gNtProtectVirtualMemoryHook{};
        InlineHookRecord gNtWriteVirtualMemoryHook{};
        InlineHookRecord gNtReadVirtualMemoryHook{};
        InlineHookRecord gNtMapViewOfSectionHook{};
        InlineHookRecord gNtUnmapViewOfSectionHook{};
        InlineHookRecord gNtDuplicateObjectHook{};
        InlineHookRecord gNtQueryInformationProcessHook{};
        InlineHookRecord gNtSetInformationProcessHook{};
        InlineHookRecord gNtQueryVirtualMemoryHook{};
        InlineHookRecord gNtCreateSectionHook{};
        InlineHookRecord gNtOpenSectionHook{};
        InlineHookRecord gNtQueueApcThreadHook{};
        InlineHookRecord gNtQueueApcThreadExHook{};
        InlineHookRecord gNtSuspendThreadHook{};
        InlineHookRecord gNtResumeThreadHook{};
        InlineHookRecord gNtGetContextThreadHook{};
        InlineHookRecord gNtSetContextThreadHook{};
        InlineHookRecord gCloseHandleHook{};
        InlineHookRecord gDuplicateHandleHook{};
        InlineHookRecord gCreateFileMappingWHook{};
        InlineHookRecord gCreateFileMappingAHook{};
        InlineHookRecord gOpenFileMappingWHook{};
        InlineHookRecord gOpenFileMappingAHook{};
        InlineHookRecord gMapViewOfFileHook{};
        InlineHookRecord gMapViewOfFileExHook{};
        InlineHookRecord gUnmapViewOfFileHook{};
        InlineHookRecord gFlushViewOfFileHook{};
        InlineHookRecord gFreeLibraryHook{};
        InlineHookRecord gGetProcAddressHook{};
        InlineHookRecord gLdrGetProcedureAddressHook{};
        InlineHookRecord gRegCreateKeyTransactedWHook{};
        InlineHookRecord gRegCreateKeyTransactedAHook{};
        InlineHookRecord gRegOpenKeyTransactedWHook{};
        InlineHookRecord gRegOpenKeyTransactedAHook{};
        InlineHookRecord gRegDeleteKeyTransactedWHook{};
        InlineHookRecord gRegDeleteKeyTransactedAHook{};
        InlineHookRecord gRegReplaceKeyWHook{};
        InlineHookRecord gRegReplaceKeyAHook{};
        InlineHookRecord gRegRestoreKeyWHook{};
        InlineHookRecord gRegRestoreKeyAHook{};
        InlineHookRecord gRegUnLoadKeyWHook{};
        InlineHookRecord gRegUnLoadKeyAHook{};
        InlineHookRecord gRegLoadAppKeyWHook{};
        InlineHookRecord gRegLoadAppKeyAHook{};
        InlineHookRecord gRegNotifyChangeKeyValueHook{};
        InlineHookRecord gNtCloseHook{};
        InlineHookRecord gNtCreateKeyTransactedHook{};
        InlineHookRecord gNtOpenKeyTransactedHook{};
        InlineHookRecord gNtOpenKeyTransactedExHook{};
        InlineHookRecord gNtReplaceKeyHook{};
        InlineHookRecord gNtRestoreKeyHook{};
        InlineHookRecord gNtUnloadKeyHook{};
        InlineHookRecord gNtUnloadKey2Hook{};
        InlineHookRecord gNtUnloadKeyExHook{};
        InlineHookRecord gOpenProcessTokenHook{};
        InlineHookRecord gOpenThreadTokenHook{};
        InlineHookRecord gAdjustTokenPrivilegesHook{};
        InlineHookRecord gDuplicateTokenHook{};
        InlineHookRecord gDuplicateTokenExHook{};
        InlineHookRecord gCreateProcessAsUserWHook{};
        InlineHookRecord gCreateProcessAsUserAHook{};
        InlineHookRecord gCreateProcessWithTokenWHook{};
        InlineHookRecord gLookupPrivilegeValueWHook{};
        InlineHookRecord gLookupPrivilegeValueAHook{};
        InlineHookRecord gOpenScManagerWHook{};
        InlineHookRecord gOpenScManagerAHook{};
        InlineHookRecord gOpenServiceWHook{};
        InlineHookRecord gOpenServiceAHook{};
        InlineHookRecord gCreateServiceWHook{};
        InlineHookRecord gCreateServiceAHook{};
        InlineHookRecord gChangeServiceConfigWHook{};
        InlineHookRecord gChangeServiceConfigAHook{};
        InlineHookRecord gStartServiceWHook{};
        InlineHookRecord gStartServiceAHook{};
        InlineHookRecord gControlServiceHook{};
        InlineHookRecord gDeleteServiceHook{};
        InlineHookRecord gCloseServiceHandleHook{};
        InlineHookRecord gWsaIoctlHook{};
        InlineHookRecord gWsaSendToHook{};
        InlineHookRecord gWsaRecvFromHook{};
        InlineHookRecord gGetAddrInfoWHook{};
        InlineHookRecord gGetAddrInfoAHook{};
        InlineHookRecord gDnsQueryWHook{};
        InlineHookRecord gDnsQueryAHook{};
        InlineHookRecord gWinHttpOpenHook{};
        InlineHookRecord gWinHttpConnectHook{};
        InlineHookRecord gWinHttpOpenRequestHook{};
        InlineHookRecord gWinHttpSendRequestHook{};
        InlineHookRecord gWinHttpReceiveResponseHook{};
        InlineHookRecord gWinHttpReadDataHook{};
        InlineHookRecord gWinHttpWriteDataHook{};
        InlineHookRecord gWinHttpCloseHandleHook{};
        InlineHookRecord gInternetOpenWHook{};
        InlineHookRecord gInternetOpenAHook{};
        InlineHookRecord gInternetConnectWHook{};
        InlineHookRecord gInternetConnectAHook{};
        InlineHookRecord gHttpOpenRequestWHook{};
        InlineHookRecord gHttpOpenRequestAHook{};
        InlineHookRecord gHttpSendRequestWHook{};
        InlineHookRecord gHttpSendRequestAHook{};
        InlineHookRecord gInternetReadFileHook{};
        InlineHookRecord gInternetWriteFileHook{};
        InlineHookRecord gInternetCloseHandleHook{};
        InlineHookRecord gCryptAcquireContextWHook{};
        InlineHookRecord gCryptAcquireContextAHook{};
        InlineHookRecord gCryptCreateHashHook{};
        InlineHookRecord gCryptHashDataHook{};
        InlineHookRecord gCryptDeriveKeyHook{};
        InlineHookRecord gCryptEncryptHook{};
        InlineHookRecord gCryptDecryptHook{};
        InlineHookRecord gCryptGenRandomHook{};
        InlineHookRecord gCryptReleaseContextHook{};
        InlineHookRecord gBCryptOpenAlgorithmProviderHook{};
        InlineHookRecord gBCryptCreateHashHook{};
        InlineHookRecord gBCryptHashDataHook{};
        InlineHookRecord gBCryptFinishHashHook{};
        InlineHookRecord gBCryptEncryptHook{};
        InlineHookRecord gBCryptDecryptHook{};
        InlineHookRecord gBCryptGenRandomHook{};
        InlineHookRecord gBCryptCloseAlgorithmProviderHook{};
        InlineHookRecord gBCryptDestroyHashHook{};
        InlineHookRecord gCoCreateInstanceHook{};
        InlineHookRecord gCoCreateInstanceExHook{};
        InlineHookRecord gCoGetClassObjectHook{};
        InlineHookRecord gVirtualAllocHook{};
        InlineHookRecord gVirtualFreeHook{};
        InlineHookRecord gVirtualProtectHook{};
        InlineHookRecord gCreateToolhelp32SnapshotHook{};
        InlineHookRecord gModule32FirstWHook{};
        InlineHookRecord gModule32NextWHook{};
        InlineHookRecord gModule32FirstAHook{};
        InlineHookRecord gModule32NextAHook{};
        InlineHookRecord gGetModuleHandleWHook{};
        InlineHookRecord gGetModuleHandleAHook{};
        InlineHookRecord gGetModuleHandleExWHook{};
        InlineHookRecord gGetModuleHandleExAHook{};
        InlineHookRecord gGetModuleFileNameWHook{};
        InlineHookRecord gGetModuleFileNameAHook{};
        InlineHookRecord gCreateHardLinkWHook{};
        InlineHookRecord gCreateHardLinkAHook{};
        InlineHookRecord gReplaceFileWHook{};
        InlineHookRecord gReplaceFileAHook{};
        InlineHookRecord gSetEndOfFileHook{};
        InlineHookRecord gLockFileExHook{};
        InlineHookRecord gUnlockFileExHook{};
        InlineHookRecord gShellExecuteWHook{};
        InlineHookRecord gShellExecuteAHook{};
        InlineHookRecord gCreateProcessWithLogonWHook{};
        InlineHookRecord gChangeServiceConfig2WHook{};
        InlineHookRecord gChangeServiceConfig2AHook{};
        InlineHookRecord gQueryServiceStatusExHook{};
        InlineHookRecord gQueryServiceConfigWHook{};
        InlineHookRecord gQueryServiceConfigAHook{};
        InlineHookRecord gEnumServicesStatusExWHook{};
        InlineHookRecord gEnumServicesStatusExAHook{};
        InlineHookRecord gWinHttpQueryHeadersHook{};
        InlineHookRecord gWinHttpQueryDataAvailableHook{};
        InlineHookRecord gWinHttpSetOptionHook{};
        InlineHookRecord gInternetOpenUrlWHook{};
        InlineHookRecord gInternetOpenUrlAHook{};
        InlineHookRecord gInternetQueryDataAvailableHook{};
        InlineHookRecord gInternetSetOptionWHook{};
        InlineHookRecord gInternetSetOptionAHook{};
        InlineHookRecord gInternetCrackUrlWHook{};
        InlineHookRecord gInternetCrackUrlAHook{};
        InlineHookRecord gUrlDownloadToFileWHook{};
        InlineHookRecord gUrlDownloadToFileAHook{};
        InlineHookRecord gCryptImportKeyHook{};
        InlineHookRecord gCryptExportKeyHook{};
        InlineHookRecord gCryptDestroyKeyHook{};
        InlineHookRecord gCryptDestroyHashHook{};
        InlineHookRecord gBCryptGenerateSymmetricKeyHook{};
        InlineHookRecord gBCryptImportKeyHook{};
        InlineHookRecord gBCryptImportKeyPairHook{};
        InlineHookRecord gBCryptDestroyKeyHook{};
        InlineHookRecord gCoInitializeExHook{};
        InlineHookRecord gCoInitializeSecurityHook{};
        InlineHookRecord gCoUninitializeHook{};
        InlineHookRecord gCreateRemoteThreadExHook{};
        InlineHookRecord gCreateSymbolicLinkWHook{};
        InlineHookRecord gCreateSymbolicLinkAHook{};
        InlineHookRecord gGetFinalPathNameByHandleWHook{};
        InlineHookRecord gGetFinalPathNameByHandleAHook{};
        InlineHookRecord gGetFileSizeExHook{};
        InlineHookRecord gSetFilePointerExHook{};
        InlineHookRecord gCreateNamedPipeWHook{};
        InlineHookRecord gCreateNamedPipeAHook{};
        InlineHookRecord gConnectNamedPipeHook{};
        InlineHookRecord gDisconnectNamedPipeHook{};
        InlineHookRecord gWaitNamedPipeWHook{};
        InlineHookRecord gWaitNamedPipeAHook{};
        InlineHookRecord gTransactNamedPipeHook{};
        InlineHookRecord gCreateMutexWHook{};
        InlineHookRecord gCreateMutexAHook{};
        InlineHookRecord gOpenMutexWHook{};
        InlineHookRecord gOpenMutexAHook{};
        InlineHookRecord gCreateEventWHook{};
        InlineHookRecord gCreateEventAHook{};
        InlineHookRecord gOpenEventWHook{};
        InlineHookRecord gOpenEventAHook{};
        InlineHookRecord gCreateSemaphoreWHook{};
        InlineHookRecord gCreateSemaphoreAHook{};
        InlineHookRecord gOpenSemaphoreWHook{};
        InlineHookRecord gOpenSemaphoreAHook{};
        InlineHookRecord gWaitForSingleObjectHook{};
        InlineHookRecord gWaitForMultipleObjectsHook{};
        InlineHookRecord gSetEventHook{};
        InlineHookRecord gResetEventHook{};
        InlineHookRecord gReleaseMutexHook{};
        InlineHookRecord gReleaseSemaphoreHook{};
        InlineHookRecord gGetEnvironmentVariableWHook{};
        InlineHookRecord gGetEnvironmentVariableAHook{};
        InlineHookRecord gSetEnvironmentVariableWHook{};
        InlineHookRecord gSetEnvironmentVariableAHook{};
        InlineHookRecord gExpandEnvironmentStringsWHook{};
        InlineHookRecord gExpandEnvironmentStringsAHook{};
        InlineHookRecord gSetDllDirectoryWHook{};
        InlineHookRecord gSetDllDirectoryAHook{};
        InlineHookRecord gSetDefaultDllDirectoriesHook{};
        InlineHookRecord gAddDllDirectoryHook{};
        InlineHookRecord gRemoveDllDirectoryHook{};
        InlineHookRecord gImpersonateLoggedOnUserHook{};
        InlineHookRecord gRevertToSelfHook{};
        InlineHookRecord gSetThreadTokenHook{};
        InlineHookRecord gSetWindowsHookExWHook{};
        InlineHookRecord gSetWindowsHookExAHook{};
        InlineHookRecord gUnhookWindowsHookExHook{};
        InlineHookRecord gEnumProcessesHook{};
        InlineHookRecord gEnumProcessModulesHook{};
        InlineHookRecord gEnumProcessModulesExHook{};
        InlineHookRecord gGetMappedFileNameWHook{};
        InlineHookRecord gGetMappedFileNameAHook{};
        InlineHookRecord gEnumWindowsHook{};
        InlineHookRecord gEnumChildWindowsHook{};
        InlineHookRecord gFindWindowWHook{};
        InlineHookRecord gFindWindowAHook{};
        InlineHookRecord gFindWindowExWHook{};
        InlineHookRecord gFindWindowExAHook{};
        InlineHookRecord gGetWindowThreadProcessIdHook{};
        InlineHookRecord gGetForegroundWindowHook{};
        InlineHookRecord gGetDcHook{};
        InlineHookRecord gReleaseDcHook{};
        InlineHookRecord gCreateCompatibleDcHook{};
        InlineHookRecord gDeleteDcHook{};
        InlineHookRecord gCreateCompatibleBitmapHook{};
        InlineHookRecord gBitBltHook{};
        InlineHookRecord gStretchBltHook{};
        InlineHookRecord gDeleteObjectHook{};
        InlineHookRecord gOpenClipboardHook{};
        InlineHookRecord gCloseClipboardHook{};
        InlineHookRecord gGetClipboardDataHook{};
        InlineHookRecord gSetClipboardDataHook{};
        InlineHookRecord gEmptyClipboardHook{};
        InlineHookRecord gStartTraceWHook{};
        InlineHookRecord gStartTraceAHook{};
        InlineHookRecord gControlTraceWHook{};
        InlineHookRecord gControlTraceAHook{};
        InlineHookRecord gEnableTraceEx2Hook{};
        InlineHookRecord gOpenTraceWHook{};
        InlineHookRecord gOpenTraceAHook{};
        InlineHookRecord gProcessTraceHook{};
        InlineHookRecord gCloseTraceHook{};
        InlineHookRecord gEventRegisterHook{};
        InlineHookRecord gEventUnregisterHook{};
        InlineHookRecord gEventWriteHook{};
        InlineHookRecord gEventWriteExHook{};
        InlineHookRecord gWinVerifyTrustHook{};
        InlineHookRecord gCryptQueryObjectHook{};
        InlineHookRecord gCertOpenStoreHook{};
        InlineHookRecord gCertCloseStoreHook{};
        InlineHookRecord gCertFindCertificateInStoreHook{};
        InlineHookRecord gCertGetCertificateChainHook{};
        InlineHookRecord gCertVerifyCertificateChainPolicyHook{};
        InlineHookRecord gCryptProtectDataHook{};
        InlineHookRecord gCryptUnprotectDataHook{};
        InlineHookRecord gNCryptOpenStorageProviderHook{};
        InlineHookRecord gNCryptOpenKeyHook{};
        InlineHookRecord gNCryptCreatePersistedKeyHook{};
        InlineHookRecord gNCryptFinalizeKeyHook{};
        InlineHookRecord gNCryptEncryptHook{};
        InlineHookRecord gNCryptDecryptHook{};
        InlineHookRecord gNCryptSignHashHook{};
        InlineHookRecord gNCryptVerifySignatureHook{};
        InlineHookRecord gNCryptExportKeyHook{};
        InlineHookRecord gNCryptImportKeyHook{};
        InlineHookRecord gNCryptDeleteKeyHook{};
        InlineHookRecord gNCryptFreeObjectHook{};
        InlineHookRecord gRpcStringBindingComposeWHook{};
        InlineHookRecord gRpcStringBindingComposeAHook{};
        InlineHookRecord gRpcBindingFromStringBindingWHook{};
        InlineHookRecord gRpcBindingFromStringBindingAHook{};
        InlineHookRecord gRpcBindingFreeHook{};
        InlineHookRecord gRpcMgmtEpEltInqBeginHook{};
        InlineHookRecord gRpcMgmtEpEltInqNextWHook{};
        InlineHookRecord gRpcMgmtEpEltInqNextAHook{};
        InlineHookRecord gRpcMgmtEpEltInqDoneHook{};
        InlineHookRecord gNtQueryInformationTokenHook{};
        InlineHookRecord gNtSetInformationTokenHook{};
        InlineHookRecord gNtAdjustPrivilegesTokenHook{};
        InlineHookRecord gNtCreateMutantHook{};
        InlineHookRecord gNtOpenMutantHook{};
        InlineHookRecord gNtReleaseMutantHook{};
        InlineHookRecord gNtCreateEventHook{};
        InlineHookRecord gNtOpenEventHook{};
        InlineHookRecord gNtSetEventHook{};
        InlineHookRecord gNtResetEventHook{};
        InlineHookRecord gNtWaitForSingleObjectHook{};
        InlineHookRecord gNtWaitForMultipleObjectsHook{};
        InlineHookRecord gNtQuerySystemInformationHook{};
        InlineHookRecord gNtQueryObjectHook{};
        InlineHookRecord gLogonUserWHook{};
        InlineHookRecord gLogonUserAHook{};
        InlineHookRecord gGetTokenInformationHook{};
        InlineHookRecord gSetTokenInformationHook{};
        InlineHookRecord gCheckTokenMembershipHook{};
        InlineHookRecord gCreateRestrictedTokenHook{};
        InlineHookRecord gImpersonateSelfHook{};
        InlineHookRecord gImpersonateNamedPipeClientHook{};
        InlineHookRecord gCredReadWHook{};
        InlineHookRecord gCredReadAHook{};
        InlineHookRecord gCredEnumerateWHook{};
        InlineHookRecord gCredEnumerateAHook{};
        InlineHookRecord gCredWriteWHook{};
        InlineHookRecord gCredWriteAHook{};
        InlineHookRecord gCredDeleteWHook{};
        InlineHookRecord gCredDeleteAHook{};
        InlineHookRecord gCredFreeHook{};
        InlineHookRecord gLsaOpenPolicyHook{};
        InlineHookRecord gLsaCloseHook{};
        InlineHookRecord gLsaEnumerateLogonSessionsHook{};
        InlineHookRecord gLsaGetLogonSessionDataHook{};
        InlineHookRecord gLsaFreeReturnBufferHook{};
        InlineHookRecord gLsaLookupNames2Hook{};
        InlineHookRecord gLsaLookupSids2Hook{};
        InlineHookRecord gOpenEventLogWHook{};
        InlineHookRecord gOpenEventLogAHook{};
        InlineHookRecord gRegisterEventSourceWHook{};
        InlineHookRecord gRegisterEventSourceAHook{};
        InlineHookRecord gReadEventLogWHook{};
        InlineHookRecord gReadEventLogAHook{};
        InlineHookRecord gClearEventLogWHook{};
        InlineHookRecord gClearEventLogAHook{};
        InlineHookRecord gReportEventWHook{};
        InlineHookRecord gReportEventAHook{};
        InlineHookRecord gCloseEventLogHook{};
        InlineHookRecord gNetUserEnumHook{};
        InlineHookRecord gNetLocalGroupEnumHook{};
        InlineHookRecord gNetGroupEnumHook{};
        InlineHookRecord gNetShareEnumHook{};
        InlineHookRecord gNetSessionEnumHook{};
        InlineHookRecord gNetServerEnumHook{};
        InlineHookRecord gNetWkstaGetInfoHook{};
        InlineHookRecord gNetApiBufferFreeHook{};
        InlineHookRecord gGetExtendedTcpTableHook{};
        InlineHookRecord gGetExtendedUdpTableHook{};
        InlineHookRecord gGetTcpTable2Hook{};
        InlineHookRecord gGetUdpTableHook{};
        InlineHookRecord gGetAdaptersAddressesHook{};
        InlineHookRecord gGetNetworkParamsHook{};
        InlineHookRecord gGetIpNetTable2Hook{};
        InlineHookRecord gGetIfTable2Hook{};
        InlineHookRecord gFreeMibTableHook{};
        InlineHookRecord gWtsOpenServerWHook{};
        InlineHookRecord gWtsOpenServerAHook{};
        InlineHookRecord gWtsCloseServerHook{};
        InlineHookRecord gWtsEnumerateSessionsWHook{};
        InlineHookRecord gWtsEnumerateSessionsAHook{};
        InlineHookRecord gWtsEnumerateProcessesWHook{};
        InlineHookRecord gWtsEnumerateProcessesAHook{};
        InlineHookRecord gWtsQuerySessionInformationWHook{};
        InlineHookRecord gWtsQuerySessionInformationAHook{};
        InlineHookRecord gWtsFreeMemoryHook{};
        InlineHookRecord gCreateJobObjectWHook{};
        InlineHookRecord gCreateJobObjectAHook{};
        InlineHookRecord gOpenJobObjectWHook{};
        InlineHookRecord gOpenJobObjectAHook{};
        InlineHookRecord gAssignProcessToJobObjectHook{};
        InlineHookRecord gTerminateJobObjectHook{};
        InlineHookRecord gSetInformationJobObjectHook{};
        InlineHookRecord gQueryInformationJobObjectHook{};
        InlineHookRecord gAcquireCredentialsHandleWHook{};
        InlineHookRecord gAcquireCredentialsHandleAHook{};
        InlineHookRecord gInitializeSecurityContextWHook{};
        InlineHookRecord gInitializeSecurityContextAHook{};
        InlineHookRecord gAcceptSecurityContextHook{};
        InlineHookRecord gEncryptMessageHook{};
        InlineHookRecord gDecryptMessageHook{};
        InlineHookRecord gDeleteSecurityContextHook{};
        InlineHookRecord gFreeCredentialsHandleHook{};
        InlineHookRecord gProcess32FirstWHook{};
        InlineHookRecord gProcess32FirstAHook{};
        InlineHookRecord gProcess32NextWHook{};
        InlineHookRecord gProcess32NextAHook{};
        InlineHookRecord gThread32FirstHook{};
        InlineHookRecord gThread32NextHook{};
        InlineHookRecord gHeap32ListFirstHook{};
        InlineHookRecord gHeap32ListNextHook{};
        InlineHookRecord gHeap32FirstHook{};
        InlineHookRecord gHeap32NextHook{};
        InlineHookRecord gQueryFullProcessImageNameWHook{};
        InlineHookRecord gQueryFullProcessImageNameAHook{};
        InlineHookRecord gGetProcessImageFileNameWHook{};
        InlineHookRecord gGetProcessImageFileNameAHook{};
        InlineHookRecord gGetProcessIdHook{};
        InlineHookRecord gGetThreadIdHook{};
        InlineHookRecord gIsWow64ProcessHook{};
        InlineHookRecord gIsWow64Process2Hook{};
        InlineHookRecord gWow64DisableWow64FsRedirectionHook{};
        InlineHookRecord gWow64RevertWow64FsRedirectionHook{};
        InlineHookRecord gGetTempPathWHook{};
        InlineHookRecord gGetTempPathAHook{};
        InlineHookRecord gGetTempFileNameWHook{};
        InlineHookRecord gGetTempFileNameAHook{};
        InlineHookRecord gGetFullPathNameWHook{};
        InlineHookRecord gGetFullPathNameAHook{};
        InlineHookRecord gSearchPathWHook{};
        InlineHookRecord gSearchPathAHook{};
        InlineHookRecord gGetShortPathNameWHook{};
        InlineHookRecord gGetShortPathNameAHook{};
        InlineHookRecord gGetLongPathNameWHook{};
        InlineHookRecord gGetLongPathNameAHook{};
        InlineHookRecord gCreatePipeHook{};
        InlineHookRecord gCreateMailslotWHook{};
        InlineHookRecord gCreateMailslotAHook{};
        InlineHookRecord gCreateDirectoryExWHook{};
        InlineHookRecord gCreateDirectoryExAHook{};
        InlineHookRecord gWsaStartupHook{};
        InlineHookRecord gWsaCleanupHook{};
        InlineHookRecord gSelectHook{};
        InlineHookRecord gIoctlSocketHook{};
        InlineHookRecord gSetSockOptHook{};
        InlineHookRecord gGetSockOptHook{};
        InlineHookRecord gGetSockNameHook{};
        InlineHookRecord gGetPeerNameHook{};
        InlineHookRecord gWsaEventSelectHook{};
        InlineHookRecord gWsaAsyncSelectHook{};
        InlineHookRecord gGetHostByNameHook{};
        InlineHookRecord gGetHostByAddrHook{};
        InlineHookRecord gGetNameInfoWHook{};
        InlineHookRecord gGetNameInfoAHook{};
        InlineHookRecord gWinHttpAddRequestHeadersHook{};
        InlineHookRecord gWinHttpSetCredentialsHook{};
        InlineHookRecord gWinHttpCrackUrlHook{};
        InlineHookRecord gWinHttpCreateUrlHook{};
        InlineHookRecord gWinHttpSetTimeoutsHook{};
        InlineHookRecord gHttpQueryInfoWHook{};
        InlineHookRecord gHttpQueryInfoAHook{};
        InlineHookRecord gInternetQueryOptionWHook{};
        InlineHookRecord gInternetQueryOptionAHook{};
        InlineHookRecord gNtOpenDirectoryObjectHook{};
        InlineHookRecord gNtQueryDirectoryObjectHook{};
        InlineHookRecord gNtCreateSymbolicLinkObjectHook{};
        InlineHookRecord gNtOpenSymbolicLinkObjectHook{};
        InlineHookRecord gNtQuerySymbolicLinkObjectHook{};
        InlineHookRecord gNtCreateSemaphoreHook{};
        InlineHookRecord gNtOpenSemaphoreHook{};
        InlineHookRecord gNtReleaseSemaphoreHook{};
        std::mutex gHookOperationMutex;

        const wchar_t* fsctlCodeToText(const ULONG fsControlCode)
        {
            switch (fsControlCode)
            {
            case FSCTL_REQUEST_OPLOCK:
                return L"FSCTL_REQUEST_OPLOCK";
            case FSCTL_REQUEST_BATCH_OPLOCK:
                return L"FSCTL_REQUEST_BATCH_OPLOCK";
            case FSCTL_REQUEST_FILTER_OPLOCK:
                return L"FSCTL_REQUEST_FILTER_OPLOCK";
            case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE:
                return L"FSCTL_OPLOCK_BREAK_ACKNOWLEDGE";
            case FSCTL_OPBATCH_ACK_CLOSE_PENDING:
                return L"FSCTL_OPBATCH_ACK_CLOSE_PENDING";
            case FSCTL_OPLOCK_BREAK_NOTIFY:
                return L"FSCTL_OPLOCK_BREAK_NOTIFY";
            case FSCTL_REQUEST_OPLOCK_LEVEL_1:
                return L"FSCTL_REQUEST_OPLOCK_LEVEL_1";
            case FSCTL_REQUEST_OPLOCK_LEVEL_2:
                return L"FSCTL_REQUEST_OPLOCK_LEVEL_2";
            default:
                return L"UNKNOWN_FSCTL";
            }
        }

        CreateFileAFn gCreateFileAOriginal = nullptr;
        CreateFileWFn gCreateFileWOriginal = nullptr;
        CreateFile2Fn gCreateFile2Original = nullptr;
        ReadFileFn gReadFileOriginal = nullptr;
        WriteFileFn gWriteFileOriginal = nullptr;
        DeviceIoControlFn gDeviceIoControlOriginal = nullptr;
        DeleteFileWFn gDeleteFileWOriginal = nullptr;
        DeleteFileAFn gDeleteFileAOriginal = nullptr;
        MoveFileExWFn gMoveFileExWOriginal = nullptr;
        MoveFileExAFn gMoveFileExAOriginal = nullptr;
        CopyFileWFn gCopyFileWOriginal = nullptr;
        CopyFileAFn gCopyFileAOriginal = nullptr;
        CopyFileExWFn gCopyFileExWOriginal = nullptr;
        CopyFileExAFn gCopyFileExAOriginal = nullptr;
        GetFileAttributesWFn gGetFileAttributesWOriginal = nullptr;
        GetFileAttributesAFn gGetFileAttributesAOriginal = nullptr;
        GetFileAttributesExWFn gGetFileAttributesExWOriginal = nullptr;
        GetFileAttributesExAFn gGetFileAttributesExAOriginal = nullptr;
        SetFileAttributesWFn gSetFileAttributesWOriginal = nullptr;
        SetFileAttributesAFn gSetFileAttributesAOriginal = nullptr;
        FindFirstFileExWFn gFindFirstFileExWOriginal = nullptr;
        FindFirstFileExAFn gFindFirstFileExAOriginal = nullptr;
        CreateDirectoryWFn gCreateDirectoryWOriginal = nullptr;
        CreateDirectoryAFn gCreateDirectoryAOriginal = nullptr;
        RemoveDirectoryWFn gRemoveDirectoryWOriginal = nullptr;
        RemoveDirectoryAFn gRemoveDirectoryAOriginal = nullptr;
        SetFileInformationByHandleFn gSetFileInformationByHandleOriginal = nullptr;
        CreateProcessAFn gCreateProcessAOriginal = nullptr;
        CreateProcessWFn gCreateProcessWOriginal = nullptr;
        OpenProcessFn gOpenProcessOriginal = nullptr;
        OpenThreadFn gOpenThreadOriginal = nullptr;
        TerminateProcessFn gTerminateProcessOriginal = nullptr;
        CreateThreadFn gCreateThreadOriginal = nullptr;
        CreateRemoteThreadFn gCreateRemoteThreadOriginal = nullptr;
        SuspendThreadFn gSuspendThreadOriginal = nullptr;
        ResumeThreadFn gResumeThreadOriginal = nullptr;
        QueueUserAPCFn gQueueUserApcOriginal = nullptr;
        GetThreadContextFn gGetThreadContextOriginal = nullptr;
        SetThreadContextFn gSetThreadContextOriginal = nullptr;
        VirtualAllocExFn gVirtualAllocExOriginal = nullptr;
        VirtualFreeExFn gVirtualFreeExOriginal = nullptr;
        VirtualProtectExFn gVirtualProtectExOriginal = nullptr;
        WriteProcessMemoryFn gWriteProcessMemoryOriginal = nullptr;
        ReadProcessMemoryFn gReadProcessMemoryOriginal = nullptr;
        WinExecFn gWinExecOriginal = nullptr;
        ShellExecuteExWFn gShellExecuteExWOriginal = nullptr;
        ShellExecuteExAFn gShellExecuteExAOriginal = nullptr;
        LoadLibraryAFn gLoadLibraryAOriginal = nullptr;
        LoadLibraryWFn gLoadLibraryWOriginal = nullptr;
        LoadLibraryExAFn gLoadLibraryExAOriginal = nullptr;
        LoadLibraryExWFn gLoadLibraryExWOriginal = nullptr;
        LdrLoadDllFn gLdrLoadDllOriginal = nullptr;
        RegOpenKeyWFn gRegOpenKeyWOriginal = nullptr;
        RegOpenKeyAFn gRegOpenKeyAOriginal = nullptr;
        RegOpenKeyExWFn gRegOpenKeyExWOriginal = nullptr;
        RegOpenKeyExAFn gRegOpenKeyExAOriginal = nullptr;
        RegCreateKeyWFn gRegCreateKeyWOriginal = nullptr;
        RegCreateKeyAFn gRegCreateKeyAOriginal = nullptr;
        RegCreateKeyExWFn gRegCreateKeyExWOriginal = nullptr;
        RegCreateKeyExAFn gRegCreateKeyExAOriginal = nullptr;
        RegQueryValueExWFn gRegQueryValueExWOriginal = nullptr;
        RegQueryValueExAFn gRegQueryValueExAOriginal = nullptr;
        RegGetValueWFn gRegGetValueWOriginal = nullptr;
        RegGetValueAFn gRegGetValueAOriginal = nullptr;
        RegSetValueExWFn gRegSetValueExWOriginal = nullptr;
        RegSetValueExAFn gRegSetValueExAOriginal = nullptr;
        RegSetKeyValueWFn gRegSetKeyValueWOriginal = nullptr;
        RegSetKeyValueAFn gRegSetKeyValueAOriginal = nullptr;
        RegDeleteValueWFn gRegDeleteValueWOriginal = nullptr;
        RegDeleteValueAFn gRegDeleteValueAOriginal = nullptr;
        RegDeleteKeyWFn gRegDeleteKeyWOriginal = nullptr;
        RegDeleteKeyAFn gRegDeleteKeyAOriginal = nullptr;
        RegDeleteKeyExWFn gRegDeleteKeyExWOriginal = nullptr;
        RegDeleteKeyExAFn gRegDeleteKeyExAOriginal = nullptr;
        RegDeleteTreeWFn gRegDeleteTreeWOriginal = nullptr;
        RegDeleteTreeAFn gRegDeleteTreeAOriginal = nullptr;
        RegCopyTreeWFn gRegCopyTreeWOriginal = nullptr;
        RegCopyTreeAFn gRegCopyTreeAOriginal = nullptr;
        RegLoadKeyWFn gRegLoadKeyWOriginal = nullptr;
        RegLoadKeyAFn gRegLoadKeyAOriginal = nullptr;
        RegSaveKeyWFn gRegSaveKeyWOriginal = nullptr;
        RegSaveKeyAFn gRegSaveKeyAOriginal = nullptr;
        RegRenameKeyFn gRegRenameKeyOriginal = nullptr;
        RegEnumKeyExWFn gRegEnumKeyExWOriginal = nullptr;
        RegEnumKeyExAFn gRegEnumKeyExAOriginal = nullptr;
        RegEnumValueWFn gRegEnumValueWOriginal = nullptr;
        RegEnumValueAFn gRegEnumValueAOriginal = nullptr;
        RegCloseKeyFn gRegCloseKeyOriginal = nullptr;
        RegQueryInfoKeyWFn gRegQueryInfoKeyWOriginal = nullptr;
        RegQueryInfoKeyAFn gRegQueryInfoKeyAOriginal = nullptr;
        RegFlushKeyFn gRegFlushKeyOriginal = nullptr;
        RegDeleteKeyValueWFn gRegDeleteKeyValueWOriginal = nullptr;
        RegDeleteKeyValueAFn gRegDeleteKeyValueAOriginal = nullptr;
        RegConnectRegistryWFn gRegConnectRegistryWOriginal = nullptr;
        RegConnectRegistryAFn gRegConnectRegistryAOriginal = nullptr;
        ConnectFn gConnectOriginal = nullptr;
        WSAConnectFn gWsaConnectOriginal = nullptr;
        SendFn gSendOriginal = nullptr;
        WSASendFn gWsaSendOriginal = nullptr;
        SendToFn gSendToOriginal = nullptr;
        RecvFn gRecvOriginal = nullptr;
        WSARecvFn gWsaRecvOriginal = nullptr;
        RecvFromFn gRecvFromOriginal = nullptr;
        BindFn gBindOriginal = nullptr;
        ListenFn gListenOriginal = nullptr;
        AcceptFn gAcceptOriginal = nullptr;
        SocketFn gSocketOriginal = nullptr;
        WSASocketWFn gWsaSocketWOriginal = nullptr;
        WSASocketAFn gWsaSocketAOriginal = nullptr;
        CloseSocketFn gCloseSocketOriginal = nullptr;
        ShutdownFn gShutdownOriginal = nullptr;
        NtCreateFileFn gNtCreateFileOriginal = nullptr;
        NtOpenFileFn gNtOpenFileOriginal = nullptr;
        NtReadFileFn gNtReadFileOriginal = nullptr;
        NtWriteFileFn gNtWriteFileOriginal = nullptr;
        NtSetInformationFileFn gNtSetInformationFileOriginal = nullptr;
        NtQueryInformationFileFn gNtQueryInformationFileOriginal = nullptr;
        NtDeleteFileFn gNtDeleteFileOriginal = nullptr;
        NtQueryAttributesFileFn gNtQueryAttributesFileOriginal = nullptr;
        NtQueryFullAttributesFileFn gNtQueryFullAttributesFileOriginal = nullptr;
        NtDeviceIoControlFileFn gNtDeviceIoControlFileOriginal = nullptr;
        NtFsControlFileFn gNtFsControlFileOriginal = nullptr;
        NtQueryDirectoryFileFn gNtQueryDirectoryFileOriginal = nullptr;
        NtQueryDirectoryFileExFn gNtQueryDirectoryFileExOriginal = nullptr;
        NtCreateKeyFn gNtCreateKeyOriginal = nullptr;
        NtOpenKeyFn gNtOpenKeyOriginal = nullptr;
        NtOpenKeyExFn gNtOpenKeyExOriginal = nullptr;
        NtSetValueKeyFn gNtSetValueKeyOriginal = nullptr;
        NtQueryValueKeyFn gNtQueryValueKeyOriginal = nullptr;
        NtEnumerateKeyFn gNtEnumerateKeyOriginal = nullptr;
        NtEnumerateValueKeyFn gNtEnumerateValueKeyOriginal = nullptr;
        NtDeleteKeyFn gNtDeleteKeyOriginal = nullptr;
        NtDeleteValueKeyFn gNtDeleteValueKeyOriginal = nullptr;
        NtFlushKeyFn gNtFlushKeyOriginal = nullptr;
        NtRenameKeyFn gNtRenameKeyOriginal = nullptr;
        NtLoadKeyFn gNtLoadKeyOriginal = nullptr;
        NtSaveKeyFn gNtSaveKeyOriginal = nullptr;
        NtQueryKeyFn gNtQueryKeyOriginal = nullptr;
        NtQueryMultipleValueKeyFn gNtQueryMultipleValueKeyOriginal = nullptr;
        NtNotifyChangeKeyFn gNtNotifyChangeKeyOriginal = nullptr;
        NtLoadKey2Fn gNtLoadKey2Original = nullptr;
        NtSaveKeyExFn gNtSaveKeyExOriginal = nullptr;
        NtLoadDriverFn gNtLoadDriverOriginal = nullptr;
        NtUnloadDriverFn gNtUnloadDriverOriginal = nullptr;
        NtOpenProcessFn gNtOpenProcessOriginal = nullptr;
        NtOpenThreadFn gNtOpenThreadOriginal = nullptr;
        NtTerminateProcessFn gNtTerminateProcessOriginal = nullptr;
        NtCreateUserProcessFn gNtCreateUserProcessOriginal = nullptr;
        NtCreateProcessExFn gNtCreateProcessExOriginal = nullptr;
        NtCreateThreadExFn gNtCreateThreadExOriginal = nullptr;
        NtAllocateVirtualMemoryFn gNtAllocateVirtualMemoryOriginal = nullptr;
        NtFreeVirtualMemoryFn gNtFreeVirtualMemoryOriginal = nullptr;
        NtProtectVirtualMemoryFn gNtProtectVirtualMemoryOriginal = nullptr;
        NtWriteVirtualMemoryFn gNtWriteVirtualMemoryOriginal = nullptr;
        NtReadVirtualMemoryFn gNtReadVirtualMemoryOriginal = nullptr;
        NtMapViewOfSectionFn gNtMapViewOfSectionOriginal = nullptr;
        NtUnmapViewOfSectionFn gNtUnmapViewOfSectionOriginal = nullptr;
        NtDuplicateObjectFn gNtDuplicateObjectOriginal = nullptr;
        NtQueryInformationProcessFn gNtQueryInformationProcessOriginal = nullptr;
        NtSetInformationProcessFn gNtSetInformationProcessOriginal = nullptr;
        NtQueryVirtualMemoryFn gNtQueryVirtualMemoryOriginal = nullptr;
        NtCreateSectionFn gNtCreateSectionOriginal = nullptr;
        NtOpenSectionFn gNtOpenSectionOriginal = nullptr;
        NtQueueApcThreadFn gNtQueueApcThreadOriginal = nullptr;
        NtQueueApcThreadExFn gNtQueueApcThreadExOriginal = nullptr;
        NtSuspendThreadFn gNtSuspendThreadOriginal = nullptr;
        NtResumeThreadFn gNtResumeThreadOriginal = nullptr;
        NtGetContextThreadFn gNtGetContextThreadOriginal = nullptr;
        NtSetContextThreadFn gNtSetContextThreadOriginal = nullptr;
        CloseHandleFn gCloseHandleOriginal = nullptr;
        DuplicateHandleFn gDuplicateHandleOriginal = nullptr;
        CreateFileMappingWFn gCreateFileMappingWOriginal = nullptr;
        CreateFileMappingAFn gCreateFileMappingAOriginal = nullptr;
        OpenFileMappingWFn gOpenFileMappingWOriginal = nullptr;
        OpenFileMappingAFn gOpenFileMappingAOriginal = nullptr;
        MapViewOfFileFn gMapViewOfFileOriginal = nullptr;
        MapViewOfFileExFn gMapViewOfFileExOriginal = nullptr;
        UnmapViewOfFileFn gUnmapViewOfFileOriginal = nullptr;
        FlushViewOfFileFn gFlushViewOfFileOriginal = nullptr;
        FreeLibraryFn gFreeLibraryOriginal = nullptr;
        GetProcAddressFn gGetProcAddressOriginal = nullptr;
        LdrGetProcedureAddressFn gLdrGetProcedureAddressOriginal = nullptr;
        RegCreateKeyTransactedWFn gRegCreateKeyTransactedWOriginal = nullptr;
        RegCreateKeyTransactedAFn gRegCreateKeyTransactedAOriginal = nullptr;
        RegOpenKeyTransactedWFn gRegOpenKeyTransactedWOriginal = nullptr;
        RegOpenKeyTransactedAFn gRegOpenKeyTransactedAOriginal = nullptr;
        RegDeleteKeyTransactedWFn gRegDeleteKeyTransactedWOriginal = nullptr;
        RegDeleteKeyTransactedAFn gRegDeleteKeyTransactedAOriginal = nullptr;
        RegReplaceKeyWFn gRegReplaceKeyWOriginal = nullptr;
        RegReplaceKeyAFn gRegReplaceKeyAOriginal = nullptr;
        RegRestoreKeyWFn gRegRestoreKeyWOriginal = nullptr;
        RegRestoreKeyAFn gRegRestoreKeyAOriginal = nullptr;
        RegUnLoadKeyWFn gRegUnLoadKeyWOriginal = nullptr;
        RegUnLoadKeyAFn gRegUnLoadKeyAOriginal = nullptr;
        RegLoadAppKeyWFn gRegLoadAppKeyWOriginal = nullptr;
        RegLoadAppKeyAFn gRegLoadAppKeyAOriginal = nullptr;
        RegNotifyChangeKeyValueFn gRegNotifyChangeKeyValueOriginal = nullptr;
        NtCloseFn gNtCloseOriginal = nullptr;
        NtCreateKeyTransactedFn gNtCreateKeyTransactedOriginal = nullptr;
        NtOpenKeyTransactedFn gNtOpenKeyTransactedOriginal = nullptr;
        NtOpenKeyTransactedExFn gNtOpenKeyTransactedExOriginal = nullptr;
        NtReplaceKeyFn gNtReplaceKeyOriginal = nullptr;
        NtRestoreKeyFn gNtRestoreKeyOriginal = nullptr;
        NtUnloadKeyFn gNtUnloadKeyOriginal = nullptr;
        NtUnloadKey2Fn gNtUnloadKey2Original = nullptr;
        NtUnloadKeyExFn gNtUnloadKeyExOriginal = nullptr;
        OpenProcessTokenFn gOpenProcessTokenOriginal = nullptr;
        OpenThreadTokenFn gOpenThreadTokenOriginal = nullptr;
        AdjustTokenPrivilegesFn gAdjustTokenPrivilegesOriginal = nullptr;
        DuplicateTokenFn gDuplicateTokenOriginal = nullptr;
        DuplicateTokenExFn gDuplicateTokenExOriginal = nullptr;
        CreateProcessAsUserWFn gCreateProcessAsUserWOriginal = nullptr;
        CreateProcessAsUserAFn gCreateProcessAsUserAOriginal = nullptr;
        CreateProcessWithTokenWFn gCreateProcessWithTokenWOriginal = nullptr;
        LookupPrivilegeValueWFn gLookupPrivilegeValueWOriginal = nullptr;
        LookupPrivilegeValueAFn gLookupPrivilegeValueAOriginal = nullptr;
        OpenSCManagerWFn gOpenScManagerWOriginal = nullptr;
        OpenSCManagerAFn gOpenScManagerAOriginal = nullptr;
        OpenServiceWFn gOpenServiceWOriginal = nullptr;
        OpenServiceAFn gOpenServiceAOriginal = nullptr;
        CreateServiceWFn gCreateServiceWOriginal = nullptr;
        CreateServiceAFn gCreateServiceAOriginal = nullptr;
        ChangeServiceConfigWFn gChangeServiceConfigWOriginal = nullptr;
        ChangeServiceConfigAFn gChangeServiceConfigAOriginal = nullptr;
        StartServiceWFn gStartServiceWOriginal = nullptr;
        StartServiceAFn gStartServiceAOriginal = nullptr;
        ControlServiceFn gControlServiceOriginal = nullptr;
        DeleteServiceFn gDeleteServiceOriginal = nullptr;
        CloseServiceHandleFn gCloseServiceHandleOriginal = nullptr;
        WSAIoctlFn gWsaIoctlOriginal = nullptr;
        WSASendToFn gWsaSendToOriginal = nullptr;
        WSARecvFromFn gWsaRecvFromOriginal = nullptr;
        GetAddrInfoWFn gGetAddrInfoWOriginal = nullptr;
        GetAddrInfoAFn gGetAddrInfoAOriginal = nullptr;
        DnsQueryWFn gDnsQueryWOriginal = nullptr;
        DnsQueryAFn gDnsQueryAOriginal = nullptr;
        WinHttpOpenFn gWinHttpOpenOriginal = nullptr;
        WinHttpConnectFn gWinHttpConnectOriginal = nullptr;
        WinHttpOpenRequestFn gWinHttpOpenRequestOriginal = nullptr;
        WinHttpSendRequestFn gWinHttpSendRequestOriginal = nullptr;
        WinHttpReceiveResponseFn gWinHttpReceiveResponseOriginal = nullptr;
        WinHttpReadDataFn gWinHttpReadDataOriginal = nullptr;
        WinHttpWriteDataFn gWinHttpWriteDataOriginal = nullptr;
        WinHttpCloseHandleFn gWinHttpCloseHandleOriginal = nullptr;
        InternetOpenWFn gInternetOpenWOriginal = nullptr;
        InternetOpenAFn gInternetOpenAOriginal = nullptr;
        InternetConnectWFn gInternetConnectWOriginal = nullptr;
        InternetConnectAFn gInternetConnectAOriginal = nullptr;
        HttpOpenRequestWFn gHttpOpenRequestWOriginal = nullptr;
        HttpOpenRequestAFn gHttpOpenRequestAOriginal = nullptr;
        HttpSendRequestWFn gHttpSendRequestWOriginal = nullptr;
        HttpSendRequestAFn gHttpSendRequestAOriginal = nullptr;
        InternetReadFileFn gInternetReadFileOriginal = nullptr;
        InternetWriteFileFn gInternetWriteFileOriginal = nullptr;
        InternetCloseHandleFn gInternetCloseHandleOriginal = nullptr;
        CryptAcquireContextWFn gCryptAcquireContextWOriginal = nullptr;
        CryptAcquireContextAFn gCryptAcquireContextAOriginal = nullptr;
        CryptCreateHashFn gCryptCreateHashOriginal = nullptr;
        CryptHashDataFn gCryptHashDataOriginal = nullptr;
        CryptDeriveKeyFn gCryptDeriveKeyOriginal = nullptr;
        CryptEncryptFn gCryptEncryptOriginal = nullptr;
        CryptDecryptFn gCryptDecryptOriginal = nullptr;
        CryptGenRandomFn gCryptGenRandomOriginal = nullptr;
        CryptReleaseContextFn gCryptReleaseContextOriginal = nullptr;
        BCryptOpenAlgorithmProviderFn gBCryptOpenAlgorithmProviderOriginal = nullptr;
        BCryptCreateHashFn gBCryptCreateHashOriginal = nullptr;
        BCryptHashDataFn gBCryptHashDataOriginal = nullptr;
        BCryptFinishHashFn gBCryptFinishHashOriginal = nullptr;
        BCryptEncryptFn gBCryptEncryptOriginal = nullptr;
        BCryptDecryptFn gBCryptDecryptOriginal = nullptr;
        BCryptGenRandomFn gBCryptGenRandomOriginal = nullptr;
        BCryptCloseAlgorithmProviderFn gBCryptCloseAlgorithmProviderOriginal = nullptr;
        BCryptDestroyHashFn gBCryptDestroyHashOriginal = nullptr;
        CoCreateInstanceFn gCoCreateInstanceOriginal = nullptr;
        CoCreateInstanceExFn gCoCreateInstanceExOriginal = nullptr;
        CoGetClassObjectFn gCoGetClassObjectOriginal = nullptr;
        VirtualAllocFn gVirtualAllocOriginal = nullptr;
        VirtualFreeFn gVirtualFreeOriginal = nullptr;
        VirtualProtectFn gVirtualProtectOriginal = nullptr;
        CreateToolhelp32SnapshotFn gCreateToolhelp32SnapshotOriginal = nullptr;
        Module32FirstWFn gModule32FirstWOriginal = nullptr;
        Module32NextWFn gModule32NextWOriginal = nullptr;
        Module32FirstAFn gModule32FirstAOriginal = nullptr;
        Module32NextAFn gModule32NextAOriginal = nullptr;
        GetModuleHandleWFn gGetModuleHandleWOriginal = nullptr;
        GetModuleHandleAFn gGetModuleHandleAOriginal = nullptr;
        GetModuleHandleExWFn gGetModuleHandleExWOriginal = nullptr;
        GetModuleHandleExAFn gGetModuleHandleExAOriginal = nullptr;
        GetModuleFileNameWFn gGetModuleFileNameWOriginal = nullptr;
        GetModuleFileNameAFn gGetModuleFileNameAOriginal = nullptr;
        CreateHardLinkWFn gCreateHardLinkWOriginal = nullptr;
        CreateHardLinkAFn gCreateHardLinkAOriginal = nullptr;
        ReplaceFileWFn gReplaceFileWOriginal = nullptr;
        ReplaceFileAFn gReplaceFileAOriginal = nullptr;
        SetEndOfFileFn gSetEndOfFileOriginal = nullptr;
        LockFileExFn gLockFileExOriginal = nullptr;
        UnlockFileExFn gUnlockFileExOriginal = nullptr;
        ShellExecuteWFn gShellExecuteWOriginal = nullptr;
        ShellExecuteAFn gShellExecuteAOriginal = nullptr;
        CreateProcessWithLogonWFn gCreateProcessWithLogonWOriginal = nullptr;
        ChangeServiceConfig2WFn gChangeServiceConfig2WOriginal = nullptr;
        ChangeServiceConfig2AFn gChangeServiceConfig2AOriginal = nullptr;
        QueryServiceStatusExFn gQueryServiceStatusExOriginal = nullptr;
        QueryServiceConfigWFn gQueryServiceConfigWOriginal = nullptr;
        QueryServiceConfigAFn gQueryServiceConfigAOriginal = nullptr;
        EnumServicesStatusExWFn gEnumServicesStatusExWOriginal = nullptr;
        EnumServicesStatusExAFn gEnumServicesStatusExAOriginal = nullptr;
        WinHttpQueryHeadersFn gWinHttpQueryHeadersOriginal = nullptr;
        WinHttpQueryDataAvailableFn gWinHttpQueryDataAvailableOriginal = nullptr;
        WinHttpSetOptionFn gWinHttpSetOptionOriginal = nullptr;
        InternetOpenUrlWFn gInternetOpenUrlWOriginal = nullptr;
        InternetOpenUrlAFn gInternetOpenUrlAOriginal = nullptr;
        InternetQueryDataAvailableFn gInternetQueryDataAvailableOriginal = nullptr;
        InternetSetOptionWFn gInternetSetOptionWOriginal = nullptr;
        InternetSetOptionAFn gInternetSetOptionAOriginal = nullptr;
        InternetCrackUrlWFn gInternetCrackUrlWOriginal = nullptr;
        InternetCrackUrlAFn gInternetCrackUrlAOriginal = nullptr;
        URLDownloadToFileWFn gUrlDownloadToFileWOriginal = nullptr;
        URLDownloadToFileAFn gUrlDownloadToFileAOriginal = nullptr;
        CryptImportKeyFn gCryptImportKeyOriginal = nullptr;
        CryptExportKeyFn gCryptExportKeyOriginal = nullptr;
        CryptDestroyKeyFn gCryptDestroyKeyOriginal = nullptr;
        CryptDestroyHashFn gCryptDestroyHashOriginal = nullptr;
        BCryptGenerateSymmetricKeyFn gBCryptGenerateSymmetricKeyOriginal = nullptr;
        BCryptImportKeyFn gBCryptImportKeyOriginal = nullptr;
        BCryptImportKeyPairFn gBCryptImportKeyPairOriginal = nullptr;
        BCryptDestroyKeyFn gBCryptDestroyKeyOriginal = nullptr;
        CoInitializeExFn gCoInitializeExOriginal = nullptr;
        CoInitializeSecurityFn gCoInitializeSecurityOriginal = nullptr;
        CoUninitializeFn gCoUninitializeOriginal = nullptr;
        CreateRemoteThreadExFn gCreateRemoteThreadExOriginal = nullptr;
        CreateSymbolicLinkWFn gCreateSymbolicLinkWOriginal = nullptr;
        CreateSymbolicLinkAFn gCreateSymbolicLinkAOriginal = nullptr;
        GetFinalPathNameByHandleWFn gGetFinalPathNameByHandleWOriginal = nullptr;
        GetFinalPathNameByHandleAFn gGetFinalPathNameByHandleAOriginal = nullptr;
        GetFileSizeExFn gGetFileSizeExOriginal = nullptr;
        SetFilePointerExFn gSetFilePointerExOriginal = nullptr;
        CreateNamedPipeWFn gCreateNamedPipeWOriginal = nullptr;
        CreateNamedPipeAFn gCreateNamedPipeAOriginal = nullptr;
        ConnectNamedPipeFn gConnectNamedPipeOriginal = nullptr;
        DisconnectNamedPipeFn gDisconnectNamedPipeOriginal = nullptr;
        WaitNamedPipeWFn gWaitNamedPipeWOriginal = nullptr;
        WaitNamedPipeAFn gWaitNamedPipeAOriginal = nullptr;
        TransactNamedPipeFn gTransactNamedPipeOriginal = nullptr;
        CreateMutexWFn gCreateMutexWOriginal = nullptr;
        CreateMutexAFn gCreateMutexAOriginal = nullptr;
        OpenMutexWFn gOpenMutexWOriginal = nullptr;
        OpenMutexAFn gOpenMutexAOriginal = nullptr;
        CreateEventWFn gCreateEventWOriginal = nullptr;
        CreateEventAFn gCreateEventAOriginal = nullptr;
        OpenEventWFn gOpenEventWOriginal = nullptr;
        OpenEventAFn gOpenEventAOriginal = nullptr;
        CreateSemaphoreWFn gCreateSemaphoreWOriginal = nullptr;
        CreateSemaphoreAFn gCreateSemaphoreAOriginal = nullptr;
        OpenSemaphoreWFn gOpenSemaphoreWOriginal = nullptr;
        OpenSemaphoreAFn gOpenSemaphoreAOriginal = nullptr;
        WaitForSingleObjectFn gWaitForSingleObjectOriginal = nullptr;
        WaitForMultipleObjectsFn gWaitForMultipleObjectsOriginal = nullptr;
        SetEventFn gSetEventOriginal = nullptr;
        ResetEventFn gResetEventOriginal = nullptr;
        ReleaseMutexFn gReleaseMutexOriginal = nullptr;
        ReleaseSemaphoreFn gReleaseSemaphoreOriginal = nullptr;
        GetEnvironmentVariableWFn gGetEnvironmentVariableWOriginal = nullptr;
        GetEnvironmentVariableAFn gGetEnvironmentVariableAOriginal = nullptr;
        SetEnvironmentVariableWFn gSetEnvironmentVariableWOriginal = nullptr;
        SetEnvironmentVariableAFn gSetEnvironmentVariableAOriginal = nullptr;
        ExpandEnvironmentStringsWFn gExpandEnvironmentStringsWOriginal = nullptr;
        ExpandEnvironmentStringsAFn gExpandEnvironmentStringsAOriginal = nullptr;
        SetDllDirectoryWFn gSetDllDirectoryWOriginal = nullptr;
        SetDllDirectoryAFn gSetDllDirectoryAOriginal = nullptr;
        SetDefaultDllDirectoriesFn gSetDefaultDllDirectoriesOriginal = nullptr;
        AddDllDirectoryFn gAddDllDirectoryOriginal = nullptr;
        RemoveDllDirectoryFn gRemoveDllDirectoryOriginal = nullptr;
        ImpersonateLoggedOnUserFn gImpersonateLoggedOnUserOriginal = nullptr;
        RevertToSelfFn gRevertToSelfOriginal = nullptr;
        SetThreadTokenFn gSetThreadTokenOriginal = nullptr;
        SetWindowsHookExWFn gSetWindowsHookExWOriginal = nullptr;
        SetWindowsHookExAFn gSetWindowsHookExAOriginal = nullptr;
        UnhookWindowsHookExFn gUnhookWindowsHookExOriginal = nullptr;
        EnumProcessesFn gEnumProcessesOriginal = nullptr;
        EnumProcessModulesFn gEnumProcessModulesOriginal = nullptr;
        EnumProcessModulesExFn gEnumProcessModulesExOriginal = nullptr;
        GetMappedFileNameWFn gGetMappedFileNameWOriginal = nullptr;
        GetMappedFileNameAFn gGetMappedFileNameAOriginal = nullptr;
        EnumWindowsFn gEnumWindowsOriginal = nullptr;
        EnumChildWindowsFn gEnumChildWindowsOriginal = nullptr;
        FindWindowWFn gFindWindowWOriginal = nullptr;
        FindWindowAFn gFindWindowAOriginal = nullptr;
        FindWindowExWFn gFindWindowExWOriginal = nullptr;
        FindWindowExAFn gFindWindowExAOriginal = nullptr;
        GetWindowThreadProcessIdFn gGetWindowThreadProcessIdOriginal = nullptr;
        GetForegroundWindowFn gGetForegroundWindowOriginal = nullptr;
        GetDCFn gGetDcOriginal = nullptr;
        ReleaseDCFn gReleaseDcOriginal = nullptr;
        CreateCompatibleDCFn gCreateCompatibleDcOriginal = nullptr;
        DeleteDCFn gDeleteDcOriginal = nullptr;
        CreateCompatibleBitmapFn gCreateCompatibleBitmapOriginal = nullptr;
        BitBltFn gBitBltOriginal = nullptr;
        StretchBltFn gStretchBltOriginal = nullptr;
        DeleteObjectFn gDeleteObjectOriginal = nullptr;
        OpenClipboardFn gOpenClipboardOriginal = nullptr;
        CloseClipboardFn gCloseClipboardOriginal = nullptr;
        GetClipboardDataFn gGetClipboardDataOriginal = nullptr;
        SetClipboardDataFn gSetClipboardDataOriginal = nullptr;
        EmptyClipboardFn gEmptyClipboardOriginal = nullptr;
        StartTraceWFn gStartTraceWOriginal = nullptr;
        StartTraceAFn gStartTraceAOriginal = nullptr;
        ControlTraceWFn gControlTraceWOriginal = nullptr;
        ControlTraceAFn gControlTraceAOriginal = nullptr;
        EnableTraceEx2Fn gEnableTraceEx2Original = nullptr;
        OpenTraceWFn gOpenTraceWOriginal = nullptr;
        OpenTraceAFn gOpenTraceAOriginal = nullptr;
        ProcessTraceFn gProcessTraceOriginal = nullptr;
        CloseTraceFn gCloseTraceOriginal = nullptr;
        EventRegisterFn gEventRegisterOriginal = nullptr;
        EventUnregisterFn gEventUnregisterOriginal = nullptr;
        EventWriteFn gEventWriteOriginal = nullptr;
        EventWriteExFn gEventWriteExOriginal = nullptr;
        WinVerifyTrustFn gWinVerifyTrustOriginal = nullptr;
        CryptQueryObjectFn gCryptQueryObjectOriginal = nullptr;
        CertOpenStoreFn gCertOpenStoreOriginal = nullptr;
        CertCloseStoreFn gCertCloseStoreOriginal = nullptr;
        CertFindCertificateInStoreFn gCertFindCertificateInStoreOriginal = nullptr;
        CertGetCertificateChainFn gCertGetCertificateChainOriginal = nullptr;
        CertVerifyCertificateChainPolicyFn gCertVerifyCertificateChainPolicyOriginal = nullptr;
        CryptProtectDataFn gCryptProtectDataOriginal = nullptr;
        CryptUnprotectDataFn gCryptUnprotectDataOriginal = nullptr;
        NCryptOpenStorageProviderFn gNCryptOpenStorageProviderOriginal = nullptr;
        NCryptOpenKeyFn gNCryptOpenKeyOriginal = nullptr;
        NCryptCreatePersistedKeyFn gNCryptCreatePersistedKeyOriginal = nullptr;
        NCryptFinalizeKeyFn gNCryptFinalizeKeyOriginal = nullptr;
        NCryptEncryptFn gNCryptEncryptOriginal = nullptr;
        NCryptDecryptFn gNCryptDecryptOriginal = nullptr;
        NCryptSignHashFn gNCryptSignHashOriginal = nullptr;
        NCryptVerifySignatureFn gNCryptVerifySignatureOriginal = nullptr;
        NCryptExportKeyFn gNCryptExportKeyOriginal = nullptr;
        NCryptImportKeyFn gNCryptImportKeyOriginal = nullptr;
        NCryptDeleteKeyFn gNCryptDeleteKeyOriginal = nullptr;
        NCryptFreeObjectFn gNCryptFreeObjectOriginal = nullptr;
        RpcStringBindingComposeWFn gRpcStringBindingComposeWOriginal = nullptr;
        RpcStringBindingComposeAFn gRpcStringBindingComposeAOriginal = nullptr;
        RpcBindingFromStringBindingWFn gRpcBindingFromStringBindingWOriginal = nullptr;
        RpcBindingFromStringBindingAFn gRpcBindingFromStringBindingAOriginal = nullptr;
        RpcBindingFreeFn gRpcBindingFreeOriginal = nullptr;
        RpcMgmtEpEltInqBeginFn gRpcMgmtEpEltInqBeginOriginal = nullptr;
        RpcMgmtEpEltInqNextWFn gRpcMgmtEpEltInqNextWOriginal = nullptr;
        RpcMgmtEpEltInqNextAFn gRpcMgmtEpEltInqNextAOriginal = nullptr;
        RpcMgmtEpEltInqDoneFn gRpcMgmtEpEltInqDoneOriginal = nullptr;
        NtQueryInformationTokenFn gNtQueryInformationTokenOriginal = nullptr;
        NtSetInformationTokenFn gNtSetInformationTokenOriginal = nullptr;
        NtAdjustPrivilegesTokenFn gNtAdjustPrivilegesTokenOriginal = nullptr;
        NtCreateMutantFn gNtCreateMutantOriginal = nullptr;
        NtOpenMutantFn gNtOpenMutantOriginal = nullptr;
        NtReleaseMutantFn gNtReleaseMutantOriginal = nullptr;
        NtCreateEventFn gNtCreateEventOriginal = nullptr;
        NtOpenEventFn gNtOpenEventOriginal = nullptr;
        NtSetEventFn gNtSetEventOriginal = nullptr;
        NtResetEventFn gNtResetEventOriginal = nullptr;
        NtWaitForSingleObjectFn gNtWaitForSingleObjectOriginal = nullptr;
        NtWaitForMultipleObjectsFn gNtWaitForMultipleObjectsOriginal = nullptr;
        NtQuerySystemInformationFn gNtQuerySystemInformationOriginal = nullptr;
        NtQueryObjectFn gNtQueryObjectOriginal = nullptr;
        LogonUserWFn gLogonUserWOriginal = nullptr;
        LogonUserAFn gLogonUserAOriginal = nullptr;
        GetTokenInformationFn gGetTokenInformationOriginal = nullptr;
        SetTokenInformationFn gSetTokenInformationOriginal = nullptr;
        CheckTokenMembershipFn gCheckTokenMembershipOriginal = nullptr;
        CreateRestrictedTokenFn gCreateRestrictedTokenOriginal = nullptr;
        ImpersonateSelfFn gImpersonateSelfOriginal = nullptr;
        ImpersonateNamedPipeClientFn gImpersonateNamedPipeClientOriginal = nullptr;
        CredReadWFn gCredReadWOriginal = nullptr;
        CredReadAFn gCredReadAOriginal = nullptr;
        CredEnumerateWFn gCredEnumerateWOriginal = nullptr;
        CredEnumerateAFn gCredEnumerateAOriginal = nullptr;
        CredWriteWFn gCredWriteWOriginal = nullptr;
        CredWriteAFn gCredWriteAOriginal = nullptr;
        CredDeleteWFn gCredDeleteWOriginal = nullptr;
        CredDeleteAFn gCredDeleteAOriginal = nullptr;
        CredFreeFn gCredFreeOriginal = nullptr;
        LsaOpenPolicyFn gLsaOpenPolicyOriginal = nullptr;
        LsaCloseFn gLsaCloseOriginal = nullptr;
        LsaEnumerateLogonSessionsFn gLsaEnumerateLogonSessionsOriginal = nullptr;
        LsaGetLogonSessionDataFn gLsaGetLogonSessionDataOriginal = nullptr;
        LsaFreeReturnBufferFn gLsaFreeReturnBufferOriginal = nullptr;
        LsaLookupNames2Fn gLsaLookupNames2Original = nullptr;
        LsaLookupSids2Fn gLsaLookupSids2Original = nullptr;
        OpenEventLogWFn gOpenEventLogWOriginal = nullptr;
        OpenEventLogAFn gOpenEventLogAOriginal = nullptr;
        RegisterEventSourceWFn gRegisterEventSourceWOriginal = nullptr;
        RegisterEventSourceAFn gRegisterEventSourceAOriginal = nullptr;
        ReadEventLogWFn gReadEventLogWOriginal = nullptr;
        ReadEventLogAFn gReadEventLogAOriginal = nullptr;
        ClearEventLogWFn gClearEventLogWOriginal = nullptr;
        ClearEventLogAFn gClearEventLogAOriginal = nullptr;
        ReportEventWFn gReportEventWOriginal = nullptr;
        ReportEventAFn gReportEventAOriginal = nullptr;
        CloseEventLogFn gCloseEventLogOriginal = nullptr;
        NetUserEnumFn gNetUserEnumOriginal = nullptr;
        NetLocalGroupEnumFn gNetLocalGroupEnumOriginal = nullptr;
        NetGroupEnumFn gNetGroupEnumOriginal = nullptr;
        NetShareEnumFn gNetShareEnumOriginal = nullptr;
        NetSessionEnumFn gNetSessionEnumOriginal = nullptr;
        NetServerEnumFn gNetServerEnumOriginal = nullptr;
        NetWkstaGetInfoFn gNetWkstaGetInfoOriginal = nullptr;
        NetApiBufferFreeFn gNetApiBufferFreeOriginal = nullptr;
        GetExtendedTcpTableFn gGetExtendedTcpTableOriginal = nullptr;
        GetExtendedUdpTableFn gGetExtendedUdpTableOriginal = nullptr;
        GetTcpTable2Fn gGetTcpTable2Original = nullptr;
        GetUdpTableFn gGetUdpTableOriginal = nullptr;
        GetAdaptersAddressesFn gGetAdaptersAddressesOriginal = nullptr;
        GetNetworkParamsFn gGetNetworkParamsOriginal = nullptr;
        GetIpNetTable2Fn gGetIpNetTable2Original = nullptr;
        GetIfTable2Fn gGetIfTable2Original = nullptr;
        FreeMibTableFn gFreeMibTableOriginal = nullptr;
        WTSOpenServerWFn gWtsOpenServerWOriginal = nullptr;
        WTSOpenServerAFn gWtsOpenServerAOriginal = nullptr;
        WTSCloseServerFn gWtsCloseServerOriginal = nullptr;
        WTSEnumerateSessionsWFn gWtsEnumerateSessionsWOriginal = nullptr;
        WTSEnumerateSessionsAFn gWtsEnumerateSessionsAOriginal = nullptr;
        WTSEnumerateProcessesWFn gWtsEnumerateProcessesWOriginal = nullptr;
        WTSEnumerateProcessesAFn gWtsEnumerateProcessesAOriginal = nullptr;
        WTSQuerySessionInformationWFn gWtsQuerySessionInformationWOriginal = nullptr;
        WTSQuerySessionInformationAFn gWtsQuerySessionInformationAOriginal = nullptr;
        WTSFreeMemoryFn gWtsFreeMemoryOriginal = nullptr;
        CreateJobObjectWFn gCreateJobObjectWOriginal = nullptr;
        CreateJobObjectAFn gCreateJobObjectAOriginal = nullptr;
        OpenJobObjectWFn gOpenJobObjectWOriginal = nullptr;
        OpenJobObjectAFn gOpenJobObjectAOriginal = nullptr;
        AssignProcessToJobObjectFn gAssignProcessToJobObjectOriginal = nullptr;
        TerminateJobObjectFn gTerminateJobObjectOriginal = nullptr;
        SetInformationJobObjectFn gSetInformationJobObjectOriginal = nullptr;
        QueryInformationJobObjectFn gQueryInformationJobObjectOriginal = nullptr;
        AcquireCredentialsHandleWFn gAcquireCredentialsHandleWOriginal = nullptr;
        AcquireCredentialsHandleAFn gAcquireCredentialsHandleAOriginal = nullptr;
        InitializeSecurityContextWFn gInitializeSecurityContextWOriginal = nullptr;
        InitializeSecurityContextAFn gInitializeSecurityContextAOriginal = nullptr;
        AcceptSecurityContextFn gAcceptSecurityContextOriginal = nullptr;
        EncryptMessageFn gEncryptMessageOriginal = nullptr;
        DecryptMessageFn gDecryptMessageOriginal = nullptr;
        DeleteSecurityContextFn gDeleteSecurityContextOriginal = nullptr;
        FreeCredentialsHandleFn gFreeCredentialsHandleOriginal = nullptr;
        Process32FirstWFn gProcess32FirstWOriginal = nullptr;
        Process32FirstAFn gProcess32FirstAOriginal = nullptr;
        Process32NextWFn gProcess32NextWOriginal = nullptr;
        Process32NextAFn gProcess32NextAOriginal = nullptr;
        Thread32FirstFn gThread32FirstOriginal = nullptr;
        Thread32NextFn gThread32NextOriginal = nullptr;
        Heap32ListFirstFn gHeap32ListFirstOriginal = nullptr;
        Heap32ListNextFn gHeap32ListNextOriginal = nullptr;
        Heap32FirstFn gHeap32FirstOriginal = nullptr;
        Heap32NextFn gHeap32NextOriginal = nullptr;
        QueryFullProcessImageNameWFn gQueryFullProcessImageNameWOriginal = nullptr;
        QueryFullProcessImageNameAFn gQueryFullProcessImageNameAOriginal = nullptr;
        GetProcessImageFileNameWFn gGetProcessImageFileNameWOriginal = nullptr;
        GetProcessImageFileNameAFn gGetProcessImageFileNameAOriginal = nullptr;
        GetProcessIdFn gGetProcessIdOriginal = nullptr;
        GetThreadIdFn gGetThreadIdOriginal = nullptr;
        IsWow64ProcessFn gIsWow64ProcessOriginal = nullptr;
        IsWow64Process2Fn gIsWow64Process2Original = nullptr;
        Wow64DisableWow64FsRedirectionFn gWow64DisableWow64FsRedirectionOriginal = nullptr;
        Wow64RevertWow64FsRedirectionFn gWow64RevertWow64FsRedirectionOriginal = nullptr;
        GetTempPathWFn gGetTempPathWOriginal = nullptr;
        GetTempPathAFn gGetTempPathAOriginal = nullptr;
        GetTempFileNameWFn gGetTempFileNameWOriginal = nullptr;
        GetTempFileNameAFn gGetTempFileNameAOriginal = nullptr;
        GetFullPathNameWFn gGetFullPathNameWOriginal = nullptr;
        GetFullPathNameAFn gGetFullPathNameAOriginal = nullptr;
        SearchPathWFn gSearchPathWOriginal = nullptr;
        SearchPathAFn gSearchPathAOriginal = nullptr;
        GetShortPathNameWFn gGetShortPathNameWOriginal = nullptr;
        GetShortPathNameAFn gGetShortPathNameAOriginal = nullptr;
        GetLongPathNameWFn gGetLongPathNameWOriginal = nullptr;
        GetLongPathNameAFn gGetLongPathNameAOriginal = nullptr;
        CreatePipeFn gCreatePipeOriginal = nullptr;
        CreateMailslotWFn gCreateMailslotWOriginal = nullptr;
        CreateMailslotAFn gCreateMailslotAOriginal = nullptr;
        CreateDirectoryExWFn gCreateDirectoryExWOriginal = nullptr;
        CreateDirectoryExAFn gCreateDirectoryExAOriginal = nullptr;
        WSAStartupFn gWsaStartupOriginal = nullptr;
        WSACleanupFn gWsaCleanupOriginal = nullptr;
        SelectFn gSelectOriginal = nullptr;
        IoctlSocketFn gIoctlSocketOriginal = nullptr;
        SetSockOptFn gSetSockOptOriginal = nullptr;
        GetSockOptFn gGetSockOptOriginal = nullptr;
        GetSockNameFn gGetSockNameOriginal = nullptr;
        GetPeerNameFn gGetPeerNameOriginal = nullptr;
        WSAEventSelectFn gWsaEventSelectOriginal = nullptr;
        WSAAsyncSelectFn gWsaAsyncSelectOriginal = nullptr;
        GetHostByNameFn gGetHostByNameOriginal = nullptr;
        GetHostByAddrFn gGetHostByAddrOriginal = nullptr;
        GetNameInfoWFn gGetNameInfoWOriginal = nullptr;
        GetNameInfoAFn gGetNameInfoAOriginal = nullptr;
        WinHttpAddRequestHeadersFn gWinHttpAddRequestHeadersOriginal = nullptr;
        WinHttpSetCredentialsFn gWinHttpSetCredentialsOriginal = nullptr;
        WinHttpCrackUrlFn gWinHttpCrackUrlOriginal = nullptr;
        WinHttpCreateUrlFn gWinHttpCreateUrlOriginal = nullptr;
        WinHttpSetTimeoutsFn gWinHttpSetTimeoutsOriginal = nullptr;
        HttpQueryInfoWFn gHttpQueryInfoWOriginal = nullptr;
        HttpQueryInfoAFn gHttpQueryInfoAOriginal = nullptr;
        InternetQueryOptionWFn gInternetQueryOptionWOriginal = nullptr;
        InternetQueryOptionAFn gInternetQueryOptionAOriginal = nullptr;
        NtOpenDirectoryObjectFn gNtOpenDirectoryObjectOriginal = nullptr;
        NtQueryDirectoryObjectFn gNtQueryDirectoryObjectOriginal = nullptr;
        NtCreateSymbolicLinkObjectFn gNtCreateSymbolicLinkObjectOriginal = nullptr;
        NtOpenSymbolicLinkObjectFn gNtOpenSymbolicLinkObjectOriginal = nullptr;
        NtQuerySymbolicLinkObjectFn gNtQuerySymbolicLinkObjectOriginal = nullptr;
        NtCreateSemaphoreFn gNtCreateSemaphoreOriginal = nullptr;
        NtOpenSemaphoreFn gNtOpenSemaphoreOriginal = nullptr;
        NtReleaseSemaphoreFn gNtReleaseSemaphoreOriginal = nullptr;

        thread_local bool gHookReentryGuard = false;

        class ScopedHookGuard
        {
        public:
            ScopedHookGuard()
            {
                bypass_ = gHookReentryGuard || isInlineHookInternalBypassActive();
                if (!bypass_)
                {
                    gHookReentryGuard = true;
                }
            }

            ~ScopedHookGuard()
            {
                if (!bypass_)
                {
                    gHookReentryGuard = false;
                }
            }

            bool bypass() const
            {
                return bypass_;
            }

        private:
            bool bypass_ = false;
        };

        struct HookBinding
        {
            const wchar_t* moduleName;                              // moduleName: Name of the module where the export resides.
            const char* procName;                                   // procName: Exported function name.
            ks::winapi_monitor::EventCategory categoryValue;        // categoryValue: Corresponding monitoring category.
            InlineHookRecord* hookRecord;                           // hookRecord: Hook status record corresponding to this API.
            void* hookAddress;                                      // hookAddress: Address of the Hooked wrapper function.
            void** originalOut;                                     // originalOut: Trampoline return address.
        };

        struct RawHookBinding
        {
            std::wstring moduleName;                                // moduleName: Raw Hook target module name.
            std::string procName;                                   // procName: Raw Hook target export name.
            std::wstring procNameWide;                              // procNameWide: Wide-character export name used for event reporting.
            ks::winapi_monitor::EventCategory categoryValue = ks::winapi_monitor::EventCategory::kProcess; // categoryValue: Roughly categorized by module.
            InlineHookRecord hookRecord{};                          // hookRecord: Raw Hook inline patch state.
            void* originalAddress = nullptr;                        // originalAddress: The trampoline generated by installInlineHook.
            void* entryStubAddress = nullptr;                       // entryStubAddress: Dynamically generated generic entry stub.
        };

        struct FakeSuccessRuntimeRule
        {
            std::wstring moduleName;                                // moduleName: Module name used for event reporting.
            std::wstring installModuleName;                         // installModuleName: The module name passed to GetModuleHandleW, defaulting to appending .dll.
            std::wstring apiName;                                   // apiName: API name used for event reporting.
            std::string apiNameAnsi;                                // apiNameAnsi: ANSI export name passed to GetProcAddress.
            std::wstring matchKey;                                  // matchKey: Normalized module!api exact match key.
            ks::winapi_monitor::EventCategory categoryValue = ks::winapi_monitor::EventCategory::kProcess; // categoryValue: Event category.
            FakeSuccessReturnType returnType = FakeSuccessReturnType::kScalar; // returnType: Return value template.
            FakeSuccessLastErrorKind lastErrorKind = FakeSuccessLastErrorKind::kNone; // lastErrorKind: Method for writing the error code.
            std::uint64_t returnValue = 0;                          // returnValue: return value written to RAX.
            std::uint32_t lastErrorValue = 0;                       // lastErrorValue: Win32/WSA error code.
            InlineHookRecord hookRecord{};                          // hookRecord: Fake-specific inline patch state.
            void* originalAddress = nullptr;                        // originalAddress: A trampoline is still generated during installation, but the fake path does not jump into it.
            void* entryStubAddress = nullptr;                       // entryStubAddress: Dynamically generated fake return stub.
        };

        // rawBindings：
        // - Inputs: None;
        // - Processing: Return the unique in-process Raw Hook dynamic binding collection; the collection is intentionally leaked until process termination.
        // - Returns: Reference to a vector that can be manually cleared.
        // - Reason: Hooked APIs may still be called by the CRT/loader during the target process exit phase; automatic destruction would cause the entry stub to point to freed context.
        std::vector<std::unique_ptr<RawHookBinding>>& rawBindings()
        {
            static auto* const kBindingList = new std::vector<std::unique_ptr<RawHookBinding>>();
            return *kBindingList;
        }

        // rawHookKeys：
        // - Inputs: None;
        // - Processing: Return the deduplicated set of Raw module!exports; the set is intentionally leaked until process termination.
        // - Returns: A reference to an unordered_set that can be manually cleared.
        std::unordered_set<std::wstring>& rawHookKeys()
        {
            static auto* const kKeySet = new std::unordered_set<std::wstring>();
            return *kKeySet;
        }

        // fakeSuccessRules：
        // - Inputs: None;
        // - Processing: Return the Fake Success rule collection; the collection itself is excluded from C++ static destruction.
        // - Returns: Reference to a vector that can be manually cleared.
        // - Reason: The fake entry stub holds a FakeSuccessRuntimeRule*. The context must not be released early by automatic destruction if the process exits without an explicit Stop.
        std::vector<std::unique_ptr<FakeSuccessRuntimeRule>>& fakeSuccessRules()
        {
            static auto* const kRuleList = new std::vector<std::unique_ptr<FakeSuccessRuntimeRule>>();
            return *kRuleList;
        }

        // fakeSuccessRuleMap：
        // - Inputs: None;
        // - Processing: Return a fast index from module!api to Fake rules; the map itself is not involved in C++ static destruction.
        // - Returns: A reference to an unordered_map that can be manually cleared.
        std::unordered_map<std::wstring, FakeSuccessRuntimeRule*>& fakeSuccessRuleMap()
        {
            static auto* const kRuleMap = new std::unordered_map<std::wstring, FakeSuccessRuntimeRule*>();
            return *kRuleMap;
        }

        std::wstring procNameToWide(const char* procNamePointer)
        {
            if (procNamePointer == nullptr)
            {
                return std::wstring();
            }

            std::wstring wideText;
            while (*procNamePointer != '\0')
            {
                wideText.push_back(static_cast<wchar_t>(*procNamePointer));
                ++procNamePointer;
            }
            return wideText;
        }

        void appendHookFailureText(
            std::wstring* detailTextOut,
            const HookBinding& bindingValue,
            const InlineHookInstallResult installResult,
            const std::wstring& errorText)
        {
            if (detailTextOut == nullptr)
            {
                return;
            }

            if (!detailTextOut->empty())
            {
                detailTextOut->append(L" | ");
            }

            detailTextOut->append(bindingValue.moduleName != nullptr ? bindingValue.moduleName : L"<module>");
            detailTextOut->append(L"!");
            detailTextOut->append(procNameToWide(bindingValue.procName));
            detailTextOut->append(
                installResult == InlineHookInstallResult::kRetryableFailure
                ? L": retryable failure - "
                : L": disabled - ");
            detailTextOut->append(errorText.empty() ? L"unknown reason" : errorText);
        }

        std::wstring safeWideText(const wchar_t* textPointer)
        {
            return textPointer != nullptr ? std::wstring(textPointer) : std::wstring();
        }

        // ansiToWide:
        // - Input: textPointer is a nullable ANSI/system code page string;
        // - Processing: Convert to wide string using CP_ACP; fall back to byte-by-byte expansion on failure.
        // - Returns: A wide string for UI display; does not throw exceptions.
        std::wstring ansiToWide(const char* const textPointer)
        {
            if (textPointer == nullptr)
            {
                return std::wstring();
            }

            const int kRequiredChars = ::MultiByteToWideChar(CP_ACP, 0, textPointer, -1, nullptr, 0);
            if (kRequiredChars > 0)
            {
                std::wstring wideText(static_cast<std::size_t>(kRequiredChars), L'\0');
                const int kConvertedChars = ::MultiByteToWideChar(
                    CP_ACP,
                    0,
                    textPointer,
                    -1,
                    wideText.data(),
                    kRequiredChars);
                if (kConvertedChars > 0 && !wideText.empty())
                {
                    wideText.resize(static_cast<std::size_t>(kConvertedChars - 1));
                    return wideText;
                }
            }

            std::wstring fallbackText;
            for (const unsigned char* scanPointer = reinterpret_cast<const unsigned char*>(textPointer);
                *scanPointer != '\0';
                ++scanPointer)
            {
                fallbackText.push_back(static_cast<wchar_t>(*scanPointer));
            }
            return fallbackText;
        }

        std::wstring toLowerWide(std::wstring textValue)
        {
            std::transform(
                textValue.begin(),
                textValue.end(),
                textValue.begin(),
                [](const wchar_t ch) { return static_cast<wchar_t>(::towlower(ch)); });
            return textValue;
        }

        std::string toLowerAnsi(std::string textValue)
        {
            std::transform(
                textValue.begin(),
                textValue.end(),
                textValue.begin(),
                [](const unsigned char ch) { return static_cast<char>(::tolower(ch)); });
            return textValue;
        }

        // makeRawHookKey:
        // - Input: module name and exported name;
        // - Processing: normalize case and concatenate into a module!api key.
        // - Returns: Stable key used for deduplication and strong-type override checks in Raw binding.
        std::wstring makeRawHookKey(const std::wstring& moduleName, const std::string& procName)
        {
            return toLowerWide(moduleName) + L"!" + toLowerWide(ansiToWide(procName.c_str()));
        }

        std::wstring normalizeModuleNameForMatch(std::wstring moduleName)
        {
            moduleName = toLowerWide(moduleName);
            if (moduleName.size() > 4 && moduleName.substr(moduleName.size() - 4) == L".dll")
            {
                moduleName.resize(moduleName.size() - 4);
            }
            return moduleName;
        }

        std::wstring makeFakeSuccessKey(const std::wstring& moduleName, const std::wstring& apiName)
        {
            return normalizeModuleNameForMatch(moduleName) + L"!" + toLowerWide(apiName);
        }

        std::wstring makeFakeSuccessKey(const std::wstring& moduleName, const std::string& apiName)
        {
            return makeFakeSuccessKey(moduleName, ansiToWide(apiName.c_str()));
        }

        // unicodeStringToWide:
        // - Input: unicodePointer is a nullable UNICODE_STRING;
        // - Processing: Copy Buffer by Length bytes; source string need not be NUL-terminated.
        // - Return: Wide string for Nt* event details.
        std::wstring unicodeStringToWide(const UNICODE_STRING* const unicodePointer)
        {
            if (unicodePointer == nullptr
                || unicodePointer->Buffer == nullptr
                || unicodePointer->Length == 0)
            {
                return std::wstring();
            }

            return std::wstring(
                unicodePointer->Buffer,
                unicodePointer->Buffer + (unicodePointer->Length / sizeof(wchar_t)));
        }

        std::wstring hexValue(const std::uint64_t value)
        {
            wchar_t textBuffer[32] = {};
            ::swprintf_s(textBuffer, L"0x%llX", static_cast<unsigned long long>(value));
            return std::wstring(textBuffer);
        }

        std::wstring handleText(const HANDLE handleValue)
        {
            return hexValue(reinterpret_cast<std::uint64_t>(handleValue));
        }

        // appendWideText:
        // - Input: targetBuffer is a stack-allocated fixed-length buffer, textPointer is a nullable wide string;
        // - Processing: Append up to maxInputChars characters from the current NUL-terminated position, safely truncating on overflow.
        // - Return: No return value; caller uses targetBuffer directly.
        template <std::size_t kCount>
        void appendWideText(
            wchar_t(&targetBuffer)[kCount],
            const wchar_t* textPointer,
            const std::size_t maxInputChars = static_cast<std::size_t>(-1))
        {
            if (kCount == 0 || textPointer == nullptr)
            {
                return;
            }

            std::size_t writeOffset = 0;
            while (writeOffset < kCount && targetBuffer[writeOffset] != L'\0')
            {
                ++writeOffset;
            }
            if (writeOffset >= kCount)
            {
                targetBuffer[kCount - 1] = L'\0';
                return;
            }

            std::size_t inputOffset = 0;
            while (writeOffset + 1 < kCount
                && inputOffset < maxInputChars
                && textPointer[inputOffset] != L'\0')
            {
                targetBuffer[writeOffset++] = textPointer[inputOffset++];
            }
            targetBuffer[writeOffset] = L'\0';
        }

        // appendAnsiText:
        // - Input: targetBuffer is a wide-character detail buffer; textPointer is an optional narrow string.
        // - Processing: Expand byte-by-byte to wchar_t with safe truncation to avoid heap allocation conversions in the Hook hot path.
        // - Return: No return value; targetBuffer contains the NUL-terminated text after best-effort appending.
        template <std::size_t kCount>
        void appendAnsiText(
            wchar_t(&targetBuffer)[kCount],
            const char* const textPointer,
            const std::size_t maxInputChars = static_cast<std::size_t>(-1))
        {
            if (kCount == 0 || textPointer == nullptr)
            {
                return;
            }

            std::size_t writeOffset = 0;
            while (writeOffset < kCount && targetBuffer[writeOffset] != L'\0')
            {
                ++writeOffset;
            }
            if (writeOffset >= kCount)
            {
                targetBuffer[kCount - 1] = L'\0';
                return;
            }

            std::size_t inputOffset = 0;
            while (writeOffset + 1 < kCount
                && inputOffset < maxInputChars
                && textPointer[inputOffset] != '\0')
            {
                targetBuffer[writeOffset++] = static_cast<unsigned char>(textPointer[inputOffset++]);
            }
            targetBuffer[writeOffset] = L'\0';
        }

        // appendUnsignedText forward declaration:
        // - Input: fixed-width character detail buffer and unsigned integer;
        // - Processing: The actual implementation is located below, made visible to the preceding template helper during instantiation;
        // - Return: No return value; the declaration itself does not alter runtime logic.
        template <std::size_t kCount>
        void AppendUnsignedText(wchar_t(&targetBuffer)[kCount], const unsigned long long value);

        // Forward declaration of appendHexText:
        // - Input: fixed-width character detail buffer and hexadecimal value;
        // - Processing: Resolve the issue where appendObjectNameText is referenced before definition in template two-phase lookup.
        // - Return: None. The actual formatting logic is still completed by the implementation below.
        template <std::size_t kCount>
        void appendHexText(wchar_t(&targetBuffer)[kCount], const std::uint64_t value);

        // appendUnicodeStringText:
        // - Input: unicodePointer is a nullable UNICODE_STRING;
        // - Processing: Append based on Length limit without relying on NUL termination in the buffer.
        // - Returns: None. Suitable for appending details for NtCreateFile/NtOpenKey and other Nt* calls.
        template <std::size_t kCount>
        void appendUnicodeStringText(
            wchar_t(&targetBuffer)[kCount],
            const UNICODE_STRING* const unicodePointer)
        {
            if (unicodePointer == nullptr
                || unicodePointer->Buffer == nullptr
                || unicodePointer->Length == 0)
            {
                return;
            }

            appendWideText(
                targetBuffer,
                unicodePointer->Buffer,
                static_cast<std::size_t>(unicodePointer->Length / sizeof(wchar_t)));
        }

        // appendObjectNameText:
        // - Input: objectAttributesPointer is an Nt* OBJECT_ATTRIBUTES;
        // - Processing: Append ObjectName text or handle root hint, avoiding dereferencing other complex kernel object states;
        // - Returns: void; the target buffer contains path=<name> or rootHandle=<handle>.
        template <std::size_t kCount>
        void appendObjectNameText(
            wchar_t(&targetBuffer)[kCount],
            const OBJECT_ATTRIBUTES* const objectAttributesPointer)
        {
            if (objectAttributesPointer == nullptr)
            {
                appendWideText(targetBuffer, L"<null>");
                return;
            }

            if (objectAttributesPointer->RootDirectory != nullptr)
            {
                appendWideText(targetBuffer, L"root=");
                appendHexText(targetBuffer, reinterpret_cast<std::uint64_t>(objectAttributesPointer->RootDirectory));
                appendWideText(targetBuffer, L"\\");
            }
            appendUnicodeStringText(targetBuffer, objectAttributesPointer->ObjectName);
        }

        // appendUnsignedText:
        // - Input: value is the unsigned integer to append;
        // - Processing: format to a small stack buffer first, then append to the target buffer;
        // - Returns: nothing. On failure, retains existing text and appends an empty string.
        template <std::size_t kCount>
        void appendUnsignedText(wchar_t(&targetBuffer)[kCount], const unsigned long long value)
        {
            wchar_t numberBuffer[32] = {};
            (void)::swprintf_s(numberBuffer, L"%llu", value);
            appendWideText(targetBuffer, numberBuffer);
        }

        // appendHexText:
        // - Input: value is the pointer/mask value to append;
        // - Processing: format as a hexadecimal string with 0x prefix;
        // - Return: No return value; safely truncates if the target buffer is insufficient.
        template <std::size_t kCount>
        void appendHexText(wchar_t(&targetBuffer)[kCount], const std::uint64_t value)
        {
            wchar_t numberBuffer[32] = {};
            (void)::swprintf_s(numberBuffer, L"0x%llX", static_cast<unsigned long long>(value));
            appendWideText(targetBuffer, numberBuffer);
        }

        // appendRegistryRootText:
        // - Input: rootKey is a registry root key or a standard HKEY handle;
        // - Processing: Output common root keys as HKxx; output regular handles in hexadecimal.
        // - Return: No return value; appends to the detail buffer provided by the caller.
        template <std::size_t kCount>
        void appendRegistryRootText(wchar_t(&targetBuffer)[kCount], const HKEY rootKey)
        {
            if (rootKey == HKEY_CLASSES_ROOT) { appendWideText(targetBuffer, L"HKCR"); return; }
            if (rootKey == HKEY_CURRENT_USER) { appendWideText(targetBuffer, L"HKCU"); return; }
            if (rootKey == HKEY_LOCAL_MACHINE) { appendWideText(targetBuffer, L"HKLM"); return; }
            if (rootKey == HKEY_USERS) { appendWideText(targetBuffer, L"HKU"); return; }
            if (rootKey == HKEY_CURRENT_CONFIG) { appendWideText(targetBuffer, L"HKCC"); return; }
            appendHexText(targetBuffer, reinterpret_cast<std::uint64_t>(rootKey));
        }

        // buildRegOpenDetail:
        // - Input: Key parameters for the registry open API.
        // - Processing: Concatenate key/sam details in a fixed stack buffer without triggering heap allocation.
        // - Returns: None. detailBuffer contains NUL-terminated text ready to be sent.
        template <std::size_t kCount>
        void buildRegOpenDetail(
            wchar_t(&detailBuffer)[kCount],
            const HKEY rootKey,
            const wchar_t* const subKeyPointer,
            const REGSAM samDesired)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"key=");
            appendRegistryRootText(detailBuffer, rootKey);
            appendWideText(detailBuffer, L"\\");
            appendWideText(detailBuffer, subKeyPointer);
            appendWideText(detailBuffer, L" sam=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(samDesired));
        }

        // buildRegOpenDetailA:
        // - Input: Root key, subkey, and access mask for the ANSI registry open API.
        // - Processing: Represent root keys as HKxx/handles; expand subkeys byte-by-byte into wide characters.
        // - Returns: No return value; detailBuffer contains text ready to be sent.
        template <std::size_t kCount>
        void buildRegOpenDetailA(
            wchar_t(&detailBuffer)[kCount],
            const HKEY rootKey,
            const char* const subKeyPointer,
            const REGSAM samDesired)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"key=");
            appendRegistryRootText(detailBuffer, rootKey);
            appendWideText(detailBuffer, L"\\");
            appendAnsiText(detailBuffer, subKeyPointer);
            appendWideText(detailBuffer, L" sam=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(samDesired));
        }

        // buildRegCreateDetail:
        // - Input: Key parameters and disposition for the registry creation API;
        // - Processing: Record only stable small fields to avoid complex parsing under registry lock.
        // - Returns: None. detailBuffer contains a fixed-length detail.
        template <std::size_t kCount>
        void buildRegCreateDetail(
            wchar_t(&detailBuffer)[kCount],
            const HKEY rootKey,
            const wchar_t* const subKeyPointer,
            const DWORD optionsValue,
            const DWORD dispositionValue)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"key=");
            appendRegistryRootText(detailBuffer, rootKey);
            appendWideText(detailBuffer, L"\\");
            appendWideText(detailBuffer, subKeyPointer);
            appendWideText(detailBuffer, L" options=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(optionsValue));
            appendWideText(detailBuffer, L" disposition=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(dispositionValue));
        }

        // buildRegCreateDetailA:
        // - Input: Key parameters for the ANSI registry creation API;
        // - Processing: Keep the same fields as the Wide version to avoid extra parsing on the UI side;
        // - Returns: None. detailBuffer contains a fixed-length summary.
        template <std::size_t kCount>
        void buildRegCreateDetailA(
            wchar_t(&detailBuffer)[kCount],
            const HKEY rootKey,
            const char* const subKeyPointer,
            const DWORD optionsValue,
            const DWORD dispositionValue)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"key=");
            appendRegistryRootText(detailBuffer, rootKey);
            appendWideText(detailBuffer, L"\\");
            appendAnsiText(detailBuffer, subKeyPointer);
            appendWideText(detailBuffer, L" options=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(optionsValue));
            appendWideText(detailBuffer, L" disposition=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(dispositionValue));
        }

        // buildRegSetValueDetail:
        // - Input: Handle, value name, type, and data length of the registry write value API;
        // - Handling: Do not read the content of dataPointer to avoid triggering page faults or copying sensitive large data.
        // - Returns: No return value; detailBuffer contains the summary text to be sent.
        template <std::size_t kCount>
        void buildRegSetValueDetail(
            wchar_t(&detailBuffer)[kCount],
            const HKEY keyHandle,
            const wchar_t* const valueNamePointer,
            const DWORD typeValue,
            const DWORD dataSize)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" value=");
            appendWideText(detailBuffer, valueNamePointer);
            appendWideText(detailBuffer, L" type=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(dataSize));
        }

        // buildRegSetValueDetailA:
        // - Input: handle, value name, type, and length of the ANSI registry write value API;
        // - Processing: Record only value name and metadata, do not copy dataPointer.
        // - Returns: None. detailBuffer contains a summary ready for transmission.
        template <std::size_t kCount>
        void buildRegSetValueDetailA(
            wchar_t(&detailBuffer)[kCount],
            const HKEY keyHandle,
            const char* const valueNamePointer,
            const DWORD typeValue,
            const DWORD dataSize)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" value=");
            appendAnsiText(detailBuffer, valueNamePointer);
            appendWideText(detailBuffer, L" type=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(dataSize));
        }

        // buildRegValueDetail:
        // - Input: Common parameters for registry value operations.
        // - Processing: Concatenate hkey/value/type/size summary for querying, deleting, and enumerating values;
        // - Returns: None. detailBuffer contains NUL-terminated details.
        template <std::size_t kCount>
        void buildRegValueDetail(
            wchar_t(&detailBuffer)[kCount],
            const wchar_t* const prefixText,
            const HKEY keyHandle,
            const wchar_t* const valueNamePointer,
            const DWORD typeValue,
            const DWORD dataSize)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, prefixText != nullptr ? prefixText : L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" value=");
            appendWideText(detailBuffer, valueNamePointer);
            appendWideText(detailBuffer, L" type=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(dataSize));
        }

        // buildRegValueDetailA:
        // - Input: ANSI registry value operation parameters;
        // - Processing: Concatenate hkey/value/type/size summary; expand value name to narrow characters.
        // - Returns: None. detailBuffer contains NUL-terminated text.
        template <std::size_t kCount>
        void buildRegValueDetailA(
            wchar_t(&detailBuffer)[kCount],
            const wchar_t* const prefixText,
            const HKEY keyHandle,
            const char* const valueNamePointer,
            const DWORD typeValue,
            const DWORD dataSize)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, prefixText != nullptr ? prefixText : L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" value=");
            appendAnsiText(detailBuffer, valueNamePointer);
            appendWideText(detailBuffer, L" type=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(dataSize));
        }

        // buildRegGetValueDetail:
        // - Input: hkey/subkey/value/flags/type/size for RegGetValueW.
        // - Processing: Concatenate query source and output summary without reading return data content.
        // - Returns: None. detailBuffer contains NUL-terminated text.
        template <std::size_t kCount>
        void buildRegGetValueDetail(
            wchar_t(&detailBuffer)[kCount],
            const HKEY keyHandle,
            const wchar_t* const subKeyPointer,
            const wchar_t* const valueNamePointer,
            const DWORD flagsValue,
            const DWORD typeValue,
            const DWORD dataSize)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" subkey=");
            appendWideText(detailBuffer, subKeyPointer);
            appendWideText(detailBuffer, L" value=");
            appendWideText(detailBuffer, valueNamePointer);
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(flagsValue));
            appendWideText(detailBuffer, L" type=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(dataSize));
        }

        // buildRegGetValueDetailA:
        // - Input: hkey/subkey/value/flags/type/size for RegGetValueA.
        // - Processing: Keep fields consistent with the Wide version; expand strings to ANSI.
        // - Returns: None. detailBuffer contains NUL-terminated text.
        template <std::size_t kCount>
        void buildRegGetValueDetailA(
            wchar_t(&detailBuffer)[kCount],
            const HKEY keyHandle,
            const char* const subKeyPointer,
            const char* const valueNamePointer,
            const DWORD flagsValue,
            const DWORD typeValue,
            const DWORD dataSize)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" subkey=");
            appendAnsiText(detailBuffer, subKeyPointer);
            appendWideText(detailBuffer, L" value=");
            appendAnsiText(detailBuffer, valueNamePointer);
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(flagsValue));
            appendWideText(detailBuffer, L" type=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(dataSize));
        }

        // buildRegSubKeyDetail:
        // - Input: Root key, subkey name, and access mask for registry subkey operations.
        // - Processing: Output short text in the format key=<root>\<subkey> view=<sam>;
        // - Return: No return value; automatically truncates if the target buffer is insufficient.
        template <std::size_t kCount>
        void buildRegSubKeyDetail(
            wchar_t(&detailBuffer)[kCount],
            const HKEY rootKey,
            const wchar_t* const subKeyPointer,
            const REGSAM viewValue)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"key=");
            appendRegistryRootText(detailBuffer, rootKey);
            appendWideText(detailBuffer, L"\\");
            appendWideText(detailBuffer, subKeyPointer);
            appendWideText(detailBuffer, L" view=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(viewValue));
        }

        // buildRegSubKeyDetailA:
        // - Input: Root key, subkey, and view mask for ANSI subkey operations;
        // - Processing: Output key=<root>\<subkey> view=<sam>;
        // - Return: No return value; safely truncates if the target buffer is insufficient.
        template <std::size_t kCount>
        void buildRegSubKeyDetailA(
            wchar_t(&detailBuffer)[kCount],
            const HKEY rootKey,
            const char* const subKeyPointer,
            const REGSAM viewValue)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"key=");
            appendRegistryRootText(detailBuffer, rootKey);
            appendWideText(detailBuffer, L"\\");
            appendAnsiText(detailBuffer, subKeyPointer);
            appendWideText(detailBuffer, L" view=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(viewValue));
        }

        // buildRegEnumKeyDetail:
        // - Input: Index, name, and name length from the enumerated subkey results;
        // - Processing: Output hkey/index/name/nameLen summary.
        // - Return: None. On failure, the name may be empty but the index is retained.
        template <std::size_t kCount>
        void buildRegEnumKeyDetail(
            wchar_t(&detailBuffer)[kCount],
            const HKEY keyHandle,
            const DWORD indexValue,
            const wchar_t* const namePointer,
            const DWORD nameLength)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" index=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(indexValue));
            appendWideText(detailBuffer, L" name=");
            appendWideText(detailBuffer, namePointer, nameLength);
            appendWideText(detailBuffer, L" nameLen=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(nameLength));
        }

        // buildRegEnumKeyDetailA:
        // - Input: Handle, index, name, and name length from RegEnumKeyExA;
        // - Processing: Preserve enumeration index and returned name, with the name expanded by ANSI bytes;
        // - Return: No return value; detailBuffer holds the enumeration summary.
        template <std::size_t kCount>
        void buildRegEnumKeyDetailA(
            wchar_t(&detailBuffer)[kCount],
            const HKEY keyHandle,
            const DWORD indexValue,
            const char* const namePointer,
            const DWORD nameLength)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" index=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(indexValue));
            appendWideText(detailBuffer, L" name=");
            appendAnsiText(detailBuffer, namePointer, nameLength);
            appendWideText(detailBuffer, L" nameLen=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(nameLength));
        }

        // buildFilePathDetailW:
        // - Input: pathPointer is a nullable wide path, other fields are file API metadata;
        // - Processing: Generate unified summary of path/access/share/disposition/flags.
        // - Returns: None. detailBuffer contains file event details.
        template <std::size_t kCount>
        void buildFilePathDetailW(
            wchar_t(&detailBuffer)[kCount],
            const wchar_t* const pathPointer,
            const DWORD desiredAccess,
            const DWORD shareMode,
            const DWORD creationDisposition,
            const DWORD flagsAndAttributes,
            const HANDLE resultHandle)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"path=");
            appendWideText(detailBuffer, pathPointer);
            appendWideText(detailBuffer, L" access=");
            appendHexText(detailBuffer, desiredAccess);
            appendWideText(detailBuffer, L" share=");
            appendHexText(detailBuffer, shareMode);
            appendWideText(detailBuffer, L" disposition=");
            appendUnsignedText(detailBuffer, creationDisposition);
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, flagsAndAttributes);
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
        }

        // buildFilePathDetailA:
        // - Input: pathPointer is a nullable ANSI path; other fields are file API metadata;
        // - Handling: Keep field consistency with the Wide version; expand paths using ANSI bytes;
        // - Returns: None. detailBuffer contains file event details.
        template <std::size_t kCount>
        void buildFilePathDetailA(
            wchar_t(&detailBuffer)[kCount],
            const char* const pathPointer,
            const DWORD desiredAccess,
            const DWORD shareMode,
            const DWORD creationDisposition,
            const DWORD flagsAndAttributes,
            const HANDLE resultHandle)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"path=");
            appendAnsiText(detailBuffer, pathPointer);
            appendWideText(detailBuffer, L" access=");
            appendHexText(detailBuffer, desiredAccess);
            appendWideText(detailBuffer, L" share=");
            appendHexText(detailBuffer, shareMode);
            appendWideText(detailBuffer, L" disposition=");
            appendUnsignedText(detailBuffer, creationDisposition);
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, flagsAndAttributes);
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
        }

        // buildTwoPathDetailW:
        // - Input: sourcePointer/targetPointer are paths for move/copy and other dual-path APIs;
        // - Processing: Output a short summary of src/dst/flags.
        // - Return: None. detailBuffer stores the text to be sent.
        template <std::size_t kCount>
        void buildTwoPathDetailW(
            wchar_t(&detailBuffer)[kCount],
            const wchar_t* const sourcePointer,
            const wchar_t* const targetPointer,
            const DWORD flagsValue)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"src=");
            appendWideText(detailBuffer, sourcePointer);
            appendWideText(detailBuffer, L" dst=");
            appendWideText(detailBuffer, targetPointer);
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, flagsValue);
        }

        // buildTwoPathDetailA:
        // - Input: sourcePointer/targetPointer are ANSI dual-path API paths;
        // - Processing: Output src/dst/flags; paths expanded to narrow characters.
        // - Return: None. detailBuffer stores the text to be sent.
        template <std::size_t kCount>
        void buildTwoPathDetailA(
            wchar_t(&detailBuffer)[kCount],
            const char* const sourcePointer,
            const char* const targetPointer,
            const DWORD flagsValue)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"src=");
            appendAnsiText(detailBuffer, sourcePointer);
            appendWideText(detailBuffer, L" dst=");
            appendAnsiText(detailBuffer, targetPointer);
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, flagsValue);
        }

        // BuildSinglePathDetailW:
        // - Input: pathPointer is a nullable wide path; flagsValue is an optional parameter.
        // - Processing: Output path/flags summary.
        // - Returns: None. detailBuffer contains NUL-terminated text.
        template <std::size_t kCount>
        void BuildSinglePathDetailW(
            wchar_t(&detailBuffer)[kCount],
            const wchar_t* const pathPointer,
            const DWORD flagsValue)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"path=");
            appendWideText(detailBuffer, pathPointer);
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, flagsValue);
        }

        // BuildSinglePathDetailA:
        // - Input: pathPointer is a nullable ANSI path, flagsValue is an optional parameter;
        // - Processing: Output path/flags summary; paths expanded to narrow characters.
        // - Returns: None. detailBuffer contains NUL-terminated text.
        template <std::size_t kCount>
        void BuildSinglePathDetailA(
            wchar_t(&detailBuffer)[kCount],
            const char* const pathPointer,
            const DWORD flagsValue)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"path=");
            appendAnsiText(detailBuffer, pathPointer);
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, flagsValue);
        }

        // buildHandleTransferDetail:
        // - Input: handleValue, requested byte count, actual byte count, and optional offset;
        // - Processing: Generate unified details for NtReadFile/NtWriteFile;
        // - Returns: None. detailBuffer contains NUL-terminated text.
        template <std::size_t kCount>
        void buildHandleTransferDetail(
            wchar_t(&detailBuffer)[kCount],
            const HANDLE handleValue,
            const unsigned long requestLength,
            const unsigned long long actualLength,
            const LARGE_INTEGER* const byteOffsetPointer)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(handleValue));
            appendWideText(detailBuffer, L" request=");
            appendUnsignedText(detailBuffer, requestLength);
            appendWideText(detailBuffer, L" transferred=");
            appendUnsignedText(detailBuffer, actualLength);
            if (byteOffsetPointer != nullptr)
            {
                appendWideText(detailBuffer, L" offset=");
                appendUnsignedText(detailBuffer, static_cast<unsigned long long>(
                    byteOffsetPointer->QuadPart < 0 ? 0 : byteOffsetPointer->QuadPart));
            }
        }

        // buildNtObjectPathDetail:
        // - Input: Nt* OBJECT_ATTRIBUTES and several mask fields
        // - Processing: Output path/access/share/options/disposition;
        // - Returns: No return value; detailBuffer contains a summary of the underlying object path.
        template <std::size_t kCount>
        void buildNtObjectPathDetail(
            wchar_t(&detailBuffer)[kCount],
            const OBJECT_ATTRIBUTES* const objectAttributesPointer,
            const ACCESS_MASK desiredAccess,
            const ULONG shareAccess,
            const ULONG createDisposition,
            const ULONG createOptions)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"path=");
            appendObjectNameText(detailBuffer, objectAttributesPointer);
            appendWideText(detailBuffer, L" access=");
            appendHexText(detailBuffer, desiredAccess);
            appendWideText(detailBuffer, L" share=");
            appendHexText(detailBuffer, shareAccess);
            appendWideText(detailBuffer, L" disposition=");
            appendUnsignedText(detailBuffer, createDisposition);
            appendWideText(detailBuffer, L" options=");
            appendHexText(detailBuffer, createOptions);
        }

        // buildNtKeyValueDetail:
        // - Input: keyHandle, valueNamePointer, type/size;
        // - Processing: Do not read the value data; record only the name and metadata.
        // - Return: No return value; detailBuffer contains a summary of the Nt registry value operation.
        template <std::size_t kCount>
        void buildNtKeyValueDetail(
            wchar_t(&detailBuffer)[kCount],
            const HANDLE keyHandle,
            const UNICODE_STRING* const valueNamePointer,
            const ULONG typeValue,
            const ULONG dataSize)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" value=");
            appendUnicodeStringText(detailBuffer, valueNamePointer);
            appendWideText(detailBuffer, L" type=");
            appendUnsignedText(detailBuffer, typeValue);
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, dataSize);
        }

        // buildProcessHandleDetail:
        // - Input: Process handle, access mask, PID, and returned handle.
        // - Processing: Unify output fields for process, access, pid, and handle.
        // - Return: No return value; detailBuffer contains the process event summary.
        template <std::size_t kCount>
        void buildProcessHandleDetail(
            wchar_t(&detailBuffer)[kCount],
            const HANDLE processHandle,
            const ACCESS_MASK accessMask,
            const std::uint64_t processId,
            const HANDLE resultHandle)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"process=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            appendWideText(detailBuffer, L" access=");
            appendHexText(detailBuffer, accessMask);
            appendWideText(detailBuffer, L" pid=");
            appendUnsignedText(detailBuffer, processId);
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
        }

        // buildRemoteMemoryDetail:
        // - Input: Target process handle, address, length, and protection or allocation flags;
        // - Processing: Generate stable fields for cross-process memory APIs;
        // - Returns: None. detailBuffer contains a summary of memory operations.
        template <std::size_t kCount>
        void buildRemoteMemoryDetail(
            wchar_t(&detailBuffer)[kCount],
            const HANDLE processHandle,
            const void* const baseAddress,
            const std::uint64_t sizeValue,
            const ULONG firstFlags,
            const ULONG secondFlags)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"process=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            appendWideText(detailBuffer, L" base=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, sizeValue);
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, firstFlags);
            appendWideText(detailBuffer, L" protect=");
            appendHexText(detailBuffer, secondFlags);
        }

        // sumWsaBufferLength:
        // - Input: Winsock WSABUF array and element count;
        // - Processing: Accumulate the 'len' field and prevent null pointer access.
        // - Returns: Total request byte count; naturally truncated to uint64 range if it exceeds uint64.
        std::uint64_t sumWsaBufferLength(const WSABUF* const bufferPointer, const DWORD bufferCount)
        {
            std::uint64_t totalLength = 0;
            if (bufferPointer == nullptr)
            {
                return totalLength;
            }

            for (DWORD indexValue = 0; indexValue < bufferCount; ++indexValue)
            {
                totalLength += static_cast<std::uint64_t>(bufferPointer[indexValue].len);
            }
            return totalLength;
        }

        // appendSocketAddress:
        // - Input: sockaddr and length;
        // - Processing: Attempt to convert to host:port using GetNameInfoW; output <unknown> on failure.
        // - Returns: None. Directly appends to detailBuffer.
        template <std::size_t kCount>
        void appendSocketAddress(wchar_t(&detailBuffer)[kCount], const sockaddr* const addressPointer, const int addressLength)
        {
            if (addressPointer == nullptr || addressLength <= 0)
            {
                appendWideText(detailBuffer, L"<null>");
                return;
            }

            wchar_t hostBuffer[NI_MAXHOST] = {};
            wchar_t serviceBuffer[NI_MAXSERV] = {};
            const int kResultValue = ::GetNameInfoW(
                addressPointer,
                addressLength,
                hostBuffer,
                NI_MAXHOST,
                serviceBuffer,
                NI_MAXSERV,
                NI_NUMERICHOST | NI_NUMERICSERV);
            if (kResultValue != 0)
            {
                appendWideText(detailBuffer, L"<unknown>");
                return;
            }

            appendWideText(detailBuffer, hostBuffer);
            appendWideText(detailBuffer, L":");
            appendWideText(detailBuffer, serviceBuffer);
        }

        // buildSocketDetail:
        // - Input: socket, request length, actual transfer length, flags, and optional address
        // - Processing: Generate network event summaries without reading network buffer contents;
        // - Return: None. detailBuffer stores the text to be sent.
        template <std::size_t kCount>
        void buildSocketDetail(
            wchar_t(&detailBuffer)[kCount],
            const wchar_t* const verbText,
            const SOCKET socketValue,
            const std::uint64_t requestLength,
            const long long transferLength,
            const DWORD flagsValue,
            const sockaddr* const addressPointer = nullptr,
            const int addressLength = 0)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"socket=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue));
            if (verbText != nullptr && verbText[0] != L'\0')
            {
                appendWideText(detailBuffer, L" ");
                appendWideText(detailBuffer, verbText);
            }
            appendWideText(detailBuffer, L" request=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(requestLength));
            appendWideText(detailBuffer, L" transferred=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(transferLength < 0 ? 0 : transferLength));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(flagsValue));
            if (addressPointer != nullptr)
            {
                appendWideText(detailBuffer, L" remote=");
                appendSocketAddress(detailBuffer, addressPointer, addressLength);
            }
        }

        bool categoryEnabled(const ks::winapi_monitor::EventCategory categoryValue)
        {
            const MonitorConfig& configValue = activeConfig();
            switch (categoryValue)
            {
            case ks::winapi_monitor::EventCategory::kFile:
                return configValue.enableFile;
            case ks::winapi_monitor::EventCategory::kRegistry:
                return configValue.enableRegistry;
            case ks::winapi_monitor::EventCategory::kNetwork:
                return configValue.enableNetwork;
            case ks::winapi_monitor::EventCategory::kProcess:
                return configValue.enableProcess;
            case ks::winapi_monitor::EventCategory::kLoader:
                // Loader hook also assumes the responsibility of 'post-loading module patching':
                // - enableLoader controls whether to report LoadLibrary events.
                // - Registry/Network/Shell32 process startup modules may load later than Agent injection; therefore, when enabling these categories, the loader hook must also be installed.
                return configValue.enableLoader || configValue.enableRegistry || configValue.enableNetwork || configValue.enableProcess;
            default:
                break;
            }
            return true;
        }

        std::wstring trimDetail(const std::wstring& detailText)
        {
            const std::size_t kDetailLimit = std::min<std::size_t>(
                activeConfig().detailLimitChars,
                ks::winapi_monitor::kMaxDetailChars - 1);
            return detailText.size() > kDetailLimit ? detailText.substr(0, kDetailLimit) : detailText;
        }

        std::wstring formatRegistryRoot(const HKEY rootKey)
        {
            if (rootKey == HKEY_CLASSES_ROOT) { return L"HKCR"; }
            if (rootKey == HKEY_CURRENT_USER) { return L"HKCU"; }
            if (rootKey == HKEY_LOCAL_MACHINE) { return L"HKLM"; }
            if (rootKey == HKEY_USERS) { return L"HKU"; }
            if (rootKey == HKEY_CURRENT_CONFIG) { return L"HKCC"; }
            return handleText(rootKey);
        }

        std::wstring formatSocketAddress(const sockaddr* addressPointer, const int addressLength)
        {
            if (addressPointer == nullptr || addressLength <= 0)
            {
                return L"<null>";
            }

            wchar_t hostBuffer[NI_MAXHOST] = {};
            wchar_t serviceBuffer[NI_MAXSERV] = {};
            const int kResultValue = ::GetNameInfoW(
                addressPointer,
                addressLength,
                hostBuffer,
                NI_MAXHOST,
                serviceBuffer,
                NI_MAXSERV,
                NI_NUMERICHOST | NI_NUMERICSERV);
            if (kResultValue != 0)
            {
                return L"<unknown>";
            }
            return std::wstring(hostBuffer) + L":" + serviceBuffer;
        }

        // SendRawEventWithStatus:
        // - Input: category/module/api/status/detail are formatted event fields;
        // - Processing: Truncate NTSTATUS/HRESULT/DWORD uniformly to protocol resultCode.
        // - Returns: The return value of sendMonitorEventRaw.
        bool SendRawEventWithStatus(
            const ks::winapi_monitor::EventCategory categoryValue,
            const wchar_t* const moduleName,
            const wchar_t* const apiName,
            const long statusValue,
            const wchar_t* const detailText)
        {
            return sendMonitorEventRaw(
                categoryValue,
                moduleName,
                apiName,
                static_cast<std::int32_t>(statusValue),
                detailText);
        }

        ks::winapi_monitor::EventCategory inferRawHookCategory(const std::wstring& moduleName, const std::string& procName);
        void emitRawStubByte(unsigned char* codePointer, std::size_t& offsetValue, unsigned char byteValue);
        void emitRawStubU64(unsigned char* codePointer, std::size_t& offsetValue, std::uint64_t value);

        std::string wideToAnsiExportName(const std::wstring& textValue)
        {
            // wideToAnsiExportName:
            // - Input: Wide string of the API export name saved in UI/INI.
            // - Processing: Convert to a narrow string required by GetProcAddress using the system code page; on failure, retain only ASCII.
            // - Return: Export name suitable for GetProcAddress; returns empty string if conversion fails.
            if (textValue.empty())
            {
                return std::string();
            }

            const int kRequiredBytes = ::WideCharToMultiByte(
                CP_ACP,
                0,
                textValue.c_str(),
                -1,
                nullptr,
                0,
                nullptr,
                nullptr);
            if (kRequiredBytes > 0)
            {
                std::string ansiText(static_cast<std::size_t>(kRequiredBytes), '\0');
                const int kConvertedBytes = ::WideCharToMultiByte(
                    CP_ACP,
                    0,
                    textValue.c_str(),
                    -1,
                    ansiText.data(),
                    kRequiredBytes,
                    nullptr,
                    nullptr);
                if (kConvertedBytes > 0 && !ansiText.empty())
                {
                    ansiText.resize(static_cast<std::size_t>(kConvertedBytes - 1));
                    return ansiText;
                }
            }

            std::string fallbackText;
            for (const wchar_t kCh : textValue)
            {
                if (kCh == L'\0')
                {
                    break;
                }
                if (kCh < 0x20 || kCh > 0x7E)
                {
                    return std::string();
                }
                fallbackText.push_back(static_cast<char>(kCh));
            }
            return fallbackText;
        }

        std::wstring buildInstallModuleName(const std::wstring& moduleName)
        {
            // buildInstallModuleName:
            // - Input: User-configured module name, which may include .dll or be a short name like KernelBase.
            // - Processing: Preserve existing extension when installing hooks; append .dll if no extension exists.
            // - Returns: Module name directly usable by GetModuleHandleW for matching.
            std::wstring installName = moduleName;
            if (installName.find(L'.') == std::wstring::npos)
            {
                installName.append(L".dll");
            }
            return installName;
        }

        FakeSuccessRuntimeRule* findFakeSuccessRule(const std::wstring& moduleName, const std::string& procName)
        {
            const MonitorConfig& configValue = activeConfig();
            auto& ruleMap = fakeSuccessRuleMap();
            if (!configValue.fakeSuccessEnabled || ruleMap.empty())
            {
                return nullptr;
            }

            const auto kIterator = ruleMap.find(makeFakeSuccessKey(moduleName, procName));
            return kIterator != ruleMap.end() ? kIterator->second : nullptr;
        }

        template <std::size_t kCount>
        void appendFakeSuccessDetail(wchar_t(&detailBuffer)[kCount], const FakeSuccessRuntimeRule& ruleValue)
        {
            appendWideText(detailBuffer, L"FakeSuccess=1 original=skipped returnType=");
            switch (ruleValue.returnType)
            {
            case FakeSuccessReturnType::kBool: appendWideText(detailBuffer, L"BOOL"); break;
            case FakeSuccessReturnType::kHandle: appendWideText(detailBuffer, L"HANDLE/PVOID"); break;
            case FakeSuccessReturnType::kDword: appendWideText(detailBuffer, L"DWORD/UINT/int"); break;
            case FakeSuccessReturnType::kNtStatus: appendWideText(detailBuffer, L"NTSTATUS"); break;
            case FakeSuccessReturnType::kHResult: appendWideText(detailBuffer, L"HRESULT"); break;
            case FakeSuccessReturnType::kLStatus: appendWideText(detailBuffer, L"LSTATUS"); break;
            case FakeSuccessReturnType::kSocketInt: appendWideText(detailBuffer, L"SOCKET/int(WSA)"); break;
            default: appendWideText(detailBuffer, L"Scalar"); break;
            }
            appendWideText(detailBuffer, L" return=");
            appendHexText(detailBuffer, ruleValue.returnValue);
            if (ruleValue.lastErrorKind != FakeSuccessLastErrorKind::kNone)
            {
                appendWideText(detailBuffer, ruleValue.lastErrorKind == FakeSuccessLastErrorKind::kWsa ? L" WSAError=" : L" LastError=");
                appendUnsignedText(detailBuffer, ruleValue.lastErrorValue);
            }
        }

        std::int32_t fakeSuccessResultCode(const FakeSuccessRuntimeRule& ruleValue)
        {
            if (ruleValue.lastErrorKind != FakeSuccessLastErrorKind::kNone && ruleValue.lastErrorValue != 0)
            {
                return static_cast<std::int32_t>(ruleValue.lastErrorValue);
            }
            if (ruleValue.returnType == FakeSuccessReturnType::kBool)
            {
                return ruleValue.returnValue != 0 ? 0 : static_cast<std::int32_t>(ruleValue.returnValue & 0xFFFFFFFFULL);
            }
            if (ruleValue.returnType == FakeSuccessReturnType::kHandle)
            {
                return (ruleValue.returnValue != 0 && ruleValue.returnValue != 0xFFFFFFFFFFFFFFFFULL)
                    ? 0
                    : static_cast<std::int32_t>(ruleValue.returnValue & 0xFFFFFFFFULL);
            }
            if (ruleValue.returnType == FakeSuccessReturnType::kSocketInt)
            {
                return static_cast<std::uint32_t>(ruleValue.returnValue & 0xFFFFFFFFULL) != 0xFFFFFFFFU
                    ? 0
                    : static_cast<std::int32_t>(ruleValue.returnValue & 0xFFFFFFFFULL);
            }
            return static_cast<std::int32_t>(ruleValue.returnValue & 0xFFFFFFFFULL);
        }

        std::uint64_t fakeSuccessEnter(FakeSuccessRuntimeRule* const ruleValue)
        {
            if (ruleValue == nullptr)
            {
                return 0;
            }

            const DWORD kPreviousLastError = ::GetLastError();
            ScopedHookGuard guardValue;
            if (!guardValue.bypass())
            {
                wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
                appendFakeSuccessDetail(detailBuffer, *ruleValue);
                SendRawEventWithStatus(
                    ruleValue->categoryValue,
                    ruleValue->moduleName.c_str(),
                    ruleValue->apiName.c_str(),
                    fakeSuccessResultCode(*ruleValue),
                    detailBuffer);
            }

            if (ruleValue->lastErrorKind == FakeSuccessLastErrorKind::kWin32)
            {
                ::SetLastError(ruleValue->lastErrorValue);
            }
            else if (ruleValue->lastErrorKind == FakeSuccessLastErrorKind::kWsa)
            {
                ::SetLastError(kPreviousLastError);
                ::WSASetLastError(static_cast<int>(ruleValue->lastErrorValue));
            }
            else
            {
                ::SetLastError(kPreviousLastError);
            }

            return ruleValue->returnValue;
        }

        // buildFakeSuccessRuleIndex:
        // - Input: Fake Success rules written by the UI in activeConfig;
        // - Processing: normalize module!api match keys, complete the installed module name, convert ANSI export names, and build an index based on 'first rule priority'.
        // - Return: No return value; fakeSuccessRules/fakeSuccessRuleMap store the runtime rules installable in this session.
        void buildFakeSuccessRuleIndex()
        {
            auto& ruleList = fakeSuccessRules();
            auto& ruleMap = fakeSuccessRuleMap();
            ruleList.clear();
            ruleMap.clear();

            const MonitorConfig& configValue = activeConfig();
            if (!configValue.fakeSuccessEnabled)
            {
                return;
            }

            for (const FakeSuccessRule& sourceRule : configValue.fakeSuccessRules)
            {
                const std::wstring kMatchKey = makeFakeSuccessKey(sourceRule.moduleName, sourceRule.apiName);
                if (kMatchKey.empty() || ruleMap.find(kMatchKey) != ruleMap.end())
                {
                    continue;
                }

                std::string ansiApiName = wideToAnsiExportName(sourceRule.apiName);
                if (ansiApiName.empty())
                {
                    continue;
                }

                auto runtimeRule = std::make_unique<FakeSuccessRuntimeRule>();
                runtimeRule->moduleName = sourceRule.moduleName;
                runtimeRule->installModuleName = buildInstallModuleName(sourceRule.moduleName);
                runtimeRule->apiName = sourceRule.apiName;
                runtimeRule->apiNameAnsi = std::move(ansiApiName);
                runtimeRule->matchKey = kMatchKey;
                runtimeRule->categoryValue = inferRawHookCategory(runtimeRule->installModuleName, runtimeRule->apiNameAnsi);
                runtimeRule->returnType = sourceRule.returnType;
                runtimeRule->returnValue = sourceRule.returnValue;
                runtimeRule->lastErrorKind = sourceRule.lastErrorKind;
                runtimeRule->lastErrorValue = sourceRule.lastErrorValue;

                FakeSuccessRuntimeRule* const kRulePointer = runtimeRule.get();
                ruleMap.emplace(kRulePointer->matchKey, kRulePointer);
                ruleList.push_back(std::move(runtimeRule));
            }
        }

        // buildFakeSuccessEntryStub:
        // - Input: ruleValue points to a Fake Success runtime rule;
        // - Processing: Generate a small x64 detour stub that calls fakeSuccessEnter(rule) to report the event and retrieve the RAX return value.
        // - Returns: Executable memory address as the detourAddress for installInlineHook; returns nullptr on failure.
        void* buildFakeSuccessEntryStub(FakeSuccessRuntimeRule* const ruleValue)
        {
            if (ruleValue == nullptr)
            {
                return nullptr;
            }

            constexpr std::size_t kFakeStubBytes = 64;
            unsigned char* const kCodePointer = static_cast<unsigned char*>(::VirtualAlloc(
                nullptr,
                kFakeStubBytes,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE));
            if (kCodePointer == nullptr)
            {
                return nullptr;
            }

            std::size_t offsetValue = 0;
            const auto kEmit = [kCodePointer, &offsetValue](const unsigned char byteValue) {
                emitRawStubByte(kCodePointer, offsetValue, byteValue);
            };

            kEmit(0x48); kEmit(0x83); kEmit(0xEC); kEmit(0x28); // sub rsp, 0x28: Align the stack and provide 32 bytes of shadow space.
            kEmit(0x48); kEmit(0xB9);                         // mov rcx, ruleValue: First argument in Windows x64.
            emitRawStubU64(kCodePointer, offsetValue, reinterpret_cast<std::uint64_t>(ruleValue));
            kEmit(0x48); kEmit(0xB8);                         // mov rax, fakeSuccessEnter。
            emitRawStubU64(kCodePointer, offsetValue, reinterpret_cast<std::uint64_t>(&fakeSuccessEnter));
            kEmit(0xFF); kEmit(0xD0);                         // call rax: Return value remains in RAX.
            kEmit(0x48); kEmit(0x83); kEmit(0xC4); kEmit(0x28); // add rsp, 0x28: restore caller stack.
            kEmit(0xC3);                                     // ret: Directly return to the original API caller without executing the original function.

            ::FlushInstructionCache(::GetCurrentProcess(), kCodePointer, offsetValue);
            return kCodePointer;
        }

        void freeFakeSuccessEntryStub(void* const stubAddress)
        {
            // freeFakeSuccessEntryStub:
            // - Input: executable memory returned by buildFakeSuccessEntryStub
            // - Processing: Release the dynamic stub; the caller must first unload the inline hook.
            // - Returns: Nothing.
            if (stubAddress != nullptr)
            {
                ::VirtualFree(stubAddress, 0, MEM_RELEASE);
            }
        }

        void appendFakeSuccessFailureText(
            std::wstring* const detailTextOut,
            const FakeSuccessRuntimeRule& ruleValue,
            const InlineHookInstallResult installResult,
            const std::wstring& errorText)
        {
            // appendFakeSuccessFailureText:
            // - Input: rules for installation failure, failure type, and HookEngine diagnostic text;
            // - Processing: Append to the aggregated errors in installConfiguredHooks for display in UI internal events.
            // - Return: No return value; silently skip if detailTextOut is null.
            if (detailTextOut == nullptr)
            {
                return;
            }
            if (!detailTextOut->empty())
            {
                detailTextOut->append(L" | ");
            }

            detailTextOut->append(ruleValue.moduleName);
            detailTextOut->append(L"!");
            detailTextOut->append(ruleValue.apiName);
            detailTextOut->append(
                installResult == InlineHookInstallResult::kRetryableFailure
                ? L": fake retryable failure - "
                : L": fake disabled - ");
            detailTextOut->append(errorText.empty() ? L"unknown reason" : errorText);
        }

        bool tryInstallFakeSuccessRule(
            FakeSuccessRuntimeRule& ruleValue,
            const std::optional<ks::winapi_monitor::EventCategory> categoryOverride,
            std::wstring* const detailTextOut)
        {
            // tryInstallFakeSuccessRule:
            // - Input: Runtime rules with an optional category override to maintain accurate category matching during strong-type binding hits;
            // Handling: Generate a fake-return stub for the rule and inline-patch the target export to this stub.
            // - Returns: true if the rule is already installed or the installation succeeded; false on failure.
            if (categoryOverride.has_value())
            {
                ruleValue.categoryValue = categoryOverride.value();
            }
            if (ruleValue.hookRecord.installed || ruleValue.hookRecord.permanentlyDisabled)
            {
                return ruleValue.hookRecord.installed;
            }
            if (ruleValue.entryStubAddress == nullptr)
            {
                ruleValue.entryStubAddress = buildFakeSuccessEntryStub(&ruleValue);
                if (ruleValue.entryStubAddress == nullptr)
                {
                    ruleValue.hookRecord.permanentlyDisabled = true;
                    appendFakeSuccessFailureText(
                        detailTextOut,
                        ruleValue,
                        InlineHookInstallResult::kPermanentFailure,
                        L"VirtualAlloc for fake-return stub failed.");
                    return false;
                }
            }

            std::wstring errorText;
            const InlineHookInstallResult kInstallResult = installInlineHook(
                ruleValue.installModuleName.c_str(),
                ruleValue.apiNameAnsi.c_str(),
                ruleValue.entryStubAddress,
                &ruleValue.hookRecord,
                &ruleValue.originalAddress,
                &errorText);
            if (kInstallResult == InlineHookInstallResult::kInstalled)
            {
                return true;
            }
            if (kInstallResult == InlineHookInstallResult::kPermanentFailure)
            {
                ruleValue.hookRecord.permanentlyDisabled = true;
            }
            appendFakeSuccessFailureText(detailTextOut, ruleValue, kInstallResult, errorText);
            return false;
        }

        // rawHookEnter:
        // - Input: bindingValue is Raw Hook metadata passed by the dynamic stub;
        // - Processing: Report module/api/target/trampoline without parsing argument semantics, and use a global reentry guard to prevent log chain recursion.
        // - Return: No return value; the dynamic stub subsequently restores registers and jumps into the trampoline to continue executing the original function.
        void rawHookEnter(RawHookBinding* const bindingValue)
        {
            if (bindingValue == nullptr)
            {
                return;
            }

            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return;
            }

            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"Raw ABI fallback target=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(bindingValue->hookRecord.targetAddress));
            appendWideText(detailBuffer, L" trampoline=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(bindingValue->originalAddress));
            appendWideText(detailBuffer, L" strongTyped=0 params=unparsed");
            SendRawEventWithStatus(
                bindingValue->categoryValue,
                bindingValue->moduleName.c_str(),
                bindingValue->procNameWide.c_str(),
                0,
                detailBuffer);
        }

        // emitRawStubByte/emitRawStubU32/emitRawStubU64 purpose:
        // - Input: Dynamic code buffer and value to write;
        // - Processing: Sequentially write x64 Raw Hook stub instruction bytes.
        // - Returns: None. Advances offsetValue to the position of the next instruction.
        void emitRawStubByte(unsigned char* const codePointer, std::size_t& offsetValue, const unsigned char byteValue)
        {
            codePointer[offsetValue++] = byteValue;
        }

        void emitRawStubU32(unsigned char* const codePointer, std::size_t& offsetValue, const std::uint32_t value)
        {
            std::memcpy(codePointer + offsetValue, &value, sizeof(value));
            offsetValue += sizeof(value);
        }

        void emitRawStubU64(unsigned char* const codePointer, std::size_t& offsetValue, const std::uint64_t value)
        {
            std::memcpy(codePointer + offsetValue, &value, sizeof(value));
            offsetValue += sizeof(value);
        }

        void emitRawStubMovdquStore(unsigned char* const codePointer, std::size_t& offsetValue, const unsigned char xmmIndex, const unsigned char stackOffset)
        {
            emitRawStubByte(codePointer, offsetValue, 0xF3);
            emitRawStubByte(codePointer, offsetValue, 0x0F);
            emitRawStubByte(codePointer, offsetValue, 0x7F);
            emitRawStubByte(codePointer, offsetValue, static_cast<unsigned char>(0x44U + (xmmIndex * 0x08U)));
            emitRawStubByte(codePointer, offsetValue, 0x24);
            emitRawStubByte(codePointer, offsetValue, stackOffset);
        }

        void emitRawStubMovdquLoad(unsigned char* const codePointer, std::size_t& offsetValue, const unsigned char xmmIndex, const unsigned char stackOffset)
        {
            emitRawStubByte(codePointer, offsetValue, 0xF3);
            emitRawStubByte(codePointer, offsetValue, 0x0F);
            emitRawStubByte(codePointer, offsetValue, 0x6F);
            emitRawStubByte(codePointer, offsetValue, static_cast<unsigned char>(0x44U + (xmmIndex * 0x08U)));
            emitRawStubByte(codePointer, offsetValue, 0x24);
            emitRawStubByte(codePointer, offsetValue, stackOffset);
        }

        // buildRawEntryStub:
        // - Input: bindingValue points to Raw Hook metadata; stub reads the trampoline via this pointer.
        // - Processing: Generate a generic x64 entry stub that saves integer parameter registers and XMM0-XMM5, calls rawHookEnter, and then jumps to the trampoline.
        // - Return: An executable memory address suitable for installInlineHook hookAddress on success; nullptr on failure.
        void* buildRawEntryStub(RawHookBinding* const bindingValue)
        {
            if (bindingValue == nullptr)
            {
                return nullptr;
            }

            constexpr std::size_t kRawStubBytes = 256;
            unsigned char* const kCodePointer = static_cast<unsigned char*>(::VirtualAlloc(
                nullptr,
                kRawStubBytes,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE));
            if (kCodePointer == nullptr)
            {
                return nullptr;
            }

            std::size_t offsetValue = 0;
            const auto kEmit = [kCodePointer, &offsetValue](const unsigned char byteValue) {
                emitRawStubByte(kCodePointer, offsetValue, byteValue);
            };

            kEmit(0x50);                         // push rax
            kEmit(0x51);                         // push rcx
            kEmit(0x52);                         // push rdx
            kEmit(0x41); kEmit(0x50);             // push r8
            kEmit(0x41); kEmit(0x51);             // push r9
            kEmit(0x41); kEmit(0x52);             // push r10
            kEmit(0x41); kEmit(0x53);             // push r11
            kEmit(0x48); kEmit(0x81); kEmit(0xEC); // sub rsp, 0xA0
            emitRawStubU32(kCodePointer, offsetValue, 0x000000A0U);

            emitRawStubMovdquStore(kCodePointer, offsetValue, 0, 0x20);
            emitRawStubMovdquStore(kCodePointer, offsetValue, 1, 0x30);
            emitRawStubMovdquStore(kCodePointer, offsetValue, 2, 0x40);
            emitRawStubMovdquStore(kCodePointer, offsetValue, 3, 0x50);
            emitRawStubMovdquStore(kCodePointer, offsetValue, 4, 0x60);
            emitRawStubMovdquStore(kCodePointer, offsetValue, 5, 0x70);

            kEmit(0x48); kEmit(0xB9);             // mov rcx, bindingValue
            emitRawStubU64(kCodePointer, offsetValue, reinterpret_cast<std::uint64_t>(bindingValue));
            kEmit(0x48); kEmit(0xB8);             // mov rax, rawHookEnter
            emitRawStubU64(kCodePointer, offsetValue, reinterpret_cast<std::uint64_t>(&rawHookEnter));
            kEmit(0xFF); kEmit(0xD0);             // call rax

            emitRawStubMovdquLoad(kCodePointer, offsetValue, 0, 0x20);
            emitRawStubMovdquLoad(kCodePointer, offsetValue, 1, 0x30);
            emitRawStubMovdquLoad(kCodePointer, offsetValue, 2, 0x40);
            emitRawStubMovdquLoad(kCodePointer, offsetValue, 3, 0x50);
            emitRawStubMovdquLoad(kCodePointer, offsetValue, 4, 0x60);
            emitRawStubMovdquLoad(kCodePointer, offsetValue, 5, 0x70);

            kEmit(0x48); kEmit(0x81); kEmit(0xC4); // add rsp, 0xA0
            emitRawStubU32(kCodePointer, offsetValue, 0x000000A0U);
            kEmit(0x41); kEmit(0x5B);             // pop r11
            kEmit(0x41); kEmit(0x5A);             // pop r10
            kEmit(0x41); kEmit(0x59);             // pop r9
            kEmit(0x41); kEmit(0x58);             // pop r8
            kEmit(0x5A);                         // pop rdx
            kEmit(0x59);                         // pop rcx
            kEmit(0x58);                         // pop rax
            kEmit(0x49); kEmit(0xBB);             // mov r11, &bindingValue->originalAddress
            emitRawStubU64(kCodePointer, offsetValue, reinterpret_cast<std::uint64_t>(&bindingValue->originalAddress));
            kEmit(0x4D); kEmit(0x8B); kEmit(0x1B); // mov r11, [r11]
            kEmit(0x41); kEmit(0xFF); kEmit(0xE3); // jmp r11

            ::FlushInstructionCache(::GetCurrentProcess(), kCodePointer, offsetValue);
            return kCodePointer;
        }

        void freeRawEntryStub(void* const stubAddress)
        {
            if (stubAddress != nullptr)
            {
                ::VirtualFree(stubAddress, 0, MEM_RELEASE);
            }
        }

        bool tryInstallBinding(HookBinding& bindingValue, std::wstring* detailTextOut)
        {
            FakeSuccessRuntimeRule* const kFakeRule = findFakeSuccessRule(bindingValue.moduleName, bindingValue.procName);
            if (kFakeRule != nullptr)
            {
                return tryInstallFakeSuccessRule(*kFakeRule, bindingValue.categoryValue, detailTextOut);
            }

            if (!categoryEnabled(bindingValue.categoryValue)
                || bindingValue.hookRecord->installed
                || bindingValue.hookRecord->permanentlyDisabled)
            {
                return bindingValue.hookRecord->installed;
            }

            std::wstring errorText;
            const InlineHookInstallResult kInstallResult = installInlineHook(
                bindingValue.moduleName,
                bindingValue.procName,
                bindingValue.hookAddress,
                bindingValue.hookRecord,
                bindingValue.originalOut,
                &errorText);
            if (kInstallResult == InlineHookInstallResult::kInstalled)
            {
                return true;
            }
            if (kInstallResult == InlineHookInstallResult::kPermanentFailure)
            {
                bindingValue.hookRecord->permanentlyDisabled = true;
            }
            appendHookFailureText(detailTextOut, bindingValue, kInstallResult, errorText);
            return false;
        }

        // sendLoaderEventIfEnabled:
        // - Input: LoadLibrary API name, path, result, and error code;
        // - Processing: Only report when the loader category is checked in the UI to avoid forcing event noise by 'installing required loader hooks'.
        // - Return: No return value; the caller is responsible for restoring LastError.
        void sendLoaderEventIfEnabled(
            const wchar_t* const apiName,
            const std::wstring& fileNameText,
            const HMODULE moduleHandle,
            const DWORD lastError,
            const std::wstring& extraText)
        {
            if (!activeConfig().enableLoader)
            {
                return;
            }

            sendMonitorEvent(
                ks::winapi_monitor::EventCategory::kLoader,
                L"Kernel32",
                apiName,
                moduleHandle != nullptr ? 0 : static_cast<std::int32_t>(lastError),
                trimDetail(L"path=" + fileNameText + extraText));
        }

        // joinIniList:
        // - Input: Raw module/blacklist list split from MonitorConfig;
        // - Processing: Rejoin the list using semicolons in INI single-line format for automatic injection of child processes to inherit the parent's Raw configuration.
        // - Returns: List text directly writable to config_<pid>.ini.
        std::wstring joinIniList(const std::vector<std::wstring>& itemList)
        {
            std::wstring joinedText;
            for (const std::wstring& itemText : itemList)
            {
                if (itemText.empty())
                {
                    continue;
                }
                if (!joinedText.empty())
                {
                    joinedText.append(L";");
                }
                joinedText.append(itemText);
            }
            return joinedText;
        }

        // writeChildMonitorConfig:
        // - Input: childPidValue is the new child process PID, configValue is the parent process's current monitoring configuration;
        // - Processing: Generate a child-process-specific INI, inheriting the current category switches, DLL paths, and auto-injection policy.
        // - Returns: true on successful write; false on failure with errorTextOut populated.
        bool writeChildMonitorConfig(
            const DWORD childPidValue,
            const MonitorConfig& configValue,
            std::wstring* const errorTextOut)
        {
            if (errorTextOut != nullptr)
            {
                errorTextOut->clear();
            }
            if (childPidValue == 0 || configValue.agentDllPath.empty())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"child pid or agent dll path is empty.";
                }
                return false;
            }

            const std::wstring kSessionDirectory = ks::winapi_monitor::buildSessionDirectory();
            (void)::CreateDirectoryW(kSessionDirectory.c_str(), nullptr);

            const std::wstring kChildConfigPath = ks::winapi_monitor::buildConfigPathForPid(childPidValue);
            const std::wstring kChildStopPath = ks::winapi_monitor::buildStopFlagPathForPid(childPidValue);
            (void)::DeleteFileW(kChildStopPath.c_str());

            HANDLE fileHandle = ::CreateFileW(
                kChildConfigPath.c_str(),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"CreateFileW child config failed. error=" + std::to_wstring(::GetLastError());
                }
                return false;
            }

            const std::wstring kConfigText =
                L"[monitor]\r\n"
                L"pipe_name=" + ks::winapi_monitor::buildPipeNameForPid(childPidValue) + L"\r\n"
                L"stop_flag_path=" + kChildStopPath + L"\r\n"
                L"agent_dll_path=" + configValue.agentDllPath + L"\r\n"
                L"enable_file=" + std::to_wstring(configValue.enableFile ? 1 : 0) + L"\r\n"
                L"enable_registry=" + std::to_wstring(configValue.enableRegistry ? 1 : 0) + L"\r\n"
                L"enable_network=" + std::to_wstring(configValue.enableNetwork ? 1 : 0) + L"\r\n"
                L"enable_process=" + std::to_wstring(configValue.enableProcess ? 1 : 0) + L"\r\n"
                L"enable_loader=" + std::to_wstring(configValue.enableLoader ? 1 : 0) + L"\r\n"
                L"auto_inject_child=" + std::to_wstring(configValue.autoInjectChild ? 1 : 0) + L"\r\n"
                L"enable_raw_fallback=" + std::to_wstring(configValue.enableRawFallback ? 1 : 0) + L"\r\n"
                L"raw_use_default_denylist=" + std::to_wstring(configValue.rawUseDefaultDenyList ? 1 : 0) + L"\r\n"
                L"raw_modules=" + joinIniList(configValue.rawModuleList) + L"\r\n"
                L"raw_denylist=" + joinIniList(configValue.rawDenyList) + L"\r\n"
                L"fake_success_enabled=" + std::to_wstring(configValue.fakeSuccessEnabled ? 1 : 0) + L"\r\n"
                L"fake_success_raw_fallback=" + std::to_wstring(configValue.fakeSuccessRawFallback ? 1 : 0) + L"\r\n"
                L"fake_success_rules=" + configValue.fakeSuccessRulesText + L"\r\n"
                L"detail_limit=" + std::to_wstring(configValue.detailLimitChars) + L"\r\n";

            const wchar_t kUnicodeBom = static_cast<wchar_t>(0xFEFF);
            DWORD bomBytesWritten = 0;
            const BOOL kBomWriteOk = ::WriteFile(
                fileHandle,
                &kUnicodeBom,
                sizeof(kUnicodeBom),
                &bomBytesWritten,
                nullptr);

            DWORD bytesWritten = 0;
            const BOOL kWriteOk = ::WriteFile(
                fileHandle,
                kConfigText.data(),
                static_cast<DWORD>(kConfigText.size() * sizeof(wchar_t)),
                &bytesWritten,
                nullptr);
            const DWORD kWriteError = ::GetLastError();
            ::CloseHandle(fileHandle);

            if (kBomWriteOk == FALSE
                || bomBytesWritten != sizeof(kUnicodeBom)
                || kWriteOk == FALSE
                || bytesWritten != kConfigText.size() * sizeof(wchar_t))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"WriteFile child config failed. error=" + std::to_wstring(kWriteError);
                }
                return false;
            }
            return true;
        }

        // injectAgentIntoChildProcess:
        // - Input: childPidValue is the child process PID, and dllPath is the path to APIMonitor_x64.dll.
        // - Processing: Inject using VirtualAllocEx/WriteProcessMemory/CreateRemoteThread(LoadLibraryW).
        // - Return: true on successful injection; false on failure with errorTextOut populated.
        bool injectAgentIntoChildProcess(
            const DWORD childPidValue,
            const std::wstring& dllPath,
            std::wstring* const errorTextOut)
        {
            if (errorTextOut != nullptr)
            {
                errorTextOut->clear();
            }
            if (childPidValue == 0 || dllPath.empty())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"child pid or dll path is empty.";
                }
                return false;
            }

            HANDLE processHandle = ::OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                FALSE,
                childPidValue);
            if (processHandle == nullptr)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"OpenProcess child failed. error=" + std::to_wstring(::GetLastError());
                }
                return false;
            }

            const std::size_t kByteCount = (dllPath.size() + 1) * sizeof(wchar_t);
            void* remotePathMemory = ::VirtualAllocEx(
                processHandle,
                nullptr,
                kByteCount,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);
            if (remotePathMemory == nullptr)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"VirtualAllocEx child failed. error=" + std::to_wstring(::GetLastError());
                }
                ::CloseHandle(processHandle);
                return false;
            }

            SIZE_T bytesWritten = 0;
            const BOOL kWriteOk = ::WriteProcessMemory(
                processHandle,
                remotePathMemory,
                dllPath.c_str(),
                kByteCount,
                &bytesWritten);
            if (kWriteOk == FALSE || bytesWritten != kByteCount)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"WriteProcessMemory child failed. error=" + std::to_wstring(::GetLastError());
                }
                ::VirtualFreeEx(processHandle, remotePathMemory, 0, MEM_RELEASE);
                ::CloseHandle(processHandle);
                return false;
            }

            HMODULE kernelModule = ::GetModuleHandleW(L"kernel32.dll");
            FARPROC loadLibraryPointer = kernelModule != nullptr ? ::GetProcAddress(kernelModule, "LoadLibraryW") : nullptr;
            if (loadLibraryPointer == nullptr)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"GetProcAddress LoadLibraryW failed.";
                }
                ::VirtualFreeEx(processHandle, remotePathMemory, 0, MEM_RELEASE);
                ::CloseHandle(processHandle);
                return false;
            }

            HANDLE remoteThread = ::CreateRemoteThread(
                processHandle,
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryPointer),
                remotePathMemory,
                0,
                nullptr);
            if (remoteThread == nullptr)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"CreateRemoteThread child failed. error=" + std::to_wstring(::GetLastError());
                }
                ::VirtualFreeEx(processHandle, remotePathMemory, 0, MEM_RELEASE);
                ::CloseHandle(processHandle);
                return false;
            }

            const DWORD kWaitResult = ::WaitForSingleObject(remoteThread, 10000);
            const DWORD kWaitError = kWaitResult == WAIT_FAILED ? ::GetLastError() : ERROR_SUCCESS;
            if (kWaitResult != WAIT_OBJECT_0)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kWaitResult == WAIT_TIMEOUT
                        ? L"Remote LoadLibraryW timed out; remote DLL path is retained until the child exits."
                        : L"WaitForSingleObject remote LoadLibraryW failed. error=" + std::to_wstring(kWaitError);
                }

                // The remote thread can still be reading remotePathMemory after a timeout.
                // The child process reclaims this allocation on exit.
                ::CloseHandle(remoteThread);
                ::CloseHandle(processHandle);
                return false;
            }

            DWORD exitCode = 0;
            if (::GetExitCodeThread(remoteThread, &exitCode) == FALSE)
            {
                const DWORD kExitCodeError = ::GetLastError();
                ::CloseHandle(remoteThread);
                ::VirtualFreeEx(processHandle, remotePathMemory, 0, MEM_RELEASE);
                ::CloseHandle(processHandle);
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"GetExitCodeThread remote LoadLibraryW failed. error=" + std::to_wstring(kExitCodeError);
                }
                return false;
            }

            ::CloseHandle(remoteThread);
            ::VirtualFreeEx(processHandle, remotePathMemory, 0, MEM_RELEASE);
            ::CloseHandle(processHandle);

            if (exitCode == 0)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"Remote LoadLibraryW returned NULL.";
                }
                return false;
            }
            return true;
        }

        // autoInjectChildIfRequested:
        // - Input: CreateProcessW result and PROCESS_INFORMATION;
        // - Processing: When configuration is enabled, write configuration to child processes and inject the current Agent.
        // - Return: No return value; success or failure is reported via internal events.
        void autoInjectChildIfRequested(
            const BOOL createResult,
            const PROCESS_INFORMATION* const processInfoPointer)
        {
            const MonitorConfig& configValue = activeConfig();
            if (createResult == FALSE
                || !configValue.autoInjectChild
                || processInfoPointer == nullptr
                || processInfoPointer->dwProcessId == 0
                || configValue.agentDllPath.empty())
            {
                return;
            }

            std::wstring errorText;
            bool successValue = writeChildMonitorConfig(processInfoPointer->dwProcessId, configValue, &errorText);
            if (successValue)
            {
                successValue = injectAgentIntoChildProcess(processInfoPointer->dwProcessId, configValue.agentDllPath, &errorText);
            }

            sendMonitorEvent(
                ks::winapi_monitor::EventCategory::kInternal,
                L"Agent",
                successValue ? L"AutoInjectChild" : L"AutoInjectChildFailed",
                successValue ? 0 : 1,
                trimDetail(
                    L"childPid=" + std::to_wstring(processInfoPointer->dwProcessId)
                    + (successValue ? L" injected" : (L" error=" + errorText))));
        }

        // autoInjectChildFromCreateProcessAIfRequested:
        // - Input: Return value and PROCESS_INFORMATION from CreateProcessA;
        // - Processing: Reuse W-version child process configuration write and injection logic;
        // - Return: No return value; success or failure is reflected via internal events.
        void autoInjectChildFromCreateProcessAIfRequested(
            const BOOL createResult,
            const PROCESS_INFORMATION* const processInfoPointer)
        {
            autoInjectChildIfRequested(createResult, processInfoPointer);
        }


        void retryPendingHooksFromHook();

        // hookedLdrLoadDll:
        // - Input: Original parameters of ntdll LdrLoadDll;
        // - Processing: Call the original function first, then install deferred hooks after the module is successfully loaded;
        // - Returns: Preserves the original NTSTATUS without rewriting loader semantics.
        NTSTATUS NTAPI hookedLdrLoadDll(PWSTR searchPathPointer, PULONG dllCharacteristicsPointer, PUNICODE_STRING dllNamePointer, PHANDLE moduleHandlePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gLdrLoadDllOriginal(searchPathPointer, dllCharacteristicsPointer, dllNamePointer, moduleHandlePointer);
            }

            const NTSTATUS kStatusValue = gLdrLoadDllOriginal(searchPathPointer, dllCharacteristicsPointer, dllNamePointer, moduleHandlePointer);
            if (NT_SUCCESS(kStatusValue))
            {
                retryPendingHooksFromHook();
            }
            if (activeConfig().enableLoader)
            {
                wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
                appendWideText(detailBuffer, L"path=");
                appendUnicodeStringText(detailBuffer, dllNamePointer);
                appendWideText(detailBuffer, L" search=");
                appendWideText(detailBuffer, searchPathPointer);
                appendWideText(detailBuffer, L" flags=");
                appendHexText(detailBuffer, dllCharacteristicsPointer != nullptr ? *dllCharacteristicsPointer : 0);
                appendWideText(detailBuffer, L" handle=");
                appendHexText(detailBuffer, moduleHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*moduleHandlePointer) : 0);
                SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kLoader, L"ntdll", L"LdrLoadDll", kStatusValue, detailBuffer);
            }
            return kStatusValue;
        }

        HMODULE WINAPI hookedLoadLibraryA(const LPCSTR fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gLoadLibraryAOriginal(fileNamePointer);
            }

            const std::wstring kFileNameText = ansiToWide(fileNamePointer);
            HMODULE moduleHandle = gLoadLibraryAOriginal(fileNamePointer);
            const DWORD kLastError = ::GetLastError();
            if (moduleHandle != nullptr)
            {
                retryPendingHooksFromHook();
            }
            sendLoaderEventIfEnabled(L"LoadLibraryA", kFileNameText, moduleHandle, kLastError, std::wstring());
            ::SetLastError(kLastError);
            return moduleHandle;
        }

        HMODULE WINAPI hookedLoadLibraryW(const LPCWSTR fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gLoadLibraryWOriginal(fileNamePointer);
            }

            const std::wstring kFileNameText = safeWideText(fileNamePointer);
            HMODULE moduleHandle = gLoadLibraryWOriginal(fileNamePointer);
            const DWORD kLastError = ::GetLastError();
            if (moduleHandle != nullptr)
            {
                retryPendingHooksFromHook();
            }
            sendLoaderEventIfEnabled(L"LoadLibraryW", kFileNameText, moduleHandle, kLastError, std::wstring());
            ::SetLastError(kLastError);
            return moduleHandle;
        }

        HMODULE WINAPI hookedLoadLibraryExA(const LPCSTR fileNamePointer, HANDLE fileHandle, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gLoadLibraryExAOriginal(fileNamePointer, fileHandle, flagsValue);
            }

            const std::wstring kFileNameText = ansiToWide(fileNamePointer);
            HMODULE moduleHandle = gLoadLibraryExAOriginal(fileNamePointer, fileHandle, flagsValue);
            const DWORD kLastError = ::GetLastError();
            if (moduleHandle != nullptr)
            {
                retryPendingHooksFromHook();
            }
            sendLoaderEventIfEnabled(L"LoadLibraryExA", kFileNameText, moduleHandle, kLastError, L" flags=" + hexValue(flagsValue));
            ::SetLastError(kLastError);
            return moduleHandle;
        }

        HMODULE WINAPI hookedLoadLibraryExW(const LPCWSTR fileNamePointer, HANDLE fileHandle, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gLoadLibraryExWOriginal(fileNamePointer, fileHandle, flagsValue);
            }

            const std::wstring kFileNameText = safeWideText(fileNamePointer);
            HMODULE moduleHandle = gLoadLibraryExWOriginal(fileNamePointer, fileHandle, flagsValue);
            const DWORD kLastError = ::GetLastError();
            if (moduleHandle != nullptr)
            {
                retryPendingHooksFromHook();
            }
            sendLoaderEventIfEnabled(L"LoadLibraryExW", kFileNameText, moduleHandle, kLastError, L" flags=" + hexValue(flagsValue));
            ::SetLastError(kLastError);
            return moduleHandle;
        }

        HANDLE WINAPI hookedCreateFileA(LPCSTR fileNamePointer, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES securityAttributes, DWORD creationDisposition, DWORD flagsAndAttributes, HANDLE templateFile)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gCreateFileAOriginal(fileNamePointer, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
            }

            HANDLE resultHandle = gCreateFileAOriginal(fileNamePointer, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildFilePathDetailA(detailBuffer, fileNamePointer, desiredAccess, shareMode, creationDisposition, flagsAndAttributes, resultHandle);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateFileA", resultHandle != INVALID_HANDLE_VALUE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return resultHandle;
        }

        HANDLE WINAPI hookedCreateFileW(LPCWSTR fileNamePointer, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES securityAttributes, DWORD creationDisposition, DWORD flagsAndAttributes, HANDLE templateFile)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gCreateFileWOriginal(fileNamePointer, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
            }

            HANDLE resultHandle = gCreateFileWOriginal(fileNamePointer, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildFilePathDetailW(detailBuffer, fileNamePointer, desiredAccess, shareMode, creationDisposition, flagsAndAttributes, resultHandle);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateFileW", resultHandle != INVALID_HANDLE_VALUE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return resultHandle;
        }

        HANDLE WINAPI hookedCreateFile2(LPCWSTR fileNamePointer, DWORD desiredAccess, DWORD shareMode, DWORD creationDisposition, LPCREATEFILE2_EXTENDED_PARAMETERS createExParamsPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gCreateFile2Original(fileNamePointer, desiredAccess, shareMode, creationDisposition, createExParamsPointer);
            }

            HANDLE resultHandle = gCreateFile2Original(fileNamePointer, desiredAccess, shareMode, creationDisposition, createExParamsPointer);
            const DWORD kLastError = ::GetLastError();
            const DWORD kFlagsValue = createExParamsPointer != nullptr ? createExParamsPointer->dwFileFlags : 0;
            const DWORD kAttributesValue = createExParamsPointer != nullptr ? createExParamsPointer->dwFileAttributes : 0;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildFilePathDetailW(detailBuffer, fileNamePointer, desiredAccess, shareMode, creationDisposition, kFlagsValue | kAttributesValue, resultHandle);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateFile2", resultHandle != INVALID_HANDLE_VALUE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return resultHandle;
        }

        BOOL WINAPI hookedReadFile(HANDLE fileHandle, LPVOID bufferPointer, DWORD bytesToRead, LPDWORD bytesReadPointer, LPOVERLAPPED overlappedPointer)
        {
            if (isMonitorPipeHandle(fileHandle))
            {
                return gReadFileOriginal(fileHandle, bufferPointer, bytesToRead, bytesReadPointer, overlappedPointer);
            }
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gReadFileOriginal(fileHandle, bufferPointer, bytesToRead, bytesReadPointer, overlappedPointer);
            }

            const BOOL kResultValue = gReadFileOriginal(fileHandle, bufferPointer, bytesToRead, bytesReadPointer, overlappedPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildHandleTransferDetail(detailBuffer, fileHandle, bytesToRead, bytesReadPointer != nullptr ? *bytesReadPointer : 0, nullptr);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"ReadFile", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedWriteFile(HANDLE fileHandle, LPCVOID bufferPointer, DWORD bytesToWrite, LPDWORD bytesWrittenPointer, LPOVERLAPPED overlappedPointer)
        {
            if (isMonitorPipeHandle(fileHandle))
            {
                return gWriteFileOriginal(fileHandle, bufferPointer, bytesToWrite, bytesWrittenPointer, overlappedPointer);
            }
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gWriteFileOriginal(fileHandle, bufferPointer, bytesToWrite, bytesWrittenPointer, overlappedPointer);
            }

            const BOOL kResultValue = gWriteFileOriginal(fileHandle, bufferPointer, bytesToWrite, bytesWrittenPointer, overlappedPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildHandleTransferDetail(detailBuffer, fileHandle, bytesToWrite, bytesWrittenPointer != nullptr ? *bytesWrittenPointer : 0, nullptr);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"WriteFile", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        // hookedDeviceIoControl:
        // - Input: device handle, IOCTL control code, input/output buffers, and OVERLAPPED structure;
        // - Processing: Record the control code and transfer size after calling the original DeviceIoControl, covering driver communication and device control behaviors.
        // - Return: preserves the original BOOL result and restores the LastError visible to the caller.
        BOOL WINAPI hookedDeviceIoControl(
            HANDLE deviceHandle,
            DWORD ioControlCode,
            LPVOID inBufferPointer,
            DWORD inBufferSize,
            LPVOID outBufferPointer,
            DWORD outBufferSize,
            LPDWORD bytesReturnedPointer,
            LPOVERLAPPED overlappedPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gDeviceIoControlOriginal(deviceHandle, ioControlCode, inBufferPointer, inBufferSize, outBufferPointer, outBufferSize, bytesReturnedPointer, overlappedPointer);
            }

            const BOOL kResultValue = gDeviceIoControlOriginal(deviceHandle, ioControlCode, inBufferPointer, inBufferSize, outBufferPointer, outBufferSize, bytesReturnedPointer, overlappedPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(deviceHandle));
            appendWideText(detailBuffer, L" code=");
            appendHexText(detailBuffer, ioControlCode);
            appendWideText(detailBuffer, L" in=");
            appendUnsignedText(detailBuffer, inBufferSize);
            appendWideText(detailBuffer, L" out=");
            appendUnsignedText(detailBuffer, outBufferSize);
            appendWideText(detailBuffer, L" returned=");
            appendUnsignedText(detailBuffer, bytesReturnedPointer != nullptr ? *bytesReturnedPointer : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"DeviceIoControl", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

#define APIMON_BOOL_SINGLE_W(HookName, Original, ApiName) \
        BOOL WINAPI HookName(LPCWSTR pathPointer) \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return Original(pathPointer); } \
            const BOOL resultValue = Original(pathPointer); \
            const DWORD lastError = ::GetLastError(); \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            BuildSinglePathDetailW(detailBuffer, pathPointer, 0); \
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", ApiName, resultValue != FALSE ? 0 : lastError, detailBuffer); \
            ::SetLastError(lastError); \
            return resultValue; \
        }

#define APIMON_BOOL_SINGLE_A(HookName, Original, ApiName) \
        BOOL WINAPI HookName(LPCSTR pathPointer) \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return Original(pathPointer); } \
            const BOOL resultValue = Original(pathPointer); \
            const DWORD lastError = ::GetLastError(); \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            BuildSinglePathDetailA(detailBuffer, pathPointer, 0); \
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", ApiName, resultValue != FALSE ? 0 : lastError, detailBuffer); \
            ::SetLastError(lastError); \
            return resultValue; \
        }

        APIMON_BOOL_SINGLE_W(HookedDeleteFileW, gDeleteFileWOriginal, L"DeleteFileW")
        APIMON_BOOL_SINGLE_A(HookedDeleteFileA, gDeleteFileAOriginal, L"DeleteFileA")
        APIMON_BOOL_SINGLE_W(HookedRemoveDirectoryW, gRemoveDirectoryWOriginal, L"RemoveDirectoryW")
        APIMON_BOOL_SINGLE_A(HookedRemoveDirectoryA, gRemoveDirectoryAOriginal, L"RemoveDirectoryA")

        BOOL WINAPI hookedMoveFileExW(LPCWSTR existingFileNamePointer, LPCWSTR newFileNamePointer, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gMoveFileExWOriginal(existingFileNamePointer, newFileNamePointer, flagsValue); }
            const BOOL kResultValue = gMoveFileExWOriginal(existingFileNamePointer, newFileNamePointer, flagsValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildTwoPathDetailW(detailBuffer, existingFileNamePointer, newFileNamePointer, flagsValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"MoveFileExW", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedMoveFileExA(LPCSTR existingFileNamePointer, LPCSTR newFileNamePointer, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gMoveFileExAOriginal(existingFileNamePointer, newFileNamePointer, flagsValue); }
            const BOOL kResultValue = gMoveFileExAOriginal(existingFileNamePointer, newFileNamePointer, flagsValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildTwoPathDetailA(detailBuffer, existingFileNamePointer, newFileNamePointer, flagsValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"MoveFileExA", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedCopyFileW(LPCWSTR existingFileNamePointer, LPCWSTR newFileNamePointer, BOOL failIfExists)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gCopyFileWOriginal(existingFileNamePointer, newFileNamePointer, failIfExists); }
            const BOOL kResultValue = gCopyFileWOriginal(existingFileNamePointer, newFileNamePointer, failIfExists);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildTwoPathDetailW(detailBuffer, existingFileNamePointer, newFileNamePointer, failIfExists ? 1 : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CopyFileW", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedCopyFileA(LPCSTR existingFileNamePointer, LPCSTR newFileNamePointer, BOOL failIfExists)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gCopyFileAOriginal(existingFileNamePointer, newFileNamePointer, failIfExists); }
            const BOOL kResultValue = gCopyFileAOriginal(existingFileNamePointer, newFileNamePointer, failIfExists);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildTwoPathDetailA(detailBuffer, existingFileNamePointer, newFileNamePointer, failIfExists ? 1 : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CopyFileA", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedCopyFileExW(LPCWSTR existingFileNamePointer, LPCWSTR newFileNamePointer, LPPROGRESS_ROUTINE progressRoutinePointer, LPVOID dataPointer, LPBOOL cancelPointer, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gCopyFileExWOriginal(existingFileNamePointer, newFileNamePointer, progressRoutinePointer, dataPointer, cancelPointer, flagsValue); }
            const BOOL kResultValue = gCopyFileExWOriginal(existingFileNamePointer, newFileNamePointer, progressRoutinePointer, dataPointer, cancelPointer, flagsValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildTwoPathDetailW(detailBuffer, existingFileNamePointer, newFileNamePointer, flagsValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CopyFileExW", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedCopyFileExA(LPCSTR existingFileNamePointer, LPCSTR newFileNamePointer, LPPROGRESS_ROUTINE progressRoutinePointer, LPVOID dataPointer, LPBOOL cancelPointer, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gCopyFileExAOriginal(existingFileNamePointer, newFileNamePointer, progressRoutinePointer, dataPointer, cancelPointer, flagsValue); }
            const BOOL kResultValue = gCopyFileExAOriginal(existingFileNamePointer, newFileNamePointer, progressRoutinePointer, dataPointer, cancelPointer, flagsValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildTwoPathDetailA(detailBuffer, existingFileNamePointer, newFileNamePointer, flagsValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CopyFileExA", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        DWORD WINAPI hookedGetFileAttributesW(LPCWSTR fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gGetFileAttributesWOriginal(fileNamePointer); }
            const DWORD kResultValue = gGetFileAttributesWOriginal(fileNamePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailW(detailBuffer, fileNamePointer, kResultValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetFileAttributesW", kResultValue != INVALID_FILE_ATTRIBUTES ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        DWORD WINAPI hookedGetFileAttributesA(LPCSTR fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gGetFileAttributesAOriginal(fileNamePointer); }
            const DWORD kResultValue = gGetFileAttributesAOriginal(fileNamePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailA(detailBuffer, fileNamePointer, kResultValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetFileAttributesA", kResultValue != INVALID_FILE_ATTRIBUTES ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedGetFileAttributesExW(LPCWSTR fileNamePointer, GET_FILEEX_INFO_LEVELS infoLevelValue, LPVOID fileInformationPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gGetFileAttributesExWOriginal(fileNamePointer, infoLevelValue, fileInformationPointer); }
            const BOOL kResultValue = gGetFileAttributesExWOriginal(fileNamePointer, infoLevelValue, fileInformationPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailW(detailBuffer, fileNamePointer, static_cast<DWORD>(infoLevelValue));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetFileAttributesExW", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedGetFileAttributesExA(LPCSTR fileNamePointer, GET_FILEEX_INFO_LEVELS infoLevelValue, LPVOID fileInformationPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gGetFileAttributesExAOriginal(fileNamePointer, infoLevelValue, fileInformationPointer); }
            const BOOL kResultValue = gGetFileAttributesExAOriginal(fileNamePointer, infoLevelValue, fileInformationPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailA(detailBuffer, fileNamePointer, static_cast<DWORD>(infoLevelValue));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetFileAttributesExA", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedSetFileAttributesW(LPCWSTR fileNamePointer, DWORD fileAttributes)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gSetFileAttributesWOriginal(fileNamePointer, fileAttributes); }
            const BOOL kResultValue = gSetFileAttributesWOriginal(fileNamePointer, fileAttributes);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailW(detailBuffer, fileNamePointer, fileAttributes);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"SetFileAttributesW", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedSetFileAttributesA(LPCSTR fileNamePointer, DWORD fileAttributes)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gSetFileAttributesAOriginal(fileNamePointer, fileAttributes); }
            const BOOL kResultValue = gSetFileAttributesAOriginal(fileNamePointer, fileAttributes);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailA(detailBuffer, fileNamePointer, fileAttributes);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"SetFileAttributesA", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        HANDLE WINAPI hookedFindFirstFileExW(LPCWSTR fileNamePointer, FINDEX_INFO_LEVELS infoLevelValue, LPVOID findFileDataPointer, FINDEX_SEARCH_OPS searchOpValue, LPVOID searchFilterPointer, DWORD additionalFlags)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gFindFirstFileExWOriginal(fileNamePointer, infoLevelValue, findFileDataPointer, searchOpValue, searchFilterPointer, additionalFlags); }
            HANDLE resultHandle = gFindFirstFileExWOriginal(fileNamePointer, infoLevelValue, findFileDataPointer, searchOpValue, searchFilterPointer, additionalFlags);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailW(detailBuffer, fileNamePointer, additionalFlags);
            appendWideText(detailBuffer, L" info=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoLevelValue));
            appendWideText(detailBuffer, L" search=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(searchOpValue));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"FindFirstFileExW", resultHandle != INVALID_HANDLE_VALUE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return resultHandle;
        }

        HANDLE WINAPI hookedFindFirstFileExA(LPCSTR fileNamePointer, FINDEX_INFO_LEVELS infoLevelValue, LPVOID findFileDataPointer, FINDEX_SEARCH_OPS searchOpValue, LPVOID searchFilterPointer, DWORD additionalFlags)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gFindFirstFileExAOriginal(fileNamePointer, infoLevelValue, findFileDataPointer, searchOpValue, searchFilterPointer, additionalFlags); }
            HANDLE resultHandle = gFindFirstFileExAOriginal(fileNamePointer, infoLevelValue, findFileDataPointer, searchOpValue, searchFilterPointer, additionalFlags);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailA(detailBuffer, fileNamePointer, additionalFlags);
            appendWideText(detailBuffer, L" info=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoLevelValue));
            appendWideText(detailBuffer, L" search=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(searchOpValue));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"FindFirstFileExA", resultHandle != INVALID_HANDLE_VALUE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return resultHandle;
        }

        BOOL WINAPI hookedCreateDirectoryW(LPCWSTR pathNamePointer, LPSECURITY_ATTRIBUTES securityAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gCreateDirectoryWOriginal(pathNamePointer, securityAttributesPointer); }
            const BOOL kResultValue = gCreateDirectoryWOriginal(pathNamePointer, securityAttributesPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailW(detailBuffer, pathNamePointer, 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateDirectoryW", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedCreateDirectoryA(LPCSTR pathNamePointer, LPSECURITY_ATTRIBUTES securityAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gCreateDirectoryAOriginal(pathNamePointer, securityAttributesPointer); }
            const BOOL kResultValue = gCreateDirectoryAOriginal(pathNamePointer, securityAttributesPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailA(detailBuffer, pathNamePointer, 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateDirectoryA", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedSetFileInformationByHandle(HANDLE fileHandle, FILE_INFO_BY_HANDLE_CLASS fileInformationClass, LPVOID fileInformationPointer, DWORD bufferSize)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gSetFileInformationByHandleOriginal(fileHandle, fileInformationClass, fileInformationPointer, bufferSize); }
            const BOOL kResultValue = gSetFileInformationByHandleOriginal(fileHandle, fileInformationClass, fileInformationPointer, bufferSize);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            appendWideText(detailBuffer, L" class=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(fileInformationClass));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, bufferSize);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"SetFileInformationByHandle", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedCreateProcessA(LPCSTR applicationNamePointer, LPSTR commandLinePointer, LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles, DWORD creationFlags, LPVOID environmentPointer, LPCSTR currentDirectoryPointer, LPSTARTUPINFOA startupInfoPointer, LPPROCESS_INFORMATION processInfoPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gCreateProcessAOriginal(applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInfoPointer);
            }

            const std::wstring kAppNameText = ansiToWide(applicationNamePointer);
            const std::wstring kCommandLineText = ansiToWide(commandLinePointer);
            const std::wstring kCurrentDirectoryText = ansiToWide(currentDirectoryPointer);
            const BOOL kResultValue = gCreateProcessAOriginal(applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInfoPointer);
            const DWORD kLastError = ::GetLastError();
            const DWORD kChildPid = (kResultValue != FALSE && processInfoPointer != nullptr) ? processInfoPointer->dwProcessId : 0;
            autoInjectChildFromCreateProcessAIfRequested(kResultValue, processInfoPointer);
            sendMonitorEvent(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateProcessA", kResultValue != FALSE ? 0 : static_cast<std::int32_t>(kLastError), trimDetail(L"app=" + kAppNameText + L" cmd=" + kCommandLineText + L" cwd=" + kCurrentDirectoryText + L" flags=" + hexValue(creationFlags) + L" inherit=" + std::to_wstring(inheritHandles != FALSE) + L" childPid=" + std::to_wstring(kChildPid)));
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedCreateProcessW(LPCWSTR applicationNamePointer, LPWSTR commandLinePointer, LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles, DWORD creationFlags, LPVOID environmentPointer, LPCWSTR currentDirectoryPointer, LPSTARTUPINFOW startupInfoPointer, LPPROCESS_INFORMATION processInfoPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gCreateProcessWOriginal(applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInfoPointer);
            }

            const std::wstring kAppNameText = safeWideText(applicationNamePointer);
            const std::wstring kCommandLineText = commandLinePointer != nullptr ? std::wstring(commandLinePointer) : std::wstring();
            const std::wstring kCurrentDirectoryText = safeWideText(currentDirectoryPointer);
            const BOOL kResultValue = gCreateProcessWOriginal(applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInfoPointer);
            const DWORD kLastError = ::GetLastError();
            const DWORD kChildPid = (kResultValue != FALSE && processInfoPointer != nullptr) ? processInfoPointer->dwProcessId : 0;
            autoInjectChildIfRequested(kResultValue, processInfoPointer);
            sendMonitorEvent(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateProcessW", kResultValue != FALSE ? 0 : static_cast<std::int32_t>(kLastError), trimDetail(L"app=" + kAppNameText + L" cmd=" + kCommandLineText + L" cwd=" + kCurrentDirectoryText + L" flags=" + hexValue(creationFlags) + L" inherit=" + std::to_wstring(inheritHandles != FALSE) + L" childPid=" + std::to_wstring(kChildPid)));
            ::SetLastError(kLastError);
            return kResultValue;
        }

        HANDLE WINAPI hookedOpenProcess(DWORD desiredAccess, BOOL inheritHandle, DWORD processId)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gOpenProcessOriginal(desiredAccess, inheritHandle, processId); }
            HANDLE resultHandle = gOpenProcessOriginal(desiredAccess, inheritHandle, processId);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildProcessHandleDetail(detailBuffer, nullptr, desiredAccess, processId, resultHandle);
            appendWideText(detailBuffer, L" inherit=");
            appendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1 : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"OpenProcess", resultHandle != nullptr ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return resultHandle;
        }

        BOOL WINAPI hookedTerminateProcess(HANDLE processHandle, UINT exitCode)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gTerminateProcessOriginal(processHandle, exitCode); }
            const BOOL kResultValue = gTerminateProcessOriginal(processHandle, exitCode);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"process=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            appendWideText(detailBuffer, L" exit=");
            appendUnsignedText(detailBuffer, exitCode);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"TerminateProcess", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        HANDLE WINAPI hookedCreateThread(LPSECURITY_ATTRIBUTES threadAttributesPointer, SIZE_T stackSize, LPTHREAD_START_ROUTINE startAddress, LPVOID parameterPointer, DWORD creationFlags, LPDWORD threadIdPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gCreateThreadOriginal(threadAttributesPointer, stackSize, startAddress, parameterPointer, creationFlags, threadIdPointer); }
            HANDLE resultHandle = gCreateThreadOriginal(threadAttributesPointer, stackSize, startAddress, parameterPointer, creationFlags, threadIdPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"start=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(startAddress));
            appendWideText(detailBuffer, L" param=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parameterPointer));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, creationFlags);
            appendWideText(detailBuffer, L" tid=");
            appendUnsignedText(detailBuffer, threadIdPointer != nullptr ? *threadIdPointer : 0);
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateThread", resultHandle != nullptr ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return resultHandle;
        }

        HANDLE WINAPI hookedCreateRemoteThread(HANDLE processHandle, LPSECURITY_ATTRIBUTES threadAttributesPointer, SIZE_T stackSize, LPTHREAD_START_ROUTINE startAddress, LPVOID parameterPointer, DWORD creationFlags, LPDWORD threadIdPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gCreateRemoteThreadOriginal(processHandle, threadAttributesPointer, stackSize, startAddress, parameterPointer, creationFlags, threadIdPointer); }
            HANDLE resultHandle = gCreateRemoteThreadOriginal(processHandle, threadAttributesPointer, stackSize, startAddress, parameterPointer, creationFlags, threadIdPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"process=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            appendWideText(detailBuffer, L" start=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(startAddress));
            appendWideText(detailBuffer, L" param=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parameterPointer));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, creationFlags);
            appendWideText(detailBuffer, L" tid=");
            appendUnsignedText(detailBuffer, threadIdPointer != nullptr ? *threadIdPointer : 0);
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateRemoteThread", resultHandle != nullptr ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return resultHandle;
        }

        LPVOID WINAPI hookedVirtualAllocEx(HANDLE processHandle, LPVOID addressPointer, SIZE_T sizeValue, DWORD allocationType, DWORD protectValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gVirtualAllocExOriginal(processHandle, addressPointer, sizeValue, allocationType, protectValue); }
            LPVOID resultPointer = gVirtualAllocExOriginal(processHandle, addressPointer, sizeValue, allocationType, protectValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRemoteMemoryDetail(detailBuffer, processHandle, resultPointer != nullptr ? resultPointer : addressPointer, static_cast<std::uint64_t>(sizeValue), allocationType, protectValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"VirtualAllocEx", resultPointer != nullptr ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return resultPointer;
        }

        BOOL WINAPI hookedVirtualFreeEx(HANDLE processHandle, LPVOID addressPointer, SIZE_T sizeValue, DWORD freeType)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gVirtualFreeExOriginal(processHandle, addressPointer, sizeValue, freeType); }
            const BOOL kResultValue = gVirtualFreeExOriginal(processHandle, addressPointer, sizeValue, freeType);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRemoteMemoryDetail(detailBuffer, processHandle, addressPointer, static_cast<std::uint64_t>(sizeValue), freeType, 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"VirtualFreeEx", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedVirtualProtectEx(HANDLE processHandle, LPVOID addressPointer, SIZE_T sizeValue, DWORD newProtect, PDWORD oldProtectPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gVirtualProtectExOriginal(processHandle, addressPointer, sizeValue, newProtect, oldProtectPointer); }
            const BOOL kResultValue = gVirtualProtectExOriginal(processHandle, addressPointer, sizeValue, newProtect, oldProtectPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRemoteMemoryDetail(detailBuffer, processHandle, addressPointer, static_cast<std::uint64_t>(sizeValue), oldProtectPointer != nullptr ? *oldProtectPointer : 0, newProtect);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"VirtualProtectEx", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedWriteProcessMemory(HANDLE processHandle, LPVOID baseAddress, LPCVOID bufferPointer, SIZE_T sizeValue, SIZE_T* bytesWrittenPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gWriteProcessMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesWrittenPointer); }
            const BOOL kResultValue = gWriteProcessMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesWrittenPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRemoteMemoryDetail(detailBuffer, processHandle, baseAddress, static_cast<std::uint64_t>(sizeValue), 0, 0);
            appendWideText(detailBuffer, L" written=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(bytesWrittenPointer != nullptr ? *bytesWrittenPointer : 0));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"WriteProcessMemory", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedReadProcessMemory(HANDLE processHandle, LPCVOID baseAddress, LPVOID bufferPointer, SIZE_T sizeValue, SIZE_T* bytesReadPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gReadProcessMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesReadPointer); }
            const BOOL kResultValue = gReadProcessMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesReadPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRemoteMemoryDetail(detailBuffer, processHandle, baseAddress, static_cast<std::uint64_t>(sizeValue), 0, 0);
            appendWideText(detailBuffer, L" read=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(bytesReadPointer != nullptr ? *bytesReadPointer : 0));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"ReadProcessMemory", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        // hookedOpenThread:
        // - Input: Thread access mask, inherit flag, and thread ID;
        // - Processing: Record thread handle opening to complete the upstream chain for subsequent Suspend/Resume/Context/APC operations.
        // - Returns: the original OpenThread HANDLE and restores the LastError.
        HANDLE WINAPI hookedOpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gOpenThreadOriginal(desiredAccess, inheritHandle, threadId); }
            HANDLE resultHandle = gOpenThreadOriginal(desiredAccess, inheritHandle, threadId);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"tid=");
            appendUnsignedText(detailBuffer, threadId);
            appendWideText(detailBuffer, L" access=");
            appendHexText(detailBuffer, desiredAccess);
            appendWideText(detailBuffer, L" inherit=");
            appendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1 : 0);
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"OpenThread", resultHandle != nullptr ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return resultHandle;
        }

        // hookedSuspendThread:
        // - Input: Target thread handle;
        // - Processing: Record thread suspension operations and original suspension counts, covering common control-plane actions in debugging/injection.
        // - Return: Preserve SuspendThread return value and restore LastError.
        DWORD WINAPI hookedSuspendThread(HANDLE threadHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gSuspendThreadOriginal(threadHandle); }
            const DWORD kResultValue = gSuspendThreadOriginal(threadHandle);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"thread=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            appendWideText(detailBuffer, L" previous=");
            appendUnsignedText(detailBuffer, kResultValue == static_cast<DWORD>(-1) ? 0 : kResultValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"SuspendThread", kResultValue != static_cast<DWORD>(-1) ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        // hookedResumeThread:
        // - Input: Target thread handle;
        // - Processing: Record thread resume operations and original suspend counts;
        // - Return: Preserve ResumeThread return value and restore LastError.
        DWORD WINAPI hookedResumeThread(HANDLE threadHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gResumeThreadOriginal(threadHandle); }
            const DWORD kResultValue = gResumeThreadOriginal(threadHandle);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"thread=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            appendWideText(detailBuffer, L" previous=");
            appendUnsignedText(detailBuffer, kResultValue == static_cast<DWORD>(-1) ? 0 : kResultValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"ResumeThread", kResultValue != static_cast<DWORD>(-1) ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        // hookedQueueUserApc:
        // - Input: APC function address, thread handle, and parameter.
        // - Processing: Record user-mode APC queuing, covering the QueueUserAPC injection path;
        // - Return: preserves the DWORD result of QueueUserAPC and restores LastError.
        DWORD WINAPI hookedQueueUserApc(PAPCFUNC apcRoutinePointer, HANDLE threadHandle, ULONG_PTR dataValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gQueueUserApcOriginal(apcRoutinePointer, threadHandle, dataValue); }
            const DWORD kResultValue = gQueueUserApcOriginal(apcRoutinePointer, threadHandle, dataValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"thread=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            appendWideText(detailBuffer, L" apc=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(apcRoutinePointer));
            appendWideText(detailBuffer, L" data=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(dataValue));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"QueueUserAPC", kResultValue != 0 ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        // hookedGetThreadContext:
        // - Input: thread handle and CONTEXT output buffer;
        // - Processing: Record thread context reads to identify debugging or hijacking pre-conditions.
        // - Returns: preserves the original BOOL result and restores LastError.
        BOOL WINAPI hookedGetThreadContext(HANDLE threadHandle, LPCONTEXT contextPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gGetThreadContextOriginal(threadHandle, contextPointer); }
            const BOOL kResultValue = gGetThreadContextOriginal(threadHandle, contextPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"thread=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, contextPointer != nullptr ? contextPointer->ContextFlags : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"GetThreadContext", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        // hookedSetThreadContext:
        // - Input: thread handle and CONTEXT input buffer;
        // - Processing: Record thread context writes, overriding SetThreadContext injection/hijack paths.
        // - Returns: preserves the original BOOL result and restores LastError.
        BOOL WINAPI hookedSetThreadContext(HANDLE threadHandle, const CONTEXT* contextPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gSetThreadContextOriginal(threadHandle, contextPointer); }
            const BOOL kResultValue = gSetThreadContextOriginal(threadHandle, contextPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"thread=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, contextPointer != nullptr ? contextPointer->ContextFlags : 0);
#if defined(_M_X64)
            appendWideText(detailBuffer, L" rip=");
            appendHexText(detailBuffer, contextPointer != nullptr ? contextPointer->Rip : 0);
#endif
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"SetThreadContext", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        UINT WINAPI hookedWinExec(LPCSTR commandLinePointer, UINT showCommand)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gWinExecOriginal(commandLinePointer, showCommand); }
            const UINT kResultValue = gWinExecOriginal(commandLinePointer, showCommand);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"cmd=");
            appendAnsiText(detailBuffer, commandLinePointer);
            appendWideText(detailBuffer, L" show=");
            appendUnsignedText(detailBuffer, showCommand);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"Kernel32", L"WinExec", kResultValue > 31 ? 0 : kResultValue, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedShellExecuteExW(SHELLEXECUTEINFOW* executeInfoPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gShellExecuteExWOriginal(executeInfoPointer); }
            const BOOL kResultValue = gShellExecuteExWOriginal(executeInfoPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"file=");
            appendWideText(detailBuffer, executeInfoPointer != nullptr ? executeInfoPointer->lpFile : nullptr);
            appendWideText(detailBuffer, L" verb=");
            appendWideText(detailBuffer, executeInfoPointer != nullptr ? executeInfoPointer->lpVerb : nullptr);
            appendWideText(detailBuffer, L" params=");
            appendWideText(detailBuffer, executeInfoPointer != nullptr ? executeInfoPointer->lpParameters : nullptr);
            appendWideText(detailBuffer, L" process=");
            appendHexText(detailBuffer, executeInfoPointer != nullptr ? reinterpret_cast<std::uint64_t>(executeInfoPointer->hProcess) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"Shell32", L"ShellExecuteExW", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOL WINAPI hookedShellExecuteExA(SHELLEXECUTEINFOA* executeInfoPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gShellExecuteExAOriginal(executeInfoPointer); }
            const BOOL kResultValue = gShellExecuteExAOriginal(executeInfoPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"file=");
            appendAnsiText(detailBuffer, executeInfoPointer != nullptr ? executeInfoPointer->lpFile : nullptr);
            appendWideText(detailBuffer, L" verb=");
            appendAnsiText(detailBuffer, executeInfoPointer != nullptr ? executeInfoPointer->lpVerb : nullptr);
            appendWideText(detailBuffer, L" params=");
            appendAnsiText(detailBuffer, executeInfoPointer != nullptr ? executeInfoPointer->lpParameters : nullptr);
            appendWideText(detailBuffer, L" process=");
            appendHexText(detailBuffer, executeInfoPointer != nullptr ? reinterpret_cast<std::uint64_t>(executeInfoPointer->hProcess) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"Shell32", L"ShellExecuteExA", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }


#define APIMON_REG_SEND(ApiName, StatusValue, DetailBuffer) \
        sendMonitorEventRaw(ks::winapi_monitor::EventCategory::kRegistry, L"Advapi32", ApiName, static_cast<std::int32_t>(StatusValue), DetailBuffer)

        LSTATUS WINAPI hookedRegOpenKeyW(HKEY rootKey, LPCWSTR subKeyPointer, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegOpenKeyWOriginal(rootKey, subKeyPointer, resultKeyPointer); }
            const LSTATUS kStatusValue = gRegOpenKeyWOriginal(rootKey, subKeyPointer, resultKeyPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegOpenDetail(detailBuffer, rootKey, subKeyPointer, 0);
            APIMON_REG_SEND(L"RegOpenKeyW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegOpenKeyA(HKEY rootKey, LPCSTR subKeyPointer, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegOpenKeyAOriginal(rootKey, subKeyPointer, resultKeyPointer); }
            const LSTATUS kStatusValue = gRegOpenKeyAOriginal(rootKey, subKeyPointer, resultKeyPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegOpenDetailA(detailBuffer, rootKey, subKeyPointer, 0);
            APIMON_REG_SEND(L"RegOpenKeyA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegOpenKeyExW(HKEY rootKey, LPCWSTR subKeyPointer, DWORD optionsValue, REGSAM samDesired, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegOpenKeyExWOriginal(rootKey, subKeyPointer, optionsValue, samDesired, resultKeyPointer); }
            const LSTATUS kStatusValue = gRegOpenKeyExWOriginal(rootKey, subKeyPointer, optionsValue, samDesired, resultKeyPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegOpenDetail(detailBuffer, rootKey, subKeyPointer, samDesired);
            APIMON_REG_SEND(L"RegOpenKeyExW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegOpenKeyExA(HKEY rootKey, LPCSTR subKeyPointer, DWORD optionsValue, REGSAM samDesired, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegOpenKeyExAOriginal(rootKey, subKeyPointer, optionsValue, samDesired, resultKeyPointer); }
            const LSTATUS kStatusValue = gRegOpenKeyExAOriginal(rootKey, subKeyPointer, optionsValue, samDesired, resultKeyPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegOpenDetailA(detailBuffer, rootKey, subKeyPointer, samDesired);
            APIMON_REG_SEND(L"RegOpenKeyExA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegCreateKeyW(HKEY rootKey, LPCWSTR subKeyPointer, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegCreateKeyWOriginal(rootKey, subKeyPointer, resultKeyPointer); }
            const LSTATUS kStatusValue = gRegCreateKeyWOriginal(rootKey, subKeyPointer, resultKeyPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegCreateDetail(detailBuffer, rootKey, subKeyPointer, 0, 0);
            APIMON_REG_SEND(L"RegCreateKeyW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegCreateKeyA(HKEY rootKey, LPCSTR subKeyPointer, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegCreateKeyAOriginal(rootKey, subKeyPointer, resultKeyPointer); }
            const LSTATUS kStatusValue = gRegCreateKeyAOriginal(rootKey, subKeyPointer, resultKeyPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegCreateDetailA(detailBuffer, rootKey, subKeyPointer, 0, 0);
            APIMON_REG_SEND(L"RegCreateKeyA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegCreateKeyExW(HKEY rootKey, LPCWSTR subKeyPointer, DWORD reservedValue, LPWSTR classPointer, DWORD optionsValue, REGSAM samDesired, const LPSECURITY_ATTRIBUTES securityAttributes, PHKEY resultKeyPointer, LPDWORD dispositionPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegCreateKeyExWOriginal(rootKey, subKeyPointer, reservedValue, classPointer, optionsValue, samDesired, securityAttributes, resultKeyPointer, dispositionPointer); }
            const LSTATUS kStatusValue = gRegCreateKeyExWOriginal(rootKey, subKeyPointer, reservedValue, classPointer, optionsValue, samDesired, securityAttributes, resultKeyPointer, dispositionPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegCreateDetail(detailBuffer, rootKey, subKeyPointer, optionsValue, dispositionPointer != nullptr ? *dispositionPointer : 0);
            APIMON_REG_SEND(L"RegCreateKeyExW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegCreateKeyExA(HKEY rootKey, LPCSTR subKeyPointer, DWORD reservedValue, LPSTR classPointer, DWORD optionsValue, REGSAM samDesired, const LPSECURITY_ATTRIBUTES securityAttributes, PHKEY resultKeyPointer, LPDWORD dispositionPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegCreateKeyExAOriginal(rootKey, subKeyPointer, reservedValue, classPointer, optionsValue, samDesired, securityAttributes, resultKeyPointer, dispositionPointer); }
            const LSTATUS kStatusValue = gRegCreateKeyExAOriginal(rootKey, subKeyPointer, reservedValue, classPointer, optionsValue, samDesired, securityAttributes, resultKeyPointer, dispositionPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegCreateDetailA(detailBuffer, rootKey, subKeyPointer, optionsValue, dispositionPointer != nullptr ? *dispositionPointer : 0);
            APIMON_REG_SEND(L"RegCreateKeyExA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegQueryValueExW(HKEY keyHandle, LPCWSTR valueNamePointer, LPDWORD reservedPointer, LPDWORD typePointer, LPBYTE dataPointer, LPDWORD dataSizePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegQueryValueExWOriginal(keyHandle, valueNamePointer, reservedPointer, typePointer, dataPointer, dataSizePointer); }
            const LSTATUS kStatusValue = gRegQueryValueExWOriginal(keyHandle, valueNamePointer, reservedPointer, typePointer, dataPointer, dataSizePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegValueDetail(detailBuffer, L"hkey=", keyHandle, valueNamePointer, typePointer != nullptr ? *typePointer : 0, dataSizePointer != nullptr ? *dataSizePointer : 0);
            APIMON_REG_SEND(L"RegQueryValueExW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegQueryValueExA(HKEY keyHandle, LPCSTR valueNamePointer, LPDWORD reservedPointer, LPDWORD typePointer, LPBYTE dataPointer, LPDWORD dataSizePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegQueryValueExAOriginal(keyHandle, valueNamePointer, reservedPointer, typePointer, dataPointer, dataSizePointer); }
            const LSTATUS kStatusValue = gRegQueryValueExAOriginal(keyHandle, valueNamePointer, reservedPointer, typePointer, dataPointer, dataSizePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegValueDetailA(detailBuffer, L"hkey=", keyHandle, valueNamePointer, typePointer != nullptr ? *typePointer : 0, dataSizePointer != nullptr ? *dataSizePointer : 0);
            APIMON_REG_SEND(L"RegQueryValueExA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegGetValueW(HKEY keyHandle, LPCWSTR subKeyPointer, LPCWSTR valueNamePointer, DWORD flagsValue, LPDWORD typePointer, PVOID dataPointer, LPDWORD dataSizePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegGetValueWOriginal(keyHandle, subKeyPointer, valueNamePointer, flagsValue, typePointer, dataPointer, dataSizePointer); }
            const LSTATUS kStatusValue = gRegGetValueWOriginal(keyHandle, subKeyPointer, valueNamePointer, flagsValue, typePointer, dataPointer, dataSizePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegGetValueDetail(detailBuffer, keyHandle, subKeyPointer, valueNamePointer, flagsValue, typePointer != nullptr ? *typePointer : 0, dataSizePointer != nullptr ? *dataSizePointer : 0);
            APIMON_REG_SEND(L"RegGetValueW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegGetValueA(HKEY keyHandle, LPCSTR subKeyPointer, LPCSTR valueNamePointer, DWORD flagsValue, LPDWORD typePointer, PVOID dataPointer, LPDWORD dataSizePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegGetValueAOriginal(keyHandle, subKeyPointer, valueNamePointer, flagsValue, typePointer, dataPointer, dataSizePointer); }
            const LSTATUS kStatusValue = gRegGetValueAOriginal(keyHandle, subKeyPointer, valueNamePointer, flagsValue, typePointer, dataPointer, dataSizePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegGetValueDetailA(detailBuffer, keyHandle, subKeyPointer, valueNamePointer, flagsValue, typePointer != nullptr ? *typePointer : 0, dataSizePointer != nullptr ? *dataSizePointer : 0);
            APIMON_REG_SEND(L"RegGetValueA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegSetValueExW(HKEY keyHandle, LPCWSTR valueNamePointer, DWORD reservedValue, DWORD typeValue, const BYTE* dataPointer, DWORD dataSize)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegSetValueExWOriginal(keyHandle, valueNamePointer, reservedValue, typeValue, dataPointer, dataSize); }
            const LSTATUS kStatusValue = gRegSetValueExWOriginal(keyHandle, valueNamePointer, reservedValue, typeValue, dataPointer, dataSize);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegSetValueDetail(detailBuffer, keyHandle, valueNamePointer, typeValue, dataSize);
            APIMON_REG_SEND(L"RegSetValueExW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegSetValueExA(HKEY keyHandle, LPCSTR valueNamePointer, DWORD reservedValue, DWORD typeValue, const BYTE* dataPointer, DWORD dataSize)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegSetValueExAOriginal(keyHandle, valueNamePointer, reservedValue, typeValue, dataPointer, dataSize); }
            const LSTATUS kStatusValue = gRegSetValueExAOriginal(keyHandle, valueNamePointer, reservedValue, typeValue, dataPointer, dataSize);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegSetValueDetailA(detailBuffer, keyHandle, valueNamePointer, typeValue, dataSize);
            APIMON_REG_SEND(L"RegSetValueExA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegSetKeyValueW(HKEY keyHandle, LPCWSTR subKeyPointer, LPCWSTR valueNamePointer, DWORD typeValue, const void* dataPointer, DWORD dataSize)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegSetKeyValueWOriginal(keyHandle, subKeyPointer, valueNamePointer, typeValue, dataPointer, dataSize); }
            const LSTATUS kStatusValue = gRegSetKeyValueWOriginal(keyHandle, subKeyPointer, valueNamePointer, typeValue, dataPointer, dataSize);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegGetValueDetail(detailBuffer, keyHandle, subKeyPointer, valueNamePointer, 0, typeValue, dataSize);
            APIMON_REG_SEND(L"RegSetKeyValueW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegSetKeyValueA(HKEY keyHandle, LPCSTR subKeyPointer, LPCSTR valueNamePointer, DWORD typeValue, const void* dataPointer, DWORD dataSize)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegSetKeyValueAOriginal(keyHandle, subKeyPointer, valueNamePointer, typeValue, dataPointer, dataSize); }
            const LSTATUS kStatusValue = gRegSetKeyValueAOriginal(keyHandle, subKeyPointer, valueNamePointer, typeValue, dataPointer, dataSize);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegGetValueDetailA(detailBuffer, keyHandle, subKeyPointer, valueNamePointer, 0, typeValue, dataSize);
            APIMON_REG_SEND(L"RegSetKeyValueA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegDeleteValueW(HKEY keyHandle, LPCWSTR valueNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegDeleteValueWOriginal(keyHandle, valueNamePointer); }
            const LSTATUS kStatusValue = gRegDeleteValueWOriginal(keyHandle, valueNamePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegValueDetail(detailBuffer, L"hkey=", keyHandle, valueNamePointer, 0, 0);
            APIMON_REG_SEND(L"RegDeleteValueW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegDeleteValueA(HKEY keyHandle, LPCSTR valueNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegDeleteValueAOriginal(keyHandle, valueNamePointer); }
            const LSTATUS kStatusValue = gRegDeleteValueAOriginal(keyHandle, valueNamePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegValueDetailA(detailBuffer, L"hkey=", keyHandle, valueNamePointer, 0, 0);
            APIMON_REG_SEND(L"RegDeleteValueA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegDeleteKeyW(HKEY rootKey, LPCWSTR subKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegDeleteKeyWOriginal(rootKey, subKeyPointer); }
            const LSTATUS kStatusValue = gRegDeleteKeyWOriginal(rootKey, subKeyPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, 0);
            APIMON_REG_SEND(L"RegDeleteKeyW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegDeleteKeyA(HKEY rootKey, LPCSTR subKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegDeleteKeyAOriginal(rootKey, subKeyPointer); }
            const LSTATUS kStatusValue = gRegDeleteKeyAOriginal(rootKey, subKeyPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, 0);
            APIMON_REG_SEND(L"RegDeleteKeyA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegDeleteKeyExW(HKEY rootKey, LPCWSTR subKeyPointer, REGSAM samDesired, DWORD reservedValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegDeleteKeyExWOriginal(rootKey, subKeyPointer, samDesired, reservedValue); }
            const LSTATUS kStatusValue = gRegDeleteKeyExWOriginal(rootKey, subKeyPointer, samDesired, reservedValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, samDesired);
            APIMON_REG_SEND(L"RegDeleteKeyExW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegDeleteKeyExA(HKEY rootKey, LPCSTR subKeyPointer, REGSAM samDesired, DWORD reservedValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegDeleteKeyExAOriginal(rootKey, subKeyPointer, samDesired, reservedValue); }
            const LSTATUS kStatusValue = gRegDeleteKeyExAOriginal(rootKey, subKeyPointer, samDesired, reservedValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, samDesired);
            APIMON_REG_SEND(L"RegDeleteKeyExA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegDeleteTreeW(HKEY rootKey, LPCWSTR subKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegDeleteTreeWOriginal(rootKey, subKeyPointer); }
            const LSTATUS kStatusValue = gRegDeleteTreeWOriginal(rootKey, subKeyPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, 0);
            APIMON_REG_SEND(L"RegDeleteTreeW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegDeleteTreeA(HKEY rootKey, LPCSTR subKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegDeleteTreeAOriginal(rootKey, subKeyPointer); }
            const LSTATUS kStatusValue = gRegDeleteTreeAOriginal(rootKey, subKeyPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, 0);
            APIMON_REG_SEND(L"RegDeleteTreeA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegCopyTreeW(HKEY rootKey, LPCWSTR subKeyPointer, HKEY destKey)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegCopyTreeWOriginal(rootKey, subKeyPointer, destKey); }
            const LSTATUS kStatusValue = gRegCopyTreeWOriginal(rootKey, subKeyPointer, destKey);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, 0);
            appendWideText(detailBuffer, L" dest=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(destKey));
            APIMON_REG_SEND(L"RegCopyTreeW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegCopyTreeA(HKEY rootKey, LPCSTR subKeyPointer, HKEY destKey)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegCopyTreeAOriginal(rootKey, subKeyPointer, destKey); }
            const LSTATUS kStatusValue = gRegCopyTreeAOriginal(rootKey, subKeyPointer, destKey);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, 0);
            appendWideText(detailBuffer, L" dest=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(destKey));
            APIMON_REG_SEND(L"RegCopyTreeA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegLoadKeyW(HKEY rootKey, LPCWSTR subKeyPointer, LPCWSTR fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegLoadKeyWOriginal(rootKey, subKeyPointer, fileNamePointer); }
            const LSTATUS kStatusValue = gRegLoadKeyWOriginal(rootKey, subKeyPointer, fileNamePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, 0);
            appendWideText(detailBuffer, L" file=");
            appendWideText(detailBuffer, fileNamePointer);
            APIMON_REG_SEND(L"RegLoadKeyW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegLoadKeyA(HKEY rootKey, LPCSTR subKeyPointer, LPCSTR fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegLoadKeyAOriginal(rootKey, subKeyPointer, fileNamePointer); }
            const LSTATUS kStatusValue = gRegLoadKeyAOriginal(rootKey, subKeyPointer, fileNamePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, 0);
            appendWideText(detailBuffer, L" file=");
            appendAnsiText(detailBuffer, fileNamePointer);
            APIMON_REG_SEND(L"RegLoadKeyA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegSaveKeyW(HKEY keyHandle, LPCWSTR fileNamePointer, const LPSECURITY_ATTRIBUTES securityAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegSaveKeyWOriginal(keyHandle, fileNamePointer, securityAttributesPointer); }
            const LSTATUS kStatusValue = gRegSaveKeyWOriginal(keyHandle, fileNamePointer, securityAttributesPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" file=");
            appendWideText(detailBuffer, fileNamePointer);
            APIMON_REG_SEND(L"RegSaveKeyW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegSaveKeyA(HKEY keyHandle, LPCSTR fileNamePointer, const LPSECURITY_ATTRIBUTES securityAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegSaveKeyAOriginal(keyHandle, fileNamePointer, securityAttributesPointer); }
            const LSTATUS kStatusValue = gRegSaveKeyAOriginal(keyHandle, fileNamePointer, securityAttributesPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" file=");
            appendAnsiText(detailBuffer, fileNamePointer);
            APIMON_REG_SEND(L"RegSaveKeyA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegRenameKey(HKEY keyHandle, LPCWSTR subKeyPointer, LPCWSTR newNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegRenameKeyOriginal(keyHandle, subKeyPointer, newNamePointer); }
            const LSTATUS kStatusValue = gRegRenameKeyOriginal(keyHandle, subKeyPointer, newNamePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" subkey=");
            appendWideText(detailBuffer, subKeyPointer);
            appendWideText(detailBuffer, L" new=");
            appendWideText(detailBuffer, newNamePointer);
            APIMON_REG_SEND(L"RegRenameKey", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegEnumKeyExW(HKEY keyHandle, DWORD indexValue, LPWSTR namePointer, LPDWORD nameLengthPointer, LPDWORD reservedPointer, LPWSTR classPointer, LPDWORD classLengthPointer, PFILETIME lastWriteTimePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegEnumKeyExWOriginal(keyHandle, indexValue, namePointer, nameLengthPointer, reservedPointer, classPointer, classLengthPointer, lastWriteTimePointer); }
            const LSTATUS kStatusValue = gRegEnumKeyExWOriginal(keyHandle, indexValue, namePointer, nameLengthPointer, reservedPointer, classPointer, classLengthPointer, lastWriteTimePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegEnumKeyDetail(detailBuffer, keyHandle, indexValue, kStatusValue == ERROR_SUCCESS ? namePointer : nullptr, kStatusValue == ERROR_SUCCESS && nameLengthPointer != nullptr ? *nameLengthPointer : 0);
            APIMON_REG_SEND(L"RegEnumKeyExW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegEnumKeyExA(HKEY keyHandle, DWORD indexValue, LPSTR namePointer, LPDWORD nameLengthPointer, LPDWORD reservedPointer, LPSTR classPointer, LPDWORD classLengthPointer, PFILETIME lastWriteTimePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegEnumKeyExAOriginal(keyHandle, indexValue, namePointer, nameLengthPointer, reservedPointer, classPointer, classLengthPointer, lastWriteTimePointer); }
            const LSTATUS kStatusValue = gRegEnumKeyExAOriginal(keyHandle, indexValue, namePointer, nameLengthPointer, reservedPointer, classPointer, classLengthPointer, lastWriteTimePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegEnumKeyDetailA(detailBuffer, keyHandle, indexValue, kStatusValue == ERROR_SUCCESS ? namePointer : nullptr, kStatusValue == ERROR_SUCCESS && nameLengthPointer != nullptr ? *nameLengthPointer : 0);
            APIMON_REG_SEND(L"RegEnumKeyExA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegEnumValueW(HKEY keyHandle, DWORD indexValue, LPWSTR valueNamePointer, LPDWORD valueNameLengthPointer, LPDWORD reservedPointer, LPDWORD typePointer, LPBYTE dataPointer, LPDWORD dataSizePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegEnumValueWOriginal(keyHandle, indexValue, valueNamePointer, valueNameLengthPointer, reservedPointer, typePointer, dataPointer, dataSizePointer); }
            const LSTATUS kStatusValue = gRegEnumValueWOriginal(keyHandle, indexValue, valueNamePointer, valueNameLengthPointer, reservedPointer, typePointer, dataPointer, dataSizePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegValueDetail(detailBuffer, L"hkey=", keyHandle, kStatusValue == ERROR_SUCCESS ? valueNamePointer : nullptr, typePointer != nullptr ? *typePointer : 0, dataSizePointer != nullptr ? *dataSizePointer : 0);
            appendWideText(detailBuffer, L" index=");
            appendUnsignedText(detailBuffer, indexValue);
            APIMON_REG_SEND(L"RegEnumValueW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegEnumValueA(HKEY keyHandle, DWORD indexValue, LPSTR valueNamePointer, LPDWORD valueNameLengthPointer, LPDWORD reservedPointer, LPDWORD typePointer, LPBYTE dataPointer, LPDWORD dataSizePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegEnumValueAOriginal(keyHandle, indexValue, valueNamePointer, valueNameLengthPointer, reservedPointer, typePointer, dataPointer, dataSizePointer); }
            const LSTATUS kStatusValue = gRegEnumValueAOriginal(keyHandle, indexValue, valueNamePointer, valueNameLengthPointer, reservedPointer, typePointer, dataPointer, dataSizePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegValueDetailA(detailBuffer, L"hkey=", keyHandle, kStatusValue == ERROR_SUCCESS ? valueNamePointer : nullptr, typePointer != nullptr ? *typePointer : 0, dataSizePointer != nullptr ? *dataSizePointer : 0);
            appendWideText(detailBuffer, L" index=");
            appendUnsignedText(detailBuffer, indexValue);
            APIMON_REG_SEND(L"RegEnumValueA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        LSTATUS WINAPI hookedRegCloseKey(HKEY keyHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegCloseKeyOriginal(keyHandle); }
            const LSTATUS kStatusValue = gRegCloseKeyOriginal(keyHandle);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            APIMON_REG_SEND(L"RegCloseKey", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        // hookedRegQueryInfoKeyW:
        // - Input: Registry key handle and statistics output buffer.
        // - Processing: Log subkey/value count queries to complete enumeration of registry API coverage.
        // - Return: Preserve the LSTATUS of RegQueryInfoKeyW and restore LastError.
        LSTATUS WINAPI hookedRegQueryInfoKeyW(
            HKEY keyHandle,
            LPWSTR classPointer,
            LPDWORD classLengthPointer,
            LPDWORD reservedPointer,
            LPDWORD subKeyCountPointer,
            LPDWORD maxSubKeyLengthPointer,
            LPDWORD maxClassLengthPointer,
            LPDWORD valueCountPointer,
            LPDWORD maxValueNameLengthPointer,
            LPDWORD maxValueLengthPointer,
            LPDWORD securityDescriptorLengthPointer,
            PFILETIME lastWriteTimePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gRegQueryInfoKeyWOriginal(keyHandle, classPointer, classLengthPointer, reservedPointer, subKeyCountPointer, maxSubKeyLengthPointer, maxClassLengthPointer, valueCountPointer, maxValueNameLengthPointer, maxValueLengthPointer, securityDescriptorLengthPointer, lastWriteTimePointer);
            }

            const LSTATUS kStatusValue = gRegQueryInfoKeyWOriginal(keyHandle, classPointer, classLengthPointer, reservedPointer, subKeyCountPointer, maxSubKeyLengthPointer, maxClassLengthPointer, valueCountPointer, maxValueNameLengthPointer, maxValueLengthPointer, securityDescriptorLengthPointer, lastWriteTimePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" subKeys=");
            appendUnsignedText(detailBuffer, subKeyCountPointer != nullptr ? *subKeyCountPointer : 0);
            appendWideText(detailBuffer, L" values=");
            appendUnsignedText(detailBuffer, valueCountPointer != nullptr ? *valueCountPointer : 0);
            APIMON_REG_SEND(L"RegQueryInfoKeyW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        // hookedRegQueryInfoKeyA:
        // - Input: ANSI version RegQueryInfoKey parameters;
        // - Processing: Log key statistics query results.
        // - Return: Preserve the original LSTATUS and restore LastError.
        LSTATUS WINAPI hookedRegQueryInfoKeyA(
            HKEY keyHandle,
            LPSTR classPointer,
            LPDWORD classLengthPointer,
            LPDWORD reservedPointer,
            LPDWORD subKeyCountPointer,
            LPDWORD maxSubKeyLengthPointer,
            LPDWORD maxClassLengthPointer,
            LPDWORD valueCountPointer,
            LPDWORD maxValueNameLengthPointer,
            LPDWORD maxValueLengthPointer,
            LPDWORD securityDescriptorLengthPointer,
            PFILETIME lastWriteTimePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gRegQueryInfoKeyAOriginal(keyHandle, classPointer, classLengthPointer, reservedPointer, subKeyCountPointer, maxSubKeyLengthPointer, maxClassLengthPointer, valueCountPointer, maxValueNameLengthPointer, maxValueLengthPointer, securityDescriptorLengthPointer, lastWriteTimePointer);
            }

            const LSTATUS kStatusValue = gRegQueryInfoKeyAOriginal(keyHandle, classPointer, classLengthPointer, reservedPointer, subKeyCountPointer, maxSubKeyLengthPointer, maxClassLengthPointer, valueCountPointer, maxValueNameLengthPointer, maxValueLengthPointer, securityDescriptorLengthPointer, lastWriteTimePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" subKeys=");
            appendUnsignedText(detailBuffer, subKeyCountPointer != nullptr ? *subKeyCountPointer : 0);
            appendWideText(detailBuffer, L" values=");
            appendUnsignedText(detailBuffer, valueCountPointer != nullptr ? *valueCountPointer : 0);
            APIMON_REG_SEND(L"RegQueryInfoKeyA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        // hookedRegFlushKey:
        // - Input: Registry key handle;
        // - Handling: Record forced flush operations, a behavior often used for persistence confirmation.
        // - Returns: The LSTATUS from RegFlushKey and restores the LastError.
        LSTATUS WINAPI hookedRegFlushKey(HKEY keyHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegFlushKeyOriginal(keyHandle); }
            const LSTATUS kStatusValue = gRegFlushKeyOriginal(keyHandle);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            APIMON_REG_SEND(L"RegFlushKey", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        // hookedRegDeleteKeyValueW:
        // - Input: key handle, optional subkey and value name;
        // - Processing: Record the combined RegDeleteKeyValue API to fill the gap between RegDeleteValue and RegDeleteTree events;
        // - Return: Preserve the original LSTATUS and restore LastError.
        LSTATUS WINAPI hookedRegDeleteKeyValueW(HKEY keyHandle, LPCWSTR subKeyPointer, LPCWSTR valueNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegDeleteKeyValueWOriginal(keyHandle, subKeyPointer, valueNamePointer); }
            const LSTATUS kStatusValue = gRegDeleteKeyValueWOriginal(keyHandle, subKeyPointer, valueNamePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegValueDetail(detailBuffer, L"hkey=", keyHandle, valueNamePointer, 0, 0);
            appendWideText(detailBuffer, L" sub=");
            appendWideText(detailBuffer, subKeyPointer);
            APIMON_REG_SEND(L"RegDeleteKeyValueW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        // hookedRegDeleteKeyValueA:
        // - Input: ANSI version key handle, optional subkey, and value name.
        // - Processing: Record the combined DeleteKeyValue API.
        // - Return: Preserve the original LSTATUS and restore LastError.
        LSTATUS WINAPI hookedRegDeleteKeyValueA(HKEY keyHandle, LPCSTR subKeyPointer, LPCSTR valueNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegDeleteKeyValueAOriginal(keyHandle, subKeyPointer, valueNamePointer); }
            const LSTATUS kStatusValue = gRegDeleteKeyValueAOriginal(keyHandle, subKeyPointer, valueNamePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRegValueDetailA(detailBuffer, L"hkey=", keyHandle, valueNamePointer, 0, 0);
            appendWideText(detailBuffer, L" sub=");
            appendAnsiText(detailBuffer, subKeyPointer);
            APIMON_REG_SEND(L"RegDeleteKeyValueA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        // hookedRegConnectRegistryW:
        // - Input: remote machine name, root key, and result handle pointer;
        // - Processing: Log remote registry connection behavior.
        // - Return: Preserve the original LSTATUS and restore LastError.
        LSTATUS WINAPI hookedRegConnectRegistryW(LPCWSTR machineNamePointer, HKEY rootKey, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegConnectRegistryWOriginal(machineNamePointer, rootKey, resultKeyPointer); }
            const LSTATUS kStatusValue = gRegConnectRegistryWOriginal(machineNamePointer, rootKey, resultKeyPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"machine=");
            appendWideText(detailBuffer, machineNamePointer);
            appendWideText(detailBuffer, L" root=");
            appendRegistryRootText(detailBuffer, rootKey);
            appendWideText(detailBuffer, L" result=");
            appendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0);
            APIMON_REG_SEND(L"RegConnectRegistryW", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        // hookedRegConnectRegistryA:
        // - Input: ANSI version remote machine name, root key, and result handle pointer;
        // - Processing: Log remote registry connection behavior.
        // - Return: Preserve the original LSTATUS and restore LastError.
        LSTATUS WINAPI hookedRegConnectRegistryA(LPCSTR machineNamePointer, HKEY rootKey, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gRegConnectRegistryAOriginal(machineNamePointer, rootKey, resultKeyPointer); }
            const LSTATUS kStatusValue = gRegConnectRegistryAOriginal(machineNamePointer, rootKey, resultKeyPointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"machine=");
            appendAnsiText(detailBuffer, machineNamePointer);
            appendWideText(detailBuffer, L" root=");
            appendRegistryRootText(detailBuffer, rootKey);
            appendWideText(detailBuffer, L" result=");
            appendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0);
            APIMON_REG_SEND(L"RegConnectRegistryA", kStatusValue, detailBuffer);
            ::SetLastError(kLastError);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtCreateFile(PHANDLE fileHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, PIO_STATUS_BLOCK ioStatusBlockPointer, PLARGE_INTEGER allocationSizePointer, ULONG fileAttributes, ULONG shareAccess, ULONG createDisposition, ULONG createOptions, PVOID eaBufferPointer, ULONG eaLength)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtCreateFileOriginal(fileHandlePointer, desiredAccess, objectAttributesPointer, ioStatusBlockPointer, allocationSizePointer, fileAttributes, shareAccess, createDisposition, createOptions, eaBufferPointer, eaLength); }
            const NTSTATUS kStatusValue = gNtCreateFileOriginal(fileHandlePointer, desiredAccess, objectAttributesPointer, ioStatusBlockPointer, allocationSizePointer, fileAttributes, shareAccess, createDisposition, createOptions, eaBufferPointer, eaLength);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildNtObjectPathDetail(detailBuffer, objectAttributesPointer, desiredAccess, shareAccess, createDisposition, createOptions);
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, fileHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*fileHandlePointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtCreateFile", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtOpenFile(PHANDLE fileHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, PIO_STATUS_BLOCK ioStatusBlockPointer, ULONG shareAccess, ULONG openOptions)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtOpenFileOriginal(fileHandlePointer, desiredAccess, objectAttributesPointer, ioStatusBlockPointer, shareAccess, openOptions); }
            const NTSTATUS kStatusValue = gNtOpenFileOriginal(fileHandlePointer, desiredAccess, objectAttributesPointer, ioStatusBlockPointer, shareAccess, openOptions);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildNtObjectPathDetail(detailBuffer, objectAttributesPointer, desiredAccess, shareAccess, 0, openOptions);
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, fileHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*fileHandlePointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtOpenFile", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtReadFile(HANDLE fileHandle, HANDLE eventHandle, KsIoApcRoutine apcRoutinePointer, PVOID apcContextPointer, PIO_STATUS_BLOCK ioStatusBlockPointer, PVOID bufferPointer, ULONG lengthValue, PLARGE_INTEGER byteOffsetPointer, PULONG keyPointer)
        {
            if (isMonitorPipeHandle(fileHandle))
            {
                return gNtReadFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, bufferPointer, lengthValue, byteOffsetPointer, keyPointer);
            }
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtReadFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, bufferPointer, lengthValue, byteOffsetPointer, keyPointer); }
            const NTSTATUS kStatusValue = gNtReadFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, bufferPointer, lengthValue, byteOffsetPointer, keyPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildHandleTransferDetail(detailBuffer, fileHandle, lengthValue, ioStatusBlockPointer != nullptr ? static_cast<unsigned long long>(ioStatusBlockPointer->Information) : 0, byteOffsetPointer);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtReadFile", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtWriteFile(HANDLE fileHandle, HANDLE eventHandle, KsIoApcRoutine apcRoutinePointer, PVOID apcContextPointer, PIO_STATUS_BLOCK ioStatusBlockPointer, PVOID bufferPointer, ULONG lengthValue, PLARGE_INTEGER byteOffsetPointer, PULONG keyPointer)
        {
            if (isMonitorPipeHandle(fileHandle))
            {
                return gNtWriteFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, bufferPointer, lengthValue, byteOffsetPointer, keyPointer);
            }
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtWriteFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, bufferPointer, lengthValue, byteOffsetPointer, keyPointer); }
            const NTSTATUS kStatusValue = gNtWriteFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, bufferPointer, lengthValue, byteOffsetPointer, keyPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildHandleTransferDetail(detailBuffer, fileHandle, lengthValue, ioStatusBlockPointer != nullptr ? static_cast<unsigned long long>(ioStatusBlockPointer->Information) : 0, byteOffsetPointer);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtWriteFile", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtSetInformationFile(HANDLE fileHandle, PIO_STATUS_BLOCK ioStatusBlockPointer, PVOID fileInformationPointer, ULONG lengthValue, KsFileInformationClass fileInformationClass)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtSetInformationFileOriginal(fileHandle, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass); }
            const NTSTATUS kStatusValue = gNtSetInformationFileOriginal(fileHandle, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            appendWideText(detailBuffer, L" class=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(fileInformationClass));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, lengthValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtSetInformationFile", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtQueryInformationFile(HANDLE fileHandle, PIO_STATUS_BLOCK ioStatusBlockPointer, PVOID fileInformationPointer, ULONG lengthValue, KsFileInformationClass fileInformationClass)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtQueryInformationFileOriginal(fileHandle, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass); }
            const NTSTATUS kStatusValue = gNtQueryInformationFileOriginal(fileHandle, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            appendWideText(detailBuffer, L" class=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(fileInformationClass));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, lengthValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtQueryInformationFile", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtDeleteFile(POBJECT_ATTRIBUTES objectAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtDeleteFileOriginal(objectAttributesPointer); }
            const NTSTATUS kStatusValue = gNtDeleteFileOriginal(objectAttributesPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildNtObjectPathDetail(detailBuffer, objectAttributesPointer, 0, 0, 0, 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtDeleteFile", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtQueryAttributesFile(POBJECT_ATTRIBUTES objectAttributesPointer, PVOID fileInformationPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtQueryAttributesFileOriginal(objectAttributesPointer, fileInformationPointer); }
            const NTSTATUS kStatusValue = gNtQueryAttributesFileOriginal(objectAttributesPointer, fileInformationPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildNtObjectPathDetail(detailBuffer, objectAttributesPointer, 0, 0, 0, 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtQueryAttributesFile", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtQueryFullAttributesFile(POBJECT_ATTRIBUTES objectAttributesPointer, PVOID fileInformationPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtQueryFullAttributesFileOriginal(objectAttributesPointer, fileInformationPointer); }
            const NTSTATUS kStatusValue = gNtQueryFullAttributesFileOriginal(objectAttributesPointer, fileInformationPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildNtObjectPathDetail(detailBuffer, objectAttributesPointer, 0, 0, 0, 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtQueryFullAttributesFile", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtDeviceIoControlFile:
        // - Input: File/device handle, event/APC, IO_STATUS_BLOCK, control code, and buffer length.
        // - Processing: Log direct ntdll device control calls to bypass the KernelBase DeviceIoControl path.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtDeviceIoControlFile(
            HANDLE fileHandle,
            HANDLE eventHandle,
            KsIoApcRoutine apcRoutinePointer,
            PVOID apcContextPointer,
            PIO_STATUS_BLOCK ioStatusBlockPointer,
            ULONG ioControlCode,
            PVOID inputBufferPointer,
            ULONG inputBufferLength,
            PVOID outputBufferPointer,
            ULONG outputBufferLength)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gNtDeviceIoControlFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, ioControlCode, inputBufferPointer, inputBufferLength, outputBufferPointer, outputBufferLength);
            }

            const NTSTATUS kStatusValue = gNtDeviceIoControlFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, ioControlCode, inputBufferPointer, inputBufferLength, outputBufferPointer, outputBufferLength);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            appendWideText(detailBuffer, L" code=");
            appendHexText(detailBuffer, ioControlCode);
            appendWideText(detailBuffer, L" in=");
            appendUnsignedText(detailBuffer, inputBufferLength);
            appendWideText(detailBuffer, L" out=");
            appendUnsignedText(detailBuffer, outputBufferLength);
            appendWideText(detailBuffer, L" info=");
            appendUnsignedText(detailBuffer, ioStatusBlockPointer != nullptr ? static_cast<unsigned long long>(ioStatusBlockPointer->Information) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtDeviceIoControlFile", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtFsControlFile:
        // - Input: File handle, control code, and buffer length;
        // - Processing: Log file system control calls, such as reparse points, volume control, and pipe control.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtFsControlFile(
            HANDLE fileHandle,
            HANDLE eventHandle,
            KsIoApcRoutine apcRoutinePointer,
            PVOID apcContextPointer,
            PIO_STATUS_BLOCK ioStatusBlockPointer,
            ULONG fsControlCode,
            PVOID inputBufferPointer,
            ULONG inputBufferLength,
            PVOID outputBufferPointer,
            ULONG outputBufferLength)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gNtFsControlFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, fsControlCode, inputBufferPointer, inputBufferLength, outputBufferPointer, outputBufferLength);
            }

            const NTSTATUS kStatusValue = gNtFsControlFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, fsControlCode, inputBufferPointer, inputBufferLength, outputBufferPointer, outputBufferLength);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"fsctlName=");
            appendWideText(detailBuffer, fsctlCodeToText(fsControlCode));
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            appendWideText(detailBuffer, L" code=");
            appendHexText(detailBuffer, fsControlCode);
            appendWideText(detailBuffer, L" status=");
            appendHexText(detailBuffer, static_cast<std::uint32_t>(kStatusValue));
            appendWideText(detailBuffer, L" in=");
            appendUnsignedText(detailBuffer, inputBufferLength);
            appendWideText(detailBuffer, L" out=");
            appendUnsignedText(detailBuffer, outputBufferLength);
            appendWideText(detailBuffer, L" info=");
            appendUnsignedText(detailBuffer, ioStatusBlockPointer != nullptr ? static_cast<unsigned long long>(ioStatusBlockPointer->Information) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtFsControlFile", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtQueryDirectoryFile:
        // - Input: Directory handle, query buffer, information class, optional file name, and restart flag;
        // - Handling: Record direct directory enumeration calls to complete Nt-layer enumeration below FindFirstFileEx;
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtQueryDirectoryFile(
            HANDLE fileHandle,
            HANDLE eventHandle,
            KsIoApcRoutine apcRoutinePointer,
            PVOID apcContextPointer,
            PIO_STATUS_BLOCK ioStatusBlockPointer,
            PVOID fileInformationPointer,
            ULONG lengthValue,
            KsFileInformationClass fileInformationClass,
            BOOLEAN returnSingleEntry,
            PUNICODE_STRING fileNamePointer,
            BOOLEAN restartScan)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gNtQueryDirectoryFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass, returnSingleEntry, fileNamePointer, restartScan);
            }

            const NTSTATUS kStatusValue = gNtQueryDirectoryFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass, returnSingleEntry, fileNamePointer, restartScan);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            appendWideText(detailBuffer, L" pattern=");
            appendUnicodeStringText(detailBuffer, fileNamePointer);
            appendWideText(detailBuffer, L" class=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(fileInformationClass));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, lengthValue);
            appendWideText(detailBuffer, L" single=");
            appendUnsignedText(detailBuffer, returnSingleEntry ? 1 : 0);
            appendWideText(detailBuffer, L" restart=");
            appendUnsignedText(detailBuffer, restartScan ? 1 : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtQueryDirectoryFile", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtQueryDirectoryFileEx:
        // - Input: Extended directory query parameters, including QueryFlags and an optional file name;
        // - Processing: Record modern NtQueryDirectoryFileEx path enumeration.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtQueryDirectoryFileEx(
            HANDLE fileHandle,
            HANDLE eventHandle,
            KsIoApcRoutine apcRoutinePointer,
            PVOID apcContextPointer,
            PIO_STATUS_BLOCK ioStatusBlockPointer,
            PVOID fileInformationPointer,
            ULONG lengthValue,
            KsFileInformationClass fileInformationClass,
            ULONG queryFlags,
            PUNICODE_STRING fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gNtQueryDirectoryFileExOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass, queryFlags, fileNamePointer);
            }

            const NTSTATUS kStatusValue = gNtQueryDirectoryFileExOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass, queryFlags, fileNamePointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            appendWideText(detailBuffer, L" pattern=");
            appendUnicodeStringText(detailBuffer, fileNamePointer);
            appendWideText(detailBuffer, L" class=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(fileInformationClass));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, queryFlags);
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, lengthValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"ntdll", L"NtQueryDirectoryFileEx", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtCreateKey(PHANDLE keyHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, ULONG titleIndex, PUNICODE_STRING classPointer, ULONG createOptions, PULONG dispositionPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtCreateKeyOriginal(keyHandlePointer, desiredAccess, objectAttributesPointer, titleIndex, classPointer, createOptions, dispositionPointer); }
            const NTSTATUS kStatusValue = gNtCreateKeyOriginal(keyHandlePointer, desiredAccess, objectAttributesPointer, titleIndex, classPointer, createOptions, dispositionPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildNtObjectPathDetail(detailBuffer, objectAttributesPointer, desiredAccess, 0, dispositionPointer != nullptr ? *dispositionPointer : 0, createOptions);
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtCreateKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtOpenKey(PHANDLE keyHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtOpenKeyOriginal(keyHandlePointer, desiredAccess, objectAttributesPointer); }
            const NTSTATUS kStatusValue = gNtOpenKeyOriginal(keyHandlePointer, desiredAccess, objectAttributesPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildNtObjectPathDetail(detailBuffer, objectAttributesPointer, desiredAccess, 0, 0, 0);
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtOpenKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtOpenKeyEx(PHANDLE keyHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, ULONG openOptions)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtOpenKeyExOriginal(keyHandlePointer, desiredAccess, objectAttributesPointer, openOptions); }
            const NTSTATUS kStatusValue = gNtOpenKeyExOriginal(keyHandlePointer, desiredAccess, objectAttributesPointer, openOptions);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildNtObjectPathDetail(detailBuffer, objectAttributesPointer, desiredAccess, 0, 0, openOptions);
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtOpenKeyEx", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtSetValueKey(HANDLE keyHandle, PUNICODE_STRING valueNamePointer, ULONG titleIndex, ULONG typeValue, PVOID dataPointer, ULONG dataSize)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtSetValueKeyOriginal(keyHandle, valueNamePointer, titleIndex, typeValue, dataPointer, dataSize); }
            const NTSTATUS kStatusValue = gNtSetValueKeyOriginal(keyHandle, valueNamePointer, titleIndex, typeValue, dataPointer, dataSize);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildNtKeyValueDetail(detailBuffer, keyHandle, valueNamePointer, typeValue, dataSize);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtSetValueKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtQueryValueKey(HANDLE keyHandle, PUNICODE_STRING valueNamePointer, KsKeyValueInformationClass keyValueInformationClass, PVOID keyValueInformationPointer, ULONG lengthValue, PULONG resultLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtQueryValueKeyOriginal(keyHandle, valueNamePointer, keyValueInformationClass, keyValueInformationPointer, lengthValue, resultLengthPointer); }
            const NTSTATUS kStatusValue = gNtQueryValueKeyOriginal(keyHandle, valueNamePointer, keyValueInformationClass, keyValueInformationPointer, lengthValue, resultLengthPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildNtKeyValueDetail(detailBuffer, keyHandle, valueNamePointer, static_cast<ULONG>(keyValueInformationClass), resultLengthPointer != nullptr ? *resultLengthPointer : lengthValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtQueryValueKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtEnumerateKey(HANDLE keyHandle, ULONG indexValue, KsKeyInformationClass keyInformationClass, PVOID keyInformationPointer, ULONG lengthValue, PULONG resultLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtEnumerateKeyOriginal(keyHandle, indexValue, keyInformationClass, keyInformationPointer, lengthValue, resultLengthPointer); }
            const NTSTATUS kStatusValue = gNtEnumerateKeyOriginal(keyHandle, indexValue, keyInformationClass, keyInformationPointer, lengthValue, resultLengthPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" index=");
            appendUnsignedText(detailBuffer, indexValue);
            appendWideText(detailBuffer, L" class=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(keyInformationClass));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : lengthValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtEnumerateKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtEnumerateValueKey(HANDLE keyHandle, ULONG indexValue, KsKeyValueInformationClass keyValueInformationClass, PVOID keyValueInformationPointer, ULONG lengthValue, PULONG resultLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtEnumerateValueKeyOriginal(keyHandle, indexValue, keyValueInformationClass, keyValueInformationPointer, lengthValue, resultLengthPointer); }
            const NTSTATUS kStatusValue = gNtEnumerateValueKeyOriginal(keyHandle, indexValue, keyValueInformationClass, keyValueInformationPointer, lengthValue, resultLengthPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" index=");
            appendUnsignedText(detailBuffer, indexValue);
            appendWideText(detailBuffer, L" class=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(keyValueInformationClass));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : lengthValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtEnumerateValueKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtDeleteKey(HANDLE keyHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtDeleteKeyOriginal(keyHandle); }
            const NTSTATUS kStatusValue = gNtDeleteKeyOriginal(keyHandle);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtDeleteKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtDeleteValueKey(HANDLE keyHandle, PUNICODE_STRING valueNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtDeleteValueKeyOriginal(keyHandle, valueNamePointer); }
            const NTSTATUS kStatusValue = gNtDeleteValueKeyOriginal(keyHandle, valueNamePointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildNtKeyValueDetail(detailBuffer, keyHandle, valueNamePointer, 0, 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtDeleteValueKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtFlushKey(HANDLE keyHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtFlushKeyOriginal(keyHandle); }
            const NTSTATUS kStatusValue = gNtFlushKeyOriginal(keyHandle);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtFlushKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtRenameKey(HANDLE keyHandle, PUNICODE_STRING newNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtRenameKeyOriginal(keyHandle, newNamePointer); }
            const NTSTATUS kStatusValue = gNtRenameKeyOriginal(keyHandle, newNamePointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" new=");
            appendUnicodeStringText(detailBuffer, newNamePointer);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtRenameKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtLoadKey(POBJECT_ATTRIBUTES targetKeyPointer, POBJECT_ATTRIBUTES sourceFilePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtLoadKeyOriginal(targetKeyPointer, sourceFilePointer); }
            const NTSTATUS kStatusValue = gNtLoadKeyOriginal(targetKeyPointer, sourceFilePointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"target=");
            appendObjectNameText(detailBuffer, targetKeyPointer);
            appendWideText(detailBuffer, L" source=");
            appendObjectNameText(detailBuffer, sourceFilePointer);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtLoadKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtSaveKey(HANDLE keyHandle, HANDLE fileHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtSaveKeyOriginal(keyHandle, fileHandle); }
            const NTSTATUS kStatusValue = gNtSaveKeyOriginal(keyHandle, fileHandle);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" file=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtSaveKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtQueryKey:
        // - Input: key handle, information class, and output buffer length;
        // - Processing: Log direct Nt-level key metadata queries;
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtQueryKey(HANDLE keyHandle, KsKeyInformationClass keyInformationClass, PVOID keyInformationPointer, ULONG lengthValue, PULONG resultLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtQueryKeyOriginal(keyHandle, keyInformationClass, keyInformationPointer, lengthValue, resultLengthPointer); }
            const NTSTATUS kStatusValue = gNtQueryKeyOriginal(keyHandle, keyInformationClass, keyInformationPointer, lengthValue, resultLengthPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" class=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(keyInformationClass));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : lengthValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtQueryKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtQueryMultipleValueKey:
        // - Input: key handle, value entries array, entry count, and value buffer length;
        // - Processing: Record the Nt-layer path for batch queries of multiple registry values.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtQueryMultipleValueKey(HANDLE keyHandle, PVOID valueEntriesPointer, ULONG entryCount, PVOID valueBufferPointer, PULONG bufferLengthPointer, PULONG requiredBufferLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtQueryMultipleValueKeyOriginal(keyHandle, valueEntriesPointer, entryCount, valueBufferPointer, bufferLengthPointer, requiredBufferLengthPointer); }
            const NTSTATUS kStatusValue = gNtQueryMultipleValueKeyOriginal(keyHandle, valueEntriesPointer, entryCount, valueBufferPointer, bufferLengthPointer, requiredBufferLengthPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" entries=");
            appendUnsignedText(detailBuffer, entryCount);
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, bufferLengthPointer != nullptr ? *bufferLengthPointer : 0);
            appendWideText(detailBuffer, L" required=");
            appendUnsignedText(detailBuffer, requiredBufferLengthPointer != nullptr ? *requiredBufferLengthPointer : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtQueryMultipleValueKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtNotifyChangeKey:
        // - Input: key handle, event/APC, filter mask, recursive flag, and buffer information.
        // - Processing: Record registry change notification subscriptions, overriding monitoring behavior.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtNotifyChangeKey(HANDLE keyHandle, HANDLE eventHandle, KsIoApcRoutine apcRoutinePointer, PVOID apcContextPointer, PIO_STATUS_BLOCK ioStatusBlockPointer, ULONG completionFilter, BOOLEAN watchTree, PVOID bufferPointer, ULONG bufferSize, BOOLEAN asynchronous)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtNotifyChangeKeyOriginal(keyHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, completionFilter, watchTree, bufferPointer, bufferSize, asynchronous); }
            const NTSTATUS kStatusValue = gNtNotifyChangeKeyOriginal(keyHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, completionFilter, watchTree, bufferPointer, bufferSize, asynchronous);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" filter=");
            appendHexText(detailBuffer, completionFilter);
            appendWideText(detailBuffer, L" tree=");
            appendUnsignedText(detailBuffer, watchTree ? 1 : 0);
            appendWideText(detailBuffer, L" async=");
            appendUnsignedText(detailBuffer, asynchronous ? 1 : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtNotifyChangeKey", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtLoadKey2:
        // - Input: target key object, source hive file object, and load flags;
        // - Processing: Record hive load paths with flags.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtLoadKey2(POBJECT_ATTRIBUTES targetKeyPointer, POBJECT_ATTRIBUTES sourceFilePointer, ULONG flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtLoadKey2Original(targetKeyPointer, sourceFilePointer, flagsValue); }
            const NTSTATUS kStatusValue = gNtLoadKey2Original(targetKeyPointer, sourceFilePointer, flagsValue);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"target=");
            appendObjectNameText(detailBuffer, targetKeyPointer);
            appendWideText(detailBuffer, L" source=");
            appendObjectNameText(detailBuffer, sourceFilePointer);
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, flagsValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtLoadKey2", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtSaveKeyEx:
        // - Input: key handle, file handle, and save format flag;
        // - Processing: Record extended hive save path.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtSaveKeyEx(HANDLE keyHandle, HANDLE fileHandle, ULONG formatValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtSaveKeyExOriginal(keyHandle, fileHandle, formatValue); }
            const NTSTATUS kStatusValue = gNtSaveKeyExOriginal(keyHandle, fileHandle, formatValue);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"hkey=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            appendWideText(detailBuffer, L" file=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            appendWideText(detailBuffer, L" format=");
            appendHexText(detailBuffer, formatValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtSaveKeyEx", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtLoadDriver:
        // - Input: Registry service path (UNICODE_STRING);
        // - Processing: Record native driver load requests and categorize them under registry/persistence-related monitoring.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtLoadDriver(PUNICODE_STRING serviceNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtLoadDriverOriginal(serviceNamePointer); }
            const NTSTATUS kStatusValue = gNtLoadDriverOriginal(serviceNamePointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"service=");
            appendUnicodeStringText(detailBuffer, serviceNamePointer);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtLoadDriver", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtUnloadDriver:
        // - Input: Registry service path (UNICODE_STRING);
        // - Processing: Record native driver unload requests.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtUnloadDriver(PUNICODE_STRING serviceNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtUnloadDriverOriginal(serviceNamePointer); }
            const NTSTATUS kStatusValue = gNtUnloadDriverOriginal(serviceNamePointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"service=");
            appendUnicodeStringText(detailBuffer, serviceNamePointer);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtUnloadDriver", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtOpenProcess(PHANDLE processHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, PksClientId clientIdPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtOpenProcessOriginal(processHandlePointer, desiredAccess, objectAttributesPointer, clientIdPointer); }
            const NTSTATUS kStatusValue = gNtOpenProcessOriginal(processHandlePointer, desiredAccess, objectAttributesPointer, clientIdPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildProcessHandleDetail(detailBuffer, nullptr, desiredAccess, clientIdPointer != nullptr ? reinterpret_cast<std::uint64_t>(clientIdPointer->uniqueProcess) : 0, processHandlePointer != nullptr ? *processHandlePointer : nullptr);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtOpenProcess", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtOpenThread(PHANDLE threadHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, PksClientId clientIdPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtOpenThreadOriginal(threadHandlePointer, desiredAccess, objectAttributesPointer, clientIdPointer); }
            const NTSTATUS kStatusValue = gNtOpenThreadOriginal(threadHandlePointer, desiredAccess, objectAttributesPointer, clientIdPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"pid=");
            appendHexText(detailBuffer, clientIdPointer != nullptr ? reinterpret_cast<std::uint64_t>(clientIdPointer->uniqueProcess) : 0);
            appendWideText(detailBuffer, L" tid=");
            appendHexText(detailBuffer, clientIdPointer != nullptr ? reinterpret_cast<std::uint64_t>(clientIdPointer->uniqueThread) : 0);
            appendWideText(detailBuffer, L" access=");
            appendHexText(detailBuffer, desiredAccess);
            appendWideText(detailBuffer, L" handle=");
            appendHexText(detailBuffer, threadHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*threadHandlePointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtOpenThread", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtTerminateProcess(HANDLE processHandle, NTSTATUS exitStatus)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtTerminateProcessOriginal(processHandle, exitStatus); }
            const NTSTATUS kStatusValue = gNtTerminateProcessOriginal(processHandle, exitStatus);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"process=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            appendWideText(detailBuffer, L" exit=");
            appendHexText(detailBuffer, static_cast<std::uint32_t>(exitStatus));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtTerminateProcess", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtCreateUserProcess(PHANDLE processHandlePointer, PHANDLE threadHandlePointer, ACCESS_MASK processDesiredAccess, ACCESS_MASK threadDesiredAccess, POBJECT_ATTRIBUTES processObjectAttributesPointer, POBJECT_ATTRIBUTES threadObjectAttributesPointer, ULONG processFlags, ULONG threadFlags, PVOID processParametersPointer, PVOID createInfoPointer, PVOID attributeListPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtCreateUserProcessOriginal(processHandlePointer, threadHandlePointer, processDesiredAccess, threadDesiredAccess, processObjectAttributesPointer, threadObjectAttributesPointer, processFlags, threadFlags, processParametersPointer, createInfoPointer, attributeListPointer); }
            const NTSTATUS kStatusValue = gNtCreateUserProcessOriginal(processHandlePointer, threadHandlePointer, processDesiredAccess, threadDesiredAccess, processObjectAttributesPointer, threadObjectAttributesPointer, processFlags, threadFlags, processParametersPointer, createInfoPointer, attributeListPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"processAccess=");
            appendHexText(detailBuffer, processDesiredAccess);
            appendWideText(detailBuffer, L" threadAccess=");
            appendHexText(detailBuffer, threadDesiredAccess);
            appendWideText(detailBuffer, L" processFlags=");
            appendHexText(detailBuffer, processFlags);
            appendWideText(detailBuffer, L" threadFlags=");
            appendHexText(detailBuffer, threadFlags);
            appendWideText(detailBuffer, L" process=");
            appendHexText(detailBuffer, processHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*processHandlePointer) : 0);
            appendWideText(detailBuffer, L" thread=");
            appendHexText(detailBuffer, threadHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*threadHandlePointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtCreateUserProcess", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtCreateProcessEx(PHANDLE processHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, HANDLE parentProcessHandle, ULONG flagsValue, HANDLE sectionHandle, HANDLE debugPortHandle, HANDLE exceptionPortHandle, BOOLEAN inJob)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtCreateProcessExOriginal(processHandlePointer, desiredAccess, objectAttributesPointer, parentProcessHandle, flagsValue, sectionHandle, debugPortHandle, exceptionPortHandle, inJob); }
            const NTSTATUS kStatusValue = gNtCreateProcessExOriginal(processHandlePointer, desiredAccess, objectAttributesPointer, parentProcessHandle, flagsValue, sectionHandle, debugPortHandle, exceptionPortHandle, inJob);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"parent=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parentProcessHandle));
            appendWideText(detailBuffer, L" access=");
            appendHexText(detailBuffer, desiredAccess);
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, flagsValue);
            appendWideText(detailBuffer, L" process=");
            appendHexText(detailBuffer, processHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*processHandlePointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtCreateProcessEx", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtCreateThreadEx(PHANDLE threadHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, HANDLE processHandle, PVOID startRoutinePointer, PVOID argumentPointer, ULONG createFlags, SIZE_T zeroBits, SIZE_T stackSize, SIZE_T maximumStackSize, PVOID attributeListPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtCreateThreadExOriginal(threadHandlePointer, desiredAccess, objectAttributesPointer, processHandle, startRoutinePointer, argumentPointer, createFlags, zeroBits, stackSize, maximumStackSize, attributeListPointer); }
            const NTSTATUS kStatusValue = gNtCreateThreadExOriginal(threadHandlePointer, desiredAccess, objectAttributesPointer, processHandle, startRoutinePointer, argumentPointer, createFlags, zeroBits, stackSize, maximumStackSize, attributeListPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"process=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            appendWideText(detailBuffer, L" start=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(startRoutinePointer));
            appendWideText(detailBuffer, L" arg=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(argumentPointer));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, createFlags);
            appendWideText(detailBuffer, L" thread=");
            appendHexText(detailBuffer, threadHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*threadHandlePointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtCreateThreadEx", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtAllocateVirtualMemory(HANDLE processHandle, PVOID* baseAddressPointer, ULONG_PTR zeroBits, PSIZE_T regionSizePointer, ULONG allocationType, ULONG protectValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtAllocateVirtualMemoryOriginal(processHandle, baseAddressPointer, zeroBits, regionSizePointer, allocationType, protectValue); }
            const NTSTATUS kStatusValue = gNtAllocateVirtualMemoryOriginal(processHandle, baseAddressPointer, zeroBits, regionSizePointer, allocationType, protectValue);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRemoteMemoryDetail(detailBuffer, processHandle, baseAddressPointer != nullptr ? *baseAddressPointer : nullptr, regionSizePointer != nullptr ? static_cast<std::uint64_t>(*regionSizePointer) : 0, allocationType, protectValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtAllocateVirtualMemory", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtFreeVirtualMemory(HANDLE processHandle, PVOID* baseAddressPointer, PSIZE_T regionSizePointer, ULONG freeType)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtFreeVirtualMemoryOriginal(processHandle, baseAddressPointer, regionSizePointer, freeType); }
            const NTSTATUS kStatusValue = gNtFreeVirtualMemoryOriginal(processHandle, baseAddressPointer, regionSizePointer, freeType);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRemoteMemoryDetail(detailBuffer, processHandle, baseAddressPointer != nullptr ? *baseAddressPointer : nullptr, regionSizePointer != nullptr ? static_cast<std::uint64_t>(*regionSizePointer) : 0, freeType, 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtFreeVirtualMemory", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtProtectVirtualMemory(HANDLE processHandle, PVOID* baseAddressPointer, PSIZE_T regionSizePointer, ULONG newProtect, PULONG oldProtectPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtProtectVirtualMemoryOriginal(processHandle, baseAddressPointer, regionSizePointer, newProtect, oldProtectPointer); }
            const NTSTATUS kStatusValue = gNtProtectVirtualMemoryOriginal(processHandle, baseAddressPointer, regionSizePointer, newProtect, oldProtectPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRemoteMemoryDetail(detailBuffer, processHandle, baseAddressPointer != nullptr ? *baseAddressPointer : nullptr, regionSizePointer != nullptr ? static_cast<std::uint64_t>(*regionSizePointer) : 0, oldProtectPointer != nullptr ? *oldProtectPointer : 0, newProtect);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtProtectVirtualMemory", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtWriteVirtualMemory(HANDLE processHandle, PVOID baseAddress, PVOID bufferPointer, SIZE_T sizeValue, PSIZE_T bytesWrittenPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtWriteVirtualMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesWrittenPointer); }
            const NTSTATUS kStatusValue = gNtWriteVirtualMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesWrittenPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRemoteMemoryDetail(detailBuffer, processHandle, baseAddress, static_cast<std::uint64_t>(sizeValue), 0, 0);
            appendWideText(detailBuffer, L" written=");
            appendUnsignedText(detailBuffer, bytesWrittenPointer != nullptr ? static_cast<unsigned long long>(*bytesWrittenPointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtWriteVirtualMemory", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtReadVirtualMemory(HANDLE processHandle, PVOID baseAddress, PVOID bufferPointer, SIZE_T sizeValue, PSIZE_T bytesReadPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtReadVirtualMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesReadPointer); }
            const NTSTATUS kStatusValue = gNtReadVirtualMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesReadPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRemoteMemoryDetail(detailBuffer, processHandle, baseAddress, static_cast<std::uint64_t>(sizeValue), 0, 0);
            appendWideText(detailBuffer, L" read=");
            appendUnsignedText(detailBuffer, bytesReadPointer != nullptr ? static_cast<unsigned long long>(*bytesReadPointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtReadVirtualMemory", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtMapViewOfSection(HANDLE sectionHandle, HANDLE processHandle, PVOID* baseAddressPointer, ULONG_PTR zeroBits, SIZE_T commitSize, PLARGE_INTEGER sectionOffsetPointer, PSIZE_T viewSizePointer, DWORD inheritDisposition, ULONG allocationType, ULONG protectValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtMapViewOfSectionOriginal(sectionHandle, processHandle, baseAddressPointer, zeroBits, commitSize, sectionOffsetPointer, viewSizePointer, inheritDisposition, allocationType, protectValue); }
            const NTSTATUS kStatusValue = gNtMapViewOfSectionOriginal(sectionHandle, processHandle, baseAddressPointer, zeroBits, commitSize, sectionOffsetPointer, viewSizePointer, inheritDisposition, allocationType, protectValue);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"section=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sectionHandle));
            appendWideText(detailBuffer, L" process=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            appendWideText(detailBuffer, L" base=");
            appendHexText(detailBuffer, baseAddressPointer != nullptr ? reinterpret_cast<std::uint64_t>(*baseAddressPointer) : 0);
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, viewSizePointer != nullptr ? static_cast<unsigned long long>(*viewSizePointer) : 0);
            appendWideText(detailBuffer, L" protect=");
            appendHexText(detailBuffer, protectValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtMapViewOfSection", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtUnmapViewOfSection(HANDLE processHandle, PVOID baseAddress)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtUnmapViewOfSectionOriginal(processHandle, baseAddress); }
            const NTSTATUS kStatusValue = gNtUnmapViewOfSectionOriginal(processHandle, baseAddress);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRemoteMemoryDetail(detailBuffer, processHandle, baseAddress, 0, 0, 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtUnmapViewOfSection", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        NTSTATUS NTAPI hookedNtDuplicateObject(HANDLE sourceProcessHandle, HANDLE sourceHandle, HANDLE targetProcessHandle, PHANDLE targetHandlePointer, ACCESS_MASK desiredAccess, ULONG handleAttributes, ULONG optionsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtDuplicateObjectOriginal(sourceProcessHandle, sourceHandle, targetProcessHandle, targetHandlePointer, desiredAccess, handleAttributes, optionsValue); }
            const NTSTATUS kStatusValue = gNtDuplicateObjectOriginal(sourceProcessHandle, sourceHandle, targetProcessHandle, targetHandlePointer, desiredAccess, handleAttributes, optionsValue);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"sourceProcess=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sourceProcessHandle));
            appendWideText(detailBuffer, L" sourceHandle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sourceHandle));
            appendWideText(detailBuffer, L" targetProcess=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(targetProcessHandle));
            appendWideText(detailBuffer, L" targetHandle=");
            appendHexText(detailBuffer, targetHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*targetHandlePointer) : 0);
            appendWideText(detailBuffer, L" access=");
            appendHexText(detailBuffer, desiredAccess);
            appendWideText(detailBuffer, L" options=");
            appendHexText(detailBuffer, optionsValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtDuplicateObject", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtQueryInformationProcess:
        // - Input: process handle, information class, and output buffer length;
        // - Processing: Record direct process information queries, covering PEB/debug/protection level and other native query paths.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtQueryInformationProcess(HANDLE processHandle, ULONG processInformationClass, PVOID processInformationPointer, ULONG processInformationLength, PULONG returnLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtQueryInformationProcessOriginal(processHandle, processInformationClass, processInformationPointer, processInformationLength, returnLengthPointer); }
            const NTSTATUS kStatusValue = gNtQueryInformationProcessOriginal(processHandle, processInformationClass, processInformationPointer, processInformationLength, returnLengthPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"process=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            appendWideText(detailBuffer, L" class=");
            appendUnsignedText(detailBuffer, processInformationClass);
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : processInformationLength);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtQueryInformationProcess", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtSetInformationProcess:
        // - Input: Process handle, information class, and input buffer length.
        // - Processing: Log direct process attribute modifications, such as protection, debugging, and priority settings.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtSetInformationProcess(HANDLE processHandle, ULONG processInformationClass, PVOID processInformationPointer, ULONG processInformationLength)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtSetInformationProcessOriginal(processHandle, processInformationClass, processInformationPointer, processInformationLength); }
            const NTSTATUS kStatusValue = gNtSetInformationProcessOriginal(processHandle, processInformationClass, processInformationPointer, processInformationLength);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"process=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            appendWideText(detailBuffer, L" class=");
            appendUnsignedText(detailBuffer, processInformationClass);
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, processInformationLength);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtSetInformationProcess", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtQueryVirtualMemory:
        // - Input: process handle, base address, information class, and output buffer length;
        // - Processing: Log native virtual memory queries to complete VirtualQueryEx/Nt-layer paths.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtQueryVirtualMemory(HANDLE processHandle, PVOID baseAddress, ULONG memoryInformationClass, PVOID memoryInformationPointer, SIZE_T memoryInformationLength, PSIZE_T returnLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtQueryVirtualMemoryOriginal(processHandle, baseAddress, memoryInformationClass, memoryInformationPointer, memoryInformationLength, returnLengthPointer); }
            const NTSTATUS kStatusValue = gNtQueryVirtualMemoryOriginal(processHandle, baseAddress, memoryInformationClass, memoryInformationPointer, memoryInformationLength, returnLengthPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildRemoteMemoryDetail(detailBuffer, processHandle, baseAddress, static_cast<std::uint64_t>(returnLengthPointer != nullptr ? *returnLengthPointer : memoryInformationLength), memoryInformationClass, 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtQueryVirtualMemory", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtCreateSection:
        // - Input: Section result handle, access mask, object attributes, maximum size, protection, attributes, and file handle;
        // - Processing: Record Section creation, overriding the pre-step of the section-map injection chain;
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtCreateSection(PHANDLE sectionHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, PLARGE_INTEGER maximumSizePointer, ULONG sectionPageProtection, ULONG allocationAttributes, HANDLE fileHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtCreateSectionOriginal(sectionHandlePointer, desiredAccess, objectAttributesPointer, maximumSizePointer, sectionPageProtection, allocationAttributes, fileHandle); }
            const NTSTATUS kStatusValue = gNtCreateSectionOriginal(sectionHandlePointer, desiredAccess, objectAttributesPointer, maximumSizePointer, sectionPageProtection, allocationAttributes, fileHandle);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"section=");
            appendHexText(detailBuffer, sectionHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*sectionHandlePointer) : 0);
            appendWideText(detailBuffer, L" access=");
            appendHexText(detailBuffer, desiredAccess);
            appendWideText(detailBuffer, L" protect=");
            appendHexText(detailBuffer, sectionPageProtection);
            appendWideText(detailBuffer, L" attrs=");
            appendHexText(detailBuffer, allocationAttributes);
            appendWideText(detailBuffer, L" file=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtCreateSection", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtOpenSection:
        // - Input: Section result handle, access mask, and object attributes;
        // - Processing: Record opening of an existing Section object;
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtOpenSection(PHANDLE sectionHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtOpenSectionOriginal(sectionHandlePointer, desiredAccess, objectAttributesPointer); }
            const NTSTATUS kStatusValue = gNtOpenSectionOriginal(sectionHandlePointer, desiredAccess, objectAttributesPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"object=");
            appendObjectNameText(detailBuffer, objectAttributesPointer);
            appendWideText(detailBuffer, L" access=");
            appendHexText(detailBuffer, desiredAccess);
            appendWideText(detailBuffer, L" section=");
            appendHexText(detailBuffer, sectionHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*sectionHandlePointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtOpenSection", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtQueueApcThread:
        // - Input: Thread handle, APC routine, and three arguments;
        // - Processing: Log native APC queuing to cover injection paths that bypass QueueUserAPC.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtQueueApcThread(HANDLE threadHandle, PVOID apcRoutinePointer, PVOID argument1Pointer, PVOID argument2Pointer, PVOID argument3Pointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtQueueApcThreadOriginal(threadHandle, apcRoutinePointer, argument1Pointer, argument2Pointer, argument3Pointer); }
            const NTSTATUS kStatusValue = gNtQueueApcThreadOriginal(threadHandle, apcRoutinePointer, argument1Pointer, argument2Pointer, argument3Pointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"thread=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            appendWideText(detailBuffer, L" apc=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(apcRoutinePointer));
            appendWideText(detailBuffer, L" arg1=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(argument1Pointer));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtQueueApcThread", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtQueueApcThreadEx:
        // - Input: thread handle, Reserve handle, APC routine, and three arguments;
        // - Processing: Record extended APC queue paths.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtQueueApcThreadEx(HANDLE threadHandle, HANDLE reserveHandle, PVOID apcRoutinePointer, PVOID argument1Pointer, PVOID argument2Pointer, PVOID argument3Pointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtQueueApcThreadExOriginal(threadHandle, reserveHandle, apcRoutinePointer, argument1Pointer, argument2Pointer, argument3Pointer); }
            const NTSTATUS kStatusValue = gNtQueueApcThreadExOriginal(threadHandle, reserveHandle, apcRoutinePointer, argument1Pointer, argument2Pointer, argument3Pointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"thread=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            appendWideText(detailBuffer, L" reserve=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(reserveHandle));
            appendWideText(detailBuffer, L" apc=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(apcRoutinePointer));
            appendWideText(detailBuffer, L" arg1=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(argument1Pointer));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtQueueApcThreadEx", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtSuspendThread:
        // - Input: thread handle and optional previous suspend count output;
        // - Processing: Record Nt-level thread suspend.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtSuspendThread(HANDLE threadHandle, PULONG previousSuspendCountPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtSuspendThreadOriginal(threadHandle, previousSuspendCountPointer); }
            const NTSTATUS kStatusValue = gNtSuspendThreadOriginal(threadHandle, previousSuspendCountPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"thread=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            appendWideText(detailBuffer, L" previous=");
            appendUnsignedText(detailBuffer, previousSuspendCountPointer != nullptr ? *previousSuspendCountPointer : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtSuspendThread", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtResumeThread:
        // - Input: thread handle and optional previous suspend count output;
        // - Processing: Record Nt-level thread resume.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtResumeThread(HANDLE threadHandle, PULONG previousSuspendCountPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtResumeThreadOriginal(threadHandle, previousSuspendCountPointer); }
            const NTSTATUS kStatusValue = gNtResumeThreadOriginal(threadHandle, previousSuspendCountPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"thread=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            appendWideText(detailBuffer, L" previous=");
            appendUnsignedText(detailBuffer, previousSuspendCountPointer != nullptr ? *previousSuspendCountPointer : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtResumeThread", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtGetContextThread:
        // - Input: thread handle and CONTEXT output buffer;
        // - Processing: Record Nt-level context read.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtGetContextThread(HANDLE threadHandle, PCONTEXT contextPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtGetContextThreadOriginal(threadHandle, contextPointer); }
            const NTSTATUS kStatusValue = gNtGetContextThreadOriginal(threadHandle, contextPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"thread=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, contextPointer != nullptr ? contextPointer->ContextFlags : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtGetContextThread", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedNtSetContextThread:
        // - Input: thread handle and CONTEXT input buffer;
        // - Processing: Record Nt-level context write.
        // - Return: preserve the original NTSTATUS.
        NTSTATUS NTAPI hookedNtSetContextThread(HANDLE threadHandle, PCONTEXT contextPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gNtSetContextThreadOriginal(threadHandle, contextPointer); }
            const NTSTATUS kStatusValue = gNtSetContextThreadOriginal(threadHandle, contextPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"thread=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, contextPointer != nullptr ? contextPointer->ContextFlags : 0);
#if defined(_M_X64)
            appendWideText(detailBuffer, L" rip=");
            appendHexText(detailBuffer, contextPointer != nullptr ? contextPointer->Rip : 0);
#endif
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtSetContextThread", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // hookedSocket:
        // - Input: address family, socket type, and protocol value;
        // - Processing: Record basic socket creation to complete network object creation behavior before connect/send.
        // - Return: preserve original SOCKET and restore WSA error code on failure.
        SOCKET WSAAPI hookedSocket(int addressFamily, int socketType, int protocolValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gSocketOriginal(addressFamily, socketType, protocolValue); }
            const SOCKET kResultSocket = gSocketOriginal(addressFamily, socketType, protocolValue);
            const int kErrorValue = kResultSocket != INVALID_SOCKET ? 0 : ::WSAGetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"af=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(addressFamily));
            appendWideText(detailBuffer, L" type=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(socketType));
            appendWideText(detailBuffer, L" proto=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(protocolValue));
            appendWideText(detailBuffer, L" socket=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(kResultSocket));
            sendMonitorEventRaw(ks::winapi_monitor::EventCategory::kNetwork, L"Ws2_32", L"socket", kErrorValue, detailBuffer);
            if (kResultSocket == INVALID_SOCKET) { ::WSASetLastError(kErrorValue); }
            return kResultSocket;
        }

        // hookedWsaSocketW:
        // - Input: Address family, socket type, protocol, protocol info, group, and flags;
        // - Processing: Record extended socket creation, including overlapped and flag information.
        // - Return: preserve original SOCKET and restore WSA error code on failure.
        SOCKET WSAAPI hookedWsaSocketW(int addressFamily, int socketType, int protocolValue, LPWSAPROTOCOL_INFOW protocolInfoPointer, GROUP groupValue, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gWsaSocketWOriginal(addressFamily, socketType, protocolValue, protocolInfoPointer, groupValue, flagsValue); }
            const SOCKET kResultSocket = gWsaSocketWOriginal(addressFamily, socketType, protocolValue, protocolInfoPointer, groupValue, flagsValue);
            const int kErrorValue = kResultSocket != INVALID_SOCKET ? 0 : ::WSAGetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"af=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(addressFamily));
            appendWideText(detailBuffer, L" type=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(socketType));
            appendWideText(detailBuffer, L" proto=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(protocolValue));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, flagsValue);
            appendWideText(detailBuffer, L" socket=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(kResultSocket));
            sendMonitorEventRaw(ks::winapi_monitor::EventCategory::kNetwork, L"Ws2_32", L"WSASocketW", kErrorValue, detailBuffer);
            if (kResultSocket == INVALID_SOCKET) { ::WSASetLastError(kErrorValue); }
            return kResultSocket;
        }

        // hookedWsaSocketA:
        // - Input: ANSI version WSASocket parameters;
        // - Processing: Record extended socket creation.
        // - Return: preserve original SOCKET and restore WSA error code on failure.
        SOCKET WSAAPI hookedWsaSocketA(int addressFamily, int socketType, int protocolValue, LPWSAPROTOCOL_INFOA protocolInfoPointer, GROUP groupValue, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gWsaSocketAOriginal(addressFamily, socketType, protocolValue, protocolInfoPointer, groupValue, flagsValue); }
            const SOCKET kResultSocket = gWsaSocketAOriginal(addressFamily, socketType, protocolValue, protocolInfoPointer, groupValue, flagsValue);
            const int kErrorValue = kResultSocket != INVALID_SOCKET ? 0 : ::WSAGetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"af=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(addressFamily));
            appendWideText(detailBuffer, L" type=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(socketType));
            appendWideText(detailBuffer, L" proto=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(protocolValue));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, flagsValue);
            appendWideText(detailBuffer, L" socket=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(kResultSocket));
            sendMonitorEventRaw(ks::winapi_monitor::EventCategory::kNetwork, L"Ws2_32", L"WSASocketA", kErrorValue, detailBuffer);
            if (kResultSocket == INVALID_SOCKET) { ::WSASetLastError(kErrorValue); }
            return kResultSocket;
        }

        // hookedCloseSocket:
        // - Input: socket handle;
        // - Processing: Record network handle closure.
        // - Return: preserves the int result of closesocket and restores the WSA error code on failure.
        int WSAAPI hookedCloseSocket(SOCKET socketValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gCloseSocketOriginal(socketValue); }
            const int kResultValue = gCloseSocketOriginal(socketValue);
            const int kErrorValue = kResultValue == 0 ? 0 : ::WSAGetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"socket=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue));
            sendMonitorEventRaw(ks::winapi_monitor::EventCategory::kNetwork, L"Ws2_32", L"closesocket", kErrorValue, detailBuffer);
            if (kResultValue != 0) { ::WSASetLastError(kErrorValue); }
            return kResultValue;
        }

        // hookedShutdown:
        // - Input: socket handle and shutdown direction.
        // - Processing: Record active half-close/full-close operations.
        // - Return: Keep the original shutdown() int result and restore the WSA error code on failure.
        int WSAAPI hookedShutdown(SOCKET socketValue, int howValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gShutdownOriginal(socketValue, howValue); }
            const int kResultValue = gShutdownOriginal(socketValue, howValue);
            const int kErrorValue = kResultValue == 0 ? 0 : ::WSAGetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"socket=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue));
            appendWideText(detailBuffer, L" how=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(howValue));
            sendMonitorEventRaw(ks::winapi_monitor::EventCategory::kNetwork, L"Ws2_32", L"shutdown", kErrorValue, detailBuffer);
            if (kResultValue != 0) { ::WSASetLastError(kErrorValue); }
            return kResultValue;
        }

        int WSAAPI hookedConnect(SOCKET socketValue, const sockaddr* namePointer, int nameLength)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gConnectOriginal(socketValue, namePointer, nameLength);
            }

            const int kResultValue = gConnectOriginal(socketValue, namePointer, nameLength);
            const int kErrorValue = kResultValue == 0 ? 0 : ::WSAGetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildSocketDetail(detailBuffer, L"connect", socketValue, 0, 0, 0, namePointer, nameLength);
            sendMonitorEventRaw(
                ks::winapi_monitor::EventCategory::kNetwork,
                L"Ws2_32",
                L"connect",
                kErrorValue,
                detailBuffer);
            if (kResultValue != 0)
            {
                ::WSASetLastError(kErrorValue);
            }
            return kResultValue;
        }

        int WSAAPI hookedWsaConnect(SOCKET socketValue, const sockaddr* namePointer, int nameLength, LPWSABUF callerDataPointer, LPWSABUF calleeDataPointer, LPQOS socketQosPointer, LPQOS groupQosPointer)
        {
            (void)callerDataPointer;
            (void)calleeDataPointer;
            (void)socketQosPointer;
            (void)groupQosPointer;
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gWsaConnectOriginal(socketValue, namePointer, nameLength, callerDataPointer, calleeDataPointer, socketQosPointer, groupQosPointer);
            }

            const int kResultValue = gWsaConnectOriginal(socketValue, namePointer, nameLength, callerDataPointer, calleeDataPointer, socketQosPointer, groupQosPointer);
            const int kErrorValue = kResultValue == 0 ? 0 : ::WSAGetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildSocketDetail(detailBuffer, L"connect", socketValue, 0, 0, 0, namePointer, nameLength);
            sendMonitorEventRaw(
                ks::winapi_monitor::EventCategory::kNetwork,
                L"Ws2_32",
                L"WSAConnect",
                kErrorValue,
                detailBuffer);
            if (kResultValue != 0)
            {
                ::WSASetLastError(kErrorValue);
            }
            return kResultValue;
        }

        int WSAAPI hookedSend(SOCKET socketValue, const char* bufferPointer, int bufferLength, int flagsValue)
        {
            (void)bufferPointer;
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gSendOriginal(socketValue, bufferPointer, bufferLength, flagsValue);
            }

            const int kResultValue = gSendOriginal(socketValue, bufferPointer, bufferLength, flagsValue);
            const int kErrorValue = kResultValue >= 0 ? 0 : ::WSAGetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildSocketDetail(detailBuffer, L"send", socketValue, static_cast<std::uint64_t>(bufferLength < 0 ? 0 : bufferLength), kResultValue, static_cast<DWORD>(flagsValue));
            sendMonitorEventRaw(
                ks::winapi_monitor::EventCategory::kNetwork,
                L"Ws2_32",
                L"send",
                kErrorValue,
                detailBuffer);
            if (kResultValue < 0)
            {
                ::WSASetLastError(kErrorValue);
            }
            return kResultValue;
        }

        int WSAAPI hookedWsaSend(SOCKET socketValue, LPWSABUF buffersPointer, DWORD bufferCount, LPDWORD bytesSentPointer, DWORD flagsValue, LPWSAOVERLAPPED overlappedPointer, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutinePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gWsaSendOriginal(socketValue, buffersPointer, bufferCount, bytesSentPointer, flagsValue, overlappedPointer, completionRoutinePointer);
            }

            const std::uint64_t kRequestLength = sumWsaBufferLength(buffersPointer, bufferCount);
            const int kResultValue = gWsaSendOriginal(socketValue, buffersPointer, bufferCount, bytesSentPointer, flagsValue, overlappedPointer, completionRoutinePointer);
            const int kErrorValue = kResultValue == 0 ? 0 : ::WSAGetLastError();
            const DWORD kSentValue = bytesSentPointer != nullptr ? *bytesSentPointer : 0;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildSocketDetail(detailBuffer, L"send", socketValue, kRequestLength, kSentValue, flagsValue);
            sendMonitorEventRaw(
                ks::winapi_monitor::EventCategory::kNetwork,
                L"Ws2_32",
                L"WSASend",
                kErrorValue,
                detailBuffer);
            if (kResultValue != 0)
            {
                ::WSASetLastError(kErrorValue);
            }
            return kResultValue;
        }

        int WSAAPI hookedSendTo(SOCKET socketValue, const char* bufferPointer, int bufferLength, int flagsValue, const sockaddr* toPointer, int toLength)
        {
            (void)bufferPointer;
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gSendToOriginal(socketValue, bufferPointer, bufferLength, flagsValue, toPointer, toLength);
            }

            const int kResultValue = gSendToOriginal(socketValue, bufferPointer, bufferLength, flagsValue, toPointer, toLength);
            const int kErrorValue = kResultValue >= 0 ? 0 : ::WSAGetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildSocketDetail(detailBuffer, L"sendto", socketValue, static_cast<std::uint64_t>(bufferLength < 0 ? 0 : bufferLength), kResultValue, static_cast<DWORD>(flagsValue), toPointer, toLength);
            sendMonitorEventRaw(
                ks::winapi_monitor::EventCategory::kNetwork,
                L"Ws2_32",
                L"sendto",
                kErrorValue,
                detailBuffer);
            if (kResultValue < 0)
            {
                ::WSASetLastError(kErrorValue);
            }
            return kResultValue;
        }

        int WSAAPI hookedRecv(SOCKET socketValue, char* bufferPointer, int bufferLength, int flagsValue)
        {
            (void)bufferPointer;
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gRecvOriginal(socketValue, bufferPointer, bufferLength, flagsValue);
            }

            const int kResultValue = gRecvOriginal(socketValue, bufferPointer, bufferLength, flagsValue);
            const int kErrorValue = kResultValue >= 0 ? 0 : ::WSAGetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildSocketDetail(detailBuffer, L"recv", socketValue, static_cast<std::uint64_t>(bufferLength < 0 ? 0 : bufferLength), kResultValue, static_cast<DWORD>(flagsValue));
            sendMonitorEventRaw(
                ks::winapi_monitor::EventCategory::kNetwork,
                L"Ws2_32",
                L"recv",
                kErrorValue,
                detailBuffer);
            if (kResultValue < 0)
            {
                ::WSASetLastError(kErrorValue);
            }
            return kResultValue;
        }

        int WSAAPI hookedWsaRecv(SOCKET socketValue, LPWSABUF buffersPointer, DWORD bufferCount, LPDWORD bytesReceivedPointer, LPDWORD flagsPointer, LPWSAOVERLAPPED overlappedPointer, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutinePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gWsaRecvOriginal(socketValue, buffersPointer, bufferCount, bytesReceivedPointer, flagsPointer, overlappedPointer, completionRoutinePointer);
            }

            const std::uint64_t kRequestLength = sumWsaBufferLength(buffersPointer, bufferCount);
            const int kResultValue = gWsaRecvOriginal(socketValue, buffersPointer, bufferCount, bytesReceivedPointer, flagsPointer, overlappedPointer, completionRoutinePointer);
            const int kErrorValue = kResultValue == 0 ? 0 : ::WSAGetLastError();
            const DWORD kReceivedValue = bytesReceivedPointer != nullptr ? *bytesReceivedPointer : 0;
            const DWORD kFlagsValue = flagsPointer != nullptr ? *flagsPointer : 0;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildSocketDetail(detailBuffer, L"recv", socketValue, kRequestLength, kReceivedValue, kFlagsValue);
            sendMonitorEventRaw(
                ks::winapi_monitor::EventCategory::kNetwork,
                L"Ws2_32",
                L"WSARecv",
                kErrorValue,
                detailBuffer);
            if (kResultValue != 0)
            {
                ::WSASetLastError(kErrorValue);
            }
            return kResultValue;
        }

        int WSAAPI hookedRecvFrom(SOCKET socketValue, char* bufferPointer, int bufferLength, int flagsValue, sockaddr* fromPointer, int* fromLengthPointer)
        {
            (void)bufferPointer;
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gRecvFromOriginal(socketValue, bufferPointer, bufferLength, flagsValue, fromPointer, fromLengthPointer);
            }

            const int kResultValue = gRecvFromOriginal(socketValue, bufferPointer, bufferLength, flagsValue, fromPointer, fromLengthPointer);
            const int kErrorValue = kResultValue >= 0 ? 0 : ::WSAGetLastError();
            const int kFromLength = fromLengthPointer != nullptr ? *fromLengthPointer : 0;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildSocketDetail(detailBuffer, L"recvfrom", socketValue, static_cast<std::uint64_t>(bufferLength < 0 ? 0 : bufferLength), kResultValue, static_cast<DWORD>(flagsValue), fromPointer, kFromLength);
            sendMonitorEventRaw(
                ks::winapi_monitor::EventCategory::kNetwork,
                L"Ws2_32",
                L"recvfrom",
                kErrorValue,
                detailBuffer);
            if (kResultValue < 0)
            {
                ::WSASetLastError(kErrorValue);
            }
            return kResultValue;
        }

        int WSAAPI hookedBind(SOCKET socketValue, const sockaddr* namePointer, int nameLength)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gBindOriginal(socketValue, namePointer, nameLength);
            }

            const int kResultValue = gBindOriginal(socketValue, namePointer, nameLength);
            const int kErrorValue = kResultValue == 0 ? 0 : ::WSAGetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildSocketDetail(detailBuffer, L"bind", socketValue, 0, 0, 0, namePointer, nameLength);
            sendMonitorEventRaw(
                ks::winapi_monitor::EventCategory::kNetwork,
                L"Ws2_32",
                L"bind",
                kErrorValue,
                detailBuffer);
            if (kResultValue != 0)
            {
                ::WSASetLastError(kErrorValue);
            }
            return kResultValue;
        }

        int WSAAPI hookedListen(SOCKET socketValue, int backlogValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gListenOriginal(socketValue, backlogValue);
            }

            const int kResultValue = gListenOriginal(socketValue, backlogValue);
            const int kErrorValue = kResultValue == 0 ? 0 : ::WSAGetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, L"socket=");
            appendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue));
            appendWideText(detailBuffer, L" backlog=");
            appendUnsignedText(detailBuffer, static_cast<unsigned long long>(backlogValue < 0 ? 0 : backlogValue));
            sendMonitorEventRaw(
                ks::winapi_monitor::EventCategory::kNetwork,
                L"Ws2_32",
                L"listen",
                kErrorValue,
                detailBuffer);
            if (kResultValue != 0)
            {
                ::WSASetLastError(kErrorValue);
            }
            return kResultValue;
        }

        SOCKET WSAAPI hookedAccept(SOCKET socketValue, sockaddr* addressPointer, int* addressLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return gAcceptOriginal(socketValue, addressPointer, addressLengthPointer);
            }

            const SOCKET kResultSocket = gAcceptOriginal(socketValue, addressPointer, addressLengthPointer);
            const int kErrorValue = kResultSocket != INVALID_SOCKET ? 0 : ::WSAGetLastError();
            const int kAddressLength = addressLengthPointer != nullptr ? *addressLengthPointer : 0;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildSocketDetail(detailBuffer, L"accept", socketValue, 0, static_cast<long long>(kResultSocket == INVALID_SOCKET ? 0 : kResultSocket), 0, addressPointer, kAddressLength);
            sendMonitorEventRaw(
                ks::winapi_monitor::EventCategory::kNetwork,
                L"Ws2_32",
                L"accept",
                kErrorValue,
                detailBuffer);
            if (kResultSocket == INVALID_SOCKET)
            {
                ::WSASetLastError(kErrorValue);
            }
            return kResultSocket;
        }


        // appendProcNameText:
        // - Input: namePointer is a function name in GetProcAddress format, which may be a MAKEINTRESOURCEA-style ordinal;
        // - Processing: Prioritize outputting name= text, then ordinal=<id> for input/output, to prevent dereferencing low-address ordinals as strings;
        // - Return: None. Appends a safe, displayable process name summary to the target buffer.
        template <std::size_t kCount>
        void appendProcNameText(wchar_t(&detailBuffer)[kCount], const char* const namePointer)
        {
            if (namePointer == nullptr)
            {
                appendWideText(detailBuffer, L"name=<null>");
                return;
            }
            if (HIWORD(reinterpret_cast<ULONG_PTR>(namePointer)) == 0)
            {
                appendWideText(detailBuffer, L"ordinal=");
                appendUnsignedText(detailBuffer, static_cast<unsigned long long>(LOWORD(reinterpret_cast<ULONG_PTR>(namePointer))));
                return;
            }
            appendWideText(detailBuffer, L"name=");
            appendAnsiText(detailBuffer, namePointer);
        }

        // appendAnsiStringText:
        // - Input: ansiPointer is an ntdll ANSI_STRING and may be null;
        // - Processing: Copy narrow characters based on Length to avoid relying on NUL termination in the buffer.
        // - Return: None. The target buffer appends potentially truncated process name text.
        template <std::size_t kCount>
        void appendAnsiStringText(wchar_t(&detailBuffer)[kCount], const ANSI_STRING* const ansiPointer)
        {
            if (ansiPointer == nullptr || ansiPointer->Buffer == nullptr || ansiPointer->Length == 0)
            {
                return;
            }
            appendAnsiText(detailBuffer, ansiPointer->Buffer, ansiPointer->Length);
        }

        // buildSimpleHandleDetail:
        // - Input: fieldName is the field name, handleValue is the handle to be recorded;
        // - Processing: Generate unified details in the format field=<hex>, reused across lifecycle APIs such as CloseHandle, NtClose, and ServiceHandle;
        // - Returns: None. detailBuffer contains a fixed-length summary.
        template <std::size_t kCount, typename HandleType>
        void buildSimpleHandleDetail(wchar_t(&detailBuffer)[kCount], const wchar_t* const fieldName, const HandleType handleValue)
        {
            detailBuffer[0] = L'\0';
            appendWideText(detailBuffer, fieldName != nullptr ? fieldName : L"handle");
            appendWideText(detailBuffer, L"=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(handleValue));
        }

        // EmitWin32BoolEvent:
        // - Input: Category, module, API, BOOL result, LastError, and details;
        // - Processing: normalize successful BOOL to resultCode=0, use LastError for failure, and restore the caller thread's LastError.
        // - Return: No return value; the original function's return value is returned by the Hooked wrapper.
        void EmitWin32BoolEvent(
            const ks::winapi_monitor::EventCategory categoryValue,
            const wchar_t* const moduleName,
            const wchar_t* const apiName,
            const BOOL resultValue,
            const DWORD lastError,
            const wchar_t* const detailText)
        {
            SendRawEventWithStatus(categoryValue, moduleName, apiName, resultValue != FALSE ? 0 : lastError, detailText);
            ::SetLastError(lastError);
        }

#define APIMON_SIMPLE_BOOL_HOOK(HookName, OriginalName, CategoryValue, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        BOOL WINAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const BOOL resultValue = OriginalName ArgList; \
            const DWORD lastError = ::GetLastError(); \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            EmitWin32BoolEvent(CategoryValue, ModuleText, ApiText, resultValue, lastError, detailBuffer); \
            return resultValue; \
        }

#define APIMON_SIMPLE_HANDLE_HOOK(ReturnType, HookName, OriginalName, CategoryValue, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        ReturnType WINAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const ReturnType resultHandle = OriginalName ArgList; \
            const DWORD lastError = ::GetLastError(); \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            SendRawEventWithStatus(CategoryValue, ModuleText, ApiText, resultHandle != nullptr ? 0 : lastError, detailBuffer); \
            ::SetLastError(lastError); \
            return resultHandle; \
        }

#define APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookName, OriginalName, CategoryValue, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        DWORD WINAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const DWORD resultValue = OriginalName ArgList; \
            const DWORD lastError = ::GetLastError(); \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            SendRawEventWithStatus(CategoryValue, ModuleText, ApiText, resultValue != 0 ? 0 : lastError, detailBuffer); \
            ::SetLastError(lastError); \
            return resultValue; \
        }

#define APIMON_SIMPLE_UINT_NONZERO_HOOK(HookName, OriginalName, CategoryValue, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        UINT WINAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const UINT resultValue = OriginalName ArgList; \
            const DWORD lastError = ::GetLastError(); \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            SendRawEventWithStatus(CategoryValue, ModuleText, ApiText, resultValue != 0 ? 0 : lastError, detailBuffer); \
            ::SetLastError(lastError); \
            return resultValue; \
        }

#define APIMON_SIMPLE_INT_POSITIVE_HOOK(HookName, OriginalName, CategoryValue, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        int WINAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const int resultValue = OriginalName ArgList; \
            const DWORD lastError = ::GetLastError(); \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            SendRawEventWithStatus(CategoryValue, ModuleText, ApiText, resultValue > 0 ? 0 : lastError, detailBuffer); \
            ::SetLastError(lastError); \
            return resultValue; \
        }

#define APIMON_SIMPLE_ULONG_STATUS_HOOK(HookName, OriginalName, CategoryValue, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        ULONG WINAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const ULONG statusValue = OriginalName ArgList; \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            SendRawEventWithStatus(CategoryValue, ModuleText, ApiText, static_cast<std::int32_t>(statusValue), detailBuffer); \
            return statusValue; \
        }

#define APIMON_SIMPLE_LONG_STATUS_HOOK(HookName, OriginalName, CategoryValue, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        LONG WINAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const LONG statusValue = OriginalName ArgList; \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            SendRawEventWithStatus(CategoryValue, ModuleText, ApiText, static_cast<std::int32_t>(statusValue), detailBuffer); \
            return statusValue; \
        }

#define APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookName, OriginalName, CategoryValue, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        SECURITY_STATUS WINAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const SECURITY_STATUS statusValue = OriginalName ArgList; \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            SendRawEventWithStatus(CategoryValue, ModuleText, ApiText, static_cast<std::int32_t>(statusValue), detailBuffer); \
            return statusValue; \
        }

#define APIMON_SIMPLE_RPC_STATUS_HOOK(HookName, OriginalName, CategoryValue, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        RPC_STATUS RPC_ENTRY HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const RPC_STATUS statusValue = OriginalName ArgList; \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            SendRawEventWithStatus(CategoryValue, ModuleText, ApiText, static_cast<std::int32_t>(statusValue), detailBuffer); \
            return statusValue; \
        }

#define APIMON_SIMPLE_VOID_HOOK(HookName, OriginalName, CategoryValue, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        void WINAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { OriginalName ArgList; return; } \
            OriginalName ArgList; \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            SendRawEventWithStatus(CategoryValue, ModuleText, ApiText, 0, detailBuffer); \
        }

        // HookedCloseHandle:
        // - Input: arbitrary Win32 HANDLE;
        // - Processing: Record handle closure to complete the object lifecycle tail, enabling correlation with Open/Create/Duplicate events;
        // - Return: preserves the original BOOL result of CloseHandle and restores LastError.
        APIMON_SIMPLE_BOOL_HOOK(HookedCloseHandle, gCloseHandleOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CloseHandle",
            (HANDLE handleValue), (handleValue),
            { buildSimpleHandleDetail(detailBuffer, L"handle", handleValue); })

        // HookedDuplicateHandle:
        // - Input: Source/target processes, source handle, target output handle, access mask, and options;
        // - Processing: Record cross-process handle duplication, covering common pre-conditions for privilege escalation, injection, and handle stealing.
        // - Return: Preserve the original BOOL result of DuplicateHandle and restore LastError.
        APIMON_SIMPLE_BOOL_HOOK(HookedDuplicateHandle, gDuplicateHandleOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"DuplicateHandle",
            (HANDLE sourceProcessHandle, HANDLE sourceHandle, HANDLE targetProcessHandle, LPHANDLE targetHandlePointer, DWORD desiredAccess, BOOL inheritHandle, DWORD optionsValue),
            (sourceProcessHandle, sourceHandle, targetProcessHandle, targetHandlePointer, desiredAccess, inheritHandle, optionsValue),
            { appendWideText(detailBuffer, L"srcProc="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sourceProcessHandle)); appendWideText(detailBuffer, L" src="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sourceHandle)); appendWideText(detailBuffer, L" dstProc="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(targetProcessHandle)); appendWideText(detailBuffer, L" dst="); appendHexText(detailBuffer, targetHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*targetHandlePointer) : 0); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" inherit="); appendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" options="); appendHexText(detailBuffer, optionsValue); })

        // HookedCreateFileMappingW:
        // - Input: File handle, protection attributes, size, and mapping name;
        // - Handling: Records section/file mapping creation, bridging the Win32 layer between MapViewOfFile and NtCreateSection.
        // - Returns: preserves the original CreateFileMappingW HANDLE and restores LastError.
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateFileMappingW, gCreateFileMappingWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateFileMappingW",
            (HANDLE fileHandle, LPSECURITY_ATTRIBUTES securityAttributes, DWORD protectValue, DWORD maximumSizeHigh, DWORD maximumSizeLow, LPCWSTR namePointer),
            (fileHandle, securityAttributes, protectValue, maximumSizeHigh, maximumSizeLow, namePointer),
            { appendWideText(detailBuffer, L"file="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); appendWideText(detailBuffer, L" protect="); appendHexText(detailBuffer, protectValue); appendWideText(detailBuffer, L" size="); appendHexText(detailBuffer, (static_cast<std::uint64_t>(maximumSizeHigh) << 32) | maximumSizeLow); appendWideText(detailBuffer, L" name="); appendWideText(detailBuffer, namePointer); })

        // HookedCreateFileMappingA:
        // - Input: ANSI version of CreateFileMapping for mapping names;
        // - Processing: Record file mapping creation parameters; expand the mapping name to wide characters.
        // - Return: Keep the original HANDLE and restore LastError.
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateFileMappingA, gCreateFileMappingAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateFileMappingA",
            (HANDLE fileHandle, LPSECURITY_ATTRIBUTES securityAttributes, DWORD protectValue, DWORD maximumSizeHigh, DWORD maximumSizeLow, LPCSTR namePointer),
            (fileHandle, securityAttributes, protectValue, maximumSizeHigh, maximumSizeLow, namePointer),
            { appendWideText(detailBuffer, L"file="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); appendWideText(detailBuffer, L" protect="); appendHexText(detailBuffer, protectValue); appendWideText(detailBuffer, L" size="); appendHexText(detailBuffer, (static_cast<std::uint64_t>(maximumSizeHigh) << 32) | maximumSizeLow); appendWideText(detailBuffer, L" name="); appendAnsiText(detailBuffer, namePointer); })

        // HookedOpenFileMappingW/A purpose: Record opening of named mappings; return the original HANDLE.
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedOpenFileMappingW, gOpenFileMappingWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"OpenFileMappingW",
            (DWORD desiredAccess, BOOL inheritHandle, LPCWSTR namePointer), (desiredAccess, inheritHandle, namePointer),
            { appendWideText(detailBuffer, L"access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" inherit="); appendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" name="); appendWideText(detailBuffer, namePointer); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedOpenFileMappingA, gOpenFileMappingAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"OpenFileMappingA",
            (DWORD desiredAccess, BOOL inheritHandle, LPCSTR namePointer), (desiredAccess, inheritHandle, namePointer),
            { appendWideText(detailBuffer, L"access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" inherit="); appendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" name="); appendAnsiText(detailBuffer, namePointer); })

        // HookedMapViewOfFile/Ex purpose: record the mapping view location and size; return the original base address pointer.
        APIMON_SIMPLE_HANDLE_HOOK(LPVOID, HookedMapViewOfFile, gMapViewOfFileOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"MapViewOfFile",
            (HANDLE mappingHandle, DWORD desiredAccess, DWORD offsetHigh, DWORD offsetLow, SIZE_T bytesToMap), (mappingHandle, desiredAccess, offsetHigh, offsetLow, bytesToMap),
            { appendWideText(detailBuffer, L"mapping="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(mappingHandle)); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" offset="); appendHexText(detailBuffer, (static_cast<std::uint64_t>(offsetHigh) << 32) | offsetLow); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(bytesToMap)); appendWideText(detailBuffer, L" base="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(LPVOID, HookedMapViewOfFileEx, gMapViewOfFileExOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"MapViewOfFileEx",
            (HANDLE mappingHandle, DWORD desiredAccess, DWORD offsetHigh, DWORD offsetLow, SIZE_T bytesToMap, LPVOID baseAddress), (mappingHandle, desiredAccess, offsetHigh, offsetLow, bytesToMap, baseAddress),
            { appendWideText(detailBuffer, L"mapping="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(mappingHandle)); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" hint="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(bytesToMap)); appendWideText(detailBuffer, L" base="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })

        // HookedUnmapViewOfFile/FlushViewOfFile: Record mapping view lifecycle and write-back actions; return original BOOL.
        APIMON_SIMPLE_BOOL_HOOK(HookedUnmapViewOfFile, gUnmapViewOfFileOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"UnmapViewOfFile",
            (LPCVOID baseAddress), (baseAddress),
            { appendWideText(detailBuffer, L"base="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedFlushViewOfFile, gFlushViewOfFileOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"FlushViewOfFile",
            (LPCVOID baseAddress, SIZE_T bytesToFlush), (baseAddress, bytesToFlush),
            { appendWideText(detailBuffer, L"base="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(bytesToFlush)); })

#define APIMON_SIMPLE_LSTATUS_HOOK(HookName, OriginalName, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        LSTATUS WINAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const LSTATUS statusValue = OriginalName ArgList; \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kRegistry, ModuleText, ApiText, statusValue, detailBuffer); \
            return statusValue; \
        }

#define APIMON_SIMPLE_NTSTATUS_HOOK(HookName, OriginalName, CategoryValue, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        NTSTATUS NTAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const NTSTATUS statusValue = OriginalName ArgList; \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            SendRawEventWithStatus(CategoryValue, ModuleText, ApiText, statusValue, detailBuffer); \
            return statusValue; \
        }

        // HookedFreeLibrary/GetProcAddress/LdrGetProcedureAddress purpose:
        // - Input: loader unload, export resolution, and ntdll-level procedure resolution parameters;
        // - Processing: Record the dynamic resolution chain to fill the gap where only target API calls are visible but the 'resolution intent' is missing;
        // - Return: preserve original return value and LastError/NTSTATUS.
        APIMON_SIMPLE_BOOL_HOOK(HookedFreeLibrary, gFreeLibraryOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"FreeLibrary",
            (HMODULE moduleHandle), (moduleHandle),
            { appendWideText(detailBuffer, L"module="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle)); })

        FARPROC WINAPI hookedGetProcAddress(HMODULE moduleHandle, LPCSTR procNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gGetProcAddressOriginal(moduleHandle, procNamePointer); }
            const FARPROC kResultPointer = gGetProcAddressOriginal(moduleHandle, procNamePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"module=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle));
            appendWideText(detailBuffer, L" ");
            appendProcNameText(detailBuffer, procNamePointer);
            appendWideText(detailBuffer, L" address=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(kResultPointer));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"GetProcAddress", kResultPointer != nullptr ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultPointer;
        }

        NTSTATUS NTAPI hookedLdrGetProcedureAddress(HMODULE moduleHandle, PANSI_STRING procNamePointer, WORD ordinalValue, PVOID* functionPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gLdrGetProcedureAddressOriginal(moduleHandle, procNamePointer, ordinalValue, functionPointer); }
            const NTSTATUS kStatusValue = gLdrGetProcedureAddressOriginal(moduleHandle, procNamePointer, ordinalValue, functionPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"module=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle));
            appendWideText(detailBuffer, L" name=");
            appendAnsiStringText(detailBuffer, procNamePointer);
            appendWideText(detailBuffer, L" ordinal=");
            appendUnsignedText(detailBuffer, ordinalValue);
            appendWideText(detailBuffer, L" address=");
            appendHexText(detailBuffer, functionPointer != nullptr ? reinterpret_cast<std::uint64_t>(*functionPointer) : 0);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kLoader, L"ntdll", L"LdrGetProcedureAddress", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // HookedReg*Transacted/Restore/Unload/Notify purpose: Complete the advapi32 registry variants; return the original LSTATUS.
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegCreateKeyTransactedW, gRegCreateKeyTransactedWOriginal, L"Advapi32", L"RegCreateKeyTransactedW",
            (HKEY rootKey, LPCWSTR subKeyPointer, DWORD reservedValue, LPWSTR classPointer, DWORD optionsValue, REGSAM samDesired, const LPSECURITY_ATTRIBUTES securityAttributes, PHKEY resultKeyPointer, LPDWORD dispositionPointer, HANDLE transactionHandle, PVOID extendedParameter),
            (rootKey, subKeyPointer, reservedValue, classPointer, optionsValue, samDesired, securityAttributes, resultKeyPointer, dispositionPointer, transactionHandle, extendedParameter),
            { buildRegCreateDetail(detailBuffer, rootKey, subKeyPointer, optionsValue, dispositionPointer != nullptr ? *dispositionPointer : 0); appendWideText(detailBuffer, L" transaction="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); appendWideText(detailBuffer, L" hkeyOut="); appendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegCreateKeyTransactedA, gRegCreateKeyTransactedAOriginal, L"Advapi32", L"RegCreateKeyTransactedA",
            (HKEY rootKey, LPCSTR subKeyPointer, DWORD reservedValue, LPSTR classPointer, DWORD optionsValue, REGSAM samDesired, const LPSECURITY_ATTRIBUTES securityAttributes, PHKEY resultKeyPointer, LPDWORD dispositionPointer, HANDLE transactionHandle, PVOID extendedParameter),
            (rootKey, subKeyPointer, reservedValue, classPointer, optionsValue, samDesired, securityAttributes, resultKeyPointer, dispositionPointer, transactionHandle, extendedParameter),
            { buildRegCreateDetailA(detailBuffer, rootKey, subKeyPointer, optionsValue, dispositionPointer != nullptr ? *dispositionPointer : 0); appendWideText(detailBuffer, L" transaction="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); appendWideText(detailBuffer, L" hkeyOut="); appendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegOpenKeyTransactedW, gRegOpenKeyTransactedWOriginal, L"Advapi32", L"RegOpenKeyTransactedW",
            (HKEY rootKey, LPCWSTR subKeyPointer, DWORD optionsValue, REGSAM samDesired, PHKEY resultKeyPointer, HANDLE transactionHandle, PVOID extendedParameter),
            (rootKey, subKeyPointer, optionsValue, samDesired, resultKeyPointer, transactionHandle, extendedParameter),
            { buildRegOpenDetail(detailBuffer, rootKey, subKeyPointer, samDesired); appendWideText(detailBuffer, L" transaction="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); appendWideText(detailBuffer, L" hkeyOut="); appendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegOpenKeyTransactedA, gRegOpenKeyTransactedAOriginal, L"Advapi32", L"RegOpenKeyTransactedA",
            (HKEY rootKey, LPCSTR subKeyPointer, DWORD optionsValue, REGSAM samDesired, PHKEY resultKeyPointer, HANDLE transactionHandle, PVOID extendedParameter),
            (rootKey, subKeyPointer, optionsValue, samDesired, resultKeyPointer, transactionHandle, extendedParameter),
            { buildRegOpenDetailA(detailBuffer, rootKey, subKeyPointer, samDesired); appendWideText(detailBuffer, L" transaction="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); appendWideText(detailBuffer, L" hkeyOut="); appendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegDeleteKeyTransactedW, gRegDeleteKeyTransactedWOriginal, L"Advapi32", L"RegDeleteKeyTransactedW",
            (HKEY rootKey, LPCWSTR subKeyPointer, REGSAM viewValue, DWORD reservedValue, HANDLE transactionHandle, PVOID extendedParameter),
            (rootKey, subKeyPointer, viewValue, reservedValue, transactionHandle, extendedParameter),
            { buildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, viewValue); appendWideText(detailBuffer, L" transaction="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegDeleteKeyTransactedA, gRegDeleteKeyTransactedAOriginal, L"Advapi32", L"RegDeleteKeyTransactedA",
            (HKEY rootKey, LPCSTR subKeyPointer, REGSAM viewValue, DWORD reservedValue, HANDLE transactionHandle, PVOID extendedParameter),
            (rootKey, subKeyPointer, viewValue, reservedValue, transactionHandle, extendedParameter),
            { buildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, viewValue); appendWideText(detailBuffer, L" transaction="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); })

        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegReplaceKeyW, gRegReplaceKeyWOriginal, L"Advapi32", L"RegReplaceKeyW",
            (HKEY rootKey, LPCWSTR subKeyPointer, LPCWSTR newFilePointer, LPCWSTR oldFilePointer), (rootKey, subKeyPointer, newFilePointer, oldFilePointer),
            { buildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, 0); appendWideText(detailBuffer, L" newFile="); appendWideText(detailBuffer, newFilePointer); appendWideText(detailBuffer, L" oldFile="); appendWideText(detailBuffer, oldFilePointer); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegReplaceKeyA, gRegReplaceKeyAOriginal, L"Advapi32", L"RegReplaceKeyA",
            (HKEY rootKey, LPCSTR subKeyPointer, LPCSTR newFilePointer, LPCSTR oldFilePointer), (rootKey, subKeyPointer, newFilePointer, oldFilePointer),
            { buildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, 0); appendWideText(detailBuffer, L" newFile="); appendAnsiText(detailBuffer, newFilePointer); appendWideText(detailBuffer, L" oldFile="); appendAnsiText(detailBuffer, oldFilePointer); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegRestoreKeyW, gRegRestoreKeyWOriginal, L"Advapi32", L"RegRestoreKeyW",
            (HKEY keyHandle, LPCWSTR filePointer, DWORD flagsValue), (keyHandle, filePointer, flagsValue),
            { appendWideText(detailBuffer, L"hkey="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" file="); appendWideText(detailBuffer, filePointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegRestoreKeyA, gRegRestoreKeyAOriginal, L"Advapi32", L"RegRestoreKeyA",
            (HKEY keyHandle, LPCSTR filePointer, DWORD flagsValue), (keyHandle, filePointer, flagsValue),
            { appendWideText(detailBuffer, L"hkey="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" file="); appendAnsiText(detailBuffer, filePointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegUnLoadKeyW, gRegUnLoadKeyWOriginal, L"Advapi32", L"RegUnLoadKeyW",
            (HKEY rootKey, LPCWSTR subKeyPointer), (rootKey, subKeyPointer),
            { buildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, 0); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegUnLoadKeyA, gRegUnLoadKeyAOriginal, L"Advapi32", L"RegUnLoadKeyA",
            (HKEY rootKey, LPCSTR subKeyPointer), (rootKey, subKeyPointer),
            { buildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, 0); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegLoadAppKeyW, gRegLoadAppKeyWOriginal, L"Advapi32", L"RegLoadAppKeyW",
            (LPCWSTR filePointer, PHKEY resultKeyPointer, REGSAM samDesired, DWORD optionsValue, DWORD reservedValue), (filePointer, resultKeyPointer, samDesired, optionsValue, reservedValue),
            { appendWideText(detailBuffer, L"file="); appendWideText(detailBuffer, filePointer); appendWideText(detailBuffer, L" sam="); appendHexText(detailBuffer, samDesired); appendWideText(detailBuffer, L" options="); appendHexText(detailBuffer, optionsValue); appendWideText(detailBuffer, L" hkeyOut="); appendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegLoadAppKeyA, gRegLoadAppKeyAOriginal, L"Advapi32", L"RegLoadAppKeyA",
            (LPCSTR filePointer, PHKEY resultKeyPointer, REGSAM samDesired, DWORD optionsValue, DWORD reservedValue), (filePointer, resultKeyPointer, samDesired, optionsValue, reservedValue),
            { appendWideText(detailBuffer, L"file="); appendAnsiText(detailBuffer, filePointer); appendWideText(detailBuffer, L" sam="); appendHexText(detailBuffer, samDesired); appendWideText(detailBuffer, L" options="); appendHexText(detailBuffer, optionsValue); appendWideText(detailBuffer, L" hkeyOut="); appendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0); })
        APIMON_SIMPLE_LSTATUS_HOOK(HookedRegNotifyChangeKeyValue, gRegNotifyChangeKeyValueOriginal, L"Advapi32", L"RegNotifyChangeKeyValue",
            (HKEY keyHandle, BOOL watchSubtree, DWORD notifyFilter, HANDLE eventHandle, BOOL asynchronous), (keyHandle, watchSubtree, notifyFilter, eventHandle, asynchronous),
            { appendWideText(detailBuffer, L"hkey="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" subtree="); appendUnsignedText(detailBuffer, watchSubtree != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" filter="); appendHexText(detailBuffer, notifyFilter); appendWideText(detailBuffer, L" event="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventHandle)); appendWideText(detailBuffer, L" async="); appendUnsignedText(detailBuffer, asynchronous != FALSE ? 1ULL : 0ULL); })

        // HookedNtClose/native registry variants purpose: supplement ntdll handle closure and advanced registry native APIs; return original NTSTATUS.
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtClose, gNtCloseOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtClose",
            (HANDLE handleValue), (handleValue),
            { buildSimpleHandleDetail(detailBuffer, L"handle", handleValue); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtCreateKeyTransacted, gNtCreateKeyTransactedOriginal, ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtCreateKeyTransacted",
            (PHANDLE keyHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, ULONG titleIndex, PUNICODE_STRING classPointer, ULONG createOptions, HANDLE transactionHandle, PULONG dispositionPointer),
            (keyHandlePointer, desiredAccess, objectAttributes, titleIndex, classPointer, createOptions, transactionHandle, dispositionPointer),
            { appendWideText(detailBuffer, L"key="); appendObjectNameText(detailBuffer, objectAttributes); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" options="); appendHexText(detailBuffer, createOptions); appendWideText(detailBuffer, L" transaction="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); appendWideText(detailBuffer, L" hkeyOut="); appendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtOpenKeyTransacted, gNtOpenKeyTransactedOriginal, ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtOpenKeyTransacted",
            (PHANDLE keyHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, HANDLE transactionHandle),
            (keyHandlePointer, desiredAccess, objectAttributes, transactionHandle),
            { appendWideText(detailBuffer, L"key="); appendObjectNameText(detailBuffer, objectAttributes); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" transaction="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); appendWideText(detailBuffer, L" hkeyOut="); appendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtOpenKeyTransactedEx, gNtOpenKeyTransactedExOriginal, ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtOpenKeyTransactedEx",
            (PHANDLE keyHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, ULONG openOptions, HANDLE transactionHandle),
            (keyHandlePointer, desiredAccess, objectAttributes, openOptions, transactionHandle),
            { appendWideText(detailBuffer, L"key="); appendObjectNameText(detailBuffer, objectAttributes); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" options="); appendHexText(detailBuffer, openOptions); appendWideText(detailBuffer, L" transaction="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtReplaceKey, gNtReplaceKeyOriginal, ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtReplaceKey",
            (POBJECT_ATTRIBUTES newFileObjectAttributes, HANDLE targetHandle, POBJECT_ATTRIBUTES oldFileObjectAttributes),
            (newFileObjectAttributes, targetHandle, oldFileObjectAttributes),
            { appendWideText(detailBuffer, L"target="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(targetHandle)); appendWideText(detailBuffer, L" newFile="); appendObjectNameText(detailBuffer, newFileObjectAttributes); appendWideText(detailBuffer, L" oldFile="); appendObjectNameText(detailBuffer, oldFileObjectAttributes); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtRestoreKey, gNtRestoreKeyOriginal, ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtRestoreKey",
            (HANDLE keyHandle, HANDLE fileHandle, ULONG flagsValue), (keyHandle, fileHandle, flagsValue),
            { appendWideText(detailBuffer, L"hkey="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" file="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtUnloadKey, gNtUnloadKeyOriginal, ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtUnloadKey",
            (POBJECT_ATTRIBUTES targetKey), (targetKey),
            { appendWideText(detailBuffer, L"key="); appendObjectNameText(detailBuffer, targetKey); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtUnloadKey2, gNtUnloadKey2Original, ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtUnloadKey2",
            (POBJECT_ATTRIBUTES targetKey, ULONG flagsValue), (targetKey, flagsValue),
            { appendWideText(detailBuffer, L"key="); appendObjectNameText(detailBuffer, targetKey); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtUnloadKeyEx, gNtUnloadKeyExOriginal, ks::winapi_monitor::EventCategory::kRegistry, L"ntdll", L"NtUnloadKeyEx",
            (POBJECT_ATTRIBUTES targetKey, HANDLE eventHandle), (targetKey, eventHandle),
            { appendWideText(detailBuffer, L"key="); appendObjectNameText(detailBuffer, targetKey); appendWideText(detailBuffer, L" event="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventHandle)); })

        // HookedToken* purpose:
        // - Input: Key parameters for token open, copy, privilege escalation, and process creation with token;
        // - Handling: Supplement Win32-layer observation for privilege escalation, token theft, and user context switching behaviors.
        // - Returns: preserves the original BOOL result and restores LastError.
        APIMON_SIMPLE_BOOL_HOOK(HookedOpenProcessToken, gOpenProcessTokenOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"OpenProcessToken",
            (HANDLE processHandle, DWORD desiredAccess, PHANDLE tokenHandlePointer), (processHandle, desiredAccess, tokenHandlePointer),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" token="); appendHexText(detailBuffer, tokenHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*tokenHandlePointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedOpenThreadToken, gOpenThreadTokenOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"OpenThreadToken",
            (HANDLE threadHandle, DWORD desiredAccess, BOOL openAsSelf, PHANDLE tokenHandlePointer), (threadHandle, desiredAccess, openAsSelf, tokenHandlePointer),
            { appendWideText(detailBuffer, L"thread="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle)); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" openAsSelf="); appendUnsignedText(detailBuffer, openAsSelf != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" token="); appendHexText(detailBuffer, tokenHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*tokenHandlePointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedAdjustTokenPrivileges, gAdjustTokenPrivilegesOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"AdjustTokenPrivileges",
            (HANDLE tokenHandle, BOOL disableAllPrivileges, PTOKEN_PRIVILEGES newStatePointer, DWORD bufferLength, PTOKEN_PRIVILEGES previousStatePointer, PDWORD returnLengthPointer),
            (tokenHandle, disableAllPrivileges, newStatePointer, bufferLength, previousStatePointer, returnLengthPointer),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); appendWideText(detailBuffer, L" disableAll="); appendUnsignedText(detailBuffer, disableAllPrivileges != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" privilegeCount="); appendUnsignedText(detailBuffer, newStatePointer != nullptr ? newStatePointer->PrivilegeCount : 0); appendWideText(detailBuffer, L" returnLen="); appendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedDuplicateToken, gDuplicateTokenOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"DuplicateToken",
            (HANDLE existingTokenHandle, SECURITY_IMPERSONATION_LEVEL impersonationLevel, PHANDLE newTokenHandlePointer), (existingTokenHandle, impersonationLevel, newTokenHandlePointer),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(existingTokenHandle)); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(impersonationLevel)); appendWideText(detailBuffer, L" newToken="); appendHexText(detailBuffer, newTokenHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*newTokenHandlePointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedDuplicateTokenEx, gDuplicateTokenExOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"DuplicateTokenEx",
            (HANDLE existingTokenHandle, DWORD desiredAccess, LPSECURITY_ATTRIBUTES tokenAttributes, SECURITY_IMPERSONATION_LEVEL impersonationLevel, TOKEN_TYPE tokenType, PHANDLE newTokenHandlePointer),
            (existingTokenHandle, desiredAccess, tokenAttributes, impersonationLevel, tokenType, newTokenHandlePointer),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(existingTokenHandle)); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(impersonationLevel)); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(tokenType)); appendWideText(detailBuffer, L" newToken="); appendHexText(detailBuffer, newTokenHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*newTokenHandlePointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCreateProcessAsUserW, gCreateProcessAsUserWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CreateProcessAsUserW",
            (HANDLE tokenHandle, LPCWSTR applicationNamePointer, LPWSTR commandLinePointer, LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles, DWORD creationFlags, LPVOID environmentPointer, LPCWSTR currentDirectoryPointer, LPSTARTUPINFOW startupInfoPointer, LPPROCESS_INFORMATION processInformationPointer),
            (tokenHandle, applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInformationPointer),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); appendWideText(detailBuffer, L" app="); appendWideText(detailBuffer, applicationNamePointer); appendWideText(detailBuffer, L" cmd="); appendWideText(detailBuffer, commandLinePointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, creationFlags); appendWideText(detailBuffer, L" childPid="); appendUnsignedText(detailBuffer, processInformationPointer != nullptr ? processInformationPointer->dwProcessId : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCreateProcessAsUserA, gCreateProcessAsUserAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CreateProcessAsUserA",
            (HANDLE tokenHandle, LPCSTR applicationNamePointer, LPSTR commandLinePointer, LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles, DWORD creationFlags, LPVOID environmentPointer, LPCSTR currentDirectoryPointer, LPSTARTUPINFOA startupInfoPointer, LPPROCESS_INFORMATION processInformationPointer),
            (tokenHandle, applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInformationPointer),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); appendWideText(detailBuffer, L" app="); appendAnsiText(detailBuffer, applicationNamePointer); appendWideText(detailBuffer, L" cmd="); appendAnsiText(detailBuffer, commandLinePointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, creationFlags); appendWideText(detailBuffer, L" childPid="); appendUnsignedText(detailBuffer, processInformationPointer != nullptr ? processInformationPointer->dwProcessId : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCreateProcessWithTokenW, gCreateProcessWithTokenWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CreateProcessWithTokenW",
            (HANDLE tokenHandle, DWORD logonFlags, LPCWSTR applicationNamePointer, LPWSTR commandLinePointer, DWORD creationFlags, LPVOID environmentPointer, LPCWSTR currentDirectoryPointer, LPSTARTUPINFOW startupInfoPointer, LPPROCESS_INFORMATION processInformationPointer),
            (tokenHandle, logonFlags, applicationNamePointer, commandLinePointer, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInformationPointer),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); appendWideText(detailBuffer, L" logonFlags="); appendHexText(detailBuffer, logonFlags); appendWideText(detailBuffer, L" app="); appendWideText(detailBuffer, applicationNamePointer); appendWideText(detailBuffer, L" cmd="); appendWideText(detailBuffer, commandLinePointer); appendWideText(detailBuffer, L" childPid="); appendUnsignedText(detailBuffer, processInformationPointer != nullptr ? processInformationPointer->dwProcessId : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedLookupPrivilegeValueW, gLookupPrivilegeValueWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"LookupPrivilegeValueW",
            (LPCWSTR systemNamePointer, LPCWSTR namePointer, PLUID luidPointer), (systemNamePointer, namePointer, luidPointer),
            { appendWideText(detailBuffer, L"system="); appendWideText(detailBuffer, systemNamePointer); appendWideText(detailBuffer, L" name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" luidLow="); appendHexText(detailBuffer, luidPointer != nullptr ? luidPointer->LowPart : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedLookupPrivilegeValueA, gLookupPrivilegeValueAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"LookupPrivilegeValueA",
            (LPCSTR systemNamePointer, LPCSTR namePointer, PLUID luidPointer), (systemNamePointer, namePointer, luidPointer),
            { appendWideText(detailBuffer, L"system="); appendAnsiText(detailBuffer, systemNamePointer); appendWideText(detailBuffer, L" name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" luidLow="); appendHexText(detailBuffer, luidPointer != nullptr ? luidPointer->LowPart : 0); })

        // HookedService* purpose:
        // - Input: SCM/Service open, create, configure, start, control, delete, and close parameters;
        // - Processing: Complete Advapi32-level observation for service installation and driver service control paths.
        // - Return: Keep the original SC_HANDLE/BOOL result and restore LastError.
        APIMON_SIMPLE_HANDLE_HOOK(SC_HANDLE, HookedOpenSCManagerW, gOpenScManagerWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"OpenSCManagerW",
            (LPCWSTR machineNamePointer, LPCWSTR databaseNamePointer, DWORD desiredAccess), (machineNamePointer, databaseNamePointer, desiredAccess),
            { appendWideText(detailBuffer, L"machine="); appendWideText(detailBuffer, machineNamePointer); appendWideText(detailBuffer, L" database="); appendWideText(detailBuffer, databaseNamePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(SC_HANDLE, HookedOpenSCManagerA, gOpenScManagerAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"OpenSCManagerA",
            (LPCSTR machineNamePointer, LPCSTR databaseNamePointer, DWORD desiredAccess), (machineNamePointer, databaseNamePointer, desiredAccess),
            { appendWideText(detailBuffer, L"machine="); appendAnsiText(detailBuffer, machineNamePointer); appendWideText(detailBuffer, L" database="); appendAnsiText(detailBuffer, databaseNamePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(SC_HANDLE, HookedOpenServiceW, gOpenServiceWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"OpenServiceW",
            (SC_HANDLE managerHandle, LPCWSTR serviceNamePointer, DWORD desiredAccess), (managerHandle, serviceNamePointer, desiredAccess),
            { appendWideText(detailBuffer, L"scm="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(managerHandle)); appendWideText(detailBuffer, L" service="); appendWideText(detailBuffer, serviceNamePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(SC_HANDLE, HookedOpenServiceA, gOpenServiceAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"OpenServiceA",
            (SC_HANDLE managerHandle, LPCSTR serviceNamePointer, DWORD desiredAccess), (managerHandle, serviceNamePointer, desiredAccess),
            { appendWideText(detailBuffer, L"scm="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(managerHandle)); appendWideText(detailBuffer, L" service="); appendAnsiText(detailBuffer, serviceNamePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(SC_HANDLE, HookedCreateServiceW, gCreateServiceWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CreateServiceW",
            (SC_HANDLE managerHandle, LPCWSTR serviceNamePointer, LPCWSTR displayNamePointer, DWORD desiredAccess, DWORD serviceType, DWORD startType, DWORD errorControl, LPCWSTR binaryPathPointer, LPCWSTR loadOrderGroupPointer, LPDWORD tagIdPointer, LPCWSTR dependenciesPointer, LPCWSTR serviceStartNamePointer, LPCWSTR passwordPointer),
            (managerHandle, serviceNamePointer, displayNamePointer, desiredAccess, serviceType, startType, errorControl, binaryPathPointer, loadOrderGroupPointer, tagIdPointer, dependenciesPointer, serviceStartNamePointer, passwordPointer),
            { appendWideText(detailBuffer, L"service="); appendWideText(detailBuffer, serviceNamePointer); appendWideText(detailBuffer, L" type="); appendHexText(detailBuffer, serviceType); appendWideText(detailBuffer, L" start="); appendHexText(detailBuffer, startType); appendWideText(detailBuffer, L" path="); appendWideText(detailBuffer, binaryPathPointer); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(SC_HANDLE, HookedCreateServiceA, gCreateServiceAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CreateServiceA",
            (SC_HANDLE managerHandle, LPCSTR serviceNamePointer, LPCSTR displayNamePointer, DWORD desiredAccess, DWORD serviceType, DWORD startType, DWORD errorControl, LPCSTR binaryPathPointer, LPCSTR loadOrderGroupPointer, LPDWORD tagIdPointer, LPCSTR dependenciesPointer, LPCSTR serviceStartNamePointer, LPCSTR passwordPointer),
            (managerHandle, serviceNamePointer, displayNamePointer, desiredAccess, serviceType, startType, errorControl, binaryPathPointer, loadOrderGroupPointer, tagIdPointer, dependenciesPointer, serviceStartNamePointer, passwordPointer),
            { appendWideText(detailBuffer, L"service="); appendAnsiText(detailBuffer, serviceNamePointer); appendWideText(detailBuffer, L" type="); appendHexText(detailBuffer, serviceType); appendWideText(detailBuffer, L" start="); appendHexText(detailBuffer, startType); appendWideText(detailBuffer, L" path="); appendAnsiText(detailBuffer, binaryPathPointer); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedChangeServiceConfigW, gChangeServiceConfigWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ChangeServiceConfigW",
            (SC_HANDLE serviceHandle, DWORD serviceType, DWORD startType, DWORD errorControl, LPCWSTR binaryPathPointer, LPCWSTR loadOrderGroupPointer, LPDWORD tagIdPointer, LPCWSTR dependenciesPointer, LPCWSTR serviceStartNamePointer, LPCWSTR passwordPointer, LPCWSTR displayNamePointer),
            (serviceHandle, serviceType, startType, errorControl, binaryPathPointer, loadOrderGroupPointer, tagIdPointer, dependenciesPointer, serviceStartNamePointer, passwordPointer, displayNamePointer),
            { appendWideText(detailBuffer, L"service="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); appendWideText(detailBuffer, L" type="); appendHexText(detailBuffer, serviceType); appendWideText(detailBuffer, L" start="); appendHexText(detailBuffer, startType); appendWideText(detailBuffer, L" path="); appendWideText(detailBuffer, binaryPathPointer); })
        APIMON_SIMPLE_BOOL_HOOK(HookedChangeServiceConfigA, gChangeServiceConfigAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ChangeServiceConfigA",
            (SC_HANDLE serviceHandle, DWORD serviceType, DWORD startType, DWORD errorControl, LPCSTR binaryPathPointer, LPCSTR loadOrderGroupPointer, LPDWORD tagIdPointer, LPCSTR dependenciesPointer, LPCSTR serviceStartNamePointer, LPCSTR passwordPointer, LPCSTR displayNamePointer),
            (serviceHandle, serviceType, startType, errorControl, binaryPathPointer, loadOrderGroupPointer, tagIdPointer, dependenciesPointer, serviceStartNamePointer, passwordPointer, displayNamePointer),
            { appendWideText(detailBuffer, L"service="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); appendWideText(detailBuffer, L" type="); appendHexText(detailBuffer, serviceType); appendWideText(detailBuffer, L" start="); appendHexText(detailBuffer, startType); appendWideText(detailBuffer, L" path="); appendAnsiText(detailBuffer, binaryPathPointer); })
        APIMON_SIMPLE_BOOL_HOOK(HookedStartServiceW, gStartServiceWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"StartServiceW",
            (SC_HANDLE serviceHandle, DWORD argumentCount, LPCWSTR* argumentVector), (serviceHandle, argumentCount, argumentVector),
            { appendWideText(detailBuffer, L"service="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); appendWideText(detailBuffer, L" argc="); appendUnsignedText(detailBuffer, argumentCount); })
        APIMON_SIMPLE_BOOL_HOOK(HookedStartServiceA, gStartServiceAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"StartServiceA",
            (SC_HANDLE serviceHandle, DWORD argumentCount, LPCSTR* argumentVector), (serviceHandle, argumentCount, argumentVector),
            { appendWideText(detailBuffer, L"service="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); appendWideText(detailBuffer, L" argc="); appendUnsignedText(detailBuffer, argumentCount); })
        APIMON_SIMPLE_BOOL_HOOK(HookedControlService, gControlServiceOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ControlService",
            (SC_HANDLE serviceHandle, DWORD controlCode, LPSERVICE_STATUS serviceStatusPointer), (serviceHandle, controlCode, serviceStatusPointer),
            { appendWideText(detailBuffer, L"service="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); appendWideText(detailBuffer, L" control="); appendHexText(detailBuffer, controlCode); })
        APIMON_SIMPLE_BOOL_HOOK(HookedDeleteService, gDeleteServiceOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"DeleteService",
            (SC_HANDLE serviceHandle), (serviceHandle),
            { buildSimpleHandleDetail(detailBuffer, L"service", serviceHandle); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCloseServiceHandle, gCloseServiceHandleOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CloseServiceHandle",
            (SC_HANDLE serviceHandle), (serviceHandle),
            { buildSimpleHandleDetail(detailBuffer, L"service", serviceHandle); })

#define APIMON_SIMPLE_WSA_INT_HOOK(HookName, OriginalName, ApiText, SuccessExpression, ParamList, ArgList, DetailBlock) \
        int WSAAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const int resultValue = OriginalName ArgList; \
            const int errorValue = (SuccessExpression) ? 0 : ::WSAGetLastError(); \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            sendMonitorEventRaw(ks::winapi_monitor::EventCategory::kNetwork, L"Ws2_32", ApiText, errorValue, detailBuffer); \
            if (!(SuccessExpression)) { ::WSASetLastError(errorValue); } \
            return resultValue; \
        }

        // HookedWs2Extended:
        // - Input: Extended Winsock control, address-oriented WSASendTo/WSARecvFrom, and name resolution parameters;
        // - Handling: Supplement high-frequency network paths beyond basic send/recv/connect.
        // - Return: preserves the original Winsock return value and restores the WSA error code.
        APIMON_SIMPLE_WSA_INT_HOOK(HookedWSAIoctl, gWsaIoctlOriginal, L"WSAIoctl", resultValue == 0,
            (SOCKET socketValue, DWORD ioControlCode, LPVOID inBufferPointer, DWORD inBufferSize, LPVOID outBufferPointer, DWORD outBufferSize, LPDWORD bytesReturnedPointer, LPWSAOVERLAPPED overlappedPointer, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutinePointer),
            (socketValue, ioControlCode, inBufferPointer, inBufferSize, outBufferPointer, outBufferSize, bytesReturnedPointer, overlappedPointer, completionRoutinePointer),
            { appendWideText(detailBuffer, L"socket="); appendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); appendWideText(detailBuffer, L" code="); appendHexText(detailBuffer, ioControlCode); appendWideText(detailBuffer, L" in="); appendUnsignedText(detailBuffer, inBufferSize); appendWideText(detailBuffer, L" out="); appendUnsignedText(detailBuffer, outBufferSize); appendWideText(detailBuffer, L" returned="); appendUnsignedText(detailBuffer, bytesReturnedPointer != nullptr ? *bytesReturnedPointer : 0); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedWSASendTo, gWsaSendToOriginal, L"WSASendTo", resultValue == 0,
            (SOCKET socketValue, LPWSABUF buffersPointer, DWORD bufferCount, LPDWORD bytesSentPointer, DWORD flagsValue, const sockaddr* toPointer, int toLength, LPWSAOVERLAPPED overlappedPointer, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutinePointer),
            (socketValue, buffersPointer, bufferCount, bytesSentPointer, flagsValue, toPointer, toLength, overlappedPointer, completionRoutinePointer),
            { buildSocketDetail(detailBuffer, L"sendto", socketValue, sumWsaBufferLength(buffersPointer, bufferCount), bytesSentPointer != nullptr ? static_cast<int>(*bytesSentPointer) : 0, flagsValue, toPointer, toLength); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedWSARecvFrom, gWsaRecvFromOriginal, L"WSARecvFrom", resultValue == 0,
            (SOCKET socketValue, LPWSABUF buffersPointer, DWORD bufferCount, LPDWORD bytesReceivedPointer, LPDWORD flagsPointer, sockaddr* fromPointer, LPINT fromLengthPointer, LPWSAOVERLAPPED overlappedPointer, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutinePointer),
            (socketValue, buffersPointer, bufferCount, bytesReceivedPointer, flagsPointer, fromPointer, fromLengthPointer, overlappedPointer, completionRoutinePointer),
            { buildSocketDetail(detailBuffer, L"recvfrom", socketValue, sumWsaBufferLength(buffersPointer, bufferCount), bytesReceivedPointer != nullptr ? static_cast<int>(*bytesReceivedPointer) : 0, flagsPointer != nullptr ? *flagsPointer : 0, fromPointer, fromLengthPointer != nullptr ? *fromLengthPointer : 0); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedGetAddrInfoW, gGetAddrInfoWOriginal, L"GetAddrInfoW", resultValue == 0,
            (PCWSTR nodeNamePointer, PCWSTR serviceNamePointer, const ADDRINFOW* hintsPointer, PADDRINFOW* resultPointer), (nodeNamePointer, serviceNamePointer, hintsPointer, resultPointer),
            { appendWideText(detailBuffer, L"node="); appendWideText(detailBuffer, nodeNamePointer); appendWideText(detailBuffer, L" service="); appendWideText(detailBuffer, serviceNamePointer); appendWideText(detailBuffer, L" result="); appendHexText(detailBuffer, resultPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultPointer) : 0); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedGetAddrInfoA, gGetAddrInfoAOriginal, L"getaddrinfo", resultValue == 0,
            (PCSTR nodeNamePointer, PCSTR serviceNamePointer, const ADDRINFOA* hintsPointer, PADDRINFOA* resultPointer), (nodeNamePointer, serviceNamePointer, hintsPointer, resultPointer),
            { appendWideText(detailBuffer, L"node="); appendAnsiText(detailBuffer, nodeNamePointer); appendWideText(detailBuffer, L" service="); appendAnsiText(detailBuffer, serviceNamePointer); appendWideText(detailBuffer, L" result="); appendHexText(detailBuffer, resultPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultPointer) : 0); })

        // hookedDnsQueryW/A purpose: record explicit DNSAPI resolution requests; return the original DNS_STATUS.
        DNS_STATUS WINAPI hookedDnsQueryW(PCWSTR namePointer, WORD typeValue, DWORD optionsValue, PVOID extraPointer, PDNS_RECORDW* queryResultsPointer, PVOID* reservedPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gDnsQueryWOriginal(namePointer, typeValue, optionsValue, extraPointer, queryResultsPointer, reservedPointer); }
            const DNS_STATUS kStatusValue = gDnsQueryWOriginal(namePointer, typeValue, optionsValue, extraPointer, queryResultsPointer, reservedPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"name=");
            appendWideText(detailBuffer, namePointer);
            appendWideText(detailBuffer, L" type=");
            appendUnsignedText(detailBuffer, typeValue);
            appendWideText(detailBuffer, L" options=");
            appendHexText(detailBuffer, optionsValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kNetwork, L"Dnsapi", L"DnsQuery_W", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        DNS_STATUS WINAPI hookedDnsQueryA(PCSTR namePointer, WORD typeValue, DWORD optionsValue, PVOID extraPointer, PDNS_RECORDA* queryResultsPointer, PVOID* reservedPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gDnsQueryAOriginal(namePointer, typeValue, optionsValue, extraPointer, queryResultsPointer, reservedPointer); }
            const DNS_STATUS kStatusValue = gDnsQueryAOriginal(namePointer, typeValue, optionsValue, extraPointer, queryResultsPointer, reservedPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"name=");
            appendAnsiText(detailBuffer, namePointer);
            appendWideText(detailBuffer, L" type=");
            appendUnsignedText(detailBuffer, typeValue);
            appendWideText(detailBuffer, L" options=");
            appendHexText(detailBuffer, optionsValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kNetwork, L"Dnsapi", L"DnsQuery_A", kStatusValue, detailBuffer);
            return kStatusValue;
        }

        // HookedWinHttp/WinInet purpose:
        // - Input: HTTP session/connect/request/read/write/close parameters.
        // - Processing: Restore high-level network semantics (URL/host/verb) when only Winsock is hooked.
        // - Return: Preserve original HINTERNET/BOOL and restore LastError.
        APIMON_SIMPLE_HANDLE_HOOK(HINTERNET, HookedWinHttpOpen, gWinHttpOpenOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpOpen",
            (LPCWSTR userAgentPointer, DWORD accessType, LPCWSTR proxyNamePointer, LPCWSTR proxyBypassPointer, DWORD flagsValue), (userAgentPointer, accessType, proxyNamePointer, proxyBypassPointer, flagsValue),
            { appendWideText(detailBuffer, L"agent="); appendWideText(detailBuffer, userAgentPointer); appendWideText(detailBuffer, L" accessType="); appendUnsignedText(detailBuffer, accessType); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HINTERNET, HookedWinHttpConnect, gWinHttpConnectOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpConnect",
            (HINTERNET sessionHandle, LPCWSTR serverNamePointer, INTERNET_PORT serverPort, DWORD reservedValue), (sessionHandle, serverNamePointer, serverPort, reservedValue),
            { appendWideText(detailBuffer, L"session="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sessionHandle)); appendWideText(detailBuffer, L" host="); appendWideText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" port="); appendUnsignedText(detailBuffer, serverPort); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HINTERNET, HookedWinHttpOpenRequest, gWinHttpOpenRequestOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpOpenRequest",
            (HINTERNET connectHandle, LPCWSTR verbPointer, LPCWSTR objectNamePointer, LPCWSTR versionPointer, LPCWSTR referrerPointer, LPCWSTR* acceptTypesPointer, DWORD flagsValue),
            (connectHandle, verbPointer, objectNamePointer, versionPointer, referrerPointer, acceptTypesPointer, flagsValue),
            { appendWideText(detailBuffer, L"connect="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(connectHandle)); appendWideText(detailBuffer, L" verb="); appendWideText(detailBuffer, verbPointer); appendWideText(detailBuffer, L" object="); appendWideText(detailBuffer, objectNamePointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpSendRequest, gWinHttpSendRequestOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpSendRequest",
            (HINTERNET requestHandle, LPCWSTR headersPointer, DWORD headersLength, LPVOID optionalPointer, DWORD optionalLength, DWORD totalLength, DWORD_PTR contextValue),
            (requestHandle, headersPointer, headersLength, optionalPointer, optionalLength, totalLength, contextValue),
            { appendWideText(detailBuffer, L"request="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); appendWideText(detailBuffer, L" headersLen="); appendUnsignedText(detailBuffer, headersLength); appendWideText(detailBuffer, L" optionalLen="); appendUnsignedText(detailBuffer, optionalLength); appendWideText(detailBuffer, L" total="); appendUnsignedText(detailBuffer, totalLength); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpReceiveResponse, gWinHttpReceiveResponseOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpReceiveResponse",
            (HINTERNET requestHandle, LPVOID reservedPointer), (requestHandle, reservedPointer),
            { buildSimpleHandleDetail(detailBuffer, L"request", requestHandle); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpReadData, gWinHttpReadDataOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpReadData",
            (HINTERNET requestHandle, LPVOID bufferPointer, DWORD bytesToRead, LPDWORD bytesReadPointer), (requestHandle, bufferPointer, bytesToRead, bytesReadPointer),
            { appendWideText(detailBuffer, L"request="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); appendWideText(detailBuffer, L" requestBytes="); appendUnsignedText(detailBuffer, bytesToRead); appendWideText(detailBuffer, L" read="); appendUnsignedText(detailBuffer, bytesReadPointer != nullptr ? *bytesReadPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpWriteData, gWinHttpWriteDataOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpWriteData",
            (HINTERNET requestHandle, LPCVOID bufferPointer, DWORD bytesToWrite, LPDWORD bytesWrittenPointer), (requestHandle, bufferPointer, bytesToWrite, bytesWrittenPointer),
            { appendWideText(detailBuffer, L"request="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); appendWideText(detailBuffer, L" requestBytes="); appendUnsignedText(detailBuffer, bytesToWrite); appendWideText(detailBuffer, L" written="); appendUnsignedText(detailBuffer, bytesWrittenPointer != nullptr ? *bytesWrittenPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpCloseHandle, gWinHttpCloseHandleOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpCloseHandle",
            (HINTERNET internetHandle), (internetHandle),
            { buildSimpleHandleDetail(detailBuffer, L"handle", internetHandle); })

        APIMON_SIMPLE_HANDLE_HOOK(HINTERNET, HookedInternetOpenW, gInternetOpenWOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetOpenW",
            (LPCWSTR agentPointer, DWORD accessType, LPCWSTR proxyNamePointer, LPCWSTR proxyBypassPointer, DWORD flagsValue), (agentPointer, accessType, proxyNamePointer, proxyBypassPointer, flagsValue),
            { appendWideText(detailBuffer, L"agent="); appendWideText(detailBuffer, agentPointer); appendWideText(detailBuffer, L" accessType="); appendUnsignedText(detailBuffer, accessType); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HINTERNET, HookedInternetOpenA, gInternetOpenAOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetOpenA",
            (LPCSTR agentPointer, DWORD accessType, LPCSTR proxyNamePointer, LPCSTR proxyBypassPointer, DWORD flagsValue), (agentPointer, accessType, proxyNamePointer, proxyBypassPointer, flagsValue),
            { appendWideText(detailBuffer, L"agent="); appendAnsiText(detailBuffer, agentPointer); appendWideText(detailBuffer, L" accessType="); appendUnsignedText(detailBuffer, accessType); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HINTERNET, HookedInternetConnectW, gInternetConnectWOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetConnectW",
            (HINTERNET internetHandle, LPCWSTR serverNamePointer, INTERNET_PORT serverPort, LPCWSTR userNamePointer, LPCWSTR passwordPointer, DWORD serviceValue, DWORD flagsValue, DWORD_PTR contextValue),
            (internetHandle, serverNamePointer, serverPort, userNamePointer, passwordPointer, serviceValue, flagsValue, contextValue),
            { appendWideText(detailBuffer, L"root="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); appendWideText(detailBuffer, L" host="); appendWideText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" port="); appendUnsignedText(detailBuffer, serverPort); appendWideText(detailBuffer, L" service="); appendUnsignedText(detailBuffer, serviceValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HINTERNET, HookedInternetConnectA, gInternetConnectAOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetConnectA",
            (HINTERNET internetHandle, LPCSTR serverNamePointer, INTERNET_PORT serverPort, LPCSTR userNamePointer, LPCSTR passwordPointer, DWORD serviceValue, DWORD flagsValue, DWORD_PTR contextValue),
            (internetHandle, serverNamePointer, serverPort, userNamePointer, passwordPointer, serviceValue, flagsValue, contextValue),
            { appendWideText(detailBuffer, L"root="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); appendWideText(detailBuffer, L" host="); appendAnsiText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" port="); appendUnsignedText(detailBuffer, serverPort); appendWideText(detailBuffer, L" service="); appendUnsignedText(detailBuffer, serviceValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HINTERNET, HookedHttpOpenRequestW, gHttpOpenRequestWOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"HttpOpenRequestW",
            (HINTERNET connectHandle, LPCWSTR verbPointer, LPCWSTR objectNamePointer, LPCWSTR versionPointer, LPCWSTR referrerPointer, LPCWSTR* acceptTypesPointer, DWORD flagsValue, DWORD_PTR contextValue),
            (connectHandle, verbPointer, objectNamePointer, versionPointer, referrerPointer, acceptTypesPointer, flagsValue, contextValue),
            { appendWideText(detailBuffer, L"connect="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(connectHandle)); appendWideText(detailBuffer, L" verb="); appendWideText(detailBuffer, verbPointer); appendWideText(detailBuffer, L" object="); appendWideText(detailBuffer, objectNamePointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HINTERNET, HookedHttpOpenRequestA, gHttpOpenRequestAOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"HttpOpenRequestA",
            (HINTERNET connectHandle, LPCSTR verbPointer, LPCSTR objectNamePointer, LPCSTR versionPointer, LPCSTR referrerPointer, LPCSTR* acceptTypesPointer, DWORD flagsValue, DWORD_PTR contextValue),
            (connectHandle, verbPointer, objectNamePointer, versionPointer, referrerPointer, acceptTypesPointer, flagsValue, contextValue),
            { appendWideText(detailBuffer, L"connect="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(connectHandle)); appendWideText(detailBuffer, L" verb="); appendAnsiText(detailBuffer, verbPointer); appendWideText(detailBuffer, L" object="); appendAnsiText(detailBuffer, objectNamePointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedHttpSendRequestW, gHttpSendRequestWOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"HttpSendRequestW",
            (HINTERNET requestHandle, LPCWSTR headersPointer, DWORD headersLength, LPVOID optionalPointer, DWORD optionalLength), (requestHandle, headersPointer, headersLength, optionalPointer, optionalLength),
            { appendWideText(detailBuffer, L"request="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); appendWideText(detailBuffer, L" headersLen="); appendUnsignedText(detailBuffer, headersLength); appendWideText(detailBuffer, L" optionalLen="); appendUnsignedText(detailBuffer, optionalLength); })
        APIMON_SIMPLE_BOOL_HOOK(HookedHttpSendRequestA, gHttpSendRequestAOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"HttpSendRequestA",
            (HINTERNET requestHandle, LPCSTR headersPointer, DWORD headersLength, LPVOID optionalPointer, DWORD optionalLength), (requestHandle, headersPointer, headersLength, optionalPointer, optionalLength),
            { appendWideText(detailBuffer, L"request="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); appendWideText(detailBuffer, L" headersLen="); appendUnsignedText(detailBuffer, headersLength); appendWideText(detailBuffer, L" optionalLen="); appendUnsignedText(detailBuffer, optionalLength); })
        APIMON_SIMPLE_BOOL_HOOK(HookedInternetReadFile, gInternetReadFileOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetReadFile",
            (HINTERNET fileHandle, LPVOID bufferPointer, DWORD bytesToRead, LPDWORD bytesReadPointer), (fileHandle, bufferPointer, bytesToRead, bytesReadPointer),
            { appendWideText(detailBuffer, L"handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); appendWideText(detailBuffer, L" requestBytes="); appendUnsignedText(detailBuffer, bytesToRead); appendWideText(detailBuffer, L" read="); appendUnsignedText(detailBuffer, bytesReadPointer != nullptr ? *bytesReadPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedInternetWriteFile, gInternetWriteFileOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetWriteFile",
            (HINTERNET fileHandle, LPCVOID bufferPointer, DWORD bytesToWrite, LPDWORD bytesWrittenPointer), (fileHandle, bufferPointer, bytesToWrite, bytesWrittenPointer),
            { appendWideText(detailBuffer, L"handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); appendWideText(detailBuffer, L" requestBytes="); appendUnsignedText(detailBuffer, bytesToWrite); appendWideText(detailBuffer, L" written="); appendUnsignedText(detailBuffer, bytesWrittenPointer != nullptr ? *bytesWrittenPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedInternetCloseHandle, gInternetCloseHandleOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetCloseHandle",
            (HINTERNET internetHandle), (internetHandle),
            { buildSimpleHandleDetail(detailBuffer, L"handle", internetHandle); })

#define APIMON_SIMPLE_HRESULT_HOOK(HookName, OriginalName, ModuleText, ApiText, ParamList, ArgList, DetailBlock) \
        HRESULT WINAPI HookName ParamList \
        { \
            ScopedHookGuard guardValue; \
            if (guardValue.bypass()) { return OriginalName ArgList; } \
            const HRESULT resultValue = OriginalName ArgList; \
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {}; \
            DetailBlock; \
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, ModuleText, ApiText, resultValue, detailBuffer); \
            return resultValue; \
        }

        // HookedCrypto/COM purpose:
        // - Input: CryptoAPI/CNG/COM critical object creation, encryption/decryption, random number generation, and class factory parameters;
        // - Processing: Complete the coverage of security-sensitive library calls; details record only algorithm, length, and handle, without copying plaintext or key content;
        // - Return: Preserve the original BOOL/NTSTATUS/HRESULT result.
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptAcquireContextW, gCryptAcquireContextWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptAcquireContextW",
            (HCRYPTPROV* providerPointer, LPCWSTR containerPointer, LPCWSTR providerNamePointer, DWORD providerType, DWORD flagsValue), (providerPointer, containerPointer, providerNamePointer, providerType, flagsValue),
            { appendWideText(detailBuffer, L"container="); appendWideText(detailBuffer, containerPointer); appendWideText(detailBuffer, L" provider="); appendWideText(detailBuffer, providerNamePointer); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, providerType); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, providerPointer != nullptr ? static_cast<std::uint64_t>(*providerPointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptAcquireContextA, gCryptAcquireContextAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptAcquireContextA",
            (HCRYPTPROV* providerPointer, LPCSTR containerPointer, LPCSTR providerNamePointer, DWORD providerType, DWORD flagsValue), (providerPointer, containerPointer, providerNamePointer, providerType, flagsValue),
            { appendWideText(detailBuffer, L"container="); appendAnsiText(detailBuffer, containerPointer); appendWideText(detailBuffer, L" provider="); appendAnsiText(detailBuffer, providerNamePointer); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, providerType); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, providerPointer != nullptr ? static_cast<std::uint64_t>(*providerPointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptCreateHash, gCryptCreateHashOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptCreateHash",
            (HCRYPTPROV providerHandle, ALG_ID algorithmId, HCRYPTKEY keyHandle, DWORD flagsValue, HCRYPTHASH* hashHandlePointer), (providerHandle, algorithmId, keyHandle, flagsValue, hashHandlePointer),
            { appendWideText(detailBuffer, L"provider="); appendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); appendWideText(detailBuffer, L" alg="); appendHexText(detailBuffer, algorithmId); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" hash="); appendHexText(detailBuffer, hashHandlePointer != nullptr ? static_cast<std::uint64_t>(*hashHandlePointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptHashData, gCryptHashDataOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptHashData",
            (HCRYPTHASH hashHandle, const BYTE* dataPointer, DWORD dataLength, DWORD flagsValue), (hashHandle, dataPointer, dataLength, flagsValue),
            { appendWideText(detailBuffer, L"hash="); appendHexText(detailBuffer, static_cast<std::uint64_t>(hashHandle)); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, dataLength); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptDeriveKey, gCryptDeriveKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptDeriveKey",
            (HCRYPTPROV providerHandle, ALG_ID algorithmId, HCRYPTHASH hashHandle, DWORD flagsValue, HCRYPTKEY* keyHandlePointer), (providerHandle, algorithmId, hashHandle, flagsValue, keyHandlePointer),
            { appendWideText(detailBuffer, L"provider="); appendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); appendWideText(detailBuffer, L" alg="); appendHexText(detailBuffer, algorithmId); appendWideText(detailBuffer, L" hash="); appendHexText(detailBuffer, static_cast<std::uint64_t>(hashHandle)); appendWideText(detailBuffer, L" key="); appendHexText(detailBuffer, keyHandlePointer != nullptr ? static_cast<std::uint64_t>(*keyHandlePointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptEncrypt, gCryptEncryptOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptEncrypt",
            (HCRYPTKEY keyHandle, HCRYPTHASH hashHandle, BOOL finalValue, DWORD flagsValue, BYTE* dataPointer, DWORD* dataLengthPointer, DWORD bufferLength), (keyHandle, hashHandle, finalValue, flagsValue, dataPointer, dataLengthPointer, bufferLength),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" final="); appendUnsignedText(detailBuffer, finalValue != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" dataLen="); appendUnsignedText(detailBuffer, dataLengthPointer != nullptr ? *dataLengthPointer : 0); appendWideText(detailBuffer, L" bufferLen="); appendUnsignedText(detailBuffer, bufferLength); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptDecrypt, gCryptDecryptOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptDecrypt",
            (HCRYPTKEY keyHandle, HCRYPTHASH hashHandle, BOOL finalValue, DWORD flagsValue, BYTE* dataPointer, DWORD* dataLengthPointer), (keyHandle, hashHandle, finalValue, flagsValue, dataPointer, dataLengthPointer),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" final="); appendUnsignedText(detailBuffer, finalValue != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" dataLen="); appendUnsignedText(detailBuffer, dataLengthPointer != nullptr ? *dataLengthPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptGenRandom, gCryptGenRandomOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptGenRandom",
            (HCRYPTPROV providerHandle, DWORD bufferLength, BYTE* bufferPointer), (providerHandle, bufferLength, bufferPointer),
            { appendWideText(detailBuffer, L"provider="); appendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, bufferLength); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptReleaseContext, gCryptReleaseContextOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptReleaseContext",
            (HCRYPTPROV providerHandle, DWORD flagsValue), (providerHandle, flagsValue),
            { appendWideText(detailBuffer, L"provider="); appendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })

        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptOpenAlgorithmProvider, gBCryptOpenAlgorithmProviderOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptOpenAlgorithmProvider",
            (BCRYPT_ALG_HANDLE* algorithmHandlePointer, LPCWSTR algorithmIdPointer, LPCWSTR implementationPointer, ULONG flagsValue),
            (algorithmHandlePointer, algorithmIdPointer, implementationPointer, flagsValue),
            { appendWideText(detailBuffer, L"alg="); appendWideText(detailBuffer, algorithmIdPointer); appendWideText(detailBuffer, L" impl="); appendWideText(detailBuffer, implementationPointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, algorithmHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*algorithmHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptCreateHash, gBCryptCreateHashOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptCreateHash",
            (BCRYPT_ALG_HANDLE algorithmHandle, BCRYPT_HASH_HANDLE* hashHandlePointer, PUCHAR hashObjectPointer, ULONG hashObjectLength, PUCHAR secretPointer, ULONG secretLength, ULONG flagsValue),
            (algorithmHandle, hashHandlePointer, hashObjectPointer, hashObjectLength, secretPointer, secretLength, flagsValue),
            { appendWideText(detailBuffer, L"algHandle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(algorithmHandle)); appendWideText(detailBuffer, L" objectLen="); appendUnsignedText(detailBuffer, hashObjectLength); appendWideText(detailBuffer, L" secretLen="); appendUnsignedText(detailBuffer, secretLength); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" hash="); appendHexText(detailBuffer, hashHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*hashHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptHashData, gBCryptHashDataOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptHashData",
            (BCRYPT_HASH_HANDLE hashHandle, PUCHAR inputPointer, ULONG inputLength, ULONG flagsValue), (hashHandle, inputPointer, inputLength, flagsValue),
            { appendWideText(detailBuffer, L"hash="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(hashHandle)); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, inputLength); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptFinishHash, gBCryptFinishHashOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptFinishHash",
            (BCRYPT_HASH_HANDLE hashHandle, PUCHAR outputPointer, ULONG outputLength, ULONG flagsValue), (hashHandle, outputPointer, outputLength, flagsValue),
            { appendWideText(detailBuffer, L"hash="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(hashHandle)); appendWideText(detailBuffer, L" outputLen="); appendUnsignedText(detailBuffer, outputLength); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptEncrypt, gBCryptEncryptOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptEncrypt",
            (BCRYPT_KEY_HANDLE keyHandle, PUCHAR inputPointer, ULONG inputLength, VOID* paddingInfoPointer, PUCHAR ivPointer, ULONG ivLength, PUCHAR outputPointer, ULONG outputLength, ULONG* resultLengthPointer, ULONG flagsValue),
            (keyHandle, inputPointer, inputLength, paddingInfoPointer, ivPointer, ivLength, outputPointer, outputLength, resultLengthPointer, flagsValue),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" inputLen="); appendUnsignedText(detailBuffer, inputLength); appendWideText(detailBuffer, L" outputLen="); appendUnsignedText(detailBuffer, outputLength); appendWideText(detailBuffer, L" resultLen="); appendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : 0); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptDecrypt, gBCryptDecryptOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptDecrypt",
            (BCRYPT_KEY_HANDLE keyHandle, PUCHAR inputPointer, ULONG inputLength, VOID* paddingInfoPointer, PUCHAR ivPointer, ULONG ivLength, PUCHAR outputPointer, ULONG outputLength, ULONG* resultLengthPointer, ULONG flagsValue),
            (keyHandle, inputPointer, inputLength, paddingInfoPointer, ivPointer, ivLength, outputPointer, outputLength, resultLengthPointer, flagsValue),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" inputLen="); appendUnsignedText(detailBuffer, inputLength); appendWideText(detailBuffer, L" outputLen="); appendUnsignedText(detailBuffer, outputLength); appendWideText(detailBuffer, L" resultLen="); appendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : 0); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptGenRandom, gBCryptGenRandomOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptGenRandom",
            (BCRYPT_ALG_HANDLE algorithmHandle, PUCHAR bufferPointer, ULONG bufferLength, ULONG flagsValue), (algorithmHandle, bufferPointer, bufferLength, flagsValue),
            { appendWideText(detailBuffer, L"algHandle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(algorithmHandle)); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, bufferLength); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptCloseAlgorithmProvider, gBCryptCloseAlgorithmProviderOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptCloseAlgorithmProvider",
            (BCRYPT_ALG_HANDLE algorithmHandle, ULONG flagsValue), (algorithmHandle, flagsValue),
            { appendWideText(detailBuffer, L"algHandle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(algorithmHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptDestroyHash, gBCryptDestroyHashOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptDestroyHash",
            (BCRYPT_HASH_HANDLE hashHandle), (hashHandle),
            { buildSimpleHandleDetail(detailBuffer, L"hash", hashHandle); })
        APIMON_SIMPLE_HRESULT_HOOK(HookedCoCreateInstance, gCoCreateInstanceOriginal, L"Ole32", L"CoCreateInstance",
            (REFCLSID classId, LPUNKNOWN outerUnknownPointer, DWORD classContext, REFIID interfaceId, LPVOID* objectPointer),
            (classId, outerUnknownPointer, classContext, interfaceId, objectPointer),
            { appendWideText(detailBuffer, L"clsctx="); appendHexText(detailBuffer, classContext); appendWideText(detailBuffer, L" object="); appendHexText(detailBuffer, objectPointer != nullptr ? reinterpret_cast<std::uint64_t>(*objectPointer) : 0); })
        APIMON_SIMPLE_HRESULT_HOOK(HookedCoCreateInstanceEx, gCoCreateInstanceExOriginal, L"Ole32", L"CoCreateInstanceEx",
            (REFCLSID classId, IUnknown* outerUnknownPointer, DWORD classContext, COSERVERINFO* serverInfoPointer, DWORD multiQiCount, MULTI_QI* resultsPointer),
            (classId, outerUnknownPointer, classContext, serverInfoPointer, multiQiCount, resultsPointer),
            { appendWideText(detailBuffer, L"clsctx="); appendHexText(detailBuffer, classContext); appendWideText(detailBuffer, L" qiCount="); appendUnsignedText(detailBuffer, multiQiCount); appendWideText(detailBuffer, L" server="); appendWideText(detailBuffer, serverInfoPointer != nullptr ? serverInfoPointer->pwszName : nullptr); })
        APIMON_SIMPLE_HRESULT_HOOK(HookedCoGetClassObject, gCoGetClassObjectOriginal, L"Ole32", L"CoGetClassObject",
            (REFCLSID classId, DWORD classContext, COSERVERINFO* serverInfoPointer, REFIID interfaceId, LPVOID* classObjectPointer),
            (classId, classContext, serverInfoPointer, interfaceId, classObjectPointer),
            { appendWideText(detailBuffer, L"clsctx="); appendHexText(detailBuffer, classContext); appendWideText(detailBuffer, L" factory="); appendHexText(detailBuffer, classObjectPointer != nullptr ? reinterpret_cast<std::uint64_t>(*classObjectPointer) : 0); appendWideText(detailBuffer, L" server="); appendWideText(detailBuffer, serverInfoPointer != nullptr ? serverInfoPointer->pwszName : nullptr); })

        // HookedLocalMemory:
        // - Input: Current process VirtualAlloc/Free/Protect parameters;
        // - Processing: Cover non-Ex local memory allocation, deallocation, and permission modification to address common paths for self-decryption and dynamic code generation.
        // - Returns: Preserves the original return value and restores LastError.
        APIMON_SIMPLE_HANDLE_HOOK(LPVOID, HookedVirtualAlloc, gVirtualAllocOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"VirtualAlloc",
            (LPVOID baseAddress, SIZE_T sizeValue, DWORD allocationType, DWORD protectValue), (baseAddress, sizeValue, allocationType, protectValue),
            { appendWideText(detailBuffer, L"baseHint="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(sizeValue)); appendWideText(detailBuffer, L" type="); appendHexText(detailBuffer, allocationType); appendWideText(detailBuffer, L" protect="); appendHexText(detailBuffer, protectValue); appendWideText(detailBuffer, L" result="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedVirtualFree, gVirtualFreeOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"VirtualFree",
            (LPVOID baseAddress, SIZE_T sizeValue, DWORD freeType), (baseAddress, sizeValue, freeType),
            { appendWideText(detailBuffer, L"base="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(sizeValue)); appendWideText(detailBuffer, L" type="); appendHexText(detailBuffer, freeType); })
        APIMON_SIMPLE_BOOL_HOOK(HookedVirtualProtect, gVirtualProtectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"VirtualProtect",
            (LPVOID baseAddress, SIZE_T sizeValue, DWORD newProtect, PDWORD oldProtectPointer), (baseAddress, sizeValue, newProtect, oldProtectPointer),
            { appendWideText(detailBuffer, L"base="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(sizeValue)); appendWideText(detailBuffer, L" newProtect="); appendHexText(detailBuffer, newProtect); appendWideText(detailBuffer, L" oldProtect="); appendHexText(detailBuffer, oldProtectPointer != nullptr ? *oldProtectPointer : 0); })

        // HookedToolhelpAndModule:
        // - Input: Toolhelp snapshot and module enumeration/module path query parameters;
        // - Processing: Complete the module enumeration and loader probing chain.
        // - Returns: preserves the original HANDLE/BOOL/DWORD semantics.
        HANDLE WINAPI hookedCreateToolhelp32Snapshot(DWORD flagsValue, DWORD processId)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gCreateToolhelp32SnapshotOriginal(flagsValue, processId); }
            const HANDLE kResultHandle = gCreateToolhelp32SnapshotOriginal(flagsValue, processId);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"flags=");
            appendHexText(detailBuffer, flagsValue);
            appendWideText(detailBuffer, L" pid=");
            appendUnsignedText(detailBuffer, processId);
            appendWideText(detailBuffer, L" snapshot=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(kResultHandle));
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"Kernel32", L"CreateToolhelp32Snapshot", kResultHandle != INVALID_HANDLE_VALUE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultHandle;
        }

        APIMON_SIMPLE_BOOL_HOOK(HookedModule32FirstW, gModule32FirstWOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"Module32FirstW",
            (HANDLE snapshotHandle, LPMODULEENTRY32W entryPointer), (snapshotHandle, entryPointer),
            { appendWideText(detailBuffer, L"snapshot="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); appendWideText(detailBuffer, L" module="); appendWideText(detailBuffer, resultValue != FALSE && entryPointer != nullptr ? entryPointer->szModule : nullptr); appendWideText(detailBuffer, L" base="); appendHexText(detailBuffer, resultValue != FALSE && entryPointer != nullptr ? reinterpret_cast<std::uint64_t>(entryPointer->modBaseAddr) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedModule32NextW, gModule32NextWOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"Module32NextW",
            (HANDLE snapshotHandle, LPMODULEENTRY32W entryPointer), (snapshotHandle, entryPointer),
            { appendWideText(detailBuffer, L"snapshot="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); appendWideText(detailBuffer, L" module="); appendWideText(detailBuffer, resultValue != FALSE && entryPointer != nullptr ? entryPointer->szModule : nullptr); appendWideText(detailBuffer, L" base="); appendHexText(detailBuffer, resultValue != FALSE && entryPointer != nullptr ? reinterpret_cast<std::uint64_t>(entryPointer->modBaseAddr) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedModule32FirstA, gModule32FirstAOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"Module32First",
            (HANDLE snapshotHandle, tagMODULEENTRY32* entryPointer), (snapshotHandle, entryPointer),
            { appendWideText(detailBuffer, L"snapshot="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); appendWideText(detailBuffer, L" module="); if (resultValue != FALSE && entryPointer != nullptr) { appendAnsiText(detailBuffer, entryPointer->szModule); } appendWideText(detailBuffer, L" base="); appendHexText(detailBuffer, resultValue != FALSE && entryPointer != nullptr ? reinterpret_cast<std::uint64_t>(entryPointer->modBaseAddr) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedModule32NextA, gModule32NextAOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"Module32Next",
            (HANDLE snapshotHandle, tagMODULEENTRY32* entryPointer), (snapshotHandle, entryPointer),
            { appendWideText(detailBuffer, L"snapshot="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); appendWideText(detailBuffer, L" module="); if (resultValue != FALSE && entryPointer != nullptr) { appendAnsiText(detailBuffer, entryPointer->szModule); } appendWideText(detailBuffer, L" base="); appendHexText(detailBuffer, resultValue != FALSE && entryPointer != nullptr ? reinterpret_cast<std::uint64_t>(entryPointer->modBaseAddr) : 0); })

        APIMON_SIMPLE_HANDLE_HOOK(HMODULE, HookedGetModuleHandleW, gGetModuleHandleWOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"GetModuleHandleW",
            (LPCWSTR moduleNamePointer), (moduleNamePointer),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, moduleNamePointer); appendWideText(detailBuffer, L" module="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HMODULE, HookedGetModuleHandleA, gGetModuleHandleAOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"GetModuleHandleA",
            (LPCSTR moduleNamePointer), (moduleNamePointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, moduleNamePointer); appendWideText(detailBuffer, L" module="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedGetModuleHandleExW, gGetModuleHandleExWOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"GetModuleHandleExW",
            (DWORD flagsValue, LPCWSTR moduleNamePointer, HMODULE* moduleHandlePointer), (flagsValue, moduleNamePointer, moduleHandlePointer),
            { appendWideText(detailBuffer, L"flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" name="); appendWideText(detailBuffer, moduleNamePointer); appendWideText(detailBuffer, L" module="); appendHexText(detailBuffer, moduleHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*moduleHandlePointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedGetModuleHandleExA, gGetModuleHandleExAOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"GetModuleHandleExA",
            (DWORD flagsValue, LPCSTR moduleNamePointer, HMODULE* moduleHandlePointer), (flagsValue, moduleNamePointer, moduleHandlePointer),
            { appendWideText(detailBuffer, L"flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" name="); appendAnsiText(detailBuffer, moduleNamePointer); appendWideText(detailBuffer, L" module="); appendHexText(detailBuffer, moduleHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*moduleHandlePointer) : 0); })

        DWORD WINAPI hookedGetModuleFileNameW(HMODULE moduleHandle, LPWSTR fileNamePointer, DWORD sizeValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gGetModuleFileNameWOriginal(moduleHandle, fileNamePointer, sizeValue); }
            const DWORD kResultValue = gGetModuleFileNameWOriginal(moduleHandle, fileNamePointer, sizeValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"module=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, sizeValue);
            appendWideText(detailBuffer, L" path=");
            appendWideText(detailBuffer, kResultValue != 0 ? fileNamePointer : nullptr, kResultValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"GetModuleFileNameW", kResultValue != 0 ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        DWORD WINAPI hookedGetModuleFileNameA(HMODULE moduleHandle, LPSTR fileNamePointer, DWORD sizeValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gGetModuleFileNameAOriginal(moduleHandle, fileNamePointer, sizeValue); }
            const DWORD kResultValue = gGetModuleFileNameAOriginal(moduleHandle, fileNamePointer, sizeValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"module=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle));
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, sizeValue);
            appendWideText(detailBuffer, L" path=");
            if (kResultValue != 0) { appendAnsiText(detailBuffer, fileNamePointer, kResultValue); }
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"GetModuleFileNameA", kResultValue != 0 ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        // HookedFileExtras purpose: record hard link, file replace, EOF set, and file lock operations; return the original BOOL.
        APIMON_SIMPLE_BOOL_HOOK(HookedCreateHardLinkW, gCreateHardLinkWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateHardLinkW",
            (LPCWSTR fileNamePointer, LPCWSTR existingFileNamePointer, LPSECURITY_ATTRIBUTES securityAttributes), (fileNamePointer, existingFileNamePointer, securityAttributes),
            { buildTwoPathDetailW(detailBuffer, existingFileNamePointer, fileNamePointer, 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCreateHardLinkA, gCreateHardLinkAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateHardLinkA",
            (LPCSTR fileNamePointer, LPCSTR existingFileNamePointer, LPSECURITY_ATTRIBUTES securityAttributes), (fileNamePointer, existingFileNamePointer, securityAttributes),
            { buildTwoPathDetailA(detailBuffer, existingFileNamePointer, fileNamePointer, 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedReplaceFileW, gReplaceFileWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"ReplaceFileW",
            (LPCWSTR replacedFilePointer, LPCWSTR replacementFilePointer, LPCWSTR backupFilePointer, DWORD flagsValue, LPVOID excludePointer, LPVOID reservedPointer),
            (replacedFilePointer, replacementFilePointer, backupFilePointer, flagsValue, excludePointer, reservedPointer),
            { buildTwoPathDetailW(detailBuffer, replacedFilePointer, replacementFilePointer, flagsValue); appendWideText(detailBuffer, L" backup="); appendWideText(detailBuffer, backupFilePointer); })
        APIMON_SIMPLE_BOOL_HOOK(HookedReplaceFileA, gReplaceFileAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"ReplaceFileA",
            (LPCSTR replacedFilePointer, LPCSTR replacementFilePointer, LPCSTR backupFilePointer, DWORD flagsValue, LPVOID excludePointer, LPVOID reservedPointer),
            (replacedFilePointer, replacementFilePointer, backupFilePointer, flagsValue, excludePointer, reservedPointer),
            { buildTwoPathDetailA(detailBuffer, replacedFilePointer, replacementFilePointer, flagsValue); appendWideText(detailBuffer, L" backup="); appendAnsiText(detailBuffer, backupFilePointer); })
        APIMON_SIMPLE_BOOL_HOOK(HookedSetEndOfFile, gSetEndOfFileOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"SetEndOfFile",
            (HANDLE fileHandle), (fileHandle),
            { buildSimpleHandleDetail(detailBuffer, L"file", fileHandle); })
        APIMON_SIMPLE_BOOL_HOOK(HookedLockFileEx, gLockFileExOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"LockFileEx",
            (HANDLE fileHandle, DWORD flagsValue, DWORD reservedValue, DWORD bytesLow, DWORD bytesHigh, LPOVERLAPPED overlappedPointer),
            (fileHandle, flagsValue, reservedValue, bytesLow, bytesHigh, overlappedPointer),
            { appendWideText(detailBuffer, L"file="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" bytes="); appendHexText(detailBuffer, (static_cast<std::uint64_t>(bytesHigh) << 32) | bytesLow); })
        APIMON_SIMPLE_BOOL_HOOK(HookedUnlockFileEx, gUnlockFileExOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"UnlockFileEx",
            (HANDLE fileHandle, DWORD reservedValue, DWORD bytesLow, DWORD bytesHigh, LPOVERLAPPED overlappedPointer),
            (fileHandle, reservedValue, bytesLow, bytesHigh, overlappedPointer),
            { appendWideText(detailBuffer, L"file="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); appendWideText(detailBuffer, L" bytes="); appendHexText(detailBuffer, (static_cast<std::uint64_t>(bytesHigh) << 32) | bytesLow); })

        // hookedShellExecuteW/A purpose:
        // - Input: ShellExecute target, parameters, directory, and show command;
        // - Processing: Supplement legacy Shell startup entry points other than ShellExecuteEx.
        // - Return: Preserve original HINSTANCE semantics; values <= 32 indicate failure and restore LastError.
        HINSTANCE WINAPI hookedShellExecuteW(HWND windowHandle, LPCWSTR operationPointer, LPCWSTR filePointer, LPCWSTR parametersPointer, LPCWSTR directoryPointer, INT showCommand)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gShellExecuteWOriginal(windowHandle, operationPointer, filePointer, parametersPointer, directoryPointer, showCommand); }
            const HINSTANCE kResultValue = gShellExecuteWOriginal(windowHandle, operationPointer, filePointer, parametersPointer, directoryPointer, showCommand);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"op=");
            appendWideText(detailBuffer, operationPointer);
            appendWideText(detailBuffer, L" file=");
            appendWideText(detailBuffer, filePointer);
            appendWideText(detailBuffer, L" params=");
            appendWideText(detailBuffer, parametersPointer);
            appendWideText(detailBuffer, L" cwd=");
            appendWideText(detailBuffer, directoryPointer);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"Shell32", L"ShellExecuteW", reinterpret_cast<INT_PTR>(kResultValue) > 32 ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        HINSTANCE WINAPI hookedShellExecuteA(HWND windowHandle, LPCSTR operationPointer, LPCSTR filePointer, LPCSTR parametersPointer, LPCSTR directoryPointer, INT showCommand)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gShellExecuteAOriginal(windowHandle, operationPointer, filePointer, parametersPointer, directoryPointer, showCommand); }
            const HINSTANCE kResultValue = gShellExecuteAOriginal(windowHandle, operationPointer, filePointer, parametersPointer, directoryPointer, showCommand);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"op=");
            appendAnsiText(detailBuffer, operationPointer);
            appendWideText(detailBuffer, L" file=");
            appendAnsiText(detailBuffer, filePointer);
            appendWideText(detailBuffer, L" params=");
            appendAnsiText(detailBuffer, parametersPointer);
            appendWideText(detailBuffer, L" cwd=");
            appendAnsiText(detailBuffer, directoryPointer);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"Shell32", L"ShellExecuteA", reinterpret_cast<INT_PTR>(kResultValue) > 32 ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        APIMON_SIMPLE_BOOL_HOOK(HookedCreateProcessWithLogonW, gCreateProcessWithLogonWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CreateProcessWithLogonW",
            (LPCWSTR userNamePointer, LPCWSTR domainPointer, LPCWSTR passwordPointer, DWORD logonFlags, LPCWSTR applicationNamePointer, LPWSTR commandLinePointer, DWORD creationFlags, LPVOID environmentPointer, LPCWSTR currentDirectoryPointer, LPSTARTUPINFOW startupInfoPointer, LPPROCESS_INFORMATION processInformationPointer),
            (userNamePointer, domainPointer, passwordPointer, logonFlags, applicationNamePointer, commandLinePointer, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInformationPointer),
            { appendWideText(detailBuffer, L"user="); appendWideText(detailBuffer, domainPointer); appendWideText(detailBuffer, L"\\"); appendWideText(detailBuffer, userNamePointer); appendWideText(detailBuffer, L" logonFlags="); appendHexText(detailBuffer, logonFlags); appendWideText(detailBuffer, L" app="); appendWideText(detailBuffer, applicationNamePointer); appendWideText(detailBuffer, L" cmd="); appendWideText(detailBuffer, commandLinePointer); appendWideText(detailBuffer, L" childPid="); appendUnsignedText(detailBuffer, processInformationPointer != nullptr ? processInformationPointer->dwProcessId : 0); })

        // HookedServiceQuery purpose: Log service secondary configuration, status, and enumeration to complete the SCM reconnaissance surface beyond service creation/startup; return the original BOOL.
        APIMON_SIMPLE_BOOL_HOOK(HookedChangeServiceConfig2W, gChangeServiceConfig2WOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ChangeServiceConfig2W",
            (SC_HANDLE serviceHandle, DWORD infoLevel, LPVOID infoPointer), (serviceHandle, infoLevel, infoPointer),
            { appendWideText(detailBuffer, L"service="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, infoLevel); })
        APIMON_SIMPLE_BOOL_HOOK(HookedChangeServiceConfig2A, gChangeServiceConfig2AOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ChangeServiceConfig2A",
            (SC_HANDLE serviceHandle, DWORD infoLevel, LPVOID infoPointer), (serviceHandle, infoLevel, infoPointer),
            { appendWideText(detailBuffer, L"service="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, infoLevel); })
        APIMON_SIMPLE_BOOL_HOOK(HookedQueryServiceStatusEx, gQueryServiceStatusExOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"QueryServiceStatusEx",
            (SC_HANDLE serviceHandle, SC_STATUS_TYPE infoLevel, LPBYTE bufferPointer, DWORD bufferSize, LPDWORD bytesNeededPointer),
            (serviceHandle, infoLevel, bufferPointer, bufferSize, bytesNeededPointer),
            { appendWideText(detailBuffer, L"service="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, infoLevel); appendWideText(detailBuffer, L" buffer="); appendUnsignedText(detailBuffer, bufferSize); appendWideText(detailBuffer, L" needed="); appendUnsignedText(detailBuffer, bytesNeededPointer != nullptr ? *bytesNeededPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedQueryServiceConfigW, gQueryServiceConfigWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"QueryServiceConfigW",
            (SC_HANDLE serviceHandle, LPQUERY_SERVICE_CONFIGW configPointer, DWORD bufferSize, LPDWORD bytesNeededPointer), (serviceHandle, configPointer, bufferSize, bytesNeededPointer),
            { appendWideText(detailBuffer, L"service="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); appendWideText(detailBuffer, L" buffer="); appendUnsignedText(detailBuffer, bufferSize); appendWideText(detailBuffer, L" needed="); appendUnsignedText(detailBuffer, bytesNeededPointer != nullptr ? *bytesNeededPointer : 0); if (resultValue != FALSE && configPointer != nullptr) { appendWideText(detailBuffer, L" path="); appendWideText(detailBuffer, configPointer->lpBinaryPathName); } })
        APIMON_SIMPLE_BOOL_HOOK(HookedQueryServiceConfigA, gQueryServiceConfigAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"QueryServiceConfigA",
            (SC_HANDLE serviceHandle, LPQUERY_SERVICE_CONFIGA configPointer, DWORD bufferSize, LPDWORD bytesNeededPointer), (serviceHandle, configPointer, bufferSize, bytesNeededPointer),
            { appendWideText(detailBuffer, L"service="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); appendWideText(detailBuffer, L" buffer="); appendUnsignedText(detailBuffer, bufferSize); appendWideText(detailBuffer, L" needed="); appendUnsignedText(detailBuffer, bytesNeededPointer != nullptr ? *bytesNeededPointer : 0); if (resultValue != FALSE && configPointer != nullptr) { appendWideText(detailBuffer, L" path="); appendAnsiText(detailBuffer, configPointer->lpBinaryPathName); } })
        APIMON_SIMPLE_BOOL_HOOK(HookedEnumServicesStatusExW, gEnumServicesStatusExWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"EnumServicesStatusExW",
            (SC_HANDLE managerHandle, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE servicesPointer, DWORD bufferSize, LPDWORD bytesNeededPointer, LPDWORD servicesReturnedPointer, LPDWORD resumeHandlePointer, LPCWSTR groupNamePointer),
            (managerHandle, infoLevel, serviceType, serviceState, servicesPointer, bufferSize, bytesNeededPointer, servicesReturnedPointer, resumeHandlePointer, groupNamePointer),
            { appendWideText(detailBuffer, L"scm="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(managerHandle)); appendWideText(detailBuffer, L" type="); appendHexText(detailBuffer, serviceType); appendWideText(detailBuffer, L" state="); appendHexText(detailBuffer, serviceState); appendWideText(detailBuffer, L" returned="); appendUnsignedText(detailBuffer, servicesReturnedPointer != nullptr ? *servicesReturnedPointer : 0); appendWideText(detailBuffer, L" group="); appendWideText(detailBuffer, groupNamePointer); })
        APIMON_SIMPLE_BOOL_HOOK(HookedEnumServicesStatusExA, gEnumServicesStatusExAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"EnumServicesStatusExA",
            (SC_HANDLE managerHandle, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE servicesPointer, DWORD bufferSize, LPDWORD bytesNeededPointer, LPDWORD servicesReturnedPointer, LPDWORD resumeHandlePointer, LPCSTR groupNamePointer),
            (managerHandle, infoLevel, serviceType, serviceState, servicesPointer, bufferSize, bytesNeededPointer, servicesReturnedPointer, resumeHandlePointer, groupNamePointer),
            { appendWideText(detailBuffer, L"scm="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(managerHandle)); appendWideText(detailBuffer, L" type="); appendHexText(detailBuffer, serviceType); appendWideText(detailBuffer, L" state="); appendHexText(detailBuffer, serviceState); appendWideText(detailBuffer, L" returned="); appendUnsignedText(detailBuffer, servicesReturnedPointer != nullptr ? *servicesReturnedPointer : 0); appendWideText(detailBuffer, L" group="); appendAnsiText(detailBuffer, groupNamePointer); })

        // HookedHttpQueryExtras purpose: record WinHTTP/WinINet queries, option settings, and direct URL entry points; return the original result.
        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpQueryHeaders, gWinHttpQueryHeadersOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpQueryHeaders",
            (HINTERNET requestHandle, DWORD infoLevel, LPCWSTR namePointer, LPVOID bufferPointer, LPDWORD bufferLengthPointer, LPDWORD indexPointer),
            (requestHandle, infoLevel, namePointer, bufferPointer, bufferLengthPointer, indexPointer),
            { appendWideText(detailBuffer, L"request="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); appendWideText(detailBuffer, L" level="); appendHexText(detailBuffer, infoLevel); appendWideText(detailBuffer, L" name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, bufferLengthPointer != nullptr ? *bufferLengthPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpQueryDataAvailable, gWinHttpQueryDataAvailableOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpQueryDataAvailable",
            (HINTERNET requestHandle, LPDWORD bytesAvailablePointer), (requestHandle, bytesAvailablePointer),
            { appendWideText(detailBuffer, L"request="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); appendWideText(detailBuffer, L" available="); appendUnsignedText(detailBuffer, bytesAvailablePointer != nullptr ? *bytesAvailablePointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpSetOption, gWinHttpSetOptionOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpSetOption",
            (HINTERNET internetHandle, DWORD optionValue, LPVOID bufferPointer, DWORD bufferLength), (internetHandle, optionValue, bufferPointer, bufferLength),
            { appendWideText(detailBuffer, L"handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); appendWideText(detailBuffer, L" option="); appendHexText(detailBuffer, optionValue); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, bufferLength); })
        APIMON_SIMPLE_HANDLE_HOOK(HINTERNET, HookedInternetOpenUrlW, gInternetOpenUrlWOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetOpenUrlW",
            (HINTERNET internetHandle, LPCWSTR urlPointer, LPCWSTR headersPointer, DWORD headersLength, DWORD flagsValue, DWORD_PTR contextValue),
            (internetHandle, urlPointer, headersPointer, headersLength, flagsValue, contextValue),
            { appendWideText(detailBuffer, L"root="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); appendWideText(detailBuffer, L" url="); appendWideText(detailBuffer, urlPointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HINTERNET, HookedInternetOpenUrlA, gInternetOpenUrlAOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetOpenUrlA",
            (HINTERNET internetHandle, LPCSTR urlPointer, LPCSTR headersPointer, DWORD headersLength, DWORD flagsValue, DWORD_PTR contextValue),
            (internetHandle, urlPointer, headersPointer, headersLength, flagsValue, contextValue),
            { appendWideText(detailBuffer, L"root="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); appendWideText(detailBuffer, L" url="); appendAnsiText(detailBuffer, urlPointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedInternetQueryDataAvailable, gInternetQueryDataAvailableOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetQueryDataAvailable",
            (HINTERNET fileHandle, LPDWORD bytesAvailablePointer, DWORD flagsValue, DWORD_PTR contextValue), (fileHandle, bytesAvailablePointer, flagsValue, contextValue),
            { appendWideText(detailBuffer, L"handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); appendWideText(detailBuffer, L" available="); appendUnsignedText(detailBuffer, bytesAvailablePointer != nullptr ? *bytesAvailablePointer : 0); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedInternetSetOptionW, gInternetSetOptionWOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetSetOptionW",
            (HINTERNET internetHandle, DWORD optionValue, LPVOID bufferPointer, DWORD bufferLength), (internetHandle, optionValue, bufferPointer, bufferLength),
            { appendWideText(detailBuffer, L"handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); appendWideText(detailBuffer, L" option="); appendHexText(detailBuffer, optionValue); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, bufferLength); })
        APIMON_SIMPLE_BOOL_HOOK(HookedInternetSetOptionA, gInternetSetOptionAOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetSetOptionA",
            (HINTERNET internetHandle, DWORD optionValue, LPVOID bufferPointer, DWORD bufferLength), (internetHandle, optionValue, bufferPointer, bufferLength),
            { appendWideText(detailBuffer, L"handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); appendWideText(detailBuffer, L" option="); appendHexText(detailBuffer, optionValue); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, bufferLength); })
        APIMON_SIMPLE_BOOL_HOOK(HookedInternetCrackUrlW, gInternetCrackUrlWOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetCrackUrlW",
            (LPCWSTR urlPointer, DWORD urlLength, DWORD flagsValue, LPURL_COMPONENTSW componentsPointer), (urlPointer, urlLength, flagsValue, componentsPointer),
            { appendWideText(detailBuffer, L"url="); appendWideText(detailBuffer, urlPointer, urlLength != 0 ? urlLength : static_cast<std::size_t>(-1)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedInternetCrackUrlA, gInternetCrackUrlAOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetCrackUrlA",
            (LPCSTR urlPointer, DWORD urlLength, DWORD flagsValue, LPURL_COMPONENTSA componentsPointer), (urlPointer, urlLength, flagsValue, componentsPointer),
            { appendWideText(detailBuffer, L"url="); appendAnsiText(detailBuffer, urlPointer, urlLength != 0 ? urlLength : static_cast<std::size_t>(-1)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })

        HRESULT WINAPI hookedUrlDownloadToFileW(LPUNKNOWN callerPointer, LPCWSTR urlPointer, LPCWSTR fileNamePointer, DWORD reservedValue, LPBINDSTATUSCALLBACK callbackPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gUrlDownloadToFileWOriginal(callerPointer, urlPointer, fileNamePointer, reservedValue, callbackPointer); }
            const HRESULT kResultValue = gUrlDownloadToFileWOriginal(callerPointer, urlPointer, fileNamePointer, reservedValue, callbackPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"url=");
            appendWideText(detailBuffer, urlPointer);
            appendWideText(detailBuffer, L" file=");
            appendWideText(detailBuffer, fileNamePointer);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kNetwork, L"Urlmon", L"URLDownloadToFileW", kResultValue, detailBuffer);
            return kResultValue;
        }

        HRESULT WINAPI hookedUrlDownloadToFileA(LPUNKNOWN callerPointer, LPCSTR urlPointer, LPCSTR fileNamePointer, DWORD reservedValue, LPBINDSTATUSCALLBACK callbackPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gUrlDownloadToFileAOriginal(callerPointer, urlPointer, fileNamePointer, reservedValue, callbackPointer); }
            const HRESULT kResultValue = gUrlDownloadToFileAOriginal(callerPointer, urlPointer, fileNamePointer, reservedValue, callbackPointer);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"url=");
            appendAnsiText(detailBuffer, urlPointer);
            appendWideText(detailBuffer, L" file=");
            appendAnsiText(detailBuffer, fileNamePointer);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kNetwork, L"Urlmon", L"URLDownloadToFileA", kResultValue, detailBuffer);
            return kResultValue;
        }

        // HookedCryptoLifecycle purpose: Record key import/export/destruction and CNG key creation/import/destruction; do not record key content.
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptImportKey, gCryptImportKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptImportKey",
            (HCRYPTPROV providerHandle, const BYTE* dataPointer, DWORD dataLength, HCRYPTKEY publicKeyHandle, DWORD flagsValue, HCRYPTKEY* keyHandlePointer),
            (providerHandle, dataPointer, dataLength, publicKeyHandle, flagsValue, keyHandlePointer),
            { appendWideText(detailBuffer, L"provider="); appendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, dataLength); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" key="); appendHexText(detailBuffer, keyHandlePointer != nullptr ? static_cast<std::uint64_t>(*keyHandlePointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptExportKey, gCryptExportKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptExportKey",
            (HCRYPTKEY keyHandle, HCRYPTKEY exportKeyHandle, DWORD blobType, DWORD flagsValue, BYTE* dataPointer, DWORD* dataLengthPointer),
            (keyHandle, exportKeyHandle, blobType, flagsValue, dataPointer, dataLengthPointer),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" exportKey="); appendHexText(detailBuffer, static_cast<std::uint64_t>(exportKeyHandle)); appendWideText(detailBuffer, L" blobType="); appendHexText(detailBuffer, blobType); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, dataLengthPointer != nullptr ? *dataLengthPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptDestroyKey, gCryptDestroyKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptDestroyKey",
            (HCRYPTKEY keyHandle), (keyHandle),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptDestroyHash, gCryptDestroyHashOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CryptDestroyHash",
            (HCRYPTHASH hashHandle), (hashHandle),
            { appendWideText(detailBuffer, L"hash="); appendHexText(detailBuffer, static_cast<std::uint64_t>(hashHandle)); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptGenerateSymmetricKey, gBCryptGenerateSymmetricKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptGenerateSymmetricKey",
            (BCRYPT_ALG_HANDLE algorithmHandle, BCRYPT_KEY_HANDLE* keyHandlePointer, PUCHAR keyObjectPointer, ULONG keyObjectLength, PUCHAR secretPointer, ULONG secretLength, ULONG flagsValue),
            (algorithmHandle, keyHandlePointer, keyObjectPointer, keyObjectLength, secretPointer, secretLength, flagsValue),
            { appendWideText(detailBuffer, L"algHandle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(algorithmHandle)); appendWideText(detailBuffer, L" objectLen="); appendUnsignedText(detailBuffer, keyObjectLength); appendWideText(detailBuffer, L" secretLen="); appendUnsignedText(detailBuffer, secretLength); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" key="); appendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptImportKey, gBCryptImportKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptImportKey",
            (BCRYPT_ALG_HANDLE algorithmHandle, BCRYPT_KEY_HANDLE importKeyHandle, LPCWSTR blobTypePointer, BCRYPT_KEY_HANDLE* keyHandlePointer, PUCHAR keyObjectPointer, ULONG keyObjectLength, PUCHAR inputPointer, ULONG inputLength, ULONG flagsValue),
            (algorithmHandle, importKeyHandle, blobTypePointer, keyHandlePointer, keyObjectPointer, keyObjectLength, inputPointer, inputLength, flagsValue),
            { appendWideText(detailBuffer, L"algHandle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(algorithmHandle)); appendWideText(detailBuffer, L" blobType="); appendWideText(detailBuffer, blobTypePointer); appendWideText(detailBuffer, L" inputLen="); appendUnsignedText(detailBuffer, inputLength); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" key="); appendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptImportKeyPair, gBCryptImportKeyPairOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptImportKeyPair",
            (BCRYPT_ALG_HANDLE algorithmHandle, BCRYPT_KEY_HANDLE importKeyHandle, LPCWSTR blobTypePointer, BCRYPT_KEY_HANDLE* keyHandlePointer, PUCHAR inputPointer, ULONG inputLength, ULONG flagsValue),
            (algorithmHandle, importKeyHandle, blobTypePointer, keyHandlePointer, inputPointer, inputLength, flagsValue),
            { appendWideText(detailBuffer, L"algHandle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(algorithmHandle)); appendWideText(detailBuffer, L" blobType="); appendWideText(detailBuffer, blobTypePointer); appendWideText(detailBuffer, L" inputLen="); appendUnsignedText(detailBuffer, inputLength); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" key="); appendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedBCryptDestroyKey, gBCryptDestroyKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Bcrypt", L"BCryptDestroyKey",
            (BCRYPT_KEY_HANDLE keyHandle), (keyHandle),
            { buildSimpleHandleDetail(detailBuffer, L"key", keyHandle); })

        APIMON_SIMPLE_HRESULT_HOOK(HookedCoInitializeEx, gCoInitializeExOriginal, L"Ole32", L"CoInitializeEx",
            (LPVOID reservedPointer, DWORD coInitValue), (reservedPointer, coInitValue),
            { appendWideText(detailBuffer, L"coinit="); appendHexText(detailBuffer, coInitValue); })
        APIMON_SIMPLE_HRESULT_HOOK(HookedCoInitializeSecurity, gCoInitializeSecurityOriginal, L"Ole32", L"CoInitializeSecurity",
            (PSECURITY_DESCRIPTOR securityDescriptorPointer, LONG authServiceCount, SOLE_AUTHENTICATION_SERVICE* authServicesPointer, void* reserved1Pointer, DWORD authnLevel, DWORD impLevel, void* authListPointer, DWORD capabilitiesValue, void* reserved3Pointer),
            (securityDescriptorPointer, authServiceCount, authServicesPointer, reserved1Pointer, authnLevel, impLevel, authListPointer, capabilitiesValue, reserved3Pointer),
            { appendWideText(detailBuffer, L"authCount="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(authServiceCount < 0 ? 0 : authServiceCount)); appendWideText(detailBuffer, L" authnLevel="); appendHexText(detailBuffer, authnLevel); appendWideText(detailBuffer, L" impLevel="); appendHexText(detailBuffer, impLevel); appendWideText(detailBuffer, L" caps="); appendHexText(detailBuffer, capabilitiesValue); })
        void WINAPI hookedCoUninitialize()
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { gCoUninitializeOriginal(); return; }
            gCoUninitializeOriginal();
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"Ole32", L"CoUninitialize", 0, L"");
        }

        // HookedThirdBatchProcess:
        // - Input: Injection extensions, synchronization objects, environment variables, DLL search paths, and User32 hook parameters.
        // - Handling: Continue using the legacy APIMonitor pattern of 'call original function first, then record result and restore error code';
        // - Returns: Preserves the original return semantics of each WinAPI.
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateRemoteThreadEx, gCreateRemoteThreadExOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateRemoteThreadEx",
            (HANDLE processHandle, LPSECURITY_ATTRIBUTES threadAttributes, SIZE_T stackSize, LPTHREAD_START_ROUTINE startAddress, LPVOID parameterPointer, DWORD creationFlags, LPPROC_THREAD_ATTRIBUTE_LIST attributeListPointer, LPDWORD threadIdPointer),
            (processHandle, threadAttributes, stackSize, startAddress, parameterPointer, creationFlags, attributeListPointer, threadIdPointer),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" start="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(startAddress)); appendWideText(detailBuffer, L" param="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parameterPointer)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, creationFlags); appendWideText(detailBuffer, L" tid="); appendUnsignedText(detailBuffer, threadIdPointer != nullptr ? *threadIdPointer : 0); appendWideText(detailBuffer, L" thread="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })

        BOOLEAN WINAPI hookedCreateSymbolicLinkW(LPCWSTR linkPointer, LPCWSTR targetPointer, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gCreateSymbolicLinkWOriginal(linkPointer, targetPointer, flagsValue); }
            const BOOLEAN kResultValue = gCreateSymbolicLinkWOriginal(linkPointer, targetPointer, flagsValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildTwoPathDetailW(detailBuffer, linkPointer, targetPointer, flagsValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateSymbolicLinkW", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        BOOLEAN WINAPI hookedCreateSymbolicLinkA(LPCSTR linkPointer, LPCSTR targetPointer, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gCreateSymbolicLinkAOriginal(linkPointer, targetPointer, flagsValue); }
            const BOOLEAN kResultValue = gCreateSymbolicLinkAOriginal(linkPointer, targetPointer, flagsValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            buildTwoPathDetailA(detailBuffer, linkPointer, targetPointer, flagsValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateSymbolicLinkA", kResultValue != FALSE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        DWORD WINAPI hookedGetFinalPathNameByHandleW(HANDLE fileHandle, LPWSTR filePathPointer, DWORD filePathSize, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gGetFinalPathNameByHandleWOriginal(fileHandle, filePathPointer, filePathSize, flagsValue); }
            const DWORD kResultValue = gGetFinalPathNameByHandleWOriginal(fileHandle, filePathPointer, filePathSize, flagsValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"file=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, flagsValue);
            appendWideText(detailBuffer, L" path=");
            if (kResultValue != 0 && kResultValue < filePathSize) { appendWideText(detailBuffer, filePathPointer, kResultValue); }
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetFinalPathNameByHandleW", kResultValue != 0 ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        DWORD WINAPI hookedGetFinalPathNameByHandleA(HANDLE fileHandle, LPSTR filePathPointer, DWORD filePathSize, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gGetFinalPathNameByHandleAOriginal(fileHandle, filePathPointer, filePathSize, flagsValue); }
            const DWORD kResultValue = gGetFinalPathNameByHandleAOriginal(fileHandle, filePathPointer, filePathSize, flagsValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"file=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            appendWideText(detailBuffer, L" flags=");
            appendHexText(detailBuffer, flagsValue);
            appendWideText(detailBuffer, L" path=");
            if (kResultValue != 0 && kResultValue < filePathSize) { appendAnsiText(detailBuffer, filePathPointer, kResultValue); }
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetFinalPathNameByHandleA", kResultValue != 0 ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        APIMON_SIMPLE_BOOL_HOOK(HookedGetFileSizeEx, gGetFileSizeExOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetFileSizeEx",
            (HANDLE fileHandle, PLARGE_INTEGER fileSizePointer), (fileHandle, fileSizePointer),
            { appendWideText(detailBuffer, L"file="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); appendWideText(detailBuffer, L" size="); appendHexText(detailBuffer, fileSizePointer != nullptr ? static_cast<std::uint64_t>(fileSizePointer->QuadPart) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedSetFilePointerEx, gSetFilePointerExOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"SetFilePointerEx",
            (HANDLE fileHandle, LARGE_INTEGER distanceValue, PLARGE_INTEGER newPointer, DWORD moveMethod), (fileHandle, distanceValue, newPointer, moveMethod),
            { appendWideText(detailBuffer, L"file="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); appendWideText(detailBuffer, L" distance="); appendHexText(detailBuffer, static_cast<std::uint64_t>(distanceValue.QuadPart)); appendWideText(detailBuffer, L" method="); appendUnsignedText(detailBuffer, moveMethod); appendWideText(detailBuffer, L" new="); appendHexText(detailBuffer, newPointer != nullptr ? static_cast<std::uint64_t>(newPointer->QuadPart) : 0); })

        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateNamedPipeW, gCreateNamedPipeWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateNamedPipeW",
            (LPCWSTR namePointer, DWORD openMode, DWORD pipeMode, DWORD maxInstances, DWORD outBufferSize, DWORD inBufferSize, DWORD defaultTimeout, LPSECURITY_ATTRIBUTES securityAttributes),
            (namePointer, openMode, pipeMode, maxInstances, outBufferSize, inBufferSize, defaultTimeout, securityAttributes),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" openMode="); appendHexText(detailBuffer, openMode); appendWideText(detailBuffer, L" pipeMode="); appendHexText(detailBuffer, pipeMode); appendWideText(detailBuffer, L" instances="); appendUnsignedText(detailBuffer, maxInstances); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateNamedPipeA, gCreateNamedPipeAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateNamedPipeA",
            (LPCSTR namePointer, DWORD openMode, DWORD pipeMode, DWORD maxInstances, DWORD outBufferSize, DWORD inBufferSize, DWORD defaultTimeout, LPSECURITY_ATTRIBUTES securityAttributes),
            (namePointer, openMode, pipeMode, maxInstances, outBufferSize, inBufferSize, defaultTimeout, securityAttributes),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" openMode="); appendHexText(detailBuffer, openMode); appendWideText(detailBuffer, L" pipeMode="); appendHexText(detailBuffer, pipeMode); appendWideText(detailBuffer, L" instances="); appendUnsignedText(detailBuffer, maxInstances); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedConnectNamedPipe, gConnectNamedPipeOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"ConnectNamedPipe",
            (HANDLE pipeHandle, LPOVERLAPPED overlappedPointer), (pipeHandle, overlappedPointer),
            { buildSimpleHandleDetail(detailBuffer, L"pipe", pipeHandle); })
        APIMON_SIMPLE_BOOL_HOOK(HookedDisconnectNamedPipe, gDisconnectNamedPipeOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"DisconnectNamedPipe",
            (HANDLE pipeHandle), (pipeHandle),
            { buildSimpleHandleDetail(detailBuffer, L"pipe", pipeHandle); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWaitNamedPipeW, gWaitNamedPipeWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"WaitNamedPipeW",
            (LPCWSTR namePointer, DWORD timeoutValue), (namePointer, timeoutValue),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" timeout="); appendUnsignedText(detailBuffer, timeoutValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWaitNamedPipeA, gWaitNamedPipeAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"WaitNamedPipeA",
            (LPCSTR namePointer, DWORD timeoutValue), (namePointer, timeoutValue),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" timeout="); appendUnsignedText(detailBuffer, timeoutValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedTransactNamedPipe, gTransactNamedPipeOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"TransactNamedPipe",
            (HANDLE pipeHandle, LPVOID inBufferPointer, DWORD inBufferSize, LPVOID outBufferPointer, DWORD outBufferSize, LPDWORD bytesReadPointer, LPOVERLAPPED overlappedPointer),
            (pipeHandle, inBufferPointer, inBufferSize, outBufferPointer, outBufferSize, bytesReadPointer, overlappedPointer),
            { appendWideText(detailBuffer, L"pipe="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(pipeHandle)); appendWideText(detailBuffer, L" in="); appendUnsignedText(detailBuffer, inBufferSize); appendWideText(detailBuffer, L" out="); appendUnsignedText(detailBuffer, outBufferSize); appendWideText(detailBuffer, L" read="); appendUnsignedText(detailBuffer, bytesReadPointer != nullptr ? *bytesReadPointer : 0); })

        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateMutexW, gCreateMutexWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateMutexW",
            (LPSECURITY_ATTRIBUTES securityAttributes, BOOL initialOwner, LPCWSTR namePointer), (securityAttributes, initialOwner, namePointer),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" initialOwner="); appendUnsignedText(detailBuffer, initialOwner != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateMutexA, gCreateMutexAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateMutexA",
            (LPSECURITY_ATTRIBUTES securityAttributes, BOOL initialOwner, LPCSTR namePointer), (securityAttributes, initialOwner, namePointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" initialOwner="); appendUnsignedText(detailBuffer, initialOwner != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedOpenMutexW, gOpenMutexWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"OpenMutexW",
            (DWORD desiredAccess, BOOL inheritHandle, LPCWSTR namePointer), (desiredAccess, inheritHandle, namePointer),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedOpenMutexA, gOpenMutexAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"OpenMutexA",
            (DWORD desiredAccess, BOOL inheritHandle, LPCSTR namePointer), (desiredAccess, inheritHandle, namePointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })

        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateEventW, gCreateEventWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateEventW",
            (LPSECURITY_ATTRIBUTES securityAttributes, BOOL manualReset, BOOL initialState, LPCWSTR namePointer), (securityAttributes, manualReset, initialState, namePointer),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" manual="); appendUnsignedText(detailBuffer, manualReset != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" initial="); appendUnsignedText(detailBuffer, initialState != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateEventA, gCreateEventAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateEventA",
            (LPSECURITY_ATTRIBUTES securityAttributes, BOOL manualReset, BOOL initialState, LPCSTR namePointer), (securityAttributes, manualReset, initialState, namePointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" manual="); appendUnsignedText(detailBuffer, manualReset != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" initial="); appendUnsignedText(detailBuffer, initialState != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedOpenEventW, gOpenEventWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"OpenEventW",
            (DWORD desiredAccess, BOOL inheritHandle, LPCWSTR namePointer), (desiredAccess, inheritHandle, namePointer),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedOpenEventA, gOpenEventAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"OpenEventA",
            (DWORD desiredAccess, BOOL inheritHandle, LPCSTR namePointer), (desiredAccess, inheritHandle, namePointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateSemaphoreW, gCreateSemaphoreWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateSemaphoreW",
            (LPSECURITY_ATTRIBUTES securityAttributes, LONG initialCount, LONG maximumCount, LPCWSTR namePointer), (securityAttributes, initialCount, maximumCount, namePointer),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" initial="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(initialCount < 0 ? 0 : initialCount)); appendWideText(detailBuffer, L" max="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(maximumCount < 0 ? 0 : maximumCount)); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateSemaphoreA, gCreateSemaphoreAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateSemaphoreA",
            (LPSECURITY_ATTRIBUTES securityAttributes, LONG initialCount, LONG maximumCount, LPCSTR namePointer), (securityAttributes, initialCount, maximumCount, namePointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" initial="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(initialCount < 0 ? 0 : initialCount)); appendWideText(detailBuffer, L" max="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(maximumCount < 0 ? 0 : maximumCount)); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedOpenSemaphoreW, gOpenSemaphoreWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"OpenSemaphoreW",
            (DWORD desiredAccess, BOOL inheritHandle, LPCWSTR namePointer), (desiredAccess, inheritHandle, namePointer),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedOpenSemaphoreA, gOpenSemaphoreAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"OpenSemaphoreA",
            (DWORD desiredAccess, BOOL inheritHandle, LPCSTR namePointer), (desiredAccess, inheritHandle, namePointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })

        DWORD WINAPI hookedWaitForSingleObject(HANDLE handleValue, DWORD millisecondsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gWaitForSingleObjectOriginal(handleValue, millisecondsValue); }
            const DWORD kResultValue = gWaitForSingleObjectOriginal(handleValue, millisecondsValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"handle=");
            appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(handleValue));
            appendWideText(detailBuffer, L" timeout=");
            appendUnsignedText(detailBuffer, millisecondsValue);
            appendWideText(detailBuffer, L" result=");
            appendHexText(detailBuffer, kResultValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"WaitForSingleObject", kResultValue != WAIT_FAILED ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        DWORD WINAPI hookedWaitForMultipleObjects(DWORD countValue, const HANDLE* handlesPointer, BOOL waitAll, DWORD millisecondsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gWaitForMultipleObjectsOriginal(countValue, handlesPointer, waitAll, millisecondsValue); }
            const DWORD kResultValue = gWaitForMultipleObjectsOriginal(countValue, handlesPointer, waitAll, millisecondsValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"count=");
            appendUnsignedText(detailBuffer, countValue);
            appendWideText(detailBuffer, L" waitAll=");
            appendUnsignedText(detailBuffer, waitAll != FALSE ? 1ULL : 0ULL);
            appendWideText(detailBuffer, L" timeout=");
            appendUnsignedText(detailBuffer, millisecondsValue);
            appendWideText(detailBuffer, L" result=");
            appendHexText(detailBuffer, kResultValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"WaitForMultipleObjects", kResultValue != WAIT_FAILED ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        APIMON_SIMPLE_BOOL_HOOK(HookedSetEvent, gSetEventOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"SetEvent",
            (HANDLE eventHandle), (eventHandle),
            { buildSimpleHandleDetail(detailBuffer, L"event", eventHandle); })
        APIMON_SIMPLE_BOOL_HOOK(HookedResetEvent, gResetEventOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"ResetEvent",
            (HANDLE eventHandle), (eventHandle),
            { buildSimpleHandleDetail(detailBuffer, L"event", eventHandle); })
        APIMON_SIMPLE_BOOL_HOOK(HookedReleaseMutex, gReleaseMutexOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"ReleaseMutex",
            (HANDLE mutexHandle), (mutexHandle),
            { buildSimpleHandleDetail(detailBuffer, L"mutex", mutexHandle); })
        APIMON_SIMPLE_BOOL_HOOK(HookedReleaseSemaphore, gReleaseSemaphoreOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"ReleaseSemaphore",
            (HANDLE semaphoreHandle, LONG releaseCount, LPLONG previousCountPointer), (semaphoreHandle, releaseCount, previousCountPointer),
            { appendWideText(detailBuffer, L"semaphore="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(semaphoreHandle)); appendWideText(detailBuffer, L" release="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(releaseCount < 0 ? 0 : releaseCount)); appendWideText(detailBuffer, L" previous="); appendUnsignedText(detailBuffer, previousCountPointer != nullptr ? static_cast<unsigned long long>(*previousCountPointer) : 0ULL); })

        DWORD WINAPI hookedGetEnvironmentVariableW(LPCWSTR namePointer, LPWSTR bufferPointer, DWORD sizeValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gGetEnvironmentVariableWOriginal(namePointer, bufferPointer, sizeValue); }
            const DWORD kResultValue = gGetEnvironmentVariableWOriginal(namePointer, bufferPointer, sizeValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"name=");
            appendWideText(detailBuffer, namePointer);
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, sizeValue);
            appendWideText(detailBuffer, L" resultLen=");
            appendUnsignedText(detailBuffer, kResultValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"GetEnvironmentVariableW", kResultValue != 0 ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        DWORD WINAPI hookedGetEnvironmentVariableA(LPCSTR namePointer, LPSTR bufferPointer, DWORD sizeValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gGetEnvironmentVariableAOriginal(namePointer, bufferPointer, sizeValue); }
            const DWORD kResultValue = gGetEnvironmentVariableAOriginal(namePointer, bufferPointer, sizeValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"name=");
            appendAnsiText(detailBuffer, namePointer);
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, sizeValue);
            appendWideText(detailBuffer, L" resultLen=");
            appendUnsignedText(detailBuffer, kResultValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"GetEnvironmentVariableA", kResultValue != 0 ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        APIMON_SIMPLE_BOOL_HOOK(HookedSetEnvironmentVariableW, gSetEnvironmentVariableWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"SetEnvironmentVariableW",
            (LPCWSTR namePointer, LPCWSTR valuePointer), (namePointer, valuePointer),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" valueLen="); appendUnsignedText(detailBuffer, valuePointer != nullptr ? static_cast<unsigned long long>(::wcslen(valuePointer)) : 0ULL); })
        APIMON_SIMPLE_BOOL_HOOK(HookedSetEnvironmentVariableA, gSetEnvironmentVariableAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"SetEnvironmentVariableA",
            (LPCSTR namePointer, LPCSTR valuePointer), (namePointer, valuePointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" valueLen="); appendUnsignedText(detailBuffer, valuePointer != nullptr ? static_cast<unsigned long long>(::strlen(valuePointer)) : 0ULL); })

        DWORD WINAPI hookedExpandEnvironmentStringsW(LPCWSTR sourcePointer, LPWSTR destinationPointer, DWORD sizeValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gExpandEnvironmentStringsWOriginal(sourcePointer, destinationPointer, sizeValue); }
            const DWORD kResultValue = gExpandEnvironmentStringsWOriginal(sourcePointer, destinationPointer, sizeValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"src=");
            appendWideText(detailBuffer, sourcePointer);
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, sizeValue);
            appendWideText(detailBuffer, L" resultLen=");
            appendUnsignedText(detailBuffer, kResultValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"ExpandEnvironmentStringsW", kResultValue != 0 ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        DWORD WINAPI hookedExpandEnvironmentStringsA(LPCSTR sourcePointer, LPSTR destinationPointer, DWORD sizeValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gExpandEnvironmentStringsAOriginal(sourcePointer, destinationPointer, sizeValue); }
            const DWORD kResultValue = gExpandEnvironmentStringsAOriginal(sourcePointer, destinationPointer, sizeValue);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"src=");
            appendAnsiText(detailBuffer, sourcePointer);
            appendWideText(detailBuffer, L" size=");
            appendUnsignedText(detailBuffer, sizeValue);
            appendWideText(detailBuffer, L" resultLen=");
            appendUnsignedText(detailBuffer, kResultValue);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"ExpandEnvironmentStringsA", kResultValue != 0 ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kResultValue;
        }

        APIMON_SIMPLE_BOOL_HOOK(HookedSetDllDirectoryW, gSetDllDirectoryWOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"SetDllDirectoryW",
            (LPCWSTR pathPointer), (pathPointer),
            { appendWideText(detailBuffer, L"path="); appendWideText(detailBuffer, pathPointer); })
        APIMON_SIMPLE_BOOL_HOOK(HookedSetDllDirectoryA, gSetDllDirectoryAOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"SetDllDirectoryA",
            (LPCSTR pathPointer), (pathPointer),
            { appendWideText(detailBuffer, L"path="); appendAnsiText(detailBuffer, pathPointer); })
        APIMON_SIMPLE_BOOL_HOOK(HookedSetDefaultDllDirectories, gSetDefaultDllDirectoriesOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"SetDefaultDllDirectories",
            (DWORD directoryFlags), (directoryFlags),
            { appendWideText(detailBuffer, L"flags="); appendHexText(detailBuffer, directoryFlags); })
        APIMON_SIMPLE_HANDLE_HOOK(DLL_DIRECTORY_COOKIE, HookedAddDllDirectory, gAddDllDirectoryOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"AddDllDirectory",
            (PCWSTR pathPointer), (pathPointer),
            { appendWideText(detailBuffer, L"path="); appendWideText(detailBuffer, pathPointer); appendWideText(detailBuffer, L" cookie="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedRemoveDllDirectory, gRemoveDllDirectoryOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Kernel32", L"RemoveDllDirectory",
            (DLL_DIRECTORY_COOKIE cookieValue), (cookieValue),
            { appendWideText(detailBuffer, L"cookie="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(cookieValue)); })

        APIMON_SIMPLE_BOOL_HOOK(HookedImpersonateLoggedOnUser, gImpersonateLoggedOnUserOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ImpersonateLoggedOnUser",
            (HANDLE tokenHandle), (tokenHandle),
            { buildSimpleHandleDetail(detailBuffer, L"token", tokenHandle); })
        APIMON_SIMPLE_BOOL_HOOK(HookedRevertToSelf, gRevertToSelfOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"RevertToSelf",
            (), (),
            { detailBuffer[0] = L'\0'; })
        APIMON_SIMPLE_BOOL_HOOK(HookedSetThreadToken, gSetThreadTokenOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"SetThreadToken",
            (PHANDLE threadHandlePointer, HANDLE tokenHandle), (threadHandlePointer, tokenHandle),
            { appendWideText(detailBuffer, L"thread="); appendHexText(detailBuffer, threadHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*threadHandlePointer) : 0); appendWideText(detailBuffer, L" token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); })

        APIMON_SIMPLE_HANDLE_HOOK(HHOOK, HookedSetWindowsHookExW, gSetWindowsHookExWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"SetWindowsHookExW",
            (int hookId, HOOKPROC hookProcPointer, HINSTANCE moduleHandle, DWORD threadId), (hookId, hookProcPointer, moduleHandle, threadId),
            { appendWideText(detailBuffer, L"id="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(hookId < 0 ? 0 : hookId)); appendWideText(detailBuffer, L" proc="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(hookProcPointer)); appendWideText(detailBuffer, L" module="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle)); appendWideText(detailBuffer, L" tid="); appendUnsignedText(detailBuffer, threadId); appendWideText(detailBuffer, L" hook="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HHOOK, HookedSetWindowsHookExA, gSetWindowsHookExAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"SetWindowsHookExA",
            (int hookId, HOOKPROC hookProcPointer, HINSTANCE moduleHandle, DWORD threadId), (hookId, hookProcPointer, moduleHandle, threadId),
            { appendWideText(detailBuffer, L"id="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(hookId < 0 ? 0 : hookId)); appendWideText(detailBuffer, L" proc="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(hookProcPointer)); appendWideText(detailBuffer, L" module="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle)); appendWideText(detailBuffer, L" tid="); appendUnsignedText(detailBuffer, threadId); appendWideText(detailBuffer, L" hook="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedUnhookWindowsHookEx, gUnhookWindowsHookExOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"UnhookWindowsHookEx",
            (HHOOK hookHandle), (hookHandle),
            { buildSimpleHandleDetail(detailBuffer, L"hook", hookHandle); })

        // HookedFourthBatchDiscovery:
        // - Input: PSAPI process/module enumeration, User32 window discovery, GDI screen capture, and clipboard parameters;
        // - Processing: Record reconnaissance, desktop interaction, and screenshot/clipboard access behaviors without copying sensitive buffer contents.
        // - Return: Preserve the original WinAPI return value and restore LastError.
        APIMON_SIMPLE_BOOL_HOOK(HookedEnumProcesses, gEnumProcessesOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Psapi", L"EnumProcesses",
            (DWORD* processIdsPointer, DWORD bytesValue, DWORD* bytesNeededPointer), (processIdsPointer, bytesValue, bytesNeededPointer),
            { appendWideText(detailBuffer, L"bytes="); appendUnsignedText(detailBuffer, bytesValue); appendWideText(detailBuffer, L" needed="); appendUnsignedText(detailBuffer, bytesNeededPointer != nullptr ? *bytesNeededPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedEnumProcessModules, gEnumProcessModulesOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Psapi", L"EnumProcessModules",
            (HANDLE processHandle, HMODULE* modulePointer, DWORD bytesValue, LPDWORD bytesNeededPointer), (processHandle, modulePointer, bytesValue, bytesNeededPointer),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, bytesValue); appendWideText(detailBuffer, L" needed="); appendUnsignedText(detailBuffer, bytesNeededPointer != nullptr ? *bytesNeededPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedEnumProcessModulesEx, gEnumProcessModulesExOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Psapi", L"EnumProcessModulesEx",
            (HANDLE processHandle, HMODULE* modulePointer, DWORD bytesValue, LPDWORD bytesNeededPointer, DWORD filterFlag), (processHandle, modulePointer, bytesValue, bytesNeededPointer, filterFlag),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, bytesValue); appendWideText(detailBuffer, L" needed="); appendUnsignedText(detailBuffer, bytesNeededPointer != nullptr ? *bytesNeededPointer : 0); appendWideText(detailBuffer, L" filter="); appendHexText(detailBuffer, filterFlag); })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetMappedFileNameW, gGetMappedFileNameWOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Psapi", L"GetMappedFileNameW",
            (HANDLE processHandle, LPVOID baseAddress, LPWSTR fileNamePointer, DWORD sizeValue), (processHandle, baseAddress, fileNamePointer, sizeValue),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" base="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, sizeValue); appendWideText(detailBuffer, L" path="); if (resultValue != 0) { appendWideText(detailBuffer, fileNamePointer, resultValue); } })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetMappedFileNameA, gGetMappedFileNameAOriginal, ks::winapi_monitor::EventCategory::kLoader, L"Psapi", L"GetMappedFileNameA",
            (HANDLE processHandle, LPVOID baseAddress, LPSTR fileNamePointer, DWORD sizeValue), (processHandle, baseAddress, fileNamePointer, sizeValue),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" base="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, sizeValue); appendWideText(detailBuffer, L" path="); if (resultValue != 0) { appendAnsiText(detailBuffer, fileNamePointer, resultValue); } })

        APIMON_SIMPLE_BOOL_HOOK(HookedEnumWindows, gEnumWindowsOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"EnumWindows",
            (WNDENUMPROC callbackPointer, LPARAM parameterValue), (callbackPointer, parameterValue),
            { appendWideText(detailBuffer, L"callback="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(callbackPointer)); appendWideText(detailBuffer, L" param="); appendHexText(detailBuffer, static_cast<std::uint64_t>(parameterValue)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedEnumChildWindows, gEnumChildWindowsOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"EnumChildWindows",
            (HWND parentWindow, WNDENUMPROC callbackPointer, LPARAM parameterValue), (parentWindow, callbackPointer, parameterValue),
            { appendWideText(detailBuffer, L"parent="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parentWindow)); appendWideText(detailBuffer, L" callback="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(callbackPointer)); appendWideText(detailBuffer, L" param="); appendHexText(detailBuffer, static_cast<std::uint64_t>(parameterValue)); })
        APIMON_SIMPLE_HANDLE_HOOK(HWND, HookedFindWindowW, gFindWindowWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"FindWindowW",
            (LPCWSTR classNamePointer, LPCWSTR windowNamePointer), (classNamePointer, windowNamePointer),
            { appendWideText(detailBuffer, L"class="); appendWideText(detailBuffer, classNamePointer); appendWideText(detailBuffer, L" title="); appendWideText(detailBuffer, windowNamePointer); appendWideText(detailBuffer, L" hwnd="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HWND, HookedFindWindowA, gFindWindowAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"FindWindowA",
            (LPCSTR classNamePointer, LPCSTR windowNamePointer), (classNamePointer, windowNamePointer),
            { appendWideText(detailBuffer, L"class="); appendAnsiText(detailBuffer, classNamePointer); appendWideText(detailBuffer, L" title="); appendAnsiText(detailBuffer, windowNamePointer); appendWideText(detailBuffer, L" hwnd="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HWND, HookedFindWindowExW, gFindWindowExWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"FindWindowExW",
            (HWND parentWindow, HWND childAfterWindow, LPCWSTR classNamePointer, LPCWSTR windowNamePointer), (parentWindow, childAfterWindow, classNamePointer, windowNamePointer),
            { appendWideText(detailBuffer, L"parent="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parentWindow)); appendWideText(detailBuffer, L" after="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(childAfterWindow)); appendWideText(detailBuffer, L" class="); appendWideText(detailBuffer, classNamePointer); appendWideText(detailBuffer, L" title="); appendWideText(detailBuffer, windowNamePointer); appendWideText(detailBuffer, L" hwnd="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HWND, HookedFindWindowExA, gFindWindowExAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"FindWindowExA",
            (HWND parentWindow, HWND childAfterWindow, LPCSTR classNamePointer, LPCSTR windowNamePointer), (parentWindow, childAfterWindow, classNamePointer, windowNamePointer),
            { appendWideText(detailBuffer, L"parent="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parentWindow)); appendWideText(detailBuffer, L" after="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(childAfterWindow)); appendWideText(detailBuffer, L" class="); appendAnsiText(detailBuffer, classNamePointer); appendWideText(detailBuffer, L" title="); appendAnsiText(detailBuffer, windowNamePointer); appendWideText(detailBuffer, L" hwnd="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetWindowThreadProcessId, gGetWindowThreadProcessIdOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"GetWindowThreadProcessId",
            (HWND windowHandle, LPDWORD processIdPointer), (windowHandle, processIdPointer),
            { appendWideText(detailBuffer, L"hwnd="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(windowHandle)); appendWideText(detailBuffer, L" pid="); appendUnsignedText(detailBuffer, processIdPointer != nullptr ? *processIdPointer : 0); appendWideText(detailBuffer, L" tid="); appendUnsignedText(detailBuffer, resultValue); })
        APIMON_SIMPLE_HANDLE_HOOK(HWND, HookedGetForegroundWindow, gGetForegroundWindowOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"GetForegroundWindow",
            (), (),
            { appendWideText(detailBuffer, L"hwnd="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HDC, HookedGetDC, gGetDcOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"GetDC",
            (HWND windowHandle), (windowHandle),
            { appendWideText(detailBuffer, L"hwnd="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(windowHandle)); appendWideText(detailBuffer, L" dc="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_INT_POSITIVE_HOOK(HookedReleaseDC, gReleaseDcOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"ReleaseDC",
            (HWND windowHandle, HDC deviceContext), (windowHandle, deviceContext),
            { appendWideText(detailBuffer, L"hwnd="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(windowHandle)); appendWideText(detailBuffer, L" dc="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(deviceContext)); appendWideText(detailBuffer, L" result="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(resultValue < 0 ? 0 : resultValue)); })

        APIMON_SIMPLE_HANDLE_HOOK(HDC, HookedCreateCompatibleDC, gCreateCompatibleDcOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Gdi32", L"CreateCompatibleDC",
            (HDC deviceContext), (deviceContext),
            { appendWideText(detailBuffer, L"sourceDc="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(deviceContext)); appendWideText(detailBuffer, L" dc="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedDeleteDC, gDeleteDcOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Gdi32", L"DeleteDC",
            (HDC deviceContext), (deviceContext),
            { appendWideText(detailBuffer, L"dc="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(deviceContext)); })
        APIMON_SIMPLE_HANDLE_HOOK(HBITMAP, HookedCreateCompatibleBitmap, gCreateCompatibleBitmapOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Gdi32", L"CreateCompatibleBitmap",
            (HDC deviceContext, int widthValue, int heightValue), (deviceContext, widthValue, heightValue),
            { appendWideText(detailBuffer, L"dc="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(deviceContext)); appendWideText(detailBuffer, L" width="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(widthValue < 0 ? 0 : widthValue)); appendWideText(detailBuffer, L" height="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(heightValue < 0 ? 0 : heightValue)); appendWideText(detailBuffer, L" bitmap="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedBitBlt, gBitBltOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Gdi32", L"BitBlt",
            (HDC destinationDc, int xDest, int yDest, int widthValue, int heightValue, HDC sourceDc, int xSource, int ySource, DWORD ropValue),
            (destinationDc, xDest, yDest, widthValue, heightValue, sourceDc, xSource, ySource, ropValue),
            { appendWideText(detailBuffer, L"dst="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(destinationDc)); appendWideText(detailBuffer, L" src="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sourceDc)); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(widthValue < 0 ? 0 : widthValue)); appendWideText(detailBuffer, L"x"); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(heightValue < 0 ? 0 : heightValue)); appendWideText(detailBuffer, L" rop="); appendHexText(detailBuffer, ropValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedStretchBlt, gStretchBltOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Gdi32", L"StretchBlt",
            (HDC destinationDc, int xDest, int yDest, int widthDest, int heightDest, HDC sourceDc, int xSource, int ySource, int widthSource, int heightSource, DWORD ropValue),
            (destinationDc, xDest, yDest, widthDest, heightDest, sourceDc, xSource, ySource, widthSource, heightSource, ropValue),
            { appendWideText(detailBuffer, L"dst="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(destinationDc)); appendWideText(detailBuffer, L" src="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sourceDc)); appendWideText(detailBuffer, L" dstSize="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(widthDest < 0 ? 0 : widthDest)); appendWideText(detailBuffer, L"x"); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(heightDest < 0 ? 0 : heightDest)); appendWideText(detailBuffer, L" srcSize="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(widthSource < 0 ? 0 : widthSource)); appendWideText(detailBuffer, L"x"); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(heightSource < 0 ? 0 : heightSource)); appendWideText(detailBuffer, L" rop="); appendHexText(detailBuffer, ropValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedDeleteObject, gDeleteObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Gdi32", L"DeleteObject",
            (HGDIOBJ objectHandle), (objectHandle),
            { appendWideText(detailBuffer, L"object="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(objectHandle)); })

        APIMON_SIMPLE_BOOL_HOOK(HookedOpenClipboard, gOpenClipboardOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"OpenClipboard",
            (HWND ownerWindow), (ownerWindow),
            { appendWideText(detailBuffer, L"owner="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(ownerWindow)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCloseClipboard, gCloseClipboardOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"CloseClipboard",
            (), (),
            { detailBuffer[0] = L'\0'; })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedGetClipboardData, gGetClipboardDataOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"GetClipboardData",
            (UINT formatValue), (formatValue),
            { appendWideText(detailBuffer, L"format="); appendUnsignedText(detailBuffer, formatValue); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedSetClipboardData, gSetClipboardDataOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"SetClipboardData",
            (UINT formatValue, HANDLE dataHandle), (formatValue, dataHandle),
            { appendWideText(detailBuffer, L"format="); appendUnsignedText(detailBuffer, formatValue); appendWideText(detailBuffer, L" input="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(dataHandle)); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedEmptyClipboard, gEmptyClipboardOriginal, ks::winapi_monitor::EventCategory::kProcess, L"User32", L"EmptyClipboard",
            (), (),
            { detailBuffer[0] = L'\0'; })

        // HookedFourthBatchTelemetry:
        // - Input: ETW session/provider/trace handle and control parameters
        // - Processing: Record user-mode event trace start/stop, provider registration, and event write entry points;
        // - Returns: the original ETW ULONG status code; ERROR_SUCCESS indicates success.
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedStartTraceW, gStartTraceWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"StartTraceW",
            (PTRACEHANDLE traceHandlePointer, LPCWSTR instanceNamePointer, PEVENT_TRACE_PROPERTIES propertiesPointer), (traceHandlePointer, instanceNamePointer, propertiesPointer),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, instanceNamePointer); appendWideText(detailBuffer, L" trace="); appendHexText(detailBuffer, traceHandlePointer != nullptr ? *traceHandlePointer : 0); appendWideText(detailBuffer, L" props="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(propertiesPointer)); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedStartTraceA, gStartTraceAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"StartTraceA",
            (PTRACEHANDLE traceHandlePointer, LPCSTR instanceNamePointer, PEVENT_TRACE_PROPERTIES propertiesPointer), (traceHandlePointer, instanceNamePointer, propertiesPointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, instanceNamePointer); appendWideText(detailBuffer, L" trace="); appendHexText(detailBuffer, traceHandlePointer != nullptr ? *traceHandlePointer : 0); appendWideText(detailBuffer, L" props="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(propertiesPointer)); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedControlTraceW, gControlTraceWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ControlTraceW",
            (TRACEHANDLE traceHandle, LPCWSTR instanceNamePointer, PEVENT_TRACE_PROPERTIES propertiesPointer, ULONG controlCode), (traceHandle, instanceNamePointer, propertiesPointer, controlCode),
            { appendWideText(detailBuffer, L"trace="); appendHexText(detailBuffer, traceHandle); appendWideText(detailBuffer, L" name="); appendWideText(detailBuffer, instanceNamePointer); appendWideText(detailBuffer, L" control="); appendHexText(detailBuffer, controlCode); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedControlTraceA, gControlTraceAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ControlTraceA",
            (TRACEHANDLE traceHandle, LPCSTR instanceNamePointer, PEVENT_TRACE_PROPERTIES propertiesPointer, ULONG controlCode), (traceHandle, instanceNamePointer, propertiesPointer, controlCode),
            { appendWideText(detailBuffer, L"trace="); appendHexText(detailBuffer, traceHandle); appendWideText(detailBuffer, L" name="); appendAnsiText(detailBuffer, instanceNamePointer); appendWideText(detailBuffer, L" control="); appendHexText(detailBuffer, controlCode); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedEnableTraceEx2, gEnableTraceEx2Original, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"EnableTraceEx2",
            (TRACEHANDLE traceHandle, LPCGUID providerIdPointer, ULONG controlCode, UCHAR levelValue, ULONGLONG matchAnyKeyword, ULONGLONG matchAllKeyword, ULONG timeoutValue, void* enableParametersPointer),
            (traceHandle, providerIdPointer, controlCode, levelValue, matchAnyKeyword, matchAllKeyword, timeoutValue, enableParametersPointer),
            { appendWideText(detailBuffer, L"trace="); appendHexText(detailBuffer, traceHandle); appendWideText(detailBuffer, L" provider="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(providerIdPointer)); appendWideText(detailBuffer, L" control="); appendHexText(detailBuffer, controlCode); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, levelValue); appendWideText(detailBuffer, L" any="); appendHexText(detailBuffer, matchAnyKeyword); appendWideText(detailBuffer, L" all="); appendHexText(detailBuffer, matchAllKeyword); })

        TRACEHANDLE WINAPI hookedOpenTraceW(PEVENT_TRACE_LOGFILEW logFilePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gOpenTraceWOriginal(logFilePointer); }
            const TRACEHANDLE kTraceHandle = gOpenTraceWOriginal(logFilePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"logfile=");
            appendWideText(detailBuffer, logFilePointer != nullptr ? logFilePointer->LogFileName : nullptr);
            appendWideText(detailBuffer, L" logger=");
            appendWideText(detailBuffer, logFilePointer != nullptr ? logFilePointer->LoggerName : nullptr);
            appendWideText(detailBuffer, L" trace=");
            appendHexText(detailBuffer, kTraceHandle);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"OpenTraceW", kTraceHandle != INVALID_PROCESSTRACE_HANDLE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kTraceHandle;
        }

        TRACEHANDLE WINAPI hookedOpenTraceA(PEVENT_TRACE_LOGFILEA logFilePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return gOpenTraceAOriginal(logFilePointer); }
            const TRACEHANDLE kTraceHandle = gOpenTraceAOriginal(logFilePointer);
            const DWORD kLastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            appendWideText(detailBuffer, L"logfile=");
            appendAnsiText(detailBuffer, logFilePointer != nullptr ? logFilePointer->LogFileName : nullptr);
            appendWideText(detailBuffer, L" logger=");
            appendAnsiText(detailBuffer, logFilePointer != nullptr ? logFilePointer->LoggerName : nullptr);
            appendWideText(detailBuffer, L" trace=");
            appendHexText(detailBuffer, kTraceHandle);
            SendRawEventWithStatus(ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"OpenTraceA", kTraceHandle != INVALID_PROCESSTRACE_HANDLE ? 0 : kLastError, detailBuffer);
            ::SetLastError(kLastError);
            return kTraceHandle;
        }

        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedProcessTrace, gProcessTraceOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ProcessTrace",
            (PTRACEHANDLE traceHandleArray, ULONG handleCount, LPFILETIME startTimePointer, LPFILETIME endTimePointer), (traceHandleArray, handleCount, startTimePointer, endTimePointer),
            { appendWideText(detailBuffer, L"count="); appendUnsignedText(detailBuffer, handleCount); appendWideText(detailBuffer, L" first="); appendHexText(detailBuffer, traceHandleArray != nullptr && handleCount != 0 ? traceHandleArray[0] : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedCloseTrace, gCloseTraceOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CloseTrace",
            (TRACEHANDLE traceHandle), (traceHandle),
            { appendWideText(detailBuffer, L"trace="); appendHexText(detailBuffer, traceHandle); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedEventRegister, gEventRegisterOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"EventRegister",
            (LPCGUID providerIdPointer, PENABLECALLBACK callbackPointer, PVOID callbackContextPointer, PREGHANDLE registrationHandlePointer), (providerIdPointer, callbackPointer, callbackContextPointer, registrationHandlePointer),
            { appendWideText(detailBuffer, L"provider="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(providerIdPointer)); appendWideText(detailBuffer, L" callback="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(callbackPointer)); appendWideText(detailBuffer, L" reg="); appendHexText(detailBuffer, registrationHandlePointer != nullptr ? *registrationHandlePointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedEventUnregister, gEventUnregisterOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"EventUnregister",
            (REGHANDLE registrationHandle), (registrationHandle),
            { appendWideText(detailBuffer, L"reg="); appendHexText(detailBuffer, registrationHandle); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedEventWrite, gEventWriteOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"EventWrite",
            (REGHANDLE registrationHandle, PCEVENT_DESCRIPTOR eventDescriptorPointer, ULONG userDataCount, PEVENT_DATA_DESCRIPTOR userDataPointer), (registrationHandle, eventDescriptorPointer, userDataCount, userDataPointer),
            { appendWideText(detailBuffer, L"reg="); appendHexText(detailBuffer, registrationHandle); appendWideText(detailBuffer, L" event="); appendUnsignedText(detailBuffer, eventDescriptorPointer != nullptr ? eventDescriptorPointer->Id : 0); appendWideText(detailBuffer, L" fields="); appendUnsignedText(detailBuffer, userDataCount); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedEventWriteEx, gEventWriteExOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"EventWriteEx",
            (REGHANDLE registrationHandle, PCEVENT_DESCRIPTOR eventDescriptorPointer, ULONG64 filterValue, ULONG flagsValue, LPCGUID activityIdPointer, LPCGUID relatedActivityIdPointer, ULONG userDataCount, PEVENT_DATA_DESCRIPTOR userDataPointer),
            (registrationHandle, eventDescriptorPointer, filterValue, flagsValue, activityIdPointer, relatedActivityIdPointer, userDataCount, userDataPointer),
            { appendWideText(detailBuffer, L"reg="); appendHexText(detailBuffer, registrationHandle); appendWideText(detailBuffer, L" event="); appendUnsignedText(detailBuffer, eventDescriptorPointer != nullptr ? eventDescriptorPointer->Id : 0); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" fields="); appendUnsignedText(detailBuffer, userDataCount); })

        // HookedFourthBatchTrustCrypto purpose: Record signatures, certificates, DPAPI, and CNG Key Storage entry points; do not record keys or plaintext content.
        APIMON_SIMPLE_LONG_STATUS_HOOK(HookedWinVerifyTrust, gWinVerifyTrustOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Wintrust", L"WinVerifyTrust",
            (HWND windowHandle, GUID* actionIdPointer, LPVOID dataPointer), (windowHandle, actionIdPointer, dataPointer),
            { appendWideText(detailBuffer, L"hwnd="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(windowHandle)); appendWideText(detailBuffer, L" action="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(actionIdPointer)); appendWideText(detailBuffer, L" data="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(dataPointer)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptQueryObject, gCryptQueryObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Crypt32", L"CryptQueryObject",
            (DWORD objectType, const void* objectPointer, DWORD expectedContentTypeFlags, DWORD expectedFormatTypeFlags, DWORD flagsValue, DWORD* encodingTypePointer, DWORD* contentTypePointer, DWORD* formatTypePointer, HCERTSTORE* certStorePointer, HCRYPTMSG* cryptMsgPointer, const void** contextPointer),
            (objectType, objectPointer, expectedContentTypeFlags, expectedFormatTypeFlags, flagsValue, encodingTypePointer, contentTypePointer, formatTypePointer, certStorePointer, cryptMsgPointer, contextPointer),
            { appendWideText(detailBuffer, L"type="); appendHexText(detailBuffer, objectType); appendWideText(detailBuffer, L" object="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(objectPointer)); appendWideText(detailBuffer, L" content="); appendHexText(detailBuffer, contentTypePointer != nullptr ? *contentTypePointer : 0); appendWideText(detailBuffer, L" format="); appendHexText(detailBuffer, formatTypePointer != nullptr ? *formatTypePointer : 0); })
        APIMON_SIMPLE_HANDLE_HOOK(HCERTSTORE, HookedCertOpenStore, gCertOpenStoreOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Crypt32", L"CertOpenStore",
            (LPCSTR storeProviderPointer, DWORD encodingType, HCRYPTPROV_LEGACY cryptProvider, DWORD flagsValue, const void* parameterPointer),
            (storeProviderPointer, encodingType, cryptProvider, flagsValue, parameterPointer),
            { appendWideText(detailBuffer, L"provider="); appendAnsiText(detailBuffer, storeProviderPointer); appendWideText(detailBuffer, L" encoding="); appendHexText(detailBuffer, encodingType); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" store="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCertCloseStore, gCertCloseStoreOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Crypt32", L"CertCloseStore",
            (HCERTSTORE certStoreHandle, DWORD flagsValue), (certStoreHandle, flagsValue),
            { appendWideText(detailBuffer, L"store="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(certStoreHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_HANDLE_HOOK(PCCERT_CONTEXT, HookedCertFindCertificateInStore, gCertFindCertificateInStoreOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Crypt32", L"CertFindCertificateInStore",
            (HCERTSTORE certStoreHandle, DWORD encodingType, DWORD findFlags, DWORD findType, const void* findParaPointer, PCCERT_CONTEXT previousContextPointer),
            (certStoreHandle, encodingType, findFlags, findType, findParaPointer, previousContextPointer),
            { appendWideText(detailBuffer, L"store="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(certStoreHandle)); appendWideText(detailBuffer, L" findType="); appendHexText(detailBuffer, findType); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, findFlags); appendWideText(detailBuffer, L" cert="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCertGetCertificateChain, gCertGetCertificateChainOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Crypt32", L"CertGetCertificateChain",
            (HCERTCHAINENGINE chainEngineHandle, PCCERT_CONTEXT certContextPointer, LPFILETIME timePointer, HCERTSTORE additionalStoreHandle, PCERT_CHAIN_PARA chainParaPointer, DWORD flagsValue, LPVOID reservedPointer, PCCERT_CHAIN_CONTEXT* chainContextPointer),
            (chainEngineHandle, certContextPointer, timePointer, additionalStoreHandle, chainParaPointer, flagsValue, reservedPointer, chainContextPointer),
            { appendWideText(detailBuffer, L"engine="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(chainEngineHandle)); appendWideText(detailBuffer, L" cert="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(certContextPointer)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" chain="); appendHexText(detailBuffer, chainContextPointer != nullptr ? reinterpret_cast<std::uint64_t>(*chainContextPointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCertVerifyCertificateChainPolicy, gCertVerifyCertificateChainPolicyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Crypt32", L"CertVerifyCertificateChainPolicy",
            (LPCSTR policyPointer, PCCERT_CHAIN_CONTEXT chainContextPointer, PCERT_CHAIN_POLICY_PARA policyParaPointer, PCERT_CHAIN_POLICY_STATUS policyStatusPointer),
            (policyPointer, chainContextPointer, policyParaPointer, policyStatusPointer),
            { appendWideText(detailBuffer, L"policy="); appendAnsiText(detailBuffer, policyPointer); appendWideText(detailBuffer, L" chain="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(chainContextPointer)); appendWideText(detailBuffer, L" error="); appendHexText(detailBuffer, policyStatusPointer != nullptr ? policyStatusPointer->dwError : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptProtectData, gCryptProtectDataOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Crypt32", L"CryptProtectData",
            (DATA_BLOB* dataInPointer, LPCWSTR descriptionPointer, DATA_BLOB* optionalEntropyPointer, PVOID reservedPointer, CRYPTPROTECT_PROMPTSTRUCT* promptPointer, DWORD flagsValue, DATA_BLOB* dataOutPointer),
            (dataInPointer, descriptionPointer, optionalEntropyPointer, reservedPointer, promptPointer, flagsValue, dataOutPointer),
            { appendWideText(detailBuffer, L"inBytes="); appendUnsignedText(detailBuffer, dataInPointer != nullptr ? dataInPointer->cbData : 0); appendWideText(detailBuffer, L" entropyBytes="); appendUnsignedText(detailBuffer, optionalEntropyPointer != nullptr ? optionalEntropyPointer->cbData : 0); appendWideText(detailBuffer, L" outBytes="); appendUnsignedText(detailBuffer, dataOutPointer != nullptr ? dataOutPointer->cbData : 0); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" desc="); appendWideText(detailBuffer, descriptionPointer); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCryptUnprotectData, gCryptUnprotectDataOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Crypt32", L"CryptUnprotectData",
            (DATA_BLOB* dataInPointer, LPWSTR* descriptionPointer, DATA_BLOB* optionalEntropyPointer, PVOID reservedPointer, CRYPTPROTECT_PROMPTSTRUCT* promptPointer, DWORD flagsValue, DATA_BLOB* dataOutPointer),
            (dataInPointer, descriptionPointer, optionalEntropyPointer, reservedPointer, promptPointer, flagsValue, dataOutPointer),
            { appendWideText(detailBuffer, L"inBytes="); appendUnsignedText(detailBuffer, dataInPointer != nullptr ? dataInPointer->cbData : 0); appendWideText(detailBuffer, L" entropyBytes="); appendUnsignedText(detailBuffer, optionalEntropyPointer != nullptr ? optionalEntropyPointer->cbData : 0); appendWideText(detailBuffer, L" outBytes="); appendUnsignedText(detailBuffer, dataOutPointer != nullptr ? dataOutPointer->cbData : 0); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" desc="); appendWideText(detailBuffer, descriptionPointer != nullptr ? *descriptionPointer : nullptr); })

        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedNCryptOpenStorageProvider, gNCryptOpenStorageProviderOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Ncrypt", L"NCryptOpenStorageProvider",
            (NCRYPT_PROV_HANDLE* providerHandlePointer, LPCWSTR providerNamePointer, DWORD flagsValue), (providerHandlePointer, providerNamePointer, flagsValue),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, providerNamePointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" provider="); appendHexText(detailBuffer, providerHandlePointer != nullptr ? static_cast<std::uint64_t>(*providerHandlePointer) : 0); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedNCryptOpenKey, gNCryptOpenKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Ncrypt", L"NCryptOpenKey",
            (NCRYPT_PROV_HANDLE providerHandle, NCRYPT_KEY_HANDLE* keyHandlePointer, LPCWSTR keyNamePointer, DWORD legacyKeySpec, DWORD flagsValue), (providerHandle, keyHandlePointer, keyNamePointer, legacyKeySpec, flagsValue),
            { appendWideText(detailBuffer, L"provider="); appendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); appendWideText(detailBuffer, L" name="); appendWideText(detailBuffer, keyNamePointer); appendWideText(detailBuffer, L" spec="); appendHexText(detailBuffer, legacyKeySpec); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" key="); appendHexText(detailBuffer, keyHandlePointer != nullptr ? static_cast<std::uint64_t>(*keyHandlePointer) : 0); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedNCryptCreatePersistedKey, gNCryptCreatePersistedKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Ncrypt", L"NCryptCreatePersistedKey",
            (NCRYPT_PROV_HANDLE providerHandle, NCRYPT_KEY_HANDLE* keyHandlePointer, LPCWSTR algorithmIdPointer, LPCWSTR keyNamePointer, DWORD legacyKeySpec, DWORD flagsValue), (providerHandle, keyHandlePointer, algorithmIdPointer, keyNamePointer, legacyKeySpec, flagsValue),
            { appendWideText(detailBuffer, L"provider="); appendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); appendWideText(detailBuffer, L" alg="); appendWideText(detailBuffer, algorithmIdPointer); appendWideText(detailBuffer, L" name="); appendWideText(detailBuffer, keyNamePointer); appendWideText(detailBuffer, L" spec="); appendHexText(detailBuffer, legacyKeySpec); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" key="); appendHexText(detailBuffer, keyHandlePointer != nullptr ? static_cast<std::uint64_t>(*keyHandlePointer) : 0); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedNCryptFinalizeKey, gNCryptFinalizeKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Ncrypt", L"NCryptFinalizeKey",
            (NCRYPT_KEY_HANDLE keyHandle, DWORD flagsValue), (keyHandle, flagsValue),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedNCryptEncrypt, gNCryptEncryptOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Ncrypt", L"NCryptEncrypt",
            (NCRYPT_KEY_HANDLE keyHandle, PBYTE inputPointer, DWORD inputLength, VOID* paddingInfoPointer, PBYTE outputPointer, DWORD outputLength, DWORD* resultLengthPointer, DWORD flagsValue),
            (keyHandle, inputPointer, inputLength, paddingInfoPointer, outputPointer, outputLength, resultLengthPointer, flagsValue),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" in="); appendUnsignedText(detailBuffer, inputLength); appendWideText(detailBuffer, L" out="); appendUnsignedText(detailBuffer, outputLength); appendWideText(detailBuffer, L" result="); appendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : 0); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedNCryptDecrypt, gNCryptDecryptOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Ncrypt", L"NCryptDecrypt",
            (NCRYPT_KEY_HANDLE keyHandle, PBYTE inputPointer, DWORD inputLength, VOID* paddingInfoPointer, PBYTE outputPointer, DWORD outputLength, DWORD* resultLengthPointer, DWORD flagsValue),
            (keyHandle, inputPointer, inputLength, paddingInfoPointer, outputPointer, outputLength, resultLengthPointer, flagsValue),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" in="); appendUnsignedText(detailBuffer, inputLength); appendWideText(detailBuffer, L" out="); appendUnsignedText(detailBuffer, outputLength); appendWideText(detailBuffer, L" result="); appendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : 0); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedNCryptSignHash, gNCryptSignHashOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Ncrypt", L"NCryptSignHash",
            (NCRYPT_KEY_HANDLE keyHandle, VOID* paddingInfoPointer, PBYTE hashValuePointer, DWORD hashValueLength, PBYTE signaturePointer, DWORD signatureLength, DWORD* resultLengthPointer, DWORD flagsValue),
            (keyHandle, paddingInfoPointer, hashValuePointer, hashValueLength, signaturePointer, signatureLength, resultLengthPointer, flagsValue),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" hash="); appendUnsignedText(detailBuffer, hashValueLength); appendWideText(detailBuffer, L" sig="); appendUnsignedText(detailBuffer, signatureLength); appendWideText(detailBuffer, L" result="); appendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : 0); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedNCryptVerifySignature, gNCryptVerifySignatureOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Ncrypt", L"NCryptVerifySignature",
            (NCRYPT_KEY_HANDLE keyHandle, VOID* paddingInfoPointer, PBYTE hashValuePointer, DWORD hashValueLength, PBYTE signaturePointer, DWORD signatureLength, DWORD flagsValue),
            (keyHandle, paddingInfoPointer, hashValuePointer, hashValueLength, signaturePointer, signatureLength, flagsValue),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" hash="); appendUnsignedText(detailBuffer, hashValueLength); appendWideText(detailBuffer, L" sig="); appendUnsignedText(detailBuffer, signatureLength); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedNCryptExportKey, gNCryptExportKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Ncrypt", L"NCryptExportKey",
            (NCRYPT_KEY_HANDLE keyHandle, NCRYPT_KEY_HANDLE exportKeyHandle, LPCWSTR blobTypePointer, VOID* parameterListPointer, PBYTE outputPointer, DWORD outputLength, DWORD* resultLengthPointer, DWORD flagsValue),
            (keyHandle, exportKeyHandle, blobTypePointer, parameterListPointer, outputPointer, outputLength, resultLengthPointer, flagsValue),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" blob="); appendWideText(detailBuffer, blobTypePointer); appendWideText(detailBuffer, L" out="); appendUnsignedText(detailBuffer, outputLength); appendWideText(detailBuffer, L" result="); appendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : 0); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedNCryptImportKey, gNCryptImportKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Ncrypt", L"NCryptImportKey",
            (NCRYPT_PROV_HANDLE providerHandle, NCRYPT_KEY_HANDLE importKeyHandle, LPCWSTR blobTypePointer, VOID* parameterListPointer, NCRYPT_KEY_HANDLE* keyHandlePointer, PBYTE inputPointer, DWORD inputLength, DWORD flagsValue),
            (providerHandle, importKeyHandle, blobTypePointer, parameterListPointer, keyHandlePointer, inputPointer, inputLength, flagsValue),
            { appendWideText(detailBuffer, L"provider="); appendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); appendWideText(detailBuffer, L" blob="); appendWideText(detailBuffer, blobTypePointer); appendWideText(detailBuffer, L" in="); appendUnsignedText(detailBuffer, inputLength); appendWideText(detailBuffer, L" key="); appendHexText(detailBuffer, keyHandlePointer != nullptr ? static_cast<std::uint64_t>(*keyHandlePointer) : 0); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedNCryptDeleteKey, gNCryptDeleteKeyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Ncrypt", L"NCryptDeleteKey",
            (NCRYPT_KEY_HANDLE keyHandle, DWORD flagsValue), (keyHandle, flagsValue),
            { appendWideText(detailBuffer, L"key="); appendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedNCryptFreeObject, gNCryptFreeObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Ncrypt", L"NCryptFreeObject",
            (NCRYPT_HANDLE objectHandle), (objectHandle),
            { appendWideText(detailBuffer, L"object="); appendHexText(detailBuffer, static_cast<std::uint64_t>(objectHandle)); })

        // HookedFourthBatchRpcNative:
        // - Input: RPC endpoint/binding enumeration parameters and ntdll token/object/sync/query parameters;
        // - Processing: Complete the RPC discovery surface and native layer object/token/synchronous call surface.
        // - Returns: Preserves original semantics of RPC_STATUS or NTSTATUS.
        APIMON_SIMPLE_RPC_STATUS_HOOK(HookedRpcStringBindingComposeW, gRpcStringBindingComposeWOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Rpcrt4", L"RpcStringBindingComposeW",
            (RPC_WSTR objUuidPointer, RPC_WSTR protocolSequencePointer, RPC_WSTR networkAddressPointer, RPC_WSTR endpointPointer, RPC_WSTR optionsPointer, RPC_WSTR* stringBindingPointer),
            (objUuidPointer, protocolSequencePointer, networkAddressPointer, endpointPointer, optionsPointer, stringBindingPointer),
            { appendWideText(detailBuffer, L"protseq="); appendWideText(detailBuffer, reinterpret_cast<LPCWSTR>(protocolSequencePointer)); appendWideText(detailBuffer, L" addr="); appendWideText(detailBuffer, reinterpret_cast<LPCWSTR>(networkAddressPointer)); appendWideText(detailBuffer, L" endpoint="); appendWideText(detailBuffer, reinterpret_cast<LPCWSTR>(endpointPointer)); appendWideText(detailBuffer, L" binding="); appendHexText(detailBuffer, stringBindingPointer != nullptr ? reinterpret_cast<std::uint64_t>(*stringBindingPointer) : 0); })
        APIMON_SIMPLE_RPC_STATUS_HOOK(HookedRpcStringBindingComposeA, gRpcStringBindingComposeAOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Rpcrt4", L"RpcStringBindingComposeA",
            (RPC_CSTR objUuidPointer, RPC_CSTR protocolSequencePointer, RPC_CSTR networkAddressPointer, RPC_CSTR endpointPointer, RPC_CSTR optionsPointer, RPC_CSTR* stringBindingPointer),
            (objUuidPointer, protocolSequencePointer, networkAddressPointer, endpointPointer, optionsPointer, stringBindingPointer),
            { appendWideText(detailBuffer, L"protseq="); appendAnsiText(detailBuffer, reinterpret_cast<LPCSTR>(protocolSequencePointer)); appendWideText(detailBuffer, L" addr="); appendAnsiText(detailBuffer, reinterpret_cast<LPCSTR>(networkAddressPointer)); appendWideText(detailBuffer, L" endpoint="); appendAnsiText(detailBuffer, reinterpret_cast<LPCSTR>(endpointPointer)); appendWideText(detailBuffer, L" binding="); appendHexText(detailBuffer, stringBindingPointer != nullptr ? reinterpret_cast<std::uint64_t>(*stringBindingPointer) : 0); })
        APIMON_SIMPLE_RPC_STATUS_HOOK(HookedRpcBindingFromStringBindingW, gRpcBindingFromStringBindingWOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Rpcrt4", L"RpcBindingFromStringBindingW",
            (RPC_WSTR stringBindingPointer, RPC_BINDING_HANDLE* bindingHandlePointer), (stringBindingPointer, bindingHandlePointer),
            { appendWideText(detailBuffer, L"bindingText="); appendWideText(detailBuffer, reinterpret_cast<LPCWSTR>(stringBindingPointer)); appendWideText(detailBuffer, L" binding="); appendHexText(detailBuffer, bindingHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*bindingHandlePointer) : 0); })
        APIMON_SIMPLE_RPC_STATUS_HOOK(HookedRpcBindingFromStringBindingA, gRpcBindingFromStringBindingAOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Rpcrt4", L"RpcBindingFromStringBindingA",
            (RPC_CSTR stringBindingPointer, RPC_BINDING_HANDLE* bindingHandlePointer), (stringBindingPointer, bindingHandlePointer),
            { appendWideText(detailBuffer, L"bindingText="); appendAnsiText(detailBuffer, reinterpret_cast<LPCSTR>(stringBindingPointer)); appendWideText(detailBuffer, L" binding="); appendHexText(detailBuffer, bindingHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*bindingHandlePointer) : 0); })
        APIMON_SIMPLE_RPC_STATUS_HOOK(HookedRpcBindingFree, gRpcBindingFreeOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Rpcrt4", L"RpcBindingFree",
            (RPC_BINDING_HANDLE* bindingHandlePointer), (bindingHandlePointer),
            { appendWideText(detailBuffer, L"binding="); appendHexText(detailBuffer, bindingHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*bindingHandlePointer) : 0); })
        APIMON_SIMPLE_RPC_STATUS_HOOK(HookedRpcMgmtEpEltInqBegin, gRpcMgmtEpEltInqBeginOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Rpcrt4", L"RpcMgmtEpEltInqBegin",
            (RPC_BINDING_HANDLE endpointBindingHandle, unsigned long inquiryType, RPC_IF_ID* ifIdPointer, unsigned long versionOption, UUID* objectUuidPointer, RPC_EP_INQ_HANDLE* inquiryContextPointer),
            (endpointBindingHandle, inquiryType, ifIdPointer, versionOption, objectUuidPointer, inquiryContextPointer),
            { appendWideText(detailBuffer, L"binding="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(endpointBindingHandle)); appendWideText(detailBuffer, L" type="); appendHexText(detailBuffer, inquiryType); appendWideText(detailBuffer, L" versionOpt="); appendHexText(detailBuffer, versionOption); appendWideText(detailBuffer, L" inquiry="); appendHexText(detailBuffer, inquiryContextPointer != nullptr ? reinterpret_cast<std::uint64_t>(*inquiryContextPointer) : 0); })
        APIMON_SIMPLE_RPC_STATUS_HOOK(HookedRpcMgmtEpEltInqNextW, gRpcMgmtEpEltInqNextWOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Rpcrt4", L"RpcMgmtEpEltInqNextW",
            (RPC_EP_INQ_HANDLE inquiryContext, RPC_IF_ID* ifIdPointer, RPC_BINDING_HANDLE* bindingHandlePointer, UUID* objectUuidPointer, RPC_WSTR* annotationPointer),
            (inquiryContext, ifIdPointer, bindingHandlePointer, objectUuidPointer, annotationPointer),
            { appendWideText(detailBuffer, L"inquiry="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(inquiryContext)); appendWideText(detailBuffer, L" binding="); appendHexText(detailBuffer, bindingHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*bindingHandlePointer) : 0); appendWideText(detailBuffer, L" annotation="); appendWideText(detailBuffer, annotationPointer != nullptr ? reinterpret_cast<LPCWSTR>(*annotationPointer) : nullptr); })
        APIMON_SIMPLE_RPC_STATUS_HOOK(HookedRpcMgmtEpEltInqNextA, gRpcMgmtEpEltInqNextAOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Rpcrt4", L"RpcMgmtEpEltInqNextA",
            (RPC_EP_INQ_HANDLE inquiryContext, RPC_IF_ID* ifIdPointer, RPC_BINDING_HANDLE* bindingHandlePointer, UUID* objectUuidPointer, RPC_CSTR* annotationPointer),
            (inquiryContext, ifIdPointer, bindingHandlePointer, objectUuidPointer, annotationPointer),
            { appendWideText(detailBuffer, L"inquiry="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(inquiryContext)); appendWideText(detailBuffer, L" binding="); appendHexText(detailBuffer, bindingHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*bindingHandlePointer) : 0); appendWideText(detailBuffer, L" annotation="); appendAnsiText(detailBuffer, annotationPointer != nullptr ? reinterpret_cast<LPCSTR>(*annotationPointer) : nullptr); })
        APIMON_SIMPLE_RPC_STATUS_HOOK(HookedRpcMgmtEpEltInqDone, gRpcMgmtEpEltInqDoneOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Rpcrt4", L"RpcMgmtEpEltInqDone",
            (RPC_EP_INQ_HANDLE* inquiryContextPointer), (inquiryContextPointer),
            { appendWideText(detailBuffer, L"inquiry="); appendHexText(detailBuffer, inquiryContextPointer != nullptr ? reinterpret_cast<std::uint64_t>(*inquiryContextPointer) : 0); })

        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtQueryInformationToken, gNtQueryInformationTokenOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtQueryInformationToken",
            (HANDLE tokenHandle, ULONG infoClass, PVOID tokenInformationPointer, ULONG tokenInformationLength, PULONG returnLengthPointer),
            (tokenHandle, infoClass, tokenInformationPointer, tokenInformationLength, returnLengthPointer),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); appendWideText(detailBuffer, L" class="); appendUnsignedText(detailBuffer, infoClass); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, tokenInformationLength); appendWideText(detailBuffer, L" return="); appendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtSetInformationToken, gNtSetInformationTokenOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtSetInformationToken",
            (HANDLE tokenHandle, ULONG infoClass, PVOID tokenInformationPointer, ULONG tokenInformationLength),
            (tokenHandle, infoClass, tokenInformationPointer, tokenInformationLength),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); appendWideText(detailBuffer, L" class="); appendUnsignedText(detailBuffer, infoClass); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, tokenInformationLength); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtAdjustPrivilegesToken, gNtAdjustPrivilegesTokenOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtAdjustPrivilegesToken",
            (HANDLE tokenHandle, BOOLEAN disableAllPrivileges, PTOKEN_PRIVILEGES newStatePointer, ULONG bufferLength, PTOKEN_PRIVILEGES previousStatePointer, PULONG returnLengthPointer),
            (tokenHandle, disableAllPrivileges, newStatePointer, bufferLength, previousStatePointer, returnLengthPointer),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); appendWideText(detailBuffer, L" disableAll="); appendUnsignedText(detailBuffer, disableAllPrivileges != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" privileges="); appendUnsignedText(detailBuffer, newStatePointer != nullptr ? newStatePointer->PrivilegeCount : 0); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, bufferLength); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtCreateMutant, gNtCreateMutantOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtCreateMutant",
            (PHANDLE mutantHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, BOOLEAN initialOwner),
            (mutantHandlePointer, desiredAccess, objectAttributesPointer, initialOwner),
            { appendWideText(detailBuffer, L"access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" initialOwner="); appendUnsignedText(detailBuffer, initialOwner != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" object="); appendObjectNameText(detailBuffer, objectAttributesPointer); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, mutantHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*mutantHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtOpenMutant, gNtOpenMutantOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtOpenMutant",
            (PHANDLE mutantHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer),
            (mutantHandlePointer, desiredAccess, objectAttributesPointer),
            { appendWideText(detailBuffer, L"access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" object="); appendObjectNameText(detailBuffer, objectAttributesPointer); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, mutantHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*mutantHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtReleaseMutant, gNtReleaseMutantOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtReleaseMutant",
            (HANDLE mutantHandle, PLONG previousCountPointer), (mutantHandle, previousCountPointer),
            { appendWideText(detailBuffer, L"mutant="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(mutantHandle)); appendWideText(detailBuffer, L" previous="); appendUnsignedText(detailBuffer, previousCountPointer != nullptr ? static_cast<unsigned long long>(*previousCountPointer < 0 ? 0 : *previousCountPointer) : 0ULL); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtCreateEvent, gNtCreateEventOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtCreateEvent",
            (PHANDLE eventHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, ULONG eventType, BOOLEAN initialState),
            (eventHandlePointer, desiredAccess, objectAttributesPointer, eventType, initialState),
            { appendWideText(detailBuffer, L"access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, eventType); appendWideText(detailBuffer, L" initial="); appendUnsignedText(detailBuffer, initialState != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" object="); appendObjectNameText(detailBuffer, objectAttributesPointer); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, eventHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*eventHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtOpenEvent, gNtOpenEventOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtOpenEvent",
            (PHANDLE eventHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer),
            (eventHandlePointer, desiredAccess, objectAttributesPointer),
            { appendWideText(detailBuffer, L"access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" object="); appendObjectNameText(detailBuffer, objectAttributesPointer); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, eventHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*eventHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtSetEvent, gNtSetEventOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtSetEvent",
            (HANDLE eventHandle, PLONG previousStatePointer), (eventHandle, previousStatePointer),
            { appendWideText(detailBuffer, L"event="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventHandle)); appendWideText(detailBuffer, L" previous="); appendUnsignedText(detailBuffer, previousStatePointer != nullptr ? static_cast<unsigned long long>(*previousStatePointer < 0 ? 0 : *previousStatePointer) : 0ULL); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtResetEvent, gNtResetEventOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtResetEvent",
            (HANDLE eventHandle, PLONG previousStatePointer), (eventHandle, previousStatePointer),
            { appendWideText(detailBuffer, L"event="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventHandle)); appendWideText(detailBuffer, L" previous="); appendUnsignedText(detailBuffer, previousStatePointer != nullptr ? static_cast<unsigned long long>(*previousStatePointer < 0 ? 0 : *previousStatePointer) : 0ULL); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtWaitForSingleObject, gNtWaitForSingleObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtWaitForSingleObject",
            (HANDLE objectHandle, BOOLEAN alertableValue, PLARGE_INTEGER timeoutPointer), (objectHandle, alertableValue, timeoutPointer),
            { appendWideText(detailBuffer, L"handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(objectHandle)); appendWideText(detailBuffer, L" alertable="); appendUnsignedText(detailBuffer, alertableValue != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" timeout="); appendHexText(detailBuffer, timeoutPointer != nullptr ? static_cast<std::uint64_t>(timeoutPointer->QuadPart) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtWaitForMultipleObjects, gNtWaitForMultipleObjectsOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtWaitForMultipleObjects",
            (ULONG countValue, HANDLE* handlesPointer, ULONG waitType, BOOLEAN alertableValue, PLARGE_INTEGER timeoutPointer),
            (countValue, handlesPointer, waitType, alertableValue, timeoutPointer),
            { appendWideText(detailBuffer, L"count="); appendUnsignedText(detailBuffer, countValue); appendWideText(detailBuffer, L" first="); appendHexText(detailBuffer, handlesPointer != nullptr && countValue != 0 ? reinterpret_cast<std::uint64_t>(handlesPointer[0]) : 0); appendWideText(detailBuffer, L" waitType="); appendUnsignedText(detailBuffer, waitType); appendWideText(detailBuffer, L" alertable="); appendUnsignedText(detailBuffer, alertableValue != FALSE ? 1ULL : 0ULL); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtQuerySystemInformation, gNtQuerySystemInformationOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtQuerySystemInformation",
            (ULONG infoClass, PVOID systemInformationPointer, ULONG systemInformationLength, PULONG returnLengthPointer),
            (infoClass, systemInformationPointer, systemInformationLength, returnLengthPointer),
            { appendWideText(detailBuffer, L"class="); appendUnsignedText(detailBuffer, infoClass); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, systemInformationLength); appendWideText(detailBuffer, L" return="); appendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtQueryObject, gNtQueryObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtQueryObject",
            (HANDLE objectHandle, ULONG infoClass, PVOID objectInformationPointer, ULONG objectInformationLength, PULONG returnLengthPointer),
            (objectHandle, infoClass, objectInformationPointer, objectInformationLength, returnLengthPointer),
            { appendWideText(detailBuffer, L"object="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(objectHandle)); appendWideText(detailBuffer, L" class="); appendUnsignedText(detailBuffer, infoClass); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, objectInformationLength); appendWideText(detailBuffer, L" return="); appendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); })

        // HookedFifthBatchSecurity:
        // - Input: Logon, token, credentials, LSA, and EventLog parameters.
        // - Processing: Cover account authentication, credential access, local security policy enumeration, and log read/write behaviors; do not record password/credential content.
        // - Returns: preserves original Win32 BOOL/HANDLE or NTSTATUS semantics.
        APIMON_SIMPLE_BOOL_HOOK(HookedLogonUserW, gLogonUserWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"LogonUserW",
            (LPCWSTR userNamePointer, LPCWSTR domainPointer, LPCWSTR passwordPointer, DWORD logonType, DWORD logonProvider, PHANDLE tokenHandlePointer),
            (userNamePointer, domainPointer, passwordPointer, logonType, logonProvider, tokenHandlePointer),
            { appendWideText(detailBuffer, L"user="); appendWideText(detailBuffer, domainPointer); appendWideText(detailBuffer, L"\\"); appendWideText(detailBuffer, userNamePointer); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, logonType); appendWideText(detailBuffer, L" provider="); appendUnsignedText(detailBuffer, logonProvider); appendWideText(detailBuffer, L" token="); appendHexText(detailBuffer, tokenHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*tokenHandlePointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedLogonUserA, gLogonUserAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"LogonUserA",
            (LPCSTR userNamePointer, LPCSTR domainPointer, LPCSTR passwordPointer, DWORD logonType, DWORD logonProvider, PHANDLE tokenHandlePointer),
            (userNamePointer, domainPointer, passwordPointer, logonType, logonProvider, tokenHandlePointer),
            { appendWideText(detailBuffer, L"user="); appendAnsiText(detailBuffer, domainPointer); appendWideText(detailBuffer, L"\\"); appendAnsiText(detailBuffer, userNamePointer); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, logonType); appendWideText(detailBuffer, L" provider="); appendUnsignedText(detailBuffer, logonProvider); appendWideText(detailBuffer, L" token="); appendHexText(detailBuffer, tokenHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*tokenHandlePointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedGetTokenInformation, gGetTokenInformationOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"GetTokenInformation",
            (HANDLE tokenHandle, TOKEN_INFORMATION_CLASS infoClass, LPVOID tokenInformationPointer, DWORD tokenInformationLength, PDWORD returnLengthPointer),
            (tokenHandle, infoClass, tokenInformationPointer, tokenInformationLength, returnLengthPointer),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); appendWideText(detailBuffer, L" class="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoClass)); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, tokenInformationLength); appendWideText(detailBuffer, L" return="); appendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedSetTokenInformation, gSetTokenInformationOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"SetTokenInformation",
            (HANDLE tokenHandle, TOKEN_INFORMATION_CLASS infoClass, LPVOID tokenInformationPointer, DWORD tokenInformationLength),
            (tokenHandle, infoClass, tokenInformationPointer, tokenInformationLength),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); appendWideText(detailBuffer, L" class="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoClass)); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, tokenInformationLength); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCheckTokenMembership, gCheckTokenMembershipOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CheckTokenMembership",
            (HANDLE tokenHandle, PSID sidPointer, PBOOL isMemberPointer), (tokenHandle, sidPointer, isMemberPointer),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); appendWideText(detailBuffer, L" sid="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sidPointer)); appendWideText(detailBuffer, L" member="); appendUnsignedText(detailBuffer, isMemberPointer != nullptr && *isMemberPointer != FALSE ? 1ULL : 0ULL); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCreateRestrictedToken, gCreateRestrictedTokenOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CreateRestrictedToken",
            (HANDLE existingTokenHandle, DWORD flagsValue, DWORD disableSidCount, PSID_AND_ATTRIBUTES sidsToDisablePointer, DWORD deletePrivilegeCount, PLUID_AND_ATTRIBUTES privilegesToDeletePointer, DWORD restrictSidCount, PSID_AND_ATTRIBUTES sidsToRestrictPointer, PHANDLE newTokenHandlePointer),
            (existingTokenHandle, flagsValue, disableSidCount, sidsToDisablePointer, deletePrivilegeCount, privilegesToDeletePointer, restrictSidCount, sidsToRestrictPointer, newTokenHandlePointer),
            { appendWideText(detailBuffer, L"token="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(existingTokenHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" disableSids="); appendUnsignedText(detailBuffer, disableSidCount); appendWideText(detailBuffer, L" deletePrivs="); appendUnsignedText(detailBuffer, deletePrivilegeCount); appendWideText(detailBuffer, L" restrictSids="); appendUnsignedText(detailBuffer, restrictSidCount); appendWideText(detailBuffer, L" newToken="); appendHexText(detailBuffer, newTokenHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*newTokenHandlePointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedImpersonateSelf, gImpersonateSelfOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ImpersonateSelf",
            (SECURITY_IMPERSONATION_LEVEL impersonationLevel), (impersonationLevel),
            { appendWideText(detailBuffer, L"level="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(impersonationLevel)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedImpersonateNamedPipeClient, gImpersonateNamedPipeClientOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ImpersonateNamedPipeClient",
            (HANDLE pipeHandle), (pipeHandle),
            { buildSimpleHandleDetail(detailBuffer, L"pipe", pipeHandle); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCredReadW, gCredReadWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CredReadW",
            (LPCWSTR targetNamePointer, DWORD typeValue, DWORD flagsValue, PVOID* credentialPointer), (targetNamePointer, typeValue, flagsValue, credentialPointer),
            { appendWideText(detailBuffer, L"target="); appendWideText(detailBuffer, targetNamePointer); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, typeValue); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" credential="); appendHexText(detailBuffer, credentialPointer != nullptr ? reinterpret_cast<std::uint64_t>(*credentialPointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCredReadA, gCredReadAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CredReadA",
            (LPCSTR targetNamePointer, DWORD typeValue, DWORD flagsValue, PVOID* credentialPointer), (targetNamePointer, typeValue, flagsValue, credentialPointer),
            { appendWideText(detailBuffer, L"target="); appendAnsiText(detailBuffer, targetNamePointer); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, typeValue); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" credential="); appendHexText(detailBuffer, credentialPointer != nullptr ? reinterpret_cast<std::uint64_t>(*credentialPointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCredEnumerateW, gCredEnumerateWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CredEnumerateW",
            (LPCWSTR filterPointer, DWORD flagsValue, DWORD* countPointer, PVOID* credentialArrayPointer), (filterPointer, flagsValue, countPointer, credentialArrayPointer),
            { appendWideText(detailBuffer, L"filter="); appendWideText(detailBuffer, filterPointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" count="); appendUnsignedText(detailBuffer, countPointer != nullptr ? *countPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCredEnumerateA, gCredEnumerateAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CredEnumerateA",
            (LPCSTR filterPointer, DWORD flagsValue, DWORD* countPointer, PVOID* credentialArrayPointer), (filterPointer, flagsValue, countPointer, credentialArrayPointer),
            { appendWideText(detailBuffer, L"filter="); appendAnsiText(detailBuffer, filterPointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" count="); appendUnsignedText(detailBuffer, countPointer != nullptr ? *countPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCredWriteW, gCredWriteWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CredWriteW",
            (PVOID credentialPointer, DWORD flagsValue), (credentialPointer, flagsValue),
            { appendWideText(detailBuffer, L"credential="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(credentialPointer)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCredWriteA, gCredWriteAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CredWriteA",
            (PVOID credentialPointer, DWORD flagsValue), (credentialPointer, flagsValue),
            { appendWideText(detailBuffer, L"credential="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(credentialPointer)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCredDeleteW, gCredDeleteWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CredDeleteW",
            (LPCWSTR targetNamePointer, DWORD typeValue, DWORD flagsValue), (targetNamePointer, typeValue, flagsValue),
            { appendWideText(detailBuffer, L"target="); appendWideText(detailBuffer, targetNamePointer); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, typeValue); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCredDeleteA, gCredDeleteAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CredDeleteA",
            (LPCSTR targetNamePointer, DWORD typeValue, DWORD flagsValue), (targetNamePointer, typeValue, flagsValue),
            { appendWideText(detailBuffer, L"target="); appendAnsiText(detailBuffer, targetNamePointer); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, typeValue); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_VOID_HOOK(HookedCredFree, gCredFreeOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CredFree",
            (PVOID bufferPointer), (bufferPointer),
            { appendWideText(detailBuffer, L"buffer="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(bufferPointer)); })

        APIMON_SIMPLE_NTSTATUS_HOOK(HookedLsaOpenPolicy, gLsaOpenPolicyOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"LsaOpenPolicy",
            (PUNICODE_STRING systemNamePointer, PVOID objectAttributesPointer, ACCESS_MASK desiredAccess, PVOID* policyHandlePointer),
            (systemNamePointer, objectAttributesPointer, desiredAccess, policyHandlePointer),
            { appendWideText(detailBuffer, L"system="); appendUnicodeStringText(detailBuffer, systemNamePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" policy="); appendHexText(detailBuffer, policyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*policyHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedLsaClose, gLsaCloseOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"LsaClose",
            (PVOID objectHandle), (objectHandle),
            { appendWideText(detailBuffer, L"handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(objectHandle)); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedLsaEnumerateLogonSessions, gLsaEnumerateLogonSessionsOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"LsaEnumerateLogonSessions",
            (PULONG logonSessionCountPointer, PVOID* logonSessionListPointer), (logonSessionCountPointer, logonSessionListPointer),
            { appendWideText(detailBuffer, L"count="); appendUnsignedText(detailBuffer, logonSessionCountPointer != nullptr ? *logonSessionCountPointer : 0); appendWideText(detailBuffer, L" list="); appendHexText(detailBuffer, logonSessionListPointer != nullptr ? reinterpret_cast<std::uint64_t>(*logonSessionListPointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedLsaGetLogonSessionData, gLsaGetLogonSessionDataOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"LsaGetLogonSessionData",
            (PVOID logonIdPointer, PVOID* sessionDataPointer), (logonIdPointer, sessionDataPointer),
            { appendWideText(detailBuffer, L"logonId="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(logonIdPointer)); appendWideText(detailBuffer, L" data="); appendHexText(detailBuffer, sessionDataPointer != nullptr ? reinterpret_cast<std::uint64_t>(*sessionDataPointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedLsaFreeReturnBuffer, gLsaFreeReturnBufferOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"LsaFreeReturnBuffer",
            (PVOID bufferPointer), (bufferPointer),
            { appendWideText(detailBuffer, L"buffer="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(bufferPointer)); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedLsaLookupNames2, gLsaLookupNames2Original, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"LsaLookupNames2",
            (PVOID policyHandle, ULONG flagsValue, ULONG countValue, PUNICODE_STRING namesPointer, PVOID* referencedDomainsPointer, PVOID* sidsPointer),
            (policyHandle, flagsValue, countValue, namesPointer, referencedDomainsPointer, sidsPointer),
            { appendWideText(detailBuffer, L"policy="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(policyHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" count="); appendUnsignedText(detailBuffer, countValue); appendWideText(detailBuffer, L" first="); if (namesPointer != nullptr && countValue != 0) { appendUnicodeStringText(detailBuffer, &namesPointer[0]); } })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedLsaLookupSids2, gLsaLookupSids2Original, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"LsaLookupSids2",
            (PVOID policyHandle, ULONG flagsValue, ULONG countValue, PVOID* sidsPointer, PVOID* referencedDomainsPointer, PVOID* namesPointer),
            (policyHandle, flagsValue, countValue, sidsPointer, referencedDomainsPointer, namesPointer),
            { appendWideText(detailBuffer, L"policy="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(policyHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" count="); appendUnsignedText(detailBuffer, countValue); appendWideText(detailBuffer, L" firstSid="); appendHexText(detailBuffer, sidsPointer != nullptr && countValue != 0 ? reinterpret_cast<std::uint64_t>(sidsPointer[0]) : 0); })

        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedOpenEventLogW, gOpenEventLogWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"OpenEventLogW",
            (LPCWSTR serverNamePointer, LPCWSTR sourceNamePointer), (serverNamePointer, sourceNamePointer),
            { appendWideText(detailBuffer, L"server="); appendWideText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" source="); appendWideText(detailBuffer, sourceNamePointer); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedOpenEventLogA, gOpenEventLogAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"OpenEventLogA",
            (LPCSTR serverNamePointer, LPCSTR sourceNamePointer), (serverNamePointer, sourceNamePointer),
            { appendWideText(detailBuffer, L"server="); appendAnsiText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" source="); appendAnsiText(detailBuffer, sourceNamePointer); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedRegisterEventSourceW, gRegisterEventSourceWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"RegisterEventSourceW",
            (LPCWSTR serverNamePointer, LPCWSTR sourceNamePointer), (serverNamePointer, sourceNamePointer),
            { appendWideText(detailBuffer, L"server="); appendWideText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" source="); appendWideText(detailBuffer, sourceNamePointer); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedRegisterEventSourceA, gRegisterEventSourceAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"RegisterEventSourceA",
            (LPCSTR serverNamePointer, LPCSTR sourceNamePointer), (serverNamePointer, sourceNamePointer),
            { appendWideText(detailBuffer, L"server="); appendAnsiText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" source="); appendAnsiText(detailBuffer, sourceNamePointer); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedReadEventLogW, gReadEventLogWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ReadEventLogW",
            (HANDLE eventLogHandle, DWORD readFlags, DWORD recordOffset, LPVOID bufferPointer, DWORD bytesToRead, DWORD* bytesReadPointer, DWORD* minBytesNeededPointer),
            (eventLogHandle, readFlags, recordOffset, bufferPointer, bytesToRead, bytesReadPointer, minBytesNeededPointer),
            { appendWideText(detailBuffer, L"log="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventLogHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, readFlags); appendWideText(detailBuffer, L" offset="); appendUnsignedText(detailBuffer, recordOffset); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, bytesToRead); appendWideText(detailBuffer, L" read="); appendUnsignedText(detailBuffer, bytesReadPointer != nullptr ? *bytesReadPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedReadEventLogA, gReadEventLogAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ReadEventLogA",
            (HANDLE eventLogHandle, DWORD readFlags, DWORD recordOffset, LPVOID bufferPointer, DWORD bytesToRead, DWORD* bytesReadPointer, DWORD* minBytesNeededPointer),
            (eventLogHandle, readFlags, recordOffset, bufferPointer, bytesToRead, bytesReadPointer, minBytesNeededPointer),
            { appendWideText(detailBuffer, L"log="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventLogHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, readFlags); appendWideText(detailBuffer, L" offset="); appendUnsignedText(detailBuffer, recordOffset); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, bytesToRead); appendWideText(detailBuffer, L" read="); appendUnsignedText(detailBuffer, bytesReadPointer != nullptr ? *bytesReadPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedClearEventLogW, gClearEventLogWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ClearEventLogW",
            (HANDLE eventLogHandle, LPCWSTR backupFileNamePointer), (eventLogHandle, backupFileNamePointer),
            { appendWideText(detailBuffer, L"log="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventLogHandle)); appendWideText(detailBuffer, L" backup="); appendWideText(detailBuffer, backupFileNamePointer); })
        APIMON_SIMPLE_BOOL_HOOK(HookedClearEventLogA, gClearEventLogAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ClearEventLogA",
            (HANDLE eventLogHandle, LPCSTR backupFileNamePointer), (eventLogHandle, backupFileNamePointer),
            { appendWideText(detailBuffer, L"log="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventLogHandle)); appendWideText(detailBuffer, L" backup="); appendAnsiText(detailBuffer, backupFileNamePointer); })
        APIMON_SIMPLE_BOOL_HOOK(HookedReportEventW, gReportEventWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ReportEventW",
            (HANDLE eventLogHandle, WORD typeValue, WORD categoryValue, DWORD eventIdValue, PSID userSidPointer, WORD stringCount, DWORD dataSize, LPCWSTR* stringsPointer, LPVOID rawDataPointer),
            (eventLogHandle, typeValue, categoryValue, eventIdValue, userSidPointer, stringCount, dataSize, stringsPointer, rawDataPointer),
            { appendWideText(detailBuffer, L"log="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventLogHandle)); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, typeValue); appendWideText(detailBuffer, L" category="); appendUnsignedText(detailBuffer, categoryValue); appendWideText(detailBuffer, L" event="); appendHexText(detailBuffer, eventIdValue); appendWideText(detailBuffer, L" strings="); appendUnsignedText(detailBuffer, stringCount); appendWideText(detailBuffer, L" data="); appendUnsignedText(detailBuffer, dataSize); })
        APIMON_SIMPLE_BOOL_HOOK(HookedReportEventA, gReportEventAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"ReportEventA",
            (HANDLE eventLogHandle, WORD typeValue, WORD categoryValue, DWORD eventIdValue, PSID userSidPointer, WORD stringCount, DWORD dataSize, LPCSTR* stringsPointer, LPVOID rawDataPointer),
            (eventLogHandle, typeValue, categoryValue, eventIdValue, userSidPointer, stringCount, dataSize, stringsPointer, rawDataPointer),
            { appendWideText(detailBuffer, L"log="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventLogHandle)); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, typeValue); appendWideText(detailBuffer, L" category="); appendUnsignedText(detailBuffer, categoryValue); appendWideText(detailBuffer, L" event="); appendHexText(detailBuffer, eventIdValue); appendWideText(detailBuffer, L" strings="); appendUnsignedText(detailBuffer, stringCount); appendWideText(detailBuffer, L" data="); appendUnsignedText(detailBuffer, dataSize); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCloseEventLog, gCloseEventLogOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Advapi32", L"CloseEventLog",
            (HANDLE eventLogHandle), (eventLogHandle),
            { buildSimpleHandleDetail(detailBuffer, L"log", eventLogHandle); })

        // HookedFifthBatchInventory:
        // - Input: NetAPI, IP Helper, WTS, Job Object, and SSPI/Secur32 parameters.
        // - Processing: Complete domain/share/session enumeration, network connection table enumeration, terminal session enumeration, process Job control, and authentication context behavior.
        // - Return: preserve original API status codes, BOOL, HANDLE, or void semantics.
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedNetUserEnum, gNetUserEnumOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Netapi32", L"NetUserEnum",
            (LPCWSTR serverNamePointer, DWORD levelValue, DWORD filterValue, LPBYTE* bufferPointer, DWORD preferredMaxLength, LPDWORD entriesReadPointer, LPDWORD totalEntriesPointer, LPDWORD resumeHandlePointer),
            (serverNamePointer, levelValue, filterValue, bufferPointer, preferredMaxLength, entriesReadPointer, totalEntriesPointer, resumeHandlePointer),
            { appendWideText(detailBuffer, L"server="); appendWideText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, levelValue); appendWideText(detailBuffer, L" filter="); appendHexText(detailBuffer, filterValue); appendWideText(detailBuffer, L" read="); appendUnsignedText(detailBuffer, entriesReadPointer != nullptr ? *entriesReadPointer : 0); appendWideText(detailBuffer, L" total="); appendUnsignedText(detailBuffer, totalEntriesPointer != nullptr ? *totalEntriesPointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedNetLocalGroupEnum, gNetLocalGroupEnumOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Netapi32", L"NetLocalGroupEnum",
            (LPCWSTR serverNamePointer, DWORD levelValue, LPBYTE* bufferPointer, DWORD preferredMaxLength, LPDWORD entriesReadPointer, LPDWORD totalEntriesPointer, PDWORD_PTR resumeHandlePointer),
            (serverNamePointer, levelValue, bufferPointer, preferredMaxLength, entriesReadPointer, totalEntriesPointer, resumeHandlePointer),
            { appendWideText(detailBuffer, L"server="); appendWideText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, levelValue); appendWideText(detailBuffer, L" read="); appendUnsignedText(detailBuffer, entriesReadPointer != nullptr ? *entriesReadPointer : 0); appendWideText(detailBuffer, L" total="); appendUnsignedText(detailBuffer, totalEntriesPointer != nullptr ? *totalEntriesPointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedNetGroupEnum, gNetGroupEnumOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Netapi32", L"NetGroupEnum",
            (LPCWSTR serverNamePointer, DWORD levelValue, LPBYTE* bufferPointer, DWORD preferredMaxLength, LPDWORD entriesReadPointer, LPDWORD totalEntriesPointer, PDWORD_PTR resumeHandlePointer),
            (serverNamePointer, levelValue, bufferPointer, preferredMaxLength, entriesReadPointer, totalEntriesPointer, resumeHandlePointer),
            { appendWideText(detailBuffer, L"server="); appendWideText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, levelValue); appendWideText(detailBuffer, L" read="); appendUnsignedText(detailBuffer, entriesReadPointer != nullptr ? *entriesReadPointer : 0); appendWideText(detailBuffer, L" total="); appendUnsignedText(detailBuffer, totalEntriesPointer != nullptr ? *totalEntriesPointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedNetShareEnum, gNetShareEnumOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Netapi32", L"NetShareEnum",
            (LPWSTR serverNamePointer, DWORD levelValue, LPBYTE* bufferPointer, DWORD preferredMaxLength, LPDWORD entriesReadPointer, LPDWORD totalEntriesPointer, LPDWORD resumeHandlePointer),
            (serverNamePointer, levelValue, bufferPointer, preferredMaxLength, entriesReadPointer, totalEntriesPointer, resumeHandlePointer),
            { appendWideText(detailBuffer, L"server="); appendWideText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, levelValue); appendWideText(detailBuffer, L" read="); appendUnsignedText(detailBuffer, entriesReadPointer != nullptr ? *entriesReadPointer : 0); appendWideText(detailBuffer, L" total="); appendUnsignedText(detailBuffer, totalEntriesPointer != nullptr ? *totalEntriesPointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedNetSessionEnum, gNetSessionEnumOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Netapi32", L"NetSessionEnum",
            (LPWSTR serverNamePointer, LPWSTR uncClientNamePointer, LPWSTR userNamePointer, DWORD levelValue, LPBYTE* bufferPointer, DWORD preferredMaxLength, LPDWORD entriesReadPointer, LPDWORD totalEntriesPointer, LPDWORD resumeHandlePointer),
            (serverNamePointer, uncClientNamePointer, userNamePointer, levelValue, bufferPointer, preferredMaxLength, entriesReadPointer, totalEntriesPointer, resumeHandlePointer),
            { appendWideText(detailBuffer, L"server="); appendWideText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" client="); appendWideText(detailBuffer, uncClientNamePointer); appendWideText(detailBuffer, L" user="); appendWideText(detailBuffer, userNamePointer); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, levelValue); appendWideText(detailBuffer, L" read="); appendUnsignedText(detailBuffer, entriesReadPointer != nullptr ? *entriesReadPointer : 0); appendWideText(detailBuffer, L" total="); appendUnsignedText(detailBuffer, totalEntriesPointer != nullptr ? *totalEntriesPointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedNetServerEnum, gNetServerEnumOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Netapi32", L"NetServerEnum",
            (LPCWSTR serverNamePointer, DWORD levelValue, LPBYTE* bufferPointer, DWORD preferredMaxLength, LPDWORD entriesReadPointer, LPDWORD totalEntriesPointer, DWORD serverType, LPCWSTR domainPointer, LPDWORD resumeHandlePointer),
            (serverNamePointer, levelValue, bufferPointer, preferredMaxLength, entriesReadPointer, totalEntriesPointer, serverType, domainPointer, resumeHandlePointer),
            { appendWideText(detailBuffer, L"server="); appendWideText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" domain="); appendWideText(detailBuffer, domainPointer); appendWideText(detailBuffer, L" type="); appendHexText(detailBuffer, serverType); appendWideText(detailBuffer, L" read="); appendUnsignedText(detailBuffer, entriesReadPointer != nullptr ? *entriesReadPointer : 0); appendWideText(detailBuffer, L" total="); appendUnsignedText(detailBuffer, totalEntriesPointer != nullptr ? *totalEntriesPointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedNetWkstaGetInfo, gNetWkstaGetInfoOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Netapi32", L"NetWkstaGetInfo",
            (LPWSTR serverNamePointer, DWORD levelValue, LPBYTE* bufferPointer), (serverNamePointer, levelValue, bufferPointer),
            { appendWideText(detailBuffer, L"server="); appendWideText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, levelValue); appendWideText(detailBuffer, L" buffer="); appendHexText(detailBuffer, bufferPointer != nullptr ? reinterpret_cast<std::uint64_t>(*bufferPointer) : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedNetApiBufferFree, gNetApiBufferFreeOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Netapi32", L"NetApiBufferFree",
            (LPVOID bufferPointer), (bufferPointer),
            { appendWideText(detailBuffer, L"buffer="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(bufferPointer)); })

        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedGetExtendedTcpTable, gGetExtendedTcpTableOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Iphlpapi", L"GetExtendedTcpTable",
            (PVOID tcpTablePointer, PDWORD sizePointer, BOOL orderValue, ULONG familyValue, ULONG tableClassValue, ULONG reservedValue),
            (tcpTablePointer, sizePointer, orderValue, familyValue, tableClassValue, reservedValue),
            { appendWideText(detailBuffer, L"family="); appendUnsignedText(detailBuffer, familyValue); appendWideText(detailBuffer, L" class="); appendUnsignedText(detailBuffer, tableClassValue); appendWideText(detailBuffer, L" ordered="); appendUnsignedText(detailBuffer, orderValue != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedGetExtendedUdpTable, gGetExtendedUdpTableOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Iphlpapi", L"GetExtendedUdpTable",
            (PVOID udpTablePointer, PDWORD sizePointer, BOOL orderValue, ULONG familyValue, ULONG tableClassValue, ULONG reservedValue),
            (udpTablePointer, sizePointer, orderValue, familyValue, tableClassValue, reservedValue),
            { appendWideText(detailBuffer, L"family="); appendUnsignedText(detailBuffer, familyValue); appendWideText(detailBuffer, L" class="); appendUnsignedText(detailBuffer, tableClassValue); appendWideText(detailBuffer, L" ordered="); appendUnsignedText(detailBuffer, orderValue != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedGetTcpTable2, gGetTcpTable2Original, ks::winapi_monitor::EventCategory::kNetwork, L"Iphlpapi", L"GetTcpTable2",
            (PVOID tcpTablePointer, PULONG sizePointer, BOOL orderValue), (tcpTablePointer, sizePointer, orderValue),
            { appendWideText(detailBuffer, L"ordered="); appendUnsignedText(detailBuffer, orderValue != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedGetUdpTable, gGetUdpTableOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Iphlpapi", L"GetUdpTable",
            (PVOID udpTablePointer, PDWORD sizePointer, BOOL orderValue), (udpTablePointer, sizePointer, orderValue),
            { appendWideText(detailBuffer, L"ordered="); appendUnsignedText(detailBuffer, orderValue != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedGetAdaptersAddresses, gGetAdaptersAddressesOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Iphlpapi", L"GetAdaptersAddresses",
            (ULONG familyValue, ULONG flagsValue, PVOID reservedPointer, PVOID addressesPointer, PULONG sizePointer),
            (familyValue, flagsValue, reservedPointer, addressesPointer, sizePointer),
            { appendWideText(detailBuffer, L"family="); appendUnsignedText(detailBuffer, familyValue); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedGetNetworkParams, gGetNetworkParamsOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Iphlpapi", L"GetNetworkParams",
            (PVOID fixedInfoPointer, PULONG sizePointer), (fixedInfoPointer, sizePointer),
            { appendWideText(detailBuffer, L"size="); appendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedGetIpNetTable2, gGetIpNetTable2Original, ks::winapi_monitor::EventCategory::kNetwork, L"Iphlpapi", L"GetIpNetTable2",
            (USHORT familyValue, PVOID* tablePointer), (familyValue, tablePointer),
            { appendWideText(detailBuffer, L"family="); appendUnsignedText(detailBuffer, familyValue); appendWideText(detailBuffer, L" table="); appendHexText(detailBuffer, tablePointer != nullptr ? reinterpret_cast<std::uint64_t>(*tablePointer) : 0); })
        APIMON_SIMPLE_ULONG_STATUS_HOOK(HookedGetIfTable2, gGetIfTable2Original, ks::winapi_monitor::EventCategory::kNetwork, L"Iphlpapi", L"GetIfTable2",
            (PVOID* tablePointer), (tablePointer),
            { appendWideText(detailBuffer, L"table="); appendHexText(detailBuffer, tablePointer != nullptr ? reinterpret_cast<std::uint64_t>(*tablePointer) : 0); })
        APIMON_SIMPLE_VOID_HOOK(HookedFreeMibTable, gFreeMibTableOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Iphlpapi", L"FreeMibTable",
            (PVOID memoryPointer), (memoryPointer),
            { appendWideText(detailBuffer, L"memory="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(memoryPointer)); })

        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedWTSOpenServerW, gWtsOpenServerWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Wtsapi32", L"WTSOpenServerW",
            (LPWSTR serverNamePointer), (serverNamePointer),
            { appendWideText(detailBuffer, L"server="); appendWideText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedWTSOpenServerA, gWtsOpenServerAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Wtsapi32", L"WTSOpenServerA",
            (LPSTR serverNamePointer), (serverNamePointer),
            { appendWideText(detailBuffer, L"server="); appendAnsiText(detailBuffer, serverNamePointer); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_VOID_HOOK(HookedWTSCloseServer, gWtsCloseServerOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Wtsapi32", L"WTSCloseServer",
            (HANDLE serverHandle), (serverHandle),
            { buildSimpleHandleDetail(detailBuffer, L"server", serverHandle); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWTSEnumerateSessionsW, gWtsEnumerateSessionsWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Wtsapi32", L"WTSEnumerateSessionsW",
            (HANDLE serverHandle, DWORD reservedValue, DWORD versionValue, PVOID* sessionInfoPointer, DWORD* countPointer),
            (serverHandle, reservedValue, versionValue, sessionInfoPointer, countPointer),
            { appendWideText(detailBuffer, L"server="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serverHandle)); appendWideText(detailBuffer, L" version="); appendUnsignedText(detailBuffer, versionValue); appendWideText(detailBuffer, L" count="); appendUnsignedText(detailBuffer, countPointer != nullptr ? *countPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWTSEnumerateSessionsA, gWtsEnumerateSessionsAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Wtsapi32", L"WTSEnumerateSessionsA",
            (HANDLE serverHandle, DWORD reservedValue, DWORD versionValue, PVOID* sessionInfoPointer, DWORD* countPointer),
            (serverHandle, reservedValue, versionValue, sessionInfoPointer, countPointer),
            { appendWideText(detailBuffer, L"server="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serverHandle)); appendWideText(detailBuffer, L" version="); appendUnsignedText(detailBuffer, versionValue); appendWideText(detailBuffer, L" count="); appendUnsignedText(detailBuffer, countPointer != nullptr ? *countPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWTSEnumerateProcessesW, gWtsEnumerateProcessesWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Wtsapi32", L"WTSEnumerateProcessesW",
            (HANDLE serverHandle, DWORD reservedValue, DWORD versionValue, PVOID* processInfoPointer, DWORD* countPointer),
            (serverHandle, reservedValue, versionValue, processInfoPointer, countPointer),
            { appendWideText(detailBuffer, L"server="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serverHandle)); appendWideText(detailBuffer, L" version="); appendUnsignedText(detailBuffer, versionValue); appendWideText(detailBuffer, L" count="); appendUnsignedText(detailBuffer, countPointer != nullptr ? *countPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWTSEnumerateProcessesA, gWtsEnumerateProcessesAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Wtsapi32", L"WTSEnumerateProcessesA",
            (HANDLE serverHandle, DWORD reservedValue, DWORD versionValue, PVOID* processInfoPointer, DWORD* countPointer),
            (serverHandle, reservedValue, versionValue, processInfoPointer, countPointer),
            { appendWideText(detailBuffer, L"server="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serverHandle)); appendWideText(detailBuffer, L" version="); appendUnsignedText(detailBuffer, versionValue); appendWideText(detailBuffer, L" count="); appendUnsignedText(detailBuffer, countPointer != nullptr ? *countPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWTSQuerySessionInformationW, gWtsQuerySessionInformationWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Wtsapi32", L"WTSQuerySessionInformationW",
            (HANDLE serverHandle, DWORD sessionId, int infoClass, LPWSTR* bufferPointer, DWORD* bytesReturnedPointer),
            (serverHandle, sessionId, infoClass, bufferPointer, bytesReturnedPointer),
            { appendWideText(detailBuffer, L"server="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serverHandle)); appendWideText(detailBuffer, L" session="); appendUnsignedText(detailBuffer, sessionId); appendWideText(detailBuffer, L" class="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoClass < 0 ? 0 : infoClass)); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, bytesReturnedPointer != nullptr ? *bytesReturnedPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWTSQuerySessionInformationA, gWtsQuerySessionInformationAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Wtsapi32", L"WTSQuerySessionInformationA",
            (HANDLE serverHandle, DWORD sessionId, int infoClass, LPSTR* bufferPointer, DWORD* bytesReturnedPointer),
            (serverHandle, sessionId, infoClass, bufferPointer, bytesReturnedPointer),
            { appendWideText(detailBuffer, L"server="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serverHandle)); appendWideText(detailBuffer, L" session="); appendUnsignedText(detailBuffer, sessionId); appendWideText(detailBuffer, L" class="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoClass < 0 ? 0 : infoClass)); appendWideText(detailBuffer, L" bytes="); appendUnsignedText(detailBuffer, bytesReturnedPointer != nullptr ? *bytesReturnedPointer : 0); })
        APIMON_SIMPLE_VOID_HOOK(HookedWTSFreeMemory, gWtsFreeMemoryOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Wtsapi32", L"WTSFreeMemory",
            (PVOID memoryPointer), (memoryPointer),
            { appendWideText(detailBuffer, L"memory="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(memoryPointer)); })

        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateJobObjectW, gCreateJobObjectWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateJobObjectW",
            (LPSECURITY_ATTRIBUTES securityAttributesPointer, LPCWSTR namePointer), (securityAttributesPointer, namePointer),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" job="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateJobObjectA, gCreateJobObjectAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"CreateJobObjectA",
            (LPSECURITY_ATTRIBUTES securityAttributesPointer, LPCSTR namePointer), (securityAttributesPointer, namePointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" job="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedOpenJobObjectW, gOpenJobObjectWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"OpenJobObjectW",
            (DWORD desiredAccess, BOOL inheritHandle, LPCWSTR namePointer), (desiredAccess, inheritHandle, namePointer),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" inherit="); appendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" job="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedOpenJobObjectA, gOpenJobObjectAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"OpenJobObjectA",
            (DWORD desiredAccess, BOOL inheritHandle, LPCSTR namePointer), (desiredAccess, inheritHandle, namePointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" inherit="); appendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" job="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedAssignProcessToJobObject, gAssignProcessToJobObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"AssignProcessToJobObject",
            (HANDLE jobHandle, HANDLE processHandle), (jobHandle, processHandle),
            { appendWideText(detailBuffer, L"job="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(jobHandle)); appendWideText(detailBuffer, L" process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedTerminateJobObject, gTerminateJobObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"TerminateJobObject",
            (HANDLE jobHandle, UINT exitCode), (jobHandle, exitCode),
            { appendWideText(detailBuffer, L"job="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(jobHandle)); appendWideText(detailBuffer, L" exit="); appendUnsignedText(detailBuffer, exitCode); })
        APIMON_SIMPLE_BOOL_HOOK(HookedSetInformationJobObject, gSetInformationJobObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"SetInformationJobObject",
            (HANDLE jobHandle, JOBOBJECTINFOCLASS infoClass, LPVOID jobObjectInformationPointer, DWORD jobObjectInformationLength),
            (jobHandle, infoClass, jobObjectInformationPointer, jobObjectInformationLength),
            { appendWideText(detailBuffer, L"job="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(jobHandle)); appendWideText(detailBuffer, L" class="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoClass)); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, jobObjectInformationLength); })
        APIMON_SIMPLE_BOOL_HOOK(HookedQueryInformationJobObject, gQueryInformationJobObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"QueryInformationJobObject",
            (HANDLE jobHandle, JOBOBJECTINFOCLASS infoClass, LPVOID jobObjectInformationPointer, DWORD jobObjectInformationLength, LPDWORD returnLengthPointer),
            (jobHandle, infoClass, jobObjectInformationPointer, jobObjectInformationLength, returnLengthPointer),
            { appendWideText(detailBuffer, L"job="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(jobHandle)); appendWideText(detailBuffer, L" class="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoClass)); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, jobObjectInformationLength); appendWideText(detailBuffer, L" return="); appendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); })

        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedAcquireCredentialsHandleW, gAcquireCredentialsHandleWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Secur32", L"AcquireCredentialsHandleW",
            (LPWSTR principalPointer, LPWSTR packagePointer, ULONG credentialUse, PVOID logonIdPointer, PVOID authDataPointer, PVOID getKeyFnPointer, PVOID getKeyArgumentPointer, PVOID credentialHandlePointer, PVOID expiryPointer),
            (principalPointer, packagePointer, credentialUse, logonIdPointer, authDataPointer, getKeyFnPointer, getKeyArgumentPointer, credentialHandlePointer, expiryPointer),
            { appendWideText(detailBuffer, L"principal="); appendWideText(detailBuffer, principalPointer); appendWideText(detailBuffer, L" package="); appendWideText(detailBuffer, packagePointer); appendWideText(detailBuffer, L" use="); appendHexText(detailBuffer, credentialUse); appendWideText(detailBuffer, L" cred="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(credentialHandlePointer)); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedAcquireCredentialsHandleA, gAcquireCredentialsHandleAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Secur32", L"AcquireCredentialsHandleA",
            (LPSTR principalPointer, LPSTR packagePointer, ULONG credentialUse, PVOID logonIdPointer, PVOID authDataPointer, PVOID getKeyFnPointer, PVOID getKeyArgumentPointer, PVOID credentialHandlePointer, PVOID expiryPointer),
            (principalPointer, packagePointer, credentialUse, logonIdPointer, authDataPointer, getKeyFnPointer, getKeyArgumentPointer, credentialHandlePointer, expiryPointer),
            { appendWideText(detailBuffer, L"principal="); appendAnsiText(detailBuffer, principalPointer); appendWideText(detailBuffer, L" package="); appendAnsiText(detailBuffer, packagePointer); appendWideText(detailBuffer, L" use="); appendHexText(detailBuffer, credentialUse); appendWideText(detailBuffer, L" cred="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(credentialHandlePointer)); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedInitializeSecurityContextW, gInitializeSecurityContextWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Secur32", L"InitializeSecurityContextW",
            (PVOID credentialHandlePointer, PVOID oldContextPointer, LPWSTR targetNamePointer, ULONG requestFlags, ULONG reserved1, ULONG targetDataRep, PVOID inputPointer, ULONG reserved2, PVOID newContextPointer, PVOID outputPointer, PULONG contextAttributesPointer, PVOID expiryPointer),
            (credentialHandlePointer, oldContextPointer, targetNamePointer, requestFlags, reserved1, targetDataRep, inputPointer, reserved2, newContextPointer, outputPointer, contextAttributesPointer, expiryPointer),
            { appendWideText(detailBuffer, L"target="); appendWideText(detailBuffer, targetNamePointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, requestFlags); appendWideText(detailBuffer, L" attrs="); appendHexText(detailBuffer, contextAttributesPointer != nullptr ? *contextAttributesPointer : 0); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedInitializeSecurityContextA, gInitializeSecurityContextAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Secur32", L"InitializeSecurityContextA",
            (PVOID credentialHandlePointer, PVOID oldContextPointer, LPSTR targetNamePointer, ULONG requestFlags, ULONG reserved1, ULONG targetDataRep, PVOID inputPointer, ULONG reserved2, PVOID newContextPointer, PVOID outputPointer, PULONG contextAttributesPointer, PVOID expiryPointer),
            (credentialHandlePointer, oldContextPointer, targetNamePointer, requestFlags, reserved1, targetDataRep, inputPointer, reserved2, newContextPointer, outputPointer, contextAttributesPointer, expiryPointer),
            { appendWideText(detailBuffer, L"target="); appendAnsiText(detailBuffer, targetNamePointer); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, requestFlags); appendWideText(detailBuffer, L" attrs="); appendHexText(detailBuffer, contextAttributesPointer != nullptr ? *contextAttributesPointer : 0); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedAcceptSecurityContext, gAcceptSecurityContextOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Secur32", L"AcceptSecurityContext",
            (PVOID credentialHandlePointer, PVOID contextHandlePointer, PVOID inputPointer, ULONG requestFlags, ULONG targetDataRep, PVOID newContextPointer, PVOID outputPointer, PULONG contextAttributesPointer, PVOID expiryPointer),
            (credentialHandlePointer, contextHandlePointer, inputPointer, requestFlags, targetDataRep, newContextPointer, outputPointer, contextAttributesPointer, expiryPointer),
            { appendWideText(detailBuffer, L"cred="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(credentialHandlePointer)); appendWideText(detailBuffer, L" ctx="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(contextHandlePointer)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, requestFlags); appendWideText(detailBuffer, L" attrs="); appendHexText(detailBuffer, contextAttributesPointer != nullptr ? *contextAttributesPointer : 0); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedEncryptMessage, gEncryptMessageOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Secur32", L"EncryptMessage",
            (PVOID contextHandlePointer, ULONG qualityOfProtection, PVOID messagePointer, ULONG sequenceNumber),
            (contextHandlePointer, qualityOfProtection, messagePointer, sequenceNumber),
            { appendWideText(detailBuffer, L"ctx="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(contextHandlePointer)); appendWideText(detailBuffer, L" qop="); appendHexText(detailBuffer, qualityOfProtection); appendWideText(detailBuffer, L" seq="); appendUnsignedText(detailBuffer, sequenceNumber); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedDecryptMessage, gDecryptMessageOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Secur32", L"DecryptMessage",
            (PVOID contextHandlePointer, PVOID messagePointer, ULONG sequenceNumber, PULONG qualityOfProtectionPointer),
            (contextHandlePointer, messagePointer, sequenceNumber, qualityOfProtectionPointer),
            { appendWideText(detailBuffer, L"ctx="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(contextHandlePointer)); appendWideText(detailBuffer, L" seq="); appendUnsignedText(detailBuffer, sequenceNumber); appendWideText(detailBuffer, L" qop="); appendHexText(detailBuffer, qualityOfProtectionPointer != nullptr ? *qualityOfProtectionPointer : 0); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedDeleteSecurityContext, gDeleteSecurityContextOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Secur32", L"DeleteSecurityContext",
            (PVOID contextHandlePointer), (contextHandlePointer),
            { appendWideText(detailBuffer, L"ctx="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(contextHandlePointer)); })
        APIMON_SIMPLE_SECURITY_STATUS_HOOK(HookedFreeCredentialsHandle, gFreeCredentialsHandleOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Secur32", L"FreeCredentialsHandle",
            (PVOID credentialHandlePointer), (credentialHandlePointer),
            { appendWideText(detailBuffer, L"cred="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(credentialHandlePointer)); })

        // HookedSixthBatchEnumerationPathsNetwork:
        // - Input: Toolhelp enumeration, process image query, path resolution/temporary files, pipes/mailslots, Winsock extensions, and HTTP query parameters.
        // - Processing: Complete reconnaissance of processes/threads/heap, path landing points, IPC creation, socket configuration, and HTTP metadata access surfaces.
        // - Return: Preserve original API return values; restore LastError/WSAError if necessary.
        APIMON_SIMPLE_BOOL_HOOK(HookedProcess32FirstW, gProcess32FirstWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Kernel32", L"Process32FirstW",
            (HANDLE snapshotHandle, PROCESSENTRY32W* entryPointer), (snapshotHandle, entryPointer),
            { appendWideText(detailBuffer, L"snapshot="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); appendWideText(detailBuffer, L" pid="); appendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32ProcessID : 0); appendWideText(detailBuffer, L" exe="); appendWideText(detailBuffer, entryPointer != nullptr ? entryPointer->szExeFile : nullptr); })
        APIMON_SIMPLE_BOOL_HOOK(HookedProcess32FirstA, gProcess32FirstAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Kernel32", L"Process32First",
            (HANDLE snapshotHandle, tagPROCESSENTRY32* entryPointer), (snapshotHandle, entryPointer),
            { appendWideText(detailBuffer, L"snapshot="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); appendWideText(detailBuffer, L" pid="); appendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32ProcessID : 0); appendWideText(detailBuffer, L" exe="); appendAnsiText(detailBuffer, entryPointer != nullptr ? entryPointer->szExeFile : nullptr); })
        APIMON_SIMPLE_BOOL_HOOK(HookedProcess32NextW, gProcess32NextWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Kernel32", L"Process32NextW",
            (HANDLE snapshotHandle, PROCESSENTRY32W* entryPointer), (snapshotHandle, entryPointer),
            { appendWideText(detailBuffer, L"snapshot="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); appendWideText(detailBuffer, L" pid="); appendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32ProcessID : 0); appendWideText(detailBuffer, L" exe="); appendWideText(detailBuffer, entryPointer != nullptr ? entryPointer->szExeFile : nullptr); })
        APIMON_SIMPLE_BOOL_HOOK(HookedProcess32NextA, gProcess32NextAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Kernel32", L"Process32Next",
            (HANDLE snapshotHandle, tagPROCESSENTRY32* entryPointer), (snapshotHandle, entryPointer),
            { appendWideText(detailBuffer, L"snapshot="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); appendWideText(detailBuffer, L" pid="); appendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32ProcessID : 0); appendWideText(detailBuffer, L" exe="); appendAnsiText(detailBuffer, entryPointer != nullptr ? entryPointer->szExeFile : nullptr); })
        APIMON_SIMPLE_BOOL_HOOK(HookedThread32First, gThread32FirstOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Kernel32", L"Thread32First",
            (HANDLE snapshotHandle, LPTHREADENTRY32 entryPointer), (snapshotHandle, entryPointer),
            { appendWideText(detailBuffer, L"snapshot="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); appendWideText(detailBuffer, L" tid="); appendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32ThreadID : 0); appendWideText(detailBuffer, L" ownerPid="); appendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32OwnerProcessID : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedThread32Next, gThread32NextOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Kernel32", L"Thread32Next",
            (HANDLE snapshotHandle, LPTHREADENTRY32 entryPointer), (snapshotHandle, entryPointer),
            { appendWideText(detailBuffer, L"snapshot="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); appendWideText(detailBuffer, L" tid="); appendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32ThreadID : 0); appendWideText(detailBuffer, L" ownerPid="); appendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32OwnerProcessID : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedHeap32ListFirst, gHeap32ListFirstOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Kernel32", L"Heap32ListFirst",
            (HANDLE snapshotHandle, LPHEAPLIST32 heapListPointer), (snapshotHandle, heapListPointer),
            { appendWideText(detailBuffer, L"snapshot="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); appendWideText(detailBuffer, L" pid="); appendUnsignedText(detailBuffer, heapListPointer != nullptr ? heapListPointer->th32ProcessID : 0); appendWideText(detailBuffer, L" heap="); appendHexText(detailBuffer, heapListPointer != nullptr ? static_cast<std::uint64_t>(heapListPointer->th32HeapID) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedHeap32ListNext, gHeap32ListNextOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Kernel32", L"Heap32ListNext",
            (HANDLE snapshotHandle, LPHEAPLIST32 heapListPointer), (snapshotHandle, heapListPointer),
            { appendWideText(detailBuffer, L"snapshot="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); appendWideText(detailBuffer, L" pid="); appendUnsignedText(detailBuffer, heapListPointer != nullptr ? heapListPointer->th32ProcessID : 0); appendWideText(detailBuffer, L" heap="); appendHexText(detailBuffer, heapListPointer != nullptr ? static_cast<std::uint64_t>(heapListPointer->th32HeapID) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedHeap32First, gHeap32FirstOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Kernel32", L"Heap32First",
            (LPHEAPENTRY32 heapEntryPointer, DWORD processId, ULONG_PTR heapId), (heapEntryPointer, processId, heapId),
            { appendWideText(detailBuffer, L"pid="); appendUnsignedText(detailBuffer, processId); appendWideText(detailBuffer, L" heap="); appendHexText(detailBuffer, heapId); appendWideText(detailBuffer, L" block="); appendHexText(detailBuffer, heapEntryPointer != nullptr ? heapEntryPointer->dwAddress : 0); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, heapEntryPointer != nullptr ? heapEntryPointer->dwBlockSize : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedHeap32Next, gHeap32NextOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Kernel32", L"Heap32Next",
            (LPHEAPENTRY32 heapEntryPointer), (heapEntryPointer),
            { appendWideText(detailBuffer, L"pid="); appendUnsignedText(detailBuffer, heapEntryPointer != nullptr ? heapEntryPointer->th32ProcessID : 0); appendWideText(detailBuffer, L" heap="); appendHexText(detailBuffer, heapEntryPointer != nullptr ? static_cast<std::uint64_t>(heapEntryPointer->th32HeapID) : 0); appendWideText(detailBuffer, L" block="); appendHexText(detailBuffer, heapEntryPointer != nullptr ? heapEntryPointer->dwAddress : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedQueryFullProcessImageNameW, gQueryFullProcessImageNameWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"QueryFullProcessImageNameW",
            (HANDLE processHandle, DWORD flagsValue, LPWSTR imageNamePointer, PDWORD sizePointer), (processHandle, flagsValue, imageNamePointer, sizePointer),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); appendWideText(detailBuffer, L" image="); if (resultValue != FALSE) { appendWideText(detailBuffer, imageNamePointer, sizePointer != nullptr ? *sizePointer : static_cast<std::size_t>(-1)); } })
        APIMON_SIMPLE_BOOL_HOOK(HookedQueryFullProcessImageNameA, gQueryFullProcessImageNameAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"QueryFullProcessImageNameA",
            (HANDLE processHandle, DWORD flagsValue, LPSTR imageNamePointer, PDWORD sizePointer), (processHandle, flagsValue, imageNamePointer, sizePointer),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); appendWideText(detailBuffer, L" image="); if (resultValue != FALSE) { appendAnsiText(detailBuffer, imageNamePointer, sizePointer != nullptr ? *sizePointer : static_cast<std::size_t>(-1)); } })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetProcessImageFileNameW, gGetProcessImageFileNameWOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Psapi", L"GetProcessImageFileNameW",
            (HANDLE processHandle, LPWSTR imageNamePointer, DWORD sizeValue), (processHandle, imageNamePointer, sizeValue),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, sizeValue); appendWideText(detailBuffer, L" image="); if (resultValue != 0) { appendWideText(detailBuffer, imageNamePointer, resultValue); } })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetProcessImageFileNameA, gGetProcessImageFileNameAOriginal, ks::winapi_monitor::EventCategory::kProcess, L"Psapi", L"GetProcessImageFileNameA",
            (HANDLE processHandle, LPSTR imageNamePointer, DWORD sizeValue), (processHandle, imageNamePointer, sizeValue),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" size="); appendUnsignedText(detailBuffer, sizeValue); appendWideText(detailBuffer, L" image="); if (resultValue != 0) { appendAnsiText(detailBuffer, imageNamePointer, resultValue); } })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetProcessId, gGetProcessIdOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"GetProcessId",
            (HANDLE processHandle), (processHandle),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" pid="); appendUnsignedText(detailBuffer, resultValue); })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetThreadId, gGetThreadIdOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"GetThreadId",
            (HANDLE threadHandle), (threadHandle),
            { appendWideText(detailBuffer, L"thread="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle)); appendWideText(detailBuffer, L" tid="); appendUnsignedText(detailBuffer, resultValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedIsWow64Process, gIsWow64ProcessOriginal, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"IsWow64Process",
            (HANDLE processHandle, PBOOL wow64ProcessPointer), (processHandle, wow64ProcessPointer),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" wow64="); appendUnsignedText(detailBuffer, wow64ProcessPointer != nullptr && *wow64ProcessPointer != FALSE ? 1ULL : 0ULL); })
        APIMON_SIMPLE_BOOL_HOOK(HookedIsWow64Process2, gIsWow64Process2Original, ks::winapi_monitor::EventCategory::kProcess, L"KernelBase", L"IsWow64Process2",
            (HANDLE processHandle, USHORT* processMachinePointer, USHORT* nativeMachinePointer), (processHandle, processMachinePointer, nativeMachinePointer),
            { appendWideText(detailBuffer, L"process="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); appendWideText(detailBuffer, L" procMachine="); appendHexText(detailBuffer, processMachinePointer != nullptr ? *processMachinePointer : 0); appendWideText(detailBuffer, L" nativeMachine="); appendHexText(detailBuffer, nativeMachinePointer != nullptr ? *nativeMachinePointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWow64DisableWow64FsRedirection, gWow64DisableWow64FsRedirectionOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"Wow64DisableWow64FsRedirection",
            (PVOID* oldValuePointer), (oldValuePointer),
            { appendWideText(detailBuffer, L"old="); appendHexText(detailBuffer, oldValuePointer != nullptr ? reinterpret_cast<std::uint64_t>(*oldValuePointer) : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWow64RevertWow64FsRedirection, gWow64RevertWow64FsRedirectionOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"Wow64RevertWow64FsRedirection",
            (PVOID oldValuePointer), (oldValuePointer),
            { appendWideText(detailBuffer, L"old="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(oldValuePointer)); })

        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetTempPathW, gGetTempPathWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetTempPathW",
            (DWORD bufferLength, LPWSTR bufferPointer), (bufferLength, bufferPointer),
            { appendWideText(detailBuffer, L"buffer="); appendUnsignedText(detailBuffer, bufferLength); appendWideText(detailBuffer, L" path="); if (resultValue != 0) { appendWideText(detailBuffer, bufferPointer, resultValue); } })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetTempPathA, gGetTempPathAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetTempPathA",
            (DWORD bufferLength, LPSTR bufferPointer), (bufferLength, bufferPointer),
            { appendWideText(detailBuffer, L"buffer="); appendUnsignedText(detailBuffer, bufferLength); appendWideText(detailBuffer, L" path="); if (resultValue != 0) { appendAnsiText(detailBuffer, bufferPointer, resultValue); } })
        APIMON_SIMPLE_UINT_NONZERO_HOOK(HookedGetTempFileNameW, gGetTempFileNameWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetTempFileNameW",
            (LPCWSTR pathNamePointer, LPCWSTR prefixStringPointer, UINT uniqueValue, LPWSTR tempFileNamePointer), (pathNamePointer, prefixStringPointer, uniqueValue, tempFileNamePointer),
            { appendWideText(detailBuffer, L"path="); appendWideText(detailBuffer, pathNamePointer); appendWideText(detailBuffer, L" prefix="); appendWideText(detailBuffer, prefixStringPointer); appendWideText(detailBuffer, L" unique="); appendUnsignedText(detailBuffer, uniqueValue); appendWideText(detailBuffer, L" file="); appendWideText(detailBuffer, tempFileNamePointer); })
        APIMON_SIMPLE_UINT_NONZERO_HOOK(HookedGetTempFileNameA, gGetTempFileNameAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetTempFileNameA",
            (LPCSTR pathNamePointer, LPCSTR prefixStringPointer, UINT uniqueValue, LPSTR tempFileNamePointer), (pathNamePointer, prefixStringPointer, uniqueValue, tempFileNamePointer),
            { appendWideText(detailBuffer, L"path="); appendAnsiText(detailBuffer, pathNamePointer); appendWideText(detailBuffer, L" prefix="); appendAnsiText(detailBuffer, prefixStringPointer); appendWideText(detailBuffer, L" unique="); appendUnsignedText(detailBuffer, uniqueValue); appendWideText(detailBuffer, L" file="); appendAnsiText(detailBuffer, tempFileNamePointer); })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetFullPathNameW, gGetFullPathNameWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetFullPathNameW",
            (LPCWSTR fileNamePointer, DWORD bufferLength, LPWSTR bufferPointer, LPWSTR* filePartPointer), (fileNamePointer, bufferLength, bufferPointer, filePartPointer),
            { appendWideText(detailBuffer, L"input="); appendWideText(detailBuffer, fileNamePointer); appendWideText(detailBuffer, L" buffer="); appendUnsignedText(detailBuffer, bufferLength); appendWideText(detailBuffer, L" full="); if (resultValue != 0 && resultValue < bufferLength) { appendWideText(detailBuffer, bufferPointer, resultValue); } })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetFullPathNameA, gGetFullPathNameAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetFullPathNameA",
            (LPCSTR fileNamePointer, DWORD bufferLength, LPSTR bufferPointer, LPSTR* filePartPointer), (fileNamePointer, bufferLength, bufferPointer, filePartPointer),
            { appendWideText(detailBuffer, L"input="); appendAnsiText(detailBuffer, fileNamePointer); appendWideText(detailBuffer, L" buffer="); appendUnsignedText(detailBuffer, bufferLength); appendWideText(detailBuffer, L" full="); if (resultValue != 0 && resultValue < bufferLength) { appendAnsiText(detailBuffer, bufferPointer, resultValue); } })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedSearchPathW, gSearchPathWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"SearchPathW",
            (LPCWSTR pathPointer, LPCWSTR fileNamePointer, LPCWSTR extensionPointer, DWORD bufferLength, LPWSTR bufferPointer, LPWSTR* filePartPointer),
            (pathPointer, fileNamePointer, extensionPointer, bufferLength, bufferPointer, filePartPointer),
            { appendWideText(detailBuffer, L"path="); appendWideText(detailBuffer, pathPointer); appendWideText(detailBuffer, L" file="); appendWideText(detailBuffer, fileNamePointer); appendWideText(detailBuffer, L" ext="); appendWideText(detailBuffer, extensionPointer); appendWideText(detailBuffer, L" result="); if (resultValue != 0 && resultValue < bufferLength) { appendWideText(detailBuffer, bufferPointer, resultValue); } })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedSearchPathA, gSearchPathAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"SearchPathA",
            (LPCSTR pathPointer, LPCSTR fileNamePointer, LPCSTR extensionPointer, DWORD bufferLength, LPSTR bufferPointer, LPSTR* filePartPointer),
            (pathPointer, fileNamePointer, extensionPointer, bufferLength, bufferPointer, filePartPointer),
            { appendWideText(detailBuffer, L"path="); appendAnsiText(detailBuffer, pathPointer); appendWideText(detailBuffer, L" file="); appendAnsiText(detailBuffer, fileNamePointer); appendWideText(detailBuffer, L" ext="); appendAnsiText(detailBuffer, extensionPointer); appendWideText(detailBuffer, L" result="); if (resultValue != 0 && resultValue < bufferLength) { appendAnsiText(detailBuffer, bufferPointer, resultValue); } })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetShortPathNameW, gGetShortPathNameWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetShortPathNameW",
            (LPCWSTR longPathPointer, LPWSTR shortPathPointer, DWORD bufferLength), (longPathPointer, shortPathPointer, bufferLength),
            { appendWideText(detailBuffer, L"input="); appendWideText(detailBuffer, longPathPointer); appendWideText(detailBuffer, L" output="); if (resultValue != 0 && resultValue < bufferLength) { appendWideText(detailBuffer, shortPathPointer, resultValue); } })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetShortPathNameA, gGetShortPathNameAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetShortPathNameA",
            (LPCSTR longPathPointer, LPSTR shortPathPointer, DWORD bufferLength), (longPathPointer, shortPathPointer, bufferLength),
            { appendWideText(detailBuffer, L"input="); appendAnsiText(detailBuffer, longPathPointer); appendWideText(detailBuffer, L" output="); if (resultValue != 0 && resultValue < bufferLength) { appendAnsiText(detailBuffer, shortPathPointer, resultValue); } })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetLongPathNameW, gGetLongPathNameWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetLongPathNameW",
            (LPCWSTR shortPathPointer, LPWSTR longPathPointer, DWORD bufferLength), (shortPathPointer, longPathPointer, bufferLength),
            { appendWideText(detailBuffer, L"input="); appendWideText(detailBuffer, shortPathPointer); appendWideText(detailBuffer, L" output="); if (resultValue != 0 && resultValue < bufferLength) { appendWideText(detailBuffer, longPathPointer, resultValue); } })
        APIMON_SIMPLE_DWORD_NONZERO_HOOK(HookedGetLongPathNameA, gGetLongPathNameAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"GetLongPathNameA",
            (LPCSTR shortPathPointer, LPSTR longPathPointer, DWORD bufferLength), (shortPathPointer, longPathPointer, bufferLength),
            { appendWideText(detailBuffer, L"input="); appendAnsiText(detailBuffer, shortPathPointer); appendWideText(detailBuffer, L" output="); if (resultValue != 0 && resultValue < bufferLength) { appendAnsiText(detailBuffer, longPathPointer, resultValue); } })
        APIMON_SIMPLE_BOOL_HOOK(HookedCreatePipe, gCreatePipeOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreatePipe",
            (PHANDLE readPipePointer, PHANDLE writePipePointer, LPSECURITY_ATTRIBUTES securityAttributesPointer, DWORD sizeValue), (readPipePointer, writePipePointer, securityAttributesPointer, sizeValue),
            { appendWideText(detailBuffer, L"size="); appendUnsignedText(detailBuffer, sizeValue); appendWideText(detailBuffer, L" read="); appendHexText(detailBuffer, readPipePointer != nullptr ? reinterpret_cast<std::uint64_t>(*readPipePointer) : 0); appendWideText(detailBuffer, L" write="); appendHexText(detailBuffer, writePipePointer != nullptr ? reinterpret_cast<std::uint64_t>(*writePipePointer) : 0); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateMailslotW, gCreateMailslotWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateMailslotW",
            (LPCWSTR namePointer, DWORD maxMessageSize, DWORD readTimeout, LPSECURITY_ATTRIBUTES securityAttributesPointer), (namePointer, maxMessageSize, readTimeout, securityAttributesPointer),
            { appendWideText(detailBuffer, L"name="); appendWideText(detailBuffer, namePointer); appendWideText(detailBuffer, L" maxMsg="); appendUnsignedText(detailBuffer, maxMessageSize); appendWideText(detailBuffer, L" timeout="); appendUnsignedText(detailBuffer, readTimeout); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HANDLE, HookedCreateMailslotA, gCreateMailslotAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateMailslotA",
            (LPCSTR namePointer, DWORD maxMessageSize, DWORD readTimeout, LPSECURITY_ATTRIBUTES securityAttributesPointer), (namePointer, maxMessageSize, readTimeout, securityAttributesPointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" maxMsg="); appendUnsignedText(detailBuffer, maxMessageSize); appendWideText(detailBuffer, L" timeout="); appendUnsignedText(detailBuffer, readTimeout); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCreateDirectoryExW, gCreateDirectoryExWOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateDirectoryExW",
            (LPCWSTR templateDirectoryPointer, LPCWSTR newDirectoryPointer, LPSECURITY_ATTRIBUTES securityAttributesPointer), (templateDirectoryPointer, newDirectoryPointer, securityAttributesPointer),
            { buildTwoPathDetailW(detailBuffer, templateDirectoryPointer, newDirectoryPointer, 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedCreateDirectoryExA, gCreateDirectoryExAOriginal, ks::winapi_monitor::EventCategory::kFile, L"KernelBase", L"CreateDirectoryExA",
            (LPCSTR templateDirectoryPointer, LPCSTR newDirectoryPointer, LPSECURITY_ATTRIBUTES securityAttributesPointer), (templateDirectoryPointer, newDirectoryPointer, securityAttributesPointer),
            { buildTwoPathDetailA(detailBuffer, templateDirectoryPointer, newDirectoryPointer, 0); })

        APIMON_SIMPLE_WSA_INT_HOOK(HookedWSAStartup, gWsaStartupOriginal, L"WSAStartup", resultValue == 0,
            (WORD versionRequested, LPWSADATA dataPointer), (versionRequested, dataPointer),
            { appendWideText(detailBuffer, L"version="); appendHexText(detailBuffer, versionRequested); appendWideText(detailBuffer, L" highVersion="); appendHexText(detailBuffer, dataPointer != nullptr ? dataPointer->wHighVersion : 0); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedWSACleanup, gWsaCleanupOriginal, L"WSACleanup", resultValue == 0,
            (), (),
            { detailBuffer[0] = L'\0'; })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedSelect, gSelectOriginal, L"select", resultValue != SOCKET_ERROR,
            (int nfdsValue, fd_set* readSetPointer, fd_set* writeSetPointer, fd_set* exceptSetPointer, const timeval* timeoutPointer),
            (nfdsValue, readSetPointer, writeSetPointer, exceptSetPointer, timeoutPointer),
            { appendWideText(detailBuffer, L"nfds="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(nfdsValue < 0 ? 0 : nfdsValue)); appendWideText(detailBuffer, L" ready="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(resultValue < 0 ? 0 : resultValue)); appendWideText(detailBuffer, L" timeout="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(timeoutPointer)); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedIoctlSocket, gIoctlSocketOriginal, L"ioctlsocket", resultValue == 0,
            (SOCKET socketValue, long commandValue, u_long* argumentPointer), (socketValue, commandValue, argumentPointer),
            { appendWideText(detailBuffer, L"socket="); appendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); appendWideText(detailBuffer, L" cmd="); appendHexText(detailBuffer, static_cast<std::uint64_t>(commandValue)); appendWideText(detailBuffer, L" arg="); appendHexText(detailBuffer, argumentPointer != nullptr ? *argumentPointer : 0); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedSetSockOpt, gSetSockOptOriginal, L"setsockopt", resultValue == 0,
            (SOCKET socketValue, int levelValue, int optionName, const char* optionValuePointer, int optionLength), (socketValue, levelValue, optionName, optionValuePointer, optionLength),
            { appendWideText(detailBuffer, L"socket="); appendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(levelValue < 0 ? 0 : levelValue)); appendWideText(detailBuffer, L" opt="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(optionName < 0 ? 0 : optionName)); appendWideText(detailBuffer, L" len="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(optionLength < 0 ? 0 : optionLength)); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedGetSockOpt, gGetSockOptOriginal, L"getsockopt", resultValue == 0,
            (SOCKET socketValue, int levelValue, int optionName, char* optionValuePointer, int* optionLengthPointer), (socketValue, levelValue, optionName, optionValuePointer, optionLengthPointer),
            { appendWideText(detailBuffer, L"socket="); appendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); appendWideText(detailBuffer, L" level="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(levelValue < 0 ? 0 : levelValue)); appendWideText(detailBuffer, L" opt="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(optionName < 0 ? 0 : optionName)); appendWideText(detailBuffer, L" len="); appendUnsignedText(detailBuffer, optionLengthPointer != nullptr ? static_cast<unsigned long long>(*optionLengthPointer < 0 ? 0 : *optionLengthPointer) : 0ULL); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedGetSockName, gGetSockNameOriginal, L"getsockname", resultValue == 0,
            (SOCKET socketValue, sockaddr* namePointer, int* nameLengthPointer), (socketValue, namePointer, nameLengthPointer),
            { appendWideText(detailBuffer, L"socket="); appendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); appendWideText(detailBuffer, L" addr="); appendSocketAddress(detailBuffer, namePointer, nameLengthPointer != nullptr ? *nameLengthPointer : 0); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedGetPeerName, gGetPeerNameOriginal, L"getpeername", resultValue == 0,
            (SOCKET socketValue, sockaddr* namePointer, int* nameLengthPointer), (socketValue, namePointer, nameLengthPointer),
            { appendWideText(detailBuffer, L"socket="); appendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); appendWideText(detailBuffer, L" addr="); appendSocketAddress(detailBuffer, namePointer, nameLengthPointer != nullptr ? *nameLengthPointer : 0); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedWSAEventSelect, gWsaEventSelectOriginal, L"WSAEventSelect", resultValue == 0,
            (SOCKET socketValue, WSAEVENT eventHandle, long networkEvents), (socketValue, eventHandle, networkEvents),
            { appendWideText(detailBuffer, L"socket="); appendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); appendWideText(detailBuffer, L" event="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventHandle)); appendWideText(detailBuffer, L" netEvents="); appendHexText(detailBuffer, static_cast<std::uint64_t>(networkEvents)); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedWSAAsyncSelect, gWsaAsyncSelectOriginal, L"WSAAsyncSelect", resultValue == 0,
            (SOCKET socketValue, HWND windowHandle, unsigned int messageValue, long networkEvents), (socketValue, windowHandle, messageValue, networkEvents),
            { appendWideText(detailBuffer, L"socket="); appendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); appendWideText(detailBuffer, L" hwnd="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(windowHandle)); appendWideText(detailBuffer, L" msg="); appendHexText(detailBuffer, messageValue); appendWideText(detailBuffer, L" netEvents="); appendHexText(detailBuffer, static_cast<std::uint64_t>(networkEvents)); })
        APIMON_SIMPLE_HANDLE_HOOK(HostEntPtr, HookedGetHostByName, gGetHostByNameOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Ws2_32", L"gethostbyname",
            (const char* namePointer), (namePointer),
            { appendWideText(detailBuffer, L"name="); appendAnsiText(detailBuffer, namePointer); appendWideText(detailBuffer, L" result="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_HANDLE_HOOK(HostEntPtr, HookedGetHostByAddr, gGetHostByAddrOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Ws2_32", L"gethostbyaddr",
            (const char* addressPointer, int lengthValue, int typeValue), (addressPointer, lengthValue, typeValue),
            { appendWideText(detailBuffer, L"len="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(lengthValue < 0 ? 0 : lengthValue)); appendWideText(detailBuffer, L" type="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue < 0 ? 0 : typeValue)); appendWideText(detailBuffer, L" result="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedGetNameInfoW, gGetNameInfoWOriginal, L"GetNameInfoW", resultValue == 0,
            (const sockaddr* sockaddrPointer, int sockaddrLength, PWCHAR hostPointer, DWORD hostLength, PWCHAR servicePointer, DWORD serviceLength, INT flagsValue),
            (sockaddrPointer, sockaddrLength, hostPointer, hostLength, servicePointer, serviceLength, flagsValue),
            { appendSocketAddress(detailBuffer, sockaddrPointer, sockaddrLength); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, static_cast<std::uint64_t>(flagsValue)); appendWideText(detailBuffer, L" host="); if (resultValue == 0) { appendWideText(detailBuffer, hostPointer); } })
        APIMON_SIMPLE_WSA_INT_HOOK(HookedGetNameInfoA, gGetNameInfoAOriginal, L"getnameinfo", resultValue == 0,
            (const sockaddr* sockaddrPointer, int sockaddrLength, PCHAR hostPointer, DWORD hostLength, PCHAR servicePointer, DWORD serviceLength, INT flagsValue),
            (sockaddrPointer, sockaddrLength, hostPointer, hostLength, servicePointer, serviceLength, flagsValue),
            { appendSocketAddress(detailBuffer, sockaddrPointer, sockaddrLength); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, static_cast<std::uint64_t>(flagsValue)); appendWideText(detailBuffer, L" host="); if (resultValue == 0) { appendAnsiText(detailBuffer, hostPointer); } })

        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpAddRequestHeaders, gWinHttpAddRequestHeadersOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpAddRequestHeaders",
            (HINTERNET requestHandle, LPCWSTR headersPointer, DWORD headersLength, DWORD modifiersValue), (requestHandle, headersPointer, headersLength, modifiersValue),
            { appendWideText(detailBuffer, L"request="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, headersLength); appendWideText(detailBuffer, L" modifiers="); appendHexText(detailBuffer, modifiersValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpSetCredentials, gWinHttpSetCredentialsOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpSetCredentials",
            (HINTERNET requestHandle, DWORD authTargets, DWORD authScheme, LPCWSTR userNamePointer, LPCWSTR passwordPointer, LPVOID authParamsPointer),
            (requestHandle, authTargets, authScheme, userNamePointer, passwordPointer, authParamsPointer),
            { appendWideText(detailBuffer, L"request="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); appendWideText(detailBuffer, L" targets="); appendHexText(detailBuffer, authTargets); appendWideText(detailBuffer, L" scheme="); appendHexText(detailBuffer, authScheme); appendWideText(detailBuffer, L" user="); appendWideText(detailBuffer, userNamePointer); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpCrackUrl, gWinHttpCrackUrlOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpCrackUrl",
            (LPCWSTR urlPointer, DWORD urlLength, DWORD flagsValue, LPURL_COMPONENTS componentsPointer), (urlPointer, urlLength, flagsValue, componentsPointer),
            { appendWideText(detailBuffer, L"url="); appendWideText(detailBuffer, urlPointer, urlLength != 0 ? urlLength : static_cast<std::size_t>(-1)); appendWideText(detailBuffer, L" flags="); appendHexText(detailBuffer, flagsValue); })
        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpCreateUrl, gWinHttpCreateUrlOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpCreateUrl",
            (LPURL_COMPONENTS componentsPointer, DWORD flagsValue, LPWSTR urlPointer, LPDWORD urlLengthPointer), (componentsPointer, flagsValue, urlPointer, urlLengthPointer),
            { appendWideText(detailBuffer, L"flags="); appendHexText(detailBuffer, flagsValue); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, urlLengthPointer != nullptr ? *urlLengthPointer : 0); appendWideText(detailBuffer, L" url="); if (resultValue != FALSE) { appendWideText(detailBuffer, urlPointer); } })
        APIMON_SIMPLE_BOOL_HOOK(HookedWinHttpSetTimeouts, gWinHttpSetTimeoutsOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Winhttp", L"WinHttpSetTimeouts",
            (HINTERNET internetHandle, int resolveTimeout, int connectTimeout, int sendTimeout, int receiveTimeout),
            (internetHandle, resolveTimeout, connectTimeout, sendTimeout, receiveTimeout),
            { appendWideText(detailBuffer, L"handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); appendWideText(detailBuffer, L" resolve="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(resolveTimeout < 0 ? 0 : resolveTimeout)); appendWideText(detailBuffer, L" connect="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(connectTimeout < 0 ? 0 : connectTimeout)); appendWideText(detailBuffer, L" send="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(sendTimeout < 0 ? 0 : sendTimeout)); appendWideText(detailBuffer, L" recv="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(receiveTimeout < 0 ? 0 : receiveTimeout)); })
        APIMON_SIMPLE_BOOL_HOOK(HookedHttpQueryInfoW, gHttpQueryInfoWOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"HttpQueryInfoW",
            (HINTERNET requestHandle, DWORD infoLevel, LPVOID bufferPointer, LPDWORD bufferLengthPointer, LPDWORD indexPointer), (requestHandle, infoLevel, bufferPointer, bufferLengthPointer, indexPointer),
            { appendWideText(detailBuffer, L"request="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); appendWideText(detailBuffer, L" level="); appendHexText(detailBuffer, infoLevel); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, bufferLengthPointer != nullptr ? *bufferLengthPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedHttpQueryInfoA, gHttpQueryInfoAOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"HttpQueryInfoA",
            (HINTERNET requestHandle, DWORD infoLevel, LPVOID bufferPointer, LPDWORD bufferLengthPointer, LPDWORD indexPointer), (requestHandle, infoLevel, bufferPointer, bufferLengthPointer, indexPointer),
            { appendWideText(detailBuffer, L"request="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); appendWideText(detailBuffer, L" level="); appendHexText(detailBuffer, infoLevel); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, bufferLengthPointer != nullptr ? *bufferLengthPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedInternetQueryOptionW, gInternetQueryOptionWOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetQueryOptionW",
            (HINTERNET internetHandle, DWORD optionValue, LPVOID bufferPointer, LPDWORD bufferLengthPointer), (internetHandle, optionValue, bufferPointer, bufferLengthPointer),
            { appendWideText(detailBuffer, L"handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); appendWideText(detailBuffer, L" option="); appendHexText(detailBuffer, optionValue); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, bufferLengthPointer != nullptr ? *bufferLengthPointer : 0); })
        APIMON_SIMPLE_BOOL_HOOK(HookedInternetQueryOptionA, gInternetQueryOptionAOriginal, ks::winapi_monitor::EventCategory::kNetwork, L"Wininet", L"InternetQueryOptionA",
            (HINTERNET internetHandle, DWORD optionValue, LPVOID bufferPointer, LPDWORD bufferLengthPointer), (internetHandle, optionValue, bufferPointer, bufferLengthPointer),
            { appendWideText(detailBuffer, L"handle="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); appendWideText(detailBuffer, L" option="); appendHexText(detailBuffer, optionValue); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, bufferLengthPointer != nullptr ? *bufferLengthPointer : 0); })

        // HookedSixthBatchNativeObjectSync:
        // - Input: ntdll object directory, symbolic link, and semaphore native object parameters;
        // - Processing: Complete the Object Manager layer access and named object resolution behavior underlying Win32 synchronization and path enumeration.
        // - Returns: Preserves the original NTSTATUS of each API and writes the object name, access mask, count, and output handle to the event details.
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtOpenDirectoryObject, gNtOpenDirectoryObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtOpenDirectoryObject",
            (PHANDLE directoryHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer),
            (directoryHandlePointer, desiredAccess, objectAttributesPointer),
            { appendWideText(detailBuffer, L"object="); appendObjectNameText(detailBuffer, objectAttributesPointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, directoryHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*directoryHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtQueryDirectoryObject, gNtQueryDirectoryObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtQueryDirectoryObject",
            (HANDLE directoryHandle, PVOID bufferPointer, ULONG lengthValue, BOOLEAN returnSingleEntry, BOOLEAN restartScan, PULONG contextPointer, PULONG returnLengthPointer),
            (directoryHandle, bufferPointer, lengthValue, returnSingleEntry, restartScan, contextPointer, returnLengthPointer),
            { appendWideText(detailBuffer, L"directory="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(directoryHandle)); appendWideText(detailBuffer, L" length="); appendUnsignedText(detailBuffer, lengthValue); appendWideText(detailBuffer, L" single="); appendUnsignedText(detailBuffer, returnSingleEntry != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" restart="); appendUnsignedText(detailBuffer, restartScan != FALSE ? 1ULL : 0ULL); appendWideText(detailBuffer, L" context="); appendUnsignedText(detailBuffer, contextPointer != nullptr ? *contextPointer : 0); appendWideText(detailBuffer, L" returned="); appendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtCreateSymbolicLinkObject, gNtCreateSymbolicLinkObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtCreateSymbolicLinkObject",
            (PHANDLE linkHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, PUNICODE_STRING targetNamePointer),
            (linkHandlePointer, desiredAccess, objectAttributesPointer, targetNamePointer),
            { appendWideText(detailBuffer, L"object="); appendObjectNameText(detailBuffer, objectAttributesPointer); appendWideText(detailBuffer, L" target="); appendUnicodeStringText(detailBuffer, targetNamePointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, linkHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*linkHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtOpenSymbolicLinkObject, gNtOpenSymbolicLinkObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtOpenSymbolicLinkObject",
            (PHANDLE linkHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer),
            (linkHandlePointer, desiredAccess, objectAttributesPointer),
            { appendWideText(detailBuffer, L"object="); appendObjectNameText(detailBuffer, objectAttributesPointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, linkHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*linkHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtQuerySymbolicLinkObject, gNtQuerySymbolicLinkObjectOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtQuerySymbolicLinkObject",
            (HANDLE linkHandle, PUNICODE_STRING targetNamePointer, PULONG returnLengthPointer),
            (linkHandle, targetNamePointer, returnLengthPointer),
            { appendWideText(detailBuffer, L"link="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(linkHandle)); appendWideText(detailBuffer, L" target="); appendUnicodeStringText(detailBuffer, targetNamePointer); appendWideText(detailBuffer, L" returned="); appendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtCreateSemaphore, gNtCreateSemaphoreOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtCreateSemaphore",
            (PHANDLE semaphoreHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, LONG initialCount, LONG maximumCount),
            (semaphoreHandlePointer, desiredAccess, objectAttributesPointer, initialCount, maximumCount),
            { appendWideText(detailBuffer, L"object="); appendObjectNameText(detailBuffer, objectAttributesPointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" initial="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(initialCount < 0 ? 0 : initialCount)); appendWideText(detailBuffer, L" max="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(maximumCount < 0 ? 0 : maximumCount)); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, semaphoreHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*semaphoreHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtOpenSemaphore, gNtOpenSemaphoreOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtOpenSemaphore",
            (PHANDLE semaphoreHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer),
            (semaphoreHandlePointer, desiredAccess, objectAttributesPointer),
            { appendWideText(detailBuffer, L"object="); appendObjectNameText(detailBuffer, objectAttributesPointer); appendWideText(detailBuffer, L" access="); appendHexText(detailBuffer, desiredAccess); appendWideText(detailBuffer, L" handle="); appendHexText(detailBuffer, semaphoreHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*semaphoreHandlePointer) : 0); })
        APIMON_SIMPLE_NTSTATUS_HOOK(HookedNtReleaseSemaphore, gNtReleaseSemaphoreOriginal, ks::winapi_monitor::EventCategory::kProcess, L"ntdll", L"NtReleaseSemaphore",
            (HANDLE semaphoreHandle, LONG releaseCount, PLONG previousCountPointer),
            (semaphoreHandle, releaseCount, previousCountPointer),
            { appendWideText(detailBuffer, L"semaphore="); appendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(semaphoreHandle)); appendWideText(detailBuffer, L" release="); appendUnsignedText(detailBuffer, static_cast<unsigned long long>(releaseCount < 0 ? 0 : releaseCount)); appendWideText(detailBuffer, L" previous="); appendUnsignedText(detailBuffer, previousCountPointer != nullptr ? static_cast<unsigned long long>(*previousCountPointer < 0 ? 0 : *previousCountPointer) : 0ULL); })

        // HookBinding g_bindings：
        // - Input: module/exports name/category from static whitelist and Hooked wrapper metadata;
        // - Handling: installConfiguredHooks iterates this table to install inline hooks; after LoadLibrary/LdrLoadDll, it retries for delayed modules.
        // - Return: The table itself has no return value; it is the authoritative source for all supported API coverage.
        HookBinding gBindings[] = {
            { L"KernelBase.dll", "CreateFileA", ks::winapi_monitor::EventCategory::kFile, &gCreateFileAHook, reinterpret_cast<void*>(&hookedCreateFileA), reinterpret_cast<void**>(&gCreateFileAOriginal) },
            { L"KernelBase.dll", "CreateFileW", ks::winapi_monitor::EventCategory::kFile, &gCreateFileWHook, reinterpret_cast<void*>(&hookedCreateFileW), reinterpret_cast<void**>(&gCreateFileWOriginal) },
            { L"KernelBase.dll", "CreateFile2", ks::winapi_monitor::EventCategory::kFile, &gCreateFile2Hook, reinterpret_cast<void*>(&hookedCreateFile2), reinterpret_cast<void**>(&gCreateFile2Original) },
            { L"KernelBase.dll", "ReadFile", ks::winapi_monitor::EventCategory::kFile, &gReadFileHook, reinterpret_cast<void*>(&hookedReadFile), reinterpret_cast<void**>(&gReadFileOriginal) },
            { L"KernelBase.dll", "WriteFile", ks::winapi_monitor::EventCategory::kFile, &gWriteFileHook, reinterpret_cast<void*>(&hookedWriteFile), reinterpret_cast<void**>(&gWriteFileOriginal) },
            { L"KernelBase.dll", "DeviceIoControl", ks::winapi_monitor::EventCategory::kFile, &gDeviceIoControlHook, reinterpret_cast<void*>(&hookedDeviceIoControl), reinterpret_cast<void**>(&gDeviceIoControlOriginal) },
            { L"KernelBase.dll", "DeleteFileW", ks::winapi_monitor::EventCategory::kFile, &gDeleteFileWHook, reinterpret_cast<void*>(&HookedDeleteFileW), reinterpret_cast<void**>(&gDeleteFileWOriginal) },
            { L"KernelBase.dll", "DeleteFileA", ks::winapi_monitor::EventCategory::kFile, &gDeleteFileAHook, reinterpret_cast<void*>(&HookedDeleteFileA), reinterpret_cast<void**>(&gDeleteFileAOriginal) },
            { L"KernelBase.dll", "MoveFileExW", ks::winapi_monitor::EventCategory::kFile, &gMoveFileExWHook, reinterpret_cast<void*>(&hookedMoveFileExW), reinterpret_cast<void**>(&gMoveFileExWOriginal) },
            { L"KernelBase.dll", "MoveFileExA", ks::winapi_monitor::EventCategory::kFile, &gMoveFileExAHook, reinterpret_cast<void*>(&hookedMoveFileExA), reinterpret_cast<void**>(&gMoveFileExAOriginal) },
            { L"KernelBase.dll", "CopyFileW", ks::winapi_monitor::EventCategory::kFile, &gCopyFileWHook, reinterpret_cast<void*>(&hookedCopyFileW), reinterpret_cast<void**>(&gCopyFileWOriginal) },
            { L"KernelBase.dll", "CopyFileA", ks::winapi_monitor::EventCategory::kFile, &gCopyFileAHook, reinterpret_cast<void*>(&hookedCopyFileA), reinterpret_cast<void**>(&gCopyFileAOriginal) },
            { L"KernelBase.dll", "CopyFileExW", ks::winapi_monitor::EventCategory::kFile, &gCopyFileExWHook, reinterpret_cast<void*>(&hookedCopyFileExW), reinterpret_cast<void**>(&gCopyFileExWOriginal) },
            { L"KernelBase.dll", "CopyFileExA", ks::winapi_monitor::EventCategory::kFile, &gCopyFileExAHook, reinterpret_cast<void*>(&hookedCopyFileExA), reinterpret_cast<void**>(&gCopyFileExAOriginal) },
            { L"KernelBase.dll", "GetFileAttributesW", ks::winapi_monitor::EventCategory::kFile, &gGetFileAttributesWHook, reinterpret_cast<void*>(&hookedGetFileAttributesW), reinterpret_cast<void**>(&gGetFileAttributesWOriginal) },
            { L"KernelBase.dll", "GetFileAttributesA", ks::winapi_monitor::EventCategory::kFile, &gGetFileAttributesAHook, reinterpret_cast<void*>(&hookedGetFileAttributesA), reinterpret_cast<void**>(&gGetFileAttributesAOriginal) },
            { L"KernelBase.dll", "GetFileAttributesExW", ks::winapi_monitor::EventCategory::kFile, &gGetFileAttributesExWHook, reinterpret_cast<void*>(&hookedGetFileAttributesExW), reinterpret_cast<void**>(&gGetFileAttributesExWOriginal) },
            { L"KernelBase.dll", "GetFileAttributesExA", ks::winapi_monitor::EventCategory::kFile, &gGetFileAttributesExAHook, reinterpret_cast<void*>(&hookedGetFileAttributesExA), reinterpret_cast<void**>(&gGetFileAttributesExAOriginal) },
            { L"KernelBase.dll", "SetFileAttributesW", ks::winapi_monitor::EventCategory::kFile, &gSetFileAttributesWHook, reinterpret_cast<void*>(&hookedSetFileAttributesW), reinterpret_cast<void**>(&gSetFileAttributesWOriginal) },
            { L"KernelBase.dll", "SetFileAttributesA", ks::winapi_monitor::EventCategory::kFile, &gSetFileAttributesAHook, reinterpret_cast<void*>(&hookedSetFileAttributesA), reinterpret_cast<void**>(&gSetFileAttributesAOriginal) },
            { L"KernelBase.dll", "FindFirstFileExW", ks::winapi_monitor::EventCategory::kFile, &gFindFirstFileExWHook, reinterpret_cast<void*>(&hookedFindFirstFileExW), reinterpret_cast<void**>(&gFindFirstFileExWOriginal) },
            { L"KernelBase.dll", "FindFirstFileExA", ks::winapi_monitor::EventCategory::kFile, &gFindFirstFileExAHook, reinterpret_cast<void*>(&hookedFindFirstFileExA), reinterpret_cast<void**>(&gFindFirstFileExAOriginal) },
            { L"KernelBase.dll", "CreateDirectoryW", ks::winapi_monitor::EventCategory::kFile, &gCreateDirectoryWHook, reinterpret_cast<void*>(&hookedCreateDirectoryW), reinterpret_cast<void**>(&gCreateDirectoryWOriginal) },
            { L"KernelBase.dll", "CreateDirectoryA", ks::winapi_monitor::EventCategory::kFile, &gCreateDirectoryAHook, reinterpret_cast<void*>(&hookedCreateDirectoryA), reinterpret_cast<void**>(&gCreateDirectoryAOriginal) },
            { L"KernelBase.dll", "RemoveDirectoryW", ks::winapi_monitor::EventCategory::kFile, &gRemoveDirectoryWHook, reinterpret_cast<void*>(&HookedRemoveDirectoryW), reinterpret_cast<void**>(&gRemoveDirectoryWOriginal) },
            { L"KernelBase.dll", "RemoveDirectoryA", ks::winapi_monitor::EventCategory::kFile, &gRemoveDirectoryAHook, reinterpret_cast<void*>(&HookedRemoveDirectoryA), reinterpret_cast<void**>(&gRemoveDirectoryAOriginal) },
            { L"KernelBase.dll", "SetFileInformationByHandle", ks::winapi_monitor::EventCategory::kFile, &gSetFileInformationByHandleHook, reinterpret_cast<void*>(&hookedSetFileInformationByHandle), reinterpret_cast<void**>(&gSetFileInformationByHandleOriginal) },
            { L"KernelBase.dll", "CreateFileMappingW", ks::winapi_monitor::EventCategory::kFile, &gCreateFileMappingWHook, reinterpret_cast<void*>(&HookedCreateFileMappingW), reinterpret_cast<void**>(&gCreateFileMappingWOriginal) },
            { L"KernelBase.dll", "CreateFileMappingA", ks::winapi_monitor::EventCategory::kFile, &gCreateFileMappingAHook, reinterpret_cast<void*>(&HookedCreateFileMappingA), reinterpret_cast<void**>(&gCreateFileMappingAOriginal) },
            { L"KernelBase.dll", "OpenFileMappingW", ks::winapi_monitor::EventCategory::kFile, &gOpenFileMappingWHook, reinterpret_cast<void*>(&HookedOpenFileMappingW), reinterpret_cast<void**>(&gOpenFileMappingWOriginal) },
            { L"KernelBase.dll", "OpenFileMappingA", ks::winapi_monitor::EventCategory::kFile, &gOpenFileMappingAHook, reinterpret_cast<void*>(&HookedOpenFileMappingA), reinterpret_cast<void**>(&gOpenFileMappingAOriginal) },
            { L"KernelBase.dll", "FlushViewOfFile", ks::winapi_monitor::EventCategory::kFile, &gFlushViewOfFileHook, reinterpret_cast<void*>(&HookedFlushViewOfFile), reinterpret_cast<void**>(&gFlushViewOfFileOriginal) },
            { L"KernelBase.dll", "CreateHardLinkW", ks::winapi_monitor::EventCategory::kFile, &gCreateHardLinkWHook, reinterpret_cast<void*>(&HookedCreateHardLinkW), reinterpret_cast<void**>(&gCreateHardLinkWOriginal) },
            { L"KernelBase.dll", "CreateHardLinkA", ks::winapi_monitor::EventCategory::kFile, &gCreateHardLinkAHook, reinterpret_cast<void*>(&HookedCreateHardLinkA), reinterpret_cast<void**>(&gCreateHardLinkAOriginal) },
            { L"KernelBase.dll", "ReplaceFileW", ks::winapi_monitor::EventCategory::kFile, &gReplaceFileWHook, reinterpret_cast<void*>(&HookedReplaceFileW), reinterpret_cast<void**>(&gReplaceFileWOriginal) },
            { L"KernelBase.dll", "ReplaceFileA", ks::winapi_monitor::EventCategory::kFile, &gReplaceFileAHook, reinterpret_cast<void*>(&HookedReplaceFileA), reinterpret_cast<void**>(&gReplaceFileAOriginal) },
            { L"KernelBase.dll", "SetEndOfFile", ks::winapi_monitor::EventCategory::kFile, &gSetEndOfFileHook, reinterpret_cast<void*>(&HookedSetEndOfFile), reinterpret_cast<void**>(&gSetEndOfFileOriginal) },
            { L"KernelBase.dll", "LockFileEx", ks::winapi_monitor::EventCategory::kFile, &gLockFileExHook, reinterpret_cast<void*>(&HookedLockFileEx), reinterpret_cast<void**>(&gLockFileExOriginal) },
            { L"KernelBase.dll", "UnlockFileEx", ks::winapi_monitor::EventCategory::kFile, &gUnlockFileExHook, reinterpret_cast<void*>(&HookedUnlockFileEx), reinterpret_cast<void**>(&gUnlockFileExOriginal) },
            { L"KernelBase.dll", "CreateSymbolicLinkW", ks::winapi_monitor::EventCategory::kFile, &gCreateSymbolicLinkWHook, reinterpret_cast<void*>(&hookedCreateSymbolicLinkW), reinterpret_cast<void**>(&gCreateSymbolicLinkWOriginal) },
            { L"KernelBase.dll", "CreateSymbolicLinkA", ks::winapi_monitor::EventCategory::kFile, &gCreateSymbolicLinkAHook, reinterpret_cast<void*>(&hookedCreateSymbolicLinkA), reinterpret_cast<void**>(&gCreateSymbolicLinkAOriginal) },
            { L"KernelBase.dll", "GetFinalPathNameByHandleW", ks::winapi_monitor::EventCategory::kFile, &gGetFinalPathNameByHandleWHook, reinterpret_cast<void*>(&hookedGetFinalPathNameByHandleW), reinterpret_cast<void**>(&gGetFinalPathNameByHandleWOriginal) },
            { L"KernelBase.dll", "GetFinalPathNameByHandleA", ks::winapi_monitor::EventCategory::kFile, &gGetFinalPathNameByHandleAHook, reinterpret_cast<void*>(&hookedGetFinalPathNameByHandleA), reinterpret_cast<void**>(&gGetFinalPathNameByHandleAOriginal) },
            { L"KernelBase.dll", "GetFileSizeEx", ks::winapi_monitor::EventCategory::kFile, &gGetFileSizeExHook, reinterpret_cast<void*>(&HookedGetFileSizeEx), reinterpret_cast<void**>(&gGetFileSizeExOriginal) },
            { L"KernelBase.dll", "SetFilePointerEx", ks::winapi_monitor::EventCategory::kFile, &gSetFilePointerExHook, reinterpret_cast<void*>(&HookedSetFilePointerEx), reinterpret_cast<void**>(&gSetFilePointerExOriginal) },
            { L"KernelBase.dll", "CreateNamedPipeW", ks::winapi_monitor::EventCategory::kFile, &gCreateNamedPipeWHook, reinterpret_cast<void*>(&HookedCreateNamedPipeW), reinterpret_cast<void**>(&gCreateNamedPipeWOriginal) },
            { L"KernelBase.dll", "CreateNamedPipeA", ks::winapi_monitor::EventCategory::kFile, &gCreateNamedPipeAHook, reinterpret_cast<void*>(&HookedCreateNamedPipeA), reinterpret_cast<void**>(&gCreateNamedPipeAOriginal) },
            { L"KernelBase.dll", "ConnectNamedPipe", ks::winapi_monitor::EventCategory::kFile, &gConnectNamedPipeHook, reinterpret_cast<void*>(&HookedConnectNamedPipe), reinterpret_cast<void**>(&gConnectNamedPipeOriginal) },
            { L"KernelBase.dll", "DisconnectNamedPipe", ks::winapi_monitor::EventCategory::kFile, &gDisconnectNamedPipeHook, reinterpret_cast<void*>(&HookedDisconnectNamedPipe), reinterpret_cast<void**>(&gDisconnectNamedPipeOriginal) },
            { L"KernelBase.dll", "WaitNamedPipeW", ks::winapi_monitor::EventCategory::kFile, &gWaitNamedPipeWHook, reinterpret_cast<void*>(&HookedWaitNamedPipeW), reinterpret_cast<void**>(&gWaitNamedPipeWOriginal) },
            { L"KernelBase.dll", "WaitNamedPipeA", ks::winapi_monitor::EventCategory::kFile, &gWaitNamedPipeAHook, reinterpret_cast<void*>(&HookedWaitNamedPipeA), reinterpret_cast<void**>(&gWaitNamedPipeAOriginal) },
            { L"KernelBase.dll", "TransactNamedPipe", ks::winapi_monitor::EventCategory::kFile, &gTransactNamedPipeHook, reinterpret_cast<void*>(&HookedTransactNamedPipe), reinterpret_cast<void**>(&gTransactNamedPipeOriginal) },
            { L"KernelBase.dll", "CreateProcessA", ks::winapi_monitor::EventCategory::kProcess, &gCreateProcessAHook, reinterpret_cast<void*>(&hookedCreateProcessA), reinterpret_cast<void**>(&gCreateProcessAOriginal) },
            { L"KernelBase.dll", "CreateProcessW", ks::winapi_monitor::EventCategory::kProcess, &gCreateProcessWHook, reinterpret_cast<void*>(&hookedCreateProcessW), reinterpret_cast<void**>(&gCreateProcessWOriginal) },
            { L"KernelBase.dll", "OpenProcess", ks::winapi_monitor::EventCategory::kProcess, &gOpenProcessHook, reinterpret_cast<void*>(&hookedOpenProcess), reinterpret_cast<void**>(&gOpenProcessOriginal) },
            { L"KernelBase.dll", "OpenThread", ks::winapi_monitor::EventCategory::kProcess, &gOpenThreadHook, reinterpret_cast<void*>(&hookedOpenThread), reinterpret_cast<void**>(&gOpenThreadOriginal) },
            { L"KernelBase.dll", "TerminateProcess", ks::winapi_monitor::EventCategory::kProcess, &gTerminateProcessHook, reinterpret_cast<void*>(&hookedTerminateProcess), reinterpret_cast<void**>(&gTerminateProcessOriginal) },
            { L"KernelBase.dll", "CreateThread", ks::winapi_monitor::EventCategory::kProcess, &gCreateThreadHook, reinterpret_cast<void*>(&hookedCreateThread), reinterpret_cast<void**>(&gCreateThreadOriginal) },
            { L"KernelBase.dll", "CreateRemoteThread", ks::winapi_monitor::EventCategory::kProcess, &gCreateRemoteThreadHook, reinterpret_cast<void*>(&hookedCreateRemoteThread), reinterpret_cast<void**>(&gCreateRemoteThreadOriginal) },
            { L"KernelBase.dll", "CreateRemoteThreadEx", ks::winapi_monitor::EventCategory::kProcess, &gCreateRemoteThreadExHook, reinterpret_cast<void*>(&HookedCreateRemoteThreadEx), reinterpret_cast<void**>(&gCreateRemoteThreadExOriginal) },
            { L"KernelBase.dll", "VirtualAllocEx", ks::winapi_monitor::EventCategory::kProcess, &gVirtualAllocExHook, reinterpret_cast<void*>(&hookedVirtualAllocEx), reinterpret_cast<void**>(&gVirtualAllocExOriginal) },
            { L"KernelBase.dll", "VirtualFreeEx", ks::winapi_monitor::EventCategory::kProcess, &gVirtualFreeExHook, reinterpret_cast<void*>(&hookedVirtualFreeEx), reinterpret_cast<void**>(&gVirtualFreeExOriginal) },
            { L"KernelBase.dll", "VirtualProtectEx", ks::winapi_monitor::EventCategory::kProcess, &gVirtualProtectExHook, reinterpret_cast<void*>(&hookedVirtualProtectEx), reinterpret_cast<void**>(&gVirtualProtectExOriginal) },
            { L"KernelBase.dll", "VirtualAlloc", ks::winapi_monitor::EventCategory::kProcess, &gVirtualAllocHook, reinterpret_cast<void*>(&HookedVirtualAlloc), reinterpret_cast<void**>(&gVirtualAllocOriginal) },
            { L"KernelBase.dll", "VirtualFree", ks::winapi_monitor::EventCategory::kProcess, &gVirtualFreeHook, reinterpret_cast<void*>(&HookedVirtualFree), reinterpret_cast<void**>(&gVirtualFreeOriginal) },
            { L"KernelBase.dll", "VirtualProtect", ks::winapi_monitor::EventCategory::kProcess, &gVirtualProtectHook, reinterpret_cast<void*>(&HookedVirtualProtect), reinterpret_cast<void**>(&gVirtualProtectOriginal) },
            { L"KernelBase.dll", "WriteProcessMemory", ks::winapi_monitor::EventCategory::kProcess, &gWriteProcessMemoryHook, reinterpret_cast<void*>(&hookedWriteProcessMemory), reinterpret_cast<void**>(&gWriteProcessMemoryOriginal) },
            { L"KernelBase.dll", "ReadProcessMemory", ks::winapi_monitor::EventCategory::kProcess, &gReadProcessMemoryHook, reinterpret_cast<void*>(&hookedReadProcessMemory), reinterpret_cast<void**>(&gReadProcessMemoryOriginal) },
            { L"KernelBase.dll", "SuspendThread", ks::winapi_monitor::EventCategory::kProcess, &gSuspendThreadHook, reinterpret_cast<void*>(&hookedSuspendThread), reinterpret_cast<void**>(&gSuspendThreadOriginal) },
            { L"KernelBase.dll", "ResumeThread", ks::winapi_monitor::EventCategory::kProcess, &gResumeThreadHook, reinterpret_cast<void*>(&hookedResumeThread), reinterpret_cast<void**>(&gResumeThreadOriginal) },
            { L"KernelBase.dll", "QueueUserAPC", ks::winapi_monitor::EventCategory::kProcess, &gQueueUserApcHook, reinterpret_cast<void*>(&hookedQueueUserApc), reinterpret_cast<void**>(&gQueueUserApcOriginal) },
            { L"KernelBase.dll", "GetThreadContext", ks::winapi_monitor::EventCategory::kProcess, &gGetThreadContextHook, reinterpret_cast<void*>(&hookedGetThreadContext), reinterpret_cast<void**>(&gGetThreadContextOriginal) },
            { L"KernelBase.dll", "SetThreadContext", ks::winapi_monitor::EventCategory::kProcess, &gSetThreadContextHook, reinterpret_cast<void*>(&hookedSetThreadContext), reinterpret_cast<void**>(&gSetThreadContextOriginal) },
            { L"KernelBase.dll", "CloseHandle", ks::winapi_monitor::EventCategory::kProcess, &gCloseHandleHook, reinterpret_cast<void*>(&HookedCloseHandle), reinterpret_cast<void**>(&gCloseHandleOriginal) },
            { L"KernelBase.dll", "DuplicateHandle", ks::winapi_monitor::EventCategory::kProcess, &gDuplicateHandleHook, reinterpret_cast<void*>(&HookedDuplicateHandle), reinterpret_cast<void**>(&gDuplicateHandleOriginal) },
            { L"KernelBase.dll", "MapViewOfFile", ks::winapi_monitor::EventCategory::kProcess, &gMapViewOfFileHook, reinterpret_cast<void*>(&HookedMapViewOfFile), reinterpret_cast<void**>(&gMapViewOfFileOriginal) },
            { L"KernelBase.dll", "MapViewOfFileEx", ks::winapi_monitor::EventCategory::kProcess, &gMapViewOfFileExHook, reinterpret_cast<void*>(&HookedMapViewOfFileEx), reinterpret_cast<void**>(&gMapViewOfFileExOriginal) },
            { L"KernelBase.dll", "UnmapViewOfFile", ks::winapi_monitor::EventCategory::kProcess, &gUnmapViewOfFileHook, reinterpret_cast<void*>(&HookedUnmapViewOfFile), reinterpret_cast<void**>(&gUnmapViewOfFileOriginal) },
            { L"KernelBase.dll", "CreateMutexW", ks::winapi_monitor::EventCategory::kProcess, &gCreateMutexWHook, reinterpret_cast<void*>(&HookedCreateMutexW), reinterpret_cast<void**>(&gCreateMutexWOriginal) },
            { L"KernelBase.dll", "CreateMutexA", ks::winapi_monitor::EventCategory::kProcess, &gCreateMutexAHook, reinterpret_cast<void*>(&HookedCreateMutexA), reinterpret_cast<void**>(&gCreateMutexAOriginal) },
            { L"KernelBase.dll", "OpenMutexW", ks::winapi_monitor::EventCategory::kProcess, &gOpenMutexWHook, reinterpret_cast<void*>(&HookedOpenMutexW), reinterpret_cast<void**>(&gOpenMutexWOriginal) },
            { L"KernelBase.dll", "OpenMutexA", ks::winapi_monitor::EventCategory::kProcess, &gOpenMutexAHook, reinterpret_cast<void*>(&HookedOpenMutexA), reinterpret_cast<void**>(&gOpenMutexAOriginal) },
            { L"KernelBase.dll", "CreateEventW", ks::winapi_monitor::EventCategory::kProcess, &gCreateEventWHook, reinterpret_cast<void*>(&HookedCreateEventW), reinterpret_cast<void**>(&gCreateEventWOriginal) },
            { L"KernelBase.dll", "CreateEventA", ks::winapi_monitor::EventCategory::kProcess, &gCreateEventAHook, reinterpret_cast<void*>(&HookedCreateEventA), reinterpret_cast<void**>(&gCreateEventAOriginal) },
            { L"KernelBase.dll", "OpenEventW", ks::winapi_monitor::EventCategory::kProcess, &gOpenEventWHook, reinterpret_cast<void*>(&HookedOpenEventW), reinterpret_cast<void**>(&gOpenEventWOriginal) },
            { L"KernelBase.dll", "OpenEventA", ks::winapi_monitor::EventCategory::kProcess, &gOpenEventAHook, reinterpret_cast<void*>(&HookedOpenEventA), reinterpret_cast<void**>(&gOpenEventAOriginal) },
            { L"KernelBase.dll", "CreateSemaphoreW", ks::winapi_monitor::EventCategory::kProcess, &gCreateSemaphoreWHook, reinterpret_cast<void*>(&HookedCreateSemaphoreW), reinterpret_cast<void**>(&gCreateSemaphoreWOriginal) },
            { L"KernelBase.dll", "CreateSemaphoreA", ks::winapi_monitor::EventCategory::kProcess, &gCreateSemaphoreAHook, reinterpret_cast<void*>(&HookedCreateSemaphoreA), reinterpret_cast<void**>(&gCreateSemaphoreAOriginal) },
            { L"KernelBase.dll", "OpenSemaphoreW", ks::winapi_monitor::EventCategory::kProcess, &gOpenSemaphoreWHook, reinterpret_cast<void*>(&HookedOpenSemaphoreW), reinterpret_cast<void**>(&gOpenSemaphoreWOriginal) },
            { L"KernelBase.dll", "OpenSemaphoreA", ks::winapi_monitor::EventCategory::kProcess, &gOpenSemaphoreAHook, reinterpret_cast<void*>(&HookedOpenSemaphoreA), reinterpret_cast<void**>(&gOpenSemaphoreAOriginal) },
            { L"KernelBase.dll", "WaitForSingleObject", ks::winapi_monitor::EventCategory::kProcess, &gWaitForSingleObjectHook, reinterpret_cast<void*>(&hookedWaitForSingleObject), reinterpret_cast<void**>(&gWaitForSingleObjectOriginal) },
            { L"KernelBase.dll", "WaitForMultipleObjects", ks::winapi_monitor::EventCategory::kProcess, &gWaitForMultipleObjectsHook, reinterpret_cast<void*>(&hookedWaitForMultipleObjects), reinterpret_cast<void**>(&gWaitForMultipleObjectsOriginal) },
            { L"KernelBase.dll", "SetEvent", ks::winapi_monitor::EventCategory::kProcess, &gSetEventHook, reinterpret_cast<void*>(&HookedSetEvent), reinterpret_cast<void**>(&gSetEventOriginal) },
            { L"KernelBase.dll", "ResetEvent", ks::winapi_monitor::EventCategory::kProcess, &gResetEventHook, reinterpret_cast<void*>(&HookedResetEvent), reinterpret_cast<void**>(&gResetEventOriginal) },
            { L"KernelBase.dll", "ReleaseMutex", ks::winapi_monitor::EventCategory::kProcess, &gReleaseMutexHook, reinterpret_cast<void*>(&HookedReleaseMutex), reinterpret_cast<void**>(&gReleaseMutexOriginal) },
            { L"KernelBase.dll", "ReleaseSemaphore", ks::winapi_monitor::EventCategory::kProcess, &gReleaseSemaphoreHook, reinterpret_cast<void*>(&HookedReleaseSemaphore), reinterpret_cast<void**>(&gReleaseSemaphoreOriginal) },
            { L"KernelBase.dll", "GetEnvironmentVariableW", ks::winapi_monitor::EventCategory::kProcess, &gGetEnvironmentVariableWHook, reinterpret_cast<void*>(&hookedGetEnvironmentVariableW), reinterpret_cast<void**>(&gGetEnvironmentVariableWOriginal) },
            { L"KernelBase.dll", "GetEnvironmentVariableA", ks::winapi_monitor::EventCategory::kProcess, &gGetEnvironmentVariableAHook, reinterpret_cast<void*>(&hookedGetEnvironmentVariableA), reinterpret_cast<void**>(&gGetEnvironmentVariableAOriginal) },
            { L"KernelBase.dll", "SetEnvironmentVariableW", ks::winapi_monitor::EventCategory::kProcess, &gSetEnvironmentVariableWHook, reinterpret_cast<void*>(&HookedSetEnvironmentVariableW), reinterpret_cast<void**>(&gSetEnvironmentVariableWOriginal) },
            { L"KernelBase.dll", "SetEnvironmentVariableA", ks::winapi_monitor::EventCategory::kProcess, &gSetEnvironmentVariableAHook, reinterpret_cast<void*>(&HookedSetEnvironmentVariableA), reinterpret_cast<void**>(&gSetEnvironmentVariableAOriginal) },
            { L"KernelBase.dll", "ExpandEnvironmentStringsW", ks::winapi_monitor::EventCategory::kProcess, &gExpandEnvironmentStringsWHook, reinterpret_cast<void*>(&hookedExpandEnvironmentStringsW), reinterpret_cast<void**>(&gExpandEnvironmentStringsWOriginal) },
            { L"KernelBase.dll", "ExpandEnvironmentStringsA", ks::winapi_monitor::EventCategory::kProcess, &gExpandEnvironmentStringsAHook, reinterpret_cast<void*>(&hookedExpandEnvironmentStringsA), reinterpret_cast<void**>(&gExpandEnvironmentStringsAOriginal) },
            { L"Kernel32.dll", "WinExec", ks::winapi_monitor::EventCategory::kProcess, &gWinExecHook, reinterpret_cast<void*>(&hookedWinExec), reinterpret_cast<void**>(&gWinExecOriginal) },
            { L"Kernel32.dll", "CreateToolhelp32Snapshot", ks::winapi_monitor::EventCategory::kProcess, &gCreateToolhelp32SnapshotHook, reinterpret_cast<void*>(&hookedCreateToolhelp32Snapshot), reinterpret_cast<void**>(&gCreateToolhelp32SnapshotOriginal) },
            { L"Shell32.dll", "ShellExecuteExW", ks::winapi_monitor::EventCategory::kProcess, &gShellExecuteExWHook, reinterpret_cast<void*>(&hookedShellExecuteExW), reinterpret_cast<void**>(&gShellExecuteExWOriginal) },
            { L"Shell32.dll", "ShellExecuteExA", ks::winapi_monitor::EventCategory::kProcess, &gShellExecuteExAHook, reinterpret_cast<void*>(&hookedShellExecuteExA), reinterpret_cast<void**>(&gShellExecuteExAOriginal) },
            { L"Shell32.dll", "ShellExecuteW", ks::winapi_monitor::EventCategory::kProcess, &gShellExecuteWHook, reinterpret_cast<void*>(&hookedShellExecuteW), reinterpret_cast<void**>(&gShellExecuteWOriginal) },
            { L"Shell32.dll", "ShellExecuteA", ks::winapi_monitor::EventCategory::kProcess, &gShellExecuteAHook, reinterpret_cast<void*>(&hookedShellExecuteA), reinterpret_cast<void**>(&gShellExecuteAOriginal) },
            { L"Advapi32.dll", "OpenProcessToken", ks::winapi_monitor::EventCategory::kProcess, &gOpenProcessTokenHook, reinterpret_cast<void*>(&HookedOpenProcessToken), reinterpret_cast<void**>(&gOpenProcessTokenOriginal) },
            { L"Advapi32.dll", "OpenThreadToken", ks::winapi_monitor::EventCategory::kProcess, &gOpenThreadTokenHook, reinterpret_cast<void*>(&HookedOpenThreadToken), reinterpret_cast<void**>(&gOpenThreadTokenOriginal) },
            { L"Advapi32.dll", "AdjustTokenPrivileges", ks::winapi_monitor::EventCategory::kProcess, &gAdjustTokenPrivilegesHook, reinterpret_cast<void*>(&HookedAdjustTokenPrivileges), reinterpret_cast<void**>(&gAdjustTokenPrivilegesOriginal) },
            { L"Advapi32.dll", "DuplicateToken", ks::winapi_monitor::EventCategory::kProcess, &gDuplicateTokenHook, reinterpret_cast<void*>(&HookedDuplicateToken), reinterpret_cast<void**>(&gDuplicateTokenOriginal) },
            { L"Advapi32.dll", "DuplicateTokenEx", ks::winapi_monitor::EventCategory::kProcess, &gDuplicateTokenExHook, reinterpret_cast<void*>(&HookedDuplicateTokenEx), reinterpret_cast<void**>(&gDuplicateTokenExOriginal) },
            { L"Advapi32.dll", "CreateProcessAsUserW", ks::winapi_monitor::EventCategory::kProcess, &gCreateProcessAsUserWHook, reinterpret_cast<void*>(&HookedCreateProcessAsUserW), reinterpret_cast<void**>(&gCreateProcessAsUserWOriginal) },
            { L"Advapi32.dll", "CreateProcessAsUserA", ks::winapi_monitor::EventCategory::kProcess, &gCreateProcessAsUserAHook, reinterpret_cast<void*>(&HookedCreateProcessAsUserA), reinterpret_cast<void**>(&gCreateProcessAsUserAOriginal) },
            { L"Advapi32.dll", "CreateProcessWithTokenW", ks::winapi_monitor::EventCategory::kProcess, &gCreateProcessWithTokenWHook, reinterpret_cast<void*>(&HookedCreateProcessWithTokenW), reinterpret_cast<void**>(&gCreateProcessWithTokenWOriginal) },
            { L"Advapi32.dll", "CreateProcessWithLogonW", ks::winapi_monitor::EventCategory::kProcess, &gCreateProcessWithLogonWHook, reinterpret_cast<void*>(&HookedCreateProcessWithLogonW), reinterpret_cast<void**>(&gCreateProcessWithLogonWOriginal) },
            { L"Advapi32.dll", "ImpersonateLoggedOnUser", ks::winapi_monitor::EventCategory::kProcess, &gImpersonateLoggedOnUserHook, reinterpret_cast<void*>(&HookedImpersonateLoggedOnUser), reinterpret_cast<void**>(&gImpersonateLoggedOnUserOriginal) },
            { L"Advapi32.dll", "RevertToSelf", ks::winapi_monitor::EventCategory::kProcess, &gRevertToSelfHook, reinterpret_cast<void*>(&HookedRevertToSelf), reinterpret_cast<void**>(&gRevertToSelfOriginal) },
            { L"Advapi32.dll", "SetThreadToken", ks::winapi_monitor::EventCategory::kProcess, &gSetThreadTokenHook, reinterpret_cast<void*>(&HookedSetThreadToken), reinterpret_cast<void**>(&gSetThreadTokenOriginal) },
            { L"Advapi32.dll", "LookupPrivilegeValueW", ks::winapi_monitor::EventCategory::kProcess, &gLookupPrivilegeValueWHook, reinterpret_cast<void*>(&HookedLookupPrivilegeValueW), reinterpret_cast<void**>(&gLookupPrivilegeValueWOriginal) },
            { L"Advapi32.dll", "LookupPrivilegeValueA", ks::winapi_monitor::EventCategory::kProcess, &gLookupPrivilegeValueAHook, reinterpret_cast<void*>(&HookedLookupPrivilegeValueA), reinterpret_cast<void**>(&gLookupPrivilegeValueAOriginal) },
            { L"Advapi32.dll", "OpenSCManagerW", ks::winapi_monitor::EventCategory::kProcess, &gOpenScManagerWHook, reinterpret_cast<void*>(&HookedOpenSCManagerW), reinterpret_cast<void**>(&gOpenScManagerWOriginal) },
            { L"Advapi32.dll", "OpenSCManagerA", ks::winapi_monitor::EventCategory::kProcess, &gOpenScManagerAHook, reinterpret_cast<void*>(&HookedOpenSCManagerA), reinterpret_cast<void**>(&gOpenScManagerAOriginal) },
            { L"Advapi32.dll", "OpenServiceW", ks::winapi_monitor::EventCategory::kProcess, &gOpenServiceWHook, reinterpret_cast<void*>(&HookedOpenServiceW), reinterpret_cast<void**>(&gOpenServiceWOriginal) },
            { L"Advapi32.dll", "OpenServiceA", ks::winapi_monitor::EventCategory::kProcess, &gOpenServiceAHook, reinterpret_cast<void*>(&HookedOpenServiceA), reinterpret_cast<void**>(&gOpenServiceAOriginal) },
            { L"Advapi32.dll", "CreateServiceW", ks::winapi_monitor::EventCategory::kProcess, &gCreateServiceWHook, reinterpret_cast<void*>(&HookedCreateServiceW), reinterpret_cast<void**>(&gCreateServiceWOriginal) },
            { L"Advapi32.dll", "CreateServiceA", ks::winapi_monitor::EventCategory::kProcess, &gCreateServiceAHook, reinterpret_cast<void*>(&HookedCreateServiceA), reinterpret_cast<void**>(&gCreateServiceAOriginal) },
            { L"Advapi32.dll", "ChangeServiceConfigW", ks::winapi_monitor::EventCategory::kProcess, &gChangeServiceConfigWHook, reinterpret_cast<void*>(&HookedChangeServiceConfigW), reinterpret_cast<void**>(&gChangeServiceConfigWOriginal) },
            { L"Advapi32.dll", "ChangeServiceConfigA", ks::winapi_monitor::EventCategory::kProcess, &gChangeServiceConfigAHook, reinterpret_cast<void*>(&HookedChangeServiceConfigA), reinterpret_cast<void**>(&gChangeServiceConfigAOriginal) },
            { L"Advapi32.dll", "ChangeServiceConfig2W", ks::winapi_monitor::EventCategory::kProcess, &gChangeServiceConfig2WHook, reinterpret_cast<void*>(&HookedChangeServiceConfig2W), reinterpret_cast<void**>(&gChangeServiceConfig2WOriginal) },
            { L"Advapi32.dll", "ChangeServiceConfig2A", ks::winapi_monitor::EventCategory::kProcess, &gChangeServiceConfig2AHook, reinterpret_cast<void*>(&HookedChangeServiceConfig2A), reinterpret_cast<void**>(&gChangeServiceConfig2AOriginal) },
            { L"Advapi32.dll", "StartServiceW", ks::winapi_monitor::EventCategory::kProcess, &gStartServiceWHook, reinterpret_cast<void*>(&HookedStartServiceW), reinterpret_cast<void**>(&gStartServiceWOriginal) },
            { L"Advapi32.dll", "StartServiceA", ks::winapi_monitor::EventCategory::kProcess, &gStartServiceAHook, reinterpret_cast<void*>(&HookedStartServiceA), reinterpret_cast<void**>(&gStartServiceAOriginal) },
            { L"Advapi32.dll", "ControlService", ks::winapi_monitor::EventCategory::kProcess, &gControlServiceHook, reinterpret_cast<void*>(&HookedControlService), reinterpret_cast<void**>(&gControlServiceOriginal) },
            { L"Advapi32.dll", "DeleteService", ks::winapi_monitor::EventCategory::kProcess, &gDeleteServiceHook, reinterpret_cast<void*>(&HookedDeleteService), reinterpret_cast<void**>(&gDeleteServiceOriginal) },
            { L"Advapi32.dll", "CloseServiceHandle", ks::winapi_monitor::EventCategory::kProcess, &gCloseServiceHandleHook, reinterpret_cast<void*>(&HookedCloseServiceHandle), reinterpret_cast<void**>(&gCloseServiceHandleOriginal) },
            { L"Advapi32.dll", "QueryServiceStatusEx", ks::winapi_monitor::EventCategory::kProcess, &gQueryServiceStatusExHook, reinterpret_cast<void*>(&HookedQueryServiceStatusEx), reinterpret_cast<void**>(&gQueryServiceStatusExOriginal) },
            { L"Advapi32.dll", "QueryServiceConfigW", ks::winapi_monitor::EventCategory::kProcess, &gQueryServiceConfigWHook, reinterpret_cast<void*>(&HookedQueryServiceConfigW), reinterpret_cast<void**>(&gQueryServiceConfigWOriginal) },
            { L"Advapi32.dll", "QueryServiceConfigA", ks::winapi_monitor::EventCategory::kProcess, &gQueryServiceConfigAHook, reinterpret_cast<void*>(&HookedQueryServiceConfigA), reinterpret_cast<void**>(&gQueryServiceConfigAOriginal) },
            { L"Advapi32.dll", "EnumServicesStatusExW", ks::winapi_monitor::EventCategory::kProcess, &gEnumServicesStatusExWHook, reinterpret_cast<void*>(&HookedEnumServicesStatusExW), reinterpret_cast<void**>(&gEnumServicesStatusExWOriginal) },
            { L"Advapi32.dll", "EnumServicesStatusExA", ks::winapi_monitor::EventCategory::kProcess, &gEnumServicesStatusExAHook, reinterpret_cast<void*>(&HookedEnumServicesStatusExA), reinterpret_cast<void**>(&gEnumServicesStatusExAOriginal) },
            { L"Advapi32.dll", "CryptAcquireContextW", ks::winapi_monitor::EventCategory::kProcess, &gCryptAcquireContextWHook, reinterpret_cast<void*>(&HookedCryptAcquireContextW), reinterpret_cast<void**>(&gCryptAcquireContextWOriginal) },
            { L"Advapi32.dll", "CryptAcquireContextA", ks::winapi_monitor::EventCategory::kProcess, &gCryptAcquireContextAHook, reinterpret_cast<void*>(&HookedCryptAcquireContextA), reinterpret_cast<void**>(&gCryptAcquireContextAOriginal) },
            { L"Advapi32.dll", "CryptCreateHash", ks::winapi_monitor::EventCategory::kProcess, &gCryptCreateHashHook, reinterpret_cast<void*>(&HookedCryptCreateHash), reinterpret_cast<void**>(&gCryptCreateHashOriginal) },
            { L"Advapi32.dll", "CryptHashData", ks::winapi_monitor::EventCategory::kProcess, &gCryptHashDataHook, reinterpret_cast<void*>(&HookedCryptHashData), reinterpret_cast<void**>(&gCryptHashDataOriginal) },
            { L"Advapi32.dll", "CryptDeriveKey", ks::winapi_monitor::EventCategory::kProcess, &gCryptDeriveKeyHook, reinterpret_cast<void*>(&HookedCryptDeriveKey), reinterpret_cast<void**>(&gCryptDeriveKeyOriginal) },
            { L"Advapi32.dll", "CryptEncrypt", ks::winapi_monitor::EventCategory::kProcess, &gCryptEncryptHook, reinterpret_cast<void*>(&HookedCryptEncrypt), reinterpret_cast<void**>(&gCryptEncryptOriginal) },
            { L"Advapi32.dll", "CryptDecrypt", ks::winapi_monitor::EventCategory::kProcess, &gCryptDecryptHook, reinterpret_cast<void*>(&HookedCryptDecrypt), reinterpret_cast<void**>(&gCryptDecryptOriginal) },
            { L"Advapi32.dll", "CryptGenRandom", ks::winapi_monitor::EventCategory::kProcess, &gCryptGenRandomHook, reinterpret_cast<void*>(&HookedCryptGenRandom), reinterpret_cast<void**>(&gCryptGenRandomOriginal) },
            { L"Advapi32.dll", "CryptReleaseContext", ks::winapi_monitor::EventCategory::kProcess, &gCryptReleaseContextHook, reinterpret_cast<void*>(&HookedCryptReleaseContext), reinterpret_cast<void**>(&gCryptReleaseContextOriginal) },
            { L"Advapi32.dll", "CryptImportKey", ks::winapi_monitor::EventCategory::kProcess, &gCryptImportKeyHook, reinterpret_cast<void*>(&HookedCryptImportKey), reinterpret_cast<void**>(&gCryptImportKeyOriginal) },
            { L"Advapi32.dll", "CryptExportKey", ks::winapi_monitor::EventCategory::kProcess, &gCryptExportKeyHook, reinterpret_cast<void*>(&HookedCryptExportKey), reinterpret_cast<void**>(&gCryptExportKeyOriginal) },
            { L"Advapi32.dll", "CryptDestroyKey", ks::winapi_monitor::EventCategory::kProcess, &gCryptDestroyKeyHook, reinterpret_cast<void*>(&HookedCryptDestroyKey), reinterpret_cast<void**>(&gCryptDestroyKeyOriginal) },
            { L"Advapi32.dll", "CryptDestroyHash", ks::winapi_monitor::EventCategory::kProcess, &gCryptDestroyHashHook, reinterpret_cast<void*>(&HookedCryptDestroyHash), reinterpret_cast<void**>(&gCryptDestroyHashOriginal) },
            { L"Kernel32.dll", "LoadLibraryA", ks::winapi_monitor::EventCategory::kLoader, &gLoadLibraryAHook, reinterpret_cast<void*>(&hookedLoadLibraryA), reinterpret_cast<void**>(&gLoadLibraryAOriginal) },
            { L"Kernel32.dll", "LoadLibraryW", ks::winapi_monitor::EventCategory::kLoader, &gLoadLibraryWHook, reinterpret_cast<void*>(&hookedLoadLibraryW), reinterpret_cast<void**>(&gLoadLibraryWOriginal) },
            { L"Kernel32.dll", "LoadLibraryExA", ks::winapi_monitor::EventCategory::kLoader, &gLoadLibraryExAHook, reinterpret_cast<void*>(&hookedLoadLibraryExA), reinterpret_cast<void**>(&gLoadLibraryExAOriginal) },
            { L"Kernel32.dll", "LoadLibraryExW", ks::winapi_monitor::EventCategory::kLoader, &gLoadLibraryExWHook, reinterpret_cast<void*>(&hookedLoadLibraryExW), reinterpret_cast<void**>(&gLoadLibraryExWOriginal) },
            { L"Kernel32.dll", "FreeLibrary", ks::winapi_monitor::EventCategory::kLoader, &gFreeLibraryHook, reinterpret_cast<void*>(&HookedFreeLibrary), reinterpret_cast<void**>(&gFreeLibraryOriginal) },
            { L"Kernel32.dll", "GetProcAddress", ks::winapi_monitor::EventCategory::kLoader, &gGetProcAddressHook, reinterpret_cast<void*>(&hookedGetProcAddress), reinterpret_cast<void**>(&gGetProcAddressOriginal) },
            { L"Kernel32.dll", "SetDllDirectoryW", ks::winapi_monitor::EventCategory::kLoader, &gSetDllDirectoryWHook, reinterpret_cast<void*>(&HookedSetDllDirectoryW), reinterpret_cast<void**>(&gSetDllDirectoryWOriginal) },
            { L"Kernel32.dll", "SetDllDirectoryA", ks::winapi_monitor::EventCategory::kLoader, &gSetDllDirectoryAHook, reinterpret_cast<void*>(&HookedSetDllDirectoryA), reinterpret_cast<void**>(&gSetDllDirectoryAOriginal) },
            { L"Kernel32.dll", "SetDefaultDllDirectories", ks::winapi_monitor::EventCategory::kLoader, &gSetDefaultDllDirectoriesHook, reinterpret_cast<void*>(&HookedSetDefaultDllDirectories), reinterpret_cast<void**>(&gSetDefaultDllDirectoriesOriginal) },
            { L"Kernel32.dll", "AddDllDirectory", ks::winapi_monitor::EventCategory::kLoader, &gAddDllDirectoryHook, reinterpret_cast<void*>(&HookedAddDllDirectory), reinterpret_cast<void**>(&gAddDllDirectoryOriginal) },
            { L"Kernel32.dll", "RemoveDllDirectory", ks::winapi_monitor::EventCategory::kLoader, &gRemoveDllDirectoryHook, reinterpret_cast<void*>(&HookedRemoveDllDirectory), reinterpret_cast<void**>(&gRemoveDllDirectoryOriginal) },
            { L"Kernel32.dll", "Module32FirstW", ks::winapi_monitor::EventCategory::kLoader, &gModule32FirstWHook, reinterpret_cast<void*>(&HookedModule32FirstW), reinterpret_cast<void**>(&gModule32FirstWOriginal) },
            { L"Kernel32.dll", "Module32NextW", ks::winapi_monitor::EventCategory::kLoader, &gModule32NextWHook, reinterpret_cast<void*>(&HookedModule32NextW), reinterpret_cast<void**>(&gModule32NextWOriginal) },
            { L"Kernel32.dll", "Module32First", ks::winapi_monitor::EventCategory::kLoader, &gModule32FirstAHook, reinterpret_cast<void*>(&HookedModule32FirstA), reinterpret_cast<void**>(&gModule32FirstAOriginal) },
            { L"Kernel32.dll", "Module32Next", ks::winapi_monitor::EventCategory::kLoader, &gModule32NextAHook, reinterpret_cast<void*>(&HookedModule32NextA), reinterpret_cast<void**>(&gModule32NextAOriginal) },
            { L"Kernel32.dll", "GetModuleHandleW", ks::winapi_monitor::EventCategory::kLoader, &gGetModuleHandleWHook, reinterpret_cast<void*>(&HookedGetModuleHandleW), reinterpret_cast<void**>(&gGetModuleHandleWOriginal) },
            { L"Kernel32.dll", "GetModuleHandleA", ks::winapi_monitor::EventCategory::kLoader, &gGetModuleHandleAHook, reinterpret_cast<void*>(&HookedGetModuleHandleA), reinterpret_cast<void**>(&gGetModuleHandleAOriginal) },
            { L"Kernel32.dll", "GetModuleHandleExW", ks::winapi_monitor::EventCategory::kLoader, &gGetModuleHandleExWHook, reinterpret_cast<void*>(&HookedGetModuleHandleExW), reinterpret_cast<void**>(&gGetModuleHandleExWOriginal) },
            { L"Kernel32.dll", "GetModuleHandleExA", ks::winapi_monitor::EventCategory::kLoader, &gGetModuleHandleExAHook, reinterpret_cast<void*>(&HookedGetModuleHandleExA), reinterpret_cast<void**>(&gGetModuleHandleExAOriginal) },
            { L"Kernel32.dll", "GetModuleFileNameW", ks::winapi_monitor::EventCategory::kLoader, &gGetModuleFileNameWHook, reinterpret_cast<void*>(&hookedGetModuleFileNameW), reinterpret_cast<void**>(&gGetModuleFileNameWOriginal) },
            { L"Kernel32.dll", "GetModuleFileNameA", ks::winapi_monitor::EventCategory::kLoader, &gGetModuleFileNameAHook, reinterpret_cast<void*>(&hookedGetModuleFileNameA), reinterpret_cast<void**>(&gGetModuleFileNameAOriginal) },
            { L"ntdll.dll", "LdrLoadDll", ks::winapi_monitor::EventCategory::kLoader, &gLdrLoadDllHook, reinterpret_cast<void*>(&hookedLdrLoadDll), reinterpret_cast<void**>(&gLdrLoadDllOriginal) },
            { L"ntdll.dll", "LdrGetProcedureAddress", ks::winapi_monitor::EventCategory::kLoader, &gLdrGetProcedureAddressHook, reinterpret_cast<void*>(&hookedLdrGetProcedureAddress), reinterpret_cast<void**>(&gLdrGetProcedureAddressOriginal) },
            { L"Advapi32.dll", "RegOpenKeyW", ks::winapi_monitor::EventCategory::kRegistry, &gRegOpenKeyWHook, reinterpret_cast<void*>(&hookedRegOpenKeyW), reinterpret_cast<void**>(&gRegOpenKeyWOriginal) },
            { L"Advapi32.dll", "RegOpenKeyA", ks::winapi_monitor::EventCategory::kRegistry, &gRegOpenKeyAHook, reinterpret_cast<void*>(&hookedRegOpenKeyA), reinterpret_cast<void**>(&gRegOpenKeyAOriginal) },
            { L"Advapi32.dll", "RegOpenKeyExW", ks::winapi_monitor::EventCategory::kRegistry, &gRegOpenKeyExWHook, reinterpret_cast<void*>(&hookedRegOpenKeyExW), reinterpret_cast<void**>(&gRegOpenKeyExWOriginal) },
            { L"Advapi32.dll", "RegOpenKeyExA", ks::winapi_monitor::EventCategory::kRegistry, &gRegOpenKeyExAHook, reinterpret_cast<void*>(&hookedRegOpenKeyExA), reinterpret_cast<void**>(&gRegOpenKeyExAOriginal) },
            { L"Advapi32.dll", "RegCreateKeyW", ks::winapi_monitor::EventCategory::kRegistry, &gRegCreateKeyWHook, reinterpret_cast<void*>(&hookedRegCreateKeyW), reinterpret_cast<void**>(&gRegCreateKeyWOriginal) },
            { L"Advapi32.dll", "RegCreateKeyA", ks::winapi_monitor::EventCategory::kRegistry, &gRegCreateKeyAHook, reinterpret_cast<void*>(&hookedRegCreateKeyA), reinterpret_cast<void**>(&gRegCreateKeyAOriginal) },
            { L"Advapi32.dll", "RegCreateKeyExW", ks::winapi_monitor::EventCategory::kRegistry, &gRegCreateKeyExWHook, reinterpret_cast<void*>(&hookedRegCreateKeyExW), reinterpret_cast<void**>(&gRegCreateKeyExWOriginal) },
            { L"Advapi32.dll", "RegCreateKeyExA", ks::winapi_monitor::EventCategory::kRegistry, &gRegCreateKeyExAHook, reinterpret_cast<void*>(&hookedRegCreateKeyExA), reinterpret_cast<void**>(&gRegCreateKeyExAOriginal) },
            { L"Advapi32.dll", "RegQueryValueExW", ks::winapi_monitor::EventCategory::kRegistry, &gRegQueryValueExWHook, reinterpret_cast<void*>(&hookedRegQueryValueExW), reinterpret_cast<void**>(&gRegQueryValueExWOriginal) },
            { L"Advapi32.dll", "RegQueryValueExA", ks::winapi_monitor::EventCategory::kRegistry, &gRegQueryValueExAHook, reinterpret_cast<void*>(&hookedRegQueryValueExA), reinterpret_cast<void**>(&gRegQueryValueExAOriginal) },
            { L"Advapi32.dll", "RegGetValueW", ks::winapi_monitor::EventCategory::kRegistry, &gRegGetValueWHook, reinterpret_cast<void*>(&hookedRegGetValueW), reinterpret_cast<void**>(&gRegGetValueWOriginal) },
            { L"Advapi32.dll", "RegGetValueA", ks::winapi_monitor::EventCategory::kRegistry, &gRegGetValueAHook, reinterpret_cast<void*>(&hookedRegGetValueA), reinterpret_cast<void**>(&gRegGetValueAOriginal) },
            { L"Advapi32.dll", "RegSetValueExW", ks::winapi_monitor::EventCategory::kRegistry, &gRegSetValueExWHook, reinterpret_cast<void*>(&hookedRegSetValueExW), reinterpret_cast<void**>(&gRegSetValueExWOriginal) },
            { L"Advapi32.dll", "RegSetValueExA", ks::winapi_monitor::EventCategory::kRegistry, &gRegSetValueExAHook, reinterpret_cast<void*>(&hookedRegSetValueExA), reinterpret_cast<void**>(&gRegSetValueExAOriginal) },
            { L"Advapi32.dll", "RegSetKeyValueW", ks::winapi_monitor::EventCategory::kRegistry, &gRegSetKeyValueWHook, reinterpret_cast<void*>(&hookedRegSetKeyValueW), reinterpret_cast<void**>(&gRegSetKeyValueWOriginal) },
            { L"Advapi32.dll", "RegSetKeyValueA", ks::winapi_monitor::EventCategory::kRegistry, &gRegSetKeyValueAHook, reinterpret_cast<void*>(&hookedRegSetKeyValueA), reinterpret_cast<void**>(&gRegSetKeyValueAOriginal) },
            { L"Advapi32.dll", "RegDeleteValueW", ks::winapi_monitor::EventCategory::kRegistry, &gRegDeleteValueWHook, reinterpret_cast<void*>(&hookedRegDeleteValueW), reinterpret_cast<void**>(&gRegDeleteValueWOriginal) },
            { L"Advapi32.dll", "RegDeleteValueA", ks::winapi_monitor::EventCategory::kRegistry, &gRegDeleteValueAHook, reinterpret_cast<void*>(&hookedRegDeleteValueA), reinterpret_cast<void**>(&gRegDeleteValueAOriginal) },
            { L"Advapi32.dll", "RegDeleteKeyW", ks::winapi_monitor::EventCategory::kRegistry, &gRegDeleteKeyWHook, reinterpret_cast<void*>(&hookedRegDeleteKeyW), reinterpret_cast<void**>(&gRegDeleteKeyWOriginal) },
            { L"Advapi32.dll", "RegDeleteKeyA", ks::winapi_monitor::EventCategory::kRegistry, &gRegDeleteKeyAHook, reinterpret_cast<void*>(&hookedRegDeleteKeyA), reinterpret_cast<void**>(&gRegDeleteKeyAOriginal) },
            { L"Advapi32.dll", "RegDeleteKeyExW", ks::winapi_monitor::EventCategory::kRegistry, &gRegDeleteKeyExWHook, reinterpret_cast<void*>(&hookedRegDeleteKeyExW), reinterpret_cast<void**>(&gRegDeleteKeyExWOriginal) },
            { L"Advapi32.dll", "RegDeleteKeyExA", ks::winapi_monitor::EventCategory::kRegistry, &gRegDeleteKeyExAHook, reinterpret_cast<void*>(&hookedRegDeleteKeyExA), reinterpret_cast<void**>(&gRegDeleteKeyExAOriginal) },
            { L"Advapi32.dll", "RegDeleteTreeW", ks::winapi_monitor::EventCategory::kRegistry, &gRegDeleteTreeWHook, reinterpret_cast<void*>(&hookedRegDeleteTreeW), reinterpret_cast<void**>(&gRegDeleteTreeWOriginal) },
            { L"Advapi32.dll", "RegDeleteTreeA", ks::winapi_monitor::EventCategory::kRegistry, &gRegDeleteTreeAHook, reinterpret_cast<void*>(&hookedRegDeleteTreeA), reinterpret_cast<void**>(&gRegDeleteTreeAOriginal) },
            { L"Advapi32.dll", "RegCopyTreeW", ks::winapi_monitor::EventCategory::kRegistry, &gRegCopyTreeWHook, reinterpret_cast<void*>(&hookedRegCopyTreeW), reinterpret_cast<void**>(&gRegCopyTreeWOriginal) },
            { L"Advapi32.dll", "RegCopyTreeA", ks::winapi_monitor::EventCategory::kRegistry, &gRegCopyTreeAHook, reinterpret_cast<void*>(&hookedRegCopyTreeA), reinterpret_cast<void**>(&gRegCopyTreeAOriginal) },
            { L"Advapi32.dll", "RegLoadKeyW", ks::winapi_monitor::EventCategory::kRegistry, &gRegLoadKeyWHook, reinterpret_cast<void*>(&hookedRegLoadKeyW), reinterpret_cast<void**>(&gRegLoadKeyWOriginal) },
            { L"Advapi32.dll", "RegLoadKeyA", ks::winapi_monitor::EventCategory::kRegistry, &gRegLoadKeyAHook, reinterpret_cast<void*>(&hookedRegLoadKeyA), reinterpret_cast<void**>(&gRegLoadKeyAOriginal) },
            { L"Advapi32.dll", "RegSaveKeyW", ks::winapi_monitor::EventCategory::kRegistry, &gRegSaveKeyWHook, reinterpret_cast<void*>(&hookedRegSaveKeyW), reinterpret_cast<void**>(&gRegSaveKeyWOriginal) },
            { L"Advapi32.dll", "RegSaveKeyA", ks::winapi_monitor::EventCategory::kRegistry, &gRegSaveKeyAHook, reinterpret_cast<void*>(&hookedRegSaveKeyA), reinterpret_cast<void**>(&gRegSaveKeyAOriginal) },
            { L"Advapi32.dll", "RegRenameKey", ks::winapi_monitor::EventCategory::kRegistry, &gRegRenameKeyHook, reinterpret_cast<void*>(&hookedRegRenameKey), reinterpret_cast<void**>(&gRegRenameKeyOriginal) },
            { L"Advapi32.dll", "RegEnumKeyExW", ks::winapi_monitor::EventCategory::kRegistry, &gRegEnumKeyExWHook, reinterpret_cast<void*>(&hookedRegEnumKeyExW), reinterpret_cast<void**>(&gRegEnumKeyExWOriginal) },
            { L"Advapi32.dll", "RegEnumKeyExA", ks::winapi_monitor::EventCategory::kRegistry, &gRegEnumKeyExAHook, reinterpret_cast<void*>(&hookedRegEnumKeyExA), reinterpret_cast<void**>(&gRegEnumKeyExAOriginal) },
            { L"Advapi32.dll", "RegEnumValueW", ks::winapi_monitor::EventCategory::kRegistry, &gRegEnumValueWHook, reinterpret_cast<void*>(&hookedRegEnumValueW), reinterpret_cast<void**>(&gRegEnumValueWOriginal) },
            { L"Advapi32.dll", "RegEnumValueA", ks::winapi_monitor::EventCategory::kRegistry, &gRegEnumValueAHook, reinterpret_cast<void*>(&hookedRegEnumValueA), reinterpret_cast<void**>(&gRegEnumValueAOriginal) },
            { L"Advapi32.dll", "RegCloseKey", ks::winapi_monitor::EventCategory::kRegistry, &gRegCloseKeyHook, reinterpret_cast<void*>(&hookedRegCloseKey), reinterpret_cast<void**>(&gRegCloseKeyOriginal) },
            { L"Advapi32.dll", "RegQueryInfoKeyW", ks::winapi_monitor::EventCategory::kRegistry, &gRegQueryInfoKeyWHook, reinterpret_cast<void*>(&hookedRegQueryInfoKeyW), reinterpret_cast<void**>(&gRegQueryInfoKeyWOriginal) },
            { L"Advapi32.dll", "RegQueryInfoKeyA", ks::winapi_monitor::EventCategory::kRegistry, &gRegQueryInfoKeyAHook, reinterpret_cast<void*>(&hookedRegQueryInfoKeyA), reinterpret_cast<void**>(&gRegQueryInfoKeyAOriginal) },
            { L"Advapi32.dll", "RegFlushKey", ks::winapi_monitor::EventCategory::kRegistry, &gRegFlushKeyHook, reinterpret_cast<void*>(&hookedRegFlushKey), reinterpret_cast<void**>(&gRegFlushKeyOriginal) },
            { L"Advapi32.dll", "RegDeleteKeyValueW", ks::winapi_monitor::EventCategory::kRegistry, &gRegDeleteKeyValueWHook, reinterpret_cast<void*>(&hookedRegDeleteKeyValueW), reinterpret_cast<void**>(&gRegDeleteKeyValueWOriginal) },
            { L"Advapi32.dll", "RegDeleteKeyValueA", ks::winapi_monitor::EventCategory::kRegistry, &gRegDeleteKeyValueAHook, reinterpret_cast<void*>(&hookedRegDeleteKeyValueA), reinterpret_cast<void**>(&gRegDeleteKeyValueAOriginal) },
            { L"Advapi32.dll", "RegConnectRegistryW", ks::winapi_monitor::EventCategory::kRegistry, &gRegConnectRegistryWHook, reinterpret_cast<void*>(&hookedRegConnectRegistryW), reinterpret_cast<void**>(&gRegConnectRegistryWOriginal) },
            { L"Advapi32.dll", "RegConnectRegistryA", ks::winapi_monitor::EventCategory::kRegistry, &gRegConnectRegistryAHook, reinterpret_cast<void*>(&hookedRegConnectRegistryA), reinterpret_cast<void**>(&gRegConnectRegistryAOriginal) },
            { L"Advapi32.dll", "RegCreateKeyTransactedW", ks::winapi_monitor::EventCategory::kRegistry, &gRegCreateKeyTransactedWHook, reinterpret_cast<void*>(&HookedRegCreateKeyTransactedW), reinterpret_cast<void**>(&gRegCreateKeyTransactedWOriginal) },
            { L"Advapi32.dll", "RegCreateKeyTransactedA", ks::winapi_monitor::EventCategory::kRegistry, &gRegCreateKeyTransactedAHook, reinterpret_cast<void*>(&HookedRegCreateKeyTransactedA), reinterpret_cast<void**>(&gRegCreateKeyTransactedAOriginal) },
            { L"Advapi32.dll", "RegOpenKeyTransactedW", ks::winapi_monitor::EventCategory::kRegistry, &gRegOpenKeyTransactedWHook, reinterpret_cast<void*>(&HookedRegOpenKeyTransactedW), reinterpret_cast<void**>(&gRegOpenKeyTransactedWOriginal) },
            { L"Advapi32.dll", "RegOpenKeyTransactedA", ks::winapi_monitor::EventCategory::kRegistry, &gRegOpenKeyTransactedAHook, reinterpret_cast<void*>(&HookedRegOpenKeyTransactedA), reinterpret_cast<void**>(&gRegOpenKeyTransactedAOriginal) },
            { L"Advapi32.dll", "RegDeleteKeyTransactedW", ks::winapi_monitor::EventCategory::kRegistry, &gRegDeleteKeyTransactedWHook, reinterpret_cast<void*>(&HookedRegDeleteKeyTransactedW), reinterpret_cast<void**>(&gRegDeleteKeyTransactedWOriginal) },
            { L"Advapi32.dll", "RegDeleteKeyTransactedA", ks::winapi_monitor::EventCategory::kRegistry, &gRegDeleteKeyTransactedAHook, reinterpret_cast<void*>(&HookedRegDeleteKeyTransactedA), reinterpret_cast<void**>(&gRegDeleteKeyTransactedAOriginal) },
            { L"Advapi32.dll", "RegReplaceKeyW", ks::winapi_monitor::EventCategory::kRegistry, &gRegReplaceKeyWHook, reinterpret_cast<void*>(&HookedRegReplaceKeyW), reinterpret_cast<void**>(&gRegReplaceKeyWOriginal) },
            { L"Advapi32.dll", "RegReplaceKeyA", ks::winapi_monitor::EventCategory::kRegistry, &gRegReplaceKeyAHook, reinterpret_cast<void*>(&HookedRegReplaceKeyA), reinterpret_cast<void**>(&gRegReplaceKeyAOriginal) },
            { L"Advapi32.dll", "RegRestoreKeyW", ks::winapi_monitor::EventCategory::kRegistry, &gRegRestoreKeyWHook, reinterpret_cast<void*>(&HookedRegRestoreKeyW), reinterpret_cast<void**>(&gRegRestoreKeyWOriginal) },
            { L"Advapi32.dll", "RegRestoreKeyA", ks::winapi_monitor::EventCategory::kRegistry, &gRegRestoreKeyAHook, reinterpret_cast<void*>(&HookedRegRestoreKeyA), reinterpret_cast<void**>(&gRegRestoreKeyAOriginal) },
            { L"Advapi32.dll", "RegUnLoadKeyW", ks::winapi_monitor::EventCategory::kRegistry, &gRegUnLoadKeyWHook, reinterpret_cast<void*>(&HookedRegUnLoadKeyW), reinterpret_cast<void**>(&gRegUnLoadKeyWOriginal) },
            { L"Advapi32.dll", "RegUnLoadKeyA", ks::winapi_monitor::EventCategory::kRegistry, &gRegUnLoadKeyAHook, reinterpret_cast<void*>(&HookedRegUnLoadKeyA), reinterpret_cast<void**>(&gRegUnLoadKeyAOriginal) },
            { L"Advapi32.dll", "RegLoadAppKeyW", ks::winapi_monitor::EventCategory::kRegistry, &gRegLoadAppKeyWHook, reinterpret_cast<void*>(&HookedRegLoadAppKeyW), reinterpret_cast<void**>(&gRegLoadAppKeyWOriginal) },
            { L"Advapi32.dll", "RegLoadAppKeyA", ks::winapi_monitor::EventCategory::kRegistry, &gRegLoadAppKeyAHook, reinterpret_cast<void*>(&HookedRegLoadAppKeyA), reinterpret_cast<void**>(&gRegLoadAppKeyAOriginal) },
            { L"Advapi32.dll", "RegNotifyChangeKeyValue", ks::winapi_monitor::EventCategory::kRegistry, &gRegNotifyChangeKeyValueHook, reinterpret_cast<void*>(&HookedRegNotifyChangeKeyValue), reinterpret_cast<void**>(&gRegNotifyChangeKeyValueOriginal) },
            { L"ntdll.dll", "NtCreateKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtCreateKeyHook, reinterpret_cast<void*>(&hookedNtCreateKey), reinterpret_cast<void**>(&gNtCreateKeyOriginal) },
            { L"ntdll.dll", "NtOpenKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtOpenKeyHook, reinterpret_cast<void*>(&hookedNtOpenKey), reinterpret_cast<void**>(&gNtOpenKeyOriginal) },
            { L"ntdll.dll", "NtOpenKeyEx", ks::winapi_monitor::EventCategory::kRegistry, &gNtOpenKeyExHook, reinterpret_cast<void*>(&hookedNtOpenKeyEx), reinterpret_cast<void**>(&gNtOpenKeyExOriginal) },
            { L"ntdll.dll", "NtSetValueKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtSetValueKeyHook, reinterpret_cast<void*>(&hookedNtSetValueKey), reinterpret_cast<void**>(&gNtSetValueKeyOriginal) },
            { L"ntdll.dll", "NtQueryValueKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtQueryValueKeyHook, reinterpret_cast<void*>(&hookedNtQueryValueKey), reinterpret_cast<void**>(&gNtQueryValueKeyOriginal) },
            { L"ntdll.dll", "NtEnumerateKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtEnumerateKeyHook, reinterpret_cast<void*>(&hookedNtEnumerateKey), reinterpret_cast<void**>(&gNtEnumerateKeyOriginal) },
            { L"ntdll.dll", "NtEnumerateValueKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtEnumerateValueKeyHook, reinterpret_cast<void*>(&hookedNtEnumerateValueKey), reinterpret_cast<void**>(&gNtEnumerateValueKeyOriginal) },
            { L"ntdll.dll", "NtDeleteKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtDeleteKeyHook, reinterpret_cast<void*>(&hookedNtDeleteKey), reinterpret_cast<void**>(&gNtDeleteKeyOriginal) },
            { L"ntdll.dll", "NtDeleteValueKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtDeleteValueKeyHook, reinterpret_cast<void*>(&hookedNtDeleteValueKey), reinterpret_cast<void**>(&gNtDeleteValueKeyOriginal) },
            { L"ntdll.dll", "NtFlushKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtFlushKeyHook, reinterpret_cast<void*>(&hookedNtFlushKey), reinterpret_cast<void**>(&gNtFlushKeyOriginal) },
            { L"ntdll.dll", "NtRenameKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtRenameKeyHook, reinterpret_cast<void*>(&hookedNtRenameKey), reinterpret_cast<void**>(&gNtRenameKeyOriginal) },
            { L"ntdll.dll", "NtLoadKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtLoadKeyHook, reinterpret_cast<void*>(&hookedNtLoadKey), reinterpret_cast<void**>(&gNtLoadKeyOriginal) },
            { L"ntdll.dll", "NtSaveKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtSaveKeyHook, reinterpret_cast<void*>(&hookedNtSaveKey), reinterpret_cast<void**>(&gNtSaveKeyOriginal) },
            { L"ntdll.dll", "NtQueryKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtQueryKeyHook, reinterpret_cast<void*>(&hookedNtQueryKey), reinterpret_cast<void**>(&gNtQueryKeyOriginal) },
            { L"ntdll.dll", "NtQueryMultipleValueKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtQueryMultipleValueKeyHook, reinterpret_cast<void*>(&hookedNtQueryMultipleValueKey), reinterpret_cast<void**>(&gNtQueryMultipleValueKeyOriginal) },
            { L"ntdll.dll", "NtNotifyChangeKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtNotifyChangeKeyHook, reinterpret_cast<void*>(&hookedNtNotifyChangeKey), reinterpret_cast<void**>(&gNtNotifyChangeKeyOriginal) },
            { L"ntdll.dll", "NtLoadKey2", ks::winapi_monitor::EventCategory::kRegistry, &gNtLoadKey2Hook, reinterpret_cast<void*>(&hookedNtLoadKey2), reinterpret_cast<void**>(&gNtLoadKey2Original) },
            { L"ntdll.dll", "NtSaveKeyEx", ks::winapi_monitor::EventCategory::kRegistry, &gNtSaveKeyExHook, reinterpret_cast<void*>(&hookedNtSaveKeyEx), reinterpret_cast<void**>(&gNtSaveKeyExOriginal) },
            { L"ntdll.dll", "NtLoadDriver", ks::winapi_monitor::EventCategory::kRegistry, &gNtLoadDriverHook, reinterpret_cast<void*>(&hookedNtLoadDriver), reinterpret_cast<void**>(&gNtLoadDriverOriginal) },
            { L"ntdll.dll", "NtUnloadDriver", ks::winapi_monitor::EventCategory::kRegistry, &gNtUnloadDriverHook, reinterpret_cast<void*>(&hookedNtUnloadDriver), reinterpret_cast<void**>(&gNtUnloadDriverOriginal) },
            { L"ntdll.dll", "NtCreateKeyTransacted", ks::winapi_monitor::EventCategory::kRegistry, &gNtCreateKeyTransactedHook, reinterpret_cast<void*>(&HookedNtCreateKeyTransacted), reinterpret_cast<void**>(&gNtCreateKeyTransactedOriginal) },
            { L"ntdll.dll", "NtOpenKeyTransacted", ks::winapi_monitor::EventCategory::kRegistry, &gNtOpenKeyTransactedHook, reinterpret_cast<void*>(&HookedNtOpenKeyTransacted), reinterpret_cast<void**>(&gNtOpenKeyTransactedOriginal) },
            { L"ntdll.dll", "NtOpenKeyTransactedEx", ks::winapi_monitor::EventCategory::kRegistry, &gNtOpenKeyTransactedExHook, reinterpret_cast<void*>(&HookedNtOpenKeyTransactedEx), reinterpret_cast<void**>(&gNtOpenKeyTransactedExOriginal) },
            { L"ntdll.dll", "NtReplaceKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtReplaceKeyHook, reinterpret_cast<void*>(&HookedNtReplaceKey), reinterpret_cast<void**>(&gNtReplaceKeyOriginal) },
            { L"ntdll.dll", "NtRestoreKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtRestoreKeyHook, reinterpret_cast<void*>(&HookedNtRestoreKey), reinterpret_cast<void**>(&gNtRestoreKeyOriginal) },
            { L"ntdll.dll", "NtUnloadKey", ks::winapi_monitor::EventCategory::kRegistry, &gNtUnloadKeyHook, reinterpret_cast<void*>(&HookedNtUnloadKey), reinterpret_cast<void**>(&gNtUnloadKeyOriginal) },
            { L"ntdll.dll", "NtUnloadKey2", ks::winapi_monitor::EventCategory::kRegistry, &gNtUnloadKey2Hook, reinterpret_cast<void*>(&HookedNtUnloadKey2), reinterpret_cast<void**>(&gNtUnloadKey2Original) },
            { L"ntdll.dll", "NtUnloadKeyEx", ks::winapi_monitor::EventCategory::kRegistry, &gNtUnloadKeyExHook, reinterpret_cast<void*>(&HookedNtUnloadKeyEx), reinterpret_cast<void**>(&gNtUnloadKeyExOriginal) },
            { L"ntdll.dll", "NtCreateFile", ks::winapi_monitor::EventCategory::kFile, &gNtCreateFileHook, reinterpret_cast<void*>(&hookedNtCreateFile), reinterpret_cast<void**>(&gNtCreateFileOriginal) },
            { L"ntdll.dll", "NtOpenFile", ks::winapi_monitor::EventCategory::kFile, &gNtOpenFileHook, reinterpret_cast<void*>(&hookedNtOpenFile), reinterpret_cast<void**>(&gNtOpenFileOriginal) },
            { L"ntdll.dll", "NtReadFile", ks::winapi_monitor::EventCategory::kFile, &gNtReadFileHook, reinterpret_cast<void*>(&hookedNtReadFile), reinterpret_cast<void**>(&gNtReadFileOriginal) },
            { L"ntdll.dll", "NtWriteFile", ks::winapi_monitor::EventCategory::kFile, &gNtWriteFileHook, reinterpret_cast<void*>(&hookedNtWriteFile), reinterpret_cast<void**>(&gNtWriteFileOriginal) },
            { L"ntdll.dll", "NtSetInformationFile", ks::winapi_monitor::EventCategory::kFile, &gNtSetInformationFileHook, reinterpret_cast<void*>(&hookedNtSetInformationFile), reinterpret_cast<void**>(&gNtSetInformationFileOriginal) },
            { L"ntdll.dll", "NtQueryInformationFile", ks::winapi_monitor::EventCategory::kFile, &gNtQueryInformationFileHook, reinterpret_cast<void*>(&hookedNtQueryInformationFile), reinterpret_cast<void**>(&gNtQueryInformationFileOriginal) },
            { L"ntdll.dll", "NtDeleteFile", ks::winapi_monitor::EventCategory::kFile, &gNtDeleteFileHook, reinterpret_cast<void*>(&hookedNtDeleteFile), reinterpret_cast<void**>(&gNtDeleteFileOriginal) },
            { L"ntdll.dll", "NtQueryAttributesFile", ks::winapi_monitor::EventCategory::kFile, &gNtQueryAttributesFileHook, reinterpret_cast<void*>(&hookedNtQueryAttributesFile), reinterpret_cast<void**>(&gNtQueryAttributesFileOriginal) },
            { L"ntdll.dll", "NtQueryFullAttributesFile", ks::winapi_monitor::EventCategory::kFile, &gNtQueryFullAttributesFileHook, reinterpret_cast<void*>(&hookedNtQueryFullAttributesFile), reinterpret_cast<void**>(&gNtQueryFullAttributesFileOriginal) },
            { L"ntdll.dll", "NtDeviceIoControlFile", ks::winapi_monitor::EventCategory::kFile, &gNtDeviceIoControlFileHook, reinterpret_cast<void*>(&hookedNtDeviceIoControlFile), reinterpret_cast<void**>(&gNtDeviceIoControlFileOriginal) },
            { L"ntdll.dll", "NtFsControlFile", ks::winapi_monitor::EventCategory::kFile, &gNtFsControlFileHook, reinterpret_cast<void*>(&hookedNtFsControlFile), reinterpret_cast<void**>(&gNtFsControlFileOriginal) },
            { L"ntdll.dll", "NtQueryDirectoryFile", ks::winapi_monitor::EventCategory::kFile, &gNtQueryDirectoryFileHook, reinterpret_cast<void*>(&hookedNtQueryDirectoryFile), reinterpret_cast<void**>(&gNtQueryDirectoryFileOriginal) },
            { L"ntdll.dll", "NtQueryDirectoryFileEx", ks::winapi_monitor::EventCategory::kFile, &gNtQueryDirectoryFileExHook, reinterpret_cast<void*>(&hookedNtQueryDirectoryFileEx), reinterpret_cast<void**>(&gNtQueryDirectoryFileExOriginal) },
            { L"ntdll.dll", "NtOpenProcess", ks::winapi_monitor::EventCategory::kProcess, &gNtOpenProcessHook, reinterpret_cast<void*>(&hookedNtOpenProcess), reinterpret_cast<void**>(&gNtOpenProcessOriginal) },
            { L"ntdll.dll", "NtOpenThread", ks::winapi_monitor::EventCategory::kProcess, &gNtOpenThreadHook, reinterpret_cast<void*>(&hookedNtOpenThread), reinterpret_cast<void**>(&gNtOpenThreadOriginal) },
            { L"ntdll.dll", "NtTerminateProcess", ks::winapi_monitor::EventCategory::kProcess, &gNtTerminateProcessHook, reinterpret_cast<void*>(&hookedNtTerminateProcess), reinterpret_cast<void**>(&gNtTerminateProcessOriginal) },
            { L"ntdll.dll", "NtCreateUserProcess", ks::winapi_monitor::EventCategory::kProcess, &gNtCreateUserProcessHook, reinterpret_cast<void*>(&hookedNtCreateUserProcess), reinterpret_cast<void**>(&gNtCreateUserProcessOriginal) },
            { L"ntdll.dll", "NtCreateProcessEx", ks::winapi_monitor::EventCategory::kProcess, &gNtCreateProcessExHook, reinterpret_cast<void*>(&hookedNtCreateProcessEx), reinterpret_cast<void**>(&gNtCreateProcessExOriginal) },
            { L"ntdll.dll", "NtCreateThreadEx", ks::winapi_monitor::EventCategory::kProcess, &gNtCreateThreadExHook, reinterpret_cast<void*>(&hookedNtCreateThreadEx), reinterpret_cast<void**>(&gNtCreateThreadExOriginal) },
            { L"ntdll.dll", "NtAllocateVirtualMemory", ks::winapi_monitor::EventCategory::kProcess, &gNtAllocateVirtualMemoryHook, reinterpret_cast<void*>(&hookedNtAllocateVirtualMemory), reinterpret_cast<void**>(&gNtAllocateVirtualMemoryOriginal) },
            { L"ntdll.dll", "NtFreeVirtualMemory", ks::winapi_monitor::EventCategory::kProcess, &gNtFreeVirtualMemoryHook, reinterpret_cast<void*>(&hookedNtFreeVirtualMemory), reinterpret_cast<void**>(&gNtFreeVirtualMemoryOriginal) },
            { L"ntdll.dll", "NtProtectVirtualMemory", ks::winapi_monitor::EventCategory::kProcess, &gNtProtectVirtualMemoryHook, reinterpret_cast<void*>(&hookedNtProtectVirtualMemory), reinterpret_cast<void**>(&gNtProtectVirtualMemoryOriginal) },
            { L"ntdll.dll", "NtWriteVirtualMemory", ks::winapi_monitor::EventCategory::kProcess, &gNtWriteVirtualMemoryHook, reinterpret_cast<void*>(&hookedNtWriteVirtualMemory), reinterpret_cast<void**>(&gNtWriteVirtualMemoryOriginal) },
            { L"ntdll.dll", "NtReadVirtualMemory", ks::winapi_monitor::EventCategory::kProcess, &gNtReadVirtualMemoryHook, reinterpret_cast<void*>(&hookedNtReadVirtualMemory), reinterpret_cast<void**>(&gNtReadVirtualMemoryOriginal) },
            { L"ntdll.dll", "NtMapViewOfSection", ks::winapi_monitor::EventCategory::kProcess, &gNtMapViewOfSectionHook, reinterpret_cast<void*>(&hookedNtMapViewOfSection), reinterpret_cast<void**>(&gNtMapViewOfSectionOriginal) },
            { L"ntdll.dll", "NtUnmapViewOfSection", ks::winapi_monitor::EventCategory::kProcess, &gNtUnmapViewOfSectionHook, reinterpret_cast<void*>(&hookedNtUnmapViewOfSection), reinterpret_cast<void**>(&gNtUnmapViewOfSectionOriginal) },
            { L"ntdll.dll", "NtDuplicateObject", ks::winapi_monitor::EventCategory::kProcess, &gNtDuplicateObjectHook, reinterpret_cast<void*>(&hookedNtDuplicateObject), reinterpret_cast<void**>(&gNtDuplicateObjectOriginal) },
            { L"ntdll.dll", "NtQueryInformationProcess", ks::winapi_monitor::EventCategory::kProcess, &gNtQueryInformationProcessHook, reinterpret_cast<void*>(&hookedNtQueryInformationProcess), reinterpret_cast<void**>(&gNtQueryInformationProcessOriginal) },
            { L"ntdll.dll", "NtSetInformationProcess", ks::winapi_monitor::EventCategory::kProcess, &gNtSetInformationProcessHook, reinterpret_cast<void*>(&hookedNtSetInformationProcess), reinterpret_cast<void**>(&gNtSetInformationProcessOriginal) },
            { L"ntdll.dll", "NtQueryVirtualMemory", ks::winapi_monitor::EventCategory::kProcess, &gNtQueryVirtualMemoryHook, reinterpret_cast<void*>(&hookedNtQueryVirtualMemory), reinterpret_cast<void**>(&gNtQueryVirtualMemoryOriginal) },
            { L"ntdll.dll", "NtCreateSection", ks::winapi_monitor::EventCategory::kProcess, &gNtCreateSectionHook, reinterpret_cast<void*>(&hookedNtCreateSection), reinterpret_cast<void**>(&gNtCreateSectionOriginal) },
            { L"ntdll.dll", "NtOpenSection", ks::winapi_monitor::EventCategory::kProcess, &gNtOpenSectionHook, reinterpret_cast<void*>(&hookedNtOpenSection), reinterpret_cast<void**>(&gNtOpenSectionOriginal) },
            { L"ntdll.dll", "NtQueueApcThread", ks::winapi_monitor::EventCategory::kProcess, &gNtQueueApcThreadHook, reinterpret_cast<void*>(&hookedNtQueueApcThread), reinterpret_cast<void**>(&gNtQueueApcThreadOriginal) },
            { L"ntdll.dll", "NtQueueApcThreadEx", ks::winapi_monitor::EventCategory::kProcess, &gNtQueueApcThreadExHook, reinterpret_cast<void*>(&hookedNtQueueApcThreadEx), reinterpret_cast<void**>(&gNtQueueApcThreadExOriginal) },
            { L"ntdll.dll", "NtSuspendThread", ks::winapi_monitor::EventCategory::kProcess, &gNtSuspendThreadHook, reinterpret_cast<void*>(&hookedNtSuspendThread), reinterpret_cast<void**>(&gNtSuspendThreadOriginal) },
            { L"ntdll.dll", "NtResumeThread", ks::winapi_monitor::EventCategory::kProcess, &gNtResumeThreadHook, reinterpret_cast<void*>(&hookedNtResumeThread), reinterpret_cast<void**>(&gNtResumeThreadOriginal) },
            { L"ntdll.dll", "NtGetContextThread", ks::winapi_monitor::EventCategory::kProcess, &gNtGetContextThreadHook, reinterpret_cast<void*>(&hookedNtGetContextThread), reinterpret_cast<void**>(&gNtGetContextThreadOriginal) },
            { L"ntdll.dll", "NtSetContextThread", ks::winapi_monitor::EventCategory::kProcess, &gNtSetContextThreadHook, reinterpret_cast<void*>(&hookedNtSetContextThread), reinterpret_cast<void**>(&gNtSetContextThreadOriginal) },
            { L"ntdll.dll", "NtClose", ks::winapi_monitor::EventCategory::kProcess, &gNtCloseHook, reinterpret_cast<void*>(&HookedNtClose), reinterpret_cast<void**>(&gNtCloseOriginal) },
            { L"Ws2_32.dll", "socket", ks::winapi_monitor::EventCategory::kNetwork, &gSocketHook, reinterpret_cast<void*>(&hookedSocket), reinterpret_cast<void**>(&gSocketOriginal) },
            { L"Ws2_32.dll", "WSASocketW", ks::winapi_monitor::EventCategory::kNetwork, &gWsaSocketWHook, reinterpret_cast<void*>(&hookedWsaSocketW), reinterpret_cast<void**>(&gWsaSocketWOriginal) },
            { L"Ws2_32.dll", "WSASocketA", ks::winapi_monitor::EventCategory::kNetwork, &gWsaSocketAHook, reinterpret_cast<void*>(&hookedWsaSocketA), reinterpret_cast<void**>(&gWsaSocketAOriginal) },
            { L"Ws2_32.dll", "closesocket", ks::winapi_monitor::EventCategory::kNetwork, &gCloseSocketHook, reinterpret_cast<void*>(&hookedCloseSocket), reinterpret_cast<void**>(&gCloseSocketOriginal) },
            { L"Ws2_32.dll", "shutdown", ks::winapi_monitor::EventCategory::kNetwork, &gShutdownHook, reinterpret_cast<void*>(&hookedShutdown), reinterpret_cast<void**>(&gShutdownOriginal) },
            { L"Ws2_32.dll", "connect", ks::winapi_monitor::EventCategory::kNetwork, &gConnectHook, reinterpret_cast<void*>(&hookedConnect), reinterpret_cast<void**>(&gConnectOriginal) },
            { L"Ws2_32.dll", "WSAConnect", ks::winapi_monitor::EventCategory::kNetwork, &gWsaConnectHook, reinterpret_cast<void*>(&hookedWsaConnect), reinterpret_cast<void**>(&gWsaConnectOriginal) },
            { L"Ws2_32.dll", "send", ks::winapi_monitor::EventCategory::kNetwork, &gSendHook, reinterpret_cast<void*>(&hookedSend), reinterpret_cast<void**>(&gSendOriginal) },
            { L"Ws2_32.dll", "WSASend", ks::winapi_monitor::EventCategory::kNetwork, &gWsaSendHook, reinterpret_cast<void*>(&hookedWsaSend), reinterpret_cast<void**>(&gWsaSendOriginal) },
            { L"Ws2_32.dll", "sendto", ks::winapi_monitor::EventCategory::kNetwork, &gSendToHook, reinterpret_cast<void*>(&hookedSendTo), reinterpret_cast<void**>(&gSendToOriginal) },
            { L"Ws2_32.dll", "recv", ks::winapi_monitor::EventCategory::kNetwork, &gRecvHook, reinterpret_cast<void*>(&hookedRecv), reinterpret_cast<void**>(&gRecvOriginal) },
            { L"Ws2_32.dll", "WSARecv", ks::winapi_monitor::EventCategory::kNetwork, &gWsaRecvHook, reinterpret_cast<void*>(&hookedWsaRecv), reinterpret_cast<void**>(&gWsaRecvOriginal) },
            { L"Ws2_32.dll", "recvfrom", ks::winapi_monitor::EventCategory::kNetwork, &gRecvFromHook, reinterpret_cast<void*>(&hookedRecvFrom), reinterpret_cast<void**>(&gRecvFromOriginal) },
            { L"Ws2_32.dll", "bind", ks::winapi_monitor::EventCategory::kNetwork, &gBindHook, reinterpret_cast<void*>(&hookedBind), reinterpret_cast<void**>(&gBindOriginal) },
            { L"Ws2_32.dll", "listen", ks::winapi_monitor::EventCategory::kNetwork, &gListenHook, reinterpret_cast<void*>(&hookedListen), reinterpret_cast<void**>(&gListenOriginal) },
            { L"Ws2_32.dll", "accept", ks::winapi_monitor::EventCategory::kNetwork, &gAcceptHook, reinterpret_cast<void*>(&hookedAccept), reinterpret_cast<void**>(&gAcceptOriginal) },
            { L"Ws2_32.dll", "WSAIoctl", ks::winapi_monitor::EventCategory::kNetwork, &gWsaIoctlHook, reinterpret_cast<void*>(&HookedWSAIoctl), reinterpret_cast<void**>(&gWsaIoctlOriginal) },
            { L"Ws2_32.dll", "WSASendTo", ks::winapi_monitor::EventCategory::kNetwork, &gWsaSendToHook, reinterpret_cast<void*>(&HookedWSASendTo), reinterpret_cast<void**>(&gWsaSendToOriginal) },
            { L"Ws2_32.dll", "WSARecvFrom", ks::winapi_monitor::EventCategory::kNetwork, &gWsaRecvFromHook, reinterpret_cast<void*>(&HookedWSARecvFrom), reinterpret_cast<void**>(&gWsaRecvFromOriginal) },
            { L"Ws2_32.dll", "GetAddrInfoW", ks::winapi_monitor::EventCategory::kNetwork, &gGetAddrInfoWHook, reinterpret_cast<void*>(&HookedGetAddrInfoW), reinterpret_cast<void**>(&gGetAddrInfoWOriginal) },
            { L"Ws2_32.dll", "getaddrinfo", ks::winapi_monitor::EventCategory::kNetwork, &gGetAddrInfoAHook, reinterpret_cast<void*>(&HookedGetAddrInfoA), reinterpret_cast<void**>(&gGetAddrInfoAOriginal) },
            { L"Dnsapi.dll", "DnsQuery_W", ks::winapi_monitor::EventCategory::kNetwork, &gDnsQueryWHook, reinterpret_cast<void*>(&hookedDnsQueryW), reinterpret_cast<void**>(&gDnsQueryWOriginal) },
            { L"Dnsapi.dll", "DnsQuery_A", ks::winapi_monitor::EventCategory::kNetwork, &gDnsQueryAHook, reinterpret_cast<void*>(&hookedDnsQueryA), reinterpret_cast<void**>(&gDnsQueryAOriginal) },
            { L"Winhttp.dll", "WinHttpOpen", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpOpenHook, reinterpret_cast<void*>(&HookedWinHttpOpen), reinterpret_cast<void**>(&gWinHttpOpenOriginal) },
            { L"Winhttp.dll", "WinHttpConnect", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpConnectHook, reinterpret_cast<void*>(&HookedWinHttpConnect), reinterpret_cast<void**>(&gWinHttpConnectOriginal) },
            { L"Winhttp.dll", "WinHttpOpenRequest", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpOpenRequestHook, reinterpret_cast<void*>(&HookedWinHttpOpenRequest), reinterpret_cast<void**>(&gWinHttpOpenRequestOriginal) },
            { L"Winhttp.dll", "WinHttpSendRequest", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpSendRequestHook, reinterpret_cast<void*>(&HookedWinHttpSendRequest), reinterpret_cast<void**>(&gWinHttpSendRequestOriginal) },
            { L"Winhttp.dll", "WinHttpReceiveResponse", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpReceiveResponseHook, reinterpret_cast<void*>(&HookedWinHttpReceiveResponse), reinterpret_cast<void**>(&gWinHttpReceiveResponseOriginal) },
            { L"Winhttp.dll", "WinHttpReadData", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpReadDataHook, reinterpret_cast<void*>(&HookedWinHttpReadData), reinterpret_cast<void**>(&gWinHttpReadDataOriginal) },
            { L"Winhttp.dll", "WinHttpWriteData", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpWriteDataHook, reinterpret_cast<void*>(&HookedWinHttpWriteData), reinterpret_cast<void**>(&gWinHttpWriteDataOriginal) },
            { L"Winhttp.dll", "WinHttpQueryHeaders", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpQueryHeadersHook, reinterpret_cast<void*>(&HookedWinHttpQueryHeaders), reinterpret_cast<void**>(&gWinHttpQueryHeadersOriginal) },
            { L"Winhttp.dll", "WinHttpQueryDataAvailable", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpQueryDataAvailableHook, reinterpret_cast<void*>(&HookedWinHttpQueryDataAvailable), reinterpret_cast<void**>(&gWinHttpQueryDataAvailableOriginal) },
            { L"Winhttp.dll", "WinHttpSetOption", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpSetOptionHook, reinterpret_cast<void*>(&HookedWinHttpSetOption), reinterpret_cast<void**>(&gWinHttpSetOptionOriginal) },
            { L"Winhttp.dll", "WinHttpCloseHandle", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpCloseHandleHook, reinterpret_cast<void*>(&HookedWinHttpCloseHandle), reinterpret_cast<void**>(&gWinHttpCloseHandleOriginal) },
            { L"Wininet.dll", "InternetOpenW", ks::winapi_monitor::EventCategory::kNetwork, &gInternetOpenWHook, reinterpret_cast<void*>(&HookedInternetOpenW), reinterpret_cast<void**>(&gInternetOpenWOriginal) },
            { L"Wininet.dll", "InternetOpenA", ks::winapi_monitor::EventCategory::kNetwork, &gInternetOpenAHook, reinterpret_cast<void*>(&HookedInternetOpenA), reinterpret_cast<void**>(&gInternetOpenAOriginal) },
            { L"Wininet.dll", "InternetConnectW", ks::winapi_monitor::EventCategory::kNetwork, &gInternetConnectWHook, reinterpret_cast<void*>(&HookedInternetConnectW), reinterpret_cast<void**>(&gInternetConnectWOriginal) },
            { L"Wininet.dll", "InternetConnectA", ks::winapi_monitor::EventCategory::kNetwork, &gInternetConnectAHook, reinterpret_cast<void*>(&HookedInternetConnectA), reinterpret_cast<void**>(&gInternetConnectAOriginal) },
            { L"Wininet.dll", "HttpOpenRequestW", ks::winapi_monitor::EventCategory::kNetwork, &gHttpOpenRequestWHook, reinterpret_cast<void*>(&HookedHttpOpenRequestW), reinterpret_cast<void**>(&gHttpOpenRequestWOriginal) },
            { L"Wininet.dll", "HttpOpenRequestA", ks::winapi_monitor::EventCategory::kNetwork, &gHttpOpenRequestAHook, reinterpret_cast<void*>(&HookedHttpOpenRequestA), reinterpret_cast<void**>(&gHttpOpenRequestAOriginal) },
            { L"Wininet.dll", "HttpSendRequestW", ks::winapi_monitor::EventCategory::kNetwork, &gHttpSendRequestWHook, reinterpret_cast<void*>(&HookedHttpSendRequestW), reinterpret_cast<void**>(&gHttpSendRequestWOriginal) },
            { L"Wininet.dll", "HttpSendRequestA", ks::winapi_monitor::EventCategory::kNetwork, &gHttpSendRequestAHook, reinterpret_cast<void*>(&HookedHttpSendRequestA), reinterpret_cast<void**>(&gHttpSendRequestAOriginal) },
            { L"Wininet.dll", "InternetReadFile", ks::winapi_monitor::EventCategory::kNetwork, &gInternetReadFileHook, reinterpret_cast<void*>(&HookedInternetReadFile), reinterpret_cast<void**>(&gInternetReadFileOriginal) },
            { L"Wininet.dll", "InternetWriteFile", ks::winapi_monitor::EventCategory::kNetwork, &gInternetWriteFileHook, reinterpret_cast<void*>(&HookedInternetWriteFile), reinterpret_cast<void**>(&gInternetWriteFileOriginal) },
            { L"Wininet.dll", "InternetOpenUrlW", ks::winapi_monitor::EventCategory::kNetwork, &gInternetOpenUrlWHook, reinterpret_cast<void*>(&HookedInternetOpenUrlW), reinterpret_cast<void**>(&gInternetOpenUrlWOriginal) },
            { L"Wininet.dll", "InternetOpenUrlA", ks::winapi_monitor::EventCategory::kNetwork, &gInternetOpenUrlAHook, reinterpret_cast<void*>(&HookedInternetOpenUrlA), reinterpret_cast<void**>(&gInternetOpenUrlAOriginal) },
            { L"Wininet.dll", "InternetQueryDataAvailable", ks::winapi_monitor::EventCategory::kNetwork, &gInternetQueryDataAvailableHook, reinterpret_cast<void*>(&HookedInternetQueryDataAvailable), reinterpret_cast<void**>(&gInternetQueryDataAvailableOriginal) },
            { L"Wininet.dll", "InternetSetOptionW", ks::winapi_monitor::EventCategory::kNetwork, &gInternetSetOptionWHook, reinterpret_cast<void*>(&HookedInternetSetOptionW), reinterpret_cast<void**>(&gInternetSetOptionWOriginal) },
            { L"Wininet.dll", "InternetSetOptionA", ks::winapi_monitor::EventCategory::kNetwork, &gInternetSetOptionAHook, reinterpret_cast<void*>(&HookedInternetSetOptionA), reinterpret_cast<void**>(&gInternetSetOptionAOriginal) },
            { L"Wininet.dll", "InternetCrackUrlW", ks::winapi_monitor::EventCategory::kNetwork, &gInternetCrackUrlWHook, reinterpret_cast<void*>(&HookedInternetCrackUrlW), reinterpret_cast<void**>(&gInternetCrackUrlWOriginal) },
            { L"Wininet.dll", "InternetCrackUrlA", ks::winapi_monitor::EventCategory::kNetwork, &gInternetCrackUrlAHook, reinterpret_cast<void*>(&HookedInternetCrackUrlA), reinterpret_cast<void**>(&gInternetCrackUrlAOriginal) },
            { L"Wininet.dll", "InternetCloseHandle", ks::winapi_monitor::EventCategory::kNetwork, &gInternetCloseHandleHook, reinterpret_cast<void*>(&HookedInternetCloseHandle), reinterpret_cast<void**>(&gInternetCloseHandleOriginal) },
            { L"Urlmon.dll", "URLDownloadToFileW", ks::winapi_monitor::EventCategory::kNetwork, &gUrlDownloadToFileWHook, reinterpret_cast<void*>(&hookedUrlDownloadToFileW), reinterpret_cast<void**>(&gUrlDownloadToFileWOriginal) },
            { L"Urlmon.dll", "URLDownloadToFileA", ks::winapi_monitor::EventCategory::kNetwork, &gUrlDownloadToFileAHook, reinterpret_cast<void*>(&hookedUrlDownloadToFileA), reinterpret_cast<void**>(&gUrlDownloadToFileAOriginal) },
            { L"Bcrypt.dll", "BCryptOpenAlgorithmProvider", ks::winapi_monitor::EventCategory::kProcess, &gBCryptOpenAlgorithmProviderHook, reinterpret_cast<void*>(&HookedBCryptOpenAlgorithmProvider), reinterpret_cast<void**>(&gBCryptOpenAlgorithmProviderOriginal) },
            { L"Bcrypt.dll", "BCryptCreateHash", ks::winapi_monitor::EventCategory::kProcess, &gBCryptCreateHashHook, reinterpret_cast<void*>(&HookedBCryptCreateHash), reinterpret_cast<void**>(&gBCryptCreateHashOriginal) },
            { L"Bcrypt.dll", "BCryptHashData", ks::winapi_monitor::EventCategory::kProcess, &gBCryptHashDataHook, reinterpret_cast<void*>(&HookedBCryptHashData), reinterpret_cast<void**>(&gBCryptHashDataOriginal) },
            { L"Bcrypt.dll", "BCryptFinishHash", ks::winapi_monitor::EventCategory::kProcess, &gBCryptFinishHashHook, reinterpret_cast<void*>(&HookedBCryptFinishHash), reinterpret_cast<void**>(&gBCryptFinishHashOriginal) },
            { L"Bcrypt.dll", "BCryptEncrypt", ks::winapi_monitor::EventCategory::kProcess, &gBCryptEncryptHook, reinterpret_cast<void*>(&HookedBCryptEncrypt), reinterpret_cast<void**>(&gBCryptEncryptOriginal) },
            { L"Bcrypt.dll", "BCryptDecrypt", ks::winapi_monitor::EventCategory::kProcess, &gBCryptDecryptHook, reinterpret_cast<void*>(&HookedBCryptDecrypt), reinterpret_cast<void**>(&gBCryptDecryptOriginal) },
            { L"Bcrypt.dll", "BCryptGenRandom", ks::winapi_monitor::EventCategory::kProcess, &gBCryptGenRandomHook, reinterpret_cast<void*>(&HookedBCryptGenRandom), reinterpret_cast<void**>(&gBCryptGenRandomOriginal) },
            { L"Bcrypt.dll", "BCryptCloseAlgorithmProvider", ks::winapi_monitor::EventCategory::kProcess, &gBCryptCloseAlgorithmProviderHook, reinterpret_cast<void*>(&HookedBCryptCloseAlgorithmProvider), reinterpret_cast<void**>(&gBCryptCloseAlgorithmProviderOriginal) },
            { L"Bcrypt.dll", "BCryptDestroyHash", ks::winapi_monitor::EventCategory::kProcess, &gBCryptDestroyHashHook, reinterpret_cast<void*>(&HookedBCryptDestroyHash), reinterpret_cast<void**>(&gBCryptDestroyHashOriginal) },
            { L"Bcrypt.dll", "BCryptGenerateSymmetricKey", ks::winapi_monitor::EventCategory::kProcess, &gBCryptGenerateSymmetricKeyHook, reinterpret_cast<void*>(&HookedBCryptGenerateSymmetricKey), reinterpret_cast<void**>(&gBCryptGenerateSymmetricKeyOriginal) },
            { L"Bcrypt.dll", "BCryptImportKey", ks::winapi_monitor::EventCategory::kProcess, &gBCryptImportKeyHook, reinterpret_cast<void*>(&HookedBCryptImportKey), reinterpret_cast<void**>(&gBCryptImportKeyOriginal) },
            { L"Bcrypt.dll", "BCryptImportKeyPair", ks::winapi_monitor::EventCategory::kProcess, &gBCryptImportKeyPairHook, reinterpret_cast<void*>(&HookedBCryptImportKeyPair), reinterpret_cast<void**>(&gBCryptImportKeyPairOriginal) },
            { L"Bcrypt.dll", "BCryptDestroyKey", ks::winapi_monitor::EventCategory::kProcess, &gBCryptDestroyKeyHook, reinterpret_cast<void*>(&HookedBCryptDestroyKey), reinterpret_cast<void**>(&gBCryptDestroyKeyOriginal) },
            { L"Ole32.dll", "CoInitializeEx", ks::winapi_monitor::EventCategory::kProcess, &gCoInitializeExHook, reinterpret_cast<void*>(&HookedCoInitializeEx), reinterpret_cast<void**>(&gCoInitializeExOriginal) },
            { L"Ole32.dll", "CoInitializeSecurity", ks::winapi_monitor::EventCategory::kProcess, &gCoInitializeSecurityHook, reinterpret_cast<void*>(&HookedCoInitializeSecurity), reinterpret_cast<void**>(&gCoInitializeSecurityOriginal) },
            { L"Ole32.dll", "CoUninitialize", ks::winapi_monitor::EventCategory::kProcess, &gCoUninitializeHook, reinterpret_cast<void*>(&hookedCoUninitialize), reinterpret_cast<void**>(&gCoUninitializeOriginal) },
            { L"Ole32.dll", "CoCreateInstance", ks::winapi_monitor::EventCategory::kProcess, &gCoCreateInstanceHook, reinterpret_cast<void*>(&HookedCoCreateInstance), reinterpret_cast<void**>(&gCoCreateInstanceOriginal) },
            { L"Ole32.dll", "CoCreateInstanceEx", ks::winapi_monitor::EventCategory::kProcess, &gCoCreateInstanceExHook, reinterpret_cast<void*>(&HookedCoCreateInstanceEx), reinterpret_cast<void**>(&gCoCreateInstanceExOriginal) },
            { L"Ole32.dll", "CoGetClassObject", ks::winapi_monitor::EventCategory::kProcess, &gCoGetClassObjectHook, reinterpret_cast<void*>(&HookedCoGetClassObject), reinterpret_cast<void**>(&gCoGetClassObjectOriginal) },
            { L"User32.dll", "SetWindowsHookExW", ks::winapi_monitor::EventCategory::kProcess, &gSetWindowsHookExWHook, reinterpret_cast<void*>(&HookedSetWindowsHookExW), reinterpret_cast<void**>(&gSetWindowsHookExWOriginal) },
            { L"User32.dll", "SetWindowsHookExA", ks::winapi_monitor::EventCategory::kProcess, &gSetWindowsHookExAHook, reinterpret_cast<void*>(&HookedSetWindowsHookExA), reinterpret_cast<void**>(&gSetWindowsHookExAOriginal) },
            { L"User32.dll", "UnhookWindowsHookEx", ks::winapi_monitor::EventCategory::kProcess, &gUnhookWindowsHookExHook, reinterpret_cast<void*>(&HookedUnhookWindowsHookEx), reinterpret_cast<void**>(&gUnhookWindowsHookExOriginal) },
            { L"Psapi.dll", "EnumProcesses", ks::winapi_monitor::EventCategory::kProcess, &gEnumProcessesHook, reinterpret_cast<void*>(&HookedEnumProcesses), reinterpret_cast<void**>(&gEnumProcessesOriginal) },
            { L"Psapi.dll", "EnumProcessModules", ks::winapi_monitor::EventCategory::kLoader, &gEnumProcessModulesHook, reinterpret_cast<void*>(&HookedEnumProcessModules), reinterpret_cast<void**>(&gEnumProcessModulesOriginal) },
            { L"Psapi.dll", "EnumProcessModulesEx", ks::winapi_monitor::EventCategory::kLoader, &gEnumProcessModulesExHook, reinterpret_cast<void*>(&HookedEnumProcessModulesEx), reinterpret_cast<void**>(&gEnumProcessModulesExOriginal) },
            { L"Psapi.dll", "GetMappedFileNameW", ks::winapi_monitor::EventCategory::kLoader, &gGetMappedFileNameWHook, reinterpret_cast<void*>(&HookedGetMappedFileNameW), reinterpret_cast<void**>(&gGetMappedFileNameWOriginal) },
            { L"Psapi.dll", "GetMappedFileNameA", ks::winapi_monitor::EventCategory::kLoader, &gGetMappedFileNameAHook, reinterpret_cast<void*>(&HookedGetMappedFileNameA), reinterpret_cast<void**>(&gGetMappedFileNameAOriginal) },
            { L"User32.dll", "EnumWindows", ks::winapi_monitor::EventCategory::kProcess, &gEnumWindowsHook, reinterpret_cast<void*>(&HookedEnumWindows), reinterpret_cast<void**>(&gEnumWindowsOriginal) },
            { L"User32.dll", "EnumChildWindows", ks::winapi_monitor::EventCategory::kProcess, &gEnumChildWindowsHook, reinterpret_cast<void*>(&HookedEnumChildWindows), reinterpret_cast<void**>(&gEnumChildWindowsOriginal) },
            { L"User32.dll", "FindWindowW", ks::winapi_monitor::EventCategory::kProcess, &gFindWindowWHook, reinterpret_cast<void*>(&HookedFindWindowW), reinterpret_cast<void**>(&gFindWindowWOriginal) },
            { L"User32.dll", "FindWindowA", ks::winapi_monitor::EventCategory::kProcess, &gFindWindowAHook, reinterpret_cast<void*>(&HookedFindWindowA), reinterpret_cast<void**>(&gFindWindowAOriginal) },
            { L"User32.dll", "FindWindowExW", ks::winapi_monitor::EventCategory::kProcess, &gFindWindowExWHook, reinterpret_cast<void*>(&HookedFindWindowExW), reinterpret_cast<void**>(&gFindWindowExWOriginal) },
            { L"User32.dll", "FindWindowExA", ks::winapi_monitor::EventCategory::kProcess, &gFindWindowExAHook, reinterpret_cast<void*>(&HookedFindWindowExA), reinterpret_cast<void**>(&gFindWindowExAOriginal) },
            { L"User32.dll", "GetWindowThreadProcessId", ks::winapi_monitor::EventCategory::kProcess, &gGetWindowThreadProcessIdHook, reinterpret_cast<void*>(&HookedGetWindowThreadProcessId), reinterpret_cast<void**>(&gGetWindowThreadProcessIdOriginal) },
            { L"User32.dll", "GetForegroundWindow", ks::winapi_monitor::EventCategory::kProcess, &gGetForegroundWindowHook, reinterpret_cast<void*>(&HookedGetForegroundWindow), reinterpret_cast<void**>(&gGetForegroundWindowOriginal) },
            { L"User32.dll", "GetDC", ks::winapi_monitor::EventCategory::kProcess, &gGetDcHook, reinterpret_cast<void*>(&HookedGetDC), reinterpret_cast<void**>(&gGetDcOriginal) },
            { L"User32.dll", "ReleaseDC", ks::winapi_monitor::EventCategory::kProcess, &gReleaseDcHook, reinterpret_cast<void*>(&HookedReleaseDC), reinterpret_cast<void**>(&gReleaseDcOriginal) },
            { L"User32.dll", "OpenClipboard", ks::winapi_monitor::EventCategory::kProcess, &gOpenClipboardHook, reinterpret_cast<void*>(&HookedOpenClipboard), reinterpret_cast<void**>(&gOpenClipboardOriginal) },
            { L"User32.dll", "CloseClipboard", ks::winapi_monitor::EventCategory::kProcess, &gCloseClipboardHook, reinterpret_cast<void*>(&HookedCloseClipboard), reinterpret_cast<void**>(&gCloseClipboardOriginal) },
            { L"User32.dll", "GetClipboardData", ks::winapi_monitor::EventCategory::kProcess, &gGetClipboardDataHook, reinterpret_cast<void*>(&HookedGetClipboardData), reinterpret_cast<void**>(&gGetClipboardDataOriginal) },
            { L"User32.dll", "SetClipboardData", ks::winapi_monitor::EventCategory::kProcess, &gSetClipboardDataHook, reinterpret_cast<void*>(&HookedSetClipboardData), reinterpret_cast<void**>(&gSetClipboardDataOriginal) },
            { L"User32.dll", "EmptyClipboard", ks::winapi_monitor::EventCategory::kProcess, &gEmptyClipboardHook, reinterpret_cast<void*>(&HookedEmptyClipboard), reinterpret_cast<void**>(&gEmptyClipboardOriginal) },
            { L"Gdi32.dll", "CreateCompatibleDC", ks::winapi_monitor::EventCategory::kProcess, &gCreateCompatibleDcHook, reinterpret_cast<void*>(&HookedCreateCompatibleDC), reinterpret_cast<void**>(&gCreateCompatibleDcOriginal) },
            { L"Gdi32.dll", "DeleteDC", ks::winapi_monitor::EventCategory::kProcess, &gDeleteDcHook, reinterpret_cast<void*>(&HookedDeleteDC), reinterpret_cast<void**>(&gDeleteDcOriginal) },
            { L"Gdi32.dll", "CreateCompatibleBitmap", ks::winapi_monitor::EventCategory::kProcess, &gCreateCompatibleBitmapHook, reinterpret_cast<void*>(&HookedCreateCompatibleBitmap), reinterpret_cast<void**>(&gCreateCompatibleBitmapOriginal) },
            { L"Gdi32.dll", "BitBlt", ks::winapi_monitor::EventCategory::kProcess, &gBitBltHook, reinterpret_cast<void*>(&HookedBitBlt), reinterpret_cast<void**>(&gBitBltOriginal) },
            { L"Gdi32.dll", "StretchBlt", ks::winapi_monitor::EventCategory::kProcess, &gStretchBltHook, reinterpret_cast<void*>(&HookedStretchBlt), reinterpret_cast<void**>(&gStretchBltOriginal) },
            { L"Gdi32.dll", "DeleteObject", ks::winapi_monitor::EventCategory::kProcess, &gDeleteObjectHook, reinterpret_cast<void*>(&HookedDeleteObject), reinterpret_cast<void**>(&gDeleteObjectOriginal) },
            { L"Advapi32.dll", "StartTraceW", ks::winapi_monitor::EventCategory::kProcess, &gStartTraceWHook, reinterpret_cast<void*>(&HookedStartTraceW), reinterpret_cast<void**>(&gStartTraceWOriginal) },
            { L"Advapi32.dll", "StartTraceA", ks::winapi_monitor::EventCategory::kProcess, &gStartTraceAHook, reinterpret_cast<void*>(&HookedStartTraceA), reinterpret_cast<void**>(&gStartTraceAOriginal) },
            { L"Advapi32.dll", "ControlTraceW", ks::winapi_monitor::EventCategory::kProcess, &gControlTraceWHook, reinterpret_cast<void*>(&HookedControlTraceW), reinterpret_cast<void**>(&gControlTraceWOriginal) },
            { L"Advapi32.dll", "ControlTraceA", ks::winapi_monitor::EventCategory::kProcess, &gControlTraceAHook, reinterpret_cast<void*>(&HookedControlTraceA), reinterpret_cast<void**>(&gControlTraceAOriginal) },
            { L"Advapi32.dll", "EnableTraceEx2", ks::winapi_monitor::EventCategory::kProcess, &gEnableTraceEx2Hook, reinterpret_cast<void*>(&HookedEnableTraceEx2), reinterpret_cast<void**>(&gEnableTraceEx2Original) },
            { L"Advapi32.dll", "OpenTraceW", ks::winapi_monitor::EventCategory::kProcess, &gOpenTraceWHook, reinterpret_cast<void*>(&hookedOpenTraceW), reinterpret_cast<void**>(&gOpenTraceWOriginal) },
            { L"Advapi32.dll", "OpenTraceA", ks::winapi_monitor::EventCategory::kProcess, &gOpenTraceAHook, reinterpret_cast<void*>(&hookedOpenTraceA), reinterpret_cast<void**>(&gOpenTraceAOriginal) },
            { L"Advapi32.dll", "ProcessTrace", ks::winapi_monitor::EventCategory::kProcess, &gProcessTraceHook, reinterpret_cast<void*>(&HookedProcessTrace), reinterpret_cast<void**>(&gProcessTraceOriginal) },
            { L"Advapi32.dll", "CloseTrace", ks::winapi_monitor::EventCategory::kProcess, &gCloseTraceHook, reinterpret_cast<void*>(&HookedCloseTrace), reinterpret_cast<void**>(&gCloseTraceOriginal) },
            { L"Advapi32.dll", "EventRegister", ks::winapi_monitor::EventCategory::kProcess, &gEventRegisterHook, reinterpret_cast<void*>(&HookedEventRegister), reinterpret_cast<void**>(&gEventRegisterOriginal) },
            { L"Advapi32.dll", "EventUnregister", ks::winapi_monitor::EventCategory::kProcess, &gEventUnregisterHook, reinterpret_cast<void*>(&HookedEventUnregister), reinterpret_cast<void**>(&gEventUnregisterOriginal) },
            { L"Advapi32.dll", "EventWrite", ks::winapi_monitor::EventCategory::kProcess, &gEventWriteHook, reinterpret_cast<void*>(&HookedEventWrite), reinterpret_cast<void**>(&gEventWriteOriginal) },
            { L"Advapi32.dll", "EventWriteEx", ks::winapi_monitor::EventCategory::kProcess, &gEventWriteExHook, reinterpret_cast<void*>(&HookedEventWriteEx), reinterpret_cast<void**>(&gEventWriteExOriginal) },
            { L"Wintrust.dll", "WinVerifyTrust", ks::winapi_monitor::EventCategory::kProcess, &gWinVerifyTrustHook, reinterpret_cast<void*>(&HookedWinVerifyTrust), reinterpret_cast<void**>(&gWinVerifyTrustOriginal) },
            { L"Crypt32.dll", "CryptQueryObject", ks::winapi_monitor::EventCategory::kProcess, &gCryptQueryObjectHook, reinterpret_cast<void*>(&HookedCryptQueryObject), reinterpret_cast<void**>(&gCryptQueryObjectOriginal) },
            { L"Crypt32.dll", "CertOpenStore", ks::winapi_monitor::EventCategory::kProcess, &gCertOpenStoreHook, reinterpret_cast<void*>(&HookedCertOpenStore), reinterpret_cast<void**>(&gCertOpenStoreOriginal) },
            { L"Crypt32.dll", "CertCloseStore", ks::winapi_monitor::EventCategory::kProcess, &gCertCloseStoreHook, reinterpret_cast<void*>(&HookedCertCloseStore), reinterpret_cast<void**>(&gCertCloseStoreOriginal) },
            { L"Crypt32.dll", "CertFindCertificateInStore", ks::winapi_monitor::EventCategory::kProcess, &gCertFindCertificateInStoreHook, reinterpret_cast<void*>(&HookedCertFindCertificateInStore), reinterpret_cast<void**>(&gCertFindCertificateInStoreOriginal) },
            { L"Crypt32.dll", "CertGetCertificateChain", ks::winapi_monitor::EventCategory::kProcess, &gCertGetCertificateChainHook, reinterpret_cast<void*>(&HookedCertGetCertificateChain), reinterpret_cast<void**>(&gCertGetCertificateChainOriginal) },
            { L"Crypt32.dll", "CertVerifyCertificateChainPolicy", ks::winapi_monitor::EventCategory::kProcess, &gCertVerifyCertificateChainPolicyHook, reinterpret_cast<void*>(&HookedCertVerifyCertificateChainPolicy), reinterpret_cast<void**>(&gCertVerifyCertificateChainPolicyOriginal) },
            { L"Crypt32.dll", "CryptProtectData", ks::winapi_monitor::EventCategory::kProcess, &gCryptProtectDataHook, reinterpret_cast<void*>(&HookedCryptProtectData), reinterpret_cast<void**>(&gCryptProtectDataOriginal) },
            { L"Crypt32.dll", "CryptUnprotectData", ks::winapi_monitor::EventCategory::kProcess, &gCryptUnprotectDataHook, reinterpret_cast<void*>(&HookedCryptUnprotectData), reinterpret_cast<void**>(&gCryptUnprotectDataOriginal) },
            { L"Ncrypt.dll", "NCryptOpenStorageProvider", ks::winapi_monitor::EventCategory::kProcess, &gNCryptOpenStorageProviderHook, reinterpret_cast<void*>(&HookedNCryptOpenStorageProvider), reinterpret_cast<void**>(&gNCryptOpenStorageProviderOriginal) },
            { L"Ncrypt.dll", "NCryptOpenKey", ks::winapi_monitor::EventCategory::kProcess, &gNCryptOpenKeyHook, reinterpret_cast<void*>(&HookedNCryptOpenKey), reinterpret_cast<void**>(&gNCryptOpenKeyOriginal) },
            { L"Ncrypt.dll", "NCryptCreatePersistedKey", ks::winapi_monitor::EventCategory::kProcess, &gNCryptCreatePersistedKeyHook, reinterpret_cast<void*>(&HookedNCryptCreatePersistedKey), reinterpret_cast<void**>(&gNCryptCreatePersistedKeyOriginal) },
            { L"Ncrypt.dll", "NCryptFinalizeKey", ks::winapi_monitor::EventCategory::kProcess, &gNCryptFinalizeKeyHook, reinterpret_cast<void*>(&HookedNCryptFinalizeKey), reinterpret_cast<void**>(&gNCryptFinalizeKeyOriginal) },
            { L"Ncrypt.dll", "NCryptEncrypt", ks::winapi_monitor::EventCategory::kProcess, &gNCryptEncryptHook, reinterpret_cast<void*>(&HookedNCryptEncrypt), reinterpret_cast<void**>(&gNCryptEncryptOriginal) },
            { L"Ncrypt.dll", "NCryptDecrypt", ks::winapi_monitor::EventCategory::kProcess, &gNCryptDecryptHook, reinterpret_cast<void*>(&HookedNCryptDecrypt), reinterpret_cast<void**>(&gNCryptDecryptOriginal) },
            { L"Ncrypt.dll", "NCryptSignHash", ks::winapi_monitor::EventCategory::kProcess, &gNCryptSignHashHook, reinterpret_cast<void*>(&HookedNCryptSignHash), reinterpret_cast<void**>(&gNCryptSignHashOriginal) },
            { L"Ncrypt.dll", "NCryptVerifySignature", ks::winapi_monitor::EventCategory::kProcess, &gNCryptVerifySignatureHook, reinterpret_cast<void*>(&HookedNCryptVerifySignature), reinterpret_cast<void**>(&gNCryptVerifySignatureOriginal) },
            { L"Ncrypt.dll", "NCryptExportKey", ks::winapi_monitor::EventCategory::kProcess, &gNCryptExportKeyHook, reinterpret_cast<void*>(&HookedNCryptExportKey), reinterpret_cast<void**>(&gNCryptExportKeyOriginal) },
            { L"Ncrypt.dll", "NCryptImportKey", ks::winapi_monitor::EventCategory::kProcess, &gNCryptImportKeyHook, reinterpret_cast<void*>(&HookedNCryptImportKey), reinterpret_cast<void**>(&gNCryptImportKeyOriginal) },
            { L"Ncrypt.dll", "NCryptDeleteKey", ks::winapi_monitor::EventCategory::kProcess, &gNCryptDeleteKeyHook, reinterpret_cast<void*>(&HookedNCryptDeleteKey), reinterpret_cast<void**>(&gNCryptDeleteKeyOriginal) },
            { L"Ncrypt.dll", "NCryptFreeObject", ks::winapi_monitor::EventCategory::kProcess, &gNCryptFreeObjectHook, reinterpret_cast<void*>(&HookedNCryptFreeObject), reinterpret_cast<void**>(&gNCryptFreeObjectOriginal) },
            { L"Rpcrt4.dll", "RpcStringBindingComposeW", ks::winapi_monitor::EventCategory::kNetwork, &gRpcStringBindingComposeWHook, reinterpret_cast<void*>(&HookedRpcStringBindingComposeW), reinterpret_cast<void**>(&gRpcStringBindingComposeWOriginal) },
            { L"Rpcrt4.dll", "RpcStringBindingComposeA", ks::winapi_monitor::EventCategory::kNetwork, &gRpcStringBindingComposeAHook, reinterpret_cast<void*>(&HookedRpcStringBindingComposeA), reinterpret_cast<void**>(&gRpcStringBindingComposeAOriginal) },
            { L"Rpcrt4.dll", "RpcBindingFromStringBindingW", ks::winapi_monitor::EventCategory::kNetwork, &gRpcBindingFromStringBindingWHook, reinterpret_cast<void*>(&HookedRpcBindingFromStringBindingW), reinterpret_cast<void**>(&gRpcBindingFromStringBindingWOriginal) },
            { L"Rpcrt4.dll", "RpcBindingFromStringBindingA", ks::winapi_monitor::EventCategory::kNetwork, &gRpcBindingFromStringBindingAHook, reinterpret_cast<void*>(&HookedRpcBindingFromStringBindingA), reinterpret_cast<void**>(&gRpcBindingFromStringBindingAOriginal) },
            { L"Rpcrt4.dll", "RpcBindingFree", ks::winapi_monitor::EventCategory::kNetwork, &gRpcBindingFreeHook, reinterpret_cast<void*>(&HookedRpcBindingFree), reinterpret_cast<void**>(&gRpcBindingFreeOriginal) },
            { L"Rpcrt4.dll", "RpcMgmtEpEltInqBegin", ks::winapi_monitor::EventCategory::kNetwork, &gRpcMgmtEpEltInqBeginHook, reinterpret_cast<void*>(&HookedRpcMgmtEpEltInqBegin), reinterpret_cast<void**>(&gRpcMgmtEpEltInqBeginOriginal) },
            { L"Rpcrt4.dll", "RpcMgmtEpEltInqNextW", ks::winapi_monitor::EventCategory::kNetwork, &gRpcMgmtEpEltInqNextWHook, reinterpret_cast<void*>(&HookedRpcMgmtEpEltInqNextW), reinterpret_cast<void**>(&gRpcMgmtEpEltInqNextWOriginal) },
            { L"Rpcrt4.dll", "RpcMgmtEpEltInqNextA", ks::winapi_monitor::EventCategory::kNetwork, &gRpcMgmtEpEltInqNextAHook, reinterpret_cast<void*>(&HookedRpcMgmtEpEltInqNextA), reinterpret_cast<void**>(&gRpcMgmtEpEltInqNextAOriginal) },
            { L"Rpcrt4.dll", "RpcMgmtEpEltInqDone", ks::winapi_monitor::EventCategory::kNetwork, &gRpcMgmtEpEltInqDoneHook, reinterpret_cast<void*>(&HookedRpcMgmtEpEltInqDone), reinterpret_cast<void**>(&gRpcMgmtEpEltInqDoneOriginal) },
            { L"ntdll.dll", "NtQueryInformationToken", ks::winapi_monitor::EventCategory::kProcess, &gNtQueryInformationTokenHook, reinterpret_cast<void*>(&HookedNtQueryInformationToken), reinterpret_cast<void**>(&gNtQueryInformationTokenOriginal) },
            { L"ntdll.dll", "NtSetInformationToken", ks::winapi_monitor::EventCategory::kProcess, &gNtSetInformationTokenHook, reinterpret_cast<void*>(&HookedNtSetInformationToken), reinterpret_cast<void**>(&gNtSetInformationTokenOriginal) },
            { L"ntdll.dll", "NtAdjustPrivilegesToken", ks::winapi_monitor::EventCategory::kProcess, &gNtAdjustPrivilegesTokenHook, reinterpret_cast<void*>(&HookedNtAdjustPrivilegesToken), reinterpret_cast<void**>(&gNtAdjustPrivilegesTokenOriginal) },
            { L"ntdll.dll", "NtCreateMutant", ks::winapi_monitor::EventCategory::kProcess, &gNtCreateMutantHook, reinterpret_cast<void*>(&HookedNtCreateMutant), reinterpret_cast<void**>(&gNtCreateMutantOriginal) },
            { L"ntdll.dll", "NtOpenMutant", ks::winapi_monitor::EventCategory::kProcess, &gNtOpenMutantHook, reinterpret_cast<void*>(&HookedNtOpenMutant), reinterpret_cast<void**>(&gNtOpenMutantOriginal) },
            { L"ntdll.dll", "NtReleaseMutant", ks::winapi_monitor::EventCategory::kProcess, &gNtReleaseMutantHook, reinterpret_cast<void*>(&HookedNtReleaseMutant), reinterpret_cast<void**>(&gNtReleaseMutantOriginal) },
            { L"ntdll.dll", "NtCreateEvent", ks::winapi_monitor::EventCategory::kProcess, &gNtCreateEventHook, reinterpret_cast<void*>(&HookedNtCreateEvent), reinterpret_cast<void**>(&gNtCreateEventOriginal) },
            { L"ntdll.dll", "NtOpenEvent", ks::winapi_monitor::EventCategory::kProcess, &gNtOpenEventHook, reinterpret_cast<void*>(&HookedNtOpenEvent), reinterpret_cast<void**>(&gNtOpenEventOriginal) },
            { L"ntdll.dll", "NtSetEvent", ks::winapi_monitor::EventCategory::kProcess, &gNtSetEventHook, reinterpret_cast<void*>(&HookedNtSetEvent), reinterpret_cast<void**>(&gNtSetEventOriginal) },
            { L"ntdll.dll", "NtResetEvent", ks::winapi_monitor::EventCategory::kProcess, &gNtResetEventHook, reinterpret_cast<void*>(&HookedNtResetEvent), reinterpret_cast<void**>(&gNtResetEventOriginal) },
            { L"ntdll.dll", "NtWaitForSingleObject", ks::winapi_monitor::EventCategory::kProcess, &gNtWaitForSingleObjectHook, reinterpret_cast<void*>(&HookedNtWaitForSingleObject), reinterpret_cast<void**>(&gNtWaitForSingleObjectOriginal) },
            { L"ntdll.dll", "NtWaitForMultipleObjects", ks::winapi_monitor::EventCategory::kProcess, &gNtWaitForMultipleObjectsHook, reinterpret_cast<void*>(&HookedNtWaitForMultipleObjects), reinterpret_cast<void**>(&gNtWaitForMultipleObjectsOriginal) },
            { L"ntdll.dll", "NtQuerySystemInformation", ks::winapi_monitor::EventCategory::kProcess, &gNtQuerySystemInformationHook, reinterpret_cast<void*>(&HookedNtQuerySystemInformation), reinterpret_cast<void**>(&gNtQuerySystemInformationOriginal) },
            { L"ntdll.dll", "NtQueryObject", ks::winapi_monitor::EventCategory::kProcess, &gNtQueryObjectHook, reinterpret_cast<void*>(&HookedNtQueryObject), reinterpret_cast<void**>(&gNtQueryObjectOriginal) },
            { L"Advapi32.dll", "LogonUserW", ks::winapi_monitor::EventCategory::kProcess, &gLogonUserWHook, reinterpret_cast<void*>(&HookedLogonUserW), reinterpret_cast<void**>(&gLogonUserWOriginal) },
            { L"Advapi32.dll", "LogonUserA", ks::winapi_monitor::EventCategory::kProcess, &gLogonUserAHook, reinterpret_cast<void*>(&HookedLogonUserA), reinterpret_cast<void**>(&gLogonUserAOriginal) },
            { L"Advapi32.dll", "GetTokenInformation", ks::winapi_monitor::EventCategory::kProcess, &gGetTokenInformationHook, reinterpret_cast<void*>(&HookedGetTokenInformation), reinterpret_cast<void**>(&gGetTokenInformationOriginal) },
            { L"Advapi32.dll", "SetTokenInformation", ks::winapi_monitor::EventCategory::kProcess, &gSetTokenInformationHook, reinterpret_cast<void*>(&HookedSetTokenInformation), reinterpret_cast<void**>(&gSetTokenInformationOriginal) },
            { L"Advapi32.dll", "CheckTokenMembership", ks::winapi_monitor::EventCategory::kProcess, &gCheckTokenMembershipHook, reinterpret_cast<void*>(&HookedCheckTokenMembership), reinterpret_cast<void**>(&gCheckTokenMembershipOriginal) },
            { L"Advapi32.dll", "CreateRestrictedToken", ks::winapi_monitor::EventCategory::kProcess, &gCreateRestrictedTokenHook, reinterpret_cast<void*>(&HookedCreateRestrictedToken), reinterpret_cast<void**>(&gCreateRestrictedTokenOriginal) },
            { L"Advapi32.dll", "ImpersonateSelf", ks::winapi_monitor::EventCategory::kProcess, &gImpersonateSelfHook, reinterpret_cast<void*>(&HookedImpersonateSelf), reinterpret_cast<void**>(&gImpersonateSelfOriginal) },
            { L"Advapi32.dll", "ImpersonateNamedPipeClient", ks::winapi_monitor::EventCategory::kProcess, &gImpersonateNamedPipeClientHook, reinterpret_cast<void*>(&HookedImpersonateNamedPipeClient), reinterpret_cast<void**>(&gImpersonateNamedPipeClientOriginal) },
            { L"Advapi32.dll", "CredReadW", ks::winapi_monitor::EventCategory::kProcess, &gCredReadWHook, reinterpret_cast<void*>(&HookedCredReadW), reinterpret_cast<void**>(&gCredReadWOriginal) },
            { L"Advapi32.dll", "CredReadA", ks::winapi_monitor::EventCategory::kProcess, &gCredReadAHook, reinterpret_cast<void*>(&HookedCredReadA), reinterpret_cast<void**>(&gCredReadAOriginal) },
            { L"Advapi32.dll", "CredEnumerateW", ks::winapi_monitor::EventCategory::kProcess, &gCredEnumerateWHook, reinterpret_cast<void*>(&HookedCredEnumerateW), reinterpret_cast<void**>(&gCredEnumerateWOriginal) },
            { L"Advapi32.dll", "CredEnumerateA", ks::winapi_monitor::EventCategory::kProcess, &gCredEnumerateAHook, reinterpret_cast<void*>(&HookedCredEnumerateA), reinterpret_cast<void**>(&gCredEnumerateAOriginal) },
            { L"Advapi32.dll", "CredWriteW", ks::winapi_monitor::EventCategory::kProcess, &gCredWriteWHook, reinterpret_cast<void*>(&HookedCredWriteW), reinterpret_cast<void**>(&gCredWriteWOriginal) },
            { L"Advapi32.dll", "CredWriteA", ks::winapi_monitor::EventCategory::kProcess, &gCredWriteAHook, reinterpret_cast<void*>(&HookedCredWriteA), reinterpret_cast<void**>(&gCredWriteAOriginal) },
            { L"Advapi32.dll", "CredDeleteW", ks::winapi_monitor::EventCategory::kProcess, &gCredDeleteWHook, reinterpret_cast<void*>(&HookedCredDeleteW), reinterpret_cast<void**>(&gCredDeleteWOriginal) },
            { L"Advapi32.dll", "CredDeleteA", ks::winapi_monitor::EventCategory::kProcess, &gCredDeleteAHook, reinterpret_cast<void*>(&HookedCredDeleteA), reinterpret_cast<void**>(&gCredDeleteAOriginal) },
            { L"Advapi32.dll", "CredFree", ks::winapi_monitor::EventCategory::kProcess, &gCredFreeHook, reinterpret_cast<void*>(&HookedCredFree), reinterpret_cast<void**>(&gCredFreeOriginal) },
            { L"Advapi32.dll", "LsaOpenPolicy", ks::winapi_monitor::EventCategory::kProcess, &gLsaOpenPolicyHook, reinterpret_cast<void*>(&HookedLsaOpenPolicy), reinterpret_cast<void**>(&gLsaOpenPolicyOriginal) },
            { L"Advapi32.dll", "LsaClose", ks::winapi_monitor::EventCategory::kProcess, &gLsaCloseHook, reinterpret_cast<void*>(&HookedLsaClose), reinterpret_cast<void**>(&gLsaCloseOriginal) },
            { L"Advapi32.dll", "LsaEnumerateLogonSessions", ks::winapi_monitor::EventCategory::kProcess, &gLsaEnumerateLogonSessionsHook, reinterpret_cast<void*>(&HookedLsaEnumerateLogonSessions), reinterpret_cast<void**>(&gLsaEnumerateLogonSessionsOriginal) },
            { L"Advapi32.dll", "LsaGetLogonSessionData", ks::winapi_monitor::EventCategory::kProcess, &gLsaGetLogonSessionDataHook, reinterpret_cast<void*>(&HookedLsaGetLogonSessionData), reinterpret_cast<void**>(&gLsaGetLogonSessionDataOriginal) },
            { L"Advapi32.dll", "LsaFreeReturnBuffer", ks::winapi_monitor::EventCategory::kProcess, &gLsaFreeReturnBufferHook, reinterpret_cast<void*>(&HookedLsaFreeReturnBuffer), reinterpret_cast<void**>(&gLsaFreeReturnBufferOriginal) },
            { L"Advapi32.dll", "LsaLookupNames2", ks::winapi_monitor::EventCategory::kProcess, &gLsaLookupNames2Hook, reinterpret_cast<void*>(&HookedLsaLookupNames2), reinterpret_cast<void**>(&gLsaLookupNames2Original) },
            { L"Advapi32.dll", "LsaLookupSids2", ks::winapi_monitor::EventCategory::kProcess, &gLsaLookupSids2Hook, reinterpret_cast<void*>(&HookedLsaLookupSids2), reinterpret_cast<void**>(&gLsaLookupSids2Original) },
            { L"Advapi32.dll", "OpenEventLogW", ks::winapi_monitor::EventCategory::kProcess, &gOpenEventLogWHook, reinterpret_cast<void*>(&HookedOpenEventLogW), reinterpret_cast<void**>(&gOpenEventLogWOriginal) },
            { L"Advapi32.dll", "OpenEventLogA", ks::winapi_monitor::EventCategory::kProcess, &gOpenEventLogAHook, reinterpret_cast<void*>(&HookedOpenEventLogA), reinterpret_cast<void**>(&gOpenEventLogAOriginal) },
            { L"Advapi32.dll", "RegisterEventSourceW", ks::winapi_monitor::EventCategory::kProcess, &gRegisterEventSourceWHook, reinterpret_cast<void*>(&HookedRegisterEventSourceW), reinterpret_cast<void**>(&gRegisterEventSourceWOriginal) },
            { L"Advapi32.dll", "RegisterEventSourceA", ks::winapi_monitor::EventCategory::kProcess, &gRegisterEventSourceAHook, reinterpret_cast<void*>(&HookedRegisterEventSourceA), reinterpret_cast<void**>(&gRegisterEventSourceAOriginal) },
            { L"Advapi32.dll", "ReadEventLogW", ks::winapi_monitor::EventCategory::kProcess, &gReadEventLogWHook, reinterpret_cast<void*>(&HookedReadEventLogW), reinterpret_cast<void**>(&gReadEventLogWOriginal) },
            { L"Advapi32.dll", "ReadEventLogA", ks::winapi_monitor::EventCategory::kProcess, &gReadEventLogAHook, reinterpret_cast<void*>(&HookedReadEventLogA), reinterpret_cast<void**>(&gReadEventLogAOriginal) },
            { L"Advapi32.dll", "ClearEventLogW", ks::winapi_monitor::EventCategory::kProcess, &gClearEventLogWHook, reinterpret_cast<void*>(&HookedClearEventLogW), reinterpret_cast<void**>(&gClearEventLogWOriginal) },
            { L"Advapi32.dll", "ClearEventLogA", ks::winapi_monitor::EventCategory::kProcess, &gClearEventLogAHook, reinterpret_cast<void*>(&HookedClearEventLogA), reinterpret_cast<void**>(&gClearEventLogAOriginal) },
            { L"Advapi32.dll", "ReportEventW", ks::winapi_monitor::EventCategory::kProcess, &gReportEventWHook, reinterpret_cast<void*>(&HookedReportEventW), reinterpret_cast<void**>(&gReportEventWOriginal) },
            { L"Advapi32.dll", "ReportEventA", ks::winapi_monitor::EventCategory::kProcess, &gReportEventAHook, reinterpret_cast<void*>(&HookedReportEventA), reinterpret_cast<void**>(&gReportEventAOriginal) },
            { L"Advapi32.dll", "CloseEventLog", ks::winapi_monitor::EventCategory::kProcess, &gCloseEventLogHook, reinterpret_cast<void*>(&HookedCloseEventLog), reinterpret_cast<void**>(&gCloseEventLogOriginal) },
            { L"Netapi32.dll", "NetUserEnum", ks::winapi_monitor::EventCategory::kNetwork, &gNetUserEnumHook, reinterpret_cast<void*>(&HookedNetUserEnum), reinterpret_cast<void**>(&gNetUserEnumOriginal) },
            { L"Netapi32.dll", "NetLocalGroupEnum", ks::winapi_monitor::EventCategory::kNetwork, &gNetLocalGroupEnumHook, reinterpret_cast<void*>(&HookedNetLocalGroupEnum), reinterpret_cast<void**>(&gNetLocalGroupEnumOriginal) },
            { L"Netapi32.dll", "NetGroupEnum", ks::winapi_monitor::EventCategory::kNetwork, &gNetGroupEnumHook, reinterpret_cast<void*>(&HookedNetGroupEnum), reinterpret_cast<void**>(&gNetGroupEnumOriginal) },
            { L"Netapi32.dll", "NetShareEnum", ks::winapi_monitor::EventCategory::kNetwork, &gNetShareEnumHook, reinterpret_cast<void*>(&HookedNetShareEnum), reinterpret_cast<void**>(&gNetShareEnumOriginal) },
            { L"Netapi32.dll", "NetSessionEnum", ks::winapi_monitor::EventCategory::kNetwork, &gNetSessionEnumHook, reinterpret_cast<void*>(&HookedNetSessionEnum), reinterpret_cast<void**>(&gNetSessionEnumOriginal) },
            { L"Netapi32.dll", "NetServerEnum", ks::winapi_monitor::EventCategory::kNetwork, &gNetServerEnumHook, reinterpret_cast<void*>(&HookedNetServerEnum), reinterpret_cast<void**>(&gNetServerEnumOriginal) },
            { L"Netapi32.dll", "NetWkstaGetInfo", ks::winapi_monitor::EventCategory::kNetwork, &gNetWkstaGetInfoHook, reinterpret_cast<void*>(&HookedNetWkstaGetInfo), reinterpret_cast<void**>(&gNetWkstaGetInfoOriginal) },
            { L"Netapi32.dll", "NetApiBufferFree", ks::winapi_monitor::EventCategory::kNetwork, &gNetApiBufferFreeHook, reinterpret_cast<void*>(&HookedNetApiBufferFree), reinterpret_cast<void**>(&gNetApiBufferFreeOriginal) },
            { L"Iphlpapi.dll", "GetExtendedTcpTable", ks::winapi_monitor::EventCategory::kNetwork, &gGetExtendedTcpTableHook, reinterpret_cast<void*>(&HookedGetExtendedTcpTable), reinterpret_cast<void**>(&gGetExtendedTcpTableOriginal) },
            { L"Iphlpapi.dll", "GetExtendedUdpTable", ks::winapi_monitor::EventCategory::kNetwork, &gGetExtendedUdpTableHook, reinterpret_cast<void*>(&HookedGetExtendedUdpTable), reinterpret_cast<void**>(&gGetExtendedUdpTableOriginal) },
            { L"Iphlpapi.dll", "GetTcpTable2", ks::winapi_monitor::EventCategory::kNetwork, &gGetTcpTable2Hook, reinterpret_cast<void*>(&HookedGetTcpTable2), reinterpret_cast<void**>(&gGetTcpTable2Original) },
            { L"Iphlpapi.dll", "GetUdpTable", ks::winapi_monitor::EventCategory::kNetwork, &gGetUdpTableHook, reinterpret_cast<void*>(&HookedGetUdpTable), reinterpret_cast<void**>(&gGetUdpTableOriginal) },
            { L"Iphlpapi.dll", "GetAdaptersAddresses", ks::winapi_monitor::EventCategory::kNetwork, &gGetAdaptersAddressesHook, reinterpret_cast<void*>(&HookedGetAdaptersAddresses), reinterpret_cast<void**>(&gGetAdaptersAddressesOriginal) },
            { L"Iphlpapi.dll", "GetNetworkParams", ks::winapi_monitor::EventCategory::kNetwork, &gGetNetworkParamsHook, reinterpret_cast<void*>(&HookedGetNetworkParams), reinterpret_cast<void**>(&gGetNetworkParamsOriginal) },
            { L"Iphlpapi.dll", "GetIpNetTable2", ks::winapi_monitor::EventCategory::kNetwork, &gGetIpNetTable2Hook, reinterpret_cast<void*>(&HookedGetIpNetTable2), reinterpret_cast<void**>(&gGetIpNetTable2Original) },
            { L"Iphlpapi.dll", "GetIfTable2", ks::winapi_monitor::EventCategory::kNetwork, &gGetIfTable2Hook, reinterpret_cast<void*>(&HookedGetIfTable2), reinterpret_cast<void**>(&gGetIfTable2Original) },
            { L"Iphlpapi.dll", "FreeMibTable", ks::winapi_monitor::EventCategory::kNetwork, &gFreeMibTableHook, reinterpret_cast<void*>(&HookedFreeMibTable), reinterpret_cast<void**>(&gFreeMibTableOriginal) },
            { L"Wtsapi32.dll", "WTSOpenServerW", ks::winapi_monitor::EventCategory::kProcess, &gWtsOpenServerWHook, reinterpret_cast<void*>(&HookedWTSOpenServerW), reinterpret_cast<void**>(&gWtsOpenServerWOriginal) },
            { L"Wtsapi32.dll", "WTSOpenServerA", ks::winapi_monitor::EventCategory::kProcess, &gWtsOpenServerAHook, reinterpret_cast<void*>(&HookedWTSOpenServerA), reinterpret_cast<void**>(&gWtsOpenServerAOriginal) },
            { L"Wtsapi32.dll", "WTSCloseServer", ks::winapi_monitor::EventCategory::kProcess, &gWtsCloseServerHook, reinterpret_cast<void*>(&HookedWTSCloseServer), reinterpret_cast<void**>(&gWtsCloseServerOriginal) },
            { L"Wtsapi32.dll", "WTSEnumerateSessionsW", ks::winapi_monitor::EventCategory::kProcess, &gWtsEnumerateSessionsWHook, reinterpret_cast<void*>(&HookedWTSEnumerateSessionsW), reinterpret_cast<void**>(&gWtsEnumerateSessionsWOriginal) },
            { L"Wtsapi32.dll", "WTSEnumerateSessionsA", ks::winapi_monitor::EventCategory::kProcess, &gWtsEnumerateSessionsAHook, reinterpret_cast<void*>(&HookedWTSEnumerateSessionsA), reinterpret_cast<void**>(&gWtsEnumerateSessionsAOriginal) },
            { L"Wtsapi32.dll", "WTSEnumerateProcessesW", ks::winapi_monitor::EventCategory::kProcess, &gWtsEnumerateProcessesWHook, reinterpret_cast<void*>(&HookedWTSEnumerateProcessesW), reinterpret_cast<void**>(&gWtsEnumerateProcessesWOriginal) },
            { L"Wtsapi32.dll", "WTSEnumerateProcessesA", ks::winapi_monitor::EventCategory::kProcess, &gWtsEnumerateProcessesAHook, reinterpret_cast<void*>(&HookedWTSEnumerateProcessesA), reinterpret_cast<void**>(&gWtsEnumerateProcessesAOriginal) },
            { L"Wtsapi32.dll", "WTSQuerySessionInformationW", ks::winapi_monitor::EventCategory::kProcess, &gWtsQuerySessionInformationWHook, reinterpret_cast<void*>(&HookedWTSQuerySessionInformationW), reinterpret_cast<void**>(&gWtsQuerySessionInformationWOriginal) },
            { L"Wtsapi32.dll", "WTSQuerySessionInformationA", ks::winapi_monitor::EventCategory::kProcess, &gWtsQuerySessionInformationAHook, reinterpret_cast<void*>(&HookedWTSQuerySessionInformationA), reinterpret_cast<void**>(&gWtsQuerySessionInformationAOriginal) },
            { L"Wtsapi32.dll", "WTSFreeMemory", ks::winapi_monitor::EventCategory::kProcess, &gWtsFreeMemoryHook, reinterpret_cast<void*>(&HookedWTSFreeMemory), reinterpret_cast<void**>(&gWtsFreeMemoryOriginal) },
            { L"KernelBase.dll", "CreateJobObjectW", ks::winapi_monitor::EventCategory::kProcess, &gCreateJobObjectWHook, reinterpret_cast<void*>(&HookedCreateJobObjectW), reinterpret_cast<void**>(&gCreateJobObjectWOriginal) },
            { L"KernelBase.dll", "CreateJobObjectA", ks::winapi_monitor::EventCategory::kProcess, &gCreateJobObjectAHook, reinterpret_cast<void*>(&HookedCreateJobObjectA), reinterpret_cast<void**>(&gCreateJobObjectAOriginal) },
            { L"KernelBase.dll", "OpenJobObjectW", ks::winapi_monitor::EventCategory::kProcess, &gOpenJobObjectWHook, reinterpret_cast<void*>(&HookedOpenJobObjectW), reinterpret_cast<void**>(&gOpenJobObjectWOriginal) },
            { L"KernelBase.dll", "OpenJobObjectA", ks::winapi_monitor::EventCategory::kProcess, &gOpenJobObjectAHook, reinterpret_cast<void*>(&HookedOpenJobObjectA), reinterpret_cast<void**>(&gOpenJobObjectAOriginal) },
            { L"KernelBase.dll", "AssignProcessToJobObject", ks::winapi_monitor::EventCategory::kProcess, &gAssignProcessToJobObjectHook, reinterpret_cast<void*>(&HookedAssignProcessToJobObject), reinterpret_cast<void**>(&gAssignProcessToJobObjectOriginal) },
            { L"KernelBase.dll", "TerminateJobObject", ks::winapi_monitor::EventCategory::kProcess, &gTerminateJobObjectHook, reinterpret_cast<void*>(&HookedTerminateJobObject), reinterpret_cast<void**>(&gTerminateJobObjectOriginal) },
            { L"KernelBase.dll", "SetInformationJobObject", ks::winapi_monitor::EventCategory::kProcess, &gSetInformationJobObjectHook, reinterpret_cast<void*>(&HookedSetInformationJobObject), reinterpret_cast<void**>(&gSetInformationJobObjectOriginal) },
            { L"KernelBase.dll", "QueryInformationJobObject", ks::winapi_monitor::EventCategory::kProcess, &gQueryInformationJobObjectHook, reinterpret_cast<void*>(&HookedQueryInformationJobObject), reinterpret_cast<void**>(&gQueryInformationJobObjectOriginal) },
            { L"Secur32.dll", "AcquireCredentialsHandleW", ks::winapi_monitor::EventCategory::kProcess, &gAcquireCredentialsHandleWHook, reinterpret_cast<void*>(&HookedAcquireCredentialsHandleW), reinterpret_cast<void**>(&gAcquireCredentialsHandleWOriginal) },
            { L"Secur32.dll", "AcquireCredentialsHandleA", ks::winapi_monitor::EventCategory::kProcess, &gAcquireCredentialsHandleAHook, reinterpret_cast<void*>(&HookedAcquireCredentialsHandleA), reinterpret_cast<void**>(&gAcquireCredentialsHandleAOriginal) },
            { L"Secur32.dll", "InitializeSecurityContextW", ks::winapi_monitor::EventCategory::kProcess, &gInitializeSecurityContextWHook, reinterpret_cast<void*>(&HookedInitializeSecurityContextW), reinterpret_cast<void**>(&gInitializeSecurityContextWOriginal) },
            { L"Secur32.dll", "InitializeSecurityContextA", ks::winapi_monitor::EventCategory::kProcess, &gInitializeSecurityContextAHook, reinterpret_cast<void*>(&HookedInitializeSecurityContextA), reinterpret_cast<void**>(&gInitializeSecurityContextAOriginal) },
            { L"Secur32.dll", "AcceptSecurityContext", ks::winapi_monitor::EventCategory::kProcess, &gAcceptSecurityContextHook, reinterpret_cast<void*>(&HookedAcceptSecurityContext), reinterpret_cast<void**>(&gAcceptSecurityContextOriginal) },
            { L"Secur32.dll", "EncryptMessage", ks::winapi_monitor::EventCategory::kProcess, &gEncryptMessageHook, reinterpret_cast<void*>(&HookedEncryptMessage), reinterpret_cast<void**>(&gEncryptMessageOriginal) },
            { L"Secur32.dll", "DecryptMessage", ks::winapi_monitor::EventCategory::kProcess, &gDecryptMessageHook, reinterpret_cast<void*>(&HookedDecryptMessage), reinterpret_cast<void**>(&gDecryptMessageOriginal) },
            { L"Secur32.dll", "DeleteSecurityContext", ks::winapi_monitor::EventCategory::kProcess, &gDeleteSecurityContextHook, reinterpret_cast<void*>(&HookedDeleteSecurityContext), reinterpret_cast<void**>(&gDeleteSecurityContextOriginal) },
            { L"Secur32.dll", "FreeCredentialsHandle", ks::winapi_monitor::EventCategory::kProcess, &gFreeCredentialsHandleHook, reinterpret_cast<void*>(&HookedFreeCredentialsHandle), reinterpret_cast<void**>(&gFreeCredentialsHandleOriginal) },
            // Sixth batch bindings: Purpose:
            // - Input: Adds enumerations, paths, IPC, Winsock, HTTP, and ntdll object layer wrappers;
            // - Processing: Continue reusing existing inline hook installation flow without introducing new external hook frameworks;
            // - Returns: this static table has no return value; new entries are installed/uninstalled uniformly via installConfiguredHooks.
            { L"Kernel32.dll", "Process32FirstW", ks::winapi_monitor::EventCategory::kProcess, &gProcess32FirstWHook, reinterpret_cast<void*>(&HookedProcess32FirstW), reinterpret_cast<void**>(&gProcess32FirstWOriginal) },
            { L"Kernel32.dll", "Process32First", ks::winapi_monitor::EventCategory::kProcess, &gProcess32FirstAHook, reinterpret_cast<void*>(&HookedProcess32FirstA), reinterpret_cast<void**>(&gProcess32FirstAOriginal) },
            { L"Kernel32.dll", "Process32NextW", ks::winapi_monitor::EventCategory::kProcess, &gProcess32NextWHook, reinterpret_cast<void*>(&HookedProcess32NextW), reinterpret_cast<void**>(&gProcess32NextWOriginal) },
            { L"Kernel32.dll", "Process32Next", ks::winapi_monitor::EventCategory::kProcess, &gProcess32NextAHook, reinterpret_cast<void*>(&HookedProcess32NextA), reinterpret_cast<void**>(&gProcess32NextAOriginal) },
            { L"Kernel32.dll", "Thread32First", ks::winapi_monitor::EventCategory::kProcess, &gThread32FirstHook, reinterpret_cast<void*>(&HookedThread32First), reinterpret_cast<void**>(&gThread32FirstOriginal) },
            { L"Kernel32.dll", "Thread32Next", ks::winapi_monitor::EventCategory::kProcess, &gThread32NextHook, reinterpret_cast<void*>(&HookedThread32Next), reinterpret_cast<void**>(&gThread32NextOriginal) },
            { L"Kernel32.dll", "Heap32ListFirst", ks::winapi_monitor::EventCategory::kProcess, &gHeap32ListFirstHook, reinterpret_cast<void*>(&HookedHeap32ListFirst), reinterpret_cast<void**>(&gHeap32ListFirstOriginal) },
            { L"Kernel32.dll", "Heap32ListNext", ks::winapi_monitor::EventCategory::kProcess, &gHeap32ListNextHook, reinterpret_cast<void*>(&HookedHeap32ListNext), reinterpret_cast<void**>(&gHeap32ListNextOriginal) },
            { L"Kernel32.dll", "Heap32First", ks::winapi_monitor::EventCategory::kProcess, &gHeap32FirstHook, reinterpret_cast<void*>(&HookedHeap32First), reinterpret_cast<void**>(&gHeap32FirstOriginal) },
            { L"Kernel32.dll", "Heap32Next", ks::winapi_monitor::EventCategory::kProcess, &gHeap32NextHook, reinterpret_cast<void*>(&HookedHeap32Next), reinterpret_cast<void**>(&gHeap32NextOriginal) },
            { L"KernelBase.dll", "QueryFullProcessImageNameW", ks::winapi_monitor::EventCategory::kProcess, &gQueryFullProcessImageNameWHook, reinterpret_cast<void*>(&HookedQueryFullProcessImageNameW), reinterpret_cast<void**>(&gQueryFullProcessImageNameWOriginal) },
            { L"KernelBase.dll", "QueryFullProcessImageNameA", ks::winapi_monitor::EventCategory::kProcess, &gQueryFullProcessImageNameAHook, reinterpret_cast<void*>(&HookedQueryFullProcessImageNameA), reinterpret_cast<void**>(&gQueryFullProcessImageNameAOriginal) },
            { L"Psapi.dll", "GetProcessImageFileNameW", ks::winapi_monitor::EventCategory::kProcess, &gGetProcessImageFileNameWHook, reinterpret_cast<void*>(&HookedGetProcessImageFileNameW), reinterpret_cast<void**>(&gGetProcessImageFileNameWOriginal) },
            { L"Psapi.dll", "GetProcessImageFileNameA", ks::winapi_monitor::EventCategory::kProcess, &gGetProcessImageFileNameAHook, reinterpret_cast<void*>(&HookedGetProcessImageFileNameA), reinterpret_cast<void**>(&gGetProcessImageFileNameAOriginal) },
            { L"KernelBase.dll", "GetProcessId", ks::winapi_monitor::EventCategory::kProcess, &gGetProcessIdHook, reinterpret_cast<void*>(&HookedGetProcessId), reinterpret_cast<void**>(&gGetProcessIdOriginal) },
            { L"KernelBase.dll", "GetThreadId", ks::winapi_monitor::EventCategory::kProcess, &gGetThreadIdHook, reinterpret_cast<void*>(&HookedGetThreadId), reinterpret_cast<void**>(&gGetThreadIdOriginal) },
            { L"KernelBase.dll", "IsWow64Process", ks::winapi_monitor::EventCategory::kProcess, &gIsWow64ProcessHook, reinterpret_cast<void*>(&HookedIsWow64Process), reinterpret_cast<void**>(&gIsWow64ProcessOriginal) },
            { L"KernelBase.dll", "IsWow64Process2", ks::winapi_monitor::EventCategory::kProcess, &gIsWow64Process2Hook, reinterpret_cast<void*>(&HookedIsWow64Process2), reinterpret_cast<void**>(&gIsWow64Process2Original) },
            { L"KernelBase.dll", "Wow64DisableWow64FsRedirection", ks::winapi_monitor::EventCategory::kFile, &gWow64DisableWow64FsRedirectionHook, reinterpret_cast<void*>(&HookedWow64DisableWow64FsRedirection), reinterpret_cast<void**>(&gWow64DisableWow64FsRedirectionOriginal) },
            { L"KernelBase.dll", "Wow64RevertWow64FsRedirection", ks::winapi_monitor::EventCategory::kFile, &gWow64RevertWow64FsRedirectionHook, reinterpret_cast<void*>(&HookedWow64RevertWow64FsRedirection), reinterpret_cast<void**>(&gWow64RevertWow64FsRedirectionOriginal) },
            { L"KernelBase.dll", "GetTempPathW", ks::winapi_monitor::EventCategory::kFile, &gGetTempPathWHook, reinterpret_cast<void*>(&HookedGetTempPathW), reinterpret_cast<void**>(&gGetTempPathWOriginal) },
            { L"KernelBase.dll", "GetTempPathA", ks::winapi_monitor::EventCategory::kFile, &gGetTempPathAHook, reinterpret_cast<void*>(&HookedGetTempPathA), reinterpret_cast<void**>(&gGetTempPathAOriginal) },
            { L"KernelBase.dll", "GetTempFileNameW", ks::winapi_monitor::EventCategory::kFile, &gGetTempFileNameWHook, reinterpret_cast<void*>(&HookedGetTempFileNameW), reinterpret_cast<void**>(&gGetTempFileNameWOriginal) },
            { L"KernelBase.dll", "GetTempFileNameA", ks::winapi_monitor::EventCategory::kFile, &gGetTempFileNameAHook, reinterpret_cast<void*>(&HookedGetTempFileNameA), reinterpret_cast<void**>(&gGetTempFileNameAOriginal) },
            { L"KernelBase.dll", "GetFullPathNameW", ks::winapi_monitor::EventCategory::kFile, &gGetFullPathNameWHook, reinterpret_cast<void*>(&HookedGetFullPathNameW), reinterpret_cast<void**>(&gGetFullPathNameWOriginal) },
            { L"KernelBase.dll", "GetFullPathNameA", ks::winapi_monitor::EventCategory::kFile, &gGetFullPathNameAHook, reinterpret_cast<void*>(&HookedGetFullPathNameA), reinterpret_cast<void**>(&gGetFullPathNameAOriginal) },
            { L"KernelBase.dll", "SearchPathW", ks::winapi_monitor::EventCategory::kFile, &gSearchPathWHook, reinterpret_cast<void*>(&HookedSearchPathW), reinterpret_cast<void**>(&gSearchPathWOriginal) },
            { L"KernelBase.dll", "SearchPathA", ks::winapi_monitor::EventCategory::kFile, &gSearchPathAHook, reinterpret_cast<void*>(&HookedSearchPathA), reinterpret_cast<void**>(&gSearchPathAOriginal) },
            { L"KernelBase.dll", "GetShortPathNameW", ks::winapi_monitor::EventCategory::kFile, &gGetShortPathNameWHook, reinterpret_cast<void*>(&HookedGetShortPathNameW), reinterpret_cast<void**>(&gGetShortPathNameWOriginal) },
            { L"KernelBase.dll", "GetShortPathNameA", ks::winapi_monitor::EventCategory::kFile, &gGetShortPathNameAHook, reinterpret_cast<void*>(&HookedGetShortPathNameA), reinterpret_cast<void**>(&gGetShortPathNameAOriginal) },
            { L"KernelBase.dll", "GetLongPathNameW", ks::winapi_monitor::EventCategory::kFile, &gGetLongPathNameWHook, reinterpret_cast<void*>(&HookedGetLongPathNameW), reinterpret_cast<void**>(&gGetLongPathNameWOriginal) },
            { L"KernelBase.dll", "GetLongPathNameA", ks::winapi_monitor::EventCategory::kFile, &gGetLongPathNameAHook, reinterpret_cast<void*>(&HookedGetLongPathNameA), reinterpret_cast<void**>(&gGetLongPathNameAOriginal) },
            { L"KernelBase.dll", "CreatePipe", ks::winapi_monitor::EventCategory::kFile, &gCreatePipeHook, reinterpret_cast<void*>(&HookedCreatePipe), reinterpret_cast<void**>(&gCreatePipeOriginal) },
            { L"KernelBase.dll", "CreateMailslotW", ks::winapi_monitor::EventCategory::kFile, &gCreateMailslotWHook, reinterpret_cast<void*>(&HookedCreateMailslotW), reinterpret_cast<void**>(&gCreateMailslotWOriginal) },
            { L"KernelBase.dll", "CreateMailslotA", ks::winapi_monitor::EventCategory::kFile, &gCreateMailslotAHook, reinterpret_cast<void*>(&HookedCreateMailslotA), reinterpret_cast<void**>(&gCreateMailslotAOriginal) },
            { L"KernelBase.dll", "CreateDirectoryExW", ks::winapi_monitor::EventCategory::kFile, &gCreateDirectoryExWHook, reinterpret_cast<void*>(&HookedCreateDirectoryExW), reinterpret_cast<void**>(&gCreateDirectoryExWOriginal) },
            { L"KernelBase.dll", "CreateDirectoryExA", ks::winapi_monitor::EventCategory::kFile, &gCreateDirectoryExAHook, reinterpret_cast<void*>(&HookedCreateDirectoryExA), reinterpret_cast<void**>(&gCreateDirectoryExAOriginal) },
            { L"Ws2_32.dll", "WSAStartup", ks::winapi_monitor::EventCategory::kNetwork, &gWsaStartupHook, reinterpret_cast<void*>(&HookedWSAStartup), reinterpret_cast<void**>(&gWsaStartupOriginal) },
            { L"Ws2_32.dll", "WSACleanup", ks::winapi_monitor::EventCategory::kNetwork, &gWsaCleanupHook, reinterpret_cast<void*>(&HookedWSACleanup), reinterpret_cast<void**>(&gWsaCleanupOriginal) },
            { L"Ws2_32.dll", "select", ks::winapi_monitor::EventCategory::kNetwork, &gSelectHook, reinterpret_cast<void*>(&HookedSelect), reinterpret_cast<void**>(&gSelectOriginal) },
            { L"Ws2_32.dll", "ioctlsocket", ks::winapi_monitor::EventCategory::kNetwork, &gIoctlSocketHook, reinterpret_cast<void*>(&HookedIoctlSocket), reinterpret_cast<void**>(&gIoctlSocketOriginal) },
            { L"Ws2_32.dll", "setsockopt", ks::winapi_monitor::EventCategory::kNetwork, &gSetSockOptHook, reinterpret_cast<void*>(&HookedSetSockOpt), reinterpret_cast<void**>(&gSetSockOptOriginal) },
            { L"Ws2_32.dll", "getsockopt", ks::winapi_monitor::EventCategory::kNetwork, &gGetSockOptHook, reinterpret_cast<void*>(&HookedGetSockOpt), reinterpret_cast<void**>(&gGetSockOptOriginal) },
            { L"Ws2_32.dll", "getsockname", ks::winapi_monitor::EventCategory::kNetwork, &gGetSockNameHook, reinterpret_cast<void*>(&HookedGetSockName), reinterpret_cast<void**>(&gGetSockNameOriginal) },
            { L"Ws2_32.dll", "getpeername", ks::winapi_monitor::EventCategory::kNetwork, &gGetPeerNameHook, reinterpret_cast<void*>(&HookedGetPeerName), reinterpret_cast<void**>(&gGetPeerNameOriginal) },
            { L"Ws2_32.dll", "WSAEventSelect", ks::winapi_monitor::EventCategory::kNetwork, &gWsaEventSelectHook, reinterpret_cast<void*>(&HookedWSAEventSelect), reinterpret_cast<void**>(&gWsaEventSelectOriginal) },
            { L"Ws2_32.dll", "WSAAsyncSelect", ks::winapi_monitor::EventCategory::kNetwork, &gWsaAsyncSelectHook, reinterpret_cast<void*>(&HookedWSAAsyncSelect), reinterpret_cast<void**>(&gWsaAsyncSelectOriginal) },
            { L"Ws2_32.dll", "gethostbyname", ks::winapi_monitor::EventCategory::kNetwork, &gGetHostByNameHook, reinterpret_cast<void*>(&HookedGetHostByName), reinterpret_cast<void**>(&gGetHostByNameOriginal) },
            { L"Ws2_32.dll", "gethostbyaddr", ks::winapi_monitor::EventCategory::kNetwork, &gGetHostByAddrHook, reinterpret_cast<void*>(&HookedGetHostByAddr), reinterpret_cast<void**>(&gGetHostByAddrOriginal) },
            { L"Ws2_32.dll", "GetNameInfoW", ks::winapi_monitor::EventCategory::kNetwork, &gGetNameInfoWHook, reinterpret_cast<void*>(&HookedGetNameInfoW), reinterpret_cast<void**>(&gGetNameInfoWOriginal) },
            { L"Ws2_32.dll", "getnameinfo", ks::winapi_monitor::EventCategory::kNetwork, &gGetNameInfoAHook, reinterpret_cast<void*>(&HookedGetNameInfoA), reinterpret_cast<void**>(&gGetNameInfoAOriginal) },
            { L"Winhttp.dll", "WinHttpAddRequestHeaders", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpAddRequestHeadersHook, reinterpret_cast<void*>(&HookedWinHttpAddRequestHeaders), reinterpret_cast<void**>(&gWinHttpAddRequestHeadersOriginal) },
            { L"Winhttp.dll", "WinHttpSetCredentials", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpSetCredentialsHook, reinterpret_cast<void*>(&HookedWinHttpSetCredentials), reinterpret_cast<void**>(&gWinHttpSetCredentialsOriginal) },
            { L"Winhttp.dll", "WinHttpCrackUrl", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpCrackUrlHook, reinterpret_cast<void*>(&HookedWinHttpCrackUrl), reinterpret_cast<void**>(&gWinHttpCrackUrlOriginal) },
            { L"Winhttp.dll", "WinHttpCreateUrl", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpCreateUrlHook, reinterpret_cast<void*>(&HookedWinHttpCreateUrl), reinterpret_cast<void**>(&gWinHttpCreateUrlOriginal) },
            { L"Winhttp.dll", "WinHttpSetTimeouts", ks::winapi_monitor::EventCategory::kNetwork, &gWinHttpSetTimeoutsHook, reinterpret_cast<void*>(&HookedWinHttpSetTimeouts), reinterpret_cast<void**>(&gWinHttpSetTimeoutsOriginal) },
            { L"Wininet.dll", "HttpQueryInfoW", ks::winapi_monitor::EventCategory::kNetwork, &gHttpQueryInfoWHook, reinterpret_cast<void*>(&HookedHttpQueryInfoW), reinterpret_cast<void**>(&gHttpQueryInfoWOriginal) },
            { L"Wininet.dll", "HttpQueryInfoA", ks::winapi_monitor::EventCategory::kNetwork, &gHttpQueryInfoAHook, reinterpret_cast<void*>(&HookedHttpQueryInfoA), reinterpret_cast<void**>(&gHttpQueryInfoAOriginal) },
            { L"Wininet.dll", "InternetQueryOptionW", ks::winapi_monitor::EventCategory::kNetwork, &gInternetQueryOptionWHook, reinterpret_cast<void*>(&HookedInternetQueryOptionW), reinterpret_cast<void**>(&gInternetQueryOptionWOriginal) },
            { L"Wininet.dll", "InternetQueryOptionA", ks::winapi_monitor::EventCategory::kNetwork, &gInternetQueryOptionAHook, reinterpret_cast<void*>(&HookedInternetQueryOptionA), reinterpret_cast<void**>(&gInternetQueryOptionAOriginal) },
            { L"ntdll.dll", "NtOpenDirectoryObject", ks::winapi_monitor::EventCategory::kProcess, &gNtOpenDirectoryObjectHook, reinterpret_cast<void*>(&HookedNtOpenDirectoryObject), reinterpret_cast<void**>(&gNtOpenDirectoryObjectOriginal) },
            { L"ntdll.dll", "NtQueryDirectoryObject", ks::winapi_monitor::EventCategory::kProcess, &gNtQueryDirectoryObjectHook, reinterpret_cast<void*>(&HookedNtQueryDirectoryObject), reinterpret_cast<void**>(&gNtQueryDirectoryObjectOriginal) },
            { L"ntdll.dll", "NtCreateSymbolicLinkObject", ks::winapi_monitor::EventCategory::kProcess, &gNtCreateSymbolicLinkObjectHook, reinterpret_cast<void*>(&HookedNtCreateSymbolicLinkObject), reinterpret_cast<void**>(&gNtCreateSymbolicLinkObjectOriginal) },
            { L"ntdll.dll", "NtOpenSymbolicLinkObject", ks::winapi_monitor::EventCategory::kProcess, &gNtOpenSymbolicLinkObjectHook, reinterpret_cast<void*>(&HookedNtOpenSymbolicLinkObject), reinterpret_cast<void**>(&gNtOpenSymbolicLinkObjectOriginal) },
            { L"ntdll.dll", "NtQuerySymbolicLinkObject", ks::winapi_monitor::EventCategory::kProcess, &gNtQuerySymbolicLinkObjectHook, reinterpret_cast<void*>(&HookedNtQuerySymbolicLinkObject), reinterpret_cast<void**>(&gNtQuerySymbolicLinkObjectOriginal) },
            { L"ntdll.dll", "NtCreateSemaphore", ks::winapi_monitor::EventCategory::kProcess, &gNtCreateSemaphoreHook, reinterpret_cast<void*>(&HookedNtCreateSemaphore), reinterpret_cast<void**>(&gNtCreateSemaphoreOriginal) },
            { L"ntdll.dll", "NtOpenSemaphore", ks::winapi_monitor::EventCategory::kProcess, &gNtOpenSemaphoreHook, reinterpret_cast<void*>(&HookedNtOpenSemaphore), reinterpret_cast<void**>(&gNtOpenSemaphoreOriginal) },
            { L"ntdll.dll", "NtReleaseSemaphore", ks::winapi_monitor::EventCategory::kProcess, &gNtReleaseSemaphoreHook, reinterpret_cast<void*>(&HookedNtReleaseSemaphore), reinterpret_cast<void**>(&gNtReleaseSemaphoreOriginal) }
        };

        bool startsWithWide(const std::wstring& textValue, const std::wstring& prefixValue)
        {
            return textValue.size() >= prefixValue.size()
                && std::equal(prefixValue.begin(), prefixValue.end(), textValue.begin());
        }

        bool isStrongTypedExport(const std::wstring& moduleName, const std::string& procName)
        {
            const std::wstring kTargetKey = makeRawHookKey(moduleName, procName);
            for (const HookBinding& bindingValue : gBindings)
            {
                if (bindingValue.moduleName == nullptr || bindingValue.procName == nullptr)
                {
                    continue;
                }
                if (makeRawHookKey(bindingValue.moduleName, bindingValue.procName) == kTargetKey)
                {
                    return true;
                }
            }
            return false;
        }

        bool isUnsafeRawFallbackModule(const std::wstring& moduleName)
        {
            // isUnsafeRawFallbackModule:
            // - Input: Module name from the Raw Fallback configuration;
            // - Processing: Identify low-level modules unsuitable for generic ABI fallback hooks.
            // - Returns: true indicates the Raw enumeration should skip this module; strong-type hooks and precise Fake Success are unaffected.
            // Reason: ntdll exports syscall, loader, runtime, and internal dispatch surfaces. Even excluding Nt/Rtl/Ldr prefixes,
            //   remaining exports may be frequently called in CRT/loader/exception handling paths, making generic Raw trampoline too risky.
            return normalizeModuleNameForMatch(moduleName) == L"ntdll";
        }

        bool matchesRawDenyPattern(const std::string& procName, const std::wstring& patternText)
        {
            if (procName.empty() || patternText.empty())
            {
                return false;
            }

            const std::wstring kLowerProcName = toLowerWide(ansiToWide(procName.c_str()));
            std::wstring lowerPattern = toLowerWide(patternText);
            if (!lowerPattern.empty() && lowerPattern.back() == L'*')
            {
                lowerPattern.pop_back();
                return !lowerPattern.empty() && startsWithWide(kLowerProcName, lowerPattern);
            }
            return kLowerProcName == lowerPattern;
        }

        std::vector<std::wstring> splitRawDenyPatternText(const wchar_t* const patternText)
        {
            // splitRawDenyPatternText:
            // - Input: built-in Raw blacklist text from shared protocol;
            // - Processing: Split by semicolon, comma, or newline, and trim leading/trailing whitespace from each item.
            // - Return: List of rules available for matchesRawDenyPattern to match item by item.
            std::vector<std::wstring> patternList;
            if (patternText == nullptr || patternText[0] == L'\0')
            {
                return patternList;
            }

            std::wstring currentPattern;
            const auto kFlushPattern = [&patternList, &currentPattern]() {
                const auto kFirstIt = std::find_if_not(
                    currentPattern.begin(),
                    currentPattern.end(),
                    [](const wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n'; });
                const auto kLastIt = std::find_if_not(
                    currentPattern.rbegin(),
                    currentPattern.rend(),
                    [](const wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n'; }).base();
                if (kFirstIt < kLastIt)
                {
                    patternList.emplace_back(kFirstIt, kLastIt);
                }
                currentPattern.clear();
            };

            for (const wchar_t kCh : std::wstring(patternText))
            {
                if (kCh == L';' || kCh == L',' || kCh == L'\r' || kCh == L'\n')
                {
                    kFlushPattern();
                    continue;
                }
                currentPattern.push_back(kCh);
            }
            kFlushPattern();
            return patternList;
        }

        const std::vector<std::wstring>& defaultRawDenyPatterns()
        {
            // defaultRawDenyPatterns:
            // - Inputs: None;
            // - Processing: Lazy-load the shared default deny list to avoid repeatedly splitting the string for every enumeration of exports;
            // - Returns: In-process read-only rule list; caller must not modify it.
            static const std::vector<std::wstring> kDefaultPatternList =
                splitRawDenyPatternText(ks::winapi_monitor::kDefaultRawHookDenyList);
            return kDefaultPatternList;
        }

        bool isRawDeniedByConfig(const std::string& procName)
        {
            const MonitorConfig& configValue = activeConfig();
            if (configValue.rawUseDefaultDenyList)
            {
                for (const std::wstring& patternText : defaultRawDenyPatterns())
                {
                    if (matchesRawDenyPattern(procName, patternText))
                    {
                        return true;
                    }
                }
            }

            // User-provided extra deny list always active:
            // - The default deny list can be disabled by the user;
            // - The custom rules below still serve as a fallback for Raw Hooks, facilitating temporary suppression of noisy APIs from specific target processes.
            for (const std::wstring& patternText : configValue.rawDenyList)
            {
                if (matchesRawDenyPattern(procName, patternText))
                {
                    return true;
                }
            }
            return false;
        }

        bool exportNameLooksHookable(const std::string& procName)
        {
            if (procName.empty())
            {
                return false;
            }
            if (procName[0] == '?' || procName[0] == '_')
            {
                return false;
            }
            for (const unsigned char kCh : procName)
            {
                if (kCh < 0x20 || kCh >= 0x7F)
                {
                    return false;
                }
            }
            return true;
        }

        ks::winapi_monitor::EventCategory inferRawHookCategory(const std::wstring& moduleName, const std::string& procName)
        {
            const std::wstring kModuleLower = toLowerWide(moduleName);
            const std::string kProcLower = toLowerAnsi(procName);
            if (kModuleLower == L"ws2_32.dll" || kModuleLower == L"wininet.dll" || kModuleLower == L"winhttp.dll"
                || kModuleLower == L"iphlpapi.dll" || kModuleLower == L"dnsapi.dll" || kModuleLower == L"netapi32.dll"
                || kModuleLower == L"urlmon.dll" || kModuleLower == L"wldap32.dll")
            {
                return ks::winapi_monitor::EventCategory::kNetwork;
            }
            if (kProcLower.rfind("reg", 0) == 0 || kProcLower.find("key") != std::string::npos)
            {
                return ks::winapi_monitor::EventCategory::kRegistry;
            }
            if (kProcLower.find("file") != std::string::npos || kProcLower.find("directory") != std::string::npos
                || kProcLower.find("path") != std::string::npos || kProcLower.find("pipe") != std::string::npos)
            {
                return ks::winapi_monitor::EventCategory::kFile;
            }
            if (kProcLower.find("library") != std::string::npos || kProcLower.find("module") != std::string::npos
                || kProcLower.rfind("ldr", 0) == 0)
            {
                return ks::winapi_monitor::EventCategory::kLoader;
            }
            return ks::winapi_monitor::EventCategory::kProcess;
        }

        bool enumerateNamedExports(HMODULE moduleHandle, std::vector<std::string>* exportNamesOut)
        {
            if (moduleHandle == nullptr || exportNamesOut == nullptr)
            {
                return false;
            }
            exportNamesOut->clear();

            const auto* const kBasePointer = reinterpret_cast<const unsigned char*>(moduleHandle);
            const auto* const kDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(kBasePointer);
            if (kDosHeader->e_magic != IMAGE_DOS_SIGNATURE || kDosHeader->e_lfanew <= 0)
            {
                return false;
            }

            const auto* const kNtHeader = reinterpret_cast<const IMAGE_NT_HEADERS64*>(kBasePointer + kDosHeader->e_lfanew);
            if (kNtHeader->Signature != IMAGE_NT_SIGNATURE)
            {
                return false;
            }

            const IMAGE_DATA_DIRECTORY& exportDirectory =
                kNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (exportDirectory.VirtualAddress == 0 || exportDirectory.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
            {
                return false;
            }

            const DWORD kImageSize = kNtHeader->OptionalHeader.SizeOfImage;
            const auto kRvaToPointer = [kBasePointer, kImageSize](const DWORD rvaValue) -> const void* {
                if (rvaValue == 0 || rvaValue >= kImageSize)
                {
                    return nullptr;
                }
                return kBasePointer + rvaValue;
            };

            const auto* const kExportTable = static_cast<const IMAGE_EXPORT_DIRECTORY*>(
                kRvaToPointer(exportDirectory.VirtualAddress));
            if (kExportTable == nullptr || kExportTable->NumberOfNames == 0 || kExportTable->AddressOfNames == 0)
            {
                return false;
            }

            const auto* const kNameRvaList = static_cast<const DWORD*>(kRvaToPointer(kExportTable->AddressOfNames));
            if (kNameRvaList == nullptr)
            {
                return false;
            }

            exportNamesOut->reserve(kExportTable->NumberOfNames);
            for (DWORD indexValue = 0; indexValue < kExportTable->NumberOfNames; ++indexValue)
            {
                const char* const kNamePointer = static_cast<const char*>(kRvaToPointer(kNameRvaList[indexValue]));
                if (kNamePointer == nullptr || kNamePointer[0] == '\0')
                {
                    continue;
                }
                exportNamesOut->push_back(kNamePointer);
            }

            std::sort(exportNamesOut->begin(), exportNamesOut->end());
            exportNamesOut->erase(
                std::unique(exportNamesOut->begin(), exportNamesOut->end()),
                exportNamesOut->end());
            return !exportNamesOut->empty();
        }

        bool tryInstallRawHookBinding(RawHookBinding& bindingValue)
        {
            if (bindingValue.hookRecord.installed || bindingValue.hookRecord.permanentlyDisabled)
            {
                return bindingValue.hookRecord.installed;
            }
            if (bindingValue.entryStubAddress == nullptr)
            {
                bindingValue.entryStubAddress = buildRawEntryStub(&bindingValue);
                if (bindingValue.entryStubAddress == nullptr)
                {
                    bindingValue.hookRecord.permanentlyDisabled = true;
                    return false;
                }
            }

            std::wstring ignoredErrorText;
            const InlineHookInstallResult kInstallResult = installInlineHook(
                bindingValue.moduleName.c_str(),
                bindingValue.procName.c_str(),
                bindingValue.entryStubAddress,
                &bindingValue.hookRecord,
                &bindingValue.originalAddress,
                &ignoredErrorText);
            if (kInstallResult == InlineHookInstallResult::kInstalled)
            {
                return true;
            }
            if (kInstallResult == InlineHookInstallResult::kPermanentFailure)
            {
                bindingValue.hookRecord.permanentlyDisabled = true;
            }
            return false;
        }

        bool installFakeSuccessHooks(std::wstring* const detailTextOut)
        {
            // installFakeSuccessHooks:
            // - Input: Fake Success rule set prepared by buildFakeSuccessRuleIndex;
            // - Handling: Only install precise module!api rules not covered by the strong-type table when fake_success_raw_fallback=1.
            // - Return: true if at least one Fake Success rule is installed or installation succeeded.
            const MonitorConfig& configValue = activeConfig();
            auto& ruleList = fakeSuccessRules();
            if (!configValue.fakeSuccessEnabled || !configValue.fakeSuccessRawFallback || ruleList.empty())
            {
                return false;
            }

            bool installedAny = false;
            for (std::unique_ptr<FakeSuccessRuntimeRule>& rulePointer : ruleList)
            {
                if (rulePointer == nullptr)
                {
                    continue;
                }
                installedAny = tryInstallFakeSuccessRule(*rulePointer, std::nullopt, detailTextOut) || installedAny;
            }
            return installedAny;
        }

        void uninstallFakeSuccessHooks()
        {
            // uninstallFakeSuccessHooks:
            // - Input: None; uses the current Fake Success runtime rule table;
            // - Processing: Revert inline patch, release trampoline and dynamic fake-return stub, and clear the index.
            // - Returns: Nothing.
            auto& ruleList = fakeSuccessRules();
            for (std::unique_ptr<FakeSuccessRuntimeRule>& rulePointer : ruleList)
            {
                if (rulePointer == nullptr)
                {
                    continue;
                }
                uninstallInlineHook(&rulePointer->hookRecord);
                rulePointer->originalAddress = nullptr;
                freeFakeSuccessEntryStub(rulePointer->entryStubAddress);
                rulePointer->entryStubAddress = nullptr;
            }
            ruleList.clear();
            fakeSuccessRuleMap().clear();
        }

        void discoverRawHookBindingsForLoadedModules()
        {
            const MonitorConfig& configValue = activeConfig();
            if (!configValue.enableRawFallback)
            {
                return;
            }

            constexpr std::size_t kMaxRawExportsPerModule = 768;
            std::vector<std::string> exportNameList;
            for (const std::wstring& moduleName : configValue.rawModuleList)
            {
                if (moduleName.empty())
                {
                    continue;
                }
                if (isUnsafeRawFallbackModule(moduleName))
                {
                    continue;
                }

                HMODULE moduleHandle = ::GetModuleHandleW(moduleName.c_str());
                if (moduleHandle == nullptr)
                {
                    continue;
                }
                if (!enumerateNamedExports(moduleHandle, &exportNameList))
                {
                    continue;
                }

                std::size_t acceptedCount = 0;
                for (const std::string& exportName : exportNameList)
                {
                    if (acceptedCount >= kMaxRawExportsPerModule)
                    {
                        break;
                    }
                    if (!exportNameLooksHookable(exportName)
                        || isStrongTypedExport(moduleName, exportName)
                        || (configValue.fakeSuccessRawFallback && findFakeSuccessRule(moduleName, exportName) != nullptr)
                        || isRawDeniedByConfig(exportName))
                    {
                        continue;
                    }

                    const std::wstring kRawKey = makeRawHookKey(moduleName, exportName);
                    auto& rawKeySet = rawHookKeys();
                    auto& rawBindingList = rawBindings();
                    if (rawKeySet.find(kRawKey) != rawKeySet.end())
                    {
                        continue;
                    }

                    auto bindingPointer = std::make_unique<RawHookBinding>();
                    bindingPointer->moduleName = moduleName;
                    bindingPointer->procName = exportName;
                    bindingPointer->procNameWide = ansiToWide(exportName.c_str());
                    bindingPointer->categoryValue = inferRawHookCategory(moduleName, exportName);
                    rawKeySet.insert(kRawKey);
                    rawBindingList.push_back(std::move(bindingPointer));
                    ++acceptedCount;
                }
            }
        }

        bool installRawFallbackHooks()
        {
            const MonitorConfig& configValue = activeConfig();
            if (!configValue.enableRawFallback)
            {
                return false;
            }

            discoverRawHookBindingsForLoadedModules();

            bool installedAny = false;
            for (std::unique_ptr<RawHookBinding>& bindingPointer : rawBindings())
            {
                if (bindingPointer == nullptr)
                {
                    continue;
                }
                installedAny = tryInstallRawHookBinding(*bindingPointer) || installedAny;
            }
            return installedAny;
        }

        void uninstallRawFallbackHooks()
        {
            auto& rawBindingList = rawBindings();
            for (std::unique_ptr<RawHookBinding>& bindingPointer : rawBindingList)
            {
                if (bindingPointer == nullptr)
                {
                    continue;
                }
                uninstallInlineHook(&bindingPointer->hookRecord);
                bindingPointer->originalAddress = nullptr;
                freeRawEntryStub(bindingPointer->entryStubAddress);
                bindingPointer->entryStubAddress = nullptr;
            }
            rawBindingList.clear();
            rawHookKeys().clear();
        }

        // retryPendingHooksUnlocked:
        // - Input: None; uses the global binding table.
        // - Processing: Install retryable hooks that are pending when the caller already holds g_hookOperationMutex.
        // - Returns: None. Failure details are reflected in the subsequent installConfiguredHooks diagnostics.
        void retryPendingHooksUnlocked()
        {
            for (HookBinding& bindingValue : gBindings)
            {
                (void)tryInstallBinding(bindingValue, nullptr);
            }
            (void)installFakeSuccessHooks(nullptr);
            (void)installRawFallbackHooks();
        }

        // retryPendingHooksFromHook:
        // - Inputs: None;
        // - Processing: after the LoadLibrary/LdrLoadDll hooked wrapper returns, try to acquire the hook lock.
        // - Return: No return value; skip this round of patching if the lock is busy.
        void retryPendingHooksFromHook()
        {
            if (gHookOperationMutex.try_lock())
            {
                ScopedInlineHookInternalBypass hookOperationBypassScope;
                retryPendingHooksUnlocked();
                gHookOperationMutex.unlock();
            }
        }

    }

    bool installConfiguredHooks(std::wstring* errorTextOut)
    {
        const std::lock_guard<std::mutex> kLock(gHookOperationMutex);
        ScopedInlineHookInternalBypass hookOperationBypassScope;
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        bool hasEnabledCategory = false;
        bool installedAny = false;
        std::wstring failureText;
        buildFakeSuccessRuleIndex();
        for (HookBinding& bindingValue : gBindings)
        {
            hasEnabledCategory = categoryEnabled(bindingValue.categoryValue) || hasEnabledCategory;
            installedAny = tryInstallBinding(bindingValue, &failureText) || installedAny;
        }
        hasEnabledCategory = activeConfig().enableRawFallback
            || (activeConfig().fakeSuccessEnabled && !fakeSuccessRules().empty())
            || hasEnabledCategory;
        installedAny = installFakeSuccessHooks(&failureText) || installedAny;
        installedAny = installRawFallbackHooks() || installedAny;
        if (!hasEnabledCategory)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"No hook category is enabled in current config.";
            }
            return false;
        }
        if (!installedAny && errorTextOut != nullptr)
        {
            *errorTextOut = failureText.empty()
                ? std::wstring(L"No hook installed successfully.")
                : failureText;
            return false;
        }
        if (installedAny && errorTextOut != nullptr)
        {
            *errorTextOut = failureText;
        }
        return installedAny;
    }

    void uninstallConfiguredHooks()
    {
        const std::lock_guard<std::mutex> kLock(gHookOperationMutex);
        ScopedInlineHookInternalBypass hookOperationBypassScope;
        for (HookBinding& bindingValue : gBindings)
        {
            uninstallInlineHook(bindingValue.hookRecord);
            if (bindingValue.originalOut != nullptr)
            {
                *bindingValue.originalOut = nullptr;
            }
        }
        uninstallRawFallbackHooks();
        uninstallFakeSuccessHooks();
    }
    void retryPendingHooks()
    {
        const std::lock_guard<std::mutex> kLock(gHookOperationMutex);
        ScopedInlineHookInternalBypass hookOperationBypassScope;
        retryPendingHooksUnlocked();
    }
}
