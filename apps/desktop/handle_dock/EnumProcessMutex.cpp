// EnumProcessHandle.cpp: This file contains the 'main' function. Program execution begins and ends here.
//

#include <iostream>
#include <functional>
#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <ntstatus.h>
#include <iostream>

// Structure for type information of kernel objects enumerated by NtQueryObject
typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING typeName;
	ULONG totalNumberOfObjects;
	ULONG totalNumberOfHandles;
	ULONG totalPagedPoolUsage;
	ULONG totalNonPagedPoolUsage;
	ULONG totalNamePoolUsage;
	ULONG totalHandleTableUsage;
	ULONG highWaterNumberOfObjects;
	ULONG highWaterNumberOfHandles;
	ULONG highWaterPagedPoolUsage;
	ULONG highWaterNonPagedPoolUsage;
	ULONG highWaterNamePoolUsage;
	ULONG highWaterHandleTableUsage;
	ULONG invalidAttributes;
	GENERIC_MAPPING genericMapping;
	ULONG validAccessMask;
	BOOLEAN securityRequired;
	BOOLEAN maintainHandleCount;
	ULONG poolType;
	ULONG defaultPagedPoolCharge;
	ULONG defaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

// A data structure for handle information.
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	ULONG processId;
	BYTE objectTypeNumber;
	BYTE flags;
	USHORT handle;
	PVOID object;
	ACCESS_MASK grantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// Retrieve detailed information for a handle,
// including the type name and the kernel object name.
// bType - Get the handle type name.
std::wstring queryHandleNameInfo(HANDLE handle, BOOL bType)
{
	std::wstring strName;
	const HMODULE kHDll = LoadLibrary(L"ntdll.dll");
	if (kHDll == NULL)
	{
		return strName;
	}
	typedef NTSTATUS(NTAPI* NtQueryObjectFunc)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
	NtQueryObjectFunc ntQueryObject = (NtQueryObjectFunc)GetProcAddress(kHDll, "NtQueryObject");

	do
	{
		if (ntQueryObject == NULL)
		{
			break;
		}
		// Get information
		const DWORD kObjectNameInformation = 1;
		OBJECT_INFORMATION_CLASS infoType = bType ? ObjectTypeInformation :
			OBJECT_INFORMATION_CLASS(kObjectNameInformation);
		std::vector<BYTE> objVec(256);
		ULONG bytesOfRead = 0;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		do
		{
			status = ntQueryObject(handle, infoType, (void*)objVec.data(), objVec.size(), &bytesOfRead);
			if (STATUS_INFO_LENGTH_MISMATCH == status)
			{
				objVec.resize(objVec.size() * 2);
				continue;
			}
			break;
		} while (TRUE);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		objVec.resize(bytesOfRead);

		if (bType)
		{
			const OBJECT_TYPE_INFORMATION* pObjType =
				reinterpret_cast<OBJECT_TYPE_INFORMATION*>(objVec.data());
			strName = std::wstring(pObjType->typeName.Buffer, pObjType->typeName.Length / sizeof(WCHAR));
		}
		else
		{
			const UNICODE_STRING* pObjName = reinterpret_cast<UNICODE_STRING*>(objVec.data());
			strName = std::wstring(pObjName->Buffer, pObjName->Length / sizeof(WCHAR));
		}

	} while (FALSE);

	FreeLibrary(kHDll);
	return strName;
}

// Handle traversal helper class
class WalkHandleHelper
{
public:
	WalkHandleHelper(const SYSTEM_HANDLE_TABLE_ENTRY_INFO& handleInfo, const HANDLE& handle)
		:handleInfo_(handleInfo), handle_(handle) {
	}
	DWORD getProcessId() const { return handleInfo_.processId; }
	std::wstring getTypeName() const
	{
		return queryHandleNameInfo(handle_, TRUE);
	}
	std::wstring getObjectName() const
	{
		return queryHandleNameInfo(handle_, FALSE);
	}

private:
	const SYSTEM_HANDLE_TABLE_ENTRY_INFO& handleInfo_;
	const HANDLE& handle_;
};

// enumerate system handles
void walkHandle(const std::function<void(const WalkHandleHelper&)>& functor)
{
	const HMODULE kHDll = LoadLibrary(L"ntdll.dll");
	if (kHDll == NULL)
	{
		return;
	}

	// Use NtQuerySystemInformation to retrieve SystemHandleInformation (16) to obtain handle information for all handles in the system.
	const DWORD kSystemHandleInformation = 16;

	// Data structure for retrieving all handles in the system via SystemHandleInformation.
	typedef struct _SYSTEM_HANDLE_INFORMATION
	{
		ULONG handleCount;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO handles[1];
	} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


	typedef NTSTATUS(NTAPI* NtQuerySystemInformationFunc)(ULONG, PVOID, ULONG, PULONG);
	NtQuerySystemInformationFunc ntQuerySystemInformation = (NtQuerySystemInformationFunc)
		GetProcAddress(kHDll, "NtQuerySystemInformation");
	const HANDLE kHCurProcess = GetCurrentProcess();
	do
	{
		if (NULL == ntQuerySystemInformation)
		{
			break;
		}
		// Get system handle table.
		std::vector<BYTE> vecData(512);
		ULONG bytesOfRead = 0;
		NTSTATUS status;
		do
		{
			status = ntQuerySystemInformation(kSystemHandleInformation, vecData.data(), vecData.size(), &bytesOfRead);
			if (STATUS_INFO_LENGTH_MISMATCH == status)
			{
				vecData.resize(vecData.size() * 2);
				continue;
			}
			break;
		} while (TRUE);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		vecData.resize(bytesOfRead);

		PSYSTEM_HANDLE_INFORMATION pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)vecData.data();
		for (int i = 0; i < pSysHandleInfo->handleCount; ++i)
		{
			const HANDLE kHOwnProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE,
				pSysHandleInfo->handles[i].processId);
			if (NULL == kHOwnProcess)
			{
				continue;
			}
			HANDLE hDuplicate = NULL;
			// The handle must be duplicated into the current process; otherwise, information about handles owned by other processes cannot be retrieved.
			if (!DuplicateHandle(kHOwnProcess, (HANDLE)pSysHandleInfo->handles[i].handle, kHCurProcess,
				&hDuplicate, 0, 0, DUPLICATE_SAME_ACCESS))
			{
				CloseHandle(kHOwnProcess);
				continue;
			}
			WalkHandleHelper helper(pSysHandleInfo->handles[i], hDuplicate);
			functor(helper);

			CloseHandle(hDuplicate);
			CloseHandle(kHOwnProcess);
		}

	} while (FALSE);

	FreeLibrary(kHDll);
}

// enumerate mutexes of the current process.
void enumCurProcessMutex()
{
	std::wcout << L"Find The Mutex Opened By Current Process:" << std::endl;
	const DWORD kDwCurProcess = GetCurrentProcessId();
	walkHandle([&](const WalkHandleHelper& helper)
		{
			const std::wstring kStrFile(L"File");

			if (helper.getTypeName().find(kStrFile) != std::wstring::npos)
			{
				wprintf(L"ProcessID: %d\n", helper.getProcessId());
				wprintf(L"TypeName: %s\n", helper.getTypeName().c_str());
				//std::wcout << L"ObjectName: " << helper.getObjectName().c_str() << std::endl;
				wchar_t szObjectName[1024] = { 0 };
				swprintf_s(szObjectName, L"ObjectName: %s\n", helper.getObjectName().c_str());
				WriteConsoleW( GetStdHandle(STD_OUTPUT_HANDLE), szObjectName,
					wcslen(szObjectName), NULL, NULL);
				wprintf(L"\n");
			}

		});
}

int wmain(int argc, WCHAR* argv[])
{
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleCP(CP_UTF8);
	HANDLE hMutex = CreateMutexW(NULL, TRUE, NULL);
	HANDLE hGlobalMutex = CreateMutexW(NULL, TRUE, L"TestMutex");
	HANDLE hGlobalNamedMutex = CreateMutexW(NULL, TRUE, L"Global\\TestGlobalMutex");
	enumCurProcessMutex();
	CloseHandle(hMutex);
	CloseHandle(hGlobalMutex);
	CloseHandle(hGlobalNamedMutex);

	std::wcout << L"Press any key to exit..." << std::endl;
	getchar();
	return 0;
}
