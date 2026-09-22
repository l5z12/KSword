#pragma once
#include <Windows.h>
#include <winternl.h>

#include <map>
#include <string>
#include <vector>
#include <winternl.h>

void kswordNtMain();

// Reuse the structure and enumeration definitions from the original code.
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
    UCHAR typeIndex;
    CHAR reservedByte;
    ULONG poolType;
    ULONG defaultPagedPoolCharge;
    ULONG defaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPES_INFORMATION {
    ULONG numberOfTypes;
} OBJECT_TYPES_INFORMATION, * POBJECT_TYPES_INFORMATION;

typedef enum MyObjectInformationClass {
    kOicObjectBasicInformation = 0,
    kOicObjectNameInformation = 1,
    kOicObjectTypeInformation = 2,
    kOicObjectTypesInformation = 3,
    kOicObjectHandleFlagInformation = 4,
    kOicObjectSessionInformation = 5,
} MyObjectInformationClass;

// Declare external functions and global variables
extern "C" NTSTATUS NTAPI NtQueryObject(
    HANDLE objectHandle,
    OBJECT_INFORMATION_CLASS objectInformationClass,
    PVOID objectInformation,
    ULONG objectInformationLength,
    PULONG returnLength
);

extern std::map<UCHAR, std::wstring> gTypeMap;
extern bool gIsQueryCompleted;
extern bool gIsQuerySuccess;

// Function declaration
std::map<UCHAR, std::wstring> queryObjectTypeIndexMap();
void RenderTypeIndexWindow();
