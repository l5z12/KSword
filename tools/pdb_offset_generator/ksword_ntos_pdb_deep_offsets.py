#!/usr/bin/env python3
"""
Ksword ntoskrnl PDB deep offset extractor.

Purpose:
- Read the TPI type stream from ntkrnlmp.pdb in the local PDB cache.
- Extracts structure fields usable for runtime detail pages of processes, threads, objects, handles, modules, drivers, memory, ALPC, etc.
- Output: JSON/CSV serving as an offline fact base for subsequent DynData v4 item IDs, detailed IOCTLs, and UI display fields.

Boundary:
- Reads PDB files only; does not download symbols, run target programs, or access drivers.
- By default, parses only the target type without full module recursive deep digging.
- The generated artifact is audit/backup data and must not be used directly as an R0 arbitrary-read allowlist.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_LLVM_PDBUTIL = r"D:\Software\VS\VC\Tools\Llvm\x64\bin\llvm-pdbutil.exe"
DEFAULT_PDB_PATH = r"E:\KswordPDB\PDB\pdb-cache\amd64\ntkrnlmp.pdb\F923DA2D238E7C7CE180B962B19A37811\ntkrnlmp.pdb"
DEFAULT_OUTPUT_DIR = r"D:\Temp\ksword_pdb_deep_offsets"

# These types cover basic runtime instances in the current target, including process details, thread details, window-related low-level objects, handles, drivers, memory, and IPC.
# Note: ntkrnlmp does not include private types for win32k window USER objects; window GUI types should be further supplemented by win32kbase/win32kfull PDBs.
TARGET_TYPE_GROUPS: dict[str, list[str]] = {
    "process_detail": [
        "_EPROCESS",
        "_KPROCESS",
        "_PEB",
        "_PEB_LDR_DATA",
        "_RTL_USER_PROCESS_PARAMETERS",
        "_PS_PROTECTION",
        "_SE_AUDIT_PROCESS_CREATION_INFO",
        "_MMSUPPORT_FULL",
        "_MMSUPPORT_INSTANCE",
        "_ALPC_PROCESS_CONTEXT",
        "_EJOB",
        "_TOKEN",
        "_SEP_TOKEN_PRIVILEGES",
    ],
    "thread_detail": [
        "_ETHREAD",
        "_KTHREAD",
        "_TEB",
        "_CLIENT_ID",
        "_KAPC_STATE",
        "_KTRAP_FRAME",
        "_KWAIT_BLOCK",
        "_KTHREAD_COUNTERS",
    ],
    "handle_object_detail": [
        "_HANDLE_TABLE",
        "_HANDLE_TABLE_ENTRY",
        "_HANDLE_TABLE_FREE_LIST",
        "_OBJECT_HEADER",
        "_OBJECT_HEADER_NAME_INFO",
        "_OBJECT_HEADER_CREATOR_INFO",
        "_OBJECT_HEADER_HANDLE_INFO",
        "_OBJECT_TYPE",
        "_OBJECT_TYPE_INITIALIZER",
        "_OBJECT_DIRECTORY",
        "_OBJECT_DIRECTORY_ENTRY",
    ],
    "module_driver_detail": [
        "_DRIVER_OBJECT",
        "_DEVICE_OBJECT",
        "_DRIVER_EXTENSION",
        "_FAST_IO_DISPATCH",
        "_KLDR_DATA_TABLE_ENTRY",
        "_LDR_DATA_TABLE_ENTRY",
        "_UNLOADED_DRIVERS",
        "_RTL_AVL_TABLE",
        "_RTL_BALANCED_NODE",
        "_RTL_RB_TREE",
    ],
    "memory_section_detail": [
        "_MMVAD",
        "_MMVAD_SHORT",
        "_MMVAD_FLAGS",
        "_MMVAD_FLAGS1",
        "_MMSECTION_FLAGS",
        "_CONTROL_AREA",
        "_SUBSECTION",
        "_SEGMENT",
        "_SECTION_OBJECT",
        "_SECTION",
        "_MMPTE",
        "_MMPFN",
        "_MM_SESSION_SPACE",
        "_MM_SESSION_SPACE_FLAGS",
    ],
    "ipc_alpc_detail": [
        "_ALPC_PORT",
        "_ALPC_COMMUNICATION_INFO",
        "_ALPC_HANDLE_TABLE",
        "_ALPC_COMPLETION_LIST",
        "_KALPC_MESSAGE",
        "_KALPC_MESSAGE_ATTRIBUTES",
        "_KALPC_SECURITY_DATA",
        "_KQUEUE",
        "_KSEMAPHORE",
        "_KEVENT",
        "_KMUTANT",
    ],
    "callback_registry_security": [
        "_CALLBACK_ENTRY",
        "_CALLBACK_ENTRY_ITEM",
        "_EX_CALLBACK",
        "_CM_CALLBACK_CONTEXT_BLOCK",
        "_CM_KEY_CONTROL_BLOCK",
        "_CM_KEY_BODY",
        "_CMHIVE",
        "_HHIVE",
        "_ETW_GUID_ENTRY",
        "_ETW_REG_ENTRY",
        "_SEP_LOGON_SESSION_REFERENCES",
    ],
    "common_kernel_primitives": [
        "_LIST_ENTRY",
        "_SINGLE_LIST_ENTRY",
        "_UNICODE_STRING",
        "_STRING",
        "_EX_PUSH_LOCK",
        "_ERESOURCE",
        "_KLOCK_ENTRY",
        "_KTIMER",
        "_KDPC",
        "_KINTERRUPT",
        "_KPRCB",
        "_KPCR",
        "_KUSER_SHARED_DATA",
    ],
}

# These aliases link the 'complete field fact library' to candidate item names for DynData v3/v4, facilitating subsequent batch numbering and IOCTL consumption.
KSWORD_ITEM_ALIASES: dict[tuple[str, str], str] = {
    ("_EPROCESS", "UniqueProcessId"): "EpUniqueProcessId",
    ("_EPROCESS", "ActiveProcessLinks"): "EpActiveProcessLinks",
    ("_EPROCESS", "ThreadListHead"): "EpThreadListHead",
    ("_EPROCESS", "ImageFileName"): "EpImageFileName",
    ("_EPROCESS", "Token"): "EpToken",
    ("_EPROCESS", "Flags"): "EpFlags",
    ("_EPROCESS", "Flags2"): "EpFlags2",
    ("_EPROCESS", "RundownProtect"): "EpRundownProtect",
    ("_EPROCESS", "ProcessLock"): "EpProcessLock",
    ("_EPROCESS", "CreateTime"): "EpCreateTime",
    ("_EPROCESS", "ExitTime"): "EpExitTime",
    ("_EPROCESS", "ExitStatus"): "EpExitStatus",
    ("_EPROCESS", "Peb"): "EpPeb",
    ("_EPROCESS", "Session"): "EpSession",
    ("_EPROCESS", "Win32Process"): "EpWin32Process",
    ("_EPROCESS", "WoW64Process"): "EpWow64Process",
    ("_EPROCESS", "InheritedFromUniqueProcessId"): "EpInheritedFromUniqueProcessId",
    ("_EPROCESS", "SeAuditProcessCreationInfo"): "EpSeAuditProcessCreationInfo",
    ("_EPROCESS", "Job"): "EpJob",
    ("_EPROCESS", "DeviceMap"): "EpDeviceMap",
    ("_EPROCESS", "DebugPort"): "EpDebugPort",
    ("_EPROCESS", "ExceptionPortData"): "EpExceptionPortData",
    ("_EPROCESS", "SectionBaseAddress"): "EpSectionBaseAddress",
    ("_EPROCESS", "ImageFilePointer"): "EpImageFilePointer",
    ("_EPROCESS", "PriorityClass"): "EpPriorityClass",
    ("_EPROCESS", "ActiveThreads"): "EpActiveThreads",
    ("_EPROCESS", "VadRoot"): "EpVadRoot",
    ("_EPROCESS", "VadHint"): "EpVadHint",
    ("_EPROCESS", "CloneRoot"): "EpCloneRoot",
    ("_EPROCESS", "NumberOfPrivatePages"): "EpNumberOfPrivatePages",
    ("_EPROCESS", "NumberOfLockedPages"): "EpNumberOfLockedPages",
    ("_EPROCESS", "CommitCharge"): "EpCommitCharge",
    ("_EPROCESS", "CommitChargePeak"): "EpCommitChargePeak",
    ("_EPROCESS", "PeakVirtualSize"): "EpPeakVirtualSize",
    ("_EPROCESS", "VirtualSize"): "EpVirtualSize",
    ("_EPROCESS", "SessionProcessLinks"): "EpSessionProcessLinks",
    ("_EPROCESS", "MitigationFlags"): "EpMitigationFlags",
    ("_EPROCESS", "MitigationFlags2"): "EpMitigationFlags2",
    ("_EPROCESS", "ProcessQuotaUsage"): "EpProcessQuotaUsage",
    ("_EPROCESS", "ProcessQuotaPeak"): "EpProcessQuotaPeak",
    ("_EPROCESS", "AddressCreationLock"): "EpAddressCreationLock",
    ("_EPROCESS", "PageTableCommitmentLock"): "EpPageTableCommitmentLock",
    ("_EPROCESS", "RotateInProgress"): "EpRotateInProgress",
    ("_EPROCESS", "ForkInProgress"): "EpForkInProgress",
    ("_EPROCESS", "CommitChargeJob"): "EpCommitChargeJob",
    ("_EPROCESS", "Cookie"): "EpCookie",
    ("_EPROCESS", "WorkingSetWatch"): "EpWorkingSetWatch",
    ("_EPROCESS", "Win32WindowStation"): "EpWin32WindowStation",
    ("_EPROCESS", "OwnerProcessId"): "EpOwnerProcessId",
    ("_EPROCESS", "QuotaBlock"): "EpQuotaBlock",
    ("_EPROCESS", "EtwDataSource"): "EpEtwDataSource",
    ("_EPROCESS", "PageDirectoryPte"): "EpPageDirectoryPte",
    ("_EPROCESS", "SecurityPort"): "EpSecurityPort",
    ("_EPROCESS", "JobLinks"): "EpJobLinks",
    ("_EPROCESS", "HighestUserAddress"): "EpHighestUserAddress",
    ("_EPROCESS", "ImagePathHash"): "EpImagePathHash",
    ("_EPROCESS", "DefaultHardErrorProcessing"): "EpDefaultHardErrorProcessing",
    ("_EPROCESS", "LastThreadExitStatus"): "EpLastThreadExitStatus",
    ("_EPROCESS", "PrefetchTrace"): "EpPrefetchTrace",
    ("_EPROCESS", "LockedPagesList"): "EpLockedPagesList",
    ("_EPROCESS", "ReadOperationCount"): "EpReadOperationCount",
    ("_EPROCESS", "WriteOperationCount"): "EpWriteOperationCount",
    ("_EPROCESS", "OtherOperationCount"): "EpOtherOperationCount",
    ("_EPROCESS", "ReadTransferCount"): "EpReadTransferCount",
    ("_EPROCESS", "WriteTransferCount"): "EpWriteTransferCount",
    ("_EPROCESS", "OtherTransferCount"): "EpOtherTransferCount",
    ("_EPROCESS", "CommitChargeLimit"): "EpCommitChargeLimit",
    ("_EPROCESS", "Vm"): "EpVm",
    ("_EPROCESS", "MmProcessLinks"): "EpMmProcessLinks",
    ("_EPROCESS", "ModifiedPageCount"): "EpModifiedPageCount",
    ("_EPROCESS", "VadCount"): "EpVadCount",
    ("_EPROCESS", "VadPhysicalPages"): "EpVadPhysicalPages",
    ("_EPROCESS", "VadPhysicalPagesLimit"): "EpVadPhysicalPagesLimit",
    ("_EPROCESS", "AlpcContext"): "EpAlpcContext",
    ("_EPROCESS", "TimerResolutionLink"): "EpTimerResolutionLink",
    ("_EPROCESS", "TimerResolutionStackRecord"): "EpTimerResolutionStackRecord",
    ("_EPROCESS", "RequestedTimerResolution"): "EpRequestedTimerResolution",
    ("_EPROCESS", "SmallestTimerResolution"): "EpSmallestTimerResolution",
    ("_EPROCESS", "InvertedFunctionTable"): "EpInvertedFunctionTable",
    ("_EPROCESS", "InvertedFunctionTableLock"): "EpInvertedFunctionTableLock",
    ("_EPROCESS", "ActiveThreadsHighWatermark"): "EpActiveThreadsHighWatermark",
    ("_EPROCESS", "LargePrivateVadCount"): "EpLargePrivateVadCount",
    ("_EPROCESS", "ThreadListLock"): "EpThreadListLock",
    ("_EPROCESS", "WnfContext"): "EpWnfContext",
    ("_EPROCESS", "Flags3"): "EpFlags3",
    ("_EPROCESS", "DiskCounters"): "EpDiskCounters",
    ("_TOKEN", "TokenSource"): "TokTokenSource",
    ("_TOKEN", "TokenId"): "TokTokenId",
    ("_TOKEN", "AuthenticationId"): "TokAuthenticationId",
    ("_TOKEN", "ParentTokenId"): "TokParentTokenId",
    ("_TOKEN", "ExpirationTime"): "TokExpirationTime",
    ("_TOKEN", "TokenLock"): "TokTokenLock",
    ("_TOKEN", "ModifiedId"): "TokModifiedId",
    ("_TOKEN", "Privileges"): "TokPrivileges",
    ("_TOKEN", "AuditPolicy"): "TokAuditPolicy",
    ("_TOKEN", "SessionId"): "TokSessionId",
    ("_TOKEN", "UserAndGroupCount"): "TokUserAndGroupCount",
    ("_TOKEN", "RestrictedSidCount"): "TokRestrictedSidCount",
    ("_TOKEN", "VariableLength"): "TokVariableLength",
    ("_TOKEN", "DynamicCharged"): "TokDynamicCharged",
    ("_TOKEN", "DynamicAvailable"): "TokDynamicAvailable",
    ("_TOKEN", "DefaultOwnerIndex"): "TokDefaultOwnerIndex",
    ("_TOKEN", "UserAndGroups"): "TokUserAndGroups",
    ("_TOKEN", "RestrictedSids"): "TokRestrictedSids",
    ("_TOKEN", "PrimaryGroup"): "TokPrimaryGroup",
    ("_TOKEN", "DynamicPart"): "TokDynamicPart",
    ("_TOKEN", "DefaultDacl"): "TokDefaultDacl",
    ("_TOKEN", "TokenType"): "TokTokenType",
    ("_TOKEN", "ImpersonationLevel"): "TokImpersonationLevel",
    ("_TOKEN", "TokenFlags"): "TokTokenFlags",
    ("_TOKEN", "TokenInUse"): "TokTokenInUse",
    ("_TOKEN", "IntegrityLevelIndex"): "TokIntegrityLevelIndex",
    ("_TOKEN", "MandatoryPolicy"): "TokMandatoryPolicy",
    ("_TOKEN", "LogonSession"): "TokLogonSession",
    ("_TOKEN", "OriginatingLogonSession"): "TokOriginatingLogonSession",
    ("_TOKEN", "SidHash"): "TokSidHash",
    ("_TOKEN", "RestrictedSidHash"): "TokRestrictedSidHash",
    ("_TOKEN", "pSecurityAttributes"): "TokPSecurityAttributes",
    ("_TOKEN", "Package"): "TokPackage",
    ("_TOKEN", "Capabilities"): "TokCapabilities",
    ("_TOKEN", "CapabilityCount"): "TokCapabilityCount",
    ("_TOKEN", "CapabilitiesHash"): "TokCapabilitiesHash",
    ("_TOKEN", "LowboxNumberEntry"): "TokLowboxNumberEntry",
    ("_TOKEN", "LowboxHandlesEntry"): "TokLowboxHandlesEntry",
    ("_TOKEN", "pClaimAttributes"): "TokPClaimAttributes",
    ("_TOKEN", "TrustLevelSid"): "TokTrustLevelSid",
    ("_TOKEN", "TrustLinkedToken"): "TokTrustLinkedToken",
    ("_TOKEN", "IntegrityLevelSidValue"): "TokIntegrityLevelSidValue",
    ("_TOKEN", "TokenSidValues"): "TokTokenSidValues",
    ("_TOKEN", "SessionObject"): "TokSessionObject",
    ("_TOKEN", "VariablePart"): "TokVariablePart",
    ("_EPROCESS", "ObjectTable"): "EpObjectTable",
    ("_EPROCESS", "SectionObject"): "EpSectionObject",
    ("_EPROCESS", "Protection"): "EpProtection",
    ("_EPROCESS", "SignatureLevel"): "EpSignatureLevel",
    ("_EPROCESS", "SectionSignatureLevel"): "EpSectionSignatureLevel",
    ("_ETHREAD", "Cid"): "EtCid",
    ("_ETHREAD", "ThreadListEntry"): "EtThreadListEntry",
    ("_ETHREAD", "StartAddress"): "EtStartAddress",
    ("_ETHREAD", "Win32StartAddress"): "EtWin32StartAddress",
    ("_KTHREAD", "Process"): "KtProcess",
    ("_KTHREAD", "InitialStack"): "KtInitialStack",
    ("_KTHREAD", "StackLimit"): "KtStackLimit",
    ("_KTHREAD", "StackBase"): "KtStackBase",
    ("_KTHREAD", "KernelStack"): "KtKernelStack",
    ("_KTHREAD", "ReadOperationCount"): "KtReadOperationCount",
    ("_KTHREAD", "WriteOperationCount"): "KtWriteOperationCount",
    ("_KTHREAD", "OtherOperationCount"): "KtOtherOperationCount",
    ("_KTHREAD", "ReadTransferCount"): "KtReadTransferCount",
    ("_KTHREAD", "WriteTransferCount"): "KtWriteTransferCount",
    ("_KTHREAD", "OtherTransferCount"): "KtOtherTransferCount",
    ("_HANDLE_TABLE", "TableCode"): "HtTableCode",
    ("_HANDLE_TABLE", "HandleCount"): "HtHandleCount",
    ("_HANDLE_TABLE_ENTRY", "LowValue"): "HteLowValue",
    ("_KLDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"): "KldrInLoadOrderLinks",
    ("_KLDR_DATA_TABLE_ENTRY", "DllBase"): "KldrDllBase",
    ("_KLDR_DATA_TABLE_ENTRY", "SizeOfImage"): "KldrSizeOfImage",
    ("_KLDR_DATA_TABLE_ENTRY", "FullDllName"): "KldrFullDllName",
    ("_KLDR_DATA_TABLE_ENTRY", "BaseDllName"): "KldrBaseDllName",
    ("_KLDR_DATA_TABLE_ENTRY", "Flags"): "KldrFlags",
    ("_DRIVER_OBJECT", "DriverStart"): "DoDriverStart",
    ("_DRIVER_OBJECT", "DriverSize"): "DoDriverSize",
    ("_DRIVER_OBJECT", "DriverSection"): "DoDriverSection",
    ("_DRIVER_OBJECT", "MajorFunction"): "DoMajorFunction",
    ("_DRIVER_OBJECT", "FastIoDispatch"): "DoFastIoDispatch",
    ("_DRIVER_OBJECT", "DriverUnload"): "DoDriverUnload",
    ("_UNLOADED_DRIVERS", "Name"): "UldName",
    ("_UNLOADED_DRIVERS", "StartAddress"): "UldStartAddress",
    ("_UNLOADED_DRIVERS", "EndAddress"): "UldEndAddress",
    ("_UNLOADED_DRIVERS", "CurrentTime"): "UldCurrentTime",
    ("_RTL_AVL_TABLE", "BalancedRoot"): "RtlAvlBalancedRoot",
    ("_RTL_AVL_TABLE", "OrderedPointer"): "RtlAvlOrderedPointer",
    ("_RTL_AVL_TABLE", "WhichOrderedElement"): "RtlAvlWhichOrderedElement",
    ("_RTL_AVL_TABLE", "NumberGenericTableElements"): "RtlAvlNumberGenericTableElements",
    ("_RTL_AVL_TABLE", "DepthOfTree"): "RtlAvlDepthOfTree",
    ("_RTL_AVL_TABLE", "RestartKey"): "RtlAvlRestartKey",
    ("_RTL_AVL_TABLE", "DeleteCount"): "RtlAvlDeleteCount",
    ("_PIDDB_CACHE_ENTRY", "DriverName"): "PiDdbDriverName",
    ("_PIDDB_CACHE_ENTRY", "TimeDateStamp"): "PiDdbTimeDateStamp",
    ("_PIDDB_CACHE_ENTRY", "LoadStatus"): "PiDdbLoadStatus",
    ("_OBJECT_TYPE", "CallbackList"): "_OBJECT_TYPE.CallbackList",
    ("_CALLBACK_ENTRY_ITEM", "EntryItemList"): "_CALLBACK_ENTRY_ITEM.EntryList",
    ("_CALLBACK_ENTRY_ITEM", "PreOperation"): "_CALLBACK_ENTRY_ITEM.PreOperation",
    ("_CALLBACK_ENTRY_ITEM", "PostOperation"): "_CALLBACK_ENTRY_ITEM.PostOperation",
    ("_CALLBACK_ENTRY_ITEM", "Operations"): "_CALLBACK_ENTRY_ITEM.Operations",
    ("_CALLBACK_ENTRY_ITEM", "CallbackEntry"): "_CALLBACK_ENTRY_ITEM.CallbackEntry",
    ("_CALLBACK_ENTRY", "Altitude"): "_CALLBACK_ENTRY.Altitude",
    ("_CALLBACK_ENTRY", "RegistrationContext"): "_CALLBACK_ENTRY.RegistrationContext",
}

# These public/global symbols are not structure member offsets, but are for subsequent CID/driver/callback detail pages.
# Required kernel global RVAs. They must come from PDB publics + section header mapping.
TARGET_GLOBAL_SYMBOL_GROUPS: dict[str, list[str]] = {
    "kernel_global_detail": [
        "PspCidTable",
        "PsLoadedModuleList",
        "MmUnloadedDrivers",
        "PiDDBCacheTable",
        "PiDDBLock",
        "KeServiceDescriptorTableShadow",
        "MmLastUnloadedDriver",
    ],
}

TYPE_HEADER_RE = re.compile(r"^\s*(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\s*\|\s*(LF_[A-Z0-9_]+)\b(.*)$")
FIELD_LIST_RE = re.compile(r"field list:\s*(?:<fieldlist\s+)?(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+|<no type>)")
STRUCT_SIZE_RE = re.compile(r"\bsizeof\s+(0x[0-9A-Fa-f]+|\d+)")
MEMBER_RE = re.compile(r"LF_MEMBER\s*\[name\s*=\s*`([^`]+)`,\s*Type\s*=\s*([^,\]]+),\s*offset\s*=\s*(0x[0-9A-Fa-f]+|\d+)")
ENUM_RE = re.compile(r"LF_ENUMERATE\s*\[([^=\]]+)\s*=\s*([^\]]+)\]")
BITFIELD_RE = re.compile(r"type\s*=\s*([^,]+),\s*bit offset\s*=\s*(\d+),\s*# bits\s*=\s*(\d+)")
POINTER_RE = re.compile(r"referent\s*=\s*([^,]+),.*kind\s*=\s*([^,\s]+)")
ARRAY_RE = re.compile(r"size:\s*(0x[0-9A-Fa-f]+|\d+),\s*index type:\s*([^,]+),\s*element type:\s*(.+)$")
PUBLIC_SYMBOL_RE = re.compile(r"^\s*(\d+)\s+\|\s+S_PUB32\s+\[size\s*=\s*(\d+)\]\s*`([^`]+)`")
PUBLIC_ADDRESS_RE = re.compile(r"flags\s*=\s*([^,]+),\s*addr\s*=\s*(\d+):(\d+)")
SECTION_HEADER_RE = re.compile(r"SECTION HEADER #(\d+)")
SECTION_VA_RE = re.compile(r"^\s*([0-9A-Fa-f]+)\s+virtual address")
SUMMARY_GUID_RE = re.compile(r"GUID:\s*\{([^}]+)\}")
SUMMARY_AGE_RE = re.compile(r"Age:\s*(\d+)")
SYMBOL_CACHE_KEY_RE = re.compile(r"^(?P<guid>[0-9A-Fa-f]{32})(?P<age>[0-9A-Fa-f]+)$")
RUNTIME_ITEM_ID_NAMESPACE = 0x80000000


@dataclass
class TypeRecord:
    """Save an llvm-pdbutil TPI record."""

    record_id: str
    kind: str
    header: str
    body: list[str] = field(default_factory=list)


@dataclass
class TypeInfo:
    """Save normalized type information for reuse during field parsing."""

    record_id: str
    kind: str
    name: str = ""
    size: int | None = None
    field_list_id: str | None = None
    forward_ref: bool = False
    referent_id: str | None = None
    pointer_kind: str = ""
    element_type_id: str | None = None
    array_size: int | None = None
    bit_base_type: str | None = None
    bit_offset: int | None = None
    bit_size: int | None = None
    underlying_type: str | None = None


def parse_int(text: str) -> int:
    """Parse decimal or 0x hexadecimal integers."""
    value = text.strip()
    return int(value, 16 if value.lower().startswith("0x") else 10)


def normalize_type_id(text: str) -> str:
    """Normalize the type ID printed by llvm-pdbutil to lowercase 0xXXXXXXXX text."""
    token = text.strip().split()[0]
    if token == "<no":
        return ""
    if token.startswith("<"):
        return ""
    raw = token.lower().removeprefix("0x")
    try:
        return f"0x{int(raw, 16):04X}".lower()
    except ValueError:
        return ""


def first_backtick_name(text: str) -> str:
    """Extract the first backtick name from the record header."""
    match = re.search(r"`([^`]+)`", text)
    return match.group(1) if match else ""


def run_pdbutil(pdbutil_path: str, pdb_path: Path, *options: str, timeout: int = 900) -> str:
    """Execute llvm-pdbutil and return stdout."""
    completed = subprocess.run(
        [pdbutil_path, "dump", *options, str(pdb_path)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    return completed.stdout


def parse_symbol_cache_identity(pdb_path: Path, pdb_guid: str) -> dict[str, Any]:
    """Extract the RSDS GUID/Age from the Microsoft symbol-cache directory name.

    Inputs:
    - pdb_path: local PDB path in the format ...\\ntkrnlmp.pdb\\<GUID+Age>\\ntkrnlmp.pdb;
    - pdb_guid: the PDB GUID extracted from the llvm-pdbutil summary.
    Processing:
    - Parse the GUID+Age key from the end of the parent directory name;
    - When the GUID matches the summary GUID, parse the trailing age as hexadecimal according to symbol-server rules.
    Returns:
    - Dictionary containing symbolCacheKey, symbolCacheGuid, and symbolCacheAge; returns null if parsing fails.
    """
    cache_key = pdb_path.parent.name.strip()
    match = SYMBOL_CACHE_KEY_RE.match(cache_key)
    normalized_summary_guid = pdb_guid.replace("-", "").lower()
    if not match or match.group("guid").lower() != normalized_summary_guid:
        return {
            "symbolCacheKey": cache_key,
            "symbolCacheGuid": "",
            "symbolCacheAge": 0,
        }

    age_text = match.group("age")
    try:
        symbol_age = int(age_text, 16)
    except ValueError:
        symbol_age = 0
    return {
        "symbolCacheKey": cache_key,
        "symbolCacheGuid": match.group("guid").upper(),
        "symbolCacheAge": symbol_age,
    }


def portable_pdb_identity_path(pdb_path: Path, symbol_identity: dict[str, Any]) -> str:
    """Construct the publishable PDB identity URI.

    Inputs:
    - pdb_path: the actual PDB path on the build machine, used only to extract arch/pdbName.
    - symbol_identity: The GUID+Age identity parsed by parse_symbol_cache_identity.
    Processing:
    - Do not write to local paths like E:/D: in the published JSON to prevent the runtime environment from mistakenly assuming a development machine symbol drive is required.
    - Retains the symbol-cache structure (arch, pdbName, GUID, Age) so that Age can still be parsed during subsequent audits.
    Returns:
    - symbol-cache://... URI; returns pdb://pdbName when the cache key is unrecognized.
    """
    path_parts = [str(part) for part in pdb_path.parts]
    arch_text = "unknown"
    for index, part in enumerate(path_parts):
        if part.lower() == "pdb-cache" and index + 1 < len(path_parts):
            arch_text = path_parts[index + 1]
            break
    if arch_text == "unknown":
        for part in path_parts:
            if part.lower() in {"amd64", "x86", "arm64"}:
                arch_text = part
                break

    cache_key = str(symbol_identity.get("symbolCacheKey", "") or "").strip()
    if not cache_key:
        return f"pdb://{pdb_path.name}"
    return f"symbol-cache://{arch_text}/{pdb_path.name}/{cache_key}/{pdb_path.name}"


def parse_summary(summary_text: str, pdb_path: Path) -> dict[str, Any]:
    """Extract PDB GUID/Age and other identity information from the summary output.

    Inputs:
    - summary_text: llvm-pdbutil dump -summary output;
    - pdb_path: actual PDB path.
    Processing:
    - summary Age is recorded as pdbSummaryAge;
    - If the PDB comes from the symbol cache, prefer using the parent directory's GUID + Age as the pdbAge for runtime/RSDS matching.
    Returns:
    - source dictionary; the pdbAge field is used to match the ark_dyndata_pack_v4.json profile identity.
    """
    guid_match = SUMMARY_GUID_RE.search(summary_text)
    age_match = SUMMARY_AGE_RE.search(summary_text)
    pdb_guid = guid_match.group(1).upper() if guid_match else ""
    summary_age = int(age_match.group(1)) if age_match else 0
    symbol_identity = parse_symbol_cache_identity(pdb_path, pdb_guid) if pdb_guid else {
        "symbolCacheKey": pdb_path.parent.name.strip(),
        "symbolCacheGuid": "",
        "symbolCacheAge": 0,
    }
    symbol_age = int(symbol_identity.get("symbolCacheAge", 0) or 0)
    effective_age = symbol_age if symbol_age > 0 else summary_age
    return {
        "pdbPath": portable_pdb_identity_path(pdb_path, symbol_identity),
        "pdbName": pdb_path.name,
        "pdbGuid": pdb_guid,
        "pdbAge": effective_age,
        "pdbSummaryAge": summary_age,
        "identitySource": "symbol_cache_path" if symbol_age > 0 else "llvm_pdbutil_summary",
        **symbol_identity,
        "hasTypes": "Has Types: true" in summary_text,
        "hasGlobals": "Has Globals: true" in summary_text,
        "hasPublics": "Has Publics: true" in summary_text,
        "isStripped": "Is stripped: true" in summary_text,
    }


def split_type_records(types_text: str) -> dict[str, TypeRecord]:
    """Split the complete TPI text into records indexed by record ID."""
    records: dict[str, TypeRecord] = {}
    current: TypeRecord | None = None
    for line in types_text.splitlines():
        header = TYPE_HEADER_RE.match(line)
        if header:
            if current is not None:
                records[current.record_id] = current
            record_id, kind, rest = header.groups()
            current = TypeRecord(record_id=normalize_type_id(record_id), kind=kind, header=line, body=[])
            continue
        if current is not None:
            current.body.append(line)
    if current is not None:
        records[current.record_id] = current
    return records


def build_type_info(records: dict[str, TypeRecord]) -> dict[str, TypeInfo]:
    """Convert raw TPI records into parseable TypeInfo."""
    infos: dict[str, TypeInfo] = {}
    for record_id, record in records.items():
        all_text = "\n".join([record.header, *record.body])
        info = TypeInfo(record_id=record_id, kind=record.kind)
        info.name = first_backtick_name(record.header)
        info.forward_ref = "forward ref" in all_text

        size_match = STRUCT_SIZE_RE.search(all_text)
        if size_match:
            info.size = parse_int(size_match.group(1))

        field_match = FIELD_LIST_RE.search(all_text)
        if field_match:
            info.field_list_id = normalize_type_id(field_match.group(1))

        if record.kind == "LF_POINTER":
            pointer_match = POINTER_RE.search(all_text)
            if pointer_match:
                info.referent_id = normalize_type_id(pointer_match.group(1))
                info.pointer_kind = pointer_match.group(2)

        if record.kind == "LF_ARRAY":
            for body_line in record.body:
                array_match = ARRAY_RE.search(body_line)
                if array_match:
                    info.array_size = parse_int(array_match.group(1))
                    info.element_type_id = normalize_type_id(array_match.group(3))
                    break

        if record.kind == "LF_BITFIELD":
            bit_match = BITFIELD_RE.search(all_text)
            if bit_match:
                info.bit_base_type = bit_match.group(1).strip()
                info.bit_offset = int(bit_match.group(2))
                info.bit_size = int(bit_match.group(3))

        if record.kind == "LF_ENUM":
            underlying_match = re.search(r"underlying type:\s*(.+)$", all_text, flags=re.MULTILINE)
            if underlying_match:
                info.underlying_type = underlying_match.group(1).strip()

        infos[record_id] = info
    return infos


def find_concrete_type(type_infos: dict[str, TypeInfo], type_name: str) -> TypeInfo | None:
    """Find the non-forward-ref definition of the target type."""
    candidates = [info for info in type_infos.values() if info.name == type_name and not info.forward_ref]
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item.size is None, -(item.size or 0)))
    return candidates[0]


def resolve_type_display(type_id: str, type_infos: dict[str, TypeInfo], depth: int = 0) -> str:
    """Convert type ID to a human-readable type name."""
    normalized = normalize_type_id(type_id)
    if not normalized:
        return type_id.strip()
    if depth > 6:
        return normalized
    info = type_infos.get(normalized)
    if info is None:
        return type_id.strip()
    if info.kind == "LF_POINTER" and info.referent_id:
        referent = resolve_type_display(info.referent_id, type_infos, depth + 1)
        return f"{referent}*"
    if info.kind == "LF_ARRAY" and info.element_type_id:
        element = resolve_type_display(info.element_type_id, type_infos, depth + 1)
        return f"{element}[{info.array_size if info.array_size is not None else '?'}]"
    if info.kind == "LF_BITFIELD":
        return f"bitfield({info.bit_base_type or 'unknown'}, offset={info.bit_offset}, bits={info.bit_size})"
    if info.name:
        return info.name
    return info.kind


def parse_member_line(line: str) -> dict[str, Any] | None:
    """Parse the LF_MEMBER line and return the member name, type ID, and byte offset."""
    match = MEMBER_RE.search(line)
    if not match:
        return None
    member_name, type_token, offset_text = match.groups()
    return {
        "name": member_name,
        "typeToken": type_token.strip(),
        "typeId": normalize_type_id(type_token),
        "offset": parse_int(offset_text),
        "raw": line.strip(),
    }


def parse_enum_line(line: str) -> dict[str, Any] | None:
    """Parse LF_ENUMERATE lines."""
    match = ENUM_RE.search(line)
    if not match:
        return None
    return {"name": match.group(1).strip(), "value": match.group(2).strip(), "raw": line.strip()}


def target_global_symbol_groups_by_name() -> dict[str, str]:
    """Build an index mapping global symbol names to domain names.

    Inputs:
    - None; reads the TARGET_GLOBAL_SYMBOL_GROUPS constant.
    Processing:
    - Iterates through each global RVA domain to map symbol names back to domain names.
    Returns:
    - dict[symbolName, groupName]: Used for O(1) lookup of target symbols during publics parsing.
    """
    groups_by_name: dict[str, str] = {}
    for group_name, symbol_names in TARGET_GLOBAL_SYMBOL_GROUPS.items():
        for symbol_name in symbol_names:
            groups_by_name[symbol_name] = group_name
    return groups_by_name


def parse_section_headers(section_text: str) -> dict[int, dict[str, Any]]:
    """Parse llvm-pdbutil -section-headers output.

    Inputs:
    - section_text: text output from llvm-pdbutil dump -section-headers.
    Processing:
    - Record the section header index, section name, and virtual address.
    - Virtual addresses are parsed as hexadecimal because llvm-pdbutil uses hexadecimal text for PE section fields.
    Returns:
    - A dictionary indexed by 1-based sectionIndex; sections where the VA cannot be obtained are not written.
    """
    sections: dict[int, dict[str, Any]] = {}
    current_index: int | None = None
    pending_name = ""

    for line in section_text.splitlines():
        header_match = SECTION_HEADER_RE.search(line)
        if header_match:
            current_index = int(header_match.group(1))
            pending_name = ""
            sections[current_index] = {
                "sectionIndex": current_index,
                "name": "",
                "virtualAddress": 0,
                "virtualAddressHex": "0x00000000",
            }
            continue

        if current_index is None:
            continue

        stripped_line = line.strip()
        if stripped_line.endswith(" name") and not pending_name:
            pending_name = stripped_line[:-len(" name")].strip()
            sections[current_index]["name"] = pending_name
            continue

        va_match = SECTION_VA_RE.match(line)
        if va_match:
            virtual_address = int(va_match.group(1), 16)
            sections[current_index]["virtualAddress"] = virtual_address
            sections[current_index]["virtualAddressHex"] = f"0x{virtual_address:08X}"

    return {
        section_index: section_entry
        for section_index, section_entry in sections.items()
        if int(section_entry.get("virtualAddress", 0) or 0) != 0
    }


def parse_public_global_symbols(publics_text: str, sections: dict[int, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Extract target kernel global RVA from publics stream.

    Inputs:
    - publics_text: llvm-pdbutil dump -publics output text;
    - sections: section VA indices returned by parse_section_headers.
    Processing:
    - Only accepts symbols listed in TARGET_GLOBAL_SYMBOL_GROUPS;
    - The address offsets for llvm-pdbutil publics are in decimal section offsets, while section virtual addresses are in hexadecimal.
    - Use sectionVA + sectionOffset to obtain the image-relative RVA.
    Returns:
    - (globalSymbols, missingSymbols). globalSymbols can be directly serialized into JSON.
    """
    groups_by_name = target_global_symbol_groups_by_name()
    found_by_name: dict[str, dict[str, Any]] = {}
    pending_symbol: dict[str, Any] | None = None

    for line in publics_text.splitlines():
        symbol_match = PUBLIC_SYMBOL_RE.match(line)
        if symbol_match:
            symbol_name = symbol_match.group(3)
            if symbol_name in groups_by_name:
                pending_symbol = {
                    "symbolRecordOffset": int(symbol_match.group(1)),
                    "recordSize": int(symbol_match.group(2)),
                    "symbolName": symbol_name,
                    "group": groups_by_name[symbol_name],
                }
            else:
                pending_symbol = None
            continue

        if pending_symbol is None:
            continue

        address_match = PUBLIC_ADDRESS_RE.search(line)
        if not address_match:
            continue

        section_index = int(address_match.group(2))
        section_offset = int(address_match.group(3))
        section_entry = sections.get(section_index)
        if section_entry is None:
            pending_symbol["status"] = "section_not_found"
            pending_symbol["sectionIndex"] = section_index
            pending_symbol["sectionOffset"] = section_offset
            found_by_name.setdefault(str(pending_symbol["symbolName"]), pending_symbol)
            pending_symbol = None
            continue

        section_va = int(section_entry.get("virtualAddress", 0) or 0)
        rva = section_va + section_offset
        runtime_item_id = stable_runtime_item_id(str(pending_symbol["group"]), "<global>", str(pending_symbol["symbolName"]))
        pending_symbol.update({
            "kind": "GlobalRva",
            "status": "ok",
            "flags": address_match.group(1).strip(),
            "sectionIndex": section_index,
            "sectionName": section_entry.get("name", ""),
            "sectionVirtualAddress": section_va,
            "sectionVirtualAddressHex": f"0x{section_va:08X}",
            "sectionOffset": section_offset,
            "sectionOffsetHex": f"0x{section_offset:08X}",
            "rva": rva,
            "rvaHex": f"0x{rva:08X}",
            "runtimeItemId": runtime_item_id,
            "runtimeItemIdHex": f"0x{runtime_item_id:08X}",
            "kswordItemName": pending_symbol["symbolName"],
        })
        found_by_name.setdefault(str(pending_symbol["symbolName"]), pending_symbol)
        pending_symbol = None

    missing_symbols: list[dict[str, str]] = []
    for group_name, symbol_names in TARGET_GLOBAL_SYMBOL_GROUPS.items():
        for symbol_name in symbol_names:
            if symbol_name not in found_by_name:
                missing_symbols.append({
                    "group": group_name,
                    "symbolName": symbol_name,
                    "reason": "public_symbol_not_found",
                })

    global_symbols = sorted(
        found_by_name.values(),
        key=lambda item: (str(item.get("group", "")), str(item.get("symbolName", ""))),
    )
    return global_symbols, missing_symbols


def extract_type_fields(
    type_name: str,
    group_name: str,
    type_infos: dict[str, TypeInfo],
    records: dict[str, TypeRecord],
) -> dict[str, Any] | None:
    """Extract all direct fields of a target type."""
    type_info = find_concrete_type(type_infos, type_name)
    if type_info is None or not type_info.field_list_id:
        return None
    field_record = records.get(type_info.field_list_id)
    if field_record is None:
        return None

    fields: list[dict[str, Any]] = []
    enum_values: list[dict[str, Any]] = []
    for line in field_record.body:
        member = parse_member_line(line)
        if member is not None:
            field_type_info = type_infos.get(member["typeId"])
            field_entry: dict[str, Any] = {
                "name": member["name"],
                "qualifiedName": f"{type_name}.{member['name']}",
                "offset": member["offset"],
                "offsetHex": f"0x{member['offset']:04X}",
                "typeId": member["typeId"],
                "typeName": resolve_type_display(member["typeToken"], type_infos),
                "rawType": member["typeToken"],
            }
            alias = KSWORD_ITEM_ALIASES.get((type_name, member["name"]))
            if alias:
                field_entry["kswordItemName"] = alias
            if field_type_info is not None and field_type_info.kind == "LF_BITFIELD":
                field_entry["bitField"] = {
                    "baseType": field_type_info.bit_base_type,
                    "bitOffset": field_type_info.bit_offset,
                    "bitSize": field_type_info.bit_size,
                }
            fields.append(field_entry)
            continue
        enum_value = parse_enum_line(line)
        if enum_value is not None:
            enum_values.append(enum_value)

    fields.sort(key=lambda item: (int(item["offset"]), str(item["name"])))
    return {
        "group": group_name,
        "typeName": type_name,
        "recordId": type_info.record_id,
        "kind": type_info.kind,
        "size": type_info.size,
        "sizeHex": f"0x{type_info.size:04X}" if type_info.size is not None else "",
        "fieldListId": type_info.field_list_id,
        "fieldCount": len(fields),
        "fields": fields,
        "enumValueCount": len(enum_values),
        "enumValues": enum_values,
    }


def build_flat_rows(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten nested target types into CSV/audit rows."""
    rows: list[dict[str, Any]] = []
    for target in targets:
        for field_entry in target.get("fields", []):
            bitfield = field_entry.get("bitField", {}) if isinstance(field_entry.get("bitField"), dict) else {}
            rows.append(
                {
                    "group": target.get("group", ""),
                    "typeName": target.get("typeName", ""),
                    "typeSize": target.get("size", ""),
                    "fieldName": field_entry.get("name", ""),
                    "qualifiedName": field_entry.get("qualifiedName", ""),
                    "offset": field_entry.get("offset", ""),
                    "offsetHex": field_entry.get("offsetHex", ""),
                    "fieldType": field_entry.get("typeName", ""),
                    "typeId": field_entry.get("typeId", ""),
                    "kswordItemName": field_entry.get("kswordItemName", ""),
                    "bitBaseType": bitfield.get("baseType", ""),
                    "bitOffset": bitfield.get("bitOffset", ""),
                    "bitSize": bitfield.get("bitSize", ""),
                }
            )
    rows.sort(key=lambda item: (str(item["group"]), str(item["typeName"]), int(item["offset"] or 0), str(item["fieldName"])))
    assign_runtime_item_ids(rows)
    return rows


def stable_runtime_item_id(group_name: str, type_name: str, field_name: str, attempt: int = 0) -> int:
    """Generate stable IDs for deep runtime fields.

    Inputs:
    - group_name/type_name/field_name: full field ownership.
    - attempt: hash collision retry sequence number.
    Processing:
    - Compute CRC32 for normalized keys;
    - Force the high bit to avoid conflicts with the existing KSW_DYN_FIELD_ID_* small integer space.
    Returns:
    - 32-bit unsigned runtime item ID, usable for subsequent v4/paged detail protocol references.
    """
    key = f"{group_name}:{type_name}:{field_name}:{attempt}".encode("utf-8", errors="strict")
    return RUNTIME_ITEM_ID_NAMESPACE | (zlib.crc32(key) & 0x7FFFFFFF)


def assign_runtime_item_ids(rows: list[dict[str, Any]]) -> None:
    """Supplement runtimeItemId to flatFields in place.

    Inputs:
    - rows: flat field list
    Processing:
    - Generate deterministic IDs using group/type/field;
    - In the extremely rare case of a CRC collision, append a salt value to the attempt and recalculate, recording the collisionAttempt.
    Returns:
    - No return value; adds runtimeItemId/runtimeItemIdHex/collisionAttempt per line.
    """
    used: dict[int, str] = {}
    for row in rows:
        group_name = str(row.get("group", ""))
        type_name = str(row.get("typeName", ""))
        field_name = str(row.get("fieldName", ""))
        identity_key = f"{group_name}:{type_name}:{field_name}"
        attempt = 0
        item_id = stable_runtime_item_id(group_name, type_name, field_name, attempt)
        while item_id in used and used[item_id] != identity_key:
            attempt += 1
            item_id = stable_runtime_item_id(group_name, type_name, field_name, attempt)
        used[item_id] = identity_key
        row["runtimeItemId"] = item_id
        row["runtimeItemIdHex"] = f"0x{item_id:08X}"
        row["collisionAttempt"] = attempt


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    """Write the field list to CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "group",
        "typeName",
        "typeSize",
        "fieldName",
        "qualifiedName",
        "offset",
        "offsetHex",
        "fieldType",
        "typeId",
        "kswordItemName",
        "runtimeItemId",
        "runtimeItemIdHex",
        "collisionAttempt",
        "bitBaseType",
        "bitOffset",
        "bitSize",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_global_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    """Output global RVA list to CSV.

    Inputs:
    - path: output CSV path;
    - rows: globalSymbols generated by parse_public_global_symbols.
    Processing:
    - Write only target public/global symbols; do not dump the complete publics stream.
    Returns:
    - None; file encoding is UTF-8 BOM for easier viewing in Excel/PowerShell.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "group",
        "kind",
        "symbolName",
        "kswordItemName",
        "rva",
        "rvaHex",
        "sectionIndex",
        "sectionName",
        "sectionVirtualAddressHex",
        "sectionOffset",
        "sectionOffsetHex",
        "runtimeItemId",
        "runtimeItemIdHex",
        "status",
        "flags",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def build_runtime_detail_catalog(
    targets: list[dict[str, Any]],
    flat_rows: list[dict[str, Any]],
    alias_rows: list[dict[str, Any]],
    global_symbols: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a grouped directory directly consumable by the runtime detail page.

    Inputs:
    - targets: Set of structure fields extracted by type.
    - flat_rows: a flattened list of all fields.
    - alias_rows: fields already mapped to Ksword DynData names.
    - global_symbols: list of public/global RVA symbols.

    Processing:
    - Aggregate types and fields by the group name in TARGET_TYPE_GROUPS;
    - Retain fields offset, type, bitfield, and kswordItemName;
    - Generates aliasMap/globalAliasMap to facilitate associating traditional DynData items with the deep offset library in subsequent R3/R0 operations.

    Returns:
    - dict; can be directly serialized into the deep offset JSON without performing any file I/O.
    """
    target_by_type: dict[str, dict[str, Any]] = {}
    for target in targets:
        target_name = str(target.get("typeName", ""))
        if target_name:
            target_by_type[target_name] = target

    fields_by_group_type: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in flat_rows:
        group_name = str(row.get("group", ""))
        type_name = str(row.get("typeName", ""))
        if not group_name or not type_name:
            continue
        fields_by_group_type.setdefault((group_name, type_name), []).append(row)

    domains: list[dict[str, Any]] = []
    for group_name, type_names in TARGET_TYPE_GROUPS.items():
        domain_types: list[dict[str, Any]] = []
        domain_field_count = 0
        domain_alias_count = 0
        for type_name in type_names:
            type_fields = fields_by_group_type.get((group_name, type_name), [])
            target = target_by_type.get(type_name, {})
            fields: list[dict[str, Any]] = []
            for field_row in type_fields:
                item_name = str(field_row.get("kswordItemName", ""))
                field_entry: dict[str, Any] = {
                    "fieldName": field_row.get("fieldName", ""),
                    "qualifiedName": field_row.get("qualifiedName", ""),
                    "runtimeItemId": field_row.get("runtimeItemId", 0),
                    "runtimeItemIdHex": field_row.get("runtimeItemIdHex", ""),
                    "offset": field_row.get("offset", 0),
                    "offsetHex": field_row.get("offsetHex", ""),
                    "fieldType": field_row.get("fieldType", ""),
                    "typeId": field_row.get("typeId", ""),
                    "kswordItemName": item_name,
                }
                if field_row.get("bitBaseType") or field_row.get("bitOffset") or field_row.get("bitSize"):
                    field_entry["bitField"] = {
                        "baseType": field_row.get("bitBaseType", ""),
                        "bitOffset": field_row.get("bitOffset", ""),
                        "bitSize": field_row.get("bitSize", ""),
                    }
                fields.append(field_entry)
                domain_field_count += 1
                if item_name:
                    domain_alias_count += 1

            domain_types.append({
                "typeName": type_name,
                "typeSize": target.get("size"),
                "typeId": target.get("typeId", ""),
                "fieldCount": len(fields),
                "fields": fields,
            })

        domains.append({
            "domain": group_name,
            "typeCount": len(domain_types),
            "fieldCount": domain_field_count,
            "kswordAliasFieldCount": domain_alias_count,
            "types": domain_types,
        })

    alias_map: dict[str, dict[str, Any]] = {}
    for row in alias_rows:
        item_name = str(row.get("kswordItemName", ""))
        if not item_name:
            continue
        alias_map[item_name] = {
            "group": row.get("group", ""),
            "typeName": row.get("typeName", ""),
            "fieldName": row.get("fieldName", ""),
            "qualifiedName": row.get("qualifiedName", ""),
            "runtimeItemId": row.get("runtimeItemId", 0),
            "runtimeItemIdHex": row.get("runtimeItemIdHex", ""),
            "offset": row.get("offset", 0),
            "offsetHex": row.get("offsetHex", ""),
            "fieldType": row.get("fieldType", ""),
        }

    global_domains: list[dict[str, Any]] = []
    global_symbols_by_group: dict[str, list[dict[str, Any]]] = {}
    for symbol_entry in global_symbols:
        group_name = str(symbol_entry.get("group", ""))
        if group_name:
            global_symbols_by_group.setdefault(group_name, []).append(symbol_entry)

    global_alias_map: dict[str, dict[str, Any]] = {}
    for group_name, symbol_names in TARGET_GLOBAL_SYMBOL_GROUPS.items():
        domain_symbols: list[dict[str, Any]] = []
        symbols_by_name = {
            str(symbol_entry.get("symbolName", "")): symbol_entry
            for symbol_entry in global_symbols_by_group.get(group_name, [])
        }
        for symbol_name in symbol_names:
            symbol_entry = symbols_by_name.get(symbol_name)
            if symbol_entry is None:
                continue
            domain_symbol = {
                "symbolName": symbol_entry.get("symbolName", ""),
                "kind": symbol_entry.get("kind", "GlobalRva"),
                "runtimeItemId": symbol_entry.get("runtimeItemId", 0),
                "runtimeItemIdHex": symbol_entry.get("runtimeItemIdHex", ""),
                "rva": symbol_entry.get("rva", 0),
                "rvaHex": symbol_entry.get("rvaHex", ""),
                "sectionIndex": symbol_entry.get("sectionIndex", 0),
                "sectionName": symbol_entry.get("sectionName", ""),
                "sectionOffset": symbol_entry.get("sectionOffset", 0),
                "sectionOffsetHex": symbol_entry.get("sectionOffsetHex", ""),
                "kswordItemName": symbol_entry.get("kswordItemName", ""),
            }
            domain_symbols.append(domain_symbol)
            global_alias_map[str(symbol_entry.get("kswordItemName", symbol_name))] = {
                "group": group_name,
                **domain_symbol,
            }
        global_domains.append({
            "domain": group_name,
            "kind": "GlobalRva",
            "symbolCount": len(domain_symbols),
            "symbols": domain_symbols,
        })

    return {
        "schemaVersion": 1,
        "kind": "KswordRuntimeDetailOffsetCatalog",
        "domainCount": len(domains),
        "fieldCount": len(flat_rows),
        "globalDomainCount": len(global_domains),
        "globalSymbolCount": len(global_symbols),
        "runtimeItemIdCount": len({row.get("runtimeItemId") for row in flat_rows if row.get("runtimeItemId")}),
        "runtimeItemIdCollisionRetryCount": sum(int(row.get("collisionAttempt", 0) or 0) for row in flat_rows),
        "kswordAliasFieldCount": len(alias_rows),
        "domains": domains,
        "globalDomains": global_domains,
        "aliasMap": alias_map,
        "globalAliasMap": global_alias_map,
        "notes": [
            "domains can be directly mapped to process, thread, handle, driver, memory, IPC, and callback detail pages.",
            "aliasMap only contains fields that can already be associated with existing DynData/pack item names.",
            "globalDomains saves public/global symbol RVAs, not structure member offsets.",
            "Fields not entered into aliasMap remain available for subsequent v4 item numbering, detail IOCTL, and UI display extensions.",
        ],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Extract useful ntoskrnl struct offsets from one PDB.")
    parser.add_argument("--pdb", default=DEFAULT_PDB_PATH, help="ntkrnlmp.pdb path to parse")
    parser.add_argument("--llvm-pdbutil", default=DEFAULT_LLVM_PDBUTIL, help="llvm-pdbutil executable path")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="directory for JSON/CSV output")
    parser.add_argument("--json-name", default="", help="optional JSON file name")
    parser.add_argument("--csv-name", default="", help="optional CSV file name")
    parser.add_argument("--global-csv-name", default="", help="optional global RVA CSV file name")
    parser.add_argument("--repo-json", default="", help="optional repository-side JSON output path")
    parser.add_argument("--dump-types-cache", default="", help="optional path to cache raw llvm-pdbutil -types output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Main entry: execute summary/types parsing and output JSON/CSV."""
    args = parse_args(argv)
    pdb_path = Path(args.pdb)
    pdbutil_path = str(Path(args.llvm_pdbutil))
    output_dir = Path(args.output_dir)

    if not pdb_path.exists():
        print(f"PDB not found: {pdb_path}", file=sys.stderr)
        return 2
    if not Path(pdbutil_path).exists():
        print(f"llvm-pdbutil not found: {pdbutil_path}", file=sys.stderr)
        return 2

    started = time.time()
    summary_text = run_pdbutil(pdbutil_path, pdb_path, "-summary", timeout=120)
    summary = parse_summary(summary_text, pdb_path)
    if not summary.get("hasTypes"):
        print("PDB has no TPI types", file=sys.stderr)
        return 3

    section_text = run_pdbutil(pdbutil_path, pdb_path, "-section-headers", timeout=120)
    sections = parse_section_headers(section_text)
    publics_text = run_pdbutil(pdbutil_path, pdb_path, "-publics", timeout=300) if summary.get("hasPublics") else ""
    global_symbols, missing_global_symbols = parse_public_global_symbols(publics_text, sections)

    if args.dump_types_cache and Path(args.dump_types_cache).exists():
        types_text = Path(args.dump_types_cache).read_text(encoding="utf-8", errors="replace")
    else:
        types_text = run_pdbutil(pdbutil_path, pdb_path, "-types", timeout=900)
        if args.dump_types_cache:
            cache_path = Path(args.dump_types_cache)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(types_text, encoding="utf-8")

    records = split_type_records(types_text)
    type_infos = build_type_info(records)

    targets: list[dict[str, Any]] = []
    missing_types: list[dict[str, str]] = []
    for group_name, type_names in TARGET_TYPE_GROUPS.items():
        for type_name in type_names:
            extracted = extract_type_fields(type_name, group_name, type_infos, records)
            if extracted is None:
                missing_types.append({"group": group_name, "typeName": type_name, "reason": "type_or_field_list_not_found"})
                continue
            targets.append(extracted)

    flat_rows = build_flat_rows(targets)
    alias_rows = [row for row in flat_rows if row.get("kswordItemName")]
    runtime_detail_catalog = build_runtime_detail_catalog(targets, flat_rows, alias_rows, global_symbols)
    default_stem = f"ntkrnlmp_{str(summary.get('pdbGuid', '')).replace('-', '').lower()}_age{summary.get('pdbAge', 0)}_deep_offsets"
    json_path = output_dir / (args.json_name or f"{default_stem}.json")
    csv_path = output_dir / (args.csv_name or f"{default_stem}.csv")
    global_csv_path = output_dir / (args.global_csv_name or f"{default_stem}_globals.csv")

    result = {
        "schemaVersion": 1,
        "kind": "KswordNtosDeepOffsetLibrary",
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generator": "tools/pdb_offset_generator/ksword_ntos_pdb_deep_offsets.py",
        "source": summary,
        "stats": {
            "typeRecordCount": len(records),
            "targetTypeCount": len(targets),
            "missingTypeCount": len(missing_types),
            "fieldCount": len(flat_rows),
            "sectionCount": len(sections),
            "targetGlobalSymbolCount": sum(len(symbol_names) for symbol_names in TARGET_GLOBAL_SYMBOL_GROUPS.values()),
            "globalSymbolCount": len(global_symbols),
            "missingGlobalSymbolCount": len(missing_global_symbols),
            "runtimeItemIdCount": len({row.get("runtimeItemId") for row in flat_rows if row.get("runtimeItemId")}),
            "runtimeItemIdCollisionRetryCount": sum(int(row.get("collisionAttempt", 0) or 0) for row in flat_rows),
            "kswordAliasFieldCount": len(alias_rows),
            "elapsedSeconds": round(time.time() - started, 3),
        },
        "targetGroups": TARGET_TYPE_GROUPS,
        "targetGlobalSymbolGroups": TARGET_GLOBAL_SYMBOL_GROUPS,
        "sectionHeaders": sections,
        "targets": targets,
        "flatFields": flat_rows,
        "kswordAliasFields": alias_rows,
        "globalSymbols": global_symbols,
        "runtimeDetailCatalog": runtime_detail_catalog,
        "missingTypes": missing_types,
        "missingGlobalSymbols": missing_global_symbols,
        "notes": [
            "ntkrnlmp PDB only covers NT kernel types; win32k window object fields require win32kbase/win32kfull PDB for further extraction.",
            "flatFields is the fallback fact library for detail pages; only fields in kswordAliasFields that are mapped to the current DynData namespace.",
            "globalSymbols saves public/global symbol RVAs; R0 must still match the loaded module's identity, TimeDateStamp, and SizeOfImage before use.",
            "bitField provides member byte offset, bit offset, and bit width; R0 must be read with a mask when used.",
        ],
    }

    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_csv(csv_path, flat_rows)
    write_global_csv(global_csv_path, global_symbols)

    repo_json = str(args.repo_json).strip()
    if repo_json:
        repo_path = Path(repo_json)
        repo_path.parent.mkdir(parents=True, exist_ok=True)
        repo_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"json={json_path}")
    print(f"csv={csv_path}")
    print(f"globalCsv={global_csv_path}")
    if repo_json:
        print(f"repoJson={repo_json}")
    print(
        f"targets={len(targets)} fields={len(flat_rows)} aliases={len(alias_rows)} "
        f"globals={len(global_symbols)} missingGlobals={len(missing_global_symbols)} missingTypes={len(missing_types)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
