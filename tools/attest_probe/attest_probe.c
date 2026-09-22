/*
 * attest_probe: Retrieve and print the runtime driver manifest signed by the secure kernel (VTL1) as-is.
 *
 * Why this is useful: On a machine with VBS enabled, we cannot access EPT, but VBS
 * provides an additional source of evidence. GetRuntimeAttestationReport lets an
 * **ordinary VTL0 user-mode process** obtain a module list generated and signed by
 * the secure kernel, **including modules that have already been unloaded**.
 * This is something EPT cross-view cannot provide: EPT can only see pages mapped at this exact moment.
 *
 * This tool **only prints, does not make judgments**. The difference-set criteria will be written after reviewing this raw data.
 * The failure mode of this approach is false-positive alerts, which is more embarrassing for an ARK tool than missing detections.
 *
 * Three proven pitfalls are noted locally below:
 *   1. Exported in kernelbase.dll, **not** in kernel32 (Microsoft documentation incorrectly states kernel32);
 *   2. Size query returns FALSE + ERROR_INSUFFICIENT_BUFFER(122); writing based
 *      on 'FALSE means failure' would incorrectly treat this path as a hard failure.
 *   3. RUNTIME_REPORT_PACKAGE_HEADER has an actual sizeof of 40 due to UINT64 alignment, not 36 as the sum of fields
 *      suggests—manual layout calculation would be off by 4 bytes. This file consistently uses sizeof/FIELD_OFFSET.
 */

#include <windows.h>
#include <psapi.h>
/*
 * mscat.h includes mssip.h, which contains an anonymous union, causing C4201 errors under /W4 /WX.
 * That is the SDK's own header; disable warnings only locally here without changing the tool's global warning level.
 */
#pragma warning(push)
#pragma warning(disable: 4201)
#include <mscat.h>
#pragma warning(pop)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")

/*
 * Use GetProcAddress instead of direct calls for two independent reasons:
 *   * Guarded by NTDDI_WIN11_GE; calling directly would require raising the entire SDK target version.
 *   * The actual export resides in kernelbase.dll; linking against kernel32.lib fails to resolve
 *     the symbol (the official documentation incorrectly lists both req.dll and req.lib as Kernel32).
 */
typedef BOOL (WINAPI *PFN_GET_RUNTIME_ATTESTATION_REPORT)(
    UCHAR* nonce,
    UINT16 packageVersion,
    UINT64 reportTypesBitmap,
    PVOID reportBuffer,
    PUINT32 reportBufferSize);

static int gJson = 0;
static int gVerdict = 0;

/*
 * Mutation testing: remove a VTL0 module from the reference set to simulate it being invisible to VTL0.
 * The injection point is deliberately placed on the **data side** (erasing hashes and names) without modifying the
 * criteria code by a single line; otherwise, we are testing the stub, not the criteria. A zero-hit result has no
 * proof value; we must first prove the criteria can hit, so "local baseline is zero" becomes a meaningful statement.
 */
static const char* gHideName = NULL;

/*
 * Mutation testing for the negative criterion: remove a VTL0 module simultaneously from both the "runtime report"
 * and the "boot manifest" to simulate a scenario where it is loaded but unrecognized by any signature manifest.
 * Only modify data, not the decision logic.
 */
static const char* gOrphanName = NULL;

static void printHashHex(const BYTE* data, size_t bytes, size_t maxBytes)
{
    size_t i;
    size_t n = (bytes < maxBytes) ? bytes : maxBytes;

    for (i = 0U; i < n; ++i) {
        printf("%02X", data[i]);
    }
    if (bytes > n) {
        printf("...");
    }
}

/* Translate CALG_* hash algorithm IDs into human-readable names; unknown ones are given as their numeric IDs. */
static const char* hashAlgName(UINT16 alg)
{
    switch (alg) {
    case 0x8003: return "MD5";
    case 0x8004: return "SHA1";
    case 0x800C: return "SHA256";
    case 0x800D: return "SHA384";
    case 0x800E: return "SHA512";
    case 0:      return "(无)";
    default:     return "(未知)";
    }
}

/*
 * The **valid** length of the digest is determined by each ImageHashAlgorithm, not by
 * DRIVER_REPORT_DIGEST_MAX_SIZE. Using the maximum length would hash the subsequent
 * PublisherThumbprint as well — in practice, the latter half of afd.sys's "hash" is exactly its
 * certificate fingerprint, appearing as a 64-byte digest but actually representing two fields.
 */
static UINT32 hashLen(UINT16 alg)
{
    switch (alg) {
    case 0x8003: return 16U;  /* MD5    */
    case 0x8004: return 20U;  /* SHA1   */
    case 0x800C: return 32U;  /* SHA256 */
    case 0x800D: return 48U;  /* SHA384 */
    case 0x800E: return 64U;  /* SHA512 */
    default:     return 0U;
    }
}

/* Certificate fingerprint is always SHA1, 20 bytes. */
#define THUMBPRINT_LEN 20U

/* JSON string escaping: only handle characters that may appear in this report. */
static void printJsonString(const char* s, size_t maxLen)
{
    size_t i;

    putchar('"');
    for (i = 0U; i < maxLen && s[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            printf("\\%c", c);
        } else if (c < 0x20 || c >= 0x7F) {
            printf("\\u%04X", c);
        } else {
            putchar((char)c);
        }
    }
    putchar('"');
}

/*
 * On the VTL0 side, use NtQuerySystemInformation(SystemModuleInformation) instead of psapi's EnumDeviceDrivers
 * as the reference surface. The reason is empirical: EnumDeviceDrivers provides correct results.
 * **Count**, but the paired GetDeviceDriverBaseName on this machine returns all 265 names as "ntoskrnl.exe".
 * Using that as the reference set causes over 200 false positives to appear out of nowhere in the difference set.
 * SystemModuleInformation includes FullPathName directly, without requiring a secondary query.
 */
#define SYSTEM_MODULE_INFORMATION_CLASS 11
#define STATUS_INFO_LENGTH_MISMATCH_L   ((LONG)0xC0000004L)

typedef struct KswRtlProcessModuleInformation {
    HANDLE section;
    PVOID  mappedBase;
    PVOID  imageBase;
    ULONG  imageSize;
    ULONG  flags;
    USHORT loadOrderIndex;
    USHORT initOrderIndex;
    USHORT loadCount;
    USHORT offsetToFileName;
    UCHAR  fullPathName[256];
} KswRtlProcessModuleInformation;

typedef struct KswRtlProcessModules {
    ULONG numberOfModules;
    KswRtlProcessModuleInformation modules[1];
} KswRtlProcessModules;

typedef LONG (WINAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(
    ULONG systemInformationClass,
    PVOID systemInformation,
    ULONG systemInformationLength,
    PULONG returnLength);

#define ATTEST_NAME_MAX 128

/*
 * ---- TCG Log (WBCL) ----
 *
 * VTL1 runtime reports IncludeBootDrivers=0, causing the entire batch of boot drivers to be missing. This batch was
 * measured into the TPM during the boot phase, and the logs are written by Windows to %WINDIR%\Logs\MeasuredBoot\.
 * **Readable by standard users without privilege escalation, and does not require a physical TPM on the machine** (even if
 * `Get-Tpm` on this machine returns no info, logs are still generated). Therefore, it does not use TBS's `Tbsi_Get_TCG_Log`.
 *
 * Local test (Windows 11 26300, log 95043 bytes):
 *   45 top-level events exactly fill the entire file; the summary table uses only one algorithm: SHA256 (0x000B/32 bytes).
 *   9 SIPAEVENT_TRUSTBOUNDARY (0x40010001) containers within EV_EVENT_TAG;
 *   It contains 212 SIPAEVENT_LOADEDMODULE_AGGREGATION (0x40010003) entries:
 *   PCR12: 106 entries (digest and size only); PCR13: 106 entries (with path/certificate/internal name).
 *   106 modules contain 74 .sys files.
 *
 * Most critical calibration: The 0x00070004 digests of these 74 .sys files match the Authenticode
 * PE image hashes of the disk files byte-for-byte (74/74, zero exceptions). This means the boot
 * manifest, VTL1 runtime reports, and our own disk-calculated hashes all share the same key space.
 */
#define TCG_EV_EVENT_TAG            0x00000006UL
#define SIPA_AGGREGATION_BIT        0x40000000UL
#define SIPAEVENT_TRUSTBOUNDARY     0x40010001UL
#define SIPAEVENT_LOADEDMODULE_AGG  0x40010003UL
#define SIPAEVENT_MODULE_PATH       0x00070001UL
#define SIPAEVENT_MODULE_SIZE       0x00070002UL
#define SIPAEVENT_MODULE_HASHALG    0x00070003UL
#define SIPAEVENT_MODULE_HASH       0x00070004UL
#define SIPAEVENT_MODULE_THUMBPRINT 0x00070009UL
#define SIPAEVENT_MODULE_INTERNAL   0x0007000DUL

#define BOOT_MODULE_MAX 512

typedef struct {
    char   path[MAX_PATH];       /* NT relative path, e.g., \WINDOWS\System32\drivers\x.sys */
    char   internalName[ATTEST_NAME_MAX];
    BYTE   hash[64];
    UINT32 hashLen;
    UINT16 alg;                  /* CALG_*: Always 0x800C (SHA256) on the local machine. */
    BYTE   thumb[20];
    int    haveThumb;
    int    matchedLoaded;        /* Whether this boot module is still present in the current VTL0 enumeration. */
} BootModule;

typedef struct {
    BootModule items[BOOT_MODULE_MAX];
    UINT32 count;
    UINT32 dropped;              /* Count of entries dropped due to capacity overflow */
    UINT32 containers;           /* Total number of containers observed: 0x40010003 (including the simplified version for PCR12).*/
    int    truncated;            /* Out of bounds during parsing; manifest incomplete. */
    UINT32 algFallback;          /* The digest algorithm is not in the digestSizes table, so the built-in length is used. */
    char   logPath[MAX_PATH];
    int    staleWarning;         /* Log timestamp is earlier than the current boot time. */
} BootModuleSet;

/*
 * A name entry for comparison: 'raw' is the lowercase original name, and 'key' is the comparison key after removing '.sys'.
 * Two entries are needed instead of one: the InternalName in the report comes from PE version resources, where
 * some entries on the same machine include extensions while others do not (e.g., qwavedrv.sys mixed with ndis).
 * Strictly matching only against raw would artificially create "one-sided" entries—the source of false positives.
 */
typedef struct {
    char   raw[ATTEST_NAME_MAX];
    char   key[ATTEST_NAME_MAX];
    char   path[MAX_PATH];   /* VTL0 side only: module's Win32 path. */
    BYTE   sha256[32];
    BYTE   sha1[20];
    UINT32 sha256Len;        /* 0 = Calculation failed. */
    UINT32 sha1Len;
    BYTE   reportHash[64];   /* Report side only: ImageHash */
    UINT32 reportHashLen;
    UINT16 reportAlg;
    int    unloaded;
    int    matched;          /* Name matches */
    int    hashMatched;      /* Hash matches */
    int    orphan;           /* Mutation testing: force treat as unknown to both attestation lists. */
} NameSlot;

/*
 * Compute the Authenticode PE image hash using the catalog API, not a flat file hash.
 * Empirically calibrated: The ImageHash in the report matches byte-for-byte the "SHA256
 * 0xDECE1DEF…" provided by AppLocker for afd.sys, whereas the flat SHA256 is completely different.
 * In other words, the secure kernel stores the **hash used by CI for signature verification**; it
 * skips the PE checksum and certificate table, so it remains stable for the same signed image.
 */
static int hashFileAuthenticode(HCATADMIN hAdmin, const char* path,
                                BYTE* out, UINT32 outCapacity, UINT32* outLen)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD cb = outCapacity;
    int ok = 0;

    if (hAdmin == NULL) { return 0; }
    hFile = CreateFileA(path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { return 0; }
    if (CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, &cb, out, 0)) {
        *outLen = (UINT32)cb;
        ok = 1;
    }
    CloseHandle(hFile);
    return ok;
}

/* The kernel provides an NT path; it must be converted to a Win32 path for CreateFile. */
static int buildWin32Path(const char* full, char* out, size_t outSize)
{
    char winDir[MAX_PATH];

    if (full[0] == '\0') { return 0; }
    if (_strnicmp(full, "\\SystemRoot\\", 12) == 0) {
        if (GetWindowsDirectoryA(winDir, (UINT)sizeof(winDir)) == 0U) { return 0; }
        return _snprintf_s(out, outSize, _TRUNCATE, "%s\\%s", winDir, full + 12) > 0;
    }
    if (_strnicmp(full, "\\??\\", 4) == 0) {
        return _snprintf_s(out, outSize, _TRUNCATE, "%s", full + 4) > 0;
    }
    if (full[0] == '\\') {
        /* Format like \Windows\System32\... — append the system drive letter. */
        if (GetWindowsDirectoryA(winDir, (UINT)sizeof(winDir)) == 0U) { return 0; }
        winDir[2] = '\0';
        return _snprintf_s(out, outSize, _TRUNCATE, "%s%s", winDir, full) > 0;
    }
    return _snprintf_s(out, outSize, _TRUNCATE, "%s", full) > 0;
}

/* Lowercase copy that always terminates with NUL. The source may be a fixed-length array without a NUL terminator, so an explicit limit is required. */
static void lowerCopy(char* dst, const char* src, size_t maxLen)
{
    size_t i;

    for (i = 0U; i < maxLen && i + 1U < (size_t)ATTEST_NAME_MAX && src[i] != '\0'; ++i) {
        char c = src[i];
        dst[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    dst[i] = '\0';
}

static void stripSysExt(char* s)
{
    size_t n = strlen(s);

    if (n > 4U && strcmp(s + n - 4U, ".sys") == 0) {
        s[n - 4U] = '\0';
    }
}

/* raw -> key: Lowercasing is already done; this step only removes the extension. */
static void fillKeyFromRaw(NameSlot* slot)
{
    memcpy(slot->key, slot->raw, strlen(slot->raw) + 1U);
    stripSysExt(slot->key);
}

/* Bounded read: fail on out-of-bounds instead of reading adjacent memory. */
static int tcgRead(const BYTE* b, size_t len, size_t* off, void* out, size_t n)
{
    if (*off > len || len - *off < n) { return 0; }
    memcpy(out, b + *off, n);
    *off += n;
    return 1;
}

static int tcgSkip(size_t len, size_t* off, size_t n)
{
    if (*off > len || len - *off < n) { return 0; }
    *off += n;
    return 1;
}

/* Convert UTF-16LE to local char for display and basename comparison only; replace non-ASCII with '?'. */
static void utf16ToNarrow(const BYTE* src, UINT32 srcBytes, char* dst, size_t dstSize)
{
    size_t o = 0U;
    UINT32 i;

    for (i = 0U; i + 1U < srcBytes && o + 1U < dstSize; i += 2U) {
        UINT16 w = (UINT16)(src[i] | ((UINT16)src[i + 1U] << 8));
        if (w == 0U) { break; }
        dst[o++] = (w < 0x80U) ? (char)w : '?';
    }
    dst[o] = '\0';
}

/*
 * Walk one level of SIPA event sequence. Aggregated events (ID with 0x40000000) contain another string of SIPA events,
 * so recursion is required; the depth limit prevents stack overflow from malformed logs, not a business requirement.
 */
static void sipaWalk(const BYTE* b, size_t start, size_t end, int depth,
                     BootModuleSet* set)
{
    size_t o = start;

    if (depth > 8) { return; }
    while (o + 8U <= end) {
        UINT32 id = 0U;
        UINT32 len = 0U;
        size_t body;

        memcpy(&id, b + o, 4U);
        memcpy(&len, b + o + 4U, 4U);
        body = o + 8U;
        if (len > end - body) { set->truncated = 1; return; }

        if (id == SIPAEVENT_LOADEDMODULE_AGG) {
            BootModule m;
            size_t f = body;
            size_t fend = body + len;

            set->containers++;
            memset(&m, 0, sizeof(m));
            while (f + 8U <= fend) {
                UINT32 fid = 0U;
                UINT32 flen = 0U;
                const BYTE* fd;

                memcpy(&fid, b + f, 4U);
                memcpy(&flen, b + f + 4U, 4U);
                fd = b + f + 8U;
                if (flen > fend - (f + 8U)) { set->truncated = 1; break; }

                if (fid == SIPAEVENT_MODULE_PATH) {
                    utf16ToNarrow(fd, flen, m.path, sizeof(m.path));
                } else if (fid == SIPAEVENT_MODULE_INTERNAL) {
                    utf16ToNarrow(fd, flen, m.internalName, sizeof(m.internalName));
                } else if (fid == SIPAEVENT_MODULE_HASH) {
                    if (flen != 0U && flen <= sizeof(m.hash)) {
                        memcpy(m.hash, fd, flen);
                        m.hashLen = flen;
                    }
                } else if (fid == SIPAEVENT_MODULE_HASHALG) {
                    if (flen == 4U) {
                        UINT32 a = 0U;
                        memcpy(&a, fd, 4U);
                        m.alg = (UINT16)a;
                    }
                } else if (fid == SIPAEVENT_MODULE_THUMBPRINT) {
                    if (flen == sizeof(m.thumb)) {
                        memcpy(m.thumb, fd, flen);
                        m.haveThumb = 1;
                    }
                }
                f += 8U + flen;
            }

            if (m.hashLen != 0U) {
                /*
                 * PCR12 and PCR13 measure the same set of modules: PCR12 containers hold only the hash and size,
                 * while PCR13 includes the path and certificate. Deduplicate by hash, letting the version with the
                 * path override the earlier minimal entry; otherwise, half the manifest entries would lack a name.
                 */
                UINT32 k;
                int merged = 0;

                for (k = 0U; k < set->count; ++k) {
                    if (set->items[k].hashLen == m.hashLen &&
                        memcmp(set->items[k].hash, m.hash, m.hashLen) == 0) {
                        if (set->items[k].path[0] == '\0' && m.path[0] != '\0') {
                            set->items[k] = m;
                        }
                        merged = 1;
                        break;
                    }
                }
                if (!merged) {
                    if (set->count < BOOT_MODULE_MAX) {
                        set->items[set->count++] = m;
                    } else {
                        set->dropped++;
                    }
                }
            }
        } else if ((id & SIPA_AGGREGATION_BIT) != 0U) {
            sipaWalk(b, body, body + len, depth + 1, set);
        }
        o = body + len;
    }
}

/* Select the log from the current boot: filename is <boot_count>-<recovery_count>.log, take the maximum by numeric value. */
static int findLatestBootLog(char* out, size_t outSize)
{
    char dir[MAX_PATH];
    char pattern[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    unsigned long bestBoot = 0UL;
    unsigned long bestResume = 0UL;
    char bestName[MAX_PATH];
    int found = 0;

    if (GetWindowsDirectoryA(dir, (UINT)sizeof(dir)) == 0U) { return 0; }
    if (_snprintf_s(pattern, sizeof(pattern), _TRUNCATE,
                    "%s\\Logs\\MeasuredBoot\\*.log", dir) < 0) {
        return 0;
    }
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) { return 0; }
    bestName[0] = '\0';
    do {
        unsigned long bc = 0UL;
        unsigned long rc = 0UL;

        if (sscanf_s(fd.cFileName, "%lu-%lu.log", &bc, &rc) == 2) {
            if (!found || bc > bestBoot || (bc == bestBoot && rc > bestResume)) {
                bestBoot = bc;
                bestResume = rc;
                found = 1;
                memcpy(bestName, fd.cFileName, strlen(fd.cFileName) + 1U);
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    if (!found) { return 0; }
    return _snprintf_s(out, outSize, _TRUNCATE,
                       "%s\\Logs\\MeasuredBoot\\%s", dir, bestName) > 0;
}

/*
 * Read and parse the boot measurement log. Returns 1 if the module list is obtained.
 *
 * The digest length **must** be read from the digestSizes table in the first Spec ID Event, not hardcoded:
 * Switching machines might measure both SHA1 and SHA256 simultaneously; hardcoding 32 will immediately cause the offset to go out of bounds.
 */
static int loadBootModules(BootModuleSet* set)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER fileSize;
    BYTE* b = NULL;
    DWORD got = 0U;
    size_t len = 0U;
    size_t off = 0U;
    UINT32 eventSize = 0U;
    UINT32 algCount = 0U;
    UINT16 algIds[16];
    UINT16 algSizes[16];
    UINT32 i;
    int ok = 0;

    memset(set, 0, sizeof(*set));
    if (!findLatestBootLog(set->logPath, sizeof(set->logPath))) { return 0; }

    hFile = CreateFileA(set->logPath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { return 0; }
    if (!GetFileSizeEx(hFile, &fileSize) ||
        fileSize.QuadPart <= 0 || fileSize.QuadPart > 64 * 1024 * 1024) {
        CloseHandle(hFile);
        return 0;
    }

    /*
     * Must verify whether the log belongs to the current boot; do not assume. When using it as a whitelist for drivers during the
     * startup phase, a log from a previous boot would cause all genuinely new startup drivers in the current boot to trigger alerts.
     */
    {
        FILETIME ftWrite;
        FILETIME ftNow;
        ULONGLONG now;
        ULONGLONG wrote;
        ULONGLONG bootAt;

        if (GetFileTime(hFile, NULL, NULL, &ftWrite)) {
            GetSystemTimeAsFileTime(&ftNow);
            now = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;
            wrote = ((ULONGLONG)ftWrite.dwHighDateTime << 32) | ftWrite.dwLowDateTime;
            bootAt = now - (GetTickCount64() * 10000ULL);
            /* Allows for 60 seconds: the boot time is derived backwards from ticks and is inherently imprecise. */
            if (wrote + 60ULL * 10000000ULL < bootAt) {
                set->staleWarning = 1;
            }
        }
    }

    len = (size_t)fileSize.QuadPart;
    b = (BYTE*)malloc(len);
    if (b == NULL) { CloseHandle(hFile); return 0; }
    if (!ReadFile(hFile, b, (DWORD)len, &got, NULL) || got != (DWORD)len) {
        free(b);
        CloseHandle(hFile);
        return 0;
    }
    CloseHandle(hFile);

    /* The first entry is a legacy TCG_PCClientPCREvent: PCR(4), Type(4), SHA1 digest(20), Length(4). */
    if (!tcgSkip(len, &off, 4U + 4U + 20U) ||
        !tcgRead(b, len, &off, &eventSize, 4U)) {
        free(b);
        return 0;
    }
    {
        /* Spec ID Event: Signature (16) Platform Class (4) Sub (1) Major (1) Revision (1) uintn (1) Algorithm Count (4) */
        size_t spec = off;

        if (!tcgSkip(len, &spec, 16U + 4U + 1U + 1U + 1U + 1U) ||
            !tcgRead(b, len, &spec, &algCount, 4U) ||
            algCount == 0U || algCount > 16U) {
            free(b);
            return 0;
        }
        for (i = 0U; i < algCount; ++i) {
            if (!tcgRead(b, len, &spec, &algIds[i], 2U) ||
                !tcgRead(b, len, &spec, &algSizes[i], 2U)) {
                free(b);
                return 0;
            }
        }
    }
    if (!tcgSkip(len, &off, eventSize)) { free(b); return 0; }

    /* The rest are all TCG_PCR_EVENT2. */
    while (off + 12U <= len) {
        UINT32 pcr = 0U;
        UINT32 type = 0U;
        UINT32 digestCount = 0U;
        UINT32 d;

        if (!tcgRead(b, len, &off, &pcr, 4U) ||
            !tcgRead(b, len, &off, &type, 4U) ||
            !tcgRead(b, len, &off, &digestCount, 4U)) {
            set->truncated = 1;
            break;
        }
        if (digestCount > 16U) { set->truncated = 1; break; }
        for (d = 0U; d < digestCount; ++d) {
            UINT16 alg = 0U;
            UINT16 dlen = 0U;
            UINT32 k;

            if (!tcgRead(b, len, &off, &alg, 2U)) { set->truncated = 1; break; }
            for (k = 0U; k < algCount; ++k) {
                if (algIds[k] == alg) { dlen = algSizes[k]; break; }
            }
            if (dlen == 0U) {
                /*
                 * The specification requires all algorithms that appear to be registered in the digestSizes table, but in practice, some
                 * firmware violates this. If the table lookup fails, we fall back to the built-in length and log a note, rather than discarding
                 * the entire log—discarding would silently invalidate the reverse check. If a fallback occurs, we mark it as truncated to
                 * disable the reverse direction in the health gate; it is better to skip the check than to report a suspicious list.
                 */
                switch (alg) {
                case 0x0004: dlen = 20U; break;  /* SHA1   */
                case 0x000B: dlen = 32U; break;  /* SHA256 */
                case 0x000C: dlen = 48U; break;  /* SHA384 */
                case 0x000D: dlen = 64U; break;  /* SHA512 */
                case 0x0012: dlen = 32U; break;  /* SM3_256 */
                default: break;
                }
                set->algFallback++;
                if (dlen == 0U) { set->truncated = 1; break; }
            }
            if (!tcgSkip(len, &off, dlen)) { set->truncated = 1; break; }
        }
        if (set->truncated) { break; }
        if (!tcgRead(b, len, &off, &eventSize, 4U)) { set->truncated = 1; break; }
        if (eventSize > len - off) { set->truncated = 1; break; }

        if (type == TCG_EV_EVENT_TAG && eventSize >= 8U) {
            UINT32 tagId = 0U;
            UINT32 tagLen = 0U;

            memcpy(&tagId, b + off, 4U);
            memcpy(&tagLen, b + off + 4U, 4U);
            if (tagId == SIPAEVENT_TRUSTBOUNDARY && tagLen <= eventSize - 8U) {
                sipaWalk(b, off + 8U, off + 8U + tagLen, 1, set);
            }
        }
        off += eventSize;
        ok = 1;
    }

    free(b);
    return ok && set->count != 0U;
}

int main(int argc, char** argv)
{
    HMODULE kernelbase = NULL;
    PFN_GET_RUNTIME_ATTESTATION_REPORT fn = NULL;
    UCHAR nonce[RUNTIME_REPORT_NONCE_SIZE];
    BYTE* buffer = NULL;
    UINT32 size = 0U;
    DWORD err = 0U;
    const RUNTIME_REPORT_PACKAGE_HEADER* pkg = NULL;
    const DRIVER_RUNTIME_REPORT* rep = NULL;
    const BYTE* authStart = NULL;
    UINT32 authOffset = 0U;
    UINT16 index = 0U;
    NameSlot* repNames = NULL;
    int verdictHits = 0;
    int i;

    (void)SetConsoleOutputCP(CP_UTF8);
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--json") == 0) { gJson = 1; }
        if (strcmp(argv[i], "--verdict") == 0) { gVerdict = 1; }
        if (strncmp(argv[i], "--selftest-hide=", 16) == 0) {
            gHideName = argv[i] + 16;
        }
        if (strncmp(argv[i], "--selftest-orphan=", 18) == 0) {
            gOrphanName = argv[i] + 18;
        }
    }

    kernelbase = GetModuleHandleW(L"kernelbase.dll");
    if (kernelbase == NULL) {
        kernelbase = LoadLibraryW(L"kernelbase.dll");
    }
    if (kernelbase != NULL) {
        fn = (PFN_GET_RUNTIME_ATTESTATION_REPORT)(void*)
            GetProcAddress(kernelbase, "GetRuntimeAttestationReport");
    }
    if (fn == NULL) {
        fprintf(stderr,
                "kernelbase.dll 里没有 GetRuntimeAttestationReport。\n"
                "这个 API 需要 Windows 11 一代及以上；老系统上这条路不存在。\n");
        return 2;
    }

    /* nonce is only used to bind the signature to this request; its content does not need to be kept secret. */
    for (i = 0; i < RUNTIME_REPORT_NONCE_SIZE; ++i) {
        nonce[i] = (UCHAR)(rand() & 0xFF);
    }

    /*
     * Pitfall 2: A successful call in this scenario returns FALSE with GetLastError() == 122.
     * Treating it as a failure would cause the entire path to deadlock at the first step.
     */
    SetLastError(0);
    (void)fn(nonce, RUNTIME_REPORT_PACKAGE_VERSION_CURRENT,
             RUNTIME_REPORT_TYPE_TO_MASK(RuntimeReportTypeDriver),
             NULL, &size);
    err = GetLastError();
    if (err != ERROR_INSUFFICIENT_BUFFER || size == 0U) {
        fprintf(stderr,
                "尺寸查询没有按预期返回 ERROR_INSUFFICIENT_BUFFER：err=%lu size=%u\n"
                "常见成因：系统未开 VBS，或 testsigning/调试标志开着（文档要求关闭）。\n",
                err, size);
        return 3;
    }

    buffer = (BYTE*)calloc(1U, size);
    if (buffer == NULL) {
        fprintf(stderr, "分配 %u 字节失败\n", size);
        return 4;
    }

    SetLastError(0);
    if (!fn(nonce, RUNTIME_REPORT_PACKAGE_VERSION_CURRENT,
            RUNTIME_REPORT_TYPE_TO_MASK(RuntimeReportTypeDriver),
            buffer, &size)) {
        fprintf(stderr, "取报告失败：err=%lu\n", GetLastError());
        free(buffer);
        return 5;
    }

    pkg = (const RUNTIME_REPORT_PACKAGE_HEADER*)buffer;
    if (pkg->Magic != RUNTIME_REPORT_PACKAGE_MAGIC) {
        fprintf(stderr, "包头 Magic 不是 RTRP：0x%08X\n", pkg->Magic);
        free(buffer);
        return 6;
    }

    /*
     * Pitfall 3: Use sizeof accumulation for layout; do not manually sum field sizes.
     * Auth section = header + nonce + digest header + signature, followed by the report body.
     */
    authOffset = (UINT32)sizeof(RUNTIME_REPORT_PACKAGE_HEADER) +
                 (UINT32)RUNTIME_REPORT_NONCE_SIZE +
                 pkg->TotalReportDigestsSize +
                 pkg->SignatureSize;
    if (authOffset + pkg->TotalAuthenticatedReportsSize > size) {
        fprintf(stderr,
                "布局越界：authOffset=%u + auth=%u > size=%u\n",
                authOffset, pkg->TotalAuthenticatedReportsSize, size);
        free(buffer);
        return 7;
    }
    authStart = buffer + authOffset;
    rep = (const DRIVER_RUNTIME_REPORT*)authStart;

    if (rep->Header.ReportType != RuntimeReportTypeDriver) {
        fprintf(stderr, "第一份报告不是 Driver 类型：%u\n", rep->Header.ReportType);
        free(buffer);
        return 8;
    }

    if (gJson) {
        printf("{\"kind\":\"attest-drivers\",\"packageSize\":%u,"
               "\"signatureScheme\":%u,\"signatureSize\":%u,"
               "\"digestAlg\":\"%s\",\"numberOfDrivers\":%u,"
               "\"reportOverflowed\":%s,\"partialReport\":%s,"
               "\"includeBootDrivers\":%s,\"drivers\":[",
               pkg->PackageSize, pkg->SignatureScheme, pkg->SignatureSize,
               hashAlgName(pkg->ReportDigestType), rep->NumberOfDrivers,
               rep->Flags.ReportOverflowed ? "true" : "false",
               rep->Flags.PartialReport ? "true" : "false",
               rep->Flags.IncludeBootDrivers ? "true" : "false");
    } else {
        printf("\n=== 安全内核（VTL1）签名的运行时驱动报告 ===\n");
        printf("  包大小       : %u 字节\n", pkg->PackageSize);
        printf("  摘要算法     : %s (0x%04X)\n",
               hashAlgName(pkg->ReportDigestType), pkg->ReportDigestType);
        printf("  签名方案     : %u %s   签名长度 %u 字节\n",
               pkg->SignatureScheme,
               pkg->SignatureScheme ==
                   RUNTIME_REPORT_SIGNATURE_SCHEME_SHA512_RSA_PSS_SHA512
                   ? "(SHA512-RSA-PSS-SHA512)" : "(未知方案)",
               pkg->SignatureSize);
        printf("  驱动条数     : %u\n", rep->NumberOfDrivers);
        printf("  报告标志     : ReportOverflowed=%u  PartialReport=%u  "
               "IncludeBootDrivers=%u\n",
               rep->Flags.ReportOverflowed, rep->Flags.PartialReport,
               rep->Flags.IncludeBootDrivers);
        if (!rep->Flags.IncludeBootDrivers) {
            printf("               ^ 为 0 表示**不含启动期驱动**，那部分信息在 "
                   "TCG Log 里。\n"
                   "                 直接拿这份清单与已加载模块做差集，会把全部"
                   "启动驱动误判成隐藏驱动。\n");
        }
        if (rep->Flags.ReportOverflowed) {
            printf("               ^ ReportOverflowed=1：安全内核的条数上限被"
                   "撑满，**清单不完整**。\n");
        }
        printf("\n  %-34s %5s %-8s %s\n",
               "InternalName", "Load", "标志", "镜像摘要 / 证书指纹");
        printf("  %s\n",
               "--------------------------------------------------------------"
               "-----------------");
    }

    repNames = (NameSlot*)calloc(
        rep->NumberOfDrivers ? rep->NumberOfDrivers : 1U, sizeof(NameSlot));
    if (repNames == NULL) {
        fprintf(stderr, "分配名字表失败\n");
        free(buffer);
        return 9;
    }

    for (index = 0U; index < rep->NumberOfDrivers; ++index) {
        const DRIVER_INFO_ENTRY* e = &rep->DriverEntries[index];
        char name[DRIVER_REPORT_NAME_MAX_LENGTH + 1];
        const BYTE* imageHash = NULL;
        const BYTE* thumb = NULL;
        const char* oem = NULL;

        /* InternalName is a fixed-length CHAR array and may not be NUL-terminated. */
        memcpy(name, e->InternalName, DRIVER_REPORT_NAME_MAX_LENGTH);
        name[DRIVER_REPORT_NAME_MAX_LENGTH] = '\0';

        lowerCopy(repNames[index].raw, name, DRIVER_REPORT_NAME_MAX_LENGTH);
        fillKeyFromRaw(&repNames[index]);
        repNames[index].unloaded = e->Flags.Unloaded ? 1 : 0;
        repNames[index].reportAlg = e->ImageHashAlgorithm;

        /* The dynamic region offset is relative to the report start, not the package start. */
        if (e->ImageHashOffset != 0U &&
            e->ImageHashOffset < pkg->TotalAuthenticatedReportsSize) {
            imageHash = authStart + e->ImageHashOffset;
            if (hashLen(e->ImageHashAlgorithm) != 0U) {
                repNames[index].reportHashLen = hashLen(e->ImageHashAlgorithm);
                memcpy(repNames[index].reportHash, imageHash,
                       repNames[index].reportHashLen);
            }
        }
        if (e->PublisherThumbprintOffset != 0U &&
            e->PublisherThumbprintOffset < pkg->TotalAuthenticatedReportsSize) {
            thumb = authStart + e->PublisherThumbprintOffset;
        }
        if (e->OemNameSize != 0U && e->OemNameOffset != 0U &&
            e->OemNameOffset < pkg->TotalAuthenticatedReportsSize) {
            oem = (const char*)(authStart + e->OemNameOffset);
        }

        if (gJson) {
            printf("%s{\"name\":", index ? "," : "");
            printJsonString(name, DRIVER_REPORT_NAME_MAX_LENGTH);
            printf(",\"loadCount\":%u,\"unloaded\":%s,\"bootDriver\":%s,"
                   "\"hotPatch\":%s,\"imageHashAlg\":\"%s\",\"imageHash\":\"",
                   e->LoadCount,
                   e->Flags.Unloaded ? "true" : "false",
                   e->Flags.BootDriver ? "true" : "false",
                   e->Flags.HotPatch ? "true" : "false",
                   hashAlgName(e->ImageHashAlgorithm));
            if (imageHash != NULL && hashLen(e->ImageHashAlgorithm) != 0U) {
                printHashHex(imageHash, hashLen(e->ImageHashAlgorithm),
                             hashLen(e->ImageHashAlgorithm));
            }
            printf("\",\"publisherThumbprint\":\"");
            if (thumb != NULL) {
                printHashHex(thumb, THUMBPRINT_LEN, THUMBPRINT_LEN);
            }
            printf("\",\"oemName\":");
            if (oem != NULL) { printJsonString(oem, e->OemNameSize); }
            else { printf("null"); }
            printf("}");
        } else {
            printf("  %-34.34s %5u %c%c%c      ",
                   name, e->LoadCount,
                   e->Flags.Unloaded   ? 'U' : '-',
                   e->Flags.BootDriver ? 'B' : '-',
                   e->Flags.HotPatch   ? 'H' : '-');
            printf("%-6s ", hashAlgName(e->ImageHashAlgorithm));
            if (imageHash != NULL && hashLen(e->ImageHashAlgorithm) != 0U) {
                printHashHex(imageHash, hashLen(e->ImageHashAlgorithm), 8U);
            } else {
                printf("(无摘要)");
            }
            printf(" / ");
            if (thumb != NULL) {
                printHashHex(thumb, THUMBPRINT_LEN, 8U);
            } else {
                printf("(无指纹)");
            }
            if (oem != NULL && e->OemNameSize != 0U) {
                printf("  OEM=%.*s", (int)e->OemNameSize, oem);
            }
            printf("\n");
        }
    }

    if (gJson) {
        printf("],");
    } else {
        printf("\n  标志：U=已卸载  B=启动期驱动  H=可热补丁\n");
    }

    /*
     * Side-by-side comparison: VTL1-signed reports vs. VTL0's own enumeration.
     *
     * Here, only the difference between the two sides is listed, with no criteria applied. Both directions have known benign causes:
     *   * Only in VTL1 — unloaded modules are naturally not enumerable from VTL0; this is precisely the value of this path.
     *   * Only within VTL0 — IncludeBootDrivers=0 means all boot-time drivers are excluded from the report;
     *     There is another batch of drivers whose InternalName differs from the disk base name.
     * If these two categories are not calibrated first, the difference-set criterion will produce false-positive alerts.
     */
    {
        enum { kMaxLoaded = 4096 };
        PFN_NT_QUERY_SYSTEM_INFORMATION ntq = NULL;
        HMODULE ntdll = NULL;
        KswRtlProcessModules* sysmods = NULL;
        ULONG sysmodsSize = 0U;
        LONG st = 0;
        NameSlot* loaded = NULL;
        LPVOID* mods = NULL;
        DWORD needed = 0U;
        DWORD psapiCount = 0U;
        DWORD count = 0U;
        DWORD di = 0U;
        DWORD both = 0U;
        DWORD relaxed = 0U;
        DWORD truncated = 0U;
        UINT16 ri = 0U;
        UINT16 onlyReport = 0U;
        DWORD onlyLoaded = 0U;
        DWORD nameMissHashHit = 0U;   /* Name mismatch but hash match — the same image with a different name. */
        DWORD nameHitHashMiss = 0U;   /* Name matches but hash does not — the file on disk is no longer the one that was loaded. */
        DWORD neitherReport = 0U;     /* Both dimensions do not match (report side).*/
        DWORD neitherLoaded = 0U;     /* Both dimensions do not match (VTL0 side).*/
        DWORD noReportHash = 0U;      /* No hash included in the report. */
        DWORD noFileHash = 0U;        /* Disk file hash could not be calculated. */
        DWORD hitCount = 0U;          /* Forward criterion hit count. */
        BootModuleSet* boot = NULL; /* List of boot-time modules in the TCG Log */
        int haveBoot = 0;
        DWORD bootReportHit = 0U;     /* Report side-mismatched entries found in the boot manifest. */
        DWORD bootLoadedHit = 0U;     /* Two-dimensional unmatched entries on the VTL0 side found in the boot manifest. */
        DWORD reverseHits = 0U;       /* VTL0 modules not found in all three locations — reverse criterion. */
        int reverseUsable = 0;        /* Reverse check allowed only if the launch manifest is healthy */

        /* psapi is retained only for count cross-verification; names are not trusted (see comments above the file). */
        mods = (LPVOID*)calloc(kMaxLoaded, sizeof(LPVOID));
        if (mods != NULL &&
            EnumDeviceDrivers(mods, (DWORD)(kMaxLoaded * sizeof(LPVOID)), &needed)) {
            psapiCount = needed / (DWORD)sizeof(LPVOID);
        }
        free(mods);
        mods = NULL;

        ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll != NULL) {
            ntq = (PFN_NT_QUERY_SYSTEM_INFORMATION)(void*)
                GetProcAddress(ntdll, "NtQuerySystemInformation");
        }
        if (ntq != NULL) {
            /*
             * Size may change between calls (drivers loading/unloading), so use a retry loop
             * instead of "query size once then fetch". Add 16KB buffer to reduce retries.
             */
            ULONG want = 0U;
            int attempt;

            st = ntq(SYSTEM_MODULE_INFORMATION_CLASS, NULL, 0U, &want);
            if (want == 0U) { want = 64U * 1024U; }
            for (attempt = 0; attempt < 8; ++attempt) {
                free(sysmods);
                sysmodsSize = want + 16U * 1024U;
                sysmods = (KswRtlProcessModules*)calloc(1U, sysmodsSize);
                if (sysmods == NULL) { break; }
                st = ntq(SYSTEM_MODULE_INFORMATION_CLASS, sysmods, sysmodsSize, &want);
                if (st != STATUS_INFO_LENGTH_MISMATCH_L) { break; }
            }
            if (st != 0 && sysmods != NULL) {
                free(sysmods);
                sysmods = NULL;
            }
        }

        if (sysmods != NULL) {
            count = sysmods->numberOfModules;
            if (count > (DWORD)kMaxLoaded) {
                truncated = count - (DWORD)kMaxLoaded;
                count = (DWORD)kMaxLoaded;
            }
        }

        loaded = (NameSlot*)calloc(count ? count : 1U, sizeof(NameSlot));
        if (loaded != NULL && sysmods != NULL) {
            for (di = 0U; di < count; ++di) {
                const KswRtlProcessModuleInformation* m = &sysmods->modules[di];
                const char* full = (const char*)m->fullPathName;
                const char* base = full;

                /* OffsetToFileName is the base name offset provided by the kernel; if out of bounds, find the separator manually. */
                if (m->offsetToFileName < sizeof(m->fullPathName)) {
                    base = full + m->offsetToFileName;
                } else {
                    const char* p = strrchr(full, '\\');
                    if (p != NULL) { base = p + 1; }
                }
                lowerCopy(loaded[di].raw, base,
                          sizeof(m->fullPathName) - (size_t)(base - full));
                fillKeyFromRaw(&loaded[di]);
                (void)buildWin32Path(full, loaded[di].path, sizeof(loaded[di].path));
            }
        }

        /*
         * Authenticode hash on the VTL0 side. Create each HCATADMIN once rather than per file:
         * 265 modules × 2 algorithms = 530 hash operations; the overhead of repeatedly calling AcquireContext exceeds the hash cost itself.
         */
        if (loaded != NULL && sysmods != NULL) {
            HCATADMIN hSha1 = NULL;
            HCATADMIN hSha256 = NULL;

            (void)CryptCATAdminAcquireContext2(&hSha1,   NULL, L"SHA1",   NULL, 0U);
            (void)CryptCATAdminAcquireContext2(&hSha256, NULL, L"SHA256", NULL, 0U);
            for (di = 0U; di < count; ++di) {
                if (loaded[di].path[0] == '\0') { continue; }
                if (!hashFileAuthenticode(hSha256, loaded[di].path,
                                          loaded[di].sha256, 32U,
                                          &loaded[di].sha256Len)) {
                    loaded[di].sha256Len = 0U;
                }
                if (!hashFileAuthenticode(hSha1, loaded[di].path,
                                          loaded[di].sha1, 20U,
                                          &loaded[di].sha1Len)) {
                    loaded[di].sha1Len = 0U;
                }
            }
            if (hSha1   != NULL) { (void)CryptCATAdminReleaseContext(hSha1, 0U); }
            if (hSha256 != NULL) { (void)CryptCATAdminReleaseContext(hSha256, 0U); }

            if (gHideName != NULL) {
                DWORD hidden = 0U;

                for (di = 0U; di < count; ++di) {
                    if (_stricmp(loaded[di].raw, gHideName) != 0) { continue; }
                    loaded[di].sha1Len = 0U;
                    loaded[di].sha256Len = 0U;
                    loaded[di].key[0] = '\0';
                    hidden++;
                }
                if (!gJson) {
                    printf("\n  *** 变异测试模式：已把 %lu 个名为 \"%s\" 的模块"
                           "从 VTL0 参照面抹掉 ***\n"
                           "      下面的结果**不是**本机真实状态。\n",
                           hidden, gHideName);
                }
            }
        }
        if (loaded != NULL && sysmods != NULL) {

            /* Bidirectional marking by key; O(n*m) with n=193 and m=265, so using a hash table is not worthwhile. */
            for (di = 0U; di < count; ++di) {
                if (loaded[di].key[0] == '\0') { continue; }
                for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                    if (repNames[ri].key[0] == '\0') { continue; }
                    if (strcmp(loaded[di].key, repNames[ri].key) == 0) {
                        loaded[di].matched = 1;
                        repNames[ri].matched = 1;
                        both++;
                        if (strcmp(loaded[di].raw, repNames[ri].raw) != 0) {
                            relaxed++;
                        }
                        break;
                    }
                }
                if (!loaded[di].matched) { onlyLoaded++; }
            }
            for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                if (!repNames[ri].matched) { onlyReport++; }
            }

            /*
             * Second-dimension matching: Authenticode hash. The name dimension is
             * already fixed by data (InternalName is free-form version resource text,
             * truncated at 32 bytes); the hash is the only key independent of the name.
             */
            for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                if (repNames[ri].reportHashLen == 0U) { continue; }
                for (di = 0U; di < count; ++di) {
                    const BYTE* v = NULL;
                    UINT32 vlen = 0U;

                    if (repNames[ri].reportAlg == 0x800C) {
                        v = loaded[di].sha256; vlen = loaded[di].sha256Len;
                    } else if (repNames[ri].reportAlg == 0x8004) {
                        v = loaded[di].sha1;   vlen = loaded[di].sha1Len;
                    }
                    if (vlen == 0U || vlen != repNames[ri].reportHashLen) { continue; }
                    if (memcmp(repNames[ri].reportHash, v, vlen) == 0) {
                        repNames[ri].hashMatched = 1;
                        loaded[di].hashMatched = 1;
                        break;
                    }
                }
            }
            for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                if (repNames[ri].reportHashLen == 0U) { noReportHash++; continue; }
                if (repNames[ri].hashMatched) {
                    if (!repNames[ri].matched) { nameMissHashHit++; }
                } else {
                    if (repNames[ri].matched) { nameHitHashMiss++; }
                    else { neitherReport++; }
                    /*
                     * The criterion checks only the hash, not the name: a matching name should not save an entry with
                     * a mismatching hash—a hidden driver could set its InternalName to that of a legitimate driver.
                     */
                    if (!repNames[ri].unloaded) { hitCount++; }
                }
            }
            for (di = 0U; di < count; ++di) {
                if (!loaded[di].matched && !loaded[di].hashMatched) { neitherLoaded++; }
                if (loaded[di].sha256Len == 0U && loaded[di].sha1Len == 0U) {
                    noFileHash++;
                }
            }

            /*
             * Third source: the TCG Log's boot-time module list, used to supplement the
             * batch missing due to IncludeBootDrivers=0. Since the summaries of all three
             * lists are Authenticode PE image hashes, they can be directly merged by hash.
             */
            if (gOrphanName != NULL) {
                DWORD orphaned = 0U;

                for (di = 0U; di < count; ++di) {
                    if (_stricmp(loaded[di].raw, gOrphanName) != 0) { continue; }
                    loaded[di].orphan = 1;
                    loaded[di].hashMatched = 0;
                    orphaned++;
                }
                if (!gJson) {
                    printf("\n  *** 变异测试模式：已把 %lu 个名为 \"%s\" 的模块"
                           "从**两份签名清单**里同时抹掉 ***\n"
                           "      下面的结果**不是**本机真实状态。\n",
                           orphaned, gOrphanName);
                }
            }

            boot = (BootModuleSet*)calloc(1U, sizeof(BootModuleSet));
            haveBoot = (boot != NULL) && loadBootModules(boot);
            if (haveBoot) {
                for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                    UINT32 k;

                    if (repNames[ri].hashMatched) { continue; }
                    if (repNames[ri].reportHashLen == 0U) { continue; }
                    for (k = 0U; k < boot->count; ++k) {
                        if (boot->items[k].hashLen == repNames[ri].reportHashLen &&
                            memcmp(boot->items[k].hash, repNames[ri].reportHash,
                                   boot->items[k].hashLen) == 0) {
                            bootReportHit++;
                            break;
                        }
                    }
                }
                for (di = 0U; di < count; ++di) {
                    UINT32 k;
                    int inBoot = 0;

                    for (k = 0U; k < boot->count && !loaded[di].orphan; ++k) {
                        if (boot->items[k].hashLen == 32U &&
                            loaded[di].sha256Len == 32U &&
                            memcmp(boot->items[k].hash, loaded[di].sha256, 32U) == 0) {
                            inBoot = 1;
                            boot->items[k].matchedLoaded = 1;
                            break;
                        }
                        if (boot->items[k].hashLen == 20U &&
                            loaded[di].sha1Len == 20U &&
                            memcmp(boot->items[k].hash, loaded[di].sha1, 20U) == 0) {
                            inBoot = 1;
                            boot->items[k].matchedLoaded = 1;
                            break;
                        }
                    }
                    if (!loaded[di].matched && !loaded[di].hashMatched && inBoot) {
                        bootLoadedHit++;
                    }
                    /*
                     * Reverse criterion candidate: This module is currently loaded in VTL0, but its image
                     * appears in neither the VTL1 runtime report nor the boot measurement manifest.
                     * Items that cannot be hashed from disk are not candidates — we simply cannot see them, not that they are suspicious.
                     */
                    if (!loaded[di].hashMatched && !inBoot &&
                        (loaded[di].sha256Len != 0U || loaded[di].sha1Len != 0U)) {
                        reverseHits++;
                    }
                }
                /*
                 * The reverse direction is only valid when the boot manifest is healthy. Any of the following—log
                 * expiration, parsing out-of-bounds, or capacity overflow causing dropped entries—will turn a 'missing'
                 * state into a false positive; in such cases, it is better not to judge than to report falsely.
                 */
                reverseUsable = !boot->staleWarning && !boot->truncated &&
                                boot->dropped == 0U && boot->algFallback == 0U;
            }
        }

        if (gJson) {
            printf("\"loadedModules\":%lu,\"matchedBoth\":%lu,"
                   "\"matchedOnlyAfterStrippingSys\":%lu,"
                   "\"enumTruncated\":%lu,"
                   "\"nameMissHashHit\":%lu,\"nameHitHashMiss\":%lu,"
                   "\"neitherReport\":%lu,\"neitherLoaded\":%lu,"
                   "\"noReportHash\":%lu,\"noFileHash\":%lu,"
                   "\"verdictHits\":%lu,"
                   "\"bootModules\":%lu,\"bootLogStale\":%s,"
                   "\"bootReportHit\":%lu,\"bootLoadedHit\":%lu,"
                   "\"reverseHits\":%lu,\"reverseUsable\":%s,"
                   "\"onlyInReport\":[",
                   count, both, relaxed, truncated,
                   nameMissHashHit, nameHitHashMiss,
                   neitherReport, neitherLoaded, noReportHash, noFileHash,
                   hitCount + (reverseUsable ? reverseHits : 0UL),
                   haveBoot ? boot->count : 0UL,
                   (haveBoot && boot->staleWarning) ? "true" : "false",
                   bootReportHit, bootLoadedHit, reverseHits,
                   reverseUsable ? "true" : "false");
            if (loaded != NULL && sysmods != NULL) {
                DWORD emitted = 0U;
                for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                    if (repNames[ri].matched) { continue; }
                    printf("%s{\"name\":", emitted ? "," : "");
                    printJsonString(repNames[ri].raw, ATTEST_NAME_MAX);
                    printf(",\"unloaded\":%s,\"hashMatched\":%s}",
                           repNames[ri].unloaded ? "true" : "false",
                           repNames[ri].hashMatched ? "true" : "false");
                    emitted++;
                }
                printf("],\"onlyInLoaded\":[");
                emitted = 0U;
                for (di = 0U; di < count; ++di) {
                    if (loaded[di].matched) { continue; }
                    printf("%s", emitted ? "," : "");
                    printJsonString(loaded[di].raw, ATTEST_NAME_MAX);
                    emitted++;
                }
                printf("]");
            } else {
                printf("],\"onlyInLoaded\":[]");
            }
            printf("}\n");
        } else {
            printf("\n=== 并排比对（原始数据，未下判据）===\n");
            printf("  VTL1 签名报告            : %u 条\n", rep->NumberOfDrivers);
            printf("  VTL0 SystemModuleInfo    : %lu 条%s\n", count,
                   truncated ? "（**被缓冲截断**，下面的差不完整）" : "");
            printf("  （交叉核验）EnumDeviceDrivers : %lu 条 —— 只用条数，"
                   "它的基名在本机全部返回 ntoskrnl.exe，不可用作参照面\n",
                   psapiCount);
            if (loaded == NULL || sysmods == NULL) {
                printf("  比对未进行：SystemModuleInformation 查询失败"
                       "（st=0x%08X）或分配失败。\n", (unsigned)st);
            } else {
                printf("\n  [名字维度]\n");
                printf("    两边都有               : %lu 条"
                       "（其中 %lu 条是去掉 .sys 才对上的）\n", both, relaxed);
                printf("    只在 VTL1 报告里       : %u 条\n", onlyReport);
                printf("    只在 VTL0 枚举里       : %lu 条\n", onlyLoaded);

                printf("\n  [Authenticode 哈希维度 —— 与名字无关]\n");
                printf("    名字对不上但哈希对上   : %lu 条  ← 同一份镜像，"
                       "只是 InternalName 与文件名不同\n", nameMissHashHit);
                printf("    名字对上但哈希对不上   : %lu 条  ← 磁盘上的文件"
                       "已不是当初加载的那一份\n", nameHitHashMiss);
                printf("    两维都对不上（报告侧） : %lu 条\n", neitherReport);
                printf("    两维都对不上（VTL0侧） : %lu 条\n", neitherLoaded);
                printf("    报告里无摘要           : %lu 条\n", noReportHash);
                printf("    磁盘文件哈希算不出     : %lu 条\n", noFileHash);

                printf("\n  [TCG Log 启动期清单 —— 补 IncludeBootDrivers=0 的缺口]\n");
                if (!haveBoot) {
                    printf("    取不到启动度量日志，反向差集仍然不可用。\n");
                } else {
                    printf("    日志                   : %s\n", boot->logPath);
                    printf("    启动期模块             : %lu 条"
                           "（见到 %lu 个度量容器，PCR12/13 按摘要归并后）\n",
                           boot->count, boot->containers);
                    if (boot->staleWarning) {
                        printf("    [警告] 这份日志比本次开机还早 —— 它不是本次启动的度量，"
                               "下面的数字不可用。\n");
                    }
                    if (boot->truncated) {
                        printf("    [警告] 解析中途越界，启动清单不完整。\n");
                    }
                    if (boot->dropped != 0U) {
                        printf("    [警告] 超出容量丢弃 %lu 条。\n", boot->dropped);
                    }
                    printf("    补上报告侧未匹配       : %lu 条\n", bootReportHit);
                    printf("    补上 VTL0 侧未匹配     : %lu / %lu 条\n",
                           bootLoadedHit, neitherLoaded);
                    printf("    三处都找不到的 VTL0 模块: %lu 条  ← 反向判据的候选\n",
                           reverseHits);
                }

                printf("\n  --- 只在 VTL1 报告里（按名字）---\n");
                for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                    if (repNames[ri].matched) { continue; }
                    printf("    %-34.34s %-10s%s\n",
                           repNames[ri].raw[0] ? repNames[ri].raw : "(空名)",
                           repNames[ri].hashMatched ? "[哈希对上]" : "[哈希也没对上]",
                           repNames[ri].unloaded ? " [已卸载 —— 预期如此]" : "");
                }

                printf("\n  --- 只在 VTL0 枚举里（按名字）---\n");
                for (di = 0U; di < count; ++di) {
                    const char* tag = "";
                    UINT32 k;

                    if (loaded[di].matched) { continue; }
                    if (loaded[di].hashMatched) {
                        tag = "[运行时报告里有]";
                    } else if (haveBoot) {
                        tag = "[三处都没有]";
                        for (k = 0U; k < boot->count; ++k) {
                            if (boot->items[k].hashLen == 32U &&
                                loaded[di].sha256Len == 32U &&
                                memcmp(boot->items[k].hash, loaded[di].sha256, 32U) == 0) {
                                tag = "[启动清单里有]";
                                break;
                            }
                        }
                        if (loaded[di].sha256Len == 0U && loaded[di].sha1Len == 0U) {
                            tag = "[磁盘哈希算不出，无法判断]";
                        }
                    }
                    printf("    %-34.34s %s\n",
                           loaded[di].raw[0] ? loaded[di].raw : "(取名失败)", tag);
                }

                printf("\n  上面两张表都**不是**结论：\n"
                       "    * 只在 VTL1 里：已卸载模块本就该只出现在这边，"
                       "这正是本条路相对 EPT cross-view 的增量；\n"
                       "    * 只在 VTL0 里：IncludeBootDrivers=%u，为 0 时"
                       "全部启动期驱动都不在报告里；\n"
                       "      另有一批驱动的 InternalName 与磁盘基名本就不同。\n"
                       "      这两类不先标定掉就写差集判据，产出的是假阳性告警。\n",
                       rep->Flags.IncludeBootDrivers);
            }
        }

        /*
         * Criterion for Step 3. Disabled by default; only runs with --verdict. Once deployed, its
         * failure mode is a **false positive alert**. For an ARK tool, a false positive is worse
         * than a false negative, so this must be an explicit action rather than a side effect.
         */
        if (gVerdict) {
            if (loaded == NULL || sysmods == NULL) {
                verdictHits = -1;
                if (!gJson) {
                    printf("\n[判据未运行] VTL0 参照面取不到，无法比对。\n");
                }
            } else {
                verdictHits = (int)hitCount + (reverseUsable ? (int)reverseHits : 0);
                if (!gJson) {
                    printf("\n=== 判据（--verdict）===\n");
                    printf("  【正向】报告里**未卸载**的条目，其 Authenticode 摘要在\n"
                           "          VTL0 当前全部已加载模块的磁盘文件里找不到。\n");
                    printf("          成因二选一：模块对 VTL0 隐身，或磁盘文件已被换掉。\n");
                    printf("  【反向】VTL0 此刻加载着的模块，其 Authenticode 摘要在\n"
                           "          VTL1 运行时报告与 TCG 启动度量清单里**都**找不到。\n");
                    printf("  **只用哈希不用名字** —— 名字维度已被本机数据判死：\n"
                           "    InternalName 取自 PE 版本资源，可为空、可带版本号、"
                           "可在 32 字节处截断。\n");
                    if (!reverseUsable) {
                        printf("  [反向未启用] 启动清单不健康"
                               "（取不到 / 过期 / 解析越界 / 丢过条目），\n"
                               "               该方向本轮不判 —— **不等于该方向干净**。\n");
                    }
                    if (noFileHash != 0U) {
                        printf("  [降级] VTL0 侧有 %lu 个模块算不出磁盘哈希"
                               "（如 crashdump 栈的 dump_* 副本，磁盘上没有对应文件），\n"
                               "         它们两个方向都无法参与匹配。\n",
                               noFileHash);
                    }
                    /*
                     * A shared source of false positives in both directions must be displayed alongside the criteria:
                     * We compare the hash of the disk file at this exact moment, whereas the two manifests record
                     * the image at the moment the module was loaded/measured. If Windows Update has modified the
                     * file but the system hasn't restarted yet, they will naturally differ—that is not tampering.
                     */
                    printf("  [注意] 比的是磁盘文件**此刻**的哈希，两份清单记的是"
                           "加载/度量当时的镜像。\n"
                           "         打过补丁尚未重启时两者本就不同，"
                           "**不匹配不等于被篡改**，命中要人工核而不是直接告警。\n");
                    for (ri = 0U; ri < rep->NumberOfDrivers; ++ri) {
                        if (repNames[ri].unloaded) { continue; }
                        if (repNames[ri].reportHashLen == 0U) { continue; }
                        if (repNames[ri].hashMatched) { continue; }
                        printf("  [正向命中] %-28.28s  ",
                               repNames[ri].raw[0] ? repNames[ri].raw : "(空名)");
                        printHashHex(repNames[ri].reportHash,
                                     repNames[ri].reportHashLen,
                                     repNames[ri].reportHashLen);
                        printf("\n");
                    }
                    if (reverseUsable) {
                        for (di = 0U; di < count; ++di) {
                            UINT32 k;
                            int inBoot = 0;

                            if (loaded[di].hashMatched) { continue; }
                            if (loaded[di].sha256Len == 0U &&
                                loaded[di].sha1Len == 0U) { continue; }
                            for (k = 0U; k < boot->count && !loaded[di].orphan; ++k) {
                                if (boot->items[k].hashLen == 32U &&
                                    loaded[di].sha256Len == 32U &&
                                    memcmp(boot->items[k].hash,
                                           loaded[di].sha256, 32U) == 0) {
                                    inBoot = 1;
                                    break;
                                }
                            }
                            if (inBoot) { continue; }
                            printf("  [反向命中] %-28.28s  ",
                                   loaded[di].raw[0] ? loaded[di].raw : "(取名失败)");
                            if (loaded[di].sha256Len == 32U) {
                                printHashHex(loaded[di].sha256, 32U, 32U);
                            }
                            printf("\n    %s\n", loaded[di].path);
                        }
                    }
                    printf("  命中 %d 条（正向 %lu + 反向 %lu）。%s\n",
                           verdictHits, hitCount,
                           reverseUsable ? reverseHits : 0UL,
                           verdictHits == 0 ? "本机基线为零。" : "以上每条都要人工核。");
                }
            }
        }

        free(boot);
        free(loaded);
        free(sysmods);
    }

    free(repNames);
    free(buffer);

    /*
     * Exit codes are in three tiers, deliberately avoiding overlap with error codes 2..9:
     *   0: Normal (criteria not enabled, or zero hits). 20: Criteria hit —
     *   requires manual verification, not a "tool error". 21: Criteria did not
     *   run (VTL0 reference surface unavailable) — **does not equal clean**.
     */
    if (gVerdict && verdictHits < 0) { return 21; }
    if (gVerdict && verdictHits > 0) { return 20; }
    return 0;
}
