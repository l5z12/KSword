#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KSW_HVM_COMMAND_MAX_ARGS 4

typedef enum HvmCommandHandler {
    kHvmControl, kHvmStatus, kHvmCpuid, kHvmPlatform, kHvmFlags, kHvmAcl,
    kHvmNestedProbe, kHvmNestedProbeAll, kHvmNestedAd, kHvmSelfvirt, kHvmSelfvirtAll,
    kHvmGdt, kHvmMsrLog, kHvmMsrClear, kHvmXonly, kHvmAllowOnce, kHvmTlb, kHvmTlbExit,
    kHvmViewQuery, kHvmViewProbe, kHvmViewEffect, kHvmSelfcheck, kHvmViewVerify,
    kHvmEptLeaf, kHvmEvents, kHvmCrOn, kHvmCrOff,
    kHvmInjectQuery, kHvmInjectTest, kHvmInjectDll, kHvmInjectRelease, kHvmInjectClear,
    kHvmProcQuery, kHvmProcFreeze, kHvmProcTerminate, kHvmProcRelease, kHvmProcClear,
    kHvmPageQuery, kHvmPageMap, kHvmPageRemove, kHvmMetrics, kHvmPageMapTest, kHvmPageRemoveTest,
    /* Region overrides: publish at a chosen leaf granularity, then edit one page
       of the published region at a time. Appended rather than inserted so every
       existing handler keeps its ordinal. */
    kHvmPageMapRegion, kHvmPageMapRegionScan, kHvmPageStage, kHvmPageDigest,
    /* First-touch memory watch.  Appended so every existing ordinal is kept. */
    kHvmWatchAddVa, kHvmWatchAddPa, kHvmWatchList, kHvmWatchRearm, kHvmWatchRemove,
    kHvmWatchSelfTest, kHvmWatchSelfTestRead, kHvmWatchSelfTestExec,
    kHvmWatchSelfTestSmp, kHvmWatchSelfTestRemap, kHvmWatchSelfTestEvidence,
    kHvmWatchSelfTestConflict, kHvmWatchSelfTestRestart, kHvmWatchSelfTestProcess,
    kHvmHelp, kHvmCommands
} HvmCommandHandler;

typedef enum HvmArgumentKind {
    kHvmDecimal32, kHvmDecimal64, kHvmHex32, kHvmHex64, kHvmPageAddress, kHvmByte, kHvmPath
} HvmArgumentKind;

typedef struct HvmCommandArgument {
    const char* name;
    HvmArgumentKind kind;
    const char* defaultValue; /* NULL means required. Values retain their declared base. */
} HvmCommandArgument;

typedef struct HvmCommandSpec {
    const char* name;
    const char* title;
    const char* group;
    const char* description;
    HvmCommandHandler handler;
    int readOnly;
    unsigned long command;
    unsigned long flags;
    unsigned int argumentCount;
    HvmCommandArgument arguments[KSW_HVM_COMMAND_MAX_ARGS];
} HvmCommandSpec;

const HvmCommandSpec* kswordHvmCommands(size_t* count);
const HvmCommandSpec* kswordHvmFindCommand(const char* name);
/* Returns 0 on success. No driver access; used by both the form and dispatcher. */
int kswordHvmValidateArguments(const HvmCommandSpec* command, int count,
    const char* const* arguments, unsigned long long values[KSW_HVM_COMMAND_MAX_ARGS],
    char* error, size_t errorSize);
void kswordHvmPrintCommands(int asJson);
void kswordHvmPrintJsonString(const char* text);
int kswordHvmCommandMain(int argc, char** argv);
int kswordHvmCommandMainWide(int argc, wchar_t** argv);

#ifdef __cplusplus
}
#endif
