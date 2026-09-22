#pragma once

//
// kernel_image_section_map.h
//
// Classify kernel virtual addresses into their owning image's PE sections. Read-only diagnostic use: callers use this to
// determine if a function pointer truly resides within a module's executable section, not merely within the image address range.
//

#include "ark/ark_driver.h"

#include "hook_scan_support.h"

EXTERN_C_START

// Maximum character count for the section name copy. PE section names are fixed at 8 bytes, leaving one byte for the null terminator.
#define KSW_IMAGE_SECTION_NAME_CHARS 9UL

// Address cannot be classified: PE header unreadable or module entry missing.
#define KSW_IMAGE_SECTION_RESULT_UNKNOWN 0UL
// The address falls within a section marked with IMAGE_SCN_MEM_EXECUTE.
#define KSW_IMAGE_SECTION_RESULT_EXECUTABLE 1UL
// Address falls within a section, but that section is non-executable.
#define KSW_IMAGE_SECTION_RESULT_NON_EXECUTABLE 2UL
// Address is within the image range but does not belong to any section (PE header or inter-section gap).
#define KSW_IMAGE_SECTION_RESULT_OUTSIDE_SECTIONS 3UL

ULONG
kswordArkImageClassifyAddress(
    _In_opt_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ ULONGLONG address,
    _Out_writes_opt_z_(sectionNameChars) PWCHAR sectionName,
    _In_ ULONG sectionNameChars,
    _Out_opt_ ULONG* sectionCharacteristicsOut
    );

EXTERN_C_END
