#pragma once

#include "../dyndata/dyndata_v4_internal.h"

EXTERN_C_START

NTSTATUS
kswordArkCiHashResolveRuntimeLayout(
    _Out_ KswDynV4CiKernelHashLayout* layoutOut
    );

EXTERN_C_END
