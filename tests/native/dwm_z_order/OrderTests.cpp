#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include "../../../integrations/dwm_z_order/OrderPlan.h"
#include <algorithm>
#include <initializer_list>
#include <iostream>
#include <cwchar>
#include <vector>

using namespace ks::dwm_order;
void runLoaderTests(void (*check)(bool, const char*), const wchar_t* agentPath);
void runCfgTests(void (*check)(bool, const char*));
int runCfgRepro(const wchar_t* fixture);
namespace
{
    int failures = 0;
    unsigned checks = 0;
    void check(bool value, const char* description)
    {
        ++checks;
        if (!value) { ++failures; std::cerr << "FAIL: " << description << '\n'; }
    }

    // Independent opaque-pixel oracle: DirectComposition paints native Flink
    // order back-to-front, so the last covering visual determines the pixel.
    std::uintptr_t paintedWindow(const std::vector<std::uintptr_t>& windows,
        std::uintptr_t first = 0, std::uintptr_t second = 0)
    {
        std::uintptr_t pixel = 0;
        for (const auto kWindow : windows)
            if (!first || kWindow == first || kWindow == second) pixel = kWindow;
        return pixel;
    }

    void order(std::initializer_list<std::uintptr_t> input, std::uintptr_t target,
        Position position, std::uintptr_t reference, std::initializer_list<std::uintptr_t> expected)
    {
        std::vector<std::uintptr_t> windows(input);
        const auto kPlan = planOrder(windows.data(), windows.size(), target, position, reference);
        check(kPlan.valid, "valid ordering request");
        if (!kPlan.valid) return;
        if (!kPlan.unchanged)
        {
            windows.erase(std::find(windows.begin(), windows.end(), target));
            auto at = windows.begin();
            if (kPlan.behind) at = std::find(windows.begin(), windows.end(), kPlan.behind) + 1;
            windows.insert(at, target);
        }
        check(windows == std::vector<std::uintptr_t>(expected), "expected compositor order");
        const auto kRepeat = planOrder(windows.data(), windows.size(), target, position, reference);
        check(kRepeat.valid && kRepeat.unchanged, "reapplying an order is idempotent");
        std::vector<std::uintptr_t> othersBefore(input), othersAfter(windows);
        othersBefore.erase(std::find(othersBefore.begin(), othersBefore.end(), target));
        othersAfter.erase(std::find(othersAfter.begin(), othersAfter.end(), target));
        check(othersBefore == othersAfter, "unselected windows retain their relative order");
        if (position == Position::kFront)
            check(paintedWindow(windows) == target, "move-to-front target covers every overlapping sibling");
        else if (position == Position::kBack)
            check(windows.size() == 1 || paintedWindow(windows) != target,
                "send-to-back target is covered by its overlapping siblings");
        else
            check(paintedWindow(windows, target, reference) == (position == Position::kBefore ? target : reference),
                "relative visual occlusion agrees with before/after, not raw list direction");
    }
}

int runRuntimeTests(int argc, wchar_t** argv);

int wmain(int argc, wchar_t** argv)
{
    if (argc >= 3 && std::wcscmp(argv[1], L"--runtime") == 0)
        return runRuntimeTests(argc - 2, argv + 2);

    if (argc == 3 && lstrcmpW(argv[1], L"--cfg-repro") == 0) return runCfgRepro(argv[2]);
    if (argc == 4 && lstrcmpW(argv[1], L"--loader-child") == 0)
    {
        HANDLE finished = reinterpret_cast<HANDLE>(_wcstoui64(argv[2], nullptr, 10));
        HANDLE ready = reinterpret_cast<HANDLE>(_wcstoui64(argv[3], nullptr, 10));
        SetEvent(ready);
        const DWORD kWait = WaitForSingleObject(finished, 60000);
        CloseHandle(ready);
        CloseHandle(finished);
        return kWait == WAIT_OBJECT_0 ? 0 : 1;
    }
    // Each array is the native list: lowest visual first, highest visual last.
    order({1,2,3,4}, 3, Position::kFront, 0, {1,2,4,3});
    order({1,2,3,4}, 4, Position::kBack, 0, {4,1,2,3});
    order({1,2,3,4}, 4, Position::kFront, 0, {1,2,3,4});
    order({1,2,3,4}, 1, Position::kBack, 0, {1,2,3,4});
    order({1}, 1, Position::kFront, 0, {1});
    order({1}, 1, Position::kBack, 0, {1});
    order({1,2,3,4}, 4, Position::kBefore, 1, {1,4,2,3});
    order({1,2,3,4}, 1, Position::kBefore, 4, {2,3,4,1});
    order({1,2,3,4}, 2, Position::kBefore, 3, {1,3,2,4});
    order({1,2,3,4}, 1, Position::kBefore, 2, {2,1,3,4});
    order({1,2,3,4}, 1, Position::kAfter, 4, {2,3,1,4});
    order({1,2,3,4}, 4, Position::kAfter, 1, {4,1,2,3});
    order({1,2,3,4}, 3, Position::kAfter, 2, {1,3,2,4});
    order({1,2,3,4}, 2, Position::kBefore, 1, {1,2,3,4});
    order({1,2,3,4}, 1, Position::kAfter, 2, {1,2,3,4});
    // IDs intentionally do not encode Band priority: any node may cross another.
    order({1,18,200}, 1, Position::kFront, 0, {18,200,1});
    order({200,18,1}, 1, Position::kBack, 0, {1,200,18});
    const std::uintptr_t kWindows[] = {1,2,3};
    const auto kFront = locateOrder(kWindows, 3, 3);
    const auto kMiddle = locateOrder(kWindows, 3, 2);
    const auto kBack = locateOrder(kWindows, 3, 1);
    check(kFront.valid && kFront.fromFront == 0 && kFront.above == 0 && kFront.below == 2,
        "frontmost receipt has index zero and no window above it");
    check(kMiddle.valid && kMiddle.fromFront == 1 && kMiddle.above == 3 && kMiddle.below == 1,
        "receipt neighbors describe visual above/below");
    check(kBack.valid && kBack.fromFront == 2 && kBack.above == 2 && kBack.below == 0,
        "backmost receipt reverses native list indexing");
    check(!locateOrder(kWindows, 3, 4).valid, "missing target has no valid receipt position");
    // Restoring target 3 in Win32 order [4,3,2,1] uses its lower neighbor 2.
    order({1,2,4,3}, 3, Position::kBefore, 2, {1,2,3,4});
    check(!planOrder(kWindows,3,4,Position::kFront,0).valid, "closed target is rejected");
    check(!planOrder(kWindows,3,1,Position::kAfter,4).valid, "closed reference is rejected");
    check(!planOrder(kWindows,3,1,Position::kBefore,1).valid, "self reference is rejected");
    check(!planOrder(kWindows,3,1,static_cast<Position>(99),0).valid, "invalid position is rejected");
    check(!planOrder(nullptr,0,1,Position::kFront,0).valid, "empty list is rejected");
    const std::uintptr_t kDuplicate[] = {1,2,1};
    const std::uintptr_t kSentinel[] = {1,0,2};
    check(!planOrder(kDuplicate,3,1,Position::kFront,0).valid, "duplicate target is rejected");
    check(!planOrder(kSentinel,3,1,Position::kFront,0).valid, "sentinel cannot be a window");

    check(argc == 2, "agent DLL path supplied");
    if (argc == 2)
    {
        runLoaderTests(&check, argv[1]);
        runCfgTests(&check);
        HMODULE agent = LoadLibraryW(argv[1]);
        check(agent != nullptr, "agent DLL loads in the ordinary test process");
        if (agent)
        {
            auto entry = reinterpret_cast<DWORD(WINAPI*)(void*)>(GetProcAddress(agent, "KswordDwmZOrderRequest"));
            check(entry != nullptr, "request export has the expected ABI name");
            if (entry)
            {
                check(entry(nullptr) == ERROR_INVALID_PARAMETER, "null request is rejected");
                Packet packet;
                packet.version = 999;
                check(entry(&packet) == ERROR_SUCCESS && packet.response.status == Status::kInvalidRequest,
                    "unknown protocol is rejected before runtime initialization");
                packet = {};
                packet.version = 1;
                packet.bytes = 144;
                check(entry(&packet) == ERROR_SUCCESS && packet.response.status == Status::kInvalidRequest,
                    "old protocol without query-only process handles is rejected");
                packet = {};
                check(entry(&packet) == ERROR_SUCCESS && packet.response.status == Status::kUnsupportedRuntime,
                    "agent refuses to modify a process other than DWM");
            }
            FreeLibrary(agent);
        }
    }
    std::cout << "CHECKS=" << checks << " FAILURES=" << failures << '\n';
    return failures ? 1 : 0;
}
