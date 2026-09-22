#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include "OrderPlan.h"
#include "RuntimeResolver.h"
#include "NativeQueries.h"
#include "../../shared/window/DwmProcessIdentity.h"

namespace ks::dwm_order
{
    namespace
    {
        using ZOrderFn = HRESULT (__fastcall*)(void*, void*, void*);
        using UpdateFn = HRESULT (__fastcall*)(void*);
        using DestroyFn = HRESULT (__fastcall*)(void*, void*);
        unsigned char* gUdwm = nullptr;
        runtime::Resolved gRuntime{};
        CRITICAL_SECTION* gDwmLock = nullptr;
        SRWLOCK gSetupLock = SRWLOCK_INIT;
        const NativeQueries* gQueries = nullptr;
        ZOrderFn gZOrder = nullptr;
        UpdateFn gUpdateScene = nullptr;
        DestroyFn gDestroyWindow = nullptr;
        thread_local unsigned gNativeDepth = 0;

        // All state and scratch storage below are protected by DWM's own lock.
        struct State
        {
            bool installed = false;
            bool active = false;
            Request request;
            void* targetData = nullptr;
            void* referenceData = nullptr;
            void* targetDwmWindow = nullptr;
            void* referenceDwmWindow = nullptr;
            Status lastStatus = Status::kOk;
        } gState;
        struct Snapshot
        {
            LIST_ENTRY* head = nullptr;
            std::size_t count = 0;
            std::uintptr_t nodes[8192]{};
        } gSnapshot;

        template<class T> T read(const void* object, std::uintptr_t offset)
        {
            T value{};
            std::memcpy(&value, static_cast<const unsigned char*>(object) + offset, sizeof(value));
            return value;
        }

        bool readable(const void* pointer, std::size_t bytes)
        {
            auto address = reinterpret_cast<std::uintptr_t>(pointer);
            if (!address || bytes > UINTPTR_MAX - address) return false;
            const auto kEnd = address + bytes;
            while (address < kEnd)
            {
                MEMORY_BASIC_INFORMATION info{};
                if (!VirtualQuery(reinterpret_cast<void*>(address), &info, sizeof(info))
                    || info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
                    return false;
                const auto kNext = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
                if (kNext <= address) return false;
                address = kNext;
            }
            return true;
        }

        bool resolveImage(unsigned char* image, runtime::Resolved& resolved)
        {
            if (!readable(image, sizeof(IMAGE_DOS_HEADER))) return false;
            const auto kDos = read<IMAGE_DOS_HEADER>(image, 0);
            if (kDos.e_magic != IMAGE_DOS_SIGNATURE || kDos.e_lfanew < 0 || kDos.e_lfanew > 0x1000)
                return false;
            if (!readable(image + kDos.e_lfanew, sizeof(IMAGE_NT_HEADERS64))) return false;
            const auto kNt = read<IMAGE_NT_HEADERS64>(image, kDos.e_lfanew);
            return runtime::resolve(image, kNt.OptionalHeader.SizeOfImage,
                reinterpret_cast<std::uintptr_t>(image), resolved) == runtime::Failure::kNone;
        }

        Status initialize()
        {
            Status result = Status::kUnsupportedRuntime;
            AcquireSRWLockExclusive(&gSetupLock);
            __try
            {
                if (gUdwm) return Status::kOk;
                wchar_t path[MAX_PATH]{};
                const DWORD kLength = GetModuleFileNameW(nullptr, path, MAX_PATH);
                if (!kLength || kLength >= MAX_PATH) return result;
                const wchar_t* name = wcsrchr(path, L'\\');
                if (!name || _wcsicmp(name + 1, L"dwm.exe")) return result;
                auto* image = reinterpret_cast<unsigned char*>(GetModuleHandleW(L"udwm.dll"));
                runtime::Resolved resolved{};
                if (!resolveImage(image, resolved)) return result;
                auto* lock = reinterpret_cast<CRITICAL_SECTION*>(image + resolved.criticalSection);
                if (!readable(lock, sizeof(*lock))) return result;
                const auto* queries = NativeQueries::create(
                    reinterpret_cast<NativeQueries::FindWindowFn>(image + resolved.functions[static_cast<unsigned>(runtime::Node::FindWindow)]),
                    reinterpret_cast<NativeQueries::DesktopListFn>(image + resolved.functions[static_cast<unsigned>(runtime::Node::kDesktopList)]));
                if (!queries) return Status::kNativeFailure;
                gQueries = queries;
                gZOrder = reinterpret_cast<ZOrderFn>(image + resolved.functions[static_cast<unsigned>(runtime::Node::kZOrder)]);
                gUpdateScene = reinterpret_cast<UpdateFn>(image + resolved.functions[static_cast<unsigned>(runtime::Node::kUpdateScene)]);
                gDestroyWindow = reinterpret_cast<DestroyFn>(image + resolved.functions[static_cast<unsigned>(runtime::Node::kDestroyWindow)]);
                gDwmLock = lock;
                gRuntime = resolved;
                gUdwm = image;
                result = Status::kOk;
            }
            __finally { ReleaseSRWLockExclusive(&gSetupLock); }
            return result;
        }

        void* windowList()
        {
            auto* manager = read<void*>(gUdwm, gRuntime.desktopManager);
            if (!readable(manager, gRuntime.windowListOffset + sizeof(void*))) return nullptr;
            auto* list = read<void*>(manager, gRuntime.windowListOffset);
            if (!readable(list, sizeof(void*))
                || read<void*>(list, 0) != gUdwm + gRuntime.vtable) return nullptr;
            return list;
        }

        bool sameWindow(const WindowIdentity& identity, bool checkCreation, std::uint64_t process = 0)
        {
            HWND hwnd = reinterpret_cast<HWND>(identity.hwnd);
            DWORD pid = 0;
            const DWORD kTid = GetWindowThreadProcessId(hwnd, &pid);
            if (!identity.hwnd || !kTid || kTid != identity.threadId || pid != identity.processId
                || GetAncestor(hwnd, GA_ROOT) != hwnd) return false;
            if (!checkCreation) return true;
            return matchesProcessIdentity(reinterpret_cast<HANDLE>(process), identity);
        }

        void* find(void* list, std::uint64_t hwnd)
        {
            auto* data = gQueries->FindWindow(list, reinterpret_cast<HWND>(hwnd));
            if (!readable(data, gRuntime.layout.dataVisual + sizeof(void*))
                || read<std::uint64_t>(data, gRuntime.layout.dataHwnd) != hwnd
                || !read<void*>(data, gRuntime.layout.dataDwmWindow)) return nullptr;
            return data;
        }

        bool capture(void* list, void* target)
        {
            gSnapshot.count = 0;
            gSnapshot.head = gQueries->desktopList(list, read<std::uint64_t>(target, gRuntime.layout.dataDesktop));
            auto* head = gSnapshot.head;
            if (!readable(head, sizeof(*head))) return false;
            auto* previous = head;
            auto* node = head->Flink;
            bool found = false;
            while (node != head)
            {
                if (gSnapshot.count == 8192 || !readable(node, gRuntime.layout.dataVisual + sizeof(void*))
                    || node->Blink != previous
                    || read<std::uint64_t>(node, gRuntime.layout.dataDesktop)
                        != read<std::uint64_t>(target, gRuntime.layout.dataDesktop)) return false;
                gSnapshot.nodes[gSnapshot.count++] = reinterpret_cast<std::uintptr_t>(node);
                found = found || node == target;
                previous = node;
                node = node->Flink;
            }
            return found && head->Blink == previous;
        }

        HRESULT nativeOrder(void* list, void* target, void* behind)
        {
            HRESULT result = E_FAIL;
            ++gNativeDepth;
            __try
            {
                result = gZOrder(list, read<void*>(target, gRuntime.layout.dataDwmWindow),
                    behind ? read<void*>(behind, gRuntime.layout.dataDwmWindow) : nullptr);
            }
            __finally { --gNativeDepth; }
            return result;
        }

        HRESULT nativeUpdate(void* list)
        {
            HRESULT result = E_FAIL;
            ++gNativeDepth;
            __try { result = gUpdateScene(list); }
            __finally { --gNativeDepth; }
            return result;
        }

        Status move(void* list, void* target, void* reference, Position position, HRESULT& hr)
        {
            if (reference && read<std::uint64_t>(reference, gRuntime.layout.dataDesktop)
                != read<std::uint64_t>(target, gRuntime.layout.dataDesktop)) return Status::kDifferentDesktop;
            if (!read<void*>(target, gRuntime.layout.dataVisual)) return Status::kWindowNotComposed;
            if (!capture(list, target)) return Status::kVerificationFailed;
            const auto kPlan = planOrder(gSnapshot.nodes, gSnapshot.count,
                reinterpret_cast<std::uintptr_t>(target), position,
                reinterpret_cast<std::uintptr_t>(reference));
            if (!kPlan.valid) return Status::kInvalidWindow;
            auto* expected = kPlan.behind
                ? reinterpret_cast<LIST_ENTRY*>(kPlan.behind) : gSnapshot.head;
            if (!kPlan.unchanged)
            {
                hr = nativeOrder(list, target, reinterpret_cast<void*>(kPlan.behind));
                if (FAILED(hr)) return Status::kNativeFailure;
            }
            return capture(list, target) && static_cast<LIST_ENTRY*>(target)->Blink == expected
                ? Status::kOk : Status::kVerificationFailed;
        }

        Status restoreSystemOrder(void* list, const WindowIdentity& identity, HRESULT& hr)
        {
            if (!sameWindow(identity, false)) return Status::kInvalidWindow;
            auto* target = find(list, identity.hwnd);
            if (!target) return Status::kWindowNotComposed;
            if (!capture(list, target)) return Status::kVerificationFailed;
            void* behind = nullptr;
            // Win32 walks top-to-bottom with NEXT, opposite to the native Flink
            // list. The native insertion anchor must be below the restored HWND.
            HWND candidate = GetWindow(reinterpret_cast<HWND>(identity.hwnd), GW_HWNDNEXT);
            unsigned visited = 0;
            while (candidate && visited++ < 8192)
            {
                auto* data = find(list, reinterpret_cast<std::uint64_t>(candidate));
                if (data && data != target
                    && read<std::uint64_t>(data, gRuntime.layout.dataDesktop)
                        == read<std::uint64_t>(target, gRuntime.layout.dataDesktop))
                {
                    for (std::size_t i = 0; i < gSnapshot.count; ++i)
                        if (gSnapshot.nodes[i] == reinterpret_cast<std::uintptr_t>(data)) behind = data;
                    if (behind) break;
                }
                candidate = GetWindow(candidate, GW_HWNDNEXT);
            }
            if (candidate && !behind) return Status::kVerificationFailed;
            auto* expected = behind ? static_cast<LIST_ENTRY*>(behind) : gSnapshot.head;
            if (static_cast<LIST_ENTRY*>(target)->Blink != expected)
            {
                hr = nativeOrder(list, target, behind);
                if (FAILED(hr)) return Status::kNativeFailure;
            }
            return capture(list, target) && static_cast<LIST_ENTRY*>(target)->Blink == expected
                ? Status::kOk : Status::kVerificationFailed;
        }

        void maintain(void* list)
        {
            if (!gState.active || gNativeDepth) return;
            auto* target = find(list, gState.request.target.hwnd);
            void* reference = nullptr;
            const bool kRelative = gState.request.position == Position::kBefore
                || gState.request.position == Position::kAfter;
            if (kRelative) reference = find(list, gState.request.reference.hwnd);
            if (target != gState.targetData || !sameWindow(gState.request.target, false)
                || (kRelative && (reference != gState.referenceData
                    || !sameWindow(gState.request.reference, false))))
            {
                gState.active = false;
                gState.lastStatus = Status::kInvalidWindow;
                // A reference disappearing releases the surviving target.
                if (target == gState.targetData && target)
                {
                    HRESULT hr = S_OK;
                    restoreSystemOrder(list, gState.request.target, hr);
                }
                return;
            }
            HRESULT hr = S_OK;
            gState.lastStatus = move(list, target, reference, gState.request.position, hr);
            if (gState.lastStatus != Status::kOk) gState.active = false;
        }

        HRESULT __fastcall updateHook(void* list)
        {
            HRESULT hr = E_FAIL;
            EnterCriticalSection(gDwmLock);
            __try
            {
                __try { if (list == windowList()) maintain(list); }
                __except (EXCEPTION_EXECUTE_HANDLER)
                { gState.active = false; gState.lastStatus = Status::kInternalException; }
                ++gNativeDepth;
                __try { hr = gUpdateScene(list); }
                __finally { --gNativeDepth; }
            }
            __finally { LeaveCriticalSection(gDwmLock); }
            return hr;
        }

        HRESULT __fastcall zOrderHook(void* list, void* target, void* behind)
        {
            HRESULT hr = E_FAIL;
            EnterCriticalSection(gDwmLock);
            __try
            {
                ++gNativeDepth;
                __try { hr = gZOrder(list, target, behind); }
                __finally { --gNativeDepth; }
                __try { if (SUCCEEDED(hr) && list == windowList()) maintain(list); }
                __except (EXCEPTION_EXECUTE_HANDLER)
                { gState.active = false; gState.lastStatus = Status::kInternalException; }
            }
            __finally { LeaveCriticalSection(gDwmLock); }
            return hr;
        }

        HRESULT __fastcall destroyHook(void* list, void* window)
        {
            HRESULT hr = E_FAIL;
            EnterCriticalSection(gDwmLock);
            __try
            {
                if (gState.active && (window == gState.targetDwmWindow || window == gState.referenceDwmWindow))
                {
                    const bool kReferenceDestroyed = window != gState.targetDwmWindow;
                    gState.active = false;
                    gState.lastStatus = Status::kInvalidWindow;
                    if (kReferenceDestroyed)
                    {
                        __try { restoreSystemOrder(list, gState.request.target, hr); }
                        __except (EXCEPTION_EXECUTE_HANDLER) { gState.lastStatus = Status::kInternalException; }
                    }
                }
                ++gNativeDepth;
                __try { hr = gDestroyWindow(list, window); }
                __finally { --gNativeDepth; }
            }
            __finally { LeaveCriticalSection(gDwmLock); }
            return hr;
        }

        Status setHooks(bool install)
        {
            if (gState.installed == install) return Status::kOk;
            auto** table = reinterpret_cast<void**>(gUdwm + gRuntime.vtable);
            const std::size_t kSlots[] = {gRuntime.destroySlot, gRuntime.zOrderSlot, gRuntime.updateSlot};
            void* originals[] = {reinterpret_cast<void*>(gDestroyWindow), reinterpret_cast<void*>(gZOrder), reinterpret_cast<void*>(gUpdateScene)};
            void* hooks[] = {reinterpret_cast<void*>(&destroyHook), reinterpret_cast<void*>(&zOrderHook), reinterpret_cast<void*>(&updateHook)};
            for (unsigned i = 0; i < 3; ++i)
                if (table[kSlots[i]] != (install ? originals[i] : hooks[i])) return Status::kHookConflict;
            if (install)
            {
                HMODULE pinned = nullptr;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                    reinterpret_cast<LPCWSTR>(&updateHook), &pinned)) return Status::kNativeFailure;
            }
            DWORD protection = 0;
            const std::size_t kBytes = (std::max)({gRuntime.destroySlot, gRuntime.zOrderSlot, gRuntime.updateSlot}) * sizeof(void*) + sizeof(void*);
            if (!VirtualProtect(table, kBytes, PAGE_READWRITE, &protection)) return Status::kNativeFailure;
            bool ok = true;
            unsigned changed = 0;
            for (; changed < 3; ++changed)
            {
                void* expected = install ? originals[changed] : hooks[changed];
                void* desired = install ? hooks[changed] : originals[changed];
                if (InterlockedCompareExchangePointer(table + kSlots[changed], desired, expected) != expected)
                { ok = false; break; }
            }
            if (!ok)
                while (changed)
                {
                    --changed;
                    InterlockedCompareExchangePointer(table + kSlots[changed],
                        install ? originals[changed] : hooks[changed], install ? hooks[changed] : originals[changed]);
                }
            DWORD ignored = 0;
            const BOOL kProtectedAgain = VirtualProtect(table, kBytes, protection, &ignored);
            if (ok) gState.installed = install;
            return ok && kProtectedAgain ? Status::kOk : Status::kHookConflict;
        }

        void describe(void* list, const Request& request, Response& response)
        {
            response.dwmProcessId = GetCurrentProcessId();
            response.flags |= gState.installed ? kHooksInstalled : 0;
            response.flags |= gState.active ? kMaintaining : 0;
            response.maintainedWindow = gState.active ? gState.request.target.hwnd : 0;
            response.maintenanceStatus = gState.lastStatus;
            auto* target = find(list, request.target.hwnd);
            if (!target || !capture(list, target)) return;
            const auto kLocation = locateOrder(gSnapshot.nodes, gSnapshot.count, reinterpret_cast<std::uintptr_t>(target));
            if (!kLocation.valid) return;
            response.windowCount = static_cast<std::uint32_t>(gSnapshot.count);
            response.band = read<DWORD>(target, gRuntime.layout.dataBand);
            response.index = kLocation.fromFront;
            response.previous = kLocation.above ? read<std::uint64_t>(reinterpret_cast<void*>(kLocation.above), gRuntime.layout.dataHwnd) : 0;
            response.next = kLocation.below ? read<std::uint64_t>(reinterpret_cast<void*>(kLocation.below), gRuntime.layout.dataHwnd) : 0;
        }

        void executeLocked(Packet& packet)
        {
            auto& response = packet.response;
            const auto& request = packet.request;
            void* list = windowList();
            if (!list) { response.status = Status::kUnsupportedRuntime; return; }
            if (request.action == Action::kConnect)
            {
                response.status = Status::kOk;
                response.flags |= kVerified;
                describe(list, request, response);
                return;
            }
            if (request.action == Action::kStop)
            {
                HRESULT restoreHr = S_OK;
                response.status = Status::kOk;
                if (gState.active)
                {
                    gState.active = false;
                    response.status = restoreSystemOrder(list, gState.request.target, restoreHr);
                    if (response.status == Status::kInvalidWindow || response.status == Status::kWindowNotComposed)
                        response.status = Status::kOk;
                }
                const auto kHookStatus = setHooks(false);
                if (response.status == Status::kOk) response.status = kHookStatus;
                if (response.status == Status::kOk)
                {
                    restoreHr = nativeUpdate(list);
                    if (FAILED(restoreHr)) response.status = Status::kNativeFailure;
                    else { response.flags |= kVerified | kRestored; gState.lastStatus = Status::kOk; }
                }
                response.nativeResult = restoreHr;
                describe(list, request, response);
                return;
            }
            if (!sameWindow(request.target, true, packet.targetProcess)) { response.status = Status::kInvalidWindow; return; }
            auto* target = find(list, request.target.hwnd);
            if (!target) { response.status = Status::kWindowNotComposed; return; }
            HRESULT hr = S_OK;
            if (request.action == Action::kQuery)
                response.status = capture(list, target) ? Status::kOk : Status::kVerificationFailed;
            else if (request.action == Action::kRestore)
            {
                if (gState.active && request.target.hwnd == gState.request.target.hwnd)
                {
                    gState.active = false;
                }
                response.status = restoreSystemOrder(list, request.target, hr);
                if (response.status == Status::kOk) response.flags |= kRestored;
                if (!gState.active)
                {
                    const auto kHookStatus = setHooks(false);
                    if (response.status == Status::kOk) response.status = kHookStatus;
                }
            }
            else if (request.action == Action::kApply)
            {
                void* reference = nullptr;
                if (request.position == Position::kBefore || request.position == Position::kAfter)
                {
                    if (!sameWindow(request.reference, true, packet.referenceProcess) || request.reference.hwnd == request.target.hwnd)
                    { response.status = Status::kInvalidWindow; goto finished; }
                    reference = find(list, request.reference.hwnd);
                    if (!reference) { response.status = Status::kWindowNotComposed; goto finished; }
                    if (read<std::uint64_t>(target, gRuntime.layout.dataDesktop) != read<std::uint64_t>(reference, gRuntime.layout.dataDesktop))
                    { response.status = Status::kDifferentDesktop; goto finished; }
                }
                if (gState.active)
                {
                    gState.active = false;
                    response.status = restoreSystemOrder(list, gState.request.target, hr);
                    if (response.status != Status::kOk) goto finished;
                }
                response.status = request.maintain ? setHooks(true) : setHooks(false);
                if (response.status != Status::kOk) goto finished;
                response.status = move(list, target, reference, request.position, hr);
                gState.lastStatus = response.status;
                if (response.status == Status::kOk && request.maintain)
                {
                    gState.request = request;
                    gState.targetData = target;
                    gState.referenceData = reference;
                    gState.targetDwmWindow = read<void*>(target, gRuntime.layout.dataDwmWindow);
                    gState.referenceDwmWindow = reference ? read<void*>(reference, gRuntime.layout.dataDwmWindow) : nullptr;
                    gState.active = true;
                }
            }
        finished:
            if (request.action != Action::kQuery && response.status == Status::kOk)
            {
                // This native entry respects DWM's animation-thread/commit checks.
                const HRESULT kCommitted = nativeUpdate(list);
                if (FAILED(kCommitted)) { hr = kCommitted; response.status = Status::kNativeFailure; }
            }
            response.nativeResult = hr;
            if (response.status == Status::kOk)
            {
                response.flags |= kVerified;
                if (request.action == Action::kRestore && !gState.active) gState.lastStatus = Status::kOk;
            }
            describe(list, request, response);
        }

        void execute(Packet& packet)
        {
            packet.response = {};
            if (packet.magic != kMagic || packet.version != kProtocolVersion || packet.bytes != sizeof(Packet)
                || packet.reserved || packet.request.reserved || packet.request.maintain > 1
                || packet.request.action > Action::kConnect || packet.request.position > Position::kAfter)
            { packet.response.status = Status::kInvalidRequest; return; }
            packet.response.status = initialize();
            if (packet.response.status != Status::kOk) return;
            const ULONGLONG kDeadline = GetTickCount64() + 2000;
            while (!TryEnterCriticalSection(gDwmLock))
            {
                if (GetTickCount64() >= kDeadline)
                { packet.response.status = Status::kTimeout; return; }
                Sleep(1);
            }
            __try { executeLocked(packet); }
            __finally { LeaveCriticalSection(gDwmLock); }
        }
    }
}

extern "C" __declspec(dllexport) DWORD WINAPI KswordDwmZOrderRequest(void* parameter)
{
    using namespace ks::dwm_order;
    if (!parameter) return ERROR_INVALID_PARAMETER;
    __try
    {
        execute(*static_cast<Packet*>(parameter));
        return ERROR_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Never turn an access fault into a successful ordering receipt.
        return ERROR_UNHANDLED_EXCEPTION;
    }
}

BOOL WINAPI DllMain(HMODULE, DWORD, void*)
{
    // Initialization starts in the exported request, outside the loader lock.
    // Keep thread notifications for the statically linked CRT and thread_local state.
    return TRUE;
}
