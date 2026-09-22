#include "DwmZOrderClient.h"
#include "DwmAgentDeployment.h"
#include "../../../shared/window/DwmRemoteLoader.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include "../../../shared/window/DwmProcessIdentity.h"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <vector>

extern "C" const unsigned char KswordDwmLoadStart[], KswordDwmLoadEnd[];

namespace ks::dwm_order
{
    namespace
    {
        class Handle
        {
        public:
            explicit Handle(HANDLE value = nullptr) : value_(value) {}
            ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
            Handle(const Handle&) = delete;
            Handle& operator=(const Handle&) = delete;
            HANDLE get() const { return value_; }
            bool valid() const { return value_ && value_ != INVALID_HANDLE_VALUE; }
            HANDLE release() { HANDLE value = value_; value_ = nullptr; return value; }
        private:
            HANDLE value_;
        };

        class DebugPrivilege
        {
        public:
            DebugPrivilege()
            {
                HANDLE old = nullptr;
                if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, TRUE, &old))
                    previous_ = old;
                else if (GetLastError() != ERROR_NO_TOKEN) return;
                HANDLE sourceRaw = nullptr;
                if (previous_)
                {
                    if (!DuplicateHandle(GetCurrentProcess(), previous_, GetCurrentProcess(), &sourceRaw,
                        0, FALSE, DUPLICATE_SAME_ACCESS)) return;
                }
                else if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &sourceRaw)) return;
                Handle source(sourceRaw);
                HANDLE adjustedRaw = nullptr;
                if (!DuplicateTokenEx(source.get(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
                    nullptr, SecurityImpersonation, TokenImpersonation, &adjustedRaw)) return;
                Handle adjusted(adjustedRaw);
                TOKEN_PRIVILEGES privilege{};
                privilege.PrivilegeCount = 1;
                if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privilege.Privileges[0].Luid)) return;
                privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                SetLastError(ERROR_SUCCESS);
                if (!AdjustTokenPrivileges(adjusted.get(), FALSE, &privilege, sizeof(privilege), nullptr, nullptr)
                    || GetLastError() != ERROR_SUCCESS) return;
                changed_ = SetThreadToken(nullptr, adjusted.get()) != FALSE;
            }
            ~DebugPrivilege()
            {
                if (changed_) SetThreadToken(nullptr, previous_);
                if (previous_) CloseHandle(previous_);
            }
        private:
            HANDLE previous_ = nullptr;
            bool changed_ = false;
        };

        bool sameIdentity(const WindowIdentity& expected, std::uint32_t& error)
        {
            WindowIdentity current;
            if (!captureWindow(expected.hwnd, current, error)) return false;
            if (current.processId != expected.processId || current.threadId != expected.threadId
                || current.processCreated != expected.processCreated)
            { error = ERROR_INVALID_WINDOW_HANDLE; return false; }
            return true;
        }

        std::wstring processPath(HANDLE process)
        {
            wchar_t path[32768]{};
            DWORD size = static_cast<DWORD>(std::size(path));
            return QueryFullProcessImageNameW(process, 0, path, &size) ? std::wstring(path, size) : std::wstring();
        }

        std::wstring normalPath(std::wstring path)
        {
            if (path.compare(0, 4, L"\\\\?\\") == 0) path.erase(0, 4);
            std::replace(path.begin(), path.end(), L'/', L'\\');
            return path;
        }

        bool samePath(const std::wstring& a, const std::wstring& b)
        {
            const auto kLeft = normalPath(a), kRight = normalPath(b);
            return !kLeft.empty() && !kRight.empty() && _wcsicmp(kLeft.c_str(), kRight.c_str()) == 0;
        }

        HANDLE openDwm(DWORD session, DWORD& pid, DWORD& error)
        {
            Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
            if (!snapshot.valid()) { error = GetLastError(); return nullptr; }
            wchar_t system[MAX_PATH]{};
            if (!GetSystemDirectoryW(system, MAX_PATH)) { error = GetLastError(); return nullptr; }
            const std::wstring kExpected = std::wstring(system) + L"\\dwm.exe";
            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            error = ERROR_NOT_FOUND;
            if (!Process32FirstW(snapshot.get(), &entry)) { error = GetLastError(); return nullptr; }
            do
            {
                if (_wcsicmp(entry.szExeFile, L"dwm.exe")) continue;
                DWORD candidateSession = 0;
                if (!ProcessIdToSessionId(entry.th32ProcessID, &candidateSession) || candidateSession != session) continue;
                Handle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE
                    | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | SYNCHRONIZE,
                    FALSE, entry.th32ProcessID));
                if (!process.valid()) { error = GetLastError(); continue; }
                if (!samePath(processPath(process.get()), kExpected)) { error = ERROR_BAD_EXE_FORMAT; continue; }
                pid = GetProcessId(process.get());
                if (pid != entry.th32ProcessID) { error = ERROR_INVALID_HANDLE; continue; }
                error = ERROR_SUCCESS;
                return process.release();
            } while (Process32NextW(snapshot.get(), &entry));
            return nullptr;
        }

        bool findModule(DWORD pid, const wchar_t* name, const std::wstring* path,
            MODULEENTRY32W& found, DWORD& error)
        {
            HANDLE raw = INVALID_HANDLE_VALUE;
            for (unsigned attempt = 0; attempt < 4; ++attempt)
            {
                raw = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
                if (raw != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH) break;
            }
            Handle snapshot(raw);
            if (!snapshot.valid()) { error = GetLastError(); return false; }
            MODULEENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            if (!Module32FirstW(snapshot.get(), &entry)) { error = GetLastError(); return false; }
            do
            {
                if (!_wcsicmp(entry.szModule, name))
                {
                    if (path && !samePath(entry.szExePath, *path)) { error = ERROR_REVISION_MISMATCH; return false; }
                    found = entry;
                    return true;
                }
            } while (Module32NextW(snapshot.get(), &entry));
            error = ERROR_MOD_NOT_FOUND;
            return false;
        }

        bool canReleaseAllocation(HANDLE process, const void* unwindFlag)
        {
            if (!unwindFlag) return true;
            DWORD registered = 1;
            SIZE_T bytes = 0;
            return ReadProcessMemory(process, unwindFlag, &registered, sizeof(registered), &bytes)
                && bytes == sizeof(registered) && registered == 0;
        }

        std::atomic<unsigned> activeRemoteCalls{0};
        struct RemoteCallState
        {
            HANDLE process = nullptr;
            HANDLE thread = nullptr;
            void* allocation = nullptr;
            const void* unwindFlag = nullptr;
            std::shared_ptr<void> lease;
            bool counted = false;
            ~RemoteCallState()
            {
                if (allocation && canReleaseAllocation(process, unwindFlag))
                    VirtualFreeEx(process, allocation, 0, MEM_RELEASE);
                if (thread) CloseHandle(thread);
                if (process) CloseHandle(process);
                if (counted) --activeRemoteCalls;
            }
        };

        DWORD WINAPI retireWhenThreadEnds(void* context)
        {
            auto* state = static_cast<RemoteCallState*>(context);
            if (WaitForSingleObject(state->thread, INFINITE) == WAIT_OBJECT_0) delete state;
            // If the wait fails, retain everything that a live remote thread can use.
            return ERROR_SUCCESS;
        }

        DWORD remoteCall(HANDLE process, std::uintptr_t entry, void* buffer, std::size_t size,
            bool readReply, DWORD& threadCode, const std::vector<unsigned char>* loaderCode = nullptr,
            std::shared_ptr<void> lease = {})
        {
            DWORD error = ERROR_SUCCESS;
            auto state = std::make_unique<RemoteCallState>();
            state->lease = std::move(lease);
            if (!DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &state->process,
                0, FALSE, DUPLICATE_SAME_ACCESS)) return GetLastError();
            SYSTEM_INFO system{};
            GetSystemInfo(&system);
            const std::size_t kPrefix = loaderCode ? system.dwPageSize : 0;
            if (loaderCode && (loaderCode->size() > kPrefix || size < sizeof(transport::LoaderPacket)))
                return ERROR_INVALID_PARAMETER;
            void* remote = VirtualAllocEx(process, nullptr, kPrefix + size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!remote) return GetLastError();
            state->allocation = remote;
            void* parameter = static_cast<unsigned char*>(remote) + kPrefix;
            const void* unwindFlag = loaderCode ? static_cast<unsigned char*>(parameter)
                + offsetof(transport::LoaderPacket, unwindRegistered) : nullptr;
            SIZE_T transferred = 0;
            if (loaderCode)
            {
                auto* packet = static_cast<transport::LoaderPacket*>(buffer);
                packet->codeBase = reinterpret_cast<std::uintptr_t>(remote);
                packet->path = reinterpret_cast<std::uintptr_t>(parameter) + sizeof(*packet);
                entry = packet->codeBase;
                DWORD previous = 0;
                if (!WriteProcessMemory(process, remote, loaderCode->data(), loaderCode->size(), &transferred)
                    || transferred != loaderCode->size()
                    || !VirtualProtectEx(process, remote, kPrefix, PAGE_EXECUTE_READ, &previous)
                    || !FlushInstructionCache(process, remote, loaderCode->size()))
                {
                    error = GetLastError() ? GetLastError() : ERROR_PARTIAL_COPY;
                    return error;
                }
            }
            if (!WriteProcessMemory(process, parameter, buffer, size, &transferred) || transferred != size)
            {
                error = GetLastError() ? GetLastError() : ERROR_PARTIAL_COPY;
                return error;
            }
            state->thread = CreateRemoteThread(process, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(entry), parameter, 0, nullptr);
            if (!state->thread) return GetLastError();
            ++activeRemoteCalls;
            state->counted = true;
            state->unwindFlag = unwindFlag;
            const DWORD kWaited = WaitForSingleObject(state->thread, 10000);
            if (kWaited != WAIT_OBJECT_0)
            {
                error = kWaited == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
                // The heap owner also holds file and query-handle leases. Queue
                // failure deliberately retains it rather than racing a live thread.
                QueueUserWorkItem(&retireWhenThreadEnds, state.release(), WT_EXECUTELONGFUNCTION);
                return error;
            }
            if (!GetExitCodeThread(state->thread, &threadCode)) error = GetLastError();
            else if (readReply && (!ReadProcessMemory(process, parameter, buffer, size, &transferred) || transferred != size))
                error = GetLastError() ? GetLastError() : ERROR_PARTIAL_COPY;
            // A timed-out/aborted unwind registration must never point at freed memory.
            if (!canReleaseAllocation(process, unwindFlag) && !error) error = ERROR_INVALID_DATA;
            return error;
        }

        struct QueryHandles
        {
            HANDLE process = nullptr;
            HANDLE target = nullptr;
            HANDLE reference = nullptr;
            ~QueryHandles()
            {
                for (HANDLE handle : {target, reference})
                {
                    if (!handle) continue;
                    HANDLE local = nullptr;
                    if (DuplicateHandle(process, handle, GetCurrentProcess(), &local,
                        0, FALSE, DUPLICATE_CLOSE_SOURCE)) CloseHandle(local);
                }
                if (process) CloseHandle(process);
            }
            DWORD add(const WindowIdentity& identity, HANDLE& remote)
            {
                Handle local(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, identity.processId));
                if (!local.valid()) return GetLastError();
                if (!matchesProcessIdentity(local.get(), identity)) return ERROR_INVALID_WINDOW_HANDLE;
                if (!DuplicateHandle(GetCurrentProcess(), local.get(), process, &remote,
                    PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) return GetLastError();
                return ERROR_SUCCESS;
            }
        };

        bool remoteImageMatches(HANDLE process, const MODULEENTRY32W& module,
            DWORD timestamp, DWORD imageSize, DWORD& error);

        std::uintptr_t remoteFunction(HANDLE process, DWORD pid, const char* name, DWORD& error)
        {
            auto* function = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), name);
            if (!function) { error = GetLastError(); return 0; }
            HMODULE owner = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(function), &owner)) { error = GetLastError(); return 0; }
            wchar_t path[MAX_PATH]{};
            if (!GetModuleFileNameW(owner, path, MAX_PATH)) { error = GetLastError(); return 0; }
            const wchar_t* filename = wcsrchr(path, L'\\');
            if (!filename) { error = ERROR_BAD_EXE_FORMAT; return 0; }
            MODULEENTRY32W remoteOwner{};
            const std::wstring kOwnerPath(path);
            if (!findModule(pid, filename + 1, &kOwnerPath, remoteOwner, error)) return 0;
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(owner);
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<unsigned char*>(owner) + dos->e_lfanew);
            if (!remoteImageMatches(process, remoteOwner, nt->FileHeader.TimeDateStamp,
                nt->OptionalHeader.SizeOfImage, error)) return 0;
            const auto kOffset = reinterpret_cast<std::uintptr_t>(function) - reinterpret_cast<std::uintptr_t>(owner);
            if (kOffset >= remoteOwner.modBaseSize) { error = ERROR_BAD_EXE_FORMAT; return 0; }
            return reinterpret_cast<std::uintptr_t>(remoteOwner.modBaseAddr) + kOffset;
        }

        bool remoteImageMatches(HANDLE process, const MODULEENTRY32W& module,
            DWORD timestamp, DWORD imageSize, DWORD& error)
        {
            IMAGE_DOS_HEADER dos{};
            SIZE_T bytes = 0;
            if (!ReadProcessMemory(process, module.modBaseAddr, &dos, sizeof(dos), &bytes)
                || bytes != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE
                || dos.e_lfanew < 0 || dos.e_lfanew > 0x1000)
            { error = ERROR_BAD_EXE_FORMAT; return false; }
            IMAGE_NT_HEADERS64 nt{};
            if (!ReadProcessMemory(process, module.modBaseAddr + dos.e_lfanew, &nt, sizeof(nt), &bytes)
                || bytes != sizeof(nt) || nt.Signature != IMAGE_NT_SIGNATURE
                || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
                || nt.FileHeader.TimeDateStamp != timestamp || nt.OptionalHeader.SizeOfImage != imageSize)
            { error = ERROR_REVISION_MISMATCH; return false; }
            return true;
        }
    }

    transport::LoadResult transport::loadAgent(void* process, std::uint32_t processId,
        const std::wstring& path, std::shared_ptr<void> lease)
    {
        LoadResult result;
        if (path.empty() || path.size() > 32767)
        { result.error = ERROR_BAD_PATHNAME; return result; }
        LoaderPacket packet;
        DWORD error = 0;
        packet.loadLibraryEx = remoteFunction(process, processId, "LoadLibraryExW", error);
        if (packet.loadLibraryEx) packet.getLastError = remoteFunction(process, processId, "GetLastError", error);
        if (packet.getLastError) packet.addFunctionTable = remoteFunction(process, processId, "RtlAddFunctionTable", error);
        if (packet.addFunctionTable) packet.deleteFunctionTable = remoteFunction(process, processId, "RtlDeleteFunctionTable", error);
        if (!packet.deleteFunctionTable) { result.error = error; return result; }

        const unsigned char* codeStart = KswordDwmLoadStart;
        // MSVC incremental links can redirect even an assembly code label via an ILT.
        // Resolve only that local rel32 jump, then validate the actual routine layout.
        if (codeStart[0] == 0xe9)
        {
            std::int32_t displacement = 0;
            std::memcpy(&displacement, codeStart + 1, sizeof(displacement));
            codeStart += 5 + displacement;
        }
        const auto kCodeSize = reinterpret_cast<std::uintptr_t>(KswordDwmLoadEnd)
            - reinterpret_cast<std::uintptr_t>(codeStart);
        const unsigned char kPrologue[] = {0x53, 0x48, 0x83, 0xec, 0x20};
        if (kCodeSize < sizeof(kPrologue) || kCodeSize > 512
            || std::memcmp(codeStart, kPrologue, sizeof(kPrologue)) != 0)
        { result.error = ERROR_BAD_EXE_FORMAT; return result; }
        packet.functionEnd = static_cast<DWORD>(kCodeSize);
        packet.unwindRva = static_cast<DWORD>((kCodeSize + 3) & ~std::size_t(3));
        // Version 1, five-byte prologue, PUSH_NONVOL RBX + ALLOC_SMALL 32.
        const unsigned char kUnwind[] = {1, 5, 2, 0, 5, 0x32, 1, 0x30};
        std::vector<unsigned char> code(packet.unwindRva + sizeof(kUnwind));
        std::memcpy(code.data(), codeStart, kCodeSize);
        std::memcpy(code.data() + packet.unwindRva, kUnwind, sizeof(kUnwind));
        std::vector<unsigned char> buffer(sizeof(packet) + (path.size() + 1) * sizeof(wchar_t));
        std::memcpy(buffer.data(), &packet, sizeof(packet));
        std::memcpy(buffer.data() + sizeof(packet), path.c_str(), (path.size() + 1) * sizeof(wchar_t));
        DWORD threadCode = 0;
        result.error = remoteCall(process, 0, buffer.data(), buffer.size(), true, threadCode, &code, std::move(lease));
        result.threadExitCode = threadCode;
        std::memcpy(&packet, buffer.data(), sizeof(packet));
        result.module = packet.module;
        result.loaderCompleted = packet.phase >= 3;
        if (result.error) return result;
        if (threadCode) { result.error = ERROR_UNHANDLED_EXCEPTION; return result; }
        if (!result.loaderCompleted || !result.module)
            result.error = packet.error ? packet.error : ERROR_INVALID_DATA;
        return result;
    }

    bool captureWindow(std::uint64_t hwndValue, WindowIdentity& identity, std::uint32_t& error)
    {
        identity = {};
        HWND hwnd = reinterpret_cast<HWND>(hwndValue);
        DWORD pid = 0;
        const DWORD kTid = GetWindowThreadProcessId(hwnd, &pid);
        if (!hwnd || !kTid || !pid || GetAncestor(hwnd, GA_ROOT) != hwnd)
        { error = ERROR_INVALID_WINDOW_HANDLE; return false; }
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!process.valid() || !GetProcessTimes(process.get(), &created, &exited, &kernel, &user))
        { error = GetLastError(); return false; }
        DWORD checkedPid = 0;
        if (GetWindowThreadProcessId(hwnd, &checkedPid) != kTid || checkedPid != pid)
        { error = ERROR_INVALID_WINDOW_HANDLE; return false; }
        identity = {hwndValue, pid, kTid,
            (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime};
        error = ERROR_SUCCESS;
        return true;
    }

    std::recursive_mutex& operationMutex()
    {
        static std::recursive_mutex mutex;
        return mutex;
    }

    Reply executeRequest(const Request& request, const std::wstring& agentPath, bool allowLoad)
    {
        const std::lock_guard<std::recursive_mutex> kLock(operationMutex());
        Reply reply;
        DebugPrivilege privilege;
        auto fail = [&](Stage stage, DWORD error, Status status = Status::kTransportFailure)
        {
            reply.stage = stage;
            reply.error = error;
            reply.response.status = error == ERROR_TIMEOUT ? Status::kTimeout : status;
            return reply;
        };
        std::uint32_t identityError = 0;
        // A timeout does not cancel the remote thread. Do not allow a later
        // restore to overtake an outstanding apply/load in this client process.
        if (activeRemoteCalls.load() != 0)
            return fail(Stage::kRequest, ERROR_TIMEOUT, Status::kTimeout);
        const bool kNeedsTarget = request.action != Action::kStop && request.action != Action::kConnect;
        if (kNeedsTarget && !sameIdentity(request.target, identityError))
            return fail(Stage::kWindow, identityError, Status::kInvalidWindow);
        if (request.action == Action::kApply && (request.position == Position::kBefore || request.position == Position::kAfter)
            && (!sameIdentity(request.reference, identityError) || request.reference.hwnd == request.target.hwnd))
            return fail(Stage::kWindow, identityError ? identityError : ERROR_INVALID_PARAMETER, Status::kInvalidWindow);

        DWORD currentSession = 0, targetSession = 0;
        if (!ProcessIdToSessionId(GetCurrentProcessId(), &currentSession)) return fail(Stage::kDwmProcess, GetLastError());
        if (kNeedsTarget
            && (!ProcessIdToSessionId(request.target.processId, &targetSession) || targetSession != currentSession))
            return fail(Stage::kWindow, ERROR_INVALID_PARAMETER, Status::kDifferentDesktop);
        DWORD dwmPid = 0, error = 0;
        Handle process(openDwm(currentSession, dwmPid, error));
        if (!process.valid()) return fail(Stage::kDwmProcess, error);

        const wchar_t* filename = wcsrchr(agentPath.c_str(), L'\\');
        if (!filename) return fail(Stage::kAgentFile, ERROR_BAD_PATHNAME);
        ++filename;
        MODULEENTRY32W remoteModule{};
        bool loaded = findModule(dwmPid, filename, nullptr, remoteModule, error);
        if (!loaded && error != ERROR_MOD_NOT_FOUND) return fail(Stage::kLoadAgent, error, Status::kAgentMismatch);
        if (!loaded && (!allowLoad || request.action == Action::kRestore || request.action == Action::kStop))
            return fail(Stage::kRequest, ERROR_SUCCESS, Status::kNotRunning);

        std::vector<unsigned char> dwmSid;
        error = transport::readProcessUserSid(process.get(), dwmSid);
        if (error) return fail(Stage::kPrepareAgent, error);
        transport::PreparedAgent prepared;
        error = transport::prepareAgentCopy(agentPath, dwmSid, prepared);
        if (error) return fail(Stage::kPrepareAgent, error);
        if (loaded && !samePath(remoteModule.szExePath, prepared.path))
            return fail(Stage::kLoadAgent, ERROR_REVISION_MISMATCH, Status::kAgentMismatch);
        HMODULE mapped = LoadLibraryExW(prepared.path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!mapped) return fail(Stage::kAgentFile, GetLastError());
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mapped);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<unsigned char*>(mapped) + dos->e_lfanew);
        const auto kEntry = GetProcAddress(mapped, "KswordDwmZOrderRequest");
        const DWORD kImageSize = nt->OptionalHeader.SizeOfImage;
        const DWORD kTimestamp = nt->FileHeader.TimeDateStamp;
        const auto kEntryRva = reinterpret_cast<std::uintptr_t>(kEntry) - reinterpret_cast<std::uintptr_t>(mapped);
        const bool kValid = kEntry && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 && kEntryRva < kImageSize;
        FreeLibrary(mapped);
        if (!kValid) return fail(Stage::kAgentFile, ERROR_BAD_EXE_FORMAT);

        if (!loaded)
        {
            const auto kLoad = transport::loadAgent(process.get(), dwmPid, prepared.path, prepared.lease);
            reply.loaderThreadExitCode = kLoad.threadExitCode;
            reply.loaderCompleted = kLoad.loaderCompleted;
            if (kLoad.error) return fail(Stage::kLoadAgent, kLoad.error);
            if (!findModule(dwmPid, filename, &prepared.path, remoteModule, error))
                return fail(Stage::kLoadAgent, error, Status::kVerificationFailed);
            if (reinterpret_cast<std::uintptr_t>(remoteModule.modBaseAddr) != kLoad.module)
                return fail(Stage::kLoadAgent, ERROR_INVALID_DATA, Status::kVerificationFailed);
        }
        if (!remoteImageMatches(process.get(), remoteModule, kTimestamp, kImageSize, error))
            return fail(Stage::kLoadAgent, error, Status::kAgentMismatch);
        if (kNeedsTarget && !sameIdentity(request.target, identityError))
            return fail(Stage::kWindow, identityError, Status::kInvalidWindow);
        Packet packet;
        packet.request = request;
        auto handles = std::make_shared<QueryHandles>();
        if (!DuplicateHandle(GetCurrentProcess(), process.get(), GetCurrentProcess(), &handles->process,
            0, FALSE, DUPLICATE_SAME_ACCESS)) return fail(Stage::kRequest, GetLastError());
        if (kNeedsTarget)
        {
            error = handles->add(request.target, handles->target);
            if (error) return fail(Stage::kWindow, error, Status::kInvalidWindow);
        }
        if (request.action == Action::kApply && (request.position == Position::kBefore || request.position == Position::kAfter))
        {
            error = handles->add(request.reference, handles->reference);
            if (error) return fail(Stage::kWindow, error, Status::kInvalidWindow);
        }
        packet.targetProcess = reinterpret_cast<std::uintptr_t>(handles->target);
        packet.referenceProcess = reinterpret_cast<std::uintptr_t>(handles->reference);
        DWORD code = 0;
        error = remoteCall(process.get(), reinterpret_cast<std::uintptr_t>(remoteModule.modBaseAddr) + kEntryRva,
            &packet, sizeof(packet), true, code, nullptr, handles);
        reply.requestThreadExitCode = code;
        // A terminated DWM can make the subsequent receipt read fail too. Keep
        // its actual thread exit status instead of relabeling it as a Win32 error.
        if (code != ERROR_SUCCESS) return fail(Stage::kRequest, ERROR_SUCCESS, Status::kInternalException);
        if (error) return fail(Stage::kRequest, error);
        if (packet.magic != kMagic || packet.version != kProtocolVersion || packet.bytes != sizeof(packet)
            || packet.response.status > Status::kInternalException
            || (packet.response.status == Status::kOk && (packet.response.dwmProcessId != dwmPid
                || !(packet.response.flags & kVerified))))
            return fail(Stage::kReceipt, ERROR_INVALID_DATA, Status::kVerificationFailed);
        reply.response = packet.response;
        reply.stage = Stage::kReceipt;
        reply.error = packet.response.win32Error;
        return reply;
    }
}
