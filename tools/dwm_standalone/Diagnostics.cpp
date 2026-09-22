#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include "Diagnostics.h"
#include "RuntimeResolver.h"
#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace standalone
{
    namespace
    {
        std::wstring hex(std::uint64_t number)
        { std::wostringstream s; s << L"0x" << std::hex << number; return s.str(); }

        std::vector<unsigned char> readFileBytes(const std::filesystem::path& path)
        {
            std::ifstream f(path, std::ios::binary | std::ios::ate);
            if (!f || f.tellg() <= 0 || f.tellg() > 128 * 1024 * 1024)
                throw std::runtime_error("Cannot read a bounded PE image");
            std::vector<unsigned char> bytes(static_cast<std::size_t>(f.tellg()));
            f.seekg(0);
            if (!f.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
                throw std::runtime_error("Incomplete file read");
            return bytes;
        }

        template<class T> T read(const std::vector<unsigned char>& bytes, std::size_t at)
        {
            if (at > bytes.size() || sizeof(T) > bytes.size() - at) throw std::runtime_error("Truncated PE");
            T v{};
            std::memcpy(&v, bytes.data() + at, sizeof(v));
            return v;
        }

        std::wstring hash(const std::vector<unsigned char>& bytes)
        {
            HCRYPTPROV provider = 0;
            HCRYPTHASH hash = 0;
            if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                throw std::runtime_error("SHA256 provider unavailable");
            std::array<unsigned char, 32> digest{};
            DWORD size = static_cast<DWORD>(digest.size());
            const bool kOk = CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)
                && CryptHashData(hash, bytes.data(), static_cast<DWORD>(bytes.size()), 0)
                && CryptGetHashParam(hash, HP_HASHVAL, digest.data(), &size, 0);
            if (hash) CryptDestroyHash(hash);
            CryptReleaseContext(provider, 0);
            if (!kOk) throw std::runtime_error("SHA256 failed");
            std::wostringstream s;
            for (auto b : digest) s << std::hex << std::setfill(L'0') << std::setw(2) << static_cast<unsigned>(b);
            return s.str();
        }

        std::wstring version(const std::filesystem::path& path)
        {
            DWORD unused = 0;
            const DWORD kSize = GetFileVersionInfoSizeW(path.c_str(), &unused);
            if (!kSize || kSize > 1024 * 1024) return L"unavailable";
            std::vector<unsigned char> data(kSize);
            VS_FIXEDFILEINFO* info = nullptr;
            UINT length = 0;
            if (!GetFileVersionInfoW(path.c_str(), 0, kSize, data.data())
                || !VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &length)
                || length < sizeof(*info)) return L"unavailable";
            std::wostringstream s;
            s << HIWORD(info->dwFileVersionMS) << L'.' << LOWORD(info->dwFileVersionMS)
              << L'.' << HIWORD(info->dwFileVersionLS) << L'.' << LOWORD(info->dwFileVersionLS);
            return s.str();
        }

        std::string utf8(const std::wstring& s)
        {
            if (s.empty()) return {};
            const int kSize = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
            if (!kSize) throw std::runtime_error("Invalid UTF-16 report text");
            std::string out(kSize, '\0');
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), kSize, nullptr, nullptr);
            return out;
        }

        void writeText(const std::filesystem::path& path, const std::wstring& text)
        {
            const auto kBytes = utf8(text);
            std::ofstream f(path, std::ios::binary);
            f.write(kBytes.data(), static_cast<std::streamsize>(kBytes.size()));
            f.close();
            if (!f) throw std::runtime_error("Report write failed");
        }

        const wchar_t* failureText(ks::dwm_order::runtime::Failure failure)
        {
            using F = ks::dwm_order::runtime::Failure;
            switch (failure)
            {
            case F::kNone: return L"None";
            case F::kInvalidImage: return L"InvalidImage";
            case F::kMissingPattern: return L"MissingPattern";
            case F::kAmbiguousPattern: return L"AmbiguousPattern";
            case F::kReferenceMismatch: return L"ReferenceMismatch";
            case F::kInvalidVtable: return L"InvalidVtable";
            case F::kInvalidCfg: return L"InvalidCfg";
            case F::kInvalidWindowList: return L"InvalidWindowList";
            case F::kInvalidFragments: return L"InvalidFragments";
            }
            return L"Unknown";
        }
    }

    std::filesystem::path executableDirectory()
    {
        std::wstring path(32768, L'\0');
        const DWORD kSize = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (!kSize || kSize >= path.size()) throw std::runtime_error("Executable path unavailable");
        path.resize(kSize);
        return std::filesystem::path(path).parent_path();
    }

    bool isAdministrator()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
        TOKEN_ELEVATION elevation{};
        DWORD size = 0;
        const bool kOk = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) != FALSE;
        CloseHandle(token);
        return kOk && elevation.TokenIsElevated;
    }

    std::wstring timestamp()
    {
        SYSTEMTIME t{};
        GetSystemTime(&t);
        wchar_t buf[48]{};
        swprintf_s(buf, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", t.wYear, t.wMonth, t.wDay,
            t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
        return buf;
    }

    Diagnostic inspect()
    {
        using namespace ks::dwm_order::runtime;
        Diagnostic d;
        std::wostringstream s;
        s << L"report_schema=1\r\ntool_version=1.0.0\r\nutc=" << timestamp()
          << L"\r\ninspection=on-disk PE only; no DWM injection\r\narchitecture=x64\r\nelevated=" << isAdministrator() << L"\r\n";
        try
        {
            using RtlVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
            const auto kAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
            RtlVersionFn rtl = nullptr;
            static_assert(sizeof(rtl) == sizeof(kAddress));
            std::memcpy(&rtl, &kAddress, sizeof(rtl));
            RTL_OSVERSIONINFOW os{};
            os.dwOSVersionInfoSize = sizeof(os);
            if (rtl && rtl(&os) == 0) s << L"os_version=" << os.dwMajorVersion << L'.' << os.dwMinorVersion << L'.' << os.dwBuildNumber << L"\r\n";
            DWORD ubr = 0, size = sizeof(ubr);
            if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR",
                RRF_RT_REG_DWORD, nullptr, &ubr, &size) == ERROR_SUCCESS) s << L"os_ubr=" << ubr << L"\r\n";
            DWORD session = 0;
            if (ProcessIdToSessionId(GetCurrentProcessId(), &session)) s << L"session=" << session << L"\r\n";
            s << L"remote_session=" << GetSystemMetrics(SM_REMOTESESSION) << L"\r\n";
            for (DWORD i = 0; i < 16; ++i)
            {
                DISPLAY_DEVICEW gpu{};
                gpu.cb = sizeof(gpu);
                if (!EnumDisplayDevicesW(nullptr, i, &gpu, 0)) break;
                s << L"display_adapter=" << gpu.DeviceString << L"\r\n";
            }
            wchar_t system[MAX_PATH]{};
            if (!GetSystemDirectoryW(system, MAX_PATH)) throw std::runtime_error("System directory unavailable");
            d.udwm = std::filesystem::path(system) / L"uDWM.dll";
            const auto kRaw = readFileBytes(d.udwm);
            d.udwmHash = hash(kRaw);
            const auto kVersion = version(d.udwm);
            s << L"udwm_version=" << kVersion << L"\r\nudwm_sha256=" << d.udwmHash << L"\r\n";
            const auto kDos = read<IMAGE_DOS_HEADER>(kRaw, 0);
            if (kDos.e_magic != IMAGE_DOS_SIGNATURE || kDos.e_lfanew < 0 || kDos.e_lfanew > 0x1000) throw std::runtime_error("Invalid DOS header");
            const auto kNt = read<IMAGE_NT_HEADERS64>(kRaw, kDos.e_lfanew);
            if (kNt.Signature != IMAGE_NT_SIGNATURE || kNt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
                || kNt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
                || kNt.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64)
                || kNt.OptionalHeader.SizeOfImage > 128 * 1024 * 1024
                || kNt.OptionalHeader.SizeOfHeaders > kRaw.size()
                || kNt.OptionalHeader.SizeOfHeaders > kNt.OptionalHeader.SizeOfImage
                || kNt.FileHeader.NumberOfSections > 96) throw std::runtime_error("Invalid x64 PE");
            std::vector<unsigned char> image(kNt.OptionalHeader.SizeOfImage);
            std::memcpy(image.data(), kRaw.data(), kNt.OptionalHeader.SizeOfHeaders);
            for (unsigned i = 0; i < kNt.FileHeader.NumberOfSections; ++i)
            {
                const auto kSection = read<IMAGE_SECTION_HEADER>(kRaw, kDos.e_lfanew + sizeof(kNt) + i * sizeof(IMAGE_SECTION_HEADER));
                if (kSection.PointerToRawData > kRaw.size() || kSection.SizeOfRawData > kRaw.size() - kSection.PointerToRawData
                    || kSection.VirtualAddress > image.size() || kSection.SizeOfRawData > image.size() - kSection.VirtualAddress)
                    throw std::runtime_error("Invalid section bounds");
                std::memcpy(image.data() + kSection.VirtualAddress, kRaw.data() + kSection.PointerToRawData, kSection.SizeOfRawData);
            }
            const auto kDebug = kNt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            if (kDebug.Size < 65536 && kDebug.VirtualAddress <= image.size() && kDebug.Size <= image.size() - kDebug.VirtualAddress)
                for (unsigned at = 0; at + sizeof(IMAGE_DEBUG_DIRECTORY) <= kDebug.Size; at += sizeof(IMAGE_DEBUG_DIRECTORY))
                {
                    const auto kE = read<IMAGE_DEBUG_DIRECTORY>(image, kDebug.VirtualAddress + at);
                    if (kE.Type != IMAGE_DEBUG_TYPE_CODEVIEW || kE.SizeOfData < 24) continue;
                    const auto kP = kE.AddressOfRawData;
                    if (kP > image.size() || kE.SizeOfData > image.size() - kP || read<DWORD>(image, kP) != 0x53445352) continue;
                    const auto kGuid = read<GUID>(image, kP + 4);
                    wchar_t text[64]{};
                    swprintf_s(text, L"%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", kGuid.Data1, kGuid.Data2, kGuid.Data3,
                        kGuid.Data4[0], kGuid.Data4[1], kGuid.Data4[2], kGuid.Data4[3], kGuid.Data4[4], kGuid.Data4[5], kGuid.Data4[6], kGuid.Data4[7]);
                    s << L"udwm_pdb_guid=" << text << L"\r\nudwm_pdb_age=" << read<DWORD>(image, kP + 20) << L"\r\n";
                }
            Resolved resolved{};
            Node node = Node::kCount;
            const auto kFailure = resolve(image.data(), image.size(), kNt.OptionalHeader.ImageBase, resolved, &node);
            d.modelMatched = kFailure == Failure::kNone;
            s << L"resolve_failure=" << failureText(kFailure) << L"\r\nfailed_node=" << static_cast<unsigned>(node)
              << L"\r\nmodel=" << resolved.model << L"\r\nwindow_list_offset=" << hex(resolved.windowListOffset)
              << L"\r\nhook_slots=" << resolved.destroySlot << L',' << resolved.zOrderSlot << L',' << resolved.updateSlot << L"\r\n";
            for (unsigned i = 0; i < static_cast<unsigned>(Node::kCount); ++i)
                s << L"function_rva_" << i << L'=' << hex(resolved.functions[i]) << L"\r\n";
            d.summary = L"uDWM " + kVersion + (d.modelMatched ? L"：文件特征匹配通过 / file model matched" : L"：文件特征不支持 / unsupported file model");
            s << L"visual_result=not inferred from file inspection\r\n";
            const auto kAgent = executableDirectory() / L"KswordDwmZOrder.dll";
            if (std::filesystem::exists(kAgent)) s << L"agent_sha256=" << hash(readFileBytes(kAgent)) << L"\r\n";
            else s << L"agent_file=missing\r\n";
            s << L"exe_sha256=" << hash(readFileBytes(executableDirectory() / L"DwmOrderTool.exe")) << L"\r\n";
            d.complete = true;
        }
        catch (const std::exception& e)
        {
            d.summary = L"文件诊断未完成 / inspection incomplete";
            s << L"inspection_error=";
            for (const char* p = e.what(); *p; ++p) s << static_cast<wchar_t>(static_cast<unsigned char>(*p));
            s << L"\r\n";
        }
        s << L"inspection_complete=" << d.complete << L"\r\n";
        d.details = s.str();
        return d;
    }

    std::wstring statusText(ks::dwm_order::Status status)
    {
        using S = ks::dwm_order::Status;
        switch (status)
        {
        case S::kOk: return L"回执成功 / OK";
        case S::kInvalidRequest: return L"请求无效 / Invalid request";
        case S::kInvalidWindow: return L"窗口失效或身份变化 / Invalid window";
        case S::kDifferentDesktop: return L"窗口不在同一桌面 / Different desktop";
        case S::kUnsupportedRuntime: return L"当前 DWM 模型不支持 / Unsupported DWM runtime";
        case S::kHookConflict: return L"排序回调冲突 / Hook conflict";
        case S::kWindowNotComposed: return L"窗口未参与合成 / Window not composed";
        case S::kNativeFailure: return L"内部调用失败，可能部分生效 / Native failure, possibly partial";
        case S::kVerificationFailed: return L"回读未通过 / Verification failed";
        case S::kNotRunning: return L"代理未运行 / Agent not running";
        case S::kAgentMismatch: return L"代理版本不同，请注销后重试 / Agent mismatch; sign out and retry";
        case S::kTransportFailure: return L"连接或加载失败 / Transport failure";
        case S::kTimeout: return L"超时，结果未知 / Timeout, outcome unknown";
        case S::kInternalException: return L"代理异常，结果未知 / Agent exception, outcome unknown";
        }
        return L"未知状态 / Unknown status";
    }

    std::wstring formatOperation(const Operation& op)
    {
        const auto& r = op.reply.response;
        std::wostringstream s;
        s << L"utc=" << op.time << L"\r\naction=" << static_cast<unsigned>(op.request.action)
          << L"\r\nposition=" << static_cast<unsigned>(op.request.position) << L"\r\nmaintain_requested=" << op.request.maintain
          << L"\r\ntarget_hwnd=" << hex(op.request.target.hwnd) << L"\r\nreference_hwnd=" << hex(op.request.reference.hwnd)
          << L"\r\nstatus=" << static_cast<unsigned>(r.status) << L" (" << statusText(r.status) << L")"
          << L"\r\nstage=" << static_cast<unsigned>(op.reply.stage) << L"\r\ntransport_win32=" << op.reply.error
          << L"\r\nagent_win32=" << r.win32Error << L"\r\nhresult=" << hex(static_cast<std::uint32_t>(r.nativeResult))
          << L"\r\nloader_completed=" << op.reply.loaderCompleted << L"\r\nloader_thread_exit=" << hex(op.reply.loaderThreadExitCode)
          << L"\r\nrequest_thread_exit=" << hex(op.reply.requestThreadExitCode) << L"\r\ndwm_pid=" << r.dwmProcessId
          << L"\r\nflags=" << r.flags << L"\r\nverified=" << !!(r.flags & ks::dwm_order::kVerified)
          << L"\r\nfront_index_zero_based=" << r.index << L"\r\nwindow_count=" << r.windowCount
          << L"\r\nband=" << r.band << L"\r\nabove_hwnd=" << hex(r.previous) << L"\r\nbelow_hwnd=" << hex(r.next)
          << L"\r\nmaintained_hwnd=" << hex(r.maintainedWindow) << L"\r\nmaintenance_status=" << static_cast<unsigned>(r.maintenanceStatus) << L"\r\n";
        return s.str();
    }

    std::filesystem::path saveReport(const std::filesystem::path& parent, const Diagnostic& d,
        const std::vector<Operation>& operations, const std::wstring& observation, const std::wstring& notes, bool includeSystemImage)
    {
        std::filesystem::create_directories(parent);
        auto stamp = timestamp();
        for (auto& ch : stamp) if (ch == L':') ch = L'-';
        std::filesystem::path output;
        for (unsigned i = 0; i < 1000; ++i)
        {
            output = parent / (L"DwmOrder-report-" + stamp + L"-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(i));
            if (std::filesystem::create_directory(output)) break;
            output.clear();
        }
        if (output.empty()) throw std::runtime_error("Cannot create unique report directory");
        std::wostringstream report;
        report << d.details << L"\r\n[tester]\r\nobservation=" << observation << L"\r\nnotes=" << notes
            << L"\r\n\r\n[operations]\r\ncount=" << operations.size() << L"\r\n";
        for (std::size_t i = 0; i < operations.size(); ++i) report << L"\r\n[operation " << i << L"]\r\n" << formatOperation(operations[i]);
        writeText(output / L"report.txt", report.str());
        if (includeSystemImage)
        {
            const auto kRaw = readFileBytes(d.udwm);
            if (d.udwmHash.empty() || hash(kRaw) != d.udwmHash) throw std::runtime_error("System image changed; inspect again before exporting");
            std::ofstream f(output / L"uDWM.dll", std::ios::binary);
            f.write(reinterpret_cast<const char*>(kRaw.data()), static_cast<std::streamsize>(kRaw.size()));
            f.close();
            if (!f) throw std::runtime_error("System image export failed");
        }
        return output;
    }

    int selfTest(const std::filesystem::path& directory)
    {
        try
        {
            const auto kD = inspect();
            if (!kD.complete || kD.udwmHash.size() != 64) return 1;
            Operation op{};
            op.time = timestamp();
            op.reply.response.status = ks::dwm_order::Status::kTimeout;
            op.reply.requestThreadExitCode = 0xc0000409;
            const auto kFirst = saveReport(directory, kD, {op}, L"not tested", L"中文报告 / Unicode", false);
            const auto kSecond = saveReport(directory, kD, {}, L"not tested", L"", true);
            const auto kReport = readFileBytes(kFirst / L"report.txt");
            const std::string kText(kReport.begin(), kReport.end());
            if (kFirst == kSecond || std::filesystem::exists(kFirst / L"uDWM.dll")
                || hash(readFileBytes(kSecond / L"uDWM.dll")) != kD.udwmHash
                || kText.find("0xc0000409") == std::string::npos
                || kText.find(utf8(L"中文报告")) == std::string::npos) return 2;
            writeText(directory / L"self-test.txt", L"REPORT_SELF_TEST=PASS\r\nNo DWM injection performed.\r\n");
            return 0;
        }
        catch (...) { return 3; }
    }
}
