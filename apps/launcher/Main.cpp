#include "Launcher.h"
#include "../../shared/crash/WinCrashHandler.h"

#include <shellapi.h>
#include <sstream>

#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace launcher {

namespace {

std::wstring text(bool chinese, const wchar_t* zh, const wchar_t* en) { return chinese ? zh : en; }

std::wstring quoteArgument(const std::wstring& value) {
    if (value.empty()) return L"\"\"";
    bool needsQuotes = false;
    for (wchar_t ch : value) if (iswspace(ch) || ch == L'"') { needsQuotes = true; break; }
    if (!needsQuotes) return value;
    std::wstring output = L"\"";
    unsigned slashCount = 0;
    for (wchar_t ch : value) {
        if (ch == L'\\') { ++slashCount; continue; }
        if (ch == L'"') { output.append(slashCount * 2 + 1, L'\\'); output.push_back(L'"'); slashCount = 0; continue; }
        output.append(slashCount, L'\\'); slashCount = 0; output.push_back(ch);
    }
    output.append(slashCount * 2, L'\\');
    output.push_back(L'"');
    return output;
}

LauncherOptions parseOptions() {
    LauncherOptions options;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return options;
    for (int index = 1; index < argc; ++index) {
        const std::wstring kArgument = argv[index];
        if (kArgument == L"--launcher-main") { options.targetOverride = true; options.useLight = false; continue; }
        if (kArgument == L"--launcher-light") { options.targetOverride = true; options.useLight = true; continue; }
        if (kArgument == L"--launcher-check-only") { options.checkOnly = true; continue; }
        if (kArgument == L"--launcher-internal-upload") { options.internalUpload = true; continue; }
        if (kArgument == L"--launcher-internal-marker") { options.internalMarker = true; continue; }
        if (kArgument == L"--launcher-crash-report") { options.crashReport = true; continue; }
        if (kArgument == L"--launcher-crash-repeat") { options.crashRepeat = true; continue; }
        if (kArgument == L"--launcher-crash-pid" && index + 1 < argc) {
            options.crashProcessId = static_cast<DWORD>(wcstoul(argv[++index], nullptr, 0));
            continue;
        }
        if (kArgument == L"--launcher-crash-code" && index + 1 < argc) {
            options.crashExceptionCode = static_cast<DWORD>(wcstoul(argv[++index], nullptr, 0));
            continue;
        }
        if (kArgument == L"--launcher-crash-address" && index + 1 < argc) {
            options.crashExceptionAddress = _wcstoui64(argv[++index], nullptr, 0);
            continue;
        }
        if (kArgument == L"--launcher-crash-dump" && index + 1 < argc) {
            options.crashDumpPath = argv[++index];
            continue;
        }
        if (kArgument == L"--launcher-crash-dump-written" && index + 1 < argc) {
            options.crashDumpWritten = wcstoul(argv[++index], nullptr, 0) != 0;
            continue;
        }
        if (kArgument == L"--launcher-crash-ready-event" && index + 1 < argc) {
            options.crashReadyEventName = argv[++index];
            continue;
        }
        if (kArgument == ks::crash::kCrashRestartedArgument) { continue; }
        if (kArgument == ks::crash::kCrashRestartWaitPidArgument && index + 1 < argc) {
            ++index;
            continue;
        }
        options.forwardedArguments.push_back(kArgument);
    }
    LocalFree(argv);
    return options;
}

bool targetExists(const RuntimePaths& paths, const LauncherOptions& options) {
    return fileExists(options.useLight ? paths.lightPath : paths.mainPath);
}

void showTargetMissing(const RuntimePaths& paths, const LauncherOptions& options, bool chinese) {
    const std::wstring kTarget = options.useLight ? paths.lightPath : paths.mainPath;
    showSimpleMessage(text(chinese, L"启动失败", L"Launch failed"),
        text(chinese, L"找不到启动目标：", L"The launch target was not found: ") + kTarget, chinese);
}

}

bool relaunchElevated(const LauncherOptions& options, bool forUpload) {
    RuntimePaths paths = resolveRuntimePaths();
    std::wstring arguments = options.useLight ? L"--launcher-light " : L"--launcher-main ";
    arguments += forUpload ? L"--launcher-internal-upload" : L"--launcher-internal-marker";
    for (const std::wstring& argument : options.forwardedArguments) { arguments.push_back(L' '); arguments += quoteArgument(argument); }
    const HINSTANCE kResult = ShellExecuteW(nullptr, L"runas", joinPath(paths.launcherDirectory, L"Launcher.exe").c_str(), arguments.c_str(), paths.launcherDirectory.c_str(), SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(kResult) > 32;
}

bool launchTarget(const RuntimePaths& paths, const LauncherOptions& options) {
    const std::wstring kTarget = options.useLight ? paths.lightPath : paths.mainPath;
    if (!fileExists(kTarget)) return false;
    std::wstring commandLine = quoteArgument(kTarget);
    for (const std::wstring& argument : options.forwardedArguments) { commandLine.push_back(L' '); commandLine += quoteArgument(argument); }
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup = { sizeof(startup) };
    PROCESS_INFORMATION process = {};
    const BOOL kCreated = CreateProcessW(kTarget.c_str(), mutableCommand.data(), nullptr, nullptr, FALSE, 0, nullptr, paths.launcherDirectory.c_str(), &startup, &process);
    if (!kCreated) return false;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return true;
}

}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    using namespace launcher;
    ks::crash::Configuration crashConfiguration;
    crashConfiguration.productName = L"Ksword Launcher";
    crashConfiguration.dumpFilePrefix = L"Launcher";
    crashConfiguration.preferLauncherReporter = false;
    ks::crash::installCrashHandler(crashConfiguration);
    ks::crash::DialogText launcherCrashText;
    if (isChineseUi()) {
        launcherCrashText.title = L"Ksword Launcher 崩溃";
        launcherCrashText.instruction = L"Ksword Launcher 因未处理的异常停止运行。";
        launcherCrashText.restartQuestion = L"选择“是”重新启动 Launcher，选择“否”退出。";
        launcherCrashText.restartFailedText = L"重新启动 Launcher 失败，程序即将退出。";
    } else {
        launcherCrashText.title = L"Ksword Launcher crashed";
        launcherCrashText.instruction = L"Ksword Launcher stopped because of an unhandled exception.";
        launcherCrashText.restartQuestion = L"Choose Yes to restart Launcher, or No to exit.";
        launcherCrashText.restartFailedText = L"Launcher could not be restarted and will now exit.";
    }
    ks::crash::updateCrashDialogText(launcherCrashText);
    (void)ks::crash::waitForCrashRestartTargetFromCommandLine();
    const bool kChinese = isChineseUi();
    const OsInfo kOs = queryOsInfo();
    const RuntimePaths kPaths = resolveRuntimePaths();
    LauncherOptions options = parseOptions();

    if (options.crashReport) {
        return handleCrashReportMode(kPaths, options, kChinese);
    }

    if (!kOs.isWindows10OrLater()) {
        showUnsupportedOsDialog(kOs, kChinese);
        return 0;
    }

    SupportManifest manifest;
    const bool kManifestLoaded = loadSupportManifest(kPaths, &manifest);
    if (!kManifestLoaded) {
        if (options.checkOnly) {
            showSimpleMessage(text(kChinese, L"偏移清单不可用", L"Support manifest unavailable"), utf8ToWide(manifest.error), kChinese);
            return 0;
        }
        if (!options.targetOverride && kOs.isEarlyQtUnsupported()) {
            const int kChoice = showEarlyWindowsChoiceDialog(kChinese);
            if (kChoice != 1001 && kChoice != 1002) return 0;
            options.useLight = kChoice == 1002;
        }
        if (!options.targetOverride && !kOs.isEarlyQtUnsupported()) options.useLight = false;
        if (!targetExists(kPaths, options)) { showTargetMissing(kPaths, options, kChinese); return 0; }
        launchTarget(kPaths, options);
        return 0;
    }

    bool markerValid = false;
    if (!options.checkOnly && !options.internalUpload && !options.internalMarker) {
        MarkerState marker;
        if (loadMarker(kPaths, &marker)) {
            ScanResult markerScan = scanCompatibility(manifest);
            if (markerScan.kernel.valid && marker.manifestSha256 == manifest.sha256 && marker.kernelKey == kernelIdentityKey(markerScan.kernel)) {
                if (!options.targetOverride) options.useLight = marker.useLight;
                markerValid = true;
            }
        }
    }

    if (!options.targetOverride && !markerValid && kOs.isEarlyQtUnsupported()) {
        const int kChoice = showEarlyWindowsChoiceDialog(kChinese);
        if (kChoice != 1001 && kChoice != 1002) return 0;
        options.useLight = kChoice == 1002;
    }

    if (markerValid && !options.checkOnly) {
        if (!launchTarget(kPaths, options)) showTargetMissing(kPaths, options, kChinese);
        return 0;
    }

    if (!targetExists(kPaths, options)) {
        showTargetMissing(kPaths, options, kChinese);
        return 0;
    }

    HWND checkingWindow = nullptr;
    showCheckingWindow(text(kChinese, L"正在核对偏移清单……", L"Checking the offset support list..."), &checkingWindow);
    ScanResult scan = scanCompatibility(manifest);
    closeCheckingWindow(checkingWindow);

    if (options.checkOnly) {
        if (scan.missing.empty()) showSimpleMessage(text(kChinese, L"核对完成", L"Check completed"), text(kChinese, L"当前系统的已加载内核模块均有完整偏移信息。", L"All loaded kernel modules have complete offset information."), kChinese);
        else showSimpleMessage(text(kChinese, L"发现缺少偏移", L"Missing offsets detected"), text(kChinese, L"发现部分已加载内核模块没有完整偏移信息。详细身份已写入上报报告，但检查模式不会启动主程序。", L"Some loaded kernel modules do not have complete offsets. Detailed identities are written to the report only; check-only mode will not launch the program."), kChinese);
        return 0;
    }

    if (!scan.missing.empty() && !options.internalUpload && !options.internalMarker) {
        const int kChoice = showMissingDataDialog(kChinese);
        if (kChoice == 1004) {
            if (relaunchElevated(options, true)) return 0;
            while (showUploadElevationFailureDialog(kChinese) == 1005) if (relaunchElevated(options, true)) return 0;
        }
    }

    if (options.internalUpload) {
        std::wstring bundle;
        CollectionProgress progress;
        showCollectionProgress(kChinese, &progress);
        const bool kPrepared = prepareUploadBundle(kPaths, manifest, scan, &bundle, &progress, kChinese);
        closeCollectionProgress(&progress);
        if (!kPrepared) {
            showSimpleMessage(text(kChinese, L"采集失败", L"Collection failed"),
                text(kChinese, L"无法准备开发者采集文件夹。", L"The developer collection folder could not be prepared."), kChinese);
        }
        if (!bundle.empty()) openBundleFolder(bundle);
    }

    MarkerState marker;
    marker.manifestSha256 = manifest.sha256;
    marker.kernelKey = kernelIdentityKey(scan.kernel);
    marker.useLight = options.useLight;
    bool accessDenied = false;
    if (!options.internalMarker) {
        if (!writeMarker(kPaths, marker, &accessDenied) && accessDenied && relaunchElevated(options, false)) return 0;
    } else {
        writeMarker(kPaths, marker, nullptr);
    }

    if (!launchTarget(kPaths, options)) { showTargetMissing(kPaths, options, kChinese); return 0; }
    return 0;
}
