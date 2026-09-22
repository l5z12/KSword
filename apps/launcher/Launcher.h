#pragma once

#include "Json.h"

#include <windows.h>
#include <string>
#include <vector>

namespace launcher {

struct OsInfo {
    DWORD major = 0;
    DWORD minor = 0;
    DWORD build = 0;
    bool isWindows10OrLater() const { return major >= 10; }
    bool isEarlyQtUnsupported() const { return major == 10 && build < 17763; }
};

struct PeIdentity {
    std::wstring fileName;
    std::wstring path;
    DWORD machine = 0;
    DWORD timeDateStamp = 0;
    DWORD sizeOfImage = 0;
    std::string pdbName;
    std::string pdbGuid;
    DWORD pdbAge = 0;
    bool valid = false;
    std::string error;
};

struct ModuleDefinition {
    int classId = -1;
    std::string className;
    std::vector<std::wstring> fileNames;
    bool alwaysCollect = false;
    bool compatibilityRequired = false;
    bool collectionOnly = false;
    std::string supportSource;
    int publishedProfileCount = 0;
    int completeProfileCount = 0;
    std::string coverageStatus;
};

struct SupportProfile {
    int classId = -1;
    DWORD machine = 0;
    DWORD timeDateStamp = 0;
    DWORD sizeOfImage = 0;
    std::string pdbName;
    std::string pdbGuid;
    DWORD pdbAge = 0;
    bool complete = false;
    double coveragePercent = 0.0;
    std::string profileName;
};

struct SupportManifest {
    int schemaVersion = 0;
    std::string generatedUtc;
    std::string product;
    DWORD minimumWindowsMajor = 10;
    DWORD qtMinimumBuild = 17763;
    DWORD advertisedMaximumBuild = 26100;
    bool allowNewerWindows11 = true;
    std::vector<ModuleDefinition> modules;
    std::vector<SupportProfile> profiles;
    std::string sha256;
    bool valid = false;
    std::string error;
};

struct LoadedModule {
    std::wstring name;
    std::wstring path;
    PeIdentity identity;
    int classId = -1;
};

struct ModuleFinding {
    LoadedModule module;
    bool profileFound = false;
    bool profileComplete = false;
    const SupportProfile* profile = nullptr;
};

struct ScanResult {
    std::vector<ModuleFinding> inspected;
    std::vector<ModuleFinding> collectionCandidates;
    std::vector<ModuleFinding> missing;
    PeIdentity kernel;
    std::string error;
};

struct LauncherOptions {
    bool checkOnly = false;
    bool targetOverride = false;
    bool useLight = false;
    bool internalUpload = false;
    bool internalMarker = false;
    bool crashReport = false;
    bool crashDumpWritten = false;
    bool crashRepeat = false;
    DWORD crashProcessId = 0;
    DWORD crashExceptionCode = 0;
    unsigned long long crashExceptionAddress = 0;
    std::wstring crashDumpPath;
    std::wstring crashReadyEventName;
    std::vector<std::wstring> forwardedArguments;
};

struct MarkerState {
    std::string manifestSha256;
    std::string kernelKey;
    bool useLight = false;
    bool valid = false;
};

struct RuntimePaths {
    std::wstring launcherDirectory;
    std::wstring configDirectory;
    std::wstring manifestPath;
    std::wstring mainPath;
    std::wstring lightPath;
    std::wstring markerPath;
};

struct CollectionProgress {
    HWND window = nullptr;
    HWND label = nullptr;
    HWND bar = nullptr;
};

bool isChineseUi();
std::wstring utf8ToWide(const std::string& text);
std::string wideToUtf8(const std::wstring& text);
std::wstring lowerWide(std::wstring value);
std::string upperAscii(std::string value);
std::wstring joinPath(const std::wstring& parent, const std::wstring& child);
bool fileExists(const std::wstring& path);
bool ensureDirectory(const std::wstring& path);
bool readFileBytes(const std::wstring& path, std::vector<BYTE>* bytes);
bool writeTextFile(const std::wstring& path, const std::string& text);
bool readTextFile(const std::wstring& path, std::string* text);
std::string sha256Bytes(const BYTE* data, size_t size);
std::string sha256File(const std::wstring& path);
std::string formatWin32Error(DWORD error = GetLastError());
std::string hex32(DWORD value);

OsInfo queryOsInfo();
RuntimePaths resolveRuntimePaths();
bool loadSupportManifest(const RuntimePaths& paths, SupportManifest* manifest);
std::string kernelIdentityKey(const PeIdentity& identity);
bool queryKernelModules(std::vector<LoadedModule>* modules);
bool probePeIdentity(const std::wstring& path, PeIdentity* identity);
ScanResult scanCompatibility(const SupportManifest& manifest);

bool loadMarker(const RuntimePaths& paths, MarkerState* marker);
bool writeMarker(const RuntimePaths& paths, const MarkerState& marker, bool* accessDenied);

int showUnsupportedOsDialog(const OsInfo& os, bool chinese);
int showEarlyWindowsChoiceDialog(bool chinese);
int showMissingDataDialog(bool chinese);
int showUploadElevationFailureDialog(bool chinese);
void showSimpleMessage(const std::wstring& title, const std::wstring& body, bool chinese);
void showCheckingWindow(const std::wstring& text, HWND* window);
void closeCheckingWindow(HWND window);
void showCollectionProgress(bool chinese, CollectionProgress* progress);
void updateCollectionProgress(CollectionProgress* progress, int percent, const std::wstring& text);
void closeCollectionProgress(CollectionProgress* progress);

bool relaunchElevated(const LauncherOptions& options, bool forUpload);
bool launchTarget(const RuntimePaths& paths, const LauncherOptions& options);
int handleCrashReportMode(const RuntimePaths& paths, const LauncherOptions& options, bool chinese);
bool prepareUploadBundle(const RuntimePaths& paths, const SupportManifest& manifest, const ScanResult& scan, std::wstring* bundlePath, CollectionProgress* progress, bool chinese);
void openBundleFolder(const std::wstring& path);
std::string buildReportJson(const RuntimePaths& paths, const SupportManifest& manifest, const ScanResult& scan);
std::string buildReportText(const SupportManifest& manifest, const ScanResult& scan, bool chinese);

}
