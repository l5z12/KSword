#include "Launcher.h"

#include <shellapi.h>
#include <algorithm>
#include <sstream>

namespace launcher {

namespace {

std::wstring fileNameOnly(const std::wstring& path) {
    const size_t kSeparator = path.find_last_of(L"\\/");
    return kSeparator == std::wstring::npos ? path : path.substr(kSeparator + 1);
}

std::wstring bundleRoot() {
    wchar_t temp[MAX_PATH] = {};
    const DWORD kLength = GetTempPathW(ARRAYSIZE(temp), temp);
    if (!kLength || kLength >= ARRAYSIZE(temp)) return {};
    std::wstring root(temp, kLength);
    while (!root.empty() && (root.back() == L'\\' || root.back() == L'/')) root.pop_back();
    return joinPath(root, L"KswordCompabilityCheck");
}

std::wstring bundleLeaf(const std::wstring& root, bool chinese) {
    return joinPath(root, chinese ? L"压缩我并发送给开发者" : L"CompressAndSendToDeveloper");
}

bool deleteTree(const std::wstring& path) {
    WIN32_FIND_DATAW data = {};
    const std::wstring kPattern = joinPath(path, L"*");
    HANDLE finder = FindFirstFileW(kPattern.c_str(), &data);
    if (finder != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
            const std::wstring kChild = joinPath(path, data.cFileName);
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!deleteTree(kChild)) { FindClose(finder); return false; }
            } else if (!DeleteFileW(kChild.c_str())) { FindClose(finder); return false; }
        } while (FindNextFileW(finder, &data));
        FindClose(finder);
    }
    return RemoveDirectoryW(path.c_str()) != FALSE || GetLastError() == ERROR_PATH_NOT_FOUND;
}

bool copyAttachment(const std::wstring& source, const std::wstring& destination, std::vector<std::wstring>* copied, std::string* log) {
    if (source.empty() || !fileExists(source)) {
        if (log) *log += "missing source: " + wideToUtf8(source) + "\n";
        return false;
    }
    if (!CopyFileW(source.c_str(), destination.c_str(), FALSE)) {
        if (log) *log += "copy failed: " + wideToUtf8(source) + " (" + formatWin32Error() + ")\n";
        return false;
    }
    copied->push_back(destination);
    return true;
}

std::string identityJson(const PeIdentity& identity) {
    const std::string kSymbolKey = upperAscii(identity.pdbGuid) + std::to_string(identity.pdbAge);
    std::ostringstream json;
    json << "{\"fileName\":\"" << jsonEscape(wideToUtf8(identity.fileName)) << "\",\"path\":\"" << jsonEscape(wideToUtf8(identity.path))
         << "\",\"machine\":" << identity.machine << ",\"timeDateStamp\":" << identity.timeDateStamp << ",\"sizeOfImage\":" << identity.sizeOfImage
         << ",\"pdbName\":\"" << jsonEscape(identity.pdbName) << "\",\"pdbGuid\":\"" << jsonEscape(identity.pdbGuid) << "\",\"pdbAge\":" << identity.pdbAge
         << ",\"pdbSymbolKey\":\"" << jsonEscape(kSymbolKey) << "\""
         << ",\"valid\":" << (identity.valid ? "true" : "false") << ",\"error\":\"" << jsonEscape(identity.error) << "\"}";
    return json.str();
}

const ModuleDefinition* findModulePolicy(const SupportManifest& manifest, int classId) {
    for (const ModuleDefinition& module : manifest.modules) if (module.classId == classId) return &module;
    return nullptr;
}

}

std::string buildReportJson(const RuntimePaths&, const SupportManifest& manifest, const ScanResult& scan) {
    const OsInfo kOs = queryOsInfo();
    std::ostringstream json;
    json << "{\n  \"schemaVersion\": 1,\n  \"os\": {\"major\": " << kOs.major << ", \"minor\": " << kOs.minor << ", \"build\": " << kOs.build << "},\n  \"manifestSha256\": \"" << jsonEscape(manifest.sha256) << "\",\n  \"kernel\": " << identityJson(scan.kernel) << ",\n  \"modules\": [\n";
    for (size_t index = 0; index < scan.inspected.size(); ++index) {
        const ModuleFinding& finding = scan.inspected[index];
        const ModuleDefinition* policy = findModulePolicy(manifest, finding.module.classId);
        json << "    {\"classId\":" << finding.module.classId << ",\"name\":\"" << jsonEscape(wideToUtf8(finding.module.name)) << "\",\"profileFound\":" << (finding.profileFound ? "true" : "false")
             << ",\"profileComplete\":" << (finding.profileComplete ? "true" : "false")
             << ",\"compatibilityRequired\":" << (policy && policy->compatibilityRequired ? "true" : "false")
             << ",\"collectionOnly\":" << (policy && policy->collectionOnly ? "true" : "false")
             << ",\"supportSource\":\"" << jsonEscape(policy ? policy->supportSource : "unknown") << "\",\"identity\":" << identityJson(finding.module.identity) << "}";
        if (index + 1 != scan.inspected.size()) json << ',';
        json << '\n';
    }
    json << "  ],\n  \"missingCount\": " << scan.missing.size() << ",\n  \"collectionCandidateCount\": " << scan.collectionCandidates.size() << ",\n  \"notes\": \"PDB files are intentionally not copied; use pdbName, pdbGuid and pdbAge to download exact symbols.\"\n}\n";
    return json.str();
}

std::string buildReportText(const SupportManifest& manifest, const ScanResult& scan, bool chinese) {
    const OsInfo kOs = queryOsInfo();
    std::ostringstream text;
    text << "Ksword Launcher compatibility report\n";
    text << "OS: Windows " << kOs.major << "." << kOs.minor << " Build " << kOs.build << " (amd64)\n";
    text << "Manifest SHA-256: " << manifest.sha256 << "\n";
    text << "Kernel: " << wideToUtf8(scan.kernel.fileName) << "\n";
    text << "  Path: " << wideToUtf8(scan.kernel.path) << "\n";
    text << "  PDB: " << scan.kernel.pdbName << "\n";
    text << "  GUID: " << scan.kernel.pdbGuid << "\n";
    text << "  Age: " << scan.kernel.pdbAge << "\n\n";
    text << "Modules inspected: " << scan.inspected.size() << "\n";
    text << "Compatibility-required modules missing or incomplete: " << scan.missing.size() << "\n";
    text << "Loaded modules selected for collection: " << scan.collectionCandidates.size() << "\n";
    for (const ModuleFinding& finding : scan.collectionCandidates) {
        text << "- " << wideToUtf8(finding.module.name) << " class=" << finding.module.classId << " profile=" << (finding.profileFound ? "incomplete" : "not published") << "\n";
        text << "  path=" << wideToUtf8(finding.module.path) << "\n";
        text << "  machine=" << finding.module.identity.machine << " timestamp=" << finding.module.identity.timeDateStamp << " imageSize=" << finding.module.identity.sizeOfImage << "\n";
        text << "  pdbName=" << finding.module.identity.pdbName << " pdbGuid=" << finding.module.identity.pdbGuid << " pdbAge=" << finding.module.identity.pdbAge
             << " pdbSymbolKey=" << upperAscii(finding.module.identity.pdbGuid) << finding.module.identity.pdbAge << "\n";
    }
    text << "\nPDB files are intentionally not included. Download symbols with the PDB name/GUID/Age above.\n";
    text << (chinese ? "界面语言：中文\n" : "UI language: English\n");
    return text.str();
}

bool prepareUploadBundle(const RuntimePaths& paths, const SupportManifest& manifest, const ScanResult& scan, std::wstring* bundlePath, CollectionProgress* progress, bool chinese) {
    if (!bundlePath) return false;
    const std::wstring kRoot = bundleRoot();
    if (kRoot.empty()) return false;
    const std::wstring kBundle = bundleLeaf(kRoot, chinese);
    auto update = [&](int percent, const std::wstring& text) {
        if (progress) updateCollectionProgress(progress, percent, text);
    };
    update(5, chinese ? L"准备采集目录…" : L"Preparing the collection folder...");
    if (!ensureDirectory(kRoot)) return false;
    // Only delete the fixed leaf directory, preserving the parent directory to avoid accidentally deleting other user temporary files.
    const DWORD kExistingAttributes = GetFileAttributesW(kBundle.c_str());
    if (kExistingAttributes != INVALID_FILE_ATTRIBUTES) {
        if (kExistingAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!deleteTree(kBundle)) return false;
        } else if (!DeleteFileW(kBundle.c_str())) {
            return false;
        }
    }
    if (!ensureDirectory(kBundle)) return false;
    std::vector<std::wstring> copied;
    std::string log;
    update(15, chinese ? L"写入报告…" : L"Writing reports...");
    const std::wstring kReadme = joinPath(kBundle, L"README.txt");
    const std::string kReadmeText = "Ksword Launcher compatibility collection\n\nCompress this folder and send it to the Ksword developer.\nThe .bin files are renamed copies of kernel modules; they are not executable replacements.\nPDB files are not included. report.json/report.txt contain PDB Name/GUID/Age/SymbolKey for symbol download.\n";
    writeTextFile(kReadme, kReadmeText);
    writeTextFile(joinPath(kBundle, L"report.json"), buildReportJson(paths, manifest, scan));
    // Keep the report body in English to facilitate direct comparison by developers on systems with different languages.
    writeTextFile(joinPath(kBundle, L"report.txt"), buildReportText(manifest, scan, false));

    std::vector<std::wstring> sourcePaths;
    sourcePaths.push_back(scan.kernel.path);
    for (const ModuleFinding& finding : scan.inspected) {
        if (finding.module.classId != 0) sourcePaths.push_back(finding.module.path);
    }
    std::sort(sourcePaths.begin(), sourcePaths.end());
    sourcePaths.erase(std::unique(sourcePaths.begin(), sourcePaths.end()), sourcePaths.end());
    const size_t kSourceCount = sourcePaths.size();
    size_t sourceIndex = 0;
    for (const std::wstring& source : sourcePaths) {
        if (source.empty()) continue;
        const std::wstring kName = fileNameOnly(source) + L".bin";
        copyAttachment(source, joinPath(kBundle, kName), &copied, &log);
        ++sourceIndex;
        const int kPercent = kSourceCount == 0 ? 75 : 25 + static_cast<int>((50.0 * sourceIndex) / kSourceCount);
        update(kPercent, chinese ? L"正在复制系统文件…" : L"Copying system files...");
    }
    std::ostringstream sums;
    update(80, chinese ? L"计算文件校验值…" : L"Calculating file checksums...");
    for (size_t index = 0; index < copied.size(); ++index) {
        const std::wstring& file = copied[index];
        sums << sha256File(file) << "  " << wideToUtf8(fileNameOnly(file)) << "\n";
        update(80 + static_cast<int>(15.0 * (index + 1) / std::max<size_t>(1, copied.size())), chinese ? L"计算文件校验值…" : L"Calculating file checksums...");
    }
    writeTextFile(joinPath(kBundle, L"SHA256SUMS.txt"), sums.str());
    if (!log.empty()) writeTextFile(joinPath(kBundle, L"launcher.log"), log);
    else writeTextFile(joinPath(kBundle, L"launcher.log"), "Collection completed without copy errors.\n");
    update(100, chinese ? L"采集完成" : L"Collection complete");
    *bundlePath = kBundle;
    return true;
}

void openBundleFolder(const std::wstring& path) {
    std::wstring folder = path;
    while (!folder.empty() && (folder.back() == L'\\' || folder.back() == L'/')) folder.pop_back();
    const size_t kSeparator = folder.find_last_of(L"\\/");
    if (kSeparator != std::wstring::npos) folder.resize(kSeparator);
    ShellExecuteW(nullptr, L"open", L"explorer.exe", folder.c_str(), nullptr, SW_SHOWNORMAL);
}

}
