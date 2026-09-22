#include "Launcher.h"

#include <sstream>

namespace launcher {

bool loadMarker(const RuntimePaths& paths, MarkerState* marker) {
    if (!marker) return false;
    *marker = MarkerState();
    std::string text;
    if (!readTextFile(paths.markerPath, &text)) return false;
    JsonValue root;
    std::string error;
    if (!parseJson(text, &root, &error) || !root.isObject()) return false;
    marker->manifestSha256 = root.stringOr("manifestSha256", "");
    marker->kernelKey = root.stringOr("kernelKey", "");
    marker->useLight = root.booleanOr("useLight", false);
    marker->valid = !marker->manifestSha256.empty() && !marker->kernelKey.empty();
    return marker->valid;
}

bool writeMarker(const RuntimePaths& paths, const MarkerState& marker, bool* accessDenied) {
    if (accessDenied) *accessDenied = false;
    if (!ensureDirectory(paths.configDirectory)) {
        if (accessDenied && (GetLastError() == ERROR_ACCESS_DENIED || GetLastError() == ERROR_PRIVILEGE_NOT_HELD)) *accessDenied = true;
        return false;
    }
    std::ostringstream json;
    json << "{\n"
         << "  \"schemaVersion\": 1,\n"
         << "  \"manifestSha256\": \"" << jsonEscape(marker.manifestSha256) << "\",\n"
         << "  \"kernelKey\": \"" << jsonEscape(marker.kernelKey) << "\",\n"
         << "  \"useLight\": " << (marker.useLight ? "true" : "false") << "\n"
         << "}\n";
    const std::wstring kTemporary = paths.markerPath + L".tmp";
    if (!writeTextFile(kTemporary, json.str())) {
        if (accessDenied && (GetLastError() == ERROR_ACCESS_DENIED || GetLastError() == ERROR_PRIVILEGE_NOT_HELD)) *accessDenied = true;
        return false;
    }
    if (!MoveFileExW(kTemporary.c_str(), paths.markerPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const DWORD kError = GetLastError();
        DeleteFileW(kTemporary.c_str());
        if (accessDenied && (kError == ERROR_ACCESS_DENIED || kError == ERROR_PRIVILEGE_NOT_HELD)) *accessDenied = true;
        return false;
    }
    return true;
}

}
