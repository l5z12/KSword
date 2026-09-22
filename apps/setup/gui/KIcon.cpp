#include "KIcon.h"

#include "KTheme.h"

#include "Fl_RGB_Image.H"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <vector>


struct NSVGimage;

// Local declaration mirrors FLTK's Fl_SVG_Image layout because this project keeps
// FLTK headers in a flat include directory while the bundled SVG header includes
// <FL/...> paths. Inputs, processing, and returns remain FLTK-owned at link time.
class FL_EXPORT Fl_SVG_Image : public Fl_RGB_Image {
private:
    typedef struct {
        NSVGimage* svgImage;
        int refCount;
    } CountedNsvGimage;
    CountedNsvGimage* countedSvgImage_;
    bool rasterized_;
    int rasterW_;
    int rasterH_;
    bool toDesaturate_;
    Fl_Color averageColor_;
    float averageWeight_;
    float svgScaling(int w, int h);
    void rasterize(int w, int h);
    void cache_size_(int& width, int& height) FL_OVERRIDE;
    void init(const char* name, const unsigned char* filedata, std::size_t length);
    Fl_SVG_Image(const Fl_SVG_Image* source);

public:
    bool proportional;
    Fl_SVG_Image(const char* filename);
    Fl_SVG_Image(const char* sharedname, const char* svgData);
    Fl_SVG_Image(const char* sharedname, const unsigned char* svgData, std::size_t length);
    virtual ~Fl_SVG_Image();
    Fl_Image* copy(int w, int h) const FL_OVERRIDE;
    Fl_Image* copy() const {
        return Fl_Image::copy();
    }
    void resize(int width, int height);
    void desaturate() FL_OVERRIDE;
    void color_average(Fl_Color c, float i) FL_OVERRIDE;
    void draw(int x, int y, int w, int h, int cx = 0, int cy = 0) FL_OVERRIDE;
    void draw(int x, int y) {
        draw(x, y, w(), h(), 0, 0);
    }
    Fl_SVG_Image* as_svg_image() FL_OVERRIDE {
        return this;
    }
    void normalize() FL_OVERRIDE;
};

namespace {
// KIconCacheEntry owns the themed SVG text and parsed FLTK image returned to callers.
struct KIconCacheEntry {
    std::string svgText;
    std::unique_ptr<Fl_SVG_Image> image;
};

// ThemeColorEntry stores one placeholder name and its resolved SVG hex color.
struct ThemeColorEntry {
    std::string name;
    std::string hex;
};

// ImageCache maps resolved path + full color signature + size to parsed SVG images.
using ImageCache = std::map<std::string, std::shared_ptr<KIconCacheEntry>>;

// TextCache maps resolved path + full color signature to themed SVG text buffers.
using TextCache = std::map<std::string, std::string>;

// cacheMutex serializes cache reads and writes because FLTK widgets may share icons.
std::mutex& cacheMutex() {
    static std::mutex mutex;
    return mutex;
}

// cachedImages returns the process-wide cache of FLTK image objects.
ImageCache& cachedImages() {
    static ImageCache cache;
    return cache;
}

// cachedTexts returns the process-wide cache of themed SVG markup strings.
TextCache& cachedTexts() {
    static TextCache cache;
    return cache;
}

// normalizeSlashes makes path comparisons stable across Windows and FLTK APIs.
std::string normalizeSlashes(std::string value) {
    std::replace(value.begin(), value.end(), '\\', '/');
    return value;
}

// lowerCopy returns a lower-case copy for extension and prefix checks.
std::string lowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

// upperCopy returns an upper-case copy for percent-style placeholder names.
std::string upperCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

// startsWith performs a stable prefix test for normalized paths and tokens.
bool startsWith(const std::string& value, const std::string& prefix) {
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

// isAbsolutePath detects Windows drive paths, UNC paths, and POSIX-style roots.
bool isAbsolutePath(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    if (path[0] == '/' || path[0] == '\\') {
        return true;
    }
    return path.size() > 1 && path[1] == ':';
}

// hasSvgExtension checks whether the caller supplied a .svg extension.
bool hasSvgExtension(const std::string& path) {
    const std::string kLower = lowerCopy(path);
    return kLower.size() >= 4 && kLower.substr(kLower.size() - 4) == ".svg";
}

// ensureSvgExtension appends .svg when callers pass names such as system/add_line.
std::string ensureSvgExtension(const std::string& path) {
    return hasSvgExtension(path) ? path : path + ".svg";
}

// stripKnownIconPrefix keeps API callers free to pass KswordGUI/Icon/system/add.svg.
std::string stripKnownIconPrefix(const std::string& path) {
    const std::string kNormalized = normalizeSlashes(path);
    const std::string kLower = lowerCopy(kNormalized);
    const std::string kProjectPrefix = "kswordframe3.0/kswordgui/icon/";
    const std::string kGuiPrefix = "kswordgui/icon/";
    const std::string kIconPrefix = "icon/";
    if (startsWith(kLower, kProjectPrefix)) {
        return kNormalized.substr(kProjectPrefix.size());
    }
    if (startsWith(kLower, kGuiPrefix)) {
        return kNormalized.substr(kGuiPrefix.size());
    }
    if (startsWith(kLower, kIconPrefix)) {
        return kNormalized.substr(kIconPrefix.size());
    }
    return kNormalized;
}

// stripAbsoluteIconPrefix accepts absolute paths only when they point below KswordGUI/Icon.
std::string stripAbsoluteIconPrefix(const std::string& path) {
    const std::string kNormalized = normalizeSlashes(path);
    const std::string kLower = lowerCopy(kNormalized);
    const std::string kMarker = "/kswordgui/icon/";
    const std::size_t kMarkerPos = kLower.find(kMarker);
    if (kMarkerPos == std::string::npos) {
        return std::string();
    }
    return kNormalized.substr(kMarkerPos + kMarker.size());
}

// hasUnsafeSegment rejects empty, current-directory, and parent-directory path parts.
bool hasUnsafeSegment(const std::string& path) {
    std::istringstream stream(path);
    std::string segment;
    while (std::getline(stream, segment, '/')) {
        if (segment.empty() || segment == "." || segment == "..") {
            return true;
        }
    }
    return false;
}

// sourceIconRoot derives the built-in Icon directory from this source file path.
std::string sourceIconRoot() {
    const std::string kSourceFile = normalizeSlashes(__FILE__);
    const std::size_t kSlash = kSourceFile.find_last_of('/');
    if (kSlash == std::string::npos) {
        return "Icon";
    }
    return kSourceFile.substr(0, kSlash) + "/Icon";
}

// fileExists performs a simple readability check without throwing exceptions.
bool fileExists(const std::string& path) {
    std::ifstream file(path.c_str(), std::ios::binary);
    return file.good();
}

// readTextFile loads the full SVG text into memory for placeholder replacement.
std::string readTextFile(const std::string& path) {
    std::ifstream file(path.c_str(), std::ios::binary);
    if (!file.good()) {
        return std::string();
    }
    std::ostringstream stream;
    stream << file.rdbuf();
    return stream.str();
}

// replaceAll substitutes one token throughout an SVG string and advances safely.
void replaceAll(std::string& text, const std::string& from, const std::string& to) {
    if (from.empty()) {
        return;
    }
    std::size_t position = 0;
    while ((position = text.find(from, position)) != std::string::npos) {
        text.replace(position, from.size(), to);
        position += to.size();
    }
}

// replaceAttributeValue replaces role names only when used as paint attribute values.
void replaceAttributeValue(std::string& svg, const std::string& attribute, const std::string& role, const std::string& hex) {
    replaceAll(svg, attribute + "=\"" + role + "\"", attribute + "=\"" + hex + "\"");
    replaceAll(svg, attribute + "='" + role + "'", attribute + "='" + hex + "'");
}

// replaceStyleValue replaces CSS-style paint placeholders inside SVG style attributes.
void replaceStyleValue(std::string& svg, const std::string& property, const std::string& role, const std::string& hex) {
    replaceAll(svg, property + ":" + role + ";", property + ":" + hex + ";");
    replaceAll(svg, property + ": " + role + ";", property + ": " + hex + ";");
    replaceAll(svg, property + ":" + role + " ", property + ":" + hex + " ");
    replaceAll(svg, property + ": " + role + " ", property + ": " + hex + " ");
    replaceAll(svg, property + ":" + role + "\"", property + ":" + hex + "\"");
    replaceAll(svg, property + ": " + role + "\"", property + ": " + hex + "\"");
    replaceAll(svg, property + ":" + role + "'", property + ":" + hex + "'");
    replaceAll(svg, property + ": " + role + "'", property + ": " + hex + "'");
}

// roleColor resolves a semantic KIconColorRole against the active KThemeManager palette.
Fl_Color roleColor(KIconColorRole role) {
    const KTheme& theme = KThemeManager::instance().theme();
    switch (role) {
    case KIconColorRole::kPrimary:
        return theme.primary;
    case KIconColorRole::kPrimaryLight:
        return theme.primaryLight;
    case KIconColorRole::kPrimaryDark:
        return theme.primaryDark;
    case KIconColorRole::kText:
        return theme.text;
    case KIconColorRole::kMuted:
        return theme.mutedText;
    case KIconColorRole::kBorder:
        return theme.border;
    case KIconColorRole::kDanger:
        return theme.danger;
    case KIconColorRole::kWarning:
        return theme.warning;
    case KIconColorRole::kSuccess:
        return theme.success;
    case KIconColorRole::kWindowBg:
        return theme.windowBg;
    case KIconColorRole::kPanelBg:
        return theme.panelBg;
    case KIconColorRole::kControlBg:
        return theme.controlBg;
    default:
        break;
    }
    return theme.primary;
}

// themeColors snapshots every named SVG role that can appear as a placeholder.
std::vector<ThemeColorEntry> themeColors() {
    const KTheme& theme = KThemeManager::instance().theme();
    std::vector<ThemeColorEntry> colors;
    colors.push_back({ "primary", KIcon::colorToHex(theme.primary) });
    colors.push_back({ "primary-light", KIcon::colorToHex(theme.primaryLight) });
    colors.push_back({ "primary-dark", KIcon::colorToHex(theme.primaryDark) });
    colors.push_back({ "text", KIcon::colorToHex(theme.text) });
    colors.push_back({ "muted", KIcon::colorToHex(theme.mutedText) });
    colors.push_back({ "muted-text", KIcon::colorToHex(theme.mutedText) });
    colors.push_back({ "border", KIcon::colorToHex(theme.border) });
    colors.push_back({ "danger", KIcon::colorToHex(theme.danger) });
    colors.push_back({ "success", KIcon::colorToHex(theme.success) });
    colors.push_back({ "warning", KIcon::colorToHex(theme.warning) });
    colors.push_back({ "window-bg", KIcon::colorToHex(theme.windowBg) });
    colors.push_back({ "panel-bg", KIcon::colorToHex(theme.panelBg) });
    colors.push_back({ "control-bg", KIcon::colorToHex(theme.controlBg) });
    return colors;
}

// replaceNamedThemeToken replaces one semantic color role in supported SVG placeholder forms.
void replaceNamedThemeToken(std::string& svg, const ThemeColorEntry& color) {
    const std::string& role = color.name;
    const std::string& hex = color.hex;
    const std::string kUpperRole = upperCopy(role);
    replaceAll(svg, "{{" + role + "}}", hex);
    replaceAll(svg, "{{theme." + role + "}}", hex);
    replaceAll(svg, "${" + role + "}", hex);
    replaceAll(svg, "${theme." + role + "}", hex);
    replaceAll(svg, "%" + kUpperRole + "%", hex);
    replaceAll(svg, "%THEME_" + kUpperRole + "%", hex);
    replaceAll(svg, "var(--" + role + ")", hex);
    replaceAll(svg, "var(--color-" + role + ")", hex);
    replaceAll(svg, "var(--ksword-" + role + ")", hex);
    replaceAll(svg, "theme(" + role + ")", hex);
    replaceAttributeValue(svg, "fill", role, hex);
    replaceAttributeValue(svg, "stroke", role, hex);
    replaceAttributeValue(svg, "color", role, hex);
    replaceAttributeValue(svg, "stop-color", role, hex);
    replaceStyleValue(svg, "fill", role, hex);
    replaceStyleValue(svg, "stroke", role, hex);
    replaceStyleValue(svg, "color", role, hex);
    replaceStyleValue(svg, "stop-color", role, hex);
}

// applyThemeColors replaces named theme placeholders plus the default one-color tint tokens.
std::string applyThemeColors(std::string svg, const std::string& tintHex) {
    const std::vector<ThemeColorEntry> kColors = themeColors();
    for (const ThemeColorEntry& color : kColors) {
        replaceNamedThemeToken(svg, color);
    }

    replaceAll(svg, "#43A0FF", tintHex);
    replaceAll(svg, "#43a0ff", tintHex);
    replaceAll(svg, "#409EFF", tintHex);
    replaceAll(svg, "#409eff", tintHex);
    replaceAll(svg, "currentColor", tintHex);
    replaceAll(svg, "{{color}}", tintHex);
    replaceAll(svg, "{{themeColor}}", tintHex);
    replaceAll(svg, "${color}", tintHex);
    replaceAll(svg, "%THEME_COLOR%", tintHex);
    return svg;
}

// joinIconName builds category/file.svg relative paths for convenience overloads.
std::string joinIconName(const std::string& category, const std::string& fileName) {
    if (category.empty()) {
        return fileName;
    }
    if (fileName.empty()) {
        return category;
    }
    return normalizeSlashes(category) + "/" + normalizeSlashes(fileName);
}

// colorSignature records every color that can affect rendered output for cache keys.
std::string colorSignature(const std::string& tintHex) {
    std::ostringstream signature;
    signature << "tint=" << tintHex;
    const std::vector<ThemeColorEntry> kColors = themeColors();
    for (const ThemeColorEntry& color : kColors) {
        signature << ';' << color.name << '=' << color.hex;
    }
    return signature.str();
}

// textCacheKey includes the resolved file path and all theme colors used in replacement.
std::string textCacheKey(const std::string& resolvedPath, const std::string& colorSignature) {
    return normalizeSlashes(resolvedPath) + "|" + colorSignature;
}

// imageCacheKey adds the requested raster size to the themed SVG text cache key.
std::string imageCacheKey(const std::string& resolvedPath, const std::string& colorSignature, int size) {
    std::ostringstream key;
    key << textCacheKey(resolvedPath, colorSignature) << "|size=" << size;
    return key.str();
}

// themedSvgTextLocked returns cached themed SVG text and expects cacheMutex to be held.
std::string themedSvgTextLocked(const std::string& resolvedPath, const std::string& tintHex, const std::string& colorSignature) {
    const std::string kKey = textCacheKey(resolvedPath, colorSignature);
    TextCache& cache = cachedTexts();
    auto found = cache.find(kKey);
    if (found != cache.end()) {
        return found->second;
    }

    const std::string kRawSvg = readTextFile(resolvedPath);
    if (kRawSvg.empty()) {
        return std::string();
    }

    const std::string kThemedSvg = applyThemeColors(kRawSvg, tintHex);
    cache[kKey] = kThemedSvg;
    return kThemedSvg;
}
} // namespace

Fl_Image* KIcon::loadThemedSvg(const std::string& name, KIconColorRole role, int size) {
    // Input is a caller icon name plus semantic role; processing resolves the role to the current theme color.
    return loadThemedSvg(name, roleColor(role), size);
}

Fl_Image* KIcon::loadThemedSvg(const std::string& category, const std::string& fileName, KIconColorRole role, int size) {
    // Input is split path parts; processing joins the path and delegates to the single-name loader.
    return loadThemedSvg(joinIconName(category, fileName), roleColor(role), size);
}

Fl_Image* KIcon::loadThemedSvg(const std::string& name, Fl_Color color, int size) {
    // Input path must resolve below KswordGUI/Icon; failure returns nullptr without touching source SVG files.
    const std::string kResolvedPath = resolveSvgPath(name);
    if (kResolvedPath.empty()) {
        return nullptr;
    }

    // The cache key includes both explicit tint and named theme colors to survive theme switches correctly.
    const std::string kTintHex = colorToHex(color);
    const std::string kColorSignature = colorSignature(kTintHex);
    const std::string kKey = imageCacheKey(kResolvedPath, kColorSignature, size);
    std::lock_guard<std::mutex> lock(cacheMutex());

    ImageCache& cache = cachedImages();
    auto found = cache.find(kKey);
    if (found != cache.end()) {
        return found->second && found->second->image ? found->second->image.get() : nullptr;
    }

    // SVG text is cached separately so text-only and image callers share replacement work.
    auto entry = std::make_shared<KIconCacheEntry>();
    entry->svgText = themedSvgTextLocked(kResolvedPath, kTintHex, kColorSignature);
    if (entry->svgText.empty()) {
        return nullptr;
    }

    // FLTK parses the themed in-memory SVG; the original SVG file remains unchanged on disk.
    entry->image.reset(new Fl_SVG_Image(nullptr, entry->svgText.c_str()));
    if (!entry->image || entry->image->fail() != 0) {
        entry->image.reset();
        return nullptr;
    }

    // A positive size requests a square icon while preserving SVG aspect ratio.
    if (size > 0) {
        entry->image->proportional = true;
        entry->image->resize(size, size);
    }

    Fl_Image* result = entry->image.get();
    cache[kKey] = entry;
    return result;
}

Fl_Image* KIcon::loadThemedSvg(const std::string& category, const std::string& fileName, Fl_Color color, int size) {
    // Input is split path parts plus explicit color; return value is the cached FLTK image pointer.
    return loadThemedSvg(joinIconName(category, fileName), color, size);
}

std::string KIcon::themedSvgText(const std::string& name, KIconColorRole role) {
    // Input role is resolved at call time so theme changes produce a new cache signature.
    return themedSvgText(name, roleColor(role));
}

std::string KIcon::themedSvgText(const std::string& name, Fl_Color color) {
    // Input path resolves inside Icon; return value is a copy of cached themed SVG markup.
    const std::string kResolvedPath = resolveSvgPath(name);
    if (kResolvedPath.empty()) {
        return std::string();
    }

    const std::string kTintHex = colorToHex(color);
    const std::string kColorSignature = colorSignature(kTintHex);
    std::lock_guard<std::mutex> lock(cacheMutex());
    return themedSvgTextLocked(kResolvedPath, kTintHex, kColorSignature);
}

std::string KIcon::resolveSvgPath(const std::string& name) {
    // Empty input cannot identify an SVG file and resolves to an empty result.
    if (name.empty()) {
        return std::string();
    }

    // Absolute inputs are accepted only when they already point below KswordGUI/Icon.
    const std::string kNormalized = normalizeSlashes(name);
    const std::string kStripped = isAbsolutePath(kNormalized) ? stripAbsoluteIconPrefix(kNormalized) : stripKnownIconPrefix(kNormalized);
    if (kStripped.empty()) {
        return std::string();
    }

    // Reject traversal so the icon loader only reads original resources from the Icon directory.
    const std::string kRelativeName = ensureSvgExtension(kStripped);
    if (isAbsolutePath(kRelativeName) || hasUnsafeSegment(kRelativeName)) {
        return std::string();
    }

    // Candidate roots cover source-tree, project-root, and current-working-directory layouts.
    std::vector<std::string> candidates;
    candidates.push_back(sourceIconRoot() + "/" + kRelativeName);
    candidates.push_back("KswordGUI/Icon/" + kRelativeName);
    candidates.push_back("Icon/" + kRelativeName);
    candidates.push_back("KswordFrame3.0/KswordGUI/Icon/" + kRelativeName);

    for (const std::string& candidate : candidates) {
        if (fileExists(candidate)) {
            return normalizeSlashes(candidate);
        }
    }
    return std::string();
}

void KIcon::clearCache() {
    // Input is none; processing destroys all cached text and images, invalidating prior returned pointers.
    std::lock_guard<std::mutex> lock(cacheMutex());
    cachedImages().clear();
    cachedTexts().clear();
}

bool KIcon::cached(const std::string& name, KIconColorRole role, int size) {
    // Input path and role are resolved exactly like loadThemedSvg so cache checks match loading behavior.
    const std::string kResolvedPath = resolveSvgPath(name);
    if (kResolvedPath.empty()) {
        return false;
    }

    const std::string kTintHex = colorToHex(roleColor(role));
    const std::string kKey = imageCacheKey(kResolvedPath, colorSignature(kTintHex), size);
    std::lock_guard<std::mutex> lock(cacheMutex());
    auto found = cachedImages().find(kKey);
    return found != cachedImages().end() && found->second && found->second->image;
}

std::string KIcon::colorToHex(Fl_Color color) {
    // Input FLTK color is converted through FLTK so indexed and RGB colors both resolve correctly.
    unsigned char red = 0;
    unsigned char green = 0;
    unsigned char blue = 0;
    Fl::get_color(color, red, green, blue);

    // Return value is uppercase #RRGGBB text suitable for SVG fill, stroke, and CSS color fields.
    std::ostringstream hex;
    hex << "#"
        << std::uppercase << std::hex << std::setfill('0')
        << std::setw(2) << static_cast<int>(red)
        << std::setw(2) << static_cast<int>(green)
        << std::setw(2) << static_cast<int>(blue);
    return hex.str();
}
