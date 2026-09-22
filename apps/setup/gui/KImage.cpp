#include "KImage.h"

#include "Fl_Image.H"
#include "Fl_Shared_Image.H"

#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>

// Cache entries own one FLTK shared-image reference and keep failed-load state.
struct KImageResourceCacheEntry {
    // Initializes an empty cache entry; callers fill path, image, dimensions, and error.
    KImageResourceCacheEntry()
        : path(),
          sharedImage(nullptr),
          width(0),
          height(0),
          error() {
    }

    // Releases the FLTK shared-image reference held by this cache entry.
    ~KImageResourceCacheEntry() {
        if (sharedImage) {
            sharedImage->release();
            sharedImage = nullptr;
        }
    }

    KImageResourceCacheEntry(const KImageResourceCacheEntry&) = delete;
    KImageResourceCacheEntry& operator=(const KImageResourceCacheEntry&) = delete;

    std::string path;
    Fl_Shared_Image* sharedImage;
    int width;
    int height;
    std::string error;
};

namespace {
// ImageCache stores both successful and failed loads so repeated paths avoid I/O.
using ImageCache = std::map<std::string, std::shared_ptr<KImageResourceCacheEntry>>;

// emptyString returns a stable reference for empty path/error accessors.
const std::string& emptyString() {
    static const std::string kEmpty;
    return kEmpty;
}

// cacheMutex serializes access to the process-wide image cache and FLTK image loader.
std::mutex& cacheMutex() {
    static std::mutex mutex;
    return mutex;
}

// Cache returns the process-wide path-to-entry map used by KImageResource.
ImageCache& imageCache() {
    static ImageCache cache;
    return cache;
}

// registerFltkImageHandlers enables FLTK's built-in PNG/JPEG/BMP/GIF handlers once.
void registerFltkImageHandlers() {
    static std::once_flag registerOnce;
    std::call_once(registerOnce, []() {
        fl_register_images();
    });
}

// canReadFile checks basic file accessibility before FLTK tries to decode it.
bool canReadFile(const std::string& path) {
    std::ifstream file(path.c_str(), std::ios::binary);
    return file.good();
}

// fltkFailureText converts FLTK image error codes into stable user-facing text.
std::string fltkFailureText(int code) {
    switch (code) {
    case Fl_Image::ERR_NO_IMAGE:
        return "FLTK did not create image data.";
    case Fl_Image::ERR_FILE_ACCESS:
        return "FLTK could not access the image file.";
    case Fl_Image::ERR_FORMAT:
        return "FLTK does not recognize the image format.";
    case Fl_Image::ERR_MEMORY_ACCESS:
        return "FLTK could not allocate or access image memory.";
    default:
        break;
    }

    std::ostringstream message;
    message << "FLTK image loader failed with error code " << code << ".";
    return message.str();
}

// makeFailureEntry creates a cached failure entry without throwing exceptions.
std::shared_ptr<KImageResourceCacheEntry> makeFailureEntry(const std::string& path, const std::string& error) {
    auto entry = std::make_shared<KImageResourceCacheEntry>();
    entry->path = path;
    entry->error = error;
    return entry;
}

// loadEntry decodes one image path through FLTK and records dimensions or error text.
std::shared_ptr<KImageResourceCacheEntry> loadEntry(const std::string& path) {
    if (path.empty()) {
        return makeFailureEntry(path, "Image path is empty.");
    }

    // The wrapper is file-path based, so report an access error before decoding.
    if (!canReadFile(path)) {
        return makeFailureEntry(path, "Image file not found or not accessible: " + path);
    }

    registerFltkImageHandlers();

    Fl_Shared_Image* image = Fl_Shared_Image::get(path.c_str());
    if (!image) {
        return makeFailureEntry(path, "FLTK could not load image file: " + path);
    }

    // FLTK can return an image object with a failure code; release that reference.
    const int kLoadError = image->fail();
    if (kLoadError != 0) {
        std::string error = fltkFailureText(kLoadError) + " Path: " + path;
        image->release();
        return makeFailureEntry(path, error);
    }

    // Zero-sized images are not drawable in this GUI layer and are treated as invalid.
    if (image->w() <= 0 || image->h() <= 0) {
        image->release();
        return makeFailureEntry(path, "Image loaded with invalid dimensions: " + path);
    }

    auto entry = std::make_shared<KImageResourceCacheEntry>();
    entry->path = path;
    entry->sharedImage = image;
    entry->width = image->w();
    entry->height = image->h();
    return entry;
}

// getOrLoadEntry returns a cached entry or loads and caches a new entry for path.
std::shared_ptr<KImageResourceCacheEntry> getOrLoadEntry(const std::string& path) {
    std::lock_guard<std::mutex> lock(cacheMutex());

    ImageCache& cache = imageCache();
    auto found = cache.find(path);
    if (found != cache.end()) {
        return found->second;
    }

    std::shared_ptr<KImageResourceCacheEntry> entry = loadEntry(path);
    cache[path] = entry;
    return entry;
}
} // namespace

KImageResource::KImageResource()
    : entry_() {
}

KImageResource::KImageResource(const std::string& path)
    : entry_() {
    loadFromFile(path);
}

void KImageResource::reset() {
    entry_.reset();
}

KImageResource KImageResource::load(const std::string& path) {
    KImageResource resource;
    resource.entry_ = getOrLoadEntry(path);
    return resource;
}

KImageResource KImageResource::fromFile(const std::string& path) {
    // Legacy factory spelling shares the same cache path as Load(); no duplicate decode occurs.
    return load(path);
}

bool KImageResource::loadFromFile(const std::string& path) {
    entry_ = getOrLoadEntry(path);
    return valid();
}

const std::string& KImageResource::path() const {
    if (!entry_) {
        return emptyString();
    }
    return entry_->path;
}

int KImageResource::width() const {
    if (!valid()) {
        return 0;
    }
    return entry_->width;
}

int KImageResource::height() const {
    if (!valid()) {
        return 0;
    }
    return entry_->height;
}

bool KImageResource::valid() const {
    return entry_ && entry_->sharedImage && entry_->error.empty();
}

const std::string& KImageResource::error() const {
    if (!entry_) {
        return emptyString();
    }
    return entry_->error;
}

Fl_Image* KImageResource::image() const {
    return valid() ? entry_->sharedImage : nullptr;
}

Fl_Shared_Image* KImageResource::sharedImage() const {
    return valid() ? entry_->sharedImage : nullptr;
}

bool KImageResource::cached(const std::string& path) {
    std::lock_guard<std::mutex> lock(cacheMutex());
    return imageCache().find(path) != imageCache().end();
}

void KImageResource::removeFromCache(const std::string& path) {
    std::lock_guard<std::mutex> lock(cacheMutex());
    imageCache().erase(path);
}

void KImageResource::clearCache() {
    std::lock_guard<std::mutex> lock(cacheMutex());
    imageCache().clear();
}
