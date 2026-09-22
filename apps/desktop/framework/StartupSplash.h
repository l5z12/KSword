#pragma once

// ============================================================
// StartupSplash.h
// Purpose:
// - Provides a globally reusable "Startup Splash Controller".
// - Unified external control interfaces for show/hide/progress.
// - Hide Win32/GDI+ details via PImpl to avoid polluting public header dependencies.
// ============================================================

#include <memory>
#include <string>

// KStartupSplash:
// - Manages the lifecycle of the native startup window;
// - Provides external show/hide/progress control;
// - For unified reuse by main and other modules during the startup phase.
class KStartupSplash final
{
public:
    // Constructor purpose:
    // - Create a placeholder for the implementation object.
    // - Do not create the window immediately; wait until show() is called.
    // Usage: Global objects are automatically constructed, or instances are created on demand by business logic.
    KStartupSplash();

    // Destructor purpose:
    // - Release the startup window and image resources;
    // - Ensure window handles are released before process exit.
    ~KStartupSplash();

    // Copy constructor and assignment operator are deleted to prevent multiple instances from holding the same native window resource.
    KStartupSplash(const KStartupSplash&) = delete;
    KStartupSplash& operator=(const KStartupSplash&) = delete;

    // show:
    // - initialize and display the startup window;
    // - Use the status text parsed by the caller in the current language for the first frame.
    // - Return false if the first call fails.
    // Invocation: Called at the earliest stage of the startup process.
    // Input parameter initialStatusText: the status text for the first frame (UTF-8); if empty, display the product name.
    // Returns: true = display successful; false = initialization or display failed.
    bool show(const std::string& initialStatusText = std::string());

    // hide:
    // - Hides and destroys the startup window;
    // - Can be called repeatedly; repeated calls are safe and side-effect free.
    // Call context: invoked after the main window's first frame or in the fallback timeout callback.
    void hide();

    // progress:
    // - Updates startup status text and progress percentage;
    // - If the window is not displayed or initialization fails, the function returns silently.
    // Usage: can be called multiple times after show succeeds.
    // Input parameter operationName: current operation name (UTF-8 text).
    // Input progressPercent: progress percentage (0~100, automatically clamped if out of bounds).
    void progress(const std::string& operationName, int progressPercent);

    // ready:
    // - Returns whether the current startup window is available.
    // - Used by the outer layer to determine whether to continue updating the progress.
    // Returns: true = window initialized and available; false = unavailable.
    bool ready() const;

private:
    // Impl forward declaration:
    // - Hide Win32/GDI+ members to avoid exposing platform details in the header file.
    class Impl;

    // m_impl:
    // - Implementation of the startup screen controller;
    // - Holds window handle, GDI+ resources, and layout parameters.
    std::unique_ptr<Impl> impl_;
};

// kSplash:
// - Global startup splash control object;
// - Exposed via Framework.h for direct invocation by the entire application.
extern KStartupSplash kSplash;
