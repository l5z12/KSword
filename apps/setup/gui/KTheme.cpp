#include "KTheme.h"

// KWidgets.h currently owns KImageView. Keep this include optional so theme
// refresh can still compile in partial checkouts where the image widget is absent.
#if __has_include("KWidgets.h")
#include "KWidgets.h"
#define KSWORD_THEME_HAS_KIMAGE_VIEW 1
#else
#define KSWORD_THEME_HAS_KIMAGE_VIEW 0
#endif

#include "Fl_Box.H"
#include "Fl_Choice.H"
#include "Fl_Group.H"
#include "Fl_Input_.H"
#include "Fl_Progress.H"
#include "Fl_Table.H"
#include "Fl_Text_Display.H"
#include "Fl_Valuator.H"
#include "fl_draw.H"

#include <algorithm>
#include <string>
#include <typeinfo>

namespace {
constexpr int kThemeFontSize = 12;

// makeColor converts RGB bytes into an FLTK color value.
Fl_Color makeColor(unsigned char red, unsigned char green, unsigned char blue) {
    return fl_rgb_color(red, green, blue);
}

// clampByte keeps computed channel values inside the 0..255 range.
unsigned char clampByte(int value) {
    if (value < 0) {
        return 0;
    }
    if (value > 255) {
        return 255;
    }
    return static_cast<unsigned char>(value);
}

// mixChannel interpolates one RGB channel toward a target channel.
unsigned char mixChannel(unsigned char source, unsigned char target, double ratio) {
    const double kRaw = static_cast<double>(source) + (static_cast<double>(target) - static_cast<double>(source)) * ratio;
    return clampByte(static_cast<int>(kRaw + 0.5));
}

// MixColor derives a lighter or darker accent color from the active primary color.
Fl_Color mixColor(unsigned char red, unsigned char green, unsigned char blue, unsigned char target, double ratio) {
    return makeColor(mixChannel(red, target, ratio), mixChannel(green, target, ratio), mixChannel(blue, target, ratio));
}

// applyCommonTypography sets shared K widget label typography.
void applyCommonTypography(Fl_Widget* widget, const KTheme& theme) {
    if (!widget) {
        return;
    }
    widget->labelfont(FL_HELVETICA);
    widget->labelsize(kThemeFontSize);
    widget->labelcolor(theme.text);
}

// applyInputPalette applies editable/read-only text field colors.
void applyInputPalette(Fl_Input_* input, const KTheme& theme) {
    if (!input) {
        return;
    }
    input->box(FL_FLAT_BOX);
    input->color(theme.controlBg);
    input->textcolor(theme.text);
    input->selection_color(theme.selection);
    input->labelfont(FL_HELVETICA);
    input->labelsize(kThemeFontSize);
    input->labelcolor(theme.text);
    input->textfont(FL_HELVETICA);
    input->textsize(kThemeFontSize);
}

// applyValuatorPalette applies slider/counter style colors.
void applyValuatorPalette(Fl_Valuator* valuator, const KTheme& theme) {
    if (!valuator) {
        return;
    }
    valuator->box(FL_FLAT_BOX);
    valuator->color(theme.controlBg);
    valuator->selection_color(theme.primary);
    valuator->labelcolor(theme.text);
    valuator->labelfont(FL_HELVETICA);
    valuator->labelsize(kThemeFontSize);
}

// isImageViewWidget detects KImageView by RTTI text when the concrete type is
// unavailable. Input is a widget pointer; output is true only for image views.
bool isImageViewWidget(Fl_Widget* widget) {
    if (!widget) {
        return false;
    }
    const std::string kRuntimeName = typeid(*widget).name();
    return kRuntimeName.find("KImageView") != std::string::npos;
}

#if KSWORD_THEME_HAS_KIMAGE_VIEW
// applyImageViewPalette writes KImageView's theme palette without triggering
// per-field redraws, so custom drawing uses the active colors while refreshAll
// remains responsible for the single top-level repaint.
void applyImageViewPalette(KImageView* imageView, const KTheme& theme) {
    if (!imageView) {
        return;
    }
    imageView->box(FL_FLAT_BOX);
    imageView->color(theme.controlBg);
    imageView->selection_color(theme.border);
    imageView->labelcolor(theme.mutedText);
    imageView->applyThemePalette(theme.controlBg, theme.border, theme.mutedText, true);
    imageView->labelfont(FL_HELVETICA);
    imageView->labelsize(kThemeFontSize);
}
#else
// applyImageViewPalette maps theme colors onto generic FLTK widget fields that
// KImageView can read without KTheme.cpp depending on KImage.h. Background uses
// color(), border uses selection_color(), and empty-state text uses labelcolor().
void ApplyImageViewPalette(Fl_Widget* widget, const KTheme& theme) {
    if (!widget) {
        return;
    }
    widget->box(FL_FLAT_BOX);
    widget->color(theme.controlBg);
    widget->selection_color(theme.border);
    widget->labelcolor(theme.mutedText);
    widget->labelfont(FL_HELVETICA);
    widget->labelsize(kThemeFontSize);
}
#endif

// applyTextDisplayPalette pins the colors used by FLTK text display redraws.
// Input is an existing display and active theme; processing writes palette and
// typography fields only, and there is no redraw side effect or return value.
void applyTextDisplayPalette(Fl_Text_Display* textDisplay, const KTheme& theme) {
    if (!textDisplay) {
        return;
    }

    // Text displays repaint internally on cursor, selection, and scrollbar
    // changes. Stable background/text/selection slots prevent those partial
    // paints from falling back to stale FLTK defaults.
    textDisplay->box(FL_FLAT_BOX);
    textDisplay->color(theme.controlBg);
    textDisplay->textcolor(theme.text);
    textDisplay->selection_color(theme.selection);
    textDisplay->labelfont(FL_HELVETICA);
    textDisplay->labelsize(kThemeFontSize);
    textDisplay->labelcolor(theme.text);
    textDisplay->textfont(FL_HELVETICA);
    textDisplay->textsize(kThemeFontSize);
}
}

KThemeManager& KThemeManager::instance() {
    static KThemeManager manager;
    return manager;
}

KThemeManager::KThemeManager()
    : mode_(KThemeMode::kLight),
      primaryR_(0),
      primaryG_(100),
      primaryB_(251),
      theme_(),
      windows_() {
    rebuildTheme();
}

const KTheme& KThemeManager::theme() const {
    return theme_;
}

KThemeMode KThemeManager::mode() const {
    return mode_;
}

void KThemeManager::setMode(KThemeMode mode) {
    if (mode_ == mode) {
        return;
    }
    mode_ = mode;
    rebuildTheme();
    refreshAll();
}

void KThemeManager::toggleMode() {
    setMode(mode_ == KThemeMode::kLight ? KThemeMode::kDark : KThemeMode::kLight);
}

void KThemeManager::setPrimaryColor(unsigned char red, unsigned char green, unsigned char blue) {
    if (primaryR_ == red && primaryG_ == green && primaryB_ == blue) {
        return;
    }
    primaryR_ = red;
    primaryG_ = green;
    primaryB_ = blue;
    rebuildTheme();
    refreshAll();
}

void KThemeManager::applyTo(Fl_Widget* widget) {
    if (!widget) {
        return;
    }

    // ApplyTo deliberately changes style state only. Redraw is controlled by
    // setWindowStyle()/refreshAll() at the top-level window so ordinary focus,
    // selection, or caller-side ApplyTo() paths cannot create a full widget-tree
    // repaint that races with FLTK child-only damage.
    const KTheme& t = theme_;
    applyCommonTypography(widget, t);

#if KSWORD_THEME_HAS_KIMAGE_VIEW
    if (auto* imageView = dynamic_cast<KImageView*>(widget)) {
        // Direct KImageView handling keeps its custom draw colors synchronized
        // with KTheme rather than relying only on generic FLTK color slots.
        applyImageViewPalette(imageView, t);
    }
#else
    if (IsImageViewWidget(widget)) {
        // KImageView is handled before generic groups/boxes so its background,
        // border, and empty-state text stay aligned with the active KTheme.
        ApplyImageViewPalette(widget, t);
    }
#endif
    else if (auto* win = dynamic_cast<Fl_Window*>(widget)) {
        win->color(t.windowBg);
        win->labelcolor(t.text);
    }
    else if (auto* input = dynamic_cast<Fl_Input_*>(widget)) {
        applyInputPalette(input, t);
    }
    else if (auto* textDisplay = dynamic_cast<Fl_Text_Display*>(widget)) {
        applyTextDisplayPalette(textDisplay, t);
    }
    else if (auto* table = dynamic_cast<Fl_Table*>(widget)) {
        // KTable/legacy FlatTable draw their own grid, cells, and dead-zone
        // background. Keep the original no-box table contract during theme
        // refreshes so selection redraws do not leave uncovered regions.
        table->box(FL_NO_BOX);
        table->color(t.windowBg);
        table->selection_color(t.selection);
    }
    else if (auto* progress = dynamic_cast<Fl_Progress*>(widget)) {
        progress->box(FL_FLAT_BOX);
        progress->color(t.controlBg);
        progress->selection_color(t.primary);
    }
    else if (auto* choice = dynamic_cast<Fl_Choice*>(widget)) {
        choice->box(FL_FLAT_BOX);
        choice->color(t.controlBg);
        choice->textcolor(t.text);
        choice->selection_color(t.selection);
    }
    else if (auto* valuator = dynamic_cast<Fl_Valuator*>(widget)) {
        applyValuatorPalette(valuator, t);
    }
    else if (auto* group = dynamic_cast<Fl_Group*>(widget)) {
        // Generic FLTK groups should not repaint an opaque rectangle on child
        // focus/selection damage. KPanel/KCard/KToolbar draw their own shell,
        // while plain groups are safest as transparent layout containers.
        group->box(FL_NO_BOX);
        group->color(t.panelBg);
        group->selection_color(t.selection);
    }
    else if (auto* box = dynamic_cast<Fl_Box*>(widget)) {
        box->box(FL_FLAT_BOX);
        box->color(t.panelBg);
    }
    else {
        widget->color(t.panelBg);
    }

    if (auto* group = dynamic_cast<Fl_Group*>(widget)) {
        for (int i = 0; i < group->children(); ++i) {
            applyTo(group->child(i));
        }
    }
}

void KThemeManager::registerWindow(Fl_Window* window) {
    if (!window || isRegistered(window)) {
        return;
    }
    windows_.push_back(window);
}

void KThemeManager::unregisterWindow(Fl_Window* window) {
    windows_.erase(std::remove(windows_.begin(), windows_.end(), window), windows_.end());
}

void KThemeManager::refreshAll() {
    windows_.erase(std::remove(windows_.begin(), windows_.end(), static_cast<Fl_Window*>(nullptr)), windows_.end());
    for (Fl_Window* window : windows_) {
        // Theme changes are true global visual changes, so repaint each
        // top-level once after the recursive style pass instead of redrawing
        // every child independently.
        applyTo(window);
        window->redraw();
    }
}

void KThemeManager::rebuildTheme() {
    theme_.primary = makeColor(primaryR_, primaryG_, primaryB_);
    theme_.primaryLight = mixColor(primaryR_, primaryG_, primaryB_, 255, 0.18);
    theme_.primaryDark = mixColor(primaryR_, primaryG_, primaryB_, 0, 0.20);
    theme_.selection = mixColor(primaryR_, primaryG_, primaryB_, 255, mode_ == KThemeMode::kLight ? 0.72 : 0.25);
    theme_.danger = makeColor(220, 53, 69);
    theme_.warning = makeColor(245, 158, 11);
    theme_.success = makeColor(34, 197, 94);

    if (mode_ == KThemeMode::kLight) {
        theme_.windowBg = makeColor(246, 247, 249);
        theme_.panelBg = makeColor(255, 255, 255);
        theme_.controlBg = makeColor(255, 255, 255);
        theme_.controlAltBg = makeColor(242, 244, 247);
        theme_.text = makeColor(31, 35, 40);
        theme_.mutedText = makeColor(96, 103, 112);
        theme_.border = makeColor(210, 214, 220);
        theme_.hover = makeColor(235, 240, 248);
        theme_.pressed = makeColor(221, 228, 238);
    }
    else {
        theme_.windowBg = makeColor(24, 26, 31);
        theme_.panelBg = makeColor(31, 34, 40);
        theme_.controlBg = makeColor(38, 42, 50);
        theme_.controlAltBg = makeColor(45, 50, 60);
        theme_.text = makeColor(232, 236, 243);
        theme_.mutedText = makeColor(157, 166, 179);
        theme_.border = makeColor(68, 75, 88);
        theme_.hover = makeColor(49, 55, 67);
        theme_.pressed = makeColor(58, 65, 78);
    }
}

bool KThemeManager::isRegistered(Fl_Window* window) const {
    return std::find(windows_.begin(), windows_.end(), window) != windows_.end();
}

void initFlatThemeGlobal() {
    Fl::set_font(FL_HELVETICA, "Microsoft YaHei");
    Fl::set_font(FL_HELVETICA_BOLD, "Microsoft YaHei");
    fl_font(FL_HELVETICA, kThemeFontSize);
    KThemeManager::instance().refreshAll();
}

void setWindowStyle(Fl_Window* win) {
    if (!win) {
        return;
    }
    KThemeManager::instance().registerWindow(win);
    KThemeManager::instance().applyTo(win);
    win->redraw();
}
