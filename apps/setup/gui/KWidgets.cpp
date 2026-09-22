#include "KWidgets.h"

#include "KPaintDebug.h"

#include "Fl_Shared_Image.H"
#include "fl_draw.H"

#include <algorithm>
#include <cmath>

namespace {
constexpr int kWidgetFontSize = 12;

// applyWidgetTextStyle gives every K widget consistent label typography.
void applyWidgetTextStyle(Fl_Widget* widget) {
    if (!widget) {
        return;
    }
    const KTheme& theme = KThemeManager::instance().theme();
    widget->labelfont(FL_HELVETICA);
    widget->labelsize(kWidgetFontSize);
    widget->labelcolor(theme.text);
}

// applyInputStyle gives editable text widgets the current theme colors.
void applyInputStyle(Fl_Input_* input) {
    if (!input) {
        return;
    }
    const KTheme& theme = KThemeManager::instance().theme();
    input->box(FL_FLAT_BOX);
    input->color(theme.controlBg);
    input->textcolor(theme.text);
    input->selection_color(theme.selection);
    input->labelfont(FL_HELVETICA);
    input->labelsize(kWidgetFontSize);
    input->labelcolor(theme.text);
    input->textfont(FL_HELVETICA);
    input->textsize(kWidgetFontSize);
}

// applyValuatorStyle gives sliders/counters a shared flat baseline.
void applyValuatorStyle(Fl_Valuator* valuator) {
    if (!valuator) {
        return;
    }
    const KTheme& theme = KThemeManager::instance().theme();
    valuator->box(FL_FLAT_BOX);
    valuator->color(theme.controlBg);
    valuator->selection_color(theme.primary);
    valuator->labelcolor(theme.text);
    valuator->labelfont(FL_HELVETICA);
    valuator->labelsize(kWidgetFontSize);
}

// drawSquareBorder paints one-pixel square borders for the flat visual language.
void drawSquareBorder(int x, int y, int w, int h, Fl_Color color) {
    fl_color(color);
    fl_rect(x, y, w, h);
}

// drawWidgetLabel renders a label safely inside the provided rectangle.
void drawWidgetLabel(const char* label, int x, int y, int w, int h, Fl_Color color, Fl_Align align) {
    if (!label || label[0] == '\0') {
        return;
    }
    fl_color(color);
    fl_font(FL_HELVETICA, kWidgetFontSize);
    fl_draw(label, x, y, w, h, align);
}

// clampPositiveSize keeps computed drawing rectangles valid for FLTK image calls.
int clampPositiveSize(double value) {
    if (value < 1.0) {
        return 1;
    }
    return static_cast<int>(std::floor(value + 0.5));
}

// hasOnlyChildDamage detects FLTK's child-only invalidation state for groups.
// Input is a live widget pointer; output is true only when the parent surface
// itself is not dirty and FLTK only needs one or more children updated.
bool hasOnlyChildDamage(const Fl_Widget* widget) {
    if (!widget) {
        return false;
    }

    // Custom Fl_Group draw() implementations must not fill their whole
    // rectangle when the damage contains only child-invalidations. FLTK can add
    // widget-specific bits to FL_DAMAGE_CHILD for caret/selection/scroll paths,
    // so checking exact equality misses the real focus-click cases reported by
    // the user. Full expose/all damage still repaints the parent shell.
    const uchar kDamage = widget->damage();
    return (kDamage & FL_DAMAGE_CHILD) != 0 &&
        (kDamage & (FL_DAMAGE_ALL | FL_DAMAGE_EXPOSE)) == 0;
}
}

KButton::KButton(int x, int y, int w, int h, const char* label, KButtonType type)
    : Fl_Button(x, y, w, h, label), type_(type), hover_(false), pressed_(false) {
    box(FL_FLAT_BOX);
    when(FL_WHEN_RELEASE);
    applyWidgetTextStyle(this);
}

void KButton::draw() {
    const KTheme& theme = KThemeManager::instance().theme();
    Fl_Color bg = theme.primary;
    Fl_Color fg = FL_WHITE;
    Fl_Color border = theme.primaryDark;

    if (type_ == kKbuttonLight) {
        bg = theme.controlBg;
        fg = theme.primary;
        border = theme.primary;
        if (hover_) {
            bg = theme.hover;
        }
        if (pressed_ || value()) {
            bg = theme.pressed;
            fg = theme.text;
        }
    }
    else if (type_ == kKbuttonSimple) {
        bg = theme.controlBg;
        fg = theme.text;
        border = theme.border;
        if (hover_) {
            bg = theme.hover;
        }
        if (pressed_ || value()) {
            bg = theme.pressed;
        }
    }
    else {
        bg = theme.primary;
        fg = FL_WHITE;
        border = theme.primaryDark;
        if (hover_) {
            bg = theme.primaryLight;
        }
        if (pressed_ || value()) {
            bg = theme.primaryDark;
        }
        if (!active()) {
            bg = theme.controlAltBg;
            fg = theme.mutedText;
            border = theme.border;
        }
    }

    fl_push_clip(x(), y(), w(), h());
    fl_color(bg);
    fl_rectf(x(), y(), w(), h());
    drawSquareBorder(x(), y(), w(), h(), border);
    drawWidgetLabel(label(), x() + 8, y(), w() - 16, h(), fg, FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    fl_pop_clip();
}

int KButton::handle(int event) {
    switch (event) {
    case FL_ENTER:
        hover_ = true;
        redraw();
        return 1;
    case FL_LEAVE:
        hover_ = false;
        pressed_ = false;
        redraw();
        return 1;
    case FL_PUSH:
        pressed_ = true;
        redraw();
        break;
    case FL_RELEASE:
        pressed_ = false;
        redraw();
        break;
    default:
        break;
    }
    return Fl_Button::handle(event);
}

void KButton::setButtonType(KButtonType type) {
    type_ = type;
    redraw();
}

KButtonType KButton::buttonType() const {
    return type_;
}

KInput::KInput(int x, int y, int w, int h, const char* label)
    : Fl_Input(x, y, w, h, label) {
    applyInputStyle(this);
}

KText::KText(int x, int y, int w, int h, const char* label)
    : Fl_Box(x, y, w, h, label) {
    box(FL_FLAT_BOX);
    align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_CENTER);
    applyWidgetTextStyle(this);
}

KPanel::KPanel(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label) {
    box(FL_FLAT_BOX);
    resizable(this);
    applyWidgetTextStyle(this);
}

void KPanel::draw() {
    kPaintDebugTraceDraw("KPanel", this);
    if (hasOnlyChildDamage(this)) {
        // Child-only damage is the key focus/click path for inputs, text
        // displays, and tables. Delegate to FLTK child drawing without
        // touching the panel pixels behind unaffected sibling controls.
        draw_children();
        return;
    }

    const KTheme& theme = KThemeManager::instance().theme();
    fl_push_clip(x(), y(), w(), h());
    fl_color(color() == FL_BACKGROUND_COLOR ? theme.panelBg : color());
    fl_rectf(x(), y(), w(), h());
    drawSquareBorder(x(), y(), w(), h(), theme.border);
    if (label() && label()[0] != '\0') {
        drawWidgetLabel(label(), x() + 8, y(), w() - 16, 22, theme.mutedText, FL_ALIGN_LEFT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    }
    fl_pop_clip();
    draw_children();
}

KCard::KCard(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label),
    title_(label ? label : ""),
    subtitle_() {
    // Cards follow KPanel's container behavior: callers may add child widgets after construction.
    box(FL_FLAT_BOX);
    resizable(this);
    applyWidgetTextStyle(this);
}

void KCard::setTitle(const char* title) {
    // Store an owned copy so callers can pass stack or temporary strings safely.
    title_ = title ? title : "";
    redraw();
}

const std::string& KCard::title() const {
    // The returned reference stays valid until the next title update or card destruction.
    return title_;
}

void KCard::setSubtitle(const char* subtitle) {
    // A null subtitle clears the optional muted secondary line.
    subtitle_ = subtitle ? subtitle : "";
    redraw();
}

const std::string& KCard::subtitle() const {
    // The returned reference stays valid until the next subtitle update or card destruction.
    return subtitle_;
}

void KCard::draw() {
    kPaintDebugTraceDraw("KCard", this);
    if (hasOnlyChildDamage(this)) {
        // Do not repaint the card shell for child focus/caret/selection
        // changes; otherwise siblings can disappear until a full redraw.
        draw_children();
        return;
    }

    const KTheme& theme = KThemeManager::instance().theme();
    const bool kHasTitle = !title_.empty();
    const bool kHasSubtitle = !subtitle_.empty();

    // The card keeps the existing square visual language: filled panel, one-pixel border, no radius.
    fl_push_clip(x(), y(), w(), h());
    fl_color(color() == FL_BACKGROUND_COLOR ? theme.panelBg : color());
    fl_rectf(x(), y(), w(), h());
    drawSquareBorder(x(), y(), w(), h(), theme.border);

    // Header text is optional; children remain responsible for their own layout below it.
    if (kHasTitle) {
        drawWidgetLabel(title_.c_str(), x() + 12, y() + 7, std::max(0, w() - 24), 18, theme.text, FL_ALIGN_LEFT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    }
    if (kHasSubtitle) {
        drawWidgetLabel(subtitle_.c_str(), x() + 12, y() + 27, std::max(0, w() - 24), 16, theme.mutedText, FL_ALIGN_LEFT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    }
    if (kHasTitle || kHasSubtitle) {
        fl_color(theme.border);
        fl_line(x() + 1, y() + 49, x() + w() - 2, y() + 49);
    }
    fl_pop_clip();

    // Group children are drawn after the card shell so embedded controls remain visible.
    draw_children();
}

KToolbar::KToolbar(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label) {
    // Toolbars are ordinary FLTK groups styled as a compact command strip.
    box(FL_FLAT_BOX);
    resizable(nullptr);
    applyWidgetTextStyle(this);
}

void KToolbar::draw() {
    kPaintDebugTraceDraw("KToolbar", this);
    if (hasOnlyChildDamage(this)) {
        // Toolbar children such as buttons and inputs handle their own
        // focused/pressed state paints. Avoid clearing the toolbar surface
        // before FLTK updates only the damaged child.
        draw_children();
        return;
    }

    const KTheme& theme = KThemeManager::instance().theme();

    // Fill first, then draw a square border so child widgets can align to the one-pixel grid.
    fl_push_clip(x(), y(), w(), h());
    fl_color(color() == FL_BACKGROUND_COLOR ? theme.controlAltBg : color());
    fl_rectf(x(), y(), w(), h());
    drawSquareBorder(x(), y(), w(), h(), theme.border);

    // Optional label is intended for compact section names such as "Edit" or "View".
    if (label() && label()[0] != '\0') {
        drawWidgetLabel(label(), x() + 8, y(), std::max(0, w() - 16), h(), theme.mutedText, FL_ALIGN_LEFT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    }
    fl_pop_clip();

    // Toolbar children keep their own event and state behavior.
    draw_children();
}

KStatusBar::KStatusBar(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label),
    text_(label ? label : ""),
    rightText_() {
    // Status bars may host small child indicators, while text is drawn by this wrapper.
    box(FL_FLAT_BOX);
    resizable(nullptr);
    applyWidgetTextStyle(this);
}

void KStatusBar::setText(const char* text) {
    // The left status region owns its content and accepts null as an empty message.
    text_ = text ? text : "";
    redraw();
}

const std::string& KStatusBar::text() const {
    // Returning a reference avoids allocation and mirrors other lightweight KWidget getters.
    return text_;
}

void KStatusBar::setRightText(const char* text) {
    // The right status region is optional and commonly used for mode or position text.
    rightText_ = text ? text : "";
    redraw();
}

const std::string& KStatusBar::rightText() const {
    // The returned text is owned by the status bar and remains stable until reassigned.
    return rightText_;
}

void KStatusBar::draw() {
    kPaintDebugTraceDraw("KStatusBar", this);
    if (hasOnlyChildDamage(this)) {
        // Status bars can host child indicators; child-only damage must not
        // clear the whole strip because FLTK may skip repainting siblings.
        draw_children();
        return;
    }

    const KTheme& theme = KThemeManager::instance().theme();

    // Status bars use a top separator more prominently than a full boxed card frame.
    fl_push_clip(x(), y(), w(), h());
    fl_color(color() == FL_BACKGROUND_COLOR ? theme.panelBg : color());
    fl_rectf(x(), y(), w(), h());
    fl_color(theme.border);
    fl_line(x(), y(), x() + w(), y());

    // Left text consumes the flexible middle area; right text is independently right aligned.
    if (!text_.empty()) {
        drawWidgetLabel(text_.c_str(), x() + 8, y(), std::max(0, w() - 16), h(), theme.mutedText, FL_ALIGN_LEFT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    }
    if (!rightText_.empty()) {
        drawWidgetLabel(rightText_.c_str(), x() + 8, y(), std::max(0, w() - 16), h(), theme.mutedText, FL_ALIGN_RIGHT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    }
    fl_pop_clip();

    // Child widgets, if any, are painted over the status surface for badges or tiny controls.
    draw_children();
}

KBadge::KBadge(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label),
    text_(label ? label : ""),
    accentColor_(KThemeManager::instance().theme().primary) {
    // Badges are leaf widgets: they draw a short state/count label and do not handle input.
    box(FL_FLAT_BOX);
    applyWidgetTextStyle(this);
}

void KBadge::setText(const char* text) {
    // Text is copied so callers do not need to keep the input buffer alive.
    text_ = text ? text : "";
    redraw();
}

const std::string& KBadge::text() const {
    // The returned reference is valid until setText(), setCount(), or destruction.
    return text_;
}

void KBadge::setCount(int count) {
    // Negative counts model the common "hidden/empty badge" state without resizing the widget.
    text_ = count < 0 ? "" : std::to_string(count);
    redraw();
}

void KBadge::setAccentColor(Fl_Color color) {
    // Store explicit accent color; draw() chooses disabled styling separately from this value.
    accentColor_ = color;
    redraw();
}

Fl_Color KBadge::accentColor() const {
    // Returns the active fill color requested by callers.
    return accentColor_;
}

void KBadge::draw() {
    const KTheme& theme = KThemeManager::instance().theme();
    const bool kEmpty = text_.empty();
    const Fl_Color kBg = !active() ? theme.controlAltBg : (kEmpty ? theme.controlBg : accentColor_);
    const Fl_Color kFg = !active() ? theme.mutedText : (kEmpty ? theme.mutedText : FL_WHITE);
    const Fl_Color kBorder = kEmpty ? theme.border : accentColor_;

    // Badges are intentionally square and flat, matching KButton and KToggleButton geometry.
    fl_push_clip(x(), y(), w(), h());
    fl_color(kBg);
    fl_rectf(x(), y(), w(), h());
    drawSquareBorder(x(), y(), w(), h(), kBorder);

    // Empty text leaves a visible placeholder frame but draws no glyphs.
    if (!kEmpty) {
        drawWidgetLabel(text_.c_str(), x() + 4, y(), std::max(0, w() - 8), h(), kFg, FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    }
    fl_pop_clip();
}

KSeparator::KSeparator(int x, int y, int w, int h, KSeparatorOrientation orientation)
    : Fl_Widget(x, y, w, h),
    orientation_(orientation) {
    // Separators are non-interactive paint-only widgets.
    box(FL_NO_BOX);
}

void KSeparator::setOrientation(KSeparatorOrientation orientation) {
    // Orientation affects only drawing; geometry remains under caller layout control.
    orientation_ = orientation;
    redraw();
}

KSeparatorOrientation KSeparator::orientation() const {
    // Returns the current line direction without side effects.
    return orientation_;
}

void KSeparator::draw() {
    const KTheme& theme = KThemeManager::instance().theme();

    // Draw a one-pixel line centered in the provided allocation for predictable spacing.
    fl_push_clip(x(), y(), w(), h());
    fl_color(theme.border);
    if (orientation_ == KSeparatorOrientation::kVertical) {
        const int kLineX = x() + w() / 2;
        fl_line(kLineX, y(), kLineX, y() + h());
    }
    else {
        const int kLineY = y() + h() / 2;
        fl_line(x(), kLineY, x() + w(), kLineY);
    }
    fl_pop_clip();
}

KCheckBox::KCheckBox(int x, int y, int w, int h, const char* label)
    : Fl_Check_Button(x, y, w, h, label) {
    box(FL_FLAT_BOX);
    when(FL_WHEN_CHANGED | FL_WHEN_RELEASE);
    applyWidgetTextStyle(this);
}

KRadioButton::KRadioButton(int x, int y, int w, int h, const char* label)
    : Fl_Round_Button(x, y, w, h, label) {
    box(FL_FLAT_BOX);
    applyWidgetTextStyle(this);
}

KToggleButton::KToggleButton(int x, int y, int w, int h, const char* label)
    : Fl_Toggle_Button(x, y, w, h, label) {
    box(FL_FLAT_BOX);
    when(FL_WHEN_CHANGED | FL_WHEN_RELEASE);
    applyWidgetTextStyle(this);
}

void KToggleButton::draw() {
    const KTheme& theme = KThemeManager::instance().theme();
    const bool kSelected = value() != 0;
    const Fl_Color kBg = kSelected ? theme.primary : theme.controlBg;
    const Fl_Color kFg = kSelected ? FL_WHITE : theme.text;
    const Fl_Color kBorder = kSelected ? theme.primaryDark : theme.border;
    fl_push_clip(x(), y(), w(), h());
    fl_color(kBg);
    fl_rectf(x(), y(), w(), h());
    drawSquareBorder(x(), y(), w(), h(), kBorder);
    drawWidgetLabel(label(), x() + 8, y(), w() - 16, h(), kFg, FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    fl_pop_clip();
}

KLightButton::KLightButton(int x, int y, int w, int h, const char* label)
    : Fl_Light_Button(x, y, w, h, label) {
    box(FL_FLAT_BOX);
    when(FL_WHEN_CHANGED | FL_WHEN_RELEASE);
    applyWidgetTextStyle(this);
}

KSlider::KSlider(int x, int y, int w, int h)
    : Fl_Slider(x, y, w, h) {
    type(FL_HORIZONTAL);
    slider(FL_FLAT_BOX);
    applyValuatorStyle(this);
}

KTextBox::KTextBox(int x, int y, int w, int h, const char* label)
    : Fl_Multiline_Input(x, y, w, h, label) {
    applyInputStyle(this);
}

void KTextBox::clearCurrentLine() {
    const char* raw = value();
    if (!raw) {
        return;
    }
    std::string text = raw;
    int pos = insert_position();
    pos = std::max(0, std::min(pos, static_cast<int>(text.size())));
    std::size_t start = text.rfind('\n', pos > 0 ? static_cast<std::size_t>(pos - 1) : 0);
    start = (start == std::string::npos) ? 0 : start + 1;
    std::size_t end = text.find('\n', static_cast<std::size_t>(pos));
    end = (end == std::string::npos) ? text.size() : end;
    text.erase(start, end - start);
    value(text.c_str());
    insert_position(static_cast<int>(start));
}

void KTextBox::clearPreviousLine() {
    const char* raw = value();
    if (!raw) {
        return;
    }
    std::string text = raw;
    int pos = insert_position();
    pos = std::max(0, std::min(pos, static_cast<int>(text.size())));
    std::size_t currentStart = text.rfind('\n', pos > 0 ? static_cast<std::size_t>(pos - 1) : 0);
    if (currentStart == std::string::npos || currentStart == 0) {
        return;
    }
    std::size_t prevEnd = currentStart;
    std::size_t prevStart = text.rfind('\n', prevEnd - 1);
    prevStart = (prevStart == std::string::npos) ? 0 : prevStart + 1;
    text.erase(prevStart, prevEnd - prevStart);
    value(text.c_str());
    insert_position(static_cast<int>(prevStart));
}

void KTextBox::clearAll() {
    value("");
    insert_position(0);
}

void KTextBox::appendText(const char* text) {
    if (!text) {
        return;
    }
    std::string content = value() ? value() : "";
    content += text;
    value(content.c_str());
    insert_position(static_cast<int>(content.size()));
}

KTextDisplay::KTextDisplay(int x, int y, int w, int h, const char* label)
    : Fl_Text_Display(x, y, w, h, label), buffer_() {
    const KTheme& theme = KThemeManager::instance().theme();

    // The display owns a persistent buffer; FLTK keeps the lifecycle native
    // while the K wrapper only pins stable colors for focus, selection, and
    // scroll redraws.
    buffer(buffer_);
    box(FL_FLAT_BOX);
    color(theme.controlBg);
    textcolor(theme.text);
    selection_color(theme.selection);
    textfont(FL_HELVETICA);
    textsize(kWidgetFontSize);
    applyWidgetTextStyle(this);
}

void KTextDisplay::setText(const char* text) {
    buffer_.text(text ? text : "");
}

KImageView::KImageView(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label),
    image_(nullptr),
    sharedImage_(nullptr),
    displayMode_(KImageViewMode::kFitContain),
    backgroundColor_(KThemeManager::instance().theme().controlBg),
    borderColor_(KThemeManager::instance().theme().border),
    borderVisible_(true),
    loadFailed_(false),
    imagePath_(),
    resource_(),
    loadErrorText_(),
    emptyText_("No image"),
    loadFailedText_("Image load failed") {
    box(FL_FLAT_BOX);
    applyWidgetTextStyle(this);
    color(backgroundColor_);
    selection_color(borderColor_);
    labelcolor(KThemeManager::instance().theme().mutedText);
}

KImageView::~KImageView() {
    // Only images loaded by setImagePath() are owned through FLTK shared-image refcounts.
    releaseSharedImage();
    resource_.reset();
    image_ = nullptr;
}

bool KImageView::setImagePath(const char* path) {
    const std::string kRequestedPath = path ? path : "";

    // A null or empty path clears the view without entering the failed-load state.
    if (kRequestedPath.empty()) {
        releaseSharedImage();
        resource_.reset();
        image_ = nullptr;
        imagePath_.clear();
        loadFailed_ = false;
        loadErrorText_.clear();
        redraw();
        return false;
    }

    // Path loading is routed through KImageResource so repeated views share one decoded image.
    const KImageResource kLoaded = KImageResource::load(kRequestedPath);
    return setResource(kLoaded);
}

bool KImageView::setResource(const KImageResource& resource) {
    // Resource-backed images are owned by KImageResource cache entries, not by shared_image_.
    releaseSharedImage();
    resource_ = resource;
    imagePath_ = resource_.path();
    image_ = resource_.image();
    loadFailed_ = !resource_.valid() && (!resource_.path().empty() || !resource_.error().empty());
    loadErrorText_ = loadFailed_ ? resource_.error() : "";
    redraw();
    return resource_.valid();
}

void KImageView::setImage(Fl_Image* image) {
    // External images remain caller-owned; this view only stores and draws the pointer.
    releaseSharedImage();
    resource_.reset();
    image_ = image;
    imagePath_.clear();
    loadFailed_ = false;
    loadErrorText_.clear();
    redraw();
}

Fl_Image* KImageView::currentImage() const {
    return image_;
}

Fl_Image* KImageView::image() const {
    // Compatibility accessor mirrors currentImage(); callers must not delete the pointer.
    return currentImage();
}

const KImageResource& KImageView::resource() const {
    return resource_;
}

void KImageView::setDisplayMode(KImageViewMode mode) {
    displayMode_ = mode;
    redraw();
}

KImageViewMode KImageView::displayMode() const {
    return displayMode_;
}

void KImageView::setFitMode(KImageFitMode mode) {
    // Compatibility input maps optional KImage naming onto this widget's display strategy.
    switch (mode) {
    case KImageFitMode::kOriginal:
        setDisplayMode(KImageViewMode::kOriginal);
        break;
    case KImageFitMode::kCover:
        setDisplayMode(KImageViewMode::kFitCover);
        break;
    case KImageFitMode::kStretch:
        setDisplayMode(KImageViewMode::kStretch);
        break;
    case KImageFitMode::kContain:
    default:
        setDisplayMode(KImageViewMode::kFitContain);
        break;
    }
}

void KImageView::setBackgroundColor(Fl_Color color) {
    // Store explicit color and mirror it to Fl_Widget::color() so theme refreshes use one channel.
    if (backgroundColor_ == color && Fl_Widget::color() == color) {
        return;
    }
    backgroundColor_ = color;
    Fl_Widget::color(color);
    redraw();
}

Fl_Color KImageView::backgroundColor() const {
    // Return the color channel actually consumed by draw(); theme refreshes may update it directly.
    return color();
}

void KImageView::setBorderColor(Fl_Color color) {
    // Store explicit color and mirror it to selection_color(), the palette slot used by draw().
    if (borderColor_ == color && selection_color() == color) {
        return;
    }
    borderColor_ = color;
    selection_color(color);
    redraw();
}

Fl_Color KImageView::borderColor() const {
    // Return the border channel actually consumed by draw(); theme refreshes may update it directly.
    return selection_color();
}

void KImageView::setBorderVisible(bool visible) {
    if (borderVisible_ == visible) {
        return;
    }
    borderVisible_ = visible;
    redraw();
}

bool KImageView::borderVisible() const {
    return borderVisible_;
}

void KImageView::applyThemePalette(Fl_Color background, Fl_Color border, Fl_Color emptyText, bool borderVisible) {
    // This method intentionally has no redraw side effect. KThemeManager
    // batches style writes across the widget tree and then invalidates the
    // owning top-level window once, avoiding per-widget repaint storms.
    backgroundColor_ = background;
    borderColor_ = border;
    borderVisible_ = borderVisible;

    // Mirror private paint fields into the public FLTK color slots consumed by
    // draw() and compatibility callers. No value is returned.
    Fl_Widget::color(background);
    selection_color(border);
    labelcolor(emptyText);
}

void KImageView::setEmptyText(const char* text) {
    emptyText_ = text ? text : "";
    redraw();
}

void KImageView::setEmptyText(const std::string& text) {
    // Snake_case wrapper copies caller text into the empty-state storage.
    setEmptyText(text.c_str());
}

const std::string& KImageView::emptyText() const {
    return emptyText_;
}

void KImageView::setLoadFailedText(const char* text) {
    loadFailedText_ = text ? text : "";
    redraw();
}

const std::string& KImageView::loadFailedText() const {
    return loadFailedText_;
}

void KImageView::draw() {
    kPaintDebugTraceDraw("KImageView", this);

    const int kInset = borderVisible_ ? 1 : 0;
    const int kContentX = x() + kInset;
    const int kContentY = y() + kInset;
    const int kContentW = std::max(0, w() - kInset * 2);
    const int kContentH = std::max(0, h() - kInset * 2);

    // Drawing is clipped to the widget so cover/crop and invalid sizes stay safe.
    fl_push_clip(x(), y(), w(), h());
    fl_color(color());
    fl_rectf(x(), y(), w(), h());

    if (image_ && image_->w() > 0 && image_->h() > 0) {
        drawImageInContent(kContentX, kContentY, kContentW, kContentH);
    }
    else if (loadFailed_) {
        // Resource load failures carry detail text; direct failures fall back to the configured label.
        const std::string& failureText = loadErrorText_.empty() ? loadFailedText_ : loadErrorText_;
        drawStateText(failureText.c_str(), KThemeManager::instance().theme().danger);
    }
    else {
        drawStateText(emptyText_.c_str(), labelcolor());
    }

    if (borderVisible_) {
        drawSquareBorder(x(), y(), w(), h(), selection_color());
    }
    fl_pop_clip();
}

void KImageView::resize(int x, int y, int w, int h) {
    Fl_Widget::resize(x, y, w, h);
    redraw();
}

void KImageView::releaseSharedImage() {
    if (sharedImage_) {
        sharedImage_->release();
        sharedImage_ = nullptr;
    }
}

void KImageView::drawStateText(const char* text, Fl_Color color) {
    if (!text || text[0] == '\0') {
        return;
    }
    drawWidgetLabel(text, x() + 6, y(), std::max(0, w() - 12), h(), color, FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
}

void KImageView::drawImageInContent(int contentX, int contentY, int contentW, int contentH) {
    if (!image_ || contentW <= 0 || contentH <= 0) {
        return;
    }

    const int kSourceW = image_->w();
    const int kSourceH = image_->h();
    if (kSourceW <= 0 || kSourceH <= 0) {
        return;
    }

    int drawX = contentX;
    int drawY = contentY;
    int drawW = kSourceW;
    int drawH = kSourceH;
    if (displayMode_ == KImageViewMode::kStretch) {
        drawW = contentW;
        drawH = contentH;
    }
    else if (displayMode_ == KImageViewMode::kFitContain) {
        const double kScale = std::min(static_cast<double>(contentW) / kSourceW, static_cast<double>(contentH) / kSourceH);
        drawW = clampPositiveSize(kSourceW * kScale);
        drawH = clampPositiveSize(kSourceH * kScale);
        drawX = contentX + (contentW - drawW) / 2;
        drawY = contentY + (contentH - drawH) / 2;
    }
    else if (displayMode_ == KImageViewMode::kFitCover) {
        const double kScale = std::max(static_cast<double>(contentW) / kSourceW, static_cast<double>(contentH) / kSourceH);
        drawW = clampPositiveSize(kSourceW * kScale);
        drawH = clampPositiveSize(kSourceH * kScale);
        drawX = contentX + (contentW - drawW) / 2;
        drawY = contentY + (contentH - drawH) / 2;
    }
    else {
        drawX = contentX + (contentW - kSourceW) / 2;
        drawY = contentY + (contentH - kSourceH) / 2;
    }

    // Scaling uses a temporary FLTK image copy so every display mode draws predictably.
    fl_push_clip(contentX, contentY, contentW, contentH);
    if (drawW == kSourceW && drawH == kSourceH) {
        image_->draw(drawX, drawY);
    }
    else {
        Fl_Image* scaled = image_->copy(drawW, drawH);
        if (scaled) {
            scaled->draw(drawX, drawY);
            scaled->release();
        }
    }
    fl_pop_clip();
}

KTabs::KTabs(int x, int y, int w, int h, const char* label)
    : Fl_Tabs(x, y, w, h, label) {
    box(FL_FLAT_BOX);
    tab_align(FL_ALIGN_CENTER);
    applyWidgetTextStyle(this);
}

void KTabs::draw_tab(int x1, int x2, int w, int h, Fl_Widget* child, int flags, int selected) {
    (void)flags;
    if (!child || x2 <= x1) {
        return;
    }
    const KTheme& theme = KThemeManager::instance().theme();
    const int kTabW = x2 - x1;
    const int kTabY = y();
    const bool kIsSelected = selected != 0 || child == value();
    const Fl_Color kBg = kIsSelected ? theme.primary : theme.panelBg;
    const Fl_Color kFg = kIsSelected ? FL_WHITE : theme.text;
    fl_push_clip(x1, kTabY, kTabW, h);
    fl_color(kBg);
    fl_rectf(x1, kTabY, kTabW, h);
    drawSquareBorder(x1, kTabY, kTabW, h, theme.border);
    drawWidgetLabel(child->label(), x1 + 8, kTabY, kTabW - 16, h, kFg, FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    fl_pop_clip();
}

void KTabs::draw() {
    if (hasOnlyChildDamage(this)) {
        // A child cursor/selection update inside a tab page must not ask
        // Fl_Tabs to repaint the tab body, because FLTK may redraw only the
        // changed child afterward. Drawing children only preserves siblings.
        draw_children();
        return;
    }

    Fl_Tabs::draw();
    const int kTabH = tab_height();
    if (kTabH > 0) {
        // The separator correction belongs to a tab/header repaint. Skipping it
        // during child-only damage prevents a tab page child event from drawing
        // outside the area FLTK intended to update.
        fl_color(KThemeManager::instance().theme().panelBg);
        fl_rectf(x(), y() + kTabH - 1, w(), 2);
    }
}

KChoice::KChoice(int x, int y, int w, int h, const char* label)
    : Fl_Choice(x, y, w, h, label) {
    box(FL_FLAT_BOX);
    textfont(FL_HELVETICA);
    textsize(kWidgetFontSize);
    applyWidgetTextStyle(this);
}

KOutput::KOutput(int x, int y, int w, int h, const char* label)
    : Fl_Output(x, y, w, h, label) {
    applyInputStyle(this);
}

KProgressBar::KProgressBar(int x, int y, int w, int h, const char* label)
    : Fl_Progress(x, y, w, h, label) {
    minimum(0);
    maximum(100);
    box(FL_FLAT_BOX);
    applyWidgetTextStyle(this);
}

KScrollArea::KScrollArea(int x, int y, int w, int h, const char* label)
    : Fl_Scroll(x, y, w, h, label) {
    box(FL_FLAT_BOX);
    applyWidgetTextStyle(this);
}

KScrollBar::KScrollBar(int x, int y, int w, int h, int typeValue)
    : Fl_Scrollbar(x, y, w, h) {
    type(typeValue);
    box(FL_FLAT_BOX);
    applyValuatorStyle(this);
}

KBrowser::KBrowser(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label), items_(), selectedIndex_(-1) {
    box(FL_FLAT_BOX);
    // KBrowser is drawn as a leaf list widget even though it derives from
    // Fl_Group for compatibility. Close the construction group immediately so
    // widgets created after a browser are not accidentally parented to it.
    resizable(nullptr);
    begin();
    end();
    applyWidgetTextStyle(this);
}

void KBrowser::add(const char* item) {
    items_.push_back(item ? item : "");
    if (selectedIndex_ < 0 && !items_.empty()) {
        selectedIndex_ = 0;
    }
    redraw();
}

void KBrowser::clear() {
    items_.clear();
    selectedIndex_ = -1;
    redraw();
}

int KBrowser::value() const {
    return selectedIndex_;
}

void KBrowser::value(int index) {
    if (index < 0 || index >= static_cast<int>(items_.size())) {
        selectedIndex_ = -1;
    }
    else {
        selectedIndex_ = index;
    }
    redraw();
}

const char* KBrowser::text(int index) const {
    if (index < 0 || index >= static_cast<int>(items_.size())) {
        return "";
    }
    return items_[static_cast<std::size_t>(index)].c_str();
}

void KBrowser::draw() {
    const KTheme& theme = KThemeManager::instance().theme();
    fl_push_clip(x(), y(), w(), h());
    fl_color(theme.controlBg);
    fl_rectf(x(), y(), w(), h());
    fl_color(theme.border);
    fl_rect(x(), y(), w(), h());

    const int kRowHeight = 22;
    const int kLabelHeight = (label() && label()[0] != '\0') ? 20 : 0;
    if (kLabelHeight > 0) {
        fl_color(theme.mutedText);
        fl_font(FL_HELVETICA, kWidgetFontSize);
        fl_draw(label(), x() + 6, y(), w() - 12, kLabelHeight, FL_ALIGN_LEFT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    }

    const int kRowTop = y() + kLabelHeight + 2;
    for (int i = 0; i < static_cast<int>(items_.size()); ++i) {
        const int kIy = kRowTop + i * kRowHeight;
        if (kIy >= y() + h()) {
            break;
        }
        const bool kSelected = i == selectedIndex_;
        fl_color(kSelected ? theme.selection : (i % 2 == 0 ? theme.controlBg : theme.controlAltBg));
        fl_rectf(x() + 1, kIy, w() - 2, std::min(kRowHeight, y() + h() - kIy - 1));
        fl_color(theme.text);
        fl_font(FL_HELVETICA, kWidgetFontSize);
        fl_draw(items_[static_cast<std::size_t>(i)].c_str(), x() + 8, kIy, w() - 16, kRowHeight, FL_ALIGN_LEFT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    }
    fl_pop_clip();
}

int KBrowser::handle(int event) {
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) {
        const int kLabelHeight = (label() && label()[0] != '\0') ? 20 : 0;
        const int kLocalY = Fl::event_y() - y() - kLabelHeight - 2;
        if (kLocalY >= 0) {
            const int kIndex = kLocalY / 22;
            if (kIndex >= 0 && kIndex < static_cast<int>(items_.size())) {
                selectedIndex_ = kIndex;
                do_callback();
                redraw();
                return 1;
            }
        }
    }
    return Fl_Group::handle(event);
}

KMenuButton::KMenuButton(int x, int y, int w, int h, const char* label)
    : Fl_Menu_Button(x, y, w, h, label) {
    box(FL_FLAT_BOX);
    textfont(FL_HELVETICA);
    textsize(kWidgetFontSize);
    applyWidgetTextStyle(this);
}

KCounter::KCounter(int x, int y, int w, int h, const char* label)
    : Fl_Counter(x, y, w, h, label) {
    applyValuatorStyle(this);
    textfont(FL_HELVETICA);
    textsize(kWidgetFontSize);
}

KSpinner::KSpinner(int x, int y, int w, int h, const char* label)
    : Fl_Value_Input(x, y, w, h, label) {
    applyValuatorStyle(this);
    textfont(FL_HELVETICA);
    textsize(kWidgetFontSize);
    step(1.0);
}

KValueInput::KValueInput(int x, int y, int w, int h, const char* label)
    : Fl_Value_Input(x, y, w, h, label) {
    applyValuatorStyle(this);
    textfont(FL_HELVETICA);
    textsize(kWidgetFontSize);
}

KSplitter::KSplitter(int x, int y, int w, int h, const char* label)
    : Fl_Tile(x, y, w, h, label) {
    box(FL_FLAT_BOX);
    applyWidgetTextStyle(this);
}
