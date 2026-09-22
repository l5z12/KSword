#include "KOverlay.h"

#include "fl_draw.H"

#include <algorithm>
#include <cmath>

namespace {
constexpr int kFont = 12;
constexpr int kTitleFont = 14;

// DrawText paints clipped text using the shared flat typography; returns no value.
void drawText(const std::string& text, int x, int y, int w, int h, Fl_Color color, Fl_Align align, int size = kFont) {
    if (text.empty() || w <= 0 || h <= 0) return;
    fl_color(color); fl_font(FL_HELVETICA, size); fl_draw(text.c_str(), x, y, w, h, align | FL_ALIGN_INSIDE);
}

// drawBorder paints the square one-pixel border used by overlay shells; returns no value.
void drawBorder(int x, int y, int w, int h, Fl_Color color) { fl_color(color); fl_rect(x, y, w, h); }

// semanticColor maps toast kind to current theme colors; output is an FLTK color.
Fl_Color semanticColor(KToastKind kind, Fl_Color info) {
    const KTheme& t = KThemeManager::instance().theme();
    if (kind == KToastKind::kSuccess) return t.success;
    if (kind == KToastKind::kWarning) return t.warning;
    if (kind == KToastKind::kDanger) return t.danger;
    return info == FL_BACKGROUND_COLOR ? t.primary : info;
}

// clampIndex returns a valid row index for non-empty item lists, otherwise -1.
int clampIndex(int index, std::size_t count) { return count == 0 ? -1 : std::max(0, std::min(index, static_cast<int>(count) - 1)); }

// resolveAccent returns current theme primary unless caller supplied an explicit accent color.
Fl_Color resolveAccent(Fl_Color color) { return color == FL_BACKGROUND_COLOR ? KThemeManager::instance().theme().primary : color; }

// nextEnabledMenuRow walks selectable context-menu rows while skipping separators and disabled items.
int nextEnabledMenuRow(const std::vector<KContextMenuItem>& items, int start, int delta) {
    if (items.empty()) return -1;
    int index = clampIndex(start, items.size());
    for (int count = 0; count < static_cast<int>(items.size()); ++count) { index = (index + delta + static_cast<int>(items.size())) % static_cast<int>(items.size()); if (items[index].enabled && !items[index].separator) return index; }
    return -1;
}
}

KToast::KToast(int x, int y, int w, int h, const char* label)
    : Fl_Window(x, y, w, h, label ? label : ""), text_(label ? label : ""), kind_(KToastKind::kInfo), duration_(3.0), accentColor_(FL_BACKGROUND_COLOR) {
    // Toasts are borderless self-painted windows, so title-bar and Dock code are not touched.
    border(0); box(FL_FLAT_BOX); end();
}

void KToast::setText(const char* text) { text_ = text ? text : ""; label(text_.c_str()); redraw(); }
void KToast::setKind(KToastKind kind) { kind_ = kind; redraw(); }
void KToast::setDuration(double seconds) { duration_ = std::max(0.0, seconds); redraw(); }
void KToast::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }
void KToast::showAt(int rootX, int rootY, const char* text) { if (text) setText(text); position(rootX, rootY); show(); }

void KToast::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const Fl_Color kAccent = semanticColor(kind_, accentColor_);
    fl_push_clip(0, 0, w(), h()); fl_color(t.panelBg); fl_rectf(0, 0, w(), h()); drawBorder(0, 0, w(), h(), t.border);
    fl_color(kAccent); fl_rectf(0, 0, 4, h()); drawText(text_, 14, 0, w() - 22, h(), t.text, FL_ALIGN_LEFT); fl_pop_clip();
}

KTooltip::KTooltip(int x, int y, int w, int h, const char* label)
    : Fl_Window(x, y, w, h, label ? label : ""), text_(label ? label : "") {
    // Tooltips are paint-only popups with no children.
    border(0); box(FL_FLAT_BOX); end();
}

void KTooltip::setText(const char* text) { text_ = text ? text : ""; label(text_.c_str()); redraw(); }
void KTooltip::showAt(int rootX, int rootY) { position(rootX, rootY); show(); }

void KTooltip::draw() {
    const KTheme& t = KThemeManager::instance().theme();
    fl_push_clip(0, 0, w(), h()); fl_color(t.controlAltBg); fl_rectf(0, 0, w(), h()); drawBorder(0, 0, w(), h(), t.border);
    drawText(text_, 8, 0, w() - 16, h(), t.text, FL_ALIGN_CENTER); fl_pop_clip();
}

KPopover::KPopover(int x, int y, int w, int h, const char* label)
    : Fl_Window(x, y, w, h, label ? label : ""), title_(label ? label : ""), content_() {
    // Popovers provide a themed content bubble without assuming child controls.
    border(0); box(FL_FLAT_BOX); end();
}

void KPopover::setTitle(const char* text) { title_ = text ? text : ""; label(title_.c_str()); redraw(); }
void KPopover::setContent(const char* text) { content_ = text ? text : ""; redraw(); }
void KPopover::showAt(int rootX, int rootY) { position(rootX, rootY); show(); }

void KPopover::draw() {
    const KTheme& t = KThemeManager::instance().theme();
    fl_push_clip(0, 0, w(), h()); fl_color(t.panelBg); fl_rectf(0, 0, w(), h()); drawBorder(0, 0, w(), h(), t.border);
    drawText(title_, 12, 8, w() - 24, 22, t.text, FL_ALIGN_LEFT, kTitleFont); drawText(content_, 12, 34, w() - 24, h() - 42, t.mutedText, FL_ALIGN_LEFT | FL_ALIGN_TOP); fl_pop_clip();
}

KModalDialog::KModalDialog(int x, int y, int w, int h, const char* label)
    : Fl_Window(x, y, w, h, label ? label : "Dialog"), title_(label ? label : "Dialog"), message_(), primaryText_("OK"), secondaryText_("Cancel"), result_(-1) {
    // The dialog is modal and self-drawn; it avoids the custom title-bar subsystem by design.
    set_modal(); border(0); box(FL_FLAT_BOX); end();
}

void KModalDialog::setTitle(const char* text) { title_ = text ? text : ""; label(title_.c_str()); redraw(); }
void KModalDialog::setMessage(const char* text) { message_ = text ? text : ""; redraw(); }
void KModalDialog::setPrimaryText(const char* text) { primaryText_ = text ? text : ""; redraw(); }
void KModalDialog::setSecondaryText(const char* text) { secondaryText_ = text ? text : ""; redraw(); }
int KModalDialog::runModal() { result_ = -1; show(); while (shown()) Fl::wait(); return result_; }
int KModalDialog::result() const { return result_; }

void KModalDialog::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const int kBy = h() - 48;
    fl_push_clip(0, 0, w(), h()); fl_color(t.panelBg); fl_rectf(0, 0, w(), h()); drawBorder(0, 0, w(), h(), t.border);
    drawText(title_, 16, 12, w() - 32, 24, t.text, FL_ALIGN_LEFT, kTitleFont); drawText(message_, 16, 46, w() - 32, kBy - 54, t.mutedText, FL_ALIGN_LEFT | FL_ALIGN_TOP);
    fl_color(t.primary); fl_rectf(w() - 104, kBy, 84, 30); drawBorder(w() - 104, kBy, 84, 30, t.primaryDark); drawText(primaryText_, w() - 104, kBy, 84, 30, FL_WHITE, FL_ALIGN_CENTER);
    fl_color(t.controlBg); fl_rectf(w() - 198, kBy, 84, 30); drawBorder(w() - 198, kBy, 84, 30, t.border); drawText(secondaryText_, w() - 198, kBy, 84, 30, t.text, FL_ALIGN_CENTER); fl_pop_clip();
}

int KModalDialog::handle(int event) {
    if (event == FL_KEYDOWN && Fl::event_key() == FL_Escape) { result_ = -1; hide(); return 1; }
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) {
        const int kBy = h() - 48, kEx = Fl::event_x(), kKey = Fl::event_y();
        if (kKey >= kBy && kKey < kBy + 30 && kEx >= w() - 104 && kEx < w() - 20) { result_ = 1; do_callback(); hide(); return 1; }
        if (kKey >= kBy && kKey < kBy + 30 && kEx >= w() - 198 && kEx < w() - 114) { result_ = 0; do_callback(); hide(); return 1; }
    }
    return Fl_Window::handle(event);
}

KDrawer::KDrawer(int x, int y, int w, int h, const char* label)
    : Fl_Window(x, y, w, h, label ? label : "Drawer"), title_(label ? label : "Drawer"), content_(), side_(KDrawerSide::kRight) {
    // Drawers are self-painted side panels and can host caller children if added manually later.
    border(0); box(FL_FLAT_BOX); end();
}

void KDrawer::setTitle(const char* text) { title_ = text ? text : ""; label(title_.c_str()); redraw(); }
void KDrawer::setContent(const char* text) { content_ = text ? text : ""; redraw(); }
void KDrawer::setSide(KDrawerSide side) { side_ = side; redraw(); }
void KDrawer::showDrawer() { show(); }
void KDrawer::hideDrawer() { hide(); }

void KDrawer::draw() {
    const KTheme& t = KThemeManager::instance().theme(); (void)side_;
    fl_push_clip(0, 0, w(), h()); fl_color(t.panelBg); fl_rectf(0, 0, w(), h()); drawBorder(0, 0, w(), h(), t.border);
    drawText(title_, 14, 12, w() - 28, 26, t.text, FL_ALIGN_LEFT, kTitleFont); fl_color(t.border); fl_line(0, 48, w(), 48);
    drawText(content_, 14, 60, w() - 28, h() - 74, t.mutedText, FL_ALIGN_LEFT | FL_ALIGN_TOP); fl_pop_clip(); draw_children();
}

KOverlayMask::KOverlayMask(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), visible_(false), opacity_(0.45) {
    // The mask does not hide the FLTK widget itself; visible_ controls painting only.
    box(FL_FLAT_BOX);
}

void KOverlayMask::setVisible(bool visible) { visible_ = visible; redraw(); }
bool KOverlayMask::visibleMask() const { return visible_; }
void KOverlayMask::setOpacity(double opacity) { opacity_ = std::max(0.0, std::min(1.0, opacity)); redraw(); }

void KOverlayMask::draw() {
    if (!visible_) return; const KTheme& t = KThemeManager::instance().theme(); (void)opacity_;
    fl_push_clip(x(), y(), w(), h()); fl_color(t.pressed); fl_rectf(x(), y(), w(), h()); fl_pop_clip();
}


KModalMask::KModalMask(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), visible_(false), opacity_(0.55), message_(label ? label : ""), accentColor_(FL_BACKGROUND_COLOR) {
    // ModalMask is paint-only and blocks interaction by consuming events while visible_.
    box(FL_FLAT_BOX);
}

void KModalMask::setVisible(bool visible) { visible_ = visible; redraw(); }
bool KModalMask::visibleMask() const { return visible_; }
void KModalMask::setOpacity(double opacity) { opacity_ = std::max(0.0, std::min(1.0, opacity)); redraw(); }
void KModalMask::setMessage(const char* text) { message_ = text ? text : ""; redraw(); }
void KModalMask::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KModalMask::draw() {
    if (!visible_) return; const KTheme& t = KThemeManager::instance().theme(); const Fl_Color kAccent = resolveAccent(accentColor_); (void)opacity_;
    fl_push_clip(x(), y(), w(), h()); fl_color(t.pressed); fl_rectf(x(), y(), w(), h());
    if (!message_.empty()) { const int kCardW = std::min(300, std::max(160, w() - 60)); const int kCardH = 72; const int kCardX = x() + (w() - kCardW) / 2; const int kCardY = y() + (h() - kCardH) / 2;
        fl_color(t.panelBg); fl_rectf(kCardX, kCardY, kCardW, kCardH); drawBorder(kCardX, kCardY, kCardW, kCardH, t.border); fl_color(kAccent); fl_rectf(kCardX, kCardY, 4, kCardH); drawText(message_, kCardX + 16, kCardY, kCardW - 28, kCardH, t.text, FL_ALIGN_CENTER, kTitleFont); }
    fl_pop_clip();
}

int KModalMask::handle(int event) {
    if (!visible_) return Fl_Widget::handle(event);
    if (event == FL_PUSH || event == FL_RELEASE || event == FL_DRAG || event == FL_MOVE || event == FL_KEYDOWN || event == FL_SHORTCUT) return 1;
    return Fl_Widget::handle(event);
}

KLoadingOverlay::KLoadingOverlay(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), loading_(false), message_(label ? label : "Loading"), progress_(-1.0), step_(0) {
    // Loading overlays are paint-only; callers can animate by changing step_.
    box(FL_FLAT_BOX);
}

void KLoadingOverlay::setLoading(bool loading) { loading_ = loading; redraw(); }
bool KLoadingOverlay::loading() const { return loading_; }
void KLoadingOverlay::setMessage(const char* text) { message_ = text ? text : ""; redraw(); }
void KLoadingOverlay::setProgress(double progress) { progress_ = progress < 0.0 ? -1.0 : std::max(0.0, std::min(1.0, progress)); redraw(); }
void KLoadingOverlay::setStep(int step) { step_ = step; redraw(); }

void KLoadingOverlay::draw() {
    if (!loading_) return; const KTheme& t = KThemeManager::instance().theme(); const int kCx = x() + w() / 2, kCy = y() + h() / 2 - 12;
    fl_push_clip(x(), y(), w(), h()); fl_color(t.pressed); fl_rectf(x(), y(), w(), h());
    fl_color(t.panelBg); fl_rectf(kCx - 82, kCy - 44, 164, progress_ >= 0.0 ? 104 : 82); drawBorder(kCx - 82, kCy - 44, 164, progress_ >= 0.0 ? 104 : 82, t.border);
    for (int i = 0; i < 8; ++i) { fl_color(i == (step_ % 8) ? t.primary : t.border); const double kA = (i * 3.14159265358979323846) / 4.0; fl_line(kCx, kCy, kCx + static_cast<int>(std::cos(kA) * 18), kCy + static_cast<int>(std::sin(kA) * 18)); }
    drawText(message_, kCx - 70, kCy + 26, 140, 20, t.text, FL_ALIGN_CENTER);
    if (progress_ >= 0.0) { fl_color(t.controlBg); fl_rectf(kCx - 62, kCy + 54, 124, 8); fl_color(t.primary); fl_rectf(kCx - 62, kCy + 54, static_cast<int>(124 * progress_), 8); drawBorder(kCx - 62, kCy + 54, 124, 8, t.border); }
    fl_pop_clip();
}

KContextMenu::KContextMenu(int x, int y, int w, int h, const char* label)
    : Fl_Window(x, y, w, h, label ? label : ""), items_(), activeIndex_(-1), selectedIndex_(-1), rowHeight_(28) {
    // Context menus are modal popups with keyboard and mouse selection.
    border(0); box(FL_FLAT_BOX); end();
}

void KContextMenu::setItems(const std::vector<KContextMenuItem>& items) { items_ = items; activeIndex_ = clampIndex(activeIndex_, items_.size()); selectedIndex_ = -1; redraw(); }
void KContextMenu::addItem(const KContextMenuItem& item) { items_.push_back(item); if (activeIndex_ < 0 && !item.separator && item.enabled) activeIndex_ = static_cast<int>(items_.size()) - 1; redraw(); }
void KContextMenu::clear() { items_.clear(); activeIndex_ = -1; selectedIndex_ = -1; redraw(); }
void KContextMenu::setActiveIndex(int index) { activeIndex_ = clampIndex(index, items_.size()); redraw(); }
int KContextMenu::selectedIndex() const { return selectedIndex_; }

int KContextMenu::popup(int rootX, int rootY) {
    selectedIndex_ = -1; const int kMenuH = std::max(rowHeight_, static_cast<int>(items_.size()) * rowHeight_ + 2);
    resize(rootX, rootY, w(), kMenuH); set_modal(); show(); Fl::grab(this); while (shown()) Fl::wait(); Fl::grab(nullptr); return selectedIndex_;
}

void KContextMenu::draw() {
    const KTheme& t = KThemeManager::instance().theme(); fl_push_clip(0, 0, w(), h()); fl_color(t.panelBg); fl_rectf(0, 0, w(), h()); drawBorder(0, 0, w(), h(), t.border);
    int cy = 1; for (int i = 0; i < static_cast<int>(items_.size()); ++i, cy += rowHeight_) {
        const KContextMenuItem& item = items_[i]; if (item.separator) { fl_color(t.border); fl_line(8, cy + rowHeight_ / 2, w() - 8, cy + rowHeight_ / 2); continue; }
        fl_color(i == activeIndex_ && item.enabled ? t.hover : t.panelBg); fl_rectf(1, cy, w() - 2, rowHeight_);
        drawText(item.checked ? "*" : "", 8, cy, 14, rowHeight_, t.primary, FL_ALIGN_CENTER);
        drawText(item.text, 26, cy, w() - 106, rowHeight_, item.enabled ? t.text : t.mutedText, FL_ALIGN_LEFT);
        drawText(item.shortcut, w() - 76, cy, 66, rowHeight_, t.mutedText, FL_ALIGN_RIGHT);
    }
    fl_pop_clip();
}

int KContextMenu::handle(int event) {
    if (event == FL_KEYDOWN) {
        if (Fl::event_key() == FL_Escape) { hide(); return 1; }
        if (Fl::event_key() == FL_Up) { activeIndex_ = nextEnabledMenuRow(items_, activeIndex_, -1); redraw(); return 1; }
        if (Fl::event_key() == FL_Down) { activeIndex_ = nextEnabledMenuRow(items_, activeIndex_, 1); redraw(); return 1; }
        if (Fl::event_key() == FL_Enter || Fl::event_key() == FL_KP_Enter) { if (activeIndex_ >= 0 && activeIndex_ < static_cast<int>(items_.size()) && items_[activeIndex_].enabled && !items_[activeIndex_].separator) { selectedIndex_ = activeIndex_; do_callback(); hide(); } return 1; }
    }
    if (event == FL_MOVE) { const int kRow = clampIndex((Fl::event_y() - 1) / rowHeight_, items_.size()); activeIndex_ = (kRow >= 0 && items_[kRow].enabled && !items_[kRow].separator) ? kRow : -1; redraw(); return 1; }
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) {
        const int kRow = (Fl::event_y() - 1) / rowHeight_;
        if (kRow >= 0 && kRow < static_cast<int>(items_.size()) && items_[kRow].enabled && !items_[kRow].separator) { selectedIndex_ = kRow; do_callback(); hide(); return 1; }
        hide(); return 1;
    }
    return Fl_Window::handle(event);
}

KModalMask* kCreateModalMask(int x, int y, int w, int h, const char* label) { return new KModalMask(x, y, w, h, label); }
