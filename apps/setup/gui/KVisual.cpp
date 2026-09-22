#include "KVisual.h"

#include "fl_draw.H"
#include "Fl_Image.H"

#include <algorithm>
#include <cctype>

namespace {
constexpr int kFont = 12;
constexpr int kTitleFont = 14;

// DrawText paints clipped text with shared typography; input strings are already owned by widgets.
void drawText(const std::string& text, int x, int y, int w, int h, Fl_Color color, Fl_Align align, int size = kFont) {
    if (text.empty() || w <= 0 || h <= 0) return;
    fl_color(color); fl_font(FL_HELVETICA, size); fl_draw(text.c_str(), x, y, w, h, align | FL_ALIGN_INSIDE);
}

// drawBorder paints a flat square border and returns no value.
void drawBorder(int x, int y, int w, int h, Fl_Color color) { fl_color(color); fl_rect(x, y, w, h); }

// alertColor maps semantic kind to active theme color.
Fl_Color alertColor(KAlertKind kind) {
    const KTheme& t = KThemeManager::instance().theme();
    if (kind == KAlertKind::kSuccess) return t.success;
    if (kind == KAlertKind::kWarning) return t.warning;
    if (kind == KAlertKind::kDanger) return t.danger;
    return t.primary;
}

// resolveAccent follows the current theme unless callers set an explicit accent color.
Fl_Color resolveAccent(Fl_Color color) { return color == FL_BACKGROUND_COLOR ? KThemeManager::instance().theme().primary : color; }

// clampIndex returns a valid index for non-empty collections, otherwise -1.
int clampIndex(int index, std::size_t count) { return count == 0 ? -1 : std::max(0, std::min(index, static_cast<int>(count) - 1)); }

// buildInitials derives one or two uppercase initials from a display name.
std::string buildInitials(const std::string& name) {
    std::string out; bool takeNext = true;
    for (char ch : name) {
        if (std::isspace(static_cast<unsigned char>(ch))) { takeNext = true; continue; }
        if (takeNext && std::isalnum(static_cast<unsigned char>(ch))) { out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch)))); takeNext = false; if (out.size() == 2) break; }
    }
    return out.empty() ? "?" : out;
}
}

KIconButton::KIconButton(int x, int y, int w, int h, const char* label)
    : Fl_Button(x, y, w, h, label), icon_(), iconName_(), text_(label ? label : ""), iconRole_(KIconColorRole::kText), iconTint_(FL_BACKGROUND_COLOR), useIconTint_(false), iconSize_(18), hover_(false), pressed_(false), checked_(false), accentColor_(FL_BACKGROUND_COLOR) {
    // Icon buttons use Fl_Button activation but paint every state themselves.
    box(FL_FLAT_BOX); when(FL_WHEN_RELEASE);
}

void KIconButton::setIcon(const char* icon) { icon_ = icon ? icon : ""; redraw(); }
void KIconButton::setIconName(const char* iconName) { iconName_ = iconName ? iconName : ""; redraw(); }
const std::string& KIconButton::iconName() const { return iconName_; }
void KIconButton::setIconColorRole(KIconColorRole role) { iconRole_ = role; useIconTint_ = false; redraw(); }
void KIconButton::setIconTint(Fl_Color color) { iconTint_ = color; useIconTint_ = true; redraw(); }
void KIconButton::clearIconTint() { useIconTint_ = false; redraw(); }
void KIconButton::setIconSize(int size) { iconSize_ = std::max(8, size); redraw(); }
void KIconButton::setText(const char* text) { text_ = text ? text : ""; label(text_.c_str()); redraw(); }
void KIconButton::setChecked(bool checked) { checked_ = checked; redraw(); }
bool KIconButton::checked() const { return checked_; }
void KIconButton::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KIconButton::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const bool kDown = pressed_ || checked_ || value();
    const Fl_Color kAccent = resolveAccent(accentColor_);
    Fl_Image* image = nullptr;
    // SVG lookup stays inside KswordGUI/Icon through KIcon; missing files simply fall back to glyph text.
    if (!iconName_.empty()) image = useIconTint_ ? KIcon::loadThemedSvg(iconName_, iconTint_, iconSize_) : KIcon::loadThemedSvg(iconName_, iconRole_, iconSize_);
    fl_push_clip(x(), y(), w(), h()); fl_color(kDown ? t.selection : (hover_ ? t.hover : t.controlBg)); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), kDown ? kAccent : t.border);
    const bool kHasIcon = image || !icon_.empty(); const int kIconW = kHasIcon ? std::min(std::max(26, iconSize_ + 8), std::max(26, w() / 2)) : 0;
    if (image) { const int kDrawSize = std::max(8, std::min(iconSize_, std::min(kIconW - 8, h() - 8))); image->draw(x() + 6, y() + (h() - kDrawSize) / 2, kDrawSize, kDrawSize); }
    else drawText(icon_, x() + 6, y(), kIconW, h(), kDown ? kAccent : t.text, FL_ALIGN_CENTER, kTitleFont);
    drawText(text_, x() + 6 + kIconW, y(), w() - 12 - kIconW, h(), kDown ? kAccent : t.text, kHasIcon ? FL_ALIGN_LEFT : FL_ALIGN_CENTER); fl_pop_clip();
}

int KIconButton::handle(int event) {
    if (event == FL_ENTER) { hover_ = true; redraw(); return 1; }
    if (event == FL_LEAVE) { hover_ = false; pressed_ = false; redraw(); return 1; }
    if (event == FL_PUSH) { pressed_ = true; redraw(); }
    if (event == FL_RELEASE) { pressed_ = false; redraw(); }
    return Fl_Button::handle(event);
}

KAvatar::KAvatar(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), name_(label ? label : ""), initials_(), accentColor_(FL_BACKGROUND_COLOR), online_(false) {
    // Avatar is paint-only and stores text identity locally.
    box(FL_FLAT_BOX);
}

void KAvatar::setName(const char* name) { name_ = name ? name : ""; redraw(); }
void KAvatar::setInitials(const char* initials) { initials_ = initials ? initials : ""; redraw(); }
void KAvatar::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }
void KAvatar::setOnline(bool online) { online_ = online; redraw(); }

void KAvatar::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const std::string kInitials = initials_.empty() ? buildInitials(name_) : initials_;
    const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_push_clip(x(), y(), w(), h()); fl_color(kAccent); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    drawText(kInitials, x(), y(), w(), h(), FL_WHITE, FL_ALIGN_CENTER, kTitleFont);
    if (online_) { fl_color(t.success); fl_rectf(x() + w() - 10, y() + h() - 10, 8, 8); drawBorder(x() + w() - 10, y() + h() - 10, 8, 8, t.panelBg); }
    fl_pop_clip();
}

KTag::KTag(int x, int y, int w, int h, const char* label) : Fl_Widget(x, y, w, h, label), text_(label ? label : ""), accentColor_(FL_BACKGROUND_COLOR) { box(FL_FLAT_BOX); }
void KTag::setText(const char* text) { text_ = text ? text : ""; label(text_.c_str()); redraw(); }
const std::string& KTag::text() const { return text_; }
void KTag::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KTag::draw() {
    const KTheme& t = KThemeManager::instance().theme(); fl_push_clip(x(), y(), w(), h());
    const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_color(t.selection); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), kAccent); drawText(text_, x() + 6, y(), w() - 12, h(), kAccent, FL_ALIGN_CENTER); fl_pop_clip();
}

KChip::KChip(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), text_(label ? label : ""), selected_(false), closable_(false), accentColor_(FL_BACKGROUND_COLOR) {
    // Chips are self-contained tokens with optional close hit target.
    box(FL_FLAT_BOX);
}

void KChip::setText(const char* text) { text_ = text ? text : ""; label(text_.c_str()); redraw(); }
void KChip::setSelected(bool selected) { selected_ = selected; redraw(); }
bool KChip::selected() const { return selected_; }
void KChip::setClosable(bool closable) { closable_ = closable; redraw(); }
void KChip::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KChip::draw() {
    const KTheme& t = KThemeManager::instance().theme(); fl_push_clip(x(), y(), w(), h());
    const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_color(selected_ ? t.selection : t.controlBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), selected_ ? kAccent : t.border);
    drawText(text_, x() + 8, y(), w() - (closable_ ? 30 : 16), h(), selected_ ? kAccent : t.text, FL_ALIGN_LEFT);
    if (closable_) drawText("x", x() + w() - 24, y(), 18, h(), t.mutedText, FL_ALIGN_CENTER); fl_pop_clip();
}

int KChip::handle(int event) {
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) {
        if (closable_ && Fl::event_x() >= x() + w() - 26) { do_callback(); return 1; }
        selected_ = !selected_; do_callback(); redraw(); return 1;
    }
    return Fl_Widget::handle(event);
}

KAlert::KAlert(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), text_(label ? label : ""), description_(), kind_(KAlertKind::kInfo) {
    // Alerts are paint-only status blocks.
    box(FL_FLAT_BOX);
}

void KAlert::setText(const char* text) { text_ = text ? text : ""; label(text_.c_str()); redraw(); }
void KAlert::setDescription(const char* text) { description_ = text ? text : ""; redraw(); }
void KAlert::setKind(KAlertKind kind) { kind_ = kind; redraw(); }

void KAlert::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const Fl_Color kAccent = alertColor(kind_);
    fl_push_clip(x(), y(), w(), h()); fl_color(t.controlBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border); fl_color(kAccent); fl_rectf(x(), y(), 4, h());
    drawText(text_, x() + 14, y() + 6, w() - 24, 20, t.text, FL_ALIGN_LEFT, kTitleFont); drawText(description_, x() + 14, y() + 28, w() - 24, h() - 34, t.mutedText, FL_ALIGN_LEFT | FL_ALIGN_TOP); fl_pop_clip();
}

KEmptyState::KEmptyState(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), text_(label ? label : "No data"), description_(), actionText_() {
    // Empty state is paint-only except for the optional action area.
    box(FL_FLAT_BOX);
}

void KEmptyState::setText(const char* text) { text_ = text ? text : ""; redraw(); }
void KEmptyState::setDescription(const char* text) { description_ = text ? text : ""; redraw(); }
void KEmptyState::setActionText(const char* text) { actionText_ = text ? text : ""; redraw(); }

void KEmptyState::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const int kCx = x() + w() / 2;
    fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    fl_color(t.controlAltBg); fl_rectf(kCx - 28, y() + 18, 56, 42); drawBorder(kCx - 28, y() + 18, 56, 42, t.border);
    drawText(text_, x() + 12, y() + 70, w() - 24, 24, t.text, FL_ALIGN_CENTER, kTitleFont); drawText(description_, x() + 18, y() + 98, w() - 36, 34, t.mutedText, FL_ALIGN_CENTER | FL_ALIGN_TOP);
    if (!actionText_.empty()) { fl_color(t.selection); fl_rectf(kCx - 50, y() + h() - 38, 100, 28); drawBorder(kCx - 50, y() + h() - 38, 100, 28, t.primary); drawText(actionText_, kCx - 50, y() + h() - 38, 100, 28, t.primary, FL_ALIGN_CENTER); }
    fl_pop_clip();
}

int KEmptyState::handle(int event) {
    const int kCx = x() + w() / 2;
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE && !actionText_.empty() && Fl::event_x() >= kCx - 50 && Fl::event_x() <= kCx + 50 && Fl::event_y() >= y() + h() - 38) { do_callback(); return 1; }
    return Fl_Widget::handle(event);
}

KSkeleton::KSkeleton(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), lineCount_(3), phase_(0), avatarVisible_(false) {
    // Skeleton uses caller-driven phase rather than timers, keeping the widget deterministic.
    box(FL_FLAT_BOX);
}

void KSkeleton::setLineCount(int count) { lineCount_ = std::max(1, count); redraw(); }
void KSkeleton::setPhase(int phase) { phase_ = phase; redraw(); }
void KSkeleton::setAvatarVisible(bool visible) { avatarVisible_ = visible; redraw(); }

void KSkeleton::draw() {
    const KTheme& t = KThemeManager::instance().theme(); fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h());
    int startX = x() + 10; if (avatarVisible_) { fl_color(t.controlAltBg); fl_rectf(startX, y() + 10, 38, 38); startX += 50; }
    for (int i = 0; i < lineCount_; ++i) { const int kRowY = y() + 12 + i * 20; const int kWidthDelta = (i * 18 + phase_) % 42; fl_color(t.controlAltBg); fl_rectf(startX, kRowY, std::max(24, w() - (startX - x()) - 18 - kWidthDelta), 10); }
    fl_pop_clip();
}

KTimeline::KTimeline(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), items_(), accentColor_(FL_BACKGROUND_COLOR) {
    // Timeline stores event rows and paints them directly.
    box(FL_FLAT_BOX);
}

void KTimeline::setItems(const std::vector<KTimelineItem>& items) { items_ = items; redraw(); }
void KTimeline::addItem(const KTimelineItem& item) { items_.push_back(item); redraw(); }
void KTimeline::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KTimeline::draw() {
    const KTheme& t = KThemeManager::instance().theme(); fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    const Fl_Color kAccent = resolveAccent(accentColor_);
    const int kLineX = x() + 18; fl_color(t.border); fl_line(kLineX, y() + 12, kLineX, y() + h() - 12);
    for (int i = 0; i < static_cast<int>(items_.size()); ++i) { const int kCy = y() + 16 + i * 44; if (kCy > y() + h()) break; fl_color(items_[i].active ? kAccent : t.border); fl_rectf(kLineX - 4, kCy - 4, 8, 8); drawText(items_[i].title, x() + 34, kCy - 12, w() - 44, 18, t.text, FL_ALIGN_LEFT, kTitleFont); drawText(items_[i].detail, x() + 34, kCy + 6, w() - 44, 18, t.mutedText, FL_ALIGN_LEFT); }
    fl_pop_clip();
}

KMetricCard::KMetricCard(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), title_(label ? label : ""), value_("0"), trend_(), trendPositive_(true), accentColor_(FL_BACKGROUND_COLOR) {
    // Metric cards are compact read-only KPI summaries.
    box(FL_FLAT_BOX);
}

void KMetricCard::setTitle(const char* text) { title_ = text ? text : ""; redraw(); }
void KMetricCard::setValue(const char* text) { value_ = text ? text : ""; redraw(); }
void KMetricCard::setTrend(const char* text, bool positive) { trend_ = text ? text : ""; trendPositive_ = positive; redraw(); }
void KMetricCard::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KMetricCard::draw() {
    const KTheme& t = KThemeManager::instance().theme(); fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_color(kAccent); fl_rectf(x(), y(), 4, h()); drawText(title_, x() + 14, y() + 10, w() - 28, 18, t.mutedText, FL_ALIGN_LEFT); drawText(value_, x() + 14, y() + 34, w() - 28, 30, t.text, FL_ALIGN_LEFT, 22);
    drawText(trend_, x() + 14, y() + h() - 28, w() - 28, 18, trendPositive_ ? t.success : t.danger, FL_ALIGN_LEFT); fl_pop_clip();
}


KStatCard::KStatCard(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), title_(label ? label : ""), value_("0"), caption_(), iconName_(), iconRole_(KIconColorRole::kPrimary), accentColor_(FL_BACKGROUND_COLOR) {
    // Stat cards keep all data local and request SVG images only during draw for current-theme tinting.
    box(FL_FLAT_BOX);
}

void KStatCard::setTitle(const char* text) { title_ = text ? text : ""; redraw(); }
void KStatCard::setValue(const char* text) { value_ = text ? text : ""; redraw(); }
void KStatCard::setCaption(const char* text) { caption_ = text ? text : ""; redraw(); }
void KStatCard::setIconName(const char* iconName) { iconName_ = iconName ? iconName : ""; redraw(); }
void KStatCard::setIconColorRole(KIconColorRole role) { iconRole_ = role; redraw(); }
void KStatCard::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KStatCard::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    fl_color(kAccent); fl_rectf(x(), y(), 4, h());
    Fl_Image* image = iconName_.empty() ? nullptr : KIcon::loadThemedSvg(iconName_, iconRole_, 22);
    // The icon area degrades to a theme-colored square when the requested SVG is absent.
    fl_color(t.selection); fl_rectf(x() + w() - 46, y() + 12, 28, 28); drawBorder(x() + w() - 46, y() + 12, 28, 28, kAccent);
    if (image) image->draw(x() + w() - 43, y() + 15, 22, 22); else drawText("*", x() + w() - 46, y() + 12, 28, 28, kAccent, FL_ALIGN_CENTER, kTitleFont);
    drawText(title_, x() + 14, y() + 10, w() - 66, 18, t.mutedText, FL_ALIGN_LEFT);
    drawText(value_, x() + 14, y() + 34, w() - 66, 30, t.text, FL_ALIGN_LEFT, 22);
    drawText(caption_, x() + 14, y() + h() - 28, w() - 28, 18, t.mutedText, FL_ALIGN_LEFT); fl_pop_clip();
}

KSearchBox::KSearchBox(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), text_(), placeholder_(label ? label : "Search"), focused_(false), hover_(false), accentColor_(FL_BACKGROUND_COLOR) {
    // SearchBox is intentionally self-painted so it can be embedded without extra FLTK child focus wiring.
    box(FL_FLAT_BOX); when(FL_WHEN_CHANGED | FL_WHEN_ENTER_KEY);
}

void KSearchBox::setText(const char* text) { text_ = text ? text : ""; redraw(); }
const std::string& KSearchBox::text() const { return text_; }
void KSearchBox::setPlaceholder(const char* text) { placeholder_ = text ? text : ""; redraw(); }
void KSearchBox::clear() { text_.clear(); redraw(); }
void KSearchBox::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KSearchBox::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_push_clip(x(), y(), w(), h()); fl_color(focused_ ? t.panelBg : t.controlBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), focused_ ? kAccent : (hover_ ? t.primaryLight : t.border));
    drawText("?", x() + 8, y(), 18, h(), focused_ ? kAccent : t.mutedText, FL_ALIGN_CENTER, kTitleFont);
    drawText(text_.empty() ? placeholder_ : text_, x() + 30, y(), w() - 62, h(), text_.empty() ? t.mutedText : t.text, FL_ALIGN_LEFT);
    if (!text_.empty()) drawText("x", x() + w() - 28, y(), 20, h(), t.mutedText, FL_ALIGN_CENTER); fl_pop_clip();
}

int KSearchBox::handle(int event) {
    if (event == FL_ENTER || event == FL_MOVE) { hover_ = true; redraw(); return 1; }
    if (event == FL_LEAVE) { hover_ = false; redraw(); return 1; }
    if (event == FL_FOCUS) { focused_ = true; redraw(); return 1; }
    if (event == FL_UNFOCUS) { focused_ = false; redraw(); return 1; }
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) {
        Fl::focus(this); focused_ = true;
        if (!text_.empty() && Fl::event_x() >= x() + w() - 32) { text_.clear(); do_callback(); redraw(); return 1; }
        redraw(); return 1;
    }
    if (event == FL_KEYDOWN && focused_) {
        if (Fl::event_key() == FL_BackSpace) { if (!text_.empty()) { text_.pop_back(); do_callback(); redraw(); } return 1; }
        if (Fl::event_key() == FL_Escape) { if (!text_.empty()) { text_.clear(); do_callback(); redraw(); } return 1; }
        if (Fl::event_key() == FL_Enter || Fl::event_key() == FL_KP_Enter) { do_callback(); return 1; }
        const char* typed = Fl::event_text(); if (typed && Fl::event_length() > 0 && static_cast<unsigned char>(typed[0]) >= 32) { text_.append(typed, static_cast<std::size_t>(Fl::event_length())); do_callback(); redraw(); return 1; }
    }
    return Fl_Widget::handle(event);
}

KSegmentedControl::KSegmentedControl(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), items_(), activeIndex_(-1), hoverIndex_(-1), accentColor_(FL_BACKGROUND_COLOR) {
    // SegmentedControl owns only labels; selection changes are reported through the normal FLTK callback.
    box(FL_FLAT_BOX);
}

void KSegmentedControl::setItems(const std::vector<std::string>& items) { items_ = items; activeIndex_ = clampIndex(activeIndex_, items_.size()); hoverIndex_ = -1; redraw(); }
void KSegmentedControl::addItem(const char* text) { items_.push_back(text ? text : ""); if (activeIndex_ < 0) activeIndex_ = 0; redraw(); }
void KSegmentedControl::clear() { items_.clear(); activeIndex_ = -1; hoverIndex_ = -1; redraw(); }
void KSegmentedControl::setActiveIndex(int index) { activeIndex_ = clampIndex(index, items_.size()); redraw(); }
int KSegmentedControl::activeIndex() const { return activeIndex_; }
std::string KSegmentedControl::activeText() const { return activeIndex_ >= 0 && activeIndex_ < static_cast<int>(items_.size()) ? items_[activeIndex_] : std::string(); }
void KSegmentedControl::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

int KSegmentedControl::segmentAt(int mouseX, int mouseY) const {
    if (items_.empty() || mouseY < y() || mouseY >= y() + h() || mouseX < x() || mouseX >= x() + w()) return -1;
    const int kSegW = std::max(1, w() / static_cast<int>(items_.size())); return std::min(static_cast<int>(items_.size()) - 1, (mouseX - x()) / kSegW);
}

void KSegmentedControl::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_push_clip(x(), y(), w(), h()); fl_color(t.controlBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    if (items_.empty()) { drawText("No segments", x(), y(), w(), h(), t.mutedText, FL_ALIGN_CENTER); fl_pop_clip(); return; }
    const int kSegW = std::max(1, w() / static_cast<int>(items_.size()));
    for (int i = 0; i < static_cast<int>(items_.size()); ++i) { const int kSx = x() + i * kSegW; const int kSw = (i + 1 == static_cast<int>(items_.size())) ? x() + w() - kSx : kSegW; const bool kActive = i == activeIndex_;
        fl_color(kActive ? t.selection : (i == hoverIndex_ ? t.hover : t.controlBg)); fl_rectf(kSx + 1, y() + 1, kSw - 1, h() - 2); if (i > 0) { fl_color(t.border); fl_line(kSx, y() + 4, kSx, y() + h() - 4); }
        drawText(items_[i], kSx + 6, y(), kSw - 12, h(), kActive ? kAccent : t.text, FL_ALIGN_CENTER); }
    fl_pop_clip();
}

int KSegmentedControl::handle(int event) {
    if (event == FL_MOVE || event == FL_ENTER) { hoverIndex_ = segmentAt(Fl::event_x(), Fl::event_y()); redraw(); return 1; }
    if (event == FL_LEAVE) { hoverIndex_ = -1; redraw(); return 1; }
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) { const int kIndex = segmentAt(Fl::event_x(), Fl::event_y()); if (kIndex >= 0) { activeIndex_ = kIndex; do_callback(); redraw(); return 1; } }
    return Fl_Widget::handle(event);
}

KSwitch::KSwitch(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), checked_(false), hover_(false), on_text_("On"), offText_("Off"), accentColor_(FL_BACKGROUND_COLOR) {
    // Switch accepts mouse and keyboard input and delegates state-change notification to callbacks.
    box(FL_FLAT_BOX); when(FL_WHEN_CHANGED);
}

void KSwitch::setChecked(bool checked) { checked_ = checked; redraw(); }
bool KSwitch::checked() const { return checked_; }
void KSwitch::setTexts(const char* onText, const char* offText) { on_text_ = onText ? onText : ""; offText_ = offText ? offText : ""; redraw(); }
void KSwitch::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KSwitch::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const Fl_Color kAccent = resolveAccent(accentColor_); const int kTrackW = std::min(w(), std::max(42, h() * 2));
    fl_push_clip(x(), y(), w(), h()); fl_color(checked_ ? kAccent : (hover_ ? t.hover : t.controlAltBg)); fl_rectf(x(), y() + 3, kTrackW, h() - 6); drawBorder(x(), y() + 3, kTrackW, h() - 6, checked_ ? kAccent : t.border);
    const int kKnob = std::max(10, h() - 12); const int kKnobX = checked_ ? x() + kTrackW - kKnob - 5 : x() + 5; fl_color(t.panelBg); fl_rectf(kKnobX, y() + (h() - kKnob) / 2, kKnob, kKnob); drawBorder(kKnobX, y() + (h() - kKnob) / 2, kKnob, kKnob, t.border);
    drawText(checked_ ? on_text_ : offText_, x() + kTrackW + 8, y(), w() - kTrackW - 8, h(), checked_ ? kAccent : t.mutedText, FL_ALIGN_LEFT); fl_pop_clip();
}

int KSwitch::handle(int event) {
    if (event == FL_ENTER || event == FL_MOVE) { hover_ = true; redraw(); return 1; }
    if (event == FL_LEAVE) { hover_ = false; redraw(); return 1; }
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) { checked_ = !checked_; do_callback(); redraw(); return 1; }
    if (event == FL_KEYDOWN && (Fl::event_key() == ' ' || Fl::event_key() == FL_Enter || Fl::event_key() == FL_KP_Enter)) { checked_ = !checked_; do_callback(); redraw(); return 1; }
    return Fl_Widget::handle(event);
}

KColorSwatch::KColorSwatch(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), text_(label ? label : ""), color_(KThemeManager::instance().theme().primary), selected_(false) {
    // ColorSwatch is a small selectable token; callers can attach a picker through callback.
    box(FL_FLAT_BOX);
}

void KColorSwatch::setSwatchColor(Fl_Color color) { color_ = color; redraw(); }
Fl_Color KColorSwatch::swatchColor() const { return color_; }
void KColorSwatch::setText(const char* text) { text_ = text ? text : ""; redraw(); }
void KColorSwatch::setSelected(bool selected) { selected_ = selected; redraw(); }
bool KColorSwatch::selected() const { return selected_; }

void KColorSwatch::draw() {
    const KTheme& t = KThemeManager::instance().theme(); fl_push_clip(x(), y(), w(), h()); fl_color(selected_ ? t.selection : t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), selected_ ? color_ : t.border);
    const int kSize = std::max(12, std::min(h() - 10, 24)); fl_color(color_); fl_rectf(x() + 8, y() + (h() - kSize) / 2, kSize, kSize); drawBorder(x() + 8, y() + (h() - kSize) / 2, kSize, kSize, t.border);
    drawText(text_, x() + kSize + 16, y(), w() - kSize - 24, h(), t.text, FL_ALIGN_LEFT); if (selected_) drawText("*", x() + w() - 24, y(), 18, h(), color_, FL_ALIGN_CENTER); fl_pop_clip();
}

int KColorSwatch::handle(int event) {
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) { selected_ = !selected_; do_callback(); redraw(); return 1; }
    return Fl_Widget::handle(event);
}

KStatCard* kCreateStatCard(int x, int y, int w, int h, const char* label) { return new KStatCard(x, y, w, h, label); }
KSearchBox* kCreateSearchBox(int x, int y, int w, int h, const char* label) { return new KSearchBox(x, y, w, h, label); }
KSegmentedControl* kCreateSegmentedControl(int x, int y, int w, int h, const char* label) { return new KSegmentedControl(x, y, w, h, label); }
KSwitch* kCreateSwitch(int x, int y, int w, int h, const char* label) { return new KSwitch(x, y, w, h, label); }
KColorSwatch* kCreateColorSwatch(int x, int y, int w, int h, const char* label) { return new KColorSwatch(x, y, w, h, label); }
