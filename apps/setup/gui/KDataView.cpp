#include "KDataView.h"

#include "fl_draw.H"

#include <algorithm>
#include <cmath>

namespace {
constexpr int kFont = 12;
constexpr int kTitleFont = 14;

// DrawText paints clipped text using common K typography and returns no value.
void drawText(const std::string& text, int x, int y, int w, int h, Fl_Color color, Fl_Align align, int size = kFont) {
    if (text.empty() || w <= 0 || h <= 0) return;
    fl_color(color); fl_font(FL_HELVETICA, size); fl_draw(text.c_str(), x, y, w, h, align | FL_ALIGN_INSIDE);
}

// drawBorder paints the flat square border used by data widgets.
void drawBorder(int x, int y, int w, int h, Fl_Color color) { fl_color(color); fl_rect(x, y, w, h); }

// clampIndex returns a valid index for non-empty collections, otherwise -1.
int clampIndex(int index, std::size_t count) { return count == 0 ? -1 : std::max(0, std::min(index, static_cast<int>(count) - 1)); }

// normalize maps a value into 0..1 and protects against zero range.
double normalize(double value, double minimum, double maximum) {
    if (maximum <= minimum) return 0.0;
    return std::max(0.0, std::min(1.0, (value - minimum) / (maximum - minimum)));
}

// resolveAccent follows the current theme unless an explicit caller accent was set.
Fl_Color resolveAccent(Fl_Color color) { return color == FL_BACKGROUND_COLOR ? KThemeManager::instance().theme().primary : color; }
}

KListView::KListView(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label), items_(), activeIndex_(-1), hoverIndex_(-1), itemHeight_(44), emptyText_("No items"), accentColor_(FL_BACKGROUND_COLOR) {
    // ListView is self-painted and intentionally not a child container.
    box(FL_FLAT_BOX); end();
}

void KListView::setItems(const std::vector<KListViewItem>& items) { items_ = items; activeIndex_ = clampIndex(activeIndex_, items_.size()); redraw(); }
void KListView::addItem(const KListViewItem& item) { items_.push_back(item); if (activeIndex_ < 0) activeIndex_ = 0; redraw(); }
void KListView::clear() { items_.clear(); activeIndex_ = -1; hoverIndex_ = -1; redraw(); }
void KListView::setActiveIndex(int index) { activeIndex_ = clampIndex(index, items_.size()); redraw(); }
int KListView::activeIndex() const { return activeIndex_; }
std::string KListView::selectedText() const { return activeIndex_ >= 0 && activeIndex_ < static_cast<int>(items_.size()) ? items_[activeIndex_].title : std::string(); }
void KListView::setItemHeight(int height) { itemHeight_ = std::max(28, height); redraw(); }
void KListView::setEmptyText(const char* text) { emptyText_ = text ? text : ""; redraw(); }
void KListView::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KListView::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_push_clip(x(), y(), w(), h()); fl_color(t.controlBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    if (items_.empty()) { drawText(emptyText_, x(), y(), w(), h(), t.mutedText, FL_ALIGN_CENTER); fl_pop_clip(); return; }
    int cy = y() + 1; for (int i = 0; i < static_cast<int>(items_.size()) && cy < y() + h(); ++i, cy += itemHeight_) {
        const bool kSelected = i == activeIndex_, kHover = i == hoverIndex_ && items_[i].enabled; fl_color(kSelected ? t.selection : (kHover ? t.hover : (i % 2 ? t.controlAltBg : t.controlBg))); fl_rectf(x() + 1, cy, w() - 2, itemHeight_);
        if (kSelected) { fl_color(kAccent); fl_rectf(x() + 1, cy, 3, itemHeight_); }
        drawText(items_[i].title, x() + 10, cy + 4, w() - 100, 18, items_[i].enabled ? (kSelected ? kAccent : t.text) : t.mutedText, FL_ALIGN_LEFT, kTitleFont);
        drawText(items_[i].detail, x() + 10, cy + 23, w() - 100, 16, t.mutedText, FL_ALIGN_LEFT); drawText(items_[i].meta, x() + w() - 86, cy, 76, itemHeight_, t.mutedText, FL_ALIGN_RIGHT);
    }
    fl_pop_clip();
}

int KListView::handle(int event) {
    const int kRow = (Fl::event_y() - y() - 1) / itemHeight_; const bool kValid = kRow >= 0 && kRow < static_cast<int>(items_.size());
    if (event == FL_MOVE || event == FL_ENTER) { hoverIndex_ = kValid ? kRow : -1; redraw(); return 1; }
    if (event == FL_LEAVE) { hoverIndex_ = -1; redraw(); return 1; }
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) {
        if (kValid && items_[kRow].enabled) { activeIndex_ = kRow; do_callback(); redraw(); return 1; }
    }
    return Fl_Group::handle(event);
}

KPropertyGrid::KPropertyGrid(int x, int y, int w, int h, const char* label) : Fl_Widget(x, y, w, h, label), properties_(), nameColumnWidth_(0), rowHeight_(24) {
    // PropertyGrid stores simple name/value pairs and does not edit them directly.
    box(FL_FLAT_BOX);
}

void KPropertyGrid::setProperties(const std::vector<KPropertyItem>& properties) { properties_ = properties; redraw(); }
void KPropertyGrid::setProperty(const char* name, const char* value) {
    const std::string kKey = name ? name : ""; for (KPropertyItem& item : properties_) if (item.name == kKey) { item.value = value ? value : ""; redraw(); return; }
    properties_.push_back(KPropertyItem{ kKey, value ? value : "" }); redraw();
}
void KPropertyGrid::clear() { properties_.clear(); redraw(); }
void KPropertyGrid::setNameColumnWidth(int width) { nameColumnWidth_ = std::max(0, width); redraw(); }
int KPropertyGrid::nameColumnWidth() const { return nameColumnWidth_; }
void KPropertyGrid::setRowHeight(int height) { rowHeight_ = std::max(18, height); redraw(); }

void KPropertyGrid::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const int kRowH = rowHeight_, kKeyW = nameColumnWidth_ > 0 ? std::min(nameColumnWidth_, std::max(40, w() - 60)) : w() / 3;
    fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border); fl_color(t.border); fl_line(x() + kKeyW, y(), x() + kKeyW, y() + h());
    for (int i = 0; i < static_cast<int>(properties_.size()); ++i) { const int kCy = y() + i * kRowH; if (kCy >= y() + h()) break; fl_color(i % 2 ? t.controlAltBg : t.controlBg); fl_rectf(x() + 1, kCy + 1, w() - 2, kRowH - 1); drawText(properties_[i].name, x() + 8, kCy, kKeyW - 12, kRowH, t.mutedText, FL_ALIGN_LEFT); drawText(properties_[i].value, x() + kKeyW + 8, kCy, w() - kKeyW - 16, kRowH, t.text, FL_ALIGN_LEFT); }
    fl_pop_clip();
}

KKeyValueTable::KKeyValueTable(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), rows_(), keyHeader_("Key"), valueHeader_("Value") {
    // KeyValueTable is read-only and intentionally independent from KTable.
    box(FL_FLAT_BOX);
}

void KKeyValueTable::setRows(const std::vector<KKeyValueRow>& rows) { rows_ = rows; redraw(); }
void KKeyValueTable::addRow(const char* key, const char* value) { rows_.push_back(KKeyValueRow{ key ? key : "", value ? value : "" }); redraw(); }
void KKeyValueTable::setHeaders(const char* keyHeader, const char* valueHeader) { keyHeader_ = keyHeader ? keyHeader : ""; valueHeader_ = valueHeader ? valueHeader : ""; redraw(); }
void KKeyValueTable::clear() { rows_.clear(); redraw(); }

void KKeyValueTable::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const int kRowH = 24, kSplit = w() / 2;
    fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    fl_color(t.controlAltBg); fl_rectf(x() + 1, y() + 1, w() - 2, kRowH); drawText(keyHeader_, x() + 8, y(), kSplit - 12, kRowH, t.text, FL_ALIGN_LEFT, kTitleFont); drawText(valueHeader_, x() + kSplit + 8, y(), w() - kSplit - 16, kRowH, t.text, FL_ALIGN_LEFT, kTitleFont);
    fl_color(t.border); fl_line(x() + kSplit, y(), x() + kSplit, y() + h()); for (int i = 0; i < static_cast<int>(rows_.size()); ++i) { const int kCy = y() + kRowH * (i + 1); if (kCy >= y() + h()) break; fl_color(i % 2 ? t.controlAltBg : t.controlBg); fl_rectf(x() + 1, kCy + 1, w() - 2, kRowH - 1); drawText(rows_[i].key, x() + 8, kCy, kSplit - 12, kRowH, t.mutedText, FL_ALIGN_LEFT); drawText(rows_[i].value, x() + kSplit + 8, kCy, w() - kSplit - 16, kRowH, t.text, FL_ALIGN_LEFT); }
    fl_pop_clip();
}

KMiniChart::KMiniChart(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), values_(), type_(KMiniChartType::kLine), autoRange_(true), minimum_(0.0), maximum_(1.0), accentColor_(FL_BACKGROUND_COLOR) {
    // MiniChart is data-only and draws line/bar variants from the same value vector.
    box(FL_FLAT_BOX);
}

void KMiniChart::setValues(const std::vector<double>& values) { values_ = values; redraw(); }
void KMiniChart::setType(KMiniChartType type) { type_ = type; redraw(); }
void KMiniChart::setRange(double minimum, double maximum) { minimum_ = minimum; maximum_ = maximum; autoRange_ = false; redraw(); }
void KMiniChart::setAutoRange(bool enabled) { autoRange_ = enabled; redraw(); }
void KMiniChart::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KMiniChart::draw() {
    const KTheme& t = KThemeManager::instance().theme(); fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    if (values_.empty()) { drawText("No data", x(), y(), w(), h(), t.mutedText, FL_ALIGN_CENTER); fl_pop_clip(); return; }
    double mn = minimum_, mx = maximum_; if (autoRange_) { mn = *std::min_element(values_.begin(), values_.end()); mx = *std::max_element(values_.begin(), values_.end()); }
    const int kLeft = x() + 6, kTop = y() + 6, kCw = std::max(1, w() - 12), kCh = std::max(1, h() - 12); fl_color(resolveAccent(accentColor_));
    if (type_ == KMiniChartType::kBar) { const int kBw = std::max(2, kCw / static_cast<int>(values_.size())); for (int i = 0; i < static_cast<int>(values_.size()); ++i) { const int kBh = static_cast<int>(normalize(values_[i], mn, mx) * kCh); fl_rectf(kLeft + i * kBw, kTop + kCh - kBh, std::max(1, kBw - 2), kBh); } }
    else { for (int i = 1; i < static_cast<int>(values_.size()); ++i) { const int kX1 = kLeft + (i - 1) * kCw / std::max(1, static_cast<int>(values_.size()) - 1), kX2 = kLeft + i * kCw / std::max(1, static_cast<int>(values_.size()) - 1); const int kY1 = kTop + kCh - static_cast<int>(normalize(values_[i - 1], mn, mx) * kCh), kY2 = kTop + kCh - static_cast<int>(normalize(values_[i], mn, mx) * kCh); fl_line(kX1, kY1, kX2, kY2); } }
    fl_pop_clip();
}

KProgressRing::KProgressRing(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), value_(0.0), text_(label ? label : ""), accentColor_(FL_BACKGROUND_COLOR) {
    // Ring uses repeated arcs for thickness while keeping FLTK-only drawing.
    box(FL_FLAT_BOX);
}

void KProgressRing::setValue(double value) { value_ = std::max(0.0, std::min(1.0, value)); redraw(); }
double KProgressRing::value() const { return value_; }
void KProgressRing::setText(const char* text) { text_ = text ? text : ""; redraw(); }
void KProgressRing::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KProgressRing::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const int kSize = std::max(1, std::min(w(), h()) - 8); const int kOx = x() + (w() - kSize) / 2, kOy = y() + (h() - kSize) / 2;
    const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h());
    for (int i = 0; i < 4; ++i) { fl_color(t.border); fl_arc(kOx + i, kOy + i, kSize - i * 2, kSize - i * 2, 0, 360); fl_color(kAccent); fl_arc(kOx + i, kOy + i, kSize - i * 2, kSize - i * 2, 90, 90 - 360 * value_); }
    const std::string kLabel = text_.empty() ? std::to_string(static_cast<int>(value_ * 100.0 + 0.5)) + "%" : text_; drawText(kLabel, x(), y(), w(), h(), t.text, FL_ALIGN_CENTER, kTitleFont); fl_pop_clip();
}

KStepper::KStepper(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), steps_(), activeIndex_(-1), accentColor_(FL_BACKGROUND_COLOR) {
    // Stepper stores a sequence of steps and paints them horizontally.
    box(FL_FLAT_BOX);
}

void KStepper::setSteps(const std::vector<KStepItem>& steps) { steps_ = steps; activeIndex_ = clampIndex(activeIndex_, steps_.size()); redraw(); }
void KStepper::setActiveIndex(int index) { activeIndex_ = clampIndex(index, steps_.size()); redraw(); }
int KStepper::activeIndex() const { return activeIndex_; }
void KStepper::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KStepper::draw() {
    const KTheme& t = KThemeManager::instance().theme(); fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    const Fl_Color kAccent = resolveAccent(accentColor_);
    if (steps_.empty()) { drawText("No steps", x(), y(), w(), h(), t.mutedText, FL_ALIGN_CENTER); fl_pop_clip(); return; }
    const int kCount = static_cast<int>(steps_.size()), kCy = y() + 26; for (int i = 0; i < kCount; ++i) {
        const int kCx = x() + 20 + (kCount == 1 ? 0 : i * (w() - 40) / (kCount - 1)); if (i > 0) { const int kPx = x() + 20 + (i - 1) * (w() - 40) / std::max(1, kCount - 1); fl_color((i <= activeIndex_ || steps_[i - 1].completed) ? kAccent : t.border); fl_line(kPx + 6, kCy, kCx - 6, kCy); }
        fl_color(i == activeIndex_ || steps_[i].completed ? kAccent : t.controlAltBg); fl_rectf(kCx - 6, kCy - 6, 12, 12); drawBorder(kCx - 6, kCy - 6, 12, 12, t.border);
        drawText(steps_[i].title, kCx - 50, kCy + 12, 100, 18, steps_[i].enabled ? t.text : t.mutedText, FL_ALIGN_CENTER); drawText(steps_[i].detail, kCx - 50, kCy + 30, 100, 18, t.mutedText, FL_ALIGN_CENTER);
    }
    fl_pop_clip();
}

int KStepper::handle(int event) {
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE && !steps_.empty()) {
        const int kCount = static_cast<int>(steps_.size()); int best = -1, bestDist = 999999;
        for (int i = 0; i < kCount; ++i) { const int kCx = x() + 20 + (kCount == 1 ? 0 : i * (w() - 40) / (kCount - 1)); const int kDist = std::abs(Fl::event_x() - kCx); if (kDist < bestDist) { best = i; bestDist = kDist; } }
        if (best >= 0 && bestDist <= 24 && steps_[best].enabled) { activeIndex_ = best; do_callback(); redraw(); return 1; }
    }
    return Fl_Widget::handle(event);
}
