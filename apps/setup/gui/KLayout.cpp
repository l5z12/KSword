#include "KLayout.h"

#include "fl_draw.H"

#include <algorithm>

namespace {
constexpr int kFont = 12;
constexpr int kTitleFont = 14;

// DrawText renders clipped text with the shared K typography; returns no value.
void drawText(const std::string& text, int x, int y, int w, int h, Fl_Color color, Fl_Align align, int size = kFont) {
    if (text.empty() || w <= 0 || h <= 0) return;
    fl_color(color); fl_font(FL_HELVETICA, size); fl_draw(text.c_str(), x, y, w, h, align | FL_ALIGN_INSIDE);
}

// drawBorder renders the one-pixel square frame used by layout containers.
void drawBorder(int x, int y, int w, int h, Fl_Color color) { fl_color(color); fl_rect(x, y, w, h); }

// clampRatio keeps splitter panes usable even with extreme input.
double clampRatio(double ratio) { return std::max(0.1, std::min(0.9, ratio)); }

// hasOnlyChildDamage prevents container backgrounds from being repainted during
// child-only updates such as text caret blinking, input focus, or table cell
// selection. Inputs are live widgets; output is true when only child damage is set.
bool hasOnlyChildDamage(const Fl_Widget* widget) {
    if (!widget) {
        return false;
    }
    const unsigned int kDamage = widget->damage();
    return (kDamage & FL_DAMAGE_CHILD) != 0 &&
        (kDamage & (FL_DAMAGE_ALL | FL_DAMAGE_EXPOSE)) == 0;
}
}

KSize::KSize(int widthValue, int heightValue)
    : width(widthValue),
    height(heightValue) {
    // Value type constructor stores caller-provided dimensions directly.  The
    // layout algorithms clamp when consuming hints, so this constructor returns
    // no value and performs no hidden policy decisions.
}

KMargins::KMargins(int leftValue, int topValue, int rightValue, int bottomValue)
    : left(leftValue),
    top(topValue),
    right(rightValue),
    bottom(bottomValue) {
    // Margins are stored in Qt-compatible left/top/right/bottom order and are
    // later subtracted from the available layout rectangle.
}

KSizePolicy::KSizePolicy(KSizePolicyType horizontal, KSizePolicyType vertical, int horizontalStretch, int verticalStretch)
    : horizontalPolicy_(horizontal),
    verticalPolicy_(vertical),
    horizontalStretch_(std::max(0, horizontalStretch)),
    verticalStretch_(std::max(0, verticalStretch)) {
    // The policy object only stores metadata; layouts decide how each policy
    // affects geometry during activate()/layoutChildren().
}

KSizePolicy KSizePolicy::fixed() { return KSizePolicy(KSizePolicyType::kFixed, KSizePolicyType::kFixed, 0, 0); }
KSizePolicy KSizePolicy::minimum() { return KSizePolicy(KSizePolicyType::kMinimum, KSizePolicyType::kMinimum, 0, 0); }
KSizePolicy KSizePolicy::expanding(int horizontalStretch, int verticalStretch) { return KSizePolicy(KSizePolicyType::kExpanding, KSizePolicyType::kExpanding, horizontalStretch, verticalStretch); }
KSizePolicy KSizePolicy::fill(int horizontalStretch, int verticalStretch) { return KSizePolicy(KSizePolicyType::kFill, KSizePolicyType::kFill, horizontalStretch, verticalStretch); }
KSizePolicyType KSizePolicy::horizontalPolicy() const { return horizontalPolicy_; }
KSizePolicyType KSizePolicy::verticalPolicy() const { return verticalPolicy_; }
void KSizePolicy::setHorizontalPolicy(KSizePolicyType policy) { horizontalPolicy_ = policy; }
void KSizePolicy::setVerticalPolicy(KSizePolicyType policy) { verticalPolicy_ = policy; }
int KSizePolicy::horizontalStretch() const { return horizontalStretch_; }
int KSizePolicy::verticalStretch() const { return verticalStretch_; }
void KSizePolicy::setHorizontalStretch(int stretch) { horizontalStretch_ = std::max(0, stretch); }
void KSizePolicy::setVerticalStretch(int stretch) { verticalStretch_ = std::max(0, stretch); }

KLayoutItem::KLayoutItem()
    : widget(nullptr),
    sizePolicy(KSizePolicy::fill()),
    minimumSize(0, 0),
    preferredSize(0, 0),
    maximumSize(kKLayoutMaximumSize, kKLayoutMaximumSize),
    stretch(0),
    row(0),
    column(0),
    rowSpan(1),
    columnSpan(1),
    hasMinimumSize(false),
    hasPreferredSize(false),
    hasMaximumSize(false) {
    // Empty metadata is safe for vector storage and ignored until a widget is set.
}

KLayoutItem::KLayoutItem(Fl_Widget* widgetValue)
    : KLayoutItem() {
    // Capture construction geometry as the initial preferred size.  Callers can
    // later override these hints with setSizeHints().
    widget = widgetValue;
    if (widget) {
        preferredSize = KSize(widget->w(), widget->h());
        hasPreferredSize = true;
    }
}

KStack::KStack(int x, int y, int w, int h, const char* label) : Fl_Group(x, y, w, h, label), activeIndex_(0) {
    // Stack is a normal FLTK container; callers add page children between begin()/end().
    box(FL_FLAT_BOX); resizable(this);
}

void KStack::setActiveIndex(int index) { activeIndex_ = children() == 0 ? -1 : std::max(0, std::min(index, children() - 1)); layoutChildren(); redraw(); }
int KStack::activeIndex() const { return children() == 0 ? -1 : activeIndex_; }

void KStack::layoutChildren() {
    // Only the active page is visible; every page is resized to fill the stack content box.
    if (children() == 0) { activeIndex_ = -1; return; }
    activeIndex_ = std::max(0, std::min(activeIndex_, children() - 1));
    for (int i = 0; i < children(); ++i) { child(i)->resize(x() + 1, y() + 1, std::max(0, w() - 2), std::max(0, h() - 2)); i == activeIndex_ ? child(i)->show() : child(i)->hide(); }
}

void KStack::draw() {
    if (hasOnlyChildDamage(this)) {
        // Child repaint only: keep the stack shell untouched and let FLTK draw
        // the damaged page widgets so sibling content is not erased.
        draw_children();
        return;
    }
    const KTheme& t = KThemeManager::instance().theme();
    layoutChildren();
    fl_color(t.panelBg);
    fl_rectf(x(), y(), w(), h());
    drawBorder(x(), y(), w(), h(), t.border);
    draw_children();
}
void KStack::resize(int x, int y, int w, int h) { Fl_Group::resize(x, y, w, h); layoutChildren(); }

KGridLayout::KGridLayout(int x, int y, int w, int h, const char* label) : Fl_Group(x, y, w, h, label), rows_(1), columns_(1), spacing_(8), margins_(8, 8, 8, 8), dirty_(true) {
    // Grid metadata is simple and deterministic so child ordering matches FLTK child order.
    box(FL_FLAT_BOX); resizable(this);
}

void KGridLayout::setGrid(int rows, int columns) { rows_ = std::max(1, rows); columns_ = std::max(1, columns); layoutChildren(); redraw(); }
void KGridLayout::setSpacing(int spacing) { spacing_ = std::max(0, spacing); dirty_ = true; layoutChildren(); redraw(); }
void KGridLayout::setGap(int gap) { setSpacing(gap); }
void KGridLayout::setContentsMargins(int left, int top, int right, int bottom) { margins_ = KMargins(std::max(0, left), std::max(0, top), std::max(0, right), std::max(0, bottom)); dirty_ = true; layoutChildren(); redraw(); }
void KGridLayout::setPadding(int padding) { const int kSafe = std::max(0, padding); setContentsMargins(kSafe, kSafe, kSafe, kSafe); }

void KGridLayout::layoutChildren() {
    // Children beyond rows*columns are left at their current geometry but hidden to avoid overlap.
    const int kContentW = w() - margins_.left - margins_.right - spacing_ * (columns_ - 1);
    const int kContentH = h() - margins_.top - margins_.bottom - spacing_ * (rows_ - 1);
    const int kCellW = std::max(1, kContentW / columns_);
    const int kCellH = std::max(1, kContentH / rows_);
    for (int i = 0; i < children(); ++i) {
        if (i >= rows_ * columns_) { child(i)->hide(); continue; }
        const int kRow = i / columns_, kCol = i % columns_; child(i)->show();
        child(i)->resize(x() + margins_.left + kCol * (kCellW + spacing_), y() + margins_.top + kRow * (kCellH + spacing_), kCellW, kCellH);
    }
}

void KGridLayout::draw() {
    if (hasOnlyChildDamage(this)) {
        // Grid geometry is unchanged during child-only updates; avoid clearing
        // the layout surface underneath focused inputs or tables.
        draw_children();
        return;
    }
    const KTheme& t = KThemeManager::instance().theme();
    layoutChildren();
    fl_color(t.panelBg);
    fl_rectf(x(), y(), w(), h());
    drawBorder(x(), y(), w(), h(), t.border);
    draw_children();
}
void KGridLayout::resize(int x, int y, int w, int h) { Fl_Group::resize(x, y, w, h); layoutChildren(); }

KVBox::KVBox(int x, int y, int w, int h, const char* label) : Fl_Group(x, y, w, h, label), spacing_(8), margins_(8, 8, 8, 8), dirty_(true) {
    // VBox distributes available height evenly across currently visible children.
    box(FL_FLAT_BOX); resizable(this);
}

void KVBox::setSpacing(int spacing) { spacing_ = std::max(0, spacing); dirty_ = true; layoutChildren(); redraw(); }
void KVBox::setGap(int gap) { setSpacing(gap); }
void KVBox::setContentsMargins(int left, int top, int right, int bottom) { margins_ = KMargins(std::max(0, left), std::max(0, top), std::max(0, right), std::max(0, bottom)); dirty_ = true; layoutChildren(); redraw(); }
void KVBox::setPadding(int padding) { const int kSafe = std::max(0, padding); setContentsMargins(kSafe, kSafe, kSafe, kSafe); }

void KVBox::layoutChildren() {
    int visibleCount = 0; for (int i = 0; i < children(); ++i) if (child(i)->visible()) ++visibleCount;
    const int kContentH = h() - margins_.top - margins_.bottom - spacing_ * (visibleCount - 1);
    const int kItemH = visibleCount == 0 ? 0 : std::max(1, kContentH / visibleCount);
    int cy = y() + margins_.top; for (int i = 0; i < children(); ++i) if (child(i)->visible()) { child(i)->resize(x() + margins_.left, cy, std::max(1, w() - margins_.left - margins_.right), kItemH); cy += kItemH + spacing_; }
}

void KVBox::draw() {
    if (hasOnlyChildDamage(this)) {
        // A child editor can redraw independently; repainting the VBox panel
        // would wipe neighboring children until the next full expose.
        draw_children();
        return;
    }
    const KTheme& t = KThemeManager::instance().theme();
    layoutChildren();
    fl_color(t.panelBg);
    fl_rectf(x(), y(), w(), h());
    drawBorder(x(), y(), w(), h(), t.border);
    draw_children();
}
void KVBox::resize(int x, int y, int w, int h) { Fl_Group::resize(x, y, w, h); layoutChildren(); }

KHBox::KHBox(int x, int y, int w, int h, const char* label) : Fl_Group(x, y, w, h, label), spacing_(8), margins_(8, 8, 8, 8), dirty_(true) {
    // HBox distributes available width evenly across currently visible children.
    box(FL_FLAT_BOX); resizable(this);
}

void KHBox::setSpacing(int spacing) { spacing_ = std::max(0, spacing); dirty_ = true; layoutChildren(); redraw(); }
void KHBox::setGap(int gap) { setSpacing(gap); }
void KHBox::setContentsMargins(int left, int top, int right, int bottom) { margins_ = KMargins(std::max(0, left), std::max(0, top), std::max(0, right), std::max(0, bottom)); dirty_ = true; layoutChildren(); redraw(); }
void KHBox::setPadding(int padding) { const int kSafe = std::max(0, padding); setContentsMargins(kSafe, kSafe, kSafe, kSafe); }

void KHBox::layoutChildren() {
    int visibleCount = 0; for (int i = 0; i < children(); ++i) if (child(i)->visible()) ++visibleCount;
    const int kContentW = w() - margins_.left - margins_.right - spacing_ * (visibleCount - 1);
    const int kItemW = visibleCount == 0 ? 0 : std::max(1, kContentW / visibleCount);
    int cx = x() + margins_.left; for (int i = 0; i < children(); ++i) if (child(i)->visible()) { child(i)->resize(cx, y() + margins_.top, kItemW, std::max(1, h() - margins_.top - margins_.bottom)); cx += kItemW + spacing_; }
}

void KHBox::draw() {
    if (hasOnlyChildDamage(this)) {
        // Preserve the HBox background and siblings during child-only focus or
        // selection repaints.
        draw_children();
        return;
    }
    const KTheme& t = KThemeManager::instance().theme();
    layoutChildren();
    fl_color(t.panelBg);
    fl_rectf(x(), y(), w(), h());
    drawBorder(x(), y(), w(), h(), t.border);
    draw_children();
}
void KHBox::resize(int x, int y, int w, int h) { Fl_Group::resize(x, y, w, h); layoutChildren(); }

KSplitterPane::KSplitterPane(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label), orientation_(KSplitterPaneOrientation::kHorizontal), ratio_(0.5), dragging_(false) {
    // Splitter arranges only the first two children; extra children retain caller geometry.
    box(FL_FLAT_BOX); resizable(this);
}

void KSplitterPane::setOrientation(KSplitterPaneOrientation orientation) { orientation_ = orientation; layoutChildren(); redraw(); }
void KSplitterPane::setRatio(double ratio) { ratio_ = clampRatio(ratio); layoutChildren(); redraw(); }
double KSplitterPane::ratio() const { return ratio_; }

void KSplitterPane::layoutChildren() {
    if (children() < 2) return; const int kDivider = 6;
    if (orientation_ == KSplitterPaneOrientation::kHorizontal) {
        const int kFirstW = static_cast<int>((w() - kDivider) * ratio_); child(0)->resize(x(), y(), kFirstW, h()); child(1)->resize(x() + kFirstW + kDivider, y(), w() - kFirstW - kDivider, h());
    } else {
        const int kFirstH = static_cast<int>((h() - kDivider) * ratio_); child(0)->resize(x(), y(), w(), kFirstH); child(1)->resize(x(), y() + kFirstH + kDivider, w(), h() - kFirstH - kDivider);
    }
}

void KSplitterPane::draw() {
    if (hasOnlyChildDamage(this) && !dragging_) {
        // While not dragging, child-only updates belong entirely to pane
        // contents; do not repaint the split surface or divider.
        draw_children();
        return;
    }
    const KTheme& t = KThemeManager::instance().theme();
    layoutChildren();
    fl_color(t.panelBg);
    fl_rectf(x(), y(), w(), h());
    draw_children();
    if (children() >= 2) {
        fl_color(dragging_ ? t.primary : t.border);
        if (orientation_ == KSplitterPaneOrientation::kHorizontal) {
            const int kDx = child(0)->x() + child(0)->w();
            fl_rectf(kDx, y(), 6, h());
        }
        else {
            const int kDy = child(0)->y() + child(0)->h();
            fl_rectf(x(), kDy, w(), 6);
        }
    }
}

int KSplitterPane::handle(int event) {
    if (children() < 2) return Fl_Group::handle(event); const int kDivider = 6; const int kDx = child(0)->x() + child(0)->w(); const int kDy = child(0)->y() + child(0)->h();
    const bool kHit = orientation_ == KSplitterPaneOrientation::kHorizontal ? (Fl::event_x() >= kDx && Fl::event_x() <= kDx + kDivider) : (Fl::event_y() >= kDy && Fl::event_y() <= kDy + kDivider);
    if (event == FL_PUSH && kHit) { dragging_ = true; return 1; }
    if (event == FL_RELEASE && dragging_) { dragging_ = false; redraw(); return 1; }
    if (event == FL_DRAG && dragging_) { setRatio(orientation_ == KSplitterPaneOrientation::kHorizontal ? static_cast<double>(Fl::event_x() - x()) / std::max(1, w()) : static_cast<double>(Fl::event_y() - y()) / std::max(1, h())); return 1; }
    return Fl_Group::handle(event);
}

void KSplitterPane::resize(int x, int y, int w, int h) { Fl_Group::resize(x, y, w, h); layoutChildren(); }

KAccordion::KAccordion(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label), sections_(), activeIndex_(-1), headerHeight_(30) {
    // Accordion owns text sections only and is not a child container.
    box(FL_FLAT_BOX); end();
}

void KAccordion::setSections(const std::vector<KAccordionSection>& sections) { sections_ = sections; activeIndex_ = sections_.empty() ? -1 : std::max(0, std::min(activeIndex_, static_cast<int>(sections_.size()) - 1)); redraw(); }
void KAccordion::toggleSection(int index) { if (index >= 0 && index < static_cast<int>(sections_.size()) && sections_[index].enabled) { sections_[index].expanded = !sections_[index].expanded; activeIndex_ = index; redraw(); } }
void KAccordion::setActiveIndex(int index) { activeIndex_ = (index >= 0 && index < static_cast<int>(sections_.size())) ? index : -1; redraw(); }
int KAccordion::activeIndex() const { return activeIndex_; }

void KAccordion::draw() {
    const KTheme& t = KThemeManager::instance().theme(); int cy = y(); fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    for (int i = 0; i < static_cast<int>(sections_.size()) && cy < y() + h(); ++i) {
        const auto& s = sections_[i]; fl_color(i == activeIndex_ ? t.selection : t.controlBg); fl_rectf(x() + 1, cy + 1, w() - 2, headerHeight_ - 1);
        drawText(s.expanded ? "-" : "+", x() + 10, cy, 16, headerHeight_, t.primary, FL_ALIGN_CENTER); drawText(s.title, x() + 32, cy, w() - 42, headerHeight_, s.enabled ? t.text : t.mutedText, FL_ALIGN_LEFT, kTitleFont); cy += headerHeight_;
        if (s.expanded) { drawText(s.content, x() + 14, cy + 4, w() - 28, 48, t.mutedText, FL_ALIGN_LEFT | FL_ALIGN_TOP); cy += 56; }
    }
    fl_pop_clip();
}

int KAccordion::handle(int event) {
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) { int cy = y(); for (int i = 0; i < static_cast<int>(sections_.size()); ++i) { if (Fl::event_y() >= cy && Fl::event_y() < cy + headerHeight_) { toggleSection(i); do_callback(); return 1; } cy += headerHeight_ + (sections_[i].expanded ? 56 : 0); } }
    return Fl_Group::handle(event);
}

KExpander::KExpander(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label), text_(label ? label : ""), expanded_(true), headerHeight_(28) {
    // Expander is a real container; child visibility follows expanded_.
    box(FL_FLAT_BOX); resizable(this);
}

void KExpander::setText(const char* text) { text_ = text ? text : ""; redraw(); }
void KExpander::setExpanded(bool expanded) { expanded_ = expanded; layoutChildren(); redraw(); }
bool KExpander::expanded() const { return expanded_; }

void KExpander::layoutChildren() {
    for (int i = 0; i < children(); ++i) { expanded_ ? child(i)->show() : child(i)->hide(); if (expanded_) child(i)->resize(x() + 8, y() + headerHeight_ + 6, std::max(1, w() - 16), std::max(1, h() - headerHeight_ - 14)); }
}

void KExpander::draw() {
    if (hasOnlyChildDamage(this)) {
        // The header did not change; repaint only expanded children.
        if (expanded_) {
            draw_children();
        }
        return;
    }
    const KTheme& t = KThemeManager::instance().theme();
    layoutChildren();
    fl_color(t.panelBg);
    fl_rectf(x(), y(), w(), h());
    drawBorder(x(), y(), w(), h(), t.border);
    fl_color(t.controlAltBg);
    fl_rectf(x() + 1, y() + 1, w() - 2, headerHeight_);
    drawText(expanded_ ? "-" : "+", x() + 8, y(), 18, headerHeight_, t.primary, FL_ALIGN_CENTER);
    drawText(text_, x() + 30, y(), w() - 38, headerHeight_, t.text, FL_ALIGN_LEFT, kTitleFont);
    if (expanded_) {
        draw_children();
    }
}

int KExpander::handle(int event) { if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE && Fl::event_y() >= y() && Fl::event_y() < y() + headerHeight_) { setExpanded(!expanded_); do_callback(); return 1; } return Fl_Group::handle(event); }

KGroupBox::KGroupBox(int x, int y, int w, int h, const char* label) : Fl_Group(x, y, w, h, label), title_(label ? label : "") {
    // GroupBox is a normal child container with a title row.
    box(FL_FLAT_BOX); resizable(this);
}

void KGroupBox::setTitle(const char* title) { title_ = title ? title : ""; label(title_.c_str()); redraw(); }
const std::string& KGroupBox::title() const { return title_; }

void KGroupBox::draw() {
    if (hasOnlyChildDamage(this)) {
        // Keep titled frame pixels stable during child-only redraws.
        draw_children();
        return;
    }
    const KTheme& t = KThemeManager::instance().theme();
    fl_color(t.panelBg);
    fl_rectf(x(), y(), w(), h());
    drawBorder(x(), y(), w(), h(), t.border);
    fl_color(t.controlAltBg);
    fl_rectf(x() + 1, y() + 1, w() - 2, 26);
    drawText(title_, x() + 10, y() + 1, w() - 20, 26, t.text, FL_ALIGN_LEFT, kTitleFont);
    draw_children();
}

KScrollablePanel::KScrollablePanel(int x, int y, int w, int h, const char* label)
    : Fl_Scroll(x, y, w, h, label), padding_(8), backgroundColor_(FL_BACKGROUND_COLOR) {
    // Scroll panel uses FLTK scrolling while painting its background from KThemeManager.
    box(FL_FLAT_BOX); resizable(this);
}

void KScrollablePanel::setContentPadding(int padding) { padding_ = std::max(0, padding); redraw(); }
void KScrollablePanel::setBackgroundColor(Fl_Color color) { backgroundColor_ = color; redraw(); }

void KScrollablePanel::draw() {
    if (hasOnlyChildDamage(this)) {
        // Scroll children repaint themselves; avoid filling the viewport over
        // partially redrawn editors or table cells.
        draw_children();
        return;
    }
    const KTheme& t = KThemeManager::instance().theme();
    (void)padding_;
    fl_color(backgroundColor_ == FL_BACKGROUND_COLOR ? t.panelBg : backgroundColor_);
    fl_rectf(x(), y(), w(), h());
    drawBorder(x(), y(), w(), h(), t.border);
    Fl_Scroll::draw();
}
