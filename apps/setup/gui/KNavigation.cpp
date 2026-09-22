#include "KNavigation.h"

#include "fl_draw.H"

#include <algorithm>
#include <cctype>
#include <functional>

namespace {
constexpr int kFont = 12;
constexpr int kTitleFont = 14;

// DrawText clips and paints text with FLTK fonts; input text is copied by caller-owned strings and no value is returned.
void drawText(const std::string& text, int x, int y, int w, int h, Fl_Color color, Fl_Align align, int size = kFont) {
    if (text.empty() || w <= 0 || h <= 0) return;
    fl_color(color); fl_font(FL_HELVETICA, size); fl_draw(text.c_str(), x, y, w, h, align | FL_ALIGN_INSIDE);
}

// drawBorder paints the square one-pixel frame used by all navigation widgets; returns no value.
void drawBorder(int x, int y, int w, int h, Fl_Color color) { fl_color(color); fl_rect(x, y, w, h); }

// clampIndex returns a valid index for non-empty collections, otherwise -1.
int clampIndex(int index, std::size_t count) { return count == 0 ? -1 : std::max(0, std::min(index, static_cast<int>(count) - 1)); }

// resolveAccent returns the current theme primary unless callers supplied an explicit accent color.
Fl_Color resolveAccent(Fl_Color color) { return color == FL_BACKGROUND_COLOR ? KThemeManager::instance().theme().primary : color; }

// lowerCopy normalizes command text for simple case-insensitive filtering.
std::string lowerCopy(const std::string& text) {
    std::string out = text;
    for (char& ch : out) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return out;
}

// commandMatches returns true when query appears in title, subtitle, or shortcut.
bool commandMatches(const KCommand& command, const std::string& query) {
    if (query.empty()) return true;
    return lowerCopy(command.title + " " + command.subtitle + " " + command.shortcut).find(query) != std::string::npos;
}

// treeNodeSelfMatches checks the searchable fields for one tree row.
bool treeNodeSelfMatches(const KTreeNode& node, const std::string& query) {
    if (query.empty()) return true;
    return lowerCopy(node.text + " " + node.icon + " " + node.badge).find(query) != std::string::npos;
}

// treeNodeBranchMatches checks whether a tree row or any descendant matches a filter query.
bool treeNodeBranchMatches(const KTreeNode& node, const std::string& query) {
    if (treeNodeSelfMatches(node, query)) return true;
    for (const KTreeNode& child : node.children) if (treeNodeBranchMatches(child, query)) return true;
    return false;
}

// setExpandedRecursive applies one expansion state to every node below the supplied vector.
void setExpandedRecursive(std::vector<KTreeNode>& nodes, bool expanded) {
    for (KTreeNode& node : nodes) { node.expanded = expanded; setExpandedRecursive(node.children, expanded); }
}
}

KBreadcrumb::KBreadcrumb(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), items_(), activeIndex_(-1), hoverIndex_(-1), accentColor_(FL_BACKGROUND_COLOR) {
    // Store only visual state; all colors are pulled from KThemeManager during draw().
    box(FL_FLAT_BOX); labelfont(FL_HELVETICA); labelsize(kFont);
}

void KBreadcrumb::setItems(const std::vector<std::string>& items) { items_ = items; activeIndex_ = clampIndex(activeIndex_, items_.size()); hoverIndex_ = -1; redraw(); }
void KBreadcrumb::addItem(const char* text) { items_.push_back(text ? text : ""); if (activeIndex_ < 0) activeIndex_ = 0; redraw(); }
void KBreadcrumb::clear() { items_.clear(); activeIndex_ = -1; hoverIndex_ = -1; redraw(); }
void KBreadcrumb::setActiveIndex(int index) { activeIndex_ = clampIndex(index, items_.size()); redraw(); }
int KBreadcrumb::activeIndex() const { return activeIndex_; }
void KBreadcrumb::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }
Fl_Color KBreadcrumb::accentColor() const { return resolveAccent(accentColor_); }

int KBreadcrumb::itemAt(int mouseX, int mouseY) const {
    if (mouseY < y() || mouseY >= y() + h()) return -1;
    fl_font(FL_HELVETICA, kFont); int cursor = x() + 8;
    for (int i = 0; i < static_cast<int>(items_.size()); ++i) {
        const int kItemW = static_cast<int>(fl_width(items_[i].c_str())) + 18;
        if (mouseX >= cursor && mouseX < cursor + kItemW) return i;
        cursor += kItemW + 14;
    }
    return -1;
}

void KBreadcrumb::draw() {
    const KTheme& t = KThemeManager::instance().theme();
    const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    fl_font(FL_HELVETICA, kFont); int cursor = x() + 8;
    for (int i = 0; i < static_cast<int>(items_.size()); ++i) {
        const int kItemW = static_cast<int>(fl_width(items_[i].c_str())) + 18;
        const bool kActive = i == activeIndex_, kHover = i == hoverIndex_;
        fl_color(kActive ? t.selection : (kHover ? t.hover : t.panelBg)); fl_rectf(cursor, y() + 4, kItemW, h() - 8);
        drawText(items_[i], cursor + 8, y(), kItemW - 16, h(), kActive ? kAccent : t.text, FL_ALIGN_CENTER);
        if (i + 1 < static_cast<int>(items_.size())) drawText(">", cursor + kItemW + 2, y(), 10, h(), t.mutedText, FL_ALIGN_CENTER);
        cursor += kItemW + 14;
    }
    fl_pop_clip();
}

int KBreadcrumb::handle(int event) {
    if (event == FL_MOVE || event == FL_ENTER) { hoverIndex_ = itemAt(Fl::event_x(), Fl::event_y()); redraw(); return 1; }
    if (event == FL_LEAVE) { hoverIndex_ = -1; redraw(); return 1; }
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) {
        const int kIndex = itemAt(Fl::event_x(), Fl::event_y());
        if (kIndex >= 0) { activeIndex_ = kIndex; do_callback(); redraw(); return 1; }
    }
    return Fl_Widget::handle(event);
}

KSideNav::KSideNav(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label), items_(), activeIndex_(-1), hoverIndex_(-1), itemHeight_(34), accentColor_(FL_BACKGROUND_COLOR) {
    // The side nav owns row data only; close FLTK child capture to avoid accidental parenting.
    box(FL_FLAT_BOX); end();
}

void KSideNav::setItems(const std::vector<KNavItem>& items) { items_ = items; activeIndex_ = clampIndex(activeIndex_, items_.size()); redraw(); }
void KSideNav::addItem(const char* text) { KNavItem item; item.text = text ? text : ""; items_.push_back(item); if (activeIndex_ < 0) activeIndex_ = 0; redraw(); }
void KSideNav::clear() { items_.clear(); activeIndex_ = -1; hoverIndex_ = -1; redraw(); }
void KSideNav::setActiveIndex(int index) { activeIndex_ = (index >= 0 && index < static_cast<int>(items_.size()) && items_[index].enabled) ? index : (index < 0 ? -1 : activeIndex_); redraw(); }
int KSideNav::activeIndex() const { return activeIndex_; }
void KSideNav::setItemHeight(int height) { itemHeight_ = std::max(20, height); redraw(); }
void KSideNav::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KSideNav::draw() {
    const KTheme& t = KThemeManager::instance().theme(); int cy = y() + 6;
    const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    if (label() && label()[0]) { drawText(label(), x() + 10, cy, w() - 20, 18, t.mutedText, FL_ALIGN_LEFT); cy += 24; }
    for (int i = 0; i < static_cast<int>(items_.size()); ++i, cy += itemHeight_) {
        const bool kActive = i == activeIndex_, kHover = i == hoverIndex_ && items_[i].enabled;
        fl_color(kActive ? t.selection : (kHover ? t.hover : t.panelBg)); fl_rectf(x() + 4, cy, w() - 8, itemHeight_ - 2);
        if (kActive) { fl_color(kAccent); fl_rectf(x() + 4, cy, 3, itemHeight_ - 2); }
        drawText(items_[i].text, x() + 14, cy, w() - 58, itemHeight_ - 2, items_[i].enabled ? (kActive ? kAccent : t.text) : t.mutedText, FL_ALIGN_LEFT);
        drawText(items_[i].badge, x() + w() - 48, cy, 36, itemHeight_ - 2, t.mutedText, FL_ALIGN_RIGHT);
    }
    fl_pop_clip();
}

int KSideNav::handle(int event) {
    const int kOffset = (label() && label()[0]) ? 30 : 6; const int kIndex = (Fl::event_y() - y() - kOffset) / itemHeight_;
    const bool kValid = kIndex >= 0 && kIndex < static_cast<int>(items_.size());
    if (event == FL_MOVE || event == FL_ENTER) { hoverIndex_ = kValid ? kIndex : -1; redraw(); return 1; }
    if (event == FL_LEAVE) { hoverIndex_ = -1; redraw(); return 1; }
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE && kValid && items_[kIndex].enabled) { activeIndex_ = kIndex; do_callback(); redraw(); return 1; }
    return Fl_Group::handle(event);
}

KTopNav::KTopNav(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label), items_(), activeIndex_(-1), hoverIndex_(-1), accentColor_(FL_BACKGROUND_COLOR) {
    // Top nav is a self-painted strip with measured row boxes.
    box(FL_FLAT_BOX); end();
}

void KTopNav::setItems(const std::vector<KNavItem>& items) { items_ = items; activeIndex_ = clampIndex(activeIndex_, items_.size()); redraw(); }
void KTopNav::addItem(const char* text) { KNavItem item; item.text = text ? text : ""; items_.push_back(item); if (activeIndex_ < 0) activeIndex_ = 0; redraw(); }
void KTopNav::clear() { items_.clear(); activeIndex_ = -1; hoverIndex_ = -1; redraw(); }
void KTopNav::setActiveIndex(int index) { activeIndex_ = (index >= 0 && index < static_cast<int>(items_.size()) && items_[index].enabled) ? index : (index < 0 ? -1 : activeIndex_); redraw(); }
int KTopNav::activeIndex() const { return activeIndex_; }
void KTopNav::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

int KTopNav::itemAt(int mouseX, int mouseY) const {
    if (mouseY < y() || mouseY >= y() + h()) return -1;
    fl_font(FL_HELVETICA, kFont); int cursor = x() + 8;
    for (int i = 0; i < static_cast<int>(items_.size()); ++i) { const int kIw = static_cast<int>(fl_width(items_[i].text.c_str())) + 34; if (mouseX >= cursor && mouseX < cursor + kIw) return i; cursor += kIw; }
    return -1;
}

void KTopNav::draw() {
    const KTheme& t = KThemeManager::instance().theme(); fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_font(FL_HELVETICA, kFont); int cursor = x() + 8;
    for (int i = 0; i < static_cast<int>(items_.size()); ++i) {
        const int kIw = static_cast<int>(fl_width(items_[i].text.c_str())) + 34; const bool kActive = i == activeIndex_, kHover = i == hoverIndex_ && items_[i].enabled;
        fl_color(kActive ? t.selection : (kHover ? t.hover : t.panelBg)); fl_rectf(cursor, y() + 3, kIw, h() - 6);
        drawText(items_[i].text, cursor + 12, y(), kIw - 24, h(), items_[i].enabled ? (kActive ? kAccent : t.text) : t.mutedText, FL_ALIGN_CENTER);
        if (kActive) { fl_color(kAccent); fl_rectf(cursor + 8, y() + h() - 4, kIw - 16, 2); }
        cursor += kIw;
    }
    fl_pop_clip();
}

int KTopNav::handle(int event) {
    if (event == FL_MOVE || event == FL_ENTER) { hoverIndex_ = itemAt(Fl::event_x(), Fl::event_y()); redraw(); return 1; }
    if (event == FL_LEAVE) { hoverIndex_ = -1; redraw(); return 1; }
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) { const int kIndex = itemAt(Fl::event_x(), Fl::event_y()); if (kIndex >= 0 && items_[kIndex].enabled) { activeIndex_ = kIndex; do_callback(); redraw(); return 1; } }
    return Fl_Group::handle(event);
}

struct KTreeView::VisibleRow { const KTreeNode* node = nullptr; std::vector<int> path; int depth = 0; };

KTreeView::KTreeView(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label), roots_(), selectedPath_(), hoverPath_(), itemHeight_(24), accentColor_(FL_BACKGROUND_COLOR), showRootLines_(true), filterText_() {
    // Tree view is a leaf group so callers can create widgets after it safely.
    box(FL_FLAT_BOX); end();
}

void KTreeView::setItems(const std::vector<KTreeNode>& items) { roots_ = items; if (!nodeAtPath(selectedPath_)) selectedPath_.clear(); redraw(); }
void KTreeView::clear() { roots_.clear(); selectedPath_.clear(); redraw(); }
void KTreeView::setActiveIndex(int index) { const auto kRows = visibleRows(); selectedPath_ = (index >= 0 && index < static_cast<int>(kRows.size())) ? kRows[index].path : std::vector<int>(); redraw(); }
int KTreeView::activeIndex() const { const auto kRows = visibleRows(); for (int i = 0; i < static_cast<int>(kRows.size()); ++i) if (kRows[i].path == selectedPath_) return i; return -1; }
std::string KTreeView::selectedText() const { const KTreeNode* n = nodeAtPath(selectedPath_); return n ? n->text : std::string(); }
void KTreeView::setItemHeight(int height) { itemHeight_ = std::max(18, height); redraw(); }
void KTreeView::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }
void KTreeView::expandAll() { setExpandedRecursive(roots_, true); redraw(); }
void KTreeView::collapseAll() { setExpandedRecursive(roots_, false); redraw(); }
void KTreeView::setFilterText(const char* text) { filterText_ = text ? text : ""; selectedPath_.clear(); hoverPath_.clear(); redraw(); }
const std::string& KTreeView::filterText() const { return filterText_; }
void KTreeView::setShowRootLines(bool show) { showRootLines_ = show; redraw(); }
bool KTreeView::showRootLines() const { return showRootLines_; }
std::vector<int> KTreeView::selectedPath() const { return selectedPath_; }
void KTreeView::setSelectedPath(const std::vector<int>& path) { selectedPath_ = nodeAtPath(path) ? path : std::vector<int>(); redraw(); }

std::vector<KTreeView::VisibleRow> KTreeView::visibleRows() const {
    std::vector<VisibleRow> rows; const std::string kQuery = lowerCopy(filterText_);
    // Recursion copies only row metadata while node storage stays owned by roots_; filters force matching branches open visually.
    std::function<void(const std::vector<KTreeNode>&, std::vector<int>, int)> collect;
    collect = [&](const std::vector<KTreeNode>& nodes, std::vector<int> path, int depth) -> void {
        for (int i = 0; i < static_cast<int>(nodes.size()); ++i) {
            if (!treeNodeBranchMatches(nodes[i], kQuery)) continue;
            std::vector<int> p = path; p.push_back(i); VisibleRow row; row.node = &nodes[i]; row.path = p; row.depth = depth; rows.push_back(row);
            if ((nodes[i].expanded || !kQuery.empty()) && !nodes[i].children.empty()) collect(nodes[i].children, p, depth + 1);
        }
    };
    collect(roots_, std::vector<int>(), 0); return rows;
}

KTreeNode* KTreeView::nodeAtPath(const std::vector<int>& path) { std::vector<KTreeNode>* level = &roots_; KTreeNode* node = nullptr; for (int index : path) { if (index < 0 || index >= static_cast<int>(level->size())) return nullptr; node = &(*level)[index]; level = &node->children; } return node; }
const KTreeNode* KTreeView::nodeAtPath(const std::vector<int>& path) const { const std::vector<KTreeNode>* level = &roots_; const KTreeNode* node = nullptr; for (int index : path) { if (index < 0 || index >= static_cast<int>(level->size())) return nullptr; node = &(*level)[index]; level = &node->children; } return node; }

void KTreeView::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const auto kRows = visibleRows(); int cy = y() + 4;
    const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_push_clip(x(), y(), w(), h()); fl_color(t.controlBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    if (kRows.empty()) { drawText(filterText_.empty() ? "No nodes" : "No matching nodes", x(), y(), w(), h(), t.mutedText, FL_ALIGN_CENTER); fl_pop_clip(); return; }
    for (const VisibleRow& row : kRows) {
        if (cy >= y() + h()) break; const bool kSelected = row.path == selectedPath_; const bool kHover = row.path == hoverPath_; const int kIndent = row.depth * 16; const bool kHasChildren = row.node && !row.node->children.empty();
        fl_color(kSelected ? t.selection : (kHover && row.node && row.node->enabled ? t.hover : t.controlBg)); fl_rectf(x() + 1, cy, w() - 2, itemHeight_);
        if (showRootLines_ && row.depth > 0) { fl_color(t.border); const int kGuideX = x() + 15 + (row.depth - 1) * 16; fl_line(kGuideX, cy, kGuideX, cy + itemHeight_); fl_line(kGuideX, cy + itemHeight_ / 2, kGuideX + 12, cy + itemHeight_ / 2); }
        drawText(kHasChildren ? (row.node->expanded || !filterText_.empty() ? "-" : "+") : "", x() + 8 + kIndent, cy, 14, itemHeight_, kAccent, FL_ALIGN_CENTER);
        const int kIconW = row.node && !row.node->icon.empty() ? 18 : 0; drawText(row.node ? row.node->icon : std::string(), x() + 26 + kIndent, cy, kIconW, itemHeight_, kAccent, FL_ALIGN_CENTER);
        drawText(row.node ? row.node->text : std::string(), x() + 28 + kIndent + kIconW, cy, w() - 76 - kIndent - kIconW, itemHeight_, row.node && row.node->enabled ? t.text : t.mutedText, FL_ALIGN_LEFT);
        drawText(row.node ? row.node->badge : std::string(), x() + w() - 46, cy, 36, itemHeight_, t.mutedText, FL_ALIGN_RIGHT); cy += itemHeight_;
    }
    fl_pop_clip();
}

int KTreeView::handle(int event) {
    const int kIndex = (Fl::event_y() - y() - 4) / itemHeight_; const auto kRows = visibleRows(); const bool kValid = kIndex >= 0 && kIndex < static_cast<int>(kRows.size());
    if (event == FL_MOVE || event == FL_ENTER) { hoverPath_ = kValid ? kRows[kIndex].path : std::vector<int>(); redraw(); return 1; }
    if (event == FL_LEAVE) { hoverPath_.clear(); redraw(); return 1; }
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE && kValid) {
        KTreeNode* node = nodeAtPath(kRows[kIndex].path); if (!node || !node->enabled) return 1;
        if (filterText_.empty() && !node->children.empty() && Fl::event_x() < x() + 24 + kRows[kIndex].depth * 16) node->expanded = !node->expanded; else { selectedPath_ = kRows[kIndex].path; do_callback(); }
        redraw(); return 1;
    }
    return Fl_Group::handle(event);
}

KCommandPalette::KCommandPalette(int x, int y, int w, int h, const char* label)
    : Fl_Window(x, y, w, h, label ? label : "Command Palette"), commands_(), query_(), placeholder_("Type a command"), activeIndex_(0), selectedCommand_(-1) {
    // Palette is modal and self-painted; no title bar or child controls are required.
    border(0); set_modal(); box(FL_FLAT_BOX); end();
}

void KCommandPalette::setItems(const std::vector<KCommand>& commands) { commands_ = commands; activeIndex_ = 0; selectedCommand_ = -1; redraw(); }
void KCommandPalette::setQuery(const char* query) { query_ = query ? query : ""; activeIndex_ = 0; redraw(); }
const std::string& KCommandPalette::query() const { return query_; }
void KCommandPalette::setPlaceholder(const char* text) { placeholder_ = text ? text : ""; redraw(); }
void KCommandPalette::setActiveIndex(int index) { activeIndex_ = clampIndex(index, filteredIndexes().size()); redraw(); }
int KCommandPalette::activeIndex() const { return activeIndex_; }
int KCommandPalette::runModal() { selectedCommand_ = -1; show(); while (shown()) Fl::wait(); return selectedCommand_; }
int KCommandPalette::selectedCommand() const { return selectedCommand_; }

std::vector<int> KCommandPalette::filteredIndexes() const {
    std::vector<int> indexes; const std::string kQuery = lowerCopy(query_);
    for (int i = 0; i < static_cast<int>(commands_.size()); ++i) if (commandMatches(commands_[i], kQuery)) indexes.push_back(i);
    return indexes;
}

void KCommandPalette::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const std::vector<int> kVisible = filteredIndexes(); activeIndex_ = clampIndex(activeIndex_, kVisible.size());
    fl_push_clip(0, 0, w(), h()); fl_color(t.panelBg); fl_rectf(0, 0, w(), h()); drawBorder(0, 0, w(), h(), t.border);
    fl_color(t.controlBg); fl_rectf(12, 12, w() - 24, 34); drawBorder(12, 12, w() - 24, 34, t.border);
    drawText(query_.empty() ? placeholder_ : query_, 22, 12, w() - 44, 34, query_.empty() ? t.mutedText : t.text, FL_ALIGN_LEFT);
    int cy = 56; if (kVisible.empty()) drawText("No commands", 12, cy, w() - 24, 42, t.mutedText, FL_ALIGN_CENTER);
    for (int row = 0; row < static_cast<int>(kVisible.size()) && cy + 42 <= h() - 8; ++row, cy += 42) {
        const KCommand& c = commands_[kVisible[row]]; fl_color(row == activeIndex_ ? t.selection : t.panelBg); fl_rectf(12, cy, w() - 24, 40);
        drawText(c.title, 22, cy + 4, w() - 132, 18, c.enabled ? t.text : t.mutedText, FL_ALIGN_LEFT, kTitleFont);
        drawText(c.subtitle, 22, cy + 22, w() - 132, 16, t.mutedText, FL_ALIGN_LEFT); drawText(c.shortcut, w() - 112, cy, 90, 40, t.mutedText, FL_ALIGN_RIGHT);
    }
    fl_pop_clip();
}

int KCommandPalette::handle(int event) {
    if (event == FL_KEYDOWN) {
        const std::vector<int> kVisible = filteredIndexes();
        if (Fl::event_key() == FL_Escape) { hide(); return 1; }
        if (Fl::event_key() == FL_Up) { setActiveIndex(activeIndex_ - 1); return 1; }
        if (Fl::event_key() == FL_Down) { setActiveIndex(activeIndex_ + 1); return 1; }
        if (Fl::event_key() == FL_Enter || Fl::event_key() == FL_KP_Enter) { if (activeIndex_ >= 0 && activeIndex_ < static_cast<int>(kVisible.size()) && commands_[kVisible[activeIndex_]].enabled) { selectedCommand_ = kVisible[activeIndex_]; do_callback(); hide(); } return 1; }
        if (Fl::event_key() == FL_BackSpace) { if (!query_.empty()) { query_.pop_back(); activeIndex_ = 0; redraw(); } return 1; }
        const char* text = Fl::event_text(); if (text && Fl::event_length() > 0 && static_cast<unsigned char>(text[0]) >= 32) { query_.append(text, static_cast<std::size_t>(Fl::event_length())); activeIndex_ = 0; redraw(); return 1; }
    }
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) { const int kRow = (Fl::event_y() - 56) / 42; const std::vector<int> kVisible = filteredIndexes(); if (kRow >= 0 && kRow < static_cast<int>(kVisible.size()) && commands_[kVisible[kRow]].enabled) { activeIndex_ = kRow; selectedCommand_ = kVisible[kRow]; do_callback(); hide(); return 1; } }
    return Fl_Window::handle(event);
}

KSectionHeader::KSectionHeader(int x, int y, int w, int h, const char* label)
    : Fl_Widget(x, y, w, h, label), text_(label ? label : ""), subtitle_(), actionText_(), accentColor_(FL_BACKGROUND_COLOR) {
    // Header is a paint-only title block except for optional action hit testing.
    box(FL_FLAT_BOX);
}

void KSectionHeader::setText(const char* text) { text_ = text ? text : ""; redraw(); }
const std::string& KSectionHeader::text() const { return text_; }
void KSectionHeader::setSubtitle(const char* text) { subtitle_ = text ? text : ""; redraw(); }
void KSectionHeader::setActionText(const char* text) { actionText_ = text ? text : ""; redraw(); }
void KSectionHeader::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

void KSectionHeader::draw() {
    const KTheme& t = KThemeManager::instance().theme(); fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h());
    const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_color(kAccent); fl_rectf(x(), y() + 9, 3, std::max(10, h() - 18));
    drawText(text_, x() + 12, y() + 4, w() - 130, 20, t.text, FL_ALIGN_LEFT, kTitleFont); drawText(subtitle_, x() + 12, y() + 24, w() - 130, 18, t.mutedText, FL_ALIGN_LEFT);
    drawText(actionText_, x() + w() - 110, y(), 98, h(), kAccent, FL_ALIGN_RIGHT); fl_color(t.border); fl_line(x(), y() + h() - 1, x() + w(), y() + h() - 1); fl_pop_clip();
}

int KSectionHeader::handle(int event) {
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE && !actionText_.empty() && Fl::event_x() >= x() + w() - 120) { do_callback(); return 1; }
    return Fl_Widget::handle(event);
}


KCardGrid::KCardGrid(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label), items_(), activeIndex_(-1), hoverIndex_(-1), columns_(3), gap_(10), accentColor_(FL_BACKGROUND_COLOR) {
    // CardGrid is self-painted and does not participate in lower-level layout algorithms.
    box(FL_FLAT_BOX); end();
}

void KCardGrid::setItems(const std::vector<KCardGridItem>& items) { items_ = items; activeIndex_ = clampIndex(activeIndex_, items_.size()); hoverIndex_ = -1; redraw(); }
void KCardGrid::addItem(const KCardGridItem& item) { items_.push_back(item); if (activeIndex_ < 0) activeIndex_ = 0; redraw(); }
void KCardGrid::clear() { items_.clear(); activeIndex_ = -1; hoverIndex_ = -1; redraw(); }
void KCardGrid::setActiveIndex(int index) { activeIndex_ = clampIndex(index, items_.size()); redraw(); }
int KCardGrid::activeIndex() const { return activeIndex_; }
void KCardGrid::setColumns(int columns) { columns_ = std::max(1, columns); redraw(); }
void KCardGrid::setGap(int gap) { gap_ = std::max(0, gap); redraw(); }
void KCardGrid::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

int KCardGrid::cardAt(int mouseX, int mouseY) const {
    if (mouseX < x() || mouseX >= x() + w() || mouseY < y() || mouseY >= y() + h() || items_.empty()) return -1;
    const int kCols = std::max(1, columns_); const int kCardW = std::max(1, (w() - gap_ * (kCols + 1)) / kCols); const int kCardH = 78;
    const int kRelX = mouseX - x() - gap_, kRelY = mouseY - y() - gap_; if (kRelX < 0 || kRelY < 0) return -1;
    const int kCol = kRelX / (kCardW + gap_), kRow = kRelY / (kCardH + gap_); if (kCol < 0 || kCol >= kCols || kRelX % (kCardW + gap_) >= kCardW || kRelY % (kCardH + gap_) >= kCardH) return -1;
    const int kIndex = kRow * kCols + kCol; return kIndex >= 0 && kIndex < static_cast<int>(items_.size()) ? kIndex : -1;
}

void KCardGrid::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    if (items_.empty()) { drawText("No cards", x(), y(), w(), h(), t.mutedText, FL_ALIGN_CENTER); fl_pop_clip(); return; }
    const int kCols = std::max(1, columns_); const int kCardW = std::max(1, (w() - gap_ * (kCols + 1)) / kCols); const int kCardH = 78;
    for (int i = 0; i < static_cast<int>(items_.size()); ++i) { const int kRow = i / kCols, kCol = i % kCols; const int kCx = x() + gap_ + kCol * (kCardW + gap_), kCy = y() + gap_ + kRow * (kCardH + gap_); if (kCy >= y() + h()) break;
        const bool kActive = i == activeIndex_, kHover = i == hoverIndex_ && items_[i].enabled; fl_color(kActive ? t.selection : (kHover ? t.hover : t.controlBg)); fl_rectf(kCx, kCy, kCardW, kCardH); drawBorder(kCx, kCy, kCardW, kCardH, kActive ? kAccent : t.border);
        if (kActive) { fl_color(kAccent); fl_rectf(kCx, kCy, 4, kCardH); } drawText(items_[i].title, kCx + 12, kCy + 10, kCardW - 24, 20, items_[i].enabled ? t.text : t.mutedText, FL_ALIGN_LEFT, kTitleFont);
        drawText(items_[i].subtitle, kCx + 12, kCy + 32, kCardW - 24, 18, t.mutedText, FL_ALIGN_LEFT); drawText(items_[i].meta, kCx + 12, kCy + kCardH - 26, kCardW - 24, 18, t.mutedText, FL_ALIGN_RIGHT); }
    fl_pop_clip();
}

int KCardGrid::handle(int event) {
    if (event == FL_MOVE || event == FL_ENTER) { hoverIndex_ = cardAt(Fl::event_x(), Fl::event_y()); redraw(); return 1; }
    if (event == FL_LEAVE) { hoverIndex_ = -1; redraw(); return 1; }
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) { const int kIndex = cardAt(Fl::event_x(), Fl::event_y()); if (kIndex >= 0 && items_[kIndex].enabled) { activeIndex_ = kIndex; do_callback(); redraw(); return 1; } }
    return Fl_Group::handle(event);
}

KSection::KSection(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label), title_(label ? label : ""), subtitle_(), actionText_(), headerHeight_(54), accentColor_(FL_BACKGROUND_COLOR) {
    // Section hosts caller children below a painted header without imposing layout rules.
    box(FL_FLAT_BOX); end();
}

void KSection::setTitle(const char* text) { title_ = text ? text : ""; redraw(); }
void KSection::setSubtitle(const char* text) { subtitle_ = text ? text : ""; redraw(); }
void KSection::setActionText(const char* text) { actionText_ = text ? text : ""; redraw(); }
void KSection::setHeaderHeight(int height) { headerHeight_ = std::max(32, height); redraw(); }
void KSection::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }
int KSection::contentY() const { return y() + headerHeight_; }

void KSection::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const Fl_Color kAccent = resolveAccent(accentColor_);
    fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border); fl_color(kAccent); fl_rectf(x(), y(), 4, headerHeight_);
    drawText(title_, x() + 14, y() + 8, w() - 126, 20, t.text, FL_ALIGN_LEFT, kTitleFont); drawText(subtitle_, x() + 14, y() + 30, w() - 126, 18, t.mutedText, FL_ALIGN_LEFT); drawText(actionText_, x() + w() - 108, y(), 96, headerHeight_, kAccent, FL_ALIGN_RIGHT);
    fl_color(t.border); fl_line(x(), y() + headerHeight_, x() + w(), y() + headerHeight_); fl_pop_clip(); draw_children();
}

int KSection::handle(int event) {
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE && !actionText_.empty() && Fl::event_y() < y() + headerHeight_ && Fl::event_x() >= x() + w() - 120) { do_callback(); return 1; }
    return Fl_Group::handle(event);
}

KInspectorPanel::KInspectorPanel(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label), sections_(), rowHeight_(26), headerHeight_(30), accentColor_(FL_BACKGROUND_COLOR) {
    // InspectorPanel is read-only by default; editable intent is indicated per row for host integration.
    box(FL_FLAT_BOX); end();
}

void KInspectorPanel::setSections(const std::vector<KInspectorSection>& sections) { sections_ = sections; redraw(); }
void KInspectorPanel::addSection(const KInspectorSection& section) { sections_.push_back(section); redraw(); }
void KInspectorPanel::clear() { sections_.clear(); redraw(); }
void KInspectorPanel::setSectionExpanded(int index, bool expanded) { if (index >= 0 && index < static_cast<int>(sections_.size())) { sections_[index].expanded = expanded; redraw(); } }
void KInspectorPanel::setRowHeight(int height) { rowHeight_ = std::max(20, height); redraw(); }
void KInspectorPanel::setAccentColor(Fl_Color color) { accentColor_ = color; redraw(); }

int KInspectorPanel::sectionAt(int mouseY) const {
    int cy = y() + 1; for (int i = 0; i < static_cast<int>(sections_.size()); ++i) { if (mouseY >= cy && mouseY < cy + headerHeight_) return i; cy += headerHeight_; if (sections_[i].expanded) cy += static_cast<int>(sections_[i].fields.size()) * rowHeight_; }
    return -1;
}

void KInspectorPanel::draw() {
    const KTheme& t = KThemeManager::instance().theme(); const Fl_Color kAccent = resolveAccent(accentColor_); int cy = y() + 1;
    fl_push_clip(x(), y(), w(), h()); fl_color(t.panelBg); fl_rectf(x(), y(), w(), h()); drawBorder(x(), y(), w(), h(), t.border);
    if (sections_.empty()) { drawText("No inspector data", x(), y(), w(), h(), t.mutedText, FL_ALIGN_CENTER); fl_pop_clip(); return; }
    for (int i = 0; i < static_cast<int>(sections_.size()) && cy < y() + h(); ++i) { const KInspectorSection& section = sections_[i]; fl_color(t.controlAltBg); fl_rectf(x() + 1, cy, w() - 2, headerHeight_); drawText(section.expanded ? "-" : "+", x() + 8, cy, 16, headerHeight_, kAccent, FL_ALIGN_CENTER); drawText(section.title, x() + 30, cy, w() - 40, headerHeight_, t.text, FL_ALIGN_LEFT, kTitleFont); cy += headerHeight_;
        if (!section.expanded) continue; for (int r = 0; r < static_cast<int>(section.fields.size()) && cy < y() + h(); ++r, cy += rowHeight_) { const KInspectorField& field = section.fields[r]; fl_color(r % 2 ? t.controlAltBg : t.controlBg); fl_rectf(x() + 1, cy, w() - 2, rowHeight_); drawText(field.name, x() + 12, cy, w() / 3, rowHeight_, t.mutedText, FL_ALIGN_LEFT); drawText(field.value, x() + w() / 3 + 16, cy, w() * 2 / 3 - 28, rowHeight_, field.readOnly ? t.text : kAccent, FL_ALIGN_LEFT); drawText(field.hint, x() + w() - 72, cy, 60, rowHeight_, t.mutedText, FL_ALIGN_RIGHT); } }
    fl_pop_clip();
}

int KInspectorPanel::handle(int event) {
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) { const int kIndex = sectionAt(Fl::event_y()); if (kIndex >= 0) { sections_[kIndex].expanded = !sections_[kIndex].expanded; do_callback(); redraw(); return 1; } }
    return Fl_Group::handle(event);
}

KCardGrid* kCreateCardGrid(int x, int y, int w, int h, const char* label) { return new KCardGrid(x, y, w, h, label); }
KSection* kCreateSection(int x, int y, int w, int h, const char* label) { return new KSection(x, y, w, h, label); }
KInspectorPanel* kCreateInspectorPanel(int x, int y, int w, int h, const char* label) { return new KInspectorPanel(x, y, w, h, label); }
