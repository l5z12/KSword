#include "KDock.h"
#include "KTheme.h"
#include "Fl.H"
#include "fl_draw.H"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <functional>
#include <map>
#include <sstream>
#include <utility>

// KDockSplitOrientation describes how one split node divides its rectangle.
// Horizontal splits allocate width to left/right children, and vertical splits
// allocate height to top/bottom children.
enum class KDockSplitOrientation {
    kHorizontal,
    kVertical
};

// KDockLayoutNode is the manager's private split tree.  Leaf nodes reference a
// KDockArea tab container, while split nodes own two child nodes and a ratio.
class KDockLayoutNode {
public:
    // Creates a leaf node for one dock area; callers attach it into the tree.
    explicit KDockLayoutNode(KDockArea* leafArea)
        : isLeaf(true),
        area(leafArea),
        orientation(KDockSplitOrientation::kHorizontal),
        firstRatio(500),
        parent(nullptr),
        first(nullptr),
        second(nullptr) {
    }

    // Creates a split node and connects both children back to this parent.
    KDockLayoutNode(KDockSplitOrientation splitOrientation,
        KDockLayoutNode* firstChild,
        KDockLayoutNode* secondChild,
        int ratioPermille)
        : isLeaf(false),
        area(nullptr),
        orientation(splitOrientation),
        firstRatio(ratioPermille),
        parent(nullptr),
        first(firstChild),
        second(secondChild) {
        if (first) {
            first->parent = this;
        }
        if (second) {
            second->parent = this;
        }
    }

    bool isLeaf;
    KDockArea* area;
    KDockSplitOrientation orientation;
    int firstRatio;
    KDockLayoutNode* parent;
    KDockLayoutNode* first;
    KDockLayoutNode* second;
};

// KDockFloatingWindow is the temporary top-level host used after a dock leaves
// the manager.  FLTK can deliver drag/release events to the grabbed window
// instead of the reparented KDockWidget, so this window forwards those events
// back to the dock and keeps drag-out/redock interaction deterministic.
class KDockFloatingWindow : public Fl_Window {
public:
    // Creates a regular top-level window and stores the dock that owns it.
    KDockFloatingWindow(int x, int y, int w, int h, const char* title, KDockWidget* dock)
        : Fl_Window(x, y, w, h, title),
        dock_(dock) {
    }

    // Rebinds the proxied dock when the host is reused; returns no value.
    void setDockWidget(KDockWidget* dock) {
        dock_ = dock;
    }

    // Proxies active drag events to the dock, otherwise uses normal FLTK window handling.
    int handle(int event) override {
        if (dock_ && dock_->hasActiveFloatingDrag()) {
            if (event == FL_DRAG) {
                dock_->continueFloatingDrag(Fl::event_x_root(), Fl::event_y_root());
                return 1;
            }
            if (event == FL_RELEASE) {
                dock_->finishFloatingDrag(Fl::event_x_root(), Fl::event_y_root());
                return 1;
            }
        }
        return Fl_Window::handle(event);
    }

private:
    KDockWidget* dock_;
};

namespace {
// Dock metrics are intentionally small so the module stays lightweight and native.
const int kTitleHeight = 24;
const int kTabHeight = 24;
const int kButtonSize = 16;
const int kButtonGap = 4;
const int kTitleButtonCount = 3;
const int kMargin = 3;
const int kMinClientSize = 24;
const int kDragThreshold = 4;
const int kDropGuideSize = 32;
const int kDropGuideInset = 12;
const int kDropPreviewMin = 36;

// hasOnlyChildDamage mirrors the container guard used by KPanel/KCard. Inputs
// are live widgets; output is true when FLTK is repainting only damaged children
// and the dock shell must not clear its whole rectangle.
bool hasOnlyChildDamage(const Fl_Widget* widget) {
    if (!widget) {
        return false;
    }
    const uchar kDamage = widget->damage();
    return (kDamage & FL_DAMAGE_CHILD) != 0 &&
        (kDamage & (FL_DAMAGE_ALL | FL_DAMAGE_EXPOSE)) == 0;
}

// Dock palette helpers read the active runtime theme without storing stale colors.
Fl_Color kColorWindow() { return KThemeManager::instance().theme().windowBg; }
Fl_Color kColorPanel() { return KThemeManager::instance().theme().panelBg; }
Fl_Color kColorBorder() { return KThemeManager::instance().theme().border; }
Fl_Color kColorPrimary() { return KThemeManager::instance().theme().primary; }
Fl_Color kColorPrimaryDark() { return KThemeManager::instance().theme().primaryDark; }
Fl_Color kColorText() { return KThemeManager::instance().theme().text; }
Fl_Color kColorMuted() { return KThemeManager::instance().theme().mutedText; }
// Converts an area enum into a stable token used by saveLayout().
const char* positionToToken(KDockAreaPosition position) {
    switch (position) {
    case KDockAreaPosition::kLeft:
        return "Left";
    case KDockAreaPosition::kRight:
        return "Right";
    case KDockAreaPosition::kTop:
        return "Top";
    case KDockAreaPosition::kBottom:
        return "Bottom";
    case KDockAreaPosition::kCenter:
    default:
        return "Center";
    }
}
// Parses a stable area token used by restoreLayout().
bool tokenToPosition(const std::string& token, KDockAreaPosition& position) {
    if (token == "Left") {
        position = KDockAreaPosition::kLeft;
        return true;
    }
    if (token == "Right") {
        position = KDockAreaPosition::kRight;
        return true;
    }
    if (token == "Top") {
        position = KDockAreaPosition::kTop;
        return true;
    }
    if (token == "Bottom") {
        position = KDockAreaPosition::kBottom;
        return true;
    }
    if (token == "Center") {
        position = KDockAreaPosition::kCenter;
        return true;
    }
    return false;
}
// Converts a drop overlay side into the current fixed KDockManager region.
KDockAreaPosition sideToPosition(KDockDropSide side) {
    switch (side) {
    case KDockDropSide::kLeft:
        return KDockAreaPosition::kLeft;
    case KDockDropSide::kRight:
        return KDockAreaPosition::kRight;
    case KDockDropSide::kTop:
        return KDockAreaPosition::kTop;
    case KDockDropSide::kBottom:
        return KDockAreaPosition::kBottom;
    case KDockDropSide::kCenter:
        return KDockAreaPosition::kCenter;
    case KDockDropSide::kNone:
    default:
        return KDockAreaPosition::kCenter;
    }
}
// Picks a center target when the pointer is away from edges, otherwise returns
// the nearest side.  The caller passes manager or dock-local coordinates.
KDockDropSide sideForPointInBox(int localX, int localY, int width, int height) {
    int safeW = std::max(1, width);
    int safeH = std::max(1, height);
    int centerLeft = safeW / 3;
    int centerRight = safeW - centerLeft;
    int centerTop = safeH / 3;
    int centerBottom = safeH - centerTop;
    if (localX >= centerLeft && localX < centerRight &&
        localY >= centerTop && localY < centerBottom) {
        return KDockDropSide::kCenter;
    }
    int leftDistance = std::max(0, localX);
    int rightDistance = std::max(0, safeW - 1 - localX);
    int topDistance = std::max(0, localY);
    int bottomDistance = std::max(0, safeH - 1 - localY);
    int best = std::min(std::min(leftDistance, rightDistance), std::min(topDistance, bottomDistance));
    if (best == leftDistance) {
        return KDockDropSide::kLeft;
    }
    if (best == rightDistance) {
        return KDockDropSide::kRight;
    }
    if (best == topDistance) {
        return KDockDropSide::kTop;
    }
    return KDockDropSide::kBottom;
}
// Escapes layout text so titles can contain separators without breaking restore.
std::string escapeTitle(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        if (ch == '\\' || ch == '|' || ch == '\n' || ch == '\r') {
            out.push_back('\\');
            if (ch == '\n') {
                out.push_back('n');
            }
            else if (ch == '\r') {
                out.push_back('r');
            }
            else {
                out.push_back(ch);
            }
        }
        else {
            out.push_back(ch);
        }
    }
    return out;
}
// Reverses escapeTitle() and tolerates simple unknown escape sequences.
std::string unescapeTitle(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 1 < value.size()) {
            ++i;
            if (value[i] == 'n') {
                out.push_back('\n');
            }
            else if (value[i] == 'r') {
                out.push_back('\r');
            }
            else {
                out.push_back(value[i]);
            }
        }
        else {
            out.push_back(value[i]);
        }
    }
    return out;
}
// Draws a compact square title-button with one printable glyph.
void drawTitleButton(int x, int y, const char* glyph, Fl_Color bg) {
    fl_color(bg);
    fl_rectf(x, y, kButtonSize, kButtonSize);
    fl_color(kColorBorder());
    fl_rect(x, y, kButtonSize, kButtonSize);
    fl_color(kColorText());
    fl_font(FL_HELVETICA_BOLD, 11);
    fl_draw(glyph, x, y, kButtonSize, kButtonSize, FL_ALIGN_CENTER);
}
// Draws one square docking guide marker and highlights the active target side.
void drawDropGuide(int x, int y, const char* label, bool active) {
    Fl_Color fill = active ? kColorPrimary() : fl_color_average(kColorPanel(), kColorWindow(), 0.65f);
    Fl_Color text = active ? FL_WHITE : kColorText();
    fl_color(fill);
    fl_rectf(x, y, kDropGuideSize, kDropGuideSize);
    fl_color(active ? kColorPrimaryDark() : kColorBorder());
    fl_rect(x, y, kDropGuideSize, kDropGuideSize);
    fl_color(text);
    fl_font(FL_HELVETICA_BOLD, 12);
    fl_draw(label, x, y, kDropGuideSize, kDropGuideSize, FL_ALIGN_CENTER);
}
// Draws the five target markers around either the manager or a hovered dock widget.
void drawDropGuideSet(int boxX, int boxY, int boxW, int boxH, KDockDropSide activeSide) {
    int safeW = std::max(kDropGuideSize, boxW);
    int safeH = std::max(kDropGuideSize, boxH);
    int centerX = boxX + safeW / 2 - kDropGuideSize / 2;
    int centerY = boxY + safeH / 2 - kDropGuideSize / 2;
    drawDropGuide(centerX, boxY + kDropGuideInset, "T", activeSide == KDockDropSide::kTop);
    drawDropGuide(centerX, boxY + safeH - kDropGuideInset - kDropGuideSize, "B", activeSide == KDockDropSide::kBottom);
    drawDropGuide(boxX + kDropGuideInset, centerY, "L", activeSide == KDockDropSide::kLeft);
    drawDropGuide(boxX + safeW - kDropGuideInset - kDropGuideSize, centerY, "R", activeSide == KDockDropSide::kRight);
    drawDropGuide(centerX, centerY, "C", activeSide == KDockDropSide::kCenter);
}
// Draws a lightweight preview rectangle for the currently selected docking side.
void drawDropPreview(int boxX, int boxY, int boxW, int boxH, KDockDropSide side) {
    int previewX = boxX;
    int previewY = boxY;
    int previewW = std::max(1, boxW);
    int previewH = std::max(1, boxH);
    int sideW = std::max(kDropPreviewMin, previewW / 4);
    int sideH = std::max(kDropPreviewMin, previewH / 4);
    if (side == KDockDropSide::kLeft) {
        previewW = sideW;
    }
    else if (side == KDockDropSide::kRight) {
        previewX = boxX + std::max(0, boxW - sideW);
        previewW = sideW;
    }
    else if (side == KDockDropSide::kTop) {
        previewH = sideH;
    }
    else if (side == KDockDropSide::kBottom) {
        previewY = boxY + std::max(0, boxH - sideH);
        previewH = sideH;
    }
    else if (side == KDockDropSide::kCenter) {
        previewX = boxX + previewW / 4;
        previewY = boxY + previewH / 4;
        previewW = std::max(kDropPreviewMin, previewW / 2);
        previewH = std::max(kDropPreviewMin, previewH / 2);
    }
    else {
        return;
    }
    Fl_Color previewFill = fl_color_average(kColorPrimary(), kColorWindow(), 0.28f);
    fl_color(previewFill);
    fl_rectf(previewX, previewY, previewW, previewH);
    fl_color(kColorPrimaryDark());
    fl_rect(previewX, previewY, previewW, previewH);
    fl_rect(previewX + 1, previewY + 1, std::max(1, previewW - 2), std::max(1, previewH - 2));
    // A light hatch pattern makes the preview visible even on similar themes.
    for (int lineX = previewX - previewH; lineX < previewX + previewW; lineX += 10) {
        fl_line(lineX, previewY + previewH, lineX + previewH, previewY);
    }
}
// Moves a widget from any current parent to a new group using normal FLTK ownership APIs.
void reparentWidget(Fl_Widget* widget, Fl_Group* target) {
    if (!widget || !target) {
        return;
    }
    Fl_Group* oldParent = widget->parent();
    if (oldParent == target) {
        return;
    }
    if (oldParent) {
        oldParent->remove(widget);
    }
    target->add(widget);
}
// Computes root-screen coordinates for a widget by combining window root and widget local offsets.
void widgetRootBox(const Fl_Widget* widget, int& rootX, int& rootY, int& width, int& height) {
    rootX = 0;
    rootY = 0;
    width = 0;
    height = 0;
    if (!widget) {
        return;
    }
    width = widget->w();
    height = widget->h();
    rootX = widget->x();
    rootY = widget->y();
    Fl_Window* top = widget->top_window();
    if (top) {
        rootX += top->x_root();
        rootY += top->y_root();
    }
}
// Returns a bounded integer so fixed side sizes never consume the whole manager.
int clampSize(int value, int minValue, int maxValue) {
    if (value < minValue) {
        return minValue;
    }
    if (value > maxValue) {
        return maxValue;
    }
    return value;
}
// Converts a split orientation into a compact token for saveLayout().
const char* orientationToToken(KDockSplitOrientation orientation) {
    return orientation == KDockSplitOrientation::kVertical ? "V" : "H";
}
// Parses one split orientation token during restoreLayout().
bool tokenToOrientation(const std::string& token, KDockSplitOrientation& orientation) {
    if (token == "H") {
        orientation = KDockSplitOrientation::kHorizontal;
        return true;
    }
    if (token == "V") {
        orientation = KDockSplitOrientation::kVertical;
        return true;
    }
    return false;
}
// Splits non-escaped layout metadata fields; titles are always stored as the
// final field on lines that need escaping, so node metadata can remain simple.
std::vector<std::string> splitPlainFields(const std::string& line) {
    std::vector<std::string> fields;
    std::string field;
    for (char ch : line) {
        if (ch == '|') {
            fields.push_back(field);
            field.clear();
        }
        else {
            field.push_back(ch);
        }
    }
    fields.push_back(field);
    return fields;
}
// Finds the leaf node that owns an area; returns nullptr if the area is absent.
KDockLayoutNode* findLeafForArea(KDockLayoutNode* node, KDockArea* dockArea) {
    if (!node || !dockArea) {
        return nullptr;
    }
    if (node->isLeaf) {
        return node->area == dockArea ? node : nullptr;
    }
    KDockLayoutNode* found = findLeafForArea(node->first, dockArea);
    if (found) {
        return found;
    }
    return findLeafForArea(node->second, dockArea);
}
// Returns true when a layout node subtree contains a dock area as one of its leaves.
bool layoutContainsArea(KDockLayoutNode* node, KDockArea* dockArea) {
    return findLeafForArea(node, dockArea) != nullptr;
}
// Compares two overlay targets so mouse-move handling can skip redundant full
// dock-manager redraws while the pointer remains over the same guide target.
bool dropTargetsEqual(const KDockDropTarget& left, const KDockDropTarget& right) {
    return left.valid == right.valid &&
        left.scope == right.scope &&
        left.side == right.side &&
        left.area == right.area &&
        left.dock == right.dock &&
        left.position == right.position;
}
// Serializes one layout-tree node and returns the generated node id.
std::string writeLayoutNode(const KDockLayoutNode* node, std::ostringstream& out, int& nextNodeId) {
    std::string nodeId = "N" + std::to_string(nextNodeId++);
    if (!node) {
        out << "NODE|" << nodeId << "|LEAF|Center\n";
        return nodeId;
    }
    if (node->isLeaf) {
        const char* layoutId = (node->area ? node->area->layoutId().c_str() : "Center");
        out << "NODE|" << nodeId << "|LEAF|" << layoutId << "\n";
        return nodeId;
    }
    std::string firstId = writeLayoutNode(node->first, out, nextNodeId);
    std::string secondId = writeLayoutNode(node->second, out, nextNodeId);
    out << "NODE|" << nodeId << "|SPLIT|" << orientationToToken(node->orientation)
        << "|" << clampSize(node->firstRatio, 100, 900)
        << "|" << firstId << "|" << secondId << "\n";
    return nodeId;
}
// Returns the numeric suffix from a dynamic area id, or -1 when not present.
int dynamicAreaNumber(const std::string& layoutId) {
    const std::string kPrefix = "Dynamic";
    if (layoutId.compare(0, kPrefix.size(), kPrefix) != 0) {
        return -1;
    }
    const char* digits = layoutId.c_str() + kPrefix.size();
    if (!*digits) {
        return -1;
    }
    return std::atoi(digits);
}
// isAncestor walks FLTK parent links to detect an accidental containment cycle.
bool isAncestor(const Fl_Widget* possibleAncestor, const Fl_Widget* widget) {
    for (const Fl_Widget* current = widget; current; current = current->parent()) {
        if (current == possibleAncestor) {
            return true;
        }
    }
    return false;
}
// ScopedLayoutFlag marks a manual layout pass and restores the flag on every exit.
class ScopedLayoutFlag {
public:
    // Stores a reference to the caller-owned flag and sets it for this scope.
    explicit ScopedLayoutFlag(bool& flag)
        : flag_(flag) {
        flag_ = true;
    }

    // Clears the caller-owned flag when the guarded layout pass finishes.
    ~ScopedLayoutFlag() {
        flag_ = false;
    }

private:
    bool& flag_;
};
} // namespace
KDockDropTarget::KDockDropTarget()
    : valid(false),
    scope(KDockDropScope::kNone),
    side(KDockDropSide::kNone),
    area(nullptr),
    dock(nullptr),
    position(KDockAreaPosition::kCenter) {
}

KDockWidget::KDockWidget(int x, int y, int w, int h, const char* title, Fl_Widget* content)
    : Fl_Group(x, y, w, h, title),
    title_(title ? title : "Dock"),
    iconName_(),
    content_(nullptr),
    manager_(nullptr),
    area_(nullptr),
    floatingWindow_(nullptr),
    pinned_(true),
    dragging_(false),
    dragStarted_(false),
    layoutingContent_(false),
    dragStartRootX_(0),
    dragStartRootY_(0),
    dragOffsetX_(0),
    dragOffsetY_(0) {
    box(FL_FLAT_BOX);
    color(kColorPanel());
    copy_label(title_.c_str());
    // KDockWidget lays out its single content child explicitly in layoutContent().
    // Disabling Fl_Group's proportional child resizing prevents a second resize
    // policy from feeding content geometry back into this dock during resize().
    resizable(nullptr);
    begin();
    end();
    setContent(content);
}
KDockWidget::~KDockWidget() {
    // The floating window is a temporary host; detach this widget before deleting it.
    if (floatingWindow_) {
        floatingWindow_->remove(this);
        Fl_Window* host = floatingWindow_;
        floatingWindow_ = nullptr;
        delete host;
    }
}
void KDockWidget::draw() {
    if (hasOnlyChildDamage(this)) {
        // Child-only damage comes from embedded editors, tables, and text views.
        // Avoid clearing the dock chrome when FLTK will repaint only that child.
        draw_children();
        return;
    }

    // Draw the panel body first so hidden content never leaks through the title bar.
    fl_color(kColorPanel());
    fl_rectf(x(), y(), w(), h());
    fl_color(kColorBorder());
    fl_rect(x(), y(), w(), h());
    // Title bar carries drag semantics and uses active-tab color to show focus.
    bool active = !area_ || area_->activeDockWidget() == this || isFloating();
    Fl_Color titleFill = active ? fl_color_average(kColorPrimary(), kColorWindow(), 0.22f) : kColorWindow();
    fl_color(titleFill);
    fl_rectf(x() + 1, y() + 1, std::max(0, w() - 2), kTitleHeight - 1);
    fl_color(active ? kColorPrimary() : kColorBorder());
    fl_rectf(x() + 1, y() + 1, 3, kTitleHeight - 1);
    fl_color(kColorBorder());
    fl_line(x(), y() + kTitleHeight, x() + w() - 1, y() + kTitleHeight);
    // Icon support is intentionally string-backed until resources are wired in.
    int titleLeft = x() + 9;
    if (!iconName_.empty()) {
        fl_color(active ? kColorPrimary() : kColorBorder());
        fl_rectf(titleLeft, y() + 5, 14, 14);
        fl_color(active ? FL_WHITE : kColorMuted());
        fl_font(FL_HELVETICA_BOLD, 9);
        fl_draw(iconName_.substr(0, 1).c_str(), titleLeft, y() + 5, 14, 14, FL_ALIGN_CENTER);
        titleLeft += 19;
    }
    // Keep title text clipped away from pin, float, and close buttons.
    int buttonsW = kButtonSize * kTitleButtonCount + kButtonGap * (kTitleButtonCount + 1);
    int textRight = x() + w() - buttonsW;
    int textW = std::max(0, textRight - titleLeft);
    fl_color(kColorText());
    fl_font(FL_HELVETICA_BOLD, 12);
    fl_draw(title_.c_str(), titleLeft, y(), textW, kTitleHeight, FL_ALIGN_LEFT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    // Buttons are drawn with ASCII glyphs for portability across configured fonts.
    drawTitleButton(x() + w() - kButtonSize * 3 - kButtonGap * 3, y() + 4, pinned_ ? "P" : "p", kColorWindow());
    drawTitleButton(x() + w() - kButtonSize * 2 - kButtonGap * 2, y() + 4, "^", kColorWindow());
    drawTitleButton(x() + w() - kButtonSize - kButtonGap, y() + 4, "x", kColorWindow());
    // Draw only the active content child; KDockArea controls show/hide before redraw.
    draw_children();
}
int KDockWidget::handle(int event) {
    int localX = Fl::event_x() - x();
    int localY = Fl::event_y() - y();
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) {
        if (inCloseButton(localX, localY)) {
            closeDock();
            return 1;
        }
        if (inFloatButton(localX, localY)) {
            floatDock();
            return 1;
        }
        if (inPinButton(localX, localY)) {
            togglePinned();
            return 1;
        }
        if (inTitleBar(localX, localY)) {
            dragging_ = true;
            dragStarted_ = false;
            dragStartRootX_ = Fl::event_x_root();
            dragStartRootY_ = Fl::event_y_root();
            dragOffsetX_ = localX;
            dragOffsetY_ = localY;
            take_focus();
            return 1;
        }
    }
    if (event == FL_DRAG && dragging_) {
        int rootX = Fl::event_x_root();
        int rootY = Fl::event_y_root();
        int dx = rootX - dragStartRootX_;
        int dy = rootY - dragStartRootY_;
        if (!dragStarted_ && (std::abs(dx) > kDragThreshold || std::abs(dy) > kDragThreshold)) {
            dragStarted_ = true;
            beginFloatingDrag(rootX, rootY);
        }
        if (dragStarted_) {
            continueFloatingDrag(rootX, rootY);
        }
        return 1;
    }
    if (event == FL_RELEASE && dragging_) {
        finishFloatingDrag(Fl::event_x_root(), Fl::event_y_root());
        return 1;
    }
    return Fl_Group::handle(event);
}
void KDockWidget::setContent(Fl_Widget* content) {
    if (content == this) {
        return;
    }
    if (content_ == content) {
        layoutContent();
        return;
    }
    // Detach old content but do not delete it; ownership stays with caller/FLTK tree.
    if (content_ && content_->parent() == this) {
        remove(content_);
    }
    content_ = content;
    if (content_) {
        // Some content widgets are Fl_Group subclasses. If such a widget was the
        // current FLTK group while this dock was constructed, FLTK may already
        // have inserted this dock below the future content. Break that accidental
        // ancestor relation before making the content a child of the dock.
        if (isAncestor(content_, this)) {
            Fl_Group* dockParent = parent();
            if (dockParent) {
                dockParent->remove(this);
            }
        }
        reparentWidget(content_, this);
        content_->show();
    }
    layoutContent();
}
Fl_Widget* KDockWidget::content() const {
    return content_;
}
void KDockWidget::setTitle(const std::string& title) {
    title_ = title;
    copy_label(title_.c_str());
    redraw();
}
const std::string& KDockWidget::title() const {
    return title_;
}
void KDockWidget::setIconName(const std::string& iconName) {
    // The dock stores only a logical icon id so callers can wire resources later.
    iconName_ = iconName;
    redraw();
    if (area_) {
        area_->redraw();
    }
}
const std::string& KDockWidget::iconName() const {
    return iconName_;
}
void KDockWidget::setPinned(bool pinned) {
    // Pinning is reserved state today; drawing updates make the state observable.
    pinned_ = pinned;
    redraw();
}
bool KDockWidget::isPinned() const {
    return pinned_;
}
void KDockWidget::togglePinned() {
    setPinned(!pinned_);
}
void KDockWidget::setDockManager(KDockManager* manager) {
    manager_ = manager;
}
KDockManager* KDockWidget::dockManager() const {
    return manager_;
}
void KDockWidget::setDockArea(KDockArea* area) {
    area_ = area;
}
KDockArea* KDockWidget::dockArea() const {
    return area_;
}
void KDockWidget::floatDock() {
    if (floatingWindow_) {
        floatingWindow_->show();
        floatingWindow_->take_focus();
        return;
    }
    int rootX = 0;
    int rootY = 0;
    int oldW = 0;
    int oldH = 0;
    widgetRootBox(this, rootX, rootY, oldW, oldH);
    int floatW = std::max(260, oldW > 0 ? oldW : 320);
    int floatH = std::max(180, oldH > 0 ? oldH : 240);
    createFloatingWindowAt(rootX + 32, rootY + 32, floatW, floatH);
}
void KDockWidget::closeDock() {
    // Close means hidden and removed from its area, not deleted.
    KDockManager* activeManager = manager_;
    if (area_) {
        area_->removeDockWidget(this);
    }
    if (floatingWindow_) {
        floatingWindow_->hide();
        floatingWindow_->remove(this);
        Fl_Window* host = floatingWindow_;
        floatingWindow_ = nullptr;
        delete host;
    }
    if (parent()) {
        parent()->remove(this);
    }
    area_ = nullptr;
    hide();
    if (activeManager) {
        activeManager->cleanupEmptyAreas();
        activeManager->layoutAreas();
        activeManager->redraw();
    }
}
void KDockWidget::activateDock() {
    // Activation is area-local; floating docks already own their visible host.
    if (area_) {
        area_->setActiveDockWidget(this);
    }
    else {
        show();
        redraw();
    }
}
void KDockWidget::layoutContent() {
    if (!content_ || layoutingContent_) {
        return;
    }
    ScopedLayoutFlag guard(layoutingContent_);
    // Content uses the full area below the native title bar.
    int clientX = x() + kMargin;
    int clientY = y() + kTitleHeight + kMargin;
    int clientW = std::max(kMinClientSize, w() - kMargin * 2);
    int clientH = std::max(kMinClientSize, h() - kTitleHeight - kMargin * 2);
    // Only issue a real resize when geometry changed. This avoids needless
    // virtual resize callbacks from child Fl_Group widgets during tab changes.
    const bool kGeometryChanged = content_->x() != clientX || content_->y() != clientY ||
        content_->w() != clientW || content_->h() != clientH;
    const bool kWasHidden = !content_->visible();
    if (kGeometryChanged) {
        content_->resize(clientX, clientY, clientW, clientH);
    }
    content_->show();
    if (kGeometryChanged || kWasHidden) {
        redraw();
    }
}
bool KDockWidget::isFloating() const {
    return floatingWindow_ != nullptr;
}
bool KDockWidget::floatingGeometry(int& rootX, int& rootY, int& width, int& height) const {
    if (!floatingWindow_) {
        rootX = 0;
        rootY = 0;
        width = 0;
        height = 0;
        return false;
    }
    rootX = floatingWindow_->x();
    rootY = floatingWindow_->y();
    width = floatingWindow_->w();
    height = floatingWindow_->h();
    return true;
}
bool KDockWidget::floatingCenterRootPoint(int& rootX, int& rootY) const {
    // Inputs are output references. Processing uses the host window bounds
    // because users often release the mouse over the floating title bar while
    // the host body covers a dock target. The return value says whether a
    // floating host exists and a center point was produced.
    int fx = 0;
    int fy = 0;
    int fw = 0;
    int fh = 0;
    if (!floatingGeometry(fx, fy, fw, fh)) {
        rootX = 0;
        rootY = 0;
        return false;
    }
    rootX = fx + std::max(1, fw) / 2;
    rootY = fy + std::max(1, fh) / 2;
    return true;
}
void KDockWidget::resize(int x, int y, int w, int h) {
    Fl_Group::resize(x, y, w, h);
    layoutContent();
}
void KDockWidget::detachFloatingWindow() {
    if (!floatingWindow_) {
        return;
    }
    // The dock itself survives; only the temporary host window is destroyed.
    Fl_Window* host = floatingWindow_;
    floatingWindow_ = nullptr;
    if (KDockFloatingWindow* floatingHost = dynamic_cast<KDockFloatingWindow*>(host)) {
        floatingHost->setDockWidget(nullptr);
    }
    Fl::grab(nullptr);
    host->hide();
    if (parent() == host) {
        host->remove(this);
    }
    Fl::delete_widget(host);
}
void KDockWidget::createFloatingWindowAt(int rootX, int rootY, int width, int height) {
    int floatW = std::max(260, width);
    int floatH = std::max(180, height);
    // Existing floating hosts are reused so drag operations do not churn windows.
    if (floatingWindow_) {
        if (KDockFloatingWindow* host = dynamic_cast<KDockFloatingWindow*>(floatingWindow_)) {
            host->setDockWidget(this);
        }
        floatingWindow_->resize(rootX, rootY, floatW, floatH);
        resize(0, 0, floatW, floatH);
        show();
        floatingWindow_->show();
        floatingWindow_->take_focus();
        return;
    }
    // Removing through the area keeps tab bookkeeping consistent before reparenting.
    KDockManager* activeManager = manager_;
    if (area_) {
        area_->removeDockWidget(this);
    }
    else if (parent()) {
        parent()->remove(this);
    }
    area_ = nullptr;
    // Runtime construction can happen while another FLTK group is current.
    // Clearing current() prevents the floating host from becoming a child of
    // the old dock area, which would make it invisible to normal window routing.
    Fl_Group* previousCurrent = Fl_Group::current();
    Fl_Group::current(nullptr);
    floatingWindow_ = new KDockFloatingWindow(rootX, rootY, floatW, floatH, title_.c_str(), this);
    Fl_Group::current(previousCurrent);
    floatingWindow_->begin();
    floatingWindow_->add(this);
    resize(0, 0, floatW, floatH);
    floatingWindow_->resizable(this);
    floatingWindow_->end();
    show();
    floatingWindow_->show();
    floatingWindow_->take_focus();
    // The manager must hide now-empty side areas as soon as a dock leaves them.
    if (activeManager) {
        activeManager->cleanupEmptyAreas();
        activeManager->layoutAreas();
        activeManager->redraw();
    }
}
void KDockWidget::beginFloatingDrag(int rootX, int rootY) {
    int oldW = std::max(260, w());
    int oldH = std::max(180, h());
    int floatX = rootX - dragOffsetX_;
    int floatY = rootY - dragOffsetY_;
    createFloatingWindowAt(floatX, floatY, oldW, oldH);
    // Root cause fix for "dragging out from inside" failures: the widget is
    // reparented during FL_DRAG, so explicitly grab the new top-level host to
    // keep subsequent drag/release events in the floating dock window.
    if (floatingWindow_) {
        Fl::grab(floatingWindow_);
    }
}
void KDockWidget::moveFloatingWindowForDrag(int rootX, int rootY) {
    if (!floatingWindow_) {
        return;
    }
    int floatX = rootX - dragOffsetX_;
    int floatY = rootY - dragOffsetY_;
    // Moving the top-level host gives the user immediate visual separation.
    floatingWindow_->position(floatX, floatY);
}
void KDockWidget::continueFloatingDrag(int rootX, int rootY) {
    // This method is intentionally usable from both the dock widget and the
    // floating host.  Inputs are root-screen coordinates, processing keeps the
    // floating window under the cursor and refreshes the manager overlay, and
    // there is no return value.
    if (!dragging_ || !dragStarted_) {
        return;
    }
    moveFloatingWindowForDrag(rootX, rootY);
    if (manager_) {
        manager_->updateDockDrag(this, rootX, rootY);
    }
}
void KDockWidget::finishFloatingDrag(int rootX, int rootY) {
    // Finish is centralized so FL_RELEASE is handled correctly even when FLTK
    // sends the event to the grabbed floating window instead of this child.
    // Inputs are root-screen coordinates; processing clears grab/drag state and
    // either docks through the manager or leaves the existing floating host.
    const bool kWasDrag = dragStarted_;
    dragging_ = false;
    dragStarted_ = false;
    Fl::grab(nullptr);
    if (kWasDrag && manager_) {
        moveFloatingWindowForDrag(rootX, rootY);
        manager_->dockWidgetFromDrag(this, rootX, rootY);
        return;
    }
    if (manager_) {
        manager_->clearDockDrag();
    }
}
bool KDockWidget::hasActiveFloatingDrag() const {
    // The floating host only needs to proxy events after a drag crossed the
    // threshold and created/reused a host window.
    return dragging_ && dragStarted_;
}
bool KDockWidget::inTitleBar(int localX, int localY) const {
    return localX >= 0 && localX < w() && localY >= 0 && localY < kTitleHeight;
}
bool KDockWidget::inCloseButton(int localX, int localY) const {
    int bx = w() - kButtonSize - kButtonGap;
    int by = 4;
    return localX >= bx && localX < bx + kButtonSize && localY >= by && localY < by + kButtonSize;
}
bool KDockWidget::inFloatButton(int localX, int localY) const {
    int bx = w() - kButtonSize * 2 - kButtonGap * 2;
    int by = 4;
    return localX >= bx && localX < bx + kButtonSize && localY >= by && localY < by + kButtonSize;
}
bool KDockWidget::inPinButton(int localX, int localY) const {
    int bx = w() - kButtonSize * 3 - kButtonGap * 3;
    int by = 4;
    return localX >= bx && localX < bx + kButtonSize && localY >= by && localY < by + kButtonSize;
}
KDockArea::KDockArea(int x, int y, int w, int h, KDockAreaPosition position, const char* label)
    : Fl_Group(x, y, w, h, label),
    position_(position),
    layoutId_(positionToToken(position)),
    docks_(),
    activeIndex_(-1),
    hoverIndex_(-1),
    defaultArea_(false),
    layoutingDocks_(false),
    tabDragging_(false),
    tabDragIndex_(-1),
    tabDragStartRootX_(0),
    tabDragStartRootY_(0),
    tabDragWidget_(nullptr) {
    box(FL_FLAT_BOX);
    color(kColorWindow());
    // Dock areas perform tab/content placement in layoutDocks(); FLTK's
    // default group-resize policy would otherwise move docks a second time.
    resizable(nullptr);
    begin();
    end();
}
void KDockArea::draw() {
    if (hasOnlyChildDamage(this)) {
        // The active dock owns its child repaint. Redrawing the tab area here
        // would erase inactive tabs or sibling regions during focused typing.
        draw_children();
        return;
    }

    fl_color(kColorWindow());
    fl_rectf(x(), y(), w(), h());
    fl_color(kColorBorder());
    fl_rect(x(), y(), w(), h());
    // Draw tabs before children; inactive docks are hidden by layoutDocks().
    int count = dockCount();
    if (count > 0) {
        int tabW = std::max(40, w() / count);
        for (int i = 0; i < count; ++i) {
            int tx = x() + i * tabW;
            int tw = (i == count - 1) ? (x() + w() - tx) : tabW;
            bool selected = (i == activeIndex_);
            bool hovered = (i == hoverIndex_);
            Fl_Color tabFill = selected ? kColorPrimary()
                : (hovered ? fl_color_average(kColorPanel(), kColorPrimary(), 0.18f) : kColorPanel());
            fl_color(tabFill);
            fl_rectf(tx, y(), std::max(0, tw), kTabHeight);
            fl_color(kColorBorder());
            fl_rect(tx, y(), std::max(0, tw), kTabHeight);
            if (selected) {
                fl_color(kColorPrimaryDark());
                fl_rectf(tx, y() + kTabHeight - 3, std::max(0, tw), 3);
            }
            fl_color(selected ? FL_WHITE : (hovered ? kColorText() : kColorMuted()));
            fl_font(FL_HELVETICA, 12);
            const char* tabLabel = docks_[i] ? docks_[i]->title().c_str() : "";
            fl_draw(tabLabel, tx + 6, y(), std::max(0, tw - 12), kTabHeight, FL_ALIGN_LEFT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
        }
    }
    draw_children();
}
int KDockArea::handle(int event) {
    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) {
        int localX = Fl::event_x() - x();
        int localY = Fl::event_y() - y();
        int index = tabIndexAt(localX, localY);
        if (index >= 0 && index < dockCount()) {
            // A tab press both activates the dock and arms a delayed drag.  The
            // actual floating host is created only after a small movement so a
            // normal click never accidentally tears the tab out of the area.
            activeIndex_ = index;
            tabDragging_ = true;
            tabDragIndex_ = index;
            tabDragStartRootX_ = Fl::event_x_root();
            tabDragStartRootY_ = Fl::event_y_root();
            tabDragWidget_ = dockAt(index);
            layoutDocks();
            redraw();
            return 1;
        }
    }

    if (event == FL_DRAG && tabDragging_) {
        int rootX = Fl::event_x_root();
        int rootY = Fl::event_y_root();
        int dx = rootX - tabDragStartRootX_;
        int dy = rootY - tabDragStartRootY_;
        if (std::abs(dx) > kDragThreshold || std::abs(dy) > kDragThreshold) {
            KDockWidget* dragWidget = tabDragWidget_;
            KDockManager* dragManager = dragWidget ? dragWidget->dockManager() : nullptr;
            const int kLocalX = Fl::event_x() - x();

            // Clear area-side drag state before reparenting.  beginFloatingDrag()
            // can make an empty dynamic area eligible for deletion, so no code
            // below relies on KDockArea members after the floating host appears.
            tabDragging_ = false;
            tabDragIndex_ = -1;
            tabDragWidget_ = nullptr;

            if (dragWidget) {
                dragWidget->dragging_ = true;
                dragWidget->dragStarted_ = true;
                dragWidget->dragStartRootX_ = tabDragStartRootX_;
                dragWidget->dragStartRootY_ = tabDragStartRootY_;
                dragWidget->dragOffsetX_ = clampSize(kLocalX, 8, std::max(8, dragWidget->w() - 8));
                dragWidget->dragOffsetY_ = kTitleHeight / 2;
                dragWidget->beginFloatingDrag(rootX, rootY);
                dragWidget->moveFloatingWindowForDrag(rootX, rootY);
                if (dragManager) {
                    dragManager->updateDockDrag(dragWidget, rootX, rootY);
                }
            }
            return 1;
        }
        return 1;
    }

    if (event == FL_RELEASE && tabDragging_) {
        // Release without crossing the drag threshold is just a tab selection.
        tabDragging_ = false;
        tabDragIndex_ = -1;
        tabDragWidget_ = nullptr;
        return 1;
    }

    if (event == FL_MOVE) {
        int localX = Fl::event_x() - x();
        int localY = Fl::event_y() - y();
        int index = tabIndexAt(localX, localY);
        if (index != hoverIndex_) {
            hoverIndex_ = index;
            redraw();
        }
    }
    if (event == FL_LEAVE && hoverIndex_ != -1 && !tabDragging_) {
        hoverIndex_ = -1;
        redraw();
    }
    return Fl_Group::handle(event);
}
void KDockArea::addDockWidget(KDockWidget* widget) {
    insertDockWidget(widget, dockCount());
}
void KDockArea::insertDockWidget(KDockWidget* widget, int index) {
    if (!widget) {
        return;
    }
    // Avoid duplicate tabs while still making the requested dock active.
    auto existing = std::find(docks_.begin(), docks_.end(), widget);
    if (existing == docks_.end()) {
        int safeIndex = clampSize(index, 0, dockCount());
        docks_.insert(docks_.begin() + safeIndex, widget);
    }
    activeIndex_ = static_cast<int>(std::find(docks_.begin(), docks_.end(), widget) - docks_.begin());
    if (widget->isFloating()) {
        widget->detachFloatingWindow();
    }
    reparentWidget(widget, this);
    widget->setDockArea(this);
    widget->show();
    layoutDocks();
    redraw();
}
void KDockArea::removeDockWidget(KDockWidget* widget) {
    if (!widget) {
        return;
    }
    auto it = std::find(docks_.begin(), docks_.end(), widget);
    if (it == docks_.end()) {
        return;
    }
    int removedIndex = static_cast<int>(it - docks_.begin());
    docks_.erase(it);
    if (widget->parent() == this) {
        remove(widget);
    }
    widget->setDockArea(nullptr);
    widget->hide();
    if (docks_.empty()) {
        activeIndex_ = -1;
    }
    else if (activeIndex_ >= removedIndex) {
        activeIndex_ = std::max(0, activeIndex_ - 1);
    }
    if (activeIndex_ >= dockCount()) {
        activeIndex_ = dockCount() - 1;
    }
    if (hoverIndex_ >= dockCount()) {
        hoverIndex_ = -1;
    }
    layoutDocks();
    redraw();
}
void KDockArea::setActiveDockWidget(KDockWidget* widget) {
    auto it = std::find(docks_.begin(), docks_.end(), widget);
    if (it == docks_.end()) {
        return;
    }
    activeIndex_ = static_cast<int>(it - docks_.begin());
    layoutDocks();
    redraw();
}
KDockWidget* KDockArea::activeDockWidget() const {
    if (activeIndex_ < 0 || activeIndex_ >= dockCount()) {
        return nullptr;
    }
    return docks_[activeIndex_];
}
int KDockArea::activeIndex() const {
    return activeIndex_;
}
void KDockArea::setActiveIndex(int index) {
    if (index < 0 || index >= dockCount()) {
        return;
    }
    activeIndex_ = index;
    layoutDocks();
    redraw();
}
int KDockArea::dockCount() const {
    return static_cast<int>(docks_.size());
}
KDockWidget* KDockArea::dockAt(int index) const {
    if (index < 0 || index >= dockCount()) {
        return nullptr;
    }
    return docks_[index];
}
int KDockArea::indexOfDockWidget(KDockWidget* widget) const {
    auto it = std::find(docks_.begin(), docks_.end(), widget);
    if (it == docks_.end()) {
        return -1;
    }
    return static_cast<int>(it - docks_.begin());
}
KDockAreaPosition KDockArea::position() const {
    return position_;
}
void KDockArea::setLayoutId(const std::string& layoutId) {
    layoutId_ = layoutId;
}
const std::string& KDockArea::layoutId() const {
    return layoutId_;
}
void KDockArea::setDefaultArea(bool defaultArea) {
    defaultArea_ = defaultArea;
}
bool KDockArea::isDefaultArea() const {
    return defaultArea_;
}
void KDockArea::layoutDocks() {
    if (layoutingDocks_) {
        return;
    }
    ScopedLayoutFlag guard(layoutingDocks_);
    int contentX = x() + 1;
    int contentY = y() + (dockCount() > 0 ? kTabHeight : 1);
    int contentW = std::max(kMinClientSize, w() - 2);
    int contentH = std::max(kMinClientSize, h() - (dockCount() > 0 ? kTabHeight : 1) - 1);
    for (int i = 0; i < dockCount(); ++i) {
        KDockWidget* dock = docks_[i];
        if (!dock) {
            continue;
        }
        // Geometry checks keep inactive tabs from receiving redundant resize
        // calls and reduce the chance of reentrant FLTK group layout.
        if (dock->x() != contentX || dock->y() != contentY ||
            dock->w() != contentW || dock->h() != contentH) {
            dock->resize(contentX, contentY, contentW, contentH);
        }
        dock->setDockArea(this);
        if (i == activeIndex_) {
            dock->show();
        }
        else {
            dock->hide();
        }
    }
}
void KDockArea::resize(int x, int y, int w, int h) {
    Fl_Group::resize(x, y, w, h);
    layoutDocks();
}
int KDockArea::tabIndexAt(int localX, int localY) const {
    if (localY < 0 || localY >= kTabHeight || localX < 0 || localX >= w()) {
        return -1;
    }
    int count = dockCount();
    if (count <= 0) {
        return -1;
    }
    int tabW = std::max(40, w() / count);
    int index = localX / tabW;
    if (index >= count) {
        index = count - 1;
    }
    return index;
}
KDockManager::KDockManager(int x, int y, int w, int h, const char* label)
    : Fl_Group(x, y, w, h, label),
    left_(nullptr),
    right_(nullptr),
    top_(nullptr),
    bottom_(nullptr),
    center_(nullptr),
    rootNode_(nullptr),
    allAreas_(),
    knownDocks_(),
    activeDropTarget_(),
    draggingWidget_(nullptr),
    nextAreaId_(1),
    leftWidth_(220),
    rightWidth_(220),
    topHeight_(150),
    bottomHeight_(150),
    layoutingAreas_(false) {
    box(FL_FLAT_BOX);
    color(kColorWindow());
    // The five default areas are persistent API targets.  They are hidden when
    // empty, while dynamic split areas can be deleted after their last dock goes
    // floating or closed.
    Fl_Group* previousCurrent = Fl_Group::current();
    begin();
    left_ = new KDockArea(0, 0, 1, 1, KDockAreaPosition::kLeft, "Left");
    right_ = new KDockArea(0, 0, 1, 1, KDockAreaPosition::kRight, "Right");
    top_ = new KDockArea(0, 0, 1, 1, KDockAreaPosition::kTop, "Top");
    bottom_ = new KDockArea(0, 0, 1, 1, KDockAreaPosition::kBottom, "Bottom");
    center_ = new KDockArea(0, 0, 1, 1, KDockAreaPosition::kCenter, "Center");
    end();
    Fl_Group::current(previousCurrent);
    KDockArea* defaults[] = { left_, right_, top_, bottom_, center_ };
    const char* ids[] = { "Left", "Right", "Top", "Bottom", "Center" };
    for (int i = 0; i < 5; ++i) {
        defaults[i]->setDefaultArea(true);
        defaults[i]->setLayoutId(ids[i]);
        defaults[i]->hide();
        registerArea(defaults[i]);
    }
    // Start with the center leaf so the manager always has a valid root target.
    rootNode_ = new KDockLayoutNode(center_);
    resizable(nullptr);
    layoutAreas();
}
KDockManager::~KDockManager() {
    // Split nodes are bookkeeping only; FLTK owns and destroys child areas.
    deleteLayoutTree(rootNode_);
    rootNode_ = nullptr;
}
void KDockManager::draw() {
    if (hasOnlyChildDamage(this) && !activeDropTarget_.valid) {
        // Dock child focus updates should not repaint the whole manager. Drag
        // overlays still force a full pass because guides are manager-level UI.
        draw_children();
        return;
    }

    // The manager owns the final overlay pass, so draw children before guides.
    fl_color(kColorWindow());
    fl_rectf(x(), y(), w(), h());
    fl_color(kColorBorder());
    fl_rect(x(), y(), w(), h());
    draw_children();
    drawDropOverlay();
}
void KDockManager::addDockWidget(KDockAreaPosition position, KDockWidget* widget) {
    if (!widget) {
        return;
    }
    // Public API drops target the stable main-window areas.  The tree is grown
    // lazily, so empty side areas do not consume space until first use.
    KDockArea* target = ensureMainAreaInTree(position);
    dockWidgetToArea(widget, target ? target : center_);
}
void KDockManager::tabifyDockWidget(KDockWidget* first, KDockWidget* second) {
    // Mirrors Qt's tabifyDockWidget: inputs are the existing anchor dock and
    // the dock being moved; processing reuses the anchor's tab area, and no
    // value is returned.
    if (!second) {
        return;
    }
    KDockArea* target = first ? first->dockArea() : nullptr;
    if (!target) {
        target = ensureMainAreaInTree(KDockAreaPosition::kCenter);
    }
    dockWidgetToArea(second, target ? target : center_);
}
void KDockManager::splitDockWidget(KDockWidget* first, KDockWidget* second, KDockDropSide side) {
    // Mirrors Qt's splitDockWidget at the dock-area level.  Center means tabify;
    // side drops create a dynamic area beside the anchor area.
    if (!second) {
        return;
    }
    if (side == KDockDropSide::kCenter) {
        tabifyDockWidget(first, second);
        return;
    }
    KDockArea* source = first ? first->dockArea() : nullptr;
    if (!source) {
        source = ensureMainAreaInTree(KDockAreaPosition::kCenter);
    }
    KDockArea* target = splitAreaForDrop(source, side);
    dockWidgetToArea(second, target ? target : source);
}
KDockArea* KDockManager::area(KDockAreaPosition position) const {
    switch (position) {
    case KDockAreaPosition::kLeft:
        return left_;
    case KDockAreaPosition::kRight:
        return right_;
    case KDockAreaPosition::kTop:
        return top_;
    case KDockAreaPosition::kBottom:
        return bottom_;
    case KDockAreaPosition::kCenter:
    default:
        return center_;
    }
}
void KDockManager::dockWidgetFromDrag(KDockWidget* widget, int rootX, int rootY) {
    if (!widget) {
        return;
    }
    Fl::grab(nullptr);
    KDockDropTarget target = dropTargetForFloatingWidget(widget, rootX, rootY);
    activeDropTarget_ = target;
    // Invalid targets intentionally leave the dock in its floating host.
    if (!target.valid) {
        if (!widget->isFloating()) {
            widget->floatDock();
        }
        clearDockDrag();
        return;
    }
    KDockArea* targetArea = nullptr;
    if (target.scope == KDockDropScope::kDockWidget && target.area) {
        // Center merges as a tab in the hovered area; sides create a real split.
        targetArea = (target.side == KDockDropSide::kCenter)
            ? target.area
            : splitAreaForDrop(target.area, target.side);
    }
    else {
        targetArea = ensureMainAreaInTree(sideToPosition(target.side));
    }
    dockWidgetToArea(widget, targetArea ? targetArea : center_);
    clearDockDrag();
}
void KDockManager::updateDockDrag(KDockWidget* widget, int rootX, int rootY) {
    draggingWidget_ = widget;
    KDockDropTarget nextTarget = dropTargetForFloatingWidget(widget, rootX, rootY);
    if (!dropTargetsEqual(activeDropTarget_, nextTarget)) {
        activeDropTarget_ = nextTarget;
        redraw();
    }
}
void KDockManager::clearDockDrag() {
    const bool kHadOverlay = activeDropTarget_.valid;
    activeDropTarget_ = KDockDropTarget();
    draggingWidget_ = nullptr;
    if (kHadOverlay) {
        redraw();
    }
}
std::string KDockManager::saveLayout() const {
    std::ostringstream out;
    out << "KDockLayout 2\n";
    int nextNodeId = 0;
    std::string rootId = writeLayoutNode(rootNode_, out, nextNodeId);
    out << "ROOT|" << rootId << "\n";
    // Area lines preserve tab order by following with TAB lines, and also store
    // the active dock title so restore can reselect the right tab.
    for (KDockArea* dockArea : allAreas_) {
        if (!dockArea || (!areaIsInLayout(dockArea) && dockArea->dockCount() <= 0)) {
            continue;
        }
        KDockWidget* active = dockArea->activeDockWidget();
        out << "AREA|" << dockArea->layoutId() << "|" << positionToToken(dockArea->position())
            << "|" << escapeTitle(active ? active->title() : std::string()) << "\n";
        for (int i = 0; i < dockArea->dockCount(); ++i) {
            KDockWidget* dock = dockArea->dockAt(i);
            if (dock) {
                out << "TAB|" << dockArea->layoutId() << "|" << i
                    << "|" << escapeTitle(dock->title()) << "\n";
            }
        }
    }
    // Floating docks are saved independently with their host geometry.
    for (KDockWidget* dock : knownDocks_) {
        int fx = 0;
        int fy = 0;
        int fw = 0;
        int fh = 0;
        if (dock && dock->floatingGeometry(fx, fy, fw, fh)) {
            out << "FLOAT|" << fx << "|" << fy << "|" << fw << "|" << fh
                << "|" << escapeTitle(dock->title()) << "\n";
        }
    }
    return out.str();
}
bool KDockManager::restoreLayout(const std::string& layoutText) {
    std::istringstream in(layoutText);
    std::string line;
    if (!std::getline(in, line)) {
        return false;
    }
    if (line == "KDockLayout 1") {
        return restoreLayoutV1(in);
    }
    if (line == "KDockLayout 2") {
        return restoreLayoutV2(in);
    }
    return false;
}
void KDockManager::layoutAreas() {
    if (layoutingAreas_) {
        return;
    }
    ScopedLayoutFlag guard(layoutingAreas_);
    if (!rootNode_) {
        rootNode_ = new KDockLayoutNode(center_);
    }
    // Hide leaves not present in the split tree so stale default areas cannot
    // draw or receive events after their last tab moved away.
    for (KDockArea* dockArea : allAreas_) {
        if (dockArea && !areaIsInLayout(dockArea)) {
            dockArea->hide();
            dockArea->resize(0, 0, 1, 1);
        }
    }
    layoutNode(rootNode_, x(), y(), std::max(1, w()), std::max(1, h()));
}
void KDockManager::resize(int x, int y, int w, int h) {
    Fl_Group::resize(x, y, w, h);
    layoutAreas();
}
void KDockManager::rememberDock(KDockWidget* widget) {
    if (!widget) {
        return;
    }
    if (std::find(knownDocks_.begin(), knownDocks_.end(), widget) == knownDocks_.end()) {
        knownDocks_.push_back(widget);
    }
}
KDockWidget* KDockManager::findDockByTitle(const std::string& title) const {
    for (KDockWidget* dock : knownDocks_) {
        if (dock && dock->title() == title) {
            return dock;
        }
    }
    return nullptr;
}
void KDockManager::removeDockFromAreas(KDockWidget* widget) {
    if (!widget) {
        return;
    }
    std::vector<KDockArea*> areas = allAreas_;
    for (KDockArea* dockArea : areas) {
        if (dockArea) {
            dockArea->removeDockWidget(widget);
        }
    }
}
void KDockManager::dockWidgetToArea(KDockWidget* widget, KDockArea* target) {
    if (!widget || !target) {
        return;
    }
    rememberDock(widget);
    widget->setDockManager(this);
    if (!areaIsInLayout(target)) {
        ensureMainAreaInTree(target->position());
    }
    if (!widget->isFloating() && target->indexOfDockWidget(widget) >= 0) {
        target->setActiveDockWidget(widget);
        layoutAreas();
        redraw();
        return;
    }
    removeDockFromAreas(widget);
    target->addDockWidget(widget);
    cleanupEmptyAreas();
    layoutAreas();
    redraw();
}
KDockArea* KDockManager::ensureMainAreaInTree(KDockAreaPosition position) {
    KDockArea* target = area(position);
    if (!target) {
        target = center_;
    }
    if (!rootNode_) {
        rootNode_ = new KDockLayoutNode(center_);
    }
    if (areaIsInLayout(target)) {
        return target;
    }
    KDockLayoutNode* oldRoot = rootNode_;
    KDockLayoutNode* targetLeaf = new KDockLayoutNode(target);
    KDockLayoutNode* split = nullptr;
    if (position == KDockAreaPosition::kLeft) {
        split = new KDockLayoutNode(KDockSplitOrientation::kHorizontal, targetLeaf, oldRoot, 250);
    }
    else if (position == KDockAreaPosition::kRight) {
        split = new KDockLayoutNode(KDockSplitOrientation::kHorizontal, oldRoot, targetLeaf, 750);
    }
    else if (position == KDockAreaPosition::kTop) {
        split = new KDockLayoutNode(KDockSplitOrientation::kVertical, targetLeaf, oldRoot, 250);
    }
    else if (position == KDockAreaPosition::kBottom) {
        split = new KDockLayoutNode(KDockSplitOrientation::kVertical, oldRoot, targetLeaf, 750);
    }
    else {
        split = new KDockLayoutNode(KDockSplitOrientation::kHorizontal, oldRoot, targetLeaf, 500);
    }
    rootNode_ = split;
    rootNode_->parent = nullptr;
    return target;
}
KDockArea* KDockManager::splitAreaForDrop(KDockArea* sourceArea, KDockDropSide side) {
    if (!sourceArea || side == KDockDropSide::kNone || side == KDockDropSide::kCenter) {
        return sourceArea;
    }
    KDockLayoutNode* sourceLeaf = findLeafForArea(rootNode_, sourceArea);
    if (!sourceLeaf) {
        return sourceArea;
    }
    KDockArea* targetArea = createDynamicArea(sourceArea->position());
    KDockLayoutNode* targetLeaf = new KDockLayoutNode(targetArea);
    KDockLayoutNode* oldParent = sourceLeaf->parent;
    KDockSplitOrientation orientation = (side == KDockDropSide::kLeft || side == KDockDropSide::kRight)
        ? KDockSplitOrientation::kHorizontal
        : KDockSplitOrientation::kVertical;
    KDockLayoutNode* split = nullptr;
    if (side == KDockDropSide::kLeft || side == KDockDropSide::kTop) {
        split = new KDockLayoutNode(orientation, targetLeaf, sourceLeaf, 500);
    }
    else {
        split = new KDockLayoutNode(orientation, sourceLeaf, targetLeaf, 500);
    }
    split->parent = oldParent;
    if (!oldParent) {
        rootNode_ = split;
    }
    else if (oldParent->first == sourceLeaf) {
        oldParent->first = split;
    }
    else {
        oldParent->second = split;
    }
    return targetArea;
}
KDockArea* KDockManager::createDynamicArea(KDockAreaPosition position) {
    std::string layoutId = "Dynamic" + std::to_string(nextAreaId_++);
    return createAreaForRestore(layoutId, position);
}
KDockArea* KDockManager::createAreaForRestore(const std::string& layoutId, KDockAreaPosition position) {
    KDockArea* existing = areaByLayoutId(layoutId);
    if (existing) {
        int number = dynamicAreaNumber(layoutId);
        if (number >= nextAreaId_) {
            nextAreaId_ = number + 1;
        }
        return existing;
    }
    Fl_Group* previousCurrent = Fl_Group::current();
    begin();
    KDockArea* dockArea = new KDockArea(0, 0, 1, 1, position, nullptr);
    end();
    Fl_Group::current(previousCurrent);
    dockArea->setDefaultArea(false);
    dockArea->setLayoutId(layoutId);
    dockArea->copy_label(layoutId.c_str());
    dockArea->hide();
    registerArea(dockArea);
    int number = dynamicAreaNumber(layoutId);
    if (number >= nextAreaId_) {
        nextAreaId_ = number + 1;
    }
    return dockArea;
}
void KDockManager::registerArea(KDockArea* dockArea) {
    if (!dockArea) {
        return;
    }
    if (std::find(allAreas_.begin(), allAreas_.end(), dockArea) == allAreas_.end()) {
        allAreas_.push_back(dockArea);
    }
}
KDockArea* KDockManager::areaByLayoutId(const std::string& layoutId) const {
    for (KDockArea* dockArea : allAreas_) {
        if (dockArea && dockArea->layoutId() == layoutId) {
            return dockArea;
        }
    }
    return nullptr;
}
bool KDockManager::areaIsInLayout(KDockArea* dockArea) const {
    return layoutContainsArea(rootNode_, dockArea);
}
void KDockManager::cleanupEmptyAreas() {
    bool changed = true;
    while (changed) {
        changed = false;
        std::vector<KDockArea*> areas = allAreas_;
        for (KDockArea* dockArea : areas) {
            if (!dockArea || dockArea == center_ || dockArea->dockCount() > 0 || !areaIsInLayout(dockArea)) {
                continue;
            }
            KDockLayoutNode* leaf = findLeafForArea(rootNode_, dockArea);
            if (!leaf) {
                continue;
            }
            KDockLayoutNode* parent = leaf->parent;
            if (!parent) {
                delete leaf;
                rootNode_ = new KDockLayoutNode(center_);
            }
            else {
                KDockLayoutNode* sibling = (parent->first == leaf) ? parent->second : parent->first;
                KDockLayoutNode* grand = parent->parent;
                if (sibling) {
                    sibling->parent = grand;
                }
                if (!grand) {
                    rootNode_ = sibling;
                }
                else if (grand->first == parent) {
                    grand->first = sibling;
                }
                else {
                    grand->second = sibling;
                }
                parent->first = nullptr;
                parent->second = nullptr;
                delete leaf;
                delete parent;
            }
            dockArea->hide();
            dockArea->resize(0, 0, 1, 1);
            if (!dockArea->isDefaultArea()) {
                if (dockArea->parent() == this) {
                    remove(dockArea);
                }
                allAreas_.erase(std::remove(allAreas_.begin(), allAreas_.end(), dockArea), allAreas_.end());
                delete dockArea;
            }
            changed = true;
            break;
        }
    }
}
void KDockManager::deleteLayoutTree(KDockLayoutNode* node) {
    if (!node) {
        return;
    }
    deleteLayoutTree(node->first);
    deleteLayoutTree(node->second);
    delete node;
}
void KDockManager::deleteDynamicAreas() {
    std::vector<KDockArea*> keep;
    for (KDockArea* dockArea : allAreas_) {
        if (!dockArea) {
            continue;
        }
        if (dockArea->isDefaultArea()) {
            keep.push_back(dockArea);
            dockArea->hide();
            dockArea->resize(0, 0, 1, 1);
            continue;
        }
        if (dockArea->parent() == this) {
            remove(dockArea);
        }
        delete dockArea;
    }
    allAreas_ = keep;
}
void KDockManager::resetDocksForRestore() {
    // First remove every dock from every area so area vectors and widget parents
    // stay synchronized before any layout nodes are deleted.
    std::vector<KDockArea*> areas = allAreas_;
    for (KDockArea* dockArea : areas) {
        while (dockArea && dockArea->dockCount() > 0) {
            dockArea->removeDockWidget(dockArea->dockAt(0));
        }
    }
    for (KDockWidget* dock : knownDocks_) {
        if (!dock) {
            continue;
        }
        if (dock->isFloating()) {
            dock->detachFloatingWindow();
        }
        if (dock->parent()) {
            dock->parent()->remove(dock);
        }
        dock->setDockArea(nullptr);
        dock->setDockManager(this);
        dock->hide();
    }
    deleteLayoutTree(rootNode_);
    rootNode_ = nullptr;
    deleteDynamicAreas();
    rootNode_ = new KDockLayoutNode(center_);
}
bool KDockManager::restoreLayoutV1(std::istream& input) {
    std::string line;
    bool restoredAny = false;
    resetDocksForRestore();
    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }
        std::size_t separator = line.find('|');
        if (separator == std::string::npos) {
            continue;
        }
        KDockAreaPosition position = KDockAreaPosition::kCenter;
        if (!tokenToPosition(line.substr(0, separator), position)) {
            continue;
        }
        KDockWidget* dock = findDockByTitle(unescapeTitle(line.substr(separator + 1)));
        if (!dock) {
            continue;
        }
        addDockWidget(position, dock);
        restoredAny = true;
    }
    cleanupEmptyAreas();
    layoutAreas();
    redraw();
    return restoredAny;
}
bool KDockManager::restoreLayoutV2(std::istream& input) {
    struct NodeSpec {
        bool leaf;
        std::string areaId;
        KDockSplitOrientation orientation;
        int ratio;
        std::string first;
        std::string second;
    };
    struct TabSpec {
        std::string areaId;
        int index;
        std::string title;
    };
    struct FloatSpec {
        int x;
        int y;
        int w;
        int h;
        std::string title;
    };
    std::string line;
    std::string rootId;
    std::map<std::string, NodeSpec> nodes;
    std::map<std::string, KDockAreaPosition> areaPositions;
    std::map<std::string, std::string> activeTitles;
    std::vector<TabSpec> tabs;
    std::vector<FloatSpec> floats;
    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }
        if (line.compare(0, 5, "NODE|") == 0) {
            std::vector<std::string> fields = splitPlainFields(line);
            if (fields.size() >= 4 && fields[2] == "LEAF") {
                NodeSpec spec;
                spec.leaf = true;
                spec.areaId = fields[3];
                spec.orientation = KDockSplitOrientation::kHorizontal;
                spec.ratio = 500;
                nodes[fields[1]] = spec;
            }
            else if (fields.size() >= 7 && fields[2] == "SPLIT") {
                KDockSplitOrientation orientation = KDockSplitOrientation::kHorizontal;
                if (!tokenToOrientation(fields[3], orientation)) {
                    continue;
                }
                NodeSpec spec;
                spec.leaf = false;
                spec.orientation = orientation;
                spec.ratio = clampSize(std::atoi(fields[4].c_str()), 100, 900);
                spec.first = fields[5];
                spec.second = fields[6];
                nodes[fields[1]] = spec;
            }
            continue;
        }
        if (line.compare(0, 5, "ROOT|") == 0) {
            rootId = line.substr(5);
            continue;
        }
        if (line.compare(0, 5, "AREA|") == 0) {
            std::size_t p1 = line.find('|');
            std::size_t p2 = line.find('|', p1 + 1);
            std::size_t p3 = line.find('|', p2 + 1);
            if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos) {
                continue;
            }
            std::string areaId = line.substr(p1 + 1, p2 - p1 - 1);
            KDockAreaPosition position = KDockAreaPosition::kCenter;
            tokenToPosition(line.substr(p2 + 1, p3 - p2 - 1), position);
            areaPositions[areaId] = position;
            activeTitles[areaId] = unescapeTitle(line.substr(p3 + 1));
            continue;
        }
        if (line.compare(0, 4, "TAB|") == 0) {
            std::size_t p1 = line.find('|');
            std::size_t p2 = line.find('|', p1 + 1);
            std::size_t p3 = line.find('|', p2 + 1);
            if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos) {
                continue;
            }
            TabSpec spec;
            spec.areaId = line.substr(p1 + 1, p2 - p1 - 1);
            spec.index = std::atoi(line.substr(p2 + 1, p3 - p2 - 1).c_str());
            spec.title = unescapeTitle(line.substr(p3 + 1));
            tabs.push_back(spec);
            continue;
        }
        if (line.compare(0, 6, "FLOAT|") == 0) {
            std::size_t p1 = line.find('|');
            std::size_t p2 = line.find('|', p1 + 1);
            std::size_t p3 = line.find('|', p2 + 1);
            std::size_t p4 = line.find('|', p3 + 1);
            std::size_t p5 = line.find('|', p4 + 1);
            if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos ||
                p4 == std::string::npos || p5 == std::string::npos) {
                continue;
            }
            FloatSpec spec;
            spec.x = std::atoi(line.substr(p1 + 1, p2 - p1 - 1).c_str());
            spec.y = std::atoi(line.substr(p2 + 1, p3 - p2 - 1).c_str());
            spec.w = std::atoi(line.substr(p3 + 1, p4 - p3 - 1).c_str());
            spec.h = std::atoi(line.substr(p4 + 1, p5 - p4 - 1).c_str());
            spec.title = unescapeTitle(line.substr(p5 + 1));
            floats.push_back(spec);
        }
    }
    if (rootId.empty() || nodes.find(rootId) == nodes.end()) {
        return false;
    }
    resetDocksForRestore();
    deleteLayoutTree(rootNode_);
    rootNode_ = nullptr;
    std::map<std::string, bool> building;
    std::function<KDockLayoutNode*(const std::string&)> buildNode = [&](const std::string& nodeId) -> KDockLayoutNode* {
        auto specIt = nodes.find(nodeId);
        if (specIt == nodes.end() || building[nodeId]) {
            return nullptr;
        }
        building[nodeId] = true;
        const NodeSpec& spec = specIt->second;
        KDockLayoutNode* node = nullptr;
        if (spec.leaf) {
            KDockAreaPosition position = KDockAreaPosition::kCenter;
            auto posIt = areaPositions.find(spec.areaId);
            if (posIt != areaPositions.end()) {
                position = posIt->second;
            }
            KDockArea* dockArea = createAreaForRestore(spec.areaId, position);
            node = new KDockLayoutNode(dockArea);
        }
        else {
            KDockLayoutNode* first = buildNode(spec.first);
            KDockLayoutNode* second = buildNode(spec.second);
            if (first && second) {
                node = new KDockLayoutNode(spec.orientation, first, second, spec.ratio);
            }
            else {
                deleteLayoutTree(first);
                deleteLayoutTree(second);
            }
        }
        building[nodeId] = false;
        return node;
    };
    rootNode_ = buildNode(rootId);
    if (!rootNode_) {
        rootNode_ = new KDockLayoutNode(center_);
    }
    rootNode_->parent = nullptr;
    std::sort(tabs.begin(), tabs.end(), [](const TabSpec& a, const TabSpec& b) {
        if (a.areaId == b.areaId) {
            return a.index < b.index;
        }
        return a.areaId < b.areaId;
    });
    bool restoredAny = false;
    for (const TabSpec& spec : tabs) {
        KDockArea* dockArea = areaByLayoutId(spec.areaId);
        KDockWidget* dock = findDockByTitle(spec.title);
        if (!dockArea || !dock) {
            continue;
        }
        rememberDock(dock);
        dock->setDockManager(this);
        dockArea->addDockWidget(dock);
        restoredAny = true;
    }
    for (const auto& item : activeTitles) {
        if (item.second.empty()) {
            continue;
        }
        KDockArea* dockArea = areaByLayoutId(item.first);
        KDockWidget* active = findDockByTitle(item.second);
        if (dockArea && active && dockArea->indexOfDockWidget(active) >= 0) {
            dockArea->setActiveDockWidget(active);
        }
    }
    for (const FloatSpec& spec : floats) {
        KDockWidget* dock = findDockByTitle(spec.title);
        if (!dock) {
            continue;
        }
        rememberDock(dock);
        dock->setDockManager(this);
        removeDockFromAreas(dock);
        dock->createFloatingWindowAt(spec.x, spec.y, spec.w, spec.h);
        restoredAny = true;
    }
    cleanupEmptyAreas();
    layoutAreas();
    redraw();
    return restoredAny;
}
KDockAreaPosition KDockManager::dropPositionForRootPoint(int rootX, int rootY) const {
    int rootBoxX = 0;
    int rootBoxY = 0;
    int rootBoxW = 0;
    int rootBoxH = 0;
    widgetRootBox(this, rootBoxX, rootBoxY, rootBoxW, rootBoxH);
    int localX = rootX - rootBoxX;
    int localY = rootY - rootBoxY;
    return sideToPosition(sideForPointInBox(localX, localY, rootBoxW, rootBoxH));
}
KDockDropTarget KDockManager::dropTargetForRootPoint(KDockWidget* widget, int rootX, int rootY) const {
    KDockDropTarget target;
    int managerRootX = 0;
    int managerRootY = 0;
    int managerW = 0;
    int managerH = 0;
    widgetRootBox(this, managerRootX, managerRootY, managerW, managerH);
    // Outside the manager is intentionally invalid so the dock remains floating.
    if (rootX < managerRootX || rootX >= managerRootX + managerW ||
        rootY < managerRootY || rootY >= managerRootY + managerH) {
        return target;
    }
    for (KDockArea* dockArea : allAreas_) {
        if (!dockArea || !dockArea->visible() || dockArea->dockCount() <= 0) {
            continue;
        }
        KDockWidget* dock = dockArea->activeDockWidget();
        if (!dock || dock == widget || !dock->visible() || dock->isFloating()) {
            continue;
        }
        int dockRootX = 0;
        int dockRootY = 0;
        int dockW = 0;
        int dockH = 0;
        widgetRootBox(dock, dockRootX, dockRootY, dockW, dockH);
        if (rootX < dockRootX || rootX >= dockRootX + dockW ||
            rootY < dockRootY || rootY >= dockRootY + dockH) {
            continue;
        }
        target.valid = true;
        target.scope = KDockDropScope::kDockWidget;
        target.side = sideForPointInBox(rootX - dockRootX, rootY - dockRootY, dockW, dockH);
        target.area = dockArea;
        target.dock = dock;
        target.position = dockArea->position();
        return target;
    }
    target.valid = true;
    target.scope = KDockDropScope::kMainWindow;
    target.side = sideForPointInBox(rootX - managerRootX, rootY - managerRootY, managerW, managerH);
    target.position = sideToPosition(target.side);
    target.area = area(target.position);
    return target;
}
KDockDropTarget KDockManager::dropTargetForFloatingWidget(KDockWidget* widget, int rootX, int rootY) const {
    // First use the real cursor point so precise guide selection still works.
    // If the cursor is outside the dock manager, fall back to the floating host
    // center. That matches user intent when the window body is visibly over the
    // dock surface but the mouse is over the floating title bar or outside the
    // small manager rectangle. The return value is the best available target.
    KDockDropTarget target = dropTargetForRootPoint(widget, rootX, rootY);
    if (target.valid || !widget || !widget->isFloating()) {
        return target;
    }
    int centerX = 0;
    int centerY = 0;
    if (!widget->floatingCenterRootPoint(centerX, centerY)) {
        return target;
    }
    return dropTargetForRootPoint(widget, centerX, centerY);
}
KDockAreaPosition KDockManager::positionForDropTarget(const KDockDropTarget& target) const {
    if (!target.valid) {
        return KDockAreaPosition::kCenter;
    }
    return sideToPosition(target.side);
}
void KDockManager::drawDropOverlay() {
    if (!activeDropTarget_.valid) {
        return;
    }
    // Main-window guides remain visible for context; dock-local drops also draw
    // a second guide set over the hovered dock to clarify split/tab scope.
    KDockDropSide mainSide = activeDropTarget_.scope == KDockDropScope::kMainWindow
        ? activeDropTarget_.side
        : KDockDropSide::kNone;
    drawDropGuideSet(x(), y(), w(), h(), mainSide);
    if (activeDropTarget_.scope == KDockDropScope::kMainWindow) {
        drawDropPreview(x(), y(), w(), h(), activeDropTarget_.side);
        return;
    }
    if (activeDropTarget_.scope != KDockDropScope::kDockWidget || !activeDropTarget_.dock) {
        return;
    }
    int windowRootX = 0;
    int windowRootY = 0;
    if (top_window()) {
        windowRootX = top_window()->x_root();
        windowRootY = top_window()->y_root();
    }
    int dockRootX = 0;
    int dockRootY = 0;
    int dockW = 0;
    int dockH = 0;
    widgetRootBox(activeDropTarget_.dock, dockRootX, dockRootY, dockW, dockH);
    int dockX = dockRootX - windowRootX;
    int dockY = dockRootY - windowRootY;
    drawDropPreview(dockX, dockY, dockW, dockH, activeDropTarget_.side);
    drawDropGuideSet(dockX, dockY, dockW, dockH, activeDropTarget_.side);
}
void KDockManager::layoutNode(KDockLayoutNode* node, int nodeX, int nodeY, int nodeW, int nodeH) {
    if (!node) {
        return;
    }
    if (node->isLeaf) {
        KDockArea* dockArea = node->area;
        if (!dockArea) {
            return;
        }
        bool shouldShow = (dockArea == center_) || dockArea->dockCount() > 0;
        if (dockArea->x() != nodeX || dockArea->y() != nodeY ||
            dockArea->w() != nodeW || dockArea->h() != nodeH) {
            dockArea->resize(nodeX, nodeY, std::max(1, nodeW), std::max(1, nodeH));
        }
        shouldShow ? dockArea->show() : dockArea->hide();
        dockArea->layoutDocks();
        return;
    }
    int ratio = clampSize(node->firstRatio, 100, 900);
    if (node->orientation == KDockSplitOrientation::kHorizontal) {
        int firstW = (nodeW <= kMinClientSize * 2)
            ? std::max(1, nodeW / 2)
            : clampSize(nodeW * ratio / 1000, kMinClientSize, nodeW - kMinClientSize);
        int secondW = std::max(1, nodeW - firstW);
        layoutNode(node->first, nodeX, nodeY, firstW, nodeH);
        layoutNode(node->second, nodeX + firstW, nodeY, secondW, nodeH);
    }
    else {
        int firstH = (nodeH <= kMinClientSize * 2)
            ? std::max(1, nodeH / 2)
            : clampSize(nodeH * ratio / 1000, kMinClientSize, nodeH - kMinClientSize);
        int secondH = std::max(1, nodeH - firstH);
        layoutNode(node->first, nodeX, nodeY, nodeW, firstH);
        layoutNode(node->second, nodeX, nodeY + firstH, nodeW, secondH);
    }
}
KDockManager* kCreateDockManager(int x, int y, int w, int h) {
    return new KDockManager(x, y, w, h);
}
KDockWidget* kCreateDockWidget(const char* title, Fl_Widget* content) {
    // Some FLTK group-derived content widgets may still be the current group
    // after construction. Creating the dock while that is true can make the
    // dock a child of its own future content, so remember a safe caller group.
    Fl_Group* previousCurrent = Fl_Group::current();
    Fl_Group* restoreCurrent = previousCurrent;
    if (content && isAncestor(content, previousCurrent)) {
        restoreCurrent = content->parent();
    }
    Fl_Group::current(restoreCurrent);
    int contentW = content ? std::max(260, content->w() + kMargin * 2) : 320;
    int contentH = content ? std::max(180, content->h() + kTitleHeight + kMargin * 2) : 240;
    KDockWidget* dock = new KDockWidget(0, 0, contentW, contentH, title, content);
    // Restore the caller's construction context after the composite dock closes
    // its own group. Never restore to a group now contained by the new dock.
    if (restoreCurrent == dock || isAncestor(dock, restoreCurrent)) {
        restoreCurrent = dock->parent();
    }
    Fl_Group::current(restoreCurrent);
    return dock;
}
