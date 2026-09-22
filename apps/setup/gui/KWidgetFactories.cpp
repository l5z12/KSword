#include "KWidgets.h"
#include "KTitleBar.h"

#include "Fl_Window.H"
#include "fl_draw.H"

#include <algorithm>
#include <cstdint>

namespace {
constexpr int kPopupFontSize = 12;

// closeMessageCallback hides the modal message window passed in user data.
void closeMessageCallback(Fl_Widget*, void* data) {
    Fl_Window* win = static_cast<Fl_Window*>(data);
    if (win) {
        win->hide();
    }
}

// PopupMenuState carries the selected index out of the modal popup loop.
struct PopupMenuState {
    int selected = -1;
    Fl_Window* window = nullptr;
};

// PopupMenuWindow closes when the user clicks outside its bounds.
class PopupMenuWindow : public Fl_Window {
public:
    // Creates a borderless popup at root-screen coordinates.
    explicit PopupMenuWindow(int x, int y, int w, int h)
        : Fl_Window(x, y, w, h) {
    }

    // Handles outside-click dismissal and delegates other events to Fl_Window.
    int handle(int event) override {
        if (event == FL_PUSH) {
            const int kEx = Fl::event_x_root();
            const int kKey = Fl::event_y_root();
            if (kEx < x() || kEx >= x() + w() || kKey < y() || kKey >= y() + h()) {
                hide();
                return 1;
            }
        }
        return Fl_Window::handle(event);
    }
};

// popupMenuItemCallback stores the clicked item index and closes the popup.
void popupMenuItemCallback(Fl_Widget* widget, void* data) {
    PopupMenuState* state = static_cast<PopupMenuState*>(data);
    if (!state || !state->window) {
        return;
    }
    state->selected = static_cast<int>(reinterpret_cast<intptr_t>(widget->user_data()));
    state->window->hide();
}
}

KButton* kCreateButton(int x, int y, int w, int h, const char* label, KButtonType type) {
    return new KButton(x, y, w, h, label, type);
}

KInput* kCreateInput(int x, int y, int w, int h, const char* label) {
    return new KInput(x, y, w, h, label);
}

KCheckBox* kCreateCheckBox(int x, int y, int w, int h, const char* label) {
    return new KCheckBox(x, y, w, h, label);
}

KSlider* kCreateSlider(int x, int y, int w, int h) {
    return new KSlider(x, y, w, h);
}

KText* kCreateText(int x, int y, int w, int h, const char* label) {
    return new KText(x, y, w, h, label);
}

KTextBox* kCreateTextBox(int x, int y, int w, int h, const char* label) {
    return new KTextBox(x, y, w, h, label);
}

KTable* kCreateTable(int x, int y, int w, int h, const char* label) {
    return new KTable(x, y, w, h, label);
}

KPanel* kCreatePanel(int x, int y, int w, int h, const char* label) {
    return new KPanel(x, y, w, h, label);
}

KCard* kCreateCard(int x, int y, int w, int h, const char* label) {
    // Factory returns an empty themed card container; callers add child widgets as needed.
    return new KCard(x, y, w, h, label);
}

KToolbar* kCreateToolbar(int x, int y, int w, int h, const char* label) {
    // Factory returns a square flat toolbar suitable for KButton and KInput children.
    return new KToolbar(x, y, w, h, label);
}

KStatusBar* kCreateStatusBar(int x, int y, int w, int h, const char* label) {
    // Factory returns a status strip with left text initialized from the optional label.
    return new KStatusBar(x, y, w, h, label);
}

KBadge* kCreateBadge(int x, int y, int w, int h, const char* label) {
    // Factory returns a compact state/count badge with theme primary accent.
    return new KBadge(x, y, w, h, label);
}

KSeparator* kCreateSeparator(int x, int y, int w, int h, KSeparatorOrientation orientation) {
    // Factory returns a paint-only divider in the requested horizontal or vertical orientation.
    return new KSeparator(x, y, w, h, orientation);
}

KChoice* kCreateChoice(int x, int y, int w, int h, const char* label) {
    return new KChoice(x, y, w, h, label);
}

void kChoiceSetItems(Fl_Choice* choice, const std::vector<std::string>& items, int selected) {
    if (!choice) {
        return;
    }
    choice->clear();
    for (const std::string& item : items) {
        choice->add(item.c_str());
    }
    if (!items.empty()) {
        selected = std::max(0, std::min(selected, static_cast<int>(items.size()) - 1));
        choice->value(selected);
    }
}

KOutput* kCreateOutput(int x, int y, int w, int h, const char* label) {
    return new KOutput(x, y, w, h, label);
}

KProgressBar* kCreateProgress(int x, int y, int w, int h, const char* label) {
    return new KProgressBar(x, y, w, h, label);
}

KRadioButton* kCreateRadioButton(int x, int y, int w, int h, const char* label) {
    return new KRadioButton(x, y, w, h, label);
}

KToggleButton* kCreateToggleButton(int x, int y, int w, int h, const char* label) {
    return new KToggleButton(x, y, w, h, label);
}

KLightButton* kCreateLightButton(int x, int y, int w, int h, const char* label) {
    return new KLightButton(x, y, w, h, label);
}

KScrollArea* kCreateScroll(int x, int y, int w, int h, const char* label) {
    return new KScrollArea(x, y, w, h, label);
}

KScrollBar* kCreateScrollBar(int x, int y, int w, int h, int type) {
    return new KScrollBar(x, y, w, h, type);
}

KTabs* kCreateTabs(int x, int y, int w, int h, const char* label) {
    return new KTabs(x, y, w, h, label);
}

KPanel* kCreateTabPage(int x, int y, int w, int h, const char* label) {
    return new KPanel(x, y, w, h, label);
}

KScrollArea* kCreateScrollArea(int x, int y, int w, int h, const char* label) {
    return new KScrollArea(x, y, w, h, label);
}

KTextDisplay* kCreateTextDisplay(int x, int y, int w, int h, const char* label) {
    return new KTextDisplay(x, y, w, h, label);
}

KImageView* kCreateImageView(int x, int y, int w, int h, const char* label) {
    // Factory returns a themed image view with no loaded image; callers set path or Fl_Image later.
    return new KImageView(x, y, w, h, label);
}

KImageView* kCreateImageViewFromFile(int x, int y, int w, int h, const char* path, const char* label, KImageFitMode mode) {
    // Factory creates the view, applies the requested fit mode, then loads through KImageResource.
    KImageView* view = new KImageView(x, y, w, h, label);
    view->setFitMode(mode);
    view->setImagePath(path);
    return view;
}

KBrowser* kCreateBrowser(int x, int y, int w, int h, const char* label) {
    return new KBrowser(x, y, w, h, label);
}

KMenuButton* kCreateMenuButton(int x, int y, int w, int h, const char* label) {
    return new KMenuButton(x, y, w, h, label);
}

KCounter* kCreateCounter(int x, int y, int w, int h, const char* label) {
    return new KCounter(x, y, w, h, label);
}

KSpinner* kCreateSpinner(int x, int y, int w, int h, const char* label) {
    return new KSpinner(x, y, w, h, label);
}

KValueInput* kCreateValueInput(int x, int y, int w, int h, const char* label) {
    return new KValueInput(x, y, w, h, label);
}

KSplitter* kCreateSplitter(int x, int y, int w, int h, const char* label) {
    return new KSplitter(x, y, w, h, label);
}

KBreadcrumb* kCreateBreadcrumb(int x, int y, int w, int h, const char* label) {
    // Factory returns a themed breadcrumb path widget with no initial items.
    return new KBreadcrumb(x, y, w, h, label);
}

KSideNav* kCreateSideNav(int x, int y, int w, int h, const char* label) {
    // Factory returns a vertical navigation list; callers populate rows with setItems().
    return new KSideNav(x, y, w, h, label);
}

KTopNav* kCreateTopNav(int x, int y, int w, int h, const char* label) {
    // Factory returns a horizontal navigation strip; callers populate rows with setItems().
    return new KTopNav(x, y, w, h, label);
}

KTreeView* kCreateTreeView(int x, int y, int w, int h, const char* label) {
    // Factory returns a lightweight expandable tree; callers provide KTreeNode roots.
    return new KTreeView(x, y, w, h, label);
}

KCommandPalette* kCreateCommandPalette(int x, int y, int w, int h, const char* label) {
    // Factory returns a modal command-palette shell without showing it immediately.
    return new KCommandPalette(x, y, w, h, label);
}

KSectionHeader* kCreateSectionHeader(int x, int y, int w, int h, const char* label) {
    // Factory returns a paint-only section header with optional action text support.
    return new KSectionHeader(x, y, w, h, label);
}

KToast* kCreateToast(int x, int y, int w, int h, const char* label) {
    // Factory returns a borderless toast popup; callers call showAt() when needed.
    return new KToast(x, y, w, h, label);
}

KTooltip* kCreateTooltip(int x, int y, int w, int h, const char* label) {
    // Factory returns a borderless tooltip popup; callers place it near the target.
    return new KTooltip(x, y, w, h, label);
}

KPopover* kCreatePopover(int x, int y, int w, int h, const char* label) {
    // Factory returns a titled popover shell with setContent() body text.
    return new KPopover(x, y, w, h, label);
}

KModalDialog* kCreateModalDialog(int x, int y, int w, int h, const char* label) {
    // Factory returns a self-drawn modal dialog shell; callers run it with runModal().
    return new KModalDialog(x, y, w, h, label);
}

KDrawer* kCreateDrawer(int x, int y, int w, int h, const char* label) {
    // Factory returns a themed drawer shell; callers decide edge positioning.
    return new KDrawer(x, y, w, h, label);
}

KOverlayMask* kCreateOverlayMask(int x, int y, int w, int h, const char* label) {
    // Factory returns a hidden overlay mask; callers enable it with setVisible().
    return new KOverlayMask(x, y, w, h, label);
}

KLoadingOverlay* kCreateLoadingOverlay(int x, int y, int w, int h, const char* label) {
    // Factory returns a loading overlay with caller-controlled loading/progress state.
    return new KLoadingOverlay(x, y, w, h, label);
}

KContextMenu* kCreateContextMenu(int x, int y, int w, int h, const char* label) {
    // Factory returns an enhanced context menu supporting disabled, checked, and separator rows.
    return new KContextMenu(x, y, w, h, label);
}

KStack* kCreateStack(int x, int y, int w, int h, const char* label) {
    // Factory returns a page stack container; callers add child pages with FLTK grouping.
    return new KStack(x, y, w, h, label);
}

KGridLayout* kCreateGridLayout(int x, int y, int w, int h, const char* label) {
    // Factory returns a fixed grid layout container.
    return new KGridLayout(x, y, w, h, label);
}

KVBox* kCreateVBox(int x, int y, int w, int h, const char* label) {
    // Factory returns a vertical box layout container.
    return new KVBox(x, y, w, h, label);
}

KHBox* kCreateHBox(int x, int y, int w, int h, const char* label) {
    // Factory returns a horizontal box layout container.
    return new KHBox(x, y, w, h, label);
}

KSplitterPane* kCreateSplitterPane(int x, int y, int w, int h, const char* label) {
    // Factory returns an enhanced two-pane splitter with draggable ratio.
    return new KSplitterPane(x, y, w, h, label);
}

KAccordion* kCreateAccordion(int x, int y, int w, int h, const char* label) {
    // Factory returns a text-section accordion; callers provide sections with setSections().
    return new KAccordion(x, y, w, h, label);
}

KExpander* kCreateExpander(int x, int y, int w, int h, const char* label) {
    // Factory returns a collapsible group container.
    return new KExpander(x, y, w, h, label);
}

KGroupBox* kCreateGroupBox(int x, int y, int w, int h, const char* label) {
    // Factory returns a titled group container.
    return new KGroupBox(x, y, w, h, label);
}

KScrollablePanel* kCreateScrollablePanel(int x, int y, int w, int h, const char* label) {
    // Factory returns a themed scroll container with padding metadata.
    return new KScrollablePanel(x, y, w, h, label);
}

KIconButton* kCreateIconButton(int x, int y, int w, int h, const char* label) {
    // Factory returns an icon-capable flat button.
    return new KIconButton(x, y, w, h, label);
}

KAvatar* kCreateAvatar(int x, int y, int w, int h, const char* label) {
    // Factory returns a square avatar with initials derived from label/name.
    return new KAvatar(x, y, w, h, label);
}

KTag* kCreateTag(int x, int y, int w, int h, const char* label) {
    // Factory returns a compact non-interactive tag.
    return new KTag(x, y, w, h, label);
}

KChip* kCreateChip(int x, int y, int w, int h, const char* label) {
    // Factory returns a selectable chip token.
    return new KChip(x, y, w, h, label);
}

KAlert* kCreateAlert(int x, int y, int w, int h, const char* label) {
    // Factory returns a semantic alert block.
    return new KAlert(x, y, w, h, label);
}

KEmptyState* kCreateEmptyState(int x, int y, int w, int h, const char* label) {
    // Factory returns an empty-state panel with optional action callback area.
    return new KEmptyState(x, y, w, h, label);
}

KSkeleton* kCreateSkeleton(int x, int y, int w, int h, const char* label) {
    // Factory returns a loading skeleton placeholder.
    return new KSkeleton(x, y, w, h, label);
}

KTimeline* kCreateTimeline(int x, int y, int w, int h, const char* label) {
    // Factory returns a vertical timeline display.
    return new KTimeline(x, y, w, h, label);
}

KMetricCard* kCreateMetricCard(int x, int y, int w, int h, const char* label) {
    // Factory returns a compact KPI card.
    return new KMetricCard(x, y, w, h, label);
}

KListView* kCreateListView(int x, int y, int w, int h, const char* label) {
    // Factory returns a lightweight rich list view.
    return new KListView(x, y, w, h, label);
}

KPropertyGrid* kCreatePropertyGrid(int x, int y, int w, int h, const char* label) {
    // Factory returns a property-name/value grid.
    return new KPropertyGrid(x, y, w, h, label);
}

KKeyValueTable* kCreateKeyValueTable(int x, int y, int w, int h, const char* label) {
    // Factory returns a read-only two-column key/value table.
    return new KKeyValueTable(x, y, w, h, label);
}

KMiniChart* kCreateMiniChart(int x, int y, int w, int h, const char* label) {
    // Factory returns a mini chart that can draw line or bar data.
    return new KMiniChart(x, y, w, h, label);
}

KProgressRing* kCreateProgressRing(int x, int y, int w, int h, const char* label) {
    // Factory returns a circular progress indicator.
    return new KProgressRing(x, y, w, h, label);
}

KStepper* kCreateStepper(int x, int y, int w, int h, const char* label) {
    // Factory returns a horizontal multi-step progress indicator.
    return new KStepper(x, y, w, h, label);
}

void kShowMessage(const char* title, const char* message) {
    Fl_Window dialog(380, 170, title ? title : "Message");
    dialog.set_modal();
    setWindowStyle(&dialog);
    dialog.begin();
    KText msg(20, 20, 340, 75, message ? message : "");
    msg.align(FL_ALIGN_LEFT | FL_ALIGN_TOP | FL_ALIGN_INSIDE);
    KButton ok(140, 115, 100, 34, u8"确定", kKbuttonHeavy);
    ok.callback(closeMessageCallback, &dialog);
    dialog.end();
    // Dialogs use the same custom caption implementation but hide maximize so
    // modal message geometry stays predictable and lightweight.
    kInstallTitleBar(&dialog, KTitleBarStyle::kFade, false);
    dialog.show();
    kApplyWindowIcon(&dialog);
    while (dialog.shown()) {
        Fl::wait();
    }
}

int kShowPopupMenu(int x, int y, const std::vector<std::string>& items) {
    if (items.empty()) {
        return -1;
    }

    const int kItemHeight = 28;
    const int kPaddingX = 12;
    fl_font(FL_HELVETICA, kPopupFontSize);
    int maxLabelWidth = 0;
    for (const std::string& item : items) {
        maxLabelWidth = std::max(maxLabelWidth, static_cast<int>(fl_width(item.c_str())));
    }

    const int kMenuWidth = maxLabelWidth + kPaddingX * 2 + 20;
    const int kMenuHeight = static_cast<int>(items.size()) * kItemHeight;
    int screenX = 0;
    int screenY = 0;
    int screenW = 0;
    int screenH = 0;
    Fl::screen_xywh(screenX, screenY, screenW, screenH, x, y);
    x = std::max(screenX, std::min(x, screenX + screenW - kMenuWidth));
    y = std::max(screenY, std::min(y, screenY + screenH - kMenuHeight));

    PopupMenuWindow menuWindow(x, y, kMenuWidth, kMenuHeight);
    menuWindow.border(0);
    setWindowStyle(&menuWindow);
    menuWindow.set_modal();
    PopupMenuState state;
    state.window = &menuWindow;

    menuWindow.begin();
    for (std::size_t i = 0; i < items.size(); ++i) {
        KButton* button = new KButton(0, static_cast<int>(i) * kItemHeight, kMenuWidth, kItemHeight, items[i].c_str(), kKbuttonLight);
        button->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        button->user_data(reinterpret_cast<void*>(static_cast<intptr_t>(i)));
        button->callback(popupMenuItemCallback, &state);
    }
    menuWindow.end();

    menuWindow.show();
    Fl::grab(&menuWindow);
    while (menuWindow.shown()) {
        Fl::wait();
    }
    Fl::grab(nullptr);
    return state.selected;
}
