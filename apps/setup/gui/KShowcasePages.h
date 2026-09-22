#ifndef KSWORD_GUI_KSHOWCASEPAGES_H
#define KSWORD_GUI_KSHOWCASEPAGES_H

#include "Fl_Group.H"

#include <vector>

// k_showcase_pages contains detached sample-panel factories for manual or mainline integration.
namespace k_showcase_pages {

// Creates a navigation sample page; caller owns the returned FLTK group through normal FLTK parenting.
Fl_Group* createNavigationPage(int x, int y, int w, int h);

// Creates a container sample page; caller owns the returned FLTK group through normal FLTK parenting.
Fl_Group* createContainerPage(int x, int y, int w, int h);

// Creates an overlay sample page; caller owns the returned FLTK group through normal FLTK parenting.
Fl_Group* createOverlayPage(int x, int y, int w, int h);

// Creates a data-display sample page; caller owns the returned FLTK group through normal FLTK parenting.
Fl_Group* createDataPage(int x, int y, int w, int h);

// Creates a visualization sample page; caller owns the returned FLTK group through normal FLTK parenting.
Fl_Group* createVisualPage(int x, int y, int w, int h);

// Creates an input-helper sample page; caller owns the returned FLTK group through normal FLTK parenting.
Fl_Group* createInputPage(int x, int y, int w, int h);

// Creates all showcase pages in a stable navigation order and returns copied pointers.
std::vector<Fl_Group*> createAllPages(int x, int y, int w, int h);

} // namespace k_showcase_pages

#endif // KSWORD_GUI_KSHOWCASEPAGES_H
