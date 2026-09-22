#pragma once

// ============================================================
// HexEditorWidget.Internal.h
// Purpose:
// Aggregates Qt includes and internal tool declarations shared across multiple compilation units of HexEditorWidget.
// - Replaces the old text-concatenation implementation to allow UI and tool logic to participate in the build using real .cpp files.
// - For internal implementation of HexEditorWidget only; external modules continue to include HexEditorWidget.h.
// ============================================================

#include "HexEditorWidget.h"
#include "CodeEditorWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QChar>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIODevice>
#include <QItemSelectionModel>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QMouseEvent>
#include <QModelIndex>
#include <QModelIndexList>
#include <QPoint>
#include <QPointer>
#include <QPushButton>
#include <QRect>
#include <QRegularExpression>
#include <QShortcut>
#include <QStringList>
#include <QStringConverter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QTextStream>
#include <QToolButton>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

namespace ksword::ui::hex_editor_internal
{
    // Style function: if input is empty, return the stylesheet text under the current theme.
    QString buildToolbarButtonStyle();
    QString buildInputStyle();
    QString buildHeaderStyle();
    QString buildMenuStyle();

    // Color functions: return match or selection highlight color if input is null.
    QColor buildMatchColor();
    QColor buildCurrentMatchColor();
    QColor buildSelectionColor();

    // byteToHexText: Takes a single byte value as input and returns a two-character uppercase HEX string.
    QString byteToHexText(std::uint8_t byteValue);

    // normalizeBytesPerRow: Takes a requested row width and returns a safely clamped row width.
    int normalizeBytesPerRow(int requestedBytesPerRow);
}
