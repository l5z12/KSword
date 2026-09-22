#include "MonitorTextViewer.h"
#include "../Theme.h"
#include "../ui/CodeEditorWidget.h"

// ============================================================
// MonitorTextViewer.cpp
// Purpose:
// 1) Uniformly create read-only text viewer windows;
// 2) Use a purely read-only text box to display details, reducing the crash risk of the monitoring details viewing chain.
// 3) Non-modal display, allowing users to view the event list while cross-referencing original details.
// ============================================================

#include <QDialog>
#include <QDialogButtonBox>
#include <QVBoxLayout>

namespace monitor_text_viewer
{
    void showReadOnlyTextWindow(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& contentText,
        const QString& virtualPathText)
    {
        QDialog* dialogPointer = new QDialog(parentWidget);
        dialogPointer->setAttribute(Qt::WA_DeleteOnClose, true);
        dialogPointer->setObjectName(QStringLiteral("MonitorTextViewerDialog"));
        dialogPointer->setWindowTitle(titleText.trimmed().isEmpty() ? QStringLiteral("详情查看") : titleText);
        dialogPointer->resize(980, 720);
        dialogPointer->setModal(false);
        // Force the details dialog to use an opaque background to avoid a black background in light mode.
        dialogPointer->setStyleSheet(ksword_theme::opaqueDialogStyle(dialogPointer->objectName()));

        QVBoxLayout* layoutPointer = new QVBoxLayout(dialogPointer);
        layoutPointer->setContentsMargins(6, 6, 6, 6);
        layoutPointer->setSpacing(6);

        // editorWidget usage:
        // - Uniformly reuse the project's built-in CodeEditorWidget to satisfy the 'default use internal editor' specification.
        // - Display read-only details text returned by ETW/WMI.
        CodeEditorWidget* editorWidget = new CodeEditorWidget(dialogPointer);
        editorWidget->setReadOnly(true);
        editorWidget->setRawText(contentText);
        editorWidget->setToolTip(virtualPathText.trimmed().isEmpty() ? titleText : virtualPathText);

        QDialogButtonBox* buttonBoxPointer = new QDialogButtonBox(QDialogButtonBox::Close, dialogPointer);
        QObject::connect(buttonBoxPointer, &QDialogButtonBox::rejected, dialogPointer, &QDialog::reject);
        QObject::connect(buttonBoxPointer, &QDialogButtonBox::accepted, dialogPointer, &QDialog::accept);

        layoutPointer->addWidget(editorWidget, 1);
        layoutPointer->addWidget(buttonBoxPointer, 0);

        dialogPointer->show();
        dialogPointer->raise();
        dialogPointer->activateWindow();
    }
}
