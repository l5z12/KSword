#include "MonitorDock.Support.h"

namespace ksword::ui::monitor_dock
{
    // Unify button styles according to the theme.
    QString blueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    // Unified style for input fields.
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QPlainTextEdit,QSpinBox{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus,QPlainTextEdit:focus,QSpinBox:focus{border:1px solid %1;}")
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            + ksword_theme::themedComboBoxStyle();
    }

    void installMonitorTableCopyMenu(QTableWidget* tableWidget)
    {
        // installMonitorTableCopyMenu：
        // - Input: Read-only or selectable tables within the monitoring page.
        // - Handling: Right-clicks to locate the current row and copies all columns in that row as TSV.
        // - Returns: None. Only copies existing UI text; does not start/stop WMI or ETW sessions.
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tableWidget, &QTableWidget::customContextMenuRequested, tableWidget, [tableWidget](const QPoint& localPosition)
        {
            const auto kClickedIndex = tableWidget->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                tableWidget->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            }

            QMenu menu(tableWidget);
            // Right-click menu must explicitly use an opaque theme to avoid black-on-black text caused by background images or transparent styles.
            menu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/log_clipboard.svg")),
                QStringLiteral("复制整行"));
            copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
            if (menu.exec(tableWidget->viewport()->mapToGlobal(localPosition)) != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QApplication::clipboard();
            const int kRowIndex = tableWidget->currentRow();
            if (clipboardObject == nullptr || kRowIndex < 0 || kRowIndex >= tableWidget->rowCount())
            {
                return;
            }

            QStringList values;
            values.reserve(tableWidget->columnCount());
            for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* item = tableWidget->item(kRowIndex, columnIndex);
                values << (item != nullptr ? item->text() : QString());
            }
            clipboardObject->setText(values.join(QLatin1Char('\t')));
        });
    }

    void installMonitorTableViewCopyMenu(QTableView* tableView)
    {
        // installMonitorTableViewCopyMenu：
        // - Input: Read-only table view using QAbstractItemModel/QSortFilterProxyModel;
        // - Processing: Right-click to locate the current proxy row and copy the entire TSV row according to the current display order.
        // - Returns: None. Only copies audit lists such as WMI Providers; does not start or stop any monitoring sessions.
        if (tableView == nullptr)
        {
            return;
        }

        tableView->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tableView, &QTableView::customContextMenuRequested, tableView, [tableView](const QPoint& localPosition)
        {
            const QModelIndex kClickedIndex = tableView->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                tableView->setCurrentIndex(kClickedIndex);
                tableView->selectRow(kClickedIndex.row());
            }

            QMenu menu(tableView);
            // QTableView must also explicitly use opaque menu styles to avoid inheriting the parent's transparent background.
            menu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/log_clipboard.svg")),
                QStringLiteral("复制整行"));
            copyRowAction->setEnabled(tableView->currentIndex().isValid());
            if (menu.exec(tableView->viewport()->mapToGlobal(localPosition)) != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QApplication::clipboard();
            QAbstractItemModel* modelObject = tableView->model();
            const QModelIndex kCurrentIndex = tableView->currentIndex();
            if (clipboardObject == nullptr || modelObject == nullptr || !kCurrentIndex.isValid())
            {
                return;
            }

            QStringList values;
            values.reserve(modelObject->columnCount(kCurrentIndex.parent()));
            for (int columnIndex = 0; columnIndex < modelObject->columnCount(kCurrentIndex.parent()); ++columnIndex)
            {
                const QModelIndex kCellIndex = modelObject->index(kCurrentIndex.row(), columnIndex, kCurrentIndex.parent());
                values << modelObject->data(kCellIndex, Qt::DisplayRole).toString();
            }
            clipboardObject->setText(values.join(QLatin1Char('\t')));
        });
    }

    // createMonitorDeferredPlaceholder:
    // - Input: parent widget, title text, and hint text;
    // - Processing: Create a lightweight placeholder page to avoid heavy monitoring sub-pages blocking the MonitorDock's first-click path.
    // - Return: Placeholder QWidget pointer; caller adds it to the corresponding host layout.
    QWidget* createMonitorDeferredPlaceholder(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& hintText)
    {
        QWidget* placeholderWidget = new QWidget(parentWidget);
        placeholderWidget->setAutoFillBackground(false);
        placeholderWidget->setAttribute(Qt::WA_StyledBackground, false);

        QVBoxLayout* placeholderLayout = new QVBoxLayout(placeholderWidget);
        placeholderLayout->setContentsMargins(24, 24, 24, 24);
        placeholderLayout->setSpacing(8);
        placeholderLayout->addStretch(1);

        QLabel* titleLabel = new QLabel(titleText, placeholderWidget);
        titleLabel->setAlignment(Qt::AlignCenter);
        titleLabel->setStyleSheet(
            QStringLiteral("font-size:16px;font-weight:700;color:%1;")
            .arg(ksword_theme::textPrimaryHex()));
        placeholderLayout->addWidget(titleLabel, 0);

        QLabel* hintLabel = new QLabel(hintText, placeholderWidget);
        hintLabel->setAlignment(Qt::AlignCenter);
        hintLabel->setWordWrap(true);
        hintLabel->setStyleSheet(
            QStringLiteral("font-size:12px;color:%1;")
            .arg(ksword_theme::textSecondaryHex()));
        placeholderLayout->addWidget(hintLabel, 0);
        placeholderLayout->addStretch(1);
        return placeholderWidget;
    }

    // Unified header style.
    QString blueHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;padding:4px;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    // collapsePanelStyle:
    // - Provides theme-adaptive borders and backgrounds for the WMI/ETW top-level collapsible panel;
    // - Returns: Style sheets ready to be applied directly to the collapsible panel's QWidget host.
    QString collapsePanelStyle()
    {
        return QStringLiteral(
            "QWidget[kswordCollapsePanel=\"true\"]{"
            "  background:transparent;"
            "  background-color:transparent;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:5px;"
            "}"
            "QWidget[kswordCollapseContent=\"true\"]{"
            "  background:transparent;"
            "  background-color:transparent;"
            "  color:%2;"
            "  border:none;"
            "}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex());
    }

    // collapseHeaderButtonStyle:
    // - Override the collapse header button theme to avoid inheriting the fixed color scheme of legacy Collapse/QToolBox;
    // - Returns: A style sheet ready to be applied to a QToolButton.
    QString collapseHeaderButtonStyle()
    {
        return QStringLiteral(
            "QToolButton{"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:5px;"
            "  padding:5px 8px;"
            "  font-weight:600;"
            "  text-align:left;"
            "}"
            "QToolButton:hover{"
            "  background:%4;"
            "  color:%2;"
            "  border-color:%5;"
            "}"
            "QToolButton:checked{"
            "  background:%4;"
            "  color:%2;"
            "  border-color:%5;"
            "}")
            .arg(ksword_theme::surfaceAltHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::primaryBlueSubtleHex())
            .arg(ksword_theme::kPrimaryBlueHex);
    }

    // createIndependentCollapseSection:
    // - Constructs a non-exclusive collapsible section, allowing all sections to collapse simultaneously.
    // - Parameters: parent (parent widget), titleText (title), contentWidget (existing content widget), expanded (initial expanded state);
    // - Returns: The outer collapsible section QWidget; its header and content are released with the parent object.
    QWidget* createIndependentCollapseSection(
        QWidget* parent,
        const QString& titleText,
        QWidget* contentWidget,
        const bool expanded)
    {
        QWidget* sectionWidget = new QWidget(parent);
        sectionWidget->setProperty("kswordCollapsePanel", QStringLiteral("true"));
        sectionWidget->setStyleSheet(collapsePanelStyle());
        sectionWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);

        QVBoxLayout* sectionLayout = new QVBoxLayout(sectionWidget);
        sectionLayout->setContentsMargins(0, 0, 0, 0);
        sectionLayout->setSpacing(0);

        QToolButton* headerButton = new QToolButton(sectionWidget);
        headerButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        headerButton->setText(titleText);
        headerButton->setCheckable(true);
        headerButton->setChecked(expanded);
        headerButton->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
        headerButton->setStyleSheet(collapseHeaderButtonStyle());
        headerButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

        QWidget* contentHostWidget = new QWidget(sectionWidget);
        contentHostWidget->setProperty("kswordCollapseContent", QStringLiteral("true"));
        contentHostWidget->setStyleSheet(collapsePanelStyle());
        contentHostWidget->setVisible(expanded);
        contentHostWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);

        QVBoxLayout* contentHostLayout = new QVBoxLayout(contentHostWidget);
        contentHostLayout->setContentsMargins(4, 4, 4, 4);
        contentHostLayout->setSpacing(4);
        contentHostLayout->addWidget(contentWidget);

        sectionLayout->addWidget(headerButton, 0);
        sectionLayout->addWidget(contentHostWidget, 0);

        QObject::connect(headerButton, &QToolButton::toggled, sectionWidget,
            [headerButton, contentHostWidget, sectionWidget](const bool checked) {
                // Each collapsible section controls only its own content area, without affecting the expansion state of sibling sections.
                headerButton->setArrowType(checked ? Qt::DownArrow : Qt::RightArrow);
                contentHostWidget->setVisible(checked);
                sectionWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
                sectionWidget->updateGeometry();
                QWidget* parentWidget = sectionWidget->parentWidget();
                while (parentWidget != nullptr)
                {
                    parentWidget->updateGeometry();
                    parentWidget = parentWidget->parentWidget();
                }
            });

        return sectionWidget;
    }

    // refreshIndependentCollapseTheme:
    // - Recursively refresh independent collapse section styles in response to light/dark theme switching;
    // - Parameter rootWidget: Root widget to scan.
    // - Returns: Nothing.
    void refreshIndependentCollapseTheme(QWidget* rootWidget)
    {
        if (rootWidget == nullptr)
        {
            return;
        }

        const QList<QWidget*> kWidgetList = rootWidget->findChildren<QWidget*>();
        for (QWidget* widgetPointer : kWidgetList)
        {
            if (widgetPointer == nullptr)
            {
                continue;
            }
            if (widgetPointer->property("kswordCollapsePanel").toString() == QStringLiteral("true")
                || widgetPointer->property("kswordCollapseContent").toString() == QStringLiteral("true"))
            {
                widgetPointer->setStyleSheet(collapsePanelStyle());
            }
        }

        const QList<QToolButton*> kHeaderButtonList = rootWidget->findChildren<QToolButton*>();
        for (QToolButton* buttonPointer : kHeaderButtonList)
        {
            if (buttonPointer != nullptr
                && buttonPointer->parentWidget() != nullptr
                && buttonPointer->parentWidget()->property("kswordCollapsePanel").toString() == QStringLiteral("true"))
            {
                buttonPointer->setStyleSheet(collapseHeaderButtonStyle());
            }
        }
    }
}
