#include "DiskMapWidget.h"

// ============================================================
// DiskMapWidget.cpp
// Purpose:
// 1) Draws a horizontal bar chart of disk partitions.
// 2) Maintains the visual proportions of partition start offsets, lengths, and unallocated regions;
// 3) Provide click linkage and hover hints for the upper-level DiskEditorTab.
// ============================================================

#include "../../Theme.h"
#include "../../internationalization/LanguageManager.h"

#include <QBrush>
#include <QFontMetrics>
#include <QLinearGradient>
#include <QMouseEvent>
#include <QPainter>
#include <QPen>
#include <QSizePolicy>
#include <QToolTip>

#include <algorithm>

namespace
{
    // kOuterMargin: Bar chart outer margin, reserving space for the title and shadow.
    constexpr int kOuterMargin = 14;

    // kHeaderHeight: Height of the top disk summary area.
    constexpr int kHeaderHeight = 28;

    // kMapHeight: Height of the main body of the horizontal partition bar.
    constexpr int kMapHeight = 72;

    // kMinVisibleSegmentWidth: Minimum click width retained for extremely small partitions.
    constexpr int kMinVisibleSegmentWidth = 7;

    // formatBytesForDiskMap：
    // - Convert byte count to a concise capacity string;
    // - bytes is the raw byte count;
    // - Returns a string like '512.00 GB'.
    QString formatBytesForDiskMap(const std::uint64_t bytes)
    {
        const double kValue = static_cast<double>(bytes);
        if (bytes >= 1024ULL * 1024ULL * 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 TB").arg(kValue / 1099511627776.0, 0, 'f', 2);
        }
        if (bytes >= 1024ULL * 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 GB").arg(kValue / 1073741824.0, 0, 'f', 2);
        }
        if (bytes >= 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 MB").arg(kValue / 1048576.0, 0, 'f', 2);
        }
        if (bytes >= 1024ULL)
        {
            return QStringLiteral("%1 KB").arg(kValue / 1024.0, 0, 'f', 2);
        }
        return QStringLiteral("%1 B").arg(static_cast<qulonglong>(bytes));
    }

    // darkerColor：
    // - Generate partition border and gradient bottom color;
    // - color is the base color.
    // - Returns a slightly darker QColor.
    QColor darkerColor(const QColor& color)
    {
        return ksword_theme::themeDarkerColor(color);
    }
}

namespace ks::misc
{
    DiskMapWidget::DiskMapWidget(QWidget* parent)
        : QWidget(parent)
    {
        // Mouse tracking enables real-time tooltips and hover outlines.
        setMouseTracking(true);
        setMinimumHeight(kOuterMargin * 2 + kHeaderHeight + kMapHeight + 22);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }

    void DiskMapWidget::setDisk(const DiskDeviceInfo& diskInfo)
    {
        // Save snapshot to avoid external vector lifetime affecting rendering.
        diskInfo_ = diskInfo;
        hasDisk_ = true;
        selectedPartitionIndex_ = -1;
        hoverPartitionIndex_ = -1;
        update();
    }

    void DiskMapWidget::clearDisk()
    {
        // Clear the state while maintaining placeholder rendering to prevent the page from suddenly collapsing.
        diskInfo_ = DiskDeviceInfo{};
        hasDisk_ = false;
        selectedPartitionIndex_ = -1;
        hoverPartitionIndex_ = -1;
        update();
    }

    void DiskMapWidget::setSelectedPartitionIndex(const int partitionIndex)
    {
        if (selectedPartitionIndex_ == partitionIndex)
        {
            return;
        }
        selectedPartitionIndex_ = partitionIndex;
        update();
    }

    void DiskMapWidget::paintEvent(QPaintEvent* event)
    {
        Q_UNUSED(event);

        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.fillRect(rect(), Qt::transparent);

        const QRect kCardRect = rect().adjusted(6, 4, -6, -4);
        painter.setPen(QPen(ksword_theme::borderColor(), 1));
        painter.setBrush(ksword_theme::surfaceColor());
        painter.drawRoundedRect(kCardRect, 10, 10);

        QFont titleFont = painter.font();
        titleFont.setBold(true);
        painter.setFont(titleFont);
        painter.setPen(ksword_theme::textPrimaryColor());

        const QString kTitleText = hasDisk_
            ? QStringLiteral("%1  ·  %2  ·  %3")
                .arg(diskInfo_.displayName.isEmpty() ? diskInfo_.devicePath : diskInfo_.displayName)
                .arg(formatBytesForDiskMap(diskInfo_.sizeBytes))
                .arg(diskInfo_.busType.isEmpty() ? QStringLiteral("未知总线") : diskInfo_.busType)
            : QStringLiteral("尚未选择磁盘");
        painter.drawText(
            kCardRect.adjusted(kOuterMargin, 8, -kOuterMargin, 0),
            Qt::AlignLeft | Qt::AlignTop,
            kTitleText);

        const QRect kMapFrame(
            kCardRect.left() + kOuterMargin,
            kCardRect.top() + kHeaderHeight + 10,
            kCardRect.width() - kOuterMargin * 2,
            kMapHeight);

        painter.setPen(QPen(ksword_theme::borderStrongColor(), 1));
        painter.setBrush(ksword_theme::surfaceAltColor());
        painter.drawRoundedRect(kMapFrame, 8, 8);

        if (!hasDisk_ || diskInfo_.sizeBytes == 0)
        {
            painter.setPen(ksword_theme::textSecondaryColor());
            painter.drawText(
                kMapFrame,
                Qt::AlignCenter,
                ks::i18n::contextText(
                    QStringLiteral("disk_map.unreadable"),
                    QStringLiteral("无法读取磁盘布局，请刷新或以管理员权限运行")));
            return;
        }

        const std::vector<PaintSegment> kSegments = rebuildPaintSegments();
        for (const PaintSegment& segment : kSegments)
        {
            const bool kSelected = segment.partition.tableIndex == selectedPartitionIndex_;
            const bool kHovered = segment.partition.tableIndex == hoverPartitionIndex_;
            const QColor kBaseColor = segment.partition.color.isValid()
                ? segment.partition.color
                : ksword_theme::accentColor(ksword_theme::AccentRole::kBlue);

            QLinearGradient gradient(segment.rect.topLeft(), segment.rect.bottomLeft());
            gradient.setColorAt(0.0, ksword_theme::themeLighterColor(kBaseColor));
            gradient.setColorAt(0.58, kBaseColor);
            gradient.setColorAt(1.0, darkerColor(kBaseColor));

            painter.setPen(QPen(kSelected || kHovered
                    ? ksword_theme::accentColor(ksword_theme::AccentRole::kBlue)
                    : darkerColor(kBaseColor),
                kSelected ? 3 : (kHovered ? 2 : 1)));
            painter.setBrush(QBrush(gradient));
            painter.drawRoundedRect(segment.rect, 6, 6);

            const QString kLabelText = segment.partition.name.isEmpty()
                ? segment.partition.typeText
                : segment.partition.name;
            const QString kSizeText = formatBytesForDiskMap(segment.partition.lengthBytes);
            const QString kVisibleText = kLabelText.isEmpty()
                ? kSizeText
                : QStringLiteral("%1\n%2").arg(kLabelText, kSizeText);

            painter.setPen(ksword_theme::maximumContrastMonochromeColor(kBaseColor));
            QFont segmentFont = painter.font();
            segmentFont.setBold(true);
            painter.setFont(segmentFont);

            const QFontMetrics kMetrics(segmentFont);
            if (segment.rect.width() >= 68)
            {
                painter.drawText(segment.rect.adjusted(5, 4, -5, -4), Qt::AlignCenter, kVisibleText);
            }
            else if (segment.rect.width() >= 28)
            {
                const QString kShortText = kMetrics.elidedText(kLabelText, Qt::ElideRight, segment.rect.width() - 4);
                painter.drawText(segment.rect.adjusted(2, 0, -2, 0), Qt::AlignCenter, kShortText);
            }
        }

        painter.setFont(QWidget::font());
        painter.setPen(ksword_theme::textSecondaryColor());
        const QString kFooterTemplate = QStringLiteral("0  ·  扇区 %1 B  ·  共 %2 个分区块  ·  末尾 %3");
        const QString kFooterText = ks::i18n::contextText(
            QStringLiteral("disk_map.footer"), kFooterTemplate)
            .arg(diskInfo_.bytesPerSector)
            .arg(static_cast<int>(kSegments.size()))
            .arg(formatBytesForDiskMap(diskInfo_.sizeBytes));
        painter.drawText(
            QRect(kMapFrame.left(), kMapFrame.bottom() + 7, kMapFrame.width(), 18),
            Qt::AlignLeft | Qt::AlignVCenter,
            kFooterText);
    }

    void DiskMapWidget::mousePressEvent(QMouseEvent* event)
    {
        if (event == nullptr || event->button() != Qt::LeftButton)
        {
            QWidget::mousePressEvent(event);
            return;
        }

        const int kPartitionIndex = hitTest(event->pos());
        if (kPartitionIndex >= 0)
        {
            selectedPartitionIndex_ = kPartitionIndex;
            update();
            emit partitionActivated(kPartitionIndex);
            return;
        }
        QWidget::mousePressEvent(event);
    }

    void DiskMapWidget::mouseMoveEvent(QMouseEvent* event)
    {
        if (event == nullptr)
        {
            return;
        }

        const std::vector<PaintSegment> kSegments = rebuildPaintSegments();
        int nextHoverIndex = -1;
        QString tooltipText;
        for (const PaintSegment& segment : kSegments)
        {
            if (segment.rect.contains(event->pos()))
            {
                nextHoverIndex = segment.partition.tableIndex;
                tooltipText = segmentTooltipText(segment);
                break;
            }
        }

        if (hoverPartitionIndex_ != nextHoverIndex)
        {
            hoverPartitionIndex_ = nextHoverIndex;
            update();
        }

        if (!tooltipText.isEmpty())
        {
            // Qt6 deprecated globalPos(); use globalPosition() and convert back to QPoint for QToolTip.
            QToolTip::showText(event->globalPosition().toPoint(), tooltipText, this);
        }
        else
        {
            QToolTip::hideText();
        }
    }

    void DiskMapWidget::leaveEvent(QEvent* event)
    {
        Q_UNUSED(event);
        hoverPartitionIndex_ = -1;
        QToolTip::hideText();
        update();
    }

    std::vector<DiskMapWidget::PaintSegment> DiskMapWidget::rebuildPaintSegments() const
    {
        std::vector<PaintSegment> segments;
        if (!hasDisk_ || diskInfo_.sizeBytes == 0)
        {
            return segments;
        }

        QRect mapRect(
            6 + kOuterMargin,
            4 + kHeaderHeight + 10,
            width() - 12 - kOuterMargin * 2,
            kMapHeight);
        mapRect = mapRect.adjusted(5, 5, -5, -5);
        if (mapRect.width() <= 0 || mapRect.height() <= 0)
        {
            return segments;
        }

        for (const DiskPartitionInfo& partition : diskInfo_.partitions)
        {
            if (partition.lengthBytes == 0 || partition.offsetBytes >= diskInfo_.sizeBytes)
            {
                continue;
            }

            const std::uint64_t kClampedEnd =
                std::min<std::uint64_t>(diskInfo_.sizeBytes, partition.offsetBytes + partition.lengthBytes);
            const double kStartRatio =
                static_cast<double>(partition.offsetBytes) / static_cast<double>(diskInfo_.sizeBytes);
            const double kEndRatio =
                static_cast<double>(kClampedEnd) / static_cast<double>(diskInfo_.sizeBytes);

            int left = mapRect.left() + static_cast<int>(kStartRatio * static_cast<double>(mapRect.width()));
            int right = mapRect.left() + static_cast<int>(kEndRatio * static_cast<double>(mapRect.width()));
            if (right <= left)
            {
                right = left + kMinVisibleSegmentWidth;
            }
            if (right > mapRect.right())
            {
                right = mapRect.right();
            }

            QRect segmentRect(left, mapRect.top(), std::max(kMinVisibleSegmentWidth, right - left), mapRect.height());
            segmentRect = segmentRect.adjusted(1, 1, -1, -1);
            if (segmentRect.right() > mapRect.right())
            {
                segmentRect.setRight(mapRect.right() - 1);
            }

            segments.push_back(PaintSegment{ segmentRect, partition });
        }

        return segments;
    }

    int DiskMapWidget::hitTest(const QPoint& point) const
    {
        const std::vector<PaintSegment> kSegments = rebuildPaintSegments();
        for (const PaintSegment& segment : kSegments)
        {
            if (segment.rect.contains(point))
            {
                return segment.partition.tableIndex;
            }
        }
        return -1;
    }

    QString DiskMapWidget::segmentTooltipText(const PaintSegment& segment)
    {
        const DiskPartitionInfo& partition = segment.partition;
        return QStringLiteral("%1\n类型: %2\n容量: %3\n偏移: 0x%4\n长度: 0x%5\n标记: %6")
            .arg(partition.name.isEmpty() ? QStringLiteral("未命名分区") : partition.name)
            .arg(partition.typeText.isEmpty() ? QStringLiteral("未知") : partition.typeText)
            .arg(formatBytesForDiskMap(partition.lengthBytes))
            .arg(static_cast<qulonglong>(partition.offsetBytes), 16, 16, QChar('0'))
            .arg(static_cast<qulonglong>(partition.lengthBytes), 16, 16, QChar('0'))
            .arg(partition.flagsText.isEmpty() ? QStringLiteral("-") : partition.flagsText)
            .toUpper();
    }
}
