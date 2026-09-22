#include "ProcessDetailWindow.InternalCommon.h"
#include "ProcessAffinityUtils.h"
#include "ProcessAffinityPersistence.h"
#include "ThreadAffinityMenu.h"
#include "../handle_dock/HandleDock.h"
#include "../memory_dock/MemoryDock.h"
#include "../network_dock/NetworkDock.h"
#include "../other_dock/OtherDock.h"
#include "../misc_dock/sound_source/SoundSourcePage.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../PluginHost.h"

#include <QTimer>
#include <QEasingCurve>
#include <QHash>
#include <QMouseEvent>
#include <QResizeEvent>
#include <QVariantAnimation>

using namespace process_detail_window_internal;

// ============================================================
// ProcessDetailWindow.BaseAndUi.cpp
// Purpose:
// - Responsible for constructing/merging base data, initializing UI for multiple tabs, and connecting base signals.
// - Focus on the logic for 'window skeleton and static display data'.
// ============================================================

namespace
{
    constexpr int kInitialDetailDataRefreshDelayMs = 350;
    constexpr int kAffinityMatrixColumnCount = 6;

    // Frame interval for lazy loading of the embedded Dock:
    // - The first stage waits for only one frame to allow Tab switching and placeholder text to complete rendering.
    // - Subsequent segments queue with 0ms delay to ensure each segment returns to the event loop for processing drawing and input.
    constexpr int kEmbeddedViewBuildFirstStageDelayMs = 16;
    constexpr int kEmbeddedViewBuildNextStageDelayMs = 0;

    // Dynamic property name for the embedded Dock build queue marker:
    // - After changing lazy loading to frame-based, the Dock pointer remains null during the queueing period.
    // - Use the page container widget's own dynamic property to record 'queued' status; it is destroyed with the page, eliminating the need for new members in the window class.
    constexpr char kEmbeddedViewBuildPendingProperty[] = "kswordEmbeddedViewBuildPending";

    // markEmbeddedViewBuildPending:
    // - Input: Pointer to the container widget of the embedded tab.
    // - Processing: Mark as queued if the container is not already queued, to suppress duplicate builds caused by users switching tabs back and forth.
    // - Returns: true indicates this call secured the build slot; false indicates a build task is already queued.
    bool markEmbeddedViewBuildPending(QWidget* const embeddedTabWidget)
    {
        if (embeddedTabWidget == nullptr)
        {
            return false;
        }

        if (embeddedTabWidget->property(kEmbeddedViewBuildPendingProperty).toBool())
        {
            return false;
        }

        embeddedTabWidget->setProperty(kEmbeddedViewBuildPendingProperty, true);
        return true;
    }

    // clearEmbeddedViewBuildPending:
    // - Input: Pointer to the container widget of the embedded tab.
    // - Handling: Clear pending queue markers after the build process completes (or is abandoned midway).
    // - Returns: Nothing.
    void clearEmbeddedViewBuildPending(QWidget* const embeddedTabWidget)
    {
        if (embeddedTabWidget != nullptr)
        {
            embeddedTabWidget->setProperty(kEmbeddedViewBuildPendingProperty, false);
        }
    }

    // attachEmbeddedDockToTabLayout:
    // - Parameters: Embedded tab layout, placeholder label member reference, and fully constructed Dock control.
    // - Processing: Remove and defer destruction of the placeholder label, then attach the Dock to the page layout with stretch factor 1.
    // - Returns: nothing. The placeholder label pointer is set to null to prevent duplicate removal.
    void attachEmbeddedDockToTabLayout(
        QVBoxLayout* const embeddedTabLayout,
        QLabel*& embeddedPlaceholderLabel,
        QWidget* const embeddedDockWidget)
    {
        if (embeddedTabLayout == nullptr || embeddedDockWidget == nullptr)
        {
            return;
        }

        if (embeddedPlaceholderLabel != nullptr)
        {
            embeddedTabLayout->removeWidget(embeddedPlaceholderLabel);
            embeddedPlaceholderLabel->deleteLater();
            embeddedPlaceholderLabel = nullptr;
        }

        // Embedded dock complex control trees cannot propagate their own minimumSizeHint back to the detail window.
        // The page allocates all available space to the Dock; overflow is handled by the Dock's internal table and scroll area.
        embeddedDockWidget->setMinimumSize(0, 0);
        embeddedDockWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
        embeddedTabLayout->addWidget(embeddedDockWidget, 1);
    }

    QWidget* createScrollableTabContent(
        QWidget* const tabPage,
        QVBoxLayout*& contentLayout,
        const int contentMargin,
        const int contentSpacing)
    {
        // Create a scalable scroll container for vertical form pages: fill the page when content is insufficient, show scrollbars when content is too large.
        if (tabPage == nullptr)
        {
            contentLayout = nullptr;
            return nullptr;
        }

        auto* outerLayout = new QVBoxLayout(tabPage);
        outerLayout->setContentsMargins(0, 0, 0, 0);
        outerLayout->setSpacing(0);

        auto* scrollArea = new QScrollArea(tabPage);
        scrollArea->setWidgetResizable(true);
        scrollArea->setFrameShape(QFrame::NoFrame);
        scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        scrollArea->setMinimumSize(0, 0);
        scrollArea->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);

        auto* contentWidget = new QWidget(scrollArea);
        contentLayout = new QVBoxLayout(contentWidget);
        contentLayout->setContentsMargins(
            contentMargin,
            contentMargin,
            contentMargin,
            contentMargin);
        contentLayout->setSpacing(contentSpacing);
        scrollArea->setWidget(contentWidget);
        outerLayout->addWidget(scrollArea, 1);
        return contentWidget;
    }

    QString buildAffinityCoreButtonStyle()
    {
        return QStringLiteral(
            "QToolButton {"
            "  min-width:42px; min-height:28px; padding:2px 6px;"
            "  color:%1; background:transparent; border:1px solid %2; border-radius:4px;"
            "}"
            "QToolButton:hover { border-color:%3; background:%4; }"
            "QToolButton:checked { color:%5; background:%3; border-color:%3; }"
            "QToolButton:disabled { color:%6; border-color:%2; background:transparent; }")
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceAltHex())
            .arg(QStringLiteral("palette(highlighted-text)"))
            .arg(ksword_theme::textSecondaryHex());
    }

    QString detailProcessFieldSourceText(const std::uint32_t sourceValue)
    {
        // sourceValue: Enum for the Phase-2 field source in the shared protocol.
        // Return value: Stable text displayed directly in the detail view.
        switch (sourceValue)
        {
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_PUBLIC_API:
            return QStringLiteral("Public API");
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_SYSTEM_INFORMER_DYNDATA:
            return QStringLiteral("System Informer DynData");
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_RUNTIME_PATTERN:
            return QStringLiteral("Runtime pattern");
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_PDB_PROFILE:
            return QStringLiteral("PDB profile");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    QString detailProcessR0StatusText(const std::uint32_t statusValue)
    {
        // statusValue usage: Extended read of the overall status during R0 enumeration.
        // Return value: Status text for the detail page, kept consistent with the ProcessDock column.
        switch (statusValue)
        {
        case KSWORD_ARK_PROCESS_R0_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_PROCESS_R0_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_PROCESS_R0_STATUS_DYNDATA_MISSING:
            return QStringLiteral("DynData missing");
        case KSWORD_ARK_PROCESS_R0_STATUS_READ_FAILED:
            return QStringLiteral("Read failed");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    QString detailProcessByteHexText(const std::uint8_t byteValue)
    {
        // byteValue usage: Single-byte kernel fields such as Protection/SignatureLevel.
        // Return: Uppercase hexadecimal text in 0xNN format.
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(byteValue), 2, 16, QChar('0'))
            .toUpper();
    }

    QString detailProcessOffsetText(const std::uint32_t offsetValue)
    {
        // offsetValue usage: EPROCESS field offset.
        // Return value: displays 'Unavailable' explicitly when unavailable; otherwise displays 0xNN.
        if (offsetValue == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE || offsetValue == 0x0000FFFFUL)
        {
            return QStringLiteral("Unavailable");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(offsetValue), 0, 16)
            .toUpper();
    }

    QString detailProcessPointerText(
        const QString& availableLabel,
        const bool available,
        const std::uint64_t addressValue,
        const std::uint32_t sourceValue)
    {
        // availableLabel usage: accepts domain semantics such as HandleTable or SectionObject.
        // Return value: First display the "available" conclusion, followed by the address and source.
        if (!available)
        {
            return QStringLiteral("Unavailable (%1)").arg(detailProcessFieldSourceText(sourceValue));
        }
        if (addressValue == 0U)
        {
            return QStringLiteral("%1: null (%2)")
                .arg(availableLabel)
                .arg(detailProcessFieldSourceText(sourceValue));
        }
        const QString kAddressText = QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(addressValue), 0, 16)
            .toUpper();
        return QStringLiteral("%1: 0x%2 (%3)")
            .arg(availableLabel)
            .arg(kAddressText.mid(2))
            .arg(detailProcessFieldSourceText(sourceValue));
    }

    QString detailProcessCapabilityText(const std::uint64_t capabilityMask)
    {
        // capabilityMask usage: DynData capability snapshot attached during R0 enumeration.
        // Returns: a hexadecimal bitmap plus capability names relevant to Phase-2.
        QStringList capabilityNames;
        if ((capabilityMask & KSW_CAP_PROCESS_OBJECT_TABLE) != 0U)
        {
            capabilityNames << QStringLiteral("ProcessObjectTable");
        }
        if ((capabilityMask & KSW_CAP_SECTION_CONTROL_AREA) != 0U)
        {
            capabilityNames << QStringLiteral("SectionControlArea");
        }
        if ((capabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) != 0U)
        {
            capabilityNames << QStringLiteral("ProcessProtectionPatch");
        }
        if (capabilityNames.isEmpty())
        {
            capabilityNames << QStringLiteral("None/Unavailable");
        }
        const QString kMaskText = QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(capabilityMask), 0, 16)
            .toUpper();
        return QStringLiteral("%1 (%2)")
            .arg(kMaskText)
            .arg(capabilityNames.join(QStringLiteral(", ")));
    }

    constexpr std::uint64_t kWindowsEpochOffset100ns = 116444736000000000ULL;
    constexpr ULONG kProcessInfoClassDebugPort = 7UL;
    constexpr ULONG kProcessInfoClassBreakOnTermination = 29UL;
    constexpr ULONG kProcessInfoClassSubsystem = 75UL;

    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(
        HANDLE,
        PROCESSINFOCLASS,
        PVOID,
        ULONG,
        PULONG);

    QString detailBoolText(const bool value)
    {
        return value ? QStringLiteral("Enabled") : QStringLiteral("Disabled");
    }

    QString detailUnavailableText()
    {
        return QStringLiteral("Unavailable");
    }

    QString detailBytesText(const std::uint64_t value)
    {
        constexpr double kKiB = 1024.0;
        constexpr double kMiB = kKiB * 1024.0;
        constexpr double kGiB = kMiB * 1024.0;
        const double kByteValue = static_cast<double>(value);
        if (kByteValue >= kGiB)
        {
            return QStringLiteral("%1 GiB (%2 bytes)")
                .arg(kByteValue / kGiB, 2, 'f', 2)
                .arg(static_cast<qulonglong>(value));
        }
        if (kByteValue >= kMiB)
        {
            return QStringLiteral("%1 MiB (%2 bytes)")
                .arg(kByteValue / kMiB, 2, 'f', 2)
                .arg(static_cast<qulonglong>(value));
        }
        if (kByteValue >= kKiB)
        {
            return QStringLiteral("%1 KiB (%2 bytes)")
                .arg(kByteValue / kKiB, 2, 'f', 2)
                .arg(static_cast<qulonglong>(value));
        }
        return QStringLiteral("%1 bytes").arg(static_cast<qulonglong>(value));
    }

    QString detailDurationText(const std::uint64_t duration100ns)
    {
        const std::uint64_t kTotalSeconds = duration100ns / 10000000ULL;
        const std::uint64_t kDayValue = kTotalSeconds / 86400ULL;
        const std::uint64_t kHourValue = (kTotalSeconds % 86400ULL) / 3600ULL;
        const std::uint64_t kMinuteValue = (kTotalSeconds % 3600ULL) / 60ULL;
        const std::uint64_t kSecondValue = kTotalSeconds % 60ULL;
        return QStringLiteral("%1d %2h %3m %4s")
            .arg(static_cast<qulonglong>(kDayValue))
            .arg(static_cast<qulonglong>(kHourValue))
            .arg(static_cast<qulonglong>(kMinuteValue))
            .arg(static_cast<qulonglong>(kSecondValue));
    }

    QString detailUptimeText(const std::uint64_t creationTime100ns)
    {
        if (creationTime100ns <= kWindowsEpochOffset100ns)
        {
            return detailUnavailableText();
        }
        const qint64 kCreationMs = static_cast<qint64>(
            (creationTime100ns - kWindowsEpochOffset100ns) / 10000ULL);
        const qint64 kNowMs = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
        if (kNowMs < kCreationMs)
        {
            return detailUnavailableText();
        }
        return detailDurationText(static_cast<std::uint64_t>(kNowMs - kCreationMs) * 10000ULL);
    }

    QString detailAffinityText(const ULONG_PTR affinityMask)
    {
        QStringList coreIndexList;
        for (int bitIndex = 0; bitIndex < static_cast<int>(sizeof(ULONG_PTR) * 8U); ++bitIndex)
        {
            const ULONG_PTR kCurrentBit = static_cast<ULONG_PTR>(1ULL) << bitIndex;
            if ((affinityMask & kCurrentBit) != 0U)
            {
                coreIndexList << QString::number(bitIndex);
            }
        }
        const QString kMaskText = QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(affinityMask), 0, 16)
            .toUpper();
        return coreIndexList.isEmpty()
            ? kMaskText
            : QStringLiteral("%1 (CPU %2)").arg(kMaskText, coreIndexList.join(','));
    }

    QString detailIntegrityText(const DWORD integrityRid)
    {
        if (integrityRid >= SECURITY_MANDATORY_SYSTEM_RID)
        {
            return QStringLiteral("System");
        }
        if (integrityRid >= SECURITY_MANDATORY_HIGH_RID)
        {
            return QStringLiteral("High");
        }
        if (integrityRid >= SECURITY_MANDATORY_MEDIUM_RID + 0x1000UL)
        {
            return QStringLiteral("Medium Plus");
        }
        if (integrityRid >= SECURITY_MANDATORY_MEDIUM_RID)
        {
            return QStringLiteral("Medium");
        }
        if (integrityRid >= SECURITY_MANDATORY_LOW_RID)
        {
            return QStringLiteral("Low");
        }
        if (integrityRid != 0U)
        {
            return QStringLiteral("Untrusted");
        }
        return detailUnavailableText();
    }

    QString detailElevationTypeText(const TOKEN_ELEVATION_TYPE elevationType)
    {
        switch (elevationType)
        {
        case TokenElevationTypeFull:
            return QStringLiteral("Full");
        case TokenElevationTypeLimited:
            return QStringLiteral("Limited");
        case TokenElevationTypeDefault:
        default:
            return QStringLiteral("Default");
        }
    }

    bool detailReadTokenInformation(
        const HANDLE tokenHandle,
        const TOKEN_INFORMATION_CLASS informationClass,
        std::vector<std::uint8_t>& bufferOut)
    {
        bufferOut.clear();
        DWORD requiredBytes = 0;
        if (::GetTokenInformation(tokenHandle, informationClass, nullptr, 0, &requiredBytes) != FALSE ||
            ::GetLastError() != ERROR_INSUFFICIENT_BUFFER || requiredBytes == 0U)
        {
            return false;
        }
        bufferOut.resize(requiredBytes);
        return ::GetTokenInformation(
            tokenHandle,
            informationClass,
            bufferOut.data(),
            requiredBytes,
            &requiredBytes) != FALSE;
    }

    template <typename TValue>
    bool detailQueryNtProcessInformation(
        const NtQueryInformationProcessFn queryFunction,
        const HANDLE processHandle,
        const ULONG informationClass,
        TValue& valueOut)
    {
        if (queryFunction == nullptr || processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        const NTSTATUS kStatusValue = queryFunction(
            processHandle,
            static_cast<PROCESSINFOCLASS>(informationClass),
            &valueOut,
            static_cast<ULONG>(sizeof(TValue)),
            nullptr);
        return kStatusValue >= 0;
    }

    struct DetailWindowCountContext
    {
        DWORD targetPid = 0;
        std::uint32_t count = 0;
    };

    BOOL CALLBACK countDetailTopLevelWindowProc(const HWND windowHandle, const LPARAM contextValue)
    {
        auto* context = reinterpret_cast<DetailWindowCountContext*>(contextValue);
        if (context == nullptr || windowHandle == nullptr)
        {
            return TRUE;
        }
        DWORD ownerPid = 0;
        ::GetWindowThreadProcessId(windowHandle, &ownerPid);
        if (ownerPid == context->targetPid)
        {
            ++context->count;
        }
        return TRUE;
    }

    std::uint32_t detailTopLevelWindowCount(const DWORD pidValue)
    {
        DetailWindowCountContext context{};
        context.targetPid = pidValue;
        ::EnumWindows(countDetailTopLevelWindowProc, reinterpret_cast<LPARAM>(&context));
        return context.count;
    }

    QString detailThreadDesktopText(const DWORD pidValue)
    {
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return detailUnavailableText();
        }

        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        QString desktopText;
        if (::Thread32First(snapshotHandle, &threadEntry) != FALSE)
        {
            do
            {
                if (threadEntry.th32OwnerProcessID != pidValue)
                {
                    continue;
                }
                const HDESK kDesktopHandle = ::GetThreadDesktop(threadEntry.th32ThreadID);
                if (kDesktopHandle == nullptr)
                {
                    continue;
                }
                wchar_t desktopName[256] = {};
                DWORD returnedBytes = 0;
                if (::GetUserObjectInformationW(
                    kDesktopHandle,
                    UOI_NAME,
                    desktopName,
                    static_cast<DWORD>(sizeof(desktopName)),
                    &returnedBytes) != FALSE)
                {
                    desktopText = QString::fromWCharArray(desktopName);
                    break;
                }
            } while (::Thread32Next(snapshotHandle, &threadEntry) != FALSE);
        }
        ::CloseHandle(snapshotHandle);
        return desktopText.trimmed().isEmpty() ? detailUnavailableText() : desktopText;
    }

    QString detailSubsystemText(const ULONG subsystemType)
    {
        switch (subsystemType)
        {
        case 0:
            return QStringLiteral("Unknown (0)");
        case 1:
            return QStringLiteral("Win32 (1)");
        case 2:
            return QStringLiteral("Windows GUI (2)");
        case 3:
            return QStringLiteral("Windows CUI (3)");
        default:
            return QStringLiteral("%1").arg(subsystemType);
        }
    }

    class ProcessPerformanceHistoryChartWidget final : public QWidget
    {
    public:
        struct Series
        {
            QString label;
            QColor color;
            std::vector<double> values;
        };

        explicit ProcessPerformanceHistoryChartWidget(QWidget* parent = nullptr)
            : QWidget(parent)
        {
            setMinimumHeight(168);
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            setContextMenuPolicy(Qt::DefaultContextMenu);
            setAutoFillBackground(false);
            setAttribute(Qt::WA_StyledBackground, false);
            setAttribute(Qt::WA_OpaquePaintEvent, false);
            seriesAnimation_ = new QVariantAnimation(this);
            seriesAnimation_->setDuration(260);
            seriesAnimation_->setEasingCurve(QEasingCurve::OutCubic);
            seriesAnimation_->setStartValue(0.0);
            seriesAnimation_->setEndValue(1.0);
            connect(seriesAnimation_, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
                animationProgress_ = value.toDouble();
                update();
            });
        }

        void setChartData(
            std::vector<qint64> timestamps,
            std::vector<Series> series,
            const QString& unitText,
            const double fixedMaximum,
            const QString& emptyText,
            const QString& timeHeader,
            const QString& copyLatestText,
            const QString& copyHistoryText)
        {
            previousPointCount_ = timestamps_.size();
            historyWindowShifted_ =
                previousPointCount_ == timestamps.size()
                && previousPointCount_ > 1U
                && timestamps.front() > timestamps_.front();
            timestamps_ = std::move(timestamps);
            previousLatestValueByLabel_.clear();
            for (const Series& oldSeries : series_)
            {
                if (!oldSeries.values.empty())
                {
                    previousLatestValueByLabel_.insert(oldSeries.label, oldSeries.values.back());
                }
            }
            series_ = std::move(series);
            unitText_ = unitText;
            fixedMaximum_ = fixedMaximum;
            emptyText_ = emptyText;
            timeHeader_ = timeHeader;
            copyLatestText_ = copyLatestText;
            copyHistoryText_ = copyHistoryText;
            animationProgress_ = 0.0;
            seriesAnimation_->stop();
            seriesAnimation_->start();
        }

    protected:
        void paintEvent(QPaintEvent* eventPointer) override
        {
            (void)eventPointer;

            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, true);

            const QColor kBorderColor = ksword_theme::borderColor();
            const QColor kTextColor = ksword_theme::textSecondaryColor();
            const QRectF kPlotRect = chartRect();
            painter.setPen(QPen(kBorderColor, 1.0));
            painter.setBrush(Qt::NoBrush);
            painter.drawRect(kPlotRect);

            if (timestamps_.empty() || series_.empty())
            {
                painter.setPen(kTextColor);
                painter.drawText(kPlotRect, Qt::AlignCenter, emptyText_);
                return;
            }

            const double kAxisMaximum = chartMaximum();
            drawGrid(painter, kPlotRect, kAxisMaximum, kBorderColor, kTextColor);
            drawLines(painter, kPlotRect, kAxisMaximum);
            drawLegend(painter, kTextColor);
            drawTimeRange(painter, kPlotRect, kTextColor);
        }

        void contextMenuEvent(QContextMenuEvent* eventPointer) override
        {
            if (eventPointer == nullptr || timestamps_.empty() || series_.empty())
            {
                return;
            }

            QMenu menu(this);
            menu.setStyleSheet(buildProcessDetailMenuStyle());
            QAction* const kCopyLatestAction = menu.addAction(copyLatestText_);
            QAction* const kCopyHistoryAction = menu.addAction(copyHistoryText_);
            QAction* const kSelectedAction = menu.exec(eventPointer->globalPos());
            if (QApplication::clipboard() == nullptr)
            {
                return;
            }
            if (kSelectedAction == kCopyLatestAction)
            {
                QApplication::clipboard()->setText(latestValuesText());
            }
            else if (kSelectedAction == kCopyHistoryAction)
            {
                QApplication::clipboard()->setText(historyText());
            }
        }

    private:
        QRectF chartRect() const
        {
            return QRectF(rect()).adjusted(62.0, 24.0, -12.0, -29.0);
        }

        double chartMaximum() const
        {
            if (fixedMaximum_ > 0.0)
            {
                return fixedMaximum_;
            }

            double maximum = 0.0;
            for (const Series& series : series_)
            {
                for (const double kValue : series.values)
                {
                    maximum = std::max(maximum, std::max(0.0, kValue));
                }
            }
            if (maximum <= 0.0)
            {
                return 1.0;
            }
            return std::max(1.0, std::ceil(maximum * 1.1));
        }

        QString valueText(const double value) const
        {
            const int kPrecision = value >= 100.0 ? 0 : (value >= 10.0 ? 1 : 2);
            const QString kNumberText = QString::number(std::max(0.0, value), 'f', kPrecision);
            if (unitText_ == QStringLiteral("%"))
            {
                return kNumberText + unitText_;
            }
            return kNumberText + QLatin1Char(' ') + unitText_;
        }

        QString timeText(const qint64 timestamp) const
        {
            return QDateTime::fromMSecsSinceEpoch(timestamp).toString(QStringLiteral("HH:mm:ss"));
        }

        void drawGrid(
            QPainter& painter,
            const QRectF& plotRect,
            const double axisMaximum,
            const QColor& borderColor,
            const QColor& textColor) const
        {
            painter.setPen(QPen(borderColor, 1.0, Qt::DotLine));
            for (int gridIndex = 0; gridIndex <= 4; ++gridIndex)
            {
                const double kRatio = static_cast<double>(gridIndex) / 4.0;
                const double kY = plotRect.bottom() - plotRect.height() * kRatio;
                painter.drawLine(QPointF(plotRect.left(), kY), QPointF(plotRect.right(), kY));
                painter.setPen(textColor);
                painter.drawText(
                    QRectF(2.0, kY - 9.0, plotRect.left() - 7.0, 18.0),
                    Qt::AlignRight | Qt::AlignVCenter,
                    valueText(axisMaximum * kRatio));
                painter.setPen(QPen(borderColor, 1.0, Qt::DotLine));
            }
        }

        double animatedXRatio(const std::size_t pointIndex, const std::size_t pointCount) const
        {
            if (pointCount <= 1U)
            {
                return 0.0;
            }

            const double kTargetRatio =
                static_cast<double>(pointIndex) / static_cast<double>(pointCount - 1U);
            double startRatio = kTargetRatio;
            if (historyWindowShifted_ && previousPointCount_ == pointCount)
            {
                startRatio = pointIndex + 1U < pointCount
                    ? static_cast<double>(pointIndex + 1U) / static_cast<double>(pointCount - 1U)
                    : 1.0;
            }
            else if (previousPointCount_ + 1U == pointCount && previousPointCount_ > 1U)
            {
                startRatio = pointIndex < previousPointCount_
                    ? static_cast<double>(pointIndex) / static_cast<double>(previousPointCount_ - 1U)
                    : 1.0;
            }

            return startRatio + (kTargetRatio - startRatio) * animationProgress_;
        }

        void drawLines(QPainter& painter, const QRectF& plotRect, const double axisMaximum) const
        {
            const std::size_t kPointCount = timestamps_.size();
            if (kPointCount == 0U)
            {
                return;
            }

            for (const Series& series : series_)
            {
                if (series.values.empty())
                {
                    continue;
                }
                QPainterPath linePath;
                const std::size_t kSeriesPointCount = std::min(kPointCount, series.values.size());
                for (std::size_t pointIndex = 0; pointIndex < kSeriesPointCount; ++pointIndex)
                {
                    const double kX = plotRect.left()
                        + plotRect.width() * animatedXRatio(pointIndex, kSeriesPointCount);
                    double displayValue = series.values[pointIndex];
                    if (pointIndex + 1U == kSeriesPointCount && animationProgress_ < 1.0)
                    {
                        const double kStartValue = previousLatestValueByLabel_.value(series.label, displayValue);
                        displayValue = kStartValue + (displayValue - kStartValue) * animationProgress_;
                    }
                    const double kValueRatio = std::min(
                        1.0,
                        std::max(0.0, displayValue) / axisMaximum);
                    const double kY = plotRect.bottom() - plotRect.height() * kValueRatio;
                    if (pointIndex == 0U)
                    {
                        linePath.moveTo(kX, kY);
                    }
                    else
                    {
                        linePath.lineTo(kX, kY);
                    }
                }
                painter.setPen(QPen(series.color, 2.0));
                painter.setBrush(Qt::NoBrush);
                painter.drawPath(linePath);
            }
        }

        void drawLegend(QPainter& painter, const QColor& textColor) const
        {
            double x = 8.0;
            constexpr double kY = 12.0;
            painter.setPen(textColor);
            for (const Series& series : series_)
            {
                painter.setPen(QPen(series.color, 2.0));
                painter.drawLine(QPointF(x, kY), QPointF(x + 15.0, kY));
                x += 20.0;
                painter.setPen(textColor);
                const QFontMetrics kMetrics(painter.font());
                painter.drawText(QPointF(x, kY + 4.0), series.label);
                x += static_cast<double>(kMetrics.horizontalAdvance(series.label)) + 16.0;
            }
        }

        void drawTimeRange(QPainter& painter, const QRectF& plotRect, const QColor& textColor) const
        {
            if (timestamps_.empty())
            {
                return;
            }
            painter.setPen(textColor);
            const QRectF kLeftTextRect(plotRect.left(), plotRect.bottom() + 5.0, 120.0, 18.0);
            const QRectF kRightTextRect(plotRect.right() - 120.0, plotRect.bottom() + 5.0, 120.0, 18.0);
            painter.drawText(kLeftTextRect, Qt::AlignLeft | Qt::AlignVCenter, timeText(timestamps_.front()));
            painter.drawText(kRightTextRect, Qt::AlignRight | Qt::AlignVCenter, timeText(timestamps_.back()));
        }

        QString latestValuesText() const
        {
            if (timestamps_.empty())
            {
                return QString();
            }
            QStringList lines;
            lines << (timeHeader_ + QStringLiteral(": ") + timeText(timestamps_.back()));
            for (const Series& series : series_)
            {
                if (!series.values.empty())
                {
                    lines << (series.label + QStringLiteral(": ") + valueText(series.values.back()));
                }
            }
            return lines.join(QLatin1Char('\n'));
        }

        QString historyText() const
        {
            QStringList headerFields;
            headerFields << timeHeader_;
            for (const Series& series : series_)
            {
                headerFields << series.label;
            }

            QStringList lines;
            lines << headerFields.join(QLatin1Char('\t'));
            for (std::size_t pointIndex = 0; pointIndex < timestamps_.size(); ++pointIndex)
            {
                QStringList rowFields;
                rowFields << timeText(timestamps_[pointIndex]);
                for (const Series& series : series_)
                {
                    rowFields << valueText(pointIndex < series.values.size() ? series.values[pointIndex] : 0.0);
                }
                lines << rowFields.join(QLatin1Char('\t'));
            }
            return lines.join(QLatin1Char('\n'));
        }

        std::vector<qint64> timestamps_;
        std::vector<Series> series_;
        QString unitText_;
        QString emptyText_;
        QString timeHeader_;
        QString copyLatestText_;
        QString copyHistoryText_;
        double fixedMaximum_ = 0.0;
        QHash<QString, double> previousLatestValueByLabel_;
        std::size_t previousPointCount_ = 0U;
        bool historyWindowShifted_ = false;
        QVariantAnimation* seriesAnimation_ = nullptr;
        double animationProgress_ = 1.0;
    };

    // CpuCoreUsageGridWidget：
    // - Reuse the 'near-square small line matrix' visual structure from HardwareDock to display per-logical-processor utilization;
    // - Single custom-drawn widget replaces tables and numerous QLabel instances, remaining lightweight even with many CPU cores;
    // - Height automatically converges with width and core count; the page only produces vertical scrolling, eliminating overly wide core tables.
    class CpuCoreUsageGridWidget final : public QWidget
    {
    public:
        explicit CpuCoreUsageGridWidget(QWidget* parent = nullptr)
            : QWidget(parent)
        {
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            setMinimumSize(0, kCellHeight);
        }

        void setCoreValues(
            std::vector<ProcessDetailWindow::CpuCoreValue> coreValues,
            const bool multipleProcessorGroups)
        {
            coreValues_ = std::move(coreValues);
            multipleProcessorGroups_ = multipleProcessorGroups;
            QSet<std::uint32_t> liveProcessorIndexes;
            for (const ProcessDetailWindow::CpuCoreValue& core : coreValues_)
            {
                liveProcessorIndexes.insert(core.processorIndex);
                std::deque<double>& history = historyByProcessorIndex_[core.processorIndex];
                history.push_back(core.sampleReady ? std::clamp(core.percent, 0.0, 100.0) : 0.0);
                while (history.size() > kHistoryLength)
                {
                    history.pop_front();
                }
            }
            for (auto historyIt = historyByProcessorIndex_.begin();
                 historyIt != historyByProcessorIndex_.end();)
            {
                if (!liveProcessorIndexes.contains(historyIt->first))
                {
                    historyIt = historyByProcessorIndex_.erase(historyIt);
                }
                else
                {
                    ++historyIt;
                }
            }
            synchronizeHeight();
            updateGeometry();
            update();
        }

        QSize sizeHint() const override
        {
            constexpr int kReferenceWidth = 820;
            return QSize(kReferenceWidth, contentHeightForWidth(kReferenceWidth));
        }

        bool hasHeightForWidth() const override
        {
            return true;
        }

        int heightForWidth(const int availableWidth) const override
        {
            return contentHeightForWidth(availableWidth);
        }

    protected:
        bool event(QEvent* eventPointer) override
        {
            const bool kHandled = QWidget::event(eventPointer);
            if (eventPointer != nullptr && eventPointer->type() == QEvent::Resize)
            {
                synchronizeHeight();
            }
            return kHandled;
        }

        void paintEvent(QPaintEvent* eventPointer) override
        {
            (void)eventPointer;
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, true);

            const int kColumnCount = gridColumnCount(width());
            const qreal kCellWidth = std::max<qreal>(
                1.0,
                (static_cast<qreal>(width()) - kGridSpacing * (kColumnCount - 1))
                    / static_cast<qreal>(kColumnCount));
            const QColor kCpuColor = ksword_theme::performanceColor(ksword_theme::PerformanceRole::kCpu);
            const QColor kCardColor = ksword_theme::surfaceAltColor();
            const QColor kBorderColor = ksword_theme::borderColor();
            const QColor kPrimaryTextColor = ksword_theme::textPrimaryColor();
            const QColor kSecondaryTextColor = ksword_theme::textSecondaryColor();

            for (int index = 0; index < static_cast<int>(coreValues_.size()); ++index)
            {
                const int kRow = index / kColumnCount;
                const int kColumn = index % kColumnCount;
                const QRectF kCellRect(
                    kColumn * (kCellWidth + kGridSpacing),
                    kRow * (kCellHeight + kGridSpacing),
                    kCellWidth,
                    kCellHeight);
                const ProcessDetailWindow::CpuCoreValue& core =
                    coreValues_[static_cast<std::size_t>(index)];

                painter.setPen(QPen(kBorderColor, 1.0));
                painter.setBrush(kCardColor);
                painter.drawRoundedRect(kCellRect.adjusted(0.5, 0.5, -0.5, -0.5), 4.0, 4.0);

                const QRectF kContentRect = kCellRect.adjusted(8.0, 5.0, -8.0, -8.0);
                QFont labelFont = painter.font();
                labelFont.setWeight(QFont::DemiBold);
                painter.setFont(labelFont);
                painter.setPen(kSecondaryTextColor);
                painter.drawText(kContentRect, Qt::AlignLeft | Qt::AlignTop, coordinateText(core));

                QFont valueFont = painter.font();
                valueFont.setWeight(QFont::Bold);
                painter.setFont(valueFont);
                painter.setPen(core.sampleReady ? kPrimaryTextColor : kSecondaryTextColor);
                painter.drawText(
                    kContentRect,
                    Qt::AlignRight | Qt::AlignTop,
                    core.sampleReady
                        ? QString::number(core.percent, 'f', core.percent >= 10.0 ? 1 : 2)
                            + QStringLiteral("%")
                        : QStringLiteral("—"));

                const QRectF kPlotRect = kCellRect.adjusted(7.0, 27.0, -7.0, -7.0);
                drawHistoryLine(
                    painter,
                    kPlotRect,
                    historyByProcessorIndex_[core.processorIndex],
                    kCpuColor,
                    kBorderColor);
            }

            if (coreValues_.empty())
            {
                painter.setPen(kSecondaryTextColor);
                painter.drawText(rect(), Qt::AlignCenter, QStringLiteral("—"));
            }
        }

    private:
        static constexpr int kCellHeight = 82;
        static constexpr int kGridSpacing = 6;
        static constexpr std::size_t kHistoryLength = 30U;

        static void drawHistoryLine(
            QPainter& painter,
            const QRectF& plotRect,
            const std::deque<double>& history,
            const QColor& lineColor,
            const QColor& borderColor)
        {
            painter.save();
            painter.setClipRect(plotRect.adjusted(-1.0, -1.0, 1.0, 1.0));
            painter.setPen(QPen(ksword_theme::withAlpha(borderColor, 90), 1.0, Qt::DotLine));
            painter.drawLine(
                QPointF(plotRect.left(), plotRect.center().y()),
                QPointF(plotRect.right(), plotRect.center().y()));
            painter.drawRect(plotRect);
            if (history.empty())
            {
                painter.restore();
                return;
            }

            QPainterPath linePath;
            const std::size_t kLeadingEmptySamples = kHistoryLength > history.size()
                ? kHistoryLength - history.size()
                : 0U;
            for (std::size_t index = 0; index < history.size(); ++index)
            {
                const double kXRatio = kHistoryLength <= 1U
                    ? 0.0
                    : static_cast<double>(kLeadingEmptySamples + index)
                        / static_cast<double>(kHistoryLength - 1U);
                const double kYRatio = std::clamp(history[index] / 100.0, 0.0, 1.0);
                const QPointF kPoint(
                    plotRect.left() + plotRect.width() * kXRatio,
                    plotRect.bottom() - plotRect.height() * kYRatio);
                if (index == 0U)
                {
                    linePath.moveTo(kPoint);
                }
                else
                {
                    linePath.lineTo(kPoint);
                }
            }
            painter.setPen(QPen(lineColor, 1.6));
            painter.setBrush(Qt::NoBrush);
            painter.drawPath(linePath);
            painter.restore();
        }

        int gridColumnCount(const int availableWidth) const
        {
            const int kCoreCount = std::max(1, static_cast<int>(coreValues_.size()));
            const int kIdealColumns = std::max(
                1,
                static_cast<int>(std::ceil(std::sqrt(static_cast<double>(kCoreCount)))));
            const int kWidthLimitedColumns = std::max(1, (std::max(1, availableWidth) + kGridSpacing) / 86);
            return std::clamp(std::min(kIdealColumns, kWidthLimitedColumns), 1, kCoreCount);
        }

        int contentHeightForWidth(const int availableWidth) const
        {
            const int kColumnCount = gridColumnCount(availableWidth);
            const int kItemCount = std::max(1, static_cast<int>(coreValues_.size()));
            const int kRowCount = std::max(1, (kItemCount + kColumnCount - 1) / kColumnCount);
            return kRowCount * kCellHeight + (kRowCount - 1) * kGridSpacing;
        }

        QString coordinateText(const ProcessDetailWindow::CpuCoreValue& core) const
        {
            return multipleProcessorGroups_
                ? QStringLiteral("G%1:L%2").arg(core.group).arg(core.number)
                : QStringLiteral("L%1").arg(core.number);
        }

        void synchronizeHeight()
        {
            const int kTargetHeight = contentHeightForWidth(std::max(1, width()));
            if (minimumHeight() != kTargetHeight || maximumHeight() != kTargetHeight)
            {
                setFixedHeight(kTargetHeight);
            }
        }

        std::vector<ProcessDetailWindow::CpuCoreValue> coreValues_;
        std::unordered_map<std::uint32_t, std::deque<double>> historyByProcessorIndex_;
        bool multipleProcessorGroups_ = false;
    };

    // CpuThreadUsageCardGridWidget: Threads are collapsed by default; clicking expands a matrix of per-core historical line charts.
    class CpuThreadUsageCardGridWidget final : public QWidget
    {
    public:
        explicit CpuThreadUsageCardGridWidget(QWidget* parent = nullptr)
            : QWidget(parent)
        {
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            setMinimumSize(0, kCollapsedCardHeight);
            setCursor(Qt::PointingHandCursor);
        }

        void setThreadValues(
            std::vector<ProcessDetailWindow::ThreadCpuCoreValue> threadValues,
            const bool multipleProcessorGroups)
        {
            threadValues_ = std::move(threadValues);
            QSet<std::uint32_t> liveThreadIds;
            for (const ProcessDetailWindow::ThreadCpuCoreValue& thread : threadValues_)
            {
                liveThreadIds.insert(thread.threadId);
                CoreHistoryMap& coreHistory = historyByThreadId_[thread.threadId];
                QSet<std::uint32_t> liveProcessorIndexes;
                for (const ProcessDetailWindow::CpuCoreValue& core : thread.cores)
                {
                    liveProcessorIndexes.insert(core.processorIndex);
                    auto historyIt = coreHistory.find(core.processorIndex);
                    if (historyIt == coreHistory.end()
                        && (!core.sampleReady || core.percent <= 0.005))
                    {
                        continue;
                    }
                    if (historyIt == coreHistory.end())
                    {
                        historyIt = coreHistory.emplace(
                            core.processorIndex,
                            std::deque<double>{}).first;
                    }
                    std::deque<double>& history = historyIt->second;
                    history.push_back(
                        core.sampleReady ? std::clamp(core.percent, 0.0, 100.0) : 0.0);
                    while (history.size() > kHistoryLength)
                    {
                        history.pop_front();
                    }
                }
                for (auto coreIt = coreHistory.begin(); coreIt != coreHistory.end();)
                {
                    if (!liveProcessorIndexes.contains(coreIt->first))
                    {
                        coreIt = coreHistory.erase(coreIt);
                    }
                    else
                    {
                        ++coreIt;
                    }
                }
            }
            for (auto threadIt = historyByThreadId_.begin(); threadIt != historyByThreadId_.end();)
            {
                if (!liveThreadIds.contains(threadIt->first))
                {
                    expandedThreadIds_.remove(threadIt->first);
                    threadIt = historyByThreadId_.erase(threadIt);
                }
                else
                {
                    ++threadIt;
                }
            }
            std::stable_sort(
                threadValues_.begin(),
                threadValues_.end(),
                [](const ProcessDetailWindow::ThreadCpuCoreValue& left,
                   const ProcessDetailWindow::ThreadCpuCoreValue& right) {
                    if (left.cpuPercent != right.cpuPercent)
                    {
                        return left.cpuPercent > right.cpuPercent;
                    }
                    return left.threadId < right.threadId;
                });
            multipleProcessorGroups_ = multipleProcessorGroups;
            synchronizeHeight();
            updateGeometry();
            update();
        }

        QSize sizeHint() const override
        {
            constexpr int kReferenceWidth = 820;
            return QSize(kReferenceWidth, contentHeightForWidth(kReferenceWidth));
        }

        bool hasHeightForWidth() const override
        {
            return true;
        }

        int heightForWidth(const int availableWidth) const override
        {
            return contentHeightForWidth(availableWidth);
        }

    protected:
        bool event(QEvent* eventPointer) override
        {
            const bool kHandled = QWidget::event(eventPointer);
            if (eventPointer != nullptr && eventPointer->type() == QEvent::Resize)
            {
                synchronizeHeight();
            }
            return kHandled;
        }

        void paintEvent(QPaintEvent* eventPointer) override
        {
            (void)eventPointer;
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, true);

            const QColor kCpuColor = ksword_theme::performanceColor(ksword_theme::PerformanceRole::kCpu);
            const QColor kCardColor = ksword_theme::surfaceAltColor();
            const QColor kBorderColor = ksword_theme::borderColor();
            const QColor kPrimaryTextColor = ksword_theme::textPrimaryColor();
            const QColor kSecondaryTextColor = ksword_theme::textSecondaryColor();
            qreal cardTop = 0.0;

            for (int index = 0; index < static_cast<int>(threadValues_.size()); ++index)
            {
                const ProcessDetailWindow::ThreadCpuCoreValue& thread =
                    threadValues_[static_cast<std::size_t>(index)];
                const bool kExpanded = expandedThreadIds_.contains(thread.threadId);
                const qreal kCurrentCardHeight = cardHeight(thread, width());
                const QRectF kCardRect(
                    0.0,
                    cardTop,
                    static_cast<qreal>(width()),
                    kCurrentCardHeight);
                cardTop += kCurrentCardHeight + kGridSpacing;

                painter.setPen(QPen(kBorderColor, 1.0));
                painter.setBrush(kCardColor);
                painter.drawRoundedRect(kCardRect.adjusted(0.5, 0.5, -0.5, -0.5), 5.0, 5.0);

                const QRectF kArrowRect(kCardRect.left() + 10.0, kCardRect.top() + 14.0, 13.0, 13.0);
                QPainterPath arrowPath;
                if (kExpanded)
                {
                    arrowPath.moveTo(kArrowRect.left(), kArrowRect.top() + 3.0);
                    arrowPath.lineTo(kArrowRect.right(), kArrowRect.top() + 3.0);
                    arrowPath.lineTo(kArrowRect.center().x(), kArrowRect.bottom());
                }
                else
                {
                    arrowPath.moveTo(kArrowRect.left() + 3.0, kArrowRect.top());
                    arrowPath.lineTo(kArrowRect.right(), kArrowRect.center().y());
                    arrowPath.lineTo(kArrowRect.left() + 3.0, kArrowRect.bottom());
                }
                arrowPath.closeSubpath();
                painter.setPen(Qt::NoPen);
                painter.setBrush(kSecondaryTextColor);
                painter.drawPath(arrowPath);

                const QRectF kHeaderRect(
                    kCardRect.left() + 31.0,
                    kCardRect.top() + 6.0,
                    kCardRect.width() - 43.0,
                    kCollapsedCardHeight - 12.0);
                QFont titleFont = painter.font();
                titleFont.setWeight(QFont::DemiBold);
                painter.setFont(titleFont);
                painter.setPen(kPrimaryTextColor);
                painter.drawText(
                    kHeaderRect,
                    Qt::AlignLeft | Qt::AlignVCenter,
                    QStringLiteral("TID %1").arg(thread.threadId));
                painter.setPen(kCpuColor);
                painter.drawText(
                    kHeaderRect,
                    Qt::AlignRight | Qt::AlignVCenter,
                    QString::number(thread.cpuPercent, 'f', thread.cpuPercent >= 10.0 ? 1 : 2)
                        + QStringLiteral("%"));

                if (!kExpanded)
                {
                    continue;
                }

                painter.setPen(QPen(kBorderColor, 1.0));
                painter.drawLine(
                    QPointF(kCardRect.left() + 10.0, kCardRect.top() + kCollapsedCardHeight),
                    QPointF(kCardRect.right() - 10.0, kCardRect.top() + kCollapsedCardHeight));

                const int kColumnCount = expandedCoreColumnCount(
                    static_cast<int>(thread.cores.size()),
                    width());
                const qreal kBodyLeft = kCardRect.left() + kExpandedBodyPadding;
                const qreal kBodyTop = kCardRect.top() + kCollapsedCardHeight + kExpandedBodyPadding;
                const qreal kBodyWidth = std::max<qreal>(
                    1.0,
                    kCardRect.width() - 2.0 * kExpandedBodyPadding);
                const qreal kCoreCardWidth = std::max<qreal>(
                    1.0,
                    (kBodyWidth - kCoreGridSpacing * (kColumnCount - 1))
                        / static_cast<qreal>(kColumnCount));
                const auto kThreadHistoryIt = historyByThreadId_.find(thread.threadId);
                for (int coreIndex = 0; coreIndex < static_cast<int>(thread.cores.size()); ++coreIndex)
                {
                    const ProcessDetailWindow::CpuCoreValue& core =
                        thread.cores[static_cast<std::size_t>(coreIndex)];
                    const int kRow = coreIndex / kColumnCount;
                    const int kColumn = coreIndex % kColumnCount;
                    const QRectF kCoreCardRect(
                        kBodyLeft + kColumn * (kCoreCardWidth + kCoreGridSpacing),
                        kBodyTop + kRow * (kCoreChartHeight + kCoreGridSpacing),
                        kCoreCardWidth,
                        kCoreChartHeight);
                    const std::deque<double>* history = nullptr;
                    if (kThreadHistoryIt != historyByThreadId_.end())
                    {
                        const auto kCoreHistoryIt = kThreadHistoryIt->second.find(core.processorIndex);
                        if (kCoreHistoryIt != kThreadHistoryIt->second.end())
                        {
                            history = &kCoreHistoryIt->second;
                        }
                    }
                    drawCoreChart(
                        painter,
                        kCoreCardRect,
                        core,
                        history,
                        kCpuColor,
                        kBorderColor,
                        kPrimaryTextColor,
                        kSecondaryTextColor);
                }
            }

            if (threadValues_.empty())
            {
                painter.setPen(kSecondaryTextColor);
                painter.drawText(rect(), Qt::AlignCenter, QStringLiteral("—"));
            }
        }

        void mousePressEvent(QMouseEvent* eventPointer) override
        {
            if (eventPointer == nullptr || eventPointer->button() != Qt::LeftButton)
            {
                QWidget::mousePressEvent(eventPointer);
                return;
            }

            qreal top = 0.0;
            for (const ProcessDetailWindow::ThreadCpuCoreValue& thread : threadValues_)
            {
                const qreal kHeight = cardHeight(thread, width());
                const QRectF kCardRect(0.0, top, static_cast<qreal>(width()), kHeight);
                if (kCardRect.contains(eventPointer->position()))
                {
                    if (expandedThreadIds_.contains(thread.threadId))
                    {
                        expandedThreadIds_.remove(thread.threadId);
                    }
                    else
                    {
                        expandedThreadIds_.insert(thread.threadId);
                    }
                    synchronizeHeight();
                    updateGeometry();
                    update();
                    eventPointer->accept();
                    return;
                }
                top += kHeight + kGridSpacing;
            }
            QWidget::mousePressEvent(eventPointer);
        }

    private:
        using CoreHistoryMap = std::unordered_map<std::uint32_t, std::deque<double>>;

        static constexpr int kCollapsedCardHeight = 44;
        static constexpr int kGridSpacing = 8;
        static constexpr int kCoreGridSpacing = 6;
        static constexpr int kCoreChartHeight = 72;
        static constexpr int kExpandedBodyPadding = 8;
        static constexpr std::size_t kHistoryLength = 30U;

        int expandedCoreColumnCount(const int coreCountValue, const int availableWidth) const
        {
            const int kCoreCount = std::max(1, coreCountValue);
            const int kIdealColumns = std::max(
                1,
                static_cast<int>(std::ceil(std::sqrt(static_cast<double>(kCoreCount)))));
            const int kInnerWidth = std::max(1, availableWidth - 2 * kExpandedBodyPadding);
            const int kWidthLimitedColumns = std::max(
                1,
                (kInnerWidth + kCoreGridSpacing) / 105);
            return std::clamp(std::min(kIdealColumns, kWidthLimitedColumns), 1, kCoreCount);
        }

        int expandedBodyHeight(
            const ProcessDetailWindow::ThreadCpuCoreValue& thread,
            const int availableWidth) const
        {
            const int kCoreCount = std::max(1, static_cast<int>(thread.cores.size()));
            const int kColumnCount = expandedCoreColumnCount(kCoreCount, availableWidth);
            const int kRowCount = std::max(1, (kCoreCount + kColumnCount - 1) / kColumnCount);
            return 2 * kExpandedBodyPadding
                + kRowCount * kCoreChartHeight
                + (kRowCount - 1) * kCoreGridSpacing;
        }

        int cardHeight(
            const ProcessDetailWindow::ThreadCpuCoreValue& thread,
            const int availableWidth) const
        {
            return kCollapsedCardHeight
                + (expandedThreadIds_.contains(thread.threadId)
                    ? expandedBodyHeight(thread, availableWidth)
                    : 0);
        }

        int contentHeightForWidth(const int availableWidth) const
        {
            if (threadValues_.empty())
            {
                return kCollapsedCardHeight;
            }
            int height = 0;
            for (const ProcessDetailWindow::ThreadCpuCoreValue& thread : threadValues_)
            {
                height += cardHeight(thread, availableWidth);
            }
            height += (static_cast<int>(threadValues_.size()) - 1) * kGridSpacing;
            return height;
        }

        QString coordinateText(const ProcessDetailWindow::CpuCoreValue& core) const
        {
            return multipleProcessorGroups_
                ? QStringLiteral("G%1:L%2").arg(core.group).arg(core.number)
                : QStringLiteral("L%1").arg(core.number);
        }

        static void drawHistoryLine(
            QPainter& painter,
            const QRectF& plotRect,
            const std::deque<double>* history,
            const QColor& lineColor,
            const QColor& borderColor)
        {
            painter.save();
            painter.setClipRect(plotRect.adjusted(-1.0, -1.0, 1.0, 1.0));
            painter.setPen(QPen(ksword_theme::withAlpha(borderColor, 90), 1.0, Qt::DotLine));
            painter.drawLine(
                QPointF(plotRect.left(), plotRect.center().y()),
                QPointF(plotRect.right(), plotRect.center().y()));
            painter.drawRect(plotRect);
            if (history == nullptr || history->empty())
            {
                painter.restore();
                return;
            }

            QPainterPath linePath;
            const std::size_t kLeadingEmptySamples = kHistoryLength > history->size()
                ? kHistoryLength - history->size()
                : 0U;
            for (std::size_t index = 0; index < history->size(); ++index)
            {
                const double kXRatio = kHistoryLength <= 1U
                    ? 0.0
                    : static_cast<double>(kLeadingEmptySamples + index)
                        / static_cast<double>(kHistoryLength - 1U);
                const double kYRatio = std::clamp((*history)[index] / 100.0, 0.0, 1.0);
                const QPointF kPoint(
                    plotRect.left() + plotRect.width() * kXRatio,
                    plotRect.bottom() - plotRect.height() * kYRatio);
                if (index == 0U)
                {
                    linePath.moveTo(kPoint);
                }
                else
                {
                    linePath.lineTo(kPoint);
                }
            }
            painter.setPen(QPen(lineColor, 1.4));
            painter.setBrush(Qt::NoBrush);
            painter.drawPath(linePath);
            painter.restore();
        }

        void drawCoreChart(
            QPainter& painter,
            const QRectF& cardRect,
            const ProcessDetailWindow::CpuCoreValue& core,
            const std::deque<double>* history,
            const QColor& lineColor,
            const QColor& borderColor,
            const QColor& primaryTextColor,
            const QColor& secondaryTextColor) const
        {
            painter.setPen(QPen(borderColor, 1.0));
            painter.setBrush(ksword_theme::surfaceColor());
            painter.drawRoundedRect(cardRect.adjusted(0.5, 0.5, -0.5, -0.5), 4.0, 4.0);

            QFont coreFont = painter.font();
            coreFont.setWeight(QFont::DemiBold);
            painter.setFont(coreFont);
            painter.setPen(secondaryTextColor);
            painter.drawText(
                cardRect.adjusted(6.0, 3.0, -6.0, -cardRect.height() + 22.0),
                Qt::AlignLeft | Qt::AlignVCenter,
                coordinateText(core));
            painter.setPen(core.sampleReady ? primaryTextColor : secondaryTextColor);
            painter.drawText(
                cardRect.adjusted(6.0, 3.0, -6.0, -cardRect.height() + 22.0),
                Qt::AlignRight | Qt::AlignVCenter,
                core.sampleReady
                    ? QString::number(core.percent, 'f', core.percent >= 10.0 ? 1 : 2)
                        + QStringLiteral("%")
                    : QStringLiteral("—"));
            drawHistoryLine(
                painter,
                cardRect.adjusted(6.0, 24.0, -6.0, -6.0),
                history,
                lineColor,
                borderColor);
        }

        void synchronizeHeight()
        {
            const int kTargetHeight = contentHeightForWidth(std::max(1, width()));
            if (minimumHeight() != kTargetHeight || maximumHeight() != kTargetHeight)
            {
                setFixedHeight(kTargetHeight);
            }
        }

        std::vector<ProcessDetailWindow::ThreadCpuCoreValue> threadValues_;
        std::unordered_map<std::uint32_t, CoreHistoryMap> historyByThreadId_;
        QSet<std::uint32_t> expandedThreadIds_;
        bool multipleProcessorGroups_ = false;
    };
}

void ProcessDetailWindow::rebuildActionAffinityCoreButtons()
{
    if (affinityMatrixLayout_ == nullptr)
    {
        return;
    }

    while (QLayoutItem* const kLayoutItem =
           affinityMatrixLayout_->takeAt(0))
    {
        if (QWidget* const kChildWidget = kLayoutItem->widget())
        {
            kChildWidget->deleteLater();
        }
        delete kLayoutItem;
    }
    affinityCoreButtons_.clear();
    const bool kIncludeProcessorGroup =
        actionAffinityReadable_ &&
        ks::process::logicalProcessorGroupCount(
            actionAffinitySnapshot_.processors) > 1U;
    if (affinityDescriptionLabel_ != nullptr)
    {
        QString descriptionText = ks::i18n::text(
            QStringLiteral("process.detail.affinity.description"),
            QString());
        if (kIncludeProcessorGroup)
        {
            descriptionText += QStringLiteral("\n") + ks::i18n::text(
                QStringLiteral(
                    "process.detail.affinity.description.multigroup"),
                QString());
        }
        affinityDescriptionLabel_->setText(descriptionText);
    }
    if (!actionAffinityReadable_)
    {
        return;
    }

    const QString kAffinityCoreButtonStyle =
        buildAffinityCoreButtonStyle();
    std::uint16_t currentGroup =
        std::numeric_limits<std::uint16_t>::max();
    int matrixRow = 0;
    int matrixColumn = 0;
    for (const ks::process::LogicalProcessorState& processor :
         actionAffinitySnapshot_.processors)
    {
        if (processor.coordinate.group != currentGroup)
        {
            if (matrixColumn != 0)
            {
                ++matrixRow;
            }
            currentGroup = processor.coordinate.group;
            matrixColumn = 0;
            if (kIncludeProcessorGroup)
            {
                QLabel* const kGroupLabel = new QLabel(
                    ks::i18n::text(
                        QStringLiteral("process.detail.affinity.group"),
                        QString())
                        .arg(currentGroup),
                    affinityActionGroup_);
                kGroupLabel->setStyleSheet(
                    QStringLiteral("color:%1;font-weight:700;")
                        .arg(ksword_theme::textSecondaryHex()));
                affinityMatrixLayout_->addWidget(
                    kGroupLabel,
                    matrixRow++,
                    0,
                    1,
                    kAffinityMatrixColumnCount);
            }
        }

        QToolButton* const kCoreButton =
            new QToolButton(affinityActionGroup_);
        const QString kIdentityText = QString::fromStdString(
            ks::process::processorDisplayIdentityText(
                processor.coordinate,
                kIncludeProcessorGroup));
        const QString kTopologyText =
            QString::fromStdString(processor.topologyLabel);
        kCoreButton->setText(
            kTopologyText.isEmpty()
                ? kIdentityText
                : kIdentityText + QStringLiteral("\n") + kTopologyText);
        kCoreButton->setCheckable(true);
        kCoreButton->setAutoRaise(false);
        kCoreButton->setFocusPolicy(Qt::NoFocus);
        kCoreButton->setStyleSheet(kAffinityCoreButtonStyle);
        QString processorToolTip = ks::i18n::text(
                QStringLiteral("process.detail.affinity.core_tooltip"),
                QString())
                .arg(kIdentityText, kTopologyText);
        if (processor.constrainedByHardAffinity)
        {
            processorToolTip += QStringLiteral("\n") +
                ks::i18n::text(
                    QStringLiteral(
                        "process.detail.affinity.constraint_tooltip"),
                    QString());
        }
        else if (!processor.available)
        {
            processorToolTip += QStringLiteral("\n") +
                ks::i18n::text(
                    QStringLiteral(
                        "process.detail.affinity.allocated_tooltip"),
                    QString());
        }
        kCoreButton->setToolTip(processorToolTip);
        const ks::process::LogicalProcessorCoordinate kCoordinate =
            processor.coordinate;
        connect(
            kCoreButton,
            &QToolButton::clicked,
            this,
            [this, kCoordinate](const bool enabled)
            {
                toggleActionAffinityCore(kCoordinate, enabled);
            });
        affinityMatrixLayout_->addWidget(
            kCoreButton,
            matrixRow,
            matrixColumn);
        affinityCoreButtons_.push_back(kCoreButton);
        ++matrixColumn;
        if (matrixColumn == kAffinityMatrixColumnCount)
        {
            matrixColumn = 0;
            ++matrixRow;
        }
    }
    affinityMatrixLayout_->setColumnStretch(
        kAffinityMatrixColumnCount,
        1);
}

ProcessDetailWindow::ProcessDetailWindow(const ks::process::ProcessRecord& baseRecord, QWidget* parent)
    : QWidget(parent)
    , baseRecord_(baseRecord)
{
    // Constructor entry log: record the target PID and identity key fields.
    KLogEvent ctorStartEvent;
    info << ctorStartEvent
        << "[ProcessDetailWindow] 构造开始, pid="
        << baseRecord_.pid
        << ", createTime100ns="
        << baseRecord_.creationTime100ns
        << eol;

    // Detail window is an independent top-level window: not a Dock, non-modal, does not block the main interface.
    setWindowFlag(Qt::Window, true);
    setWindowModality(Qt::NonModal);
    setAttribute(Qt::WA_DeleteOnClose, true);
    // Retain the original initial width of approximately 75% of the client area, but no longer set maximumWidth.
    // Initial and minimum dimensions are constrained only by the target screen's available area; users can freely resize or maximize afterward.
    constexpr int kPreferredWindowWidth = 1160;
    const int kInitialWindowWidth = std::min(
        kPreferredWindowWidth,
        calculateStandaloneWindowInitialWidth(
            parent,
            this,
            0.75,
            kPreferredWindowWidth));
    ks::ui::applyResponsiveWindowGeometry(
        this,
        parent,
        QSize(kInitialWindowWidth, 760),
        QSize(720, 640),
        0.9);

    // identity: Used for log and window reuse location.
    identityKey_ = ks::process::buildProcessIdentityKey(
        baseRecord_.pid,
        baseRecord_.creationTime100ns);

    // Do not perform synchronous static detail queries during construction:
    // - queryProcessStaticDetailByPid reads slow fields such as command line, tokens, and signatures.
    // - WinVerifyTrust may significantly block the UI when certificate chains or network policies are abnormal.
    // - The window must return to the event loop before opening; missing fields are filled by background tasks.
    const bool kNeedStaticQuery =
        baseRecord_.imagePath.empty() ||
        baseRecord_.commandLine.empty() ||
        baseRecord_.userName.empty() ||
        baseRecord_.signatureState.empty() ||
        baseRecord_.signatureState == "Pending";
    if (kNeedStaticQuery && baseRecord_.pid != 0)
    {
        KLogEvent ctorStaticQueryDeferredEvent;
        info << ctorStaticQueryDeferredEvent
            << "[ProcessDetailWindow] 构造阶段跳过同步静态查询，改为后台补齐, pid="
            << baseRecord_.pid
            << eol;
    }

    // initialize in the order: build UI -> connect signals -> delay fill -> first async refresh.
    // Full details read the icon, parent process, token, and mitigation policies. Start after the window has settled to avoid competing for the UI thread while it opens.
    initializeUi();
    initializeConnections();
    QTimer::singleShot(kInitialDetailDataRefreshDelayMs, this, [this]() {
        refreshDetailTabTexts();
        requestAsyncStaticDetailRefresh(true);
        requestAsyncDetailOverviewRefresh();
        requestInitialRefreshForCurrentTab();
    });

    // Construction completion log: marks the end of the window initialization chain.
    KLogEvent ctorFinishEvent;
    info << ctorFinishEvent
        << "[ProcessDetailWindow] 构造完成, pid="
        << baseRecord_.pid
        << ", identity="
        << identityKey_
        << eol;
}

void ProcessDetailWindow::updateBaseRecord(const ks::process::ProcessRecord& baseRecord)
{
    // Log entry for update start: record new snapshot PID and old identity.
    KLogEvent updateRecordStartEvent;
    info << updateRecordStartEvent
        << "[ProcessDetailWindow] updateBaseRecord: 开始更新, incomingPid="
        << baseRecord.pid
        << ", oldIdentity="
        << identityKey_
        << eol;

    const std::string kOldIdentityKey = identityKey_;

    // When an external new snapshot is pushed:
    // 1) Retain existing 'completed fields'.
    // 2) Then merge the new snapshot.
    // 3) Optionally fetch static details to prevent fields from being overwritten by null values.
    ks::process::ProcessRecord mergedRecord = baseRecord;
    if (mergedRecord.imagePath.empty()) mergedRecord.imagePath = baseRecord_.imagePath;
    if (mergedRecord.commandLine.empty()) mergedRecord.commandLine = baseRecord_.commandLine;
    if (mergedRecord.userName.empty()) mergedRecord.userName = baseRecord_.userName;
    if (mergedRecord.startTimeText.empty()) mergedRecord.startTimeText = baseRecord_.startTimeText;
    if (mergedRecord.signatureState.empty()) mergedRecord.signatureState = baseRecord_.signatureState;
    if (mergedRecord.signaturePublisher.empty()) mergedRecord.signaturePublisher = baseRecord_.signaturePublisher;
    if (mergedRecord.r0FieldFlags == 0U) mergedRecord.r0FieldFlags = baseRecord_.r0FieldFlags;
    if (mergedRecord.r0ImagePath.empty()) mergedRecord.r0ImagePath = baseRecord_.r0ImagePath;
    if (mergedRecord.r0Status == KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE) mergedRecord.r0Status = baseRecord_.r0Status;
    if (mergedRecord.r0DynDataCapabilityMask == 0U) mergedRecord.r0DynDataCapabilityMask = baseRecord_.r0DynDataCapabilityMask;
    if (mergedRecord.r0ProtectionSource == KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE) mergedRecord.r0ProtectionSource = baseRecord_.r0ProtectionSource;
    if (mergedRecord.r0SignatureLevelSource == KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE) mergedRecord.r0SignatureLevelSource = baseRecord_.r0SignatureLevelSource;
    if (mergedRecord.r0SectionSignatureLevelSource == KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE) mergedRecord.r0SectionSignatureLevelSource = baseRecord_.r0SectionSignatureLevelSource;
    if (mergedRecord.r0ObjectTableSource == KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE) mergedRecord.r0ObjectTableSource = baseRecord_.r0ObjectTableSource;
    if (mergedRecord.r0SectionObjectSource == KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE) mergedRecord.r0SectionObjectSource = baseRecord_.r0SectionObjectSource;
    if (mergedRecord.r0ProtectionOffset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE) mergedRecord.r0ProtectionOffset = baseRecord_.r0ProtectionOffset;
    if (mergedRecord.r0SignatureLevelOffset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE) mergedRecord.r0SignatureLevelOffset = baseRecord_.r0SignatureLevelOffset;
    if (mergedRecord.r0SectionSignatureLevelOffset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE) mergedRecord.r0SectionSignatureLevelOffset = baseRecord_.r0SectionSignatureLevelOffset;
    if (mergedRecord.r0ObjectTableOffset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE) mergedRecord.r0ObjectTableOffset = baseRecord_.r0ObjectTableOffset;
    if (mergedRecord.r0SectionObjectOffset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE) mergedRecord.r0SectionObjectOffset = baseRecord_.r0SectionObjectOffset;
    if (mergedRecord.r0ObjectTableAddress == 0U) mergedRecord.r0ObjectTableAddress = baseRecord_.r0ObjectTableAddress;
    if (mergedRecord.r0SectionObjectAddress == 0U) mergedRecord.r0SectionObjectAddress = baseRecord_.r0SectionObjectAddress;
    mergedRecord.r0Protection = (mergedRecord.r0FieldFlags != 0U) ? mergedRecord.r0Protection : baseRecord_.r0Protection;
    mergedRecord.r0SignatureLevel = (mergedRecord.r0FieldFlags != 0U) ? mergedRecord.r0SignatureLevel : baseRecord_.r0SignatureLevel;
    mergedRecord.r0SectionSignatureLevel = (mergedRecord.r0FieldFlags != 0U) ? mergedRecord.r0SectionSignatureLevel : baseRecord_.r0SectionSignatureLevel;
    mergedRecord.signatureTrusted = mergedRecord.signatureTrusted || baseRecord_.signatureTrusted;

    const bool kNeedStaticQuery =
        mergedRecord.imagePath.empty() ||
        mergedRecord.commandLine.empty() ||
        mergedRecord.userName.empty() ||
        mergedRecord.signatureState.empty() ||
        mergedRecord.signatureState == "Pending";
    const bool kShouldTryStaticBackgroundRefresh =
        kNeedStaticQuery &&
        mergedRecord.pid != 0 &&
        !staticDetailRefreshing_ &&
        !staticDetailRefreshAttempted_;
    if (kNeedStaticQuery && mergedRecord.pid != 0)
    {
        // updateBaseRecord may be triggered by ProcessDock's periodic refresh.
        // Synchronous calls to queryProcessStaticDetailByPid are not allowed here, as they would freeze the UI on every refresh cycle after opening the details window.
        KLogEvent updateRecordStaticDeferredEvent;
        dbg << updateRecordStaticDeferredEvent
            << "[ProcessDetailWindow] updateBaseRecord: 静态信息缺失，保留现有值并等待后台补齐, pid="
            << mergedRecord.pid
            << eol;
    }

    baseRecord_ = mergedRecord;
    identityKey_ = ks::process::buildProcessIdentityKey(
        baseRecord_.pid,
        baseRecord_.creationTime100ns);
    const bool kIdentityChanged = identityKey_ != kOldIdentityKey;
    if (kIdentityChanged)
    {
        // If the same window is reused for a new identity, the one-time background refresh state must be reset.
        // Otherwise, the first-load flag of the old process will block on-demand loading of new process data.
        staticDetailRefreshing_ = false;
        staticDetailRefreshAttempted_ = false;
        ++staticDetailRefreshTicket_;
        detailOverviewRefreshing_ = false;
        ++detailOverviewRefreshTicket_;
        detailOverviewResult_ = DetailOverviewRefreshResult{};
        threadInspectInitialRefreshStarted_ = false;
        moduleInitialRefreshStarted_ = false;
        tokenInitialRefreshStarted_ = false;
        tokenSwitchInitialRefreshStarted_ = false;
        sectionInfoInitialRefreshStarted_ = false;
        hotkeyInitialRefreshStarted_ = false;
        keyboardInitialRefreshStarted_ = false;
        pebInitialRefreshStarted_ = false;
        ++hotkeyRefreshTicket_;
        ++keyboardRefreshTicket_;
        performanceHistory_.clear();
        cpuCoreViewSample_ = CpuCoreViewSample{};
    }
    refreshDetailTabTexts();
    if (kShouldTryStaticBackgroundRefresh || kIdentityChanged)
    {
        requestAsyncStaticDetailRefresh(true);
    }
    if (kIdentityChanged)
    {
        requestAsyncDetailOverviewRefresh();
    }
    requestInitialRefreshForCurrentTab();

    // Update end log: output the new identity and key field status.
    KLogEvent updateRecordFinishEvent;
    info << updateRecordFinishEvent
        << "[ProcessDetailWindow] updateBaseRecord: 完成, pid="
        << baseRecord_.pid
        << ", newIdentity="
        << identityKey_
        << ", signatureState="
        << baseRecord_.signatureState
        << eol;
}

std::uint32_t ProcessDetailWindow::pid() const
{
    return baseRecord_.pid;
}

std::string ProcessDetailWindow::identityKey() const
{
    return identityKey_;
}

void ProcessDetailWindow::setPerformanceHistory(std::vector<PerformanceHistorySample> history)
{
    constexpr std::size_t kMaximumHistorySamples = 1800U;
    if (history.size() > kMaximumHistorySamples)
    {
        history.erase(history.begin(), history.end() - static_cast<std::ptrdiff_t>(kMaximumHistorySamples));
    }

    performanceHistory_.clear();
    for (const PerformanceHistorySample& sample : history)
    {
        if (sample.unixMilliseconds > 0)
        {
            performanceHistory_.push_back(sample);
        }
    }
    refreshPerformanceHistoryCharts();
}

void ProcessDetailWindow::appendPerformanceHistorySample(const PerformanceHistorySample& sample)
{
    if (sample.unixMilliseconds <= 0)
    {
        return;
    }

    performanceHistory_.push_back(sample);
    constexpr std::size_t kMaximumHistorySamples = 1800U;
    while (performanceHistory_.size() > kMaximumHistorySamples)
    {
        performanceHistory_.pop_front();
    }
    refreshPerformanceHistoryCharts();
}

void ProcessDetailWindow::setCpuCoreViewSample(CpuCoreViewSample sample)
{
    // The page uses lazy loading; when the control is not yet constructed, only the latest interval is saved so it can be displayed directly upon first entry.
    cpuCoreViewSample_ = std::move(sample);
    refreshCpuCoreView();
}

void ProcessDetailWindow::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);

    // Note: Rebuild internal styles immediately during theme switching to prevent residual colors from the old theme.
    if (event == nullptr)
    {
        return;
    }

    const bool kIsThemeEvent =
        (event->type() == QEvent::PaletteChange) ||
        (event->type() == QEvent::ApplicationPaletteChange) ||
        (event->type() == QEvent::StyleChange);
    if (!kIsThemeEvent)
    {
        return;
    }

    applyThemeStyle();
    refreshDetailTabTexts();

    if (threadInspectStatusLabel_ != nullptr)
    {
        updateThreadInspectStatusLabel(threadInspectStatusLabel_->text(), threadInspectRefreshing_);
    }

    if (moduleStatusLabel_ != nullptr)
    {
        updateModuleStatusLabel(moduleStatusLabel_->text(), moduleRefreshing_);
        if (!moduleRefreshing_ && moduleRecords_.empty())
        {
            moduleStatusLabel_->setStyleSheet(buildStateLabelStyle(statusErrorColor(), 700));
        }
    }

    if (tokenStatusLabel_ != nullptr)
    {
        tokenStatusLabel_->setStyleSheet(
            tokenRefreshing_
            ? buildStateLabelStyle(ksword_theme::primaryBlueColor, 700)
            : buildStateLabelStyle(statusIdleColor(), 600));
    }

    if (tokenSwitchStatusLabel_ != nullptr)
    {
        const QString kStatusText = tokenSwitchStatusLabel_->text();
        if (kStatusText.contains(QStringLiteral("失败")) || kStatusText.contains(QStringLiteral("失败项")))
        {
            tokenSwitchStatusLabel_->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        }
        else if (kStatusText.contains(QStringLiteral("完成")) || kStatusText.contains(QStringLiteral("成功")))
        {
            tokenSwitchStatusLabel_->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
        }
        else
        {
            tokenSwitchStatusLabel_->setStyleSheet(buildStateLabelStyle(statusSecondaryColor(), 600));
        }
    }

    if (pebStatusLabel_ != nullptr)
    {
        const bool kHasDiagnostic = pebStatusLabel_->text().contains(QStringLiteral(" | "));
        if (pebRefreshing_)
        {
            pebStatusLabel_->setStyleSheet(buildStateLabelStyle(ksword_theme::primaryBlueColor, 700));
        }
        else if (kHasDiagnostic)
        {
            pebStatusLabel_->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        }
        else
        {
            pebStatusLabel_->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
        }
    }

    if (hotkeyStatusLabel_ != nullptr)
    {
        const QString kStatusText = hotkeyStatusLabel_->text();
        if (hotkeyRefreshing_)
        {
            hotkeyStatusLabel_->setStyleSheet(buildStateLabelStyle(ksword_theme::primaryBlueColor, 700));
        }
        else if (kStatusText.contains(QStringLiteral("无公开API")) || kStatusText.contains(QStringLiteral("失败")))
        {
            hotkeyStatusLabel_->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        }
        else
        {
            hotkeyStatusLabel_->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
        }
    }

    if (keyboardStatusLabel_ != nullptr)
    {
        const QString kStatusText = keyboardStatusLabel_->text();
        if (keyboardRefreshing_)
        {
            keyboardStatusLabel_->setStyleSheet(buildStateLabelStyle(ksword_theme::primaryBlueColor, 700));
        }
        else if (kStatusText.contains(QStringLiteral("失败")) || kStatusText.contains(QStringLiteral("不可用")))
        {
            keyboardStatusLabel_->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        }
        else
        {
            keyboardStatusLabel_->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
        }
    }

    refreshKernelObjectTabTexts();
}

void ProcessDetailWindow::applyThemeStyle()
{
    if (themeStyleApplying_)
    {
        return;
    }
    themeStyleApplying_ = true;

    // Explicitly set the window palette:
    // - On Win11, explicitly force the window background to prevent the system from automatically switching it to a light color.
    const bool kDarkModeEnabled = ksword_theme::isDarkModeEnabled();
    QPalette themedPalette = (qApp != nullptr) ? qApp->palette() : palette();
    themedPalette.setColor(QPalette::Window, ksword_theme::windowColor());
    themedPalette.setColor(QPalette::WindowText, ksword_theme::textPrimaryColor());
    themedPalette.setColor(QPalette::Base, ksword_theme::surfaceColor());
    themedPalette.setColor(QPalette::AlternateBase, ksword_theme::surfaceAltColor());
    themedPalette.setColor(QPalette::Text, ksword_theme::textPrimaryColor());
    themedPalette.setColor(QPalette::Mid, ksword_theme::borderColor());
    themedPalette.setColor(QPalette::Highlight, ksword_theme::accentColor(ksword_theme::AccentRole::kBlue));
    themedPalette.setColor(QPalette::HighlightedText, ksword_theme::onAccentColor());

    setPalette(themedPalette);
    setAutoFillBackground(true);
    setAttribute(Qt::WA_StyledBackground, true);
    setStyleSheet(buildProcessDetailRootStyle());

    // Force-set the background color for sub-pages to avoid white backgrounds in the tab content area.
    const std::vector<QWidget*> kTabPageList{
        detailTab_,
        performanceTab_,
        cpuCoreTab_,
        threadTab_,
        actionTab_,
        moduleTab_,
        tokenTab_,
        tokenSwitchTab_,
        kernelObjectTab_,
        hotkeyTab_,
        keyboardTab_,
        pluginTab_,
        pebTab_
    };
    for (QWidget* tabPage : kTabPageList)
    {
        if (tabPage == nullptr)
        {
            continue;
        }
        tabPage->setPalette(themedPalette);
        tabPage->setAutoFillBackground(true);
        tabPage->setAttribute(Qt::WA_StyledBackground, true);
    }

    // Use theme text color for headers uniformly to prevent black text issues in dark mode.
    const QString kHeaderStyle = QStringLiteral(
        "QHeaderView::section {"
        "  color:%1;"
        "  background:transparent; /* %2 */"
        "  border:1px solid %3;"
        "  padding:4px;"
        "  font-weight:600;"
        "}")
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::borderHex());

    if (threadInspectTable_ != nullptr && threadInspectTable_->horizontalHeader() != nullptr)
    {
        threadInspectTable_->horizontalHeader()->setStyleSheet(kHeaderStyle);
    }
    if (moduleTable_ != nullptr && moduleTable_->header() != nullptr)
    {
        moduleTable_->header()->setStyleSheet(kHeaderStyle);
    }
    if (hotkeyTable_ != nullptr && hotkeyTable_->horizontalHeader() != nullptr)
    {
        hotkeyTable_->horizontalHeader()->setStyleSheet(kHeaderStyle);
    }
    if (keyboardHotkeyTable_ != nullptr && keyboardHotkeyTable_->horizontalHeader() != nullptr)
    {
        keyboardHotkeyTable_->horizontalHeader()->setStyleSheet(kHeaderStyle);
    }
    if (keyboardHookTable_ != nullptr && keyboardHookTable_->horizontalHeader() != nullptr)
    {
        keyboardHookTable_->horizontalHeader()->setStyleSheet(kHeaderStyle);
    }
    if (processCpuCoreGrid_ != nullptr)
    {
        processCpuCoreGrid_->update();
    }
    if (threadCpuCoreGrid_ != nullptr)
    {
        threadCpuCoreGrid_->update();
    }

    if (cpuCoreTitleLabel_ != nullptr)
    {
        cpuCoreTitleLabel_->setStyleSheet(QStringLiteral("font-size:16px;font-weight:700;color:%1;")
            .arg(ksword_theme::textPrimaryHex()));
    }
    if (cpuCoreDescriptionLabel_ != nullptr)
    {
        cpuCoreDescriptionLabel_->setStyleSheet(QStringLiteral("color:%1;")
            .arg(ksword_theme::textSecondaryHex()));
    }
    const QString kCpuCoreSummaryStyle = QStringLiteral("font-size:20px;font-weight:700;color:%1;")
        .arg(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue).name());
    if (cpuCoreSystemValueLabel_ != nullptr)
    {
        cpuCoreSystemValueLabel_->setStyleSheet(kCpuCoreSummaryStyle);
    }
    if (cpuCoreEquivalentValueLabel_ != nullptr)
    {
        cpuCoreEquivalentValueLabel_->setStyleSheet(kCpuCoreSummaryStyle);
    }
    refreshCpuCoreView();

    if (signatureCheckBox_ != nullptr)
    {
        signatureCheckBox_->setStyleSheet(QStringLiteral(
            "QCheckBox { color:%1; font-weight:600; }")
            .arg(ksword_theme::textPrimaryHex()));
    }

    if (tokenRawInfoClassCombo_ != nullptr || tokenRawInputModeCombo_ != nullptr)
    {
        const QString kComboStyle = ksword_theme::themedComboBoxStyle();
        if (tokenRawInfoClassCombo_ != nullptr)
        {
            tokenRawInfoClassCombo_->setStyleSheet(kComboStyle);
        }
        if (tokenRawInputModeCombo_ != nullptr)
        {
            tokenRawInputModeCombo_->setStyleSheet(kComboStyle);
        }
    }

    themeStyleApplying_ = false;
}

void ProcessDetailWindow::initializeUi()
{
    // UI initialization entry log: used to troubleshoot window initialization order.
    KLogEvent initUiEvent;
    info << initUiEvent
        << "[ProcessDetailWindow] initializeUi: 创建根布局和Tab容器。"
        << eol;

    // The root window object name is used for precise style selector matching.
    setObjectName(QStringLiteral("ProcessDetailWindowRoot"));

    // The page area retains QTabWidget to avoid affecting existing page navigation, currentChanged, and lazy refresh logic.
    // After hiding the native QTabBar, a single-column left navigation provides access to all pages.
    rootLayout_ = new QHBoxLayout(this);
    rootLayout_->setContentsMargins(8, 8, 8, 8);
    rootLayout_->setSpacing(6);

    tabNavigation_ = new QWidget(this);
    tabNavigation_->setObjectName(QStringLiteral("ProcessDetailTabNavigation"));
    tabNavigation_->setFixedWidth(210);
    tabNavigation_->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);
    auto* tabNavigationLayout = new QVBoxLayout(tabNavigation_);
    tabNavigationLayout->setContentsMargins(5, 5, 5, 5);
    tabNavigationLayout->setSpacing(4);

    tabWidget_ = new QTabWidget(this);
    // QTabWidget takes the largest minimumSizeHint from all constructed pages. Since the detail page uses lazy loading, using the default
    // sizing policy would propagate this hint to the top-level window upon creating a new page, triggering an automatic expansion.
    tabWidget_->setMinimumSize(0, 0);
    tabWidget_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
    tabWidget_->tabBar()->hide();
    tabNavigationButtonGroup_ = new QButtonGroup(this);
    tabNavigationButtonGroup_->setExclusive(true);
    rootLayout_->addWidget(tabNavigation_);
    rootLayout_->addWidget(tabWidget_, 1);

    // Create lightweight page containers first; the actual control tree is constructed when the user first enters.
    detailTab_ = new QWidget(tabWidget_);
    performanceTab_ = new QWidget(tabWidget_);
    cpuCoreTab_ = new QWidget(tabWidget_);
    threadTab_ = new QWidget(tabWidget_);
    actionTab_ = new QWidget(tabWidget_);
    moduleTab_ = new QWidget(tabWidget_);
    embeddedHandleTab_ = new QWidget(tabWidget_);
    embeddedMemoryTab_ = new QWidget(tabWidget_);
    embeddedNetworkTab_ = new QWidget(tabWidget_);
    soundSourceTab_ = new QWidget(tabWidget_);
    embeddedWindowTab_ = new QWidget(tabWidget_);
    tokenTab_ = new QWidget(tabWidget_);
    tokenSwitchTab_ = new QWidget(tabWidget_);
    kernelObjectTab_ = new QWidget(tabWidget_);
    hotkeyTab_ = new QWidget(tabWidget_);
    keyboardTab_ = new QWidget(tabWidget_);
    pluginTab_ = new QWidget(tabWidget_);
    pebTab_ = new QWidget(tabWidget_);
    kernelCallbackTab_ = new QWidget(tabWidget_);

    detailTab_->setObjectName(QStringLiteral("ProcessDetailTab_Detail"));
    performanceTab_->setObjectName(QStringLiteral("ProcessDetailTab_Performance"));
    cpuCoreTab_->setObjectName(QStringLiteral("ProcessDetailTab_CpuCore"));
    threadTab_->setObjectName(QStringLiteral("ProcessDetailTab_Thread"));
    actionTab_->setObjectName(QStringLiteral("ProcessDetailTab_Action"));
    moduleTab_->setObjectName(QStringLiteral("ProcessDetailTab_Module"));
    embeddedHandleTab_->setObjectName(QStringLiteral("ProcessDetailTab_EmbeddedHandle"));
    embeddedMemoryTab_->setObjectName(QStringLiteral("ProcessDetailTab_EmbeddedMemory"));
    embeddedNetworkTab_->setObjectName(QStringLiteral("ProcessDetailTab_EmbeddedNetwork"));
    soundSourceTab_->setObjectName(QStringLiteral("ProcessDetailTab_SoundSource"));
    embeddedWindowTab_->setObjectName(QStringLiteral("ProcessDetailTab_EmbeddedWindow"));
    tokenTab_->setObjectName(QStringLiteral("ProcessDetailTab_Token"));
    tokenSwitchTab_->setObjectName(QStringLiteral("ProcessDetailTab_TokenSwitch"));
    kernelObjectTab_->setObjectName(QStringLiteral("ProcessDetailTab_ProcessDetailEvidence"));
    hotkeyTab_->setObjectName(QStringLiteral("ProcessDetailTab_Hotkey"));
    keyboardTab_->setObjectName(QStringLiteral("ProcessDetailTab_Keyboard"));
    pluginTab_->setObjectName(QStringLiteral("ProcessDetailTab_Plugin"));
    pebTab_->setObjectName(QStringLiteral("ProcessDetailTab_Peb"));
    kernelCallbackTab_->setObjectName(QStringLiteral("ProcessDetailTab_KernelCallbackTable"));

    // The Details tab is the default page and is constructed during window creation; all other pages are constructed on first access triggered by the left navigation.
    initializeDetailTab();
    initializedTabs_.insert(detailTab_);

    // Assign icon and title text to the tab.
    tabWidget_->addTab(detailTab_, QIcon(":/Icon/process_details.svg"), "详细信息");
    tabWidget_->addTab(
        performanceTab_,
        QIcon(":/Icon/process_performance.svg"),
        ks::i18n::text(QStringLiteral("process.detail.tab.performance"), QString()));
    tabWidget_->addTab(
        cpuCoreTab_,
        QIcon(":/Icon/process_performance.svg"),
        ks::i18n::text(QStringLiteral("process.detail.tab.cpu_core"), QString()));
    tabWidget_->addTab(threadTab_, QIcon(":/Icon/process_tree.svg"), "线程");
    tabWidget_->addTab(actionTab_, QIcon(":/Icon/process_priority.svg"), "操作");
    tabWidget_->addTab(moduleTab_, QIcon(":/Icon/process_list.svg"), "模块");
    tabWidget_->addTab(embeddedHandleTab_, QIcon(":/Icon/handle_refresh.svg"), "句柄");
    tabWidget_->addTab(embeddedMemoryTab_, QIcon(":/Icon/process_list.svg"), "内存");
    tabWidget_->addTab(embeddedNetworkTab_, QIcon(":/Icon/process_details.svg"), "网络连接");
    tabWidget_->addTab(soundSourceTab_, QIcon(":/Icon/sound_source.svg"), "声音来源");
    tabWidget_->addTab(embeddedWindowTab_, QIcon(":/Icon/process_tree.svg"), "窗口列表");
    tabWidget_->addTab(tokenTab_, QIcon(":/Icon/process_critical.svg"), "令牌");
    tabWidget_->addTab(tokenSwitchTab_, QIcon(":/Icon/process_start.svg"), "令牌开关");
    tabWidget_->addTab(kernelObjectTab_, QIcon(":/Icon/process_critical.svg"), "Process Detail Evidence");
    tabWidget_->addTab(hotkeyTab_, QIcon(":/Icon/process_hotkey.svg"), "进程热键");
    tabWidget_->addTab(keyboardTab_, QIcon(":/Icon/process_hotkey.svg"), "键盘");
    tabWidget_->addTab(pluginTab_, QIcon(":/Icon/process_start.svg"), "插件");
    tabWidget_->addTab(pebTab_, QIcon(":/Icon/process_tree.svg"), "PEB");
    tabWidget_->addTab(kernelCallbackTab_, QIcon(":/Icon/process_hotkey.svg"), "内核回调表");
    // addTab shows QTabBar again when the first page is added, so hide it again after adding all pages.
    tabWidget_->tabBar()->hide();

    for (int tabIndex = 0; tabIndex < tabWidget_->count(); ++tabIndex)
    {
        auto* navigationButton = new QToolButton(tabNavigation_);
        navigationButton->setCheckable(true);
        navigationButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        navigationButton->setIcon(tabWidget_->tabIcon(tabIndex));
        navigationButton->setIconSize(QSize(18, 18));
        navigationButton->setText(tabWidget_->tabText(tabIndex));
        navigationButton->setToolTip(tabWidget_->tabText(tabIndex));
        navigationButton->setMinimumHeight(30);
        navigationButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        tabNavigationButtonGroup_->addButton(navigationButton, tabIndex);
        tabNavigationLayout->addWidget(navigationButton);
    }
    tabNavigationLayout->addStretch(1);

    tabWidget_->setCurrentWidget(detailTab_);
    if (QAbstractButton* currentNavigationButton =
            tabNavigationButtonGroup_->button(tabWidget_->currentIndex()))
    {
        currentNavigationButton->setChecked(true);
    }

    // Apply the theme style uniformly after all controls are created.
    applyThemeStyle();

    updateWindowTitle();
}

void ProcessDetailWindow::ensureTabContentInitialized(QWidget* const tab)
{
    if (tab == nullptr || initializedTabs_.contains(tab))
    {
        return;
    }

    // Mark first to prevent recursive creation of the control tree when tab events occur during initialization.
    initializedTabs_.insert(tab);
    if (tab == threadTab_)
    {
        initializeThreadTab();
    }
    else if (tab == performanceTab_)
    {
        initializePerformanceTab();
    }
    else if (tab == cpuCoreTab_)
    {
        initializeCpuCoreTab();
    }
    else if (tab == actionTab_)
    {
        initializeActionTab();
    }
    else if (tab == moduleTab_)
    {
        initializeModuleTab();
    }
    else if (tab == embeddedHandleTab_)
    {
        initializeEmbeddedHandleTab();
    }
    else if (tab == embeddedMemoryTab_)
    {
        initializeEmbeddedMemoryTab();
    }
    else if (tab == embeddedNetworkTab_)
    {
        initializeEmbeddedNetworkTab();
    }
    else if (tab == soundSourceTab_)
    {
        initializeSoundSourceTab();
    }
    else if (tab == embeddedWindowTab_)
    {
        initializeEmbeddedWindowTab();
    }
    else if (tab == tokenTab_)
    {
        initializeTokenTab();
    }
    else if (tab == tokenSwitchTab_)
    {
        initializeTokenSwitchTab();
    }
    else if (tab == kernelObjectTab_)
    {
        initializeKernelObjectTab();
        refreshKernelObjectTabTexts();
    }
    else if (tab == hotkeyTab_)
    {
        initializeHotkeyTab();
    }
    else if (tab == keyboardTab_)
    {
        initializeKeyboardTab();
    }
    else if (tab == pluginTab_)
    {
        initializePluginTab();
    }
    else if (tab == pebTab_)
    {
        initializePebTab();
    }
    else if (tab == kernelCallbackTab_)
    {
        initializeKernelCallbackTab();
    }

    // After creating a new page, connect its signals and apply the unified theme; existing controls will not be connected again.
    initializeConnections();
    applyThemeStyle();
}

void ProcessDetailWindow::initializePluginTab()
{
    // The plugin tab provides only one link: 'process context -> independent plugin process'.
    // - Reads only the host manifest fields from plugin.json;
    // - Do not load Python, DLL, or model details into the detail window.
    // - Re-discover compatible plugins via Ksword each time the menu is expanded to prevent cache expiration.
    auto* layout = new QVBoxLayout(pluginTab_);
    layout->setContentsMargins(14, 14, 14, 14);
    layout->setSpacing(10);

    auto* titleLabel = new QLabel(QStringLiteral("进程插件"), pluginTab_);
    titleLabel->setStyleSheet(QStringLiteral("font-size:16px; font-weight:700; color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    layout->addWidget(titleLabel);

    auto* descriptionLabel = new QLabel(
        QStringLiteral("选择适用于当前进程的插件进行分析。"),
        pluginTab_);
    descriptionLabel->setWordWrap(true);
    descriptionLabel->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    layout->addWidget(descriptionLabel);

    auto* actionLayout = new QHBoxLayout();
    pluginTargetMenuButton_ = new QToolButton(pluginTab_);
    pluginTargetMenuButton_->setText(QStringLiteral("插件"));
    pluginTargetMenuButton_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    pluginTargetMenuButton_->setPopupMode(QToolButton::InstantPopup);
    pluginTargetMenuButton_->setIcon(QIcon(":/Icon/process_start.svg"));
    pluginTargetMenuButton_->setStyleSheet(buildBlueButtonStyle());
    pluginTargetMenu_ = new QMenu(pluginTargetMenuButton_);
    pluginTargetMenuButton_->setMenu(pluginTargetMenu_);
    actionLayout->addWidget(pluginTargetMenuButton_);

    auto* managerButton = new QPushButton(QStringLiteral("插件管理"), pluginTab_);
    managerButton->setStyleSheet(buildBlueButtonStyle());
    actionLayout->addWidget(managerButton);
    actionLayout->addStretch(1);
    layout->addLayout(actionLayout);
    layout->addStretch(1);

    connect(pluginTargetMenu_, &QMenu::aboutToShow, this, [this]() {
        ks::plugin_host::InvocationContext context;
        context.targetKind = ks::plugin_host::TargetKind::kProcess;
        context.processId = baseRecord_.pid;
        context.processName = QString::fromStdString(baseRecord_.processName);
        context.filePath = QString::fromStdString(
            baseRecord_.imagePath.empty() ? baseRecord_.r0ImagePath : baseRecord_.imagePath);
        ks::plugin_host::populateTargetMenu(pluginTargetMenu_, this, context);
    });
    connect(managerButton, &QPushButton::clicked, this, [this]() {
        ks::plugin_host::showPluginManager(this);
    });
}

void ProcessDetailWindow::showActionTab()
{
    // Right-click shortcut to the process list entry:
    // - Input: none; target process comes from m_baseRecord bound to the current detail window
    // - Processing: Switch to the 'Actions' tab and set focus to the DLL path input box to facilitate direct selection of the injection file.
    // - Returns: None. If controls are not yet initialized, only logs the event and keeps the current page.
    if (tabWidget_ != nullptr && actionTab_ != nullptr)
    {
        tabWidget_->setCurrentWidget(actionTab_);
    }

    if (dllPathLineEdit_ != nullptr)
    {
        dllPathLineEdit_->setFocus(Qt::OtherFocusReason);
    }

    KLogEvent actionTabEntryEvent;
    info << actionTabEntryEvent
        << "[ProcessDetailWindow] showActionTab: pid="
        << baseRecord_.pid
        << eol;
}

void ProcessDetailWindow::requestInitialRefreshForCurrentTab()
{
    // Lazy loading strategy:
    // - The detail page displays only lightweight fields existing at construction time;
    // - Defer heavy queries (threads, modules, tokens, PEB, Sections, etc.) until the user switches to the corresponding page.
    // - The automatic first render per page executes only once; users can still manually refresh by clicking the refresh button.
    if (tabWidget_ == nullptr)
    {
        return;
    }

    QWidget* const kCurrentTab = tabWidget_->currentWidget();
    if (kCurrentTab == nullptr)
    {
        return;
    }
    ensureTabContentInitialized(kCurrentTab);

    if (kCurrentTab == threadTab_)
    {
        if (!threadInspectInitialRefreshStarted_)
        {
            requestAsyncThreadInspectRefresh();
        }
        return;
    }

    if (kCurrentTab == moduleTab_)
    {
        if (!moduleInitialRefreshStarted_)
        {
            requestAsyncModuleRefresh(true);
        }
        return;
    }

    if (kCurrentTab == actionTab_)
    {
        if (!actionPrivilegeInitialRefreshStarted_)
        {
            requestAsyncActionPrivilegeRefresh();
        }
        return;
    }

    if (kCurrentTab == tokenTab_)
    {
        if (!tokenInitialRefreshStarted_)
        {
            requestAsyncTokenRefresh();
        }
        return;
    }

    if (kCurrentTab == tokenSwitchTab_)
    {
        if (!tokenSwitchInitialRefreshStarted_)
        {
            refreshTokenSwitchStates();
        }
        return;
    }

    if (kCurrentTab == kernelObjectTab_)
    {
        if (!sectionInfoInitialRefreshStarted_)
        {
            requestAsyncSectionRefresh();
        }
        return;
    }

    if (kCurrentTab == hotkeyTab_)
    {
        if (!hotkeyInitialRefreshStarted_)
        {
            requestAsyncHotkeyRefresh();
        }
        return;
    }

    if (kCurrentTab == keyboardTab_)
    {
        if (!keyboardInitialRefreshStarted_)
        {
            requestAsyncKeyboardRefresh();
        }
        return;
    }

    if (kCurrentTab == pebTab_ && !pebInitialRefreshStarted_)
    {
        requestAsyncPebRefresh();
        return;
    }

    if (kCurrentTab == embeddedHandleTab_)
    {
        ensureEmbeddedHandleView();
        return;
    }

    if (kCurrentTab == embeddedMemoryTab_)
    {
        ensureEmbeddedMemoryView();
        return;
    }

    if (kCurrentTab == embeddedNetworkTab_)
    {
        ensureEmbeddedNetworkView();
        return;
    }

    if (kCurrentTab == embeddedWindowTab_)
    {
        ensureEmbeddedWindowView();
        return;
    }

    if (kCurrentTab == kernelCallbackTab_ && !kernelCallbackInitialRefreshStarted_)
    {
        requestAsyncKernelCallbackRefresh();
    }
}

void ProcessDetailWindow::initializeEmbeddedHandleTab()
{
    // Create only a lightweight container; HandleDock itself contains multiple tables and asynchronous enumeration, so construct it only when switching to the tab for the first time.
    embeddedHandleLayout_ = new QVBoxLayout(embeddedHandleTab_);
    embeddedHandleLayout_->setContentsMargins(0, 0, 0, 0);
    embeddedHandleLayout_->setSpacing(0);

    embeddedHandlePlaceholder_ = new QLabel(
        QStringLiteral("句柄审计视图将在首次进入本页时加载。"),
        embeddedHandleTab_);
    embeddedHandlePlaceholder_->setAlignment(Qt::AlignCenter);
    embeddedHandlePlaceholder_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    embeddedHandleLayout_->addWidget(embeddedHandlePlaceholder_, 1);
}

void ProcessDetailWindow::ensureEmbeddedHandleView()
{
    // Purpose: Lazy-load the embedded HandleDock upon first entering the "Handles" page and lock the current PID.
    // Input: none (target process taken from m_baseRecord).
    // Return: None. Split by frame consistent with memory pages: slot functions return immediately; control tree construction and PID focus belong to separate event loops.
    if (embeddedHandleDock_ != nullptr || embeddedHandleLayout_ == nullptr)
    {
        return;
    }

    if (!markEmbeddedViewBuildPending(embeddedHandleTab_))
    {
        return;
    }

    QTimer::singleShot(kEmbeddedViewBuildFirstStageDelayMs, this, [this]() {
        if (embeddedHandleDock_ != nullptr || embeddedHandleLayout_ == nullptr)
        {
            clearEmbeddedViewBuildPending(embeddedHandleTab_);
            return;
        }

        // First phase: construct the control tree and replace placeholder text.
        embeddedHandleDock_ = new HandleDock(embeddedHandleTab_);
        embeddedHandleDock_->hide();
        attachEmbeddedDockToTabLayout(
            embeddedHandleLayout_,
            embeddedHandlePlaceholder_,
            embeddedHandleDock_);
        embeddedHandleDock_->show();

        // Stage 2: Focus by current PID; handle enumeration is already asynchronous.
        const std::uint32_t kTargetProcessId = baseRecord_.pid;
        QTimer::singleShot(kEmbeddedViewBuildNextStageDelayMs, this, [this, kTargetProcessId]() {
            if (embeddedHandleDock_ != nullptr)
            {
                embeddedHandleDock_->focusProcessId(kTargetProcessId, false);
            }
            clearEmbeddedViewBuildPending(embeddedHandleTab_);
        });
    });
}

void ProcessDetailWindow::initializeEmbeddedMemoryTab()
{
    embeddedMemoryLayout_ = new QVBoxLayout(embeddedMemoryTab_);
    embeddedMemoryLayout_->setContentsMargins(0, 0, 0, 0);
    embeddedMemoryLayout_->setSpacing(0);
    embeddedMemoryPlaceholder_ = new QLabel(
        QStringLiteral("内存管理视图将在首次进入本页时加载。"),
        embeddedMemoryTab_);
    embeddedMemoryPlaceholder_->setAlignment(Qt::AlignCenter);
    embeddedMemoryPlaceholder_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    embeddedMemoryLayout_->addWidget(embeddedMemoryPlaceholder_, 1);
}

void ProcessDetailWindow::ensureEmbeddedMemoryView()
{
    // Purpose:
    // - Lazy-load the embedded MemoryDock upon first entering the 'Memory' page and attach the current process to that Dock.
    // - This chain represents the heaviest synchronous overhead in the detail window: the MemoryDock constructor synchronously enumerates
    //   all system processes, focusProcessForOperations enumerates processes again, and attachToProcess traverses the entire address space
    //   of the target process. Stacking these three operations within a single Tab click causes the UI to hang for several seconds.
    // - Therefore, switch to frame-by-frame construction: the slot function returns immediately to allow placeholder text to render first, while control tree
    //   construction and process attachment each occupy a separate event loop iteration, allowing the UI to repaint and respond to input between iterations.
    // Input: none (target process taken from m_baseRecord).
    // Returns: None. Repeated calls during the queueing phase are short-circuited by the queue flag, preventing the construction of a second MemoryDock.
    if (embeddedMemoryDock_ != nullptr || embeddedMemoryLayout_ == nullptr)
    {
        return;
    }

    if (!markEmbeddedViewBuildPending(embeddedMemoryTab_))
    {
        return;
    }

    // Pass 'this' as the context object to QTimer::singleShot: if the window is destroyed before the timer fires, the callback will not execute.
    // This aligns with the existing delayed-first-render pattern in the constructor, eliminating the need for additional liveness checks.
    QTimer::singleShot(kEmbeddedViewBuildFirstStageDelayMs, this, [this]() {
        if (embeddedMemoryDock_ != nullptr || embeddedMemoryLayout_ == nullptr)
        {
            clearEmbeddedViewBuildPending(embeddedMemoryTab_);
            return;
        }

        // Phase 1: Construct the control tree and mount the page only; do not trigger attachment to the target process.
        embeddedMemoryDock_ = new MemoryDock(embeddedMemoryTab_);
        embeddedMemoryDock_->hide();
        attachEmbeddedDockToTabLayout(
            embeddedMemoryLayout_,
            embeddedMemoryPlaceholder_,
            embeddedMemoryDock_);
        embeddedMemoryDock_->setProcessDetailMemoryScope();
        embeddedMemoryDock_->show();

        // Step 2: Attach the target process. The PID is fixed during construction of this segment to ensure consistency with the current build target.
        const std::uint32_t kTargetProcessId = baseRecord_.pid;
        QTimer::singleShot(kEmbeddedViewBuildNextStageDelayMs, this, [this, kTargetProcessId]() {
            if (embeddedMemoryDock_ != nullptr)
            {
                embeddedMemoryDock_->focusProcessForOperations(kTargetProcessId, false);
            }
            clearEmbeddedViewBuildPending(embeddedMemoryTab_);
        });
    });
}

void ProcessDetailWindow::initializeEmbeddedNetworkTab()
{
    embeddedNetworkLayout_ = new QVBoxLayout(embeddedNetworkTab_);
    embeddedNetworkLayout_->setContentsMargins(0, 0, 0, 0);
    embeddedNetworkLayout_->setSpacing(0);
    embeddedNetworkPlaceholder_ = new QLabel(
        QStringLiteral("网络连接视图将在首次进入本页时加载。"),
        embeddedNetworkTab_);
    embeddedNetworkPlaceholder_->setAlignment(Qt::AlignCenter);
    embeddedNetworkPlaceholder_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    embeddedNetworkLayout_->addWidget(embeddedNetworkPlaceholder_, 1);
}

void ProcessDetailWindow::ensureEmbeddedNetworkView()
{
    // Purpose: Lazy-load the embedded NetworkDock upon first entering the 'Network' tab, retaining only the connections for the current process.
    // Input: none (target process taken from m_baseRecord).
    // Return: None. Split by frame consistent with memory pages to avoid constructing the control tree and applying connection filters within a single Tab click.
    if (embeddedNetworkDock_ != nullptr || embeddedNetworkLayout_ == nullptr)
    {
        return;
    }

    if (!markEmbeddedViewBuildPending(embeddedNetworkTab_))
    {
        return;
    }

    QTimer::singleShot(kEmbeddedViewBuildFirstStageDelayMs, this, [this]() {
        if (embeddedNetworkDock_ != nullptr || embeddedNetworkLayout_ == nullptr)
        {
            clearEmbeddedViewBuildPending(embeddedNetworkTab_);
            return;
        }

        // Phase 1: Construct the control tree, crop the page range, and replace placeholder text.
        embeddedNetworkDock_ = new NetworkDock(embeddedNetworkTab_);
        embeddedNetworkDock_->hide();
        attachEmbeddedDockToTabLayout(
            embeddedNetworkLayout_,
            embeddedNetworkPlaceholder_,
            embeddedNetworkDock_);
        embeddedNetworkDock_->setProcessDetailConnectionScope();
        embeddedNetworkDock_->show();

        // Second pass: filter connections by the current PID; connection enumeration is already implemented asynchronously.
        const quint32 kTargetProcessId = static_cast<quint32>(baseRecord_.pid);
        QTimer::singleShot(kEmbeddedViewBuildNextStageDelayMs, this, [this, kTargetProcessId]() {
            if (embeddedNetworkDock_ != nullptr)
            {
                embeddedNetworkDock_->focusConnectionsByPids(
                    QVector<quint32>{ kTargetProcessId });
            }
            clearEmbeddedViewBuildPending(embeddedNetworkTab_);
        });
    });
}

void ProcessDetailWindow::initializeSoundSourceTab()
{
    // Process details only pass the current PID; the page internally uses background sampling and R0 verification consistent with the Miscellaneous page.
    auto* soundSourceLayout = new QVBoxLayout(soundSourceTab_);
    soundSourceLayout->setContentsMargins(0, 0, 0, 0);
    soundSourceLayout->setSpacing(0);

    auto* soundSourcePage = new ks::misc::SoundSourcePage(
        baseRecord_.pid,
        baseRecord_.creationTime100ns,
        soundSourceTab_);
    soundSourceLayout->addWidget(soundSourcePage, 1);
}

void ProcessDetailWindow::initializeEmbeddedWindowTab()
{
    embeddedWindowLayout_ = new QVBoxLayout(embeddedWindowTab_);
    embeddedWindowLayout_->setContentsMargins(0, 0, 0, 0);
    embeddedWindowLayout_->setSpacing(0);
    embeddedWindowPlaceholder_ = new QLabel(
        QStringLiteral("窗口列表视图将在首次进入本页时加载。"),
        embeddedWindowTab_);
    embeddedWindowPlaceholder_->setAlignment(Qt::AlignCenter);
    embeddedWindowPlaceholder_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    embeddedWindowLayout_->addWidget(embeddedWindowPlaceholder_, 1);
}

void ProcessDetailWindow::ensureEmbeddedWindowView()
{
    // Purpose: Lazy-load the embedded OtherDock upon first entering the 'Window' tab, retaining only the window list for the current process.
    // Input: none (target process taken from m_baseRecord).
    // Return: None. Split by frame consistent with memory pages to avoid blocking control tree construction and window enumeration within a single Tab click.
    if (embeddedWindowDock_ != nullptr || embeddedWindowLayout_ == nullptr)
    {
        return;
    }

    if (!markEmbeddedViewBuildPending(embeddedWindowTab_))
    {
        return;
    }

    QTimer::singleShot(kEmbeddedViewBuildFirstStageDelayMs, this, [this]() {
        if (embeddedWindowDock_ != nullptr || embeddedWindowLayout_ == nullptr)
        {
            clearEmbeddedViewBuildPending(embeddedWindowTab_);
            return;
        }

        // Phase 1: Construct the control tree, crop the page range, and replace placeholder text.
        embeddedWindowDock_ = new OtherDock(embeddedWindowTab_);
        embeddedWindowDock_->hide();
        attachEmbeddedDockToTabLayout(
            embeddedWindowLayout_,
            embeddedWindowPlaceholder_,
            embeddedWindowDock_);
        embeddedWindowDock_->setWindowListOnlyScope();
        embeddedWindowDock_->show();

        // Second segment: Filter the window list by the current PID.
        const quint32 kTargetProcessId = static_cast<quint32>(baseRecord_.pid);
        QTimer::singleShot(kEmbeddedViewBuildNextStageDelayMs, this, [this, kTargetProcessId]() {
            if (embeddedWindowDock_ != nullptr)
            {
                embeddedWindowDock_->focusProcessIds(
                    QVector<quint32>{ kTargetProcessId });
            }
            clearEmbeddedViewBuildPending(embeddedWindowTab_);
        });
    });
}

void ProcessDetailWindow::requestAsyncStaticDetailRefresh(const bool includeSignatureCheck)
{
    // Static detail completion re-entrancy prevention:
    // - Periodic refresh may frequently call updateBaseRecord;
    // - Only one background static detail task is allowed per window to avoid signature verification backlog.
    const std::uint32_t kCurrentPid = baseRecord_.pid;
    const std::uint64_t kCurrentCreationTime = baseRecord_.creationTime100ns;
    if (kCurrentPid == 0 || staticDetailRefreshing_ || staticDetailRefreshAttempted_)
    {
        return;
    }

    const bool kNeedStaticQuery =
        baseRecord_.imagePath.empty() ||
        baseRecord_.commandLine.empty() ||
        baseRecord_.userName.empty() ||
        baseRecord_.startTimeText.empty() ||
        baseRecord_.architectureText.empty() ||
        baseRecord_.priorityText.empty() ||
        baseRecord_.signatureState.empty() ||
        baseRecord_.signatureState == "Pending";
    if (!kNeedStaticQuery)
    {
        return;
    }

    staticDetailRefreshing_ = true;
    staticDetailRefreshAttempted_ = true;
    const std::uint64_t kTicketValue = ++staticDetailRefreshTicket_;
    const std::uint32_t kPidValue = kCurrentPid;
    const std::uint64_t kCreationTimeValue = kCurrentCreationTime;
    const std::string kIdentityKeyValue = ks::process::buildProcessIdentityKey(
        kPidValue,
        kCreationTimeValue);
    QPointer<ProcessDetailWindow> guardThis(this);

    KLogEvent requestStaticDetailEvent;
    info << requestStaticDetailEvent
        << "[ProcessDetailWindow] requestAsyncStaticDetailRefresh: 后台补齐静态详情, pid="
        << kPidValue
        << ", includeSignature="
        << (includeSignatureCheck ? "true" : "false")
        << eol;

    QRunnable* refreshTask = QRunnable::create(
        [guardThis, kTicketValue, kPidValue, kCreationTimeValue, kIdentityKeyValue, includeSignatureCheck]()
        {
            StaticDetailRefreshResult refreshResult{};
            const auto kBeginTime = std::chrono::steady_clock::now();
            refreshResult.processRecord.pid = kPidValue;
            refreshResult.processRecord.creationTime100ns = kCreationTimeValue;
            refreshResult.processRecord.processName = ks::process::getProcessNameByPid(kPidValue);

            // Dynamic counters only supplement lightweight values; signature validation is controlled by the parameters of fillProcessStaticDetails.
            ks::process::refreshProcessDynamicCounters(refreshResult.processRecord);
            if (kCreationTimeValue != 0 &&
                refreshResult.processRecord.creationTime100ns != 0 &&
                refreshResult.processRecord.creationTime100ns != kCreationTimeValue)
            {
                // PID reused: discard current results to avoid writing new process info back to the old window.
                QMetaObject::invokeMethod(
                    guardThis,
                    [guardThis, kTicketValue, kIdentityKeyValue]()
                    {
                        if (guardThis == nullptr || guardThis->staticDetailRefreshTicket_ != kTicketValue)
                        {
                            return;
                        }
                        const std::string kCurrentIdentityKey = ks::process::buildProcessIdentityKey(
                            guardThis->baseRecord_.pid,
                            guardThis->baseRecord_.creationTime100ns);
                        if (kCurrentIdentityKey == kIdentityKeyValue)
                        {
                            guardThis->staticDetailRefreshing_ = false;
                            guardThis->staticDetailRefreshAttempted_ = true;
                        }
                    },
                    Qt::QueuedConnection);
                return;
            }
            refreshResult.queryOk = ks::process::fillProcessStaticDetails(
                refreshResult.processRecord,
                includeSignatureCheck);
            if (kCreationTimeValue == 0 && refreshResult.processRecord.creationTime100ns != 0)
            {
                // When lightweight window creation lacks a creation time, keep the identity as PID#0.
                // This ensures ProcessDock's window cache key does not drift after background completion.
                refreshResult.processRecord.creationTime100ns = kCreationTimeValue;
            }
            if (!refreshResult.queryOk)
            {
                refreshResult.diagnosticText = QStringLiteral("静态详情读取失败或权限不足");
            }
            if (refreshResult.processRecord.processName.empty())
            {
                refreshResult.processRecord.processName = "PID_" + std::to_string(kPidValue);
            }

            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - kBeginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kTicketValue, kIdentityKeyValue, includeSignatureCheck, refreshResult]()
                {
                    if (guardThis == nullptr || guardThis->staticDetailRefreshTicket_ != kTicketValue)
                    {
                        return;
                    }
                    const std::string kCurrentIdentityKey = ks::process::buildProcessIdentityKey(
                        guardThis->baseRecord_.pid,
                        guardThis->baseRecord_.creationTime100ns);
                    if (kCurrentIdentityKey != kIdentityKeyValue)
                    {
                        // Discard stale results when the target process identity changes, and allow the new identity to re-queue for completion.
                        guardThis->staticDetailRefreshing_ = false;
                        guardThis->staticDetailRefreshAttempted_ = false;
                        guardThis->requestAsyncStaticDetailRefresh(includeSignatureCheck);
                        return;
                    }
                    guardThis->applyStaticDetailRefreshResult(refreshResult);
                },
                Qt::QueuedConnection);
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyStaticDetailRefreshResult(const StaticDetailRefreshResult& refreshResult)
{
    // Background static detail population:
    // - Merge only valid fields to avoid clearing user-visible cached fields due to insufficient permissions.
    // - Retains R0 extended fields as they may originate from the process list or driver enumeration.
    staticDetailRefreshing_ = false;
    if (refreshResult.processRecord.pid != baseRecord_.pid)
    {
        return;
    }

    const ks::process::ProcessRecord& queriedRecord = refreshResult.processRecord;
    if (!queriedRecord.processName.empty()) baseRecord_.processName = queriedRecord.processName;
    if (!queriedRecord.imagePath.empty()) baseRecord_.imagePath = queriedRecord.imagePath;
    if (!queriedRecord.commandLine.empty()) baseRecord_.commandLine = queriedRecord.commandLine;
    if (!queriedRecord.userName.empty()) baseRecord_.userName = queriedRecord.userName;
    if (!queriedRecord.startTimeText.empty()) baseRecord_.startTimeText = queriedRecord.startTimeText;
    if (!queriedRecord.architectureText.empty()) baseRecord_.architectureText = queriedRecord.architectureText;
    if (!queriedRecord.priorityText.empty()) baseRecord_.priorityText = queriedRecord.priorityText;
    if (!queriedRecord.signatureState.empty()) baseRecord_.signatureState = queriedRecord.signatureState;
    if (!queriedRecord.signaturePublisher.empty()) baseRecord_.signaturePublisher = queriedRecord.signaturePublisher;
    baseRecord_.signatureTrusted = queriedRecord.signatureTrusted;
    baseRecord_.isAdmin = queriedRecord.isAdmin;
    if (queriedRecord.parentPid != 0) baseRecord_.parentPid = queriedRecord.parentPid;
    if (queriedRecord.sessionId != 0) baseRecord_.sessionId = queriedRecord.sessionId;
    if (queriedRecord.threadCount != 0) baseRecord_.threadCount = queriedRecord.threadCount;
    if (queriedRecord.handleCount != 0) baseRecord_.handleCount = queriedRecord.handleCount;
    if (queriedRecord.creationTime100ns != 0) baseRecord_.creationTime100ns = queriedRecord.creationTime100ns;
    if (queriedRecord.staticDetailsReady) baseRecord_.staticDetailsReady = true;

    identityKey_ = ks::process::buildProcessIdentityKey(
        baseRecord_.pid,
        baseRecord_.creationTime100ns);
    refreshDetailTabTexts();

    KLogEvent applyStaticDetailEvent;
    (refreshResult.queryOk ? info : warn) << applyStaticDetailEvent
        << "[ProcessDetailWindow] applyStaticDetailRefreshResult: 完成, pid="
        << baseRecord_.pid
        << ", queryOk="
        << (refreshResult.queryOk ? "true" : "false")
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << ", diagnostic="
        << refreshResult.diagnosticText.toStdString()
        << eol;
}

void ProcessDetailWindow::requestAsyncDetailOverviewRefresh()
{
    const std::uint32_t kPidValue = baseRecord_.pid;
    if (kPidValue == 0U || detailOverviewRefreshing_)
    {
        return;
    }

    detailOverviewRefreshing_ = true;
    const std::uint64_t kTicketValue = ++detailOverviewRefreshTicket_;
    const std::string kIdentityKeyValue = identityKey_;
    if (refreshDetailOverviewButton_ != nullptr)
    {
        refreshDetailOverviewButton_->setEnabled(false);
    }
    if (detailOverviewStatusLabel_ != nullptr)
    {
        detailOverviewStatusLabel_->setText(ks::i18n::text(
            QStringLiteral("process.detail.status.loading"),
            QStringLiteral("● 正在读取运行时详细数据...")));
        detailOverviewStatusLabel_->setStyleSheet(
            buildStateLabelStyle(ksword_theme::primaryBlueColor, 700));
    }

    QPointer<ProcessDetailWindow> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, kPidValue, kIdentityKeyValue, kTicketValue]() {
        DetailOverviewRefreshResult refreshResult{};
        refreshResult.identityKey = kIdentityKeyValue;
        const auto kBeginTime = std::chrono::steady_clock::now();
        const auto kPutValue = [&refreshResult](const QString& key, const QString& value) {
            refreshResult.values.insert(key, value.trimmed().isEmpty() ? detailUnavailableText() : value);
        };

        kPutValue(QStringLiteral("gui_top_level_windows"), QString::number(detailTopLevelWindowCount(kPidValue)));
        const QString kDesktopText = detailThreadDesktopText(kPidValue);
        kPutValue(QStringLiteral("thread_desktop"), kDesktopText);

        DWORD sessionId = 0;
        if (::ProcessIdToSessionId(kPidValue, &sessionId) != FALSE)
        {
            kPutValue(QStringLiteral("window_station"),
                kDesktopText == detailUnavailableText()
                    ? QStringLiteral("Session %1 (not available)").arg(sessionId)
                    : QStringLiteral("WinSta0 (inferred, session %1)").arg(sessionId));
        }
        else
        {
            kPutValue(QStringLiteral("window_station"), detailUnavailableText());
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            kPidValue);
        if (processHandle == nullptr)
        {
            processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, kPidValue);
        }

        if (processHandle == nullptr)
        {
            refreshResult.diagnosticText = QStringLiteral("OpenProcess failed (%1)").arg(::GetLastError());
        }
        else
        {
            PROCESS_MEMORY_COUNTERS_EX memoryCounters{};
            if (::GetProcessMemoryInfo(
                processHandle,
                reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&memoryCounters),
                sizeof(memoryCounters)) != FALSE)
            {
                kPutValue(QStringLiteral("peak_working_set"), detailBytesText(memoryCounters.PeakWorkingSetSize));
                kPutValue(QStringLiteral("page_faults"), QString::number(memoryCounters.PageFaultCount));
                refreshResult.queryOk = true;
            }

            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime) != FALSE)
            {
                ULARGE_INTEGER kernelTimeValue{};
                kernelTimeValue.LowPart = kernelTime.dwLowDateTime;
                kernelTimeValue.HighPart = kernelTime.dwHighDateTime;
                ULARGE_INTEGER userTimeValue{};
                userTimeValue.LowPart = userTime.dwLowDateTime;
                userTimeValue.HighPart = userTime.dwHighDateTime;
                kPutValue(QStringLiteral("kernel_cpu_time"), detailDurationText(kernelTimeValue.QuadPart));
                kPutValue(QStringLiteral("user_cpu_time"), detailDurationText(userTimeValue.QuadPart));
                refreshResult.queryOk = true;
            }

            IO_COUNTERS ioCounters{};
            if (::GetProcessIoCounters(processHandle, &ioCounters) != FALSE)
            {
                kPutValue(QStringLiteral("io_read_ops"), QString::number(static_cast<qulonglong>(ioCounters.ReadOperationCount)));
                kPutValue(QStringLiteral("io_write_ops"), QString::number(static_cast<qulonglong>(ioCounters.WriteOperationCount)));
                kPutValue(QStringLiteral("io_other_ops"), QString::number(static_cast<qulonglong>(ioCounters.OtherOperationCount)));
                kPutValue(QStringLiteral("io_read_bytes"), detailBytesText(ioCounters.ReadTransferCount));
                kPutValue(QStringLiteral("io_write_bytes"), detailBytesText(ioCounters.WriteTransferCount));
                kPutValue(QStringLiteral("io_other_bytes"), detailBytesText(ioCounters.OtherTransferCount));
                refreshResult.queryOk = true;
            }

            ULONG_PTR processAffinity = 0;
            ULONG_PTR systemAffinity = 0;
            if (::GetProcessAffinityMask(processHandle, &processAffinity, &systemAffinity) != FALSE)
            {
                kPutValue(QStringLiteral("cpu_affinity"), detailAffinityText(processAffinity));
                refreshResult.queryOk = true;
            }

            kPutValue(QStringLiteral("gdi_objects"), QString::number(::GetGuiResources(processHandle, GR_GDIOBJECTS)));
            kPutValue(QStringLiteral("user_objects"), QString::number(::GetGuiResources(processHandle, GR_USEROBJECTS)));

            BOOL inJobObject = FALSE;
            if (::IsProcessInJob(processHandle, nullptr, &inJobObject) != FALSE)
            {
                kPutValue(QStringLiteral("job_object"), detailBoolText(inJobObject != FALSE));
                refreshResult.queryOk = true;
            }

            HANDLE tokenHandle = nullptr;
            if (::OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) != FALSE)
            {
                std::vector<std::uint8_t> tokenBuffer;
                if (detailReadTokenInformation(tokenHandle, TokenIntegrityLevel, tokenBuffer) &&
                    tokenBuffer.size() >= sizeof(TOKEN_MANDATORY_LABEL))
                {
                    const auto* mandatoryLabel = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(tokenBuffer.data());
                    DWORD integrityRid = 0;
                    if (mandatoryLabel->Label.Sid != nullptr &&
                        *::GetSidSubAuthorityCount(mandatoryLabel->Label.Sid) > 0)
                    {
                        integrityRid = *::GetSidSubAuthority(
                            mandatoryLabel->Label.Sid,
                            *::GetSidSubAuthorityCount(mandatoryLabel->Label.Sid) - 1);
                    }
                    kPutValue(QStringLiteral("integrity_level"), detailIntegrityText(integrityRid));
                }

                TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
                DWORD returnedBytes = 0;
                if (::GetTokenInformation(
                    tokenHandle,
                    TokenElevationType,
                    &elevationType,
                    sizeof(elevationType),
                    &returnedBytes) != FALSE)
                {
                    kPutValue(QStringLiteral("elevation_type"), detailElevationTypeText(elevationType));
                }

                DWORD appContainerValue = 0;
                if (::GetTokenInformation(
                    tokenHandle,
                    TokenIsAppContainer,
                    &appContainerValue,
                    sizeof(appContainerValue),
                    &returnedBytes) != FALSE)
                {
                    kPutValue(QStringLiteral("app_container"), detailBoolText(appContainerValue != 0U));
                }

                DWORD virtualizationValue = 0;
                if (::GetTokenInformation(
                    tokenHandle,
                    TokenVirtualizationEnabled,
                    &virtualizationValue,
                    sizeof(virtualizationValue),
                    &returnedBytes) != FALSE)
                {
                    kPutValue(QStringLiteral("token_virtualization"), detailBoolText(virtualizationValue != 0U));
                }
                ::CloseHandle(tokenHandle);
                refreshResult.queryOk = true;
            }

            HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
            const NtQueryInformationProcessFn kNtQueryProcess = reinterpret_cast<NtQueryInformationProcessFn>(
                ntdllModule != nullptr ? ::GetProcAddress(ntdllModule, "NtQueryInformationProcess") : nullptr);
            ULONG_PTR debugPort = 0;
            if (detailQueryNtProcessInformation(kNtQueryProcess, processHandle, kProcessInfoClassDebugPort, debugPort))
            {
                kPutValue(
                    QStringLiteral("debug_port"),
                    debugPort == 0U
                        ? QStringLiteral("None")
                        : QStringLiteral("Attached (0x%1)")
                            .arg(static_cast<qulonglong>(debugPort), 0, 16)
                            .toUpper());
            }
            ULONG criticalValue = 0;
            if (detailQueryNtProcessInformation(kNtQueryProcess, processHandle, kProcessInfoClassBreakOnTermination, criticalValue))
            {
                kPutValue(QStringLiteral("critical_process"), detailBoolText(criticalValue != 0U));
            }
            ULONG subsystemType = 0;
            if (detailQueryNtProcessInformation(kNtQueryProcess, processHandle, kProcessInfoClassSubsystem, subsystemType))
            {
                kPutValue(QStringLiteral("subsystem"), detailSubsystemText(subsystemType));
            }

            PROCESS_MITIGATION_DEP_POLICY depPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessDEPPolicy, &depPolicy, sizeof(depPolicy)) != FALSE)
            {
                kPutValue(QStringLiteral("mitigation_dep"),
                    depPolicy.Enable != 0U
                        ? (depPolicy.Permanent != FALSE ? QStringLiteral("Enabled (permanent)") : QStringLiteral("Enabled"))
                        : QStringLiteral("Disabled"));
            }
            PROCESS_MITIGATION_ASLR_POLICY aslrPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy)) != FALSE)
            {
                QStringList enabledModes;
                if (aslrPolicy.EnableBottomUpRandomization != 0U) enabledModes << QStringLiteral("Bottom-up");
                if (aslrPolicy.EnableForceRelocateImages != 0U) enabledModes << QStringLiteral("Force relocate");
                if (aslrPolicy.EnableHighEntropy != 0U) enabledModes << QStringLiteral("High entropy");
                if (aslrPolicy.DisallowStrippedImages != 0U) enabledModes << QStringLiteral("Disallow stripped images");
                kPutValue(QStringLiteral("mitigation_aslr"), enabledModes.isEmpty() ? QStringLiteral("Disabled") : enabledModes.join(QStringLiteral(", ")));
            }
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessControlFlowGuardPolicy, &cfgPolicy, sizeof(cfgPolicy)) != FALSE)
            {
                QStringList enabledModes;
                if (cfgPolicy.EnableControlFlowGuard != 0U) enabledModes << QStringLiteral("CFG");
                if (cfgPolicy.EnableExportSuppression != 0U) enabledModes << QStringLiteral("Export suppression");
                if (cfgPolicy.StrictMode != 0U) enabledModes << QStringLiteral("Strict mode");
                if (cfgPolicy.EnableXfg != 0U) enabledModes << QStringLiteral("XFG");
                kPutValue(QStringLiteral("mitigation_cfg"), enabledModes.isEmpty() ? QStringLiteral("Disabled") : enabledModes.join(QStringLiteral(", ")));
            }
            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessDynamicCodePolicy, &dynamicCodePolicy, sizeof(dynamicCodePolicy)) != FALSE)
            {
                QStringList enabledModes;
                if (dynamicCodePolicy.ProhibitDynamicCode != 0U) enabledModes << QStringLiteral("Prohibit dynamic code");
                if (dynamicCodePolicy.AllowThreadOptOut != 0U) enabledModes << QStringLiteral("Allow thread opt-out");
                if (dynamicCodePolicy.AllowRemoteDowngrade != 0U) enabledModes << QStringLiteral("Allow remote downgrade");
                kPutValue(QStringLiteral("mitigation_dynamic_code"), enabledModes.isEmpty() ? QStringLiteral("Disabled") : enabledModes.join(QStringLiteral(", ")));
            }
            PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionPointPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessExtensionPointDisablePolicy, &extensionPointPolicy, sizeof(extensionPointPolicy)) != FALSE)
            {
                kPutValue(QStringLiteral("mitigation_extension_points"), detailBoolText(extensionPointPolicy.DisableExtensionPoints != 0U));
            }
            PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessImageLoadPolicy, &imageLoadPolicy, sizeof(imageLoadPolicy)) != FALSE)
            {
                QStringList enabledModes;
                if (imageLoadPolicy.NoRemoteImages != 0U) enabledModes << QStringLiteral("No remote images");
                if (imageLoadPolicy.NoLowMandatoryLabelImages != 0U) enabledModes << QStringLiteral("No low-label images");
                if (imageLoadPolicy.PreferSystem32Images != 0U) enabledModes << QStringLiteral("Prefer System32");
                kPutValue(QStringLiteral("mitigation_image_load"), enabledModes.isEmpty() ? QStringLiteral("Disabled") : enabledModes.join(QStringLiteral(", ")));
            }
            PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strictHandlePolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessStrictHandleCheckPolicy, &strictHandlePolicy, sizeof(strictHandlePolicy)) != FALSE)
            {
                kPutValue(QStringLiteral("mitigation_strict_handles"), detailBoolText(strictHandlePolicy.RaiseExceptionOnInvalidHandleReference != 0U));
            }
            PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY systemCallPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessSystemCallDisablePolicy, &systemCallPolicy, sizeof(systemCallPolicy)) != FALSE)
            {
                kPutValue(QStringLiteral("mitigation_win32k"), detailBoolText(systemCallPolicy.DisallowWin32kSystemCalls != 0U));
            }
            PROCESS_MITIGATION_CHILD_PROCESS_POLICY childProcessPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessChildProcessPolicy, &childProcessPolicy, sizeof(childProcessPolicy)) != FALSE)
            {
                kPutValue(QStringLiteral("mitigation_child_process"), detailBoolText(childProcessPolicy.NoChildProcessCreation != 0U));
            }
            PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY shadowStackPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessUserShadowStackPolicy, &shadowStackPolicy, sizeof(shadowStackPolicy)) != FALSE)
            {
                kPutValue(QStringLiteral("mitigation_shadow_stack"), detailBoolText(shadowStackPolicy.EnableUserShadowStack != 0U));
            }

            ::CloseHandle(processHandle);
        }

        std::uint32_t protectionLevel = 0;
        std::string protectionText;
        if (ks::process::queryProcessProtectionLevelByPid(
            kPidValue,
            &protectionLevel,
            &protectionText,
            nullptr))
        {
            kPutValue(QStringLiteral("ppl_protection"), QString::fromStdString(protectionText));
            refreshResult.queryOk = true;
        }

        refreshResult.elapsedMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kBeginTime).count());
        QMetaObject::invokeMethod(
            guardThis,
            [guardThis, refreshResult, kTicketValue]() {
                if (guardThis == nullptr || guardThis->detailOverviewRefreshTicket_ != kTicketValue)
                {
                    return;
                }
                guardThis->applyDetailOverviewRefreshResult(refreshResult);
            },
            Qt::QueuedConnection);
    });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyDetailOverviewRefreshResult(const DetailOverviewRefreshResult& refreshResult)
{
    detailOverviewRefreshing_ = false;
    if (refreshResult.identityKey != identityKey_)
    {
        return;
    }

    detailOverviewResult_ = refreshResult;
    if (refreshDetailOverviewButton_ != nullptr)
    {
        refreshDetailOverviewButton_->setEnabled(baseRecord_.pid != 0U);
    }
    if (detailOverviewStatusLabel_ != nullptr)
    {
        const QString kStatusText = refreshResult.queryOk
            ? ks::i18n::text(
                QStringLiteral("process.detail.status.completed"),
                QStringLiteral("● 运行时详细数据已刷新 %1 ms")).arg(refreshResult.elapsedMs)
            : ks::i18n::text(
                QStringLiteral("process.detail.status.failed"),
                QStringLiteral("● 运行时详细数据不可用：%1"))
                .arg(refreshResult.diagnosticText.isEmpty() ? detailUnavailableText() : refreshResult.diagnosticText);
        detailOverviewStatusLabel_->setText(kStatusText);
        detailOverviewStatusLabel_->setStyleSheet(buildStateLabelStyle(
            refreshResult.queryOk ? signatureTrustedColor() : signatureUntrustedColor(),
            700));
    }
    refreshDetailTabTexts();
}

void ProcessDetailWindow::initializeDetailTab()
{
    // Detail page initialization log: confirms the start of building the detail information panel.
    KLogEvent initDetailTabEvent;
    info << initDetailTabEvent
        << "[ProcessDetailWindow] initializeDetailTab: 构建详细信息页面。"
        << eol;

    auto& languageManager = ks::i18n::LanguageManager::instance();
    auto configureCopyableLabel = [&languageManager](QLabel* label) {
        if (label == nullptr)
        {
            return;
        }
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(label, &QWidget::customContextMenuRequested, label,
            [label, &languageManager](const QPoint& localPosition) {
                QMenu menu(label);
                QAction* copyAction = menu.addAction(languageManager.text(
                    QStringLiteral("process.detail.action.copy"),
                    QStringLiteral("复制")));
                if (menu.exec(label->mapToGlobal(localPosition)) == copyAction &&
                    QApplication::clipboard() != nullptr)
                {
                    QApplication::clipboard()->setText(label->text());
                }
            });
    };
    auto createValueLabel = [&configureCopyableLabel](QWidget* parent) {
        auto* valueLabel = new QLabel(QStringLiteral("-"), parent);
        valueLabel->setWordWrap(true);
        valueLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        configureCopyableLabel(valueLabel);
        return valueLabel;
    };
    auto configureFormLayout = [](QFormLayout* formLayout) {
        formLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        formLayout->setHorizontalSpacing(18);
        formLayout->setVerticalSpacing(6);
        formLayout->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
    };
    auto addFixedRow = [&languageManager, &configureCopyableLabel](
        QFormLayout* formLayout,
        QWidget* parent,
        const QString& translationKey,
        const QString& fallbackText,
        QLabel* valueLabel) {
            auto* nameLabel = new QLabel(parent);
            configureCopyableLabel(nameLabel);
            languageManager.bindText(nameLabel, translationKey, fallbackText);
            formLayout->addRow(nameLabel, valueLabel);
        };
    auto addExtraRow = [this, &languageManager, &configureCopyableLabel, &createValueLabel](
        QFormLayout* formLayout,
        QWidget* parent,
        const QString& valueKey,
        const QString& translationKey,
        const QString& fallbackText) {
            auto* nameLabel = new QLabel(parent);
            configureCopyableLabel(nameLabel);
            languageManager.bindText(nameLabel, translationKey, fallbackText);
            QLabel* valueLabel = createValueLabel(parent);
            detailExtraValues_.insert(valueKey, valueLabel);
            formLayout->addRow(nameLabel, valueLabel);
        };

    // The detail page has many fields; changed to a vertically scrollable content area so the window size does not squeeze the left navigation when constrained.
    auto* outerLayout = new QVBoxLayout(detailTab_);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    auto* detailScrollArea = new QScrollArea(detailTab_);
    detailScrollArea->setWidgetResizable(true);
    detailScrollArea->setFrameShape(QFrame::NoFrame);
    auto* detailContent = new QWidget(detailScrollArea);
    detailScrollArea->setWidget(detailContent);
    outerLayout->addWidget(detailScrollArea);

    detailLayout_ = new QVBoxLayout(detailContent);
    detailLayout_->setContentsMargins(8, 8, 8, 8);
    detailLayout_->setSpacing(8);

    // Top: 40px icon + process name and PID.
    QHBoxLayout* titleLayout = new QHBoxLayout();
    processIconLabel_ = new QLabel(detailContent);
    processIconLabel_->setFixedSize(40, 40);
    processTitleLabel_ = new QLabel(detailContent);
    processTitleLabel_->setStyleSheet(
        QStringLiteral("font-size:18px; font-weight:700; color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    configureCopyableLabel(processTitleLabel_);
    titleLayout->addWidget(processIconLabel_, 0, Qt::AlignTop);
    titleLayout->addWidget(processTitleLabel_, 1);
    titleLayout->addStretch(1);
    detailLayout_->addLayout(titleLayout);

    // Path row: Read-only input field with copy, open folder, and entry to the existing file details window.
    QHBoxLayout* pathLayout = new QHBoxLayout();
    auto* pathLabel = new QLabel(detailContent);
    languageManager.bindText(pathLabel, QStringLiteral("process.detail.label.image_path"), QStringLiteral("程序路径:"));
    configureCopyableLabel(pathLabel);
    pathLayout->addWidget(pathLabel);
    pathLineEdit_ = new QLineEdit(detailContent);
    pathLineEdit_->setReadOnly(true);
    copyPathButton_ = new QPushButton(QIcon(":/Icon/process_copy_cell.svg"), QString(), detailContent);
    openPathFolderButton_ = new QPushButton(QIcon(":/Icon/process_open_folder.svg"), QString(), detailContent);
    openFileDetailButton_ = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), detailContent);
    languageManager.bindText(copyPathButton_, QStringLiteral("process.detail.action.copy"), QStringLiteral("复制"));
    languageManager.bindText(openPathFolderButton_, QStringLiteral("process.detail.action.open_folder"), QStringLiteral("打开文件夹"));
    languageManager.bindText(openFileDetailButton_, QStringLiteral("process.detail.action.open_file_detail"), QStringLiteral("转到文件详细信息"));
    pathLayout->addWidget(pathLineEdit_, 1);
    pathLayout->addWidget(copyPathButton_);
    pathLayout->addWidget(openPathFolderButton_);
    pathLayout->addWidget(openFileDetailButton_);
    detailLayout_->addLayout(pathLayout);

    // Command line: read-only input box + copy.
    QHBoxLayout* commandLayout = new QHBoxLayout();
    auto* commandLabel = new QLabel(detailContent);
    languageManager.bindText(commandLabel, QStringLiteral("process.detail.label.command_line"), QStringLiteral("启动命令行:"));
    configureCopyableLabel(commandLabel);
    commandLayout->addWidget(commandLabel);
    commandLineEdit_ = new QLineEdit(detailContent);
    commandLineEdit_->setReadOnly(true);
    copyCommandButton_ = new QPushButton(QIcon(":/Icon/process_copy_cell.svg"), QString(), detailContent);
    languageManager.bindText(copyCommandButton_, QStringLiteral("process.detail.action.copy"), QStringLiteral("复制"));
    commandLayout->addWidget(commandLineEdit_, 1);
    commandLayout->addWidget(copyCommandButton_);
    detailLayout_->addLayout(commandLayout);

    // Parent process row: 20px icon + name PID + 'Go to parent process' button (shown if it exists).
    QHBoxLayout* parentLayout = new QHBoxLayout();
    auto* parentLabel = new QLabel(detailContent);
    languageManager.bindText(parentLabel, QStringLiteral("process.detail.label.parent_process"), QStringLiteral("父进程:"));
    configureCopyableLabel(parentLabel);
    parentIconLabel_ = new QLabel(detailContent);
    parentIconLabel_->setFixedSize(20, 20);
    parentInfoLabel_ = new QLabel(detailContent);
    parentInfoLabel_->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(ksword_theme::textSecondaryHex()));
    configureCopyableLabel(parentInfoLabel_);
    detailOpenHandleDockButton_ = new QPushButton(QIcon(":/Icon/process_list.svg"), QString(), detailContent);
    detailOpenHandleDockButton_->setToolTip(QStringLiteral("跳转到句柄 Dock，并按当前 PID 过滤"));
    ksword_theme::applyCompactIconButtonMetrics(detailOpenHandleDockButton_);
    gotoParentButton_ = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), detailContent);
    languageManager.bindText(gotoParentButton_, QStringLiteral("process.detail.action.goto_parent"), QStringLiteral("转到父进程"));
    gotoParentButton_->setVisible(false);
    parentLayout->addWidget(parentLabel);
    parentLayout->addWidget(parentIconLabel_);
    parentLayout->addWidget(parentInfoLabel_, 1);
    parentLayout->addWidget(detailOpenHandleDockButton_);
    parentLayout->addWidget(gotoParentButton_);
    detailLayout_->addLayout(parentLayout);

    QHBoxLayout* detailActionLayout = new QHBoxLayout();
    refreshDetailOverviewButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), detailContent);
    languageManager.bindText(refreshDetailOverviewButton_, QStringLiteral("process.detail.action.refresh"), QStringLiteral("刷新运行时详细数据"));
    detailOverviewStatusLabel_ = new QLabel(detailContent);
    languageManager.bindText(detailOverviewStatusLabel_, QStringLiteral("process.detail.status.waiting"), QStringLiteral("● 等待读取运行时详细数据"));
    configureCopyableLabel(detailOverviewStatusLabel_);
    detailActionLayout->addWidget(refreshDetailOverviewButton_);
    detailActionLayout->addWidget(detailOverviewStatusLabel_, 1);
    detailLayout_->addLayout(detailActionLayout);

    // Overview and Resources: Basic snapshots and high-frequency performance metrics are grouped together for easier routine troubleshooting.
    auto* overviewGroup = new QGroupBox(detailContent);
    languageManager.bindText(overviewGroup, QStringLiteral("process.detail.group.overview_resource"), QStringLiteral("概览与资源"));
    auto* overviewGrid = new QGridLayout(overviewGroup);
    auto* overviewLeftForm = new QFormLayout();
    auto* overviewRightForm = new QFormLayout();
    configureFormLayout(overviewLeftForm);
    configureFormLayout(overviewRightForm);
    overviewGrid->addLayout(overviewLeftForm, 0, 0);
    overviewGrid->addLayout(overviewRightForm, 0, 1);
    overviewGrid->setColumnStretch(0, 1);
    overviewGrid->setColumnStretch(1, 1);

    detailStartTimeValue_ = createValueLabel(overviewGroup);
    detailUserValue_ = createValueLabel(overviewGroup);
    detailAdminValue_ = createValueLabel(overviewGroup);
    detailArchitectureValue_ = createValueLabel(overviewGroup);
    detailPriorityValue_ = createValueLabel(overviewGroup);
    detailSessionValue_ = createValueLabel(overviewGroup);
    detailThreadCountValue_ = createValueLabel(overviewGroup);
    detailHandleCountValue_ = createValueLabel(overviewGroup);
    detailCpuValue_ = createValueLabel(overviewGroup);
    detailCpuCoreValue_ = createValueLabel(overviewGroup);
    detailRamValue_ = createValueLabel(overviewGroup);
    detailDiskValue_ = createValueLabel(overviewGroup);
    detailSignatureValue_ = createValueLabel(overviewGroup);

    addExtraRow(overviewLeftForm, overviewGroup, QStringLiteral("pid"), QStringLiteral("process.detail.field.pid"), QStringLiteral("PID"));
    addExtraRow(overviewLeftForm, overviewGroup, QStringLiteral("parent_pid"), QStringLiteral("process.detail.field.parent_pid"), QStringLiteral("父 PID"));
    addFixedRow(overviewLeftForm, overviewGroup, QStringLiteral("process.detail.field.start_time"), QStringLiteral("启动时间"), detailStartTimeValue_);
    addExtraRow(overviewLeftForm, overviewGroup, QStringLiteral("uptime"), QStringLiteral("process.detail.field.uptime"), QStringLiteral("运行时长"));
    addFixedRow(overviewLeftForm, overviewGroup, QStringLiteral("process.detail.field.user"), QStringLiteral("用户"), detailUserValue_);
    addFixedRow(overviewLeftForm, overviewGroup, QStringLiteral("process.detail.field.admin"), QStringLiteral("管理员"), detailAdminValue_);
    addExtraRow(overviewLeftForm, overviewGroup, QStringLiteral("integrity_level"), QStringLiteral("process.detail.field.integrity"), QStringLiteral("完整性级别"));
    addExtraRow(overviewLeftForm, overviewGroup, QStringLiteral("elevation_type"), QStringLiteral("process.detail.field.elevation_type"), QStringLiteral("提升类型"));
    addFixedRow(overviewLeftForm, overviewGroup, QStringLiteral("process.detail.field.architecture"), QStringLiteral("架构"), detailArchitectureValue_);
    addFixedRow(overviewLeftForm, overviewGroup, QStringLiteral("process.detail.field.session_id"), QStringLiteral("Session ID"), detailSessionValue_);

    addFixedRow(overviewRightForm, overviewGroup, QStringLiteral("process.detail.field.priority"), QStringLiteral("优先级"), detailPriorityValue_);
    addFixedRow(overviewRightForm, overviewGroup, QStringLiteral("process.detail.field.cpu"), QStringLiteral("CPU 占用"), detailCpuValue_);
    addFixedRow(overviewRightForm, overviewGroup, QStringLiteral("process.detail.field.cpu_core"), QStringLiteral("CPU 单核等效"), detailCpuCoreValue_);
    addExtraRow(overviewRightForm, overviewGroup, QStringLiteral("gpu"), QStringLiteral("process.detail.field.gpu"), QStringLiteral("GPU 占用"));
    addFixedRow(overviewRightForm, overviewGroup, QStringLiteral("process.detail.field.disk"), QStringLiteral("DISK 吞吐"), detailDiskValue_);
    addExtraRow(overviewRightForm, overviewGroup, QStringLiteral("network_rx"), QStringLiteral("process.detail.field.network_rx"), QStringLiteral("网络下行"));
    addExtraRow(overviewRightForm, overviewGroup, QStringLiteral("network_tx"), QStringLiteral("process.detail.field.network_tx"), QStringLiteral("网络上行"));
    addFixedRow(overviewRightForm, overviewGroup, QStringLiteral("process.detail.field.thread_count"), QStringLiteral("线程数量"), detailThreadCountValue_);
    addFixedRow(overviewRightForm, overviewGroup, QStringLiteral("process.detail.field.handle_count"), QStringLiteral("句柄数量"), detailHandleCountValue_);
    addExtraRow(overviewRightForm, overviewGroup, QStringLiteral("working_set"), QStringLiteral("process.detail.field.working_set"), QStringLiteral("工作集"));
    addExtraRow(overviewRightForm, overviewGroup, QStringLiteral("private_commit"), QStringLiteral("process.detail.field.private_commit"), QStringLiteral("私有提交"));
    addExtraRow(overviewRightForm, overviewGroup, QStringLiteral("peak_working_set"), QStringLiteral("process.detail.field.peak_working_set"), QStringLiteral("峰值工作集"));
    addExtraRow(overviewRightForm, overviewGroup, QStringLiteral("page_faults"), QStringLiteral("process.detail.field.page_faults"), QStringLiteral("页错误"));
    addFixedRow(overviewRightForm, overviewGroup, QStringLiteral("process.detail.field.signature"), QStringLiteral("数字签名"), detailSignatureValue_);
    detailLayout_->addWidget(overviewGroup);

    // I/O and GUI resources: Retains cumulative counts and object usage to facilitate detection of abnormal resource leaks.
    auto* ioGroup = new QGroupBox(detailContent);
    languageManager.bindText(ioGroup, QStringLiteral("process.detail.group.io_gui"), QStringLiteral("I/O 与 GUI 资源"));
    auto* ioGrid = new QGridLayout(ioGroup);
    auto* ioLeftForm = new QFormLayout();
    auto* ioRightForm = new QFormLayout();
    configureFormLayout(ioLeftForm);
    configureFormLayout(ioRightForm);
    ioGrid->addLayout(ioLeftForm, 0, 0);
    ioGrid->addLayout(ioRightForm, 0, 1);
    ioGrid->setColumnStretch(0, 1);
    ioGrid->setColumnStretch(1, 1);
    addExtraRow(ioLeftForm, ioGroup, QStringLiteral("io_read_ops"), QStringLiteral("process.detail.field.io_read_ops"), QStringLiteral("读取操作"));
    addExtraRow(ioLeftForm, ioGroup, QStringLiteral("io_write_ops"), QStringLiteral("process.detail.field.io_write_ops"), QStringLiteral("写入操作"));
    addExtraRow(ioLeftForm, ioGroup, QStringLiteral("io_other_ops"), QStringLiteral("process.detail.field.io_other_ops"), QStringLiteral("其他 I/O 操作"));
    addExtraRow(ioLeftForm, ioGroup, QStringLiteral("io_read_bytes"), QStringLiteral("process.detail.field.io_read_bytes"), QStringLiteral("读取字节"));
    addExtraRow(ioLeftForm, ioGroup, QStringLiteral("io_write_bytes"), QStringLiteral("process.detail.field.io_write_bytes"), QStringLiteral("写入字节"));
    addExtraRow(ioLeftForm, ioGroup, QStringLiteral("io_other_bytes"), QStringLiteral("process.detail.field.io_other_bytes"), QStringLiteral("其他 I/O 字节"));
    addExtraRow(ioLeftForm, ioGroup, QStringLiteral("kernel_cpu_time"), QStringLiteral("process.detail.field.kernel_cpu_time"), QStringLiteral("内核 CPU 时间"));
    addExtraRow(ioLeftForm, ioGroup, QStringLiteral("user_cpu_time"), QStringLiteral("process.detail.field.user_cpu_time"), QStringLiteral("用户 CPU 时间"));
    addExtraRow(ioRightForm, ioGroup, QStringLiteral("gdi_objects"), QStringLiteral("process.detail.field.gdi_objects"), QStringLiteral("GDI 对象"));
    addExtraRow(ioRightForm, ioGroup, QStringLiteral("user_objects"), QStringLiteral("process.detail.field.user_objects"), QStringLiteral("USER 对象"));
    addExtraRow(ioRightForm, ioGroup, QStringLiteral("gui_top_level_windows"), QStringLiteral("process.detail.field.top_level_windows"), QStringLiteral("顶层窗口"));
    addExtraRow(ioRightForm, ioGroup, QStringLiteral("job_object"), QStringLiteral("process.detail.field.job_object"), QStringLiteral("Job 对象"));
    detailLayout_->addWidget(ioGroup);

    // Runtime environment: CPU scheduling, subsystem, and GUI session context.
    auto* environmentGroup = new QGroupBox(detailContent);
    languageManager.bindText(environmentGroup, QStringLiteral("process.detail.group.runtime_environment"), QStringLiteral("运行环境"));
    auto* environmentForm = new QFormLayout(environmentGroup);
    configureFormLayout(environmentForm);
    addExtraRow(environmentForm, environmentGroup, QStringLiteral("cpu_affinity"), QStringLiteral("process.detail.field.cpu_affinity"), QStringLiteral("CPU 亲和性"));
    addExtraRow(environmentForm, environmentGroup, QStringLiteral("efficiency_mode"), QStringLiteral("process.detail.field.efficiency_mode"), QStringLiteral("效率模式"));
    addExtraRow(environmentForm, environmentGroup, QStringLiteral("subsystem"), QStringLiteral("process.detail.field.subsystem"), QStringLiteral("子系统"));
    addExtraRow(environmentForm, environmentGroup, QStringLiteral("thread_desktop"), QStringLiteral("process.detail.field.thread_desktop"), QStringLiteral("线程桌面"));
    addExtraRow(environmentForm, environmentGroup, QStringLiteral("window_station"), QStringLiteral("process.detail.field.window_station"), QStringLiteral("窗口站"));
    detailLayout_->addWidget(environmentGroup);

    // Security status: Token, PPL, debug status, and exposed process mitigation policies are displayed separately.
    auto* securityGroup = new QGroupBox(detailContent);
    languageManager.bindText(securityGroup, QStringLiteral("process.detail.group.security"), QStringLiteral("安全状态与缓解策略"));
    auto* securityGrid = new QGridLayout(securityGroup);
    auto* securityLeftForm = new QFormLayout();
    auto* securityRightForm = new QFormLayout();
    configureFormLayout(securityLeftForm);
    configureFormLayout(securityRightForm);
    securityGrid->addLayout(securityLeftForm, 0, 0);
    securityGrid->addLayout(securityRightForm, 0, 1);
    securityGrid->setColumnStretch(0, 1);
    securityGrid->setColumnStretch(1, 1);
    addExtraRow(securityLeftForm, securityGroup, QStringLiteral("ppl_protection"), QStringLiteral("process.detail.field.ppl"), QStringLiteral("PPL 保护级别"));
    addExtraRow(securityLeftForm, securityGroup, QStringLiteral("critical_process"), QStringLiteral("process.detail.field.critical"), QStringLiteral("关键进程"));
    addExtraRow(securityLeftForm, securityGroup, QStringLiteral("debug_port"), QStringLiteral("process.detail.field.debug_port"), QStringLiteral("调试端口"));
    addExtraRow(securityLeftForm, securityGroup, QStringLiteral("app_container"), QStringLiteral("process.detail.field.app_container"), QStringLiteral("AppContainer"));
    addExtraRow(securityLeftForm, securityGroup, QStringLiteral("token_virtualization"), QStringLiteral("process.detail.field.token_virtualization"), QStringLiteral("令牌虚拟化"));
    addExtraRow(securityLeftForm, securityGroup, QStringLiteral("mitigation_dep"), QStringLiteral("process.detail.field.mitigation_dep"), QStringLiteral("DEP"));
    addExtraRow(securityLeftForm, securityGroup, QStringLiteral("mitigation_aslr"), QStringLiteral("process.detail.field.mitigation_aslr"), QStringLiteral("ASLR"));
    addExtraRow(securityLeftForm, securityGroup, QStringLiteral("mitigation_cfg"), QStringLiteral("process.detail.field.mitigation_cfg"), QStringLiteral("CFG / XFG"));
    addExtraRow(securityLeftForm, securityGroup, QStringLiteral("mitigation_dynamic_code"), QStringLiteral("process.detail.field.mitigation_dynamic_code"), QStringLiteral("动态代码限制"));
    addExtraRow(securityLeftForm, securityGroup, QStringLiteral("mitigation_extension_points"), QStringLiteral("process.detail.field.mitigation_extension_points"), QStringLiteral("扩展点禁用"));
    addExtraRow(securityRightForm, securityGroup, QStringLiteral("mitigation_image_load"), QStringLiteral("process.detail.field.mitigation_image_load"), QStringLiteral("映像加载限制"));
    addExtraRow(securityRightForm, securityGroup, QStringLiteral("mitigation_strict_handles"), QStringLiteral("process.detail.field.mitigation_strict_handles"), QStringLiteral("严格句柄检查"));
    addExtraRow(securityRightForm, securityGroup, QStringLiteral("mitigation_win32k"), QStringLiteral("process.detail.field.mitigation_win32k"), QStringLiteral("Win32k 调用禁用"));
    addExtraRow(securityRightForm, securityGroup, QStringLiteral("mitigation_child_process"), QStringLiteral("process.detail.field.mitigation_child_process"), QStringLiteral("子进程创建限制"));
    addExtraRow(securityRightForm, securityGroup, QStringLiteral("mitigation_shadow_stack"), QStringLiteral("process.detail.field.mitigation_shadow_stack"), QStringLiteral("用户影子栈 (CET)"));
    detailLayout_->addWidget(securityGroup);

    detailLayout_->addStretch(1);

    const QString kButtonStyle = buildBlueButtonStyle();
    copyPathButton_->setStyleSheet(kButtonStyle);
    openPathFolderButton_->setStyleSheet(kButtonStyle);
    openFileDetailButton_->setStyleSheet(kButtonStyle);
    copyCommandButton_->setStyleSheet(kButtonStyle);
    detailOpenHandleDockButton_->setStyleSheet(buildBlueButtonStyle());
    gotoParentButton_->setStyleSheet(kButtonStyle);
    refreshDetailOverviewButton_->setStyleSheet(kButtonStyle);
}

void ProcessDetailWindow::initializePerformanceTab()
{
    auto& languageManager = ks::i18n::LanguageManager::instance();
    const auto kConfigureCopyableLabel = [&languageManager](QLabel* label) {
        if (label == nullptr)
        {
            return;
        }
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(label, &QWidget::customContextMenuRequested, label,
            [label, &languageManager](const QPoint& localPosition) {
                QMenu menu(label);
                menu.setStyleSheet(buildProcessDetailMenuStyle());
                QAction* const kCopyAction = menu.addAction(languageManager.text(
                    QStringLiteral("process.detail.action.copy"),
                    QString()));
                if (menu.exec(label->mapToGlobal(localPosition)) == kCopyAction &&
                    QApplication::clipboard() != nullptr)
                {
                    QApplication::clipboard()->setText(label->text());
                }
            });
    };
    auto* layout = new QVBoxLayout(performanceTab_);
    layout->setContentsMargins(14, 14, 14, 14);
    layout->setSpacing(8);

    auto* titleLabel = new QLabel(performanceTab_);
    titleLabel->setStyleSheet(QStringLiteral("font-size:16px; font-weight:700; color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    languageManager.bindText(titleLabel, QStringLiteral("process.detail.performance.title"), QString());
    kConfigureCopyableLabel(titleLabel);
    layout->addWidget(titleLabel);

    auto* descriptionLabel = new QLabel(performanceTab_);
    descriptionLabel->setWordWrap(true);
    descriptionLabel->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    languageManager.bindText(descriptionLabel, QStringLiteral("process.detail.performance.description"), QString());
    kConfigureCopyableLabel(descriptionLabel);
    layout->addWidget(descriptionLabel);

    performanceHistoryStatusLabel_ = new QLabel(performanceTab_);
    performanceHistoryStatusLabel_->setWordWrap(true);
    performanceHistoryStatusLabel_->setStyleSheet(buildStateLabelStyle(statusSecondaryColor(), 600));
    kConfigureCopyableLabel(performanceHistoryStatusLabel_);
    layout->addWidget(performanceHistoryStatusLabel_);

    auto* chartScrollArea = new QScrollArea(performanceTab_);
    chartScrollArea->setWidgetResizable(true);
    chartScrollArea->setFrameShape(QFrame::NoFrame);
    auto* chartContent = new QWidget(chartScrollArea);
    chartContent->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::MinimumExpanding);
    auto* chartLayout = new QVBoxLayout(chartContent);
    chartLayout->setContentsMargins(0, 0, 0, 0);
    chartLayout->setSpacing(10);
    chartLayout->setAlignment(Qt::AlignTop);

    const auto kAddChart = [&languageManager, chartContent, chartLayout](
        QWidget*& chartTarget,
        const QString& titleKey) {
        auto* group = new QGroupBox(chartContent);
        languageManager.bindText(group, titleKey, QString());
        group->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(group, &QWidget::customContextMenuRequested, group,
            [group, &languageManager](const QPoint& localPosition) {
                QMenu menu(group);
                menu.setStyleSheet(buildProcessDetailMenuStyle());
                QAction* const kCopyAction = menu.addAction(languageManager.text(
                    QStringLiteral("process.detail.action.copy"),
                    QString()));
                if (menu.exec(group->mapToGlobal(localPosition)) == kCopyAction &&
                    QApplication::clipboard() != nullptr)
                {
                    QApplication::clipboard()->setText(group->title());
                }
            });
        auto* groupLayout = new QVBoxLayout(group);
        groupLayout->setContentsMargins(9, 17, 9, 9);
        chartTarget = new ProcessPerformanceHistoryChartWidget(group);
        groupLayout->addWidget(chartTarget);
        chartLayout->addWidget(group);
    };

    kAddChart(performanceCpuChart_, QStringLiteral("process.detail.performance.chart.cpu"));
    kAddChart(performanceCpuCoreChart_, QStringLiteral("process.detail.performance.chart.cpu_core"));
    kAddChart(performanceMemoryChart_, QStringLiteral("process.detail.performance.chart.memory"));
    kAddChart(performanceDiskChart_, QStringLiteral("process.detail.performance.chart.disk"));
    kAddChart(performanceNetworkChart_, QStringLiteral("process.detail.performance.chart.network"));
    kAddChart(performanceGpuChart_, QStringLiteral("process.detail.performance.chart.gpu"));
    chartLayout->addStretch(1);
    chartScrollArea->setWidget(chartContent);
    chartScrollArea->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    layout->addWidget(chartScrollArea, 1);

    refreshPerformanceHistoryCharts();
}

void ProcessDetailWindow::refreshPerformanceHistoryCharts()
{
    if (performanceHistoryStatusLabel_ == nullptr)
    {
        return;
    }

    const auto kText = [](const QString& key) {
        return ks::i18n::text(key, QString());
    };
    if (performanceHistory_.empty())
    {
        performanceHistoryStatusLabel_->setText(kText(QStringLiteral("process.detail.performance.status.empty")));
        return;
    }

    std::vector<qint64> timestamps;
    std::vector<double> cpuValues;
    std::vector<double> cpuCoreValues;
    std::vector<double> memoryValues;
    std::vector<double> diskValues;
    std::vector<double> networkRxValues;
    std::vector<double> networkTxValues;
    std::vector<double> gpuValues;
    timestamps.reserve(performanceHistory_.size());
    cpuValues.reserve(performanceHistory_.size());
    cpuCoreValues.reserve(performanceHistory_.size());
    memoryValues.reserve(performanceHistory_.size());
    diskValues.reserve(performanceHistory_.size());
    networkRxValues.reserve(performanceHistory_.size());
    networkTxValues.reserve(performanceHistory_.size());
    gpuValues.reserve(performanceHistory_.size());
    for (const PerformanceHistorySample& sample : performanceHistory_)
    {
        timestamps.push_back(sample.unixMilliseconds);
        cpuValues.push_back(sample.cpuPercent);
        cpuCoreValues.push_back(sample.cpuCorePercent);
        memoryValues.push_back(sample.memoryMB);
        diskValues.push_back(sample.diskMBps);
        networkRxValues.push_back(sample.networkRxKBps);
        networkTxValues.push_back(sample.networkTxKBps);
        gpuValues.push_back(sample.gpuPercent);
    }

    const QString kTimeHeader = kText(QStringLiteral("process.detail.performance.header.time"));
    const QString kEmptyText = kText(QStringLiteral("process.detail.performance.chart.empty"));
    const QString kCopyLatestText = kText(QStringLiteral("process.detail.performance.action.copy_current"));
    const QString kCopyHistoryText = kText(QStringLiteral("process.detail.performance.action.copy_history"));
    const auto kSetChartData = [&timestamps, &kEmptyText, &kTimeHeader, &kCopyLatestText, &kCopyHistoryText](
        QWidget* chartWidget,
        std::vector<ProcessPerformanceHistoryChartWidget::Series> series,
        const QString& unitText,
        const double fixedMaximum) {
        auto* chart = static_cast<ProcessPerformanceHistoryChartWidget*>(chartWidget);
        if (chart == nullptr)
        {
            return;
        }
        chart->setChartData(
            timestamps,
            std::move(series),
            unitText,
            fixedMaximum,
            kEmptyText,
            kTimeHeader,
            kCopyLatestText,
            kCopyHistoryText);
    };

    kSetChartData(
        performanceCpuChart_,
        { ProcessPerformanceHistoryChartWidget::Series{
            kText(QStringLiteral("process.detail.performance.series.cpu")),
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kCpu),
            std::move(cpuValues) } },
        QStringLiteral("%"),
        100.0);
    const double kCpuCoreMaximum = cpuCoreValues.empty()
        ? 100.0
        : std::max(
            100.0,
            std::ceil(*std::max_element(cpuCoreValues.cbegin(), cpuCoreValues.cend()) / 100.0) * 100.0);
    kSetChartData(
        performanceCpuCoreChart_,
        { ProcessPerformanceHistoryChartWidget::Series{
            kText(QStringLiteral("process.detail.performance.series.cpu_core")),
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kCpu),
            std::move(cpuCoreValues) } },
        QStringLiteral("%"),
        kCpuCoreMaximum);
    kSetChartData(
        performanceMemoryChart_,
        { ProcessPerformanceHistoryChartWidget::Series{
            kText(QStringLiteral("process.detail.performance.series.memory")),
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kMemory),
            std::move(memoryValues) } },
        QStringLiteral("MB"),
        0.0);
    kSetChartData(
        performanceDiskChart_,
        { ProcessPerformanceHistoryChartWidget::Series{
            kText(QStringLiteral("process.detail.performance.series.disk")),
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kDisk),
            std::move(diskValues) } },
        QStringLiteral("MB/s"),
        0.0);
    kSetChartData(
        performanceNetworkChart_,
        {
            ProcessPerformanceHistoryChartWidget::Series{
                kText(QStringLiteral("process.detail.performance.series.network_rx")),
                ksword_theme::performanceColor(ksword_theme::PerformanceRole::kRead),
                std::move(networkRxValues) },
            ProcessPerformanceHistoryChartWidget::Series{
                kText(QStringLiteral("process.detail.performance.series.network_tx")),
                ksword_theme::performanceColor(ksword_theme::PerformanceRole::kWrite),
                std::move(networkTxValues) }
        },
        QStringLiteral("KB/s"),
        0.0);
    kSetChartData(
        performanceGpuChart_,
        { ProcessPerformanceHistoryChartWidget::Series{
            kText(QStringLiteral("process.detail.performance.series.gpu")),
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kGpu),
            std::move(gpuValues) } },
        QStringLiteral("%"),
        100.0);

    const QString kBeginTime = QDateTime::fromMSecsSinceEpoch(timestamps.front()).toString(QStringLiteral("HH:mm:ss"));
    const QString kEndTime = QDateTime::fromMSecsSinceEpoch(timestamps.back()).toString(QStringLiteral("HH:mm:ss"));
    performanceHistoryStatusLabel_->setText(
        kText(QStringLiteral("process.detail.performance.status.samples"))
            .arg(static_cast<qulonglong>(performanceHistory_.size()))
            .arg(kBeginTime)
            .arg(kEndTime));
}

void ProcessDetailWindow::initializeCpuCoreTab()
{
    auto& languageManager = ks::i18n::LanguageManager::instance();
    QVBoxLayout* layout = nullptr;
    QWidget* const kContentWidget = createScrollableTabContent(cpuCoreTab_, layout, 12, 10);
    if (kContentWidget == nullptr || layout == nullptr)
    {
        return;
    }

    cpuCoreTitleLabel_ = new QLabel(kContentWidget);
    cpuCoreTitleLabel_->setStyleSheet(QStringLiteral("font-size:16px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    languageManager.bindText(
        cpuCoreTitleLabel_,
        QStringLiteral("process.detail.cpu_core.title"),
        QStringLiteral("进程与线程 CPU 核心视图"));
    layout->addWidget(cpuCoreTitleLabel_);

    cpuCoreDescriptionLabel_ = new QLabel(kContentWidget);
    cpuCoreDescriptionLabel_->setWordWrap(true);
    cpuCoreDescriptionLabel_->setStyleSheet(QStringLiteral("color:%1;")
        .arg(ksword_theme::textSecondaryHex()));
    languageManager.bindText(
        cpuCoreDescriptionLabel_,
        QStringLiteral("process.detail.cpu_core.description"),
        QStringLiteral("基于线程上下文切换区间统计真实运行核心；单组使用 Lx，多组使用 Gx:Ly。"));
    layout->addWidget(cpuCoreDescriptionLabel_);

    cpuCoreStatusLabel_ = new QLabel(kContentWidget);
    cpuCoreStatusLabel_->setWordWrap(true);
    layout->addWidget(cpuCoreStatusLabel_);

    auto* equivalentGroup = new QGroupBox(kContentWidget);
    languageManager.bindText(
        equivalentGroup,
        QStringLiteral("process.detail.cpu_core.group.summary"),
        QStringLiteral("进程汇总"));
    auto* equivalentLayout = new QHBoxLayout(equivalentGroup);
    auto* systemTitleLabel = new QLabel(equivalentGroup);
    languageManager.bindText(
        systemTitleLabel,
        QStringLiteral("process.detail.cpu_core.summary.system"),
        QStringLiteral("CPU 占用"));
    cpuCoreSystemValueLabel_ = new QLabel(QStringLiteral("0.00%"), equivalentGroup);
    cpuCoreSystemValueLabel_->setStyleSheet(QStringLiteral("font-size:20px;font-weight:700;color:%1;")
        .arg(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue).name()));
    auto* equivalentTitleLabel = new QLabel(equivalentGroup);
    languageManager.bindText(
        equivalentTitleLabel,
        QStringLiteral("process.detail.field.cpu_core"),
        QStringLiteral("CPU 单核等效"));
    cpuCoreEquivalentValueLabel_ = new QLabel(QStringLiteral("0.00%"), equivalentGroup);
    cpuCoreEquivalentValueLabel_->setStyleSheet(QStringLiteral("font-size:20px;font-weight:700;color:%1;")
        .arg(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue).name()));
    equivalentLayout->addWidget(systemTitleLabel);
    equivalentLayout->addWidget(cpuCoreSystemValueLabel_);
    equivalentLayout->addSpacing(24);
    equivalentLayout->addWidget(equivalentTitleLabel);
    equivalentLayout->addWidget(cpuCoreEquivalentValueLabel_);
    equivalentLayout->addStretch(1);
    layout->addWidget(equivalentGroup);

    auto* processGroup = new QGroupBox(kContentWidget);
    languageManager.bindText(
        processGroup,
        QStringLiteral("process.detail.cpu_core.group.process"),
        QStringLiteral("进程逐核心占用"));
    auto* processLayout = new QVBoxLayout(processGroup);
    processLayout->setContentsMargins(8, 10, 8, 8);
    processLayout->setSpacing(0);
    processCpuCoreGrid_ = new CpuCoreUsageGridWidget(processGroup);
    processLayout->addWidget(processCpuCoreGrid_);
    layout->addWidget(processGroup);

    auto* threadGroup = new QGroupBox(kContentWidget);
    languageManager.bindText(
        threadGroup,
        QStringLiteral("process.detail.cpu_core.group.thread"),
        QStringLiteral("线程逐核心占用"));
    auto* threadLayout = new QVBoxLayout(threadGroup);
    threadLayout->setContentsMargins(8, 10, 8, 8);
    threadLayout->setSpacing(6);
    auto* threadUsageHintLabel = new QLabel(threadGroup);
    threadUsageHintLabel->setWordWrap(true);
    threadUsageHintLabel->setStyleSheet(QStringLiteral("color:%1;")
        .arg(ksword_theme::textSecondaryHex()));
    languageManager.bindText(
        threadUsageHintLabel,
        QStringLiteral("process.detail.cpu_core.thread_hint"),
        QStringLiteral("此百分比统计了线程在每个核心的占用时间（线程所在的核心可能发生跳变）（单个线程不可能同时使用多个核心）"));
    threadLayout->addWidget(threadUsageHintLabel);
    threadCpuCoreGrid_ = new CpuThreadUsageCardGridWidget(threadGroup);
    threadLayout->addWidget(threadCpuCoreGrid_);
    layout->addWidget(threadGroup);
    layout->addStretch(1);

    refreshCpuCoreView();
}

void ProcessDetailWindow::refreshCpuCoreView()
{
    if (cpuCoreStatusLabel_ == nullptr ||
        processCpuCoreGrid_ == nullptr ||
        threadCpuCoreGrid_ == nullptr)
    {
        return;
    }

    const CpuCoreViewSample& sample = cpuCoreViewSample_;
    if (cpuCoreSystemValueLabel_ != nullptr)
    {
        cpuCoreSystemValueLabel_->setText(
            QString::number(sample.processSystemPercent, 'f', 2) + QStringLiteral("%"));
    }
    if (cpuCoreEquivalentValueLabel_ != nullptr)
    {
        cpuCoreEquivalentValueLabel_->setText(
            QString::number(sample.processCoreEquivalentPercent, 'f', 2) + QStringLiteral("%"));
    }

    QString statusText;
    QColor statusColor = statusSecondaryColor();
    if (!sample.monitorRunning)
    {
        statusText = sample.diagnosticText.trimmed().isEmpty()
            ? ks::i18n::text(QStringLiteral("process.detail.cpu_core.status.unavailable"), QString())
            : ks::i18n::text(QStringLiteral("process.detail.cpu_core.status.failed"), QString())
                .arg(sample.diagnosticText);
        statusColor = ksword_theme::errorColor();
    }
    else if (!sample.sampleReady)
    {
        statusText = ks::i18n::text(QStringLiteral("process.detail.cpu_core.status.sampling"), QString());
        statusColor = ksword_theme::primaryBlueColor;
    }
    else if (sample.dataLossDetected)
    {
        statusText = ks::i18n::text(QStringLiteral("process.detail.cpu_core.status.loss"), QString())
            .arg(static_cast<qulonglong>(sample.eventsLost));
        statusColor = statusWarningColor();
    }
    else
    {
        statusText = ks::i18n::text(QStringLiteral("process.detail.cpu_core.status.ready"), QString())
            .arg(static_cast<qulonglong>(sample.contextSwitchEvents));
        statusColor = signatureTrustedColor();
    }
    cpuCoreStatusLabel_->setText(statusText);
    cpuCoreStatusLabel_->setStyleSheet(buildStateLabelStyle(statusColor, 600));

    const bool kMultipleProcessorGroups = !sample.processCores.empty() && std::any_of(
        sample.processCores.cbegin(),
        sample.processCores.cend(),
        [&sample](const CpuCoreValue& core) {
            return core.group != sample.processCores.front().group;
        });
    static_cast<CpuCoreUsageGridWidget*>(processCpuCoreGrid_)->setCoreValues(
        sample.processCores,
        kMultipleProcessorGroups);
    static_cast<CpuThreadUsageCardGridWidget*>(threadCpuCoreGrid_)->setThreadValues(
        sample.threads,
        kMultipleProcessorGroups);
}

void ProcessDetailWindow::initializeThreadTab()
{
    // Thread-page initialization log: move thread enumeration and register summary to a separate tab.
    KLogEvent initThreadTabEvent;
    info << initThreadTabEvent
        << "[ProcessDetailWindow] initializeThreadTab: 构建线程信息页面。"
        << eol;

    threadLayout_ = new QVBoxLayout(threadTab_);
    threadLayout_->setContentsMargins(6, 6, 6, 6);
    threadLayout_->setSpacing(8);

    QGroupBox* threadGroup = new QGroupBox("线程枚举与上下文摘要", threadTab_);
    QVBoxLayout* threadGroupLayout = new QVBoxLayout(threadGroup);
    threadGroupLayout->setContentsMargins(8, 8, 8, 8);
    threadGroupLayout->setSpacing(6);

    // Top toolbar:
    // - The refresh button retains explicit text to avoid ambiguity, as relying solely on the icon makes the 'thread refresh' semantics unclear.
    // - Status label on the right, continuously reporting the elapsed time for this refresh cycle and diagnostic information.
    QHBoxLayout* threadTopBarLayout = new QHBoxLayout();
    refreshThreadInspectButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), "刷新线程", threadGroup);
    refreshThreadInspectButton_->setToolTip("异步刷新线程枚举、TEB、起始地址与寄存器摘要");
    sampleThreadRuntimeButton_ = new QPushButton(QIcon(":/Icon/process_tree.svg"), "采样PDB字段", threadGroup);
    sampleThreadRuntimeButton_->setToolTip("只读采样当前选中线程的 PDB deep runtime 字段，不批量扫描全部线程");
    auto* openThreadStackButton = new QPushButton(QIcon(":/Icon/process_threads.svg"), "查看调用栈", threadGroup);
    openThreadStackButton->setToolTip("打开当前选中线程的 Phase-8 调用栈窗口");
    threadInspectStatusLabel_ = new QLabel("● 尚未刷新", threadGroup);
    threadInspectStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    threadTopBarLayout->addWidget(refreshThreadInspectButton_);
    threadTopBarLayout->addWidget(sampleThreadRuntimeButton_);
    threadTopBarLayout->addWidget(openThreadStackButton);
    threadTopBarLayout->addWidget(threadInspectStatusLabel_, 1);
    threadGroupLayout->addLayout(threadTopBarLayout);

    // Thread table:
    // - Continue using the original column definitions and refresh logic.
    // - Moves the display location from the bottom of the details page to a separate tab.
    threadInspectTable_ = new ks::ui::VisibleTableWidget(threadGroup);
    threadInspectTable_->setColumnCount(toThreadColumnIndex(ThreadRowColumn::kCount));
    threadInspectTable_->setHorizontalHeaderLabels(kThreadInspectHeaders);
    threadInspectTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    threadInspectTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    threadInspectTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    threadInspectTable_->setAlternatingRowColors(true);
    threadInspectTable_->verticalHeader()->setVisible(false);
    threadInspectTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    threadInspectTable_->horizontalHeader()->setStretchLastSection(true);
    threadInspectTable_->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::kThreadId), 96);
    threadInspectTable_->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::kState), 82);
    threadInspectTable_->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::kPriority), 72);
    threadInspectTable_->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::kSwitchCount), 96);
    threadInspectTable_->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::kStartAddress), 130);
    threadInspectTable_->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::kTebAddress), 130);
    threadInspectTable_->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::kAffinity), 108);
    threadInspectTable_->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::kStackBoundary), 260);
    threadInspectTable_->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::kRuntimeDetail), 360);
    threadInspectTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    threadGroupLayout->addWidget(threadInspectTable_, 1);

    // Current thread's deep PDB sampling details:
    // - By default, only display readable runtime details for the selected row;
    // - After clicking 'Sample PDB Fields', the thread runtime field sampler is called in the background.
    // - Use CodeEditorWidget to facilitate copying/searching long field lists.
    threadRuntimeSampleOutput_ = new CodeEditorWidget(threadGroup);
    threadRuntimeSampleOutput_->setReadOnly(true);
    threadRuntimeSampleOutput_->setMaximumHeight(220);
    threadRuntimeSampleOutput_->setText(QStringLiteral(
        "选择线程行后可查看 R0 runtime detail；点击“采样PDB字段”可按需读取 thread_detail deep JSON 小字段。"));
    threadGroupLayout->addWidget(threadRuntimeSampleOutput_, 0);

    ks::ui::DetailLayoutRegistry::registerHost(
        threadInspectTable_, threadRuntimeSampleOutput_, threadGroup);

    threadLayout_->addWidget(threadGroup, 1);

    const QString kButtonStyle = buildBlueButtonStyle();
    refreshThreadInspectButton_->setStyleSheet(kButtonStyle);
    sampleThreadRuntimeButton_->setStyleSheet(kButtonStyle);
    openThreadStackButton->setStyleSheet(kButtonStyle);
    connect(sampleThreadRuntimeButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncSelectedThreadRuntimeSample();
        });
    connect(openThreadStackButton, &QPushButton::clicked, this, [this]() {
        openSelectedThreadStackWindow();
        });
    connect(threadInspectTable_, &QTableWidget::currentCellChanged, this, [this](int currentRow, int, int, int) {
        // Selected row details:
        // - Input: Current table row;
        // - Handling: Retrieve ThreadInspectItem from cache and display a fixed detail IOCTL readable summary.
        // - Return: None. No new driver calls are executed.
        if (threadRuntimeSampleOutput_ == nullptr)
        {
            return;
        }
        if (threadInspectTable_ == nullptr || currentRow < 0)
        {
            threadRuntimeSampleOutput_->setText(QStringLiteral("请选择一条线程记录查看 runtime detail。"));
            return;
        }
        const QTableWidgetItem* threadIdItem =
            threadInspectTable_->item(currentRow, toThreadColumnIndex(ThreadRowColumn::kThreadId));
        const std::size_t kCacheIndex = threadIdItem != nullptr
            ? static_cast<std::size_t>(threadIdItem->data(Qt::UserRole).toULongLong())
            : static_cast<std::size_t>(threadInspectRows_.size());
        if (kCacheIndex >= threadInspectRows_.size())
        {
            threadRuntimeSampleOutput_->setText(QStringLiteral("当前线程行缺少缓存详情，请刷新线程页。"));
            return;
        }

        const ThreadInspectItem& rowItem = threadInspectRows_[kCacheIndex];
        const auto kThreadDetailStatusName = [](const std::uint32_t statusValue) -> QString
        {
            switch (statusValue)
            {
            case KSWORD_ARK_DETAIL_STATUS_OK:
                return QStringLiteral("OK");
            case KSWORD_ARK_DETAIL_STATUS_PARTIAL:
                return QStringLiteral("Partial");
            case KSWORD_ARK_DETAIL_STATUS_UNSUPPORTED:
                return QStringLiteral("Unsupported");
            case KSWORD_ARK_DETAIL_STATUS_LOOKUP_FAILED:
                return QStringLiteral("LookupFailed");
            case KSWORD_ARK_DETAIL_STATUS_CAPABILITY_MISSING:
                return QStringLiteral("CapabilityMissing");
            case KSWORD_ARK_DETAIL_STATUS_READ_FAILED:
                return QStringLiteral("ReadFailed");
            default:
                return QStringLiteral("Status(%1)").arg(statusValue);
            }
        };
        const auto kThreadStatusHexText = [](const long statusValue) -> QString
        {
            return QStringLiteral("0x%1")
                .arg(static_cast<quint32>(statusValue), 8, 16, QChar('0'))
                .toUpper();
        };
        QStringList detailLines;
        detailLines << QStringLiteral("[Thread Runtime Detail]");
        detailLines << QStringLiteral("TID/PID: %1/%2").arg(rowItem.threadId).arg(rowItem.processId);
        detailLines << QStringLiteral("Start/Win32Start: %1 / %2")
            .arg(uint64ToHex(rowItem.startAddress))
            .arg(uint64ToHex(rowItem.win32StartAddress));
        detailLines << QStringLiteral("TEB: %1").arg(uint64ToHex(rowItem.tebAddress));
        detailLines << QStringLiteral("R0 stack: Kernel=%1 Limit=%2 Base=%3 Initial=%4")
            .arg(uint64ToHex(rowItem.r0KernelStack))
            .arg(uint64ToHex(rowItem.r0StackLimit))
            .arg(uint64ToHex(rowItem.r0StackBase))
            .arg(uint64ToHex(rowItem.r0InitialStack));
        detailLines << QStringLiteral("I/O ops: R/W/O=%1/%2/%3")
            .arg(static_cast<qulonglong>(rowItem.r0ReadOperationCount))
            .arg(static_cast<qulonglong>(rowItem.r0WriteOperationCount))
            .arg(static_cast<qulonglong>(rowItem.r0OtherOperationCount));
        detailLines << QStringLiteral("I/O bytes: R/W/O=%1/%2/%3")
            .arg(static_cast<qulonglong>(rowItem.r0ReadTransferCount))
            .arg(static_cast<qulonglong>(rowItem.r0WriteTransferCount))
            .arg(static_cast<qulonglong>(rowItem.r0OtherTransferCount));
        detailLines << QStringLiteral("DetailStatus: %1").arg(kThreadDetailStatusName(rowItem.r0DetailStatus));
        detailLines << QStringLiteral("MissingCapability: %1")
            .arg(uint64ToHex(rowItem.r0MissingCapabilityMask));
        detailLines << QStringLiteral("LastStatus: %1").arg(kThreadStatusHexText(rowItem.r0DetailLastStatus));
        detailLines << QStringLiteral("说明: %1").arg(
            rowItem.r0RuntimeDetailText.trimmed().isEmpty()
            ? QStringLiteral("线程 runtime detail 暂不可用。")
            : rowItem.r0RuntimeDetailText);
        detailLines << QStringLiteral("\n点击“采样PDB字段”可对当前 TID 按需读取 thread_detail deep offset 小字段。");
        threadRuntimeSampleOutput_->setText(detailLines.join(QChar('\n')));
        });
    connect(threadInspectTable_, &QTableWidget::cellDoubleClicked, this, [this](int, int) {
        openSelectedThreadStackWindow();
    });
    connect(threadInspectTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
    {
        // Thread table right-click menu:
        // - Input: The click position on the table by the user;
        // - Processing: Select clicked row and copy visible text from the current row.
        // - Return: None; only writes to the clipboard, no thread operations are performed.
        if (threadInspectTable_ == nullptr)
        {
            return;
        }

        const QModelIndex kClickedIndex = threadInspectTable_->indexAt(localPosition);
        if (kClickedIndex.isValid())
        {
            threadInspectTable_->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
        }

        QMenu menu(threadInspectTable_);
        menu.setStyleSheet(buildProcessDetailMenuStyle());
        QAction* copyRowAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
            QStringLiteral("复制当前行"));
        copyRowAction->setEnabled(threadInspectTable_->currentRow() >= 0);
        const int kSelectedThreadRow = threadInspectTable_->currentRow();
        const QTableWidgetItem* const kSelectedThreadIdItem =
            kSelectedThreadRow >= 0
                ? threadInspectTable_->item(
                    kSelectedThreadRow,
                    toThreadColumnIndex(ThreadRowColumn::kThreadId))
                : nullptr;
        const std::size_t kSelectedThreadCacheIndex = kSelectedThreadIdItem != nullptr
            ? static_cast<std::size_t>(kSelectedThreadIdItem->data(Qt::UserRole).toULongLong())
            : static_cast<std::size_t>(threadInspectRows_.size());
        const ThreadInspectItem* const kSelectedThreadAffinityTarget =
            kSelectedThreadCacheIndex < threadInspectRows_.size()
                ? &threadInspectRows_[kSelectedThreadCacheIndex]
                : nullptr;
        QMenu* const kAffinityMenu = ks::process::addThreadAffinitySubMenu(
            &menu,
            QIcon(QStringLiteral(":/Icon/process_priority.svg")),
            kSelectedThreadAffinityTarget != nullptr
                ? kSelectedThreadAffinityTarget->processId
                : 0U,
            kSelectedThreadAffinityTarget != nullptr
                ? kSelectedThreadAffinityTarget->threadId
                : 0U,
            kSelectedThreadAffinityTarget != nullptr
                ? kSelectedThreadAffinityTarget->createTime100ns
                : 0U,
            buildProcessDetailMenuStyle(),
            [this](const bool actionOk, const QString& resultText)
            {
                if (threadInspectStatusLabel_ != nullptr)
                {
                    threadInspectStatusLabel_->setText(resultText);
                    threadInspectStatusLabel_->setStyleSheet(buildStateLabelStyle(
                        actionOk ? statusIdleColor() : statusWarningColor(),
                        actionOk ? 600 : 700));
                }
                KLogEvent actionEvent;
                (actionOk ? info : err) << actionEvent
                    << "[ProcessDetailWindow] thread affinity update: pid="
                    << baseRecord_.pid
                    << ", actionOk="
                    << (actionOk ? "true" : "false")
                    << ", detail="
                    << resultText.toStdString()
                    << eol;
                requestAsyncThreadInspectRefresh();
            });
        QAction* r0SuspendThreadAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_suspend.svg")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.r0_suspend"),
                QStringLiteral("R0挂起线程")));
        QAction* r0ResumeThreadAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_resume.svg")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.r0_resume"),
                QStringLiteral("R0恢复线程")));
        QAction* suspendDriverThreadAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_suspend.svg")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_suspend"),
                QStringLiteral("ZwSuspendThread / NtSuspendThread（实验性）")));
        QAction* resumeDriverThreadAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_resume.svg")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_resume"),
                QStringLiteral("ZwResumeThread / NtResumeThread（实验性）")));
        QMenu* terminateDriverThreadMenu = menu.addMenu(
            QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_terminate_experimental"),
                QStringLiteral("结束驱动线程（实验性原始 API）")));
        QAction* terminateDriverThreadPspAction = terminateDriverThreadMenu->addAction(
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_terminate.psp"),
                QStringLiteral("PspTerminateThreadByPointer（实验性/未文档化）")));
        QAction* terminateDriverThreadZwAction = terminateDriverThreadMenu->addAction(
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_terminate.zw"),
                QStringLiteral("ZwTerminateThread / NtTerminateThread（实验性）")));
        QAction* terminateDriverThreadNormalApcAction = terminateDriverThreadMenu->addAction(
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_terminate.normal_apc"),
                QStringLiteral("KeInsertQueueApc → Normal Kernel APC → PsTerminateSystemThread（实验性）")));
        QAction* terminateDriverThreadSpecialApcAction = terminateDriverThreadMenu->addAction(
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_terminate.special_apc"),
                QStringLiteral("KeInsertQueueApc → Special Kernel APC → Normal Kernel APC → PsTerminateSystemThread（实验性）")));
        terminateDriverThreadMenu->addSeparator();
        QAction* firmwareRebootAction = terminateDriverThreadMenu->addAction(
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.hal_return_to_firmware"),
                QStringLiteral("HalReturnToFirmware(HalRebootRoutine)（实验性/整机动作）")));
        QAction* r0TerminateThreadAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.r0_terminate"),
                QStringLiteral("R0结束线程")));
        const bool kHasR0ThreadControlTarget =
            threadInspectTable_->currentRow() >= 0 && baseRecord_.pid > 4U;
        if (kAffinityMenu != nullptr &&
            (kSelectedThreadAffinityTarget == nullptr ||
                kSelectedThreadAffinityTarget->processId != baseRecord_.pid ||
                kSelectedThreadAffinityTarget->threadId == 0U ||
                kSelectedThreadAffinityTarget->createTime100ns == 0U))
        {
            kAffinityMenu->setEnabled(false);
            kAffinityMenu->setToolTip(ks::i18n::contextText(
                QStringLiteral("process.thread.menu.affinity.unavailable"),
                QStringLiteral("无法读取此线程的 CPU Set 亲和性。")));
        }
        r0SuspendThreadAction->setEnabled(kHasR0ThreadControlTarget);
        r0ResumeThreadAction->setEnabled(kHasR0ThreadControlTarget);
        r0TerminateThreadAction->setEnabled(kHasR0ThreadControlTarget);
        bool hasDriverThreadTarget = false;
        if (threadInspectTable_->currentRow() >= 0 && baseRecord_.pid == 4U)
        {
            const QTableWidgetItem* selectedThreadIdItem = threadInspectTable_->item(
                threadInspectTable_->currentRow(),
                toThreadColumnIndex(ThreadRowColumn::kThreadId));
            const std::size_t kSelectedCacheIndex = selectedThreadIdItem != nullptr
                ? static_cast<std::size_t>(selectedThreadIdItem->data(Qt::UserRole).toULongLong())
                : static_cast<std::size_t>(threadInspectRows_.size());
            hasDriverThreadTarget =
                kSelectedCacheIndex < threadInspectRows_.size() &&
                threadInspectRows_[kSelectedCacheIndex].threadId != 0U &&
                threadInspectRows_[kSelectedCacheIndex].createTime100ns != 0ULL &&
                (threadInspectRows_[kSelectedCacheIndex].startAddress != 0ULL ||
                 threadInspectRows_[kSelectedCacheIndex].win32StartAddress != 0ULL);
        }
        suspendDriverThreadAction->setVisible(hasDriverThreadTarget);
        resumeDriverThreadAction->setVisible(hasDriverThreadTarget);
        terminateDriverThreadMenu->menuAction()->setVisible(hasDriverThreadTarget);
        menu.addSeparator();
        QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
            &menu,
            this,
            [this]() -> ks::online_scan::SandboxUploadTarget
            {
                // Input: Current row in the thread table.
                // Processing: Resolve the module path belonging to the thread, without falling back to the process EXE.
                // Returns: Module path to upload and source description.
                ks::online_scan::SandboxUploadTarget uploadTarget;
                QString errorText;
                uploadTarget.filePath = resolveSelectedThreadModulePathForUpload(&errorText);
                uploadTarget.sourceText = QStringLiteral("进程详情线程模块 PID=%1").arg(baseRecord_.pid);
                uploadTarget.errorText = errorText;
                return uploadTarget;
            });
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(threadInspectTable_->currentRow() >= 0);
        }

        QAction* selectedAction = menu.exec(threadInspectTable_->viewport()->mapToGlobal(localPosition));
        if (selectedAction == uploadVirusTotalAction)
        {
            return;
        }
        if (selectedAction == r0SuspendThreadAction)
        {
            executeR0SuspendSelectedThreadAction();
            return;
        }
        if (selectedAction == r0ResumeThreadAction)
        {
            executeR0ResumeSelectedThreadAction();
            return;
        }
        if (selectedAction == suspendDriverThreadAction)
        {
            executeDriverThreadAction(KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND);
            return;
        }
        if (selectedAction == resumeDriverThreadAction)
        {
            executeDriverThreadAction(KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME);
            return;
        }
        if (selectedAction == terminateDriverThreadPspAction)
        {
            executeDriverThreadAction(
                KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE,
                KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER);
            return;
        }
        if (selectedAction == terminateDriverThreadZwAction)
        {
            executeDriverThreadAction(
                KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE,
                KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT);
            return;
        }
        if (selectedAction == terminateDriverThreadNormalApcAction)
        {
            executeDriverThreadAction(
                KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE,
                KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC);
            return;
        }
        if (selectedAction == terminateDriverThreadSpecialApcAction)
        {
            executeDriverThreadAction(
                KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE,
                KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC);
            return;
        }
        if (selectedAction == firmwareRebootAction)
        {
            executeExperimentalFirmwareRebootAction();
            return;
        }
        if (selectedAction == r0TerminateThreadAction)
        {
            executeR0TerminateSelectedThreadAction();
            return;
        }
        if (selectedAction != copyRowAction)
        {
            return;
        }

        const int kRowIndex = threadInspectTable_->currentRow();
        if (kRowIndex < 0 || QApplication::clipboard() == nullptr)
        {
            return;
        }

        QStringList rowFields;
        rowFields.reserve(threadInspectTable_->columnCount());
        for (int columnIndex = 0; columnIndex < threadInspectTable_->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = threadInspectTable_->item(kRowIndex, columnIndex);
            rowFields.push_back(item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(rowFields.join('\t'));
    });
}

void ProcessDetailWindow::initializeActionTab()
{
    // Action page initialization log: Confirm action button area construction.
    KLogEvent initActionTabEvent;
    info << initActionTabEvent
        << "[ProcessDetailWindow] initializeActionTab: 构建进程操作页面。"
        << eol;

    QWidget* const kActionContent = createScrollableTabContent(
        actionTab_,
        actionLayout_,
        6,
        10);

    // buildTextActionButton:
    // Generate unified text action buttons for the operation page.
    // - Input buttonText as the user-visible button label, toolTipText as supplementary explanation.
    // - Returns a QPushButton without an icon-only form to avoid unintuitive operation panel semantics.
    const auto kBuildTextActionButton =
        [](const QString& buttonText, const QString& toolTipText, QWidget* parentWidget) -> QPushButton*
    {
        QPushButton* actionButton = new QPushButton(buttonText, parentWidget);
        actionButton->setMinimumHeight(32);
        actionButton->setMinimumWidth(72);
        actionButton->setToolTip(toolTipText);
        return actionButton;
    };

    // End and Control group:
    // - Change 'Termination Scheme' to a dropdown selection to avoid four wide buttons filling the entire row;
    // - Run control and critical process operations are changed to compact icon buttons, retaining tooltip explanations for semantics.
    QGroupBox* controlGroup = new QGroupBox("结束与控制", kActionContent);
    QGridLayout* controlLayout = new QGridLayout(controlGroup);
    controlLayout->setHorizontalSpacing(8);
    controlLayout->setVerticalSpacing(8);

    terminateActionCombo_ = new QComboBox(controlGroup);
    terminateActionCombo_->addItem(QIcon(":/Icon/process_terminate.svg"), "结束进程(组合方法链)", 2);
    terminateActionCombo_->addItem(QIcon(":/Icon/process_terminate.svg"), "TerminateProcess", 0);
    terminateActionCombo_->addItem(QIcon(":/Icon/process_terminate.svg"), "TerminateThread(全部线程)", 1);
    terminateActionCombo_->setToolTip("选择结束当前进程的执行方案");
    executeTerminateActionButton_ = kBuildTextActionButton(
        QStringLiteral("执行"),
        QStringLiteral("执行当前选中的结束方案"),
        controlGroup);

    suspendProcessCheck_ = new QCheckBox(QStringLiteral("挂起"), controlGroup);
    suspendProcessCheck_->setToolTip(
        QStringLiteral("勾上挂起当前进程，取消勾选恢复。勾选态反映进程当前是否处于挂起，不表示是谁挂的。"));
    setCriticalButton_ = kBuildTextActionButton(
        QStringLiteral("设为关键"),
        QStringLiteral("把当前进程设为关键进程"),
        controlGroup);
    clearCriticalButton_ = kBuildTextActionButton(
        QStringLiteral("取消关键"),
        QStringLiteral("取消当前进程的关键进程标记"),
        controlGroup);
    priorityCombo_ = new QComboBox(controlGroup);
    priorityCombo_->addItem("Idle", 0);
    priorityCombo_->addItem("Below Normal", 1);
    priorityCombo_->addItem("Normal", 2);
    priorityCombo_->addItem("Above Normal", 3);
    priorityCombo_->addItem("High", 4);
    priorityCombo_->addItem("Realtime", 5);
    priorityCombo_->setCurrentIndex(2);
    priorityCombo_->setToolTip("选择当前进程的新优先级");
    applyPriorityButton_ = kBuildTextActionButton(
        QStringLiteral("应用"),
        QStringLiteral("应用当前选中的进程优先级"),
        controlGroup);

    controlLayout->addWidget(new QLabel("结束方案", controlGroup), 0, 0);
    controlLayout->addWidget(terminateActionCombo_, 0, 1, 1, 3);
    controlLayout->addWidget(executeTerminateActionButton_, 0, 4);
    controlLayout->addWidget(new QLabel("运行控制", controlGroup), 1, 0);
    controlLayout->addWidget(suspendProcessCheck_, 1, 1, 1, 2);
    controlLayout->addWidget(new QLabel("关键进程", controlGroup), 2, 0);
    controlLayout->addWidget(setCriticalButton_, 2, 1);
    controlLayout->addWidget(clearCriticalButton_, 2, 2);
    controlLayout->addWidget(new QLabel("优先级", controlGroup), 3, 0);
    controlLayout->addWidget(priorityCombo_, 3, 1, 1, 3);
    controlLayout->addWidget(applyPriorityButton_, 3, 4);
    actionLayout_->addWidget(controlGroup);

    // CPU affinity:
    // - Display stable logical processor identities in a 6-column matrix; show Gx prefix and group headers only when multiple groups exist.
    // - Read the actual CPU Set only after the first entry into the 'Actions' tab to keep the initial open path of the detail window lightweight.
    // - Each button toggles independently; a blue theme background indicates that the corresponding logical processor is enabled.
    affinityActionGroup_ = new QGroupBox(
        ks::i18n::text(QStringLiteral("process.detail.affinity.title"), QString()),
        kActionContent);
    QVBoxLayout* affinityGroupLayout = new QVBoxLayout(affinityActionGroup_);
    affinityGroupLayout->setContentsMargins(10, 10, 10, 10);
    affinityGroupLayout->setSpacing(8);

    const auto kInstallCopyMenu = [](QWidget* widget, const std::function<QString()>& textProvider)
    {
        if (widget == nullptr)
        {
            return;
        }
        widget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(widget, &QWidget::customContextMenuRequested, widget,
            [widget, textProvider](const QPoint& localPosition)
            {
                const QString kCopyText = textProvider ? textProvider().trimmed() : QString();
                if (kCopyText.isEmpty())
                {
                    return;
                }
                QMenu contextMenu(widget);
                contextMenu.setStyleSheet(buildProcessDetailMenuStyle());
                QAction* copyAction = contextMenu.addAction(
                    ks::i18n::text(QStringLiteral("process.detail.action.copy"), QString()));
                if (contextMenu.exec(widget->mapToGlobal(localPosition)) == copyAction)
                {
                    QApplication::clipboard()->setText(kCopyText);
                }
            });
    };

    affinityDescriptionLabel_ = new QLabel(
        ks::i18n::text(QStringLiteral("process.detail.affinity.description"), QString()),
        affinityActionGroup_);
    affinityDescriptionLabel_->setWordWrap(true);
    affinityDescriptionLabel_->setMinimumWidth(0);
    affinityDescriptionLabel_->setSizePolicy(
        QSizePolicy::Ignored,
        QSizePolicy::Preferred);
    affinityDescriptionLabel_->setTextInteractionFlags(
        Qt::TextSelectableByMouse);
    affinityDescriptionLabel_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    kInstallCopyMenu(affinityDescriptionLabel_, [this]()
    {
        return affinityDescriptionLabel_ != nullptr
            ? affinityDescriptionLabel_->text()
            : QString();
    });
    affinityGroupLayout->addWidget(affinityDescriptionLabel_);

    affinityPersistenceCheckBox_ = new QCheckBox(
        ks::i18n::text(QStringLiteral("process.detail.affinity.persistence"), QString()),
        affinityActionGroup_);
    affinityPersistenceCheckBox_->setToolTip(
        ks::i18n::text(QStringLiteral("process.detail.affinity.persistence.tooltip"), QString()));
    affinityGroupLayout->addWidget(affinityPersistenceCheckBox_);

    QHBoxLayout* affinityTopLayout = new QHBoxLayout();
    affinityTopLayout->setContentsMargins(0, 0, 0, 0);
    affinityTopLayout->setSpacing(8);
    affinityStatusLabel_ = new QLabel(affinityActionGroup_);
    affinityStatusLabel_->setWordWrap(true);
    affinityStatusLabel_->setMinimumWidth(0);
    affinityStatusLabel_->setSizePolicy(
        QSizePolicy::Ignored,
        QSizePolicy::Preferred);
    affinityStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    affinityStatusLabel_->setStyleSheet(buildStateLabelStyle(statusSecondaryColor(), 600));
    kInstallCopyMenu(affinityStatusLabel_, [this]()
    {
        return affinityStatusLabel_ != nullptr ? affinityStatusLabel_->text() : QString();
    });
    affinityRefreshButton_ = kBuildTextActionButton(
        ks::i18n::text(QStringLiteral("process.detail.affinity.refresh"), QString()),
        ks::i18n::text(QStringLiteral("process.detail.affinity.refresh"), QString()),
        affinityActionGroup_);
    affinityAllCoresButton_ = kBuildTextActionButton(
        ks::i18n::text(QStringLiteral("process.detail.affinity.all_cores"), QString()),
        ks::i18n::text(QStringLiteral("process.detail.affinity.all_cores"), QString()),
        affinityActionGroup_);
    affinityTopLayout->addWidget(affinityStatusLabel_, 1);
    affinityTopLayout->addWidget(affinityRefreshButton_);
    affinityTopLayout->addWidget(affinityAllCoresButton_);
    affinityGroupLayout->addLayout(affinityTopLayout);

    affinityMatrixLayout_ = new QGridLayout();
    affinityMatrixLayout_->setContentsMargins(0, 0, 0, 0);
    affinityMatrixLayout_->setHorizontalSpacing(6);
    affinityMatrixLayout_->setVerticalSpacing(6);
    affinityCoreButtons_.clear();
    affinityGroupLayout->addLayout(affinityMatrixLayout_);
    actionLayout_->addWidget(affinityActionGroup_);

    connect(affinityRefreshButton_, &QPushButton::clicked, this, [this]()
    {
        refreshActionAffinityControls();
    });
    connect(affinityAllCoresButton_, &QPushButton::clicked, this, [this]()
    {
        if (!actionAffinityReadable_ ||
            actionAffinitySnapshot_.processors.empty())
        {
            refreshActionAffinityControls();
            return;
        }
        ks::process::ProcessAffinityRule affinityRule;
        affinityRule.selectAllAvailable = true;
        applyActionAffinityRule(affinityRule);
    });
    connect(affinityPersistenceCheckBox_, &QCheckBox::toggled, this, [this](const bool enabled)
    {
        if (enabled && !confirmActionAffinityRisk(true))
        {
            const QSignalBlocker kSignalBlocker(
                affinityPersistenceCheckBox_);
            affinityPersistenceCheckBox_->setChecked(false);
            return;
        }

        std::string detailText;
        const bool kPersistenceOk = enabled
            ? (actionAffinityReadable_ &&
                ks::process::savePersistedProcessAffinityRule(
                    baseRecord_.imagePath,
                    ks::process::affinityRuleFromSnapshot(
                        actionAffinitySnapshot_),
                    &detailText))
            : ks::process::removePersistedProcessAffinityRule(
                baseRecord_.imagePath,
                &detailText);
        if (!kPersistenceOk)
        {
            const QSignalBlocker kSignalBlocker(affinityPersistenceCheckBox_);
            affinityPersistenceCheckBox_->setChecked(!enabled);
            KLogEvent persistenceEvent;
            warn << persistenceEvent
                << "[ProcessDetailWindow] CPU affinity persistence toggle failed, pid="
                << baseRecord_.pid
                << ", enabled=" << (enabled ? "true" : "false")
                << ", detail=" << detailText
                << eol;
        }
        if (affinityStatusLabel_ != nullptr)
        {
            affinityStatusLabel_->setText(
                kPersistenceOk
                    ? ks::i18n::text(
                        enabled
                            ? QStringLiteral("process.detail.affinity.persistence.saved")
                            : QStringLiteral("process.detail.affinity.persistence.removed"),
                        QString())
                    : ks::i18n::text(
                        QStringLiteral(
                            "process.detail.affinity.persistence.update_failed"),
                        QString()));
            affinityStatusLabel_->setStyleSheet(buildStateLabelStyle(
                kPersistenceOk ? statusIdleColor() : statusWarningColor(),
                kPersistenceOk ? 600 : 700));
        }
    });
    QTimer::singleShot(0, this, [this]()
    {
        refreshActionAffinityControls();
    });

    // Token privileges area:
    // - Uses checkboxes to express enabled/disabled states; items that fail to query or do not exist in the token are displayed in gray.
    // - R3/R0 use independent application buttons to allow users to clearly select the communication layer.
    // - Right-clicking any checkbox copies the privilege name, ensuring the detail page content is copyable.
    privilegeActionGroup_ = new QGroupBox(
        ks::i18n::text(QStringLiteral("process.detail.privileges.title"), QString()),
        kActionContent);
    QVBoxLayout* privilegeGroupLayout = new QVBoxLayout(privilegeActionGroup_);
    privilegeGroupLayout->setContentsMargins(10, 10, 10, 10);
    privilegeGroupLayout->setSpacing(8);

    QLabel* privilegeDescriptionLabel = new QLabel(
        ks::i18n::text(QStringLiteral("process.detail.privileges.description"), QString()),
        privilegeActionGroup_);
    privilegeDescriptionLabel->setWordWrap(true);
    privilegeDescriptionLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    privilegeDescriptionLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    kInstallCopyMenu(privilegeDescriptionLabel, [privilegeDescriptionLabel]()
    {
        return privilegeDescriptionLabel->text();
    });
    privilegeGroupLayout->addWidget(privilegeDescriptionLabel);

    QHBoxLayout* privilegeActionTopLayout = new QHBoxLayout();
    privilegeActionTopLayout->setContentsMargins(0, 0, 0, 0);
    privilegeActionTopLayout->setSpacing(8);
    actionPrivilegeStatusLabel_ = new QLabel(privilegeActionGroup_);
    actionPrivilegeStatusLabel_->setWordWrap(true);
    actionPrivilegeStatusLabel_->setMinimumWidth(0);
    actionPrivilegeStatusLabel_->setSizePolicy(
        QSizePolicy::Ignored,
        QSizePolicy::Preferred);
    actionPrivilegeStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    actionPrivilegeStatusLabel_->setStyleSheet(
        buildStateLabelStyle(statusSecondaryColor(), 600));
    kInstallCopyMenu(actionPrivilegeStatusLabel_, [this]()
    {
        return actionPrivilegeStatusLabel_ != nullptr
            ? actionPrivilegeStatusLabel_->text()
            : QString();
    });
    actionPrivilegeRefreshButton_ = kBuildTextActionButton(
        ks::i18n::text(QStringLiteral("process.detail.privileges.refresh"), QString()),
        ks::i18n::text(QStringLiteral("process.detail.privileges.refresh"), QString()),
        privilegeActionGroup_);
    applyActionPrivilegeR3Button_ = kBuildTextActionButton(
        ks::i18n::text(QStringLiteral("process.detail.privileges.apply_r3"), QString()),
        ks::i18n::text(QStringLiteral("process.detail.privileges.apply_r3.tooltip"), QString()),
        privilegeActionGroup_);
    applyActionPrivilegeR0Button_ = kBuildTextActionButton(
        ks::i18n::text(QStringLiteral("process.detail.privileges.apply_r0"), QString()),
        ks::i18n::text(QStringLiteral("process.detail.privileges.apply_r0.tooltip"), QString()),
        privilegeActionGroup_);
    // Disable before the first query completes to avoid submitting R0 changes without a comparable snapshot.
    applyActionPrivilegeR0Button_->setEnabled(false);
    privilegeActionTopLayout->addWidget(actionPrivilegeStatusLabel_, 1);
    privilegeActionTopLayout->addWidget(actionPrivilegeRefreshButton_);
    privilegeActionTopLayout->addWidget(applyActionPrivilegeR3Button_);
    privilegeActionTopLayout->addWidget(applyActionPrivilegeR0Button_);
    privilegeGroupLayout->addLayout(privilegeActionTopLayout);

    QGridLayout* privilegeGridLayout = new QGridLayout();
    privilegeGridLayout->setContentsMargins(0, 0, 0, 0);
    privilegeGridLayout->setHorizontalSpacing(16);
    privilegeGridLayout->setVerticalSpacing(4);
    const std::vector<std::string>& knownPrivilegeNames =
        ks::process::knownTokenPrivilegeNames();
    actionPrivilegeCheckBoxes_.clear();
    actionPrivilegeCheckBoxes_.reserve(knownPrivilegeNames.size());
    for (std::size_t privilegeIndex = 0U;
         privilegeIndex < knownPrivilegeNames.size();
         ++privilegeIndex)
    {
        QCheckBox* privilegeCheckBox = new QCheckBox(
            QString::fromLatin1(knownPrivilegeNames[privilegeIndex].c_str()),
            privilegeActionGroup_);
        privilegeCheckBox->setEnabled(false);
        privilegeCheckBox->setToolTip(
            ks::i18n::text(QStringLiteral("process.detail.privileges.waiting"), QString()));
        privilegeCheckBox->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(privilegeCheckBox, &QWidget::customContextMenuRequested,
            privilegeCheckBox, [privilegeCheckBox](const QPoint& localPosition)
        {
            QMenu copyMenu(privilegeCheckBox);
            copyMenu.setStyleSheet(buildProcessDetailMenuStyle());
            QAction* copyAction = copyMenu.addAction(
                ks::i18n::text(QStringLiteral("process.detail.action.copy"), QString()));
            if (copyMenu.exec(privilegeCheckBox->mapToGlobal(localPosition)) == copyAction)
            {
                QApplication::clipboard()->setText(privilegeCheckBox->text());
            }
        });
        actionPrivilegeCheckBoxes_.push_back(privilegeCheckBox);
        privilegeGridLayout->addWidget(
            privilegeCheckBox,
            static_cast<int>(privilegeIndex / 3U),
            static_cast<int>(privilegeIndex % 3U));
    }
    privilegeGridLayout->setColumnStretch(3, 1);
    privilegeGroupLayout->addLayout(privilegeGridLayout);
    actionLayout_->addWidget(privilegeActionGroup_);

    QGroupBox* gotoGroup = new QGroupBox(QStringLiteral("转到"), kActionContent);
    QGridLayout* gotoLayout = new QGridLayout(gotoGroup);
    gotoLayout->setHorizontalSpacing(8);
    gotoLayout->setVerticalSpacing(8);
    openHandleDockButton_ = kBuildTextActionButton(
        QStringLiteral("句柄"), QStringLiteral("打开句柄页并按当前 PID 过滤"), gotoGroup);
    openMemoryDockButton_ = kBuildTextActionButton(
        QStringLiteral("内存"), QStringLiteral("打开内存页并附加当前 PID"), gotoGroup);
    openNetworkDockButton_ = kBuildTextActionButton(
        QStringLiteral("网络"), QStringLiteral("打开连接管理页并按当前 PID 过滤"), gotoGroup);
    openWindowDockButton_ = kBuildTextActionButton(
        QStringLiteral("窗口"), QStringLiteral("打开窗口页并按当前 PID 过滤"), gotoGroup);
    gotoLayout->addWidget(openHandleDockButton_, 0, 0);
    gotoLayout->addWidget(openMemoryDockButton_, 0, 1);
    gotoLayout->addWidget(openNetworkDockButton_, 0, 2);
    gotoLayout->addWidget(openWindowDockButton_, 0, 3);
    gotoLayout->setColumnStretch(4, 1);
    actionLayout_->addWidget(gotoGroup);

    // Extended action group:
    // - Aligned with the right-click menu in the process list, incorporating the efficiency mode, PPL refresh, and R0 capabilities that were previously omitted from the detail view.
    // - R0 buttons use explicit text and corresponding business icons; menu items are dynamically generated on click.
    QGroupBox* extendedActionGroup = new QGroupBox(QStringLiteral("右键菜单同步能力"), kActionContent);
    QGridLayout* extendedActionLayout = new QGridLayout(extendedActionGroup);
    extendedActionLayout->setHorizontalSpacing(8);
    extendedActionLayout->setVerticalSpacing(8);

    openProcessFolderButton_ = kBuildTextActionButton(
        QStringLiteral("打开目录"),
        QStringLiteral("打开当前进程所在目录"),
        extendedActionGroup);
    refreshPplProtectionButton_ = kBuildTextActionButton(
        QStringLiteral("刷新PPL"),
        QStringLiteral("手动刷新当前进程 PPL 保护级别"),
        extendedActionGroup);
    efficiencyModeCheck_ = new QCheckBox(QStringLiteral("效率模式"), extendedActionGroup);
    efficiencyModeCheck_->setToolTip(
        QStringLiteral("勾上开启当前进程效率模式（绿叶），取消勾选关闭。本机或该进程不支持时勾选无效，详情页的效率模式一行会显示不可用。"));

    // buildR0MenuButton:
    // - Create buttons for R0 functionality with explicit text and business icons;
    // - Input: buttonText is the visible text, iconPath is the business icon, and toolTipText is supplementary explanation.
    // - Returns the button object; the caller is responsible for adding it to the layout and handling the clicked signal.
    const auto kBuildR0MenuButton =
        [](const QString& buttonText, const QString& iconPath, const QString& toolTipText, QWidget* parentWidget) -> QPushButton*
    {
        QPushButton* actionButton = new QPushButton(
            buildProcessDetailR0ActionIcon(iconPath),
            buttonText,
            parentWidget);
        actionButton->setMinimumHeight(32);
        actionButton->setMinimumWidth(92);
        actionButton->setIconSize(QSize(16, 16));
        actionButton->setToolTip(toolTipText);
        return actionButton;
    };

    r0TerminateProcessButton_ = kBuildR0MenuButton(
        QStringLiteral("R0结束"),
        QStringLiteral(":/Icon/process_terminate.svg"),
        QStringLiteral("通过 R0 驱动结束当前进程"),
        extendedActionGroup);
    r0SuspendProcessButton_ = kBuildR0MenuButton(
        QStringLiteral("R0挂起"),
        QStringLiteral(":/Icon/process_suspend.svg"),
        QStringLiteral("通过 R0 驱动挂起当前进程"),
        extendedActionGroup);
    r0SetPplButton_ = kBuildR0MenuButton(
        QStringLiteral("R0 保护"),
        QStringLiteral(":/Icon/process_critical.svg"),
        QStringLiteral("通过 R0 驱动设置当前进程 PPL/PP 保护层级"),
        extendedActionGroup);
    r0VisibilityButton_ = kBuildR0MenuButton(
        QStringLiteral("R0隐藏"),
        QStringLiteral(":/Icon/process_details.svg"),
        QStringLiteral("通过 R0 驱动隐藏/恢复当前进程"),
        extendedActionGroup);
    r0DangerFlagsButton_ = kBuildR0MenuButton(
        QStringLiteral("R0危险"),
        QStringLiteral(":/Icon/process_uncritical.svg"),
        QStringLiteral("R0 BreakOnTermination / APC / DKOM 高风险操作"),
        extendedActionGroup);

    extendedActionLayout->addWidget(new QLabel(QStringLiteral("辅助"), extendedActionGroup), 0, 0);
    extendedActionLayout->addWidget(openProcessFolderButton_, 0, 1);
    extendedActionLayout->addWidget(refreshPplProtectionButton_, 0, 2);
    extendedActionLayout->addWidget(new QLabel(QStringLiteral("效率模式"), extendedActionGroup), 1, 0);
    extendedActionLayout->addWidget(efficiencyModeCheck_, 1, 1, 1, 2);
    extendedActionLayout->addWidget(new QLabel(QStringLiteral("R0"), extendedActionGroup), 2, 0);
    extendedActionLayout->addWidget(r0TerminateProcessButton_, 2, 1);
    extendedActionLayout->addWidget(r0SuspendProcessButton_, 2, 2);
    extendedActionLayout->addWidget(r0SetPplButton_, 2, 3);
    extendedActionLayout->addWidget(r0VisibilityButton_, 2, 4);
    extendedActionLayout->addWidget(r0DangerFlagsButton_, 2, 5);
    extendedActionLayout->setColumnStretch(6, 1);
    actionLayout_->addWidget(extendedActionGroup);

    // Injection and loading group:
    // - Consolidate the two sets of operations (DLL / Shellcode) into a unified two-line layout;
    // - Use text buttons for the Browse and Execute actions to ensure the operation panel no longer relies on icons to convey meaning.
    QGroupBox* injectGroup = new QGroupBox("注入与载入", kActionContent);
    QGridLayout* injectLayout = new QGridLayout(injectGroup);
    injectLayout->setHorizontalSpacing(8);
    injectLayout->setVerticalSpacing(8);

    injectionModeCombo_ = new QComboBox(injectGroup);
    injectionModeCombo_->addItem(QStringLiteral("R3"), 0);
    injectionModeCombo_->addItem(
        buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("R0驱动"),
        1);
    injectionModeCombo_->setToolTip(QStringLiteral("选择 DLL / Shellcode 注入执行方式。R0驱动模式通过 KswordARK 驱动完成远端分配、写入和建线程。"));

    dllPathLineEdit_ = new QLineEdit(injectGroup);
    dllPathLineEdit_->setPlaceholderText("请选择要注入的 DLL 路径");
    browseDllButton_ = kBuildTextActionButton(
        QStringLiteral("浏览"),
        QStringLiteral("浏览并选择 DLL 文件"),
        injectGroup);
    injectDllButton_ = kBuildTextActionButton(
        QStringLiteral("注入"),
        QStringLiteral("执行 DLL 注入"),
        injectGroup);

    shellcodePathLineEdit_ = new QLineEdit(injectGroup);
    shellcodePathLineEdit_->setPlaceholderText("请选择原始 shellcode 二进制文件");
    browseShellcodeButton_ = kBuildTextActionButton(
        QStringLiteral("浏览"),
        QStringLiteral("浏览并选择 shellcode 文件"),
        injectGroup);
    injectShellcodeButton_ = kBuildTextActionButton(
        QStringLiteral("执行"),
        QStringLiteral("执行 shellcode 注入"),
        injectGroup);

    injectLayout->addWidget(new QLabel("模式", injectGroup), 0, 0);
    injectLayout->addWidget(injectionModeCombo_, 0, 1, 1, 3);
    injectLayout->addWidget(new QLabel("DLL", injectGroup), 1, 0);
    injectLayout->addWidget(dllPathLineEdit_, 1, 1);
    injectLayout->addWidget(browseDllButton_, 1, 2);
    injectLayout->addWidget(injectDllButton_, 1, 3);
    injectLayout->addWidget(new QLabel("Shellcode", injectGroup), 2, 0);
    injectLayout->addWidget(shellcodePathLineEdit_, 2, 1);
    injectLayout->addWidget(browseShellcodeButton_, 2, 2);
    injectLayout->addWidget(injectShellcodeButton_, 2, 3);
    actionLayout_->addWidget(injectGroup);

    actionLayout_->addStretch(1);

    // Unified button theme style:
    // - ComboBox continues to use the item's blue border.
    // - Compact buttons use the unified blue button style to avoid visual fragmentation of local controls.
    const QString kButtonStyle = buildBlueButtonStyle();
    const QString kComboStyle = ksword_theme::themedComboBoxStyle();
    terminateActionCombo_->setStyleSheet(kComboStyle);
    priorityCombo_->setStyleSheet(kComboStyle);
    injectionModeCombo_->setStyleSheet(kComboStyle);

    const std::vector<QPushButton*> kActionButtons{
        executeTerminateActionButton_,
        setCriticalButton_,
        clearCriticalButton_,
        applyPriorityButton_,
        affinityRefreshButton_,
        affinityAllCoresButton_,
        actionPrivilegeRefreshButton_,
        applyActionPrivilegeR3Button_,
        applyActionPrivilegeR0Button_,
        openProcessFolderButton_,
        refreshPplProtectionButton_,
        r0TerminateProcessButton_,
        r0SuspendProcessButton_,
        r0SetPplButton_,
        r0VisibilityButton_,
        r0DangerFlagsButton_,
        browseDllButton_,
        injectDllButton_,
        browseShellcodeButton_,
        injectShellcodeButton_
    };
    for (QPushButton* buttonItem : kActionButtons)
    {
        if (buttonItem != nullptr)
        {
            buttonItem->setStyleSheet(kButtonStyle);
        }
    }
}

void ProcessDetailWindow::initializeModuleTab()
{
    // Module page initialization log: confirm module table and toolbar creation.
    KLogEvent initModuleTabEvent;
    info << initModuleTabEvent
        << "[ProcessDetailWindow] initializeModuleTab: 构建模块页面。"
        << eol;

    moduleLayout_ = new QVBoxLayout(moduleTab_);
    moduleLayout_->setContentsMargins(6, 6, 6, 6);
    moduleLayout_->setSpacing(6);

    // Top toolbar: refresh button + signature verification option + status label.
    moduleTopBarLayout_ = new QHBoxLayout();
    moduleTopBarLayout_->setContentsMargins(0, 0, 0, 0);
    moduleTopBarLayout_->setSpacing(8);
    refreshModuleButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), "刷新模块", moduleTab_);
    dllHijackScanButton_ = new QPushButton(
        QIcon(":/Icon/process_details.svg"),
        ks::i18n::sourceText(QStringLiteral("DLL 劫持检测")),
        moduleTab_);
    dllHijackScanButton_->setToolTip(ks::i18n::sourceText(
        QStringLiteral("只读比较程序目录 DLL 与架构匹配、签名可信的系统 DLL；不会加载待检 DLL")));
    // Split Quick and Deep into two buttons: the only difference is the comparison range;
    // using a hidden modifier key would require users to know about this beforehand.
    injectionTraceButton_ = new QPushButton(
        QIcon(":/Icon/process_details.svg"),
        ks::i18n::sourceText(QStringLiteral("快速注入检查")),
        moduleTab_);
    // Note: The literal must be written on a single line. The i18n audit treats every segment of adjacent string concatenation
    // as an independent translatable text; splitting lines would artificially create numerous half-sentence entries.
    injectionTraceButton_->setToolTip(ks::i18n::sourceText(
        QStringLiteral("只读检查：有没有来路不明的可执行内存、模块清单对不对得上、线程从哪里开始跑。只比对当前正在使用的代码页，一般几秒出结果。不挂起进程、不改内存权限。结果只说明看到了什么，不会给出“已注入/未注入”的判定。")));
    injectionTraceDeepButton_ = new QPushButton(
        QIcon(":/Icon/process_details.svg"),
        ks::i18n::sourceText(QStringLiteral("深度注入检查")),
        moduleTab_);
    injectionTraceDeepButton_->setToolTip(ks::i18n::sourceText(
        QStringLiteral("和快速检查用的是同一套判据，区别只在比对范围：深度会把每个模块的可执行代码整段与磁盘上的原文件比一遍，因此能查出“暂时没在运行、但已经被改过”的代码，代价是最长可能跑上一两分钟。同样是只读检查。")));
    signatureCheckBox_ = new QCheckBox("刷新时校验签名", moduleTab_);
    signatureCheckBox_->setChecked(true);
    signatureCheckBox_->setStyleSheet(QStringLiteral(
        "QCheckBox { color:%1; font-weight:600; }")
        .arg(ksword_theme::textPrimaryHex()));
    moduleStatusLabel_ = new QLabel("● 等待首次刷新", moduleTab_);
    moduleStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(ksword_theme::textSecondaryHex()));
    moduleTopBarLayout_->addWidget(refreshModuleButton_);
    moduleTopBarLayout_->addWidget(dllHijackScanButton_);
    moduleTopBarLayout_->addWidget(injectionTraceButton_);
    moduleTopBarLayout_->addWidget(injectionTraceDeepButton_);
    moduleTopBarLayout_->addWidget(signatureCheckBox_);
    moduleTopBarLayout_->addStretch(1);
    moduleTopBarLayout_->addWidget(moduleStatusLabel_);
    moduleLayout_->addLayout(moduleTopBarLayout_);

    // Module list table.
    moduleTable_ = new QTreeWidget(moduleTab_);
    moduleTable_->setColumnCount(static_cast<int>(ModuleColumn::kCount));
    moduleTable_->setHeaderLabels(kModuleHeaders);
    moduleTable_->setRootIsDecorated(false);
    moduleTable_->setItemsExpandable(false);
    moduleTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    moduleTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    moduleTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    moduleTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    moduleTable_->setSortingEnabled(true);
    moduleTable_->setAlternatingRowColors(true);
    moduleLayout_->addWidget(moduleTable_, 1);

    // Column width initialization.
    moduleTable_->setColumnWidth(toModuleColumnIndex(ModuleColumn::kPath), 560);
    moduleTable_->setColumnWidth(toModuleColumnIndex(ModuleColumn::kSize), 110);
    moduleTable_->setColumnWidth(toModuleColumnIndex(ModuleColumn::kSignature), 260);
    moduleTable_->setColumnWidth(toModuleColumnIndex(ModuleColumn::kEntryOffset), 120);
    moduleTable_->setColumnWidth(toModuleColumnIndex(ModuleColumn::kState), 90);
    moduleTable_->setColumnWidth(toModuleColumnIndex(ModuleColumn::kThreadId), 180);

    // Blue theme for headers.
    moduleTable_->header()->setStyleSheet(QStringLiteral(
        "QHeaderView::section {"
        "  color:%1;"
        "  background:transparent; /* %2 */"
        "  border:1px solid %3;"
        "  padding:4px;"
        "  font-weight:600;"
        "}")
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::borderHex()));

    refreshModuleButton_->setStyleSheet(buildBlueButtonStyle());
    dllHijackScanButton_->setStyleSheet(buildBlueButtonStyle());
    injectionTraceButton_->setStyleSheet(buildBlueButtonStyle());
    injectionTraceDeepButton_->setStyleSheet(buildBlueButtonStyle());
}

void ProcessDetailWindow::initializeTokenTab()
{
    // Token page initialization: specifically displays SID, privileges, integrity level, etc.
    KLogEvent initTokenTabEvent;
    info << initTokenTabEvent
        << "[ProcessDetailWindow] initializeTokenTab: 构建令牌信息页面。"
        << eol;

    tokenLayout_ = new QVBoxLayout(tokenTab_);
    tokenLayout_->setContentsMargins(6, 6, 6, 6);
    tokenLayout_->setSpacing(6);

    QHBoxLayout* tokenTopBarLayout = new QHBoxLayout();
    refreshTokenButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), "刷新令牌", tokenTab_);
    refreshTokenButton_->setToolTip("异步刷新用户 SID、组、特权、完整性级别等令牌信息");
    tokenStatusLabel_ = new QLabel("● 尚未刷新", tokenTab_);
    tokenStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(ksword_theme::textSecondaryHex()));
    tokenTopBarLayout->addWidget(refreshTokenButton_);
    tokenTopBarLayout->addWidget(tokenStatusLabel_, 1);
    tokenLayout_->addLayout(tokenTopBarLayout);

    tokenDetailOutput_ = new CodeEditorWidget(tokenTab_);
    tokenDetailOutput_->setReadOnly(true);
    tokenDetailOutput_->setText(QStringLiteral("令牌详细信息将在此处显示。"));
    tokenLayout_->addWidget(tokenDetailOutput_, 1);

    const QString kButtonStyle = buildBlueButtonStyle();
    refreshTokenButton_->setStyleSheet(kButtonStyle);
}

void ProcessDetailWindow::initializeKernelObjectTab()
{
    // Process Detail Evidence page initialization:
    // - Display Phase-2 process extension information;
    // - Skips handle table/Section enumeration to avoid triggering subsequent high-risk paths when DynData is missing.
    KLogEvent initKernelObjectTabEvent;
    info << initKernelObjectTabEvent
        << "[ProcessDetailWindow] initializeKernelObjectTab: 构建 Process Detail Evidence 页面。"
        << eol;

    QWidget* const kKernelObjectContent = createScrollableTabContent(
        kernelObjectTab_,
        kernelObjectLayout_,
        6,
        8);

    QGroupBox* summaryGroup = new QGroupBox(QStringLiteral("R0 扩展摘要"), kKernelObjectContent);
    QFormLayout* summaryFormLayout = new QFormLayout(summaryGroup);
    summaryFormLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    summaryFormLayout->setHorizontalSpacing(18);
    summaryFormLayout->setVerticalSpacing(6);

    kernelObjectR0StatusValue_ = new QLabel(summaryGroup);
    kernelObjectCapabilityValue_ = new QLabel(summaryGroup);
    kernelObjectImagePathValue_ = new QLabel(summaryGroup);
    kernelObjectR0StatusValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    kernelObjectCapabilityValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    kernelObjectImagePathValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    kernelObjectImagePathValue_->setWordWrap(true);

    summaryFormLayout->addRow(QStringLiteral("R0 状态"), kernelObjectR0StatusValue_);
    summaryFormLayout->addRow(QStringLiteral("DynData Capability"), kernelObjectCapabilityValue_);
    summaryFormLayout->addRow(QStringLiteral("R0 镜像路径"), kernelObjectImagePathValue_);
    kernelObjectLayout_->addWidget(summaryGroup);

    QGroupBox* objectGroup = new QGroupBox(QStringLiteral("对象字段可用性"), kKernelObjectContent);
    QFormLayout* objectFormLayout = new QFormLayout(objectGroup);
    objectFormLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    objectFormLayout->setHorizontalSpacing(18);
    objectFormLayout->setVerticalSpacing(6);

    kernelObjectHandleTableValue_ = new QLabel(objectGroup);
    kernelObjectSectionObjectValue_ = new QLabel(objectGroup);
    kernelObjectHandleTableValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    kernelObjectSectionObjectValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    objectFormLayout->addRow(QStringLiteral("HandleTable"), kernelObjectHandleTableValue_);
    objectFormLayout->addRow(QStringLiteral("SectionObject"), kernelObjectSectionObjectValue_);
    kernelObjectLayout_->addWidget(objectGroup);

    QGroupBox* protectionGroup = new QGroupBox(QStringLiteral("保护与签名字段"), kKernelObjectContent);
    QFormLayout* protectionFormLayout = new QFormLayout(protectionGroup);
    protectionFormLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    protectionFormLayout->setHorizontalSpacing(18);
    protectionFormLayout->setVerticalSpacing(6);

    kernelObjectProtectionValue_ = new QLabel(protectionGroup);
    kernelObjectSignatureValue_ = new QLabel(protectionGroup);
    kernelObjectSectionSignatureValue_ = new QLabel(protectionGroup);
    kernelObjectProtectionValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    kernelObjectSignatureValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    kernelObjectSectionSignatureValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    protectionFormLayout->addRow(QStringLiteral("EPROCESS.Protection"), kernelObjectProtectionValue_);
    protectionFormLayout->addRow(QStringLiteral("SignatureLevel"), kernelObjectSignatureValue_);
    protectionFormLayout->addRow(QStringLiteral("SectionSignatureLevel"), kernelObjectSectionSignatureValue_);
    kernelObjectLayout_->addWidget(protectionGroup);

    QGroupBox* sourceGroup = new QGroupBox(QStringLiteral("字段来源"), kKernelObjectContent);
    QFormLayout* sourceFormLayout = new QFormLayout(sourceGroup);
    sourceFormLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    sourceFormLayout->setHorizontalSpacing(18);
    sourceFormLayout->setVerticalSpacing(6);

    kernelObjectSessionSourceValue_ = new QLabel(sourceGroup);
    kernelObjectImagePathSourceValue_ = new QLabel(sourceGroup);
    kernelObjectProtectionSourceValue_ = new QLabel(sourceGroup);
    kernelObjectSignatureSourceValue_ = new QLabel(sourceGroup);
    kernelObjectSectionSignatureSourceValue_ = new QLabel(sourceGroup);
    kernelObjectObjectTableSourceValue_ = new QLabel(sourceGroup);
    kernelObjectSectionObjectSourceValue_ = new QLabel(sourceGroup);
    sourceFormLayout->addRow(QStringLiteral("Session"), kernelObjectSessionSourceValue_);
    sourceFormLayout->addRow(QStringLiteral("ImagePath"), kernelObjectImagePathSourceValue_);
    sourceFormLayout->addRow(QStringLiteral("Protection"), kernelObjectProtectionSourceValue_);
    sourceFormLayout->addRow(QStringLiteral("SignatureLevel"), kernelObjectSignatureSourceValue_);
    sourceFormLayout->addRow(QStringLiteral("SectionSignatureLevel"), kernelObjectSectionSignatureSourceValue_);
    sourceFormLayout->addRow(QStringLiteral("ObjectTable"), kernelObjectObjectTableSourceValue_);
    sourceFormLayout->addRow(QStringLiteral("SectionObject"), kernelObjectSectionObjectSourceValue_);
    kernelObjectLayout_->addWidget(sourceGroup);

    QGroupBox* offsetGroup = new QGroupBox(QStringLiteral("EPROCESS 偏移"), kKernelObjectContent);
    QFormLayout* offsetFormLayout = new QFormLayout(offsetGroup);
    offsetFormLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    offsetFormLayout->setHorizontalSpacing(18);
    offsetFormLayout->setVerticalSpacing(6);

    kernelObjectProtectionOffsetValue_ = new QLabel(offsetGroup);
    kernelObjectSignatureOffsetValue_ = new QLabel(offsetGroup);
    kernelObjectSectionSignatureOffsetValue_ = new QLabel(offsetGroup);
    kernelObjectObjectTableOffsetValue_ = new QLabel(offsetGroup);
    kernelObjectSectionObjectOffsetValue_ = new QLabel(offsetGroup);
    offsetFormLayout->addRow(QStringLiteral("Protection"), kernelObjectProtectionOffsetValue_);
    offsetFormLayout->addRow(QStringLiteral("SignatureLevel"), kernelObjectSignatureOffsetValue_);
    offsetFormLayout->addRow(QStringLiteral("SectionSignatureLevel"), kernelObjectSectionSignatureOffsetValue_);
    offsetFormLayout->addRow(QStringLiteral("ObjectTable"), kernelObjectObjectTableOffsetValue_);
    offsetFormLayout->addRow(QStringLiteral("SectionObject"), kernelObjectSectionObjectOffsetValue_);
    kernelObjectLayout_->addWidget(offsetGroup);

    QGroupBox* sectionGroup = new QGroupBox(QStringLiteral("Section / ControlArea 映射关系"), kKernelObjectContent);
    QVBoxLayout* sectionGroupLayout = new QVBoxLayout(sectionGroup);
    sectionGroupLayout->setContentsMargins(8, 8, 8, 8);
    sectionGroupLayout->setSpacing(6);

    QHBoxLayout* sectionTopBarLayout = new QHBoxLayout();
    refreshSectionInfoButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("刷新 Section"), sectionGroup);
    refreshSectionInfoButton_->setToolTip(QStringLiteral("通过 R0 查询当前进程 SectionObject、ControlArea 和映射摘要"));
    sectionInfoStatusLabel_ = new QLabel(QStringLiteral("● 尚未刷新"), sectionGroup);
    sectionInfoStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(ksword_theme::textSecondaryHex()));
    sectionTopBarLayout->addWidget(refreshSectionInfoButton_);
    sectionTopBarLayout->addWidget(sectionInfoStatusLabel_, 1);
    sectionGroupLayout->addLayout(sectionTopBarLayout);

    sectionInfoOutput_ = new CodeEditorWidget(sectionGroup);
    sectionInfoOutput_->setReadOnly(true);
    sectionInfoOutput_->setText(QStringLiteral("Section/ControlArea 查询结果将在此处显示。"));
    sectionGroupLayout->addWidget(sectionInfoOutput_, 1);
    kernelObjectLayout_->addWidget(sectionGroup, 1);

    kernelObjectLayout_->addStretch(1);
}

void ProcessDetailWindow::initializeTokenSwitchTab()
{
    // Token settings page initialization:
    // - The first part provides common switch checkboxes (quick settings).
    // - The second part provides the raw NtSetInformationToken entry (covering all information classes).
    KLogEvent initTokenSwitchTabEvent;
    info << initTokenSwitchTabEvent
        << "[ProcessDetailWindow] initializeTokenSwitchTab: 构建完整令牌设置页面。"
        << eol;

    QWidget* const kTokenSwitchContent = createScrollableTabContent(
        tokenSwitchTab_,
        tokenSwitchLayout_,
        6,
        8);

    // Top toolbar button:
    // - Refresh switch: refreshes only the quick switch checkboxes.
    // - App switch: submit quick switch.
    // - Refresh All: Trigger a refresh of the 'full information enumeration' in the token detail page.
    QHBoxLayout* tokenSwitchTopBarLayout = new QHBoxLayout();
    refreshTokenSwitchButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), kTokenSwitchContent);
    refreshTokenSwitchButton_->setToolTip(QStringLiteral("刷新当前进程令牌的各项开关状态"));
    ksword_theme::applyStandardIconButtonMetrics(refreshTokenSwitchButton_);
    applyTokenSwitchButton_ = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), kTokenSwitchContent);
    applyTokenSwitchButton_->setToolTip(QStringLiteral("把下方复选框状态写回目标进程令牌"));
    ksword_theme::applyStandardIconButtonMetrics(applyTokenSwitchButton_);
    refreshTokenAllInfoButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), kTokenSwitchContent);
    refreshTokenAllInfoButton_->setToolTip(QStringLiteral("刷新完整令牌信息（包含全部 TokenInformationClass 枚举）"));
    ksword_theme::applyStandardIconButtonMetrics(refreshTokenAllInfoButton_);
    tokenSwitchStatusLabel_ = new QLabel(QStringLiteral("● 尚未刷新令牌开关"), kTokenSwitchContent);
    tokenSwitchStatusLabel_->setWordWrap(true);
    tokenSwitchStatusLabel_->setMinimumWidth(0);
    tokenSwitchStatusLabel_->setSizePolicy(
        QSizePolicy::Ignored,
        QSizePolicy::Preferred);
    tokenSwitchStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(ksword_theme::textSecondaryHex()));
    tokenSwitchTopBarLayout->addWidget(refreshTokenSwitchButton_);
    tokenSwitchTopBarLayout->addWidget(applyTokenSwitchButton_);
    tokenSwitchTopBarLayout->addWidget(refreshTokenAllInfoButton_);
    tokenSwitchTopBarLayout->addWidget(tokenSwitchStatusLabel_, 1);
    tokenSwitchLayout_->addLayout(tokenSwitchTopBarLayout);

    // Quick switch group:
    // - Corresponds to common Token boolean bits and MandatoryPolicy bits;
    // - Suitable for high-frequency modification scenarios requiring 'instant visibility + one-click application'.
    QGroupBox* tokenSwitchGroup = new QGroupBox(QStringLiteral("Token 快捷开关"), kTokenSwitchContent);
    QGridLayout* tokenSwitchGridLayout = new QGridLayout(tokenSwitchGroup);
    tokenSwitchGridLayout->setHorizontalSpacing(12);
    tokenSwitchGridLayout->setVerticalSpacing(8);

    tokenSandboxInertCheck_ = new QCheckBox(QStringLiteral("SandboxInert"), tokenSwitchGroup);
    tokenSandboxInertCheck_->setToolTip(QStringLiteral("TokenSandBoxInert：沙箱惰性开关，常用于兼容旧进程策略"));
    tokenVirtualizationAllowedCheck_ = new QCheckBox(QStringLiteral("VirtualizationAllowed"), tokenSwitchGroup);
    tokenVirtualizationAllowedCheck_->setToolTip(QStringLiteral("TokenVirtualizationAllowed：是否允许 UAC 虚拟化"));
    tokenVirtualizationEnabledCheck_ = new QCheckBox(QStringLiteral("VirtualizationEnabled"), tokenSwitchGroup);
    tokenVirtualizationEnabledCheck_->setToolTip(QStringLiteral("TokenVirtualizationEnabled：是否启用 UAC 虚拟化"));
    tokenUiAccessCheck_ = new QCheckBox(QStringLiteral("UIAccess"), tokenSwitchGroup);
    tokenUiAccessCheck_->setToolTip(QStringLiteral("TokenUIAccess：是否允许跨完整性级别访问部分 UI"));
    tokenMandatoryNoWriteUpCheck_ = new QCheckBox(QStringLiteral("MandatoryPolicy.NoWriteUp"), tokenSwitchGroup);
    tokenMandatoryNoWriteUpCheck_->setToolTip(QStringLiteral("TokenMandatoryPolicy 位 0：禁止低完整性向高完整性写入"));
    tokenMandatoryNewProcessMinCheck_ = new QCheckBox(QStringLiteral("MandatoryPolicy.NewProcessMin"), tokenSwitchGroup);
    tokenMandatoryNewProcessMinCheck_->setToolTip(QStringLiteral("TokenMandatoryPolicy 位 1：新进程最小化完整性策略"));

    tokenSwitchGridLayout->addWidget(tokenSandboxInertCheck_, 0, 0);
    tokenSwitchGridLayout->addWidget(tokenVirtualizationAllowedCheck_, 0, 1);
    tokenSwitchGridLayout->addWidget(tokenVirtualizationEnabledCheck_, 1, 0);
    tokenSwitchGridLayout->addWidget(tokenUiAccessCheck_, 1, 1);
    tokenSwitchGridLayout->addWidget(tokenMandatoryNoWriteUpCheck_, 2, 0);
    tokenSwitchGridLayout->addWidget(tokenMandatoryNewProcessMinCheck_, 2, 1);
    tokenSwitchLayout_->addWidget(tokenSwitchGroup);

    // Common information class (boolean semantics) group:
    // - These items are high-frequency classes from the TokenInformationClass dropdown;
    // - Read and write directly via checkboxes to reduce repetitive "select class + fill value" operations.
    QGroupBox* tokenCommonClassGroup =
        new QGroupBox(QStringLiteral("Token 常用信息类（布尔语义）"), kTokenSwitchContent);
    QGridLayout* tokenCommonClassGridLayout = new QGridLayout(tokenCommonClassGroup);
    tokenCommonClassGridLayout->setHorizontalSpacing(12);
    tokenCommonClassGridLayout->setVerticalSpacing(8);

    tokenHasRestrictionsCheck_ =
        new QCheckBox(QStringLiteral("HasRestrictions"), tokenCommonClassGroup);
    tokenHasRestrictionsCheck_->setToolTip(
        QStringLiteral("TokenHasRestrictions（class=21）：是否存在限制 SID / 限制策略"));
    tokenIsAppContainerCheck_ =
        new QCheckBox(QStringLiteral("IsAppContainer"), tokenCommonClassGroup);
    tokenIsAppContainerCheck_->setToolTip(
        QStringLiteral("TokenIsAppContainer（class=29）：当前令牌是否为 AppContainer"));
    tokenIsRestrictedCheck_ =
        new QCheckBox(QStringLiteral("IsRestricted"), tokenCommonClassGroup);
    tokenIsRestrictedCheck_->setToolTip(
        QStringLiteral("TokenIsRestricted（class=40）：当前令牌是否受限制"));
    tokenIsLessPrivilegedAppContainerCheck_ =
        new QCheckBox(QStringLiteral("IsLessPrivilegedAppContainer"), tokenCommonClassGroup);
    tokenIsLessPrivilegedAppContainerCheck_->setToolTip(
        QStringLiteral("TokenIsLessPrivilegedAppContainer（class=46）：是否为低权限 AppContainer"));
    tokenIsSandboxedCheck_ =
        new QCheckBox(QStringLiteral("IsSandboxed"), tokenCommonClassGroup);
    tokenIsSandboxedCheck_->setToolTip(
        QStringLiteral("TokenIsSandboxed（class=47）：当前令牌是否被沙箱化"));
    tokenIsAppSiloCheck_ =
        new QCheckBox(QStringLiteral("IsAppSilo"), tokenCommonClassGroup);
    tokenIsAppSiloCheck_->setToolTip(
        QStringLiteral("TokenIsAppSilo（class=51）：当前令牌是否属于 AppSilo"));

    tokenCommonClassGridLayout->addWidget(tokenHasRestrictionsCheck_, 0, 0);
    tokenCommonClassGridLayout->addWidget(tokenIsAppContainerCheck_, 0, 1);
    tokenCommonClassGridLayout->addWidget(tokenIsRestrictedCheck_, 1, 0);
    tokenCommonClassGridLayout->addWidget(tokenIsLessPrivilegedAppContainerCheck_, 1, 1);
    tokenCommonClassGridLayout->addWidget(tokenIsSandboxedCheck_, 2, 0);
    tokenCommonClassGridLayout->addWidget(tokenIsAppSiloCheck_, 2, 1);
    tokenSwitchLayout_->addWidget(tokenCommonClassGroup);

    // Raw set group:
    // - Allow the user to select any TokenInformationClass.
    // - Payload supports UInt32/UInt64/HexBytes and directly invokes NtSetInformationToken.
    QGroupBox* rawSetGroup = new QGroupBox(QStringLiteral("原始 NtSetInformationToken（全部信息类）"), kTokenSwitchContent);
    QGridLayout* rawSetLayout = new QGridLayout(rawSetGroup);
    rawSetLayout->setHorizontalSpacing(10);
    rawSetLayout->setVerticalSpacing(8);

    tokenRawInfoClassCombo_ = new QComboBox(rawSetGroup);
    tokenRawInfoClassCombo_->setToolTip(QStringLiteral("选择要传给 NtSetInformationToken 的 TokenInformationClass"));
    const auto kTokenInfoClassNameById = [](const int classId) -> QString
    {
        switch (classId)
        {
        case 1: return QStringLiteral("TokenUser");
        case 2: return QStringLiteral("TokenGroups");
        case 3: return QStringLiteral("TokenPrivileges");
        case 4: return QStringLiteral("TokenOwner");
        case 5: return QStringLiteral("TokenPrimaryGroup");
        case 6: return QStringLiteral("TokenDefaultDacl");
        case 7: return QStringLiteral("TokenSource");
        case 8: return QStringLiteral("TokenType");
        case 9: return QStringLiteral("TokenImpersonationLevel");
        case 10: return QStringLiteral("TokenStatistics");
        case 11: return QStringLiteral("TokenRestrictedSids");
        case 12: return QStringLiteral("TokenSessionId");
        case 13: return QStringLiteral("TokenGroupsAndPrivileges");
        case 14: return QStringLiteral("TokenSessionReference");
        case 15: return QStringLiteral("TokenSandBoxInert");
        case 16: return QStringLiteral("TokenAuditPolicy");
        case 17: return QStringLiteral("TokenOrigin");
        case 18: return QStringLiteral("TokenElevationType");
        case 19: return QStringLiteral("TokenLinkedToken");
        case 20: return QStringLiteral("TokenElevation");
        case 21: return QStringLiteral("TokenHasRestrictions");
        case 22: return QStringLiteral("TokenAccessInformation");
        case 23: return QStringLiteral("TokenVirtualizationAllowed");
        case 24: return QStringLiteral("TokenVirtualizationEnabled");
        case 25: return QStringLiteral("TokenIntegrityLevel");
        case 26: return QStringLiteral("TokenUIAccess");
        case 27: return QStringLiteral("TokenMandatoryPolicy");
        case 28: return QStringLiteral("TokenLogonSid");
        case 29: return QStringLiteral("TokenIsAppContainer");
        case 30: return QStringLiteral("TokenCapabilities");
        case 31: return QStringLiteral("TokenAppContainerSid");
        case 32: return QStringLiteral("TokenAppContainerNumber");
        case 33: return QStringLiteral("TokenUserClaimAttributes");
        case 34: return QStringLiteral("TokenDeviceClaimAttributes");
        case 35: return QStringLiteral("TokenRestrictedUserClaimAttributes");
        case 36: return QStringLiteral("TokenRestrictedDeviceClaimAttributes");
        case 37: return QStringLiteral("TokenDeviceGroups");
        case 38: return QStringLiteral("TokenRestrictedDeviceGroups");
        case 39: return QStringLiteral("TokenSecurityAttributes");
        case 40: return QStringLiteral("TokenIsRestricted");
        case 41: return QStringLiteral("TokenProcessTrustLevel");
        case 42: return QStringLiteral("TokenPrivateNameSpace");
        case 43: return QStringLiteral("TokenSingletonAttributes");
        case 44: return QStringLiteral("TokenBnoIsolation");
        case 45: return QStringLiteral("TokenChildProcessFlags");
        case 46: return QStringLiteral("TokenIsLessPrivilegedAppContainer");
        case 47: return QStringLiteral("TokenIsSandboxed");
        case 48: return QStringLiteral("TokenOriginatingProcessTrustLevel");
        case 49: return QStringLiteral("TokenLoggingInformation");
        case 50: return QStringLiteral("TokenLearningMode");
        case 51: return QStringLiteral("TokenIsAppSilo");
        default: return QStringLiteral("TokenClass%1").arg(classId);
        }
    };
    for (int classId = 1; classId <= 80; ++classId)
    {
        const QString kItemText = QStringLiteral("[%1] %2")
            .arg(classId)
            .arg(kTokenInfoClassNameById(classId));
        tokenRawInfoClassCombo_->addItem(kItemText, classId);
    }
    tokenRawInfoClassCombo_->setCurrentIndex(14);

    tokenRawInputModeCombo_ = new QComboBox(rawSetGroup);
    tokenRawInputModeCombo_->setToolTip(QStringLiteral("选择原始负载解释方式"));
    tokenRawInputModeCombo_->addItem(QStringLiteral("UInt32"), QStringLiteral("u32"));
    tokenRawInputModeCombo_->addItem(QStringLiteral("UInt64"), QStringLiteral("u64"));
    tokenRawInputModeCombo_->addItem(QStringLiteral("HexBytes"), QStringLiteral("hex"));

    tokenRawPayloadEdit_ = new QLineEdit(rawSetGroup);
    tokenRawPayloadEdit_->setPlaceholderText(QStringLiteral("示例：UInt32=1；UInt64=0x10；HexBytes=01 00 00 00"));
    tokenRawPayloadEdit_->setToolTip(QStringLiteral("原始输入内容，按当前输入模式解析后直接传给 NtSetInformationToken"));

    tokenRawApplyButton_ = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), rawSetGroup);
    tokenRawApplyButton_->setToolTip(QStringLiteral("应用原始 NtSetInformationToken 设置"));
    ksword_theme::applyStandardIconButtonMetrics(tokenRawApplyButton_);

    rawSetLayout->addWidget(new QLabel(QStringLiteral("信息类"), rawSetGroup), 0, 0);
    rawSetLayout->addWidget(tokenRawInfoClassCombo_, 0, 1, 1, 2);
    rawSetLayout->addWidget(new QLabel(QStringLiteral("输入模式"), rawSetGroup), 1, 0);
    rawSetLayout->addWidget(tokenRawInputModeCombo_, 1, 1, 1, 2);
    rawSetLayout->addWidget(new QLabel(QStringLiteral("原始负载"), rawSetGroup), 2, 0);
    rawSetLayout->addWidget(tokenRawPayloadEdit_, 2, 1);
    rawSetLayout->addWidget(tokenRawApplyButton_, 2, 2);
    tokenSwitchLayout_->addWidget(rawSetGroup);

    QLabel* tokenSwitchHintLabel = new QLabel(
        QStringLiteral("提示：可先点“刷新全部令牌信息”查看所有 TokenInformationClass 的当前状态，再按快捷或原始模式应用。"),
        kTokenSwitchContent);
    tokenSwitchHintLabel->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    tokenSwitchLayout_->addWidget(tokenSwitchHintLabel);
    tokenSwitchLayout_->addStretch(1);

    // Page style:
    // - Unify icon buttons with a blue skin.
    // - The original combo box settings use the same stroke/highlight style.
    const QString kButtonStyle = buildBlueButtonStyle();
    refreshTokenSwitchButton_->setStyleSheet(kButtonStyle);
    applyTokenSwitchButton_->setStyleSheet(kButtonStyle);
    refreshTokenAllInfoButton_->setStyleSheet(kButtonStyle);
    tokenRawApplyButton_->setStyleSheet(kButtonStyle);

    const QString kComboStyle = ksword_theme::themedComboBoxStyle();
    tokenRawInfoClassCombo_->setStyleSheet(kComboStyle);
    tokenRawInputModeCombo_->setStyleSheet(kComboStyle);
}

void ProcessDetailWindow::initializePebTab()
{
    // PEB page initialization: Display PEB address, parameter block, environment variables, etc.
    KLogEvent initPebTabEvent;
    info << initPebTabEvent
        << "[ProcessDetailWindow] initializePebTab: 构建 PEB 信息页面。"
        << eol;

    pebLayout_ = new QVBoxLayout(pebTab_);
    pebLayout_->setContentsMargins(6, 6, 6, 6);
    pebLayout_->setSpacing(6);

    QHBoxLayout* pebTopBarLayout = new QHBoxLayout();
    refreshPebButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), "刷新PEB", pebTab_);
    refreshPebButton_->setToolTip("异步刷新 PEB、命令行、当前目录、环境块与安全标志");
    applyPebEditButton_ = new QPushButton(QIcon(":/Icon/process_settings.svg"), QStringLiteral("应用修改"), pebTab_);
    applyPebEditButton_->setToolTip(QStringLiteral("把下方可编辑字段写回目标进程。字符串字段优先写入现有缓冲区；空间不足时会尝试远程分配新缓冲区。"));
    pebStatusLabel_ = new QLabel("● 尚未刷新", pebTab_);
    pebStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(ksword_theme::textSecondaryHex()));
    pebTopBarLayout->addWidget(refreshPebButton_);
    pebTopBarLayout->addWidget(applyPebEditButton_);
    pebTopBarLayout->addWidget(pebStatusLabel_, 1);
    pebLayout_->addLayout(pebTopBarLayout);

    QGroupBox* editableGroup = new QGroupBox(QStringLiteral("PEB 可编辑字段（R3 写入目标进程内存）"), pebTab_);
    QGridLayout* editableGrid = new QGridLayout(editableGroup);
    editableGrid->setContentsMargins(8, 8, 8, 8);
    editableGrid->setSpacing(6);

    pebTargetCombo_ = new QComboBox(editableGroup);
    pebTargetCombo_->addItem(QStringLiteral("NativePEB"), QStringLiteral("NativePEB"));
    pebTargetCombo_->addItem(QStringLiteral("Wow64PEB"), QStringLiteral("Wow64PEB"));
    pebTargetCombo_->setToolTip(QStringLiteral("选择写入 Native PEB 还是 Wow64 PEB。32 位目标通常需要同步修改 Wow64PEB。"));

    pebCommandLineEdit_ = new QLineEdit(editableGroup);
    pebImagePathEdit_ = new QLineEdit(editableGroup);
    pebCurrentDirectoryEdit_ = new QLineEdit(editableGroup);
    pebEnvironmentNameEdit_ = new QLineEdit(editableGroup);
    pebEnvironmentValueEdit_ = new QLineEdit(editableGroup);
    pebImageBaseEdit_ = new QLineEdit(editableGroup);
    pebAffinityMaskEdit_ = new QLineEdit(editableGroup);
    pebPriorityClassCombo_ = new QComboBox(editableGroup);

    pebCommandLineEdit_->setPlaceholderText(QStringLiteral("RTL_USER_PROCESS_PARAMETERS.CommandLine"));
    pebImagePathEdit_->setPlaceholderText(QStringLiteral("RTL_USER_PROCESS_PARAMETERS.ImagePathName"));
    pebCurrentDirectoryEdit_->setPlaceholderText(QStringLiteral("RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath"));
    pebEnvironmentNameEdit_->setPlaceholderText(QStringLiteral("例如 PATH / TEMP / 自定义变量名"));
    pebEnvironmentValueEdit_->setPlaceholderText(QStringLiteral("变量值；为空表示写成 NAME=，不会删除旧环境块条目"));
    pebImageBaseEdit_->setPlaceholderText(QStringLiteral("高级：PEB.ImageBaseAddress，例如 0x7C0000"));
    pebAffinityMaskEdit_->setPlaceholderText(QStringLiteral("进程亲和性掩码，例如 0xFFFFFFFF"));

    pebImageBaseEdit_->setToolTip(QStringLiteral("危险字段：只修改 PEB.ImageBaseAddress 指针，不会重映射模块。错误值可能误导目标进程或工具。"));
    pebAffinityMaskEdit_->setToolTip(QStringLiteral("调用 SetProcessAffinityMask，属于真实进程属性，不是 PEB 字段。"));

    pebPriorityClassCombo_->addItem(QStringLiteral("不修改"), 0u);
    pebPriorityClassCombo_->addItem(QStringLiteral("IDLE"), static_cast<unsigned int>(IDLE_PRIORITY_CLASS));
    pebPriorityClassCombo_->addItem(QStringLiteral("BELOW_NORMAL"), static_cast<unsigned int>(BELOW_NORMAL_PRIORITY_CLASS));
    pebPriorityClassCombo_->addItem(QStringLiteral("NORMAL"), static_cast<unsigned int>(NORMAL_PRIORITY_CLASS));
    pebPriorityClassCombo_->addItem(QStringLiteral("ABOVE_NORMAL"), static_cast<unsigned int>(ABOVE_NORMAL_PRIORITY_CLASS));
    pebPriorityClassCombo_->addItem(QStringLiteral("HIGH"), static_cast<unsigned int>(HIGH_PRIORITY_CLASS));
    pebPriorityClassCombo_->addItem(QStringLiteral("REALTIME"), static_cast<unsigned int>(REALTIME_PRIORITY_CLASS));

    editableGrid->addWidget(new QLabel(QStringLiteral("目标PEB"), editableGroup), 0, 0);
    editableGrid->addWidget(pebTargetCombo_, 0, 1);
    editableGrid->addWidget(new QLabel(QStringLiteral("CommandLine"), editableGroup), 1, 0);
    editableGrid->addWidget(pebCommandLineEdit_, 1, 1, 1, 3);
    editableGrid->addWidget(new QLabel(QStringLiteral("ImagePathName"), editableGroup), 2, 0);
    editableGrid->addWidget(pebImagePathEdit_, 2, 1, 1, 3);
    editableGrid->addWidget(new QLabel(QStringLiteral("CurrentDirectory"), editableGroup), 3, 0);
    editableGrid->addWidget(pebCurrentDirectoryEdit_, 3, 1, 1, 3);
    editableGrid->addWidget(new QLabel(QStringLiteral("环境变量名"), editableGroup), 4, 0);
    editableGrid->addWidget(pebEnvironmentNameEdit_, 4, 1);
    editableGrid->addWidget(new QLabel(QStringLiteral("环境变量值"), editableGroup), 4, 2);
    editableGrid->addWidget(pebEnvironmentValueEdit_, 4, 3);
    editableGrid->addWidget(new QLabel(QStringLiteral("ImageBaseAddress"), editableGroup), 5, 0);
    editableGrid->addWidget(pebImageBaseEdit_, 5, 1);
    editableGrid->addWidget(new QLabel(QStringLiteral("AffinityMask"), editableGroup), 5, 2);
    editableGrid->addWidget(pebAffinityMaskEdit_, 5, 3);
    editableGrid->addWidget(new QLabel(QStringLiteral("PriorityClass"), editableGroup), 6, 0);
    editableGrid->addWidget(pebPriorityClassCombo_, 6, 1);
    pebLayout_->addWidget(editableGroup, 0);

    pebDetailOutput_ = new CodeEditorWidget(pebTab_);
    pebDetailOutput_->setReadOnly(true);
    pebDetailOutput_->setText(QStringLiteral("PEB 与地址空间摘要将在此处显示。"));
    pebLayout_->addWidget(pebDetailOutput_, 1);

    // Read-only field descriptions are program-generated detail text; use a unified editor for instant redraw in English mode.
    pebReadonlyReasonOutput_ = new CodeEditorWidget(pebTab_);
    pebReadonlyReasonOutput_->setReadOnly(true);
    pebReadonlyReasonOutput_->setMaximumHeight(220);
    pebReadonlyReasonOutput_->setLocalizedText(QStringLiteral(
        "不可直接修改/不建议直接修改：\n"
        "- KernelCpuMs/UserCpuMs/WorkingSet/PrivateUsage/IO计数/PageFaultCount：系统统计计数，只能由内核/调度器/内存管理器更新。\n"
        "- VirtualAddressRegionPreview：地址空间枚举结果；应通过 VirtualAllocEx/VirtualProtectEx/Unmap/Map 等专门操作改变。\n"
        "- RegionCount/CommitBytes/MappedBytes/ImageBytes/PrivateBytes：统计结果，不是单一字段。\n"
        "- HeapCount/HeapBlock：需要堆管理器一致性，不在 PEB 页直接写。\n"
        "- ProcessParameters 指针/Environment 指针：本页会按需更新字符串字段/环境项，不建议手工乱改指针。"));
    pebLayout_->addWidget(pebReadonlyReasonOutput_, 0);

    const QString kButtonStyle = buildBlueButtonStyle();
    refreshPebButton_->setStyleSheet(kButtonStyle);
    applyPebEditButton_->setStyleSheet(kButtonStyle);
}

void ProcessDetailWindow::initializeKernelCallbackTab()
{
    // PEB.KernelCallbackTable independent audit page:
    // - Not bound to PEB large-text refresh; reads remote memory only when switching to this page.
    // - Table fixed to support copying cells, the current row, and all content.
    kernelCallbackLayout_ = new QVBoxLayout(kernelCallbackTab_);
    kernelCallbackLayout_->setContentsMargins(6, 6, 6, 6);
    kernelCallbackLayout_->setSpacing(6);

    auto* topBarLayout = new QHBoxLayout();
    refreshKernelCallbackButton_ = new QPushButton(
        QIcon(":/Icon/process_refresh.svg"),
        QStringLiteral("刷新内核回调表"),
        kernelCallbackTab_);
    refreshKernelCallbackButton_->setToolTip(QStringLiteral(
        "异步读取 PEB.KernelCallbackTable，并核对回调地址所属模块与内存保护属性。\n"
        "读取来源为 NativePEB 或 Wow64PEB 中的用户态内核回调表。"));
    refreshKernelCallbackButton_->setStyleSheet(buildBlueButtonStyle());
    topBarLayout->addWidget(refreshKernelCallbackButton_);

    kernelCallbackStatusLabel_ = new QLabel(QStringLiteral("● 尚未刷新"), kernelCallbackTab_);
    kernelCallbackStatusLabel_->setStyleSheet(buildStateLabelStyle(statusSecondaryColor(), 600));
    topBarLayout->addWidget(kernelCallbackStatusLabel_, 1);
    kernelCallbackLayout_->addLayout(topBarLayout);

    kernelCallbackTable_ = new ks::ui::VisibleTableWidget(kernelCallbackTab_);
    kernelCallbackTable_->setColumnCount(7);
    kernelCallbackTable_->setHorizontalHeaderLabels(QStringList()
        << QStringLiteral("索引")
        << QStringLiteral("回调名称")
        << QStringLiteral("地址")
        << QStringLiteral("模块")
        << QStringLiteral("模块偏移")
        << QStringLiteral("保护属性")
        << QStringLiteral("状态"));
    if (QTableWidgetItem* const kCallbackStateHeaderItem = kernelCallbackTable_->horizontalHeaderItem(6))
    {
        kCallbackStateHeaderItem->setToolTip(QStringLiteral(
            "非模块可执行地址、不可执行地址和读取失败项会标为异常。"));
    }
    kernelCallbackTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    kernelCallbackTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    kernelCallbackTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    kernelCallbackTable_->setAlternatingRowColors(true);
    kernelCallbackTable_->setSortingEnabled(true);
    kernelCallbackTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    kernelCallbackTable_->verticalHeader()->setVisible(false);
    kernelCallbackTable_->horizontalHeader()->setStretchLastSection(true);
    kernelCallbackTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    kernelCallbackTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    kernelCallbackTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    kernelCallbackTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    kernelCallbackTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    kernelCallbackTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    kernelCallbackTable_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    kernelCallbackLayout_->addWidget(kernelCallbackTable_, 1);

    connect(
        kernelCallbackTable_,
        &QTableWidget::customContextMenuRequested,
        this,
        [this](const QPoint& localPosition)
        {
            if (kernelCallbackTable_ == nullptr)
            {
                return;
            }

            if (QTableWidgetItem* clickedItem = kernelCallbackTable_->itemAt(localPosition))
            {
                kernelCallbackTable_->setCurrentItem(clickedItem);
            }

            QMenu menu(kernelCallbackTable_);
            menu.setStyleSheet(buildProcessDetailMenuStyle());
            QAction* copyCellAction = menu.addAction(QStringLiteral("复制当前单元格"));
            QAction* copyRowAction = menu.addAction(QStringLiteral("复制当前行"));
            QAction* copyAllAction = menu.addAction(QStringLiteral("复制全部"));
            const int kCurrentRow = kernelCallbackTable_->currentRow();
            const int kCurrentColumn = kernelCallbackTable_->currentColumn();
            copyCellAction->setEnabled(kCurrentRow >= 0 && kCurrentColumn >= 0);
            copyRowAction->setEnabled(kCurrentRow >= 0);
            copyAllAction->setEnabled(kernelCallbackTable_->rowCount() > 0);

            QAction* selectedAction = menu.exec(kernelCallbackTable_->viewport()->mapToGlobal(localPosition));
            if (selectedAction == nullptr)
            {
                return;
            }

            if (selectedAction == copyCellAction)
            {
                const QTableWidgetItem* item = kernelCallbackTable_->item(kCurrentRow, kCurrentColumn);
                QApplication::clipboard()->setText(item != nullptr ? item->text() : QString());
                return;
            }

            const auto kRowText = [this](const int rowIndex)
            {
                QStringList values;
                for (int columnIndex = 0; columnIndex < kernelCallbackTable_->columnCount(); ++columnIndex)
                {
                    const QTableWidgetItem* item = kernelCallbackTable_->item(rowIndex, columnIndex);
                    values << (item != nullptr ? item->text() : QString());
                }
                return values.join('\t');
            };

            if (selectedAction == copyRowAction)
            {
                QApplication::clipboard()->setText(kRowText(kCurrentRow));
                return;
            }

            QStringList allLines;
            QStringList headers;
            for (int columnIndex = 0; columnIndex < kernelCallbackTable_->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* headerItem = kernelCallbackTable_->horizontalHeaderItem(columnIndex);
                headers << (headerItem != nullptr ? headerItem->text() : QString());
            }
            allLines << headers.join('\t');
            for (int rowIndex = 0; rowIndex < kernelCallbackTable_->rowCount(); ++rowIndex)
            {
                allLines << kRowText(rowIndex);
            }
            QApplication::clipboard()->setText(allLines.join('\n'));
        });
}

void ProcessDetailWindow::initializeConnections()
{
    // After the page is constructed on demand, this function is called again. The local connect wrapper deduplicates by sender,
    // skipping controls that haven't been created yet and avoiding duplicate connections for the same signal on existing controls.
    const auto kConnect = [this](auto* sender, const auto signal, QObject* context, const auto& callback) {
        if (sender == nullptr || connectedSignalSources_.contains(sender))
        {
            return;
        }
        QObject::connect(sender, signal, context, callback);
        connectedSignalSources_.insert(sender);
    };

    // Connection initialization log: confirms that signals and slots for buttons on all created pages have been connected.
    KLogEvent initConnectionsEvent;
    info << initConnectionsEvent
        << "[ProcessDetailWindow] initializeConnections: 开始连接信号槽。"
        << eol;

    // Copy path button.
    kConnect(copyPathButton_, &QPushButton::clicked, this, [this]() {
        QApplication::clipboard()->setText(pathLineEdit_->text());
        KLogEvent logEvent;
        dbg << logEvent << "[ProcessDetailWindow] 复制程序路径, pid=" << baseRecord_.pid << eol;
    });

    // Open path button.
    kConnect(openPathFolderButton_, &QPushButton::clicked, this, [this]() {
        std::string detailText;
        const bool kActionOk = ks::process::openFolderByPath(baseRecord_.imagePath, &detailText);
        // Opening the path belongs to the same action chain; reuse the same KLogEvent to pass the result to the function.
        KLogEvent actionEvent;
        (kActionOk ? info : err) << actionEvent
            << "[ProcessDetailWindow] 打开程序路径, pid="
            << baseRecord_.pid
            << ", actionOk="
            << (kActionOk ? "true" : "false")
            << ", detail="
            << detailText
            << eol;
        showActionResultMessage("打开程序路径", kActionOk, detailText, actionEvent);
    });

    // Navigate to file details: forwarded by ProcessDock to mainWindow::openFileDetailDockByPath, reusing the non-modal detail window from FileDock.
    kConnect(openFileDetailButton_, &QPushButton::clicked, this, [this]() {
        const QString kImagePath = QString::fromStdString(baseRecord_.imagePath).trimmed();
        if (!kImagePath.isEmpty() && QFileInfo(kImagePath).isFile())
        {
            emit requestOpenFileDetailByPath(kImagePath);
        }
    });

    kConnect(refreshDetailOverviewButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncDetailOverviewRefresh();
    });

    // Copy command line button.
    kConnect(copyCommandButton_, &QPushButton::clicked, this, [this]() {
        QApplication::clipboard()->setText(commandLineEdit_->text());
        KLogEvent logEvent;
        dbg << logEvent << "[ProcessDetailWindow] 复制命令行, pid=" << baseRecord_.pid << eol;
    });

    // Button to navigate to parent process.
    kConnect(gotoParentButton_, &QPushButton::clicked, this, [this]() {
        const QVariant kParentPidVariant = gotoParentButton_->property("parent_pid");
        if (!kParentPidVariant.isValid())
        {
            return;
        }
        const std::uint32_t kParentPid = kParentPidVariant.toUInt();
        emit requestOpenProcessByPid(kParentPid);
    });

    // Jump Handle button: forwards the current PID to the external (mainWindow) to open the Handle Dock.
    kConnect(openHandleDockButton_, &QPushButton::clicked, this, [this]() {
        if (baseRecord_.pid == 0)
        {
            return;
        }
        emit requestOpenHandleDockByPid(baseRecord_.pid);
    });
    kConnect(detailOpenHandleDockButton_, &QPushButton::clicked, this, [this]() {
        if (baseRecord_.pid != 0U)
        {
            emit requestOpenHandleDockByPid(baseRecord_.pid);
        }
    });
    kConnect(openMemoryDockButton_, &QPushButton::clicked, this, [this]() {
        if (baseRecord_.pid != 0U)
        {
            emit requestOpenMemoryDockByPid(baseRecord_.pid);
        }
    });
    kConnect(openNetworkDockButton_, &QPushButton::clicked, this, [this]() {
        if (baseRecord_.pid != 0U)
        {
            emit requestOpenNetworkDockByPid(baseRecord_.pid);
        }
    });
    kConnect(openWindowDockButton_, &QPushButton::clicked, this, [this]() {
        if (baseRecord_.pid != 0U)
        {
            emit requestOpenWindowDockByPid(baseRecord_.pid);
        }
    });

    // Thread detail refresh button.
    kConnect(refreshThreadInspectButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncThreadInspectRefresh();
    });

    // Token page refresh button.
    kConnect(refreshTokenButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncTokenRefresh();
    });

    // Token switch page refresh button: re-read the current token switch value and synchronize the checkbox.
    kConnect(refreshTokenSwitchButton_, &QPushButton::clicked, this, [this]() {
        refreshTokenSwitchStates();
    });

    // Token switch page Apply button: write the checkbox state back to the target token.
    kConnect(applyTokenSwitchButton_, &QPushButton::clicked, this, [this]() {
        applyTokenSwitchStates();
    });

    // Token Settings page "Refresh All Info" button: triggers a full refresh of token details (including all information class enums).
    kConnect(refreshTokenAllInfoButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncTokenRefresh();
    });

    // Token Settings page 'Apply Raw' button: directly call NtSetInformationToken using the current class + payload.
    kConnect(tokenRawApplyButton_, &QPushButton::clicked, this, [this]() {
        applyRawTokenInformation();
    });

    // PEB page refresh button.
    kConnect(refreshPebButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncPebRefresh();
    });
    kConnect(applyPebEditButton_, &QPushButton::clicked, this, [this]() {
        applyPebEditableFields();
    });
    kConnect(refreshKernelCallbackButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncKernelCallbackRefresh();
    });
    kConnect(pebTargetCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        if (pebDetailOutput_ != nullptr)
        {
            populatePebEditableFieldsFromText(pebDetailOutput_->text());
        }
    });

    // Section/ControlArea refresh button: pass only the PID to ArkDriverClient to avoid UI sending kernel addresses back.
    kConnect(refreshSectionInfoButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncSectionRefresh();
    });

    // Process hotkey page refresh button.
    kConnect(refreshHotkeyButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncHotkeyRefresh();
    });

    // Keyboard page refresh button: refreshes hotkeys and keyboard hooks together.
    kConnect(refreshKeyboardButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncKeyboardRefresh();
    });

    // The navigation area is responsible for page selection; QTabWidget remains the sole source of page state.
    // This ensures that external calls to setCurrentWidget and internal navigation via keyboard pages both synchronize the button state.
    kConnect(tabNavigationButtonGroup_, &QButtonGroup::idClicked, this, [this](const int tabIndex) {
        if (tabWidget_ != nullptr && tabIndex >= 0 && tabIndex < tabWidget_->count())
        {
            tabWidget_->setCurrentIndex(tabIndex);
        }
    });

    // Trigger heavy refresh and update the left navigation selection state only on the first tab switch.
    // - The process detail window open path constructs only the UI and lightweight text.
    // - This allows the user to see the window immediately; background scanning will not concurrently occupy the thread pool and UI backfill.
    kConnect(tabWidget_, &QTabWidget::currentChanged, this, [this](const int tabIndex) {
        if (tabWidget_ != nullptr)
        {
            ensureTabContentInitialized(tabWidget_->widget(tabIndex));
        }
        if (tabNavigationButtonGroup_ != nullptr)
        {
            if (QAbstractButton* navigationButton = tabNavigationButtonGroup_->button(tabIndex))
            {
                navigationButton->setChecked(true);
            }
        }
        requestInitialRefreshForCurrentTab();
    });

    // Operation page button connections:
    // - Termination actions are unified via the dropdown dispatcher to avoid retaining multiple redundant large buttons.
    // - Other control actions remain unchanged and use their original execution functions.
    kConnect(executeTerminateActionButton_, &QPushButton::clicked, this, [this]() { executeSelectedTerminateAction(); });
    // Use clicked instead of toggled: toggled emits even for programmatic setChecked calls. Since refresh
    // operations call setChecked with the latest reading each time, using toggled would repeatedly
    // trigger suspend and resume actions within the refresh cycle. clicked emits only on user clicks.
    kConnect(suspendProcessCheck_, &QCheckBox::clicked, this, [this](const bool checked) {
        if (checked) { executeSuspendProcessAction(); }
        else { executeResumeProcessAction(); }
    });
    kConnect(setCriticalButton_, &QPushButton::clicked, this, [this]() { executeSetCriticalAction(true); });
    kConnect(clearCriticalButton_, &QPushButton::clicked, this, [this]() { executeSetCriticalAction(false); });
    kConnect(applyPriorityButton_, &QPushButton::clicked, this, [this]() { executeSetPriorityAction(); });
    kConnect(actionPrivilegeRefreshButton_, &QPushButton::clicked, this, [this]() { requestAsyncActionPrivilegeRefresh(); });
    kConnect(applyActionPrivilegeR3Button_, &QPushButton::clicked, this, [this]() { executeApplyActionPrivileges(false); });
    kConnect(applyActionPrivilegeR0Button_, &QPushButton::clicked, this, [this]() { executeApplyActionPrivileges(true); });
    kConnect(openProcessFolderButton_, &QPushButton::clicked, this, [this]() { executeOpenProcessFolderAction(); });
    kConnect(refreshPplProtectionButton_, &QPushButton::clicked, this, [this]() { executeRefreshPplProtectionLevelAction(); });
    kConnect(efficiencyModeCheck_, &QCheckBox::clicked, this, [this](const bool checked) {
        executeSetEfficiencyModeAction(checked);
    });
    kConnect(r0TerminateProcessButton_, &QPushButton::clicked, this, [this]() { executeR0TerminateProcessAction(); });
    kConnect(r0SuspendProcessButton_, &QPushButton::clicked, this, [this]() { executeR0SuspendProcessAction(); });

    // R0 PPL menu:
    // - Menu content is consistent with the process list context menu.
    // - Dynamically create a local QMenu on each button click to avoid holding stale QAction objects during the window's lifecycle.
    kConnect(r0SetPplButton_, &QPushButton::clicked, this, [this]() {
        QMenu r0PplMenu(this);
        r0PplMenu.setStyleSheet(buildProcessDetailMenuStyle());
        QAction* noneAction = r0PplMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_critical.svg")),
            QStringLiteral("关闭进程保护 (0x00)"));
        noneAction->setData(0x00U);

        // Isomorphic with the process list right-click menu: the signer list is shared, with PPL (Type=1) and PP (Type=2) displayed in two separate groups.
        struct ProcessProtectionSignerPreset
        {
            int signerValue = 0;           // signerValue: Signer value.
            const char* signerName = "";   // signerName: Menu display name.
            const char* meaningText = "";  // meaningText: Menu display explanation.
        };
        const ProcessProtectionSignerPreset kPresetList[] =
        {
            { 1, "Authenticode", "签名代码（Authenticode）" },
            { 2, "CodeGen", "动态代码生成" },
            { 3, "Antimalware", "反恶意软件" },
            { 4, "Lsa", "本地安全机构" },
            { 5, "Windows", "Windows 组件" },
            { 6, "WinTcb", "可信计算基础（最高）" },
            { 7, "WinSystem", "系统 signer（System 进程同级）" }
        };
        struct ProcessProtectionTypePreset
        {
            unsigned int typeValue = 0;            // typeValue: PS_PROTECTION type bits.
            const char* sectionTextUtf8 = "";      // sectionTextUtf8: group title.
        };
        const ProcessProtectionTypePreset kTypeList[] =
        {
            { 1U, "PPL 轻量保护（Type=1）" },
            { 2U, "PP 完整保护（Type=2，更强）" }
        };
        for (const ProcessProtectionTypePreset& typeEntry : kTypeList)
        {
            r0PplMenu.addSection(QString::fromUtf8(typeEntry.sectionTextUtf8));
            for (const ProcessProtectionSignerPreset& presetEntry : kPresetList)
            {
                const unsigned int kProtectionLevel =
                    (static_cast<unsigned int>(presetEntry.signerValue) << 4U) | typeEntry.typeValue;
                const QString kProtectionLevelHexText = QStringLiteral("0x%1")
                    .arg(kProtectionLevel, 2, 16, QChar('0'))
                    .toUpper();
                QAction* presetAction = r0PplMenu.addAction(
                    buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_critical.svg")),
                    QStringLiteral("%1 (%2) → %3 [%4]")
                    .arg(QString::fromLatin1(presetEntry.signerName))
                    .arg(presetEntry.signerValue)
                    .arg(QString::fromUtf8(presetEntry.meaningText))
                    .arg(kProtectionLevelHexText));
                presetAction->setData(kProtectionLevel);
            }
        }

        QAction* selectedAction = r0PplMenu.exec(r0SetPplButton_->mapToGlobal(QPoint(0, r0SetPplButton_->height())));
        if (selectedAction == nullptr)
        {
            return;
        }
        const unsigned int kLevelValue = selectedAction->data().toUInt();
        if (kLevelValue > 0xFFU)
        {
            KLogEvent actionEvent;
            warn << actionEvent
                << "[ProcessDetailWindow] R0 进程保护层级菜单值无效, levelValue="
                << kLevelValue
                << eol;
            showActionResultMessage(
                QStringLiteral("R0设置进程保护层级"),
                false,
                std::string("invalid PPL level value"),
                actionEvent);
            return;
        }
        executeR0SetPplProtectionAction(
            static_cast<std::uint8_t>(kLevelValue),
            selectedAction->text());
    });

    // R0: Restorable hidden menu
    // - Sends recoverable hide/recover requests via ArkDriverClient;
    // - Menu items explicitly include tooltips describing specific kernel-side change strategies.
    kConnect(r0VisibilityButton_, &QPushButton::clicked, this, [this]() {
        QMenu visibilityMenu(this);
        visibilityMenu.setStyleSheet(buildProcessDetailMenuStyle());
        QAction* hideUnlinkOnlyAction = visibilityMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_suspend.svg")),
            QStringLiteral("隐藏当前进程：只断链"));
        QAction* hidePatchPidOnlyAction = visibilityMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_uncritical.svg")),
            QStringLiteral("隐藏当前进程：只改PID"));
        QAction* hideLegacyBothAction = visibilityMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_critical.svg")),
            QStringLiteral("隐藏当前进程：改PID+断链(旧版高风险)"));
        visibilityMenu.addSeparator();
        QAction* unhideProcessAction = visibilityMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_resume.svg")),
            QStringLiteral("取消隐藏当前进程"));
        QAction* clearHiddenAction = visibilityMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/log_clear.svg")),
            QStringLiteral("清空全部隐藏标记"));
        hideUnlinkOnlyAction->setToolTip(QStringLiteral("只摘除 ActiveProcessLinks，不修改 PID；更容易按原 PID 找回和恢复。"));
        hidePatchPidOnlyAction->setToolTip(QStringLiteral("只修改 UniqueProcessId，不摘链；高风险，可能影响按原 PID 查找目标。"));
        hideLegacyBothAction->setToolTip(QStringLiteral("兼容旧版：同时修改 UniqueProcessId 并摘除 ActiveProcessLinks；风险最高。"));
        unhideProcessAction->setToolTip(QStringLiteral("恢复由 Ksword 记录的 UniqueProcessId 和进程链表位置。"));
        clearHiddenAction->setToolTip(QStringLiteral("恢复所有由 Ksword 摘链的进程，并清空驱动内记录。"));

        QAction* selectedAction = visibilityMenu.exec(r0VisibilityButton_->mapToGlobal(QPoint(0, r0VisibilityButton_->height())));
        if (selectedAction == hideUnlinkOnlyAction)
        {
            executeR0SetProcessHiddenAction(true, KSWORD_ARK_PROCESS_VISIBILITY_FLAG_UNLINK_ACTIVE_LIST);
        }
        else if (selectedAction == hidePatchPidOnlyAction)
        {
            executeR0SetProcessHiddenAction(true, KSWORD_ARK_PROCESS_VISIBILITY_FLAG_PATCH_UNIQUE_PID);
        }
        else if (selectedAction == hideLegacyBothAction)
        {
            executeR0SetProcessHiddenAction(true, KSWORD_ARK_PROCESS_VISIBILITY_FLAG_LEGACY_BOTH);
        }
        else if (selectedAction == unhideProcessAction)
        {
            executeR0SetProcessHiddenAction(false);
        }
        else if (selectedAction == clearHiddenAction)
        {
            executeR0ClearProcessHiddenAction();
        }
    });

    // R0 danger flags / DKOM menu:
    // - Align BreakOnTermination/APC/DKOM capabilities with the list right-click menu.
    // - High-risk confirmation is performed inside the action function; the menu itself is only responsible for dispatching.
    kConnect(r0DangerFlagsButton_, &QPushButton::clicked, this, [this]() {
        QMenu dangerMenu(this);
        dangerMenu.setStyleSheet(buildProcessDetailMenuStyle());
        QAction* enableBreakAction = dangerMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_critical.svg")),
            QStringLiteral("启用 BreakOnTermination"));
        QAction* disableBreakAction = dangerMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_uncritical.svg")),
            QStringLiteral("关闭 BreakOnTermination"));
        QAction* disableApcAction = dangerMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_suspend.svg")),
            QStringLiteral("禁止APC插入(现有线程)"));
        dangerMenu.addSeparator();
        QAction* dkomCidRemoveAction = dangerMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_uncritical.svg")),
            QStringLiteral("DKOM从PspCidTable删除"));
        enableBreakAction->setToolTip(QStringLiteral("调用 ZwSetInformationProcess(ProcessBreakOnTermination=1)。"));
        disableBreakAction->setToolTip(QStringLiteral("调用 ZwSetInformationProcess(ProcessBreakOnTermination=0)。"));
        disableApcAction->setToolTip(QStringLiteral("清除目标进程现有线程 ETHREAD ApcQueueable 位。"));
        dkomCidRemoveAction->setToolTip(QStringLiteral("从 PspCidTable 清零目标 EPROCESS 的 CID 表项；高风险且不可通过本菜单恢复。"));

        QAction* selectedAction = dangerMenu.exec(r0DangerFlagsButton_->mapToGlobal(QPoint(0, r0DangerFlagsButton_->height())));
        if (selectedAction == enableBreakAction)
        {
            executeR0SetBreakOnTerminationAction(true);
        }
        else if (selectedAction == disableBreakAction)
        {
            executeR0SetBreakOnTerminationAction(false);
        }
        else if (selectedAction == disableApcAction)
        {
            executeR0DisableApcInsertionAction();
        }
        else if (selectedAction == dkomCidRemoveAction)
        {
            executeR0DkomRemoveFromCidTableAction();
        }
    });
    kConnect(injectDllButton_, &QPushButton::clicked, this, [this]() { executeInjectDllAction(); });
    kConnect(injectShellcodeButton_, &QPushButton::clicked, this, [this]() { executeInjectShellcodeAction(); });

    // Browse DLL path.
    kConnect(browseDllButton_, &QPushButton::clicked, this, [this]() {
        const QString kFilePath = QFileDialog::getOpenFileName(
            this,
            "选择要注入的 DLL",
            QString(),
            "DLL Files (*.dll);;All Files (*)");
        if (!kFilePath.isEmpty())
        {
            dllPathLineEdit_->setText(kFilePath);
        }
    });

    // Browse shellcode file path.
    kConnect(browseShellcodeButton_, &QPushButton::clicked, this, [this]() {
        const QString kFilePath = QFileDialog::getOpenFileName(
            this,
            "选择 shellcode 文件",
            QString(),
            "Binary Files (*.bin *.dat);;All Files (*)");
        if (!kFilePath.isEmpty())
        {
            shellcodePathLineEdit_->setText(kFilePath);
        }
    });

    // Module refresh button.
    kConnect(refreshModuleButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDetailWindow] 用户点击“刷新模块”, pid=" << baseRecord_.pid
            << eol;
        requestAsyncModuleRefresh(true);
    });

    // DLL hijacking detection always runs in the background in read-only mode; it does not reuse injection or loading paths.
    kConnect(dllHijackScanButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncDllHijackScan();
    });

    // Injection trace inspection is also read-only collection. Both buttons use identical criteria (the normalized profile
    // is the same), differing only in comparison scope: Depth compares the entire executable image range, making it slower.
    kConnect(injectionTraceButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncInjectionTraceScan(false);
    });
    kConnect(injectionTraceDeepButton_, &QPushButton::clicked, this, [this]() {
        requestAsyncInjectionTraceScan(true);
    });

    // Module table right-click menu.
    kConnect(moduleTable_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showModuleContextMenu(localPosition);
    });
}

void ProcessDetailWindow::refreshDetailTabTexts()
{
    // Detail refresh entry log: Records the current PID and process name.
    KLogEvent refreshDetailEvent;
    dbg << refreshDetailEvent
        << "[ProcessDetailWindow] refreshDetailTabTexts: pid="
        << baseRecord_.pid
        << ", processName="
        << baseRecord_.processName
        << eol;

    // Top title and icon.
    processTitleLabel_->setText(
        QString("%1  (PID: %2)")
        .arg(QString::fromStdString(baseRecord_.processName.empty() ? "Unknown" : baseRecord_.processName))
        .arg(baseRecord_.pid));
    processIconLabel_->setPixmap(resolveProcessIcon(baseRecord_.imagePath, 40).pixmap(40, 40));

    // Path and command line.
    QString processPathText = QString::fromStdString(baseRecord_.imagePath);
    if (processPathText.trimmed().isEmpty() && baseRecord_.pid != 0)
    {
        // Fall back to re-query the path to prevent the UI from showing an empty path.
        processPathText = QString::fromStdString(ks::process::queryProcessPathByPid(baseRecord_.pid));
        if (!processPathText.trimmed().isEmpty())
        {
            baseRecord_.imagePath = processPathText.toStdString();
        }
    }
    pathLineEdit_->setText(processPathText.trimmed().isEmpty() ? "-" : processPathText);
    commandLineEdit_->setText(QString::fromStdString(baseRecord_.commandLine.empty() ? "-" : baseRecord_.commandLine));
    if (detailOpenHandleDockButton_ != nullptr)
    {
        detailOpenHandleDockButton_->setVisible(baseRecord_.pid != 0);
    }
    if (openFileDetailButton_ != nullptr)
    {
        const QFileInfo kProcessFileInfo(processPathText);
        openFileDetailButton_->setEnabled(kProcessFileInfo.exists() && kProcessFileInfo.isFile());
    }

    // Assign detailed fields.
    detailStartTimeValue_->setText(QString::fromStdString(baseRecord_.startTimeText.empty() ? "-" : baseRecord_.startTimeText));
    detailUserValue_->setText(QString::fromStdString(baseRecord_.userName.empty() ? "-" : baseRecord_.userName));
    detailAdminValue_->setText(baseRecord_.isAdmin ? "■ 是" : "■ 否");
    detailAdminValue_->setStyleSheet(
        baseRecord_.isAdmin
        ? buildStateLabelStyle(signatureTrustedColor(), 700)
        : buildStateLabelStyle(signatureUntrustedColor(), 700));
    detailArchitectureValue_->setText(QString::fromStdString(baseRecord_.architectureText.empty() ? "Unknown" : baseRecord_.architectureText));
    detailPriorityValue_->setText(QString::fromStdString(baseRecord_.priorityText.empty() ? "Unknown" : baseRecord_.priorityText));
    detailSessionValue_->setText(QString::number(baseRecord_.sessionId));
    detailThreadCountValue_->setText(QString::number(baseRecord_.threadCount));
    detailHandleCountValue_->setText(QString::number(baseRecord_.handleCount));
    detailCpuValue_->setText(formatDoubleText(baseRecord_.cpuPercent, 2) + "%");
    detailCpuCoreValue_->setText(formatDoubleText(baseRecord_.cpuCorePercent, 2) + "%");
    detailRamValue_->setText(formatDoubleText(baseRecord_.ramMB, 1) + " MB");
    detailDiskValue_->setText(formatDoubleText(baseRecord_.diskMBps, 2) + " MB/s");
    detailSignatureValue_->setText(QString::fromStdString(baseRecord_.signatureState.empty() ? "Unknown" : baseRecord_.signatureState));

    // High-frequency fields in the current process snapshot are filled directly first; other fields are overwritten by the asynchronous runtime snapshot.
    const auto kSetExtraValue = [this](const QString& key, const QString& valueText) {
        QLabel* const kValueLabel = detailExtraValues_.value(key, nullptr);
        if (kValueLabel != nullptr)
        {
            const QString kDisplayText = valueText.trimmed().isEmpty() ? detailUnavailableText() : valueText;
            const bool kEnabledState =
                kDisplayText == QStringLiteral("Enabled") ||
                kDisplayText == QStringLiteral("Enabled (permanent)");
            const bool kDisabledState = kDisplayText == QStringLiteral("Disabled");
            if (kEnabledState || kDisabledState)
            {
                kValueLabel->setText(QString(QChar(0x25A0)) + QLatin1Char(' ') + kDisplayText);
                kValueLabel->setStyleSheet(buildStateLabelStyle(
                    kEnabledState ? signatureTrustedColor() : signatureUntrustedColor(),
                    700));
            }
            else
            {
                kValueLabel->setText(kDisplayText);
                kValueLabel->setStyleSheet(QString());
            }
        }
    };
    kSetExtraValue(QStringLiteral("pid"), QString::number(baseRecord_.pid));
    kSetExtraValue(QStringLiteral("parent_pid"),
        baseRecord_.parentPid != 0U ? QString::number(baseRecord_.parentPid) : detailUnavailableText());
    kSetExtraValue(QStringLiteral("uptime"), detailUptimeText(baseRecord_.creationTime100ns));
    kSetExtraValue(QStringLiteral("gpu"), formatDoubleText(baseRecord_.gpuPercent, 2) + "%");
    kSetExtraValue(QStringLiteral("network_rx"), formatDoubleText(baseRecord_.netRxKBps, 2) + " KB/s");
    kSetExtraValue(QStringLiteral("network_tx"), formatDoubleText(baseRecord_.netTxKBps, 2) + " KB/s");
    if (baseRecord_.dynamicCountersReady)
    {
        kSetExtraValue(QStringLiteral("working_set"), detailBytesText(baseRecord_.rawWorkingSetBytes));
        kSetExtraValue(QStringLiteral("private_commit"), detailBytesText(baseRecord_.rawPrivateBytes));
    }
    else
    {
        kSetExtraValue(QStringLiteral("working_set"), detailUnavailableText());
        kSetExtraValue(QStringLiteral("private_commit"), detailUnavailableText());
    }
    kSetExtraValue(
        QStringLiteral("efficiency_mode"),
        baseRecord_.efficiencyModeSupported
            ? detailBoolText(baseRecord_.efficiencyModeEnabled)
            : detailUnavailableText());

    // The two switches' checked states refresh based on the same reading. If they are not synchronized, the switch remains stuck at the value when the window opened,
    // while suspension might have been triggered elsewhere (e.g., right-click menu, other tools), causing the interface to display contradictory information.
    //
    // Display as unchecked when the status is unknown: processStateKnown is only false in pathological cases like
    // buffer overflows; normal processes are always detectable, so this is not using a default value to fake a reading.
    if (suspendProcessCheck_ != nullptr)
    {
        suspendProcessCheck_->setChecked(
            baseRecord_.processStateKnown && baseRecord_.processSuspended);
    }
    if (efficiencyModeCheck_ != nullptr)
    {
        efficiencyModeCheck_->setChecked(
            baseRecord_.efficiencyModeSupported && baseRecord_.efficiencyModeEnabled);
    }
    if (baseRecord_.protectionLevelKnown && !baseRecord_.protectionLevelText.empty())
    {
        kSetExtraValue(QStringLiteral("ppl_protection"), QString::fromStdString(baseRecord_.protectionLevelText));
    }
    for (auto resultIt = detailOverviewResult_.values.cbegin();
         resultIt != detailOverviewResult_.values.cend();
         ++resultIt)
    {
        kSetExtraValue(resultIt.key(), resultIt.value());
    }

    if (!baseRecord_.signatureTrusted && baseRecord_.signatureState != "Pending")
    {
        detailSignatureValue_->setStyleSheet(
            buildStateLabelStyle(signatureUntrustedColor(), 700));
    }
    else if (baseRecord_.signatureTrusted)
    {
        detailSignatureValue_->setStyleSheet(
            buildStateLabelStyle(signatureTrustedColor(), 700));
    }
    else
    {
        detailSignatureValue_->setStyleSheet(
            buildStateLabelStyle(statusSecondaryColor(), 600));
    }

    // Refresh parent process section.
    refreshParentProcessSection();
    refreshKernelObjectTabTexts();
    updateWindowTitle();

    // Detail refresh completion log: confirms core fields have been rendered to the UI.
    KLogEvent refreshDetailFinishEvent;
    dbg << refreshDetailFinishEvent
        << "[ProcessDetailWindow] refreshDetailTabTexts: 完成, signatureState="
        << baseRecord_.signatureState
        << ", user="
        << baseRecord_.userName
        << eol;
}

void ProcessDetailWindow::refreshKernelObjectTabTexts()
{
    // Kernel object tab refresh:
    // - All fields are sourced from the current ProcessRecord cache.
    // - Avoids requesting R0 during UI refresh to prevent the details window from inadvertently triggering kernel enumeration.
    if (kernelObjectTab_ == nullptr)
    {
        return;
    }

    const bool kProtectionPresent =
        (baseRecord_.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT) != 0U;
    const bool kSignaturePresent =
        (baseRecord_.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SIGNATURE_LEVEL_PRESENT) != 0U;
    const bool kSectionSignaturePresent =
        (baseRecord_.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SECTION_SIGNATURE_LEVEL_PRESENT) != 0U;
    const bool kObjectTableAvailable =
        (baseRecord_.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE) != 0U;
    const bool kSectionObjectAvailable =
        (baseRecord_.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE) != 0U;

    if (kernelObjectR0StatusValue_ != nullptr)
    {
        kernelObjectR0StatusValue_->setText(detailProcessR0StatusText(baseRecord_.r0Status));
        kernelObjectR0StatusValue_->setStyleSheet(
            buildStateLabelStyle(
                baseRecord_.r0Status == KSWORD_ARK_PROCESS_R0_STATUS_OK
                ? statusIdleColor()
                : statusWarningColor(),
                700));
    }

    if (kernelObjectCapabilityValue_ != nullptr)
    {
        kernelObjectCapabilityValue_->setText(detailProcessCapabilityText(baseRecord_.r0DynDataCapabilityMask));
    }
    if (kernelObjectImagePathValue_ != nullptr)
    {
        kernelObjectImagePathValue_->setText(
            QString::fromStdString(baseRecord_.r0ImagePath.empty() ? std::string("-") : baseRecord_.r0ImagePath));
    }

    if (kernelObjectHandleTableValue_ != nullptr)
    {
        kernelObjectHandleTableValue_->setText(detailProcessPointerText(
            QStringLiteral("HandleTable available"),
            kObjectTableAvailable,
            baseRecord_.r0ObjectTableAddress,
            baseRecord_.r0ObjectTableSource));
        kernelObjectHandleTableValue_->setStyleSheet(
            buildStateLabelStyle(kObjectTableAvailable ? statusIdleColor() : statusSecondaryColor(), 700));
    }
    if (kernelObjectSectionObjectValue_ != nullptr)
    {
        kernelObjectSectionObjectValue_->setText(detailProcessPointerText(
            QStringLiteral("SectionObject available"),
            kSectionObjectAvailable,
            baseRecord_.r0SectionObjectAddress,
            baseRecord_.r0SectionObjectSource));
        kernelObjectSectionObjectValue_->setStyleSheet(
            buildStateLabelStyle(kSectionObjectAvailable ? statusIdleColor() : statusSecondaryColor(), 700));
    }

    if (kernelObjectProtectionValue_ != nullptr)
    {
        kernelObjectProtectionValue_->setText(kProtectionPresent
            ? detailProcessByteHexText(baseRecord_.r0Protection)
            : QStringLiteral("Unavailable"));
    }
    if (kernelObjectSignatureValue_ != nullptr)
    {
        kernelObjectSignatureValue_->setText(kSignaturePresent
            ? detailProcessByteHexText(baseRecord_.r0SignatureLevel)
            : QStringLiteral("Unavailable"));
    }
    if (kernelObjectSectionSignatureValue_ != nullptr)
    {
        kernelObjectSectionSignatureValue_->setText(kSectionSignaturePresent
            ? detailProcessByteHexText(baseRecord_.r0SectionSignatureLevel)
            : QStringLiteral("Unavailable"));
    }

    if (kernelObjectSessionSourceValue_ != nullptr) kernelObjectSessionSourceValue_->setText(detailProcessFieldSourceText(baseRecord_.r0SessionSource));
    if (kernelObjectImagePathSourceValue_ != nullptr) kernelObjectImagePathSourceValue_->setText(detailProcessFieldSourceText(baseRecord_.r0ImagePathSource));
    if (kernelObjectProtectionSourceValue_ != nullptr) kernelObjectProtectionSourceValue_->setText(detailProcessFieldSourceText(baseRecord_.r0ProtectionSource));
    if (kernelObjectSignatureSourceValue_ != nullptr) kernelObjectSignatureSourceValue_->setText(detailProcessFieldSourceText(baseRecord_.r0SignatureLevelSource));
    if (kernelObjectSectionSignatureSourceValue_ != nullptr) kernelObjectSectionSignatureSourceValue_->setText(detailProcessFieldSourceText(baseRecord_.r0SectionSignatureLevelSource));
    if (kernelObjectObjectTableSourceValue_ != nullptr) kernelObjectObjectTableSourceValue_->setText(detailProcessFieldSourceText(baseRecord_.r0ObjectTableSource));
    if (kernelObjectSectionObjectSourceValue_ != nullptr) kernelObjectSectionObjectSourceValue_->setText(detailProcessFieldSourceText(baseRecord_.r0SectionObjectSource));

    if (kernelObjectProtectionOffsetValue_ != nullptr) kernelObjectProtectionOffsetValue_->setText(detailProcessOffsetText(baseRecord_.r0ProtectionOffset));
    if (kernelObjectSignatureOffsetValue_ != nullptr) kernelObjectSignatureOffsetValue_->setText(detailProcessOffsetText(baseRecord_.r0SignatureLevelOffset));
    if (kernelObjectSectionSignatureOffsetValue_ != nullptr) kernelObjectSectionSignatureOffsetValue_->setText(detailProcessOffsetText(baseRecord_.r0SectionSignatureLevelOffset));
    if (kernelObjectObjectTableOffsetValue_ != nullptr) kernelObjectObjectTableOffsetValue_->setText(detailProcessOffsetText(baseRecord_.r0ObjectTableOffset));
    if (kernelObjectSectionObjectOffsetValue_ != nullptr) kernelObjectSectionObjectOffsetValue_->setText(detailProcessOffsetText(baseRecord_.r0SectionObjectOffset));
}

void ProcessDetailWindow::refreshParentProcessSection()
{
    // Parent process section refresh log: record the parent PID.
    KLogEvent refreshParentEvent;
    dbg << refreshParentEvent
        << "[ProcessDetailWindow] refreshParentProcessSection: parentPid="
        << baseRecord_.parentPid
        << eol;

    // The 'Go to Parent Process' button is hidden by default and only displayed if the parent process still exists.
    gotoParentButton_->setVisible(false);
    gotoParentButton_->setProperty("parent_pid", QVariant());

    if (baseRecord_.parentPid == 0)
    {
        parentInfoLabel_->setText("无父进程信息");
        parentIconLabel_->setPixmap(QIcon(":/Icon/process_main.svg").pixmap(20, 20));
        return;
    }

    const std::uint32_t kParentPid = baseRecord_.parentPid;
    const std::string kParentName = ks::process::getProcessNameByPid(kParentPid);
    const bool kParentAlive = !kParentName.empty();

    if (kParentAlive)
    {
        parentInfoLabel_->setText(
            QString("%1 (PID: %2)")
            .arg(QString::fromStdString(kParentName))
            .arg(kParentPid));
        const std::string kParentPath = ks::process::queryProcessPathByPid(kParentPid);
        parentIconLabel_->setPixmap(resolveProcessIcon(kParentPath, 20).pixmap(20, 20));
        gotoParentButton_->setVisible(true);
        gotoParentButton_->setProperty("parent_pid", QVariant::fromValue(kParentPid));
        KLogEvent refreshParentAliveEvent;
        dbg << refreshParentAliveEvent
            << "[ProcessDetailWindow] refreshParentProcessSection: 父进程可访问, parentPid="
            << kParentPid
            << eol;
    }
    else
    {
        parentInfoLabel_->setText(QString("父进程已退出或不可访问 (PID: %1)").arg(kParentPid));
        parentIconLabel_->setPixmap(QIcon(":/Icon/process_main.svg").pixmap(20, 20));
        KLogEvent refreshParentDeadEvent;
        info << refreshParentDeadEvent
            << "[ProcessDetailWindow] refreshParentProcessSection: 父进程不可访问, parentPid="
            << kParentPid
            << eol;
    }
}

void ProcessDetailWindow::updateWindowTitle()
{
    // Title update log: Helps troubleshoot title confusion in multi-window scenarios.
    KLogEvent updateTitleEvent;
    dbg << updateTitleEvent
        << "[ProcessDetailWindow] updateWindowTitle: pid="
        << baseRecord_.pid
        << eol;

    setWindowTitle(
        QString("进程详细信息 - %1 (PID %2)")
        .arg(QString::fromStdString(baseRecord_.processName.empty() ? "Unknown" : baseRecord_.processName))
        .arg(baseRecord_.pid));
}
