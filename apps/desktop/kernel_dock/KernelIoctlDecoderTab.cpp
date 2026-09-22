#include "KernelIoctlDecoderTab.h"

#include "KernelDock.h"
#include "../Theme.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPaintEvent>
#include <QPainter>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QVBoxLayout>

#include <array>

using ksword::kernel_dock_internal::kernelText;

// KernelIoctlBitLayoutWidget：
// - Purpose: Draw a scale from bit 31 to 0, and mark partitions for Common, Device, Access, Custom, Function,
//   and Method according to the 1/15/2/1/11/2 bit layout of CTL_CODE, consistent with the reference issue diagram.
// - Input/Output: setCode receives the parsing state; paintEvent is responsible solely for theming the read-only display.
class KernelIoctlBitLayoutWidget final : public QWidget
{
public:
    explicit KernelIoctlBitLayoutWidget(QWidget* parent = nullptr)
        : QWidget(parent)
    {
        setMinimumSize(560, 190);
        setToolTip(kernelText(
            "kernel.ioctl_decoder.layout.tooltip",
            QStringLiteral("CTL_CODE：Common[31]、Device[30:16]、Access[15:14]、Custom[13]、Function[12:2]、Method[1:0]")));
    }

    // setCode：
    // - Input codeValue: 32-bit control code; valid: whether the current input is complete and valid.
    // - Processing: Cache the state and request a redraw.
    // - Returns: Nothing.
    void setCode(const std::uint32_t codeValue, const bool valid)
    {
        if (codeValue_ == codeValue && valid_ == valid)
        {
            return;
        }
        codeValue_ = codeValue;
        valid_ = valid;
        update();
    }

protected:
    // paintEvent：
    // - Input event: Qt paint event; the event itself requires no additional reading;
    // - Handling: Draw proportional segments, current value, legend, and Common/Custom flags.
    // - Returns: Nothing.
    void paintEvent(QPaintEvent* event) override
    {
        Q_UNUSED(event);

        // painter handles all vector rendering; enables anti-aliasing to prevent blurry borders after scaling.
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.fillRect(rect(), ksword_theme::surfaceColor());

        // diagramRect reserves space for top bit numbering and bottom legend, with a fixed 32-bit cell area in the middle.
        const QRectF kDiagramRect = QRectF(rect()).adjusted(18.0, 34.0, -18.0, -86.0);
        if (kDiagramRect.width() <= 0.0 || kDiagramRect.height() <= 0.0)
        {
            return;
        }

        struct Segment
        {
            int highBit = 0;              // highBit: Highest bit of the current segment.
            int lowBit = 0;               // lowBit: Lowest bit of the current segment.
            QString labelText;            // labelText: Section name under the theme language.
            QColor accentColor;           // accentColor: Theme accent color distinguishing the six bitfields.
        };

        // segments are strictly ordered from bit 31 down to bit 0 per the reference diagram; Common/Custom occupy a single
        // column. The left side (Device/Function) still displays the full 16/12-bit parameters of the standard CTL_CODE.
        const std::array<Segment, 6> kSegments = {{
            { 31, 31,
                kernelText("kernel.ioctl_decoder.flag.common", QStringLiteral("Common")),
                ksword_theme::accentColor(ksword_theme::AccentRole::kRed) },
            { 30, 16,
                kernelText("kernel.ioctl_decoder.field.device", QStringLiteral("Device")),
                ksword_theme::primaryAccentColor() },
            { 15, 14,
                kernelText("kernel.ioctl_decoder.field.access", QStringLiteral("Access")),
                ksword_theme::accentColor(ksword_theme::AccentRole::kGreen) },
            { 13, 13,
                kernelText("kernel.ioctl_decoder.flag.custom", QStringLiteral("Custom")),
                ksword_theme::accentColor(ksword_theme::AccentRole::kYellow) },
            { 12, 2,
                kernelText("kernel.ioctl_decoder.field.function", QStringLiteral("Function")),
                ksword_theme::accentColor(ksword_theme::AccentRole::kOrange) },
            { 1, 0,
                kernelText("kernel.ioctl_decoder.field.method", QStringLiteral("Method")),
                ksword_theme::accentColor(ksword_theme::AccentRole::kPurple) }
        }};

        // Uses a compact font for bit numbers so that 31..0 remain visible bit-by-bit in narrow windows.
        const QFont kBaseFont = painter.font();
        QFont bitNumberFont = kBaseFont;
        bitNumberFont.setPointSizeF(qMax(6.0, bitNumberFont.pointSizeF() - 3.0));
        painter.setFont(bitNumberFont);

        const qreal kBitCellWidth = kDiagramRect.width() / 32.0;
        for (int displayIndex = 0; displayIndex < 32; ++displayIndex)
        {
            const int kBitIndex = 31 - displayIndex;
            const Segment* ownerSegment = nullptr;
            for (const Segment& segment : kSegments)
            {
                if (kBitIndex <= segment.highBit && kBitIndex >= segment.lowBit)
                {
                    ownerSegment = &segment;
                    break;
                }
            }
            if (ownerSegment == nullptr)
            {
                continue;
            }

            const qreal kCellLeft =
                kDiagramRect.left() + kBitCellWidth * static_cast<qreal>(displayIndex);
            const qreal kCellRight = displayIndex == 31
                ? kDiagramRect.right()
                : kDiagramRect.left() +
                    kBitCellWidth * static_cast<qreal>(displayIndex + 1);
            const QRectF kCellRect(
                kCellLeft,
                kDiagramRect.top(),
                kCellRight - kCellLeft,
                kDiagramRect.height());
            painter.setPen(QPen(ownerSegment->accentColor, 1.0));
            painter.setBrush(ksword_theme::withAlpha(
                ownerSegment->accentColor,
                valid_ ? 64 : 24));
            painter.drawRect(kCellRect);

            painter.setPen(ksword_theme::textSecondaryColor());
            painter.drawText(
                QRectF(kCellRect.left(), kDiagramRect.top() - 25.0, kCellRect.width(), 20.0),
                Qt::AlignCenter,
                QString::number(kBitIndex));

            painter.setPen(ksword_theme::textPrimaryColor());
            painter.drawText(
                kCellRect.adjusted(1.0, 1.0, -1.0, -1.0),
                Qt::AlignCenter,
                valid_
                    ? QString::number((codeValue_ >> kBitIndex) & 0x1U)
                    : QStringLiteral("—"));
        }

        // Restore the legend to the original font size and provide full names and bit ranges for the six fields.
        painter.setFont(kBaseFont);

        // The legend uses fixed-width six columns, unaffected by the narrow segment limitation caused by Common/Custom having only one digit.
        const qreal kLegendTop = kDiagramRect.bottom() + 12.0;
        const qreal kLegendWidth = kDiagramRect.width() / static_cast<qreal>(kSegments.size());
        QFont legendFont = painter.font();
        legendFont.setBold(false);
        painter.setFont(legendFont);
        for (std::size_t index = 0U; index < kSegments.size(); ++index)
        {
            const Segment& segment = kSegments[index];
            const QRectF kLegendRect(
                kDiagramRect.left() + kLegendWidth * static_cast<qreal>(index),
                kLegendTop,
                kLegendWidth,
                22.0);
            painter.fillRect(
                QRectF(kLegendRect.left() + 4.0, kLegendRect.top() + 6.0, 10.0, 10.0),
                segment.accentColor);
            painter.setPen(ksword_theme::textPrimaryColor());
            painter.drawText(
                kLegendRect.adjusted(18.0, 0.0, -2.0, 0.0),
                Qt::AlignVCenter | Qt::AlignLeft,
                QStringLiteral("%1 [%2:%3]")
                    .arg(segment.labelText)
                    .arg(segment.highBit)
                    .arg(segment.lowBit));
        }

        // Common is bit 31, Custom is bit 13; they occupy the most significant bits of the Device and Function fields, respectively.
        const QString kCommonText = kernelText("kernel.ioctl_decoder.flag.common", QStringLiteral("Common"));
        const QString kCustomText = kernelText("kernel.ioctl_decoder.flag.custom", QStringLiteral("Custom"));
        const QString kFlagText = valid_
            ? QStringLiteral("%1(bit 31)=%2    %3(bit 13)=%4")
                .arg(kCommonText)
                .arg((codeValue_ >> 31U) & 0x1U)
                .arg(kCustomText)
                .arg((codeValue_ >> 13U) & 0x1U)
            : QStringLiteral("%1(bit 31)=—    %2(bit 13)=—").arg(kCommonText, kCustomText);
        painter.setPen(ksword_theme::textSecondaryColor());
        painter.drawText(
            QRectF(kDiagramRect.left(), kLegendTop + 26.0, kDiagramRect.width(), 22.0),
            Qt::AlignCenter,
            kFlagText);
    }

private:
    std::uint32_t codeValue_ = 0U; // m_codeValue: Most recent valid 32-bit control code or cleared value.
    bool valid_ = false;           // m_valid: Determines whether to display field values; when false, only structure placeholders are shown.
};

KernelIoctlDecoderTab::KernelIoctlDecoderTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelIoctlDecoderTab::initializeUi()
{
    // rootLayout manages the description, left and right columns, and status hints; the page itself performs no kernel calls.
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(12, 12, 12, 12);
    rootLayout->setSpacing(10);

    auto* descriptionLabel = new QLabel(
        kernelText(
            "kernel.ioctl_decoder.description",
            QStringLiteral("输入 32 位 IOCTL 控制码，实时解析 CTL_CODE 字段并显示位布局。")),
        this);
    descriptionLabel->setWordWrap(true);
    descriptionLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:13px;").arg(ksword_theme::textSecondaryHex()));
    rootLayout->addWidget(descriptionLabel);

    // contentLayout: Places the field form and bit layout side by side, maintaining the layout ratio consistent with the issue reference image.
    auto* contentLayout = new QHBoxLayout();
    contentLayout->setSpacing(12);
    auto* decoderGroup = new QGroupBox(
        kernelText("kernel.ioctl_decoder.group.fields", QStringLiteral("控制码字段")),
        this);
    auto* fieldLayout = new QFormLayout(decoderGroup);
    fieldLayout->setContentsMargins(14, 16, 14, 14);
    fieldLayout->setHorizontalSpacing(10);
    fieldLayout->setVerticalSpacing(10);
    fieldLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);

    // createOutputEdit uniformly generates non-editable result boxes to avoid inconsistent theme states across the four fields.
    const auto kCreateOutputEdit = [decoderGroup]() -> QLineEdit*
    {
        auto* outputEdit = new QLineEdit(decoderGroup);
        outputEdit->setReadOnly(true);
        outputEdit->setText(QStringLiteral("—"));
        outputEdit->setStyleSheet(QStringLiteral(
            "QLineEdit{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:5px 8px;}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex()));
        return outputEdit;
    };

    codeEdit_ = new QLineEdit(decoderGroup);
    codeEdit_->setClearButtonEnabled(true);
    codeEdit_->setPlaceholderText(
        kernelText("kernel.ioctl_decoder.input.placeholder", QStringLiteral("例如：0x222004")));
    codeEdit_->setToolTip(
        kernelText("kernel.ioctl_decoder.input.tooltip", QStringLiteral("输入 0 到 FFFFFFFF，可选 0x 前缀")));
    deviceEdit_ = kCreateOutputEdit();
    functionEdit_ = kCreateOutputEdit();
    accessEdit_ = kCreateOutputEdit();
    methodEdit_ = kCreateOutputEdit();

    fieldLayout->addRow(
        kernelText("kernel.ioctl_decoder.input.label", QStringLiteral("IOCTL（十六进制）：")),
        codeEdit_);
    fieldLayout->addRow(
        kernelText("kernel.ioctl_decoder.form.device", QStringLiteral("Device：")),
        deviceEdit_);
    fieldLayout->addRow(
        kernelText("kernel.ioctl_decoder.form.function", QStringLiteral("Function：")),
        functionEdit_);
    fieldLayout->addRow(
        kernelText("kernel.ioctl_decoder.form.access", QStringLiteral("Access：")),
        accessEdit_);
    fieldLayout->addRow(
        kernelText("kernel.ioctl_decoder.form.method", QStringLiteral("Method：")),
        methodEdit_);

    auto* layoutGroup = new QGroupBox(
        kernelText("kernel.ioctl_decoder.group.layout", QStringLiteral("CTL_CODE 位布局")),
        this);
    auto* bitLayout = new QVBoxLayout(layoutGroup);
    bitLayout->setContentsMargins(8, 8, 8, 8);
    bitLayoutWidget_ = new KernelIoctlBitLayoutWidget(layoutGroup);
    bitLayout->addWidget(bitLayoutWidget_, 1);

    contentLayout->addWidget(decoderGroup, 5);
    contentLayout->addWidget(layoutGroup, 7);
    rootLayout->addLayout(contentLayout, 1);

    statusLabel_ = new QLabel(
        kernelText("kernel.ioctl_decoder.status.empty", QStringLiteral("请输入 32 位 IOCTL 控制码。")),
        this);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    rootLayout->addWidget(statusLabel_);

    // textChanged provides real-time parsing; editingFinished only normalizes display without altering field semantics.
    connect(codeEdit_, &QLineEdit::textChanged, this, [this](const QString& inputText)
    {
        updateDecodedFields(inputText);
    });
    connect(codeEdit_, &QLineEdit::editingFinished, this, [this]()
    {
        normalizeInput();
    });
    updateDecodedFields(QString());
}

void KernelIoctlDecoderTab::updateDecodedFields(const QString& inputText)
{
    // normalizedText removes leading/trailing whitespace and the optional 0x prefix; subsequent parsing reads strictly as hexadecimal.
    QString normalizedText = inputText.trimmed();
    if (normalizedText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        normalizedText.remove(0, 2);
    }

    if (normalizedText.isEmpty())
    {
        deviceEdit_->setText(QStringLiteral("—"));
        functionEdit_->setText(QStringLiteral("—"));
        accessEdit_->setText(QStringLiteral("—"));
        methodEdit_->setText(QStringLiteral("—"));
        statusLabel_->setText(
            kernelText("kernel.ioctl_decoder.status.empty", QStringLiteral("请输入 32 位 IOCTL 控制码。")));
        statusLabel_->setStyleSheet(
            QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
        bitLayoutWidget_->setCode(0U, false);
        return;
    }

    // parsedValue uses a 64-bit temporary to detect overflow; the final valid value must fit entirely within the 32-bit range.
    static const QRegularExpression kExactHexCodeExpression(
        QStringLiteral("^[0-9A-Fa-f]{1,8}$"));
    const bool kInputShapeOk =
        kExactHexCodeExpression.match(normalizedText).hasMatch();
    bool parseOk = false;
    const qulonglong kParsedValue = kInputShapeOk
        ? normalizedText.toULongLong(&parseOk, 16)
        : 0ULL;
    if (!kInputShapeOk || !parseOk || kParsedValue > 0xFFFFFFFFULL)
    {
        deviceEdit_->setText(QStringLiteral("—"));
        functionEdit_->setText(QStringLiteral("—"));
        accessEdit_->setText(QStringLiteral("—"));
        methodEdit_->setText(QStringLiteral("—"));
        statusLabel_->setText(kernelText(
            "kernel.ioctl_decoder.status.invalid",
            QStringLiteral("输入无效：请输入 1 至 8 位十六进制控制码。")));
        statusLabel_->setStyleSheet(
            QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::errorHex()));
        bitLayoutWidget_->setCode(0U, false);
        return;
    }

    // The four local variables strictly correspond to the Microsoft CTL_CODE macro to prevent UI and protocol bit definition offsets.
    const std::uint32_t kCodeValue = static_cast<std::uint32_t>(kParsedValue);
    const std::uint32_t kDeviceValue = (kCodeValue >> 16U) & 0xFFFFU;
    const std::uint32_t kAccessValue = (kCodeValue >> 14U) & 0x3U;
    const std::uint32_t kFunctionValue = (kCodeValue >> 2U) & 0xFFFU;
    const std::uint32_t kMethodValue = kCodeValue & 0x3U;

    deviceEdit_->setText(formatNumericField(kDeviceValue, 4));
    functionEdit_->setText(formatNumericField(kFunctionValue, 3));
    accessEdit_->setText(
        QStringLiteral("0x%1 · %2").arg(kAccessValue, 1, 16).arg(accessName(kAccessValue)).toUpper());
    methodEdit_->setText(
        QStringLiteral("0x%1 · %2").arg(kMethodValue, 1, 16).arg(methodName(kMethodValue)).toUpper());

    const std::uint32_t kCommonBit = (kCodeValue >> 31U) & 0x1U;
    const std::uint32_t kCustomBit = (kCodeValue >> 13U) & 0x1U;
    statusLabel_->setText(
        kernelText(
            "kernel.ioctl_decoder.status.valid",
            QStringLiteral("解析完成：Common=%1，Custom=%2。"))
            .arg(kCommonBit)
            .arg(kCustomBit));
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::successHex()));
    bitLayoutWidget_->setCode(kCodeValue, true);
}

void KernelIoctlDecoderTab::normalizeInput()
{
    // normalizedText shares the same prefix rules as real-time parsing; the input box is updated only when the input is fully valid.
    QString normalizedText = codeEdit_->text().trimmed();
    if (normalizedText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        normalizedText.remove(0, 2);
    }

    static const QRegularExpression kExactHexCodeExpression(
        QStringLiteral("^[0-9A-Fa-f]{1,8}$"));
    const bool kInputShapeOk =
        kExactHexCodeExpression.match(normalizedText).hasMatch();
    bool parseOk = false;
    const qulonglong kParsedValue = kInputShapeOk
        ? normalizedText.toULongLong(&parseOk, 16)
        : 0ULL;
    if (!kInputShapeOk || !parseOk || kParsedValue > 0xFFFFFFFFULL)
    {
        return;
    }

    // signalBlocker prevents normalized text from triggering two intermediate parses, then explicitly refreshes the final result once.
    const QString kFormattedText = QStringLiteral("0x%1")
        .arg(kParsedValue, 8, 16, QLatin1Char('0'))
        .toUpper();
    const QSignalBlocker kSignalBlocker(codeEdit_);
    codeEdit_->setText(kFormattedText);
    updateDecodedFields(kFormattedText);
}

QString KernelIoctlDecoderTab::formatNumericField(
    const std::uint32_t value,
    const int hexWidth)
{
    return QStringLiteral("0x%1 (%2)")
        .arg(value, hexWidth, 16, QLatin1Char('0'))
        .arg(value)
        .toUpper();
}

QString KernelIoctlDecoderTab::accessName(const std::uint32_t accessValue)
{
    switch (accessValue & 0x3U)
    {
    case 0U:
        return QStringLiteral("FILE_ANY_ACCESS");
    case 1U:
        return QStringLiteral("FILE_READ_ACCESS");
    case 2U:
        return QStringLiteral("FILE_WRITE_ACCESS");
    case 3U:
        return QStringLiteral("FILE_READ_ACCESS | FILE_WRITE_ACCESS");
    default:
        return QStringLiteral("FILE_ANY_ACCESS");
    }
}

QString KernelIoctlDecoderTab::methodName(const std::uint32_t methodValue)
{
    switch (methodValue & 0x3U)
    {
    case 0U:
        return QStringLiteral("METHOD_BUFFERED");
    case 1U:
        return QStringLiteral("METHOD_IN_DIRECT");
    case 2U:
        return QStringLiteral("METHOD_OUT_DIRECT");
    case 3U:
        return QStringLiteral("METHOD_NEITHER");
    default:
        return QStringLiteral("METHOD_BUFFERED");
    }
}
