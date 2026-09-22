#pragma once

#include <QWidget>

#include <cstdint>

class QLabel;
class QLineEdit;
class KernelIoctlBitLayoutWidget;

// KernelIoctlDecoderTab：
// - Purpose: Decompose 32-bit Windows IOCTL control codes into Device, Function, Access, and Method;
// - Invocation: Created directly as the IOCTLS sub-page of the KernelDock 'I/O Management' tab;
// - Input/Output: User inputs a hexadecimal control code; the page synchronously outputs field values and the CTL_CODE bit layout.
class KernelIoctlDecoderTab final : public QWidget
{
public:
    // Constructor:
    // - Input parent: Qt parent widget;
    // - Processing: Create hex input, read-only parse fields, and bit layout diagrams.
    // - Returns: No explicit return value; the control can be added to a QTabWidget immediately after construction.
    explicit KernelIoctlDecoderTab(QWidget* parent = nullptr);
    ~KernelIoctlDecoderTab() override = default;

private:
    // initializeUi：
    // - Inputs: None;
    // - Processing: Create the left-side field form and right-side CTL_CODE bit layout according to the reference diagram.
    // - Returns: Nothing.
    void initializeUi();

    // updateDecodedFields：
    // - Input inputText: 1 to 8-digit hexadecimal text, optionally prefixed with 0x;
    // - Processing: Validate and parse the four CTL_CODE fields while refreshing status and bit layout;
    // - Returns: Nothing.
    void updateDecodedFields(const QString& inputText);

    // normalizeInput：
    // - Input: read current input field;
    // - Processing: normalize valid values to uppercase 8-digit hexadecimal with 0x prefix upon edit completion.
    // - Returns: Nothing.
    void normalizeInput();

    // formatNumericField：
    // - Input: value is the field numeric value, hexWidth is the hexadecimal display width;
    // - Processing: Generate both hexadecimal and decimal text simultaneously;
    // - Returns: String suitable for display in read-only fields.
    static QString formatNumericField(std::uint32_t value, int hexWidth);

    // accessName：
    // - Input accessValue: The two Access bits of the CTL_CODE;
    // - Returns: The corresponding FILE_*_ACCESS constant name.
    static QString accessName(std::uint32_t accessValue);

    // methodName：
    // - Input methodValue: Two Method bits of the CTL_CODE;
    // - Returns: The corresponding METHOD_* constant name.
    static QString methodName(std::uint32_t methodValue);

    QLineEdit* codeEdit_ = nullptr;         // m_codeEdit: User-input 32-bit hexadecimal IOCTL.
    QLineEdit* deviceEdit_ = nullptr;       // m_deviceEdit: DeviceType bitfield parsing result.
    QLineEdit* functionEdit_ = nullptr;     // m_functionEdit: Function bitfield parsing result.
    QLineEdit* accessEdit_ = nullptr;       // m_accessEdit: Access bitfield and constant names.
    QLineEdit* methodEdit_ = nullptr;       // m_methodEdit: Method bitfield and constant name.
    QLabel* statusLabel_ = nullptr;         // m_statusLabel: Displays status input and Common/Custom bit hints.
    KernelIoctlBitLayoutWidget* bitLayoutWidget_ = nullptr; // m_bitLayoutWidget: CTL_CODE bit layout diagram.
};
