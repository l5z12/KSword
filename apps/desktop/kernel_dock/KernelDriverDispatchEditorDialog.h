#pragma once

#include <QDialog>
#include <QString>

#include <cstdint>

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

// Generic DriverObject.MajorFunction editor.
// UI is responsible for clearly warning about consequences; R0 protocol does not restrict target driver types or target address ownership.
class KernelDriverDispatchEditorDialog final : public QDialog
{
public:
    explicit KernelDriverDispatchEditorDialog(
        const QString& driverObjectName,
        QWidget* parent = nullptr);

private:
    void initializeUi();
    void refreshDriverSnapshot();
    bool refreshSelectedTransaction();
    void applySelectedDispatch();
    void restoreSelectedDispatch();
    void abandonSelectedRecord();
    void setActionsEnabled(bool enabled);
    void setStatus(const QString& text, const QString& colorHex);

    int selectedRow() const;
    std::uint32_t selectedMajorFunction() const;

    static QString pointerText(std::uint64_t address);
    static QString ntStatusText(long status);
    static QString majorFunctionName(std::uint32_t majorFunction);
    static bool parsePointer(const QString& text, std::uint64_t& addressOut);

    QString requestedDriverName_;
    QString canonicalDriverName_;
    QLabel* riskLabel_ = nullptr;
    QLabel* identityLabel_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTableWidget* table_ = nullptr;
    QLineEdit* desiredAddressEdit_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QPushButton* querySlotButton_ = nullptr;
    QPushButton* applyButton_ = nullptr;
    QPushButton* restoreButton_ = nullptr;
    QPushButton* abandonButton_ = nullptr;

    std::uint64_t moduleBase_ = 0;
    std::uint64_t driverObjectAddress_ = 0;
    std::uint64_t currentDispatchAddress_ = 0;
    std::uint32_t generation_ = 0;
    std::uint32_t responseFlags_ = 0;
};
