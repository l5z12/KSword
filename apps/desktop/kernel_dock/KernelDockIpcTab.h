#pragma once

// ============================================================
// KernelDockIpcTab.h
// Purpose:
// 1) Provides a read-only IPC view.
// 2) Aggregate NamedPipe, ALPC, and communication object enumeration pages.
// 3) Do not expose any write paths or destructive actions.
// ============================================================

#include "../Framework.h"
#include "../../../shared/ark_client/ArkDriverTypes.h"

#include <QWidget>

#include <cstdint>

class CodeEditorWidget;
class QLabel;
class QLineEdit;
class QPushButton;
class QHBoxLayout;
class QTableWidget;
class QTabWidget;

class KernelDockIpcTab final : public QWidget
{
public:
    explicit KernelDockIpcTab(QWidget* parent = nullptr);
    ~KernelDockIpcTab() override = default;

private:
    void initializeUi();
    void initializeConnections();
    void initializeAlpcPage();
    void refreshAlpcQuery();
    void applyIpcSummaryResult();
    void applyAlpcQueryResult();
    QString buildAlpcDetail(int rowIndex) const;
    void updateAlpcDetailForRow(int rowIndex);
    QString buildIpcSummaryDetail(int rowIndex) const;
    void updateIpcSummaryDetailForRow(int rowIndex);
    void copyIpcSummaryCurrentRow() const;
    void copyAlpcCurrentRow() const;
    static QString formatHex32(std::uint32_t value);
    static QString formatHex64(std::uint64_t value);
    static QString statusText(long statusValue);

private:
    QTabWidget* innerTabWidget_ = nullptr;

    QWidget* alpcPage_ = nullptr;
    QHBoxLayout* alpcToolbarLayout_ = nullptr;
    QLineEdit* alpcProcessIdEdit_ = nullptr;
    QLineEdit* alpcHandleEdit_ = nullptr;
    QPushButton* alpcRefreshButton_ = nullptr;
    QLabel* alpcStatusLabel_ = nullptr;
    QTableWidget* ipcSummaryTable_ = nullptr;
    QTableWidget* alpcTable_ = nullptr;
    CodeEditorWidget* alpcDetailEditor_ = nullptr;

    std::uint32_t alpcProcessId_ = 0;
    std::uint64_t alpcHandleValue_ = 0;
    ksword::ark::IpcSummaryAuditResult lastIpcSummaryResult_;
    ksword::ark::AlpcPortQueryResult lastAlpcResult_;
};
