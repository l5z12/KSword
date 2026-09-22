#pragma once

#include <QByteArray>
#include <QDialog>
#include <QString>
#include <QVector>

#include <cstdint>
#include <optional>

class QLabel;
class QTableWidget;

namespace ks::ui
{
    enum class DisassemblyArchitecture : int
    {
        kX86 = 0,
        kX64
    };

    struct DisassemblyRow
    {
        std::uint64_t address = 0U;
        std::uint32_t byteOffset = 0U;
        QByteArray bytes;
        QString mnemonic;
        QString operands;
        bool decoded = false;
    };

    struct DisassemblyResult
    {
        QVector<DisassemblyRow> rows;
        QString backendName;
        QString diagnosticText;
        bool complete = false;
    };

    struct DisassemblySelection
    {
        std::uint64_t address = 0U;
        std::uint32_t byteOffset = 0U;
        QByteArray originalBytes;
    };

    class InstructionDecoder final
    {
    public:
        static DisassemblyResult decode(
            const QByteArray& bytes,
            std::uint64_t baseAddress,
            DisassemblyArchitecture architecture,
            std::uint32_t maximumInstructions = 4096U);
    };

    class KernelDisassemblyDialog final : public QDialog
    {
        Q_OBJECT

    public:
        explicit KernelDisassemblyDialog(QWidget* parent = nullptr);

        static void openKernelAddress(
            QWidget* parent,
            std::uint64_t address,
            const QString& sourceDescription,
            std::uint32_t byteCount = 4096U);

        void setSnapshot(
            const QByteArray& bytes,
            std::uint64_t baseAddress,
            DisassemblyArchitecture architecture,
            const QString& sourceDescription);
        void setKernelMutationEnabled(bool enabled);

        QByteArray originalBytes() const;
        std::uint64_t baseAddress() const;
        std::optional<DisassemblySelection>
            selectedByteRange() const;

    signals:
        void requestModifyBytes(
            std::uint64_t address,
            QByteArray originalBytes);

    private:
        void rebuildRows();
        void emitModifyRequest();
        void executeKernelMutation(
            std::uint64_t address,
            const QByteArray& originalBytes);

        QByteArray originalBytes_;
        std::uint64_t baseAddress_ = 0U;
        DisassemblyArchitecture architecture_ =
            DisassemblyArchitecture::kX64;
        QVector<DisassemblyRow> rows_;
        QLabel* sourceLabel_ = nullptr;
        QLabel* backendLabel_ = nullptr;
        QLabel* mutationRiskLabel_ = nullptr;
        QLabel* mutationStatusLabel_ = nullptr;
        QTableWidget* table_ = nullptr;
        bool kernelMutationEnabled_ = false;
    };
}
