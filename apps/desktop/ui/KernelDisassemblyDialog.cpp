#include "KernelDisassemblyDialog.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../Theme.h"
/* Unified entry point: this page does not need to know GPA, EPT leaf, or ruleId. */
#include "KvmWatchDialog.h"
#include "VisibleTableWidget.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QRegularExpression>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

#if __has_include(<Zydis.h>)
#define KSWORD_HAS_ZYDIS 1
#include <Zydis.h>
#elif __has_include(<Zydis/Zydis.h>)
#define KSWORD_HAS_ZYDIS 1
#include <Zydis/Zydis.h>
#else
#define KSWORD_HAS_ZYDIS 0
#endif

namespace
{
    QString bytesText(const QByteArray& bytes)
    {
        QStringList parts;
        parts.reserve(bytes.size());
        for (const char kValue : bytes)
        {
            parts.push_back(
                QStringLiteral("%1")
                    .arg(
                        static_cast<unsigned char>(kValue),
                        2,
                        16,
                        QChar('0'))
                    .toUpper());
        }
        return parts.join(QChar(' '));
    }

    QString addressText(const std::uint64_t address)
    {
        return QStringLiteral("0x%1")
            .arg(
                static_cast<qulonglong>(address),
                16,
                16,
                QChar('0'))
            .toUpper();
    }

    bool parseHexBytes(
        const QString& text,
        QByteArray& bytesOut,
        QString& errorTextOut)
    {
        bytesOut.clear();
        errorTextOut.clear();
        QString normalized = text.trimmed();
        normalized.replace(QChar(','), QChar(' '));
        normalized.replace(QChar(';'), QChar(' '));
        normalized.replace(QChar('-'), QChar(' '));
        const QStringList kTokens = normalized.split(
            QRegularExpression(QStringLiteral("\\s+")),
            Qt::SkipEmptyParts);
        for (QString token : kTokens)
        {
            if (token.startsWith(
                    QStringLiteral("0x"),
                    Qt::CaseInsensitive))
            {
                token.remove(0, 2);
            }
            if (token.isEmpty() || (token.size() % 2) != 0)
            {
                errorTextOut = QStringLiteral(
                    "十六进制字节必须由完整的两位数构成。");
                return false;
            }
            for (qsizetype index = 0; index < token.size(); index += 2)
            {
                bool ok = false;
                const unsigned int kValue =
                    token.mid(index, 2).toUInt(&ok, 16);
                if (!ok || kValue > 0xFFU)
                {
                    errorTextOut = QStringLiteral(
                        "输入包含无效十六进制字节。");
                    bytesOut.clear();
                    return false;
                }
                bytesOut.append(static_cast<char>(kValue));
                if (bytesOut.size()
                    > static_cast<qsizetype>(
                        KSWORD_ARK_MUTATION_MAX_BYTES))
                {
                    errorTextOut = QStringLiteral(
                        "单次事务最多修改 %1 字节。")
                        .arg(KSWORD_ARK_MUTATION_MAX_BYTES);
                    bytesOut.clear();
                    return false;
                }
            }
        }
        if (bytesOut.isEmpty())
        {
            errorTextOut = QStringLiteral(
                "请输入至少一个十六进制字节。");
            return false;
        }
        return true;
    }

    std::vector<std::uint8_t> byteVector(
        const QByteArray& bytes)
    {
        const auto* begin = reinterpret_cast<const std::uint8_t*>(
            bytes.constData());
        return std::vector<std::uint8_t>(
            begin,
            begin + static_cast<std::size_t>(bytes.size()));
    }

    bool bytePrefixMatches(
        const std::vector<std::uint8_t>& bytes,
        const QByteArray& expected)
    {
        if (bytes.size()
            < static_cast<std::size_t>(expected.size()))
        {
            return false;
        }
        return std::equal(
            expected.cbegin(),
            expected.cend(),
            bytes.cbegin(),
            [](const char left, const std::uint8_t right)
            {
                return static_cast<std::uint8_t>(
                    static_cast<unsigned char>(left)) == right;
            });
    }

    QString mutationResponseText(
        const QString& stage,
        const ksword::ark::MutationResponseResult& response)
    {
        return QStringLiteral(
            "%1：tx=%2，status=%3，risk=0x%4，"
            "NTSTATUS=0x%5，后端=%6")
            .arg(stage)
            .arg(
                static_cast<qulonglong>(
                    response.transactionId))
            .arg(response.status)
            .arg(response.riskFlags, 8, 16, QChar('0'))
            .arg(
                static_cast<unsigned long>(
                    response.lastStatus),
                8,
                16,
                QChar('0'))
            .arg(QString::fromStdString(response.io.message));
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    ks::ui::DisassemblyRow fallbackDecodeOne(
        const QByteArray& bytes,
        std::uint32_t offset,
        std::uint64_t baseAddress,
        ks::ui::DisassemblyArchitecture architecture);

    bool tryZydis(
        const QByteArray& bytes,
        const std::uint64_t baseAddress,
        const ks::ui::DisassemblyArchitecture architecture,
        const std::uint32_t maximumInstructions,
        ks::ui::DisassemblyResult& resultOut)
    {
#if KSWORD_HAS_ZYDIS
        ks::ui::DisassemblyResult result;
        result.backendName = QStringLiteral(
            "Zydis v4（编译期固定依赖）");
        std::uint32_t offset = 0U;
        while (offset < static_cast<std::uint32_t>(bytes.size())
            && result.rows.size()
                < static_cast<qsizetype>(maximumInstructions))
        {
            ZydisDisassembledInstruction instruction{};
            const ZydisMachineMode kMode =
                architecture
                    == ks::ui::DisassemblyArchitecture::kX64
                ? ZYDIS_MACHINE_MODE_LONG_64
                : ZYDIS_MACHINE_MODE_LEGACY_32;
            const ZyanStatus kStatus = ZydisDisassembleIntel(
                kMode,
                baseAddress + offset,
                bytes.constData() + static_cast<qsizetype>(offset),
                static_cast<ZyanUSize>(
                    bytes.size() - static_cast<qsizetype>(offset)),
                &instruction);
            if (!ZYAN_SUCCESS(kStatus)
                || instruction.info.length == 0U)
            {
                break;
            }
            const std::uint32_t kLength =
                instruction.info.length;
            if (kLength
                > static_cast<std::uint32_t>(bytes.size()) - offset)
            {
                break;
            }
            const QString kText =
                QString::fromLatin1(instruction.text).trimmed();
            const qsizetype kSeparator =
                kText.indexOf(QChar(' '));
            ks::ui::DisassemblyRow row;
            row.address = baseAddress + offset;
            row.byteOffset = offset;
            row.bytes = bytes.mid(
                static_cast<qsizetype>(offset),
                static_cast<qsizetype>(kLength));
            if (kSeparator < 0)
            {
                row.mnemonic = kText;
            }
            else
            {
                row.mnemonic = kText.left(kSeparator);
                row.operands = kText.mid(kSeparator + 1).trimmed();
            }
            row.decoded = true;
            result.rows.push_back(std::move(row));
            offset += kLength;
        }
        result.complete =
            offset >= static_cast<std::uint32_t>(bytes.size());
        if (!result.rows.isEmpty())
        {
            if (!result.complete)
            {
                result.diagnosticText = QStringLiteral(
                    "Zydis 在快照尾部遇到截断或无效指令；"
                    "剩余字节将由有界降级解码器保留。");
                while (offset
                        < static_cast<std::uint32_t>(bytes.size())
                    && result.rows.size()
                        < static_cast<qsizetype>(
                            maximumInstructions))
                {
                    ks::ui::DisassemblyRow row =
                        fallbackDecodeOne(
                            bytes,
                            offset,
                            baseAddress,
                            architecture);
                    const std::uint32_t kConsumed = std::max(
                        1U,
                        static_cast<std::uint32_t>(
                            row.bytes.size()));
                    result.rows.push_back(std::move(row));
                    offset += kConsumed;
                }
                result.complete =
                    offset
                    >= static_cast<std::uint32_t>(bytes.size());
            }
            resultOut = std::move(result);
            return true;
        }
#else
        Q_UNUSED(bytes);
        Q_UNUSED(baseAddress);
        Q_UNUSED(architecture);
        Q_UNUSED(maximumInstructions);
        Q_UNUSED(resultOut);
#endif
        return false;
    }

    QString registerName(
        const unsigned int registerIndex,
        const bool wide)
    {
        static constexpr std::array<const char*, 16> kRegisters64{
            "rax", "rcx", "rdx", "rbx",
            "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15"
        };
        static constexpr std::array<const char*, 16> kRegisters32{
            "eax", "ecx", "edx", "ebx",
            "esp", "ebp", "esi", "edi",
            "r8d", "r9d", "r10d", "r11d",
            "r12d", "r13d", "r14d", "r15d"
        };
        const unsigned int kBounded = registerIndex & 0x0FU;
        return QString::fromLatin1(
            wide ? kRegisters64[kBounded] : kRegisters32[kBounded]);
    }

    std::uint32_t modRmLength(
        const QByteArray& bytes,
        const std::uint32_t offset,
        const bool address64)
    {
        if (offset >= static_cast<std::uint32_t>(bytes.size()))
        {
            return 0U;
        }
        const unsigned char kModRm =
            static_cast<unsigned char>(bytes.at(offset));
        const unsigned int kMod = kModRm >> 6U;
        const unsigned int kRm = kModRm & 7U;
        std::uint32_t length = 1U;
        if (kMod != 3U && kRm == 4U)
        {
            if (offset + length
                >= static_cast<std::uint32_t>(bytes.size()))
            {
                return 0U;
            }
            const unsigned char kSib =
                static_cast<unsigned char>(
                    bytes.at(offset + length));
            ++length;
            if (kMod == 0U && (kSib & 7U) == 5U)
            {
                length += 4U;
            }
        }
        if (kMod == 0U && kRm == 5U)
        {
            length += address64 ? 4U : 4U;
        }
        else if (kMod == 1U)
        {
            ++length;
        }
        else if (kMod == 2U)
        {
            length += 4U;
        }
        return offset + length
                <= static_cast<std::uint32_t>(bytes.size())
            ? length
            : 0U;
    }

    ks::ui::DisassemblyRow fallbackDecodeOne(
        const QByteArray& bytes,
        const std::uint32_t offset,
        const std::uint64_t baseAddress,
        const ks::ui::DisassemblyArchitecture architecture)
    {
        ks::ui::DisassemblyRow row;
        row.address = baseAddress + offset;
        row.byteOffset = offset;
        const std::uint32_t kRemaining =
            static_cast<std::uint32_t>(bytes.size()) - offset;
        const unsigned char kFirst =
            static_cast<unsigned char>(bytes.at(offset));
        std::uint32_t cursor = offset;
        bool rexWide = false;
        unsigned int rexBits = 0U;
        if (architecture == ks::ui::DisassemblyArchitecture::kX64
            && kFirst >= 0x40U && kFirst <= 0x4FU)
        {
            rexBits = kFirst & 0x0FU;
            rexWide = (rexBits & 0x08U) != 0U;
            ++cursor;
            if (cursor >= static_cast<std::uint32_t>(bytes.size()))
            {
                row.bytes = bytes.mid(offset, 1);
                row.mnemonic = QStringLiteral("db");
                row.operands = QStringLiteral("0x%1")
                    .arg(kFirst, 2, 16, QChar('0'))
                    .toUpper();
                return row;
            }
        }
        const unsigned char kOpcode =
            static_cast<unsigned char>(bytes.at(cursor));
        const std::uint32_t kPrefixBytes = cursor - offset;
        auto finish = [&row, &bytes, offset](
            const std::uint32_t length,
            const QString& mnemonic,
            const QString& operands = QString())
        {
            row.bytes = bytes.mid(
                static_cast<qsizetype>(offset),
                static_cast<qsizetype>(length));
            row.mnemonic = mnemonic;
            row.operands = operands;
            row.decoded = true;
        };
        if (kOpcode == 0x90U)
        {
            finish(kPrefixBytes + 1U, QStringLiteral("nop"));
            return row;
        }
        if (kOpcode == 0xCCU)
        {
            finish(kPrefixBytes + 1U, QStringLiteral("int3"));
            return row;
        }
        if (kOpcode == 0xC3U)
        {
            finish(kPrefixBytes + 1U, QStringLiteral("ret"));
            return row;
        }
        if (kOpcode == 0xF4U)
        {
            finish(kPrefixBytes + 1U, QStringLiteral("hlt"));
            return row;
        }
        if (kOpcode == 0xFAU || kOpcode == 0xFBU)
        {
            finish(
                kPrefixBytes + 1U,
                kOpcode == 0xFAU
                    ? QStringLiteral("cli")
                    : QStringLiteral("sti"));
            return row;
        }
        if (kOpcode >= 0x50U && kOpcode <= 0x5FU)
        {
            const bool kPop = kOpcode >= 0x58U;
            const unsigned int kIndex =
                (kOpcode & 7U)
                + ((rexBits & 1U) != 0U ? 8U : 0U);
            finish(
                kPrefixBytes + 1U,
                kPop ? QStringLiteral("pop") : QStringLiteral("push"),
                registerName(
                    kIndex,
                    architecture
                        == ks::ui::DisassemblyArchitecture::kX64));
            return row;
        }
        if ((kOpcode == 0xE8U || kOpcode == 0xE9U)
            && kRemaining >= kPrefixBytes + 5U)
        {
            std::int32_t displacement = 0;
            std::memcpy(
                &displacement,
                bytes.constData()
                    + static_cast<qsizetype>(cursor + 1U),
                sizeof(displacement));
            const std::uint32_t kLength = kPrefixBytes + 5U;
            finish(
                kLength,
                kOpcode == 0xE8U
                    ? QStringLiteral("call")
                    : QStringLiteral("jmp"),
                addressText(
                    row.address + kLength + displacement));
            return row;
        }
        if (kOpcode == 0xEBU
            && kRemaining >= kPrefixBytes + 2U)
        {
            const auto kDisplacement = static_cast<std::int8_t>(
                bytes.at(static_cast<qsizetype>(cursor + 1U)));
            const std::uint32_t kLength = kPrefixBytes + 2U;
            finish(
                kLength,
                QStringLiteral("jmp"),
                addressText(
                    row.address + kLength + kDisplacement));
            return row;
        }
        static constexpr std::array<const char*, 16> kConditions{
            "jo", "jno", "jb", "jae",
            "je", "jne", "jbe", "ja",
            "js", "jns", "jp", "jnp",
            "jl", "jge", "jle", "jg"
        };
        if (kOpcode >= 0x70U
            && kOpcode <= 0x7FU
            && kRemaining >= kPrefixBytes + 2U)
        {
            const auto kDisplacement = static_cast<std::int8_t>(
                bytes.at(static_cast<qsizetype>(cursor + 1U)));
            const std::uint32_t kLength = kPrefixBytes + 2U;
            finish(
                kLength,
                QString::fromLatin1(
                    kConditions[kOpcode - 0x70U]),
                addressText(
                    row.address + kLength + kDisplacement));
            return row;
        }
        if (kOpcode == 0x0FU
            && kRemaining >= kPrefixBytes + 2U)
        {
            const unsigned char kSecond =
                static_cast<unsigned char>(
                    bytes.at(static_cast<qsizetype>(cursor + 1U)));
            if (kSecond == 0x05U
                || kSecond == 0x07U
                || kSecond == 0x0BU)
            {
                finish(
                    kPrefixBytes + 2U,
                    kSecond == 0x05U
                        ? QStringLiteral("syscall")
                        : kSecond == 0x07U
                            ? QStringLiteral("sysret")
                            : QStringLiteral("ud2"));
                return row;
            }
            if (kSecond >= 0x80U
                && kSecond <= 0x8FU
                && kRemaining >= kPrefixBytes + 6U)
            {
                std::int32_t displacement = 0;
                std::memcpy(
                    &displacement,
                    bytes.constData()
                        + static_cast<qsizetype>(cursor + 2U),
                    sizeof(displacement));
                const std::uint32_t kLength = kPrefixBytes + 6U;
                finish(
                    kLength,
                    QString::fromLatin1(
                        kConditions[kSecond - 0x80U]),
                    addressText(
                        row.address + kLength + displacement));
                return row;
            }
        }
        if (kOpcode >= 0xB8U
            && kOpcode <= 0xBFU)
        {
            const std::uint32_t kImmediateBytes =
                rexWide ? 8U : 4U;
            if (kRemaining >= kPrefixBytes + 1U + kImmediateBytes)
            {
                std::uint64_t immediate = 0U;
                std::memcpy(
                    &immediate,
                    bytes.constData()
                        + static_cast<qsizetype>(cursor + 1U),
                    kImmediateBytes);
                const unsigned int kIndex =
                    (kOpcode & 7U)
                    + ((rexBits & 1U) != 0U ? 8U : 0U);
                finish(
                    kPrefixBytes + 1U + kImmediateBytes,
                    QStringLiteral("mov"),
                    QStringLiteral("%1, 0x%2")
                        .arg(registerName(kIndex, rexWide))
                        .arg(
                            static_cast<qulonglong>(immediate),
                            0,
                            16)
                        .toUpper());
                return row;
            }
        }
        const bool kHasModRm =
            kOpcode == 0x89U || kOpcode == 0x8BU
            || kOpcode == 0x8DU || kOpcode == 0x31U
            || kOpcode == 0x33U || kOpcode == 0x85U
            || kOpcode == 0x81U || kOpcode == 0x83U
            || kOpcode == 0xFFU;
        if (kHasModRm)
        {
            const std::uint32_t kModRmBytes =
                modRmLength(
                    bytes,
                    cursor + 1U,
                    architecture
                        == ks::ui::DisassemblyArchitecture::kX64);
            std::uint32_t immediateBytes = 0U;
            if (kOpcode == 0x81U)
            {
                immediateBytes = 4U;
            }
            else if (kOpcode == 0x83U)
            {
                immediateBytes = 1U;
            }
            const std::uint32_t kLength =
                kPrefixBytes + 1U + kModRmBytes + immediateBytes;
            if (kModRmBytes != 0U && kRemaining >= kLength)
            {
                const unsigned char kModRm =
                    static_cast<unsigned char>(
                        bytes.at(static_cast<qsizetype>(
                            cursor + 1U)));
                const unsigned int kExtension =
                    (kModRm >> 3U) & 7U;
                QString mnemonic;
                if (kOpcode == 0x89U || kOpcode == 0x8BU)
                {
                    mnemonic = QStringLiteral("mov");
                }
                else if (kOpcode == 0x8DU)
                {
                    mnemonic = QStringLiteral("lea");
                }
                else if (kOpcode == 0x31U || kOpcode == 0x33U)
                {
                    mnemonic = QStringLiteral("xor");
                }
                else if (kOpcode == 0x85U)
                {
                    mnemonic = QStringLiteral("test");
                }
                else if (kOpcode == 0xFFU)
                {
                    mnemonic = kExtension == 2U
                        ? QStringLiteral("call")
                        : kExtension == 4U
                            ? QStringLiteral("jmp")
                            : kExtension == 6U
                                ? QStringLiteral("push")
                                : QStringLiteral("ff-group");
                }
                else
                {
                    static constexpr std::array<
                        const char*, 8> kGroupOne{
                        "add", "or", "adc", "sbb",
                        "and", "sub", "xor", "cmp"
                    };
                    mnemonic = QString::fromLatin1(
                        kGroupOne[kExtension]);
                }
                finish(
                    kLength,
                    mnemonic,
                    QStringLiteral("<ModR/M %1>")
                        .arg(
                            kModRm,
                            2,
                            16,
                            QChar('0'))
                        .toUpper());
                return row;
            }
        }
        row.bytes = bytes.mid(
            static_cast<qsizetype>(offset),
            1);
        row.mnemonic = QStringLiteral("db");
        row.operands = QStringLiteral("0x%1")
            .arg(kFirst, 2, 16, QChar('0'))
            .toUpper();
        row.decoded = false;
        return row;
    }
}

namespace ks::ui
{
    DisassemblyResult InstructionDecoder::decode(
        const QByteArray& bytes,
        const std::uint64_t baseAddress,
        const DisassemblyArchitecture architecture,
        const std::uint32_t maximumInstructions)
    {
        DisassemblyResult result;
        if (bytes.isEmpty())
        {
            result.backendName = QStringLiteral("无输入");
            result.diagnosticText =
                QStringLiteral("没有可解码的字节。");
            return result;
        }
        if (baseAddress
            > std::numeric_limits<std::uint64_t>::max()
                - static_cast<std::uint64_t>(
                    bytes.size() - 1))
        {
            result.backendName =
                QStringLiteral("输入校验");
            result.diagnosticText =
                QStringLiteral("指令快照地址范围发生 64 位溢出。");
            return result;
        }
        const std::uint32_t kBoundedMaximum =
            std::clamp(maximumInstructions, 1U, 65536U);
        if (tryZydis(
                bytes,
                baseAddress,
                architecture,
                kBoundedMaximum,
                result))
        {
            return result;
        }
        result.backendName =
            QStringLiteral("内置 x86/x64 有界解码器");
        result.diagnosticText = QStringLiteral(
            "编译时未启用 Zydis v4.1.1，或输入首条指令无效；"
            "常见控制流、序言、尾声和 ModR/M 指令已解码，"
            "未知指令以 db 保留原始字节，不猜测语义。");
        std::uint32_t offset = 0U;
        while (offset < static_cast<std::uint32_t>(bytes.size())
            && result.rows.size()
                < static_cast<qsizetype>(kBoundedMaximum))
        {
            DisassemblyRow row = fallbackDecodeOne(
                bytes,
                offset,
                baseAddress,
                architecture);
            const std::uint32_t kConsumed = std::max(
                1U,
                static_cast<std::uint32_t>(row.bytes.size()));
            result.rows.push_back(std::move(row));
            offset += kConsumed;
        }
        result.complete =
            offset >= static_cast<std::uint32_t>(bytes.size());
        return result;
    }

    KernelDisassemblyDialog::KernelDisassemblyDialog(
        QWidget* parent)
        : QDialog(parent)
    {
        setWindowTitle(QStringLiteral("指令视图"));
        resize(980, 640);
        auto* layout = new QVBoxLayout(this);
        sourceLabel_ = new QLabel(this);
        sourceLabel_->setWordWrap(true);
        layout->addWidget(sourceLabel_);
        backendLabel_ = new QLabel(this);
        backendLabel_->setWordWrap(true);
        layout->addWidget(backendLabel_);
        mutationRiskLabel_ = new QLabel(this);
        mutationRiskLabel_->setWordWrap(true);
        mutationRiskLabel_->setTextInteractionFlags(
            Qt::TextSelectableByMouse);
        // Use semantic color tokens: the hardcoded #b3261e has insufficient contrast in dark themes and does not follow custom accent colors.
        mutationRiskLabel_->setStyleSheet(QStringLiteral(
            "QLabel{border:1px solid %1;border-radius:6px;"
            "padding:8px;color:%1;font-weight:600;}")
            .arg(ksword_theme::errorHex()));
        mutationRiskLabel_->hide();
        layout->addWidget(mutationRiskLabel_);
        mutationStatusLabel_ = new QLabel(this);
        mutationStatusLabel_->setWordWrap(true);
        mutationStatusLabel_->setTextInteractionFlags(
            Qt::TextSelectableByMouse);
        mutationStatusLabel_->hide();
        layout->addWidget(mutationStatusLabel_);
        table_ = new ks::ui::VisibleTableWidget(this);
        table_->setColumnCount(5);
        table_->setHorizontalHeaderLabels({
            QStringLiteral("地址"),
            QStringLiteral("偏移"),
            QStringLiteral("原始字节"),
            QStringLiteral("助记符"),
            QStringLiteral("操作数")
        });
        table_->setSelectionBehavior(
            QAbstractItemView::SelectRows);
        table_->setSelectionMode(
            QAbstractItemView::SingleSelection);
        table_->setEditTriggers(
            QAbstractItemView::NoEditTriggers);
        table_->setContextMenuPolicy(
            Qt::CustomContextMenu);
        table_->horizontalHeader()->setStretchLastSection(true);
        layout->addWidget(table_, 1);
        auto* buttons = new QDialogButtonBox(
            QDialogButtonBox::Close,
            this);
        layout->addWidget(buttons);
        connect(
            buttons,
            &QDialogButtonBox::rejected,
            this,
            &QDialog::reject);
        connect(
            this,
            &KernelDisassemblyDialog::requestModifyBytes,
            this,
            [this](
                const std::uint64_t address,
                const QByteArray& originalBytes)
            {
                if (kernelMutationEnabled_)
                {
                    executeKernelMutation(
                        address,
                        originalBytes);
                }
            });
        connect(
            table_,
            &QTableWidget::customContextMenuRequested,
            this,
            [this](const QPoint& position)
            {
                if (QTableWidgetItem* item =
                        table_->itemAt(position);
                    item != nullptr)
                {
                    table_->setCurrentCell(
                        item->row(),
                        0);
                }
                const auto kSelection = selectedByteRange();
                if (!kSelection.has_value())
                {
                    return;
                }
                QMenu menu(this);
                menu.setStyleSheet(
                    ksword_theme::contextMenuStyle());
                QAction* copyAddress = menu.addAction(
                    QStringLiteral("复制地址"));
                QAction* copyBytes = menu.addAction(
                    QStringLiteral("复制原始字节"));
                /*
                 * Monitor execution, not writes.
                 *
                 * The selected item in the disassembly view is an instruction; the user wants to
                 * know 'who executes here next'. Placing a watch here is almost always wrong: the
                 * code page is rarely written to, so the watch will wait indefinitely for a hit.
                 */
                menu.addSeparator();
                QAction* watchExecute = menu.addAction(
                    QStringLiteral("HVM 监视：下一次执行到这里"));
                watchExecute->setToolTip(
                    QStringLiteral("装一条首次访问监视，等下一次有人执行这一页时记下现场。EPT 是页粒度，所以实际监视的是这条指令所在的整个 4 KiB 页。"));
                QAction* modify = nullptr;
                if (kernelMutationEnabled_)
                {
                    menu.addSeparator();
                    QMenu* mutationMenu = menu.addMenu(
                        QStringLiteral("字节事务"));
                    modify = mutationMenu->addAction(
                        QStringLiteral("修改所选字节…"));
                }
                QAction* selected = menu.exec(
                    table_->viewport()->mapToGlobal(position));
                if (selected == copyAddress)
                {
                    QApplication::clipboard()->setText(
                        addressText(kSelection->address));
                }
                else if (selected == copyBytes)
                {
                    QApplication::clipboard()->setText(
                        bytesText(kSelection->originalBytes));
                }
                else if (selected == watchExecute)
                {
                    HvmWatchRequest request;
                    request.virtualAddress = true;
                    request.address = kSelection->address;
                    /*
                     * Length is the byte count of this instruction, not the entire page.
                     *
                     * It does not change the hardware monitoring scope; it only enables answering "on
                     * the selected instruction or elsewhere on the same page" after a hit — on a page
                     * full of code, this distinction almost determines whether the evidence is useful.
                     */
                    request.length = kSelection->originalBytes.isEmpty()
                        ? 1U
                        : static_cast<quint64>(kSelection->originalBytes.size());
                    request.access = KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE;
                    request.label = QStringLiteral("%1 处的指令")
                        .arg(addressText(kSelection->address));
                    openHvmWatch(this, request);
                }
                else if (modify != nullptr
                    && selected == modify)
                {
                    emitModifyRequest();
                }
            });
    }

    void KernelDisassemblyDialog::openKernelAddress(
        QWidget* parent,
        const std::uint64_t address,
        const QString& sourceDescription,
        const std::uint32_t byteCount)
    {
        if (address == 0U || byteCount == 0U)
        {
            QMessageBox::warning(
                parent,
                QStringLiteral("指令视图"),
                QStringLiteral("目标内核地址或读取长度无效。"));
            return;
        }
        const std::uint32_t kBoundedBytes = std::min<std::uint32_t>(
            byteCount,
            KSWORD_ARK_MEMORY_READ_MAX_BYTES);
        const ksword::ark::DriverClient kClient;
        const ksword::ark::VirtualMemoryReadResult kRead =
            kClient.readVirtualMemory(
                0U,
                address,
                kBoundedBytes,
                KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS
                    | KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE);
        if (!kRead.io.ok
            || kRead.data.empty()
            || kRead.bytesRead == 0U)
        {
            QMessageBox::warning(
                parent,
                QStringLiteral("指令视图"),
                QStringLiteral(
                    "R0 内核字节读取失败。\n"
                    "Win32=%1，NTSTATUS=0x%2，读取=%3/%4。\n%5")
                    .arg(kRead.io.win32Error)
                    .arg(
                        static_cast<unsigned long>(
                            kRead.copyStatus),
                        8,
                        16,
                        QChar('0'))
                    .arg(kRead.bytesRead)
                    .arg(kBoundedBytes)
                    .arg(QString::fromStdString(
                        kRead.io.message)));
            return;
        }
        const qsizetype kSnapshotBytes =
            static_cast<qsizetype>(std::min<std::size_t>(
                kRead.data.size(),
                static_cast<std::size_t>(
                    std::numeric_limits<int>::max())));
        const QByteArray kSnapshot(
            reinterpret_cast<const char*>(kRead.data.data()),
            kSnapshotBytes);
        KernelDisassemblyDialog dialog(parent);
        dialog.setSnapshot(
            kSnapshot,
            address,
            DisassemblyArchitecture::kX64,
            sourceDescription);
        dialog.setKernelMutationEnabled(true);
        dialog.exec();
    }

    void KernelDisassemblyDialog::setSnapshot(
        const QByteArray& bytes,
        const std::uint64_t baseAddress,
        const DisassemblyArchitecture architecture,
        const QString& sourceDescription)
    {
        originalBytes_ = bytes;
        baseAddress_ = baseAddress;
        architecture_ = architecture;
        sourceLabel_->setText(
            QStringLiteral(
                "证据源：%1\n基址：%2；架构：%3；快照：%4 字节。"
                "本窗口只解码传入快照；是否允许事务修改由当前证据源策略决定。")
                .arg(sourceDescription)
                .arg(addressText(baseAddress))
                .arg(
                    architecture == DisassemblyArchitecture::kX64
                        ? QStringLiteral("x64")
                        : QStringLiteral("x86"))
                .arg(bytes.size()));
        rebuildRows();
    }

    void KernelDisassemblyDialog::setKernelMutationEnabled(
        const bool enabled)
    {
        kernelMutationEnabled_ = enabled;
        mutationRiskLabel_->setVisible(enabled);
        mutationStatusLabel_->setVisible(enabled);
        if (enabled)
        {
            mutationRiskLabel_->setText(QStringLiteral(
                "风险：此入口可通过 R0 事务修改当前指令对应的内核虚拟字节。"
                "目标可能是正在执行的代码或关键内核数据；错误修改可能立即导致"
                "权限边界失效、数据损坏、系统挂起或蓝屏。"
                "1–64 字节活体内核补丁不是硬件原子操作，其他 CPU 仍可能"
                "在写入过程中并发执行或修改目标。"
                "PREPARE、dry-run、FORCE+UI_CONFIRMED、写后校验、回滚和审计。"
                "在指令行上右键可进入“字节事务”二级菜单。"));
            mutationRiskLabel_->setToolTip(QStringLiteral(
                "在指令行上右键，进入“字节事务”二级菜单。"));
            mutationStatusLabel_->setText(
                QStringLiteral(
                    "事务后端：尚未执行；等待选择一条指令。"
                    "每次写入均要求显式危险确认。"));
        }
    }

    QByteArray KernelDisassemblyDialog::originalBytes() const
    {
        return originalBytes_;
    }

    std::uint64_t KernelDisassemblyDialog::baseAddress() const
    {
        return baseAddress_;
    }

    std::optional<DisassemblySelection>
    KernelDisassemblyDialog::selectedByteRange() const
    {
        if (table_ == nullptr)
        {
            return std::nullopt;
        }
        const int kRowIndex = table_->currentRow();
        if (kRowIndex < 0
            || kRowIndex >= static_cast<int>(rows_.size()))
        {
            return std::nullopt;
        }
        const DisassemblyRow& row = rows_.at(kRowIndex);
        DisassemblySelection selection;
        selection.address = row.address;
        selection.byteOffset = row.byteOffset;
        selection.originalBytes = row.bytes;
        return selection;
    }

    void KernelDisassemblyDialog::rebuildRows()
    {
        const DisassemblyResult kResult =
            InstructionDecoder::decode(
                originalBytes_,
                baseAddress_,
                architecture_);
        rows_ = kResult.rows;
        backendLabel_->setText(
            QStringLiteral("解码后端：%1%2")
                .arg(kResult.backendName)
                .arg(
                    kResult.diagnosticText.isEmpty()
                        ? QString()
                        : QStringLiteral("\n%1")
                            .arg(kResult.diagnosticText)));
        table_->setRowCount(
            static_cast<int>(rows_.size()));
        for (qsizetype index = 0; index < rows_.size(); ++index)
        {
            const DisassemblyRow& row = rows_.at(index);
            table_->setItem(
                static_cast<int>(index),
                0,
                readOnlyItem(addressText(row.address)));
            table_->setItem(
                static_cast<int>(index),
                1,
                readOnlyItem(
                    QStringLiteral("0x%1")
                        .arg(
                            row.byteOffset,
                            8,
                            16,
                            QChar('0'))
                        .toUpper()));
            table_->setItem(
                static_cast<int>(index),
                2,
                readOnlyItem(bytesText(row.bytes)));
            table_->setItem(
                static_cast<int>(index),
                3,
                readOnlyItem(row.mnemonic));
            table_->setItem(
                static_cast<int>(index),
                4,
                readOnlyItem(row.operands));
        }
        table_->resizeColumnsToContents();
    }

    void KernelDisassemblyDialog::emitModifyRequest()
    {
        const auto kSelection = selectedByteRange();
        if (!kSelection.has_value())
        {
            return;
        }
        emit requestModifyBytes(
            kSelection->address,
            kSelection->originalBytes);
    }

    void KernelDisassemblyDialog::executeKernelMutation(
        const std::uint64_t address,
        const QByteArray& originalBytes)
    {
        if (!kernelMutationEnabled_
            || originalBytes.isEmpty()
            || originalBytes.size()
                > static_cast<qsizetype>(
                    KSWORD_ARK_MUTATION_MAX_BYTES))
        {
            return;
        }

        QDialog editor(this);
        editor.setWindowTitle(QStringLiteral("内核字节事务"));
        editor.resize(680, 360);
        auto* layout = new QVBoxLayout(&editor);
        auto* risk = new QLabel(
            QStringLiteral(
                "目标：%1；快照长度：%2 字节。\n"
                "修改可能作用于正在执行的内核代码。错误字节可能导致系统崩溃、"
                "安全边界失效或不可恢复的数据损坏。事务会先核对原始字节并"
                "执行 dry-run，只有最终 FORCE+UI_CONFIRMED 阶段才写入；"
                "写后校验失败会立即请求回滚。多字节写入不是硬件原子操作，"
                "其他 CPU 仍可能并发执行或修改目标。")
                .arg(addressText(address))
                .arg(originalBytes.size()),
            &editor);
        risk->setWordWrap(true);
        risk->setStyleSheet(QStringLiteral(
            "QLabel{border:1px solid %1;border-radius:6px;"
            "padding:8px;color:%1;font-weight:600;}")
            .arg(ksword_theme::errorHex()));
        layout->addWidget(risk);
        auto* inputHint = new QLabel(
            QStringLiteral(
                "输入与原始快照等长的十六进制字节；"
                "可使用空格、逗号或连续十六进制。"),
            &editor);
        inputHint->setWordWrap(true);
        layout->addWidget(inputHint);
        auto* input = new QPlainTextEdit(&editor);
        input->setPlainText(bytesText(originalBytes));
        input->selectAll();
        layout->addWidget(input, 1);
        auto* buttons = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
            &editor);
        layout->addWidget(buttons);
        connect(
            buttons,
            &QDialogButtonBox::accepted,
            &editor,
            &QDialog::accept);
        connect(
            buttons,
            &QDialogButtonBox::rejected,
            &editor,
            &QDialog::reject);
        if (editor.exec() != QDialog::Accepted)
        {
            return;
        }

        QByteArray replacementBytes;
        QString parseError;
        if (!parseHexBytes(
                input->toPlainText(),
                replacementBytes,
                parseError))
        {
            QMessageBox::warning(
                this,
                QStringLiteral("内核字节事务"),
                parseError);
            return;
        }
        if (replacementBytes.size() != originalBytes.size())
        {
            QMessageBox::warning(
                this,
                QStringLiteral("内核字节事务"),
                QStringLiteral(
                    "替换长度必须与所选原始指令一致（%1 字节），"
                    "以便完整执行 expected-before 校验。")
                    .arg(originalBytes.size()));
            return;
        }
        if (replacementBytes == originalBytes)
        {
            mutationStatusLabel_->setText(QStringLiteral(
                "事务后端：替换字节与快照一致，未创建事务。"));
            return;
        }

        const QMessageBox::StandardButton kConfirmed =
            QMessageBox::warning(
                this,
                QStringLiteral("确认内核字节事务"),
                QStringLiteral(
                    "即将修改内核虚拟地址 %1 的 %2 字节。\n"
                    "原始：%3\n替换：%4\n\n"
                    "这可能立即造成系统挂起、蓝屏、数据损坏或"
                    "安全边界失效。是否继续执行 PREPARE 和 dry-run？")
                    .arg(addressText(address))
                    .arg(originalBytes.size())
                    .arg(bytesText(originalBytes))
                    .arg(bytesText(replacementBytes)),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
        if (kConfirmed != QMessageBox::Yes)
        {
            mutationStatusLabel_->setText(
                QStringLiteral("事务后端：用户取消。"));
            return;
        }

        const ksword::ark::DriverClient kClient;
        const unsigned long kFinalFlags =
            KSWORD_ARK_MUTATION_FLAG_FORCE
            | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED;
        ksword::ark::MutationPrepareInput prepareInput;
        prepareInput.flags =
            KSWORD_ARK_MUTATION_FLAG_DRY_RUN
            | KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT;
        prepareInput.targetKind =
            KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL;
        prepareInput.bytes =
            static_cast<std::uint32_t>(
                replacementBytes.size());
        prepareInput.targetAddress = address;
        prepareInput.afterBytes =
            byteVector(replacementBytes);
        prepareInput.expectedBeforeBytes =
            byteVector(originalBytes);

        mutationStatusLabel_->setText(QStringLiteral(
            "事务后端：正在 PREPARE 并核对原始快照…"));
        const ksword::ark::MutationResponseResult kPrepared =
            kClient.prepareMutation(prepareInput);
        if (!kPrepared.io.ok
            || kPrepared.status
                != KSWORD_ARK_MUTATION_STATUS_PREPARED
            || kPrepared.transactionId == 0U
            || kPrepared.bytes
                != static_cast<std::uint32_t>(
                    originalBytes.size())
            || !bytePrefixMatches(
                kPrepared.beforeBytes,
                originalBytes))
        {
            const QString kDetail = mutationResponseText(
                QStringLiteral("PREPARE 失败"),
                kPrepared);
            mutationStatusLabel_->setText(
                QStringLiteral("事务后端：%1").arg(kDetail));
            QMessageBox::critical(
                this,
                QStringLiteral("内核字节事务"),
                QStringLiteral(
                    "PREPARE 未通过；没有发出写入。\n%1")
                    .arg(kDetail));
            return;
        }

        const auto kReadKernelBytesMatches =
            [&kClient, address](
                const QByteArray& expected,
                ksword::ark::VirtualMemoryReadResult& readResult)
            {
                readResult = kClient.readVirtualMemory(
                    0U,
                    address,
                    static_cast<std::uint32_t>(
                        expected.size()),
                    KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS);
                return readResult.io.ok
                    && readResult.readStatus
                        == KSWORD_ARK_MEMORY_READ_STATUS_OK
                    && readResult.bytesRead
                        == static_cast<std::uint32_t>(
                            expected.size())
                    && readResult.data.size()
                        == static_cast<std::size_t>(
                            expected.size())
                    && bytePrefixMatches(
                        readResult.data,
                        expected);
            };

        mutationStatusLabel_->setText(QStringLiteral(
            "事务后端：PREPARE 完成；正在执行 dry-run…"));
        const ksword::ark::MutationResponseResult kDryRun =
            kClient.commitMutation(
                kPrepared.transactionId,
                KSWORD_ARK_MUTATION_FLAG_DRY_RUN);
        if (!kDryRun.io.ok
            || kDryRun.status
                != KSWORD_ARK_MUTATION_STATUS_DRY_RUN)
        {
            const QString kDetail = mutationResponseText(
                QStringLiteral("dry-run 失败"),
                kDryRun);
            mutationStatusLabel_->setText(
                QStringLiteral("事务后端：%1").arg(kDetail));
            QMessageBox::critical(
                this,
                QStringLiteral("内核字节事务"),
                QStringLiteral(
                    "dry-run 未通过；没有发出 FORCE 写入。\n%1")
                    .arg(kDetail));
            return;
        }

        mutationStatusLabel_->setText(QStringLiteral(
            "事务后端：dry-run 通过；正在提交 "
            "FORCE+UI_CONFIRMED 并由 R0 写后校验…"));
        const ksword::ark::MutationResponseResult kCommitted =
            kClient.commitMutation(
                kPrepared.transactionId,
                kFinalFlags);
        if (!kCommitted.io.ok
            || kCommitted.status
                != KSWORD_ARK_MUTATION_STATUS_COMMITTED)
        {
            const QString kDetail = mutationResponseText(
                QStringLiteral("FORCE 提交失败"),
                kCommitted);
            ksword::ark::VirtualMemoryReadResult recoveryRead;
            bool restored = kReadKernelBytesMatches(
                originalBytes,
                recoveryRead);
            QString rollbackDetail;
            if (restored)
            {
                rollbackDetail = QStringLiteral(
                    "R3 复读确认原始快照仍完整，无需发出回滚写入。");
            }
            else
            {
                const ksword::ark::MutationResponseResult kRollback =
                    kClient.rollbackMutation(
                        kPrepared.transactionId,
                        kFinalFlags);
                restored = kReadKernelBytesMatches(
                    originalBytes,
                    recoveryRead);
                rollbackDetail = mutationResponseText(
                    QStringLiteral("自动回滚"),
                    kRollback)
                    + QChar('\n')
                    + (restored
                        ? QStringLiteral(
                            "R3 复读已确认原始快照恢复。")
                        : QStringLiteral(
                            "警告：回滚后 R3 复读未确认原始快照，"
                            "目标可能处于部分修改状态。"));
            }
            mutationStatusLabel_->setText(
                QStringLiteral("事务后端：%1；%2")
                    .arg(kDetail, rollbackDetail));
            QMessageBox::critical(
                this,
                QStringLiteral("内核字节事务"),
                (restored
                    ? QStringLiteral(
                        "提交未完成，但已通过 R3 复读确认原始快照。\n"
                        "%1\n%2")
                    : QStringLiteral(
                        "提交未完成，且无法确认原始快照已经恢复。"
                        "请立即停止继续修改并审查事务审计。\n"
                        "%1\n%2"))
                    .arg(kDetail, rollbackDetail));
            return;
        }

        ksword::ark::VirtualMemoryReadResult verify;
        const bool kVerified = kReadKernelBytesMatches(
            replacementBytes,
            verify);
        if (!kVerified)
        {
            const ksword::ark::MutationResponseResult kRollback =
                kClient.rollbackMutation(
                    kPrepared.transactionId,
                    kFinalFlags);
            ksword::ark::VirtualMemoryReadResult rollbackRead;
            const bool kRollbackVerified =
                kReadKernelBytesMatches(
                    originalBytes,
                    rollbackRead);
            const QString kCommitDetail = mutationResponseText(
                QStringLiteral("FORCE 已返回"),
                kCommitted);
            const QString kRollbackDetail = mutationResponseText(
                QStringLiteral("校验失败后回滚"),
                kRollback)
                + QChar('\n')
                + (kRollbackVerified
                    ? QStringLiteral(
                        "R3 复读已确认原始快照恢复。")
                    : QStringLiteral(
                        "警告：回滚后 R3 复读未确认原始快照，"
                        "目标可能处于部分修改状态。"));
            mutationStatusLabel_->setText(
                (kRollbackVerified
                    ? QStringLiteral(
                        "事务后端：R3 写后复读不一致；%1")
                    : QStringLiteral(
                        "事务后端：R3 写后复读不一致且回滚未验证；%1"))
                    .arg(kRollbackDetail));
            QMessageBox::critical(
                this,
                QStringLiteral("内核字节事务"),
                (kRollbackVerified
                    ? QStringLiteral(
                        "R3 写后复读未得到预期字节，回滚后已确认"
                        "原始快照恢复。\n%1\n复读后端：%2\n%3")
                    : QStringLiteral(
                        "R3 写后复读未得到预期字节，且回滚后仍无法"
                        "确认原始快照。请立即停止继续修改并审查事务"
                        "审计。\n%1\n复读后端：%2\n%3"))
                    .arg(kCommitDetail)
                    .arg(QString::fromStdString(
                        verify.io.message))
                    .arg(kRollbackDetail));
            return;
        }

        const QString kCompletedText =
            QStringLiteral(
                "事务后端：完成。%1；R3 复读与替换字节一致。"
                "原始证据快照仍保留在当前表格中。")
                .arg(mutationResponseText(
                    QStringLiteral("COMMIT"),
                    kCommitted));
        mutationStatusLabel_->setText(kCompletedText);
        QMessageBox::information(
            this,
            QStringLiteral("内核字节事务"),
            kCompletedText);
    }
}
