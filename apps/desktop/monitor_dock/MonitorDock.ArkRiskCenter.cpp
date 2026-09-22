#include "MonitorDock.h"
#include "../ui/VisibleTableWidget.h"
#include "../internationalization/LanguageManager.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/TableColumnAutoFit.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../../../shared/platform/process/Process.h"
#include "../Theme.h"

// F-09 / F-12: This file is the first location to integrate these two criteria into production call points.
// The criteria remain in shared/evidence (Qt-free / Win32-free); this layer only handles value conversion
// and UI text, avoiding a makeshift "looks like the same process" implementation on the Qt side.
#include "../../../shared/evidence/LiveNavigation.h"
#include "../../../shared/evidence/ObjectIdentity.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QByteArray>
#include <QCheckBox>
#include <QClipboard>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QIODevice>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaMethod>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QVariant>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

// evidence: Short alias for analysis-layer criteria. The production side only passes values and reads its enum conclusions.
namespace evidence = ksword::evidence;

namespace
{
    enum class RiskColumn : int { kScore = 0, kSource, kCategory, kTitle, kDetail, kCount };

    constexpr int kRiskEntryIndexRole = Qt::UserRole + 1;
    constexpr int kRiskProcessIdRole = Qt::UserRole + 2;
    // kRiskEvidenceIdRole: F-12 evidence ID follows the table row.
    // Why not reuse kRiskEntryIndexRole to check the cache: the index remains 'valid' after the snapshot is swapped,
    // silently pointing to a different record. An evidence ID that cannot be found should be explicitly exposed as such.
    constexpr int kRiskEvidenceIdRole = Qt::UserRole + 3;

    // ERROR_ACCESS_DENIED / ERROR_INVALID_PARAMETER。
    // Do not include Windows.h here: this file only needs to distinguish between "read failure" and
    // "does not exist"; using two constants is clearer than pulling in the entire Win32 header.
    constexpr std::uint64_t kWin32ErrorAccessDenied = 5U;
    constexpr std::uint64_t kWin32ErrorInvalidParameter = 87U;

    int riskColumnIndex(const RiskColumn column)
    {
        // Input: risk-center logical column. Processing: cast to Qt table column. Return: integer index.
        return static_cast<int>(column);
    }

    QString hex64(const std::uint64_t value)
    {
        // Input: 64-bit address/hash/mask. Processing: render fixed-width uppercase hex. Return: display text.
        return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), 16, 16, QChar('0')).toUpper();
    }

    QString hex32(const std::uint32_t value)
    {
        // Input: 32-bit flags/status. Processing: render fixed-width uppercase hex. Return: display text.
        return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0')).toUpper();
    }

    QString wideText(const std::wstring& value)
    {
        // Input: ArkDriverClient wide string. Processing: convert to QString. Return: empty or display text.
        return value.empty() ? QString() : QString::fromStdWString(value);
    }

    QString narrowText(const std::string& value)
    {
        // Input: ArkDriverClient narrow string. Processing: convert to QString. Return: empty or display text.
        return value.empty() ? QString() : QString::fromStdString(value);
    }

    QString friendlyIoMessage(const std::string& value)
    {
        // Input: ArkDriverClient io.message raw text.
        // Processing: Convert DeviceIoControl/unsupported/empty messages into Chinese descriptions suitable for the status bar and risk details.
        // Returns: short text that can be directly concatenated into the ARK Risk Center summary row.
        const QString kRawText = narrowText(value).trimmed();
        if (kRawText.isEmpty())
        {
            return QStringLiteral("无额外驱动消息");
        }
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该审计入口");
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动版本尚未提供该审计入口");
        }
        return kRawText;
    }

    double clampScore(const double score)
    {
        // Input: arbitrary risk score. Processing: clamp to the risk-center range. Return: 0..100 score.
        return std::max(0.0, std::min(100.0, score));
    }

    QString scoreText(const double score)
    {
        // Input: normalized risk score. Processing: keep one decimal place. Return: sortable display text.
        return QString::number(clampScore(score), 'f', 1);
    }

    QString ioSummary(const ksword::ark::IoResult& io)
    {
        // Input: ArkDriverClient I/O result. Processing: compact transport/protocol diagnostics. Return: one line.
        return QStringLiteral("ok=%1 win32=%2 nt=%3 bytes=%4 说明=%5")
            .arg(io.ok ? QStringLiteral("true") : QStringLiteral("false"))
            .arg(io.win32Error)
            .arg(hex32(static_cast<std::uint32_t>(io.ntStatus)))
            .arg(io.bytesReturned)
            .arg(friendlyIoMessage(io.message));
    }

    QString arkRiskTableMenuStyle()
    {
        // Inputs: None.
        // Processing: Generate an opaque QMenu style to prevent transparency or unreadable text in the right-click menu under dark themes.
        // Returns: style text directly applicable to setStyleSheet for the table's right-click menu.
        return QStringLiteral(
            "QMenu{background:%1;color:%2;border:1px solid %3;}"
            "QMenu::item{padding:5px 24px 5px 24px;background:transparent;}"
            "QMenu::item:selected{background:%4;color:%6;}"
            "QMenu::item:disabled{color:%5;}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::textSecondaryHex())
            .arg(ksword_theme::onAccentDynamicHex());
    }

    void copyArkRiskTableCurrentRow(QTableWidget* table)
    {
        // Input: Risk center table.
        // Processing: Read all columns of the currently displayed row and write to clipboard in TSV format.
        // Returns: None; returns silently if there is no current row or the clipboard is unavailable.
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const int kRowIndex = table->currentRow();
        if (kRowIndex < 0 || kRowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(kRowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(fields.join(QChar('\t')));
    }

    void installArkRiskTableCopyMenu(MonitorDock* dock, QTableWidget* table)
    {
        // Input: Risk center's Dock and result table.
        // Processing: Install 'Copy Current Row' and 'Go to Process Details' context menu items; synchronize the current cell when right-clicking a row.
        //       The jump itself is delegated to MonitorDock::navigateToProcessDetailFromArkRiskRow, because
        //       The criteria for F-09/F-12 require reading the Dock's snapshot cache (evidence ID reverse lookup), which this menu layer cannot access.
        // Returns: None; triggers no audit actions or system modifications.
        if (dock == nullptr || table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QPointer<MonitorDock> guardDock(dock);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [guardDock, table](const QPoint& localPosition) {
            const QModelIndex kClickedIndex = table->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                table->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            }

            QMenu menu(table);
            menu.setStyleSheet(arkRiskTableMenuStyle());
            QAction* copyRowAction = menu.addAction(QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);

            quint32 processId = 0U;
            const QTableWidgetItem* scoreItem = table->currentRow() >= 0
                ? table->item(table->currentRow(), riskColumnIndex(RiskColumn::kScore))
                : nullptr;
            bool processIdOk = false;
            const qulonglong kStoredProcessId = scoreItem != nullptr
                ? scoreItem->data(kRiskProcessIdRole).toULongLong(&processIdOk)
                : 0ULL;
            if (processIdOk && kStoredProcessId > 0ULL &&
                kStoredProcessId <= static_cast<qulonglong>(std::numeric_limits<quint32>::max()))
            {
                processId = static_cast<quint32>(kStoredProcessId);
            }

            QAction* openProcessAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_details.svg")),
                QStringLiteral("转到进程详细信息"));
            // Clicking is allowed if this row points to a PID: eligibility is determined by the predicate, and the explanation is also
            // provided by the predicate. Disabling the menu item prematurely would only confuse users about why they cannot proceed.
            openProcessAction->setEnabled(processId != 0U);

            const int kCurrentRow = table->currentRow();
            const QAction* selectedAction = menu.exec(table->viewport()->mapToGlobal(localPosition));
            if (selectedAction == copyRowAction)
            {
                copyArkRiskTableCurrentRow(table);
            }
            else if (selectedAction == openProcessAction && guardDock != nullptr)
            {
                guardDock->navigateToProcessDetailFromArkRiskRow(kCurrentRow);
            }
        });
    }

    quint32 payloadProcessId(const QJsonObject& payload)
    {
        const QJsonValue kProcessIdValue = payload.value(QStringLiteral("processId"));
        bool processIdOk = false;
        const qulonglong kProcessId = kProcessIdValue.toVariant().toULongLong(&processIdOk);
        return processIdOk && kProcessId > 0ULL &&
            kProcessId <= static_cast<qulonglong>(std::numeric_limits<quint32>::max())
            ? static_cast<quint32>(kProcessId)
            : 0U;
    }

    QString arkRiskSessionBootId()
    {
        // Inputs: None.
        // Handling: Return the session identifier for the current KSword run, serving as a conservative proxy for ProcessInstanceId::bootId.
        //       Why this usage is valid (F-03/F-09):
        //         1) ObjectIdentity.h requires non-empty, equal bootId values on both sides before a Confirmed
        //            result is possible, preventing matches based on the same PID across different boots;
        //         2) The risk center snapshot exists only in memory. Collection and clicks must occur within the same process run,
        //            and a single process run cannot span a reboot. Therefore, "same run ⇒ same boot cycle" is not an overstatement.
        //         3) Reverse deviation is safe: even if two runs occur within the same system boot, they will obtain different
        //            tokens. The result will only degrade to Candidate and reject the jump, never allowing an incorrect target.
        // Returns: Session identifier text constant within the process.
        static const QString kSessionBootId = QStringLiteral("ksword-run-%1-%2")
            .arg(static_cast<qulonglong>(QCoreApplication::applicationPid()))
            .arg(static_cast<qulonglong>(QDateTime::currentMSecsSinceEpoch()));
        return kSessionBootId;
    }

    bool parseWin32CodeFromDetail(const std::string& detailText, std::uint64_t& codeOut)
    {
        // Input: Diagnostic text from ks::process::queryProcessCreationTimeByPid, formatted as "OpenProcess failed(5)".
        // Handling: Extract the decimal number from the last pair of parentheses. Never fabricate
        //       0 on parse failure—this would disguise 'unknown error code' as 'error code 0 (success)'.
        // Returns true with codeOut written on success; otherwise returns false without modifying codeOut.
        const std::size_t kOpenIndex = detailText.rfind('(');
        if (kOpenIndex == std::string::npos)
        {
            return false;
        }
        const std::size_t kCloseIndex = detailText.find(')', kOpenIndex + 1U);
        if (kCloseIndex == std::string::npos || kCloseIndex <= kOpenIndex + 1U)
        {
            return false;
        }
        const std::string_view kCodeText =
            std::string_view(detailText).substr(kOpenIndex + 1U, kCloseIndex - kOpenIndex - 1U);
        return evidence::parseU64(kCodeText, codeOut);
    }

    struct LiveProcessProbe final
    {
        // present: Indicates whether there is positive evidence that the PID is currently bound to a process object.
        // Note this is not equal to createTimeKnown: insufficient permissions to read creation time actually indicate the object exists.
        bool present = false;
        bool createTimeKnown = false;
        std::uint64_t createTime100ns = 0U;
        evidence::CollectionOutcome outcome;
    };

    LiveProcessProbe probeProcessCreateTime(const std::uint32_t processId)
    {
        // Input: Target PID.
        // Processing: Read the creation time of the current process instance once, and decompose the failure semantics (F-05):
        //         * Success -> present + createTimeKnown
        //         * ERROR_INVALID_PARAMETER (87) -> No process exists for this PID, present=false
        //         * ERROR_ACCESS_DENIED (5) and others -> Object exists but creation time cannot be read, present=true.
        //       Why does the default fall to 'cannot read' instead of 'exited'? resolveProcessNavigation treats
        //       !found directly as RejectObjectExited. If permission failure is also treated as !found, it would
        //       falsely claim a still-living process has exited, which is a fabricated conclusion.
        //       Both paths reject the jump; the difference lies only in whether the explanation provided to the user is accurate.
        // Returns: The probe result; the original error code is preserved alongside the text in outcome.
        LiveProcessProbe probe;
        if (processId == 0U)
        {
            probe.outcome = evidence::CollectionOutcome::notCollected();
            return probe;
        }

        std::uint64_t createTime100ns = 0U;
        std::string detailText;
        if (ks::process::queryProcessCreationTimeByPid(processId, &createTime100ns, &detailText))
        {
            probe.present = true;
            probe.createTimeKnown = true;
            probe.createTime100ns = createTime100ns;
            probe.outcome = evidence::CollectionOutcome::success();
            return probe;
        }

        std::uint64_t win32Code = 0U;
        const bool kCodeKnown = parseWin32CodeFromDetail(detailText, win32Code);
        if (!kCodeKnown)
        {
            // Failed to parse the error code: set status to Error and leave nativeCode unset ("unknown" is not 0).
            probe.present = true;
            probe.outcome.status = evidence::CollectionStatus::kError;
            probe.outcome.message = detailText;
            return probe;
        }

        probe.present = win32Code != kWin32ErrorInvalidParameter;
        probe.outcome = evidence::CollectionOutcome::failure(
            win32Code == kWin32ErrorAccessDenied
                ? evidence::CollectionStatus::kAccessDenied
                : evidence::CollectionStatus::kError,
            std::string("WIN32"),
            win32Code,
            detailText);
        return probe;
    }

    evidence::ProcessInstanceId makeSavedProcessIdentity(const MonitorDock::ArkRiskCenterEntry& entry)
    {
        // Input: A single risk record.
        // Processing: Translate fields fixed during the collection phase into ProcessInstanceId for the
        //       analysis layer. Perform value conversion only; do not inject Qt types into shared/evidence.
        //       When pid or createTime is missing, keep OptionalU64 in the unset state: this causes strength() to become
        //       Weak/Unusable, crossSessionKey() to return an empty string, and navigation to be judged as IdentityUnusable.
        //       This is exactly what we want: do not allow jumps if identity is insufficient.
        // Returns: Identity during collection period.
        evidence::ProcessInstanceId identity;
        identity.bootId = entry.identityBootId.toStdString();
        if (entry.processId != 0U)
        {
            identity.pid = evidence::OptionalU64::of(static_cast<std::uint64_t>(entry.processId));
        }
        if (entry.processCreateTimeKnown)
        {
            identity.createTime100ns = evidence::OptionalU64::of(entry.processCreateTime100ns);
        }
        identity.imageName = entry.payload.value(QStringLiteral("imageName")).toString().toStdString();
        return identity;
    }

    QJsonValue optionalU64Json(const evidence::OptionalU64& value, const evidence::U64Format format)
    {
        // Input: A potentially unknown 64-bit value and a persistence format.
        // Processing: Output JSON null for unknown values; output decimal or hexadecimal strings for known values.
        //       F-08: Operate entirely with strings, avoiding doubles; "unknown" must never degrade to "0".
        // Returns: A JSON value ready to be inserted directly into a payload.
        const std::string kText = evidence::formatOptionalU64(value, format);
        return kText.empty() ? QJsonValue(QJsonValue::Null) : QJsonValue(QString::fromStdString(kText));
    }

    QJsonObject collectionOutcomeJson(const evidence::CollectionOutcome& outcome)
    {
        // Input: Result of a single collection.
        // Handling: Include status, original error code field, original error code, and original message in the export
        //       to maintain distinguishability for 'Access Denied', 'Not Found', and 'Other Failures' in JSON/CSV (F-05).
        // Returns: payload sub-object.
        QJsonObject json;
        json.insert(QStringLiteral("status"),
            QString::fromLatin1(evidence::collectionStatusName(outcome.status)));
        json.insert(QStringLiteral("nativeCodeDomain"),
            outcome.nativeCodeDomain.empty() ? QJsonValue(QJsonValue::Null)
                                             : QJsonValue(QString::fromStdString(outcome.nativeCodeDomain)));
        json.insert(QStringLiteral("nativeCode"),
            optionalU64Json(outcome.nativeCode, evidence::U64Format::kDecimal));
        json.insert(QStringLiteral("message"),
            outcome.message.empty() ? QJsonValue(QJsonValue::Null)
                                    : QJsonValue(QString::fromStdString(outcome.message)));
        return json;
    }

    void attachArkRiskNavigationIdentity(
        std::vector<MonitorDock::ArkRiskCenterEntry>& entries,
        const QString& sessionBootId,
        const std::uint64_t refreshTicket)
    {
        // Input: sorted risk rows, session ID for this run, and refresh ticket for this round.
        // Processing: F-12 sends an evidence ID for each row; F-09 fixes the identity (PID + creation
        //       time) of the process instance pointed to by that row at the **moment of collection**.
        //       Why read the creation time here: if read when the user clicks, it captures the
        //       process currently occupying that PID, making it impossible to prove it is the same
        //       instance as the one mentioned in the risk row—PID reuse would be completely missed.
        //       If the value cannot be read, keep processCreateTimeKnown=false; never write 0 as a substitute.
        // Returns void. This function runs on the worker thread, writing only to source text and values without calling LanguageManager.
        std::unordered_map<std::uint32_t, LiveProcessProbe> probeCache;
        for (std::size_t index = 0; index < entries.size(); ++index)
        {
            MonitorDock::ArkRiskCenterEntry& entry = entries[index];
            // The evidence ID includes the ticket: old snapshot rows will not collide with new snapshot row IDs,
            // allowing detection of 'menu still open but snapshot changed' instead of silently pointing to someone else.
            entry.evidenceId = QStringLiteral("ark-risk/%1/%2")
                .arg(static_cast<qulonglong>(refreshTicket))
                .arg(static_cast<qulonglong>(index));
            entry.payload.insert(QStringLiteral("evidenceId"), entry.evidenceId);

            entry.identityBootId = sessionBootId;
            entry.processId = static_cast<std::uint32_t>(payloadProcessId(entry.payload));
            if (entry.processId == 0U)
            {
                // This line does not point to a process (driver / CPU / Hook class).
                // Keep as NotCollected: this is not a 'collection failure' nor does it indicate 'no identity issues'.
                entry.processIdentityOutcome = evidence::CollectionOutcome::notCollected();
                continue;
            }

            auto cached = probeCache.find(entry.processId);
            if (cached == probeCache.end())
            {
                cached = probeCache.emplace(entry.processId, probeProcessCreateTime(entry.processId)).first;
            }
            const LiveProcessProbe& probe = cached->second;
            entry.processCreateTimeKnown = probe.createTimeKnown;
            entry.processCreateTime100ns = probe.createTime100ns;
            entry.processIdentityOutcome = probe.outcome;

            evidence::OptionalU64 createTime;
            if (probe.createTimeKnown)
            {
                createTime = evidence::OptionalU64::of(probe.createTime100ns);
            }
            QJsonObject identityJson;
            identityJson.insert(QStringLiteral("bootId"), sessionBootId);
            identityJson.insert(QStringLiteral("pid"),
                QString::fromStdString(evidence::formatU64(entry.processId, evidence::U64Format::kDecimal)));
            identityJson.insert(QStringLiteral("createTime100ns"),
                optionalU64Json(createTime, evidence::U64Format::kDecimal));
            identityJson.insert(QStringLiteral("createTimeCollection"), collectionOutcomeJson(probe.outcome));
            entry.payload.insert(QStringLiteral("processIdentity"), identityJson);
        }
    }

    bool processDetailRouteAvailable()
    {
        // Inputs: None.
        // Processing: Read-only probe for top-level windows capable of receiving navigation to process details with identity.
        //       Note: Why not use invokeMethod for probing: it would actually send the navigation, preventing a pre-check before deciding.
        //       F-12 requires "accurate explanation when target is missing," so "target page not
        //       present" and "object not in page" must be distinguished as separate conclusions.
        // Returns true if a window capable of receiving the navigation exists.
        const QWidgetList kTopLevelWidgetList = QApplication::topLevelWidgets();
        for (const QWidget* topLevelWidget : kTopLevelWidgetList)
        {
            if (topLevelWidget == nullptr)
            {
                continue;
            }
            const QMetaObject* metaObject = topLevelWidget->metaObject();
            for (int methodIndex = 0; methodIndex < metaObject->methodCount(); ++methodIndex)
            {
                const QMetaMethod kMethod = metaObject->method(methodIndex);
                // Match by method name and parameter count without constructing signature strings: MOC records the type names (quint32/quint64) as
                // written in the header file. If the constructed signature does not match, it will be incorrectly judged as 'target page not found'.
                if (kMethod.parameterCount() == 2 &&
                    kMethod.name() == QByteArrayLiteral("openProcessDetailByIdentity"))
                {
                    return true;
                }
            }
        }
        return false;
    }

    QString arkRiskNavigationRejectionText(
        const evidence::NavigationOutcome outcome,
        const evidence::LiveNavigationDecision liveDecision,
        const bool liveDecisionEvaluated,
        const bool noProcessBinding)
    {
        // Input: F-12 request judgment, F-09 on-site review judgment, whether the
        //       latter actually ran, and whether this line points to no process at all.
        // Note: Translate the conclusion of the two criteria into a single sentence readable by
        //       the user. This is called only on the GUI thread, so LanguageManager can be used here.
        // Returns: The rejection reason text.
        if (noProcessBinding)
        {
            // The criterion is also IdentityUnusable, but the reason is 'no object' rather than 'creation time not retrieved'.
            // Reusing the latter text would mislead users into checking for a non-existent permission issue.
            return ks::i18n::contextText(
                QStringLiteral("monitor.ark_risk.nav.no_process"),
                QStringLiteral("该风险记录没有关联到任何进程实例，无法转到进程详情。"));
        }
        if (!liveDecisionEvaluated)
        {
            switch (outcome)
            {
            case evidence::NavigationOutcome::kIdentityUnusable:
                return ks::i18n::contextText(
                    QStringLiteral("monitor.ark_risk.nav.identity_unusable"),
                    QStringLiteral(
                        "该风险记录在采集时没能取到进程创建时间，身份不足以确认是同一个进程实例。"
                        "为避免 PID 被复用后打开无关进程，本次跳转已取消。"));
            case evidence::NavigationOutcome::kEvidenceIdMissing:
                return ks::i18n::contextText(
                    QStringLiteral("monitor.ark_risk.nav.evidence_id_missing"),
                    QStringLiteral("该行没有携带证据 id，跳转后无法回到原始证据，本次跳转已取消。"));
            case evidence::NavigationOutcome::kEvidenceNotSaved:
                return ks::i18n::contextText(
                    QStringLiteral("monitor.ark_risk.nav.evidence_not_saved"),
                    QStringLiteral(
                        "这条证据已不在当前风险快照中（快照可能已被重新刷新）。请重新刷新风险后再试。"));
            case evidence::NavigationOutcome::kTargetPageMissing:
                return ks::i18n::contextText(
                    QStringLiteral("monitor.ark_risk.nav.target_page_missing"),
                    QStringLiteral("找不到可接收进程详情导航的主窗口，目标页可能已关闭。"));
            case evidence::NavigationOutcome::kObjectNotPresent:
                return ks::i18n::contextText(
                    QStringLiteral("monitor.ark_risk.nav.object_not_present"),
                    QStringLiteral("该 PID 对应的进程当前已不存在，无法转到进程详情。"));
            case evidence::NavigationOutcome::kDelivered:
                // Delivered events always trigger manual review and will not reach this point; this code remains to exhaustively cover all enumeration cases.
                break;
            }
            // Default to stating "unable to confirm" without fabricating a more definitive conclusion based on the criteria.
            return ks::i18n::contextText(
                QStringLiteral("monitor.ark_risk.nav.identity_unverifiable"),
                QStringLiteral(
                    "现场无法确认该 PID 仍是采集时的那个进程实例（例如权限不足读不到创建时间）。"
                    "本次跳转已取消。"));
        }

        switch (liveDecision)
        {
        case evidence::LiveNavigationDecision::kRejectObjectExited:
            return ks::i18n::contextText(
                QStringLiteral("monitor.ark_risk.nav.object_exited"),
                QStringLiteral("该风险记录对应的进程实例已退出，本次跳转已取消。"));
        case evidence::LiveNavigationDecision::kRejectIdentityMismatch:
            return ks::i18n::contextText(
                QStringLiteral("monitor.ark_risk.nav.identity_mismatch"),
                QStringLiteral(
                    "该 PID 现在属于另一个进程实例（创建时间不一致，PID 已被复用）。"
                    "本次跳转已取消，不会把操作交给新进程。"));
        case evidence::LiveNavigationDecision::kRejectIdentityUnverifiable:
            return ks::i18n::contextText(
                QStringLiteral("monitor.ark_risk.nav.identity_unverifiable"),
                QStringLiteral(
                    "现场无法确认该 PID 仍是采集时的那个进程实例（例如权限不足读不到创建时间）。"
                    "本次跳转已取消。"));
        case evidence::LiveNavigationDecision::kAllow:
            // When Allow is chosen, the caller has already exited and will not request the rejection text; this is also to exhaustively cover the enum.
            break;
        }
        return ks::i18n::contextText(
            QStringLiteral("monitor.ark_risk.nav.identity_unverifiable"),
            QStringLiteral(
                "现场无法确认该 PID 仍是采集时的那个进程实例（例如权限不足读不到创建时间）。"
                "本次跳转已取消。"));
    }

    QJsonObject payloadBase(const QString& source, const QString& category, const QString& title, const QString& detail, const double score)
    {
        // Input: Risk source, category, title, details, and score.
        // Processing: Construct a JSON root object shared by the export and detail sections.
        // Returns: A payload object containing basic risk fields.
        QJsonObject payload;
        payload.insert(QStringLiteral("source"), source);
        payload.insert(QStringLiteral("category"), category);
        payload.insert(QStringLiteral("title"), title);
        payload.insert(QStringLiteral("detail"), detail);
        payload.insert(QStringLiteral("riskScore"), clampScore(score));
        return payload;
    }

    MonitorDock::ArkRiskCenterEntry makeEntry(
        const QString& source,
        const QString& category,
        const QString& title,
        const QString& detail,
        const double score,
        QJsonObject payload)
    {
        // Input: display fields and structured payload. Processing: fill cache row. Return: risk-center entry.
        MonitorDock::ArkRiskCenterEntry entry;
        entry.sourceName = source;
        entry.category = category;
        entry.title = title;
        entry.detail = detail;
        entry.riskScore = clampScore(score);
        entry.riskScoreText = scoreText(entry.riskScore);
        payload.insert(QStringLiteral("source"), source);
        payload.insert(QStringLiteral("category"), category);
        payload.insert(QStringLiteral("title"), title);
        payload.insert(QStringLiteral("detail"), detail);
        payload.insert(QStringLiteral("riskScore"), entry.riskScore);
        entry.payload = std::move(payload);
        return entry;
    }

    class ScoreItem final : public QTableWidgetItem
    {
    public:
        explicit ScoreItem(const double score)
            : QTableWidgetItem(scoreText(score))
        {
            // Input: risk score. Processing: store numeric UserRole for sorting. Return: constructor has no return.
            setData(Qt::UserRole, clampScore(score));
            setTextAlignment(Qt::AlignVCenter | Qt::AlignRight);
        }

        bool operator<(const QTableWidgetItem& other) const override
        {
            // Input: another table item. Processing: prefer numeric UserRole comparison. Return: sort decision.
            bool leftOk = false;
            bool rightOk = false;
            const double kLeft = data(Qt::UserRole).toDouble(&leftOk);
            const double kRight = other.data(Qt::UserRole).toDouble(&rightOk);
            return (leftOk && rightOk) ? kLeft < kRight : QTableWidgetItem::operator<(other);
        }
    };

    QTableWidgetItem* textItem(const QString& value)
    {
        // Input: display text. Processing: create read-only table item. Return: item owned by QTableWidget.
        QTableWidgetItem* item = new QTableWidgetItem(value);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QString csvEscape(const QString& value)
    {
        // Input: CSV field. Processing: quote when needed and double embedded quotes. Return: CSV-safe text.
        QString escaped = value;
        escaped.replace(QChar('"'), QStringLiteral("\"\""));
        if (escaped.contains(QChar(',')) || escaped.contains(QChar('"')) || escaped.contains(QChar('\n')) || escaped.contains(QChar('\r')))
        {
            escaped = QStringLiteral("\"%1\"").arg(escaped);
        }
        return escaped;
    }

    bool matchesFilter(const MonitorDock::ArkRiskCenterEntry& entry, const QString& filter)
    {
        // Input: cache row and filter text. Processing: case-insensitive scan across display fields and JSON. Return: match flag.
        if (filter.isEmpty())
        {
            return true;
        }
        const QString kPayloadText = QString::fromUtf8(QJsonDocument(entry.payload).toJson(QJsonDocument::Compact));
        const QStringList kFields{ entry.sourceName, entry.category, entry.title, entry.detail, entry.riskScoreText, kPayloadText };
        for (const QString& field : kFields)
        {
            if (field.contains(filter, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    void addStatusEntry(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, QStringList& statusLines, const QString& source, const QString& category, const bool ok, const bool unsupported, const ksword::ark::IoResult& io)
    {
        // Input: one read-only query status. Processing: append status text and optional low-risk failure row. Return: no value.
        const QString kSummary = unsupported ? QStringLiteral("%1: 未集成/驱动过旧/能力缺失").arg(source) : QStringLiteral("%1: %2").arg(source, ioSummary(io));
        statusLines << kSummary;
        if (ok)
        {
            return;
        }
        const double kRisk = unsupported ? 0.0 : 5.0;
        QJsonObject payload = payloadBase(source, category, unsupported ? QStringLiteral("等待 R0 支持") : QStringLiteral("查询失败"), kSummary, kRisk);
        payload.insert(QStringLiteral("unsupported"), unsupported);
        payload.insert(QStringLiteral("win32Error"), static_cast<int>(io.win32Error));
        payload.insert(QStringLiteral("ntStatus"), hex32(static_cast<std::uint32_t>(io.ntStatus)));
        entries.push_back(makeEntry(source, category, unsupported ? QStringLiteral("未集成/驱动过旧") : QStringLiteral("查询失败"), kSummary, kRisk, payload));
    }

    double memoryScore(const ksword::ark::KernelMemoryEvidenceEntry& row)
    {
        // Input: memory evidence row. Processing: score RWX/non-module/pool/text risks and confidence. Return: risk score.
        double score = 0.0;
        if (row.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX) score += 35.0;
        if (row.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE) score += 35.0;
        if (row.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE) score += 25.0;
        if (row.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL) score += 25.0;
        if (row.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE) score += 12.0;
        if (row.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING) score += 12.0;
        score += std::min<double>(15.0, static_cast<double>(row.confidence) / 10.0);
        return clampScore(score);
    }

    QString memoryRiskText(const std::uint32_t flags)
    {
        // Input: memory evidence risk bits. Processing: map known bits. Return: compact text.
        QStringList parts;
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX) parts << QStringLiteral("RWX");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE) parts << QStringLiteral("非模块执行");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE) parts << QStringLiteral("模块非text执行");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL) parts << QStringLiteral("执行池");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE) parts << QStringLiteral("大页执行");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING) parts << QStringLiteral("Owner缺失");
        return parts.isEmpty() ? QStringLiteral("正常") : parts.join(QStringLiteral(" | "));
    }

    double crossViewScore(const std::uint32_t flags, const std::uint32_t confidence)
    {
        // Input: cross-view anomaly bits and confidence. Processing: score DKOM-style mismatches. Return: risk score.
        double score = 0.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST) score += 40.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE) score += 35.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN) score += 35.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY) score += 30.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE) score += 30.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT) score += 30.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST) score += 28.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY) score += 20.0;
        score += std::min<double>(15.0, static_cast<double>(confidence) / 10.0);
        return clampScore(score);
    }

    QString crossViewText(const std::uint32_t flags)
    {
        // Input: cross-view anomaly bits. Processing: map known DKOM indicators. Return: compact text.
        QStringList parts;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY) parts << QStringLiteral("CID-only");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY) parts << QStringLiteral("Active-only");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST) parts << QStringLiteral("缺ActiveList");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE) parts << QStringLiteral("缺CID");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN) parts << QStringLiteral("孤儿线程");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST) parts << QStringLiteral("线程进程缺失");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE) parts << QStringLiteral("入口出模块");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT) parts << QStringLiteral("悬空对象");
        return parts.isEmpty() ? QStringLiteral("正常") : parts.join(QStringLiteral(" | "));
    }

    double driverScore(const std::uint32_t flags, const std::uint32_t confidence)
    {
        // Input: driver integrity risk bits and confidence. Processing: score CPU/IDT/owner/dispatch risks. Return: risk score.
        double score = 0.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER) score += 40.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH) score += 35.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE) score += 35.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED) score += 35.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID) score += 25.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED) score += 25.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED) score += 22.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH) score += 18.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH) score += 18.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED) score += 18.0;
        score += std::min<double>(15.0, static_cast<double>(confidence) / 10.0);
        return clampScore(score);
    }

    QString driverRiskText(const std::uint32_t flags)
    {
        // Input: driver integrity risk bits. Processing: map high-value known bits. Return: compact text.
        QStringList parts;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH) parts << QStringLiteral("Owner不匹配");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE) parts << QStringLiteral("外跳");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER) parts << QStringLiteral("IDT外部Owner");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED) parts << QStringLiteral("WP关闭");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED) parts << QStringLiteral("NXE关闭");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED) parts << QStringLiteral("SMEP关闭");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED) parts << QStringLiteral("SMAP关闭");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID) parts << QStringLiteral("描述符异常");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH) parts << QStringLiteral("Section不匹配");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH) parts << QStringLiteral("跨驱动挂接");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED) parts << QStringLiteral("模块未解析");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE) parts << QStringLiteral("DynData缺失");
        return parts.isEmpty() ? hex32(flags) : parts.join(QStringLiteral(" | "));
    }

    QString hookStatusText(const std::uint32_t status)
    {
        // Input: kernel hook status. Processing: map known status codes. Return: display text.
        switch (status)
        {
        case KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN: return QStringLiteral("Clean");
        case KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS: return QStringLiteral("Suspicious");
        case KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH: return QStringLiteral("InternalBranch");
        case KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED: return QStringLiteral("ReadFailed");
        case KSWORD_ARK_KERNEL_HOOK_STATUS_PARSE_FAILED: return QStringLiteral("ParseFailed");
        case KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED: return QStringLiteral("ForceRequired");
        default: return QStringLiteral("Status(%1)").arg(status);
        }
    }

    double hookScore(const std::uint32_t status, const bool hasPatchOrDiff)
    {
        // Input: hook status and patch/diff presence. Processing: score suspicious hook evidence. Return: risk score.
        double score = hasPatchOrDiff ? 25.0 : 0.0;
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS) score += 60.0;
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED) score += 55.0;
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED) score += 15.0;
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_PARSE_FAILED) score += 15.0;
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH) score += 8.0;
        return clampScore(score);
    }

    QString callbackClassText(const std::uint32_t callbackClass)
    {
        // Input: callback class id. Processing: map shared protocol constants. Return: display text.
        switch (callbackClass)
        {
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY: return QStringLiteral("Registry");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS: return QStringLiteral("Process");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD: return QStringLiteral("Thread");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE: return QStringLiteral("Image");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT: return QStringLiteral("Object");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER: return QStringLiteral("Minifilter");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT: return QStringLiteral("WFP");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER: return QStringLiteral("ETW");
        default: return QStringLiteral("Callback(%1)").arg(callbackClass);
        }
    }

    double callbackScore(const ksword::ark::CallbackEnumEntry& row)
    {
        // Input: callback enumeration row. Processing: score private/unresolved/untrusted rows. Return: risk score.
        double score = 0.0;
        if (row.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED) score += 20.0;
        if (row.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED ||
            row.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN ||
            row.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY ||
            row.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST ||
            row.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST)
        {
            score += 25.0;
        }
        if (row.moduleBase == 0U && row.callbackAddress != 0U) score += 30.0;
        if ((row.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE) == 0U) score += 15.0;
        if ((row.trustFlags & (KSWORD_ARK_CALLBACK_TRUST_REVALIDATED | KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API | KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE)) == 0U) score += 12.0;
        return clampScore(score);
    }

    QString mutationOperationText(const std::uint32_t operation)
    {
        // Input: mutation operation id. Processing: map known audit operation. Return: display text.
        switch (operation)
        {
        case KSWORD_ARK_MUTATION_OPERATION_PREPARE: return QStringLiteral("Prepare");
        case KSWORD_ARK_MUTATION_OPERATION_COMMIT: return QStringLiteral("Commit");
        case KSWORD_ARK_MUTATION_OPERATION_ROLLBACK: return QStringLiteral("Rollback");
        case KSWORD_ARK_MUTATION_OPERATION_QUERY_AUDIT: return QStringLiteral("QueryAudit");
        default: return QStringLiteral("Operation(%1)").arg(operation);
        }
    }

    QString mutationStatusText(const std::uint32_t status)
    {
        // Input: mutation status id. Processing: map common audit status. Return: display text.
        switch (status)
        {
        case KSWORD_ARK_MUTATION_STATUS_PREPARED: return QStringLiteral("Prepared");
        case KSWORD_ARK_MUTATION_STATUS_DRY_RUN: return QStringLiteral("DryRun");
        case KSWORD_ARK_MUTATION_STATUS_COMMITTED: return QStringLiteral("Committed");
        case KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK: return QStringLiteral("RolledBack");
        case KSWORD_ARK_MUTATION_STATUS_REJECTED_SAFETY_POLICY: return QStringLiteral("RejectedSafetyPolicy");
        case KSWORD_ARK_MUTATION_STATUS_REJECTED_BEFORE_MISMATCH: return QStringLiteral("RejectedBeforeMismatch");
        case KSWORD_ARK_MUTATION_STATUS_REJECTED_TARGET_CHANGED: return QStringLiteral("RejectedTargetChanged");
        case KSWORD_ARK_MUTATION_STATUS_WRITE_FAILED: return QStringLiteral("WriteFailed");
        case KSWORD_ARK_MUTATION_STATUS_READ_FAILED: return QStringLiteral("ReadFailed");
        default: return QStringLiteral("Status(%1)").arg(status);
        }
    }

    double mutationScore(const ksword::ark::MutationAuditEntry& row)
    {
        // Input: mutation audit row. Processing: score commit/write-fail/rejected changes; dry-run lowers score. Return: risk score.
        double score = 0.0;
        if (row.operation == KSWORD_ARK_MUTATION_OPERATION_COMMIT) score += 45.0;
        if (row.status == KSWORD_ARK_MUTATION_STATUS_COMMITTED) score += 30.0;
        if (row.status == KSWORD_ARK_MUTATION_STATUS_WRITE_FAILED) score += 25.0;
        if (row.status == KSWORD_ARK_MUTATION_STATUS_REJECTED_TARGET_CHANGED) score += 18.0;
        if (row.status == KSWORD_ARK_MUTATION_STATUS_REJECTED_BEFORE_MISMATCH) score += 16.0;
        if (row.operation == KSWORD_ARK_MUTATION_OPERATION_ROLLBACK) score += 12.0;
        if (row.riskFlags != 0U) score += 20.0;
        if ((row.flags & KSWORD_ARK_MUTATION_FLAG_DRY_RUN) != 0U) score -= 20.0;
        return clampScore(score);
    }

    void appendMemory(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::KernelMemoryEvidenceResult& result)
    {
        // Input: memory evidence result. Processing: append only non-zero risk rows. Return: no value.
        for (const auto& row : result.entries)
        {
            if (row.riskFlags == 0U) continue;
            const double kRisk = memoryScore(row);
            const QString kTitle = QStringLiteral("%1 %2").arg(memoryRiskText(row.riskFlags), hex64(row.virtualAddress));
            const QString kDetail = QStringLiteral("owner=%1 size=%2 confidence=%3 %4")
                .arg(wideText(row.ownerName), hex64(row.regionSize)).arg(row.confidence).arg(wideText(row.detail));
            QJsonObject payload = payloadBase(QStringLiteral("Memory Evidence"), QStringLiteral("Memory"), kTitle, kDetail, kRisk);
            payload.insert(QStringLiteral("virtualAddress"), hex64(row.virtualAddress));
            payload.insert(QStringLiteral("regionSize"), hex64(row.regionSize));
            payload.insert(QStringLiteral("riskFlags"), hex32(row.riskFlags));
            payload.insert(QStringLiteral("permissionFlags"), hex32(row.permissionFlags));
            payload.insert(QStringLiteral("ownerName"), wideText(row.ownerName));
            payload.insert(QStringLiteral("contentHash"), hex64(row.contentHash));
            entries.push_back(makeEntry(QStringLiteral("Memory Evidence"), QStringLiteral("Memory"), kTitle, kDetail, kRisk, payload));
        }
    }

    void appendProcessCrossView(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::ProcessCrossViewResult& result)
    {
        // Input: process cross-view result. Processing: append anomalous process rows. Return: no value.
        for (const auto& row : result.entries)
        {
            if (row.anomalyFlags == 0U) continue;
            const double kRisk = crossViewScore(row.anomalyFlags, row.confidence);
            const QString kTitle = QStringLiteral("PID %1 %2").arg(row.processId).arg(crossViewText(row.anomalyFlags));
            const QString kDetail = QStringLiteral("image=%1 object=%2 source=%3 %4")
                .arg(narrowText(row.imageName), hex64(row.objectAddress), hex32(row.sourceMask), narrowText(row.detail));
            QJsonObject payload = payloadBase(QStringLiteral("Process Cross-View"), QStringLiteral("Process"), kTitle, kDetail, kRisk);
            payload.insert(QStringLiteral("processId"), static_cast<int>(row.processId));
            payload.insert(QStringLiteral("imageName"), narrowText(row.imageName));
            payload.insert(QStringLiteral("objectAddress"), hex64(row.objectAddress));
            payload.insert(QStringLiteral("anomalyFlags"), hex32(row.anomalyFlags));
            payload.insert(QStringLiteral("sourceMask"), hex32(row.sourceMask));
            entries.push_back(makeEntry(QStringLiteral("Process Cross-View"), QStringLiteral("Process"), kTitle, kDetail, kRisk, payload));
        }
    }

    void appendThreadCrossView(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::ThreadCrossViewResult& result)
    {
        // Input: thread cross-view result. Processing: append anomalous thread rows. Return: no value.
        for (const auto& row : result.entries)
        {
            if (row.anomalyFlags == 0U) continue;
            const double kRisk = crossViewScore(row.anomalyFlags, row.confidence);
            const QString kTitle = QStringLiteral("TID %1/PID %2 %3").arg(row.threadId).arg(row.processId).arg(crossViewText(row.anomalyFlags));
            const QString kDetail = QStringLiteral("thread=%1 process=%2 start=%3 %4")
                .arg(hex64(row.objectAddress), hex64(row.processObjectAddress), hex64(row.startAddress), narrowText(row.detail));
            QJsonObject payload = payloadBase(QStringLiteral("Thread Cross-View"), QStringLiteral("Thread"), kTitle, kDetail, kRisk);
            payload.insert(QStringLiteral("threadId"), static_cast<int>(row.threadId));
            payload.insert(QStringLiteral("processId"), static_cast<int>(row.processId));
            payload.insert(QStringLiteral("objectAddress"), hex64(row.objectAddress));
            payload.insert(QStringLiteral("anomalyFlags"), hex32(row.anomalyFlags));
            payload.insert(QStringLiteral("sourceMask"), hex32(row.sourceMask));
            entries.push_back(makeEntry(QStringLiteral("Thread Cross-View"), QStringLiteral("Thread"), kTitle, kDetail, kRisk, payload));
        }
    }

    void appendDriverIntegrity(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const QString& source, const ksword::ark::DriverIntegrityResult& result)
    {
        // Input: driver or CPU integrity result. Processing: append rows with risk flags. Return: no value.
        for (const auto& row : result.entries)
        {
            if (row.riskFlags == 0U) continue;
            const double kRisk = driverScore(row.riskFlags, row.confidence);
            const QString kTitle = QStringLiteral("%1 %2").arg(source, driverRiskText(row.riskFlags));
            const QString kDetail = QStringLiteral("owner=%1 object=%2 target=%3 cpu=G%4/%5/V%6 %7")
                .arg(wideText(row.ownerModule), hex64(row.objectAddress), hex64(row.targetAddress))
                .arg(row.processorGroup).arg(row.processorNumber).arg(row.vector).arg(wideText(row.detail));
            QJsonObject payload = payloadBase(source, QStringLiteral("Driver"), kTitle, kDetail, kRisk);
            payload.insert(QStringLiteral("riskFlags"), hex32(row.riskFlags));
            payload.insert(QStringLiteral("objectAddress"), hex64(row.objectAddress));
            payload.insert(QStringLiteral("targetAddress"), hex64(row.targetAddress));
            payload.insert(QStringLiteral("ownerModule"), wideText(row.ownerModule));
            payload.insert(QStringLiteral("processorGroup"), static_cast<int>(row.processorGroup));
            payload.insert(QStringLiteral("processorNumber"), static_cast<int>(row.processorNumber));
            payload.insert(QStringLiteral("vector"), static_cast<int>(row.vector));
            entries.push_back(makeEntry(source, QStringLiteral("Driver"), kTitle, kDetail, kRisk, payload));
        }
    }

    void appendInlineHooks(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::KernelInlineHookScanResult& result)
    {
        // Input: inline hook scan result. Processing: append suspicious or patched rows. Return: no value.
        for (const auto& row : result.entries)
        {
            const bool kHasPatch = row.hookType != KSWORD_ARK_INLINE_HOOK_TYPE_NONE;
            const double kRisk = hookScore(row.status, kHasPatch);
            if (kRisk <= 0.0) continue;
            const QString kFunctionName = narrowText(row.functionName).trimmed();
            const QString kTitle = QStringLiteral("%1 %2").arg(hookStatusText(row.status), kFunctionName.isEmpty() ? hex64(row.functionAddress) : kFunctionName);
            const QString kDetail = QStringLiteral("module=%1 targetModule=%2 function=%3 target=%4")
                .arg(wideText(row.moduleName), wideText(row.targetModuleName), hex64(row.functionAddress), hex64(row.targetAddress));
            QJsonObject payload = payloadBase(QStringLiteral("Inline Hook"), QStringLiteral("Hook"), kTitle, kDetail, kRisk);
            payload.insert(QStringLiteral("status"), hookStatusText(row.status));
            payload.insert(QStringLiteral("hookType"), static_cast<int>(row.hookType));
            payload.insert(QStringLiteral("functionAddress"), hex64(row.functionAddress));
            payload.insert(QStringLiteral("targetAddress"), hex64(row.targetAddress));
            payload.insert(QStringLiteral("moduleName"), wideText(row.moduleName));
            entries.push_back(makeEntry(QStringLiteral("Inline Hook"), QStringLiteral("Hook"), kTitle, kDetail, kRisk, payload));
        }
    }

    void appendIatEatHooks(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::KernelIatEatHookScanResult& result)
    {
        // Input: IAT/EAT hook scan result. Processing: append suspicious or pointer-diff rows. Return: no value.
        for (const auto& row : result.entries)
        {
            const bool kDiffers = row.currentTarget != 0U && row.expectedTarget != 0U && row.currentTarget != row.expectedTarget;
            const double kRisk = hookScore(row.status, kDiffers);
            if (kRisk <= 0.0) continue;
            const QString kHookClass = row.hookClass == KSWORD_ARK_IAT_EAT_HOOK_CLASS_EAT ? QStringLiteral("EAT") : QStringLiteral("IAT");
            const QString kTitle = QStringLiteral("%1 %2 %3").arg(kHookClass, hookStatusText(row.status), narrowText(row.functionName));
            const QString kDetail = QStringLiteral("module=%1 import=%2 current=%3 expected=%4")
                .arg(wideText(row.moduleName), wideText(row.importModuleName), hex64(row.currentTarget), hex64(row.expectedTarget));
            QJsonObject payload = payloadBase(QStringLiteral("IAT/EAT Hook"), QStringLiteral("Hook"), kTitle, kDetail, kRisk);
            payload.insert(QStringLiteral("hookClass"), kHookClass);
            payload.insert(QStringLiteral("status"), hookStatusText(row.status));
            payload.insert(QStringLiteral("thunkAddress"), hex64(row.thunkAddress));
            payload.insert(QStringLiteral("currentTarget"), hex64(row.currentTarget));
            payload.insert(QStringLiteral("expectedTarget"), hex64(row.expectedTarget));
            payload.insert(QStringLiteral("moduleName"), wideText(row.moduleName));
            entries.push_back(makeEntry(QStringLiteral("IAT/EAT Hook"), QStringLiteral("Hook"), kTitle, kDetail, kRisk, payload));
        }
    }

    void appendCallbacks(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::CallbackEnumResult& result)
    {
        // Input: callback enumeration result. Processing: append private/unresolved/untrusted callback rows. Return: no value.
        for (const auto& row : result.entries)
        {
            const double kRisk = callbackScore(row);
            if (kRisk < 20.0) continue;
            const QString kCallbackClass = callbackClassText(row.callbackClass);
            const QString kTitle = QStringLiteral("%1 %2").arg(kCallbackClass, hex64(row.callbackAddress));
            const QString kDetail = QStringLiteral("module=%1 name=%2 altitude=%3 source=%4 trust=%5")
                .arg(wideText(row.modulePath), wideText(row.name), wideText(row.altitude)).arg(row.source).arg(hex32(row.trustFlags));
            QJsonObject payload = payloadBase(QStringLiteral("Callback"), QStringLiteral("Callback"), kTitle, kDetail, kRisk);
            payload.insert(QStringLiteral("callbackClass"), kCallbackClass);
            payload.insert(QStringLiteral("source"), static_cast<int>(row.source));
            payload.insert(QStringLiteral("fieldFlags"), hex32(row.fieldFlags));
            payload.insert(QStringLiteral("trustFlags"), hex32(row.trustFlags));
            payload.insert(QStringLiteral("callbackAddress"), hex64(row.callbackAddress));
            payload.insert(QStringLiteral("modulePath"), wideText(row.modulePath));
            payload.insert(QStringLiteral("name"), wideText(row.name));
            payload.insert(QStringLiteral("altitude"), wideText(row.altitude));
            entries.push_back(makeEntry(QStringLiteral("Callback"), QStringLiteral("Callback"), kTitle, kDetail, kRisk, payload));
        }
    }

    void appendMutationAudit(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::MutationAuditResult& result)
    {
        // Input: read-only mutation audit result. Processing: append audit rows without exposing write controls. Return: no value.
        for (const auto& row : result.entries)
        {
            const double kRisk = mutationScore(row);
            if (kRisk <= 0.0) continue;
            const QString kOperation = mutationOperationText(row.operation);
            const QString kStatus = mutationStatusText(row.status);
            const QString kTitle = QStringLiteral("TX %1 %2 %3").arg(static_cast<qulonglong>(row.transactionId)).arg(kOperation, kStatus);
            const QString kDetail = QStringLiteral("target=%1 bytes=%2 pid=%3 flags=%4 risk=%5")
                .arg(hex64(row.targetAddress)).arg(row.bytes).arg(row.processId).arg(hex32(row.flags), hex32(row.riskFlags));
            QJsonObject payload = payloadBase(QStringLiteral("Mutation Audit"), QStringLiteral("Mutation"), kTitle, kDetail, kRisk);
            payload.insert(QStringLiteral("operation"), kOperation);
            payload.insert(QStringLiteral("status"), kStatus);
            payload.insert(QStringLiteral("transactionId"), QString::number(static_cast<qulonglong>(row.transactionId)));
            payload.insert(QStringLiteral("sequence"), QString::number(static_cast<qulonglong>(row.sequence)));
            payload.insert(QStringLiteral("targetAddress"), hex64(row.targetAddress));
            payload.insert(QStringLiteral("bytes"), static_cast<int>(row.bytes));
            payload.insert(QStringLiteral("processId"), static_cast<int>(row.processId));
            payload.insert(QStringLiteral("flags"), hex32(row.flags));
            payload.insert(QStringLiteral("riskFlags"), hex32(row.riskFlags));
            entries.push_back(makeEntry(QStringLiteral("Mutation Audit"), QStringLiteral("Mutation"), kTitle, kDetail, kRisk, payload));
        }
    }
}

void MonitorDock::initializeArkRiskCenterTab()
{
    // Input: None; called by initializeUi.
    // Processing: Create a read-only ARK Risk Center page; all driver access is performed in ArkDriverClient.
    // Returns void; the widget is released by the Qt parent-child tree.
    arkRiskCenterPage_ = new QWidget(sideTabWidget_);
    QVBoxLayout* pageLayout = new QVBoxLayout(arkRiskCenterPage_);
    pageLayout->setContentsMargins(6, 6, 6, 6);
    pageLayout->setSpacing(6);

    QHBoxLayout* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(8);

    arkRiskRefreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新风险"), arkRiskCenterPage_);
    arkRiskRefreshButton_->setToolTip(QStringLiteral("只读聚合 Memory / Process / Driver / Callback / Hook / Mutation 发现"));
    arkRiskHighOnlyCheck_ = new QCheckBox(QStringLiteral("仅高风险"), arkRiskCenterPage_);
    arkRiskHighOnlyCheck_->setChecked(true);
    arkRiskHighOnlyCheck_->setToolTip(QStringLiteral("仅显示 riskScore >= 50 的记录"));
    arkRiskFilterEdit_ = new QLineEdit(arkRiskCenterPage_);
    arkRiskFilterEdit_->setClearButtonEnabled(true);
    arkRiskFilterEdit_->setPlaceholderText(QStringLiteral("过滤来源/分类/标题/详情/JSON"));
    arkRiskExportJsonButton_ = new QPushButton(QStringLiteral("导出 JSON"), arkRiskCenterPage_);
    arkRiskExportCsvButton_ = new QPushButton(QStringLiteral("导出 CSV"), arkRiskCenterPage_);
    arkRiskStatusLabel_ = new QLabel(QStringLiteral("状态：等待刷新"), arkRiskCenterPage_);
    arkRiskStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    arkRiskStatusLabel_->setStyleSheet(QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::textSecondaryHex()));

    toolbarLayout->addWidget(arkRiskRefreshButton_);
    toolbarLayout->addWidget(arkRiskHighOnlyCheck_);
    toolbarLayout->addWidget(arkRiskFilterEdit_, 1);
    toolbarLayout->addWidget(arkRiskExportJsonButton_);
    toolbarLayout->addWidget(arkRiskExportCsvButton_);
    toolbarLayout->addWidget(arkRiskStatusLabel_);
    pageLayout->addLayout(toolbarLayout);

    QSplitter* splitter = new QSplitter(Qt::Vertical, arkRiskCenterPage_);
    pageLayout->addWidget(splitter, 1);

    arkRiskTable_ = new ks::ui::VisibleTableWidget(splitter);
    arkRiskTable_->setColumnCount(riskColumnIndex(RiskColumn::kCount));
    arkRiskTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("riskScore"),
        QStringLiteral("来源"),
        QStringLiteral("分类"),
        QStringLiteral("标题"),
        QStringLiteral("详情")
        });
    arkRiskTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    arkRiskTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    arkRiskTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    arkRiskTable_->setAlternatingRowColors(true);
    arkRiskTable_->setSortingEnabled(true);
    arkRiskTable_->verticalHeader()->setVisible(false);
    arkRiskTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    arkRiskTable_->horizontalHeader()->setSectionResizeMode(riskColumnIndex(RiskColumn::kDetail), QHeaderView::Stretch);
    installArkRiskTableCopyMenu(this, arkRiskTable_);
    splitter->addWidget(arkRiskTable_);

    arkRiskDetailEdit_ = new CodeEditorWidget(splitter);
    arkRiskDetailEdit_->setReadOnly(true);
    arkRiskDetailEdit_->setText(QStringLiteral("ARK 风险中心为只读聚合页。\n不提供任意写、修复、提交 mutation 或驱动卸载按钮；Mutation 仅展示 dry-run/audit/rollback 状态。"));
    splitter->addWidget(arkRiskDetailEdit_);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerHost(
        arkRiskTable_, arkRiskDetailEdit_, arkRiskCenterPage_);

    connect(arkRiskRefreshButton_, &QPushButton::clicked, this, [this]() { refreshArkRiskCenterAsync(); });
    connect(arkRiskFilterEdit_, &QLineEdit::textChanged, this, [this]() { rebuildArkRiskCenterTable(); });
    connect(arkRiskHighOnlyCheck_, &QCheckBox::toggled, this, [this]() { rebuildArkRiskCenterTable(); });
    connect(arkRiskTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) { showArkRiskCenterDetailForCurrentRow(); });
    connect(arkRiskExportJsonButton_, &QPushButton::clicked, this, [this]() { exportArkRiskCenterAsJson(); });
    connect(arkRiskExportCsvButton_, &QPushButton::clicked, this, [this]() { exportArkRiskCenterAsCsv(); });

    sideTabWidget_->addTab(arkRiskCenterPage_, QIcon(QStringLiteral(":/Icon/process_critical.svg")), QStringLiteral("ARK 风险中心"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_,
        arkRiskCenterPage_,
        QStringLiteral("monitor.tab.ark_risk_center"),
        QStringLiteral("ARK 风险中心"));
}

void MonitorDock::refreshArkRiskCenterAsync()
{
    // Input: Triggered by refresh button or first page entry.
    // Processing: Background queries multi-channel evidence via ArkDriverClient in read-only mode; main thread updates cache and tables.
    // Returns: Nothing.
    if (arkRiskRefreshInProgress_)
    {
        return;
    }

    arkRiskRefreshInProgress_ = true;
    const std::uint64_t kTicket = ++arkRiskRefreshTicket_;
    if (arkRiskRefreshButton_ != nullptr)
    {
        arkRiskRefreshButton_->setEnabled(false);
    }
    if (arkRiskStatusLabel_ != nullptr)
    {
        arkRiskStatusLabel_->setText(QStringLiteral("状态：聚合查询中..."));
        arkRiskStatusLabel_->setStyleSheet(QStringLiteral("color:%1; font-weight:700;").arg(ksword_theme::kPrimaryBlueHex));
    }

    QPointer<MonitorDock> guardThis(this);
    // sessionBootId is fetched once in the GUI thread: it is constant within the process, so worker threads can use
    // the value directly to avoid race conditions between static initialization and collection on different threads.
    const QString kSessionBootId = arkRiskSessionBootId();
    QRunnable* task = QRunnable::create([guardThis, kTicket, kSessionBootId]() {
        std::vector<MonitorDock::ArkRiskCenterEntry> entries;
        QStringList statusLines;
        const ksword::ark::DriverClient kClient;

        const unsigned long kMemoryFlags =
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES |
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;
        const auto kMemory = kClient.queryKernelMemoryEvidence(kMemoryFlags);
        addStatusEntry(entries, statusLines, QStringLiteral("Memory Evidence"), QStringLiteral("Memory"), kMemory.io.ok, kMemory.unsupported, kMemory.io);
        if (kMemory.io.ok) appendMemory(entries, kMemory);

        const auto kProcess = kClient.queryProcessCrossView();
        addStatusEntry(entries, statusLines, QStringLiteral("Process Cross-View"), QStringLiteral("Process"), kProcess.io.ok, kProcess.unsupported, kProcess.io);
        if (kProcess.io.ok) appendProcessCrossView(entries, kProcess);

        const auto kThread = kClient.queryThreadCrossView();
        addStatusEntry(entries, statusLines, QStringLiteral("Thread Cross-View"), QStringLiteral("Thread"), kThread.io.ok, kThread.unsupported, kThread.io);
        if (kThread.io.ok) appendThreadCrossView(entries, kThread);

        const auto kDriver = kClient.queryDriverIntegrity();
        addStatusEntry(entries, statusLines, QStringLiteral("Driver Integrity"), QStringLiteral("Driver"), kDriver.io.ok, kDriver.unsupported, kDriver.io);
        if (kDriver.io.ok) appendDriverIntegrity(entries, QStringLiteral("Driver Integrity"), kDriver);

        const auto kCpu = kClient.queryKernelCpuIntegrity();
        addStatusEntry(entries, statusLines, QStringLiteral("CPU Integrity"), QStringLiteral("Driver"), kCpu.io.ok, kCpu.unsupported, kCpu.io);
        if (kCpu.io.ok) appendDriverIntegrity(entries, QStringLiteral("CPU Integrity"), kCpu);

        const auto kInlineHooks = kClient.scanInlineHooks();
        addStatusEntry(entries, statusLines, QStringLiteral("Inline Hook"), QStringLiteral("Hook"), kInlineHooks.io.ok, false, kInlineHooks.io);
        if (kInlineHooks.io.ok) appendInlineHooks(entries, kInlineHooks);

        const auto kIatEatHooks = kClient.enumerateIatEatHooks();
        addStatusEntry(entries, statusLines, QStringLiteral("IAT/EAT Hook"), QStringLiteral("Hook"), kIatEatHooks.io.ok, false, kIatEatHooks.io);
        if (kIatEatHooks.io.ok) appendIatEatHooks(entries, kIatEatHooks);

        const auto kCallbacks = kClient.enumerateCallbacks();
        addStatusEntry(entries, statusLines, QStringLiteral("Callback"), QStringLiteral("Callback"), kCallbacks.io.ok, false, kCallbacks.io);
        if (kCallbacks.io.ok) appendCallbacks(entries, kCallbacks);

        const auto kMutation = kClient.queryMutationAudit();
        addStatusEntry(entries, statusLines, QStringLiteral("Mutation Audit"), QStringLiteral("Mutation"), kMutation.io.ok, kMutation.unsupported, kMutation.io);
        if (kMutation.io.ok) appendMutationAudit(entries, kMutation);

        std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
            return left.riskScore > right.riskScore;
        });

        // F-09/F-12: After finalizing the sort order, emit the evidence ID and fix the process identity so that the ID corresponds one-to-one with the final sequence.
        attachArkRiskNavigationIdentity(entries, kSessionBootId, kTicket);

        if (guardThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            guardThis.data(),
            [guardThis, kTicket, entries = std::move(entries), statusLines = std::move(statusLines)]() mutable {
                if (guardThis == nullptr || guardThis->arkRiskRefreshTicket_ != kTicket)
                {
                    return;
                }

                auto deferredEntries =
                    std::make_shared<std::vector<MonitorDock::ArkRiskCenterEntry>>(std::move(entries));
                auto deferredStatusLines = std::make_shared<QStringList>(std::move(statusLines));
                auto commit = [guardThis, kTicket, deferredEntries, deferredStatusLines]() mutable
                {
                    if (guardThis == nullptr || guardThis->arkRiskRefreshTicket_ != kTicket)
                    {
                        return;
                    }

                    guardThis->arkRiskRefreshInProgress_ = false;
                    if (guardThis->arkRiskRefreshButton_ != nullptr)
                    {
                        guardThis->arkRiskRefreshButton_->setEnabled(true);
                    }
                    guardThis->arkRiskCenterEntries_ = std::move(*deferredEntries);
                    guardThis->rebuildArkRiskCenterTable();
                    guardThis->showArkRiskCenterDetailForCurrentRow();
                    if (guardThis->arkRiskStatusLabel_ != nullptr)
                    {
                        guardThis->arkRiskStatusLabel_->setText(
                            QStringLiteral("状态：%1 项；%2")
                            .arg(static_cast<qulonglong>(guardThis->arkRiskCenterEntries_.size()))
                            .arg(deferredStatusLines->join(QStringLiteral("；"))));
                        guardThis->arkRiskStatusLabel_->setStyleSheet(
                            QStringLiteral("color:%1; font-weight:700;")
                                .arg(ksword_theme::textPrimaryHex()));
                    }
                };
                if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                        guardThis.data(),
                        QStringLiteral("monitor-ark-risk-center-snapshot-apply"),
                        {guardThis->arkRiskTable_},
                        commit))
                {
                    return;
                }
                commit();
            },
            Qt::QueuedConnection);
    });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void MonitorDock::rebuildArkRiskCenterTable()
{
    // Input: none; reads risk center cache and filter controls.
    // Processing: Project the table using high-only and keywords; do not access the driver.
    // Returns: Nothing.
    if (arkRiskTable_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(arkRiskDetailEdit_);
    const QString kFilter = arkRiskFilterEdit_ != nullptr ? arkRiskFilterEdit_->text().trimmed() : QString();
    const bool kHighOnly = arkRiskHighOnlyCheck_ != nullptr && arkRiskHighOnlyCheck_->isChecked();

    std::vector<std::size_t> visibleIndexes;
    visibleIndexes.reserve(arkRiskCenterEntries_.size());
    for (std::size_t index = 0; index < arkRiskCenterEntries_.size(); ++index)
    {
        const auto& entry = arkRiskCenterEntries_[index];
        if (kHighOnly && entry.riskScore < 50.0)
        {
            continue;
        }
        if (!matchesFilter(entry, kFilter))
        {
            continue;
        }
        visibleIndexes.push_back(index);
    }

    const QSignalBlocker kBlocker(arkRiskTable_);
    arkRiskTable_->setSortingEnabled(false);
    arkRiskTable_->setRowCount(static_cast<int>(visibleIndexes.size()));
    for (int row = 0; row < static_cast<int>(visibleIndexes.size()); ++row)
    {
        const std::size_t kCacheIndex = visibleIndexes[static_cast<std::size_t>(row)];
        const auto& entry = arkRiskCenterEntries_[kCacheIndex];
        QTableWidgetItem* scoreItem = new ScoreItem(entry.riskScore);
        scoreItem->setData(kRiskEntryIndexRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(kCacheIndex)));
        // PID and evidence ID are both taken directly from the cache row, without re-parsing the payload:
        // The identity was fixed during the collection phase; here we only move it (F-09).
        scoreItem->setData(kRiskProcessIdRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(entry.processId)));
        scoreItem->setData(kRiskEvidenceIdRole, entry.evidenceId);
        arkRiskTable_->setItem(row, riskColumnIndex(RiskColumn::kScore), scoreItem);
        arkRiskTable_->setItem(row, riskColumnIndex(RiskColumn::kSource), textItem(entry.sourceName));
        arkRiskTable_->setItem(row, riskColumnIndex(RiskColumn::kCategory), textItem(entry.category));
        arkRiskTable_->setItem(row, riskColumnIndex(RiskColumn::kTitle), textItem(entry.title));
        arkRiskTable_->setItem(row, riskColumnIndex(RiskColumn::kDetail), textItem(entry.detail));
    }
    if (arkRiskTable_->rowCount() > 0 && arkRiskTable_->currentRow() < 0)
    {
        arkRiskTable_->setCurrentCell(0, riskColumnIndex(RiskColumn::kScore));
    }
    arkRiskTable_->setSortingEnabled(true);
    ks::ui::requestTableColumnAutoFit(arkRiskTable_);
}

void MonitorDock::showArkRiskCenterDetailForCurrentRow() const
{
    // Input: None; reads the current table selection.
    // Processing: Expand summary and JSON payload via cache index.
    // Returns: Nothing.
    if (arkRiskDetailEdit_ == nullptr || arkRiskTable_ == nullptr)
    {
        return;
    }
    const int kRow = arkRiskTable_->currentRow();
    if (kRow < 0)
    {
        arkRiskDetailEdit_->setText(QStringLiteral("请选择一条风险记录。"));
        return;
    }
    const QTableWidgetItem* scoreItem = arkRiskTable_->item(kRow, riskColumnIndex(RiskColumn::kScore));
    bool ok = false;
    const qulonglong kCacheIndex = scoreItem != nullptr ? scoreItem->data(kRiskEntryIndexRole).toULongLong(&ok) : 0ULL;
    if (!ok || kCacheIndex >= static_cast<qulonglong>(arkRiskCenterEntries_.size()))
    {
        arkRiskDetailEdit_->setText(QStringLiteral("当前行缓存索引无效。"));
        return;
    }
    const auto& entry = arkRiskCenterEntries_[static_cast<std::size_t>(kCacheIndex)];
    QString detail;
    detail += QStringLiteral("ARK 风险详情\n");
    detail += QStringLiteral("riskScore: %1\nsource: %2\ncategory: %3\ntitle: %4\ndetail: %5\n\n")
        .arg(entry.riskScoreText, entry.sourceName, entry.category, entry.title, entry.detail);
    detail += QString::fromUtf8(QJsonDocument(entry.payload).toJson(QJsonDocument::Indented));
    arkRiskDetailEdit_->setText(detail);
}

void MonitorDock::navigateToProcessDetailFromArkRiskRow(const int tableRow)
{
    // Input: Display row index in the risk center table.
    // Note: Handling the dual criteria of F-12 + F-09; this is the first production call point to integrate these two criteria in this round.
    //       The original implementation was ks::ui::openProcessDetailByPid(processId) — a raw PID jump. The risk
    //       row is asynchronously collected; between collection and click, the target process may exit and release
    //       the PID. A raw PID would hand the operation to a new process that happens to occupy that number.
    // Returns: No return value. If the condition fails, only a message is displayed; never jumps to a raw PID.
    if (arkRiskTable_ == nullptr || tableRow < 0 || tableRow >= arkRiskTable_->rowCount())
    {
        return;
    }

    // Evidence ID is retrieved from the table row: F-12 requires navigation to access it.
    const QTableWidgetItem* scoreItem = arkRiskTable_->item(tableRow, riskColumnIndex(RiskColumn::kScore));
    const QString kEvidenceId = scoreItem != nullptr
        ? scoreItem->data(kRiskEvidenceIdRole).toString()
        : QString();

    // Reverse-lookup the current snapshot by evidence ID, not by line number or cache index.
    // The index remains 'valid' after the snapshot is swapped out, silently pointing to a different record; if the ID is not found, it simply isn't found.
    const MonitorDock::ArkRiskCenterEntry* entry = nullptr;
    if (!kEvidenceId.isEmpty())
    {
        for (const MonitorDock::ArkRiskCenterEntry& candidate : arkRiskCenterEntries_)
        {
            if (candidate.evidenceId == kEvidenceId)
            {
                entry = &candidate;
                break;
            }
        }
    }

    // outcome / liveDecision: The original conclusions of the two criteria, passed along to the prompt text for easier log-based troubleshooting.
    evidence::NavigationOutcome outcome = evidence::NavigationOutcome::kEvidenceIdMissing;
    evidence::LiveNavigationDecision liveDecision = evidence::LiveNavigationDecision::kAllow;
    bool liveDecisionEvaluated = false;
    // identityDiagnosticParts: Retains original diagnostics from both the collection phase and the on-site review phase.
    // These two describe failures at different moments; collapsing them into one line makes it impossible to distinguish between "failed to retrieve initially" and "cannot read now".
    QStringList identityDiagnosticParts;
    quint32 rejectedProcessId = 0U;
    bool noProcessBinding = false;

    if (kEvidenceId.isEmpty())
    {
        // The request lacks an evidence ID: decideNavigation also returns EvidenceIdMissing for such requests. Since no
        // request object can be constructed here, we use the same enum value directly without creating new semantics.
        outcome = evidence::NavigationOutcome::kEvidenceIdMissing;
    }
    else if (entry == nullptr)
    {
        // Has an ID but not found in the current snapshot: This evidence is not in the session and cannot be 'guessed' and added on the spot.
        outcome = evidence::NavigationOutcome::kEvidenceNotSaved;
    }
    else if (entry->processId == 0U)
    {
        // This line does not point to a process (driver / CPU / hook class). Identity determination is also
        // IdentityUnusable—ProcessInstanceId without a pid is Unusable—but the rejection reason must clearly state "no object".
        outcome = evidence::NavigationOutcome::kIdentityUnusable;
        noProcessBinding = true;
    }
    else
    {
        rejectedProcessId = entry->processId;
        if (!entry->processIdentityOutcome.message.empty())
        {
            identityDiagnosticParts << QStringLiteral("capture=%1(%2)")
                .arg(QString::fromStdString(entry->processIdentityOutcome.message),
                    QString::fromLatin1(
                        evidence::collectionStatusName(entry->processIdentityOutcome.status)));
        }

        // Collection period identity (offline side).
        const evidence::ProcessInstanceId kSavedIdentity = makeSavedProcessIdentity(*entry);

        // On-site re-verification (F-09): Re-read immediately upon jump; never reuse
        // results from the collection period—reusing equals no re-verification.
        const LiveProcessProbe kLiveProbe = probeProcessCreateTime(entry->processId);
        evidence::LiveResolution liveResolution;
        liveResolution.found = kLiveProbe.present;
        if (kLiveProbe.present)
        {
            // On the live side, fill in the **current** running session, not the one copied from the collection row.
            // Copying over implies unconditionally claiming 'both sides belong to the same boot cycle'; once support for loading old
            // snapshots from files is added, this assumption would silently allow cross-boot PID matches. Filling them separately
            // ensures that different bootId values cause matchProcessInstance to return NoMatch, which is the intended rejection (F-03).
            liveResolution.liveProcess.bootId = arkRiskSessionBootId().toStdString();
            liveResolution.liveProcess.pid =
                evidence::OptionalU64::of(static_cast<std::uint64_t>(entry->processId));
            if (kLiveProbe.createTimeKnown)
            {
                liveResolution.liveProcess.createTime100ns =
                    evidence::OptionalU64::of(kLiveProbe.createTime100ns);
            }
            liveResolution.liveProcess.imageName = kSavedIdentity.imageName;
        }
        if (!kLiveProbe.outcome.message.empty())
        {
            identityDiagnosticParts << QStringLiteral("live=%1(%2)")
                .arg(QString::fromStdString(kLiveProbe.outcome.message),
                    QString::fromLatin1(evidence::collectionStatusName(kLiveProbe.outcome.status)));
        }

        evidence::NavigationRequest request;
        request.page = evidence::NavigationPage::kProcess;
        // The key for makeProcessRef comes from crossSessionKey(): if the identity is not Strong, it is an empty string.
        // ObjectRef::navigable() becomes false, and decideNavigation checks for IdentityUnusable.
        // This is the enforcement point for the rule: if creation time cannot be retrieved, jumping is not allowed.
        request.object = evidence::makeProcessRef(kSavedIdentity, kEvidenceId.toStdString());
        request.evidenceId = kEvidenceId.toStdString();
        request.anchor = evidence::formatU64(entry->processId, evidence::U64Format::kDecimal);
        request.requireExactMatch = true;

        outcome = evidence::decideNavigation(
            request,
            processDetailRouteAvailable(),
            // Whether the object still exists: rely on live probing. If permissions are insufficient to read the creation time, the object may
            // still exist; such cases must be explained via the subsequent identity verification step, not falsely reported as "object not found."
            kLiveProbe.present,
            // Evidence ID already matched in the current snapshot; this evidence is indeed still in the session.
            true);

        if (outcome == evidence::NavigationOutcome::kDelivered)
        {
            liveDecision = evidence::resolveProcessNavigation(kSavedIdentity, liveResolution);
            liveDecisionEvaluated = true;
            if (liveDecision == evidence::LiveNavigationDecision::kAllow)
            {
                // Allow implies matchProcessInstance == Confirmed, and Confirmed requires both creation
                // times to be present and equal, so processCreateTime100ns here must be a valid value.
                // Even if someone breaks this precondition in the future, openProcessDetailByIdentity
                // will directly reject creationTime==0 without degrading to a raw PID jump.
                ks::ui::openProcessDetailByIdentity(entry->processId, entry->processCreateTime100ns);
                return;
            }
        }
    }

    QString messageText =
        arkRiskNavigationRejectionText(outcome, liveDecision, liveDecisionEvaluated, noProcessBinding);
    messageText += QStringLiteral("\n\n");
    messageText += ks::i18n::contextText(
        QStringLiteral("monitor.ark_risk.nav.context"),
        QStringLiteral("证据 id：%1\nPID：%2\n判据：%3 / %4"))
        .arg(kEvidenceId.isEmpty() ? QStringLiteral("-") : kEvidenceId)
        .arg(rejectedProcessId)
        .arg(QString::fromLatin1(evidence::navigationOutcomeName(outcome)),
            liveDecisionEvaluated
                ? QString::fromLatin1(evidence::liveNavigationDecisionName(liveDecision))
                : QStringLiteral("-"));
    if (!identityDiagnosticParts.isEmpty())
    {
        messageText += QStringLiteral("\n");
        messageText += ks::i18n::contextText(
            QStringLiteral("monitor.ark_risk.nav.diagnostic"),
            QStringLiteral("身份查询诊断：%1"))
            .arg(identityDiagnosticParts.join(QStringLiteral(" | ")));
    }

    QMessageBox::information(
        this,
        ks::i18n::contextText(
            QStringLiteral("monitor.ark_risk.nav.title"),
            QStringLiteral("无法转到进程详情")),
        messageText);
}

void MonitorDock::exportArkRiskCenterAsJson() const
{
    // Input: None; reads the risk center cache.
    // Processing: Write JSON array after user selects path; prompt if cache is empty.
    // Returns: Nothing.
    if (arkRiskCenterEntries_.empty())
    {
        QMessageBox::information(const_cast<MonitorDock*>(this), QStringLiteral("ARK 风险中心"), QStringLiteral("当前没有可导出的风险记录。"));
        return;
    }
    const QString kDefaultPath = QDir::home().filePath(QStringLiteral("ark-risk-center-%1.json").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-hhmmss"))));
    const QString kFilePath = QFileDialog::getSaveFileName(const_cast<MonitorDock*>(this), QStringLiteral("导出 ARK 风险 JSON"), kDefaultPath, QStringLiteral("JSON (*.json)"));
    if (kFilePath.isEmpty())
    {
        return;
    }
    QJsonArray rows;
    for (const auto& entry : arkRiskCenterEntries_)
    {
        rows.append(entry.payload);
    }
    QFile file(kFilePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(const_cast<MonitorDock*>(this), QStringLiteral("导出失败"), file.errorString());
        return;
    }
    file.write(QJsonDocument(rows).toJson(QJsonDocument::Indented));
}

void MonitorDock::exportArkRiskCenterAsCsv() const
{
    // Input: None; reads the risk center cache.
    // Processing: Write CSV after user selects a path; prompt if the cache is empty.
    // Returns: Nothing.
    if (arkRiskCenterEntries_.empty())
    {
        QMessageBox::information(const_cast<MonitorDock*>(this), QStringLiteral("ARK 风险中心"), QStringLiteral("当前没有可导出的风险记录。"));
        return;
    }
    const QString kDefaultPath = QDir::home().filePath(QStringLiteral("ark-risk-center-%1.csv").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-hhmmss"))));
    const QString kFilePath = QFileDialog::getSaveFileName(const_cast<MonitorDock*>(this), QStringLiteral("导出 ARK 风险 CSV"), kDefaultPath, QStringLiteral("CSV (*.csv)"));
    if (kFilePath.isEmpty())
    {
        return;
    }
    QFile file(kFilePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
    {
        QMessageBox::warning(const_cast<MonitorDock*>(this), QStringLiteral("导出失败"), file.errorString());
        return;
    }
    file.write("riskScore,source,category,title,detail,json\n");
    for (const auto& entry : arkRiskCenterEntries_)
    {
        const QString kJsonText = QString::fromUtf8(QJsonDocument(entry.payload).toJson(QJsonDocument::Compact));
        const QString kLine = QStringLiteral("%1,%2,%3,%4,%5,%6\n")
            .arg(csvEscape(entry.riskScoreText),
                csvEscape(entry.sourceName),
                csvEscape(entry.category),
                csvEscape(entry.title),
                csvEscape(entry.detail),
                csvEscape(kJsonText));
        file.write(kLine.toUtf8());
    }
}
