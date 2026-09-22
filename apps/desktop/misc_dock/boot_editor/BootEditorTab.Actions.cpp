#include "BootEditorTab.h"
#include "../../framework/PrivilegeElevationPrompt.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFileDialog>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QProcess>
#include <QRegularExpression>
#include <QSpinBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextCursor>
#include <QThreadPool>
#include <QTimer>
#include <QVariant>

#include <atomic>

namespace
{
    // Extract duplicate constants within the file:
    // - kColumnIdentifier must remain consistent with the main file.
    // - kDefaultCommandTimeoutMs is kept consistent with the main file.
    constexpr int kColumnIdentifier = 0;
    constexpr int kDefaultCommandTimeoutMs = 30000;

    // parseBoolText：
    // - Parses boolean values from strings;
    // - Falls back to defaultValue on parsing failure.
    bool parseBoolText(const QString& rawText, const bool defaultValue)
    {
        const QString kNormalizedText = rawText.trimmed().toLower();
        if (kNormalizedText == QStringLiteral("yes")
            || kNormalizedText == QStringLiteral("on")
            || kNormalizedText == QStringLiteral("true")
            || kNormalizedText == QStringLiteral("1")
            || kNormalizedText == QStringLiteral("enabled"))
        {
            return true;
        }
        if (kNormalizedText == QStringLiteral("no")
            || kNormalizedText == QStringLiteral("off")
            || kNormalizedText == QStringLiteral("false")
            || kNormalizedText == QStringLiteral("0")
            || kNormalizedText == QStringLiteral("disabled"))
        {
            return false;
        }
        return defaultValue;
    }

    // ===================== Read-only enumeration
    // asynchronous support ===================== Background:
    // - The BootEditorTab constructor directly calls refreshBcdEntries(). Since both the constructor and refreshBcdEntries() reside in
    //   BootEditorTab.cpp and are outside the scope of this modification, the initial enumeration cannot be moved out of the construction phase.
    // Therefore, intercept "refresh dedicated read-only enumeration" inside runBcdEdit: the real bcdedit is executed by the thread pool; the caller immediately
    //   receives a placeholder result composed of cached text from the previous round, and the UI thread refreshes once after the background result is posted back.
    // - Cross-call state is carried by QObject dynamic properties, avoiding unmodifiable header
    //   files and ensuring state is destroyed with the control to prevent file-level residue.

    // kEnumPendingGenerationProperty: Identifier for an in-progress enumeration request; missing property or value 0 indicates no background task is active.
    constexpr char kEnumPendingGenerationProperty[] = "ks_bcdEnumPendingGeneration";
    // kEnumReadyResultProperty: Enumerated result temporarily stored after background re-injection, waiting to be retrieved by the next synchronous call.
    constexpr char kEnumReadyResultProperty[] = "ks_bcdEnumReadyResult";

    // Enum result QVariantMap field names:
    // - Background thread writes, UI thread reads;
    // - Centralize definitions to avoid spelling drift of keys on both sides.
    constexpr char kEnumResultStartSucceededKey[] = "startSucceeded";
    constexpr char kEnumResultTimeoutKey[] = "timeout";
    constexpr char kEnumResultExitCodeKey[] = "exitCode";
    constexpr char kEnumResultStandardOutputKey[] = "standardOutput";
    constexpr char kEnumResultStandardErrorKey[] = "standardError";

    // kProcessStartTimeoutMs: Maximum time (in milliseconds) to wait for the child process to finish creating.
    constexpr int kProcessStartTimeoutMs = 3000;
    // kProcessKillWaitMs: Maximum wait time (in milliseconds) to reclaim process objects after forced termination.
    constexpr int kProcessKillWaitMs = 1000;
    // kBackgroundWaitSliceMs: The granularity (in milliseconds) for background wait slices, used to periodically recheck process status and application exit flags.
    constexpr int kBackgroundWaitSliceMs = 200;

    // g_enumRequestGenerationCounter：
    // - Purpose: Global monotonically increasing enumeration request ID used to discard old results superseded by new requests.
    // - Note: Currently incremented only on the UI thread; using an atomic type prevents accidental use from other threads.
    std::atomic<quint64> gEnumRequestGenerationCounter{ 0 };

    // g_placeholderLogOwnerObject：
    // - Purpose: Record the control address indicating that the most recent runBcdEdit call returned an asynchronous placeholder result;
    // - Note: If appendCommandLog reads from the same address, skip logging this time to avoid writing cached text repeatedly into the original output area.
    // - Thread: Read/write only on the UI thread.
    const void* gPlaceholderLogOwnerObject = nullptr;

    // g_synchronousCommandDepth：
    // - Purpose: Track the number of write commands currently stuck in nested event loops.
    // - Note: When >0, asynchronous enumeration results are blocked from triggering refreshes to prevent rebuilding the table from inadvertently overwriting the user's in-progress edits.
    // - Thread: Read/write only on the UI thread.
    int gSynchronousCommandDepth = 0;

    // isBcdRefreshEnumRequest：
    // - Purpose: Determine if the current call is a read-only enumeration of the entire table dedicated to the refresh process.
    // - Input argumentList: bcdedit parameter list; Input commandDescription: caller description text;
    // - Return: true only when both arguments and description match the refresh-specific enumeration; user-defined commands will not be misidentified.
    bool isBcdRefreshEnumRequest(const QStringList& argumentList, const QString& commandDescription)
    {
        if (commandDescription != QStringLiteral("枚举全部 BCD 条目"))
        {
            return false;
        }
        return argumentList.size() == 3
            && argumentList.at(0).compare(QStringLiteral("/enum"), Qt::CaseInsensitive) == 0
            && argumentList.at(1).compare(QStringLiteral("all"), Qt::CaseInsensitive) == 0
            && argumentList.at(2).compare(QStringLiteral("/v"), Qt::CaseInsensitive) == 0;
    }

    // runBcdEditInCallingThread：
    // - Purpose: Execute bcdedit completely in the current thread to produce a pure value-type result that can be transferred across threads.
    // - Input argumentList: bcdedit argument list; Input timeoutMs: overall execution timeout upper limit (milliseconds);
    // - Return: QVariantMap containing boot status, timeout flag, exit code, and standard output/error text.
    QVariantMap runBcdEditInCallingThread(const QStringList& argumentList, const int timeoutMs)
    {
        QVariantMap resultMap;
        resultMap.insert(QString::fromLatin1(kEnumResultStartSucceededKey), false);
        resultMap.insert(QString::fromLatin1(kEnumResultTimeoutKey), false);
        resultMap.insert(QString::fromLatin1(kEnumResultExitCodeKey), -1);
        resultMap.insert(QString::fromLatin1(kEnumResultStandardOutputKey), QString());
        resultMap.insert(QString::fromLatin1(kEnumResultStandardErrorKey), QString());

        // Deliberately omit parent object in background thread: QProcess lifetime is entirely determined by this function's stack, with no cross-thread sharing.
        QProcess backgroundProcess;
        backgroundProcess.setProgram(QStringLiteral("bcdedit"));
        backgroundProcess.setArguments(argumentList);
        backgroundProcess.setProcessChannelMode(QProcess::SeparateChannels);
        backgroundProcess.start();

        if (!backgroundProcess.waitForStarted(kProcessStartTimeoutMs))
        {
            resultMap.insert(
                QString::fromLatin1(kEnumResultStandardErrorKey),
                backgroundProcess.errorString());
            return resultMap;
        }
        resultMap.insert(QString::fromLatin1(kEnumResultStartSucceededKey), true);

        // Segmented Wait:
        // - Background threads lack an event loop; waitForFinished does not re-enter the UI, so processEvents is unnecessary;
        // - Chunking into small pieces ensures we release resources quickly upon application exit, preventing the thread pool cleanup phase from being blocked by long-running commands.
        const int kEffectiveTimeoutMs = timeoutMs > 0 ? timeoutMs : kDefaultCommandTimeoutMs;
        QElapsedTimer elapsedTimer;
        elapsedTimer.start();
        bool processFinished = false;
        while (true)
        {
            if (backgroundProcess.waitForFinished(kBackgroundWaitSliceMs)
                || backgroundProcess.state() == QProcess::NotRunning)
            {
                processFinished = true;
                break;
            }
            if (elapsedTimer.elapsed() >= kEffectiveTimeoutMs || QCoreApplication::closingDown())
            {
                break;
            }
        }

        if (processFinished)
        {
            resultMap.insert(QString::fromLatin1(kEnumResultExitCodeKey), backgroundProcess.exitCode());
        }
        else
        {
            backgroundProcess.kill();
            backgroundProcess.waitForFinished(kProcessKillWaitMs);
            resultMap.insert(QString::fromLatin1(kEnumResultTimeoutKey), true);
        }

        resultMap.insert(
            QString::fromLatin1(kEnumResultStandardOutputKey),
            QString::fromLocal8Bit(backgroundProcess.readAllStandardOutput()));
        resultMap.insert(
            QString::fromLatin1(kEnumResultStandardErrorKey),
            QString::fromLocal8Bit(backgroundProcess.readAllStandardError()));
        return resultMap;
    }
}

void BootEditorTab::applySelectedEntryChanges()
{
    const BcdEntry* selectedEntry = currentEntry();
    if (selectedEntry == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("引导编辑器"), QStringLiteral("请先选择一个引导条目。"));
        return;
    }

    const QString kIdentifierText = selectedEntry->identifierText.trimmed();
    if (kIdentifierText.isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("引导编辑器"), QStringLiteral("当前条目标识符为空，无法写入。"));
        return;
    }

    // Batch write policy:
    // - Execute bcdedit /set field by field.
    // - Terminate subsequent writes immediately if any step fails to avoid partial state persistence.
    if (!descriptionEdit_->text().trimmed().isEmpty())
    {
        if (!runBcdAndExpectSuccess(
            QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("description"), descriptionEdit_->text().trimmed() },
            QStringLiteral("写入 description"),
            false))
        {
            return;
        }
    }
    if (!deviceEdit_->text().trimmed().isEmpty())
    {
        if (!runBcdAndExpectSuccess(
            QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("device"), deviceEdit_->text().trimmed() },
            QStringLiteral("写入 device"),
            false))
        {
            return;
        }
    }
    if (!osDeviceEdit_->text().trimmed().isEmpty())
    {
        if (!runBcdAndExpectSuccess(
            QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("osdevice"), osDeviceEdit_->text().trimmed() },
            QStringLiteral("写入 osdevice"),
            false))
        {
            return;
        }
    }
    if (!pathEdit_->text().trimmed().isEmpty())
    {
        if (!runBcdAndExpectSuccess(
            QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("path"), pathEdit_->text().trimmed() },
            QStringLiteral("写入 path"),
            false))
        {
            return;
        }
    }
    if (!systemRootEdit_->text().trimmed().isEmpty())
    {
        if (!runBcdAndExpectSuccess(
            QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("systemroot"), systemRootEdit_->text().trimmed() },
            QStringLiteral("写入 systemroot"),
            false))
        {
            return;
        }
    }
    if (!localeEdit_->text().trimmed().isEmpty())
    {
        if (!runBcdAndExpectSuccess(
            QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("locale"), localeEdit_->text().trimmed() },
            QStringLiteral("写入 locale"),
            false))
        {
            return;
        }
    }

    const QString kBootMenuPolicyValue = bootMenuPolicyCombo_->currentData().toString().trimmed();
    if (!kBootMenuPolicyValue.isEmpty())
    {
        if (!runBcdAndExpectSuccess(
            QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("bootmenupolicy"), kBootMenuPolicyValue },
            QStringLiteral("写入 bootmenupolicy"),
            false))
        {
            return;
        }
    }

    if (!runBcdAndExpectSuccess(
        QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("testsigning"), boolToBcdOnOff(testSigningCheck_->isChecked()) },
        QStringLiteral("写入 testsigning"),
        false))
    {
        return;
    }
    if (!runBcdAndExpectSuccess(
        QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("nointegritychecks"), boolToBcdOnOff(noIntegrityCheck_->isChecked()) },
        QStringLiteral("写入 nointegritychecks"),
        false))
    {
        return;
    }
    if (!runBcdAndExpectSuccess(
        QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("debug"), boolToBcdOnOff(debugCheck_->isChecked()) },
        QStringLiteral("写入 debug"),
        false))
    {
        return;
    }
    if (!runBcdAndExpectSuccess(
        QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("bootlog"), boolToBcdYesNo(bootLogCheck_->isChecked()) },
        QStringLiteral("写入 bootlog"),
        false))
    {
        return;
    }
    if (!runBcdAndExpectSuccess(
        QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("basevideo"), boolToBcdYesNo(baseVideoCheck_->isChecked()) },
        QStringLiteral("写入 basevideo"),
        false))
    {
        return;
    }
    if (!runBcdAndExpectSuccess(
        QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("recoveryenabled"), boolToBcdYesNo(recoveryEnabledCheck_->isChecked()) },
        QStringLiteral("写入 recoveryenabled"),
        false))
    {
        return;
    }

    // safeboot handling:
    // - Shutdown mode: deletes safeboot and safebootalternateshell;
    // - For other modes: write based on the combined value.
    const QString kSafeBootModeValue = safeBootCombo_->currentData().toString().trimmed().toLower();

    // deleteValueWithMissingTolerance：
    // - Uniformly handle the return value of deletevalue.
    // - If the failure is solely due to a missing field, the target state is considered satisfied.
    // - Abort immediately on other failures to avoid a false positive "Write Complete".
    const auto kDeleteValueWithMissingTolerance = [this, &kIdentifierText](const QString& elementName) -> bool
        {
            const QString kOperationText = QStringLiteral("删除 %1").arg(elementName);
            const BcdCommandResult kDeleteResult = runBcdEdit(
                QStringList{
                    QStringLiteral("/deletevalue"),
                    kIdentifierText,
                    elementName
                },
                kDefaultCommandTimeoutMs,
                kOperationText);
            appendCommandLog(
                QStringLiteral("bcdedit /deletevalue %1 %2").arg(kIdentifierText, elementName),
                kDeleteResult);

            if (kDeleteResult.startSucceeded && !kDeleteResult.timeout && kDeleteResult.exitCode == 0)
            {
                return true;
            }

            const QString kOutputLowerText = kDeleteResult.mergedOutputText.toLower();
            const bool kLikelyMissingElement =
                kOutputLowerText.contains(QStringLiteral("not found"))
                || kOutputLowerText.contains(QStringLiteral("cannot find"))
                || kOutputLowerText.contains(QStringLiteral("does not exist"))
                || kDeleteResult.mergedOutputText.contains(QStringLiteral("找不到"))
                || kDeleteResult.mergedOutputText.contains(QStringLiteral("不存在"))
                || kDeleteResult.mergedOutputText.contains(QStringLiteral("未找到"));

            if (kLikelyMissingElement)
            {
                KLogEvent warnEvent;
                warn << warnEvent
                    << "[BootEditor] deletevalue 字段不存在，按目标状态继续: element="
                    << elementName.toStdString()
                    << ", identifier="
                    << kIdentifierText.toStdString()
                    << eol;
                return true;
            }

            QMessageBox::warning(
                this,
                QStringLiteral("引导编辑器"),
                QStringLiteral("%1失败：\n%2")
                .arg(kOperationText, kDeleteResult.mergedOutputText.trimmed()));
            return false;
        };

    if (kSafeBootModeValue == QStringLiteral("off"))
    {
        if (!kDeleteValueWithMissingTolerance(QStringLiteral("safeboot")))
        {
            return;
        }
        if (!kDeleteValueWithMissingTolerance(QStringLiteral("safebootalternateshell")))
        {
            return;
        }
    }
    else if (kSafeBootModeValue == QStringLiteral("minimal"))
    {
        if (!runBcdAndExpectSuccess(
            QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("safeboot"), QStringLiteral("minimal") },
            QStringLiteral("写入 safeboot=minimal"),
            false))
        {
            return;
        }
        if (!kDeleteValueWithMissingTolerance(QStringLiteral("safebootalternateshell")))
        {
            return;
        }
    }
    else if (kSafeBootModeValue == QStringLiteral("network"))
    {
        if (!runBcdAndExpectSuccess(
            QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("safeboot"), QStringLiteral("network") },
            QStringLiteral("写入 safeboot=network"),
            false))
        {
            return;
        }
        if (!kDeleteValueWithMissingTolerance(QStringLiteral("safebootalternateshell")))
        {
            return;
        }
    }
    else if (kSafeBootModeValue == QStringLiteral("alternateshell"))
    {
        if (!runBcdAndExpectSuccess(
            QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("safeboot"), QStringLiteral("minimal") },
            QStringLiteral("写入 safeboot=minimal"),
            false))
        {
            return;
        }
        if (!runBcdAndExpectSuccess(
            QStringList{ QStringLiteral("/set"), kIdentifierText, QStringLiteral("safebootalternateshell"), QStringLiteral("yes") },
            QStringLiteral("写入 safebootalternateshell=yes"),
            false))
        {
            return;
        }
    }

    QMessageBox::information(this, QStringLiteral("引导编辑器"), QStringLiteral("当前条目已写入完成。"));
    refreshBcdEntries();
}

void BootEditorTab::applyBootManagerChanges()
{
    if (!runBcdAndExpectSuccess(
        QStringList{ QStringLiteral("/timeout"), QString::number(timeoutSpin_->value()) },
        QStringLiteral("写入 timeout"),
        true))
    {
        return;
    }
    refreshBcdEntries();
}

void BootEditorTab::setLegacyBootForSelectedEntry()
{
    // Current item: legacy boot.
    // - Write bootmenupolicy Legacy to the currently selected entry;
    // - Refresh the list and right-side details upon success.
    const BcdEntry* selectedEntry = currentEntry();
    if (selectedEntry == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("传统引导"), QStringLiteral("请先选择一个引导条目。"));
        return;
    }

    if (!applyBootMenuPolicyByIdentifier(
        selectedEntry->identifierText.trimmed(),
        QStringLiteral("Legacy"),
        QStringLiteral("当前项启用传统引导")))
    {
        return;
    }
    refreshBcdEntries();
}

void BootEditorTab::setLegacyBootForDefaultEntry()
{
    // Default item legacy boot:
    // - Write bootmenupolicy Legacy to the entry corresponding to {bootmgr}.default;
    // - If the default identifier is not read, prompt to refresh and retry.
    const QString kDefaultIdentifierText = defaultIdentifierText_.trimmed();
    if (kDefaultIdentifierText.isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("传统引导"),
            QStringLiteral("当前未识别到默认启动项，请先刷新 BCD。"));
        return;
    }

    if (!applyBootMenuPolicyByIdentifier(
        kDefaultIdentifierText,
        QStringLiteral("Legacy"),
        QStringLiteral("默认项启用传统引导")))
    {
        return;
    }
    refreshBcdEntries();
}

void BootEditorTab::setStandardBootForSelectedEntry()
{
    // Current item: restore standard.
    // - Writes bootmenupolicy Standard to the currently selected entry;
    // - Used to revert the 'Legacy Boot' quick settings.
    const BcdEntry* selectedEntry = currentEntry();
    if (selectedEntry == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("传统引导"), QStringLiteral("请先选择一个引导条目。"));
        return;
    }

    if (!applyBootMenuPolicyByIdentifier(
        selectedEntry->identifierText.trimmed(),
        QStringLiteral("Standard"),
        QStringLiteral("当前项恢复标准引导")))
    {
        return;
    }
    refreshBcdEntries();
}

void BootEditorTab::setSelectedAsDefaultEntry()
{
    const BcdEntry* selectedEntry = currentEntry();
    if (selectedEntry == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("引导编辑器"), QStringLiteral("请先选择一个引导条目。"));
        return;
    }
    if (!runBcdAndExpectSuccess(
        QStringList{ QStringLiteral("/default"), selectedEntry->identifierText.trimmed() },
        QStringLiteral("设置默认启动项"),
        true))
    {
        return;
    }
    refreshBcdEntries();
}

void BootEditorTab::addSelectedToBootSequence()
{
    const BcdEntry* selectedEntry = currentEntry();
    if (selectedEntry == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("引导编辑器"), QStringLiteral("请先选择一个引导条目。"));
        return;
    }
    if (!runBcdAndExpectSuccess(
        QStringList{
            QStringLiteral("/bootsequence"),
            selectedEntry->identifierText.trimmed(),
            QStringLiteral("/addfirst")
        },
        QStringLiteral("设置下一次启动项"),
        true))
    {
        return;
    }
    refreshBcdEntries();
}

void BootEditorTab::createCopyFromSelectedEntry()
{
    const BcdEntry* selectedEntry = currentEntry();
    if (selectedEntry == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("引导编辑器"), QStringLiteral("请先选择一个引导条目。"));
        return;
    }

    const QString kSourceDescription = readElementValue(
        *selectedEntry,
        QStringList{ QStringLiteral("description"), QStringLiteral("描述") });
    const QString kDefaultNewDescription = kSourceDescription.trimmed().isEmpty()
        ? QStringLiteral("新建引导项")
        : QStringLiteral("%1 - 副本").arg(kSourceDescription.trimmed());

    bool inputOk = false;
    const QString kNewDescription = QInputDialog::getText(
        this,
        QStringLiteral("复制引导项"),
        QStringLiteral("新引导项描述："),
        QLineEdit::Normal,
        kDefaultNewDescription,
        &inputOk).trimmed();
    if (!inputOk || kNewDescription.isEmpty())
    {
        return;
    }

    const BcdCommandResult kCopyResult = runBcdEdit(
        QStringList{
            QStringLiteral("/copy"),
            selectedEntry->identifierText.trimmed(),
            QStringLiteral("/d"),
            kNewDescription
        },
        kDefaultCommandTimeoutMs,
        QStringLiteral("复制引导项"));
    appendCommandLog(QStringLiteral("bcdedit /copy"), kCopyResult);

    if (!kCopyResult.startSucceeded || kCopyResult.timeout || kCopyResult.exitCode != 0)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("复制引导项"),
            QStringLiteral("复制失败：\n%1").arg(kCopyResult.mergedOutputText.trimmed()));
        return;
    }

    // newIdentifierRegex：
    // - Extract new GUID from command output.
    // - Automatically appended to the end of displayorder upon success.
    const QRegularExpression kNewIdentifierRegex(QStringLiteral("\\{[^\\}\\s]+\\}"));
    QRegularExpressionMatchIterator matchIterator = kNewIdentifierRegex.globalMatch(kCopyResult.mergedOutputText);
    QString newIdentifierText;
    while (matchIterator.hasNext())
    {
        const QRegularExpressionMatch kMatch = matchIterator.next();
        newIdentifierText = kMatch.captured(0);
    }

    if (!newIdentifierText.trimmed().isEmpty())
    {
        runBcdAndExpectSuccess(
            QStringList{
                QStringLiteral("/displayorder"),
                newIdentifierText.trimmed(),
                QStringLiteral("/addlast")
            },
            QStringLiteral("追加到 displayorder"),
            false);
    }

    QMessageBox::information(this, QStringLiteral("复制引导项"), QStringLiteral("复制成功。"));
    refreshBcdEntries();
}

void BootEditorTab::deleteSelectedEntry()
{
    const BcdEntry* selectedEntry = currentEntry();
    if (selectedEntry == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("引导编辑器"), QStringLiteral("请先选择一个引导条目。"));
        return;
    }

    const QString kIdentifierText = selectedEntry->identifierText.trimmed();
    if (kIdentifierText.compare(QStringLiteral("{bootmgr}"), Qt::CaseInsensitive) == 0)
    {
        QMessageBox::warning(this, QStringLiteral("删除引导项"), QStringLiteral("不允许删除 {bootmgr}。"));
        return;
    }
    if (kIdentifierText.compare(QStringLiteral("{current}"), Qt::CaseInsensitive) == 0)
    {
        QMessageBox::warning(this, QStringLiteral("删除引导项"), QStringLiteral("不允许删除 {current}。"));
        return;
    }

    const int kConfirmResult = QMessageBox::warning(
        this,
        QStringLiteral("删除引导项"),
        QStringLiteral("即将删除条目：%1\n该操作不可撤销，是否继续？").arg(kIdentifierText),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmResult != QMessageBox::Yes)
    {
        return;
    }

    if (!runBcdAndExpectSuccess(
        QStringList{ QStringLiteral("/delete"), kIdentifierText },
        QStringLiteral("删除引导项"),
        true))
    {
        return;
    }
    refreshBcdEntries();
}

void BootEditorTab::exportBcdStore()
{
    const QString kDefaultFileName = QStringLiteral("bcd_backup_%1.bcd")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
    const QString kOutputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出 BCD"),
        kDefaultFileName,
        QStringLiteral("BCD 文件 (*.bcd);;所有文件 (*.*)"));
    if (kOutputPath.trimmed().isEmpty())
    {
        return;
    }

    if (!runBcdAndExpectSuccess(
        QStringList{ QStringLiteral("/export"), kOutputPath },
        QStringLiteral("导出 BCD"),
        true))
    {
        return;
    }
}

void BootEditorTab::importBcdStore()
{
    const QString kInputPath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("导入 BCD"),
        QString(),
        QStringLiteral("BCD 文件 (*.bcd);;所有文件 (*.*)"));
    if (kInputPath.trimmed().isEmpty())
    {
        return;
    }

    const int kConfirmResult = QMessageBox::warning(
        this,
        QStringLiteral("导入 BCD"),
        QStringLiteral("导入会覆盖当前 BCD 存储，可能影响系统启动。\n确认继续吗？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmResult != QMessageBox::Yes)
    {
        return;
    }

    if (!runBcdAndExpectSuccess(
        QStringList{ QStringLiteral("/import"), kInputPath },
        QStringLiteral("导入 BCD"),
        true))
    {
        return;
    }
    refreshBcdEntries();
}

void BootEditorTab::executeCustomCommand()
{
    const QString kRawCommandText = customCommandEdit_->text().trimmed();
    if (kRawCommandText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("自定义命令"), QStringLiteral("请输入命令参数。"));
        return;
    }

    // Argument parsing strategy:
    // - Support '/set ...'.
    // - Also supports "bcdedit /set ...", automatically stripping the program prefix;
    QStringList argumentList = QProcess::splitCommand(kRawCommandText);
    if (!argumentList.isEmpty()
        && argumentList.front().compare(QStringLiteral("bcdedit"), Qt::CaseInsensitive) == 0)
    {
        argumentList.removeFirst();
    }
    if (argumentList.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("自定义命令"), QStringLiteral("未解析到有效参数。"));
        return;
    }

    const BcdCommandResult kCommandResult = runBcdEdit(
        argumentList,
        kDefaultCommandTimeoutMs,
        QStringLiteral("执行自定义 bcdedit"));
    appendCommandLog(QStringLiteral("bcdedit %1").arg(argumentList.join(' ')), kCommandResult);

    if (!kCommandResult.startSucceeded || kCommandResult.timeout || kCommandResult.exitCode != 0)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("自定义命令"),
            QStringLiteral("命令执行失败：\n%1").arg(kCommandResult.mergedOutputText.trimmed()));
        return;
    }

    QMessageBox::information(this, QStringLiteral("自定义命令"), QStringLiteral("命令执行成功。"));

    const QString kNormalizedCommandText = kRawCommandText.toLower();
    if (!kNormalizedCommandText.contains(QStringLiteral("/enum")))
    {
        refreshBcdEntries();
    }
}

void BootEditorTab::copySelectedRowToClipboard()
{
    const int kRowIndex = entryTable_->currentRow();
    if (kRowIndex < 0)
    {
        return;
    }

    QStringList cellTextList;
    for (int colIndex = 0; colIndex < entryTable_->columnCount(); ++colIndex)
    {
        QTableWidgetItem* item = entryTable_->item(kRowIndex, colIndex);
        cellTextList.push_back(item != nullptr ? item->text() : QString());
    }
    QApplication::clipboard()->setText(cellTextList.join('\t'));
}

int BootEditorTab::currentEntryIndex() const
{
    const int kRowIndex = entryTable_->currentRow();
    if (kRowIndex < 0)
    {
        return -1;
    }
    QTableWidgetItem* identifierItem = entryTable_->item(kRowIndex, kColumnIdentifier);
    if (identifierItem == nullptr)
    {
        return -1;
    }
    return identifierItem->data(Qt::UserRole).toInt();
}

const BootEditorTab::BcdEntry* BootEditorTab::currentEntry() const
{
    const int kIndex = currentEntryIndex();
    if (kIndex < 0 || kIndex >= static_cast<int>(entryList_.size()))
    {
        return nullptr;
    }
    return &entryList_[static_cast<std::size_t>(kIndex)];
}

bool BootEditorTab::entryMatchesFilter(const BcdEntry& entry) const
{
    const QString kKeywordText = filterEdit_->text().trimmed();
    if (kKeywordText.isEmpty())
    {
        return true;
    }
    const QString kLowerKeyword = kKeywordText.toLower();
    const QString kDescriptionText = readElementValue(entry, QStringList{
        QStringLiteral("description"),
        QStringLiteral("描述")
        });
    const QString kPathText = readElementValue(entry, QStringList{
        QStringLiteral("path"),
        QStringLiteral("路径")
        });
    const QString kDeviceText = readElementValue(entry, QStringList{
        QStringLiteral("device"),
        QStringLiteral("设备")
        });

    return entry.identifierText.toLower().contains(kLowerKeyword)
        || entry.objectTypeText.toLower().contains(kLowerKeyword)
        || kDescriptionText.toLower().contains(kLowerKeyword)
        || kPathText.toLower().contains(kLowerKeyword)
        || kDeviceText.toLower().contains(kLowerKeyword);
}

QString BootEditorTab::readElementValue(
    const BcdEntry& entry,
    const QStringList& candidateKeyList) const
{
    // Perform exact key matching only:
    // - Avoid false matches by 'contains' for similar fields like 'device' or 'osdevice';
    // - Return empty if the field is missing, leaving subsequent behavior to the caller;
    for (const QString& candidateRawKey : candidateKeyList)
    {
        const QString kNormalizedCandidateKey = normalizeElementKey(candidateRawKey);
        if (entry.elementMap.contains(kNormalizedCandidateKey))
        {
            return entry.elementMap.value(kNormalizedCandidateKey);
        }
    }
    return QString();
}

bool BootEditorTab::readElementBool(
    const BcdEntry& entry,
    const QStringList& candidateKeyList,
    const bool defaultValue) const
{
    const QString kValueText = readElementValue(entry, candidateKeyList);
    return parseBoolText(kValueText, defaultValue);
}

void BootEditorTab::appendCommandLog(
    const QString& commandTitle,
    const BcdCommandResult& commandResult)
{
    // Do not log asynchronous placeholder results.
    // - The placeholder result simply returns the cached text from the previous round unchanged to the refresh flow to maintain the existing UI content.
    // - After the background real result is fed back, the refresh logic runs again; only that second refresh writes to the log, ensuring exactly one record per refresh.
    if (gPlaceholderLogOwnerObject == this)
    {
        gPlaceholderLogOwnerObject = nullptr;
        return;
    }

    // Log block format:
    // - Display timestamp and command title on the first line.
    // - Display the original output starting from the second line;
    // - Append execution status summary at the end.
    const QString kTimestampText = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    QString statusText = QStringLiteral("start=%1, timeout=%2, exit=%3")
        .arg(commandResult.startSucceeded ? QStringLiteral("true") : QStringLiteral("false"))
        .arg(commandResult.timeout ? QStringLiteral("true") : QStringLiteral("false"))
        .arg(commandResult.exitCode);
    QString logText = QStringLiteral("[%1] %2\n%3\n[%4]\n\n")
        .arg(kTimestampText)
        .arg(commandTitle)
        .arg(commandResult.mergedOutputText.trimmed())
        .arg(statusText);

    rawOutputEdit_->moveCursor(QTextCursor::End);
    rawOutputEdit_->insertPlainText(logText);
    rawOutputEdit_->moveCursor(QTextCursor::End);
}

BootEditorTab::BcdCommandResult BootEditorTab::runBcdEdit(
    const QStringList& argumentList,
    const int timeoutMs,
    const QString& commandDescription)
{
    // On entry, clear the placeholder log marker:
    // - In the normal flow, appendCommandLog will immediately consume it;
    // - Fallback if a caller didn't write a log, to avoid suppressing the next real log.
    gPlaceholderLogOwnerObject = nullptr;

    BcdCommandResult result;
    const QString kCommandVerb = argumentList.value(0).trimmed().toLower();
    const bool kReadOnlyCommand = kCommandVerb == QStringLiteral("/enum") ||
        kCommandVerb == QStringLiteral("/enumall") ||
        kCommandVerb == QStringLiteral("/v");
    if (!kReadOnlyCommand && !ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("修改 BCD 启动配置"));
        result.startSucceeded = false;
        result.standardErrorText = QStringLiteral("需要管理员权限。请在管理员实例中重试。");
        result.mergedOutputText = result.standardErrorText;
        return result;
    }

    // ============ Refresh-specific read-only enumeration: Entire operation delegated to thread pool, zero UI thread blocking ============
    if (isBcdRefreshEnumRequest(argumentList, commandDescription))
    {
        // Step 1: If the background result has already been pushed back, retrieve it directly and return it with synchronous semantics so the refresh flow can correctly populate the table and write logs.
        const QVariant kReadyResultVariant = property(kEnumReadyResultProperty);
        if (kReadyResultVariant.isValid())
        {
            setProperty(kEnumReadyResultProperty, QVariant());

            const QVariantMap kReadyResultMap = kReadyResultVariant.toMap();
            result.startSucceeded =
                kReadyResultMap.value(QString::fromLatin1(kEnumResultStartSucceededKey)).toBool();
            result.timeout =
                kReadyResultMap.value(QString::fromLatin1(kEnumResultTimeoutKey)).toBool();
            result.exitCode =
                kReadyResultMap.value(QString::fromLatin1(kEnumResultExitCodeKey)).toInt();
            result.standardOutputText =
                kReadyResultMap.value(QString::fromLatin1(kEnumResultStandardOutputKey)).toString();
            result.standardErrorText =
                kReadyResultMap.value(QString::fromLatin1(kEnumResultStandardErrorKey)).toString();
            result.mergedOutputText = result.standardOutputText;
            if (!result.standardErrorText.trimmed().isEmpty())
            {
                if (!result.mergedOutputText.trimmed().isEmpty())
                {
                    result.mergedOutputText += QStringLiteral("\n");
                }
                result.mergedOutputText += result.standardErrorText;
            }

            KLogEvent asyncResultEvent;
            if (!result.startSucceeded)
            {
                err << asyncResultEvent
                    << "[BootEditor] 命令启动失败: "
                    << commandDescription.toStdString()
                    << ", error="
                    << result.standardErrorText.toStdString()
                    << eol;
            }
            else if (result.timeout)
            {
                err << asyncResultEvent
                    << "[BootEditor] 命令执行超时: "
                    << commandDescription.toStdString()
                    << ", timeoutMs="
                    << timeoutMs
                    << eol;
            }
            else if (result.exitCode == 0)
            {
                info << asyncResultEvent
                    << "[BootEditor] 命令执行完成: "
                    << commandDescription.toStdString()
                    << ", exitCode="
                    << result.exitCode
                    << eol;
            }
            else
            {
                warn << asyncResultEvent
                    << "[BootEditor] 命令返回非零: "
                    << commandDescription.toStdString()
                    << ", exitCode="
                    << result.exitCode
                    << eol;
            }
            return result;
        }

        // Step 2: Dispatch a background task if no result exists; if a task is already running, reuse it to avoid relaunching bcdedit.
        if (property(kEnumPendingGenerationProperty).toULongLong() == 0)
        {
            // requestGeneration purpose: Discards old results superseded by newer requests.
            const quint64 kRequestGeneration = ++gEnumRequestGenerationCounter;
            setProperty(
                kEnumPendingGenerationProperty,
                QVariant::fromValue<qulonglong>(kRequestGeneration));

            // guardedSelf usage: background tasks may outlive the widget; verify lifecycle before callback.
            const QPointer<BootEditorTab> kGuardedSelf(this);
            const QStringList kRequestArgumentList = argumentList;
            const int kRequestTimeoutMs = timeoutMs;
            QThreadPool::globalInstance()->start(
                [kGuardedSelf, kRequestGeneration, kRequestArgumentList, kRequestTimeoutMs]()
                {
                    // Background thread performs pure data collection, producing value types safe for cross-thread transfer.
                    const QVariantMap kCollectedResultMap =
                        runBcdEditInCallingThread(kRequestArgumentList, kRequestTimeoutMs);

                    QCoreApplication* const kAppInstance = QCoreApplication::instance();
                    if (kAppInstance == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        kAppInstance,
                        [kGuardedSelf, kRequestGeneration, kCollectedResultMap]()
                        {
                            if (kGuardedSelf == nullptr)
                            {
                                return;
                            }
                            const quint64 kCurrentPendingGeneration =
                                kGuardedSelf->property(kEnumPendingGenerationProperty).toULongLong();
                            if (kCurrentPendingGeneration != kRequestGeneration)
                            {
                                return;
                            }
                            kGuardedSelf->setProperty(kEnumPendingGenerationProperty, QVariant());
                            if (gSynchronousCommandDepth > 0)
                            {
                                // Currently stuck in synchronous wait for write command:
                                // - This snapshot was taken before the write and was already expired.
                                // - Refreshing now rebuilds the table and overwrites the content of the edit box the user is submitting.
                                // - Discard directly; the write process cleanup will automatically call refreshBcdEntries to re-fetch.
                                return;
                            }
                            kGuardedSelf->setProperty(kEnumReadyResultProperty, kCollectedResultMap);
                            kGuardedSelf->refreshBcdEntries();
                        });
                });
        }

        // Step 3: Immediately return a placeholder result.
        // - Retain the original enumeration text from the previous round; during the wait, the table and edit area maintain their existing content without flashing to an empty state.
        // - Mark the placeholder log ownership to avoid writing cached text repeatedly into the 'Raw Output' area.
        result.startSucceeded = true;
        result.timeout = false;
        result.exitCode = 0;
        result.standardOutputText = lastEnumRawText_;
        result.mergedOutputText = lastEnumRawText_;
        gPlaceholderLogOwnerObject = this;

        if (lastEnumRawText_.trimmed().isEmpty() && statusLabel_ != nullptr)
        {
            // On the first load, there is no historical data to reuse; refreshBcdEntries will write a summary stating "Total entries: 0".
            // Here, reset the status bar to 'Not Loaded' in the next event loop iteration to avoid misinterpretation that the system truly has no boot entries.
            QTimer::singleShot(0, this, [this]()
                {
                    if (statusLabel_ == nullptr)
                    {
                        return;
                    }
                    if (property(kEnumPendingGenerationProperty).toULongLong() == 0)
                    {
                        return;
                    }
                    statusLabel_->setText(QStringLiteral("状态：尚未加载 BCD 数据"));
                });
        }
        return result;
    }

    // ============ Remaining commands: signal-driven
    // bounded wait ============= Note:
    // - The caller of write operations decides whether to proceed with subsequent writes based on the return value; synchronous semantics must be preserved.
    // - But the wait mechanism is no longer a hard block on waitForStarted followed by busy polling on waitForFinished/processEvents:
    //   Process termination, startup failure, and timeout are all signal-driven. The nested event loop excludes user input
    //   events, blocking the path where clicking other tabs during the wait triggers lazy-load reentrancy construction.
    QProcess process; // Deliberately do not set a parent object: during nested event loops, destroying the parent control would cause a dangling pointer.

    process.setProgram(QStringLiteral("bcdedit"));
    process.setArguments(argumentList);
    process.setProcessChannelMode(QProcess::SeparateChannels);

    process.start();

    // buildStartFailureResult：
    // - Purpose: Unify result population and error logging for 'process failed to start' scenarios.
    // - Returns: a command result with error information already filled in.
    const auto kBuildStartFailureResult = [&result, &process, &commandDescription]() -> BcdCommandResult
        {
            result.startSucceeded = false;
            result.standardErrorText = process.errorString();
            result.mergedOutputText = result.standardErrorText;
            KLogEvent startFailedEvent;
            err << startFailedEvent
                << "[BootEditor] 命令启动失败: "
                << commandDescription.toStdString()
                << ", error="
                << result.standardErrorText.toStdString()
                << eol;
            return result;
        };

    if (process.state() == QProcess::NotRunning)
    {
        // When CreateProcess fails directly, QProcess synchronously returns NotRunning, so no wait loop is needed.
        return kBuildStartFailureResult();
    }

    QEventLoop waitEventLoop;
    QTimer waitTimeoutTimer;
    waitTimeoutTimer.setSingleShot(true);
    waitTimeoutTimer.setInterval(timeoutMs > 0 ? timeoutMs : kDefaultCommandTimeoutMs);

    bool processFailedToStart = false;
    bool waitTimedOut = false;

    QObject::connect(&process, &QProcess::finished, &waitEventLoop,
        [&waitEventLoop](int, QProcess::ExitStatus)
        {
            waitEventLoop.quit();
        });
    QObject::connect(&process, &QProcess::errorOccurred, &waitEventLoop,
        [&waitEventLoop, &processFailedToStart](const QProcess::ProcessError processError)
        {
            if (processError != QProcess::FailedToStart)
            {
                return;
            }
            processFailedToStart = true;
            waitEventLoop.quit();
        });
    QObject::connect(&waitTimeoutTimer, &QTimer::timeout, &waitEventLoop,
        [&waitEventLoop, &waitTimedOut]()
        {
            waitTimedOut = true;
            waitEventLoop.quit();
        });

    waitTimeoutTimer.start();
    if (process.state() != QProcess::NotRunning)
    {
        // Mark synchronous depth during nested wait:
        // - Exclude user input that would otherwise block 'lazy-load re-entry construction triggered by clicking other tabs while waiting'.
        // - Mark depth to block asynchronous enumeration results from being re-injected and refreshed at this moment, providing a double safety measure.
        ++gSynchronousCommandDepth;
        waitEventLoop.exec(QEventLoop::ExcludeUserInputEvents);
        --gSynchronousCommandDepth;
    }
    waitTimeoutTimer.stop();

    if (processFailedToStart)
    {
        return kBuildStartFailureResult();
    }
    result.startSucceeded = true;

    if (waitTimedOut)
    {
        result.timeout = true;
        process.kill();
        process.waitForFinished(kProcessKillWaitMs);

        result.standardOutputText = QString::fromLocal8Bit(process.readAllStandardOutput());
        result.standardErrorText = QString::fromLocal8Bit(process.readAllStandardError());
        result.mergedOutputText = result.standardOutputText + QStringLiteral("\n") + result.standardErrorText;

        KLogEvent timeoutEvent;
        err << timeoutEvent
            << "[BootEditor] 命令执行超时: "
            << commandDescription.toStdString()
            << ", timeoutMs="
            << timeoutMs
            << eol;
        return result;
    }

    result.exitCode = process.exitCode();
    result.standardOutputText = QString::fromLocal8Bit(process.readAllStandardOutput());
    result.standardErrorText = QString::fromLocal8Bit(process.readAllStandardError());
    result.mergedOutputText = result.standardOutputText;
    if (!result.standardErrorText.trimmed().isEmpty())
    {
        if (!result.mergedOutputText.trimmed().isEmpty())
        {
            result.mergedOutputText += QStringLiteral("\n");
        }
        result.mergedOutputText += result.standardErrorText;
    }

    KLogEvent event;
    if (result.exitCode == 0)
    {
        info << event
            << "[BootEditor] 命令执行完成: "
            << commandDescription.toStdString()
            << ", exitCode="
            << result.exitCode
            << eol;
    }
    else
    {
        warn << event
            << "[BootEditor] 命令返回非零: "
            << commandDescription.toStdString()
            << ", exitCode="
            << result.exitCode
            << eol;
    }
    return result;
}

bool BootEditorTab::runBcdAndExpectSuccess(
    const QStringList& argumentList,
    const QString& operationText,
    const bool showSuccessToast)
{
    const BcdCommandResult kResult = runBcdEdit(argumentList, kDefaultCommandTimeoutMs, operationText);
    appendCommandLog(QStringLiteral("bcdedit %1").arg(argumentList.join(' ')), kResult);

    if (!kResult.startSucceeded)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("引导编辑器"),
            QStringLiteral("%1失败：命令未能启动。\n%2").arg(operationText, kResult.mergedOutputText.trimmed()));
        return false;
    }
    if (kResult.timeout)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("引导编辑器"),
            QStringLiteral("%1失败：命令执行超时。").arg(operationText));
        return false;
    }
    if (kResult.exitCode != 0)
    {
        // privilegePromptHandled: The privilege recovery prompt has been displayed; the generic command error dialog will not be shown for this failure.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            operationText,
            kResult.mergedOutputText);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("引导编辑器"),
                QStringLiteral("%1失败：\n%2").arg(operationText, kResult.mergedOutputText.trimmed()));
        }
        return false;
    }

    if (showSuccessToast)
    {
        QMessageBox::information(this, QStringLiteral("引导编辑器"), QStringLiteral("%1成功。").arg(operationText));
    }
    return true;
}

bool BootEditorTab::applyBootMenuPolicyByIdentifier(
    const QString& identifierText,
    const QString& policyValueText,
    const QString& operationText)
{
    // Common policy write:
    // - Unify validation of identifiers and target policy parameters.
    // - Provide explicit result feedback upon success.
    const QString kNormalizedIdentifierText = identifierText.trimmed();
    const QString kNormalizedPolicyText = policyValueText.trimmed();
    if (kNormalizedIdentifierText.isEmpty() || kNormalizedPolicyText.isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("传统引导"),
            QStringLiteral("参数无效：标识符或策略为空。"));
        return false;
    }

    if (!runBcdAndExpectSuccess(
        QStringList{
            QStringLiteral("/set"),
            kNormalizedIdentifierText,
            QStringLiteral("bootmenupolicy"),
            kNormalizedPolicyText
        },
        operationText,
        false))
    {
        return false;
    }

    QMessageBox::information(
        this,
        QStringLiteral("传统引导"),
        QStringLiteral("%1成功。\n标识符：%2\n策略：%3")
        .arg(operationText)
        .arg(kNormalizedIdentifierText)
        .arg(kNormalizedPolicyText));
    return true;
}

QString BootEditorTab::normalizeElementKey(const QString& rawKeyText)
{
    // Normalization rules:
    // - Convert to lowercase;
    // - Remove spaces, hyphens, underscores, and tabs.
    // - Retain alphanumeric characters and common Chinese field names.
    QString normalizedText = rawKeyText.trimmed().toLower();
    normalizedText.remove(QRegularExpression(QStringLiteral("[\\s\\-_:]")));
    return normalizedText;
}

std::vector<BootEditorTab::BcdEntry> BootEditorTab::parseBcdEnumOutput(const QString& enumOutputText)
{
    std::vector<BcdEntry> entryList;

    BcdEntry currentEntry;
    QStringList currentRawLineList;
    bool insideBlock = false;
    bool nextNonEmptyLineIsType = false;

    // flushCurrent：
    // - Push the currently constructed object into the results;
    // - Clears state to begin the next object.
    const auto kFlushCurrent = [&entryList, &currentEntry, &currentRawLineList]()
        {
            if (currentEntry.identifierText.trimmed().isEmpty()
                && currentEntry.elementMap.isEmpty()
                && currentEntry.objectTypeText.trimmed().isEmpty())
            {
                currentRawLineList.clear();
                currentEntry = BcdEntry();
                return;
            }

            const QString kIdLowerText = currentEntry.identifierText.trimmed().toLower();
            currentEntry.isBootManager = (kIdLowerText == QStringLiteral("{bootmgr}"));
            currentEntry.isCurrent = (kIdLowerText == QStringLiteral("{current}"));
            currentEntry.rawBlockText = currentRawLineList.join('\n');
            entryList.push_back(currentEntry);

            currentEntry = BcdEntry();
            currentRawLineList.clear();
        };

    const QStringList kAllLineList = enumOutputText.split('\n');
    const QRegularExpression kSeparatorRegex(QStringLiteral("^-{3,}$"));
    const QRegularExpression kPairRegex(QStringLiteral("^(.+?)\\s{2,}(.+)$"));

    for (const QString& rawLine : kAllLineList)
    {
        const QString kLineText = rawLine;
        const QString kTrimmedLineText = kLineText.trimmed();

        if (kTrimmedLineText.isEmpty())
        {
            if (insideBlock)
            {
                currentRawLineList.push_back(kLineText);
            }
            continue;
        }

        if (kSeparatorRegex.match(kTrimmedLineText).hasMatch())
        {
            kFlushCurrent();
            insideBlock = true;
            nextNonEmptyLineIsType = true;
            currentRawLineList.push_back(kLineText);
            continue;
        }

        if (!insideBlock)
        {
            continue;
        }

        currentRawLineList.push_back(kLineText);

        if (nextNonEmptyLineIsType)
        {
            currentEntry.objectTypeText = kTrimmedLineText;
            nextNonEmptyLineIsType = false;
            continue;
        }

        const QRegularExpressionMatch kPairMatch = kPairRegex.match(kLineText);
        if (!kPairMatch.hasMatch())
        {
            continue;
        }

        const QString kKeyText = kPairMatch.captured(1).trimmed();
        const QString kValueText = kPairMatch.captured(2).trimmed();
        const QString kNormalizedKeyText = normalizeElementKey(kKeyText);

        if (!kNormalizedKeyText.isEmpty())
        {
            currentEntry.elementMap.insert(kNormalizedKeyText, kValueText);
        }

        const bool kMaybeIdentifierKey =
            kNormalizedKeyText.contains(QStringLiteral("identifier"))
            || kNormalizedKeyText.contains(QStringLiteral("标识符"))
            || kNormalizedKeyText.contains(QStringLiteral("识别符"));
        if (currentEntry.identifierText.trimmed().isEmpty())
        {
            if (kMaybeIdentifierKey)
            {
                currentEntry.identifierText = kValueText;
            }
            else if (kValueText.startsWith('{') && kValueText.endsWith('}'))
            {
                currentEntry.identifierText = kValueText;
            }
        }
    }

    kFlushCurrent();
    return entryList;
}

QString BootEditorTab::boolToBcdOnOff(const bool enabled)
{
    return enabled ? QStringLiteral("on") : QStringLiteral("off");
}

QString BootEditorTab::boolToBcdYesNo(const bool enabled)
{
    return enabled ? QStringLiteral("yes") : QStringLiteral("no");
}
