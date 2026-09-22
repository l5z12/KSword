// DisableDsePage.cpp
// See DisableDsePage.h for details. All kernel access occurs within DisableDseBackend; this file handles only the UI and dispatching.

#include "DisableDsePage.h"

#include "../../internationalization/LanguageManager.h"
#include "../../ui/CodeEditorWidget.h"
#include "../../Theme.h"

#include <QApplication>
#include <QEvent>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QVBoxLayout>

#include <thread>

namespace
{
    using ks::misc::disable_dse::ApplyResult;
    using ks::misc::disable_dse::BlockReason;
    using ks::misc::disable_dse::CodeIntegrityPosture;
    using ks::misc::disable_dse::PostureSource;

    // formatHex32：
    // - Input value: 32-bit value.
    // - Purpose: Standardize to the 0xXXXXXXXX format for easy comparison with output from other tools.
    // - Returns: Fixed-width hexadecimal text.
    QString formatHex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0'));
    }

    // formatHex64：
    // - Input value: 64-bit address;
    // - Purpose: Unify to a fixed-width address format with a 0x prefix.
    // - Returns: Fixed-width hexadecimal text.
    QString formatHex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1").arg(value, 16, 16, QChar('0'));
    }

    // postureSourceText：
    // - Input source: posture data source;
    // - Purpose: Inform the user who provided this status.
    // - Returns: Source description text.
    QString postureSourceText(const PostureSource source)
    {
        switch (source)
        {
        case PostureSource::kDriver:
            return QStringLiteral("R0 驱动查询");
        case PostureSource::kWin32:
            return QStringLiteral("R3 系统查询");
        case PostureSource::kNone:
        default:
            break;
        }
        return QStringLiteral("无可用通道");
    }

    // onOffText：
    // - Input enabled: Switch status.
    // - Purpose: Unify 'On/Off' text.
    // - Returns: The status text.
    // This is intentionally not written as a single-line ternary operator: cramming two QStringLiteral calls on one line
    // causes the i18n extractor to mistakenly treat the intermediate ") : QStringLiteral(" as a translatable literal.
    QString onOffText(const bool enabled)
    {
        if (enabled)
        {
            return QStringLiteral("开启");
        }
        return QStringLiteral("关闭");
    }

    // showOpaqueMessage：
    // - Purpose: Display a non-transparent themed message box to avoid inheriting the semi-transparent background from the parent chain.
    // - Returns: Nothing.
    void showOpaqueMessage(
        QWidget* const parent,
        const QMessageBox::Icon icon,
        const QString& title,
        const QString& message)
    {
        QMessageBox dialog(parent);
        dialog.setObjectName(QStringLiteral("ksDisableDseMessageBox"));
        dialog.setStyleSheet(ksword_theme::opaqueDialogStyle(dialog.objectName()));
        dialog.setIcon(icon);
        dialog.setWindowTitle(title);
        dialog.setText(message);
        dialog.setStandardButtons(QMessageBox::Ok);
        dialog.exec();
    }

    // askConfirmation：
    // - Purpose: Perform an explicit confirmation for irreversible operations like modifying kernel data.
    // - Return: true indicates the user chose to continue.
    bool askConfirmation(
        QWidget* const parent,
        const QString& title,
        const QString& message)
    {
        QMessageBox dialog(parent);
        dialog.setObjectName(QStringLiteral("ksDisableDseConfirmBox"));
        dialog.setStyleSheet(ksword_theme::opaqueDialogStyle(dialog.objectName()));
        dialog.setIcon(QMessageBox::Warning);
        dialog.setWindowTitle(title);
        dialog.setText(message);
        dialog.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        dialog.setDefaultButton(QMessageBox::No);
        return dialog.exec() == QMessageBox::Yes;
    }
}

namespace ks::misc
{
    DisableDsePage::DisableDsePage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
        initializeConnections();
        updateStateDisplay();
        updateButtons();
    }

    DisableDsePage::~DisableDsePage()
    {
        // The user might unload the driver immediately after loading it. If g_CiOptions remains in a modified state, PatchGuard
        // will flag it as kernel data tampering during its inspection; therefore, perform a final synchronous write-back here.
        if (!hasSavedOriginal_ || !location_.ok)
        {
            return;
        }

        const disable_dse::ReadbackResult kReadback =
            disable_dse::readCiOptions(location_);
        if (!kReadback.ok || kReadback.value == savedOriginalValue_)
        {
            return;
        }

        const disable_dse::ApplyResult kResult = disable_dse::writeCiOptions(
            location_, kReadback.value, savedOriginalValue_);

        KLogEvent closeEvent;
        if (kResult.ok)
        {
            const QString kMessage =
                QStringLiteral("[DisableDSE] 页面关闭时已把 g_CiOptions 写回原值 %1。")
                    .arg(formatHex32(savedOriginalValue_));
            info << closeEvent << kMessage.toStdString() << eol;
        }
        else
        {
            const QString kMessage =
                QStringLiteral("[DisableDSE] 页面关闭时恢复 g_CiOptions 失败：%1 请立即手动恢复或重启系统。")
                    .arg(kResult.detailText);
            err << closeEvent << kMessage.toStdString() << eol;
        }
    }

    void DisableDsePage::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        refreshPosture();
    }

    void DisableDsePage::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event == nullptr)
        {
            return;
        }
        if (event->type() == QEvent::ApplicationPaletteChange
            || event->type() == QEvent::PaletteChange)
        {
            applyBannerStyle();
            updateStateDisplay();
        }
    }

    // applyBannerStyle:
    // - Input: None. Reads semantic colors of the current theme.
    // - Processing: apply styles for the risk banner and pending restoration prompt; construction and theme switch follow the same path.
    // - Returns: None. Silently skips if the control has not been created yet.
    void DisableDsePage::applyBannerStyle()
    {
        if (warningLabel_ != nullptr)
        {
            warningLabel_->setStyleSheet(
                QStringLiteral(
                    "QLabel{padding:10px;border:1px solid %1;border-radius:5px;"
                    "background:%2;color:%3;}")
                    .arg(ksword_theme::errorHex())
                    .arg(ksword_theme::themeColorName(ksword_theme::errorBackgroundColor()))
                    .arg(ksword_theme::textPrimaryHex()));
        }
        if (pendingLabel_ != nullptr)
        {
            pendingLabel_->setStyleSheet(
                QStringLiteral(
                    "QLabel{padding:8px;border:1px solid %1;border-radius:5px;"
                    "background:%2;color:%3;}")
                    .arg(ksword_theme::warningHex())
                    .arg(ksword_theme::themeColorName(ksword_theme::warningBackgroundColor()))
                    .arg(ksword_theme::textPrimaryHex()));
        }
    }

    void DisableDsePage::initializeUi()
    {
        auto& language = ks::i18n::LanguageManager::instance();

        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(12, 12, 12, 12);
        rootLayout->setSpacing(10);

        // ===================== Risk Banner =====================
        warningLabel_ = new QLabel(this);
        warningLabel_->setWordWrap(true);
        warningLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        language.bindText(
            warningLabel_,
            QStringLiteral("misc.disable_dse.warning"),
            QStringLiteral("高风险功能：本页直接修改内核里 CI.dll!g_CiOptions 的 4 个字节，关闭后系统将接受未签名驱动。该变量在 PatchGuard 的巡检范围内，长时间保持关闭会触发 CRITICAL_STRUCTURE_CORRUPTION 蓝屏。请在加载完目标驱动后立刻点“恢复”，不要让系统长期停在关闭状态。"));
        rootLayout->addWidget(warningLabel_);

        // ===================== Current Status =====================
        auto* postureGroup = new QGroupBox(this);
        language.bindText(
            postureGroup,
            QStringLiteral("misc.disable_dse.posture.title"),
            QStringLiteral("代码完整性状态"));
        auto* postureLayout = new QVBoxLayout(postureGroup);
        postureLayout->setSpacing(6);

        postureLabel_ = new QLabel(postureGroup);
        postureLabel_->setWordWrap(true);
        postureLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        postureLayout->addWidget(postureLabel_);

        optionsLabel_ = new QLabel(postureGroup);
        optionsLabel_->setWordWrap(true);
        optionsLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        postureLayout->addWidget(optionsLabel_);

        blockLabel_ = new QLabel(postureGroup);
        blockLabel_->setWordWrap(true);
        blockLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        postureLayout->addWidget(blockLabel_);

        rootLayout->addWidget(postureGroup);

        // ===================== Target Location =====================
        auto* locationGroup = new QGroupBox(this);
        language.bindText(
            locationGroup,
            QStringLiteral("misc.disable_dse.location.title"),
            QStringLiteral("g_CiOptions 定位"));
        auto* locationLayout = new QVBoxLayout(locationGroup);
        locationLayout->setSpacing(6);

        locationLabel_ = new QLabel(locationGroup);
        locationLabel_->setWordWrap(true);
        locationLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        locationLayout->addWidget(locationLabel_);

        // The trace location belongs to program-generated detail text; use the project's built-in editor uniformly.
        // m_traceLines: Retains the original Chinese specification source text; CodeEditorWidget re-renders on language switch.
        traceEdit_ = new CodeEditorWidget(locationGroup);
        traceEdit_->setReadOnly(true);
        traceEdit_->setMaximumHeight(150);
        language.bindToolTip(
            traceEdit_,
            QStringLiteral("misc.disable_dse.trace.tooltip"),
            QStringLiteral("定位轨迹与事务日志。定位不使用任何硬编码偏移：从导出的 CiInitialize 反汇编找到 CipInitialize，再在其中找写 g_CiOptions 的指令。"));
        locationLayout->addWidget(traceEdit_);

        rootLayout->addWidget(locationGroup);

        // ===================== Operations =====================
        auto* actionGroup = new QGroupBox(this);
        language.bindText(
            actionGroup,
            QStringLiteral("misc.disable_dse.action.title"),
            QStringLiteral("操作"));
        auto* actionLayout = new QVBoxLayout(actionGroup);
        actionLayout->setSpacing(8);

        pendingLabel_ = new QLabel(actionGroup);
        pendingLabel_->setWordWrap(true);
        pendingLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        pendingLabel_->setVisible(false);
        actionLayout->addWidget(pendingLabel_);

        auto* buttonLayout = new QHBoxLayout();
        buttonLayout->setSpacing(8);

        refreshButton_ = new QPushButton(actionGroup);
        refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        language.bindText(
            refreshButton_,
            QStringLiteral("misc.disable_dse.action.refresh"),
            QStringLiteral("刷新状态"));
        buttonLayout->addWidget(refreshButton_);

        locateButton_ = new QPushButton(actionGroup);
        locateButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        language.bindText(
            locateButton_,
            QStringLiteral("misc.disable_dse.action.locate"),
            QStringLiteral("定位并校验"));
        buttonLayout->addWidget(locateButton_);

        disableButton_ = new QPushButton(actionGroup);
        disableButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        language.bindText(
            disableButton_,
            QStringLiteral("misc.disable_dse.action.disable"),
            QStringLiteral("关闭签名强制"));
        buttonLayout->addWidget(disableButton_);

        restoreButton_ = new QPushButton(actionGroup);
        restoreButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        language.bindText(
            restoreButton_,
            QStringLiteral("misc.disable_dse.action.restore"),
            QStringLiteral("恢复原值"));
        buttonLayout->addWidget(restoreButton_);

        buttonLayout->addStretch(1);
        actionLayout->addLayout(buttonLayout);

        resultLabel_ = new QLabel(actionGroup);
        resultLabel_->setWordWrap(true);
        resultLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        actionLayout->addWidget(resultLabel_);

        rootLayout->addWidget(actionGroup);
        rootLayout->addStretch(1);

        applyBannerStyle();
    }

    void DisableDsePage::initializeConnections()
    {
        connect(refreshButton_, &QPushButton::clicked, this, [this]() {
            refreshPosture();
        });
        connect(locateButton_, &QPushButton::clicked, this, [this]() {
            runLocate();
        });
        connect(disableButton_, &QPushButton::clicked, this, [this]() {
            const QString kMessage = ks::i18n::text(
                QStringLiteral("misc.disable_dse.confirm.disable"),
                QStringLiteral("即将把 g_CiOptions 改成 0，系统将不再校验驱动签名。\n\n该变量在 PatchGuard 的巡检范围内，保持关闭状态会导致蓝屏，请在加载完驱动后立即恢复。\n\n确定继续吗？"));
            if (!askConfirmation(
                    this,
                    ks::i18n::text(
                        QStringLiteral("misc.disable_dse.confirm.title"),
                        QStringLiteral("关闭驱动签名强制")),
                    kMessage))
            {
                return;
            }
            runApply(disable_dse::kDisabledValue, false);
        });
        connect(restoreButton_, &QPushButton::clicked, this, [this]() {
            runApply(savedOriginalValue_, true);
        });
    }

    void DisableDsePage::refreshPosture()
    {
        posture_ = disable_dse::queryPosture();
        updateStateDisplay();
        updateButtons();

        if (!posture_.queried)
        {
            setResultText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.posture_failed"),
                    QStringLiteral("状态查询失败："))
                    + posture_.failureText,
                true);
        }
    }

    void DisableDsePage::runLocate()
    {
        if (busy_)
        {
            return;
        }
        setBusy(true);
        appendTrace(QStringLiteral("开始定位 g_CiOptions……"));

        const QPointer<DisableDsePage> kGuardThis(this);
        const disable_dse::CodeIntegrityPosture kPosture = posture_;

        std::thread([kGuardThis, kPosture]() {
            LocateOutcome outcome;
            outcome.posture = kPosture;
            outcome.location = disable_dse::locateCiOptions();
            if (outcome.location.ok)
            {
                outcome.readback = disable_dse::readCiOptions(outcome.location);
                // Pre-write guard: g_CiOptions uses CI.dll's internal encoding, which is not the same set as the
                // system-reported CODEINTEGRITY_OPTION_*. The two values are inherently unequal, so we only compare the
                // single semantic meaning of 'whether forced signing is currently active'. If the address is mislocated
                // and lands on unrelated kernel data, it is highly unlikely to coincidentally satisfy this relationship.
                outcome.valueMatched = outcome.readback.ok
                    && disable_dse::ciOptionsAgreesWithPosture(
                        outcome.readback.value, outcome.posture);
            }

            if (kGuardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(qApp, [kGuardThis, outcome]() {
                if (kGuardThis == nullptr)
                {
                    return;
                }
                kGuardThis->applyLocateOutcome(outcome);
            });
        }).detach();
    }

    void DisableDsePage::runApply(const std::uint32_t desiredValue, const bool isRestore)
    {
        if (busy_ || !location_.ok)
        {
            return;
        }
        setBusy(true);

        const QPointer<DisableDsePage> kGuardThis(this);
        const disable_dse::TargetLocation kLocation = location_;

        std::thread([kGuardThis, kLocation, desiredValue, isRestore]() {
            ApplyResult result;
            // Read again before writing to align the expected-before value with the current real value:
            // Other tools may have modified g_CiOptions during this period.
            const disable_dse::ReadbackResult kReadback =
                disable_dse::readCiOptions(kLocation);
            if (!kReadback.ok)
            {
                result.detailText = kReadback.failureText;
            }
            else
            {
                result = disable_dse::writeCiOptions(
                    kLocation, kReadback.value, desiredValue);
            }

            if (kGuardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(qApp, [kGuardThis, result, isRestore]() {
                if (kGuardThis == nullptr)
                {
                    return;
                }
                kGuardThis->applyApplyOutcome(result, isRestore);
            });
        }).detach();
    }

    void DisableDsePage::applyLocateOutcome(const LocateOutcome& outcome)
    {
        setBusy(false);
        location_ = outcome.location;
        valueMatched_ = outcome.valueMatched;

        for (const QString& line : outcome.location.traceLines)
        {
            appendTrace(line);
        }

        if (!outcome.location.ok)
        {
            hasCurrentValue_ = false;
            appendTrace(QStringLiteral("定位失败：%1").arg(outcome.location.failureText));
            updateStateDisplay();
            updateButtons();
            setResultText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.locate_failed"),
                    QStringLiteral("定位失败："))
                    + outcome.location.failureText,
                true);
            return;
        }

        if (!outcome.readback.ok)
        {
            hasCurrentValue_ = false;
            appendTrace(QStringLiteral("读回失败：%1").arg(outcome.readback.failureText));
            updateStateDisplay();
            updateButtons();
            setResultText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.read_failed"),
                    QStringLiteral("读回失败："))
                    + outcome.readback.failureText,
                true);
            return;
        }

        currentValue_ = outcome.readback.value;
        hasCurrentValue_ = true;
        appendTrace(QStringLiteral("读回 g_CiOptions = %1（%2）")
                        .arg(formatHex32(outcome.readback.value))
                        .arg(disable_dse::describeCiOptions(outcome.readback.value)));

        if (!outcome.valueMatched)
        {
            appendTrace(
                QStringLiteral("校验不通过：系统自报驱动签名强制为“%1”，而读回值 %2 的强制位与之矛盾。已拒绝后续写入。")
                    .arg(onOffText(outcome.posture.ciEnabled))
                    .arg(formatHex32(outcome.readback.value)));
            updateStateDisplay();
            updateButtons();
            setResultText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.mismatch"),
                    QStringLiteral("读回值的强制签名位与系统自报状态矛盾，地址存疑，已禁止写入。")),
                true);
            return;
        }

        appendTrace(QStringLiteral("校验通过：读回值的强制签名位与系统自报状态一致。"));
        updateStateDisplay();
        updateButtons();
        setResultText(
            ks::i18n::text(
                QStringLiteral("misc.disable_dse.result.locate_ok"),
                QStringLiteral("定位并校验通过，可以执行操作。")),
            false);
    }

    void DisableDsePage::applyApplyOutcome(const ApplyResult& result, const bool isRestore)
    {
        setBusy(false);

        for (const QString& line : result.traceLines)
        {
            appendTrace(line);
        }

        if (!result.ok)
        {
            appendTrace(QStringLiteral("操作失败：%1").arg(result.detailText));
            updateStateDisplay();
            updateButtons();
            setResultText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.apply_failed"),
                    QStringLiteral("操作失败："))
                    + result.detailText,
                true);
            return;
        }

        currentValue_ = result.writtenValue;
        hasCurrentValue_ = true;

        if (isRestore)
        {
            // Clear the pending recovery accounting upon successful restoration so the destructor does not write again.
            hasSavedOriginal_ = false;
            appendTrace(QStringLiteral("已恢复 g_CiOptions = %1")
                            .arg(formatHex32(result.writtenValue)));
        }
        else
        {
            // Record the original value only on the first close: consecutive closes must not overwrite the original value with 0.
            if (!hasSavedOriginal_)
            {
                savedOriginalValue_ = result.previousValue;
                hasSavedOriginal_ = true;
            }
            appendTrace(QStringLiteral("已关闭签名强制，原值 %1 已记录，请尽快恢复。")
                            .arg(formatHex32(savedOriginalValue_)));
        }

        // Writing changes CodeIntegrityOptions; re-query the posture to keep the display synchronized.
        posture_ = disable_dse::queryPosture();
        updateStateDisplay();
        updateButtons();

        setResultText(
            isRestore
                ? ks::i18n::text(
                      QStringLiteral("misc.disable_dse.result.restore_ok"),
                      QStringLiteral("已恢复原值，驱动签名强制回到原始状态。"))
                : ks::i18n::text(
                      QStringLiteral("misc.disable_dse.result.disable_ok"),
                      QStringLiteral("已关闭驱动签名强制。请立即加载目标驱动，然后马上点“恢复原值”。")),
            false);
    }

    void DisableDsePage::appendTrace(const QString& line)
    {
        if (traceEdit_ == nullptr)
        {
            return;
        }
        traceLines_.append(line);
        traceEdit_->setLocalizedText(traceLines_.join(QChar('\n')));
    }

    void DisableDsePage::setResultText(const QString& text, const bool isError)
    {
        if (resultLabel_ == nullptr)
        {
            return;
        }
        resultLabel_->setText(text);
        resultLabel_->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(isError ? ksword_theme::errorHex() : ksword_theme::successHex()));
    }

    void DisableDsePage::setBusy(const bool busy)
    {
        busy_ = busy;
        updateButtons();
    }

    void DisableDsePage::updateButtons()
    {
        const bool kAllowed = !busy_ && blockReason_ == disable_dse::BlockReason::kNone;

        if (refreshButton_ != nullptr)
        {
            refreshButton_->setEnabled(!busy_);
        }
        if (locateButton_ != nullptr)
        {
            // Locate is read-only only; enable it when not busy. Failure reasons are more useful than a grayed-out button.
            locateButton_->setEnabled(!busy_);
        }
        if (disableButton_ != nullptr)
        {
            disableButton_->setEnabled(
                kAllowed && valueMatched_ && hasCurrentValue_
                && currentValue_ != disable_dse::kDisabledValue);
        }
        if (restoreButton_ != nullptr)
        {
            restoreButton_->setEnabled(
                kAllowed && valueMatched_ && hasSavedOriginal_
                && hasCurrentValue_ && currentValue_ != savedOriginalValue_);
        }
    }

    void DisableDsePage::updateStateDisplay()
    {
        blockReason_ = disable_dse::evaluateBlockReason(posture_, location_);
        if (blockReason_ == disable_dse::BlockReason::kNone
            && location_.ok && !valueMatched_ && hasCurrentValue_)
        {
            blockReason_ = disable_dse::BlockReason::kValueMismatch;
        }

        if (postureLabel_ != nullptr)
        {
            if (!posture_.queried)
            {
                postureLabel_->setText(
                    ks::i18n::text(
                        QStringLiteral("misc.disable_dse.posture.unknown"),
                        QStringLiteral("尚未取得代码完整性状态。")));
            }
            else
            {
                QStringList parts;
                parts << QStringLiteral("驱动签名强制：%1").arg(onOffText(posture_.ciEnabled));
                parts << QStringLiteral("测试签名：%1").arg(onOffText(posture_.testSigningEnabled));
                parts << QStringLiteral("内存完整性(HVCI)：%1").arg(onOffText(posture_.hvciEnabled));
                if (posture_.source == PostureSource::kDriver)
                {
                    parts << QStringLiteral("安全启动：%1").arg(onOffText(posture_.secureBootEnabled));
                }
                postureLabel_->setText(
                    QStringLiteral("%1\n数据来源：%2　系统内部版本：%3")
                        .arg(parts.join(QStringLiteral("　")))
                        .arg(postureSourceText(posture_.source))
                        .arg(posture_.buildNumber));
            }
        }

        if (optionsLabel_ != nullptr)
        {
            if (!posture_.queried)
            {
                optionsLabel_->clear();
            }
            else
            {
                QString text = QStringLiteral("系统自报 CodeIntegrityOptions = %1（%2）")
                                   .arg(formatHex32(posture_.options))
                                   .arg(disable_dse::describeOptions(posture_.options));
                if (hasCurrentValue_)
                {
                    // The two values use different bit encodings and should not be compared numerically; therefore, annotate their meanings on separate lines.
                    text += QStringLiteral("\n内核读回 g_CiOptions = %1（%2）")
                                .arg(formatHex32(currentValue_))
                                .arg(disable_dse::describeCiOptions(currentValue_));
                }
                optionsLabel_->setText(text);
            }
            optionsLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
        }

        if (blockLabel_ != nullptr)
        {
            const QString kReasonText = disable_dse::blockReasonText(blockReason_);
            blockLabel_->setText(kReasonText);
            blockLabel_->setVisible(!kReasonText.isEmpty());
            blockLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
        }

        if (locationLabel_ != nullptr)
        {
            if (!location_.ok)
            {
                locationLabel_->setText(
                    ks::i18n::text(
                        QStringLiteral("misc.disable_dse.location.none"),
                        QStringLiteral("尚未定位。点“定位并校验”开始。")));
            }
            else
            {
                locationLabel_->setText(
                    QStringLiteral("%1 基址 %2　RVA 0x%3（节 %4）\ng_CiOptions 内核地址 %5")
                        .arg(location_.moduleName)
                        .arg(formatHex64(location_.moduleBase))
                        .arg(location_.rva, 0, 16)
                        .arg(location_.sectionName)
                        .arg(formatHex64(location_.kernelAddress)));
            }
        }

        if (pendingLabel_ != nullptr)
        {
            pendingLabel_->setVisible(hasSavedOriginal_);
            if (hasSavedOriginal_)
            {
                pendingLabel_->setText(
                    QStringLiteral("驱动签名强制当前处于被本页修改的状态，原值 %1 已记录。请在加载完驱动后立即点“恢复原值”；若直接关闭程序，本页会在退出时尝试自动写回。")
                        .arg(formatHex32(savedOriginalValue_)));
            }
        }
    }
}
