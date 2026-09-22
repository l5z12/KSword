#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        QWidget* FileDetailDialog::buildMetadataSecurityPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QLabel* hint = new QLabel(QStringLiteral(
                "可编辑 Owner、Primary Group、DACL、SACL、Mandatory Integrity 与继承保护。"
                "SDDL 会在保存事务中通过 Windows 安全 API 写入。"), page);
            hint->setWordWrap(true);
            layout->addWidget(hint);
            QPlainTextEdit* sddlEdit = new QPlainTextEdit(page);
            sddlEdit->setPlaceholderText(QStringLiteral("例如 O:...G:...D:...S:..."));
            layout->addWidget(sddlEdit, 1);
            QHBoxLayout* scopes = new QHBoxLayout();
            QCheckBox* ownerCheck = new QCheckBox(QStringLiteral("Owner"), page);
            QCheckBox* groupCheck = new QCheckBox(QStringLiteral("Primary Group"), page);
            QCheckBox* daclCheck = new QCheckBox(QStringLiteral("DACL"), page);
            QCheckBox* saclCheck = new QCheckBox(QStringLiteral("SACL / Mandatory Label"), page);
            QCheckBox* protectDaclCheck = new QCheckBox(QStringLiteral("保护 DACL 继承"), page);
            QCheckBox* protectSaclCheck = new QCheckBox(QStringLiteral("保护 SACL 继承"), page);
            daclCheck->setChecked(true);
            scopes->addWidget(ownerCheck);
            scopes->addWidget(groupCheck);
            scopes->addWidget(daclCheck);
            scopes->addWidget(saclCheck);
            scopes->addWidget(protectDaclCheck);
            scopes->addWidget(protectSaclCheck);
            scopes->addStretch(1);
            layout->addLayout(scopes);
            QHBoxLayout* effectiveLayout = new QHBoxLayout();
            QLineEdit* effectiveTrusteeEdit = new QLineEdit(page);
            effectiveTrusteeEdit->setPlaceholderText(QStringLiteral(
                "账户或 SID，例如 BUILTIN\\Users / Everyone / S-1-5-32-545"));
            QPushButton* effectiveButton = new QPushButton(QStringLiteral("检查有效权限"), page);
            QLabel* effectiveResult = new QLabel(QStringLiteral("Mask: -"), page);
            effectiveResult->setTextInteractionFlags(Qt::TextSelectableByMouse);
            effectiveLayout->addWidget(effectiveTrusteeEdit, 1);
            effectiveLayout->addWidget(effectiveButton);
            effectiveLayout->addWidget(effectiveResult);
            layout->addLayout(effectiveLayout);
            QLabel* status = new QLabel(QStringLiteral("可从第一个目标读取 Owner、Group 与 DACL SDDL。"), page);
            status->setWordWrap(true);
            layout->addWidget(status);
            QHBoxLayout* actions = new QHBoxLayout();
            QPushButton* loadButton = new QPushButton(QStringLiteral("读取当前 SDDL"), page);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存安全描述符"), page);
            actions->addWidget(loadButton);
            actions->addStretch(1);
            actions->addWidget(stageButton);
            layout->addLayout(actions);
            connect(loadButton, &QPushButton::clicked, this, [this, sddlEdit, status]()
                {
                    status->setText(QStringLiteral("● 正在后台读取安全描述符..."));
                    const QString kPath = filePath_;
                    QPointer<QPlainTextEdit> editorGuard(sddlEdit);
                    QPointer<QLabel> statusGuard(status);
                    auto* task = QRunnable::create([kPath, editorGuard, statusGuard]()
                        {
                            DWORD error = ERROR_SUCCESS;
                            const QString kSddl =
                                ks::file::metadata::readSecurityDescriptorSddl(kPath, &error);
                            if (editorGuard == nullptr || statusGuard == nullptr) return;
                            QMetaObject::invokeMethod(editorGuard.data(),
                                [editorGuard, statusGuard, kSddl, error]()
                                {
                                    if (editorGuard == nullptr || statusGuard == nullptr) return;
                                    if (error != ERROR_SUCCESS)
                                    {
                                        statusGuard->setText(QStringLiteral("● SDDL 读取失败：%1")
                                            .arg(formatWin32ErrorText(error)));
                                        return;
                                    }
                                    editorGuard->setPlainText(kSddl);
                                    statusGuard->setText(QStringLiteral("● 当前 SDDL 已读取。"));
                                }, Qt::QueuedConnection);
                        });
                    task->setAutoDelete(true);
                    QThreadPool::globalInstance()->start(task);
                });
            connect(effectiveButton, &QPushButton::clicked, this,
                [this, effectiveTrusteeEdit, effectiveResult]()
                {
                    DWORD accessMask = 0U;
                    const DWORD kError = ks::file::metadata::queryEffectiveAccessMask(
                        filePath_,
                        effectiveTrusteeEdit->text(),
                        &accessMask);
                    effectiveResult->setText(kError == ERROR_SUCCESS
                        ? QStringLiteral("Mask: 0x%1 · %2")
                            .arg(accessMask, 8, 16, QLatin1Char('0'))
                            .arg(accessMaskToText(accessMask))
                        : QStringLiteral("检查失败：%1").arg(formatWin32ErrorText(kError)));
                });
            connect(stageButton, &QPushButton::clicked, this,
                [this, sddlEdit, ownerCheck, groupCheck, daclCheck, saclCheck,
                 protectDaclCheck, protectSaclCheck, status]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    SECURITY_INFORMATION information = 0U;
                    if (ownerCheck->isChecked()) information |= OWNER_SECURITY_INFORMATION;
                    if (groupCheck->isChecked()) information |= GROUP_SECURITY_INFORMATION;
                    if (daclCheck->isChecked()) information |= DACL_SECURITY_INFORMATION;
                    if (saclCheck->isChecked()) information |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
                    if (protectDaclCheck->isChecked())
                        information |= DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
                    if (protectSaclCheck->isChecked())
                        information |= SACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION;
                    if (information == 0U || sddlEdit->toPlainText().trimmed().isEmpty())
                    {
                        QMessageBox::warning(this, QStringLiteral("安全描述符"),
                            QStringLiteral("请填写 SDDL 并至少选择一个写入范围。"));
                        return;
                    }
                    PSECURITY_DESCRIPTOR descriptor = nullptr;
                    if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddlEdit->toPlainText().trimmed().toStdWString().c_str(),
                        SDDL_REVISION_1, &descriptor, nullptr) == FALSE)
                    {
                        QMessageBox::warning(this, QStringLiteral("安全描述符"),
                            QStringLiteral("SDDL 格式无效：%1")
                                .arg(formatWin32ErrorText(::GetLastError())));
                        return;
                    }
                    ::LocalFree(descriptor);
                    for (ks::file::metadata::TargetPatch& patch : pendingPatches_)
                    {
                        patch.security.replaceSddl = true;
                        patch.security.sddl = sddlEdit->toPlainText().trimmed();
                        patch.security.securityInformation = information;
                    }
                    status->setText(QStringLiteral("● 安全描述符已暂存。"));
                    updatePendingSaveUi();
                });
            return page;
        }

        QWidget* FileDetailDialog::buildMetadataPeAndReparsePage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QGroupBox* reparseGroup = new QGroupBox(QStringLiteral("重解析点原始缓冲"), page);
            QVBoxLayout* reparseLayout = new QVBoxLayout(reparseGroup);
            QHBoxLayout* reparseActions = new QHBoxLayout();
            QComboBox* reparseAction = new QComboBox(reparseGroup);
            reparseAction->addItems(QStringList{
                QStringLiteral("不修改"),
                QStringLiteral("写入原始缓冲"),
                QStringLiteral("删除重解析点") });
            QPushButton* loadReparseButton = new QPushButton(QStringLiteral("读取当前原始缓冲"), reparseGroup);
            reparseActions->addWidget(reparseAction);
            reparseActions->addWidget(loadReparseButton);
            reparseActions->addStretch(1);
            QPlainTextEdit* reparseEdit = new QPlainTextEdit(reparseGroup);
            reparseEdit->setPlaceholderText(QStringLiteral("完整 REPARSE_DATA_BUFFER 十六进制，包含 Tag/Length/Reserved"));
            reparseEdit->setMaximumHeight(100);
            reparseLayout->addLayout(reparseActions);
            reparseLayout->addWidget(reparseEdit);
            layout->addWidget(reparseGroup);

            QGroupBox* resourceGroup = new QGroupBox(QStringLiteral("PE 资源编辑"), page);
            QGridLayout* resourceLayout = new QGridLayout(resourceGroup);
            QComboBox* resourcePreset = new QComboBox(resourceGroup);
            resourcePreset->addItems(QStringList{
                QStringLiteral("VERSIONINFO（RT_VERSION #16）"),
                QStringLiteral("Manifest（RT_MANIFEST #24）"),
                QStringLiteral("其它资源") });
            QLineEdit* resourceTypeEdit = new QLineEdit(QStringLiteral("#16"), resourceGroup);
            QLineEdit* resourceNameEdit = new QLineEdit(QStringLiteral("#1"), resourceGroup);
            QSpinBox* resourceLanguageSpin = new QSpinBox(resourceGroup);
            resourceLanguageSpin->setRange(0, 65535);
            QComboBox* resourceFormatCombo = new QComboBox(resourceGroup);
            resourceFormatCombo->addItems(QStringList{ QStringLiteral("文本 UTF-8"), QStringLiteral("十六进制") });
            resourceFormatCombo->setCurrentIndex(1);
            QCheckBox* removeResourceCheck = new QCheckBox(QStringLiteral("删除该资源"), resourceGroup);
            QPushButton* loadResourceButton = new QPushButton(QStringLiteral("读取当前资源"), resourceGroup);
            QPlainTextEdit* resourceDataEdit = new QPlainTextEdit(resourceGroup);
            resourceDataEdit->setMaximumHeight(110);
            resourceLayout->addWidget(resourcePreset, 0, 0);
            resourceLayout->addWidget(new QLabel(QStringLiteral("类型"), resourceGroup), 0, 1);
            resourceLayout->addWidget(resourceTypeEdit, 0, 2);
            resourceLayout->addWidget(new QLabel(QStringLiteral("名称 / ID"), resourceGroup), 0, 3);
            resourceLayout->addWidget(resourceNameEdit, 0, 4);
            resourceLayout->addWidget(new QLabel(QStringLiteral("语言 ID"), resourceGroup), 1, 0);
            resourceLayout->addWidget(resourceLanguageSpin, 1, 1);
            resourceLayout->addWidget(resourceFormatCombo, 1, 2);
            resourceLayout->addWidget(removeResourceCheck, 1, 3);
            resourceLayout->addWidget(loadResourceButton, 1, 4);
            resourceLayout->addWidget(resourceDataEdit, 2, 0, 1, 5);
            layout->addWidget(resourceGroup);

            QCheckBox* clearSignatureCheck = new QCheckBox(
                QStringLiteral("保存时清除嵌入式 Authenticode 签名（Catalog 签名不会被删除）"), page);
            layout->addWidget(clearSignatureCheck);
            QLabel* warning = new QLabel(QStringLiteral(
                "原始重解析点、PE 资源和签名清除属于高风险操作，必须启用底部备份选项。"
                "VERSIONINFO 可用原始十六进制编辑，Manifest 可用 UTF-8 文本编辑，其它资源支持原始字节。"), page);
            warning->setWordWrap(true);
            layout->addWidget(warning);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存重解析点 / PE / 签名操作"), page);
            layout->addWidget(stageButton, 0, Qt::AlignRight);
            layout->addStretch(1);

            connect(resourcePreset, &QComboBox::currentIndexChanged, this,
                [resourceTypeEdit, resourceNameEdit, resourceFormatCombo](const int index)
                {
                    if (index == 0)
                    {
                        resourceTypeEdit->setText(QStringLiteral("#16"));
                        resourceNameEdit->setText(QStringLiteral("#1"));
                        resourceFormatCombo->setCurrentIndex(1);
                    }
                    else if (index == 1)
                    {
                        resourceTypeEdit->setText(QStringLiteral("#24"));
                        resourceNameEdit->setText(QStringLiteral("#1"));
                        resourceFormatCombo->setCurrentIndex(0);
                    }
                });
            connect(loadReparseButton, &QPushButton::clicked, this, [this, reparseEdit]()
                {
                    DWORD error = ERROR_SUCCESS;
                    const QByteArray kData = ks::file::metadata::readRawReparseData(filePath_, &error);
                    if (error != ERROR_SUCCESS)
                    {
                        QMessageBox::warning(this, QStringLiteral("重解析点"),
                            QStringLiteral("读取原始缓冲失败：%1").arg(formatWin32ErrorText(error)));
                        return;
                    }
                    reparseEdit->setPlainText(QString::fromLatin1(kData.toHex(' ').toUpper()));
                });
            connect(loadResourceButton, &QPushButton::clicked, this,
                [this, resourceTypeEdit, resourceNameEdit, resourceLanguageSpin,
                 resourceFormatCombo, resourceDataEdit]()
                {
                    DWORD error = ERROR_SUCCESS;
                    const QByteArray kData = ks::file::metadata::readPeResource(
                        filePath_,
                        resourceTypeEdit->text(),
                        resourceNameEdit->text(),
                        static_cast<WORD>(resourceLanguageSpin->value()),
                        &error);
                    if (error != ERROR_SUCCESS)
                    {
                        QMessageBox::warning(this, QStringLiteral("PE 资源"),
                            QStringLiteral("读取资源失败：%1").arg(formatWin32ErrorText(error)));
                        return;
                    }
                    resourceDataEdit->setPlainText(resourceFormatCombo->currentIndex() == 0
                        ? QString::fromUtf8(kData)
                        : QString::fromLatin1(kData.toHex(' ').toUpper()));
                });
            connect(stageButton, &QPushButton::clicked, this,
                [this, reparseAction, reparseEdit, resourceTypeEdit, resourceNameEdit,
                 resourceLanguageSpin, resourceFormatCombo, removeResourceCheck,
                 resourceDataEdit, clearSignatureCheck]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    QByteArray reparseBytes;
                    if (reparseAction->currentIndex() == 1)
                    {
                        bool reparseOk = false;
                        reparseBytes = parseMetadataHexText(reparseEdit->toPlainText(), &reparseOk);
                        if (!reparseOk || reparseBytes.size() < 8 ||
                            reparseBytes.size() > MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
                        {
                            QMessageBox::warning(this, QStringLiteral("重解析点"),
                                QStringLiteral("原始重解析缓冲必须是 8 到 16384 字节的有效十六进制。"));
                            return;
                        }
                    }
                    const bool kHasResourceInput =
                        !resourceTypeEdit->text().trimmed().isEmpty() &&
                        !resourceNameEdit->text().trimmed().isEmpty() &&
                        (removeResourceCheck->isChecked() || !resourceDataEdit->toPlainText().isEmpty());
                    QByteArray resourceBytes;
                    if (kHasResourceInput && !removeResourceCheck->isChecked())
                    {
                        bool resourceOk = false;
                        resourceBytes = metadataEditorBytes(
                            resourceDataEdit, resourceFormatCombo, &resourceOk);
                        if (!resourceOk)
                        {
                            QMessageBox::warning(this, QStringLiteral("PE 资源"),
                                QStringLiteral("资源十六进制格式无效。"));
                            return;
                        }
                    }
                    for (ks::file::metadata::TargetPatch& patch : pendingPatches_)
                    {
                        patch.reparse.update = reparseAction->currentIndex() != 0;
                        patch.reparse.remove = reparseAction->currentIndex() == 2;
                        patch.reparse.rawBuffer = reparseBytes;
                        patch.signatureDisposition = clearSignatureCheck->isChecked()
                            ? ks::file::metadata::SignatureDisposition::kRemoveEmbedded
                            : ks::file::metadata::SignatureDisposition::kPreserve;
                        if (kHasResourceInput)
                        {
                            ks::file::metadata::PeResourcePatch resource;
                            resource.type = resourceTypeEdit->text().trimmed();
                            resource.name = resourceNameEdit->text().trimmed();
                            resource.language = static_cast<WORD>(resourceLanguageSpin->value());
                            resource.action = removeResourceCheck->isChecked()
                                ? ks::file::metadata::BinaryPatchAction::kRemove
                                : ks::file::metadata::BinaryPatchAction::kReplace;
                            resource.data = resourceBytes;
                            patch.peResources.push_back(resource);
                        }
                    }
                    updatePendingSaveUi();
                });
            return page;
        }
}
