#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

bool MonitorDock::saveEtwFilterConfigToPath(const QString& filePath, const bool showErrorDialog) const
{
    return saveEtwFilterConfigModelToPath(
        captureEtwFilterConfigModel(), filePath, showErrorDialog);
}

bool MonitorDock::loadEtwFilterConfigFromPath(
    const QString& filePath,
    const bool showErrorDialog,
    const bool persistAsDefault)
{
    const QString kNormalizedPath = QFileInfo(filePath).absoluteFilePath();
    QFile inputFile(kNormalizedPath);
    if (!inputFile.exists())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("ETW筛选"), QStringLiteral("配置文件不存在：%1").arg(kNormalizedPath));
        }
        return false;
    }

    if (!inputFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("ETW筛选"), QStringLiteral("读取配置文件失败：%1").arg(kNormalizedPath));
        }
        return false;
    }

    const QByteArray kJsonData = inputFile.readAll();
    inputFile.close();
    EtwFilterConfigModel candidateModel;
    if (!tryParseEtwFilterConfigModel(kJsonData, candidateModel))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("ETW筛选"), QStringLiteral("配置文件格式无效：%1").arg(kNormalizedPath));
        }
        return false;
    }

    EtwFilterConfigCompiledModel compiledModel;
    QString compileErrorText;
    if (!tryCompileEtwFilterConfigModel(
            candidateModel,
            compiledModel,
            compileErrorText))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("ETW筛选器"), compileErrorText);
        }
        return false;
    }

    // On user import, atomically write the default configuration first. If persistence fails, do not touch the UI or runtime filters.
    if (persistAsDefault
        && !saveEtwFilterConfigModelToPath(
            candidateModel,
            etwFilterConfigPath(),
            showErrorDialog))
    {
        return false;
    }

    commitEtwFilterConfigModel(candidateModel, std::move(compiledModel));
    return true;
}

void MonitorDock::saveEtwFilterConfigToDefaultPath(const bool showDialog) const
{
    const QString kDefaultPath = etwFilterConfigPath();
    const bool kSaved = saveEtwFilterConfigToPath(kDefaultPath, showDialog);
    if (kSaved && showDialog)
    {
        QMessageBox::information(
            const_cast<MonitorDock*>(this),
            QStringLiteral("ETW筛选"),
            QStringLiteral("筛选配置已保存到：%1").arg(kDefaultPath));
    }
}

void MonitorDock::loadEtwFilterConfigFromDefaultPath(const bool showDialog)
{
    const QString kDefaultPath = etwFilterConfigPath();
    const bool kLoaded = loadEtwFilterConfigFromPath(kDefaultPath, showDialog, false);
    if (!kLoaded)
    {
        // If the default file is missing or invalid, compile only the current UI default values without writing back to overwrite the original file.
        const EtwFilterConfigModel kCurrentModel = captureEtwFilterConfigModel();
        EtwFilterConfigCompiledModel compiledModel;
        QString compileErrorText;
        if (tryCompileEtwFilterConfigModel(
                kCurrentModel,
                compiledModel,
                compileErrorText))
        {
            commitEtwFilterConfigModel(kCurrentModel, std::move(compiledModel));
        }
    }
}

void MonitorDock::importEtwFilterConfigFromUserSelectedPath()
{
    const QString kSelectedPath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("导入ETW筛选配置"),
        QFileInfo(etwFilterConfigPath()).absolutePath(),
        QStringLiteral("ETW Config (*.cfg *.json);;All Files (*.*)"));
    if (kSelectedPath.trimmed().isEmpty())
    {
        return;
    }

    if (loadEtwFilterConfigFromPath(kSelectedPath, true, true))
    {
        QMessageBox::information(
            this,
            QStringLiteral("ETW筛选"),
            QStringLiteral("已导入配置：%1").arg(QFileInfo(kSelectedPath).absoluteFilePath()));
    }
}

void MonitorDock::exportEtwFilterConfigToUserSelectedPath() const
{
    const QString kSelectedPath = QFileDialog::getSaveFileName(
        const_cast<MonitorDock*>(this),
        QStringLiteral("导出ETW筛选配置"),
        etwFilterConfigPath(),
        QStringLiteral("ETW Config (*.cfg);;JSON (*.json);;All Files (*.*)"));
    if (kSelectedPath.trimmed().isEmpty())
    {
        return;
    }

    if (saveEtwFilterConfigToPath(kSelectedPath, true))
    {
        QMessageBox::information(
            const_cast<MonitorDock*>(this),
            QStringLiteral("ETW筛选"),
            QStringLiteral("已导出配置：%1").arg(QFileInfo(kSelectedPath).absoluteFilePath()));
    }
}
