#include "StartupDock.Internal.h"

#include <QFile>
#include <QTextStream>

namespace startup_dock_detail
{
    namespace
    {
        // loadRegistryLocationCatalog:
        // - Read the raw list of Autoruns-style registry locations from Qt resources;
        // - Non-UI standardization, correction, and deduplication logic has been migrated to ks::startup.
        // - Return: QStringList preserving resource order for creating grouped nodes in the registry tree.
        QStringList loadRegistryLocationCatalog()
        {
            std::vector<std::string> rawLineList;
            QFile catalogFile(QStringLiteral(":/Data/startup_registry_locations.txt"));
            if (!catalogFile.open(QIODevice::ReadOnly | QIODevice::Text))
            {
                return QStringList();
            }

            QTextStream catalogStream(&catalogFile);
            catalogStream.setEncoding(QStringConverter::Utf8);
            while (!catalogStream.atEnd())
            {
                const QString kRawLineText = catalogStream.readLine();
                const QByteArray kRawLineBytes = kRawLineText.toUtf8();
                rawLineList.emplace_back(kRawLineBytes.constData(), static_cast<std::size_t>(kRawLineBytes.size()));
            }

            QStringList locationList;
            const std::vector<std::string> kNormalizedList =
                ks::startup::buildKnownStartupRegistryLocationList(rawLineList);
            for (const std::string& locationText : kNormalizedList)
            {
                locationList.push_back(QString::fromUtf8(locationText.c_str(), static_cast<int>(locationText.size())));
            }
            return locationList;
        }
    }

    QStringList buildKnownStartupRegistryLocationList()
    {
        // Static caching remains at the UI layer to prevent re-reading Qt resources from the registry tree on every refresh.
        static const QStringList kCachedLocationList = loadRegistryLocationCatalog();
        return kCachedLocationList;
    }
}
