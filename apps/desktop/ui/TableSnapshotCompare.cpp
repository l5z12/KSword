#include "TableSnapshotCompare.h"

#include "../internationalization/LanguageManager.h"
#include "../Theme.h"
#include "TableFreezeSupport.h"

#include <QAbstractItemModel>
#include <QBitArray>
#include <QByteArray>
#include <QByteArrayView>
#include <QColor>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QEventLoop>
#include <QHash>
#include <QHeaderView>
#include <QMetaType>
#include <QObject>
#include <QPointer>
#include <QRegularExpression>
#include <QTableView>
#include <QThread>
#include <QVariant>

#include <algorithm>
#include <limits>

namespace
{
    constexpr char kSnapshotKeyColumnsProperty[] = "kswordSnapshotKeyColumns";

    quint64 saturatingAdd(const quint64 left, const quint64 right)
    {
        return right > std::numeric_limits<quint64>::max() - left
            ? std::numeric_limits<quint64>::max()
            : left + right;
    }

    quint64 estimatedTextStorageBytes(const QString& text)
    {
        const quint64 kCharacterCount = static_cast<quint64>(std::max<qsizetype>(0, text.size()));
        return kCharacterCount > std::numeric_limits<quint64>::max() / sizeof(QChar)
            ? std::numeric_limits<quint64>::max()
            : kCharacterCount * sizeof(QChar);
    }

    quint64 estimatedColumnStorageBytes(const ks::ui::TableSnapshotColumn& column)
    {
        return saturatingAdd(
            sizeof(ks::ui::TableSnapshotColumn),
            estimatedTextStorageBytes(column.headerText));
    }

    quint64 estimatedRowStorageBytes(const ks::ui::TableSnapshotRow& row)
    {
        quint64 bytes = saturatingAdd(
            sizeof(ks::ui::TableSnapshotRow),
            static_cast<quint64>(row.values.size()) * sizeof(QString));
        for (const QString& value : row.values)
        {
            bytes = saturatingAdd(bytes, estimatedTextStorageBytes(value));
        }
        return bytes;
    }

    quint64 estimatedSnapshotStorageBytes(const ks::ui::TableSnapshot& snapshot)
    {
        quint64 bytes = saturatingAdd(
            sizeof(ks::ui::TableSnapshot),
            estimatedTextStorageBytes(snapshot.label));
        for (const ks::ui::TableSnapshotColumn& column : snapshot.visibleColumns)
        {
            bytes = saturatingAdd(bytes, estimatedColumnStorageBytes(column));
        }
        for (const ks::ui::TableSnapshotRow& row : snapshot.rows)
        {
            bytes = saturatingAdd(bytes, estimatedRowStorageBytes(row));
        }
        return saturatingAdd(
            bytes,
            static_cast<quint64>(snapshot.keyColumns.size()) * sizeof(int));
    }

    bool canRetainEstimatedBytes(
        const quint64 currentBytes,
        const quint64 additionalBytes,
        const quint64 byteLimit)
    {
        return currentBytes <= byteLimit && additionalBytes <= byteLimit - currentBytes;
    }

    struct BoundedDisplayText
    {
        QString text;
        bool truncated = false;
        bool supported = true;
    };

    BoundedDisplayText boundedDisplayText(const QVariant& value, const int maximumCharacters)
    {
        BoundedDisplayText result;
        if (!value.isValid() || value.isNull())
        {
            return result;
        }

        const int kSafeMaximumCharacters = std::max(0, maximumCharacters);
        switch (value.metaType().id())
        {
        case QMetaType::QString:
        {
            const QString kSourceText = value.value<QString>();
            const qsizetype kRetainedCharacters = std::min(
                kSourceText.size(),
                static_cast<qsizetype>(kSafeMaximumCharacters));
            result.text = QString(kSourceText.constData(), kRetainedCharacters);
            result.truncated = kRetainedCharacters < kSourceText.size();
            break;
        }
        case QMetaType::QByteArray:
        {
            const QByteArray kBytes = value.value<QByteArray>();
            const qsizetype kMaximumInputBytes = static_cast<qsizetype>(
                std::min<quint64>(
                    static_cast<quint64>(kSafeMaximumCharacters) * 4ULL + 4ULL,
                    static_cast<quint64>(std::numeric_limits<qsizetype>::max())));
            const qsizetype kBytesToDecode = std::min(kBytes.size(), kMaximumInputBytes);
            result.text = QString::fromUtf8(kBytes.constData(), kBytesToDecode);
            result.truncated = kBytesToDecode < kBytes.size();
            break;
        }
        case QMetaType::Bool:
        case QMetaType::Int:
        case QMetaType::UInt:
        case QMetaType::LongLong:
        case QMetaType::ULongLong:
        case QMetaType::Double:
        case QMetaType::QChar:
        case QMetaType::QDate:
        case QMetaType::QTime:
        case QMetaType::QDateTime:
        case QMetaType::QUuid:
        case QMetaType::Long:
        case QMetaType::Short:
        case QMetaType::Char:
        case QMetaType::ULong:
        case QMetaType::UShort:
        case QMetaType::UChar:
        case QMetaType::Float:
        case QMetaType::SChar:
            result.text = value.toString();
            break;
        default:
            result.supported = false;
            return result;
        }

        if (result.text.size() > kSafeMaximumCharacters)
        {
            result.text.truncate(kSafeMaximumCharacters);
            result.truncated = true;
        }
        // Never retain a model-owned implicit-sharing allocation whose capacity can
        // be much larger than the bounded logical value accounted above.
        result.text.squeeze();
        return result;
    }

    void recordBoundedDisplayValue(
        ks::ui::TableSnapshot& snapshot,
        const BoundedDisplayText& value,
        const bool headerValue)
    {
        if (!value.supported)
        {
            snapshot.truncatedByValueLimit = true;
            ++snapshot.unsupportedDisplayValueCount;
            return;
        }
        if (!value.truncated)
        {
            return;
        }

        snapshot.truncatedByValueLimit = true;
        if (headerValue)
        {
            ++snapshot.truncatedHeaderValueCount;
        }
        else
        {
            ++snapshot.truncatedCellValueCount;
        }
    }

    struct HeaderCaptureState
    {
        QVector<int> logicalIndexes;
        QVector<int> sectionSizes;
        QBitArray hiddenSections;
        int sectionCount = 0;
        int sortSection = -1;
        Qt::SortOrder sortOrder = Qt::AscendingOrder;
        bool headerHidden = false;
    };

    HeaderCaptureState captureHeaderState(QHeaderView* header, const int visualSectionsToTrack)
    {
        HeaderCaptureState state;
        if (header == nullptr)
        {
            return state;
        }

        state.sectionCount = header->count();
        state.sortSection = header->sortIndicatorSection();
        state.sortOrder = header->sortIndicatorOrder();
        state.headerHidden = header->isHidden();
        const int kSectionCount = std::min(
            std::max(0, visualSectionsToTrack),
            std::max(0, header->count()));
        state.logicalIndexes.reserve(kSectionCount);
        state.sectionSizes.reserve(kSectionCount);
        state.hiddenSections.resize(kSectionCount);
        for (int visualIndex = 0; visualIndex < kSectionCount; ++visualIndex)
        {
            const int kLogicalIndex = header->logicalIndex(visualIndex);
            state.logicalIndexes.push_back(kLogicalIndex);
            state.sectionSizes.push_back(
                kLogicalIndex >= 0 ? header->sectionSize(kLogicalIndex) : -1);
            state.hiddenSections.setBit(
                visualIndex,
                kLogicalIndex >= 0 && header->isSectionHidden(kLogicalIndex));
        }
        return state;
    }

    bool headerStateMatches(QHeaderView* header, const HeaderCaptureState& expected)
    {
        if (header == nullptr ||
            header->count() != expected.sectionCount ||
            header->sortIndicatorSection() != expected.sortSection ||
            header->sortIndicatorOrder() != expected.sortOrder ||
            header->isHidden() != expected.headerHidden ||
            expected.logicalIndexes.size() != expected.sectionSizes.size() ||
            expected.logicalIndexes.size() != expected.hiddenSections.size())
        {
            return false;
        }

        for (int visualIndex = 0; visualIndex < expected.logicalIndexes.size(); ++visualIndex)
        {
            const int kLogicalIndex = expected.logicalIndexes.at(visualIndex);
            if (header->logicalIndex(visualIndex) != kLogicalIndex ||
                kLogicalIndex < 0 ||
                header->sectionSize(kLogicalIndex) != expected.sectionSizes.at(visualIndex) ||
                header->isSectionHidden(kLogicalIndex) != expected.hiddenSections.testBit(visualIndex))
            {
                return false;
            }
        }
        return true;
    }

    void discardInvalidatedSnapshot(ks::ui::TableSnapshot& snapshot)
    {
        snapshot.sourceInvalidated = true;
        snapshot.visibleColumns.clear();
        snapshot.rows.clear();
        snapshot.keyColumns.clear();
        snapshot.estimatedBytes = estimatedSnapshotStorageBytes(snapshot);
    }

    struct SnapshotColumnLookup
    {
        explicit SnapshotColumnLookup(const ks::ui::TableSnapshot& snapshot)
        {
            valueIndexBySourceColumn.reserve(snapshot.visibleColumns.size());
            for (int valueIndex = 0; valueIndex < snapshot.visibleColumns.size(); ++valueIndex)
            {
                const int kSourceColumn = snapshot.visibleColumns.at(valueIndex).sourceColumn;
                if (kSourceColumn >= 0 && !valueIndexBySourceColumn.contains(kSourceColumn))
                {
                    valueIndexBySourceColumn.insert(kSourceColumn, valueIndex);
                }
            }
        }

        int valueIndex(const int sourceColumn) const
        {
            const auto kIterator = valueIndexBySourceColumn.constFind(sourceColumn);
            return kIterator == valueIndexBySourceColumn.cend() ? -1 : kIterator.value();
        }

        QHash<int, int> valueIndexBySourceColumn;
    };

    const QString& valueForSourceColumn(
        const ks::ui::TableSnapshotRow& row,
        const SnapshotColumnLookup& lookup,
        const int sourceColumn)
    {
        static const QString kEmptyValue;
        const int kValueIndex = lookup.valueIndex(sourceColumn);
        return kValueIndex >= 0 && kValueIndex < row.values.size()
            ? row.values.at(kValueIndex)
            : kEmptyValue;
    }

    QVector<int> valueIndexesForColumns(
        const SnapshotColumnLookup& lookup,
        const QVector<ks::ui::TableSnapshotColumn>& columns)
    {
        QVector<int> indexes;
        indexes.reserve(columns.size());
        for (const ks::ui::TableSnapshotColumn& column : columns)
        {
            indexes.push_back(lookup.valueIndex(column.sourceColumn));
        }
        return indexes;
    }

    QVector<ks::ui::TableSnapshotColumn> combinedColumns(
        const ks::ui::TableSnapshot& earlier,
        const ks::ui::TableSnapshot& later)
    {
        QVector<ks::ui::TableSnapshotColumn> columns;
        QSet<int> seenColumns;
        const auto kAppendMissingColumns = [&columns, &seenColumns](const QVector<ks::ui::TableSnapshotColumn>& source)
            {
                for (const ks::ui::TableSnapshotColumn& column : source)
                {
                    if (column.sourceColumn >= 0 && !seenColumns.contains(column.sourceColumn))
                    {
                        columns.push_back(column);
                        seenColumns.insert(column.sourceColumn);
                    }
                }
            };
        kAppendMissingColumns(earlier.visibleColumns);
        kAppendMissingColumns(later.visibleColumns);
        return columns;
    }

    struct ComparisonWorkState
    {
        const ks::ui::TableSnapshotComparisonLimits& limits;
        const std::function<bool()>& shouldCancel;
        ks::ui::TableComparisonResult& result;
        quint64 temporaryEstimatedBytes = 0;
        quint64 processedRows = 0;

        bool consumeWork(const quint64 units = 1)
        {
            const quint64 kUpdated = saturatingAdd(result.workUnits, units);
            if (kUpdated > limits.maximumWorkUnits)
            {
                result.truncatedByWorkLimit = true;
                return false;
            }
            result.workUnits = kUpdated;
            return true;
        }

        bool reserveTemporary(const quint64 bytes)
        {
            const quint64 kUpdated = saturatingAdd(temporaryEstimatedBytes, bytes);
            if (kUpdated > limits.maximumTemporaryEstimatedBytes)
            {
                result.truncatedByTemporaryByteLimit = true;
                return false;
            }
            temporaryEstimatedBytes = kUpdated;
            result.temporaryPeakEstimatedBytes = std::max(
                result.temporaryPeakEstimatedBytes,
                temporaryEstimatedBytes);
            return true;
        }

        bool checkpointAfterRow()
        {
            ++processedRows;
            const int kYieldRows = std::max(1, limits.eventLoopYieldRows);
            if (processedRows % static_cast<quint64>(kYieldRows) != 0)
            {
                return true;
            }
            if (QCoreApplication::instance() != nullptr)
            {
                QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 5);
            }
            if (shouldCancel && shouldCancel())
            {
                result.cancelled = true;
                return false;
            }
            return true;
        }

        bool canContinue() const
        {
            return !result.isTruncated();
        }
    };

    void addHashInteger(QCryptographicHash& hash, const qint64 value)
    {
        hash.addData(
            QByteArrayView(
                reinterpret_cast<const char*>(&value),
                static_cast<qsizetype>(sizeof(value))));
    }

    bool isBlankKeyValue(const QString& value)
    {
        for (const QChar kCharacter : value)
        {
            if (!kCharacter.isSpace())
            {
                return false;
            }
        }
        return true;
    }

    QByteArray rowHash(
        const ks::ui::TableSnapshotRow& row,
        const SnapshotColumnLookup& lookup,
        const QVector<ks::ui::TableSnapshotColumn>& columns,
        const QSet<int>& ignoredColumns,
        ComparisonWorkState& work)
    {
        QCryptographicHash hash(QCryptographicHash::Sha256);
        for (const ks::ui::TableSnapshotColumn& column : columns)
        {
            if (ignoredColumns.contains(column.sourceColumn))
            {
                continue;
            }
            if (!work.consumeWork())
            {
                return {};
            }
            const QString& value = valueForSourceColumn(row, lookup, column.sourceColumn);
            addHashInteger(hash, column.sourceColumn);
            addHashInteger(hash, value.size());
            hash.addData(
                QByteArrayView(
                    reinterpret_cast<const char*>(value.constData()),
                    value.size() * static_cast<qsizetype>(sizeof(QChar))));
        }
        return hash.result();
    }

    QByteArray rowKeyHash(
        const ks::ui::TableSnapshotRow& row,
        const SnapshotColumnLookup& lookup,
        const QVector<int>& keyColumns,
        ComparisonWorkState& work)
    {
        QCryptographicHash hash(QCryptographicHash::Sha256);
        for (const int kSourceColumn : keyColumns)
        {
            if (!work.consumeWork())
            {
                return {};
            }
            const QString& value = valueForSourceColumn(row, lookup, kSourceColumn);
            if (isBlankKeyValue(value))
            {
                return {};
            }
            addHashInteger(hash, kSourceColumn);
            addHashInteger(hash, value.size());
            hash.addData(
                QByteArrayView(
                    reinterpret_cast<const char*>(value.constData()),
                    value.size() * static_cast<qsizetype>(sizeof(QChar))));
        }
        return hash.result();
    }

    QVector<int> usableStableKeyColumns(
        const ks::ui::TableSnapshot& earlier,
        const ks::ui::TableSnapshot& later,
        const SnapshotColumnLookup& earlierLookup,
        const SnapshotColumnLookup& laterLookup,
        const QVector<int>& requestedKeyColumns,
        const QSet<int>& ignoredColumns)
    {
        QVector<int> keyColumns;
        const QVector<int>& candidates = requestedKeyColumns.isEmpty()
            ? earlier.keyColumns
            : requestedKeyColumns;
        for (const int kSourceColumn : candidates)
        {
            if (!ignoredColumns.contains(kSourceColumn) &&
                (requestedKeyColumns.isEmpty() ? later.keyColumns.contains(kSourceColumn) : true) &&
                earlierLookup.valueIndex(kSourceColumn) >= 0 &&
                laterLookup.valueIndex(kSourceColumn) >= 0)
            {
                keyColumns.push_back(kSourceColumn);
            }
        }
        return keyColumns;
    }

    bool buildUniqueRowKeys(
        const ks::ui::TableSnapshot& snapshot,
        const SnapshotColumnLookup& lookup,
        const QVector<int>& keyColumns,
        QHash<QByteArray, int>& rowByKey,
        ComparisonWorkState& work)
    {
        rowByKey.clear();
        if (!work.reserveTemporary(
                static_cast<quint64>(snapshot.rows.size()) * (sizeof(int) + 96ULL)))
        {
            return false;
        }
        rowByKey.reserve(snapshot.rows.size());
        for (int rowIndex = 0; rowIndex < snapshot.rows.size(); ++rowIndex)
        {
            const QByteArray kKey = rowKeyHash(snapshot.rows.at(rowIndex), lookup, keyColumns, work);
            if (!work.canContinue())
            {
                return false;
            }
            if (kKey.isEmpty() || rowByKey.contains(kKey))
            {
                rowByKey.clear();
                return false;
            }
            rowByKey.insert(kKey, rowIndex);
            if (!work.checkpointAfterRow())
            {
                return false;
            }
        }
        return true;
    }

    quint64 logicalSnapshotBytes(const ks::ui::TableSnapshot& snapshot)
    {
        return std::max(
            snapshot.estimatedBytes,
            estimatedSnapshotStorageBytes(snapshot));
    }

    bool appendComparisonRow(
        ks::ui::TableComparisonResult& result,
        const ks::ui::TableSnapshotComparisonLimits& limits,
        const ks::ui::TableComparisonSource source,
        const int earlierRowIndex,
        const int laterRowIndex,
        const bool displayLater,
        QSet<int> changedSourceColumns = QSet<int>())
    {
        quint64 rowBytes = sizeof(ks::ui::TableComparisonRow);
        rowBytes = saturatingAdd(
            rowBytes,
            static_cast<quint64>(changedSourceColumns.size()) * 64ULL);
        if (!canRetainEstimatedBytes(
                result.estimatedBytes,
                rowBytes,
                limits.maximumEstimatedBytes))
        {
            result.truncatedByResultByteLimit = true;
            return false;
        }

        ks::ui::TableComparisonRow row;
        row.source = source;
        row.earlierRowIndex = earlierRowIndex;
        row.laterRowIndex = laterRowIndex;
        row.displayLater = displayLater;
        row.changedSourceColumns = std::move(changedSourceColumns);
        result.rows.push_back(std::move(row));
        result.estimatedBytes += rowBytes;
        return true;
    }

    bool headerMatchesKeyword(const QString& header, const QString& keyword)
    {
        const QString kTrimmedKeyword = keyword.trimmed();
        return !kTrimmedKeyword.isEmpty() &&
            header.contains(kTrimmedKeyword, Qt::CaseInsensitive);
    }

    QVector<int> declaredKeyColumns(
        QTableView* tableView,
        const ks::ui::TableSnapshot& snapshot,
        const int maximumEntries,
        const int maximumEntryCharacters)
    {
        QVector<int> result;
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return result;
        }

        const QVariant kRawProperty = tableView->property(kSnapshotKeyColumnsProperty);
        if (!kRawProperty.isValid() || kRawProperty.isNull())
        {
            return result;
        }

        QVariantList entryList;
        if (kRawProperty.metaType().id() == QMetaType::QVariantList)
        {
            const QVariantList kSourceEntries = kRawProperty.toList();
            const int kEntryCount = std::min(
                std::max(0, maximumEntries),
                static_cast<int>(kSourceEntries.size()));
            entryList.reserve(kEntryCount);
            for (int index = 0; index < kEntryCount; ++index)
            {
                entryList.push_back(kSourceEntries.at(index));
            }
        }
        else if (kRawProperty.metaType().id() == QMetaType::QStringList)
        {
            const QStringList kStringList = kRawProperty.toStringList();
            const int kEntryCount = std::min(
                std::max(0, maximumEntries),
                static_cast<int>(kStringList.size()));
            entryList.reserve(kEntryCount);
            for (int index = 0; index < kEntryCount; ++index)
            {
                entryList.push_back(kStringList.at(index));
            }
        }
        else
        {
            const BoundedDisplayText kPropertyText = boundedDisplayText(
                kRawProperty,
                std::max(0, maximumEntries) * std::max(0, maximumEntryCharacters));
            const QString& text = kPropertyText.text;
            const QStringList kStringList = text.split(
                QRegularExpression(QStringLiteral("[,;|]")),
                Qt::SkipEmptyParts);
            const int kEntryCount = std::min(
                std::max(0, maximumEntries),
                static_cast<int>(kStringList.size()));
            entryList.reserve(kEntryCount);
            for (int index = 0; index < kEntryCount; ++index)
            {
                entryList.push_back(kStringList.at(index));
            }
        }

        const QAbstractItemModel* model = tableView->model();
        for (const QVariant& entry : entryList)
        {
            bool numericColumn = false;
            const int kSourceColumn = entry.toInt(&numericColumn);
            if (numericColumn && kSourceColumn >= 0 && kSourceColumn < model->columnCount())
            {
                if (!result.contains(kSourceColumn))
                {
                    result.push_back(kSourceColumn);
                }
                continue;
            }

            const BoundedDisplayText kBoundedEntry = boundedDisplayText(
                entry,
                maximumEntryCharacters);
            const QString kHeaderName = kBoundedEntry.text.trimmed();
            if (kHeaderName.isEmpty())
            {
                continue;
            }
            for (const ks::ui::TableSnapshotColumn& column : snapshot.visibleColumns)
            {
                if (column.headerText.compare(kHeaderName, Qt::CaseInsensitive) == 0 &&
                    !result.contains(column.sourceColumn))
                {
                    result.push_back(column.sourceColumn);
                    break;
                }
            }
        }
        return result;
    }

    QColor earlierOnlyColor()
    {
        return ksword_theme::withAlpha(ksword_theme::errorColor(), 96);
    }

    QColor laterOnlyColor()
    {
        return ksword_theme::withAlpha(ksword_theme::successColor(), 96);
    }

    QColor changedFieldColor()
    {
        return ksword_theme::withAlpha(ksword_theme::warningColor(), 96);
    }
}

namespace ks::ui
{
    TableSnapshot TableSnapshotCompareEngine::capture(
        QTableView* tableView,
        const QString& label,
        const quint64 sequence,
        const TableSnapshotCaptureLimits& limits)
    {
        TableSnapshot snapshot;
        snapshot.label = label;
        snapshot.capturedAt = QDateTime::currentDateTime();
        snapshot.sequence = sequence;
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return snapshot;
        }

        QAbstractItemModel* model = tableView->model();
        snapshot.estimatedBytes = estimatedSnapshotStorageBytes(snapshot);
        if (QThread::currentThread() != tableView->thread() ||
            QThread::currentThread() != model->thread())
        {
            snapshot.sourceInvalidated = true;
            return snapshot;
        }

        const int kMaximumRows = std::max(0, limits.maximumRows);
        const int kMaximumColumns = std::max(0, limits.maximumColumns);
        const int kMaximumCellCharacters = std::max(0, limits.maximumCellCharacters);
        const int kMaximumHeaderCharacters = std::max(0, limits.maximumHeaderCharacters);
        const int kEventLoopYieldRows = std::max(1, limits.eventLoopYieldRows);
        const quint64 kMaximumEstimatedBytes = std::max(
            limits.maximumEstimatedBytes,
            snapshot.estimatedBytes);
        QPointer<QTableView> tableGuard(tableView);
        QPointer<QAbstractItemModel> modelGuard(model);
        QPointer<QHeaderView> horizontalHeader(tableView->horizontalHeader());
        QPointer<QHeaderView> verticalHeader(tableView->verticalHeader());

        QObject epochObserver;
        quint64 sourceEpoch = 0;
        const auto kMarkSourceChanged = [&sourceEpoch]()
            {
                ++sourceEpoch;
            };
        const auto kObserveModelSignal = [&](auto signal)
            {
                QObject::connect(model, signal, &epochObserver, kMarkSourceChanged);
            };
        kObserveModelSignal(&QAbstractItemModel::dataChanged);
        kObserveModelSignal(&QAbstractItemModel::headerDataChanged);
        kObserveModelSignal(&QAbstractItemModel::layoutAboutToBeChanged);
        kObserveModelSignal(&QAbstractItemModel::layoutChanged);
        kObserveModelSignal(&QAbstractItemModel::modelAboutToBeReset);
        kObserveModelSignal(&QAbstractItemModel::modelReset);
        kObserveModelSignal(&QAbstractItemModel::rowsAboutToBeInserted);
        kObserveModelSignal(&QAbstractItemModel::rowsInserted);
        kObserveModelSignal(&QAbstractItemModel::rowsAboutToBeRemoved);
        kObserveModelSignal(&QAbstractItemModel::rowsRemoved);
        kObserveModelSignal(&QAbstractItemModel::rowsAboutToBeMoved);
        kObserveModelSignal(&QAbstractItemModel::rowsMoved);
        kObserveModelSignal(&QAbstractItemModel::columnsAboutToBeInserted);
        kObserveModelSignal(&QAbstractItemModel::columnsInserted);
        kObserveModelSignal(&QAbstractItemModel::columnsAboutToBeRemoved);
        kObserveModelSignal(&QAbstractItemModel::columnsRemoved);
        kObserveModelSignal(&QAbstractItemModel::columnsAboutToBeMoved);
        kObserveModelSignal(&QAbstractItemModel::columnsMoved);
        QObject::connect(model, &QObject::destroyed, &epochObserver, kMarkSourceChanged);
        QObject::connect(tableView, &QObject::destroyed, &epochObserver, kMarkSourceChanged);

        const auto kObserveHeader = [&](QHeaderView* header)
            {
                if (header == nullptr)
                {
                    return;
                }
                QObject::connect(header, &QHeaderView::geometriesChanged, &epochObserver, kMarkSourceChanged);
                QObject::connect(header, &QHeaderView::sectionMoved, &epochObserver, kMarkSourceChanged);
                QObject::connect(header, &QHeaderView::sectionResized, &epochObserver, kMarkSourceChanged);
                QObject::connect(header, &QHeaderView::sectionCountChanged, &epochObserver, kMarkSourceChanged);
                QObject::connect(header, &QHeaderView::sortIndicatorChanged, &epochObserver, kMarkSourceChanged);
                QObject::connect(header, &QObject::destroyed, &epochObserver, kMarkSourceChanged);
            };
        kObserveHeader(horizontalHeader.data());
        kObserveHeader(verticalHeader.data());

        const int kColumnCount = model->columnCount();
        const int kRowCount = model->rowCount();
        snapshot.sourceColumnCount = kColumnCount;
        snapshot.sourceRowCount = kRowCount;
        const int kColumnsToVisit = std::min(kColumnCount, kMaximumColumns);
        const int kRowsToVisit = std::min(kRowCount, kMaximumRows);
        const HeaderCaptureState kHorizontalState =
            captureHeaderState(horizontalHeader.data(), kColumnsToVisit);
        const HeaderCaptureState kVerticalState =
            captureHeaderState(verticalHeader.data(), kRowsToVisit);
        const quint64 kCaptureEpoch = sourceEpoch;

        const auto kSourceIdentityIsStable = [&]()
            {
                return sourceEpoch == kCaptureEpoch &&
                    !tableGuard.isNull() &&
                    !modelGuard.isNull() &&
                    tableGuard->model() == modelGuard.data() &&
                    tableGuard->horizontalHeader() == horizontalHeader.data() &&
                    tableGuard->verticalHeader() == verticalHeader.data() &&
                    modelGuard->rowCount() == kRowCount &&
                    modelGuard->columnCount() == kColumnCount;
            };
        const auto kSourceStateIsStable = [&]()
            {
                return kSourceIdentityIsStable() &&
                    headerStateMatches(horizontalHeader.data(), kHorizontalState) &&
                    headerStateMatches(verticalHeader.data(), kVerticalState);
            };

        if (!kSourceStateIsStable())
        {
            discardInvalidatedSnapshot(snapshot);
            return snapshot;
        }

        for (int visualColumn = 0; visualColumn < kColumnsToVisit; ++visualColumn)
        {
            ++snapshot.visitedSourceColumns;
            const int kSourceColumn = visualColumn < kHorizontalState.logicalIndexes.size()
                ? kHorizontalState.logicalIndexes.at(visualColumn)
                : visualColumn;
            // Frozen columns are also 'hidden' in the source table, but these are user-pinned columns that must
            // remain in the snapshot; otherwise, the comparison baseline during freezing will lose columns.
            if (kSourceColumn < 0 ||
                kSourceColumn >= kColumnCount ||
                (visualColumn < kHorizontalState.hiddenSections.size() &&
                    kHorizontalState.hiddenSections.testBit(visualColumn) &&
                    !isColumnHiddenByFreeze(tableView, kSourceColumn)))
            {
                continue;
            }

            const BoundedDisplayText kHeaderText = boundedDisplayText(
                modelGuard->headerData(kSourceColumn, Qt::Horizontal, Qt::DisplayRole),
                kMaximumHeaderCharacters);
            recordBoundedDisplayValue(snapshot, kHeaderText, true);
            if (!kSourceIdentityIsStable())
            {
                discardInvalidatedSnapshot(snapshot);
                return snapshot;
            }
            TableSnapshotColumn column{ kSourceColumn, kHeaderText.text };
            const quint64 kColumnBytes = estimatedColumnStorageBytes(column);
            if (!canRetainEstimatedBytes(
                    snapshot.estimatedBytes,
                    kColumnBytes,
                    kMaximumEstimatedBytes))
            {
                snapshot.truncatedByByteLimit = true;
                break;
            }
            snapshot.visibleColumns.push_back(std::move(column));
            snapshot.estimatedBytes += kColumnBytes;
        }
        if (!snapshot.truncatedByByteLimit && kColumnsToVisit < kColumnCount)
        {
            snapshot.truncatedByColumnLimit = true;
        }

        for (int visualRow = 0;
             visualRow < kRowsToVisit && !snapshot.truncatedByByteLimit;
             ++visualRow)
        {
            if (visualRow > 0 && visualRow % kEventLoopYieldRows == 0)
            {
                if (QCoreApplication::instance() != nullptr)
                {
                    QCoreApplication::processEvents(
                        QEventLoop::ExcludeUserInputEvents,
                        5);
                }
                if (!kSourceStateIsStable())
                {
                    discardInvalidatedSnapshot(snapshot);
                    break;
                }
            }

            ++snapshot.visitedSourceRows;
            const int kSourceRow = visualRow < kVerticalState.logicalIndexes.size()
                ? kVerticalState.logicalIndexes.at(visualRow)
                : visualRow;
            // Same as above: frozen rows are pinned evidence rows and must not be omitted from the snapshot just because the source table is hidden.
            if (kSourceRow < 0 ||
                kSourceRow >= kRowCount ||
                (visualRow < kVerticalState.hiddenSections.size() &&
                    kVerticalState.hiddenSections.testBit(visualRow) &&
                    !isRowHiddenByFreeze(tableView, kSourceRow)))
            {
                continue;
            }

            TableSnapshotRow row;
            row.sourceRow = kSourceRow;
            row.values.reserve(snapshot.visibleColumns.size());
            quint64 rowBytes = saturatingAdd(
                sizeof(TableSnapshotRow),
                static_cast<quint64>(snapshot.visibleColumns.size()) * sizeof(QString));
            if (!canRetainEstimatedBytes(
                    snapshot.estimatedBytes,
                    rowBytes,
                    kMaximumEstimatedBytes))
            {
                snapshot.truncatedByByteLimit = true;
                break;
            }

            for (const TableSnapshotColumn& column : snapshot.visibleColumns)
            {
                const BoundedDisplayText kValue = boundedDisplayText(
                    modelGuard->data(
                        modelGuard->index(kSourceRow, column.sourceColumn),
                        Qt::DisplayRole),
                    kMaximumCellCharacters);
                recordBoundedDisplayValue(snapshot, kValue, false);
                if (!kSourceIdentityIsStable())
                {
                    discardInvalidatedSnapshot(snapshot);
                    break;
                }
                rowBytes = saturatingAdd(rowBytes, estimatedTextStorageBytes(kValue.text));
                if (!canRetainEstimatedBytes(
                        snapshot.estimatedBytes,
                        rowBytes,
                        kMaximumEstimatedBytes))
                {
                    snapshot.truncatedByByteLimit = true;
                    break;
                }
                row.values.push_back(kValue.text);
            }
            if (snapshot.truncatedByByteLimit || snapshot.sourceInvalidated)
            {
                break;
            }
            snapshot.rows.push_back(std::move(row));
            snapshot.estimatedBytes += rowBytes;
        }

        if (!snapshot.truncatedByByteLimit &&
            !snapshot.sourceInvalidated &&
            kRowsToVisit < kRowCount)
        {
            snapshot.truncatedByRowLimit = true;
        }
        if (horizontalHeader != nullptr)
        {
            snapshot.sortColumn = kHorizontalState.sortSection;
            snapshot.sortOrder = kHorizontalState.sortOrder;
        }
        if (!snapshot.sourceInvalidated && !kSourceStateIsStable())
        {
            discardInvalidatedSnapshot(snapshot);
        }
        if (!tableGuard.isNull() && !snapshot.sourceInvalidated)
        {
            const QVector<int> kKeyColumns = declaredKeyColumns(
                tableGuard.data(),
                snapshot,
                kMaximumColumns,
                kMaximumHeaderCharacters);
            if (!kSourceStateIsStable())
            {
                discardInvalidatedSnapshot(snapshot);
                return snapshot;
            }
            const quint64 kKeyColumnBytes =
                static_cast<quint64>(kKeyColumns.size()) * sizeof(int);
            if (canRetainEstimatedBytes(
                    snapshot.estimatedBytes,
                    kKeyColumnBytes,
                    kMaximumEstimatedBytes))
            {
                snapshot.keyColumns = kKeyColumns;
                snapshot.estimatedBytes += kKeyColumnBytes;
            }
            else
            {
                snapshot.truncatedByByteLimit = true;
            }
        }
        snapshot.visibleColumns.squeeze();
        snapshot.rows.squeeze();
        snapshot.keyColumns.squeeze();
        snapshot.estimatedBytes = estimatedSnapshotStorageBytes(snapshot);
        return snapshot;
    }

    quint64 TableSnapshotCompareEngine::totalEstimatedBytes(
        const QVector<TableSnapshot>& snapshots)
    {
        quint64 totalBytes = 0;
        for (const TableSnapshot& snapshot : snapshots)
        {
            totalBytes = saturatingAdd(
                totalBytes,
                snapshot.estimatedBytes != 0
                    ? snapshot.estimatedBytes
                    : estimatedSnapshotStorageBytes(snapshot));
        }
        return totalBytes;
    }

    TableSnapshotRetentionResult TableSnapshotCompareEngine::enforceRetentionLimits(
        QVector<TableSnapshot>& snapshots,
        const TableSnapshotRetentionLimits& limits)
    {
        for (TableSnapshot& snapshot : snapshots)
        {
            if (snapshot.estimatedBytes == 0)
            {
                snapshot.estimatedBytes = estimatedSnapshotStorageBytes(snapshot);
            }
        }

        TableSnapshotRetentionResult result;
        result.remainingEstimatedBytes = totalEstimatedBytes(snapshots);
        const int kMaximumSnapshots = std::max(0, limits.maximumSnapshots);
        while (!snapshots.isEmpty() &&
               (snapshots.size() > kMaximumSnapshots ||
                result.remainingEstimatedBytes > limits.maximumEstimatedBytes))
        {
            const TableSnapshot& oldestSnapshot = snapshots.front();
            result.evictedLabels.push_back(oldestSnapshot.label);
            result.remainingEstimatedBytes =
                oldestSnapshot.estimatedBytes >= result.remainingEstimatedBytes
                ? 0
                : result.remainingEstimatedBytes - oldestSnapshot.estimatedBytes;
            snapshots.erase(snapshots.begin());
        }
        return result;
    }

    QStringList TableSnapshotCompareEngine::defaultIgnoredColumnKeywords()
    {
        return {
            QStringLiteral("序号"),
            QStringLiteral("行号"),
            QStringLiteral("时间"),
            QStringLiteral("日期"),
            QStringLiteral("Index"),
            QStringLiteral("No."),
            QStringLiteral("Sequence"),
            QStringLiteral("Time"),
            QStringLiteral("Timestamp"),
            QStringLiteral("Date")
        };
    }

    QSet<int> TableSnapshotCompareEngine::defaultIgnoredColumnIndexes(const TableSnapshot& snapshot)
    {
        QSet<int> ignoredColumns;
        const QStringList kKeywords = defaultIgnoredColumnKeywords();
        for (const TableSnapshotColumn& column : snapshot.visibleColumns)
        {
            for (const QString& keyword : kKeywords)
            {
                if (headerMatchesKeyword(column.headerText, keyword))
                {
                    ignoredColumns.insert(column.sourceColumn);
                    break;
                }
            }
        }
        return ignoredColumns;
    }

    QSet<int> TableSnapshotCompareEngine::ignoredColumnIndexesForKeywords(
        const TableSnapshot& earlier,
        const TableSnapshot& later,
        const QStringList& keywords)
    {
        QSet<int> ignoredColumns;
        const auto kAppendMatchingColumns = [&ignoredColumns, &keywords](
            const QVector<TableSnapshotColumn>& columns)
        {
            for (const TableSnapshotColumn& column : columns)
            {
                for (const QString& keyword : keywords)
                {
                    if (headerMatchesKeyword(column.headerText, keyword))
                    {
                        ignoredColumns.insert(column.sourceColumn);
                        break;
                    }
                }
            }
        };
        kAppendMatchingColumns(earlier.visibleColumns);
        kAppendMatchingColumns(later.visibleColumns);
        return ignoredColumns;
    }

    TableComparisonResult TableSnapshotCompareEngine::compare(
        const TableSnapshot& earlier,
        const TableSnapshot& later,
        const QSet<int>& ignoredOriginalColumnIndexes,
        const QVector<int>& keyColumnIndexes,
        const TableSnapshotComparisonLimits& limits,
        const std::function<bool()>& shouldCancel)
    {
        TableComparisonResult result;
        result.earlierSnapshot = earlier;
        result.laterSnapshot = later;
        result.columns = combinedColumns(earlier, later);
        result.ignoredSourceColumns = ignoredOriginalColumnIndexes;

        const SnapshotColumnLookup kEarlierLookup(result.earlierSnapshot);
        const SnapshotColumnLookup kLaterLookup(result.laterSnapshot);
        result.earlierValueIndexes = valueIndexesForColumns(kEarlierLookup, result.columns);
        result.laterValueIndexes = valueIndexesForColumns(kLaterLookup, result.columns);
        result.estimatedBytes = sizeof(TableComparisonResult);
        result.estimatedBytes = saturatingAdd(
            result.estimatedBytes,
            logicalSnapshotBytes(result.earlierSnapshot));
        result.estimatedBytes = saturatingAdd(
            result.estimatedBytes,
            logicalSnapshotBytes(result.laterSnapshot));
        result.estimatedBytes = saturatingAdd(
            result.estimatedBytes,
            static_cast<quint64>(result.columns.size()) *
                (sizeof(TableSnapshotColumn) + sizeof(int) * 2ULL));
        if (result.estimatedBytes > limits.maximumEstimatedBytes)
        {
            result.truncatedByResultByteLimit = true;
            return result;
        }
        if (shouldCancel && shouldCancel())
        {
            result.cancelled = true;
            return result;
        }

        ComparisonWorkState work{ limits, shouldCancel, result };
        if (!work.reserveTemporary(
                static_cast<quint64>(
                    kEarlierLookup.valueIndexBySourceColumn.size() +
                    kLaterLookup.valueIndexBySourceColumn.size()) * 64ULL))
        {
            return result;
        }

        const QVector<int> kKeyColumns = usableStableKeyColumns(
            earlier,
            later,
            kEarlierLookup,
            kLaterLookup,
            keyColumnIndexes,
            result.ignoredSourceColumns);
        QHash<QByteArray, int> earlierRowsByKey;
        QHash<QByteArray, int> laterRowsByKey;
        const bool kCanUseStableKeys = !kKeyColumns.isEmpty() &&
            buildUniqueRowKeys(earlier, kEarlierLookup, kKeyColumns, earlierRowsByKey, work) &&
            buildUniqueRowKeys(later, kLaterLookup, kKeyColumns, laterRowsByKey, work);
        if (!work.canContinue())
        {
            return result;
        }

        if (kCanUseStableKeys)
        {
            result.usesStableKeys = true;
            if (!work.reserveTemporary(
                    static_cast<quint64>(later.rows.size()) * sizeof(bool)))
            {
                return result;
            }
            QVector<bool> matchedLaterRows(later.rows.size(), false);
            for (int earlierIndex = 0; earlierIndex < earlier.rows.size(); ++earlierIndex)
            {
                const TableSnapshotRow& earlierRow = earlier.rows.at(earlierIndex);
                const QByteArray kKey = rowKeyHash(earlierRow, kEarlierLookup, kKeyColumns, work);
                if (!work.canContinue())
                {
                    return result;
                }
                const auto kLaterIterator = laterRowsByKey.constFind(kKey);
                if (kLaterIterator == laterRowsByKey.cend())
                {
                    if (!appendComparisonRow(
                            result,
                            limits,
                            TableComparisonSource::kEarlierOnly,
                            earlierIndex,
                            -1,
                            false))
                    {
                        return result;
                    }
                    if (!work.checkpointAfterRow())
                    {
                        return result;
                    }
                    continue;
                }

                const int kLaterIndex = kLaterIterator.value();
                matchedLaterRows[kLaterIndex] = true;
                const TableSnapshotRow& laterRow = later.rows.at(kLaterIndex);
                QSet<int> changedColumns;
                for (const TableSnapshotColumn& column : result.columns)
                {
                    if (!work.consumeWork())
                    {
                        return result;
                    }
                    if (!result.ignoredSourceColumns.contains(column.sourceColumn) &&
                        valueForSourceColumn(earlierRow, kEarlierLookup, column.sourceColumn) !=
                            valueForSourceColumn(laterRow, kLaterLookup, column.sourceColumn))
                    {
                        changedColumns.insert(column.sourceColumn);
                    }
                }
                if (!appendComparisonRow(
                        result,
                        limits,
                        TableComparisonSource::kBoth,
                        earlierIndex,
                        kLaterIndex,
                        true,
                        std::move(changedColumns)))
                {
                    return result;
                }
                if (!work.checkpointAfterRow())
                {
                    return result;
                }
            }
            for (int laterIndex = 0; laterIndex < later.rows.size(); ++laterIndex)
            {
                if (!matchedLaterRows.at(laterIndex) &&
                    !appendComparisonRow(
                        result,
                        limits,
                        TableComparisonSource::kLaterOnly,
                        -1,
                        laterIndex,
                        true))
                {
                    return result;
                }
                if (!work.checkpointAfterRow())
                {
                    return result;
                }
            }
            return result;
        }

        if (!work.reserveTemporary(
                static_cast<quint64>(later.rows.size()) * 112ULL))
        {
            return result;
        }
        QHash<QByteArray, QVector<int>> laterRowsBySignature;
        laterRowsBySignature.reserve(later.rows.size());
        for (int laterIndex = 0; laterIndex < later.rows.size(); ++laterIndex)
        {
            const QByteArray kSignature = rowHash(
                later.rows.at(laterIndex),
                kLaterLookup,
                result.columns,
                result.ignoredSourceColumns,
                work);
            if (!work.canContinue())
            {
                return result;
            }
            laterRowsBySignature[kSignature].push_back(laterIndex);
            if (!work.checkpointAfterRow())
            {
                return result;
            }
        }

        if (!work.reserveTemporary(
                static_cast<quint64>(later.rows.size()) * (sizeof(bool) + 96ULL)))
        {
            return result;
        }
        QHash<QByteArray, int> matchedPerSignature;
        QVector<bool> matchedLaterRows(later.rows.size(), false);
        for (int earlierIndex = 0; earlierIndex < earlier.rows.size(); ++earlierIndex)
        {
            const TableSnapshotRow& earlierRow = earlier.rows.at(earlierIndex);
            const QByteArray kSignature = rowHash(
                earlierRow,
                kEarlierLookup,
                result.columns,
                result.ignoredSourceColumns,
                work);
            if (!work.canContinue())
            {
                return result;
            }
            const auto kMatchesIterator = laterRowsBySignature.constFind(kSignature);
            const int kMatchOffset = matchedPerSignature.value(kSignature);
            if (kMatchesIterator != laterRowsBySignature.cend() &&
                kMatchOffset < kMatchesIterator.value().size())
            {
                const int kLaterIndex = kMatchesIterator.value().at(kMatchOffset);
                matchedPerSignature.insert(kSignature, kMatchOffset + 1);
                matchedLaterRows[kLaterIndex] = true;
                if (!appendComparisonRow(
                        result,
                        limits,
                        TableComparisonSource::kBoth,
                        earlierIndex,
                        kLaterIndex,
                        false))
                {
                    return result;
                }
            }
            else
            {
                if (!appendComparisonRow(
                        result,
                        limits,
                        TableComparisonSource::kEarlierOnly,
                        earlierIndex,
                        -1,
                        false))
                {
                    return result;
                }
            }
            if (!work.checkpointAfterRow())
            {
                return result;
            }
        }
        for (int laterIndex = 0; laterIndex < later.rows.size(); ++laterIndex)
        {
            if (!matchedLaterRows.at(laterIndex) &&
                !appendComparisonRow(
                    result,
                    limits,
                    TableComparisonSource::kLaterOnly,
                    -1,
                    laterIndex,
                    true))
            {
                return result;
            }
            if (!work.checkpointAfterRow())
            {
                return result;
            }
        }
        return result;
    }

    QString TableSnapshotCompareEngine::snapshotLabelForOrdinal(quint64 ordinal)
    {
        QString label;
        quint64 current = ordinal + 1;
        while (current > 0)
        {
            const quint64 kRemainder = (current - 1) % 26;
            label.prepend(QChar(QLatin1Char('A').unicode() + static_cast<ushort>(kRemainder)));
            current = (current - 1) / 26;
        }
        return label;
    }

    TableComparisonModel::TableComparisonModel(QObject* parent)
        : QAbstractTableModel(parent)
    {
    }

    TableComparisonModel::TableComparisonModel(TableComparisonResult comparison, QObject* parent)
        : QAbstractTableModel(parent)
        , comparison_(std::move(comparison))
    {
        rebuildVisibleRows();
    }

    void TableComparisonModel::setComparison(TableComparisonResult comparison)
    {
        beginResetModel();
        comparison_ = std::move(comparison);
        rebuildVisibleRows();
        endResetModel();
    }

    const TableComparisonResult& TableComparisonModel::comparison() const
    {
        return comparison_;
    }

    void TableComparisonModel::setShowDifferencesOnly(const bool enabled)
    {
        if (showDifferencesOnly_ == enabled)
        {
            return;
        }
        beginResetModel();
        showDifferencesOnly_ = enabled;
        rebuildVisibleRows();
        endResetModel();
    }

    bool TableComparisonModel::showDifferencesOnly() const
    {
        return showDifferencesOnly_;
    }

    int TableComparisonModel::rowCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : visibleRows_.size();
    }

    int TableComparisonModel::columnCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : comparison_.columns.size() + 1;
    }

    QVariant TableComparisonModel::data(const QModelIndex& index, const int role) const
    {
        if (!index.isValid() || index.row() < 0 || index.row() >= visibleRows_.size())
        {
            return {};
        }

        const TableComparisonRow& row = comparison_.rows.at(visibleRows_.at(index.row()));
        if (role == Qt::DisplayRole)
        {
            if (index.column() == 0)
            {
                switch (row.source)
                {
                case TableComparisonSource::kEarlierOnly:
                    return QStringLiteral("A");
                case TableComparisonSource::kLaterOnly:
                    return QStringLiteral("B");
                case TableComparisonSource::kBoth:
                    return QStringLiteral("AB");
                }
            }

            const int kValueIndex = index.column() - 1;
            if (kValueIndex < 0 || kValueIndex >= comparison_.columns.size())
            {
                return {};
            }

            const TableSnapshot& snapshot = row.displayLater
                ? comparison_.laterSnapshot
                : comparison_.earlierSnapshot;
            const QVector<int>& valueIndexes = row.displayLater
                ? comparison_.laterValueIndexes
                : comparison_.earlierValueIndexes;
            const int kSnapshotRowIndex = row.displayLater
                ? row.laterRowIndex
                : row.earlierRowIndex;
            if (kSnapshotRowIndex < 0 ||
                kSnapshotRowIndex >= snapshot.rows.size() ||
                kValueIndex >= valueIndexes.size())
            {
                return {};
            }
            const int kSnapshotValueIndex = valueIndexes.at(kValueIndex);
            const TableSnapshotRow& snapshotRow = snapshot.rows.at(kSnapshotRowIndex);
            return kSnapshotValueIndex >= 0 && kSnapshotValueIndex < snapshotRow.values.size()
                ? QVariant(snapshotRow.values.at(kSnapshotValueIndex))
                : QVariant();
        }

        if (role == Qt::BackgroundRole)
        {
            if (row.source == TableComparisonSource::kEarlierOnly)
            {
                return earlierOnlyColor();
            }
            if (row.source == TableComparisonSource::kLaterOnly)
            {
                return laterOnlyColor();
            }
            if (index.column() > 0)
            {
                const int kSourceIndex = index.column() - 1;
                if (kSourceIndex >= 0 && kSourceIndex < comparison_.columns.size() &&
                    row.changedSourceColumns.contains(comparison_.columns.at(kSourceIndex).sourceColumn))
                {
                    return changedFieldColor();
                }
            }
        }
        return {};
    }

    QVariant TableComparisonModel::headerData(
        const int section,
        const Qt::Orientation orientation,
        const int role) const
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole || section < 0)
        {
            return {};
        }
        if (section == 0)
        {
            return ks::i18n::sourceText(QStringLiteral("来源"));
        }

        const int kColumnIndex = section - 1;
        return kColumnIndex >= 0 && kColumnIndex < comparison_.columns.size()
            ? QVariant(ks::i18n::displayText(comparison_.columns.at(kColumnIndex).headerText))
            : QVariant();
    }

    Qt::ItemFlags TableComparisonModel::flags(const QModelIndex& index) const
    {
        return index.isValid() ? (Qt::ItemIsEnabled | Qt::ItemIsSelectable) : Qt::NoItemFlags;
    }

    void TableComparisonModel::rebuildVisibleRows()
    {
        visibleRows_.clear();
        visibleRows_.reserve(comparison_.rows.size());
        for (int rowIndex = 0; rowIndex < comparison_.rows.size(); ++rowIndex)
        {
            const TableComparisonRow& row = comparison_.rows.at(rowIndex);
            if (!showDifferencesOnly_ || row.source != TableComparisonSource::kBoth ||
                !row.changedSourceColumns.isEmpty())
            {
                visibleRows_.push_back(rowIndex);
            }
        }
    }
}
