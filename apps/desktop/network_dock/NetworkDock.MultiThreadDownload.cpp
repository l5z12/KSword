#include "NetworkDock.InternalCommon.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

// ============================================================
// NetworkDock.MultiThreadDownload.cpp
// Purpose:
// 1) Add a "Multi-thread Download" tab (similar to IDM segmented download).
// 2) Supports setting the number of threads before download (default 16).
// 3) Display task-level percentage, segment-level percentage, and a segmented total progress bar.
// ============================================================

#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QPainter>
#include <QSignalBlocker>
#include <QStandardPaths>
#include <QUrl>

#include <cwchar>
#include <functional>
#include <limits>
#include <string>

#include <winhttp.h>

#pragma comment(lib, "Winhttp.lib")

using namespace network_dock_detail;

namespace
{
    enum MultiDownloadTaskColumn
    {
        kMultiDownloadTaskColumnId = 0,
        kMultiDownloadTaskColumnFile,
        kMultiDownloadTaskColumnUrl,
        kMultiDownloadTaskColumnThread,
        kMultiDownloadTaskColumnTotal,
        kMultiDownloadTaskColumnDownloaded,
        kMultiDownloadTaskColumnProgress,
        kMultiDownloadTaskColumnStatus,
        kMultiDownloadTaskColumnAction,
        kMultiDownloadTaskColumnCount
    };

    enum MultiDownloadSegmentColumn
    {
        kMultiDownloadSegmentColumnIndex = 0,
        kMultiDownloadSegmentColumnRange,
        kMultiDownloadSegmentColumnDownloaded,
        kMultiDownloadSegmentColumnProgress,
        kMultiDownloadSegmentColumnStatus,
        kMultiDownloadSegmentColumnCount
    };

    constexpr DWORD kReadBufferBytes = 64U * 1024U;

    struct WinHttpUrlParts
    {
        std::wstring hostText;
        std::wstring pathAndQueryText;
        INTERNET_PORT portValue = INTERNET_DEFAULT_HTTP_PORT;
        bool isHttps = false;
    };

    class WinHttpHandleGuard final
    {
    public:
        explicit WinHttpHandleGuard(HINTERNET handleValue = nullptr)
            : handleValue_(handleValue)
        {
        }

        ~WinHttpHandleGuard()
        {
            if (handleValue_ != nullptr)
            {
                ::WinHttpCloseHandle(handleValue_);
                handleValue_ = nullptr;
            }
        }

        WinHttpHandleGuard(const WinHttpHandleGuard&) = delete;
        WinHttpHandleGuard& operator=(const WinHttpHandleGuard&) = delete;

        [[nodiscard]] bool valid() const
        {
            return handleValue_ != nullptr;
        }

        [[nodiscard]] HINTERNET get() const
        {
            return handleValue_;
        }

    private:
        HINTERNET handleValue_ = nullptr;
    };

    QString formatBytesText(const std::uint64_t bytesValue)
    {
        return QString::fromStdString(ks::network::formatByteCount(bytesValue));
    }

    std::wstring queryHeaderWideText(HINTERNET requestHandle, const DWORD headerFlag)
    {
        DWORD headerBytes = 0;
        const BOOL kFirstOk = ::WinHttpQueryHeaders(
            requestHandle,
            headerFlag,
            WINHTTP_HEADER_NAME_BY_INDEX,
            WINHTTP_NO_OUTPUT_BUFFER,
            &headerBytes,
            WINHTTP_NO_HEADER_INDEX);
        if (kFirstOk != FALSE || ::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            return std::wstring();
        }

        std::wstring outputText;
        outputText.resize(headerBytes / sizeof(wchar_t));
        const BOOL kSecondOk = ::WinHttpQueryHeaders(
            requestHandle,
            headerFlag,
            WINHTTP_HEADER_NAME_BY_INDEX,
            outputText.data(),
            &headerBytes,
            WINHTTP_NO_HEADER_INDEX);
        if (kSecondOk == FALSE)
        {
            return std::wstring();
        }

        while (!outputText.empty() && outputText.back() == L'\0')
        {
            outputText.pop_back();
        }
        return outputText;
    }

    bool parseWinHttpUrlParts(
        const QString& urlText,
        WinHttpUrlParts* urlPartsOut,
        QString* errorTextOut)
    {
        if (urlPartsOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("内部错误：URL输出参数为空。");
            }
            return false;
        }

        URL_COMPONENTS components{};
        components.dwStructSize = sizeof(components);

        wchar_t hostBuffer[512] = {};
        wchar_t pathBuffer[2048] = {};
        wchar_t extraBuffer[2048] = {};
        components.lpszHostName = hostBuffer;
        components.dwHostNameLength = static_cast<DWORD>((sizeof(hostBuffer) / sizeof(hostBuffer[0])) - 1);
        components.lpszUrlPath = pathBuffer;
        components.dwUrlPathLength = static_cast<DWORD>((sizeof(pathBuffer) / sizeof(pathBuffer[0])) - 1);
        components.lpszExtraInfo = extraBuffer;
        components.dwExtraInfoLength = static_cast<DWORD>((sizeof(extraBuffer) / sizeof(extraBuffer[0])) - 1);

        const std::wstring kWideUrlText = urlText.toStdWString();
        const BOOL kCrackOk = ::WinHttpCrackUrl(
            kWideUrlText.c_str(),
            static_cast<DWORD>(kWideUrlText.size()),
            0,
            &components);
        if (kCrackOk == FALSE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("URL解析失败。");
            }
            return false;
        }

        urlPartsOut->hostText = std::wstring(components.lpszHostName, components.dwHostNameLength);
        urlPartsOut->pathAndQueryText = std::wstring(components.lpszUrlPath, components.dwUrlPathLength);
        const std::wstring kExtraText(components.lpszExtraInfo, components.dwExtraInfoLength);
        if (urlPartsOut->pathAndQueryText.empty())
        {
            urlPartsOut->pathAndQueryText = L"/";
        }
        if (!kExtraText.empty())
        {
            urlPartsOut->pathAndQueryText += kExtraText;
        }
        urlPartsOut->portValue = components.nPort;
        urlPartsOut->isHttps = (components.nScheme == INTERNET_SCHEME_HTTPS);
        return true;
    }

    bool queryRemoteFileMeta(
        const WinHttpUrlParts& urlParts,
        std::uint64_t* totalBytesOut,
        bool* supportsRangeOut,
        QString* errorTextOut)
    {
        if (totalBytesOut == nullptr || supportsRangeOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("内部错误：元信息输出参数为空。");
            }
            return false;
        }

        WinHttpHandleGuard sessionHandle(::WinHttpOpen(
            L"Ksword-MultiDownload/2026.04",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0));
        if (!sessionHandle.valid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建 WinHTTP 会话失败。");
            }
            return false;
        }

        WinHttpHandleGuard connectHandle(::WinHttpConnect(
            sessionHandle.get(),
            urlParts.hostText.c_str(),
            urlParts.portValue,
            0));
        if (!connectHandle.valid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("连接目标主机失败。");
            }
            return false;
        }

        const DWORD kRequestFlags = urlParts.isHttps ? WINHTTP_FLAG_SECURE : 0;
        WinHttpHandleGuard headRequestHandle(::WinHttpOpenRequest(
            connectHandle.get(),
            L"HEAD",
            urlParts.pathAndQueryText.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            kRequestFlags));
        if (!headRequestHandle.valid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建 HEAD 请求失败。");
            }
            return false;
        }

        if (::WinHttpSendRequest(headRequestHandle.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == FALSE
            || ::WinHttpReceiveResponse(headRequestHandle.get(), nullptr) == FALSE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("发送或接收 HEAD 请求失败。");
            }
            return false;
        }

        DWORD statusCode = 0;
        DWORD statusBytes = sizeof(statusCode);
        ::WinHttpQueryHeaders(
            headRequestHandle.get(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode,
            &statusBytes,
            WINHTTP_NO_HEADER_INDEX);
        if (statusCode >= 400)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("HEAD 状态码异常：%1").arg(statusCode);
            }
            return false;
        }

        const std::wstring kContentLengthText = queryHeaderWideText(headRequestHandle.get(), WINHTTP_QUERY_CONTENT_LENGTH);
        if (kContentLengthText.empty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("响应中缺少 Content-Length。");
            }
            return false;
        }

        const std::uint64_t kTotalBytes = static_cast<std::uint64_t>(std::wcstoull(kContentLengthText.c_str(), nullptr, 10));
        const std::wstring kAcceptRangesText = queryHeaderWideText(headRequestHandle.get(), WINHTTP_QUERY_ACCEPT_RANGES);
        const QString kAcceptRangesQString = QString::fromWCharArray(kAcceptRangesText.c_str()).toLower();

        *totalBytesOut = kTotalBytes;
        *supportsRangeOut = kAcceptRangesQString.contains(QStringLiteral("bytes"));
        return true;
    }

    bool ensureDirectoryReady(const QString& directoryPathText, QString* errorTextOut)
    {
        if (directoryPathText.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("下载目录为空。");
            }
            return false;
        }

        QDir directory(directoryPathText);
        if (directory.exists())
        {
            return true;
        }

        if (!directory.mkpath(QStringLiteral(".")))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建下载目录失败：%1").arg(directoryPathText);
            }
            return false;
        }
        return true;
    }

    void setCellText(QTableWidget* tableWidget, const int rowIndex, const int columnIndex, const QString& text)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        QTableWidgetItem* itemPointer = tableWidget->item(rowIndex, columnIndex);
        if (itemPointer == nullptr)
        {
            itemPointer = new QTableWidgetItem();
            itemPointer->setFlags(itemPointer->flags() & ~Qt::ItemIsEditable);
            tableWidget->setItem(rowIndex, columnIndex, itemPointer);
        }
        if (itemPointer->text() != text)
        {
            itemPointer->setText(text);
        }
    }
}
namespace
{
    QString buildSafeOutputFileName(const QUrl& downloadUrl, const int taskId)
    {
        QString fileNameText = QFileInfo(downloadUrl.path()).fileName().trimmed();
        if (fileNameText.isEmpty())
        {
            fileNameText = QStringLiteral("download_task_%1.bin").arg(taskId);
        }

        static const QChar kInvalidCharList[] = {
            QChar('<'), QChar('>'), QChar(':'), QChar('"'),
            QChar('/'), QChar('\\'), QChar('|'), QChar('?'), QChar('*')
        };
        for (const QChar kInvalidChar : kInvalidCharList)
        {
            fileNameText.replace(kInvalidChar, QChar('_'));
        }
        return fileNameText;
    }

    QString buildUniqueOutputPath(const QString& directoryPathText, const QString& fileNameText)
    {
        QDir directory(directoryPathText);
        QString outputPathText = directory.filePath(fileNameText);
        if (!QFileInfo::exists(outputPathText))
        {
            return outputPathText;
        }

        const QFileInfo kInfo(fileNameText);
        const QString kBaseNameText = kInfo.completeBaseName();
        const QString kSuffixText = kInfo.suffix();
        int indexValue = 1;
        while (indexValue < 10000)
        {
            const QString kCandidateNameText = kSuffixText.isEmpty()
                ? QStringLiteral("%1(%2)").arg(kBaseNameText).arg(indexValue)
                : QStringLiteral("%1(%2).%3").arg(kBaseNameText).arg(indexValue).arg(kSuffixText);
            outputPathText = directory.filePath(kCandidateNameText);
            if (!QFileInfo::exists(outputPathText))
            {
                return outputPathText;
            }
            ++indexValue;
        }
        return directory.filePath(fileNameText);
    }

    bool prepareOutputFile(const QString& outputFilePathText, const std::uint64_t totalBytes, QString* errorTextOut)
    {
        const std::wstring kOutputPathWideText = outputFilePathText.toStdWString();
        HANDLE outputFileHandle = ::CreateFileW(
            kOutputPathWideText.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (outputFileHandle == INVALID_HANDLE_VALUE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建输出文件失败，错误码=%1").arg(::GetLastError());
            }
            return false;
        }

        bool resultOk = true;
        if (totalBytes > 0)
        {
            LARGE_INTEGER sizeValue{};
            sizeValue.QuadPart = static_cast<LONGLONG>(totalBytes);
            if (::SetFilePointerEx(outputFileHandle, sizeValue, nullptr, FILE_BEGIN) == FALSE
                || ::SetEndOfFile(outputFileHandle) == FALSE)
            {
                resultOk = false;
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("预分配输出文件失败，错误码=%1").arg(::GetLastError());
                }
            }
        }

        ::CloseHandle(outputFileHandle);
        return resultOk;
    }

    bool downloadSegmentToFile(
        const WinHttpUrlParts& urlParts,
        const QString& outputFilePathText,
        const std::uint64_t beginByte,
        const std::uint64_t endByte,
        const bool enableRange,
        const std::atomic_bool* cancelFlag,
        const std::atomic_bool* pauseFlag,
        const std::function<void(std::uint64_t)>& chunkCallback,
        QString* errorTextOut)
    {
        WinHttpHandleGuard sessionHandle(::WinHttpOpen(
            L"Ksword-MultiDownload/2026.04",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0));
        if (!sessionHandle.valid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建下载会话失败。");
            }
            return false;
        }

        WinHttpHandleGuard connectHandle(::WinHttpConnect(
            sessionHandle.get(),
            urlParts.hostText.c_str(),
            urlParts.portValue,
            0));
        if (!connectHandle.valid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("连接下载主机失败。");
            }
            return false;
        }

        const DWORD kRequestFlags = urlParts.isHttps ? WINHTTP_FLAG_SECURE : 0;
        WinHttpHandleGuard requestHandle(::WinHttpOpenRequest(
            connectHandle.get(),
            L"GET",
            urlParts.pathAndQueryText.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            kRequestFlags));
        if (!requestHandle.valid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建下载请求失败。");
            }
            return false;
        }

        if (enableRange)
        {
            const std::wstring kRangeHeaderText = QString::fromStdString(
                ks::network::buildHttpRangeHeader(beginByte, endByte)).toStdWString();
            if (::WinHttpAddRequestHeaders(
                requestHandle.get(),
                kRangeHeaderText.c_str(),
                static_cast<DWORD>(kRangeHeaderText.size()),
                WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) == FALSE)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("附加 Range 请求头失败。");
                }
                return false;
            }
        }

        if (::WinHttpSendRequest(requestHandle.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == FALSE
            || ::WinHttpReceiveResponse(requestHandle.get(), nullptr) == FALSE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("发送或接收下载请求失败。");
            }
            return false;
        }

        DWORD statusCode = 0;
        DWORD statusBytes = sizeof(statusCode);
        ::WinHttpQueryHeaders(
            requestHandle.get(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode,
            &statusBytes,
            WINHTTP_NO_HEADER_INDEX);
        if (statusCode >= 400 || (enableRange && statusCode != 206))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("下载响应状态码异常=%1").arg(statusCode);
            }
            return false;
        }

        const std::wstring kOutputPathWideText = outputFilePathText.toStdWString();
        HANDLE outputFileHandle = ::CreateFileW(
            kOutputPathWideText.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (outputFileHandle == INVALID_HANDLE_VALUE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("打开输出文件失败，错误码=%1").arg(::GetLastError());
            }
            return false;
        }

        LARGE_INTEGER offsetValue{};
        offsetValue.QuadPart = static_cast<LONGLONG>(beginByte);
        if (::SetFilePointerEx(outputFileHandle, offsetValue, nullptr, FILE_BEGIN) == FALSE)
        {
            ::CloseHandle(outputFileHandle);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("设置文件偏移失败，错误码=%1").arg(::GetLastError());
            }
            return false;
        }

        // expectedBytes reuses the pure logic from ks::network to avoid maintaining range length algorithms separately in the download thread and the UI progress bar.
        const std::uint64_t kExpectedBytes = ks::network::calculateSegmentByteCount(beginByte, endByte);
        std::uint64_t writtenBytes = 0;
        std::vector<std::uint8_t> buffer(kReadBufferBytes);

        bool resultOk = true;
        while (writtenBytes < kExpectedBytes)
        {
            // Pause uses short-period waiting within the thread:
            // - Do not close the current WinHTTP request; if resumed, continue reading from the current connection.
            // - Check the cancellation flag during the wait to ensure the application exits as soon as the user clicks 'Cancel'.
            while (pauseFlag != nullptr && pauseFlag->load())
            {
                if (cancelFlag != nullptr && cancelFlag->load())
                {
                    resultOk = false;
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("任务已取消。");
                    }
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(120));
            }
            if (!resultOk)
            {
                break;
            }

            if (cancelFlag != nullptr && cancelFlag->load())
            {
                resultOk = false;
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("任务已取消。");
                }
                break;
            }

            DWORD readBytes = 0;
            if (::WinHttpReadData(requestHandle.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &readBytes) == FALSE)
            {
                resultOk = false;
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("读取网络数据失败。");
                }
                break;
            }
            if (readBytes == 0)
            {
                break;
            }

            const std::uint64_t kRemainBytes = kExpectedBytes - writtenBytes;
            const DWORD kWriteBytes = static_cast<DWORD>(std::min<std::uint64_t>(kRemainBytes, readBytes));
            DWORD realWriteBytes = 0;
            if (::WriteFile(outputFileHandle, buffer.data(), kWriteBytes, &realWriteBytes, nullptr) == FALSE
                || realWriteBytes != kWriteBytes)
            {
                resultOk = false;
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("写入输出文件失败，错误码=%1").arg(::GetLastError());
                }
                break;
            }

            writtenBytes += static_cast<std::uint64_t>(realWriteBytes);
            if (chunkCallback)
            {
                chunkCallback(static_cast<std::uint64_t>(realWriteBytes));
            }
        }

        ::CloseHandle(outputFileHandle);

        if (!resultOk)
        {
            return false;
        }
        if (writtenBytes != kExpectedBytes)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("分段长度不匹配，期望=%1，实际=%2")
                    .arg(static_cast<qulonglong>(kExpectedBytes))
                    .arg(static_cast<qulonglong>(writtenBytes));
            }
            return false;
        }
        return true;
    }
}

class MultiThreadDownloadSegmentBarWidget final : public QWidget
{
public:
    explicit MultiThreadDownloadSegmentBarWidget(QWidget* parent = nullptr)
        : QWidget(parent)
    {
        setMinimumHeight(28);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }

    void setSegmentRatios(const QVector<double>& segmentRatios, const double totalRatio, const bool finished)
    {
        segmentRatios_ = segmentRatios;
        totalRatio_ = std::clamp(totalRatio, 0.0, 1.0);
        finished_ = finished;
        update();
    }

protected:
    void paintEvent(QPaintEvent* event) override
    {
        Q_UNUSED(event);

        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);

        const QRectF kOuterRect = rect().adjusted(1.0, 1.0, -1.0, -1.0);
        painter.setPen(QPen(ksword_theme::borderStrongColor(), 1.0));
        painter.setBrush(ksword_theme::surfaceColor());
        painter.drawRoundedRect(kOuterRect, 4.0, 4.0);

        const QRectF kContentRect = kOuterRect.adjusted(2.0, 2.0, -2.0, -2.0);
        if (segmentRatios_.isEmpty())
        {
            painter.setPen(Qt::NoPen);
            painter.setBrush(ksword_theme::withAlpha(
                ksword_theme::accentColor(ksword_theme::AccentRole::kBlue), 180));
            painter.drawRect(QRectF(kContentRect.left(), kContentRect.top(), kContentRect.width() * totalRatio_, kContentRect.height()));
            return;
        }

        const int kCountValue = segmentRatios_.size();
        const double kGapWidth = finished_ ? 0.0 : 2.0;
        const double kAllGapWidth = kGapWidth * static_cast<double>(std::max(0, kCountValue - 1));
        const double kEachWidth = (kContentRect.width() - kAllGapWidth) / static_cast<double>(kCountValue);

        for (int index = 0; index < kCountValue; ++index)
        {
            const QRectF kSegmentRect(
                kContentRect.left() + index * (kEachWidth + kGapWidth),
                kContentRect.top(),
                kEachWidth,
                kContentRect.height());
            painter.setPen(Qt::NoPen);
            painter.setBrush(ksword_theme::surfaceAltColor());
            painter.drawRect(kSegmentRect);

            const double kRatioValue = std::clamp(segmentRatios_.at(index), 0.0, 1.0);
            if (kRatioValue > 0.0)
            {
                painter.setBrush(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue));
                painter.drawRect(QRectF(kSegmentRect.left(), kSegmentRect.top(), kSegmentRect.width() * kRatioValue, kSegmentRect.height()));
            }
        }
    }

private:
    QVector<double> segmentRatios_;
    double totalRatio_ = 0.0;
    bool finished_ = false;
};
void NetworkDock::initializeMultiThreadDownloadTab()
{
    multiThreadDownloadPage_ = new QWidget(this);
    multiThreadDownloadLayout_ = new QVBoxLayout(multiThreadDownloadPage_);
    multiThreadDownloadLayout_->setContentsMargins(6, 6, 6, 6);
    multiThreadDownloadLayout_->setSpacing(6);

    multiThreadDownloadControlLayout_ = new QHBoxLayout();
    multiThreadDownloadControlLayout_->setSpacing(6);

    QLabel* urlLabel = new QLabel(QStringLiteral("URL:"), multiThreadDownloadPage_);
    multiDownloadUrlEdit_ = new QLineEdit(multiThreadDownloadPage_);
    multiDownloadUrlEdit_->setPlaceholderText(QStringLiteral("输入 http/https 下载地址"));
    multiDownloadUrlEdit_->setToolTip(QStringLiteral("仅支持 HTTP/HTTPS 下载。"));

    QLabel* dirLabel = new QLabel(QStringLiteral("下载目录:"), multiThreadDownloadPage_);
    multiDownloadSaveDirEdit_ = new QLineEdit(multiThreadDownloadPage_);
    multiDownloadSaveDirEdit_->setToolTip(QStringLiteral("默认目录为用户 Downloads。"));
    multiDownloadSaveDirEdit_->setMinimumWidth(180);
    multiDownloadSaveDirEdit_->setMaximumWidth(360);

    const QString kDefaultDownloadPath = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    multiDownloadSaveDirEdit_->setText(kDefaultDownloadPath.isEmpty() ? QDir::homePath() : kDefaultDownloadPath);

    QLabel* threadLabel = new QLabel(QStringLiteral("线程:"), multiThreadDownloadPage_);
    multiDownloadThreadCountSpin_ = new QSpinBox(multiThreadDownloadPage_);
    multiDownloadThreadCountSpin_->setRange(1, 64);
    multiDownloadThreadCountSpin_->setValue(16);
    multiDownloadThreadCountSpin_->setToolTip(QStringLiteral("下载开始前可调整线程数，默认 16。"));

    multiDownloadBrowseDirButton_ = new QPushButton(multiThreadDownloadPage_);
    multiDownloadBrowseDirButton_->setIcon(QIcon(":/Icon/file_find.svg"));
    multiDownloadBrowseDirButton_->setToolTip(QStringLiteral("选择下载目录"));

    multiDownloadStartButton_ = new QPushButton(multiThreadDownloadPage_);
    multiDownloadStartButton_->setIcon(QIcon(":/Icon/process_start.svg"));
    multiDownloadStartButton_->setToolTip(QStringLiteral("启动新的多线程下载任务"));

    multiDownloadStatusLabel_ = new QLabel(QStringLiteral("状态：等待下载任务"), multiThreadDownloadPage_);
    multiDownloadStatusLabel_->setWordWrap(true);
    multiDownloadStatusLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    multiThreadDownloadControlLayout_->addWidget(urlLabel);
    multiThreadDownloadControlLayout_->addWidget(multiDownloadUrlEdit_, 1);
    multiThreadDownloadControlLayout_->addWidget(dirLabel);
    multiThreadDownloadControlLayout_->addWidget(multiDownloadSaveDirEdit_);
    multiThreadDownloadControlLayout_->addWidget(threadLabel);
    multiThreadDownloadControlLayout_->addWidget(multiDownloadThreadCountSpin_);
    multiThreadDownloadControlLayout_->addWidget(multiDownloadBrowseDirButton_);
    multiThreadDownloadControlLayout_->addWidget(multiDownloadStartButton_);
    multiThreadDownloadControlLayout_->addWidget(multiDownloadStatusLabel_, 1);
    multiThreadDownloadLayout_->addLayout(multiThreadDownloadControlLayout_);

    // Download capture settings bar:
    // - Provide a toggle for 'Clipboard Auto-Capture Download Links'.
    // - Provides an editable input box for 'recognizable file extensions';
    // - Write settings to JSON via the independent save button.
    QGroupBox* captureSettingsGroup = new QGroupBox(QStringLiteral("下载捕获设置"), multiThreadDownloadPage_); // captureSettingsGroup: Group container for download capture settings.
    QGridLayout* captureSettingsLayout = new QGridLayout(captureSettingsGroup); // captureSettingsLayout: Download capture settings group layout.
    captureSettingsLayout->setHorizontalSpacing(6);
    captureSettingsLayout->setVerticalSpacing(6);
    captureSettingsLayout->setColumnStretch(1, 1);

    multiDownloadAutoCaptureClipboardCheck_ = new QCheckBox(QStringLiteral("自动捕获剪贴板链接"), captureSettingsGroup);
    multiDownloadAutoCaptureClipboardCheck_->setToolTip(
        QStringLiteral("启用后，当剪贴板出现匹配后缀的 HTTP/HTTPS 链接时自动弹出下载询问框。"));

    QLabel* suffixLabel = new QLabel(QStringLiteral("识别后缀:"), captureSettingsGroup); // suffixLabel: Label for the suffix input box title.
    multiDownloadCaptureSuffixEdit_ = new QLineEdit(captureSettingsGroup);
    multiDownloadCaptureSuffixEdit_->setPlaceholderText(QStringLiteral("示例：.zip;.7z;.iso;.exe"));
    multiDownloadCaptureSuffixEdit_->setToolTip(
        QStringLiteral("支持以 ; , 空格 分隔后缀名，自动补全前导点。"));

    multiDownloadSaveCaptureSettingsButton_ = new QPushButton(captureSettingsGroup);
    multiDownloadSaveCaptureSettingsButton_->setIcon(QIcon(":/Icon/codeeditor_save.svg"));
    multiDownloadSaveCaptureSettingsButton_->setToolTip(QStringLiteral("保存下载捕获设置到 JSON"));

    QLabel* captureHintLabel = new QLabel(
        QStringLiteral("提示：剪贴板询问框为非阻塞窗口，不会阻塞主界面操作。"),
        captureSettingsGroup); // captureHintLabel: Hint label for download capture settings.
    captureHintLabel->setWordWrap(true);
    captureHintLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));

    captureSettingsLayout->addWidget(multiDownloadAutoCaptureClipboardCheck_, 0, 0, 1, 3);
    captureSettingsLayout->addWidget(suffixLabel, 1, 0);
    captureSettingsLayout->addWidget(multiDownloadCaptureSuffixEdit_, 1, 1);
    captureSettingsLayout->addWidget(multiDownloadSaveCaptureSettingsButton_, 1, 2);
    captureSettingsLayout->addWidget(captureHintLabel, 2, 0, 1, 3);
    multiThreadDownloadLayout_->addWidget(captureSettingsGroup);

    multiDownloadTaskTable_ = new ks::ui::VisibleTableWidget(multiThreadDownloadPage_);
    multiDownloadTaskTable_->setColumnCount(kMultiDownloadTaskColumnCount);
    multiDownloadTaskTable_->setHorizontalHeaderLabels({
        QStringLiteral("任务ID"),
        QStringLiteral("文件名"),
        QStringLiteral("URL"),
        QStringLiteral("线程"),
        QStringLiteral("总大小"),
        QStringLiteral("已下载"),
        QStringLiteral("进度"),
        QStringLiteral("状态"),
        QStringLiteral("操作")
        });
    multiDownloadTaskTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    multiDownloadTaskTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    multiDownloadTaskTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    multiDownloadTaskTable_->verticalHeader()->setVisible(false);
    multiDownloadTaskTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    // Horizontal scrollbar is not forcibly closed: by default, it is pushed into the viewport by global column width adaptation; it appears as needed after the user widens a column.
    installCopyCurrentRowMenu(multiDownloadTaskTable_);
    multiThreadDownloadLayout_->addWidget(multiDownloadTaskTable_, 1);

    QLabel* progressTitleLabel = new QLabel(
        QStringLiteral("当前选中任务总进度（未完成时会断成多节）："),
        multiThreadDownloadPage_);
    progressTitleLabel->setWordWrap(true);
    multiThreadDownloadLayout_->addWidget(progressTitleLabel);

    multiDownloadSegmentBar_ = new MultiThreadDownloadSegmentBarWidget(multiThreadDownloadPage_);
    multiThreadDownloadLayout_->addWidget(multiDownloadSegmentBar_);

    multiDownloadTotalProgressLabel_ = new QLabel(QStringLiteral("总进度：0.00%"), multiThreadDownloadPage_);
    multiThreadDownloadLayout_->addWidget(multiDownloadTotalProgressLabel_);

    multiDownloadSegmentTable_ = new ks::ui::VisibleTableWidget(multiThreadDownloadPage_);
    multiDownloadSegmentTable_->setColumnCount(kMultiDownloadSegmentColumnCount);
    multiDownloadSegmentTable_->setHorizontalHeaderLabels({
        QStringLiteral("分段"),
        QStringLiteral("字节范围"),
        QStringLiteral("已下载"),
        QStringLiteral("进度"),
        QStringLiteral("状态")
        });
    multiDownloadSegmentTable_->setSelectionMode(QAbstractItemView::NoSelection);
    multiDownloadSegmentTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    multiDownloadSegmentTable_->verticalHeader()->setVisible(false);
    multiDownloadSegmentTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    // Horizontal scrollbar is not forcibly closed: by default, it is pushed into the viewport by global column width adaptation; it appears as needed after the user widens a column.
    installCopyCurrentRowMenu(multiDownloadSegmentTable_);
    multiThreadDownloadLayout_->addWidget(multiDownloadSegmentTable_, 1);

    sideTabWidget_->addTab(
        multiThreadDownloadPage_,
        QIcon(":/Icon/process_start.svg"),
        QStringLiteral("多线程下载"));

    // Set load timing:
    // - Must be called after control construction to correctly populate UI with JSON values.
    // - If the settings file does not exist, automatically fall back to default values and write them to the memory state.
    loadMultiThreadDownloadCaptureSettings();

    KLogEvent initEvent;
    info << initEvent << "[NetworkDock] 多线程下载页初始化完成。" << eol;
}

void NetworkDock::browseMultiThreadDownloadDirectory()
{
    if (multiDownloadSaveDirEdit_ == nullptr)
    {
        return;
    }

    const QString kSelectedDirectory = QFileDialog::getExistingDirectory(
        this,
        QStringLiteral("选择下载目录"),
        multiDownloadSaveDirEdit_->text().trimmed().isEmpty() ? QDir::homePath() : multiDownloadSaveDirEdit_->text().trimmed(),
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (kSelectedDirectory.isEmpty())
    {
        return;
    }

    multiDownloadSaveDirEdit_->setText(kSelectedDirectory);

    KLogEvent browseEvent;
    info << browseEvent
        << "[NetworkDock] 用户切换多线程下载目录, path="
        << kSelectedDirectory.toStdString()
        << eol;
}

void NetworkDock::startMultiThreadDownloadTask()
{
    if (multiDownloadUrlEdit_ == nullptr
        || multiDownloadSaveDirEdit_ == nullptr
        || multiDownloadThreadCountSpin_ == nullptr)
    {
        return;
    }

    KLogEvent startEvent;
    const QString kUrlText = multiDownloadUrlEdit_->text().trimmed();
    const QUrl kDownloadUrl(kUrlText);
    if (!kDownloadUrl.isValid()
        || (kDownloadUrl.scheme().compare(QStringLiteral("http"), Qt::CaseInsensitive) != 0
            && kDownloadUrl.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) != 0))
    {
        QMessageBox::warning(this, QStringLiteral("多线程下载"), QStringLiteral("请输入合法的 HTTP/HTTPS 地址。"));
        warn << startEvent << "[NetworkDock] 多线程下载启动失败：URL非法。" << eol;
        return;
    }

    const QString kDirectoryText = multiDownloadSaveDirEdit_->text().trimmed();
    QString directoryErrorText;
    if (!ensureDirectoryReady(kDirectoryText, &directoryErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("多线程下载"), directoryErrorText);
        warn << startEvent
            << "[NetworkDock] 多线程下载启动失败：目录不可用, reason="
            << directoryErrorText.toStdString()
            << eol;
        return;
    }

    WinHttpUrlParts urlParts;
    QString parseErrorText;
    if (!parseWinHttpUrlParts(kUrlText, &urlParts, &parseErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("多线程下载"), parseErrorText);
        warn << startEvent
            << "[NetworkDock] 多线程下载启动失败：URL解析失败, reason="
            << parseErrorText.toStdString()
            << eol;
        return;
    }

    std::uint64_t totalBytes = 0;
    bool supportsRange = false;
    QString metaErrorText;
    if (!queryRemoteFileMeta(urlParts, &totalBytes, &supportsRange, &metaErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("多线程下载"), QStringLiteral("读取远端文件信息失败：%1").arg(metaErrorText));
        warn << startEvent
            << "[NetworkDock] 多线程下载启动失败：读取远端文件信息失败, reason="
            << metaErrorText.toStdString()
            << eol;
        return;
    }

    const int kTaskId = multiDownloadNextTaskId_++;
    const QString kFileNameText = buildSafeOutputFileName(kDownloadUrl, kTaskId);
    const QString kOutputPathText = buildUniqueOutputPath(kDirectoryText, kFileNameText);

    QString prepareErrorText;
    if (!prepareOutputFile(kOutputPathText, totalBytes, &prepareErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("多线程下载"), prepareErrorText);
        warn << startEvent
            << "[NetworkDock] 多线程下载启动失败：输出文件准备失败, reason="
            << prepareErrorText.toStdString()
            << eol;
        return;
    }

    std::shared_ptr<MultiThreadDownloadTaskState> taskState = std::make_shared<MultiThreadDownloadTaskState>();
    taskState->taskId = kTaskId;
    taskState->urlText = kUrlText;
    taskState->savePathText = kOutputPathText;
    taskState->fileNameText = kFileNameText;
    taskState->requestedThreadCount = std::max(1, multiDownloadThreadCountSpin_->value());
    taskState->supportsRange = supportsRange;
    taskState->totalBytes = totalBytes;
    taskState->statusText = QStringLiteral("下载中");

    const ks::network::DownloadPlan kDownloadPlan = ks::network::buildDownloadSegmentPlan(
        totalBytes,
        taskState->requestedThreadCount,
        taskState->supportsRange);
    taskState->actualThreadCount = kDownloadPlan.actualThreadCount;

    if (kDownloadPlan.emptyFile)
    {
        std::shared_ptr<MultiThreadDownloadSegmentState> segmentState = std::make_shared<MultiThreadDownloadSegmentState>();
        segmentState->rangeBeginByte = kDownloadPlan.segments.front().beginByte;
        segmentState->rangeEndByte = kDownloadPlan.segments.front().endByte;
        segmentState->finished.store(true);
        segmentState->statusText = QStringLiteral("空文件");
        taskState->segmentStateList.push_back(segmentState);
        taskState->finished.store(true);
        taskState->statusText = QStringLiteral("已完成（空文件）");
    }
    else
    {
        for (const ks::network::DownloadSegmentPlan& segmentPlan : kDownloadPlan.segments)
        {
            std::shared_ptr<MultiThreadDownloadSegmentState> segmentState = std::make_shared<MultiThreadDownloadSegmentState>();
            segmentState->rangeBeginByte = segmentPlan.beginByte;
            segmentState->rangeEndByte = segmentPlan.endByte;
            segmentState->statusText = QStringLiteral("等待中");
            taskState->segmentStateList.push_back(segmentState);
        }

        taskState->runningWorkerCount.store(kDownloadPlan.actualThreadCount);
        const bool kUseRange = kDownloadPlan.useRange;
        for (const std::shared_ptr<MultiThreadDownloadSegmentState>& segmentState : taskState->segmentStateList)
        {
            std::thread([taskState, segmentState, urlParts, kUseRange]()
                {
                    {
                        std::lock_guard<std::mutex> segmentGuard(segmentState->statusMutex);
                        segmentState->statusText = QStringLiteral("下载中");
                    }

                    QString downloadErrorText;
                    const bool kDownloadOk = downloadSegmentToFile(
                        urlParts,
                        taskState->savePathText,
                        segmentState->rangeBeginByte,
                        segmentState->rangeEndByte,
                        kUseRange,
                        &taskState->cancelRequested,
                        &taskState->pauseRequested,
                        [taskState, segmentState](const std::uint64_t chunkBytes)
                        {
                            segmentState->downloadedBytes.fetch_add(chunkBytes);
                            taskState->downloadedBytes.fetch_add(chunkBytes);
                        },
                        &downloadErrorText);

                    if (!kDownloadOk)
                    {
                        taskState->cancelRequested.store(true);
                        const bool kCanceledByUser = taskState->canceled.load();
                        if (!kCanceledByUser)
                        {
                            taskState->failed.store(true);
                        }
                        {
                            std::lock_guard<std::mutex> segmentGuard(segmentState->statusMutex);
                            segmentState->statusText = kCanceledByUser ? QStringLiteral("已取消") : QStringLiteral("失败");
                        }
                        {
                            std::lock_guard<std::mutex> taskGuard(taskState->statusMutex);
                            taskState->statusText = kCanceledByUser ? QStringLiteral("已取消") : QStringLiteral("失败");
                            if (!kCanceledByUser && taskState->errorReasonText.isEmpty())
                            {
                                taskState->errorReasonText = downloadErrorText;
                            }
                        }
                    }
                    else
                    {
                        segmentState->finished.store(true);
                        std::lock_guard<std::mutex> segmentGuard(segmentState->statusMutex);
                        segmentState->statusText = QStringLiteral("完成");
                    }

                    const int kRemainWorker = taskState->runningWorkerCount.fetch_sub(1) - 1;
                    if (kRemainWorker <= 0)
                    {
                        taskState->finished.store(true);
                        if (taskState->canceled.load())
                        {
                            std::lock_guard<std::mutex> taskGuard(taskState->statusMutex);
                            taskState->statusText = QStringLiteral("已取消");
                        }
                        else if (!taskState->failed.load())
                        {
                            taskState->downloadedBytes.store(taskState->totalBytes);
                            std::lock_guard<std::mutex> taskGuard(taskState->statusMutex);
                            taskState->statusText = QStringLiteral("已完成");
                        }
                    }
                }).detach();
        }
    }

    {
        std::lock_guard<std::mutex> guard(multiDownloadTaskMutex_);
        multiDownloadTaskList_.push_back(taskState);
    }

    if (multiDownloadSelectedTaskId_ == 0)
    {
        multiDownloadSelectedTaskId_ = taskState->taskId;
    }

    if (multiDownloadStatusLabel_ != nullptr)
    {
        multiDownloadStatusLabel_->setText(
            QStringLiteral("状态：任务 #%1 已启动，输出=%2")
            .arg(taskState->taskId)
            .arg(taskState->savePathText));
    }

    info << startEvent
        << "[NetworkDock] 多线程下载任务启动, taskId=" << taskState->taskId
        << ", requestedThreads=" << taskState->requestedThreadCount
        << ", actualThreads=" << taskState->actualThreadCount
        << ", totalBytes=" << static_cast<unsigned long long>(taskState->totalBytes)
        << ", supportsRange=" << (taskState->supportsRange ? "true" : "false")
        << ", outputPath=" << taskState->savePathText.toStdString()
        << eol;

    refreshMultiThreadDownloadUi();
}

bool NetworkDock::startMultiThreadDownloadTaskFromInput(
    const QString& urlText,
    const QString& saveDirectoryText)
{
    if (multiDownloadUrlEdit_ == nullptr || multiDownloadSaveDirEdit_ == nullptr)
    {
        return false;
    }

    // Snapshot before and after start:
    // - Determines if a 'new task was successfully created' by checking if the task count increased.
    // - This method reuses the original startMultiThreadDownloadTask validation and download logic.
    std::size_t taskCountBefore = 0;
    {
        std::lock_guard<std::mutex> guard(multiDownloadTaskMutex_);
        taskCountBefore = multiDownloadTaskList_.size();
    }

    // Synchronize the confirmation value from the dialog back to the main download page input fields to maintain consistent user visibility.
    multiDownloadUrlEdit_->setText(urlText.trimmed());
    multiDownloadSaveDirEdit_->setText(saveDirectoryText.trimmed());
    startMultiThreadDownloadTask();

    std::size_t taskCountAfter = 0;
    {
        std::lock_guard<std::mutex> guard(multiDownloadTaskMutex_);
        taskCountAfter = multiDownloadTaskList_.size();
    }

    return taskCountAfter > taskCountBefore;
}

std::shared_ptr<NetworkDock::MultiThreadDownloadTaskState> NetworkDock::findMultiThreadDownloadTaskById(const int taskId) const
{
    if (taskId <= 0)
    {
        return nullptr;
    }

    std::lock_guard<std::mutex> guard(multiDownloadTaskMutex_);
    for (const std::shared_ptr<MultiThreadDownloadTaskState>& taskState : multiDownloadTaskList_)
    {
        if (taskState != nullptr && taskState->taskId == taskId)
        {
            return taskState;
        }
    }
    return nullptr;
}

void NetworkDock::setMultiThreadDownloadTaskPaused(const int taskId, const bool paused)
{
    const std::shared_ptr<MultiThreadDownloadTaskState> kTaskState = findMultiThreadDownloadTaskById(taskId);
    if (kTaskState == nullptr || kTaskState->finished.load() || kTaskState->cancelRequested.load())
    {
        return;
    }

    kTaskState->pauseRequested.store(paused);
    {
        std::lock_guard<std::mutex> taskGuard(kTaskState->statusMutex);
        kTaskState->statusText = paused ? QStringLiteral("已暂停") : QStringLiteral("下载中");
    }

    for (const std::shared_ptr<MultiThreadDownloadSegmentState>& segmentState : kTaskState->segmentStateList)
    {
        if (segmentState == nullptr || segmentState->finished.load())
        {
            continue;
        }

        std::lock_guard<std::mutex> segmentGuard(segmentState->statusMutex);
        segmentState->statusText = paused ? QStringLiteral("已暂停") : QStringLiteral("下载中");
    }

    KLogEvent pauseEvent;
    info << pauseEvent
        << "[NetworkDock] 多线程下载任务"
        << (paused ? "暂停" : "继续")
        << ", taskId="
        << taskId
        << eol;
    refreshMultiThreadDownloadUi();
}

void NetworkDock::cancelMultiThreadDownloadTask(const int taskId)
{
    const std::shared_ptr<MultiThreadDownloadTaskState> kTaskState = findMultiThreadDownloadTaskById(taskId);
    if (kTaskState == nullptr || kTaskState->finished.load())
    {
        return;
    }

    kTaskState->canceled.store(true);
    kTaskState->cancelRequested.store(true);
    kTaskState->pauseRequested.store(false);
    {
        std::lock_guard<std::mutex> taskGuard(kTaskState->statusMutex);
        kTaskState->statusText = QStringLiteral("取消中");
        kTaskState->errorReasonText.clear();
    }

    for (const std::shared_ptr<MultiThreadDownloadSegmentState>& segmentState : kTaskState->segmentStateList)
    {
        if (segmentState == nullptr || segmentState->finished.load())
        {
            continue;
        }

        std::lock_guard<std::mutex> segmentGuard(segmentState->statusMutex);
        segmentState->statusText = QStringLiteral("取消中");
    }

    KLogEvent cancelEvent;
    info << cancelEvent
        << "[NetworkDock] 多线程下载任务取消请求, taskId="
        << taskId
        << eol;
    refreshMultiThreadDownloadUi();
}

void NetworkDock::refreshMultiThreadDownloadUi()
{
    if (multiDownloadTaskTable_ == nullptr
        || multiDownloadSegmentTable_ == nullptr
        || multiDownloadSegmentBar_ == nullptr
        || multiDownloadTotalProgressLabel_ == nullptr)
    {
        return;
    }

    std::vector<std::shared_ptr<MultiThreadDownloadTaskState>> snapshotList;
    {
        std::lock_guard<std::mutex> guard(multiDownloadTaskMutex_);
        snapshotList = multiDownloadTaskList_;
    }

    const QSignalBlocker kTaskTableSignalBlocker(multiDownloadTaskTable_);
    const bool kTaskTableUpdatesEnabled = multiDownloadTaskTable_->updatesEnabled();
    multiDownloadTaskTable_->setUpdatesEnabled(false);
    multiDownloadTaskTable_->setRowCount(static_cast<int>(snapshotList.size()));

    int runningCount = 0;
    int finishedCount = 0;
    int failedCount = 0;
    int canceledCount = 0;
    for (int row = 0; row < static_cast<int>(snapshotList.size()); ++row)
    {
        const std::shared_ptr<MultiThreadDownloadTaskState>& taskState = snapshotList[static_cast<std::size_t>(row)];
        if (taskState == nullptr)
        {
            continue;
        }

        const std::uint64_t kDownloaded = taskState->downloadedBytes.load();
        const std::uint64_t kTotal = taskState->totalBytes;
        const double kPercent = ks::network::calculateProgressPercent(kDownloaded, kTotal);

        QString statusText;
        {
            std::lock_guard<std::mutex> taskGuard(taskState->statusMutex);
            statusText = taskState->statusText;
            if (taskState->failed.load() && !taskState->errorReasonText.isEmpty())
            {
                statusText += QStringLiteral("（%1）").arg(taskState->errorReasonText);
            }
        }

        setCellText(multiDownloadTaskTable_, row, kMultiDownloadTaskColumnId, QString::number(taskState->taskId));
        setCellText(multiDownloadTaskTable_, row, kMultiDownloadTaskColumnFile, taskState->fileNameText);
        setCellText(multiDownloadTaskTable_, row, kMultiDownloadTaskColumnUrl, taskState->urlText);
        setCellText(
            multiDownloadTaskTable_,
            row,
            kMultiDownloadTaskColumnThread,
            QStringLiteral("%1/%2").arg(taskState->actualThreadCount).arg(taskState->requestedThreadCount));
        setCellText(multiDownloadTaskTable_, row, kMultiDownloadTaskColumnTotal, formatBytesText(kTotal));
        setCellText(multiDownloadTaskTable_, row, kMultiDownloadTaskColumnDownloaded, formatBytesText(kDownloaded));
        setCellText(multiDownloadTaskTable_, row, kMultiDownloadTaskColumnProgress, QStringLiteral("%1%").arg(kPercent, 0, 'f', 2));
        setCellText(multiDownloadTaskTable_, row, kMultiDownloadTaskColumnStatus, statusText);

        const bool kTaskFinished = taskState->finished.load();
        const bool kTaskCanceled = taskState->canceled.load();
        const bool kTaskPaused = taskState->pauseRequested.load();
        const bool kTaskActionEnabled = !kTaskFinished && !taskState->cancelRequested.load();
        QWidget* actionWidget = multiDownloadTaskTable_->cellWidget(row, kMultiDownloadTaskColumnAction);
        if (actionWidget == nullptr)
        {
            actionWidget = new QWidget(multiDownloadTaskTable_);
            QHBoxLayout* actionLayout = new QHBoxLayout(actionWidget);
            actionLayout->setContentsMargins(2, 2, 2, 2);
            actionLayout->setSpacing(4);

            QPushButton* pauseButton = new QPushButton(actionWidget);
            connect(pauseButton, &QPushButton::clicked, this, [this, taskId = taskState->taskId]()
                {
                    const std::shared_ptr<MultiThreadDownloadTaskState> kCurrentTask = findMultiThreadDownloadTaskById(taskId);
                    if (kCurrentTask != nullptr)
                    {
                        setMultiThreadDownloadTaskPaused(taskId, !kCurrentTask->pauseRequested.load());
                    }
                });

            QPushButton* cancelButton = new QPushButton(actionWidget);
            connect(cancelButton, &QPushButton::clicked, this, [this, taskId = taskState->taskId]()
                {
                    cancelMultiThreadDownloadTask(taskId);
                });

            actionLayout->addWidget(pauseButton);
            actionLayout->addWidget(cancelButton);
            actionLayout->addStretch(1);
            multiDownloadTaskTable_->setCellWidget(row, kMultiDownloadTaskColumnAction, actionWidget);
        }

        QHBoxLayout* actionLayout = qobject_cast<QHBoxLayout*>(actionWidget->layout());
        QPushButton* pauseButton = actionLayout != nullptr && actionLayout->count() > 0
            ? qobject_cast<QPushButton*>(actionLayout->itemAt(0)->widget())
            : nullptr;
        QPushButton* cancelButton = actionLayout != nullptr && actionLayout->count() > 1
            ? qobject_cast<QPushButton*>(actionLayout->itemAt(1)->widget())
            : nullptr;
        if (pauseButton != nullptr)
        {
            pauseButton->setText(kTaskPaused ? QStringLiteral("继续") : QStringLiteral("暂停"));
            pauseButton->setIcon(QIcon(kTaskPaused ? ":/Icon/process_start.svg" : ":/Icon/process_pause.svg"));
            pauseButton->setToolTip(kTaskPaused ? QStringLiteral("继续当前下载任务") : QStringLiteral("暂停当前下载任务"));
            pauseButton->setEnabled(kTaskActionEnabled);
        }
        if (cancelButton != nullptr)
        {
            cancelButton->setText(QStringLiteral("取消"));
            cancelButton->setIcon(QIcon(":/Icon/log_cancel_track.svg"));
            cancelButton->setToolTip(QStringLiteral("取消当前下载任务，已写入的临时文件内容会保留"));
            cancelButton->setEnabled(kTaskActionEnabled);
        }

        if (kTaskCanceled)
        {
            ++canceledCount;
        }
        else if (taskState->failed.load())
        {
            ++failedCount;
        }
        else if (taskState->finished.load())
        {
            ++finishedCount;
        }
        else
        {
            ++runningCount;
        }
    }

    if (multiDownloadStatusLabel_ != nullptr)
    {
        multiDownloadStatusLabel_->setText(
            QStringLiteral("状态：运行中 %1，已完成 %2，失败 %3，已取消 %4")
            .arg(runningCount)
            .arg(finishedCount)
            .arg(failedCount)
            .arg(canceledCount));
    }

    multiDownloadTaskTable_->setUpdatesEnabled(kTaskTableUpdatesEnabled);
    if (kTaskTableUpdatesEnabled && multiDownloadTaskTable_->viewport() != nullptr)
    {
        multiDownloadTaskTable_->viewport()->update();
    }

    if (multiDownloadSelectedTaskId_ <= 0 && !snapshotList.empty())
    {
        multiDownloadSelectedTaskId_ = snapshotList.front()->taskId;
    }

    if (multiDownloadSelectedTaskId_ > 0)
    {
        for (int row = 0; row < multiDownloadTaskTable_->rowCount(); ++row)
        {
            QTableWidgetItem* idItem = multiDownloadTaskTable_->item(row, kMultiDownloadTaskColumnId);
            if (idItem == nullptr)
            {
                continue;
            }

            bool parseOk = false;
            const int kTaskId = idItem->text().toInt(&parseOk, 10);
            if (parseOk && kTaskId == multiDownloadSelectedTaskId_)
            {
                multiDownloadTaskTable_->selectRow(row);
                break;
            }
        }
    }

    std::shared_ptr<MultiThreadDownloadTaskState> selectedTask = findMultiThreadDownloadTaskById(multiDownloadSelectedTaskId_);
    if (selectedTask == nullptr)
    {
        multiDownloadSegmentTable_->setRowCount(0);
        multiDownloadSegmentBar_->setSegmentRatios(QVector<double>(), 0.0, false);
        multiDownloadTotalProgressLabel_->setText(QStringLiteral("总进度：0.00%"));
        return;
    }

    const auto& segmentList = selectedTask->segmentStateList;
    const bool kSegmentTableUpdatesEnabled = multiDownloadSegmentTable_->updatesEnabled();
    multiDownloadSegmentTable_->setUpdatesEnabled(false);
    multiDownloadSegmentTable_->setRowCount(static_cast<int>(segmentList.size()));

    QVector<double> segmentRatios;
    segmentRatios.reserve(static_cast<int>(segmentList.size()));
    for (int index = 0; index < static_cast<int>(segmentList.size()); ++index)
    {
        const std::shared_ptr<MultiThreadDownloadSegmentState>& segmentState = segmentList[static_cast<std::size_t>(index)];
        if (segmentState == nullptr)
        {
            segmentRatios.push_back(0.0);
            continue;
        }

        const std::uint64_t kRangeBytes = ks::network::calculateSegmentByteCount(
            segmentState->rangeBeginByte,
            segmentState->rangeEndByte);
        const std::uint64_t kDownloaded = segmentState->downloadedBytes.load();
        const double kRatio = ks::network::calculateProgressRatio(kDownloaded, kRangeBytes);
        const double kPercent = ks::network::calculateProgressPercent(kDownloaded, kRangeBytes);

        QString segmentStatus;
        {
            std::lock_guard<std::mutex> segmentGuard(segmentState->statusMutex);
            segmentStatus = segmentState->statusText;
        }

        setCellText(multiDownloadSegmentTable_, index, kMultiDownloadSegmentColumnIndex, QStringLiteral("#%1").arg(index + 1));
        setCellText(
            multiDownloadSegmentTable_,
            index,
            kMultiDownloadSegmentColumnRange,
            QStringLiteral("%1-%2")
            .arg(static_cast<qulonglong>(segmentState->rangeBeginByte))
            .arg(static_cast<qulonglong>(segmentState->rangeEndByte)));
        setCellText(
            multiDownloadSegmentTable_,
            index,
            kMultiDownloadSegmentColumnDownloaded,
            QStringLiteral("%1 / %2").arg(formatBytesText(kDownloaded)).arg(formatBytesText(kRangeBytes)));
        setCellText(
            multiDownloadSegmentTable_,
            index,
            kMultiDownloadSegmentColumnProgress,
            QStringLiteral("%1%").arg(kPercent, 0, 'f', 2));
        setCellText(multiDownloadSegmentTable_, index, kMultiDownloadSegmentColumnStatus, segmentStatus);

        segmentRatios.push_back(kRatio);
    }

    const std::uint64_t kSelectedDownloaded = selectedTask->downloadedBytes.load();
    const std::uint64_t kSelectedTotal = selectedTask->totalBytes;
    const double kSelectedRatio = ks::network::calculateProgressRatio(kSelectedDownloaded, kSelectedTotal);
    const double kSelectedPercent = ks::network::calculateProgressPercent(kSelectedDownloaded, kSelectedTotal);

    multiDownloadSegmentBar_->setSegmentRatios(
        segmentRatios,
        kSelectedRatio,
        selectedTask->finished.load() && !selectedTask->failed.load());
    multiDownloadTotalProgressLabel_->setText(
        QStringLiteral("总进度：%1%    已下载：%2 / %3")
        .arg(kSelectedPercent, 0, 'f', 2)
        .arg(formatBytesText(kSelectedDownloaded))
        .arg(formatBytesText(kSelectedTotal)));

    multiDownloadSegmentTable_->setUpdatesEnabled(kSegmentTableUpdatesEnabled);
    if (kSegmentTableUpdatesEnabled && multiDownloadSegmentTable_->viewport() != nullptr)
    {
        multiDownloadSegmentTable_->viewport()->update();
    }
}
