#include "MainWindow.h"
#include "misc_dock/MiscDock.h"
#include <QCoreApplication>
#include <QFont>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QPainter>
#include <QPointer>
#include <QImage>
#include <QThreadPool>
#include <QMetaObject>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "../../shared/ark_client/ArkDriverClient.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <utility>
#include <cstring>
#include <vector>
#include <TlHelp32.h>

#include "MainWindow.BugcheckSupport.h"

namespace ksword::ui::main_window
{
    constexpr int kBugcheckBitmapMaxWidth =
        static_cast<int>(KSWORD_ARK_BUGCHECK_BITMAP_MAX_WIDTH);

    constexpr int kBugcheckBitmapMaxHeight =
        static_cast<int>(KSWORD_ARK_BUGCHECK_BITMAP_MAX_HEIGHT);

    constexpr int kBugcheckLogoWidth = 240;

    constexpr int kBugcheckLogoHeight = 84;

    static_assert(kBugcheckLogoWidth <= kBugcheckBitmapMaxWidth);

    static_assert(kBugcheckLogoHeight <= kBugcheckBitmapMaxHeight);

    constexpr QRgb kBugcheckBitmapBackground = qRgba(5, 15, 33, 255);

    constexpr QRgb kBugcheckBitmapLightText = qRgba(226, 232, 244, 255);

    std::uint32_t detectBugcheckBrandColor(const QImage& image)
    {
        std::uint64_t redTotal = 0;
        std::uint64_t greenTotal = 0;
        std::uint64_t blueTotal = 0;
        std::uint64_t sampleCount = 0;

        for (int y = 0; y < image.height(); ++y)
        {
            for (int x = 0; x < image.width(); ++x)
            {
                const QColor kColor = image.pixelColor(x, y);
                if (kColor.alpha() < 32 || kColor.blue() < 96 ||
                    kColor.blue() < kColor.red() + 24 ||
                    kColor.blue() < kColor.green() + 8)
                {
                    continue;
                }
                redTotal += static_cast<std::uint64_t>(kColor.red());
                greenTotal += static_cast<std::uint64_t>(kColor.green());
                blueTotal += static_cast<std::uint64_t>(kColor.blue());
                ++sampleCount;
            }
        }

        if (sampleCount == 0)
        {
            return 0x0078D4U;
        }
        return
            (static_cast<std::uint32_t>(redTotal / sampleCount) << 16) |
            (static_cast<std::uint32_t>(greenTotal / sampleCount) << 8) |
            static_cast<std::uint32_t>(blueTotal / sampleCount);
    }

    [[maybe_unused]] void queueBugcheckBitmapUpload()
    {
        // The branding packet is optional. Keep decoding and driver I/O away
        // from the UI thread and intentionally discard every failure result.
        QThreadPool::globalInstance()->start([]()
        {
            QImage source(QStringLiteral(":/Image/Resource/Logo/KswordHome-En.png"));
            if (source.isNull())
            {
                return;
            }

            if (source.width() != kBugcheckLogoWidth ||
                source.height() != kBugcheckLogoHeight)
            {
                source = source.scaled(
                    kBugcheckLogoWidth,
                    kBugcheckLogoHeight,
                    Qt::IgnoreAspectRatio,
                    Qt::SmoothTransformation);
                if (source.isNull())
                {
                    return;
                }
            }

            const std::uint32_t kBrandColor = detectBugcheckBrandColor(source);
            QImage darkCompatibleSource = source.convertToFormat(QImage::Format_ARGB32);
            if (darkCompatibleSource.isNull())
            {
                return;
            }
            for (int y = 0; y < darkCompatibleSource.height(); ++y)
            {
                QRgb* const kRow = reinterpret_cast<QRgb*>(darkCompatibleSource.scanLine(y));
                for (int x = 0; x < darkCompatibleSource.width(); ++x)
                {
                    const QColor kColor = QColor::fromRgba(kRow[x]);
                    if (kColor.alpha() != 0 && kColor.red() < 72 &&
                        kColor.green() < 72 && kColor.blue() < 72)
                    {
                        kRow[x] = qRgba(
                            qRed(kBugcheckBitmapLightText),
                            qGreen(kBugcheckBitmapLightText),
                            qBlue(kBugcheckBitmapLightText),
                            kColor.alpha());
                    }
                }
            }
            QImage bitmap(source.size(), QImage::Format_ARGB32);
            if (bitmap.isNull())
            {
                return;
            }
            bitmap.fill(kBugcheckBitmapBackground);
            {
                QPainter painter(&bitmap);
                painter.setCompositionMode(QPainter::CompositionMode_SourceOver);
                painter.drawImage(0, 0, darkCompatibleSource);
            }

            const std::uint32_t kWidth = static_cast<std::uint32_t>(bitmap.width());
            const std::uint32_t kHeight = static_cast<std::uint32_t>(bitmap.height());
            const std::uint32_t kStride = kWidth * 4U;
            if (bitmap.bytesPerLine() < static_cast<qsizetype>(kStride))
            {
                return;
            }

            std::vector<std::uint8_t> pixels(
                static_cast<std::size_t>(kStride) * kHeight);
            for (std::uint32_t y = 0; y < kHeight; ++y)
            {
                std::memcpy(
                    pixels.data() + static_cast<std::size_t>(y) * kStride,
                    bitmap.constScanLine(static_cast<int>(y)),
                    kStride);
            }

            (void)ksword::ark::DriverClient().setBugcheckBitmap(
                kWidth,
                kHeight,
                kStride,
                kBrandColor,
                pixels);
        });
    }

    constexpr int kBugcheckVerdictWidth =
        static_cast<int>(KSWORD_ARK_BUGCHECK_VERDICT_MAX_WIDTH);

    constexpr int kBugcheckVerdictMaxHeight =
        static_cast<int>(KSWORD_ARK_BUGCHECK_VERDICT_MAX_HEIGHT);

    constexpr int kBugcheckVerdictPadding = 8;

    QImage renderBugcheckVerdictCard(const QString& text, const QFont& systemFont)
    {
        constexpr int kTextFlags =
            Qt::AlignLeft | Qt::AlignVCenter | Qt::TextWordWrap;
        QFont verdictFont = systemFont;
        QRect textBounds;

        verdictFont.setWeight(QFont::DemiBold);
        for (int pixelSize = 18; pixelSize >= 12; --pixelSize)
        {
            verdictFont.setPixelSize(pixelSize);
            const QFontMetrics kMetrics(verdictFont);
            textBounds = kMetrics.boundingRect(
                QRect(
                    0,
                    0,
                    kBugcheckVerdictWidth - kBugcheckVerdictPadding * 2,
                    2048),
                kTextFlags,
                text);
            if (textBounds.height() + kBugcheckVerdictPadding * 2 <=
                kBugcheckVerdictMaxHeight)
            {
                break;
            }
        }

        const int kCardHeight = std::clamp(
            textBounds.height() + kBugcheckVerdictPadding * 2,
            48,
            kBugcheckVerdictMaxHeight);
        QImage card(
            kBugcheckVerdictWidth,
            kCardHeight,
            QImage::Format_ARGB32);
        if (card.isNull())
        {
            return {};
        }

        card.fill(kBugcheckBitmapBackground);
        QPainter painter(&card);
        painter.setRenderHint(QPainter::TextAntialiasing, true);
        painter.setCompositionMode(QPainter::CompositionMode_SourceOver);
        painter.setFont(verdictFont);
        painter.setPen(QColor::fromRgba(kBugcheckBitmapLightText));
        painter.drawText(
            QRect(
                kBugcheckVerdictPadding,
                kBugcheckVerdictPadding,
                card.width() - kBugcheckVerdictPadding * 2,
                card.height() - kBugcheckVerdictPadding * 2),
            kTextFlags,
            text);
        painter.end();
        return card;
    }

    bool appendBugcheckVerdictBitmap(
        std::vector<ksword::ark::BugcheckVerdictBitmap>& resources,
        const std::uint32_t language,
        const std::uint32_t classification,
        const QString& text,
        const QFont& systemFont)
    {
        const QImage kCard = renderBugcheckVerdictCard(text, systemFont);
        if (kCard.isNull())
        {
            return false;
        }

        ksword::ark::BugcheckVerdictBitmap resource;
        resource.language = language;
        resource.classification = classification;
        resource.width = static_cast<std::uint32_t>(kCard.width());
        resource.height = static_cast<std::uint32_t>(kCard.height());
        resource.stride = resource.width * 4U;
        if (kCard.bytesPerLine() < static_cast<qsizetype>(resource.stride))
        {
            return false;
        }
        resource.bgraPixels.resize(
            static_cast<std::size_t>(resource.stride) * resource.height);
        for (std::uint32_t y = 0; y < resource.height; ++y)
        {
            std::memcpy(
                resource.bgraPixels.data() +
                    static_cast<std::size_t>(y) * resource.stride,
                kCard.constScanLine(static_cast<int>(y)),
                resource.stride);
        }
        resources.push_back(std::move(resource));
        return true;
    }

    void queueBugcheckVerdictResourceUpload()
    {
        const QFont kSystemFont =
            QFontDatabase::systemFont(QFontDatabase::GeneralFont);
        QThreadPool::globalInstance()->start([kSystemFont]()
        {
            const std::array<std::uint32_t, 4> kClassifications{
                KSWORD_ARK_BUGCHECK_VERDICT_CLASS_OURS,
                KSWORD_ARK_BUGCHECK_VERDICT_CLASS_MICROSOFT,
                KSWORD_ARK_BUGCHECK_VERDICT_CLASS_THIRD_PARTY,
                KSWORD_ARK_BUGCHECK_VERDICT_CLASS_UNKNOWN
            };
            const std::array<QString, 4> kChineseTexts{
                QStringLiteral("这是KswordARK的问题，我们非常抱歉。请您尽快将MiniDump发送给开发者以取得修复。"),
                QStringLiteral("这不是KswordARK的问题，而是微软的屎山代码发力了。向技术人员发送MiniDump或此页面的照片。"),
                QStringLiteral("这不是KswordARK的问题，也不是微软的问题，而是第三方驱动程序的问题。向技术人员发送MiniDump或此页面的照片。"),
                QStringLiteral("这不是任何人的问题，你电脑就是炸了。重启、重装、重买。")
            };
            const std::array<QString, 4> kEnglishTexts{
                QStringLiteral("This is a KswordARK problem. We are very sorry. Please send the MiniDump to the developers as soon as possible so it can be fixed."),
                QStringLiteral("This is not a KswordARK problem. Microsoft's spaghetti code struck again. Send the MiniDump or a photo of this page to technical support."),
                QStringLiteral("This is neither a KswordARK nor a Microsoft problem. A third-party driver is responsible. Send the MiniDump or a photo of this page to technical support."),
                QStringLiteral("This is nobody's fault. Your computer just exploded. Restart it, reinstall it, or buy a new one.")
            };

            std::vector<ksword::ark::BugcheckVerdictBitmap> resources;
            resources.reserve(KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT);
            for (std::size_t index = 0; index < kClassifications.size(); ++index)
            {
                if (!appendBugcheckVerdictBitmap(
                        resources,
                        KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_CHINESE,
                        kClassifications[index],
                        kChineseTexts[index],
                        kSystemFont) ||
                    !appendBugcheckVerdictBitmap(
                        resources,
                        KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_ENGLISH,
                        kClassifications[index],
                        kEnglishTexts[index],
                        kSystemFont))
                {
                    return;
                }
            }
            (void)ksword::ark::DriverClient().setBugcheckVerdictResources(
                resources);
        });
    }
}

using namespace ksword::ui::main_window;

void MainWindow::updateBugcheckDiagnosticsEntryVisibility()
{
    const bool kShouldShowEntry =
        currentAppearanceSettings_.bugcheckDiagnosticsAutoInstallEnabled ||
        bugcheckDiagnosticsInstalledForSession_ ||
        bugcheckDiagnosticsEntryRequestedForSession_;
    if (miscWidget_ != nullptr)
    {
        // The Miscellaneous page uses hiding instead of deletion for the Tab, ensuring that pages already constructed can safely destruct even if automatic installation is cancelled.
        miscWidget_->setBugcheckDiagnosticsVisible(kShouldShowEntry);
    }
}

void MainWindow::installBugcheckDiagnosticsAfterServiceStart()
{
    if (!r0DriverServiceRunning_ ||
        !currentAppearanceSettings_.bugcheckDiagnosticsAutoInstallEnabled)
    {
        return;
    }

    // BGP parsing and pre-generation can be time-consuming; both automatic and manual installations wait for R0 IOCTL on a worker thread.
    const QPointer<MainWindow> kGuardedSelf(this);
    QThreadPool::globalInstance()->start(
        [kGuardedSelf]()
        {
            const ksword::ark::BugcheckDiagnosticsResult kResult =
                ksword::ark::DriverClient().configureBugcheckDiagnostics(
                    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_INSTALL);
            QCoreApplication* const kApplication = QCoreApplication::instance();
            if (kApplication == nullptr)
            {
                return;
            }

            if (!kGuardedSelf.isNull())
            {
                QMetaObject::invokeMethod(
                    kGuardedSelf,
                    [kGuardedSelf, kResult]()
                {
                    if (kGuardedSelf == nullptr)
                    {
                        return;
                    }

                    KLogEvent logEvent;
                    if (kResult.io.ok &&
                        kResult.response.status ==
                            KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK)
                    {
                        kGuardedSelf->bugcheckDiagnosticsInstalledForSession_ = true;
                        kGuardedSelf->updateBugcheckDiagnosticsEntryVisibility();
                        queueBugcheckVerdictResourceUpload();
                        info << logEvent
                            << "[MainWindow][R0] 已按配置安装蓝屏诊断, callbackMask=0x"
                            << std::hex
                            << kResult.response.callbackMask
                            << std::dec
                            << eol;
                    }
                    else
                    {
                        warn << logEvent
                            << "[MainWindow][R0] 自动安装蓝屏诊断失败, win32="
                            << kResult.io.win32Error
                            << ", protocol="
                            << kResult.response.status
                            << ", ntstatus=0x"
                            << std::hex
                            << static_cast<unsigned long>(kResult.response.lastStatus)
                            << std::dec
                            << eol;
                    }
                },
                Qt::QueuedConnection);
            }
        });
}
