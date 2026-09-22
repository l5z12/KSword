#include "HttpsProxyService.h"
#include "../../../shared/platform/network/NetworkConnectionTools.h"

#include <algorithm>

#include <QtCore/QCoreApplication>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QProcess>
#include <QtCore/QPointer>
#include <QtCore/QStandardPaths>
#include <QtCore/QThread>
#include <QtCore/QThreadPool>
#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslCipher>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslError>
#include <QtNetwork/QSslKey>
#include <QtNetwork/QSslSocket>
#include <QtNetwork/QTcpServer>
#include <QtNetwork/QTcpSocket>

#include <utility>
#include <vector>

// Windows certificate store:
// - isRootTrusted directly queries the current user's ROOT store, replacing the previous approach of launching powershell.exe just for a boolean value.
// - windows.h and WinSock2.h are already included by network_connection_tools.h; only the wincrypt declaration is added here.
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

namespace ks::network
{
    namespace
    {
        // kRootSubjectText usage: Unified root certificate Subject text.
        constexpr const char* kRootSubjectText = "CN=Ksword HTTPS Root CA";
        // kRootFriendlyText: Purpose: Unified root certificate FriendlyName.
        constexpr const char* kRootFriendlyText = "Ksword HTTPS Root CA";
        // kPfxPasswordText usage: Fixed password used when exporting the PFX.
        constexpr const char* kPfxPasswordText = "KswordHttpsProxy!2026";
        // kMaxConnectHeaderBytes: Limits CONNECT header cache size to prevent malicious accumulation.
        constexpr int kMaxConnectHeaderBytes = 32 * 1024;
        // kMaxHttpHeaderBytes usage: Limits the size of a single HTTP request or response header to prevent abnormal traffic from continuously occupying session memory.
        constexpr int kMaxHttpHeaderBytes = 64 * 1024;
        // kMaxPendingPlainBytes usage: Limits plaintext pending before TLS handshake completion to prevent unbounded caching due to slow handshakes.
        constexpr int kMaxPendingPlainBytes = 4 * 1024 * 1024;
        // kPowerShellTimeoutMs usage: Maximum execution time for a single PowerShell script.
        constexpr int kPowerShellTimeoutMs = 120000;
        // kSessionStopFirstWaitMs: Maximum wait time for the first round when stopping the proxy for a single session thread.
        constexpr int kSessionStopFirstWaitMs = 3000;
        // kSessionStopFinalWaitMs usage: Maximum additional wait time for a single session thread after a request interruption.
        constexpr int kSessionStopFinalWaitMs = 5000;

        // quoteForPowerShell:
        // - Wrap the text as a PowerShell single-quoted literal.
        QString quoteForPowerShell(const QString& textValue)
        {
            QString escapedText = textValue;
            escapedText.replace('\'', QStringLiteral("''"));
            return QStringLiteral("'%1'").arg(escapedText);
        }

        // powerShellExecutionMutex:
        // - Returns the process-level PowerShell serialization lock.
        // - The background root certificate task and the session thread's leaf certificate generation share the same working directory.
        //   Execution must be serialized to avoid a race condition where one party exports root_ca.pfx while the other reads it simultaneously.
        // Returns: A reference to the process-unique mutex.
        std::mutex& powerShellExecutionMutex()
        {
            static std::mutex executionMutex;
            return executionMutex;
        }

        // executePowerShellScript:
        // - Synchronously execute a PowerShell script; it relies solely on value-type input parameters and can be called from any thread.
        // Parameter scriptText: script text.
        // Parameter standardOutputOut: standard output, may be null.
        // Parameter standardErrorOut: standard error, may be null.
        // Parameter errorTextOut: error text output on failure, may be null.
        // Returns: true = execution successful; false = launch failed, timed out, or non-zero exit code.
        bool executePowerShellScript(
            const QString& scriptText,
            QString* standardOutputOut,
            QString* standardErrorOut,
            QString* errorTextOut)
        {
            const std::lock_guard<std::mutex> kExecutionGuard(powerShellExecutionMutex());

            QProcess processObject;
            processObject.setProgram(QStringLiteral("powershell.exe"));

            const QByteArray kUtf16ScriptBytes(
                reinterpret_cast<const char*>(scriptText.utf16()),
                scriptText.size() * static_cast<int>(sizeof(char16_t)));
            processObject.setArguments({
                QStringLiteral("-NoProfile"),
                QStringLiteral("-ExecutionPolicy"),
                QStringLiteral("Bypass"),
                QStringLiteral("-EncodedCommand"),
                QString::fromLatin1(kUtf16ScriptBytes.toBase64())
                });
            processObject.start();

            if (!processObject.waitForStarted(2000))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("PowerShell 启动失败。");
                }
                return false;
            }

            if (!processObject.waitForFinished(kPowerShellTimeoutMs))
            {
                processObject.kill();
                processObject.waitForFinished(2000);
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("PowerShell 执行超时。");
                }
                return false;
            }

            const QString kStandardOutputText = QString::fromLocal8Bit(processObject.readAllStandardOutput()).trimmed();
            const QString kStandardErrorText = QString::fromLocal8Bit(processObject.readAllStandardError()).trimmed();
            if (standardOutputOut != nullptr)
            {
                *standardOutputOut = kStandardOutputText;
            }
            if (standardErrorOut != nullptr)
            {
                *standardErrorOut = kStandardErrorText;
            }

            if (processObject.exitStatus() != QProcess::NormalExit || processObject.exitCode() != 0)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("PowerShell 执行失败：%1")
                        .arg(kStandardErrorText.isEmpty() ? QStringLiteral("unknown") : kStandardErrorText);
                }
                return false;
            }
            return true;
        }

        // buildRootCertificateScriptText:
        // - Generate a PowerShell script to ensure the root certificate exists (optional import of trusted root);
        // - Synchronous and asynchronous paths share the same script to avoid text drift in two places.
        // Parameter rootPfxPath: Root certificate PFX path.
        // Parameter rootCerPath: Root certificate CER path.
        // Parameter installToTrustStore: whether to import the root certificate into the current user's trusted root store.
        // Return: Script text ready to be passed directly to executePowerShellScript.
        QString buildRootCertificateScriptText(
            const QString& rootPfxPath,
            const QString& rootCerPath,
            const bool installToTrustStore)
        {
            const QString kInstallFlagText = installToTrustStore ? QStringLiteral("1") : QStringLiteral("0");
            return QStringLiteral(
                "$ErrorActionPreference='Stop'; "
                "$ProgressPreference='SilentlyContinue'; "
                "$pfxPath=%1; "
                "$cerPath=%2; "
                "$installRoot=%3; "
                "$friendly=%4; "
                "$subject=%5; "
                "$pwd=ConvertTo-SecureString %6 -AsPlainText -Force; "
                "$rootCert=$null; "
                "if(Test-Path $pfxPath){ "
                "  $pfxData=Get-PfxData -FilePath $pfxPath -Password $pwd; "
                "  $thumb=$pfxData.EndEntityCertificates[0].Thumbprint; "
                "  $rootCert=Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1; "
                "  if($null -eq $rootCert){ "
                "    Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\\CurrentUser\\My -Password $pwd | Out-Null; "
                "    $rootCert=Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1; "
                "  } "
                "} "
                "if($null -eq $rootCert){ "
                "  $rootCert=Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { $_.FriendlyName -eq $friendly -or $_.Subject -eq $subject } | Sort-Object NotAfter -Descending | Select-Object -First 1; "
                "} "
                "if($null -ne $rootCert -and -not $rootCert.HasPrivateKey){ "
                "  Remove-Item -Path ('Cert:\\CurrentUser\\My\\' + $rootCert.Thumbprint) -Force -ErrorAction SilentlyContinue; "
                "  $rootCert=$null; "
                "} "
                "if($null -eq $rootCert){ "
                "  $rootCert=New-SelfSignedCertificate -Type Custom -Subject $subject -FriendlyName $friendly -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm sha256 "
                "    -CertStoreLocation 'Cert:\\CurrentUser\\My' -KeyExportPolicy Exportable -KeyUsage CertSign,CRLSign,DigitalSignature "
                "    -TextExtension @('2.5.29.19={critical}{text}ca=true&pathlength=1') -NotAfter (Get-Date).AddYears(10); "
                "} "
                "Export-PfxCertificate -Cert $rootCert -FilePath $pfxPath -Password $pwd -Force | Out-Null; "
                "Export-Certificate -Cert $rootCert -FilePath $cerPath -Force | Out-Null; "
                "if($installRoot -eq '1'){ "
                "  $trusted=Get-ChildItem Cert:\\CurrentUser\\Root | Where-Object { $_.Thumbprint -eq $rootCert.Thumbprint } | Select-Object -First 1; "
                "  if($null -eq $trusted){ Import-Certificate -FilePath $cerPath -CertStoreLocation 'Cert:\\CurrentUser\\Root' | Out-Null; } "
                "} "
                "Write-Output $rootCert.Thumbprint;")
                .arg(quoteForPowerShell(rootPfxPath))
                .arg(quoteForPowerShell(rootCerPath))
                .arg(quoteForPowerShell(kInstallFlagText))
                .arg(quoteForPowerShell(QString::fromLatin1(kRootFriendlyText)))
                .arg(quoteForPowerShell(QString::fromLatin1(kRootSubjectText)))
                .arg(quoteForPowerShell(QString::fromLatin1(kPfxPasswordText)));
        }

        // isThumbprintInCurrentUserRootStore:
        // - Searches for certificates by SHA-1 thumbprint in the 'Current User - Trusted Root Certification Authorities' store.
        // - Pure local CryptoAPI calls with microsecond-level return times, safe for direct use on the UI thread.
        // Parameter thumbprintBytes: Certificate SHA-1 fingerprint (20 bytes).
        // Returns: true if the thumbprint is in the trusted root store; false if not found or the store cannot be opened.
        bool isThumbprintInCurrentUserRootStore(const QByteArray& thumbprintBytes)
        {
            if (thumbprintBytes.size() != 20)
            {
                return false;
            }

            const HCERTSTORE kTrustedRootStoreHandle = ::CertOpenSystemStoreW(0, L"ROOT");
            if (kTrustedRootStoreHandle == nullptr)
            {
                return false;
            }

            CRYPT_HASH_BLOB thumbprintBlob{};
            thumbprintBlob.cbData = static_cast<DWORD>(thumbprintBytes.size());
            thumbprintBlob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(thumbprintBytes.constData()));

            const PCCERT_CONTEXT kMatchedCertificateContext = ::CertFindCertificateInStore(
                kTrustedRootStoreHandle,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SHA1_HASH,
                &thumbprintBlob,
                nullptr);
            const bool kCertificateTrusted = kMatchedCertificateContext != nullptr;
            if (kMatchedCertificateContext != nullptr)
            {
                ::CertFreeCertificateContext(kMatchedCertificateContext);
            }
            ::CertCloseStore(kTrustedRootStoreHandle, 0);
            return kCertificateTrusted;
        }

        // currentTimestampMs:
        // - Returns the current Unix timestamp in milliseconds.
        std::uint64_t currentTimestampMs()
        {
            return static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
        }

        // sslProtocolToText:
        // - Converts Qt SSL protocol enumerations to human-readable text.
        QString sslProtocolToText(const QSsl::SslProtocol protocolValue)
        {
            switch (protocolValue)
            {
            case QSsl::TlsV1_2:
                return QStringLiteral("TLS 1.2");
            case QSsl::TlsV1_3:
                return QStringLiteral("TLS 1.3");
            case QSsl::TlsV1_2OrLater:
                return QStringLiteral("TLS 1.2+");
            default:
                return QStringLiteral("Unknown");
            }
        }

        // parseConnectAuthority:
        // - Parse CONNECT authority, supporting host:port and [ipv6]:port.
        bool parseConnectAuthority(const QByteArray& authorityText, QString* hostOut, std::uint16_t* portOut)
        {
            if (hostOut == nullptr || portOut == nullptr)
            {
                return false;
            }

            const QString kTrimmedAuthority = QString::fromUtf8(authorityText).trimmed();
            if (kTrimmedAuthority.startsWith('['))
            {
                const int kCloseIndex = kTrimmedAuthority.indexOf(']');
                const int kColonIndex = kTrimmedAuthority.lastIndexOf(':');
                if (kCloseIndex <= 0 || kColonIndex <= kCloseIndex)
                {
                    return false;
                }

                bool parseOk = false;
                const int kPortValue = kTrimmedAuthority.mid(kColonIndex + 1).toInt(&parseOk, 10);
                if (!parseOk || kPortValue <= 0 || kPortValue > 65535)
                {
                    return false;
                }

                *hostOut = kTrimmedAuthority.mid(1, kCloseIndex - 1);
                *portOut = static_cast<std::uint16_t>(kPortValue);
                return !hostOut->isEmpty();
            }

            const int kColonIndex = kTrimmedAuthority.lastIndexOf(':');
            if (kColonIndex <= 0)
            {
                return false;
            }

            bool parseOk = false;
            const int kPortValue = kTrimmedAuthority.mid(kColonIndex + 1).toInt(&parseOk, 10);
            if (!parseOk || kPortValue <= 0 || kPortValue > 65535)
            {
                return false;
            }

            *hostOut = kTrimmedAuthority.left(kColonIndex).trimmed();
            *portOut = static_cast<std::uint16_t>(kPortValue);
            return !hostOut->isEmpty();
        }

        // rewriteRequestHeaderToCloseConnection:
        // - Force rewrite the request header to Connection: close.
        // - Remove proxy residue fields such as Proxy-Connection.
        QByteArray rewriteRequestHeaderToCloseConnection(const QByteArray& originalHeaderBlock)
        {
            const QList<QByteArray> kRawLineList = originalHeaderBlock.split('\n');
            QList<QByteArray> outputLineList;
            outputLineList.reserve(kRawLineList.size() + 3);

            bool firstLineHandled = false;
            for (const QByteArray& rawLine : kRawLineList)
            {
                QByteArray lineText = rawLine;
                if (lineText.endsWith('\r'))
                {
                    lineText.chop(1);
                }

                if (!firstLineHandled)
                {
                    outputLineList.push_back(lineText);
                    firstLineHandled = true;
                    continue;
                }
                if (lineText.isEmpty())
                {
                    continue;
                }

                const int kColonIndex = lineText.indexOf(':');
                if (kColonIndex <= 0)
                {
                    continue;
                }

                const QByteArray kHeaderName = lineText.left(kColonIndex).trimmed().toLower();
                if (kHeaderName == "connection" || kHeaderName == "proxy-connection" || kHeaderName == "keep-alive")
                {
                    continue;
                }
                outputLineList.push_back(lineText);
            }

            outputLineList.push_back(QByteArrayLiteral("Connection: close"));
            outputLineList.push_back(QByteArray());
            outputLineList.push_back(QByteArray());
            return outputLineList.join("\r\n");
        }

        // headerValue function: reads the value of a specified field from the HTTP header block; field name comparison is case-insensitive.
        QByteArray headerValue(const QByteArray& headerBlock, const QByteArray& headerName)
        {
            const QList<QByteArray> kLineList = headerBlock.split('\n');
            for (int lineIndex = 1; lineIndex < kLineList.size(); ++lineIndex)
            {
                const QByteArray kLineText = kLineList.at(lineIndex).trimmed();
                const int kColonIndex = kLineText.indexOf(':');
                if (kColonIndex <= 0)
                {
                    continue;
                }
                if (kLineText.left(kColonIndex).trimmed().compare(headerName, Qt::CaseInsensitive) == 0)
                {
                    return kLineText.mid(kColonIndex + 1).trimmed();
                }
            }
            return {};
        }

        // contentLengthFromHeader purpose: Parse HTTP Content-Length; return -1 if unknown, missing, or invalid.
        qint64 contentLengthFromHeader(const QByteArray& headerBlock)
        {
            bool parseOk = false;
            const qlonglong kContentLength = QString::fromLatin1(headerValue(headerBlock, QByteArrayLiteral("Content-Length"))).toLongLong(&parseOk, 10);
            return parseOk && kContentLength >= 0 ? static_cast<qint64>(kContentLength) : -1;
        }

        // populateRemoteTlsMetadata: Writes verified remote TLS session and certificate information into the parsed record.
        void populateRemoteTlsMetadata(HttpsProxyParsedEntry* parsedEntry, const QSslSocket* remoteSocket)
        {
            if (parsedEntry == nullptr || remoteSocket == nullptr)
            {
                return;
            }

            parsedEntry->tlsVersionText = sslProtocolToText(remoteSocket->sessionProtocol());
            parsedEntry->alpnText = QString::fromLatin1(remoteSocket->sslConfiguration().nextNegotiatedProtocol());
            parsedEntry->cipherSuiteText = remoteSocket->sessionCipher().name();

            const QSslCertificate kPeerCertificate = remoteSocket->peerCertificate();
            if (kPeerCertificate.isNull())
            {
                return;
            }

            parsedEntry->certificateSubjectText = kPeerCertificate.subjectInfo(QSslCertificate::CommonName).join(QStringLiteral(", "));
            parsedEntry->certificateIssuerText = kPeerCertificate.issuerInfo(QSslCertificate::CommonName).join(QStringLiteral(", "));
            parsedEntry->certificateExpiryText = kPeerCertificate.expiryDate().toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
            parsedEntry->certificateSha256Text = QString::fromLatin1(
                QCryptographicHash::hash(kPeerCertificate.toDer(), QCryptographicHash::Sha256).toHex(':'));
        }

        class ProxySession final : public QObject
        {
        public:
            using HostCertLoader = std::function<bool(const QString&, QSslCertificate*, QSslKey*, QString*)>;
            using ParsedEmitter = std::function<void(const HttpsProxyParsedEntry&)>;
            using StatusEmitter = std::function<void(const QString&)>;

            ProxySession(
                const std::uint64_t sessionIdValue,
                const qintptr socketDescriptorValue,
                HostCertLoader hostCertLoaderValue,
                ParsedEmitter parsedEmitterValue,
                StatusEmitter statusEmitterValue)
                : QObject(nullptr)
                , kMSessionId(sessionIdValue)
                , kMSocketDescriptor(socketDescriptorValue)
                , hostCertLoader_(std::move(hostCertLoaderValue))
                , parsedEmitter_(std::move(parsedEmitterValue))
                , statusEmitter_(std::move(statusEmitterValue))
            {
            }

            void initialize()
            {
                clientSocket_ = new QSslSocket();
                clientSocket_->setParent(this);
                if (!clientSocket_->setSocketDescriptor(kMSocketDescriptor))
                {
                    emitStatusLine(QStringLiteral("HTTPS代理接管客户端套接字失败：%1").arg(clientSocket_->errorString()));
                    deleteLater();
                    return;
                }

                connect(clientSocket_, &QSslSocket::readyRead, this, [this]() { onClientReadyRead(); });
                connect(clientSocket_, &QSslSocket::disconnected, this, [this]() { closePeerAndDelete(); });
                connect(clientSocket_, &QSslSocket::sslErrors, this, [this](const QList<QSslError>& errorList) {
                    failWithError(QStringLiteral("客户端 TLS 失败：%1")
                        .arg(errorList.isEmpty() ? clientSocket_->errorString() : errorList.first().errorString()));
                });
            }

            // requestStop: Called from the service shutdown path on the session's thread; closes the socket before destroying the session.
            void requestStop()
            {
                closePeerAndDelete();
            }

        private:
            void onClientReadyRead()
            {
                if (clientSocket_ == nullptr)
                {
                    return;
                }

                if (!connectReady_)
                {
                    connectHeaderBuffer_ += clientSocket_->readAll();
                    if (connectHeaderBuffer_.size() > kMaxConnectHeaderBytes)
                    {
                        failWithError(QStringLiteral("CONNECT 请求头过大。"));
                        return;
                    }

                    const int kHeaderEndIndex = connectHeaderBuffer_.indexOf("\r\n\r\n");
                    if (kHeaderEndIndex < 0)
                    {
                        return;
                    }

                    const QByteArray kHeaderBlock = connectHeaderBuffer_.left(kHeaderEndIndex + 4);
                    if (!handleConnectHeader(kHeaderBlock))
                    {
                        return;
                    }
                    connectHeaderBuffer_.clear();
                    return;
                }

                const QByteArray kPlainBytes = clientSocket_->readAll();
                if (kPlainBytes.isEmpty())
                {
                    return;
                }

                if (!requestHeaderHandled_)
                {
                    requestHeaderBuffer_ += kPlainBytes;
                    if (requestHeaderBuffer_.size() > kMaxHttpHeaderBytes)
                    {
                        failWithError(QStringLiteral("HTTP 请求头过大。"));
                        return;
                    }
                    const int kHeaderEndIndex = requestHeaderBuffer_.indexOf("\r\n\r\n");
                    if (kHeaderEndIndex < 0)
                    {
                        return;
                    }

                    const QByteArray kOriginalHeaderBlock = requestHeaderBuffer_.left(kHeaderEndIndex + 4);
                    const QByteArray kBodyRemainder = requestHeaderBuffer_.mid(kHeaderEndIndex + 4);
                    forwardToRemote(rewriteRequestHeaderToCloseConnection(kOriginalHeaderBlock) + kBodyRemainder);
                    emitRequestParsedEvent(kOriginalHeaderBlock);
                    requestHeaderBuffer_.clear();
                    requestHeaderHandled_ = true;
                    return;
                }

                forwardToRemote(kPlainBytes);
            }

            bool handleConnectHeader(const QByteArray& headerBlock)
            {
                const QList<QByteArray> kLineList = headerBlock.split('\n');
                if (kLineList.isEmpty())
                {
                    failWithError(QStringLiteral("CONNECT 请求为空。"));
                    return false;
                }

                const QList<QByteArray> kFirstLineParts = kLineList.first().trimmed().split(' ');
                if (kFirstLineParts.size() < 3 || kFirstLineParts.at(0).toUpper() != "CONNECT")
                {
                    failWithError(QStringLiteral("当前代理仅支持 HTTPS CONNECT。"));
                    return false;
                }

                if (!parseConnectAuthority(kFirstLineParts.at(1), &targetHostText_, &targetPort_))
                {
                    failWithError(QStringLiteral("CONNECT 目标解析失败。"));
                    return false;
                }

                clientProcessText_ = resolveClientProcessText();
                emitConnectEvent(headerBlock);
                connectReady_ = true;
                sessionStartedTimestampMs_ = currentTimestampMs();
                clientSocket_->write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: Ksword\r\n\r\n");
                clientSocket_->flush();

                QSslCertificate localCertificate;
                QSslKey localPrivateKey;
                QString errorText;
                if (!hostCertLoader_(targetHostText_, &localCertificate, &localPrivateKey, &errorText))
                {
                    failWithError(QStringLiteral("站点证书加载失败：%1").arg(errorText));
                    return false;
                }

                QSslConfiguration clientConfiguration = QSslConfiguration::defaultConfiguration();
                clientConfiguration.setProtocol(QSsl::TlsV1_2OrLater);
                clientConfiguration.setPeerVerifyMode(QSslSocket::VerifyNone);
                clientConfiguration.setAllowedNextProtocols({ QByteArrayLiteral("http/1.1") });
                clientConfiguration.setLocalCertificate(localCertificate);
                clientConfiguration.setPrivateKey(localPrivateKey);
                clientSocket_->setSslConfiguration(clientConfiguration);
                connect(clientSocket_, &QSslSocket::encrypted, this, [this]() { clientEncrypted_ = true; flushPendingToClient(); });

                remoteSocket_ = new QSslSocket(this);
                connect(remoteSocket_, &QSslSocket::encrypted, this, [this]() { onRemoteEncrypted(); });
                connect(remoteSocket_, &QSslSocket::readyRead, this, [this]() { onRemoteReadyRead(); });
                connect(remoteSocket_, &QSslSocket::disconnected, this, [this]() { closePeerAndDelete(); });
                connect(remoteSocket_, &QSslSocket::sslErrors, this, [this](const QList<QSslError>& errorList) {
                    if (remoteSocket_ != nullptr)
                    {
                        failWithError(QStringLiteral("远端 TLS 证书验证失败：%1")
                            .arg(errorList.isEmpty() ? remoteSocket_->errorString() : errorList.first().errorString()));
                    }
                });
                connect(remoteSocket_, &QSslSocket::errorOccurred, this, [this](const QAbstractSocket::SocketError) {
                    if (remoteSocket_ != nullptr)
                    {
                        failWithError(QStringLiteral("远端 TLS 错误：%1").arg(remoteSocket_->errorString()));
                    }
                });

                QSslConfiguration remoteConfiguration = QSslConfiguration::defaultConfiguration();
                remoteConfiguration.setProtocol(QSsl::TlsV1_2OrLater);
                remoteConfiguration.setPeerVerifyMode(QSslSocket::VerifyPeer);
                remoteConfiguration.setAllowedNextProtocols({ QByteArrayLiteral("http/1.1") });
                remoteSocket_->setSslConfiguration(remoteConfiguration);
                remoteSocket_->setPeerVerifyName(targetHostText_);
                remoteSocket_->connectToHostEncrypted(targetHostText_, targetPort_);

                clientSocket_->startServerEncryption();
                return true;
            }

            void onRemoteEncrypted()
            {
                remoteEncrypted_ = true;
                HttpsProxyParsedEntry parsedEntry;
                parsedEntry.timestampMs = currentTimestampMs();
                parsedEntry.sessionId = kMSessionId;
                parsedEntry.clientEndpointText = clientEndpointText();
                parsedEntry.clientProcessText = clientProcessText_;
                parsedEntry.targetHostText = targetHostText_;
                parsedEntry.targetPort = static_cast<int>(targetPort_);
                parsedEntry.eventTypeText = QStringLiteral("TLS");
                parsedEntry.sniText = targetHostText_;
                populateRemoteTlsMetadata(&parsedEntry, remoteSocket_);
                parsedEntry.detailText = QStringLiteral("远端 TLS 握手完成，证书已验证。");
                emitParsedEntry(parsedEntry);
                emitStatusLine(QStringLiteral("HTTPS 会话 #%1 已建立：%2:%3").arg(kMSessionId).arg(targetHostText_).arg(targetPort_));
                flushPendingToRemote();
            }

            void onRemoteReadyRead()
            {
                if (remoteSocket_ == nullptr)
                {
                    return;
                }

                const QByteArray kPlainBytes = remoteSocket_->readAll();
                if (kPlainBytes.isEmpty())
                {
                    return;
                }

                if (!responseHeaderHandled_)
                {
                    responseHeaderBuffer_ += kPlainBytes;
                    if (responseHeaderBuffer_.size() > kMaxHttpHeaderBytes)
                    {
                        failWithError(QStringLiteral("HTTP 响应头过大。"));
                        return;
                    }
                    const int kHeaderEndIndex = responseHeaderBuffer_.indexOf("\r\n\r\n");
                    if (kHeaderEndIndex < 0)
                    {
                        return;
                    }

                    const QByteArray kHeaderBlock = responseHeaderBuffer_.left(kHeaderEndIndex + 4);
                    const QByteArray kBodyRemainder = responseHeaderBuffer_.mid(kHeaderEndIndex + 4);
                    forwardToClient(kHeaderBlock + kBodyRemainder);
                    emitResponseParsedEvent(kHeaderBlock);
                    responseHeaderBuffer_.clear();
                    responseHeaderHandled_ = true;
                    return;
                }

                forwardToClient(kPlainBytes);
            }

            void forwardToRemote(const QByteArray& plainBytes)
            {
                if (plainBytes.isEmpty())
                {
                    return;
                }
                if (remoteEncrypted_ && remoteSocket_ != nullptr)
                {
                    remoteSocket_->write(plainBytes);
                }
                else
                {
                    if (pendingToRemoteBytes_.size() + plainBytes.size() > kMaxPendingPlainBytes)
                    {
                        failWithError(QStringLiteral("等待远端 TLS 握手的请求数据过多。"));
                        return;
                    }
                    pendingToRemoteBytes_ += plainBytes;
                }
                uploadBytes_ += static_cast<std::uint64_t>(plainBytes.size());
            }

            void forwardToClient(const QByteArray& plainBytes)
            {
                if (plainBytes.isEmpty())
                {
                    return;
                }
                if (clientEncrypted_ && clientSocket_ != nullptr)
                {
                    clientSocket_->write(plainBytes);
                }
                else
                {
                    if (pendingToClientBytes_.size() + plainBytes.size() > kMaxPendingPlainBytes)
                    {
                        failWithError(QStringLiteral("等待客户端 TLS 握手的响应数据过多。"));
                        return;
                    }
                    pendingToClientBytes_ += plainBytes;
                }
                downloadBytes_ += static_cast<std::uint64_t>(plainBytes.size());
            }

            void flushPendingToRemote()
            {
                if (remoteEncrypted_ && remoteSocket_ != nullptr && !pendingToRemoteBytes_.isEmpty())
                {
                    remoteSocket_->write(pendingToRemoteBytes_);
                    pendingToRemoteBytes_.clear();
                }
            }

            void flushPendingToClient()
            {
                if (clientEncrypted_ && clientSocket_ != nullptr && !pendingToClientBytes_.isEmpty())
                {
                    clientSocket_->write(pendingToClientBytes_);
                    pendingToClientBytes_.clear();
                }
            }

            void emitConnectEvent(const QByteArray& rawHeaderBlock) const
            {
                HttpsProxyParsedEntry parsedEntry;
                parsedEntry.timestampMs = currentTimestampMs();
                parsedEntry.sessionId = kMSessionId;
                parsedEntry.clientEndpointText = clientEndpointText();
                parsedEntry.clientProcessText = clientProcessText_;
                parsedEntry.targetHostText = targetHostText_;
                parsedEntry.targetPort = static_cast<int>(targetPort_);
                parsedEntry.eventTypeText = QStringLiteral("CONNECT");
                parsedEntry.sniText = targetHostText_;
                parsedEntry.uploadBytes = uploadBytes_;
                parsedEntry.downloadBytes = downloadBytes_;
                parsedEntry.detailText = QStringLiteral("收到 CONNECT 请求。");
                parsedEntry.rawBytes = rawHeaderBlock;
                emitParsedEntry(parsedEntry);
            }

            void emitRequestParsedEvent(const QByteArray& headerBlock)
            {
                QString methodText;
                QString pathText;
                const QList<QByteArray> kLineList = headerBlock.split('\n');
                if (!kLineList.isEmpty())
                {
                    const QList<QByteArray> kFirstLineParts = kLineList.first().trimmed().split(' ');
                    methodText = QString::fromUtf8(kFirstLineParts.value(0));
                    pathText = QString::fromUtf8(kFirstLineParts.value(1));
                }

                HttpsProxyParsedEntry parsedEntry;
                parsedEntry.timestampMs = currentTimestampMs();
                parsedEntry.sessionId = kMSessionId;
                parsedEntry.clientEndpointText = clientEndpointText();
                parsedEntry.clientProcessText = clientProcessText_;
                parsedEntry.targetHostText = targetHostText_;
                parsedEntry.targetPort = static_cast<int>(targetPort_);
                parsedEntry.eventTypeText = QStringLiteral("REQUEST");
                parsedEntry.methodText = methodText;
                parsedEntry.pathText = pathText;
                parsedEntry.sniText = targetHostText_;
                parsedEntry.contentTypeText = QString::fromUtf8(headerValue(headerBlock, QByteArrayLiteral("Content-Type")));
                parsedEntry.contentLength = contentLengthFromHeader(headerBlock);
                parsedEntry.uploadBytes = uploadBytes_;
                parsedEntry.downloadBytes = downloadBytes_;
                requestTimestampMs_ = parsedEntry.timestampMs;
                parsedEntry.detailText = QStringLiteral("请求头已解析，内容正文仅转发，不保存。");
                parsedEntry.rawBytes = headerBlock;
                emitParsedEntry(parsedEntry);
            }

            void emitResponseParsedEvent(const QByteArray& headerBlock) const
            {
                int statusCode = 0;
                const QList<QByteArray> kLineList = headerBlock.split('\n');
                if (!kLineList.isEmpty())
                {
                    const QList<QByteArray> kFirstLineParts = kLineList.first().trimmed().split(' ');
                    bool parseOk = false;
                    statusCode = QString::fromUtf8(kFirstLineParts.value(1)).toInt(&parseOk, 10);
                    if (!parseOk)
                    {
                        statusCode = 0;
                    }
                }

                HttpsProxyParsedEntry parsedEntry;
                parsedEntry.timestampMs = currentTimestampMs();
                parsedEntry.sessionId = kMSessionId;
                parsedEntry.clientEndpointText = clientEndpointText();
                parsedEntry.clientProcessText = clientProcessText_;
                parsedEntry.targetHostText = targetHostText_;
                parsedEntry.targetPort = static_cast<int>(targetPort_);
                parsedEntry.eventTypeText = QStringLiteral("RESPONSE");
                parsedEntry.statusCode = statusCode;
                parsedEntry.contentTypeText = QString::fromUtf8(headerValue(headerBlock, QByteArrayLiteral("Content-Type")));
                parsedEntry.contentLength = contentLengthFromHeader(headerBlock);
                parsedEntry.uploadBytes = uploadBytes_;
                parsedEntry.downloadBytes = downloadBytes_;
                parsedEntry.elapsedMs = requestTimestampMs_ > 0 && parsedEntry.timestampMs >= requestTimestampMs_
                    ? parsedEntry.timestampMs - requestTimestampMs_
                    : 0;
                populateRemoteTlsMetadata(&parsedEntry, remoteSocket_);
                parsedEntry.detailText = QStringLiteral("响应头已解析，内容正文仅转发，不保存。");
                parsedEntry.rawBytes = headerBlock;
                emitParsedEntry(parsedEntry);
            }

            void failWithError(const QString& errorText)
            {
                if (closing_)
                {
                    return;
                }
                HttpsProxyParsedEntry parsedEntry;
                parsedEntry.timestampMs = currentTimestampMs();
                parsedEntry.sessionId = kMSessionId;
                parsedEntry.clientEndpointText = clientEndpointText();
                parsedEntry.clientProcessText = clientProcessText_;
                parsedEntry.targetHostText = targetHostText_;
                parsedEntry.targetPort = static_cast<int>(targetPort_);
                parsedEntry.eventTypeText = QStringLiteral("ERROR");
                parsedEntry.uploadBytes = uploadBytes_;
                parsedEntry.downloadBytes = downloadBytes_;
                populateRemoteTlsMetadata(&parsedEntry, remoteSocket_);
                parsedEntry.detailText = errorText;
                emitParsedEntry(parsedEntry);
                emitStatusLine(QStringLiteral("HTTPS 会话 #%1 失败：%2").arg(kMSessionId).arg(errorText));
                closePeerAndDelete();
            }

            QString clientEndpointText() const
            {
                if (clientSocket_ == nullptr)
                {
                    return QStringLiteral("N/A");
                }
                return QStringLiteral("%1:%2").arg(clientSocket_->peerAddress().toString()).arg(clientSocket_->peerPort());
            }

            // resolveClientProcessText purpose: Associate Windows TCP owners by local proxy connection four-tuple and supplement process dimension.
            QString resolveClientProcessText() const
            {
                if (clientSocket_ == nullptr)
                {
                    return QStringLiteral("未知");
                }

                std::vector<ks::network::TcpConnectionRecord> connectionRecordList;
                std::string errorText;
                if (!ks::network::enumerateTcpConnectionRecords(connectionRecordList, &errorText))
                {
                    return QStringLiteral("未知");
                }

                const QHostAddress kClientAddress = clientSocket_->peerAddress();
                const QHostAddress kProxyAddress = clientSocket_->localAddress();
                const std::uint16_t kClientPort = clientSocket_->peerPort();
                const std::uint16_t kProxyPort = clientSocket_->localPort();
                for (const ks::network::TcpConnectionRecord& connectionRecord : connectionRecordList)
                {
                    if (connectionRecord.localPort != kClientPort || connectionRecord.remotePort != kProxyPort)
                    {
                        continue;
                    }

                    const QHostAddress kRecordLocalAddress(QString::fromStdString(connectionRecord.localAddressText));
                    const QHostAddress kRecordRemoteAddress(QString::fromStdString(connectionRecord.remoteAddressText));
                    if (kRecordLocalAddress != kClientAddress || kRecordRemoteAddress != kProxyAddress)
                    {
                        continue;
                    }

                    const QString kProcessNameText = QString::fromUtf8(connectionRecord.processName.c_str());
                    return kProcessNameText.isEmpty()
                        ? QStringLiteral("PID %1").arg(connectionRecord.processId)
                        : QStringLiteral("%1 (PID %2)").arg(kProcessNameText).arg(connectionRecord.processId);
                }
                return QStringLiteral("未知");
            }

            void emitParsedEntry(const HttpsProxyParsedEntry& parsedEntry) const
            {
                if (parsedEmitter_)
                {
                    parsedEmitter_(parsedEntry);
                }
            }

            void emitStatusLine(const QString& statusText) const
            {
                if (statusEmitter_)
                {
                    statusEmitter_(statusText);
                }
            }

            void closePeerAndDelete()
            {
                if (closing_)
                {
                    return;
                }
                closing_ = true;
                emitSessionSummary();
                if (clientSocket_ != nullptr && clientSocket_->state() != QAbstractSocket::UnconnectedState)
                {
                    clientSocket_->disconnectFromHost();
                }
                if (remoteSocket_ != nullptr && remoteSocket_->state() != QAbstractSocket::UnconnectedState)
                {
                    remoteSocket_->disconnectFromHost();
                }
                deleteLater();
            }

            // emitSessionSummary: At session end, supplement readable total duration, up/down bytes, and TLS certificate info.
            void emitSessionSummary()
            {
                if (summaryEmitted_ || !connectReady_)
                {
                    return;
                }
                summaryEmitted_ = true;

                HttpsProxyParsedEntry parsedEntry;
                parsedEntry.timestampMs = currentTimestampMs();
                parsedEntry.sessionId = kMSessionId;
                parsedEntry.clientEndpointText = clientEndpointText();
                parsedEntry.clientProcessText = clientProcessText_;
                parsedEntry.targetHostText = targetHostText_;
                parsedEntry.targetPort = static_cast<int>(targetPort_);
                parsedEntry.eventTypeText = QStringLiteral("SUMMARY");
                parsedEntry.sniText = targetHostText_;
                parsedEntry.uploadBytes = uploadBytes_;
                parsedEntry.downloadBytes = downloadBytes_;
                parsedEntry.elapsedMs = sessionStartedTimestampMs_ > 0 && parsedEntry.timestampMs >= sessionStartedTimestampMs_
                    ? parsedEntry.timestampMs - sessionStartedTimestampMs_
                    : 0;
                populateRemoteTlsMetadata(&parsedEntry, remoteSocket_);
                parsedEntry.detailText = QStringLiteral("HTTPS 会话已结束。");
                emitParsedEntry(parsedEntry);
            }

        private:
            const std::uint64_t kMSessionId;          // m_sessionId: Current session ID.
            const qintptr kMSocketDescriptor = -1;    // m_socketDescriptor: Client socket descriptor.
            QSslSocket* clientSocket_ = nullptr;     // m_clientSocket: Client socket.
            QSslSocket* remoteSocket_ = nullptr;     // m_remoteSocket: Remote TLS socket.
            HostCertLoader hostCertLoader_;          // m_hostCertLoader: Leaf certificate loader.
            ParsedEmitter parsedEmitter_;            // m_parsedEmitter: Parsing result callback.
            StatusEmitter statusEmitter_;            // m_statusEmitter: Status text callback.
            QByteArray connectHeaderBuffer_;         // m_connectHeaderBuffer: CONNECT header buffer.
            QByteArray requestHeaderBuffer_;         // m_requestHeaderBuffer: Request header parsing buffer.
            QByteArray responseHeaderBuffer_;        // m_responseHeaderBuffer: Response header parse buffer.
            QByteArray pendingToRemoteBytes_;        // m_pendingToRemoteBytes: Bytes waiting to be forwarded to the remote endpoint.
            QByteArray pendingToClientBytes_;        // m_pendingToClientBytes: Bytes pending forwarding to the client.
            QString targetHostText_;                // m_targetHostText: The target host name.
            QString clientProcessText_;             // m_clientProcessText: Text indicating client process ownership.
            std::uint16_t targetPort_ = 0;          // m_targetPort: Target port.
            std::uint64_t sessionStartedTimestampMs_ = 0; // m_sessionStartedTimestampMs: CONNECT completion time.
            std::uint64_t requestTimestampMs_ = 0;  // m_requestTimestampMs: timestamp of the first request header parse.
            std::uint64_t uploadBytes_ = 0;         // m_uploadBytes: Number of plaintext bytes forwarded to the remote endpoint.
            std::uint64_t downloadBytes_ = 0;       // m_downloadBytes: Number of plaintext bytes forwarded to the client.
            bool connectReady_ = false;             // m_connectReady: Whether the CONNECT phase is complete.
            bool requestHeaderHandled_ = false;     // m_requestHeaderHandled: Whether the first request header has been parsed.
            bool responseHeaderHandled_ = false;    // m_responseHeaderHandled: Whether the first response header has been parsed.
            bool clientEncrypted_ = false;          // m_clientEncrypted: Whether client TLS is established.
            bool remoteEncrypted_ = false;          // m_remoteEncrypted: Whether remote TLS is established.
            bool summaryEmitted_ = false;           // m_summaryEmitted: Whether session summary records have been dispatched.
            bool closing_ = false;                  // m_closing: indicates whether the session is ending to prevent duplicate errors or summaries.
        };

        // ProxySessionRegistry: Centralizes active session threads to ensure synchronous cleanup upon proxy stop and destruction.
        class ProxySessionRegistry final
        {
        public:
            struct SessionWorker
            {
                QPointer<ProxySession> session; // session: session object, automatically set to null after destruction.
                QPointer<QThread> thread;       // thread: Thread carrying the session event loop.
            };

            bool add(ProxySession* sessionValue, QThread* threadValue)
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stopping_)
                {
                    return false;
                }
                sessionWorkerList_.push_back(SessionWorker{ sessionValue, threadValue });
                return true;
            }

            void remove(QThread* threadValue)
            {
                std::lock_guard<std::mutex> lock(mutex_);
                sessionWorkerList_.erase(
                    std::remove_if(
                        sessionWorkerList_.begin(),
                        sessionWorkerList_.end(),
                        [threadValue](const SessionWorker& worker)
                        {
                            return worker.thread.isNull() || worker.thread.data() == threadValue;
                        }),
                    sessionWorkerList_.end());
            }

            void stopAndWait()
            {
                std::vector<SessionWorker> sessionWorkerList;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    stopping_ = true;
                    sessionWorkerList = sessionWorkerList_;
                }

                for (const SessionWorker& worker : sessionWorkerList)
                {
                    const QPointer<ProxySession> kSession = worker.session;
                    if (!kSession.isNull())
                    {
                        const bool kQueued = QMetaObject::invokeMethod(
                            kSession.data(),
                            [kSession]()
                            {
                                if (!kSession.isNull())
                                {
                                    kSession->requestStop();
                                }
                            },
                            Qt::QueuedConnection);
                        if (kQueued)
                        {
                            continue;
                        }
                    }

                    if (!worker.thread.isNull())
                    {
                        worker.thread->quit();
                    }
                }

                // The session thread may be stuck on powershell.exe generating leaf certificates; wait with a timeout:
                // Perform an initial wait cycle; if it times out, request interruption and call quit again. If it still hasn't
                // exited, give up waiting. The caller (including the destructor path) must never hang indefinitely here.
                for (const SessionWorker& worker : sessionWorkerList)
                {
                    if (worker.thread.isNull() || worker.thread.data() == QThread::currentThread())
                    {
                        continue;
                    }
                    if (worker.thread->wait(kSessionStopFirstWaitMs))
                    {
                        continue;
                    }
                    worker.thread->requestInterruption();
                    worker.thread->quit();
                    worker.thread->wait(kSessionStopFinalWaitMs);
                }

                std::lock_guard<std::mutex> lock(mutex_);
                sessionWorkerList_.clear();
            }

        private:
            std::mutex mutex_; // m_mutex: Protects session registration and snapshot stopping.
            std::vector<SessionWorker> sessionWorkerList_; // m_sessionWorkerList: All session threads that have not yet ended.
            bool stopping_ = false; // m_stopping: Reject new session registration during the stopping phase.
        };

        class ProxyServer final : public QTcpServer
        {
        public:
            using HostCertLoader = ProxySession::HostCertLoader;
            using ParsedEmitter = ProxySession::ParsedEmitter;
            using StatusEmitter = ProxySession::StatusEmitter;
            using SessionIdProvider = std::function<std::uint64_t()>;

            ProxyServer(
                HostCertLoader hostCertLoaderValue,
                ParsedEmitter parsedEmitterValue,
                StatusEmitter statusEmitterValue,
                SessionIdProvider sessionIdProviderValue,
                std::shared_ptr<ProxySessionRegistry> sessionRegistryValue)
                : hostCertLoader_(std::move(hostCertLoaderValue))
                , parsedEmitter_(std::move(parsedEmitterValue))
                , statusEmitter_(std::move(statusEmitterValue))
                , sessionIdProvider_(std::move(sessionIdProviderValue))
                , sessionRegistry_(std::move(sessionRegistryValue))
            {
            }

        protected:
            void incomingConnection(qintptr socketDescriptor) override
            {
                const std::uint64_t kSessionId = sessionIdProvider_ ? sessionIdProvider_() : 0;
                QThread* sessionThread = new QThread();
                ProxySession* session = new ProxySession(
                    kSessionId,
                    socketDescriptor,
                    hostCertLoader_,
                    parsedEmitter_,
                    statusEmitter_);
                if (sessionRegistry_ != nullptr && !sessionRegistry_->add(session, sessionThread))
                {
                    QTcpSocket rejectedSocket;
                    rejectedSocket.setSocketDescriptor(socketDescriptor);
                    rejectedSocket.abort();
                    delete session;
                    delete sessionThread;
                    return;
                }
                session->moveToThread(sessionThread);
                connect(sessionThread, &QThread::started, session, [session]() { session->initialize(); });
                connect(session, &QObject::destroyed, sessionThread, &QThread::quit, Qt::DirectConnection);
                connect(sessionThread, &QThread::finished, session, &QObject::deleteLater);
                connect(
                    sessionThread,
                    &QThread::finished,
                    sessionThread,
                    [sessionRegistry = sessionRegistry_, sessionThread]()
                    {
                        if (sessionRegistry != nullptr)
                        {
                            sessionRegistry->remove(sessionThread);
                        }
                    },
                    Qt::DirectConnection);
                connect(sessionThread, &QThread::finished, sessionThread, &QObject::deleteLater);
                sessionThread->start();
            }

        private:
            HostCertLoader hostCertLoader_;      // m_hostCertLoader: Leaf certificate loader.
            ParsedEmitter parsedEmitter_;        // m_parsedEmitter: Parsing event callback.
            StatusEmitter statusEmitter_;        // m_statusEmitter: Status text callback.
            SessionIdProvider sessionIdProvider_; // m_sessionIdProvider: Session ID allocator.
            std::shared_ptr<ProxySessionRegistry> sessionRegistry_; // m_sessionRegistry: Active session thread registry.
        };
    }

    HttpsMitmProxyService::HttpsMitmProxyService()
        : QObject(nullptr)
    {
    }

    HttpsMitmProxyService::~HttpsMitmProxyService()
    {
        stop();
    }

    bool HttpsMitmProxyService::start(
        const QHostAddress& listenAddress,
        const std::uint16_t listenPort,
        QString* errorTextOut)
    {
        if (listenPort == 0)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("监听端口不能为 0。");
            }
            return false;
        }

        // In the normal flow, the UI calls ensureRootCertificateAsync beforehand to prepare the root certificate in the background; this performs a
        // single lock-free quick check. Synchronous generation is only triggered for abnormal cases like external deletion of the certificate file.
        if (!isRootCertificateReady())
        {
            QString errorText;
            if (!ensureRootCertificate(false, &errorText))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = errorText;
                }
                return false;
            }
        }

        stop();

        const QPointer<HttpsMitmProxyService> kSafeThis(this);

        auto hostCertLoader = [kSafeThis](const QString& hostName, QSslCertificate* certificateOut, QSslKey* privateKeyOut, QString* certErrorOut)
            {
                if (kSafeThis.isNull())
                {
                    if (certErrorOut != nullptr)
                    {
                        *certErrorOut = QStringLiteral("HTTPS代理服务已销毁。");
                    }
                    return false;
                }
                return kSafeThis->loadHostCertificateBundle(hostName, certificateOut, privateKeyOut, certErrorOut);
            };
        auto parsedEmitter = [kSafeThis](const HttpsProxyParsedEntry& parsedEntry)
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->emitParsedEntry(parsedEntry);
                }
            };
        auto statusEmitter = [kSafeThis](const QString& statusText)
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->emitStatus(statusText);
                }
            };
        auto sessionIdProvider = [kSafeThis]() -> std::uint64_t
            {
                if (kSafeThis.isNull())
                {
                    return 0;
                }
                return kSafeThis->nextSessionId_++;
            };
        const std::shared_ptr<ProxySessionRegistry> kSessionRegistry = std::make_shared<ProxySessionRegistry>();

        server_ = std::make_unique<ProxyServer>(
            std::move(hostCertLoader),
            std::move(parsedEmitter),
            std::move(statusEmitter),
            std::move(sessionIdProvider),
            kSessionRegistry);
        stopSessionWorkers_ = [kSessionRegistry]()
        {
            kSessionRegistry->stopAndWait();
        };

        if (!server_->listen(listenAddress, listenPort))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("HTTPS代理监听失败：%1").arg(server_->errorString());
            }
            server_.reset();
            stopSessionWorkers_ = {};
            return false;
        }

        listenAddress_ = listenAddress;
        listenPort_ = listenPort;
        emitStatus(QStringLiteral("HTTPS代理已启动：%1:%2").arg(listenAddress_.toString()).arg(listenPort_));
        return true;
    }

    void HttpsMitmProxyService::stop()
    {
        const bool kHadActiveProxy = server_ != nullptr || static_cast<bool>(stopSessionWorkers_);
        if (server_ != nullptr)
        {
            server_->close();
            server_.reset();
        }
        // If the previous iteration used stopAsync, first reclaim that background cleanup thread; its internal waits all have timeouts and will not hang.
        joinStopWorkerThread();
        if (stopSessionWorkers_)
        {
            // Session threads hold service callbacks; they must exit before the service object is allowed to destruct.
            const std::function<void()> kStopSessionWorkers = std::move(stopSessionWorkers_);
            stopSessionWorkers_ = {};
            kStopSessionWorkers();
        }
        listenAddress_ = QHostAddress();
        listenPort_ = 0;
        if (kHadActiveProxy)
        {
            emitStatus(QStringLiteral("HTTPS代理已停止。"));
        }
    }

    void HttpsMitmProxyService::stopAsync(std::function<void()> completionCallback)
    {
        // Stop listening must remain on the current thread: QTcpServer has thread affinity and cannot be handled by a background thread.
        const bool kHadActiveProxy = server_ != nullptr || static_cast<bool>(stopSessionWorkers_);
        if (server_ != nullptr)
        {
            server_->close();
            server_.reset();
        }
        joinStopWorkerThread();

        std::function<void()> stopSessionWorkers = std::move(stopSessionWorkers_);
        stopSessionWorkers_ = {};
        listenAddress_ = QHostAddress();
        listenPort_ = 0;

        if (!stopSessionWorkers)
        {
            if (kHadActiveProxy)
            {
                emitStatus(QStringLiteral("HTTPS代理已停止。"));
            }
            if (completionCallback)
            {
                completionCallback();
            }
            return;
        }

        // stopSessionWorkers holds only a shared_ptr to the session registry and does not touch the service object itself;
        // therefore, even if the service is destroyed before the background thread, the thread's wait operation remains safe.
        const QPointer<HttpsMitmProxyService> kGuardedSelf(this);
        stopWorkerThread_ = std::make_unique<std::thread>(
            [kGuardedSelf, stopSessionWorkers = std::move(stopSessionWorkers), completionCallback, kHadActiveProxy]()
            {
                stopSessionWorkers();

                QCoreApplication* const kAppInstance = QCoreApplication::instance();
                if (kAppInstance == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    kAppInstance,
                    [kGuardedSelf, completionCallback, kHadActiveProxy]()
                    {
                        if (!kGuardedSelf.isNull())
                        {
                            // The background thread has already reached its final statement; joining here merely reclaims the handle and will not cause significant blocking.
                            kGuardedSelf->joinStopWorkerThread();
                            if (kHadActiveProxy)
                            {
                                kGuardedSelf->emitStatus(QStringLiteral("HTTPS代理已停止。"));
                            }
                        }
                        if (completionCallback)
                        {
                            completionCallback();
                        }
                    },
                    Qt::QueuedConnection);
            });
    }

    void HttpsMitmProxyService::joinStopWorkerThread()
    {
        if (stopWorkerThread_ != nullptr && stopWorkerThread_->joinable())
        {
            stopWorkerThread_->join();
        }
        stopWorkerThread_.reset();
    }

    bool HttpsMitmProxyService::isRunning() const
    {
        return server_ != nullptr && server_->isListening();
    }

    void HttpsMitmProxyService::setParsedCallback(ParsedCallback callbackValue)
    {
        parsedCallback_ = std::move(callbackValue);
    }

    void HttpsMitmProxyService::setStatusCallback(StatusCallback callbackValue)
    {
        statusCallback_ = std::move(callbackValue);
    }

    bool HttpsMitmProxyService::ensureRootCertificate(const bool installToTrustStore, QString* errorTextOut)
    {
        std::lock_guard<std::recursive_mutex> guard(certificateMutex_);

        if (isRootCertificateReady() && (!installToTrustStore || isRootTrusted()))
        {
            return true;
        }

        const QString kScriptText = buildRootCertificateScriptText(
            rootCertificatePfxPath(),
            rootCertificateCerPath(),
            installToTrustStore);

        QString standardOutputText;
        QString standardErrorText;
        QString errorText;
        if (!runPowerShellScript(kScriptText, &standardOutputText, &standardErrorText, &errorText))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = errorText;
            }
            return false;
        }

        rootCertificatePrepared_ = true;
        return true;
    }

    void HttpsMitmProxyService::ensureRootCertificateAsync(
        const bool installToTrustStore,
        std::function<void(bool, QString)> completionCallback)
    {
        QCoreApplication* const kAppInstance = QCoreApplication::instance();

        // Fast path: If the certificate file is ready and trust requirements are met, there is no need to launch powershell.exe.
        // Deliberately avoids acquiring m_certificateMutex here to prevent blocking the UI thread while the session thread is generating the leaf certificate.
        if (isRootCertificateReady() && (!installToTrustStore || isRootTrusted()))
        {
            if (completionCallback && kAppInstance != nullptr)
            {
                // Unify to 'callback always triggers later on the UI thread'; callers need not distinguish between fast and slow paths.
                QMetaObject::invokeMethod(
                    kAppInstance,
                    [completionCallback]() { completionCallback(true, QString()); },
                    Qt::QueuedConnection);
            }
            return;
        }

        const QString kScriptText = buildRootCertificateScriptText(
            rootCertificatePfxPath(),
            rootCertificateCerPath(),
            installToTrustStore);
        const QPointer<HttpsMitmProxyService> kGuardedSelf(this);
        QThreadPool::globalInstance()->start(
            [kGuardedSelf, kScriptText, completionCallback]()
            {
                // The background thread only processes value-type arguments and QProcess, without touching any members of this service object.
                QString standardOutputText;
                QString standardErrorText;
                QString errorText;
                const bool kExecuted = executePowerShellScript(
                    kScriptText,
                    &standardOutputText,
                    &standardErrorText,
                    &errorText);

                QCoreApplication* const kWorkerAppInstance = QCoreApplication::instance();
                if (kWorkerAppInstance == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    kWorkerAppInstance,
                    [kGuardedSelf, kExecuted, errorText, completionCallback]()
                    {
                        if (kExecuted && !kGuardedSelf.isNull())
                        {
                            kGuardedSelf->rootCertificatePrepared_ = true;
                        }
                        if (completionCallback)
                        {
                            completionCallback(kExecuted, errorText);
                        }
                    },
                    Qt::QueuedConnection);
            });
    }

    bool HttpsMitmProxyService::isRootTrusted() const
    {
        // A boolean value is sufficient; there is no need to launch powershell.exe for this.
        // Read the exported root certificate in DER format directly, then look up the current user's ROOT store by SHA-1 fingerprint.
        QFile rootCertificateFile(rootCertificateCerPath());
        if (!rootCertificateFile.open(QIODevice::ReadOnly))
        {
            return false;
        }
        const QByteArray kRootCertificateBytes = rootCertificateFile.readAll();
        rootCertificateFile.close();
        if (kRootCertificateBytes.isEmpty())
        {
            return false;
        }

        QSslCertificate rootCertificate(kRootCertificateBytes, QSsl::Der);
        if (rootCertificate.isNull())
        {
            // Compatible with root certificate files that may historically have been written in PEM format.
            rootCertificate = QSslCertificate(kRootCertificateBytes, QSsl::Pem);
        }
        if (rootCertificate.isNull())
        {
            return false;
        }

        return isThumbprintInCurrentUserRootStore(rootCertificate.digest(QCryptographicHash::Sha1));
    }

    bool HttpsMitmProxyService::isRootCertificateReady() const
    {
        return rootCertificatePrepared_.load()
            && QFile::exists(rootCertificatePfxPath())
            && QFile::exists(rootCertificateCerPath());
    }

    bool HttpsMitmProxyService::loadHostCertificateBundle(
        const QString& hostName,
        QSslCertificate* certificateOut,
        QSslKey* privateKeyOut,
        QString* errorTextOut)
    {
        std::lock_guard<std::recursive_mutex> guard(certificateMutex_);

        if (certificateOut == nullptr || privateKeyOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("输出证书对象为空。");
            }
            return false;
        }

        QString errorText;
        if (!ensureRootCertificate(false, &errorText) || !ensureHostCertificateFile(hostName, &errorText))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = errorText;
            }
            return false;
        }

        auto tryLoadPemBundle =
            [this](const QString& targetHostName, QSslCertificate* certificateTargetOut, QSslKey* privateKeyTargetOut, QString* loadErrorTextOut) -> bool
            {
                QFile hostCertificatePemFile(hostCertificatePemPath(targetHostName));
                if (!hostCertificatePemFile.open(QIODevice::ReadOnly))
                {
                    if (loadErrorTextOut != nullptr)
                    {
                        *loadErrorTextOut = QStringLiteral("读取主机证书 PEM 失败：%1").arg(hostCertificatePemFile.errorString());
                    }
                    return false;
                }

                QFile hostPrivateKeyPemFile(hostPrivateKeyPemPath(targetHostName));
                if (!hostPrivateKeyPemFile.open(QIODevice::ReadOnly))
                {
                    if (loadErrorTextOut != nullptr)
                    {
                        *loadErrorTextOut = QStringLiteral("读取主机私钥 PEM 失败：%1").arg(hostPrivateKeyPemFile.errorString());
                    }
                    return false;
                }

                const QByteArray kCertificatePemBytes = hostCertificatePemFile.readAll();
                const QByteArray kPrivateKeyPemBytes = hostPrivateKeyPemFile.readAll();
                QSslCertificate localCertificate(kCertificatePemBytes, QSsl::Pem);
                QSslKey localPrivateKey(kPrivateKeyPemBytes, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
                if (localPrivateKey.isNull())
                {
                    // Some Qt/OpenSSL combinations are picky about explicit algorithm specification with PKCS#8; fall back to Opaque and try again.
                    localPrivateKey = QSslKey(kPrivateKeyPemBytes, QSsl::Opaque, QSsl::Pem, QSsl::PrivateKey);
                }
                if (localCertificate.isNull() || localPrivateKey.isNull())
                {
                    if (loadErrorTextOut != nullptr)
                    {
                        *loadErrorTextOut = QStringLiteral("加载主机 PEM 证书或私钥失败。certNull=%1 keyNull=%2 certPath=%3 keyPath=%4")
                            .arg(localCertificate.isNull() ? QStringLiteral("true") : QStringLiteral("false"))
                            .arg(localPrivateKey.isNull() ? QStringLiteral("true") : QStringLiteral("false"))
                            .arg(hostCertificatePemPath(targetHostName))
                            .arg(hostPrivateKeyPemPath(targetHostName));
                    }
                    return false;
                }

                *certificateTargetOut = localCertificate;
                *privateKeyTargetOut = localPrivateKey;
                return true;
            };

        if (tryLoadPemBundle(hostName, certificateOut, privateKeyOut, errorTextOut))
        {
            return true;
        }

        // Fallback strategy: If an old format or corrupted cache is encountered, delete the host cache and rebuild it once.
        QFile::remove(hostCertificatePfxPath(hostName));
        QFile::remove(hostCertificatePemPath(hostName));
        QFile::remove(hostPrivateKeyPemPath(hostName));

        QString rebuildErrorText;
        if (!ensureHostCertificateFile(hostName, &rebuildErrorText))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = rebuildErrorText;
            }
            return false;
        }

        if (tryLoadPemBundle(hostName, certificateOut, privateKeyOut, errorTextOut))
        {
            return true;
        }

        if (errorTextOut != nullptr && !errorTextOut->contains(QStringLiteral("重建")))
        {
            *errorTextOut = QStringLiteral("%1；已执行一次缓存删除重建但仍失败。").arg(*errorTextOut);
        }
        return false;
    }

    QHostAddress HttpsMitmProxyService::currentListenAddress() const
    {
        return listenAddress_;
    }

    std::uint16_t HttpsMitmProxyService::currentListenPort() const
    {
        return listenPort_;
    }

    QString HttpsMitmProxyService::rootCertificatePath() const
    {
        return rootCertificateCerPath();
    }

    void HttpsMitmProxyService::emitParsedEntry(const HttpsProxyParsedEntry& parsedEntry) const
    {
        if (parsedCallback_)
        {
            parsedCallback_(parsedEntry);
        }
    }

    void HttpsMitmProxyService::emitStatus(const QString& statusText) const
    {
        if (statusCallback_)
        {
            statusCallback_(statusText);
        }
    }

    QString HttpsMitmProxyService::certificateWorkspaceDir() const
    {
        QString baseDirectoryText = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        if (baseDirectoryText.isEmpty())
        {
            baseDirectoryText = QDir::currentPath();
        }

        QDir workspaceDirectory(baseDirectoryText);
        workspaceDirectory.mkpath(QStringLiteral("HttpsProxy"));
        return workspaceDirectory.filePath(QStringLiteral("HttpsProxy"));
    }

    bool HttpsMitmProxyService::runPowerShellScript(
        const QString& scriptText,
        QString* standardOutputOut,
        QString* standardErrorOut,
        QString* errorTextOut) const
    {
        // The actual implementation is placed in a free function within an anonymous namespace: background certificate
        // tasks can directly reuse it, avoiding the need to hold a pointer to this service object just to run a script.
        return executePowerShellScript(scriptText, standardOutputOut, standardErrorOut, errorTextOut);
    }

    QString HttpsMitmProxyService::hostCertificatePfxPath(const QString& hostName) const
    {
        return QDir(certificateWorkspaceDir()).filePath(
            QStringLiteral("leaf_%1.pfx").arg(normalizedHostForFileName(hostName)));
    }

    QString HttpsMitmProxyService::hostCertificatePemPath(const QString& hostName) const
    {
        return QDir(certificateWorkspaceDir()).filePath(
            QStringLiteral("leaf_%1_cert.pem").arg(normalizedHostForFileName(hostName)));
    }

    QString HttpsMitmProxyService::hostPrivateKeyPemPath(const QString& hostName) const
    {
        return QDir(certificateWorkspaceDir()).filePath(
            QStringLiteral("leaf_%1_key.pem").arg(normalizedHostForFileName(hostName)));
    }

    QString HttpsMitmProxyService::rootCertificatePfxPath() const
    {
        return QDir(certificateWorkspaceDir()).filePath(QStringLiteral("root_ca.pfx"));
    }

    QString HttpsMitmProxyService::rootCertificateCerPath() const
    {
        return QDir(certificateWorkspaceDir()).filePath(QStringLiteral("root_ca.cer"));
    }

    bool HttpsMitmProxyService::ensureHostCertificateFile(const QString& hostName, QString* errorTextOut)
    {
        if (hostName.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("目标主机名为空。");
            }
            return false;
        }

        const QString kRootPfxPath = rootCertificatePfxPath();
        const QString kHostPfxPath = hostCertificatePfxPath(hostName);
        const QString kHostCertPemPath = hostCertificatePemPath(hostName);
        const QString kHostKeyPemPath = hostPrivateKeyPemPath(hostName);
        const QString kScriptText = QStringLiteral(
            "$ErrorActionPreference='Stop'; "
            "$ProgressPreference='SilentlyContinue'; "
            "$rootPfx=%1; "
            "$hostPfx=%2; "
            "$hostPem=%3; "
            "$hostKeyPem=%4; "
            "$hostName=%5; "
            "$plainPwd=%6; "
            "$pwd=ConvertTo-SecureString $plainPwd -AsPlainText -Force; "
            "$nl=[System.Environment]::NewLine; "
            "$rootPfxData=Get-PfxData -FilePath $rootPfx -Password $pwd; "
            "$rootThumb=$rootPfxData.EndEntityCertificates[0].Thumbprint; "
            "$rootCert=Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { $_.Thumbprint -eq $rootThumb } | Select-Object -First 1; "
            "if($null -eq $rootCert){ "
            "  Import-PfxCertificate -FilePath $rootPfx -CertStoreLocation Cert:\\CurrentUser\\My -Password $pwd | Out-Null; "
            "  $rootCert=Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { $_.Thumbprint -eq $rootThumb } | Select-Object -First 1; "
            "} "
            "$leafCert=$null; "
            "if(Test-Path $hostPfx){ "
            "  $leafPfxData=Get-PfxData -FilePath $hostPfx -Password $pwd; "
            "  $leafThumb=$leafPfxData.EndEntityCertificates[0].Thumbprint; "
            "  $leafCert=Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { $_.Thumbprint -eq $leafThumb } | Select-Object -First 1; "
            "  if($null -eq $leafCert){ "
            "    Import-PfxCertificate -FilePath $hostPfx -CertStoreLocation Cert:\\CurrentUser\\My -Password $pwd | Out-Null; "
            "    $leafCert=Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { $_.Thumbprint -eq $leafThumb } | Select-Object -First 1; "
            "  } "
            "} "
            "if($null -ne $leafCert -and -not $leafCert.HasPrivateKey){ "
            "  Remove-Item -Path ('Cert:\\CurrentUser\\My\\' + $leafCert.Thumbprint) -Force -ErrorAction SilentlyContinue; "
            "  $leafCert=$null; "
            "} "
            "if($null -eq $leafCert){ "
            "  $leafCert=New-SelfSignedCertificate -Type Custom -Subject ('CN=' + $hostName) -DnsName $hostName "
            "    -FriendlyName ('Ksword HTTPS Leaf ' + $hostName) -Signer $rootCert -CertStoreLocation 'Cert:\\CurrentUser\\My' "
            "    -KeyExportPolicy Exportable -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm sha256 "
            "    -KeyUsage DigitalSignature,KeyEncipherment "
            "    -TextExtension @('2.5.29.19={text}ca=false','2.5.29.37={text}1.3.6.1.5.5.7.3.1') "
            "    -NotAfter (Get-Date).AddYears(2); "
            "} "
            "Export-PfxCertificate -Cert $leafCert -FilePath $hostPfx -Password $pwd -Force | Out-Null; "
            "$leafCertPem = '-----BEGIN CERTIFICATE-----' + $nl + [Convert]::ToBase64String($leafCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert), 'InsertLineBreaks') + $nl + '-----END CERTIFICATE-----' + $nl; "
            "$leafRsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($leafCert); "
            "if($null -eq $leafRsa){ throw 'Leaf private key export failed'; } "
            "$leafKeyPem = $null; "
            "if($leafRsa | Get-Member -Name ExportPkcs8PrivateKeyPem -MemberType Method -ErrorAction SilentlyContinue){ "
            "  $leafKeyPem = $leafRsa.ExportPkcs8PrivateKeyPem(); "
            "} elseif(($leafRsa.PSObject.Properties.Name -contains 'Key') -and $null -ne $leafRsa.Key){ "
            "  $pkcs8Bytes = $leafRsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob); "
            "  $leafKeyPem = '-----BEGIN PRIVATE KEY-----' + $nl + [Convert]::ToBase64String($pkcs8Bytes, 'InsertLineBreaks') + $nl + '-----END PRIVATE KEY-----' + $nl; "
            "} else { "
            "  throw 'Leaf private key export API unavailable'; "
            "} "
            "[System.IO.File]::WriteAllText($hostPem, $leafCertPem, [System.Text.UTF8Encoding]::new($false)); "
            "[System.IO.File]::WriteAllText($hostKeyPem, $leafKeyPem, [System.Text.UTF8Encoding]::new($false)); "
            "Write-Output $hostPfx;")
            .arg(quoteForPowerShell(kRootPfxPath))
            .arg(quoteForPowerShell(kHostPfxPath))
            .arg(quoteForPowerShell(kHostCertPemPath))
            .arg(quoteForPowerShell(kHostKeyPemPath))
            .arg(quoteForPowerShell(hostName))
            .arg(quoteForPowerShell(QString::fromLatin1(kPfxPasswordText)));

        QString standardOutputText;
        QString standardErrorText;
        QString errorText;
        if (!runPowerShellScript(kScriptText, &standardOutputText, &standardErrorText, &errorText))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = errorText;
            }
            return false;
        }
        return QFile::exists(kHostPfxPath)
            && QFile::exists(kHostCertPemPath)
            && QFile::exists(kHostKeyPemPath);
    }

    QString HttpsMitmProxyService::normalizedHostForFileName(const QString& hostName) const
    {
        const QByteArray kHashBytes = QCryptographicHash::hash(
            hostName.trimmed().toLower().toUtf8(),
            QCryptographicHash::Sha1);
        return QString::fromLatin1(kHashBytes.toHex());
    }

    QByteArray HttpsMitmProxyService::rootPfxPassword() const
    {
        return QByteArrayLiteral(kPfxPasswordText);
    }
}
