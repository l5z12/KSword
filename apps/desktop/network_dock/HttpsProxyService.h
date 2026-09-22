#pragma once

// ============================================================
// HttpsProxyService.h
// Purpose:
// 1) Provide a local HTTPS proxy resolution service.
// 2) Responsible for root certificate generation, trust import, and site certificate caching;
// 3) Return parsing results and status text to NetworkDock via callbacks.
// ============================================================

#include <QtCore/QByteArray>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtNetwork/QHostAddress>

#include <atomic>     // std::atomic_bool: Root certificate ready flag for cross-thread read/write.
#include <cstdint>    // std::uint*_t: session ID, timestamp, and port.
#include <functional> // std::function: UI callback bridge.
#include <memory>     // std::unique_ptr: Internal object lifecycle management.
#include <mutex>      // std::recursive_mutex: Serialization of certificate generation and export.
#include <thread>     // std::thread: Execute session cleanup in a background thread.

class QSslCertificate;
class QSslKey;
class QTcpServer;

namespace ks::network
{
    // HttpsProxyParsedEntry:
    // - Describes an HTTPS parsing result.
    // - UI can directly generate a table row based on this.
    struct HttpsProxyParsedEntry
    {
        std::uint64_t timestampMs = 0;  // timestampMs: Event timestamp (Unix ms).
        std::uint64_t sessionId = 0;    // sessionId: Proxy session ID.
        QString clientEndpointText;     // clientEndpointText: Client endpoint text.
        QString clientProcessText;      // clientProcessText: The matched client process name and PID.
        QString targetHostText;         // targetHostText: target host name.
        int targetPort = 0;             // targetPort: The target port number.
        QString eventTypeText;          // eventTypeText: Event type (CONNECT/REQUEST/RESPONSE/ERROR).
        QString methodText;             // methodText: HTTP request method.
        QString pathText;               // pathText: HTTP request path.
        int statusCode = 0;             // statusCode: HTTP response status code.
        QString tlsVersionText;         // tlsVersionText: TLS version text.
        QString alpnText;               // alpnText: ALPN negotiation result.
        QString sniText;                // sniText: SNI or CONNECT hostname.
        QString contentTypeText;        // contentTypeText：HTTP Content-Type。
        qint64 contentLength = -1;      // contentLength: HTTP Content-Length; -1 if unknown.
        std::uint64_t elapsedMs = 0;    // elapsedMs: Time elapsed from request issuance to the first response header.
        std::uint64_t uploadBytes = 0;  // uploadBytes: Number of plaintext bytes forwarded to the remote side in this session.
        std::uint64_t downloadBytes = 0;// downloadBytes: Plaintext bytes forwarded to the client in this session.
        QString cipherSuiteText;        // cipherSuiteText: Remote TLS negotiated cipher suite.
        QString certificateSubjectText; // certificateSubjectText: Remote certificate subject.
        QString certificateIssuerText;  // certificateIssuerText: Remote certificate issuer.
        QString certificateExpiryText;  // certificateExpiryText: remote certificate expiration time.
        QString certificateSha256Text;  // certificateSha256Text: Remote certificate SHA-256 fingerprint.
        QString detailText;             // detailText: Supplementary explanation or error details.
        QByteArray rawBytes;            // rawBytes: raw plaintext bytes corresponding to this event.
    };

    class HttpsMitmProxyService final : public QObject
    {
    public:
        // ParsedCallback:
        // - Push single HTTPS parsing result to UI.
        using ParsedCallback = std::function<void(const HttpsProxyParsedEntry&)>;

        // StatusCallback:
        // - Push status text and error text to the UI.
        using StatusCallback = std::function<void(const QString&)>;

    public:
        // Constructor purpose:
        // - initialize the certificate directory, default state, and internal object pointers.
        explicit HttpsMitmProxyService();

        // Destructor purpose:
        // - Stop listening and clean up sessions.
        ~HttpsMitmProxyService() override;

        // start:
        // - Start the local HTTPS proxy listener.
        // Parameter listenAddress: Listen address.
        // Parameter listenPort: Listening port.
        // Parameter errorTextOut: outputs error text on failure.
        // Returns: true on success; false on failure.
        bool start(const QHostAddress& listenAddress, std::uint16_t listenPort, QString* errorTextOut);

        // stop:
        // - Stop the local HTTPS proxy and disconnect sessions;
        // - Synchronous semantics, used in scenarios requiring guaranteed session thread cleanup, such as destructors.
        // - Internally, the session thread wait is time-bound only, preventing indefinite hangs.
        void stop();

        // stopAsync:
        // - Close the listening socket on the calling thread (UI thread) and offload the time-consuming part of waiting for the session thread to exit to a background thread.
        // - Used by the UI's 'Stop Proxy' button to prevent the interface from freezing during session thread cleanup.
        // Parameter completionCallback: callback executed after cleanup completes, fixed to run on the UI thread; also invoked if the service has already been destructed.
        void stopAsync(std::function<void()> completionCallback);

        // isRunning:
        // - Returns whether the proxy is in listening state.
        [[nodiscard]] bool isRunning() const;

        // setParsedCallback:
        // - Set parsed result callback.
        void setParsedCallback(ParsedCallback callbackValue);

        // setStatusCallback:
        // - Set status text callback.
        void setStatusCallback(StatusCallback callbackValue);

        // ensureRootCertificate:
        // - Ensure the root certificate exists.
        // - When installToTrustStore=true, automatically import the current user's trusted root certificates.
        // Parameter installToTrustStore: Whether to import the current user's trusted root.
        // Parameter errorTextOut: outputs error text on failure.
        // Returns: true on success; false on failure.
        bool ensureRootCertificate(bool installToTrustStore, QString* errorTextOut);

        // ensureRootCertificateAsync:
        // - Semantically consistent with `ensureRootCertificate`, but moves the `powershell.exe` invocation to a
        //   background thread so the calling thread (UI thread) is not blocked by certificate generation/export.
        // - No child process is spawned if the certificate file is complete and the trust status meets requirements; only one completion callback is dispatched.
        // Parameter installToTrustStore: Whether to import the current user's trusted root.
        // Parameter completionCallback: completion callback executed on the UI thread; parameters are (success status, failure reason text).
        //                          May be called even after the service is destroyed; the caller must guard its own lifetime.
        void ensureRootCertificateAsync(bool installToTrustStore, std::function<void(bool, QString)> completionCallback);

        // isRootTrusted:
        // - Check if the root certificate is trusted in the current user's trusted root store.
        // Directly reads the current user's ROOT certificate store without spawning child processes, allowing calls from the UI thread.
        [[nodiscard]] bool isRootTrusted() const;

        // loadHostCertificateBundle:
        // - Loads or generates the leaf certificate and private key for the specified host.
        // Parameter hostName: Target host name.
        // Parameter certificateOut: Output leaf certificate.
        // Parameter privateKeyOut: outputs the leaf private key.
        // Parameter errorTextOut: outputs error text on failure.
        // Returns: true on success; false on failure.
        bool loadHostCertificateBundle(
            const QString& hostName,
            QSslCertificate* certificateOut,
            QSslKey* privateKeyOut,
            QString* errorTextOut);

        // currentListenAddress:
        // - Returns the current listening address.
        [[nodiscard]] QHostAddress currentListenAddress() const;

        // currentListenPort:
        // - Returns the current listening port.
        [[nodiscard]] std::uint16_t currentListenPort() const;

        // rootCertificatePath:
        // - Returns the path to the root certificate `.cer` file, used for UI import and display.
        [[nodiscard]] QString rootCertificatePath() const;

    private:
        // emitParsedEntry:
        // - Unify dispatching of parsed result callbacks internally within the service.
        void emitParsedEntry(const HttpsProxyParsedEntry& parsedEntry) const;

        // emitStatus:
        // - Unify dispatching of status text callbacks internally within the service.
        void emitStatus(const QString& statusText) const;

        // certificateWorkspaceDir:
        // - Returns the certificate workspace directory and creates it if missing.
        QString certificateWorkspaceDir() const;

        // runPowerShellScript:
        // - Synchronously execute a PowerShell script.
        // Parameter scriptText: script text.
        // Parameter standardOutputOut: Standard output.
        // Parameter standardErrorOut: Standard error.
        // Parameter errorTextOut: outputs error text on failure.
        // Returns: true on success; false on failure.
        bool runPowerShellScript(
            const QString& scriptText,
            QString* standardOutputOut,
            QString* standardErrorOut,
            QString* errorTextOut) const;

        // hostCertificatePfxPath:
        // - Calculate the certificate PFX path for the specified host.
        QString hostCertificatePfxPath(const QString& hostName) const;

        // hostCertificatePemPath:
        // - Computes the certificate PEM path for the specified host.
        QString hostCertificatePemPath(const QString& hostName) const;

        // hostPrivateKeyPemPath:
        // - Computes the private key PEM path for the specified host.
        QString hostPrivateKeyPemPath(const QString& hostName) const;

        // rootCertificatePfxPath:
        // - Returns the root certificate PFX path.
        QString rootCertificatePfxPath() const;

        // rootCertificateCerPath:
        // - Returns the root certificate CER path.
        QString rootCertificateCerPath() const;

        // ensureHostCertificateFile:
        // - Ensures the leaf certificate PFX file for the specified host exists.
        // Parameter hostName: Target host name.
        // Parameter errorTextOut: outputs error text on failure.
        // Returns: true on success; false on failure.
        bool ensureHostCertificateFile(const QString& hostName, QString* errorTextOut);

        // normalizedHostForFileName:
        // - Converts hostname to a filename-safe fragment.
        QString normalizedHostForFileName(const QString& hostName) const;

        // rootPfxPassword:
        // - Returns a fixed PFX export password.
        QByteArray rootPfxPassword() const;

        // isRootCertificateReady:
        // - Lock-free fast check for root certificate readiness (spawns no child processes, does not contend for the certificate mutex).
        // - Allows start and async preparation paths to short-circuit quickly, preventing the UI thread from being blocked by background certificate tasks.
        // Return: true = root certificate files are complete; false = regeneration required.
        [[nodiscard]] bool isRootCertificateReady() const;

        // joinStopWorkerThread:
        // - Reclaim the background session cleanup thread to ensure only one cleanup thread exists at any given time.
        // - All waits inside this thread include timeouts, so the join here will not block indefinitely.
        void joinStopWorkerThread();

    private:
        std::unique_ptr<QTcpServer> server_;  // m_server: Local proxy listening server.
        std::unique_ptr<std::thread> stopWorkerThread_; // m_stopWorkerThread: worker thread for background session cleanup.
        std::function<void()> stopSessionWorkers_; // m_stopSessionWorkers: Stop and wait for all active proxy session threads.
        ParsedCallback parsedCallback_;       // m_parsedCallback: Parsing result callback.
        StatusCallback statusCallback_;       // m_statusCallback: Status text callback.
        QHostAddress listenAddress_;          // m_listenAddress: Current listening address.
        std::uint16_t listenPort_ = 0;        // m_listenPort: Current listening port.
        std::uint64_t nextSessionId_ = 1;     // m_nextSessionId: Next assigned session ID.
        mutable std::recursive_mutex certificateMutex_; // m_certificateMutex: Serialization lock for certificate read/write.
        std::atomic_bool rootCertificatePrepared_{ false }; // m_rootCertificatePrepared: Whether the root certificate file is ready; accessed by both the session thread and the UI thread.
    };
}
