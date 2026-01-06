#ifndef APPCONTROLLER_H
#define APPCONTROLLER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QVariantMap>
#include <QTimer>
#include <QDir>
#include <QMutex>
#include <memory>

// No namespace declarations
class AppController : public QObject
{
    Q_OBJECT

    Q_PROPERTY(bool isAuthenticated READ isAuthenticated NOTIFY authenticationChanged)
    Q_PROPERTY(QString currentUser READ currentUser NOTIFY userChanged)
    Q_PROPERTY(QString systemStatus READ getSystemStatus NOTIFY statusChanged)

public:
    explicit AppController(QObject *parent = nullptr);
    ~AppController();

    // === AUTHENTICATION ===
    Q_INVOKABLE bool login(const QString &username, const QString &password, const QString &otp = "");
    Q_INVOKABLE bool logout();

    // === DISK OPERATIONS ===
    Q_INVOKABLE bool encryptDisk(const QString &inputPath, const QString &outputPath);
    Q_INVOKABLE bool decryptDisk(const QString &inputPath, const QString &outputPath);
    Q_INVOKABLE void cancelOperation();

    // === KEY MANAGEMENT ===
    Q_INVOKABLE QString generateKeyPair();
    Q_INVOKABLE QByteArray generateDEK();

    // === SHARE MANAGEMENT ===
    Q_INVOKABLE QStringList createShares(const QByteArray &secret, int total, int required);
    Q_INVOKABLE QByteArray recoverFromShares(const QStringList &sharePaths);

    // === STATUS ===
    bool isAuthenticated() const;
    QString currentUser() const;
    QString getSystemStatus() const;

signals:
    void operationStarted(const QString &operation);
    void operationCompleted(bool success, const QString &message);
    void encryptionProgress(int percent);
    void decryptionProgress(int percent);
    void statusChanged(const QString &status);
    void logMessage(const QString &log);
    void authenticationChanged(bool authenticated);
    void userChanged(const QString &username);

private:
    QByteArray readFile(const QString &path) const;
    bool writeFile(const QString &path, const QByteArray &data) const;
    QString getConfigPath() const;

    // State
    QString m_currentUser;
    bool m_isAuthenticated;
    QByteArray m_masterKey;

    mutable QMutex m_mutex;
};

#endif // APPCONTROLLER_H
