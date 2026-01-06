#include "AppController.h"

// Include team headers WITHOUT namespaces
#include "../src/crypto/HybridEncryption.h"
#include "../src/crypto/AES.h"
#include "../src/crypto/PQC.h"
#include "../src/disk/DiskEncryptor.h"
#include "../src/disk/DiskDecryptor.h"
#include "../src/recovery/KeyRecovery.h"
#include "../src/recovery/ShamirSSS.h"
#include "../src/recovery/ShareStorage.h"
#include "../src/auth/AuthManager.h"
#include "../src/auth/AuditLogger.h"
#include "../src/auth/PasswordHasher.h"
#include "../src/auth/PolicyEnforcer.h"
#include "../src/auth/TwoFactor.h"

#include <QFile>
#include <QDir>
#include <QDateTime>
#include <QStandardPaths>
#include <QMutexLocker>
#include <QDebug>
#include <vector>
#include <string>

// Conversion helpers
static std::vector<uint8_t> qbaToVector(const QByteArray &qba) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(qba.constData());
    return std::vector<uint8_t>(data, data + qba.size());
}

static QByteArray vectorToQba(const std::vector<uint8_t> &vec) {
    const char* data = reinterpret_cast<const char*>(vec.data());
    return QByteArray(data, static_cast<int>(vec.size()));
}

AppController::AppController(QObject *parent)
    : QObject(parent)
    , m_isAuthenticated(false)
{
    emit logMessage("AppController initialized");
    emit statusChanged("System Ready");
}

AppController::~AppController()
{
}

// ==================== AUTHENTICATION ====================

bool AppController::login(const QString &username, const QString &password, const QString &otp)
{
    // ========== TEMPORARY TEST CODE - REMOVE LATER ==========
    // For testing only while you figure out real AuthManager
    if (username == "admin" && password == "admin123") {
        m_isAuthenticated = true;
        m_currentUser = username;

        emit authenticationChanged(true);
        emit userChanged(username);
        emit statusChanged("Logged in as " + username);
        emit operationCompleted(true, "Login successful (test mode)");
        return true;
    }
    // ========== END TEMPORARY CODE ==========
    QMutexLocker locker(&m_mutex);

    try {
        // Check policy
        if (!PolicyEnforcer::canDecrypt(username.toStdString())) {
            emit operationCompleted(false, "Login not permitted");
            AuditLogger::logEvent("Login denied: " + username.toStdString());
            return false;
        }

        // Authenticate
        AuthManager auth;
        bool success = auth.login(
            username.toStdString(),
            password.toStdString(),
            otp.toStdString()
            );

        if (success) {
            m_isAuthenticated = true;
            m_currentUser = username;

            AuditLogger::logEvent("User logged in: " + username.toStdString());
            emit authenticationChanged(true);
            emit userChanged(username);
            emit statusChanged("Logged in as " + username);
            emit operationCompleted(true, "Login successful");

            return true;
        } else {
            PolicyEnforcer::registerFailedAttempt(username.toStdString());
            AuditLogger::logEvent("Failed login: " + username.toStdString());
            emit operationCompleted(false, "Invalid credentials");
            return false;
        }

    } catch (const std::exception &e) {
        emit operationCompleted(false, QString("Login error: %1").arg(e.what()));
        return false;
    }
}

bool AppController::logout()
{
    QMutexLocker locker(&m_mutex);

    if (m_isAuthenticated) {
        AuditLogger::logEvent("User logged out: " + m_currentUser.toStdString());
    }

    m_isAuthenticated = false;
    m_currentUser.clear();

    emit authenticationChanged(false);
    emit userChanged("");
    emit statusChanged("Logged out");

    return true;
}

// ==================== DISK ENCRYPTION ====================

bool AppController::encryptDisk(const QString &inputPath, const QString &outputPath)
{
    if (!m_isAuthenticated) {
        emit operationCompleted(false, "Authentication required");
        return false;
    }

    emit operationStarted("Encrypting Disk");
    emit statusChanged("Starting encryption...");

    try {
        qDebug() << "=== ENCRYPTION START ===";

        // 1. Create necessary directories
        QString configPath = getConfigPath();
        QString keyDir = configPath + "/keys";
        QString shareDir = configPath + "/shares";

        QDir().mkpath(keyDir);
        QDir().mkpath(shareDir);

        // 2. Generate or load PQC key pair
        emit encryptionProgress(10);
        std::vector<uint8_t> publicKey;
        std::vector<uint8_t> privateKey;

        QString privateKeyPath = keyDir + "/private.key";
        QString publicKeyPath = keyDir + "/public.key";

        if (QFile::exists(privateKeyPath) && QFile::exists(publicKeyPath)) {
            // Load existing keys
            publicKey = qbaToVector(readFile(publicKeyPath));
            privateKey = qbaToVector(readFile(privateKeyPath));
            qDebug() << "Loaded existing PQC keys";
        } else {
            // Generate new keys
            PQCKeyPair keyPair = PQC::generateKeypair();
            publicKey = keyPair.publicKey;
            privateKey = keyPair.secretKey;

            // Save keys
            writeFile(publicKeyPath, vectorToQba(publicKey));
            writeFile(privateKeyPath, vectorToQba(privateKey));
            qDebug() << "Generated new PQC key pair";
        }

        // 3. Create master key if doesn't exist
        QString masterKeyPath = configPath + "/master.key";
        if (!QFile::exists(masterKeyPath)) {
            m_masterKey = QByteArray(32, 'M'); // Simple master key
            writeFile(masterKeyPath, m_masterKey);
            qDebug() << "Created new master key";
        } else {
            m_masterKey = readFile(masterKeyPath);
        }

        // 4. Encrypt disk and get wrapped key
        emit encryptionProgress(30);
        DiskEncryptor encryptor;
        WrappedKey wrappedKey;

        qDebug() << "Calling DiskEncryptor::encryptDisk()...";
        encryptor.encryptDisk(
            inputPath.toStdString(),
            outputPath.toStdString(),
            publicKey,
            shareDir.toStdString(),
            qbaToVector(m_masterKey),
            wrappedKey  // This will be filled by the function
            );

        qDebug() << "Disk encryption completed";
        qDebug() << "Wrapped key sizes - PQC ciphertext:" << wrappedKey.pqcCiphertext.size()
                 << "Wrapped DEK:" << wrappedKey.wrappedDEK.size();

        // 5. Save metadata with wrapped key
        emit encryptionProgress(90);
        QFile metaFile(outputPath + ".meta");
        if (metaFile.open(QIODevice::WriteOnly)) {
            QTextStream stream(&metaFile);
            stream << "PQC_WRAPPED_KEY:" << vectorToQba(wrappedKey.pqcCiphertext).toBase64() << "\n";
            stream << "WRAPPED_DEK:" << vectorToQba(wrappedKey.wrappedDEK).toBase64() << "\n";
            stream << "SHARE_DIR:" << shareDir << "\n";
            stream << "ENCRYPTION_TIME:" << QDateTime::currentDateTime().toString() << "\n";
            stream << "ORIGINAL_FILE:" << inputPath << "\n";
            metaFile.close();
            qDebug() << "Metadata saved:" << outputPath + ".meta";
        }

        // 6. Complete
        emit encryptionProgress(100);

        AuditLogger::logEvent("Disk encrypted: " + inputPath.toStdString());
        emit operationCompleted(true,
                                QString("Disk encrypted successfully!\n"
                                        "Encrypted file: %1\n"
                                        "Metadata: %2.meta\n"
                                        "Keys: %3\n"
                                        "Shares: %4")
                                    .arg(outputPath, outputPath, keyDir, shareDir));

        qDebug() << "=== ENCRYPTION END (SUCCESS) ===";
        return true;

    } catch (const std::exception &e) {
        qDebug() << "=== ENCRYPTION END (ERROR):" << e.what();
        emit operationCompleted(false, QString("Encryption failed: %1").arg(e.what()));
        return false;
    }
}

// ==================== DISK DECRYPTION ====================

bool AppController::decryptDisk(const QString &inputPath, const QString &outputPath)
{
    qDebug() << "\n=== DECRYPTION DEBUG START ===";

    if (!m_isAuthenticated) {
        qDebug() << "ERROR: Not authenticated";
        emit operationCompleted(false, "Authentication required");
        return false;
    }

    emit operationStarted("Decrypting Disk");
    emit statusChanged("Starting decryption...");

    try {
        // 1. Check input file
        qDebug() << "Step 1: Checking input file";
        if (!QFile::exists(inputPath)) {
            qDebug() << "ERROR: Input file doesn't exist:" << inputPath;
            emit operationCompleted(false, "Input file does not exist: " + inputPath);
            return false;
        }
        qDebug() << "Input file exists, size:" << QFileInfo(inputPath).size() << "bytes";

        // 2. Check metadata file
        qDebug() << "Step 2: Checking metadata";
        QString metaPath = inputPath + ".meta";
        if (!QFile::exists(metaPath)) {
            qDebug() << "ERROR: No .meta file found:" << metaPath;
            emit operationCompleted(false, "Metadata file not found");
            return false;
        }
        qDebug() << "Meta file exists:" << metaPath;

        // 3. Extract wrapped key from metadata
        qDebug() << "Step 3: Extracting wrapped key from metadata";
        WrappedKey wrappedKey;

        QFile metaFile(metaPath);
        if (metaFile.open(QIODevice::ReadOnly)) {
            QTextStream stream(&metaFile);
            while (!stream.atEnd()) {
                QString line = stream.readLine();
                if (line.startsWith("PQC_WRAPPED_KEY:")) {
                    QString base64 = line.mid(16);
                    QByteArray data = QByteArray::fromBase64(base64.toLatin1());
                    wrappedKey.pqcCiphertext = qbaToVector(data);
                    qDebug() << "  PQC ciphertext size:" << wrappedKey.pqcCiphertext.size();
                }
                if (line.startsWith("WRAPPED_DEK:")) {
                    QString base64 = line.mid(12);
                    QByteArray data = QByteArray::fromBase64(base64.toLatin1());
                    wrappedKey.wrappedDEK = qbaToVector(data);
                    qDebug() << "  Wrapped DEK size:" << wrappedKey.wrappedDEK.size();
                }
                if (line.startsWith("SHARE_DIR:")) {
                    QString shareDir = line.mid(10);
                    qDebug() << "  Share dir from metadata:" << shareDir;
                }
            }
            metaFile.close();
        }

        // Verify wrapped key
        if (wrappedKey.pqcCiphertext.empty() || wrappedKey.wrappedDEK.empty()) {
            qDebug() << "ERROR: Invalid wrapped key in metadata";
            emit operationCompleted(false, "Invalid wrapped key in metadata");
            return false;
        }

        // 4. Find share directory
        qDebug() << "Step 4: Finding share directory";
        QString shareDir;

        // Try to get from metadata first
        metaFile.open(QIODevice::ReadOnly);
        QTextStream stream(&metaFile);
        while (!stream.atEnd()) {
            QString line = stream.readLine();
            if (line.startsWith("SHARE_DIR:")) {
                shareDir = line.mid(10);
                break;
            }
        }
        metaFile.close();

        if (shareDir.isEmpty()) {
            shareDir = getConfigPath() + "/shares";
            qDebug() << "Using default share dir:" << shareDir;
        }

        // Check share directory exists
        QDir shareDirObj(shareDir);
        if (!shareDirObj.exists()) {
            qDebug() << "ERROR: Share directory doesn't exist:" << shareDir;
            emit operationCompleted(false, "Share directory not found: " + shareDir);
            return false;
        }

        qDebug() << "Share directory exists. Files in it:";
        foreach(QString file, shareDirObj.entryList(QDir::Files)) {
            qDebug() << "  " << file << "size:" << QFileInfo(shareDir + "/" + file).size();
        }

        // 5. Load private key
        qDebug() << "Step 5: Loading private key";
        QString keyDir = getConfigPath() + "/keys";
        QString privateKeyPath = keyDir + "/private.key";

        if (!QFile::exists(privateKeyPath)) {
            qDebug() << "ERROR: Private key not found:" << privateKeyPath;
            emit operationCompleted(false, "Private key not found");
            return false;
        }

        QByteArray privateKey = readFile(privateKeyPath);
        qDebug() << "Private key loaded, size:" << privateKey.size() << "bytes";

        // 6. Load master key
        qDebug() << "Step 6: Loading master key";
        QString masterKeyPath = getConfigPath() + "/master.key";

        if (!QFile::exists(masterKeyPath)) {
            qDebug() << "ERROR: Master key not found:" << masterKeyPath;
            emit operationCompleted(false, "Master key not found");
            return false;
        }

        m_masterKey = readFile(masterKeyPath);
        qDebug() << "Master key loaded, size:" << m_masterKey.size() << "bytes";

        // 7. Test share loading
        qDebug() << "Step 7: Testing share loading";
        try {
            Share testShare = ShareStorage::loadShare(
                (shareDir + "/share_0.dat").toStdString(),
                qbaToVector(m_masterKey)
                );
            qDebug() << "  Share loaded successfully. Index:" << testShare.index
                     << "Value size:" << testShare.value.size();
        } catch (const std::exception& e) {
            qDebug() << "  WARNING: Failed to load share:" << e.what();
        }

        // 8. Call DiskDecryptor with wrapped key
        qDebug() << "Step 8: Calling DiskDecryptor";
        qDebug() << "  Input:" << inputPath;
        qDebug() << "  Output:" << outputPath;
        qDebug() << "  Private key size:" << privateKey.size();
        qDebug() << "  Share dir:" << shareDir;
        qDebug() << "  Master key size:" << m_masterKey.size();
        qDebug() << "  Wrapped key - PQC size:" << wrappedKey.pqcCiphertext.size();
        qDebug() << "  Wrapped key - DEK size:" << wrappedKey.wrappedDEK.size();

        emit decryptionProgress(30);

        DiskDecryptor decryptor;
        decryptor.decryptDisk(
            inputPath.toStdString(),
            outputPath.toStdString(),
            qbaToVector(privateKey),
            shareDir.toStdString(),
            qbaToVector(m_masterKey),
            wrappedKey  // PASS THE WRAPPED KEY
            );

        qDebug() << "Step 9: Decryption completed successfully";
        emit decryptionProgress(100);

        AuditLogger::logEvent("Disk decrypted: " + inputPath.toStdString());
        emit operationCompleted(true, "Disk decrypted successfully!");

        qDebug() << "=== DECRYPTION DEBUG END (SUCCESS) ===\n";
        return true;

    } catch (const std::exception &e) {
        qDebug() << "=== DECRYPTION DEBUG END (EXCEPTION) ===";
        qDebug() << "Exception:" << e.what();
        emit operationCompleted(false, QString("Decryption failed: %1").arg(e.what()));
        return false;
    } catch (...) {
        qDebug() << "=== DECRYPTION DEBUG END (UNKNOWN EXCEPTION) ===";
        emit operationCompleted(false, "Unknown error during decryption");
        return false;
    }
}
void AppController::cancelOperation()
{
    emit statusChanged("Operation cancelled");
    emit operationCompleted(false, "Operation cancelled");
}

// ==================== KEY MANAGEMENT ====================

QString AppController::generateKeyPair()
{
    try {
        PQCKeyPair keyPair = PQC::generateKeypair();

        QString keyDir = getConfigPath() + "/keys_" +
                         QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");
        QDir().mkpath(keyDir);

        writeFile(keyDir + "/public.key", vectorToQba(keyPair.publicKey));
        writeFile(keyDir + "/private.key", vectorToQba(keyPair.secretKey));

        AuditLogger::logEvent("Key pair generated");
        emit operationCompleted(true, "Key pair generated");

        return keyDir;

    } catch (const std::exception &e) {
        emit operationCompleted(false, QString("Key generation failed: %1").arg(e.what()));
        return QString();
    }
}

QByteArray AppController::generateDEK()
{
    try {
        std::vector<uint8_t> dek = HybridEncryption::generateDEK();
        return vectorToQba(dek);
    } catch (const std::exception &e) {
        emit logMessage(QString("DEK generation failed: %1").arg(e.what()));
        return QByteArray();
    }
}

// ==================== SHARE MANAGEMENT ====================

QStringList AppController::createShares(const QByteArray &secret, int total, int required)
{
    try {
        std::vector<uint8_t> secretVec = qbaToVector(secret);
        std::vector<Share> shares = ShamirSSS::splitSecret(secretVec, required, total);

        QStringList result;
        for (const auto &share : shares) {
            QString shareStr = QString("%1:%2")
            .arg(share.index)
                .arg(QString(vectorToQba(share.value).toHex()));
            result.append(shareStr);
        }

        return result;

    } catch (const std::exception &e) {
        emit logMessage(QString("Share creation failed: %1").arg(e.what()));
        return QStringList();
    }
}

QByteArray AppController::recoverFromShares(const QStringList &sharePaths)
{
    if (!m_isAuthenticated) {
        emit operationCompleted(false, "Authentication required");
        return QByteArray();
    }

    if (!PolicyEnforcer::canRecoverKey(m_currentUser.toStdString())) {
        emit operationCompleted(false, "Key recovery not permitted");
        return QByteArray();
    }

    emit operationStarted("Recovering Key");

    try {
        // Convert paths
        std::vector<std::string> stdPaths;
        for (const QString &path : sharePaths) {
            stdPaths.push_back(path.toStdString());
        }

        // Get master key
        if (m_masterKey.isEmpty()) {
            m_masterKey = QByteArray(32, 'A');
        }

        // Recover key
        std::vector<uint8_t> recovered = KeyRecovery::recoverKey(
            stdPaths,
            3, // threshold
            qbaToVector(m_masterKey)
            );

        QByteArray result = vectorToQba(recovered);

        AuditLogger::logEvent("Key recovered");
        emit operationCompleted(true, "Key recovered successfully!");

        return result;

    } catch (const std::exception &e) {
        emit operationCompleted(false, QString("Key recovery failed: %1").arg(e.what()));
        return QByteArray();
    }
}

// ==================== HELPER METHODS ====================

QByteArray AppController::readFile(const QString &path) const
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return QByteArray();
    }
    QByteArray data = file.readAll();
    file.close();
    return data;
}

bool AppController::writeFile(const QString &path, const QByteArray &data) const
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }
    qint64 written = file.write(data);
    file.close();
    return written == data.size();
}

QString AppController::getConfigPath() const
{
    return QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation) +
           "/QuantumSafe";
}

// ==================== GETTERS ====================

bool AppController::isAuthenticated() const
{
    QMutexLocker locker(&m_mutex);
    return m_isAuthenticated;
}

QString AppController::currentUser() const
{
    QMutexLocker locker(&m_mutex);
    return m_currentUser;
}

QString AppController::getSystemStatus() const
{
    QMutexLocker locker(&m_mutex);

    return QString(
               "QuantumSafe Disk Encryption\n"
               "Status: %1\n"
               "User: %2\n"
               "System: Ready"
               ).arg(
            m_isAuthenticated ? "Authenticated" : "Not authenticated",
            m_currentUser.isEmpty() ? "None" : m_currentUser
            );
}
