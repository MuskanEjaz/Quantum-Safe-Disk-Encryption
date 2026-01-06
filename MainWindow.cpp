#include "MainWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QFileDialog>
#include <QMessageBox>
#include <QStatusBar>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_controller(new AppController(this))
{
    setupUI();
    setupConnections();

    setWindowTitle("QuantumSafe Disk Encryption");
    resize(800, 600);

    statusBar()->showMessage("Ready");
}

MainWindow::~MainWindow()
{
}

void MainWindow::setupUI()
{
    QWidget *central = new QWidget(this);
    setCentralWidget(central);

    QVBoxLayout *mainLayout = new QVBoxLayout(central);

    // Create tab widget
    m_tabs = new QTabWidget(this);
    mainLayout->addWidget(m_tabs);

    // ===== TAB 1: LOGIN =====
    QWidget *loginTab = new QWidget;
    QVBoxLayout *loginLayout = new QVBoxLayout(loginTab);

    QGroupBox *authGroup = new QGroupBox("Authentication");
    QFormLayout *authForm = new QFormLayout;

    m_usernameEdit = new QLineEdit;
    m_usernameEdit->setPlaceholderText("Enter username");
    authForm->addRow("Username:", m_usernameEdit);

    m_passwordEdit = new QLineEdit;
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_passwordEdit->setPlaceholderText("Enter password");
    authForm->addRow("Password:", m_passwordEdit);

    QHBoxLayout *buttonLayout = new QHBoxLayout;
    m_loginButton = new QPushButton("Login");
    m_logoutButton = new QPushButton("Logout");
    m_logoutButton->setEnabled(false);
    buttonLayout->addWidget(m_loginButton);
    buttonLayout->addWidget(m_logoutButton);
    authForm->addRow("", buttonLayout);

    m_authStatusLabel = new QLabel("Not logged in");
    authForm->addRow("Status:", m_authStatusLabel);

    authGroup->setLayout(authForm);
    loginLayout->addWidget(authGroup);
    loginLayout->addStretch();

    m_tabs->addTab(loginTab, "Login");

    // ===== TAB 2: ENCRYPT =====
    QWidget *encryptTab = new QWidget;
    QVBoxLayout *encryptLayout = new QVBoxLayout(encryptTab);

    QGroupBox *encryptGroup = new QGroupBox("Encrypt Disk/File");
    QFormLayout *encryptForm = new QFormLayout;

    m_encryptInputEdit = new QLineEdit;
    QPushButton *browseInput = new QPushButton("Browse...");
    QHBoxLayout *inputLayout = new QHBoxLayout;
    inputLayout->addWidget(m_encryptInputEdit);
    inputLayout->addWidget(browseInput);
    encryptForm->addRow("Input File:", inputLayout);

    m_encryptOutputEdit = new QLineEdit;
    QPushButton *browseOutput = new QPushButton("Browse...");
    QHBoxLayout *outputLayout = new QHBoxLayout;
    outputLayout->addWidget(m_encryptOutputEdit);
    outputLayout->addWidget(browseOutput);
    encryptForm->addRow("Output File:", outputLayout);

    m_encryptProgress = new QProgressBar;
    encryptForm->addRow("Progress:", m_encryptProgress);

    m_encryptButton = new QPushButton("Start Encryption");
    m_encryptButton->setEnabled(false);
    encryptForm->addRow("", m_encryptButton);

    encryptGroup->setLayout(encryptForm);
    encryptLayout->addWidget(encryptGroup);
    encryptLayout->addStretch();

    m_tabs->addTab(encryptTab, "Encrypt");
    m_tabs->setTabEnabled(1, false); // Disable until login

    // ===== TAB 3: DECRYPT =====

    QWidget *decryptTab = new QWidget;
    QVBoxLayout *decryptLayout = new QVBoxLayout(decryptTab);

    QGroupBox *decryptGroup = new QGroupBox("Decrypt Disk/File");
    QFormLayout *decryptForm = new QFormLayout;

    m_decryptInputEdit = new QLineEdit;
    QPushButton *browseDecryptInput = new QPushButton("Browse...");
    QHBoxLayout *decryptInputLayout = new QHBoxLayout;
    decryptInputLayout->addWidget(m_decryptInputEdit);
    decryptInputLayout->addWidget(browseDecryptInput);
    decryptForm->addRow("Input File:", decryptInputLayout);

    m_decryptOutputEdit = new QLineEdit;
    QPushButton *browseDecryptOutput = new QPushButton("Browse...");
    QHBoxLayout *decryptOutputLayout = new QHBoxLayout;
    decryptOutputLayout->addWidget(m_decryptOutputEdit);
    decryptOutputLayout->addWidget(browseDecryptOutput);
    decryptForm->addRow("Output File:", decryptOutputLayout);

    m_decryptProgress = new QProgressBar;
    decryptForm->addRow("Progress:", m_decryptProgress);

    m_decryptButton = new QPushButton("Start Decryption");
    m_decryptButton->setEnabled(false);
    decryptForm->addRow("", m_decryptButton);

    decryptGroup->setLayout(decryptForm);
    decryptLayout->addWidget(decryptGroup);
    decryptLayout->addStretch();

    m_tabs->addTab(decryptTab, "Decrypt");
    m_tabs->setTabEnabled(2, false);

    // ===== TAB 4: RECOVER =====

    QWidget *recoverTab = new QWidget;
    QVBoxLayout *recoverLayout = new QVBoxLayout(recoverTab);

    QGroupBox *recoverGroup = new QGroupBox("Key Recovery");
    QVBoxLayout *recoverGroupLayout = new QVBoxLayout;

    m_sharesEdit = new QTextEdit;
    m_sharesEdit->setPlaceholderText("Enter share data or load from files...");
    recoverGroupLayout->addWidget(new QLabel("Shares:"));
    recoverGroupLayout->addWidget(m_sharesEdit);

    // === ADD BROWSE BUTTON FOR SHARES ===
    QPushButton *loadSharesButton = new QPushButton("Load Share Files...");
    recoverGroupLayout->addWidget(loadSharesButton);

    m_recoverButton = new QPushButton("Recover Key");
    m_recoverButton->setEnabled(false);
    recoverGroupLayout->addWidget(m_recoverButton);

    recoverGroupLayout->addWidget(new QLabel("Recovered Key:"));
    m_recoveredKeyEdit = new QTextEdit;
    m_recoveredKeyEdit->setReadOnly(true);
    recoverGroupLayout->addWidget(m_recoveredKeyEdit);

    recoverGroup->setLayout(recoverGroupLayout);
    recoverLayout->addWidget(recoverGroup);
    recoverLayout->addStretch();

    m_tabs->addTab(recoverTab, "Recover");
    m_tabs->setTabEnabled(3, false);

    // ===== TAB 5: LOGS =====
    QWidget *logTab = new QWidget;
    QVBoxLayout *logLayout = new QVBoxLayout(logTab);

    m_logText = new QTextEdit;
    m_logText->setReadOnly(true);
    logLayout->addWidget(m_logText);

    m_tabs->addTab(logTab, "Logs");

    // Status bar
    m_statusLabel = new QLabel;
    statusBar()->addWidget(m_statusLabel);

    // Connect browse buttons
    connect(browseInput, &QPushButton::clicked, [this]() {
        QString file = QFileDialog::getOpenFileName(this, "Select file to encrypt");
        if (!file.isEmpty()) m_encryptInputEdit->setText(file);
    });

    connect(browseOutput, &QPushButton::clicked, [this]() {
        QString file = QFileDialog::getSaveFileName(this, "Save encrypted file as");
        if (!file.isEmpty()) m_encryptOutputEdit->setText(file);
    });

    connect(browseDecryptInput, &QPushButton::clicked, [this]() {
        QString file = QFileDialog::getOpenFileName(this, "Select file to decrypt");
        if (!file.isEmpty()) m_decryptInputEdit->setText(file);
    });

    connect(browseDecryptOutput, &QPushButton::clicked, [this]() {
        QString file = QFileDialog::getSaveFileName(this, "Save decrypted file as");
        if (!file.isEmpty()) m_decryptOutputEdit->setText(file);
    });
    connect(loadSharesButton, &QPushButton::clicked, [this]() {
        // Allow selecting multiple files
        QStringList newFiles = QFileDialog::getOpenFileNames(
            this,
            "Select Share Files",
            QDir::homePath(),
            "Share Files (*.share *.dat *.txt);;All Files (*.*)"
            );

        if (!newFiles.isEmpty()) {
            // Append new files to existing selection
            for (int i = 0; i < newFiles.size(); i++) {
                const QString &file = newFiles[i];
                // Avoid duplicates
                if (!m_selectedShareFiles.contains(file)) {
                    m_selectedShareFiles.append(file);
                }
            }

            // Display in the text edit
            QString displayText = QString("Loaded %1 share file(s):\n\n").arg(m_selectedShareFiles.size());
            for (int i = 0; i < m_selectedShareFiles.size(); i++) {
                QString fileName = QFileInfo(m_selectedShareFiles[i]).fileName();
                displayText += QString("%1. %2\n").arg(i+1).arg(fileName);
            }

            m_sharesEdit->setPlainText(displayText);

            // Enable recover button if we have enough shares (3 for example)
            m_recoverButton->setEnabled(m_selectedShareFiles.size() >= 3);
        }
    });
}

void MainWindow::setupConnections()
{
    connect(m_loginButton, &QPushButton::clicked, this, &MainWindow::onLogin);
    connect(m_logoutButton, &QPushButton::clicked, this, &MainWindow::onLogout);
    connect(m_encryptButton, &QPushButton::clicked, this, &MainWindow::onEncrypt);
    connect(m_decryptButton, &QPushButton::clicked, this, &MainWindow::onDecrypt);
    connect(m_recoverButton, &QPushButton::clicked, this, &MainWindow::onRecover);


    connect(m_controller, &AppController::operationCompleted,
            this, &MainWindow::onOperationCompleted);
    connect(m_controller, &AppController::statusChanged,
            this, &MainWindow::onStatusChanged);
    connect(m_controller, &AppController::logMessage,
            this, &MainWindow::onLogMessage);
}

void MainWindow::onLogin()
{
    QString username = m_usernameEdit->text();
    QString password = m_passwordEdit->text();

    if (username.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please enter username and password");
        return;
    }

    bool success = m_controller->login(username, password);
    if (success) {
        m_authStatusLabel->setText("Logged in as " + username);
        m_loginButton->setEnabled(false);
        m_logoutButton->setEnabled(true);
        m_encryptButton->setEnabled(true);
        m_decryptButton->setEnabled(true);
        m_recoverButton->setEnabled(true);

        // Enable all tabs except login
        for (int i = 1; i < m_tabs->count(); i++) {
            m_tabs->setTabEnabled(i, true);
        }
        m_tabs->setCurrentIndex(1); // Switch to encrypt tab
    }
}

void MainWindow::onLogout()
{
    m_controller->logout();
    m_authStatusLabel->setText("Not logged in");
    m_loginButton->setEnabled(true);
    m_logoutButton->setEnabled(false);
    m_encryptButton->setEnabled(false);
    m_decryptButton->setEnabled(false);
    m_recoverButton->setEnabled(false);

    // Disable all tabs except login
    for (int i = 1; i < m_tabs->count(); i++) {
        m_tabs->setTabEnabled(i, false);
    }
    m_tabs->setCurrentIndex(0); // Switch to login tab
}

void MainWindow::onEncrypt()
{
    QString input = m_encryptInputEdit->text();
    QString output = m_encryptOutputEdit->text();

    if (input.isEmpty() || output.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please select input and output files");
        return;
    }

    bool success = m_controller->encryptDisk(input, output);
    if (!success) {
        // Error shown via signal
    }
}

void MainWindow::onDecrypt()
{
    QString input = m_decryptInputEdit->text();
    QString output = m_decryptOutputEdit->text();

    if (input.isEmpty() || output.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please select input and output files");
        return;
    }

    bool success = m_controller->decryptDisk(input, output);
    if (!success) {
        // Error shown via signal
    }
}
void MainWindow::onRecover()
{
    if (m_selectedShareFiles.isEmpty()) {
        QMessageBox::warning(this, "Error", "No share files selected. Please load share files first.");
        return;
    }

    if (m_selectedShareFiles.size() < 3) {
        QMessageBox::warning(this, "Error",
                             QString("Need at least 3 share files for recovery. Only %1 provided.")
                                 .arg(m_selectedShareFiles.size()));
        return;
    }

    // Show a simple message instead of progress dialog
    statusBar()->showMessage("Recovering key...");
    m_recoverButton->setEnabled(false);

    // Call controller to recover key
    QByteArray recoveredKey = m_controller->recoverFromShares(m_selectedShareFiles);

    if (recoveredKey.isEmpty()) {
        statusBar()->showMessage("Recovery failed", 3000);
        QMessageBox::warning(this, "Recovery Failed",
                             "Failed to recover key from the provided shares.");
        m_recoverButton->setEnabled(true);
        return;
    }

    // Display the recovered key
    QString hexKey = recoveredKey.toHex();
    m_recoveredKeyEdit->setPlainText(hexKey);

    statusBar()->showMessage("Key recovered successfully", 3000);

    QMessageBox::information(this, "Success",
                             QString("Key recovered successfully!\n\n"
                                     "Key length: %1 bytes\n"
                                     "Full key displayed in the text box below.")
                                 .arg(recoveredKey.size()));

    m_recoverButton->setEnabled(true);
}

void MainWindow::onOperationCompleted(bool success, const QString &message)
{
    m_logText->append(QString("[%1] %2").arg(
        QDateTime::currentDateTime().toString("hh:mm:ss"), message));

    if (success) {
        m_statusLabel->setText("Success: " + message);
        statusBar()->showMessage("Operation completed", 3000);
    } else {
        m_statusLabel->setText("Error: " + message);
        statusBar()->showMessage("Operation failed", 3000);
        QMessageBox::warning(this, "Error", message);
    }
}

void MainWindow::onStatusChanged(const QString &status)
{
    statusBar()->showMessage(status, 3000);
    m_logText->append("[STATUS] " + status);
}

void MainWindow::onLogMessage(const QString &log)
{
    m_logText->append(log);
}
