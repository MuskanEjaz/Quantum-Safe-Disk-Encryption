#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTabWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QLabel>
#include <QProgressBar>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include "AppController.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // Basic operations
    void onLogin();
    void onLogout();
    void onEncrypt();
    void onDecrypt();
    void onRecover();

    // Controller signals
    void onOperationCompleted(bool success, const QString &message);
    void onStatusChanged(const QString &status);
    void onLogMessage(const QString &log);

private:
    void setupUI();
    void setupConnections();

    // UI Components
    QTabWidget *m_tabs;

    // Login Tab
    QLineEdit *m_usernameEdit;
    QLineEdit *m_passwordEdit;
    QPushButton *m_loginButton;
    QPushButton *m_logoutButton;
    QLabel *m_authStatusLabel;

    // Encrypt Tab
    QLineEdit *m_encryptInputEdit;
    QLineEdit *m_encryptOutputEdit;
    QPushButton *m_encryptButton;
    QProgressBar *m_encryptProgress;

    // Decrypt Tab
    QLineEdit *m_decryptInputEdit;
    QLineEdit *m_decryptOutputEdit;
    QPushButton *m_decryptButton;
    QProgressBar *m_decryptProgress;

    // Recover Tab
    QStringList m_shareFiles;  // Store loaded share file paths
    QTextEdit *m_sharesEdit;
    QPushButton *m_recoverButton;
    QTextEdit *m_recoveredKeyEdit;
    QStringList m_selectedShareFiles;  // Store selected share file paths

    // Status
    QLabel *m_statusLabel;
    QTextEdit *m_logText;

    // Controller
    AppController *m_controller;
};

#endif // MAINWINDOW_H
