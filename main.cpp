#include <QApplication>
#include <QStyleFactory>
#include <QFont>
#include "MainWindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    // Set application metadata
    app.setApplicationName("QuantumSafe Disk Encryption");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("Information Security Team");

    // Set modern style
    app.setStyle(QStyleFactory::create("Fusion"));

    // Set default font
    QFont font("Segoe UI", 10);
    app.setFont(font);

    // Create and show main window
    MainWindow window;
    window.setWindowTitle("QuantumSafe Disk Encryption v1.0");
    window.resize(1200, 800);
    window.show();

    return app.exec();
}
