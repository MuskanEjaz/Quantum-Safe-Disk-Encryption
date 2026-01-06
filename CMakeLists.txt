cmake_minimum_required(VERSION 3.16)
project(QuantumSafeGUI)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets)

# List only .cpp files (headers are automatically included)
add_executable(QuantumSafeGUI
    main.cpp
    MainWindow.cpp
    MainWindow.h
    AppController.cpp
    AppController.h
    ../src/auth/AuditLogger.cpp ../src/auth/AuditLogger.h ../src/auth/AuthManager.cpp ../src/auth/AuthManager.h ../src/auth/PasswordHasher.cpp ../src/auth/PasswordHasher.h ../src/auth/PolicyEnforcer.cpp ../src/auth/PolicyEnforcer.h ../src/auth/TwoFactor.cpp ../src/auth/TwoFactor.h ../src/crypto/AES.cpp ../src/crypto/AES.h ../src/crypto/HybridEncryption.cpp ../src/crypto/HybridEncryption.h ../src/crypto/PQC.cpp ../src/crypto/PQC.h ../src/disk/BlockIO.cpp ../src/disk/BlockIO.h ../src/disk/DiskDecryptor.cpp ../src/disk/DiskDecryptor.h ../src/disk/DiskEncryptor.cpp ../src/disk/DiskEncryptor.h ../src/recovery/KeyRecovery.cpp ../src/recovery/KeyRecovery.h ../src/recovery/ShamirSSS.cpp ../src/recovery/ShamirSSS.h ../src/recovery/ShareStorage.cpp ../src/recovery/ShareStorage.h
    mainwindow.ui
)

target_link_libraries(QuantumSafeGUI PRIVATE
    Qt6::Core
    Qt6::Widgets
)
