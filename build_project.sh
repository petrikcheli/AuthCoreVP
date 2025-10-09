#!/bin/bash

# Скрипт для сборки AuthCoreVP на Linux
# Работает только на Linux
# Требуется: git, curl, build-essential, cmake, qt6-base-dev, qt6-tools-dev, vcpkg

set -e  # Прерывать выполнение при любой ошибке

echo "=== Установка зависимостей через apt ==="
sudo apt update
sudo apt install -y autoconf automake libtool pkg-config make cmake git curl flex build-essential \
    qt6-base-dev qt6-tools-dev qt6-tools-dev-tools

# Настройка vcpkg
VCPKG_ROOT=${VCPKG_ROOT:-"$HOME/vcpkg"}  # Можно переопределить через переменную окружения

if [ ! -d "$VCPKG_ROOT" ]; then
    echo "=== Клонирование vcpkg ==="
    git clone https://github.com/microsoft/vcpkg.git "$VCPKG_ROOT"
    "$VCPKG_ROOT/bootstrap-vcpkg.sh"
fi

export PATH="$VCPKG_ROOT:$PATH"
echo "VCPKG_ROOT установлен в $VCPKG_ROOT"

# Клонирование проекта, если его нет
PROJECT_DIR=/opt/AuthCoreVP
if [ ! -d "$PROJECT_DIR" ]; then
    echo "=== Клонирование AuthCoreVP ==="
    sudo git clone https://github.com/petrikcheli/AuthCoreVP.git "$PROJECT_DIR"
fi

cd "$PROJECT_DIR"

# Установка зависимостей через vcpkg
echo "=== Установка зависимостей через vcpkg ==="
"$VCPKG_ROOT/vcpkg" install sqlite-modern-cpp sqlite3 libsodium jwt-cpp crow gtest curlpp nlohmann-json

# Создание папки сборки
mkdir -p build
cd build

# Запуск CMake с vcpkg toolchain
echo "=== Конфигурация CMake ==="
cmake .. -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"

# Сборка проекта
echo "=== Сборка проекта ==="
make -j$(nproc)

echo "=== Сборка завершена успешно! ==="
