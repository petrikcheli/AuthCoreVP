#!/bin/bash
set -ex

# Обновление системы и установка базовых инструментов
sudo apt update
sudo apt install -y autoconf automake libtool pkg-config make cmake git curl flex build-essential \
    qt6-base-dev qt6-tools-dev qt6-tools-dev-tools

# Клонируем и собираем vcpkg
cd /opt
sudo git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
sudo ./bootstrap-vcpkg.sh

# Экспортируем переменные окружения
export VCPKG_ROOT=/opt/vcpkg
export PATH=$PATH:$VCPKG_ROOT

# Клонируем проект
sudo git clone https://github.com/petrikcheli/AuthCoreVP.git
cd AuthCoreVP

# Установка всех зависимостей через vcpkg
sudo $VCPKG_ROOT/vcpkg install sqlite-modern-cpp sqlite3 libsodium jwt-cpp crow gtest curlpp nlohmann-json

# Создаем каталог сборки и собираем проект
mkdir -p build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
make -j$(nproc)
