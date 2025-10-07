FROM ubuntu:24.04

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    clang \
    cmake \
    make \
    git \
    build-essential \
    curl \
    zip \
    unzip \
    tar \
    pkg-config \
    libboost-all-dev \
    && rm -rf /var/lib/apt/lists/*

# Установка vcpkg
WORKDIR /opt
RUN git clone https://github.com/microsoft/vcpkg.git && \
    chmod +x vcpkg/bootstrap-vcpkg.sh && \
    ./vcpkg/bootstrap-vcpkg.sh

ENV VCPKG_ROOT=/opt/vcpkg
ENV PATH="${VCPKG_ROOT}:${PATH}"

# Установка библиотек через vcpkg
RUN ${VCPKG_ROOT}/vcpkg install \
    crow \
    jwt-cpp \
    libsodium \
    sqlite3 sqlite-modern-cpp \
    nlohmann-json

WORKDIR /app

# Копируем проект
COPY CMakeLists.txt ./
COPY . .

# Сборка проекта с использованием clang и vcpkg
RUN cmake -B build -S . \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_TOOLCHAIN_FILE=/opt/vcpkg/scripts/buildsystems/vcpkg.cmake \
    && cmake --build build -j$(nproc)

EXPOSE 8081

# Запуск сервера
# CMD ["./build/client/server/Debug/server"]
CMD ["./build/server"]
