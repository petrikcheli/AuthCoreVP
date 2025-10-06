cmake_minimum_required(VERSION 3.20)
project(AuthCoreVP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Добавляем подпроекты
add_subdirectory(client)
add_subdirectory(server)
