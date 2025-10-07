project(server LANGUAGES CXX)
cmake_minimum_required(VERSION 3.20)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Crow CONFIG REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)
find_path(SQLITE_MODERN_CPP_INCLUDE_DIRS "sqlite_modern_cpp.h")
find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(server
    main.cpp
    data_base.h
    password_hasher.h
    jwt_manager.h
)

target_link_libraries(server PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(server PRIVATE jwt-cpp::jwt-cpp)
target_include_directories(server PRIVATE ${SQLITE_MODERN_CPP_INCLUDE_DIRS})
target_link_libraries(server PRIVATE unofficial::sqlite3::sqlite3)
target_link_libraries(server PRIVATE Crow::Crow asio::asio)
target_link_libraries(server PRIVATE unofficial-sodium::sodium)
# todo: сделать условие для unix
if (WIN32)
    target_link_libraries(server PRIVATE wsock32 ws2_32)
endif()

# Копируем templates и static рядом с бинарником после сборки
add_custom_target(copy_resources ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/templates
            ${CMAKE_BINARY_DIR}/templates
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/static
            ${CMAKE_BINARY_DIR}/static
)


include(GNUInstallDirs)
install(TARGETS server
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
