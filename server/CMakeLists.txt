project(server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(Boost_USE_STATIC_LIBS ON)

find_package(Crow CONFIG REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)
find_path(SQLITE_MODERN_CPP_INCLUDE_DIRS "sqlite_modern_cpp.h")
find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS program_options)

# Собираем все исходники, включая файлы из db/
file(GLOB SOURCES
    main.cpp
    haser/*.h
    haser/*.cpp
    jwt/*.h
    jwt/*.cpp
    routes/*.cpp
    routes/*.h
    db/*.cpp
    db/*.h
    cli/*.h
    cli/*.cpp
    rate_limiter/*.h
    rate_limiter/*.cpp
)

# Создаём исполняемый файл
add_executable(${PROJECT_NAME} ${SOURCES})

# Указываем, где искать заголовочные файлы
target_include_directories(${PROJECT_NAME} PRIVATE db jwt hasher routes cli rate_limiter audit)
target_include_directories(${PROJECT_NAME} PRIVATE ${SQLITE_MODERN_CPP_INCLUDE_DIRS})

target_link_libraries(${PROJECT_NAME} PRIVATE
    nlohmann_json::nlohmann_json
    jwt-cpp::jwt-cpp
    unofficial::sqlite3::sqlite3
    Crow::Crow
    asio::asio
    unofficial-sodium::sodium
)

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_include_directories(${PROJECT_NAME} PRIVATE ${Boost_INCLUDE_DIRS})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${Boost_LIBRARIES})
endif()

# todo: сделать условие для unix
if (WIN32)
    target_link_libraries(server PRIVATE wsock32 ws2_32)
endif()

# Копируем templates и static рядом с бинарником после сборки
add_custom_target(copy_resources ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/templates
            $<TARGET_FILE_DIR:${PROJECT_NAME}>/templates
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/static
            $<TARGET_FILE_DIR:${PROJECT_NAME}>/static
)

add_dependencies(${PROJECT_NAME} copy_resources)

include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
