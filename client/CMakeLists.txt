project(client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Gui)
find_package(Threads REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(unofficial-curlpp CONFIG REQUIRED)
find_package(GTest REQUIRED)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/api
    ${CMAKE_CURRENT_SOURCE_DIR}/dialog
    ${CMAKE_CURRENT_SOURCE_DIR}/mainwindow
)

file(GLOB_RECURSE SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/api/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/dialog/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/mainwindow/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp"
)

file(GLOB_RECURSE TEST_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp"
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE
    unofficial::curlpp::curlpp
    Threads::Threads
    Qt6::Core
    Qt6::Widgets
    Qt6::Gui
    nlohmann_json::nlohmann_json
)

enable_testing()

add_executable(tests ${TEST_SOURCES})

target_link_libraries(tests PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Gui
    GTest::gtest_main
    unofficial::curlpp::curlpp
    nlohmann_json::nlohmann_json
    Threads::Threads
)

include(GoogleTest)
gtest_discover_tests(tests)