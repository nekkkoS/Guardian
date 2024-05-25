cmake_minimum_required(VERSION 3.27)
project(Guardian)

set(license_key "AAC780D096627F84E425679EE2A916247F7B716D675AF9CBAF1C7A093B07F8CDDBB64BAD59A25A6F1E39E98D422C775B684CFC2AA2BD7D13E5B3DAF7DFF02F61")

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_MODULE_PATH "${CMAKE_BINARY_DIR};${CMAKE_MODULE_PATH}")

add_executable(Guardian main.cpp
        Guardian/src/Guardian.cpp
        Guardian/inc/Guardian.hpp)

set_property(TARGET "${PROJECT_NAME}" PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

target_compile_definitions(${PROJECT_NAME} PRIVATE LicenseKey="${license_key}")

find_package(nlohmann_json REQUIRED)
if (nlohmann_json_FOUND)
    target_include_directories(${PROJECT_NAME} PUBLIC ${nlohmann_json_INCLUDE_DIRS})
    target_link_libraries(${PROJECT_NAME} ${nlohmann_json_LIBRARIES})
endif()

find_package( cryptopp REQUIRED )
if(cryptopp_FOUND)
    include_directories(${PROJECT_NAME} ${cryptopp_INCLUDE_DIRS})
    TARGET_LINK_LIBRARIES( ${PROJECT_NAME} ${cryptopp_LIBS})
endif()