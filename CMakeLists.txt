cmake_minimum_required(VERSION 3.16)

option(ENABLE_TESTS "Build unit tests" OFF)

if(BUILD_TESTING)
  list(APPEND VCPKG_MANIFEST_FEATURES "tests")
endif()


project(https_client VERSION 1.0.0 LANGUAGES CXX)

if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
endif()

add_definitions(-DHTTPS_CLIENT_BUILDING_DLL)

if (WIN32)
    add_compile_definitions(
        _WIN32_WINNT=0x0A00
        WINVER=0x0A00
    )
endif()

find_package(Boost REQUIRED COMPONENTS asio beast system regex)
find_package(OpenSSL REQUIRED)


set(SOURCES
    src/https_client.cpp
    src/logger.cpp
    src/http_session.cpp
    $<$<PLATFORM_ID:Darwin>:src/apple/ssl_context_builder.cpp>
    $<$<NOT:$<PLATFORM_ID:Darwin>>:src/default/ssl_context_builder.cpp>
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)


set(HEADERS_PUBLIC
    include/public/https_client_export.h
    include/public/https_client.h
    include/public/common_types.h
)

set(HEADERS_PRIVATE
    include/private/logger.h
    include/private/http_session.h
    include/private/ssl_context_builder.h
)

add_library(https_client SHARED ${SOURCES} ${HEADERS_PUBLIC} ${HEADERS_PRIVATE})

target_compile_options(https_client PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/bigobj>)
target_include_directories(https_client
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${Boost_INCLUDE_DIRS}
)

if(APPLE)
    find_library(COREFOUNDATION_LIBRARY CoreFoundation)
    find_library(SECURITY_LIBRARY Security)
endif()

if(WIN32)
    set_target_properties(https_client PROPERTIES
        DEFINE_SYMBOL "HTTPS_CLIENT_BUILDING_DLL"
    )
endif()

target_link_libraries(https_client
    PRIVATE
        Boost::system
        Boost::regex
        Boost::beast
        OpenSSL::SSL
        OpenSSL::Crypto
        $<$<PLATFORM_ID:Darwin>:${COREFOUNDATION_LIBRARY}>
        $<$<PLATFORM_ID:Darwin>:${SECURITY_LIBRARY}>
)

install(TARGETS https_client
    EXPORT https_clientTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${HEADERS_PUBLIC}
    DESTINATION include
)

install(EXPORT https_clientTargets
    FILE https_clientConfig.cmake
    NAMESPACE https_client::
    DESTINATION lib/cmake/https_client
)


include(InstallRequiredSystemLibraries)

set(CPACK_PACKAGE_NAME "https-client")
set(CPACK_PACKAGE_VENDOR "Alex-gv")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "HTTPS client library")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})

set(CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}"
)

if(WIN32)
    set(CPACK_GENERATOR "ZIP")
else()
    set(CPACK_GENERATOR "TGZ")
endif()

include(CPack)




add_subdirectory(example)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()