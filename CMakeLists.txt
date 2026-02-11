cmake_minimum_required(VERSION 3.16)
project(https_client VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Политика видимости символов
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
endif()

add_definitions(-DHTTPS_CLIENT_BUILDING_DLL)
add_definitions(-D_WIN32_WINNT=0x0601)

find_package(Boost REQUIRED COMPONENTS system regex)
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS beast)


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

#add_subdirectory(tests)
add_subdirectory(example)


include(InstallRequiredSystemLibraries)

set(CPACK_PACKAGE_NAME "https_client")
set(CPACK_PACKAGE_VENDOR "Alex-gv")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "HTTPS client library")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})

set(CPACK_PACKAGE_CONTACT "www.aleksej@gmail.com")

set(CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}"
)

if(WIN32)
    set(CPACK_GENERATOR "ZIP")
else()
    set(CPACK_GENERATOR "TGZ")
endif()

include(CPack)
