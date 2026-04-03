find_package(GTest REQUIRED)
include(GoogleTest)

find_package(httplib CONFIG REQUIRED)
if(APPLE)
    find_library(COREFOUNDATION_LIBRARY CoreFoundation)
    find_library(SECURITY_LIBRARY Security)
endif()

add_executable(https_client_tests
    test_sync_requests.cpp
    test_async_requests.cpp
    test_parallel.cpp
    test_error_handling.cpp
    test_proxy.cpp
)

if(WIN32)
add_custom_command(TARGET https_client_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:https_client>"
        $<TARGET_FILE_DIR:https_client_tests>
)
endif()

target_link_libraries(https_client_tests
    PRIVATE
        GTest::gtest
        GTest::gtest_main
        httplib::httplib
        $<$<PLATFORM_ID:Darwin>:${COREFOUNDATION_LIBRARY}>
        $<$<PLATFORM_ID:Darwin>:${SECURITY_LIBRARY}>
        https_client
)


#add_test(NAME https_clienttests COMMAND https_client_tests)

gtest_discover_tests(https_client_tests)