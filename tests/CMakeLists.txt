include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.17.0
)
FetchContent_MakeAvailable(googletest)

add_executable(https_client_tests
    test_sync.cpp
    test_async.cpp
)

target_link_libraries(https_client_tests
    PRIVATE
        https_client
        gtest_main
)

include(GoogleTest)
gtest_discover_tests(https_client_tests)
