add_executable(https_client_example
    main.cpp
)

target_link_libraries(https_client_example
    PRIVATE
        https_client
)
