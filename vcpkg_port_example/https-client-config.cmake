if (TARGET https-client::https-client)
    return()
endif()

get_filename_component(_IMPORT_PREFIX "${CMAKE_CURRENT_LIST_DIR}" DIRECTORY)
get_filename_component(_IMPORT_PREFIX "${_IMPORT_PREFIX}" DIRECTORY)

find_library(https-client_release_path
            PATHS ${_IMPORT_PREFIX}
            PATH_SUFFIXES lib
            NAMES https_client
            REQUIRED)

find_library(https-client_debug_path
            PATHS ${_IMPORT_PREFIX}
            PATH_SUFFIXES debug/lib
            NAMES https_client
            REQUIRED)


set(https-client_release_path_dll ${https-client_release_path})
set(https-client_debug_path_dll ${https-client_debug_path})
if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    cmake_path(REPLACE_EXTENSION https-client_release_path_dll dll)
    cmake_path(REPLACE_EXTENSION https-client_debug_path_dll dll)
endif()

add_library(https-client::https-client SHARED IMPORTED)

set_target_properties(https-client::https-client PROPERTIES
                    IMPORTED_LOCATION_RELEASE ${https-client_release_path_dll}
                    IMPORTED_LOCATION_DEBUG ${https-client_debug_path_dll}
                    IMPORTED_IMPLIB_RELEASE ${https-client_release_path}
                    IMPORTED_IMPLIB_DEBUG ${https-client_debug_path}
                    IMPORTED_NO_SONAME ON)

target_include_directories(https-client::https-client INTERFACE ${_IMPORT_PREFIX}/include)

unset(_IMPORT_PREFIX)
unset(https-client_release_path)
unset(https-client_debug_path)
unset(https-client_release_path_dll)
unset(https-client_debug_path_dll)
