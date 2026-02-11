#pragma once

#if defined(_WIN32) || defined(_WIN64)
    #ifdef HTTPS_CLIENT_BUILDING_DLL
        #define HTTPS_CLIENT_API __declspec(dllexport)
    #else
        #define HTTPS_CLIENT_API __declspec(dllimport)
    #endif
    #define HTTPS_CLIENT_CALL __stdcall
#else
    #define HTTPS_CLIENT_API __attribute__((visibility("default")))
    #define HTTPS_CLIENT_CALL
#endif