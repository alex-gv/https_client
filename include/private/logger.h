#pragma once

#include "public/common_types.h"

#include <string>
#include <functional>
#include <mutex>

namespace https_client {

class Logger {
 public:
    using LogCallback = std::function<void(LogLevel level, const std::string& message)>;

    explicit Logger(LogCallback callback = nullptr);

    void setCallback(LogCallback callback);

    void log(LogLevel level, const std::string& message);
    void debug(const std::string& message);
    void info(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);
    void critical(const std::string& message);

    static std::string levelToString(LogLevel level);

 private:
    static std::string getCurrentTimestamp();
    static std::string getCurrentThreadId();
    static std::string formatMessage(LogLevel level, const std::string& message);

 private:
    LogCallback callback_;
    std::mutex mutex_;
};

}  // namespace https_client