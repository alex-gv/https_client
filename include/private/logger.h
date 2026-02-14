/*
 *  logger.h
 *
 *  Copyright (c) 2026 <Aleksei Gurov>
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

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