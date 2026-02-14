/*
 *  logger.cpp
 *
 *  Copyright (c) 2026 <Aleksei Gurov>
 *
 */
#include "private/logger.h"
#include <iostream>
#include <functional>
#include <mutex>
#include <chrono>
#include <thread>
#include <iomanip>
#include <sstream>

namespace https_client {

Logger::Logger(LogCallback callback) : callback_(std::move(callback)) {}

void Logger::log(LogLevel level, const std::string& message) {
    std::string formatted_message = formatMessage(level, message);
    if (callback_) {
        callback_(level, formatted_message);
    }
}


void Logger::setCallback(LogCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = std::move(callback);
}
std::string Logger::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}


std::string Logger::getCurrentThreadId() {
    std::stringstream ss;
    ss << std::this_thread::get_id();
    return ss.str();
}

std::string Logger::formatMessage(LogLevel level, const std::string& message) {
    std::stringstream formatted;

    // Format: [timestamp] [level] [thread_id] message
    formatted << "[" << getCurrentTimestamp() << "] "
              << "[" << levelToString(level) << "] "
              << "[Thread:" << getCurrentThreadId() << "] "
              << message;

    return formatted.str();
}

void Logger::debug(const std::string& message) {
    log(LogLevel::DEBUG, message);
}

void Logger::info(const std::string& message) {
    log(LogLevel::INFO, message);
}

void Logger::warning(const std::string& message) {
    log(LogLevel::WARNING, message);
}

void Logger::error(const std::string& message) {
    log(LogLevel::ERROR_, message);
}

void Logger::critical(const std::string& message) {
    log(LogLevel::CRITICAL, message);
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR_: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}


} // namespace https_client