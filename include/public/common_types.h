#pragma once
#include "public/https_client_export.h"

#include <string>
#include <vector>
#include <functional>
#include <any>

namespace https_client {

// public
enum class HTTPS_CLIENT_API LogLevel { DEBUG, INFO, WARNING, ERROR_, CRITICAL };

struct HTTPS_CLIENT_API Response {
    int status{-1};
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    std::string version;
    std::string reason;
    std::string url;
    bool success{true};
    std::string errorMessage;

    bool isOk() const {
        return status == 200;
    }

    std::string getHeader(const std::string& name, const std::string& defaultValue = "") const {
        auto it = headers.find(name);
        return it != headers.end() ? it->second : defaultValue;
    }
};

enum class HTTPS_CLIENT_API Method { GET, POST, PUT, DELETE_, PATCH, HEAD, OPTIONS };

struct HTTPS_CLIENT_API RequestConfig {
    std::string url;
    std::any body;
    std::string contentType{"application/json"};
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> queryParams;
    std::unordered_map<std::string, std::string> formData;
    std::string userAgent;

    int timeoutSeconds{10};
    int connectTimeoutSeconds{3};
    bool followRedirects{true};
    int maxRedirects{5};
    bool verifySsl = true;
    std::string sslCertificateFile;
    std::vector<std::string> sslCiphers;

    RequestConfig(const std::string& url) : url(url) {}
    RequestConfig() = default;
};

struct HTTPS_CLIENT_API ExternalRequestConfig : public RequestConfig {
    ExternalRequestConfig()= default;
    ExternalRequestConfig(const RequestConfig& cfg, Method method) {
        this->url = cfg.url;
        this->body = cfg.body;
        this->contentType = cfg.contentType;
        this->headers = cfg.headers;
        this->queryParams = cfg.queryParams;
        this->formData = cfg.formData;
        this->userAgent = cfg.userAgent;
        this->timeoutSeconds = cfg.timeoutSeconds;
        this->connectTimeoutSeconds = cfg.connectTimeoutSeconds;
        this->followRedirects = cfg.followRedirects;
        this->maxRedirects = cfg.maxRedirects;
        this->verifySsl = cfg.verifySsl;
        this->sslCertificateFile = cfg.sslCertificateFile;
        this->sslCiphers = cfg.sslCiphers;
        this->method = method;
    }
    ExternalRequestConfig(const std::string& url, Method method) : RequestConfig(url), method(method) {}

    Method method{Method::GET};
};

using ResponseCallback = std::function<void(const Response&)>;
using ErrorCallback = std::function<void(const std::string&)>;
using LogCallback = std::function<void(LogLevel level, const std::string& message)>;


// private
inline std::string methodToString(Method method) {
    switch (method) {
        case Method::GET:
            return "GET";
        case Method::POST:
            return "POST";
        case Method::PUT:
            return "PUT";
        case Method::DELETE_:
            return "DELETE";
        case Method::PATCH:
            return "PATCH";
        case Method::HEAD:
            return "HEAD";
        case Method::OPTIONS:
            return "OPTIONS";
        default:
            return "GET";
    }
};

}  // namespace https_client