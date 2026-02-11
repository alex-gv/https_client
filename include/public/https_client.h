#pragma once

#include "public/https_client_export.h"
#include "public/common_types.h"
#include <future>

namespace https_client {

class HTTPS_CLIENT_API HttpsClient {
public:
    // Constructors/Destructor
    explicit HttpsClient(size_t threads = 1);
    explicit HttpsClient(LogCallback logCallback, size_t threads = 1);
    ~HttpsClient();

    // Delete copy and move operations
    HttpsClient(const HttpsClient&) = delete;
    HttpsClient& operator=(const HttpsClient&) = delete;
    HttpsClient(HttpsClient&&) = delete;
    HttpsClient& operator=(HttpsClient&&) = delete;

    void setLogCallback(LogCallback callback);
    // Synchronous methods
    Response get(const RequestConfig& config);
    Response post(const RequestConfig& config);
    Response put(const RequestConfig& config);
    Response del(const RequestConfig& config);

    // Asynchronous methods with callback
    void getAsync(const RequestConfig& config, ResponseCallback callback);
    void postAsync(const RequestConfig& config, ResponseCallback callback);
    void putAsync(const RequestConfig& config, ResponseCallback callback);
    void deleteAsync(const RequestConfig& config, ResponseCallback callback);

    // Asynchronous methods with future
    std::future<Response> getAsync(const RequestConfig& config);
    std::future<Response> postAsync(const RequestConfig& config);
    std::future<Response> putAsync(const RequestConfig& config);
    std::future<Response> deleteAsync(const RequestConfig& config);

    // Parallel execution
    void executeParallel(const std::vector<ExternalRequestConfig>& configs,
                         std::function<void(const std::vector<Response>&)> completionCallback);
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace https_client
