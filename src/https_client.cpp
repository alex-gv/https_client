#include "public/https_client.h"
#include <private/ssl_context_builder.h>
#include "private/logger.h"
#include "private/http_session.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>
#include <boost/beast.hpp>

#include <iostream>
#include <chrono>
#include <memory>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;

namespace https_client {

// Implementation class
class HttpsClient::Impl {
 public:
    explicit Impl(size_t threads);
    explicit Impl(LogCallback log_callback, size_t threads);
    ~Impl();

    void setLogCallback(LogCallback callback);
    Response executeRequest(const ExternalRequestConfig& config);
    void executeRequestAsync(const ExternalRequestConfig& config, ResponseCallback callback);
    std::future<Response> executeRequestWithFuture(const ExternalRequestConfig& config);
    void executeParallel(const std::vector<ExternalRequestConfig>& configs,
                         std::function<void(const std::vector<Response>&)> completion_callback);
    std::unique_ptr<ssl::context> createSslContext(const ExternalRequestConfig& config);

 private:
    void initialize(size_t threads);

 private:
    net::io_context ioc_;
    net::executor_work_guard<net::io_context::executor_type> work_guard_;
    std::vector<std::thread> threads_;
    Logger logger_;
};

// Static helper function implementations
std::unique_ptr<ssl::context> HttpsClient::Impl::createSslContext(const ExternalRequestConfig& config) {
    SSLCustomContextBuilder ctx_builder;
    auto ctx = ctx_builder.CreateContext(ssl::context::tls_client);

    ctx->set_default_verify_paths();
    ctx->set_options(ssl::context::default_workarounds);

    if (config.verifySsl) {
        ctx->set_verify_mode(ssl::verify_peer);
        ctx->set_verify_callback([](bool preverified, ssl::verify_context& ctx) { return true; });
    } else {
        ctx->set_verify_mode(ssl::verify_none);
    }

    if (!config.sslCertificateFile.empty()) {
        ctx->load_verify_file(config.sslCertificateFile);
    }

    if (!config.sslCiphers.empty()) {
        std::string ciphers;
        for (const auto& cipher : config.sslCiphers) {
            if (!ciphers.empty())
                ciphers += ":";
            ciphers += cipher;
        }
        SSL_CTX_set_cipher_list(ctx->native_handle(), ciphers.c_str());
    }

    return ctx;
}

void HttpsClient::Impl::initialize(size_t threads) {
    logger_.info("HttpsClient initialized with " + std::to_string(threads) + " threads");

    for (size_t i = 0; i < threads; ++i) {
        threads_.emplace_back([this]() {
            try {
                logger_.debug("IO thread started");
                ioc_.run();
                logger_.debug("IO thread stopped");
            } catch (const std::exception& e) {
                logger_.error("IO Context exception: " + std::string(e.what()));
            }
        });
    }
}

// Constructors
HttpsClient::Impl::Impl(size_t threads) : ioc_(threads > 0 ? threads : 1), work_guard_(net::make_work_guard(ioc_)) {
    initialize(threads);
}

HttpsClient::Impl::Impl(LogCallback log_callback, size_t threads)
    : ioc_(threads > 0 ? threads : 1), work_guard_(net::make_work_guard(ioc_)), logger_(std::move(log_callback)) {
    initialize(threads);
}

// Destructor
HttpsClient::Impl::~Impl() {
    logger_.info("Shutting down HttpsClient");
    work_guard_.reset();
    ioc_.stop();
    for (auto& thread : threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    logger_.info("HttpsClient shutdown complete");
}

// Configuration methods
void HttpsClient::Impl::setLogCallback(LogCallback callback) {
    logger_.setCallback(std::move(callback));
    logger_.info("Log callback set");
}

// Async request execution methods
void HttpsClient::Impl::executeRequestAsync(const ExternalRequestConfig& config, ResponseCallback callback) {
    logger_.debug("Queueing " + methodToString(config.method)+ " request to: " + config.url);
    auto ssl_ctx = createSslContext(config);
    auto session = std::make_shared<HttpSession>(ioc_, std::move(ssl_ctx), config, std::move(callback), logger_);
    session->run();
}

std::future<Response> HttpsClient::Impl::executeRequestWithFuture(const ExternalRequestConfig& config) {
    auto promise = std::make_shared<std::promise<Response>>();
    auto future = promise->get_future();

    executeRequestAsync(config, [promise](const Response& response) {
        try {
            promise->set_value(response);
        } catch (const std::future_error& e) {
            if (e.code() != std::future_errc::promise_already_satisfied) {
                std::cerr << "Future error: " << e.what() << std::endl;
            }
        }
    });

    return future;
}

// Parallel execution
void HttpsClient::Impl::executeParallel(const std::vector<ExternalRequestConfig>& configs,
                                        std::function<void(const std::vector<Response>&)> completion_callback) {
    logger_.info("Starting parallel execution of " + std::to_string(configs.size()) + " requests");

    auto responses = std::make_shared<std::vector<Response>>(configs.size());
    auto counter = std::make_shared<std::atomic<int>>(0);
    auto mutex = std::make_shared<std::mutex>();

    for (size_t i = 0; i < configs.size(); ++i) {
        executeRequestAsync(
            configs[i], [responses, i, counter, configs, completion_callback, mutex, this](const Response& response) {
                {
                    std::lock_guard<std::mutex> lock(*mutex);
                    (*responses)[i] = response;
                }

                int completed = counter->fetch_add(1) + 1;
                logger_.debug("Parallel request completed: " + std::to_string(completed) + "/" +
                              std::to_string(configs.size()));

                if (completed == static_cast<int>(configs.size())) {
                    logger_.info("All parallel requests completed");
                    completion_callback(*responses);
                }
            });
    }
}

Response HttpsClient::Impl::executeRequest(const ExternalRequestConfig& config) {
    Response response;
    response.url = config.url;

    try {
        auto ssl_ctx = HttpsClient::Impl::createSslContext(config);

        std::promise<Response> promise;
        std::future<Response> future = promise.get_future();

        bool callback_called = false;

        auto session = std::make_shared<HttpSession>(
            ioc_, std::move(ssl_ctx), config,
            [&promise, &callback_called](const Response& resp) {
                if (!callback_called) {
                    callback_called = true;
                    promise.set_value(resp);
                }
            },
            logger_);
        session->run();
        response = future.get();
    } catch (const std::exception& e) {
        response.status = 0;
        response.success = false;
        response.errorMessage = "Error: " + std::string(e.what());
        response.reason = response.errorMessage;
        logger_.error("Request failed: " + response.errorMessage);
    } catch (...) {
        response.status = 0;
        response.success = false;
        response.errorMessage = "Unknown error";
        response.reason = response.errorMessage;
        logger_.error("Request failed with unknown error");
    }

    return response;
}

// HttpsClient public interface implementation
HttpsClient::HttpsClient(size_t threads) : impl_(std::make_unique<Impl>(threads)) {}

HttpsClient::HttpsClient(LogCallback log_callback, size_t threads)
    : impl_(std::make_unique<Impl>(std::move(log_callback), threads)) {}

HttpsClient::~HttpsClient() = default;

void HttpsClient::setLogCallback(LogCallback callback) {
    impl_->setLogCallback(std::move(callback));
}

Response HttpsClient::get(const RequestConfig& config) {
    ExternalRequestConfig new_config(config,  Method::GET);
    return impl_->executeRequest(new_config);
}

Response HttpsClient::post(const RequestConfig& config) {
    ExternalRequestConfig new_config(config,  Method::POST);
    return impl_->executeRequest(new_config);
}

Response HttpsClient::put(const RequestConfig& config) {
    ExternalRequestConfig new_config(config,  Method::PUT);
    return impl_->executeRequest(new_config);
}

Response HttpsClient::del(const RequestConfig& config) {
    ExternalRequestConfig new_config(config,  Method::DELETE_);
    return impl_->executeRequest(new_config);
}

void HttpsClient::getAsync(const RequestConfig& config, ResponseCallback callback) {
    ExternalRequestConfig new_config(config,  Method::GET);
    impl_->executeRequestAsync(new_config, std::move(callback));
}

void HttpsClient::postAsync(const RequestConfig& config, ResponseCallback callback) {
    ExternalRequestConfig new_config(config,  Method::POST);
    impl_->executeRequestAsync(new_config, std::move(callback));
}

void HttpsClient::putAsync(const RequestConfig& config, ResponseCallback callback) {
    ExternalRequestConfig new_config(config,  Method::PUT);
    impl_->executeRequestAsync(new_config, std::move(callback));
}

void HttpsClient::deleteAsync(const RequestConfig& config, ResponseCallback callback) {
    ExternalRequestConfig new_config(config,  Method::DELETE_);
    impl_->executeRequestAsync(new_config, std::move(callback));
}

std::future<Response> HttpsClient::getAsync(const RequestConfig& config) {
    ExternalRequestConfig new_config(config,  Method::GET);
    return impl_->executeRequestWithFuture(new_config);
}

std::future<Response> HttpsClient::postAsync(const RequestConfig& config) {
    ExternalRequestConfig new_config(config,  Method::POST);
    return impl_->executeRequestWithFuture(new_config);
}

std::future<Response> HttpsClient::putAsync(const RequestConfig& config) {
    ExternalRequestConfig new_config(config,  Method::PUT);
    return impl_->executeRequestWithFuture(new_config);
}

std::future<Response> HttpsClient::deleteAsync(const RequestConfig& config) {
    ExternalRequestConfig new_config(config,  Method::DELETE_);
    return impl_->executeRequestWithFuture(new_config);
}

void HttpsClient::executeParallel(const std::vector<ExternalRequestConfig>& configs,
                                  std::function<void(const std::vector<Response>&)> completion_callback) {
    impl_->executeParallel(configs, std::move(completion_callback));
}

}  // namespace https_client