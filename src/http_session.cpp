/*
 *  http_session.cpp
 *
 *  Copyright (c) 2026 <Aleksei Gurov>
 *
 */
#include "private/http_session.h"

#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/regex.hpp>
#include <iomanip>
#include <chrono>


namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

namespace https_client {

namespace {

std::string urlEncode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
    }

    return escaped.str();
}
std::string buildQueryString(const std::unordered_map<std::string, std::string>& params) {
    if (params.empty())
        return "";

    std::string query;
    for (const auto& [key, value] : params) {
        if (!query.empty())
            query += "&";
        query += urlEncode(key) + "=" + urlEncode(value);
    }

    return query;
}

}  // namespace

static http::verb methodToBoostVerb(Method method) {
    switch (method) {
        case  Method::GET:
            return http::verb::get;
        case  Method::POST:
            return http::verb::post;
        case  Method::PUT:
            return http::verb::put;
        case  Method::DELETE_:
            return http::verb::delete_;
        case  Method::PATCH:
            return http::verb::patch;
        case  Method::HEAD:
            return http::verb::head;
        case  Method::OPTIONS:
            return http::verb::options;
        default:
            return http::verb::get;
    }
}

HttpSession::HttpSession(net::io_context& ioc, std::unique_ptr<ssl::context> sslCtx, const ExternalRequestConfig& config,
                         ResponseCallback callback, Logger& logger)
    : ioc_(ioc),
      sslCtx_(std::move(sslCtx)),
      config_(config),
      callback_(std::move(callback)),
      logger_(logger),
      resolver_(net::make_strand(ioc)),
      timer_(net::make_strand(ioc)) {
    result_.url = config.url;

    if (config_.userAgent.empty()) {
        config_.userAgent = "AG Client " + std::string(BOOST_BEAST_VERSION_STRING);
    }
}

void HttpSession::run() {
    try {
        logger_.debug("Starting request to: " + config_.url);

        urlParts_ = parseUrl(config_.url);
        logger_.debug("Parsed URL - Host: " + urlParts_.host + ", Port: " + urlParts_.port +
                      ", Path: " + urlParts_.path);

        if (!config_.queryParams.empty()) {
            std::string queryString = buildQueryString(config_.queryParams);
            if (urlParts_.query.empty()) {
                urlParts_.query = queryString;
            } else {
                urlParts_.query += "&" + queryString;
            }
            logger_.debug("Query string: " + urlParts_.query);
        }

        isHttps_ = (urlParts_.protocol == "https");
        logger_.debug("Protocol: " + urlParts_.protocol + ", HTTPS: " + std::to_string(isHttps_));

        startTimeout();

        logger_.info("Resolving host: " + urlParts_.host);

        resolver_.async_resolve(urlParts_.host, urlParts_.port,
                                beast::bind_front_handler(&HttpSession::onResolve, shared_from_this()));

    } catch (const std::exception& e) {
        logger_.error("Request setup error: " + std::string(e.what()));
        finishWithError("Error: " + std::string(e.what()));
    }
}

HttpSession::UrlParts HttpSession::parseUrl(const std::string& url) {
    UrlParts parts;
    parts.protocol = "http";
    parts.port = "80";
    parts.path = "/";

    boost::regex urlRegex(R"((https?)://([^:/]+)(?::(\d+))?(/[^?#]*)?(?:\?([^#]*))?)");
    boost::smatch matches;

    if (boost::regex_match(url, matches, urlRegex)) {
        parts.protocol = matches[1].str();
        parts.host = matches[2].str();

        if (matches[3].matched) {
            parts.port = matches[3].str();
        } else {
            parts.port = (parts.protocol == "https") ? "443" : "80";
        }

        if (matches[4].matched && !matches[4].str().empty()) {
            parts.path = matches[4].str();
        }

        if (matches[5].matched) {
            parts.query = matches[5].str();
        }
    }

    return parts;
}

std::string HttpSession::getBodyString(const ExternalRequestConfig& config) {
    if (!config.body.has_value()) {
        if (!config.formData.empty() && config.contentType == "application/x-www-form-urlencoded") {
            return buildQueryString(config.formData);
        }
        return "";
    }

    const std::type_info& type = config.body.type();

    if (type == typeid(std::string)) {
        return std::any_cast<std::string>(config.body);
    } else if (type == typeid(const char*)) {
        return std::string(std::any_cast<const char*>(config.body));
    } else if (type == typeid(int)) {
        return std::to_string(std::any_cast<int>(config.body));
    } else if (type == typeid(double)) {
        return std::to_string(std::any_cast<double>(config.body));
    } else if (type == typeid(bool)) {
        return std::any_cast<bool>(config.body) ? "true" : "false";
    } else {
        throw std::runtime_error("Unsupported body type");
    }
}

void HttpSession::startTimeout() {
    timer_.expires_after(std::chrono::seconds(config_.timeoutSeconds));
    timer_.async_wait(beast::bind_front_handler(&HttpSession::onTimeout, shared_from_this()));
    logger_.debug("Timeout set to " + std::to_string(config_.timeoutSeconds) + " seconds");
}

void HttpSession::cancelTimeout() {
    timer_.cancel();
}

void HttpSession::onTimeout(beast::error_code ec) {
    if (!ec) {
        logger_.error("Request timeout for URL: " + config_.url);
        finishWithError("Request timeout");
    }
}

void HttpSession::finishWithError(const std::string& error) {
    if (!finished_.exchange(true)) {
        cancelTimeout();

        result_.status = 0;
        result_.success = false;
        result_.errorMessage = error;
        result_.reason = error;

        logger_.error("Request failed: " + error);

        closeConnection();
        callback_(result_);
    }
}

void HttpSession::finishSuccess() {
    if (!finished_.exchange(true)) {
        cancelTimeout();
        logger_.info("Request completed successfully. Status: " + std::to_string(result_.status) +
                     ", Body size: " + std::to_string(result_.body.size()) + " bytes");
        closeConnection();
        callback_(result_);
    }
}

void HttpSession::onResolve(beast::error_code ec, tcp::resolver::results_type results) {
    if (ec) {
        logger_.error("DNS resolution failed for " + urlParts_.host + ": " + ec.message());
        finishWithError("Resolve failed: " + ec.message());
        return;
    }

    logger_.info("DNS resolved for " + urlParts_.host + " with " + std::to_string(results.size()) + " endpoints");

    if (isHttps_) {
        sslStream_ = std::make_unique<beast::ssl_stream<beast::tcp_stream>>(net::make_strand(ioc_), *sslCtx_);
        stream_ = &sslStream_->next_layer();
        if (!SSL_set_tlsext_host_name(sslStream_->native_handle(), urlParts_.host.c_str())) {
            ec = beast::error_code(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category());
            logger_.error("SSL SNI setup failed for " + urlParts_.host);
            finishWithError("SSL SNI failed: " + ec.message());
            return;
        }
        logger_.debug("SSL stream created for HTTPS connection");
    } else {
        tcpStream_ = std::make_unique<beast::tcp_stream>(net::make_strand(ioc_));
        stream_ = tcpStream_.get();
        logger_.debug("TCP stream created for HTTP connection");
    }

    stream_->expires_after(std::chrono::seconds(config_.connectTimeoutSeconds));
    logger_.info("Attempting connection to " + urlParts_.host + ":" + urlParts_.port);

    stream_->async_connect(results, beast::bind_front_handler(&HttpSession::onConnect, shared_from_this()));
}

void HttpSession::onConnect(beast::error_code ec, tcp::resolver::results_type::endpoint_type endpoint) {
    if (ec) {
        logger_.error("Connection failed to " + urlParts_.host + ":" + urlParts_.port + ": " + ec.message());
        finishWithError("Connect failed: " + ec.message());
        return;
    }

    auto endpointStr = endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
    logger_.info("Connected to " + endpointStr);

    if (isHttps_) {
        stream_->expires_after(std::chrono::seconds(config_.timeoutSeconds));
        logger_.debug("Starting SSL handshake");
        sslStream_->async_handshake(ssl::stream_base::client,
                                    beast::bind_front_handler(&HttpSession::onHandshake, shared_from_this()));
    } else {
        sendRequest();
    }
}

void HttpSession::onHandshake(beast::error_code ec) {
    if (ec) {
        logger_.error("SSL handshake failed: " + ec.message());
        finishWithError("SSL handshake failed: " + ec.message());
        return;
    }
    logger_.info("SSL handshake completed successfully");
    sendRequest();
}

void HttpSession::sendRequest() {
    std::string target = urlParts_.path;
    if (!urlParts_.query.empty()) {
        target += "?" + urlParts_.query;
    }

    http::verb boostVerb = methodToBoostVerb(config_.method);
    request_.method(boostVerb);
    request_.target(target);
    request_.version(11);
    request_.set(http::field::host, urlParts_.host);
    request_.set(http::field::user_agent, config_.userAgent);
    request_.set(http::field::accept, "*/*");
    request_.set(http::field::connection, "close");

    std::string bodyContent = getBodyString(config_);
    if (!bodyContent.empty() &&
        (boostVerb == http::verb::post || boostVerb == http::verb::put || boostVerb == http::verb::patch)) {
        if (!config_.contentType.empty()) {
            request_.set(http::field::content_type, config_.contentType);
        }

        request_.body() = bodyContent;
        request_.prepare_payload();

        logger_.debug("Request body prepared. Size: " + std::to_string(bodyContent.size()) + " bytes");
    }

    for (const auto& [key, value] : config_.headers) {
        request_.set(key, value);
    }

    logger_.info("Sending " + std::string(http::to_string(boostVerb)) + " request to: " + target);
    logger_.debug("Request headers count: " + std::to_string(config_.headers.size()));

    stream_->expires_after(std::chrono::seconds(config_.timeoutSeconds));
    if (isHttps_) {
        http::async_write(*sslStream_, request_, beast::bind_front_handler(&HttpSession::onWrite, shared_from_this()));
    } else {
        http::async_write(*tcpStream_, request_, beast::bind_front_handler(&HttpSession::onWrite, shared_from_this()));
    }
}

void HttpSession::onWrite(beast::error_code ec, std::size_t bytesWritten) {
    if (ec) {
        logger_.error("Request write failed: " + ec.message());
        finishWithError("Write failed: " + ec.message());
        return;
    }

    logger_.debug("Request sent. Bytes written: " + std::to_string(bytesWritten));

    stream_->expires_after(std::chrono::seconds(config_.timeoutSeconds));
    if (isHttps_) {
        http::async_read(*sslStream_, buffer_, httpResponse_,
                         beast::bind_front_handler(&HttpSession::onRead, shared_from_this()));
    } else {
        http::async_read(*tcpStream_, buffer_, httpResponse_,
                         beast::bind_front_handler(&HttpSession::onRead, shared_from_this()));
    }
}

void HttpSession::onRead(beast::error_code ec, std::size_t bytesRead) {
    if (ec == boost::asio::ssl::error::stream_truncated) {
        if (httpResponse_.result() == http::status::unknown) {
            logger_.error("SSL stream truncated: " + ec.message());
            finishWithError("SSL stream truncated: " + ec.message());
            return;
        }
    } else if (ec && ec != beast::http::error::end_of_stream) {
        logger_.error("Response read failed: " + ec.message());
        finishWithError("Read failed: " + ec.message());
        return;
    }

    logger_.debug("Response received. Bytes read: " + std::to_string(bytesRead));

    result_.status = httpResponse_.result_int();
    result_.version = std::to_string(httpResponse_.version() / 10) + "." + std::to_string(httpResponse_.version() % 10);
    result_.reason = std::string(httpResponse_.reason());
    result_.success = httpResponse_.result() == http::status::ok;

    if (httpResponse_.body().size() > 0) {
        result_.body = beast::buffers_to_string(httpResponse_.body().data());
    }

    for (const auto& field : httpResponse_) {
        result_.headers[std::string(field.name_string())] = std::string(field.value());
    }

    logger_.info("Response status: " + std::to_string(result_.status) + " " + result_.reason);
    logger_.debug("Response headers count: " + std::to_string(result_.headers.size()));

    if (config_.followRedirects && result_.status >= 300 && result_.status < 400 && config_.maxRedirects > 0) {
        auto locationIt = result_.headers.find("location");
        if (locationIt != result_.headers.end()) {
            logger_.info("Redirecting to: " + locationIt->second +
                         " (remaining redirects: " + std::to_string(config_.maxRedirects - 1) + ")");

            ExternalRequestConfig newConfig = config_;
            newConfig.maxRedirects--;

            std::string newUrl = locationIt->second;
            if (newUrl.find("://") == std::string::npos) {
                if (newUrl[0] == '/') {
                    newUrl = urlParts_.protocol + "://" + urlParts_.host + newUrl;
                } else {
                    newUrl = urlParts_.protocol + "://" + urlParts_.host + urlParts_.path +
                             (urlParts_.path.back() == '/' ? "" : "/") + newUrl;
                }
            }

            newConfig.url = newUrl;
            cancelTimeout();
            closeConnection();

            auto session = std::make_shared<HttpSession>(ioc_, std::move(sslCtx_), newConfig, callback_, logger_);
            session->run();
            return;
        }
    }

    finishSuccess();
}

void HttpSession::closeConnection() {
    beast::error_code ec;

    if (isHttps_ && sslStream_) {
        logger_.debug("Closing SSL connection");
        sslStream_->async_shutdown([self = shared_from_this()](beast::error_code shutdownEc) {
            if (shutdownEc) {
                self->logger_.warning("SSL shutdown error: " + shutdownEc.message());
            }
        });
    } else {
        if (stream_) {
            stream_->socket().shutdown(tcp::socket::shutdown_both, ec);
            if (ec && ec != net::error::not_connected) {
                logger_.warning("Socket shutdown error: " + ec.message());
            }
            logger_.debug("TCP connection closed");
        }
    }
}

}  // namespace https_client