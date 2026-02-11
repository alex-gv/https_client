#pragma once

#include "private/logger.h"
#include "public/common_types.h"

#include <memory>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>

namespace https_client {

class HttpSession : public std::enable_shared_from_this<HttpSession> {
public:
    HttpSession(boost::asio::io_context& ioc,
                std::unique_ptr<boost::asio::ssl::context> sslCtx,
                const ExternalRequestConfig& config,
                ResponseCallback callback,
                Logger& logger);

    void run();

private:
    struct UrlParts {
        std::string protocol;
        std::string host;
        std::string port;
        std::string path;
        std::string query;
    };

    void startTimeout();
    void cancelTimeout();
    void onTimeout(boost::beast::error_code ec);

    void finishWithError(const std::string& error);
    void finishSuccess();

    void onResolve(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type results);
    void onConnect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type endpoint);
    void onHandshake(boost::beast::error_code ec);
    void sendRequest();
    void onWrite(boost::beast::error_code ec, std::size_t bytesWritten);
    void onRead(boost::beast::error_code ec, std::size_t bytesRead);
    void closeConnection();

    UrlParts parseUrl(const std::string& url);
    std::string getBodyString(const ExternalRequestConfig& config);

private:
    boost::asio::io_context& ioc_;
    std::unique_ptr<boost::asio::ssl::context> sslCtx_;
    ExternalRequestConfig config_;
    ResponseCallback callback_;
    Logger& logger_;
    Response result_;

    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::steady_timer timer_;

    std::unique_ptr<boost::beast::tcp_stream> tcpStream_;
    std::unique_ptr<boost::beast::ssl_stream<boost::beast::tcp_stream>> sslStream_;
    boost::beast::tcp_stream* stream_{nullptr};

    bool isHttps_{false};
    UrlParts urlParts_;

    boost::beast::http::request<boost::beast::http::string_body> request_;
    boost::beast::http::response<boost::beast::http::dynamic_body> httpResponse_;
    boost::beast::flat_buffer buffer_;

    std::atomic<bool> finished_{false};
};

} // namespace https_client
