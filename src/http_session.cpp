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
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cctype>

#ifdef _WIN32
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <windows.h>
#include <security.h>
#elif defined(HTTPS_CLIENT_HAS_GSSAPI)
#ifdef __APPLE__
#include <GSS/GSS.h>
#else
#include <gssapi/gssapi.h>
#endif
#endif

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

namespace https_client {

namespace {

std::string base64Encode(const std::string& input) {
    static const char* base64Chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string result;
    int val = 0;
    int valb = -6;

    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(base64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        result.push_back(base64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (result.size() % 4) {
        result.push_back('=');
    }

    return result;
}

std::string base64Decode(const std::string& input) {
    static const std::string base64Chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string result;
    int val = 0;
    int valb = -8;

    for (unsigned char c : input) {
        if (std::isspace(c)) {
            continue;
        }
        if (c == '=') {
            break;
        }

        auto index = base64Chars.find(static_cast<char>(c));
        if (index == std::string::npos) {
            break;
        }

        val = (val << 6) + static_cast<int>(index);
        valb += 6;
        if (valb >= 0) {
            result.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return result;
}

std::string trim(std::string value) {
    auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

bool startsWithNoCase(const std::string& value, const std::string& prefix) {
    if (value.size() < prefix.size()) {
        return false;
    }

    return std::equal(prefix.begin(), prefix.end(), value.begin(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
    });
}

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

struct HttpSession::PlatformProxyAuthContext {
#ifdef _WIN32
    CredHandle credentials{};
    CtxtHandle context{};
    TimeStamp expiry{};
    bool hasCredentials{false};
    bool hasContext{false};
    std::string username;
    std::string domain;
    std::string password;
    SEC_WINNT_AUTH_IDENTITY_A identity{};

    ~PlatformProxyAuthContext() {
        if (hasContext) {
            DeleteSecurityContext(&context);
        }
        if (hasCredentials) {
            FreeCredentialsHandle(&credentials);
        }
    }

    void acquire(const std::string& packageName, const std::string& rawUsername, const std::string& rawPassword) {
        void* authData = nullptr;

        if (!rawUsername.empty()) {
            auto slash = rawUsername.find('\\');
            auto at = rawUsername.find('@');
            if (slash != std::string::npos) {
                domain = rawUsername.substr(0, slash);
                username = rawUsername.substr(slash + 1);
            } else if (packageName != "Kerberos" && at != std::string::npos) {
                username = rawUsername.substr(0, at);
                domain = rawUsername.substr(at + 1);
            } else {
                username = rawUsername;
            }
            password = rawPassword;

            identity.User = reinterpret_cast<unsigned char*>(username.data());
            identity.UserLength = static_cast<unsigned long>(username.size());
            identity.Domain = domain.empty() ? nullptr : reinterpret_cast<unsigned char*>(domain.data());
            identity.DomainLength = static_cast<unsigned long>(domain.size());
            identity.Password = reinterpret_cast<unsigned char*>(password.data());
            identity.PasswordLength = static_cast<unsigned long>(password.size());
            identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
            authData = &identity;
        }

        auto status = AcquireCredentialsHandleA(nullptr, const_cast<SEC_CHAR*>(packageName.c_str()), SECPKG_CRED_OUTBOUND,
                                                nullptr, authData, nullptr, nullptr, &credentials, &expiry);
        if (status != SEC_E_OK) {
            throw std::runtime_error("AcquireCredentialsHandle(" + packageName + ") failed: 0x" + statusToHex(status));
        }

        hasCredentials = true;
    }

    std::string createToken(const std::string& packageName, const std::string& proxyHost, const std::string& challenge) {
        if (!hasCredentials) {
            throw std::runtime_error(packageName + " credentials were not acquired");
        }

        SecBuffer outBuffer{};
        outBuffer.BufferType = SECBUFFER_TOKEN;

        SecBufferDesc outDesc{};
        outDesc.ulVersion = SECBUFFER_VERSION;
        outDesc.cBuffers = 1;
        outDesc.pBuffers = &outBuffer;

        SecBuffer inBuffer{};
        SecBufferDesc inDesc{};
        SecBufferDesc* inDescPtr = nullptr;
        if (!challenge.empty()) {
            inBuffer.BufferType = SECBUFFER_TOKEN;
            inBuffer.cbBuffer = static_cast<unsigned long>(challenge.size());
            inBuffer.pvBuffer = const_cast<char*>(challenge.data());
            inDesc.ulVersion = SECBUFFER_VERSION;
            inDesc.cBuffers = 1;
            inDesc.pBuffers = &inBuffer;
            inDescPtr = &inDesc;
        }

        unsigned long attrs = 0;
        const auto flags = ISC_REQ_CONNECTION | ISC_REQ_ALLOCATE_MEMORY;
        std::string target = "HTTP/" + proxyHost;
        auto status = InitializeSecurityContextA(&credentials, hasContext ? &context : nullptr, target.data(), flags, 0,
                                                 SECURITY_NATIVE_DREP, inDescPtr, 0, &context, &outDesc, &attrs, &expiry);

        if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
            throw std::runtime_error("InitializeSecurityContext(" + packageName + ") failed: 0x" + statusToHex(status));
        }

        hasContext = true;

        std::string token;
        if (outBuffer.pvBuffer && outBuffer.cbBuffer > 0) {
            token.assign(static_cast<const char*>(outBuffer.pvBuffer), outBuffer.cbBuffer);
            FreeContextBuffer(outBuffer.pvBuffer);
        }

        return token;
    }

private:
    static std::string statusToHex(unsigned long status) {
        std::ostringstream stream;
        stream << std::hex << std::uppercase << status;
        return stream.str();
    }
#else
#ifdef HTTPS_CLIENT_HAS_GSSAPI
    gss_ctx_id_t context{GSS_C_NO_CONTEXT};
    gss_name_t targetName{GSS_C_NO_NAME};

    ~PlatformProxyAuthContext() {
        OM_uint32 minor = 0;
        if (context != GSS_C_NO_CONTEXT) {
            gss_delete_sec_context(&minor, &context, GSS_C_NO_BUFFER);
        }
        if (targetName != GSS_C_NO_NAME) {
            gss_release_name(&minor, &targetName);
        }
    }

    void acquire(const std::string& packageName, const std::string& rawUsername, const std::string& rawPassword) {
        if (packageName != "Kerberos") {
            throw std::runtime_error(packageName + " proxy authentication is only supported on Windows");
        }
        if (!rawUsername.empty() || !rawPassword.empty()) {
            throw std::runtime_error(
                "Kerberos proxy authentication on GSSAPI platforms uses the current credential cache; "
                "explicit username/password is not supported");
        }
    }

    std::string createToken(const std::string& packageName, const std::string& proxyHost, const std::string& challenge) {
        if (packageName != "Kerberos") {
            throw std::runtime_error(packageName + " proxy authentication is only supported on Windows");
        }

        ensureTargetName(proxyHost);

        gss_buffer_desc inputToken{0, nullptr};
        gss_buffer_t inputTokenPtr = GSS_C_NO_BUFFER;
        if (!challenge.empty()) {
            inputToken.length = challenge.size();
            inputToken.value = const_cast<char*>(challenge.data());
            inputTokenPtr = &inputToken;
        }

        gss_buffer_desc outputToken{0, nullptr};
        OM_uint32 minor = 0;
        OM_uint32 flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;
        OM_uint32 actualFlags = 0;
        OM_uint32 status = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &context, targetName, GSS_C_NO_OID, flags, 0,
                                                GSS_C_NO_CHANNEL_BINDINGS, inputTokenPtr, nullptr, &outputToken,
                                                &actualFlags, nullptr);

        if (status != GSS_S_COMPLETE && status != GSS_S_CONTINUE_NEEDED) {
            throw std::runtime_error("gss_init_sec_context(Kerberos) failed: " + gssErrorToString(status, minor));
        }

        std::string token;
        if (outputToken.value && outputToken.length > 0) {
            token.assign(static_cast<const char*>(outputToken.value), outputToken.length);
            gss_release_buffer(&minor, &outputToken);
        }

        return token;
    }

private:
    void ensureTargetName(const std::string& proxyHost) {
        if (targetName != GSS_C_NO_NAME) {
            return;
        }

        std::string serviceName = "HTTP@" + proxyHost;
        gss_buffer_desc nameBuffer{};
        nameBuffer.value = serviceName.data();
        nameBuffer.length = serviceName.size();

        OM_uint32 minor = 0;
        OM_uint32 status = gss_import_name(&minor, &nameBuffer, GSS_C_NT_HOSTBASED_SERVICE, &targetName);
        if (status != GSS_S_COMPLETE) {
            throw std::runtime_error("gss_import_name(HTTP service) failed: " + gssErrorToString(status, minor));
        }
    }

    static std::string displayStatus(OM_uint32 code, int type) {
        std::string result;
        OM_uint32 minor = 0;
        OM_uint32 context = 0;

        do {
            gss_buffer_desc message{0, nullptr};
            OM_uint32 status = gss_display_status(&minor, code, type, GSS_C_NO_OID, &context, &message);
            if (status != GSS_S_COMPLETE) {
                break;
            }

            if (!result.empty()) {
                result += "; ";
            }
            result.append(static_cast<const char*>(message.value), message.length);
            gss_release_buffer(&minor, &message);
        } while (context != 0);

        return result;
    }

    static std::string gssErrorToString(OM_uint32 major, OM_uint32 minor) {
        std::string result = displayStatus(major, GSS_C_GSS_CODE);
        std::string minorMessage = displayStatus(minor, GSS_C_MECH_CODE);
        if (!minorMessage.empty()) {
            if (!result.empty()) {
                result += " / ";
            }
            result += minorMessage;
        }
        return result.empty() ? "unknown GSSAPI error" : result;
    }
#else
    void acquire(const std::string& packageName, const std::string&, const std::string&) {
        throw std::runtime_error(packageName + " proxy authentication is not available on this platform");
    }

    std::string createToken(const std::string& packageName, const std::string&, const std::string&) {
        throw std::runtime_error(packageName + " proxy authentication is not available on this platform");
    }
#endif
#endif
};

static http::verb methodToBoostVerb(Method method) {
    switch (method) {
        case Method::GET:
            return http::verb::get;
        case Method::POST:
            return http::verb::post;
        case Method::PUT:
            return http::verb::put;
        case Method::DELETE_:
            return http::verb::delete_;
        case Method::PATCH:
            return http::verb::patch;
        case Method::HEAD:
            return http::verb::head;
        case Method::OPTIONS:
            return http::verb::options;
        default:
            return http::verb::get;
    }
}

HttpSession::HttpSession(net::io_context& ioc, std::shared_ptr<ssl::context> sslCtx,
                         const ExternalRequestConfig& config, ResponseCallback callback, Logger& logger)
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

HttpSession::~HttpSession() = default;

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

    if (config_.proxy.isEnabled()) {
        logger_.info("Using proxy: " + config_.proxy.host + ":" + config_.proxy.port);
        resolver_.async_resolve(config_.proxy.host, config_.proxy.port,
                                beast::bind_front_handler(&HttpSession::onProxyResolve, shared_from_this(), results));
        return;
    }

    onResolveTarget(results);
}

void HttpSession::onProxyResolve(tcp::resolver::results_type targetResults, beast::error_code ec,
                                 tcp::resolver::results_type proxyResults) {
    if (ec) {
        logger_.error("Proxy DNS resolution failed for " + config_.proxy.host + ": " + ec.message());
        finishWithError("Proxy resolve failed: " + ec.message());
        return;
    }
    logger_.info("Proxy DNS resolved for " + config_.proxy.host);

    proxyTargetResults_ = targetResults;
    tcpStream_ = std::make_unique<beast::tcp_stream>(net::make_strand(ioc_));
    stream_ = tcpStream_.get();
    stream_->expires_after(std::chrono::seconds(config_.connectTimeoutSeconds));
    logger_.info("Connecting to proxy " + config_.proxy.host + ":" + config_.proxy.port);
    stream_->async_connect(proxyResults, beast::bind_front_handler(&HttpSession::onProxyConnect, shared_from_this()));
}

void HttpSession::onProxyConnect(beast::error_code ec, tcp::resolver::results_type::endpoint_type endpoint) {
    if (ec) {
        logger_.error("Proxy connection failed to " + config_.proxy.host + ":" + config_.proxy.port + ": " +
                      ec.message());
        finishWithError("Proxy connect failed: " + ec.message());
        return;
    }
    logger_.info("Connected to proxy: " + endpoint.address().to_string() + ":" + std::to_string(endpoint.port()));

    if (config_.proxy.useHttps) {
        logger_.info("Starting SSL handshake with HTTPS proxy");
        proxySslCtx_ = std::make_unique<ssl::context>(ssl::context::tls_client);
        proxySslCtx_->set_default_verify_paths();
        proxySslCtx_->set_verify_mode(ssl::verify_none);

        proxySslStream_ =
            std::make_unique<beast::ssl_stream<beast::tcp_stream>>(std::move(*tcpStream_), *proxySslCtx_);
        stream_ = &proxySslStream_->next_layer();

        proxySslStream_->async_handshake(ssl::stream_base::client,
                                         beast::bind_front_handler(&HttpSession::onProxyHandshake, shared_from_this()));
    } else {
        sendProxyConnectRequest();
    }
}

void HttpSession::onProxyHandshake(beast::error_code ec) {
    if (ec) {
        logger_.error("SSL handshake with proxy failed: " + ec.message());
        finishWithError("Proxy SSL handshake failed: " + ec.message());
        return;
    }

    logger_.info("SSL handshake with proxy completed successfully");

    sendProxyConnectRequest();
}

void HttpSession::onResolveTarget(tcp::resolver::results_type results) {
    if (isHttps_) {
        sslStream_ = std::make_unique<beast::ssl_stream<beast::tcp_stream>>(net::make_strand(ioc_), *sslCtx_);
        stream_ = &sslStream_->next_layer();
        if (!SSL_set_tlsext_host_name(sslStream_->native_handle(), urlParts_.host.c_str())) {
            beast::error_code ec =
                beast::error_code(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category());
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

void HttpSession::sendProxyConnectRequest() {
    proxyConnectRequest_ = {};
    proxyConnectRequest_.version(11);
    proxyConnectRequest_.method(http::verb::connect);

    std::string target = urlParts_.host + ":" + urlParts_.port;
    proxyConnectRequest_.target(target);

    proxyConnectRequest_.set(http::field::host, target);
    proxyConnectRequest_.set(http::field::user_agent, config_.userAgent);
    proxyConnectRequest_.set(http::field::proxy_connection, isProxyPlatformAuth() ? "keep-alive" : "close");

    if (isProxyPlatformAuth()) {
        try {
            std::string authHeader = buildProxyPlatformAuthHeader();
            proxyConnectRequest_.set(http::field::proxy_authorization, authHeader);
            logger_.debug("Proxy platform authentication header added");
        } catch (const std::exception& e) {
            finishWithError(e.what());
            return;
        }
    } else if (!config_.proxy.username.empty() && !config_.proxy.password.empty()) {
        std::string authHeader = buildProxyAuthorizationHeader(config_.proxy.username, config_.proxy.password);
        proxyConnectRequest_.set(http::field::proxy_authorization, authHeader);
        logger_.debug("Basic Proxy-Authorization header added");
    }

    logger_.info("Sending CONNECT request to proxy for " + target);
    stream_->expires_after(std::chrono::seconds(config_.timeoutSeconds));

    if (config_.proxy.useHttps && proxySslStream_) {
        http::async_write(*proxySslStream_, proxyConnectRequest_,
                          beast::bind_front_handler(&HttpSession::onProxyConnectWrite, shared_from_this()));
    } else {
        http::async_write(*stream_, proxyConnectRequest_,
                          beast::bind_front_handler(&HttpSession::onProxyConnectWrite, shared_from_this()));
    }
}

void HttpSession::onProxyConnectWrite(beast::error_code ec, std::size_t /*bytesWritten*/) {
    if (ec) {
        logger_.error("Proxy CONNECT write failed: " + ec.message());
        finishWithError("Proxy CONNECT write failed: " + ec.message());
        return;
    }

    logger_.debug("CONNECT request sent to proxy");
    stream_->expires_after(std::chrono::seconds(config_.timeoutSeconds));

    if (config_.proxy.useHttps && proxySslStream_) {
        http::async_read(*proxySslStream_, buffer_, proxyConnectResponse_,
                         beast::bind_front_handler(&HttpSession::onProxyConnectRead, shared_from_this()));
    } else {
        http::async_read(*stream_, buffer_, proxyConnectResponse_,
                         beast::bind_front_handler(&HttpSession::onProxyConnectRead, shared_from_this()));
    }
}

void HttpSession::onProxyConnectRead(beast::error_code ec, std::size_t /*bytesRead*/) {
    if (ec) {
        logger_.error("Proxy CONNECT read failed: " + ec.message());
        finishWithError("Proxy CONNECT read failed: " + ec.message());
        return;
    }

    auto status = proxyConnectResponse_.result_int();
    logger_.info("Proxy CONNECT response status: " + std::to_string(status));

    if (status == 407 && isProxyPlatformAuth() && proxyAuthStep_ > 0 && proxyAuthStep_ < 3) {
        const std::string scheme = config_.proxy.authType == ProxyAuthType::Kerberos ? "Negotiate" : "NTLM";
        proxyAuthChallenge_ = extractProxyAuthChallenge(scheme);
        if (proxyAuthChallenge_.empty()) {
            finishWithError("Proxy requested Windows authentication but did not send a challenge token");
            return;
        }

        logger_.debug("Proxy authentication challenge received, sending authentication response");
        proxyConnectResponse_ = {};
        sendProxyConnectRequest();
        return;
    }

    if (status != 200) {
        std::string reason = std::string(proxyConnectResponse_.reason());
        logger_.error("Proxy CONNECT failed with status " + std::to_string(status) + ": " + reason);
        finishWithError("Proxy CONNECT failed: " + std::to_string(status) + " " + reason);
        return;
    }

    logger_.info("Proxy tunnel established successfully");

    if (isHttps_) {
        if (proxySslStream_) {
            auto* sslPtr = proxySslStream_->native_handle();
            SSL_set_tlsext_host_name(sslPtr, urlParts_.host.c_str());
            stream_ = &proxySslStream_->next_layer();
            sslStream_ = std::move(proxySslStream_);
        } else {
            sslStream_ = std::make_unique<beast::ssl_stream<beast::tcp_stream>>(std::move(*tcpStream_), *sslCtx_);
            stream_ = &sslStream_->next_layer();
            if (!SSL_set_tlsext_host_name(sslStream_->native_handle(), urlParts_.host.c_str())) {
                beast::error_code sslEc =
                    beast::error_code(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category());
                finishWithError("SSL SNI failed: " + sslEc.message());
                return;
            }
        }
        stream_->expires_after(std::chrono::seconds(config_.timeoutSeconds));
        logger_.debug("Starting SSL handshake with target server through proxy tunnel");
        sslStream_->async_handshake(ssl::stream_base::client,
                                    beast::bind_front_handler(&HttpSession::onHandshake, shared_from_this()));
    } else {
        logger_.debug("HTTP through proxy, sending request");
        sendRequest();
    }
}

std::string HttpSession::buildProxyAuthorizationHeader(const std::string& username, const std::string& password) {
    std::string credentials = username + ":" + password;
    return "Basic " + base64Encode(credentials);
}

bool HttpSession::isProxyPlatformAuth() const {
    return config_.proxy.authType == ProxyAuthType::NTLM || config_.proxy.authType == ProxyAuthType::Kerberos;
}

std::string HttpSession::buildProxyPlatformAuthHeader() {
    const bool useKerberos = config_.proxy.authType == ProxyAuthType::Kerberos;
    const std::string packageName = useKerberos ? "Kerberos" : "NTLM";
    const std::string headerScheme = useKerberos ? "Negotiate" : "NTLM";

    if (!platformProxyAuth_) {
        platformProxyAuth_ = std::make_unique<PlatformProxyAuthContext>();
        platformProxyAuth_->acquire(packageName, config_.proxy.username, config_.proxy.password);
    }

    std::string challenge;
    if (proxyAuthStep_ > 0 && !proxyAuthChallenge_.empty()) {
        challenge = base64Decode(proxyAuthChallenge_);
    }

    auto token = platformProxyAuth_->createToken(packageName, config_.proxy.host, challenge);
    if (token.empty()) {
        throw std::runtime_error(packageName + " proxy authentication produced an empty token");
    }

    ++proxyAuthStep_;
    return headerScheme + " " + base64Encode(token);
}

std::string HttpSession::extractProxyAuthChallenge(const std::string& scheme) const {
    for (const auto& field : proxyConnectResponse_) {
        if (field.name() != http::field::proxy_authenticate) {
            continue;
        }

        std::string value = trim(std::string(field.value()));
        if (!startsWithNoCase(value, scheme)) {
            continue;
        }

        value = trim(value.substr(scheme.size()));
        if (!value.empty()) {
            return value;
        }
    }

    return "";
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
    } else if (proxySslStream_) {
        http::async_write(*proxySslStream_, request_,
                          beast::bind_front_handler(&HttpSession::onWrite, shared_from_this()));
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
    } else if (proxySslStream_) {
        http::async_read(*proxySslStream_, buffer_, httpResponse_,
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

            auto session = std::make_shared<HttpSession>(ioc_, sslCtx_, newConfig, callback_, logger_);
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
    } else if (proxySslStream_) {
        logger_.debug("Closing proxy SSL connection");
        proxySslStream_->async_shutdown([self = shared_from_this()](beast::error_code shutdownEc) {
            if (shutdownEc) {
                self->logger_.warning("Proxy SSL shutdown error: " + shutdownEc.message());
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
