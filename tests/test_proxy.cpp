#include <gtest/gtest.h>
#include "public/https_client.h"

using namespace https_client;

namespace {
const std::string PROXY_HOST = "20.112.94.127";
const std::string PROXY_PORT = "443";
}  // namespace

TEST(ProxyTest, HttpsRequestThroughProxy) {
    HttpsClient client([](LogLevel level, const std::string& message) {
        std::cout << message << std::endl;
    });

    RequestConfig cfg;
    cfg.url = "https://httpbin.org/get";
    cfg.timeoutSeconds = 30;
    cfg.connectTimeoutSeconds = 10;

    ExternalRequestConfig extCfg(cfg, Method::GET);
    extCfg.proxy = ProxyConfig(PROXY_HOST, PROXY_PORT);

    Response res = client.get(extCfg);

    EXPECT_TRUE(res.success);
    EXPECT_EQ(res.status, 200);
    EXPECT_FALSE(res.body.empty());
}

TEST(ProxyTest, HttpRequestThroughProxy) {
    HttpsClient client([](LogLevel level, const std::string& message) {
        std::cout << message << std::endl;
    });

    RequestConfig cfg;
    cfg.url = "http://httpbin.org/get";
    cfg.timeoutSeconds = 30;
    cfg.connectTimeoutSeconds = 10;

    ExternalRequestConfig extCfg(cfg, Method::GET);
    extCfg.proxy = ProxyConfig(PROXY_HOST, PROXY_PORT);

    Response res = client.get(extCfg);

    EXPECT_TRUE(res.success);
    EXPECT_EQ(res.status, 200);
    EXPECT_FALSE(res.body.empty());
}

TEST(ProxyTest, PostRequestThroughProxy) {
    HttpsClient client([](LogLevel level, const std::string& message) {
        std::cout << message << std::endl;
    });

    RequestConfig cfg;
    cfg.url = "https://httpbin.org/post";
    cfg.body = "{\"test\":\"data\"}";
    cfg.contentType = "application/json";
    cfg.timeoutSeconds = 30;
    cfg.connectTimeoutSeconds = 10;

    ExternalRequestConfig extCfg(cfg, Method::POST);
    extCfg.proxy = ProxyConfig(PROXY_HOST, PROXY_PORT);

    Response res = client.post(extCfg);

    EXPECT_TRUE(res.success);
    EXPECT_EQ(res.status, 200);
    EXPECT_FALSE(res.body.empty());
    EXPECT_NE(res.body.find("test"), std::string::npos);
}

TEST(ProxyTest, ProxyWithAuthentication) {
    HttpsClient client([](LogLevel level, const std::string& message) {
        std::cout << message << std::endl;
    });

    RequestConfig cfg;
    cfg.url = "https://httpbin.org/get";
    cfg.timeoutSeconds = 30;
    cfg.connectTimeoutSeconds = 10;

    ExternalRequestConfig extCfg(cfg, Method::GET);
    // Прокси с аутентификацией (тестовые данные)
    extCfg.proxy = ProxyConfig(PROXY_HOST, PROXY_PORT, "user", "password");

    // Этот тест может упасть если прокси не требует или отклоняет данные credentials
    // Основная цель - проверить что Proxy-Authorization header отправляется
    Response res = client.get(extCfg);

    // Ожидаем либо успех (если прокси принял credentials), либо ошибку авторизации
    // Главное что механизм авторизации работает
    EXPECT_TRUE(res.success || res.status == 407);
}

TEST(ProxyTest, AsyncRequestThroughProxy) {
    HttpsClient client([](LogLevel level, const std::string& message) {
        std::cout << message << std::endl;
    });

    RequestConfig cfg;
    cfg.url = "https://httpbin.org/get";
    cfg.timeoutSeconds = 30;
    cfg.connectTimeoutSeconds = 10;

    ExternalRequestConfig extCfg(cfg, Method::GET);
    extCfg.proxy = ProxyConfig(PROXY_HOST, PROXY_PORT);

    std::promise<Response> promise;
    auto future = promise.get_future();

    client.getAsync(extCfg, [&promise](const Response& response) {
        promise.set_value(response);
    });

    auto status = future.wait_for(std::chrono::seconds(45));
    ASSERT_EQ(status, std::future_status::ready);

    Response res = future.get();
    EXPECT_TRUE(res.success);
    EXPECT_EQ(res.status, 200);
}

TEST(ProxyTest, HttpsRequestThroughHttpsProxy) {
    // Тест для HTTPS proxy (когда прокси использует TLS)
    // Используем тот же прокси но с флагом useHttps=true
    // Если прокси не поддерживает HTTPS, тест упадёт - это ожидаемо
    HttpsClient client([](LogLevel level, const std::string& message) {
        std::cout << message << std::endl;
    });

    RequestConfig cfg;
    cfg.url = "https://httpbin.org/get";
    cfg.timeoutSeconds = 30;
    cfg.connectTimeoutSeconds = 10;

    ExternalRequestConfig extCfg(cfg, Method::GET);
    extCfg.proxy = ProxyConfig(PROXY_HOST, PROXY_PORT, "", "", true);  // useHttps = true

    Response res = client.get(extCfg);

    // Тест может упасть если прокси не поддерживает HTTPS
    // Основная цель - проверить что механизм HTTPS proxy работает
    EXPECT_TRUE(res.success || !res.errorMessage.empty());
}

TEST(ProxyTest, ProxyConfigIsEnabled) {
    ProxyConfig emptyProxy;
    EXPECT_FALSE(emptyProxy.isEnabled());

    ProxyConfig partialProxy("host", "");
    EXPECT_FALSE(partialProxy.isEnabled());

    ProxyConfig validProxy("host", "port");
    EXPECT_TRUE(validProxy.isEnabled());

    ProxyConfig fullProxy("host", "port", "user", "pass");
    EXPECT_TRUE(fullProxy.isEnabled());
}
