#include <gtest/gtest.h>
#include <future>
#include "public/https_client.h"
#include "mock_server.h"

using namespace https_client;
TEST(HttpsClientErrors, InvalidUrl) {
    HttpsClient client;

    RequestConfig cfg;
    cfg.url = "http://invalid-host";

    ExternalRequestConfig extCfg(cfg, Method::GET);
    Response res = client.get(extCfg);

    EXPECT_NE(res.status, 200);
    EXPECT_FALSE(res.errorMessage.empty());
}

TEST(HttpsClientLogging, CallbackCalled) {
    HttpsClient client;

    bool called = false;
    client.setLogCallback([&](LogLevel level, const std::string& message) {
        called = true;
    });

    RequestConfig cfg;
    cfg.url = "http://invalid-host";
    ExternalRequestConfig extCfg(cfg, Method::GET);
    client.get(extCfg);

    EXPECT_TRUE(called);
}
