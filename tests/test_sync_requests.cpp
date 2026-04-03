#include <gtest/gtest.h>
#include "public/https_client.h"
#include "mock_server.h"

using namespace https_client;

TEST(HttpsClientSync, GetSuccess) {
    MockServer server;

    HttpsClient client;
    RequestConfig cfg;
    cfg.url = "http://localhost:8081/ok";

    ExternalRequestConfig extCfg(cfg, Method::GET);
    Response res = client.get(extCfg);

    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(res.body, "OK");
}

TEST(HttpsClientSync, PostEcho) {
    MockServer server;

    HttpsClient client;
    RequestConfig cfg;
    cfg.url = "http://localhost:8081/echo";
    cfg.body = "hello";

    ExternalRequestConfig extCfg(cfg, Method::POST);
    Response res = client.post(extCfg);

    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(res.body, "hello");
}
