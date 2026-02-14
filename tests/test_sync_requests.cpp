#include <gtest/gtest.h>
#include "public/https_client.h"
#include "mock_server.h"

using namespace https_client;

TEST(HttpsClientSync, GetSuccess) {
    MockServer server;

    HttpsClient client;
    RequestConfig cfg;
    cfg.url = "http://localhost:8081/ok";

    Response res = client.get(cfg);

    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(res.body, "OK");
}

TEST(HttpsClientSync, PostEcho) {
    MockServer server;

    HttpsClient client;
    RequestConfig cfg;
    cfg.url = "http://localhost:8081/echo";
    cfg.body = "hello";

    Response res = client.post(cfg);

    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(res.body, "hello");
}
