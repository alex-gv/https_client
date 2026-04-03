#include <gtest/gtest.h>
#include <future>
#include "public/https_client.h"
#include "mock_server.h"

using namespace https_client;

TEST(HttpsClientAsync, GetCallback) {
    MockServer server;
    HttpsClient client;

    RequestConfig cfg;
    cfg.url = "http://localhost:8081/ok";

    ExternalRequestConfig extCfg(cfg, Method::GET);

    std::promise<Response> promise;
    auto future = promise.get_future();

    client.getAsync(extCfg, [&](Response r) {
        promise.set_value(r);
    });

    Response res = future.get();
    EXPECT_EQ(res.status, 200);
}


TEST(HttpsClientAsync, GetFuture) {
    MockServer server;
    HttpsClient client;

    RequestConfig cfg;
    cfg.url = "http://localhost:8081/ok";

    ExternalRequestConfig extCfg(cfg, Method::GET);

    auto future = client.getAsync(extCfg);
    Response res = future.get();

    EXPECT_EQ(res.status, 200);
}
