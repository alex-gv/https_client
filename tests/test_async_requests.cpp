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

    std::promise<Response> promise;
    auto future = promise.get_future();

    client.getAsync(cfg, [&](Response r) {
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

    auto future = client.getAsync(cfg);
    Response res = future.get();

    EXPECT_EQ(res.status, 200);
}
