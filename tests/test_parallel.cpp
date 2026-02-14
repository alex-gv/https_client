#include <gtest/gtest.h>
#include <future>
#include "public/https_client.h"
#include "mock_server.h"

using namespace https_client;

TEST(HttpsClientParallel, ExecuteMultiple) {
    MockServer server;
    HttpsClient client(4);

std::vector<ExternalRequestConfig> requests = {
    ExternalRequestConfig("http://localhost:8081/ok", Method::GET),
    ExternalRequestConfig("http://localhost:8081/ok", Method::GET),
    ExternalRequestConfig("http://localhost:8081/ok", Method::GET)
};


    std::promise<std::vector<Response>> promise;
    auto future = promise.get_future();

    client.executeParallel(requests, [&](const std::vector<Response>& responses) {
        promise.set_value(responses);
    });

    auto responses = future.get();
    EXPECT_EQ(responses.size(), 3);
    for (auto& r : responses) {
        EXPECT_EQ(r.status, 200);
    }
}
