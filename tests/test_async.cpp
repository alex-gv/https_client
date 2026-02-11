#include <gtest/gtest.h>
#include "public/https_client.h"

TEST(HttpsClient, AsyncFuture) {
    using namespace https_client;
    HttpsClient client(2);
    RequestConfig cfg("https://httpbin.org/get");

    auto f = client.getAsync(cfg);
    auto resp = f.get();

    EXPECT_TRUE(resp.isOk());
}
