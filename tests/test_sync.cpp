#include <gtest/gtest.h>
#include "public/https_client.h"

TEST(HttpsClient, SyncGet) {
    using namespace https_client;
    HttpsClient client(2);
    RequestConfig cfg("https://httpbin.org/get");
    auto resp = client.get(cfg);

    EXPECT_TRUE(resp.success);
    EXPECT_EQ(resp.status, 200);
    EXPECT_FALSE(resp.body.empty());
}


