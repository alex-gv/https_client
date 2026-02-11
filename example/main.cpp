#include <public/https_client.h>
#include <iostream>

int main() {
    using namespace https_client;
    HttpsClient client(2); // 2 рабочих потока
    {
        RequestConfig cfg;
        cfg.url = "https://httpbin.org/get";
        cfg.headers["Accept"] = "application/json";

        auto resp = client.get(cfg);

        std::cout << "\n[SYNC GET]\n";
        std::cout << "Status: " << resp.status << "\n";
        std::cout << "Body:\n" << resp.body << "\n";
    }

    // ====== СИНХРОННЫЙ POST ======
    {
        RequestConfig cfg;
        cfg.url = "https://httpbin.org/post";
        cfg.body = std::string("{\"hello\":\"world\"}");
        cfg.contentType = "application/json";

        auto resp = client.post(cfg);

        std::cout << "\n[SYNC POST]\n";
        std::cout << "Status: " << resp.status << "\n";
        std::cout << "Body:\n" << resp.body << "\n";
    }

    // ====== ASYNC + CALLBACK ======
    {
        RequestConfig cfg;
        cfg.url = "https://httpbin.org/get";

        client.getAsync(cfg, [](const Response& resp) {
            std::cout << "\n[ASYNC CALLBACK]\n";
            std::cout << "Status: " << resp.status << "\n";
            std::cout << "Body size: " << resp.body.size() << "\n";
            std::cout << "Body:\n" << resp.body << "\n";
        });
    }

    // ====== ASYNC + FUTURE ======
    {
        RequestConfig cfg;
        cfg.url = "https://httpbin.org/get";

        auto future = client.getAsync(cfg);
        auto resp = future.get();

        std::cout << "\n[ASYNC FUTURE]\n";
        std::cout << "Status: " << resp.status << "\n";
        std::cout << "Body:\n" << resp.body << "\n";
    }

    // ====== ПАРАЛЛЕЛЬНЫЕ ЗАПРОСЫ ======
    {
        std::vector<ExternalRequestConfig> requests;
        for (int i = 0; i < 5; ++i) {
            requests.emplace_back("https://httpbin.org/get", Method::GET);
        }

        std::mutex m;
        std::condition_variable cv;
        bool done = false;

        client.executeParallel(
            requests,
            [&](const std::vector<Response>& responses) {
                std::cout << "\n[PARALLEL]\n";
                for (size_t i = 0; i < responses.size(); ++i) {
                    std::cout << "Request " << i
                              << " status=" << responses[i].status << "\n";
                    std::cout << "Body:\n" << responses[i].body << "\n";
                }
                done = true;
                cv.notify_one();
            });

        std::unique_lock<std::mutex> lock(m);
        cv.wait(lock, [&]() { return done; });
    }

    std::cout << "\nDone.\n";
    return 0;
}
