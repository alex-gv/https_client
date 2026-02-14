#pragma once
#include <httplib.h>
#include <thread>

class MockServer {
public:
    MockServer() {
        server_.Get("/ok", [](auto&, auto& res) {
            res.status = 200;
            res.set_content("OK", "text/plain");
        });

        server_.Post("/echo", [](const auto& req, auto& res) {
            res.status = 200;
            res.set_content(req.body, "text/plain");
        });

        thread_ = std::thread([this]() {
            server_.listen("localhost", 8081);
        });
    }

    ~MockServer() {
        server_.stop();
        thread_.join();
    }

private:
    httplib::Server server_;
    std::thread thread_;
};
