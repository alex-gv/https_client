#pragma once

#include <boost/asio/ssl.hpp>
#include <memory>

namespace https_client {
class SSLCustomContextBuilder {
 public:
    std::unique_ptr<boost::asio::ssl::context> CreateContext(boost::asio::ssl::context_base::method method);

 private:
    class Impl;
    Impl* impl_;
};

}  // namespace https_client
