#include <private/ssl_context_builder.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <vector>

namespace https_client {
class SSLCustomContextBuilder::Impl {
 public:
    std::unique_ptr<boost::asio::ssl::context> CreateContext(boost::asio::ssl::context_base::method method) {
        return std::make_unique<boost::asio::ssl::context>(method);
    }
};

std::unique_ptr<boost::asio::ssl::context> SSLCustomContextBuilder::CreateContext(
    boost::asio::ssl::context_base::method method) {
    return impl_->CreateContext(method);
};

}  // namespace https_client