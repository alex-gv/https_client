#include <private/ssl_context_builder.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <vector>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#ifdef ___OSX___
#include <Security/SecTrustSettings.h>
#endif

namespace https_client {
class SSLCustomContextBuilder::Impl {
 public:
    std::unique_ptr<boost::asio::ssl::context> CreateContext(boost::asio::ssl::context_base::method method) {
        auto ctx = std::make_unique<boost::asio::ssl::context>(method);
        AddMacosSystemCertificates(*ctx);
        return ctx;
    }

 private:
    void AddMacosSystemCertificates(boost::asio::ssl::context& ctx) {
        SSL_CTX* ssl_ctx = ctx.native_handle();
        X509_STORE* store = SSL_CTX_get_cert_store(ssl_ctx);
        if (!store) {
            throw std::runtime_error("Cannot get X509 store from SSL context");
        }
#ifdef___OSX___
        AddCertificatesFromKeychain(store, kSecTrustSettingsDomainUser);
        AddCertificatesFromKeychain(store, kSecTrustSettingsDomainAdmin);
        AddCertificatesFromKeychain(store, kSecTrustSettingsDomainSystem);
#else
        AddCertificatesFromKeychain(store);
#endif
        boost::system::error_code ec;
        ctx.set_default_verify_paths(ec);
    }

    void AddCertificatesFromKeychain(X509_STORE* store) {
        CFArrayRef certs = nullptr;
        OSStatus status = SecTrustCopyAnchorCertificates(&certs);
        if (status != errSecSuccess || !certs) {
            return;
        }
        CFIndex count = CFArrayGetCount(certs);
        for (CFIndex i = 0; i < count; i++) {
            SecCertificateRef sec_cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);

            CFDataRef cert_data = SecCertificateCopyData(sec_cert);
            if (!cert_data)
                continue;

            const UInt8* data = CFDataGetBytePtr(cert_data);
            CFIndex length = CFDataGetLength(cert_data);

            const unsigned char* p = data;
            X509* x509 = d2i_X509(nullptr, &p, length);

            if (x509) {
                X509_STORE_add_cert(store, x509);
                X509_free(x509);
            }
            CFRelease(cert_data);
        }
        CFRelease(certs);
    }

    void AddCertificatesFromKeychain(X509_STORE* store, SecTrustSettingsDomain domain) {
        CFArrayRef certs = nullptr;
        OSStatus status = SecTrustSettingsCopyCertificates(domain, &certs);
        if (status != errSecSuccess || !certs) {
            return;
        }
        CFIndex count = CFArrayGetCount(certs);
        for (CFIndex i = 0; i < count; i++) {
            SecCertificateRef sec_cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);

            CFDataRef cert_data = SecCertificateCopyData(sec_cert);
            if (!cert_data)
                continue;

            const UInt8* data = CFDataGetBytePtr(cert_data);
            CFIndex length = CFDataGetLength(cert_data);

            const unsigned char* p = data;
            X509* x509 = d2i_X509(nullptr, &p, length);

            if (x509) {
                X509_STORE_add_cert(store, x509);
                X509_free(x509);
            }
            CFRelease(cert_data);
        }
        CFRelease(certs);
    }
};

std::unique_ptr<boost::asio::ssl::context> SSLCustomContextBuilder::CreateContext(
    boost::asio::ssl::context_base::method method) {
    return impl_->CreateContext(method);
};

}  // namespace https_client