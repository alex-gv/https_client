#include <private/ssl_context_builder.h>
#include "private/logger.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <vector>
#include <stdexcept>

namespace https_client {
class SSLCustomContextBuilder::Impl {
 public:
    std::unique_ptr<boost::asio::ssl::context> CreateContext(boost::asio::ssl::context_base::method method) {
        auto ctx = std::make_unique<boost::asio::ssl::context>(method);
        AddAndoridSystemCertificates(*ctx);
        return ctx;
    }

 private:
    void AddAndoridSystemCertificates(boost::asio::ssl::context& ctx) {
        std::vector<std::string> cert_paths = {
            "/apex/com.android.conscrypt/cacerts",  // Android 14+ (обновляемые через Google Play)
            "/system/etc/security/cacerts",         // Android 4.0-13 (основной путь)
            "/data/misc/user/0/cacerts-added",      // Android 7.0+ (пользовательские)
            "/data/misc/keychain/cacerts-added",    // До Android 7.0 (пользовательские)
            "/data/misc/keychain/cacerts",          // Некоторые устройства
            "/etc/security/cacerts"                 // Старые версии (до Android 4.0)
        };

        bool loaded = false;
        for (const auto& path : cert_paths) {
            if (!fs::exists(path)) {
                continue;
            }
            try {
                if (fs::is_directory(path)) {
                    for (const auto& entry : fs::directory_iterator(path)) {
                        if (entry.is_regular_file()) {
                            const auto& file_path = entry.path();
                            try {
                                if (!LoadDERCertificate(ctx, file_path.string())) {
                                    loaded = true;
                                }
                            } catch (const std::exception&) {
                                // do nothing
                            }
                        }
                    }
                } else if (fs::is_regular_file(path)) {
                    ctx.load_verify_file(path);
                    loaded = true;
                }
            } catch (const std::exception&) {
                // do nothing
            }
        }
        if (!loaded) {
            ctx.set_default_verify_paths();
        }
    }

    bool LoadDERCertificate(boost::asio::ssl::context& ctx, const std::string& file_path) {
        struct FileDeleter {
            void operator()(FILE* fp) const {
                if (fp)
                    fclose(fp);
            }
        };
        struct X509Deleter {
            void operator()(X509* cert) const {
                if (cert)
                    X509_free(cert);
            }
        };
        struct BIODeleter {
            void operator()(BIO* bio) const {
                if (bio)
                    BIO_free(bio);
            }
        };

        using FilePtr = std::unique_ptr<FILE, FileDeleter>;
        using X509Ptr = std::unique_ptr<X509, X509Deleter>;
        using BIOPtr = std::unique_ptr<BIO, BIODeleter>;

        FilePtr fp(fopen(file_path.c_str(), "rb"));
        if (!fp)
            return false;

        X509Ptr cert(d2i_X509_fp(fp.get(), nullptr));
        if (!cert)
            return false;

        BIOPtr bio(BIO_new(BIO_s_mem()));
        if (!bio)
            return false;

        if (PEM_write_bio_X509(bio.get(), cert.get()) != 1)
            return false;

        char subject[512] = {0};
        X509_NAME_oneline(X509_get_subject_name(cert.get()), subject, sizeof(subject) - 1);
        std::string subject_str(subject);

        if (subject_str.find("Russian") != std::string::npos) {
            try {
                std::string pem = BioToString(bio.get());
                ctx.add_certificate_authority(boost::asio::buffer(pem.data(), pem.size()));
                return true;
            } catch (const std::exception&) {
                // do nothing
            }
        }
        return false;
    }

    std::unique_ptr<boost::asio::ssl::context> SSLCustomContextBuilder::CreateContext(
        boost::asio::ssl::context_base::method method) {
        if(!impl_) {
            throw std::runtime_error("SSLCustomContextBuilder is not initialized");
        }
        return impl_->CreateContext(method);
    };

}  // namespace https_client