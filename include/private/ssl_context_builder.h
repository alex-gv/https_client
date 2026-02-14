/*
 *  ssl_context_builder.h
 *
 *  Copyright (c) 2026 <Aleksei Gurov>
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

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
