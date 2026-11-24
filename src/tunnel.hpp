#pragma once
#include "protocol.hpp"
#include <asio.hpp>
#include <memory>
#include <string>

namespace ft {
struct Config
{
    bool server;
    std::string address;
    Key key;
};
class Runtime
{
public:
    Runtime(asio::io_context &, Config);
    ~Runtime();
    void start();
    void stop();
    bool failed() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace ft
