#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace ft {

using Bytes = std::vector<std::uint8_t>;
using Key = std::array<std::uint8_t, 32>;
enum Mode : std::uint8_t
{
    Stream = 1,
    Datagram = 2
};
inline constexpr std::size_t HelloSize = 72;
inline constexpr std::size_t ResponseSize = 64;
inline constexpr std::size_t RecordOverhead = 24;
inline constexpr std::string_view RequestPrefix =
    "GET / HTTP/1.1\r\nHost: speedtest.fkcucc.com\r\nContent-Length: 72\r\nConnection: keep-alive\r\n\r\n";
inline constexpr std::string_view ResponsePrefix =
    "HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: keep-alive\r\n\r\n";

// Only authenticated duplicate or stale records produce this error.
class ReplayError : public std::runtime_error
{
public:
    ReplayError() : std::runtime_error("record replayed or outside replay window") {}
};

struct HelloInfo
{
    Mode mode;
    std::uint16_t port;
};

class Session;
struct Accepted
{
    Bytes response;
    std::shared_ptr<Session> session;
};

Bytes
new_client_hello(const Key &key, Mode mode, std::uint16_t port);
HelloInfo
verify_client_hello(const Key &key, std::span<const std::uint8_t> hello);
Accepted
accept_client_hello(const Key &key, std::span<const std::uint8_t> hello);
std::shared_ptr<Session>
client_session(const Key &key, std::span<const std::uint8_t> hello, std::span<const std::uint8_t> response);

class Session
{
public:
    ~Session();
    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;

    Bytes seal(std::span<const std::uint8_t> plaintext);
    Bytes open(std::span<const std::uint8_t> record);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    Session(const Key &key, std::span<const std::uint8_t> hello, std::span<const std::uint8_t> response, bool client);
    friend Accepted accept_client_hello(const Key &, std::span<const std::uint8_t>);
    friend std::shared_ptr<Session>
    client_session(const Key &, std::span<const std::uint8_t>, std::span<const std::uint8_t>);
};

} // namespace ft
