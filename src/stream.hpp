#pragma once

#include "protocol.hpp"

#include <asio.hpp>
#include <exception>
#include <string>

namespace ft {

std::string
format_stream_error(std::exception_ptr failure);
asio::awaitable<void>
serve_stream(asio::ip::tcp::acceptor &listener, Key key);
asio::awaitable<void>
relay_stream(asio::ip::tcp::socket local, std::string endpoint, Key key, std::uint16_t port);

} // namespace ft
