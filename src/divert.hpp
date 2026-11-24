#pragma once

#include "protocol.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#    define NOMINMAX
#endif
#include <windows.h>
#include <windivert.h>

#include <cstdint>
#include <span>
#include <string>

namespace ft {

struct Captured
{
    Bytes bytes;
    WINDIVERT_ADDRESS address{};
};

class Divert
{
public:
    Divert(const std::string &filter, std::int16_t priority, bool send_only = false);
    ~Divert();
    Divert(const Divert &) = delete;
    Divert &operator=(const Divert &) = delete;
    Divert(Divert &&other) noexcept;
    Divert &operator=(Divert &&other) noexcept;

    Captured recv(std::span<std::uint8_t> buffer);
    void send(std::span<std::uint8_t> bytes, WINDIVERT_ADDRESS address);
    // Shutdown receive, join its reader, then close the handle.
    void shutdown_recv();
    void close() noexcept;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

} // namespace ft
