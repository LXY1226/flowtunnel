#pragma once

#include "protocol.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <tuple>
#include <vector>

namespace ft {

inline constexpr std::uint8_t Fin = 1;
inline constexpr std::uint8_t Syn = 2;
inline constexpr std::uint8_t Rst = 4;
inline constexpr std::uint8_t Psh = 8;
inline constexpr std::uint8_t Ack = 16;
inline constexpr std::size_t FragmentHeader = 13;
inline constexpr std::size_t MaxDatagram = 65507;

struct Packet
{
    Bytes bytes;
    std::size_t ip_len = 0;
    std::size_t transport_len = 0;
    std::uint8_t protocol = 0;
    std::uint8_t flags = 0;
    std::uint32_t src = 0;
    std::uint32_t dst = 0;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint16_t fragment = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;

    static Packet parse(Bytes bytes);
    std::span<const std::uint8_t> payload() const;
    bool has_marker() const;
    void reflect(std::uint16_t port, bool reverse);
};

Bytes
tcp_packet(
    std::uint32_t src,
    std::uint32_t dst,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::uint32_t seq,
    std::uint32_t ack,
    std::uint8_t flags,
    std::span<const std::uint8_t> payload,
    bool marker = false);
Bytes
udp_packet(
    std::uint32_t src,
    std::uint32_t dst,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::span<const std::uint8_t> payload);

class IPReassembler
{
public:
    std::optional<Bytes> add(const Packet &packet);

private:
    struct Part
    {
        std::size_t offset;
        Bytes data;
    };
    struct Group
    {
        Bytes header;
        std::vector<Part> parts;
        std::optional<std::size_t> end;
        std::size_t size = 0;
        std::chrono::steady_clock::time_point created;
    };
    using Identity = std::tuple<std::uint32_t, std::uint32_t, std::uint8_t, std::uint16_t>;
    std::map<Identity, Group> groups_;
    std::size_t size_ = 0;
};

class DatagramAssembler
{
public:
    std::optional<Bytes> add(std::span<const std::uint8_t> fragment);

private:
    struct Part
    {
        std::size_t offset;
        Bytes data;
    };
    struct Group
    {
        std::size_t total;
        std::vector<Part> parts;
        std::size_t size = 0;
        std::chrono::steady_clock::time_point created;
    };
    std::map<std::uint64_t, Group> groups_;
    std::size_t size_ = 0;
};

std::vector<Bytes>
split_datagram(std::span<const std::uint8_t> payload, std::uint64_t id, std::size_t chunk);

} // namespace ft
