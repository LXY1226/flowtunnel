#include "packet.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <utility>

namespace ft {
namespace {

constexpr std::array<std::uint8_t, 8> Marker{ 254, 8, 'F', 'T', '0', '1', 0, 1 };
constexpr auto AssemblyTimeout = std::chrono::seconds(3);

std::uint16_t
read16(std::span<const std::uint8_t> bytes, std::size_t pos)
{
    return static_cast<std::uint16_t>((bytes[pos] << 8) | bytes[pos + 1]);
}

std::uint32_t
read32(std::span<const std::uint8_t> bytes, std::size_t pos)
{
    return (static_cast<std::uint32_t>(bytes[pos]) << 24) | (static_cast<std::uint32_t>(bytes[pos + 1]) << 16) |
           (static_cast<std::uint32_t>(bytes[pos + 2]) << 8) | bytes[pos + 3];
}

std::uint64_t
read64(std::span<const std::uint8_t> bytes, std::size_t pos)
{
    return (static_cast<std::uint64_t>(read32(bytes, pos)) << 32) | read32(bytes, pos + 4);
}

void
write16(Bytes &bytes, std::size_t pos, std::uint16_t value)
{
    bytes[pos] = static_cast<std::uint8_t>(value >> 8);
    bytes[pos + 1] = static_cast<std::uint8_t>(value);
}

void
write32(Bytes &bytes, std::size_t pos, std::uint32_t value)
{
    bytes[pos] = static_cast<std::uint8_t>(value >> 24);
    bytes[pos + 1] = static_cast<std::uint8_t>(value >> 16);
    bytes[pos + 2] = static_cast<std::uint8_t>(value >> 8);
    bytes[pos + 3] = static_cast<std::uint8_t>(value);
}

void
write64(Bytes &bytes, std::size_t pos, std::uint64_t value)
{
    write32(bytes, pos, static_cast<std::uint32_t>(value >> 32));
    write32(bytes, pos + 4, static_cast<std::uint32_t>(value));
}

Bytes
ip_packet(std::uint32_t src, std::uint32_t dst, std::size_t size, std::uint8_t protocol)
{
    if (size > 65535)
    {
        throw std::length_error("packet exceeds IPv4 maximum size");
    }
    Bytes bytes(size);
    bytes[0] = 0x45;
    bytes[8] = 64;
    bytes[9] = protocol;
    write16(bytes, 2, static_cast<std::uint16_t>(size));
    write16(bytes, 6, 0x4000);
    write32(bytes, 12, src);
    write32(bytes, 16, dst);
    return bytes;
}

bool
overlaps(std::size_t offset, std::size_t size, std::size_t other_offset, std::size_t other_size)
{
    return offset < other_offset + other_size && other_offset < offset + size;
}

} // namespace

Packet
Packet::parse(Bytes bytes)
{
    if (bytes.size() < 20 || bytes[0] >> 4 != 4)
    {
        throw std::runtime_error("invalid IPv4 packet");
    }
    Packet packet;
    packet.ip_len = static_cast<std::size_t>(bytes[0] & 15) * 4;
    const auto total = read16(bytes, 2);
    if (packet.ip_len < 20 || total < packet.ip_len || total > bytes.size())
    {
        throw std::runtime_error("invalid IPv4 length");
    }
    bytes.resize(total);
    packet.protocol = bytes[9];
    packet.src = read32(bytes, 12);
    packet.dst = read32(bytes, 16);
    packet.fragment = read16(bytes, 6) & 0x3fff;
    if (packet.fragment == 0 && packet.protocol == 6)
    {
        const auto length = bytes.size() - packet.ip_len;
        if (length < 20)
        {
            throw std::runtime_error("short TCP header");
        }
        packet.transport_len = static_cast<std::size_t>(bytes[packet.ip_len + 12] >> 4) * 4;
        if (packet.transport_len < 20 || packet.transport_len > length)
        {
            throw std::runtime_error("invalid TCP header length");
        }
        packet.seq = read32(bytes, packet.ip_len + 4);
        packet.ack = read32(bytes, packet.ip_len + 8);
        packet.flags = bytes[packet.ip_len + 13];
    }
    else if (packet.fragment == 0 && packet.protocol == 17)
    {
        const auto length = bytes.size() - packet.ip_len;
        if (length < 8 || read16(bytes, packet.ip_len + 4) != length)
        {
            throw std::runtime_error("invalid UDP length");
        }
        packet.transport_len = 8;
    }
    if (packet.transport_len != 0)
    {
        packet.src_port = read16(bytes, packet.ip_len);
        packet.dst_port = read16(bytes, packet.ip_len + 2);
    }
    packet.bytes = std::move(bytes);
    return packet;
}

std::span<const std::uint8_t>
Packet::payload() const
{
    return std::span<const std::uint8_t>(bytes).subspan(ip_len + transport_len);
}

bool
Packet::has_marker() const
{
    if (protocol != 6 || fragment != 0)
    {
        return false;
    }
    auto options = std::span<const std::uint8_t>(bytes).subspan(ip_len + 20, transport_len - 20);
    while (!options.empty())
    {
        if (options[0] == 0)
        {
            break;
        }
        if (options[0] == 1)
        {
            options = options.subspan(1);
            continue;
        }
        if (options.size() < 2 || options[1] < 2 || options[1] > options.size())
        {
            return false;
        }
        if (options[0] == Marker[0] && options[1] == Marker.size() &&
            std::equal(Marker.begin(), Marker.end(), options.begin()))
        {
            return true;
        }
        options = options.subspan(options[1]);
    }
    return false;
}

void
Packet::reflect(std::uint16_t port, bool reverse)
{
    std::swap(src, dst);
    write32(bytes, 12, src);
    write32(bytes, 16, dst);
    if (reverse)
    {
        src_port = port;
        write16(bytes, ip_len, port);
    }
    else
    {
        dst_port = port;
        write16(bytes, ip_len + 2, port);
    }
}

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
    bool marker)
{
    const auto header = 20 + (marker ? Marker.size() : 0);
    if (payload.size() > 65535 - 20 - header)
    {
        throw std::length_error("TCP payload exceeds IPv4 maximum size");
    }
    auto bytes = ip_packet(src, dst, 20 + header + payload.size(), 6);
    write16(bytes, 20, src_port);
    write16(bytes, 22, dst_port);
    write32(bytes, 24, seq);
    write32(bytes, 28, ack);
    bytes[32] = static_cast<std::uint8_t>((header / 4) << 4);
    bytes[33] = flags;
    write16(bytes, 34, 65535);
    if (marker)
    {
        std::copy(Marker.begin(), Marker.end(), bytes.begin() + 40);
    }
    std::copy(payload.begin(), payload.end(), bytes.begin() + 20 + header);
    return bytes;
}

Bytes
udp_packet(
    std::uint32_t src,
    std::uint32_t dst,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::span<const std::uint8_t> payload)
{
    if (payload.size() > MaxDatagram)
    {
        throw std::length_error("UDP datagram exceeds IPv4 maximum size");
    }
    auto bytes = ip_packet(src, dst, 28 + payload.size(), 17);
    write16(bytes, 20, src_port);
    write16(bytes, 22, dst_port);
    write16(bytes, 24, static_cast<std::uint16_t>(8 + payload.size()));
    std::copy(payload.begin(), payload.end(), bytes.begin() + 28);
    return bytes;
}

std::optional<Bytes>
IPReassembler::add(const Packet &packet)
{
    if (packet.fragment == 0)
    {
        return packet.bytes;
    }
    const auto now = std::chrono::steady_clock::now();
    for (auto it = groups_.begin(); it != groups_.end();)
    {
        if (now - it->second.created > AssemblyTimeout)
        {
            size_ -= it->second.size;
            it = groups_.erase(it);
        }
        else
        {
            ++it;
        }
    }
    const auto identity = Identity{ packet.src, packet.dst, packet.protocol, read16(packet.bytes, 4) };
    const auto payload = packet.payload();
    auto it = groups_.find(identity);
    if (it == groups_.end())
    {
        if (groups_.size() >= 128 || size_ + payload.size() > (8u << 20))
        {
            throw std::runtime_error("IPv4 reassembly limit exceeded");
        }
        it = groups_.emplace(identity, Group{ {}, {}, {}, 0, now }).first;
    }
    auto &group = it->second;
    const auto fail = [&]() -> std::optional<Bytes> {
        size_ -= group.size;
        groups_.erase(it);
        throw std::runtime_error("invalid IPv4 fragments");
    };
    const auto offset = static_cast<std::size_t>(packet.fragment & 0x1fff) * 8;
    const bool more = (packet.fragment & 0x2000) != 0;
    if (payload.empty() || offset + payload.size() > 65515 || (more && payload.size() % 8 != 0))
    {
        return fail();
    }
    for (const auto &part : group.parts)
    {
        if (overlaps(offset, payload.size(), part.offset, part.data.size()))
        {
            return fail();
        }
    }
    if (group.end && offset + payload.size() > *group.end)
    {
        return fail();
    }
    if (!more)
    {
        if (group.end && *group.end != offset + payload.size())
        {
            return fail();
        }
        group.end = offset + payload.size();
        for (const auto &part : group.parts)
        {
            if (part.offset + part.data.size() > *group.end)
            {
                return fail();
            }
        }
    }
    if (offset == 0)
    {
        group.header.assign(packet.bytes.begin(), packet.bytes.begin() + packet.ip_len);
    }
    if (size_ + payload.size() > (8u << 20))
    {
        return fail();
    }
    group.parts.push_back(Part{ offset, Bytes(payload.begin(), payload.end()) });
    group.size += payload.size();
    size_ += payload.size();
    if (!group.end || group.size != *group.end || group.header.empty())
    {
        return std::nullopt;
    }
    if (group.header.size() + *group.end > 65535)
    {
        return fail();
    }
    Bytes result(group.header.size() + *group.end);
    std::copy(group.header.begin(), group.header.end(), result.begin());
    for (const auto &part : group.parts)
    {
        std::copy(part.data.begin(), part.data.end(), result.begin() + group.header.size() + part.offset);
    }
    write16(result, 2, static_cast<std::uint16_t>(result.size()));
    write16(result, 6, 0);
    size_ -= group.size;
    groups_.erase(it);
    return result;
}

std::optional<Bytes>
DatagramAssembler::add(std::span<const std::uint8_t> fragment)
{
    if (fragment.size() < FragmentHeader || fragment[0] != 1)
    {
        throw std::runtime_error("invalid datagram fragment");
    }
    const auto id = read64(fragment, 1);
    const auto total = static_cast<std::size_t>(read16(fragment, 9));
    const auto offset = static_cast<std::size_t>(read16(fragment, 11));
    const auto payload = fragment.subspan(FragmentHeader);
    if (total > MaxDatagram || offset + payload.size() > total || (total != 0 && payload.empty()))
    {
        throw std::runtime_error("invalid datagram fragment bounds");
    }
    if (total == 0)
    {
        return Bytes{};
    }
    const auto now = std::chrono::steady_clock::now();
    for (auto it = groups_.begin(); it != groups_.end();)
    {
        if (now - it->second.created > AssemblyTimeout)
        {
            size_ -= it->second.size;
            it = groups_.erase(it);
        }
        else
        {
            ++it;
        }
    }
    auto it = groups_.find(id);
    if (it == groups_.end())
    {
        if (groups_.size() >= 64 || size_ + payload.size() > (1u << 20))
        {
            throw std::runtime_error("datagram reassembly limit exceeded");
        }
        it = groups_.emplace(id, Group{ total, {}, 0, now }).first;
    }
    auto &group = it->second;
    const auto fail = [&]() -> std::optional<Bytes> {
        size_ -= group.size;
        groups_.erase(it);
        throw std::runtime_error("overlapping or inconsistent datagram fragments");
    };
    if (total != group.total || size_ + payload.size() > (1u << 20))
    {
        return fail();
    }
    for (const auto &part : group.parts)
    {
        if (overlaps(offset, payload.size(), part.offset, part.data.size()))
        {
            return fail();
        }
    }
    group.parts.push_back(Part{ offset, Bytes(payload.begin(), payload.end()) });
    group.size += payload.size();
    size_ += payload.size();
    if (group.size != group.total)
    {
        return std::nullopt;
    }
    Bytes result(total);
    for (const auto &part : group.parts)
    {
        std::copy(part.data.begin(), part.data.end(), result.begin() + part.offset);
    }
    size_ -= group.size;
    groups_.erase(it);
    return result;
}

std::vector<Bytes>
split_datagram(std::span<const std::uint8_t> payload, std::uint64_t id, std::size_t chunk)
{
    if (payload.size() > MaxDatagram || chunk == 0)
    {
        throw std::length_error("invalid UDP datagram or fragment size");
    }
    std::vector<Bytes> fragments;
    for (std::size_t offset = 0; offset < payload.size() || offset == 0;)
    {
        const auto length = std::min(chunk, payload.size() - offset);
        Bytes fragment(FragmentHeader + length);
        fragment[0] = 1;
        write64(fragment, 1, id);
        write16(fragment, 9, static_cast<std::uint16_t>(payload.size()));
        write16(fragment, 11, static_cast<std::uint16_t>(offset));
        std::copy_n(payload.begin() + offset, length, fragment.begin() + FragmentHeader);
        fragments.push_back(std::move(fragment));
        offset += length;
        if (payload.empty())
        {
            break;
        }
    }
    return fragments;
}

} // namespace ft
