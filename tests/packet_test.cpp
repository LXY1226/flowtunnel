#include "packet.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

constexpr std::uint32_t Client = 0xc000020a;
constexpr std::uint32_t Virtual = 0x0ac80001;

void
require(bool condition, const std::string &message)
{
    if (!condition)
    {
        throw std::runtime_error(message);
    }
}

template <typename Action>
void
reject(Action action, const std::string &message)
{
    try
    {
        action();
    }
    catch (const std::exception &)
    {
        return;
    }
    throw std::runtime_error(message);
}

void
write16(ft::Bytes &bytes, std::size_t offset, std::uint16_t value)
{
    bytes[offset] = static_cast<std::uint8_t>(value >> 8);
    bytes[offset + 1] = static_cast<std::uint8_t>(value);
}

ft::Bytes
patterned(std::size_t size)
{
    ft::Bytes bytes(size);
    for (std::size_t i = 0; i < size; ++i)
    {
        bytes[i] = static_cast<std::uint8_t>(i * 31);
    }
    return bytes;
}

ft::Packet
fragment(const ft::Bytes &original, std::uint16_t id, std::size_t offset, std::size_t size, bool more)
{
    ft::Bytes bytes(original.begin(), original.begin() + 20);
    bytes.insert(bytes.end(), original.begin() + 20 + offset, original.begin() + 20 + offset + size);
    write16(bytes, 2, static_cast<std::uint16_t>(bytes.size()));
    write16(bytes, 4, id);
    write16(bytes, 6, static_cast<std::uint16_t>(offset / 8) | (more ? 0x2000 : 0));
    return ft::Packet::parse(std::move(bytes));
}

void
test_parse_and_marker()
{
    const auto payload = patterned(31);
    const auto tcp =
        ft::Packet::parse(ft::tcp_packet(Client, Virtual, 49152, 445, 123, 456, ft::Psh | ft::Ack, payload, true));
    require(
        tcp.src == Client && tcp.dst == Virtual && tcp.src_port == 49152 && tcp.dst_port == 445 && tcp.seq == 123 &&
            tcp.ack == 456 && tcp.flags == (ft::Psh | ft::Ack) && tcp.has_marker() &&
            std::ranges::equal(tcp.payload(), payload),
        "TCP parse changed flow identity or payload");
    const auto udp = ft::Packet::parse(ft::udp_packet(Client, Virtual, 49153, 3389, payload));
    require(
        udp.protocol == 17 && udp.src_port == 49153 && udp.dst_port == 3389 && !udp.has_marker() &&
            std::ranges::equal(udp.payload(), payload),
        "UDP parse changed flow identity or payload");
    require(
        ft::Packet::parse(ft::udp_packet(Client, Virtual, 1, 2, {})).payload().empty(), "empty UDP datagram changed");

    const auto plain = ft::tcp_packet(Client, Virtual, 1, 2, 0, 0, ft::Syn, {}, false);
    auto invalid = plain;
    invalid.resize(19);
    reject([&] { ft::Packet::parse(invalid); }, "short IPv4 packet accepted");
    invalid = plain;
    invalid[0] = 0x65;
    reject([&] { ft::Packet::parse(invalid); }, "non-IPv4 packet accepted");
    invalid = plain;
    invalid[0] = 0x44;
    reject([&] { ft::Packet::parse(invalid); }, "undersized IPv4 header accepted");
    invalid = plain;
    write16(invalid, 2, 41);
    reject([&] { ft::Packet::parse(invalid); }, "oversized IPv4 total length accepted");
    invalid = plain;
    write16(invalid, 2, 19);
    reject([&] { ft::Packet::parse(invalid); }, "IPv4 total length below header accepted");
    invalid = plain;
    invalid[32] = 0x40;
    reject([&] { ft::Packet::parse(invalid); }, "undersized TCP header accepted");
    invalid = plain;
    invalid[32] = 0xf0;
    reject([&] { ft::Packet::parse(invalid); }, "oversized TCP header accepted");
    invalid = ft::udp_packet(Client, Virtual, 1, 2, payload);
    write16(invalid, 24, 8);
    reject([&] { ft::Packet::parse(invalid); }, "inconsistent UDP length accepted");
    auto padded = plain;
    padded.insert(padded.end(), { 1, 2, 3 });
    require(ft::Packet::parse(padded).bytes.size() == plain.size(), "trailing IP padding became payload");

    const std::array<std::uint8_t, 8> marker{ 254, 8, 'F', 'T', '0', '1', 0, 1 };
    for (const auto &prefix : std::vector<ft::Bytes>{ {}, { 1, 1, 1, 1 }, { 2, 4, 5, 180 } })
    {
        auto bytes = plain;
        bytes.insert(bytes.end(), prefix.begin(), prefix.end());
        bytes.insert(bytes.end(), marker.begin(), marker.end());
        write16(bytes, 2, static_cast<std::uint16_t>(bytes.size()));
        bytes[32] = static_cast<std::uint8_t>(((20 + prefix.size() + marker.size()) / 4) << 4);
        require(ft::Packet::parse(bytes).has_marker(), "valid marker with TCP options rejected");
    }
    for (const auto &options : std::vector<ft::Bytes>{ { 0, 0, 0, 0, 254, 8, 'F', 'T', '0', '1', 0, 1 },
                                                       { 254, 1, 0, 0 },
                                                       { 254, 8, 'F', 'T' },
                                                       { 254, 8, 'F', 'T', '0', '1', 0, 2 } })
    {
        auto bytes = plain;
        bytes.insert(bytes.end(), options.begin(), options.end());
        write16(bytes, 2, static_cast<std::uint16_t>(bytes.size()));
        bytes[32] = static_cast<std::uint8_t>(((20 + options.size()) / 4) << 4);
        require(!ft::Packet::parse(bytes).has_marker(), "invalid or terminated marker options accepted");
    }
}

void
test_reflection()
{
    const auto payload = patterned(13);
    auto request = ft::Packet::parse(ft::tcp_packet(Client, Virtual, 49152, 445, 100, 200, ft::Ack, payload));
    request.reflect(34010, false);
    const auto reflected = ft::Packet::parse(request.bytes);
    require(
        reflected.src == Virtual && reflected.dst == Client && reflected.src_port == 49152 &&
            reflected.dst_port == 34010 && reflected.seq == 100 && reflected.ack == 200 &&
            std::ranges::equal(reflected.payload(), payload),
        "request reflection lost flow identity");
    auto reply = ft::Packet::parse(ft::tcp_packet(Client, Virtual, 34010, 49152, 200, 100, ft::Ack, payload));
    reply.reflect(445, true);
    const auto restored = ft::Packet::parse(reply.bytes);
    require(
        restored.src == Virtual && restored.dst == Client && restored.src_port == 445 && restored.dst_port == 49152 &&
            std::ranges::equal(restored.payload(), payload),
        "reply reflection lost flow identity");
}

void
test_ipv4_fragments()
{
    for (const auto size : { 4096u, 60000u, 65507u })
    {
        const auto payload = patterned(size);
        const auto original = ft::udp_packet(Client, Virtual, 50000, 3389, payload);
        std::vector<ft::Packet> parts;
        for (std::size_t offset = 0; offset < original.size() - 20; offset += 1480)
        {
            const auto count = std::min<std::size_t>(1480, original.size() - 20 - offset);
            parts.push_back(fragment(original, 77, offset, count, offset + count < original.size() - 20));
        }
        ft::IPReassembler assembler;
        for (std::size_t i = parts.size(); i-- > 0;)
        {
            const auto assembled = assembler.add(parts[i]);
            require(assembled.has_value() == (i == 0), "incomplete IPv4 fragment set delivered");
            if (assembled)
            {
                const auto packet = ft::Packet::parse(*assembled);
                require(
                    packet.fragment == 0 && std::ranges::equal(packet.payload(), payload),
                    "IPv4 reassembly corrupted UDP datagram");
            }
        }
    }

    const auto original = ft::udp_packet(Client, Virtual, 50000, 3389, patterned(4096));
    ft::IPReassembler missing;
    require(!missing.add(fragment(original, 1, 0, 1480, true)), "first IPv4 fragment delivered");
    require(
        !missing.add(fragment(original, 1, 2960, original.size() - 20 - 2960, false)),
        "IPv4 datagram delivered with missing middle fragment");
    reject([&] { missing.add(fragment(original, 1, 1472, 1480, true)); }, "overlapping IPv4 fragment accepted");
    require(!missing.add(fragment(original, 1, 0, 1480, true)), "invalid IPv4 assembly retained overlapping state");

    ft::IPReassembler bounds;
    reject([&] { bounds.add(fragment(original, 2, 0, 15, true)); }, "unaligned non-final IPv4 fragment accepted");
    auto excessive = fragment(original, 3, 0, 16, true).bytes;
    write16(excessive, 6, 0x3fff);
    reject([&] { bounds.add(ft::Packet::parse(excessive)); }, "IPv4 fragment above total size limit accepted");
    ft::IPReassembler conflicting_end;
    require(
        !conflicting_end.add(fragment(original, 4, 2960, original.size() - 20 - 2960, false)),
        "last fragment delivered alone");
    reject(
        [&] { conflicting_end.add(fragment(original, 4, 1480, 16, false)); },
        "inconsistent IPv4 final offset accepted");

    ft::IPReassembler limited;
    for (std::uint16_t id = 0; id < 128; ++id)
    {
        require(!limited.add(fragment(original, id, 0, 16, true)), "incomplete fragment delivered");
    }
    reject([&] { limited.add(fragment(original, 128, 0, 16, true)); }, "IPv4 incomplete assembly limit not enforced");
}

void
test_datagram_fragments()
{
    for (const auto size : { 0u, 1u, 1100u, 4096u, 60000u, 65507u })
    {
        const auto payload = patterned(size);
        const auto parts = ft::split_datagram(payload, 123, 1100);
        ft::DatagramAssembler assembler;
        for (std::size_t i = parts.size(); i-- > 0;)
        {
            const auto assembled = assembler.add(parts[i]);
            require(assembled.has_value() == (i == 0), "incomplete tunnel datagram delivered");
            if (assembled)
            {
                require(*assembled == payload, "tunnel datagram changed payload or boundary");
            }
        }
    }
    const auto parts = ft::split_datagram(patterned(4096), 123, 1100);
    ft::DatagramAssembler missing;
    for (std::size_t i = 0; i < parts.size(); ++i)
    {
        if (i != 1)
        {
            require(!missing.add(parts[i]), "tunnel datagram delivered with missing fragment");
        }
    }
    for (const bool overlap : { false, true })
    {
        ft::DatagramAssembler assembler;
        require(!assembler.add(parts[0]), "first tunnel fragment delivered");
        auto bad = parts[1];
        write16(bad, overlap ? 11 : 9, overlap ? 1099 : 4097);
        reject([&] { assembler.add(bad); }, "conflicting tunnel fragments accepted");
        require(!assembler.add(parts[0]), "conflicting tunnel datagram retained state");
    }
    reject([&] { ft::split_datagram(patterned(65508), 1, 1100); }, "oversized IPv4 UDP datagram accepted");
    reject([&] { ft::udp_packet(Client, Virtual, 1, 2, patterned(65508)); }, "oversized UDP packet accepted");
    reject([&] { ft::split_datagram(patterned(1), 1, 0); }, "zero fragment chunk accepted");
    auto bad_total = parts[0];
    write16(bad_total, 9, 65508);
    reject([&] { ft::DatagramAssembler{}.add(bad_total); }, "oversized datagram total accepted");
    auto bad_offset = parts[0];
    write16(bad_offset, 11, 4096);
    reject([&] { ft::DatagramAssembler{}.add(bad_offset); }, "datagram fragment outside total accepted");
    auto bad_kind = parts[0];
    bad_kind[0] = 3;
    reject([&] { ft::DatagramAssembler{}.add(bad_kind); }, "incorrect datagram kind accepted");
    ft::Bytes short_header(12);
    reject([&] { ft::DatagramAssembler{}.add(short_header); }, "short datagram fragment header accepted");
    auto empty_body = parts[0];
    empty_body.resize(ft::FragmentHeader);
    reject([&] { ft::DatagramAssembler{}.add(empty_body); }, "empty fragment of nonempty datagram accepted");

    ft::DatagramAssembler limited;
    for (std::uint64_t id = 0; id < 64; ++id)
    {
        require(!limited.add(ft::split_datagram(patterned(1101), id, 1100)[0]), "incomplete datagram delivered");
    }
    reject(
        [&] { limited.add(ft::split_datagram(patterned(1101), 64, 1100)[0]); },
        "tunnel incomplete assembly limit not enforced");
    std::this_thread::sleep_for(std::chrono::milliseconds(3100));
    require(
        !limited.add(ft::split_datagram(patterned(1101), 64, 1100)[0]), "expired tunnel assembly storage not released");
}

} // namespace

void
test_packet()
{
    test_parse_and_marker();
    test_reflection();
    test_ipv4_fragments();
    test_datagram_fragments();
}
