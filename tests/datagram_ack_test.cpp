#include "datagram_ack.hpp"

#include <chrono>
#include <cstdint>
#include <stdexcept>

namespace {

using namespace std::chrono_literals;
using Ack = ft::DatagramAck;

void
require(bool condition, const char *message)
{
    if (!condition)
        throw std::runtime_error(message);
}

void
sparse_traffic_has_a_bounded_ack_delay()
{
    Ack ack(100);
    const Ack::TimePoint start{};
    require(!ack.pending() && !ack.deadline() && !ack.due(start), "idle datagram flow requested an ACK");
    require(!ack.observe(132, start), "one small datagram requested an immediate ACK");
    require(ack.pending() && ack.sequence() == 132, "received datagram did not become pending ACK progress");
    require(ack.deadline() == start + Ack::Delay, "small datagram did not establish the ACK deadline");
    require(!ack.due(start + Ack::Delay - 1ms), "sparse flow ACK preceded its deadline");
    require(ack.due(start + Ack::Delay), "sparse flow ACK was not due at its deadline");

    ack.sent();
    require(!ack.pending() && !ack.deadline() && !ack.due(start + 1s),
            "completed ACK left an idle timer or repeated ACK pending");
}

void
traffic_does_not_postpone_an_existing_deadline()
{
    Ack ack(1000);
    const Ack::TimePoint start{};
    ack.observe(1100, start);
    const auto deadline = ack.deadline();
    require(!ack.observe(1200, start + 1ms), "small follow-up datagram requested an immediate ACK");
    require(ack.deadline() == deadline, "follow-up traffic postponed the first datagram's ACK deadline");
    require(ack.observe(1300, start + Ack::Delay), "continued small traffic suppressed a due ACK");
}

void
bulk_traffic_acks_on_the_byte_threshold()
{
    constexpr std::uint32_t initial = 700;
    Ack ack(initial);
    const Ack::TimePoint start{};
    require(!ack.observe(initial + Ack::ByteThreshold - 1, start), "byte threshold fired early");
    require(ack.observe(initial + Ack::ByteThreshold, start), "byte threshold did not ACK bulk traffic");
    ack.sent();
    require(!ack.observe(initial + 2 * Ack::ByteThreshold - 1, start + 1ms),
            "ACK accounting retained already acknowledged bytes");
    require(ack.observe(initial + 2 * Ack::ByteThreshold, start + 1ms),
            "second bulk interval did not independently reach its byte threshold");
}

void
outbound_payload_consumes_a_pending_ack()
{
    Ack ack(4000);
    const Ack::TimePoint start{};
    ack.observe(4100, start);
    ack.sent();
    require(ack.sequence() == 4100 && !ack.pending() && !ack.deadline(),
            "piggybacked ACK did not consume the received sequence progress");
    require(!ack.due(start + Ack::Delay), "piggybacked ACK was followed by a redundant timer ACK");
    ack.observe(4200, start + 1s);
    require(ack.deadline() == start + 1s + Ack::Delay,
            "new inbound data reused the piggybacked ACK's old deadline");
}

void
loss_reordering_and_sequence_wrap_do_not_regress_ack_progress()
{
    const Ack::TimePoint start{};
    Ack ack(10000);
    ack.observe(14000, start);
    ack.observe(12000, start + 1ms);
    ack.observe(14000, start + 2ms);
    require(ack.sequence() == 14000, "reordered or duplicate datagram regressed fake TCP ACK progress");
    require(!ack.due(start + 2ms), "duplicate or reordered data inflated the ACK byte threshold");
    require(ack.observe(10000 + Ack::ByteThreshold, start + 3ms),
            "missing earlier datagrams blocked cumulative fake TCP ACK progress");

    constexpr std::uint32_t initial = 0xfffff000u;
    Ack wrapped(initial);
    const std::uint32_t before_threshold = initial + Ack::ByteThreshold - 1;
    const std::uint32_t at_threshold = initial + Ack::ByteThreshold;
    require(!wrapped.observe(before_threshold, start), "sequence wrap falsely exceeded the ACK byte threshold");
    require(wrapped.observe(at_threshold, start), "sequence wrap lost forward ACK progress");
    wrapped.observe(0xfffffff0u, start + 1ms);
    require(wrapped.sequence() == at_threshold, "pre-wrap reordered datagram regressed post-wrap ACK progress");
}

void
new_handshake_resets_the_ack_state()
{
    Ack ack(123);
    const Ack::TimePoint start{};
    ack.observe(456, start);
    ack.reset(90000);
    require(ack.sequence() == 90000 && !ack.pending() && !ack.deadline() && !ack.due(start + 1s),
            "new handshake retained earlier ACK sequence or timer state");
    require(!ack.observe(90001, start + 2s), "reset left earlier received bytes in the ACK threshold");
}

} // namespace

void
test_datagram_ack()
{
    sparse_traffic_has_a_bounded_ack_delay();
    traffic_does_not_postpone_an_existing_deadline();
    bulk_traffic_acks_on_the_byte_threshold();
    outbound_payload_consumes_a_pending_ack();
    loss_reordering_and_sequence_wrap_do_not_regress_ack_progress();
    new_handshake_resets_the_ack_state();
}
