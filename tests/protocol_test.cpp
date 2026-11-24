#include "protocol.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {
void
require(bool condition, std::string_view message)
{
    if (!condition)
        throw std::runtime_error(std::string(message));
}

template <typename Function>
void
reject(Function &&function, std::string_view message)
{
    try
    {
        function();
    }
    catch (const std::runtime_error &)
    {
        return;
    }
    throw std::runtime_error(std::string(message));
}

ft::Key
key(std::uint8_t value)
{
    ft::Key result{};
    result.fill(value);
    return result;
}

ft::Bytes
bytes(std::string_view value)
{
    return ft::Bytes(value.begin(), value.end());
}

std::uint64_t
counter(std::span<const std::uint8_t> record)
{
    require(record.size() >= 8, "record counter is truncated");
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < 8; ++i)
        result = (result << 8) | record[i];
    return result;
}

struct Sessions
{
    std::shared_ptr<ft::Session> client;
    std::shared_ptr<ft::Session> server;
};

Sessions
sessions()
{
    const auto psk = key(0x63);
    const auto hello = ft::new_client_hello(psk, ft::Mode::Datagram, 3389);
    const auto accepted = ft::accept_client_hello(psk, hello);
    return { ft::client_session(psk, hello, accepted.response), accepted.session };
}

ft::Bytes
seal(ft::Session &session, std::string_view text)
{
    return session.seal(bytes(text));
}

void
open(ft::Session &session, std::span<const std::uint8_t> record, std::string_view text)
{
    require(session.open(record) == bytes(text), "decrypted plaintext differs from the sent record");
}

void
handshake_authenticates_transcript()
{
    const auto psk = key(0x22);
    for (const auto mode : { ft::Mode::Stream, ft::Mode::Datagram })
    {
        const auto hello = ft::new_client_hello(psk, mode, 445);
        require(hello.size() == ft::HelloSize, "hello has the wrong wire size");
        const auto info = ft::verify_client_hello(psk, hello);
        require(info.mode == mode && info.port == 445, "hello mode or destination port was changed");
        reject([&] { ft::verify_client_hello(key(0x23), hello); }, "hello accepted with the wrong PSK");
        for (const auto offset : std::array<std::size_t, 7>{ 0, 4, 5, 6, 7, 8, hello.size() - 1 })
        {
            auto altered = hello;
            altered[offset] ^= 1;
            reject([&] { ft::verify_client_hello(psk, altered); }, "altered hello was authenticated");
        }
        const auto accepted = ft::accept_client_hello(psk, hello);
        require(accepted.response.size() == ft::ResponseSize, "response has the wrong wire size");
        require(
            ft::client_session(psk, hello, accepted.response) != nullptr, "valid response did not establish a session");
        reject(
            [&] { ft::client_session(key(0x23), hello, accepted.response); }, "response accepted with the wrong PSK");
        for (const auto offset : std::array<std::size_t, 3>{ 0, 31, accepted.response.size() - 1 })
        {
            auto altered = accepted.response;
            altered[offset] ^= 1;
            reject([&] { ft::client_session(psk, hello, altered); }, "altered response was authenticated");
        }
        const auto other_hello = ft::new_client_hello(psk, mode, 445);
        reject(
            [&] { ft::client_session(psk, other_hello, accepted.response); },
            "response accepted for another client transcript");
    }
}

void
handshake_rejects_malformed_input()
{
    const auto psk = key(0x41);
    for (const auto value : { 0, 3, 255 })
        reject([&] { ft::new_client_hello(psk, static_cast<ft::Mode>(value), 22); }, "invalid transport mode accepted");
    reject([&] { ft::new_client_hello(psk, ft::Mode::Stream, 0); }, "destination port zero accepted");
    const auto hello = ft::new_client_hello(psk, ft::Mode::Stream, 22);
    auto extended_hello = hello;
    extended_hello.push_back(0);
    const auto hello_span = std::span<const std::uint8_t>(hello);
    for (const auto invalid : { std::span<const std::uint8_t>{},
                                hello_span.first(hello.size() - 1),
                                std::span<const std::uint8_t>(extended_hello) })
    {
        reject([&] { ft::verify_client_hello(psk, invalid); }, "malformed hello accepted by verifier");
        reject([&] { ft::accept_client_hello(psk, invalid); }, "malformed hello established a server session");
    }
    const auto accepted = ft::accept_client_hello(psk, hello);
    auto extended_response = accepted.response;
    extended_response.push_back(0);
    const auto response_span = std::span<const std::uint8_t>(accepted.response);
    for (const auto invalid : { std::span<const std::uint8_t>{},
                                response_span.first(accepted.response.size() - 1),
                                std::span<const std::uint8_t>(extended_response) })
        reject([&] { ft::client_session(psk, hello, invalid); }, "malformed response established a client session");
}

void
duplex_keys_and_replay()
{
    const auto pair = sessions();
    const auto request = seal(*pair.client, "same plaintext");
    const auto response = seal(*pair.server, "same plaintext");
    require(request != response, "opposite directions reused ciphertext");
    require(counter(request) == 1 && counter(response) == 1, "initial record counter is not one");
    reject([&] { pair.client->open(request); }, "client accepted its own outbound record");
    open(*pair.server, request, "same plaintext");
    open(*pair.client, response, "same plaintext");
    reject([&] { pair.server->open(request); }, "replayed client record accepted");
    reject([&] { pair.client->open(response); }, "replayed server record accepted");
}

void
replay_window_accepts_reordering()
{
    const auto pair = sessions();
    std::vector<ft::Bytes> records;
    records.reserve(1030);
    for (std::size_t i = 0; i < 1030; ++i)
        records.push_back(seal(*pair.client, "datagram"));
    open(*pair.server, records[1029], "datagram");
    open(*pair.server, records[6], "datagram");
    open(*pair.server, records[999], "datagram");
    reject([&] { pair.server->open(records[5]); }, "record outside the 1024-counter window accepted");
    reject([&] { pair.server->open(records[6]); }, "reordered duplicate accepted");
    open(*pair.server, records[7], "datagram");
}

void
authentication_failure_preserves_replay_state()
{
    const auto pair = sessions();
    const auto record = seal(*pair.client, "valid after forgery");
    auto forged = record;
    std::fill_n(forged.begin(), 8, std::numeric_limits<std::uint8_t>::max());
    reject([&] { pair.server->open(forged); }, "forged high counter authenticated");
    auto corrupt = record;
    corrupt.back() ^= 1;
    reject([&] { pair.server->open(corrupt); }, "corrupt authentication tag accepted");
    const auto record_span = std::span<const std::uint8_t>(record);
    for (const auto invalid :
         { std::span<const std::uint8_t>{}, record_span.first(7), record_span.first(record.size() - 1) })
        reject([&] { pair.server->open(invalid); }, "truncated record authenticated");
    open(*pair.server, record, "valid after forgery");
}

void
replay_window_moves_across_word_boundaries()
{
    const auto pair = sessions();
    std::vector<ft::Bytes> records;
    records.reserve(1200);
    for (std::size_t i = 0; i < 1200; ++i)
        records.push_back(seal(*pair.client, "moving window"));
    std::vector<std::size_t> seen;
    for (const auto value :
         std::array<std::size_t, 13>{ 1, 2, 64, 65, 128, 129, 511, 512, 513, 1024, 1025, 1100, 1200 })
    {
        open(*pair.server, records[value - 1], "moving window");
        seen.push_back(value);
        for (const auto previous : seen)
            reject([&] { pair.server->open(records[previous - 1]); }, "moving window forgot a seen record");
    }
    open(*pair.server, records[176], "moving window");
    reject([&] { pair.server->open(records[175]); }, "record outside the moved window accepted");
}

void
reconnect_uses_independent_keys()
{
    const auto first = sessions();
    const auto second = sessions();
    const auto first_record = seal(*first.client, "same plaintext");
    const auto second_record = seal(*second.client, "same plaintext");
    require(first_record != second_record, "reconnected sessions reused ciphertext");
    reject([&] { second.server->open(first_record); }, "old-session ciphertext accepted after reconnect");
    reject([&] { first.server->open(second_record); }, "new-session ciphertext accepted in an old session");
    open(*first.server, first_record, "same plaintext");
    open(*second.server, second_record, "same plaintext");
}

void
concurrent_seal_allocates_unique_counters()
{
    const auto pair = sessions();
    constexpr std::size_t count = 128;
    std::vector<ft::Bytes> records(count);
    std::exception_ptr failure;
    std::mutex failure_mutex;
    {
        std::vector<std::jthread> threads;
        threads.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            threads.emplace_back([&, i] {
                try
                {
                    records[i] = seal(*pair.client, "concurrent datagram");
                }
                catch (...)
                {
                    std::lock_guard lock(failure_mutex);
                    if (!failure)
                        failure = std::current_exception();
                }
            });
        }
    }
    if (failure)
        std::rethrow_exception(failure);
    std::set<std::uint64_t> seen;
    for (const auto &record : records)
    {
        require(seen.insert(counter(record)).second, "concurrent seal reused a record counter");
        open(*pair.server, record, "concurrent datagram");
    }
    require(seen.size() == count, "concurrent seal lost records");
}

void
empty_records_require_authentication()
{
    auto pair = sessions();
    const auto empty = pair.client->seal(ft::Bytes{});
    require(empty.size() == ft::RecordOverhead, "empty record has unexpected wire size");
    auto altered = empty;
    altered.back() ^= 1;
    reject([&] { pair.server->open(altered); }, "empty record with invalid authentication tag was accepted");
    auto forged = empty;
    std::fill_n(forged.begin(), 8, std::uint8_t{ 0xff });
    reject([&] { pair.server->open(forged); }, "empty forged counter bypassed authentication");
    require(pair.server->open(empty).empty(), "valid empty record failed after unauthenticated counters");
    open(*pair.server, seal(*pair.client, "next record"), "next record");
}

void
authenticated_replays_preserve_receive_state()
{
    const auto replay = [](ft::Session &receiver, const ft::Bytes &record) {
        try
        {
            receiver.open(record);
        }
        catch (const ft::ReplayError &)
        {
            return;
        }
        throw std::runtime_error("authenticated replay did not produce ReplayError");
    };
    const auto unauthenticated = [](ft::Session &receiver, const ft::Bytes &record) {
        try
        {
            receiver.open(record);
        }
        catch (const ft::ReplayError &)
        {
            throw std::runtime_error("unauthenticated record was classified as an authenticated replay");
        }
        catch (const std::runtime_error &)
        {
            return;
        }
        throw std::runtime_error("unauthenticated record was accepted");
    };

    auto pair = sessions();
    const auto first = seal(*pair.client, "first");
    open(*pair.server, first, "first");
    replay(*pair.server, first);
    auto altered = first;
    altered.back() ^= 1;
    unauthenticated(*pair.server, altered);
    open(*pair.server, seal(*pair.client, "second"), "second");

    auto window = sessions();
    std::vector<ft::Bytes> records;
    for (std::size_t i = 0; i < 1026; ++i)
        records.push_back(seal(*window.client, "window"));
    open(*window.server, records.back(), "window");
    replay(*window.server, records.front());
    auto expired = records.front();
    expired.back() ^= 1;
    unauthenticated(*window.server, expired);
    auto seen = records.back();
    seen.back() ^= 1;
    unauthenticated(*window.server, seen);
    replay(*window.server, records.back());
    open(*window.server, records[1024], "window");
    open(*window.server, seal(*window.client, "after errors"), "after errors");
}
} // namespace

void
test_protocol()
{
    handshake_authenticates_transcript();
    handshake_rejects_malformed_input();
    duplex_keys_and_replay();
    replay_window_accepts_reordering();
    authentication_failure_preserves_replay_state();
    replay_window_moves_across_word_boundaries();
    reconnect_uses_independent_keys();
    concurrent_seal_allocates_unique_counters();
    empty_records_require_authentication();
    authenticated_replays_preserve_receive_state();
}
