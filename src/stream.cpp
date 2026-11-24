#include "stream.hpp"

#include <asio/experimental/parallel_group.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <syncstream>
#include <unordered_set>

namespace ft {

std::string
format_stream_error(std::exception_ptr failure)
{
    if (!failure)
        return "none";
    try
    {
        std::rethrow_exception(failure);
    }
    catch (const std::system_error &error)
    {
        return "code=" + std::string(error.code().category().name()) + ':' + std::to_string(error.code().value()) +
               " message=" + error.what();
    }
    catch (const std::exception &error)
    {
        std::string description = error.what();
        if (auto nested = dynamic_cast<const std::nested_exception *>(&error); nested && nested->nested_ptr())
            description += " cause={" + format_stream_error(nested->nested_ptr()) + "}";
        return description;
    }
    catch (...)
    {
        return "non-standard exception";
    }
}

namespace {

using asio::use_awaitable;
using asio::ip::tcp;
using Socket = std::shared_ptr<tcp::socket>;
constexpr std::uint8_t DataRecord = 1;
constexpr std::uint8_t FinRecord = 2;
constexpr std::uint8_t ClientFinished = 3;
constexpr std::uint8_t ServerReady = 4;
constexpr std::uint32_t MaxRecord = 65536;
constexpr std::size_t MaxClients = 256;

bool
cancelled(std::exception_ptr failure)
{
    if (!failure)
        return true;
    try
    {
        std::rethrow_exception(failure);
    }
    catch (const asio::system_error &error)
    {
        return error.code() == asio::error::operation_aborted;
    }
    catch (const std::exception &error)
    {
        auto nested = dynamic_cast<const std::nested_exception *>(&error);
        return nested && nested->nested_ptr() && cancelled(nested->nested_ptr());
    }
    catch (...)
    {
        return false;
    }
}

std::uint64_t
load_counter(std::span<const std::uint8_t> data)
{
    std::uint64_t result{};
    for (std::size_t i = 0; i < 8; ++i)
        result = (result << 8) | data[i];
    return result;
}

std::uint32_t
load_size(const std::array<std::uint8_t, 4> &data)
{
    std::uint32_t result{};
    for (auto value : data)
        result = (result << 8) | value;
    return result;
}

void
close_socket(const Socket &socket)
{
    asio::error_code ignored;
    socket->cancel(ignored);
    socket->close(ignored);
}

class Deadline
{
    asio::steady_timer timer_;

public:
    Deadline(
        asio::any_io_executor executor,
        std::weak_ptr<tcp::socket> socket,
        std::weak_ptr<tcp::resolver> resolver = {}) :
        timer_(executor, std::chrono::seconds(5))
    {
        timer_.async_wait([socket, resolver](asio::error_code error) {
            if (!error)
            {
                if (auto pending = resolver.lock())
                    pending->cancel();
                if (auto pending = socket.lock())
                    close_socket(pending);
            }
        });
    }
    ~Deadline() { cancel(); }
    void cancel() { timer_.cancel(); }
};

asio::awaitable<void>
read_prefix(const Socket &socket, std::string_view expected)
{
    std::string received(expected.size(), '\0');
    co_await asio::async_read(*socket, asio::buffer(received), use_awaitable);
    if (received != expected)
    {
        if (expected == ResponsePrefix)
        {
            auto end = received.find_first_of("\r\n");
            std::string status = "unavailable";
            if (received.starts_with("HTTP/") && end != std::string::npos)
            {
                status.clear();
                for (std::size_t i = 0; i < std::min(end, std::size_t{ 128 }); ++i)
                {
                    auto value = static_cast<unsigned char>(received[i]);
                    status.push_back(value >= 0x20 && value <= 0x7e ? received[i] : '?');
                }
            }
            throw std::runtime_error("unexpected HTTP handshake prefix (response status: " + status + ")");
        }
        auto mismatch = std::mismatch(received.begin(), received.end(), expected.begin());
        auto offset = static_cast<std::size_t>(mismatch.first - received.begin());
        throw std::runtime_error(
            "unexpected HTTP handshake prefix (request byte offset: " + std::to_string(offset) + ")");
    }
}

asio::awaitable<void>
write_handshake(const Socket &socket, std::string_view prefix, std::span<const std::uint8_t> body)
{
    Bytes output(prefix.begin(), prefix.end());
    output.insert(output.end(), body.begin(), body.end());
    co_await asio::async_write(*socket, asio::buffer(output), use_awaitable);
}

asio::awaitable<void>
write_record(const Socket &socket, const std::shared_ptr<Session> &session, std::span<const std::uint8_t> plaintext)
{
    auto record = session->seal(plaintext);
    if (record.size() > MaxRecord)
        throw std::runtime_error("encrypted TCP record too large");
    auto size = static_cast<std::uint32_t>(record.size());
    std::array<std::uint8_t, 4> header{ static_cast<std::uint8_t>(size >> 24),
                                        static_cast<std::uint8_t>(size >> 16),
                                        static_cast<std::uint8_t>(size >> 8),
                                        static_cast<std::uint8_t>(size) };
    std::array<asio::const_buffer, 2> buffers{ asio::buffer(header), asio::buffer(record) };
    co_await asio::async_write(*socket, buffers, use_awaitable);
}

asio::awaitable<void>
read_confirmation(const Socket &socket, const std::shared_ptr<Session> &session, std::uint8_t kind)
{
    std::array<std::uint8_t, 4> header{};
    co_await asio::async_read(*socket, asio::buffer(header), use_awaitable);
    if (load_size(header) != RecordOverhead + 1)
        throw std::runtime_error("invalid encrypted TCP confirmation length");
    Bytes record(RecordOverhead + 1);
    co_await asio::async_read(*socket, asio::buffer(record), use_awaitable);
    if (load_counter(record) != 1)
        throw std::runtime_error("invalid encrypted TCP confirmation counter");
    auto plaintext = session->open(record);
    if (plaintext != Bytes{ kind })
        throw std::runtime_error("invalid encrypted TCP confirmation kind");
}

asio::awaitable<void>
send_records(const Socket &local, const Socket &remote, const std::shared_ptr<Session> &session)
{
    Bytes buffer(32 * 1024 + 1);
    buffer[0] = DataRecord;
    std::string_view stage = "read_plain";
    try
    {
        for (;;)
        {
            stage = "read_plain";
            asio::error_code error;
            auto size = co_await local->async_read_some(
                asio::buffer(buffer.data() + 1, buffer.size() - 1), asio::redirect_error(use_awaitable, error));
            if (size != 0)
            {
                stage = "write_tunnel";
                co_await write_record(remote, session, std::span<const std::uint8_t>(buffer).first(size + 1));
            }
            if (error == asio::error::eof)
            {
                stage = "write_tunnel_fin";
                const std::array<std::uint8_t, 1> fin{ FinRecord };
                co_await write_record(remote, session, fin);
                co_return;
            }
            if (error)
            {
                stage = "read_plain";
                throw asio::system_error(error);
            }
        }
    }
    catch (...)
    {
        std::throw_with_nested(std::runtime_error("stage=" + std::string(stage)));
    }
}

asio::awaitable<void>
receive_records(const Socket &remote, const Socket &local, const std::shared_ptr<Session> &session)
{
    std::uint64_t expected = 2;
    std::string_view stage = "read_tunnel_header";
    try
    {
        for (;;)
        {
            stage = "read_tunnel_header";
            std::array<std::uint8_t, 4> header{};
            co_await asio::async_read(*remote, asio::buffer(header), use_awaitable);
            auto size = load_size(header);
            if (size < RecordOverhead + 1 || size > MaxRecord)
                throw std::runtime_error("invalid encrypted TCP record length");
            Bytes record(size);
            stage = "read_tunnel_body";
            co_await asio::async_read(*remote, asio::buffer(record), use_awaitable);
            stage = "decrypt";
            if (expected == 0 || load_counter(record) != expected)
                throw std::runtime_error("encrypted TCP record counter is not consecutive");
            auto plaintext = session->open(record);
            ++expected;
            if (plaintext[0] == DataRecord)
            {
                stage = "write_plain";
                co_await asio::async_write(
                    *local, asio::buffer(plaintext.data() + 1, plaintext.size() - 1), use_awaitable);
            }
            else if (plaintext[0] == FinRecord && plaintext.size() == 1)
            {
                stage = "shutdown_plain";
                local->shutdown(tcp::socket::shutdown_send);
                co_return;
            }
            else
            {
                throw std::runtime_error("invalid TCP record type");
            }
        }
    }
    catch (...)
    {
        std::throw_with_nested(std::runtime_error("stage=" + std::string(stage)));
    }
}

asio::awaitable<void>
bridge(const Socket &local, const Socket &remote, const std::shared_ptr<Session> &session)
{
    using namespace asio::experimental;
    auto executor = co_await asio::this_coro::executor;
    try
    {
        auto [order, outgoing, incoming] =
            co_await make_parallel_group(
                asio::co_spawn(executor, send_records(local, remote, session), asio::deferred),
                asio::co_spawn(executor, receive_records(remote, local, session), asio::deferred))
                .async_wait(wait_for_one_error(), asio::deferred);
        if (outgoing || incoming)
        {
            if (cancelled(outgoing) && cancelled(incoming))
                throw asio::system_error(asio::error::operation_aborted);
            const std::array<std::exception_ptr, 2> failures{ outgoing, incoming };
            constexpr std::array<std::string_view, 2> directions{ "plain_to_tunnel", "tunnel_to_plain" };
            std::string description = "duplex failure";
            bool first = true;
            for (auto index : order)
            {
                if (!failures[index])
                    continue;
                description += first ? " primary={" : " secondary={";
                description +=
                    "direction=" + std::string(directions[index]) + ' ' + format_stream_error(failures[index]) + '}';
                first = false;
            }
            throw std::runtime_error(description);
        }
    }
    catch (...)
    {
        close_socket(local);
        close_socket(remote);
        throw;
    }
    close_socket(local);
    close_socket(remote);
}

asio::awaitable<void>
serve_connection(Socket local, Key key, std::uint16_t listen_port)
{
    auto executor = co_await asio::this_coro::executor;
    auto started = std::chrono::steady_clock::now();
    std::string_view phase = "read_hello";
    std::uint16_t target_port = 0;
    try
    {
        Deadline handshake_deadline(executor, local);
        co_await read_prefix(local, RequestPrefix);
        Bytes hello(HelloSize);
        co_await asio::async_read(*local, asio::buffer(hello), use_awaitable);
        phase = "authenticate_hello";
        auto info = verify_client_hello(key, hello);
        if (info.mode != Stream || info.port == listen_port)
            throw std::runtime_error("invalid TCP forwarding destination");
        target_port = info.port;
        auto accepted = accept_client_hello(key, hello);
        phase = "write_challenge";
        co_await write_handshake(local, ResponsePrefix, accepted.response);
        phase = "read_client_finished";
        co_await read_confirmation(local, accepted.session, ClientFinished);
        handshake_deadline.cancel();
        auto remote = std::make_shared<tcp::socket>(executor);
        Deadline connect_deadline(executor, remote);
        phase = "connect_target";
        co_await remote->async_connect(tcp::endpoint(asio::ip::address_v4::loopback(), info.port), use_awaitable);
        connect_deadline.cancel();
        const std::array<std::uint8_t, 1> ready{ ServerReady };
        phase = "write_server_ready";
        co_await write_record(local, accepted.session, ready);
        std::osyncstream(std::cout) << "TCP connected peer=" << local->remote_endpoint() << " target=" << info.port
                                    << std::endl;
        phase = "bridge";
        co_await bridge(remote, local, accepted.session);
    }
    catch (...)
    {
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
        std::throw_with_nested(
            std::runtime_error(
                "phase=" + std::string(phase) + " target=" + std::to_string(target_port) +
                " age_ms=" + std::to_string(age.count())));
    }
}

asio::awaitable<void>
relay_connection(tcp::socket socket, std::string endpoint, Key key, std::uint16_t port)
{
    auto executor = co_await asio::this_coro::executor;
    auto local = std::make_shared<tcp::socket>(std::move(socket));
    auto remote = std::make_shared<tcp::socket>(executor);
    auto resolver = std::make_shared<tcp::resolver>(executor);
    Deadline deadline(executor, remote, resolver);
    auto started = std::chrono::steady_clock::now();
    std::string_view phase = "resolve_endpoint";
    try
    {
        auto split = endpoint.rfind(':');
        if (split == std::string::npos || split == 0 || split + 1 == endpoint.size())
            throw std::runtime_error("endpoint requires IPv4 address or hostname and port");
        auto destinations = co_await resolver->async_resolve(
            tcp::v4(), endpoint.substr(0, split), endpoint.substr(split + 1), use_awaitable);
        phase = "connect_tunnel";
        co_await asio::async_connect(*remote, destinations, use_awaitable);
        auto hello = new_client_hello(key, Stream, port);
        phase = "write_hello";
        co_await write_handshake(remote, RequestPrefix, hello);
        phase = "read_challenge";
        co_await read_prefix(remote, ResponsePrefix);
        Bytes response(ResponseSize);
        co_await asio::async_read(*remote, asio::buffer(response), use_awaitable);
        auto session = client_session(key, hello, response);
        const std::array<std::uint8_t, 1> finished{ ClientFinished };
        phase = "write_client_finished";
        co_await write_record(remote, session, finished);
        phase = "read_server_ready";
        co_await read_confirmation(remote, session, ServerReady);
        deadline.cancel();
        phase = "bridge";
        co_await bridge(local, remote, session);
    }
    catch (...)
    {
        close_socket(local);
        close_socket(remote);
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
        std::throw_with_nested(
            std::runtime_error("phase=" + std::string(phase) + " age_ms=" + std::to_string(age.count())));
    }
}

struct ServerState
{
    std::mutex mutex;
    std::unordered_set<Socket> active;

    bool add(const Socket &socket)
    {
        std::lock_guard lock(mutex);
        if (active.size() >= MaxClients)
            return false;
        active.insert(socket);
        return true;
    }

    void remove(const Socket &socket)
    {
        std::lock_guard lock(mutex);
        active.erase(socket);
    }

    void close()
    {
        std::lock_guard lock(mutex);
        for (const auto &socket : active)
            asio::dispatch(socket->get_executor(), [socket] { close_socket(socket); });
    }
};

void
report(std::exception_ptr failure, std::string_view peer)
{
    if (!failure || cancelled(failure))
        return;
    std::osyncstream(std::cerr) << "TCP session peer=" << peer << ": " << format_stream_error(failure) << '\n';
}

} // namespace

asio::awaitable<void>
serve_stream(tcp::acceptor &listener, Key key)
{
    auto state = std::make_shared<ServerState>();
    auto listen_port = listener.local_endpoint().port();
    auto &io = static_cast<asio::io_context &>(listener.get_executor().context());
    try
    {
        for (;;)
        {
            auto socket =
                std::make_shared<tcp::socket>(co_await listener.async_accept(asio::make_strand(io), use_awaitable));
            if (!state->add(socket))
            {
                close_socket(socket);
                continue;
            }
            auto executor = socket->get_executor();
            asio::error_code endpoint_error;
            auto endpoint = socket->remote_endpoint(endpoint_error);
            auto peer = endpoint_error ? std::string("unknown")
                                       : endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
            asio::co_spawn(
                executor,
                serve_connection(socket, key, listen_port),
                [state, socket, peer](std::exception_ptr failure) {
                    close_socket(socket);
                    state->remove(socket);
                    report(failure, peer);
                });
        }
    }
    catch (...)
    {
        state->close();
        throw;
    }
}

asio::awaitable<void>
relay_stream(tcp::socket local, std::string endpoint, Key key, std::uint16_t port)
{
    auto executor = co_await asio::this_coro::executor;
    auto &io = static_cast<asio::io_context &>(executor.context());
    co_await asio::co_spawn(
        asio::make_strand(io), relay_connection(std::move(local), std::move(endpoint), key, port), use_awaitable);
}

} // namespace ft
