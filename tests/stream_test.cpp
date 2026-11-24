#include "stream.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <exception>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using asio::use_awaitable;
using asio::ip::tcp;
using Acceptor = std::shared_ptr<tcp::acceptor>;

void
require(bool condition, const char *message)
{
    if (!condition)
        throw std::runtime_error(message);
}

ft::Key
test_key(std::uint8_t value)
{
    ft::Key key{};
    key.fill(value);
    return key;
}

class Fixture
{
public:
    asio::io_context io;

private:
    asio::executor_work_guard<asio::io_context::executor_type> work_;
    std::vector<std::thread> workers_;

public:
    Fixture() : work_(asio::make_work_guard(io))
    {
        for (int i = 0; i < 2; ++i)
            workers_.emplace_back([this] { io.run(); });
    }
    ~Fixture()
    {
        io.stop();
        for (auto &worker : workers_)
            worker.join();
    }
    Acceptor listener()
    {
        return std::make_shared<tcp::acceptor>(
            asio::make_strand(io), tcp::endpoint(asio::ip::address_v4::loopback(), 0));
    }
};

template <class T>
T
result(std::future<T> &future)
{
    if (future.wait_for(std::chrono::seconds(10)) != std::future_status::ready)
        throw std::runtime_error("native TCP test timed out");
    return future.get();
}

asio::awaitable<void>
keep_server(Acceptor listener, ft::Key key)
{
    co_await ft::serve_stream(*listener, key);
}

asio::awaitable<void>
echo(tcp::socket socket)
{
    ft::Bytes received;
    std::array<std::uint8_t, 16384> buffer{};
    for (;;)
    {
        asio::error_code error;
        auto size = co_await socket.async_read_some(asio::buffer(buffer), asio::redirect_error(use_awaitable, error));
        received.insert(received.end(), buffer.begin(), buffer.begin() + size);
        if (error == asio::error::eof)
            break;
        if (error)
            throw asio::system_error(error);
    }
    co_await asio::async_write(socket, asio::buffer(received), use_awaitable);
    socket.shutdown(tcp::socket::shutdown_send);
}

asio::awaitable<void>
echo_accepts(
    Acceptor listener,
    std::size_t count,
    std::shared_ptr<std::atomic<std::size_t>> completed,
    std::shared_ptr<std::promise<void>> finished)
{
    for (std::size_t i = 0; i < count; ++i)
    {
        auto socket = co_await listener->async_accept(asio::make_strand(listener->get_executor()), use_awaitable);
        auto executor = socket.get_executor();
        asio::co_spawn(executor, echo(std::move(socket)), [completed, finished, count](std::exception_ptr) {
            if (++*completed == count)
                finished->set_value();
        });
    }
}

asio::awaitable<void>
relay_accepts(Acceptor listener, std::string endpoint, ft::Key key, std::uint16_t port, std::size_t count)
{
    for (std::size_t i = 0; i < count; ++i)
    {
        tcp::socket socket =
            co_await listener->async_accept(asio::make_strand(listener->get_executor()), use_awaitable);
        auto executor = socket.get_executor();
        asio::co_spawn(executor, ft::relay_stream(std::move(socket), endpoint, key, port), [](std::exception_ptr) {});
    }
}

asio::awaitable<void>
relay_one(Acceptor listener, std::string endpoint, ft::Key key, std::uint16_t port)
{
    tcp::socket socket = co_await listener->async_accept(use_awaitable);
    co_await ft::relay_stream(std::move(socket), std::move(endpoint), key, port);
}

asio::awaitable<ft::Bytes>
application(tcp::endpoint endpoint, ft::Bytes payload)
{
    tcp::socket socket(co_await asio::this_coro::executor);
    co_await socket.async_connect(endpoint, use_awaitable);
    co_await asio::async_write(socket, asio::buffer(payload), use_awaitable);
    socket.shutdown(tcp::socket::shutdown_send);
    ft::Bytes received;
    std::array<std::uint8_t, 16384> buffer{};
    for (;;)
    {
        asio::error_code error;
        auto size = co_await socket.async_read_some(asio::buffer(buffer), asio::redirect_error(use_awaitable, error));
        received.insert(received.end(), buffer.begin(), buffer.begin() + size);
        if (error == asio::error::eof)
            co_return received;
        if (error)
            throw asio::system_error(error);
    }
}

void
concurrent_half_close()
{
    Fixture fixture;
    auto target = fixture.listener();
    auto server = fixture.listener();
    auto proxy = fixture.listener();
    auto key = test_key(0x43);
    auto server_task = asio::co_spawn(server->get_executor(), keep_server(server, key), asio::use_future);
    auto completed = std::make_shared<std::atomic<std::size_t>>(0);
    auto finished = std::make_shared<std::promise<void>>();
    auto targets_done = finished->get_future();
    constexpr std::size_t count = 8;
    auto targets =
        asio::co_spawn(target->get_executor(), echo_accepts(target, count, completed, finished), asio::use_future);
    std::string endpoint = "127.0.0.1:" + std::to_string(server->local_endpoint().port());
    auto relays = asio::co_spawn(
        proxy->get_executor(),
        relay_accepts(proxy, endpoint, key, target->local_endpoint().port(), count),
        asio::use_future);
    std::vector<std::future<ft::Bytes>> clients;
    for (std::size_t i = 0; i < count; ++i)
    {
        ft::Bytes payload(256 * 1024, static_cast<std::uint8_t>(i + 1));
        clients.push_back(
            asio::co_spawn(
                asio::make_strand(fixture.io),
                application(proxy->local_endpoint(), std::move(payload)),
                asio::use_future));
    }
    for (std::size_t i = 0; i < count; ++i)
    {
        auto received = result(clients[i]);
        require(
            received == ft::Bytes(256 * 1024, static_cast<std::uint8_t>(i + 1)),
            "native concurrent TCP stream or half-close corrupted application bytes");
    }
    result(targets);
    result(relays);
    result(targets_done);
    require(completed->load() == count, "native TCP targets did not complete their half-close replies");
}

asio::awaitable<void>
detect_contact(Acceptor listener, std::shared_ptr<std::atomic<bool>> contacted)
{
    auto socket = co_await listener->async_accept(use_awaitable);
    contacted->store(true);
}

asio::awaitable<void>
delay()
{
    asio::steady_timer timer(co_await asio::this_coro::executor, std::chrono::milliseconds(100));
    co_await timer.async_wait(use_awaitable);
}

void
unauthenticated_client_cannot_reach_target()
{
    Fixture fixture;
    auto target = fixture.listener();
    auto server = fixture.listener();
    auto proxy = fixture.listener();
    auto contacted = std::make_shared<std::atomic<bool>>(false);
    auto target_task = asio::co_spawn(target->get_executor(), detect_contact(target, contacted), asio::use_future);
    auto server_task = asio::co_spawn(server->get_executor(), keep_server(server, test_key(0x13)), asio::use_future);
    std::string endpoint = "127.0.0.1:" + std::to_string(server->local_endpoint().port());
    auto relay = asio::co_spawn(
        proxy->get_executor(),
        relay_one(proxy, endpoint, test_key(0x14), target->local_endpoint().port()),
        asio::use_future);
    auto client =
        asio::co_spawn(asio::make_strand(fixture.io), application(proxy->local_endpoint(), {}), asio::use_future);
    bool rejected = false;
    try
    {
        result(relay);
    }
    catch (const std::exception &)
    {
        rejected = true;
    }
    require(rejected, "native TCP server accepted a wrong PSK");
    auto received = result(client);
    require(received.empty(), "unauthenticated application received target data");
    auto settled = asio::co_spawn(fixture.io, delay(), asio::use_future);
    result(settled);
    require(!contacted->load(), "unauthenticated TCP client reached the target service");
}

std::uint32_t
record_size(const std::array<std::uint8_t, 4> &header)
{
    std::uint32_t size{};
    for (auto value : header)
        size = (size << 8) | value;
    return size;
}

void
append_frame(ft::Bytes &output, const ft::Bytes &record)
{
    auto size = static_cast<std::uint32_t>(record.size());
    output.push_back(static_cast<std::uint8_t>(size >> 24));
    output.push_back(static_cast<std::uint8_t>(size >> 16));
    output.push_back(static_cast<std::uint8_t>(size >> 8));
    output.push_back(static_cast<std::uint8_t>(size));
    output.insert(output.end(), record.begin(), record.end());
}

asio::awaitable<void>
read_control(
    tcp::socket &socket,
    const std::shared_ptr<ft::Session> &session,
    std::uint8_t kind,
    std::uint64_t expected)
{
    std::array<std::uint8_t, 4> header{};
    co_await asio::async_read(socket, asio::buffer(header), use_awaitable);
    require(record_size(header) == ft::RecordOverhead + 1, "invalid encrypted control record in native stream test");
    ft::Bytes record(ft::RecordOverhead + 1);
    co_await asio::async_read(socket, asio::buffer(record), use_awaitable);
    std::uint64_t counter{};
    for (std::size_t i = 0; i < 8; ++i)
        counter = (counter << 8) | record[i];
    require(counter == expected, "incorrect encrypted control counter in native stream test");
    require(session->open(record) == ft::Bytes{ kind }, "incorrect encrypted control kind in native stream test");
}

asio::awaitable<ft::Bytes>
replay_hello(tcp::endpoint endpoint, ft::Bytes hello, ft::Bytes finish)
{
    tcp::socket socket(co_await asio::this_coro::executor);
    co_await socket.async_connect(endpoint, use_awaitable);
    ft::Bytes request(ft::RequestPrefix.begin(), ft::RequestPrefix.end());
    request.insert(request.end(), hello.begin(), hello.end());
    co_await asio::async_write(socket, asio::buffer(request), use_awaitable);
    std::string prefix(ft::ResponsePrefix.size(), '\0');
    co_await asio::async_read(socket, asio::buffer(prefix), use_awaitable);
    require(prefix == ft::ResponsePrefix, "replayed hello did not receive a server challenge");
    ft::Bytes response(ft::ResponseSize);
    co_await asio::async_read(socket, asio::buffer(response), use_awaitable);
    if (!finish.empty())
    {
        ft::Bytes framed;
        append_frame(framed, finish);
        co_await asio::async_write(socket, asio::buffer(framed), use_awaitable);
    }
    std::array<std::uint8_t, 1> extra{};
    asio::error_code error;
    auto size = co_await socket.async_read_some(asio::buffer(extra), asio::redirect_error(use_awaitable, error));
    require(
        size == 0 && (error == asio::error::eof || error == asio::error::connection_reset),
        "unconfirmed replayed hello was not closed");
    co_return response;
}

void
replayed_hello_cannot_reach_target()
{
    Fixture fixture;
    auto target = fixture.listener();
    auto server = fixture.listener();
    auto key = test_key(0x36);
    auto contacted = std::make_shared<std::atomic<bool>>(false);
    auto target_task = asio::co_spawn(target->get_executor(), detect_contact(target, contacted), asio::use_future);
    auto server_task = asio::co_spawn(server->get_executor(), keep_server(server, key), asio::use_future);
    auto hello = ft::new_client_hello(key, ft::Stream, target->local_endpoint().port());
    auto first = asio::co_spawn(
        asio::make_strand(fixture.io), replay_hello(server->local_endpoint(), hello, {}), asio::use_future);
    auto challenge = result(first);
    require(!contacted->load(), "replayed hello reached the target without proving its new session key");
    auto old_session = ft::client_session(key, hello, challenge);
    auto stale_finish = old_session->seal(ft::Bytes{ 3 });
    auto repeated = asio::co_spawn(
        asio::make_strand(fixture.io),
        replay_hello(server->local_endpoint(), hello, std::move(stale_finish)),
        asio::use_future);
    auto next_challenge = result(repeated);
    require(next_challenge != challenge, "replayed hello reused the server session challenge");
    auto settled = asio::co_spawn(fixture.io, delay(), asio::use_future);
    result(settled);
    require(!contacted->load(), "old client Finished record reached the target under a new challenge");
}

asio::awaitable<void>
reordered_server(Acceptor listener, ft::Key key)
{
    auto socket = co_await listener->async_accept(use_awaitable);
    ft::Bytes request(ft::RequestPrefix.size() + ft::HelloSize);
    co_await asio::async_read(socket, asio::buffer(request), use_awaitable);
    auto accepted =
        ft::accept_client_hello(key, std::span<const std::uint8_t>(request).subspan(ft::RequestPrefix.size()));
    ft::Bytes response(ft::ResponsePrefix.begin(), ft::ResponsePrefix.end());
    response.insert(response.end(), accepted.response.begin(), accepted.response.end());
    co_await asio::async_write(socket, asio::buffer(response), use_awaitable);
    co_await read_control(socket, accepted.session, 3, 1);
    ft::Bytes ready;
    append_frame(ready, accepted.session->seal(ft::Bytes{ 4 }));
    co_await asio::async_write(socket, asio::buffer(ready), use_awaitable);
    co_await read_control(socket, accepted.session, 2, 2);
    const auto first = accepted.session->seal(ft::Bytes{ 1, 'f', 'i', 'r', 's', 't' });
    const auto second = accepted.session->seal(ft::Bytes{ 1, 's', 'e', 'c', 'o', 'n', 'd' });
    ft::Bytes output;
    append_frame(output, second);
    append_frame(output, first);
    co_await asio::async_write(socket, asio::buffer(output), use_awaitable);
    socket.shutdown(tcp::socket::shutdown_send);
}

void
authenticated_records_cannot_be_reordered()
{
    Fixture fixture;
    auto server = fixture.listener();
    auto proxy = fixture.listener();
    auto key = test_key(0x27);
    auto mock = asio::co_spawn(server->get_executor(), reordered_server(server, key), asio::use_future);
    std::string endpoint = "127.0.0.1:" + std::to_string(server->local_endpoint().port());
    auto relay = asio::co_spawn(proxy->get_executor(), relay_one(proxy, endpoint, key, 443), asio::use_future);
    auto client =
        asio::co_spawn(asio::make_strand(fixture.io), application(proxy->local_endpoint(), {}), asio::use_future);
    bool rejected = false;
    try
    {
        result(relay);
    }
    catch (...)
    {
        rejected = ft::format_stream_error(std::current_exception()).find("counter is not consecutive") != std::string::npos;
    }
    require(rejected, "native TCP relay accepted exchanged authenticated records");
    require(result(client).empty(), "reordered authenticated stream bytes reached the application");
    result(mock);
}

asio::awaitable<void>
read_data_frame(tcp::socket &socket, const std::shared_ptr<ft::Session> &session,
                ft::Bytes payload, std::uint64_t expected_counter)
{
    std::array<std::uint8_t, 4> header{};
    co_await asio::async_read(socket, asio::buffer(header), use_awaitable);
    require(record_size(header) == ft::RecordOverhead + payload.size() + 1,
            "incorrect data record length in native stream fault fixture");
    ft::Bytes record(record_size(header));
    co_await asio::async_read(socket, asio::buffer(record), use_awaitable);
    std::uint64_t counter{};
    for (std::size_t i = 0; i < 8; ++i)
        counter = (counter << 8) | record[i];
    require(counter == expected_counter, "incorrect data counter in native stream fault fixture");
    payload.insert(payload.begin(), 1);
    require(session->open(record) == payload, "native stream fault fixture received incorrect application data");
}

asio::awaitable<void>
held_application(tcp::endpoint endpoint)
{
    tcp::socket socket(co_await asio::this_coro::executor);
    co_await socket.async_connect(endpoint, use_awaitable);
    const std::array<std::uint8_t, 5> probe{ 'p', 'r', 'o', 'b', 'e' };
    co_await asio::async_write(socket, asio::buffer(probe), use_awaitable);
    std::array<std::uint8_t, 2> reply{};
    co_await asio::async_read(socket, asio::buffer(reply), use_awaitable);
    require(reply == std::array<std::uint8_t, 2>{ 'o', 'k' }, "fault fixture did not complete a bidirectional exchange");
    const std::array<std::uint8_t, 4> waiting{ 'w', 'a', 'i', 't' };
    co_await asio::async_write(socket, asio::buffer(waiting), use_awaitable);
    std::array<std::uint8_t, 1> extra{};
    asio::error_code error;
    auto size = co_await socket.async_read_some(asio::buffer(extra), asio::redirect_error(use_awaitable, error));
    require(size == 0 && (error == asio::error::eof || error == asio::error::connection_reset),
            "faulted relay did not close the held application connection");
}

asio::awaitable<void>
faulting_server(Acceptor listener, ft::Key key, bool reset)
{
    auto socket = co_await listener->async_accept(use_awaitable);
    ft::Bytes request(ft::RequestPrefix.size() + ft::HelloSize);
    co_await asio::async_read(socket, asio::buffer(request), use_awaitable);
    auto accepted =
        ft::accept_client_hello(key, std::span<const std::uint8_t>(request).subspan(ft::RequestPrefix.size()));
    ft::Bytes response(ft::ResponsePrefix.begin(), ft::ResponsePrefix.end());
    response.insert(response.end(), accepted.response.begin(), accepted.response.end());
    co_await asio::async_write(socket, asio::buffer(response), use_awaitable);
    co_await read_control(socket, accepted.session, 3, 1);
    ft::Bytes ready;
    append_frame(ready, accepted.session->seal(ft::Bytes{ 4 }));
    co_await asio::async_write(socket, asio::buffer(ready), use_awaitable);
    co_await read_data_frame(socket, accepted.session, ft::Bytes{ 'p', 'r', 'o', 'b', 'e' }, 2);
    ft::Bytes reply;
    append_frame(reply, accepted.session->seal(ft::Bytes{ 1, 'o', 'k' }));
    co_await asio::async_write(socket, asio::buffer(reply), use_awaitable);
    co_await read_data_frame(socket, accepted.session, ft::Bytes{ 'w', 'a', 'i', 't' }, 3);
    asio::steady_timer settled(co_await asio::this_coro::executor, std::chrono::milliseconds(20));
    co_await settled.async_wait(use_awaitable);
    if (reset)
    {
        socket.set_option(asio::socket_base::linger(true, 0));
        socket.close();
        co_return;
    }
    ft::Bytes truncated;
    append_frame(truncated, accepted.session->seal(ft::Bytes{ 1, 'x' }));
    truncated.resize(7);
    co_await asio::async_write(socket, asio::buffer(truncated), use_awaitable);
    socket.shutdown(tcp::socket::shutdown_send);
}

std::string
code_description(asio::error_code error)
{
    return "code=" + std::string(error.category().name()) + ':' + std::to_string(error.value());
}

void
socket_fault_retains_stage_and_both_directions(bool reset)
{
    Fixture fixture;
    auto server = fixture.listener();
    auto proxy = fixture.listener();
    auto key = test_key(0x52);
    auto mock = asio::co_spawn(server->get_executor(), faulting_server(server, key, reset), asio::use_future);
    std::string endpoint = "127.0.0.1:" + std::to_string(server->local_endpoint().port());
    auto relay = asio::co_spawn(proxy->get_executor(), relay_one(proxy, endpoint, key, 443), asio::use_future);
    auto client = asio::co_spawn(asio::make_strand(fixture.io), held_application(proxy->local_endpoint()), asio::use_future);
    std::string description;
    try
    {
        result(relay);
    }
    catch (...)
    {
        description = ft::format_stream_error(std::current_exception());
    }
    require(!description.empty(), "native relay completed successfully after a forced socket fault");
    require(description.find("multiple exceptions") == std::string::npos &&
            description.find("multiple_exceptions") == std::string::npos,
            "native relay discarded the socket fault behind a multiple-exception message");
    const auto primary_position = description.find("primary={");
    const auto secondary_position = description.find("secondary={");
    require(primary_position != std::string::npos, "native relay did not label its primary failure");
    require(secondary_position != std::string::npos, "native relay did not retain the cancelled pending plain read");
    const auto primary = description.substr(primary_position, secondary_position - primary_position);
    const auto secondary = description.substr(secondary_position);
    require(primary.find("direction=tunnel_to_plain") != std::string::npos,
            "native relay lost the primary socket direction");
    require(primary.find(reset ? "stage=read_tunnel_header" : "stage=read_tunnel_body") != std::string::npos,
            "native relay lost the exact failed read stage");
    const asio::error_code expected = reset ? asio::error_code(asio::error::connection_reset)
                                            : asio::error_code(asio::error::eof);
    require(primary.find(code_description(expected)) != std::string::npos,
            "native relay lost the original socket error category or numeric code");
    require(secondary.find("direction=plain_to_tunnel") != std::string::npos &&
            secondary.find("stage=read_plain") != std::string::npos &&
            secondary.find(code_description(asio::error_code(asio::error::operation_aborted))) != std::string::npos,
            "native relay lost the cancelled secondary read and its native error code");
    result(client);
    result(mock);
}

} // namespace

void
test_stream()
{
    concurrent_half_close();
    unauthenticated_client_cannot_reach_target();
    replayed_hello_cannot_reach_target();
    authenticated_records_cannot_be_reordered();
    socket_fault_retains_stage_and_both_directions(true);
    socket_fault_retains_stage_and_both_directions(false);
}
