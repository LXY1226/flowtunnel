#include "tunnel.hpp"
#include "divert.hpp"
#include "datagram_ack.hpp"
#include "packet.hpp"
#include "stream.hpp"
#include <bcrypt.h>
#include <atomic>
#include <chrono>
#include <deque>
#include <iostream>
#include <map>
#include <syncstream>
#include <thread>
#include <tuple>
#include <asio/experimental/awaitable_operators.hpp>

namespace ft {
using asio::ip::tcp;
using asio::ip::udp;
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
namespace {
constexpr uint32_t VirtualIP = 0x0ac80001;
uint32_t
random32()
{
    uint32_t value;
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&value), sizeof(value), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("random generator failed");
    return value;
}
uint16_t
be16(std::span<const uint8_t> b)
{
    return static_cast<uint16_t>((b[0] << 8) | b[1]);
}
uint64_t
be64(std::span<const uint8_t> b)
{
    uint64_t n = 0;
    for (auto v : b.first(8))
        n = (n << 8) | v;
    return n;
}
void
put16(Bytes &b, size_t offset, uint16_t n)
{
    b[offset] = static_cast<uint8_t>(n >> 8);
    b[offset + 1] = static_cast<uint8_t>(n);
}
void
put64(Bytes &b, size_t offset, uint64_t n)
{
    for (size_t i = 0; i < 8; i++)
        b[offset + 7 - i] = static_cast<uint8_t>(n >> (i * 8));
}
bool
prefix(std::span<const uint8_t> b, std::string_view s)
{
    return b.size() >= s.size() && std::equal(s.begin(), s.end(), b.begin());
}
Bytes
prefixed(std::string_view prefix, std::span<const uint8_t> body)
{
    Bytes b(prefix.begin(), prefix.end());
    b.insert(b.end(), body.begin(), body.end());
    return b;
}
std::pair<std::string, std::string>
split_address(const std::string &address)
{
    auto pos = address.rfind(':');
    if (pos == std::string::npos)
        throw std::runtime_error("address requires host:port");
    return { address.substr(0, pos), address.substr(pos + 1) };
}
struct Flow
{
    uint32_t source;
    uint16_t source_port, target_port;
    auto operator<=>(const Flow &) const = default;
};
struct Tuple
{
    uint32_t local, remote;
    uint16_t local_port, remote_port;
    auto operator<=>(const Tuple &) const = default;
};
struct Mapping
{
    Flow flow;
    uint16_t translated;
    Clock::time_point last = Clock::now();
    bool accepted = false, closed = false;
};
} // namespace

struct Runtime::Impl
{
    struct DatagramFlow;
    asio::io_context &io;
    asio::strand<asio::io_context::executor_type> strand;
    Config config;
    std::unique_ptr<Divert> capture, inject;
    tcp::acceptor listener;
    uint16_t public_port = 0;
    std::map<Flow, std::shared_ptr<Mapping>> mappings;
    std::map<uint16_t, std::shared_ptr<Mapping>> translations;
    std::map<Tuple, std::shared_ptr<DatagramFlow>> sessions;
    std::map<Flow, std::shared_ptr<DatagramFlow>> flows;
    IPReassembler fragments;
    std::thread receiver;
    std::atomic<size_t> pending_bytes{ 0 };
    std::atomic<bool> stopping{ false };
    std::atomic<bool> failed{ false };

    Impl(asio::io_context &context, Config cfg) :
        io(context), strand(asio::make_strand(context)), config(std::move(cfg)), listener(strand)
    {
    }
    ~Impl()
    {
        stopping = true;
        if (capture)
            try
            {
                capture->shutdown_recv();
            }
            catch (const std::exception &error)
            {
                std::cerr << "Shutdown: " << error.what() << std::endl;
            }
        if (receiver.joinable())
            receiver.join();
    }
    void start();
    void stop();
    void captured(Captured);
    bool fake(Packet &, const WINDIVERT_ADDRESS &);
    void application_udp(const Packet &, const WINDIVERT_ADDRESS &);
    std::shared_ptr<Mapping> mapping(Flow, bool);
    asio::awaitable<void> accept_proxy();
};

struct Runtime::Impl::DatagramFlow : std::enable_shared_from_this<DatagramFlow>
{
    Impl &owner;
    Tuple tuple{};
    Flow flow{};
    WINDIVERT_ADDRESS address{};
    bool server = false, closed = false, handshake_sent = false;
    enum Phase
    {
        Resolving,
        SynSent,
        HelloSent,
        Established,
        ServerPending
    } phase;
    uint32_t isn = random32(), seq = isn + 1, ack = 0;
    DatagramAck acknowledgments;
    uint64_t id = 0;
    size_t chunk = 1100, queued_bytes = 0;
    uint16_t target_port = 0;
    unsigned attempts = 0;
    Clock::time_point created = Clock::now(), last = created, last_datagram = created,
                      last_probe = created - 15s, last_handshake = created - 1s;
    Bytes hello, response;
    std::shared_ptr<Session> session;
    DatagramAssembler assembler;
    std::deque<Bytes> queued;
    std::map<uint64_t, size_t> probes;
    tcp::acceptor reservation;
    udp::socket target;
    udp::resolver resolver;
    asio::steady_timer timer, ack_timer;

    DatagramFlow(Impl &root, bool is_server) :
        owner(root),
        server(is_server),
        phase(is_server ? ServerPending : Resolving),
        reservation(root.strand),
        target(root.strand),
        resolver(root.strand),
        timer(root.strand),
        ack_timer(root.strand)
    {
    }
    void
    raw(std::span<const uint8_t> body, uint8_t flags, bool syn = false, std::optional<uint32_t> sequence = std::nullopt)
    {
        auto packet = tcp_packet(
            tuple.local,
            tuple.remote,
            tuple.local_port,
            tuple.remote_port,
            sequence.value_or(syn ? isn : seq),
            ack,
            flags,
            body,
            syn);
        auto out = address;
        out.Outbound = 1;
        owner.inject->send(packet, out);
        if (!syn && !sequence)
            seq += static_cast<uint32_t>(body.size());
        if ((flags & Ack) && acknowledgments.pending())
        {
            acknowledgments.sent();
            ack_timer.cancel();
        }
    }
    void handshake_record(std::span<const uint8_t> body)
    {
        raw(body, Psh | Ack, false, isn + 1);
        if (!handshake_sent)
        {
            seq = isn + 1 + static_cast<uint32_t>(body.size());
            handshake_sent = true;
        }
    }
    void acknowledge(const Packet &packet)
    {
        const auto now = Clock::now();
        const bool pending = acknowledgments.pending();
        const bool due = acknowledgments.observe(packet.seq + static_cast<uint32_t>(packet.payload().size()), now);
        ack = acknowledgments.sequence();
        if (due)
        {
            raw({}, Ack);
            return;
        }
        if (pending)
            return;
        ack_timer.expires_at(*acknowledgments.deadline());
        auto self = shared_from_this();
        ack_timer.async_wait([self](std::error_code error) {
            if (error || self->closed)
                return;
            try
            {
                if (self->acknowledgments.due(Clock::now()))
                    self->raw({}, Ack);
            }
            catch (const std::exception &error)
            {
                std::cerr << "UDP acknowledgment: " << error.what() << std::endl;
                self->close();
            }
        });
    }
    void encrypted(std::span<const uint8_t> body)
    {
        auto wire = session->seal(body);
        raw(wire, 0x18);
    }
    void close(bool notify = true)
    {
        if (closed)
            return;
        if (notify && session && !owner.stopping)
            try
            {
                encrypted(Bytes{ 3 });
            }
            catch (const std::exception &)
            {
            }
        closed = true;
        std::error_code ec;
        timer.cancel();
        ack_timer.cancel();
        resolver.cancel();
        reservation.close(ec);
        target.close(ec);
        if (auto found = owner.sessions.find(tuple); found != owner.sessions.end() && found->second.get() == this)
            owner.sessions.erase(found);
        if (auto found = owner.flows.find(flow); found != owner.flows.end() && found->second.get() == this)
            owner.flows.erase(found);
    }
    void submit(std::span<const uint8_t> data)
    {
        last_datagram = Clock::now();
        if (phase == Established)
        {
            send_datagram(data);
            return;
        }
        if (queued.size() >= 16 || queued_bytes + data.size() > 1 << 20)
            return;
        queued.emplace_back(data.begin(), data.end());
        queued_bytes += data.size();
    }
    void send_datagram(std::span<const uint8_t> data)
    {
        last_datagram = Clock::now();
        for (auto &part : split_datagram(data, ++id, chunk))
            encrypted(part);
    }
    void established()
    {
        phase = Established;
        last = Clock::now();
        std::cout << "UDP session ready source=" << flow.source_port << " target=" << flow.target_port << std::endl;
        while (!queued.empty())
        {
            auto data = std::move(queued.front());
            queued.pop_front();
            queued_bytes -= data.size();
            send_datagram(data);
        }
    }
    asio::awaitable<void> prepare()
    {
        using namespace asio::experimental::awaitable_operators;
        auto [host, port] = split_address(owner.config.address);
        asio::steady_timer deadline(owner.strand, 5s);
        auto result = co_await (
            resolver.async_resolve(udp::v4(), host, port, asio::use_awaitable) ||
            deadline.async_wait(asio::use_awaitable));
        if (result.index() != 0)
            throw std::runtime_error("UDP endpoint resolution timeout");
        if (closed)
            co_return;
        auto remote = std::get<0>(result).begin()->endpoint();
        if (remote.address().to_v4().to_uint() == VirtualIP || remote.address().is_unspecified())
            throw std::runtime_error("endpoint resolves to an invalid tunnel address");
        udp::socket route(owner.strand);
        route.open(udp::v4());
        route.connect(remote);
        auto local = route.local_endpoint().address().to_v4();
        reservation.open(tcp::v4());
        reservation.bind({ local, 0 });
        reservation.listen(1);
        tuple = {
            local.to_uint(), remote.address().to_v4().to_uint(), reservation.local_endpoint().port(), remote.port()
        };
        owner.sessions[tuple] = shared_from_this();
        hello = new_client_hello(owner.config.key, Datagram, flow.target_port);
        phase = SynSent;
        handshake();
    }
    void handshake()
    {
        if (attempts++ >= 10)
            throw std::runtime_error("Fake TCP handshake timeout");
        last_handshake = Clock::now();
        if (phase == SynSent)
            raw({}, 2, true);
        if (phase == HelloSent)
            handshake_record(prefixed(RequestPrefix, hello));
    }
    void packet(const Packet &packet)
    {
        if (closed)
            return;
        if (server && (packet.flags & 2))
        {
            raw({}, 0x12, true);
            return;
        }
        if (!server && phase == SynSent)
        {
            if ((packet.flags & 0x12) == 0x12 && packet.ack == isn + 1)
            {
                ack = packet.seq + 1;
                phase = HelloSent;
                attempts = 0;
                handshake();
            }
            return;
        }
        auto body = packet.payload();
        if (body.empty())
            return;
        if (server && prefix(body, RequestPrefix))
        {
            auto request = body.subspan(RequestPrefix.size());
            if (session)
            {
                if (!std::equal(request.begin(), request.end(), hello.begin(), hello.end()))
                    throw std::runtime_error("unexpected UDP handshake");
                handshake_record(response);
                return;
            }
            auto info = verify_client_hello(owner.config.key, request);
            if (info.mode != Datagram || info.port == owner.public_port)
                throw std::runtime_error("invalid UDP target");
            auto accepted = accept_client_hello(owner.config.key, request);
            target_port = info.port;
            hello.assign(request.begin(), request.end());
            session = std::move(accepted.session);
            response = prefixed(ResponsePrefix, accepted.response);
            ack = packet.seq + static_cast<uint32_t>(body.size());
            acknowledgments.reset(ack);
            last = Clock::now();
            handshake_record(response);
            return;
        }
        if (!server && phase == HelloSent)
        {
            if (body.size() == ResponsePrefix.size() + ResponseSize && prefix(body, ResponsePrefix))
            {
                session = client_session(owner.config.key, hello, body.subspan(ResponsePrefix.size()));
                ack = packet.seq + static_cast<uint32_t>(body.size());
                acknowledgments.reset(ack);
                established();
            }
            return;
        }
        if (!session || (!server && prefix(body, ResponsePrefix)))
            return;
        Bytes plain;
        try
        {
            plain = session->open(body);
        }
        catch (const ReplayError &)
        {
            acknowledge(packet);
            return;
        }
        if (plain.empty())
            throw std::runtime_error("empty UDP record");
        phase = Established;
        last = Clock::now();
        acknowledge(packet);
        switch (plain[0])
        {
        case 1: {
            auto data = assembler.add(plain);
            if (data)
            {
                last_datagram = Clock::now();
                if (server)
                {
                    if (!target.is_open())
                    {
                        target.open(udp::v4());
                        target.connect({ asio::ip::address_v4::loopback(), target_port });
                        std::cout << "UDP connected peer=" << asio::ip::address_v4(tuple.remote) << ':'
                                  << tuple.remote_port << " target=" << target_port
                                  << " target_local_port=" << target.local_endpoint().port() << std::endl;
                        auto self = shared_from_this();
                        asio::co_spawn(owner.strand, read_target(), [self](std::exception_ptr error) {
                            if (error && !self->closed)
                                self->close();
                        });
                    }
                    auto held = std::make_shared<Bytes>(std::move(*data));
                    auto self = shared_from_this();
                    target.async_send(asio::buffer(*held), [self, held](std::error_code error, size_t) {
                        if (error && !self->closed)
                            self->close();
                    });
                }
                else
                {
                    auto out = address;
                    out.Outbound = 0;
                    auto reply = udp_packet(VirtualIP, flow.source, flow.target_port, flow.source_port, *data);
                    owner.capture->send(reply, out);
                }
            }
            break;
        }
        case 2:
            if (plain.size() != 1)
                throw std::runtime_error("invalid keepalive");
            break;
        case 3:
            if (plain.size() != 1)
                throw std::runtime_error("invalid UDP close");
            close(false);
            break;
        case 4: {
            if (plain.size() < 11 || plain.size() + 64 != be16(std::span(plain).subspan(9)))
                throw std::runtime_error("invalid MTU probe");
            Bytes reply{ 5 };
            reply.insert(reply.end(), plain.begin() + 1, plain.begin() + 9);
            encrypted(reply);
            break;
        }
        case 5: {
            if (plain.size() != 9)
                throw std::runtime_error("invalid MTU acknowledgment");
            auto token = be64(std::span(plain).subspan(1));
            if (auto p = probes.find(token); p != probes.end())
            {
                chunk = std::max(chunk, p->second - 77);
                probes.erase(p);
            }
            break;
        }
        default:
            throw std::runtime_error("unknown UDP record");
        }
    }
    asio::awaitable<void> read_target()
    {
        Bytes buffer(65507);
        while (!closed)
        {
            auto n = co_await target.async_receive(asio::buffer(buffer), asio::use_awaitable);
            send_datagram(std::span(buffer).first(n));
        }
    }
    void probe(size_t size)
    {
        Bytes body(size - 64);
        body[0] = 4;
        put64(body, 1, ++id);
        put16(body, 9, static_cast<uint16_t>(size));
        probes[id] = size;
        encrypted(body);
    }
    asio::awaitable<void> tick()
    {
        while (!closed)
        {
            timer.expires_after(500ms);
            co_await timer.async_wait(asio::use_awaitable);
            if (closed)
                co_return;
            auto now = Clock::now();
            const char *reason = nullptr;
            if (phase == ServerPending && now - created > 5s)
                reason = "handshake_timeout";
            else if (now - last > 2min)
                reason = "peer_timeout";
            else if (now - last_datagram > 2min)
                reason = "application_idle";
            if (reason)
            {
                std::cout << "UDP expired peer=" << asio::ip::address_v4(tuple.remote) << ':' << tuple.remote_port
                          << " target=" << (server ? target_port : flow.target_port)
                          << " age_ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(now - created).count()
                          << " idle_ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(now - last_datagram).count()
                          << " reason=" << reason << std::endl;
                close();
                co_return;
            }
            if ((phase == SynSent || phase == HelloSent) && now - last_handshake >= 500ms)
                handshake();
            if (phase == Established && now - last_probe >= 15s)
            {
                last_probe = now;
                chunk = 1100;
                probes.clear();
                encrypted(Bytes{ 2 });
                probe(1400);
                probe(1500);
            }
        }
    }
    void start()
    {
        auto self = shared_from_this();
        auto done = [self](std::exception_ptr error) {
            if (error && !self->closed)
            {
                try
                {
                    std::rethrow_exception(error);
                }
                catch (const std::exception &e)
                {
                    std::cerr << "UDP session: " << e.what() << std::endl;
                }
                self->close();
            }
        };
        asio::co_spawn(owner.strand, tick(), done);
        if (!server)
            asio::co_spawn(owner.strand, prepare(), done);
    }
};

void
Runtime::Impl::start()
{
    auto [host, port_text] = split_address(config.address);
    public_port = static_cast<uint16_t>(std::stoi(port_text));
    listener.open(tcp::v4());
    listener.bind(
        { config.server ? asio::ip::make_address_v4(host) : asio::ip::address_v4::any(),
          config.server ? public_port : uint16_t(0) });
    listener.listen();
    std::string filter;
    if (config.server)
        filter = "ip and tcp and (tcp.DstPort == " + port_text + " or tcp.SrcPort == " + port_text + ")";
    else
    {
        auto private_port = std::to_string(listener.local_endpoint().port());
        filter =
            "ip and ((outbound and ip.DstAddr == 10.200.0.1) or (tcp and outbound and tcp.SrcPort == " + private_port +
            ") or (tcp and (tcp.SrcPort == " + port_text + " or (tcp.DstPort == " + port_text + " and tcp.Rst))))";
    }
    capture = std::make_unique<Divert>(filter, static_cast<int16_t>(config.server ? 200 : 100));
    inject = std::make_unique<Divert>("false", int16_t(30000), true);
    if (config.server)
        asio::co_spawn(strand, serve_stream(listener, config.key), [this](std::exception_ptr error) {
            if (error && !stopping)
            {
                failed = true;
                try
                {
                    std::rethrow_exception(error);
                }
                catch (const std::exception &e)
                {
                    std::cerr << "TCP server: " << e.what() << std::endl;
                }
            }
            stop();
        });
    else
        asio::co_spawn(strand, accept_proxy(), [this](std::exception_ptr error) {
            if (error && !stopping)
            {
                failed = true;
                stop();
            }
        });
    receiver = std::thread([this] {
        try
        {
            Bytes buffer(65535);
            while (!stopping)
            {
                auto event = capture->recv(buffer);
                auto n = event.bytes.size();
                if (pending_bytes.fetch_add(n) + n > 8 << 20)
                {
                    pending_bytes.fetch_sub(n);
                    continue;
                }
                asio::post(strand, [this, event = std::move(event), n]() mutable {
                    pending_bytes.fetch_sub(n);
                    if (stopping)
                        return;
                    try
                    {
                        captured(std::move(event));
                    }
                    catch (const std::system_error &error)
                    {
                        failed = true;
                        std::cerr << "Network I/O: " << error.what() << std::endl;
                        stop();
                    }
                    catch (const std::exception &e)
                    {
                        std::cerr << "Packet rejected: " << e.what() << std::endl;
                    }
                });
            }
        }
        catch (const std::exception &e)
        {
            if (!stopping)
            {
                failed = true;
                std::cerr << "WinDivert receive: " << e.what() << std::endl;
                stop();
            }
        }
    });
    std::cout << (config.server ? "server" : "client") << " ready address=" << config.address
              << " virtual_ip=10.200.0.1" << std::endl;
}

void
Runtime::Impl::stop()
{
    if (stopping.exchange(true))
        return;
    if (capture)
        try
        {
            capture->shutdown_recv();
        }
        catch (const std::exception &error)
        {
            failed = true;
            std::cerr << "Shutdown: " << error.what() << std::endl;
        }
    asio::post(strand, [this] {
        std::error_code error;
        listener.close(error);
        auto active = sessions;
        for (auto &[key, f] : active)
            f->close(false);
        auto pending = flows;
        for (auto &[key, f] : pending)
            f->close(false);
        io.stop();
    });
}

bool
Runtime::Impl::fake(Packet &p, const WINDIVERT_ADDRESS &address)
{
    if (p.protocol != 6 || p.fragment)
        return false;
    std::shared_ptr<DatagramFlow> f;
    if (config.server)
    {
        auto local = listener.local_endpoint().address().to_v4().to_uint();
        if (p.dst_port == public_port && (local == 0 || p.dst == local))
        {
            Tuple key{ p.dst, p.src, p.dst_port, p.src_port };
            if (auto entry = sessions.find(key); entry != sessions.end())
                f = entry->second;
            if (!f && (p.flags & 2) && !(p.flags & 16) && p.has_marker())
            {
                if (sessions.size() >= 256)
                    return true;
                f = std::make_shared<DatagramFlow>(*this, true);
                f->tuple = key;
                f->address = address;
                f->ack = p.seq + 1;
                sessions[key] = f;
                f->start();
            }
        }
        else if (p.src_port == public_port && (p.flags & 4))
            return sessions.contains(Tuple{ p.src, p.dst, p.src_port, p.dst_port });
    }
    else
    {
        if (p.src_port == public_port)
        {
            if (auto entry = sessions.find(Tuple{ p.dst, p.src, p.dst_port, p.src_port }); entry != sessions.end())
                f = entry->second;
        }
        if (p.dst_port == public_port && (p.flags & 4))
            return sessions.contains(Tuple{ p.src, p.dst, p.src_port, p.dst_port });
    }
    if (!f)
        return false;
    if (p.flags & 4 || p.payload().size() > 1460)
        return true;
    try
    {
        f->packet(p);
    }
    catch (const std::system_error &)
    {
        throw;
    }
    catch (const std::exception &e)
    {
        std::cerr << "UDP packet rejected: " << e.what() << std::endl;
    }
    return true;
}

void
Runtime::Impl::application_udp(const Packet &p, const WINDIVERT_ADDRESS &address)
{
    Flow key{ p.src, p.src_port, p.dst_port };
    auto found = flows.find(key);
    std::shared_ptr<DatagramFlow> f;
    if (found != flows.end())
        f = found->second;
    if (!f)
    {
        if (flows.size() >= 256)
            return;
        f = std::make_shared<DatagramFlow>(*this, false);
        f->flow = key;
        f->address = address;
        flows[key] = f;
        f->start();
    }
    f->submit(p.payload());
}

std::shared_ptr<Mapping>
Runtime::Impl::mapping(Flow flow, bool syn)
{
    auto now = Clock::now();
    for (auto i = mappings.begin(); i != mappings.end();)
    {
        auto m = i->second;
        if ((m->closed && now - m->last > 30s) || (!m->accepted && now - m->last > 10s))
        {
            translations.erase(m->translated);
            i = mappings.erase(i);
        }
        else
            ++i;
    }
    if (auto entry = mappings.find(flow); entry != mappings.end())
    {
        auto m = entry->second;
        if (!(syn && m->closed))
        {
            m->last = now;
            return m;
        }
        translations.erase(m->translated);
        mappings.erase(entry);
    }
    if (!syn || mappings.size() >= 1024)
        return {};
    uint16_t translated;
    do
    {
        translated = static_cast<uint16_t>(1024 + random32() % 64511);
    } while (translations.contains(translated));
    auto m = std::make_shared<Mapping>();
    m->flow = flow;
    m->translated = translated;
    mappings[flow] = m;
    translations[translated] = m;
    return m;
}

void
Runtime::Impl::captured(Captured event)
{
    auto p = Packet::parse(std::move(event.bytes));
    auto address = event.address;
    if (fake(p, address))
        return;
    if (config.server)
    {
        capture->send(p.bytes, address);
        return;
    }
    const auto private_port = listener.local_endpoint().port();
    if (address.Outbound && p.dst == VirtualIP && !(p.protocol == 6 && p.src_port == private_port))
    {
        if (p.fragment)
        {
            auto complete = fragments.add(p);
            if (!complete)
                return;
            p = Packet::parse(std::move(*complete));
        }
        if (p.protocol == 6)
        {
            auto m = mapping({ p.src, p.src_port, p.dst_port }, (p.flags & 2) != 0);
            if (!m)
                return;
            put16(p.bytes, p.ip_len, m->translated);
            p.reflect(private_port, false);
            address.Outbound = 0;
            capture->send(p.bytes, address);
        }
        if (p.protocol == 17)
            application_udp(p, address);
        return;
    }
    if (address.Outbound && p.protocol == 6 && p.src_port == private_port)
    {
        auto entry = translations.find(p.dst_port);
        if (entry == translations.end())
            return;
        auto m = entry->second;
        m->last = Clock::now();
        put16(p.bytes, p.ip_len + 2, m->flow.source_port);
        p.reflect(m->flow.target_port, true);
        address.Outbound = 0;
        capture->send(p.bytes, address);
        return;
    }
    capture->send(p.bytes, address);
}

asio::awaitable<void>
Runtime::Impl::accept_proxy()
{
    while (!stopping)
    {
        auto local = co_await listener.async_accept(asio::use_awaitable);
        auto remote = local.remote_endpoint();
        auto entry = translations.find(remote.port());
        if (remote.address().to_v4().to_uint() != VirtualIP || entry == translations.end())
        {
            local.close();
            continue;
        }
        auto m = entry->second;
        m->accepted = true;
        asio::co_spawn(
            asio::make_strand(io),
            relay_stream(std::move(local), config.address, config.key, m->flow.target_port),
            [this, m](std::exception_ptr error) {
                if (error && !stopping)
                {
                    std::osyncstream(std::cerr) << "TCP relay source=" << asio::ip::address_v4(m->flow.source)
                                               << ':' << m->flow.source_port << " target=" << m->flow.target_port
                                               << ": " << format_stream_error(error) << std::endl;
                }
                asio::post(strand, [m] {
                    m->closed = true;
                    m->last = Clock::now();
                });
            });
    }
}

Runtime::Runtime(asio::io_context &io, Config config) : impl_(std::make_unique<Impl>(io, std::move(config))) {}
Runtime::~Runtime() = default;
void
Runtime::start()
{
    impl_->start();
}
void
Runtime::stop()
{
    impl_->stop();
}
bool
Runtime::failed() const
{
    return impl_->failed.load();
}
} // namespace ft
