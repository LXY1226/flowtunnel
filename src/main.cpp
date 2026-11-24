#include "tunnel.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <toml++/toml.hpp>
#include <algorithm>
#include <charconv>
#include <iostream>
#include <thread>

namespace {
HANDLE stop_event = nullptr;
BOOL WINAPI
console_handler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT || type == CTRL_SHUTDOWN_EVENT)
    {
        SetEvent(stop_event);
        return TRUE;
    }
    return FALSE;
}
std::string
base64(const ft::Key &key)
{
    DWORD n = 0;
    if (!CryptBinaryToStringA(
            key.data(), static_cast<DWORD>(key.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &n))
        throw std::runtime_error("Base64 encoding failed");
    std::string text(n, '\0');
    if (!CryptBinaryToStringA(
            key.data(), static_cast<DWORD>(key.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, text.data(), &n))
        throw std::runtime_error("Base64 encoding failed");
    text.resize(n);
    return text;
}
ft::Key
decode_key(const std::string &text)
{
    ft::Key key{};
    DWORD n = static_cast<DWORD>(key.size());
    if (text.size() != 44 ||
        !CryptStringToBinaryA(
            text.c_str(),
            static_cast<DWORD>(text.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
            key.data(),
            &n,
            nullptr,
            nullptr) ||
        n != key.size() || base64(key) != text)
        throw std::runtime_error("key requires Base64 encoding of 32 random bytes");
    return key;
}
ft::Config
configuration(const char *path)
{
    auto table = toml::parse_file(path);
    for (auto &[name, value] : table)
        if (name != "mode" && name != "listen" && name != "endpoint" && name != "key")
            throw std::runtime_error("unknown configuration field: " + std::string(name.str()));
    auto require = [&](std::string_view name) {
        auto value = table[name].value<std::string>();
        if (!value)
            throw std::runtime_error("missing string field: " + std::string(name));
        return *value;
    };
    auto mode = require("mode");
    if (mode != "server" && mode != "client")
        throw std::runtime_error("mode must be server or client");
    bool server = mode == "server";
    if (table.contains(server ? "endpoint" : "listen"))
        throw std::runtime_error("address field does not match mode");
    auto address = require(server ? "listen" : "endpoint");
    auto colon = address.rfind(':');
    if (colon == std::string::npos || colon == 0 || address.find(':') != colon)
        throw std::runtime_error("address requires IPv4 or domain host:port");
    unsigned port = 0;
    auto result = std::from_chars(address.data() + colon + 1, address.data() + address.size(), port);
    if (result.ec != std::errc{} || result.ptr != address.data() + address.size() || port < 1 || port > 65535)
        throw std::runtime_error("port must be 1..65535");
    auto host = address.substr(0, colon);
    if (server)
        asio::ip::make_address_v4(host);
    else if (host == "0.0.0.0" || host == "10.200.0.1")
        throw std::runtime_error("endpoint must be a reachable server address");
    return { server, std::move(address), decode_key(require("key")) };
}
} // namespace

int
main(int argc, char **argv)
{
    try
    {
        if (argc == 2 && std::string_view(argv[1]) == "genkey")
        {
            ft::Key key;
            if (BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) <
                0)
                throw std::runtime_error("random generator failed");
            std::cout << base64(key) << '\n';
            return 0;
        }
        if (argc != 3 || (std::string_view(argv[1]) != "run" && std::string_view(argv[1]) != "check"))
            throw std::runtime_error("usage: flowtunnel genkey | check <config.toml> | run <config.toml>");
        auto config = configuration(argv[2]);
        if (std::string_view(argv[1]) == "check")
        {
            std::cout << "configuration valid\n";
            return 0;
        }
        asio::io_context io;
        ft::Runtime runtime(io, std::move(config));
        auto event_name = L"Local\\FlowTunnel.Stop." + std::to_wstring(GetCurrentProcessId());
        stop_event = CreateEventW(nullptr, TRUE, FALSE, event_name.c_str());
        if (!stop_event)
            throw std::runtime_error("create shutdown event failed");
        SetConsoleCtrlHandler(console_handler, TRUE);
        runtime.start();
        std::thread stopper([&] {
            WaitForSingleObject(stop_event, INFINITE);
            runtime.stop();
        });
        unsigned count = std::clamp(std::thread::hardware_concurrency(), 2u, 4u);
        std::vector<std::thread> workers;
        for (unsigned i = 1; i < count; i++)
            workers.emplace_back([&] { io.run(); });
        io.run();
        SetEvent(stop_event);
        stopper.join();
        for (auto &worker : workers)
            worker.join();
        SetConsoleCtrlHandler(console_handler, FALSE);
        CloseHandle(stop_event);
        stop_event = nullptr;
        return runtime.failed() ? 1 : 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "fatal: " << error.what() << std::endl;
        if (stop_event)
            CloseHandle(stop_event);
        return 1;
    }
}
