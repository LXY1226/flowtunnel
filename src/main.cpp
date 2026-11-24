#include "tunnel.hpp"
#include "service.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <toml++/toml.hpp>
#include <algorithm>
#include <charconv>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <system_error>
#include <thread>

namespace {
HANDLE stop_event = nullptr;
std::mutex stop_mutex;
void
request_stop()
{
    std::lock_guard lock(stop_mutex);
    if (stop_event)
        SetEvent(stop_event);
}
BOOL WINAPI
console_handler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT || type == CTRL_SHUTDOWN_EVENT)
    {
        request_stop();
        return TRUE;
    }
    return FALSE;
}
class StopEvent
{
public:
    StopEvent()
    {
        const auto name = L"Local\\FlowTunnel.Stop." + std::to_wstring(GetCurrentProcessId());
        handle_ = CreateEventW(nullptr, TRUE, FALSE, name.c_str());
        if (!handle_)
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "create shutdown event");
        std::lock_guard lock(stop_mutex);
        stop_event = handle_;
    }
    ~StopEvent()
    {
        std::lock_guard lock(stop_mutex);
        stop_event = nullptr;
        CloseHandle(handle_);
    }
    HANDLE handle() const { return handle_; }

private:
    HANDLE handle_ = nullptr;
};
class ConsoleControl
{
public:
    explicit ConsoleControl(bool enabled) : enabled_(enabled)
    {
        if (enabled_ && !SetConsoleCtrlHandler(console_handler, TRUE))
            throw std::system_error(
                static_cast<int>(GetLastError()), std::system_category(), "register console handler");
    }
    ~ConsoleControl()
    {
        if (enabled_)
            SetConsoleCtrlHandler(console_handler, FALSE);
    }

private:
    bool enabled_;
};
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
configuration(const wchar_t *path)
{
    auto table = toml::parse_file(std::wstring_view(path));
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

int
run_runtime(ft::Config config, const std::function<void()> &on_started, bool console)
{
    asio::io_context io;
    ft::Runtime runtime(io, std::move(config));
    StopEvent event;
    ConsoleControl control(console);
    runtime.start();
    std::mutex failure_mutex;
    std::exception_ptr failure;
    auto record_failure = [&] {
        std::lock_guard lock(failure_mutex);
        if (!failure)
            failure = std::current_exception();
    };
    auto run_io = [&] {
        for (;;)
            try
            {
                io.run();
                return;
            }
            catch (...)
            {
                record_failure();
                runtime.stop();
            }
    };
    std::vector<std::jthread> workers;
    std::jthread stopper([&] {
        WaitForSingleObject(event.handle(), INFINITE);
        runtime.stop();
    });
    try
    {
        on_started();
        const unsigned count = std::clamp(std::thread::hardware_concurrency(), 2u, 4u);
        for (unsigned i = 1; i < count; i++)
            workers.emplace_back(run_io);
        run_io();
    }
    catch (...)
    {
        record_failure();
        runtime.stop();
        run_io();
    }
    request_stop();
    stopper.join();
    workers.clear();
    if (failure)
        std::rethrow_exception(failure);
    return runtime.failed() ? 1 : 0;
}
} // namespace

int
wmain(int argc, wchar_t **argv)
{
    try
    {
        if (argc == 2 && std::wstring_view(argv[1]) == L"genkey")
        {
            ft::Key key;
            if (BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) <
                0)
                throw std::runtime_error("random generator failed");
            std::cout << base64(key) << '\n';
            return 0;
        }
        if (argc == 5 && std::wstring_view(argv[1]) == L"service")
        {
            return ft::run_service(
                argv[2],
                argv[4],
                [&](const auto &started) {
                    if (!std::filesystem::path(argv[3]).is_absolute())
                        throw std::runtime_error("service configuration path must be absolute");
                    return run_runtime(configuration(argv[3]), started, false);
                },
                request_stop);
        }
        if (argc != 3 || (std::wstring_view(argv[1]) != L"run" && std::wstring_view(argv[1]) != L"check"))
            throw std::runtime_error(
                "usage: flowtunnel genkey | check <config.toml> | run <config.toml> | service <service-name> <config.toml> <log-directory>");
        auto config = configuration(argv[2]);
        if (std::wstring_view(argv[1]) == L"check")
        {
            const auto port = std::stoi(config.address.substr(config.address.rfind(':') + 1));
            std::cout << "{\"mode\":\"" << (config.server ? "server" : "client") << "\",\"port\":" << port << "}\n";
            return 0;
        }
        return run_runtime(std::move(config), [] {}, true);
    }
    catch (const std::exception &error)
    {
        std::cerr << "fatal: " << error.what() << std::endl;
        return 1;
    }
}
