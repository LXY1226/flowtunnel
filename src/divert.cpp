#include "divert.hpp"

#include <array>
#include <filesystem>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace ft {
namespace {

[[noreturn]] void
windows_error(const char *operation)
{
    const auto error = GetLastError();
    throw std::system_error(static_cast<int>(error), std::system_category(), operation);
}

class Api
{
public:
    Api()
    {
        std::array<wchar_t, 32768> executable{};
        const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (length == 0 || length == executable.size())
        {
            windows_error("GetModuleFileNameW");
        }
        const auto library = std::filesystem::path(executable.data()).parent_path() / L"WinDivert.dll";
        module_ = LoadLibraryExW(
            library.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (!module_)
        {
            windows_error("LoadLibraryExW WinDivert.dll");
        }
        try
        {
            open = load<decltype(open)>("WinDivertOpen");
            recv = load<decltype(recv)>("WinDivertRecv");
            send = load<decltype(send)>("WinDivertSend");
            shutdown = load<decltype(shutdown)>("WinDivertShutdown");
            close = load<decltype(close)>("WinDivertClose");
            checksums = load<decltype(checksums)>("WinDivertHelperCalcChecksums");
        }
        catch (...)
        {
            FreeLibrary(module_);
            throw;
        }
    }

    ~Api() { FreeLibrary(module_); }
    Api(const Api &) = delete;
    Api &operator=(const Api &) = delete;

    decltype(&WinDivertOpen) open = nullptr;
    decltype(&WinDivertRecv) recv = nullptr;
    decltype(&WinDivertSend) send = nullptr;
    decltype(&WinDivertShutdown) shutdown = nullptr;
    decltype(&WinDivertClose) close = nullptr;
    decltype(&WinDivertHelperCalcChecksums) checksums = nullptr;

private:
    template <typename Function>
    Function load(const char *name)
    {
        const auto function = GetProcAddress(module_, name);
        if (!function)
        {
            windows_error(name);
        }
        return reinterpret_cast<Function>(function);
    }
    HMODULE module_ = nullptr;
};

Api &
api()
{
    static Api instance;
    return instance;
}

} // namespace

Divert::Divert(const std::string &filter, std::int16_t priority, bool send_only)
{
    handle_ = api().open(filter.c_str(), WINDIVERT_LAYER_NETWORK, priority, send_only ? WINDIVERT_FLAG_SEND_ONLY : 0);
    if (handle_ == INVALID_HANDLE_VALUE)
    {
        windows_error("WinDivertOpen");
    }
}

Divert::~Divert()
{
    close();
}

Divert::Divert(Divert &&other) noexcept : handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE)) {}

Divert &
Divert::operator=(Divert &&other) noexcept
{
    if (this != &other)
    {
        close();
        handle_ = std::exchange(other.handle_, INVALID_HANDLE_VALUE);
    }
    return *this;
}

Captured
Divert::recv(std::span<std::uint8_t> buffer)
{
    Captured captured;
    UINT received = 0;
    if (!api().recv(handle_, buffer.data(), static_cast<UINT>(buffer.size()), &received, &captured.address))
    {
        windows_error("WinDivertRecv");
    }
    captured.bytes.assign(buffer.begin(), buffer.begin() + received);
    return captured;
}

void
Divert::send(std::span<std::uint8_t> bytes, WINDIVERT_ADDRESS address)
{
    if (bytes.empty() || bytes.size() > 65535)
    {
        throw std::length_error("invalid WinDivert packet size");
    }
    const auto length = static_cast<UINT>(bytes.size());
    if (!api().checksums(bytes.data(), length, &address, 0))
    {
        throw std::runtime_error("WinDivertHelperCalcChecksums rejected packet");
    }
    UINT sent = 0;
    if (!api().send(handle_, bytes.data(), length, &sent, &address))
    {
        windows_error("WinDivertSend");
    }
    if (sent != length)
    {
        throw std::runtime_error("WinDivertSend returned a short packet");
    }
}

void
Divert::shutdown_recv()
{
    if (handle_ != INVALID_HANDLE_VALUE && !api().shutdown(handle_, WINDIVERT_SHUTDOWN_RECV))
    {
        windows_error("WinDivertShutdown");
    }
}

void
Divert::close() noexcept
{
    if (handle_ != INVALID_HANDLE_VALUE)
    {
        api().close(std::exchange(handle_, INVALID_HANDLE_VALUE));
    }
}

} // namespace ft
