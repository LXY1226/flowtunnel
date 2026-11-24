#include "service.hpp"
#include <windows.h>
#include <cstdio>
#include <iostream>
#include <memory>
#include <mutex>
#include <string_view>
#include <system_error>
#include <utility>

namespace ft {
namespace {
struct Service
{
    std::wstring name;
    std::filesystem::path log_directory;
    ServiceRun run;
    std::function<void()> stop;
    std::mutex mutex;
    SERVICE_STATUS_HANDLE handle = nullptr;
    SERVICE_STATUS status{ SERVICE_WIN32_OWN_PROCESS };
    int result = 1;

    void event(std::string_view message) const noexcept
    {
        const auto length =
            MultiByteToWideChar(CP_UTF8, 0, message.data(), static_cast<int>(message.size()), nullptr, 0);
        try
        {
            std::wstring text(static_cast<size_t>(length), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, message.data(), static_cast<int>(message.size()), text.data(), length);
            const wchar_t *strings[] = { text.c_str() };
            const auto source = RegisterEventSourceW(nullptr, name.c_str());
            if (source)
            {
                ReportEventW(source, EVENTLOG_ERROR_TYPE, 0, 1, nullptr, 1, 0, strings, nullptr);
                DeregisterEventSource(source);
            }
            OutputDebugStringW(text.c_str());
        }
        catch (...)
        {
            OutputDebugStringW(L"FlowTunnel service diagnostic could not be written");
        }
    }

    bool report(DWORD state, DWORD exit_code = 0) noexcept
    {
        status.dwCurrentState = state;
        status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
        status.dwWin32ExitCode = exit_code ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
        status.dwServiceSpecificExitCode = exit_code;
        const bool pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
        status.dwCheckPoint = pending ? 1 : 0;
        status.dwWaitHint = pending ? 10000 : 0;
        if (SetServiceStatus(handle, &status))
            return true;
        char message[80];
        snprintf(message, sizeof(message), "SetServiceStatus failed: %lu", GetLastError());
        event(message);
        return false;
    }

    void open_logs()
    {
        if (!log_directory.is_absolute())
            throw std::runtime_error("service log directory must be absolute");
        std::filesystem::create_directories(log_directory);
        FILE *file = nullptr;
        const auto output = log_directory / L"stdout.log";
        auto error = _wfreopen_s(&file, output.c_str(), L"ab", stdout);
        if (error)
            throw std::system_error(error, std::generic_category(), "open service stdout.log");
        const auto errors = log_directory / L"stderr.log";
        error = _wfreopen_s(&file, errors.c_str(), L"ab", stderr);
        if (error)
            throw std::system_error(error, std::generic_category(), "open service stderr.log");
        if (setvbuf(stdout, nullptr, _IONBF, 0) || setvbuf(stderr, nullptr, _IONBF, 0))
            throw std::runtime_error("configure service log buffering failed");
    }
};

// The dispatcher and HandlerEx can run concurrently; keep their context alive until process exit.
std::unique_ptr<Service> service;

DWORD WINAPI
control_handler(DWORD control, DWORD, void *, void *context)
{
    auto &self = *static_cast<Service *>(context);
    if (control == SERVICE_CONTROL_INTERROGATE)
        return NO_ERROR;
    if (control != SERVICE_CONTROL_STOP && control != SERVICE_CONTROL_SHUTDOWN)
        return ERROR_CALL_NOT_IMPLEMENTED;
    {
        std::lock_guard lock(self.mutex);
        if (self.status.dwCurrentState != SERVICE_RUNNING)
            return NO_ERROR;
        if (!self.report(SERVICE_STOP_PENDING))
            self.result = 1;
    }
    try
    {
        self.stop();
    }
    catch (const std::exception &error)
    {
        self.event(std::string("service stop failed: ") + error.what());
        std::lock_guard lock(self.mutex);
        self.result = 1;
    }
    catch (...)
    {
        self.event("service stop failed with an unknown exception");
        std::lock_guard lock(self.mutex);
        self.result = 1;
    }
    return NO_ERROR;
}

void WINAPI
service_main(DWORD, wchar_t **)
{
    auto &self = *service;
    self.handle = RegisterServiceCtrlHandlerExW(self.name.c_str(), control_handler, &self);
    if (!self.handle)
    {
        self.event("RegisterServiceCtrlHandlerExW failed: " + std::to_string(GetLastError()));
        self.result = 1;
        return;
    }
    int result = 1;
    try
    {
        {
            std::lock_guard lock(self.mutex);
            if (!self.report(SERVICE_START_PENDING))
                throw std::runtime_error("report service start pending failed");
        }
        self.open_logs();
        result = self.run([&] {
            std::lock_guard lock(self.mutex);
            if (!self.report(SERVICE_RUNNING))
                throw std::runtime_error("report service running failed");
        });
    }
    catch (const std::exception &error)
    {
        std::cerr << "fatal: " << error.what() << std::endl;
        self.event(std::string("FlowTunnel service failed: ") + error.what());
    }
    catch (...)
    {
        std::cerr << "fatal: unknown service exception" << std::endl;
        self.event("FlowTunnel service failed with an unknown exception");
    }
    std::cout.flush();
    std::cerr.flush();
    if (!std::cout || !std::cerr || fflush(stdout) == EOF || fflush(stderr) == EOF || ferror(stdout) || ferror(stderr))
    {
        self.event("FlowTunnel service log write failed");
        result = 1;
    }
    std::lock_guard lock(self.mutex);
    self.result = self.result == 1 ? 1 : result;
    if (!self.report(SERVICE_STOPPED, static_cast<DWORD>(self.result)))
        self.result = 1;
}
} // namespace

int
run_service(std::wstring name, std::filesystem::path log_directory, ServiceRun run, std::function<void()> stop)
{
    service = std::make_unique<Service>();
    service->name = std::move(name);
    service->log_directory = std::move(log_directory);
    service->run = std::move(run);
    service->stop = std::move(stop);
    service->result = 0;
    SERVICE_TABLE_ENTRYW table[] = { { service->name.data(), service_main }, { nullptr, nullptr } };
    if (!StartServiceCtrlDispatcherW(table))
        throw std::system_error(
            static_cast<int>(GetLastError()), std::system_category(), "StartServiceCtrlDispatcherW");
    std::lock_guard lock(service->mutex);
    return service->result;
}
} // namespace ft
