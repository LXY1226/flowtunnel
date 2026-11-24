#pragma once
#include <filesystem>
#include <functional>
#include <string>

namespace ft {
using ServiceRun = std::function<int(const std::function<void()> &on_started)>;

// run must return only after the runtime and its worker threads have stopped.
int
run_service(std::wstring name, std::filesystem::path log_directory, ServiceRun run, std::function<void()> stop);
} // namespace ft
