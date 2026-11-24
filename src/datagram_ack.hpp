#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

namespace ft {

class DatagramAck
{
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    static constexpr std::uint32_t ByteThreshold = 16 * 1024;
    static constexpr auto Delay = std::chrono::milliseconds(10);

    explicit DatagramAck(std::uint32_t sequence = 0) : sequence_(sequence), acknowledged_(sequence) {}

    void reset(std::uint32_t sequence)
    {
        sequence_ = acknowledged_ = sequence;
        deadline_.reset();
    }

    // TCP serial ordering assumes each forward observation spans less than half the sequence space.
    bool observe(std::uint32_t sequence_end, TimePoint now)
    {
        const auto progress = sequence_end - sequence_;
        if (progress != 0 && progress < 0x80000000u)
            sequence_ = sequence_end;
        if (!deadline_)
            deadline_ = now + Delay;
        return due(now);
    }

    bool due(TimePoint now) const
    {
        return deadline_ && (sequence_ - acknowledged_ >= ByteThreshold || now >= *deadline_);
    }

    std::optional<TimePoint> deadline() const { return deadline_; }
    std::uint32_t sequence() const { return sequence_; }
    bool pending() const { return deadline_.has_value(); }

    void sent()
    {
        acknowledged_ = sequence_;
        deadline_.reset();
    }

private:
    std::uint32_t sequence_, acknowledged_;
    std::optional<TimePoint> deadline_;
};

} // namespace ft
