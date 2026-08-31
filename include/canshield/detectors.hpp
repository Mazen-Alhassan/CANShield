#ifndef CANSHIELD_DETECTORS_HPP
#define CANSHIELD_DETECTORS_HPP

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "canshield/can_frame.hpp"
#include "canshield/message_catalog.hpp"

namespace canshield {

enum class Severity { Info, Low, Medium, High, Critical };
const char* to_string(Severity s);

struct Alert {
    std::uint64_t timestamp_us = 0;
    std::uint32_t can_id = 0;
    std::string detector;   // which detector fired
    std::string reason;     // human-readable explanation
    Severity severity = Severity::Medium;
};

// every detector sees frames in bus order and may emit zero or more alerts.
// inspect() must be allocation-light and O(1)-ish to keep per-frame latency low.
class IDetector {
public:
    virtual ~IDetector() = default;
    virtual const char* name() const = 0;
    // append any alerts raised by this frame to `out`.
    virtual void inspect(const CanFrame& f, std::vector<Alert>& out) = 0;
};

// ---- individual detectors -------------------------------------------------

// flags ids not present in the known bus matrix (fuzzing, flooding with junk).
class UnknownIdDetector : public IDetector {
public:
    explicit UnknownIdDetector(const MessageCatalog& c) : cat_(c) {}
    const char* name() const override { return "unknown_id"; }
    void inspect(const CanFrame& f, std::vector<Alert>& out) override;
private:
    const MessageCatalog& cat_;
};

// flags structural problems: bad dlc vs matrix, error frames, malformed.
class ProtocolDetector : public IDetector {
public:
    explicit ProtocolDetector(const MessageCatalog& c) : cat_(c) {}
    const char* name() const override { return "protocol"; }
    void inspect(const CanFrame& f, std::vector<Alert>& out) override;
private:
    const MessageCatalog& cat_;
};

// validates the reverse-engineered checksum on integrity-protected messages.
class ChecksumDetector : public IDetector {
public:
    explicit ChecksumDetector(const MessageCatalog& c) : cat_(c) {}
    const char* name() const override { return "checksum"; }
    void inspect(const CanFrame& f, std::vector<Alert>& out) override;
private:
    const MessageCatalog& cat_;
};

// tracks the rolling counter per id; flags repeats/skips (replay, masquerade).
class CounterDetector : public IDetector {
public:
    explicit CounterDetector(const MessageCatalog& c) : cat_(c) {}
    const char* name() const override { return "counter"; }
    void inspect(const CanFrame& f, std::vector<Alert>& out) override;
private:
    const MessageCatalog& cat_;
    struct St { bool have = false; std::uint8_t last = 0; };
    std::unordered_map<std::uint32_t, St> state_;
};

// learns each id's period and flags arrivals that are too fast (injection).
// tolerance is a fraction of the expected period.
class TimingDetector : public IDetector {
public:
    explicit TimingDetector(const MessageCatalog& c, double tol = 0.5)
        : cat_(c), tol_(tol) {}
    const char* name() const override { return "timing"; }
    void inspect(const CanFrame& f, std::vector<Alert>& out) override;
private:
    const MessageCatalog& cat_;
    double tol_;
    std::unordered_map<std::uint32_t, std::uint64_t> last_us_;
};

// checks each decoded signal against its physical min/max (spoofed values).
class RangeDetector : public IDetector {
public:
    explicit RangeDetector(const MessageCatalog& c) : cat_(c) {}
    const char* name() const override { return "range"; }
    void inspect(const CanFrame& f, std::vector<Alert>& out) override;
private:
    const MessageCatalog& cat_;
};

// sliding-window per-id and global rate; flags bursts (flood, spoof, diag abuse,
// error-frame storms). window is in microseconds.
class RateDetector : public IDetector {
public:
    RateDetector(const MessageCatalog& c, std::uint64_t window_us = 100000,
                 double burst_factor = 3.0)
        : cat_(c), window_us_(window_us), burst_(burst_factor) {}
    const char* name() const override { return "rate"; }
    void inspect(const CanFrame& f, std::vector<Alert>& out) override;
private:
    const MessageCatalog& cat_;
    std::uint64_t window_us_;
    double burst_;
    struct Win { std::vector<std::uint64_t> ts; };
    std::unordered_map<std::uint32_t, Win> win_;
};

// cross-signal plausibility: wheel speeds must agree with vehicle speed, and
// engine rpm must be plausible for the current motion. catches masquerade /
// spoofing that is otherwise structurally perfect (valid checksum + counter +
// timing) but physically inconsistent with the rest of the bus.
class PhysicsConsistencyDetector : public IDetector {
public:
    const char* name() const override { return "physics"; }
    void inspect(const CanFrame& f, std::vector<Alert>& out) override;
private:
    bool have_speed_ = false, have_wheel_ = false, have_rpm_ = false;
    double vehicle_speed_ = 0, mean_wheel_ = 0, rpm_ = 0;
};

// flags diagnostic ids appearing at abnormal rate (diagnostic abuse while
// driving); diagnostics are normally silent/occasional.
class DiagnosticDetector : public IDetector {
public:
    DiagnosticDetector(std::uint64_t window_us = 1000000, int max_per_window = 20)
        : window_us_(window_us), max_(max_per_window) {}
    const char* name() const override { return "diagnostic"; }
    void inspect(const CanFrame& f, std::vector<Alert>& out) override;
private:
    std::uint64_t window_us_;
    int max_;
    std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> hits_;
};

}  // namespace canshield

#endif
