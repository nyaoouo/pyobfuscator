#pragma once

#include "observer.hpp"
#include "backend.hpp"
#include "context/runtime.hpp"

namespace pyobfuscator::native::measurement::observer::detail {
inline constexpr Error good{Status::ok, BootstrapContextStatus::ok,
    reference::Status::ok, measurement::Status::ok};
inline constexpr std::uint32_t operation = 0x6f627331, version = 1;
inline constexpr std::uint64_t reply = 0x70796f626f627331;
enum class Action : std::uint32_t { observe = 1, validate, invalidate };

struct Response {
    Observation data{};
    std::uint8_t expected[32]{};
    bool reused = false;
    Validation validation{};
};
struct Request {
    std::uint32_t version = detail::version, size = sizeof(Request);
    Action action = Action::observe;
    std::uint32_t force = 0;
    std::uint64_t instance = 0;
    const Observation *snapshot = nullptr;
    Response *output = nullptr;
};
struct State {
    reference::Reference reference;
    reference::Identity identity;
    Spec spec;
    ModuleView view{};
    pyobfuscator::native::detail::BootstrapContextState *context = nullptr;
    std::uint64_t epoch = 1, admitted = 0, published = 0;
    Error failure = good;
    Observation cached{};
    bool has_cache = false;
    ReaderBinding reader{};
    platform::CodeLease reader_code{}, codec_code{};
};

bool valid_policy(const Policy &) noexcept;
bool within(std::uint64_t ticks, std::uint64_t frequency, std::uint64_t ns) noexcept;
Status interval(const Data &, const Policy &, const ClockSample &) noexcept;
bool same_identity(const reference::Identity &, const reference::Identity &) noexcept;
Error context_error(BootstrapContextStatus) noexcept;
void lock(State &) noexcept;
void unlock(State &) noexcept;
Error live(const State &) noexcept;
void revoke(State &, Error) noexcept;
Observation header(const State &, std::uint64_t sequence) noexcept;
bool clock(ClockSample &) noexcept;
BootstrapContextResult dispatch(const BootstrapContextRequest &, void *) noexcept;
void destroy(void *) noexcept;
void acquire(State &, bool force, Response &) noexcept;
void sample(State &, std::uint64_t epoch, std::uint64_t sequence, Response &) noexcept;
void validate(State &, const Observation &, Validation &) noexcept;
Error inspect(const State &, const Observation &, const ClockSample &) noexcept;
void fill(const State &, const Observation &, bool reused, Response &) noexcept;

}  // namespace pyobfuscator::native::measurement::observer::detail
