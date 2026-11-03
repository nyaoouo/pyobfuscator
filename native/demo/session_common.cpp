#include "session_fixture.hpp"

#include <cstdio>
#include <cstdlib>

namespace session_fixture {
void require(bool condition, const char *message) {
    if (!condition) { std::fprintf(stderr, "session check failed: %s\n", message); std::exit(1); }
}
void observe(std::uint32_t stage, void *data) {
    if (stage >= 2)
        require(active_key == nullptr && counters.keys == counters.erased_keys && hash_material == nullptr,
                "key and serialization erased before observer callbacks");
    auto &trace = *static_cast<Trace *>(data);
    require(trace.count < 8, "bounded observer trace");
    trace.stages[trace.count++] = stage;
    if (stage == 6) require(counters.unloads == 1, "final observer event follows image unload");
    if (stage == counters.throw_stage) throw ObserverFailure{stage};
}
}
