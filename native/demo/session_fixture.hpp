#pragma once

#include "bootstrap/flow.hpp"

#include <cstddef>
#include <cstdint>

namespace session_fixture {

struct Counters {
    unsigned allocation_attempts = 0, allocations = 0, releases = 0, erasures = 0;
    unsigned pins = 0, unpins = 0, decrypts = 0, loads = 0, unloads = 0, entries = 0;
    unsigned fail_allocation = 0, throw_stage = 0;
    bool authenticated = true, load_succeeds = true, resolve_succeeds = true;
    pyobfuscator::native::environment::Result environment = pyobfuscator::native::environment::Result::clear;
    bool environment_valid = true;
    bool hash_succeeds = true;
    unsigned hashes = 0, material_erasures = 0;
    unsigned keys = 0, erased_keys = 0;
    std::uint32_t decrypt_fold[8]{};
    std::uint32_t phase_fold[2][8]{};
    std::uint32_t retire_on_phase = 0;
};

struct Trace { std::uint32_t stages[8]{}; unsigned count = 0; };
struct ObserverFailure { std::uint32_t stage; };

extern Counters counters;
extern pyobfuscator::native::BootstrapContextLease retained;
extern pyobfuscator::native::demo::RuntimeContext *fold_context;
extern const std::uint8_t *hash_material;
extern std::size_t hash_material_size;
extern const std::uint8_t *active_key;
extern bool active_key_erased;
void require(bool, const char *);
void reset();
void verify_clean();
void observe(std::uint32_t, void *);
void check_protocol();
void check_fold();

}  // namespace session_fixture
