#pragma once

#include "bootstrap/decoy.hpp"

#include <cstddef>
#include <cstdint>

namespace decoy_fixture {

struct Counters {
    unsigned attempts = 0, allocations = 0, releases = 0, pins = 0, unpins = 0;
    unsigned real_decrypts = 0, decoy_decrypts = 0, real_loads = 0, decoy_loads = 0;
    unsigned real_load_attempts = 0, decoy_load_attempts = 0;
    unsigned invalid_load_attempts = 0;
    unsigned real_entries = 0, decoy_entries = 0, real_unloads = 0, decoy_unloads = 0;
    unsigned real_hashes = 0, decoy_hashes = 0, material_erasures = 0, keys = 0, erased_keys = 0;
    unsigned fail_allocation = 0, public_allocation = 0, throw_stage = 0;
    bool denied = false, real_hash_succeeds = true, decoy_hash_succeeds = true;
    bool decoy_aead_succeeds = true, load_succeeds = true, resolve_succeeds = true;
    bool decoy_started = false;
    std::uint32_t decoy_fold[8]{}, failed_real_fold[8]{};
};
struct Trace { std::uint32_t stages[16]{}; unsigned count = 0; };
struct ObserverFailure { std::uint32_t stage; };

extern Counters counters;
extern pyobfuscator::native::demo::RuntimeContext *real_context;
extern pyobfuscator::native::path_fold::Storage *decoy_fold;
extern pyobfuscator::native::BootstrapContextLease retained;
extern const std::uint8_t *hash_material, *active_key;
extern std::size_t hash_material_size;
extern bool active_key_erased;
void require(bool, const char *);
void initialize_images(const char *, const char *);
void reset();
void verify_clean();
void observe(std::uint32_t, void *);
void suite();
void release_fault(const char *);

}  // namespace decoy_fixture
