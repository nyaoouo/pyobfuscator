#include "pyobfuscator_native/contribution.hpp"
#include "pyobfuscator_native/system_ops.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {
bool allocation_fails = false, hash_succeeds = true, zero_digest = false;
bool digest_erased = false, material_erased = false;
unsigned allocations = 0, releases = 0, hashes = 0;
std::uint8_t digest[32];
const std::uint8_t *material = nullptr;
std::size_t material_size = 0;
void require(bool value, const char *message) {
    if (!value) { std::fprintf(stderr, "contribution derivation failed: %s\n", message); std::abort(); }
}
void reset() {
    require(material == nullptr, "previous stack serialization retired");
    allocation_fails = false; hash_succeeds = true; zero_digest = false;
    digest_erased = material_erased = false; allocations = releases = hashes = 0;
}
}

namespace pyobfuscator::native::platform {
void *allocate(std::size_t size) noexcept {
    require(size == sizeof(digest), "bounded digest allocation");
    if (allocation_fails) return nullptr;
    ++allocations; std::memset(digest, 0xcc, sizeof(digest)); return digest;
}
bool hash_sha256(const std::uint8_t *bytes, std::size_t size, std::uint8_t *output) noexcept {
    require(output == digest && material == nullptr, "independent complete serialization");
    material = bytes; material_size = size; ++hashes;
    std::memset(output, zero_digest ? 0 : 0xcc, 32);
    if (!zero_digest) { output[0] = 0x78; output[1] = 0x56; output[2] = 0x34; output[3] = 0x12; }
    return hash_succeeds;
}
void erase(void *memory, std::size_t size) noexcept {
    require(memory == digest ? size == sizeof(digest) : memory == material && size == material_size,
            "erase only exact digest or serialization span");
    auto *bytes = static_cast<volatile std::uint8_t *>(memory);
    for (std::size_t index = 0; index != size; ++index) bytes[index] = 0;
    if (memory == digest) digest_erased = true;
    else { material_erased = true; material = nullptr; material_size = 0; }
}
void release(void *memory) noexcept {
    require(memory == digest && digest_erased && material_erased && releases == 0, "erase all private material before digest release");
    for (auto byte : digest) require(byte == 0, "digest remains zero at release");
    ++releases;
}
}

int main() {
    using namespace pyobfuscator::native;
    const std::uint32_t words[]{1, 2, 3, 4, 5, 6, 7, 8};
    const contribution::Site point{1, 2, 3, 4, 5};
    for (unsigned mode = 0; mode != 4; ++mode) {
        reset(); allocation_fails = mode == 0; hash_succeeds = mode != 1; zero_digest = mode == 2;
        const auto result = contribution::derive(words, 7, point);
        require(result.status == (mode == 0 ? BootstrapContextStatus::allocation_failed : mode == 1 ?
                BootstrapContextStatus::unavailable : BootstrapContextStatus::ok), "allocation/hash failure status");
        require(result.word == (mode <= 1 ? 0u : mode == 2 ? 1u : 0x12345678u), "nonzero canonical normalization and failed-result poisoning");
        require(allocations == unsigned(mode != 0) && releases == allocations && hashes == allocations,
                "one owned digest and one hashing operation");
    }
    reset();
    auto invalid = point; invalid.source = 0;
    require(contribution::derive(words, 7, invalid).status == BootstrapContextStatus::invalid_request && allocations == 0,
            "invalid site refuses before allocation or private reads");
    std::puts("contribution derivation: digest OOM, provider false/zero, canonical word and private serialization/digest erasure verified");
}
