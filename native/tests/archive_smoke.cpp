#include "archive/runtime.hpp"
#include "archive_fixture.hpp"

#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "archive check failed at line %d: %s\n", __LINE__, #condition); return 1; \
} } while (false)

using pyobfuscator::native::archive::Cache;
using pyobfuscator::native::archive::Status;
using pyobfuscator::native::archive::acquire_record;

namespace {
constexpr std::size_t count = sizeof(fixture::records) / sizeof(fixture::records[0]);
struct alignas(4096) Storage { std::uint8_t bytes[64]; };
Storage outputs[count]{};

std::size_t offset(const std::uint8_t *package, unsigned record) {
    std::uint64_t result = 0;
    for (unsigned byte = 0; byte < 8; ++byte)
        result |= std::uint64_t{package[40 + record * 96 + 24 + byte]} << (byte * 8);
    return static_cast<std::size_t>(result);
}
}

int main(int argc, char **) {
    if (argc > 1) {
        Cache cache;
        std::uint8_t wrong[32]{};
        pyobfuscator::native::archive::require_record(fixture::package, sizeof(fixture::package),
            1, outputs[1].bytes, 64, cache, wrong);
        std::puts("DATA-CONSUMED");
        return 0;
    }
    Cache caches[count];
    for (unsigned index = 0; index < count; ++index) {
        const auto &record = fixture::records[index];
        std::memset(outputs[index].bytes, 0xa5, 64);
        std::uint8_t wrong[32];
        std::memcpy(wrong, record.key, 32);
        wrong[0] ^= 1;
        CHECK(acquire_record(fixture::package, sizeof(fixture::package), index,
            outputs[index].bytes, 64, caches[index], wrong) == Status::verification_failed);
        CHECK(outputs[index].bytes[0] == 0xa5);
        for (unsigned repeat = 0; repeat < 2; ++repeat) {
            CHECK(acquire_record(fixture::package, sizeof(fixture::package), index,
                outputs[index].bytes, 64, caches[index], record.key) == Status::ready);
            CHECK(std::memcmp(outputs[index].bytes, record.data, record.size) == 0);
        }
        CHECK(acquire_record(fixture::package, sizeof(fixture::package), index,
            outputs[index].bytes, 64, caches[index], wrong) == Status::verification_failed);
        CHECK(std::memcmp(outputs[index].bytes, record.data, record.size) == 0);
        fixture::wrappers[index](record.key, outputs[index].bytes, 64);
        CHECK(std::memcmp(outputs[index].bytes, record.data, record.size) == 0);
        fixture::wrappers[index](record.key, outputs[index].bytes, 64);
    }
    // Empty records may share a ciphertext offset, never cache identity.
    CHECK(offset(fixture::package, 0) == offset(fixture::package, 1));
    CHECK(acquire_record(fixture::package, sizeof(fixture::package), 1,
        outputs[0].bytes, 64, caches[0], fixture::records[1].key) == Status::binding_mismatch);
    Storage other{};
    CHECK(acquire_record(fixture::package, sizeof(fixture::package), 1,
        other.bytes, 64, caches[1], fixture::records[1].key) == Status::binding_mismatch);
    auto copy = std::vector<std::uint8_t>(std::begin(fixture::package), std::end(fixture::package));
    CHECK(acquire_record(copy.data(), copy.size(), 1, outputs[1].bytes, 64,
        caches[1], fixture::records[1].key) == Status::binding_mismatch);

    // A damaged body has a valid access tag but cannot publish partial plaintext.
    copy[offset(copy.data(), 1)] ^= 1;
    Cache failed;
    std::memset(other.bytes, 0xa5, 64);
    CHECK(acquire_record(copy.data(), copy.size(), 1, other.bytes, 64, failed,
        fixture::records[1].key) == Status::decode_failed);
    for (std::size_t byte = 0; byte < fixture::records[1].size; ++byte) CHECK(other.bytes[byte] == 0);
    CHECK(other.bytes[fixture::records[1].size] == 0xa5);
    copy[offset(copy.data(), 1)] ^= 1;
    CHECK(acquire_record(copy.data(), copy.size(), 1, other.bytes, 64, failed,
        fixture::records[1].key) == Status::decode_failed);

    // A different but structurally valid type cannot reuse an existing authenticated record.
    copy.assign(std::begin(fixture::package), std::end(fixture::package));
    copy[40 + 4 * 96 + 4] = 1;
    Cache changed_type;
    CHECK(acquire_record(copy.data(), copy.size(), 4, other.bytes, 64, changed_type,
        fixture::records[4].key) == Status::verification_failed);
    Cache wrong_order;
    CHECK(acquire_record(fixture::big_endian_package, sizeof(fixture::big_endian_package), 0,
        other.bytes, 64, wrong_order, fixture::big_endian_key) == Status::invalid_record);

    for (const auto position : std::array<std::size_t, 13>{0, 8, 12, 32,
                               40u + 96u + 4u, 40u + 96u + 12u, 40u + 96u + 16u,
                               40u + 96u + 24u, 40u + 96u + 36u, 40u + 96u + 40u,
                               40u + 96u + 52u, 40u + 96u + 68u, 40u + 96u + 80u}) {
        copy.assign(std::begin(fixture::package), std::end(fixture::package));
        copy[position] ^= 0x80;
        Cache damaged;
        CHECK(acquire_record(copy.data(), copy.size(), 1, other.bytes, 64, damaged,
            fixture::records[1].key) != Status::ready);
    }
    for (std::size_t size = 0; size < sizeof(fixture::package); ++size) {
        Cache truncated;
        CHECK(acquire_record(fixture::package, size, 1, other.bytes, 64, truncated,
            fixture::records[1].key) == Status::invalid_record);
    }
    Cache invalid_storage;
    CHECK(acquire_record(fixture::package, sizeof(fixture::package), 1, nullptr, 64,
        invalid_storage, fixture::records[1].key) == Status::invalid_storage);
    CHECK(acquire_record(fixture::package, sizeof(fixture::package), 1, other.bytes, 0,
        invalid_storage, fixture::records[1].key) == Status::invalid_storage);
    CHECK(acquire_record(fixture::package, sizeof(fixture::package), 2, other.bytes + 1, 32,
        invalid_storage, fixture::records[2].key) == Status::invalid_storage);
    CHECK(acquire_record(fixture::package, sizeof(fixture::package), 1,
        reinterpret_cast<std::uint8_t *>(&invalid_storage), sizeof(invalid_storage),
        invalid_storage, fixture::records[1].key) == Status::invalid_storage);
    copy.assign(std::begin(fixture::package), std::end(fixture::package));
    CHECK(acquire_record(copy.data(), copy.size(), 1, copy.data(), copy.size(),
        invalid_storage, fixture::records[1].key) == Status::invalid_storage);
    CHECK(acquire_record(fixture::package, sizeof(fixture::package), static_cast<unsigned>(count),
        other.bytes, 64, invalid_storage, fixture::records[1].key) == Status::invalid_record);
    copy[40 + 96 + 24] = 0xff;
    for (unsigned byte = 1; byte < 8; ++byte) copy[40 + 96 + 24 + byte] = 0xff;
    CHECK(acquire_record(copy.data(), copy.size(), 1, other.bytes, 64,
        invalid_storage, fixture::records[1].key) == Status::invalid_record);
    Cache empty;
    CHECK(acquire_record(fixture::package, sizeof(fixture::package), 0, nullptr, 0,
        empty, fixture::records[0].key) == Status::ready);

    Cache recursive;
    const auto recurse = [&](auto &self, unsigned depth) -> bool {
        if (acquire_record(fixture::package, sizeof(fixture::package), 1, other.bytes, 64,
                recursive, fixture::records[1].key) != Status::ready) return false;
        if (depth != 0 && !self(self, depth - 1)) return false;
        return std::memcmp(other.bytes, fixture::records[1].data, fixture::records[1].size) == 0;
    };
    CHECK(recurse(recurse, 32));

    Cache concurrent;
    std::atomic<unsigned> failures{0};
    std::atomic<bool> start{false};
    std::vector<std::thread> threads;
    for (unsigned thread = 0; thread < 12; ++thread) threads.emplace_back([&] {
        while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
        for (unsigned repeat = 0; repeat < 32; ++repeat)
            if (acquire_record(fixture::package, sizeof(fixture::package), 1, other.bytes, 64,
                    concurrent, fixture::records[1].key) != Status::ready ||
                std::memcmp(other.bytes, fixture::records[1].data, fixture::records[1].size) != 0)
                ++failures;
    });
    start.store(true, std::memory_order_release);
    for (auto &thread : threads) thread.join();
    CHECK(failures == 0);
    std::puts("archive runtime verified");
    return 0;
}
