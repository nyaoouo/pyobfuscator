#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "release/measured_internal.hpp"
#include "pyobfuscator_native/system_ops.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#if defined(PYOBF_TEST_MEASURED_CONTRIBUTION)
#include "measured_contribution_cases.hpp"
#endif
#if defined(PYOBF_TEST_MEASURED_SCOPE)
#include "scope_cases.hpp"
#endif

namespace native = pyobfuscator::native;
namespace measured = native::release::measured;
namespace observer = native::measurement::observer;
namespace {
void require(bool value, const char *why) { if (!value) { std::fprintf(stderr, "measured key: %s\n", why); std::exit(1); } }
std::vector<std::uint8_t> read(const char *path) {
    auto *file = std::fopen(path, "rb"); require(file != nullptr, "input open");
    std::vector<std::uint8_t> data;
    for (int value; (value = std::fgetc(file)) != EOF;) {
        require(data.size() < 512 * 1024, "input limit"); data.push_back(static_cast<std::uint8_t>(value));
    }
    require(!std::ferror(file) && std::fclose(file) == 0, "input read"); return data;
}
void blank(const std::uint8_t (&key)[32]) { for (auto value : key) require(value == 0, "failed key not erased"); }
bool decrypt(const std::uint8_t *key, const std::vector<std::uint8_t> &sealed) {
    constexpr char aad[] = "measured-release-test-v1";
    std::vector<std::uint8_t> plain(sealed.size() - 28);
    const bool success = PYOBF_NATIVE_AEAD_DECRYPT(sealed.data() + 28, plain.size(), key, sealed.data(),
        sealed.data() + 12, reinterpret_cast<const std::uint8_t *>(aad), sizeof(aad) - 1, plain.data());
    if (success) require(plain == std::vector<std::uint8_t>({'m', 'e', 'a', 's', 'u', 'r', 'e', 'd'}), "child bytes");
    return success;
}
}
int main(int argc, char **argv) {
    if (argc == 3 && std::strcmp(argv[1], "vectors") == 0) {
        const auto bytes = read(argv[2]); require(!bytes.empty() && bytes.size() % 116 == 0, "vector frame");
        for (std::size_t offset = 0; offset != bytes.size(); offset += 116) {
            native::path_fold::Storage fold{}; native::measurement::reference::Identity identity{};
            std::memcpy(fold.words, bytes.data() + offset, 32); std::memcpy(&identity, bytes.data() + offset + 32, 52);
            std::uint8_t key[32]; std::memset(key, 0xa5, sizeof(key));
            const auto status = measured::detail::expand(fold.words, identity, bytes.data() + offset + 84, key);
            std::printf("%u ", static_cast<unsigned>(status));
            for (auto byte : key) std::printf("%02x", byte);
            std::puts(""); PYOBF_NATIVE_ERASE(key, sizeof(key));
        }
        return 0;
    }
#if defined(PYOBF_TEST_MEASURED_SCOPE)
    constexpr int base_arguments = 8;
    constexpr bool scoped_mode = true;
#elif defined(PYOBF_TEST_MEASURED_CONTRIBUTION)
    constexpr int base_arguments = 7;
    constexpr bool scoped_mode = false;
#else
    constexpr int base_arguments = 6;
    constexpr bool scoped_mode = false;
#endif
    const bool bypass = argc == base_arguments + 1 && std::strcmp(argv[base_arguments], "bypass") == 0;
#if defined(PYOBF_TEST_MEASURED_SCOPE)
    const bool scope_bad = argc == base_arguments + 1 && std::strcmp(argv[base_arguments], "scope-bad") == 0;
    const bool scope_digest = argc == base_arguments + 1 && std::strcmp(argv[base_arguments], "scope-digest") == 0;
#else
    constexpr bool scope_bad = false;
    constexpr bool scope_digest = false;
#endif
    require(argc == base_arguments || (argc == base_arguments + 1 && (bypass || scope_bad || scope_digest || std::strcmp(argv[base_arguments], "cost") == 0)),
        "metadata/package/record/DLL/child inputs");
    const auto meta = read(argv[1]), package = read(argv[2]), record_bytes = read(argv[3]), sealed = read(argv[5]);
    require(meta.size() == 84 && record_bytes.size() == 64 && sealed.size() == 36, "fixed independent inputs");
    native::measurement::reference::Identity identity{}; native::path_fold::Storage fold{}; native::release::Record record{};
    std::memcpy(&identity, meta.data(), 52); std::memcpy(fold.words, meta.data() + 52, 32);
    std::memcpy(&record, record_bytes.data(), 64);
    const auto module = LoadLibraryA(argv[4]); require(module != nullptr, "actual module load");
#if defined(PYOBF_TEST_MEASURED_SCOPE)
    auto parent = make_scope_parent();
    const auto subject_instance = parent.owner.generation();
#else
    constexpr std::uint64_t subject_instance = 1;
#endif
    auto created = observer::create(package.data(), package.size(), identity, fold.words,
        {{observer::Mode::per_use, 10000000000ull, 10000000000ull},
        reinterpret_cast<native::platform::CodeAddress>(GetProcAddress(module, "measurement_target")), subject_instance});
    require(created.error.code == observer::Status::ok, "authenticated observer creation");
    auto lease = created.owner.lease(); auto snapshot = observer::observe(lease);
#if defined(PYOBF_TEST_MEASURED_CONTRIBUTION)
    const auto expected = read(argv[6]);
    if (identity.stage != 2) {
        const auto result = native::contribution::measured::derive(fold, record, snapshot, 1, {1, 1, 1, 1, 0});
        require(result.status == native::contribution::measured::Status::invalid_stage && result.value.word == 0,
            "pre-release material admitted as post-release contribution");
        require(FreeLibrary(module) != 0, "pre-stage external module release"); return 0;
    }
    check_contributions(fold, record, snapshot, expected, true);
#if defined(PYOBF_TEST_MEASURED_SCOPE)
    std::uint32_t expected_word = 0;
    for (unsigned byte = 0; byte != 4; ++byte) expected_word |= std::uint32_t(expected[24 + byte]) << (byte * 8);
    const auto scope_material = read(argv[7]);
    check_scopes(parent.owner, lease, fold, scope_material, identity, expected_word, scope_bad ? 1u : scope_digest ? 2u : 0u,
        argc == base_arguments + 1 && std::strcmp(argv[base_arguments], "cost") == 0);
#endif
#endif
    std::uint8_t key[32]; std::memset(key, 0xa5, sizeof(key));
    require(measured::reconstruct(fold, record, snapshot, key).status == measured::Status::ok && decrypt(key, sealed),
        "actual digest did not release child"); PYOBF_NATIVE_ERASE(key, sizeof(key));
    if (bypass) {
        // The driver replaces Snapshot::check after emission and deliberately bypasses
        // the final gate. Changing data must still lose the crypto key, even with that oracle.
        const auto original = snapshot.data();
        for (unsigned index = 0; index != 116; ++index) for (unsigned bit = 0; bit != 8; ++bit) {
            auto changed_fold = fold;
            auto &data = const_cast<observer::Observation &>(snapshot.data()); data = original;
            auto *byte = index < 32 ? reinterpret_cast<std::uint8_t *>(changed_fold.words) + index :
                index < 84 ? reinterpret_cast<std::uint8_t *>(&data.identity) + index - 32 : data.measured.digest + index - 84;
            *byte ^= static_cast<std::uint8_t>(1u << bit);
            const auto status = measured::reconstruct(changed_fold, record, snapshot, key).status;
            if (status == measured::Status::ok) require(!decrypt(key, sealed), "patched validation manufactured correct key from wrong actual input");
            else { require(status == measured::Status::invalid_identity, "bypass fixture did not actually bypass snapshot validation"); blank(key); }
#if defined(PYOBF_TEST_MEASURED_CONTRIBUTION)
            check_contributions(changed_fold, record, snapshot, expected, false);
#endif
            PYOBF_NATIVE_ERASE(key, sizeof(key));
        }
        const_cast<observer::Observation &>(snapshot.data()) = original;
        require(FreeLibrary(module) != 0, "bypass external module release");
        std::puts("patched snapshot validation cannot manufacture a key for928 changed actual input bits"); return 0;
    }
    if (argc == base_arguments + 1 && !scoped_mode) {
        LARGE_INTEGER frequency{}, begin{}, end{}; require(QueryPerformanceFrequency(&frequency) != 0, "cost frequency");
        for (unsigned batch = 0; batch != 7; ++batch) {
            require(QueryPerformanceCounter(&begin) != 0, "cost start");
            for (unsigned call = 0; call != 128; ++call) {
#if defined(PYOBF_TEST_MEASURED_CONTRIBUTION)
                const auto result = native::contribution::measured::derive(fold, record, snapshot, 7, {3, 5, 7, 11, 13});
                require(result.status == native::contribution::measured::Status::ok && result.value.word != 0, "hot material-to-word derivation");
#else
                require(measured::reconstruct(fold, record, snapshot, key).status == measured::Status::ok, "hot key expansion");
#endif
                PYOBF_NATIVE_ERASE(key, sizeof(key));
            }
            require(QueryPerformanceCounter(&end) != 0, "cost end");
            std::printf("cost %.3f\n", double(end.QuadPart - begin.QuadPart) * 1e9 / double(frequency.QuadPart) / 128.0);
        }
    }
    for (unsigned index = 0; index != 64; ++index) {
        auto changed = record; reinterpret_cast<std::uint8_t *>(&changed)[index] ^= 1;
        std::memset(key, 0xa5, sizeof(key));
        const auto status = measured::reconstruct(fold, changed, snapshot, key).status;
        if (index >= 24 && index < 56) require(status == measured::Status::ok && !decrypt(key, sealed), "wrong mask decrypted child");
        else { require(status == measured::Status::invalid_record, "malformed record accepted"); blank(key); }
#if defined(PYOBF_TEST_MEASURED_CONTRIBUTION)
        check_contributions(fold, changed, snapshot, expected, false);
#endif
        PYOBF_NATIVE_ERASE(key, sizeof(key));
    }
    auto legacy = record; legacy.magic[14] = '1'; legacy.version = 1;
    require(measured::reconstruct(fold, legacy, snapshot, key).status == measured::Status::invalid_record, "fold-only fallback"); blank(key);
    auto wrong_fold = fold; wrong_fold.words[7] ^= 1;
    require(measured::reconstruct(wrong_fold, record, snapshot, key).status == measured::Status::ok && !decrypt(key, sealed),
        "wrong actual fold decrypted child"); PYOBF_NATIVE_ERASE(key, sizeof(key));
#if defined(PYOBF_TEST_MEASURED_CONTRIBUTION)
    check_contributions(fold, legacy, snapshot, expected, false);
    check_contributions(wrong_fold, record, snapshot, expected, false);
#endif
    observer::Snapshot missing;
    require(measured::reconstruct(fold, record, missing, key).status == measured::Status::observation_failed, "missing observation"); blank(key);
    observer::invalidate(lease);
    const auto denied = measured::reconstruct(fold, record, snapshot, key);
    require(denied.status == measured::Status::observation_failed && denied.observation.code == observer::Status::revoked,
        "revoked origin granted key"); blank(key);
#if defined(PYOBF_TEST_MEASURED_CONTRIBUTION)
    check_contributions(fold, record, snapshot, expected, false);
#endif
    require(FreeLibrary(module) != 0, "external module release");
    std::puts("measured actual code/AEAD release,64 record mutations,v1 refusal,wrong fold,missing/revoked origin pass");
}
