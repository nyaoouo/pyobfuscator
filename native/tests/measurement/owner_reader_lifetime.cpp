#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "measurement/observer_internal.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace native = pyobfuscator::native;
namespace measurement = native::measurement;
namespace observer = measurement::observer;
namespace {
HMODULE borrowed_module = nullptr;
unsigned missing_pin = 0;
void require(bool value, const char *message) {
    if (!value) { std::fprintf(stderr, "reader lifetime: %s\n", message); std::exit(1); }
}
std::vector<std::uint8_t> read(const char *path) {
    auto *file = std::fopen(path, "rb"); require(file != nullptr, "input open");
    std::vector<std::uint8_t> data;
    for (int value; (value = std::fgetc(file)) != EOF;) {
        require(data.size() < 512 * 1024, "input size"); data.push_back(static_cast<std::uint8_t>(value));
    }
    require(!std::ferror(file) && std::fclose(file) == 0, "input close"); return data;
}
using Factory = const observer::ReaderBinding *(*)(unsigned *) noexcept;
Factory factory(HMODULE module) {
    auto result = reinterpret_cast<Factory>(GetProcAddress(module, "pyobf_test_owner_readers"));
    require(result != nullptr, "private same-build factory"); return result;
}
void exercise(const char *a, const char *b, bool split, native::platform::CodeAddress member,
        const measurement::reference::Identity &identity, const std::uint32_t (&words)[8],
        const std::vector<std::uint8_t> &package, const std::uint8_t *expected) {
    unsigned detached_a = 0, detached_b = 0;
    const auto module_a = LoadLibraryA(a); require(module_a != nullptr, "capture module");
    const auto module_b = split ? LoadLibraryA(b) : module_a;
    require(module_b != nullptr && (!split || module_b != module_a), "independently loaded codec module");
    auto binding = *factory(module_a)(&detached_a);
    if (split) binding.cache_codec = factory(module_b)(&detached_b)->cache_codec;
    const auto capture = binding.capture; const auto codec = binding.cache_codec; const auto key = binding.key;
    borrowed_module = missing_pin == 1 ? module_a : missing_pin == 2 ? module_b : nullptr;
    auto made = observer::create(package.data(), package.size(), identity, words,
        {{observer::Mode::once_per_instance, 0, 10000000000ull}, member, 1, &binding});
    require(made.error.code == observer::Status::ok, "owned reader creation");
    auto lease = made.owner.lease();
    const auto &state = *static_cast<observer::detail::State *>(native::detail::BootstrapContextAccess::state(lease)->spec.user_data);
    require(state.spec.reader == nullptr && state.reader.capture == capture && state.reader.cache_codec == codec &&
        state.reader.key == key && state.reader_code.module == module_a && state.codec_code.module == module_b,
        "both actual callback origins must be copied and pinned");
    binding = {};
    require(FreeLibrary(module_a) != 0 && (!split || FreeLibrary(module_b) != 0), "drop caller module ownership");
    require(detached_a == 0, "capture module detached before first observation");
    require(detached_b == 0, "codec module detached before first observation");
    auto held = observer::observe(lease);
    require(held.check().error.code == observer::Status::ok && !held.reused() &&
        std::memcmp(held.data().measured.digest, expected, 32) == 0 &&
        std::memcmp(state.cached.measured.digest, expected, 32) != 0, "actual cross-DLL CNG and encoded cache");
    {
        auto hit = observer::observe(lease), refreshed = observer::observe(lease, true);
        require(hit.reused() && !refreshed.reused() && hit.data().sequence == held.data().sequence &&
            refreshed.data().sequence > held.data().sequence && hit.check().error.code == observer::Status::ok &&
            refreshed.check().error.code == observer::Status::ok && held.check().error.code == observer::Status::ok &&
            std::memcmp(hit.data().measured.digest, expected, 32) == 0 &&
            std::memcmp(refreshed.data().measured.digest, expected, 32) == 0, "live callback reads/decoding and immutable old snapshot");
    }
    made.owner.close(); lease.reset(); made.owner = {};
    require(held.check().error.code == observer::Status::closed && detached_a == 0 && detached_b == 0,
        "last snapshot must retain both modules after owner close");
    held.reset();
    require(detached_a == 1 && detached_b == (split ? 1u : 0u), "each module must detach once after the final snapshot");
}
}
namespace pyobfuscator::native::platform {
CodeLease retain_code_actual(CodeAddress) noexcept;
CodeLease retain_code(CodeAddress address) noexcept {
    HMODULE module = nullptr;
    require(GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(address), &module) != 0, "actual callback code origin");
    // A borrowed but correctly addressed handle must not pass the lifetime proof.
    if (module == borrowed_module) return {module};
    return retain_code_actual(address);
}
}
int main(int argc, char **argv) {
    require(argc == 6 || argc == 7, "metadata/package/subject/two callback modules/optional pin fault");
    if (argc == 7) {
        require(std::strcmp(argv[6], "borrow-capture") == 0 || std::strcmp(argv[6], "borrow-codec") == 0, "pin fault mode");
        missing_pin = std::strcmp(argv[6], "borrow-capture") == 0 ? 1 : 2;
    }
    const auto metadata = read(argv[1]), package = read(argv[2]); require(metadata.size() == 116, "metadata shape");
    measurement::reference::Identity identity{}; std::uint32_t words[8]{};
    std::memcpy(&identity, metadata.data(), 52); std::memcpy(words, metadata.data() + 52, 32);
    const auto subject = LoadLibraryA(argv[3]); require(subject != nullptr, "actual measured subject");
    const auto member = reinterpret_cast<native::platform::CodeAddress>(GetProcAddress(subject, "measurement_target"));
    require(member != nullptr, "subject module anchor");
    if (missing_pin) exercise(argv[4], argv[5], true, member, identity, words, package, metadata.data() + 84);
    else for (bool split : {false, true}) exercise(argv[4], argv[5], split, member, identity, words, package, metadata.data() + 84);
    require(FreeLibrary(subject) != 0, "subject release");
    std::puts("same/split callback DLLs: actual CNG read/cache/refresh after caller unload, immutable snapshot pins and exact final detach pass");
}
