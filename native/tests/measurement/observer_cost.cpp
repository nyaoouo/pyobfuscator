#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "measurement/observer.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <utility>

namespace native = pyobfuscator::native;
namespace observer = native::measurement::observer;
namespace reference = native::measurement::reference;
namespace {
void require(bool value) { if (!value) std::exit(1); }
std::vector<std::uint8_t> read(const std::string &path) {
    auto *file = std::fopen(path.c_str(), "rb"); require(file != nullptr);
    std::vector<std::uint8_t> result;
    for (int byte; (byte = std::fgetc(file)) != EOF;) {
        require(result.size() < 512 * 1024); result.push_back(static_cast<std::uint8_t>(byte));
    }
    require(!std::ferror(file) && std::fclose(file) == 0); return result;
}
struct Input { reference::Identity identity{}; std::uint32_t words[8]{}; std::vector<std::uint8_t> package; };
observer::Creation make(const Input &input, observer::Mode mode, native::platform::CodeAddress member) {
    return observer::create(input.package.data(), input.package.size(), input.identity, input.words,
        {{mode, mode == observer::Mode::once_per_instance ? 0ull : 10000000000ull, 10000000000ull}, member, 1});
}
volatile std::uint32_t consumed = 0;
void use(const native::BootstrapContextLease &lease) {
    auto snapshot = observer::observe(lease);
    require(snapshot.check().error.code == observer::Status::ok);
    consumed ^= snapshot.data().measured.digest[0];
}
}
int main(int argc, char **argv) {
    require(argc == 3);
    auto module = LoadLibraryA(argv[2]); require(module != nullptr);
    const auto member = reinterpret_cast<native::platform::CodeAddress>(GetProcAddress(module, "measurement_target"));
    require(member != nullptr);
    Input inputs[4];
    for (unsigned index = 0; index != 4; ++index) {
        const auto base = std::string(argv[1]) + "/" + std::to_string(7 + index);
        auto meta = read(base + ".meta"); require(meta.size() == 84);
        std::memcpy(&inputs[index].identity, meta.data(), 52); std::memcpy(inputs[index].words, meta.data() + 52, 32);
        inputs[index].package = read(base + ".bin");
    }
    LARGE_INTEGER frequency{}; require(QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0);
    for (unsigned mode = 0; mode != 3; ++mode) for (unsigned count : {1u, 4u}) {
        native::BootstrapContextOwner owners[4]; native::BootstrapContextLease leases[4];
        for (unsigned index = 0; index != count; ++index) {
            auto made = make(inputs[index], static_cast<observer::Mode>(mode), member);
            require(made.error.code == observer::Status::ok); owners[index] = std::move(made.owner);
            leases[index] = owners[index].lease(); use(leases[index]);
        }
        for (unsigned cold = 0; cold != 2; ++cold) for (unsigned batch = 0; batch != 7; ++batch) {
            LARGE_INTEGER begin{}, end{}; require(QueryPerformanceCounter(&begin));
            for (unsigned group = 0; group != 32; ++group) for (unsigned index = 0; index != count; ++index) {
                if (cold) {
                    auto made = make(inputs[index], static_cast<observer::Mode>(mode), member);
                    require(made.error.code == observer::Status::ok); use(made.owner.lease());
                } else use(leases[index]);
            }
            require(QueryPerformanceCounter(&end) && end.QuadPart >= begin.QuadPart);
            std::printf("cost %u %u %u %.3f\n", mode, count, cold,
                double(end.QuadPart - begin.QuadPart) * 1e9 / double(frequency.QuadPart) / 32.0);
        }
    }
    require(FreeLibrary(module));
}
