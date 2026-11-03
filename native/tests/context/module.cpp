#include "checks.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace context_test {
void check_provider(const char *path) {
    const auto module = LoadLibraryA(path);
    require(module != nullptr, "actual provider DLL loaded");
    using Factory = void (*)(std::atomic<unsigned> *, BootstrapContextSpec *) noexcept;
    const auto factory = reinterpret_cast<Factory>(GetProcAddress(module, "context_provider"));
    require(factory != nullptr, "actual provider factory found");
    std::atomic<unsigned> destroyed{0};
    BootstrapContextSpec spec;
    factory(&destroyed, &spec);
    auto created = create_bootstrap_context(spec);
    require(created.status == Status::ok, "provider code references acquired");
    auto lease = created.owner.lease();
    require(FreeLibrary(module) != 0, "caller loader reference released");
    require(GetModuleHandleA(path) != nullptr, "registered callbacks retain the provider");
    require(lease.invoke({7}).value == 107, "callback runs after caller unload");
    created.owner = {};
    require(destroyed.load() == 0 && GetModuleHandleA(path) != nullptr, "closed lease retains callback/destructor");
    require(lease.invoke({7}).status == Status::closed, "retained module does not reopen context");
    lease.reset();
    require(destroyed.load() == 1 && GetModuleHandleA(path) == nullptr, "final release destroys then unloads provider");
}
}  // namespace context_test
