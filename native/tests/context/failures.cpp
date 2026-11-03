#include "checks.hpp"
#include "context/runtime.hpp"
#include "context/publication.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"

#include <limits>
#include <thread>

namespace {
bool allocation_fails = false;
unsigned fail_pin = 0, allocations = 0, frees = 0, pins = 0, unpins = 0, destroys = 0;
std::size_t allocation_size = 0;
}

// Deliberately isolated test backend: production sources still use semantic operations.
namespace pyobfuscator::native::platform {
void *allocate(std::size_t size) noexcept {
    ++allocations;
    allocation_size = size;
    return allocation_fails ? nullptr : std::malloc(size);
}
void erase(void *memory, std::size_t size) noexcept {
    auto *bytes = static_cast<volatile unsigned char *>(memory);
    while (size != 0) bytes[--size] = 0;
}
void release(void *memory) noexcept {
    const auto *bytes = static_cast<const unsigned char *>(memory);
    for (std::size_t i = 0; i != allocation_size; ++i)
        context_test::require(bytes[i] == 0, "control block erased before free");
    ++frees;
    std::free(memory);
}
CodeLease retain_code(CodeAddress) noexcept {
    ++pins;
    return pins == fail_pin ? CodeLease{} : CodeLease{reinterpret_cast<void *>(std::uintptr_t{pins})};
}
bool release_code(CodeLease lease) noexcept { if (lease.module != nullptr) ++unpins; return true; }
std::uint32_t atomic_compare_exchange32(AtomicWord32 *word, std::uint32_t expected, std::uint32_t desired) noexcept {
    word->compare_exchange_strong(expected, desired);
    return expected;
}
void atomic_store32(AtomicWord32 *word, std::uint32_t value) noexcept { word->store(value); }
void spin_pause() noexcept { std::this_thread::yield(); }
[[noreturn]] void protection_failure(std::uint32_t) noexcept { std::abort(); }
}  // namespace pyobfuscator::native::platform

namespace {
using namespace context_test;
BootstrapContextResult dispatch(const BootstrapContextRequest &, void *) noexcept { return {Status::ok, 11}; }
void destroy(void *) noexcept { ++destroys; }
void reset() { allocations = frees = pins = unpins = destroys = 0; allocation_fails = false; fail_pin = 0; }
}

int main() {
    using namespace context_test;
    int state = 0;
    const BootstrapContextSpec spec{bootstrap_context_abi_version, dispatch, &state, destroy};
    allocation_fails = true;
    require(create_bootstrap_context(spec).status == Status::allocation_failed, "allocation failure explicit");
    require(pins == 0 && frees == 0 && destroys == 0, "failed allocation never adopts state");
    reset();
    fail_pin = 1;
    require(create_bootstrap_context(spec).status == Status::code_unavailable, "dispatch provider failure explicit");
    require(frees == 1 && unpins == 0 && destroys == 0, "first pin failure cleans allocation only");
    reset();
    fail_pin = 2;
    require(create_bootstrap_context(spec).status == Status::code_unavailable, "destroy provider failure explicit");
    require(frees == 1 && unpins == 1 && destroys == 0, "partial provider acquisition balanced without adoption");
    reset();
    {
        auto created = create_bootstrap_context(spec);
        require(created.status == Status::ok, "mock provider success");
        auto lease = created.owner.lease();
        created.owner = {};
        require(frees == 0 && destroys == 0, "closed lease delays cleanup");
        lease.reset();
    }
    require(frees == 1 && unpins == 2 && destroys == 1, "all resources released once");

    reset();
    {
        auto created = create_bootstrap_context(spec);
        auto expected = created.owner.lease();
        auto scope = bind_bootstrap_context(expected);
        require(scope.status == Status::ok, "failure fixture publication");
        auto &slot = detail::context_publication();
        auto *context = slot.context;
        const auto references = context->references;
        context->references = std::numeric_limits<std::uint32_t>::max();
        require(call_bound_bootstrap(expected, {1}).status == Status::reference_limit,
                "bound call cannot overflow captured lease reference");
        context->references = references;
        detail::release_publication(&slot, slot.serial + 1);
        require(call_bound_bootstrap(expected, {1}).value == 11, "foreign publication serial cannot clear current scope");
        scope.binding.reset();
        const auto unpublished_references = context->references;
        context->references = std::numeric_limits<std::uint32_t>::max();
        require(bind_bootstrap_context(expected).status == Status::reference_limit && slot.context == nullptr,
                "failed retain never publishes partial scope");
        context->references = unpublished_references;
        fail_pin = pins + 1;
        require(bind_bootstrap_context(expected).status == Status::code_unavailable && slot.context == nullptr &&
                context->references == unpublished_references, "publication-provider failure balances context reference");
        fail_pin = 0;
        slot.serial = std::numeric_limits<std::uint64_t>::max();
        require(bind_bootstrap_context(expected).status == Status::generation_exhausted && slot.context == nullptr &&
                context->references == unpublished_references, "publication exhaustion balances retained reference");
        require(bind_bootstrap_context(expected).status == Status::generation_exhausted,
                "publication serial cannot wrap or resume");
    }
    require(frees == 1 && unpins == pins - 1 && destroys == 1, "failed publication retains no state or provider leak");

    detail::BootstrapContextState bounded{spec, 1, {}};
    bounded.references = std::numeric_limits<std::uint32_t>::max();
    require(detail::retain_context(&bounded, true) == Status::reference_limit, "reference overflow rejected");
    require(detail::admit_context_call(&bounded) == Status::reference_limit, "frame reference overflow rejected");
    bounded.references = 1;
    bounded.active_calls = std::numeric_limits<std::uint32_t>::max();
    require(detail::admit_context_call(&bounded) == Status::reference_limit, "active frame overflow rejected");
    bounded.closing = true;
    require(detail::retain_context(&bounded, false) == Status::closed, "close wins admission");
    auto counter = std::numeric_limits<std::uint64_t>::max() - 1;
    require(detail::advance_context_generation(counter) == std::numeric_limits<std::uint64_t>::max(),
            "last generation issued once");
    require(detail::advance_context_generation(counter) == 0 &&
            detail::advance_context_generation(counter) == 0, "generation exhaustion cannot wrap or resume");
    std::puts("owned context failure boundaries verified");
}
