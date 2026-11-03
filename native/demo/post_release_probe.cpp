#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "bootstrap/flow.hpp"
#include "context/runtime.hpp"
#include "contribution/protocol.hpp"
#include "measurement/observer_internal.hpp"
#include "post_profile.hpp"
#include "owner_readers.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace native = pyobfuscator::native;
namespace demo = native::demo;
namespace observer = native::measurement::observer;
namespace scoped = native::contribution::scoped;
namespace {
void require(bool value, const char *message) {
    if (!value) { std::fprintf(stderr, "post release: %s\n", message); std::exit(1); }
}
unsigned allocations = 0, fail_at = 0, live = 0;
demo::RuntimeSession *active = nullptr;
demo::InnerEntry entry = nullptr;
const demo::PayloadHandoff *handoff = nullptr;
const char *mode = nullptr;
unsigned effects = 0;
bool failure_seen = false;
bool fail_hash = false, fail_clock = false;
unsigned code_reads = 0;
struct Replay { observer::detail::Response response{}; };
void replay_destroy(void *) noexcept {}
native::BootstrapContextResult replay_observation(const native::BootstrapContextRequest &request, void *opaque) noexcept {
    if (request.operation_id != observer::detail::operation || request.input == nullptr ||
            request.input_size != sizeof(observer::detail::Request)) return {native::BootstrapContextStatus::invalid_request, 0};
    const auto &message = *static_cast<const observer::detail::Request *>(request.input);
    if (message.version != observer::detail::version || message.size != sizeof(message) || message.output == nullptr)
        return {native::BootstrapContextStatus::invalid_request, 0};
    *message.output = static_cast<Replay *>(opaque)->response;
    return {native::BootstrapContextStatus::ok, observer::detail::reply};
}
std::uint64_t foreign_generation = 0;
native::BootstrapContextResult foreign_admission(const native::BootstrapContextRequest &, void *) noexcept {
    return {native::BootstrapContextStatus::ok, foreign_generation};
}
HMODULE foreign_context(demo::RuntimeSession &session, const char *path, native::BootstrapContextCreation &foreign) {
    const auto module = LoadLibraryA(path); require(module != nullptr, "foreign context module");
    using Factory = void (*)(const native::BootstrapContextSpec *, native::BootstrapContextCreation *) noexcept;
    const auto factory = reinterpret_cast<Factory>(GetProcAddress(module, "pyobf_test_foreign_context"));
    require(factory != nullptr, "foreign factory");
    const native::BootstrapContextSpec spec{native::bootstrap_context_abi_version, foreign_admission};
    factory(&spec, &foreign);
    require(foreign.status == native::BootstrapContextStatus::ok &&
        foreign.owner.generation() == session.context->generation, "actual cross-module generation collision");
    // A single foreign SDK state uses the same process heap, then the host's final release.
    ++live;
    foreign_generation = session.context->generation;
    session.expected = foreign.owner.lease();
    return module;
}
void finish_foreign(demo::RuntimeSession &session, native::BootstrapContextCreation &foreign, HMODULE module) {
    demo::retire_payload(session);
    foreign.owner.close(); session.expected.reset(); foreign.owner = {};
    session.owner = {}; session.context = nullptr;
    require(live == 0 && FreeLibrary(module) != 0, "foreign/parent preparation cleanup");
    std::puts("foreign-origin-denied");
}
observer::detail::State &state(const native::BootstrapContextLease &lease) {
    return *static_cast<observer::detail::State *>(native::detail::BootstrapContextAccess::state(lease)->spec.user_data);
}
unsigned references(const native::BootstrapContextLease &lease) {
    const auto *state = native::detail::BootstrapContextAccess::state(lease);
    require(state != nullptr && state->active_calls == 0, "reference sample outside call quiescence");
    return state->references;
}
void observe(std::uint32_t stage, void *) {
    std::printf("stage:%u\n", stage); std::fflush(stdout);
    if (stage != 7) return;
    ++effects;
    if (std::strcmp(mode, "synthetic-observer") == 0) {
        require(code_reads == 1, "synthetic origin must not count as a real parent read");
        std::puts("synthetic-source-effect"); return;
    }
    require(code_reads == 2, "both invocation observations must perform an actual fresh code digest");
    require(references(active->expected) == 5, "both operations must pin parent through the user effect");
    const bool borrowed_inner = std::strcmp(mode, "inner-owner") == 0;
    require(references(active->post.leases[0]) == (borrowed_inner ? 4u : 3u) &&
        references(active->post.leases[1]) == (borrowed_inner ? 2u : 3u),
        "each actual observation must survive the user effect");
    const auto &parent = state(active->post.leases[0]), &application = state(active->post.leases[1]);
    require(&parent != &application && &parent.cached != &application.cached && parent.view.base != application.view.base &&
        parent.has_cache && (borrowed_inner ? !application.has_cache : application.has_cache &&
            parent.cached.instance != application.cached.instance),
        "distinct actual parent/inner reads and cache storage");
    if (std::strcmp(mode, "unwind") == 0) throw 1777;
    if (std::strcmp(mode, "reentrant") == 0)
        require(entry(handoff, 5) == -100 && effects == 1, "reentry replaced active publication/scopes");
}
__attribute__((noinline, used)) int unused_anchor(int value) { return value + 0x1234567; }
void change_code(void *address) {
    DWORD previous = 0, ignored = 0;
    require(VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &previous) != 0, "test code mutation permission");
    *static_cast<volatile unsigned char *>(address) ^= 1;
    require(VirtualProtect(address, 1, previous, &ignored) != 0, "restore measured executable permissions");
    require(FlushInstructionCache(GetCurrentProcess(), address, 1) != 0, "test mutation visibility");
}
void *change_subject(const native::BootstrapContextLease &lease, unsigned index) {
    const auto &owner = state(lease);
    const auto &descriptor = owner.reference.descriptor();
    require(index < descriptor.range_count, "explicit actual subject range");
    const auto &range = descriptor.ranges[index];
    require(range.size != 0 && range.rva <= owner.view.image_size &&
        range.size <= owner.view.image_size - range.rva, "actual owned range extent");
    auto *address = const_cast<std::uint8_t *>(owner.view.base) + range.rva + range.size - 1;
    change_code(address);
    return address;
}
void admission(demo::RuntimeSession &session) {
    const auto &spec = session.post.handoff.roles[0].spec;
    scoped::Admission request{scoped::admission_version, sizeof(scoped::Admission), spec.routing, spec.domain,
        spec.function, spec.source, session.context->generation, spec.function, 0,
        session.post.leases[0].generation(),
        reinterpret_cast<std::uintptr_t>(native::detail::BootstrapContextAccess::state(session.post.leases[0]))};
    const auto invoke = [&] { return session.expected.invoke({spec.routing, &request, sizeof(request)}); };
    auto reply = invoke();
    require(reply.status == native::BootstrapContextStatus::unavailable && reply.value == 0, "pre-entry admission");
    const demo::LifecycleMessage enter{session.context->generation, spec.routing, demo::LifecycleOperation::enter_payload};
    require(session.expected.invoke({spec.routing, &enter, sizeof(enter)}).status == native::BootstrapContextStatus::ok,
        "actual enter transition");
    reply = invoke();
    require(reply.status == native::BootstrapContextStatus::ok && reply.value == session.context->generation,
        "admission returns only the live generation");
    const auto original = request;
    for (unsigned field = 0; field != 12; ++field) {
        request = original;
        switch (field) {
        case 0: ++request.version; break; case 1: --request.size; break;
        case 2: request.routing ^= 1; break; case 3: request.domain ^= 1; break;
        case 4: request.function ^= 1; break; case 5: request.source ^= 1; break;
        case 6: ++request.generation; break; case 7: request.observation_owner ^= 1; break;
        case 8: request.reserved = 1; break; case 9: request.function = request.observation_owner = 0; break;
        case 10: ++request.observation_instance; break; case 11: request.observation_context ^= 1; break;
        }
        reply = invoke();
        require(reply.status != native::BootstrapContextStatus::ok && reply.value == 0, "forged role admission");
    }
    request = original;
    for (unsigned phase = 0; phase != 8; ++phase) {
        PYOBF_NATIVE_ATOMIC_STORE32(&session.context->phase, phase);
        reply = invoke();
        require((reply.status == native::BootstrapContextStatus::ok) ==
            (phase == static_cast<unsigned>(demo::LifecyclePhase::payload_entered)), "wrong phase admission");
        if (reply.status != native::BootstrapContextStatus::ok) require(reply.value == 0, "failed phase supplied a word");
    }
    PYOBF_NATIVE_ATOMIC_STORE32(&session.context->phase, static_cast<unsigned>(demo::LifecyclePhase::payload_entered));
    native::contribution::Message legacy{};
    legacy.version = native::contribution::context_protocol_version; legacy.size = sizeof(legacy);
    legacy.routing_tag = spec.routing; legacy.generation = session.context->generation;
    reply = session.expected.invoke({spec.routing, &legacy, sizeof(legacy)});
    require(reply.status == native::BootstrapContextStatus::invalid_request && reply.value == 0, "legacy correct-word oracle");
}
}
namespace pyobfuscator::native::platform {
void *allocate_actual(std::size_t) noexcept;
void release_actual(void *) noexcept;
bool hash_sha256_actual(const std::uint8_t *, std::size_t, std::uint8_t *) noexcept;
bool measurement_clock_actual(measurement::ClockSample &) noexcept;
bool hash_sha256(const std::uint8_t *input, std::size_t size, std::uint8_t *output) noexcept {
    constexpr char domain[] = "pyobf.native.code.observation.v1";
    if (size >= sizeof(domain) && std::memcmp(input, domain, sizeof(domain)) == 0) {
        ++code_reads;
        if (fail_hash) { std::memset(output, 0xdd, 32); return false; }
    }
    return hash_sha256_actual(input, size, output);
}
bool measurement_clock(measurement::ClockSample &output) noexcept {
    if (fail_clock) { output = {}; return false; }
    return measurement_clock_actual(output);
}
void *allocate(std::size_t size) noexcept {
    if (fail_at != 0 && ++allocations == fail_at) { failure_seen = true; return nullptr; }
    auto *memory = allocate_actual(size); if (memory != nullptr) ++live; return memory;
}
void release(void *memory) noexcept {
    if (memory != nullptr) { require(live != 0, "unpaired host release"); --live; }
    release_actual(memory);
}
}
int main(int argc, char **argv) {
    require(argc == 2 || argc == 3, "explicit probe mode"); mode = argv[1];
    {
        demo::RuntimeSession session; active = &session;
        require(demo::initialize_session(session, observe, nullptr), "owned parent");
#if defined(PYOBF_POST_PROBE_ALLOW_UNAVAILABLE)
        // Reach post consumption in the fixture; actual strict DLL admission is tested separately.
        session.context->config.allow_unavailable = true;
#endif
        if (std::strcmp(mode, "unprepared") == 0) {
            require(!demo::prepare_post(session, reinterpret_cast<native::platform::CodeAddress>(&unused_anchor)) &&
                session.post.stage_status == native::BootstrapContextStatus::invalid_request, "unprepared post stage");
        } else {
            require(demo::pass_environment_gate(session.context) && demo::prepare_support(session), "real early gates");
#if defined(PYOBF_DEMO_PRE_CODE_HASH)
            if (std::strcmp(mode, "foreign-key") == 0) {
                require(argc == 3, "foreign key context DLL supplied");
                native::BootstrapContextCreation foreign;
                const auto module = foreign_context(session, argv[2], foreign);
                require(demo::release_and_load_payload(false, session) == -8 &&
                    session.code_stage_status == native::BootstrapContextStatus::context_mismatch &&
                    session.image == nullptr && session.code_owner.generation() == 0,
                    "foreign origin with equal generation bypassed measured key admission");
                finish_foreign(session, foreign, module); return 0;
            }
#endif
            require(demo::release_and_load_payload(false, session) == 0, "real release and loader");
            entry = reinterpret_cast<demo::InnerEntry>(PYOBF_NATIVE_RESOLVE(session.image)); require(entry != nullptr, "real child export");
            if (std::strcmp(mode, "foreign-generation") == 0 || std::strcmp(mode, "foreign-ready") == 0) {
                require(argc == 3, "foreign context DLL supplied");
                native::BootstrapContextCreation foreign;
                const auto module = foreign_context(session, argv[2], foreign);
                if (std::strcmp(mode, "foreign-ready") == 0) {
#if defined(PYOBF_DEMO_PRE_CODE_HASH)
                    require(!demo::measured_release_is_ready(session) &&
                        session.code_stage_status == native::BootstrapContextStatus::context_mismatch,
                        "foreign origin with equal generation bypassed measured readiness");
#else
                    require(false, "measured readiness needs its actual pre-release profile");
#endif
                } else require(!demo::prepare_post(session, reinterpret_cast<native::platform::CodeAddress>(entry)) &&
                        session.post.stage_status == native::BootstrapContextStatus::context_mismatch,
                        "foreign origin with equal generation bypassed post-stage admission");
                finish_foreign(session, foreign, module); return 0;
            }
            const auto baseline = live;
            if (std::strcmp(mode, "oom") == 0) {
                require(argc == 3, "OOM ordinal"); fail_at = static_cast<unsigned>(std::atoi(argv[2])); require(fail_at != 0, "positive OOM ordinal");
            }
            const auto ready = demo::prepare_post(session, reinterpret_cast<native::platform::CodeAddress>(entry));
            fail_at = 0;
            if (failure_seen) {
                require(!ready && live == baseline && PYOBF_NATIVE_ATOMIC_LOAD32(&session.context->post_ready) == 3,
                    "partial two-owner preparation did not roll back");
                for (unsigned index = 0; index != 2; ++index)
                    require(session.post.owners[index].generation() == 0 && session.post.leases[index].generation() == 0,
                        "partial owner/lease survived failure");
                require(session.post.preparation[0].code != observer::Status::ok ||
                    session.post.preparation[1].code != observer::Status::ok, "preparation error provenance");
                std::puts("oom-denied");
            } else {
                require(ready, "two-role preparation");
                for (unsigned index = 0; index != 2; ++index) {
#if defined(PYOBF_DEMO_PRE_CODE_HASH)
                    constexpr unsigned first = 1;
#else
                    constexpr unsigned first = 0;
#endif
                    const auto &owned = state(session.post.leases[index]);
                    const auto &binding = native::measurement::generated_readers::bindings[first + index];
                    require(owned.spec.reader == nullptr && owned.reader.owner == owned.identity.owner &&
                        owned.reader.key == binding.key && owned.reader.capture == binding.capture &&
                        owned.reader.cache_codec == binding.cache_codec && owned.reader_code.module != nullptr &&
                        owned.codec_code.module != nullptr, "production owner lost its exact copied/pinned reader domain");
                }
                const auto &a = state(session.post.leases[0]).reader, &b = state(session.post.leases[1]).reader;
                require(a.key != b.key && a.capture != b.capture && a.cache_codec != b.cache_codec,
                    "production roles share their reader/codec domains");
                require(session.post.owners[0].generation() != session.post.owners[1].generation(), "shared observation owner");
                for (unsigned index = 0; index != 2; ++index) {
                    const auto &lease = session.post.leases[index];
                    require(references(lease) == 2 &&
                        session.context->post_observation_instances[index] == lease.generation() &&
                        session.context->post_observation_contexts[index] == native::detail::BootstrapContextAccess::state(lease),
                        "exact observation source registration");
                }
                if (std::strcmp(mode, "admission") == 0) admission(session);
                else if (std::strcmp(mode, "repeat") == 0) {
                    const auto first = session.post.owners[0].generation(), second = session.post.owners[1].generation();
                    require(!demo::prepare_post(session, reinterpret_cast<native::platform::CodeAddress>(entry)) &&
                        first == session.post.owners[0].generation() && second == session.post.owners[1].generation(), "repeated preparation replaced owners");
                } else {
                    if (std::strcmp(mode, "reader-key") == 0) ++state(session.post.leases[0]).reader.key;
                    if (std::strcmp(mode, "reader-codec") == 0)
                        state(session.post.leases[0]).reader.cache_codec = state(session.post.leases[1]).reader.cache_codec;
                    if (std::strcmp(mode, "independent") == 0) {
                        auto first = observer::observe(session.post.leases[0]), second = observer::observe(session.post.leases[1]);
                        const auto previous = second.data().sequence;
                        auto refreshed = observer::observe(session.post.leases[0]);
                        require(std::memcmp(state(session.post.leases[0]).cached.measured.digest, refreshed.data().measured.digest, 32) != 0 &&
                            std::memcmp(state(session.post.leases[1]).cached.measured.digest, second.data().measured.digest, 32) != 0,
                            "production cache lost its private encoded representation");
                        require(!first.reused() && !second.reused() && !refreshed.reused() &&
                            refreshed.data().sequence == first.data().sequence + 1 && second.data().sequence == previous &&
                            state(session.post.leases[1]).admitted == previous &&
                            first.check().error.code == observer::Status::ok && second.check().error.code == observer::Status::ok,
                            "one owner refresh changed the other cache or an immutable snapshot");
                    }
                    auto view = demo::make_payload_handoff(session); handoff = &view;
                    auto post = session.post.handoff; view.post = &post;
                    Replay replay;
                    native::BootstrapContextCreation synthetic;
                    native::BootstrapContextLease synthetic_lease;
                    HMODULE synthetic_module = nullptr;
                    if (std::strcmp(mode, "synthetic-observer") == 0) {
                        require(argc == 3, "synthetic source needs an independent SDK factory module");
                        auto original = observer::observe(session.post.leases[0]);
                        replay.response.data = original.data(); replay.response.validation = original.check();
                        require(replay.response.validation.error.code == observer::Status::ok, "actual original evidence");
                        std::memcpy(replay.response.expected, original.reference_digest(), 32);
                        require(observer::invalidate(session.post.leases[0]).code == observer::Status::revoked &&
                            original.check().error.code == observer::Status::revoked, "real observation was not revoked");
                        synthetic_module = LoadLibraryA(argv[2]); require(synthetic_module != nullptr, "synthetic SDK module");
                        using Factory = void (*)(const native::BootstrapContextSpec *, native::BootstrapContextCreation *) noexcept;
                        const auto create = reinterpret_cast<Factory>(GetProcAddress(synthetic_module, "pyobf_test_foreign_context"));
                        require(create != nullptr, "synthetic factory");
                        const native::BootstrapContextSpec spec{native::bootstrap_context_abi_version, replay_observation, &replay, replay_destroy};
                        do {
                            synthetic.owner = {}; create(&spec, &synthetic);
                            require(synthetic.status == native::BootstrapContextStatus::ok, "synthetic context creation");
                            ++live;
                            require(synthetic.owner.generation() <= original.data().instance, "synthetic generation overshot actual origin");
                        } while (synthetic.owner.generation() != original.data().instance);
                        synthetic_lease = synthetic.owner.lease(); post.roles[0].observation = &synthetic_lease;
                        std::puts("synthetic-same-generation-ready");
                    }
                    auto fold = *post.fold;
                    std::uint8_t material[scoped::material_bytes];
                    const unsigned material_role = std::strcmp(mode, "inner-material") == 0 ? 1 : 0;
                    std::memcpy(material, post.roles[material_role].material, sizeof(material));
                    if (std::strcmp(mode, "missing") == 0) view.post = nullptr;
                    if (std::strcmp(mode, "wrong-owner") == 0) post.roles[0].observation = post.roles[1].observation;
                    if (std::strcmp(mode, "inner-owner") == 0) post.roles[1].observation = post.roles[0].observation;
                    if (std::strcmp(mode, "wrong-fold") == 0) { fold.words[0] ^= 1; post.fold = &fold; }
                    if (std::strcmp(mode, "wrong-material") == 0 || std::strcmp(mode, "inner-material") == 0) {
                        material[sizeof(material) - 1] ^= 1; post.roles[material_role].material = material;
                    }
                    void *changed_code = nullptr;
                    const bool parent_code = std::strcmp(mode, "parent-code") == 0, inner_code = std::strcmp(mode, "inner-code") == 0;
                    if (parent_code || inner_code) {
                        require(argc == 3, "explicit subject range ordinal");
                        changed_code = change_subject(session.post.leases[inner_code ? 1 : 0], static_cast<unsigned>(std::strtoul(argv[2], nullptr, 10)));
                    }
                    fail_hash = std::strcmp(mode, "hash-failed") == 0;
                    fail_clock = std::strcmp(mode, "clock-failed") == 0;
                    const bool bad_reader = std::strcmp(mode, "reader-key") == 0 || std::strcmp(mode, "reader-codec") == 0;
                    code_reads = 0;
                    const bool denied = std::strcmp(mode, "missing") == 0 || std::strcmp(mode, "parent-code") == 0 ||
                        std::strcmp(mode, "inner-code") == 0 || fail_hash || fail_clock || bad_reader;
                    bool unwound = false;
                    try { require(entry(&view, 5) == (denied ? -104 : 16), "actual child result"); }
                    catch (int code) { require(std::strcmp(mode, "unwind") == 0 && code == 1777, "actual EH result"); unwound = true; }
                    if (changed_code != nullptr) {
                        const auto role = inner_code ? 1u : 0u;
                        require(state(session.post.leases[role]).failure.code == observer::Status::digest_mismatch &&
                            state(session.post.leases[1u - role]).failure.code == observer::Status::ok && code_reads == 2,
                            "changed subject denied outside its actual independent digest boundary");
                        const auto &descriptor = state(session.post.leases[role]).reference.descriptor();
                        const auto ordinal = static_cast<unsigned>(std::strtoul(argv[2], nullptr, 10));
                        const auto &range = descriptor.ranges[ordinal];
                        std::printf("range-denied:%u:%u:%u:%u\n", descriptor.kind, ordinal, range.rva, range.size);
                        change_code(changed_code);
                    }
                    if (fail_hash || fail_clock) {
                        const auto source = fail_hash ? native::measurement::Status::crypto_failed : native::measurement::Status::clock_failed;
                        for (auto &lease : session.post.leases) {
                            const auto &error = state(lease).failure;
                            require(error.code == observer::Status::capture_failed && error.capture == source,
                                "actual post read failure lost typed provenance");
                        }
                    }
                    if (bad_reader) {
                        const bool key = std::strcmp(mode, "reader-key") == 0;
                        const auto &error = state(session.post.leases[0]).failure;
                        require(error.code == (key ? observer::Status::capture_failed : observer::Status::invalid_snapshot) &&
                            (!key || error.capture == native::measurement::Status::invalid_descriptor) &&
                            state(session.post.leases[1]).failure.code == observer::Status::ok && code_reads == (key ? 1u : 2u),
                            "reader domain failure lost its exact source or denied a peer");
                        std::puts("reader-domain-denied");
                    }
                    fail_hash = fail_clock = false;
                    require(unwound == (std::strcmp(mode, "unwind") == 0) && effects == (denied ? 0u : 1u), "effect/cleanup boundary");
                    for (auto &lease : session.post.leases) require(references(lease) == 2, "operation snapshot leaked past normal/EH return");
                    require(references(session.expected) == 3, "operation parent leases leaked past return");
                    if (synthetic_module != nullptr) {
                        synthetic_lease.reset(); synthetic.owner.close(); synthetic.owner = {};
                        require(FreeLibrary(synthetic_module) != 0, "synthetic source cleanup");
                    }
                }
                const auto retained_role = std::strcmp(mode, "parent-code") == 0 || std::strcmp(mode, "reader-key") == 0 ||
                    std::strcmp(mode, "reader-codec") == 0 || std::strcmp(mode, "synthetic-observer") == 0 ? 1 : 0;
                auto held = observer::observe(session.post.leases[retained_role]);
                const auto original_error = held.check().error.code;
                const bool source_failed = std::strcmp(mode, "hash-failed") == 0 || std::strcmp(mode, "clock-failed") == 0;
                require(original_error == (source_failed ? observer::Status::capture_failed : observer::Status::ok), "held observation before retirement");
                auto retired = session.post.leases[retained_role];
                demo::retire_payload(session);
                for (unsigned index = 0; index != 2; ++index)
                    require(session.context->post_observation_instances[index] == 0 &&
                        session.context->post_observation_contexts[index] == nullptr,
                        "retired observation source registration");
                require(held.check().error.code == (source_failed ? original_error : observer::Status::closed) &&
                    retired.availability() == native::BootstrapContextStatus::closed && session.image == nullptr &&
                    session.publication.binding.generation() == 0 && session.owner.quiescent(), "retired observation/publication/image");
                for (auto &lease : session.post.leases) require(lease.generation() == 0, "retired post lease");
                held.reset();
                retired.reset();
                std::puts("post-verified");
            }
        }
    }
    require(live == 0, "host allocation leak after session destruction");
}
