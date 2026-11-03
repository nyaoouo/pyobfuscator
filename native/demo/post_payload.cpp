#include "post_payload.hpp"
#include "bootstrap/post_handoff.hpp"
#include "post_profile.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

#include <utility>

namespace native = pyobfuscator::native;
namespace demo = native::demo;
namespace scoped = native::contribution::scoped;
namespace observer = native::measurement::observer;
namespace profile = demo::post_profile;
using Lease = native::BootstrapContextLease;

extern "C" {
#if defined(PYOBF_DEMO_POST_MIXED)
static int pyobf_demo_bound_compute(const Lease &, scoped::Scope &, int) __asm__("pyobf_demo_bound_compute");
static PYOBF_NATIVE_CFF int pyobf_demo_bound_compute(const Lease &lease, scoped::Scope &scope, int value) {
    const Lease *volatile retained_lease = &lease;
    scoped::Scope *volatile retained_scope = &scope;
    (void)retained_lease; (void)retained_scope;
#else
static int pyobf_demo_bound_compute(scoped::Scope &, int) __asm__("pyobf_demo_bound_compute");
static PYOBF_NATIVE_CFF int pyobf_demo_bound_compute(scoped::Scope &scope, int value) {
    pyobf_native_measured_contribution_site_v1(scope, 701);
#endif
    if (value < 0) return -value + 11;
    if (value == 0) return 17;
    return value * 3 + 1;
}
#if defined(PYOBF_DEMO_POST_MIXED)
static int pyobf_demo_protection_wrapper(const Lease &, scoped::Scope &, scoped::Scope &,
    const demo::PayloadHandoff *, int) __asm__("pyobf_demo_protection_wrapper");
static PYOBF_NATIVE_CFF int pyobf_demo_protection_wrapper(const Lease &lease, scoped::Scope &parent,
        scoped::Scope &application, const demo::PayloadHandoff *handoff, int value) {
    const Lease *volatile retained_lease = &lease;
    scoped::Scope *volatile retained_scope = &parent;
    (void)retained_lease; (void)retained_scope;
#else
static int pyobf_demo_protection_wrapper(scoped::Scope &, scoped::Scope &, const demo::PayloadHandoff *, int)
    __asm__("pyobf_demo_protection_wrapper");
static PYOBF_NATIVE_CFF int pyobf_demo_protection_wrapper(scoped::Scope &parent, scoped::Scope &application,
        const demo::PayloadHandoff *handoff, int value) {
    pyobf_native_measured_contribution_site_v1(parent, 702);
#endif
    if (handoff->generation != parent.observation().subject_instance) return -104;
    handoff->record_stage(7, handoff->observer_context);
#if defined(PYOBF_DEMO_POST_MIXED)
    return pyobf_demo_bound_compute(lease, application, value);
#else
    return pyobf_demo_bound_compute(application, value);
#endif
}
}

namespace {
PYOBF_NATIVE_CFF_SDK bool valid_post(const demo::PayloadHandoff *handoff) noexcept {
    if (handoff == nullptr || handoff->expected == nullptr || handoff->post == nullptr ||
            handoff->post->version != demo::post_handoff_version ||
            handoff->post->count != 2 || handoff->post->fold == nullptr) return false;
    for (unsigned index = 0; index != 2; ++index) {
        const auto &role = handoff->post->roles[index];
        const auto owner = index == 0 ? profile::wrapper_owner : profile::compute_owner;
        if (role.observation == nullptr || role.material == nullptr || role.material_size != scoped::material_bytes ||
                role.spec.routing != handoff->routing_tag || role.spec.domain != profile::domain ||
                role.spec.source != profile::source || role.spec.function != owner ||
                role.spec.reference.owner != owner || role.spec.reference.stage != 2) return false;
    }
    return true;
}
}
extern "C" PYOBF_NATIVE_CFF_SDK int pyobf_demo_post_payload(const demo::PayloadHandoff *handoff, int value) {
    if (!valid_post(handoff)) return -104;
    const auto &parent = handoff->post->roles[0], &application = handoff->post->roles[1];
    auto parent_snapshot = observer::observe(*parent.observation);
    auto application_snapshot = observer::observe(*application.observation);
    if (parent_snapshot.check().error.code != observer::Status::ok ||
            application_snapshot.check().error.code != observer::Status::ok) return -104;
    scoped::Scope parent_operation(*handoff->expected, parent.spec, *handoff->post->fold,
        parent.material, parent.material_size, std::move(parent_snapshot));
    scoped::Scope application_operation(*handoff->expected, application.spec, *handoff->post->fold,
        application.material, application.material_size, std::move(application_snapshot));
#if defined(PYOBF_DEMO_POST_MIXED)
    return pyobf_demo_protection_wrapper(*handoff->expected, parent_operation, application_operation,
        handoff, value);
#else
    return pyobf_demo_protection_wrapper(parent_operation, application_operation, handoff, value);
#endif
}
