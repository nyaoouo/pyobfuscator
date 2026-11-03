#include "flow.hpp"
#include "path_events.hpp"

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP bool pass_environment_gate(RuntimeContext *context) {
    context->environment = environment::inspect(context->config.detector_selection);
    record_stage(1, context);
    const bool accepted = context->environment.valid &&
           context->environment.overall != environment::Result::triggered &&
           (context->config.allow_unavailable ||
            context->environment.overall != environment::Result::unavailable);
    if (!accepted || PYOBF_NATIVE_ATOMIC_CAS32(&context->phase,
        static_cast<std::uint32_t>(LifecyclePhase::created),
        static_cast<std::uint32_t>(LifecyclePhase::environment_accepting)) !=
        static_cast<std::uint32_t>(LifecyclePhase::created)) return false;
    pyobf_native_path_fold_step_v1(context->fold, path_events::environment_tag, path_events::environment_word);
    return PYOBF_NATIVE_ATOMIC_CAS32(&context->phase,
        static_cast<std::uint32_t>(LifecyclePhase::environment_accepting),
        static_cast<std::uint32_t>(LifecyclePhase::environment_accepted)) ==
        static_cast<std::uint32_t>(LifecyclePhase::environment_accepting);
}

}  // namespace pyobfuscator::native::demo
