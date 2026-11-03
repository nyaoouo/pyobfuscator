#include "session_fixture.hpp"

extern "C" int pyobf_native_inner_entry(const pyobfuscator::native::demo::PayloadHandoff *, int);

namespace session_fixture {
void check_protocol() {
    using namespace pyobfuscator::native;
    using namespace pyobfuscator::native::demo;
    reset();
    {
        RuntimeSession session;
        Trace trace;
        require(initialize_session(session, observe, &trace), "direct protocol session");
        require(!initialize_session(session, observe, &trace), "duplicate session initialization rejected");
        const LifecycleMessage message{session.owner.generation(), session.context->config.environment_operation_id,
                                       LifecycleOperation::enter_payload};
        auto request = BootstrapContextRequest{message.routing_tag, &message, sizeof(message)};
        require(session.expected.invoke(request).status == BootstrapContextStatus::unavailable,
                "entry before environment/support rejected");
        require(release_and_load_payload(false, session) == -7 && counters.decrypts == 0,
                "unprepared session rejected before decrypt");
        require(pass_environment_gate(session.context), "environment lifecycle transition");
        require(!pass_environment_gate(session.context), "duplicate environment transition rejected");
        auto bad = message;
        ++bad.generation;
        require(session.expected.invoke({bad.routing_tag, &bad, sizeof(bad)}).status == BootstrapContextStatus::context_mismatch,
                "wrong generation rejected");
        bad = message;
        ++bad.routing_tag;
        require(session.expected.invoke({message.routing_tag, &bad, sizeof(bad)}).status == BootstrapContextStatus::context_mismatch,
                "wrong message routing tag rejected");
        require(session.expected.invoke({message.routing_tag, &message, sizeof(message) - 1}).status ==
                BootstrapContextStatus::invalid_request, "malformed lifecycle message rejected");
        require(prepare_support(session) && support_is_ready(session), "owned support preparation");
        require(!prepare_support(session), "duplicate support preparation rejected");
        auto handoff = make_payload_handoff(session);
        auto invalid = handoff;
        ++invalid.abi_version;
        require(pyobf_native_inner_entry(&invalid, 5) == -100, "wrong handoff ABI rejected");
        invalid = handoff;
        ++invalid.generation;
        require(pyobf_native_inner_entry(&invalid, 5) == -100, "wrong handoff generation rejected");
        invalid = handoff;
        ++invalid.routing_tag;
        require(pyobf_native_inner_entry(&invalid, 5) == -100, "wrong handoff routing rejected");
        require(pyobf_native_inner_entry(nullptr, 5) == -100, "missing handoff rejected");
        require(pyobf_native_inner_entry(&handoff, 5) == 16, "actual strict entry executes original compute");
        require(pyobf_native_inner_entry(&handoff, 5) == -100, "occupied publication cannot be replaced");
        require(release_and_load_payload(false, session) == -7 && counters.decrypts == 0,
                "entered session cannot reuse pre-release support");
        retire_payload(session);
        require(!support_is_ready(session) && session.expected.invoke(request).status == BootstrapContextStatus::closed,
                "retired context cannot resume earlier lifecycle");
    }
    verify_clean();
}
}  // namespace session_fixture
