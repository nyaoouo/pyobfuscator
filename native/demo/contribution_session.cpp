#include "session_fixture.hpp"
#include "contribution/protocol.hpp"
#include "pyobfuscator_native/contribution.hpp"

#include <cstdio>
#include <cstring>

namespace {
using namespace pyobfuscator::native;
using namespace pyobfuscator::native::demo;
using namespace session_fixture;
constexpr contribution::Site point{1, 2, 3, 4, 0x12345678};

void enter(RuntimeSession &session) {
    const LifecycleMessage message{session.context->generation, session.context->config.environment_operation_id, LifecycleOperation::enter_payload};
    require(session.expected.invoke({message.routing_tag, &message, sizeof(message)}).status == BootstrapContextStatus::ok,
            "source entry lifecycle admitted");
}
contribution::Result sample(RuntimeSession &session) {
    return contribution::request(session.expected, session.context->config.environment_operation_id, point);
}
void prefix(RuntimeSession &session) {
    require(initialize_session(session, nullptr, nullptr) && pass_environment_gate(session.context) && prepare_support(session),
            "source actual release prefix");
    session.publication = bind_bootstrap_context(session.expected);
    require(session.publication.status == BootstrapContextStatus::ok, "source expected identity published");
}
}

int main() {
    reset();
    {
        RuntimeSession session;
        prefix(session);
        require(sample(session).status == BootstrapContextStatus::unavailable, "support status alone supplies no contribution");
        enter(session);
        require(sample(session).status == BootstrapContextStatus::unavailable && counters.hashes == 0 && counters.loads == 0,
                "entering without authentication supplies no snapshot or word");
    }
    verify_clean();
    reset();
    {
        RuntimeSession session;
        prefix(session);
        require(release_and_load_payload(true, session) == -4, "real AEAD authentication failed");
        enter(session);
        require(sample(session).status == BootstrapContextStatus::unavailable && counters.loads == 0,
                "failed authentication cannot publish source material");
        PYOBF_NATIVE_ATOMIC_STORE32(&session.context->contribution_state, 2);
        const auto forged = sample(session);
        require(forged.status == BootstrapContextStatus::ok && forged.word != 0, "patched flags can expose only the wrong source material");
        std::printf("bootstrap-fold context-zero %u\n", forged.word);
    }
    verify_clean();
    reset();
    {
        RuntimeSession session;
        prefix(session);
        require(release_and_load_payload(false, session) == 0 && PYOBF_NATIVE_ATOMIC_LOAD32(&session.context->contribution_state) == 2,
                "real authenticated release publishes one private snapshot");
        require(sample(session).status == BootstrapContextStatus::unavailable, "source use waits for payload entry");
        enter(session);
        const auto normal = sample(session);
        require(normal.status == BootstrapContextStatus::ok && normal.word != 0, "actual bootstrap derived contribution");
        std::printf("bootstrap-fold context-word %u\n", normal.word);
        session.context->fold.words[0] ^= 1;
        require(!freeze_contribution(*session.context) && sample(session).word == normal.word,
                "snapshot is immutable, separate from the earlier mutable fold");
        contribution::Message message{1, sizeof(contribution::Message), session.context->config.environment_operation_id,
            0, session.expected.generation(), point, 0};
        for (unsigned field = 0; field != 10; ++field) {
            auto bad = message;
            if (field == 0) ++bad.version; if (field == 1) --bad.size;
            if (field == 2) bad.reserved = 1; if (field == 3) bad.tail_reserved = 1;
            if (field == 4) ++bad.generation; if (field == 5) ++bad.routing_tag;
            if (field == 6) bad.point.domain = 0; if (field == 7) bad.point.function = 0;
            if (field == 8) bad.point.site = 0; if (field == 9) bad.point.source = 0;
            const auto result = session.expected.invoke({message.routing_tag, &bad, sizeof(bad)});
            require(result.status != BootstrapContextStatus::ok && result.value == 0, "malformed source message has no reply authority");
        }
        std::uint8_t unaligned[sizeof(message) + 1];
        std::memcpy(unaligned + 1, &message, sizeof(message));
        require(session.expected.invoke({message.routing_tag, unaligned + 1, sizeof(message)}).status == BootstrapContextStatus::ok,
                "bounded unaligned input copied before validation");
        const auto next_allocation = counters.allocation_attempts + 1;
        counters.fail_allocation = next_allocation;
        require(sample(session).status == BootstrapContextStatus::allocation_failed, "source digest OOM refuses without value");
        counters.fail_allocation = 0; counters.hash_succeeds = false;
        const auto failed = sample(session);
        require(failed.status == BootstrapContextStatus::unavailable && failed.word == 0, "source provider failure remains unusable");
        counters.hash_succeeds = true;
        require(sample(session).word == normal.word, "new independent request after transient provider failure");
        ++session.context->generation;
        require(sample(session).status == BootstrapContextStatus::context_mismatch, "runtime and owned generation must agree");
        --session.context->generation;
        session.owner.close();
        const auto closed = sample(session);
        require(closed.status == BootstrapContextStatus::closed && closed.word == 0, "closed source cannot be reacquired");
    }
    verify_clean();
    std::puts("actual bootstrap source: authenticated immutable snapshot, forged-state wrong material, framing/generation/OOM/hash/retirement and erased storage verified");
}
