#pragma once

#include "measurement/observer_internal.hpp"
#include "failure_fixture.hpp"

#include <vector>

namespace observer_test {
namespace native = pyobfuscator::native;
namespace observer = native::measurement::observer;
namespace internal = observer::detail;
using capture_test::require;
extern native::measurement::reference::Identity identity;
extern std::uint32_t words[8];
extern std::vector<std::uint8_t> package, plaintext;
extern unsigned pin_attempts, pins, unpins, fail_pin;
extern bool fail_release, fail_access, fail_body;
extern bool scope_material;
void anchor();
void reset();
void balanced();
observer::Creation make(observer::Policy = {}, const observer::ReaderBinding * = nullptr);
internal::State &state(const native::BootstrapContextLease &);
void policies();
void races();
void failures();
}
