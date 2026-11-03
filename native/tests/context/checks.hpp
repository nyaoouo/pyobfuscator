#pragma once

#include "pyobfuscator_native/bootstrap_context.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>

namespace context_test {
using namespace pyobfuscator::native;
using Status = BootstrapContextStatus;

inline void require(bool condition, const char *message) {
    if (!condition) {
        std::fprintf(stderr, "context check failed: %s\n", message);
        std::exit(1);
    }
}

void check_concurrency();
void check_provider(const char *path);
void check_binding_reentrancy();
void check_binding_concurrency();
}  // namespace context_test
