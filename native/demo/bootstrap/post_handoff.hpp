#pragma once

#include "contribution/scope.hpp"

namespace pyobfuscator::native::demo {
inline constexpr std::uint32_t post_handoff_version = 1;
struct PostRole {
    contribution::scoped::Spec spec{};
    const BootstrapContextLease *observation = nullptr;
    const std::uint8_t *material = nullptr;
    std::size_t material_size = 0;
};
struct PostHandoff {
    std::uint32_t version = post_handoff_version, count = 2;
    const path_fold::Storage *fold = nullptr;
    PostRole roles[2]{};
};
struct PostSession {
    BootstrapContextOwner owners[2];
    BootstrapContextLease leases[2];
    PostHandoff handoff;
    BootstrapContextStatus stage_status = BootstrapContextStatus::unavailable;
    measurement::observer::Error preparation[2]{};
};
}
