#pragma once

#include "buffer.hpp"
#include "flow.hpp"
#include "../decoy/handoff.hpp"

namespace pyobfuscator::native::demo {

struct DecoySession {
    DecoySession() noexcept;
    DecoySession(const DecoySession &) = delete;
    DecoySession &operator=(const DecoySession &) = delete;
    ~DecoySession();
    void reset() noexcept;
    TransientBuffer storage;
    path_fold::Storage *fold = nullptr;
    void *image = nullptr;
};

bool initialize_decoy(DecoySession &) noexcept;
bool advance_decoy_selection(DecoySession &, int) noexcept;
void advance_decoy_preparation(DecoySession &) noexcept;
bool reconstruct_decoy_key(const DecoySession &, std::uint8_t *) noexcept;
int release_decoy(int, int, RuntimeContext *, bool);

}  // namespace pyobfuscator::native::demo
