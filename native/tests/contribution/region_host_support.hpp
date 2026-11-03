#pragma once

struct RegionState { int countdown = 0, result = 0, remaining = 0, before = 0, after = 0, headers = 0, entered = 0, ticks = 0, positive = 0, negative = 0; };
static_assert(sizeof(RegionState) == 10 * sizeof(int));
extern "C" int contribution_region(const pyobfuscator::native::BootstrapContextLease &, int, RegionState *, int) noexcept;
extern "C" int contribution_region_choice(RegionState *, int value) noexcept { return value & 1; }
extern "C" void contribution_region_step(RegionState *state, int value, int delta) noexcept { state->result += value + delta; }
extern "C" void contribution_region_after(RegionState *state) noexcept { ++state->after; }
extern "C" void contribution_region_anchor(RegionState *state) noexcept { ++state->headers; }
extern "C" void contribution_region_entered(RegionState *state) noexcept { state->entered += state->countdown; }
extern "C" void contribution_region_tick(RegionState *state) noexcept { state->ticks += state->countdown; }
extern "C" void contribution_region_positive(RegionState *state) noexcept { ++state->positive; }
extern "C" void contribution_region_negative(RegionState *state) noexcept { ++state->negative; }

namespace {
bool region_run(const pyobfuscator::native::BootstrapContextLease &lease) {
    for (int value = -13; value <= 13; ++value) {
        RegionState state;
        const int rounds = (value & 3) + 1;
        const int expected = rounds * ((value & 1) ? 3 : 2) * (value + ((value & 1) ? 7 : -5));
        const int count = (value & 1) ? 3 : 2;
        if (contribution_region(lease, value, &state, rounds) != expected || state.result != expected ||
                state.before != rounds || state.after != rounds || state.remaining != 0 || state.countdown != 0 ||
                state.headers != rounds * (count + 1) || state.entered != rounds * count ||
                state.ticks != rounds * count * (count - 1) / 2 ||
                state.positive != ((value & 1) ? rounds * count : 0) ||
                state.negative != ((value & 1) ? 0 : rounds * count)) return false;
    }
    return true;
}
}
