#include "contribution_gate.hpp"
#include "transition_layers.hpp"
#include "bogus_controls.hpp"

#include "llvm/IR/BasicBlock.h"

namespace pyobfuscator::native::cff {
const llvm::Value *ContributionGateSeal::normal_encoded(const llvm::BasicBlock &body, const llvm::Value *encoded) const {
    return layers_ == nullptr ? encoded : layers_->normal_encoded(body, encoded);
}
bool ContributionGateSeal::owns_state_read(const llvm::LoadInst &read) const {
    return (layers_ != nullptr && layers_->owns_state_read(read)) || (controls_ != nullptr && controls_->owns_state_read(read));
}
bool ContributionGateSeal::owns_state_write(const llvm::StoreInst &write) const {
    return controls_ != nullptr && controls_->owns_state_write(write);
}
bool ContributionGateSeal::covers_unconditional(const llvm::BasicBlock &body,
    std::uint32_t state, std::uint32_t normal_encoded) const {
    if (body.getParent() != owner_) return false;
    for (const auto &point : points_)
        if (point.body == &body && point.unconditional && point.state == state &&
                point.normal_yes == normal_encoded && point.normal_no == normal_encoded) return true;
    return false;
}
}
