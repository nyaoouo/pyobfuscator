#include "transition_registry.hpp"
#include "recipe.hpp"
#include "cff.hpp"

namespace pyobfuscator::native::cff {
llvm::ArrayRef<TransitionModelRegistration> registered_transition_models() {
    static const TransitionModelRegistration models[]{
        {"opaque-choices", select_opaque_transition}, {"reachable-junk", apply_reachable_junk},
        {"decoy-transitions", select_decoy_transition}};
    return models;
}
const TransitionModelRegistration *find_transition_model(llvm::StringRef name) {
    for (const auto &model : registered_transition_models()) if (name == model.name) return &model;
    return nullptr;
}
}
