#include "contribution_mix.hpp"
#include "scalar_proof.hpp"

namespace pyobfuscator::native::cff {
bool match_contribution_mix(const llvm::Value *value, const ContributionMixPlan &plan,
    llvm::ArrayRef<const llvm::Value *> inputs, const llvm::BasicBlock &body) {
    if (inputs.size() != plan.inputs) return false;
    std::vector<const llvm::Value *> matched(plan.nodes.size());
    std::vector<std::pair<const llvm::Value *, unsigned>> pending{{value, plan.root}};
    while (!pending.empty()) {
        const auto [actual, index] = pending.back(); pending.pop_back();
        if (actual == nullptr) return false;
        if (matched[index] != nullptr) { if (matched[index] != actual) return false; continue; }
        const auto &node = plan.nodes[index];
        if (node.kind == ContributionMixPlan::Kind::literal) { if (!scalar_constant(actual, node.value)) return false; }
        else if (node.kind == ContributionMixPlan::Kind::input) { if (actual != inputs[node.value]) return false; }
        else {
            const auto *op = scalar_operation(actual, node.opcode, &body);
            if (op == nullptr) return false;
            pending.push_back({op->getOperand(0), node.left}); pending.push_back({op->getOperand(1), node.right});
        }
        matched[index] = actual;
    }
    return true;
}
}
