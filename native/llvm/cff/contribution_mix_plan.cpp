#include "contribution_mix.hpp"
#include "path_fold/value.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {
class Builder {
public:
    ContributionMixPlan plan;
    unsigned literal(std::uint32_t value) {
        plan.nodes.push_back({ContributionMixPlan::Kind::literal, value}); return plan.nodes.size() - 1;
    }
    unsigned input(unsigned index) {
        plan.nodes.push_back({ContributionMixPlan::Kind::input, index}); return plan.nodes.size() - 1;
    }
    unsigned op(unsigned code, unsigned left, unsigned right) {
        const auto a = plan.nodes[left], b = plan.nodes[right];
        if (a.kind == ContributionMixPlan::Kind::literal && b.kind == ContributionMixPlan::Kind::literal) {
            std::uint32_t value;
            switch (code) {
            case llvm::Instruction::Add: value = a.value + b.value; break;
            case llvm::Instruction::Mul: value = a.value * b.value; break;
            case llvm::Instruction::Xor: value = a.value ^ b.value; break;
            case llvm::Instruction::Or: value = a.value | b.value; break;
            case llvm::Instruction::Shl: value = a.value << b.value; break;
            case llvm::Instruction::LShr: value = a.value >> b.value; break;
            default: llvm::report_fatal_error("unknown contribution mix operation");
            }
            return literal(value);
        }
        plan.nodes.push_back({ContributionMixPlan::Kind::operation, 0, code, left, right});
        return plan.nodes.size() - 1;
    }
    unsigned rotate(unsigned value, unsigned count) {
        return op(llvm::Instruction::Or, op(llvm::Instruction::Shl, value, literal(count)),
            op(llvm::Instruction::LShr, value, literal(32 - count)));
    }
    unsigned mix(unsigned value) {
        for (const auto [shift, multiplier] : {std::pair{16u, 0x7feb352du}, std::pair{15u, 0x846ca68bu}}) {
            value = op(llvm::Instruction::Xor, value, op(llvm::Instruction::LShr, value, literal(shift)));
            value = op(llvm::Instruction::Mul, value, literal(multiplier));
        }
        return op(llvm::Instruction::Xor, value, op(llvm::Instruction::LShr, value, literal(16)));
    }
    struct State { unsigned left, right; std::uint32_t words; };
    State absorb(State before, std::uint32_t label, unsigned word) {
        const auto value = mix(op(llvm::Instruction::Xor, word, literal(0x9e3779b9u)));
        const auto tag = literal(path_fold::mix(label ^ 0xd1b54a35u));
        return {op(llvm::Instruction::Xor,
                    rotate(op(llvm::Instruction::Add, op(llvm::Instruction::Add, before.left, value), literal(before.words)), 7),
                    op(llvm::Instruction::Add, before.right, tag)),
                op(llvm::Instruction::Add, rotate(op(llvm::Instruction::Xor, before.right, tag), 11),
                    op(llvm::Instruction::Xor, before.left, value)), before.words + 1};
    }
};
}
ContributionMixPlan plan_contribution_mix(std::uint32_t domain, std::uint32_t function,
    std::uint32_t site, llvm::ArrayRef<std::pair<std::uint32_t, std::uint32_t>> labels) {
    if (labels.empty() || labels.size() > 256) llvm::report_fatal_error("contribution mix needs one to256 sources");
    Builder b;
    auto state = b.absorb({b.literal(path_fold::mix(domain ^ 0x243f6a88u)),
        b.literal(path_fold::mix(function ^ 0x85a308d3u)), 0}, 1, b.literal(site));
    unsigned index = 0;
    for (const auto [label, encoding] : labels) {
        state = b.absorb(state, 0x53524301u, b.literal(label));
        state = b.absorb(state, 0x53524302u, b.literal(encoding));
        state = b.absorb(state, 0x53524303u, b.literal(1));
        state = b.absorb(state, 0x574f5244u, b.input(index++));
    }
    b.plan.root = b.mix(b.op(llvm::Instruction::Xor,
        b.op(llvm::Instruction::Xor, state.left, b.rotate(state.right, 13)), b.literal(path_fold::mix(state.words))));
    b.plan.inputs = index;
    return std::move(b.plan);
}
}
