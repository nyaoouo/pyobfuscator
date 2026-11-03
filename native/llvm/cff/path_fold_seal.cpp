#include "path_fold_sites.hpp"
#include "state_layout.hpp"
#include "site_provenance.hpp"
#include "path_fold/value.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Operator.h"

namespace pyobfuscator::native::cff {

PathFoldSeal::PathFoldSeal(llvm::Function &function, const StateLayout &layout,
                         llvm::ArrayRef<InstructionSite> planned_sites)
    : owner_(&function) {
    for (const auto &site : planned_sites) {
        if (!site.reason.empty() || !layout.states.contains(site.instruction->getParent())) continue;
        auto marker = inspect_path_fold_marker(*site.instruction);
        const auto id = instruction_provenance(*site.instruction);
        expected_.emplace(id, Expected{marker.call->getArgOperand(0), site.instruction->getParent(),
            layout.states.lookup(site.instruction->getParent()), marker.word, marker.tag, marker.kind});
    }
}

std::string PathFoldSeal::verify(const llvm::Function &function) const {
    if (&function != owner_) return "path-fold source owner changed";
    if (const auto reason = validate_path_fold(function); !reason.empty()) return reason;
    std::map<std::string, unsigned> lanes;
    for (const auto &body : function) for (const auto &instruction : body) {
        const auto *node = instruction.getMetadata("pyobf.path-fold.bound");
        if (node == nullptr) continue;
        // The dataflow proof above has checked descriptor types and store spans.
        const auto id = llvm::cast<llvm::MDString>(node->getOperand(0))->getString().str();
        const auto found = expected_.find(id);
        if (found == expected_.end()) return "path-fold generated an unplanned source site";
        const auto &expected = found->second;
        const auto word = [&](unsigned index) {
            return static_cast<std::uint32_t>(llvm::mdconst::extract<llvm::ConstantInt>(node->getOperand(index))->getZExtValue());
        };
        const auto *store = llvm::cast<llvm::StoreInst>(&instruction);
        const auto *address = llvm::cast<llvm::GEPOperator>(store->getPointerOperand());
        if (expected.storage == nullptr || address->getPointerOperand() != expected.storage || &body != expected.body ||
                word(2) != static_cast<unsigned>(expected.kind) || word(4) != expected.tag ||
                word(5) != path_fold::encode_word(expected.word, expected.state, word(6)))
            return "path-fold binding differs from its frozen source storage, event or body state";
        ++lanes[id];
    }
    for (const auto &[id, expected] : expected_)
        if (lanes[id] != 8) return "path-fold lost a frozen source binding";
    return {};
}

}  // namespace pyobfuscator::native::cff
