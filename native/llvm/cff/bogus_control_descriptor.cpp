#include "bogus_controls.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
llvm::MDNode *describe_bogus_control(llvm::LLVMContext &context, const BogusControlDescription &d) {
    llvm::SmallVector<llvm::Metadata *, 11> fields;
    for (const auto word : {1u, d.id, d.kind, d.state, d.normal, d.decoy, d.salt, d.predicate_salt,
            std::uint32_t(d.literal_seed.has_value()), d.literal_seed.value_or(0)})
        fields.push_back(llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), word)));
    fields.push_back(llvm::MDString::get(context, d.provenance));
    return llvm::MDNode::get(context, fields);
}
std::optional<BogusControlDescription> read_bogus_control(const llvm::MDNode *tag) {
    if (tag == nullptr || tag->getNumOperands() != 11) return {};
    std::array<std::uint32_t, 10> words;
    for (unsigned i = 0; i != words.size(); ++i) {
        const auto *word = llvm::mdconst::dyn_extract<llvm::ConstantInt>(tag->getOperand(i));
        if (word == nullptr || !word->getType()->isIntegerTy(32)) return {};
        words[i] = word->getZExtValue();
    }
    const auto *provenance = llvm::dyn_cast<llvm::MDString>(tag->getOperand(10));
    if (words[0] != 1 || words[1] == 0 || words[2] < 1 || words[2] > 2 || words[8] > 1 ||
            (words[8] == 0 && words[9] != 0) || provenance == nullptr || provenance->getString().empty()) return {};
    return BogusControlDescription{words[1], words[2], words[3], words[4], words[5], words[6], words[7],
        words[8] ? std::optional<std::uint32_t>(words[9]) : std::nullopt, provenance->getString().str()};
}
void reject_bogus_control_artifacts(const llvm::Module &module) {
    for (const auto &function : module) {
        if (function.hasFnAttribute("pyobf.bogus.controls") || function.hasFnAttribute("pyobf.bogus.controls.verified"))
            llvm::report_fatal_error("native CFF input contains reserved bogus control identity");
        for (const auto &body : function) for (const auto &instruction : body)
            if (instruction.getMetadata("pyobf.bogus.guard") || instruction.getMetadata("pyobf.bogus.work"))
                llvm::report_fatal_error("native CFF input contains reserved bogus control descriptors");
    }
}
}
