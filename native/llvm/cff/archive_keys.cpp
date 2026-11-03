#include "recipe.hpp"
#include "scalar_mask.hpp"
#include "site_report.hpp"

#include "../archive/metadata.hpp"
#include "../archive/source_report.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_archive_sites(llvm::Function &function, const ResolvedRecipe &recipe) {
    if (!function.hasFnAttribute("pyobf.archive.planned"))
        return archive::source_candidates(function, !recipe.enabled("integer-literals"));
    std::vector<InstructionSite> result;
    for (auto &block : function) for (auto &instruction : block)
        if (instruction.getMetadata("pyobf.archive.key-slot") != nullptr ||
            instruction.getMetadata("pyobf.archive.gate") != nullptr) result.push_back({&instruction, 0, {}});
    return result;
}

unsigned bind_archive_keys(llvm::BasicBlock &body, llvm::Value *state_slot, std::uint32_t expected_state,
                            std::uint32_t salt, SiteCoverage *coverage) {
    unsigned count = 0;
    for (auto &instruction : body) {
        if (auto *tag = instruction.getMetadata("pyobf.archive.key-slot")) {
            auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction);
            const auto *material = instruction.getMetadata("pyobf.archive.key-material");
            if (store == nullptr || material == nullptr) archive::invalid_binding("key lane is not materialized");
            const auto word = archive::number_field(material, 0);
            const auto lane = archive::number_field(tag, 2);
            const auto lane_salt = component_seed(salt, archive::text_field(tag, 1), archive::text_field(tag, 0)) ^
                static_cast<std::uint32_t>(lane * 0x9e3779b9u);
            llvm::IRBuilder<> builder(store);
            auto *state = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.archive.state");
            auto *mask = emit_scalar_mask(builder, builder.getInt32Ty(), state, lane_salt, ScalarMaskDomain::archive);
            const auto encoded = llvm::APInt(32, word) ^ scalar_mask_value(32, expected_state, lane_salt, ScalarMaskDomain::archive);
            store->setOperand(0, builder.CreateXor(llvm::ConstantInt::get(builder.getInt32Ty(), encoded), mask,
                                                  "pyobf.archive.key-word"));
            store->setMetadata("pyobf.archive.key-material", nullptr);
            store->setMetadata("pyobf.archive.key-bound", tag);
            if (coverage != nullptr) {
                coverage->applied("constant-archive", instruction);
                coverage->record_type("constant-archive", "key-word32");
            }
            ++count;
        } else if (instruction.getMetadata("pyobf.archive.gate") != nullptr) {
            if (coverage != nullptr) coverage->applied("constant-archive", instruction);
            ++count;
        }
    }
    return count;
}

}  // namespace pyobfuscator::native::cff
