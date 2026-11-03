#pragma once

#include "bogus_control_plan.hpp"
#include "transition_binding.hpp"
#include "transition_model.hpp"
#include <array>
#include <optional>
#include <set>

namespace llvm { class AllocaInst; class MDNode; class Module; class StoreInst; class LLVMContext; }
namespace pyobfuscator::native::cff {
struct StateLayout;
class TransitionLayers;
struct BogusControlDescription {
    std::uint32_t id, kind, state, normal, decoy, salt, predicate_salt;
    std::optional<std::uint32_t> literal_seed;
    std::string provenance;
};
llvm::MDNode *describe_bogus_control(llvm::LLVMContext &, const BogusControlDescription &);
std::optional<BogusControlDescription> read_bogus_control(const llvm::MDNode *);
void reject_bogus_control_artifacts(const llvm::Module &);

class BogusControls : public TransitionBinding {
public:
    BogusControls(llvm::Function &, const StateLayout &, const llvm::AllocaInst *,
        const BogusControlPlan &, std::optional<std::uint32_t> literal_seed = {}, const TransitionLayers * = nullptr);
    explicit BogusControls(const llvm::Function &, const TransitionLayers * = nullptr);
    std::string verify(const llvm::Function &) const override;
    bool covers_unconditional(const llvm::BasicBlock &, std::uint32_t, std::uint32_t) const override { return false; }
    const llvm::Value *normal_encoded(const llvm::BasicBlock &, const llvm::Value *) const override;
    bool owns_state_read(const llvm::LoadInst &) const override;
    bool owns_state_write(const llvm::StoreInst &) const override;
    bool empty() const { return records_.empty(); }
private:
    struct Record {
        BogusControlDescription description;
        const llvm::MDNode *tag;
        llvm::WeakVH body, decoy, predicate, result, work;
        std::unique_ptr<TransitionModel> model;
    };
    void add(BogusControlDescription, const llvm::MDNode *, llvm::Value *predicate,
        llvm::StoreInst *work, llvm::Value *result);
    const llvm::Function *owner_;
    llvm::WeakVH state_;
    const TransitionLayers *layers_;
    std::vector<Record> records_;
    std::string error_;
    mutable bool verified_ = false;
    mutable std::set<const llvm::LoadInst *> reads_;
    mutable std::set<const llvm::StoreInst *> writes_;
};
}
