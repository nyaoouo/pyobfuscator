#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include "llvm/ADT/StringRef.h"
namespace llvm { class Module; class Function; class Value; class BasicBlock; class LoadInst; class ConstantInt; }
namespace pyobfuscator::native::cff {
struct Component;
struct ResolvedRecipe;
class TransitionModel {
public:
    TransitionModel(const llvm::Function &, const Component &, llvm::StringRef provenance,
        std::uint32_t state, std::uint32_t seed, const ResolvedRecipe &);
    TransitionModel(const llvm::Function &, std::uint32_t state, std::uint32_t predicate_salt,
        std::optional<std::uint32_t> literal_seed = {});
    TransitionModel(const llvm::Function &, const llvm::ConstantInt &, std::uint32_t state, std::uint32_t literal_seed);
    ~TransitionModel();
    bool valid() const { return error_.empty(); }
    const std::string &error() const { return error_; }
    const llvm::Value *match(const llvm::Value *actual, const llvm::Value *state_slot,
        const llvm::BasicBlock &, std::set<const llvm::LoadInst *> &) const;
    bool match_predicate(const llvm::Value *, const llvm::Value *state_slot,
        const llvm::BasicBlock &, std::set<const llvm::LoadInst *> &) const;
    bool match_literal(const llvm::Value *, const llvm::Value *state_slot,
        const llvm::BasicBlock &, std::set<const llvm::LoadInst *> &) const;
private:
    bool match_graph(const llvm::Value *, const llvm::Value *, const llvm::BasicBlock &,
        const llvm::Value *&normal, std::set<const llvm::LoadInst *> &) const;
    std::unique_ptr<llvm::Module> module_;
    const llvm::Function *model_ = nullptr;
    const llvm::Value *result_ = nullptr;
    std::string error_;
    enum class Mode { identity, predicate, literal };
    Mode mode_ = Mode::identity;
};
bool transition_model_identity(const llvm::Function &, std::uint32_t state);
bool transition_predicate_identity(const llvm::Function &, std::uint32_t state);
bool transition_literal_identity(const llvm::Function &, std::uint32_t state, const llvm::ConstantInt &);
}
