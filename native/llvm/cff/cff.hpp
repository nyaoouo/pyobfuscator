#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/IRBuilder.h"

namespace llvm {
class BasicBlock;
class Function;
class Module;
class Value;
class StringRef;
class Instruction;
class CallInst;
}

namespace pyobfuscator::native::cff {

struct ResolvedRecipe;
class SiteCoverage;

struct Leaf {
    std::uint32_t state;
    llvm::BasicBlock *body;
};

struct Strategy {
    const char *name;
    std::string (*validate)(const llvm::Function &function);
    void (*apply)(llvm::Function &function, unsigned seed);
};

const Strategy *find_strategy(llvm::StringRef name);
std::map<std::string, std::string> collect_marked_functions(const llvm::Module &module);
std::string validate_relative_tree(const llvm::Function &function);
std::string validate_cfg_shape(const llvm::Function &function, bool landingpad_eh);
std::string validate_configured(const llvm::Function &function, const ResolvedRecipe &recipe);
std::string validate_relative_tree_deep(const llvm::Function &function);
bool has_eligible_integer_constants(const llvm::Function &function);
bool has_eligible_internal_calls(const llvm::Function &function);
bool eligible_integer_operand(const llvm::Instruction &instruction, unsigned index);
bool eligible_internal_call(const llvm::CallInst &call, const llvm::Function &function);
llvm::BasicBlock *build_dispatch_tree(llvm::Function &function, llvm::Value *state,
                                      llvm::ArrayRef<Leaf> leaves,
                                      std::uint64_t &random_state);
void flatten(llvm::Function &function, unsigned seed);
void flatten_deep(llvm::Function &function, unsigned seed);
std::string flatten_configured(llvm::Function &function, const ResolvedRecipe &recipe,
                                SiteCoverage &coverage);
unsigned hide_integer_constants(llvm::BasicBlock &body, llvm::Value *state_slot,
                                std::uint32_t expected_state, std::uint32_t salt,
                                SiteCoverage *coverage = nullptr);
unsigned route_internal_calls(llvm::Function &function,
                              llvm::ArrayRef<llvm::BasicBlock *> bodies,
                              SiteCoverage *coverage = nullptr, unsigned seed = 0);
llvm::Value *select_decoy_transition(llvm::IRBuilder<> &builder, llvm::Value *normal,
                                     llvm::Value *state_slot,
                                     std::uint32_t expected_state, std::uint32_t salt,
                                     const ResolvedRecipe &recipe);
void lower_switches(llvm::Function &function, SiteCoverage *coverage = nullptr);
void lower_cross_block_ssa(llvm::Function &function, SiteCoverage *coverage = nullptr);
void pad_small_cfg(llvm::Function &function, unsigned min_blocks = 3, SiteCoverage *coverage = nullptr);
void shuffle_body_layout(llvm::Function &function,
                         llvm::ArrayRef<llvm::BasicBlock *> bodies,
                         std::uint64_t &random_state);

}  // namespace pyobfuscator::native::cff
