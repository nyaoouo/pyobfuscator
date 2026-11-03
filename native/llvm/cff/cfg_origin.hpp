#pragma once

#include <map>
#include <string>
#include <vector>

namespace llvm {
class BasicBlock;
class Function;
}

namespace pyobfuscator::native::cff {

enum class BlockRole { real, shape, routing, decoy, junk };
const char *role_name(BlockRole role);

class CfgOrigins {
public:
    void set(const llvm::BasicBlock &block, BlockRole role);
    BlockRole get(const llvm::BasicBlock &block) const;
    std::string validate_new_blocks(const llvm::Function &function,
                                    const std::vector<const llvm::BasicBlock *> &before) const;

private:
    std::map<const llvm::BasicBlock *, BlockRole> roles_;
};

}  // namespace pyobfuscator::native::cff
