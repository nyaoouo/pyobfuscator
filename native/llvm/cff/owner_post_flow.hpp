#pragma once

#include "llvm/Support/JSON.h"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace llvm { class Function; class Module; }
namespace pyobfuscator::native::cff {
class PostRoleFlowSeal {
public:
    PostRoleFlowSeal(const llvm::Module &, const std::set<std::string> &selected);
    bool empty() const { return roles_.empty(); }
    llvm::json::Object verify(const llvm::Module &) const;

private:
    struct Role {
        unsigned role = 0, creator_index = 0;
        std::uint32_t owner = 0, routing_tag = 0, domain = 0, source = 0;
        std::uint64_t code_offset = 0, material_offset = 0;
        std::string producer, creator, plan;
    };
    std::vector<Role> roles_;
};
}
