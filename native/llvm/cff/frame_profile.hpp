#pragma once

#include <map>
#include <string>
#include <vector>

namespace llvm { class CallBase; class CallInst; class Function; class MDNode; class Module; }

namespace pyobfuscator::native::cff {

struct GeneratedDefinition;

struct FrameProfiles { llvm::MDNode *outer, *inner; };
FrameProfiles frame_profiles(const llvm::CallBase &);
std::string profile_snapshot(const llvm::MDNode *);

class FrameProfileSeal {
public:
    explicit FrameProfileSeal(const llvm::Module &);
    std::string bind(const llvm::Module &, const std::map<std::string, GeneratedDefinition> &);
    std::string verify(const llvm::Module &) const;

private:
    struct Source {
        const llvm::CallBase *call;
        const llvm::Function *owner, *target;
        std::string original, outer, inner;
    };
    struct Bound {
        const llvm::Function *owner, *helper;
        const llvm::CallInst *inner;
        const llvm::MDNode *descriptor;
        bool invoke;
        std::string outer_profile, inner_profile;
    };
    const llvm::Module *module_;
    std::vector<Source> sources_;
    std::vector<Bound> bound_;
    bool bound_once_ = false;
};

}  // namespace pyobfuscator::native::cff
