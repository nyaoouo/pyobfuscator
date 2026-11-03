#pragma once

namespace llvm { class Value; class AllocaInst; class CallInst; class Function; }

namespace pyobfuscator::native::archive {
bool is_key_address(const llvm::Value *value, const llvm::AllocaInst *frame, unsigned lane);
const llvm::Function *routed_callee(const llvm::CallInst &call);
}
