#pragma once

namespace llvm { class Value; }

namespace pyobfuscator::native::cff {

// Follow only closed, unambiguous reg2mem copies; no arithmetic or escaped storage.
const llvm::Value *unique_spill_origin(const llvm::Value *);

}  // namespace pyobfuscator::native::cff
