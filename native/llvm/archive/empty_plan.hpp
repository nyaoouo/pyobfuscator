#pragma once

namespace llvm { class Module; }

namespace pyobfuscator::native::archive {
struct Bindings;

void materialize_empty_plan(llvm::Module &module, const Bindings &bindings);
void verify_empty_prepared(const llvm::Module &module);
}  // namespace pyobfuscator::native::archive
