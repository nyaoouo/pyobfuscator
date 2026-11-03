#pragma once

namespace llvm { class Function; }
namespace pyobfuscator::native::cff {
void verify_post_mixed_child_sites(const llvm::Function &, unsigned expected_scope_argument);
}
