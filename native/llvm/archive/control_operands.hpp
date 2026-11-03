#pragma once

namespace llvm { class Instruction; }

namespace pyobfuscator::native::archive {

bool control_operand(const llvm::Instruction &, unsigned operand);

}  // namespace pyobfuscator::native::archive
