#pragma once

#include "llvm/ADT/StringRef.h"
#include <cstdint>
namespace llvm { class Function; }
namespace pyobfuscator::native::cff {
struct ResolvedRecipe;
llvm::StringRef contribution_marker_name(const ResolvedRecipe &);
llvm::StringRef contribution_query_name(const llvm::Function &);
llvm::StringRef contribution_group_query_name(llvm::StringRef provider, std::uint32_t schema);
bool reserved_contribution_query(llvm::StringRef);
}
