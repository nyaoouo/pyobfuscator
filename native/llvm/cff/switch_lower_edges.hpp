#pragma once

namespace llvm { class Function; }
namespace pyobfuscator::native::cff {
class CfgOrigins;
class ContributionEdgePlan;
void lower_switch_edges(llvm::Function &, CfgOrigins *, ContributionEdgePlan *);
}
