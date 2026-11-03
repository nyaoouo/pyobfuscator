#include "recipe.hpp"

namespace pyobfuscator::native::cff {
std::uint32_t component_seed(unsigned seed, llvm::StringRef function,
                             llvm::StringRef component) {
    // This is public build diversity, never key derivation or an integrity claim.
    std::uint32_t value = 2166136261u ^ seed;
    for (const auto part : {llvm::StringRef("pyobf.cff.v1"), function, component}) {
        for (const unsigned char byte : part.bytes()) value = (value ^ byte) * 16777619u;
        value = (value ^ 0xffu) * 16777619u;
    }
    return value;
}

}
