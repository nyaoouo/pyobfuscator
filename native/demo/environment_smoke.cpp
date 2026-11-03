#include "pyobfuscator_native/environment.hpp"

#include <cstring>

int main() {
    using namespace pyobfuscator::native::environment;
    const auto empty = inspect("");
    const auto missing = inspect("missing");
    const auto duplicate = inspect("placeholder,placeholder");
    const auto placeholder = inspect("placeholder");
    const auto clear = inspect("clear_fixture");
    const auto mixed = inspect("clear_fixture,placeholder");
    const auto combined = inspect("placeholder,triggered");
    return !empty.valid && !missing.valid && !duplicate.valid &&
                   placeholder.valid && placeholder.count == 1 &&
                   std::strcmp(placeholder.observations[0].name, "placeholder") == 0 &&
                   placeholder.observations[0].result == Result::unavailable &&
                   placeholder.overall == Result::unavailable &&
                   clear.valid && clear.overall == Result::clear &&
                   mixed.valid && mixed.overall == Result::unavailable &&
                   combined.valid && combined.count == 2 &&
                   combined.observations[1].result == Result::triggered &&
                   combined.overall == Result::triggered ? 0 : 1;
}
