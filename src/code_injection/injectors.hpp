#ifndef CI_INJECTORS_HPP_
#define CI_INJECTORS_HPP_

/*
 Built-in injectors
*/

#include "code_injection.hpp"

namespace CI {
void inject_context(const PROCESS_INFORMATION &pi, const shell_code_t &sc);
}

#endif