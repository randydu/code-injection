#ifndef CI_SHELLCODES_H_
#define CI_SHELLCODES_H_

#include <code_injection/code_injection.hpp>

namespace CI::ut {
//show hello world message box in target process
shell_code_t sc_hello_world_32(bool self_resovle_api);
shell_code_t sc_hello_world_64(bool self_resolve_api);

shell_code_t sc_beep(bool self_resolve_api, shell_code_t::arch_t arch);

} // namespace CI::ut

#endif