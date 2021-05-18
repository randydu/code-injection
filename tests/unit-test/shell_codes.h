#ifndef CI_SHELLCODES_H_
#define CI_SHELLCODES_H_

#include <code_injection/code_injection.hpp>

namespace CI::ut {
//show hello world message box in target process
shell_code_t sc_hello_world_32();
shell_code_t sc_hello_world_64();

shell_code_t sc_beep_64();

using fn_context = std::function<void(shell_code_t&, const CONTEXT&)>;
shell_code_t sc_beep_continue_64(const CONTEXT& cxt);
} // namespace CI::ut

#endif