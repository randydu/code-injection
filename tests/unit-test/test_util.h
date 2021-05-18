#ifndef TEST_UTIL_H_
#define TEST_UTIL_H_

#include <string>

namespace CI::ut {
constexpr auto TEST_DATA_ENV = "CI_TEST_DATA_DIR";
void init();

std::string get_test_data_file(const std::string &rel_data_path);
std::wstring get_test_data_file(const std::wstring &rel_data_path);

} // namespace CI::ut

#endif