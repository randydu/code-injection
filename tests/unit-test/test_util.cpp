#include "test_util.h"
#include <catch2/catch.hpp>

#include <filesystem>

namespace CI {
namespace {
std::filesystem::path test_data_dir; //path to test data folder



template<typename T>
std::filesystem::path impl_get_test_data_file(const T &rel_data_path) {
    auto p = test_data_dir / rel_data_path;
    if (!std::filesystem::exists(p)) {
        throw std::invalid_argument("test data file [" + p.string() + "] not found!");
    }
    return p;
}
}

void init() {
    char *p = getenv(TEST_DATA_ENV);
    if (p == nullptr || strlen(p) == 0)
        throw std::runtime_error("Environment CI_TEST_DATA_DIR not found!");

    test_data_dir = p;
    if (!std::filesystem::exists(test_data_dir)) {
        throw std::runtime_error("test data folder not found!");
    }
}

std::string get_test_data_file(const std::string &rel_data_path) {
    return impl_get_test_data_file(rel_data_path).string();
}

std::wstring get_test_data_file(const std::wstring &rel_data_path) {
    return impl_get_test_data_file(rel_data_path).wstring();
}

} // namespace CI
