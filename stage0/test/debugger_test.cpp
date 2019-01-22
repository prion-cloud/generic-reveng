#include <catch2/catch.hpp>

#include <libgen.h>

#include "../source/debugger.hpp"

std::string get_file_path(std::string const& file_name)
{
    return std::string(::dirname(std::string(__FILE__).data())) + "/" + file_name;
}

TEST_CASE("Debug x86-32")
{
    debugger debugger;
    debugger.load_executable_file(::get_file_path("helloworld_32.exe"));

    CHECK(debugger.position() == 0x4012A8);

    /* TODO */
}
TEST_CASE("Debug x86-64")
{
    debugger debugger;
    debugger.load_executable_file(::get_file_path("helloworld_64.exe"));

    CHECK(debugger.position() == 0x140011023);

    /* TODO */
}
