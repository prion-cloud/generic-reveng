#include <catch2/catch.hpp>

#include <libgen.h>

#include "../include/scout/debugger.h"

std::string get_file_path(std::string const& file_name)
{
    return std::string(::dirname(const_cast<char*>(std::string(__FILE__).c_str()))) + "/" + file_name;
}

TEST_CASE("Debug x86-32")
{
    auto d = debugger::load(::get_file_path("helloworld_32.exe"));

    CHECK(d.position() == 0x4012A8);

    /* TODO */
}
TEST_CASE("Debug x86-64")
{
    auto d = debugger::load(::get_file_path("helloworld_64.exe"));

    CHECK(d.position() == 0x140011023);

    /* TODO */
}
