#include <catch2/catch.hpp>

#include <fstream>
#include <iostream>

#include <libgen.h>

#include "../include/scout/control_flow_graph.h"
#include "../include/scout/debugger.h"

#include "test_helper.h"

std::string get_full_name(std::string const& file_name)
{
    return std::string(dirname(const_cast<char*>(std::string(__FILE__).c_str()))) + "/" + file_name;
}

TEST_CASE("Debug x86-32")
{
    auto d = debugger::load(get_full_name("helloworld_32.exe"));

    CHECK(d.position() == 0x4012A8);

    /* TODO */

    SECTION("Successful control flow graph construction")
    {
        std::cout << to_cfg_string(control_flow_graph(d)) << std::endl;
    }
}
TEST_CASE("Debug x86-64")
{
    auto d = debugger::load(get_full_name("helloworld_64.exe"));

    CHECK(d.position() == 0x140011023);

    /* TODO */
}
