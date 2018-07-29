#define CATCH_CONFIG_RUNNER
#include "catch2/catch.hpp"

int main(const int argc, char* argv[])
{
    Catch::Session().run(argc, argv);

    system("pause");
    return 0;
}
