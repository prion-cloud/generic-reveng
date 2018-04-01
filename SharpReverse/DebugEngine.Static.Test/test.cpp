#include "pch.h"

#include "bin_dump.h"

TEST(bin_dump, create_dump)
{
    const std::string test_file = "TestFiles\\test1";
    
    const std::vector<char> expected = { '\x55', '\x48', '\x8b', '\x05', '\xb8', '\x13', '\x00', '\x00' };

    std::vector<char> actual;
    create_dump(test_file, actual);

    EXPECT_EQ(expected.size(), actual.size());

    for (unsigned i = 0; i < expected.size(); ++i)
        EXPECT_EQ(expected[i], actual[i]);
}
