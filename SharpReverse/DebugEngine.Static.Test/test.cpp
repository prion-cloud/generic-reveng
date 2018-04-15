#include "pch.h"

#include "bin_dump.h"

TEST(bin_dump, create_filedump__success)
{
    const std::string test_file = TEST_FOLDER "test1";
    
    const std::vector<char> expected = { '\x55', '\x48', '\x8b', '\x05', '\xb8', '\x13', '\x00', '\x00' };

    std::vector<char> actual;
    ASSERT_FALSE(create_filedump(test_file, actual));

    ASSERT_EQ(expected.size(), actual.size());

    for (unsigned i = 0; i < expected.size(); ++i)
        EXPECT_EQ(expected[i], actual[i]);
}
