#include "stdafx.h"

uc_err uc_ext_mem_read_string(uc_engine* uc, const uint64_t address, std::string& value)
{
    std::vector<char> chars;
    for (auto j = 0;; ++j)
    {
        char c;
        const auto err = uc_ext_mem_read<char>(uc, address, c, j);
        if (err)
            return err;

        if (c == '\0')
            break;

        chars.push_back(c);
    }

    value = std::string(chars.begin(), chars.end());

    return UC_ERR_OK;
}
