#include "stdafx.h"

uc_err uc_ext_mem_read_string_skip(uc_engine* uc, const size_t address, std::string& value)
{
    auto end = false;
    std::vector<char> chars;
    for (auto j = 0;; ++j)
    {
        char c;
        const auto err = uc_ext_mem_read<char>(uc, address, c, j);
        if (err)
            return err;

        if (c != '\0')
            end = true;
        else if (!end)
            continue;

        chars.push_back(c);

        if (c == '\0' && end)
            break;
    }

    value = std::string(chars.begin(), chars.end());

    return UC_ERR_OK;
}
