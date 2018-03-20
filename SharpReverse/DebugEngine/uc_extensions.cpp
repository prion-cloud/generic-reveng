#include "stdafx.h"

#include "uc_extensions.h"

uc_err uc_mem_read_string(uc_engine* uc, const uint64_t address, std::string& s)
{
    auto end = false;
    std::vector<char> chars;
    for (auto j = 0;; ++j)
    {
        char c;
        const auto err = uc_mem_read(uc, address, j, c);
        if (err != UC_ERR_OK)
            return err;

        if (c != '\0')
            end = true;
        else if (!end)
            continue;

        chars.push_back(c);

        if (c == '\0' && end)
            break;
    }

    s = std::string(chars.begin(), chars.end());

    return UC_ERR_OK;
}
