#include "stdafx.h"

std::string uc_ext_mem_read_string_skip(uc_engine* uc, const size_t address)
{
    auto end = false;
    std::vector<char> chars;
    for (auto j = 0;; ++j)
    {
        char c;
        C_VIT(uc_ext_mem_read<char>(uc, address, c, j));

        if (c != '\0')
            end = true;
        else if (!end)
            continue;

        chars.push_back(c);

        if (c == '\0' && end)
            break;
    }

    return std::string(chars.begin(), chars.end());
}

uint64_t uc_ext_reg_read(uc_engine* uc, const int regid, const uint64_t scale)
{
    uint64_t value;
    C_VIT(uc_reg_read(uc, regid, &value));

    return value & scale;
}
void uc_ext_reg_write(uc_engine* uc, const int regid, const uint64_t value)
{
    C_VIT(uc_reg_write(uc, regid, &value));
}
