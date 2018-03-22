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

uc_err uc_initialize_registers(uc_engine* uc, size_t entry_point, size_t stack_pointer)
{
    auto err = uc_reg_write(uc, X86_REG_EIP, &entry_point);
    if (err != UC_ERR_OK)
        return err;

    err = uc_reg_write(uc, X86_REG_ESP, &stack_pointer);
    if (err != UC_ERR_OK)
        return err;
    err = uc_reg_write(uc, X86_REG_EBP, &stack_pointer);
    if (err != UC_ERR_OK)
        return err;

    return UC_ERR_OK;
}

uc_err uc_initialize_section(uc_engine* uc, const std::vector<char> bytes, const size_t address)
{
    const auto alignment = 0x1000;

    auto size = alignment * (bytes.size() / alignment);
    if (bytes.size() % alignment > 0)
        size += alignment;

    const auto err = uc_mem_map(uc, address, size, UC_PROT_ALL);
    if (err != UC_ERR_OK)
        return err;

    if (bytes.size() == 0)
        return UC_ERR_OK;

    return uc_mem_write(uc, address, &bytes[0], bytes.size());
}
