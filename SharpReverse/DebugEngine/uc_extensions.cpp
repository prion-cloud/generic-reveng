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
uc_err uc_initialize_section(uc_engine* uc, std::optional<binary_reader> reader, size_t virtual_address, size_t alignment, size_t raw_size)
{
    auto virtual_size = alignment * (raw_size / alignment);
    if (raw_size % alignment > 0)
        virtual_size += alignment;

    const auto err = uc_mem_map(uc, virtual_address, virtual_size, UC_PROT_ALL);
    if (err != UC_ERR_OK)
        return err;

    if (reader == std::nullopt)
        return UC_ERR_OK;

    std::vector<char> byte_vec;
    reader->read(byte_vec, raw_size);
    return uc_mem_write(uc, virtual_address, &byte_vec[0], byte_vec.size() - 1);
}
