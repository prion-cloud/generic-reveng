#pragma once

#include "binary_reader.h"
#include "debug_32.h"

class debugger
{
    csh cs_handle_ { };
    uc_engine* uc_handle_ { };

    void initialize_section(
        binary_reader reader,
        size_t alignment,
        size_t raw_address,
        size_t raw_size,
        size_t virtual_address) const;
    void initialize_section(
        size_t alignment,
        size_t raw_size,
        size_t virtual_address) const;
    void initialize_import_table(
        size_t image_base,
        size_t import_table_address) const;
    void initialize_registers(
        uint32_t stack_pointer,
        uint32_t entry_point) const;

    debug_32 create_result(
        cs_insn* insn) const;

    void load_dll(
        std::string name) const;

public:

    explicit debugger(
        std::string file_name);

    void close();

    debug_32 debug() const;
};
