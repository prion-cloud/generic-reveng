#pragma once

#include "binary_reader.h"

#include "instruction_32.h"
#include "register_state_32.h"

class debugger
{
    csh cs_ { };
    uc_engine* uc_ { };

    void initialize_import_table(
        size_t image_base,
        size_t import_table_address) const;
    void initialize_registers(
        uint32_t stack_pointer,
        uint32_t entry_point) const;

    void load_dll(
        std::string name) const;

public:

    explicit debugger(
        std::string file_name);

    void close();

    instruction_32 debug_32() const;

    register_state_32 get_registers_32() const;
};
