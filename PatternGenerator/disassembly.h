#pragma once

#include <capstone.h>
#include <unicorn.h>

#include "instruction.h"

#define PAGE_SIZE 0x1000
#define STACK_TOP 0x0

class disassembly
{
    struct pe_header
    {
        IMAGE_DOS_HEADER dos_header { };

        IMAGE_FILE_HEADER file_header { };
        IMAGE_OPTIONAL_HEADER64 optional_header { };

        std::vector<IMAGE_SECTION_HEADER> section_headers;

        explicit pe_header(const std::vector<uint8_t>& code);
    };

    pe_header header_;

    csh cs_ { };
    uc_engine* uc_ { };

public:

    explicit disassembly(const std::vector<uint8_t>& code);
    ~disassembly();

    std::map<x86_reg, uint64_t> get_context();
    void set_context(std::map<x86_reg, uint64_t> context);

    instruction operator[](uint64_t address) const;

private:

    void mem_map(uint64_t address, size_t size) const;
    void mem_map(uint64_t address, const std::vector<uint8_t>& buffer) const;
};
