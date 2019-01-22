#pragma once

#include <memory>

#include <capstone/capstone.h>

using instruction = cs_insn;

class disassembler
{
public:

    using architecture = cs_arch;
    using mode = cs_mode;

private:

    std::shared_ptr<csh> cs_;

public:

    disassembler();
    disassembler(architecture architecture, mode mode);

    std::shared_ptr<instruction const> operator()(uint64_t* address, std::basic_string_view<uint8_t>* code) const;
};
