#pragma once

#include <memory>
#include <vector>

#include <capstone/capstone.h>

#include "machine_architecture.hpp"

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

    std::shared_ptr<instruction> operator()(std::vector<uint8_t>* code, uint64_t* address) const;
};
