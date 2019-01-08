#pragma once

#include <array>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <capstone/capstone.h>

class assembly_instruction
{
    std::shared_ptr<cs_insn> base_;

public:

    explicit assembly_instruction(std::shared_ptr<cs_insn> base);

    bool has_detail() const;

    bool belongs_to(cs_group_type group) const;

    std::vector<std::optional<uint64_t>> get_successors() const;

    cs_insn const* operator->() const;
};

class machine_instruction
{
public:

    static size_t constexpr SIZE = 0x10;

private:

    std::shared_ptr<csh> cs_;

public:

    uint64_t address;

    std::array<uint8_t, SIZE> code { };

    machine_instruction(std::shared_ptr<csh> cs, uint64_t address, std::array<uint8_t, SIZE> const& code);

    assembly_instruction disassemble() const;
};
