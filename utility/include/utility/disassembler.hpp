#pragma once

#include <memory>
#include <unordered_set>

#include <capstone/capstone.h>

struct instruction : public cs_insn
{
    std::unordered_set<std::optional<uint64_t>> get_called_addresses() const;
    std::unordered_set<std::optional<uint64_t>> get_jumped_addresses() const;
};

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

    std::shared_ptr<instruction> operator()(uint64_t* address, std::basic_string_view<uint8_t>* code) const;
};

static_assert(std::is_destructible_v<instruction>);

static_assert(std::is_move_constructible_v<instruction>);
static_assert(std::is_move_assignable_v<instruction>);

static_assert(std::is_copy_constructible_v<instruction>);
static_assert(std::is_copy_assignable_v<instruction>);

static_assert(std::is_destructible_v<disassembler>);

static_assert(std::is_move_constructible_v<disassembler>);
static_assert(std::is_move_assignable_v<disassembler>);

static_assert(std::is_copy_constructible_v<disassembler>);
static_assert(std::is_copy_assignable_v<disassembler>);
