#pragma once

#include <utility/disassembler.hpp>
#include <utility/emulator.hpp>

class loader
{
    disassembler* disassembler_;
    emulator* emulator_;

public:

    loader(disassembler* disassembler, emulator* emulator);

    void operator()(std::vector<uint8_t> const& data) const;

private:

    void load_pe(std::vector<uint8_t> const& data) const;
};

static_assert(std::is_destructible_v<loader>);

static_assert(std::is_move_constructible_v<loader>);
static_assert(std::is_move_assignable_v<loader>);

static_assert(std::is_copy_constructible_v<loader>);
static_assert(std::is_copy_assignable_v<loader>);
