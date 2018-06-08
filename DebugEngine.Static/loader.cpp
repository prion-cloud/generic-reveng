#include "stdafx.h"

#include "loader.h"

loader::loader()
    : emulator_(nullptr) { }

std::shared_ptr<emulator> loader::get_emulator() const
{
    return emulator_;
}

void loader::initialize_environment(const size_t stack_size, const double stack_fill, const uint64_t entry_address) const
{
    const uint64_t stack_bottom = 0xffffffff; // TODO: May cause problems.
    emulator_->mem_map(stack_bottom - stack_size + 1, std::vector<uint8_t>(stack_size));

    emulator_->resize_stack(stack_bottom - static_cast<uint64_t>(stack_size * stack_fill));
    emulator_->jump_to(entry_address);
}
