#include "stdafx.h"

#include "loader.h"

loader_raw::loader_raw(const uint16_t machine, const uint64_t base_address)
    : machine_(machine), base_address_(base_address) { }

std::string loader_raw::label_at(const uint64_t) const
{
    return { };
}

uint16_t loader_raw::load(const std::vector<uint8_t> code)
{
    emulator_ = std::make_shared<emulator>(machine_);

    emulator_->mem_map(base_address_, code);

    initialize_environment(PAGE_SIZE, 0.5, base_address_);

    return machine_;
}

bool loader_raw::ensure_availablility(const uint64_t)
{
    return false;
}

uint64_t loader_raw::to_raw_address(const uint64_t virtual_address) const
{
    return virtual_address;
}
