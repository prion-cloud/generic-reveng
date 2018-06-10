#include "stdafx.h"

#include "loader.h"

std::string loader_raw::label_at(const uint64_t) const
{
    return { };
}

uint16_t loader_raw::load(const std::vector<uint8_t> bytes)
{
    auto it = bytes.begin();

    const auto machine = parse_to<uint16_t>(it);
    const auto base_address = parse_to<uint64_t>(it);

    emulator_ = std::make_shared<emulator>(machine);

    emulator_->mem_map(base_address, std::vector<uint8_t>(it, bytes.end()));

    initialize_environment(PAGE_SIZE, 0.5, base_address);

    return machine;
}

bool loader_raw::ensure_availability(const uint64_t)
{
    return false;
}

uint64_t loader_raw::to_raw_address(const uint64_t virtual_address) const
{
    return virtual_address;
}
