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
    const auto code = std::vector<uint8_t>(it, bytes.end());

    emulator_ = std::make_shared<emulator>(machine);

    emulator_->mem_map(base_address, code);

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

TPL std::vector<uint8_t> to_bytes(T value)
{
    std::vector<uint8_t> bytes;

    const auto size = sizeof(T);

    for (auto i = 0; i < size; ++i)
        bytes.push_back(static_cast<uint8_t>(value >> i * 8));

    return bytes;
}

std::vector<uint8_t> loader_raw::create_aid(const uint16_t machine, const uint64_t base_address, const std::vector<uint8_t> bytes)
{
    std::vector<uint8_t> aid;

    const auto bytes_machine = to_bytes(machine);
    aid.insert(aid.end(), bytes_machine.begin(), bytes_machine.end());

    const auto bytes_base_address = to_bytes(base_address);
    aid.insert(aid.end(), bytes_base_address.begin(), bytes_base_address.end());

    aid.insert(aid.end(), bytes.begin(), bytes.end());

    return aid;
}
