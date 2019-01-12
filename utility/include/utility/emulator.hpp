#pragma once

#include <functional>
#include <memory>

#include <unicorn/unicorn.h>

#include "machine_architecture.hpp"

class emulator : public std::unique_ptr<uc_engine*, std::function<void(uc_engine**)>>
{
public:

    explicit emulator(machine_architecture const& architecture);

    uint64_t read_register(int id) const;

    void write_register(int id, uint64_t value) const;

    void allocate_memory(uint64_t address, size_t size) const;

    std::vector<uint8_t> read_memory(uint64_t address, size_t size) const;

    void write_memory(uint64_t address, std::vector<uint8_t> const& data) const;

    void operator()(uint64_t address);
};
