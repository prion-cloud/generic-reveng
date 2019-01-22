#pragma once

#include <map>
#include <memory>
#include <vector>

#include <unicorn/unicorn.h>

class emulator
{
public:

    using architecture = uc_arch;
    using mode = uc_mode;

private:

    struct uc_deleter
    {
        void operator()(uc_engine** uc) const;
    };

    struct memory_region_exclusive_address_order
    {
        using is_transparent = std::true_type;

        bool operator()(uc_mem_region const& regionA, uc_mem_region const& regionB) const;

        bool operator()(uc_mem_region const& region, uint64_t address) const;
        bool operator()(uint64_t address, uc_mem_region const& region) const;
    };

    std::unique_ptr<uc_engine*, uc_deleter> uc_;

    int ip_register_;

    std::map<uc_mem_region, std::vector<uint8_t>, memory_region_exclusive_address_order> memory_;

public:

    emulator();
    emulator(architecture architecture, mode mode, int ip_register);

    uint64_t position() const;
    void position(uint64_t address) const;

    std::basic_string_view<uint8_t> get_memory(uint64_t address) const;
    void allocate_memory(uint64_t address, std::vector<uint8_t> data);

    void operator()() const;

private:

    uint64_t read_register(int id) const;
    void write_register(int id, uint64_t value) const;
};

static_assert(std::is_destructible_v<emulator>);

static_assert(std::is_move_constructible_v<emulator>);
static_assert(std::is_move_assignable_v<emulator>);

static_assert(!std::is_copy_constructible_v<emulator>);
static_assert(!std::is_copy_assignable_v<emulator>);
