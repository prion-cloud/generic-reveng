#include "../include/utility/emulator.hpp"

inline void handle_uc_error(uc_err const error_code)
{
    if (error_code != UC_ERR_OK)
        throw std::runtime_error(uc_strerror(error_code));
}

inline void delete_uc(uc_engine** uc)
{
    uc_close(*uc);
    delete uc; // NOLINT [cppcoreguidelines-owning-memory]
}

emulator::emulator(machine_architecture const& architecture)
    : uc_(new uc_engine*, delete_uc)
{
    uc_arch uc_architecture;
    uc_mode uc_mode;
    switch (architecture)
    {
    case machine_architecture::x86_32:
        uc_architecture = UC_ARCH_X86;
        uc_mode = UC_MODE_32;
        break;
    case machine_architecture::x86_64:
        uc_architecture = UC_ARCH_X86;
        uc_mode = UC_MODE_64;
        break;
    }

    handle_uc_error(
        uc_open(uc_architecture, uc_mode, uc_.get()));
}

uint64_t emulator::read_register(int const id) const
{
    uint64_t value = 0;
    handle_uc_error(
        uc_reg_read(*uc_, id, &value));

    return value;
}

void emulator::write_register(int const id, uint64_t const value) const
{
    handle_uc_error(
        uc_reg_write(*uc_, id, &value));
}

void emulator::allocate_memory(uint64_t const address, size_t const size) const
{
    size_t constexpr page_size = 0x1000;

    handle_uc_error(
        uc_mem_map(*uc_, address, page_size * ((size - 1) / page_size + 1), UC_PROT_ALL));
}

std::vector<uint8_t> emulator::read_memory(uint64_t const address, size_t const size) const
{
    std::vector<uint8_t> data(size);
    handle_uc_error(
        uc_mem_read(*uc_, address, &data.front(), data.size()));

    return data;
}

void emulator::write_memory(uint64_t const address, std::vector<uint8_t> const& data) const
{
    handle_uc_error(
        uc_mem_write(*uc_, address, &data.front(), data.size()));
}

void emulator::operator()(uint64_t const address)
{
    handle_uc_error(
        uc_emu_start(*uc_, address, 0, 0, 1));
}
