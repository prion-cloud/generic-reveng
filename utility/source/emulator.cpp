#include <sstream>

#include "../include/utility/emulator.hpp"

#define HANDLE_UC_ERROR(uc_call)                            \
{                                                           \
    auto const error_code = uc_call;                        \
    if (error_code != UC_ERR_OK)                            \
    {                                                       \
        std::ostringstream message;                         \
        message          << uc_strerror(error_code)         \
            << std::endl << #uc_call                        \
            << std::endl << __FILE__ << ':' << __LINE__;    \
                                                            \
        throw std::runtime_error(message.str());            \
    }                                                       \
}

void emulator::uc_deleter::operator()(uc_engine** const uc) const
{
    uc_close(*uc);
    delete uc; // NOLINT [cppcoreguidelines-owning-memory]
}

emulator::emulator() = default;
emulator::emulator(uc_arch const architecture, uc_mode const mode, int const ip_register)
    : uc_(new uc_engine*), ip_register_(ip_register)
{
    HANDLE_UC_ERROR(
        uc_open(architecture, mode, uc_.get()));
}

uint64_t emulator::position() const
{
    return read_register(ip_register_);
}
void emulator::position(uint64_t const address) const
{
    return write_register(ip_register_, address);
}

void emulator::map_memory(uint64_t const address, size_t const size) const
{
    size_t constexpr page_size = 0x1000;

    HANDLE_UC_ERROR(
        uc_mem_map(*uc_, address, page_size * ((size - 1) / page_size + 1), UC_PROT_ALL));
}

std::vector<uint8_t> emulator::read_memory(uint64_t const address, size_t const size) const
{
    std::vector<uint8_t> data(size);
    HANDLE_UC_ERROR(
        uc_mem_read(*uc_, address, data.data(), data.size()));

    return data;
}
void emulator::write_memory(uint64_t const address, std::vector<uint8_t> const& data) const
{
    HANDLE_UC_ERROR(
        uc_mem_write(*uc_, address, data.data(), data.size()));
}

void emulator::operator()() const
{
    HANDLE_UC_ERROR(
        uc_emu_start(*uc_, position(), 0, 0, 1));
}

uint64_t emulator::read_register(int const id) const
{
    uint64_t value = 0;
    HANDLE_UC_ERROR(
        uc_reg_read(*uc_, id, &value));

    return value;
}
void emulator::write_register(int const id, uint64_t const value) const
{
    HANDLE_UC_ERROR(
        uc_reg_write(*uc_, id, &value));
}
