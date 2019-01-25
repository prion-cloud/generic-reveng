#include <sstream>

#include <utility/emulator.hpp>

#define HANDLE_UC_ERROR(uc_call)                            \
{                                                           \
    uc_err const error_code = uc_call;                      \
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

bool emulator::memory_region_exclusive_address_order::operator()(uc_mem_region const& regionA,
    uc_mem_region const& regionB) const
{
    return regionA.end < regionB.begin;
}

bool emulator::memory_region_exclusive_address_order::operator()(uc_mem_region const& region, uint64_t const address) const
{
    return region.end < address;
}
bool emulator::memory_region_exclusive_address_order::operator()(uint64_t const address, uc_mem_region const& region) const
{
    return address < region.begin;
}

emulator::emulator()
    : ip_register_() { }
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

std::basic_string_view<uint8_t> emulator::get_memory(uint64_t const address) const
{
    auto const memory_search = memory_.lower_bound(address);

    if (memory_search == memory_.upper_bound(address))
        HANDLE_UC_ERROR(UC_ERR_ARG);

    auto const& [region, data] = *memory_search;

    return std::basic_string_view<uint8_t>(&data.at(address - region.begin), region.end - address + 1);
}
void emulator::allocate_memory(uint64_t address, std::vector<uint8_t> data)
{
    auto constexpr page_size = 0x1000;

    address = page_size * (address / page_size);

    auto const size = page_size * ((data.size() - 1) / page_size + 1);
    data.resize(size);

    auto const permissions = UC_PROT_ALL; // TODO

    uc_mem_region const region
    {
        address,
        address + size - 1,
        permissions
    };

    auto const [memory_it, insertion_successful] = memory_.emplace(region, std::move(data));

    if (!insertion_successful)
        HANDLE_UC_ERROR(UC_ERR_ARG);

    HANDLE_UC_ERROR(
        uc_mem_map_ptr(*uc_, address, size, permissions, memory_it->second.data()));
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
