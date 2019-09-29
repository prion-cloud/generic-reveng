#include <decompilation/memory.hpp>

namespace dec
{
    bool memory::section::exclusive_address_order::operator()(section const& section_1, section const& section_2) const
    {
        return section_1.address + section_1.data.size() <= section_2.address;
    }

    bool memory::section::exclusive_address_order::operator()(section const& section, std::uint64_t const address) const
    {
        return section.address + section.data.size() <= address;
    }
    bool memory::section::exclusive_address_order::operator()(std::uint64_t const address, section const& section) const
    {
        return address < section.address;
    }

    memory::memory(std::vector<std::uint8_t> data) :
        data_(std::move(data))
    {
        sections_.insert(
            section
            {
                .address = 0x0,
                .data = std::basic_string_view<std::uint8_t>(data_.data(), data_.size())
            });
    }

    std::basic_string_view<std::uint8_t> memory::operator[](std::uint64_t const address) const
    {
        auto const section = sections_.lower_bound(address);

        if (section == sections_.upper_bound(address))
            throw std::invalid_argument("Invalid address");

        return section->data.substr(address - section->address);
    }

    static_assert(std::is_destructible_v<memory>);

    static_assert(std::is_move_constructible_v<memory>);
    static_assert(std::is_move_assignable_v<memory>);

    static_assert(std::is_copy_constructible_v<memory>);
    static_assert(std::is_copy_assignable_v<memory>);
}
