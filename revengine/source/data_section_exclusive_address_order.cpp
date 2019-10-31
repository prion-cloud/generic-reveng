#include <revengine/data_section.hpp>

namespace rev
{
    bool data_section::exclusive_address_order::operator()(data_section const& section_1, data_section const& section_2) const
    {
        return section_1.address + section_1.data.size() <= section_2.address;
    }

    bool data_section::exclusive_address_order::operator()(data_section const& section, std::uint64_t const address) const
    {
        return section.address + section.data.size() <= address;
    }
    bool data_section::exclusive_address_order::operator()(std::uint64_t const address, data_section const& section) const
    {
        return address < section.address;
    }

    static_assert(std::is_destructible_v<data_section::exclusive_address_order>);

    static_assert(std::is_move_constructible_v<data_section::exclusive_address_order>);
    static_assert(std::is_move_assignable_v<data_section::exclusive_address_order>);

    static_assert(std::is_copy_constructible_v<data_section::exclusive_address_order>);
    static_assert(std::is_copy_assignable_v<data_section::exclusive_address_order>);
}
