#include <decompilation/data_section.hpp>

namespace dec
{
    bool data_section::exclusive_address_order::operator()(data_section const& a, data_section const& b) const
    {
        auto const max_1 = a.address + a.bytes.size() - 1;
        auto const min_2 = b.address;

        return max_1 < min_2;
    }

    bool data_section::exclusive_address_order::operator()(data_section const& a, std::uint_fast64_t const b) const
    {
        auto const max_1 = a.address + a.bytes.size() - 1;
        auto const min_2 = b;

        return max_1 < min_2;
    }
    bool data_section::exclusive_address_order::operator()(std::uint_fast64_t const a, data_section const& b) const
    {
        auto const max_1 = a;
        auto const min_2 = b.address;

        return max_1 < min_2;
    }

    static_assert(std::is_destructible_v<data_section>);

    static_assert(std::is_move_constructible_v<data_section>);
    static_assert(std::is_move_assignable_v<data_section>);

    static_assert(std::is_copy_constructible_v<data_section>);
    static_assert(std::is_copy_assignable_v<data_section>);
}
