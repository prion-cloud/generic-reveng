#include <generic-reveng/loading/address_space_segment.hpp>

namespace grev
{
    bool address_space_segment::exclusive_address_order::operator()(address_space_segment const& segment_1, address_space_segment const& segment_2) const
    {
        return segment_1.address_ + segment_1.raw_size_ <= segment_2.address_; // TODO virtual_size
    }

    bool address_space_segment::exclusive_address_order::operator()(address_space_segment const& segment, std::uint64_t const address) const
    {
        return segment.address_ + segment.raw_size_ <= address;
    }
    bool address_space_segment::exclusive_address_order::operator()(std::uint64_t const address, address_space_segment const& segment) const
    {
        return address < segment.address_;
    }

    static_assert(std::is_destructible_v<address_space_segment::exclusive_address_order>);

    static_assert(std::is_copy_constructible_v<address_space_segment::exclusive_address_order>);
    static_assert(std::is_copy_assignable_v<address_space_segment::exclusive_address_order>);

    static_assert(std::is_move_constructible_v<address_space_segment::exclusive_address_order>);
    static_assert(std::is_move_assignable_v<address_space_segment::exclusive_address_order>);
}
