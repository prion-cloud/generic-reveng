#include <generic-reveng/loading/address_space_segment.hpp>

namespace grev
{
    address_space_segment::address_space_segment(std::uint64_t address, std::size_t raw_offset, std::size_t raw_size) :
        address_(address),
        raw_offset_(raw_offset),
        raw_size_(raw_size) { }

    data_section address_space_segment::dissect(std::u8string_view const& data_view, std::uint64_t const address) const
    {
        auto const shift = address - address_;

        return
        {
            .address = address,
            .data = data_view.substr(raw_offset_ + shift, raw_size_ - shift)
        };
    }
}

static_assert(std::is_destructible_v<grev::address_space_segment>);

static_assert(std::is_copy_constructible_v<grev::address_space_segment>);
static_assert(std::is_nothrow_move_constructible_v<grev::address_space_segment>);

static_assert(std::is_copy_assignable_v<grev::address_space_segment>);
static_assert(std::is_nothrow_move_assignable_v<grev::address_space_segment>);
