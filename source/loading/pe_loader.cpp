#include <generic-reveng/loading/pe_loader.hpp>

#include "pe/pe_header.hpp"

namespace grev
{
    pe_loader::pe_loader(std::u8string const& data) :
        data_(data),
        header_(std::make_unique<pe_header>(pe_header::inspect(data))) { }
    pe_loader::~pe_loader() = default;

    machine_architecture pe_loader::architecture() const
    {
        switch (header_->coff.machine_id)
        {
        case 332:
            return machine_architecture::x86_32;
        default:
            throw std::runtime_error("Unexpected architecture");
        }
    }
    std::uint32_t pe_loader::entry_point_address() const
    {
        return header_->optional.base_address + header_->optional.relative_start_address;
    }

    std::map<std::uint32_t, std::u8string_view> pe_loader::memory_segments() const
    {
        std::map<std::uint32_t, std::u8string_view> memory_segments;
        for (auto const& section : header_->sections)
        {
            memory_segments.emplace(
                header_->optional.base_address + section.relative_section_address,
                data_.substr(section.section_offset, section.section_size));
        }

        return memory_segments;
    }
}

static_assert(std::is_destructible_v<grev::pe_loader>);

static_assert(!std::is_copy_constructible_v<grev::pe_loader>); // TODO
static_assert(!std::is_nothrow_move_constructible_v<grev::pe_loader>); // TODO

static_assert(!std::is_copy_assignable_v<grev::pe_loader>); // TODO
static_assert(!std::is_nothrow_move_assignable_v<grev::pe_loader>); // TODO
