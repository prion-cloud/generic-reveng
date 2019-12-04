#pragma once

#include "loading/loader.hpp"

#include "pe_header.hpp"

namespace grev
{
    class pe_loader : public loader
    {
        std::u8string_view data_;

        pe_header header_;

    public:

        explicit pe_loader(std::u8string const& data);

        machine_architecture architecture() const override;
        std::optional<std::uint32_t> entry_point_address() const override;

        std::map<std::uint32_t, std::u8string_view> memory_segments() const override;
    };
}
