#pragma once

#include <map>
#include <memory>

#include <generic-reveng/analysis/machine_architecture.hpp>

namespace grev
{
    struct pe_header;

    class pe_loader
    {
        std::u8string_view data_;

        std::unique_ptr<pe_header> header_;

    public:

        explicit pe_loader(std::u8string const& data);
        ~pe_loader();

        machine_architecture architecture() const;
        std::uint32_t entry_point_address() const;

        std::map<std::uint32_t, std::u8string_view> memory_segments() const;
    };
}
