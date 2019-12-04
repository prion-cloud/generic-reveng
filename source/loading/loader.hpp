#pragma once

#include <map>

#include <generic-reveng/analysis/machine_architecture.hpp>

namespace grev
{
    class loader
    {
    public:

        virtual ~loader();

        virtual machine_architecture architecture() const = 0;
        virtual std::optional<std::uint32_t> entry_point_address() const = 0;

        virtual std::map<std::uint32_t, std::u8string_view> memory_segments() const = 0;
    };
}
