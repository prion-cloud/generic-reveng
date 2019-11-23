#pragma once

#include <memory>
#include <set>

#include <generic-reveng/analysis/machine_architecture.hpp>
#include <generic-reveng/loading/address_space_segment.hpp>

namespace grev
{
    class program
    {
        std::u8string data_;

    protected:

        explicit program(std::u8string data);

    public:

        virtual ~program();

        virtual machine_architecture architecture() const = 0;
        virtual std::uint32_t start_address() const = 0;

        data_section operator[](std::uint32_t address) const;

    protected:

        virtual std::set<address_space_segment, address_space_segment::exclusive_address_order> const&
            segments() const = 0; // TODO std::span<...>

        std::u8string_view data_view() const;
        std::size_t data_size() const;

    public:

        static std::unique_ptr<program> load(std::u8string data);
    };
}
