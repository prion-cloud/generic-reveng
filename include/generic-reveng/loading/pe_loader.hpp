#pragma once

#include <forward_list>
#include <functional>
#include <map>
#include <memory>

#include <generic-reveng/analysis/import_descriptor.hpp>
#include <generic-reveng/analysis/machine_architecture.hpp>
#include <generic-reveng/analysis/machine_import.hpp>

namespace grev
{
    struct pe_header;

    class pe_loader
    {
        std::unique_ptr<pe_header> header_;

    public:

        explicit pe_loader(std::u8string_view data);
        ~pe_loader();

        machine_architecture architecture() const;

        std::uint32_t base_address() const;
        std::uint32_t entry_point_address() const;

        std::map<std::uint32_t, std::pair<std::uint32_t, std::uint32_t>> memory_segments() const;

        std::optional<std::uint32_t> imports_address() const;

        std::unordered_map<std::string, std::uint32_t>
            export_map(std::function<std::u8string_view (std::uint32_t)> const& func) const;

        std::forward_list<import_descriptor> import_descriptors(std::u8string_view data) const;
        std::forward_list<std::uint32_t> import_origins(std::u8string_view data) const;
        machine_import import(std::u8string_view const& data) const;
    };
}
