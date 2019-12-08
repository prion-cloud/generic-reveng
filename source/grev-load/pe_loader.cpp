#include <grev-load/pe_loader.hpp>

#include "pe/pe_header.hpp"

namespace grev
{
    pe_loader::pe_loader(std::u8string_view data) :
        header_(std::make_unique<pe_header>(pe_header::inspect(std::move(data)))) { }
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

    std::uint32_t pe_loader::base_address() const
    {
        return header_->optional.base_address;
    }
    std::uint32_t pe_loader::entry_point_address() const
    {
        return header_->optional.base_address + header_->optional.relative_entry_point_address;
    }

    std::map<std::uint32_t, std::pair<std::uint32_t, std::uint32_t>> pe_loader::memory_segments() const
    {
        std::map<std::uint32_t, std::pair<std::uint32_t, std::uint32_t>> memory_segments;
        for (auto const& section : header_->sections)
        {
            memory_segments.emplace(
                header_->optional.base_address + section.relative_section_address,
                std::pair
                {
                    section.section_offset,
                    section.section_size
                });
        }

        return memory_segments;
    }

    std::optional<std::uint32_t> pe_loader::imports_address() const
    {
        if (auto const relative_imports_address = header_->optional.relative_imports_address; relative_imports_address != 0)
            return header_->optional.base_address + relative_imports_address;

        return std::nullopt;
    }

    std::unordered_map<std::string, std::uint32_t>
        pe_loader::export_map(std::function<std::u8string_view (std::uint32_t)> const& func) const
    {
        auto const relative_exports_address = header_->optional.relative_exports_address;

        if (relative_exports_address == 0)
            return { };

        auto const exports_address = header_->optional.base_address + relative_exports_address;

        struct pe_export_directory
        {
            std::uint32_t characteristics;
            std::uint32_t time_date_stamp;
            std::uint16_t major_version;
            std::uint16_t minor_version;
            std::uint32_t name;
            std::uint32_t base;
            std::uint32_t numberOfFunctions;
            std::uint32_t numberOfNames;
            std::uint32_t addressOfFunctions;
            std::uint32_t addressOfNames;
            std::uint32_t addressOfNameOrdinals;
        };

        auto const ed = *reinterpret_cast<pe_export_directory const*>(func(exports_address).data());

        auto const function_address_data = func(header_->optional.base_address + ed.addressOfFunctions);

        auto name_address_data = func(header_->optional.base_address + ed.addressOfNames);
        auto name_ordinal_data = func(header_->optional.base_address + ed.addressOfNameOrdinals);

        std::unordered_map<std::string, std::uint32_t> export_map;
        for (auto i = 0; i < ed.numberOfNames; ++i)
        {
            auto const name_address = *reinterpret_cast<std::uint32_t const*>(name_address_data.data());
            name_address_data.remove_prefix(sizeof(std::uint32_t));

            auto const name_ordinal = *reinterpret_cast<std::uint16_t const*>(name_ordinal_data.data());
            name_ordinal_data.remove_prefix(sizeof(std::uint16_t));

            std::string name{reinterpret_cast<char const*>(func(header_->optional.base_address + name_address).data())};
            auto const function_address =
                *reinterpret_cast<std::uint32_t const*>(function_address_data.substr(name_ordinal * sizeof(std::uint32_t)).data());

            export_map.emplace(std::move(name), header_->optional.base_address + function_address);
        }

        return export_map;
    }

    std::forward_list<import_descriptor> pe_loader::import_descriptors(std::u8string_view data) const
    {
        struct pe_import_descriptor
        {
            std::uint32_t original_first_thunk;
            std::uint32_t time_date_stamp;
            std::uint32_t forwarder_chain;
            std::uint32_t name;
            std::uint32_t first_thunk;
        };

        static std::u8string const delimiter(sizeof(pe_import_descriptor), '\0');

        std::forward_list<import_descriptor> import_descriptors;
        for (; !data.starts_with(delimiter); data.remove_prefix(sizeof(pe_import_descriptor)))
        {
            auto const id = *reinterpret_cast<pe_import_descriptor const*>(data.data());
            import_descriptors.push_front(
            {
                .name_address = header_->optional.base_address + id.name,
                .origin_address = header_->optional.base_address + id.original_first_thunk,
                .reference_address = header_->optional.base_address + id.first_thunk
            });
        }

        return import_descriptors;
    }
    std::forward_list<std::uint32_t> pe_loader::import_origins(std::u8string_view data) const
    {
        static std::u8string const delimiter(sizeof(std::uint32_t), '\0');

        std::forward_list<std::uint32_t> import_origins;
        for (; !data.starts_with(delimiter); data.remove_prefix(sizeof(std::uint32_t)))
            import_origins.push_front(header_->optional.base_address + *reinterpret_cast<std::uint32_t const*>(data.data()));

        return import_origins;
    }
    machine_import pe_loader::import(std::u8string_view const& data) const
    {
        return
        {
            .address = *reinterpret_cast<std::uint16_t const*>(data.data()),
            .name = reinterpret_cast<char const*>(data.substr(sizeof(std::uint16_t)).data())
        };
    }
}

static_assert(std::is_destructible_v<grev::pe_loader>);

static_assert(!std::is_copy_constructible_v<grev::pe_loader>); // TODO
static_assert(!std::is_nothrow_move_constructible_v<grev::pe_loader>); // TODO

static_assert(!std::is_copy_assignable_v<grev::pe_loader>); // TODO
static_assert(!std::is_nothrow_move_assignable_v<grev::pe_loader>); // TODO
