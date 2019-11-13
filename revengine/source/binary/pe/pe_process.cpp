#include "pe_file.hpp"
#include "pe_process.hpp"

namespace rev::bin::pe
{
    pe_process::pe_process(std::u8string data) :
        process(std::move(data))
    {
        auto data_view = process::data_view();

        auto const file = pe_file::inspect(&data_view); // TODO member field (?)

        switch (file.coff_header.machine_id)
        {
        case 332:
            architecture_ = machine_architecture::x86_32;
            break;
        case 34404:
            architecture_ = machine_architecture::x86_64;
            break;
        }

        start_address_ = file.optional_header.base_address + file.coff_header.relative_entry_point_address;

        segments_.emplace(file.optional_header.base_address, 0, data_size() - data_view.size());
        for (auto const& section_header : file.section_headers)
        {
            segments_.emplace(
                section_header.relative_section_address + file.optional_header.base_address,
                section_header.section_offset,
                section_header.section_size);
        }

        // TODO imports
    }

    machine_architecture pe_process::architecture() const
    {
        return architecture_;
    }
    std::uint64_t pe_process::start_address() const
    {
        return start_address_;
    }

    std::set<address_space_segment, address_space_segment::exclusive_address_order> const& pe_process::segments() const
    {
        return segments_;
    }
}
