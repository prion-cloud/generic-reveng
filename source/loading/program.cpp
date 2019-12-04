#include <memory>

#include <generic-reveng/loading/program.hpp>

#include "pe/pe_loader.hpp"

namespace grev
{
    program::program(std::u8string data) :
        data_(std::move(data))
    {
        std::unique_ptr<loader const> loader;
        if (data_.starts_with(u8"MZ"))
            loader = std::make_unique<pe_loader const>(data_);
        // TODO ELF
        else
            throw std::invalid_argument("Unknown binary format");

        architecture_ = loader->architecture();
        entry_point_address_ = loader->entry_point_address();

        memory_segments_ = loader->memory_segments();
    }
    program::program(std::u8string data, machine_architecture architecture) :
        data_(std::move(data)),
        architecture_(std::move(architecture)),
        entry_point_address_(0)
    {
        memory_segments_.emplace(0, data_);
    }

    machine_architecture const& program::architecture() const
    {
        return architecture_;
    }
    std::optional<std::uint32_t> const& program::entry_point_address() const
    {
        return entry_point_address_;
    }

    std::u8string_view program::operator[](std::uint32_t address) const
    {
        std::uint32_t segment_address;
        std::u8string_view segment_data;

        for (auto segment = memory_segments_.begin();; ++segment)
        {
            if (segment == memory_segments_.end())
                return { };

            std::tie(segment_address, segment_data) = *segment;

            if (segment_address <= address && address < segment_address + segment_data.size())
                break;
        }

        return segment_data.substr(address - segment_address);
    }
}
