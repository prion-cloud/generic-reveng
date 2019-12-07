#include <generic-reveng/analysis/machine_program.hpp>

namespace grev
{
    machine_program::machine_program() = default;

    machine_program::machine_program(std::u8string data, machine_architecture architecture) :
        data_(std::move(data)),
        architecture_(std::move(architecture)),
        entry_point_address_(0)
    {
        memory_segments_.emplace(0, data_);
    }

    machine_architecture machine_program::architecture() const
    {
        return architecture_;
    }
    std::uint32_t machine_program::entry_point_address() const
    {
        return entry_point_address_;
    }

    std::u8string_view machine_program::operator[](std::uint32_t address) const
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
