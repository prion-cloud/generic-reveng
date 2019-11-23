#include <generic-reveng/loading/program.hpp>

#include "pe/pe_program.hpp"

namespace grev
{
    program::program(std::u8string data) :
        data_(std::move(data)) { }

    program::~program() = default;

    data_section program::operator[](std::uint32_t address) const
    {
        auto const& seg = segments(); // TODO rename

        if (auto const segment = seg.lower_bound(address); segment != seg.upper_bound(address))
            return segment->dissect(data_, address);

        return
        {
            .address = address,
            .data = std::u8string_view(nullptr, 0)
        };
    }

    std::u8string_view program::data_view() const
    {
        return data_;
    }
    std::size_t program::data_size() const
    {
        return data_.size();
    }

    std::unique_ptr<program> program::load(std::u8string data)
    {
        if (data.starts_with(u8"MZ"))
            return std::make_unique<pe_program>(std::move(data));

        throw std::invalid_argument("Unknown binary format");
    }
}