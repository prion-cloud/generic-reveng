#include <generic-reveng/loading/program.hpp>

#include "pe/pe_program.hpp"

namespace grev
{
    program::program(std::u8string data) :
        data_(std::move(data)) { }

    program::~program() = default;

    data_section program::operator[](std::uint64_t address) const
    {
        auto const segment = segments().lower_bound(address);

        if (segment == segments().upper_bound(address))
            throw std::invalid_argument("Invalid address");

        return segment->dissect(data_, address);
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
