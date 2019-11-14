#include <generic-reveng/loading/process.hpp>

#include "pe/pe_process.hpp"

namespace grev
{
    process::process(std::u8string data) :
        data_(std::move(data)) { }

    process::~process() = default;

    data_section process::operator[](std::uint64_t address) const
    {
        auto const segment = segments().lower_bound(address);

        if (segment == segments().upper_bound(address))
            throw std::invalid_argument("Invalid address");

        return segment->dissect(data_, address);
    }

    std::u8string_view process::data_view() const
    {
        return data_;
    }
    std::size_t process::data_size() const
    {
        return data_.size();
    }

    std::unique_ptr<process> process::load(std::u8string data)
    {
        if (data.starts_with(u8"MZ"))
            return std::make_unique<pe_process>(std::move(data));

        throw std::invalid_argument("Unknown binary format");
    }
}
