#include <revengine/process.hpp>

namespace rev
{
    // TODO Real loading mechanism

    process::process(std::vector<std::uint8_t> data, instruction_set_architecture const architecture) :
        data_(std::move(data)),
        architecture_(architecture),
        start_address_(0)
    {
        data_sections_.insert(
            data_section
            {
                .address = start_address_,
                .data = std::basic_string_view<std::uint8_t>(data_.data(), data_.size())
            });
    }

    instruction_set_architecture process::architecture() const
    {
        return architecture_;
    }

    std::uint64_t process::start_address() const
    {
        return start_address_;
    }

    data_section process::operator[](std::uint64_t const address) const
    {
        auto const data_section = data_sections_.lower_bound(address);

        if (data_section == data_sections_.upper_bound(address))
            throw std::invalid_argument("Invalid address");

        return
        {
            .address = address,
            .data = data_section->data.substr(address - data_section->address)
        };
    }

    static_assert(std::is_destructible_v<process>);

    static_assert(std::is_move_constructible_v<process>);
    static_assert(std::is_move_assignable_v<process>);

    static_assert(std::is_copy_constructible_v<process>);
    static_assert(std::is_copy_assignable_v<process>);
}
