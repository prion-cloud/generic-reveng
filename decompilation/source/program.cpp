#include "common_exception.hpp"

#include <decompilation/program.hpp>

namespace dec
{
    program::program(std::vector<std::byte> data) :
        data_(std::move(data))
    {
        std::string_view data_text(reinterpret_cast<char const*>(data_.data()), data_.size());

        if (data_text.substr(0, 2) == "MZ")
        {
            struct dos_header
            {
                std::byte a[60];

                std::uint32_t pe_offset;
            };
            struct pe_header
            {
                std::byte a[4];

                std::uint16_t machine_id;
                std::uint16_t section_count;

                std::byte d[12];

                std::uint16_t optional_header_size;

                std::byte f[18];

                std::uint32_t relative_entry_point_address;
            };
            struct optional_header_32
            {
                std::byte a[4];

                std::uint32_t base_address;

                std::byte c[72];

                std::uint32_t import_address;
            };
            struct optional_header_64
            {
                std::uint64_t base_address;

                std::byte b[88];

                std::uint32_t import_address;
            };
            struct section_header
            {
                std::uint32_t miscellaneous;
                std::uint32_t relative_section_address;
                std::uint32_t section_size;
                std::uint32_t section_offset;
            };

            auto const dh = *reinterpret_cast<dos_header const*>(data_.data());
            auto const ph = *reinterpret_cast<pe_header const*>(&data_.at(dh.pe_offset));

            switch (ph.machine_id)
            {
                case 332:
                {
                    architecture_ = instruction_set_architecture::x86_32;
                    break;
                }
                case 34404:
                {
                    architecture_ = instruction_set_architecture::x86_64;
                    break;
                }
                default:
                    throw unknown_architecture();
            }

            std::uint_fast64_t base_address;
            std::uint_fast64_t import_address;
            switch (ph.optional_header_size)
            {
                case 224:
                {
                    auto const oh = *reinterpret_cast<optional_header_32 const*>(&data_.at(dh.pe_offset + 48));
                    base_address = oh.base_address;
                    import_address = oh.import_address;
                    break;
                }
                case 240:
                {
                    auto const oh = *reinterpret_cast<optional_header_64 const*>(&data_.at(dh.pe_offset + 48));
                    base_address = oh.base_address;
                    import_address = oh.import_address;
                    break;
                }
                default:
                    throw invalid_binary_format();
            }

            start_address_ = base_address + ph.relative_entry_point_address;

            sections_.insert(
                data_section
                {
                    .address = base_address,
                    .bytes = std::basic_string_view<std::byte>(data_.data(), dh.pe_offset + ph.optional_header_size + ph.section_count * 40 + 20)
                });
            for (auto section_index = 0; section_index < ph.section_count; ++section_index)
            {
                auto const sh = *reinterpret_cast<section_header const*>(&data_.at(dh.pe_offset + ph.optional_header_size + section_index * 40 + 32));

                sections_.insert(
                    data_section
                    {
                        .address = base_address + sh.relative_section_address,
                        .bytes = sh.section_size < sh.miscellaneous
                            ? std::basic_string_view<std::byte>(nullptr, sh.miscellaneous)
                            : std::basic_string_view<std::byte>(&data_.at(sh.section_offset), sh.section_size)
                    });
            }

            // TODO imports

            return;
        }
        if (data_text.substr(0, 4) == "\x7F""ELF")
        {
            // TODO
            throw invalid_binary_format();
        }

        throw invalid_binary_format();
    }
    program::program(std::vector<std::byte> data, instruction_set_architecture const architecture) :
        architecture_(architecture),
        data_(std::move(data)),
        sections_
        {
            data_section
            {
                .address = 0x0,
                .bytes = std::basic_string_view<std::byte>(data_.data(), data_.size())
            }
        }
    { }

    instruction_set_architecture program::architecture() const
    {
        return architecture_;
    }
    std::uint_fast64_t program::start_address() const
    {
        return start_address_;
    }

    std::basic_string_view<std::byte> program::operator[](std::uint_fast64_t const address) const
    {
        auto const section = sections_.lower_bound(address);

        if (section == sections_.upper_bound(address))
            throw std::invalid_argument("Invalid address");

        return section->bytes.substr(address - section->address);
    }

    static_assert(std::is_destructible_v<program>);

    static_assert(std::is_move_constructible_v<program>);
    static_assert(std::is_move_assignable_v<program>);

    static_assert(std::is_copy_constructible_v<program>);
    static_assert(std::is_copy_assignable_v<program>);
}
