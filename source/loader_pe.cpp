#include <vector>

#include "../include/follower/loader.h"
#include "../include/follower/win_structs.h"

template <typename T>
T extract(std::istream& stream)
{
    T result { };
    stream.read(reinterpret_cast<char*>(&result), sizeof(T));

    return result;
}
std::vector<uint8_t> extract(std::istream& stream, size_t size)
{
    std::vector<uint8_t> result(size);
    stream.read(reinterpret_cast<char*>(&result.front()), size);

    return result;
}

loader_pe::loader_pe(uc_arch const architecture, const uc_mode mode)
    : loader(architecture, mode) { }

std::shared_ptr<uc_engine> loader_pe::operator()(std::istream& is) const
{
    auto const dos_header = extract<image_dos_header>(is);

    if (dos_header.e_magic != 0x5a4d)
        throw std::runtime_error("Invalid PE header");

    is.seekg(dos_header.e_lfanew);

    if (extract<uint32_t>(is) != 0x4550)
        throw std::runtime_error("Invalid PE header");

    auto const file_header = extract<image_file_header>(is);

    std::unordered_map<uint16_t, std::pair<uc_arch, uc_mode>> machine_map
    {
        { IMAGE_FILE_MACHINE_I386, { UC_ARCH_X86, UC_MODE_32 } },
        { IMAGE_FILE_MACHINE_X64,  { UC_ARCH_X86, UC_MODE_64 } }
    };

    auto const it_machine = machine_map.find(file_header.machine);
    if (it_machine == machine_map.end() || it_machine->second != machine_)
        throw std::runtime_error("Invalid PE architecture");

    uint64_t entry_point;
    uint64_t image_base;
    switch (file_header.size_of_optional_header)
    {
    case sizeof(image_optional_header_32):
        {
            auto const optional_header = extract<image_optional_header_32>(is);
            entry_point = optional_header.address_of_entry_point;
            image_base = optional_header.image_base;
        }
        break;
    case sizeof(image_optional_header_64):
        {
            auto const optional_header = extract<image_optional_header_64>(is);
            entry_point = optional_header.address_of_entry_point;
            image_base = optional_header.image_base;
        }
        break;
    default:
        throw std::runtime_error("Invalid PE header");
    }

    std::vector<image_section_header> section_headers;
    for (unsigned i = 0; i < file_header.number_of_sections; ++i)
        section_headers.push_back(extract<image_section_header>(is));

    auto const uc = create_uc();

    for (auto const& section_header : section_headers)
    {
        size_t constexpr PAGE_SIZE = 0x1000;

        auto const address = image_base + section_header.virtual_address;
        auto const size = PAGE_SIZE * ((section_header.size_of_raw_data - 1) / PAGE_SIZE + 1);

        is.seekg(section_header.pointer_to_raw_data);
        auto const bytes = extract(is, section_header.size_of_raw_data);

        uc_mem_map(uc.get(), address, size, UC_PROT_ALL);
        uc_mem_write(uc.get(), address, &bytes.front(), bytes.size());
    }

    entry_point += image_base;
    uc_reg_write(uc.get(), instruction_pointer_register_id_, &entry_point);

    is.seekg(0, std::ios_base::end);
    return uc;
}
