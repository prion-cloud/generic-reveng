#include <iostream>
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

loader_pe::loader_pe(uc_arch const architecture, const uc_mode mode)
    : loader(architecture, mode) { }

std::shared_ptr<uc_engine> loader_pe::operator()(std::istream& stream) const
{
    uc_engine* uc;
    uc_open(UC_ARCH_X86, UC_MODE_64, &uc);

    auto const dos_header = extract<image_dos_header>(stream);

    if (dos_header.e_magic != 0x5a4d)
        throw std::runtime_error("PE header invalid");

    stream.seekg(dos_header.e_lfanew);

    if (extract<uint32_t>(stream) != 0x4550)
        throw std::runtime_error("PE header invalid");

    uint64_t entry_point;
    uint64_t image_base;
    switch (extract<image_file_header>(stream).SizeOfOptionalHeader)
    {
    case sizeof(image_optional_header_32):
        {
            auto const optional_header = extract<image_optional_header_32>(stream);
            entry_point = optional_header.AddressOfEntryPoint;
            image_base = optional_header.ImageBase;
        }
        break;
    case sizeof(image_optional_header_64):
        {
            auto const optional_header = extract<image_optional_header_64>(stream);
            entry_point = optional_header.AddressOfEntryPoint;
            image_base = optional_header.ImageBase;
        }
        break;
    default:
        throw std::runtime_error("PE header invalid");
    }

    std::cout << "Entry point: 0x" << std::hex << std::uppercase << image_base + entry_point << std::endl;

    // TODO

    return std::shared_ptr<uc_engine>(uc, uc_close);
}
