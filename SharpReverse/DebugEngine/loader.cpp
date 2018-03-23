#include "stdafx.h"

#include "loader.h"

#include "bin_dump.h"

template <typename T>
T mem_read(uc_engine* uc, const uint64_t address, const int offset)
{
    T t;
    const auto size = sizeof(T);
    if (uc_mem_read(uc, address + offset * size, &t, size))
        throw;
    return t;
}
template <typename T>
T mem_read(uc_engine* uc, const uint64_t address)
{
    return mem_read<T>(uc, address, 0);
}

std::string mem_read_string(uc_engine* uc, const uint64_t address)
{
    auto end = false;
    std::vector<char> chars;
    for (auto j = 0;; ++j)
    {
        auto c = mem_read<char>(uc, address, j);

        if (c != '\0')
            end = true;
        else if (!end)
            continue;

        chars.push_back(c);

        if (c == '\0' && end)
            break;
    }

    return std::string(chars.begin(), chars.end());
}

template <typename T>
void mem_write(uc_engine* uc, const uint64_t address, T t, const int offset)
{
    const auto size = sizeof(T);
    if (uc_mem_write(uc, address + offset * size, &t, size))
        throw;
}
template <typename T>
void mem_write(uc_engine* uc, const uint64_t address, T t)
{
    mem_write<T>(uc, address, t, 0);
}

void init_registers(uc_engine* uc, size_t stack_pointer, size_t entry_point)
{
    if (uc_reg_write(uc, X86_REG_ESP, &stack_pointer))
        throw;
    if (uc_reg_write(uc, X86_REG_EBP, &stack_pointer))
        throw;

    if (uc_reg_write(uc, X86_REG_EIP, &entry_point))
        throw;
}
void init_section(uc_engine* uc, const std::vector<char> bytes, const size_t address)
{
    const auto alignment = 0x1000;

    auto size = alignment * (bytes.size() / alignment);
    if (bytes.size() % alignment > 0)
        size += alignment;

    if (uc_mem_map(uc, address, size, UC_PROT_ALL))
        throw;

    if (uc_mem_write(uc, address, &bytes[0], bytes.size()))
        throw;
}

int inspect_pe(const std::vector<char> bytes, pe_header_32& header)
{
    size_t cursor = 0;

    header.dos_header = *reinterpret_cast<const IMAGE_DOS_HEADER*>(&bytes[cursor]);

    if (header.dos_header.e_magic != 0x5A4D)
        return -1;

    const auto pe_id = *reinterpret_cast<const DWORD*>(&bytes[cursor += header.dos_header.e_lfanew]);

    if (pe_id != 0x4550)
        return -1;

    header.file_header = *reinterpret_cast<const IMAGE_FILE_HEADER*>(&bytes[cursor += sizeof(DWORD)]);
    header.optional_header = *reinterpret_cast<const IMAGE_OPTIONAL_HEADER*>(&bytes[cursor += sizeof(IMAGE_FILE_HEADER)]);
    
    header.section_headers = std::vector<IMAGE_SECTION_HEADER>(header.file_header.NumberOfSections);
    for (auto i = 0; i < header.section_headers.size(); ++i)
        header.section_headers[i] = *reinterpret_cast<const IMAGE_SECTION_HEADER*>(&bytes[cursor + sizeof(IMAGE_OPTIONAL_HEADER) + i * sizeof(IMAGE_SECTION_HEADER)]);

    //std::memcpy(&header.section_headers, &bytes[cursor], header.file_header.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    return 0;
}

void load_dll(uc_engine* uc, const std::string name)
{
    const auto file_name = "C:\\Windows\\System32\\" + name; // TODO: Replace with %windir%, etc.

    const auto bytes = create_dump(file_name);

    auto header = pe_header_32();
    if (inspect_pe(bytes, header))
        throw;

    const auto reloc = header.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    const auto dll_base = reinterpret_cast<uint32_t>(GetModuleHandleA(name.c_str())); // TODO: GetModuleHandle?

    for (auto s_h : header.section_headers)
        init_section(uc, std::vector<char>(bytes.begin() + s_h.PointerToRawData, bytes.begin() + s_h.PointerToRawData + s_h.SizeOfRawData), dll_base + s_h.VirtualAddress);

    auto offset = 0;
    while (true)
    {
        const auto br = mem_read<IMAGE_BASE_RELOCATION>(uc, dll_base + reloc + offset);

        if (br.VirtualAddress == 0x0)
            break;

        const int count = (br.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        for (auto j = 0; j < count; ++j)
        {
            auto w = mem_read<WORD>(uc, dll_base + reloc + offset + sizeof(IMAGE_BASE_RELOCATION), j);

            const auto type = (w & 0xf000) >> 12;
            w &= 0xfff;

            if (type == IMAGE_REL_BASED_HIGHLOW)
            {
                const auto address = dll_base + br.VirtualAddress + w;
                const auto delta = dll_base - header.optional_header.ImageBase;

                const auto value = mem_read<DWORD>(uc, address);

                mem_write(uc, address, value + delta);
            }
        }

        offset += br.SizeOfBlock;
    }
}

void initialize_import_table(uc_engine* uc, const size_t image_base, const size_t import_table_address)
{
    for (auto i = 0;; ++i)
    {
        const auto descriptor = mem_read<IMAGE_IMPORT_DESCRIPTOR>(uc, image_base + import_table_address, i);

        if (descriptor.Name == 0x0)
            break;

        auto module_name = mem_read_string(uc, image_base + descriptor.Name);

        load_dll(uc, module_name);

        for (auto j = 0;; ++j)
        {
            const auto proc_name_address = mem_read<DWORD>(uc, image_base + descriptor.FirstThunk, j);

            if (proc_name_address == 0x0)
                break;

            auto proc_name = mem_read_string(uc, image_base + proc_name_address);

            const auto proc_address = GetProcAddress(GetModuleHandleA(module_name.c_str()), proc_name.c_str()); // TODO: GetModuleHandle/GetProcAddress?
            mem_write(uc, image_base + descriptor.FirstThunk, proc_address, j);
        }
    }
}

void load(const std::vector<char> bytes, csh& cs, uc_engine*& uc)
{
    uint32_t entry_point;

    uint32_t stack_pointer;
    uint32_t stack_size;

    auto header = pe_header_32();
    if (inspect_pe(bytes, header))
    {
        cs_open(CS_ARCH_X86, CS_MODE_32, &cs); //
        uc_open(UC_ARCH_X86, UC_MODE_32, &uc); // TODO: Arch and mode?

        entry_point = 0x0;

        init_section(uc, bytes, entry_point);

        stack_pointer = 0xffffffff;
        stack_size = 0x1000;
    }
    else
    {
        cs_open(CS_ARCH_X86, CS_MODE_32, &cs); //
        uc_open(UC_ARCH_X86, UC_MODE_32, &uc); // TODO: Determine arch and mode from header.

        const auto image_base = header.optional_header.ImageBase;

        for (auto s_h : header.section_headers)
            init_section(uc, std::vector<char>(bytes.begin() + s_h.PointerToRawData, bytes.begin() + s_h.PointerToRawData + s_h.SizeOfRawData), image_base + s_h.VirtualAddress);

        initialize_import_table(uc, image_base, header.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        entry_point = image_base + header.optional_header.AddressOfEntryPoint;

        stack_pointer = 0xffffffff; // End of address space; TODO: Change?
        stack_size = header.optional_header.SizeOfStackCommit;
    }

    init_section(uc, std::vector<char>(stack_size), stack_pointer - stack_size + 1);
    init_registers(uc, stack_pointer, entry_point);
}
