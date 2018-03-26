#include "stdafx.h"

#include "loader.h"

#include "bin_dump.h"

#define VISIT(var, member) visit([](auto x) { return x.member; }, var)
#define VISIT_CAST(var, member, cast) visit([](auto x) { return static_cast<cast>(x.member); }, var)

template <typename T>
T mem_read(uc_engine* uc, const size_t address, const int offset)
{
    T t;
    const auto size = sizeof(T);
    if (uc_mem_read(uc, address + offset * size, &t, size))
        throw;
    return t;
}
template <typename T>
T mem_read(uc_engine* uc, const size_t address)
{
    return mem_read<T>(uc, address, 0);
}

template <typename T>
void mem_write(uc_engine* uc, const size_t address, T t, const int offset)
{
    const auto size = sizeof(T);
    if (uc_mem_write(uc, address + offset * size, &t, size))
        throw;
}
template <typename T>
void mem_write(uc_engine* uc, const size_t address, T t)
{
    mem_write<T>(uc, address, t, 0);
}

template <typename T>
void reg_write(uc_engine* uc, const int regid, const T value)
{
    if (uc_reg_write(uc, regid, &value))
        throw;
}

std::string mem_read_string(uc_engine* uc, const size_t address)
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

int inspect_pe(const std::vector<char> bytes, pe_header& header)
{
    size_t cursor = 0;

    header.dos_header = *reinterpret_cast<const IMAGE_DOS_HEADER*>(&bytes[cursor]);

    if (header.dos_header.e_magic != 0x5A4D)
        return -1;

    const auto pe_id = *reinterpret_cast<const DWORD*>(&bytes[cursor += header.dos_header.e_lfanew]);

    if (pe_id != 0x4550)
        return -1;

    header.file_header = *reinterpret_cast<const IMAGE_FILE_HEADER*>(&bytes[cursor += sizeof(DWORD)]);

    cursor += sizeof(IMAGE_FILE_HEADER);

    switch (header.file_header.SizeOfOptionalHeader)
    {
    case sizeof(IMAGE_OPTIONAL_HEADER32):
        header.optional_header = *reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(&bytes[cursor]);
        break;
    case sizeof(IMAGE_OPTIONAL_HEADER64):
        header.optional_header = *reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(&bytes[cursor]);
        break;
    default:
        return -1;
    }

    cursor += header.file_header.SizeOfOptionalHeader;

    header.section_headers = std::vector<IMAGE_SECTION_HEADER>(header.file_header.NumberOfSections);
    for (auto i = 0; i < header.section_headers.size(); ++i)
        header.section_headers[i] = *reinterpret_cast<const IMAGE_SECTION_HEADER*>(&bytes[cursor + i * sizeof(IMAGE_SECTION_HEADER)]);

    return 0;
}

void init_registers(uc_engine* uc, const target_machine target, const size_t stack_pointer, const size_t entry_point)
{
    switch (target)
    {
    case machine_x86_32:
        reg_write(uc, UC_X86_REG_ESP, stack_pointer);
        reg_write(uc, UC_X86_REG_EBP, stack_pointer);
        reg_write(uc, UC_X86_REG_EIP, entry_point);
        break;
    case machine_x86_64:
        reg_write(uc, UC_X86_REG_RSP, stack_pointer);
        reg_write(uc, UC_X86_REG_RBP, stack_pointer);
        reg_write(uc, UC_X86_REG_RIP, entry_point);
        break;
    default:
        throw;
    }
}
void init_section(uc_engine* uc, const std::vector<char> bytes, const size_t address)
{
    if (bytes.size() == 0)
        return;

    const auto alignment = 0x1000;

    auto size = alignment * (bytes.size() / alignment);
    if (bytes.size() % alignment > 0)
        size += alignment;

    if (uc_mem_map(uc, address, size, UC_PROT_ALL))
        throw;

    if (uc_mem_write(uc, address, &bytes[0], bytes.size()))
        throw;
}

void init_imports(uc_engine* uc, const size_t image_base, const size_t import_table_address)
{
    for (auto i = 0;; ++i)
    {
        const auto descriptor = mem_read<IMAGE_IMPORT_DESCRIPTOR>(uc, image_base + import_table_address, i);

        if (descriptor.Name == 0x0)
            break;

        const auto dll_name = mem_read_string(uc, image_base + descriptor.Name);
        const auto dll_handle = GetModuleHandleA(dll_name.c_str());   // TODO: GetModuleHandle?
        const auto dll_base = reinterpret_cast<size_t>(dll_handle); //

        const auto dll_bytes = create_dump("C:\\Windows\\System32\\" + dll_name); // TODO: Replace with %windir%, etc. / Search dll file
        
        auto dll_header = pe_header();
        if (inspect_pe(dll_bytes, dll_header))
            throw;

        const auto dll_reloc = VISIT(dll_header.optional_header, DataDirectory)[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        
        for (auto s_h : dll_header.section_headers)
            init_section(uc, std::vector<char>(dll_bytes.begin() + s_h.PointerToRawData, dll_bytes.begin() + s_h.PointerToRawData + s_h.SizeOfRawData), dll_base + s_h.VirtualAddress);

        auto offset = 0;
        while (true)
        {
            const auto reloc = mem_read<IMAGE_BASE_RELOCATION>(uc, dll_base + dll_reloc + offset);

            if (!reloc.VirtualAddress)
                break;

            const int count = (reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (auto j = 0; j < count; ++j)
            {
                auto w = mem_read<WORD>(uc, dll_base + dll_reloc + offset + sizeof(IMAGE_BASE_RELOCATION), j);

                const auto type = (w & 0xf000) >> 12;
                w &= 0xfff;

                if (type == IMAGE_REL_BASED_HIGHLOW)
                {
                    const auto address = dll_base + reloc.VirtualAddress + w;
                    const auto delta = dll_base - std::visit([](auto x) { return static_cast<uint64_t>(x.ImageBase); }, dll_header.optional_header);

                    const auto value = mem_read<DWORD>(uc, address);

                    mem_write(uc, address, value + delta);
                }
            }

            offset += reloc.SizeOfBlock;
        }

        for (auto j = 0;; ++j)
        {
            const auto proc_name_address = mem_read<DWORD>(uc, image_base + descriptor.FirstThunk, j);

            if (!proc_name_address)
                break;

            mem_write(uc, image_base + descriptor.FirstThunk,
                GetProcAddress(dll_handle, mem_read_string(uc, image_base + proc_name_address).c_str()), j); // TODO: GetProcAddress?
        }
    }
}

target_machine load_x86(const std::vector<char> bytes, csh& cs, uc_engine*& uc)
{
    target_machine target;

    size_t entry_point;

    size_t stack_size;

    auto header = pe_header();
    if (inspect_pe(bytes, header))
    {
        target = machine_x86_32;

        cs_open(CS_ARCH_X86, CS_MODE_32, &cs); //
        uc_open(UC_ARCH_X86, UC_MODE_32, &uc); // TODO: Arch and mode?

        entry_point = 0x0;

        init_section(uc, bytes, entry_point);

        stack_size = 0x1000;
    }
    else
    {
        cs_mode cs_mode;
        uc_mode uc_mode;

        switch (header.file_header.Machine)
        {
        case IMAGE_FILE_MACHINE_I386:
            target = machine_x86_32;
            cs_mode = CS_MODE_32;
            uc_mode = UC_MODE_32;
            break;
#ifdef _WIN64
        case IMAGE_FILE_MACHINE_AMD64:
            target = machine_x86_64;
            cs_mode = CS_MODE_64;
            uc_mode = UC_MODE_64;
            break;
#endif
        default:
            throw;
        }

        cs_open(CS_ARCH_X86, cs_mode, &cs);
        uc_open(UC_ARCH_X86, uc_mode, &uc);

        const auto image_base = VISIT_CAST(header.optional_header, ImageBase, size_t);

        for (auto s_h : header.section_headers)
            init_section(uc, std::vector<char>(bytes.begin() + s_h.PointerToRawData, bytes.begin() + s_h.PointerToRawData + s_h.SizeOfRawData), image_base + s_h.VirtualAddress);

        init_imports(uc, image_base, VISIT(header.optional_header, DataDirectory)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        entry_point = image_base + VISIT(header.optional_header, AddressOfEntryPoint);

        stack_size = VISIT_CAST(header.optional_header, SizeOfStackCommit, size_t);
    }
    
    size_t stack_pointer; // End of address space; TODO: Change?
    switch (target)
    {
    case machine_x86_32:
        stack_pointer = 0xffffffff;
        break;
    case machine_x86_64:
        stack_pointer = 0xffffffffffffffff;
        break;
    default:
        throw;
    }

    init_section(uc, std::vector<char>(stack_size), stack_pointer - stack_size + 1);
    init_registers(uc, target, stack_pointer, entry_point);

    return target;
}
