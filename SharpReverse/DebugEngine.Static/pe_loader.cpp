#include "stdafx.h"

#include "pe_loader.h"

#include "bin_dump.h"

#define VISIT(var, member) visit([](auto x) { return x.member; }, var)
#define VISIT_CAST(var, member, cast) visit([](auto x) { return static_cast<cast>(x.member); }, var)

bool pe_header::targets_32() const
{
    return file_header.Machine == IMAGE_FILE_MACHINE_I386;
}
bool pe_header::targets_64() const
{
    return file_header.Machine == IMAGE_FILE_MACHINE_AMD64;
}

template <typename T>
T mem_read(uc_engine* uc, const size_t address, const int offset)
{
    T t;
    const auto size = sizeof(T);
    C_VIT(uc_mem_read(uc, address + offset * size, &t, size));
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
    C_VIT(uc_mem_write(uc, address + offset * size, &t, size));
}
template <typename T>
void mem_write(uc_engine* uc, const size_t address, T t)
{
    mem_write<T>(uc, address, t, 0);
}

template <typename T>
void reg_write(uc_engine* uc, const int regid, const T value)
{
    C_VIT(uc_reg_write(uc, regid, &value));
}

std::string mem_read_string_skip(uc_engine* uc, const size_t address)
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

int inspect_header(const std::vector<char> bytes, pe_header& header)
{
    size_t cursor = 0;

    header.dos_header = *reinterpret_cast<const IMAGE_DOS_HEADER*>(&bytes[cursor]);

    if (header.dos_header.e_magic != 0x5A4D)
        return F_FAILURE;

    const auto pe_id = *reinterpret_cast<const DWORD*>(&bytes[cursor += header.dos_header.e_lfanew]);

    if (pe_id != 0x4550)
        return F_FAILURE;

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
        return F_FAILURE;
    }

    cursor += header.file_header.SizeOfOptionalHeader;

    header.section_headers = std::vector<IMAGE_SECTION_HEADER>(header.file_header.NumberOfSections);
    for (auto i = 0; i < header.section_headers.size(); ++i)
        header.section_headers[i] = *reinterpret_cast<const IMAGE_SECTION_HEADER*>(&bytes[cursor + i * sizeof(IMAGE_SECTION_HEADER)]);

    return F_SUCCESS;
}

void init_section(uc_engine* uc, const std::vector<char> bytes, const size_t address)
{
    if (bytes.size() == 0)
        return;

    const auto alignment = 0x1000;

    auto size = alignment * (bytes.size() / alignment);
    if (bytes.size() % alignment > 0)
        size += alignment;

    C_VIT(uc_mem_map(uc, address, size, UC_PROT_ALL));
    C_VIT(uc_mem_write(uc, address, &bytes[0], bytes.size()));
}
void init_imports(uc_engine* uc, const size_t image_base, const size_t import_table_address)
{
    for (auto i = 0;; ++i)
    {
        const auto descriptor = mem_read<IMAGE_IMPORT_DESCRIPTOR>(uc, image_base + import_table_address, i);

        if (descriptor.Name == 0x0)
            break;

        const auto dll_name = mem_read_string_skip(uc, image_base + descriptor.Name);
        const auto dll_handle = GetModuleHandleA(dll_name.c_str());   // TODO: GetModuleHandle?
        const auto dll_base = reinterpret_cast<size_t>(dll_handle); //

        std::vector<char> dll_bytes;
        C_VIT(create_dump("C:\\Windows\\System32\\" + dll_name, dll_bytes)); // TODO: Replace with %windir%, etc. / Search dll file
        
        auto dll_header = pe_header();
        C_VIT(inspect_header(dll_bytes, dll_header));

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
                GetProcAddress(dll_handle, mem_read_string_skip(uc, image_base + proc_name_address).c_str()), j); // TODO: GetProcAddress?
        }
    }
}

int load_pe(const std::vector<char> bytes, pe_header& header, csh& cs, uc_engine*& uc)
{
    size_t stack_pointer; // End of address space; TODO: Change?
    size_t stack_size;

    if (inspect_header(bytes, header))
    {
        // TODO: Move this somewhere else -> FAILURE

        cs_open(CS_ARCH_X86, CS_MODE_32, &cs); //
        uc_open(UC_ARCH_X86, UC_MODE_32, &uc); // TODO: Arch and mode?

        init_section(uc, bytes, 0x0);
        
        stack_pointer = 0xffffffff;
        stack_size = 0x1000;

        reg_write(uc, UC_X86_REG_ESP, stack_pointer);
        reg_write(uc, UC_X86_REG_EBP, stack_pointer);
        reg_write(uc, UC_X86_REG_EIP, 0x0);
    }
    else
    {
        const auto image_base = VISIT_CAST(header.optional_header, ImageBase, size_t);
        const auto entry_point = image_base + VISIT_CAST(header.optional_header, AddressOfEntryPoint, size_t);

        if (header.targets_32())
        {
            cs_open(CS_ARCH_X86, CS_MODE_32, &cs);
            uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
            
            stack_pointer = 0xffffffff;

            reg_write(uc, UC_X86_REG_ESP, stack_pointer);
            reg_write(uc, UC_X86_REG_EBP, stack_pointer);
            reg_write(uc, UC_X86_REG_EIP, entry_point);
        }
#ifdef _WIN64
        else if (header.targets_64())
        {
            cs_open(CS_ARCH_X86, CS_MODE_64, &cs);
            uc_open(UC_ARCH_X86, UC_MODE_64, &uc);

            stack_pointer = 0xffffffffffffffff;

            reg_write(uc, UC_X86_REG_RSP, stack_pointer);
            reg_write(uc, UC_X86_REG_RBP, stack_pointer);
            reg_write(uc, UC_X86_REG_RIP, entry_point);
        }
#endif
        else E_THROW;

        for (auto s_h : header.section_headers)
            init_section(uc, std::vector<char>(bytes.begin() + s_h.PointerToRawData, bytes.begin() + s_h.PointerToRawData + s_h.SizeOfRawData), image_base + s_h.VirtualAddress);

        init_imports(uc, image_base, VISIT(header.optional_header, DataDirectory)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        stack_size = VISIT_CAST(header.optional_header, SizeOfStackCommit, size_t);
    }

    init_section(uc, std::vector<char>(stack_size), stack_pointer - stack_size + 1);

    return F_SUCCESS;
}