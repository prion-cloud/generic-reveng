#include "stdafx.h"

#include "loader.h"

#include "binary_reader.h"

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

bool inspect_header(const binary_reader reader, pe_header_32& header)
{
    const auto find = [](binary_reader reader, std::optional<pe_header_32>& header_opt)
    {
        header_opt = std::nullopt;

        auto mz_id = reader.read_value<uint16_t>(0);
        if (mz_id != 0x5A4D)
            return;

        auto dh = reader.read_value<IMAGE_DOS_HEADER>(0);

        // TODO: dh -> magic_number?

        auto pe_id = reader.read_value<uint32_t>(dh.e_lfanew);
        if (pe_id != 0x00004550)
            return;

        auto fh = reader.read_value<IMAGE_FILE_HEADER>();

        const auto oh_size = fh.SizeOfOptionalHeader;

        IMAGE_OPTIONAL_HEADER32 oh;
        if (oh_size == sizeof(IMAGE_OPTIONAL_HEADER32))
            oh = reader.read_value<IMAGE_OPTIONAL_HEADER32>();
        else return;

        auto shs = reader.read_vector<IMAGE_SECTION_HEADER>(fh.NumberOfSections);

        std::optional<pe_header_32> h = pe_header_32();

        h->dos_header = dh;
        h->file_header = fh;

        h->optional_header = oh;

        h->section_headers = shs;

        header_opt = h;
    };

    std::optional<pe_header_32> header_opt;
    find(reader, header_opt); // TODO: Catch exception?

    if (header_opt == std::nullopt)
        return true;

    header = header_opt.value();

    return false;
}

void load_dll(uc_engine* uc, const std::string name)
{
    auto reader = binary_reader("C:\\Windows\\System32\\" + name); // TODO: Replace with %windir%, etc.

    auto header = pe_header_32();
    if (inspect_header(reader, header))
        throw;

    const auto reloc = header.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    const auto dll_base = reinterpret_cast<uint32_t>(GetModuleHandleA(name.c_str())); // TODO: GetModuleHandle?

    for (auto s_h : header.section_headers)
        init_section(uc, reader.read_vector<char>(s_h.SizeOfRawData, s_h.PointerToRawData), dll_base + s_h.VirtualAddress);

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

void load_pe(const std::string file_name, csh& cs, uc_engine*& uc)
{
    auto reader = binary_reader(file_name);

    auto header = pe_header_32();
    if (inspect_header(reader, header))
        throw;

    cs_open(CS_ARCH_X86, CS_MODE_32, &cs); //
    uc_open(UC_ARCH_X86, UC_MODE_32, &uc); // TODO: Determine arch and mode

    const auto image_base = header.optional_header.ImageBase;

    for (auto s_h : header.section_headers)
        init_section(uc, reader.read_vector<char>(s_h.SizeOfRawData, s_h.PointerToRawData), image_base + s_h.VirtualAddress);

    initialize_import_table(uc, image_base, header.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    reader.close();

    const auto stack_pointer = 0xffffffff; // End of address space; TODO: Change?
    const auto stack_size = header.optional_header.SizeOfStackCommit;

    init_section(uc, std::vector<char>(stack_size), stack_pointer - stack_size + 1);
    init_registers(uc, stack_pointer, image_base + header.optional_header.AddressOfEntryPoint);
}

void load_bytes(const std::vector<char> bytes, csh& cs, uc_engine*& uc)
{
    cs_open(CS_ARCH_X86, CS_MODE_32, &cs);
    uc_open(UC_ARCH_X86, UC_MODE_32, &uc);

    const uint32_t entry_point = 0x0;

    init_section(uc, bytes, entry_point);

    const auto stack_pointer = 0xffffffff;
    const auto stack_size = 0x1000;

    init_section(uc, std::vector<char>(stack_size), stack_pointer - stack_size + 1);
    init_registers(uc, stack_pointer, entry_point);
}
