#include "stdafx.h"

#include "loader.h"

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
        IMAGE_IMPORT_DESCRIPTOR descriptor;
        C_VIT(uc_ext_mem_read<IMAGE_IMPORT_DESCRIPTOR>(uc, image_base + import_table_address, descriptor, i));

        if (descriptor.Name == 0x0)
            break;

        const auto dll_name = uc_ext_mem_read_string_skip(uc, image_base + descriptor.Name);
        const auto dll_handle = GetModuleHandleA(dll_name.c_str()); // TODO: GetModuleHandle?
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
            IMAGE_BASE_RELOCATION reloc;
            C_VIT(uc_ext_mem_read(uc, dll_base + dll_reloc + offset, reloc));

            if (!reloc.VirtualAddress)
                break;

            const int count = (reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (auto j = 0; j < count; ++j)
            {
                WORD w;
                C_VIT(uc_ext_mem_read(uc, dll_base + dll_reloc + offset + sizeof(IMAGE_BASE_RELOCATION), w, j));

                const auto type = (w & 0xf000) >> 12;
                w &= 0xfff;

                if (type == IMAGE_REL_BASED_HIGHLOW)
                {
                    const auto address = dll_base + reloc.VirtualAddress + w;
                    const auto delta = dll_base - std::visit([](auto x) { return static_cast<uint64_t>(x.ImageBase); }, dll_header.optional_header);

                    DWORD value;
                    C_VIT(uc_ext_mem_read(uc, address, value));

                    C_VIT(uc_ext_mem_write(uc, address, value + delta));
                }
            }

            offset += reloc.SizeOfBlock;
        }

        for (auto j = 0;; ++j)
        {
            DWORD proc_name_address;
            C_VIT(uc_ext_mem_read(uc, image_base + descriptor.FirstThunk, proc_name_address, j));

            if (!proc_name_address)
                break;

            C_VIT(uc_ext_mem_write(uc, image_base + descriptor.FirstThunk,
                GetProcAddress(dll_handle, uc_ext_mem_read_string_skip(uc, image_base + proc_name_address).c_str()), j)); // TODO: GetProcAddress?
        }
    }
}

int pe_loader::load(const std::vector<char> bytes, csh& cs, uc_engine*& uc, uint64_t& scale, std::vector<int>& regs, int& ip_index) const
{
    pe_header header;
    C_IMP(inspect_header(bytes, header));

    const auto image_base = VISIT_CAST(header.optional_header, ImageBase, size_t);
    const auto entry_point = image_base + VISIT_CAST(header.optional_header, AddressOfEntryPoint, size_t);
    
    if (header.targets_32())
    {
        cs_open(CS_ARCH_X86, CS_MODE_32, &cs);
        uc_open(UC_ARCH_X86, UC_MODE_32, &uc);

        scale = 0xffffffff;

        regs =
        {
            X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_EDX,
            X86_REG_ESP, X86_REG_EBP,
            X86_REG_ESI, X86_REG_EDI,
            X86_REG_EIP
        };
        ip_index = 8;
    }
#ifdef _WIN64
    else if (header.targets_64())
    {
        cs_open(CS_ARCH_X86, CS_MODE_64, &cs);
        uc_open(UC_ARCH_X86, UC_MODE_64, &uc);

        scale = 0xffffffffffffffff;

        regs =
        {
            X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX,
            X86_REG_RSP, X86_REG_RBP,
            X86_REG_RSI, X86_REG_RDI,
            X86_REG_RIP
        };
        ip_index = 8;
    }
#endif
    else E_THROW;

    for (auto s_h : header.section_headers)
        init_section(uc, std::vector<char>(bytes.begin() + s_h.PointerToRawData, bytes.begin() + s_h.PointerToRawData + s_h.SizeOfRawData), image_base + s_h.VirtualAddress);

    init_imports(uc, image_base, VISIT(header.optional_header, DataDirectory)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    const auto stack_pointer = scale; // End of address space; TODO: Change?
    const auto stack_size = VISIT_CAST(header.optional_header, SizeOfStackCommit, size_t);
    init_section(uc, std::vector<char>(stack_size), stack_pointer - stack_size + 1);

    C_VIT(uc_reg_write(uc, regs[4], &stack_pointer));
    C_VIT(uc_reg_write(uc, regs[5], &stack_pointer));
    C_VIT(uc_reg_write(uc, regs[8], &entry_point));

    return F_SUCCESS;
}
