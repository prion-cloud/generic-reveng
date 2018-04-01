#include "stdafx.h"
#include "macro.h"

#include "loader.h"

#include "bin_dump.h"

#define VISIT(var, member) visit([](auto x) { return x.member; }, var)
#define VISIT_CAST(var, member, cast) visit([](auto x) { return static_cast<cast>(x.member); }, var)

int binary_search(const std::function<std::string(int)> f, const std::string s, int l, int r)
{
    while (true)
    {
        if (l > r)
            return -1;

        const auto m = (l + r) / 2;

        if (f(m).compare(s) < 0)
        {
            l = m + 1;
            continue;
        }

        if (f(m).compare(s) > 0)
        {
            r = m - 1;
            continue;
        }

        return m;
    }
}

std::vector<char> dump_dll(const std::string dll_name, const WORD machine)
{
    auto file_name = std::ostringstream();
    file_name << getenv("windir") << "\\";
    
    auto wow64 = FALSE;
    C_FAT(!IsWow64Process(GetCurrentProcess(), &wow64));
    
#ifdef _WIN64
    wow64 = wow64 || machine == IMAGE_FILE_MACHINE_I386;
#endif

    file_name << (wow64 ? "SysWOW64" : "System32") << "\\" << dll_name;

    std::vector<char> dll_bytes;
    C_FAT(create_dump(file_name.str(), dll_bytes));

    return dll_bytes;
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

uint64_t init_section(uc_engine* uc, const std::vector<char> bytes, const uint64_t address)
{
    if (bytes.size() == 0)
        return 0;
    
    const uint64_t alignment = 0x1000;

    auto size = alignment * (bytes.size() / alignment);
    if (bytes.size() % alignment > 0)
        size += alignment;

    C_FAT(uc_mem_map(uc, address, static_cast<size_t>(size), UC_PROT_ALL));
    C_FAT(uc_mem_write(uc, address, &bytes[0], bytes.size()));

    return size;
}
void init_imports(uc_engine* uc, const uint64_t image_base, const uint64_t imports_address, const WORD machine)
{
    uint64_t dll_image_base = 0x70000000; // TODO: Make bitness-dependent.

    for (auto i = 0;; ++i)
    {
        IMAGE_IMPORT_DESCRIPTOR import_descriptor;
        C_FAT(uc_ext_mem_read(uc, image_base + imports_address, import_descriptor, i));

        if (import_descriptor.Name == 0x0)
            break;

        std::string dll_name;
        C_FAT(uc_ext_mem_read_string(uc, image_base + import_descriptor.Name, dll_name));

        const auto dll_bytes = dump_dll(dll_name, machine);
        
        auto dll_header = pe_header();
        C_FAT(inspect_header(dll_bytes, dll_header));

        const auto dll_reloc = VISIT(dll_header.optional_header, DataDirectory)[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        
        uint64_t dll_end = 0;
        for (auto s_h : dll_header.section_headers)
        {
            dll_end = dll_image_base + s_h.VirtualAddress;
            dll_end += init_section(uc, std::vector<char>(dll_bytes.begin() + s_h.PointerToRawData, dll_bytes.begin() + s_h.PointerToRawData + s_h.SizeOfRawData), dll_end);
        }

        auto offset = 0;
        while (true)
        {
            IMAGE_BASE_RELOCATION reloc;
            C_FAT(uc_ext_mem_read(uc, dll_image_base + dll_reloc + offset, reloc));

            if (!reloc.VirtualAddress)
                break;

            const int count = (reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (auto j = 0; j < count; ++j)
            {
                WORD w;
                C_FAT(uc_ext_mem_read(uc, dll_image_base + dll_reloc + offset + sizeof(IMAGE_BASE_RELOCATION), w, j));

                const auto type = (w & 0xf000) >> 12;
                w &= 0xfff;

                if (type == IMAGE_REL_BASED_HIGHLOW)
                {
                    const auto address = dll_image_base + reloc.VirtualAddress + w;
                    const auto delta = dll_image_base - std::visit([](auto x) { return static_cast<uint64_t>(x.ImageBase); }, dll_header.optional_header);

                    DWORD value;
                    C_FAT(uc_ext_mem_read(uc, address, value));

                    C_FAT(uc_ext_mem_write(uc, address, value + delta));
                }
            }

            offset += reloc.SizeOfBlock;
        }

        for (auto j = 0;; ++j)
        {
            DWORD dll_import_proc_name_address;
            C_FAT(uc_ext_mem_read(uc, image_base + import_descriptor.FirstThunk, dll_import_proc_name_address, j));

            if (dll_import_proc_name_address == 0x0)
                break;

            dll_import_proc_name_address += sizeof(WORD);

            std::string dll_import_proc_name;
            C_FAT(uc_ext_mem_read_string(uc, image_base + dll_import_proc_name_address, dll_import_proc_name));

            const uint64_t dll_exports_address = VISIT(dll_header.optional_header, DataDirectory)[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

            IMAGE_EXPORT_DIRECTORY dll_export_directory;
            C_FAT(uc_ext_mem_read(uc, dll_image_base + dll_exports_address, dll_export_directory));

            DWORD dll_export_proc_address = 0x0;

            const std::function<std::string(int)> f = [uc, dll_image_base, dll_export_directory](int k)
            {
                DWORD dll_export_proc_name_address;
                C_FAT(uc_ext_mem_read(uc, dll_image_base + dll_export_directory.AddressOfNames, dll_export_proc_name_address, k));
                
                std::string dll_export_proc_name;
                C_FAT(uc_ext_mem_read_string(uc, dll_image_base + dll_export_proc_name_address, dll_export_proc_name));

                return dll_export_proc_name;
            };

            const auto dll_export_proc_index = binary_search(f, dll_import_proc_name, 0, dll_export_directory.NumberOfNames - 1);

            C_FAT(dll_export_proc_index < 0);

            C_FAT(uc_ext_mem_read<DWORD>(uc, dll_image_base + dll_export_directory.AddressOfFunctions, dll_export_proc_address, dll_export_proc_index));

            if (dll_export_proc_address == 0x0)
                continue; // TODO: Error ?
            
            C_FAT(uc_ext_mem_write<DWORD>(uc, image_base + import_descriptor.FirstThunk, dll_image_base + dll_export_proc_address, j));
        }

        dll_image_base = dll_end;
    }
}

int pe_loader::load(const std::vector<char> bytes, csh& cs, uc_engine*& uc, uint64_t& scale, std::vector<int>& regs, int& ip_index) const
{
    pe_header header;
    C_ERR(inspect_header(bytes, header));

    const auto image_base = VISIT_CAST(header.optional_header, ImageBase, size_t);
    const auto entry_point = image_base + VISIT_CAST(header.optional_header, AddressOfEntryPoint, size_t);
    
    if (header.file_header.Machine == IMAGE_FILE_MACHINE_I386)
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
    else if (header.file_header.Machine == IMAGE_FILE_MACHINE_AMD64)
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

    init_imports(uc, image_base, VISIT(header.optional_header, DataDirectory)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, header.file_header.Machine);

    const auto stack_pointer = scale; // End of address space; TODO: Change?
    const auto stack_size = VISIT_CAST(header.optional_header, SizeOfStackCommit, size_t);
    init_section(uc, std::vector<char>(stack_size), stack_pointer - stack_size + 1);

    C_FAT(uc_reg_write(uc, regs[4], &stack_pointer));
    C_FAT(uc_reg_write(uc, regs[5], &stack_pointer));
    C_FAT(uc_reg_write(uc, regs[8], &entry_point));

    return F_SUCCESS;
}
