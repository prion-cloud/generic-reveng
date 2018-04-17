#include "stdafx.h"
#include "macro.h"

#include "loader.h"

#include "bin_dump.h"

std::map<std::string, std::tuple<uint64_t, uint64_t>> imports;

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

int dump_dll(const std::string dll_name, const WORD machine, std::vector<char>& dll_bytes)
{
    // TODO: Look for DLL in application folder.

    auto file_name = std::ostringstream();
    file_name << getenv("windir") << "\\";
    
    auto wow64 = FALSE;
    E_FAT(!IsWow64Process(GetCurrentProcess(), &wow64));
    
#ifdef _WIN64
    wow64 |= machine == IMAGE_FILE_MACHINE_I386;
#endif

    file_name << (wow64 ? "SysWOW64" : "System32") << "\\" << dll_name;

    if (create_filedump(file_name.str(), dll_bytes))
        return R_FAILURE;

    return R_SUCCESS;
}

int header_pe::inspect(std::vector<char> bytes)
{
    size_t cursor = 0;

    const auto h_dos = *reinterpret_cast<const IMAGE_DOS_HEADER*>(&bytes[cursor]);
    E_ERR(h_dos.e_magic != 0x5A4D);

    const auto pe_sig = *reinterpret_cast<const DWORD*>(&bytes[cursor += h_dos.e_lfanew]);
    E_ERR(pe_sig != 0x4550);

    const auto h_fil = *reinterpret_cast<const IMAGE_FILE_HEADER*>(&bytes[cursor += sizeof(DWORD)]);
    cursor += sizeof h_fil;

    machine = h_fil.Machine;

    data_directories = std::array<IMAGE_DATA_DIRECTORY, 16>();

    switch (h_fil.SizeOfOptionalHeader)
    {
    case sizeof(IMAGE_OPTIONAL_HEADER32):
        const auto h_opt32 = *reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(&bytes[cursor]);

        image_base = h_opt32.ImageBase;
        stack_commit = h_opt32.SizeOfStackCommit;

        entry_point = h_opt32.AddressOfEntryPoint;

        std::copy(
            std::begin(h_opt32.DataDirectory),
            std::end(h_opt32.DataDirectory),
            std::begin(data_directories));

        break;
    case sizeof(IMAGE_OPTIONAL_HEADER64):
    {
        const auto h_opt64 = *reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(&bytes[cursor]);

        image_base = h_opt64.ImageBase;
        stack_commit = h_opt64.SizeOfStackCommit;

        entry_point = h_opt64.AddressOfEntryPoint;

        std::copy(
            std::begin(h_opt64.DataDirectory),
            std::end(h_opt64.DataDirectory),
            std::begin(data_directories));

        break;
    }
    default:
        return R_FAILURE;
    }
    cursor += h_fil.SizeOfOptionalHeader;

    section_headers = std::vector<IMAGE_SECTION_HEADER>();
    for (unsigned i = 0; i < h_fil.NumberOfSections; ++i)
        section_headers.push_back(*reinterpret_cast<const IMAGE_SECTION_HEADER*>(&bytes[cursor + i * sizeof(IMAGE_SECTION_HEADER)]));

    return R_SUCCESS;
}

uint64_t init_section(uc_engine* uc, const std::vector<char> bytes, const uint64_t address)
{
    if (bytes.size() == 0)
        return 0;
    
    const uint64_t alignment = 0x1000;

    auto size = alignment * (bytes.size() / alignment);
    if (bytes.size() % alignment > 0)
        size += alignment;

    E_FAT(uc_mem_map(uc, address, static_cast<size_t>(size), UC_PROT_ALL));
    E_FAT(uc_mem_write(uc, address, &bytes[0], bytes.size()));

    return size;
}

void loader_pe::import_table(uc_engine* uc, const uint64_t image_base, const IMAGE_IMPORT_DESCRIPTOR import_descriptor, const std::string dll_name, const uint64_t dll_image_base, const uint64_t dll_exports_address)
{
    for (auto j = 0;; ++j)
    {
        DWORD dll_import_proc_name_address;
        E_FAT(uc_ext_mem_read(uc, image_base + import_descriptor.FirstThunk, dll_import_proc_name_address, j));

        if (dll_import_proc_name_address == 0x0)
            break; // END

        std::string dll_import_proc_name;
        E_FAT(uc_ext_mem_read_string(uc, image_base + dll_import_proc_name_address + sizeof(WORD), dll_import_proc_name));

        // --> Find DLL export function and replace
        IMAGE_EXPORT_DIRECTORY dll_export_directory;
        E_FAT(uc_ext_mem_read(uc, dll_image_base + dll_exports_address, dll_export_directory));

        DWORD dll_export_proc_address = 0x0;

        const std::function<std::string(int)> f = [uc, dll_image_base, dll_export_directory](int k)
        {
            DWORD dll_export_proc_name_address;
            E_FAT(uc_ext_mem_read(uc, dll_image_base + dll_export_directory.AddressOfNames, dll_export_proc_name_address, k));
                
            std::string dll_export_proc_name;
            E_FAT(uc_ext_mem_read_string(uc, dll_image_base + dll_export_proc_name_address, dll_export_proc_name));

            return dll_export_proc_name;
        };

        const auto dll_export_proc_index = binary_search(f, dll_import_proc_name, 0, dll_export_directory.NumberOfNames - 1); // TODO: Use hint.

        E_FAT(dll_export_proc_index < 0);

        E_FAT(uc_ext_mem_read<DWORD>(uc, dll_image_base + dll_export_directory.AddressOfFunctions, dll_export_proc_address, dll_export_proc_index));

        if (dll_export_proc_address == 0x0)
            continue; // Export not found
            
        E_FAT(uc_ext_mem_write(uc, image_base + import_descriptor.FirstThunk, static_cast<DWORD>(dll_image_base) + dll_export_proc_address, j));

        libs_.emplace(dll_image_base + dll_export_proc_address, std::make_tuple(dll_name, dll_import_proc_name));
        // <--
    }
}
uint64_t loader_pe::init_imports(uc_engine* uc, const header_pe header, uint64_t dll_image_base)
{
    // --> Locate import table
    const auto imports_address = header.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (imports_address == 0x0)
        return dll_image_base; // NO IMPORTS
    // <--
    
    // --> Inspect import table
    for (auto i = 0;; ++i)
    {
        // --> Inspect descriptor
        IMAGE_IMPORT_DESCRIPTOR import_descriptor;
        E_FAT(uc_ext_mem_read(uc, header.image_base + imports_address, import_descriptor, i));

        if (import_descriptor.Name == 0x0 || import_descriptor.Characteristics == 0x0) // TODO: Characteristics ?
            break; // END

        std::string dll_name;
        E_FAT(uc_ext_mem_read_string(uc, header.image_base + import_descriptor.Name, dll_name));
        // <--
        
        if (imports.find(dll_name) != imports.end())
        {
            // DLL is already load:
            // - Skip "Load DLL", "DLL relocation"
            // - Table update with this address
            // - Continue without base increase
            
            auto info = imports[dll_name];
            import_table(uc, header.image_base, import_descriptor, dll_name, std::get<0>(info), std::get<1>(info));
            continue;
        }
        
        // --> Load DLL
        std::vector<char> dll_bytes;
        if (dump_dll(dll_name, header.machine, dll_bytes))
            continue; // DLL not found
        
        auto dll_header = header_pe();
        E_FAT(dll_header.inspect(dll_bytes));

        const auto old_dll_image_base = dll_header.image_base;
        dll_header.image_base = dll_image_base;
        
        uint64_t dll_end = 0;
        for (auto h_sec : dll_header.section_headers)
        {
            dll_end = dll_image_base + h_sec.VirtualAddress;

            const auto begin = dll_bytes.begin() + h_sec.PointerToRawData;
            dll_end += init_section(uc, std::vector<char>(begin, begin + h_sec.SizeOfRawData), dll_end);
        }
        // <--

        // --> DLL relocation
        const auto dll_reloc = dll_header.data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

        auto offset = 0;
        while (true)
        {
            IMAGE_BASE_RELOCATION reloc;
            E_FAT(uc_ext_mem_read(uc, dll_image_base + dll_reloc + offset, reloc));

            if (reloc.VirtualAddress == 0x0)
                break; // END

            const int count = (reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (auto j = 0; j < count; ++j)
            {
                WORD w;
                E_FAT(uc_ext_mem_read(uc, dll_image_base + dll_reloc + offset + sizeof(IMAGE_BASE_RELOCATION), w, j));

                const auto type = (w & 0xf000) >> 12;
                w &= 0xfff;

                if (type == IMAGE_REL_BASED_HIGHLOW)
                {
                    const auto address = dll_image_base + reloc.VirtualAddress + w;
                    const auto delta = dll_image_base - old_dll_image_base;

                    DWORD value;
                    E_FAT(uc_ext_mem_read(uc, address, value));

                    E_FAT(uc_ext_mem_write(uc, address, value + delta));
                }
            }

            offset += reloc.SizeOfBlock;
        }
        // <--

        // --> Import table update
        const auto dll_exports_address = dll_header.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        import_table(uc, header.image_base, import_descriptor, dll_name, dll_image_base, dll_exports_address);
        // <--

        // Mark DLL as load
        imports.emplace(dll_name, std::make_tuple(dll_image_base, dll_exports_address));

        // Increase base for next DLL
        dll_image_base = init_imports(uc, dll_header, dll_end);
    }
    // <--

    return dll_image_base;
}

int loader_pe::load(const std::vector<char> bytes, csh& cs, uc_engine*& uc)
{
    header_pe header;
    E_ERR(header.inspect(bytes));

    machine_ = header.machine;

    switch (header.machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        cs_open(CS_ARCH_X86, CS_MODE_32, &cs);
        uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
        break;
#ifdef _WIN64
    case IMAGE_FILE_MACHINE_AMD64:
        cs_open(CS_ARCH_X86, CS_MODE_64, &cs);
        uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
        break;
#endif
    default:
        return R_FAILURE;
    }

    secs_ = std::map<uint64_t, std::string>();

    for (auto h_sec : header.section_headers)
    {
        const auto begin = bytes.begin() + h_sec.PointerToRawData;
        init_section(uc, std::vector<char>(begin, begin + h_sec.SizeOfRawData), header.image_base + h_sec.VirtualAddress);
        secs_.emplace(header.image_base + h_sec.VirtualAddress, std::string(reinterpret_cast<char*>(h_sec.Name)));
    }

    imports = std::map<std::string, std::tuple<uint64_t, uint64_t>>();
    libs_ = std::map<uint64_t, std::tuple<std::string, std::string>>();

    init_imports(uc, header, 0x70000000);

    const uint64_t stack_ptr = 0xffffffff;
    const auto instr_ptr = header.image_base + header.entry_point;

    init_section(uc, std::vector<char>(header.stack_commit), stack_ptr - header.stack_commit + 1);

    auto r = regs();
    E_FAT(uc_reg_write(uc, r[4], &stack_ptr));
    E_FAT(uc_reg_write(uc, r[5], &stack_ptr));
    E_FAT(uc_reg_write(uc, r[8], &instr_ptr));

    return R_SUCCESS;
}

uint64_t loader_pe::scale() const
{
    switch (machine_)
    {
    case IMAGE_FILE_MACHINE_I386:
        return 0xffffffff;
#ifdef _WIN64
    case IMAGE_FILE_MACHINE_AMD64:
        return 0xffffffffffffffff;
#endif
    default:
        THROW_E;
    }
}

std::vector<int> loader_pe::regs() const
{
    switch (machine_)
    {
    case IMAGE_FILE_MACHINE_I386:
        return
        {
            X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_EDX,
            X86_REG_ESP, X86_REG_EBP,
            X86_REG_ESI, X86_REG_EDI,
            X86_REG_EIP
        };
#ifdef _WIN64
    case IMAGE_FILE_MACHINE_AMD64:
        return
        {
            X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX,
            X86_REG_RSP, X86_REG_RBP,
            X86_REG_RSI, X86_REG_RDI,
            X86_REG_RIP
        };
#endif
    default:
        THROW_E;
    }
}
int loader_pe::ip_index() const
{
    switch (machine_)
    {
    case IMAGE_FILE_MACHINE_I386:
        return 8;
#ifdef _WIN64
    case IMAGE_FILE_MACHINE_AMD64:
        return 8;
#endif
    default:
        THROW_E;
    }
}

std::map<uint64_t, std::string> loader_pe::secs() const
{
    return secs_;
}
std::map<uint64_t, std::tuple<std::string, std::string>> loader_pe::libs() const
{
    return libs_;
}
