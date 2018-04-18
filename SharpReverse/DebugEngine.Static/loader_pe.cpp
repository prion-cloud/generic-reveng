#include "stdafx.h"
#include "macro.h"

#include "loader.h"

#define PAGE_SIZE 0x1000

#define SEC_DESC_PE_HEADER "(PE header)"
#define SEC_DESC_STACK "(Stack)"

#define SEC_OWNER_SELF "(Self)"

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

size_t calc_virt_size(const size_t raw_size)
{
    auto virt_size = PAGE_SIZE * (raw_size / PAGE_SIZE);
    if (raw_size % PAGE_SIZE > 0)
        virt_size += PAGE_SIZE;

    return virt_size;
}

void loader_pe::init_section(uc_engine* uc, std::string owner, std::string desc, const uint64_t address, const size_t size)
{
    E_FAT(size == 0);
    E_FAT(uc_mem_map(uc, address, calc_virt_size(size), UC_PROT_ALL));

    secs_.emplace(address, std::make_pair(owner, desc));
}
void loader_pe::init_section(uc_engine* uc, const std::string owner, const std::string desc, const uint64_t address, const void* buffer, const size_t size)
{
    init_section(uc, owner, desc, address, size);

    E_FAT(uc_mem_write(uc, address, buffer, size));
}

void loader_pe::import_descriptor_update(uc_engine* uc, const uint64_t image_base, const IMAGE_IMPORT_DESCRIPTOR import_descriptor, const std::string dll_name, const uint64_t dll_image_base, const uint64_t dll_exports_address)
{
    // Inspect import descriptor procs
    for (auto j = 0;; ++j)
    {
        DWORD dll_import_proc_name_address;
        E_FAT(uc_ext_mem_read(uc, image_base + import_descriptor.FirstThunk, dll_import_proc_name_address, j));

        if (dll_import_proc_name_address == 0x0)
            break; // No more procs

        std::string dll_import_proc_name;
        E_FAT(uc_ext_mem_read_string(uc, image_base + dll_import_proc_name_address + sizeof(WORD), dll_import_proc_name));

        // Retrieve export directory
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

        dll_procs_.emplace(dll_image_base + dll_export_proc_address, std::make_pair(dll_name, dll_import_proc_name));
    }
}
void loader_pe::import_dlls(uc_engine* uc, const header_pe header, const bool sub)
{
    // Locate import table
    const auto imports_address = header.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (imports_address == 0x0)
        return; // No imports
    
    // Inspect import table entries
    for (auto i = 0;; ++i)
    {
        // Retrieve import descriptor
        IMAGE_IMPORT_DESCRIPTOR import_descriptor;
        E_FAT(uc_ext_mem_read(uc, header.image_base + imports_address, import_descriptor, i));

        if (import_descriptor.Characteristics == 0x0 || import_descriptor.Name == 0x0)
            break; // No more entries

        // DLL: Get name
        std::string dll_name;
        E_FAT(uc_ext_mem_read_string(uc, header.image_base + import_descriptor.Name, dll_name));
        
        // DLL: Get handle
        const auto dll_handle = sub
            ? GetModuleHandleA(dll_name.c_str()) // TODO: Kernel32 apis may refer to itself!
            : LoadLibraryA(dll_name.c_str());
        const auto dll_address = reinterpret_cast<uint64_t>(dll_handle);

        // DLL: Update name
        char dll_path[MAX_PATH];
        GetModuleFileNameA(dll_handle, dll_path, MAX_PATH);
        char dll_name_c[MAX_PATH];
        _splitpath(dll_path, nullptr, nullptr, dll_name_c, nullptr);
        dll_name = std::string(dll_name_c, strlen(dll_name_c));

        uint64_t dll_exports_address;

        // DLL: Not yet imported?
        if (dll_export_addresses_.find(dll_address) == dll_export_addresses_.end())
        {
            const auto dll_header_size = PAGE_SIZE;

            // DLL: Read bytes of header section
            const auto dll_header_buffer = static_cast<char*>(malloc(dll_header_size));
            ReadProcessMemory(GetCurrentProcess(), dll_handle, dll_header_buffer, dll_header_size, nullptr);

            // DLL: Initialize header section in UC (optional)
            init_section(uc, dll_name, SEC_DESC_PE_HEADER, dll_address, dll_header_buffer, dll_header_size);

            // DLL: Create header from bytes
            auto dll_header = header_pe();
            E_FAT(dll_header.inspect(dll_header_buffer));

            free(dll_header_buffer);

            // DLL Assert: Equal base addresses (optional)
            E_FAT(dll_address != dll_header.image_base);

            // DLL: Retrieve export table address and mark as imported
            dll_exports_address = dll_header.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            dll_export_addresses_.emplace(dll_address, dll_exports_address);

            // DLL: Use header to write remaining sections to UC
            for (auto dll_sec_header : dll_header.section_headers)
            {
                const auto dll_sec_address = dll_address + dll_sec_header.VirtualAddress;
                const auto dll_sec_handle = reinterpret_cast<HMODULE>(dll_sec_address);
                const auto dll_sec_size = dll_sec_header.SizeOfRawData;

                const auto dll_sec_buffer = static_cast<char*>(malloc(dll_sec_size));
                ReadProcessMemory(GetCurrentProcess(), dll_sec_handle, dll_sec_buffer, dll_sec_size, nullptr);

                init_section(uc, dll_name, std::string(reinterpret_cast<char*>(dll_sec_header.Name), IMAGE_SIZEOF_SHORT_NAME),
                    dll_sec_address, dll_sec_buffer, dll_sec_size);

                free(dll_sec_buffer);
            }

            // Recurse to get sub DLLs
            import_dlls(uc, dll_header, true);
        }
        else
        {
            // Assert: Section exists
            E_FAT(secs_.find(dll_address) == secs_.end());

            const auto sec = secs_[dll_address];

            // Assert: Section owner is DLL
            E_FAT(std::get<0>(sec) != dll_name);

            // Assert: Section description is DLL header
            E_FAT(std::get<1>(sec) != SEC_DESC_PE_HEADER);

            dll_exports_address = dll_export_addresses_[dll_address];
        }

        // Update all proc references of import descriptor
        if (!sub)
        {
            import_descriptor_update(uc, header.image_base, import_descriptor, dll_name, dll_address, dll_exports_address);

            // TODO: FreeLibrary ?
        }
    }
}

int header_pe::inspect(const char* buffer)
{
    size_t cursor = 0;

    const auto h_dos = *reinterpret_cast<const IMAGE_DOS_HEADER*>(&buffer[cursor]);
    E_ERR(h_dos.e_magic != 0x5A4D);

    const auto pe_sig = *reinterpret_cast<const DWORD*>(&buffer[cursor += h_dos.e_lfanew]);
    E_ERR(pe_sig != 0x4550);

    const auto h_fil = *reinterpret_cast<const IMAGE_FILE_HEADER*>(&buffer[cursor += sizeof(DWORD)]);
    cursor += sizeof h_fil;

    machine = h_fil.Machine;

    data_directories = std::array<IMAGE_DATA_DIRECTORY, 16>();

    switch (h_fil.SizeOfOptionalHeader)
    {
    case sizeof(IMAGE_OPTIONAL_HEADER32):
        const auto h_opt32 = *reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(&buffer[cursor]);

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
        const auto h_opt64 = *reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(&buffer[cursor]);

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
        section_headers.push_back(*reinterpret_cast<const IMAGE_SECTION_HEADER*>(&buffer[cursor + i * sizeof(IMAGE_SECTION_HEADER)]));

    return R_SUCCESS;
}

int loader_pe::load(const std::vector<char> bytes, csh& cs, uc_engine*& uc)
{
    header_pe header;
    E_ERR(header.inspect(&bytes[0]));

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
    
    // -->
    // Essential map initialization

    //dll_export_addresses_ = std::map<uint64_t, uint64_t>();
    
    secs_ = std::map<uint64_t, std::pair<std::string, std::string>>();
    dll_procs_ = std::map<uint64_t, std::pair<std::string, std::string>>();

    // <--

    // TODO: Init header section

    for (auto h_sec : header.section_headers)
    {
        init_section(uc, SEC_OWNER_SELF, std::string(reinterpret_cast<char*>(h_sec.Name), IMAGE_SIZEOF_SHORT_NAME),
            header.image_base + h_sec.VirtualAddress, &bytes[0] + h_sec.PointerToRawData, h_sec.SizeOfRawData);
    }

    import_dlls(uc, header, false);

    const uint64_t stack_pointer = 0xffffffff;
    const auto stack_size = header.stack_commit;

    init_section(uc, SEC_OWNER_SELF, SEC_DESC_STACK, stack_pointer - stack_size + 1, stack_size);

    auto r = regs();
    E_FAT(uc_reg_write(uc, r[4], &stack_pointer));
    E_FAT(uc_reg_write(uc, r[5], &stack_pointer));
    
    const auto instruction_pointer = header.image_base + header.entry_point;

    E_FAT(uc_reg_write(uc, r[8], &instruction_pointer));

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

std::map<uint64_t, std::pair<std::string, std::string>> loader_pe::secs() const
{
    return secs_;
}
std::map<uint64_t, std::pair<std::string, std::string>> loader_pe::dll_procs() const
{
    return dll_procs_;
}
