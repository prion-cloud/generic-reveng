#include "stdafx.h"

#include "loader.h"

#define SEC_DESC_PE_HEADER "(PE header)"
#define SEC_DESC_STACK "(Stack)"

#define SEC_OWNER_SELF "(Self)"

int header_pe::inspect(const uint8_t* buffer)
{
    size_t cursor = 0;

    const auto h_dos = *reinterpret_cast<const IMAGE_DOS_HEADER*>(&buffer[cursor]);
    E_ERR(h_dos.e_magic != 0x5a4d);

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

void loader_pe::init_section(emulator* emulator, const std::string owner, const std::string desc, const uint64_t address, void* buffer, const size_t size)
{
    if (size == 0)
        return;

    sections_.emplace(address, std::make_pair(owner, desc));

    emulator->mem_map(address, buffer, size);
}
void loader_pe::init_imports(emulator* emulator, const header_pe header, const bool sub)
{
    // Locate import table
    const auto imports_address = header.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (imports_address == 0x0)
        return; // No imports
    
    // Inspect import table entries
    for (auto i = 0;; ++i)
    {
        // Retrieve import descriptor
        const auto import_descriptor = emulator->mem_read<IMAGE_IMPORT_DESCRIPTOR>(header.image_base + imports_address, i);

        if (import_descriptor.Characteristics == 0x0 || import_descriptor.Name == 0x0)
            break; // No more entries

        // DLL: Get name
        auto dll_name = emulator->mem_read_string(header.image_base + import_descriptor.Name);
        
        // DLL: Get handle
        const auto dll_handle = sub
            ? GetModuleHandleA(dll_name.c_str()) // TODO: Kernel32 apis may refer to themselves!
            : LoadLibraryA(dll_name.c_str());

        // Assert: Valid handle
        E_FAT(dll_handle == nullptr);

        // DLL: Resolve base address
        const auto dll_address = reinterpret_cast<uint64_t>(dll_handle);

        // DLL: Update name
        char dll_path[MAX_PATH];
        GetModuleFileNameA(dll_handle, dll_path, MAX_PATH);
        char dll_name_c[MAX_PATH];
        _splitpath_s(dll_path, nullptr, 0, nullptr, 0, dll_name_c, MAX_PATH, nullptr, 0);
        dll_name = std::string(dll_name_c, strlen(dll_name_c));

        // DLL: Not yet imported?
        if (imported_dlls_.find(dll_name) == imported_dlls_.end())
        {
            const auto dll_header_size = PAGE_SIZE;

            // DLL: Read bytes of header section
            const auto dll_header_buffer = static_cast<uint8_t*>(malloc(dll_header_size));
            ReadProcessMemory(GetCurrentProcess(), dll_handle, dll_header_buffer, dll_header_size, nullptr);

            // DLL: Initialize header section in UC (optional)
            init_section(emulator, dll_name, SEC_DESC_PE_HEADER, dll_address, dll_header_buffer, dll_header_size);

            // DLL: Create header from bytes
            auto dll_header = header_pe();
            E_FAT(dll_header.inspect(dll_header_buffer));

            free(dll_header_buffer);

            // DLL Assert: Equal base addresses (optional)
            E_FAT(dll_address != dll_header.image_base);

            // DLL: Use header to write remaining sections to UC
            for (auto dll_sec_header : dll_header.section_headers)
            {
                const auto dll_sec_address = dll_address + dll_sec_header.VirtualAddress;
                const auto dll_sec_handle = reinterpret_cast<HMODULE>(dll_sec_address);
                const auto dll_sec_size = dll_sec_header.SizeOfRawData;

                const auto dll_sec_buffer = static_cast<char*>(malloc(dll_sec_size));
                ReadProcessMemory(GetCurrentProcess(), dll_sec_handle, dll_sec_buffer, dll_sec_size, nullptr);

                init_section(emulator, dll_name, std::string(reinterpret_cast<char*>(dll_sec_header.Name), IMAGE_SIZEOF_SHORT_NAME),
                    dll_sec_address, dll_sec_buffer, dll_sec_size);

                free(dll_sec_buffer);
            }

            // DLL: Mark as imported
            imported_dlls_.insert(dll_name);

            // Recurse to get sub DLLs
            init_imports(emulator, dll_header, true);
        }
        else
        {
            // Assert: Section exists
            E_FAT(sections_.find(dll_address) == sections_.end());

            const auto sec = sections_[dll_address];

            // Assert: Section owner is DLL
            E_FAT(std::get<0>(sec) != dll_name);

            // Assert: Section description is DLL header
            E_FAT(std::get<1>(sec) != SEC_DESC_PE_HEADER);
        }

        // Inspect import descriptor procs
        for (auto j = 0;; ++j)
        {
            const auto import_proc_name_address = emulator->mem_read<DWORD>(header.image_base + import_descriptor.OriginalFirstThunk, j);

            if (import_proc_name_address == 0x0)
                break; // No more procs

            std::string import_proc_name;
            try // TODO: What exactly causes this error ?
            {
                import_proc_name = emulator->mem_read_string(header.image_base + import_proc_name_address + sizeof(WORD));
            }
            catch (std::runtime_error)
            {
                continue;
            }

            const auto dll_export_proc_address = reinterpret_cast<DWORD>(GetProcAddress(dll_handle, import_proc_name.c_str()));

            // Update address (only for imports of the executable itself, no indirect DLL imports)
            if (!sub)
                emulator->mem_write(header.image_base + import_descriptor.FirstThunk, dll_export_proc_address, j);

            auto label_stream = std::ostringstream();
            label_stream << dll_name << "." << import_proc_name;
            labels_.emplace(dll_export_proc_address, label_stream.str());
        }

        if (!sub)
            E_FAT(!FreeLibrary(dll_handle));
    }
}

int loader_pe::load(emulator* emulator, std::vector<uint8_t> bytes)
{
    // Reset data structures
    imported_dlls_ = std::set<std::string>();
    sections_ = std::map<uint64_t, std::pair<std::string, std::string>>();
    labels_ = std::map<uint64_t, std::string>();

    // Bytes contain a valid PE header?
    header_pe header;
    E_ERR(header.inspect(&bytes[0]));

    // Mem: All defined sections
    init_section(emulator, SEC_OWNER_SELF, SEC_DESC_PE_HEADER, header.image_base, &bytes[0], PAGE_SIZE);
    for (auto h_sec : header.section_headers)
    {
        init_section(emulator, SEC_OWNER_SELF, std::string(reinterpret_cast<char*>(h_sec.Name), IMAGE_SIZEOF_SHORT_NAME),
            header.image_base + h_sec.VirtualAddress, &bytes[0] + h_sec.PointerToRawData, h_sec.SizeOfRawData);
    }

    // DLL: All defined imports (start recursion)
    init_imports(emulator, header, false);

    // Mem: Stack
    const uint64_t stack_pointer = 0xffffffff;
    const auto stack_size = header.stack_commit;
    init_section(emulator, SEC_OWNER_SELF, SEC_DESC_STACK, stack_pointer - stack_size + 1, nullptr, stack_size);

    // Reg: Initialize
    emulator->init_regs(stack_pointer, header.image_base + header.entry_point);

    return R_SUCCESS;
}

std::map<uint64_t, std::pair<std::string, std::string>> loader_pe::sections() const
{
    return sections_;
}
std::map<uint64_t, std::string> loader_pe::labels() const
{
    return labels_;
}
