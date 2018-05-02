#include "stdafx.h"

#include "loader.h"

int header_pe::retrieve(const uint8_t* buffer)
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

void loader_pe::import_dlls(const header_pe header, const bool sub)
{
    // Locate import table
    const auto imports_address = header.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (imports_address == 0x0)
        return; // No imports
    
    // Inspect import table entries
    for (auto i = 0;; ++i)
    {
        // Retrieve import descriptor
        const auto import_descriptor = emulator_->mem_read<IMAGE_IMPORT_DESCRIPTOR>(header.image_base + imports_address, i);

        if (import_descriptor.Characteristics == 0x0 || import_descriptor.Name == 0x0)
            break; // No more entries

        // DLL: Get name
        auto dll_name = emulator_->mem_read_string(header.image_base + import_descriptor.Name);
        
        // DLL: Get handle
        const auto dll_handle = sub // TODO: Validate necessity
            ? GetModuleHandleA(dll_name.c_str())
            : LoadLibraryA(dll_name.c_str());
        E_FAT(dll_handle == nullptr);
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

            // DLL: Initialize header section in UC
            emulator_->mem_map(dll_address, dll_header_buffer, dll_header_size);

            // DLL: Create header from bytes
            auto dll_header = header_pe();
            E_FAT(dll_header.retrieve(dll_header_buffer));

            free(dll_header_buffer);

            // DLL Assert: Equal base addresses
            E_FAT(dll_address != dll_header.image_base);

            // DLL: Use header to write remaining sections to UC
            for (auto dll_sec : dll_header.section_headers)
            {
                const auto dll_sec_address = dll_address + dll_sec.VirtualAddress;
                const auto dll_sec_handle = reinterpret_cast<HMODULE>(dll_sec_address);
                const auto dll_sec_size = dll_sec.SizeOfRawData;

                const auto dll_sec_buffer = static_cast<char*>(malloc(dll_sec_size));
                ReadProcessMemory(GetCurrentProcess(), dll_sec_handle, dll_sec_buffer, dll_sec_size, nullptr);

                emulator_->mem_map(dll_sec_address, dll_sec_buffer, dll_sec_size);

                free(dll_sec_buffer);
            }

            // DLL: Mark as imported
            imported_dlls_.emplace(dll_name, dll_header);

            // Recurse to get sub DLLs
            import_dlls(dll_header, true);
        }

        // Inspect import descriptor procs
        for (auto j = 0;; ++j)
        {
            const auto import_proc_name_address = emulator_->mem_read<DWORD>(header.image_base + import_descriptor.OriginalFirstThunk, j);

            if (import_proc_name_address == 0x0)
                break; // No more procs

            std::string import_proc_name;
            try // TODO: What is this error ?
            {
                import_proc_name = emulator_->mem_read_string(header.image_base + import_proc_name_address + sizeof(WORD));
            }
            catch (std::runtime_error)
            {
                continue;
            }

            const auto dll_export_proc_address = reinterpret_cast<DWORD>(GetProcAddress(dll_handle, import_proc_name.c_str()));

            // Update address (only for imports of the executable itself, no indirect DLL imports)
            if (!sub)
                emulator_->mem_write(header.image_base + import_descriptor.FirstThunk, dll_export_proc_address, j);

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
    emulator_ = emulator;
    
    // Reset data structures
    imported_dlls_ = std::map<std::string, header_pe>();
    deferred_dlls_ = std::map<uint64_t, std::string*>();
    labels_ = std::map<uint64_t, std::string>();

    // Bytes contain a valid PE header?
    E_ERR(header_.retrieve(&bytes[0]));

    // Mem: All defined sections
    emulator_->mem_map(header_.image_base, &bytes[0], PAGE_SIZE);
    for (auto sec : header_.section_headers)
        emulator_->mem_map(header_.image_base + sec.VirtualAddress, &bytes[0] + sec.PointerToRawData, sec.SizeOfRawData);

    // DLL: All defined imports (start recursion)
    import_dlls(header_, false);

    // Mem: Stack
    const uint64_t stack_pointer = 0xffffffff;
    const auto stack_size = header_.stack_commit;
    emulator_->mem_map(stack_pointer - stack_size + 1, nullptr, stack_size);

    // Reg: Initialize
    emulator_->init_regs(stack_pointer, header_.image_base + header_.entry_point);

    return R_SUCCESS;
}

std::map<uint64_t, std::string> loader_pe::labels() const
{
    return labels_;
}

void loader_pe::check_import(const uint64_t address)
{
    if (deferred_dlls_.find(address) == deferred_dlls_.end())
        return;

    const auto dll_name_ptr = deferred_dlls_.at(address);
    const auto dll_name = *dll_name_ptr;

    E_FAT(dll_name == STR_UNKNOWN);
    
    // import_dll(header_, dll_name, false); TODO

    *dll_name_ptr = STR_UNKNOWN; // TODO: dll_name = ?
}
