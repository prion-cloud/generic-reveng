#include "stdafx.h"

#include "loader.h"

TPL T parse_to(std::vector<uint8_t>::const_iterator& iterator)
{
    const auto next = iterator + sizeof(T);
    const auto value = *reinterpret_cast<const T*>(iterator._Ptr);
    
    iterator = next;

    return value;
}

loader_pe::header_pe::header_pe() = default;
loader_pe::header_pe::header_pe(const std::vector<uint8_t> buffer)
{
    auto it = buffer.begin();

    const auto dos_header = parse_to<IMAGE_DOS_HEADER>(it);
    FATAL_IF(dos_header.e_magic != 0x5a4d);

    it = buffer.begin() + dos_header.e_lfanew;

    const auto pe_signature = parse_to<DWORD>(it);
    FATAL_IF(pe_signature != 0x4550);
    
    const auto file_header = parse_to<IMAGE_FILE_HEADER>(it);

    machine = file_header.Machine;

    switch (file_header.SizeOfOptionalHeader)
    {
    case sizeof(IMAGE_OPTIONAL_HEADER32):

        const auto optional_header32 = parse_to<IMAGE_OPTIONAL_HEADER32>(it);

        image_base = optional_header32.ImageBase;
        stack_commit = optional_header32.SizeOfStackCommit;

        entry_point = optional_header32.AddressOfEntryPoint;

        import_directory = optional_header32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        break;
    case sizeof(IMAGE_OPTIONAL_HEADER64):

        const auto optional_header64 = parse_to<IMAGE_OPTIONAL_HEADER64>(it);

        image_base = optional_header64.ImageBase;
        stack_commit = optional_header64.SizeOfStackCommit;

        entry_point = optional_header64.AddressOfEntryPoint;

        import_directory = optional_header64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        break;
    default:
        THROW;
    }

    section_headers = std::vector<IMAGE_SECTION_HEADER>();
    for (unsigned i = 0; i < file_header.NumberOfSections; ++i)
        section_headers.push_back(parse_to<IMAGE_SECTION_HEADER>(it));
}

void loader_pe::import_single_dll(const uint64_t base, std::string dll_name, const bool sub)
{
    // Get handle
    const auto dll_handle = LoadLibraryA(dll_name.c_str());
    FATAL_IF(dll_handle == nullptr);
    const auto dll_address = reinterpret_cast<uint64_t>(dll_handle);
    
    // Retrieve import descriptor
    const auto import_descriptor = import_descriptors_.at(base).at(dll_name);

    // Update name
    char dll_path[MAX_PATH];
    GetModuleFileNameA(dll_handle, dll_path, MAX_PATH);
    char dll_name_c[MAX_PATH];
    _splitpath_s(dll_path, nullptr, 0, nullptr, 0, dll_name_c, MAX_PATH, nullptr, 0);
    dll_name = std::string(dll_name_c, strlen(dll_name_c));

    // Not yet imported?
    if (imported_dlls_.find(dll_name) == imported_dlls_.end())
    {
        // Read bytes of header section
        std::vector<uint8_t> dll_header_buffer(PAGE_SIZE);
        ReadProcessMemory(GetCurrentProcess(), dll_handle, &dll_header_buffer.at(0), PAGE_SIZE, nullptr);

        // Initialize header section in UC
        emulator_->mem_map(dll_address, dll_header_buffer);

        // Create header from bytes
        auto dll_header = header_pe(dll_header_buffer);
        FATAL_IF(dll_header.image_base != dll_address);

        // Use header to write remaining sections to UC
        for (auto dll_sec : dll_header.section_headers)
        {
            const auto dll_sec_address = dll_address + dll_sec.VirtualAddress;
            const auto dll_sec_handle = reinterpret_cast<HMODULE>(dll_sec_address);
            const auto dll_sec_size = dll_sec.SizeOfRawData;

            std::vector<uint8_t> dll_sec_buffer(dll_sec_size);
            ReadProcessMemory(GetCurrentProcess(), dll_sec_handle, &dll_sec_buffer.at(0), dll_sec_size, nullptr);

            emulator_->mem_map(dll_sec_address, dll_sec_buffer);
        }

        // Mark as imported
        imported_dlls_.emplace(dll_name, dll_header);

        // "Recurse" to get sub DLLs
        import_all_dlls(dll_header, true);
    }

    // Inspect import descriptor procs
    for (auto i = 0;; ++i)
    {
        // Read name address
        const auto import_proc_name_address = emulator_->mem_read<DWORD>(base + import_descriptor.OriginalFirstThunk, i);

        // No more procs?
        if (import_proc_name_address == 0x0)
            break;

        if (!emulator_->mem_is_mapped(base + import_proc_name_address))
            continue;

        // Read name
        std::string import_proc_name;
        import_proc_name = emulator_->mem_read_string(base + import_proc_name_address + sizeof(WORD));

        // Retrieve export address
        const auto dll_export_proc_address = reinterpret_cast<DWORD>(GetProcAddress(dll_handle, import_proc_name.c_str()));

        // Update proc address (only for imports of the executable itself, no indirect DLL imports)
        if (!sub)
            emulator_->mem_write(base + import_descriptor.FirstThunk, dll_export_proc_address, i);

        // Create label
        auto label_stream = std::ostringstream();
        label_stream << dll_name << "." << import_proc_name;
        labels_.emplace(dll_export_proc_address, label_stream.str());
    }

    // Release handle
    FreeLibrary(dll_handle);
}
void loader_pe::import_all_dlls(const header_pe header, const bool sub)
{
    // Locate import table
    const auto imports_address = header.import_directory.VirtualAddress;

    // No imports?
    if (imports_address == 0x0)
        return;

    // Get ready to store import descriptors
    import_descriptors_.emplace(header.image_base, std::map<std::string, IMAGE_IMPORT_DESCRIPTOR>());

    // Inspect import table entries
    for (auto i = 0;; ++i)
    {
        // Retrieve import descriptor
        const auto import_descriptor = emulator_->mem_read<IMAGE_IMPORT_DESCRIPTOR>(header.image_base + imports_address, i);

        // No more descriptors?
        if (import_descriptor.Characteristics == 0x0 || import_descriptor.Name == 0x0)
            break;

        // Read DLL name
        auto dll_name = emulator_->mem_read_string(header.image_base + import_descriptor.Name);

        // Store import descriptor
        import_descriptors_.at(header.image_base).emplace(dll_name, import_descriptor);

        // Defer any imports now?
        if (defer_)
        {
            for (auto j = 0;; ++j)
            {
                if (emulator_->mem_read<DWORD>(header.image_base + import_descriptor.OriginalFirstThunk, j) == 0x0)
                    break;

                const auto address = static_cast<uint64_t>(emulator_->mem_read<DWORD>(header.image_base + import_descriptor.FirstThunk, j));
                deferred_dlls_.emplace(address, dll_name);
            }
        }
        else import_single_dll(header.image_base, dll_name, sub);
    }
}

loader_pe::loader_pe()
{
    defer_ = global_flag_status.lazy;
}

std::shared_ptr<emulator> loader_pe::get_emulator() const
{
    return emulator_;
}

std::string loader_pe::label_at(const uint64_t address) const
{
    if (labels_.find(address) == labels_.end())
        return { };

    return labels_.at(address);
}

uint16_t loader_pe::load(std::vector<uint8_t> code)
{
    // Reset data structures
    imported_dlls_ = std::map<std::string, header_pe>();
    deferred_dlls_ = std::map<uint64_t, std::string>();
    labels_ = std::map<uint64_t, std::string>();
    import_descriptors_ = std::map<uint64_t, std::map<std::string, IMAGE_IMPORT_DESCRIPTOR>>();

    // Do the bytes define a valid PE header?
    header_ = header_pe(code);

    // Create emulator
    emulator_ = std::make_shared<emulator>(header_.machine);

    // Map all sections
    emulator_->mem_map(header_.image_base, std::vector<uint8_t>(code.begin(), code.begin() + PAGE_SIZE));
    for (auto sec : header_.section_headers)
    {
        const auto start = code.begin() + sec.PointerToRawData;
        emulator_->mem_map(header_.image_base + sec.VirtualAddress, std::vector<uint8_t>(start, start + sec.SizeOfRawData));
    }

    // Import all DLLs (or defer them)
    import_all_dlls(header_, false);

    // Map stack
    const uint64_t stack_pointer = 0xffffffff;
    const auto stack_size = static_cast<size_t>(header_.stack_commit);
    emulator_->mem_map(stack_pointer - stack_size + 1, std::vector<uint8_t>(stack_size));

    // Retrieve and map 'Thread Information Block' (TIB) TODO: Unused
    uint64_t tib_address;
#ifdef _M_IX86
    tib_address = __readfsdword(0x18);
#elif _M_AMD64
    tib_address = __readgsqword(0x30);
#endif
    std::vector<uint8_t> tib_buffer(PAGE_SIZE);
    ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(tib_address), &tib_buffer.at(0), PAGE_SIZE, nullptr);
    emulator_->mem_map(tib_address, tib_buffer);

    // Initialize registers
    emulator_->init_regs(stack_pointer, header_.image_base + header_.entry_point);

    // Do not defer any more
    defer_ = false;

    // Return the file's machine specification
    return header_.machine;
}

bool loader_pe::ensure_availablility(const uint64_t address)
{
    if (emulator_->mem_is_mapped(address))
        return false;

    if (deferred_dlls_.find(address) != deferred_dlls_.end())
    {
        const auto dll_name = deferred_dlls_.at(address);

        FATAL_IF(dll_name == STR_UNKNOWN);
        
        import_single_dll(header_.image_base, dll_name, false);

        //dll_name_ptr = STR_UNKNOWN; // TODO: dll_name = ?

        return true;
    }

    return false;
}
