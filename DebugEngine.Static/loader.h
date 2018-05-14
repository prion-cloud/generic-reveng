#pragma once

#include "emulator.h"

// Initializer for machine code emulation
class loader
{
public:

    virtual ~loader() = default;

    virtual emulator* get_emulator() const = 0;

    virtual std::map<uint64_t, std::string> get_labels() const = 0;

    // Initializes a new emulator according to a set of machine code.
    virtual uint16_t load(std::vector<uint8_t> code) = 0;

    // Provides certanity that a specified address contains mapped memory.
    // Returns 'true' if previously unmapped memory is now mapped, otherwise 'false'.
    virtual bool ensure_availablility(uint64_t address) = 0;
};

// Initializer for machine code emulation of PE binaries
class loader_pe : public loader
{
    // Important properties of a PE file header
    struct header_pe
    {
        WORD machine;

        ULONGLONG image_base;
        ULONGLONG stack_commit;

        DWORD entry_point;

        IMAGE_DATA_DIRECTORY import_directory;

        std::vector<IMAGE_SECTION_HEADER> section_headers;

        header_pe();

        // Inspects a range of bytes for a valid PE header and initializes all fields if successful.
        explicit header_pe(std::vector<uint8_t> buffer);
    };

    bool defer_;

    emulator* emulator_ { };

    header_pe header_ { };

    std::map<std::string, header_pe> imported_dlls_ { };
    std::map<uint64_t, std::string> deferred_dlls_ { };

    std::map<uint64_t, std::string> labels_ { };

    std::map<uint64_t, std::map<std::string, IMAGE_IMPORT_DESCRIPTOR>> import_descriptors_ { };

    void import_single_dll(uint64_t base, std::string dll_name, bool sub);
    void import_all_dlls(header_pe header, bool sub);

public:

    loader_pe();

    emulator* get_emulator() const override;

    std::map<uint64_t, std::string> get_labels() const override;

    uint16_t load(std::vector<uint8_t> code) override;

    bool ensure_availablility(uint64_t address) override;
};
