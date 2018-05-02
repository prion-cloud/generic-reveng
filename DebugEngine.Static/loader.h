#pragma once

#include "emulator.h"

// Initializer for machine code emulation
class loader
{
public:

    virtual ~loader() = default;

    // Initializes an emulator according to a set of machine code.
    virtual int load(emulator* emulator, std::vector<uint8_t> bytes) = 0;

    virtual void check_import(uint64_t address) = 0;

    virtual std::map<uint64_t, std::string> labels() const = 0;
};

// Important properties of a PE file header
struct header_pe
{
    WORD machine;

    ULONGLONG image_base;
    ULONGLONG stack_commit;

    DWORD entry_point;

    std::array<IMAGE_DATA_DIRECTORY, 16> data_directories;

    std::vector<IMAGE_SECTION_HEADER> section_headers;

    // Inspects a range of bytes for a valid PE header and initializes all fields if successful.
    int retrieve(const uint8_t* buffer);
};

// Initializer for machine code emulation of PE binaries
class loader_pe : public loader
{
    emulator* emulator_ { };

    header_pe header_ { };

    std::map<std::string, header_pe> imported_dlls_ { };
    std::map<uint64_t, std::string*> deferred_dlls_ { };

    std::map<uint64_t, std::string> labels_ { };

    std::map<std::string, IMAGE_IMPORT_DESCRIPTOR> import_descriptors_ { };

    void import_dlls(header_pe header, bool sub);
    // void import_dll(header_pe header, std::string dll_name, bool sub); TODO

public:

    int load(emulator* emulator, std::vector<uint8_t> bytes) override;

    void check_import(uint64_t address) override;

    std::map<uint64_t, std::string> labels() const override;
};
