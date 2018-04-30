#pragma once

#include "emulator.h"

// Initializer for machine code emulation
class loader
{
public:

    virtual ~loader() = default;

    // Initializes an emulator according to a set of machine code.
    virtual int load(emulator* emulator, std::vector<uint8_t> bytes) = 0;

    virtual std::map<uint64_t, std::pair<std::string, std::string>> sections() const = 0;
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
    int inspect(const uint8_t* buffer);
};

// Initializer for machine code emulation of PE binaries
class loader_pe : public loader
{
    std::set<std::string> imported_dlls_ { };

    std::map<uint64_t, std::pair<std::string, std::string>> sections_ { };
    std::map<uint64_t, std::string> labels_ { };

    void init_section(emulator* emulator, std::string owner, std::string desc, uint64_t address, void* buffer, size_t size);
    void init_imports(emulator* emulator, header_pe header, bool sub);

public:

    int load(emulator* emulator, std::vector<uint8_t> bytes) override;

    std::map<uint64_t, std::pair<std::string, std::string>> sections() const override;
    std::map<uint64_t, std::string> labels() const override;
};
