#pragma once

/**
 * \brief Initializer for machine code emulation
 */
class loader
{
public:

    virtual ~loader() = default;

    /**
     * \brief Initializes a disassembler and an emulator according to a set of machine code.
     */
    virtual int load(std::vector<char> bytes, csh& cs, uc_engine*& uc, uint64_t& scale, std::vector<int>& regs, int& ip_index, std::map<uint64_t, std::string>& secs) const = 0;
};

/**
 * \brief Important properties of a PE file header
 */
struct header_pe
{
    WORD machine;

    ULONGLONG image_base;
    ULONGLONG stack_commit;

    DWORD entry_point;

    std::array<IMAGE_DATA_DIRECTORY, 16> data_directories;

    std::vector<IMAGE_SECTION_HEADER> section_headers;

    /**
     * \brief Inspects a range of bytes for a valid PE header and initializes all fields if successful.
     */
    int inspect(std::vector<char> bytes);
};

/**
 * \brief Initializer for machine code emulation of PE binaries
 */
class loader_pe : public loader
{
public:

    int load(std::vector<char> bytes, csh& cs, uc_engine*& uc, uint64_t& scale, std::vector<int>& regs, int& ip_index, std::map<uint64_t, std::string>& secs) const override;
};
