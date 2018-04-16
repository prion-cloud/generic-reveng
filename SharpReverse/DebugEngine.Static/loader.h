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
    virtual int load(std::vector<char> bytes, csh& cs, uc_engine*& uc) = 0;

    virtual uint64_t scale() const = 0;

    virtual std::vector<int> regs() const = 0;
    virtual int ip_index() const = 0;

    virtual std::map<uint64_t, std::string> secs() const = 0;
    virtual std::map<uint64_t, std::tuple<std::string, std::string>> libs() const = 0;
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
    WORD machine_ { };

    std::map<uint64_t, std::string> secs_ { };
    std::map<uint64_t, std::tuple<std::string, std::string>> libs_;

    void import_table(uc_engine* uc, uint64_t image_base, IMAGE_IMPORT_DESCRIPTOR import_descriptor, std::string dll_name, uint64_t dll_image_base, uint64_t dll_exports_address);
    uint64_t init_imports(uc_engine* uc, header_pe header, uint64_t dll_image_base);

public:

    int load(std::vector<char> bytes, csh& cs, uc_engine*& uc) override;

    uint64_t scale() const override;

    std::vector<int> regs() const override;
    int ip_index() const override;

    std::map<uint64_t, std::string> secs() const override;
    std::map<uint64_t, std::tuple<std::string, std::string>> libs() const override;
};