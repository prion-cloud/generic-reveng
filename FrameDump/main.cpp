#include "stdafx.h"

#include "../Bin-Capstone/capstone.h"

#include "disassembly.h"
#include "serialization.h"

#define FILE_1 "text1.dis"
#define FILE_2 "text2.dis"

static void process(const std::vector<uint8_t> bytes, const uint64_t base_address, const size_t length, const std::string out_file_name)
{
    const auto start = bytes.begin() + base_address;
    const std::vector<uint8_t> section(start, start + length);

    disassembly_x86::create_complete(base_address, section).save(out_file_name);
}

int main(const int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Invalid number of arguments." << std::endl;
        return -1;
    }

    const std::string file_name(argv[1]);

    std::cout << "File: \"" << file_name << "\"" << std::endl;
    
    std::ifstream file_stream(file_name, std::ios::binary);

    if (!file_stream.is_open())
    {
        std::cerr << "Could not open file." << std::endl;
        return -1;
    }

    std::vector<uint8_t> bytes(get_size(file_stream));
    file_stream.read(reinterpret_cast<char*>(&bytes.at(0)), bytes.size());

    std::cout << "Size: " << bytes.size() << " bytes" << std::endl;

    // -----

    process(bytes, 0x1000, 0x4b4a00, FILE_1);
    process(bytes, 0x989000, 0x4dd000, FILE_2);

    std::cout << "Complete" << std::endl;

    // -----

    std::cin.get();
    return 0;
}
