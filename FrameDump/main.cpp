#include "stdafx.h"

#include "../Bin-Capstone/capstone.h"

static size_t get_size(std::ifstream& stream)
{
    const auto pos = stream.tellg();

    stream.seekg(0, std::ios::end);
    const size_t size = stream.tellg();

    stream.seekg(pos, std::ios::beg);

    return size;
}

static std::vector<cs_insn>* disassemble_all(const uint64_t address, const std::vector<uint8_t> bytes)
{
    csh handle;
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn* c_disassembly;
    const auto count = cs_disasm(handle, &bytes.at(0), bytes.size(), address, 0, &c_disassembly);

    cs_close(&handle);

    const auto disassembly = new std::vector<cs_insn>(c_disassembly, c_disassembly + count);

    cs_free(c_disassembly, count);

    return disassembly;
}

static std::map<uint64_t, size_t> find_sequences(std::vector<cs_insn> disassembly, const int min, const unsigned find, const std::set<unsigned> add)
{
    std::map<uint64_t, size_t> sequences;

    for (auto i = 0; i < disassembly.size(); ++i)
    {
        const auto ins = disassembly.at(i);

        if (ins.id != find)
            continue;

        auto j = 0;

        do
        {
            ++i;
            ++j;

            if (i >= disassembly.size())
                break;
        }
        while (disassembly.at(i).id == find || add.find(disassembly.at(i).id) != add.end());

        if (j >= min)
        {
            std::cout << "  " << std::hex << std::showbase << ins.address << " (" << j << ")" << std::endl;
            sequences.emplace(ins.address, j);
        }
    }

    return sequences;
}

static void save_disassembly(const std::string file_name, const std::vector<cs_insn> disassembly)
{
    std::ofstream(file_name, std::ios::binary).write(reinterpret_cast<const char*>(&disassembly.at(0)), disassembly.size() * sizeof(cs_insn));
}
static std::vector<cs_insn> load_disassembly(const std::string file_name)
{
    std::ifstream file_stream(file_name, std::ios::binary);

    const auto size = get_size(file_stream);
    const auto count = size / sizeof(cs_insn);

    const auto c_disassembly = new cs_insn[count];
    file_stream.read(reinterpret_cast<char*>(c_disassembly), size);

    const std::vector<cs_insn> disassembly(c_disassembly, c_disassembly + count);

    delete[] c_disassembly;

    return disassembly;
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

    const uint64_t addr1 = 0x1000;
    const uint64_t addr2 = 0x989000;

    const std::vector<uint8_t> b_text1(bytes.begin() + addr1, bytes.begin() + 0x4b5a00);
    const std::vector<uint8_t> b_text2(bytes.begin() + addr2, bytes.begin() + 0xe66000);

    const auto ins1 = disassemble_all(addr1, b_text1);
    save_disassembly("ins1.dis", *ins1);
    delete ins1;

    const auto ins2 = disassemble_all(addr2, b_text2);
    save_disassembly("ins2.dis", *ins2);
    delete ins2;

    std::cout << "Complete" << std::endl;

    // -----

    std::cin.get();
    return 0;
}
