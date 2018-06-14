#include "stdafx.h"

#include "../Bin-Capstone/capstone.h"

#define FILE_1 "text1.dis"
#define FILE_2 "text2.dis"

struct cs_detailed
{
    cs_insn base;

    cs_x86 detail;
};

static size_t get_size(std::ifstream& stream)
{
    const auto pos = stream.tellg();

    stream.seekg(0, std::ios::end);
    const size_t size = stream.tellg();

    stream.seekg(pos, std::ios::beg);

    return size;
}

static std::vector<cs_detailed>* disassemble_all(const uint64_t address, const std::vector<uint8_t> bytes)
{
    csh handle;
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn* c_disassembly;
    const auto count = cs_disasm(handle, &bytes.at(0), bytes.size(), address, 0, &c_disassembly);

    cs_close(&handle);

    const auto disassembly = new std::vector<cs_detailed>;
    for (auto i = 0; i < count; ++i)
    {
        cs_detailed det;
        det.base = c_disassembly[i];

        if (c_disassembly[i].detail == nullptr)
            det.detail = { };
        else det.detail = c_disassembly[i].detail->x86;

        disassembly->push_back(det);
    }

    cs_free(c_disassembly, count);

    return disassembly;
}

static std::set<uint64_t> find_sequences(const std::vector<cs_detailed> disassembly, const int min, const unsigned find, const std::set<unsigned> add)
{
    std::set<uint64_t> result;

    for (auto i = 0; i < disassembly.size(); ++i)
    {
        const auto ins = disassembly.at(i).base;

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
        while (disassembly.at(i).base.id == find || add.find(disassembly.at(i).base.id) != add.end());

        if (j >= min)
        {
            std::cout << std::hex << ins.address << " (" << std::dec << j << ")" << std::endl;
            result.insert(ins.address);
        }
    }

    return result;
}

static std::map<uint64_t, std::vector<uint64_t>> find_immediates(const std::vector<cs_detailed> disassembly, const std::set<uint64_t> imm, const std::set<unsigned> consider)
{
    std::map<uint64_t, std::vector<uint64_t>> result;

    for (const auto ins : disassembly)
    {
        if (consider.find(ins.base.id) == consider.end())
            continue;

        const auto detail = ins.detail;

        for (auto i = 0; i < detail.op_count; ++i)
        {
            const auto op = detail.operands[i];

            if (op.type == X86_OP_IMM && imm.find(op.imm) != imm.end())
            {
                result[op.imm].push_back(ins.base.address);
                break;
            }
        }
    }
    
    for (const auto x : result)
    {
        std::cout << std::hex << x.first << " <- " << std::endl;
        for (const auto y : x.second)
            std::cout << std::hex << "  " << y << std::endl;
    }

    return result;
}

static void save_disassembly(const std::string file_name, const std::vector<cs_detailed> disassembly)
{
    std::ofstream(file_name, std::ios::binary).write(reinterpret_cast<const char*>(&disassembly.at(0)), disassembly.size() * sizeof(cs_detailed));
}
static std::vector<cs_detailed> load_disassembly(const std::string file_name)
{
    std::ifstream file_stream(file_name, std::ios::binary);

    const auto size = get_size(file_stream);
    const auto count = size / sizeof(cs_detailed);

    const auto c_disassembly = new cs_detailed[count];
    file_stream.read(reinterpret_cast<char*>(c_disassembly), size);

    const std::vector<cs_detailed> disassembly(c_disassembly, c_disassembly + count);

    delete[] c_disassembly;

    return disassembly;
}

/*
int main()
{
    const auto ins1 = load_disassembly(FILE_1);
    const auto ins2 = load_disassembly(FILE_2);

    const auto seqs = find_sequences(ins2, 10, X86_INS_PUSH, { X86_INS_PUSHFQ, X86_INS_MOVUPD, X86_INS_LEA });

    std::cout << "# Sequences: " << seqs.size() << std::endl;

    const auto refs1 = find_immediates(ins1, seqs, { X86_INS_JMP, X86_INS_CALL });
    const auto refs2 = find_immediates(ins2, seqs, { X86_INS_JMP, X86_INS_CALL });

    std::cout << "# Refs1: " << refs1.size() << std::endl;
    std::cout << "# Refs2: " << refs2.size() << std::endl;

    std::cin.get();
    return 0;
}
*/

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

    const std::vector<uint8_t> b_text1(bytes.begin() + addr1, bytes.begin() + addr1 + 0x4b4a00);
    const std::vector<uint8_t> b_text2(bytes.begin() + addr2, bytes.begin() + addr2 + 0x4dd000);

    const auto ins1 = disassemble_all(addr1, b_text1);
    save_disassembly(FILE_1, *ins1);
    delete ins1;

    const auto ins2 = disassemble_all(addr2, b_text2);
    save_disassembly(FILE_2, *ins2);
    delete ins2;

    std::cout << "Complete" << std::endl;

    // -----

    std::cin.get();
    return 0;
}
