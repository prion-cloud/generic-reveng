#include "stdafx.h"

#include "../Bin-Capstone/capstone.h"

#include "instruction.h"
#include "serialization.h"

static size_t get_size(std::ifstream& stream)
{
    const auto pos = stream.tellg();

    stream.seekg(0, std::ios::end);
    const size_t size = stream.tellg();

    stream.seekg(pos, std::ios::beg);

    return size;
}

static std::vector<x86_instruction>* disassemble_all(const uint64_t address, const std::vector<uint8_t>* bytes)
{
    std::cout << "Disassembling...";

    csh handle;
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn* cs_instructions;
    const auto count = cs_disasm(handle, &bytes->at(0), bytes->size(), address, 0, &cs_instructions);

    cs_close(&handle);

    std::cout << "Converting...";

    auto disassembly = new std::vector<x86_instruction>;
    for (auto i = 0; i < 0; ++i)
    {
        const auto cs_ins = cs_instructions[i];

        x86_instruction ins;

        ins.id = static_cast<x86_insn>(cs_ins.id);
        ins.address = cs_ins.address;
        ins.bytes = std::vector<uint8_t>(cs_ins.bytes, cs_ins.bytes + cs_ins.size);
        ins.representation = std::string(cs_ins.mnemonic) + " " + std::string(cs_ins.op_str);

        if (cs_ins.detail == nullptr)
            continue;

        const auto cs_ins_detail = cs_ins.detail->x86;

        for (auto j = 0; j < cs_ins_detail.op_count; ++j)
        {
            const auto cs_op = cs_ins_detail.operands[j];

            x86_operator op;

            op.type = cs_op.type;
            op.value = cs_op.imm;

            ins.operators.push_back(op);
        }

        disassembly->push_back(ins);
    }

    cs_free(cs_instructions, count);

    std::cout << "Finished" << std::endl;

    return disassembly;
}

static std::map<uint64_t, size_t> find_sequences(std::vector<x86_instruction>* disassembly, const int min, const unsigned find, const std::set<unsigned> add)
{
    std::map<uint64_t, size_t> sequences;

    for (auto i = 0; i < disassembly->size(); ++i)
    {
        const auto ins = disassembly->at(i);

        if (ins.id != find)
            continue;

        auto j = 0;

        do
        {
            ++i;
            ++j;

            if (i >= disassembly->size())
                break;
        }
        while (disassembly->at(i).id == find || add.find(disassembly->at(i).id) != add.end());

        if (j >= min)
        {
            std::cout << "  " << std::hex << std::showbase << ins.address << " (" << j << ")" << std::endl;
            sequences.emplace(ins.address, j);
        }
    }

    return sequences;
}

static void save_disassembly(const std::string file_name, const std::vector<x86_instruction>* disassembly)
{
    std::cout << "Saving...";

    std::ofstream file_stream(file_name, std::ios::binary);

    file_stream <<= static_cast<uint64_t>(disassembly->size());

    for (const auto ins : *disassembly)
        file_stream <<= ins;

    std::cout << "Finished" << std::endl;
}
static std::vector<x86_instruction>* load_disassembly(const std::string file_name)
{
    std::ifstream file_stream(file_name, std::ios::binary);

    uint64_t size = 0;
    file_stream >>= size;

    auto disassembly = new std::vector<x86_instruction>;
    for (auto i = 0; i < size; ++i)
    {
        x86_instruction ins;
        file_stream >>= ins;
        disassembly->push_back(ins);
    }

    return disassembly;
}

static std::vector<uint8_t>* load_bytes(const std::string file_name)
{
    std::ifstream file_stream(file_name, std::ios::binary);

    if (!file_stream.is_open())
        return nullptr;

    auto bytes = new std::vector<uint8_t>(get_size(file_stream));
    file_stream.read(reinterpret_cast<char*>(&bytes->at(0)), bytes->size());

    return bytes;
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

    const auto bytes = load_bytes(file_name);

    if (bytes == nullptr)
    {
        std::cerr << "Could not open file." << std::endl;
        return -1;
    }

    std::cout << "Size: " << bytes->size() << " bytes" << std::endl;

    // -----

    const uint64_t addr1 = 0x1000;
    const uint64_t addr2 = 0x989000;

    //std::vector<uint8_t> text;
    //text.insert(text.end(), b_text1.begin(), b_text1.end());
    //text.insert(text.end(), b_text2.begin(), b_text2.end());

    const auto b_text1 = new std::vector<uint8_t>(bytes->begin() + addr1, bytes->begin() + 0x4b5a00);

    const auto ins1 = disassemble_all(addr1, b_text1);

    delete b_text1;
    delete bytes;

    save_disassembly("ins1.dis", ins1);

    delete ins1;

    //const auto b_text2 = new std::vector<uint8_t>(bytes.begin() + addr2, bytes.begin() + 0xe66000);
    //const auto ins2 = disassemble_all(addr2, b_text2);
    //delete b_text2;
    //save_disassembly("ins2.dis", ins2);
    //delete ins2;

    //const auto seq = find_sequences(ins2, 10, X86_INS_POP, { X86_INS_PUSHFQ, X86_INS_MOVUPD, X86_INS_LEA });

    std::cout << "Complete" << std::endl;

    //FATAL_IF(ins1 != load);

    // -----

    std::cin.get();
    return 0;
}
