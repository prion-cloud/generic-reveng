#include "stdafx.h"

#include "cli_debug.h"

static const std::string arrow = "->  ";

static std::vector<uint8_t> dump_file(const std::string file_name)
{
    FILE* file;
    fopen_s(&file, file_name.c_str(), "rb");

    fseek(file, 0, SEEK_END);
    const auto length = ftell(file);
    rewind(file);

    const auto buffer = static_cast<char*>(malloc(length));
    fread(buffer, sizeof(char), length, file);
    fclose(file);

    const auto byte_vec = std::vector<uint8_t>(buffer, buffer + length);
    free(buffer);

    return byte_vec;
}

static void cout_replace(const std::string str)
{
    std::cout << '\r' << str << '\r';
}
static void cout_erase(const size_t size)
{
    cout_replace(std::string(size, ' '));
}

static void print_instruction(const instruction instruction)
{
    std::cout << std::hex << std::right <<
#ifdef _WIN64
        std::setw(16)
#else
        std::setw(8)
#endif
    << instruction.address;

    if (!instruction.registers.empty())
        COUT_COL(COL_REG, << "*");

    std::cout << "\t";

    auto col = COL_DEF;
    switch (instruction.id)
    {
    case X86_INS_JMP:
    case X86_INS_JO:
    case X86_INS_JNO:
    case X86_INS_JS:
    case X86_INS_JNS:
    case X86_INS_JE:
    case X86_INS_JNE:
    case X86_INS_JB:
    case X86_INS_JAE:
    case X86_INS_JBE:
    case X86_INS_JA:
    case X86_INS_JL:
    case X86_INS_JGE:
    case X86_INS_JLE:
    case X86_INS_JG:
    case X86_INS_JP:
    case X86_INS_JNP:
    case X86_INS_JCXZ:
        col = COL_JUMP;
        break;
    case X86_INS_CALL:
    case X86_INS_RET:
        col = COL_CALL;
        break;
    default:;
    }

    COUT_COL(col, << instruction.mnemonic << " " << instruction.operands);

    if (!instruction.label.empty())
    {
        std::cout << " ";
        COUT_COL(COL_LABEL, << "<" << instruction.label << ">");
    }
}

cli_debug::cli_debug(const HANDLE h_console, const std::string file_name)
    : h_console_(h_console)
{
    update_cursor(false);

    static loader_pe loader;

    if (!global_flag_status.lazy)
        std::cout << "Loading... ";

    debugger_ = std::make_unique<debugger>(loader, dump_file(file_name));

    std::cout << "File: \"" << file_name << "\"" << std::endl;

    std::cout << std::endl;
    print_next_instruction();

    erase_size_ = 0;
}

void cli_debug::reset()
{
    if (erase_size_ > 0)
    {
        cout_erase(erase_size_);
        erase_size_ = 0;
    }
}

void cli_debug::step_into(const bool registers)
{
    if (endl_)
        cout_erase(arrow.size());

    const auto cur_instruction = debugger_->next_instruction();
    const auto trace_entry = debugger_->step_into();

    if (trace_entry.error)
        COUT_COL(COL_FAIL, << std::endl << trace_entry.error_str << " <" << trace_entry.error << ">");

    if (registers && !trace_entry.registers.empty())
    {
        std::cout << std::endl;

        auto first = true;
        for (const auto reg : trace_entry.registers)
        {
            if (!first)
                std::cout << " ";

            auto reg_name = reg.first;
            std::transform(reg_name.begin(), reg_name.end(), reg_name.begin(), toupper);

            COUT_COL(COL_REG, << reg_name << ": " << std::hex << reg.second);

            first = false;
        }
    }

    if (endl_)
        std::cout << std::endl;

    print_next_instruction();
}

void cli_debug::process_command()
{
    if (endl_)
    {
        cout_erase(arrow.size());
        std::cout << std::endl;
    }

    const std::string line = ">> ";

    std::cout << line;

    update_cursor(true);

    std::string command;
    for (;;)
    {
        _getch();
        const char cmd_c = _getch();

        if (cmd_c == '\r')
            break;

        std::cout << cmd_c;

        if (cmd_c == '\b')
        {
            command = command.substr(0, command.size() - 1);
            std::cout << " \b";
            continue;
        }

        command += cmd_c;
    }
    _getch();

    update_cursor(false);

    cout_erase(line.size() + command.size());

    std::istringstream cmd_stream(command);

    std::string name;
    cmd_stream >> name;
    
    std::transform(name.begin(), name.end(), name.begin(), tolower);

    std::string error;

    auto valid = true;
    
    endl_ = false;
    
    if (name == "jump")
    {
        std::string address_str;
        cmd_stream >> address_str;

        char* end;
        const auto address = strtoumax(address_str.c_str(), &end, 16);

        if (*end == '\0')
        {
            std::cout << "JUMP" << std::endl;
            debugger_->jump_to(address);
            print_next_instruction();
        }
        else valid = false;
    }
    else if (name == "skip")
    {
        std::cout << "SKIP" << std::endl;
        debugger_->skip();
        print_next_instruction();
    }
    else error = "Command \"" + name + "\" unknown.";

    if (!valid)
        error = "Command \"" + name + "\" has invalid operators.";

    if (!error.empty())
    {
        std::cout << error << '\r';
        erase_size_ = error.size();
    }
}

void cli_debug::print_next_instruction()
{
    print_instruction(debugger_->next_instruction());
    cout_replace(arrow);
    endl_ = true;
}

void cli_debug::update_cursor(const bool visible) const
{
    CONSOLE_CURSOR_INFO info;
    GetConsoleCursorInfo(h_console_, &info);
    info.bVisible = visible;
    SetConsoleCursorInfo(h_console_, &info);
}
