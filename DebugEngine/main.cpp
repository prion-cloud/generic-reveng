#include "stdafx.h"

#include <conio.h>
#include <iomanip>
#include <iostream>

#include "../DebugEngine.Static/debugger.h"

#define ARG_SUCCESS 0
#define ARG_FAILURE 1

#define COL_DEF FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE

#define COL_FAIL FOREGROUND_RED | FOREGROUND_INTENSITY

#define COL_CALL FOREGROUND_GREEN | FOREGROUND_BLUE
#define COL_JUMP FOREGROUND_RED | FOREGROUND_GREEN
#define COL_LABEL FOREGROUND_GREEN
#define COL_REG FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY

#define COUT_COL(color, stream) \
    { \
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); \
        std::cout stream; \
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COL_DEF); \
    }

#define FLAG_HELP "help"

#define FLAG_NO_FAT "nofat"
#define FLAG_LAZY "lazy"
#define FLAG_UGLY "ugly"

HANDLE h_console;

std::vector<debug_trace_entry> trace;

void to_upper(std::string& s)
{
    std::transform(s.begin(), s.end(), s.begin(), toupper);
}

void show_cursor(const bool visible)
{
    CONSOLE_CURSOR_INFO info;
    GetConsoleCursorInfo(h_console, &info);
    info.bVisible = visible;
    SetConsoleCursorInfo(h_console, &info);
}

void init_console()
{
    h_console = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_FONT_INFOEX cfi;
    cfi.cbSize = sizeof cfi;
    cfi.nFont = 0;
    cfi.dwFontSize.X = 0;
    cfi.dwFontSize.Y = 24;
    cfi.FontFamily = FF_DONTCARE;
    cfi.FontWeight = FW_NORMAL;
    wcscpy_s(cfi.FaceName, L"Consolas");
    SetCurrentConsoleFontEx(h_console, FALSE, &cfi);

    SetConsoleTextAttribute(h_console, COL_DEF);
}

std::vector<uint8_t> dump_file(const std::string file_name)
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

void print_help()
{
    std::ostringstream help;
    help << "This is kind of a reverse engineering tool, I guess." << std::endl << std::endl;
    std::left(help);
    help << "\t" << std::setw(20) << "--" FLAG_HELP << "Print this help." << std::endl << std::endl;
    help << "\t" << std::setw(20) << "--" FLAG_NO_FAT << "Disable fatal errors." << std::endl;
    help << "\t" << std::setw(20) << "--" FLAG_LAZY << "Do any memory allocation once it is needed." << std::endl;
    help << "\t" << std::setw(20) << "--" FLAG_UGLY << "Ignore instruction failures." << std::endl;

    std::cout << help.str();
}

void print_manual()
{
    std::ostringstream manual;
    manual << std::string(68, '=') << std::endl;
    manual << "Press...";
    std::left(manual);
    manual << " " << std::setw(10) << "SPACE" << "to debug the next instruction" << std::endl;
    manual << "\t " << std::setw(10) << "ENTER" << "to execute a command" << std::endl;
    manual << "\t " << std::setw(10) << "r" << "to display recently accessed registers (* if any)" << std::endl;
    manual << "\t " << std::setw(10) << "x" << "to quit" << std::endl;
    manual << std::string(68, '=') << std::endl;
    manual << std::endl;

    std::cout << manual.str();
}

void print_trace_entry(const debug_trace_entry trace_entry)
{
    const auto instruction = trace_entry.instruction;
    const auto label = trace_entry.label;
    const auto registers = trace_entry.registers;

    std::cout << std::hex << std::right <<
#ifdef _WIN64
        std::setw(16)
#else
        std::setw(8)
#endif
    << instruction.address;

    if (!registers.empty())
        COUT_COL(COL_REG, << "*");
    
    if (trace_entry.error != R_SUCCESS)
        COUT_COL(COL_FAIL, << "X");

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

    if (!label.empty())
    {
        std::cout << " ";
        COUT_COL(COL_LABEL, << "<" << label << ">");
    }

    std::cout << std::endl;

    if (trace_entry.error != R_SUCCESS)
        COUT_COL(COL_FAIL, << trace_entry.error_str << " <" << trace_entry.error << ">" << std::endl);
}
void print_registers(const std::map<std::string, uint64_t> registers)
{
    auto first = true;
    for (const auto reg : registers)
    {
        if (!first)
            std::cout << " ";

        auto reg_name = reg.first;
        to_upper(reg_name);

        COUT_COL(COL_REG, << reg_name << ": " << std::hex << reg.second);

        first = false;
    }

    std::cout << std::endl;
}

int process_command()
{
    const std::string line = ">> ";

    std::cout << line;

    show_cursor(true);

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

    show_cursor(false);

    std::cout << "\r" << std::string(line.size() + command.size(), ' ') << "\r";

    std::istringstream cmd_stream(command);

    std::string name;
    cmd_stream >> name;
    to_upper(name);

    std::string error;

    auto valid = true;
    
    if (name == "JUMP")
    {
        std::string address;
        cmd_stream >> address;

        char* end;
        const auto addr = strtoumax(address.c_str(), &end, 16);

        if (*end == '\0')
        {
            std::cout << "JUMP -> " << std::hex << addr << std::endl;
            // TODO
        }
        else valid = false;
    }
    else if (name == "SKIP")
    {
        std::cout << "SKIP" << std::endl;
        // TODO
    }
    else error = "Command \"" + name + "\" unknown.";

    if (!valid)
        error = "Command \"" + name + "\" has invalid operators.";

    if (!error.empty())
    {
        std::cout << error << '\r';
        return error.size();
    }

    return 0;
}

int inspect_args(std::vector<std::string> args, std::string& file_name, flag_status& flag_status)
{
    auto got_file_name = false;
    auto got_flag = false;

    for (const auto arg : args)
    {
        if (arg[0] == '-' && arg[1] == '-')
        {
            std::string flag = &arg[2];
            std::transform(flag.begin(), flag.end(), flag.begin(), tolower);

            if (flag == FLAG_HELP)
            {
                print_help();
                exit(EXIT_SUCCESS);
            }
            
            if (flag == FLAG_NO_FAT)
                flag_status.fat = false;
            else if (flag == FLAG_LAZY)
                flag_status.lazy = true;
            else if (flag == FLAG_UGLY)
                flag_status.ugly = true;
            else return ARG_FAILURE;

            std::cout << "Flag: " << flag << std::endl;
            got_flag = true;

            continue;
        }

        if (got_file_name)
            return ARG_FAILURE;

        file_name = arg;
        got_file_name = true;
    }

    if (!got_file_name)
        return ARG_FAILURE;

    if (!got_flag)
        std::cout << "No flags specified." << std::endl;

    std::cout << std::endl;

    return ARG_SUCCESS;
}

void debug(const std::string file_name)
{
    loader_pe loader;

    if (!global_flag_status.lazy)
        std::cout << "Loading... ";

    const debugger debugger(loader, dump_file(file_name));

    std::cout << "File: \"" << file_name << "\"" << std::endl << std::endl;

    debug_trace_entry current_trace_entry;

    auto regs_shown = false;

    auto erase = 0;

    for (;;)
    {
        const char c = _getch();

        if (erase > 0)
        {
            std::cout << std::string(erase, ' ') << '\r';
            erase = 0;
        }
        
        if (c == 'x')
            break;

        switch (c)
        {
        case ' ':
            current_trace_entry = debugger.step_into();
            trace.push_back(current_trace_entry);
            print_trace_entry(current_trace_entry);
            regs_shown = false;
            break;
        case '\r':
            erase = process_command();
            break;
        case 'r':
            if (regs_shown || current_trace_entry.registers.empty())
                break;
            print_registers(current_trace_entry.registers);
            regs_shown = true;
            break;
        default:;
        }
    }
}

// Entry point
int main(const int argc, char* argv[])
{
    init_console();

    show_cursor(false);
    
    std::string file_name;
    const auto res = inspect_args(std::vector<std::string>(argv + 1, argv + argc), file_name, global_flag_status);
    if (res == ARG_FAILURE)
    {
        std::cout << "Invalid arguments.";
        exit(EXIT_FAILURE);
    }

    struct stat buf;
    if (stat(file_name.c_str(), &buf))
    {
        std::cout << "Specified file does not exist.";
        exit(EXIT_FAILURE);
    }

    print_manual();

    try
    {
        debug(file_name);
    }
    catch (std::runtime_error err)
    {
        COUT_COL(COL_FAIL, << err.what());
    }
}
