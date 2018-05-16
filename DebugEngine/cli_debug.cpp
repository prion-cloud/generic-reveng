#include "stdafx.h"

#include "cli_debug.h"

#ifdef _WIN64
#define ADDR_SIZE 16
#else
#define ADDR_SIZE 8
#endif

static const std::string arrow = "-> ";

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

static int get_instruction_color(const int id)
{
    switch (id)
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
        return COL_JUMP;
    case X86_INS_CALL:
    case X86_INS_RET:
        return COL_CALL;
    default:
        return COL_DEF;
    }
}

static void erase(const size_t size)
{
    std::cout << '\r' << std::string(size, ' ') << '\r';
}

cli_debug::cli_debug(const HANDLE h_console, const std::string file_name)
    : h_console_(h_console)
{
    arrow_line_ = -1;

    bytes_shown_ = false;

    update_cursor(false);

    static loader_pe loader;

    if (!global_flag_status.lazy)
        std::cout << "Loading... ";

    debugger_ = std::make_unique<debugger>(loader, dump_file(file_name));

    std::cout << "File: \"" << file_name << "\"" << std::endl;

    std::cout << std::setfill('0');

    std::cout << std::endl;
    print_next_instruction();
}

void cli_debug::step_into(const bool registers)
{
    const auto cur_instruction = debugger_->next_instruction();
    const auto trace_entry = debugger_->step_into();

    bytes_shown_ = false;

    if (trace_entry.error)
        COUT_COL(COL_FAIL, << trace_entry.error_str << " <" << trace_entry.error << ">" << std::endl);

    if (registers && !trace_entry.new_registers.empty())
    {
        auto first = true;
        for (const auto reg : trace_entry.new_registers)
        {
            if (!first)
                std::cout << " ";

            auto reg_name = reg.first;
            std::transform(reg_name.begin(), reg_name.end(), reg_name.begin(), toupper);

            COUT_COL(COL_REG, << reg_name << ": " << std::hex << reg.second);

            first = false;
        }

        std::cout << std::endl;
    }

    if (cur_instruction.address + cur_instruction.bytes.size() != debugger_->next_instruction().address)
        std::cout << std::endl;

    print_next_instruction();
}

void cli_debug::process_command()
{
    const std::map<std::string, std::function<int(std::vector<std::string>)>> commands =
    {
        {
            "break",
            [this](const std::vector<std::string> ops)
            {
                // TODO
                return R_FAILURE;
            }
        },
        {
            "jump",
            [this](const std::vector<std::string> ops)
            {
                E_ERR(ops.size() != 1);

                char* end;
                const auto address = strtoull(ops.at(0).c_str(), &end, 16);
                E_ERR(*end != '\0');

                debugger_->jump_to(address); // TODO: Error!

                update_arrow();
                print_next_instruction();

                return R_SUCCESS;
            }
        },
        {
            "skip",
            [this](const std::vector<std::string> ops)
            {
                E_ERR(!ops.empty());
                
                debugger_->skip(); // TODO: Error?
                
                update_arrow();
                print_next_instruction();

                return R_SUCCESS;
            }
        }
    };

    const std::string prompt = "$ ";

    const auto line = get_cursor();
    const auto top = floor_cursor();

    std::cout << prompt;
    
    update_cursor(true);

    const char qualifier = std::cin.get();

    std::string command;
    std::string ops_string;
    if (qualifier != '\n')
    {
        std::cin >> command;
        command = qualifier + command;
        std::getline(std::cin, ops_string);
    }
    _getch();
    set_cursor(top);

    update_cursor(false);

    floor_cursor();
    reprint_instruction(get_cursor(), prompt.size() + command.size() + ops_string.size());

    set_cursor(line);

    if (command.empty())
        return;

    std::transform(command.begin(), command.end(), command.begin(), tolower);

    if (commands.find(command) == commands.end())
    {
        print_error("UKNOWN COMMAND");
        return;
    }
    
    std::stringstream ops_stream(ops_string);
    const std::vector<std::string> ops(std::istream_iterator<std::string>(ops_stream), { });

    if (commands.at(command)(ops) != R_SUCCESS)
        print_error("INVALID OPERATOR(S)");
}

void cli_debug::show_bytes()
{
    if (bytes_shown_)
        return;

    std::cout << std::string(ADDR_SIZE, ' ') << "\t(";

    auto sep = false;
    for (const auto byte : debugger_->next_instruction().bytes)
    {
        if (sep)
            std::cout << "'";
        std::cout << std::setw(2) << std::hex << +byte;
        sep = true;
    }

    std::cout << ")" << std::endl;

    bytes_shown_ = true;
}

void cli_debug::update_arrow()
{
    const auto line = get_cursor();

    if (arrow_line_ >= 0)
    {
        set_cursor(arrow_line_);
        erase(arrow.size());

        set_cursor(line);
    }

    std::cout << arrow;

    arrow_line_ = line;
}

void cli_debug::print_instruction(const instruction instruction)
{
    const auto line = get_cursor();

    const auto it1 = line_by_ins_.find(instruction.address);
    if (it1 == line_by_ins_.end())
        line_by_ins_.emplace(instruction.address, get_cursor());
    else set_cursor(it1->second);

    const auto it2 = ins_by_line_.find(line);
    if (it2 == ins_by_line_.end())
        ins_by_line_.emplace(line, instruction);
    else it2->second = instruction;

    std::cout << std::string(arrow.size(), ' ') << std::hex << std::right << std::setw(ADDR_SIZE) << instruction.address;

    if (!instruction.registers.empty())
        COUT_COL(COL_REG, << "*");

    std::cout << "\t";
    
    COUT_COL(get_instruction_color(instruction.id), << instruction.mnemonic << " " << instruction.operands);

    if (!instruction.label.empty())
    {
        std::cout << " ";
        COUT_COL(COL_LABEL, << "<" << instruction.label << ">");
    }

    std::cout << std::endl;
}
void cli_debug::print_next_instruction()
{
    update_arrow();
    print_instruction(debugger_->next_instruction());
}

void cli_debug::reprint_instruction(const int16_t line, const size_t erase_size = 0)
{
    erase(erase_size);

    const auto it = ins_by_line_.find(line);
    if (it != ins_by_line_.end())
        print_instruction(it->second);
}

void cli_debug::print_error(const std::string message)
{
    const auto line = get_cursor();
    const auto top = floor_cursor();

    COUT_COL(COL_FAIL, << message);
    _getch();
    set_cursor(top);

    floor_cursor();
    reprint_instruction(get_cursor(), message.size());

    set_cursor(line);
}

void cli_debug::update_cursor(const bool visible) const
{
    CONSOLE_CURSOR_INFO info;
    GetConsoleCursorInfo(h_console_, &info);
    info.bVisible = visible;
    SetConsoleCursorInfo(h_console_, &info);
}

int16_t cli_debug::get_cursor() const
{
    CONSOLE_SCREEN_BUFFER_INFO info { };
    GetConsoleScreenBufferInfo(h_console_, &info);
    return info.dwCursorPosition.Y;
}
void cli_debug::set_cursor(const int16_t line) const
{
    if (line < 0)
        return;

    SetConsoleCursorPosition(h_console_, { 0, line });
}

int16_t cli_debug::floor_cursor() const
{
    CONSOLE_SCREEN_BUFFER_INFO info { };
    GetConsoleScreenBufferInfo(h_console_, &info);
    set_cursor(info.srWindow.Bottom);
    return info.srWindow.Top;
}
