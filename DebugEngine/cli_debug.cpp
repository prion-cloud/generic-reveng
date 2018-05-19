#include "stdafx.h"

#include "cli_debug.h"

#include "console.h"

#ifdef _WIN64
#define ADDR_SIZE 16
#else
#define ADDR_SIZE 8
#endif

static const std::string arrow = "-> ";

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

static std::function<void(std::vector<uint8_t>)> print_bytes = [](const std::vector<uint8_t> bytes)
{
    std::cout << std::string(ADDR_SIZE, ' ') << "\t(";

    auto sep = false;
    for (const auto byte : bytes)
    {
        if (sep)
            std::cout << "'";
        std::cout << std::setw(2) << std::hex << +byte;
        sep = true;
    }

    std::cout << ")" << std::endl;
};
static std::function<void(instruction)> print_instruction = [](const instruction instruction)
{
    const auto pos = get_cursor();
    set_cursor(pos.first, pos.second + static_cast<int16_t>(arrow.size()));

    std::cout << std::hex << std::right << std::setw(ADDR_SIZE) << instruction.address;

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
};
static std::function<void(std::map<std::string, uint64_t>)> print_registers = [](const std::map<std::string, uint64_t> registers)
{
    auto first = true;
    for (const auto reg : registers)
    {
        if (!first)
            std::cout << " ";

        auto reg_name = reg.first;
        std::transform(reg_name.begin(), reg_name.end(), reg_name.begin(), toupper);

        COUT_COL(COL_REG, << reg_name << ": " << std::hex << reg.second);

        first = false;
    }

    std::cout << std::endl;
};
static std::function<void(std::pair<int, std::string>)> print_run_error = [](const std::pair<int, std::string> error)
{
    COUT_COL(COL_FAIL, << std::string(ADDR_SIZE, ' ') << '\t' << error.second << " <" << error.first << ">" << std::endl);
};

cli_debug::cli_debug(const std::shared_ptr<debugger> debugger)
    : debugger_(debugger)
{
    printer_.register_func(print_bytes);
    printer_.register_func(print_instruction);
    printer_.register_func(print_registers);
    printer_.register_func(print_run_error);
    
    arrow_line_ = -1;
    bytes_shown_ = false;

    commands_ = create_commands();

    std::cout << std::setfill('0');

    print_next_instruction();
}

void cli_debug::step_into(const bool registers)
{
    const auto cur_instruction = debugger_->next_instruction();
    const auto trace_entry = debugger_->step_into();

    bytes_shown_ = false;

    if (trace_entry.error)
        printer_.print(std::make_shared<std::pair<int, std::string>>(trace_entry.error, trace_entry.error_str));

    if (registers && !trace_entry.new_registers.empty())
        printer_.print(std::make_shared<std::map<std::string, uint64_t>>(trace_entry.new_registers));

    if (cur_instruction->address + cur_instruction->bytes.size() != debugger_->next_instruction()->address)
        printer_.print_blank();
    
    print_next_instruction();
}

void cli_debug::process_command()
{
    const auto input = printer_.bottom_in("$ ");

    if (input.empty())
        return;
    
    std::stringstream in_stream(input);
    const std::vector<std::string> split(std::istream_iterator<std::string>(in_stream), { });

    auto command = split.at(0);
    std::transform(command.begin(), command.end(), command.begin(), tolower);

    if (commands_.find(command) == commands_.end())
    {
        printer_.bottom_out("UKNOWN COMMAND");
        return;
    }

    if (commands_.at(input)(std::vector<std::string>(split.begin() + 1, split.end())) != R_SUCCESS)
        printer_.bottom_out("INVALID OPERATOR(S)");
}

void cli_debug::show_bytes()
{
    if (bytes_shown_)
        return;

    printer_.print(std::make_shared<std::vector<uint8_t>>(debugger_->next_instruction()->bytes));

    bytes_shown_ = true;
}

void cli_debug::print_next_instruction()
{
    update_arrow();
    printer_.print(debugger_->next_instruction());
}

void cli_debug::update_arrow()
{
    const auto line = get_cursor_line();

    if (arrow_line_ >= 0)
    {
        set_cursor(arrow_line_, 0);
        erase(arrow.size());

        set_cursor(line, 0);
    }

    replace(arrow);

    arrow_line_ = line;
}

std::map<std::string, std::function<int(std::vector<std::string>)>> cli_debug::create_commands()
{
    return std::map<std::string, std::function<int(std::vector<std::string>)>>
    {
        {
            "back",
            [this](const std::vector<std::string> ops)
            {
                ERROR_IF(!ops.empty());

                ERROR_IF(debugger_->step_back());

                print_next_instruction();
                return R_SUCCESS;
            }
        },
        {
            "break",
            [this](const std::vector<std::string> ops)
            {
                for (const auto op : ops)
                {
                    char* end;
                    const auto address = strtoull(op.c_str(), &end, 16);
                    ERROR_IF(*end != '\0');

                    ERROR_IF(debugger_->set_breakpoint(address));
                }

                return R_SUCCESS;
            }
        },
        {
            "jump",
            [this](const std::vector<std::string> ops)
            {
                ERROR_IF(ops.size() != 1);

                char* end;
                const auto address = strtoull(ops.at(0).c_str(), &end, 16);
                ERROR_IF(*end != '\0');

                ERROR_IF(debugger_->jump_to(address));

                print_next_instruction();
                return R_SUCCESS;
            }
        },
        {
            "skip",
            [this](const std::vector<std::string> ops)
            {
                ERROR_IF(!ops.empty());
                
                ERROR_IF(debugger_->skip());

                print_next_instruction();
                return R_SUCCESS;
            }
        }
    };
}
