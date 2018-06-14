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
        return FOREGROUND_YELLOW;
    case X86_INS_CALL:
    case X86_INS_RET:
        return FOREGROUND_CYAN;
    default:
        return FOREGROUND_WHITE;
    }
}

static int parse_string(const std::string string, uint64_t& number, const int base)
{
    char* end;
    number = strtoull(string.c_str(), &end, base);
    return *end != '\0';
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

    std::cout << ")";
};
static std::function<void(instruction)> print_instruction = [](const instruction instruction)
{
    const auto pos = get_cursor();
    set_cursor(pos.first, pos.second + static_cast<int16_t>(arrow.size()));

    std::cout << std::uppercase << std::hex << std::right << std::setw(ADDR_SIZE) << instruction.address;

    if (!instruction.registers.empty())
        std::cout << " *";

    std::cout << "\t" << colorize(get_instruction_color(instruction.id)) << instruction.mnemonic << " " << instruction.operands;

    if (!instruction.label.empty())
        std::cout << " " << colorize(FOREGROUND_GREEN) << "<" << instruction.label << ">";

    decolorize(std::cout);
};
static std::function<void(std::pair<std::string, uint64_t>)> print_register = [](const std::pair<std::string, uint64_t> reg)
{
    std::cout << std::string(ADDR_SIZE, ' ') << '\t';

    auto reg_name = reg.first;
    std::transform(reg_name.begin(), reg_name.end(), reg_name.begin(), toupper);

    std::cout << reg_name << ": " << std::uppercase << std::hex << reg.second;
};
static std::function<void(std::pair<int, std::string>)> print_run_error = [](const std::pair<int, std::string> error)
{
    std::cout << std::string(ADDR_SIZE, ' ') << '\t' << colorize(FOREGROUND_RED | FOREGROUND_INTENSITY) << error.second << " <" << error.first << ">" << decolorize;
};

cli_debug::cli_debug(const std::shared_ptr<debugger> debugger)
    : debugger_(debugger)
{
    printer_.register_func(print_bytes);
    printer_.register_func(print_instruction);
    printer_.register_func(print_register);
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
    {
        for (const auto reg : trace_entry.new_registers)
            printer_.print(std::make_shared<std::pair<std::string, uint64_t>>(reg.first, reg.second));
    }

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

    if (commands_.at(command)(std::vector<std::string>(split.begin() + 1, split.end())) != RES_SUCCESS)
        printer_.bottom_out("COMMAND FAILED");
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
    const auto next = debugger_->next_instruction();

    if (arrow_line_ >= 0)
    {
        set_cursor(arrow_line_, 0);
        erase(arrow.size());
    }

    printer_.print(next);

    replace(arrow);

    arrow_line_ = get_cursor_line();
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
                return RES_SUCCESS;
            }
        },
        {
            "break",
            [this](const std::vector<std::string> ops)
            {
                ERROR_IF(ops.empty());

                for (const auto op : ops)
                {
                    uint64_t address;
                    ERROR_IF(parse_string(op, address, 16));
                    ERROR_IF(debugger_->set_debug_point(address, dp_break));
                }

                return RES_SUCCESS;
            }
        },
        {
            "jump",
            [this](const std::vector<std::string> ops)
            {
                ERROR_IF(ops.size() != 1);

                uint64_t address;
                ERROR_IF(parse_string(ops.at(0), address, 16));
                ERROR_IF(debugger_->jump_to(address));

                printer_.print_blank();

                print_next_instruction();
                return RES_SUCCESS;
            }
        },
        {
            "raw",
            [this](const std::vector<std::string> ops)
            {
                ERROR_IF(ops.size() > 1);

                uint64_t address;

                if (ops.size() == 0)
                    address = debugger_->next_instruction()->address;
                else ERROR_IF(parse_string(ops.at(0), address, 16));

                uint64_t raw;
                size_t section_index;
                std::string section_name;
                ERROR_IF(debugger_->get_raw(address, raw, section_index, section_name));

                std::ostringstream stream;
                stream << std::uppercase << std::hex << raw << std::dec << " [" << section_index << "]: " << section_name;

                printer_.bottom_out(stream.str());

                return RES_SUCCESS;
            }
        },
        {
            "run",
            [this](const std::vector<std::string> ops)
            {
                ERROR_IF(ops.size() > 1);

                debug_trace_entry trace_entry;
                if (ops.empty())
                    trace_entry = debugger_->run();
                else
                {
                    uint64_t count;
                    ERROR_IF(parse_string(ops.at(0), count, 10));
                    trace_entry = debugger_->run(count);
                }

                printer_.print_blank();

                if (trace_entry.error)
                    printer_.print(std::make_shared<std::pair<int, std::string>>(trace_entry.error, trace_entry.error_str));
                
                print_next_instruction();
                return RES_SUCCESS;
            }
        },
        {
            "save",
            [this](const std::vector<std::string> ops)
            {
                ERROR_IF(ops.size() != 2);

                uint64_t address;
                ERROR_IF(parse_string(ops.at(0), address, 16));

                size_t count;
                ERROR_IF(parse_string(ops.at(1), count, 10));

                std::vector<uint8_t> bytes;
                ERROR_IF(debugger_->get_bytes(address, count, bytes));

                const auto aid = loader_raw::create_aid(IMAGE_FILE_MACHINE_AMD64, address, bytes);

                const std::string file_name = "saved.aid";
                std::ofstream stream(file_name, std::ios::binary);

                stream.write(reinterpret_cast<const char*>(&aid.at(0)), aid.size());

                stream.close();

                return RES_SUCCESS;
            }
        },
        {
            "skip",
            [this](const std::vector<std::string> ops)
            {
                if(ops.empty())
                {
                    ERROR_IF(debugger_->skip());
                    print_next_instruction();
                }
                else
                {
                    for (const auto op : ops)
                    {
                        uint64_t address;
                        ERROR_IF(parse_string(op, address, 16));
                        ERROR_IF(debugger_->set_debug_point(address, dp_skip));
                    }
                }

                return RES_SUCCESS;
            }
        },
        {
            "take",
            [this](const std::vector<std::string> ops)
            {
                if (ops.empty())
                {
                    ERROR_IF(debugger_->take());
                    printer_.print_blank();
                    print_next_instruction();
                }
                else
                {
                    for (const auto op : ops)
                    {
                        uint64_t address;
                        ERROR_IF(parse_string(op, address, 16));
                        ERROR_IF(debugger_->set_debug_point(address, dp_take));
                    }
                }

                return RES_SUCCESS;
            }
        }
    };
}
